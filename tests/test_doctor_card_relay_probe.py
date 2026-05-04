"""Tests for ``yggdrasim_common.doctor._probe_card_relay`` (CB-3).

A minimal stub bridge -- built on the stdlib's ``http.server`` -- answers
``/ping`` and ``/status`` so the doctor probe's full
decision tree without depending on the HilBridge / Card Bridge stack
or on a real reader.

Coverage:

* No URL configured → single ``info`` line, exit code stays clean.
* URL configured but unreachable → ``warn``.
* ``/ping`` returns non-200 → ``warn``.
* ``/status`` requires auth and request lacks token → ``warn``.
* ``/status`` requires auth and token present → ``ok`` with fingerprint.
* ``/status`` does not require auth and bind host is non-loopback →
  ``warn`` (refuse to use unauthenticated non-loopback bridge).
* ``/status`` reports loopback + audit on → ``ok`` mentions both.
* URL with trailing ``/apdu`` is normalised to the bridge root.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)
from yggdrasim_common.doctor import DoctorReport, _probe_card_relay


def _make_handler(
    *,
    ping_status: int = 200,
    status_status: int = 200,
    status_payload: dict[str, Any] | None = None,
    require_token: str = "",
    ping_raises_connection_close: bool = False,
):
    """Build a handler class that snapshots the args via closure."""

    class _StubHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args, **_kwargs):
            return  # silence stdout in tests

        def do_GET(self) -> None:  # noqa: N802 -- http.server convention
            if ping_raises_connection_close and self.path == "/ping":
                # Simulate a peer reset: close without sending headers.
                try:
                    self.connection.close()
                except Exception:
                    pass
                return
            if self.path == "/ping":
                self.send_response(ping_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if 200 <= ping_status < 300:
                    self.wfile.write(b"{\"ok\":true}")
                return
            if self.path == "/status":
                if len(require_token) > 0:
                    presented = self.headers.get("Authorization") or ""
                    if presented != f"Bearer {require_token}":
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b"{\"error\":\"unauthorised\"}")
                        return
                self.send_response(status_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = status_payload or {}
                self.wfile.write(json.dumps(payload).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

    return _StubHandler


class _StubBridge:
    def __init__(self, **handler_kwargs: Any) -> None:
        handler = _make_handler(**handler_kwargs)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class DoctorCardRelayProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Ensure we start each case with a clean environment so the
        # resolution chain doesn't pick up state from another test.
        # Includes ``YGGDRASIM_RUNTIME_ROOT`` because the marker-file
        # branch in ``_resolve_card_relay_url`` would otherwise surface
        # leftover state from the daemon test stack.
        import os as _os
        import tempfile

        self._env_snapshot = {}
        for key in (
            CARD_RELAY_URL_ENV,
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            "YGGDRASIM_RUNTIME_ROOT",
        ):
            self._env_snapshot[key] = _os.environ.get(key)
            _os.environ.pop(key, None)
        self._runtime_root = tempfile.mkdtemp(prefix="ygg-cb-doctor-")
        _os.environ["YGGDRASIM_RUNTIME_ROOT"] = self._runtime_root

    def tearDown(self) -> None:
        import os as _os
        import shutil

        for key, value in self._env_snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value
        shutil.rmtree(self._runtime_root, ignore_errors=True)

    def _run_probe(self) -> DoctorReport:
        report = DoctorReport()
        _probe_card_relay(report)
        return report

    def _row(self, report: DoctorReport):
        for check in report.checks:
            if check.name == "Remote card bridge":
                return check
        raise AssertionError("Remote card bridge probe did not emit a row")

    def test_unconfigured_returns_info(self) -> None:
        report = self._run_probe()
        row = self._row(report)
        self.assertEqual(row.status, "info")
        self.assertIn("not configured", row.detail.lower())

    def test_unreachable_url_warns(self) -> None:
        import os as _os

        # Pick a port that's almost certainly not listening.
        _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:1/apdu"
        report = self._run_probe()
        row = self._row(report)
        self.assertEqual(row.status, "warn")
        self.assertIn("unreachable", row.detail.lower())

    def test_ping_non_200_warns(self) -> None:
        bridge = _StubBridge(ping_status=503)
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "warn")
            self.assertIn("HTTP 503", row.detail)
        finally:
            bridge.close()

    def test_status_requires_token_but_none_present(self) -> None:
        bridge = _StubBridge(
            require_token="secret-1",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": "abc123",
                "host": "127.0.0.1",
            },
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "warn")
            self.assertIn("rejected", row.detail.lower())
        finally:
            bridge.close()

    def test_token_accepted_on_loopback(self) -> None:
        bridge = _StubBridge(
            require_token="secret-2",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": "fp1234",
                "host": "127.0.0.1",
                "auditEnabled": True,
            },
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            _os.environ[CARD_RELAY_TOKEN_ENV] = "secret-2"
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "ok")
            self.assertIn("auth ok", row.detail)
            self.assertIn("audit on", row.detail)
        finally:
            bridge.close()

    def test_unauthenticated_non_loopback_rejected(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "10.0.0.5",
            },
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "warn")
            self.assertIn("non-loopback", row.detail.lower())
        finally:
            bridge.close()

    def test_loopback_no_auth_required_ok(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "127.0.0.1",
                "auditEnabled": False,
            },
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "ok")
            self.assertIn("loopback", row.detail.lower())
            self.assertIn("audit off", row.detail.lower())
        finally:
            bridge.close()

    def test_url_with_apdu_suffix_is_normalised(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "127.0.0.1",
            },
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url + "/apdu"
            report = self._run_probe()
            row = self._row(report)
            self.assertEqual(row.status, "ok")
            self.assertNotIn("/apdu", row.detail)
        finally:
            bridge.close()

    def test_probe_handles_completely_invalid_url(self) -> None:
        import os as _os

        _os.environ[CARD_RELAY_URL_ENV] = "http://"
        report = self._run_probe()
        row = self._row(report)
        # Either "warn" with a transport-error message, or "info" if
        # the resolver rejects the URL outright. Both are acceptable --
        # the doctor must not raise.
        self.assertIn(row.status, {"warn", "info"})


if __name__ == "__main__":
    unittest.main()
