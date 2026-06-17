"""Tests for ``yggdrasim_common.gui_server.actions.card_bridge`` (CB-4 backend).

Coverage:

* ``card_bridge.status`` reports unconfigured / configured / token
  fingerprint without leaking the raw token.
* ``card_bridge.probe`` reaches a stub bridge and returns
  ``ok=True`` with latency + ATR + fingerprint.
* ``card_bridge.probe`` distinguishes auth-required-but-rejected,
  unreachable, and ``auth-disabled-non-loopback`` postures.
* ``card_bridge.probe`` falls back to configured URL when the form
  leaves ``url`` blank, and obeys ``use_configured=False`` to skip
  the fallback.
* The action specs are registered in the global registry under the
  expected ids.
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
from yggdrasim_common.card_bridge_auth import fingerprint as _fingerprint
from yggdrasim_common.gui_server.actions import card_bridge as cb
from yggdrasim_common.gui_server.actions.registry import ActionContext, get_registry


def _make_handler(
    *,
    require_token: str = "",
    status_status: int = 200,
    status_payload: dict[str, Any] | None = None,
    ping_status: int = 200,
):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args, **_kwargs):
            return

        def do_GET(self) -> None:  # noqa: N802
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

    return _Handler


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


class _EnvSandbox:
    """Snapshot/restore the relay-related env vars per test.

    Also redirects ``YGGDRASIM_RUNTIME_ROOT`` to a fresh tempdir so the
    marker-file branch in ``card_backend._resolve_card_relay_url``
    cannot surface state from a sibling test (the daemon stack writes
    its own marker, but on a hot CI runner those tempdirs can outlive
    the test that created them).
    """

    def __init__(self) -> None:
        self._snapshot: dict[str, str | None] = {}
        self._runtime_root: str | None = None

    def __enter__(self):
        import os as _os
        import tempfile

        for key in (
            CARD_RELAY_URL_ENV,
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            "YGGDRASIM_RUNTIME_ROOT",
        ):
            self._snapshot[key] = _os.environ.get(key)
            _os.environ.pop(key, None)
        self._runtime_root = tempfile.mkdtemp(prefix="ygg-cb-actions-")
        _os.environ["YGGDRASIM_RUNTIME_ROOT"] = self._runtime_root
        return self

    def __exit__(self, *_):
        import os as _os
        import shutil

        for key, value in self._snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value
        if self._runtime_root is not None:
            shutil.rmtree(self._runtime_root, ignore_errors=True)


class CardBridgeActionRegistrationTests(unittest.TestCase):
    def test_status_spec_registered(self) -> None:
        spec = get_registry().get("card_bridge.status")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.subsystem, "Card Bridge")
        self.assertFalse(spec.requires_card)

    def test_probe_spec_registered(self) -> None:
        spec = get_registry().get("card_bridge.probe")
        self.assertIsNotNone(spec)
        # Inputs must include url + token + use_configured.
        names = {field.name for field in spec.inputs}
        self.assertEqual(names, {"url", "token", "use_configured"})
        token_field = next(field for field in spec.inputs if field.name == "token")
        self.assertTrue(token_field.secret)


class CardBridgeStatusTests(unittest.TestCase):
    def test_status_unconfigured(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_status(ActionContext())
        self.assertFalse(payload["configured"])
        self.assertEqual(payload["url"], "")
        self.assertFalse(payload["has_token"])
        self.assertIn("not configured", payload["summary"].lower())

    def test_status_configured_with_raw_token(self) -> None:
        with _EnvSandbox():
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:8642/apdu"
            _os.environ[CARD_RELAY_TOKEN_ENV] = "secret-token-1"
            payload = cb._dispatch_status(ActionContext())
        self.assertTrue(payload["configured"])
        self.assertEqual(payload["url"], "http://127.0.0.1:8642/apdu")
        self.assertEqual(payload["base_url"], "http://127.0.0.1:8642")
        self.assertTrue(payload["has_token"])
        self.assertEqual(payload["token_source"], "env-raw")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("secret-token-1"))
        self.assertNotIn("secret-token-1", json.dumps(payload))

    def test_status_configured_with_token_file(self) -> None:
        import tempfile as _tmp

        with _EnvSandbox():
            with _tmp.NamedTemporaryFile("w", delete=False) as handle:
                handle.write("from-file-token")
                token_path = handle.name
            try:
                import os as _os

                _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:8642/apdu"
                _os.environ[CARD_RELAY_TOKEN_FILE_ENV] = token_path
                payload = cb._dispatch_status(ActionContext())
            finally:
                _os.unlink(token_path)
        self.assertTrue(payload["has_token"])
        self.assertEqual(payload["token_source"], "env-file")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("from-file-token"))


class CardBridgeProbeTests(unittest.TestCase):
    def test_probe_no_url_returns_helpful_reason(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_probe(ActionContext())
        self.assertFalse(payload["ok"])
        self.assertIn("no URL", payload["reason"])

    def test_probe_explicit_url_no_token_required(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "127.0.0.1",
                "atrHex": "3b9f96804fe7828031a073be211367",
                "reader": "Stub Reader",
                "auditEnabled": True,
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["url"], bridge.url)
        self.assertEqual(payload["auth_posture"], "no-token-required")
        self.assertEqual(payload["atr_hex"], "3B9F96804FE7828031A073BE211367")
        self.assertGreater(payload["ping_latency_ms"], 0.0)
        self.assertGreater(payload["status_latency_ms"], 0.0)
        self.assertTrue(payload["audit_enabled"])

    def test_probe_token_accepted(self) -> None:
        bridge = _StubBridge(
            require_token="match-me",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": _fingerprint("match-me"),
                "host": "127.0.0.1",
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="match-me",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["auth_posture"], "token-accepted")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("match-me"))
        self.assertTrue(payload["fingerprint_match"])

    def test_probe_token_rejected(self) -> None:
        bridge = _StubBridge(require_token="real")
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="wrong",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status_status"], 401)
        self.assertEqual(payload["auth_posture"], "token-rejected")

    def test_probe_unreachable_url(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_probe(
                ActionContext(),
                url="http://127.0.0.1:1/apdu",
                use_configured=False,
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ping_status"] if "ping_status" in payload else 0, 0)
        # Reason is a transport error class string.
        self.assertTrue(len(payload["reason"]) > 0)

    def test_probe_auth_disabled_non_loopback_flagged(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "10.0.0.5",
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["auth_posture"], "auth-disabled-non-loopback")

    def test_probe_falls_back_to_configured_url(self) -> None:
        bridge = _StubBridge(
            status_payload={"authRequired": False, "host": "127.0.0.1"}
        )
        try:
            with _EnvSandbox():
                import os as _os

                _os.environ[CARD_RELAY_URL_ENV] = bridge.url
                payload = cb._dispatch_probe(ActionContext())  # blank inputs
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertTrue(payload["used_configured_url"])

    def test_probe_apdu_suffix_stripped(self) -> None:
        bridge = _StubBridge(
            status_payload={"authRequired": False, "host": "127.0.0.1"}
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url + "/apdu",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["url"], bridge.url)

    def test_probe_does_not_leak_token_in_response(self) -> None:
        bridge = _StubBridge(
            require_token="should-not-appear",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": _fingerprint("should-not-appear"),
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="should-not-appear",
                    use_configured=False,
                )
        finally:
            bridge.close()
        serialised = json.dumps(payload)
        self.assertNotIn("should-not-appear", serialised)
        self.assertIn(_fingerprint("should-not-appear"), serialised)

    def test_probe_ping_failure_short_circuits(self) -> None:
        bridge = _StubBridge(ping_status=503)
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("ping_status"), 503)
        # status_status must not be reported because we never reach /status.
        self.assertNotIn("status_status", payload)


if __name__ == "__main__":
    unittest.main()
