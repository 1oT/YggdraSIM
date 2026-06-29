# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the remote-bridge entry in ``GET /api/live/readers`` (CB-3).

The live route module pulls FastAPI / Pydantic at import time. When
those optional dependencies are missing (the lean ``yggdrasim`` install)
the module isn't importable — we ``skipUnless`` the entire suite in
that case so the rest of the test matrix stays green on lean CIs.

Coverage:

* No remote URL configured → ``_probe_remote_bridge_reader`` returns
  ``None`` and ``list_readers`` does not fabricate a row.
* URL configured + bridge online with ATR → row marked ``kind="remote"``
  with the reported ATR and ``source_url`` populated.
* URL configured + bridge requires token, request lacks one → row
  status describes the 401.
* URL configured + bridge unreachable → row status reports the
  transport error class.
* Trailing ``/apdu`` is stripped from ``source_url``.
"""

from __future__ import annotations

import importlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

try:
    _live_module = importlib.import_module(
        "yggdrasim_common.gui_server.routes.live"
    )
except Exception:  # pragma: no cover — environment-dependent
    _live_module = None

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)


def _make_handler(
    *,
    require_token: str = "",
    status_status: int = 200,
    status_payload: dict[str, Any] | None = None,
):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args, **_kwargs):
            return

        def do_GET(self) -> None:  # noqa: N802
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


@unittest.skipUnless(
    _live_module is not None,
    "FastAPI/Pydantic not installed — install yggdrasim[gui-server] to run",
)
class GuiLiveRemoteReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        import os as _os
        import tempfile

        self._snapshot = {}
        for key in (
            CARD_RELAY_URL_ENV,
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            "YGGDRASIM_RUNTIME_ROOT",
        ):
            self._snapshot[key] = _os.environ.get(key)
            _os.environ.pop(key, None)
        self._runtime_root = tempfile.mkdtemp(prefix="ygg-cb-live-")
        _os.environ["YGGDRASIM_RUNTIME_ROOT"] = self._runtime_root

    def tearDown(self) -> None:
        import os as _os
        import shutil

        for key, value in self._snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value
        shutil.rmtree(self._runtime_root, ignore_errors=True)

    def test_unconfigured_returns_none(self) -> None:
        result = _live_module._probe_remote_bridge_reader()
        self.assertIsNone(result)

    def test_configured_online_with_atr(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "atrHex": "3b9f96804fe7828031a073be211367",
                "reader": "Stub Reader 0",
            }
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            row = _live_module._probe_remote_bridge_reader()
            self.assertIsNotNone(row)
            self.assertEqual(row.kind, "remote")
            self.assertEqual(row.atr_hex, "3B9F96804FE7828031A073BE211367")
            self.assertIn("Stub Reader 0", row.name)
            self.assertEqual(row.source_url, bridge.url)
            self.assertIn("card present", row.status)
        finally:
            bridge.close()

    def test_configured_token_rejected_returns_401_status_text(self) -> None:
        bridge = _StubBridge(require_token="secret-3")
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url
            # No token configured → bridge replies 401 to /status.
            row = _live_module._probe_remote_bridge_reader()
            self.assertIsNotNone(row)
            self.assertEqual(row.kind, "remote")
            self.assertIn("token rejected", row.status.lower())
        finally:
            bridge.close()

    def test_configured_unreachable_returns_descriptive_status(self) -> None:
        import os as _os

        _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:1/apdu"
        row = _live_module._probe_remote_bridge_reader()
        self.assertIsNotNone(row)
        self.assertEqual(row.kind, "remote")
        self.assertIn("unreachable", row.status.lower())
        self.assertEqual(row.atr_hex, "")

    def test_apdu_suffix_stripped_from_source_url(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "atrHex": "3B00",
            }
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url + "/apdu"
            row = _live_module._probe_remote_bridge_reader()
            self.assertIsNotNone(row)
            self.assertEqual(row.source_url, bridge.url)
            self.assertNotIn("/apdu", row.source_url)
        finally:
            bridge.close()

    def test_remote_only_backend_when_pyscard_missing(self) -> None:
        """When pyscard import fails the route still surfaces the remote row."""
        bridge = _StubBridge(
            status_payload={"atrHex": "3B00"},
        )
        try:
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = bridge.url

            # Force the smartcard import to fail so we exercise the
            # ``except ImportError`` branch in ``list_readers``.
            import sys

            saved = sys.modules.pop("smartcard", None)
            saved_system = sys.modules.pop("smartcard.System", None)
            sys.modules["smartcard"] = None  # type: ignore[assignment]
            try:
                response = _live_module.list_readers()
            finally:
                sys.modules.pop("smartcard", None)
                if saved is not None:
                    sys.modules["smartcard"] = saved
                if saved_system is not None:
                    sys.modules["smartcard.System"] = saved_system

            self.assertEqual(response.backend, "remote-only")
            self.assertEqual(len(response.readers), 1)
            self.assertEqual(response.readers[0].kind, "remote")
            self.assertIn("only the configured remote", response.note.lower())
        finally:
            bridge.close()


if __name__ == "__main__":
    unittest.main()
