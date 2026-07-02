# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HTTP-level integration tests for the Card Bridge actions (CB-4 frontend).

The frontend panel calls ``POST /api/actions/card_bridge.status/run``
and ``POST /api/actions/card_bridge.probe/run``. These tests pin the
wire shape that the JS expects (``ok`` / ``data`` / ``error`` envelope)
so any future churn in the route layer or dispatcher is caught before
the operator opens the browser.

Skips cleanly when FastAPI / Starlette / httpx aren't installed —
matches the existing pattern in ``tests/test_yggdracore_http_app.py``.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

try:
    import httpx  # noqa: F401  — required by starlette TestClient

    _HAS_HTTPX = True
except ImportError:  # pragma: no cover — environment-dependent
    _HAS_HTTPX = False

try:
    from fastapi.testclient import TestClient  # type: ignore

    _HAS_FASTAPI = True
except Exception:  # pragma: no cover — environment-dependent
    _HAS_FASTAPI = False

if _HAS_FASTAPI and _HAS_HTTPX:
    from yggdrasim_common.gui_server.app import create_app
    from yggdrasim_common.gui_server.config import (
        GuiServerConfig,
        MODE_WEB_SERVER,
    )

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)
from yggdrasim_common.card_bridge_auth import fingerprint as _fingerprint


_TEST_TOKEN = "test-bearer-32-bytes-long-padding-to-meet-floor"


def _make_handler(
    *,
    require_token: str = "",
    status_payload: dict[str, Any] | None = None,
    status_code: int = 200,
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
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(status_payload or {}).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

    return _Handler


class _StubBridge:
    def __init__(self, **kwargs: Any) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(**kwargs))
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
    _HAS_FASTAPI and _HAS_HTTPX,
    "FastAPI + httpx required (install yggdrasim[gui-server,test])",
)
class CardBridgeActionsHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Build a minimal GUI app so we can exercise the action route
        # layer without spinning up uvicorn. ``port=0`` is fine because
        # ``TestClient`` never opens a socket.
        config = GuiServerConfig(
            mode=MODE_WEB_SERVER,
            host="127.0.0.1",
            port=0,
            token=_TEST_TOKEN,
        )
        cls.app = create_app(config)
        cls.client = TestClient(cls.app)
        cls.headers = {"Authorization": f"Bearer {_TEST_TOKEN}"}

    def setUp(self) -> None:
        import os as _os
        import tempfile

        # Snapshot the relay env vars + the runtime root. Pointing
        # YGGDRASIM_RUNTIME_ROOT at a fresh tempdir guarantees the
        # marker-file branch in ``_resolve_card_relay_url`` doesn't
        # surface state from a sibling test (the daemon test stack
        # writes a marker into its own tempdir but earlier suites can
        # leave one in the user's $HOME).
        self._snapshot = {}
        for key in (
            CARD_RELAY_URL_ENV,
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            "YGGDRASIM_RUNTIME_ROOT",
        ):
            self._snapshot[key] = _os.environ.get(key)
            _os.environ.pop(key, None)
        self._runtime_root = tempfile.mkdtemp(prefix="ygg-cb-http-")
        _os.environ["YGGDRASIM_RUNTIME_ROOT"] = self._runtime_root

    def tearDown(self) -> None:
        import os as _os
        import shutil

        for key, value in self._snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value
        try:
            shutil.rmtree(self._runtime_root, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass

    def _post(self, action_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
        response = self.client.post(
            f"/api/actions/{action_id}/run",
            headers=self.headers,
            json={"inputs": inputs},
        )
        self.assertEqual(response.status_code, 200, msg=response.text)
        return response.json()

    def test_status_unconfigured(self) -> None:
        body = self._post("card_bridge.status", {})
        self.assertTrue(body["ok"])
        self.assertEqual(body["action_id"], "card_bridge.status")
        data = body["data"]
        self.assertFalse(data["configured"])
        self.assertIn("not configured", data["summary"].lower())

    def test_status_configured_returns_fingerprint(self) -> None:
        import os as _os

        _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:8642/apdu"
        _os.environ[CARD_RELAY_TOKEN_ENV] = "panel-token"

        body = self._post("card_bridge.status", {})
        self.assertTrue(body["ok"])
        data = body["data"]
        self.assertTrue(data["configured"])
        self.assertEqual(data["url"], "http://127.0.0.1:8642/apdu")
        self.assertTrue(data["has_token"])
        self.assertEqual(data["token_fingerprint"], _fingerprint("panel-token"))
        # Raw token must not appear anywhere in the wire payload.
        self.assertNotIn("panel-token", json.dumps(data))

    def test_probe_no_url_returns_helpful_reason(self) -> None:
        body = self._post(
            "card_bridge.probe",
            {"url": "", "token": "", "use_configured": False},
        )
        self.assertTrue(body["ok"])  # action returned, even if probe says not-ok
        data = body["data"]
        self.assertFalse(data["ok"])
        self.assertIn("no URL", data["reason"])

    def test_probe_explicit_url_happy_path(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "127.0.0.1",
                "atrHex": "3b00",
                "reader": "Stub",
                "auditEnabled": True,
            },
        )
        try:
            body = self._post(
                "card_bridge.probe",
                {"url": bridge.url, "token": "", "use_configured": False},
            )
        finally:
            bridge.close()
        self.assertTrue(body["ok"])
        data = body["data"]
        self.assertTrue(data["ok"], msg=str(data))
        self.assertEqual(data["auth_posture"], "no-token-required")
        self.assertEqual(data["atr_hex"], "3B00")
        self.assertGreaterEqual(data["ping_latency_ms"], 0.0)

    def test_probe_token_rejected_returns_401_posture(self) -> None:
        bridge = _StubBridge(require_token="real")
        try:
            body = self._post(
                "card_bridge.probe",
                {"url": bridge.url, "token": "wrong", "use_configured": False},
            )
        finally:
            bridge.close()
        self.assertTrue(body["ok"])  # outer envelope still ok
        data = body["data"]
        self.assertFalse(data["ok"])
        self.assertEqual(data["auth_posture"], "token-rejected")

    def test_unknown_action_returns_404(self) -> None:
        response = self.client.post(
            "/api/actions/card_bridge.does_not_exist/run",
            headers=self.headers,
            json={"inputs": {}},
        )
        self.assertEqual(response.status_code, 404)

    def test_action_endpoint_requires_token(self) -> None:
        response = self.client.post(
            "/api/actions/card_bridge.status/run",
            json={"inputs": {}},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
