# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Route-contract tests for the Card Bridge actions (CB-4 frontend).

The frontend panel calls ``POST /api/actions/card_bridge.status/run``
and ``POST /api/actions/card_bridge.probe/run``. These tests pin the
response shape that the JS expects (``ok`` / ``data`` / ``error``
envelope) so any future churn in the route layer or dispatcher is caught
before the operator opens the browser.

The action endpoint is invoked directly instead of through Starlette's
threaded ``TestClient``. This keeps the tests deterministic on Python
3.13 while still exercising request validation, dispatch, and the
response model. The bearer gate is covered separately at its pure-ASGI
boundary.
"""

from __future__ import annotations

import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import patch

import pytest

try:
    from fastapi import HTTPException

    _HAS_FASTAPI = True
except ImportError:  # pragma: no cover — environment-dependent
    _HAS_FASTAPI = False

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)
from yggdrasim_common.card_bridge_auth import fingerprint as _fingerprint
from yggdrasim_common.gui_server.auth import AuthMiddleware

if _HAS_FASTAPI:
    from yggdrasim_common.gui_server.routes import actions as actions_routes


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
        try:
            self.server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                _make_handler(**kwargs),
            )
        except PermissionError as error:
            raise unittest.SkipTest(
                f"loopback sockets are unavailable in this environment: {error}"
            ) from error
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
    _HAS_FASTAPI,
    "FastAPI required (install yggdrasim[gui-server,test])",
)
class CardBridgeActionsHttpTests(unittest.TestCase):
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
        async def _invoke_inline(spec, ctx, coerced):
            dispatcher = spec.dispatcher
            if dispatcher is None:
                raise AssertionError(f"{spec.id!r} has no dispatcher")
            result = dispatcher(ctx, **coerced)
            if asyncio.iscoroutine(result):
                return await result
            return result

        # Dispatch inline so ``asyncio.run`` never has to tear down a
        # one-shot default executor. The route's coercion, error mapping,
        # result scrubbing, and response envelope remain under test.
        with patch.object(actions_routes, "_invoke_dispatcher", _invoke_inline):
            response = asyncio.run(
                actions_routes.run_action(
                    action_id,
                    actions_routes.RunRequest(inputs=inputs),
                )
            )
        return response.model_dump()

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

    @pytest.mark.usefixtures("require_loopback_socket")
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

    @pytest.mark.usefixtures("require_loopback_socket")
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
        with self.assertRaises(HTTPException) as raised:
            self._post("card_bridge.does_not_exist", {})
        self.assertEqual(raised.exception.status_code, 404)

    def test_action_endpoint_requires_token(self) -> None:
        downstream_called = False
        messages: list[dict[str, Any]] = []

        async def downstream(scope, receive, send) -> None:
            nonlocal downstream_called
            del scope, receive, send
            downstream_called = True

        async def receive() -> dict[str, Any]:
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        async def send(message: dict[str, Any]) -> None:
            messages.append(message)

        middleware = AuthMiddleware(
            downstream,
            expected_token=_TEST_TOKEN,
        )
        asyncio.run(
            middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/api/actions/card_bridge.status/run",
                    "headers": [],
                    "client": ("127.0.0.1", 12345),
                },
                receive,
                send,
            )
        )

        starts = [
            message
            for message in messages
            if message.get("type") == "http.response.start"
        ]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["status"], 401)
        self.assertFalse(downstream_called)


if __name__ == "__main__":
    unittest.main()
