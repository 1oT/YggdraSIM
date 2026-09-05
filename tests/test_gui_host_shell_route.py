# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Route-level tests for ``/api/host-shell/*``.

WebSocket coverage for the actual PTY bridge is intentionally light —
spinning a real shell up in a route test is brittle and the spawn helper
has its own dedicated coverage in
``tests/test_gui_host_shell_resolver.py``. What we exercise here is the
authentication contract, the disabled-by-default capability surface,
and the device-enumeration response shape.

The route functions are driven directly instead of through Starlette's
threaded ``TestClient``. This keeps the tests deterministic on Python
3.13 and in sandboxes that prohibit loopback sockets.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest


_FASTAPI_AVAILABLE = True
try:
    import fastapi as _fastapi  # noqa: F401
    import starlette as _starlette  # noqa: F401
except ImportError:
    _FASTAPI_AVAILABLE = False


_needs_gui_stack = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI / Starlette not installed — gui extra missing.",
)


class _GateWebSocket:
    def __init__(self, *, authenticated: bool) -> None:
        self.headers = (
            {
                "sec-websocket-protocol": (
                    "yggdrasim, bearer.test-host-shell-token"
                )
            }
            if authenticated
            else {}
        )
        self.query_params: dict[str, str] = {}
        self.app = SimpleNamespace(
            state=SimpleNamespace(gui_token="test-host-shell-token"),
        )
        self.client = SimpleNamespace(host="test", port=1)
        self.accepted_protocol: str | None = None
        self.sent_text: list[str] = []
        self.close_code: int | None = None
        self.close_reason: str | None = None

    async def accept(self, subprotocol: str | None = None) -> None:
        self.accepted_protocol = subprotocol

    async def send_text(self, value: str) -> None:
        self.sent_text.append(value)

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        self.close_code = code
        self.close_reason = reason


# ---------------------------------------------------------------------------
# /api/host-shell/capabilities
# ---------------------------------------------------------------------------


@_needs_gui_stack
class TestCapabilities:
    def test_default_disabled(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

        monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
        payload = host_shell_routes.get_capabilities()
        assert payload["enabled"] is False
        assert payload["shell"] is None
        assert "YGGDRASIM_GUI_HOST_SHELL" in (payload.get("reason") or "")

    def test_enabled_reports_shell(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

        monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", "1")
        payload = host_shell_routes.get_capabilities()
        assert payload["enabled"] is True
        # ``shell`` is None on stripped containers without /bin/bash and
        # /bin/sh; otherwise it must be an absolute path.
        if payload["supported"] and payload["shell"] is not None:
            assert payload["shell"].startswith("/")


# ---------------------------------------------------------------------------
# /api/host-shell/devices
# ---------------------------------------------------------------------------


@_needs_gui_stack
class TestDevices:
    def test_devices_endpoint_shape(self) -> None:
        from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

        payload = host_shell_routes.get_devices()
        assert "devices" in payload
        assert "count" in payload
        assert isinstance(payload["devices"], list)
        for entry in payload["devices"]:
            assert "path" in entry
            assert "label" in entry


# ---------------------------------------------------------------------------
# WS handshake — auth + disabled refusal
# ---------------------------------------------------------------------------


@_needs_gui_stack
class TestWebSocket:
    def test_ws_rejects_missing_token(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

        monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", "1")
        websocket = _GateWebSocket(authenticated=False)
        asyncio.run(host_shell_routes.host_shell_socket(websocket))
        assert websocket.close_code == 1008
        assert websocket.close_reason == "auth"

    def test_ws_rejects_when_disabled(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

        monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
        monkeypatch.setattr(host_shell_routes.host_shell_module, "is_supported", lambda: True)
        websocket = _GateWebSocket(authenticated=True)
        asyncio.run(host_shell_routes.host_shell_socket(websocket))
        assert websocket.accepted_protocol == "yggdrasim"
        assert len(websocket.sent_text) == 1
        payload = json.loads(websocket.sent_text[0])
        assert payload["event"] == "error"
        assert "YGGDRASIM_GUI_HOST_SHELL" in payload["message"]
        assert websocket.close_code == 1008
        assert websocket.close_reason == "disabled"
