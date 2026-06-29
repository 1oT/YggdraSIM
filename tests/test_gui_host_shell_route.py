# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Route-level tests for ``/api/host-shell/*``.

WebSocket coverage for the actual PTY bridge is intentionally light —
spinning a real shell up under TestClient is brittle and the spawn
helper has its own dedicated coverage in
``tests/test_gui_host_shell_resolver.py``. What we exercise here is the
authentication contract, the disabled-by-default capability surface,
and the device-enumeration response shape.

Skipped automatically when the optional FastAPI / Starlette extras
are absent (matches the existing pattern in ``test_gui_actions.py``).
"""

from __future__ import annotations

import os

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


def _build_app(token: str = "test-host-shell-token"):
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.routes import host_shell as host_shell_routes

    app = FastAPI()
    app.state.gui_token = token
    app.include_router(host_shell_routes.router)
    return app


def _client(token: str = "test-host-shell-token"):
    from fastapi.testclient import TestClient

    return TestClient(_build_app(token))


# ---------------------------------------------------------------------------
# /api/host-shell/capabilities
# ---------------------------------------------------------------------------


@_needs_gui_stack
class TestCapabilities:
    def test_default_disabled(self, monkeypatch) -> None:
        monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
        with _client() as client:
            resp = client.get("/api/host-shell/capabilities")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["enabled"] is False
        assert payload["shell"] is None
        assert "YGGDRASIM_GUI_HOST_SHELL" in (payload.get("reason") or "")

    def test_enabled_reports_shell(self, monkeypatch) -> None:
        monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", "1")
        with _client() as client:
            resp = client.get("/api/host-shell/capabilities")
        assert resp.status_code == 200
        payload = resp.json()
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
        with _client() as client:
            resp = client.get("/api/host-shell/devices")
        assert resp.status_code == 200
        payload = resp.json()
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
        from starlette.websockets import WebSocketDisconnect

        monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", "1")
        with _client() as client:
            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect("/api/host-shell"):
                    pass
        # 1008 == policy violation, matching close code in the route.
        assert exc_info.value.code == 1008

    def test_ws_rejects_when_disabled(self, monkeypatch) -> None:
        import json

        from starlette.websockets import WebSocketDisconnect

        monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
        with _client() as client:
            url = "/api/host-shell?t=test-host-shell-token"
            with client.websocket_connect(url) as ws:
                error_frame = ws.receive_text()
                payload = json.loads(error_frame)
                assert payload["event"] == "error"
                assert "YGGDRASIM_GUI_HOST_SHELL" in payload["message"]
                with pytest.raises(WebSocketDisconnect):
                    ws.receive_text()
