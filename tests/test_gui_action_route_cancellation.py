# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Cancellation-contract coverage for the generic GUI action routes."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from starlette.websockets import WebSocketDisconnect

from yggdrasim_common.gui_server.actions.registry import (
    ActionRegistry,
    ActionSpec,
)
from yggdrasim_common.gui_server.routes import actions as action_routes


class _ScriptedWebSocket:
    def __init__(self, frames: list[str]) -> None:
        self.headers = {
            "sec-websocket-protocol": "yggdrasim, bearer.test-token",
        }
        self.query_params: dict[str, str] = {}
        self.app = SimpleNamespace(
            state=SimpleNamespace(gui_token="test-token"),
        )
        self._frames = list(frames)
        self.accepted = False
        self.sent: list[dict[str, Any]] = []
        self.close_calls: list[dict[str, Any]] = []

    async def accept(self, subprotocol: str | None = None) -> None:
        assert subprotocol == "yggdrasim"
        self.accepted = True

    async def receive_text(self) -> str:
        if self._frames:
            return self._frames.pop(0)
        raise WebSocketDisconnect(code=1000)

    async def send_text(self, value: str) -> None:
        self.sent.append(json.loads(value))

    async def close(
        self,
        code: int = 1000,
        reason: str | None = None,
    ) -> None:
        self.close_calls.append({"code": code, "reason": reason})


def test_stream_cancel_frame_sets_dispatcher_context_event(
    monkeypatch: Any,
) -> None:
    registry = ActionRegistry()
    observed: dict[str, Any] = {}

    async def _dispatcher(ctx: Any) -> Any:
        event = ctx.extras.get("cancel_event")
        observed["event"] = event
        yield {"level": "info", "phase": "STARTED"}
        for _ in range(100):
            if event.is_set():
                yield {"level": "done", "phase": "CANCELLED"}
                return
            await asyncio.sleep(0)
        raise AssertionError("cancel frame did not reach the dispatcher")

    registry.register(
        ActionSpec(
            id="test.cancellable",
            subsystem="test",
            title="Cancellable",
            description="Test-only cancellable stream.",
            dispatcher=_dispatcher,
            streams=True,
        )
    )
    monkeypatch.setattr(
        action_routes,
        "ensure_builtin_actions_loaded",
        lambda: registry,
    )
    websocket = _ScriptedWebSocket(
        [
            json.dumps({"type": "start", "inputs": {}}),
            json.dumps({"type": "cancel"}),
        ]
    )

    asyncio.run(action_routes.stream_action(websocket, "test.cancellable"))

    assert websocket.accepted is True
    assert isinstance(observed["event"], threading.Event)
    assert observed["event"].is_set() is True
    assert [frame["phase"] for frame in websocket.sent] == [
        "STARTED",
        "CANCELLED",
    ]
    assert websocket.close_calls


def test_frontend_exposes_cancel_control_for_generic_action_streams() -> None:
    static_root = (
        Path(__file__).resolve().parents[1]
        / "yggdrasim_common"
        / "gui_server"
        / "static"
    )
    javascript = (static_root / "app.js").read_text(encoding="utf-8")
    stylesheet = (static_root / "app.css").read_text(encoding="utf-8")

    assert 'streamSocket.send(JSON.stringify({ type: "cancel" }))' in javascript
    assert "cc-action-stream-cancel" in javascript
    assert 'action.id !== "scp11.download_profile"' in javascript
    assert ".cc-action-stream-cancel" in stylesheet
