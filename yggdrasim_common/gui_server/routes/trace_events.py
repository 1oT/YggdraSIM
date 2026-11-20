# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``/api/events/trace`` -- the lines running actions print, as they print them.

Each frame is ``{"event": "trace", "action", "trace_id", "level", "line"}``
from :mod:`yggdrasim_common.gui_server.live_trace`; a ``ping`` frame keeps an
idle socket open. Nothing is replayed on connect: a finished action's text is
in its own result. Auth is the bearer-token contract of the other sockets.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from yggdrasim_common.gui_server import live_trace
from yggdrasim_common.gui_server.auth import (
    compare_tokens,
    token_id,
    websocket_accept_protocol,
    websocket_bearer,
)


_LOGGER = logging.getLogger("yggdrasim.gui.trace_events")

router = APIRouter(tags=["events"])

_HEARTBEAT_SECONDS = 25.0


@router.websocket("/api/events/trace")
async def trace_event_stream(websocket: WebSocket) -> None:
    """Forward live trace frames to one page until it disconnects."""
    raw = getattr(websocket.app.state, "gui_token", None)
    expected = str(raw) if isinstance(raw, str) else ""
    provided = websocket_bearer(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth")
        _LOGGER.info("gui.trace_events.auth_rejected")
        return

    await websocket.accept(subprotocol=websocket_accept_protocol(websocket))
    _LOGGER.info("gui.trace_events.opened token=%s", token_id(provided))

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=live_trace.QUEUE_CAP)
    detach = live_trace.get_bus().attach(queue, asyncio.get_running_loop())
    try:
        while True:
            try:
                frame = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))
                continue
            await websocket.send_text(json.dumps(frame))
    except (WebSocketDisconnect, asyncio.CancelledError):
        # A window close cancels the task while it waits on the queue.
        pass
    except Exception as err:  # noqa: BLE001 -- one client must not take the bus down
        _LOGGER.warning("gui.trace_events.stream_error: %s: %s", type(err).__name__, err)
    finally:
        detach()
