# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""WebSocket route that streams every wire-level APDU into the GUI.

The :mod:`yggdrasim_common.apdu_recorder` singleton captures every
APDU exchange that flows through ``card_backend.create_card_connection``.
This route attaches a per-client :class:`asyncio.Queue` to the
recorder, replays the most recent N exchanges so a freshly-opened tab
isn't blank, then keeps the socket alive forwarding new events one
JSON frame at a time.

Framing matches the rest of the GUI's WebSocket conventions: text
frames with a top-level ``"event"`` discriminator. The token check
follows the same pattern as :mod:`yggdrasim_common.gui_server.routes.terminal`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from yggdrasim_common.apdu_recorder import ApduExchange, get_recorder
from yggdrasim_common.gui_server.auth import compare_tokens, token_id


_LOGGER = logging.getLogger("yggdrasim.gui.apdu_events")

router = APIRouter(tags=["events"])

_QUEUE_CAP = 256
_HEARTBEAT_SECONDS = 25.0


# --- helpers (mirrors routes.terminal so each WS file stays self-contained) --


def _extract_token(websocket: WebSocket) -> str:
    header = websocket.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()

    subproto = websocket.headers.get("sec-websocket-protocol") or ""
    for fragment in (part.strip() for part in subproto.split(",")):
        if fragment.lower().startswith("bearer."):
            return fragment.split(".", 1)[1].strip()

    qs_token = websocket.query_params.get("t")
    if qs_token:
        return str(qs_token)

    return ""


def _expected_token(websocket: WebSocket) -> str:
    raw_token = getattr(websocket.app.state, "gui_token", None)
    if isinstance(raw_token, str) and len(raw_token) > 0:
        return raw_token
    return ""


def _exchange_to_frame(exchange: ApduExchange) -> dict[str, Any]:
    """Wrap an :class:`ApduExchange` in the GUI's ``event=apdu`` frame."""
    payload = exchange.to_json()
    payload["event"] = "apdu"
    return payload


# --- route -------------------------------------------------------------


@router.websocket("/api/events/apdu")
async def apdu_event_stream(websocket: WebSocket) -> None:
    """Stream every captured APDU exchange to the connected SPA client.

    Auth follows the same bearer-token contract as the terminal WS.
    On accept, we send up to 200 buffered events first (so the dock
    isn't empty for the operator who just opened the page) and then
    forward each subsequent recorder emit as it lands.
    """
    expected = _expected_token(websocket)
    provided = _extract_token(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="auth"
        )
        _LOGGER.info("gui.apdu_events.auth_rejected")
        return

    await websocket.accept()
    _LOGGER.info(
        "gui.apdu_events.opened token=%s", token_id(provided)
    )

    recorder = get_recorder()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[ApduExchange] = asyncio.Queue(maxsize=_QUEUE_CAP)
    detach = recorder.attach_queue(queue, loop=loop)

    try:
        # Replay recent buffer so a freshly-opened tab gets context
        # immediately. We keep the limit modest (200 rows) — enough to
        # show a typical scan + read loop without flooding the UI.
        for past in recorder.snapshot(limit=200):
            await websocket.send_text(json.dumps(_exchange_to_frame(past)))

        while True:
            try:
                exchange = await asyncio.wait_for(
                    queue.get(), timeout=_HEARTBEAT_SECONDS
                )
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))
                continue
            await websocket.send_text(
                json.dumps(_exchange_to_frame(exchange))
            )
    except WebSocketDisconnect:
        pass
    except Exception as err:  # noqa: BLE001 — never let one client crash the bus
        _LOGGER.warning(
            "gui.apdu_events.stream_error: %s: %s",
            type(err).__name__,
            err,
        )
    finally:
        detach()
