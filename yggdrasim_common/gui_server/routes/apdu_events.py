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

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from yggdrasim_common.apdu_recorder import ApduExchange, get_recorder
from yggdrasim_common.gui_server.auth import (
    compare_tokens,
    token_id,
    websocket_accept_protocol,
    websocket_bearer,
)


_LOGGER = logging.getLogger("yggdrasim.gui.apdu_events")

router = APIRouter(tags=["events"])

_QUEUE_CAP = 256
_HEARTBEAT_SECONDS = 25.0


# --- helpers (mirrors routes.terminal so each WS file stays self-contained) --


def _extract_token(websocket: WebSocket) -> str:
    return websocket_bearer(websocket)


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


class RawCaptureConsent(BaseModel):
    scope: str = Field(min_length=1, max_length=256)
    ttl_seconds: int = Field(default=60, ge=30, le=300)
    consent: str


@router.post("/api/events/apdu/raw-consent")
def enable_raw_capture(body: RawCaptureConsent) -> dict[str, Any]:
    """Enable diagnostic raw capture for one reader/source for at most 5 minutes."""
    try:
        get_recorder().enable_raw_capture(
            body.scope,
            ttl_seconds=body.ttl_seconds,
            consent=body.consent,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {
        "enabled": True,
        "scope": body.scope,
        "ttl_seconds": body.ttl_seconds,
        "warning": "Raw APDU payloads can contain PINs, keys, and profile data.",
    }


@router.delete("/api/events/apdu/raw-consent/{scope}")
def disable_raw_capture(scope: str) -> dict[str, Any]:
    get_recorder().disable_raw_capture(scope)
    return {"enabled": False, "scope": scope}


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

    await websocket.accept(subprotocol=websocket_accept_protocol(websocket))
    _LOGGER.info(
        "gui.apdu_events.opened token=%s", token_id(provided)
    )

    recorder = get_recorder()
    requested_scope = str(websocket.query_params.get("scope") or "").strip()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[ApduExchange] = asyncio.Queue(maxsize=_QUEUE_CAP)
    detach = recorder.attach_queue(
        queue,
        loop=loop,
        scope=requested_scope or None,
    )

    try:
        # Replay recent buffer so a freshly-opened tab gets context
        # immediately. We keep the limit modest (200 rows) — enough to
        # show a typical scan + read loop without flooding the UI.
        for past in recorder.snapshot(
            limit=200,
            scope=requested_scope or None,
        ):
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
