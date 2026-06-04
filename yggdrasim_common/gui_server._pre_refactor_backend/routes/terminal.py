# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""WebSocket route that bridges xterm.js to a PTY child (Milestone B-2).

The client is expected to connect to ``/api/terminal/<module>?t=<token>``
after the normal SPA token hand-off. Framing:

* Server -> client: binary frames carry raw PTY output. A JSON text
  frame (``{"event": "exit", "status": <int>}``) is emitted right
  before close.
* Client -> server: text frames carry JSON control messages
  (``{"type": "resize", "rows": 40, "cols": 140}``) or ``{"type":
  "stdin", "data": "…"}``. Binary frames are interpreted as raw stdin
  bytes so paste workflows work without JSON wrapping.

The WebSocket bypass on the main ASGI auth middleware means we have to
repeat the token check here explicitly.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from yggdrasim_common.gui_server import terminal as pty_module
from yggdrasim_common.gui_server.auth import compare_tokens, token_id


_LOGGER = logging.getLogger("yggdrasim.gui.terminal")

router = APIRouter(tags=["terminal"])


# --- helpers -----------------------------------------------------------


def _extract_token(websocket: WebSocket) -> str:
    """Pull the bearer token from (in order): ``Authorization`` header,
    ``Sec-WebSocket-Protocol`` subprotocol, or ``?t=`` query parameter.

    xterm.js does not set an ``Authorization`` header directly, so the
    ``?t=`` fallback is the expected path in normal use. The subprotocol
    path mirrors the pattern used by OpenTelemetry collectors.
    """
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
    config = getattr(websocket.app.state, "gui_config_redacted", None)
    # We stash the real token on the middleware state elsewhere; fall
    # back to re-reading from app.state.
    raw_token = getattr(websocket.app.state, "gui_token", None)
    if isinstance(raw_token, str) and raw_token:
        return raw_token
    if isinstance(config, dict):
        # Shouldn't happen in production — the redacted form never
        # carries the raw token — but keeps the types straight.
        return str(config.get("token_hint", ""))
    return ""


# --- routes ------------------------------------------------------------


@router.get("/api/terminal/modules", tags=["terminal"])
def list_modules() -> dict:
    """Return the CLI-module allow-list for the terminal picker."""
    from yggdrasim_common.registry import CLI_MODULES

    return {
        "supported": pty_module.is_supported(),
        "modules": list(CLI_MODULES),
    }


@router.websocket("/api/terminal/{module}")
async def terminal_socket(websocket: WebSocket, module: str) -> None:
    """WebSocket handler: provide an interactive terminal session over the GUI socket."""
    expected = _expected_token(websocket)
    provided = _extract_token(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth")
        _LOGGER.info("gui.terminal.auth_rejected module=%s", module)
        return

    if not pty_module.is_supported():
        await websocket.accept()
        await websocket.send_text(
            json.dumps({
                "event": "error",
                "message": "PTY bridge not supported on this platform (Windows PTY support is not wired up yet).",
            })
        )
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="platform")
        return

    if not pty_module.is_allowed_module(module):
        await websocket.accept()
        await websocket.send_text(
            json.dumps({
                "event": "error",
                "message": f"module not in CLI allow-list: {module}",
            })
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="module")
        return

    await websocket.accept()
    bound_reader = str(websocket.query_params.get("reader") or "").strip()
    _LOGGER.info(
        "gui.terminal.opened module=%s token=%s reader=%s",
        module,
        token_id(provided),
        bound_reader if len(bound_reader) > 0 else "(unset)",
    )

    rows = int(websocket.query_params.get("rows") or 30)
    cols = int(websocket.query_params.get("cols") or 120)

    # Reader-as-session: the SPA forwards the active top-bar pill name
    # via ``?reader=`` so we can pin the spawned shell to the operator's
    # current reader. We export ``YGGDRASIM_READER`` rather than
    # surfacing a CLI flag because every legacy module already calls
    # ``card_backend.create_card_connection`` which is the single
    # reader-resolution chokepoint.
    spec_env: dict[str, str] = {}
    reader_query = websocket.query_params.get("reader")
    if reader_query is not None:
        reader_name_value = str(reader_query).strip()
        if len(reader_name_value) > 0:
            spec_env["YGGDRASIM_READER"] = reader_name_value

    session = pty_module.PtySession()
    try:
        await session.spawn(
            pty_module.PtyStartSpec(
                module=module,
                rows=rows,
                cols=cols,
                env=spec_env or None,
            ),
        )
    except (ValueError, RuntimeError) as error:
        await websocket.send_text(json.dumps({"event": "error", "message": str(error)}))
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="spawn")
        return

    await websocket.send_text(json.dumps({"event": "spawned", "pid": session.pid, "module": module}))

    reader_task = asyncio.create_task(_pump_output(session, websocket))
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if "bytes" in message and message["bytes"] is not None:
                session.send(message["bytes"])
                continue
            text = message.get("text") or ""
            if len(text) == 0:
                continue
            await _handle_client_text(session, text)
    except WebSocketDisconnect:
        pass
    except Exception as error:  # pragma: no cover - defensive
        _LOGGER.warning("gui.terminal.loop_error module=%s err=%s", module, error)
    finally:
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass
        await session.close()
        try:
            await websocket.close()
        except Exception:
            pass
        _LOGGER.info("gui.terminal.closed module=%s", module)


async def _pump_output(session: pty_module.PtySession, websocket: WebSocket) -> None:
    while not session.closed:
        chunk = await session.read_once(timeout=0.25)
        if chunk is None:
            break
        if len(chunk) == 0:
            # No bytes ready this tick; yield to keep the event loop
            # responsive.
            await asyncio.sleep(0)
            continue
        try:
            await websocket.send_bytes(chunk)
        except (WebSocketDisconnect, RuntimeError):
            break
    try:
        await websocket.send_text(json.dumps({"event": "exit", "status": 0}))
    except Exception:
        pass


async def _handle_client_text(session: pty_module.PtySession, raw: str) -> None:
    """Interpret JSON control frames; fall back to treating text as stdin."""
    payload: Optional[dict] = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            payload = parsed
    except json.JSONDecodeError:
        payload = None

    if payload is None:
        session.send(raw.encode("utf-8", errors="replace"))
        return

    kind = str(payload.get("type") or "").lower()
    if kind == "stdin":
        data = payload.get("data") or ""
        session.send(str(data).encode("utf-8", errors="replace"))
        return
    if kind == "resize":
        rows = int(payload.get("rows") or 0)
        cols = int(payload.get("cols") or 0)
        if rows > 0 and cols > 0:
            session.resize(rows, cols)
        return
    if kind == "signal":
        # Best-effort ctrl-c passthrough. xterm usually handles this by
        # sending \x03 directly, so this is only used when the client
        # explicitly wants to send a named signal.
        name = str(payload.get("name") or "").upper()
        if name == "SIGINT":
            session.send(b"\x03")
        elif name == "SIGQUIT":
            session.send(b"\x1c")
        return
    # Unknown type: ignore silently so future client features fail
    # gracefully on older servers.
