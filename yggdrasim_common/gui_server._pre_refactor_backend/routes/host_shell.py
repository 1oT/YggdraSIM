# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HTTP + WebSocket routes for the GUI ``Advanced > Host shell`` tab.

Three endpoints:

* ``GET  /api/host-shell/capabilities`` — capability snapshot the SPA
  consults before rendering the sidebar entry. Always returns 200 so a
  disabled host shell is distinguishable from a missing GUI bundle.
* ``GET  /api/host-shell/devices`` — best-effort enumeration of the
  serial devices the operator might want to paste into ``socat`` /
  ``tio`` / ``minicom``. Read-only, no side effects.
* ``WS   /api/host-shell`` — bridges xterm.js to a host-shell PTY. Same
  framing as ``/api/terminal/{module}``: binary frames carry raw PTY
  bytes; JSON text frames carry control messages
  (``{"type": "stdin" | "resize" | "signal" | "at_decode"}``).

The router is mounted unconditionally so the capability probe can
answer ``200 OK`` with ``enabled=false`` and the SPA can render the
disabled notice instead of guessing from a 404. The WebSocket
handler itself re-reads :func:`host_shell.is_enabled` on every
handshake and refuses connections (after sending one ``error`` text
frame) when the env flag is unset, so the always-mounted route is
safe to leave in place.

Full operator-facing walkthrough — enabling the env flag, sidebar UX,
HTTP / WebSocket payload shapes, ``at_decoded`` framing, modem-CLI
recipes, threat model, and troubleshooting — lives in
:file:`guides/GUI_HOST_SHELL_GUIDE.md`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from yggdrasim_common.gui_server import at_decoder, host_shell as host_shell_module
from yggdrasim_common.gui_server.auth import compare_tokens, token_id


_LOGGER = logging.getLogger("yggdrasim.gui.host_shell.route")


router = APIRouter(tags=["host_shell"])


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@router.get("/api/host-shell/capabilities", tags=["host_shell"])
def get_capabilities() -> dict:
    """Return the host-shell capability snapshot."""
    return host_shell_module.describe_capability()


@router.get("/api/host-shell/devices", tags=["host_shell"])
def get_devices() -> dict:
    """Return the serial-device picker payload.

    Devices are advisory — they only feed the "Insert at cursor"
    affordance in the SPA; the PTY is byte-for-byte transparent and the
    operator can type anything they like into it.
    """
    rows = host_shell_module.enumerate_serial_devices()
    return {"devices": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# WebSocket bridge
# ---------------------------------------------------------------------------


def _extract_token(websocket: WebSocket) -> str:
    """Mirror :func:`yggdrasim_common.gui_server.routes.terminal._extract_token`."""
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
    if isinstance(raw_token, str) and raw_token:
        return raw_token
    return ""


def _peer_for_log(websocket: WebSocket) -> str:
    client = getattr(websocket, "client", None)
    if client is None:
        return "?"
    host = getattr(client, "host", "?") or "?"
    port = getattr(client, "port", "?")
    return f"{host}:{port}"


@router.websocket("/api/host-shell")
async def host_shell_socket(websocket: WebSocket) -> None:
    """WebSocket handler: provide an interactive host-shell session over the GUI socket."""
    expected = _expected_token(websocket)
    provided = _extract_token(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth")
        _LOGGER.info("gui.host_shell.auth_rejected peer=%s", _peer_for_log(websocket))
        return

    if not host_shell_module.is_supported():
        await websocket.accept()
        await websocket.send_text(
            json.dumps({
                "event": "error",
                "message": "Host shell PTY bridge is not supported on this platform.",
            })
        )
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="platform")
        return

    if not host_shell_module.is_enabled():
        await websocket.accept()
        await websocket.send_text(
            json.dumps({
                "event": "error",
                "message": (
                    "Host shell is disabled. Set YGGDRASIM_GUI_HOST_SHELL=1 "
                    "and restart yggdrasim to enable it."
                ),
            })
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="disabled")
        return

    rows = _safe_int(websocket.query_params.get("rows"), default=30, lo=1, hi=500)
    cols = _safe_int(websocket.query_params.get("cols"), default=120, lo=1, hi=1000)
    spec = host_shell_module.HostShellStartSpec(rows=rows, cols=cols)

    await websocket.accept()
    peer = _peer_for_log(websocket)
    _LOGGER.warning(
        "gui.host_shell.opened token=%s peer=%s rows=%s cols=%s "
        "(operator has shell-equivalent capability over the bearer token)",
        token_id(provided),
        peer,
        rows,
        cols,
    )

    try:
        session = await host_shell_module.spawn_host_shell(spec)
    except (RuntimeError, ValueError) as error:
        await websocket.send_text(json.dumps({"event": "error", "message": str(error)}))
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="spawn")
        _LOGGER.warning("gui.host_shell.spawn_failed err=%s peer=%s", error, peer)
        return

    decoder_state = _DecoderState()
    await websocket.send_text(json.dumps({
        "event": "spawned",
        "pid": session.pid,
        "shell": host_shell_module.resolve_shell(),
    }))

    reader_task = asyncio.create_task(_pump_output(session, websocket, decoder_state))
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            if "bytes" in message and message["bytes"] is not None:
                payload = bytes(message["bytes"])
                session.send(payload)
                if decoder_state.enabled:
                    _emit_decoded(websocket, decoder_state.tx_accumulator, payload, "tx")
                continue
            text = message.get("text") or ""
            if len(text) == 0:
                continue
            await _handle_client_text(session, text, decoder_state)
    except WebSocketDisconnect:
        pass
    except Exception as error:  # pragma: no cover - defensive
        _LOGGER.warning("gui.host_shell.loop_error peer=%s err=%s", peer, error)
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
        _LOGGER.info("gui.host_shell.closed peer=%s", peer)


# ---------------------------------------------------------------------------
# Decoder plumbing
# ---------------------------------------------------------------------------


class _DecoderState:
    """Per-WebSocket decoder bookkeeping.

    Two accumulators because TX and RX line boundaries are independent
    (the operator typing ``AT+CSIM=...`` and the modem echoing ``OK``
    cross the wire in opposite directions and may interleave at the
    byte level on a real serial device).
    """

    __slots__ = ("enabled", "tx_accumulator", "rx_accumulator")

    def __init__(self) -> None:
        self.enabled: bool = False
        self.tx_accumulator = at_decoder.LineAccumulator()
        self.rx_accumulator = at_decoder.LineAccumulator()


async def _pump_output(session, websocket: WebSocket, decoder: _DecoderState) -> None:
    """Read bytes from the PTY, ship them as binary frames, optionally tee."""
    while not session.closed:
        chunk = await session.read_once(timeout=0.25)
        if chunk is None:
            break
        if len(chunk) == 0:
            await asyncio.sleep(0)
            continue
        try:
            await websocket.send_bytes(chunk)
        except (WebSocketDisconnect, RuntimeError):
            break
        if decoder.enabled:
            _emit_decoded(websocket, decoder.rx_accumulator, chunk, "rx")
    try:
        await websocket.send_text(json.dumps({"event": "exit", "status": 0}))
    except Exception:
        pass


def _emit_decoded(
    websocket: WebSocket,
    accumulator: at_decoder.LineAccumulator,
    chunk: bytes,
    direction: str,
) -> None:
    """Synchronous-style fan-out: every decoded entry becomes a JSON frame.

    We schedule the actual ``send_text`` on the event loop because
    ``send_text`` is a coroutine. ``ensure_future`` keeps the function
    callable from synchronous call sites (``session.send`` etc.) without
    awaiting them inline, which would block the receive loop.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    for entry in at_decoder.feed_and_decode(accumulator, chunk, direction):
        try:
            payload = json.dumps(entry)
        except (TypeError, ValueError):
            continue
        loop.create_task(_send_decoded_frame(websocket, payload))


async def _send_decoded_frame(websocket: WebSocket, payload: str) -> None:
    try:
        await websocket.send_text(payload)
    except (WebSocketDisconnect, RuntimeError):
        return


async def _handle_client_text(session, raw: str, decoder: _DecoderState) -> None:
    """JSON control frames; falls back to raw stdin for unknown shapes."""
    payload: Optional[dict] = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            payload = parsed
    except json.JSONDecodeError:
        payload = None

    if payload is None:
        chunk = raw.encode("utf-8", errors="replace")
        session.send(chunk)
        if decoder.enabled:
            for _ in decoder.tx_accumulator.feed(chunk):
                pass
        return

    kind = str(payload.get("type") or "").lower()
    if kind == "stdin":
        data = payload.get("data") or ""
        chunk = str(data).encode("utf-8", errors="replace")
        session.send(chunk)
        # AT decode for the typed-stdin path is handled by the caller
        # of _emit_decoded — this branch only handles the
        # PTY-write side-effect; the byte stream of typed input shows
        # up via the tx_accumulator already because the WS receive loop
        # mirrors the bytes through _emit_decoded for binary frames.
        return
    if kind == "resize":
        rows = int(payload.get("rows") or 0)
        cols = int(payload.get("cols") or 0)
        if rows > 0 and cols > 0:
            session.resize(rows, cols)
        return
    if kind == "signal":
        name = str(payload.get("name") or "").upper()
        if name == "SIGINT":
            session.send(b"\x03")
        elif name == "SIGQUIT":
            session.send(b"\x1c")
        return
    if kind == "at_decode":
        decoder.enabled = bool(payload.get("enabled"))
        return
    # Unknown control shape: silently ignored so older servers / newer
    # clients stay forward-compatible.


def _safe_int(value, *, default: int, lo: int, hi: int) -> int:
    """Clamp a query-parameter integer to a plausible range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return int(default)
    if parsed < lo:
        return int(lo)
    if parsed > hi:
        return int(hi)
    return parsed
