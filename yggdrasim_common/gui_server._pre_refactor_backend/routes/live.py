# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/live/*`` — hardware-adjacent routes (Milestone B-3).

This router wraps the live PC/SC + SGP.22 surface. Unlike the pure-
function routes in :mod:`.tools`, these endpoints touch real hardware
(reader enumeration) and a real network stack (SM-DP+). They are still
best-effort: if ``pyscard`` is not available, the reader list falls
back to ``[]`` with a descriptive status rather than 500-ing the whole
panel.

The download-profile flow runs the existing ``SGP22Orchestrator`` in a
background thread and tees stdout/stderr into the WebSocket so the GUI
can render a live progress log. This matches the "smoke-test the
real flow" requirement in §11.2 of ``V2_UNIVERSAL_GUI_PLAN.md``
without forcing invasive instrumentation into the orchestrator itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import threading
import traceback
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel

from yggdrasim_common.gui_server.auth import compare_tokens, token_id


_LOGGER = logging.getLogger("yggdrasim.gui.live")

router = APIRouter(tags=["live"])


# --- reader enumeration (HTTP) -----------------------------------------


class ReaderInfo(BaseModel):
    name: str
    atr_hex: str
    status: str
    kind: str = "local"
    source_url: str = ""


class ReadersResponse(BaseModel):
    backend: str
    readers: list[ReaderInfo]
    note: str


def _session_atr_by_reader_name() -> dict[str, str]:
    """Map reader-name → cached ATR from any live scp03 session.

    The reader-bar polls ``/api/live/readers`` every 5 s. Before this
    helper existed, the poll opened a *second* PC/SC handle to each
    reader, grabbed the ATR, and disconnected — which pyscard
    translates to ``SCardDisconnect(hcard, SCARD_UNPOWER_CARD)`` by
    default. On ``SCARD_SHARE_SHARED`` setups that unpower is visible
    to the *first* handle (our live scan session): the card cold-
    resets behind the scan's back, its ``current_fid`` points at a
    DF that's no longer selected, and the next click in the file
    tree fails with 6A82 ("file not found").

    Symptoms the operator sees:
      * Every file click fails and triggers ``scp03.recover_session``
        (cold reset + rescan), so the tree "rescans on every click".
      * The preview briefly shows "reading…", then falls into the
        recovery banner, then eventually renders — ~2 s per click
        wasted.

    The fix is two-pronged:
      1. Skip the ATR probe entirely when the reader already has a
         live scp03 session — the session knows the ATR and we have
         nothing to learn. This short-circuit is implemented here.
      2. For readers *without* a session, we still probe but use
         ``SCARD_LEAVE_CARD`` so the probe's ``disconnect()`` doesn't
         power-cycle the card (see ``_probe_reader``).
    """
    mapping: dict[str, str] = {}
    try:
        from yggdrasim_common.gui_server.sessions import get_manager
    except Exception:  # noqa: BLE001 — import-safe in the test sandbox
        return mapping
    try:
        for entry in get_manager().list():
            if entry.get("kind") != "scp03":
                continue
            md = entry.get("metadata") or {}
            reader_name = str(md.get("reader_name") or "").strip()
            atr_hex = str(md.get("atr_hex") or "").strip().upper()
            if not reader_name or reader_name == "(default)":
                continue
            if atr_hex:
                mapping[reader_name] = atr_hex
    except Exception:  # noqa: BLE001
        return mapping
    return mapping


def _probe_remote_bridge_reader() -> ReaderInfo | None:
    """Return a ``ReaderInfo`` row for the configured remote card bridge.

    Returns ``None`` when no bridge is configured. Always returns a
    populated row otherwise — even an unreachable bridge gets a row so
    operators can see *why* it isn't usable without leaving the GUI.
    The probe shells out to ``GET /status`` on the bridge with a tight
    2 s timeout so we never wedge the reader poll on a stuck remote.
    """
    try:
        from yggdrasim_common.card_backend import (
            _resolve_card_relay_url,
            _resolve_card_relay_token,
        )
    except Exception:  # noqa: BLE001
        return None

    try:
        relay_url, _source = _resolve_card_relay_url()
    except Exception:  # noqa: BLE001
        return None
    if len(relay_url) == 0:
        return None

    base_url = relay_url
    if base_url.endswith("/apdu"):
        base_url = base_url[: -len("/apdu")]
    base_url = base_url.rstrip("/")

    display_name = f"\U0001F310 remote@{base_url}"

    try:
        token = _resolve_card_relay_token(allow_marker=True)
    except Exception:  # noqa: BLE001
        token = ""

    import urllib.error
    import urllib.request

    request = urllib.request.Request(f"{base_url}/status", method="GET")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=2.0) as response:
            payload_raw = response.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(payload_raw)
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        atr_hex = str(payload.get("atrHex") or payload.get("atr") or "").strip()
        reader_name = str(payload.get("reader") or "").strip()
        if len(reader_name) > 0:
            display_name = f"\U0001F310 {reader_name} (remote@{base_url})"
        if len(atr_hex) > 0:
            return ReaderInfo(
                name=display_name,
                atr_hex=atr_hex.upper(),
                status="card present (remote bridge)",
                kind="remote",
                source_url=base_url,
            )
        return ReaderInfo(
            name=display_name,
            atr_hex="",
            status="remote bridge online (no card / ATR not reported)",
            kind="remote",
            source_url=base_url,
        )
    except urllib.error.HTTPError as error:
        if int(error.code) == 401:
            status_text = "remote bridge online but token rejected (HTTP 401)"
        else:
            status_text = f"remote bridge HTTP {error.code} ({error.reason})"
        return ReaderInfo(
            name=display_name,
            atr_hex="",
            status=status_text,
            kind="remote",
            source_url=base_url,
        )
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as error:
        return ReaderInfo(
            name=display_name,
            atr_hex="",
            status=f"remote bridge unreachable: {error.__class__.__name__}",
            kind="remote",
            source_url=base_url,
        )


@router.get("/api/live/readers", response_model=ReadersResponse)
def list_readers() -> ReadersResponse:
    """Return a JSON list of available PCSC readers and simulated-card backends."""
    remote_row = _probe_remote_bridge_reader()

    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError:
        rows: list[ReaderInfo] = []
        if remote_row is not None:
            rows.append(remote_row)
        if len(rows) > 0:
            return ReadersResponse(
                backend="remote-only",
                readers=rows,
                note="pyscard not installed locally — only the configured remote card bridge is available.",
            )
        return ReadersResponse(
            backend="missing",
            readers=[],
            note="pyscard is not installed — install it with `pip install pyscard` to enumerate PC/SC readers.",
        )

    try:
        reader_list = list_pcsc_readers()
    except Exception as error:  # pyscard raises SmartcardException on PCSC daemon issues
        rows = []
        if remote_row is not None:
            rows.append(remote_row)
        return ReadersResponse(
            backend="error" if remote_row is None else "remote-only",
            readers=rows,
            note=f"PC/SC enumeration failed: {error}",
        )

    session_atrs = _session_atr_by_reader_name()

    rows: list[ReaderInfo] = []
    for reader in reader_list:
        cached_atr = session_atrs.get(str(reader), "")
        info = _probe_reader(reader, cached_atr=cached_atr)
        rows.append(info)

    if remote_row is not None:
        rows.append(remote_row)

    local_count = len(rows) - (1 if remote_row is not None else 0)
    if remote_row is not None:
        note = f"found {local_count} local reader(s) + 1 remote bridge."
    else:
        note = "found " + str(local_count) + " reader(s)."
    if local_count == 0 and remote_row is None:
        note = "no readers detected — check USB connection and pcscd service."
    return ReadersResponse(backend="pyscard", readers=rows, note=note)


class AtrProbeRequest(BaseModel):
    reader: str


@router.post("/api/live/atr", response_model=ReaderInfo)
def probe_single_atr(body: AtrProbeRequest) -> ReaderInfo:
    """Connect to one reader, read the ATR, and return a JSON summary."""
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError:
        raise HTTPException(status_code=503, detail="pyscard not installed.")

    needle = body.reader.strip()
    if len(needle) == 0:
        raise HTTPException(status_code=400, detail="reader name is required.")

    reader_list = list_pcsc_readers()
    for reader in reader_list:
        if str(reader) == needle:
            session_atrs = _session_atr_by_reader_name()
            cached_atr = session_atrs.get(str(reader), "")
            return _probe_reader(reader, cached_atr=cached_atr)
    raise HTTPException(status_code=404, detail=f"reader not found: {needle}")


def _probe_reader(reader: Any, *, cached_atr: str = "") -> ReaderInfo:
    """Non-destructively probe a PC/SC reader for its card's ATR.

    Two critical non-obvious behaviours:

    * **Short-circuit on cached ATR** — if ``cached_atr`` is non-empty
      (populated from a live scp03 session's metadata in the caller),
      we skip the PC/SC round-trip entirely. Opening a second handle
      to a reader that already hosts an active SCP03 session racks up
      PC/SC churn for no gain: we already know the ATR. Avoiding the
      handle also sidesteps the card-reset hazard described below.

    * **``SCARD_LEAVE_CARD`` on disconnect** — pyscard's
      ``CardConnection.connect()`` defaults ``disposition`` to
      ``SCARD_UNPOWER_CARD``, which is what ``disconnect()`` passes
      to ``SCardDisconnect``. On ``SCARD_SHARE_SHARED`` setups that
      unpower propagates to the card regardless of other handles —
      the card cold-resets between GUI polls. The explicit
      ``disposition=SCARD_LEAVE_CARD`` keeps the card powered up so
      the primary scan session's APDU state (selected DF, secure
      channel, etc.) survives the 5 s poll.

    Returns a descriptive status on error rather than raising, so the
    reader table can still list offline / empty readers.
    """
    name = str(reader)
    if cached_atr:
        return ReaderInfo(
            name=name,
            atr_hex=cached_atr,
            status="card present (cached from live session)",
        )
    # Lazy-import the PC/SC constant so this module stays importable
    # in environments without pyscard (tests, headless sandboxes).
    leave_card = 0  # SCARD_LEAVE_CARD — numeric default, overridden below
    try:
        from smartcard.scard import SCARD_LEAVE_CARD as _SCARD_LEAVE_CARD
        leave_card = _SCARD_LEAVE_CARD
    except Exception:  # noqa: BLE001
        pass
    connection = None
    try:
        connection = reader.createConnection()
        # pyscard's connect() accepts ``disposition`` as a keyword
        # and stashes it on the instance; disconnect() reads it back
        # when issuing SCardDisconnect. Passing it here is the
        # low-friction way to avoid monkey-patching ``connection.disposition``
        # after the fact.
        try:
            connection.connect(disposition=leave_card)
        except TypeError:
            # Older pyscard releases don't expose ``disposition`` as a
            # kwarg. Fall back to the default connect, then tweak the
            # instance attribute before disconnect.
            connection.connect()
            try:
                connection.disposition = leave_card
            except Exception:  # noqa: BLE001
                pass
        atr = connection.getATR() or []
        atr_hex = "".join("{:02X}".format(int(byte)) for byte in atr)
        return ReaderInfo(name=name, atr_hex=atr_hex, status="card present")
    except Exception as error:
        return ReaderInfo(name=name, atr_hex="", status=f"no card or error: {error}")
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                pass


# --- download-profile flow (WebSocket) ---------------------------------


@dataclass
class FlowContext:
    reader: str
    activation_code: str
    confirmation_code: str = ""
    dry_run: bool = False
    cancel_event: threading.Event = field(default_factory=threading.Event)


def _extract_token(websocket: WebSocket) -> str:
    header = websocket.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    qs_token = websocket.query_params.get("t")
    if qs_token:
        return str(qs_token)
    return ""


def _expected_token(websocket: WebSocket) -> str:
    raw_token = getattr(websocket.app.state, "gui_token", None)
    if isinstance(raw_token, str) and raw_token:
        return raw_token
    return ""


@router.websocket("/api/flows/download-profile")
async def download_profile_flow(websocket: WebSocket) -> None:
    """Trigger a profile-download flow for the specified EID/reader and stream progress events."""
    expected = _expected_token(websocket)
    provided = _extract_token(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth")
        return

    await websocket.accept()
    _LOGGER.info("gui.flow.opened kind=download-profile token=%s", token_id(provided))

    event_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    async def _emit(level: str, message: str, **extra: Any) -> None:
        await event_queue.put({"level": level, "message": message, **extra})

    await _emit("info", "waiting for start payload…")

    # Wait for start payload.
    try:
        first = await websocket.receive_text()
    except WebSocketDisconnect:
        return
    try:
        start_msg = json.loads(first)
    except json.JSONDecodeError as error:
        await websocket.send_text(json.dumps({"level": "error", "message": f"bad payload: {error}"}))
        await websocket.close()
        return
    if str(start_msg.get("type") or "") != "start":
        await websocket.send_text(json.dumps({"level": "error", "message": "first frame must have type=start"}))
        await websocket.close()
        return

    ctx = FlowContext(
        reader=str(start_msg.get("reader") or ""),
        activation_code=str(start_msg.get("activation_code") or ""),
        confirmation_code=str(start_msg.get("confirmation_code") or ""),
        dry_run=bool(start_msg.get("dry_run") or False),
    )
    if len(ctx.reader) == 0 or len(ctx.activation_code) == 0:
        await websocket.send_text(
            json.dumps({"level": "error", "message": "reader and activation_code are required."})
        )
        await websocket.close()
        return

    # Spawn the orchestrator on a thread and bridge its stdout to the WS.
    worker = threading.Thread(
        target=_run_flow_worker,
        args=(ctx, loop, event_queue),
        name="yggdrasim-gui-download-flow",
        daemon=True,
    )
    worker.start()

    # Concurrent: forward event_queue to the WS, and listen for cancel messages.
    async def _forward_events() -> None:
        while True:
            event = await event_queue.get()
            if event is None:
                return
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                return

    forward_task = asyncio.create_task(_forward_events())

    try:
        while worker.is_alive():
            try:
                message = await asyncio.wait_for(websocket.receive_text(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                ctx.cancel_event.set()
                break
            try:
                payload = json.loads(message)
            except json.JSONDecodeError:
                continue
            if str(payload.get("type") or "") == "cancel":
                ctx.cancel_event.set()
                await _emit("warn", "cancel requested — orchestrator will stop at next phase boundary.")
    finally:
        # Let the worker finish emitting its final events, then close.
        worker.join(timeout=2.0)
        await event_queue.put(None)
        try:
            await forward_task
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
        _LOGGER.info("gui.flow.closed kind=download-profile")


def _run_flow_worker(ctx: FlowContext, loop: asyncio.AbstractEventLoop, event_queue: asyncio.Queue) -> None:
    """Body of the background thread.

    Tees stdout/stderr into the WS, parses the activation code, and
    launches the SGP.22 orchestrator. Every emitted line is wrapped in
    a JSON event so the frontend can style levels.
    """

    def _post(level: str, message: str, **extra: Any) -> None:
        # Thread-safe scheduling back onto the asyncio loop.
        asyncio.run_coroutine_threadsafe(
            event_queue.put({"level": level, "message": message, **extra}),
            loop,
        )

    try:
        smdp, matching_id = _parse_activation_code(ctx.activation_code)
    except ValueError as error:
        _post("error", f"activation-code parse failed: {error}")
        _post("done", "flow aborted.")
        return

    _post("info", f"SM-DP+ address: {smdp}")
    _post("info", f"matching id:    {matching_id or '(auto)'}")
    _post("info", f"reader:         {ctx.reader}")
    if ctx.dry_run:
        _post("info", "dry-run: skipping GetBoundProfilePackage + install.")

    try:
        _post("info", "connecting to reader…")
        reader_index = _resolve_reader_index(ctx.reader)

        # Use the SCP11 live PC/SC channel directly: it implements the
        # orchestrator-facing ``send(bytes, log_name) → bytes`` interface
        # and handles 61/6C retries. ``dataclasses.replace`` gives us a
        # cfg copy with the reader override so we don't touch the
        # frozen default singleton.
        from dataclasses import replace
        from SCP11.live.config import SGPConfig
        from SCP11.live.transport import PcscApduChannel

        cfg = replace(SGPConfig(), READER_INDEX=int(reader_index))
        apdu_channel = PcscApduChannel(reader_index=int(reader_index))
        _post("info", "card connected; ATR capture complete.")

        if ctx.dry_run:
            try:
                apdu_channel._conn.disconnect()
            except Exception:
                pass
            _post("done", "dry-run success — card reachable, flow not executed.")
            return

        _post("info", "loading SCP11 live orchestrator…")
        from SCP11.live.orchestrator import SGP22Orchestrator

        _post("info", "orchestrator ready; launching run_flow()")

        # Tee stdout/stderr into the event queue so the orchestrator's
        # native progress prints reach the GUI without invasive changes.
        capture = _CapturingStream(post=_post)
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=apdu_channel)
            if ctx.cancel_event.is_set():
                _post("warn", "cancelled before run_flow could start.")
            else:
                orchestrator.run_flow(matching_id=matching_id, smdp_address=smdp)

        try:
            apdu_channel._conn.disconnect()
        except Exception:
            pass

        _post("done", "run_flow completed.")
    except Exception as error:
        _post("error", f"{type(error).__name__}: {error}")
        _post("error", traceback.format_exc())
        _post("done", "flow aborted.")


def _parse_activation_code(code: str) -> tuple[str, str]:
    """Split an SGP.22 activation code into ``(smdp_address, matching_id)``.

    Accepted shapes:

    * ``LPA:1$smdp.example.com$MATCHING`` (standard)
    * ``smdp.example.com$MATCHING`` (CLI-friendly shorthand)
    * bare ``smdp.example.com`` → empty matching id
    """
    text = (code or "").strip()
    if text.startswith("LPA:1$"):
        text = text[len("LPA:1$"):]
    parts = text.split("$")
    if len(parts) == 1:
        smdp = parts[0].strip()
        matching = ""
    else:
        smdp = parts[0].strip()
        matching = parts[1].strip() if len(parts) > 1 else ""
    if len(smdp) == 0:
        raise ValueError("SM-DP+ address is empty.")
    return smdp, matching


def _resolve_reader_index(reader_name: str) -> int:
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError as error:
        raise RuntimeError("pyscard not available") from error
    for idx, reader in enumerate(list_pcsc_readers()):
        if str(reader) == reader_name:
            return idx
    raise RuntimeError(f"reader not found: {reader_name}")


class _CapturingStream(io.TextIOBase):
    """Line-oriented ``io.TextIOBase`` proxy — every newline-terminated
    chunk becomes a single WS event. Partial lines are buffered until
    the next ``\n`` so we don't flood the socket with per-character
    frames when the orchestrator uses ``\r`` to redraw progress bars.
    """

    def __init__(self, post) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self._post = post
        self._buffer = ""

    def write(self, data: str) -> int:
        """Serialise and stream a live-session event to the WebSocket client."""
        self._buffer += data
        while "\n" in self._buffer:
            line, _, rest = self._buffer.partition("\n")
            self._buffer = rest
            if len(line) == 0:
                continue
            level = _infer_level(line)
            self._post(level, line)
        return len(data)

    def flush(self) -> None:
        if len(self._buffer) > 0:
            level = _infer_level(self._buffer)
            self._post(level, self._buffer)
            self._buffer = ""


def _infer_level(line: str) -> str:
    lowered = line.lower()
    if "[-]" in line or "error" in lowered or "failed" in lowered:
        return "error"
    if "warn" in lowered or "!" in line[:5]:
        return "warn"
    if "ok" in lowered or "[+]" in line or "✓" in line:
        return "info"
    return "info"
