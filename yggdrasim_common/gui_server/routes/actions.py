# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``/api/actions/*`` -- Command Center route layer.

Exposes three endpoints:

* ``GET  /api/actions``            -- catalogue (grouped by subsystem)
* ``POST /api/actions/{id}/run``   -- dispatch a synchronous action
* ``WS   /api/actions/{id}/stream``-- dispatch a streaming action

The router intentionally has no per-action knowledge. It:

1. Looks the spec up via :func:`ensure_builtin_actions_loaded`.
2. Calls :func:`coerce_inputs` against the declared fields.
3. Invokes the dispatcher.
4. Wraps the result (or the async-generator's events) in a small JSON
   envelope so the UI always sees ``{"ok": bool, ...}``.

``/api/sessions`` is also exposed here as a sibling -- dispatchers that
open a card session return a ``session_id`` the UI can later list or
close through this endpoint.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from yggdrasim_common.cancellation import register_active_event
from yggdrasim_common.gui_server.actions.registry import (
    ActionSpec,
    coerce_inputs,
    ensure_builtin_actions_loaded,
)
from yggdrasim_common.gui_server.actions.registry import ActionContext
from yggdrasim_common.gui_server.auth import (
    compare_tokens,
    token_id,
    websocket_accept_protocol,
    websocket_bearer,
)
from yggdrasim_common import reader_claims
from yggdrasim_common.gui_server import live_trace
from yggdrasim_common.gui_server.sessions import get_manager


_LOGGER = logging.getLogger("yggdrasim.gui.actions.routes")

router = APIRouter(tags=["actions"])


# ----------------------------------------------------------------------
# Catalogue
# ----------------------------------------------------------------------


class ActionSummary(BaseModel):
    id: str
    subsystem: str
    title: str
    description: str
    output_kind: str
    inputs: list[dict[str, Any]]
    requires_card: bool
    # The page reads this to ask for authentication before it opens a gated
    # form; a field the model lacks is dropped from the catalogue silently.
    requires_auth: bool = False
    streams: bool
    tags: list[str]


class CatalogueResponse(BaseModel):
    count: int
    subsystems: dict[str, list[ActionSummary]]


@router.get("/api/actions", response_model=CatalogueResponse)
def list_actions() -> CatalogueResponse:
    """Return a JSON list of all registered operator actions and their schemas."""
    registry = ensure_builtin_actions_loaded()
    groups: dict[str, list[ActionSummary]] = {}
    count = 0
    for subsystem, specs in registry.by_subsystem().items():
        rendered: list[ActionSummary] = []
        for spec in specs:
            schema = spec.to_schema()
            rendered.append(ActionSummary(**schema))
            count += 1
        groups[subsystem] = rendered
    return CatalogueResponse(count=count, subsystems=groups)


# ----------------------------------------------------------------------
# Synchronous dispatch
# ----------------------------------------------------------------------


class RunRequest(BaseModel):
    inputs: dict[str, Any] = Field(default_factory=dict)
    # Chosen by the page: tags the lines this run prints on the live trace
    # socket (/api/events/trace) so the page can show them under the action.
    trace_id: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.-]*$")


class RunResponse(BaseModel):
    ok: bool
    action_id: str
    data: dict[str, Any] | None = None
    error: str | None = None


@router.post("/api/actions/{action_id}/run", response_model=RunResponse)
async def run_action(action_id: str, body: RunRequest) -> RunResponse:
    """Execute a named operator action synchronously and return the result JSON."""
    registry = ensure_builtin_actions_loaded()
    try:
        spec = registry.get(action_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown action: {action_id!r}")

    if spec.streams:
        raise HTTPException(
            status_code=400,
            detail=f"action {action_id!r} is streaming -- use the WebSocket endpoint.",
        )
    if spec.dispatcher is None:
        raise HTTPException(
            status_code=501,
            detail=f"action {action_id!r} has no synchronous dispatcher.",
        )

    try:
        coerced = coerce_inputs(spec, body.inputs or {})
    except ValueError as validation_error:
        raise HTTPException(status_code=422, detail=str(validation_error))

    cancel_event = threading.Event()
    register_active_event(cancel_event)
    ctx = ActionContext(extras={"cancel_event": cancel_event})
    _trace_run, trace_token = live_trace.begin_run(action_id, body.trace_id)
    try:
        result = await _invoke_dispatcher(spec, ctx, coerced)
    except HTTPException:
        raise
    except ValueError as user_error:
        # Typed user-input / session errors → 422 rather than 500.
        return RunResponse(ok=False, action_id=action_id, error=str(user_error))
    except FileNotFoundError as missing_file:
        return RunResponse(ok=False, action_id=action_id, error=str(missing_file))
    except KeyError as missing_session:
        return RunResponse(ok=False, action_id=action_id, error=str(missing_session))
    except reader_claims.ReaderBusyError as busy:
        return RunResponse(ok=False, action_id=action_id, error=str(busy))
    except RuntimeError as runtime_error:
        message = str(runtime_error)
        if message.startswith("no_card:"):
            return RunResponse(ok=False, action_id=action_id, error=message)
        _LOGGER.exception("action dispatch failed: %s", action_id)
        return RunResponse(
            ok=False,
            action_id=action_id,
            error=f"{type(runtime_error).__name__}: {runtime_error}",
        )
    except Exception as server_error:  # noqa: BLE001 -- surface the class + message
        _LOGGER.exception("action dispatch failed: %s", action_id)
        return RunResponse(
            ok=False,
            action_id=action_id,
            error=f"{type(server_error).__name__}: {server_error}",
        )
    finally:
        live_trace.end_run(trace_token)

    if isinstance(result, dict):
        payload = dict(result)
    else:
        payload = {"value": result}
    if spec.subsystem == "SCP03":
        session_id = str(coerced.get("session_id") or "").strip()
        if session_id:
            try:
                card_session = get_manager().get(session_id)
                handle = card_session.handle
                transporter = handle.get("transporter") if isinstance(handle, dict) else None
                secure_session = getattr(transporter, "session", None)
                payload["session_authenticated"] = bool(
                    getattr(secure_session, "is_authenticated", False)
                )
            except (KeyError, AttributeError):
                payload["session_authenticated"] = False
    return RunResponse(ok=True, action_id=action_id, data=payload)


def _session_for_serialisation(coerced: dict[str, Any]) -> Any:
    """Return the live card session this call targets, or None.

    A session owns one physical card and one PC/SC connection, so two
    dispatchers running against it concurrently interleave APDUs on the
    same channel and mutate the same file-system cursor. A missing or
    already-reaped session is not an error here -- the dispatcher itself
    reports that far more precisely than this helper could.
    """
    session_id = str(coerced.get("session_id") or "").strip()
    if len(session_id) == 0:
        return None
    try:
        return get_manager().get(session_id)
    except Exception:  # noqa: BLE001
        return None


def _action_reader(spec: ActionSpec, coerced: dict[str, Any], session: Any) -> str | None:
    """The reader a call drives, as the claims key it, or None for no card.

    A session-bound call drives its session's reader (a SAIP authoring
    session holds none); any other call names it in its reader field, unless
    its spec says this call does not use it (``ActionSpec.uses_reader``).
    """
    if session is not None:
        name = str((getattr(session, "metadata", None) or {}).get("reader_name") or "").strip()
        return reader_claims.reader_key(name) if len(name) > 0 else None
    for field in spec.inputs:
        if getattr(field, "kind", "") == "reader":
            uses_reader = getattr(spec, "uses_reader", None)
            if uses_reader is not None and not uses_reader(coerced):
                return None
            return reader_claims.reader_key(coerced.get(field.name))
    return None


def _claim_reader(
    spec: ActionSpec, coerced: dict[str, Any], session: Any, *, long_running: bool
) -> tuple[str, object] | None:
    """Claim the call's reader (yggdrasim_common.reader_claims) on the calling thread.

    Called off the event loop: the claim may wait for another operation, and
    naming the default reader enumerates PC/SC.
    """
    reader = _action_reader(spec, coerced, session)
    if reader is None:
        return None
    return reader, reader_claims.claim(reader, spec.title, long_running=long_running)


def _release_reader(claimed: tuple[str, object] | None) -> None:
    if claimed is not None:
        reader_claims.release(*claimed)


def _call_dispatcher_claimed(
    dispatcher: Any, spec: ActionSpec, session: Any, ctx: ActionContext, coerced: dict[str, Any]
) -> Any:
    # On the worker thread, never on the event loop, so a slow card operation
    # or a wait for its reader blocks only its own thread. The reader is
    # claimed before the session lock and given back after it.
    claimed = _claim_reader(spec, coerced, session, long_running=False)
    try:
        if session is None:
            return dispatcher(ctx, **coerced)
        with session._lock:
            return dispatcher(ctx, **coerced)
    finally:
        _release_reader(claimed)


async def _invoke_dispatcher(spec: ActionSpec, ctx: ActionContext, coerced: dict[str, Any]) -> Any:
    dispatcher = spec.dispatcher
    if dispatcher is None:
        raise HTTPException(status_code=501, detail=f"no dispatcher for {spec.id!r}")

    session = _session_for_serialisation(coerced)
    if inspect.iscoroutinefunction(dispatcher):
        claimed = await asyncio.to_thread(_claim_reader, spec, coerced, session, long_running=False)
        try:
            return await dispatcher(ctx, **coerced)
        finally:
            _release_reader(claimed)
    # Sync dispatcher → push off the event loop thread: one operation at a
    # time per reader, and per session within it, so concurrent requests
    # cannot interleave APDUs on one card.
    return await asyncio.to_thread(_call_dispatcher_claimed, dispatcher, spec, session, ctx, coerced)


# ----------------------------------------------------------------------
# Streaming dispatch (WebSocket)
# ----------------------------------------------------------------------


def _extract_ws_token(websocket: WebSocket) -> str:
    return websocket_bearer(websocket)


def _expected_ws_token(websocket: WebSocket) -> str:
    raw = getattr(websocket.app.state, "gui_token", None)
    return str(raw) if isinstance(raw, str) else ""


@router.websocket("/api/actions/{action_id}/stream")
async def stream_action(websocket: WebSocket, action_id: str) -> None:
    """Execute a named operator action and stream progress events as SSE."""
    expected = _expected_ws_token(websocket)
    provided = _extract_ws_token(websocket)
    if len(expected) == 0 or not compare_tokens(expected, provided):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth")
        return

    registry = ensure_builtin_actions_loaded()
    try:
        spec = registry.get(action_id)
    except KeyError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="no-such-action")
        return

    if not spec.streams:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="not-streaming")
        return
    if spec.dispatcher is None:
        # A streaming action without a dispatcher is served by another WS
        # endpoint; this route has nothing to run for it.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="external-endpoint")
        return

    await websocket.accept(subprotocol=websocket_accept_protocol(websocket))
    _LOGGER.info("gui.action.stream.open id=%s token=%s", action_id, token_id(provided))

    try:
        first_frame = await websocket.receive_text()
    except WebSocketDisconnect:
        return
    try:
        start_msg = json.loads(first_frame)
    except json.JSONDecodeError as error:
        await websocket.send_text(json.dumps({"level": "error", "message": f"bad payload: {error}"}))
        await websocket.close()
        return
    if str(start_msg.get("type") or "") != "start":
        await websocket.send_text(json.dumps({"level": "error", "message": "first frame must have type=start"}))
        await websocket.close()
        return

    inputs = start_msg.get("inputs") or {}
    try:
        coerced = coerce_inputs(spec, inputs)
    except ValueError as validation_error:
        await websocket.send_text(
            json.dumps({"level": "error", "message": f"validation: {validation_error}"})
        )
        await websocket.close()
        return

    # A stream holds its reader until it ends; one already held by another
    # stream is refused at once, one held by a short action is waited for.
    try:
        claimed = await asyncio.to_thread(
            _claim_reader, spec, coerced, _session_for_serialisation(coerced), long_running=True
        )
    except reader_claims.ReaderBusyError as busy:
        await websocket.send_text(json.dumps({"level": "error", "message": str(busy)}))
        await websocket.close()
        return
    try:
        await _run_stream(websocket, spec, action_id, coerced)
    finally:
        _release_reader(claimed)


async def _run_stream(websocket: WebSocket, spec: ActionSpec, action_id: str, coerced: dict[str, Any]) -> None:
    """Run a streaming dispatcher and forward its events until it ends."""
    cancel_event = threading.Event()
    register_active_event(cancel_event)
    ctx = ActionContext(extras={"cancel_event": cancel_event})
    dispatcher = spec.dispatcher
    try:
        stream = dispatcher(ctx, **coerced)
    except Exception as err:  # noqa: BLE001
        await websocket.send_text(json.dumps({"level": "error", "message": f"{type(err).__name__}: {err}"}))
        await websocket.close()
        return

    # We accept both async-generators and regular async coroutines that
    # return a dict. Promote the latter to a single-event stream.
    if inspect.isasyncgen(stream):
        async_iter = stream
    elif inspect.iscoroutine(stream):
        async def _single_event_stream():
            value = await stream
            if isinstance(value, dict):
                yield value
            else:
                yield {"level": "info", "message": str(value)}
            yield {"level": "done", "message": "dispatcher returned."}

        async_iter = _single_event_stream()
    else:
        await websocket.send_text(
            json.dumps({"level": "error", "message": "dispatcher did not return an async generator."})
        )
        await websocket.close()
        return

    async def _listen_for_cancel() -> None:
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if str(payload.get("type") or "") == "cancel":
                    cancel_event.set()
                    return
        except WebSocketDisconnect:
            cancel_event.set()
        except Exception:
            cancel_event.set()

    cancel_listener = asyncio.create_task(_listen_for_cancel())

    try:
        async for event in async_iter:
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception as stream_error:  # noqa: BLE001
        _LOGGER.exception("streaming dispatcher raised: %s", action_id)
        try:
            await websocket.send_text(
                json.dumps({"level": "error", "message": f"{type(stream_error).__name__}: {stream_error}"})
            )
        except Exception:
            pass
    finally:
        cancel_event.set()
        cancel_listener.cancel()
        try:
            await cancel_listener
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
        # Drain & close the async generator explicitly so any worker
        # thread / queue / card connection it owns is released right
        # away. Relying on GC is non-deterministic and pre-CPython 3.13
        # used to leave the worker pumping events into a queue nobody
        # reads, which counted as a slow per-action memory leak under
        # long-running GUI sessions.
        if inspect.isasyncgen(async_iter):
            try:
                await async_iter.aclose()
            except Exception:  # noqa: BLE001 -- best-effort cleanup
                pass
        try:
            await websocket.close()
        except Exception:
            pass
        _LOGGER.info("gui.action.stream.close id=%s", action_id)


# ----------------------------------------------------------------------
# Session listing / close
# ----------------------------------------------------------------------


class SessionListResponse(BaseModel):
    count: int
    sessions: list[dict[str, Any]]


@router.get("/api/sessions", response_model=SessionListResponse)
def list_sessions() -> SessionListResponse:
    sessions = get_manager().list()
    return SessionListResponse(count=len(sessions), sessions=sessions)


@router.delete("/api/sessions/{session_id}")
def close_session(session_id: str) -> dict[str, Any]:
    closed = get_manager().close(session_id)
    if not closed:
        raise HTTPException(status_code=404, detail="session not found")
    return {"ok": True, "closed": 1}
