# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/actions/*`` — Command Center route layer.

Exposes three endpoints:

* ``GET  /api/actions``            — catalogue (grouped by subsystem)
* ``POST /api/actions/{id}/run``   — dispatch a synchronous action
* ``WS   /api/actions/{id}/stream``— dispatch a streaming action

The router intentionally has no per-action knowledge. It:

1. Looks the spec up via :func:`ensure_builtin_actions_loaded`.
2. Calls :func:`coerce_inputs` against the declared fields.
3. Invokes the dispatcher.
4. Wraps the result (or the async-generator's events) in a small JSON
   envelope so the UI always sees ``{"ok": bool, ...}``.

``/api/sessions`` is also exposed here as a sibling — dispatchers that
open a card session return a ``session_id`` the UI can later list or
close through this endpoint.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from yggdrasim_common.gui_server.actions.registry import (
    ActionSpec,
    coerce_inputs,
    ensure_builtin_actions_loaded,
)
from yggdrasim_common.gui_server.actions.registry import ActionContext
from yggdrasim_common.gui_server.auth import compare_tokens, token_id
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
            detail=f"action {action_id!r} is streaming — use the WebSocket endpoint.",
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

    ctx = ActionContext()
    try:
        result = await _invoke_dispatcher(spec, ctx, coerced)
    except HTTPException:
        raise
    except ValueError as user_error:
        # Typed user-input / session errors → 422 rather than 500.
        return RunResponse(ok=False, action_id=action_id, error=str(user_error))
    except KeyError as missing_session:
        return RunResponse(ok=False, action_id=action_id, error=str(missing_session))
    except Exception as server_error:  # noqa: BLE001 — surface the class + message
        _LOGGER.exception("action dispatch failed: %s", action_id)
        return RunResponse(
            ok=False,
            action_id=action_id,
            error=f"{type(server_error).__name__}: {server_error}",
        )

    if isinstance(result, dict):
        payload: dict[str, Any] = result
    else:
        payload = {"value": result}
    return RunResponse(ok=True, action_id=action_id, data=payload)


async def _invoke_dispatcher(spec: ActionSpec, ctx: ActionContext, coerced: dict[str, Any]) -> Any:
    dispatcher = spec.dispatcher
    if dispatcher is None:
        raise HTTPException(status_code=501, detail=f"no dispatcher for {spec.id!r}")

    if inspect.iscoroutinefunction(dispatcher):
        return await dispatcher(ctx, **coerced)
    # Sync dispatcher → push off the event loop thread.
    return await asyncio.to_thread(dispatcher, ctx, **coerced)


# ----------------------------------------------------------------------
# Streaming dispatch (WebSocket)
# ----------------------------------------------------------------------


def _extract_ws_token(websocket: WebSocket) -> str:
    header = websocket.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    qs_token = websocket.query_params.get("t")
    if qs_token:
        return str(qs_token)
    return ""


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
        # Some streaming actions delegate to an existing WS endpoint
        # (e.g. scp11.download_profile → /api/flows/download-profile).
        # Tell the client where to go.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="external-endpoint")
        return

    await websocket.accept()
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

    ctx = ActionContext()
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
        # Drain & close the async generator explicitly so any worker
        # thread / queue / card connection it owns is released right
        # away. Relying on GC is non-deterministic and pre-CPython 3.13
        # used to leave the worker pumping events into a queue nobody
        # reads, which counted as a slow per-action memory leak under
        # long-running GUI sessions.
        if inspect.isasyncgen(async_iter):
            try:
                await async_iter.aclose()
            except Exception:  # noqa: BLE001 — best-effort cleanup
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
