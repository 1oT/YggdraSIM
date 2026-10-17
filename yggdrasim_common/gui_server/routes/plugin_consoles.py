# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""GUI routes of the plugin consoles: list, pills, status, start, stop, fill, command, stream, help.

One route family serves every console a loaded plugin registered in
``plugin_console_registry``; the console id in the path selects it. The list
answers ``available: false`` with the loader's reason when plugin loading is
off. The polls (list, pills, status, stream) never answer 500: a provider failure
comes back as the console's ``last_error`` or the stream's ``error``. Input
is checked by ``plugin_console_values`` before a provider sees it, and every
answer goes through ``plugin_console_output`` before the browser does.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from yggdrasim_common.plugin_runtime import plugin_status_report

from .. import plugin_console_output as output
from ..plugin_console_registry import console_registry
from ..plugin_console_values import ConsoleInputError, check_command_line, check_values, render_action_line

_LOGGER = logging.getLogger("yggdrasim.gui.plugin_consoles")

router = APIRouter(prefix="/api/plugin-consoles", tags=["plugin-consoles"])


class StartRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class FillRequest(BaseModel):
    field: str = ""
    values: dict[str, Any] = Field(default_factory=dict)


class CommandRequest(BaseModel):
    line: str = ""
    action: str = ""
    values: dict[str, Any] = Field(default_factory=dict)


def _console(console_id: str) -> tuple[dict[str, Any], Any]:
    entry = console_registry().get(console_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no plugin console {console_id!r}")
    return entry


def _failure(error: Exception, what: str) -> HTTPException:
    if isinstance(error, HTTPException):
        return error
    if isinstance(error, ValueError):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, RuntimeError):
        return HTTPException(status_code=409, detail=str(error))
    _LOGGER.exception("plugin console %s failed", what)
    return HTTPException(status_code=500, detail=f"{type(error).__name__}: {error}")


def _status(manifest: dict[str, Any], console: Any) -> dict[str, Any]:
    try:
        return output.status_payload(console.status(), manifest)
    except Exception as error:  # noqa: BLE001 - a poll reports the failure, never a 500
        return {"running": False, "last_error": f"{type(error).__name__}: {error}"}


def _cursors(manifest: dict[str, Any], given: list[str]) -> dict[str, int]:
    declared = {stream["id"] for stream in manifest["streams"]}
    cursors: dict[str, int] = {}
    for item in given:
        name, _separator, position = str(item).partition(":")
        if name not in declared or not position.isdigit():
            raise HTTPException(status_code=422, detail=f"cursor {item!r}: '<declared stream>:<position>'")
        cursors[name] = int(position)
    return cursors


def _command_line(manifest: dict[str, Any], body: CommandRequest) -> str:
    wants_line = len(body.line.strip()) > 0
    wants_action = len(body.action.strip()) > 0
    if wants_line == wants_action:
        raise ConsoleInputError("send a command line or an action, not both or neither")
    if wants_line:
        if manifest["command_line"] is None:
            raise ConsoleInputError(f"console {manifest['id']!r} takes no free command line")
        if body.values:
            raise ConsoleInputError("values belong to an action, not a command line")
        return check_command_line(body.line)
    action_id = body.action.strip()
    action = next((item for item in manifest["actions"] if item["id"] == action_id), None)
    if action is None:
        raise ConsoleInputError(f"console {manifest['id']!r} has no action {action_id!r}")
    return render_action_line(action, check_values(action["fields"], body.values))


@router.get("")
def list_consoles() -> dict[str, Any]:
    """Every registered console's manifest, the refusals, and whether plugins loaded at all."""
    try:
        report = plugin_status_report()
        registry = console_registry()
    except Exception as error:  # noqa: BLE001 - the list is polled at startup and must not 500
        _LOGGER.exception("plugin console list failed")
        return {"available": False, "reason": f"{type(error).__name__}: {error}", "requires_restart": False, "consoles": [], "refused": []}
    allowed = bool(report.get("allowed"))
    reason = "" if allowed else str(report.get("block_reason") or report.get("namespace_error") or "Plugin loading is off.")
    return {
        "available": allowed,
        "reason": reason,
        "requires_restart": bool(report.get("requires_restart")),
        "consoles": registry.manifests(),
        "refused": registry.refused(),
    }


@router.get("/pills")
def console_pills() -> dict[str, Any]:
    """The top bar pills of every console that declares some, those with a value only."""
    try:
        registry = console_registry()
    except Exception:  # noqa: BLE001 - the top bar polls this and must not 500
        _LOGGER.exception("plugin console pills failed")
        return {"pills": []}
    pills: list[dict[str, str]] = []
    for manifest in registry.manifests():
        entry = registry.get(manifest["id"]) if manifest["pills"] else None
        if entry is None:
            continue
        try:
            pills.extend(output.pills_payload(manifest, entry[1].pills()))
        except Exception:  # noqa: BLE001 - a broken console loses its pills, the others stay
            _LOGGER.debug("plugin console %s pills failed", manifest["id"], exc_info=True)
    return {"pills": pills}


@router.get("/{console_id}/status")
def console_status(console_id: str) -> dict[str, Any]:
    manifest, console = _console(console_id)
    return _status(manifest, console)


@router.post("/{console_id}/start")
def start_console(console_id: str, body: StartRequest) -> dict[str, Any]:
    manifest, console = _console(console_id)
    if manifest["start"] is None:
        raise HTTPException(status_code=409, detail=f"console {console_id!r} has no start form")
    try:
        values = check_values(manifest["start"]["fields"], body.values)
        return output.status_payload(console.start(values), manifest)
    except Exception as error:  # noqa: BLE001 - mapped to a status code by _failure
        raise _failure(error, "start") from error


@router.post("/{console_id}/stop")
def stop_console(console_id: str) -> dict[str, Any]:
    manifest, console = _console(console_id)
    if manifest["start"] is None:
        raise HTTPException(status_code=409, detail=f"console {console_id!r} has no start form")
    try:
        return output.status_payload(console.stop(), manifest)
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "stop") from error


@router.post("/{console_id}/fill")
def fill_field(console_id: str, body: FillRequest) -> dict[str, Any]:
    """The value of one start field the console fills from the others (a button beside the field)."""
    manifest, console = _console(console_id)
    fields = manifest["start"]["fields"] if manifest["start"] is not None else []
    target = next((field for field in fields if field["name"] == body.field), None)
    if target is None or target["fill"] is None:
        raise HTTPException(status_code=422, detail=f"console {console_id!r} fills no start field {body.field!r}")
    try:
        # The other start values as typed so far: checked, but none of them required yet.
        given = {key: value for key, value in body.values.items() if key != target["name"]}
        values = check_values([{**field, "required": False} for field in fields], given)
        return output.fill_payload(target, console.fill(target["name"], values))
    except Exception as error:  # noqa: BLE001 - mapped to a status code by _failure
        raise _failure(error, "fill") from error


@router.post("/{console_id}/command")
def run_command(console_id: str, body: CommandRequest) -> dict[str, Any]:
    """A free line, or an action rendered from its template; both reach the provider as one line."""
    manifest, console = _console(console_id)
    try:
        line = _command_line(manifest, body)
        return output.command_payload(line, console.command(line))
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "command") from error


@router.get("/{console_id}/stream")
def read_streams(console_id: str, cursor: Optional[list[str]] = Query(default=None)) -> dict[str, Any]:
    """One poll: the status plus every declared stream's entries after its cursor (``id:position``)."""
    manifest, console = _console(console_id)
    cursors = _cursors(manifest, list(cursor or []))
    streams: dict[str, Any] = {}
    for stream in manifest["streams"]:
        after = cursors.get(stream["id"], 0)
        try:
            streams[stream["id"]] = output.stream_batch(stream, console.stream(stream["id"], after), after)
        except Exception as error:  # noqa: BLE001 - one broken stream must not blank the others
            streams[stream["id"]] = {"entries": [], "next": after, "truncated": False, "error": f"{type(error).__name__}: {error}"}
    return {"status": _status(manifest, console), "streams": streams}


@router.get("/{console_id}/help")
def console_help(console_id: str) -> dict[str, Any]:
    _manifest, console = _console(console_id)
    method = getattr(console, "help", None)
    if not callable(method):
        return {"groups": [], "text": ""}
    try:
        return output.help_payload(method())
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "help") from error
