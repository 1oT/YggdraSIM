# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""GUI routes of a plugin console's run form: start, list, report, events, cancel, credentials.

The routes sit beside ``plugin_consoles`` under the same prefix and answer
409 for a console that declares no run form. ``select_run`` reduces a run
request to the visible fields in use before the provider sees it, a start
that needs a credential which is not usable (for a named credential: whose
picked entry is not stored and usable) is refused, and every answer is cut
to the closed shapes of ``plugin_console_runs_output``. A named credential's
store and forget name the entry they act on; a plain credential takes no
entry name. A run id arrives in the path and is matched against a narrow
pattern before any provider call.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import plugin_console_runs_output as output
from ..plugin_console_output import choices_payload, dynamic_sources
from ..plugin_console_registry import console_registry
from ..plugin_console_selection import select_run
from ..plugin_console_values import ConsoleInputError, check_entry_name, check_values

_LOGGER = logging.getLogger("yggdrasim.gui.plugin_console_runs")

router = APIRouter(prefix="/api/plugin-consoles", tags=["plugin-consoles"])

RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")


class RunRequest(BaseModel):
    variant: str = ""
    items: list[Any] = Field(default_factory=list)
    values: dict[str, Any] = Field(default_factory=dict)
    credential_entries: Optional[dict[str, Any]] = None


class CredentialRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)
    name: Optional[str] = None


def _runs(console_id: str) -> tuple[dict[str, Any], Any]:
    entry = console_registry().get(console_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no plugin console {console_id!r}")
    manifest, console = entry
    if manifest["runs"] is None:
        raise HTTPException(status_code=409, detail=f"console {console_id!r} has no run form")
    return manifest["runs"], console


def _run_id(value: str) -> str:
    if RUN_ID.fullmatch(value) is None:
        raise HTTPException(status_code=422, detail="not a run id")
    return value


def _credential(runs: dict[str, Any], credential_id: str) -> dict[str, Any]:
    for item in runs["credentials"]:
        if item["id"] == credential_id:
            return item
    raise HTTPException(status_code=404, detail=f"no credential {credential_id!r}")


def _failure(error: Exception, what: str) -> HTTPException:
    if isinstance(error, HTTPException):
        return error
    if isinstance(error, KeyError):
        return HTTPException(status_code=404, detail="no such run")
    if isinstance(error, ValueError):
        return HTTPException(status_code=422, detail=str(error))
    if isinstance(error, RuntimeError):
        return HTTPException(status_code=409, detail=str(error))
    _LOGGER.exception("plugin console %s failed", what)
    return HTTPException(status_code=500, detail=f"{type(error).__name__}: {error}")


def _entry_name(declared: dict[str, Any], name: Optional[str]) -> Optional[str]:
    """The checked entry name of a named credential; None for a plain one, which takes no name."""
    if declared["named"]:
        return check_entry_name(name, declared["label"])
    if name:
        raise ConsoleInputError(f"{declared['label']}: keeps one entry and takes no entry name")
    return None


def _refuse_unusable(runs: dict[str, Any], console: Any, request: dict[str, Any]) -> None:
    needed = request["credentials"]
    if not needed:
        return
    status = output.credentials_payload(runs, console.credentials())["credentials"]
    picks = request.get("credential_entries") or {}
    missing: list[str] = []
    problems: list[str] = []
    for item in runs["credentials"]:
        if item["id"] not in needed:
            continue
        if not item["named"]:
            if not status[item["id"]]["usable"]:
                missing.append(item["label"])
            continue
        usable = [entry["name"] for entry in status[item["id"]]["entries"] if entry["usable"]]
        pick = picks.get(item["id"], "")
        if pick in usable:
            continue
        if pick:
            problems.append(f"{item['label']}: the picked entry is not stored or not usable")
        elif usable:
            problems.append(f"{item['label']}: pick the entry this run uses")
        else:
            missing.append(item["label"])
    if missing:
        problems.insert(0, "store the " + ", ".join(missing) + " first")
    if problems:
        raise RuntimeError("; ".join(problems))


def _live_choices(runs: dict[str, Any], console: Any) -> dict[str, list[dict[str, str]]]:
    """The console's current options for the fields it fills, read from its status; a
    console that fills none is not asked, and a failed status leaves every list empty."""
    if not dynamic_sources(runs):
        return {}
    try:
        status = console.status()
    except Exception:  # noqa: BLE001 - the start is then refused for that field, naming it
        return {}
    return choices_payload(runs, status.get("choices") if isinstance(status, dict) else None)


@router.post("/{console_id}/runs")
def start_run(console_id: str, body: RunRequest) -> dict[str, Any]:
    """Start one run from the checked request; the answer is its history row."""
    runs, console = _runs(console_id)
    try:
        request = select_run(runs, body.model_dump(), _live_choices(runs, console))
        _refuse_unusable(runs, console, request)
        return output.run_summary(console.run_start(request))
    except Exception as error:  # noqa: BLE001 - mapped to a status code by _failure
        raise _failure(error, "run start") from error


@router.get("/{console_id}/runs")
def list_runs(console_id: str, limit: int = Query(default=30, ge=1, le=output.MAX_RUN_LIST)) -> dict[str, Any]:
    runs, console = _runs(console_id)
    try:
        return output.run_list(console.runs(limit), limit)
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "run list") from error


@router.get("/{console_id}/runs/{run_id}")
def run_report(console_id: str, run_id: str) -> dict[str, Any]:
    runs, console = _runs(console_id)
    try:
        return output.run_report(console.run(_run_id(run_id)))
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "run report") from error


@router.get("/{console_id}/runs/{run_id}/events")
def run_events(console_id: str, run_id: str, after: int = Query(default=0, ge=0)) -> dict[str, Any]:
    runs, console = _runs(console_id)
    try:
        return output.run_events(console.run_events(_run_id(run_id), after), after)
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "run events") from error


@router.post("/{console_id}/runs/{run_id}/cancel")
def cancel_run(console_id: str, run_id: str) -> dict[str, Any]:
    runs, console = _runs(console_id)
    try:
        answer = console.run_cancel(_run_id(run_id))
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "run cancel") from error
    accepted = answer.get("cancel_requested") is True if isinstance(answer, dict) else answer is True
    return {"id": run_id, "cancel_requested": accepted}


@router.get("/{console_id}/credentials")
def credentials(console_id: str) -> dict[str, Any]:
    """Every declared credential's status; never a secret value."""
    runs, console = _runs(console_id)
    if not runs["credentials"]:
        return {"credentials": {}}
    try:
        return output.credentials_payload(runs, console.credentials())
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "credential status") from error


@router.post("/{console_id}/credentials/{credential_id}")
def store_credential(console_id: str, credential_id: str, body: CredentialRequest) -> dict[str, Any]:
    """Store a plain credential, or add or replace the named entry ``name`` of a named one."""
    runs, console = _runs(console_id)
    declared = _credential(runs, credential_id)
    try:
        values = check_values(declared["fields"], body.values)
        name = _entry_name(declared, body.name)
        answer = console.credential_store(credential_id, values) if name is None else console.credential_store(credential_id, values, name)
        return output.credential_entry(declared, answer)
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "credential store") from error


@router.delete("/{console_id}/credentials/{credential_id}")
def forget_credential(console_id: str, credential_id: str, name: Optional[str] = Query(default=None)) -> dict[str, Any]:
    """Forget a plain credential, or the entry ``name`` of a named one."""
    runs, console = _runs(console_id)
    declared = _credential(runs, credential_id)
    try:
        entry = _entry_name(declared, name)
        answer = console.credential_forget(credential_id) if entry is None else console.credential_forget(credential_id, entry)
        return output.credential_entry(declared, answer)
    except Exception as error:  # noqa: BLE001
        raise _failure(error, "credential forget") from error
