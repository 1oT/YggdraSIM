# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/env_flags/*`` — view / edit over the YGGDRASIM_* registry.

The GUI's "Env flags" pane surfaces the same data the launcher menu
``[E]`` shows: name, category, summary, default hint, current resolved
source. Writes mirror the menu's ``set`` / ``clear`` operations via
:func:`yggdrasim_common.env_flags.set_flag_value` and
:func:`yggdrasim_common.env_flags.clear_flag_value` — session-only flags
never hit disk, persistable flags (``PERSIST_FILE`` /
``PERSIST_HOME``) land in the same ``state/env_overrides.json`` /
``~/.yggdrasim/env_overrides.json`` files the CLI manages.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel


router = APIRouter(prefix="/api/env_flags", tags=["env-flags"])


class EnvFlagView(BaseModel):
    name: str
    category: str
    summary: str
    kind: str
    choices: list[str]
    default_hint: str
    applies: str
    sensitive: bool
    persist_scope: str
    current_value: Optional[str]
    is_set: bool


class EnvFlagListResponse(BaseModel):
    categories: list[str]
    flags: list[EnvFlagView]


class EnvFlagSetRequest(BaseModel):
    value: str
    persist: bool = True


class EnvFlagClearRequest(BaseModel):
    persist: bool = True


class EnvFlagResetRequest(BaseModel):
    clear_session: bool = False


class EnvFlagMutationResponse(BaseModel):
    flag: EnvFlagView
    note: str


class EnvFlagResetResponse(BaseModel):
    removed: int
    cleared_session: bool
    note: str


def _view_for_flag(flag) -> EnvFlagView:
    raw = os.environ.get(flag.name)
    return EnvFlagView(
        name=flag.name,
        category=flag.category,
        summary=flag.summary,
        kind=flag.kind,
        choices=list(flag.choices or []),
        default_hint=flag.default_hint,
        applies=flag.applies,
        sensitive=bool(flag.sensitive),
        persist_scope=flag.persist_scope,
        current_value=(None if raw is None else str(raw)),
        is_set=(raw is not None and len(str(raw)) > 0),
    )


def _lookup_flag(name: str):
    from yggdrasim_common import env_flags as ef

    cleaned = str(name or "").strip()
    if len(cleaned) == 0:
        raise HTTPException(status_code=400, detail="flag name is required.")
    for flag in ef.FLAG_REGISTRY:
        if flag.name == cleaned:
            return flag
    raise HTTPException(status_code=404, detail=f"unknown env flag: {cleaned}")


@router.get("/list", response_model=EnvFlagListResponse)
def list_flags() -> EnvFlagListResponse:
    """HTTP handler: return the current runtime environment-flag settings as JSON."""
    from yggdrasim_common import env_flags as ef

    views = [_view_for_flag(flag) for flag in ef.FLAG_REGISTRY]
    return EnvFlagListResponse(
        categories=list(ef.CATEGORY_ORDER),
        flags=views,
    )


@router.post("/{name}/set", response_model=EnvFlagMutationResponse)
def set_flag(name: str, payload: EnvFlagSetRequest) -> EnvFlagMutationResponse:
    """Set an env flag value (stripped). Empty value clears it."""
    from yggdrasim_common import env_flags as ef

    flag = _lookup_flag(name)
    try:
        effective = ef.set_flag_value(flag, payload.value, persist=bool(payload.persist))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if len(effective) == 0:
        note = f"{flag.name} cleared (persist={payload.persist})."
    else:
        note = f"{flag.name}={effective} (persist={payload.persist})."
    return EnvFlagMutationResponse(flag=_view_for_flag(flag), note=note)


@router.post("/{name}/clear", response_model=EnvFlagMutationResponse)
def clear_flag(
    name: str,
    payload: EnvFlagClearRequest | None = Body(default=None),
) -> EnvFlagMutationResponse:
    """Clear an env flag (drops from ``os.environ`` and persistence)."""
    from yggdrasim_common import env_flags as ef

    flag = _lookup_flag(name)
    persist = True if payload is None else bool(payload.persist)
    try:
        ef.clear_flag_value(flag, persist=persist)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return EnvFlagMutationResponse(
        flag=_view_for_flag(flag),
        note=f"{flag.name} cleared (persist={persist}).",
    )


@router.post("/reset", response_model=EnvFlagResetResponse)
def reset_flags(payload: EnvFlagResetRequest | None = None) -> EnvFlagResetResponse:
    """Remove every persisted override (optionally also clear session state)."""
    from yggdrasim_common import env_flags as ef

    clear_session = False if payload is None else bool(payload.clear_session)
    removed = ef.reset_all_persisted(clear_session=clear_session)
    return EnvFlagResetResponse(
        removed=int(removed),
        cleared_session=clear_session,
        note=(
            f"{removed} persisted override(s) removed"
            + (" and session env cleared." if clear_session else ".")
        ),
    )
