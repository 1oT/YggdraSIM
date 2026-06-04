# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/backend/*`` — thin wrapper over ``yggdrasim_common.card_backend``.

The GUI's top-bar card-backend badge and the "Card backend" settings
panel both route through these endpoints. Setting the backend here is
scoped to the server process (``persist=False``) so a GUI toggle cannot
silently rewrite the operator's on-disk selection; the existing CLI
menu remains the surface for persistent changes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


router = APIRouter(prefix="/api/backend", tags=["card-backend"])


class BackendState(BaseModel):
    backend: str
    source: str
    is_simulated: bool


class SetBackendRequest(BaseModel):
    backend: str


@router.get("/state", response_model=BackendState)
def get_state() -> BackendState:
    """Return the current card-backend configuration as a JSON object."""
    from yggdrasim_common import card_backend as cb

    backend = cb.get_card_backend()
    return BackendState(
        backend=backend,
        source=cb.get_card_backend_source(),
        is_simulated=cb.is_simulated_card_backend(),
    )


@router.post("/card", response_model=BackendState)
def set_backend(body: SetBackendRequest) -> BackendState:
    """Update the active card-backend choice and return the new state."""
    from yggdrasim_common import card_backend as cb

    normalized = cb.normalize_card_backend(body.backend)
    if normalized not in (cb.CARD_BACKEND_READER, cb.CARD_BACKEND_SIM):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported backend {body.backend!r}; expected 'reader' or 'sim'.",
        )
    # Session-scoped change: the GUI never rewrites the persisted file.
    cb.set_card_backend(normalized, persist=False)
    return BackendState(
        backend=cb.get_card_backend(),
        source=cb.get_card_backend_source(),
        is_simulated=cb.is_simulated_card_backend(),
    )
