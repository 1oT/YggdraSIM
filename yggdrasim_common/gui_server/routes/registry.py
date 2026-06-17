# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/registry/*`` — introspection over ``yggdrasim_common.registry``.

The GUI's left-rail navigation is built from ``SUBSYSTEMS`` so the
frontend never has to hard-code the list. Lookups (``/symbol/{key}``)
return just the dotted import target as a string — the engine object
itself is never serialised to JSON.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


router = APIRouter(prefix="/api/registry", tags=["registry"])


class SubsystemEntry(BaseModel):
    name: str
    description: str


class SubsystemListResponse(BaseModel):
    subsystems: list[SubsystemEntry]
    cli_modules: list[str]


class SymbolResponse(BaseModel):
    key: str
    target: str
    module: str
    attribute: str


class SymbolSearchResponse(BaseModel):
    query: str
    matches: list[SymbolResponse]


@router.get("/subsystems", response_model=SubsystemListResponse)
def list_subsystems() -> SubsystemListResponse:
    """Return a JSON list of all registered subsystem names."""
    from yggdrasim_common import registry as yggdrasim_registry

    entries = [
        SubsystemEntry(name=name, description=description)
        for name, description in yggdrasim_registry.iter_subsystems()
    ]
    return SubsystemListResponse(
        subsystems=entries,
        cli_modules=list(yggdrasim_registry.CLI_MODULES),
    )


@router.get("/symbol/{key:path}", response_model=SymbolResponse)
def get_symbol(key: str) -> SymbolResponse:
    """Return the JSON schema for a specific registered symbol."""
    from yggdrasim_common import registry as yggdrasim_registry

    target = yggdrasim_registry.SYMBOL_REGISTRY.get(key)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Unknown registry key: {key!r}")
    module, _, attribute = target.partition(":")
    return SymbolResponse(key=key, target=target, module=module, attribute=attribute)


@router.get("/search", response_model=SymbolSearchResponse)
def search_symbols(query: Optional[str] = None) -> SymbolSearchResponse:
    """Return a filtered JSON list of symbols matching a search query."""
    from yggdrasim_common import registry as yggdrasim_registry

    needle = str(query or "").strip()
    matches = []
    for key, target in yggdrasim_registry.search(needle):
        module, _, attribute = target.partition(":")
        matches.append(
            SymbolResponse(key=key, target=target, module=module, attribute=attribute)
        )
    return SymbolSearchResponse(query=needle, matches=matches)
