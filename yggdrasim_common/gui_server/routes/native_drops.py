# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``/api/gui/native_drop/resolve`` -- where the files just dropped on the window live.

The page posts the name and size of every ``File`` its ``drop`` event
carried and gets one path per file back, in the same order, or null for
a file the desktop process did not record (a browser tab, a drag that
came from somewhere other than a file manager). The record itself is
kept by ``yggdrasim_common/gui_server/native_drops.py``.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yggdrasim_common.gui_server import native_drops

router = APIRouter(prefix="/api/gui", tags=["gui"])

_MAX_FILES_PER_DROP = 256


class DroppedFile(BaseModel):
    name: str
    size: Optional[int] = None


class NativeDropResolveRequest(BaseModel):
    files: list[DroppedFile] = Field(default_factory=list)


class NativeDropResolveResponse(BaseModel):
    paths: list[Optional[str]]


@router.post("/native_drop/resolve", response_model=NativeDropResolveResponse)
async def resolve_native_drop(body: NativeDropResolveRequest) -> NativeDropResolveResponse:
    """Return the recorded path of each dropped file, aligned with the request.

    Runs off the event loop: the resolver may wait for a backend that
    records the paths after the page has already asked.
    """
    if len(body.files) > _MAX_FILES_PER_DROP:
        raise HTTPException(status_code=422, detail="too many files in one drop")
    wanted = [
        (str(item.name), None if item.size is None or item.size < 0 else int(item.size))
        for item in body.files
    ]
    paths = await asyncio.to_thread(
        native_drops.resolve_dropped_paths,
        wanted,
        wait_s=native_drops.RESOLVE_WAIT_S,
    )
    return NativeDropResolveResponse(paths=paths)
