# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``/api/gui/startup`` -- the files named on the command line, handed to the SPA once.

``yggdrasim --gui FILE`` (what the desktop launcher's Open With entry
runs) records FILE on the application state. The SPA asks for it after
the action catalogue has loaded and routes each path through the SAIP
workbench's open entry point. The list is cleared on the first read, so
a page reload does not reopen the file and a second browser tab on a
headless server finds nothing to do.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/gui", tags=["gui"])


class StartupResponse(BaseModel):
    open_paths: list[str]


@router.get("/startup", response_model=StartupResponse)
async def get_startup(request: Request) -> StartupResponse:
    """Return the pending startup files and clear them.

    ``async def`` keeps the read-and-clear on the event loop thread, so
    two tabs racing for the list cannot both receive it.
    """
    app_state = request.app.state
    pending = [
        str(path) for path in (getattr(app_state, "startup_open_paths", ()) or ())
    ]
    app_state.startup_open_paths = ()
    return StartupResponse(open_paths=pending)
