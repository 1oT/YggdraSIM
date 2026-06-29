# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/health`` — liveness + build-flavor + uptime summary.

Matches the V2 plan §6.3 surface. Side-effect-free; safe to poll from a
supervisor or from the SPA's connection-status badge.

``/api/health/memory`` is a sibling diagnostic that returns the operator-
visible counters used to verify the GUI process is not bleeding RAM
(session count, APDU recorder buffer occupancy, RSS in MiB). It is
explicitly best-effort: if ``resource`` / ``psutil`` are unavailable the
RSS field falls back to ``-1.0`` and the rest of the payload still
populates.
"""

from __future__ import annotations

import os
import resource
import time
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel


router = APIRouter(prefix="/api", tags=["health"])


class HealthResponse(BaseModel):
    ok: bool
    version: str
    flavor: str
    uptime_seconds: float
    mode: str
    pid: int


class MemoryReport(BaseModel):
    pid: int
    uptime_seconds: float
    rss_mib: float
    sessions: int
    sessions_max: int
    apdu_buffer: int
    apdu_buffer_max: int
    apdu_subscribers: int
    apdu_subscribers_max: int
    apdu_dropped: int


@router.get("/health", response_model=HealthResponse)
def get_health(request: Request) -> HealthResponse:
    """HTTP handler: return the system health status as JSON."""
    from yggdrasim_common.__about__ import __version__
    from yggdrasim_common import flavor as yggdrasim_flavor

    app_state = request.app.state
    started = float(getattr(app_state, "started_monotonic", time.monotonic()))
    uptime = max(0.0, time.monotonic() - started)
    mode = str(getattr(app_state, "gui_mode", "desktop"))
    return HealthResponse(
        ok=True,
        version=str(__version__),
        flavor=yggdrasim_flavor.describe_flavor(),
        uptime_seconds=round(uptime, 3),
        mode=mode,
        pid=os.getpid(),
    )


def _rss_mib() -> float:
    """Best-effort RSS in MiB, returning ``-1.0`` if probing fails."""
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
    except (ValueError, OSError):
        return -1.0
    raw = float(getattr(usage, "ru_maxrss", -1.0))
    if raw < 0:
        return -1.0
    # Linux reports KiB, macOS reports bytes; normalise to MiB.
    if os.name == "posix" and "darwin" in str(os.uname().sysname).lower() if hasattr(os, "uname") else False:
        return round(raw / (1024.0 * 1024.0), 3)
    return round(raw / 1024.0, 3)


@router.get("/health/memory", response_model=MemoryReport)
def get_memory(request: Request) -> MemoryReport:
    """Return the counters needed to spot creeping growth at a glance.

    Used by the leak-watch panel and the regression smoke test that
    polls this endpoint while exercising the action surface.
    """
    from yggdrasim_common.apdu_recorder import get_recorder
    from yggdrasim_common.gui_server.sessions import get_manager

    app_state = request.app.state
    started = float(getattr(app_state, "started_monotonic", time.monotonic()))
    manager = get_manager()
    recorder = get_recorder()

    sessions_listing: list[dict[str, Any]] = manager.list()
    buffer = recorder.snapshot()
    return MemoryReport(
        pid=os.getpid(),
        uptime_seconds=round(max(0.0, time.monotonic() - started), 3),
        rss_mib=_rss_mib(),
        sessions=len(sessions_listing),
        sessions_max=int(getattr(manager, "_max_sessions", 0)),
        apdu_buffer=len(buffer),
        apdu_buffer_max=int(getattr(recorder, "_buffer", buffer).maxlen or 0)
            if hasattr(getattr(recorder, "_buffer", None), "maxlen") else 0,
        apdu_subscribers=int(getattr(recorder, "async_queue_count", 0)),
        apdu_subscribers_max=int(getattr(recorder, "async_queue_cap", 0)),
        apdu_dropped=int(recorder.dropped),
    )
