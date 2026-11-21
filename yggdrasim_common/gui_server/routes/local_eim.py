# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""``/api/local-eim/service``: the state of the Local eIM service, for the top bar pill.

The service is a process of its own (SERVE start in a shell, the Local eIM
page or the pill), so the page asks for its state here. Starting and stopping
go through the Local eIM actions (``eim_local.service_start`` and
``eim_local.service_stop``), the same SERVE verb the shell runs.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(prefix="/api/local-eim", tags=["local-eim"])

# What the pill shows of the service: where it answers and since when; the store path and the log stay out.
_FIELDS = ("url", "pid", "started_at", "eim_fqdn", "tls_url", "tls_setup", "smdp_tls_url", "smds_tls_url")


@router.get("/service")
def service_state() -> dict[str, Any]:
    """Running or not, whether it answers its /ping, and where.

    A plain ``def``: the answer check can take two seconds, and FastAPI runs a
    plain handler on its worker threads.
    """
    from SCP11.eim_local.engine.server import describe

    status = describe()
    state: dict[str, Any] = {"running": bool(status.get("running")), "answers": bool(status.get("answers"))}
    for key in _FIELDS:
        value = status.get(key)
        if value not in (None, ""):
            state[key] = value
    return state
