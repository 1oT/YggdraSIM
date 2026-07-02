# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraSIM universal GUI server — FastAPI + pywebview surface.

This package is intentionally lazy about its heavyweight imports. Merely
importing :mod:`yggdrasim_common.gui_server` does **not** pull ``fastapi``,
``uvicorn``, or ``pywebview`` — they live under :mod:`.app` and are only
resolved when one of the entry points (``run_desktop`` / ``run_web_server``)
is actually invoked. This keeps the base ``pip install yggdrasim`` install
lean and matches the acceptance criterion §16.5 of
``V2_UNIVERSAL_GUI_PLAN.md``.

Public entry points are re-exported here for ergonomics, using lazy
attribute access so they trigger the import only on first use.
"""

from __future__ import annotations

from typing import Any


__all__ = [
    "GuiServerConfig",
    "build_desktop_config",
    "build_web_server_config",
    "run_desktop",
    "run_web_server",
]


def __getattr__(name: str) -> Any:
    if name in ("GuiServerConfig", "build_desktop_config", "build_web_server_config"):
        from . import config as _config_module

        return getattr(_config_module, name)
    if name in ("run_desktop", "run_web_server"):
        from . import app as _app_module

        return getattr(_app_module, name)
    raise AttributeError(f"module 'yggdrasim_common.gui_server' has no attribute {name!r}")
