# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Command Center actions (R2-004 Phase C).

Actions are small, structured wrappers around existing engine entry points
so the GUI can render task-oriented panels (buttons + forms) instead of
leaving the user to drive a raw CLI. Each action declares:

* ``id``           : stable identifier, e.g. ``scp03.scan``
* ``subsystem``    : which left-nav group it belongs to
* ``title``        : short, human-facing label
* ``description``  : one-paragraph help text
* ``inputs``       : typed form-field list (used by the UI to draw a form)
* ``output_kind``  : hint for the UI result renderer (``tree`` / ``fcp`` / ``log_stream`` / …)
* ``dispatcher``   : callable that runs the action (sync) or coroutine
  (async / streaming). Dispatchers receive a kwargs dict matching the
  declared inputs (already type-coerced) plus a short ``ActionContext``
  handle.

The registry lives in :mod:`.registry`; per-subsystem modules register
their actions eagerly on import. Importing this package is cheap — the
dispatchers themselves use lazy imports so FastAPI / pywebview stay
optional.
"""

from __future__ import annotations

from typing import Any


def __getattr__(name: str) -> Any:
    if name in (
        "ActionContext",
        "ActionField",
        "ActionSpec",
        "ActionRegistry",
        "get_registry",
    ):
        from . import registry as _registry_module

        return getattr(_registry_module, name)
    raise AttributeError(f"module 'yggdrasim_common.gui_server.actions' has no attribute {name!r}")
