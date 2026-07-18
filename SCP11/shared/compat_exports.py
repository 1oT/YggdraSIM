# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Helpers for compatibility modules that preserve historical public names."""

from __future__ import annotations

from types import ModuleType
from typing import Any


def reexport_public(
    implementation: ModuleType,
    namespace: dict[str, Any],
) -> list[str]:
    """Populate *namespace* with exactly the names an import-star exposed."""

    declared = getattr(implementation, "__all__", None)
    if declared is None:
        names = [
            name
            for name in vars(implementation)
            if name.startswith("_") is False
        ]
    else:
        names = [str(name) for name in declared]
    namespace.update({name: getattr(implementation, name) for name in names})
    return names
