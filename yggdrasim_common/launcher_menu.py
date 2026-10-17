# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Launcher menu entries a plugin can add (``main/main.py`` shows and dispatches them).

A plugin's ``extend_target`` receives a ``LauncherMenu`` and calls
``add_entry`` with a key the built-in menu does not use; the launcher lists
the entries under a "Plugins" heading and runs one when its key is chosen.
The reserved keys are the built-in menu's, including the legacy digits it
still maps, so a plugin can never shadow a built-in choice.
"""
from __future__ import annotations

import dataclasses
from typing import Callable

RESERVED_KEYS = frozenset(
    {
        "1", "2", "3", "3A", "3C", "3D", "5", "6", "7", "8", "9", "9A", "9B", "9C", "10", "11",
        "B", "C", "CB", "E", "G", "A", "L", "Q", "QA",
    }
)


@dataclasses.dataclass(frozen=True)
class LauncherEntry:
    key: str
    label: str
    run: Callable[[], None]


class LauncherMenu:
    def __init__(self) -> None:
        self._entries: dict[str, LauncherEntry] = {}

    def add_entry(self, key: str, label: str, run: Callable[[], None]) -> LauncherEntry:
        choice = str(key or "").strip().upper()
        if len(choice) == 0 or choice in RESERVED_KEYS:
            raise ValueError(f"launcher key {key!r} is empty or reserved by the built-in menu")
        if choice in self._entries:
            raise ValueError(f"launcher key {choice!r} is already taken by {self._entries[choice].label!r}")
        if not callable(run):
            raise ValueError("a launcher entry needs a callable to run")
        entry = LauncherEntry(choice, str(label or "").strip() or choice, run)
        self._entries[choice] = entry
        return entry

    def entries(self) -> list[LauncherEntry]:
        return [self._entries[key] for key in sorted(self._entries)]

    def lines(self) -> list[str]:
        return [f" [{entry.key}] {entry.label}" for entry in self.entries()]

    def dispatch(self, choice: str) -> bool:
        """Run the entry *choice* names; False when no plugin owns it."""
        entry = self._entries.get(str(choice or "").strip().upper())
        if entry is None:
            return False
        entry.run()
        return True


def plugin_launcher_menu() -> LauncherMenu:
    """A menu carrying every entry the loaded plugins add (loading stays behind its gate)."""
    from yggdrasim_common.plugin_runtime import extend_target_with_plugins

    menu = LauncherMenu()
    extend_target_with_plugins(menu)
    return menu
