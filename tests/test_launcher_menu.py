# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The launcher menu entries plugins add, and the launcher's use of them."""
from __future__ import annotations

import pytest

from yggdrasim_common import launcher_menu
from yggdrasim_common.launcher_menu import RESERVED_KEYS, LauncherMenu


def test_add_entry_refuses_reserved_and_duplicate_keys():
    menu = LauncherMenu()
    for key in ("1", "3a", "cb", "q", ""):
        with pytest.raises(ValueError):
            menu.add_entry(key, "taken", lambda: None)
    menu.add_entry("m", "Diagnostics", lambda: None)
    with pytest.raises(ValueError):
        menu.add_entry("M", "Again", lambda: None)
    with pytest.raises(ValueError):
        menu.add_entry("N", "No callable", None)  # type: ignore[arg-type]
    assert "M" in {entry.key for entry in menu.entries()} and "M" not in RESERVED_KEYS


def test_lines_and_dispatch():
    ran = []
    menu = LauncherMenu()
    menu.add_entry("N", "Second", lambda: ran.append("N"))
    menu.add_entry("M", "First", lambda: ran.append("M"))
    assert menu.lines() == [" [M] First", " [N] Second"]
    assert menu.dispatch("m") is True
    assert menu.dispatch("X") is False
    assert menu.dispatch("") is False
    assert ran == ["M"]


def test_plugin_menu_is_built_through_the_plugin_runtime(monkeypatch):
    seen = []

    def fake_extend(target):
        seen.append(target)
        target.add_entry("M", "From a plugin", lambda: None)
        return target

    monkeypatch.setattr("yggdrasim_common.plugin_runtime.extend_target_with_plugins", fake_extend)
    menu = launcher_menu.plugin_launcher_menu()
    assert isinstance(seen[0], LauncherMenu)
    assert menu.lines() == [" [M] From a plugin"]


def test_launcher_dispatch_hands_unknown_choices_to_the_plugin_menu(monkeypatch):
    import main.main as launcher

    ran = []
    menu = LauncherMenu()
    menu.add_entry("M", "Plugin entry", lambda: ran.append("M"))
    monkeypatch.setattr(launcher, "plugin_launcher_menu", lambda: menu)
    launcher._dispatch_main_menu_choice("m")
    assert ran == ["M"]
    launcher._dispatch_main_menu_choice("ZZ")
    assert ran == ["M"]
