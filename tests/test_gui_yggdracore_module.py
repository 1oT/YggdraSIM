# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The YggdraCore module: the stub AUSF and the AKMA actions in one sidebar leaf.

Before it, the 17 actions were registered with no leaf and no overview card,
so the page could not reach them. The AKMA actions moved under the YggdraCore
subsystem because they read and clear the AAnF stub the AUSF writes (user
rule: entries that share a store are one module with tabs).
"""

from __future__ import annotations

import re
from pathlib import Path

from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded, get_registry

ROOT = Path(__file__).resolve().parents[1]
COMMAND_CENTER = ROOT / "gui_frontend" / "src" / "js" / "command-center.js"


def _module_actions() -> list[str]:
    ensure_builtin_actions_loaded()
    return sorted(spec.id for spec in get_registry().all() if spec.subsystem == "YggdraCore")


def _tab_groups(source: str) -> dict[str, list[str]]:
    start = source.index('    "YggdraCore": [')
    end = source.index("\n    ],\n", start)
    block = source[start:end]
    groups: dict[str, list[str]] = {}
    for match in re.finditer(r'label: "([^"]+)",[\s\S]*?suffixes: \[([\s\S]*?)\]', block):
        groups[match.group(1)] = re.findall(r'"([a-z0-9_]+)"', match.group(2))
    return groups


def test_the_module_holds_the_yggdracore_and_akma_actions() -> None:
    actions = _module_actions()
    assert len(actions) == 17
    assert {action.split(".", 1)[0] for action in actions} == {"yggdracore", "akma"}
    assert sum(1 for action in actions if action.startswith("akma.")) == 5


def test_the_sidebar_has_a_leaf_for_it() -> None:
    source = COMMAND_CENTER.read_text(encoding="utf-8")
    assert re.search(r'id: "leaf-adv-yggdracore",[\s\S]{0,300}?subsystem: "YggdraCore"', source)
    assert '"leaf-adv-yggdracore": "CORE"' in source


def test_every_action_has_one_tab_and_no_tab_holds_one_button() -> None:
    groups = _tab_groups(COMMAND_CENTER.read_text(encoding="utf-8"))
    assert list(groups) == ["Subscriptions", "AKMA", "Open5GS", "Diagnostics"]
    placed = [suffix for suffixes in groups.values() for suffix in suffixes]
    assert len(placed) == len(set(placed))
    assert sorted(placed) == sorted(action.split(".", 1)[1] for action in _module_actions())
    for label, suffixes in groups.items():
        assert len(suffixes) > 1, label
