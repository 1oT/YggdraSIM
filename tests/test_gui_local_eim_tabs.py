# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tabs of the Local eIM module's action list.

Five tabs, one per store the actions work on: the queue, the eUICC records,
the eIM's own configuration, the card in the reader and the package files.
Every Local eIM action this repository registers sits in exactly one of them,
none in "Other", and a tab draws its buttons in the order its suffixes are
listed. The page's own functions run under ``node`` on the registry's actions.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

_SOURCE = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js"

_HARNESS = """
%s
%s
%s
var actions = %s;
var grouped = ccGroupActionsForSubsystem("Local eIM", actions) || [];
console.log(JSON.stringify({
  table: CC_ACTION_GROUPS_BY_SUBSYSTEM["Local eIM"],
  grouped: grouped.map(function (bucket) {
    return [bucket.group.id, bucket.group.label, bucket.items.map(function (item) { return item.id; })];
  }),
  ordered: ccOrderActionsByGroups("Local eIM", actions).map(function (item) { return item.id; }),
  unknown: ccOrderActionsByGroups("No such module", actions).map(function (item) { return item.id; }),
}));
"""

TABS = [
    ("eim-ops", "Operations"),
    ("eim-euiccs", "eUICCs"),
    ("eim-config", "eIM configuration"),
    ("eim-card", "Direct card commands"),
    ("eim-files", "Package files"),
]


def _core_actions() -> list[dict[str, Any]]:
    registry = ensure_builtin_actions_loaded()
    return [
        {"id": spec.id, "title": spec.title, "tags": list(spec.tags)}
        for spec in registry.by_subsystem().get("Local eIM", [])
        if spec.id.startswith("eim_local.")
    ]


def _page(actions: list[dict[str, Any]]) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    text = _SOURCE.read_text(encoding="utf-8")
    table_start = text.index("  var CC_ACTION_GROUPS_BY_SUBSYSTEM = {")
    table = text[table_start:text.index("\n  };\n", table_start) + len("\n  };\n")]
    suffix_start = text.index("  function ccActionSuffix(actionId) {")
    suffix = text[suffix_start:text.index("\n  }\n", suffix_start) + len("\n  }\n")]
    start = text.index("  function ccGroupActionsForSubsystem(")
    functions = text[start:text.index("  var CC_ESIM_ACTION_FLAVORS", start)]
    script = _HARNESS % (table, suffix, functions, json.dumps(actions))
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


def test_five_tabs_hold_every_core_action_once() -> None:
    actions = _core_actions()
    page = _page(actions)
    assert [(group["id"], group["label"]) for group in page["table"]] == TABS
    assert all(group["hint"] for group in page["table"])
    listed = [suffix for group in page["table"] for suffix in group["suffixes"]]
    assert len(listed) == len(set(listed)), sorted(suffix for suffix in set(listed) if listed.count(suffix) > 1)

    assert [(group_id, label) for group_id, label, _items in page["grouped"]] == TABS
    placed = [action_id for _group_id, _label, items in page["grouped"] for action_id in items]
    assert sorted(placed) == sorted(action["id"] for action in actions)
    # A suffix the registry no longer has is a stale row of the table.
    assert sorted(listed) == sorted(action["id"].rsplit(".", 1)[-1] for action in actions)


def test_a_tab_draws_its_buttons_in_the_order_of_its_list() -> None:
    actions = _core_actions()
    loose = {"id": "extra.one.loose", "title": "Aaa", "tags": []}
    page = _page([loose] + actions)
    ordered = page["ordered"]
    # The queue's entry point opens the first tab.
    assert ordered[0] == "eim_local.op_queue"
    suffixes = [action_id.rsplit(".", 1)[-1] for action_id in ordered[:-1]]
    listed = [suffix for group in page["table"] for suffix in group["suffixes"]]
    assert suffixes == listed
    # An action no tab lists keeps its place after the listed ones.
    assert ordered[-1] == "extra.one.loose"
    # A module without a table keeps the order it was given.
    assert page["unknown"] == ["extra.one.loose"] + [action["id"] for action in actions]


def test_a_tagged_action_joins_a_tab_or_opens_its_own() -> None:
    joined = {"id": "extra.one.code", "title": "Code", "tags": ["tab:eim-ops"]}
    own = {"id": "extra.two.run", "title": "Run", "tags": ["tab:extra-runs", "tab-label:Runs"]}
    bare = {"id": "extra.three.bare", "title": "Bare", "tags": []}
    page = _page(_core_actions() + [joined, own, bare])
    grouped = {group_id: (label, items) for group_id, label, items in page["grouped"]}
    assert "extra.one.code" in grouped["eim-ops"][1]
    assert grouped["extra-runs"] == ("Runs", ["extra.two.run"])
    assert grouped["other"] == ("Other", ["extra.three.bare"])
    assert [group_id for group_id, _label, _items in page["grouped"]] == [tab for tab, _label in TABS] + ["extra-runs", "other"]


def test_page_owned_actions_are_not_buttons() -> None:
    """What the Local eIM page or its Leaf editor fetches for itself stays out of the action list."""
    text = _SOURCE.read_text(encoding="utf-8")
    start = text.index("    var LOCAL_EIM_OVERVIEW_SUFFIXES = {")
    block = text[start:text.index("\n    };\n", start)]
    for suffix in ("overview", "op_detail", "tls_leaf_rows"):
        assert f"      {suffix}: true," in block
    assert "ccOrderActionsByGroups(subsystem, actions.filter(_shouldShowLocalEimDashboardAction))" in text
