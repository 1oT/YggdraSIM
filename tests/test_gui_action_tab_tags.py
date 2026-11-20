# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tab of a Command Center action whose id suffix the page's tab table lacks.

``ccGroupActionsForSubsystem`` places such an action by its ``tab:<group id>``
tag, opens a tab of its own for a group id the table does not have when a
``tab-label:<label>`` tag comes with it, and leaves everything else in
"Other". The function runs under ``node`` on a two-tab table.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_SOURCE = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js"

_HARNESS = """
var CC_ACTION_GROUPS_BY_SUBSYSTEM = {"Demo": [
  {id: "demo-queue", label: "Queue", suffixes: ["queue"]},
  {id: "demo-status", label: "Status", suffixes: ["status"]}
]};
function ccActionSuffix(id) { return String(id).split(".").pop(); }
%s
var grouped = ccGroupActionsForSubsystem("Demo", %s);
console.log(JSON.stringify(grouped.map(function (bucket) {
  return [bucket.group.id, bucket.group.label, bucket.items.map(function (item) { return item.id; })];
})));
"""


def _group(actions: list[dict[str, object]]) -> list[list[object]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    text = _SOURCE.read_text(encoding="utf-8")
    start = text.index("  function ccGroupActionsForSubsystem(")
    end = text.index("  var CC_ESIM_ACTION_FLAVORS", start)
    script = _HARNESS % (text[start:end], json.dumps(actions))
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


def test_a_suffix_in_the_table_wins_over_a_tag() -> None:
    grouped = _group([{"id": "demo.queue", "tags": ["tab:demo-status"]}])
    assert grouped == [["demo-queue", "Queue", ["demo.queue"]]]


def test_a_tag_places_an_action_in_a_tab_of_the_table() -> None:
    grouped = _group([{"id": "extra.one.sweep", "tags": ["extra", "tab:demo-status"]}])
    assert grouped == [["demo-status", "Status", ["extra.one.sweep"]]]


def test_a_labelled_tag_opens_one_tab_after_the_table() -> None:
    tags = ["tab:demo-runs", "tab-label:Runs"]
    grouped = _group([
        {"id": "demo.status", "tags": []},
        {"id": "extra.one.new", "tags": tags},
        {"id": "extra.one.next", "tags": tags},
    ])
    assert grouped == [
        ["demo-status", "Status", ["demo.status"]],
        ["demo-runs", "Runs", ["extra.one.new", "extra.one.next"]],
    ]


def test_an_unknown_tab_without_a_label_and_no_tag_land_in_other() -> None:
    grouped = _group([
        {"id": "extra.one.loose", "tags": ["tab:nowhere"]},
        {"id": "extra.one.bare", "tags": []},
        {"id": "extra.one.untagged"},
    ])
    assert grouped == [["other", "Other", ["extra.one.loose", "extra.one.bare", "extra.one.untagged"]]]
