# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Entries of the Offline Tools module in the sidebar.

Tools that share an input or a store are one entry with a tab per tool; every
other tool keeps an entry of its own, and a tool the page's table does not name
follows the listed ones by title. The page's own functions run under ``node``
on the actions the registry holds, so a tool added to the backend without a
place in the table shows up here as an entry nobody chose.
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
var actions = %s;
var entries = CC_OFFLINE_TOOL_ENTRIES.filter(function (entry) { return !!entry.tabs; }).map(function (entry) {
  return [entry.id, ccOfflineToolEntryTabs(entry, actions).map(function (tab) {
    return [tab.id, tab.label, tab.panel];
  })];
});
console.log(JSON.stringify({
  leaves: ccOfflineToolSubLeaves(actions),
  entries: entries,
  hidden: Object.keys(CC_OFFLINE_TOOLS_HIDDEN_ACTIONS),
  decoder: ccOfflineToolEntry(CC_OFFLINE_DECODER_SCOPE).id,
  unknown: ccOfflineToolEntry("tool.gsma.codes"),
}));
"""

# The actions this repository registers under Offline Tools; a plugin may add more.
_CORE_PREFIXES = ("tool.", "suci.", "simcard.")


def _core_actions() -> list[dict[str, str]]:
    registry = ensure_builtin_actions_loaded()
    return [
        {"id": spec.id, "title": spec.title, "description": spec.description}
        for spec in registry.by_subsystem().get("Offline Tools", [])
        if spec.id.startswith(_CORE_PREFIXES)
    ]


def _page(actions: list[dict[str, str]]) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    text = _SOURCE.read_text(encoding="utf-8")
    hidden_start = text.index("  var CC_OFFLINE_TOOLS_HIDDEN_ACTIONS = {")
    hidden = text[hidden_start:text.index("\n  };\n", hidden_start) + len("\n  };\n")]
    start = text.index('  var CC_OFFLINE_DECODER_SCOPE = "decoder";')
    end = text.index("  // Short legends for the collapsed sidebar", start)
    script = _HARNESS % (hidden, text[start:end], json.dumps(actions))
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


def test_seven_entries_cover_every_registered_tool() -> None:
    actions = _core_actions()
    page = _page(actions)
    assert [leaf["label"] for leaf in page["leaves"]] == [
        "Decoder", "TERMINAL PROFILE", "AddInitialEim", "eIM package lint", "SUCI keys",
        "TUAK -- derive TOPc", "GSMA error-code reference",
    ]
    assert [leaf["id"] for leaf in page["leaves"]] == [
        "leaf-tool-offline-decoder", "leaf-tool-offline-terminal-profile", "leaf-tool-offline-add-initial-eim",
        "leaf-tool-offline-tool.eim.lint", "leaf-tool-offline-suci-keys",
        "leaf-tool-offline-simcard.tuak_derive_topc", "leaf-tool-offline-tool.gsma.codes",
    ]
    assert all(leaf["subsystem"] == "Offline Tools" and leaf["hint"] for leaf in page["leaves"])
    assert page["decoder"] == "decoder" and page["unknown"] is None

    tabs = dict(page["entries"])
    assert [label for _id, label, _panel in tabs["decoder"]] == ["Decoder", "ASN.1/TLV decode"]
    assert tabs["decoder"][0][2] == "decoder" and tabs["decoder"][1][0] == "tool.asn1_tlv.decode"
    assert [label for _id, label, _panel in tabs["terminal-profile"]] == ["Decode", "Build"]
    assert [label for _id, label, _panel in tabs["add-initial-eim"]] == [
        "Build", "Send", "Configurations", "Certificate store", "Saved values",
    ]
    assert [label for _id, label, _panel in tabs["suci-keys"]] == ["Use key file", "Generate", "Dump public key"]

    # Each registered tool has exactly one home: hidden, a tab, or an entry of its own.
    in_tabs = [tab_id for entry_tabs in tabs.values() for tab_id, _label, panel in entry_tabs if not panel]
    own_entry = [leaf["scope"] for leaf in page["leaves"] if leaf["scope"] not in tabs]
    homes = page["hidden"] + in_tabs + own_entry
    assert sorted(homes) == sorted(action["id"] for action in actions)
    assert len(set(homes)) == len(homes)
    # The state line of the SUCI keys entry is a registered action.
    assert "suci.status" in page["hidden"] and "suci.status" in {action["id"] for action in actions}


def test_a_tool_the_table_does_not_name_follows_by_title() -> None:
    extra = [
        {"id": "extra.two.report", "title": "Zeta report", "description": "z"},
        {"id": "extra.one.sweep", "title": "Alpha sweep", "description": "a"},
    ]
    page = _page(_core_actions() + extra)
    labels = [leaf["label"] for leaf in page["leaves"]]
    assert labels[:7][-1] == "GSMA error-code reference"
    assert labels[7:] == ["Alpha sweep", "Zeta report"]
    assert page["leaves"][7]["scope"] == "extra.one.sweep"


def test_an_entry_without_a_registered_tool_is_not_listed() -> None:
    without_suci = [action for action in _core_actions() if not action["id"].startswith("suci.")]
    page = _page(without_suci)
    assert "SUCI keys" not in [leaf["label"] for leaf in page["leaves"]]
    # The Decoder panel is drawn by the page, so its entry stays with no action at all.
    bare = _page([])
    assert [leaf["label"] for leaf in bare["leaves"]] == ["Decoder"]
    assert dict(bare["entries"])["decoder"] == [["decoder", "Decoder", "decoder"]]
    # One of two tools registered: the entry stays, with the one tab.
    one = [action for action in _core_actions() if action["id"] != "tool.tp.build"]
    assert [label for _id, label, _panel in dict(_page(one)["entries"])["terminal-profile"]] == ["Decode"]


def test_the_suci_tool_command_is_set_in_one_place(monkeypatch, tmp_path) -> None:
    """No action sets the suci-keytool command: a bridge that lives for one request cannot keep it.

    The setting is the env flag, which Environment > Configuration writes into
    the running server; the state line over the SUCI keys tabs names the
    command in use, where it comes from and where to set it.
    """
    from Tools.SuciTool import tool as suci_tool
    from yggdrasim_common import env_flags
    from yggdrasim_common.gui_server.actions import suci

    registry = ensure_builtin_actions_loaded()
    assert "suci.set_tool_command" not in {spec.id for spec in registry.by_subsystem().get("Offline Tools", [])}
    assert not hasattr(suci, "SET_TOOL_COMMAND_SPEC")
    assert suci_tool.SUCI_TOOL_ENV in {flag.name for flag in env_flags.iter_flags()}

    def tool_line() -> str:
        lines = {line["key"]: line["value"] for line in suci._dispatch_status(None)["lines"]}
        assert list(lines) == ["Workspace root", "Active key file", "Tool command"]
        return lines["Tool command"]

    monkeypatch.delenv(suci_tool.SUCI_TOOL_ENV, raising=False)
    monkeypatch.setattr(suci_tool.shutil, "which", lambda name: None)
    assert tool_line() == "not found: set YGGDRASIM_SUCI_TOOL under Environment > Configuration"

    monkeypatch.setattr(suci_tool.shutil, "which", lambda name: "/opt/tools/" + name)
    assert tool_line() == (
        "/opt/tools/suci-keytool.py (found on PATH; YGGDRASIM_SUCI_TOOL under Environment > Configuration overrides it)"
    )

    script = tmp_path / "suci-keytool.py"
    monkeypatch.setenv(suci_tool.SUCI_TOOL_ENV, f"python {script}")
    assert tool_line() == f"python {script} (from YGGDRASIM_SUCI_TOOL under Environment > Configuration)"

    monkeypatch.setenv(suci_tool.SUCI_TOOL_ENV, 'python "unclosed')
    assert tool_line().startswith("YGGDRASIM_SUCI_TOOL does not read as a command line")


def test_the_suci_actions_tell_a_finished_run_from_a_failed_one(monkeypatch, tmp_path) -> None:
    """Exit code 0 is a success: Generate and Dump say what they did, and say so only then."""
    from Tools.SuciTool.tool import SuciKeyToolBridge
    from yggdrasim_common.gui_server.actions import suci

    answers: list[tuple[int, str]] = []
    seen: list[list[str]] = []

    def runner(command):
        import subprocess

        seen.append(list(command))
        code, printed = answers.pop(0)
        return subprocess.CompletedProcess(list(command), code, stdout=printed, stderr="" if code == 0 else "usage: ...")

    monkeypatch.setattr(
        suci, "_build_bridge",
        lambda: SuciKeyToolBridge(workspace_root=tmp_path, runner=runner, tool_command=["suci-keytool.py"]),
    )
    monkeypatch.setattr(suci, "_last_key_file", None)

    answers.append((0, ""))
    made = suci._dispatch_generate_key(None, key_file="demo.key", curve="secp256r1")
    assert made["ok"] is True and made["returncode"] == 0
    assert made["note"] == f"generated secp256r1 key at {tmp_path / 'demo.key'}."
    assert seen[-1][-3:] == ["generate-key", "--curve", "secp256r1"]

    # A compressed P-256 point as pySim's suci-keytool prints it: the hex and nothing else.
    public = "03" + "5A" * 32
    answers.append((0, public.lower() + "\n"))
    dumped = suci._dispatch_dump_pub_key(None, key_file="", compressed=True)
    assert dumped["ok"] is True and dumped["public_key_hex"] == public
    assert dumped["note"] == f"public key: {public}"
    assert seen[-1][-2:] == ["dump-pub-key", "--compressed"]

    answers.append((2, ""))
    failed = suci._dispatch_dump_pub_key(None, key_file="", compressed=False)
    assert failed["ok"] is False and failed["returncode"] == 2 and failed["public_key_hex"] == ""
    assert failed["note"] == "suci-keytool exited with code 2."
    # A result that carries no exit code at all is not a success.
    assert suci._result_to_dict(object())["returncode"] == 1
