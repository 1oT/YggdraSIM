# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""A sensitive flag is confirmed on both editors before it is written.

The launcher menu asks before it takes the value; the Configuration page of
the GUI asks between Set and the write. A flag whose value is a command the
process runs is sensitive for that reason. The page's own row function runs
here under ``node`` on what the route answers for the registry's flags, with
a small stand-in for the document.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from yggdrasim_common import env_flags

_SOURCE = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "core.js"

# Flags whose value is a command line the process runs on an operator's action.
_COMMAND_FLAGS = ("YGGDRASIM_SUCI_TOOL", "YGGDRASIM_SAIP_TOOL")

_TYPED = "/opt/venv/bin/python /opt/tools/keytool.py"
_CURRENT = "/opt/current/keytool"

_HARNESS = r"""
function Node(tag) {
  this.tagName = tag;
  this.children = [];
  this.listeners = {};
  this.attributes = {};
  this.className = "";
  this.textContent = "";
  this.value = "";
  this.type = "";
  this.checked = false;
  this.parentNode = null;
  var self = this;
  this.classList = { add: function (name) { self.className += " " + name; } };
}
Node.prototype.appendChild = function (child) { child.parentNode = this; this.children.push(child); return child; };
Node.prototype.removeChild = function (child) {
  this.children = this.children.filter(function (item) { return item !== child; });
  child.parentNode = null;
  return child;
};
Node.prototype.addEventListener = function (name, handler) {
  (this.listeners[name] = this.listeners[name] || []).push(handler);
};
Node.prototype.setAttribute = function (name, value) { this.attributes[name] = String(value); };
Node.prototype.fire = function (name) {
  (this.listeners[name] || []).forEach(function (handler) { handler({ type: name }); });
};
var document = {
  createElement: function (tag) { return new Node(tag); },
  createTextNode: function (text) { var node = new Node("#text"); node.textContent = text; return node; },
};
function hasClass(node, name) { return (" " + node.className + " ").indexOf(" " + name + " ") >= 0; }
function find(node, name) {
  if (hasClass(node, name)) { return node; }
  for (var index = 0; index < node.children.length; index += 1) {
    var hit = find(node.children[index], name);
    if (hit) { return hit; }
  }
  return null;
}
function count(node, name) {
  return (hasClass(node, name) ? 1 : 0) + node.children.reduce(function (sum, child) { return sum + count(child, name); }, 0);
}
function allText(node) { return node.textContent + node.children.map(allText).join(""); }

var calls = [];
function applyEnvFlag(name, value, persist) { calls.push([name, value, persist]); }

%(functions)s

function row(flag, typed) {
  calls = [];
  var built = renderEnvFlag(flag);
  var parts = {
    row: built,
    input: find(built, "env-flag-input"),
    set: find(built, "btn-primary"),
    clear: find(built, "env-flag-action--clear"),
    persist: find(built, "env-flag-persist").children[0],
  };
  if (typed !== undefined) { parts.input.value = typed; }
  return parts;
}
function strip(parts) { return find(parts.row, "env-flag-confirm"); }

var flags = %(flags)s;
var typed = %(typed)s;
var out = { types: {}, asked: {} };

Object.keys(flags).forEach(function (name) {
  out.types[name] = row(flags[name]).input.type;
  var parts = row(flags[name], "1");
  parts.set.fire("click");
  out.asked[name] = { strip: !!strip(parts), calls: calls.length };
});

var plain = row(flags[%(plain)s], typed);
plain.set.fire("click");
out.plain = { strip: !!strip(plain), calls: calls };

var parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
var shown = strip(parts);
out.armed = {
  calls: calls.length,
  text: allText(shown),
  role: shown.attributes.role,
  buttons: [find(shown, "env-flag-confirm-yes").textContent, find(shown, "env-flag-confirm-no").textContent],
};
parts.set.fire("click");
out.armedTwice = { strips: count(parts.row, "env-flag-confirm"), calls: calls.length };
find(strip(parts), "env-flag-confirm-yes").fire("click");
out.confirmed = { strip: !!strip(parts), calls: calls };

parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
parts.input.fire("input");
out.edited = { strip: !!strip(parts), calls: calls.length };
parts.set.fire("click");
out.editedThenSet = { strip: !!strip(parts), calls: calls.length };

parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
find(strip(parts), "env-flag-confirm-no").fire("click");
out.cancelled = { strip: !!strip(parts), calls: calls.length };

parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
parts.persist.fire("change");
out.persistChanged = { strip: !!strip(parts), calls: calls.length };

parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
parts.clear.fire("click");
out.cleared = { strip: !!strip(parts), calls: calls };

parts = row(flags[%(sensitive)s], "   ");
parts.set.fire("click");
out.emptySet = { strip: !!strip(parts), calls: calls };

// A value that changes without an event (a browser filling the field) is not what was confirmed.
parts = row(flags[%(sensitive)s], typed);
parts.set.fire("click");
parts.input.value = "/somewhere/else";
parts.persist.checked = !parts.persist.checked;
find(strip(parts), "env-flag-confirm-yes").fire("click");
out.confirmedAfterSilentChange = calls;

console.log(JSON.stringify(out));
"""


def _function_source(source: str, name: str) -> str:
    start = source.index(f"  function {name}(")
    return source[start:source.index("\n  }\n", start) + len("\n  }\n")]


def _page_views() -> dict[str, dict]:
    pytest.importorskip("fastapi")
    from yggdrasim_common.gui_server.routes import env_flags as route

    return {flag.name: route._view_for_flag(flag).model_dump() for flag in env_flags.iter_flags()}


@pytest.fixture(scope="module")
def page() -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    views = _page_views()
    plain = next(name for name, view in views.items() if view["kind"] == "string" and not view["sensitive"])
    for view in views.values():
        # No value of this machine reaches the harness: every flag is unset but the one under test.
        view["current_value"] = None
        view["is_set"] = False
    views[_COMMAND_FLAGS[0]].update(current_value=_CURRENT, is_set=True)
    source = _SOURCE.read_text(encoding="utf-8")
    script = _HARNESS % {
        "functions": _function_source(source, "renderEnvFlag") + _function_source(source, "envFlagConfirmStrip"),
        "flags": json.dumps(views),
        "typed": json.dumps(_TYPED),
        "plain": json.dumps(plain),
        "sensitive": json.dumps(_COMMAND_FLAGS[0]),
    }
    done = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    answer = json.loads(done.stdout)
    answer["plain_name"] = plain
    return answer


def test_a_flag_that_names_a_command_is_sensitive_and_says_why() -> None:
    for name in _COMMAND_FLAGS:
        flag = env_flags.get_flag(name)
        assert flag is not None
        assert flag.sensitive is True, name
        assert "the command this names" in flag.notes, name


def test_the_api_token_is_the_one_credential() -> None:
    assert [flag.name for flag in env_flags.iter_flags() if flag.secret] == ["YGGDRASIM_GUI_TOKEN"]


@pytest.mark.parametrize("name", _COMMAND_FLAGS)
def test_the_launcher_menu_asks_before_it_takes_the_value(name, monkeypatch, capsys) -> None:
    from main import env_flags_ui

    flag = env_flags.get_flag(name)
    for answer, expected in (("", False), ("n", False), ("y", True), ("YES", True)):
        monkeypatch.setattr("builtins.input", lambda _prompt, answer=answer: answer)
        assert env_flags_ui._confirm_sensitive(flag) is expected
        printed = capsys.readouterr().out
        assert f"{name} is security-sensitive." in printed
        assert flag.notes in printed


def _run_launcher_edit(monkeypatch, answers: list[str]) -> list[tuple]:
    """Drive the launcher's edit page for the SUCI command with typed answers; return the writes it made."""
    from main import env_flags_ui

    writes: list[tuple] = []
    pending = list(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt="": pending.pop(0))
    monkeypatch.setattr(
        env_flags, "set_flag_value", lambda flag, value, *, persist=True: writes.append(("set", flag.name, value, persist)) or value
    )
    monkeypatch.setattr(env_flags, "clear_flag_value", lambda flag, *, persist=True: writes.append(("clear", flag.name, persist)))
    env_flags_ui._edit_flag(env_flags.get_flag(_COMMAND_FLAGS[0]))
    assert pending == []
    return writes


def test_the_launcher_edit_page_writes_only_after_a_yes(monkeypatch, capsys) -> None:
    name = _COMMAND_FLAGS[0]
    assert _run_launcher_edit(monkeypatch, ["S", "n", "Q"]) == []
    assert "Change cancelled." in capsys.readouterr().out
    assert _run_launcher_edit(monkeypatch, ["S", "y", _TYPED, "Q"]) == [("set", name, _TYPED, True)]
    # Set for this session only asks the same question.
    assert _run_launcher_edit(monkeypatch, ["T", "", "Q"]) == []
    assert _run_launcher_edit(monkeypatch, ["T", "yes", _TYPED, "Q"]) == [("set", name, _TYPED, False)]
    # Clear is not asked about.
    assert _run_launcher_edit(monkeypatch, ["C", "Q"]) == [("clear", name, True)]


def test_the_route_tells_the_page_why_a_flag_is_sensitive() -> None:
    views = _page_views()
    for flag in env_flags.iter_flags():
        view = views[flag.name]
        assert view["sensitive"] is flag.sensitive
        assert view["notes"] == flag.notes
        assert view["secret"] is flag.secret


def test_set_on_a_plain_flag_writes_at_once(page) -> None:
    assert page["plain"] == {"strip": False, "calls": [[page["plain_name"], _TYPED, True]]}


def test_set_on_every_sensitive_flag_asks_first(page) -> None:
    sensitive = {flag.name for flag in env_flags.iter_flags() if flag.sensitive}
    assert set(_COMMAND_FLAGS) <= sensitive
    for flag in env_flags.iter_flags():
        asked = page["asked"][flag.name]
        if flag.name in sensitive:
            assert asked == {"strip": True, "calls": 0}, flag.name
        else:
            assert asked == {"strip": False, "calls": 1}, flag.name


def test_the_confirmation_names_the_flag_and_the_reason_and_never_the_value(page) -> None:
    name = _COMMAND_FLAGS[0]
    armed = page["armed"]
    assert armed["calls"] == 0
    assert armed["role"] == "alert"
    assert armed["buttons"] == ["Confirm", "Cancel"]
    assert armed["text"] == f"{name} is security-sensitive. {env_flags.get_flag(name).notes}ConfirmCancel"
    assert _TYPED not in armed["text"]
    assert _CURRENT not in armed["text"]
    # A second Set adds no second confirmation and writes nothing.
    assert page["armedTwice"] == {"strips": 1, "calls": 0}


def test_confirm_writes_what_was_shown_when_set_was_pressed(page) -> None:
    name = _COMMAND_FLAGS[0]
    assert page["confirmed"] == {"strip": False, "calls": [[name, _TYPED, True]]}
    assert page["confirmedAfterSilentChange"] == [[name, _TYPED, True]]


def test_a_change_or_cancel_withdraws_the_confirmation(page) -> None:
    assert page["edited"] == {"strip": False, "calls": 0}
    assert page["editedThenSet"] == {"strip": True, "calls": 0}
    assert page["cancelled"] == {"strip": False, "calls": 0}
    assert page["persistChanged"] == {"strip": False, "calls": 0}


def test_clearing_is_not_asked_about(page) -> None:
    # The launcher menu clears without a question as well; an empty field is a clear.
    name = _COMMAND_FLAGS[0]
    assert page["cleared"] == {"strip": False, "calls": [[name, "", True]]}
    assert page["emptySet"] == {"strip": False, "calls": [[name, "   ", True]]}


def test_only_a_credential_is_typed_blind(page) -> None:
    for flag in env_flags.iter_flags():
        if flag.choices:
            continue
        assert page["types"][flag.name] == ("password" if flag.secret else "text"), flag.name
