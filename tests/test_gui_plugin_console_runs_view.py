# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of the run form in the plugin console view.

The skeleton carries generic labels only (every one is replaced by the
manifest's), the controllers build plugin strings with ``textContent``, a
start sends the visible fields only, and ``pcRunPlan`` in the bundle answers
the selection table exactly as ``plan_run`` does on the server.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from yggdrasim_common.gui_server.plugin_console_manifest import validate_manifest
from yggdrasim_common.gui_server.plugin_console_runform import LABEL_DEFAULTS
from yggdrasim_common.gui_server.plugin_console_selection import find_variant, plan_run

from tests.plugin_console_runs_support import PICK_CASES, SELECTION_CASES, demo_manifest, named_demo_runs, pick_demo_runs

_REPO_ROOT = Path(__file__).resolve().parents[1]
_STATIC = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static"
_SRC = _REPO_ROOT / "gui_frontend" / "src"
_RUN_CONTROLLERS = ("plugin-console-runform.js", "plugin-console-credentials.js", "plugin-console-runs.js")
_PLAN_FUNCTIONS = ("pcHas", "pcRunMatches", "pcRunBlank", "pcRunNormal", "pcRunOptions", "pcRunEvaluate", "pcRunPlan")
_PICK_FUNCTIONS = (
    "pcHas",
    "pcCredentialValue",
    "pcCredentialDefinition",
    "pcCredentialStatus",
    "pcCredentialEntries",
    "pcCredentialUsable",
    "pcCredentialDraft",
    "pcCredentialTyped",
    "pcCredentialNameTaken",
    "pcCredentialPick",
    "pcCredentialPicks",
    "pcCredentialProblem",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _runs_section(html: str) -> str:
    # The run form sits in the controls pane, the current run and history in the output pane.
    start = html.index('<div class="pc-tab-panel" id="pc-tab-run"')
    return html[start : html.index('<section data-view="registry"', start)]


def _function(source: str, name: str) -> str:
    """The text of ``function <name>(...) {...}``, braces matched outside string literals."""
    start = source.index(f"function {name}(")
    depth = 0
    quote = ""
    index = source.index("{", start)
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise AssertionError(f"unterminated function {name}")


def test_the_run_skeleton_is_in_the_bundle_with_generic_labels_only() -> None:
    section = _runs_section(_read(_STATIC / "index.html"))
    for element_id in (
        "pc-run-form-title",
        "pc-run-variant",
        "pc-run-common",
        "pc-run-fields",
        "pc-run-before",
        "pc-run-before-title",
        "pc-run-credentials",
        "pc-run-before-groups",
        "pc-run-items-title",
        "pc-run-items",
        "pc-run-after-groups",
        "pc-run-start",
        "pc-run-validation",
        "pc-run-current-title",
        "pc-run-state",
        "pc-run-cancel",
        "pc-run-title",
        "pc-run-meta",
        "pc-run-error",
        "pc-run-results",
        "pc-run-log",
        "pc-run-history-title",
        "pc-run-list",
        "pc-tab-credentials",
        "pc-credentials-title",
        "pc-credentials",
    ):
        assert f'id="{element_id}"' in section, element_id
    assert "<label" not in section
    for key in ("form", "credentials", "items", "start", "current", "history"):
        assert f">{LABEL_DEFAULTS[key]}<" in section, key


def test_every_skeleton_label_is_replaced_from_the_manifest() -> None:
    runs = _read(_SRC / "js" / "plugin-console-runs.js")
    for element_id, key in (
        ("pc-run-form-title", "form"),
        ("pc-run-before-title", "credentials"),
        ("pc-run-items-title", "items"),
        ("pc-run-start", "start"),
        ("pc-run-cancel", "cancel"),
        ("pc-run-current-title", "current"),
        ("pc-run-history-title", "history"),
    ):
        assert f'setText("{element_id}", labels.{key});' in runs, element_id
    assert "runs.labels.variant" in _read(_SRC / "js" / "plugin-console-runform.js")
    assert "runs.labels.empty_history" in runs


def test_the_run_controllers_are_bundled_after_the_poll() -> None:
    js_order = _read(_SRC / "js" / ".js_order").split()
    positions = [js_order.index(name) for name in ("plugin-console-poll.js", *_RUN_CONTROLLERS, "saip-workbench.js")]
    assert positions == sorted(positions)
    css_order = _read(_SRC / "css" / ".css_order").split()
    assert css_order.index("views/plugin-console.css") < css_order.index("views/plugin-console-runs.css")
    bundle = _read(_STATIC / "app.js")
    for name in ("function pcRunPlan(", "function pcRenderRuns(", "async function pcStoreCredential(", "async function pcRunPoll("):
        assert name in bundle, name


def test_the_run_controllers_render_plugin_strings_as_text_only() -> None:
    for name in _RUN_CONTROLLERS:
        js = _read(_SRC / "js" / name)
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", ".style.", 'setAttribute("style"', 'setAttribute("on'):
            assert banned not in js, (name, banned)
        assert "textContent" in js, name


def test_a_start_sends_the_visible_fields_only_and_stores_typed_credentials_first() -> None:
    runs = _read(_SRC / "js" / "plugin-console-runs.js")
    body = _function(runs, "pcStartRun")
    assert "plan.visible.forEach(function (name) { values[name] = plan.given[name]; });" in body
    assert body.index("pcStoreCredential(") < body.index('pcApi(consoleId, "/runs")')
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    assert 'input.type = field.secret ? "password"' in forms
    assert 'input.autocomplete = field.secret ? "new-password" : "off";' in forms


def test_the_status_poll_hands_an_active_run_to_the_run_poll() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert "pcRunsOnStatus(status);" in _function(poll, "pcRenderStatus")
    assert "pcRunStopPoll();" in _function(poll, "pcStopPolling")
    assert "var running = Boolean(status.running) && !manifest.runs;" in poll


def test_the_run_stylesheet_reaches_colour_through_tokens_only() -> None:
    css = re.sub(r"/\*.*?\*/", "", _read(_SRC / "css" / "views" / "plugin-console-runs.css"), flags=re.DOTALL)
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", css) is None
    assert re.search(r"\b(?:rgb|rgba|hsl|hsla)\(", css) is None
    assert "position: fixed" not in css and "resize: both" not in css
    assert re.search(r"var\(--[a-z-]+,", css) is None
    for token in ("var(--warn", "var(--fail", "var(--accent"):
        assert token in css, token


def test_the_view_plans_a_pick_exactly_as_the_server_does() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's plan under test.")
    bundle = _read(_STATIC / "app.js")
    functions = "\n".join(_function(bundle, name) for name in _PLAN_FUNCTIONS)
    runs = validate_manifest(demo_manifest(pick_demo_runs()))["runs"]
    variant = find_variant(runs, "other")
    cases = [{"ticked": ticked, "values": values, "choices": choices} for _name, ticked, values, choices, _expected in PICK_CASES]
    harness = (
        functions
        + "\nconst runs = "
        + json.dumps(runs)
        + ";\nconst variant = runs.variants[1];\nconst cases = "
        + json.dumps(cases)
        + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => pcRunPlan(runs, variant, c.ticked, c.values, c.choices))));\n"
    )
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    answers = json.loads(completed.stdout)
    for (name, ticked, values, choices, expected), answer in zip(PICK_CASES, answers):
        server = plan_run(runs, variant, ticked, values, choices)
        keys = ("items", "auto_items", "visible", "values", "missing", "credentials")
        assert {key: answer[key] for key in keys} == {key: server[key] for key in keys}, name
        assert {key: answer[key] for key in expected} == expected, name


def test_the_view_plans_a_run_exactly_as_the_server_does() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's plan under test.")
    bundle = _read(_STATIC / "app.js")
    functions = "\n".join(_function(bundle, name) for name in _PLAN_FUNCTIONS)
    runs = validate_manifest(demo_manifest())["runs"]
    variant = find_variant(runs, "basic")
    cases = [{"ticked": ticked, "values": values} for _name, ticked, values, _expected in SELECTION_CASES]
    harness = (
        functions
        + "\nconst runs = "
        + json.dumps(runs)
        + ";\nconst variant = runs.variants[0];\nconst cases = "
        + json.dumps(cases)
        + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => pcRunPlan(runs, variant, c.ticked, c.values))));\n"
    )
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    answers = json.loads(completed.stdout)
    for (name, ticked, values, expected), answer in zip(SELECTION_CASES, answers):
        server = plan_run(runs, variant, ticked, values)
        keys = ("items", "auto_items", "visible", "missing", "credentials")
        assert {key: answer[key] for key in keys} == {key: server[key] for key in keys}, name
        assert {key: answer[key] for key in expected} == expected, name
        # Valid values normalise alike, so a controller reads the same on both sides.
        assert answer["values"] == server["values"], name


def test_a_named_credential_sends_its_entry_name_and_the_run_its_picks() -> None:
    credentials = _read(_SRC / "js" / "plugin-console-credentials.js")
    store = _function(credentials, "pcStoreCredential")
    assert "if (definition.named) body.name = name;" in store
    # Store bypasses the run validation, so it refuses an Add under a stored name itself.
    assert store.index("pcCredentialNameTaken(id, name)") < store.index("apiFetch(")
    assert '"?name=" + encodeURIComponent(name)' in _function(credentials, "pcForgetCredential")
    assert 'label.textContent = "Use for this run";' in _function(credentials, "pcCredentialPicker")
    runs = _read(_SRC / "js" / "plugin-console-runs.js")
    start = _function(runs, "pcStartRun")
    assert "request.credential_entries = picks;" in start
    assert start.index("pcStoreCredential(") < start.index("pcCredentialPicks(plan.credentials)")
    assert "var problem = pcCredentialProblem(id);" in _function(_read(_SRC / "js" / "plugin-console-runform.js"), "pcRunValidate")


# Stored entries, drafts and picks -> the pick, the run's picks and the problems.
_PICK_CASES = [
    ("nothing stored", {}, {}, {}, {"pick": "", "picks": {}, "problem": "enter the Vault token", "plain": "enter the Service key"}),
    ("the only usable entry is picked by itself", {"vault": [("prod", True), ("old", False)]}, {}, {}, {"pick": "prod", "picks": {"vault": "prod"}, "problem": ""}),
    ("two usable entries wait for a pick", {"vault": [("prod", True), ("stage", True)]}, {}, {}, {"pick": "", "picks": {}, "problem": "pick the Vault token this run uses"}),
    ("the operator's pick wins", {"vault": [("prod", True), ("stage", True)]}, {}, {"vault": "stage"}, {"pick": "stage", "picks": {"vault": "stage"}, "problem": ""}),
    ("a pick that is not usable falls back", {"vault": [("prod", True), ("old", False)]}, {}, {"vault": "old"}, {"pick": "prod", "problem": ""}),
    ("a typed new entry needs a name", {"vault": [("prod", True), ("stage", True)]}, {"vault": {"values": {"token": "T"}, "replacing": True, "name": " ", "target": ""}}, {}, {"problem": "name the new Vault token"}),
    ("a typed new entry with a name is enough", {}, {"vault": {"values": {"token": "T"}, "replacing": False, "name": "prod", "target": ""}}, {}, {"problem": ""}),
    ("a typed replacement is enough", {"vault": [("prod", True), ("stage", True)]}, {"vault": {"values": {"token": "T"}, "replacing": True, "name": "", "target": "stage"}}, {}, {"problem": ""}),
    ("adding under a stored name is refused", {"vault": [("prod", True)]}, {"vault": {"values": {"token": "T"}, "replacing": True, "name": " PROD ", "target": ""}}, {}, {"problem": "Vault token: an entry of that name exists; use its Replace"}),
]


def test_the_view_picks_the_entry_a_run_uses() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's pick under test.")
    bundle = _read(_STATIC / "app.js")
    runs = validate_manifest(demo_manifest(named_demo_runs()))["runs"]
    cases = []
    for _name, stored, drafts, picks, _expected in _PICK_CASES:
        credentials = {
            credential_id: {"stored": True, "usable": any(usable for _entry, usable in rows), "summary": "", "entries": [{"name": entry, "usable": usable, "summary": "", "values": {}} for entry, usable in rows]}
            for credential_id, rows in stored.items()
        }
        cases.append({"credentials": credentials, "drafts": drafts, "picks": picks})
    harness = (
        "\n".join(_function(bundle, name) for name in _PICK_FUNCTIONS)
        + "\nconst runs = "
        + json.dumps(runs)
        + ";\nfunction pcRuns() { return runs; }\nlet pcState = {};\nconst cases = "
        + json.dumps(cases)
        + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => {\n"
        + "  pcState = { credentials: c.credentials, credentialDrafts: c.drafts, credentialPicks: c.picks };\n"
        + "  return { pick: pcCredentialPick('vault'), picks: pcCredentialPicks(['vault']), problem: pcCredentialProblem('vault'), plain: pcCredentialProblem('service'), none: pcCredentialPicks(['service']) };\n"
        + "})));\n"
    )
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    for (name, _stored, _drafts, _picks, expected), answer in zip(_PICK_CASES, json.loads(completed.stdout)):
        assert {key: answer[key] for key in expected} == expected, name
        assert answer["none"] is None, name


def test_a_credential_with_an_optional_secret_counts_as_typed_once_its_required_fields_are_filled() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's pick under test.")
    bundle = _read(_STATIC / "app.js")
    runs = validate_manifest(demo_manifest(named_demo_runs()))["runs"]
    # A client certificate: required settings and a passphrase that may stay empty.
    runs["credentials"].append(
        {
            "id": "cert",
            "label": "Client certificate",
            "hint": "",
            "named": True,
            "fields": [
                {"name": "url", "label": "URL", "type": "text", "required": True, "secret": False, "default": "", "max_length": 256},
                {"name": "passphrase", "label": "Passphrase", "type": "text", "required": False, "secret": True, "default": "", "max_length": 256},
            ],
        }
    )
    cases = [
        ("an untouched form", "cert", {}, {"typed": False, "problem": "enter the Client certificate"}),
        ("every required field filled, no passphrase", "cert", {"values": {"url": "https://eim.example.test"}, "replacing": False, "name": "lab", "target": ""}, {"typed": True, "problem": ""}),
        ("a required field left blank", "cert", {"values": {"url": " "}, "replacing": False, "name": "lab", "target": ""}, {"typed": False, "problem": "enter the Client certificate"}),
        ("filled but not named", "cert", {"values": {"url": "https://eim.example.test"}, "replacing": False, "name": "", "target": ""}, {"typed": True, "problem": "name the new Client certificate"}),
        ("a required secret still has to be typed", "vault", {"values": {"url": "https://vault.example.test"}, "replacing": False, "name": "prod", "target": ""}, {"typed": False, "problem": "enter the Vault token"}),
    ]
    harness = (
        "\n".join(_function(bundle, name) for name in _PICK_FUNCTIONS)
        + "\nconst runs = "
        + json.dumps(runs)
        + ";\nfunction pcRuns() { return runs; }\nlet pcState = {};\nconst cases = "
        + json.dumps([{"id": credential_id, "draft": draft} for _name, credential_id, draft, _expected in cases])
        + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => {\n"
        + "  const drafts = {}; if (Object.keys(c.draft).length) drafts[c.id] = c.draft;\n"
        + "  pcState = { credentials: {}, credentialDrafts: drafts, credentialPicks: {} };\n"
        + "  return { typed: pcCredentialTyped(c.id), problem: pcCredentialProblem(c.id) };\n"
        + "})));\n"
    )
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    for (name, _credential_id, _draft, expected), answer in zip(cases, json.loads(completed.stdout)):
        assert answer == expected, name


def test_every_credential_has_a_panel_in_its_tab_and_the_form_shows_what_it_needs() -> None:
    credentials = _read(_SRC / "js" / "plugin-console-credentials.js")
    render = _function(credentials, "pcRenderCredentials")
    assert '$("pc-credentials")' in render and "host.appendChild(pcCredentialPanel(definition.id));" in render
    assert "needs.appendChild(pcCredentialNeed(id));" in render
    need = _function(credentials, "pcCredentialNeed")
    assert 'pcSelectTab("controls", "credentials", true);' in need
    assert "row.appendChild(pcCredentialPicker(id, usable));" in need
    # The panel's buttons carry the credential's own words (a sign-in reads Sign in / Sign out).
    panel = _function(credentials, "pcCredentialPanel")
    for key in ("store", "replace", "forget"):
        assert f"buttonsText.{key}" in panel, key
    assert "pcCredentialButtons(definition).forget" in _function(credentials, "pcForgetCredential")
    runs = _read(_SRC / "js" / "plugin-console-runs.js")
    assert 'setText("pc-credentials-title", labels.credentials);' in runs
