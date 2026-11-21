# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of the generic plugin console view in the served bundle.

One view renders every console from its validated manifest: the markup is a
fixed skeleton, the nav leaves are added to ``CC_NAV_TREE`` at runtime when
the console list lands, and the controller builds every plugin string with
``textContent``. The poll asks for the status and every stream in one
request, and the stylesheet reaches colour through tokens only.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_STATIC = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static"
_SRC = _REPO_ROOT / "gui_frontend" / "src"
_CONTROLLERS = ("plugin-console.js", "plugin-console-forms.js", "plugin-console-poll.js", "plugin-console-compare.js", "plugin-console-tabs.js", "plugin-console-pills.js")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _section(html: str) -> str:
    start = html.index('<section data-view="plugin_console"')
    return html[start : html.index('<section data-view="registry"', start)]


def test_the_view_skeleton_is_in_the_bundle() -> None:
    html = _read(_STATIC / "index.html")
    section = _section(html)
    for element_id in (
        "pc-title",
        "pc-summary",
        "pc-refresh",
        "pc-chip",
        "pc-notice",
        "pc-layout",
        "pc-pane-controls",
        "pc-pane-output",
        "pc-tabs-controls",
        "pc-tabs-output",
        "pc-tab-session",
        "pc-tab-state",
        "pc-tab-actions",
        "pc-tab-run",
        "pc-tab-compare",
        "pc-tab-runs",
        "pc-state-panel",
        "pc-state-title",
        "pc-state-empty",
        "pc-run-status",
        "pc-start-fields",
        "pc-start-controls",
        "pc-start",
        "pc-stop",
        "pc-last-error",
        "pc-state",
        "pc-actions-panel",
        "pc-actions",
        "pc-command-panel",
        "pc-transcript",
        "pc-command-form",
        "pc-command-input",
        "pc-help",
        "pc-help-body",
        "pc-streams",
        "pc-compare",
        "pc-compare-title",
        "pc-compare-summary",
        "pc-compare-hint",
        "pc-compare-note",
        "pc-compare-body",
    ):
        assert f'id="{element_id}"' in section, element_id
    # Every field label is built with its input; none points at a generated id.
    assert "<label" not in section


def test_the_controllers_and_stylesheet_are_in_the_build_manifests() -> None:
    js_order = _read(_SRC / "js" / ".js_order").split()
    positions = [js_order.index(name) for name in ("command-center.js", *_CONTROLLERS, "saip-workbench.js")]
    assert positions == sorted(positions)
    assert "views/plugin-console.css" in _read(_SRC / "css" / ".css_order").split()
    bundle = _read(_STATIC / "app.js")
    for name in ("function loadPluginConsoles(", "function pcRenderConsole(", "async function pcPoll("):
        assert name in bundle, name
    assert ".pc-stream-table th" in _read(_STATIC / "app.css")


def test_consoles_become_leaves_of_the_plugin_consoles_group_at_runtime() -> None:
    js = _read(_SRC / "js" / "plugin-console.js")
    assert 'var PC_GROUP_ID = "group-plugin-consoles";' in js
    assert 'var PC_LEAF_PREFIX = "leaf-plugin-console-";' in js
    assert 'inspectView: "plugin_console",' in js
    # A listing replaces the group's leaves; with no console the group leaves the tree.
    assert "pcNavGroup().children = pcState.consoles.map(" in js
    assert "if (pcState.consoles.length === 0) {" in js and "CC_NAV_TREE.splice(index, 1);" in js
    # The group is added before Advanced, never carried by the static tree.
    assert 'CC_NAV_TREE[j].id === "group-advanced"' in js and "CC_NAV_TREE.splice(at, 0, group);" in js
    assert "renderCommandNav(commandState.catalogue);" in js
    assert "renderOverviewModuleLauncher(commandState.catalogue);" in js
    assert "group-plugin-consoles" not in _read(_SRC / "js" / "command-center.js")


def test_the_view_is_wired_into_navigation_and_bootstrap() -> None:
    command_center = _read(_SRC / "js" / "command-center.js")
    assert 'viewName === "plugin_console"' in command_center
    assert "loadPluginConsole(commandState.activeLeafId);" in command_center
    assert 'if (viewName !== "plugin_console") {\n      pcStopPolling();' in command_center
    assert 'plugin_console: "Plugin consoles",' in _read(_SRC / "js" / "core.js")
    trailing = _read(_SRC / "js" / "trailing.js")
    assert "wirePluginConsolePanel();" in trailing
    assert trailing.index("loadCommandCatalogue()") < trailing.index("loadPluginConsoles();")


def test_generated_field_ids_cannot_shadow_the_skeleton() -> None:
    static_ids = re.findall(r'\bid="([^"]+)"', _section(_read(_SRC / "index.html")))
    assert static_ids and not any(value.startswith("pc-f-") for value in static_ids)
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    assert 'var PC_FIELD_ID_PREFIX = "pc-f-";' in forms
    assert 'pcBuildField(field, PC_FIELD_ID_PREFIX + "start-")' in forms
    assert 'pcBuildField(field, PC_FIELD_ID_PREFIX + "act-" + action.id + "-")' in forms


def test_a_poll_asked_for_during_a_console_switch_is_kept() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    body = poll[poll.index("async function pcPoll(") : poll.index("function pcRenderStatus(")]
    after = body[body.index("pcState.polling = false;") :]
    assert after.index("if (pcState.pollAgain) {") < after.index("consoleId !== pcState.activeId")


# The one style write: a stream table's minimum width, a number summed from
# PC_COLUMN_MIN_EM (the closed width vocabulary), never a plugin string.
_TABLE_MINIMUM = 'table.style.setProperty("--pc-table-min", minimum.toFixed(1) + "em");'


def test_the_controllers_render_plugin_strings_as_text_only() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert poll.count(_TABLE_MINIMUM) == 1
    assert "minimum += PC_COLUMN_MIN_EM[pcColumnClass(column)] || PC_COLUMN_MIN_EM.fill;" in poll
    for name in _CONTROLLERS:
        js = _read(_SRC / "js" / name).replace(_TABLE_MINIMUM, "")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", ".style.", "setAttribute(\"style\"", "setAttribute(\"on"):
            assert banned not in js, (name, banned)
        assert "textContent" in js, name


def test_one_request_per_poll_tick() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert 'apiFetch(pcApi(consoleId, "/stream") + pcStreamQuery(manifest))' in poll
    assert '"cursor=" + encodeURIComponent(stream.id + ":"' in poll
    for name in _CONTROLLERS:
        assert '"/status"' not in _read(_SRC / "js" / name), name
    # The oldest rows past the cap go in one range, not one removal per row.
    trim = _function(poll, "pcTrimRows")
    assert "var extra = body.rows.length - PC_MAX_ROWS;" in trim and "range.deleteContents();" in trim


def test_the_stylesheet_reaches_colour_through_tokens_only() -> None:
    css = re.sub(r"/\*.*?\*/", "", _read(_SRC / "css" / "views" / "plugin-console.css"), flags=re.DOTALL)
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", css) is None
    assert re.search(r"\b(?:rgb|rgba|hsl|hsla)\(", css) is None
    assert "position: fixed" not in css and "resize: both" not in css
    assert re.search(r"var\(--[a-z-]+,", css) is None
    for token in ("var(--ok", "var(--warn", "var(--fail"):
        assert token in css, token


def _function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    depth = 0
    index = source.index("{", start)
    while index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise AssertionError(f"unbalanced function {name}")


def test_the_comparison_panel_follows_the_status_and_its_manifest() -> None:
    html = _section(_read(_SRC / "index.html"))
    assert html.index('id="pc-layout"') < html.index('id="pc-compare"') < html.index('id="pc-runs"')
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    render_status = poll[poll.index("function pcRenderStatus(") : poll.index("function pcValueText(")]
    assert "pcRenderCompare(status ? status.compare : null);" in render_status
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    assert "pcRenderCompareManifest(manifest);" in forms
    console = _read(_SRC / "js" / "plugin-console.js")
    assert 'compareSignature: "",' in console and "pcRenderCompareManifest(null);" in console
    compare = _read(_SRC / "js" / "plugin-console-compare.js")
    # Redrawn only when the answer changed; every plugin string is text.
    assert "if (signature === pcState.compareSignature) return;" in compare
    assert compare.count("textContent =") >= 8


def test_the_comparison_summary_counts_what_differs() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's summary under test.")
    compare = _read(_SRC / "js" / "plugin-console-compare.js")
    functions = "\n".join(_function(compare, name) for name in ("pcCompareCounts", "pcCompareSummary"))
    cases = [
        [],
        [{"rows": [{"verdict": "same"}, {"verdict": "info"}]}],
        [{"rows": [{"verdict": "differs"}, {"verdict": "missing"}]}, {"rows": [{"verdict": "differs"}]}],
        [{"rows": None}, None],
    ]
    harness = functions + "\nconst cases = " + json.dumps(cases) + ";\nprocess.stdout.write(JSON.stringify(cases.map((c) => pcCompareSummary(pcCompareCounts(c)))));\n"
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == ["nothing to compare yet", "all rows match", "2 differ, 1 on one side only", "nothing to compare yet"]


def test_the_comparison_verdicts_reach_colour_through_status_tokens() -> None:
    css = _read(_SRC / "css" / "views" / "plugin-console.css")
    assert ".pc-compare-row--differs .pc-compare-verdict {\n  background: var(--warn-soft);\n  color: var(--warn);" in css
    assert ".pc-compare-row--missing .pc-compare-verdict {\n  background: var(--fail-soft);\n  color: var(--fail);" in css
    assert ".pc-compare-row--same .pc-compare-verdict {\n  color: var(--ok);" in css


def test_a_filled_start_field_gets_a_button_that_asks_the_console() -> None:
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    assert "fill.textContent = field.fill.label;" in forms
    assert 'apiFetch(pcApi(consoleId, "/fill"), { method: "POST", body: JSON.stringify({ field: field.name, values: values }) })' in forms
    assert "input.value = String(answer.value || \"\");" in forms
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert '"#pc-start-fields [data-pc-type], #pc-start-fields .pc-field-fill"' in poll


# --- panes and tabs ------------------------------------------------------------------


def _manifest_for(**parts: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "id": "demo",
        "start": None,
        "state": None,
        "actions": [],
        "command_line": None,
        "streams": [],
        "compare": None,
        "runs": None,
    }
    manifest.update(parts)
    return manifest


def test_each_pane_gets_a_tab_per_declared_part() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's tab plan under test.")
    tabs = _read(_SRC / "js" / "plugin-console-tabs.js")
    runs = {"labels": {"form": "Queue operations", "history": "Queue runs", "credentials": "Sign-in and keys"}, "credentials": [{"id": "portal"}]}
    keyless = {"labels": {"form": "New run", "history": "Recent runs", "credentials": "Keys"}, "credentials": []}
    stream = {"id": "trace", "title": "APDU trace"}
    cases = [
        # A session console with a titled state, actions and two streams.
        _manifest_for(start={"label": "Start"}, state={"title": "Environment"}, actions=[{}], command_line={}, streams=[{"id": "log", "title": "Log"}, stream]),
        # A console with a comparison and a run form beside its session.
        _manifest_for(start={"label": "Open"}, actions=[{}], command_line={}, streams=[stream], compare={"title": "Card and middleware"}, runs=runs),
        # A run form alone (with and without credentials), and a command line alone.
        _manifest_for(runs=runs),
        _manifest_for(runs=keyless),
        _manifest_for(command_line={}),
    ]
    harness = (
        'var PC_STREAM_TAB_PREFIX = "stream-";\n'
        + _function(tabs, "pcTabPlan")
        + "\nconst cases = " + json.dumps(cases) + ";\n"
        + "process.stdout.write(JSON.stringify(cases.map((m) => { const p = pcTabPlan(m); return [p.controls.map((t) => t.id + '=' + t.label), p.output.map((t) => t.id + '=' + t.label)]; })));\n"
    )
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == [
        [["session=Session", "state=Environment", "actions=Actions"], ["stream-log=Log", "stream-trace=APDU trace"]],
        [["session=Session", "actions=Actions", "run=Queue operations", "credentials=Sign-in and keys"], ["compare=Card and middleware", "stream-trace=APDU trace", "runs=Queue runs"]],
        [["run=Queue operations", "credentials=Sign-in and keys"], ["runs=Queue runs"]],
        [["run=New run"], ["runs=Recent runs"]],
        [["session=Session", "actions=Command line"], []],
    ]


def test_tabs_are_rendered_after_the_panels_and_remembered_without_relying_on_storage() -> None:
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    render = _function(forms, "pcRenderConsole")
    assert render.index("pcRenderStreams(manifest);") < render.index("pcRenderTabs(manifest);")
    assert render.index("pcPlaceState(manifest);") < render.index("pcRenderTabs(manifest);")
    tabs = _read(_SRC / "js" / "plugin-console-tabs.js")
    for name in ("pcRememberedTab", "pcRememberTab"):
        body = _function(tabs, name)
        assert "try {" in body and "catch (_err)" in body, name
    select = _function(tabs, "pcSelectTab")
    assert "button.tabIndex = on ? 0 : -1;" in select and 'button.setAttribute("aria-selected"' in select
    # A stream tab that is shown again jumps to its newest row when it follows new rows.
    assert "pcStreamShown(" in select
    keys = _function(tabs, "pcTabKeydown")
    for key in ("ArrowRight", "ArrowLeft", "Home", "End"):
        assert f'"{key}"' in keys, key
    core = _read(_SRC / "js" / "core.js")
    assert 'mainEl.classList.toggle("main--plugin-console", name === "plugin_console");' in core


def test_stream_tables_have_fixed_columns_and_cut_long_values() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    render = _function(poll, "pcRenderStreams")
    assert 'document.createElement("colgroup")' in render
    assert 'col.className = "pc-col pc-col--" + pcColumnClass(column);' in render
    assert 'row.classList.toggle("is-expanded");' in render
    assert 'table.classList.toggle("is-wrapped", on);' in render
    append = _function(poll, "pcAppendRows")
    # A hidden table reads zero sizes; it keeps the follow choice it had.
    assert "var shown = scroll.clientHeight > 0;" in append and ": pcStreamPinned(stream.id);" in append
    assert "if (pinned && shown) scroll.scrollTop = scroll.scrollHeight;" in append
    css = _read(_SRC / "css" / "views" / "plugin-console.css")
    assert "table-layout: fixed;" in css and "contain: content;" in css
    for width in ("time", "narrow", "medium"):
        assert f".pc-col--{width} {{" in css, width
    assert ".pc-cell--clip {\n  overflow: hidden;\n  text-overflow: ellipsis;\n  white-space: nowrap;" in css


def test_a_state_poll_rewrites_values_in_place() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    body = _function(poll, "pcRenderState")
    assert "if (keys === pcState.stateKeys && pcState.stateCells.length === rows.length) {" in body
    assert "if (cell.textContent !== row[1]) cell.textContent = row[1];" in body
    place = _function(poll, "pcPlaceState")
    assert 'var home = manifest.state ? $("pc-state-panel") : $("pc-session");' in place


# --- top bar pills and inline action results --------------------------------------------


def test_top_bar_pills_poll_only_while_visible_and_open_their_console() -> None:
    html = _read(_SRC / "index.html")
    cluster = html[html.index('<div class="status-cluster">') : html.index('id="badge-api"')]
    assert 'id="topbar-plugin-pills" hidden' in cluster
    pills = _read(_SRC / "js" / "plugin-console-pills.js")
    poll = _function(pills, "pcPollPills")
    assert "if (document.hidden || pcPills.polling) return;" in poll
    assert 'apiFetch("/api/plugin-consoles/pills")' in poll
    render = _function(pills, "pcRenderPills")
    assert 'ccOpenInspectView("plugin_console", PC_LEAF_PREFIX + pill.console);' in render
    assert '"topbar-card-bridge topbar-plugin-pill"' in render
    console = _read(_SRC / "js" / "plugin-console.js")
    assert "pcSchedulePills(0);" in _function(console, "loadPluginConsoles")
    assert "pcSchedulePills(0);" in _function(console, "wirePluginConsolePanel")
    shell = _read(_SRC / "css" / "layout" / "shell.css")
    assert '.topbar-card-bridge[data-state="warn"] {' in shell
    assert ".topbar-plugin-pill .topbar-card-bridge-value {\n    display: none;" in shell


def test_comparison_sections_fold_and_remember_their_state() -> None:
    compare = _read(_SRC / "js" / "plugin-console-compare.js")
    render = _function(compare, "pcRenderCompare")
    assert 'document.createElement("details")' in render and 'document.createElement("summary")' in render
    assert 'block.setAttribute("data-pc-section", title);' in render
    # A redraw keeps a section as it is on screen; a new one opens unless it was folded before.
    assert 'body.querySelectorAll("details[data-pc-section]")' in render
    assert "shown[title] : folded.indexOf(title) < 0;" in render
    assert "pcCompareRememberFold(consoleId, title, block.open);" in render
    remembered = _function(compare, "pcCompareFolded")
    assert "window.localStorage.getItem(PC_COMPARE_FOLD_KEY + consoleId)" in remembered and "catch (_err)" in remembered
    css = _read(_SRC / "css" / "views" / "plugin-console.css")
    assert ".pc-compare-section[open] > .pc-compare-heading::before {" in css
    assert ".pc-compare-heading::-webkit-details-marker {\n  display: none;" in css


def test_a_section_heading_counts_its_rows() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to run the view's heading text under test.")
    compare = _read(_SRC / "js" / "plugin-console-compare.js")
    functions = "\n".join(_function(compare, name) for name in ("pcCompareCounts", "pcCompareSectionMeta"))
    cases = [{"rows": []}, {"rows": [{"verdict": "same"}]}, {"rows": [{"verdict": "differs"}, {"verdict": "missing"}, {"verdict": "info"}]}]
    harness = functions + "\nconst cases = " + json.dumps(cases) + ";\nprocess.stdout.write(JSON.stringify(cases.map(pcCompareSectionMeta)));\n"
    completed = subprocess.run([node, "-e", harness], check=False, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == ["0 rows", "1 row", "3 rows, 1 differ, 1 on one side"]


def test_actions_placed_in_the_comparison_panel_render_in_its_toolbar() -> None:
    html = _section(_read(_SRC / "index.html"))
    assert html.index('id="pc-compare-hint"') < html.index('id="pc-compare-actions"') < html.index('id="pc-compare-result"') < html.index('id="pc-compare-body"')
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    render = _function(forms, "pcRenderActions")
    assert 'action.place === "compare"' in render and "pcBuildToolbarAction(action, shared)" in render
    assert "panel.hidden = listed.length === 0;" in render and "toolbar.hidden = placed.length === 0;" in render
    build = _function(forms, "pcBuildToolbarAction")
    assert "pcSend({ action: action.id, values: pcCollectValues(form) }, action.label, shared);" in build
    assert 'shared.setAttribute("data-pc-prefix", action.label + ": ");' in build
    assert 'holder.className = "pc-toolbar-field";' in build
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert '"#pc-actions button[type=submit], #pc-compare-actions button[type=submit]"' in poll


def test_a_choice_the_console_fills_follows_its_status() -> None:
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    select = _function(forms, "pcBuildSelect")
    assert 'select.setAttribute("data-pc-options-from", field.options_from);' in select
    assert 'pick.textContent = field.placeholder || "(pick one)";' in select
    runform = _read(_SRC / "js" / "plugin-console-runform.js")
    apply = _function(runform, "pcApplyChoices")
    assert 'document.querySelectorAll("select[data-pc-options-from]")' in apply
    assert "pcState.choices = current;" in apply
    # Rebuilt only when the list changed; the pick survives while it is still listed.
    assert 'select.getAttribute("data-pc-choices") === signature' in apply
    assert "String(option.value) === picked" in apply
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    assert "pcApplyChoices(status ? status.choices : null);" in poll
    assert "pcApplyChoices(pcState.choices);" in _function(runform, "pcRenderRunForm")
    validate = _function(runform, "pcRunValidate")
    assert 'if (pcState.runActive && !runs.accepts_while_running) problems.push("a run is in progress");' in validate
    runs = _read(_SRC / "js" / "plugin-console-runs.js")
    assert "if (summary.id === pcState.runActive) {" in _function(runs, "pcStartRun")


def test_a_mono_column_wraps_in_the_mono_font() -> None:
    poll = _read(_SRC / "js" / "plugin-console-poll.js")
    rows = _function(poll, "pcAppendRows")
    assert 'var clipped = (column.format !== "text" && column.format !== "mono") || column.width === "narrow";' in rows
    css = _read(_SRC / "css" / "views" / "plugin-console.css")
    assert ".pc-cell--mono {\n  font-family: var(--font-mono);\n  font-size: 12px;\n  white-space: pre-wrap;\n}" in css


def test_a_console_s_reader_fields_follow_the_top_bar_pill() -> None:
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    follow = _function(forms, "pcFollowReaderPill")
    assert 'document.querySelectorAll(\'#pc-layout select[data-pc-type="reader"]\')' in follow
    # A reader the operator picked by hand is kept.
    assert 'if (current !== "" && current !== String(previous || "")) return;' in follow
    centre = _read(_SRC / "js" / "command-center.js")
    assert "pcFollowReaderPill(prevReader, readerName);" in centre


def test_an_action_answers_under_its_own_card() -> None:
    forms = _read(_SRC / "js" / "plugin-console-forms.js")
    build = _function(forms, "pcBuildAction")
    assert 'result.className = "pc-action-result";' in build
    assert "pcSend({ action: action.id, values: pcCollectValues(form) }, action.label, result);" in build
    send = _function(forms, "pcSend")
    assert 'pcShowActionResult(inline, result.output || "", false);' in send
    assert "pcShowActionResult(inline, pcErrorText(err), true);" in send
