"""Regression tests for the GUI polish pass following the nav-tree rollout.

Operator feedback captured for this slice:

    "The session context aware split between the reader tabs up top does
     not seem to work properly. Also instead of having massive boxes in
     the eIM, Over-the-Air use the better layout as we have for
     Filesystem and Applications. We have duplicated tabs in the left
     panel, remove those not using the new nested structure. Drop down
     menus use white text on white background, that needs fixing,
     preferably with a style coherent with the rest of the GUI. Make
     file paths, like for SAIP Tool be drag-n-drop-able."

This file pins the static-bundle contracts that enforce each of those
fixes. Live browser behaviour is exercised by the Playwright smoke
lane; the goal here is to make sure a future refactor can't silently
reintroduce any of the regressions.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# 1. Sidebar dedupe — legacy flat Inspect + Advanced groups are gone.
# ----------------------------------------------------------------------


def test_legacy_sidebar_groups_removed() -> None:
    """No more "Inspect" / "Advanced" flat groups in the shell.

    The nested ``CC_NAV_TREE`` now owns Registry browser, Card backend,
    Env flags, PC/SC readers and Raw shell under its Environment /
    Advanced buckets. Keeping the old groups produced duplicated entries
    and made the sidebar visibly messy.
    """
    html = _read("index.html")
    assert ">Inspect<" not in html, "legacy Inspect group must be removed"
    assert ">Advanced<" not in html, "legacy Advanced group must be removed"


def test_meta_group_retains_overview_and_about() -> None:
    """Overview + About are the only flat entries that survive.

    Neither has a natural home inside the task-oriented tree (they're
    landing/help surfaces), so they're grouped under a small ``Meta``
    list at the bottom of the sidebar instead of disappearing.
    """
    html = _read("index.html")
    assert ">Meta<" in html
    assert 'data-view="overview"' in html
    assert 'data-view="about"' in html


def test_duplicated_flat_nav_entries_are_gone() -> None:
    """Registry browser / Card backend / Env flags / PC/SC readers / Raw
    shell must no longer appear as flat sidebar ``<li data-view=…>``
    entries; they live inside the nested tree now.

    The corresponding view panels (``<section data-view="…">``) do still
    exist in ``index.html`` — nav leaves dispatch into them via
    ``showView(inspectView)`` — so we pin the absence of the list-item
    markers specifically.
    """
    html = _read("index.html")
    for view_id in (
        "registry",
        "backend",
        "env_flags",
        "live_readers",
        "terminal",
    ):
        marker = '<li data-view="' + view_id + '"'
        assert marker not in html, "legacy flat sidebar entry still present: " + marker


# ----------------------------------------------------------------------
# 2. Reader-pill context fix — scope is preserved across pill clicks.
# ----------------------------------------------------------------------


def test_open_command_subsystem_preserves_scope_on_same_subsystem() -> None:
    """Calling ``openCommandSubsystem(subsystem)`` without options on the
    same subsystem must keep the current ``activeScope`` / ``activeLeafId``.

    Before the fix the reader-bar auto-route passed only the subsystem
    name, which hard-reset the workbench to "all" scope every time the
    operator clicked a different reader pill — the exact "session
    context aware split doesn't work properly" symptom.
    """
    js = _read("app.js")
    block = js.split("function openCommandSubsystem(subsystem, options)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert "sameSubsystem && commandState.activeScope" in block
    assert "sameSubsystem && commandState.activeLeafId" in block


def test_reader_bar_activate_skips_redundant_workbench_rebuild() -> None:
    """``readerBarActivate`` must not call ``openCommandSubsystem("SCP03")``
    when the operator is already on the SCP03 workbench.

    ``readerBarSyncToScp03Tab`` already repainted the tab strip + body
    for the new reader — a second full workbench rebuild destroys
    scope, ribbon-tab selection and popout state.
    """
    js = _read("app.js")
    block = js.split("function readerBarActivate(readerName)", 1)[1]
    block = block.split("function readerBarSyncToScp03Tab", 1)[0]
    # The only remaining auto-route is from the Overview view.
    assert "commandState.activeSubsystem === null" in block
    assert 'commandState.activeSubsystem === "SCP03"' not in block
    assert 'inScp03' not in block


def test_default_leaf_id_respects_scope() -> None:
    """``_ccDefaultLeafIdForSubsystem`` must accept a scope argument.

    The reader-bar fix preserves scope across pill clicks; when no
    explicit leaf id is available, we still need to highlight the
    matching sidebar leaf so the nav selection tracks the scope the
    workbench will actually render in.
    """
    js = _read("app.js")
    assert re.search(
        r"function _ccDefaultLeafIdForSubsystem\(subsystem, scope\)",
        js,
    )


# ----------------------------------------------------------------------
# 3. Compact workbench — SCP80 / eIM / eSIM etc. use the new layout.
# ----------------------------------------------------------------------


def test_render_command_subsystem_falls_through_to_compact_workbench() -> None:
    """Every subsystem that isn't SCP03 or SAIP must reach
    ``renderCompactWorkbench`` instead of the old card-grid loop."""
    js = _read("app.js")
    block = js.split("function renderCommandSubsystem(subsystem, options)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert "renderCompactWorkbench(container, subsystem, actions, leaf)" in block
    # The old full-width grid render path must no longer exist in this
    # function — grep for the loop signature.
    assert "actions.forEach(function (action) {\n      var card = buildActionCard" not in block


def test_compact_workbench_defined_with_sidenav_and_main() -> None:
    """The helper must emit a two-column layout: action picker + card."""
    js = _read("app.js")
    assert "function renderCompactWorkbench(container, subsystem, actions, leaf)" in js
    block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert 'className = "cc-workbench cc-workbench--compact"' in block
    assert 'className = "cc-compact-sidenav"' in block
    assert 'className = "cc-compact-main"' in block
    assert 'className = "cc-compact-entry"' in block


def test_compact_workbench_filter_threshold() -> None:
    """A search input appears only for subsystems with >= 8 actions.

    Small subsystems (SUCI, SIMCARD, HIL) stay clean; eSIM Live and
    Local eIM — which each hold dozens of entries — get a filter.
    """
    js = _read("app.js")
    block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert "actions.length >= 8" in block
    assert 'className = "cc-compact-search-input"' in block


def test_compact_workbench_css_contract() -> None:
    """CSS for the compact layout must ship alongside the JS."""
    css = _read("app.css")
    for selector in (
        ".cc-workbench--compact",
        ".cc-compact-header",
        ".cc-compact-title",
        ".cc-compact-body",
        ".cc-compact-sidenav",
        ".cc-compact-entry",
        ".cc-compact-entry.active",
        ".cc-compact-main",
    ):
        assert selector in css, "compact workbench CSS missing: " + selector


def test_esim_nav_leaves_require_reader_session() -> None:
    """eSIM module leaves are marked as reader-scoped surfaces."""
    js = _read("app.js")
    esim_nav = js.split('id: "group-esim"', 1)[1].split('id: "group-tools"', 1)[0]

    assert esim_nav.count("requiresReader: true") >= 3
    assert 'data-cc-requires-reader", "1"' in js


def test_esim_modules_gate_on_reader_session() -> None:
    """eSIM modules must render a reader-session gate before action UI."""
    js = _read("app.js")
    block = js.split("function renderCommandSubsystem(subsystem, options)", 1)[1]
    block = block.split("\n  }\n", 1)[0]

    assert "function ccSubsystemRequiresReaderSession(subsystem)" in js
    assert "function renderReaderSessionGate(container, subsystem, actions, leaf, scope)" in js
    assert 'ccSubsystemRequiresReaderSession(subsystem) && !ccActiveReaderName()' in block
    assert "renderReaderSessionGate(container, subsystem, actions, leaf, scope)" in block


def test_reader_scoped_actions_hide_reader_field_and_inject_active_reader() -> None:
    """Reader-scoped eSIM actions use the active session, not a dropdown."""
    js = _read("app.js")
    build_field = js.split("function buildField(action, field)", 1)[1]
    build_field = build_field.split("async function prefillReaderSelect", 1)[0]
    apply_default = js.split("function applyActiveReaderDefault(action, inputs)", 1)[1]
    apply_default = apply_default.split("async function runActionFromForm", 1)[0]
    run_form = js.split("async function runActionFromForm(action, form", 1)[1]
    run_form = run_form.split("function renderErrorBlock", 1)[0]

    assert "function ccShouldHideReaderField(action, field)" in js
    assert 'field.kind === "reader"' in js
    assert "ccShouldHideReaderField(action, field)" in build_field
    assert 'input.type = "hidden"' in build_field
    assert "row.hidden = true" in build_field
    hidden_branch = build_field.split("if (ccShouldHideReaderField(action, field))", 1)[1]
    hidden_branch = hidden_branch.split('if (field.kind === "bool")', 1)[0]
    assert "cc-reader-session-chip" not in hidden_branch
    assert "forceSessionReader = ccActionUsesReaderSession(action)" in apply_default
    assert "inputs[fieldName] = activeReader" in apply_default
    assert "Select a reader session before running this eSIM action." in run_form


def test_reader_scoped_action_results_render_as_tree() -> None:
    """Reader-scoped command output is shown as a nested result tree."""
    js = _read("app.js")
    render_result = js.split("function renderActionResult(action, data, container)", 1)[1]
    render_result = render_result.split("function renderMarkdownResult", 1)[0]

    assert "function ccActionResultPrefersTree(action, kind, data)" in js
    assert 'subsystem === "eSIM Management"' in js
    assert 'subsystem === "SCP11 Local"' in js
    assert 'subsystem === "Local eIM"' in js
    assert 'actionId === "scp11_live.get_all_data"' in js
    assert 'actionId === "scp03.get_sgp32_all_data"' in js
    assert "function renderStructuredActionTreeResult(action, data, container)" in js
    assert "renderPrettyValue(ccActionResultTreePayload(action, data), 0)" in js
    assert "ccActionResultPrefersTree(action, kind, data)" in render_result
    assert "renderStructuredActionTreeResult(action, data, container)" in render_result


def test_consolidated_report_payload_is_split_into_tree_sections() -> None:
    """Captured consolidated reports should not render as one flat string."""
    js = _read("app.js")
    assert "function ccReportSectionsFromText(text)" in js
    assert "function ccReportLineEntry(line)" in js
    payload = js.split("function ccActionResultTreePayload(action, data)", 1)[1]
    payload = payload.split("function renderStructuredActionTreeResult", 1)[0]
    assert "ccReportSectionsFromText(data.report)" in payload
    assert "payload.report_sections = reportSections" in payload
    assert "report: true" in payload
    tree = js.split("function renderStructuredActionTreeResult(action, data, container)", 1)[1]
    tree = tree.split("function renderActionResult(action, data, container)", 1)[0]
    assert 'scp03DatasheetAppendTraceMain(sheet, data.report, "Console report")' in tree


def test_action_popout_auto_runs_without_manual_fields() -> None:
    """Reader-session-only actions should run when the popout opens."""
    js = _read("app.js")
    assert "function ccActionNeedsManualInput(action)" in js
    assert "function ccActionShouldAutoRunOnOpen(action)" in js
    needs = js.split("function ccActionNeedsManualInput(action)", 1)[1]
    needs = needs.split("function ccActionShouldAutoRunOnOpen", 1)[0]
    assert "ccShouldHideReaderField(action, field)" in needs
    popout = js.split("function _ccBuildActionPopout(action)", 1)[1]
    popout = popout.split("function renderCompactWorkbench", 1)[0]
    assert "ccActionShouldAutoRunOnOpen(action)" in popout
    assert 'runBtn.textContent = "Re-run"' in popout
    assert "window.setTimeout(function ()" in popout
    assert "runActionFromForm(action, form, status, result)" in popout


def test_reader_scoped_dashboard_autofetch_uses_active_reader() -> None:
    """eSIM dashboards only fetch while active and pass the session reader."""
    js = _read("app.js")
    block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    block = block.split("function stopHilWorkbenchRuntime", 1)[0]

    assert "var scopedReader = ccSubsystemRequiresReaderSession(subsystem)" in block
    assert "isDashboardSubsystem && commandState.activeSubsystem === subsystem" in block
    assert "scanInputs.reader = scopedReader" in block
    assert "commandState.activeSubsystem !== subsystem" in block


def test_reader_session_gate_css_contract() -> None:
    """Reader session gate and hidden reader field are styled."""
    css = _read("app.css")
    for selector in (
        ".cc-reader-session-gate",
        ".cc-reader-session-card",
        ".cc-reader-session-list",
        ".cc-reader-session-choice",
        ".cc-form-row--reader-session",
    ):
        assert selector in css, "reader-session CSS missing: " + selector


def test_hil_aid_context_groups_with_filesystem() -> None:
    """AID-scoped file paths belong under the file-system HIL group.

    The HIL context list should not split ``FS MF/AID`` traffic into a
    separate Application AID section; those are still filesystem paths.
    """
    js = _read("app.js")
    block = js.split("function hilClassifyPacket(row, ann)", 1)[1]
    block = block.split("function hilPacketSearchText", 1)[0]
    filesystem_block = block.split('return "UICC filesystem"', 1)[0]

    assert 'return "Application AID"' not in block
    assert '"FS MF/AID"' in filesystem_block
    assert '"SELECT AID"' in filesystem_block


def test_hil_modem_shell_tab_contract() -> None:
    """HIL exposes a modem-shell tab backed by the host-shell PTY route."""
    js = _read("app.js")
    css = _read("app.css")

    assert 'hilTabButton("modem", "Modem shell")' in js
    assert 'HIL_MODEM_DEFAULT_COMMAND = "sudo tio /dev/ttyUSB2"' in js
    assert '"/api/host-shell"' in js
    assert '"/api/host-shell/capabilities?scope=hil-modem"' in js
    assert '"&scope=hil-modem"' in js
    assert '"&command="' in js
    assert 'state.activeTab === "dissector"' in js

    for selector in (
        ".cc-hil-modem-shell",
        ".cc-hil-modem-command",
        ".cc-hil-modem-terminal-frame",
        ".cc-hil-modem-terminal",
    ):
        assert selector in css, "HIL modem shell CSS missing: " + selector


def test_hil_modem_shell_survives_hil_tab_switches() -> None:
    """Switching HIL tabs must not close the modem-shell PTY session."""
    js = _read("app.js")
    render_block = js.split("function renderHilWorkbench(container, actions, leaf)", 1)[1]
    render_block = render_block.split("function hilRenderActivePaneOnly", 1)[0]
    modem_block = js.split("function renderHilModemShellTab(body)", 1)[1]
    modem_block = modem_block.split("async function hilLoadModemShellMetadata", 1)[0]

    assert 'state.activeTab === "modem" && tabId !== "modem"' not in render_block
    assert "hilStopModemShell({ dispose: true })" not in render_block
    assert "function hilAttachModemShellTerminal(host)" in js
    assert "hilAttachModemShellTerminal(terminalHost)" in modem_block


def test_hil_auto_refresh_uses_incremental_decode() -> None:
    """Timer-driven HIL refreshes should not re-read the pcap from frame 1."""
    js = _read("app.js")
    block = js.split("async function hilRefreshSnapshot(options)", 1)[1]
    block = block.split("function hilShouldIncludeDetail", 1)[0]

    assert 'state.activeTab === "raw"' in block
    assert 'state.activeTab === "dissector"' in block
    assert "afterFrame = deltaMode" in block
    assert "hilMaxFrameNumber(state.rows || [])" in block
    assert "state.liveBaselineFrameNumber" in block
    assert "includeAnnotations = !deltaMode" in block


def test_hil_auto_refresh_timer_is_dissector_scoped() -> None:
    """Raw trace and modem shell tabs should not keep tshark polling live."""
    js = _read("app.js")
    block = js.split("function renderHilWorkbench(container, actions, leaf)", 1)[1]
    block = block.split("function hilTabButton", 1)[0]

    assert 'state.activeTab === "dissector"' in block
    assert 'state.activeTab !== "modem"' not in block
    assert "hilScheduleRawRowsRender()" in js
    assert "rawRenderTimerId" in js


def test_hil_live_baseline_is_lightweight_and_skips_history_refresh() -> None:
    """Live attach must not decode historical detail/annotations on startup."""
    js = _read("app.js")
    baseline = js.split("async function hilEstablishLiveBaseline()", 1)[1]
    baseline = baseline.split("function hilApplyReaderBinding", 1)[0]
    start = js.split("async function hilStartLiveSession", 1)[1]
    start = start.split("async function hilStopLiveSession", 1)[0]

    assert "include_detail: false" in baseline
    assert "include_annotations: false" in baseline
    assert "hilRefreshSnapshot({ force: false })" in start


def test_hil_refresh_is_single_flight_with_queued_force() -> None:
    """Forced refreshes should queue, not stack concurrent tshark decodes."""
    js = _read("app.js")
    block = js.split("async function hilRefreshSnapshot(options)", 1)[1]
    block = block.split("function hilShouldIncludeDetail", 1)[0]

    assert "refreshQueuedForce" in js
    assert "if (state.inflight) {" in block
    assert "state.refreshQueuedForce = true" in block
    assert "setTimeout(function ()" in block
    assert "hilRefreshSnapshot({ force: true })" in block


def test_hil_collapsible_focus_ring_uses_theme_tokens() -> None:
    """Native summary focus outlines must not leak into the HIL panes."""
    css = _read("app.css")

    assert ".cc-hil-context-title:focus" in css
    assert ".cc-hil-decoded-summary:focus" in css
    assert ".cc-hil-context-title:focus-visible" in css
    assert ".cc-hil-decoded-summary:focus-visible" in css
    block = css.split(".cc-hil-context-title:focus-visible", 1)[1]
    block = block.split("}", 1)[0]
    assert "var(--accent)" in block
    assert "box-shadow: inset" in block


def test_idle_api_badge_does_not_animate_forever() -> None:
    """The always-visible API status badge must not keep WebEngine repainting."""
    css = _read("app.css")
    block = css.split('.badge-api[data-state="ok"] .dot', 1)[1]
    block = block.split("}", 1)[0]

    assert "animation:" not in block
    assert "infinite" not in block
    assert "box-shadow" in block


# ----------------------------------------------------------------------
# 4. <select> theming — options no longer render "white text on white".
# ----------------------------------------------------------------------


def test_select_has_explicit_theme_aware_background() -> None:
    """Top-level ``select`` rule forces a theme-aware background + fg.

    Without this the native popup inherits OS chrome on some platforms
    (most visibly: white text on white background on Qt WebEngine +
    dark themes).
    """
    css = _read("app.css")
    # Pin the base ``select`` block with the token background / fg.
    assert re.search(
        r"^select\s*\{[\s\S]{0,600}?background-color:\s*var\(--bg-elev",
        css,
        re.MULTILINE,
    )
    assert re.search(
        r"^select\s*\{[\s\S]{0,600}?color:\s*var\(--fg",
        css,
        re.MULTILINE,
    )


def test_select_option_and_optgroup_forced_theme_colours() -> None:
    """Options + optgroups use the same theme tokens — not OS defaults."""
    css = _read("app.css")
    assert re.search(
        r"select option,\s*\n\s*select optgroup\s*\{",
        css,
    )
    assert "background-color: var(--bg-elev" in css
    assert "color: var(--fg" in css


def test_select_has_custom_chevron_no_native_appearance() -> None:
    """The custom chevron replaces the native indicator, which was
    invisible against dark backgrounds.
    """
    css = _read("app.css")
    # ``appearance: none`` zeroes out the native widget.
    assert re.search(r"^select\s*\{[\s\S]{0,600}?appearance:\s*none", css, re.MULTILINE)
    # The chevron is a two-slice CSS gradient at the right edge.
    assert "background-position" in css
    assert "currentColor" in css


def test_theme_picker_options_no_longer_hard_coded_light() -> None:
    """Theme picker options used to be ``#0d1926`` on ``#ffffff`` — that
    looked broken on every dark theme. They must now follow the
    active theme tokens so the popup tracks the page palette.
    """
    css = _read("app.css")
    block_match = re.search(r"\.theme-picker select option\s*\{([\s\S]*?)\}", css)
    assert block_match is not None, "theme-picker option block missing"
    block = block_match.group(1)
    assert "#0d1926" not in block
    assert "#ffffff" not in block
    assert "var(--bg-elev)" in block
    assert "var(--fg)" in block


def test_scp03_apdu_preset_select_uses_theme_token() -> None:
    """``.scp03-apdu-preset-select`` previously read ``var(--surface)``
    which is undefined on most themes and fell back to the transparent
    default — showing OS-native white. It now uses ``--bg-elev``.
    """
    css = _read("app.css")
    block_match = re.search(
        r"\.scp03-apdu-preset-select\s*\{([\s\S]*?)\}",
        css,
    )
    assert block_match is not None
    block = block_match.group(1)
    assert "var(--bg-elev)" in block
    assert "var(--surface)" not in block


# ----------------------------------------------------------------------
# 5. Drag-and-drop for path inputs.
# ----------------------------------------------------------------------


def test_enable_file_path_drop_defined_and_exposed() -> None:
    """Single helper wires the drop handlers + extracts a usable path."""
    js = _read("app.js")
    assert "function enableFilePathDrop(input, onPath)" in js
    assert "function extractPathFromDrop(event)" in js
    assert "window.YggdraSimEnableFilePathDrop = enableFilePathDrop;" in js


def test_drop_extraction_honours_file_path_uri_and_plain_text() -> None:
    """``extractPathFromDrop`` checks every transport the operator may
    produce from a native file manager → ``File.path`` → ``file://``
    URI list → plain text fallback."""
    js = _read("app.js")
    block = js.split("function extractPathFromDrop(event)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert "dt.files" in block
    assert 'getData("text/uri-list")' in block
    assert 'file://' in block
    assert 'getData("text/plain")' in block


def test_build_field_wires_drop_for_path_kinds() -> None:
    """ActionField inputs with ``kind=path|directory|save_path`` must
    be enrolled as drop targets via ``enableFilePathDrop``."""
    js = _read("app.js")
    block = js.split("if (isPathKind) {", 1)[1].split("} else {", 1)[0]
    assert "enableFilePathDrop(input)" in block


def test_attach_path_picker_wires_drop_for_saip_tool() -> None:
    """The SAIP Tool (and any other caller using ``attachPathPicker``)
    gets drag-and-drop for free through the shared helper."""
    js = _read("app.js")
    block = js.split("function attachPathPicker(input, mode)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert "enableFilePathDrop(input)" in block


def test_document_drop_guard_prevents_navigation_outside_targets() -> None:
    """Stray file drops outside ``.cc-path-drop-target`` must be swallowed
    so pywebview doesn't navigate the webview to ``file://…``. This
    guard is critical — without it a misaimed drop blows up the SPA.
    SAIP owns a workbench-wide drop surface, so the guard must let that
    managed target handle file drops too.
    """
    js = _read("app.js")
    assert "installDropGuard" in js
    # The guard only preventDefaults when the drop target is NOT inside
    # one of our managed drop surfaces.
    guard_block = js.split("function installDropGuard()", 1)[1]
    guard_block = guard_block.split("})();", 1)[0]
    assert ".cc-path-drop-target, .saip-workbench" in guard_block
    assert ".saip-workbench" in guard_block
    assert 'event.preventDefault()' in guard_block


def test_saip_workbench_drop_uses_shared_path_extractor() -> None:
    """Workbench-wide SAIP drops must share the normal file-path extractor.

    The exported helper matters because the global drop guard and path
    input handlers use the same pywebview / URI-list / plain-text
    semantics. SAIP then falls back to upload when no filesystem path is
    exposed by the WebEngine.
    """
    js = _read("app.js")
    block = js.split("function wireSaipWorkbenchDrop(wb)", 1)[1]
    block = block.split("function renderSaipWorkbench(container, actions)", 1)[0]
    assert "window.YggdraSimExtractPathFromDrop" in block
    assert "saipOpenPackageByDroppedFile" in block


def test_saip_drop_open_uses_cached_workbench_slots() -> None:
    """SAIP drag-drop must render against cached slots before first package.

    With no package open, ``.saip-pe-list`` / ``.saip-detail`` are not
    mounted in the document yet; they live in ``wb.__saipSlots``. The
    drop-open path must resolve those cached nodes or the package opens
    but does not paint until the operator re-enters the module.
    """
    js = _read("app.js")
    assert "function saipResolveSlots(overrides)" in js
    assert "wb.__saipSlots" in js
    drop_block = js.split("function saipDropOpenPath(path)", 1)[1]
    drop_block = drop_block.split("function saipBase64FromArrayBuffer", 1)[0]
    assert "var slots = saipResolveSlots();" in drop_block
    assert "slots.peList" in drop_block
    open_block = js.split("function saipActivateOpenedPackage(", 1)[1]
    open_block = open_block.split("async function saipOpenPackageByPath", 1)[0]
    assert "var slots = saipResolveSlots({" in open_block
    assert "renderSaipActiveSlots(peList, detail, validation);" in open_block
    assert "if (peList && detail) renderSaipActiveSlots" not in open_block


def test_saip_active_slot_renderer_resolves_cached_slots() -> None:
    """Active-slot paints should not trust stale captured elements."""
    js = _read("app.js")
    block = js.split("function renderSaipActiveSlots(peList, detail, validation)", 1)[1]
    block = block.split("function renderSaipTabBody", 1)[0]
    assert "var slots = saipResolveSlots({" in block
    assert "peList = slots.peList" in block
    assert "detail = slots.detail" in block
    assert "saipIsDomNode(peList)" in block
    assert "SAIP workbench slot lookup failed after package open." in block


def test_drop_hover_visual_state_styled() -> None:
    """Hover cue must be visible during drag — accent outline + label."""
    css = _read("app.css")
    assert ".cc-path-drop-target" in css
    assert ".cc-path-drop-target.cc-path-drop-hover" in css
    # The after-element prompts the operator with a drop hint.
    assert "drop to paste path" in css
