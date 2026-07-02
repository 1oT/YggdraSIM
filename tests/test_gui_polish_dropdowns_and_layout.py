# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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

    The nested ``CC_NAV_TREE`` owns Registry browser, Env flags and Raw
    shell under its Environment / Advanced buckets. Backend switching
    and PC/SC reader selection live in the top-bar runtime controls.
    Keeping the old groups produced duplicated entries and made the
    sidebar visibly messy.
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
    assert 'data-view="card_bridge" class="subsystem-entry"' not in html


def test_remote_bridge_lives_under_advanced_before_environment() -> None:
    """Remote Bridge belongs in Advanced, and Advanced renders before Environment."""
    js = _read("app.js")
    advanced_pos = js.index('id: "group-advanced"')
    environment_pos = js.index('id: "group-env"')
    advanced_block = js[advanced_pos:environment_pos]

    assert advanced_pos < environment_pos
    assert 'id: "leaf-adv-card-bridge"' in advanced_block
    assert 'label: "Remote Bridge"' in advanced_block
    assert 'inspectView: "card_bridge"' in advanced_block
    assert 'card_bridge: "Advanced · Remote Bridge"' in js


def test_duplicated_flat_nav_entries_are_gone() -> None:
    """Registry browser / Env flags / Raw shell must no longer appear as
    flat sidebar ``<li data-view=…>`` entries; they live inside the
    nested tree now.
    """
    html = _read("index.html")
    for view_id in (
        "registry",
        "env_flags",
        "terminal",
    ):
        marker = '<li data-view="' + view_id + '"'
        assert marker not in html, "legacy flat sidebar entry still present: " + marker


def test_backend_and_reader_probe_are_topbar_controls_not_modules() -> None:
    """Backend switching and PC/SC enumeration are top-bar controls."""
    html = _read("index.html")
    js = _read("app.js")
    assert 'id="topbar-backend-reader"' in html
    assert 'id="topbar-backend-sim"' in html
    assert 'id="topbar-readers"' in html
    assert 'data-view="backend"' not in html
    assert 'data-view="live_readers"' not in html
    assert "leaf-env-backend" not in js
    assert "leaf-env-readers" not in js


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
    """``readerBarActivate`` must not route SCP03 through a second special
    workbench selector when the operator clicks a reader pill.

    SCP03 is now part of the same reader-scoped subsystem table as OTA and
    eSIM. The only SCP03-specific logic left here is the optional auto-open
    scan when a card is present and no SCP03 session exists yet.
    """
    js = _read("app.js")
    block = js.split("function readerBarActivate(readerName)", 1)[1]
    block = block.split("function readerBarSyncToScp03Tab", 1)[0]
    # The only explicit SCP03 route is from the Overview view.
    assert "commandState.activeSubsystem === null" in block
    assert 'openCommandSubsystem("SCP03")' in block
    assert 'commandState.activeSubsystem === "SCP03"' in block
    assert "readerBarProbeHasCard(readerName)" in block
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


def test_compact_workbench_defined_with_action_grid_dashboard() -> None:
    """The helper must emit the dense action-rail + dashboard layout."""
    js = _read("app.js")
    assert "function renderCompactWorkbench(container, subsystem, actions, leaf)" in js
    block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    block = block.split("\n  }\n", 1)[0]
    assert 'className = "cc-workbench cc-workbench--compact"' in block
    assert 'className = "cc-compact-action-grid"' in block
    assert 'className = "cc-dashboard"' in block
    assert 'className = "cc-dash-actions"' in block
    assert 'className = "cc-compact-rbtn"' in block


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
        ".main--module-workbench",
        ".main--module-workbench .cc-workbench",
        ".cc-workbench--compact",
        ".cc-compact-header",
        ".cc-compact-title",
        ".cc-compact-action-grid",
        ".cc-dashboard",
        ".cc-dash-actions",
        ".cc-compact-rbtn",
    ):
        assert selector in css, "compact workbench CSS missing: " + selector


def test_action_surfaces_use_shared_svg_icon_renderer() -> None:
    """Action toolbars use one themed inline-SVG icon path, not text glyphs."""
    js = _read("app.js")
    css = _read("app.css")

    assert "var CC_ICON_MARKUP" in js
    assert "function ccSetActionIcon(host, iconName)" in js
    assert 'svg.classList.add("cc-action-svg")' in js
    assert 'ccSetActionIcon(icon, _ccResolveIcon(action.id))' in js
    assert 'ccSetActionIcon(icon, spec.icon || "action")' in js
    assert 'ccSetActionIcon(icon, iconName || "action")' in js

    resolver = js.split("function _ccResolveIcon(actionId)", 1)[1]
    resolver = resolver.split("function ccActionNeedsManualInput", 1)[0]
    for icon_name in (
        "hotfolder",
        "notification",
        "write",
        "import",
        "export",
        "enable",
        "delete",
        "run",
        "refresh",
        "auth",
        "scan",
        "check",
        "read",
        "package",
        "shell",
        "trace",
        "counter",
        "action",
    ):
        assert f'return "{icon_name}";' in resolver
    for old_token in ('"RD"', '"WR"', '"KY"', '"RF"', '"OK"', '"AC"', '"●"'):
        assert old_token not in resolver

    for selector in (
        ".cc-action-svg",
        ".cc-hil-action-icon .cc-action-svg",
        ".cc-compact-rbtn-icon .cc-action-svg",
        ".cc-local-eim-tool-icon .cc-action-svg",
        ".ctx-menu-icon .cc-action-svg",
        ".saip-ribbon-btn-icon .cc-action-svg",
    ):
        assert selector in css, "shared action icon CSS missing: " + selector


def test_action_icon_call_sites_do_not_use_mixed_glyph_text() -> None:
    """SAIP, HIL, local eSIM, and context menus must not regress to glyph soup."""
    js = _read("app.js")

    compact = js.split("function appendActionButton(parent, action)", 1)[1]
    compact = compact.split('if (subsystem === "Offline Tools")', 1)[0]
    hil_button = js.split("function hilToolbarButton(iconName", 1)[1]
    hil_button = hil_button.split("\n  }\n", 1)[0]
    local_smdp = js.split("function _buildLocalSmdpOverviewPanel()", 1)[1]
    local_smdp = local_smdp.split("function _buildLocalEimOverviewPanel()", 1)[0]
    local_eim = js.split("function _buildLocalEimOverviewPanel()", 1)[1]
    local_eim = local_eim.split("// --- Main content area ---", 1)[0]
    saip_ribbon = js.split("function renderSaipRibbon(ribbon, drawer, peList, detail, validation)", 1)[1]
    saip_ribbon = saip_ribbon.split("var SAIP_TOP_TABS", 1)[0]
    pe_context = js.split("function saipBuildPeContextMenuItem(spec)", 1)[1]
    pe_context = pe_context.split("function saipPeIsSequenceAnchor", 1)[0]
    reader_context = js.split("function buildContextMenuItem(spec)", 1)[1]
    reader_context = reader_context.split("function showContextMenu", 1)[0]

    for block in (compact, hil_button, local_smdp, local_eim, saip_ribbon, pe_context, reader_context):
        assert "icon.textContent" not in block
        assert "ccSetActionIcon(" in block

    for needle in (
        'icon: "save", label: "Save"',
        'icon: "save-as", label: "Save as',
        'icon: "check", label: "Validate"',
        'icon: "add-above", label: "Add above"',
        'icon: "move-down", label: "Move down"',
        'icon: "reference", label: "Spec card"',
        'icon: "guides", label: "Guides"',
        'addTool("refresh", "Refresh"',
        'addTool("hotfolder", "Hotfolder"',
        'hilToolbarButton("refresh", "Refresh"',
        'hilToolbarButton("clear", "Clear raw"',
        'var startButton = hilToolbarButton("run", "Start"',
        'icon: "copy",',
    ):
        assert needle in js

    for old_marker in (
        'icon: "OP"',
        'icon: "SV"',
        'icon: "OK"',
        'icon: "+U"',
        'icon: "+D"',
        'icon: "FD"',
        'icon: "?"',
        'addTool("↻"',
        'addTool("▶"',
        'hilToolbarButton("▶"',
        'hilToolbarButton("■"',
        'hilToolbarButton("↻"',
        'hilToolbarButton("⏸"',
        'hilToolbarButton("▤"',
        'hilToolbarButton("☰"',
        'hilToolbarButton("⎘"',
        'hilToolbarButton("⌂"',
        'hilToolbarButton("×"',
    ):
        assert old_marker not in js


def test_scp80_ota_module_uses_dedicated_split_overview() -> None:
    """OTA should not render as a bare generic action strip."""
    js = _read("app.js")
    css = _read("app.css")
    render_block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    render_block = render_block.split("function stopHilWorkbenchRuntime", 1)[0]
    ota_block = js.split("function _buildOtaOverviewPanel()", 1)[1]
    ota_block = ota_block.split("// Mutation suffixes", 1)[0]
    ota_refresh = ota_block.split("async function refreshConfig()", 1)[1]
    ota_refresh = ota_refresh.split("async function saveConfig()", 1)[0]

    assert 'var isOtaModuleSurface = subsystem === "SCP80";' in render_block
    assert "var useEsimSplitPane = isDashboardSubsystem || isOtaModuleSurface" in render_block
    assert "mutationActions = [];" in render_block
    assert "_appendCompactContent(_buildOtaOverviewPanel())" in render_block
    assert "if (!isOtaModuleSurface) {\n      _appendCompactContent(dashBody);\n    }" in render_block
    assert 'esimFlowTitle.textContent = "OTA output"' in render_block
    assert 'subsystem === "SCP80"' in js

    for needle in (
        'panel.className = "cc-ota-overview"',
        'setAttribute("data-ota-overview", "1")',
        'otaAction("scp80.show_config")',
        'otaAction("scp80.set_config")',
        'body: JSON.stringify({ inputs: { reader: scopedReader } })',
        "async function runOtaAction",
        'runOtaAction("scp80.send"',
        'runOtaAction("scp80.build_plan"',
        'runOtaAction("scp80.ota_smart"',
        'runOtaAction("scp80.send_raw"',
        'runOtaAction("scp80.run_script"',
        'runOtaAction("scp80.protocol_summary"',
        'runOtaAction("scp80.reset_connection"',
        'payloadLabel.textContent = "Payload override (APDU hex)"',
        'scriptLabel.textContent = "Script file"',
        'verboseLabel.textContent = "Verbose APDU trace"',
    ):
        assert needle in ota_block
    assert "openOtaAction" not in ota_block
    assert "renderMetaError" in ota_refresh
    assert "_renderEsimFlowError" not in ota_refresh
    assert '{ key: "reader_idx", label: "Reader index"' not in ota_block

    for selector in (
        ".cc-ota-overview",
        ".cc-ota-config-grid",
        ".cc-ota-config-card",
        ".cc-ota-options-grid",
        ".cc-ota-profile-row",
        ".cc-ota-config-select",
        ".cc-ota-run-tools",
        ".cc-ota-runtime-card",
        ".cc-ota-runtime-error",
        ".cc-ota-result",
        ".cc-ota-result-grid",
        ".cc-ota-result-details",
    ):
        assert selector in css, "OTA overview CSS missing: " + selector


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


def test_reader_scoped_actions_hide_reader_fields_and_inject_active_reader() -> None:
    """Reader-scoped actions use the active top-bar pill, not local pickers."""
    js = _read("app.js")
    build_field = js.split("function buildField(action, field)", 1)[1]
    build_field = build_field.split("async function prefillReaderSelect", 1)[0]
    apply_default = js.split("function applyActiveReaderDefault(action, inputs)", 1)[1]
    apply_default = apply_default.split("async function runActionFromForm", 1)[0]
    run_form = js.split("async function runActionFromForm(action, form", 1)[1]
    run_form = run_form.split("function renderErrorBlock", 1)[0]

    assert "function ccShouldHideReaderField(action, field)" in js
    assert "function ccIsReaderIndexOverrideField(field)" in js
    assert "function ccReaderSessionFieldMode(field)" in js
    assert '"SCP80": true' in js
    assert '"HIL": true' in js
    assert '"Card Bridge": true' in js
    assert 'field.kind === "reader"' in js
    assert 'name === "reader_name"' in js
    assert 'name === "reader_index"' in js
    assert "ccShouldHideReaderField(action, field)" in build_field
    assert 'input.type = "hidden"' in build_field
    assert "row.hidden = true" in build_field
    assert 'data-reader-session-field' in build_field
    assert 'sessionFieldMode === "reader" ? ccActiveReaderName() : ""' in build_field
    hidden_branch = build_field.split("if (ccShouldHideReaderField(action, field))", 1)[1]
    hidden_branch = hidden_branch.split('if (field.kind === "bool")', 1)[0]
    assert "cc-reader-session-chip" not in hidden_branch
    assert "ccReaderSessionFieldMode(field)" in apply_default
    assert 'inputs[fieldName] = "";' in apply_default
    assert "forceSessionReader = ccActionUsesReaderSession(action)" in apply_default
    assert "inputs[fieldName] = activeReader" in apply_default
    assert "Select a reader before running this reader-backed action." in run_form


def test_reader_scoped_action_results_render_as_tree() -> None:
    """Reader-scoped command output is shown as a nested result tree."""
    js = _read("app.js")
    render_result = js.split("function renderActionResult(action, data, container)", 1)[1]
    render_result = render_result.split("function renderMarkdownResult", 1)[0]

    assert "function ccActionResultPrefersTree(action, kind, data)" in js
    assert 'subsystem === "eSIM Management"' in js
    assert 'subsystem === "SCP11 Local"' in js
    assert 'subsystem === "Local eIM"' in js
    assert 'subsystem === "SCP80"' in js
    assert 'actionId === "scp03.get_sgp32_all_data"' in js
    assert "function renderStructuredActionTreeResult(action, data, container)" in js
    assert "renderPrettyValue(ccActionResultTreePayload(action, data), 0, {" in js
    assert "collapseObjects: true" in js
    assert "collapseFromDepth: 1" in js
    assert "ccActionResultPrefersTree(action, kind, data)" in render_result
    assert "renderStructuredActionTreeResult(action, data, container)" in render_result
    assert 'action && action.id === "scp11_live.get_all_data"' in render_result
    assert "renderEsimConsolidatedResult(action, data, container)" in render_result


def test_consolidated_report_payload_is_rendered_as_esim_overview() -> None:
    """Consolidated eSIM results render only named card sections."""
    js = _read("app.js")
    css = _read("app.css")
    assert "function ccReportSectionsFromText(text)" in js
    assert "function ccReportLineEntry(line)" in js
    assert "function renderEsimConsolidatedResult(action, data, container)" in js
    assert "function ccEsimDashboardSection(title, options)" in js
    assert "function ccEsimAppendOverviewSections(dashboard, snapshot, options)" in js
    assert "function ccEsimAppendDiscoveryReportSections(dashboard, reportSections, options)" in js
    assert "function ccEsimReportEntryIsNoise(entry)" in js
    assert 'if (typeof value === "boolean") return value ? "true" : "false";' in js
    assert 'ipa_mode: "IPA mode"' in js
    assert 'iot_specific_info: "IoT specific info"' in js
    assert 'ecall_supported: "eCall supported"' in js
    assert 'fallback_supported: "Fallback supported"' in js
    assert 'lower.indexOf("failed") >= 0 || lower.indexOf("retrying") >= 0' in js
    renderer = js.split("function renderEsimConsolidatedResult(action, data, container)", 1)[1]
    renderer = renderer.split("function renderStructuredActionTreeResult", 1)[0]
    assert '"Card Overview"' in js
    assert '"eUICC Configuration Data"' in js
    assert "var foldOptions = { collapsible: true, open: false, openDiscoveryCards: false };" in renderer
    assert "var hasOverview = ccEsimAppendOverviewSections(dashboard, snapshot, foldOptions)" in renderer
    assert "ccEsimAppendDiscoveryReportSections(dashboard, reportSections, foldOptions)" in renderer
    assert 'document.createElement(collapsible ? "details" : "div")' in js
    assert "sec.open = opts.open === true" in js
    assert 'document.createElement(opts.collapsible ? "details" : "section")' in js
    assert "card.open = opts.openDiscoveryCards === true" in js
    assert "if (!hasOverview && !hasDiscovery) {" in renderer
    assert 'container.closest(".cc-esim-flow-body")' in renderer
    assert "if (body) body.innerHTML = \"\";" in renderer
    assert "scp03DatasheetAppendMetaKvl" not in renderer
    assert 'label: "Reader"' not in renderer
    assert 'label: "Profiles"' not in renderer
    assert "No card overview returned" not in renderer
    assert "ccEsimAppendRunLog" not in renderer
    assert "ccEsimAppendRawReport" not in renderer
    assert "scp03RenderTrace" not in renderer
    for selector in (
        ".cc-esim-discovery-list",
        ".cc-esim-discovery-card",
        ".cc-esim-discovery-title",
        ".cc-esim-discovery-row",
        ".cc-dash-section--collapsible",
        ".cc-esim-discovery-card--collapsible",
    ):
        assert selector in css, "discovery detail CSS missing: " + selector
    payload = js.split("function ccActionResultTreePayload(action, data)", 1)[1]
    payload = payload.split("function renderStructuredActionTreeResult", 1)[0]
    assert "ccReportSectionsFromText(data.report)" in payload
    assert "payload.report_sections = reportSections" in payload
    assert "report: true" in payload
    special = js.split('if (action && action.id === "scp11_live.get_all_data")', 1)[1]
    special = special.split("if (ccActionResultPrefersTree(action, kind, data))", 1)[0]
    assert "renderEsimConsolidatedResult(action, data, container)" in special


def test_esim_split_autorun_actions_skip_generated_form_chrome() -> None:
    """Reader-only split-pane actions should not render a Re-run form shell."""
    js = _read("app.js")
    pane = js.split("function _openEsimActionPane(action)", 1)[1]
    pane = pane.split("function _ensureInlineActionPane", 1)[0]
    autorun = pane.split("if (ccActionShouldAutoRunInEsimFlowPane(action))", 1)[1]
    autorun = autorun.split("var body = _resetEsimFlowPane(action, \"idle\")", 1)[0]

    assert "_runActionInEsimFlowPane(action, {}, {" in autorun
    assert "showDescription: false" in autorun
    assert "runActionFromForm" not in autorun
    assert 'runBtn.textContent = action.streams ? "Restart" : "Re-run"' in pane


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


def test_reader_scoped_dashboard_refresh_is_manual_and_uses_active_reader() -> None:
    """eSIM dashboards stay passive on open; manual refresh uses the active reader."""
    js = _read("app.js")
    css = _read("app.css")
    block = js.split("function renderCompactWorkbench(container, subsystem, actions, leaf)", 1)[1]
    block = block.split("function stopHilWorkbenchRuntime", 1)[0]
    manual_tail = block.split("// --- Manual dashboard refresh ---", 1)[1]
    manual_tail = manual_tail.split("container.appendChild(wb);", 1)[0]

    assert "var scopedReader = ccSubsystemRequiresReaderSession(subsystem)" in block
    assert "function renderDashboardPlaceholder(message, options)" in block
    assert "Load card overview" in block
    assert "refreshEsimSurface({ manual: true })" in block
    assert "card overview not loaded" in manual_tail
    assert "refreshDashboard();" not in manual_tail
    assert "scanInputs.reader = scopedReader" in block
    assert "commandState.activeSubsystem !== subsystem" in block
    assert ".cc-dash-placeholder" in css
    assert ".cc-dash-load-btn" in css
    assert ".cc-esim-flow-body .cc-action-tree" in css
    assert ".cc-esim-flow-body .cc-action-datasheet-main > .cc-log-inline" in css
    assert "max-height: none" in css


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


def test_hil_context_grouping_comes_from_backend_tree() -> None:
    """The web HIL view must not keep a second APDU grouping classifier."""
    js = _read("app.js")

    assert "function renderHilContextTree" in js
    assert "function hilFilterContextTreeForRows" in js
    assert "function hilContextSectionKey" in js
    assert "function hilToggleContextHeader" in js
    assert 'header.setAttribute("aria-expanded"' in js
    assert "collapsedDepths" in js
    assert "preserveExactScroll: true" in js
    assert "return state.packetSectionOpen[hilContextSectionKey(item)] === true" in js
    assert "state.packetSectionOpen[key] = true" in js
    assert "data.context_tree" in js
    assert "context_after_frame: contextAfterFrame" in js
    assert "function hilClassifyPacket" not in js
    assert "function hilPacketClassifyText" not in js
    assert "function hilPacketSearchText" not in js


def test_hil_packet_refresh_defers_visible_repaint_during_user_activity() -> None:
    """Automatic packet imports update state without rebuilding the active list."""
    js = _read("app.js")
    css = _read("app.css")
    pointer_block = js.split("function hilBeginPacketPointerInteraction", 1)[1]
    pointer_block = pointer_block.split("function hilEndPacketPointerInteraction", 1)[0]
    row_css = css.split(".cc-hil-packet-row {", 1)[1].split("}", 1)[0]
    context_css = css.split(".cc-hil-context-title {", 1)[1].split("}", 1)[0]

    assert "packetRenderPending" in js
    assert "packetRenderTimerId" in js
    assert "packetPointerActive" in js
    assert "packetHoverActive" in js
    assert "packetPointerReleaseTimerId" in js
    assert "function hilShouldDeferPacketRender" in js
    assert "function hilScheduleDeferredPacketRender" in js
    assert "function hilBeginPacketPointerInteraction" in js
    assert "function hilEndPacketPointerInteraction" in js
    assert "function hilPacketHoverIsActive" in js
    assert "function hilUpdatePacketHoverInteraction" in js
    assert "function hilEndPacketHoverInteraction" in js
    assert "function hilFlushDeferredPacketRender" in js
    assert "setPointerCapture" not in pointer_block
    assert 'hilShouldDeferPacketRender(opts)' in js
    assert 'list.addEventListener("wheel"' in js
    assert 'list.addEventListener("pointerdown"' in js
    assert 'list.addEventListener("pointerover"' in js
    assert 'list.addEventListener("pointermove"' in js
    assert 'list.addEventListener("pointerleave"' in js
    assert 'list.addEventListener("pointerup"' in js
    assert 'list.addEventListener("lostpointercapture"' in js
    assert 'window.addEventListener("pointerup"' in js
    assert ".cc-hil-packet-list:hover" not in js
    assert "Date.now() - Number(state.lastPacketScrollAt || 0) < 450" in js
    assert "return hilPacketPointerIsActive() || hilPacketHoverIsActive() || hilPacketListIsUserActive()" in js
    assert "if (hilPacketPointerIsActive()) {\n        hilSchedulePacketVirtualRender(list);\n        return;\n      }" in js
    assert "if (markUserScroll) {\n      state.lastPacketScrollAt = Date.now();\n      state.followTail = bottomGap <= 24;\n    }" in js
    assert "hilCancelDeferredPacketRender()" in js
    assert "box-sizing: border-box;" in row_css
    assert "height: 26px;" in row_css
    assert "min-height: 26px;" in row_css
    assert "box-sizing: border-box;" in context_css
    assert "height: 26px;" in context_css
    assert "min-height: 26px;" in context_css


def test_hil_packet_selection_does_not_rebuild_workbench() -> None:
    """Selecting a packet should not race a full Command Center rebuild."""
    js = _read("app.js")
    select_block = js.split("function hilSelectFrame(frameNumber)", 1)[1]
    select_block = select_block.split("async function hilRefreshSnapshot", 1)[0]
    row_block = js.split("function hilPacketRow(row, annotation, options)", 1)[1]
    row_block = row_block.split("function renderHilRawTab", 1)[0]
    apply_block = js.split("function hilApplySnapshot(data)", 1)[1]
    apply_block = apply_block.split("var detailIncluded", 1)[0]
    explicit_selected_branch = "} else if (selectedFromDataVisible && previousSelected === selectedFromData) {"
    pinned_selected_branch = "} else if (!state.selectionFollowsTail && previousSelected && frameNumbers[previousSelected]) {"

    assert 'renderCommandSubsystem("HIL"' not in select_block
    assert "state.selectionFollowsTail = false" in select_block
    assert "hilCancelDeferredPacketRender()" in select_block
    assert "hilRenderActivePaneOnly()" in select_block
    assert "hilRefreshSnapshot({ force: true, selectedFrame: frameNumber })" in select_block
    assert "hilStorePacketScroll(list, false)" in row_block
    assert "selectionFollowsTail: true" in js
    assert explicit_selected_branch in apply_block
    assert pinned_selected_branch in apply_block
    assert "state.selectionFollowsTail = nextSelectionFollowsTail" in js
    assert "} else if (state.followTail) {" not in apply_block
    assert apply_block.index(explicit_selected_branch) < apply_block.index("} else if (state.selectionFollowsTail || !previousSelected) {")
    assert apply_block.index(pinned_selected_branch) < apply_block.index("} else if (state.selectionFollowsTail || !previousSelected) {")


def test_hil_live_gui_memory_caps_are_bounded() -> None:
    """The live HIL GUI caps DOM rendering without dropping loaded packets."""
    js = _read("app.js")

    assert "var HIL_PACKET_FETCH_LIMIT = 5000" in js
    assert "var HIL_PACKET_RENDER_LIMIT = 750" in js
    assert "var HIL_RAW_TRACE_LIMIT = 750" in js
    assert "limit: hilPacketFetchLimit()" in js
    assert "function hilRenderPacketItems" in js
    assert "function hilPacketSpacer" in js
    assert "return HIL_PACKET_RENDER_LIMIT" in js
    assert "return HIL_RAW_TRACE_LIMIT" in js
    assert "merged.slice(merged.length - limit)" not in js


def test_hil_context_trace_chain_ui_is_retired() -> None:
    """The HIL packet list must not render the retired trace strip."""
    js = _read("app.js")
    css = _read("app.css")

    for needle in (
        "function hilTraceBar",
        "function hilTraceForFrame",
        "function hilNormalizeFrameList",
        "is-trace-related",
        "is-trace-parent",
        "cc-hil-trace-chip",
    ):
        assert needle not in js

    for selector in (
        ".cc-hil-trace-bar",
        ".cc-hil-trace-chip",
        ".cc-hil-packet-row.is-trace-related",
        ".cc-hil-packet-row.is-trace-parent",
    ):
        assert selector not in css


def test_local_smdp_path_inputs_are_themed() -> None:
    """Local SM-DP+ path fields must not fall back to white browser inputs."""
    css = _read("app.css")
    block = css.split(".cc-local-eim-path-input {", 1)[1].split("}", 1)[0]
    placeholder = css.split(".cc-local-eim-path-input::placeholder {", 1)[1].split("}", 1)[0]
    hover = css.split(".cc-local-eim-path-input:hover {", 1)[1].split("}", 1)[0]
    focus = css.split(".cc-local-eim-path-input:focus {", 1)[1].split("}", 1)[0]

    assert '.cc-local-eim-overview input[type="text"]' in css
    assert '.cc-local-smdp-overview input[type="text"]' in css
    assert '.cc-ota-overview input[type="text"]' in css
    assert ".cc-ota-config-select" in css
    assert "appearance: none;" in block
    assert "background: var(--bg-elev);" in block
    assert "background-color: var(--bg-elev);" in block
    assert "color-scheme: dark;" in block
    assert "color: var(--fg);" in block
    assert "caret-color: var(--accent);" in block
    assert "border: 1px solid var(--border-soft, var(--border));" in block
    assert "border-radius: var(--radius-sm, 6px);" in block
    assert "color: var(--fg-dim);" in placeholder
    assert "background:" in hover
    assert "border-color: var(--accent);" in focus
    assert "box-shadow: 0 0 0 2px var(--accent-soft);" in focus


def test_hil_modem_shell_tab_contract() -> None:
    """HIL exposes a modem-shell tab backed by the host-shell PTY route."""
    js = _read("app.js")
    css = _read("app.css")

    assert 'hilTabButton("modem", "Modem shell")' in js
    assert 'HIL_MODEM_DEFAULT_COMMAND = "sudo tio /dev/ttyUSB2"' in js
    assert "modemShellDefaultCommand" in js
    assert "default_command_source" in js
    assert '"remote-card-bridge"' in js
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


def test_hil_web_context_refresh_contract() -> None:
    """The web HIL context view keeps classifications and deltas current."""
    js = _read("app.js")
    css = _read("app.css")
    refresh_block = js.split("async function hilRefreshSnapshot(options)", 1)[1]
    refresh_block = refresh_block.split("function hilShouldIncludeDetail", 1)[0]
    status_block = js.split("function hilRenderStatusbar", 1)[1]
    status_block = status_block.split("function hilCapturePathFromRows", 1)[0]
    context_title_block = css.split(".cc-hil-context-title", 1)[1]
    context_title_block = context_title_block.split("}", 1)[0]

    assert "var selected = opts.selectedFrame || (state.selectionFollowsTail ? \"\" : state.selectedFrameNumber)" in refresh_block
    assert 'state.statusText = "refreshing"' not in refresh_block
    assert 'state.inflight ? "refreshing" : state.statusText' not in status_block
    assert 'hilStatusChip("status", state.statusText)' in status_block
    assert 'var includeAnnotations = state.activeTab === "dissector" || !deltaMode' in refresh_block
    assert "var contextAfterFrame = hilIsLiveCaptureMode(state)" in refresh_block
    assert "context_after_frame: contextAfterFrame" in refresh_block
    assert "contextTree: []" in js
    assert "hilContextTreeRenderKey" in js
    assert "packetScrollRestoring" in js
    assert "function hilStorePacketScroll" in js
    assert "position: sticky" not in context_title_block
    assert "cursor: pointer" in context_title_block
    assert "cc-hil-context-caret" in css
    assert ".cc-hil-toolbar-group--exit" not in css


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
    assert 'includeAnnotations = state.activeTab === "dissector" || !deltaMode' in block


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


def test_hil_remote_capture_attach_does_not_stop_remote_service() -> None:
    """Remote HIL capture attach should detach the view instead of stopping services."""
    js = _read("app.js")
    stop_block = js.split("async function hilStopLiveSession", 1)[1]
    stop_block = stop_block.split("if (!window.confirm", 1)[0]
    status_block = js.split("function hilRenderStatusbar", 1)[1]
    status_block = status_block.split("function hilRefreshTimerStatusbar", 1)[0]

    assert 'state.startMode === "remote" || state.captureSource === "remote"' in stop_block
    assert 'state.actionStatusText = "Remote HIL view detached."' in stop_block
    assert 'hilStatusChip("source", state.captureSource)' in status_block


def test_hil_refresh_is_single_flight_with_queued_force() -> None:
    """Forced refreshes should queue, not stack concurrent tshark decodes."""
    js = _read("app.js")
    block = js.split("async function hilRefreshSnapshot(options)", 1)[1]
    block = block.split("function hilShouldIncludeDetail", 1)[0]

    assert "refreshQueuedForce" in js
    assert "refreshQueuedSelectedFrame" in js
    assert "if (state.inflight) {" in block
    assert "state.refreshQueuedForce = true" in block
    assert "state.refreshQueuedSelectedFrame = opts.selectedFrame" in block
    assert "setTimeout(function ()" in block
    assert "hilRefreshSnapshot({ force: true, selectedFrame: queuedSelectedFrame || state.selectedFrameNumber })" in block


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


def test_hil_decoded_gsm_sim_section_opens_by_default() -> None:
    """Opening a packet should expand the GSM SIM 11.11 decoded section."""
    js = _read("app.js")
    decoded_block = js.split("function hilDecodedBlock", 1)[1]
    decoded_block = decoded_block.split("function hilDecodedSectionBody", 1)[0]

    assert "hilDecodedSectionDefaultOpen(section.title)" in decoded_block
    assert 'toUpperCase() === "GSM SIM 11.11"' in js
    assert "Object.prototype.hasOwnProperty.call(state.detailSectionOpen, stateKey)" in decoded_block


def test_hil_statusbar_surfaces_active_timer_countdown() -> None:
    """HIL status chips should mirror the TUI timer countdown summary."""
    js = _read("app.js")
    status_block = js.split("function hilRenderStatusbar", 1)[1]
    status_block = status_block.split("function hilRefreshTimerStatusbar", 1)[0]

    assert "hilActiveTimerStatusChips().forEach" in status_block
    assert 'hilStatusChip("timers", String(timerSummary.count))' in js
    assert 'hilStatusChip("countdown", timerSummary.text)' in js
    assert "function hilLatestTimerAnnotation" in js
    assert "function hilRefreshTimerStatusbar" in js
    assert "function hilStartTimerStatusTicker" in js
    assert "function hilRefreshTimerAnchor" in js
    assert "function hilTimerAnnotationSignature" in js
    assert "function hilFormatDurationClock" in js
    assert "state.timerStatusTimerId = setInterval" in js
    assert "state.timerSnapshotSignature !== signature" in js
    assert "state.timerSnapshotAppliedAt = Date.now()" in js


def test_hil_decoded_and_bytes_panes_share_byte_highlighting() -> None:
    """Decoded rows and byte spans should share Wireshark-style ranges."""
    js = _read("app.js")
    css = _read("app.css")

    for needle in (
        "detailRanges",
        "function hilRenderByteDumpLine",
        "function hilFindRangeForDecodedLine",
        "function hilBestRangeForByte",
        "function hilApplyByteHighlightClasses",
        "cc-hil-byte",
        "cc-hil-decoded-range",
    ):
        assert needle in js

    for selector in (
        ".cc-hil-byte.is-highlighted",
        ".cc-hil-byte.is-pinned",
        ".cc-hil-decoded-range.is-highlighted",
        ".cc-hil-decoded-range.is-pinned",
    ):
        assert selector in css


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


def test_card_bridge_remote_rig_promotes_one_click_start() -> None:
    """The Card Bridge rig UI must keep the full sequence as the primary path."""
    html = _read("index.html")
    assert 'id="cb-rig-start-all">Start full rig</button>' in html
    assert '<details class="cb-override cb-rig-manual">' in html
    primary_pos = html.index('id="cb-rig-start-all"')
    manual_pos = html.index('<details class="cb-override cb-rig-manual">')
    local_pos = html.index('id="cb-rig-start-local"')
    assert primary_pos < manual_pos < local_pos

    css = _read("app.css")
    assert ".cb-rig-primary-actions" in css
    assert ".cb-rig-manual .cb-rig-actions" in css


def test_card_bridge_start_full_rig_forwards_rpi_gui() -> None:
    """The one-click Card Bridge start should include the GUI tunnel."""
    js = _read("app.js")
    block = js.split("async function cbRigStartAll(button)", 1)[1]
    block = block.split("async function cbRigStopTunnel(button)", 1)[0]
    helper_block = js.split("function cbRigRemoteRigStartInputs(cfg)", 1)[1]
    helper_block = helper_block.split("function cbRigSetBusy", 1)[0]
    assert '"card_bridge.remote_rig_start"' in block
    assert "cbRigRemoteRigStartInputs(cfg)" in block
    assert "cbRigRequireActiveReader" in block
    assert "forward_gui: true" in helper_block
    assert "reader_name: cfg.reader_name" in helper_block


def test_card_bridge_remote_rig_surfaces_hil_path_status() -> None:
    """Remote rig status must distinguish HIL service from modem APDU path."""
    html = _read("index.html")
    for marker in (
        'id="cb-rig-bridge-status"',
        'id="cb-rig-usb-status"',
        'id="cb-rig-remsim-status"',
        'id="cb-rig-modem-link-status"',
    ):
        assert marker in html

    js = _read("app.js")
    status_block = js.split("function cbRigRenderStatus(data", 1)[1]
    status_block = status_block.split("async function cbRigRun", 1)[0]
    assert "state.remote_hil" in status_block
    assert "cb-rig-bridge-status" in status_block
    assert "cb-rig-usb-status" in status_block
    assert "cb-rig-remsim-status" in status_block
    assert "cb-rig-modem-link-status" in status_block
    assert "control waiting" in status_block
    assert "bankd waiting" in status_block

    refresh_block = js.split("async function cbRigRefreshStatus(button)", 1)[1]
    refresh_block = refresh_block.split("async function cbRigStartLocal", 1)[0]
    assert "remote_workdir: cfg.remote_workdir" in refresh_block
    assert "remote_python: cfg.remote_python" in refresh_block

    describe_block = js.split("function cbRigDescribeAction(data, fallback)", 1)[1]
    describe_block = describe_block.split("function cbRigUpdateGuiUrl", 1)[0]
    assert "steps.slice().reverse().find" in describe_block


def test_card_bridge_remote_rig_allows_remsim_binary_override() -> None:
    """RPi profiles must persist the REMSIM binary path used by the service."""
    html = _read("index.html")
    assert 'id="cb-rig-remsim-binary"' in html
    assert 'value="osmo-remsim-client-st2"' in html

    js = _read("app.js")
    assert '"cb-rig-remsim-binary"' in js
    assert 'remsim_binary: cbRigPayloadValue(payload, "cb-rig-remsim-binary")' in js

    start_block = js.split("async function cbRigStartAll(button)", 1)[1]
    start_block = start_block.split("async function cbRigStopTunnel(button)", 1)[0]
    helper_block = js.split("function cbRigRemoteRigStartInputs(cfg)", 1)[1]
    helper_block = helper_block.split("function cbRigSetBusy", 1)[0]
    assert "cbRigRemoteRigStartInputs(cfg)" in start_block
    assert "remsim_binary: cfg.remsim_binary" in helper_block

    install_block = js.split("async function cbRigInstallService(button)", 1)[1]
    install_block = install_block.split("async function cbRigServiceAction", 1)[0]
    assert "remsim_binary: cfg.remsim_binary" in install_block


def test_card_bridge_remote_rig_numeric_fields_match_text_input_design() -> None:
    """Numeric rig fields should use the same styled input surface as SSH target."""
    html = _read("index.html")
    for field_id in (
        "cb-rig-reader-index",
        "cb-rig-card-port",
        "cb-rig-gui-port",
        "cb-rig-hil-port",
    ):
        marker = f'type="text" id="{field_id}" inputmode="numeric" pattern="[0-9]*"'
        assert marker in html
        assert f'type="number" id="{field_id}"' not in html


def test_card_bridge_remote_rig_profiles_are_keyed_by_ssh_target() -> None:
    """Saved Card Bridge rig profiles should be selectable by SSH target."""
    html = _read("index.html")
    assert 'list="cb-rig-ssh-target-options"' in html
    assert '<datalist id="cb-rig-ssh-target-options"></datalist>' in html

    js = _read("app.js")
    assert "CB_RIG_PROFILES_STORAGE_KEY" in js
    assert "CB_RIG_FIELD_IDS" in js
    assert "function cbRigApplyProfileForTarget(target)" in js
    assert "cbRigRenderProfileOptions(profiles)" in js
    assert "Object.assign({}, knownProfiles[storedTarget], stored)" in js
    assert "cbRigSaveSettings({ updateProfile: applied });" in js


def test_remote_bridge_running_state_surfaces_globally() -> None:
    """A live Remote Bridge should be visible outside the Remote Bridge page."""
    html = _read("index.html")
    assert 'id="topbar-hil-bridge"' in html
    assert re.search(r'<button\s+type="button"\s+class="topbar-card-bridge"\s+id="topbar-hil-bridge"', html)
    assert '<span class="topbar-card-bridge-label">HIL bridge</span>' in html
    assert 'id="topbar-hil-bridge-value">stopped</span>' in html
    assert 'id="topbar-card-bridge"' in html
    assert re.search(r'<button\s+type="button"\s+class="topbar-card-bridge"\s+id="topbar-card-bridge"', html)
    assert 'title="Remote Bridge status"' in html
    assert '<span class="topbar-card-bridge-label">Remote bridge</span>' in html
    assert 'id="topbar-card-bridge-value">stopped</span>' in html

    css = _read("app.css")
    assert '.topbar-card-bridge[data-state="running"]' in css
    assert '.topbar-card-bridge:disabled' in css
    assert '.topbar-card-bridge[data-busy="true"]' in css
    assert '.topbar-card-bridge:focus-visible' in css
    assert '#command-center-nav .cc-nav-leaf[data-cb-state="running"] .cc-nav-card-bridge-state' in css
    assert '.overview-module-card[data-cb-state="running"] .overview-module-card-badge' in css

    js = _read("app.js")
    assert "function cbSetGlobalBridgeStatus(state, label)" in js
    assert "function cbSyncCommandCenterBridgeIndicators()" in js
    assert 'pill.title = "Remote Bridge status: " + nextLabel' in js
    assert '"leaf-adv-card-bridge"' in js
    assert '"cc-nav-card-bridge-state"' in js
    assert 'leaf.inspectView === "card_bridge"' in js
    assert 'loadCardBridgeStatus();' in js
    assert 'cbSetGlobalBridgeStatus("running", "running")' in js


def test_hil_trace_running_state_surfaces_in_command_center_list() -> None:
    """An active HIL trace should be visible in the module list."""
    css = _read("app.css")
    assert '#command-center-nav .cc-nav-leaf[data-hil-trace-state="running"] .cc-nav-hil-trace-state' in css
    assert '.overview-module-card[data-hil-trace-state="running"] .overview-module-card-badge' in css

    js = _read("app.js")
    assert "function hilSyncCommandCenterTraceIndicators()" in js
    assert "function hilTraceIndicatorStatus()" in js
    assert 'state.armed && state.startMode !== "offline"' in js
    assert 'var topbar = $("topbar-hil-bridge")' in js
    assert 'setText("topbar-hil-bridge-value", topbarLabel)' in js
    assert '"cc-nav-hil-trace-state"' in js
    assert 'leaf.subsystem === "HIL"' in js
    assert 'badge.setAttribute("data-hil-role", "overview-status")' in js
    assert 'card.setAttribute("data-cc-subsystem", leaf.subsystem)' in js
    assert 'label: "tracing"' in js


def test_card_bridge_launch_success_flashes_note_green() -> None:
    """Successful rig launch should paint the inline status note green."""
    css = _read("app.css")
    assert ".cb-rig-note-ok" in css
    assert ".cb-rig-note-ok-flash" in css
    assert "@keyframes cb-rig-note-ok-flash" in css

    js = _read("app.js")
    assert "function cbRigSetNote(message, isError, options)" in js
    assert "options && options.flashOk" in js
    start_block = js.split("async function cbRigStartAll(button)", 1)[1]
    start_block = start_block.split("async function cbRigStopTunnel", 1)[0]
    assert '"starting rig…"' in start_block
    assert "{ flashOk: true }" in start_block
    assert "cbRigRenderStatus(data, { flashOk: data.ok !== false });" in js


def test_hil_toolbar_can_launch_saved_remote_bridge_rig() -> None:
    """HIL should expose the saved Remote Bridge one-click launch path."""
    js = _read("app.js")
    assert "function cbRigStartAllFromSavedSettings()" in js
    assert "function cbRigStopAllFromSavedSettings()" in js
    assert "function cbRigInputsFromSavedSettings()" in js
    assert "function cbRigRemoteRigStartInputs(cfg)" in js
    assert "cardBridgeLaunchInFlight" in js
    assert "function hilLaunchCardBridgeRig(actions, container, leaf)" in js

    block = js.split("function renderHilWorkbench(container, actions, leaf)", 1)[1]
    block = block.split("function hilToolbarButton", 1)[0]
    assert 'state.cardBridgeLaunchInFlight ? "..." : "⇄"' in block
    assert 'state.cardBridgeLaunchInFlight ? "Starting bridge" : "Remote Bridge"' in block
    assert "hilLaunchCardBridgeRig(actions, container, leaf);" in block

    launch_block = js.split("function hilLaunchCardBridgeRig(actions, container, leaf)", 1)[1]
    launch_block = launch_block.split("function renderHilDissectorTab", 1)[0]
    assert "cbRigStartAllFromSavedSettings()" in launch_block
    assert 'state.actionStatusText = "starting Remote Bridge rig"' in launch_block
    assert "Remote Bridge rig start failed." in launch_block


def test_topbar_bridge_pills_toggle_start_stop_actions() -> None:
    """Top-bar bridge pills should act as global start/stop controls."""
    js = _read("app.js")
    assert "function wireTopbarBridgeControls()" in js
    assert "function hilToggleTopbarBridge()" in js
    assert "function cbToggleTopbarRemoteBridge()" in js
    assert 'hil.addEventListener("click"' in js
    assert 'remote.addEventListener("click"' in js
    assert 'cbRigStartAllFromSavedSettings()' in js
    assert 'cbRigStopAllFromSavedSettings()' in js
    assert 'openCommandSubsystem("HIL", { scope: "all", leafId: "leaf-adv-hil" });' in js
    assert 'hilStartLiveSession(actions, container, leaf)' in js
    assert 'hilStopLiveSession(actions, container, leaf)' in js
    assert "reader_name: activeReader" in js
    assert 'reader_index: ""' in js
    assert "options.saveSettings !== false" in js
    assert "cbRigInputsFromSavedSettings()" in js
