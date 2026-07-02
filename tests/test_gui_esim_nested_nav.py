# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static contract for the eSIM Command Center management surfaces.

The eSIM Management workbench is intentionally flatter than the older
category-ribbon layout: card overview and profiles stay in one dashboard,
profile rows expose lifecycle controls directly, and the generic operation
buttons are tabbed between SGP.22 Consumer (LPA-d) and SGP.32 IoT (IPA-d).
Local SMDP+ adds a compact profile-load / certificate-import strip above
the remaining Local SM-DP+ Provisioning and Card & Session Operations rails.
Local eIM adds a compact certificate and package-queue control strip above
the remaining actions. These three eSIM modules render as a split surface:
left-side controls and card overview, right-side APDU flow/output pane.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# JS contract
# ----------------------------------------------------------------------


def test_action_grouping_map_keyed_by_subsystem() -> None:
    js = _read("app.js")
    assert "var CC_ACTION_GROUPS_BY_SUBSYSTEM = {" in js, (
        "CC_ACTION_GROUPS_BY_SUBSYSTEM map missing; compact grouping will not render."
    )
    for subsystem in ('"eSIM Management"', '"SCP11 Local"', '"Local eIM"'):
        assert subsystem in js, f"grouping entry missing for subsystem {subsystem}"
    assert '"eSIM Test"' not in js


def test_esim_management_declares_two_sgp_flavors() -> None:
    js = _read("app.js")
    group_start = js.index("var CC_ACTION_GROUPS_BY_SUBSYSTEM = {")
    map_start = js.index('"eSIM Management"', group_start)
    map_end = js.index('"SCP11 Local"', map_start)
    map_window = js[map_start:map_end]

    for label in (
        '"SGP.22 Consumer (LPA-d)"',
        '"SGP.32 IoT (IPA-d)"',
    ):
        assert label in map_window, f"eSIM Management missing flavor label {label}"

    for retired_label in (
        '"Profile provisioning"',
        '"Profile management"',
        '"Card inspection"',
        '"SM-DP+ endpoints"',
    ):
        assert retired_label not in map_window, (
            f"old eSIM category tab still present: {retired_label}"
        )


def test_esim_action_flavor_helper_covers_consumer_and_iot_paths() -> None:
    js = _read("app.js")
    assert "var CC_ESIM_ACTION_FLAVORS = {" in js
    helper = js.split("function ccEsimActionFlavor(action)", 1)[1]
    helper = helper.split("function ccEsimActionFlavorGroups", 1)[0]

    for iot_suffix in (
        '"discover"',
        '"get_eim_config"',
        '"get_rat"',
        '"set_pol"',
        '"store_metadata"',
        '"verify_scp11"',
    ):
        assert iot_suffix in helper
    assert 'id.indexOf(".eim_") !== -1' in helper
    assert 'return "sgp22"' in helper


def test_esim_action_rails_hide_get_all_data_duplicates() -> None:
    """The eSIM dashboard should prefer the consolidated read command."""
    js = _read("app.js")
    assert "var CC_ESIM_CONSOLIDATED_READ_SUFFIXES = {" in js
    helper = js.split("function ccShouldShowEsimManagementAction(action)", 1)[1]
    helper = helper.split("function ccEsimActionFlavor", 1)[0]
    assert 'if (suffix === "get_all_data") return true;' in helper
    assert "CC_ESIM_CONSOLIDATED_READ_SUFFIXES[suffix]" in helper

    filter_block = js.split('if (subsystem === "eSIM Management") {', 1)[1]
    filter_block = filter_block.split('} else if (subsystem === "SCP11 Local")', 1)[0]
    assert "actions.filter(ccShouldShowEsimManagementAction)" in filter_block

    read_map = js.split("var CC_ESIM_CONSOLIDATED_READ_SUFFIXES = {", 1)[1]
    read_map = read_map.split("};", 1)[0]
    for suffix in (
        "scan",
        "status",
        "discover",
        "get_eid",
        "list_profiles",
        "list_notifications",
        "euicc_info1",
        "euicc_info2",
        "get_rat",
        "get_eim_config",
        "get_certs",
        "get_smdp",
        "get_es9",
    ):
        assert suffix + ": true" in read_map


def test_esim_profile_target_fields_offer_aid_suggestions() -> None:
    js = _read("app.js")
    assert "profileTargetCache" in js
    assert "function ccSetProfileTargetCache" in js
    assert "function ccShouldSuggestProfileAidTargets" in js
    assert 'profile.aid || profile.isdp_aid || profile.isd_p_aid' in js
    assert 'input.setAttribute("list", listId)' in js
    assert 'profileTargetList.setAttribute("data-profile-targets", "1")' in js


def test_local_smdp_declares_two_operation_flavors() -> None:
    js = _read("app.js")
    group_start = js.index("var CC_ACTION_GROUPS_BY_SUBSYSTEM = {")
    map_start = js.index('"SCP11 Local"', group_start)
    map_end = js.index('"Local eIM"', map_start)
    map_window = js[map_start:map_end]

    for label in (
        '"Local SM-DP+ Provisioning"',
        '"Card & Session Operations"',
    ):
        assert label in map_window, f"Local SMDP+ missing operation label {label}"

    for retired_label in (
        '"Status & telemetry"',
        '"Card inspection"',
        '"Profile management"',
        '"Validation"',
    ):
        assert retired_label not in map_window, (
            f"old Local SMDP+ category tab still present: {retired_label}"
        )


def test_local_smdp_action_flavor_helper_covers_delivery_and_card_paths() -> None:
    js = _read("app.js")
    assert "var CC_LOCAL_SMDP_ACTION_FLAVORS = {" in js
    helper = js.split("function ccLocalSmdpActionFlavor(action)", 1)[1]
    helper = helper.split("function ccLocalSmdpActionFlavorGroups", 1)[0]
    for provisioning_suffix in (
        '"load_profile"',
        '"get_certs_inventory"',
        '"import_certificate"',
        '"store_metadata"',
        '"metadata_lint"',
        '"export_keybag"',
    ):
        assert provisioning_suffix in helper
    assert 'return "provisioning"' in helper
    assert 'return "card"' in helper


def test_profile_rows_wire_lifecycle_actions_for_live_and_local() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    for token in (
        "function _buildProfileCard(profile)",
        "cc-esim-profile-card",
        "cc-esim-profile-action--\" + operation",
        'var prefix = subsystem === "SCP11 Local" ? "scp11_local" : "scp11_live"',
        'return prefix + "." + operation + "_profile"',
        'fields[i] && fields[i].name === "identifier"',
        "inputs[_profileLifecycleInputName(action)] = target",
        "if (_profileLifecycleNeedsConfirm(action))",
        "applyActiveReaderDefault(action, inputs)",
        "refreshDashboard({ quiet: true })",
    ):
        assert token in fn_window


def test_esim_modules_expose_reset_and_refresh_toolbar() -> None:
    js = _read("app.js")
    assert "function ccFindCatalogueActionById(actionId)" in js
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    for token in (
        "cc-esim-module-toolbar",
        "Re-read the card and reload the displayed eSIM data",
        "Reset",
        "function refreshEsimSurface(opts)",
        "function resetEsimSurface()",
        'ccFindCatalogueActionById("scp11_live.reset_card")',
        "confirm: true",
        "localOverviewRefreshers",
    ):
        assert token in fn_window


def test_esim_modules_render_split_control_and_flow_panes() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    for token in (
        "var useEsimSplitPane = isDashboardSubsystem",
        'grid.className += " cc-esim-split-grid"',
        'contentHost.className = "cc-esim-split-pane cc-esim-left-pane"',
        'esimFlowPane.className = "cc-esim-split-pane cc-esim-flow-pane"',
        'esimFlowPane.setAttribute("aria-label", "APDU flow output")',
        "function _openEsimActionPane(action)",
        "runActionFromForm(action, form, status, result)",
    ):
        assert token in fn_window

    actions_append = fn_window.index("_appendCompactContent(dashActions)")
    dashboard_append = fn_window.index("_appendCompactContent(dashBody)")
    assert actions_append < dashboard_append


def test_local_eim_overview_renders_above_generic_actions() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    assert "function _buildLocalEimOverviewPanel()" in fn_window
    assert 'subsystem === "Local eIM"' in fn_window
    assert '_appendCompactContent(_buildLocalEimOverviewPanel())' in fn_window
    assert "LOCAL_EIM_OVERVIEW_SUFFIXES" in fn_window
    assert "function _shouldShowLocalEimDashboardAction(action)" in fn_window
    assert "actions.filter(_shouldShowLocalEimDashboardAction)" in fn_window

    overview_append = fn_window.index("_appendCompactContent(_buildLocalEimOverviewPanel())")
    actions_append = fn_window.index("_appendCompactContent(dashActions)")
    dashboard_append = fn_window.index("_appendCompactContent(dashBody)")

    assert overview_append < actions_append < dashboard_append


def test_local_smdp_overview_renders_above_generic_actions() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    assert "function _buildLocalSmdpOverviewPanel()" in fn_window
    assert 'subsystem === "SCP11 Local"' in fn_window
    assert '_appendCompactContent(_buildLocalSmdpOverviewPanel())' in fn_window
    assert "LOCAL_SMDP_OVERVIEW_SUFFIXES" in fn_window
    assert "function _shouldShowLocalSmdpDashboardAction(action)" in fn_window
    assert "actions.filter(_shouldShowLocalSmdpDashboardAction)" in fn_window

    overview_append = fn_window.index("_appendCompactContent(_buildLocalSmdpOverviewPanel())")
    actions_append = fn_window.index("_appendCompactContent(dashActions)")
    dashboard_append = fn_window.index("_appendCompactContent(dashBody)")

    assert overview_append < actions_append < dashboard_append


def test_local_smdp_overview_wires_profile_and_cert_actions() -> None:
    js = _read("app.js")
    fn_start = js.index("function _localSmdpAction")
    fn_window = js[fn_start : js.index("function _buildLocalEimOverviewPanel", fn_start)]

    for token in (
        "cc-local-smdp-overview",
        "cc-local-smdp-inputs",
        "cc-local-smdp-tools",
        "cc-local-smdp-summary",
        "scp11_local.get_certs_inventory",
        "scp11_local.import_certificate",
        "scp11_local.load_profile",
        "certificate_role: roleSelect.value",
        "private_key_path: _localEimText(keyPath.input.value)",
        "profile_path: pathValue",
        "pickForField(field)",
    ):
        assert token in fn_window


def test_local_eim_overview_wires_cert_and_queue_actions() -> None:
    js = _read("app.js")
    fn_start = js.index("function _localEimPathField")
    fn_window = js[fn_start : js.index("// --- Main content area ---", fn_start)]

    for token in (
        "cc-local-eim-overview",
        "cc-local-eim-inputs",
        "cc-local-eim-tools",
        "cc-local-eim-summary",
        "eim_local.eim_certs_inventory",
        "eim_local.hotfolder_metadata",
        "eim_local.issue_package",
        "eim_local.eim_package_lint",
        "eim_local.eim_package_explain",
        "eim_local.load_eim_package",
        "eim_local.hotfolder_campaign",
        "_openEsimActionPane(action)",
        "cert_path: certInputValue()",
        "enableFilePathDrop(input)",
        "pickForField(field)",
    ):
        assert token in fn_window


def test_esim_and_local_smdp_skip_category_ribbon_but_use_flavor_rails() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    assert 'subsystem === "eSIM Management"\n      || subsystem === "SCP11 Local"' in fn_window
    assert "ccEsimActionFlavorGroups(mutationActions)" in fn_window
    assert "ccLocalSmdpActionFlavorGroups(mutationActions)" in fn_window
    assert "cc-esim-action-section cc-esim-action-section--" in fn_window
    assert "cc-local-smdp-action-section--" in fn_window
    assert 'subsystem === "SCP11 Local"' in fn_window


def test_esim_lpad_and_ipad_render_as_action_tabs() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]

    for token in (
        "cc-esim-action-rails--tabbed",
        "cc-esim-action-tabs",
        "cc-esim-action-tab",
        "cc-esim-action-tab-label",
        "cc-esim-action-tab-count",
        "cc-esim-action-panel",
        "activeActionFlavorId = flavorGroups[0].meta.id",
        "function switchActionFlavor(flavorId)",
        "switchActionFlavor(group.meta.id)",
        "_openEsimActionPane(action)",
    ):
        assert token in fn_window


def test_esim_action_runs_stay_in_flow_pane_not_popout() -> None:
    js = _read("app.js")
    assert "function ccActionShouldAutoRunInEsimFlowPane(action)" in js
    helper = js.split("function ccActionShouldAutoRunInEsimFlowPane(action)", 1)[1]
    helper = helper.split("// -- Action popout builder", 1)[0]
    assert "!ccActionNeedsManualInput(action)" in helper
    assert "action.streams" not in helper

    form_start = js.index("async function runActionFromForm(action, form, statusEl, resultEl)")
    form_window = js[form_start : js.index("function renderErrorBlock", form_start)]
    assert 'resultEl.closest(".cc-esim-flow-pane")' in form_window
    assert "&& !currentEsimFlowPane" in form_window

    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]
    assert "if (useEsimSplitPane) {\n            _openEsimActionPane(action);" in fn_window
    assert "_openInlineActionPane(action);" in fn_window

    pane_start = fn_window.index("function _openEsimActionPane(action)")
    pane_window = fn_window[pane_start : fn_window.index("// Mutation suffixes", pane_start)]
    assert "ccActionShouldAutoRunInEsimFlowPane(action)" in pane_window
    assert 'runBtn.textContent = action.streams ? "Restart" : "Re-run"' in pane_window


def test_streaming_flow_error_frames_are_debug_gated() -> None:
    js = _read("app.js")
    for token in (
        'var CC_GLOBAL_DEBUG_FLAG = "YGGDRASIM_GLOBAL_DEBUG"',
        "function ccRefreshGlobalDebugFlag()",
        "function ccShouldShowStreamFrame(level)",
    ):
        assert token in js

    helper = js.split("function ccShouldShowStreamFrame(level)", 1)[1]
    helper = helper.split("function ccSubsystemRequiresReaderSession", 1)[0]
    assert 'String(level || "info").toLowerCase() !== "error"' in helper
    assert "ccIsGlobalDebugEnabled()" in helper

    stream_start = js.index("function runStreamingAction(action, inputs, statusEl, resultEl, card)")
    stream_window = js[stream_start : js.index("function renderReportSummary", stream_start)]
    for token in (
        "ccRefreshGlobalDebugFlag().then(function ()",
        "var hiddenErrorCount = 0",
        "var showFrame = ccShouldShowStreamFrame(level)",
        "hiddenErrorCount += 1",
        "if (showFrame) {\n              statusEl.textContent = \"error\";",
        "Flow stopped before completion. Enable debug for details.",
    ):
        assert token in stream_window


def test_command_center_modules_use_frameless_workbench_chrome() -> None:
    js = _read("app.js")
    assert 'mainEl.classList.toggle("main--module-workbench", true);' in js
    assert 'mainEl.classList.remove("main--module-workbench")' in js


def test_render_compact_workbench_still_uses_grouping_helper_for_other_modules() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]
    assert "ccGroupActionsForSubsystem(subsystem, actions)" in fn_window, (
        "Grouped workbenches still need compact category grouping."
    )
    assert "cc-compact-ribbon" in fn_window, (
        "grouped workbenches must still emit the compact category ribbon."
    )
    for token in (
        "function groupedActionCategoryId(action)",
        "function applyGroupedActionFilters()",
        "actionFilterRecords = allButtons",
        "categoryId: groupedBuckets ? groupedActionCategoryId(act) : \"\"",
    ):
        assert token in fn_window


def test_search_hides_empty_esim_flavor_sections() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]
    assert "allButtons.forEach" in fn_window
    assert "rec.btn.hidden = q.length > 0 && rec.haystack.indexOf(q) === -1" in fn_window
    assert 'var tabbedEsim = wb.querySelector(".cc-esim-action-rails--tabbed")' in fn_window
    assert 'tab.hidden = q.length > 0 && !hasVisible' in fn_window
    assert 'firstVisibleTab.getAttribute("data-action-flavor")' in fn_window
    assert 'wb.querySelectorAll(".cc-esim-action-section")' in fn_window
    assert "section.hidden = !visible" in fn_window


# ----------------------------------------------------------------------
# CSS contract
# ----------------------------------------------------------------------


def test_category_styles_present_for_remaining_grouped_workbenches() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-compact-ribbon",
        ".cc-compact-tabstrip",
        ".cc-compact-tab",
        ".cc-compact-tab.active",
        ".cc-compact-tab-label",
        ".cc-compact-tab-count",
        ".cc-compact-tab.active .cc-compact-tab-count",
        ".cc-compact-rbtn[hidden]",
    ):
        assert selector in css, f"category selector missing: {selector}"


def test_esim_management_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".main--module-workbench .cc-workbench",
        ".main--module-workbench .cc-workbench.cc-workbench--compact",
        ".main--module-workbench .cc-header",
        ".main--module-workbench .cc-actions",
        ".main--module-workbench .cc-compact-header",
        ".main--module-workbench .cc-compact-action-grid",
        ".cc-esim-split-grid",
        ".cc-esim-left-pane",
        ".cc-esim-flow-pane",
        ".cc-esim-flow-result .flow-log",
        ".cc-esim-module-toolbar",
        ".cc-esim-module-tool",
        ".cc-esim-module-tool--reset",
        ".cc-esim-module-toolbar-status",
        ".cc-esim-profile-list",
        ".cc-esim-profile-card",
        ".cc-esim-profile-summary",
        ".cc-esim-profile-controls",
        ".cc-esim-profile-action--enable",
        ".cc-esim-profile-action--delete",
        ".cc-esim-action-rails",
        ".cc-esim-action-rails--tabbed",
        ".cc-esim-action-tabs",
        ".cc-esim-action-tab",
        ".cc-esim-action-tab.active",
        ".cc-esim-action-tab-count",
        ".cc-esim-action-panel",
        ".cc-esim-action-section[hidden]",
        ".cc-esim-action-section",
        ".cc-esim-action-section-title",
        ".cc-esim-action-buttons",
    ):
        assert selector in css, f"eSIM management selector missing: {selector}"


def test_local_smdp_management_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-local-smdp-overview",
        ".cc-local-smdp-role",
        ".cc-local-smdp-inputs",
        ".cc-local-smdp-tools",
        ".cc-local-smdp-summary",
        ".cc-local-smdp-action-rails",
        ".cc-local-smdp-action-section",
    ):
        assert selector in css, f"Local SMDP+ selector missing: {selector}"


def test_local_eim_management_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-local-eim-overview",
        ".cc-local-eim-inputs",
        ".cc-local-eim-tools",
        ".cc-local-eim-summary",
        ".cc-local-eim-card",
        ".cc-local-eim-cert-list",
        ".cc-local-eim-queue-list",
        ".cc-local-eim-row-actions",
        ".cc-local-eim-result",
    ):
        assert selector in css, f"Local eIM selector missing: {selector}"
