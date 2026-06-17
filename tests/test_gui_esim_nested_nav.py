"""Static contract for the eSIM Command Center management surfaces.

The eSIM Management workbench is intentionally flatter than the older
category-ribbon layout: card overview and profiles stay in one dashboard,
profile rows expose lifecycle controls directly, and the generic operation
buttons are split into SGP.22 Consumer (LPA-d) and SGP.32 IoT (IPA-d)
flavors. Local SMDP+ uses the same dashboard treatment with Local SM-DP+
Provisioning and Card & Session Operations rails. Local eIM still uses the
compact category ribbon until its dedicated redesign.
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


def test_render_compact_workbench_still_uses_grouping_helper_for_other_modules() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]
    assert "ccGroupActionsForSubsystem(subsystem, actions)" in fn_window, (
        "Local eIM and other grouped workbenches still need compact category grouping."
    )
    assert "cc-compact-ribbon" in fn_window, (
        "grouped workbenches must still emit the compact category ribbon."
    )


def test_search_hides_empty_esim_flavor_sections() -> None:
    js = _read("app.js")
    fn_start = js.index("function renderCompactWorkbench(container, subsystem, actions, leaf)")
    fn_window = js[fn_start : js.index("function stopHilWorkbenchRuntime", fn_start)]
    assert "allButtons.forEach" in fn_window
    assert "rec.btn.hidden = q.length > 0 && rec.haystack.indexOf(q) === -1" in fn_window
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
    ):
        assert selector in css, f"category selector missing: {selector}"


def test_esim_management_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-esim-profile-list",
        ".cc-esim-profile-card",
        ".cc-esim-profile-summary",
        ".cc-esim-profile-controls",
        ".cc-esim-profile-action--enable",
        ".cc-esim-profile-action--delete",
        ".cc-esim-action-rails",
        ".cc-esim-action-section",
        ".cc-esim-action-section-title",
        ".cc-esim-action-buttons",
    ):
        assert selector in css, f"eSIM management selector missing: {selector}"


def test_local_smdp_management_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-local-smdp-action-rails",
        ".cc-local-smdp-action-section",
    ):
        assert selector in css, f"Local SMDP+ selector missing: {selector}"
