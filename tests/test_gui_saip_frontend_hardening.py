# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression guards for SAIP workbench lifecycle and browser safety.

These checks intentionally target the canonical modular source.  The release
bundle is rebuilt from that source by the frontend build step.
"""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "gui_frontend/src/js/saip-workbench.js"
_RIBBON_CSS = _ROOT / "gui_frontend/src/css/views/saip/ribbon-bar.css"
_PLACEHOLDER_CSS = (
    _ROOT / "gui_frontend/src/css/views/saip/placeholder-lead.css"
)
_FIND_CSS = _ROOT / "gui_frontend/src/css/views/saip/find-overlay.css"
_TAB_CSS = _ROOT / "gui_frontend/src/css/views/saip/tab-strip.css"
_WORKBENCH_CSS = (
    _ROOT / "gui_frontend/src/css/views/saip/workbench-shell.css"
)


def _body() -> str:
    return _SOURCE.read_text(encoding="utf-8")


def _between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    end = body.index(end_marker, start)
    return body[start:end]


def test_browser_workbook_upload_uses_private_plugin_fields_and_two_size_checks() -> None:
    body = _body()
    route = _between(
        body,
        "  function saipRouteSpreadsheetToGenerator(",
        "\n  function saipRefreshCatalogueContributions(",
    )
    dropped = _between(
        body,
        "  async function saipOpenPackageByDroppedFile(",
        "\n  // Ribbon Open: path picker",
    )

    assert "initialValues.workbook_filename" in route
    assert "initialValues.workbook_content_base64" in route
    assert "_ccBuildActionPopout(action, initialValues)" in route
    assert "file.arrayBuffer()" in dropped
    assert "Number(file.size || 0) > SAIP_MAX_WORKBOOK_UPLOAD_BYTES" in dropped
    assert "workbookBuffer.byteLength > SAIP_MAX_WORKBOOK_UPLOAD_BYTES" in dropped
    assert "buffer.byteLength > SAIP_MAX_UPLOAD_BYTES" in dropped
    assert '"browser workbook upload prepared: upload:"' in route
    assert 'String(upload.workbook_filename || "workbook.xlsx")' in route


def test_advanced_palette_cannot_launch_workbench_lifecycle_actions() -> None:
    body = _body()
    eligibility = _between(
        body,
        "  var SAIP_ACTION_PALETTE_EXCLUDED_IDS = {",
        "\n  function saipActionSessionField(",
    )
    for action_id in (
        "saip.open_package",
        "saip.open_package_upload",
        "saip.open_package_with_variables",
        "saip.create_package",
        "saip.close_package",
        "saip.save_package",
        "saip.revert_changes",
        "saip.undo",
        "saip.redo",
    ):
        assert f'"{action_id}": true' in eligibility

    assert "SAIP_ACTION_PALETTE_EXCLUDED_IDS[id] !== true" in eligibility
    assert 'tags.indexOf("deprecated") === -1' in eligibility
    assert "saipActionIsPaletteEligible(action)" in eligibility
    assert "Additional registered SAIP actions" in body


def test_advanced_palette_contains_keyboard_focus_and_restores_it() -> None:
    body = _body()
    palette = _between(
        body,
        "  function saipOpenActionPalette(pkg)",
        "\n  async function saipRefreshActivePackage(",
    )
    close = _between(
        body,
        "  function saipCloseActionPalette()",
        "\n  async function saipOpenAdvancedAction(",
    )

    assert 'event.key === "Escape"' in palette
    assert 'event.key === "Tab"' in palette
    assert "card.contains(document.activeElement)" in palette
    assert "(event.shiftKey ? last : first).focus()" in palette
    assert "search.focus()" in palette
    assert "returnFocus.focus()" in close


def test_add_file_modal_contains_focus_and_removes_its_global_listener() -> None:
    body = _body()
    modal = _between(
        body,
        "  function saipCloseAddFileModal()",
        "\n  async function saipRefreshAfterAddFile(",
    ) + _between(
        body,
        "  function saipOpenAddFileModal(",
        "\n  async function saipApplyTemplateFileToggle(",
    )

    assert 'card.setAttribute("aria-modal", "true")' in modal
    assert 'ev.key === "Tab"' in modal
    assert 'document.addEventListener("keydown", escListener, true)' in modal
    assert '"keydown", existing.__saipKeyHandler, true' in modal
    assert "returnFocus.focus()" in modal


def test_close_requires_explicit_backend_confirmation_and_passes_discard_intent() -> None:
    body = _body()
    close = _between(
        body,
        "  async function saipClosePackage(",
        "\n  async function saipLoadPeRows(",
    )

    assert "discard_changes: discardChanges === true" in close
    assert "if (discardChanges === true)" in close
    assert "saipCancelPendingAutoApplies(pkg)" in close
    assert "await saipFlushPendingAutoApplies(pkg)" in close
    assert "response.data.closed !== true" in close
    assert "return false;" in close
    assert "wb.packages = wb.packages.filter" in close
    assert close.index("response.data.closed !== true") < close.index(
        "wb.packages = wb.packages.filter"
    )


def test_expired_backend_session_can_be_removed_from_the_local_workbench() -> None:
    body = _body()
    close = _between(
        body,
        "  async function saipClosePackage(",
        "\n  async function saipLoadPeRows(",
    )

    assert "var backendAlreadyGone = pkg.sessionUnavailable === true" in close
    assert "if (pkg.sessionId && !backendAlreadyGone)" in close
    assert "backendAlreadyGone = saipResponseSaysSessionGone(response)" in close
    assert "if (!backendAlreadyGone)" in close
    assert "removed cached package for an expired backend session" in close
    assert close.index("if (!backendAlreadyGone)") < close.index(
        "wb.packages = wb.packages.filter"
    )


def test_validation_and_application_errors_are_rendered_as_text() -> None:
    body = _body()
    finding = _between(
        body,
        "  function saipBuildValRow(",
        "\n  function saipFindingJumpKind(",
    )
    applications = _between(
        body,
        "  function saipBuildApplicationCard(",
        "\n  function saipAppAidRow(",
    )

    assert '["fail", "warn", "info", "pass"].indexOf(rawSeverity)' in finding
    assert "severityChip.textContent = sev.toUpperCase()" in finding
    assert "sevCell.innerHTML" not in finding
    assert "resolutionError.textContent" in applications
    assert "row.pe_index" in applications


def test_secret_token_values_are_not_written_to_download_sidecars_or_logs() -> None:
    body = _body()
    export = _between(
        body,
        "  function saipBuildTokenExportDocument(",
        "\n  function saipDownloadJsonDocument(",
    )
    apply_variable = _between(
        body,
        "  async function saipApplyVariable(",
        "\n  // ------------------------------------------------------------------\n  // SA-4 compare pane",
    )

    assert "secret_omitted_count" in export
    assert "value_omitted: true" in export
    assert "tokenDefs[name]" in export
    assert export.index("value_omitted: true") < export.index("tokenDefs[name]")
    assert "saipVariableRedactMessage" in apply_variable
    assert 'message: n + (secret ? " secret value submitted"' in apply_variable


def test_text_editing_shortcuts_and_cross_platform_recent_names_are_preserved() -> None:
    body = _body()
    shortcuts = _between(
        body,
        "  function saipEventTargetIsEditable(",
        "\n  // ─────────────────────────────────────────────────────────────────\n"
        "  // SA-G1: ribbon command bar",
    )

    assert "if (saipEventTargetIsEditable(evt.target)) return;" in shortcuts
    assert 'tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT"' in shortcuts
    assert "split(/[\\\\/]/)" in body


def test_saip_command_strip_preserves_workspace_height_and_accessibility() -> None:
    body = _body()
    css = _RIBBON_CSS.read_text(encoding="utf-8")
    render = _between(
        body,
        "  function renderSaipRibbon(",
        "\n  var SAIP_TOP_TABS",
    )

    assert 'ribbon.setAttribute("role", "region")' in body
    assert 'ribbon.setAttribute("aria-label", "SAIP commands")' in body
    assert 'ribbon.setAttribute("tabindex", "0")' in body
    assert 'group.setAttribute("role", "group")' in render
    assert 'group.setAttribute("aria-label", label + " commands")' in render
    assert "flex-wrap: nowrap" in css
    assert "overflow-x: auto" in css
    assert ".saip-ribbon:focus-visible" in css
    assert ".saip-ribbon-btn:focus-visible" in css


def test_empty_saip_workbench_offers_a_direct_open_action() -> None:
    body = _body()
    css = _PLACEHOLDER_CSS.read_text(encoding="utf-8")
    active_slots = _between(
        body,
        "  function renderSaipActiveSlots(",
        "\n  // Mount the right slot tree",
    )

    assert 'emptyState.setAttribute("role", "region")' in active_slots
    assert 'emptyTitle.textContent = "Open a SAIP package"' in active_slots
    assert 'openButton.textContent = "Open package"' in active_slots
    assert "saipRibbonOpenPackage(" in active_slots
    assert "You can also drop a file anywhere in this workspace." in active_slots
    assert ".saip-placeholder-action:focus-visible" in css


def test_saip_find_overlay_keeps_all_options_keyboard_accessible() -> None:
    body = _body()
    css = _FIND_CSS.read_text(encoding="utf-8")
    find_overlay = _between(
        body,
        "  function saipCloseFindOverlay()",
        "\n  async function saipRibbonShowPeInfo(",
    )

    assert "_saipFindState.returnFocus = document.activeElement" in find_overlay
    assert "document.contains(returnFocus)" in find_overlay
    assert 'inp.setAttribute("aria-label", "Find in package")' in find_overlay
    assert 'caseCb.setAttribute("aria-label", "Case-sensitive search")' in find_overlay
    assert 'regexCb.setAttribute("aria-label", "Use regular expressions")' in find_overlay
    assert 'status.setAttribute("aria-live", "polite")' in find_overlay
    assert 'overlay.addEventListener("keydown"' in find_overlay
    assert 'ev.key !== "Escape"' in find_overlay
    assert "display: none" not in css
    assert ".saip-find-toggle:focus-within" in css
    assert ".saip-find-result:focus-visible" in css
    assert "@media (max-width: 560px)" in css


def test_saip_tabs_expose_the_controlled_panel_and_focus_cue() -> None:
    body = _body()
    css = _TAB_CSS.read_text(encoding="utf-8")
    tabs = _between(
        body,
        "  function renderSaipTopTabs(",
        "\n  function saipApplicationsCount(",
    )

    assert 'tabBody.setAttribute("role", "tabpanel")' in body
    assert 'btn.setAttribute("role", "tab")' in tabs
    assert 'btn.setAttribute("aria-selected"' in tabs
    assert 'btn.setAttribute("aria-controls", "saip-tab-body")' in tabs
    assert 'btn.id = "saip-top-tab-" + spec.id' in tabs
    assert 'tabBody.setAttribute("aria-labelledby"' in tabs
    assert ".saip-top-tab:focus-visible" in css


def test_open_package_rows_use_separate_keyboard_buttons() -> None:
    body = _body()
    css = _WORKBENCH_CSS.read_text(encoding="utf-8")
    drawer = _between(
        body,
        "  function renderSaipDrawer(",
        "\n  // ``renderSaipEditToolbar``",
    )

    assert 'ul.setAttribute("aria-label", "Open packages")' in drawer
    assert 'select.className = "saip-pkg-select"' in drawer
    assert '"Activate package " + String(pkg.filename' in drawer
    assert '"Close package " + String(pkg.filename' in drawer
    assert 'li.addEventListener("click"' not in drawer
    assert ".saip-pkg-select:focus-visible" in css
    assert ".saip-pkg-close:focus-visible" in css
    assert ".saip-pkg-row:focus-within" in css


def test_secondary_saip_tabs_share_complete_keyboard_semantics() -> None:
    body = _body()
    helper = _between(
        body,
        "  function saipConfigureLocalTabs(",
        "\n  function saipShortcutHandler(",
    )

    assert 'tablist.setAttribute("role", "tablist")' in helper
    assert 'button.setAttribute("role", "tab")' in helper
    assert 'button.setAttribute("aria-controls", panel.id)' in helper
    assert 'button.setAttribute("aria-selected"' in helper
    assert 'event.key === "ArrowLeft"' in helper
    assert 'event.key === "ArrowRight"' in helper
    assert 'event.key === "Home"' in helper
    assert 'event.key === "End"' in helper
    assert body.count("saipConfigureLocalTabs(") >= 6


def test_file_tree_uses_roving_focus_and_restores_it_after_render() -> None:
    body = _body()
    renderer = _between(
        body,
        "  function renderSaipFileListPane(",
        "\n  function saipFileTreeIsContainerKind(",
    )
    node = _between(
        body,
        "  function saipBuildFileTreeNode(",
        "\n  function saipExpandFileTreePath(",
    )
    opener = _between(
        body,
        "  function saipOpenFileRow(",
        "\n  function saipFileSectionLabel(",
    )

    assert 'ul.setAttribute("role", "tree")' in renderer
    assert 'ul.setAttribute("aria-label", "Profile file system")' in renderer
    assert "item === preferred ? 0 : -1" in renderer
    assert 'li.dataset.fileNodeId = String(node.id || "")' in node
    assert "li.tabIndex = -1" in node
    assert 'event.key === "ArrowUp"' in node
    assert 'event.key === "ArrowDown"' in node
    assert "visibleItems[next].focus()" in node
    assert "if (restored) restored.focus()" in node
    assert "restoreTreeFocus" in opener
    assert "if (restored) restored.focus()" in opener


def test_saip_clickable_rows_and_disclosures_have_keyboard_equivalents() -> None:
    body = _body()
    file_summary = _between(
        body,
        "  function saipEditorRenderFilesCard(",
        "\n  function saipTemplatePeFileKeys(",
    )
    decoded_row = _between(
        body,
        "  function saipBuildDecodedFieldRow(",
        "\n  function saipDecodedPayloadDiffers(",
    )
    semantic = _between(
        body,
        "  function saipRenderSemanticDiffSection(",
        "\n  function _semSevAbbr(",
    )
    applications = _between(
        body,
        "  function saipBuildApplicationCard(",
        "\n  function saipAppAidRow(",
    )

    assert 'tr.setAttribute("role", "button")' in file_summary
    assert 'event.key !== "Enter" && event.key !== " "' in file_summary
    assert 'head.setAttribute("role", "button")' in decoded_row
    assert 'head.setAttribute("aria-expanded"' in decoded_row
    assert 'head.setAttribute("aria-controls", form.id)' in decoded_row
    assert 'head.addEventListener("keydown"' in decoded_row
    assert '"aria-label",' in semantic
    assert 'tr.addEventListener("keydown"' in semantic
    assert 'inlineHost.addEventListener("click"' in applications
    assert "event.stopPropagation()" in applications


def test_saip_focus_targets_and_names_remain_visible_and_usable() -> None:
    body = _body()
    workbench_css = _WORKBENCH_CSS.read_text(encoding="utf-8")
    tree_css = (
        _ROOT / "gui_frontend/src/css/views/saip/file-system-tree.css"
    ).read_text(encoding="utf-8")
    validation_css = (
        _ROOT / "gui_frontend/src/css/views/saip/validation-dock.css"
    ).read_text(encoding="utf-8")
    typed_css = (
        _ROOT / "gui_frontend/src/css/views/saip/typed-pe-editor.css"
    ).read_text(encoding="utf-8")

    assert 'ta.setAttribute("aria-label", "Profile element JSON")' in body
    assert 'filterInput.setAttribute("aria-label", "Filter decoded fields")' in body
    assert 'copyBtn.setAttribute("aria-label", "Copy validation code "' in body
    assert ".saip-detail-tab:focus-visible" in workbench_css
    assert "min-height: 30px" in workbench_css
    assert ".saip-file-node:focus-visible > .saip-file-node-row" in tree_css
    assert ".saip-val-code-cell:focus-within .saip-val-copy-btn" in validation_css
    assert ".saip-val-copy-btn:focus-visible" in validation_css
    assert "button.saip-chip:focus-visible" in typed_css
