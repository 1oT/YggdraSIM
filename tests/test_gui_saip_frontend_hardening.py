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


def test_save_treats_the_browser_upload_label_as_no_location() -> None:
    body = _body()
    save = _between(
        body,
        "  async function saipRibbonSavePackage(",
        "\n  // Generic multi-field ribbon modal.",
    )

    # ``upload:<name>`` names no file on disk: Save asks where to write
    # instead of resolving the label against the server's working directory.
    assert "function saipIsUploadSource(sourcePath)" in body
    assert "/^upload:/i.test(" in body
    assert 'if (saipIsUploadSource(outPath)) outPath = "";' in save
    assert "var needsPicker = shiftToSaveAs || !outPath;" in save
    assert save.index("saipIsUploadSource(outPath)") < save.index("var needsPicker")


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
    assert "You can also drop one or more files anywhere in this workspace." in active_slots
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


def test_file_tree_containers_are_selectable_not_just_expandable() -> None:
    node = _between(
        _body(),
        "  function saipBuildFileTreeNode(",
        "\n  function saipExpandFileTreePath(",
    )

    # The caret owns expand/collapse so the row is free to select.
    assert 'caret.addEventListener("click", function (event) {' in node
    assert "event.stopPropagation();" in node
    # A node with a createFCP row opens the detail pane whether or not it
    # has children -- MF / DF / ADF used to fall into the toggle branch
    # and were unreachable from the detail pane.
    assert (
        'row.addEventListener("click", function () {\n'
        "        saipOpenFileRow(pkg, node.row, peList, detail, validation);"
    ) in node
    # Selecting a container must not shrink the expand target to a glyph.
    assert 'row.addEventListener("dblclick", function (event) {' in node


def test_directory_detail_hides_the_body_tabs_and_keeps_the_ef_preference() -> None:
    detail = _between(
        _body(),
        "  function renderSaipFileDetail(",
        "\n  function saipFileRenderHex(",
    )

    # mf / df / adf come back with body_size 0 and no decoded/records
    # payload, so the Data and Template tabs have nothing to render.
    assert 'var isContainer = fcpKind === "mf" || fcpKind === "df" || fcpKind === "adf";' in detail
    assert "var tabData = isContainer ? null : mkTab(" in detail
    assert "var hasTemplateTab = !isContainer && !!(" in detail
    assert "if (tabData) tabs.appendChild(tabData);" in detail
    # Containers track their own sub-tab so opening a folder does not
    # reset the tab the operator chose for EFs.
    assert (
        'var tabStateKey = isContainer ? "activeContainerFileTab" : "activeFileTab";'
    ) in detail
    assert "pkg[tabStateKey] = id;" in detail


def test_file_tree_kind_glyphs_do_not_reuse_the_caret_triangles() -> None:
    body = _body()
    caret = _between(
        body, 'caret.className = "saip-file-caret saip-file-caret--toggle";',
        'caret.setAttribute("aria-hidden", "true");',
    )
    assert 'caret.textContent = collapsed ? "▶" : "▼";' in caret
    glyphs = _between(
        body, "function saipFileGlyph(kind) {", "async function saipLoadShowPe("
    )
    # The DF glyph used to be ▼, which sat right beside the ▶ / ▼ caret
    # and read as a second, dead disclosure control on every directory.
    for triangle in ("▶", "▼", "◀", "▲", "▸", "▾"):
        assert triangle not in glyphs
    assert 'if (kind === "df") return "■";' in glyphs


def test_pe_export_dialog_writes_the_pe_document_by_default() -> None:
    body = _body()
    helpers = _between(
        body, "  // Single-PE files.", "\n  async function saipRibbonExportPe("
    )
    assert 'var SAIP_PE_EXPORT_EXTS = { json: ".pe.json", der: ".der", hex: ".hex" };' in helpers
    assert "function saipPeExportBaseName(pkg, idx)" in helpers
    assert "function saipPeExportFormatForPath(pathValue, fallback)" in helpers
    export = _between(
        body, "  async function saipRibbonExportPe(", "\n  async function saipRibbonMovePe("
    )
    assert 'default: "json"' in export
    assert "saveFilename: baseName + SAIP_PE_EXPORT_EXTS.json" in export
    # The destination's extension names the format; the select is the seed.
    assert "var format = saipPeExportFormatForPath(outPath, selected);" in export
    assert "format: format," in export
    # Template sessions choose between keeping the literals and substituting.
    assert "if (templateSession) inputs.resolve_variables = !!result.values.resolve_variables;" in export
    assert 'saipEmitPeIoWarnings("saip.export_pe", d);' in export


def test_pe_import_dialog_accepts_pe_documents_and_relays_warnings() -> None:
    body = _body()
    imported = _between(
        body, "  async function saipRibbonImportPe(", "\n  // Single-PE files."
    )
    assert '"PE document (*.pe.json;*.json)",' in imported
    assert '"PE bytes (*.der;*.asn;*.asn1;*.txt;*.hex)",' in imported
    assert 'saipEmitPeIoWarnings("saip.import_pe", resp.data);' in imported
    assert "pkg.peCount = resp.data.pe_count;" in imported


def test_fcp_editor_applies_a_row_on_enter_and_ctrl_enter() -> None:
    body = _body()
    editor = _between(
        body,
        "    _SAIP_EDIT_FIELDS.forEach(function (spec) {",
        "    fcpCard.appendChild(editTable);",
    )

    # Plain Enter in a text or number input of the row is the Apply button
    # (a select and a checkbox keep it); Ctrl/Cmd+Enter applies from any
    # control of the row, the chord every workbench editor takes.
    assert 'if (ev.key !== "Enter" || ev.shiftKey || ev.altKey) return;' in editor
    assert "if (ev.ctrlKey || ev.metaKey) {\n          if (!saipEventTargetIsEditable(el)) return;" in editor
    assert 'if (el.tagName !== "INPUT") return;' in editor
    assert 'if (el.type === "checkbox" || el.type === "hidden") return;' in editor
    assert "applyButton.click();" in editor
    assert "applyButton = btn;" in editor
    assert editor.index("td2.addEventListener(\"keydown\"") < editor.index("applyButton = btn;")


def test_fcp_pin_status_row_reads_the_pin_status_member() -> None:
    body = _body()
    fields = _between(body, "  var _SAIP_EDIT_FIELDS = [", "  ];")

    assert 'row: "pin_status_template"' in fields
    assert 'row: "details"' not in fields


def test_fcp_editor_carries_the_life_cycle_state_row() -> None:
    body = _body()
    fields = _between(body, "  var _SAIP_EDIT_FIELDS = [", "  ];")

    # TCA SAIP v3.4.1 §8.3.2 ``Fcp.lcsi`` (DEFAULT '05'H, optional for every
    # file kind on pages 30 and 46); TS 102 221 §11.1.1.4.9 tag '8A'. The
    # row sits where both FCP orders put it: right before the security
    # attributes.
    assert 'sub: "lcsi"' in fields
    assert 'row: "lcsi"' in fields
    assert fields.index('sub: "lcsi"') < fields.index('sub: "securityAttributesReferenced"')
    lcsi_row = _between(fields, 'sub: "lcsi"', 'sub: "securityAttributesReferenced"')
    for kind in ("mf", "adf", "df", '"ef-t"', '"ef-lf"', '"ef-cy"', '"ef-ber"', "link"):
        assert kind + ': "O"' in lcsi_row

    # The state the byte encodes is shown beside the hex and follows the
    # input while the operator types, the way the EF.ARR record chip does.
    editor = _between(
        body,
        "    _SAIP_EDIT_FIELDS.forEach(function (spec) {",
        "    fcpCard.appendChild(editTable);",
    )
    assert 'if (spec.sub === "lcsi") {' in editor
    assert "saipDecodeLcsi(input.value)" in editor
    assert 'input.addEventListener("input", refreshStateChip);' in editor


def test_security_attrs_record_is_shown_in_decimal_and_hex() -> None:
    body = _body()

    assert "function saipArrRecordLabel(record)" in body
    assert "function saipSecurityAttrsRecordChip(hexValue)" in body
    resolver = _between(
        body,
        "  function saipResolveSecurityAttrsRef(hexValue, fcp, accessRule) {",
        "  function saipDeriveEfSize(fcp, fileKind) {",
    )
    assert "saipArrRecordLabel(bytes[2])" in resolver
    assert "saipArrRecordLabel(bytes[0])" in resolver
    assert '" · record " + bytes[' not in resolver
    block = _between(
        body,
        "  function saipBuildAccessRuleBlock(info) {",
        "    var rules = Array.isArray(info.rules) ? info.rules : [];",
    )
    assert block.count("saipArrRecordLabel(info.record)") == 2
    editor = _between(
        body,
        "    _SAIP_EDIT_FIELDS.forEach(function (spec) {",
        "    fcpCard.appendChild(editTable);",
    )
    assert 'if (spec.sub === "securityAttributesReferenced") {\n          // The record' in editor
    assert 'input.addEventListener("input", refreshRecordChip);' in editor
