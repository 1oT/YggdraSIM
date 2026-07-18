# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _source_and_served_bodies() -> tuple[str, str]:
    source = (_ROOT / "gui_frontend/src/js/saip-workbench.js").read_text(encoding="utf-8")
    served = (_ROOT / "yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
    return source, served


def _command_center_source() -> str:
    return (_ROOT / "gui_frontend/src/js/command-center.js").read_text(encoding="utf-8")


def _between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    end = body.index(end_marker, start)
    return body[start:end]


def _assert_conditional_baseline_launcher(body: str) -> None:
    assert '"saip-ribbon-package-form"' in body
    assert '"saip-ribbon-package-session"' in body
    assert "saipCatalogueActionsByTag" in body
    assert "_ccBuildActionPopout(action)" in body
    assert "saipRibbonRunSessionContribution" in body
    assert "label: action.title || action.id" in body
    assert "icon: _ccResolveIcon(action.id)" in body
    assert 'encodeURIComponent(action.id) + "/run"' in body
    assert "concrete_export_allowed === false" in body
    assert "AUTHORING ONLY — DER/HEX export blocked" in body


def test_canonical_source_has_plugin_conditional_launcher() -> None:
    body, _served = _source_and_served_bodies()
    _assert_conditional_baseline_launcher(body)


def test_served_bundle_has_plugin_conditional_launcher() -> None:
    _source, body = _source_and_served_bodies()
    _assert_conditional_baseline_launcher(body)


def test_plugin_contribution_blocks_match_source_and_served_bundle() -> None:
    source, served = _source_and_served_bodies()
    session_start = "  async function saipRibbonRunSessionContribution("
    session_end = "\n  // Shared open pipeline."
    assert _between(source, session_start, session_end) == _between(
        served,
        session_start,
        session_end,
    )

    ribbon_start = '    saipCatalogueActionsByTag("saip-ribbon-package-form")'
    ribbon_end = "\n    pkgGrp.inner.appendChild(mkBtn({"
    assert _between(source, ribbon_start, ribbon_end) == _between(
        served,
        ribbon_start,
        ribbon_end,
    )


def test_save_as_enforces_template_and_concrete_format_contract() -> None:
    source, served = _source_and_served_bodies()
    start = "  async function saipRibbonSavePackage("
    end = "\n  // ─────────────────────────────────────────────────────────────────"
    source_block = _between(source, start, end)
    served_block = _between(served, start, end)
    assert source_block == served_block

    assert "Varder template (*.varder)" in source_block
    assert "ASN.1 template (*.asn;*.asn1)" in source_block
    assert "Tagged JSON template (*.json)" in source_block
    assert "DER profile (*.der)" in source_block
    assert "ASN.1 profile (*.asn;*.asn1)" in source_block
    assert "JSON profile (*.json)" in source_block
    assert ".varder is only available for templates" in source_block
    assert "DER/HEX are concrete-profile formats" in source_block
    assert "Tagged JSON partial draft (*.json)" in source_block


def test_token_form_contribution_is_conditional_and_synced() -> None:
    source, served = _source_and_served_bodies()
    contribution_start = (
        '    saipCatalogueActionsByTag("saip-ribbon-tokens-form")'
    )
    contribution_end = '\n    varsGrp.inner.appendChild(mkBtn({'

    source_block = _between(source, contribution_start, contribution_end)
    served_block = _between(served, contribution_start, contribution_end)
    assert source_block == served_block

    for body in (source, served):
        token_ribbon = _between(
            body,
            '    var varsGrp = mkGroup("Tokens");',
            '\n    // -- Lint commands',
        )
        assert token_ribbon.count('saip-ribbon-tokens-form') == 1
        assert token_ribbon.index('label: "Token editor"') < token_ribbon.index(
            'saip-ribbon-tokens-form'
        )
        assert 'saipCatalogueActionsByTag("saip-ribbon-tokens-form").forEach' in (
            token_ribbon
        )
        assert "_ccBuildActionPopout(action)" in token_ribbon
        assert "label: action.title || action.id" in token_ribbon


def test_catalogue_refresh_rebuilds_saip_token_contributions() -> None:
    command_source = _command_center_source()
    _source, served = _source_and_served_bodies()
    for body in (command_source, served):
        catalogue_load = _between(
            body,
            "  async function loadCommandCatalogue()",
            "\n  // Left-nav tree",
        )
        assert "commandState.catalogue = data" in catalogue_load
        assert "saipRefreshCatalogueContributions()" in catalogue_load


def test_token_registry_form_is_large_and_refreshes_after_save_or_reset() -> None:
    command_source = _command_center_source()
    _saip_source, served = _source_and_served_bodies()
    for body in (command_source, served):
        form_enhancement = _between(
            body,
            "  function ccEnhanceActionForm(action, form)",
            "\n  function ccEnhanceAsn1TlvDecodeForm(form)",
        )
        assert 'actionTags.indexOf("saip-ribbon-tokens-form")' in form_enhancement
        assert 'form.querySelector(\'[name="registry_json"]\')' in form_enhancement
        assert "registryInput.rows = Math.max" in form_enhancement
        assert ", 18)" in form_enhancement
        assert (
            '["expected_digest", "reload_current", "list_configurations"]'
            in form_enhancement
        )
        assert (
            'ccReplaceTokenConfigurationInput(form, "configuration_id", "manager")'
            in form_enhancement
        )
        assert "function ccApplyTokenRegistryActionResult" in form_enhancement
        assert 'form.elements.namedItem("expected_digest")' in form_enhancement
        assert "field.default = digest" in form_enhancement

        popout = _between(
            body,
            "  function _ccBuildActionPopout(action, initialValues)",
            "\n  // Compact workbench layout",
        )
        assert (
            "ccInitializeSaipTokenConfigurationForm("
            "action, form, runBtn, status, result"
        ) in popout

        action_run = _between(
            body,
            "  async function runActionFromForm(action, form, statusEl, resultEl)",
            "\n  function renderErrorBlock(message)",
        )
        assert "ccApplyTokenRegistryActionResult(action, form, resp.data || {})" in action_run


def test_named_token_configuration_selectors_are_live_and_synced() -> None:
    command_source = _command_center_source()
    _saip_source, served = _source_and_served_bodies()
    helper_start = "  var CC_SAIP_TOKEN_CONFIGURATION_MANAGER_TAG ="
    helper_end = "\n  function ccCompactHexText("
    source_helpers = _between(command_source, helper_start, helper_end)
    served_helpers = _between(served, helper_start, helper_end)
    assert source_helpers == served_helpers

    required_fragments = (
        '"saip-ribbon-tokens-form"',
        'ccActionHasInput(action, "token_configuration_id")',
        'select.dataset.saipTokenConfigurationRole = role',
        '"Loading token configurations…"',
        '"No token configurations available"',
        "Array.isArray(data.token_configurations)",
        "select.dataset.preferredConfiguration",
        'data-saip-token-configuration-role="manager"',
        'data-saip-token-configuration-role="generator"',
        "ccFindCatalogueActionByTag(",
        "encodeURIComponent(managerAction.id)",
        "body: JSON.stringify({ inputs: { list_configurations: true } })",
        'form.elements.namedItem("token_configuration_id")',
        'form.elements.namedItem("configuration_id")',
        'form.elements.namedItem("save_as_configuration_id")',
        'form.elements.namedItem("delete_configuration")',
        'form.elements.namedItem("list_configurations")',
        "ccReloadTokenConfigurationManager(",
        "ccInitializeTokenConfigurationGenerator(",
        "ccInitializeTokenConfigurationManager(",
        'listInput.checked = false',
        'form.dataset.saipTokenConfigurationResponseApplied = "false"',
        "runBtn.disabled = !loaded",
    )
    for fragment in required_fragments:
        assert fragment in source_helpers
    assert "plugin.saip_profile_generator.configure_token_definitions" not in (
        source_helpers
    )

    for body in (command_source, served):
        popout = _between(
            body,
            "  function _ccBuildActionPopout(action, initialValues)",
            "\n  // Compact workbench layout",
        )
        assert "ccInitializeSaipTokenConfigurationForm(" in popout

        card = _between(
            body,
            "  function buildActionCard(action)",
            "\n  function makeBadge(",
        )
        assert "ccInitializeSaipTokenConfigurationForm(" in card

        result_apply = _between(
            body,
            "  function ccApplyTokenRegistryActionResult(action, form, data)",
            "\n  function ccEnhanceAsn1TlvDecodeForm(form)",
        )
        assert "ccApplyTokenConfigurationCatalogue(data)" in result_apply
        assert 'form.elements.namedItem("save_as_configuration_id")' in result_apply
        assert '"delete_configuration"' in result_apply
        assert '"list_configurations"' in result_apply
        assert (
            'form.dataset.saipTokenConfigurationResponseApplied = "true"'
            in result_apply
        )

    reload_start = "  function ccReloadTokenConfigurationManager("
    reload_end = "\n  function ccInitializeTokenConfigurationManager("
    reload_block = _between(command_source, reload_start, reload_end)
    assert "reloadInput.checked = true" in reload_block
    assert "listInput.checked = false" in reload_block
    assert "listInput.checked = true" not in reload_block

    manager_start = "  function ccInitializeTokenConfigurationManager("
    manager_end = "\n  function ccInitializeSaipTokenConfigurationForm("
    manager_block = _between(command_source, manager_start, manager_end)
    catalogue_call = manager_block.index("await ccFetchTokenConfigurationCatalogue()")
    reload_call = manager_block.index("await ccReloadTokenConfigurationManager(")
    assert catalogue_call < reload_call


def test_form_contribution_activates_returned_saip_session() -> None:
    source = _command_center_source()
    served = _source_and_served_bodies()[1]
    for body in (source, served):
        assert 'actionTags.indexOf("saip-ribbon-package-form")' in body
        assert "returnedSessionId.length > 0" in body
        assert "saipActivateOpenedPackage(" in body


def test_active_session_form_contribution_is_safe_and_synced() -> None:
    saip_source, served = _source_and_served_bodies()
    helper_start = "  function saipActionAcceptsActiveSessionPrefill("
    helper_end = "\n  // Shared open pipeline."
    source_helper = _between(saip_source, helper_start, helper_end)
    served_helper = _between(served, helper_start, helper_end)
    assert source_helper == served_helper

    contribution_start = (
        '    var activeSessionActions = saipCatalogueActionsByTag('
    )
    contribution_end = "\n    // -- Element commands"
    source_contribution = _between(
        saip_source, contribution_start, contribution_end
    )
    served_contribution = _between(served, contribution_start, contribution_end)
    assert source_contribution == served_contribution

    for block in (source_helper, served_helper):
        assert 'field.name === "session_id"' in block
        assert "field.secret !== true" in block
        flush = block.index("await saipFlushPendingAutoApplies(pkg)")
        open_popout = block.index(
            "_ccBuildActionPopout(action, { session_id: pkg.sessionId })"
        )
        assert flush < open_popout
        assert "Object.keys(pkg.autoApplyJobs).length > 0" in block

    for block in (source_contribution, served_contribution):
        assert '"saip-ribbon-active-session-form"' in block
        assert 'var actionGrp = mkGroup("Actions")' in block
        assert "disabled: !hasLiveSession" in block
        assert "saipRibbonOpenActiveSessionContribution(action, pkg)" in block


def test_active_session_prefill_is_hidden_and_never_activates_result() -> None:
    command_source = _command_center_source()
    _saip_source, served = _source_and_served_bodies()
    for body in (command_source, served):
        prefill = _between(
            body,
            "  function ccApplyActionFormInitialValues(",
            "\n  // -- Action popout builder",
        )
        assert '"saip-ribbon-active-session-form"' in prefill
        assert 'field.name === "session_id"' in prefill
        assert "row.hidden = true" in prefill
        assert 'row.dataset.prefilledActiveSession = "true"' in prefill
        assert 'form.elements.namedItem("profile_path")' in prefill
        assert "alternatePath.disabled = true" in prefill
        assert "alternatePathRow.hidden = true" in prefill
        assert (
            'alternatePathRow.dataset.activeSessionAlternateSource = "true"'
            in prefill
        )

        action_run = _between(
            body,
            "  async function runActionFromForm(action, form, statusEl, resultEl)",
            "\n  function renderErrorBlock(message)",
        )
        package_tag = action_run.index(
            'actionTags.indexOf("saip-ribbon-package-form") !== -1'
        )
        active_session_exclusion = action_run.index(
            'actionTags.indexOf("saip-ribbon-active-session-form") === -1'
        )
        package_activation = action_run.index("saipActivateOpenedPackage(")
        assert package_tag < active_session_exclusion < package_activation

        # Active-session forms use the ordinary ActionField renderer, so
        # save_path fields retain the shared foreground-capable native picker.
        assert 'field.kind === "save_path"' in body
        assert "form.appendChild(buildField(action, field))" in body

    trailing_source = (
        _ROOT / "gui_frontend/src/js/trailing.js"
    ).read_text(encoding="utf-8")
    for body in (trailing_source, served):
        assert "return await pathPicker.saveFile(opts)" in body


def test_spreadsheet_open_guard_is_synced_and_precedes_normal_open() -> None:
    source, served = _source_and_served_bodies()
    helper_start = "  var SAIP_SPREADSHEET_SUFFIX_RE"
    helper_end = "\n  function saipDropOpenPath"
    assert _between(source, helper_start, helper_end) == _between(
        served,
        helper_start,
        helper_end,
    )

    for body in (source, served):
        helper = _between(body, helper_start, helper_end)
        assert "/\\.(?:xlsx|xlsm|xls|ods)$/i" in helper
        assert 'SAIP_WORKBOOK_GENERATOR_TAG = "saip-filesystem-workbook"' in helper
        assert "initialValues.workbook_path = safePrefill" in helper
        assert "YGGDRASIM_ALLOW_PLUGINS=1" in helper
        assert "YGGDRASIM_DISALLOW_PLUGINS" in helper
        assert "restart YggdraSIM" in helper

        path_open = _between(
            body,
            "  async function saipOpenPackageByPath(",
            "\n  async function saipOpenPackageByDroppedFile(",
        )
        assert path_open.index("saipRouteSpreadsheetToGenerator(clean, clean)") < path_open.index(
            'apiFetch("/api/actions/saip.open_package/run"'
        )

        dropped_open = _between(
            body,
            "  async function saipOpenPackageByDroppedFile(",
            "\n  // Ribbon Open:",
        )
        assert dropped_open.index("saipIsSpreadsheetInput") < dropped_open.index(
            "file.arrayBuffer()"
        )


def test_catalogue_refresh_and_safe_action_prefill_are_synced() -> None:
    command_source = _command_center_source()
    _saip_source, served = _source_and_served_bodies()
    prefill_start = "  function ccApplyActionFormInitialValues("
    prefill_end = "\n  // -- Action popout builder"
    assert _between(command_source, prefill_start, prefill_end) == _between(
        served,
        prefill_start,
        prefill_end,
    )

    for body in (command_source, served):
        prefill = _between(body, prefill_start, prefill_end)
        assert "field.secret" in prefill
        assert "form.elements.namedItem(field.name)" in prefill
        assert "Object.prototype.hasOwnProperty.call(initialValues, field.name)" in prefill
        assert "function _ccBuildActionPopout(action, initialValues)" in body
        assert "ccApplyActionFormInitialValues(action, form, initialValues)" in body

        catalogue_load = _between(
            body,
            "  async function loadCommandCatalogue()",
            "\n  // Left-nav tree",
        )
        assert "commandState.catalogue = data" in catalogue_load
        assert "saipRefreshCatalogueContributions()" in catalogue_load


def test_generated_session_lifecycle_is_present_in_source_and_served_bundle() -> None:
    source, served = _source_and_served_bodies()
    required_fragments = (
        "dirty: Boolean(resp.dirty)",
        "Array.isArray(resp.dirty_pe_indices)",
        "dirtySequenceWide: Boolean(resp.dirty_sequence_wide)",
        "saipRefreshDirty(record).then(function ()",
        'var hasSource = Boolean(pkg && String(pkg.sourcePath || "").trim())',
        "Save this in-memory profile as tagged JSON before reverting.",
        "Save this in-memory profile as tagged JSON before comparing with disk.",
        "Save this in-memory profile as tagged JSON before resetting overrides.",
        "data.source_path || data.output_path || outputPath",
        "data.encoding || fmt",
    )

    for body in (source, served):
        for fragment in required_fragments:
            assert fragment in body
