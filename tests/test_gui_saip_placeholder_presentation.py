# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Placeholder presentation contracts against the built SAIP bundle.

Every placeholder in a field or a file shows the same binding row: the
literal chip verbatim, the width the literal declares, the value that
will replace it (typed, universal, or an honest "unresolved") and an Edit
action. The old row derived a byte count from the text of its own
"unresolved" message and shortened literals to sixteen characters.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def _function_source(js: str, signature: str) -> str:
    start = js.index(signature)
    match = re.search(r"\n  (?:async )?function ", js[start + len(signature):])
    end = len(js) if match is None else start + len(signature) + match.start()
    return js[start:end]


def _rule(css: str, selector: str) -> str:
    match = re.search(r"(?:^|\n)" + re.escape(selector) + r"[^{]*\{([^}]*)\}", css)
    assert match is not None, selector
    return match.group(1)


def test_binding_row_helpers_ship() -> None:
    js = _read("app.js")
    for helper in (
        "function saipParsePlaceholderLiteral(",
        "function saipPlaceholderResolution(",
        "function saipFormTokenChipRow(",
        "function saipRenderPlaceholderBindingRow(",
        "async function saipApplyUniversalTokens(",
    ):
        assert helper in js, helper


def test_literal_parser_matches_the_python_grammar() -> None:
    js = _read("app.js")
    window = js[js.index("var _SAIP_PLACEHOLDER_TYPES") : js.index("function saipPlaceholderResolution(")]
    assert '"ICCID|IMSI|MSISDN|BINARY|TEXT|RI|OPLMN"' in window
    assert "parts.key = parts.variable + parts.type + String(parts.byteLength) + parts.modifier;" in window


def test_binding_row_reports_declared_width_not_the_message_length() -> None:
    js = _read("app.js")
    row = _function_source(js, "function saipFormTokenChipRow(")
    assert '"(unresolved -- no stored value or token definition)"' in row
    assert 'state.byteLength + " B declared"' in row
    assert "chipLiteral: true" in row
    # The unresolved message is plain text: no byte chip is computed from it.
    assert 'kind: encoding === "hex" ? "hex_bytes" : "auto"' not in row
    assert '"(unresolved -- no token definition)"' not in js


def test_every_literal_shape_gets_the_binding_row() -> None:
    js = _read("app.js")
    info = _function_source(js, "function saipFormPlaceholderInfo(")
    assert '"^(?:" + _SAIP_INLINE_PLACEHOLDER_SOURCE + ")$"' in info
    assert 'shape: text.charAt(0) === "[" ? "bracket" : "brace"' in info


def test_resolution_prefers_the_variable_behind_an_inline_literal() -> None:
    js = _read("app.js")
    resolver = _function_source(js, "function saipPlaceholderResolution(")
    assert "var candidates = parts ? [parts.variable, name] : [name];" in resolver
    assert 'out.source = row.universal === true ? "universal" : (flags.inline ? "typed" : "token");' in resolver


def test_entry_chips_never_shorten_a_placeholder_literal() -> None:
    js = _read("app.js")
    chip = _function_source(js, "function saipFormShortItemChip(")
    literal_check = chip.index("saipInlinePlaceholderLiteral(candidate) === candidate.trim()")
    fallback = chip.index("String(firstVal).slice(0, 16)")
    assert literal_check < fallback
    section = _function_source(js, "function saipFormSection(")
    assert 'chip.classList.add("saip-form-section-chip--literal")' in section
    readonly = _function_source(js, "function saipFormReadOnlyRow(")
    assert 'if (opts.chipLiteral) lock.classList.add("saip-form-lock-chip--literal");' in readonly


def test_files_show_binding_rows_above_the_hex_editor() -> None:
    js = _read("app.js")
    card = _function_source(js, "function saipBuildRawBytesCard(")
    assert "bindings.appendChild(saipRenderPlaceholderBindingRow(opts.pkg, entry));" in card
    # The file view hands the card its placeholders merged with the length
    # bytes that follow a stored value.
    assert "placeholders: filePlaceholders," in js
    assert "filePlaceholders = filePlaceholders.concat(data.inline_length_fields);" in js
    binding = _function_source(js, "function saipRenderPlaceholderBindingRow(")
    assert '"Template placeholder"' in binding
    assert 'declared + " B declared"' in binding
    # The value is edited in place, below the hex field, never in a prompt.
    assert "window.prompt(" not in binding
    assert "saipPromptSetVariable" not in js
    assert "card.appendChild(saipBuildPlaceholderValueEditor(opts.pkg, entry, refreshFile));" in card
    editor = _function_source(js, "function saipBuildPlaceholderValueEditor(")
    assert "window.prompt(" not in editor
    assert 'input.className = "saip-rawbytes-input saip-placeholder-value-input";' in editor
    assert 'applyBtn.textContent = "Apply value";' in editor
    assert "saipSetVariableValue(pkg, name, value)" in editor
    assert 'if (typeof refresh === "function") refresh();' in editor
    # Applying a value re-fetches the file so the hex pane follows, in the
    # FS-tree file detail and in a PE's template-file panel alike.
    assert "saipRedrawFileSurfaces(opts.pkg, opts.sectionKey, opts.fieldPath, opts.peList, opts.validation);" in card
    assert "pkg.templateFileRedraw[sectionKey] = function (fieldPath) {" in js
    surfaces = _function_source(js, "function saipRedrawFileSurfaces(")
    assert "saipRedrawFileDetail(pkg, sectionKey, fieldPath, peList, validation);" in surfaces
    assert 'if (typeof hook === "function") hook(String(fieldPath || ""));' in surfaces


def test_legend_and_token_editor_name_the_universal_source() -> None:
    js = _read("app.js")
    legend = _function_source(js, "function saipRenderInlinePlaceholderLegend(")
    assert 'var universal = entry.source === "universal";' in legend
    assert "saip-vars-state-chip is-universal" in js
    assert "saip-token-apply-universal" in js
    assert '"/api/actions/saip.apply_universal_tokens/run"' in js
    # The ribbon carries the Variables panel and the generated test
    # profile; the list actions live in the panel.
    assert 'label: "Variables"' in js
    assert 'label: "Generate test profile"' in js
    assert 'label: "Export complete profile"' not in js
    assert 'label: "Test values"' not in js


def test_css_keeps_literals_verbatim_and_styles_the_new_chips() -> None:
    css = _read("app.css")
    literal = _rule(css, ".saip-form-section-chip--literal")
    assert "text-transform: none" in literal
    assert "font-family: var(--mono)" in literal
    assert ".saip-form-lock-chip--literal" in css
    assert "background: var(--accent-soft)" in _rule(css, ".saip-vars-state-chip.is-universal")
    assert "flex-direction: column" in _rule(css, ".saip-file-placeholder-bindings")


def test_binding_row_falls_back_to_the_active_package() -> None:
    """A read-only decoded form has no package in its context; the row
    still resolves through the active package and keeps its Edit button."""
    js = _read("app.js")
    row = _function_source(js, "function saipFormTokenChipRow(")
    assert 'typeof saipActivePackage === "function" ? saipActivePackage() : null' in row
    assert "if (opts.allowEdit !== false && pkg && pkg.sessionId) {" in row
    assert "rowObj.row.appendChild(saipBuildPlaceholderValueEditor(pkg, {" in row


def test_profile_header_iccid_placeholder_gets_the_binding_row() -> None:
    js = _read("app.js")
    assert "function saipRenderPlaceholderBindingRowFromLiteral(" in js
    assert "card.appendChild(saipRenderPlaceholderBindingRowFromLiteral(pkg, iccidPlaceholder));" in js
    header = _function_source(js, "function saipEditorRenderProfileHeader(")
    assert "card.appendChild(saipBuildPlaceholderValueEditor(pkg, {" in header
    assert "void saipRefreshPeDetailAfterMutation(pkg, 0, sectionKey, peList, validation);" in header


def test_the_secrecy_class_marks_a_row_without_masking_its_value() -> None:
    """PIN, PUK, ADM and key names keep their classification; whoever holds
    the profile sees the value, typed or universal."""
    js = _read("app.js")
    row = _function_source(js, "function saipBuildVariableRow(")
    assert "var secret = saipVariableIsSecret(v);" in row
    resolver = _function_source(js, "function saipPlaceholderResolution(")
    assert "out.secret = saipVariableIsSecret(row);" in resolver


def test_a_literal_inside_a_longer_value_still_binds() -> None:
    js = _read("app.js")
    info = _function_source(js, "function saipFormPlaceholderInfo(")
    assert "var embedded = saipInlinePlaceholderLiteral(text);" in info
    assert "prefixHex:" in info and "suffixHex:" in info
    row = _function_source(js, "function saipFormTokenChipRow(")
    assert '" Followed by " + saipFormatHexPretty(opts.suffixHex)' in row


def test_pin_and_puk_cards_keep_the_literal_whole() -> None:
    js = _read("app.js")
    card = _function_source(js, "function saipEditorRenderPinPukCard(")
    assert "var literalInValue = saipInlinePlaceholderLiteral(hex);" in card
    assert "saipRenderPlaceholderBindingRowFromLiteral(bindingPkg, literalInValue)" in card
    assert "saipTokenizeHexWithPlaceholders(hex).join(\" \")" in card
    assert "var vLen = saipPlaceholderAwareByteCount(vHex);" in card
    assert "function saipPlaceholderAwareByteCount(" in js


def test_hex_pane_shows_the_placeholder_value_and_keeps_the_marker() -> None:
    js = _read("app.js")
    card = _function_source(js, "function saipBuildRawBytesCard(")
    shown = _function_source(js, "function saipPlaceholderShownImage(")
    assert 'var valueHex = String(entry.value_hex || "")' in shown
    assert "textPieces.push(fits ? valueHex : String(entry.literal || \"\"));" in shown
    assert "hexPieces.push(fits ? valueHex : clean.slice(startNibble, endNibble));" in shown
    assert "var shown = saipPlaceholderShownImage(imageHex, placeholderRanges);" in card
    assert "saip-rawbytes-placeholder-flag" in card
    assert 'ta.classList.add("is-placeholder-bearing")' in card
    assert "saipRestorePlaceholderSentinels(ta.value, imageHex, placeholderRanges)" in card
    restore = _function_source(js, "function saipRestorePlaceholderSentinels(")
    assert "out = out.slice(0, startNibble) + imageHex.slice(startNibble, endNibble) + out.slice(endNibble);" in restore
    assert "keep its " in restore
    css = _read("app.css")
    assert "border-color" in _rule(css, ".saip-rawbytes-input.is-placeholder-bearing")
    assert "color: var(--accent)" in _rule(css, ".saip-rawbytes-placeholder-flag")


def test_pin_and_puk_panels_keep_the_placeholder_model() -> None:
    """The PIN/PUK direct editor drops read-only JSON models; a placeholder
    model is the only view its field has and must stay, outside the JSON
    toggle."""
    js = _read("app.js")
    assert "function saipDecodedIsPlaceholderModel(" in js
    helper = _function_source(js, "function saipDecodedIsPlaceholderModel(")
    assert "Array.isArray(payload.placeholders)" in helper
    start = js.index("function keepDirectDecodedField(f) {")
    keep = js[start : js.index("function _isJsonFallback(f) {", start)]
    assert "if (saipDecodedIsPlaceholderModel(f)) return true;" in keep
    fallback_start = js.index("function _isJsonFallback(f) {")
    fallback = js[fallback_start : fallback_start + 400]
    assert "if (saipDecodedIsPlaceholderModel(f)) return false;" in fallback


def test_generic_file_management_data_tab_merges_the_server_file_view() -> None:
    """The GFM card renders bytes from client-side ops; in a template
    session the server locates the placeholders, so the tab merges the
    file view's image and ranges first."""
    js = _read("app.js")
    start = js.index("var gfmData = {")
    window = js[start : start + 1400]
    assert "saipInlineTemplateActive(pkg) && pkg.sessionId && v.fieldPath" in window
    assert "saipLoadShowFile(pkg, sectionKey, v.fieldPath).then(renderDetail);" in window
    assert '"body_hex", "body_size", "body_record_size", "body_record_count",' in window
    assert '"body_declared_size", "inline_placeholders", "decoded",' in window


def test_placeholder_fields_get_the_compact_editor() -> None:
    """One bytes row, the export bytes when known, one binding row per
    placeholder; the raw placeholders / segments model folds away."""
    js = _read("app.js")
    dispatch = _function_source(js, "function saipRenderDecodedEditor(")
    assert "} else if (saipDecodedIsPlaceholderModel(field)) {" in dispatch
    assert "saipRenderEditorPlaceholder(form, pkg, sectionKey, field, peList, validation);" in dispatch
    editor = _function_source(js, "function saipRenderEditorPlaceholder(")
    assert 'saipMakeLabeledInput(grid, "Bytes (template)", bytesInput);' in editor
    assert '"Bytes on export (" + (resolvedHex.length / 2) + " B)"' in editor
    assert "saipRenderPlaceholderBindingRowFromLiteral(pkg, literal)" in editor
    assert 'summary.textContent = "Show JSON";' in editor
    resolver = _function_source(js, "function saipResolvedPlaceholderHex(")
    assert "valueHex.length !== parts.byteLength * 2" in resolver
    css = _read("app.css")
    assert "font-family: var(--mono)" in _rule(css, ".saip-placeholder-bytes-input")


def test_nothing_in_the_workbench_masks_a_value() -> None:
    js = _read("app.js")
    assert "••••••••" not in js
    assert "(secret value stored -- hidden)" not in js
    resolver = _function_source(js, "function saipPlaceholderResolution(")
    assert 'out.value = String(row.value || "");' in resolver
    row = _function_source(js, "function saipBuildVariableRow(")
    # The row's input carries the stored value in full; a secret name only
    # marks the row.
    assert 'var storedText = String(visibleValue == null ? "" : visibleValue);' in row
    assert 'input.value = draft && typeof draft.value === "string" ? draft.value : storedText;' in row
    assert ">Sensitive</span>" in row


def test_binding_rows_built_from_a_literal_carry_the_value() -> None:
    js = _read("app.js")
    helper = _function_source(js, "function saipRenderPlaceholderBindingRowFromLiteral(")
    assert 'stored_value: state.value || "",' in helper
    assert 'state.secret ? ""' not in helper


def test_compact_editor_loads_the_variable_listing_it_resolves_through() -> None:
    js = _read("app.js")
    editor = _function_source(js, "function saipRenderEditorPlaceholder(")
    assert "saipLoadVariables(pkg).then(function () {" in editor
    assert "saipRenderEditorPlaceholder(form, pkg, sectionKey, field, peList, validation);" in editor


def test_wizards_are_seeded_with_the_resolved_image_and_write_through_placeholders() -> None:
    """A whole-file wizard sees the bytes the hex pane shows, not the
    sentinels, and a placeholder range it changes becomes that
    placeholder's value instead of literal file bytes."""
    js = _read("app.js")
    assert "? saipPlaceholderShownImage(efImageHex, wizardPlaceholders).hex" in js
    host = _function_source(js, "function saipRenderEfWizardCard(")
    assert "return saipApplyWizardHexOverPlaceholders(opts, ranges, newHex);" in host
    bridge = _function_source(js, "async function saipApplyWizardHexOverPlaceholders(")
    assert "var stored = await saipSetVariableValue(opts.pkg, name, after);" in bridge
    assert 'if (form.label !== "hex bytes") {' in bridge
    assert "+ imageHex.slice(startNibble, endNibble)" in bridge
