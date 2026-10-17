# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Variables panel: one row per placeholder with its value and source.

Pins the served bundle (the panel is edited in its rows, the ribbon carries
two entries, a tokenized field opens the panel on its variable) and the
listing's ``test_value_source`` the source badge reads.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

_BUNDLE = Path("yggdrasim_common/gui_server/static/app.js")
_SOURCE = Path("gui_frontend/src/js/saip-workbench.js")


def _function_source(js: str, marker: str, length: int = 9000) -> str:
    anchor = js.find(marker)
    assert anchor >= 0, marker
    return js[anchor: anchor + length]


@unittest.skipUnless(_BUNDLE.is_file(), "served bundle is required")
class VariablesPanelBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _BUNDLE.read_text(encoding="utf-8")

    def test_rows_carry_a_value_input_and_a_source_badge(self) -> None:
        row = _function_source(self.js, "function saipBuildVariableRow(")
        self.assertIn('input.className = "saip-form-input saip-vars-value-input"', row)
        self.assertIn('if (event.key !== "Enter") return;', row)
        self.assertIn("saipApplyVariable(pkg, variableName, input.value, drawer, peList, detail, validation, secret)", row)
        self.assertIn("saipVariableSourceBadge(v, hasOverride, sourceFlags)", row)
        self.assertIn('saipDraftKey("variables", "row", variableName)', row)
        self.assertIn('"Use list value"', row)
        badge = _function_source(self.js, "function saipVariableSourceBadge(")
        for text in ('"Typed"', '"Profile list"', '"Universal list"', '"List value"', '"Unset"', '"Catalog default"', '"Token"'):
            self.assertIn(text, badge)
        self.assertIn('origin === "bound"', badge)

    def test_panel_is_named_variables_and_folds_the_name_form(self) -> None:
        dock = _function_source(self.js, "function renderSaipTokenDock(")
        self.assertIn('title.textContent = "Variables";', dock)
        pane_start = self.js.find("function renderSaipVariablesPane(")
        pane = self.js[pane_start: self.js.find("function saipTokenExportBaseName(", pane_start)]
        self.assertIn('bindSummary.textContent = "Set a variable by name";', pane)
        self.assertIn('bindTitle.textContent = "Set a variable"', pane)
        self.assertIn("<th>Value</th>", pane)
        self.assertIn("<th>Source</th>", pane)
        self.assertIn("saipFocusVariableRow(host);", pane)
        self.assertIn('listMore.className = "saip-token-list-actions saip-token-list-actions--more"', pane)

    def test_ribbon_carries_variables_and_the_test_profile(self) -> None:
        ribbon = _function_source(self.js, 'var varsGrp = mkGroup("Tokens");', 4000)
        self.assertIn('label: "Variables"', ribbon)
        self.assertIn('label: "Generate test profile"', ribbon)
        self.assertNotIn('label: "Export complete profile"', ribbon)
        self.assertNotIn('label: "Test values"', ribbon)
        self.assertIn('if (action && action.id === "saip.universal_tokens") return;', ribbon)
        self.assertIn('{ encoding: "der", generate: true }', ribbon)
        # The button stays live while a variable is unset: the run reads the
        # lists again and the refusal names what is still open.
        self.assertIn("disabled: !inlineTemplate,", ribbon)
        self.assertIn("saipGenerateTestProfileTitle(unresolvedForExport)", ribbon)
        generate = _function_source(self.js, "async function saipGenerateTestProfile(")
        self.assertIn('"/api/actions/saip.generate_test_profile/run"', generate)
        self.assertIn('row.name + " = " + row.value + " (" + row.source + ")"', generate)
        self.assertIn("renderSaipTokenDock();", generate)
        save_flow = _function_source(self.js, "async function saipRibbonSavePackage(", 9000)
        self.assertIn("var generateRun = Boolean(preset && preset.generate)", save_flow)
        self.assertIn("saipGenerateTestProfile(pkg, outPath, encoding, drawer, peList, detail, validation);", save_flow)
        self.assertIn('"DER test profile -- every placeholder replaced by its value (*.der)"', save_flow)
        pane_start = self.js.find("function renderSaipVariablesPane(")
        pane = self.js[pane_start: self.js.find("function saipTokenExportBaseName(", pane_start)]
        self.assertIn('completeBtn.textContent = "Generate test profile\\u2026";', pane)
        self.assertIn('completeBtn.title = saipGenerateTestProfileTitle(unresolvedInline);', pane)
        self.assertNotIn("completeBtn.disabled", pane)
        self.assertIn('? "test profile ready"', pane)

    def test_legacy_pieces_hide_and_the_typed_spelling_button_shows(self) -> None:
        self.assertIn("function saipPackageHasLegacyTokens(", self.js)
        self.assertIn("function saipInlineNonTypedLiterals(", self.js)
        self.assertIn("function saipNormalisePlaceholderSpelling(", self.js)
        self.assertIn('"/api/actions/saip.normalise_placeholder_spelling/run"', self.js)
        pane_start = self.js.find("function renderSaipVariablesPane(")
        pane = self.js[pane_start: self.js.find("function saipTokenExportBaseName(", pane_start)]
        self.assertIn('spellingBtn.textContent = "Typed spelling";', pane)
        self.assertIn("if (saipPackageHasLegacyTokens(pkg)) listMore.appendChild(exportJsonBtn);", pane)
        dock = _function_source(self.js, "function renderSaipTokenDock(")
        self.assertIn("var styleChip = saipPackageHasLegacyTokens(pkg)", dock)

    def test_detail_pane_fetches_a_missing_pe_itself(self) -> None:
        # A mutation that empties the PE cache repaints before the PE is
        # back; the detail asks for it and repaints, so no mutation path
        # has to remember to reload.
        detail = _function_source(self.js, "function renderSaipDetail(", 12000)
        self.assertIn("detail.__saipPendingPe = wantedIndex;", detail)
        self.assertIn("saipLoadShowPe(pkg, wantedIndex).then(function () {", detail)
        loader = _function_source(self.js, "async function saipLoadShowPe(", 2200)
        self.assertIn("if (pkg.showPePending[peIndex]) return pkg.showPePending[peIndex];", loader)
        pane = _function_source(self.js, 'var leftTitle = top === "file_system" ? "Files" : "Profile elements";', 600)
        self.assertIn("(pkg.peCount || 0)", pane)

    def test_aid_directory_names_an_rfm_default_directory(self) -> None:
        tab = _function_source(self.js, "// ── Default directory (RFM) ──", 1600)
        self.assertIn('scopeLabel.textContent = "Default directory";', tab)
        self.assertIn('"MF -- UICC shared file system"', tab)

    def test_source_matches_the_bundle(self) -> None:
        source = _SOURCE.read_text(encoding="utf-8")
        for marker in ("function saipVariableSourceBadge(", "function saipRevealVariable(", "saip-vars-value-input"):
            self.assertIn(marker, source)


class VariablesListingSourceTests(unittest.TestCase):
    """``_collect_variables`` names the list a stored test value came from."""

    def _records(self):
        from Tools.ProfilePackage.saip_hex_template import substitute_inline_placeholders

        _text, records = substitute_inline_placeholders("AA{iccidICCID10}BB{imsi:IMSI:8:encode_imsi}CC")
        return records

    def test_test_value_source_names_universal_bound_or_stored(self) -> None:
        from Tools.ProfilePackage.saip_variable_materialization import inline_record_key
        from yggdrasim_common.gui_server.actions.saip import _collect_variables

        records = self._records()
        iccid_key = inline_record_key(records[0])
        imsi_key = inline_record_key(records[1])
        raw_values = {iccid_key: "8988201234567890123F", imsi_key: "0809101010000000"}
        with mock.patch.dict(os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": "/tmp/universal-for-test.csv"}):
            sources = {iccid_key: "/tmp/universal-for-test.csv", imsi_key: "/tmp/operator-a.csv"}
            payload = _collect_variables({}, records, {}, raw_values, raw_sources=sources)
            rows = {row["name"]: row for row in payload["variables"]}
            self.assertEqual(rows["iccid"]["test_value_source"], "universal")
            self.assertEqual(rows["imsi"]["test_value_source"], "bound")
            self.assertTrue(rows["iccid"]["universal"])
            unknown = _collect_variables({}, records, {}, raw_values)
            self.assertEqual({row["test_value_source"] for row in unknown["variables"]}, {"stored"})
            typed = _collect_variables({}, records, {"iccid": "8988201234567890123"}, raw_values, raw_sources=sources)
            iccid = {row["name"]: row for row in typed["variables"]}["iccid"]
            self.assertFalse(iccid["universal"])
            self.assertEqual(iccid["test_value_source"], "")


class TypedSpellingActionTests(unittest.TestCase):
    """``saip.normalise_placeholder_spelling`` respells the session's literals."""

    _REFERENCE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")

    def setUp(self) -> None:
        import tempfile

        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self._actions = saip_actions
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        reference = self._REFERENCE.read_text(encoding="utf-8")
        self._template = root / "compact.varder"
        self._template.write_text(
            reference.replace("89880811111111111112", "[iccidICCID10NibbleSwap]"), encoding="utf-8"
        )
        self._list = root / "universal.csv"
        self._list.write_text("iccidICCID10NibbleSwap,8988201234567890123F\n", encoding="utf-8")
        self._env = mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._list), "YGGDRASIM_RUNTIME_ROOT": str(root / "runtime")},
        )
        self._env.start()
        self._sids: list[str] = []

    def tearDown(self) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        for sid in self._sids:
            try:
                get_manager()._sessions.pop(sid, None)
            except Exception:
                pass
        self._env.stop()
        self._tmp.cleanup()

    @unittest.skipUnless(_REFERENCE.is_file(), "reference test profile fixture is required")
    def test_respelling_keeps_the_values_and_flags_nothing_afterwards(self) -> None:
        opened = self._actions._dispatch_open_package(ctx=None, path=str(self._template))
        sid = opened["session_id"]
        self._sids.append(sid)
        before = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        self.assertEqual(before["inline_template"]["non_typed_literals"], ["[iccidICCID10NibbleSwap]"])
        # The list that answered on open is named from the first listing.
        seeded = next(r for r in before["variables"] if r["name"].casefold() == "iccid")
        self.assertEqual(seeded["test_value_source"], "universal")
        result = self._actions._dispatch_normalise_placeholder_spelling(ctx=None, session_id=sid)
        self.assertEqual(result["changed"], 1)
        self.assertEqual(
            result["rewritten"],
            [{"from": "[iccidICCID10NibbleSwap]", "to": "{iccid:ICCID:10:nibble_swap}"}],
        )
        self.assertEqual(result["inline_template"]["non_typed_literals"], [])
        after = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        row = next(r for r in after["variables"] if r["name"].casefold() == "iccid")
        # The list value survived the respelling: the occurrence key is the same.
        self.assertEqual(row["value"], "8988201234567890123F")
        self.assertTrue(row["universal"])
        again = self._actions._dispatch_normalise_placeholder_spelling(ctx=None, session_id=sid)
        self.assertEqual(again["changed"], 0)

    def test_action_is_registered(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

        spec = ensure_builtin_actions_loaded().get("saip.normalise_placeholder_spelling")
        self.assertIsNotNone(spec)
        self.assertEqual({field.name for field in spec.inputs}, {"session_id"})
        self.assertNotIn("saip-ribbon-active-session-form", spec.tags)


if __name__ == "__main__":
    unittest.main()


class PlaceholderPickerBundleTests(unittest.TestCase):
    """A placeholder is declared where its bytes go, from the picker."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.js = _SOURCE.read_text(encoding="utf-8")

    def test_the_picker_offers_package_variables_the_list_and_a_new_one(self) -> None:
        picker = _function_source(self.js, "function saipOpenPlaceholderPicker(", 14000)
        self.assertIn('select.appendChild(new Option("New variable\\u2026", "__new__"));', picker)
        self.assertIn('" \\u00b7 this package \\u00b7 "', picker)
        self.assertIn('" \\u00b7 universal list \\u00b7 "', picker)
        # Every variable is offered; a narrower one lands at a byte offset,
        # only a wider one is greyed out.
        self.assertIn("var fits = saipPlaceholderFits(parts, want, mode);", picker)
        self.assertIn('offsetRow.appendChild(document.createTextNode("At byte offset "));', picker)
        self.assertIn('choice.mode = "offset";', picker)
        self.assertIn("if (pkg && pkg.sessionId && !pkg.variables) {", picker)
        self.assertIn("saipLoadAvailableTokens(pkg).then(function () {", picker)
        self.assertIn('["selection", "The selected bytes (" + selection.byteLength + " B)"]', picker)
        self.assertIn("the length byte that counts it cannot be reconciled", picker)
        self.assertIn('saveRow.appendChild(document.createTextNode(" Save to the universal list', picker)
        loader = _function_source(self.js, "async function saipLoadAvailableTokens(", 1200)
        self.assertIn('"/api/actions/saip.universal_tokens/run"', loader)

    def test_insert_variable_sits_on_the_json_tab_and_the_editors(self) -> None:
        json_tab = _function_source(self.js, "function saipFileRenderJson(", 7000)
        self.assertIn('applyJson.className = "btn btn-primary btn-small saip-json-apply";', json_tab)
        self.assertIn("saipInsertVariableButton(pkg, ta, { anchor: tools, applyRoot: card, caret: true })", json_tab)
        for editor in ("saipRenderEditorIccid", "saipRenderEditorImsi", "saipRenderEditorRawHex"):
            source = _function_source(self.js, "function " + editor + "(", 3000)
            self.assertIn("saipInsertVariableButton(pkg,", source, editor)
        iccid = _function_source(self.js, "function saipRenderEditorIccid(", 1600)
        self.assertIn("if (saipParsePlaceholderLiteral(iccid)) return { iccid: iccid };", iccid)
        insert = _function_source(self.js, "function saipPlaceholderTextInsert(", 1800)
        self.assertIn(
            'applyRoot.querySelector(".saip-decoded-apply-btn, .saip-json-apply, .saip-profile-header-apply")',
            insert,
        )
        header = _function_source(self.js, "function saipEditorRenderProfileHeader(", 9000)
        self.assertIn('saipParsePlaceholderLiteral(typed) ? "iccid_hex" : "iccid_digits"', header)
        self.assertIn("iccidBody.appendChild(saipInsertVariableButton(pkg, iccidInput, {", header)
        # EF.IMSI keeps its length byte in front of the eight-byte placeholder.
        self.assertIn("if (/^[0-9A-F]{18}$/.test(hex)) text = hex.slice(0, 2) + choice.literal;", insert)

    def test_every_apply_path_reports_the_placeholder_change(self) -> None:
        for fn, source in (
            ("async function saipApplyFileDecoded(", "saip.update_file_decoded"),
            ("async function saipApplyFileContent(", "saip.update_file_content"),
            ("async function saipApplyRecordEdit(", "saip.update_record_bytes"),
            ("async function saipApplyProfileHeaderScalar(", "saip.update_profile_header_field"),
            ("function saipMakeApplyBar(", "saip.apply_decoded_edit"),
        ):
            body = _function_source(self.js, fn, 6000)
            self.assertIn('saipNotePlaceholderEdit(pkg, ', body, fn)
            self.assertIn('"' + source + '"', body, fn)
        note = _function_source(self.js, "function saipNotePlaceholderEdit(", 1800)
        self.assertIn("saipInvalidateVariables(pkg);", note)
        self.assertIn("if (first && first.variable) saipRevealVariable(pkg, String(first.variable));", note)

    def test_the_tokenize_buttons_are_gone(self) -> None:
        self.assertNotIn("saipFormTokenizeButton", self.js)
        self.assertNotIn('"{T}"', self.js)
        css = Path("gui_frontend/src/css/views/saip/applications-tab-cards.css").read_text(encoding="utf-8")
        self.assertNotIn(".saip-form-tokenize", css)

    def test_panel_variables_drag_and_copy_their_literal(self) -> None:
        row = _function_source(self.js, "function saipBuildVariableRow(", 9000)
        self.assertIn('nameCode.className = "saip-vars-name";', row)
        self.assertIn("if (dragLiteral) saipMakePlaceholderChip(nameCode, dragLiteral);", row)
        chip = _function_source(self.js, "function saipMakePlaceholderChip(", 1800)
        self.assertIn('ev.dataTransfer.setData("text/plain", literal);', chip)
        self.assertIn("copyTextToClipboard(literal)", chip)
        literal = _function_source(self.js, "function saipVariableDragLiteral(", 1200)
        self.assertIn("if (literals.length) return String(literals[0]);", literal)
        section = _function_source(self.js, "function saipBuildUniversalListSection(", 3200)
        self.assertIn('title.textContent = "Universal list";', section)
        self.assertIn("tbody.appendChild(saipBuildUniversalListRow(parts, literal, entry));", section)
        row = _function_source(self.js, "function saipBuildUniversalListRow(", 3600)
        self.assertIn("saipMakePlaceholderChip(nameCode, literal);", row)
        self.assertIn('input.value = declaredOnly ? "" : String(entry.hex || "");', row)
        self.assertIn('>Universal list</span>', row)
        self.assertIn("listCol.appendChild(saipBuildUniversalListSection(pkg, vars));", self.js)

    def test_a_dropped_or_pasted_literal_overwrites_the_bytes_it_stands_for(self) -> None:
        self.assertIn('var _SAIP_PLACEHOLDER_TARGETS = "input.saip-form-hex, textarea.saip-form-hex, textarea.saip-rawbytes-input, "', self.js)
        installer = _function_source(self.js, "(function installPlaceholderOverwrite() {", 2200)
        self.assertIn('document.addEventListener("beforeinput", function (ev) {', installer)
        self.assertIn("saipSpliceLiteral(el, literal, prefix, prefix, true);", installer)
        target = _function_source(self.js, "function saipPlaceholderDropTarget(", 500)
        self.assertIn('(type === "insertFromDrop" || type === "insertFromPaste")', target)
        splice = _function_source(self.js, "function saipSpliceLiteral(", 1400)
        self.assertIn("if (parts) after = after.slice(saipHexSpanEnd(after, parts.byteLength * 2));", splice)
        insert = _function_source(self.js, "function saipPlaceholderTextInsert(", 2000)
        self.assertIn('} else if (mode === "caret") {', insert)
        self.assertIn('} else if (mode === "offset") {', insert)

    def test_the_dialing_number_box_takes_a_placeholder_and_a_chip_is_never_a_file(self) -> None:
        self.assertIn('dn.digits = saipParsePlaceholderLiteral(typed) ? typed : typed.replace(/\\D+/g, "");', self.js)
        self.assertIn('className: "saip-connectivity-digits"', self.js)
        self.assertIn('input.saip-connectivity-digits";', self.js)
        installer = _function_source(self.js, "(function installPlaceholderOverwrite() {", 2600)
        self.assertIn('if (el.classList.contains("saip-connectivity-digits")) {', installer)
        chip = _function_source(self.js, "function saipMakePlaceholderChip(", 1800)
        self.assertIn('ev.dataTransfer.setData("application/x-ygg-placeholder", literal);', chip)
        wiring = _function_source(self.js, "function wireSaipWorkbenchDrop(", 4000)
        self.assertIn('if (t === "application/x-ygg-placeholder") return false;', wiring)
        self.assertIn("if (!dragHasFile(event)) return;\n      // Skip the workbench-wide handling", wiring)

    def test_hex_inputs_keep_a_literal_and_count_its_bytes(self) -> None:
        clean = _function_source(self.js, "function saipConnectivityCleanHex(", 200)
        self.assertIn("return saipFormHexNorm(value);", clean)
        header_hex = _function_source(self.js, "function saipHeaderBytesHex(", 700)
        self.assertIn("if (direct) return saipFormHexNorm(direct);", header_hex)
        pretty = _function_source(self.js, "function saipFormatHexPretty(", 300)
        self.assertIn('return saipTokenizeHexWithPlaceholders(String(hex)).join(" ");', pretty)
        norm = _function_source(self.js, "function saipFormHexNorm(", 700)
        self.assertIn("new RegExp(_SAIP_INLINE_PLACEHOLDER_SOURCE, \"g\")", norm)
        hex_input = _function_source(self.js, "function saipFormHexInput(", 1400)
        self.assertIn("var count = saipPlaceholderAwareByteCount(clean);", hex_input)
        literal = _function_source(self.js, "function saipBuildPlaceholderLiteral(", 500)
        self.assertIn("saipTypedModifierSpelling(modifier, type)", literal)

    def test_the_panel_defines_a_variable_and_flags_a_length_counted_unset_row(self) -> None:
        card = _function_source(self.js, "function saipBuildDefineVariableCard(", 7000)
        self.assertIn('summary.textContent = "Define a variable";', card)
        self.assertIn('"/api/actions/saip.define_variable/run"', card)
        self.assertIn("placeholder_type: typeSel.value,", card)
        pane = _function_source(self.js, "function renderSaipVariablesPane(", 4000)
        self.assertIn("formCol.appendChild(saipBuildDefineVariableCard(pkg, drawer, peList, detail, validation));", pane)
        row = _function_source(self.js, "function saipBuildVariableRow(", 9000)
        self.assertIn('lengthFlag.textContent = "No value: the length byte that counts it cannot be reconciled.";', row)
        css = Path("gui_frontend/src/css/views/saip/placeholder-picker.css").read_text(encoding="utf-8")
        self.assertIn(".saip-ph-picker {", css)
        self.assertIn("views/saip/placeholder-picker.css", Path("gui_frontend/src/css/.css_order").read_text(encoding="utf-8"))
