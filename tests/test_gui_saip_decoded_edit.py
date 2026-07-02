# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the SAIP decoded-edit dispatchers and the
frontend wiring that renders the per-kind mini-forms.

The Command Center used to expose only ``saip.update_file_field``
which required the operator to hand-type raw TLV hex for every
mutation. The new ``saip.list_decoded_fields`` and
``saip.apply_decoded_edit`` dispatchers bridge
``Tools.ProfilePackage.saip_decoded_edit`` so fields such as LCSI
states, file IDs, byte counts and service tables are editable via
type-aware forms.

Tests here drive the backend dispatchers end-to-end against a real
reference profile to guarantee:

1. Listing decoded fields for a populated section returns a non-empty
   collection projected into the JSON-safe wire shape.
2. Applying a decoded edit mutates the cached decoded document and
   marks the owning PE dirty so Save picks it up.
3. The tagged-path splicer refuses to create missing nodes (any such
   call means the editor model is out of date).
4. The frontend bundle ships the expected decoded-edit plumbing —
   we keep a light assertion on the public JS symbols so missing
   wiring fails CI instead of silently landing a broken GUI.
"""

from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any


_REFERENCE_PROFILE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")


class DecodedEditSplicerTests(unittest.TestCase):
    """Unit tests for the tagged-path splicer helper."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )

    def test_splice_replaces_dict_value(self) -> None:
        doc = {"ef-imsi": [{"@": ["bytes", {"hex": "00"}]}]}
        self.saip._splice_tagged_value_at_rel_path(
            doc,
            ["ef-imsi", 0, "@", 1],
            {"hex": "AA"},
        )
        self.assertEqual(doc["ef-imsi"][0]["@"][1], {"hex": "AA"})

    def test_splice_rejects_empty_path(self) -> None:
        doc = {"x": 1}
        with self.assertRaises(ValueError):
            self.saip._splice_tagged_value_at_rel_path(doc, [], 99)

    def test_splice_rejects_missing_key(self) -> None:
        doc = {"x": {"y": 1}}
        with self.assertRaises(ValueError):
            self.saip._splice_tagged_value_at_rel_path(doc, ["x", "z"], 99)

    def test_splice_rejects_out_of_range(self) -> None:
        doc = {"x": [1, 2]}
        with self.assertRaises(ValueError):
            self.saip._splice_tagged_value_at_rel_path(doc, ["x", 5], 99)

    def test_splice_rejects_type_mismatch(self) -> None:
        doc = {"x": {"y": 1}}
        with self.assertRaises(ValueError):
            self.saip._splice_tagged_value_at_rel_path(doc, ["x", 0], 99)


class DecodedEditProjectionTests(unittest.TestCase):
    """Unit tests for the wire-shape projector."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )

    def test_projector_emits_jsonable_shape(self) -> None:
        entry = {
            "field_name": "lcsi",
            "rel_path": ["adf-usim", 0, "@", 1, "lcsi"],
            "last_ef_key": None,
            "pe_section_key": "usim",
            "display_path": "adf-usim / [0] / lcsi",
            "summary": "lcsi_state · state=operational_activated",
            "editor_kind": "lcsi_state",
            "target_length": None,
            "read_only": False,
            "model": {
                "title": "Decoded editor: Life Cycle Status Integer",
                "note": "Supported states: …",
                "editor_kind": "lcsi_state",
                "payload": {"state": "operational_activated"},
                "target_length": None,
                "read_only": False,
            },
        }
        projected = self.saip._project_decoded_field_entry(entry)
        self.assertEqual(projected["field_name"], "lcsi")
        self.assertEqual(projected["editor_kind"], "lcsi_state")
        self.assertEqual(projected["rel_path"], ["adf-usim", 0, "@", 1, "lcsi"])
        self.assertEqual(
            projected["model"]["payload"],
            {"state": "operational_activated"},
        )
        self.assertIs(projected["read_only"], False)

    def test_projector_defaults_editor_kind_to_json(self) -> None:
        projected = self.saip._project_decoded_field_entry(
            {
                "field_name": "x",
                "rel_path": ["x"],
                "model": {"payload": {"y": 1}},
            }
        )
        self.assertEqual(projected["editor_kind"], "json")

    def test_projector_preserves_gfm_file_path(self) -> None:
        projected = self.saip._project_decoded_field_entry(
            {
                "field_name": "fillFileContent",
                "rel_path": ["fileManagementCMD", 0, 2, "@", 1],
                "gfm_file_path": "fileManagementCMD[0][1]",
                "model": {"payload": {"imsi": "001010000000001"}},
            }
        )
        self.assertEqual(projected["gfm_file_path"], "fileManagementCMD[0][1]")

    def test_gfm_synthetic_path_mutates_live_create_fcp(self) -> None:
        class _Pe:
            type = "genericFileManagement"

            def __init__(self) -> None:
                self.decoded = {
                    "fileManagementCMD": [
                        [
                            ("filePath", b"\x7F\x10"),
                            (
                                "createFCP",
                                {
                                    "fileID": b"\x6F\x40",
                                    "fileDescriptor": b"\x41\x21",
                                },
                            ),
                        ],
                    ],
                }

        pe = _Pe()
        choice_list = self.saip._mutable_file_choice_list_for_path(
            pe,
            "fileManagementCMD[0][1]",
        )
        self.assertIs(choice_list, pe.decoded["fileManagementCMD"][0])
        applied = self.saip._apply_hex_mutation(
            choice_list,
            "fileID",
            bytes.fromhex("6F42"),
        )
        self.assertTrue(applied)
        self.assertEqual(
            pe.decoded["fileManagementCMD"][0][1][1]["fileID"],
            bytes.fromhex("6F42"),
        )


@unittest.skipUnless(
    _REFERENCE_PROFILE.exists(),
    "reference profile sample missing — skipping end-to-end test",
)
class DecodedEditEndToEndTests(unittest.TestCase):
    """Drive the dispatchers against the reference profile."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module(
            "yggdrasim_common.gui_server.sessions"
        )

        # The reference profile ships as a text-armored blob that
        # pySim's strict loader does not unwrap directly. Go through
        # ``SaipToolBridge._prepare_input_for_tool`` to normalise it
        # into raw DER, then feed that to ``saip.open_package`` so the
        # session carries the semantic ``sections`` keys (``header``,
        # ``usim``, ``telecom``) we actually want to edit here.
        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        ws = Path(".").resolve()
        bridge = SaipToolBridge(ws)
        src = bridge.resolve_input_path(
            str(_REFERENCE_PROFILE),
            must_exist=True,
        )
        raw = bridge._prepare_input_for_tool(src).read_bytes()
        tmp = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        tmp.write(raw)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        open_resp = self.saip._dispatch_open_package(
            self.ctx,
            path=tmp.name,
        )
        self.session_id = open_resp["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)

    def _pick_usim_section(self) -> str:
        sections = self.handle["decoded_document"].get("sections") or {}
        for key, value in sections.items():
            if isinstance(value, dict) and "ef-imsi" in value:
                return key
        self.fail("reference profile missing a USIM-style section with ef-imsi")

    def test_list_decoded_fields_surfaces_lcsi_editor(self) -> None:
        section = self._pick_usim_section()
        resp = self.saip._dispatch_list_decoded_fields(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )
        self.assertGreater(resp["field_count"], 0)
        lcsi = [f for f in resp["fields"] if f["editor_kind"] == "lcsi_state"]
        self.assertGreater(len(lcsi), 0, "reference profile should expose at least one LCSI state")
        # Every entry must be wire-serialisable.
        import json
        json.dumps(resp)

    def test_apply_decoded_edit_roundtrips_lcsi_state(self) -> None:
        section = self._pick_usim_section()
        listed = self.saip._dispatch_list_decoded_fields(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )
        target = None
        for field in listed["fields"]:
            if field["editor_kind"] != "lcsi_state":
                continue
            if field["model"]["payload"].get("state") == "operational_activated":
                target = field
                break
        if target is None:
            self.skipTest("reference profile has no operational_activated LCSI entry")

        apply_resp = self.saip._dispatch_apply_decoded_edit(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            rel_path=target["rel_path"],
            field_name=target["field_name"],
            last_ef_key=target.get("last_ef_key"),
            editor_kind=target["editor_kind"],
            editor_payload={"state": "operational_deactivated"},
        )
        self.assertGreaterEqual(apply_resp["dirty_pe_count"], 1)
        self.assertIsInstance(apply_resp.get("pe_index"), int)

        refreshed = self.saip._dispatch_list_decoded_fields(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )
        match = None
        for field in refreshed["fields"]:
            if field["rel_path"] == target["rel_path"]:
                match = field
                break
        self.assertIsNotNone(match, "LCSI field should still be enumerable after edit")
        self.assertEqual(
            match["model"]["payload"].get("state"),
            "operational_deactivated",
        )


class DecodedEditBundleWiringTests(unittest.TestCase):
    """Light assertions that the frontend bundle still ships the
    decoded-edit plumbing. Prevents silent drift between the backend
    dispatchers and the GUI they feed.
    """

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_frontend_exposes_decoded_edit_helpers(self) -> None:
        for symbol in (
            "saipRenderDecodedEditPanel",
            "saipLoadDecodedFields",
            "saipBuildDecodedFieldRow",
            "saipRenderEditorLcsi",
            "saipRenderEditorFileId",
            "saipRenderEditorByteCount",
            "saipRenderEditorServiceTable",
            "saipRenderEditorImsi",
            "saipRenderEditorIccid",
            "saipRenderEditorRawHex",
            "saipRenderEditorJsonFallback",
            "saipFilterFileDataPayloadForGeneralPanel",
            "saipLinearRecordLayout",
            "saipDecodedFieldTitle",
            "saipDecodedKindLabel",
            "saipPrettySaipFieldKey",
            "saipPrettyArrayRowLabel",
            "saipHumanizePathText",
            "saipStructureUiLabel",
            "saipRenderFileDataPayloadPanel",
        ):
            self.assertIn(symbol, self.app_js, f"missing JS symbol: {symbol}")

    def test_frontend_calls_both_backend_actions(self) -> None:
        self.assertIn("saip.list_decoded_fields/run", self.app_js)
        self.assertIn("saip.apply_decoded_edit/run", self.app_js)

    def test_decoded_edit_auto_apply_is_session_only(self) -> None:
        for token in (
            "autoApplyJobs: {}",
            "saipDecodedInstallAutoApply",
            "saipDecodedQueuePayload",
            "Pending auto-apply",
            "Auto-applying",
            "saipFlushPendingAutoApplies",
        ):
            self.assertIn(token, self.app_js)

        start = self.app_js.index("async function saipDecodedApplyPayload")
        end = self.app_js.index("async function saipDecodedDrainJob")
        segment = self.app_js[start:end]
        self.assertIn("saip.apply_decoded_edit/run", segment)
        self.assertNotIn("saip.save_package", segment)
        self.assertNotIn("saip.save_package/run", segment)

    def test_save_flushes_pending_decoded_auto_applies(self) -> None:
        ribbon_start = self.app_js.index("async function saipRibbonSavePackage")
        ribbon_end = self.app_js.index("var encoding =", ribbon_start)
        self.assertIn("await saipFlushPendingAutoApplies(pkg)", self.app_js[ribbon_start:ribbon_end])

        save_start = self.app_js.index("async function saipSavePackage")
        save_end = self.app_js.index("pkg.saveStatus = \"Saving", save_start)
        self.assertIn("await saipFlushPendingAutoApplies(pkg)", self.app_js[save_start:save_end])

    def test_discard_paths_cancel_pending_decoded_auto_applies(self) -> None:
        for symbol in (
            "async function saipRevertPackage",
            "async function saipClosePackage",
        ):
            start = self.app_js.index(symbol)
            self.assertIn(
                "saipCancelPendingAutoApplies(pkg)",
                self.app_js[start:start + 500],
            )

    def test_file_detail_general_panel_labels_file_data(self) -> None:
        # The legacy "File data" payload table was retired when the
        # detail view split into File Control Parameters / Data / JSON
        # tabs. The General tab hosts the FCP-metadata editor; the
        # Data tab folds both the hexadecimal view and the interpreted
        # view (ePC §"File Content") so the decoded-field editors
        # surface alongside the byte image.
        self.assertIn("FCP metadata (editable)", self.app_js)
        self.assertIn('fn === "filedescriptor"', self.app_js)
        self.assertIn("fillFileContents", self.app_js)
        self.assertIn("function saipBuildRawBytesCard(", self.app_js)
        self.assertIn("Raw bytes", self.app_js)
        self.assertIn('"File Control Parameters"', self.app_js)
        self.assertIn('"Data"', self.app_js)
        self.assertIn('"JSON"', self.app_js)

    def test_frontend_uses_canonical_payload_keys(self) -> None:
        # These keys must match saip_decoded_edit's encoder contracts.
        self.assertIn('{ fid:', self.app_js)
        self.assertIn("byteCount:", self.app_js)
        self.assertIn("{ state:", self.app_js)
        self.assertIn("{ offset:", self.app_js)
        self.assertIn("{ imsi:", self.app_js)
        self.assertIn("{ iccid:", self.app_js)

    def test_css_ships_decoded_edit_styles(self) -> None:
        for klass in (
            ".saip-decoded-card",
            ".saip-decoded-row",
            ".saip-decoded-form-grid",
            ".saip-decoded-services-list",
            ".saip-decoded-form-status",
            ".saip-file-data-row",
            ".saip-file-data-tools",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS class: {klass}")


class DecodedEditPolishWiringTests(unittest.TestCase):
    """Guards the filter / revert / highlight additions so the panel
    keeps its polish pass intact after later refactors.
    """

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_panel_renders_filter_toolbar_for_large_field_sets(self) -> None:
        self.assertIn("saip-decoded-toolbar", self.app_js)
        self.assertIn("saip-decoded-filter", self.app_js)
        self.assertIn("saip-decoded-count", self.app_js)

    def test_panel_uses_tree_pane_layout(self) -> None:
        # SA-G7: the flat list of editor rows was replaced with a
        # left-side path tree + right-side editor pane. The tree
        # groups by EF (``last_ef_key``) and collapses verbose
        # JSON-fallback editors behind a single "JSON" leaf to keep
        # the index legible.
        self.assertIn("saip-decoded-split", self.app_js)
        self.assertIn("saip-decoded-treepane", self.app_js)
        self.assertIn("saip-decoded-editorpane", self.app_js)
        self.assertIn("saip-decoded-tree-group", self.app_js)
        self.assertIn("saip-decoded-tree-leaf", self.app_js)
        # JSON-fallback toggle is wired through a checkbox in the
        # toolbar (off by default so the tree doesn't drown in
        # roundtrip-decoded leaves).
        self.assertIn("saip-decoded-json-toggle", self.app_js)
        # Selected-leaf state persists per (section, field) on the
        # package handle.
        self.assertIn("pkg.decodedSelected", self.app_js)

    def test_panel_css_ships_tree_pane_tokens(self) -> None:
        for klass in (
            ".saip-decoded-split",
            ".saip-decoded-treepane",
            ".saip-decoded-editorpane",
            ".saip-decoded-tree-group",
            ".saip-decoded-tree-leaf",
            ".saip-decoded-json-toggle",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS class: {klass}")

    def test_saip_checkbox_skin_is_scoped_and_theme_aligned(self) -> None:
        for token in (
            '.saip-workbench input[type="checkbox"]',
            '.saip-modal-host input[type="checkbox"]',
            "border-radius: 999px",
            "radial-gradient(circle at center, var(--accent",
            "color-mix(in srgb, var(--accent",
        ):
            self.assertIn(token, self.app_css)

    def test_filter_matches_across_name_path_kind_and_ef(self) -> None:
        for token in (
            "f.field_name",
            "f.display_path",
            "f.editor_kind",
            "f.last_ef_key",
        ):
            self.assertIn(token, self.app_js, f"missing filter haystack: {token}")

    def test_revert_button_wired_to_apply_decoded_edit(self) -> None:
        self.assertIn("saipDecodedRevertField", self.app_js)
        self.assertIn("decodedPristine", self.app_js)
        self.assertIn("saipDecodedPayloadDiffers", self.app_js)

    def test_package_record_initialises_pristine_cache(self) -> None:
        self.assertIn("decodedPristine: {}", self.app_js)

    def test_modified_row_has_css_highlight(self) -> None:
        self.assertIn(".saip-decoded-row.is-modified", self.app_css)
        self.assertIn(".saip-decoded-chip-mod", self.app_css)
        self.assertIn(".saip-decoded-revert-btn", self.app_css)

    def test_decoded_panel_intro_is_operator_facing(self) -> None:
        self.assertIn("Each row uses a type-aware editor", self.app_js)

    def test_large_field_set_filter_placeholder(self) -> None:
        self.assertIn("Filter by name, path, kind, or EF", self.app_js)

    def test_data_tab_summary_names_hex_write_spans(self) -> None:
        self.assertIn("Whole-file hex view", self.app_js)
        self.assertIn("Apply hex", self.app_js)

    def test_record_select_supports_page_keys(self) -> None:
        self.assertIn('"PageUp"', self.app_js)
        self.assertIn('"PageDown"', self.app_js)

    def test_gfm_subfield_decodes_records_payload(self) -> None:
        self.assertIn('key === "fillfilecontent"', self.app_js)
        self.assertIn('fillfilecontents', self.app_js)

    def test_data_hex_dump_has_copy_toolbar(self) -> None:
        # The wholesale ``saip-hexdump-tools`` block was removed when
        # the Data tab dropped the trailing FF-flood hex dump (operator
        # feedback — sparse fillFileContent layouts hid the decoded
        # cards behind a wall of FF). Per-record Copy hex affordances
        # now live on each record card; the wholesale Raw bytes editor
        # carries its own Copy hex button for transparent EFs.
        self.assertIn("saip-record-copy", self.app_js)
        self.assertIn("Copy hex", self.app_js)
        self.assertIn("saip-rawbytes-card", self.app_js)

    def test_file_system_placeholder_mentions_tabs(self) -> None:
        # The placeholder enumerates the three detail tabs operators
        # land on when no file is selected. Stays in sync with the
        # tab labels in ``renderSaipFileDetail``.
        self.assertIn("File Control Parameters", self.app_js)
        self.assertIn("Data (raw hex + decoded field editors)", self.app_js)

    def test_pe_placeholder_mentions_editor_surfaces(self) -> None:
        # The PE detail-view placeholder enumerates the two PE detail
        # tabs (Decoded view + JSON view).
        self.assertIn("Decoded view (typed forms,", self.app_js)
        self.assertIn("JSON view", self.app_js)

    def test_file_detail_tabs_define_tooltips(self) -> None:
        # Tooltip strings for the three detail tabs (FCP / Data /
        # JSON). The "Decoded" sibling tab was merged into Data so the
        # interpreted + hex views land in the same panel (ePC §"File
        # Content").
        self.assertIn("FCP metadata + access rules", self.app_js)
        self.assertIn("EF body bytes plus decoded view", self.app_js)
        self.assertIn("JSON projection of the ASN.1 CHOICE list", self.app_js)

    def test_raw_hex_editor_has_copy_toolbar(self) -> None:
        self.assertIn("saip-decoded-hex-tools", self.app_js)
        self.assertIn("Copy raw hex", self.app_js)
        self.assertIn(".saip-decoded-hex-tools", self.app_css)

    def test_loading_messages_are_capitalized(self) -> None:
        self.assertIn("Loading file…", self.app_js)
        self.assertIn("Loading PE…", self.app_js)
        self.assertIn("Loading applications…", self.app_js)
        self.assertIn("Loading diff vs saved…", self.app_js)
        self.assertIn("Comparing…", self.app_js)

    def test_pe_detail_tabs_have_tooltips(self) -> None:
        # Two-tab world: "Decoded view" (typed editor + hex) and "JSON".
        # The legacy "PE-<Type> Editor" / "ASN.1 Value Notation" / "block
        # tree" labels were retired so YggdraSIM's surface text is its
        # own and not a Comprion ePC echo.
        self.assertIn("Typed PE layout and decoded-field editors", self.app_js)
        self.assertIn(
            "Flat JSON projection of the decoded PE document",
            self.app_js,
        )

    def test_fill_file_offset_editor_labels_byte_offset(self) -> None:
        self.assertIn("Byte offset (bytes)", self.app_js)
        self.assertIn("Sets the write head for the next records payload", self.app_js)

    def test_pe_data_tab_has_copy_hex_button(self) -> None:
        # The legacy three-tab PE layout (with a separate "ASN.1 text"
        # tab carrying its own copy bar) was retired when the JSON tab
        # absorbed both projections. The remaining copy affordance is
        # the raw-hex copy on the file Data tab.
        self.assertIn('copyBtn.textContent = "Copy raw hex"', self.app_js)
        self.assertIn(".saip-hexdump-tools", self.app_css)
        self.assertIn(".saip-decoded-hex-tools", self.app_css)

    def test_validation_dock_copy_is_sentence_case(self) -> None:
        self.assertIn("Running linter…", self.app_js)
        self.assertIn("Preparing linter…", self.app_js)
        self.assertIn('score.textContent = "Score "', self.app_js)
        self.assertIn('score.textContent = "Error"', self.app_js)
        self.assertIn('? "Running…" : "Not run yet"', self.app_js)

    def test_save_status_messages_are_sentence_case(self) -> None:
        # The save form left the drawer in the workbench rebuild;
        # save / revert status now lives on the package object so the
        # ribbon Save / Revert buttons can surface progress chips.
        # The "Output path required" guard moved into Save as… input
        # validation rather than a saveStatus assignment.
        self.assertIn('pkg.saveStatus = "Saving…"', self.app_js)
        self.assertIn('pkg.saveStatus = "Saved " +', self.app_js)
        self.assertIn('pkg.saveStatus = "Error: "', self.app_js)
        self.assertIn('pkg.saveStatus = "Reverting…"', self.app_js)
        self.assertIn('pkg.saveStatus = "Reverted to source."', self.app_js)

    def test_ribbon_action_buttons_have_tooltips(self) -> None:
        # The save/revert/compare actions moved from the left drawer
        # onto the ribbon in the SAIP workbench rebuild — these
        # tooltips are now the ones the operator sees.
        self.assertIn("Save back to the source path", self.app_js)
        self.assertIn("Drop in-memory edits and reload", self.app_js)
        self.assertIn("Diff this package against another open package", self.app_js)

    def test_open_package_ribbon_path_is_wired(self) -> None:
        # The open-package form left the drawer in the workbench
        # rebuild — Open is a ribbon button, drag-drop drop, or
        # Ctrl+O. The handler funnels through saipRibbonOpenPackage,
        # so pin its existence and the drag-drop wiring helper.
        self.assertIn("saipRibbonOpenPackage", self.app_js)
        self.assertIn("wireSaipWorkbenchDrop", self.app_js)
        self.assertIn(
            "Open a SAIP package from disk — drag-and-drop also works",
            self.app_js,
        )

    def test_decoded_apply_status_copy(self) -> None:
        self.assertIn('manual ? "Applying…" : "Auto-applying…"', self.app_js)
        self.assertIn('manual ? "Applied." : "Auto-applied."', self.app_js)
        self.assertIn('"Apply failed."', self.app_js)

    def test_fcp_row_apply_buttons_have_tooltips(self) -> None:
        self.assertIn("writes hex via the server; use Save in the drawer to persist", self.app_js)

    def test_decoded_modified_chip_is_capitalized(self) -> None:
        self.assertIn('modChip.textContent = "Modified"', self.app_js)

    def test_validation_dock_validate_and_strict_hints(self) -> None:
        self.assertIn("Honors the Strict checkbox.", self.app_js)
        self.assertIn(
            "When checked, the next validation run requests strict mode",
            self.app_js,
        )
        self.assertIn('strictText.textContent = "Strict"', self.app_js)

    def test_tokens_pane_placeholders_and_apply_hint(self) -> None:
        # "Variable" was renamed to "Token" in the SAIP rebrand —
        # so this checks the current token-editor copy.
        self.assertIn("8988201234567890123 (BCD) or raw hex", self.app_js)
        self.assertIn("Register or update this token's value", self.app_js)
        self.assertIn('Reset all (" + overrideNames.length + ")', self.app_js)

    def test_variables_state_chips_are_capitalized(self) -> None:
        self.assertIn('>Override</span>', self.app_js)
        self.assertIn('>Defined</span>', self.app_js)
        self.assertIn('>Used</span>', self.app_js)

    def test_pe_and_file_list_rows_have_navigation_tooltips(self) -> None:
        self.assertIn('card.title = "Show PE #" + row.index', self.app_js)
        self.assertIn('row.title = hasChildren', self.app_js)
        self.assertIn('"Open " + node.label + " — "', self.app_js)

    def test_compare_and_diff_errors_are_operator_facing(self) -> None:
        self.assertIn("The other package is no longer open.", self.app_js)
        self.assertIn("That number is not in the list.", self.app_js)
        self.assertIn("Diff vs saved failed.", self.app_js)

    def test_variable_modal_chrome(self) -> None:
        # "Variable editor" was renamed to "Token editor" so the surface
        # text is YggdraSIM's own and not a Comprion ePC echo.
        self.assertIn("Close token editor (same as Esc).", self.app_js)
        self.assertIn("overrideWord", self.app_js)
        self.assertIn("placeholderWord", self.app_js)
        self.assertIn("Leave diff vs saved and return to the normal detail view.", self.app_js)
        self.assertIn("Leave compare mode and return to normal browsing.", self.app_js)

    def test_validation_dock_header_and_decoded_tooltips(self) -> None:
        self.assertIn(
            "Show or hide findings. Severity chips stay visible when collapsed.",
            self.app_js,
        )
        self.assertIn("Substring match on name, path, editor kind, or EF key.", self.app_js)
        self.assertIn("How many decoded-field leaves pass the filter.", self.app_js)
        self.assertIn("Encode this field and patch the in-memory PE", self.app_js)

    def test_decoded_panel_errors_are_operator_facing(self) -> None:
        self.assertIn("List decoded fields failed.", self.app_js)
        self.assertIn("No response when loading decoded fields.", self.app_js)
        self.assertIn("Could not load decoded fields:", self.app_js)

    def test_compare_pe_view_button_has_tooltip(self) -> None:
        self.assertIn(
            "Side-by-side decoded-field editors for this profile element.",
            self.app_js,
        )

    def test_gfm_editor_two_pane_layout(self) -> None:
        self.assertIn("Generic File Management", self.app_js)
        self.assertIn("saipGfmBuildCommandView", self.app_js)
        self.assertIn("saipGfmFileBlockPathList", self.app_js)
        self.assertIn("saipEditorRenderGfmCard", self.app_js)
        self.assertIn("saip-gfm-panes", self.app_js)
        self.assertIn("saip-gfm-list-pane", self.app_js)
        self.assertIn("saip-gfm-detail-pane", self.app_js)
        self.assertIn("saip-gfm-list-row", self.app_js)
        self.assertIn("saipFileRenderGeneral(", self.app_js)
        self.assertIn("fileManagementCMD[i][j]", self.app_js)
        self.assertIn("_GFM_FID_NAMES", self.app_js)
        self.assertIn('tabData.textContent = "File data"', self.app_js)
        self.assertIn('tabJson.textContent = "SHOW JSON"', self.app_js)
        self.assertIn("FCP metadata (editable)", self.app_js)
        self.assertIn(".saip-gfm-panes", self.app_css)
        self.assertIn(".saip-gfm-list-pane", self.app_css)
        self.assertIn(".saip-gfm-list-row", self.app_css)
        self.assertIn(".saip-gfm-detail-pane", self.app_css)

    def test_split_pane_headers_are_rendered(self) -> None:
        self.assertIn("saip-pane saip-pane--list", self.app_js)
        self.assertIn("saip-pane saip-pane--detail", self.app_js)
        self.assertIn("saip-pane-head", self.app_js)
        self.assertIn("saip-pane-chip", self.app_js)
        self.assertIn(".saip-pane-head", self.app_css)
        self.assertIn(".saip-pane-chip", self.app_css)


class PeLevelDecodedPanelWiringTests(unittest.TestCase):
    """Pins the SA-G3 PE-level decoded edit panel.

    The typed PE editor for header / PIN / PUK / AKA / SecurityDomain /
    GFM PEs needs a section-wide decoded panel (no per-EF scope) so
    the operator can edit ``pinValue`` / ``maxAttempts`` / ``Ki`` /
    ``keyComponents`` / GFM file commands without dropping into the
    JSON tree. This guard keeps the wildcard sentinel and the per-PE
    invocation in place.
    """

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )

    def test_show_pe_threads_pkg_into_editor(self) -> None:
        self.assertIn(
            "renderSaipPeEditor(data, pkg, peList, validation)",
            self.app_js,
        )
        self.assertIn(
            "renderSaipPeDetail(detail, peCached, pkg, peList, validation)",
            self.app_js,
        )

    def test_field_match_treats_star_as_wildcard(self) -> None:
        self.assertIn('if (tail === "*") return true;', self.app_js)

    def test_pe_editor_invokes_decoded_panel_with_wildcard(self) -> None:
        # The PE-level invocation passes ``"*"`` as the fieldPath so
        # the panel skips the per-EF filter and surfaces every
        # decodable field for the section. Match flexibly because
        # the host variable is named differently in each call site
        # (`inlineHost`, `decodedHost`, `panelA`, …).
        import re
        pattern = re.compile(
            r'saipRenderDecodedEditPanel\(\s*\w+,\s*pkg,\s*\w+,\s*"\*",\s*peList'
        )
        matches = pattern.findall(self.app_js)
        self.assertGreaterEqual(
            len(matches), 1,
            "saipRenderDecodedEditPanel(host, pkg, sectionKey, '*', peList, …) "
            "invocation missing — the PE-level decoded panel may have lost "
            "its wildcard fieldPath.",
        )

    def test_decoded_panel_is_default_on(self) -> None:
        # Default policy: every PE gets the decoded panel unless the
        # type explicitly opts out (file-bearing application
        # templates). This guards against future refactors that
        # accidentally flip the default and silently strip the panel
        # from header / GFM / RFM / gsm-access PEs.
        self.assertIn("var supportsDecodedPanel = true;", self.app_js)

    def test_application_templates_opt_out(self) -> None:
        # USIM / ISIM / CSIM PEs already have a typed template + files
        # editor and route per-EF edits through the Files tab. The
        # decoded panel must remain disabled here to avoid showing the
        # same fields three times.
        marker = "saipEditorRenderTemplateFilesWorkbenchCard("
        anchor = self.app_js.find(marker)
        self.assertGreater(anchor, 0, "USIM/ISIM/CSIM template workbench invocation missing")
        # Window covers the whole template-catalog + filesystem-wizards
        # block that follows, ending at the ``supportsDecodedPanel`` flip.
        window = self.app_js[anchor: anchor + 600]
        self.assertIn("supportsDecodedPanel = false", window)

    def test_generic_roundtrip_kept_for_direct_pe_families(self) -> None:
        self.assertIn("function saipDirectPeAllowsGenericDecoded(", self.app_js)
        self.assertIn("saipIsSecurityDomainSectionKey(sectionKey)", self.app_js)
        self.assertIn("saipIsApplicationSectionKey(sectionKey)", self.app_js)
        self.assertIn("saipIsRemoteManagementSectionKey(sectionKey)", self.app_js)
        self.assertIn("saipIsAkaSectionKey(sectionKey)", self.app_js)

    def test_pin_puk_direct_groups_are_named(self) -> None:
        self.assertIn("function saipDecodedPinPukGroupTitle(", self.app_js)
        self.assertIn("saip-decoded-entry-group--pinpuk", self.app_js)
        self.assertIn(".saip-decoded-entry-group-head", Path("yggdrasim_common/gui_server/static/app.css").read_text(encoding="utf-8"))

    def test_pin_puk_direct_groups_are_collapsed_details(self) -> None:
        anchor = self.app_js.find("if (directIsPinPuk) {")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 5200]
        self.assertIn('document.createElement("details")', body)
        self.assertIn('document.createElement("summary")', body)
        self.assertNotIn(".open = true", body)
        self.assertIn("ev.preventDefault();", body)
        self.assertIn("forceCollapsible: true", body)
        self.assertIn("startCollapsed: true", body)
        self.assertIn("+ Add code", body)

    def test_security_domain_key_fields_are_grouped(self) -> None:
        self.assertIn("function saipDecodedSdKeyGroupTitle(", self.app_js)
        self.assertIn("saip-decoded-entry-group--sd-key", self.app_js)
        anchor = self.app_js.find("} else if (directIsSecurityDomain) {")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 5200]
        self.assertIn("saipDecodedSdKeyIndex(field.rel_path)", body)
        self.assertIn("saipDecodedSdKeyFieldOrder(a)", body)
        self.assertIn("saipDecodedSdKeyGroupTitle(entryIdx, fields)", body)
        self.assertIn('document.createElement("details")', body)
        self.assertIn('document.createElement("summary")', body)
        self.assertIn("forceCollapsible: true", body)
        self.assertIn("startCollapsed: true", body)

    def test_direct_pe_dropdowns_cover_manual_constrained_fields(self) -> None:
        self.assertIn("var _SAIP_PE_TYPES_BY_HINT = {", self.app_js)
        self.assertIn("var _SAIP_KEY_IDENTIFIER_OPTIONS = [", self.app_js)
        self.assertIn("var _SAIP_KEY_VERSION_OPTIONS = [", self.app_js)
        self.assertIn('if (fn === "type") {', self.app_js)
        self.assertIn('if (fn === "access" && hint.indexOf("security") !== -1)', self.app_js)
        self.assertIn('if (fn === "keyidentifier") {', self.app_js)
        self.assertIn('if (fn === "keyversionnumber") {', self.app_js)
        self.assertIn('fn === "keyidentifier"', self.app_js)
        self.assertIn('fn === "keyversionnumber"', self.app_js)

    def test_decoded_field_row_accepts_start_collapsed_option(self) -> None:
        anchor = self.app_js.find("function saipBuildDecodedFieldRow(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 6500]
        self.assertIn("rowOpts.forceCollapsible === true", body)
        self.assertIn("rowOpts.startCollapsed === true", body)
        self.assertIn('row.classList.add("is-collapsed");', body)

    def test_direct_sd_rfm_application_aka_cards_start_collapsed(self) -> None:
        self.assertIn("function saipDirectPeCardsStartCollapsed(", self.app_js)
        anchor = self.app_js.find("function saipDirectPeCardsStartCollapsed(")
        self.assertGreater(anchor, 0)
        helper = self.app_js[anchor: anchor + 700]
        self.assertIn("saipIsSecurityDomainSectionKey(sectionKey)", helper)
        self.assertIn("saipIsApplicationSectionKey(sectionKey)", helper)
        self.assertIn("saipIsRemoteManagementSectionKey(sectionKey)", helper)
        self.assertIn("saipIsAkaSectionKey(sectionKey)", helper)
        direct_anchor = self.app_js.find("var directCollapseRows = opts.directEditor")
        self.assertGreater(direct_anchor, 0)
        generic_anchor = self.app_js.find(
            '      } else {\n        directFields.forEach(function (f) {',
            direct_anchor,
        )
        self.assertGreater(generic_anchor, 0)
        direct_body = self.app_js[direct_anchor: generic_anchor + 900]
        self.assertIn("saipDirectPeCardsStartCollapsed(sectionKey)", direct_body)
        self.assertIn("rowOpts.forceCollapsible = true", direct_body)
        self.assertIn("rowOpts.startCollapsed = true", direct_body)


@unittest.skipUnless(
    _REFERENCE_PROFILE.exists(),
    "reference profile sample missing — skipping end-to-end test",
)
class ShowPeSectionKeyTests(unittest.TestCase):
    """Pins the ``section_key`` field that ``saip.show_pe`` exposes so
    the GUI can drive ``saip.list_decoded_fields`` / ``apply_decoded_edit``
    without having to re-derive section ordering on the client.
    """

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module(
            "yggdrasim_common.gui_server.sessions"
        )

        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        ws = Path(".").resolve()
        bridge = SaipToolBridge(ws)
        src = bridge.resolve_input_path(
            str(_REFERENCE_PROFILE),
            must_exist=True,
        )
        raw = bridge._prepare_input_for_tool(src).read_bytes()
        tmp = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        tmp.write(raw)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        open_resp = self.saip._dispatch_open_package(self.ctx, path=tmp.name)
        self.session_id = open_resp["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)

    def test_show_pe_returns_section_key_for_each_pe(self) -> None:
        section_keys = list(
            (self.handle["decoded_document"].get("sections") or {}).keys()
        )
        self.assertGreater(len(section_keys), 0)
        for idx, expected in enumerate(section_keys):
            resp = self.saip._dispatch_show_pe(
                self.ctx,
                session_id=self.session_id,
                pe_index=idx,
            )
            self.assertEqual(resp["section_key"], expected)
            self.assertEqual(resp["pe_index"], idx)


class FilesTabParityWiringTests(unittest.TestCase):
    """Pins the SA-G3 file-bearing PE coverage.

    Before the parity sweep the Files card only rendered for USIM /
    ISIM / CSIM application templates. Root DFs (MF, Telecom,
    DF.5GS, DF.SAIP, DF.SNPN, DF.5GPROSE, DF.EAP, DF.GSM-ACCESS) and
    the Telecom phonebook fell through to the untyped fallback,
    leaving the operator with a raw JSON tree. SA-G3 unifies those
    PEs onto the same typed editor.
    """

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )

    def test_root_df_pes_route_through_files_card(self) -> None:
        # Locate the file-bearing branch and assert every root-DF
        # type is listed before the next branch (securityDomain).
        marker = "saipEditorRenderFilesCard(wrap, decoded, data.type);"
        anchor = self.app_js.find(marker)
        self.assertGreater(anchor, 0, "files-card invocation missing")
        # Walk back from the marker to find the opening if; everything
        # between the if-test and the marker is the type list.
        prefix = self.app_js[max(0, anchor - 1500): anchor]
        for needle in (
            't === "mf"',
            't === "telecom"',
            't === "df-telecom"',
            't === "phonebook"',
            't === "df-phonebook"',
            't === "df-5gs"',
            't === "df-saip"',
            't === "df-snpn"',
            't === "df-5gprose"',
            't === "gsm-access"',
        ):
            self.assertIn(needle, prefix, f"file-bearing branch must include {needle}")

    def test_template_fid_map_covers_root_dfs(self) -> None:
        # Spot-check a handful of well-known FIDs so a future map
        # rewrite cannot silently drop the spec defaults.
        for needle in (
            '"mf": ["3F00", null]',
            '"ef-iccid": ["2FE2", null]',
            '"df-telecom": ["7F10", null]',
            '"df-gsm-access": ["5F3B", null]',
        ):
            self.assertIn(needle, self.app_js, f"missing template FID: {needle}")

    def test_template_card_skips_when_empty(self) -> None:
        # Template card must opt out when there is neither a template
        # OID nor any root descriptor data — otherwise non-template
        # PEs render an empty card with one blank row.
        self.assertIn(
            "if (!hasTemplate && !hasRoot) return;",
            self.app_js,
        )


class FileTreeSearchSortWiringTests(unittest.TestCase):
    """Pins the FS tree search / sort / default-collapse controls."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(encoding="utf-8")

    def test_file_tree_has_search_and_sort_controls(self) -> None:
        anchor = self.app_js.find("function renderSaipFileListPane(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 5200]
        self.assertIn("saip-file-tree-search", body)
        self.assertIn("Search FID or filename", body)
        self.assertIn("Sort: FID", body)
        self.assertIn("Sort: Name", body)
        self.assertIn("saipFilterFileTree(tree, query)", body)

    def test_file_tree_search_matches_names_and_fids(self) -> None:
        self.assertIn("function saipFileTreeSearchHaystack(", self.app_js)
        anchor = self.app_js.find("function saipFileTreeSearchHaystack(")
        body = self.app_js[anchor: anchor + 1100]
        self.assertIn("row.friendly_name", body)
        self.assertIn("row.field_path", body)
        self.assertIn("row.file_id", body)
        self.assertIn("row.short_efid", body)
        self.assertIn("row.fid_chain", body)

    def test_file_tree_starts_df_adf_collapsed_and_search_expands(self) -> None:
        self.assertIn("function saipFileTreeDefaultCollapsed(", self.app_js)
        anchor = self.app_js.find("function saipFileTreeDefaultCollapsed(")
        body = self.app_js[anchor: anchor + 800]
        self.assertIn('k === "df" || k === "adf"', body)
        self.assertIn("saipApplyFileTreeDefaultCollapse(pkg, tree)", self.app_js)
        self.assertIn("{ searchActive: query.length > 0 }", self.app_js)
        self.assertIn(".saip-file-node-row--search-match", self.app_css)


class SaipDrawerAndMaximizeWiringTests(unittest.TestCase):
    """Pins package-drawer collapse and removal of panel double-click maximize."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(encoding="utf-8")

    def test_open_packages_drawer_can_collapse(self) -> None:
        self.assertIn("packageDrawerCollapsed", self.app_js)
        self.assertIn("function saipPackageTooltip(", self.app_js)
        self.assertIn("function saipSelectPackage(", self.app_js)
        anchor = self.app_js.find("function renderSaipDrawer(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 3600]
        self.assertIn("saip-drawer--collapsed", body)
        self.assertIn("saip-layout--drawer-collapsed", body)
        self.assertIn("saip-drawer-toggle", body)
        self.assertIn("saip-drawer-rail-pkg", body)
        self.assertIn("badge.title = saipPackageTooltip(pkg)", body)
        self.assertIn("saipSelectPackage(pkg.id, drawer, peList, detail, validation)", body)
        self.assertIn(".saip-layout--drawer-collapsed", self.app_css)
        self.assertIn(".saip-drawer-rail-pkg", self.app_css)

    def test_install_maximizable_no_longer_binds_double_click(self) -> None:
        anchor = self.app_js.find("function installMaximizable(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: self.app_js.find("\n  function toggleMaximize", anchor)]
        self.assertNotIn('addEventListener("dblclick"', body)
        self.assertNotIn("double-click or Esc to restore", self.app_js)


class ApplicationsInlineEditorWiringTests(unittest.TestCase):
    """Pins the inline decoded-field editor on Application cards."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_card_carries_edit_button_and_inline_host(self) -> None:
        for needle in (
            'editBtn.className = "btn btn-small saip-app-card-edit";',
            'editBtn.textContent = "Edit fields";',
            'inlineHost.className = "saip-app-card-inline";',
        ):
            self.assertIn(needle, self.app_js, f"missing app-card hook: {needle}")

    def test_inline_panel_drives_decoded_edit_panel(self) -> None:
        # Inline editor must reach for saipRenderDecodedEditPanel with
        # the wildcard sentinel so every decodable field of the PE is
        # surfaced.
        marker = 'saipLoadShowPe(pkg, row.pe_index).then(function () {'
        # Two such blocks exist (jump button + inline editor). Find
        # the second occurrence and verify the panel call lives near
        # it (inside the inline expander).
        first = self.app_js.find(marker)
        self.assertGreater(first, 0)
        second = self.app_js.find(marker, first + len(marker))
        self.assertGreater(second, 0, "inline editor expander missing")
        nearby = self.app_js[max(0, second - 800): second + 800]
        self.assertIn("saipRenderDecodedEditPanel(", nearby)
        self.assertIn('"*"', nearby)

    def test_app_card_inline_css_present(self) -> None:
        for klass in (
            ".saip-app-card-edit",
            ".saip-app-card-inline",
            '.saip-app-card-edit[aria-expanded="true"]',
        ):
            self.assertIn(klass, self.app_css, f"missing CSS: {klass}")


class GfmInlineDecoderWiringTests(unittest.TestCase):
    """Pins the GFM op-level inline decoders."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )

    def test_decoder_helper_is_defined(self) -> None:
        self.assertIn("function saipDecodeGfmSubField(", self.app_js)
        self.assertIn("function saipEditorKvWithSub(", self.app_js)

    def test_decoder_handles_known_sub_fields(self) -> None:
        for needle in (
            'if (key === "filedescriptor") {',
            'if (key === "lcsi") {',
            'if (key === "securityattributesreferenced") {',
            'if (key === "fileid") {',
            'if (key === "shortefid") {',
            'if (key === "dfname") {',
            'if (key === "pinstatustemplatedo") {',
            'if (key === "filepath") {',
            'if (key === "fillfileoffset") {',
        ):
            self.assertIn(needle, self.app_js, f"missing GFM decoder branch: {needle}")

    def test_filepath_decoder_emits_hop_list(self) -> None:
        # filePath payloads encode a sequence of 2-byte FIDs; the
        # decoder must split them on the 4-hex-char boundary so the
        # operator sees ``3F00 / 7F10 / 6F3A`` instead of opaque hex.
        marker = 'if (key === "filepath") {'
        anchor = self.app_js.find(marker)
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 600]
        self.assertIn("hops.push(fp.slice(i, i + 4));", window)
        self.assertIn('hops.join(" / ")', window)


class NavTreeSubsystemWiringTests(unittest.TestCase):
    """Keeps the sidebar in sync with the action registry."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )

    def test_esim_test_leaf_is_absent(self) -> None:
        self.assertNotIn('subsystem: "eSIM Test"', self.app_js)
        self.assertNotIn("leaf-esim-test", self.app_js)


class SemanticDiffWiringTests(unittest.TestCase):
    """Pins the semantic diff integration in the compare view and diff-vs-saved."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_saip_diff_packages_called_concurrently(self) -> None:
        # saipLoadCompare must fire saip.diff_packages alongside saip.compare.
        anchor = self.app_js.find("async function saipLoadCompare(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 3000]
        self.assertIn("saip.diff_packages", body)
        self.assertIn("Promise.allSettled(", body)

    def test_semantic_diff_stored_as_pkg_semanticDiff(self) -> None:
        self.assertIn("pkg.semanticDiff =", self.app_js)

    def test_render_semantic_diff_section_defined(self) -> None:
        self.assertIn("function saipRenderSemanticDiffSection(", self.app_js)

    def test_semantic_diff_rendered_in_compare_view(self) -> None:
        anchor = self.app_js.find("function renderSaipCompareDetail(")
        self.assertGreater(anchor, 0)
        next_fn = self.app_js.find("\n  function ", anchor + 100)
        end = next_fn if next_fn > anchor else anchor + 15000
        body = self.app_js[anchor:end]
        self.assertIn("saipRenderSemanticDiffSection(", body)

    def test_diff_vs_saved_button_in_drawer(self) -> None:
        self.assertIn("Diff vs saved", self.app_js)
        self.assertIn("saipStartDiffVsSaved(", self.app_js)

    def test_diff_vs_saved_calls_diff_against_source(self) -> None:
        anchor = self.app_js.find("async function saipLoadDiffVsSaved(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1500]
        self.assertIn("saip.diff_against_source", body)

    def test_diff_vs_saved_render_function_defined(self) -> None:
        self.assertIn("function renderSaipDiffVsSavedDetail(", self.app_js)

    def test_diff_vs_saved_routed_in_renderSaipDetail(self) -> None:
        anchor = self.app_js.find("function renderSaipDetail(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1000]
        self.assertIn("diffVsSavedActive", body)
        self.assertIn("renderSaipDiffVsSavedDetail(", body)

    def test_semantic_diff_css_classes_present(self) -> None:
        for klass in (
            ".saip-cmp-sem-table",
            ".saip-cmp-sem-chip",
            ".saip-cmp-sem-chip--crit",
            ".saip-cmp-sem-chip--warn",
            ".saip-cmp-sem-chip--info",
            ".saip-cmp-sem-row--critical",
            ".saip-cmp-sem-group",
            ".saip-cmp-sem-group-summary",
            ".saip-cmp-sem-row--clickable",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS: {klass}")

    def test_section_key_to_pe_index_helper_defined(self) -> None:
        self.assertIn("function saipSectionKeyToPeIndex(", self.app_js)

    def test_jump_to_section_key_helper_defined(self) -> None:
        self.assertIn("function saipJumpToSectionKey(", self.app_js)

    def test_sem_diff_section_passes_pkg_to_renderer(self) -> None:
        # Both call sites must pass pkg to saipRenderSemanticDiffSection.
        anchor1 = self.app_js.find("function renderSaipCompareDetail(")
        anchor2 = self.app_js.find("function renderSaipDiffVsSavedDetail(")
        for anchor, label in [(anchor1, "compare"), (anchor2, "diff-vs-saved")]:
            self.assertGreater(anchor, 0, f"function not found: {label}")
            end = self.app_js.find("\n  function ", anchor + 100)
            body = self.app_js[anchor: end if end > anchor else anchor + 8000]
            # Both must pass at least 3 extra args (pkg, peList, detail, validation)
            call_idx = body.find("saipRenderSemanticDiffSection(body, pkg.")
            self.assertGreater(call_idx, -1,
                f"saipRenderSemanticDiffSection not called with extended args in {label}")

    def test_clickable_row_class_applied_when_section_key_resolvable(self) -> None:
        anchor = self.app_js.find("function saipRenderSemanticDiffSection(")
        self.assertGreater(anchor, 0)
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 8000]
        self.assertIn("saip-cmp-sem-row--clickable", body)
        self.assertIn("saipJumpToSectionKey(", body)


class ValidationJumpHighlightWiringTests(unittest.TestCase):
    """Pins the decoded-panel highlight path opened by saipJumpToFinding."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_highlight_helper_is_defined(self) -> None:
        self.assertIn("function saipHighlightDecodedField(", self.app_js)

    def test_field_name_helper_is_defined(self) -> None:
        self.assertIn("function saipFindingFieldName(", self.app_js)

    def test_jump_calls_highlight_on_file_route(self) -> None:
        # After the file-route load resolves, saipHighlightDecodedField
        # must be called so the matching decoded row scrolls into view.
        marker = "saipLoadShowFile(pkg, finding.section_key, finding.field_path)"
        anchor = self.app_js.find(marker)
        self.assertGreater(anchor, 0, "file-route load missing in saipJumpToFinding")
        window = self.app_js[anchor: anchor + 600]
        self.assertIn("saipHighlightDecodedField(", window)

    def test_jump_calls_highlight_on_pe_route(self) -> None:
        # The PE-route branch must also open and highlight the decoded panel.
        marker = "saipLoadShowPe(pkg, finding.pe_index)"
        anchor = self.app_js.find(marker)
        self.assertGreater(anchor, 0, "pe-route load missing in saipJumpToFinding")
        window = self.app_js[anchor: anchor + 600]
        self.assertIn("saipHighlightDecodedField(", window)

    def test_highlight_css_class_defined(self) -> None:
        self.assertIn(".saip-decoded-row--highlight", self.app_css)

    def test_highlight_polls_for_async_panel(self) -> None:
        # The helper must retry with a delay to handle the async
        # decoded-panel load; confirm the polling idiom is present.
        anchor = self.app_js.find("function saipHighlightDecodedField(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1800]
        self.assertIn("setTimeout(tryHighlight", body)
        self.assertIn("saip-decoded-row-name", body)
        self.assertIn("scrollIntoView(", body)


class CompareModeTypedEditorWiringTests(unittest.TestCase):
    """Pins the side-by-side typed PE editor added to the compare view."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )
        self.app_css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_view_button_rendered_per_pe_row(self) -> None:
        # Each PE row in the compare table must carry a toggle button.
        self.assertIn('className = "btn btn-small saip-cmp-view-btn"', self.app_js)

    def test_side_panel_structure_present(self) -> None:
        # The expand row carries a two-pane split host.
        for needle in (
            "saip-cmp-side",
            "saip-cmp-side-pane--a",
            "saip-cmp-side-pane--b",
            "saip-cmp-side-label",
        ):
            self.assertIn(needle, self.app_js, f"missing compare panel class: {needle}")

    def test_both_sides_call_decoded_panel(self) -> None:
        # Both panes must invoke saipRenderDecodedEditPanel to get the
        # full typed-editor experience. The function is large (the
        # click handler for the View button is deeply nested inside a
        # forEach), so search up to the next top-level function boundary.
        anchor = self.app_js.find("function renderSaipCompareDetail(")
        self.assertGreater(anchor, 0)
        # Find the next top-level function after renderSaipCompareDetail
        next_fn = self.app_js.find("\n  function ", anchor + 100)
        end = next_fn if next_fn > anchor else anchor + 20000
        body = self.app_js[anchor:end]
        count = body.count("saipRenderDecodedEditPanel(")
        self.assertGreaterEqual(count, 2, "expected ≥2 decoded-panel calls in compare view")

    def test_compare_css_side_pane_rules_present(self) -> None:
        for klass in (
            ".saip-cmp-side",
            ".saip-cmp-side-pane",
            ".saip-cmp-side-pane--a",
            ".saip-cmp-side-pane--b",
            ".saip-cmp-view-btn",
            ".cc-chip--a",
            ".cc-chip--b",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS: {klass}")

    def test_toggle_collapses_on_second_click(self) -> None:
        self.assertIn("expandTrRef = null", self.app_js)
        self.assertIn("expandTrRef = expandTr;", self.app_js)


class PeCardLintBadgeWiringTests(unittest.TestCase):
    """Pins the PE-card worst-severity lint badge injected after a linter run."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(encoding="utf-8")

    def test_build_pe_worst_severity_helper_defined(self) -> None:
        self.assertIn("function saipBuildPeWorstSeverity(", self.app_js)

    def test_pe_worst_sev_passed_to_build_card(self) -> None:
        # renderSaipPeList must compute peWorstSev and pass it to saipBuildPeCard.
        anchor = self.app_js.find("var peWorstSev = saipBuildPeWorstSeverity(")
        self.assertGreater(anchor, 0)

    def test_worst_sev_used_in_build_card(self) -> None:
        anchor = self.app_js.find("function saipBuildPeCard(")
        self.assertGreater(anchor, 0)
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("worstSev", body)
        self.assertIn("lint-fail", body)
        self.assertIn("lint-warn", body)

    def test_lint_chip_css_classes_present(self) -> None:
        for klass in (
            ".saip-pe-chip--lint-fail",
            ".saip-pe-chip--lint-warn",
            ".saip-pe-chip--lint-info",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS: {klass}")

    def test_pe_sev_rank_map_defined(self) -> None:
        self.assertIn("var _PE_SEV_RANK =", self.app_js)


class RfmCardWiringTests(unittest.TestCase):
    """Pins the RFM decoded helpers and unified PE-level routing."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_rfm_card_function_defined(self) -> None:
        self.assertIn("function saipEditorRenderRfmCard(", self.app_js)

    def test_rfm_uses_unified_direct_decoded_panel(self) -> None:
        self.assertIn("function saipIsRemoteManagementSectionKey(", self.app_js)
        self.assertIn("saipIsRemoteManagementSectionKey(sectionKey)", self.app_js)
        self.assertIn("saipDirectPeAllowsGenericDecoded(sectionKey)", self.app_js)

    def test_msl_decoder_defined(self) -> None:
        self.assertIn("function saipDecodeMsl(", self.app_js)

    def test_access_domain_decoder_defined(self) -> None:
        self.assertIn("function saipDecodeAccessDomain(", self.app_js)

    def test_tar_length_note_in_card(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRfmCard(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("tarList", body)
        self.assertIn("3 B", body)

    def test_rfm_tar_editor_action_wired(self) -> None:
        self.assertIn("async function saipRfmApplyTarList(", self.app_js)
        self.assertIn("saip.update_rfm_tars", self.app_js)
        self.assertIn("Apply TAR list", self.app_js)
        anchor = self.app_js.find('} else if (t === "rfm")')
        window = self.app_js[anchor: anchor + 240]
        self.assertIn("pkg, sectionKey, peList, validation", window)

    def test_key_reference_rendered(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRfmCard(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("keyReference", body)

    def test_msl_bits_table_defined(self) -> None:
        self.assertIn("var _MSL_BITS =", self.app_js)

    def test_access_domain_bits_table_defined(self) -> None:
        self.assertIn("var _ACCESS_DOMAIN_BITS =", self.app_js)


class TemplatePinAidArrDecodeWiringTests(unittest.TestCase):
    """Pins AID RID/PIX split + pinStatusTemplateDO + ARR-ref decoding
    added to saipEditorRenderTemplateCard."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipEditorRenderTemplateCard(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.body = self.app_js[anchor: end if end > anchor else anchor + 6000]

    def test_rid_pix_split_present(self) -> None:
        self.assertIn("RID", self.body)
        self.assertIn("PIX", self.body)

    def test_pin_status_template_bit_decode_present(self) -> None:
        self.assertIn("pinTplSub", self.body)
        self.assertIn("Enabled:", self.body)

    def test_arr_ref_fid_decode_present(self) -> None:
        self.assertIn("EF.ARR FID", self.body)
        self.assertIn("arrFid", self.body)

    def test_arr_ref_record_index_present(self) -> None:
        self.assertIn("record", self.body)

    def test_aid_kvwithsub_call(self) -> None:
        self.assertIn("saipEditorKvWithSub(card", self.body)


class EfAccHplmnDecodeWiringTests(unittest.TestCase):
    """Pins saipDecodeEfAcc / saipDecodeEfHplmn helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        # Capture the saipFileRenderData body for data-tab assertions.
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 6000]

    def test_decode_ef_acc_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfAcc(", self.app_js)

    def test_decode_ef_hplmn_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfHplmn(", self.app_js)

    def test_acc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-acc", self.data_body)
        self.assertIn("saipDecodeEfAcc(", self.data_body)

    def test_hplmn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-hplmn", self.data_body)
        self.assertIn("saipDecodeEfHplmn(", self.data_body)

    def test_acc_no_user_class_note_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfAcc(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1500]
        self.assertIn("no user class", body)

    def test_hplmn_disabled_note_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfHplmn(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1000]
        self.assertIn("disabled", body)


class EfArrDataTabAndWizardWiringTests(unittest.TestCase):
    """Pins EF.ARR record-card fallback + suppression of the hollow top wizard."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(
            encoding="utf-8",
        )

    def test_flatten_arr_records_payload_defined(self) -> None:
        self.assertIn("function saipFlattenArrRecordsPayload(", self.app_js)

    def test_synthesize_arr_records_fallback_present(self) -> None:
        self.assertIn("function saipSynthesizeRecordRowsFromLayout(", self.app_js)
        self.assertIn("function saipSynthesizeArrRecordsFromLayout(", self.app_js)

    def test_ef_arr_top_level_wizard_suppressed(self) -> None:
        anchor = self.app_js.find("function saipRenderEfWizardCard(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 450]
        self.assertIn("saipIsArrEfKey(efKey)", body)
        self.assertIn("return null", body)

    def test_no_placeholder_saip_wizards_ef_arr_assignment(self) -> None:
        self.assertNotIn('_SAIP_WIZARDS["ef-arr"]', self.app_js)

    def test_data_tab_arr_records_route_through_unified_navigator(self) -> None:
        # EF.ARR records used to live in a bespoke "ARR records" card
        # on the Decoded tab. After the Decoded → Data merge they
        # route through the unified record navigator like every other
        # record-fixed EF; the per-record decoded payload (rule
        # breakdown) is rendered by ``saipRenderBackendDecoded`` inside
        # the navigator's record block, and ``_SAIP_RECORD_WIZARDS
        # ["ef-arr"]`` provides the structured rule editor.
        anchor = self.app_js.find("function saipFileRenderData(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 24000]
        self.assertIn("saipBuildRecordNavigator({", window)
        self.assertIn("saipIsArrEfKey(efKey)", window)

    def test_frontend_reconstruction_uses_seek_cur_offsets(self) -> None:
        anchor = self.app_js.find("function saipBuildVirtualFileImage(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 2200]
        self.assertIn('ct.name === "fillFileOffset"', window)
        self.assertIn("offset += delta", window)
        self.assertNotIn("offset = newOff", window)

    def test_arr_key_helper_covers_contextual_arr_names(self) -> None:
        self.assertIn("function saipNormalizeEfKey(", self.app_js)
        self.assertIn("function saipIsArrEfKey(", self.app_js)
        anchor = self.app_js.find("function saipIsArrEfKey(")
        body = self.app_js[anchor: anchor + 500]
        self.assertIn('key.indexOf("ef-arr-") === 0', body)
        self.assertIn('key.indexOf("-ef-arr") >= 0', body)

    def test_backend_decoded_tree_folded_by_default(self) -> None:
        anchor = self.app_js.find("function saipRenderBackendDecoded(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 2200]
        self.assertIn("cc-pv-collapsible", body)
        self.assertIn("opts.decodedTreeOpen", body)


class RecordCardCollapsibleWiringTests(unittest.TestCase):
    """Per-record cards are ``<details>``-wrapped collapsed-by-default."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(
            encoding="utf-8",
        )
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(
            encoding="utf-8",
        )

    def test_record_block_uses_details_wrapper(self) -> None:
        anchor = self.app_js.find("function saipBuildRecordBlock(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 4500]
        self.assertIn('createElement("details")', body)
        self.assertIn("saip-record-fold", body)
        self.assertIn("cc-pv-collapsible", body)
        # Summary head carries the index + one-line brief.
        self.assertIn("saip-record-fold-summary", body)
        self.assertIn("saip-record-fold-idx", body)
        self.assertIn("saip-record-fold-brief", body)

    def test_record_block_has_summary_helper(self) -> None:
        self.assertIn("function _saipRecordHeadSummary(", self.app_js)

    def test_record_block_decoded_tree_opens_inside_details(self) -> None:
        # Record-fixed EFs now get the same decoded-edit form used by
        # transparent EFs. The read-only decoded tree remains as the
        # fallback when no edit-capable field is available.
        anchor = self.app_js.find("function saipBuildRecordBlock(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 6500]
        self.assertIn("saip-record-decoded-edit", body)
        self.assertIn("record-decoded:", body)
        self.assertIn("decodedTreeOpen: true", body)

    def test_record_block_generic_wizard_fallback(self) -> None:
        anchor = self.app_js.find("function saipBuildRecordBlock(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 7000]
        self.assertIn("_SAIP_RECORD_WIZARD_GENERIC", body)

    def test_record_block_css_styles_collapsible(self) -> None:
        for klass in (
            ".saip-record-fold",
            ".saip-record-fold-idx",
            ".saip-record-fold-brief",
            ".saip-record-fold-body",
        ):
            self.assertIn(klass, self.app_css, klass)

    def test_arr_wizard_button_expands_row_context(self) -> None:
        anchor = self.app_js.find("function saipRenderArrRecordRow(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 9000]
        click_anchor = body.find('wizBtn.addEventListener("click"')
        self.assertGreater(click_anchor, 0)
        click_body = body[click_anchor: click_anchor + 700]
        self.assertIn("setExpanded(true);", click_body)
        self.assertIn("wizardPanel.scrollIntoView", click_body)


class DispatcherCoverageManifestTests(unittest.TestCase):
    """The Phase 1 manifest publishes routed ef-keys for the audit."""

    def test_known_dispatcher_ef_keys_exposed(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            dispatcher_routes_ef_key,
            known_dispatcher_ef_keys,
        )

        manifest = known_dispatcher_ef_keys()
        self.assertIsInstance(manifest, frozenset)
        self.assertGreater(len(manifest), 100)
        self.assertIn("ef-arr", manifest)
        self.assertTrue(dispatcher_routes_ef_key("ef-csim-st"))
        self.assertTrue(dispatcher_routes_ef_key("ef-csim-anything"))


class AddFileModalWiringTests(unittest.TestCase):
    """The Phase 3 Add-file modal is gated, fetched, and rendered."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(
            encoding="utf-8",
        )
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(
            encoding="utf-8",
        )

    def test_pe_detail_gates_button_on_pe_supports_add_file(self) -> None:
        anchor = self.app_js.find("function renderSaipPeDetail(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 4000]
        self.assertIn("data.pe_supports_add_file === true", body)
        self.assertIn("Add file", body)
        self.assertIn("saipOpenAddFileModal(", body)

    def test_modal_opens_via_dispatcher(self) -> None:
        self.assertIn("function saipOpenAddFileModal(", self.app_js)
        self.assertIn(
            "saip.list_addable_files_for_pe/run",
            self.app_js,
        )

    def test_modal_routes_single_and_subtree_paths(self) -> None:
        self.assertIn("function saipAddTemplateFile(", self.app_js)
        self.assertIn("function saipAddTemplateSubtree(", self.app_js)
        self.assertIn(
            "saip.add_template_file/run",
            self.app_js,
        )
        self.assertIn(
            "saip.add_template_subtree/run",
            self.app_js,
        )

    def test_modal_refreshes_caches_on_success(self) -> None:
        anchor = self.app_js.find("async function saipRefreshAfterAddFile(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1200]
        self.assertIn("saipInvalidatePeTemplate", body)
        self.assertIn("pkg.showPeCache", body)
        self.assertIn("pkg.fileRows", body)
        self.assertIn("pkg.showFileCache", body)

    def test_modal_marks_present_entries_disabled(self) -> None:
        anchor = self.app_js.find("function saipBuildAddFileTreeRow(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 2400]
        self.assertIn("node.disabled === true", body)
        self.assertIn("saip-add-file-row--disabled", body)
        self.assertIn("saip-add-file-present", body)

    def test_modal_css_styles_present(self) -> None:
        for klass in (
            ".saip-add-file-btn",
            ".saip-add-file-tree",
            ".saip-add-file-row",
            ".saip-add-file-row--disabled",
            ".saip-add-file-present",
        ):
            self.assertIn(klass, self.app_css, klass)


class AddFileBackendWiringTests(unittest.TestCase):
    """``saip.show_pe`` reports add-file capability; new dispatchers register."""

    def test_show_pe_emits_pe_supports_add_file(self) -> None:
        text = Path(
            "yggdrasim_common/gui_server/actions/saip.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"pe_supports_add_file"', text)
        self.assertIn(
            'bool(hasattr(pe, "create_file"))',
            text,
        )

    def test_dispatcher_specs_registered(self) -> None:
        text = Path(
            "yggdrasim_common/gui_server/actions/saip.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'id="saip.list_addable_files_for_pe"',
            text,
        )
        self.assertIn(
            'id="saip.add_template_subtree"',
            text,
        )
        self.assertIn("LIST_ADDABLE_FILES_FOR_PE_SPEC", text)
        self.assertIn("ADD_TEMPLATE_SUBTREE_SPEC", text)

    def test_dispatchers_importable(self) -> None:
        from yggdrasim_common.gui_server.actions.saip import (
            ADD_TEMPLATE_SUBTREE_SPEC,
            LIST_ADDABLE_FILES_FOR_PE_SPEC,
            _dispatch_add_template_subtree,
            _dispatch_list_addable_files_for_pe,
        )

        self.assertEqual(
            LIST_ADDABLE_FILES_FOR_PE_SPEC.id,
            "saip.list_addable_files_for_pe",
        )
        self.assertEqual(
            ADD_TEMPLATE_SUBTREE_SPEC.id,
            "saip.add_template_subtree",
        )
        # Both dispatchers reject empty session_id without touching pySim.
        class _Ctx:
            pass

        ctx = _Ctx()
        with self.assertRaises(ValueError):
            _dispatch_list_addable_files_for_pe(
                ctx, session_id="", section_key="usim",
            )
        with self.assertRaises(ValueError):
            _dispatch_add_template_subtree(
                ctx,
                session_id="",
                section_key="usim",
                pe_names=["ef-imsi"],
            )


class BackendDecodedTreeAndDecodedTabEditWiringTests(unittest.TestCase):
    """Pins vertical backend-decoded tree rendering and decoded-tab encode-back."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(
            encoding="utf-8",
        )
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(
            encoding="utf-8",
        )

    def test_tree_helpers_defined(self) -> None:
        self.assertIn("function saipBuildBackendDecodedTree(", self.app_js)
        self.assertIn("function saipAppendBackendDecodedBranch(", self.app_js)

    def test_data_tab_mounts_decoded_edit_panel(self) -> None:
        # The Data tab keeps byte-stream reconstruction in the Hex
        # pane. The decoded side mounts semantic file-content editors
        # such as EF.ICCID and round-trip TLV payloads, while raw
        # offsets and raw hex fallbacks stay out of this surface.
        self.assertIn("saip-file-decoded-edit", self.app_js)
        self.assertNotIn("includeFillPayloadFields: true", self.app_js)
        self.assertIn("function saipDecodedIsSemanticContentField(", self.app_js)
        anchor = self.app_js.find("function saipFileRenderData(")
        self.assertGreater(anchor, 0)
        end = self.app_js.find("// ── SA-G3 Access rules tab", anchor)
        self.assertGreater(end, anchor)
        window = self.app_js[anchor:end]
        self.assertIn("saipRenderDecodedEditPanel(", window)
        self.assertIn("Use the Hex pane for byte-level fillFileContent / fillFileOffset edits.", window)

    def test_direct_decoded_mode_keeps_pin_puk_roundtrip_fields(self) -> None:
        anchor = self.app_js.find("function keepDirectDecodedField(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1300]
        self.assertIn("opts.directEditor === true && saipIsPinPukSectionKey(sectionKey)", body)
        self.assertIn('kind === "roundtrip_decoded" || kind === "json"', body)

    def test_decoded_field_match_accepts_gfm_synthetic_paths(self) -> None:
        anchor = self.app_js.find("function saipDecodedFieldsMatch(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1300]
        self.assertIn("fileManagementCMD\\[(\\d+)\\]\\[(\\d+)\\]", body)
        self.assertIn("field.gfm_file_path", body)
        self.assertIn('String(rel[0] || "") === "fileManagementCMD"', body)

    def test_data_tab_uses_record_synthesis_fallback(self) -> None:
        # When the backend omits the per-record decoded payload (older
        # response shape, or the file lives in the TCA template
        # default), the navigator falls back to a synthesised record
        # list reconstructed from the FCP descriptor + image bytes.
        anchor = self.app_js.find("function saipFileRenderData(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 24000]
        self.assertIn("saipSynthesizeRecordRowsFromLayout(image.bytes, layout)", window)

    def test_data_tab_renders_record_navigator_for_record_fixed_files(self) -> None:
        anchor = self.app_js.find("function saipFileRenderData(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 24000]
        self.assertIn("saipBuildRecordNavigator({", window)
        self.assertIn("isRecordFixedForRaw", window)

    def test_decoded_ef_wizards_are_registered(self) -> None:
        # The 42 EFs listed below close out the residual coverage gap
        # for the YggdraSIM decoded-EF wizard registry (the rest
        # already had bespoke wizards before this sweep). Each
        # registration is asserted as a literal assignment so the
        # wave does not silently regress.
        for entry in (
            '_SAIP_WIZARDS["ef-pst"]',
            '_SAIP_WIZARDS["ef-5g-prose-st"]',
            '_SAIP_WIZARDS["ef-bst"]',
            '_SAIP_WIZARDS["ef-csim-st"]',
            '_SAIP_WIZARDS["ef-mst"]',
            '_SAIP_WIZARDS["ef-vst"]',
            '_SAIP_WIZARDS["ef-plmnsel"]',
            '_SAIP_RECORD_WIZARDS["ef-ice-dn"]',
        ):
            self.assertIn(entry, self.app_js, entry)

    def test_service_table_factory_present(self) -> None:
        self.assertIn(
            "function _saipBuildServiceTableWizard(",
            self.app_js,
        )

    def test_record_fixed_check_accepts_space_separated_structure(self) -> None:
        # saipDecodeFileDescriptor returns ``structure: "linear fixed"``
        # (with a space) — the Decoded / Data tabs used to compare
        # against ``"linear-fixed"`` (with a dash) which made
        # ``isRecordFixed`` permanently false for every linear-fixed EF,
        # so neither tab entered its records-rendering branch.
        anchor_decoded = self.app_js.find("function saipFileRecordLayoutForData(")
        self.assertGreater(anchor_decoded, 0)
        body = self.app_js[anchor_decoded: anchor_decoded + 1800]
        self.assertIn('"linear fixed"', body)
        self.assertIn('"cyclic"', body)
        anchor_data = self.app_js.find("function saipFileRenderData(")
        self.assertGreater(anchor_data, 0)
        data_body = self.app_js[anchor_data: anchor_data + 8000]
        self.assertIn('"linear fixed"', data_body)
        self.assertIn('isRecordFixedForRaw', data_body)

    def test_record_fixed_data_tab_mounts_record_local_decoded_editors(self) -> None:
        # Decoded-field editors were merged into the Data tab when the
        # separate Decoded sibling tab was retired (ePC §"File
        # Content"). Record-fixed EFs render those editors inside the
        # selected record block so EF.DIR-style nested TLVs follow the
        # same single-record workflow as EF.ARR.
        nav_anchor = self.app_js.find("function saipBuildRecordNavigator(")
        self.assertGreater(nav_anchor, 0)
        nav_body = self.app_js[nav_anchor: nav_anchor + 9000]
        self.assertIn("recordDecodedEditor: true", nav_body)
        self.assertIn("recordDecodedIndex: _recordDecodedIndex(current)", nav_body)

        block_anchor = self.app_js.find("function saipBuildRecordBlock(")
        self.assertGreater(block_anchor, 0)
        block_body = self.app_js[block_anchor: block_anchor + 7000]
        self.assertIn("saipRenderDecodedEditPanel(", block_body)
        self.assertIn("saip-record-decoded-edit", block_body)

    def test_decoded_panel_skips_inner_heading_when_title_empty(self) -> None:
        anchor = self.app_js.find("async function saipRenderDecodedEditPanel(")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1400]
        self.assertIn("String(titleRaw).trim().length > 0", body)

    def test_backend_decoded_tree_css(self) -> None:
        for klass in (
            ".saip-backend-decoded-tree",
            ".saip-file-card--decoded-edit",
            ".saip-file-card-title",
        ):
            self.assertIn(klass, self.app_css, f"missing CSS: {klass}")


class GfmWizardBucketWiringTests(unittest.TestCase):
    """Pins GFM routing through the dedicated file workbench."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_gfm_uses_dedicated_file_workbench_not_pe_bucket_wizard(self) -> None:
        self.assertIn("function saipEditorRenderGfmCard(", self.app_js)
        anchor = self.app_js.find('t === "genericfilemanagement" || t === "gfm"')
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 300]
        self.assertIn("saipEditorRenderGfmCard", window)
        self.assertIn("supportsDecodedPanel = false", window)
        self.assertIn("saipFileRenderGeneral(", self.app_js)


class SparseCardWiringTests(unittest.TestCase):
    """Pins the sparse-card helper and CDMA/5G/EAP dispatch branches."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_sparse_card_function_defined(self) -> None:
        self.assertIn("function saipEditorRenderSparseCard(", self.app_js)

    def test_cdma_dispatch_branch(self) -> None:
        self.assertIn('t === "cdmaparameter"', self.app_js)

    def test_5gnas_dispatch_branch(self) -> None:
        self.assertIn('t === "5gnasparameter"', self.app_js)

    def test_eap_dispatch_branch(self) -> None:
        self.assertIn('t === "eap"', self.app_js)

    def test_untyped_fallback_updated_text(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderUntyped(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1000]
        self.assertNotIn("Typed editors land in subsequent", body)
        self.assertIn("no typed editor", body)

    def test_sparse_wizard_buckets_skip_ef_paths_for_crypto_heuristic(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderSparseParamWizard(")
        self.assertGreater(anchor, 0)
        self.assertIn("var isFsKey = (", self.app_js[anchor: anchor + 1200])


class EfAdDecodeWiringTests(unittest.TestCase):
    """Pins saipDecodeEfAd helper and its Data-tab wiring."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_decode_ef_ad_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfAd(", self.app_js)

    def test_ad_op_bits_table_defined(self) -> None:
        self.assertIn("var _AD_OP_BITS =", self.app_js)

    def test_mnc_length_label_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfAd(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 2000]
        self.assertIn("mnc_length", body)

    def test_ef_ad_decode_in_data_tab(self) -> None:
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("ef-ad", body)
        self.assertIn("saipDecodeEfAd(", body)

    def test_ef_ad_card_title_in_data_tab(self) -> None:
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("EF.AD decoded", body)


class PeEditorFilesystemDispatchTests(unittest.TestCase):
    """Pins PE editor dispatch expansions (CD / IoT / WLAN / profile header aliases)."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_cd_in_filesystem_template_branch(self) -> None:
        self.assertIn('|| t === "cd"', self.app_js)

    def test_application_branch_before_management(self) -> None:
        app_at = self.app_js.find('} else if (t === "application") {')
        mgmt_at = self.app_js.find('} else if (t === "applicationmanagement") {')
        self.assertGreater(app_at, 0)
        self.assertGreater(mgmt_at, app_at)

    def test_nonstandard_sparse_branch(self) -> None:
        self.assertIn('} else if (t === "nonstandard") {', self.app_js)

    def test_profileheader_alias(self) -> None:
        self.assertIn('if (t === "profileheader")', self.app_js)

    def test_securitydomain_ssd_alias(self) -> None:
        self.assertIn('if (t === "securitydomain_ssd")', self.app_js)

    def test_isdr_in_security_domain_branch(self) -> None:
        anchor = self.app_js.find('|| t === "isdr"')
        self.assertGreater(anchor, 0)

    def test_filesystem_branch_mounts_decoded_wizard_cards(self) -> None:
        self.assertIn("function saipEditorRenderFilesystemDecodedWizards(", self.app_js)
        cat_at = self.app_js.find("saipEditorRenderTemplateCatalogCard(")
        wiz_at = self.app_js.find("saipEditorRenderFilesystemDecodedWizards();")
        self.assertGreater(cat_at, 0)
        self.assertGreater(wiz_at, cat_at)


class ProfileHeaderConnectivityEditorWiringTests(unittest.TestCase):
    """Pins ProfileHeader POL, ICCID sync, and connectivity editor wiring."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_connectivity_uses_typed_bearer_renderer(self) -> None:
        self.assertIn("function saipConnectivityRenderBearerCard(", self.app_js)
        self.assertIn("function saipConnectivityRenderSmsFields(", self.app_js)
        self.assertIn("function saipConnectivityRenderNamedBearerFields(", self.app_js)

    def test_connectivity_render_form_no_generic_json_form(self) -> None:
        anchor = self.app_js.find("function saipConnectivityRenderForm(")
        self.assertGreater(anchor, 0)
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor:end if end > anchor else anchor + 4000]
        self.assertNotIn("saipRenderJsonAsForm", body)

    def test_profile_header_iccid_sync_control(self) -> None:
        self.assertIn("Sync from EF.ICCID", self.app_js)
        self.assertIn('"iccid_from_ef"', self.app_js)
        self.assertIn("saipConnectivityHeaderIccidDigits", self.app_js)

    def test_profile_header_pol_bitmask_control(self) -> None:
        self.assertIn('saipFormBitmaskDef("pol")', self.app_js)
        self.assertIn("Profile policy rules", self.app_js)


class SaipSecurityDomainApplicationRfmFormWiringTests(unittest.TestCase):
    """Pins PE-SD / PE-Application / PE-RFM decoded-form controls."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_access_domain_editor_wired(self) -> None:
        self.assertIn("function saipFormAccessDomainRow(", self.app_js)
        self.assertIn("_SAIP_ACCESS_DOMAIN_PARAMETER_OPTIONS", self.app_js)
        self.assertIn("Application PIN 1", self.app_js)
        self.assertIn("ADM 10", self.app_js)

    def test_sd_parameter_dropdown_and_bitmask_fields_wired(self) -> None:
        self.assertIn("Global Service Parameters", self.app_js)
        self.assertIn("Implicit Selection Parameter", self.app_js)
        self.assertIn("Restrict Parameter", self.app_js)
        self.assertIn("_SAIP_AFI_OPTIONS", self.app_js)
        self.assertIn("_SAIP_MAX_DATA_RATE_OPTIONS", self.app_js)

    def test_application_and_rfm_aid_selectors_wired(self) -> None:
        self.assertIn('fn === "instanceaid"', self.app_js)
        self.assertIn('fn === "associatedsecuritydomainaid"', self.app_js)
        self.assertIn('fn === "executableloadfileaid"', self.app_js)
        self.assertIn('fn === "moduleaid"', self.app_js)

    def test_selectable_saip_lists_wired(self) -> None:
        self.assertIn("function saipFormSelectableListInfo(", self.app_js)
        self.assertIn("Application instances", self.app_js)
        self.assertIn("Key components", self.app_js)

    def test_application_parameter_summary_card_wired(self) -> None:
        self.assertIn("function saipEditorRenderApplicationParametersCard(", self.app_js)
        self.assertIn("_application_parameter_summary", self.app_js)
        self.assertIn("Application Specific Parameters (C9)", self.app_js)
        self.assertIn("inst.applicationParameters", self.app_js)
        self.assertIn("minimumSecurityLevelRaw", self.app_js)
        self.assertIn("TAR values", self.app_js)
        self.assertIn("saipEditorTarListNode", self.app_js)
        self.assertIn("function saipSdParamBuildState(", self.app_js)
        self.assertIn("function saipSdParamApply(", self.app_js)
        self.assertIn("function saipSdIsParameterField(", self.app_js)
        self.assertIn("function saipRenderDirectPeDecodedBlock(", self.app_js)
        self.assertIn("saip.update_sd_parameters", self.app_js)
        self.assertIn("UICC Toolkit App. Specific Parameters (80)", self.app_js)
        self.assertIn("+ TAR", self.app_js)
        self.assertIn("Remove TAR", self.app_js)
        self.assertIn("Use structured fields", self.app_js)
        self.assertIn("SIM Toolkit application parameters", self.app_js)
        self.assertIn("SIM file access parameters", self.app_js)
        self.assertIn("+ TLV item", self.app_js)
        self.assertIn("Memory Management", self.app_js)
        self.assertIn("Volatile memory quota (C7)", self.app_js)
        self.assertIn("Contactless Parameters", self.app_js)
        self.assertIn("Reader Mode Protocol Data Type A", self.app_js)
        self.assertIn("Application is allowed to register a CLTObserverListener", self.app_js)
        self.assertIn("+ ADF access", self.app_js)
        self.assertIn("ts102226AdditionalContactlessParameters", self.app_js)
        self.assertIn("contactlessProtocolParameters", self.app_js)
        self.assertIn("userInteractionContactlessParameters", self.app_js)
        self.assertIn("Security Domain parameters", self.app_js)
        self.assertIn("suppressEmptyDirectEditor", self.app_js)
        self.assertIn("0x00 — Full access", self.app_js)

    def test_security_domain_dispatch_renders_parameter_card(self) -> None:
        anchor = self.app_js.find('t === "securitydomain"')
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 1200]
        self.assertIn("isSecurityDomainLike", window)
        self.assertIn("saipSdIsLeadInstanceField", window)
        self.assertIn("saipSdIsParameterField", window)
        self.assertIn("saipEditorRenderApplicationParametersCard", window)

    def test_rfm_tar_summary_fallback_wired(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRfmCard(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 1800]
        self.assertIn("decoded._tar_summary", window)
        self.assertIn("tarValues", window)
        self.assertIn("Apply TAR list", self.app_js)
        self.assertIn("saipTarEntriesFromValue", self.app_js)


class AdditionalPeTypedCardsWiringTests(unittest.TestCase):
    """Pins end/applicationManagement/ram typed cards and dispatch branches."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")

    def test_end_card_function_defined(self) -> None:
        self.assertIn("function saipEditorRenderEndCard(", self.app_js)

    def test_end_dispatch_branch(self) -> None:
        anchor = self.app_js.find('} else if (t === "end")')
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 80]
        self.assertIn("saipEditorRenderEndCard", window)

    def test_app_mgmt_card_function_defined(self) -> None:
        self.assertIn("function saipEditorRenderAppMgmtCard(", self.app_js)

    def test_app_mgmt_dispatch_branch(self) -> None:
        anchor = self.app_js.find('} else if (t === "applicationmanagement")')
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 100]
        self.assertIn("saipEditorRenderAppMgmtCard", window)

    def test_ram_card_function_defined(self) -> None:
        self.assertIn("function saipEditorRenderRamCard(", self.app_js)

    def test_ram_dispatch_branch(self) -> None:
        anchor = self.app_js.find('} else if (t === "ram")')
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 80]
        self.assertIn("saipEditorRenderRamCard", window)

    def test_app_mgmt_card_shows_rid_pix(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderAppMgmtCard(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 4000]
        self.assertIn("RID", body)
        self.assertIn("PIX", body)

    def test_ram_card_shows_sd_aid(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRamCard(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 3000]
        self.assertIn("securityDomainAID", body)
        self.assertIn("Security Domain AID", body)

    def test_aka_wizard_crypto_branch_before_broad_sqn(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderAkaWizard(")
        self.assertGreater(anchor, 0)
        crypto_at = self.app_js.find("if (cryptoFn[fn]", anchor)
        sqn_at = self.app_js.find('if (hay.indexOf("sqn")', anchor)
        self.assertGreater(crypto_at, anchor)
        self.assertGreater(sqn_at, anchor)
        self.assertLess(crypto_at, sqn_at)

    def test_rfm_wizard_buckets_instance_aid_with_access_domain(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRfmWizard(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 900]
        self.assertIn("instanceaid", window.lower())

    def test_ram_wizard_header_matches_dashed_header_suffix(self) -> None:
        anchor = self.app_js.find("function saipEditorRenderRamWizard(")
        self.assertGreater(anchor, 0)
        window = self.app_js[anchor: anchor + 700]
        self.assertIn("-header", window)


class ValRowExpandWiringTests(unittest.TestCase):
    """Pins the inline-expand detail row and clipboard copy button
    added to saipBuildValRow."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipBuildValRow(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.body = self.app_js[anchor: end if end > anchor else anchor + 5000]

    def test_detail_row_hidden_class(self) -> None:
        self.assertIn("saip-val-detail-row--hidden", self.body)

    def test_recommendation_surfaced_inline(self) -> None:
        self.assertIn("Recommendation:", self.body)

    def test_evidence_surfaced_inline(self) -> None:
        self.assertIn("Evidence:", self.body)

    def test_copy_button_present(self) -> None:
        self.assertIn("saip-val-copy-btn", self.body)
        self.assertIn("navigator.clipboard", self.body)

    def test_expand_caret_symbols(self) -> None:
        self.assertIn("▸", self.body)
        self.assertIn("▾", self.body)


class ValDomainGroupWiringTests(unittest.TestCase):
    """Pins the domain-grouped, severity-sorted validation panel rendering."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        # Capture the renderSaipValidation function body.
        anchor = self.app_js.find("function renderSaipValidation(")
        end = self.app_js.find("\n  function ", anchor + 200)
        self.body = self.app_js[anchor: end if end > anchor else anchor + 8000]

    def test_severity_sort_order_defined(self) -> None:
        self.assertIn("_SEV_ORDER", self.body)

    def test_fail_first_in_sort_order(self) -> None:
        anchor = self.body.find("_SEV_ORDER")
        snippet = self.body[anchor: anchor + 200]
        self.assertIn("FAIL", snippet)
        self.assertIn("WARN", snippet)

    def test_domain_grouping_by_yrl_code(self) -> None:
        self.assertIn("YRL-([A-Z0-9]+)-", self.body)

    def test_collapsible_domain_header_row(self) -> None:
        self.assertIn("saip-val-domain-header", self.body)
        self.assertIn("aria-expanded", self.body)

    def test_domain_caret_element(self) -> None:
        self.assertIn("saip-val-domain-caret", self.body)

    def test_domain_chips_present(self) -> None:
        self.assertIn("saip-val-domain-chips", self.body)

    def test_col_subheader_row(self) -> None:
        self.assertIn("saip-val-col-header", self.body)

    def test_keyboard_toggle_support(self) -> None:
        self.assertIn("keydown", self.body)
        self.assertIn("Enter", self.body)

    def test_findings_sorted_before_grouping(self) -> None:
        # sort() call must precede the group-building forEach
        sort_pos = self.body.find(".sort(function")
        group_pos = self.body.find("groupOrder.push")
        self.assertGreater(sort_pos, 0)
        self.assertGreater(group_pos, sort_pos)

    def test_domain_label_prefixed_yrl(self) -> None:
        self.assertIn('"YRL-" + domain', self.body)


class EfLociEpsLociImsiUstDecodeWiringTests(unittest.TestCase):
    """Pins LOCI / EPSLOCI / IMSI / UST decode helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 14000]

    def test_decode_ef_loci_defined(self) -> None:
        self.assertIn("function saipDecodeEfLoci(", self.app_js)

    def test_decode_ef_epsloci_defined(self) -> None:
        self.assertIn("function saipDecodeEfEpsLoci(", self.app_js)

    def test_decode_ef_imsi_defined(self) -> None:
        self.assertIn("function saipDecodeEfImsi(", self.app_js)

    def test_decode_ef_ust_defined(self) -> None:
        self.assertIn("function saipDecodeEfUst(", self.app_js)

    def test_loci_wired_in_data_tab(self) -> None:
        self.assertIn("ef-loci", self.data_body)
        self.assertIn("saipDecodeEfLoci(", self.data_body)

    def test_epsloci_wired_in_data_tab(self) -> None:
        self.assertIn("ef-epsloci", self.data_body)
        self.assertIn("saipDecodeEfEpsLoci(", self.data_body)

    def test_imsi_wired_in_data_tab(self) -> None:
        self.assertIn("ef-imsi", self.data_body)
        self.assertIn("saipDecodeEfImsi(", self.data_body)

    def test_ust_wired_in_data_tab(self) -> None:
        self.assertIn("ef-ust", self.data_body)
        self.assertIn("saipDecodeEfUst(", self.data_body)

    def test_loci_card_label(self) -> None:
        self.assertIn("EF.LOCI decoded", self.data_body)

    def test_epsloci_card_label(self) -> None:
        self.assertIn("EF.EPSLOCI decoded", self.data_body)

    def test_imsi_card_label(self) -> None:
        self.assertIn("EF.IMSI decoded", self.data_body)

    def test_ust_card_label(self) -> None:
        self.assertIn("EF.UST decoded", self.data_body)

    def test_ust_keeps_file_content_editor_and_skips_duplicate_payload_cards(self) -> None:
        self.assertIn("function saipDecodedEditOwnsWholeFileWizard(", self.app_js)
        self.assertIn('key === "ef-ust"', self.app_js)
        self.assertIn("function saipDirectDecodedEditorOwnsBackendPayload(", self.app_js)
        self.assertIn("var directDecodedOwnsPayload = saipDirectDecodedEditorOwnsBackendPayload(efKey);", self.data_body)
        self.assertIn("var skipLegacyDecoders = directDecodedOwnsPayload;", self.data_body)
        self.assertIn("&& !directDecodedOwnsPayload", self.data_body)

    def test_loci_lus_labels_present(self) -> None:
        anchor = self.app_js.find("_LOCI_LUS_LABELS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("updated", body)
        self.assertIn("not allowed", body)

    def test_ust_service_labels_fdn_present(self) -> None:
        anchor = self.app_js.find("_UST_SERVICE_LABELS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 1500]
        self.assertIn("FDN", body)
        self.assertIn("IMS", body)


class EfSuciUacAcmLiDecodeWiringTests(unittest.TestCase):
    """Pins SUCI-CALC-INFO / UAC-AIC / ACM / ACMmax / LI decode helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 34000]

    def test_suci_calc_info_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfSuciCalcInfo(", self.app_js)

    def test_uac_aic_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfUacAic(", self.app_js)

    def test_acm_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfAcm(", self.app_js)

    def test_acm_max_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfAcmMax(", self.app_js)

    def test_suci_wired_in_data_tab(self) -> None:
        self.assertIn("ef-suci-calc-info", self.data_body)
        self.assertIn("saipDecodeEfSuciCalcInfo(", self.data_body)

    def test_uac_wired_in_data_tab(self) -> None:
        self.assertIn("ef-uac-aic", self.data_body)
        self.assertIn("saipDecodeEfUacAic(", self.data_body)

    def test_acm_wired_in_data_tab(self) -> None:
        self.assertIn("ef-acm", self.data_body)
        self.assertIn("saipDecodeEfAcm(", self.data_body)

    def test_li_reuses_pl_decoder(self) -> None:
        self.assertIn("ef-li", self.data_body)
        self.assertIn("saipDecodeEfPl(", self.data_body)

    def test_suci_scheme_labels_present(self) -> None:
        anchor = self.app_js.find("_SUCI_SCHEME_LABELS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("Profile A", body)
        self.assertIn("Profile B", body)

    def test_uac_aic_access_class_labels(self) -> None:
        anchor = self.app_js.find("_UAC_AIC_BITS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 500]
        self.assertIn("emergency", body)
        self.assertIn("Class 15", body)

    def test_suci_card_label(self) -> None:
        self.assertIn("EF.SUCI-CALC-INFO decoded", self.data_body)

    def test_acm_no_limit_note(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfAcmMax(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 400]
        self.assertIn("no call barring", body)


class EfEpsnscKcHfnRiLoci5gDecodeWiringTests(unittest.TestCase):
    """Pins EPSNSC / KC / START-HFN / RoutingIndicator / 5GS-LOCI decode helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 28000]

    def test_decode_ef_epsnsc_defined(self) -> None:
        self.assertIn("function saipDecodeEfEpsnsc(", self.app_js)

    def test_decode_ef_kc_defined(self) -> None:
        self.assertIn("function saipDecodeEfKc(", self.app_js)

    def test_decode_ef_start_hfn_defined(self) -> None:
        self.assertIn("function saipDecodeEfStartHfn(", self.app_js)

    def test_decode_ef_routing_indicator_defined(self) -> None:
        self.assertIn("function saipDecodeEfRoutingIndicator(", self.app_js)

    def test_decode_ef_5gs_loci_defined(self) -> None:
        self.assertIn("function saipDecodeEf5gsLoci(", self.app_js)

    def test_epsnsc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-epsnsc", self.data_body)
        self.assertIn("saipDecodeEfEpsnsc(", self.data_body)

    def test_kc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-kc", self.data_body)
        self.assertIn("saipDecodeEfKc(", self.data_body)

    def test_start_hfn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-start-hfn", self.data_body)
        self.assertIn("saipDecodeEfStartHfn(", self.data_body)

    def test_routing_indicator_wired_in_data_tab(self) -> None:
        self.assertIn("ef-routing-indicator", self.data_body)
        self.assertIn("saipDecodeEfRoutingIndicator(", self.data_body)

    def test_5gs_loci_wired_in_data_tab(self) -> None:
        self.assertIn("ef-5gs3gpploci", self.data_body)
        self.assertIn("saipDecodeEf5gsLoci(", self.data_body)

    def test_epsnsc_algo_labels(self) -> None:
        anchor = self.app_js.find("_EPSNSC_NAS_ALG_ENC")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 200]
        self.assertIn("EEA0", body)

    def test_hfn_threshold_warning(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfStartHfn(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 800]
        self.assertIn("threshold", body)

    def test_5gs_update_status_labels(self) -> None:
        anchor = self.app_js.find("_5GS_UPDATE_STATUS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("5GU1", body)


class EfIccidEhplmnPlGidDecodeWiringTests(unittest.TestCase):
    """Pins ICCID / EHPLMN / PL / GID decode helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 22000]

    def test_decode_ef_iccid_defined(self) -> None:
        self.assertIn("function saipDecodeEfIccid(", self.app_js)

    def test_decode_ef_ehplmn_defined(self) -> None:
        self.assertIn("function saipDecodeEfEhplmn(", self.app_js)

    def test_decode_ef_pl_defined(self) -> None:
        self.assertIn("function saipDecodeEfPl(", self.app_js)

    def test_decode_ef_gid_defined(self) -> None:
        self.assertIn("function saipDecodeEfGid(", self.app_js)

    def test_iccid_wired_in_data_tab(self) -> None:
        self.assertIn("ef-iccid", self.data_body)
        self.assertIn("saipDecodeEfIccid(", self.data_body)

    def test_ehplmn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-ehplmn", self.data_body)
        self.assertIn("saipDecodeEfEhplmn(", self.data_body)

    def test_pl_wired_in_data_tab(self) -> None:
        self.assertIn("ef-pl", self.data_body)
        self.assertIn("saipDecodeEfPl(", self.data_body)

    def test_gid1_wired_in_data_tab(self) -> None:
        self.assertIn("ef-gid1", self.data_body)
        self.assertIn("saipDecodeEfGid(", self.data_body)

    def test_iccid_card_label(self) -> None:
        self.assertIn("EF.ICCID decoded", self.data_body)

    def test_ehplmn_card_label(self) -> None:
        self.assertIn("EF.EHPLMN decoded", self.data_body)

    def test_pl_card_label(self) -> None:
        self.assertIn("EF.PL decoded", self.data_body)

    def test_iccid_iin_extraction(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfIccid(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1000]
        self.assertIn("IIN", body)

    def test_pl_iso639_hint(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfPl(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 800]
        self.assertIn("0xFF", body)


class EfKeysMsisdnMwisEccDecodeWiringTests(unittest.TestCase):
    """Pins KEYS / MSISDN / MWIS / ECC decode helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 18000]

    def test_decode_ef_keys_defined(self) -> None:
        self.assertIn("function saipDecodeEfKeys(", self.app_js)

    def test_decode_ef_msisdn_defined(self) -> None:
        self.assertIn("function saipDecodeEfMsisdn(", self.app_js)

    def test_decode_ef_mwis_defined(self) -> None:
        self.assertIn("function saipDecodeEfMwis(", self.app_js)

    def test_decode_ef_ecc_defined(self) -> None:
        self.assertIn("function saipDecodeEfEcc(", self.app_js)

    def test_bcd_number_helper_defined(self) -> None:
        self.assertIn("function saipDecodeBcdNumber(", self.app_js)

    def test_keys_wired_in_data_tab(self) -> None:
        self.assertIn("ef-keys", self.data_body)
        self.assertIn("saipDecodeEfKeys(", self.data_body)

    def test_msisdn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-msisdn", self.data_body)
        self.assertIn("saipDecodeEfMsisdn(", self.data_body)

    def test_mwis_wired_in_data_tab(self) -> None:
        self.assertIn("ef-mwis", self.data_body)
        self.assertIn("saipDecodeEfMwis(", self.data_body)

    def test_ecc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-ecc", self.data_body)
        self.assertIn("saipDecodeEfEcc(", self.data_body)

    def test_keys_card_label(self) -> None:
        self.assertIn("EF.KEYS decoded", self.data_body)

    def test_msisdn_card_label(self) -> None:
        self.assertIn("EF.MSISDN decoded", self.data_body)

    def test_mwis_status_bits_present(self) -> None:
        anchor = self.app_js.find("_MWIS_STATUS_BITS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("Voicemail", body)

    def test_ecc_service_bits_present(self) -> None:
        anchor = self.app_js.find("_ECC_SERVICE_BITS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("ambulance", body)

    def test_keys_ksi_sentinel_note(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfKeys(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1000]
        self.assertIn("0x07", body)


class EfEstFplmnDecodeWiringTests(unittest.TestCase):
    """Pins saipDecodeEfEst / saipDecodeEfFplmn helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 10000]

    def test_decode_ef_est_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfEst(", self.app_js)

    def test_decode_ef_fplmn_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfFplmn(", self.app_js)

    def test_plmn_bytes_helper_defined(self) -> None:
        self.assertIn("function saipDecodePlmnBytes(", self.app_js)

    def test_est_wired_in_data_tab(self) -> None:
        self.assertIn("ef-est", self.data_body)
        self.assertIn("saipDecodeEfEst(", self.data_body)

    def test_fplmn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-fplmn", self.data_body)
        self.assertIn("saipDecodeEfFplmn(", self.data_body)

    def test_est_bit_labels_present(self) -> None:
        anchor = self.app_js.find("_EST_BIT_LABELS")
        self.assertGreater(anchor, 0)
        body = self.app_js[anchor: anchor + 500]
        self.assertIn("FDN", body)
        self.assertIn("ACL", body)

    def test_est_decoded_card_label(self) -> None:
        self.assertIn("EF.EST decoded", self.data_body)

    def test_fplmn_decoded_card_label(self) -> None:
        self.assertIn("EF.FPLMN decoded", self.data_body)

    def test_fplmn_slot_count_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfFplmn(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1500]
        self.assertIn("slot", body)


class EfSpnSmspDecodeWiringTests(unittest.TestCase):
    """Pins saipDecodeEfSpn / saipDecodeEfSmsp helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 8000]

    def test_decode_ef_spn_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfSpn(", self.app_js)

    def test_decode_ef_smsp_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfSmsp(", self.app_js)

    def test_spn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-spn", self.data_body)
        self.assertIn("saipDecodeEfSpn(", self.data_body)

    def test_smsp_wired_in_data_tab(self) -> None:
        self.assertIn("ef-smsp", self.data_body)
        self.assertIn("saipDecodeEfSmsp(", self.data_body)

    def test_spn_display_conditions_decoded(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfSpn(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 2000]
        self.assertIn("display-conditions", body)
        self.assertIn("HPLMN", body)

    def test_spn_all_ff_check(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfSpn(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 2000]
        self.assertIn("not configured", body)

    def test_smsp_minimum_length_check(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfSmsp(")
        end = self.app_js.find("\n  function ", anchor + 100)
        body = self.app_js[anchor: end if end > anchor else anchor + 1500]
        self.assertIn("28", body)
        self.assertIn("alphaLen = byteLen - 28", body)
        self.assertIn("Parameter indicators", body)

    def test_smsp_wizard_uses_variable_alpha_and_28_byte_footer(self) -> None:
        self.assertIn("recordSize < 28", self.app_js)
        self.assertIn("alphaLen = recordSize - 28", self.app_js)
        self.assertIn("Parameter block (28 B)", self.app_js)
        self.assertNotIn("EF.SMSP records are 38 B", self.app_js)

    def test_iccid_imsi_use_backend_decoded_editor_only(self) -> None:
        self.assertIn("function saipDecodedEditOwnsWholeFileWizard(", self.app_js)
        self.assertIn('key === "ef-iccid" || key === "ef-imsi"', self.app_js)

    def test_proper_whole_file_wizard_suppresses_generic_file_content_editor(self) -> None:
        self.assertIn('_SAIP_WIZARDS["ef-dir"]', self.app_js)
        anchor = self.data_body.find("Primary file-body editing surface")
        self.assertGreater(anchor, 0)
        body = self.data_body[anchor: anchor + 1800]
        self.assertIn("&& !wizardCard", body)
        self.assertIn("suppressEmptyDirectFileEditor: !!wizardCard", body)

    def test_spn_ef_decoded_card_label(self) -> None:
        self.assertIn("EF.SPN decoded", self.data_body)

    def test_smsp_ef_decoded_card_label(self) -> None:
        self.assertIn("EF.SMSP decoded", self.data_body)


class EfSmssSimpleDecodesWiringTests(unittest.TestCase):
    """Pins saipDecodeEfSmss / saipDecodeEfPuct / saipDecodeEfSpdi /
    saipDecodeEfMbi / saipDecodeEfPsc / saipDecodeEfCc /
    saipDecodeEfNetpar and their Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 24000]

    def test_smss_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfSmss(", self.app_js)

    def test_puct_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfPuct(", self.app_js)

    def test_spdi_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfSpdi(", self.app_js)

    def test_mbi_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfMbi(", self.app_js)

    def test_psc_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfPsc(", self.app_js)

    def test_cc_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfCc(", self.app_js)

    def test_netpar_function_defined(self) -> None:
        self.assertIn("function saipDecodeEfNetpar(", self.app_js)

    def test_smss_wired_in_data_tab(self) -> None:
        self.assertIn("ef-smss", self.data_body)
        self.assertIn("saipDecodeEfSmss(", self.data_body)

    def test_puct_wired_in_data_tab(self) -> None:
        self.assertIn("ef-puct", self.data_body)
        self.assertIn("saipDecodeEfPuct(", self.data_body)

    def test_spdi_wired_in_data_tab(self) -> None:
        self.assertIn("ef-spdi", self.data_body)
        self.assertIn("saipDecodeEfSpdi(", self.data_body)

    def test_mbi_wired_in_data_tab(self) -> None:
        self.assertIn("ef-mbi", self.data_body)
        self.assertIn("saipDecodeEfMbi(", self.data_body)

    def test_psc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-psc", self.data_body)
        self.assertIn("saipDecodeEfPsc(", self.data_body)

    def test_cc_wired_in_data_tab(self) -> None:
        self.assertIn("ef-cc", self.data_body)
        self.assertIn("saipDecodeEfCc(", self.data_body)

    def test_netpar_wired_in_data_tab(self) -> None:
        self.assertIn("ef-netpar", self.data_body)
        self.assertIn("saipDecodeEfNetpar(", self.data_body)

    def test_smss_mce_label_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfSmss(")
        body = self.app_js[anchor: anchor + 800]
        self.assertIn("MCE", body)

    def test_spdi_plmn_helper_reuse(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfSpdi(")
        body = self.app_js[anchor: anchor + 1500]
        self.assertIn("saipDecodePlmnBytes", body)

    def test_mbi_voice_label_in_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfMbi(")
        body = self.app_js[anchor: anchor + 800]
        self.assertIn("Voice", body)


class AdnPnnOplExt1DecodeWiringTests(unittest.TestCase):
    """Pins saipDecodeAdnRecord / saipDecodeAdnFile / saipDecodeEfPnn /
    saipDecodeEfOpl / saipDecodeEfExt1 helpers and Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 26000]

    def test_adn_record_helper_defined(self) -> None:
        self.assertIn("function saipDecodeAdnRecord(", self.app_js)

    def test_adn_file_helper_defined(self) -> None:
        self.assertIn("function saipDecodeAdnFile(", self.app_js)

    def test_pnn_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfPnn(", self.app_js)

    def test_opl_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfOpl(", self.app_js)

    def test_ext1_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfExt1(", self.app_js)

    def test_fdn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-fdn", self.data_body)
        self.assertIn("saipDecodeAdnFile(", self.data_body)

    def test_bdn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-bdn", self.data_body)

    def test_sdn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-sdn", self.data_body)

    def test_mbdn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-mbdn", self.data_body)

    def test_pnn_wired_in_data_tab(self) -> None:
        self.assertIn("ef-pnn", self.data_body)
        self.assertIn("saipDecodeEfPnn(", self.data_body)

    def test_opl_wired_in_data_tab(self) -> None:
        self.assertIn("ef-opl", self.data_body)
        self.assertIn("saipDecodeEfOpl(", self.data_body)

    def test_ext1_wired_in_data_tab(self) -> None:
        self.assertIn("ef-ext1", self.data_body)
        self.assertIn("saipDecodeEfExt1(", self.data_body)

    def test_adn_record_uses_bcd_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeAdnRecord(")
        body = self.app_js[anchor: anchor + 1500]
        self.assertIn("saipDecodeBcdNumber", body)

    def test_opl_uses_plmn_helper(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfOpl(")
        body = self.app_js[anchor: anchor + 1200]
        self.assertIn("saipDecodePlmnBytes", body)

    def test_pnn_gsm_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfPnn(")
        body = self.app_js[anchor: anchor + 1200]
        self.assertIn("Full name", body)

    def test_fdn_card_label(self) -> None:
        self.assertIn("EF.FDN decoded", self.data_body)

    def test_pnn_card_label(self) -> None:
        self.assertIn("EF.PNN decoded", self.data_body)

    def test_opl_card_label(self) -> None:
        self.assertIn("EF.OPL decoded", self.data_body)

    def test_ext1_card_label(self) -> None:
        self.assertIn("EF.EXT1 decoded", self.data_body)


class CbSmsCfisIsimMiscDecodeWiringTests(unittest.TestCase):
    """Pins CB/SMS/CFIS/ISIM/misc helpers and their Data-tab dispatch."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 36000]

    # --- helpers present ---
    def test_cblist_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfCbList(", self.app_js)

    def test_sms_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfSms(", self.app_js)

    def test_cfis_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfCfis(", self.app_js)

    def test_impi_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfImpi(", self.app_js)

    def test_domain_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfDomain(", self.app_js)

    def test_impu_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfImpu(", self.app_js)

    def test_ist_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfIst(", self.app_js)

    def test_pcscf_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfPcscf(", self.app_js)

    def test_text_label_helper_defined(self) -> None:
        self.assertIn("function saipDecodeTextLabel(", self.app_js)

    def test_uid_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfUid(", self.app_js)

    def test_invscan_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfInvscan(", self.app_js)

    def test_sume_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfSume(", self.app_js)

    def test_umpc_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfUmpc(", self.app_js)

    def test_dir_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfDir(", self.app_js)

    def test_arr_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfArr(", self.app_js)

    # --- dispatch wired ---
    def test_cbmi_wired(self) -> None:
        self.assertIn("ef-cbmi", self.data_body)
        self.assertIn("saipDecodeEfCbList(", self.data_body)

    def test_cbmir_wired(self) -> None:
        self.assertIn("ef-cbmir", self.data_body)

    def test_sms_wired(self) -> None:
        self.assertIn("ef-sms", self.data_body)
        self.assertIn("saipDecodeEfSms(", self.data_body)

    def test_cfis_wired(self) -> None:
        self.assertIn("ef-cfis", self.data_body)
        self.assertIn("saipDecodeEfCfis(", self.data_body)

    def test_impi_wired(self) -> None:
        self.assertIn("ef-impi", self.data_body)
        self.assertIn("saipDecodeEfImpi(", self.data_body)

    def test_domain_wired(self) -> None:
        self.assertIn("ef-domain", self.data_body)
        self.assertIn("saipDecodeEfDomain(", self.data_body)

    def test_impu_wired(self) -> None:
        self.assertIn("ef-impu", self.data_body)
        self.assertIn("saipDecodeEfImpu(", self.data_body)

    def test_ist_wired(self) -> None:
        self.assertIn("ef-ist", self.data_body)
        self.assertIn("saipDecodeEfIst(", self.data_body)

    def test_pcscf_wired(self) -> None:
        self.assertIn("ef-pcscf", self.data_body)
        self.assertIn("saipDecodeEfPcscf(", self.data_body)

    def test_aas_wired(self) -> None:
        self.assertIn("ef-aas", self.data_body)
        self.assertIn("saipDecodeTextLabel(", self.data_body)

    def test_gas_wired(self) -> None:
        self.assertIn("ef-gas", self.data_body)

    def test_uid_wired(self) -> None:
        self.assertIn("ef-uid", self.data_body)
        self.assertIn("saipDecodeEfUid(", self.data_body)

    def test_sume_wired(self) -> None:
        self.assertIn("ef-sume", self.data_body)
        self.assertIn("saipDecodeEfSume(", self.data_body)

    def test_umpc_wired(self) -> None:
        self.assertIn("ef-umpc", self.data_body)
        self.assertIn("saipDecodeEfUmpc(", self.data_body)

    def test_dir_wired(self) -> None:
        self.assertIn("ef-dir", self.data_body)
        self.assertIn("saipDecodeEfDir(", self.data_body)

    def test_arr_wired(self) -> None:
        # EF.ARR dispatch is covered by ``saipIsArrEfKey(efKey)`` (a
        # tolerant matcher that also catches contextual paths like
        # ``efIccProfile/ef-arr`` from nested file systems) plus the
        # ``saipDecodeEfArr`` summary helper. Either reference path is
        # acceptable — the test guards the wiring, not the literal.
        self.assertTrue(
            "ef-arr" in self.data_body or "saipIsArrEfKey" in self.data_body,
            "EF.ARR dispatch missing from saipFileRenderData",
        )
        self.assertIn("saipDecodeEfArr(", self.data_body)

    # --- content spot-checks ---
    def test_cb_range_mode_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfCbList(")
        body = self.app_js[anchor: anchor + 1000]
        self.assertIn("range(s)", body)

    def test_sms_status_labels(self) -> None:
        anchor = self.app_js.find("_SMS_STATUS_LABELS")
        body = self.app_js[anchor: anchor + 300]
        self.assertIn("free slot", body)
        self.assertIn("MT read", body)

    def test_ist_service_label(self) -> None:
        anchor = self.app_js.find("_IST_SERVICE_LABELS")
        body = self.app_js[anchor: anchor + 400]
        self.assertIn("SM over IP", body)

    def test_pcscf_ipv4_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfPcscf(")
        body = self.app_js[anchor: anchor + 1600]
        self.assertIn("IPv4", body)
        self.assertIn("FQDN", body)

    # --- card labels ---
    def test_sms_card_label(self) -> None:
        self.assertIn("EF.SMS decoded", self.data_body)

    def test_cfis_card_label(self) -> None:
        self.assertIn("EF.CFIS decoded", self.data_body)

    def test_impi_card_label(self) -> None:
        self.assertIn("EF.IMPI decoded", self.data_body)

    def test_pcscf_card_label(self) -> None:
        self.assertIn("EF.PCSCF decoded", self.data_body)

    def test_dir_card_label(self) -> None:
        self.assertIn("EF.DIR decoded", self.data_body)


class FinalSevenEfDecodeWiringTests(unittest.TestCase):
    """Pins the last 7 EF decode helpers (PBR, CCP1, CPBCCH, GBA, NAFKCA,
    UICCIARI, RMA) and verifies that the dispatch gap is fully closed."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        anchor = self.app_js.find("function saipFileRenderData(")
        end = self.app_js.find("\n  function ", anchor + 100)
        self.data_body = self.app_js[anchor: end if end > anchor else anchor + 44000]

    # --- helpers defined ---
    def test_pbr_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfPbr(", self.app_js)

    def test_ccp1_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfCcp1(", self.app_js)

    def test_cpbcch_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfCpbcch(", self.app_js)

    def test_gba_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfGba(", self.app_js)

    def test_nafkca_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfNafkca(", self.app_js)

    def test_uicciari_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfUicciari(", self.app_js)

    def test_rma_helper_defined(self) -> None:
        self.assertIn("function saipDecodeEfRma(", self.app_js)

    # --- dispatch wired ---
    def test_pbr_wired(self) -> None:
        self.assertIn("ef-pbr", self.data_body)
        self.assertIn("saipDecodeEfPbr(", self.data_body)

    def test_ccp1_wired(self) -> None:
        self.assertIn("ef-ccp1", self.data_body)
        self.assertIn("saipDecodeEfCcp1(", self.data_body)

    def test_cpbcch_wired(self) -> None:
        self.assertIn("ef-cpbcch", self.data_body)
        self.assertIn("saipDecodeEfCpbcch(", self.data_body)

    def test_gba_wired(self) -> None:
        self.assertIn("ef-gba", self.data_body)
        self.assertIn("saipDecodeEfGba(", self.data_body)

    def test_nafkca_wired(self) -> None:
        self.assertIn("ef-nafkca", self.data_body)
        self.assertIn("saipDecodeEfNafkca(", self.data_body)

    def test_uicciari_wired(self) -> None:
        self.assertIn("ef-uicciari", self.data_body)
        self.assertIn("saipDecodeEfUicciari(", self.data_body)

    def test_rma_wired(self) -> None:
        self.assertIn("ef-rma", self.data_body)
        self.assertIn("saipDecodeEfRma(", self.data_body)

    # --- content spot-checks ---
    def test_pbr_type_labels(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfPbr(")
        body = self.app_js[anchor: anchor + 1800]
        self.assertIn("Type-1", body)
        self.assertIn("Type-2", body)
        self.assertIn("Type-3", body)

    def test_pbr_inner_tag_label(self) -> None:
        anchor = self.app_js.find("_PBR_INNER_TAG_LABELS")
        body = self.app_js[anchor: anchor + 600]
        self.assertIn("EF.ADN", body)

    def test_cpbcch_arfcn_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfCpbcch(")
        body = self.app_js[anchor: anchor + 900]
        self.assertIn("ARFCN", body)

    def test_gba_btid_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfGba(")
        body = self.app_js[anchor: anchor + 1400]
        self.assertIn("B-TID", body)

    def test_nafkca_fqdn_label(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfNafkca(")
        body = self.app_js[anchor: anchor + 800]
        self.assertIn("FQDN", body)

    def test_uicciari_tag80(self) -> None:
        anchor = self.app_js.find("function saipDecodeEfUicciari(")
        body = self.app_js[anchor: anchor + 900]
        self.assertIn("IARI", body)

    # --- card labels ---
    def test_pbr_card_label(self) -> None:
        self.assertIn("EF.PBR decoded", self.data_body)

    def test_gba_card_label(self) -> None:
        self.assertIn("EF.GBA decoded", self.data_body)

    def test_uicciari_card_label(self) -> None:
        self.assertIn("EF.UICCIARI decoded", self.data_body)

    # --- zero gap assertion ---
    def test_all_registered_ef_keys_have_dispatch(self) -> None:
        # Coverage criteria: every EF advertised in the FID map must be
        # reachable through one of three render paths —
        #  1. a legacy ``efKey === "ef-X"`` branch in saipFileRenderData
        #     (the historical text-decoder pipeline),
        #  2. a transparent-EF wizard registered in ``_SAIP_WIZARDS``,
        #  3. a record-fixed wizard registered in
        #     ``_SAIP_RECORD_WIZARDS``,
        # plus the structural EF.ARR helper (saipIsArrEfKey) which
        # owns the per-record decoder dispatch end-to-end.
        import re
        fid_keys = set(re.findall(r'"(ef-[a-z0-9-]+)": \["[0-9A-F]{4}"', self.app_js))
        branch_keys = set(re.findall(r'efKey === "(ef-[a-z0-9-]+)"', self.app_js))
        wizard_keys = set(
            re.findall(r'_SAIP_WIZARDS\["(ef-[a-z0-9-]+)"\]', self.app_js),
        )
        wizard_keys |= set(
            re.findall(r'"(ef-[a-z0-9-]+)":\s*_SAIP_WIZARD_', self.app_js),
        )
        record_wizard_keys = set(
            re.findall(r'_SAIP_RECORD_WIZARDS\["(ef-[a-z0-9-]+)"\]', self.app_js),
        )
        record_wizard_keys |= set(
            re.findall(r'"(ef-[a-z0-9-]+)":\s*_SAIP_RECORD_WIZARD_', self.app_js),
        )
        covered = branch_keys | wizard_keys | record_wizard_keys | {"ef-arr"}
        missing = sorted(fid_keys - covered)
        self.assertEqual(
            missing, [],
            msg="EF keys registered in FID map but missing from saipFileRenderData dispatch: "
                + str(missing),
        )


if __name__ == "__main__":
    unittest.main()
