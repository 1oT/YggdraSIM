# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit tests for SAIP TRANSCODE-TUI quick-add (blank PE templates)."""

import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import (
    _TAG_BYTES,
    _TAG_TUPLE,
    build_decoded_document_from_sequence,
    build_profile_sequence_from_document,
    encode_der_from_document,
    ensure_workspace_pysim_on_path,
)
from Tools.ProfilePackage.saip_pe_quick_add import (
    copy_pe_snapshot,
    file_add_override_defaults,
    gfm_root_bootstrap_defaults,
    insert_blank_pe_for_menu_id,
    insert_blank_file_for_pename,
    iter_option_list_specs,
    list_addable_file_rows,
    list_pe_quick_add_rows,
    move_pe_in_document,
    paste_pe_snapshot,
    remove_pe_from_document,
)
from Tools.ProfilePackage.saip_tool import SaipToolBridge


class TestSaipPeQuickAdd(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        from pySim.esim.saip import ProfileElementEnd, ProfileElementHeader, ProfileElementSequence

        cls._ProfileElementEnd = ProfileElementEnd
        cls._ProfileElementHeader = ProfileElementHeader
        cls._ProfileElementSequence = ProfileElementSequence
        cls._bridge = SaipToolBridge(cls.workspace_root)

    def _base_document(self, intro_line: str = "probe") -> dict:
        pes = self._ProfileElementSequence()
        pes.append(self._ProfileElementHeader())
        pes.append(self._ProfileElementEnd())
        return build_decoded_document_from_sequence(pes, intro_lines=[intro_line])

    def _document_with_pes(self, *menu_ids: str) -> dict:
        document = self._base_document("filesystem")
        for menu_id in menu_ids:
            document = insert_blank_pe_for_menu_id(
                document,
                self.workspace_root,
                menu_id=menu_id,
            )
        return document

    def _reference_document(self) -> dict:
        resolved = self._bridge.resolve_input_path(
            "Tools/ProfilePackage/profile/reference_test_profile.txt",
            must_exist=True,
        )
        raw = self._bridge._prepare_input_for_tool(resolved).read_bytes()
        pes = self._ProfileElementSequence.from_der(raw)
        return build_decoded_document_from_sequence(pes, intro_lines=["reference"])

    def test_insert_mf_before_end_roundtrips(self) -> None:
        doc = self._base_document("probe")
        doc2 = insert_blank_pe_for_menu_id(doc, self.workspace_root, menu_id="mf")
        der = encode_der_from_document(doc2, self.workspace_root)
        pes2 = self._ProfileElementSequence.from_der(der)
        types = [pe.type for pe in pes2.pe_list]
        self.assertEqual(types, ["header", "mf", "end"])

    def test_duplicate_header_rejected(self) -> None:
        doc = self._base_document("x")
        with self.assertRaises(ValueError) as ctx:
            insert_blank_pe_for_menu_id(doc, self.workspace_root, menu_id="header")
        self.assertIn("header", str(ctx.exception).lower())

    def test_iter_option_list_specs_has_cancel(self) -> None:
        rows = iter_option_list_specs(set())
        self.assertEqual(rows[0][0], "_cancel")
        ids = {r[0] for r in rows}
        self.assertIn("usim", ids)
        self.assertIn("securityDomain_ssd", ids)

    def test_blocked_disables_header_row(self) -> None:
        rows = iter_option_list_specs({"header"})
        header_row = next(r for r in rows if r[0] == "header")
        self.assertTrue(header_row[3])

    def test_quick_add_rows_include_application_and_nonstandard(self) -> None:
        row_ids = {row[0] for row in list_pe_quick_add_rows()}
        self.assertIn("application", row_ids)
        self.assertIn("nonStandard", row_ids)

    def test_insert_blank_application_adds_application_section(self) -> None:
        updated = insert_blank_pe_for_menu_id(
            self._base_document("application"),
            self.workspace_root,
            menu_id="application",
        )
        self.assertIn("application", updated["sections"])

    def test_insert_blank_nonstandard_adds_round_trippable_section(self) -> None:
        updated = insert_blank_pe_for_menu_id(
            self._base_document("nonStandard"),
            self.workspace_root,
            menu_id="nonStandard",
        )
        self.assertIn("nonStandard", updated["sections"])
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertIn("nonStandard", [pe.type for pe in rebuilt.pe_list])

    def test_insert_blank_pe_after_selected_anchor(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("anchor"),
            self.workspace_root,
            menu_id="mf",
        )
        updated = insert_blank_pe_for_menu_id(
            doc,
            self.workspace_root,
            menu_id="application",
            anchor_key="header",
            insert_after=True,
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "application", "mf", "end"],
        )

    def test_insert_blank_pe_before_selected_anchor(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("anchor-before"),
            self.workspace_root,
            menu_id="mf",
        )
        updated = insert_blank_pe_for_menu_id(
            doc,
            self.workspace_root,
            menu_id="application",
            anchor_key="mf",
            insert_after=False,
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "application", "mf", "end"],
        )

    def test_move_pe_in_document_reorders_between_regular_pes(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("move"),
            self.workspace_root,
            menu_id="mf",
        )
        doc = insert_blank_pe_for_menu_id(
            doc,
            self.workspace_root,
            menu_id="application",
        )
        updated = move_pe_in_document(
            doc,
            self.workspace_root,
            section_key="application",
            direction="up",
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "application", "mf", "end"],
        )

    def test_move_header_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            move_pe_in_document(
                self._base_document("header"),
                self.workspace_root,
                section_key="header",
                direction="down",
            )
        self.assertIn("anchored", str(ctx.exception).lower())

    def test_copy_paste_selected_pe_after_anchor_duplicates_section(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("copy"),
            self.workspace_root,
            menu_id="application",
        )
        snapshot = copy_pe_snapshot(doc, section_key="application")
        updated = paste_pe_snapshot(
            doc,
            self.workspace_root,
            snapshot=snapshot,
            anchor_key="application",
            insert_after=True,
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "application", "application", "end"],
        )

    def test_copy_paste_without_anchor_defaults_before_end(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("copy-default"),
            self.workspace_root,
            menu_id="application",
        )
        snapshot = copy_pe_snapshot(doc, section_key="application")
        updated = paste_pe_snapshot(
            doc,
            self.workspace_root,
            snapshot=snapshot,
            anchor_key=None,
            insert_after=True,
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "application", "application", "end"],
        )

    def test_remove_pe_from_document_removes_selected_section(self) -> None:
        doc = insert_blank_pe_for_menu_id(
            self._base_document("remove"),
            self.workspace_root,
            menu_id="mf",
        )
        doc = insert_blank_pe_for_menu_id(
            doc,
            self.workspace_root,
            menu_id="application",
        )
        updated = remove_pe_from_document(
            doc,
            self.workspace_root,
            section_key="application",
        )
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "mf", "end"],
        )

    def test_remove_header_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            remove_pe_from_document(
                self._base_document("remove-header"),
                self.workspace_root,
                section_key="header",
            )
        self.assertIn("anchored", str(ctx.exception).lower())

    def test_list_addable_file_rows_filters_root_and_nested_context(self) -> None:
        document = self._document_with_pes("mf", "telecom")

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="telecom",
        )
        row_ids = {row[0] for row in rows}
        self.assertIsNone(context_key)
        self.assertEqual(context_label, "DF.TELECOM")
        self.assertIn("df-graphics", row_ids)
        self.assertIn("ef-sume", row_ids)
        self.assertIn("ef-img", row_ids)
        ef_img_row = next(row for row in rows if row[0] == "ef-img")
        self.assertIn("creates DF.GRAPHICS", ef_img_row[2] or "")

        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="telecom",
            file_pe_name="df-graphics",
        )
        nested_context_key, nested_context_label, nested_rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="telecom",
            context_key="df-graphics",
        )
        nested_row_ids = {row[0] for row in nested_rows}
        self.assertEqual(nested_context_key, "df-graphics")
        self.assertEqual(nested_context_label, "DF.GRAPHICS")
        self.assertIn("ef-img", nested_row_ids)
        self.assertNotIn("ef-sume", nested_row_ids)

    def test_list_addable_file_rows_shows_dynamic_arr_in_pe_and_dir_context(self) -> None:
        document = self._document_with_pes("mf", "telecom")
        arr_record = "8001019000800102A406830101950108"
        document["sections"]["telecom"]["ef-arr"] = [
            {
                _TAG_TUPLE: [
                    "fileDescriptor",
                    {
                        "fileDescriptor": {_TAG_BYTES: "4221001010"},
                        "efFileSize": {_TAG_BYTES: "0100"},
                        "shortEFID": {_TAG_BYTES: "06"},
                        "lcsi": {_TAG_BYTES: "05"},
                    },
                ]
            },
            {
                _TAG_TUPLE: [
                    "fillFileOffset",
                    0,
                ]
            },
            {
                _TAG_TUPLE: [
                    "fillFileContent",
                    {
                        _TAG_BYTES: arr_record * 16,
                    },
                ]
            },
        ]

        _context_key, _context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="telecom",
        )
        ef_sume_row = next(row for row in rows if row[0] == "ef-sume")
        self.assertIn("ARR", ef_sume_row[2] or "")
        self.assertIn("Always", ef_sume_row[2] or "")
        self.assertIn("PIN1", ef_sume_row[2] or "")

        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="telecom",
            file_pe_name="df-graphics",
        )
        _nested_context_key, _nested_context_label, nested_rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="telecom",
            context_key="df-graphics",
        )
        ef_img_row = next(row for row in nested_rows if row[0] == "ef-img")
        self.assertIn("ARR", ef_img_row[2] or "")
        self.assertIn("Always", ef_img_row[2] or "")
        self.assertIn("PIN1", ef_img_row[2] or "")

    def test_insert_blank_file_for_pename_roundtrips_nested_telecom_file(self) -> None:
        document = self._document_with_pes("mf", "telecom")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="telecom",
            file_pe_name="df-graphics",
        )
        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="telecom",
            file_pe_name="ef-img",
            context_key="df-graphics",
        )

        telecom_section = updated["sections"]["telecom"]
        self.assertIn("df-graphics", telecom_section)
        self.assertIn("ef-img", telecom_section)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "mf", "telecom", "end"],
        )

    def test_insert_blank_file_for_pename_auto_creates_missing_parent_df(self) -> None:
        document = self._document_with_pes("mf", "telecom")
        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="telecom",
            file_pe_name="ef-img",
        )

        telecom_section = updated["sections"]["telecom"]
        self.assertIn("df-graphics", telecom_section)
        self.assertIn("ef-img", telecom_section)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "mf", "telecom", "end"],
        )

    def test_insert_blank_file_for_pename_roundtrips_optional_usim_file(self) -> None:
        document = self._document_with_pes("mf", "usim", "opt-usim")
        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="opt-usim",
            file_pe_name="ef-pnn",
        )

        self.assertIn("ef-pnn", updated["sections"]["opt-usim"])
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        self.assertEqual(
            [pe.type for pe in rebuilt.pe_list],
            ["header", "mf", "usim", "opt-usim", "end"],
        )

    def test_list_addable_file_rows_rejects_non_filesystem_pe(self) -> None:
        document = self._document_with_pes("application")
        with self.assertRaises(ValueError) as ctx:
            list_addable_file_rows(
                document,
                self.workspace_root,
                section_key="application",
            )
        self.assertIn("does not support", str(ctx.exception).lower())

    def test_list_addable_file_rows_supports_generic_file_management_context(self) -> None:
        document = self._reference_document()

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7F10))
        self.assertEqual(context_label, "MF/DF.TELECOM")
        self.assertIn("df-graphics", row_ids)
        self.assertIn("ef-img", row_ids)
        self.assertIn("df-phonebook", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_file_management_context(self) -> None:
        document = self._reference_document()

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-img",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F10/5F50", generic.files)
        self.assertIn("3F00/7F10/5F50/4F20", generic.files)

    def test_list_addable_file_rows_supports_root_generic_tree_creation(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00,))
        self.assertEqual(context_label, "MF")
        self.assertIn("adf-usim", row_ids)
        self.assertIn("adf-isim", row_ids)
        self.assertIn("adf-usim::ef-pnn", row_ids)
        self.assertTrue(any(row_id.startswith("adf-isim::") for row_id in row_ids))
        self.assertIn("df-cd", row_ids)
        self.assertIn("df-telecom", row_ids)
        self.assertIn("df-gsm", row_ids)
        self.assertIn("df-pkcs15", row_ids)
        self.assertIn("df-gsm-access", row_ids)
        self.assertIn("ef-pcscf", row_ids)
        self.assertIn("ef-launchpad", row_ids)
        self.assertIn("ef-sume", row_ids)
        self.assertIn("ef-img", row_ids)
        self.assertIn("ef-pnn", row_ids)
        self.assertIn("ef-pkcs15-odf", row_ids)
        adf_usim_row = next(row for row in rows if row[0] == "adf-usim")
        adf_isim_row = next(row for row in rows if row[0] == "adf-isim")
        df_cd_row = next(row for row in rows if row[0] == "df-cd")
        df_telecom_row = next(row for row in rows if row[0] == "df-telecom")
        df_gsm_row = next(row for row in rows if row[0] == "df-gsm")
        df_pkcs15_row = next(row for row in rows if row[0] == "df-pkcs15")
        df_gsm_access_row = next(row for row in rows if row[0] == "df-gsm-access")
        ef_pcscf_row = next(row for row in rows if row[0] == "ef-pcscf")
        ef_launchpad_row = next(row for row in rows if row[0] == "ef-launchpad")
        ef_sume_row = next(row for row in rows if row[0] == "ef-sume")
        ef_img_row = next(row for row in rows if row[0] == "ef-img")
        ef_pnn_row = next(row for row in rows if row[0] == "ef-pnn")
        ef_odf_row = next(row for row in rows if row[0] == "ef-pkcs15-odf")
        self.assertIn("creates EF.ARR", adf_usim_row[2] or "")
        self.assertIn("creates EF.ARR", adf_isim_row[2] or "")
        self.assertIn("directory file", df_cd_row[2] or "")
        self.assertIn("creates EF.ARR", df_telecom_row[2] or "")
        self.assertIn("creates EF.ARR", df_gsm_row[2] or "")
        self.assertIn("creates EF.ARR", df_pkcs15_row[2] or "")
        self.assertIn("creates ADF.USIM / EF.ARR", df_gsm_access_row[2] or "")
        self.assertIn("creates ADF.ISIM / EF.ARR", ef_pcscf_row[2] or "")
        self.assertIn("creates DF.CD", ef_launchpad_row[2] or "")
        self.assertIn("creates DF.TELECOM / EF.ARR", ef_sume_row[2] or "")
        self.assertIn("creates DF.TELECOM / EF.ARR / DF.GRAPHICS", ef_img_row[2] or "")
        self.assertIn("creates DF.GSM / EF.ARR", ef_pnn_row[2] or "")
        self.assertIn("creates DF.PKCS15 / EF.ARR", ef_odf_row[2] or "")

    def test_gfm_root_bootstrap_defaults_reports_adf_usim_defaults(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        defaults = gfm_root_bootstrap_defaults(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim::ef-pnn",
        )

        self.assertIsNotNone(defaults)
        assert defaults is not None
        self.assertEqual(defaults["root_kind"], "adf-usim")
        self.assertEqual(defaults["temporary_fid"], "7FF0")
        self.assertEqual(defaults["aid_prefix"], "A0000000871002")

    def test_file_add_override_defaults_reports_descriptor_fields(self) -> None:
        document = self._document_with_pes("mf", "usim", "opt-usim")

        defaults = file_add_override_defaults(
            document,
            self.workspace_root,
            section_key="opt-usim",
            file_pe_name="ef-pnn",
        )

        self.assertIsNotNone(defaults)
        assert defaults is not None
        self.assertEqual(defaults["file_name"], "EF.PNN")
        self.assertEqual(defaults["file_type"], "LF")
        self.assertEqual(defaults["short_efid"], "25")
        self.assertEqual(defaults["arr_record"], "10")
        self.assertEqual(defaults["record_length"], "16")
        self.assertEqual(defaults["record_count"], "10")

    def test_insert_blank_file_for_pename_applies_filesystem_file_overrides(self) -> None:
        document = self._document_with_pes("mf", "usim", "opt-usim")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="opt-usim",
            file_pe_name="ef-pnn",
            file_overrides={
                "short_efid": "28",
                "arr_record": "12",
                "record_length": "20",
                "record_count": "4",
            },
        )

        descriptor_payload = dict(updated["sections"]["opt-usim"]["ef-pnn"])[
            "fileDescriptor"
        ]
        self.assertEqual(descriptor_payload["shortEFID"], bytes.fromhex("1C"))
        self.assertEqual(
            descriptor_payload["securityAttributesReferenced"],
            bytes.fromhex("0C"),
        )
        self.assertEqual(descriptor_payload["efFileSize"], bytes.fromhex("50"))
        self.assertEqual(
            descriptor_payload["fileDescriptor"],
            bytes.fromhex("42210014"),
        )

    def test_insert_blank_file_for_pename_applies_gfm_file_overrides(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim::ef-pnn",
            file_overrides={
                "short_efid": "28",
                "arr_record": "12",
                "record_length": "20",
                "record_count": "4",
            },
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        target_group = commands[-1]
        target_payload = dict(target_group)["createFCP"]
        self.assertEqual(target_payload["shortEFID"], bytes.fromhex("1C"))
        self.assertEqual(
            target_payload["securityAttributesReferenced"],
            bytes.fromhex("0C"),
        )
        self.assertEqual(target_payload["efFileSize"], bytes.fromhex("50"))
        self.assertEqual(target_payload["fileDescriptor"], bytes.fromhex("42210014"))

    def test_insert_blank_file_for_pename_creates_root_generic_adf_usim_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF0", generic.files)
        self.assertIn("3F00/7FF0/6F06", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_adf_isim_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-isim",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF2", generic.files)
        self.assertIn("3F00/7FF2/6F06", generic.files)

    def test_insert_blank_file_for_pename_supports_custom_adf_usim_bootstrap(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim::ef-pnn",
            bootstrap_overrides={
                "temporary_fid": "7FF1",
                "df_name": "A0000000871002FF1122334455667788",
            },
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF1", generic.files)
        self.assertIn("3F00/7FF1/6F06", generic.files)
        self.assertIn("3F00/7FF1/6FC5", generic.files)

        context_key, context_label, rows = list_addable_file_rows(
            updated,
            self.workspace_root,
            section_key="genericFileManagement",
            group_index=0,
        )
        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7FF1))
        self.assertEqual(context_label, "MF/ADF.USIM")
        self.assertIn("ef-li", row_ids)

        updated = insert_blank_file_for_pename(
            updated,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-li",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF1/6F05", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_cd_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-cd",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 1)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F11", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_gsm_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-gsm",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F20", generic.files)
        self.assertIn("3F00/7F20/6F06", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_pkcs15_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-pkcs15",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F50", generic.files)
        self.assertIn("3F00/7F50/6F06", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_telecom_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-telecom",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F10", generic.files)
        self.assertIn("3F00/7F10/6F06", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_adf_usim_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-gsm-access",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 3)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF0", generic.files)
        self.assertIn("3F00/7FF0/6F06", generic.files)
        self.assertIn("3F00/7FF0/5F3B", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_adf_isim_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-pcscf",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 3)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF2", generic.files)
        self.assertIn("3F00/7FF2/6F06", generic.files)
        self.assertIn("3F00/7FF2/6F09", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_cd_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-launchpad",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 2)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F11", generic.files)
        self.assertIn("3F00/7F11/6F01", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_gsm_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-pnn",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 3)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F20", generic.files)
        self.assertIn("3F00/7F20/6F06", generic.files)
        self.assertIn("3F00/7F20/6FC5", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_telecom_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-img",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 4)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F10", generic.files)
        self.assertIn("3F00/7F10/6F06", generic.files)
        self.assertIn("3F00/7F10/5F50", generic.files)
        self.assertIn("3F00/7F10/5F50/4F20", generic.files)

    def test_insert_blank_file_for_pename_creates_root_generic_pkcs15_descendant_tree(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-pkcs15-odf",
        )

        commands = updated["sections"]["genericFileManagement"]["fileManagementCMD"]
        self.assertEqual(len(commands), 3)
        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F50", generic.files)
        self.assertIn("3F00/7F50/6F06", generic.files)
        self.assertIn("3F00/7F50/5031", generic.files)

    def test_list_addable_file_rows_supports_generic_adf_usim_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim",
        )

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7FF0))
        self.assertEqual(context_label, "MF/ADF.USIM")
        self.assertIn("ef-li", row_ids)
        self.assertIn("df-gsm-access", row_ids)
        self.assertIn("df-phonebook", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_adf_usim_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-usim",
        )

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-gsm-access",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF0/5F3B", generic.files)

    def test_list_addable_file_rows_supports_generic_adf_isim_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-isim",
        )

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7FF2))
        self.assertEqual(context_label, "MF/ADF.ISIM")
        self.assertIn("ef-pcscf", row_ids)
        self.assertIn("ef-uicciari", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_adf_isim_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="adf-isim",
        )

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-pcscf",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7FF2/6F09", generic.files)

    def test_list_addable_file_rows_supports_generic_df_cd_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-cd",
        )

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7F11))
        self.assertEqual(context_label, "MF/DF.CD")
        self.assertIn("ef-launchpad", row_ids)
        self.assertIn("ef-icon", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_df_cd_context(self) -> None:
        document = self._document_with_pes("mf", "genericFileManagement")
        document = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="df-cd",
        )

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement",
            file_pe_name="ef-launchpad",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic = next(pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement")
        self.assertIn("3F00/7F11/6F01", generic.files)

    def test_list_addable_file_rows_supports_generic_df_gsm_context(self) -> None:
        document = self._reference_document()

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement_2",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7F20))
        self.assertEqual(context_label, "MF/DF.GSM")
        self.assertIn("ef-cpbcch", row_ids)
        self.assertIn("ef-invscan", row_ids)
        self.assertIn("ef-pnn", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_df_gsm_context(self) -> None:
        document = self._reference_document()

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement_2",
            file_pe_name="ef-cpbcch",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic_sections = [
            pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement"
        ]
        self.assertIn("3F00/7F20/6F63", generic_sections[1].files)

    def test_list_addable_file_rows_supports_generic_pkcs15_context(self) -> None:
        document = self._reference_document()
        pkcs_commands = list(document["sections"]["genericFileManagement_4"]["fileManagementCMD"][0])
        document["sections"]["genericFileManagement_4"]["fileManagementCMD"][0] = pkcs_commands[:-2]

        context_key, context_label, rows = list_addable_file_rows(
            document,
            self.workspace_root,
            section_key="genericFileManagement_4",
            group_index=0,
        )

        row_ids = {row[0] for row in rows}
        self.assertEqual(context_key, (0x3F00, 0x7F50))
        self.assertEqual(context_label, "MF/DF.PKCS15")
        self.assertIn("ef-pkcs15-accf", row_ids)

    def test_insert_blank_file_for_pename_supports_generic_pkcs15_context(self) -> None:
        document = self._reference_document()
        pkcs_commands = list(document["sections"]["genericFileManagement_4"]["fileManagementCMD"][0])
        document["sections"]["genericFileManagement_4"]["fileManagementCMD"][0] = pkcs_commands[:-2]

        updated = insert_blank_file_for_pename(
            document,
            self.workspace_root,
            section_key="genericFileManagement_4",
            file_pe_name="ef-pkcs15-accf",
            group_index=0,
        )

        rebuilt = build_profile_sequence_from_document(updated, self.workspace_root)
        generic_sections = [
            pe for pe in rebuilt.pe_list if pe.type == "genericFileManagement"
        ]
        self.assertIn("3F00/7F50/4310", generic_sections[3].files)


if __name__ == "__main__":
    unittest.main()
