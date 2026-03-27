"""Unit tests for SAIP TRANSCODE-TUI quick-add (blank PE templates)."""

import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
    build_profile_sequence_from_document,
    encode_der_from_document,
    ensure_workspace_pysim_on_path,
)
from Tools.ProfilePackage.saip_pe_quick_add import (
    copy_pe_snapshot,
    insert_blank_pe_for_menu_id,
    iter_option_list_specs,
    list_pe_quick_add_rows,
    move_pe_in_document,
    paste_pe_snapshot,
)


class TestSaipPeQuickAdd(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        from pySim.esim.saip import ProfileElementEnd, ProfileElementHeader, ProfileElementSequence

        cls._ProfileElementEnd = ProfileElementEnd
        cls._ProfileElementHeader = ProfileElementHeader
        cls._ProfileElementSequence = ProfileElementSequence

    def _base_document(self, intro_line: str = "probe") -> dict:
        pes = self._ProfileElementSequence()
        pes.append(self._ProfileElementHeader())
        pes.append(self._ProfileElementEnd())
        return build_decoded_document_from_sequence(pes, intro_lines=[intro_line])

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


if __name__ == "__main__":
    unittest.main()
