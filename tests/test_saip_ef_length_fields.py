# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Length fields follow the stored token values.

A template hard-codes the length byte in front of a placeholder-filled
BCD field. The file view, a complete export and the linter read the
field the way the card does (3GPP TS 31.102 §4.4.2.3 dialling-number
tail, §4.2.2 EF.IMSI, §4.2.27 EF.SMSP) and reconcile the byte.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.lint_engine import SaipProfileLinter
from Tools.ProfilePackage.saip_ef_length_fields import (
    apply_length_edits,
    coding_for_file,
    derive_length_edits,
    iter_document_files,
    reconcile_document,
    record_size_from_descriptor,
    substitute_ranges,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_HEX = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
# The reference profile's DF.TELECOM EF.MSISDN record: a 14-byte alpha
# identifier, length 09, TON/NPI 91 and an 8-byte number.
_MSISDN_TAIL = "099101000000000000F1"
_MSISDN_VALUE = "48273525111"
_MSISDN_HEX = "8472535211F1FFFF"
_MSISDN = coding_for_file("EF.MSISDN")
_IMSI = coding_for_file("EF.IMSI")
_SMSP = coding_for_file("EF.SMSP")


def _adn_record(alpha_len: int, length_byte: int, ton: int, number_hex: str, tail: str = "FFFF") -> bytes:
    return bytes.fromhex(
        "FF" * alpha_len + f"{length_byte:02X}{ton:02X}" + number_hex.ljust(20, "F") + tail
    )


def _smsp_record(indicators: int, tp_da_hex: str, sca_hex: str) -> bytes:
    return bytes.fromhex(
        f"{indicators:02X}" + tp_da_hex.ljust(24, "F") + sca_hex.ljust(24, "F") + "FFFFFF"
    )


class DeriveLengthEditsTests(unittest.TestCase):
    def test_dialling_tail_counts_ton_npi_and_digit_bytes(self) -> None:
        record = _adn_record(20, 0x09, 0x91, _MSISDN_HEX)
        edits = derive_length_edits(_MSISDN, record, 34)
        self.assertEqual(len(edits), 1)
        edit = edits[0]
        self.assertEqual((edit.record, edit.offset, edit.declared, edit.derived), (1, 20, 9, 7))
        self.assertEqual(edit.digits, 11)
        self.assertEqual(edit.value_hex, "07")
        self.assertEqual(edit.template_hex, "09")
        self.assertIn("EF.MSISDN record 1: Length of BCD number/SSC contents 09 -> 07", edit.describe())
        self.assertIn("1 TON/NPI byte + 6 BCD byte(s) for 11 digit(s)", edit.describe())
        self.assertEqual(apply_length_edits(record, edits)[20], 0x07)
        self.assertEqual(edit.to_wire()["kind"], "length_field")
        self.assertEqual((edit.to_wire()["start"], edit.to_wire()["end"]), (20, 21))

    def test_consistent_unused_and_short_records(self) -> None:
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x07, 0x91, _MSISDN_HEX), 34), [])
        self.assertEqual(derive_length_edits(_MSISDN, b"\xff" * 34, 34), [])
        # A short image reads as FF beyond its end; the tail still counts.
        short = _adn_record(14, 0x09, 0x91, _MSISDN_HEX)[:24]
        edits = derive_length_edits(_MSISDN, short, 28)
        self.assertEqual([(edit.record, edit.offset, edit.derived) for edit in edits], [(1, 14, 7)])
        # Only the mismatched record of several is reported: three digits
        # take two bytes, plus the TON/NPI byte.
        image = _adn_record(20, 0x07, 0x91, _MSISDN_HEX) + _adn_record(20, 0x0B, 0x91, "21F3")
        edits = derive_length_edits(_MSISDN, image, 34)
        self.assertEqual([(edit.record, edit.offset, edit.derived, edit.digits) for edit in edits], [(2, 54, 3, 3)])
        # A length that says "unused" in front of digits is a mismatch too.
        edits = derive_length_edits(_MSISDN, _adn_record(20, 0xFF, 0x91, _MSISDN_HEX), 34)
        self.assertEqual([(edit.declared, edit.derived) for edit in edits], [(0xFF, 7)])

    def test_malformed_fields_are_left_alone(self) -> None:
        # TON/NPI 'FF' is only valid without a number (TS 31.102 §4.4.2.3).
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x09, 0xFF, _MSISDN_HEX), 34), [])
        # A digit after the F endmark, and a nibble outside the digit table.
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x09, 0x91, "F123"), 34), [])
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x09, 0x91, "8472"), 34)[0].derived, 3)
        # '*', '#', 'a', 'b', 'c' are digits of a dialling string.
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x09, 0x91, "A1CB"), 34)[0].derived, 3)
        # The dialling tail never counts more than 11 bytes.
        self.assertEqual(derive_length_edits(_MSISDN, _adn_record(20, 0x03, 0x91, "12" * 10), 34)[0].derived, 11)

    def test_skip_ranges_cover_unresolved_placeholders(self) -> None:
        record = _adn_record(20, 0x09, 0x91, _MSISDN_HEX)
        self.assertEqual(derive_length_edits(_MSISDN, record, 34, skip_ranges=[(22, 30)]), [])
        self.assertEqual(len(derive_length_edits(_MSISDN, record, 34, skip_ranges=[(0, 5)])), 1)

    def test_other_tails_and_fixed_offsets(self) -> None:
        bdn = coding_for_file("EF.BDN")
        record = _adn_record(14, 0x09, 0x91, _MSISDN_HEX, tail="FFFFFF")
        self.assertEqual(len(record), 29)
        edits = derive_length_edits(bdn, record, 29)
        self.assertEqual([(edit.offset, edit.derived) for edit in edits], [(14, 7)])
        cfis = coding_for_file("EF.CFIS")
        record = bytes.fromhex("0100" + "0991" + _MSISDN_HEX.ljust(20, "F") + "FFFF")
        self.assertEqual(len(record), 16)
        edits = derive_length_edits(cfis, record, 16)
        self.assertEqual([(edit.offset, edit.derived, edit.label) for edit in edits], [(2, 7, "Length of BCD number")])
        oci = coding_for_file("EF.OCI")
        record = _adn_record(4, 0x09, 0x91, _MSISDN_HEX, tail="FF" * 15)
        self.assertEqual(len(record), 31)
        self.assertEqual([edit.offset for edit in derive_length_edits(oci, record, 31)], [4])

    def test_imsi_length_counts_significant_bytes(self) -> None:
        self.assertEqual(derive_length_edits(_IMSI, bytes.fromhex("089999990000000000")), [])
        # 13 digits: the parity byte plus six digit bytes.
        edits = derive_length_edits(_IMSI, bytes.fromhex("0819103254769800FFFF"[:18]))
        self.assertEqual([(edit.record, edit.offset, edit.derived, edit.digits) for edit in edits], [(0, 0, 7, 13)])
        self.assertIn("significant byte(s)", edits[0].describe())
        self.assertEqual(derive_length_edits(_IMSI, b"\xff" * 9), [])
        # A hex digit that is not decimal is not an IMSI.
        self.assertEqual(derive_length_edits(_IMSI, bytes.fromhex("08A9FFFFFFFFFFFFFF")), [])

    def test_extension_records_count_their_additional_data(self) -> None:
        ext = coding_for_file("EF.EXT1")
        # Type 02 additional data: 12 more digits take 6 BCD bytes.
        record = bytes.fromhex("02" + "0A" + "214365872143" + "FFFFFFFF" + "FF")
        self.assertEqual(len(record), 13)
        edits = derive_length_edits(ext, record, 13)
        self.assertEqual([(edit.offset, edit.declared, edit.derived, edit.digits) for edit in edits], [(1, 10, 6, 12)])
        self.assertIn("EF.EXT1 record 1: Length of extension data 0A -> 06 (6 BCD byte(s) for 12 digit(s))", edits[0].describe())
        self.assertEqual(derive_length_edits(ext, bytes.fromhex("0206214365872143FFFFFFFFFF"), 13), [])
        # A subaddress record (type 01) or a free record is not counted.
        self.assertEqual(derive_length_edits(ext, bytes.fromhex("010A214365872143FFFFFFFFFF"), 13), [])
        self.assertEqual(derive_length_edits(ext, b"\xff" * 13, 13), [])
        for name, fid in (("EF.EXT2", "6F4B"), ("EF.EXT3", "6F4C"), ("EF.EXT4", "6F55"), ("EF.EXT5", "6F4E"), ("EF.EXT6", "6FC8"), ("EF.EXT7", "6FCC")):
            self.assertIs(coding_for_file(name, fid), coding_for_file("", fid, parent_fid="7F10"))

    def test_smsp_addresses_honour_the_parameter_indicators(self) -> None:
        # FD: TP-DA absent (bit 1), SC address present (bit 2).
        record = _smsp_record(0xFD, "00" * 12, "069153133254F6")
        self.assertEqual(derive_length_edits(_SMSP, record, 28), [])
        record = _smsp_record(0xFD, "00" * 12, "089153133254F6")
        edits = derive_length_edits(_SMSP, record, 28)
        self.assertEqual([(edit.offset, edit.derived, edit.label) for edit in edits], [(13, 6, "TS-Service Centre Address length")])
        # FC: both present; the TP-DA length counts semi-octets.
        record = _smsp_record(0xFC, "0B918472535211F1", "069153133254F6")
        self.assertEqual(derive_length_edits(_SMSP, record, 28), [])
        record = _smsp_record(0xFC, "0C918472535211F1", "069153133254F6")
        edits = derive_length_edits(_SMSP, record, 28)
        self.assertEqual([(edit.offset, edit.derived, edit.digits) for edit in edits], [(1, 11, 11)])
        self.assertIn("useful semi-octet(s)", edits[0].describe())
        # An alpha identifier shifts every offset.
        record = b"\x41" * 4 + _smsp_record(0xFC, "0C918472535211F1", "069153133254F6")
        self.assertEqual([edit.offset for edit in derive_length_edits(_SMSP, record, 32)], [5])


class CodingLookupTests(unittest.TestCase):
    def test_names_identifiers_and_parents(self) -> None:
        for name in ("EF.MSISDN", "ef-msisdn", "EF_MSISDN", "msisdn"):
            self.assertIs(coding_for_file(name), _MSISDN)
        self.assertIs(coding_for_file("EF.MSISDN", "6F40"), _MSISDN)
        self.assertIsNone(coding_for_file("EF.MSISDN", "6F41"))
        self.assertIsNone(coding_for_file("EF.ICON", "6F40"))
        self.assertIs(coding_for_file("", "6F40", parent_fid="7F10"), _MSISDN)
        self.assertIsNone(coding_for_file("", "6F40", parent_fid="5F50"))
        self.assertIsNone(coding_for_file("", "4F30", parent_fid="5F3A"))
        self.assertIs(coding_for_file("", "0x6f07"), _IMSI)
        self.assertEqual(_IMSI.structure, "transparent")

    def test_descriptor_record_size(self) -> None:
        self.assertEqual(record_size_from_descriptor({"fileDescriptor": bytes.fromhex("42210022")}), (34, None))
        self.assertEqual(
            record_size_from_descriptor({"fileDescriptor": {"hex": "4221002202"}, "efFileSize": {"hex": "44"}}),
            (34, 68),
        )
        self.assertEqual(record_size_from_descriptor({"fileDescriptor": bytes.fromhex("4121")}), (None, None))
        self.assertEqual(record_size_from_descriptor("nope"), (None, None))

    def test_substitute_ranges_uses_only_fitting_values(self) -> None:
        image = bytes.fromhex("00" * 4)
        ranges = [
            {"start": 1, "end": 3, "value_hex": "AABB"},
            {"start": 3, "end": 4, "value_hex": "CCDD"},
            {"start": 0, "end": 1, "value_hex": ""},
        ]
        self.assertEqual(substitute_ranges(image, ranges).hex().upper(), "00AABB00")


def _gfm_group(fid_hex: str, descriptor_hex: str, fill: bytes) -> list:
    return [
        ("filePath", bytes.fromhex("7F10")),
        (
            "createFCP",
            {
                "fileID": bytes.fromhex(fid_hex),
                "fileDescriptor": bytes.fromhex(descriptor_hex),
                "efFileSize": bytes([len(fill)]),
            },
        ),
        ("fillFileContent", fill),
    ]


def _document(msisdn_record: bytes, gfm_fill: bytes, *, gfm_descriptor: str = "4221001C") -> dict:
    return {
        "sections": {
            "header": {"type": "header", "iccid": bytes.fromhex("89880812345678901234")},
            "mf": {"type": "mf"},
            "opt-usim": {
                "type": "opt-usim",
                "ef-msisdn": [
                    ("fileDescriptor", {"fileDescriptor": bytes.fromhex("42210022")}),
                    ("fillFileContent", msisdn_record),
                ],
            },
            "genericFileManagement": {
                "type": "genericFileManagement",
                "fileManagementCMD": [_gfm_group("6F40", gfm_descriptor, gfm_fill)],
            },
            "end": {"type": "end"},
        }
    }


class IterDocumentFilesTests(unittest.TestCase):
    def test_lists_template_and_gfm_files_with_their_sizes(self) -> None:
        template_record = _adn_record(20, 0x09, 0x91, _MSISDN_HEX)
        gfm_fill = _adn_record(14, 0x09, 0x91, _MSISDN_HEX)[:24]
        document = _document(template_record, gfm_fill)
        files = list(iter_document_files(document))
        self.assertEqual(
            [(f.section_key, f.path, f.fid, f.parent_fid, f.record_size, f.link_path) for f in files],
            [
                ("opt-usim", "ef-msisdn", "6F40", "", 34, ""),
                ("genericFileManagement", "7F10/6F40", "6F40", "7F10", 28, ""),
            ],
        )
        self.assertEqual(files[0].image, template_record)
        self.assertEqual(files[1].image, gfm_fill)
        # A hint fills a size the descriptor does not carry.
        document["sections"]["opt-usim"]["ef-msisdn"][0] = ("fileDescriptor", {})
        hinted = list(iter_document_files(document, record_sizes={("opt-usim", "ef-msisdn"): 40}))
        self.assertEqual(hinted[0].record_size, 40)
        self.assertEqual(list(iter_document_files({"sections": None})), [])
        self.assertEqual(list(iter_document_files(None)), [])

    def test_link_path_names_the_shared_file(self) -> None:
        document = {
            "sections": {
                "usim": {
                    "ef-smsp": [
                        ("fileDescriptor", {"linkPath": bytes.fromhex("7F106F42"), "lcsi": b"\x05"}),
                    ],
                    "ef-arr": [("fileDescriptor", {"linkPath": bytes.fromhex("2F06")})],
                },
            },
        }
        files = list(iter_document_files(document))
        self.assertEqual([(f.path, f.link_path, f.image) for f in files], [
            ("ef-smsp", "7F10/6F42", b""),
            ("ef-arr", "3F00/2F06", b""),
        ])


class ReconcileDocumentTests(unittest.TestCase):
    def test_patches_template_and_gfm_entries_in_a_copy(self) -> None:
        template_record = _adn_record(20, 0x09, 0x91, _MSISDN_HEX)
        gfm_fill = _adn_record(14, 0x09, 0x91, _MSISDN_HEX)[:24]
        document = _document(template_record, gfm_fill)
        rewritten, edits = reconcile_document(document)
        self.assertEqual(
            sorted((item.section_key, item.path, item.edit.offset, item.patched) for item in edits),
            [
                ("genericFileManagement", "fileManagementCMD.7F10/6F40", 14, True),
                ("opt-usim", "ef-msisdn", 20, True),
            ],
        )
        self.assertEqual(rewritten["sections"]["opt-usim"]["ef-msisdn"][1][1][20], 0x07)
        group = rewritten["sections"]["genericFileManagement"]["fileManagementCMD"][0]
        self.assertEqual(group[2][1][14], 0x07)
        # The input document is left as it was.
        self.assertEqual(document["sections"]["opt-usim"]["ef-msisdn"][1][1][20], 0x09)
        self.assertEqual(document["sections"]["genericFileManagement"]["fileManagementCMD"][0][2][1][14], 0x09)
        unchanged, found = reconcile_document(document, apply=False)
        self.assertIs(unchanged, document)
        self.assertEqual([item.patched for item in found], [False, False])

    def test_sentinel_records_and_editor_shapes(self) -> None:
        sentinel = bytes.fromhex("DD40F6518907")
        template_record = _adn_record(20, 0x09, 0x91, sentinel.hex() + "FFFF")
        document = _document(template_record, b"")
        _rewritten, edits = reconcile_document(document, sentinel_hexes=[sentinel.hex()])
        self.assertEqual(edits, [])
        # The editor projection wraps the tuples and hex-encodes the bytes.
        editor = {
            "sections": {
                "usim": {
                    "type": "usim",
                    "ef-msisdn": [
                        {"@": ["fileDescriptor", {"fileDescriptor": {"hex": "42210022"}}]},
                        {"@": ["fillFileContent", {"hex": _adn_record(20, 0x09, 0x91, _MSISDN_HEX).hex().upper()}]},
                    ],
                },
            }
        }
        rewritten, edits = reconcile_document(editor)
        self.assertEqual([(item.section_key, item.edit.derived) for item in edits], [("usim", 7)])
        patched_hex = rewritten["sections"]["usim"]["ef-msisdn"][1]["@"][1]["hex"]
        self.assertEqual(patched_hex[40:42], "07")

    def test_linter_reports_what_nothing_fixes(self) -> None:
        imsi_group = [
            ("filePath", bytes.fromhex("7F20")),
            ("createFCP", {"fileID": bytes.fromhex("6F07"), "fileDescriptor": bytes.fromhex("4121")}),
            ("fillFileContent", bytes.fromhex("0819103254769800FF")),
        ]
        smsp_group = _gfm_group("6F42", "4221001C", _smsp_record(0xFC, "0A918472535211F1", "069153133254F6"))
        document = _document(_adn_record(20, 0x09, 0x91, _MSISDN_HEX), _adn_record(14, 0x07, 0x91, _MSISDN_HEX)[:24])
        document["sections"]["genericFileManagement"]["fileManagementCMD"].extend([imsi_group, smsp_group])
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=document,
            profile_label="lengths.der",
            check_return_code=None,
            check_stderr="",
            emit_missing_check_finding=False,
        )
        by_code = {finding.code: finding for finding in report.findings if finding.code.startswith("YRL-LEN")}
        self.assertEqual(sorted(by_code), ["YRL-LEN-001", "YRL-LEN-002", "YRL-LEN-003"])
        self.assertEqual(by_code["YRL-LEN-001"].severity, "WARN")
        self.assertEqual(by_code["YRL-LEN-001"].path, "opt-usim.ef-msisdn.fillFileContent")
        self.assertIn("09 -> 07", by_code["YRL-LEN-001"].message)
        self.assertIn("counts FF filler", by_code["YRL-LEN-001"].message)
        self.assertEqual(by_code["YRL-LEN-002"].evidence["derived"], "0x07")
        self.assertIn("TP-Destination Address length", by_code["YRL-LEN-003"].message)
        self.assertIn("stops short", by_code["YRL-LEN-003"].message)
        # With the sentinel named, the placeholder record is not linted.
        sentinel = bytes.fromhex("DD40F6518907")
        document = _document(_adn_record(20, 0x09, 0x91, sentinel.hex() + "FFFF"), b"")
        report = SaipProfileLinter(strict=False).lint_decoded_document(
            decoded_document=document,
            profile_label="lengths.der",
            emit_missing_check_finding=False,
            inline_sentinel_hexes=frozenset({sentinel.hex().upper()}),
        )
        self.assertEqual([finding.code for finding in report.findings if finding.code.startswith("YRL-LEN")], [])


class LengthFieldSessionTests(unittest.TestCase):
    """The reference profile with its DF.TELECOM MSISDN number tokenised."""

    @classmethod
    def setUpClass(cls) -> None:
        if _REFERENCE_HEX.is_file() is False:
            raise unittest.SkipTest("No tracked reference SAIP profile fixture")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.saip = saip_actions
        cls.manager = get_manager()
        text = "".join(_REFERENCE_HEX.read_text(encoding="utf-8").split()).upper()
        assert text.count(_MSISDN_TAIL) == 1
        cls.template_text = text.replace(_MSISDN_TAIL, "0991[msisdnMSISDN8NibbleSwap]", 1)

    def _open(self, root: Path) -> str:
        source = root / "profile.varder"
        source.write_text(self.template_text, encoding="utf-8-sig")
        return self.saip._dispatch_open_package(None, path=str(source))["session_id"]

    def _msisdn_row(self, session_id: str) -> dict:
        handle = self.manager.claim(session_id)
        for row in self.saip._filesystem_tree_rows(handle["decoded_document"]):
            if (
                str(row.get("file_id") or "").upper() == "6F40"
                and str(row.get("section_key") or "").startswith("genericFileManagement")
            ):
                return row
        raise AssertionError("no DF.TELECOM EF.MSISDN row")

    def _lint_codes(self, session_id: str) -> list[str]:
        report = self.saip._dispatch_validate(None, session_id=session_id)
        return sorted(
            str(item.get("code")) for item in report["findings"] if str(item.get("code")).startswith("YRL-LEN")
        )

    def test_stored_value_reconciles_view_export_and_lint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            session_id = self._open(root)
            try:
                row = self._msisdn_row(session_id)
                before = self.saip._dispatch_show_file(
                    None, session_id=session_id, section_key=row["section_key"], field_path=row["field_path"]
                )
                self.assertNotIn("inline_length_fields", before)
                self.assertEqual(before["records"][0]["decoded"]["format"], "Inline template placeholder")
                # The sentinel record is not linted for its length byte.
                self.assertEqual(self._lint_codes(session_id), [])

                applied = self.saip._dispatch_set_variable(
                    None, session_id=session_id, name="msisdn", value=_MSISDN_VALUE
                )
                self.assertTrue(
                    any("EF.MSISDN record 1" in line and "09 -> 07" in line for line in applied["summaries"]),
                    applied["summaries"],
                )

                shown = self.saip._dispatch_show_file(
                    None, session_id=session_id, section_key=row["section_key"], field_path=row["field_path"]
                )
                fields = shown["inline_length_fields"]
                self.assertEqual(len(fields), 1)
                self.assertEqual((fields[0]["start"], fields[0]["end"]), (14, 15))
                self.assertEqual((fields[0]["template_hex"], fields[0]["value_hex"]), ("09", "07"))
                self.assertEqual(fields[0]["kind"], "length_field")
                self.assertEqual(fields[0]["record"], 1)
                # The template keeps its byte and its sentinel; the decode
                # reads the stored value with the reconciled length.
                self.assertEqual(shown["body_hex"][28:30], "09")
                self.assertTrue(shown["inline_placeholders"][0]["resolved"])
                self.assertEqual(shown["records"][0]["decoded"]["number"], _MSISDN_VALUE)
                self.assertNotEqual(shown["records"][0]["decoded"].get("format"), "Inline template placeholder")
                self.assertEqual(self._lint_codes(session_id), [])

                saved = self.saip._dispatch_save_package(
                    None, session_id=session_id, output_path=str(root / "complete.der"), format="der"
                )
                self.assertTrue(saved["materialized"])
                self.assertEqual(len(saved["length_reconciliations"]), 1)
                self.assertIn("EF.MSISDN record 1", saved["length_reconciliations"][0])
                self.assertTrue(any("written for this export" in line for line in saved["warnings"]))
                der = (root / "complete.der").read_bytes()
                self.assertIn(bytes.fromhex("0791" + _MSISDN_HEX), der)
                self.assertNotIn(bytes.fromhex("0991" + _MSISDN_HEX), der)
                # The session still holds the template byte.
                again = self.saip._dispatch_show_file(
                    None, session_id=session_id, section_key=row["section_key"], field_path=row["field_path"]
                )
                self.assertEqual(again["body_hex"][28:30], "09")
            finally:
                self.manager.close(session_id)


if __name__ == "__main__":
    unittest.main()
