# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for pure static helpers in ``SCP03.logic.fs.FileSystemController``.

Covers: _classify_tree_node_kind, _is_hex_identifier, _build_select_command,
_is_successful_select_response, _normalize_registry_path_tokens,
_parse_fid_registry_line.
All methods under test are @staticmethod or @classmethod — no transport
object is required.
"""

from __future__ import annotations

import unittest

from SCP03.logic.fs import FileSystemController


class ClassifyTreeNodeKindTests(unittest.TestCase):
    """ETSI TS 102 221 §8.2–§8.3 node-kind classification."""

    def test_mf(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("MF"), "mf")

    def test_adf_underscore(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("ADF_USIM"), "adf")

    def test_adf_dot(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("ADF.ISIM"), "adf")

    def test_df_underscore(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("DF_GSM"), "df")

    def test_df_dot(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("DF.TELECOM"), "df")

    def test_ef_underscore(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("EF_ICCID"), "ef")

    def test_ef_dot(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("EF.IMSI"), "ef")

    def test_empty_returns_unknown(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind(""), "unknown")

    def test_no_prefix_with_children_returns_df(self) -> None:
        self.assertEqual(
            FileSystemController._classify_tree_node_kind("SOME_NAME", has_children=True), "df"
        )

    def test_no_prefix_without_children_returns_ef(self) -> None:
        self.assertEqual(
            FileSystemController._classify_tree_node_kind("SOME_NAME", has_children=False), "ef"
        )

    def test_case_insensitive(self) -> None:
        self.assertEqual(FileSystemController._classify_tree_node_kind("adf_usim"), "adf")


class IsHexIdentifierTests(unittest.TestCase):

    def test_valid_fid(self) -> None:
        self.assertTrue(FileSystemController._is_hex_identifier("3F00"))

    def test_valid_aid(self) -> None:
        self.assertTrue(FileSystemController._is_hex_identifier("A000000151000000"))

    def test_lowercase_accepted(self) -> None:
        self.assertTrue(FileSystemController._is_hex_identifier("a000"))

    def test_odd_length_rejected(self) -> None:
        self.assertFalse(FileSystemController._is_hex_identifier("3F0"))

    def test_non_hex_chars_rejected(self) -> None:
        self.assertFalse(FileSystemController._is_hex_identifier("ZZZZ"))

    def test_empty_rejected(self) -> None:
        self.assertFalse(FileSystemController._is_hex_identifier(""))

    def test_whitespace_rejected(self) -> None:
        self.assertFalse(FileSystemController._is_hex_identifier("3F 00"))


class BuildSelectCommandTests(unittest.TestCase):

    def test_short_fid_uses_select_by_fid(self) -> None:
        cmd = FileSystemController._build_select_command("3F00")
        self.assertEqual(cmd.upper(), "00A40004023F00")

    def test_long_aid_uses_select_by_name(self) -> None:
        cmd = FileSystemController._build_select_command("A0000000871002")
        # CLA=00 INS=A4 P1=04 P2=00 Lc=07 AID
        self.assertIn("A0000000871002", cmd.upper())
        self.assertTrue(cmd.upper().startswith("00A40400"))

    def test_lc_byte_matches_aid_length(self) -> None:
        aid = "A000000151000000"  # 8 bytes
        cmd = FileSystemController._build_select_command(aid)
        lc_hex = cmd[8:10]
        self.assertEqual(int(lc_hex, 16), len(aid) // 2)

    def test_uppercase_output(self) -> None:
        cmd = FileSystemController._build_select_command("3f00")
        self.assertEqual(cmd, cmd.upper())


class IsSuccessfulSelectResponseTests(unittest.TestCase):

    def test_sw1_90_is_success(self) -> None:
        self.assertTrue(FileSystemController._is_successful_select_response(0x90, b""))

    def test_sw1_61_is_success(self) -> None:
        self.assertTrue(FileSystemController._is_successful_select_response(0x61, b""))

    def test_sw1_9f_is_success(self) -> None:
        self.assertTrue(FileSystemController._is_successful_select_response(0x9F, b""))

    def test_sw1_62_with_data_is_success(self) -> None:
        self.assertTrue(
            FileSystemController._is_successful_select_response(0x62, b"\x00")
        )

    def test_sw1_62_without_data_is_failure(self) -> None:
        self.assertFalse(
            FileSystemController._is_successful_select_response(0x62, b"")
        )

    def test_sw1_6a_is_failure(self) -> None:
        self.assertFalse(
            FileSystemController._is_successful_select_response(0x6A, b"\x82")
        )

    def test_sw1_69_is_failure(self) -> None:
        self.assertFalse(
            FileSystemController._is_successful_select_response(0x69, b"")
        )


class NormalizeRegistryPathTokensTests(unittest.TestCase):

    def test_valid_tokens_uppercase(self) -> None:
        result = FileSystemController._normalize_registry_path_tokens(["ef_iccid", "mf"])
        self.assertEqual(result, ["EF_ICCID", "MF"])

    def test_empty_tokens_skipped(self) -> None:
        result = FileSystemController._normalize_registry_path_tokens(["", "MF", ""])
        self.assertEqual(result, ["MF"])

    def test_whitespace_stripped_and_uppercased(self) -> None:
        result = FileSystemController._normalize_registry_path_tokens(["  mf  "])
        self.assertEqual(result, ["MF"])

    def test_empty_input_list(self) -> None:
        self.assertEqual(FileSystemController._normalize_registry_path_tokens([]), [])

    def test_preserves_order(self) -> None:
        tokens = ["3F00", "7FF0", "6F07"]
        result = FileSystemController._normalize_registry_path_tokens(tokens)
        self.assertEqual(result, tokens)


class ParseFidRegistryLineTests(unittest.TestCase):

    def test_normal_line(self) -> None:
        result = FileSystemController._parse_fid_registry_line("    EF_ICCID: 2FE2 # ICCID")
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "EF_ICCID")
        self.assertEqual(result["candidates"], ["2FE2"])
        self.assertIn("ICCID", result["comment"])

    def test_indent_tracked(self) -> None:
        result = FileSystemController._parse_fid_registry_line("    EF_ICCID: 2FE2")
        self.assertEqual(result["indent"], 4)

    def test_zero_indent(self) -> None:
        result = FileSystemController._parse_fid_registry_line("MF: 3F00")
        self.assertEqual(result["indent"], 0)

    def test_multiple_candidates(self) -> None:
        result = FileSystemController._parse_fid_registry_line("EF_MULTI: 2FE2:2FE3")
        self.assertIsNotNone(result)
        self.assertIn("2FE2", result["candidates"])
        self.assertIn("2FE3", result["candidates"])

    def test_comment_line_returns_none(self) -> None:
        self.assertIsNone(FileSystemController._parse_fid_registry_line("# this is a comment"))

    def test_empty_line_returns_none(self) -> None:
        self.assertIsNone(FileSystemController._parse_fid_registry_line("   "))

    def test_no_colon_returns_none(self) -> None:
        self.assertIsNone(FileSystemController._parse_fid_registry_line("EF_ICCID 2FE2"))

    def test_returns_dict_with_required_keys(self) -> None:
        result = FileSystemController._parse_fid_registry_line("MF: 3F00")
        self.assertIsNotNone(result)
        for key in ("indent", "name", "candidates", "comment"):
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
