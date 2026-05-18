# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_gfm_select`` — single-DF-context GFM helpers."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_gfm_select as G


def _pe_with(transactions: list[list[tuple[str, object]]]) -> dict:
    return {"fileManagementCMD": transactions}


class NormaliseDfPathTests(unittest.TestCase):

    def test_empty_is_mf_root(self) -> None:
        self.assertEqual(G.normalise_df_path(""), "")

    def test_strips_leading_mf(self) -> None:
        self.assertEqual(G.normalise_df_path("3F007F10"), "7F10")

    def test_rejects_odd_fid(self) -> None:
        with self.assertRaises(ValueError):
            G.normalise_df_path("7F1")

    def test_rejects_non_hex(self) -> None:
        with self.assertRaises(ValueError):
            G.normalise_df_path("ZZZZ")


class GetDfContextTests(unittest.TestCase):

    def test_canonical_layout(self) -> None:
        pe = _pe_with([[
            ("filePath", b"\x7f\x10"),
            ("createFCP", {"fileID": b"\x6f\x3a"}),
            ("createFCP", {"fileID": b"\x6f\x40"}),
        ]])
        ctx = G.get_df_context(pe)
        self.assertEqual(ctx["df_path_hex"], "7F10")
        self.assertEqual(ctx["file_count"], 2)
        self.assertEqual(ctx["extra_filepath_count"], 0)
        self.assertEqual(ctx["warnings"], [])

    def test_divergent_filepaths_raise_warning(self) -> None:
        pe = _pe_with([
            [("filePath", b""), ("createFCP", {"fileID": b"\x6f\x05"})],
            [("filePath", b"\x7f\x10"), ("createFCP", {"fileID": b"\x6f\x3a"})],
        ])
        ctx = G.get_df_context(pe)
        self.assertEqual(ctx["df_path_hex"], "")
        self.assertEqual(ctx["extra_filepath_count"], 1)
        self.assertEqual(len(ctx["warnings"]), 1)


class SetDfContextTests(unittest.TestCase):

    def test_collapses_into_single_transaction(self) -> None:
        pe = _pe_with([
            [("filePath", b""), ("createFCP", {"fileID": b"\x6f\x05"})],
            [("filePath", b"\x7f\x10"), ("createFCP", {"fileID": b"\x6f\x3a"})],
            [("filePath", b"\x7f\x10"), ("createFCP", {"fileID": b"\x6f\x40"})],
        ])
        result = G.set_df_context(pe, df_path="7F10")
        self.assertEqual(result["df_path_hex"], "7F10")
        self.assertEqual(result["file_count"], 3)
        self.assertEqual(result["dropped_filepath_count"], 3)
        self.assertEqual(len(pe["fileManagementCMD"]), 1)
        first = pe["fileManagementCMD"][0]
        self.assertEqual(first[0][0], "filePath")
        self.assertEqual(sum(1 for op, _ in first[1:] if op == "createFCP"), 3)


class FileListAndReorderTests(unittest.TestCase):

    def setUp(self) -> None:
        self.pe = _pe_with([[
            ("filePath", b"\x7f\x10"),
            ("createFCP", {"fileID": b"\x6f\x05"}),
            ("createFCP", {"fileID": b"\x6f\x3a"}),
            ("createFCP", {"fileID": b"\x6f\x40"}),
        ]])

    def test_list_files(self) -> None:
        rows = G.list_files(self.pe)
        self.assertEqual([row["file_id_hex"] for row in rows], ["6F05", "6F3A", "6F40"])
        self.assertTrue(all(row["df_path_hex"] == "7F10" for row in rows))

    def test_reorder_first_to_last(self) -> None:
        G.reorder_files(self.pe, from_index=0, to_index=2)
        rows = G.list_files(self.pe)
        self.assertEqual([row["file_id_hex"] for row in rows], ["6F3A", "6F40", "6F05"])

    def test_reorder_out_of_range(self) -> None:
        with self.assertRaises(IndexError):
            G.reorder_files(self.pe, from_index=0, to_index=9)

    def test_remove_file(self) -> None:
        G.remove_file(self.pe, position=1)
        rows = G.list_files(self.pe)
        self.assertEqual([row["file_id_hex"] for row in rows], ["6F05", "6F40"])


if __name__ == "__main__":
    unittest.main()
