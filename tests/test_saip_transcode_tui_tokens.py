"""Unit tests for the TUI token-manager data helpers.

These tests intentionally avoid importing the Textual-based TUI module. They
only exercise the pure helpers that feed :class:`TokenManagerPicker` so the
test suite can run without Textual being installed.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_transcode_tui_tokens import (
    build_token_rows,
    format_token_row,
    format_token_value_preview,
    placeholder_style_from_document,
    summarize_token_counts,
)


class FormatTokenValuePreviewTests(unittest.TestCase):

    def test_hex_string_short(self) -> None:
        self.assertEqual(
            format_token_value_preview("0123456789ABCDEF"),
            "0123456789ABCDEF",
        )

    def test_hex_string_long_is_truncated(self) -> None:
        long_value = "AB" * 200
        preview = format_token_value_preview(long_value)
        self.assertLess(len(preview), 50)
        self.assertTrue(preview.endswith("…"))

    def test_dict_is_json_encoded(self) -> None:
        preview = format_token_value_preview({"zero_len": 10})
        self.assertEqual(preview, '{"zero_len": 10}')

    def test_dict_long_is_truncated(self) -> None:
        preview = format_token_value_preview(
            {"pattern_hex": "FF", "byte_len": 2048, "extra": "x" * 120}
        )
        self.assertLess(len(preview), 50)
        self.assertTrue(preview.endswith("…"))

    def test_none_is_stringified(self) -> None:
        self.assertEqual(format_token_value_preview(None), "None")


class BuildTokenRowsTests(unittest.TestCase):

    def _sample_doc(self) -> dict:
        return {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "0899999999999999",
                "BIG": {"zero_len": 200},
            },
            "sections": {
                "a": {"x": {"hex": "{ICCID}{#ICCID}"}},
                "b": {"y": {"hex": "{IMSI}"}},
            },
        }

    def test_rows_sorted_case_insensitive(self) -> None:
        rows = build_token_rows(self._sample_doc())
        names = [row["name"] for row in rows]
        self.assertEqual(names, ["BIG", "ICCID", "IMSI"])

    def test_reference_counts_are_accurate(self) -> None:
        rows = {row["name"]: row for row in build_token_rows(self._sample_doc())}
        self.assertEqual(rows["ICCID"]["content"], 1)
        self.assertEqual(rows["ICCID"]["length"], 1)
        self.assertEqual(rows["IMSI"]["content"], 1)
        self.assertEqual(rows["IMSI"]["length"], 0)
        self.assertEqual(rows["BIG"]["content"], 0)
        self.assertEqual(rows["BIG"]["length"], 0)

    def test_value_preview_populated(self) -> None:
        rows = {row["name"]: row for row in build_token_rows(self._sample_doc())}
        self.assertEqual(rows["IMSI"]["value_preview"], "0899999999999999")
        self.assertEqual(
            rows["ICCID"]["value_preview"], '{"hex": "89881111111111111112"}'
        )

    def test_raw_value_preserved(self) -> None:
        rows = {row["name"]: row for row in build_token_rows(self._sample_doc())}
        self.assertEqual(rows["BIG"]["raw_value"], {"zero_len": 200})

    def test_empty_document_returns_empty_list(self) -> None:
        self.assertEqual(build_token_rows({}), [])

    def test_malformed_defs_block_is_tolerated(self) -> None:
        self.assertEqual(
            build_token_rows({"__ygg_token_defs__": "not-a-dict"}),
            [],
        )


class FormatTokenRowTests(unittest.TestCase):

    def test_name_padded_to_width(self) -> None:
        row = {"name": "AB", "content": 1, "length": 0, "value_preview": "FF"}
        rendered = format_token_row(row, name_width=6)
        self.assertTrue(rendered.startswith("AB    "))
        self.assertIn("content=  1", rendered)
        self.assertIn("length=  0", rendered)
        self.assertTrue(rendered.endswith("FF"))

    def test_width_expands_for_long_names(self) -> None:
        row = {
            "name": "SOMETHING_LONG",
            "content": 3,
            "length": 2,
            "value_preview": "--",
        }
        rendered = format_token_row(row, name_width=4)
        self.assertTrue(rendered.startswith("SOMETHING_LONG "))


class PlaceholderStyleFromDocumentTests(unittest.TestCase):

    def test_default_is_brace(self) -> None:
        self.assertEqual(placeholder_style_from_document({}), "brace")

    def test_explicit_brace(self) -> None:
        self.assertEqual(
            placeholder_style_from_document({"__ygg_placeholder_style__": "brace"}),
            "brace",
        )

    def test_explicit_bracket(self) -> None:
        self.assertEqual(
            placeholder_style_from_document({"__ygg_placeholder_style__": "bracket"}),
            "bracket",
        )

    def test_curly_alias_normalised_to_brace(self) -> None:
        self.assertEqual(
            placeholder_style_from_document({"__ygg_placeholder_style__": "CURLY"}),
            "brace",
        )

    def test_unknown_style_falls_back_to_brace(self) -> None:
        self.assertEqual(
            placeholder_style_from_document({"__ygg_placeholder_style__": "crazy"}),
            "brace",
        )


class SummarizeTokenCountsTests(unittest.TestCase):

    def test_empty_document(self) -> None:
        summary = summarize_token_counts({})
        self.assertEqual(
            summary,
            {"tokens": 0, "content_refs": 0, "length_refs": 0},
        )

    def test_aggregates_all_defs(self) -> None:
        doc = {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89"},
                "IMSI": "08",
                "SPARE": {"zero_len": 4},
            },
            "sections": {
                "a": {"x": {"hex": "{ICCID}{ICCID}{#ICCID}{IMSI}"}},
            },
        }
        summary = summarize_token_counts(doc)
        self.assertEqual(summary["tokens"], 3)
        self.assertEqual(summary["content_refs"], 3)
        self.assertEqual(summary["length_refs"], 1)


if __name__ == "__main__":
    unittest.main()
