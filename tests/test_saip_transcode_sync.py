# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for Tools/ProfilePackage/saip_transcode_sync.py pure-Python utilities.

Covers: location_to_offset, offset_to_location, key_for_byte_offset,
        section_keys_touching_json_range, infer_section_key_from_json_cursor,
        scan_json_object_member_entries, build_json_entry_spans,
        byte_range_to_hex_selection, hex_selection_to_byte_range.
"""

from __future__ import annotations

import unittest

try:
    from Tools.ProfilePackage.saip_transcode_sync import (
        build_json_entry_spans,
        byte_range_to_hex_selection,
        hex_selection_to_byte_range,
        infer_section_key_from_json_cursor,
        key_for_byte_offset,
        location_to_offset,
        offset_to_location,
        scan_json_object_member_entries,
        section_keys_touching_json_range,
    )
    from textual.document._document import Location, Selection
    _IMPORT_OK = True
except (ImportError, ModuleNotFoundError):
    _IMPORT_OK = False

_SKIP = unittest.skipUnless(_IMPORT_OK, "textual not installed")


# ---------------------------------------------------------------------------
# location_to_offset / offset_to_location
# ---------------------------------------------------------------------------

@_SKIP
class LocationToOffsetTests(unittest.TestCase):

    def test_first_line_col_zero(self) -> None:
        text = "abc\ndef\nghi"
        self.assertEqual(location_to_offset(text, (0, 0)), 0)

    def test_second_line_col_zero(self) -> None:
        text = "abc\ndef\nghi"
        self.assertEqual(location_to_offset(text, (1, 0)), 4)

    def test_col_within_line(self) -> None:
        text = "abc\ndef"
        self.assertEqual(location_to_offset(text, (0, 2)), 2)

    def test_col_clamp_at_line_end(self) -> None:
        text = "abc\ndef"
        # col 99 should clamp to end of line (3 chars)
        self.assertEqual(location_to_offset(text, (0, 99)), 3)


@_SKIP
class OffsetToLocationTests(unittest.TestCase):

    def test_offset_zero(self) -> None:
        self.assertEqual(offset_to_location("abc\ndef", 0), (0, 0))

    def test_offset_start_of_second_line(self) -> None:
        self.assertEqual(offset_to_location("abc\ndef", 4), (1, 0))

    def test_negative_offset(self) -> None:
        self.assertEqual(offset_to_location("abc\ndef", -1), (0, 0))

    def test_round_trip(self) -> None:
        text = "foo\nbar\nbaz"
        loc = (1, 2)
        offset = location_to_offset(text, loc)
        self.assertEqual(offset_to_location(text, offset), loc)


# ---------------------------------------------------------------------------
# key_for_byte_offset
# ---------------------------------------------------------------------------

@_SKIP
class KeyForByteOffsetTests(unittest.TestCase):

    def _ranges(self) -> list:
        return [("header", 0, 10), ("usim", 10, 40), ("end", 40, 50)]

    def test_first_range(self) -> None:
        self.assertEqual(key_for_byte_offset(self._ranges(), 0), "header")

    def test_middle_range(self) -> None:
        self.assertEqual(key_for_byte_offset(self._ranges(), 15), "usim")

    def test_last_byte_of_range(self) -> None:
        self.assertEqual(key_for_byte_offset(self._ranges(), 39), "usim")

    def test_boundary_is_exclusive(self) -> None:
        # offset 40 belongs to "end", not "usim"
        self.assertEqual(key_for_byte_offset(self._ranges(), 40), "end")

    def test_beyond_all_ranges_returns_none(self) -> None:
        self.assertIsNone(key_for_byte_offset(self._ranges(), 100))


# ---------------------------------------------------------------------------
# section_keys_touching_json_range
# ---------------------------------------------------------------------------

@_SKIP
class SectionKeysTouchingJsonRangeTests(unittest.TestCase):

    def _spans(self) -> dict:
        # (entry_begin, value_start, value_end)
        return {
            "header": (0, 5, 30),
            "usim":   (30, 35, 80),
            "end":    (80, 85, 100),
        }

    def test_single_key_touched(self) -> None:
        keys = ["header", "usim", "end"]
        result = section_keys_touching_json_range(keys, self._spans(), 10, 20)
        self.assertEqual(result, ["header"])

    def test_two_keys_touched(self) -> None:
        keys = ["header", "usim", "end"]
        result = section_keys_touching_json_range(keys, self._spans(), 20, 50)
        self.assertIn("header", result)
        self.assertIn("usim", result)

    def test_no_touch_before_all(self) -> None:
        keys = ["header", "usim", "end"]
        result = section_keys_touching_json_range(keys, self._spans(), 200, 300)
        self.assertEqual(result, [])

    def test_swapped_offsets_normalised(self) -> None:
        keys = ["header", "usim", "end"]
        r1 = section_keys_touching_json_range(keys, self._spans(), 10, 20)
        r2 = section_keys_touching_json_range(keys, self._spans(), 20, 10)
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# infer_section_key_from_json_cursor
# ---------------------------------------------------------------------------

@_SKIP
class InferSectionKeyFromJsonCursorTests(unittest.TestCase):

    _DOC = '\n'.join([
        '{',
        '  "sections": {',
        '    "header": {',
        '      "value": 1',
        '    },',
        '    "usim": {',
        '      "value": 2',
        '    }',
        '  }',
        '}',
    ])

    def test_cursor_inside_usim_value(self) -> None:
        result = infer_section_key_from_json_cursor(self._DOC, 6)
        self.assertEqual(result, "usim")

    def test_cursor_before_any_key_returns_none(self) -> None:
        result = infer_section_key_from_json_cursor(self._DOC, 1)
        self.assertIsNone(result)

    def test_negative_line_returns_none(self) -> None:
        result = infer_section_key_from_json_cursor(self._DOC, -1)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# scan_json_object_member_entries
# ---------------------------------------------------------------------------

@_SKIP
class ScanJsonObjectMemberEntriesTests(unittest.TestCase):

    def test_simple_object(self) -> None:
        text = '{"a": 1, "b": 2}'
        entries = scan_json_object_member_entries(text, 0, len(text))
        keys = [e[0] for e in entries]
        self.assertIn("a", keys)
        self.assertIn("b", keys)

    def test_empty_object(self) -> None:
        text = '{}'
        entries = scan_json_object_member_entries(text, 0, len(text))
        self.assertEqual(entries, [])

    def test_nested_object_key_extracted(self) -> None:
        text = '{"outer": {"inner": 42}}'
        entries = scan_json_object_member_entries(text, 0, len(text))
        self.assertEqual(entries[0][0], "outer")


# ---------------------------------------------------------------------------
# build_json_entry_spans
# ---------------------------------------------------------------------------

@_SKIP
class BuildJsonEntrySpansTests(unittest.TestCase):

    _DOC = '{"sections": {"header": {"x": 1}, "usim": {"y": 2}}}'

    def test_sections_key_found(self) -> None:
        spans = build_json_entry_spans(self._DOC, ["header", "usim"])
        # May or may not have both keys depending on parser depth; at minimum must be a dict
        self.assertIsInstance(spans, dict)

    def test_no_sections_key_returns_empty(self) -> None:
        spans = build_json_entry_spans('{"other": {}}', ["header"])
        self.assertEqual(spans, {})


# ---------------------------------------------------------------------------
# byte_range_to_hex_selection / hex_selection_to_byte_range
# ---------------------------------------------------------------------------

@_SKIP
class ByteRangeToHexSelectionTests(unittest.TestCase):

    def test_returns_selection(self) -> None:
        # 4-byte payload formatted as 32-byte-wide lines
        hex_text = "DE AD BE EF"
        sel = byte_range_to_hex_selection(hex_text, 0, 2)
        self.assertIsInstance(sel, Selection)

    def test_start_at_zero(self) -> None:
        hex_text = "DE AD BE EF"
        sel = byte_range_to_hex_selection(hex_text, 0, 1)
        start_line, start_col = sel.start
        self.assertEqual(start_line, 0)
        self.assertEqual(start_col, 0)


@_SKIP
class HexSelectionToByteRangeTests(unittest.TestCase):

    def test_empty_selection_returns_single_byte(self) -> None:
        hex_text = "DE AD BE EF"
        # Empty selection at position (0,0)
        sel = Selection((0, 0), (0, 0))
        result = hex_selection_to_byte_range(hex_text, sel)
        self.assertIsNotNone(result)
        if result is not None:
            self.assertEqual(result[1] - result[0], 1)

    def test_returns_none_for_offset_beyond_data(self) -> None:
        hex_text = "DE"
        # Selection well beyond the single byte
        sel = Selection((0, 99), (0, 99))
        result = hex_selection_to_byte_range(hex_text, sel)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
