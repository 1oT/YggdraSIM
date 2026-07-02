# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for coordinate-mapping helpers in ``Tools.ProfilePackage.saip_transcode_sync``.

Covers: ordered_section_keys_from_pes, pe_byte_ranges,
json_editor_range_to_der_byte_range, der_byte_range_to_json_editor_range,
enclosing_json_value_span, location_to_offset, offset_to_location,
key_for_byte_offset, section_keys_touching_json_range.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from Tools.ProfilePackage.saip_transcode_sync import (
    der_byte_range_to_json_editor_range,
    enclosing_json_value_span,
    json_editor_range_to_der_byte_range,
    key_for_byte_offset,
    location_to_offset,
    offset_to_location,
    ordered_section_keys_from_pes,
    pe_byte_ranges,
    section_keys_touching_json_range,
)


def _make_pes(types: list[str], der_sizes: list[int]) -> MagicMock:
    pe_list = []
    for t, size in zip(types, der_sizes):
        pe = MagicMock()
        pe.type = t
        pe.to_der.return_value = bytes(size)
        pe_list.append(pe)
    pes = MagicMock()
    pes.pe_list = pe_list
    return pes


# Shared spans/ranges fixture used by mapping tests.
_KEYS = ["pe1", "pe2", "pe3"]
_SPANS: dict[str, tuple[int, int, int]] = {
    "pe1": (0, 5, 20),
    "pe2": (25, 30, 45),
    "pe3": (50, 55, 70),
}
_RANGES_BY_KEY: dict[str, tuple[int, int]] = {
    "pe1": (0, 100),
    "pe2": (100, 200),
    "pe3": (200, 300),
}


class OrderedSectionKeysTests(unittest.TestCase):

    def test_unique_types_unchanged(self) -> None:
        pes = _make_pes(["header", "usim", "isim"], [10, 20, 5])
        keys = ordered_section_keys_from_pes(pes)
        self.assertEqual(keys, ["header", "usim", "isim"])

    def test_duplicate_type_gets_suffix(self) -> None:
        pes = _make_pes(["header", "usim", "header"], [10, 20, 5])
        keys = ordered_section_keys_from_pes(pes)
        self.assertEqual(keys[0], "header")
        self.assertEqual(keys[2], "header_2")

    def test_triple_duplicate_suffix(self) -> None:
        pes = _make_pes(["x", "x", "x"], [1, 1, 1])
        keys = ordered_section_keys_from_pes(pes)
        self.assertEqual(keys, ["x", "x_2", "x_3"])

    def test_empty_pe_list(self) -> None:
        pes = MagicMock()
        pes.pe_list = []
        self.assertEqual(ordered_section_keys_from_pes(pes), [])

    def test_returns_list_of_strings(self) -> None:
        pes = _make_pes(["a"], [4])
        result = ordered_section_keys_from_pes(pes)
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(k, str) for k in result))


class PeByteRangesTests(unittest.TestCase):

    def test_non_overlapping_ranges(self) -> None:
        pes = _make_pes(["header", "usim"], [10, 20])
        ranges = pe_byte_ranges(pes)
        # First range starts at 0.
        self.assertEqual(ranges[0], ("header", 0, 10))
        self.assertEqual(ranges[1], ("usim", 10, 30))

    def test_count_matches_pe_list(self) -> None:
        pes = _make_pes(["a", "b", "c"], [5, 15, 10])
        ranges = pe_byte_ranges(pes)
        self.assertEqual(len(ranges), 3)

    def test_contiguous_coverage(self) -> None:
        pes = _make_pes(["a", "b", "c"], [4, 8, 12])
        ranges = pe_byte_ranges(pes)
        for i in range(len(ranges) - 1):
            self.assertEqual(ranges[i][2], ranges[i + 1][1])

    def test_total_byte_length(self) -> None:
        sizes = [3, 7, 11]
        pes = _make_pes(["a", "b", "c"], sizes)
        ranges = pe_byte_ranges(pes)
        self.assertEqual(ranges[-1][2], sum(sizes))


class LocationOffsetRoundTripTests(unittest.TestCase):

    _TEXT = "abc\ndef\nghi"

    def test_start_of_first_line(self) -> None:
        self.assertEqual(location_to_offset(self._TEXT, (0, 0)), 0)

    def test_start_of_second_line(self) -> None:
        self.assertEqual(location_to_offset(self._TEXT, (1, 0)), 4)

    def test_mid_third_line(self) -> None:
        self.assertEqual(location_to_offset(self._TEXT, (2, 1)), 9)

    def test_offset_to_location_start(self) -> None:
        self.assertEqual(offset_to_location(self._TEXT, 0), (0, 0))

    def test_offset_to_location_second_line(self) -> None:
        self.assertEqual(offset_to_location(self._TEXT, 4), (1, 0))

    def test_offset_to_location_mid_third(self) -> None:
        self.assertEqual(offset_to_location(self._TEXT, 9), (2, 1))

    def test_roundtrip(self) -> None:
        offset = 5
        loc = offset_to_location(self._TEXT, offset)
        back = location_to_offset(self._TEXT, loc)
        self.assertEqual(back, offset)


class KeyForByteOffsetTests(unittest.TestCase):

    _RANGES = [("pe1", 0, 10), ("pe2", 10, 20), ("pe3", 20, 30)]

    def test_first_range(self) -> None:
        self.assertEqual(key_for_byte_offset(self._RANGES, 0), "pe1")
        self.assertEqual(key_for_byte_offset(self._RANGES, 9), "pe1")

    def test_second_range(self) -> None:
        self.assertEqual(key_for_byte_offset(self._RANGES, 10), "pe2")

    def test_beyond_all_ranges(self) -> None:
        self.assertIsNone(key_for_byte_offset(self._RANGES, 30))

    def test_empty_ranges(self) -> None:
        self.assertIsNone(key_for_byte_offset([], 5))


class SectionKeysTouchingRangeTests(unittest.TestCase):

    def test_touches_two_sections(self) -> None:
        result = section_keys_touching_json_range(_KEYS, _SPANS, 3, 28)
        self.assertIn("pe1", result)
        self.assertIn("pe2", result)

    def test_empty_query_touches_nothing(self) -> None:
        result = section_keys_touching_json_range(_KEYS, _SPANS, 0, 0)
        self.assertEqual(result, [])

    def test_range_within_single_section(self) -> None:
        result = section_keys_touching_json_range(_KEYS, _SPANS, 6, 18)
        self.assertEqual(result, ["pe1"])

    def test_unknown_key_in_spans_skipped(self) -> None:
        result = section_keys_touching_json_range(["missing"], _SPANS, 0, 100)
        self.assertEqual(result, [])


class JsonEditorRangeToDerByteRangeTests(unittest.TestCase):

    def test_cursor_in_pe1_returns_tuple(self) -> None:
        result = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 10, 10, empty_selection=True
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_no_touch_returns_none(self) -> None:
        result = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 999, 1000, empty_selection=False
        )
        self.assertIsNone(result)

    def test_range_within_pe1(self) -> None:
        result = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 5, 19, empty_selection=False
        )
        self.assertIsNotNone(result)
        a, b = result
        self.assertLessEqual(a, b)
        self.assertGreaterEqual(a, 0)

    def test_multi_pe_selection_spans_both(self) -> None:
        result = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 5, 44, empty_selection=False
        )
        self.assertIsNotNone(result)
        a, b = result
        self.assertLess(a, 200)

    def test_inverted_range_normalized(self) -> None:
        result_forward = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 5, 19, empty_selection=False
        )
        result_backward = json_editor_range_to_der_byte_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 19, 5, empty_selection=False
        )
        self.assertEqual(result_forward, result_backward)


class DerByteRangeToJsonEditorRangeTests(unittest.TestCase):

    def test_range_in_pe1(self) -> None:
        result = der_byte_range_to_json_editor_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 0, 50
        )
        self.assertIsNotNone(result)
        js, je = result
        self.assertLessEqual(js, je)
        self.assertGreaterEqual(js, 5)   # within pe1 value_start

    def test_range_in_pe2(self) -> None:
        result = der_byte_range_to_json_editor_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 100, 150
        )
        self.assertIsNotNone(result)
        js, je = result
        self.assertGreaterEqual(js, 30)

    def test_no_intersect_returns_none(self) -> None:
        result = der_byte_range_to_json_editor_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 500, 600
        )
        self.assertIsNone(result)

    def test_single_byte_returns_tuple(self) -> None:
        result = der_byte_range_to_json_editor_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 0, 1
        )
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)

    def test_span_end_le_start_corrected(self) -> None:
        # byte_end <= byte_start should be clamped internally.
        result = der_byte_range_to_json_editor_range(
            _KEYS, _SPANS, _RANGES_BY_KEY, 50, 50
        )
        self.assertIsNotNone(result)


class EnclosingJsonValueSpanTests(unittest.TestCase):

    def test_cursor_in_array(self) -> None:
        text = '{"a": [1, 2, 3], "b": "hi"}'
        s, e = enclosing_json_value_span(text, 7, 7)
        self.assertEqual(text[s:e], "[1, 2, 3]")

    def test_empty_text(self) -> None:
        self.assertEqual(enclosing_json_value_span("", 0, 0), (0, 0))

    def test_inverted_lo_hi_normalized(self) -> None:
        text = '{"a": [1, 2], "b": "x"}'
        r_normal = enclosing_json_value_span(text, 6, 12)
        r_inverted = enclosing_json_value_span(text, 12, 6)
        self.assertEqual(r_normal, r_inverted)

    def test_top_level_array(self) -> None:
        text = "[1, 2, 3]"
        s, e = enclosing_json_value_span(text, 0, 0)
        self.assertEqual(text[s:e], "[1, 2, 3]")

    def test_returns_two_tuple(self) -> None:
        text = '{"k": 42}'
        result = enclosing_json_value_span(text, 5, 5)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
