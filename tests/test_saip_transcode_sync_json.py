# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for JSON-scanner helpers in ``Tools.ProfilePackage.saip_transcode_sync``.

Covers: scan_json_object_members, scan_json_list_items,
enclosing_json_value_span.  All three functions are pure-text
scanners that do not touch the card, pySim, or ASN.1 codec.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_transcode_sync import (
    enclosing_json_value_span,
    scan_json_list_items,
    scan_json_object_members,
)


class ScanJsonObjectMembersTests(unittest.TestCase):

    def test_simple_object(self) -> None:
        text = '{"a": 1, "b": "hello"}'
        members = scan_json_object_members(text, 0, len(text))
        keys = [m[0] for m in members]
        self.assertEqual(keys, ["a", "b"])

    def test_empty_object_returns_empty_list(self) -> None:
        text = "{}"
        members = scan_json_object_members(text, 0, len(text))
        self.assertEqual(members, [])

    def test_nested_value_is_single_member(self) -> None:
        # The value span for "x" should cover the entire nested object.
        text = '{"x": {"y": 1}}'
        members = scan_json_object_members(text, 0, len(text))
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0][0], "x")

    def test_string_value(self) -> None:
        text = '{"key": "val"}'
        members = scan_json_object_members(text, 0, len(text))
        self.assertEqual(members[0][0], "key")
        key_text, value_start, value_end = members[0]
        self.assertEqual(text[value_start:value_end], '"val"')

    def test_numeric_value(self) -> None:
        text = '{"n": 42}'
        members = scan_json_object_members(text, 0, len(text))
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0][0], "n")

    def test_returns_list(self) -> None:
        self.assertIsInstance(scan_json_object_members("{}", 0, 2), list)


class ScanJsonListItemsTests(unittest.TestCase):

    def test_simple_list(self) -> None:
        text = "[1, 2, 3]"
        items = scan_json_list_items(text, 0, len(text))
        self.assertEqual(len(items), 3)

    def test_empty_list_returns_empty(self) -> None:
        text = "[]"
        items = scan_json_list_items(text, 0, len(text))
        self.assertEqual(items, [])

    def test_string_items(self) -> None:
        text = '["a", "b"]'
        items = scan_json_list_items(text, 0, len(text))
        self.assertEqual(len(items), 2)

    def test_item_spans_cover_value(self) -> None:
        text = "[42, 99]"
        items = scan_json_list_items(text, 0, len(text))
        first_start, first_end = items[0]
        self.assertEqual(text[first_start:first_end], "42")

    def test_nested_object_in_list(self) -> None:
        text = '[{"a": 1}, {"b": 2}]'
        items = scan_json_list_items(text, 0, len(text))
        self.assertEqual(len(items), 2)

    def test_returns_list_of_tuples(self) -> None:
        items = scan_json_list_items("[1]", 0, 3)
        self.assertIsInstance(items, list)
        for item in items:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)


class EnclosingJsonValueSpanTests(unittest.TestCase):

    def test_empty_text_returns_zero_zero(self) -> None:
        s, e = enclosing_json_value_span("", 0, 0)
        self.assertEqual((s, e), (0, 0))

    def test_top_level_array(self) -> None:
        text = "[1, 2, 3]"
        s, e = enclosing_json_value_span(text, 0, len(text))
        self.assertEqual(text[s:e], "[1, 2, 3]")

    def test_caret_inside_array_returns_array(self) -> None:
        text = '{"key": [1, 2, 3]}'
        # Caret at index 9 (inside the array value).
        s, e = enclosing_json_value_span(text, 9, 9)
        self.assertEqual(text[s:e], "[1, 2, 3]")

    def test_top_level_string(self) -> None:
        text = '"hello"'
        s, e = enclosing_json_value_span(text, 2, 2)
        self.assertEqual(text[s:e], '"hello"')

    def test_inverted_lo_hi_normalized(self) -> None:
        text = "[1, 2]"
        s1, e1 = enclosing_json_value_span(text, 2, 0)
        s2, e2 = enclosing_json_value_span(text, 0, 2)
        self.assertEqual((s1, e1), (s2, e2))

    def test_returns_tuple_of_two_ints(self) -> None:
        result = enclosing_json_value_span("[1]", 0, 1)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], int)
        self.assertIsInstance(result[1], int)

    def test_span_starts_not_after_end(self) -> None:
        text = '{"a": 1}'
        s, e = enclosing_json_value_span(text, 0, len(text))
        self.assertLessEqual(s, e)


if __name__ == "__main__":
    unittest.main()
