# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for Tools/ProfilePackage/saip_profile_template.py pure utility functions.

Covers: normalize_placeholder_style, render_placeholder,
        normalize_raw_hex_token_value, build_override_token_definitions,
        and the visit/walk logic indirectly through build_override_token_definitions.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_profile_template import (
    build_override_token_definitions,
    normalize_placeholder_style,
    normalize_raw_hex_token_value,
    render_placeholder,
)


# ---------------------------------------------------------------------------
# normalize_placeholder_style
# ---------------------------------------------------------------------------

class NormalizePlaceholderStyleTests(unittest.TestCase):

    def test_brace_accepted(self) -> None:
        self.assertEqual(normalize_placeholder_style("brace"), "brace")

    def test_curly_alias_normalised_to_brace(self) -> None:
        self.assertEqual(normalize_placeholder_style("curly"), "brace")

    def test_bracket_accepted(self) -> None:
        self.assertEqual(normalize_placeholder_style("bracket"), "bracket")

    def test_case_insensitive(self) -> None:
        self.assertEqual(normalize_placeholder_style("BRACE"), "brace")
        self.assertEqual(normalize_placeholder_style("BRACKET"), "bracket")

    def test_unknown_style_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_placeholder_style("square")

    def test_empty_string_defaults_to_brace(self) -> None:
        self.assertEqual(normalize_placeholder_style(""), "brace")

    def test_none_defaults_to_brace(self) -> None:
        self.assertEqual(normalize_placeholder_style(None), "brace")


# ---------------------------------------------------------------------------
# render_placeholder
# ---------------------------------------------------------------------------

class RenderPlaceholderTests(unittest.TestCase):

    def test_brace_style_wraps_with_curly(self) -> None:
        self.assertEqual(render_placeholder("ICCID", "brace"), "{ICCID}")

    def test_bracket_style_wraps_with_square(self) -> None:
        self.assertEqual(render_placeholder("IMSI", "bracket"), "[IMSI]")

    def test_default_style_is_brace(self) -> None:
        self.assertEqual(render_placeholder("KEY"), "{KEY}")

    def test_brace_wrapped_name_accepted(self) -> None:
        self.assertEqual(render_placeholder("{ICCID}"), "{ICCID}")

    def test_bracket_wrapped_name_in_brace_style(self) -> None:
        self.assertEqual(render_placeholder("[ICCID]", "brace"), "{ICCID}")

    def test_invalid_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            render_placeholder("123INVALID")


# ---------------------------------------------------------------------------
# normalize_raw_hex_token_value
# ---------------------------------------------------------------------------

class NormalizeRawHexTokenValueTests(unittest.TestCase):

    def test_valid_hex_returned_uppercase(self) -> None:
        result = normalize_raw_hex_token_value("deadbeef", token_name="KEY")
        self.assertEqual(result, "DEADBEEF")

    def test_hex_with_spaces_stripped(self) -> None:
        result = normalize_raw_hex_token_value("DE AD BE EF", token_name="KEY")
        self.assertEqual(result, "DEADBEEF")

    def test_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_raw_hex_token_value("", token_name="KEY")

    def test_odd_nibbles_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_raw_hex_token_value("ABC", token_name="KEY")

    def test_non_hex_characters_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_raw_hex_token_value("GGGG", token_name="KEY")


# ---------------------------------------------------------------------------
# build_override_token_definitions
# ---------------------------------------------------------------------------

class BuildOverrideTokenDefinitionsTests(unittest.TestCase):

    _VALID_ICCID = "8988201234567890123"  # 19 digits → padded to 20 with F

    def test_iccid_produces_two_entries(self) -> None:
        result = build_override_token_definitions({"ICCID": self._VALID_ICCID})
        self.assertIn("ICCID", result)
        self.assertIn("ICCID_EF", result)

    def test_iccid_hex_is_20_nibbles(self) -> None:
        result = build_override_token_definitions({"ICCID": self._VALID_ICCID})
        self.assertEqual(len(result["ICCID"]["hex"]), 20)

    def test_imsi_produces_hex_field(self) -> None:
        result = build_override_token_definitions({"IMSI": "001010000000001"})
        self.assertIn("IMSI", result)
        self.assertIn("hex", result["IMSI"])

    def test_raw_hex_token_stored(self) -> None:
        result = build_override_token_definitions({"KEY": "AABBCCDD"})
        self.assertIn("KEY", result)
        self.assertEqual(result["KEY"]["hex"], "AABBCCDD")

    def test_raw_hex_token_uppercase_normalised(self) -> None:
        result = build_override_token_definitions({"KEY": "aabbccdd"})
        self.assertEqual(result["KEY"]["hex"], "AABBCCDD")

    def test_empty_assignments_returns_empty_dict(self) -> None:
        result = build_override_token_definitions({})
        self.assertEqual(result, {})

    def test_brace_wrapped_key_normalised(self) -> None:
        result = build_override_token_definitions({"{KEY}": "AABB"})
        self.assertIn("KEY", result)

    def test_invalid_hex_for_raw_token_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_override_token_definitions({"RAW": "ZZZZ"})


if __name__ == "__main__":
    unittest.main()
