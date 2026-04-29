# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
"""Coverage for the canonical Nord palette module.

The palette is the single source of truth for every CLI / TUI / docs
surface, so the values in :mod:`yggdrasim_common.nord_palette` are
contractually frozen. Any drift here is a release-blocking incident.
"""

from __future__ import annotations

import unittest

from yggdrasim_common.nord_palette import (
    NORD,
    NordAnsi,
    NordHex,
    hex_to_ansi,
    hex_to_ansi_bg,
)


class NordHexCanonicalTests(unittest.TestCase):
    """Pin the canonical Nord hex values."""

    EXPECTED = {
        "POLAR_NIGHT_0": "#2E3440",
        "POLAR_NIGHT_1": "#3B4252",
        "POLAR_NIGHT_2": "#434C5E",
        "POLAR_NIGHT_3": "#4C566A",
        "SNOW_0": "#D8DEE9",
        "SNOW_1": "#E5E9F0",
        "SNOW_2": "#ECEFF4",
        "FROST_TEAL": "#8FBCBB",
        "FROST_CYAN": "#88C0D0",
        "FROST_BLUE": "#81A1C1",
        "FROST_DEEP": "#5E81AC",
        "AURORA_RED": "#BF616A",
        "AURORA_ORANGE": "#D08770",
        "AURORA_YELLOW": "#EBCB8B",
        "AURORA_GREEN": "#A3BE8C",
        "AURORA_PURPLE": "#B48EAD",
    }

    def test_canonical_values_are_pinned(self) -> None:
        for attribute, expected_hex in self.EXPECTED.items():
            with self.subTest(attribute=attribute):
                self.assertEqual(getattr(NordHex, attribute), expected_hex)

    def test_role_aliases_resolve_to_canonical_values(self) -> None:
        self.assertEqual(NordHex.HEADER, NordHex.FROST_TEAL)
        self.assertEqual(NordHex.GREEN, NordHex.AURORA_GREEN)
        self.assertEqual(NordHex.WARNING, NordHex.AURORA_YELLOW)
        self.assertEqual(NordHex.FAIL, NordHex.AURORA_RED)
        self.assertEqual(NordHex.WHITE, NordHex.SNOW_2)
        self.assertEqual(NordHex.BG, NordHex.POLAR_NIGHT_0)


class HexToAnsiTests(unittest.TestCase):
    """Validate the hex -> 24-bit ANSI helper."""

    def test_known_value_with_hash(self) -> None:
        self.assertEqual(hex_to_ansi("#A3BE8C"), "\033[38;2;163;190;140m")

    def test_known_value_without_hash(self) -> None:
        self.assertEqual(hex_to_ansi("BF616A"), "\033[38;2;191;97;106m")

    def test_lowercase_input_is_accepted(self) -> None:
        self.assertEqual(hex_to_ansi("#88c0d0"), "\033[38;2;136;192;208m")

    def test_three_digit_shorthand_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            hex_to_ansi("#ABC")

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            hex_to_ansi("")

    def test_background_helper_emits_48_prefix(self) -> None:
        rendered = hex_to_ansi_bg("#2E3440")
        self.assertEqual(rendered, "\033[48;2;46;52;64m")


class NordAnsiSequencesTests(unittest.TestCase):
    """The pre-rendered ANSI table must agree with the hex helper."""

    def test_each_role_matches_its_hex_origin(self) -> None:
        pairs = [
            (NordAnsi.HEADER, NordHex.FROST_TEAL),
            (NordAnsi.BLUE, NordHex.FROST_BLUE),
            (NordAnsi.CYAN, NordHex.FROST_CYAN),
            (NordAnsi.DEEP_BLUE, NordHex.FROST_DEEP),
            (NordAnsi.GREEN, NordHex.AURORA_GREEN),
            (NordAnsi.YELLOW, NordHex.AURORA_YELLOW),
            (NordAnsi.RED, NordHex.AURORA_RED),
            (NordAnsi.ORANGE, NordHex.AURORA_ORANGE),
            (NordAnsi.PURPLE, NordHex.AURORA_PURPLE),
            (NordAnsi.WHITE, NordHex.SNOW_2),
            (NordAnsi.GUIDE, NordHex.POLAR_NIGHT_3),
        ]
        for ansi_value, hex_value in pairs:
            with self.subTest(hex=hex_value):
                self.assertEqual(ansi_value, hex_to_ansi(hex_value))

    def test_role_aliases_match_their_canonical_role(self) -> None:
        self.assertEqual(NordAnsi.WARNING, NordAnsi.YELLOW)
        self.assertEqual(NordAnsi.FAIL, NordAnsi.RED)
        self.assertEqual(NordAnsi.BROWN, NordAnsi.ORANGE)
        self.assertEqual(NordAnsi.MAGENTA, NordAnsi.PURPLE)

    def test_module_singleton_exposes_attributes(self) -> None:
        self.assertEqual(NORD.RESET, "\033[0m")
        self.assertEqual(NORD.BOLD, "\033[1m")
        self.assertEqual(NORD.GREEN, NordAnsi.GREEN)


if __name__ == "__main__":
    unittest.main()
