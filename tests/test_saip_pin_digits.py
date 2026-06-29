# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_pin_digits``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_pin_digits as P


class EncodeDigitsTests(unittest.TestCase):

    def test_pin_round_trip_default(self) -> None:
        encoded = P.encode_digits_to_hex("1234")
        self.assertEqual(encoded, "31323334FFFFFFFF")
        decoded = P.decode_hex_to_digits(encoded)
        self.assertEqual(decoded["digits"], "1234")
        self.assertEqual(decoded["pad_byte_hex"], "FF")
        self.assertTrue(decoded["valid_digits_only"])

    def test_pin_full_eight_digits(self) -> None:
        encoded = P.encode_digits_to_hex("12345678")
        self.assertEqual(encoded, "3132333435363738")
        decoded = P.decode_hex_to_digits(encoded)
        self.assertEqual(decoded["digits"], "12345678")
        self.assertEqual(decoded["pad_byte_hex"], "")
        self.assertTrue(decoded["valid_digits_only"])

    def test_pin_sixteen_byte_target(self) -> None:
        encoded = P.encode_digits_to_hex("99", target_byte_length=16)
        self.assertEqual(len(encoded) // 2, 16)
        self.assertTrue(encoded.startswith("3939"))

    def test_rejects_non_digit(self) -> None:
        with self.assertRaises(ValueError):
            P.encode_digits_to_hex("12A4")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            P.encode_digits_to_hex("")

    def test_rejects_too_long(self) -> None:
        with self.assertRaises(ValueError):
            P.encode_digits_to_hex("123456789")  # 9 digits in 8-byte slot

    def test_rejects_unsupported_target_length(self) -> None:
        with self.assertRaises(ValueError):
            P.encode_digits_to_hex("1234", target_byte_length=12)


class DecodeHexTests(unittest.TestCase):

    def test_decode_partial_padding(self) -> None:
        decoded = P.decode_hex_to_digits("3132FFFFFFFFFFFF")
        self.assertEqual(decoded["digits"], "12")
        self.assertEqual(decoded["pad_byte_hex"], "FF")

    def test_decode_invalid_post_pad_byte(self) -> None:
        decoded = P.decode_hex_to_digits("3132FFFF31FFFFFF")
        self.assertEqual(decoded["digits"], "12")
        self.assertFalse(decoded["valid_digits_only"])

    def test_decode_non_ff_pad(self) -> None:
        decoded = P.decode_hex_to_digits("313200000000FFFF")
        self.assertEqual(decoded["digits"], "12")
        self.assertEqual(decoded["pad_byte_hex"], "00")
        self.assertFalse(decoded["valid_digits_only"])

    def test_decode_rejects_odd_nibble(self) -> None:
        with self.assertRaises(ValueError):
            P.decode_hex_to_digits("313")

    def test_decode_rejects_unsupported_length(self) -> None:
        with self.assertRaises(ValueError):
            P.decode_hex_to_digits("313233")  # 3 bytes


class CoerceDispatchTests(unittest.TestCase):

    def test_coerce_digits(self) -> None:
        self.assertEqual(P.coerce_to_hex("1234", coding="digits"), "31323334FFFFFFFF")

    def test_coerce_hex_passthrough(self) -> None:
        self.assertEqual(
            P.coerce_to_hex("31323334ffffffff", coding="hex"),
            "31323334FFFFFFFF",
        )

    def test_coerce_unknown_mode(self) -> None:
        with self.assertRaises(ValueError):
            P.coerce_to_hex("1234", coding="ascii")


if __name__ == "__main__":
    unittest.main()
