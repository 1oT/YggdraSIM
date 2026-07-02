# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP03/logic/euicc_info2.py utility decoders.

Covers: parse_tlv_simple, unwrap_euicc_info2_payload,
        resolve_euicc_info2_tag_name, decode_euicc_info2_value,
        decode_euicc_category, format_named_bit_string,
        decode_named_bit_string, decode_ext_card_resource_value, quote_text.
"""

from __future__ import annotations

import unittest

from SCP03.logic.euicc_info2 import (
    decode_euicc_category,
    decode_euicc_info2_value,
    decode_ext_card_resource_value,
    decode_named_bit_string,
    format_named_bit_string,
    parse_tlv_simple,
    quote_text,
    resolve_euicc_info2_tag_name,
    unwrap_euicc_info2_payload,
)


# ---------------------------------------------------------------------------
# parse_tlv_simple
# ---------------------------------------------------------------------------

class ParseTlvSimpleTests(unittest.TestCase):

    def _tlv(self, tag: int, value: bytes) -> bytes:
        """Build a minimal BER-TLV with short-form length (single-byte tag only)."""
        return bytes([tag, len(value)]) + value

    def test_single_tag_extracted(self) -> None:
        # Single-byte tag 0x04 (primitive, class universal)
        data = self._tlv(0x04, b"\x01\x02")
        result = parse_tlv_simple(data)
        self.assertIn(0x04, result)

    def test_empty_bytes_returns_empty_dict(self) -> None:
        result = parse_tlv_simple(b"")
        self.assertEqual(result, {})

    def test_duplicate_tag_becomes_list(self) -> None:
        tag_a = self._tlv(0x04, b"\x01")
        tag_b = self._tlv(0x04, b"\x02")
        result = parse_tlv_simple(tag_a + tag_b)
        self.assertIsInstance(result.get(0x04), list)


# ---------------------------------------------------------------------------
# unwrap_euicc_info2_payload
# ---------------------------------------------------------------------------

class UnwrapEuiccInfo2PayloadTests(unittest.TestCase):

    def _make_bf22_wrapper(self, inner: bytes) -> bytes:
        length = len(inner)
        return bytes([0xBF, 0x22, length]) + inner

    def test_bf22_wrapped_payload_unwrapped(self) -> None:
        inner = bytes([0x81, 0x01, 0x01])
        wrapped = self._make_bf22_wrapper(inner)
        result = unwrap_euicc_info2_payload(wrapped)
        self.assertEqual(result, inner)

    def test_already_unwrapped_returned_as_is(self) -> None:
        inner = bytes([0x81, 0x01, 0x01])
        result = unwrap_euicc_info2_payload(inner)
        self.assertEqual(result, inner)


# ---------------------------------------------------------------------------
# resolve_euicc_info2_tag_name
# ---------------------------------------------------------------------------

class ResolveEuiccInfo2TagNameTests(unittest.TestCase):

    def test_known_top_level_tag_resolves(self) -> None:
        # 0x81 = profileVersion within BF22
        name = resolve_euicc_info2_tag_name(0x81, 0xBF22)
        self.assertIsNotNone(name)
        self.assertIsInstance(name, str)

    def test_unknown_tag_returns_none(self) -> None:
        name = resolve_euicc_info2_tag_name(0xFF, 0xBF22)
        self.assertIsNone(name)

    def test_no_parent_unknown_returns_none(self) -> None:
        name = resolve_euicc_info2_tag_name(0x81, None)
        self.assertIsNone(name)


# ---------------------------------------------------------------------------
# decode_euicc_info2_value
# ---------------------------------------------------------------------------

class DecodeEuiccInfo2ValueTests(unittest.TestCase):

    def test_profile_version_decoded_as_string(self) -> None:
        # 0x81 = profileVersion: three-byte version
        result = decode_euicc_info2_value(0x81, bytes([0x02, 0x00, 0x00]), 0xBF22)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_euicc_category_decoded(self) -> None:
        result = decode_euicc_info2_value(0x8B, bytes([0x01]), 0xBF22)
        self.assertIsNotNone(result)
        self.assertIn("basicEuicc", str(result))

    def test_ipa_mode_decoded(self) -> None:
        result = decode_euicc_info2_value(0x90, bytes([0x00]), 0xBF22)
        self.assertIsNotNone(result)
        self.assertIn("ipad", str(result).lower())

    def test_unknown_combination_returns_none(self) -> None:
        result = decode_euicc_info2_value(0xFF, bytes([0x00]), None)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# decode_euicc_category
# ---------------------------------------------------------------------------

class DecodeEuiccCategoryTests(unittest.TestCase):

    def test_other(self) -> None:
        self.assertIn("other", decode_euicc_category(bytes([0x00])))

    def test_basic_euicc(self) -> None:
        self.assertIn("basicEuicc", decode_euicc_category(bytes([0x01])))

    def test_medium_euicc(self) -> None:
        self.assertIn("mediumEuicc", decode_euicc_category(bytes([0x02])))

    def test_contactless_euicc(self) -> None:
        self.assertIn("contactlessEuicc", decode_euicc_category(bytes([0x03])))

    def test_unknown_value_is_labelled(self) -> None:
        result = decode_euicc_category(bytes([0xFE]))
        self.assertIn("unknown", result)

    def test_wrong_length_returns_hex(self) -> None:
        result = decode_euicc_category(bytes([0x01, 0x02]))
        self.assertIn("0102", result.lower())


# ---------------------------------------------------------------------------
# decode_named_bit_string / format_named_bit_string
# ---------------------------------------------------------------------------

_SAMPLE_BITS = {0: "alpha", 1: "beta", 2: "gamma"}


class DecodeNamedBitStringTests(unittest.TestCase):

    def test_empty_value_returns_empty_list(self) -> None:
        self.assertEqual(decode_named_bit_string(b"", _SAMPLE_BITS), [])

    def test_no_bits_set(self) -> None:
        # unused_bits=0, payload byte 0x00 — no bits set
        result = decode_named_bit_string(bytes([0x00, 0x00]), _SAMPLE_BITS)
        self.assertEqual(result, [])

    def test_first_bit_set(self) -> None:
        # unused_bits=0, payload byte 0x80 — bit 0 set
        result = decode_named_bit_string(bytes([0x00, 0x80]), _SAMPLE_BITS)
        self.assertIn("alpha", result)

    def test_multiple_bits_set(self) -> None:
        # bits 0 and 1 set → 0xC0
        result = decode_named_bit_string(bytes([0x00, 0xC0]), _SAMPLE_BITS)
        self.assertIn("alpha", result)
        self.assertIn("beta", result)

    def test_unknown_bit_label_auto_generated(self) -> None:
        # bit 7 set (0x01 in first byte with unused=0), not in _SAMPLE_BITS
        result = decode_named_bit_string(bytes([0x00, 0x01]), _SAMPLE_BITS)
        self.assertTrue(any(r.startswith("bit") for r in result))


class FormatNamedBitStringTests(unittest.TestCase):

    def test_empty_payload_set_none(self) -> None:
        result = format_named_bit_string(bytes([0x00, 0x00]), _SAMPLE_BITS)
        self.assertIn("none", result)

    def test_set_bit_appears_in_output(self) -> None:
        result = format_named_bit_string(bytes([0x00, 0x80]), _SAMPLE_BITS)
        self.assertIn("alpha", result)

    def test_hex_prefix_present(self) -> None:
        result = format_named_bit_string(bytes([0x00, 0x80]), _SAMPLE_BITS)
        self.assertIn("0080", result.lower())


# ---------------------------------------------------------------------------
# decode_ext_card_resource_value
# ---------------------------------------------------------------------------

class DecodeExtCardResourceValueTests(unittest.TestCase):

    def test_tag_81_returns_int_string(self) -> None:
        result = decode_ext_card_resource_value(0x81, bytes([0x00, 0x0A]))
        self.assertIsNotNone(result)
        self.assertIn("10", str(result))

    def test_tag_82_small_value_in_bytes(self) -> None:
        result = decode_ext_card_resource_value(0x82, bytes([0x00, 0x64]))
        self.assertIsNotNone(result)
        self.assertIn("B", str(result))

    def test_tag_82_large_value_in_kb(self) -> None:
        # 4096 bytes = 4.0 KB
        result = decode_ext_card_resource_value(0x82, bytes([0x10, 0x00]))
        self.assertIsNotNone(result)
        self.assertIn("KB", str(result))

    def test_unknown_tag_returns_none(self) -> None:
        result = decode_ext_card_resource_value(0xFF, bytes([0x01]))
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# quote_text
# ---------------------------------------------------------------------------

class QuoteTextTests(unittest.TestCase):

    def test_ascii_text_wrapped_in_quotes(self) -> None:
        result = quote_text(b"hello")
        self.assertEqual(result, '"hello"')

    def test_non_utf8_returns_hex(self) -> None:
        result = quote_text(bytes([0x80, 0xFE]))
        self.assertNotIn('"', result)
        self.assertIn("80", result.lower())

    def test_empty_bytes_returns_empty_quoted_string(self) -> None:
        result = quote_text(b"")
        self.assertEqual(result, '""')


if __name__ == "__main__":
    unittest.main()
