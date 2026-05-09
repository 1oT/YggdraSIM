# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP03/logic/sgp32_decode.py pure utility functions.

Covers: decode_integer, decode_text_or_hex, decode_bcd_digits,
        first_bytes, count_child_tag, collect_nested_tag_values,
        unwrap_root_tag, decode_notification_entry.
"""

from __future__ import annotations

import unittest

from SCP03.logic.sgp32_decode import (
    collect_nested_tag_values,
    count_child_tag,
    decode_bcd_digits,
    decode_integer,
    decode_notification_entry,
    decode_text_or_hex,
    first_bytes,
    unwrap_root_tag,
)


# ---------------------------------------------------------------------------
# decode_integer
# ---------------------------------------------------------------------------

class DecodeIntegerTests(unittest.TestCase):

    def test_empty_returns_zero(self) -> None:
        self.assertEqual(decode_integer(b""), 0)

    def test_single_byte(self) -> None:
        self.assertEqual(decode_integer(bytes([0x0A])), 10)

    def test_two_bytes_big_endian(self) -> None:
        self.assertEqual(decode_integer(bytes([0x00, 0x0A])), 10)

    def test_large_value(self) -> None:
        self.assertEqual(decode_integer(bytes([0x01, 0x00, 0x00])), 65536)


# ---------------------------------------------------------------------------
# decode_text_or_hex
# ---------------------------------------------------------------------------

class DecodeTextOrHexTests(unittest.TestCase):

    def test_empty_returns_empty_string(self) -> None:
        self.assertEqual(decode_text_or_hex(b""), "")

    def test_ascii_text_returned(self) -> None:
        self.assertEqual(decode_text_or_hex(b"hello"), "hello")

    def test_non_utf8_returns_hex(self) -> None:
        result = decode_text_or_hex(bytes([0x80, 0xFF]))
        self.assertNotEqual(result, "")
        self.assertIn("80", result.lower())

    def test_non_printable_utf8_returns_hex(self) -> None:
        # Null byte is valid UTF-8 but not isprintable
        result = decode_text_or_hex(bytes([0x00]))
        self.assertIn("00", result.lower())


# ---------------------------------------------------------------------------
# decode_bcd_digits
# ---------------------------------------------------------------------------

class DecodeBcdDigitsTests(unittest.TestCase):

    def test_two_digits_per_byte(self) -> None:
        # 0x21 → low=1, high=2 → "12"
        self.assertEqual(decode_bcd_digits(bytes([0x21])), "12")

    def test_four_digit_iccid_fragment(self) -> None:
        # 0x21 0x43 → "1234"
        self.assertEqual(decode_bcd_digits(bytes([0x21, 0x43])), "1234")

    def test_filler_nibble_omitted(self) -> None:
        # low nibble first: 0xF1 → low=1, high=F(filler) → "1"
        self.assertEqual(decode_bcd_digits(bytes([0xF1])), "1")

    def test_invalid_nibble_returns_hex(self) -> None:
        # 0xAB → low=B=11>9 and not filler → falls back to hex
        result = decode_bcd_digits(bytes([0xAB]))
        self.assertIn("ab", result.lower())

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(decode_bcd_digits(b""), "")


# ---------------------------------------------------------------------------
# first_bytes
# ---------------------------------------------------------------------------

class FirstBytesTests(unittest.TestCase):

    def test_bytes_returned_as_is(self) -> None:
        self.assertEqual(first_bytes(b"\xAA\xBB"), b"\xAA\xBB")

    def test_list_returns_first_element(self) -> None:
        self.assertEqual(first_bytes([b"\x01", b"\x02"]), b"\x01")

    def test_none_returns_none(self) -> None:
        self.assertIsNone(first_bytes(None))

    def test_empty_list_returns_none(self) -> None:
        self.assertIsNone(first_bytes([]))

    def test_list_of_non_bytes_returns_none(self) -> None:
        self.assertIsNone(first_bytes([1, 2, 3]))


# ---------------------------------------------------------------------------
# unwrap_root_tag
# ---------------------------------------------------------------------------

class UnwrapRootTagTests(unittest.TestCase):

    def _make_tlv(self, tag: int, value: bytes) -> bytes:
        if tag <= 0x7F:
            tag_bytes = bytes([tag])
        else:
            tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF])
        return tag_bytes + bytes([len(value)]) + value

    def test_matching_tag_unwrapped(self) -> None:
        inner = bytes([0x81, 0x01, 0x00])
        data = self._make_tlv(0x04, inner)
        result = unwrap_root_tag(data, 0x04)
        self.assertEqual(result, inner)

    def test_wrong_tag_returns_none(self) -> None:
        inner = bytes([0x01])
        data = self._make_tlv(0x04, inner)
        result = unwrap_root_tag(data, 0x80)
        self.assertIsNone(result)

    def test_multiple_tlvs_returns_none(self) -> None:
        t1 = self._make_tlv(0x04, b"\x01")
        t2 = self._make_tlv(0x04, b"\x02")
        result = unwrap_root_tag(t1 + t2, 0x04)
        self.assertIsNone(result)

    def test_zero_tag_empty_input_returns_empty(self) -> None:
        result = unwrap_root_tag(b"", 0)
        self.assertEqual(result, b"")


# ---------------------------------------------------------------------------
# count_child_tag
# ---------------------------------------------------------------------------

class CountChildTagTests(unittest.TestCase):

    def _make_tlv(self, tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    def test_two_matching_children_counted(self) -> None:
        child = self._make_tlv(0x80, b"\x01")
        parent_value = child + child
        result = count_child_tag(parent_value, 0x80)
        self.assertEqual(result, 2)

    def test_no_matching_child_returns_zero(self) -> None:
        child = self._make_tlv(0x80, b"\x01")
        result = count_child_tag(child, 0x81)
        self.assertEqual(result, 0)

    def test_none_input_returns_zero(self) -> None:
        self.assertEqual(count_child_tag(None, 0x80), 0)


# ---------------------------------------------------------------------------
# collect_nested_tag_values
# ---------------------------------------------------------------------------

class CollectNestedTagValuesTests(unittest.TestCase):

    def _make_tlv(self, tag: int, value: bytes, constructed: bool = False) -> bytes:
        tag_byte = tag | (0x20 if constructed else 0x00)
        return bytes([tag_byte, len(value)]) + value

    def test_flat_match_collected(self) -> None:
        inner = bytes([0xDE, 0xAD])
        data = self._make_tlv(0x04, inner)
        result = collect_nested_tag_values(data, 0x04)
        self.assertIn(inner, result)

    def test_nested_match_collected(self) -> None:
        leaf = self._make_tlv(0x04, b"\xFF")
        wrapper = self._make_tlv(0x24, leaf, constructed=True)
        result = collect_nested_tag_values(wrapper, 0x04)
        self.assertIn(b"\xFF", result)

    def test_no_match_returns_empty(self) -> None:
        data = self._make_tlv(0x04, b"\x01")
        result = collect_nested_tag_values(data, 0x99)
        self.assertEqual(result, [])

    def test_empty_input_returns_empty(self) -> None:
        self.assertEqual(collect_nested_tag_values(b"", 0x04), [])


# ---------------------------------------------------------------------------
# decode_notification_entry
# ---------------------------------------------------------------------------

class DecodeNotificationEntryTests(unittest.TestCase):

    def test_empty_entry_returns_empty_dict(self) -> None:
        result = decode_notification_entry(b"")
        self.assertIsInstance(result, dict)

    def test_seq_number_extracted(self) -> None:
        # Build a minimal TLV: tag 0x80, value 0x01
        tlv = bytes([0x80, 0x01, 0x01])
        result = decode_notification_entry(tlv)
        self.assertIn("seqNumber", result)
        self.assertEqual(result["seqNumber"], "1")

    def test_iccid_tag_extracted_as_bcd(self) -> None:
        # tag 0x5A (ICCID in TLV), value 0x21 0x43
        tlv = bytes([0x5A, 0x02, 0x21, 0x43])
        result = decode_notification_entry(tlv)
        self.assertIn("iccid", result)
        self.assertIn("1234", result["iccid"])


if __name__ == "__main__":
    unittest.main()
