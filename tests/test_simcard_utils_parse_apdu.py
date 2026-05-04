"""ISO 7816-4 APDU parser regression tests for ``SIMCARD/utils.py``.

These cover all four cases from §5.1 in both short and extended
encodings. A prior implementation mishandled case 2E (extended Le,
no command data) by treating the Le bytes as an Lc and rejecting the
APDU with "Extended APDU payload is truncated".
"""

from __future__ import annotations

import unittest

from SIMCARD.utils import parse_apdu


def _apdu(hex_text: str) -> bytes:
    return bytes.fromhex(hex_text.replace(" ", ""))


class ParseApduShortCases(unittest.TestCase):

    def test_case_1_no_data_no_le(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00"))
        self.assertEqual(parsed["cla"], 0x00)
        self.assertEqual(parsed["ins"], 0xA4)
        self.assertEqual(parsed["data"], b"")
        self.assertIsNone(parsed["le"])

    def test_case_2s_le_small(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 05"))
        self.assertEqual(parsed["data"], b"")
        self.assertEqual(parsed["le"], 5)

    def test_case_2s_le_zero_means_256(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 00"))
        self.assertEqual(parsed["data"], b"")
        self.assertEqual(parsed["le"], 256)

    def test_case_3s_with_data(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 02 FF FF"))
        self.assertEqual(parsed["data"], b"\xff\xff")
        self.assertIsNone(parsed["le"])

    def test_case_4s_data_and_le(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 02 FF FF 03"))
        self.assertEqual(parsed["data"], b"\xff\xff")
        self.assertEqual(parsed["le"], 3)


class ParseApduExtendedCases(unittest.TestCase):

    def test_case_2e_le_short_extended(self) -> None:
        # CLA INS P1 P2 00 Le_hi Le_lo -> Le = 0x0100 = 256
        parsed = parse_apdu(_apdu("00 A4 00 00 00 01 00"))
        self.assertEqual(parsed["data"], b"")
        self.assertEqual(parsed["le"], 256)

    def test_case_2e_le_zero_means_65536(self) -> None:
        # Le_hi=00 Le_lo=00 encodes the maximum extended Le.
        parsed = parse_apdu(_apdu("00 A4 00 00 00 00 00"))
        self.assertEqual(parsed["data"], b"")
        self.assertEqual(parsed["le"], 65536)

    def test_case_3e_with_data(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 00 00 02 FF FF"))
        self.assertEqual(parsed["data"], b"\xff\xff")
        self.assertIsNone(parsed["le"])

    def test_case_4e_data_with_extended_le(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 00 00 02 FF FF 01 00"))
        self.assertEqual(parsed["data"], b"\xff\xff")
        self.assertEqual(parsed["le"], 256)

    def test_case_4e_le_zero_means_65536(self) -> None:
        parsed = parse_apdu(_apdu("00 A4 00 00 00 00 02 FF FF 00 00"))
        self.assertEqual(parsed["data"], b"\xff\xff")
        self.assertEqual(parsed["le"], 65536)

    def test_short_apdu_body_truncated_is_rejected(self) -> None:
        # Lc=5 but only 3 bytes follow
        with self.assertRaises(ValueError):
            parse_apdu(_apdu("00 A4 00 00 05 01 02 03"))

    def test_extended_apdu_body_truncated_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_apdu(_apdu("00 A4 00 00 00 00 05 01 02 03"))

    def test_extended_apdu_with_stray_trailing_bytes_is_rejected(self) -> None:
        # Case 4E must have exactly 2 trailing bytes for Le.
        with self.assertRaises(ValueError):
            parse_apdu(_apdu("00 A4 00 00 00 00 02 FF FF 01 00 AA"))

    def test_apdu_too_short_for_header(self) -> None:
        with self.assertRaises(ValueError):
            parse_apdu(b"\x00\xA4\x00")


if __name__ == "__main__":
    unittest.main()
