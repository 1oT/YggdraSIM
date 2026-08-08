# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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


class ApduLengthErrorTests(unittest.TestCase):
    """Length faults carry a type the engine can map to a precise SW.

    ``ApduLengthError`` subclasses ``ValueError``, so callers that only
    catch ``ValueError`` are unaffected.
    """

    def test_length_error_is_a_value_error(self) -> None:
        from SIMCARD.utils import ApduLengthError

        self.assertTrue(issubclass(ApduLengthError, ValueError))

    def test_every_length_fault_raises_the_dedicated_type(self) -> None:
        from SIMCARD.utils import ApduLengthError

        cases = {
            "runt under four bytes": "00A400",
            "short Lc over-claims its body": "00A40004F23F00",
            "trailing bytes after short Lc": "00A4000403DEADBEEFCA",
            "extended payload truncated": "00A400040000 05AABB",
        }
        for label, hex_text in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ApduLengthError):
                    parse_apdu(_apdu(hex_text))


class EngineLengthStatusWordTests(unittest.TestCase):
    """ISO/IEC 7816-4 §5.6: a length mismatch is 6700, not 6F00."""

    @classmethod
    def setUpClass(cls) -> None:
        from SIMCARD.connection import get_shared_engine

        cls.engine = get_shared_engine()

    def _sw(self, hex_text: str) -> str:
        _data, sw1, sw2 = self.engine.transmit(_apdu(hex_text))
        return f"{sw1:02X}{sw2:02X}"

    def test_over_claiming_lc_returns_6700(self) -> None:
        # Found by the simulator-targeted fuzzer: Lc=0xF2 with two data
        # bytes previously fell through to the 6F00 catch-all.
        self.assertEqual(self._sw("00A40004F23F00"), "6700")

    def test_runt_apdu_returns_6700(self) -> None:
        self.assertEqual(self._sw("00A400"), "6700")

    def test_trailing_bytes_after_lc_return_6700(self) -> None:
        self.assertEqual(self._sw("00A4000403DEADBEEFCA"), "6700")

    def test_truncated_extended_payload_returns_6700(self) -> None:
        self.assertEqual(self._sw("00A400040000 05AABB"), "6700")

    def test_valid_apdus_are_unaffected(self) -> None:
        for label, hex_text in {
            "case 3S SELECT MF": "00A40004023F00",
            "case 2S with Le": "00A4000402",
            "case 2E extended Le": "00A400040000 0A",
        }.items():
            with self.subTest(case=label):
                self.assertEqual(self._sw(hex_text), "9000")

    def test_internal_faults_still_return_6f00(self) -> None:
        """6F00 stays reserved for a genuine no-precise-diagnosis fault.

        TERMINATE CARD USAGE makes the card refuse everything but STATUS;
        that is a deliberate 6F00 return, not a length fault.
        """
        self.engine.transmit(_apdu("00FE000000"))
        try:
            self.assertEqual(self._sw("00A40000023F00"), "6F00")
        finally:
            self.engine.state.terminated_card_usage = False
