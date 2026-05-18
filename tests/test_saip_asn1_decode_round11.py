# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Round-11 EF-decoder field-level parity tests.

Targets the field-level enrichments to EF.AD, EF.IMSI, EF.ICCID,
EF.Routing_Indicator, and the EF.UST service catalogue so the GUI
editor surfaces the same atomic fields the reference profile-creator
exposes per the 3GPP TS 31.102 v18.4 layout.
"""
from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _UST_SERVICE_NAMES,
    _decode_ad,
    _decode_iccid,
    _decode_imsi,
    _decode_routing_indicator,
)


class UstCatalogueTests(unittest.TestCase):
    def test_release_18_services_147_through_150_present(self) -> None:
        for service_number in (147, 148, 149, 150):
            self.assertIn(service_number, _UST_SERVICE_NAMES)
        self.assertIn("5MBS", _UST_SERVICE_NAMES[147])
        self.assertIn("SENSE", _UST_SERVICE_NAMES[148])
        self.assertIn("A2X", _UST_SERVICE_NAMES[149])
        self.assertIn("IMS Data Channel", _UST_SERVICE_NAMES[150])


class AdministrativeDataTests(unittest.TestCase):
    def test_normal_mode_with_explicit_2digit_mnc(self) -> None:
        # Op mode 'normal' (00), additional info bytes 00 00, MNC=2.
        decoded = _decode_ad("00000002")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["administrativeMode"], "Normal")
        self.assertEqual(decoded["mncLengthDigits"], 2)
        self.assertEqual(decoded["mncLengthSource"], "explicit")

    def test_specific_facilities_byte_3_flag_bits(self) -> None:
        # Mode=01, byte2=00, byte3=0x1F = ciphering+csg+prose+edrx+5g_prose
        decoded = _decode_ad("01001F03")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["administrativeMode"], "Normal + specific facilities")
        flags = decoded["additionalInfoFlags"]
        assert isinstance(flags, dict)
        self.assertTrue(flags["cipheringIndicatorEnabled"])
        self.assertTrue(flags["csgDisplayControl"])
        self.assertTrue(flags["proseForPublicSafetyAuthorized"])
        self.assertTrue(flags["extendedDrxAuthorized"])
        self.assertTrue(flags["fiveGProseAuthorized"])
        self.assertEqual(decoded["mncLengthDigits"], 3)

    def test_service_driven_mnc_length_zero_carries_explanatory_label(self) -> None:
        decoded = _decode_ad("00000000")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["mncLengthDigits"], 0)
        self.assertIn("service-driven", decoded["mncLengthSource"])

    def test_trailing_rfu_bytes_surfaced(self) -> None:
        # 5+ byte file — extra bytes treated as RFU.
        decoded = _decode_ad("0000000201020304")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["rfuTrailingHex"], "01020304")


class ImsiBreakdownTests(unittest.TestCase):
    @staticmethod
    def _encode_imsi(digits: str) -> str:
        """Encode an IMSI digit string to the EF.IMSI hex form.

        TS 24.008 §10.5.1.4 layout: length byte || (type/parity LSN +
        1st digit MSN) || nibble-swapped pairs of remaining digits
        with 0xF padding for an even pair count.
        """
        if digits.isdigit() is False:
            raise AssertionError(f"non-digit IMSI: {digits}")
        # Byte 1 = type-of-identity (low nibble) + first digit (high
        # nibble). Type=001, parity=odd→1/even→0 in b4; for an
        # odd digit count parity bit = 1 → low nibble 0x9.
        odd = (len(digits) % 2) == 1
        parity = 0x09 if odd else 0x01
        first_digit = int(digits[0])
        byte1 = (first_digit << 4) | parity
        # Remaining digits — pad to even count so they pack into
        # whole bytes; pad nibble = 0xF.
        remaining = digits[1:]
        if (len(remaining) % 2) == 1:
            remaining = remaining + "F"
        body_bytes: list[int] = []
        for index in range(0, len(remaining), 2):
            d_lo = remaining[index]
            d_hi = remaining[index + 1]
            lo = 0xF if d_lo == "F" else int(d_lo)
            hi = 0xF if d_hi == "F" else int(d_hi)
            body_bytes.append((hi << 4) | lo)
        # Pad the byte stream to 8 bytes (TS 31.102 EF.IMSI is 9
        # bytes total: 1 length + 8 digits).
        while len(body_bytes) < 8:
            body_bytes.append(0xFF)
        length = 1 + len(body_bytes)
        if length > 9:
            raise AssertionError("IMSI too long for EF.IMSI")
        prefix = bytes([length - 1]).hex().upper() if False else "08"
        return prefix + bytes([byte1]).hex().upper() + bytes(body_bytes).hex().upper()

    def test_test_plmn_001_01_uses_2digit_mnc_for_001_in_catalogue(self) -> None:
        # IMSI 001010000000001 — TS 23.003 §2.2 test PLMN. MCC 001
        # is in the 3-digit-MNC catalogue but the test PLMN body uses
        # a 2-digit MNC ("01"); the decoder defaults to 3-digit MNC
        # for MCC 001 because the catalogue lists it. The editor
        # surfaces the alternate 2-digit interpretation as well.
        encoded = self._encode_imsi("001010000000001")
        decoded = _decode_imsi(encoded)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["imsi"], "001010000000001")
        self.assertEqual(decoded["mcc"], "001")
        self.assertEqual(decoded["mncLengthAssumed"], 3)
        self.assertEqual(decoded["mnc"], "010")
        self.assertIn("mncAlternate", decoded)
        alt = decoded["mncAlternate"]
        assert isinstance(alt, dict)
        self.assertEqual(alt["length"], 2)
        self.assertEqual(alt["mnc"], "01")

    def test_two_digit_mnc_default_for_uncatalogued_mcc(self) -> None:
        # MCC '262' is not in the 3-digit-MNC catalogue → default
        # 2-digit MNC interpretation, with an alternate 3-digit
        # interpretation surfaced for cross-check against EF.AD.
        encoded = self._encode_imsi("262010000000000")
        decoded = _decode_imsi(encoded)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["mcc"], "262")
        self.assertEqual(decoded["mncLengthAssumed"], 2)
        self.assertEqual(decoded["mnc"], "01")
        self.assertIn("mncAlternate", decoded)
        alt = decoded["mncAlternate"]
        assert isinstance(alt, dict)
        self.assertEqual(alt["length"], 3)


class IccidBreakdownTests(unittest.TestCase):
    def test_telecom_mii_and_luhn_validated(self) -> None:
        # Test ICCID 8988201234567890123 (E.118 telecom + 999/01 test
        # PLMN body). Compute the actual Luhn digit so the test
        # holds regardless of trailing-pad layout.
        body = "898820123456789012"
        total = 0
        for index, ch in enumerate(reversed(body)):
            n = int(ch)
            if (index % 2) == 0:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        check = (10 - (total % 10)) % 10
        iccid = body + str(check)
        # Encode as nibble-swapped BCD with 0xF padding to 20 nibbles.
        padded = iccid + "F" * (20 - len(iccid))
        swapped = "".join(padded[i + 1] + padded[i] for i in range(0, 20, 2))
        decoded = _decode_iccid(swapped)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["iccid"], iccid)
        self.assertEqual(decoded["majorIndustryIdentifier"], "89")
        self.assertIn("Telecommunications", decoded["majorIndustryIdentifierLabel"])
        self.assertTrue(decoded["luhnValid"])

    def test_invalid_luhn_flagged(self) -> None:
        # ICCID with the last digit deliberately wrong.
        iccid = "89882012345678901230"  # last digit '0' not '5'
        padded = iccid + "F" * (20 - len(iccid))
        swapped = "".join(padded[i + 1] + padded[i] for i in range(0, 20, 2))
        decoded = _decode_iccid(swapped)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        # Either the supplied last digit doesn't match the
        # recomputed check digit, or the whole sum is non-zero mod 10.
        self.assertFalse(decoded["luhnValid"])


class RoutingIndicatorTests(unittest.TestCase):
    def test_two_digit_ri_with_default_rfu_tail_is_marked_default(self) -> None:
        # RI = '12', BCD-encoded '21FF', RFU = 'FFFF'.
        decoded = _decode_routing_indicator("21FFFFFF")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["routingIndicator"], "12")
        self.assertEqual(decoded["routingIndicatorDigitCount"], 2)
        self.assertEqual(decoded["rfuTrailingHex"], "FFFF")
        self.assertFalse(decoded["rfuNonDefault"])

    def test_non_default_rfu_tail_is_surfaced(self) -> None:
        decoded = _decode_routing_indicator("21FF0000")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertTrue(decoded["rfuNonDefault"])
        self.assertIn("rfu=", decoded["summary"])

    def test_wrong_length_returns_none(self) -> None:
        self.assertIsNone(_decode_routing_indicator("21FFFF"))
        self.assertIsNone(_decode_routing_indicator("21FFFFFFFF"))


if __name__ == "__main__":
    unittest.main()
