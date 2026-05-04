"""ETSI TS 102 223 default-encoding conformance for STK state.

Locks the byte layout of the simulator-side and controller-side
default values that are emitted in DEVICE IDENTITIES (§8.7),
LOCATION INFORMATION (§8.19), and IMEI (§8.20) TLVs.

The earlier defaults stored an ASCII string ("1oT.YggdraSIM") as
the IMEI, which a real terminal would parse as garbage BCD. The
location object on the simulator side was 3 bytes long, also
non-compliant.
"""

from __future__ import annotations

import unittest

from SCP03.logic.stk import (
    StkState,
    _encode_imei_bcd,
    _encode_location_information_gsm,
)
from SIMCARD.state import (
    _default_stk_imei_bcd,
    _default_stk_location_information,
    SimToolkitState,
)


class ImeiBcdEncodingTests(unittest.TestCase):
    """3GPP TS 24.008 §10.5.1.4 mobile-identity IMEI encoding."""

    def test_encoded_imei_is_eight_bytes(self) -> None:
        encoded = _encode_imei_bcd("123456789012345")
        self.assertEqual(len(encoded), 8)

    def test_first_byte_carries_first_digit_in_high_nibble_and_type_low(self) -> None:
        encoded = _encode_imei_bcd("123456789012345")
        # high nibble = 1, low nibble = 0xA (010 IMEI + odd parity)
        self.assertEqual(encoded[0], 0x1A)

    def test_subsequent_bytes_pack_digits_with_low_nibble_first(self) -> None:
        encoded = _encode_imei_bcd("123456789012345")
        self.assertEqual(encoded[1], 0x32)
        self.assertEqual(encoded[2], 0x54)
        self.assertEqual(encoded[3], 0x76)
        self.assertEqual(encoded[4], 0x98)
        self.assertEqual(encoded[5], 0x10)
        self.assertEqual(encoded[6], 0x32)
        self.assertEqual(encoded[7], 0x54)

    def test_short_or_non_numeric_imei_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _encode_imei_bcd("123")
        with self.assertRaises(ValueError):
            _encode_imei_bcd("ABCDEFGHIJKLMNO")


class LocationInformationEncodingTests(unittest.TestCase):
    """3GPP TS 24.008 §10.5.1.3 PLMN encoding inside §8.19 layout."""

    def test_gsm_2digit_mnc_emits_seven_bytes(self) -> None:
        encoded = _encode_location_information_gsm("001", "01", 0x0001, 0x0001)
        self.assertEqual(len(encoded), 7)
        # MCC=001, MNC=01 (3GPP TS 23.003 §2.2 test PLMN) → BCD 00 F1 10
        self.assertEqual(encoded[:3], bytes.fromhex("00F110"))
        self.assertEqual(encoded[3:5], b"\x00\x01")
        self.assertEqual(encoded[5:], b"\x00\x01")

    def test_gsm_3digit_mnc_packs_third_digit_in_high_nibble(self) -> None:
        encoded = _encode_location_information_gsm("310", "260", 0x1234, 0xABCD)
        # 3GPP TS 24.008 §10.5.1.3 PLMN coding for MCC=310 MNC=260:
        # - byte 1: MCC2 (1) | MCC1 (3) -> 0x13
        # - byte 2: MNC3 (0) | MCC3 (0) -> 0x00
        # - byte 3: MNC2 (6) | MNC1 (2) -> 0x62
        self.assertEqual(encoded[:3], bytes.fromhex("130062"))
        self.assertEqual(encoded[3:5], b"\x12\x34")
        self.assertEqual(encoded[5:], b"\xAB\xCD")


class StkStateDefaultsTests(unittest.TestCase):
    def test_controller_default_imei_is_eight_byte_bcd(self) -> None:
        state = StkState()
        self.assertEqual(len(state.imei), 8)
        # Low nibble of byte 1 must be 0xA (IMEI + odd parity).
        self.assertEqual(state.imei[0] & 0x0F, 0x0A)

    def test_controller_default_location_information_is_seven_bytes(self) -> None:
        state = StkState()
        self.assertEqual(len(state.location_information), 7)

    def test_simulator_default_imei_matches_controller_default(self) -> None:
        sim_imei = SimToolkitState().imei
        controller_imei = StkState().imei
        self.assertEqual(sim_imei, controller_imei)
        self.assertEqual(sim_imei, _default_stk_imei_bcd())

    def test_simulator_default_location_matches_controller_default(self) -> None:
        sim_loc = SimToolkitState().location_information
        controller_loc = StkState().location_information
        self.assertEqual(sim_loc, controller_loc)
        self.assertEqual(sim_loc, _default_stk_location_information())


if __name__ == "__main__":
    unittest.main()
