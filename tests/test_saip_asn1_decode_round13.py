# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Round-13 EF-decoder spec-correctness tests.

Targets two semantic bugs identified in the EF.SPN display-condition
decoder (legacy field naming was inverted relative to TS 31.102
§4.2.12) and the EF.5GS3GPPLOCI / EF.5GSN3GPPLOCI update-status
labels (codes 0x02 / 0x03 were mapped to the wrong TS 24.501
§9.11.3.2 strings).
"""
from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _5GS_UPDATE_STATUS_LABELS,
    _decode_5gs_loci,
    _decode_spn,
)
from Tools.ProfilePackage.saip_asn1_encode import encode_ef_spn


class SpnDisplayConditionTests(unittest.TestCase):
    def test_b1_set_means_display_plmn_required(self) -> None:
        # 0x01 + ASCII "Home" padded with 0xFF.
        decoded = _decode_spn("01486F6D65" + "FF" * 12)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertTrue(decoded["displayPlmnNameRequiredOnHomePlmn"])
        self.assertFalse(decoded["spnDisplayNotRequiredOnNonHomePlmn"])
        # Legacy alias remains inverted for back-compat with the
        # encoder's pre-round-13 fallback.
        self.assertFalse(decoded["displayInHplmnRequired"])
        self.assertEqual(decoded["serviceProviderName"], "Home")

    def test_b2_set_means_spn_display_not_required_on_non_home(self) -> None:
        decoded = _decode_spn("02486F6D65" + "FF" * 12)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertFalse(decoded["displayPlmnNameRequiredOnHomePlmn"])
        self.assertTrue(decoded["spnDisplayNotRequiredOnNonHomePlmn"])

    def test_both_bits_clear_default_state(self) -> None:
        decoded = _decode_spn("00486F6D65" + "FF" * 12)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertFalse(decoded["displayPlmnNameRequiredOnHomePlmn"])
        self.assertFalse(decoded["spnDisplayNotRequiredOnNonHomePlmn"])
        self.assertEqual(decoded["displayConditionRfuBits"], "0x00")

    def test_rfu_bits_surface_when_set(self) -> None:
        # 0xC1 = b1 set + b7/b8 RFU set.
        decoded = _decode_spn("C1486F6D65" + "FF" * 12)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["displayConditionRfuBits"], "0xC0")
        self.assertTrue(decoded["displayPlmnNameRequiredOnHomePlmn"])

    def test_encoder_accepts_spec_correct_fields(self) -> None:
        encoded = encode_ef_spn(
            {
                "serviceProviderName": "Home",
                "displayPlmnNameRequiredOnHomePlmn": True,
                "spnDisplayNotRequiredOnNonHomePlmn": False,
            },
            target_length=17,
        )
        self.assertEqual(len(encoded), 17)
        self.assertEqual(encoded[0], 0x01)
        self.assertEqual(encoded[1:5], b"Home")
        self.assertTrue(all(b == 0xFF for b in encoded[5:]))

    def test_encoder_legacy_fallback_still_round_trips(self) -> None:
        # Old decoder output (pre-round-13) carried the inverted
        # ``displayInHplmnRequired`` field. Confirm the legacy
        # encoder branch still produces the same byte the original
        # decoder consumed.
        legacy_payload = {
            "serviceProviderName": "Home",
            "displayInHplmnRequired": False,
            "hideInOplmnIfEquivalentPlmn": False,
        }
        encoded = encode_ef_spn(legacy_payload, target_length=17)
        self.assertEqual(encoded[0], 0x01)


class FiveGUpdateStatusTests(unittest.TestCase):
    def test_code_0x02_is_roaming_not_allowed(self) -> None:
        self.assertEqual(_5GS_UPDATE_STATUS_LABELS[0x02], "5U3 ROAMING NOT ALLOWED")

    def test_code_0x03_through_0x07_are_reserved(self) -> None:
        for code in range(0x03, 0x08):
            self.assertEqual(_5GS_UPDATE_STATUS_LABELS[code], "reserved")

    def test_decoder_routes_status_byte_through_label_table(self) -> None:
        # Build a 20-byte EF.5GS3GPPLOCI payload: GUTI(13) || TAI(6) || status.
        # Use byte 19 = 0x02 to trigger 5U3 ROAMING NOT ALLOWED.
        payload = ("FF" * 13) + ("FF" * 6) + "02"
        decoded = _decode_5gs_loci(
            payload,
            format_name="5GS 3GPP Location Info",
            spec_reference="TS 31.102 §4.4.11.2",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["updateStatus"]["value"], 0x02)
        self.assertEqual(
            decoded["updateStatus"]["label"], "5U3 ROAMING NOT ALLOWED"
        )

    def test_decoder_marks_reserved_status_correctly(self) -> None:
        payload = ("FF" * 13) + ("FF" * 6) + "03"
        decoded = _decode_5gs_loci(
            payload,
            format_name="5GS 3GPP Location Info",
            spec_reference="TS 31.102 §4.4.11.2",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["updateStatus"]["label"], "reserved")


if __name__ == "__main__":
    unittest.main()
