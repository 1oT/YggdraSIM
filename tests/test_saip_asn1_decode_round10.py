# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Round-10 EF-decoder coverage tests.

Exercises the manual-list parity decoders added so the GUI editor
matches the reference profile-creator's "interpreted EF" surface for
EF.PST, EF.BST, EF.UPLMNWLAN, EF.OPLMNWLAN, and EF.WLRPLMN.
"""
from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_ef_bst,
    _decode_ef_pst,
    _decode_ef_wlrplmn,
    _decode_known_ef_payload,
)


class ProSeServiceTableTests(unittest.TestCase):
    def test_single_service_byte_decodes_active_set(self) -> None:
        # bits 0,2 set → services 1, 3
        decoded = _decode_ef_pst("05")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["format"], "ProSe Service Table")
        self.assertEqual(decoded["activeServices"], [1, 3])
        self.assertIn("ProSe direct-discovery parameters", decoded["summary"])

    def test_two_byte_payload_walks_into_second_octet(self) -> None:
        decoded = _decode_ef_pst("8003")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["activeServices"], [8, 9, 10])

    def test_empty_payload_returns_none(self) -> None:
        self.assertIsNone(_decode_ef_pst(""))

    def test_invalid_hex_returns_none(self) -> None:
        self.assertIsNone(_decode_ef_pst("zz"))

    def test_dispatcher_routes_ef_pst_token(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-pst",
            fid=None,
            hex_clean="07",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["activeServices"], [1, 2, 3])


class BcastServiceTableTests(unittest.TestCase):
    def test_first_two_services_active(self) -> None:
        decoded = _decode_ef_bst("03")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["format"], "BCAST Service Table")
        self.assertEqual(decoded["activeServices"], [1, 2])
        self.assertIn("BCMCS", decoded["summary"])

    def test_unknown_service_bit_falls_through_to_anonymous_label(self) -> None:
        # bit 7 → service 8, beyond OMA-defined 1..6 catalogue.
        decoded = _decode_ef_bst("80")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["activeServices"], [8])
        # No human label for service 8; summary just shows #8.
        self.assertIn("#8", decoded["summary"])

    def test_dispatcher_routes_ef_bst_token(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-bst",
            fid=None,
            hex_clean="01",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["activeServices"], [1])


class WlrPlmnTests(unittest.TestCase):
    def test_three_byte_plmn_decodes_to_mcc_mnc(self) -> None:
        # Test PLMN 001/01 per 3GPP TS 23.003 §2.2 — encoded as 00 F1 10.
        decoded = _decode_ef_wlrplmn("00F110")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["format"], "I-WLAN Last Registered PLMN")
        self.assertIsNotNone(decoded["plmn"])
        self.assertIn("PLMN", decoded["summary"])

    def test_all_ones_means_no_registration(self) -> None:
        decoded = _decode_ef_wlrplmn("FFFFFF")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertIsNone(decoded["plmn"])
        self.assertEqual(decoded["summary"], "no PLMN registered")

    def test_wrong_length_returns_none(self) -> None:
        self.assertIsNone(_decode_ef_wlrplmn("00F1"))
        self.assertIsNone(_decode_ef_wlrplmn("00F11000"))


class WlanPlmnSelectorTests(unittest.TestCase):
    def test_oplmnwlan_decodes_as_plmn_list_without_act(self) -> None:
        # Two PLMNs — 001/01 and 999/99 — neither carries an AcT bitmap.
        decoded = _decode_known_ef_payload(
            ef_key="ef-oplmnwlan",
            fid=None,
            hex_clean="00F11099F999",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["entryCount"], 2)
        self.assertEqual(decoded["encoding"], "PLMN list")

    def test_uplmnwlan_skips_all_ones_entries(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-uplmnwlan",
            fid=None,
            hex_clean="00F110FFFFFF",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["entryCount"], 1)


if __name__ == "__main__":
    unittest.main()
