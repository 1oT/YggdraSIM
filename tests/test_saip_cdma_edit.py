# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_cdma_edit``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_cdma_edit as cdma


class CdmaSetFieldTests(unittest.TestCase):

    def test_set_authentication_key_round_trip(self) -> None:
        pe: dict = {}
        cdma.set_cdma_field(pe, field="authenticationKey", hex_value="00112233445566 77")
        self.assertEqual(pe["authenticationKey"], bytes.fromhex("0011223344556677"))

    def test_authentication_key_must_be_8_bytes(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({}, field="authenticationKey", hex_value="00112233")

    def test_authentication_key_cannot_be_cleared(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({"authenticationKey": b"\x00" * 8}, field="authenticationKey", hex_value="")

    def test_optional_field_clear_drops_key(self) -> None:
        pe: dict = {"hrpdAccessAuthenticationData": b"\x00\x01"}
        cdma.set_cdma_field(pe, field="hrpdAccessAuthenticationData", hex_value="")
        self.assertNotIn("hrpdAccessAuthenticationData", pe)

    def test_simple_ip_lower_bound(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({}, field="simpleIPAuthenticationData", hex_value="0011")

    def test_simple_ip_upper_bound(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({}, field="simpleIPAuthenticationData", hex_value="00" * 484)

    def test_unknown_field_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({}, field="bogus", hex_value="00")

    def test_ssd_must_be_16_bytes(self) -> None:
        with self.assertRaises(ValueError):
            cdma.set_cdma_field({}, field="ssd", hex_value="00112233")


class CdmaSummaryTests(unittest.TestCase):

    def test_summary_includes_split_when_ssd_present(self) -> None:
        pe = {
            "authenticationKey": b"\x01" * 8,
            "ssd": bytes.fromhex("00" * 8 + "FF" * 8),
        }
        summary = cdma.cdma_summary(pe)
        self.assertEqual(summary["authenticationKey"], "01" * 8)
        self.assertEqual(summary["ssd"], "00" * 8 + "FF" * 8)
        self.assertEqual(summary["ssd_a_hex"], "00" * 8)
        self.assertEqual(summary["ssd_b_hex"], "FF" * 8)

    def test_summary_skips_split_when_ssd_absent(self) -> None:
        pe = {"authenticationKey": b"\x00" * 8}
        summary = cdma.cdma_summary(pe)
        self.assertEqual(summary["ssd"], "")
        self.assertNotIn("ssd_a_hex", summary)


class CdmaSplitTests(unittest.TestCase):

    def test_set_both_halves(self) -> None:
        pe: dict = {}
        cdma.set_ssd_split(pe, ssd_a_hex="00" * 8, ssd_b_hex="FF" * 8)
        self.assertEqual(pe["ssd"], bytes.fromhex("00" * 8 + "FF" * 8))

    def test_set_one_half_keeps_other(self) -> None:
        pe = {"ssd": bytes.fromhex("00" * 8 + "FF" * 8)}
        cdma.set_ssd_split(pe, ssd_a_hex="11" * 8)
        self.assertEqual(pe["ssd"], bytes.fromhex("11" * 8 + "FF" * 8))

    def test_clear_both_drops_field(self) -> None:
        pe = {"ssd": bytes.fromhex("00" * 16)}
        cdma.set_ssd_split(pe, ssd_a_hex="", ssd_b_hex="")
        self.assertNotIn("ssd", pe)

    def test_partial_clear_rejected(self) -> None:
        pe: dict = {}
        with self.assertRaises(ValueError):
            cdma.set_ssd_split(pe, ssd_a_hex="11" * 8, ssd_b_hex="")


class CdmaCatalogTests(unittest.TestCase):

    def test_catalog_lists_all_fields(self) -> None:
        cat = cdma.supported_fields()
        self.assertIn("authenticationKey", cat)
        self.assertTrue(cat["authenticationKey"]["mandatory"])
        self.assertFalse(cat["ssd"]["mandatory"])
        self.assertEqual(cat["ssd"]["min_bytes"], 16)
        self.assertEqual(cat["mobileIPAuthenticationData"]["max_bytes"], 957)


if __name__ == "__main__":
    unittest.main()
