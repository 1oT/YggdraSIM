# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SecurityDomain symbolic decoder + PIN shared-context helper."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import (
    saip_pin_shared_context as pin_ctx,
    saip_security_domain_decode as sd_decode,
)


class PrivilegeRoundTripTests(unittest.TestCase):

    def test_security_domain_only(self) -> None:
        # bit b1 of byte 1 (MSB = 0x80) → "Security Domain"
        decoded = sd_decode.decode_privileges("800000")
        self.assertEqual(decoded["flags"], ["Security Domain"])
        self.assertEqual(decoded["hex"], "800000")

    def test_isd_typical_combo(self) -> None:
        # ISD privileges: Security Domain + Card Reset + CVM Mgmt + Final App
        # Security Domain (byte0 0x80) | Card Reset (byte0 0x04) |
        # CVM Mgmt (byte0 0x02) = 0x86; Final Application is byte1 0x02.
        decoded = sd_decode.decode_privileges("860200")
        self.assertIn("Security Domain", decoded["flags"])
        self.assertIn("Card Reset", decoded["flags"])
        self.assertIn("CVM Management", decoded["flags"])
        self.assertIn("Final Application", decoded["flags"])

    def test_encode_round_trip(self) -> None:
        original = ["Security Domain", "Authorized Management", "Trusted Path"]
        encoded = sd_decode.encode_privileges(original)
        # Security Domain = byte0 0x80, Trusted Path = byte1 0x80,
        # Authorized Management = byte1 0x40 → bytes "80 C0 00".
        self.assertEqual(encoded, "80C000")
        re_decoded = sd_decode.decode_privileges(encoded)
        self.assertEqual(set(re_decoded["flags"]), set(original))

    def test_unknown_privilege_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_decode.encode_privileges(["Bogus Flag"])

    def test_short_input_padded(self) -> None:
        # Short input gets right-padded with zero bytes.
        decoded = sd_decode.decode_privileges("80")
        self.assertEqual(decoded["hex"], "800000")
        self.assertEqual(decoded["flags"], ["Security Domain"])

    def test_oversize_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_decode.decode_privileges("AABBCCDD")

    def test_catalog_has_24_entries(self) -> None:
        cat = sd_decode.privilege_catalog()
        self.assertEqual(len(cat), 24)
        labels = [entry["name"] for entry in cat]
        self.assertIn("Security Domain", labels)
        self.assertIn("Contactless Self-Activation", labels)


class LifeCycleTests(unittest.TestCase):

    def test_decode_known_byte(self) -> None:
        self.assertEqual(sd_decode.decode_life_cycle("0F")["name"], "PERSONALIZED")
        self.assertEqual(sd_decode.decode_life_cycle("FF")["name"], "TERMINATED")

    def test_decode_custom_byte(self) -> None:
        result = sd_decode.decode_life_cycle("AA")
        self.assertEqual(result["name"], "CUSTOM")
        self.assertEqual(result["hex"], "AA")

    def test_encode_by_name(self) -> None:
        self.assertEqual(sd_decode.encode_life_cycle("PERSONALIZED"), "0F")
        self.assertEqual(sd_decode.encode_life_cycle("locked"), "83")

    def test_encode_by_hex(self) -> None:
        self.assertEqual(sd_decode.encode_life_cycle("FF"), "FF")

    def test_encode_empty_rejected(self) -> None:
        with self.assertRaises(ValueError):
            sd_decode.encode_life_cycle("")

    def test_catalog_is_sorted(self) -> None:
        cat = sd_decode.life_cycle_catalog()
        self.assertEqual(len(cat), 6)
        self.assertEqual(cat[0]["name"], "INSTALLED")


class PinSharedContextTests(unittest.TestCase):

    def test_get_shared_when_filepath_present(self) -> None:
        pe = {"pin-Header": {}, "filePath": bytes.fromhex("7FFF")}
        result = pin_ctx.get_shared_context(pe)
        self.assertTrue(result["shared"])
        self.assertEqual(result["file_path_hex"], "7FFF")
        self.assertEqual(result["pin_count"], 0)

    def test_get_local_when_pinconfig_present(self) -> None:
        pe = {"pin-Header": {}, "pinconfig": [{"keyReference": "pinAppl1"}]}
        result = pin_ctx.get_shared_context(pe)
        self.assertFalse(result["shared"])
        self.assertEqual(result["pin_count"], 1)

    def test_get_handles_nested_pinCodes_wrapper(self) -> None:
        pe = {"pin-Header": {}, "pinCodes": {"filePath": b"\x7f\xff"}}
        result = pin_ctx.get_shared_context(pe)
        self.assertTrue(result["shared"])
        self.assertEqual(result["file_path_hex"], "7FFF")

    def test_set_shared_replaces_pinconfig(self) -> None:
        pe = {"pin-Header": {}, "pinconfig": [{"keyReference": "pinAppl1"}]}
        msg = pin_ctx.set_shared_context(pe, file_path_hex="7F10")
        self.assertNotIn("pinconfig", pe)
        self.assertEqual(pe["filePath"], bytes.fromhex("7F10"))
        self.assertIn("7F10", msg)

    def test_set_local_clears_filepath(self) -> None:
        pe = {"pin-Header": {}, "filePath": b"\x7f\xff"}
        pin_ctx.set_local_context(pe)
        self.assertNotIn("filePath", pe)
        self.assertEqual(pe["pinconfig"], [])

    def test_set_shared_rejects_oversize(self) -> None:
        with self.assertRaises(ValueError):
            pin_ctx.set_shared_context({}, file_path_hex="00" * 9)

    def test_set_shared_strips_slashes(self) -> None:
        pe = {"pin-Header": {}}
        pin_ctx.set_shared_context(pe, file_path_hex="7F10/5F3A")
        self.assertEqual(pe["filePath"], bytes.fromhex("7F105F3A"))

    def test_set_shared_empty_path_yields_mf(self) -> None:
        pe = {"pin-Header": {}, "pinconfig": []}
        msg = pin_ctx.set_shared_context(pe, file_path_hex="")
        self.assertEqual(pe["filePath"], b"")
        self.assertIn("MF", msg)


if __name__ == "__main__":
    unittest.main()
