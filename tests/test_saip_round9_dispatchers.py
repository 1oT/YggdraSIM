# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for round-9 PE-parity SAIP dispatchers.

Covers the stateless action surfaces — the session-aware ones share
their logic with the helper-module test suites.
"""

from __future__ import annotations

import struct
import unittest

from yggdrasim_common.gui_server.actions import saip
from yggdrasim_common.gui_server.actions.registry import get_registry


_NEW_ACTION_IDS = (
    "saip.pin_encode_value",
    "saip.pin_decode_value",
    "saip.aka_mapping_option_catalog",
    "saip.aka_get_choice",
    "saip.aka_set_mapping_parameter",
    "saip.aka_set_algo_parameter",
    "saip.list_sd_catalog_extended",
    "saip.sd_decode_field",
    "saip.sd_encode_field",
    "saip.arr_encode_reference",
    "saip.arr_decode_reference",
    "saip.arr_list_records",
    "saip.gfm_get_df_context",
    "saip.gfm_set_df_context",
    "saip.gfm_reorder_files",
    "saip.gfm_remove_file",
    "saip.connectivity_decode",
    "saip.connectivity_encode",
    "saip.connectivity_bearer_catalog",
    "saip.cap_inspect",
    "saip.ssim_eaptls_inspect",
    "saip.ssim_eaptls_match_pair",
)


class RegistrationTests(unittest.TestCase):

    def test_every_round9_action_is_registered(self) -> None:
        reg = get_registry()
        for action_id in _NEW_ACTION_IDS:
            self.assertTrue(reg.has(action_id), f"missing: {action_id}")


class StatelessPinTests(unittest.TestCase):

    def test_pin_encode_round_trip(self) -> None:
        encoded = saip._dispatch_pin_encode_value(
            ctx=None, value="1234", coding="digits",
        )
        self.assertEqual(encoded["hex"], "31323334FFFFFFFF")
        self.assertEqual(encoded["byte_length"], 8)

    def test_pin_decode(self) -> None:
        decoded = saip._dispatch_pin_decode_value(
            ctx=None, hex_value="31323334FFFFFFFF",
        )
        self.assertEqual(decoded["digits"], "1234")
        self.assertTrue(decoded["valid_digits_only"])


class StatelessAkaTests(unittest.TestCase):

    def test_mapping_option_catalog_has_eight_flags(self) -> None:
        out = saip._dispatch_aka_mapping_option_catalog(ctx=None)
        self.assertEqual(len(out["options"]), 8)


class StatelessSdTests(unittest.TestCase):

    def test_extended_catalog_keys(self) -> None:
        out = saip._dispatch_list_sd_catalog_extended(ctx=None)
        for key in ("access_domain", "afi", "key_access", "key_component_type",
                    "key_usage", "msl", "restrict"):
            self.assertIn(key, out)

    def test_decode_known_field(self) -> None:
        out = saip._dispatch_sd_decode_field(
            ctx=None, field="access_domain", hex_value="00",
        )
        self.assertEqual(out["name"], "FULL_ACCESS")

    def test_encode_known_field(self) -> None:
        out = saip._dispatch_sd_encode_field(
            ctx=None, field="afi", name_or_hex="PAYMENT",
        )
        self.assertEqual(out["hex"], "10")

    def test_encode_msl_kwargs(self) -> None:
        out = saip._dispatch_sd_encode_field(
            ctx=None, field="msl",
            msl_kwargs={
                "auth_response": "cryptographic_checksum",
                "integrity": "no_integrity",
            },
        )
        self.assertTrue(out["hex"].startswith("02"))

    def test_encode_unknown_field(self) -> None:
        with self.assertRaises(ValueError):
            saip._dispatch_sd_encode_field(ctx=None, field="nonsense")


class StatelessArrTests(unittest.TestCase):

    def test_encode_reference(self) -> None:
        self.assertEqual(
            saip._dispatch_arr_encode_reference(
                ctx=None, file_id="2F06", record_index=1,
            )["hex"],
            "2F0601",
        )

    def test_decode_long_reference(self) -> None:
        out = saip._dispatch_arr_decode_reference(ctx=None, hex_value="2F0601")
        self.assertEqual(out["kind"], "long")
        self.assertEqual(out["record_index"], 1)


class StatelessConnectivityTests(unittest.TestCase):

    def test_round_trip(self) -> None:
        bearers = [{
            "bearer": "https",
            "bearer_description_hex": "020188",
            "network_access_name": {"text": "lab.example.test"},
            "user_login": {"text": "op"},
            "user_password": {"text": "pw"},
            "server_uri": "https://eim.example.test/sgp32",
        }]
        encoded = saip._dispatch_connectivity_encode(ctx=None, bearers=bearers)
        decoded = saip._dispatch_connectivity_decode(
            ctx=None, hex_value=encoded["hex"],
        )
        self.assertEqual(decoded["bearers"][0]["bearer"], "https")
        self.assertEqual(decoded["bearers"][0]["server_uri"],
                         "https://eim.example.test/sgp32")

    def test_catalog(self) -> None:
        out = saip._dispatch_connectivity_bearer_catalog(ctx=None)
        bearers = {entry["bearer"] for entry in out["bearers"]}
        self.assertEqual(bearers, {"sms", "cat_tp", "https"})


class StatelessCapTests(unittest.TestCase):

    def _build_ijc(self, package_aid: str, applet_aid: str, import_aid: str) -> bytes:
        def comp(tag: int, payload: bytes) -> bytes:
            return bytes([tag]) + struct.pack(">H", len(payload)) + payload

        aid = bytes.fromhex(package_aid)
        hdr = (
            b"\xDE\xCA\xFF\xED" + bytes([0, 2, 0, 2, 1])
            + bytes([len(aid)]) + aid
        )
        applet = bytes.fromhex(applet_aid)
        applet_payload = (
            bytes([1]) + bytes([len(applet)]) + applet + b"\x00\x10"
        )
        imp = bytes.fromhex(import_aid)
        import_payload = (
            bytes([1]) + bytes([0, 2]) + bytes([len(imp)]) + imp
        )
        return comp(1, hdr) + comp(3, applet_payload) + comp(4, import_payload)

    def test_inspect_hex(self) -> None:
        ijc = self._build_ijc(
            "A000000087100201",
            "A000000087100201AB",
            "A0000000620201",
        )
        out = saip._dispatch_cap_inspect(ctx=None, payload_hex=ijc.hex())
        self.assertEqual(out["package_aid_hex"], "A000000087100201")
        self.assertEqual(out["applet_aids"], ["A000000087100201AB"])
        self.assertEqual(out["import_aids"], ["A0000000620201"])

    def test_inspect_requires_input(self) -> None:
        with self.assertRaises(ValueError):
            saip._dispatch_cap_inspect(ctx=None)


class StatelessSsimEaptlsTests(unittest.TestCase):

    def test_inspect_rejects_garbage(self) -> None:
        with self.assertRaises(ValueError):
            saip._dispatch_ssim_eaptls_inspect(
                ctx=None, pem_or_der="not a cert",
            )


if __name__ == "__main__":
    unittest.main()
