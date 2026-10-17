# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import sys
import unittest
from pathlib import Path

EIM_PACKAGES_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "eim_packages.py"

spec = importlib.util.spec_from_file_location("scp11_eim_packages_module", EIM_PACKAGES_PATH)
eim_packages_module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
sys.modules[spec.name] = eim_packages_module
spec.loader.exec_module(eim_packages_module)

TYPE_PROFILE_STATE_MANAGEMENT = eim_packages_module.TYPE_PROFILE_STATE_MANAGEMENT
TYPE_EIM_CONFIGURATION_OBJECT = eim_packages_module.TYPE_EIM_CONFIGURATION_OBJECT
TYPE_EUICC_CONFIGURATION = eim_packages_module.TYPE_EUICC_CONFIGURATION
TYPE_PROFILE_DOWNLOAD_TRIGGER = eim_packages_module.TYPE_PROFILE_DOWNLOAD_TRIGGER
TYPE_GENERIC = eim_packages_module.TYPE_GENERIC
parse_eim_package = eim_packages_module.parse_eim_package
euicc_package_choice_tag = eim_packages_module.euicc_package_choice_tag
package_changes_eim_configuration = eim_packages_module.package_changes_eim_configuration


DUMMY_TEST_EIM_OID = "2.25.311782205282738360923618091971140414400"


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_der_length(len(value)) + value


class EimPackageParsingTests(unittest.TestCase):
    def test_profile_state_management_extracts_inner_card_request(self):
        signed_request = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", DUMMY_TEST_EIM_OID.encode("utf-8")),
                    wrap_tlv("5A", bytes.fromhex("89049032123456789012345678901234")),
                    wrap_tlv("81", b"\x34"),
                    wrap_tlv("82", b"\x00\x00\x00\x00\x00\x00\x04\x9D"),
                    wrap_tlv("A0", wrap_tlv("BF2D", b"")),
                ]
            ),
        )
        raw = wrap_tlv("BF51", signed_request + wrap_tlv("5F37", b"\xAA" * 64))

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_PROFILE_STATE_MANAGEMENT)
        self.assertEqual(parsed.card_request, bytes.fromhex("BF2D00"))

    def _signed_euicc_package(self, choice_tag: str, commands: bytes) -> bytes:
        signed_request = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", DUMMY_TEST_EIM_OID.encode("utf-8")),
                    wrap_tlv("5A", bytes.fromhex("89049032123456789012345678901234")),
                    wrap_tlv("81", b"\x34"),
                    wrap_tlv("82", b"\x00\x00\x00\x00\x00\x00\x04\x9E"),
                    wrap_tlv(choice_tag, commands),
                ]
            ),
        )
        return wrap_tlv("BF51", signed_request + wrap_tlv("5F37", b"\xAA" * 64))

    def test_bf51_with_inner_eim_configuration_object_is_classified_as_eco(self):
        add_eim = wrap_tlv("A8", wrap_tlv("80", b"1.3.6.1.4.1"))
        raw = self._signed_euicc_package("A1", add_eim)

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EIM_CONFIGURATION_OBJECT)
        self.assertEqual(parsed.card_request, add_eim)
        self.assertTrue(package_changes_eim_configuration(raw))

    def test_list_eim_under_eco_list_is_not_reported_as_psmo(self):
        # SGP.32 §2.11.1.1 listEim [11]: an ecoList member, and one that
        # leaves the card's eIM configuration untouched.
        raw = self._signed_euicc_package("A1", wrap_tlv("AB", b""))

        parsed = parse_eim_package(raw)

        self.assertEqual(euicc_package_choice_tag(raw), b"\xA1")
        self.assertEqual(parsed.package_type, TYPE_EIM_CONFIGURATION_OBJECT)
        self.assertFalse(package_changes_eim_configuration(raw))

    def test_set_fallback_attribute_under_psmo_list_stays_psmo(self):
        # 'A8' is setFallbackAttribute under psmoList and addEim under
        # ecoList, so only the enclosing alternative can tell them apart.
        raw = self._signed_euicc_package("A0", wrap_tlv("A8", wrap_tlv("5A", b"\x98\x88" * 5)))

        parsed = parse_eim_package(raw)

        self.assertEqual(euicc_package_choice_tag(raw), b"\xA0")
        self.assertEqual(parsed.package_type, TYPE_PROFILE_STATE_MANAGEMENT)
        self.assertFalse(package_changes_eim_configuration(raw))

    def test_eco_list_with_delete_and_update_marks_configuration_changed(self):
        commands = wrap_tlv("AB", b"") + wrap_tlv("AA", wrap_tlv("80", b"1.3.6.1.4.1"))
        raw = self._signed_euicc_package("A1", commands)

        self.assertEqual(parse_eim_package(raw).package_type, TYPE_EIM_CONFIGURATION_OBJECT)
        self.assertTrue(package_changes_eim_configuration(raw))

    def test_euicc_configuration_extracts_inner_card_request(self):
        signed_request = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", DUMMY_TEST_EIM_OID.encode("utf-8")),
                    wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
                    wrap_tlv("81", b"\x52"),
                    wrap_tlv("82", b"\x00\x00\x00\x00\x00\x00\x04\x9D"),
                    wrap_tlv("A0", wrap_tlv("BF55", b"")),
                ]
            ),
        )
        raw = wrap_tlv("BF52", signed_request + wrap_tlv("5F37", b"\xBB" * 64))

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EUICC_CONFIGURATION)
        self.assertEqual(parsed.card_request, bytes.fromhex("BF5500"))

    def test_euicc_configuration_extracts_requested_tags_and_request_token(self):
        raw = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A081A2BF20BF228384A5A6A8A9"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A1")),
        )

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EUICC_CONFIGURATION)
        self.assertEqual(
            parsed.requested_tags,
            (
                bytes.fromhex("A0"),
                bytes.fromhex("81"),
                bytes.fromhex("A2"),
                bytes.fromhex("BF20"),
                bytes.fromhex("BF22"),
                bytes.fromhex("83"),
                bytes.fromhex("84"),
                bytes.fromhex("A5"),
                bytes.fromhex("A6"),
                bytes.fromhex("A8"),
                bytes.fromhex("A9"),
            ),
        )
        self.assertEqual(parsed.request_token, bytes.fromhex("00000000000004A1"))

    def test_euicc_configuration_extracts_search_criteria_sequence_numbers(self):
        raw = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A0A2"))
            + wrap_tlv("A1", wrap_tlv("80", b"\x02"))
            + wrap_tlv("A2", wrap_tlv("80", b"\x09"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A2")),
        )

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EUICC_CONFIGURATION)
        self.assertEqual(parsed.notification_seq_number, 2)
        self.assertEqual(parsed.notification_profile_management_operation, b"")
        self.assertEqual(parsed.euicc_package_result_seq_number, 9)
        self.assertEqual(parsed.request_token, bytes.fromhex("00000000000004A2"))

    def test_euicc_configuration_extracts_profile_management_operation_criteria(self):
        raw = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A0"))
            + wrap_tlv("A1", wrap_tlv("81", bytes.fromhex("0640")))
            + wrap_tlv("83", bytes.fromhex("00000000000004A7")),
        )

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EUICC_CONFIGURATION)
        self.assertEqual(parsed.notification_seq_number, None)
        self.assertEqual(parsed.notification_profile_management_operation, bytes.fromhex("0640"))

    def test_signed_euicc_configuration_extracts_outer_eim_id_and_nested_request(self):
        inner_request = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("84"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A3")),
        )
        signed_request = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"manager-2"),
                    wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
                    wrap_tlv("81", b"\x35"),
                    wrap_tlv("82", b"\x00\x00\x00\x00\x00\x00\x04\xA3"),
                    wrap_tlv("A0", inner_request),
                ]
            ),
        )
        raw = wrap_tlv("BF52", signed_request + wrap_tlv("5F37", b"\xCC" * 64))

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_EUICC_CONFIGURATION)
        self.assertEqual(parsed.eim_id, "manager-2")
        self.assertEqual(parsed.requested_tags, (bytes.fromhex("84"),))
        self.assertEqual(parsed.request_token, bytes.fromhex("00000000000004A3"))
        self.assertEqual(parsed.card_request, inner_request)

    def test_profile_download_trigger_extracts_activation_code(self):
        trigger = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"LPA:1$rsp.example.com$MATCH-54"),
                    wrap_tlv("A0", wrap_tlv("BF43", b"")),
                ]
            ),
        )
        raw = wrap_tlv("BF54", trigger)

        parsed = parse_eim_package(raw)

        self.assertEqual(parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
        self.assertEqual(parsed.smdp_address, "rsp.example.com")
        self.assertEqual(parsed.matching_id, "MATCH-54")
        self.assertEqual(parsed.card_request, bytes.fromhex("BF4300"))

    def test_truncated_package_falls_back_to_generic(self):
        parsed = parse_eim_package(bytes.fromhex("BF5481"))

        self.assertEqual(parsed.package_type, TYPE_GENERIC)
        self.assertEqual(parsed.card_request, b"")


if __name__ == "__main__":
    unittest.main()
