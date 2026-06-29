# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Standalone ES10c / ES10b tag-surface smoke tests that bypass the inventory
crypto layer by exercising SgpLogic.handle_store_data directly.

Covers tag paths that are required by LPA / IPA integrations but not yet
exercised elsewhere:

- BF29 SetNickname (SGP.22 §5.7.19)
- BF3F SetDefaultDpAddress (SGP.22 §5.7.21)
- BF25 StoreMetadata (standalone profile metadata personalisation)
- BF2A UpdateMetadata (standalone metadata rewrite)
- BF2D GetProfilesInfo snapshot stability after metadata updates
"""

from __future__ import annotations

import unittest

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimCardState
from SIMCARD.utils import encode_iccid_ef, find_first_tlv, read_tlv, tlv


def _read_simple_value(container: bytes, tag: str) -> bytes:
    raw = find_first_tlv(container, tag)
    if len(raw) == 0:
        return b""
    _, value, _, _ = read_tlv(raw, 0)
    return value


def _fresh_state() -> SimCardState:
    return build_default_state()


class Es10cSetNicknameTests(unittest.TestCase):
    def test_set_nickname_updates_matching_profile_by_iccid(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        target = state.profiles[0]
        target.nickname = ""
        payload = tlv(
            "BF29",
            tlv("5A", encode_iccid_ef(target.iccid)) + tlv("90", b"Nickname Test 1"),
        )

        response, sw1, sw2 = logic.handle_store_data(payload)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[:2], bytes.fromhex("BF29"))
        outer = _read_simple_value(response, "BF29")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x00")
        self.assertEqual(state.profiles[0].nickname, "Nickname Test 1")

    def test_set_nickname_reports_iccid_not_found(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        payload = tlv(
            "BF29",
            tlv("5A", encode_iccid_ef("98765432109876543210")) + tlv("90", b"x"),
        )

        response, sw1, sw2 = logic.handle_store_data(payload)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer = _read_simple_value(response, "BF29")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x01")

    def test_set_nickname_rejects_missing_iccid_field(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        payload = tlv("BF29", tlv("90", b"only nickname"))

        response, _sw1, _sw2 = logic.handle_store_data(payload)

        outer = _read_simple_value(response, "BF29")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x7F")


class Es10bSetDefaultDpAddressTests(unittest.TestCase):
    def test_set_default_dp_address_persists_address(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        payload = tlv("BF3F", tlv("80", b"smdp.example.com"))

        response, sw1, sw2 = logic.handle_store_data(payload)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer = _read_simple_value(response, "BF3F")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x00")
        self.assertEqual(state.default_dp_address, "smdp.example.com")

    def test_set_default_dp_address_empty_string_clears_default(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        state.default_dp_address = "preconfigured.example"
        payload = tlv("BF3F", tlv("80", b""))

        response, _sw1, _sw2 = logic.handle_store_data(payload)

        outer = _read_simple_value(response, "BF3F")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x00")
        self.assertEqual(state.default_dp_address, "")

    def test_set_default_dp_address_rejects_missing_field(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        payload = tlv("BF3F", b"")

        response, _sw1, _sw2 = logic.handle_store_data(payload)

        outer = _read_simple_value(response, "BF3F")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x01")

    def test_set_default_dp_address_rejects_oversized_address(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        oversize = ("a" * 129).encode("utf-8")
        payload = tlv("BF3F", tlv("80", oversize))

        response, _sw1, _sw2 = logic.handle_store_data(payload)

        outer = _read_simple_value(response, "BF3F")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x01")


class Es10aStandaloneMetadataTests(unittest.TestCase):
    def test_standalone_store_metadata_updates_service_provider_and_name(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        target = state.profiles[0]
        payload = tlv(
            "BF25",
            tlv("5A", encode_iccid_ef(target.iccid))
            + tlv("91", b"Example Operator")
            + tlv("92", b"Example Primary")
            + tlv("95", b"\x02"),
        )

        response, sw1, sw2 = logic.handle_store_data(payload)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer = _read_simple_value(response, "BF25")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x00")
        self.assertEqual(state.profiles[0].service_provider, "Example Operator")
        self.assertEqual(state.profiles[0].profile_name, "Example Primary")
        self.assertEqual(state.profiles[0].profile_class, "operational")

    def test_standalone_update_metadata_matches_by_iccid(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        target = state.profiles[0]
        payload = tlv(
            "BF2A",
            tlv("5A", encode_iccid_ef(target.iccid))
            + tlv("91", b"Updated Provider")
            + tlv("92", b"Renamed Profile"),
        )

        response, sw1, sw2 = logic.handle_store_data(payload)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer = _read_simple_value(response, "BF2A")
        self.assertEqual(_read_simple_value(outer, "80"), b"\x00")
        self.assertEqual(state.profiles[0].service_provider, "Updated Provider")
        self.assertEqual(state.profiles[0].profile_name, "Renamed Profile")

    def test_get_profiles_info_reflects_metadata_updates(self) -> None:
        state = _fresh_state()
        logic = SgpLogic(state)
        target = state.profiles[0]
        update = tlv(
            "BF25",
            tlv("5A", encode_iccid_ef(target.iccid)) + tlv("92", b"Named Primary"),
        )
        _response, sw1, sw2 = logic.handle_store_data(update)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

        info_response, info_sw1, info_sw2 = logic.handle_store_data(
            bytes.fromhex("BF2D00")
        )

        self.assertEqual((info_sw1, info_sw2), (0x90, 0x00))
        outer = _read_simple_value(info_response, "BF2D")
        self.assertGreater(len(outer), 0)
        self.assertIn(b"Named Primary", outer)


if __name__ == "__main__":
    unittest.main()
