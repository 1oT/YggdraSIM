# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for pure-function helpers in ``Tools.HilBridge.protocol``.

Covers: ensure_bytes, build_simple_tlv, describe_refresh_mode,
normalize_refresh_mode, build_proactive_refresh_command,
build_ipa_ping, build_component_identity, build_client_slot,
build_bank_slot, build_rspro_pdu, get_pdu_message_name,
get_pdu_message_body, get_pdu_tag, build_connect_client_res,
decode_slot_phys_status, parse_proactive_command_details,
refresh_mode_from_fetch_response.

All tested functions are pure (no network, no ASN.1 codec).
"""

from __future__ import annotations

import unittest

from Tools.HilBridge.protocol import (
    REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    REFRESH_MODE_UICC_RESET,
    ProactiveCommandDetails,
    SlotPhysStatus,
    build_bank_slot,
    build_client_slot,
    build_component_identity,
    build_connect_client_res,
    build_ipa_ping,
    build_proactive_refresh_command,
    build_rspro_pdu,
    build_simple_tlv,
    decode_slot_phys_status,
    describe_refresh_mode,
    ensure_bytes,
    get_pdu_message_body,
    get_pdu_message_name,
    get_pdu_tag,
    normalize_refresh_mode,
    parse_proactive_command_details,
    refresh_mode_from_fetch_response,
)


class EnsureBytesTests(unittest.TestCase):

    def test_bytes_passthrough(self) -> None:
        raw = b"\xAA\xBB"
        result = ensure_bytes(raw)
        self.assertIs(result, raw)

    def test_bytearray_converted(self) -> None:
        ba = bytearray([0x01, 0x02])
        result = ensure_bytes(ba)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b"\x01\x02")

    def test_list_converted(self) -> None:
        result = ensure_bytes([0x10, 0x20])
        self.assertEqual(result, b"\x10\x20")

    def test_tuple_converted(self) -> None:
        result = ensure_bytes((0xAB, 0xCD))
        self.assertEqual(result, b"\xAB\xCD")


class BuildSimpleTlvTests(unittest.TestCase):

    def test_short_value(self) -> None:
        # Tag 0x82, value 0xDEAD → 82 02 DE AD
        result = build_simple_tlv(0x82, b"\xDE\xAD")
        self.assertEqual(result, bytes([0x82, 0x02, 0xDE, 0xAD]))

    def test_empty_value(self) -> None:
        result = build_simple_tlv(0x01, b"")
        self.assertEqual(result, bytes([0x01, 0x00]))

    def test_tag_masked_to_byte(self) -> None:
        # Tag values above 0xFF are masked.
        result = build_simple_tlv(0x1FF, b"\xAA")
        self.assertEqual(result[0], 0xFF)

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(build_simple_tlv(0x10, b"\x00"), bytes)


class DescribeRefreshModeTests(unittest.TestCase):

    def test_known_qualifier_uicc_reset(self) -> None:
        self.assertEqual(describe_refresh_mode(0x04), REFRESH_MODE_UICC_RESET)

    def test_known_qualifier_profile_state_change(self) -> None:
        self.assertEqual(describe_refresh_mode(0x09), REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE)

    def test_unknown_qualifier_fallback(self) -> None:
        result = describe_refresh_mode(0xFF)
        self.assertIn("0xFF", result)

    def test_returns_string(self) -> None:
        self.assertIsInstance(describe_refresh_mode(0x00), str)


class NormalizeRefreshModeTests(unittest.TestCase):

    def test_integer_input(self) -> None:
        name, qualifier = normalize_refresh_mode(4)
        self.assertEqual(qualifier, 4)
        self.assertEqual(name, REFRESH_MODE_UICC_RESET)

    def test_canonical_string(self) -> None:
        name, qualifier = normalize_refresh_mode(REFRESH_MODE_UICC_RESET)
        self.assertEqual(qualifier, 0x04)
        self.assertEqual(name, REFRESH_MODE_UICC_RESET)

    def test_alias_string(self) -> None:
        name, qualifier = normalize_refresh_mode("reset")
        self.assertEqual(name, REFRESH_MODE_UICC_RESET)

    def test_0x_hex_prefix(self) -> None:
        name, qualifier = normalize_refresh_mode("0x04")
        self.assertEqual(qualifier, 4)

    def test_two_char_hex(self) -> None:
        name, qualifier = normalize_refresh_mode("04")
        self.assertEqual(qualifier, 4)

    def test_empty_string_defaults_to_profile_state_change(self) -> None:
        name, qualifier = normalize_refresh_mode("")
        self.assertEqual(name, REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE)

    def test_invalid_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_refresh_mode("no-such-mode-xyz")

    def test_returns_tuple(self) -> None:
        result = normalize_refresh_mode(0x00)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)


class BuildProactiveRefreshCommandTests(unittest.TestCase):

    def test_produces_bytes(self) -> None:
        result = build_proactive_refresh_command(command_number=1, qualifier="uicc-reset")
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_zero_command_number_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_proactive_refresh_command(command_number=0, qualifier="uicc-reset")

    def test_qualifier_int(self) -> None:
        result = build_proactive_refresh_command(command_number=1, qualifier=4)
        self.assertIsInstance(result, bytes)

    def test_different_qualifiers_differ(self) -> None:
        a = build_proactive_refresh_command(command_number=1, qualifier="uicc-reset")
        b = build_proactive_refresh_command(command_number=1, qualifier="euicc-profile-state-change")
        self.assertNotEqual(a, b)


class BuildIpaPingTests(unittest.TestCase):

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(build_ipa_ping(), bytes)

    def test_non_empty(self) -> None:
        self.assertGreater(len(build_ipa_ping()), 0)

    def test_deterministic(self) -> None:
        self.assertEqual(build_ipa_ping(), build_ipa_ping())


class BuildComponentIdentityTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        result = build_component_identity(
            "server", name="test", software="sw", sw_version="1.0"
        )
        self.assertIsInstance(result, dict)

    def test_contains_expected_keys(self) -> None:
        result = build_component_identity(
            "server", name="test", software="sw", sw_version="1.0"
        )
        self.assertIn("type", result)
        self.assertIn("name", result)
        self.assertIn("software", result)
        self.assertIn("swVersion", result)

    def test_values_preserved(self) -> None:
        result = build_component_identity(
            "bankd", name="my-bridge", software="YggdraSIM", sw_version="0.2"
        )
        self.assertEqual(result["name"], "my-bridge")
        self.assertEqual(result["swVersion"], "0.2")


class BuildSlotTests(unittest.TestCase):

    def test_client_slot_keys(self) -> None:
        result = build_client_slot(3, 1)
        self.assertEqual(result, {"clientId": 3, "slotNr": 1})

    def test_bank_slot_keys(self) -> None:
        result = build_bank_slot(1, 2)
        self.assertEqual(result, {"bankId": 1, "slotNr": 2})

    def test_values_are_ints(self) -> None:
        result = build_client_slot(0, 0)
        self.assertIsInstance(result["clientId"], int)
        self.assertIsInstance(result["slotNr"], int)


class PduHelperTests(unittest.TestCase):

    def _make_pdu(self) -> dict:
        return build_rspro_pdu(7, "connectClientRes", {"result": "ok"})

    def test_get_pdu_message_name(self) -> None:
        pdu = self._make_pdu()
        self.assertEqual(get_pdu_message_name(pdu), "connectClientRes")

    def test_get_pdu_message_body(self) -> None:
        pdu = self._make_pdu()
        body = get_pdu_message_body(pdu)
        self.assertIsInstance(body, dict)
        self.assertEqual(body["result"], "ok")

    def test_get_pdu_tag(self) -> None:
        pdu = self._make_pdu()
        self.assertEqual(get_pdu_tag(pdu), 7)

    def test_invalid_pdu_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            get_pdu_message_name({"msg": "not-a-tuple"})

    def test_invalid_pdu_body_raises(self) -> None:
        with self.assertRaises(ValueError):
            get_pdu_message_body({"msg": ("name", "not-a-dict")})

    def test_missing_tag_returns_zero(self) -> None:
        self.assertEqual(get_pdu_tag({}), 0)


class BuildConnectClientResTests(unittest.TestCase):

    def _make_identity(self) -> dict:
        return build_component_identity(
            "server", name="test", software="sw", sw_version="1.0"
        )

    def test_returns_dict(self) -> None:
        identity = self._make_identity()
        result = build_connect_client_res(tag=5, component_identity=identity)
        self.assertIsInstance(result, dict)

    def test_message_name_correct(self) -> None:
        identity = self._make_identity()
        result = build_connect_client_res(tag=5, component_identity=identity)
        self.assertEqual(get_pdu_message_name(result), "connectClientRes")

    def test_tag_preserved(self) -> None:
        identity = self._make_identity()
        result = build_connect_client_res(tag=12, component_identity=identity)
        self.assertEqual(get_pdu_tag(result), 12)

    def test_body_contains_identity(self) -> None:
        identity = self._make_identity()
        result = build_connect_client_res(tag=1, component_identity=identity)
        body = get_pdu_message_body(result)
        self.assertIn("identity", body)


class DecodeSlotPhysStatusTests(unittest.TestCase):

    def test_full_status(self) -> None:
        status = decode_slot_phys_status(
            {
                "slotPhysStatus": {
                    "resetActive": True,
                    "vccPresent": True,
                    "clkActive": False,
                    "cardPresent": True,
                },
            }
        )
        self.assertTrue(status.reset_active)
        self.assertTrue(status.vcc_present)
        self.assertFalse(status.clk_active)
        self.assertTrue(status.card_present)

    def test_optional_members_read_none(self) -> None:
        status = decode_slot_phys_status({"slotPhysStatus": {"resetActive": False}})
        self.assertFalse(status.reset_active)
        self.assertIsNone(status.vcc_present)
        self.assertIsNone(status.clk_active)
        self.assertIsNone(status.card_present)

    def test_empty_body_reads_as_no_reset(self) -> None:
        self.assertEqual(decode_slot_phys_status({}), SlotPhysStatus())

    def test_malformed_member_reads_as_no_reset(self) -> None:
        self.assertEqual(decode_slot_phys_status({"slotPhysStatus": b"\x01"}), SlotPhysStatus())
        self.assertEqual(decode_slot_phys_status(None), SlotPhysStatus())


class ParseProactiveCommandDetailsTests(unittest.TestCase):
    # Observed on the rig: REFRESH, command number 1, "UICC Reset", with
    # the status word the modem receives behind it.
    REFRESH_UICC_RESET = bytes.fromhex("D0098103010104820281829000")

    def test_reads_command_details(self) -> None:
        self.assertEqual(
            parse_proactive_command_details(self.REFRESH_UICC_RESET),
            ProactiveCommandDetails(command_number=1, command_type=0x01, qualifier=0x04),
        )

    def test_status_word_is_optional(self) -> None:
        self.assertEqual(
            parse_proactive_command_details(self.REFRESH_UICC_RESET[:-2]),
            ProactiveCommandDetails(command_number=1, command_type=0x01, qualifier=0x04),
        )

    def test_two_byte_length_form(self) -> None:
        # SEND DATA carrying 200 bytes: the outer length is 81 xx, and so
        # is the channel-data object's.
        body = (
            build_simple_tlv(0x81, bytes((0x01, 0x43, 0x00)))
            + build_simple_tlv(0x82, bytes((0x81, 0x21)))
            + build_simple_tlv(0x36, bytes(200))
        )
        payload = build_simple_tlv(0xD0, body)
        self.assertEqual(payload[1], 0x81)
        self.assertEqual(
            parse_proactive_command_details(payload),
            ProactiveCommandDetails(command_number=1, command_type=0x43, qualifier=0x00),
        )

    def test_command_details_without_comprehension_bit(self) -> None:
        self.assertEqual(
            parse_proactive_command_details(bytes.fromhex("D009010301010402028182")),
            ProactiveCommandDetails(command_number=1, command_type=0x01, qualifier=0x04),
        )

    def test_accepts_list_input(self) -> None:
        self.assertIsNotNone(parse_proactive_command_details(list(self.REFRESH_UICC_RESET)))

    def test_decode_boundaries_return_none(self) -> None:
        cases = {
            "empty": b"",
            "bare tag": b"\xD0",
            "truncated two-byte length": b"\xD0\x81",
            "zero-length command": b"\xD0\x00",
            "outer length over-claims": b"\xD0\x09\x81\x03\x01",
            "inner length over-claims": b"\xD0\x04\x81\x03\x01\x01",
            "inner header truncated": b"\xD0\x02\x81\x81",
            "command details too short": b"\xD0\x04\x81\x02\x01\x01",
            "no command details object": b"\xD0\x04\x82\x02\x81\x82",
            "three-byte length form": b"\xD0\x82\x00\x04\x81\x03\x01\x01\x04",
            "not a proactive command": b"\x80\x12\x00\x00\x10",
            "status word only": b"\x91\x0B",
        }
        for label, payload in cases.items():
            with self.subTest(label):
                self.assertIsNone(parse_proactive_command_details(payload))


class RefreshModeFromFetchResponseTests(unittest.TestCase):

    def test_uicc_reset(self) -> None:
        self.assertEqual(
            refresh_mode_from_fetch_response(bytes.fromhex("D0098103010104820281829000")),
            (REFRESH_MODE_UICC_RESET, 0x04),
        )

    def test_round_trips_the_builder(self) -> None:
        payload = build_proactive_refresh_command(
            command_number=3,
            qualifier=REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
        )
        self.assertEqual(
            refresh_mode_from_fetch_response(payload + b"\x90\x00"),
            (REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE, 0x09),
        )

    def test_other_proactive_command_is_not_a_refresh(self) -> None:
        # CLOSE CHANNEL observed on the rig.
        self.assertIsNone(refresh_mode_from_fetch_response(bytes.fromhex("D0098103014100820281219000")))

    def test_malformed_is_not_a_refresh(self) -> None:
        self.assertIsNone(refresh_mode_from_fetch_response(b""))
        self.assertIsNone(refresh_mode_from_fetch_response(b"\xD0"))


if __name__ == "__main__":
    unittest.main()
