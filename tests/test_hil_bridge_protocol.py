# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for pure-function helpers in ``Tools.HilBridge.protocol``.

Covers: ensure_bytes, build_simple_tlv, describe_refresh_mode,
normalize_refresh_mode, build_proactive_refresh_command,
build_ipa_ping, build_component_identity, build_client_slot,
build_bank_slot, build_rspro_pdu, get_pdu_message_name,
get_pdu_message_body, get_pdu_tag, build_connect_client_res.

All tested functions are pure (no network, no ASN.1 codec).
"""

from __future__ import annotations

import unittest

from Tools.HilBridge.protocol import (
    REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    REFRESH_MODE_UICC_RESET,
    build_bank_slot,
    build_client_slot,
    build_component_identity,
    build_connect_client_res,
    build_ipa_ping,
    build_proactive_refresh_command,
    build_rspro_pdu,
    build_simple_tlv,
    describe_refresh_mode,
    ensure_bytes,
    get_pdu_message_body,
    get_pdu_message_name,
    get_pdu_tag,
    normalize_refresh_mode,
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


if __name__ == "__main__":
    unittest.main()
