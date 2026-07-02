# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.ProfilePackage.saip_dgi_decode``.

Pure-function module: no I/O, no card transport. The fixture below
mirrors the SAIP shell's existing
``test_render_result_stdout_decodes_special_saip_fields`` test, so
the lift from ``shell.py`` into the new module is locked in as
byte-for-byte equivalent at the structural level the renderer
relies on.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_dgi_decode import (
    DEFAULT_DGI_NAMES,
    decode_compact_binary_value,
    decode_dgi_records,
    decode_dgi_stream,
    decode_length_prefixed_identifier_block,
    decode_network_access_name,
    decode_simple_tlv_payload,
    decode_stk_value,
    describe_bearer_description,
    describe_transport_level,
    decode_other_address,
    parse_simple_tlv_stream,
    value_to_bytes,
    value_to_hex_strings,
)


# Real-world ``sdPersoData`` blob carrying connectivity parameters.
# Same payload used by the existing shell render-test, so the lift is
# regression-proof against the historical shape consumers rely on.
_SD_PERSO_FIXTURE_HEX: str = (
    "00707a"
    "8578"
    "841c"
    "010301400102028182"
    "350103"
    "390205dc"
    "3c030227be"
    "3e0521c000020a"
    "8517"
    "133839343435303136303532343637363333363202400186070003a503002000"
    "8936"
    "8a0d3133392e3136322e31352e3633"
    "8b133839313033303030303030303638353336333"
    "38c102f67736d612f61646d696e6167656e74"
).replace(" ", "")


class ValueCoercionTests(unittest.TestCase):
    def test_value_to_bytes_accepts_hex_str(self) -> None:
        self.assertEqual(value_to_bytes("aabb"), b"\xaa\xbb")

    def test_value_to_bytes_rejects_odd_length(self) -> None:
        self.assertIsNone(value_to_bytes("abc"))

    def test_value_to_bytes_rejects_non_hex_chars(self) -> None:
        self.assertIsNone(value_to_bytes("zz"))

    def test_value_to_bytes_rejects_bool(self) -> None:
        self.assertIsNone(value_to_bytes(True))

    def test_value_to_hex_strings_flattens_lists(self) -> None:
        self.assertEqual(
            value_to_hex_strings(["aa", b"\xbb", ["cc"]]),
            ["aa", "bb", "cc"],
        )


class DgiEnvelopeTests(unittest.TestCase):
    def test_short_length_field(self) -> None:
        # DGI 0070, 1-byte length 03, value AABBCC.
        records = decode_dgi_stream(bytes.fromhex("007003AABBCC"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dgi"], "0070")
        self.assertEqual(records[0]["length"], 3)
        self.assertEqual(records[0]["raw"], "aabbcc")
        # 0070 is in DEFAULT_DGI_NAMES.
        self.assertEqual(records[0]["name"], DEFAULT_DGI_NAMES["0070"])

    def test_extended_length_field(self) -> None:
        # DGI 8010, FF-prefixed 2-byte length 0x0010 = 16, value 16x 'AA'.
        body = bytes.fromhex("AA" * 16)
        wire = bytes.fromhex("8010FF0010") + body
        records = decode_dgi_stream(wire)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dgi"], "8010")
        self.assertEqual(records[0]["length"], 16)
        self.assertEqual(records[0]["raw"], body.hex())

    def test_truncated_tail_is_silently_dropped(self) -> None:
        # Valid first block, second block claims 4 bytes but only has 2.
        wire = bytes.fromhex("00700100" "00800400AA")
        records = decode_dgi_stream(wire)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dgi"], "0070")


class SimpleTlvPayloadTests(unittest.TestCase):
    def test_parse_simple_tlv_stream_well_formed(self) -> None:
        # 84 02 0001  39 02 05DC
        items = parse_simple_tlv_stream(bytes.fromhex("8402000139020 5DC".replace(" ", "")))
        self.assertEqual(items, [(0x84, b"\x00\x01"), (0x39, b"\x05\xDC")])

    def test_parse_simple_tlv_stream_rejects_truncated(self) -> None:
        # Tag 84 claims length 4 but only 2 bytes follow.
        self.assertIsNone(parse_simple_tlv_stream(bytes.fromhex("8404AABB")))

    def test_decode_simple_tlv_payload_recurses(self) -> None:
        # 85 04 [ 84 02 AABB ] — outer simple-TLV that wraps another.
        decoded = decode_simple_tlv_payload(bytes.fromhex("85048402AABB"))
        self.assertIsInstance(decoded, list)
        self.assertEqual(decoded[0]["tag"], "85")
        self.assertEqual(decoded[0]["decoded"][0]["tag"], "84")


class StkLeafDecoderTests(unittest.TestCase):
    def test_bearer_description_named(self) -> None:
        # Type 0x02 = GPRS, plus a 1-byte parameter trailer.
        decoded = describe_bearer_description(b"\x02\x01")
        self.assertEqual(decoded["typeName"], "GPRS")
        self.assertEqual(decoded["parameters"], "01")

    def test_transport_level_protocol_and_port(self) -> None:
        # Protocol 0x02 = TCP remote, port 0x27BE = 10174.
        decoded = describe_transport_level(b"\x02\x27\xBE")
        self.assertEqual(decoded["protocolName"], "TCP, remote connection")
        self.assertEqual(decoded["port"], 10174)

    def test_other_address_ipv4(self) -> None:
        decoded = decode_other_address(b"\x21\xc0\x00\x02\x0a")
        self.assertEqual(decoded["typeName"], "IPv4")
        self.assertEqual(decoded["address"], "192.0.2.10")


class DgiRecordsHighLevelTests(unittest.TestCase):
    def test_decode_dgi_records_against_connectivity_fixture(self) -> None:
        # Mirror the shape the SAIP shell INFO renderer reads in
        # ``test_render_result_stdout_decodes_special_saip_fields``.
        records = decode_dgi_records([_SD_PERSO_FIXTURE_HEX])
        self.assertIsNotNone(records)
        self.assertEqual(len(records), 1)
        first = records[0]
        self.assertEqual(first["record"], 1)
        self.assertEqual(first["format"], "DGI")
        # The fixture starts with DGI 0070 (Card Recognition Data /
        # IIN). The decoder must surface that as the first item.
        first_dgi = first["items"][0]
        self.assertEqual(first_dgi["dgi"], "0070")

    def test_decode_dgi_records_returns_none_for_garbage(self) -> None:
        # No hex content means nothing can parse.
        self.assertIsNone(decode_dgi_records([]))
        self.assertIsNone(decode_dgi_records("zz"))

    def test_decode_dgi_records_unwraps_nested_lists(self) -> None:
        # SAIP jsonified ``sdPersoData`` arrives as a list of hex
        # strings. Single-element lists must round-trip identically.
        single = decode_dgi_records(["007003AABBCC"])
        nested = decode_dgi_records([["007003AABBCC"]])
        self.assertEqual(single, nested)


class DecodeNetworkAccessNameTests(unittest.TestCase):
    def test_single_label(self) -> None:
        payload = bytes([0x03]) + b"apn"
        self.assertEqual(decode_network_access_name(payload), "apn")

    def test_multi_label_dot_joined(self) -> None:
        # TS 31.111 §6.6.5: each label is length-prefixed.
        payload = bytes([0x07]) + b"example" + bytes([0x03]) + b"com"
        self.assertEqual(decode_network_access_name(payload), "example.com")

    def test_empty_input(self) -> None:
        self.assertEqual(decode_network_access_name(b""), "(empty)")

    def test_zero_length_label_terminates(self) -> None:
        # A 0x00 label-length byte is a terminator; ignore remainder.
        payload = bytes([0x03]) + b"apn" + bytes([0x00]) + b"trailing"
        self.assertEqual(decode_network_access_name(payload), "apn")

    def test_truncated_label_falls_back_to_hex(self) -> None:
        # Claims a 10-byte label but only 3 bytes follow.
        payload = bytes([0x0A]) + b"abc"
        result = decode_network_access_name(payload)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_non_ascii_falls_back_to_hex(self) -> None:
        payload = bytes([0x02, 0xFF, 0xFE])
        result = decode_network_access_name(payload)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))


class DecodeStkValueTests(unittest.TestCase):
    def test_tag35_bearer_description(self) -> None:
        result = decode_stk_value(0x35, b"\x02\x01")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["typeName"], "GPRS")

    def test_tag39_two_byte_integer(self) -> None:
        # Tag 0x39 with exactly 2 bytes → big-endian unsigned integer.
        self.assertEqual(decode_stk_value(0x39, bytes([0x05, 0xDC])), 1500)

    def test_tag39_wrong_length_returns_none(self) -> None:
        self.assertIsNone(decode_stk_value(0x39, b"\x05"))

    def test_tag3c_transport_level(self) -> None:
        result = decode_stk_value(0x3C, b"\x02\x27\xBE")
        self.assertIsInstance(result, dict)
        self.assertIn("port", result)

    def test_tag3e_other_address(self) -> None:
        result = decode_stk_value(0x3E, b"\x21\x0a\x0a\x0a\x0a")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["typeName"], "IPv4")

    def test_tag47_network_access_name(self) -> None:
        payload = bytes([0x03]) + b"apn"
        result = decode_stk_value(0x47, payload)
        self.assertEqual(result, "apn")

    def test_unknown_tag_returns_none(self) -> None:
        self.assertIsNone(decode_stk_value(0x01, b"\xAA\xBB"))


class DecodeCompactBinaryValueTests(unittest.TestCase):
    def test_empty_bytes(self) -> None:
        result = decode_compact_binary_value(b"")
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("empty"))

    def test_single_byte(self) -> None:
        result = decode_compact_binary_value(b"\xFF")
        self.assertIsNotNone(result)
        self.assertEqual(result["decimal"], 255)
        self.assertEqual(result["hex"], "ff")
        self.assertEqual(result["bytes"], ["0xFF"])

    def test_two_bytes_big_endian(self) -> None:
        result = decode_compact_binary_value(b"\xDE\xAD")
        self.assertEqual(result["decimal"], 0xDEAD)

    def test_four_bytes_max(self) -> None:
        result = decode_compact_binary_value(b"\x00\x01\x02\x03")
        self.assertIsNotNone(result)

    def test_five_bytes_returns_none(self) -> None:
        self.assertIsNone(decode_compact_binary_value(b"\x00" * 5))


class DecodeLengthPrefixedIdentifierBlockTests(unittest.TestCase):
    def test_identifier_only(self) -> None:
        payload = bytes([0x05]) + b"hello"
        result = decode_length_prefixed_identifier_block(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["identifierAscii"], "hello")
        self.assertNotIn("trailerHex", result)

    def test_identifier_with_trailer(self) -> None:
        payload = bytes([0x05]) + b"hello" + bytes([0xAB])
        result = decode_length_prefixed_identifier_block(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["trailerHex"], "ab")
        self.assertEqual(result["trailerBytes"], ["0xAB"])

    def test_empty_input_returns_none(self) -> None:
        self.assertIsNone(decode_length_prefixed_identifier_block(b""))

    def test_zero_identifier_length_returns_none(self) -> None:
        self.assertIsNone(decode_length_prefixed_identifier_block(bytes([0x00]) + b"abc"))

    def test_truncated_identifier_returns_none(self) -> None:
        # Claims 10-byte identifier but only 2 follow.
        self.assertIsNone(decode_length_prefixed_identifier_block(bytes([0x0A]) + b"ab"))

    def test_non_ascii_identifier_returns_none(self) -> None:
        payload = bytes([0x02, 0xFF, 0xFE])
        self.assertIsNone(decode_length_prefixed_identifier_block(payload))


if __name__ == "__main__":
    unittest.main()
