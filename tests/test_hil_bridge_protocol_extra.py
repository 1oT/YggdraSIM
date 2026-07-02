# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Additional tests for ``Tools.HilBridge.protocol`` pure helpers.

Covers: build_ipa_frame, build_ipa_pong, build_ip_choice,
build_config_client_id_req, build_config_client_bank_req,
build_config_client_bank_res, build_pcap_global_header,
build_pcap_packet_record.
These require no ASN.1 codec and no network.
"""

from __future__ import annotations

import struct
import unittest

from Tools.HilBridge.protocol import (
    IPA_MSGT_PING,
    IPA_MSGT_PONG,
    IPA_PROTO_CCM,
    build_bank_slot,
    build_client_slot,
    build_config_client_bank_req,
    build_config_client_bank_res,
    build_config_client_id_req,
    build_ip_choice,
    build_ipa_frame,
    build_ipa_pong,
    build_pcap_global_header,
    build_pcap_packet_record,
    get_pdu_message_name,
    get_pdu_message_body,
)

PCAP_MAGIC_USEC = 0xA1B2C3D4


class BuildIpaFrameTests(unittest.TestCase):

    def test_no_ext_three_byte_header(self) -> None:
        frame = build_ipa_frame(IPA_PROTO_CCM, b"\x01\x02")
        # 2-byte length + 1-byte proto + 2-byte payload
        self.assertEqual(len(frame), 5)

    def test_with_ext_four_byte_header(self) -> None:
        frame = build_ipa_frame(IPA_PROTO_CCM, b"", ext=IPA_MSGT_PONG)
        # 2-byte length + 1-byte proto + 1-byte ext = 4 bytes (payload empty)
        self.assertEqual(len(frame), 4)

    def test_length_field_big_endian(self) -> None:
        frame = build_ipa_frame(IPA_PROTO_CCM, b"\xAA" * 10)
        length = struct.unpack(">H", frame[:2])[0]
        # Length = payload_size + 1 (proto byte)
        self.assertEqual(length, 11)

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(build_ipa_frame(IPA_PROTO_CCM), bytes)

    def test_empty_payload(self) -> None:
        frame = build_ipa_frame(IPA_PROTO_CCM)
        length = struct.unpack(">H", frame[:2])[0]
        self.assertEqual(length, 1)


class BuildIpaPongTests(unittest.TestCase):

    def test_matches_manually_built(self) -> None:
        expected = build_ipa_frame(IPA_PROTO_CCM, ext=IPA_MSGT_PONG)
        self.assertEqual(build_ipa_pong(), expected)

    def test_deterministic(self) -> None:
        self.assertEqual(build_ipa_pong(), build_ipa_pong())

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(build_ipa_pong(), bytes)


class BuildIpChoiceTests(unittest.TestCase):

    def test_ipv4_returns_ipv4_label(self) -> None:
        label, packed = build_ip_choice("192.0.2.1")
        self.assertEqual(label, "ipv4")
        self.assertEqual(len(packed), 4)

    def test_ipv4_packed_correct(self) -> None:
        _, packed = build_ip_choice("192.0.2.1")
        self.assertEqual(packed, bytes([192, 0, 2, 1]))

    def test_ipv6_returns_ipv6_label(self) -> None:
        label, packed = build_ip_choice("2001:db8::1")
        self.assertEqual(label, "ipv6")
        self.assertEqual(len(packed), 16)

    def test_invalid_address_raises(self) -> None:
        with self.assertRaises((ValueError, Exception)):
            build_ip_choice("not-an-ip")


class BuildConfigClientIdReqTests(unittest.TestCase):

    def test_message_name(self) -> None:
        pdu = build_config_client_id_req(tag=3, client_slot=build_client_slot(1, 0))
        self.assertEqual(get_pdu_message_name(pdu), "configClientIdReq")

    def test_body_contains_client_slot(self) -> None:
        cs = build_client_slot(5, 2)
        pdu = build_config_client_id_req(tag=3, client_slot=cs)
        body = get_pdu_message_body(pdu)
        self.assertIn("clientSlot", body)

    def test_tag_preserved(self) -> None:
        from Tools.HilBridge.protocol import get_pdu_tag
        pdu = build_config_client_id_req(tag=11, client_slot=build_client_slot(0, 0))
        self.assertEqual(get_pdu_tag(pdu), 11)


class BuildConfigClientBankReqTests(unittest.TestCase):

    def test_message_name(self) -> None:
        pdu = build_config_client_bank_req(
            tag=4,
            bank_slot=build_bank_slot(1, 0),
            bank_host="192.0.2.1",
            bank_port=9000,
        )
        self.assertEqual(get_pdu_message_name(pdu), "configClientBankReq")

    def test_body_contains_bank_slot_and_bankd(self) -> None:
        pdu = build_config_client_bank_req(
            tag=4,
            bank_slot=build_bank_slot(1, 0),
            bank_host="192.0.2.1",
            bank_port=9000,
        )
        body = get_pdu_message_body(pdu)
        self.assertIn("bankSlot", body)
        self.assertIn("bankd", body)

    def test_port_in_bankd(self) -> None:
        pdu = build_config_client_bank_req(
            tag=4,
            bank_slot=build_bank_slot(1, 0),
            bank_host="192.0.2.1",
            bank_port=12345,
        )
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["bankd"]["port"], 12345)


class BuildConfigClientBankResTests(unittest.TestCase):

    def test_message_name(self) -> None:
        pdu = build_config_client_bank_res(tag=5)
        self.assertEqual(get_pdu_message_name(pdu), "configClientBankRes")

    def test_default_result_ok(self) -> None:
        pdu = build_config_client_bank_res(tag=5)
        body = get_pdu_message_body(pdu)
        self.assertIn("result", body)

    def test_custom_result(self) -> None:
        pdu = build_config_client_bank_res(tag=5, result="error")
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["result"], "error")


class BuildPcapGlobalHeaderTests(unittest.TestCase):

    def test_length_24_bytes(self) -> None:
        self.assertEqual(len(build_pcap_global_header()), 24)

    def test_magic_number_correct(self) -> None:
        header = build_pcap_global_header()
        magic = struct.unpack("<I", header[:4])[0]
        self.assertEqual(magic, PCAP_MAGIC_USEC)

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(build_pcap_global_header(), bytes)


class BuildPcapPacketRecordTests(unittest.TestCase):

    def test_frame_appended(self) -> None:
        frame = b"\xAA\xBB\xCC"
        record = build_pcap_packet_record(frame, 1000, 500)
        self.assertTrue(record.endswith(frame))

    def test_header_is_16_bytes(self) -> None:
        frame = b"\x01\x02\x03"
        record = build_pcap_packet_record(frame, 0, 0)
        # 16-byte header + frame
        self.assertEqual(len(record), 16 + len(frame))

    def test_capture_lengths_equal_frame_length(self) -> None:
        frame = b"\xDE\xAD\xBE\xEF"
        record = build_pcap_packet_record(frame, 0, 0)
        incl_len, orig_len = struct.unpack("<II", record[8:16])
        self.assertEqual(incl_len, len(frame))
        self.assertEqual(orig_len, len(frame))

    def test_negative_microseconds_clamped(self) -> None:
        frame = b"\x00"
        record = build_pcap_packet_record(frame, 0, -100)
        us = struct.unpack("<I", record[4:8])[0]
        self.assertEqual(us, 0)


if __name__ == "__main__":
    unittest.main()
