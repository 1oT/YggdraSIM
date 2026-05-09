# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for remaining RSPRO and SIMtrace builder helpers in
``Tools.HilBridge.protocol``.

Covers: build_set_atr_req, build_set_atr_res, build_tpdu_card_to_modem,
build_reset_state_res, build_simtrace_apdu_payload,
build_capture_udp_ipv4_ethernet_frame.
"""

from __future__ import annotations

import struct
import unittest

from Tools.HilBridge.protocol import (
    build_bank_slot,
    build_capture_udp_ipv4_ethernet_frame,
    build_client_slot,
    build_reset_state_res,
    build_set_atr_req,
    build_set_atr_res,
    build_simtrace_apdu_payload,
    build_tpdu_card_to_modem,
    get_pdu_message_body,
    get_pdu_message_name,
    get_pdu_tag,
    RESULT_OK,
)


class BuildSetAtrReqTests(unittest.TestCase):

    def _make(self, atr: bytes = b"\x3B\x90\x00") -> dict:
        return build_set_atr_req(
            tag=2,
            client_slot=build_client_slot(1, 0),
            atr=atr,
        )

    def test_message_name_is_set_atr_req(self) -> None:
        pdu = self._make()
        self.assertEqual(get_pdu_message_name(pdu), "setAtrReq")

    def test_tag_preserved(self) -> None:
        pdu = self._make()
        self.assertEqual(get_pdu_tag(pdu), 2)

    def test_atr_in_body(self) -> None:
        atr = bytes.fromhex("3B9F96801FC78031A073BE21136743200718000001A5")
        pdu = build_set_atr_req(tag=1, client_slot=build_client_slot(0, 0), atr=atr)
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["atr"], atr)

    def test_slot_in_body(self) -> None:
        pdu = self._make()
        body = get_pdu_message_body(pdu)
        self.assertIn("slot", body)

    def test_returns_dict(self) -> None:
        self.assertIsInstance(self._make(), dict)


class BuildSetAtrResTests(unittest.TestCase):

    def test_message_name_is_set_atr_res(self) -> None:
        pdu = build_set_atr_res(tag=5)
        self.assertEqual(get_pdu_message_name(pdu), "setAtrRes")

    def test_default_result_is_ok(self) -> None:
        pdu = build_set_atr_res(tag=5)
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["result"], RESULT_OK)

    def test_custom_result_preserved(self) -> None:
        pdu = build_set_atr_res(tag=5, result="cardNotPresent")
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["result"], "cardNotPresent")

    def test_tag_preserved(self) -> None:
        pdu = build_set_atr_res(tag=7)
        self.assertEqual(get_pdu_tag(pdu), 7)


class BuildTpduCardToModemTests(unittest.TestCase):

    def _make(self, data: bytes = b"\x90\x00") -> dict:
        return build_tpdu_card_to_modem(
            tag=3,
            bank_slot=build_bank_slot(1, 0),
            client_slot=build_client_slot(1, 0),
            data=data,
        )

    def test_message_name_is_tpdu_card_to_modem(self) -> None:
        self.assertEqual(get_pdu_message_name(self._make()), "tpduCardToModem")

    def test_data_in_body(self) -> None:
        body = get_pdu_message_body(self._make(b"\xAA\xBB\xCC"))
        self.assertEqual(body["data"], b"\xAA\xBB\xCC")

    def test_both_slots_in_body(self) -> None:
        body = get_pdu_message_body(self._make())
        self.assertIn("fromBankSlot", body)
        self.assertIn("toClientSlot", body)

    def test_flags_present_in_body(self) -> None:
        body = get_pdu_message_body(self._make())
        self.assertIn("flags", body)

    def test_bytearray_data_accepted(self) -> None:
        pdu = self._make(bytearray(b"\x61\x20"))
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["data"], b"\x61\x20")


class BuildResetStateResTests(unittest.TestCase):

    def test_message_name_is_reset_state_res(self) -> None:
        pdu = build_reset_state_res(tag=10)
        self.assertEqual(get_pdu_message_name(pdu), "resetStateRes")

    def test_default_result_is_ok(self) -> None:
        pdu = build_reset_state_res(tag=10)
        body = get_pdu_message_body(pdu)
        self.assertEqual(body["result"], RESULT_OK)

    def test_tag_preserved(self) -> None:
        pdu = build_reset_state_res(tag=11)
        self.assertEqual(get_pdu_tag(pdu), 11)

    def test_returns_dict(self) -> None:
        self.assertIsInstance(build_reset_state_res(tag=1), dict)


class BuildSimtraceApduPayloadTests(unittest.TestCase):

    def test_combined_payload(self) -> None:
        cmd = bytes.fromhex("00A40400")
        rsp = bytes.fromhex("9000")
        out = build_simtrace_apdu_payload(cmd, rsp)
        self.assertEqual(out, cmd + rsp)

    def test_empty_command_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_simtrace_apdu_payload(b"", b"\x90\x00")

    def test_empty_response_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_simtrace_apdu_payload(b"\x00\xA4", b"")

    def test_bytearray_inputs_accepted(self) -> None:
        out = build_simtrace_apdu_payload(
            bytearray(b"\x80\xCA\x9F\x7F\x00"),
            bytearray(b"\x90\x00"),
        )
        self.assertIsInstance(out, bytes)
        self.assertEqual(len(out), 7)

    def test_list_inputs_accepted(self) -> None:
        out = build_simtrace_apdu_payload([0x00, 0xA4], [0x90, 0x00])
        self.assertEqual(out, bytes([0x00, 0xA4, 0x90, 0x00]))


class BuildCaptureUdpIpv4EthernetFrameTests(unittest.TestCase):

    def _frame(self, payload: bytes = b"\xAA\xBB") -> bytes:
        return build_capture_udp_ipv4_ethernet_frame(payload)

    def test_frame_ends_with_payload(self) -> None:
        payload = b"\x11\x22\x33"
        frame = self._frame(payload)
        self.assertTrue(frame.endswith(payload))

    def test_ethernet_ipv4_ethertype(self) -> None:
        frame = self._frame()
        # Ethertype at bytes [12:14] for a 14-byte Ethernet header.
        self.assertEqual(frame[12:14], b"\x08\x00")

    def test_ip_protocol_is_udp(self) -> None:
        frame = self._frame()
        # IPv4 protocol field at offset 14+9=23.
        self.assertEqual(frame[23], 0x11)

    def test_total_frame_length(self) -> None:
        payload = b"\xDE\xAD"
        frame = self._frame(payload)
        # 14 (eth) + 20 (ip) + 8 (udp) + 2 (payload) = 44
        self.assertEqual(len(frame), 44)

    def test_custom_udp_port_reflected(self) -> None:
        frame = build_capture_udp_ipv4_ethernet_frame(b"\x00", udp_port=4729)
        # UDP src-port at offset 14+20=34, big-endian uint16.
        udp_src = struct.unpack("!H", frame[34:36])[0]
        self.assertEqual(udp_src, 4729)

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(self._frame(), bytes)


if __name__ == "__main__":
    unittest.main()
