# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A PoR concatenated over several SMS-SUBMIT messages.

TS 31.115 v19 clause 4.5 splits a long Response Packet over concatenated
short messages: the first carries the concatenation element and the RPI
'71', each later one the concatenation element alone (TS 23.040 v19 clause
9.2.3.24.1). The card raises one SEND SHORT MESSAGE per segment, the next
after the TERMINAL RESPONSE to the one before; a segment left on the card
answers the next ENVELOPE as if it were that command's PoR.
"""

from __future__ import annotations

import unittest
from typing import Any

from SCP80 import transport as scp80_transport

#: Six GET STATUS entries ('E3' with a 16-octet AID under '4F').
STATUS_DATA = b"".join(
    bytes.fromhex("E3124F10A0000005591010FFFFFFFF89000010") + bytes([index, 0x00])
    for index in range(6)
)
#: RHL '0A', TAR, CNTR, PCNTR and status '00'; two commands, last SW '9000'.
_HEADER_TO_DATA = bytes.fromhex("0AB000010000000001000002" "9000")
RESPONSE_PACKET = (
    (len(_HEADER_TO_DATA) + len(STATUS_DATA)).to_bytes(2, "big")
    + _HEADER_TO_DATA
    + STATUS_DATA
)
SPLIT = 120
TERMINAL_RESPONSE = "801400000C810301130082028281030100"
PROVIDE_LOCAL_INFO = bytes.fromhex("D009810301260082028182")


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    return bytes([0x81, length])


def _send_short_message(user_data: bytes) -> bytes:
    """Wrap TP-UD in an SMS-SUBMIT and a SEND SHORT MESSAGE command."""

    tpdu = bytes.fromhex("410005811250F300F6") + bytes([len(user_data)]) + user_data
    body = (
        bytes.fromhex("8103011300" "82028183" "0500" "86028001")
        + b"\x8b"
        + _ber_length(len(tpdu))
        + tpdu
    )
    return b"\xd0" + _ber_length(len(body)) + body


def _segment(sequence: int, *, total: int = 2, reference: int = 0x41) -> bytes:
    concatenation = bytes([0x00, 0x03, reference, total, sequence])
    if sequence == 1:
        header = concatenation + bytes.fromhex("7100")
        data = RESPONSE_PACKET[:SPLIT]
    else:
        header = concatenation
        data = RESPONSE_PACKET[SPLIT:]
    return _send_short_message(bytes([len(header)]) + header + data)


def _transport(responses: list[tuple[bytes, int]]) -> tuple[Any, list[str]]:
    """Return a transport whose card answers the APDUs in order."""

    transport = scp80_transport.Transport.__new__(scp80_transport.Transport)
    transport.cfg = None
    transport.conn = None
    transport.active_protocol = None
    transport._stk_bootstrap_trace = []
    transport._stk_bootstrap_trace_printed = False
    queue = list(responses)
    calls: list[str] = []

    def fake_transmit(apdu_hex: str, **kwargs):
        del kwargs
        calls.append(apdu_hex)
        if len(queue) == 0:
            return b"", 0x9000
        return queue.pop(0)

    transport.transmit = fake_transmit
    return transport, calls


def _fetch(command: bytes) -> str:
    return f"80120000{len(command):02X}"


class DecodeConcatenatedPor(unittest.TestCase):
    def test_two_segments_rebuild_the_response_packet(self) -> None:
        decoded = scp80_transport.Transport.decode_por(_segment(1) + _segment(2), 0x91AB)

        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["sms_segments"], 2)
        self.assertEqual(decoded["status_code"], "00")
        self.assertEqual(decoded["tar"], "B00001")
        self.assertEqual(decoded["command_count"], 2)
        self.assertEqual(decoded["command_sw"], "9000")
        self.assertEqual(decoded["command_response"], STATUS_DATA.hex().upper())
        self.assertTrue(decoded["rpl_matches"])

    def test_segments_are_ordered_by_sequence_number(self) -> None:
        decoded = scp80_transport.Transport.decode_por(_segment(2) + _segment(1), 0x91AB)

        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["command_response"], STATUS_DATA.hex().upper())

    def test_a_segment_without_the_first_one_is_named_as_left_over(self) -> None:
        decoded = scp80_transport.Transport.decode_por(_segment(2), 0x91AB)

        self.assertFalse(decoded["valid"])
        self.assertIn("lacks segment(s) 1 of 2", decoded["error"])
        self.assertIn("left over from an earlier command", decoded["error"])

    def test_segments_of_two_messages_are_refused(self) -> None:
        decoded = scp80_transport.Transport.decode_por(
            _segment(1) + _segment(2, reference=0x42), 0x91AB
        )

        self.assertFalse(decoded["valid"])
        self.assertIn("different concatenated messages", decoded["error"])

    def test_a_16_bit_reference_is_read_the_same_way(self) -> None:
        """TS 23.040 v19 clause 9.2.3.24.8: IEI '08' with a two-octet reference."""

        def segment(sequence: int) -> bytes:
            concatenation = bytes([0x08, 0x04, 0x12, 0x34, 2, sequence])
            if sequence == 1:
                header = concatenation + bytes.fromhex("7100")
                data = RESPONSE_PACKET[:SPLIT]
            else:
                header = concatenation
                data = RESPONSE_PACKET[SPLIT:]
            return _send_short_message(bytes([len(header)]) + header + data)

        decoded = scp80_transport.Transport.decode_por(segment(1) + segment(2), 0x91AB)

        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["command_response"], STATUS_DATA.hex().upper())

    def test_a_first_segment_without_the_rpi_is_refused(self) -> None:
        concatenation = bytes([0x00, 0x03, 0x41, 2, 1])
        first = _send_short_message(
            bytes([len(concatenation)]) + concatenation + RESPONSE_PACKET[:SPLIT]
        )

        decoded = scp80_transport.Transport.decode_por(first + _segment(2), 0x91AB)

        self.assertFalse(decoded["valid"])
        self.assertIn("carries no RPI '71'", decoded["error"])

    def test_an_element_the_receiver_must_ignore_reads_as_a_single_message(self) -> None:
        """Clause 9.2.3.24.1: a total of zero, or a sequence of zero or above
        the total, voids the element."""

        for total, sequence in ((0, 1), (2, 0), (2, 3)):
            with self.subTest(total=total, sequence=sequence):
                tpdu = _send_short_message(
                    bytes.fromhex("05000341") + bytes([total, sequence]) + bytes(4)
                )
                element = scp80_transport.Transport._concatenation_element(
                    scp80_transport.Transport._proactive_sms_tpdu(tpdu)
                )
                self.assertIsNone(element)


class CollectConcatenatedPor(unittest.TestCase):
    def test_every_segment_is_fetched_and_answered(self) -> None:
        first, second = _segment(1), _segment(2)
        transport, calls = _transport(
            [
                (first, 0x9000),
                (b"", 0x9100 | len(second)),
                (second, 0x9000),
                (b"", 0x9000),
            ]
        )

        por, pending = transport._collect_por(0x9100 | len(first))

        self.assertEqual(por, first + second)
        self.assertEqual(pending, b"")
        self.assertEqual(
            calls,
            [_fetch(first), TERMINAL_RESPONSE, _fetch(second), TERMINAL_RESPONSE],
        )

    def test_a_command_after_a_whole_por_is_pending_not_answered(self) -> None:
        first, second = _segment(1), _segment(2)
        transport, calls = _transport(
            [
                (first, 0x9000),
                (b"", 0x9100 | len(second)),
                (second, 0x9000),
                (b"", 0x9100 | len(PROVIDE_LOCAL_INFO)),
                (PROVIDE_LOCAL_INFO, 0x9000),
            ]
        )

        por, pending = transport._collect_por(0x9100 | len(first))

        self.assertEqual(por, first + second)
        self.assertEqual(pending, PROVIDE_LOCAL_INFO)
        self.assertEqual(calls[-1], _fetch(PROVIDE_LOCAL_INFO))
        self.assertEqual(calls.count(TERMINAL_RESPONSE), 2)

    def test_a_non_sms_command_between_segments_stops_the_collection(self) -> None:
        first = _segment(1)
        transport, calls = _transport(
            [
                (first, 0x9000),
                (b"", 0x9100 | len(PROVIDE_LOCAL_INFO)),
                (PROVIDE_LOCAL_INFO, 0x9000),
            ]
        )

        por, pending = transport._collect_por(0x9100 | len(first))

        self.assertEqual(por, first)
        self.assertEqual(pending, PROVIDE_LOCAL_INFO)
        self.assertEqual(calls, [_fetch(first), TERMINAL_RESPONSE, _fetch(PROVIDE_LOCAL_INFO)])

    def test_a_single_message_por_stops_after_its_answer(self) -> None:
        single = _send_short_message(bytes.fromhex("027100") + RESPONSE_PACKET[:40])
        transport, calls = _transport([(single, 0x9000), (b"", 0x9000)])

        por, pending = transport._collect_por(0x9100 | len(single))

        self.assertEqual(por, single)
        self.assertEqual(pending, b"")
        self.assertEqual(calls, [_fetch(single), TERMINAL_RESPONSE])


if __name__ == "__main__":
    unittest.main()
