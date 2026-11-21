# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A SET UP EVENT LIST the card raises behind a PoR.

TS 102 241 V18.1 clause 6.7.1.2 has the CAT Runtime send SET UP EVENT LIST
whenever the registered event list changes, so an OTA command that switches a
toolkit applet on or off draws one right after its PoR. The shell answers it
with TERMINAL RESPONSE (OK) as the bootstrap does (TS 102 223 V18.3 clause
6.4.16); the first other command behind it stays unanswered.
"""

from __future__ import annotations

import unittest
from typing import Any

from SCP80 import transport as scp80_transport

ENVELOPE = "80C2000002D100"
SEND_SMS_POR = bytes.fromhex(
    "D02E810301130082028183050086028001"
    "8B1D410005811250F37FF613"
    "027100000E0AB0000100000000010000019000"
)
SEND_SMS_TERMINAL_RESPONSE = "801400000C810301130082028281030100"
#: UDH '027100', RPL, RHL, TAR, CNTR, PCNTR, status '00', one command '90 00'.
ACK_POR_OK = bytes.fromhex("027100000E0AB00001000000FFFF0000019000")
#: Events '03' Location status, '09' Data available, '0A' Channel status.
SET_UP_EVENT_LIST = bytes.fromhex("D00E810301050082028182990303090A")
EMPTY_EVENT_LIST = bytes.fromhex("D00B8103010500820281829900")
EVENT_LIST_TERMINAL_RESPONSE = "801400000C810301050082028281030100"
PROVIDE_LOCAL_INFO = bytes.fromhex("D009810301260082028182")


class _Config:
    def __init__(self) -> None:
        self.counter_increments = 0

    def get(self, key: str) -> str:
        return {"transport": "reader", "spi": "1621"}.get(key, "")

    def increment_counter(self) -> None:
        self.counter_increments += 1


def _transport(responses: dict[str, tuple[bytes, int]]) -> tuple[Any, list[str]]:
    """Return a transport whose card answers each APDU from *responses*."""

    transport = scp80_transport.Transport.__new__(scp80_transport.Transport)
    transport.cfg = _Config()
    transport.conn = None
    transport.active_protocol = None
    transport._stk_bootstrap_trace = []
    transport._stk_bootstrap_trace_printed = False
    transport._ensure_reader_protocol = lambda apdus, verbose=False: True
    calls: list[str] = []

    def fake_transmit(apdu_hex: str, **kwargs):
        del kwargs
        calls.append(apdu_hex)
        return responses.get(apdu_hex, (b"", 0x9000))

    transport.transmit = fake_transmit
    return transport, calls


class AnswerEventListBehindPor(unittest.TestCase):
    def test_the_list_behind_a_send_short_message_por_is_answered(self) -> None:
        transport, calls = _transport(
            {
                ENVELOPE: (b"", 0x9130),
                "8012000030": (SEND_SMS_POR, 0x9000),
                SEND_SMS_TERMINAL_RESPONSE: (b"", 0x9110),
                "8012000010": (SET_UP_EVENT_LIST, 0x9000),
            }
        )

        result = transport.send_ota_sequence([ENVELOPE])

        self.assertTrue(result["delivered"])
        self.assertEqual(result["por_decoded"]["status_code"], "00")
        self.assertEqual(result["answered_event_lists"], ["03090A"])
        self.assertIsNone(result["pending_proactive"])
        self.assertEqual(
            calls,
            [
                ENVELOPE,
                "8012000030",
                SEND_SMS_TERMINAL_RESPONSE,
                "8012000010",
                EVENT_LIST_TERMINAL_RESPONSE,
            ],
        )
        self.assertEqual(transport.cfg.counter_increments, 1)

    def test_the_list_behind_an_envelope_response_por_is_answered(self) -> None:
        transport, calls = _transport(
            {
                ENVELOPE: (ACK_POR_OK, 0x9110),
                "8012000010": (SET_UP_EVENT_LIST, 0x9000),
            }
        )

        result = transport._send_single_ota_apdu(ENVELOPE)

        self.assertEqual(result["por"], ACK_POR_OK.hex().upper())
        self.assertEqual(result["answered_event_lists"], ["03090A"])
        self.assertIsNone(result["pending_proactive"])
        self.assertEqual(calls, [ENVELOPE, "8012000010", EVENT_LIST_TERMINAL_RESPONSE])

    def test_a_command_behind_the_list_stays_unanswered(self) -> None:
        transport, calls = _transport(
            {
                ENVELOPE: (b"", 0x9130),
                "8012000030": (SEND_SMS_POR, 0x9000),
                SEND_SMS_TERMINAL_RESPONSE: (b"", 0x9110),
                "8012000010": (SET_UP_EVENT_LIST, 0x9000),
                EVENT_LIST_TERMINAL_RESPONSE: (b"", 0x910B),
                "801200000B": (PROVIDE_LOCAL_INFO, 0x9000),
            }
        )

        result = transport._send_single_ota_apdu(ENVELOPE)

        self.assertEqual(result["answered_event_lists"], ["03090A"])
        self.assertEqual(result["pending_proactive"], PROVIDE_LOCAL_INFO.hex().upper())
        # The shell cannot honour PROVIDE LOCAL INFORMATION, so it sends no
        # TERMINAL RESPONSE for it.
        self.assertEqual(calls[-2:], [EVENT_LIST_TERMINAL_RESPONSE, "801200000B"])

    def test_answers_stop_at_the_limit(self) -> None:
        transport, calls = _transport(
            {
                ENVELOPE: (b"", 0x9130),
                "8012000030": (SEND_SMS_POR, 0x9000),
                SEND_SMS_TERMINAL_RESPONSE: (b"", 0x9110),
                "8012000010": (SET_UP_EVENT_LIST, 0x9000),
                EVENT_LIST_TERMINAL_RESPONSE: (b"", 0x9110),
            }
        )

        result = transport._send_single_ota_apdu(ENVELOPE)

        limit = scp80_transport._EVENT_LIST_ANSWER_LIMIT
        self.assertEqual(result["answered_event_lists"], ["03090A"] * limit)
        self.assertEqual(result["pending_proactive"], SET_UP_EVENT_LIST.hex().upper())
        self.assertEqual(calls.count(EVENT_LIST_TERMINAL_RESPONSE), limit)


class SetUpEventListEvents(unittest.TestCase):
    def test_the_event_list_is_read(self) -> None:
        events = scp80_transport.Transport._set_up_event_list_events(SET_UP_EVENT_LIST)
        self.assertEqual(events, bytes.fromhex("03090A"))

    def test_an_empty_list_is_still_an_event_list(self) -> None:
        events = scp80_transport.Transport._set_up_event_list_events(EMPTY_EVENT_LIST)
        self.assertEqual(events, b"")

    def test_other_and_malformed_commands_are_refused_without_raising(self) -> None:
        cases = {
            "empty": b"",
            "one byte": b"\xd0",
            "truncated header": bytes.fromhex("D00E81"),
            "over-claiming length": bytes.fromhex("D07F810301050082028182990303090A"),
            "no event list": bytes.fromhex("D009810301050082028182"),
            "other command": PROVIDE_LOCAL_INFO,
        }
        for label, data in cases.items():
            with self.subTest(label):
                self.assertIsNone(
                    scp80_transport.Transport._set_up_event_list_events(data)
                )


if __name__ == "__main__":
    unittest.main()
