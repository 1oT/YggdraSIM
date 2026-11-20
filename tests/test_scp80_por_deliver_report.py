# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A PoR requested by SMS-DELIVER-REPORT (SPI2 b6 = 0).

The card answers the SMS-PP ENVELOPE with the PoR as its response data, the
UICC Acknowledgement of TS 31.111 v19.4 clause 7.1.1.2, opened by a UDH that
holds the RPI '71' (TS 31.115 v19 clause 4.4). A proactive command pending
behind it is a command of its own, and carries the PoR only after a '0B'
handover (TS 31.115 v19 clause 7).
"""

from __future__ import annotations

import unittest
from typing import Any

from SCP80 import transport as scp80_transport

#: UDH '027100', then RPL, RHL, TAR, CNTR, PCNTR and status '06'.
ACK_SECURITY_ERROR = bytes.fromhex("027100000B0AB0000100000000000006")
#: Status '00' with one executed command that ended '90 00'.
ACK_POR_OK = bytes.fromhex("027100000E0AB00001000000FFFF0000019000")
#: Status '0B': the response data follows in a SEND SHORT MESSAGE.
ACK_HANDOVER = bytes.fromhex("027100000B0AB000010000000001000B")
SEND_SMS_POR = bytes.fromhex(
    "D02E810301130082028183050086028001"
    "8B1D410005811250F37FF613"
    "027100000E0AB0000100000000010000019000"
)
SEND_SMS_TERMINAL_RESPONSE = "801400000C810301130082028281030100"
PROVIDE_LOCAL_INFO = bytes.fromhex("D009810301260082028182")


class _Config:
    def __init__(self) -> None:
        self.counter_increments = 0

    def get(self, key: str) -> str:
        return {"transport": "reader", "spi": "1601"}.get(key, "")

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
    calls: list[str] = []

    def fake_transmit(apdu_hex: str, **kwargs):
        del kwargs
        calls.append(apdu_hex)
        return responses.get(apdu_hex, (b"", 0x9000))

    transport.transmit = fake_transmit
    return transport, calls


class DecodeEnvelopeResponse(unittest.TestCase):
    def test_a_security_error_is_read_from_the_response_data(self) -> None:
        decoded = scp80_transport.Transport.decode_por(ACK_SECURITY_ERROR, 0x9000)
        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["por_carrier"], "ENVELOPE response")
        self.assertEqual(decoded["status_code"], "06")
        self.assertEqual(decoded["status_meaning"], "Unidentified security error")
        self.assertEqual(decoded["tar"], "B00001")
        self.assertEqual(decoded["cntr"], "0000000000")
        self.assertNotIn("sms_tpdu", decoded)

    def test_the_command_status_follows_the_count(self) -> None:
        decoded = scp80_transport.Transport.decode_por(ACK_POR_OK, "611A")
        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["status_code"], "00")
        self.assertEqual(decoded["command_count"], 1)
        self.assertEqual(decoded["command_sw"], "9000")
        self.assertEqual(decoded["fetch_sw"], "611A")

    def test_a_send_short_message_names_its_carrier(self) -> None:
        decoded = scp80_transport.Transport.decode_por(SEND_SMS_POR, 0x9130)
        self.assertTrue(decoded["valid"], decoded.get("error"))
        self.assertEqual(decoded["por_carrier"], "SEND SHORT MESSAGE")

    def test_malformed_response_data_is_refused_without_raising(self) -> None:
        cases = {
            "empty": b"",
            "udhl only": b"\x02",
            "truncated udh": bytes.fromhex("0271"),
            "over-claiming iedl": bytes.fromhex("027105"),
            "command packet identifier": bytes.fromhex("027000000B0AB0000100000000000006"),
            "short response packet": bytes.fromhex("0271000001"),
        }
        for label, data in cases.items():
            with self.subTest(label):
                decoded = scp80_transport.Transport.decode_por(data, 0x9000)
                self.assertFalse(decoded["valid"])
                self.assertTrue(decoded["error"])

    def test_status_0b_names_the_sms_submit_handover(self) -> None:
        self.assertEqual(
            scp80_transport.Transport._por_status_meaning(0x0B),
            "Actual response data to be sent using SMS-SUBMIT",
        )


class CollectEnvelopeResponse(unittest.TestCase):
    def test_get_response_returns_the_por(self) -> None:
        transport, calls = _transport({"00C0000010": (ACK_SECURITY_ERROR, 0x9000)})

        por, pending = transport._collect_por(0x6110)

        self.assertEqual(por, ACK_SECURITY_ERROR)
        self.assertEqual(pending, b"")
        self.assertEqual(calls, ["00C0000010"])

    def test_a_later_proactive_command_stays_out_of_the_por(self) -> None:
        transport, calls = _transport(
            {
                "00C0000013": (ACK_POR_OK, 0x910B),
                "801200000B": (PROVIDE_LOCAL_INFO, 0x9000),
            }
        )

        por, pending = transport._collect_por(0x6113)

        self.assertEqual(por, ACK_POR_OK)
        self.assertEqual(pending, PROVIDE_LOCAL_INFO)
        # The shell cannot honour PROVIDE LOCAL INFORMATION, so it sends no
        # TERMINAL RESPONSE for it.
        self.assertEqual(calls, ["00C0000013", "801200000B"])

    def test_a_0b_handover_takes_the_por_from_send_short_message(self) -> None:
        transport, calls = _transport(
            {
                "00C0000010": (ACK_HANDOVER, 0x9130),
                "8012000030": (SEND_SMS_POR, 0x9000),
            }
        )

        por, pending = transport._collect_por(0x6110)

        self.assertEqual(por, SEND_SMS_POR)
        self.assertEqual(pending, b"")
        self.assertEqual(
            calls, ["00C0000010", "8012000030", SEND_SMS_TERMINAL_RESPONSE]
        )

    def test_t1_response_data_beside_91xx_is_kept(self) -> None:
        envelope = "80C2000002D100"
        transport, calls = _transport(
            {
                envelope: (ACK_POR_OK, 0x910B),
                "801200000B": (PROVIDE_LOCAL_INFO, 0x9000),
            }
        )

        result = transport._send_single_ota_apdu(envelope)

        self.assertTrue(result["delivered"])
        self.assertEqual(result["por"], ACK_POR_OK.hex().upper())
        self.assertEqual(result["por_decoded"]["status_code"], "00")
        self.assertEqual(result["pending_proactive"], PROVIDE_LOCAL_INFO.hex().upper())
        self.assertEqual(calls, [envelope, "801200000B"])

    def test_t0_warning_fetches_the_por_with_get_response(self) -> None:
        """TS 102 221 v18.4 annex C.1.7: Le '00', then '6C Luicc', then data."""

        envelope = "80C2000002D100"
        transport, calls = _transport(
            {
                envelope: (b"", 0x6200),
                "00C0000000": (b"", 0x6C10),
                "00C0000010": (ACK_SECURITY_ERROR, 0x9000),
            }
        )

        result = transport._send_single_ota_apdu(envelope)

        self.assertTrue(result["delivered"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["por"], ACK_SECURITY_ERROR.hex().upper())
        self.assertEqual(result["por_decoded"]["status_code"], "06")
        self.assertEqual(result["por_decoded"]["por_carrier"], "ENVELOPE response")
        self.assertEqual(result["por_decoded"]["fetch_sw"], "6200")
        self.assertEqual(calls, [envelope, "00C0000000", "00C0000010"])

    def test_t1_warning_carries_the_por_itself(self) -> None:
        envelope = "80C2000002D100"
        transport, calls = _transport({envelope: (ACK_SECURITY_ERROR, 0x6200)})

        result = transport._send_single_ota_apdu(envelope)

        self.assertEqual(result["por"], ACK_SECURITY_ERROR.hex().upper())
        self.assertEqual(result["por_decoded"]["status_code"], "06")
        self.assertEqual(calls, [envelope])

    def test_a_warning_without_response_data_reports_the_missing_por(self) -> None:
        envelope = "80C2000002D100"
        transport, calls = _transport(
            {
                envelope: (b"", 0x6200),
                "00C0000000": (b"", 0x6F00),
            }
        )

        result = transport._send_single_ota_apdu(envelope)

        self.assertTrue(result["delivered"])
        self.assertIsNone(result["por"])
        self.assertIn("ENVELOPE answered 6200, GET RESPONSE 6F00", str(result["error"]))
        self.assertEqual(calls, [envelope, "00C0000000"])

    def test_a_warning_followed_by_a_proactive_command_keeps_both_apart(self) -> None:
        envelope = "80C2000002D100"
        transport, calls = _transport(
            {
                envelope: (b"", 0x6300),
                "00C0000000": (b"", 0x6C13),
                "00C0000013": (ACK_POR_OK, 0x910B),
                "801200000B": (PROVIDE_LOCAL_INFO, 0x9000),
            }
        )

        result = transport._send_single_ota_apdu(envelope)

        self.assertEqual(result["por"], ACK_POR_OK.hex().upper())
        self.assertEqual(result["pending_proactive"], PROVIDE_LOCAL_INFO.hex().upper())
        self.assertEqual(
            calls, [envelope, "00C0000000", "00C0000013", "801200000B"]
        )

    def test_the_sequence_reports_the_pending_command(self) -> None:
        envelope = "80C2000002D100"
        transport, _calls = _transport(
            {
                envelope: (b"", 0x6113),
                "00C0000013": (ACK_POR_OK, 0x910B),
                "801200000B": (PROVIDE_LOCAL_INFO, 0x9000),
            }
        )
        transport._ensure_reader_protocol = lambda apdus, verbose=False: True

        result = transport.send_ota_sequence([envelope])

        self.assertTrue(result["delivered"])
        self.assertEqual(result["por_decoded"]["por_carrier"], "ENVELOPE response")
        self.assertEqual(result["pending_proactive"], PROVIDE_LOCAL_INFO.hex().upper())
        self.assertEqual(transport.cfg.counter_increments, 1)


if __name__ == "__main__":
    unittest.main()
