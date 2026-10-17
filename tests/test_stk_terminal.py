# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The shared TERMINAL PROFILE, generic TERMINAL RESPONSE and proactive drain."""
from __future__ import annotations

import unittest

from yggdrasim_common.stk_terminal import (
    MAXIMAL_TERMINAL_PROFILE,
    drain_proactive_commands,
    generic_terminal_response_apdu,
    terminal_profile_apdu,
)


def _byte(number: int) -> int:
    """Profile byte *number*, counted from 1 as ETSI TS 102 223 §5.2 counts them."""
    return MAXIMAL_TERMINAL_PROFILE[number - 1]


class MaximalTerminalProfileTests(unittest.TestCase):
    """ETSI TS 102 223 V18.3.0 §5.2 with 3GPP TS 31.111 V19.4.0 §5.2 bytes 36-39."""

    def test_the_profile_reaches_the_last_assigned_byte(self) -> None:
        # Byte 39 b1 (PLI, NG-RAN timing advance) is the last assigned bit.
        self.assertEqual(len(MAXIMAL_TERMINAL_PROFILE), 39)
        self.assertEqual(_byte(39), 0x01)

    def test_the_apdu_is_a_terminal_profile(self) -> None:
        apdu = terminal_profile_apdu()
        self.assertEqual(apdu[:5], bytes([0x80, 0x10, 0x00, 0x00, 39]))
        self.assertEqual(apdu[5:], MAXIMAL_TERMINAL_PROFILE)
        self.assertEqual(terminal_profile_apdu(cla=0xA0)[0], 0xA0)

    def test_rfu_deprecated_and_forbidden_bits_stay_clear(self) -> None:
        for number, mask in (
            (7, 0xE0),  # b6-b8 RFU
            (10, 0xFC),  # b3-b8 RFU
            (16, 0x10),  # b5 RFU
            (19, 0xF0),  # b5-b8 RFU
            (21, 0xF0),  # b5-b8 RFU
            (24, 0xF0),  # b5-b8 RFU
            (26, 0xFC),  # b3-b8 RFU
            (27, 0xFF),  # RFU
            (28, 0xC0),  # b7-b8 RFU
            (29, 0x80),  # b8 RFU
            (32, 0x40),  # b7 CAT service list for eCAT client: shall not be set
            (34, 0x80),  # b8 deprecated, bit = 0
            (35, 0xC0),  # b7-b8 RFU
            (37, 0xF0),  # b5-b8 for future usage
            (38, 0xFF),  # for future usage
            (39, 0xFE),  # b2-b8 for future usage
        ):
            with self.subTest(byte=number):
                self.assertEqual(_byte(number) & mask, 0)
        # Byte 11 is the soft-key count, whose 'FF' is reserved.
        self.assertNotEqual(_byte(11), 0xFF)

    def test_no_negative_or_foreign_capability_is_claimed(self) -> None:
        # Byte 14 b6 "no display" and b7 "no keypad" would contradict the
        # display and input commands the profile claims.
        self.assertEqual(_byte(14) & 0x60, 0)
        # TIA/EIA-136-270 and 3GPP2 CCAT facilities are not a 3GPP terminal's.
        self.assertEqual(_byte(19), 0)
        self.assertEqual(_byte(20), 0)

    def test_the_facilities_the_cards_here_depend_on_are_claimed(self) -> None:
        for number, mask, facility in (
            (1, 0x20, "timer expiration"),
            (4, 0x40, "PLI (MCC, MNC, LAC, Cell ID & IMEI)"),
            (5, 0x01, "SET UP EVENT LIST"),
            (5, 0x10, "Event: Location status"),
            (6, 0x0C, "Events: Data available, Channel status"),
            (8, 0x03, "TIMER MANAGEMENT"),
            (12, 0xFF, "Bearer Independent Protocol commands"),
            (17, 0x01, "TCP, UICC in client mode, remote connection"),
            (25, 0x10, "Event: Network Rejection"),
            (33, 0x01, "DNS server address request for OPEN CHANNEL"),
            (34, 0x20, "REFRESH with eUICC Profile State Change"),
        ):
            with self.subTest(facility=facility):
                self.assertEqual(_byte(number) & mask, mask)

    def test_every_other_defined_byte_is_fully_claimed(self) -> None:
        for number in (1, 2, 3, 4, 5, 6, 8, 9, 12, 13, 15, 17, 18, 22, 23, 25, 30, 31, 33, 36):
            with self.subTest(byte=number):
                self.assertEqual(_byte(number), 0xFF)


class GenericTerminalResponseTests(unittest.TestCase):
    """ETSI TS 102 223 §6.8 TERMINAL RESPONSE to any proactive command."""

    def test_the_command_details_are_echoed_and_the_result_is_success(self) -> None:
        # TIMER MANAGEMENT start timer 2, as a card issues it.
        fetch = bytes.fromhex("D0118103012700820281822401022503001000")
        self.assertEqual(
            generic_terminal_response_apdu(fetch),
            bytes.fromhex("801400000C" "8103012700" "82028281" "830100"),
        )

    def test_the_card_device_identities_tag_is_kept(self) -> None:
        # PROVIDE LOCAL INFORMATION from a card that clears the comprehension
        # bit on its tags: both objects come back under its convention.
        fetch = bytes.fromhex("D009" "0103012600" "02028182")
        self.assertEqual(
            generic_terminal_response_apdu(fetch),
            bytes.fromhex("801400000C" "0103012600" "02028281" "830100"),
        )

    def test_an_unparsable_command_still_gets_a_response(self) -> None:
        self.assertEqual(
            generic_terminal_response_apdu(b""),
            bytes.fromhex("801400000C" "8103010000" "82028281" "830100"),
        )


class DrainProactiveCommandsTests(unittest.TestCase):
    def _card(self, script):
        """An exchange that answers from *script*, one reply per APDU."""
        sent: list[bytes] = []

        def exchange(apdu: bytes, log_name: str):
            sent.append(bytes(apdu))
            return script.pop(0)

        return exchange, sent

    def test_every_announced_command_is_fetched_and_answered(self) -> None:
        exchange, sent = self._card(
            [
                (bytes.fromhex("D0118103012700820281822401022503001000"), 0x90, 0x00),
                (b"", 0x91, 0x0F),
                (bytes.fromhex("D00D8103010500820281829902090A"), 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )

        sw1, sw2, answered = drain_proactive_commands(exchange, 0x91, 0x13, "TEST")

        self.assertEqual((sw1, sw2, answered), (0x90, 0x00, 2))
        self.assertEqual(sent[0], bytes.fromhex("8012000013"))
        self.assertEqual(sent[2], bytes.fromhex("801200000F"))
        self.assertEqual(sent[1][:2], bytes([0x80, 0x14]))
        self.assertEqual(sent[3][5:10], bytes.fromhex("8103010500"))

    def test_a_failed_fetch_stops_the_drain(self) -> None:
        exchange, sent = self._card([(b"", 0x6F, 0x00)])

        self.assertEqual(
            drain_proactive_commands(exchange, 0x91, 0x10, "TEST"), (0x6F, 0x00, 0)
        )
        self.assertEqual(len(sent), 1)

    def test_the_limit_bounds_a_card_that_never_goes_idle(self) -> None:
        # POLL INTERVAL, 10 seconds: 15 bytes, announced as '91 0F'.
        command = bytes.fromhex("D00D" "8103010300" "82028182" "8402000A")
        script = []
        for _ in range(3):
            script.append((command, 0x90, 0x00))
            script.append((b"", 0x91, 0x0F))
        exchange, _ = self._card(script)

        self.assertEqual(
            drain_proactive_commands(exchange, 0x91, 0x0F, "TEST", limit=3),
            (0x91, 0x0F, 3),
        )

    def test_a_status_word_without_a_pending_command_sends_nothing(self) -> None:
        exchange, sent = self._card([])

        self.assertEqual(
            drain_proactive_commands(exchange, 0x90, 0x00, "TEST"), (0x90, 0x00, 0)
        )
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
