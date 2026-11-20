# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SMS framing around the OTA packet: TP-UDL and the ENVELOPE header.

TP-UDL tells the receiving entity how many octets of user data follow.
Nothing in the suite read it before, so a fixed value survived: it was
right only for one payload size and wrong either way around it.
"""

from __future__ import annotations

import unittest

from SCP80.builder import OtaPacketBuilder

#: Offset of TP-UDL in an SMS-DELIVER whose TP-OA is five semi-octets:
#: one octet of TP-MTI, five of address, TP-PID, TP-DCS, seven of TP-SCTS.
TP_UDL_OFFSET = 15


class _StubConfig:
    def __init__(self, sender: str = "82") -> None:
        self.values = {"pid": "7F", "dcs": "F6", "sender": sender, "cla": "80"}

    def get(self, key: str) -> str:
        return self.values[key]


def _builder(sender: str = "82") -> OtaPacketBuilder:
    builder = object.__new__(OtaPacketBuilder)
    builder.cfg = _StubConfig(sender)
    return builder


class SmsUserDataLength(unittest.TestCase):
    """TS 23.040 §9.2.3.16: with a header present, TP-UDL is the octets of
    the header plus the octets of the data."""

    def test_single_message_length_follows_the_payload(self) -> None:
        builder = _builder()
        for size in (1, 10, 34, 80, 130):
            with self.subTest(block=size):
                tpdu, reported = builder._build_single_sms_tpdu(bytes(size))
                actual = len(tpdu) - TP_UDL_OFFSET - 1
                self.assertEqual(tpdu[TP_UDL_OFFSET], actual)
                self.assertEqual(reported, actual)

    def test_concatenated_segment_length_follows_the_fragment(self) -> None:
        builder = _builder()
        for size in (1, 20, 120):
            with self.subTest(fragment=size):
                tpdu, reported = builder._build_concat_sms_tpdu(bytes(size), 0x41, 3, 1)
                actual = len(tpdu) - TP_UDL_OFFSET - 1
                self.assertEqual(tpdu[TP_UDL_OFFSET], actual)
                self.assertEqual(reported, actual)

    def test_no_octets_sit_between_the_timestamp_and_the_length(self) -> None:
        """The prefix used to carry a length and a header byte of its own,
        so a concatenated segment had two stray octets before TP-UDL."""

        builder = _builder()
        tpdu, _ = builder._build_concat_sms_tpdu(bytes(20), 0x41, 3, 1)
        self.assertEqual(len(OtaPacketBuilder.SMS_TPDU_PREFIX), TP_UDL_OFFSET)
        # The user data header follows TP-UDL immediately.
        self.assertEqual(tpdu[TP_UDL_OFFSET + 1], 0x07)

    def test_single_message_header_carries_the_command_packet_identifier(self) -> None:
        """TS 23.048 table 6: UDHL '02', IEIa CPI '70', IEIDL '00'."""

        builder = _builder()
        tpdu, _ = builder._build_single_sms_tpdu(bytes(8))
        self.assertEqual(tpdu[TP_UDL_OFFSET + 1 : TP_UDL_OFFSET + 4], bytes.fromhex("027000"))


class EnvelopeDeviceIdentities(unittest.TestCase):
    """TS 102 223 v18.3 §8.7 device identities; the source is ``sender``."""

    def test_the_default_source_is_the_terminal(self) -> None:
        prefix = _builder()._envelope_prefix()
        self.assertEqual(prefix[0], 0x02, "device identities tag")
        self.assertEqual(prefix[1], 0x02, "device identities length")
        self.assertEqual(prefix[2], 0x82, "source: terminal")
        self.assertEqual(prefix[3], 0x81, "destination: UICC")

    def test_sender_83_names_the_network_as_a_modem_does(self) -> None:
        """TS 31.111 v19.4 §7.1.1.2: a modem sets the source to the network."""

        prefix = _builder("83")._envelope_prefix()
        self.assertEqual(prefix[2], 0x83, "source: network")
        self.assertEqual(prefix[3], 0x81, "destination: UICC")

    def test_the_envelope_carries_the_configured_source(self) -> None:
        for sender in ("82", "83"):
            with self.subTest(sender=sender):
                apdu = _builder(sender)._wrap_sms_tpdu(bytes(4))
                self.assertEqual(apdu[14:22], f"0202{sender}81")

    def test_address_object_follows(self) -> None:
        prefix = _builder()._envelope_prefix()
        self.assertEqual(prefix[4], 0x06, "address tag")
        self.assertEqual(prefix[5], len(prefix) - 6)


if __name__ == "__main__":
    unittest.main()
