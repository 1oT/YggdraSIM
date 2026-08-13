# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What rides inside a BIP channel, and why it has to be decoded.

An eUICC downloading a profile does it over a Bearer Independent
Protocol channel, and the bytes in that channel are ordinary DNS, TLS
and HTTP. Both the stock ``etsi_cat`` dissector and this one used to
stop at ``Channel data: 1503030002022a``, which is the difference
between "the download failed" and "the SM-DP+ presented a certificate
the eUICC rejected".

Note on numbering: TLS AlertDescription values are decimal.
``bad_certificate`` is 42, which is ``0x2A``. Reading it as hex ``0x42``
gives 66, which is unassigned -- an operator would see nothing at all.
The tests below pin the decimal reading.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    DISSECTOR_PATH,
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    run_tshark,
    write_capture,
)


def comprehension_tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


def proactive(body: bytes) -> bytes:
    """Wrap a COMPREHENSION-TLV run in its BER 0xD0 envelope."""
    return bytes.fromhex("D0") + bytes([len(body)]) + body


def fetch(body: bytes) -> Exchange:
    return Exchange(bytes.fromhex("8012000000"), proactive(body) + b"\x90\x00")


def open_channel(port: int) -> bytes:
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014001")),
            comprehension_tlv("82", bytes.fromhex("8121")),
            comprehension_tlv("35", bytes.fromhex("0203040506")),
            comprehension_tlv("39", bytes.fromhex("0578")),
            comprehension_tlv(
                "3C", bytes([0x01]) + port.to_bytes(2, "big")
            ),
            comprehension_tlv("3E", bytes([0x21, 8, 8, 8, 8])),
        ]
    )


def open_channel_to_terminal(port: int) -> bytes:
    """OPEN CHANNEL as a card really sends it: UICC to terminal.

    The channel identifier is absent, because the terminal has not
    allocated one yet.
    """
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014001")),
            comprehension_tlv("82", bytes.fromhex("8182")),
            comprehension_tlv("35", bytes.fromhex("0303040506")),
            comprehension_tlv("39", bytes.fromhex("0578")),
            comprehension_tlv("3C", bytes([0x01]) + port.to_bytes(2, "big")),
            comprehension_tlv("3E", bytes([0x21, 8, 8, 8, 8])),
        ]
    )


def send_data(payload: bytes, *, channel: int = 1) -> bytes:
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014301")),
            comprehension_tlv("82", bytes([0x81, 0x20 + channel])),
            comprehension_tlv("36", payload),
        ]
    )


#: A fatal alert: level 2, description 42 (bad_certificate).
TLS_BAD_CERTIFICATE = bytes.fromhex("1503030002022A")

#: A DNS query for an SM-DP+ hostname.
DNS_QUERY = (
    bytes.fromhex("abcd01000001000000000000")
    + b"\x04smdp\x07example\x03com\x00"
    + bytes.fromhex("00010001")
)

HTTP_REQUEST = (
    b"GET /gsma/rsp2/es9plus/ HTTP/1.1\r\nHost: smdp.example.com\r\n\r\n"
)


class BipPayloadBase(unittest.TestCase):
    @classmethod
    def build(cls, exchanges: list[Exchange], name: str) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(Path(cls._directory.name) / name, exchanges)
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def protocols(self) -> list[str]:
        rows = decode_fields(self.capture, ["frame.protocols"])
        return [row[0] for row in rows if row]


class TlsAlertsAreVisible(BipPayloadBase):
    """The case that motivated this: a certificate rejection."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                fetch(open_channel(443)),
                fetch(send_data(TLS_BAD_CERTIFICATE)),
            ],
            "tls.pcap",
        )

    def test_the_tls_dissector_is_reached(self) -> None:
        self.assertIn("tls", self.protocols()[1])

    def test_the_alert_is_named_not_left_as_hex(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("bad_certificate", text)
        self.assertIn("Description: Bad Certificate (42)", text)

    def test_the_alert_is_decimal_42_not_hex_42(self) -> None:
        """0x42 would be 66, which is unassigned."""
        rows = decode_fields(self.capture, ["yapdu.tls.alert"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["bad_certificate (42)"])
        self.assertNotIn("66", values[0])

    def test_a_fatal_alert_raises_expert_info(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("fatal TLS alert 42", text)

    def test_the_level_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tls.alert_level"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["fatal"])

    def test_the_alert_is_filterable(self) -> None:
        result = run_tshark(
            [
                "-X",
                f"lua_script:{DISSECTOR_PATH}",
                "-r",
                str(self.capture),
                "-Y",
                'yapdu.tls.alert contains "bad_certificate"',
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())


class DnsInsideBip(BipPayloadBase):
    """A download that fails on name resolution looks like a network fault."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [fetch(open_channel(53)), fetch(send_data(DNS_QUERY))], "dns.pcap"
        )

    def test_the_dns_dissector_is_reached(self) -> None:
        self.assertIn("dns", self.protocols()[1])

    def test_the_queried_name_is_visible(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("smdp.example.com", text)

    def test_the_payload_protocol_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["dns"])


class HttpInsideBip(BipPayloadBase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [fetch(open_channel(80)), fetch(send_data(HTTP_REQUEST))], "http.pcap"
        )

    def test_the_http_dissector_is_reached(self) -> None:
        self.assertIn("http", self.protocols()[1])

    def test_the_es9plus_request_uri_is_visible(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("/gsma/rsp2/es9plus/", text)


class ContentBeatsPort(BipPayloadBase):
    """A channel's port is a hint, not a verdict.

    The device identity does not always tie a SEND DATA back to the
    OPEN CHANNEL that preceded it, so the port can be inherited from the
    wrong channel. When the bytes plainly say HTTP, they win.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                fetch(open_channel(53)),
                # Sent on a different channel, carrying obvious HTTP.
                fetch(send_data(HTTP_REQUEST, channel=2)),
            ],
            "mixed.pcap",
        )

    def test_http_on_a_dns_port_is_still_read_as_http(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["http"])


class PartialRecordsDegradeCleanly(BipPayloadBase):
    """A TLS record split across SEND DATA blocks must not be mangled.

    Handing half a record to the stock dissector reports a malformed
    packet, which is less useful than the header this dissector can read
    for itself.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # A handshake record claiming 512 bytes, of which 4 are present.
        truncated = bytes.fromhex("160303020001020304")
        cls.build(
            [fetch(open_channel(443)), fetch(send_data(truncated))],
            "partial.pcap",
        )

    def test_the_record_is_flagged_incomplete(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tls.incomplete"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["True"])

    def test_the_record_type_is_still_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tls.content_type"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["handshake"])

    def test_the_stock_dissector_is_not_handed_a_partial_record(self) -> None:
        self.assertNotIn("tls", self.protocols()[1])

    def test_no_malformed_packet_is_produced(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        section = "YggdraSIM APDU" + text.split("YggdraSIM APDU")[-1]
        self.assertNotIn("Malformed", section)


class NonProtocolPayloadIsLeftAlone(BipPayloadBase):
    """Random bytes must not be forced into a dissector."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [fetch(send_data(bytes.fromhex("DEADBEEFCAFEBABE")))], "opaque.pcap"
        )

    def test_no_protocol_is_claimed(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        self.assertEqual([row[0] for row in rows if row and row[0]], [])

    def test_the_bytes_are_still_shown(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("deadbeefcafebabe", text.lower())


def terminal_response(body: bytes) -> Exchange:
    return Exchange(
        bytes.fromhex("80140000") + bytes([len(body)]) + body,
        bytes.fromhex("9000"),
    )


def channel_status(channel: int, *, established: bool = True) -> bytes:
    first = channel + (0x80 if established else 0x00)
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014001")),
            comprehension_tlv("82", bytes.fromhex("8281")),
            comprehension_tlv("83", bytes.fromhex("00")),
            comprehension_tlv("38", bytes([first, 0x00])),
        ]
    )


class DnsResolvesThroughTheAllocatedChannel(BipPayloadBase):
    """The realistic OPEN CHANNEL flow, which used to learn nothing.

    ETSI TS 102 223 clause 6.4.27 addresses OPEN CHANNEL UICC to
    terminal ('81' to '82'): the channel does not exist yet, and the
    terminal allocates it in the Channel status TLV of its TERMINAL
    RESPONSE. Reading a channel number out of the command's own device
    identities therefore always failed, nothing was ever recorded, and a
    profile download that failed on name resolution stayed exactly as
    invisible as it had been before the dissector existed.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                fetch(open_channel_to_terminal(53)),
                terminal_response(channel_status(1)),
                fetch(send_data(DNS_QUERY)),
            ],
            "dns-allocated.pcap",
        )

    def test_the_port_survives_from_open_channel_to_send_data(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["dns"])

    def test_the_queried_name_is_visible(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==3")
        self.assertIn("smdp.example.com", text)


class EncryptedAlertsAreNotGuessedAt(BipPayloadBase):
    """A plaintext alert is exactly two bytes; anything longer is not one.

    Reading bytes 6 and 7 out of ciphertext produces a random alert
    name, and roughly one record in 128 produces a fatal-looking one --
    a "fatal TLS alert" expert item raised over nothing at all.
    """

    @classmethod
    def setUpClass(cls) -> None:
        encrypted = bytes.fromhex("1503030014") + bytes(range(0x14))
        cls.build(
            [fetch(open_channel(443)), fetch(send_data(encrypted))],
            "encrypted-alert.pcap",
        )

    def test_no_alert_name_is_invented(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tls.alert"])
        self.assertEqual([row[0] for row in rows if row and row[0]], [])

    def test_no_fatal_alert_expert_item_is_raised(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertNotIn("fatal TLS alert", text)

    def test_the_record_is_marked_as_encrypted(self) -> None:
        """Saying nothing at all would read as "there was no alert"."""
        rows = decode_fields(self.capture, ["yapdu.tls.alert_encrypted"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["True"])


class AlertTableConformance(unittest.TestCase):
    """Spot-check the alert table against RFC 5246 / RFC 8446."""

    EXPECTED = {
        0: "close_notify",
        10: "unexpected_message",
        20: "bad_record_mac",
        40: "handshake_failure",
        42: "bad_certificate",
        43: "unsupported_certificate",
        44: "certificate_revoked",
        45: "certificate_expired",
        46: "certificate_unknown",
        47: "illegal_parameter",
        48: "unknown_ca",
        49: "access_denied",
        50: "decode_error",
        51: "decrypt_error",
        70: "protocol_version",
        71: "insufficient_security",
        80: "internal_error",
        86: "inappropriate_fallback",
        90: "user_canceled",
        109: "missing_extension",
        112: "unrecognized_name",
        113: "bad_certificate_status_response",
        116: "certificate_required",
        120: "no_application_protocol",
    }

    def test_every_expected_alert_is_present_at_its_decimal_value(self) -> None:
        source = (
            Path(DISSECTOR_PATH).parent / "yggdrasim_apdu" / "cat.lua"
        ).read_text(encoding="utf-8")
        for value, name in self.EXPECTED.items():
            with self.subTest(alert=name):
                self.assertIn(f"[{value}] = \"{name}\"", source)


if __name__ == "__main__":
    unittest.main()
