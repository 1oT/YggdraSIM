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
            comprehension_tlv("3E", bytes([0x21, 192, 0, 2, 53])),
        ]
    )


def open_channel_tcp(port: int) -> bytes:
    """OPEN CHANNEL with transport level '02' -- TCP, UICC client."""
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014001")),
            comprehension_tlv("82", bytes.fromhex("8121")),
            comprehension_tlv("35", bytes.fromhex("0203040506")),
            comprehension_tlv("39", bytes.fromhex("0578")),
            comprehension_tlv("3C", bytes([0x02]) + port.to_bytes(2, "big")),
            comprehension_tlv("3E", bytes([0x21, 192, 0, 2, 53])),
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
            comprehension_tlv("3E", bytes([0x21, 192, 0, 2, 53])),
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


def client_hello(host: str = "smdp.example.com") -> bytes:
    """A TLS 1.2 ClientHello naming *host* in its SNI extension.

    RFC 8446 clause 4.1.2 for the message, RFC 6066 clause 3 for the
    extension. Built rather than captured: a recorded handshake carries
    both a real hostname and a real random.
    """
    name = host.encode("ascii")
    server_name = bytes([0x00]) + len(name).to_bytes(2, "big") + name
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extension = (
        bytes.fromhex("0000")
        + len(server_name_list).to_bytes(2, "big")
        + server_name_list
    )
    body = b"".join(
        [
            bytes.fromhex("0303"),          # legacy_version
            bytes(range(32)),               # random
            bytes([0x00]),                  # legacy_session_id: empty
            bytes.fromhex("0002")           # cipher_suites
            + bytes.fromhex("1301"),        # TLS_AES_128_GCM_SHA256
            bytes.fromhex("0100"),          # legacy_compression_methods
            len(extension).to_bytes(2, "big") + extension,
        ]
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return (
        bytes.fromhex("160303") + len(handshake).to_bytes(2, "big") + handshake
    )


#: A ServerHello: handshake type 2, which carries no SNI.
SERVER_HELLO = bytes.fromhex("1603030004020000")

#: A record declaring length 0 whose only body byte is the handshake type.
#: The ClientHello walk reads a 24-bit length from bytes 7 to 9, which are
#: not there -- the shortest block that reaches the SNI parser at all.
TLS_HANDSHAKE_STUB = bytes.fromhex("160303000001")


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


def open_channel_ipv6(port: int, address: bytes) -> bytes:
    """OPEN CHANNEL whose Other address is a 16-byte IPv6 literal."""
    return b"".join(
        [
            comprehension_tlv("81", bytes.fromhex("014001")),
            comprehension_tlv("82", bytes.fromhex("8121")),
            comprehension_tlv("35", bytes.fromhex("0203040506")),
            comprehension_tlv("39", bytes.fromhex("0578")),
            comprehension_tlv("3C", bytes([0x01]) + port.to_bytes(2, "big")),
            comprehension_tlv("3E", bytes([0x57]) + address),
        ]
    )


class TheAddressIsFilterableByValue(BipPayloadBase):
    """The Other address is carried as a typed field, not only a string.

    The string field keeps the role label, so it can only be matched with
    `contains`. The typed peers carry the raw bytes, so Wireshark filters
    them like `ip.addr` -- subnet match and address-literal comparison --
    and formats IPv6 in its RFC 5952 canonical form.
    """

    #: RFC 3849 documentation range; renders canonically as 2001:db8::1.
    IPV6 = bytes.fromhex("20010db8000000000000000000000001")

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                # open_channel() carries 192.0.2.53 in its Other address.
                fetch(open_channel(443)),
                fetch(open_channel_ipv6(443, cls.IPV6)),
            ],
            "typed-address.pcap",
        )

    def test_the_ipv4_address_populates_a_typed_field(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.address.ipv4"])
        self.assertIn("192.0.2.53", [row[0] for row in rows if row and row[0]])

    def test_the_ipv4_address_matches_a_subnet_filter(self) -> None:
        text = decode_text(
            self.capture, display_filter="yapdu.cat.address.ipv4 == 192.0.2.0/24"
        )
        self.assertIn("192.0.2.53", text)

    def test_the_ipv6_address_renders_canonically(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.address.ipv6"])
        # RFC 5952: leading zeros suppressed, longest zero run compressed.
        self.assertIn("2001:db8::1", [row[0] for row in rows if row and row[0]])

    def test_the_string_field_still_carries_the_role_label(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.address"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertTrue(any("data destination address:" in v for v in values))


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

    def test_the_query_name_populates_a_filterable_field(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.fqdn"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["smdp.example.com"])

    def test_the_query_name_reaches_the_send_data_detail(self) -> None:
        # The whole point: the resolved host shows in the packet list, not
        # only three levels down in the stock dns tree.
        rows = decode_fields(self.capture, ["yapdu.command_name", "yapdu.detail"])
        send = [
            row[1]
            for row in rows
            if len(row) > 1 and row[0] == "FETCH" and "SEND DATA" in row[1]
        ]
        self.assertTrue(send)
        self.assertIn("smdp.example.com", send[0])


class TlsSniInsideBip(BipPayloadBase):
    """The host survives the switch from DNS to TLS.

    Once the IPAd has resolved the eIM or SM-DP+ it opens a channel to
    the address, and from there the ClientHello's SNI is the only place
    the name still appears -- so a trace read from the packet list would
    otherwise go anonymous exactly where the download happens.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                fetch(open_channel(443)),
                fetch(send_data(client_hello())),
            ],
            "sni.pcap",
        )

    def test_the_tls_dissector_is_still_reached(self) -> None:
        self.assertIn("tls", self.protocols()[1])

    def test_the_payload_protocol_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["tls"])

    def test_the_sni_populates_the_same_field_as_a_dns_name(self) -> None:
        # One field for "this row names a host", whichever half of the
        # trace it came from; payload_protocol says which.
        rows = decode_fields(self.capture, ["yapdu.cat.fqdn"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["smdp.example.com"])

    def test_the_sni_reaches_the_send_data_detail(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.command_name", "yapdu.detail"])
        send = [
            row[1]
            for row in rows
            if len(row) > 1 and row[0] == "FETCH" and "SEND DATA" in row[1]
        ]
        self.assertTrue(send)
        self.assertIn("smdp.example.com", send[0])


class TlsWithoutAClientHelloNamesNoHost(BipPayloadBase):
    """Only a complete ClientHello yields a name.

    A truncated handshake would give a truncated hostname, and BIP
    channel data is not reassembled -- so half a name in the Detail
    column is worse than none. A ServerHello and an alert carry no SNI
    at all, and must not acquire one from a misread offset.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [
                fetch(open_channel(443)),
                # A ClientHello cut mid-extension, as a >236-byte one
                # arrives split across channel-data blocks.
                fetch(send_data(client_hello()[:40])),
                fetch(send_data(SERVER_HELLO)),
                fetch(send_data(TLS_BAD_CERTIFICATE)),
                fetch(send_data(TLS_HANDSHAKE_STUB)),
            ],
            "sni-absent.pcap",
        )

    def test_no_row_claims_a_host(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.fqdn"])
        self.assertEqual([row[0] for row in rows if row and row[0]], [])

    def test_a_record_too_short_to_walk_does_not_abort_the_frame(self) -> None:
        """A raise in the SNI walk would take the whole frame's tree down.

        Nothing in add_channel_payload wraps the call, so reading past the
        end of a short block is not a missing name -- it is a frame that
        stops dissecting at the CAT layer.
        """
        rows = decode_fields(
            self.capture,
            ["frame.number", "yapdu.cat.payload_protocol", "yapdu.detail"],
        )
        stub = [row for row in rows if row and row[0] == "5"]
        self.assertTrue(stub, "the stub frame did not decode at all")
        self.assertEqual(stub[0][1], "tls")
        self.assertIn("SEND DATA", stub[0][2])

    def test_the_truncated_record_is_still_flagged(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.tls.incomplete"])
        self.assertTrue([row[0] for row in rows if row and row[0]])


class DnsOverTcpIsDeFramed(BipPayloadBase):
    """DNS over a TCP BIP channel is prefixed with a 2-byte length.

    RFC 1035 clause 4.2.2 puts a two-byte message length ahead of the DNS
    header on TCP. The stock dns dissector expects a bare message on a
    channel tvb, so the prefix is stripped before handoff -- but only
    when it agrees with the payload and what follows is really DNS.
    """

    #: DNS_QUERY carried over TCP: its 2-byte length, then the message.
    TCP_DNS = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY

    @classmethod
    def setUpClass(cls) -> None:
        cls.build(
            [fetch(open_channel_tcp(53)), fetch(send_data(cls.TCP_DNS))],
            "dns-tcp.pcap",
        )

    def test_the_dns_dissector_is_reached(self) -> None:
        self.assertIn("dns", self.protocols()[1])

    def test_the_payload_protocol_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        self.assertEqual([row[0] for row in rows if row and row[0]], ["dns"])

    def test_the_queried_name_is_visible(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        self.assertIn("smdp.example.com", text)

    def test_no_malformed_packet_from_the_length_prefix(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==2")
        section = "YggdraSIM APDU" + text.split("YggdraSIM APDU")[-1]
        self.assertNotIn("Malformed", section)


class NonDnsBytesOnTcpPort53AreNotHandedOver(BipPayloadBase):
    """The length prefix and DNS shape must both hold, or the bytes stay
    raw -- a profile-package fragment on a TCP/53 channel is not DNS."""

    @classmethod
    def setUpClass(cls) -> None:
        # A plausible 2-byte length ahead of non-DNS bytes.
        payload = bytes.fromhex("0005") + bytes.fromhex("BF360A1122")
        cls.build(
            [fetch(open_channel_tcp(53)), fetch(send_data(payload))],
            "not-dns-tcp.pcap",
        )

    def test_nothing_is_handed_to_the_dns_dissector(self) -> None:
        self.assertNotIn(":dns", self.protocols()[1])

    def test_no_payload_protocol_is_claimed(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.cat.payload_protocol"])
        self.assertEqual([row[0] for row in rows if row and row[0]], [])


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

    def test_the_query_name_reaches_the_send_data_detail(self) -> None:
        # Frame 3 is the SEND DATA on the channel the terminal allocated;
        # its Detail must name the host even though the port was learned
        # two frames earlier.
        rows = decode_fields(self.capture, ["yapdu.command_name", "yapdu.detail"])
        send = [
            row[1]
            for row in rows
            if len(row) > 1 and row[0] == "FETCH" and "SEND DATA" in row[1]
        ]
        self.assertTrue(send)
        self.assertIn("smdp.example.com", send[0])


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

    def test_every_expected_alert_is_present_at_its_value(self) -> None:
        # The registry moved out of cat.lua into the generated
        # tables.lua, which renders integer keys as two-digit uppercase
        # hex. Accepting either rendering keeps a generator formatting
        # change a question about the table rather than a test failure.
        source = (
            Path(DISSECTOR_PATH).parent / "yggdrasim_apdu" / "tables.lua"
        ).read_text(encoding="utf-8")
        for value, name in self.EXPECTED.items():
            with self.subTest(alert=name):
                self.assertTrue(
                    f"[{value}] = \"{name}\"" in source
                    or f"[0x{value:02X}] = \"{name}\"" in source,
                    f"alert {value} ({name}) is missing from the generated table",
                )


if __name__ == "__main__":
    unittest.main()
