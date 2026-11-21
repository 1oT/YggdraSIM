# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What the BIP channel observer reports, and what it refuses to invent.

The cases that matter here are the ones a per-block decoder got wrong: a
TLS record split across two SEND DATA blocks, and the complete records
that shared a block with it. Those assertions are written against the
transport's real shape -- roughly 236-byte channel-data blocks -- rather
than against hand-picked boundaries, because that is what the card
actually hands the terminal.
"""

from __future__ import annotations

import unittest

from yggdrasim_common.bip_stream_decode import (
    LAYER_DNS,
    LAYER_PAYLOAD,
    MAX_HANDSHAKE_MESSAGE_BYTES,
    MAX_PENDING_BYTES,
    BipChannelObserver,
    ChannelEvent,
    decode_payload,
    peek_tls_record,
)
from yggdrasim_common.tls_tables import (
    TLS_ALERT_DESCRIPTIONS,
    TLS_MAX_RECORD_LENGTH,
    alert_description_name,
    cipher_suite_name,
    extension_type_name,
    named_group_name,
    protocol_version_name,
    signature_scheme_name,
)

#: ETSI TS 102 223 §6.4.13 sizes a channel-data block to the transport,
#: not to the record it carries.
CHANNEL_DATA_BLOCK = 236


def tls_record(content_type: int, body: bytes, minor: int = 3) -> bytes:
    """Build one TLS record around *body*."""
    return bytes([content_type, 3, minor]) + len(body).to_bytes(2, "big") + body


def handshake_message(handshake_type: int, body: bytes) -> bytes:
    """Build one TLS handshake message around *body*."""
    return bytes([handshake_type]) + len(body).to_bytes(3, "big") + body


def client_hello_with_sni(server_name: str) -> bytes:
    """Build a ClientHello body carrying an RFC 6066 §3 server_name."""
    name_bytes = server_name.encode("ascii")
    entry = bytes([0x00]) + len(name_bytes).to_bytes(2, "big") + name_bytes
    extension_value = len(entry).to_bytes(2, "big") + entry
    extension = b"\x00\x00" + len(extension_value).to_bytes(2, "big") + extension_value
    return (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extension).to_bytes(2, "big")
        + extension
    )


def split_into_blocks(stream: bytes, size: int = CHANNEL_DATA_BLOCK) -> list[bytes]:
    return [stream[index:index + size] for index in range(0, len(stream), size)]


# Code points read from the library: RFC 5289 §3.2 (0xC02B), RFC 5487 §3.1 (0x00AE,
# 0x00B0), RFC 5746 §3.3 (0x00FF), RFC 6066 §1.1 (extensions 0 and 1) and §4 (code 4 is
# 2^12), RFC 8446 §4.2 (43), §4.2.3 (0x0403), §4.2.7 (0x0017).
ECDHE_ECDSA_AES_128_GCM = 0xC02B
PSK_AES_128_CBC = 0x00AE
PSK_NULL = 0x00B0
RENEGOTIATION_SCSV = 0x00FF
SERVER_NAME = 0
MAX_FRAGMENT_LENGTH = 1
SUPPORTED_VERSIONS = 43
RENEGOTIATION_INFO = 0xFF01


def extensions_block(entries: tuple[tuple[int, bytes], ...]) -> bytes:
    body = b"".join(
        kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value for kind, value in entries
    )
    return len(body).to_bytes(2, "big") + body


def server_name_value(server_name: str) -> bytes:
    name_bytes = server_name.encode("ascii")
    entry = bytes([0x00]) + len(name_bytes).to_bytes(2, "big") + name_bytes
    return len(entry).to_bytes(2, "big") + entry


def client_hello(
    *,
    server_name: str = "",
    cipher_suites: tuple[int, ...] = (ECDHE_ECDSA_AES_128_GCM,),
    fragment_code: int | None = None,
) -> bytes:
    """An RFC 5246 §7.4.1.2 ClientHello body."""
    entries: list[tuple[int, bytes]] = []
    if fragment_code is not None:
        entries.append((MAX_FRAGMENT_LENGTH, bytes([fragment_code])))
    if len(server_name) > 0:
        entries.append((SERVER_NAME, server_name_value(server_name)))
    suites = b"".join(suite.to_bytes(2, "big") for suite in cipher_suites)
    return (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + len(suites).to_bytes(2, "big")
        + suites
        + b"\x01\x00"
        + extensions_block(tuple(entries))
    )


def server_hello(
    *,
    cipher_suite: int = ECDHE_ECDSA_AES_128_GCM,
    extensions: tuple[tuple[int, bytes], ...] = (),
) -> bytes:
    """An RFC 5246 §7.4.1.3 ServerHello body."""
    return (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + cipher_suite.to_bytes(2, "big")
        + b"\x00"
        + extensions_block(extensions)
    )


def certificate_list(*certificates: bytes) -> bytes:
    """An RFC 5246 §7.4.2 Certificate body around opaque entries."""
    entries = b"".join(len(entry).to_bytes(3, "big") + entry for entry in certificates)
    return len(entries).to_bytes(3, "big") + entries


def ecdhe_key_exchange(group: int = 0x0017, scheme: int = 0x0403) -> bytes:
    """RFC 8422 §5.4 ServerECDHParams (named_curve, an uncompressed P-256 point) and a signature."""
    point = b"\x04" + bytes(64)
    signature = bytes(70)
    return (
        b"\x03"
        + group.to_bytes(2, "big")
        + bytes([len(point)])
        + point
        + scheme.to_bytes(2, "big")
        + len(signature).to_bytes(2, "big")
        + signature
    )


def handshake_events(observer: BipChannelObserver, record: bytes, direction: str) -> list[ChannelEvent]:
    return [event for event in observer.observe(record, direction) if event.kind == "Handshake"]


def notes_by_label(event: ChannelEvent) -> dict[str, tuple[str, str]]:
    return {note.label: (note.value, note.tone) for note in event.notes}


class TlsReassemblyTests(unittest.TestCase):
    def test_records_sharing_a_block_with_a_split_record_survive(self) -> None:
        """The regression a per-block decoder had: all-or-nothing decoding.

        A block holding two whole records and the head of a third used to
        report nothing at all, because the truncated tail failed the
        length check and discarded the block.
        """
        stream = (
            tls_record(22, handshake_message(2, bytes(70)))
            + tls_record(22, handshake_message(12, bytes(60)))
            + tls_record(22, handshake_message(11, bytes(300)))
        )
        blocks = split_into_blocks(stream)
        self.assertGreater(len(blocks), 1, "case needs a record to straddle a block")

        observer = BipChannelObserver()
        first = observer.observe(blocks[0], "RX")

        self.assertEqual(
            [event.summary for event in first],
            [
                "TLS Handshake: ServerHello (70 byte(s))",
                "TLS Handshake: ServerKeyExchange (60 byte(s))",
            ],
        )
        self.assertGreater(observer.pending_bytes("RX"), 0)

    def test_split_record_completes_and_reports_its_segment_count(self) -> None:
        stream = tls_record(22, handshake_message(11, bytes(300)))
        blocks = split_into_blocks(stream)
        observer = BipChannelObserver()

        events: list = []
        for block in blocks:
            events.extend(observer.observe(block, "RX"))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].summary, "TLS Handshake: Certificate (300 byte(s))")
        self.assertEqual(events[0].segments, len(blocks))
        self.assertTrue(events[0].reassembled)
        self.assertEqual(observer.pending_bytes("RX"), 0)

    def test_alert_after_a_split_record_is_reported(self) -> None:
        """The alert is the point of the exercise: it used to be invisible."""
        stream = (
            tls_record(22, handshake_message(11, bytes(300)))
            + tls_record(21, bytes([2, 42]))
        )
        observer = BipChannelObserver()
        events: list = []
        for block in split_into_blocks(stream):
            events.extend(observer.observe(block, "RX"))

        alerts = [event for event in events if event.is_protocol_alert]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_level, "fatal")
        self.assertEqual(alerts[0].alert_description, "bad_certificate")
        self.assertEqual(alerts[0].summary, "TLS Alert: fatal bad_certificate")

    def test_directions_buffer_independently(self) -> None:
        observer = BipChannelObserver()
        outbound = tls_record(22, handshake_message(1, bytes(400)))
        inbound = tls_record(21, bytes([1, 0]))

        head, tail = outbound[:100], outbound[100:]
        self.assertEqual(observer.observe(head, "TX"), [])
        inbound_events = observer.observe(inbound, "RX")
        self.assertEqual(len(inbound_events), 1)
        self.assertTrue(inbound_events[0].is_protocol_alert)

        completed = observer.observe(tail, "TX")
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].direction, "TX")

    def test_reset_drops_a_previous_channel_carry_over(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(11, bytes(300)))[:100], "RX")
        self.assertGreater(observer.pending_bytes("RX"), 0)

        observer.reset()

        self.assertEqual(observer.pending_bytes("RX"), 0)
        events = observer.observe(tls_record(21, bytes([2, 40])), "RX")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].alert_description, "handshake_failure")

    def test_flush_reports_bytes_that_never_completed(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(11, bytes(300)))[:100], "RX")

        flushed = observer.flush()

        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0].layer, LAYER_PAYLOAD)
        self.assertTrue(flushed[0].truncated)
        self.assertEqual(flushed[0].byte_count, 100)
        self.assertEqual(observer.pending_bytes("RX"), 0)

    def test_a_second_flush_reports_nothing(self) -> None:
        """A channel can be closed more than once on the way down."""
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(11, bytes(300)))[:100], "RX")

        self.assertEqual(len(observer.flush()), 1)
        self.assertEqual(observer.flush(), [])
        self.assertEqual(observer.flush(), [])

    def test_flushing_an_untouched_observer_reports_nothing(self) -> None:
        self.assertEqual(BipChannelObserver().flush(), [])


class RecordClassificationTests(unittest.TestCase):
    def test_encrypted_alert_is_not_treated_as_a_protocol_alert(self) -> None:
        """RFC 8446 §6.1 makes a cleartext alert exactly two bytes.

        Reading a level and description out of a longer, protected record
        yields a random name -- fatal-looking roughly one time in 128.
        """
        events = BipChannelObserver().observe(tls_record(21, bytes(24)), "RX")

        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].encrypted)
        self.assertFalse(events[0].is_protocol_alert)
        self.assertEqual(events[0].summary, "TLS Alert: encrypted (24 byte(s))")

    def test_handshake_after_change_cipher_spec_is_not_parsed(self) -> None:
        """RFC 5246 §7.1: every record after a CCS has a ciphertext body.

        Walking that ciphertext as HandshakeType/length invents message
        names -- a run of zero bytes reads as ten HelloRequests.
        """
        observer = BipChannelObserver()
        stream = tls_record(20, b"\x01") + tls_record(22, bytes(40))

        events = observer.observe(stream, "TX")

        self.assertEqual(
            [event.summary for event in events],
            [
                "TLS Record: ChangeCipherSpec (1 byte(s))",
                "TLS Record: Handshake (40 byte(s))",
            ],
        )
        self.assertTrue(events[1].encrypted)
        self.assertEqual(events[1].handshake_type, "")

    def test_a_handshake_before_the_cipher_is_still_parsed(self) -> None:
        events = BipChannelObserver().observe(
            tls_record(22, handshake_message(2, bytes(70))), "RX"
        )

        self.assertEqual(events[0].handshake_type, "ServerHello")

    def test_cipher_state_does_not_leak_into_the_next_channel(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(20, b"\x01"), "TX")

        observer.reset()
        events = observer.observe(tls_record(22, handshake_message(1, bytes(60))), "TX")

        self.assertEqual(events[0].handshake_type, "ClientHello")

    def test_client_hello_reports_its_server_name(self) -> None:
        body = client_hello_with_sni("eim.example.test")
        events = BipChannelObserver().observe(
            tls_record(22, handshake_message(1, body)), "TX"
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].server_name, "eim.example.test")
        self.assertIn("sni=eim.example.test", events[0].summary)

    def test_non_tls_bytes_are_reported_as_a_raw_payload(self) -> None:
        events = BipChannelObserver().observe(b"\xde\xad\xbe\xef\x00\x11", "RX")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].layer, LAYER_PAYLOAD)
        self.assertFalse(events[0].truncated)
        self.assertEqual(events[0].summary, "Raw payload: 6 byte(s)")

    def test_an_implausible_record_version_is_not_a_record(self) -> None:
        self.assertIsNone(peek_tls_record(bytes([22, 0x03, 0x04, 0x00, 0x10])))
        self.assertIsNone(peek_tls_record(bytes([99, 0x03, 0x03, 0x00, 0x10])))

    def test_an_oversized_length_claim_is_not_a_record(self) -> None:
        """RFC 8446 §5.2 caps a ciphertext record at 2^14 + 256."""
        self.assertIsNone(peek_tls_record(bytes([23, 0x03, 0x03, 0xFF, 0xFF])))


class BufferBoundTests(unittest.TestCase):
    """The carry-over bound, which the runtime's singleton engine needs.

    The bound is structural rather than enforced: bytes are held back
    only for a record whose declared length ``peek_tls_record`` accepted,
    and that check rejects anything above ``TLS_MAX_RECORD_LENGTH``.
    These assert both halves -- the cap that produces the bound, and the
    bound holding across a long stream.
    """

    def test_a_length_above_the_record_cap_is_never_buffered(self) -> None:
        observer = BipChannelObserver()
        oversized = bytes([23, 0x03, 0x03]) + (TLS_MAX_RECORD_LENGTH + 1).to_bytes(2, "big")

        events = observer.observe(oversized + bytes(64), "RX")

        self.assertEqual(observer.pending_bytes("RX"), 0)
        self.assertEqual([event.layer for event in events], [LAYER_PAYLOAD])

    def test_a_record_that_never_completes_stays_within_the_bound(self) -> None:
        observer = BipChannelObserver()
        header = bytes([23, 0x03, 0x03]) + TLS_MAX_RECORD_LENGTH.to_bytes(2, "big")
        self.assertEqual(observer.observe(header, "RX"), [])

        for _ in range(64):
            self.assertEqual(observer.observe(bytes(64), "RX"), [])
            self.assertLessEqual(observer.pending_bytes("RX"), MAX_PENDING_BYTES)

        self.assertGreater(observer.pending_bytes("RX"), 0)

    def test_pending_bytes_stay_bounded_across_a_long_stream(self) -> None:
        observer = BipChannelObserver()
        stream = (
            tls_record(22, handshake_message(11, bytes(4000)))
            + tls_record(23, bytes(1200))
        ) * 8

        for block in split_into_blocks(stream):
            observer.observe(block, "RX")
            self.assertLessEqual(observer.pending_bytes("RX"), MAX_PENDING_BYTES)


class DnsTests(unittest.TestCase):
    def _query(self, qname: str) -> bytes:
        labels = b"".join(
            bytes([len(part)]) + part.encode("ascii") for part in qname.split(".")
        )
        return (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + labels
            + b"\x00\x00\x01\x00\x01"
        )

    def test_query_reports_its_name_as_a_field(self) -> None:
        events = BipChannelObserver().observe(self._query("eim.example.test"), "TX")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].layer, LAYER_DNS)
        self.assertEqual(events[0].query_name, "eim.example.test")
        self.assertIn("qname=eim.example.test", events[0].summary)

    def test_a_response_whose_question_does_not_parse_is_not_reported(self) -> None:
        """Reporting the header alone invents a response out of any bytes."""
        events = BipChannelObserver().observe(
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xc0\xff", "RX"
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].layer, LAYER_PAYLOAD)


class HandshakeReassemblyTests(unittest.TestCase):
    """RFC 5246 §6.2.1: one handshake message may span several records.

    A client that negotiates 2^9-byte fragments (RFC 6066 §4) receives
    the server's certificate chain that way. Decoding each record on its
    own read the second record's first bytes as a new message: a 600-byte
    Certificate over two 512-byte records printed "TLS Handshake: 0x82
    (3179056 byte(s))" under the real one.
    """

    def test_a_message_split_across_records_is_reported_once_whole(self) -> None:
        message = handshake_message(11, certificate_list(bytes(300), bytes(290)))
        observer = BipChannelObserver()

        first = observer.observe(tls_record(22, message[:512]), "RX")
        second = observer.observe(tls_record(22, message[512:]), "RX")

        self.assertEqual(first, [])
        self.assertEqual(
            [event.summary for event in second],
            [f"TLS Handshake: Certificate ({len(message) - 4} byte(s))"],
        )
        self.assertEqual(second[0].records, 2)
        self.assertEqual(second[0].segments, 2)
        self.assertFalse(second[0].truncated)
        self.assertEqual(second[0].certificates, (bytes(300), bytes(290)))
        self.assertEqual(observer.held_handshake_bytes("RX"), 0)

    def test_a_message_over_three_records_and_the_one_behind_it(self) -> None:
        message = handshake_message(11, certificate_list(bytes(1200)))
        done = handshake_message(14, b"")
        stream = (
            tls_record(22, message[:500])
            + tls_record(22, message[500:1000])
            + tls_record(22, message[1000:] + done)
        )
        observer = BipChannelObserver()
        events: list[ChannelEvent] = []
        for block in split_into_blocks(stream):
            events.extend(observer.observe(block, "RX"))

        self.assertEqual(
            [event.summary for event in events],
            [
                f"TLS Handshake: Certificate ({len(message) - 4} byte(s))",
                "TLS Handshake: ServerHelloDone (0 byte(s))",
            ],
        )
        self.assertEqual([event.records for event in events], [3, 1])
        self.assertEqual(events[1].segments, 1)

    def test_change_cipher_spec_reports_a_message_cut_short(self) -> None:
        """RFC 8446 §5.1: a handshake message never spans a key change."""
        message = handshake_message(11, certificate_list(bytes(300)))
        observer = BipChannelObserver()
        observer.observe(tls_record(22, message[:100]), "RX")

        events = observer.observe(tls_record(20, b"\x01"), "RX")

        self.assertEqual(
            [event.summary for event in events],
            [
                f"TLS Handshake: Certificate ({len(message) - 4} byte(s))",
                "TLS Record: ChangeCipherSpec (1 byte(s))",
            ],
        )
        self.assertTrue(events[0].truncated)
        self.assertEqual(observer.held_handshake_bytes("RX"), 0)

    def test_flush_names_a_message_whose_records_stopped(self) -> None:
        message = handshake_message(11, certificate_list(bytes(300)))
        observer = BipChannelObserver()
        observer.observe(tls_record(22, message[:100]), "RX")

        flushed = observer.flush()

        self.assertEqual(len(flushed), 1)
        self.assertTrue(flushed[0].truncated)
        self.assertEqual(flushed[0].handshake_type, "Certificate")
        self.assertEqual(flushed[0].byte_count, len(message) - 4)
        self.assertEqual(observer.flush(), [])

    def test_a_header_cut_short_is_named_by_its_type(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, b"\x0b\x00"), "RX")

        flushed = observer.flush("RX")

        self.assertEqual([event.summary for event in flushed], ["TLS Handshake: Certificate (header cut short)"])

    def test_a_length_above_the_bound_is_skipped_not_held(self) -> None:
        declared = MAX_HANDSHAKE_MESSAGE_BYTES + 1
        message_head = bytes([11]) + declared.to_bytes(3, "big")
        observer = BipChannelObserver()

        events = observer.observe(tls_record(22, message_head + bytes(16000)), "RX")

        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].truncated)
        self.assertEqual(events[0].byte_count, declared)
        self.assertEqual(observer.held_handshake_bytes("RX"), 0)
        remaining = declared - 16000
        while remaining > 0:
            step = min(remaining, 16000)
            self.assertEqual(observer.observe(tls_record(22, bytes(step)), "RX"), [])
            self.assertEqual(observer.held_handshake_bytes("RX"), 0)
            remaining -= step
        after = observer.observe(tls_record(22, handshake_message(14, b"")), "RX")
        self.assertEqual([event.summary for event in after], ["TLS Handshake: ServerHelloDone (0 byte(s))"])

    def test_held_bytes_stay_below_the_bound(self) -> None:
        message = handshake_message(11, bytes(MAX_HANDSHAKE_MESSAGE_BYTES))
        observer = BipChannelObserver()
        for index in range(0, len(message) - 1, 16000):
            observer.observe(tls_record(22, message[index:min(index + 16000, len(message) - 1)]), "RX")
            self.assertLess(observer.held_handshake_bytes("RX"), MAX_HANDSHAKE_MESSAGE_BYTES + 4)

        self.assertEqual(observer.held_handshake_bytes("RX"), len(message) - 1)

    def test_decode_payload_reassembles_inside_one_payload(self) -> None:
        message = handshake_message(11, certificate_list(bytes(600)))
        payload = tls_record(22, message[:300]) + tls_record(22, message[300:])

        events = decode_payload(payload, "RX")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].records, 2)
        self.assertEqual(events[0].certificates, (bytes(600),))

    def test_decode_payload_names_a_message_that_continues_past_it(self) -> None:
        message = handshake_message(11, certificate_list(bytes(600)))

        events = decode_payload(tls_record(22, message[:300]), "RX")

        self.assertEqual([event.summary for event in events], [f"TLS Handshake: Certificate ({len(message) - 4} byte(s))"])
        self.assertTrue(events[0].truncated)


class HelloTests(unittest.TestCase):
    def _answered(
        self,
        offer: bytes,
        answer: bytes,
    ) -> ChannelEvent:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(1, offer)), "TX")
        return handshake_events(observer, tls_record(22, handshake_message(2, answer)), "RX")[0]

    def test_a_client_hello_carries_its_offer(self) -> None:
        body = client_hello(
            server_name="smdp.example.test",
            cipher_suites=(ECDHE_ECDSA_AES_128_GCM, PSK_AES_128_CBC),
            fragment_code=4,
        )

        event = handshake_events(BipChannelObserver(), tls_record(22, handshake_message(1, body)), "TX")[0]

        self.assertEqual(event.summary, f"TLS Handshake: ClientHello sni=smdp.example.test ({len(body)} byte(s))")
        self.assertEqual(event.protocol_version, 0x0303)
        self.assertEqual(event.cipher_suites, (ECDHE_ECDSA_AES_128_GCM, PSK_AES_128_CBC))
        self.assertEqual(event.extension_types, (MAX_FRAGMENT_LENGTH, SERVER_NAME))
        self.assertEqual(event.max_fragment_length, 4096)
        self.assertEqual(
            notes_by_label(event),
            {
                "version": ("TLS 1.2", ""),
                "cipher suites": ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_CBC_SHA256", ""),
                "max_fragment_length": ("2^12 (4096 bytes)", ""),
                "extensions": ("max_fragment_length, server_name", ""),
            },
        )

    def test_a_fragment_length_outside_the_four_values_fails(self) -> None:
        body = client_hello(fragment_code=5)

        event = handshake_events(BipChannelObserver(), tls_record(22, handshake_message(1, body)), "TX")[0]

        self.assertEqual(notes_by_label(event)["max_fragment_length"], ("invalid value 5", "fail"))
        self.assertEqual(event.max_fragment_length, 0)

    def test_the_requested_fragment_length_echoed_back(self) -> None:
        event = self._answered(
            client_hello(server_name="smdp.example.test", fragment_code=4),
            server_hello(extensions=((SERVER_NAME, b""), (MAX_FRAGMENT_LENGTH, b"\x04"))),
        )

        notes = notes_by_label(event)
        self.assertEqual(notes["max_fragment_length"], ("2^12 (4096 bytes), as requested", "ok"))
        self.assertEqual(notes["extensions"], ("server_name, max_fragment_length", ""))
        self.assertEqual(notes["cipher suite"], ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ""))
        self.assertEqual(event.max_fragment_length, 4096)

    def test_a_fragment_length_left_unanswered_is_a_warning(self) -> None:
        """RFC 6066 §4: without the echo, fragments run to 2^14 bytes."""
        event = self._answered(client_hello(fragment_code=4), server_hello())

        self.assertEqual(
            notes_by_label(event)["max_fragment_length"],
            ("2^12 (4096 bytes) requested, not accepted: fragments run to 2^14 bytes", "warn"),
        )

    def test_a_different_fragment_length_in_the_answer_fails(self) -> None:
        event = self._answered(
            client_hello(fragment_code=4),
            server_hello(extensions=((MAX_FRAGMENT_LENGTH, b"\x02"),)),
        )

        self.assertEqual(
            notes_by_label(event)["max_fragment_length"],
            ("2^10 (1024 bytes), but 2^12 (4096 bytes) was requested", "fail"),
        )

    def test_an_extension_the_client_did_not_send_fails(self) -> None:
        """RFC 5246 §7.4.1.4: the client aborts with unsupported_extension."""
        event = self._answered(
            client_hello(),
            server_hello(extensions=((MAX_FRAGMENT_LENGTH, b"\x04"),)),
        )

        notes = notes_by_label(event)
        self.assertEqual(notes["max_fragment_length"], ("2^12 (4096 bytes), never requested", "fail"))
        self.assertEqual(
            notes["extensions"],
            ("max_fragment_length; not in the ClientHello: max_fragment_length", "fail"),
        )

    def test_renegotiation_info_answers_the_scsv(self) -> None:
        """RFC 5746 §3.6: the SCSV obliges the server to send the extension."""
        event = self._answered(
            client_hello(cipher_suites=(ECDHE_ECDSA_AES_128_GCM, RENEGOTIATION_SCSV)),
            server_hello(extensions=((RENEGOTIATION_INFO, b"\x00"),)),
        )

        self.assertEqual(notes_by_label(event)["extensions"], ("renegotiation_info", ""))

    def test_a_suite_the_client_did_not_offer_fails(self) -> None:
        event = self._answered(client_hello(), server_hello(cipher_suite=PSK_AES_128_CBC))

        self.assertEqual(
            notes_by_label(event)["cipher suite"],
            ("TLS_PSK_WITH_AES_128_CBC_SHA256, not one the ClientHello offered", "fail"),
        )

    def test_a_null_cipher_is_a_warning(self) -> None:
        event = self._answered(
            client_hello(cipher_suites=(PSK_NULL,)),
            server_hello(cipher_suite=PSK_NULL),
        )

        self.assertEqual(
            notes_by_label(event)["cipher suite"],
            ("TLS_PSK_WITH_NULL_SHA256: NULL cipher, records travel unencrypted", "warn"),
        )

    def test_a_server_hello_without_its_client_hello_is_not_judged(self) -> None:
        answer = server_hello(extensions=((MAX_FRAGMENT_LENGTH, b"\x04"),))

        event = handshake_events(BipChannelObserver(), tls_record(22, handshake_message(2, answer)), "RX")[0]

        self.assertEqual(
            notes_by_label(event),
            {
                "version": ("TLS 1.2", ""),
                "cipher suite": ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ""),
                "max_fragment_length": ("2^12 (4096 bytes)", ""),
                "extensions": ("max_fragment_length", ""),
            },
        )

    def test_supported_versions_names_tls_1_3_and_leaves_its_certificate_alone(self) -> None:
        """RFC 8446 §4.2.1 and §4.4.2: the 1.3 Certificate has another layout."""
        observer = BipChannelObserver()
        answer = server_hello(cipher_suite=0x1301, extensions=((SUPPORTED_VERSIONS, b"\x03\x04"),))
        hello = handshake_events(observer, tls_record(22, handshake_message(2, answer)), "RX")[0]
        certificate = handshake_events(
            observer, tls_record(22, handshake_message(11, certificate_list(bytes(40)))), "RX"
        )[0]

        self.assertEqual(hello.protocol_version, 0x0304)
        self.assertEqual(notes_by_label(hello)["version"], ("TLS 1.3", ""))
        self.assertEqual(certificate.certificates, ())

    def test_a_client_hello_reset_forgets_the_offer(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(1, client_hello(fragment_code=4))), "TX")
        observer.reset()

        event = handshake_events(observer, tls_record(22, handshake_message(2, server_hello())), "RX")[0]

        self.assertNotIn("max_fragment_length", notes_by_label(event))


class ServerKeyExchangeTests(unittest.TestCase):
    def _after(self, suite: int, body: bytes) -> ChannelEvent:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(1, client_hello(cipher_suites=(suite,)))), "TX")
        observer.observe(tls_record(22, handshake_message(2, server_hello(cipher_suite=suite))), "RX")
        return handshake_events(observer, tls_record(22, handshake_message(12, body)), "RX")[0]

    def test_ecdhe_parameters_after_an_ecdhe_suite(self) -> None:
        event = self._after(ECDHE_ECDSA_AES_128_GCM, ecdhe_key_exchange())

        self.assertEqual(event.named_group, 0x0017)
        self.assertEqual(event.signature_scheme, 0x0403)
        self.assertEqual(
            notes_by_label(event),
            {
                "key exchange": ("ECDHE secp256r1, 65-byte public key", ""),
                "signature": ("ecdsa_secp256r1_sha256", ""),
            },
        )

    def test_a_psk_suite_leaves_the_key_exchange_unread(self) -> None:
        # RFC 4279 §2: a PSK ServerKeyExchange carries psk_identity_hint<0..2^16-1>.
        event = self._after(PSK_AES_128_CBC, b"\x00\x03" + b"\x03\x00\x17")

        self.assertEqual(event.named_group, 0)
        self.assertEqual(event.notes, ())

    def test_without_a_server_hello_only_an_exact_parse_counts(self) -> None:
        observer = BipChannelObserver()
        exact = handshake_events(observer, tls_record(22, handshake_message(12, ecdhe_key_exchange())), "RX")[0]
        trailing = handshake_events(
            BipChannelObserver(), tls_record(22, handshake_message(12, ecdhe_key_exchange() + b"\x00")), "RX"
        )[0]
        unknown_group = handshake_events(
            BipChannelObserver(), tls_record(22, handshake_message(12, ecdhe_key_exchange(group=0x0042))), "RX"
        )[0]

        self.assertEqual(exact.named_group, 0x0017)
        self.assertEqual(trailing.named_group, 0)
        self.assertEqual(unknown_group.named_group, 0)


class CertificateMessageTests(unittest.TestCase):
    def test_the_list_keeps_its_order_and_the_name_the_client_asked_for(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(1, client_hello(server_name="smdp.example.test"))), "TX")

        event = handshake_events(
            observer, tls_record(22, handshake_message(11, certificate_list(b"\x30\x01", b"\x30\x02"))), "RX"
        )[0]

        self.assertEqual(event.certificates, (b"\x30\x01", b"\x30\x02"))
        self.assertEqual(event.server_name, "smdp.example.test")
        self.assertEqual(event.notes, ())

    def test_a_client_certificate_is_not_tied_to_the_server_name(self) -> None:
        observer = BipChannelObserver()
        observer.observe(tls_record(22, handshake_message(1, client_hello(server_name="smdp.example.test"))), "TX")

        event = handshake_events(
            observer, tls_record(22, handshake_message(11, certificate_list(b"\x30\x01"))), "TX"
        )[0]

        self.assertEqual(event.server_name, "")
        self.assertEqual(event.certificates, (b"\x30\x01",))

    def test_a_list_whose_lengths_do_not_add_up_is_only_noted(self) -> None:
        body = certificate_list(b"\x30\x01") + b"\x00"

        event = handshake_events(BipChannelObserver(), tls_record(22, handshake_message(11, body)), "RX")[0]

        self.assertEqual(event.certificates, ())
        self.assertEqual(
            notes_by_label(event),
            {"structure": ("does not parse as a Certificate; its fields are not shown", "")},
        )


class HandshakeDecodeBoundaryTests(unittest.TestCase):
    """The decode-boundary inputs of the coding standards, for each handshake body read."""

    #: Empty, one byte, a header cut short, and a length that over-claims its body.
    _BODIES = {
        1: (b"", b"\x03", b"\x03\x03" + bytes(10), b"\x03\x03" + bytes(32) + b"\xff" + bytes(4)),
        2: (b"", b"\x03", b"\x03\x03" + bytes(20), b"\x03\x03" + bytes(32) + b"\x00\xc0\x2b\x00\xff\xff"),
        11: (b"", b"\x00", b"\x00\x00", b"\x00\x00\x09" + b"\x00\x00\x40\x30"),
        12: (b"", b"\x03", b"\x03\x00", b"\x03\x00\x17\x41" + bytes(4)),
    }

    def test_each_body_reports_its_message_and_no_fields(self) -> None:
        for handshake_type, bodies in self._BODIES.items():
            for body in bodies:
                with self.subTest(handshake_type=handshake_type, body=body.hex()):
                    events = handshake_events(
                        BipChannelObserver(), tls_record(22, handshake_message(handshake_type, body)), "RX"
                    )

                    self.assertEqual(len(events), 1)
                    self.assertEqual(events[0].cipher_suites, ())
                    self.assertEqual(events[0].certificates, ())
                    self.assertEqual(events[0].named_group, 0)
                    self.assertTrue(all(note.tone == "" for note in events[0].notes))

    def test_an_over_claiming_extension_block_is_not_read(self) -> None:
        body = client_hello(server_name="smdp.example.test")[:-3]

        event = handshake_events(BipChannelObserver(), tls_record(22, handshake_message(1, body)), "TX")[0]

        self.assertEqual(event.server_name, "")
        self.assertEqual(event.extension_types, ())


class TableTests(unittest.TestCase):
    def test_alert_descriptions_are_decimal(self) -> None:
        """bad_certificate is 42. Read as hex 0x42 it is 66, unassigned."""
        self.assertEqual(TLS_ALERT_DESCRIPTIONS[42], "bad_certificate")
        self.assertEqual(alert_description_name(42), "bad_certificate")
        self.assertEqual(alert_description_name(48), "unknown_ca")

    def test_an_unassigned_alert_code_renders_as_hex(self) -> None:
        self.assertEqual(alert_description_name(0x66), "0x66")

    def test_handshake_parameters_resolve_by_code_point(self) -> None:
        self.assertEqual(cipher_suite_name(0xC02B), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
        self.assertEqual(cipher_suite_name(0x00AE), "TLS_PSK_WITH_AES_128_CBC_SHA256")
        self.assertEqual(cipher_suite_name(0x002C), "TLS_PSK_WITH_NULL_SHA")
        self.assertEqual(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256")
        self.assertEqual(extension_type_name(1), "max_fragment_length")
        self.assertEqual(extension_type_name(0xFF01), "renegotiation_info")
        self.assertEqual(named_group_name(0x001A), "brainpoolP256r1")
        self.assertEqual(signature_scheme_name(0x0403), "ecdsa_secp256r1_sha256")
        self.assertEqual(protocol_version_name(0x0303), "TLS 1.2")

    def test_a_code_point_outside_the_tables_renders_as_hex(self) -> None:
        self.assertEqual(cipher_suite_name(0x1234), "0x1234")
        self.assertEqual(extension_type_name(0x9999), "0x9999")
        self.assertEqual(named_group_name(0x0042), "0x0042")
        self.assertEqual(protocol_version_name(0x0302), "0x0302")


if __name__ == "__main__":
    unittest.main()
