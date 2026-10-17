# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Passive observer for the payloads a BIP channel carries.

A card driving its own TLS session over BIP hands the terminal one
SEND DATA or RECEIVE DATA block at a time (ETSI TS 102 223 §6.4.13,
§6.4.14). Those blocks are transport-sized, around 236 bytes, and carry
no framing of their own, so a TLS record routinely straddles two of
them. Decoding each block in isolation therefore discards every complete
record that shared the block with a truncated one, and the bytes
resurface as an unattributed raw payload. :class:`BipChannelObserver`
keeps a per-direction buffer instead and only reports a record once it
is whole.

The observer holds no session keys, so a protected record's body stays
opaque. What it can always report is the record layer: the content type,
the declared length, and -- for a cleartext alert, which RFC 8446 §5.1
forbids fragmenting or coalescing -- the level and description. Nothing
here guesses at ciphertext. Until a direction's ChangeCipherSpec the
handshake is cleartext too (RFC 5246 §7.4): each message is reassembled
across the records it spans (§6.2.1), and the hellos, the server's
certificate list and its ECDHE parameters are read out of it.

Results are :class:`ChannelEvent` records, not strings. Callers that
need YggdraSIM's trace line read ``event.summary``; callers deciding
whether the card reported a real protocol alert read
``event.is_protocol_alert`` rather than matching a prefix on rendered
text. Raw payload bytes are deliberately not retained: these events are
appended to history lists on a process-wide singleton, so an event that
held its own body would grow the poll loop's footprint without bound.
The one exception is a Certificate message's certificate list, which a
caller needs whole to read the chain; it rides on that event alone, and
no handshake message is held beyond ``MAX_HANDSHAKE_MESSAGE_BYTES``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from yggdrasim_common.tls_tables import (
    TLS_MAX_FRAGMENT_LENGTHS,
    TLS_MAX_RECORD_LENGTH,
    TLS_NAMED_GROUPS,
    alert_description_name,
    alert_level_name,
    cipher_suite_name,
    content_type_name,
    display_name,
    extension_type_name,
    handshake_type_name,
    named_group_name,
    protocol_version_name,
    signature_scheme_name,
)

__all__ = [
    "ChannelEvent",
    "BipChannelObserver",
    "HandshakeNote",
    "LAYER_DNS",
    "LAYER_HTTP",
    "LAYER_PAYLOAD",
    "LAYER_TLS",
    "MAX_HANDSHAKE_MESSAGE_BYTES",
    "MAX_PENDING_BYTES",
    "decode_payload",
    "dns_query_summary",
    "peek_tls_record",
]

LAYER_DNS = "DNS"
LAYER_TLS = "TLS"
LAYER_HTTP = "HTTP"
LAYER_PAYLOAD = "PAYLOAD"

KIND_ALERT = "Alert"
KIND_HANDSHAKE = "Handshake"
KIND_QUERY = "Query"
KIND_RAW = "Raw"
KIND_REQUEST = "Request"
KIND_RECORD = "Record"
KIND_RESPONSE = "Response"

#: The bound on what one direction carries between calls. It is not a
#: policy the observer enforces after the fact but a consequence of
#: :func:`peek_tls_record` rejecting a declared length above
#: ``TLS_MAX_RECORD_LENGTH``: bytes are only ever held back for a record
#: whose length passed that check, so an incomplete record is always
#: shorter than its header plus the cap. The runtime's card engine is a
#: process-wide singleton, so that bound is what keeps a poll loop from
#: accumulating a channel's traffic for the life of the process.
MAX_PENDING_BYTES = TLS_MAX_RECORD_LENGTH + 5

#: Plausibility bounds for an RFC 1035 §4.1.1 header. A BIP channel
#: resolves one name at a time, so counts far above these mark bytes that
#: are not a DNS message at all.
_MAX_DNS_QUESTION_COUNT = 16
_MAX_DNS_RECORD_COUNT = 64

_DNS_RECORD_TYPES = {
    0x0001: "A",
    0x0005: "CNAME",
    0x001C: "AAAA",
}
_DNS_QUERY_TYPES = {
    0x0001: "A",
    0x001C: "AAAA",
}
_DNS_CLASSES = {
    0x0001: "IN",
}

_TLS_CONTENT_CHANGE_CIPHER_SPEC = 20
_TLS_CONTENT_ALERT = 21
_TLS_CONTENT_HANDSHAKE = 22
_TLS_HANDSHAKE_CLIENT_HELLO = 1
_TLS_HANDSHAKE_SERVER_HELLO = 2
_TLS_HANDSHAKE_CERTIFICATE = 11
_TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12
_TLS_HANDSHAKE_HEADER_LENGTH = 4

_TLS_EXTENSION_SERVER_NAME = 0
_TLS_EXTENSION_MAX_FRAGMENT_LENGTH = 1
_TLS_EXTENSION_SUPPORTED_VERSIONS = 43
_TLS_EXTENSION_RENEGOTIATION_INFO = 0xFF01
#: RFC 5746 §3.6: a ClientHello carrying this SCSV obliges the server to
#: answer with an empty renegotiation_info extension.
_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
#: RFC 8446 §4.2.1: the supported_versions value of TLS 1.3. Its
#: Certificate message has another layout (§4.4.2) and is encrypted.
_TLS_VERSION_1_3 = 0x0304
#: RFC 8422 §5.4: named_curve is the one ECCurveType left.
_EC_CURVE_TYPE_NAMED_CURVE = 3

#: The bound on one handshake message held while its records arrive.
#: RFC 5246 §6.2.1 lets a message span several records, and a client
#: that negotiates 2^9-byte fragments (RFC 6066 §4) receives a
#: certificate chain in pieces; the 24-bit length field would otherwise
#: let one header pin 16 MiB on a process-wide singleton. A message
#: above the bound is reported by name and length, and its bytes are
#: skipped as they arrive instead of held.
MAX_HANDSHAKE_MESSAGE_BYTES = 1 << 16

#: RFC 8446 §6.1: an alert fragment is exactly AlertLevel plus
#: AlertDescription. A longer alert record is AEAD- or CBC-protected and
#: its code cannot be read on the wire; reading bytes out of that
#: ciphertext yields a random alert name, fatal-looking roughly one time
#: in 128, which would raise a session-failure diagnosis over nothing.
_TLS_CLEARTEXT_ALERT_LENGTH = 2


class HandshakeNote(NamedTuple):
    """One line of what a handshake message carried, with a tone ('', 'ok', 'warn' or 'fail')."""

    label: str
    value: str
    tone: str = ""


@dataclass(frozen=True)
class ChannelEvent:
    """One decoded thing the observer saw on a BIP channel.

    ``byte_count`` is the declared record body length for a TLS record
    and the payload length otherwise, matching what the trace line
    prints. ``segments`` counts the channel-data blocks the record was
    reassembled from, so a record that arrived whole reads as 1; a
    handshake message also counts the ``records`` it spanned.

    ``server_name`` is the RFC 6066 §3 name of the handshake: the one a
    ClientHello carried, and on a Certificate the one the channel's
    ClientHello asked for, so the chain can be held against it.
    ``protocol_version``, ``cipher_suites``, ``extension_types`` and
    ``max_fragment_length`` (plaintext bytes, RFC 6066 §4) are what a
    hello offered or, on a ServerHello, chose; ``named_group`` and
    ``signature_scheme`` are an ECDHE ServerKeyExchange's;
    ``certificates`` is a Certificate message's list, sender first
    (RFC 5246 §7.4.2). ``notes`` renders all of that line by line,
    with a ServerHello judged against the ClientHello it answers.
    """

    direction: str
    layer: str
    kind: str
    summary: str
    byte_count: int = 0
    segments: int = 1
    is_protocol_alert: bool = False
    encrypted: bool = False
    truncated: bool = False
    alert_level: str = ""
    alert_description: str = ""
    handshake_type: str = ""
    server_name: str = ""
    query_name: str = ""
    answers: tuple[str, ...] = ()
    http_method: str = ""
    http_target: str = ""
    http_status: str = ""
    records: int = 1
    protocol_version: int = 0
    cipher_suites: tuple[int, ...] = ()
    extension_types: tuple[int, ...] = ()
    max_fragment_length: int = 0
    named_group: int = 0
    signature_scheme: int = 0
    certificates: tuple[bytes, ...] = ()
    notes: tuple[HandshakeNote, ...] = ()

    @property
    def reassembled(self) -> bool:
        """True when the record did not fit in a single channel-data block."""
        return self.segments > 1


@dataclass(frozen=True)
class TlsRecordHeader:
    """A five-byte TLS record header that passed a plausibility check."""

    content_type: int
    major: int
    minor: int
    length: int
    complete: bool

    @property
    def total_length(self) -> int:
        return 5 + self.length


def peek_tls_record(value_bytes: bytes) -> TlsRecordHeader | None:
    """Inspect a record header without consuming it.

    Returns ``None`` when the bytes are not a plausible record. RFC 8446
    §5.1 pins legacy_record_version to 0x0303 (0x0301 on an initial
    ClientHello), so the set that ever reaches the wire is 0x0300 to
    0x0303; 0x0304 is a protocol version, never a record version, and
    accepting it only widens the false-positive surface of a five-byte
    sniff.
    """
    if len(value_bytes) < 5:
        return None
    content_type = value_bytes[0]
    if len(content_type_name(content_type)) == 0:
        return None
    if value_bytes[1] != 0x03 or value_bytes[2] > 0x03:
        return None
    record_length = int.from_bytes(value_bytes[3:5], "big", signed=False)
    if record_length > TLS_MAX_RECORD_LENGTH:
        return None
    return TlsRecordHeader(
        content_type=content_type,
        major=value_bytes[1],
        minor=value_bytes[2],
        length=record_length,
        complete=len(value_bytes) >= 5 + record_length,
    )


def _record_display_name(content_type: int) -> str:
    registry_name = content_type_name(content_type)
    if len(registry_name) == 0:
        return f"0x{int(content_type):02X}"
    return display_name(registry_name)


def _handshake_display_name(handshake_type: int) -> str:
    registry_name = handshake_type_name(handshake_type)
    if len(registry_name) == 0:
        return f"0x{int(handshake_type):02X}"
    return display_name(registry_name)


class BipChannelObserver:
    """Reassembles BIP channel payloads into whole records per direction.

    One instance follows one open channel. ``reset`` clears both
    directions and belongs on OPEN CHANNEL and CLOSE CHANNEL, so a new
    session never inherits the previous session's trailing bytes.
    """

    def __init__(self) -> None:
        self._pending: dict[str, bytearray] = {}
        self._blocks: dict[str, int] = {}
        self._cipher_active: dict[str, bool] = {}
        self._handshake = _HandshakeLayer()

    def reset(self) -> None:
        """Drop any buffered bytes, cipher and handshake state in both directions."""
        self._pending.clear()
        self._blocks.clear()
        self._cipher_active.clear()
        self._handshake.reset()

    def pending_bytes(self, direction: str) -> int:
        """Bytes held back waiting for the rest of their record."""
        return len(self._pending.get(direction, b""))

    def held_handshake_bytes(self, direction: str) -> int:
        """Bytes of a handshake message waiting for its next record.

        Fewer than ``MAX_HANDSHAKE_MESSAGE_BYTES`` + 4: a longer message is
        skipped rather than held.
        """
        return self._handshake.held(direction)

    def observe(self, payload: bytes, direction: str) -> list[ChannelEvent]:
        """Feed one channel-data block and return what completed."""
        payload_bytes = bytes(payload or b"")
        if len(payload_bytes) == 0:
            return []
        buffer = self._pending.setdefault(direction, bytearray())
        carried_bytes = len(buffer)
        if carried_bytes == 0:
            datagram_event = _decode_datagram(payload_bytes, direction)
            if datagram_event is not None:
                return [datagram_event]
        buffer.extend(payload_bytes)
        self._blocks[direction] = self._blocks.get(direction, 0) + 1
        return self._drain(direction, carried_bytes)

    def flush(self, direction: str = "") -> list[ChannelEvent]:
        """Report whatever never completed, then drop it.

        A channel that closes mid-record leaves bytes the session will
        never finish. Reporting them as truncated is what separates "the
        peer stopped talking" from "nothing was pending", which the
        diagnosis layer reads differently.
        """
        known = set(self._pending).union(self._handshake.directions())
        directions = [direction] if len(direction) > 0 else sorted(known)
        events: list[ChannelEvent] = []
        for pending_direction in directions:
            events.extend(self._handshake.drop(pending_direction))
            buffer = self._pending.get(pending_direction)
            if buffer is None or len(buffer) == 0:
                continue
            events.append(
                ChannelEvent(
                    direction=pending_direction,
                    layer=LAYER_PAYLOAD,
                    kind=KIND_RAW,
                    summary=f"Raw payload: {len(buffer)} byte(s)",
                    byte_count=len(buffer),
                    segments=max(1, self._blocks.get(pending_direction, 1)),
                    truncated=True,
                )
            )
            buffer.clear()
            self._blocks[pending_direction] = 0
        return events

    def _drain(self, direction: str, carried_bytes: int) -> list[ChannelEvent]:
        buffer = self._pending[direction]
        events: list[ChannelEvent] = []
        first_emit = True
        while len(buffer) > 0:
            header = peek_tls_record(bytes(buffer))
            if header is None:
                events.append(self._raw_event(direction, carried_bytes > 0))
                return events
            if not header.complete:
                # Held back until the rest arrives. This is the only path
                # that carries bytes across a call, and it runs solely for
                # a length peek_tls_record accepted, which is what bounds
                # the carry-over at MAX_PENDING_BYTES.
                return events
            segments = self._blocks.get(direction, 1) if first_emit else 1
            if header.content_type == _TLS_CONTENT_CHANGE_CIPHER_SPEC:
                # RFC 8446 §5.1: a handshake message never spans a key change.
                events.extend(self._handshake.drop(direction))
            events.extend(
                _decode_record(
                    header,
                    bytes(buffer[5:header.total_length]),
                    direction,
                    segments,
                    self._handshake,
                    self._cipher_active.get(direction, False),
                )
            )
            if header.content_type == _TLS_CONTENT_CHANGE_CIPHER_SPEC:
                self._cipher_active[direction] = True
            del buffer[:header.total_length]
            first_emit = False
            self._blocks[direction] = 1
        self._blocks[direction] = 0
        return events

    def _raw_event(self, direction: str, was_reassembling: bool) -> ChannelEvent:
        buffer = self._pending[direction]
        event = ChannelEvent(
            direction=direction,
            layer=LAYER_PAYLOAD,
            kind=KIND_RAW,
            summary=f"Raw payload: {len(buffer)} byte(s)",
            byte_count=len(buffer),
            segments=max(1, self._blocks.get(direction, 1)),
            truncated=was_reassembling,
        )
        buffer.clear()
        self._blocks[direction] = 0
        return event



def _decode_datagram(payload: bytes, direction: str) -> ChannelEvent | None:
    """Decode a payload that carries one self-framed message."""
    query_event = _decode_dns_query(payload, direction)
    if query_event is not None:
        return query_event
    response_event = _decode_dns_response(payload, direction)
    if response_event is not None:
        return response_event
    return _decode_http_message(payload, direction)


def _decode_record(
    header: TlsRecordHeader,
    body: bytes,
    direction: str,
    segments: int,
    handshake: _HandshakeLayer,
    cipher_active: bool = False,
) -> list[ChannelEvent]:
    """Decode one whole record.

    *cipher_active* says a ChangeCipherSpec has already gone by in this
    direction (RFC 5246 §7.1), which makes every later record body
    ciphertext. Handshake structure is only read while it is False:
    walking ciphertext as HandshakeType/length yields invented message
    names, and a run of zero bytes reads as ten HelloRequests. A
    handshake record goes to *handshake*, which reports a message once
    its last fragment is in, so a record that carries only part of one
    reports nothing yet.
    """
    if header.content_type == _TLS_CONTENT_ALERT:
        return [_alert_event(header, body, direction, segments)]
    if header.content_type == _TLS_CONTENT_HANDSHAKE and not cipher_active and len(body) > 0:
        return handshake.feed(direction, body, segments)
    return [
        ChannelEvent(
            direction=direction,
            layer=LAYER_TLS,
            kind=KIND_RECORD,
            summary=(
                f"TLS Record: {_record_display_name(header.content_type)} "
                f"({header.length} byte(s))"
            ),
            byte_count=header.length,
            segments=segments,
            encrypted=cipher_active and header.content_type == _TLS_CONTENT_HANDSHAKE,
        )
    ]


def decode_payload(payload: bytes, direction: str = "") -> list[ChannelEvent]:
    """Decode one self-contained payload, carrying nothing across calls.

    This is the single-shot counterpart to :class:`BipChannelObserver`,
    for callers that render one captured frame at a time and have no
    stream to reassemble. A record that runs past the end of *payload*
    stops the walk: the records ahead of it are still reported, which is
    what a per-block decoder could not do.
    """
    payload_bytes = bytes(payload or b"")
    if len(payload_bytes) == 0:
        return []
    datagram_event = _decode_datagram(payload_bytes, direction)
    if datagram_event is not None:
        return [datagram_event]
    events: list[ChannelEvent] = []
    offset = 0
    cipher_active = False
    handshake = _HandshakeLayer()
    while offset < len(payload_bytes):
        header = peek_tls_record(payload_bytes[offset:])
        if header is None or not header.complete:
            break
        if header.content_type == _TLS_CONTENT_CHANGE_CIPHER_SPEC:
            events.extend(handshake.drop(direction))
        body_start = offset + 5
        events.extend(
            _decode_record(
                header,
                payload_bytes[body_start:offset + header.total_length],
                direction,
                1,
                handshake,
                cipher_active,
            )
        )
        if header.content_type == _TLS_CONTENT_CHANGE_CIPHER_SPEC:
            cipher_active = True
        offset += header.total_length
    # A message whose last fragment lies beyond this payload is named,
    # with its declared length, as continuing.
    events.extend(handshake.drop(direction))
    if len(events) > 0:
        return events
    return [
        ChannelEvent(
            direction=direction,
            layer=LAYER_PAYLOAD,
            kind=KIND_RAW,
            summary=f"Raw payload: {len(payload_bytes)} byte(s)",
            byte_count=len(payload_bytes),
        )
    ]


#: RFC 9112 §3 request methods a BIP channel plausibly carries.
_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


def _decode_http_message(payload: bytes, direction: str) -> ChannelEvent | None:
    """Decode an RFC 9112 §3 request line or §4 status line."""
    if len(payload) < 8:
        return None
    try:
        preview_text = payload[:512].decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    preview_lines = preview_text.splitlines()
    first_line = str(preview_lines[0] if len(preview_lines) > 0 else "").strip()
    if len(first_line) == 0:
        return None
    parts = first_line.split()
    if " HTTP/" in first_line and len(parts) >= 2:
        for method in _HTTP_METHODS:
            if not first_line.startswith(f"{method} "):
                continue
            return ChannelEvent(
                direction=direction,
                layer=LAYER_HTTP,
                kind=KIND_REQUEST,
                summary=f"HTTP Request: {parts[0]} {parts[1]}",
                byte_count=len(payload),
                http_method=parts[0],
                http_target=parts[1],
            )
    if first_line.startswith("HTTP/"):
        status_parts = first_line.split(None, 2)
        if len(status_parts) < 2:
            return None
        status_text = " ".join(status_parts[1:])
        return ChannelEvent(
            direction=direction,
            layer=LAYER_HTTP,
            kind=KIND_RESPONSE,
            summary=f"HTTP Response: {status_text}",
            byte_count=len(payload),
            http_status=status_parts[1],
        )
    return None


def _alert_event(
    header: TlsRecordHeader,
    body: bytes,
    direction: str,
    segments: int,
) -> ChannelEvent:
    if header.length == _TLS_CLEARTEXT_ALERT_LENGTH and len(body) >= 2:
        level_name = alert_level_name(body[0])
        description_name = alert_description_name(body[1])
        return ChannelEvent(
            direction=direction,
            layer=LAYER_TLS,
            kind=KIND_ALERT,
            summary=f"TLS Alert: {level_name} {description_name}",
            byte_count=header.length,
            segments=segments,
            is_protocol_alert=True,
            alert_level=level_name,
            alert_description=description_name,
        )
    return ChannelEvent(
        direction=direction,
        layer=LAYER_TLS,
        kind=KIND_ALERT,
        summary=f"TLS Alert: encrypted ({header.length} byte(s))",
        byte_count=header.length,
        segments=segments,
        encrypted=True,
    )


@dataclass
class _PendingMessage:
    """One direction's handshake bytes waiting for the rest of their message."""

    data: bytearray = field(default_factory=bytearray)
    skip: int = 0
    records: int = 0
    segments: int = 0


@dataclass(frozen=True)
class _ClientHello:
    version: int
    cipher_suites: tuple[int, ...]
    extension_types: tuple[int, ...]
    server_name: str
    fragment_code: int | None
    supported_versions: tuple[int, ...]


@dataclass(frozen=True)
class _ServerHello:
    version: int
    cipher_suite: int
    extension_types: tuple[int, ...]
    fragment_code: int | None


class _HandshakeLayer:
    """The handshake messages of one channel, reassembled per direction.

    RFC 5246 §6.2.1 lets one message span several records and one record
    carry several messages, so a record boundary says nothing about a
    message boundary: bytes are held per direction until the message
    their first four announce is whole. The layer also keeps what the
    channel's hellos said, so a ServerHello is judged against the
    ClientHello it answers, the server's Certificate is tied to the name
    the client asked for, and a ServerKeyExchange is read as ECDHE only
    when the chosen suite is one.
    """

    def __init__(self) -> None:
        self._pending: dict[str, _PendingMessage] = {}
        self._client_hello: _ClientHello | None = None
        self._client_direction = ""
        self._server_hello: _ServerHello | None = None

    def reset(self) -> None:
        self._pending.clear()
        self._client_hello = None
        self._client_direction = ""
        self._server_hello = None

    def held(self, direction: str) -> int:
        pending = self._pending.get(direction)
        return len(pending.data) if pending is not None else 0

    def directions(self) -> list[str]:
        """Directions holding part of a message."""
        return [direction for direction, pending in self._pending.items() if len(pending.data) > 0]

    def feed(self, direction: str, body: bytes, segments: int) -> list[ChannelEvent]:
        """Take one handshake record's body; return the messages it completed."""
        pending = self._pending.setdefault(direction, _PendingMessage())
        data = bytes(body)
        if pending.skip > 0:
            step = min(pending.skip, len(data))
            pending.skip -= step
            data = data[step:]
        if len(data) == 0:
            return []
        if len(pending.data) > 0:
            pending.records += 1
            pending.segments += segments
        else:
            pending.records = 1
            pending.segments = segments
        pending.data.extend(data)
        events: list[ChannelEvent] = []
        while len(pending.data) >= _TLS_HANDSHAKE_HEADER_LENGTH:
            length = int.from_bytes(pending.data[1:4], "big")
            total = _TLS_HANDSHAKE_HEADER_LENGTH + length
            if length > MAX_HANDSHAKE_MESSAGE_BYTES:
                events.append(self._continuing_event(direction, pending))
                taken = min(total, len(pending.data))
                del pending.data[:taken]
                pending.skip = total - taken
            elif len(pending.data) >= total:
                message = bytes(pending.data[:total])
                del pending.data[:total]
                events.append(
                    self._message_event(direction, message, pending.records, pending.segments)
                )
            else:
                break
            # A message that starts later in this record took no block of its own.
            pending.records = 1
            pending.segments = 1
        return events

    def drop(self, direction: str) -> list[ChannelEvent]:
        """Report the part of a message that will not complete, then forget it."""
        pending = self._pending.pop(direction, None)
        if pending is None or len(pending.data) == 0:
            return []
        return [self._continuing_event(direction, pending)]

    def _continuing_event(self, direction: str, pending: _PendingMessage) -> ChannelEvent:
        """A message whose bytes stop short, named with the length its header declares."""
        name = _handshake_display_name(pending.data[0])
        if len(pending.data) >= _TLS_HANDSHAKE_HEADER_LENGTH:
            length = int.from_bytes(pending.data[1:4], "big")
            summary = f"TLS Handshake: {name} ({length} byte(s))"
        else:
            length = 0
            summary = f"TLS Handshake: {name} (header cut short)"
        return ChannelEvent(
            direction=direction,
            layer=LAYER_TLS,
            kind=KIND_HANDSHAKE,
            summary=summary,
            byte_count=length,
            segments=max(1, pending.segments),
            records=max(1, pending.records),
            truncated=True,
            handshake_type=name,
        )

    def _message_event(self, direction: str, message: bytes, records: int, segments: int) -> ChannelEvent:
        handshake_type = message[0]
        body = message[_TLS_HANDSHAKE_HEADER_LENGTH:]
        name = _handshake_display_name(handshake_type)
        details: dict[str, Any] = {}
        if handshake_type == _TLS_HANDSHAKE_CLIENT_HELLO:
            details = self._client_hello_details(direction, body)
        elif handshake_type == _TLS_HANDSHAKE_SERVER_HELLO:
            details = self._server_hello_details(body)
        elif handshake_type == _TLS_HANDSHAKE_CERTIFICATE:
            details = self._certificate_details(direction, body)
        elif handshake_type == _TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
            details = self._server_key_exchange_details(body)
        summary = f"TLS Handshake: {name}"
        server_name = str(details.get("server_name", ""))
        if handshake_type == _TLS_HANDSHAKE_CLIENT_HELLO and len(server_name) > 0:
            summary += f" sni={server_name}"
        summary += f" ({len(body)} byte(s))"
        return ChannelEvent(
            direction=direction,
            layer=LAYER_TLS,
            kind=KIND_HANDSHAKE,
            summary=summary,
            byte_count=len(body),
            segments=segments,
            records=records,
            handshake_type=name,
            **details,
        )

    def _client_hello_details(self, direction: str, body: bytes) -> dict[str, Any]:
        hello = _parse_client_hello(body)
        if hello is None:
            return {"notes": (_unparsed_note("ClientHello"),)}
        self._client_hello = hello
        self._client_direction = direction
        self._server_hello = None
        return {
            "server_name": hello.server_name,
            "protocol_version": hello.version,
            "cipher_suites": hello.cipher_suites,
            "extension_types": hello.extension_types,
            "max_fragment_length": _fragment_bytes(hello.fragment_code),
            "notes": _client_hello_notes(hello),
        }

    def _server_hello_details(self, body: bytes) -> dict[str, Any]:
        hello = _parse_server_hello(body)
        if hello is None:
            return {"notes": (_unparsed_note("ServerHello"),)}
        self._server_hello = hello
        return {
            "protocol_version": hello.version,
            "cipher_suites": (hello.cipher_suite,),
            "extension_types": hello.extension_types,
            "max_fragment_length": _fragment_bytes(hello.fragment_code),
            "notes": _server_hello_notes(hello, self._client_hello),
        }

    def _certificate_details(self, direction: str, body: bytes) -> dict[str, Any]:
        details: dict[str, Any] = {}
        if self._client_hello is not None and direction != self._client_direction:
            details["server_name"] = self._client_hello.server_name
        if self._server_hello is not None and self._server_hello.version == _TLS_VERSION_1_3:
            return details
        certificates = _parse_certificate_list(body)
        if certificates is None:
            details["notes"] = (_unparsed_note("Certificate"),)
        else:
            details["certificates"] = certificates
        return details

    def _server_key_exchange_details(self, body: bytes) -> dict[str, Any]:
        suite = self._server_hello.cipher_suite if self._server_hello is not None else None
        parameters = _parse_ecdhe_server_key_exchange(body, suite)
        if parameters is None:
            return {}
        group, point_length, scheme = parameters
        return {
            "named_group": group,
            "signature_scheme": scheme,
            "notes": (
                HandshakeNote("key exchange", f"ECDHE {named_group_name(group)}, {point_length}-byte public key"),
                HandshakeNote("signature", signature_scheme_name(scheme)),
            ),
        }


class _Reader:
    """A cursor over a handshake body that raises ValueError rather than read past its end."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def take(self, count: int) -> bytes:
        end = self._offset + count
        if end > len(self._data):
            raise ValueError("handshake field runs past the end of its message")
        chunk = self._data[self._offset:end]
        self._offset = end
        return chunk

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big", signed=False)

    def vector(self, length_size: int) -> bytes:
        return self.take(self.number(length_size))


def _parse_extensions(reader: _Reader) -> tuple[tuple[int, bytes], ...]:
    """RFC 5246 §7.4.1.4: Extension extensions<0..2^16-1>, the last field of a hello."""
    if reader.remaining == 0:
        return ()
    block = _Reader(reader.vector(2))
    if reader.remaining != 0:
        raise ValueError("bytes follow the extensions")
    found: list[tuple[int, bytes]] = []
    while block.remaining > 0:
        extension_type = block.number(2)
        found.append((extension_type, block.vector(2)))
    return tuple(found)


def _two_byte_values(data: bytes) -> tuple[int, ...]:
    if len(data) % 2 != 0:
        raise ValueError("a list of two-byte values has an odd length")
    return tuple(int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2))


def _first_value(extensions: tuple[tuple[int, bytes], ...], extension_type: int) -> bytes | None:
    for found_type, value in extensions:
        if found_type == extension_type:
            return value
    return None


def _fragment_code(extensions: tuple[tuple[int, bytes], ...]) -> int | None:
    """RFC 6066 §4: one MaxFragmentLength byte; -1 when the extension carries anything else."""
    value = _first_value(extensions, _TLS_EXTENSION_MAX_FRAGMENT_LENGTH)
    if value is None:
        return None
    return value[0] if len(value) == 1 else -1


def _fragment_bytes(code: int | None) -> int:
    return TLS_MAX_FRAGMENT_LENGTHS.get(code, 0) if code is not None else 0


def _parse_client_hello(body: bytes) -> _ClientHello | None:
    """RFC 5246 §7.4.1.2, with the server_name and max_fragment_length of RFC 6066 §3 and §4."""
    reader = _Reader(body)
    try:
        version = reader.number(2)
        reader.take(32)
        reader.vector(1)
        cipher_suites = _two_byte_values(reader.vector(2))
        reader.vector(1)
        extensions = _parse_extensions(reader)
        versions_value = _first_value(extensions, _TLS_EXTENSION_SUPPORTED_VERSIONS)
        # RFC 8446 §4.2.1: a ClientHello lists ProtocolVersion versions<2..254>.
        supported_versions = (
            _two_byte_values(_Reader(versions_value).vector(1)) if versions_value is not None else ()
        )
    except ValueError:
        return None
    name_value = _first_value(extensions, _TLS_EXTENSION_SERVER_NAME)
    return _ClientHello(
        version=version,
        cipher_suites=cipher_suites,
        extension_types=tuple(extension_type for extension_type, _ in extensions),
        server_name=_decode_server_name_extension(name_value) if name_value is not None else "",
        fragment_code=_fragment_code(extensions),
        supported_versions=supported_versions,
    )


def _parse_server_hello(body: bytes) -> _ServerHello | None:
    """RFC 5246 §7.4.1.3; a supported_versions answer (RFC 8446 §4.2.1) names the version chosen."""
    reader = _Reader(body)
    try:
        version = reader.number(2)
        reader.take(32)
        reader.vector(1)
        cipher_suite = reader.number(2)
        reader.number(1)
        extensions = _parse_extensions(reader)
    except ValueError:
        return None
    selected = _first_value(extensions, _TLS_EXTENSION_SUPPORTED_VERSIONS)
    if selected is not None:
        if len(selected) != 2:
            return None
        version = int.from_bytes(selected, "big")
    return _ServerHello(
        version=version,
        cipher_suite=cipher_suite,
        extension_types=tuple(extension_type for extension_type, _ in extensions),
        fragment_code=_fragment_code(extensions),
    )


def _parse_certificate_list(body: bytes) -> tuple[bytes, ...] | None:
    """RFC 5246 §7.4.2: ASN.1Cert certificate_list<0..2^24-1>, each ASN.1Cert<1..2^24-1>."""
    reader = _Reader(body)
    try:
        listing = _Reader(reader.vector(3))
        if reader.remaining != 0:
            return None
        certificates: list[bytes] = []
        while listing.remaining > 0:
            certificate = listing.vector(3)
            if len(certificate) == 0:
                return None
            certificates.append(certificate)
    except ValueError:
        return None
    return tuple(certificates)


def _parse_ecdhe_server_key_exchange(body: bytes, cipher_suite: int | None) -> tuple[int, int, int] | None:
    """RFC 8422 §5.4 ServerECDHParams, then the RFC 5246 §4.7 DigitallySigned over them.

    Read only when the chosen suite is ECDHE. With no ServerHello seen the
    parameters have to parse to the last byte and name a known group,
    because a DHE or PSK ServerKeyExchange has another layout.
    """
    if cipher_suite is not None and "_ECDHE_" not in cipher_suite_name(cipher_suite):
        return None
    reader = _Reader(body)
    try:
        if reader.number(1) != _EC_CURVE_TYPE_NAMED_CURVE:
            return None
        group = reader.number(2)
        point = reader.vector(1)
        scheme = reader.number(2)
        reader.vector(2)
    except ValueError:
        return None
    if len(point) == 0 or reader.remaining != 0:
        return None
    if cipher_suite is None and group not in TLS_NAMED_GROUPS:
        return None
    return group, len(point), scheme


def _unparsed_note(message: str) -> HandshakeNote:
    # Neutral, not a finding: a layout this reader does not know is likelier than a broken peer.
    return HandshakeNote("structure", f"does not parse as a {message}; its fields are not shown")


def _names(values: tuple[int, ...], namer: Any) -> str:
    return ", ".join(namer(value) for value in values) or "(none)"


def _fragment_text(code: int) -> str:
    size = TLS_MAX_FRAGMENT_LENGTHS.get(code)
    if size is None:
        return "malformed" if code < 0 else f"invalid value {code}"
    return f"2^{size.bit_length() - 1} ({size} bytes)"


def _client_hello_notes(hello: _ClientHello) -> tuple[HandshakeNote, ...]:
    versions = hello.supported_versions if len(hello.supported_versions) > 0 else (hello.version,)
    notes = [
        HandshakeNote("version", _names(versions, protocol_version_name)),
        HandshakeNote("cipher suites", _names(hello.cipher_suites, cipher_suite_name)),
    ]
    if hello.fragment_code is not None:
        # RFC 6066 §4: a server answers a value outside 2^9..2^12 with illegal_parameter.
        tone = "" if hello.fragment_code in TLS_MAX_FRAGMENT_LENGTHS else "fail"
        notes.append(HandshakeNote("max_fragment_length", _fragment_text(hello.fragment_code), tone))
    notes.append(HandshakeNote("extensions", _names(hello.extension_types, extension_type_name)))
    return tuple(notes)


def _server_hello_notes(hello: _ServerHello, client: _ClientHello | None) -> tuple[HandshakeNote, ...]:
    notes = [HandshakeNote("version", protocol_version_name(hello.version))]
    suite = cipher_suite_name(hello.cipher_suite)
    if client is not None and hello.cipher_suite not in client.cipher_suites:
        # RFC 5246 §7.4.1.3: the suite is chosen from ClientHello.cipher_suites.
        notes.append(HandshakeNote("cipher suite", f"{suite}, not one the ClientHello offered", "fail"))
    elif "_WITH_NULL_" in suite:
        notes.append(HandshakeNote("cipher suite", f"{suite}: NULL cipher, records travel unencrypted", "warn"))
    else:
        notes.append(HandshakeNote("cipher suite", suite))
    fragment = _fragment_answer(hello, client)
    if fragment is not None:
        notes.append(fragment)
    notes.append(_server_extensions_note(hello, client))
    return tuple(notes)


def _fragment_answer(hello: _ServerHello, client: _ClientHello | None) -> HandshakeNote | None:
    """RFC 6066 §4: a server that accepts echoes the value asked for; without it fragments run to 2^14."""
    requested = client.fragment_code if client is not None else None
    echoed = hello.fragment_code
    if client is None:
        return HandshakeNote("max_fragment_length", _fragment_text(echoed)) if echoed is not None else None
    if requested is None and echoed is None:
        return None
    if echoed is None:
        return HandshakeNote(
            "max_fragment_length",
            f"{_fragment_text(requested)} requested, not accepted: fragments run to 2^14 bytes",
            "warn",
        )
    if requested is None:
        return HandshakeNote("max_fragment_length", f"{_fragment_text(echoed)}, never requested", "fail")
    if echoed != requested:
        # RFC 6066 §4: the client MUST then abort with illegal_parameter.
        return HandshakeNote(
            "max_fragment_length",
            f"{_fragment_text(echoed)}, but {_fragment_text(requested)} was requested",
            "fail",
        )
    return HandshakeNote("max_fragment_length", f"{_fragment_text(echoed)}, as requested", "ok")


def _server_extensions_note(hello: _ServerHello, client: _ClientHello | None) -> HandshakeNote:
    names = _names(hello.extension_types, extension_type_name)
    if client is None:
        return HandshakeNote("extensions", names)
    solicited = set(client.extension_types)
    if _TLS_EMPTY_RENEGOTIATION_INFO_SCSV in client.cipher_suites:
        # RFC 5746 §3.6: the SCSV asks for renegotiation_info as the extension would.
        solicited.add(_TLS_EXTENSION_RENEGOTIATION_INFO)
    unsolicited = tuple(extension_type for extension_type in hello.extension_types if extension_type not in solicited)
    if len(unsolicited) == 0:
        return HandshakeNote("extensions", names)
    # RFC 5246 §7.4.1.4: the client MUST abort with unsupported_extension.
    return HandshakeNote(
        "extensions",
        f"{names}; not in the ClientHello: {_names(unsolicited, extension_type_name)}",
        "fail",
    )


def _decode_server_name_extension(extension_value: bytes) -> str:
    if len(extension_value) < 5:
        return ""
    list_length = int.from_bytes(extension_value[0:2], "big", signed=False)
    list_end = 2 + list_length
    if list_end > len(extension_value):
        return ""
    cursor = 2
    while cursor + 3 <= list_end:
        name_type = int(extension_value[cursor])
        name_length = int.from_bytes(extension_value[cursor + 1:cursor + 3], "big", signed=False)
        cursor += 3
        name_end = cursor + name_length
        if name_end > list_end:
            return ""
        if name_type == 0x00:
            try:
                decoded_name = extension_value[cursor:name_end].decode("ascii")
            except UnicodeDecodeError:
                return ""
            return decoded_name.strip().strip(".").lower()
        cursor = name_end
    return ""


def _dns_header_is_plausible(flags: int, question_count: int) -> bool:
    """True when a 12-byte DNS header (RFC 1035 §4.1.1) is self-consistent.

    A BIP channel carrying TLS hands this decoder record fragments that
    have no framing of their own, so the header fields have to carry the
    discrimination: OPCODE is 0 to 2, the Z field is reserved and must be
    zero, and a message always asks at least one question.
    """
    if ((flags >> 11) & 0x0F) > 2:
        return False
    if ((flags >> 4) & 0x07) != 0:
        return False
    return 1 <= question_count <= _MAX_DNS_QUESTION_COUNT


def _decode_dns_name(value_bytes: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(value_bytes):
        raise ValueError("DNS name offset is out of bounds.")
    labels: list[str] = []
    current_offset = offset
    next_offset = offset
    jumped = False
    visited_offsets: set[int] = set()
    while current_offset < len(value_bytes):
        length_value = value_bytes[current_offset]
        if length_value == 0:
            current_offset += 1
            if jumped is False:
                next_offset = current_offset
            return ".".join(labels), next_offset
        if (length_value & 0xC0) == 0xC0:
            if current_offset + 1 >= len(value_bytes):
                raise ValueError("DNS compression pointer is truncated.")
            pointer_offset = ((length_value & 0x3F) << 8) | value_bytes[current_offset + 1]
            if pointer_offset in visited_offsets:
                raise ValueError("DNS compression pointer loop detected.")
            if pointer_offset >= len(value_bytes):
                raise ValueError("DNS compression pointer is out of bounds.")
            if jumped is False:
                next_offset = current_offset + 2
            visited_offsets.add(pointer_offset)
            current_offset = pointer_offset
            jumped = True
            continue
        if (length_value & 0xC0) != 0:
            raise ValueError("Unsupported DNS label encoding.")
        current_offset += 1
        label_end = current_offset + length_value
        if label_end > len(value_bytes):
            raise ValueError("DNS label exceeds payload length.")
        labels.append(value_bytes[current_offset:label_end].decode("ascii"))
        current_offset = label_end
    raise ValueError("DNS name did not terminate.")


def _parse_dns_question(value_bytes: bytes, offset: int) -> tuple[dict[str, Any], int]:
    qname_value, cursor = _decode_dns_name(value_bytes, offset)
    if cursor + 4 > len(value_bytes):
        raise ValueError("DNS question is truncated.")
    return {
        "qname": qname_value,
        "query_type": int.from_bytes(value_bytes[cursor:cursor + 2], "big", signed=False),
        "query_class": int.from_bytes(value_bytes[cursor + 2:cursor + 4], "big", signed=False),
    }, cursor + 4


def _parse_dns_resource_record(value_bytes: bytes, offset: int) -> tuple[dict[str, Any], int]:
    record_name, cursor = _decode_dns_name(value_bytes, offset)
    if cursor + 10 > len(value_bytes):
        raise ValueError("DNS resource record header is truncated.")
    record_type = int.from_bytes(value_bytes[cursor:cursor + 2], "big", signed=False)
    record_class = int.from_bytes(value_bytes[cursor + 2:cursor + 4], "big", signed=False)
    ttl_value = int.from_bytes(value_bytes[cursor + 4:cursor + 8], "big", signed=False)
    record_length = int.from_bytes(value_bytes[cursor + 8:cursor + 10], "big", signed=False)
    record_data_offset = cursor + 10
    record_data_end = record_data_offset + record_length
    if record_data_end > len(value_bytes):
        raise ValueError("DNS resource record data is truncated.")
    record_data = value_bytes[record_data_offset:record_data_end]
    record_value = record_data.hex().upper()
    if record_type == 0x0001 and len(record_data) == 4:
        record_value = ".".join(str(octet) for octet in record_data)
    elif record_type == 0x001C and len(record_data) == 16:
        record_value = str(ipaddress.IPv6Address(record_data))
    elif record_type == 0x0005:
        record_value, _ = _decode_dns_name(value_bytes, record_data_offset)
    return {
        "name": record_name,
        "record_type": record_type,
        "record_class": record_class,
        "ttl_seconds": ttl_value,
        "value": record_value,
    }, record_data_end


def _decode_dns_query(value_bytes: bytes, direction: str) -> ChannelEvent | None:
    if len(value_bytes) < 17:
        return None
    flags = int.from_bytes(value_bytes[2:4], "big", signed=False)
    if (flags & 0x8000) != 0:
        return None
    question_count = int.from_bytes(value_bytes[4:6], "big", signed=False)
    answer_count = int.from_bytes(value_bytes[6:8], "big", signed=False)
    authority_count = int.from_bytes(value_bytes[8:10], "big", signed=False)
    if question_count != 1 or answer_count != 0 or authority_count != 0:
        return None
    if not _dns_header_is_plausible(flags, question_count):
        return None
    try:
        question, _ = _parse_dns_question(value_bytes, 12)
    except (ValueError, IndexError, UnicodeDecodeError):
        return None
    query_name = str(question.get("qname", "")).strip()
    if len(query_name) == 0:
        return None
    query_type = int(question.get("query_type", 0) or 0)
    query_class = int(question.get("query_class", 0) or 0)
    type_name = _DNS_QUERY_TYPES.get(query_type, f"0x{query_type:04X}")
    class_name = _DNS_CLASSES.get(query_class, f"0x{query_class:04X}")
    query_id = int.from_bytes(value_bytes[0:2], "big", signed=False)
    return ChannelEvent(
        direction=direction,
        layer=LAYER_DNS,
        kind=KIND_QUERY,
        summary=(
            f"DNS Query: id=0x{query_id:04X} "
            f"qname={query_name} type={type_name} class={class_name}"
        ),
        byte_count=len(value_bytes),
        query_name=query_name,
    )


def _decode_dns_response(value_bytes: bytes, direction: str) -> ChannelEvent | None:
    if len(value_bytes) < 12:
        return None
    flags = int.from_bytes(value_bytes[2:4], "big", signed=False)
    if (flags & 0x8000) == 0:
        return None
    question_count = int.from_bytes(value_bytes[4:6], "big", signed=False)
    answer_count = int.from_bytes(value_bytes[6:8], "big", signed=False)
    authority_count = int.from_bytes(value_bytes[8:10], "big", signed=False)
    additional_count = int.from_bytes(value_bytes[10:12], "big", signed=False)
    if not _dns_header_is_plausible(flags, question_count):
        return None
    if max(answer_count, authority_count, additional_count) > _MAX_DNS_RECORD_COUNT:
        return None
    question_name = ""
    answer_summaries: list[str] = []
    # A question that does not parse means these bytes were never a DNS
    # message; reporting the header anyway invents a response out of
    # whatever the channel happened to carry.
    try:
        offset = 12
        for question_index in range(question_count):
            question, offset = _parse_dns_question(value_bytes, offset)
            if question_index == 0:
                question_name = str(question.get("qname", "")).strip()
    except (ValueError, IndexError, UnicodeDecodeError):
        return None
    if len(question_name) == 0:
        return None
    try:
        for _ in range(min(answer_count, 6)):
            answer_record, offset = _parse_dns_resource_record(value_bytes, offset)
            record_type_name = _DNS_RECORD_TYPES.get(
                int(answer_record.get("record_type", 0) or 0),
                f"0x{int(answer_record.get('record_type', 0) or 0):04X}",
            )
            record_value = str(answer_record.get("value", "")).strip()
            if len(record_value) == 0:
                continue
            answer_summaries.append(f"{record_type_name}:{record_value}")
    except (ValueError, IndexError, UnicodeDecodeError):
        answer_summaries = []
    query_id = int.from_bytes(value_bytes[0:2], "big", signed=False)
    response_code = flags & 0x000F
    summary_text = f"DNS Response: id=0x{query_id:04X} qname={question_name}"
    summary_text += (
        f" qd={question_count} an={answer_count} "
        f"ns={authority_count} ar={additional_count} rcode={response_code}"
    )
    if len(answer_summaries) > 0:
        summary_text += f" answers={','.join(answer_summaries)}"
    return ChannelEvent(
        direction=direction,
        layer=LAYER_DNS,
        kind=KIND_RESPONSE,
        summary=summary_text,
        byte_count=len(value_bytes),
        query_name=question_name,
        answers=tuple(answer_summaries),
    )


def dns_query_summary(payload: bytes) -> str:
    """Return the DNS query trace line for *payload*, or an empty string.

    Callers that only need to know whether a block is a DNS question --
    the SEND DATA path lengthens its receive timeout for one -- ask here
    rather than keeping a second copy of the header checks.
    """
    event = _decode_dns_query(bytes(payload or b""), "")
    if event is None:
        return ""
    return event.summary
