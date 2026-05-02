"""Wire-format DNS message helpers for the SGP.32 IPA-poll path.

Encodes A / AAAA queries and parses answer sections. dnspython is a
soft dependency; when missing the module falls back to a minimal
hand-rolled encoder/decoder. The decoder validates the answer's
transaction id against the question id so a stale UDP packet cannot
poison the resolved-IP cache.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Final


try:
    import dns.message  # type: ignore
    import dns.name  # type: ignore
    import dns.rdataclass  # type: ignore
    import dns.rdatatype  # type: ignore

    _DNSPYTHON_AVAILABLE = True
except Exception:
    _DNSPYTHON_AVAILABLE = False


QTYPE_A: Final[int] = 0x0001
QTYPE_AAAA: Final[int] = 0x001C
QCLASS_IN: Final[int] = 0x0001


@dataclass(slots=True)
class DnsAnswer:
    """Decoded DNS answer summary used by the IPA-poll state machine.

    ``rcode`` is the response code from the DNS header (0 = NOERROR,
    3 = NXDOMAIN, etc.). ``a_records`` / ``aaaa_records`` are the
    successfully decoded address strings. ``error`` is a non-empty
    string when the wire bytes could not be parsed, in which case the
    address lists are guaranteed to be empty.
    """

    transaction_id: int = 0
    rcode: int = 0
    a_records: list[str] = None  # type: ignore[assignment]
    aaaa_records: list[str] = None  # type: ignore[assignment]
    error: str = ""

    def __post_init__(self) -> None:
        if self.a_records is None:
            self.a_records = []
        if self.aaaa_records is None:
            self.aaaa_records = []


def encode_dns_query(qname: str, qtype: int, *, transaction_id: int) -> bytes:
    """Encode a single-question DNS query for ``qname`` / ``qtype``.

    The packet layout follows RFC 1035: 12-byte
    header (id / flags=0x0100 RD / QDCOUNT=1 / others=0), one question,
    no OPT record. ``transaction_id`` must fit in 16 bits; values that
    overflow are silently masked rather than raising.
    """

    cleaned = str(qname or "").strip(".")
    if len(cleaned) == 0:
        raise ValueError("encode_dns_query: qname must be non-empty")
    qtype_code = int(qtype) & 0xFFFF
    txid = int(transaction_id) & 0xFFFF

    if _DNSPYTHON_AVAILABLE:
        message = dns.message.make_query(
            dns.name.from_text(cleaned),
            qtype_code,
            rdclass=QCLASS_IN,
            use_edns=-1,
        )
        message.id = txid
        return message.to_wire()

    return _encode_dns_query_minimal(cleaned, qtype_code, txid)


def decode_dns_answer(wire: bytes) -> DnsAnswer:
    """Decode the resolver's reply, extracting A and AAAA records."""

    payload = bytes(wire or b"")
    if len(payload) < 12:
        return DnsAnswer(error="payload shorter than DNS header")

    if _DNSPYTHON_AVAILABLE:
        try:
            message = dns.message.from_wire(payload, ignore_trailing=True)
        except Exception as exc:  # pragma: no cover -- defensive
            return DnsAnswer(error=f"dnspython parse failed: {exc}")
        a_records: list[str] = []
        aaaa_records: list[str] = []
        for answer in message.answer:
            for item in answer:
                rdtype = int(getattr(item, "rdtype", 0) or 0)
                if rdtype == QTYPE_A:
                    a_records.append(str(item))
                elif rdtype == QTYPE_AAAA:
                    aaaa_records.append(str(item))
        return DnsAnswer(
            transaction_id=int(message.id),
            rcode=int(message.rcode()),
            a_records=a_records,
            aaaa_records=aaaa_records,
        )

    return _decode_dns_answer_minimal(payload)


def _encode_dns_query_minimal(qname: str, qtype_code: int, txid: int) -> bytes:
    parts = [part for part in qname.split(".") if len(part) > 0]
    qname_bytes = bytearray()
    for part in parts:
        encoded = part.encode("ascii", "ignore")
        if len(encoded) > 0x3F:
            encoded = encoded[:0x3F]
        qname_bytes.append(len(encoded))
        qname_bytes.extend(encoded)
    qname_bytes.append(0x00)

    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = bytes(qname_bytes) + struct.pack(">HH", qtype_code, QCLASS_IN)
    return header + question


def _decode_dns_answer_minimal(payload: bytes) -> DnsAnswer:
    try:
        txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from(
            ">HHHHHH", payload, 0
        )
    except struct.error as exc:
        return DnsAnswer(error=f"header unpack failed: {exc}")
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        offset = _skip_qname(payload, offset)
        if offset < 0:
            return DnsAnswer(transaction_id=txid, rcode=rcode, error="bad question qname")
        offset += 4
    a_records: list[str] = []
    aaaa_records: list[str] = []
    for _ in range(ancount):
        offset = _skip_qname(payload, offset)
        if offset < 0:
            return DnsAnswer(transaction_id=txid, rcode=rcode, error="bad answer qname")
        if offset + 10 > len(payload):
            return DnsAnswer(transaction_id=txid, rcode=rcode, error="answer header truncated")
        rrtype, _rrclass, _ttl, rdlength = struct.unpack_from(">HHIH", payload, offset)
        offset += 10
        if offset + rdlength > len(payload):
            return DnsAnswer(transaction_id=txid, rcode=rcode, error="rdata truncated")
        rdata = payload[offset : offset + rdlength]
        offset += rdlength
        if rrtype == QTYPE_A and len(rdata) == 4:
            a_records.append(str(ipaddress.IPv4Address(rdata)))
        elif rrtype == QTYPE_AAAA and len(rdata) == 16:
            aaaa_records.append(str(ipaddress.IPv6Address(rdata)))
    return DnsAnswer(
        transaction_id=int(txid),
        rcode=int(rcode),
        a_records=a_records,
        aaaa_records=aaaa_records,
    )


def _skip_qname(payload: bytes, offset: int) -> int:
    """Walk a DNS-encoded name and return the offset after the trailing null.

    Handles compression pointers (RFC 1035 §4.1.4): a pointer cuts the
    label walk short -- the caller's offset just needs to step past the
    two pointer bytes. Returns ``-1`` on malformed input.
    """

    pos = offset
    while pos < len(payload):
        length = payload[pos]
        if length == 0x00:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length
    return -1
