# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Small, strict BER-TLV reader shared by SCP11 eIM package surfaces."""

from __future__ import annotations


def read_ber_tlv(
    data: bytes,
    offset: int = 0,
) -> tuple[bytes, bytes, bytes, int]:
    """Read one definite-length BER-TLV.

    Indefinite and non-minimal length forms are rejected. The function
    never reads beyond *data* and returns ``(tag, value, raw, next_offset)``.
    """

    raw = bytes(data or b"")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("TLV offset must be an integer.")
    if offset < 0 or offset >= len(raw):
        raise ValueError("TLV offset out of range.")

    tag_start = offset
    first_tag_octet = raw[offset]
    offset += 1
    if first_tag_octet & 0x1F == 0x1F:
        if offset >= len(raw):
            raise ValueError("Truncated multi-byte tag.")
        first_continuation = raw[offset]
        if first_continuation & 0x7F == 0:
            raise ValueError("Non-minimal multi-byte tag.")
        while offset < len(raw):
            current = raw[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            raise ValueError("Truncated multi-byte tag.")
    tag_bytes = raw[tag_start:offset]

    if offset >= len(raw):
        raise ValueError("Missing TLV length.")
    first_length_octet = raw[offset]
    offset += 1
    if first_length_octet < 0x80:
        length = first_length_octet
    else:
        length_octet_count = first_length_octet & 0x7F
        if length_octet_count == 0:
            raise ValueError("Indefinite TLV lengths are not supported.")
        if length_octet_count == 0x7F:
            # X.690 clause 8.1.3.5 c) reserves the initial octet 0xFF.
            raise ValueError("Reserved TLV length octet 0xFF.")
        if offset + length_octet_count > len(raw):
            raise ValueError("Truncated TLV length.")
        length_octets = raw[offset : offset + length_octet_count]
        if length_octets[0] == 0:
            raise ValueError("Non-minimal long-form TLV length.")
        length = int.from_bytes(length_octets, "big", signed=False)
        if length < 0x80:
            raise ValueError("Non-minimal long-form TLV length.")
        offset += length_octet_count

    value_start = offset
    value_end = value_start + length
    if value_end > len(raw):
        raise ValueError("TLV value overruns input.")
    return (
        tag_bytes,
        raw[value_start:value_end],
        raw[tag_start:value_end],
        value_end,
    )


def read_single_ber_tlv(data: bytes) -> tuple[bytes, bytes, bytes]:
    """Read one BER-TLV and require it to consume the complete input."""

    raw = bytes(data or b"")
    tag, value, raw_tlv, next_offset = read_ber_tlv(raw, 0)
    if next_offset != len(raw):
        raise ValueError("Trailing bytes after root TLV.")
    return tag, value, raw_tlv


def validate_ber_tlv_tree(
    data: bytes,
    *,
    max_depth: int = 64,
    max_nodes: int = 100_000,
) -> None:
    """Validate every constructed TLV in a complete BER value.

    The depth and node limits make the check deterministic for untrusted eIM
    responses while still allowing realistic profile-management packages.
    """

    raw = bytes(data or b"")
    if not raw:
        raise ValueError("BER input must not be empty.")
    stack: list[tuple[bytes, int, int]] = [(raw, 0, 0)]
    node_count = 0
    while stack:
        current, offset, depth = stack.pop()
        while offset < len(current):
            tag, value, _raw_tlv, next_offset = read_ber_tlv(current, offset)
            node_count += 1
            if node_count > max_nodes:
                raise ValueError("BER tree exceeds the node limit.")
            if tag[0] & 0x20 and value:
                if depth >= max_depth:
                    raise ValueError("BER tree exceeds the nesting-depth limit.")
                stack.append((value, 0, depth + 1))
            offset = next_offset


def decode_object_identifier(value: bytes) -> str:
    """Decode OBJECT IDENTIFIER contents octets into dotted notation.

    ITU-T X.690 (02/2021) clause 8.19.2 lists the subidentifiers in base 128
    with bit 8 as the continuation flag and forbids a leading ``0x80`` octet;
    clause 8.19.4 folds the first two components into one subidentifier as
    ``X * 40 + Y``, which for the arc 2 may exceed a single octet.
    """

    raw = bytes(value or b"")
    if len(raw) == 0:
        raise ValueError("OBJECT IDENTIFIER contents must not be empty.")
    subidentifiers: list[int] = []
    current = 0
    in_progress = False
    for octet in raw:
        if in_progress is False and octet == 0x80:
            raise ValueError("Non-minimal OBJECT IDENTIFIER subidentifier.")
        in_progress = True
        current = (current << 7) | (octet & 0x7F)
        if octet & 0x80 == 0:
            subidentifiers.append(current)
            current = 0
            in_progress = False
    if in_progress:
        raise ValueError("Truncated OBJECT IDENTIFIER subidentifier.")
    first = subidentifiers[0]
    if first < 40:
        components = [0, first]
    elif first < 80:
        components = [1, first - 40]
    else:
        components = [2, first - 80]
    components.extend(subidentifiers[1:])
    return ".".join(str(component) for component in components)


def encode_ber_length(length: int) -> bytes:
    """Encode a definite length in the minimal short or long form."""

    if length < 0:
        raise ValueError("BER length must not be negative.")
    if length < 0x80:
        return bytes([length])
    octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def retag_sequence(tag: bytes, der: bytes) -> bytes:
    """Carry a DER SEQUENCE under an IMPLICIT context tag.

    The implicit tag replaces the SEQUENCE's own tag octet; the length and
    contents octets are kept. This is how the official SGP.32 v1.3 module
    encodes ``eimPublicKeyData [5] CHOICE { eimPublicKey SubjectPublicKeyInfo,
    eimCertificate Certificate }``: ``A5 { A0 <SubjectPublicKeyInfo contents> }``
    or ``A5 { A1 <Certificate contents> }``, never the SEQUENCE header itself.
    """

    raw = bytes(der or b"")
    inner_tag, contents, _raw_tlv, end = read_ber_tlv(raw, 0)
    if inner_tag != b"\x30" or end != len(raw):
        raise ValueError("Expected exactly one DER SEQUENCE.")
    return bytes(tag) + encode_ber_length(len(contents)) + contents


def restore_sequence(contents: bytes) -> bytes:
    """Rebuild the DER SEQUENCE whose contents travelled under an implicit tag."""

    raw = bytes(contents or b"")
    return b"\x30" + encode_ber_length(len(raw)) + raw
