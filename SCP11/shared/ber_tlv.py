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
