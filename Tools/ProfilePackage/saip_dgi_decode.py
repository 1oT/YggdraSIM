# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""DGI (Data Grouping Identifier) decoder for SAIP / GlobalPlatform.

A SAIP ``securityDomain`` PE carries personalization payloads under
``sdPersoData``. Each entry in that ``SEQUENCE OF OCTET STRING`` is a
DGI block formatted as::

    DGI(2 bytes)  L(1 byte, or 0xFF + 2 bytes BE)  V(L bytes)

where the value V is itself a TLV stream — typically the simple
1-byte-tag / 1-byte-length encoding used for SCP80 connectivity
parameters (3GPP TS 31.111 §6.6, ETSI TS 102 226 §8) wrapped inside
GlobalPlatform Amendment A "Confidential Card Content Management"
DGI containers.

This module owns the envelope walker and the connectivity / STK leaf
decoders. ``decode_dgi_records(value)`` returns a list of
``{"record", "format", "items"}`` dicts mirroring the historical
shell ``INFO`` rendering, so call-sites that already render that shape
(SAIP shell ``INFO``, transcode-TUI Decoded pane, diff-TUI Decoded
pane) all use the same structure.

References:

* GlobalPlatform Card Specification v2.3 §11.11 (STORE DATA, DGI
  encoding).
* GlobalPlatform Amendment A v1.2 §4.5 (DGI containers used during
  ISD-P / SD personalization).
* 3GPP TS 31.111 §6.6 (CAT bearer description / transport-level /
  other-address tag encodings used inside connectivity DGIs).
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable


_HEX_DIGITS: frozenset[str] = frozenset("0123456789ABCDEFabcdef")


# Top-level connectivity tags found inside SCP80 transport DGIs
# (TS 31.111 §8.13 / ETSI TS 102 226 §8.2). These are the names the
# historical shell decoder used; keeping them verbatim preserves the
# diff against existing ``INFO`` golden outputs.
DEFAULT_TOP_LEVEL_TAG_NAMES: dict[str, str] = {
    "84": "Transport Parameters",
    "85": "Security / Address Container",
    "86": "Security Parameters",
    "89": "Remote Endpoint",
    "8A": "Host / Address",
    "8B": "Remote Identifier",
    "8C": "Remote Path",
}


DEFAULT_NESTED_TAG_NAMES: dict[str, dict[str, str]] = {
    "85": {
        "84": "Transport Parameters",
        "85": "Remote Identifier Block",
        "86": "Security Parameters",
        "89": "Remote Endpoint",
    },
    "84": {
        "01": "Parameter 01",
        "02": "Parameter 02",
        "35": "Bearer Description",
        "39": "Buffer Size",
        "3C": "Transport Level",
        "3E": "Other Address",
    },
    "86": {
        "00": "Parameter 00",
        "20": "Parameter 20",
    },
    "89": {
        "8A": "Host / Address",
        "8B": "Remote Identifier",
        "8C": "Remote Path",
    },
}


# Common GlobalPlatform Amendment A DGI codes seen in SAIP profile
# personalization. The tag list is intentionally short — anything not
# in this map renders as a bare DGI hex with no name annotation,
# which is how operators expect the output to read for vendor-private
# DGIs.
DEFAULT_DGI_NAMES: dict[str, str] = {
    "0070": "Card Recognition Data / IIN",
    "0080": "File Identifier",
    "00A6": "DAP block",
    "00CE": "DAP signature",
    "8010": "Symmetric key set",
    "9000": "Personalisation parameter",
    "9201": "Card Recognition Parameters",
    "9202": "Operator Parameters",
    "B080": "Master File / OS parameters",
}


def _is_hex_string(text: str) -> bool:
    if len(text) == 0 or (len(text) % 2) != 0:
        return False
    for character in text:
        if character not in _HEX_DIGITS:
            return False
    return True


def value_to_bytes(value: Any) -> bytes | None:
    """Coerce ``value`` to ``bytes`` if it parses cleanly.

    Accepts ``bytes``, ``bytearray``, non-negative ``int``, and
    even-length hex ``str``. Returns ``None`` for anything else (incl.
    booleans, negative ints, odd-length / non-hex strings).
    """
    if isinstance(value, (bytes, bytearray)) is True:
        return bytes(value)
    if isinstance(value, bool) is True:
        return None
    if isinstance(value, int) is True:
        if value < 0:
            return None
        length = max(1, (int(value).bit_length() + 7) // 8)
        return int(value).to_bytes(length, "big", signed=False)
    if isinstance(value, str) is True:
        compact = value.strip()
        if _is_hex_string(compact) is False:
            return None
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return None
    return None


def value_to_hex_strings(value: Any) -> list[str]:
    """Flatten ``value`` to a list of compact hex strings.

    Accepts a single hex string, raw bytes, or a (possibly nested)
    list of either. Tagged-bytes wrappers (``{"hex": "..."}``) are
    *not* unwrapped here — call sites that handle SAIP-shape
    documents need to convert those to plain strings beforehand.
    """
    if isinstance(value, str) is True:
        compact = value.strip()
        if _is_hex_string(compact) is True:
            return [compact]
        return []
    if isinstance(value, (bytes, bytearray)) is True:
        return [bytes(value).hex()]
    if isinstance(value, list) is True:
        out: list[str] = []
        for item in value:
            out.extend(value_to_hex_strings(item))
        return out
    return []


def decode_printable_ascii(value_bytes: bytes) -> str | None:
    """Return the ASCII rendering of ``value_bytes`` if every byte is printable."""
    if len(value_bytes) == 0:
        return None
    try:
        decoded = value_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None
    for character in decoded:
        if ord(character) < 0x20 or ord(character) > 0x7E:
            return None
    return decoded


def decode_network_access_name(value_bytes: bytes) -> str:
    """TS 31.111 §6.6.5 NAA: dot-joined length-prefixed labels."""
    if len(value_bytes) == 0:
        return "(empty)"
    labels: list[str] = []
    offset = 0
    while offset < len(value_bytes):
        label_length = value_bytes[offset]
        offset += 1
        if label_length == 0:
            break
        label_end = offset + label_length
        if label_end > len(value_bytes):
            return value_bytes.hex()
        label_bytes = value_bytes[offset:label_end]
        try:
            labels.append(label_bytes.decode("ascii"))
        except UnicodeDecodeError:
            return value_bytes.hex()
        offset = label_end
    if len(labels) == 0:
        return value_bytes.hex()
    return ".".join(labels)


def describe_bearer_description(value_bytes: bytes) -> dict[str, Any] | str:
    """TS 31.111 §6.6.5 Bearer Description (tag 35)."""
    if len(value_bytes) == 0:
        return "(empty)"
    bearer_type = value_bytes[0]
    bearer_names = {
        0x01: "CSD",
        0x02: "GPRS",
        0x03: "Default bearer",
        0x04: "Local link",
    }
    decoded: dict[str, Any] = {
        "type": f"0x{bearer_type:02X}",
        "typeName": bearer_names.get(bearer_type, "Unknown"),
    }
    if len(value_bytes) > 1:
        decoded["parameters"] = value_bytes[1:].hex()
    return decoded


def describe_transport_level(value_bytes: bytes) -> dict[str, Any] | str:
    """TS 31.111 §6.6.5 Transport Level (tag 3C): 1-byte protocol + 2-byte port."""
    if len(value_bytes) != 3:
        return value_bytes.hex()
    protocol_type = value_bytes[0]
    port_number = int.from_bytes(value_bytes[1:], "big", signed=False)
    protocol_names = {
        0x01: "UDP, remote connection",
        0x02: "TCP, remote connection",
        0x03: "TCP, local connection",
        0x04: "UDP, local connection",
    }
    return {
        "protocol": f"0x{protocol_type:02X}",
        "protocolName": protocol_names.get(protocol_type, "Unknown"),
        "port": port_number,
    }


def decode_other_address(value_bytes: bytes) -> dict[str, Any] | str:
    """TS 31.111 §6.6.5 Other Address (tag 3E): 1-byte type + IPv4/IPv6 body."""
    if len(value_bytes) < 2:
        return value_bytes.hex()
    address_type = value_bytes[0]
    address_value = value_bytes[1:]
    type_names = {
        0x21: "IPv4",
        0x57: "IPv6",
    }
    decoded: dict[str, Any] = {
        "type": f"0x{address_type:02X}",
        "typeName": type_names.get(address_type, "Unknown"),
    }
    try:
        if address_type == 0x21 and len(address_value) == 4:
            decoded["address"] = str(ipaddress.IPv4Address(address_value))
        elif address_type == 0x57 and len(address_value) == 16:
            decoded["address"] = str(ipaddress.IPv6Address(address_value))
        else:
            decoded["rawAddress"] = address_value.hex()
    except ipaddress.AddressValueError:
        decoded["rawAddress"] = address_value.hex()
    return decoded


def decode_stk_value(tag_value: int, value_bytes: bytes) -> Any:
    """Dispatch the connectivity / STK leaf tags handled inside DGI values.

    Tags 35 / 39 / 3C / 3E / 47 fall under this dispatcher; everything
    else returns ``None`` so the caller can recurse into the value as a
    nested simple-TLV stream instead.
    """
    if tag_value == 0x35:
        return describe_bearer_description(value_bytes)
    if tag_value == 0x39 and len(value_bytes) == 2:
        return int.from_bytes(value_bytes, "big", signed=False)
    if tag_value == 0x3C:
        return describe_transport_level(value_bytes)
    if tag_value == 0x3E:
        return decode_other_address(value_bytes)
    if tag_value == 0x47:
        return decode_network_access_name(value_bytes)
    return None


def decode_compact_binary_value(
    value_bytes: bytes,
) -> dict[str, Any] | None:
    """Render ≤4-byte values as ``{hex, decimal, bytes}`` triples."""
    if len(value_bytes) == 0:
        return {"hex": "", "empty": True}
    if len(value_bytes) > 4:
        return None
    return {
        "hex": value_bytes.hex(),
        "decimal": int.from_bytes(value_bytes, "big", signed=False),
        "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
    }


def decode_length_prefixed_identifier_block(
    value_bytes: bytes,
) -> dict[str, Any] | None:
    """Decode a 1-byte-prefix ASCII identifier block (used inside tag 85.85)."""
    if len(value_bytes) < 1:
        return None
    identifier_length = value_bytes[0]
    if identifier_length == 0 or 1 + identifier_length > len(value_bytes):
        return None
    identifier_bytes = value_bytes[1:1 + identifier_length]
    identifier_ascii = decode_printable_ascii(identifier_bytes)
    if identifier_ascii is None:
        return None
    decoded: dict[str, Any] = {
        "format": "Length-prefixed identifier block",
        "identifierLength": identifier_length,
        "identifierAscii": identifier_ascii,
    }
    trailer_bytes = value_bytes[1 + identifier_length:]
    if len(trailer_bytes) > 0:
        decoded["trailerHex"] = trailer_bytes.hex()
        decoded["trailerBytes"] = [
            f"0x{byte_value:02X}" for byte_value in trailer_bytes
        ]
    return decoded


_DEFAULT_NESTED_DECODER_MAPS: dict[str, dict[str, Callable[[bytes], Any]]] = {
    "85": {
        "85": decode_length_prefixed_identifier_block,
    },
    "84": {
        "01": decode_compact_binary_value,
        "02": decode_compact_binary_value,
    },
    "86": {
        "00": decode_compact_binary_value,
        "20": decode_compact_binary_value,
    },
}


def parse_simple_tlv_stream(data: bytes) -> list[tuple[int, bytes]] | None:
    """Parse a simple-TLV stream (1-byte tag, 1-byte length, value).

    Returns ``None`` if the stream does not parse cleanly so callers
    can fall back to a hex / ASCII rendering.
    """
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            return None
        tag_value = data[offset]
        length_value = data[offset + 1]
        offset += 2
        value_end = offset + length_value
        if value_end > len(data):
            return None
        items.append((tag_value, data[offset:value_end]))
        offset = value_end
    return items


def decode_simple_tlv_payload(
    data: bytes,
    *,
    tag_names: dict[str, str] | None = None,
    nested_tag_names: dict[str, dict[str, str]] | None = None,
    custom_decoder_map: dict[str, Callable[[bytes], Any]] | None = None,
    nested_decoder_maps: dict[str, dict[str, Callable[[bytes], Any]]] | None = None,
) -> Any:
    """Recursively decode a simple-TLV payload, threading the tag tables.

    Returns one of:

    * a ``list`` of ``{tag, length, raw, name?, decoded?, ascii?}``
      records when the buffer parses as one or more simple TLVs;
    * a ``{"ascii": ...}`` dict when the buffer is a printable ASCII
      string but does not parse as TLV;
    * the raw hex string otherwise.
    """
    items = parse_simple_tlv_stream(data)
    if items is None or len(items) == 0:
        ascii_value = decode_printable_ascii(data)
        if ascii_value is not None:
            return {"ascii": ascii_value}
        return data.hex()

    decoded_items: list[dict[str, Any]] = []
    for tag_value, value_bytes in items:
        tag_hex = f"{tag_value:02X}"
        item: dict[str, Any] = {
            "tag": tag_hex,
            "length": len(value_bytes),
            "raw": value_bytes.hex(),
        }
        if tag_names is not None and tag_hex in tag_names:
            item["name"] = tag_names[tag_hex]

        if tag_value in (0x35, 0x39, 0x3C, 0x3E, 0x47):
            description = decode_stk_value(tag_value, value_bytes)
            if description is not None:
                item["decoded"] = description
        else:
            if custom_decoder_map is not None:
                custom_decoder = custom_decoder_map.get(tag_hex)
                if custom_decoder is not None:
                    custom_decoded = custom_decoder(value_bytes)
                    if custom_decoded is not None:
                        item["decoded"] = custom_decoded
                        decoded_items.append(item)
                        continue
            child_tag_names = None
            if nested_tag_names is not None:
                child_tag_names = nested_tag_names.get(tag_hex)
            child_decoder_map = None
            if nested_decoder_maps is not None:
                child_decoder_map = nested_decoder_maps.get(tag_hex)
            nested = decode_simple_tlv_payload(
                value_bytes,
                tag_names=child_tag_names,
                nested_tag_names=nested_tag_names,
                custom_decoder_map=child_decoder_map,
                nested_decoder_maps=nested_decoder_maps,
            )
            if nested != value_bytes.hex():
                item["decoded"] = nested
            else:
                ascii_value = decode_printable_ascii(value_bytes)
                if ascii_value is not None:
                    item["ascii"] = ascii_value

        decoded_items.append(item)
    return decoded_items


def decode_dgi_stream(
    data: bytes,
    *,
    tag_names: dict[str, str] | None = None,
    nested_tag_names: dict[str, dict[str, str]] | None = None,
    nested_decoder_maps: dict[str, dict[str, Callable[[bytes], Any]]] | None = None,
    dgi_names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Walk a DGI stream and return one record per ``DGI || L || V`` block.

    ``tag_names`` / ``nested_tag_names`` / ``nested_decoder_maps``
    apply to the simple-TLV stream *inside* each DGI value. ``dgi_names``
    is consulted for the outer DGI tag itself; when present, the
    matching record carries a ``"name"`` field. Defaults: the
    SCP80 connectivity tables (``DEFAULT_TOP_LEVEL_TAG_NAMES``,
    ``DEFAULT_NESTED_TAG_NAMES``, ``DEFAULT_NESTED_DECODER_MAPS``)
    and the GP Amendment A DGI table (``DEFAULT_DGI_NAMES``).

    Truncated tail fragments are dropped silently rather than raising;
    a SAIP profile that runs off the end of an ``sdPersoData`` blob is
    still partially diagnosable from the records that did parse.
    """
    if tag_names is None:
        tag_names = DEFAULT_TOP_LEVEL_TAG_NAMES
    if nested_tag_names is None:
        nested_tag_names = DEFAULT_NESTED_TAG_NAMES
    if nested_decoder_maps is None:
        nested_decoder_maps = _DEFAULT_NESTED_DECODER_MAPS
    if dgi_names is None:
        dgi_names = DEFAULT_DGI_NAMES

    items: list[dict[str, Any]] = []
    offset = 0
    while offset + 3 <= len(data):
        tag_bytes = data[offset:offset + 2]
        offset += 2
        if offset >= len(data):
            break
        length_octet = data[offset]
        offset += 1
        if length_octet == 0xFF:
            if offset + 2 > len(data):
                break
            length_value = int.from_bytes(
                data[offset:offset + 2],
                "big",
                signed=False,
            )
            offset += 2
        else:
            length_value = length_octet
        value_end = offset + length_value
        if value_end > len(data):
            break
        value_bytes = data[offset:value_end]
        offset = value_end
        dgi_tag = tag_bytes.hex().upper()
        record: dict[str, Any] = {
            "dgi": tag_bytes.hex(),
            "length": length_value,
            "raw": value_bytes.hex(),
            "decoded": decode_simple_tlv_payload(
                value_bytes,
                tag_names=tag_names,
                nested_tag_names=nested_tag_names,
                nested_decoder_maps=nested_decoder_maps,
            ),
        }
        if dgi_tag in dgi_names:
            record["name"] = dgi_names[dgi_tag]
        items.append(record)
    return items


def decode_dgi_records(value: Any) -> list[dict[str, Any]] | None:
    """High-level entry point used by SAIP shell ``INFO`` and TUI panes.

    ``value`` may be a single hex string, raw bytes, or a list of
    either (jsonified ``sdPersoData`` is a list of hex strings). Each
    element is decoded as an independent DGI stream and returned as a
    record::

        [{"record": 1, "format": "DGI", "items": [...]}, ...]

    Returns ``None`` when no element parses to a non-empty record set,
    which is the historical signal the shell uses to fall back to the
    plain raw rendering.
    """
    hex_values = value_to_hex_strings(value)
    if len(hex_values) == 0:
        return None
    decoded_entries: list[dict[str, Any]] = []
    record_index = 1
    for hex_value in hex_values:
        entry_bytes = value_to_bytes(hex_value)
        if entry_bytes is None:
            continue
        items = decode_dgi_stream(entry_bytes)
        if len(items) == 0:
            continue
        decoded_entries.append(
            {
                "record": record_index,
                "format": "DGI",
                "items": items,
            }
        )
        record_index += 1
    if len(decoded_entries) == 0:
        return None
    return decoded_entries


__all__ = [
    "DEFAULT_DGI_NAMES",
    "DEFAULT_NESTED_TAG_NAMES",
    "DEFAULT_TOP_LEVEL_TAG_NAMES",
    "decode_dgi_records",
    "decode_dgi_stream",
    "decode_simple_tlv_payload",
    "decode_stk_value",
    "describe_bearer_description",
    "describe_transport_level",
    "decode_compact_binary_value",
    "decode_length_prefixed_identifier_block",
    "decode_network_access_name",
    "decode_other_address",
    "decode_printable_ascii",
    "parse_simple_tlv_stream",
    "value_to_bytes",
    "value_to_hex_strings",
]
