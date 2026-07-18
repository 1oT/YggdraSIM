# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SIM utility primitives: BER-TLV builder/parser, BCD nibble-swap, EF.ICCID and EF.IMSI encoders."""
from __future__ import annotations

from typing import Any


def encode_length(length: int) -> bytes:
    """Encode a non-negative BER definite length using its minimal form."""
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("BER length must be an integer.")
    if length < 0:
        raise ValueError("BER length must not be negative.")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(encoded) > 0x7E:
        # 0xFF is reserved and 0x80 denotes indefinite length.
        raise ValueError("BER length requires too many length octets.")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag: bytes | str, value: bytes) -> bytes:
    tag_bytes = tag
    if isinstance(tag, str):
        tag_bytes = bytes.fromhex(tag)
    return bytes(tag_bytes) + encode_length(len(value)) + bytes(value)


def read_tlv(data: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, int]:
    """Parse one BER-TLV record at *offset* and return (tag, length_bytes, value, next_offset).

    Supports 1-byte and 2-byte tags, and definite short and long-form lengths.
    Raises ``ValueError`` on truncated or malformed input.
    """
    if offset >= len(data):
        raise ValueError("TLV offset out of range.")

    tag_start = offset
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            raise ValueError("Truncated multi-byte tag.")

    tag_bytes = data[tag_start:offset]
    if offset >= len(data):
        raise ValueError("Missing TLV length.")
    first = data[offset]
    if first < 0x80:
        length = first
        length_size = 1
    else:
        count = first & 0x7F
        if count == 0:
            raise ValueError("Indefinite TLV lengths are not supported.")
        if offset + 1 + count > len(data):
            raise ValueError("Truncated TLV length.")
        length = int.from_bytes(data[offset + 1 : offset + 1 + count], "big", signed=False)
        length_size = 1 + count

    value_start = offset + length_size
    value_end = value_start + length
    if value_end > len(data):
        raise ValueError("TLV value overruns input.")
    raw_tlv = data[tag_start:value_end]
    return tag_bytes, data[value_start:value_end], raw_tlv, value_end


def read_tlv_header(data: bytes, offset: int = 0) -> tuple[bytes, int, int, int]:
    """Parse a BER-TLV header at *offset* and return (tag_bytes, length_value, header_size, next_offset).

    Reads only the tag and length fields without copying the value bytes.
    """
    if offset >= len(data):
        raise ValueError("TLV offset out of range.")

    tag_start = offset
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            raise ValueError("Truncated multi-byte tag.")

    tag_bytes = data[tag_start:offset]
    if offset >= len(data):
        raise ValueError("Missing TLV length.")
    first = data[offset]
    if first < 0x80:
        length = first
        length_size = 1
    else:
        count = first & 0x7F
        if count == 0:
            raise ValueError("Indefinite TLV lengths are not supported.")
        if offset + 1 + count > len(data):
            raise ValueError("Truncated TLV length.")
        length = int.from_bytes(data[offset + 1 : offset + 1 + count], "big", signed=False)
        length_size = 1 + count
    header_length = len(tag_bytes) + length_size
    return tag_bytes, length, header_length, offset + length_size


def find_first_tlv(data: bytes, target_tag: bytes | str) -> bytes:
    """Return the value bytes of the first TLV in *data* whose tag matches *target_tag*.

    Returns an empty bytes object when the tag is not found.
    """
    target = bytes.fromhex(target_tag) if isinstance(target_tag, str) else bytes(target_tag)
    offset = 0
    while offset < len(data):
        tag_bytes, value, raw_tlv, next_offset = read_tlv(data, offset)
        if tag_bytes == target:
            return raw_tlv
        if len(tag_bytes) > 0 and (tag_bytes[0] & 0x20):
            nested = find_first_tlv(value, target)
            if len(nested) > 0:
                return nested
        offset = next_offset
    return b""


def swap_bcd_nibbles(hex_text: str) -> str:
    """Swap the nibbles of every byte-pair in a hex string (ETSI BCD byte-reversal).

    For example ``"219301"`` becomes ``"123190"``.
    Raises ``ValueError`` on odd-length input.
    """
    cleaned = str(hex_text or "").strip().upper()
    if len(cleaned) % 2 != 0:
        raise ValueError("BCD text must contain an even number of nibbles.")
    out: list[str] = []
    offset = 0
    while offset < len(cleaned):
        pair = cleaned[offset : offset + 2]
        out.append(pair[1] + pair[0])
        offset += 2
    return "".join(out)


def encode_iccid_ef(iccid_digits: str) -> bytes:
    """Encode an ICCID digit string into the 10-byte EF.ICCID body (ETSI TS 102 221 §13.2).

    Accepts 19 or 20 decimal digits. A 19-digit representation may
    optionally carry its terminal ``F`` filler explicitly. The result is
    always exactly ten bytes.
    """
    cleaned = str(iccid_digits or "").strip().replace(" ", "").replace("-", "").upper()
    if cleaned.endswith("F"):
        if len(cleaned) != 20 or not cleaned[:-1].isdigit():
            raise ValueError(
                "ICCID filler form must contain exactly 19 decimal digits followed by F."
            )
        normalized = cleaned
    elif cleaned.isdigit() and len(cleaned) == 19:
        normalized = cleaned + "F"
    elif cleaned.isdigit() and len(cleaned) == 20:
        normalized = cleaned
    else:
        raise ValueError("ICCID must contain exactly 19 or 20 decimal digits.")
    encoded = bytes.fromhex(swap_bcd_nibbles(normalized))
    if len(encoded) != 10:  # Defensive invariant for future normalization changes.
        raise ValueError("EF.ICCID encoding must be exactly 10 bytes.")
    return encoded


def encode_imsi_ef(imsi_digits: str) -> bytes:
    """Encode an IMSI digit string into the 9-byte EF.IMSI body (3GPP TS 31.102 §4.2.2).

    The first byte is the fixed EF payload length (8), followed by the
    parity/type nibble and BCD-packed digits padded with ``0xF``. IMSIs
    are limited to 15 digits and the result is always exactly nine bytes.
    """
    digits = str(imsi_digits or "").strip().replace(" ", "").replace("-", "")
    if len(digits) == 0 or digits.isdigit() is False:
        raise ValueError("IMSI must contain decimal digits.")
    if len(digits) > 15:
        raise ValueError("IMSI must contain at most 15 decimal digits.")
    odd_digit_count = len(digits) % 2 == 1
    first_digit = int(digits[0])
    body = bytearray([(first_digit << 4) | (0x09 if odd_digit_count else 0x01)])
    remaining = digits[1:]
    if len(remaining) % 2:
        remaining += "F"
    for offset in range(0, len(remaining), 2):
        low_nibble = int(remaining[offset])
        high_text = remaining[offset + 1]
        high_nibble = 0x0F if high_text == "F" else int(high_text)
        body.append((high_nibble << 4) | low_nibble)
    body.extend(b"\xFF" * (8 - len(body)))
    encoded = b"\x08" + bytes(body)
    if len(encoded) != 9:  # Defensive invariant for future layout changes.
        raise ValueError("EF.IMSI encoding must be exactly 9 bytes.")
    return encoded


def decode_bcd_digits(value: bytes) -> str:
    """Decode BCD-packed bytes to a digit string, stripping trailing 0xF fillers."""
    digits = ""
    for byte in bytes(value or b""):
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low <= 9:
            digits += str(low)
        if high <= 9:
            digits += str(high)
    return digits


def decode_imsi_ef(value: bytes) -> str:
    """Decode a 9-byte EF.IMSI body to a plain digit string (3GPP TS 31.102 §4.2.2).

    Strips the length byte and parity nibble before BCD-decoding.
    """
    raw = bytes(value or b"")
    if len(raw) < 2:
        return ""
    encoded = raw[1:]
    digits = decode_bcd_digits(encoded)
    if len(digits) == 0:
        return ""
    # EF.IMSI stores the odd/even indicator in the first decoded nibble.
    return digits[1:]


def parse_apdu(apdu: bytes) -> dict[str, Any]:
    """Parse a raw APDU byte string into its ISO 7816-4 header and body fields.

    Returns a dict with ``cla``, ``ins``, ``p1``, ``p2``, ``lc``, ``data``, and ``le``.
    Handles short (1-byte) and extended (3-byte) Lc/Le forms.
    Raises ``ValueError`` when the APDU is shorter than 4 bytes.
    """
    data = bytes(apdu or b"")
    if len(data) < 4:
        raise ValueError("APDU must be at least 4 bytes.")
    cla = data[0]
    ins = data[1]
    p1 = data[2]
    p2 = data[3]
    body = data[4:]
    command_data = b""
    le = None

    if len(body) == 0:
        return {
            "cla": cla,
            "ins": ins,
            "p1": p1,
            "p2": p2,
            "data": command_data,
            "le": le,
        }

    if len(body) == 1:
        le = 256 if body[0] == 0 else body[0]
        return {
            "cla": cla,
            "ins": ins,
            "p1": p1,
            "p2": p2,
            "data": command_data,
            "le": le,
        }

    if body[0] != 0x00:
        lc = body[0]
        if len(body) < 1 + lc:
            raise ValueError("Short APDU body is truncated.")
        command_data = body[1 : 1 + lc]
        trailing = body[1 + lc :]
        if len(trailing) == 1:
            le = 256 if trailing[0] == 0 else trailing[0]
        elif len(trailing) > 1:
            raise ValueError(
                f"Short APDU has {len(trailing)} trailing bytes after Lc; "
                "expected 0 (case 3S) or 1 (case 4S)."
            )
        return {
            "cla": cla,
            "ins": ins,
            "p1": p1,
            "p2": p2,
            "data": command_data,
            "le": le,
        }

    if len(body) < 3:
        raise ValueError("Extended APDU body is truncated.")

    # ISO 7816-4 §5.1 Case 2E: ``CLA INS P1 P2 00 Le_hi Le_lo``. A
    # 3-byte body that starts with 0x00 is a command with no data and
    # an extended Le, not an extended Lc. Le=0000 encodes 65536 per
    # §5.3.2. The previous implementation treated these bytes as Lc
    # and either lost the Le (Le=0 → None) or raised "Extended APDU
    # payload is truncated" (Le>0 → expected <lc> data bytes that do
    # not exist).
    if len(body) == 3:
        le_value = int.from_bytes(body[1:3], "big", signed=False)
        if le_value == 0:
            le_value = 65536
        return {
            "cla": cla,
            "ins": ins,
            "p1": p1,
            "p2": p2,
            "data": command_data,
            "le": le_value,
        }

    lc = int.from_bytes(body[1:3], "big", signed=False)
    if lc == 0:
        raise ValueError(
            "Extended Lc=0 is invalid outside the exact three-byte case 2E body."
        )
    if len(body) < 3 + lc:
        raise ValueError("Extended APDU payload is truncated.")
    command_data = body[3 : 3 + lc]
    trailing = body[3 + lc :]
    if len(trailing) == 2:
        le = int.from_bytes(trailing[:2], "big", signed=False)
        if le == 0:
            le = 65536
    elif len(trailing) != 0:
        raise ValueError(
            f"Extended APDU has {len(trailing)} trailing bytes after "
            "data; expected 0 (case 3E) or 2 (case 4E)."
        )
    return {
        "cla": cla,
        "ins": ins,
        "p1": p1,
        "p2": p2,
        "data": command_data,
        "le": le,
    }


def apdu_encoded_length(data: bytes) -> int:
    """Return the on-wire byte length of the first short or extended APDU in *data*."""
    if len(data) < 4:
        raise ValueError("APDU shorter than header.")
    body = data[4:]
    if len(body) == 0:
        return 4
    if len(body) == 1:
        return 5
    if body[0] != 0x00:
        lc = body[0]
        need = 1 + lc
        if len(body) < need:
            raise ValueError("Short APDU body is truncated.")
        trailing = body[need:]
        if len(trailing) == 0:
            return 4 + need
        if len(trailing) == 1:
            return 4 + need + 1
        # Remaining bytes start the next APDU (OTA multi-command line).
        return 4 + need
    if len(body) == 3:
        return 7
    lc = int.from_bytes(body[1:3], "big", signed=False)
    if lc == 0:
        raise ValueError(
            "Extended Lc=0 is invalid outside the exact three-byte case 2E body."
        )
    need = 3 + lc
    if len(body) < need:
        raise ValueError("Extended APDU payload is truncated.")
    trailing = body[need:]
    if len(trailing) == 0:
        return 4 + need
    if len(trailing) == 2:
        return 4 + need + 2
    if len(trailing) < 2:
        raise ValueError("Extended APDU has truncated trailing.")
    return 4 + need


def split_apdu_sequence(raw: bytes) -> list[bytes]:
    """Split *raw* into consecutive command APDUs (OTA multi-command lines)."""
    buf = bytes(raw or b"")
    out: list[bytes] = []
    idx = 0
    while idx < len(buf):
        step = apdu_encoded_length(buf[idx:])
        out.append(buf[idx : idx + step])
        idx += step
    return out
