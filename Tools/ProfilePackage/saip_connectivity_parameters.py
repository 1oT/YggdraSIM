# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ProfileHeader ``connectivityParameters`` BER-TLV breakdown.

TCA SAIP carries a single OCTET STRING ``connectivityParameters`` on
the ProfileHeader; the bytes are a SEQUENCE of TLV-tagged blocks each
holding the configuration for one OTA bearer. This module decodes the
three bearer types defined by ETSI TS 102 226 / 3GPP TS 31.115 and
provides the inverse encoders so the GUI can edit each bearer through
typed form fields rather than raw hex.

Bearer registry (TCA SAIP §A.2 ``ConnectivityParameters``)::

  Tag  Bearer        Reference
  ----  -----------   --------------------------------------------------
  0xA0  SMS-PP        ETSI TS 102 225 §5.1, TS 31.115 §4
  0xA1  HTTP / TLS    ETSI TS 102 226 §5.7, GP Amd B §3.2
  0xA2  CAT_TP        ETSI TS 102 124, TS 102 127

Each bearer block carries a sequence of optional sub-tags. The names
below come straight from the spec definitions; we never invent a
field-name not anchored in either ETSI or GP literature.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _strip(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def _to_bytes(value: Any, *, label: str) -> bytes:
    text = _strip(value)
    if len(text) == 0:
        return b""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"{label} has odd nibble count ({len(text)}); expected whole bytes.",
        )
    return bytes.fromhex(text)


# ----------------------------------------------------------------------
# Generic BER-TLV walker (definite-length only, indefinite-length is
# explicitly forbidden by ETSI TS 102 226 §3 for connectivity blobs).
# ----------------------------------------------------------------------


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int, int] | None:
    """Return ``(tag, length, value_offset, next_offset)`` or ``None``."""
    if offset >= len(data):
        return None
    tag = data[offset]
    cursor = offset + 1
    if cursor >= len(data):
        return None
    length_byte = data[cursor]
    cursor += 1
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        # Indefinite length is not legal here.
        return None
    else:
        length_octets = length_byte & 0x7F
        if length_octets == 0 or cursor + length_octets > len(data):
            return None
        length = int.from_bytes(data[cursor : cursor + length_octets], "big")
        cursor += length_octets
    if cursor + length > len(data):
        return None
    return (tag, length, cursor, cursor + length)


def _emit_tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    if len(value) <= 0xFF:
        return bytes([tag, 0x81, len(value)]) + value
    if len(value) <= 0xFFFF:
        return bytes([tag, 0x82, (len(value) >> 8) & 0xFF, len(value) & 0xFF]) + value
    raise ValueError(f"TLV length {len(value)} exceeds 2-byte length encoding.")


# ----------------------------------------------------------------------
# SMS-PP bearer (tag 0xA0). Inner sub-tags per SGP.02 Table 92 /
# TS 31.115 §4 / TS 102 225:
#
#   06   dialing number (TON+NPI byte || BCD digits, TS 24.011 §8.2.5)
#   81   PID  (Protocol Identifier, TS 23.040 §9.2.3.9)
#   82   DCS  (Data Coding Scheme, TS 23.038 §4)
#   83   legacy SMSC address override accepted for existing editor output
# ----------------------------------------------------------------------


_SMS_TON_NAMES: tuple[tuple[int, str], ...] = (
    (0x0, "unknown"),
    (0x1, "international"),
    (0x2, "national"),
    (0x3, "network_specific"),
    (0x4, "subscriber"),
    (0x5, "alphanumeric"),
    (0x6, "abbreviated"),
)


_SMS_NPI_NAMES: tuple[tuple[int, str], ...] = (
    (0x0, "unknown"),
    (0x1, "isdn"),
    (0x3, "data"),
    (0x4, "telex"),
    (0x8, "national"),
    (0x9, "private"),
)


def _decode_dialing_number(value: bytes) -> dict[str, Any]:
    if len(value) == 0:
        return {"ton": "", "npi": "", "digits": ""}
    ton_byte = value[0]
    ton = (ton_byte >> 4) & 0x07
    npi = ton_byte & 0x0F
    digits = ""
    for byte in value[1:]:
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low <= 9:
            digits += str(low)
        if high <= 9:
            digits += str(high)
    ton_name = next((n for v, n in _SMS_TON_NAMES if v == ton), f"ton_{ton:X}")
    npi_name = next((n for v, n in _SMS_NPI_NAMES if v == npi), f"npi_{npi:X}")
    return {
        "ton": ton_name,
        "npi": npi_name,
        "digits": digits,
        "raw_hex": value.hex().upper(),
    }


def _encode_dialing_number(ton_name: Any, npi_name: Any, digits: Any) -> bytes:
    by_ton = {n: v for v, n in _SMS_TON_NAMES}
    by_npi = {n: v for v, n in _SMS_NPI_NAMES}
    ton_value = by_ton.get(str(ton_name or "unknown").strip().lower())
    if ton_value is None:
        raise ValueError(
            f"unknown TON {ton_name!r}; allowed: {', '.join(by_ton.keys())}",
        )
    npi_value = by_npi.get(str(npi_name or "isdn").strip().lower())
    if npi_value is None:
        raise ValueError(
            f"unknown NPI {npi_name!r}; allowed: {', '.join(by_npi.keys())}",
        )
    digits_text = re.sub(r"\s+", "", str(digits or ""))
    if not digits_text.isdigit() and len(digits_text) > 0:
        raise ValueError(f"dialing number digits must be 0-9; got {digits!r}")
    out = bytearray([(0x80 | ((ton_value & 0x07) << 4) | (npi_value & 0x0F)) & 0xFF])
    pad = digits_text + ("F" if len(digits_text) % 2 else "")
    for index in range(0, len(pad), 2):
        low = pad[index]
        high = pad[index + 1]
        nibble_low = int(low, 16)
        nibble_high = int(high, 16) if high != "F" else 0xF
        out.append(((nibble_high & 0x0F) << 4) | (nibble_low & 0x0F))
    return bytes(out)


def _decode_sms_block(value: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"bearer": "sms"}
    cursor = 0
    while cursor < len(value):
        parsed = _read_tlv(value, cursor)
        if parsed is None:
            out["parse_remainder_hex"] = value[cursor:].hex().upper()
            break
        tag, _length, val_offset, next_offset = parsed
        chunk = value[val_offset:next_offset]
        if tag in (0x06, 0x80):
            out["dialing_number"] = _decode_dialing_number(chunk)
        elif tag == 0x81 and len(chunk) >= 1:
            out["pid_hex"] = f"{chunk[0]:02X}"
        elif tag == 0x82 and len(chunk) >= 1:
            out["dcs_hex"] = f"{chunk[0]:02X}"
        elif tag == 0x83:
            out["smsc_dialing_number"] = _decode_dialing_number(chunk)
        else:
            _append_extra(out, tag, chunk)
        cursor = next_offset
    return out


def _encode_sms_block(payload: dict[str, Any]) -> bytes:
    body = bytearray()
    if "dialing_number" in payload:
        dn = payload["dialing_number"] or {}
        body += _emit_tlv(
            0x06,
            _encode_dialing_number(dn.get("ton"), dn.get("npi"), dn.get("digits")),
        )
    if payload.get("pid_hex"):
        body += _emit_tlv(0x81, _to_bytes(payload["pid_hex"], label="pid"))
    if payload.get("dcs_hex"):
        body += _emit_tlv(0x82, _to_bytes(payload["dcs_hex"], label="dcs"))
    if "smsc_dialing_number" in payload:
        sm = payload["smsc_dialing_number"] or {}
        body += _emit_tlv(
            0x83,
            _encode_dialing_number(sm.get("ton"), sm.get("npi"), sm.get("digits")),
        )
    body += _encode_extras(payload.get("extras"))
    return _emit_tlv(0xA0, bytes(body))


# ----------------------------------------------------------------------
# CAT_TP bearer (tag 0xA2). Inner sub-tags per TS 102 124 §6 / TS 102 127:
#
#   35   bearer description (TS 102 223 §8.52)
#   47   network access name (TS 102 223 §8.70)
#   0D   text string, first occurrence user login, second user password
# ----------------------------------------------------------------------


def _decode_cat_tp_block(value: bytes) -> dict[str, Any]:
    return _decode_named_bearer(value, bearer_name="cat_tp")


def _encode_cat_tp_block(payload: dict[str, Any]) -> bytes:
    return _encode_named_bearer(payload, outer_tag=0xA2)


# ----------------------------------------------------------------------
# HTTPS / TLS bearer (tag 0xA1). Sub-tags per ETSI TS 102 226 §5.7 /
# GP Amd B §3.2:
#
#   35   bearer description
#   47   network access name
#   0D   text string, first occurrence user login, second user password
#   84   legacy server URI (UTF-8, RFC 3986), preserved when present
# ----------------------------------------------------------------------


def _decode_https_block(value: bytes) -> dict[str, Any]:
    out = _decode_named_bearer(value, bearer_name="https")
    cursor = 0
    while cursor < len(value):
        parsed = _read_tlv(value, cursor)
        if parsed is None:
            break
        tag, _length, val_offset, next_offset = parsed
        if tag == 0x84:
            try:
                out["server_uri"] = value[val_offset:next_offset].decode("utf-8")
            except UnicodeDecodeError:
                out["server_uri_hex"] = value[val_offset:next_offset].hex().upper()
        cursor = next_offset
    return out


def _encode_https_block(payload: dict[str, Any]) -> bytes:
    body_inner = _encode_named_bearer_body(payload)
    if payload.get("server_uri"):
        body_inner += _emit_tlv(0x84, str(payload["server_uri"]).encode("utf-8"))
    elif payload.get("server_uri_hex"):
        body_inner += _emit_tlv(0x84, _to_bytes(payload["server_uri_hex"], label="server_uri_hex"))
    return _emit_tlv(0xA1, body_inner)


# ----------------------------------------------------------------------
# Shared helpers for the bearer-description / NAN / login / password
# block used by CAT_TP and HTTPS.
# ----------------------------------------------------------------------


def _decode_named_bearer(value: bytes, *, bearer_name: str) -> dict[str, Any]:
    out: dict[str, Any] = {"bearer": bearer_name}
    cursor = 0
    text_string_count = 0
    while cursor < len(value):
        parsed = _read_tlv(value, cursor)
        if parsed is None:
            out["parse_remainder_hex"] = value[cursor:].hex().upper()
            break
        tag, _length, val_offset, next_offset = parsed
        chunk = value[val_offset:next_offset]
        if tag in (0x35, 0x80):
            out["bearer_description_hex"] = chunk.hex().upper()
        elif tag in (0x47, 0x81):
            out["network_access_name"] = (
                _decode_network_access_name(chunk) if tag == 0x47 else _utf8_or_hex(chunk)
            )
        elif tag == 0x39 and len(chunk) == 2:
            out["buffer_size"] = int.from_bytes(chunk, "big", signed=False)
        elif tag == 0x82:
            out["user_login"] = _utf8_or_hex(chunk)
        elif tag == 0x83:
            out["user_password"] = _utf8_or_hex(chunk)
        elif tag == 0x0D:
            text_string_count += 1
            if text_string_count == 1:
                out["user_login"] = _decode_text_string(chunk)
            elif text_string_count == 2:
                out["user_password"] = _decode_text_string(chunk)
            else:
                _append_extra(out, tag, chunk)
        elif tag == 0x84:
            try:
                out["server_uri"] = chunk.decode("utf-8")
            except UnicodeDecodeError:
                out["server_uri_hex"] = chunk.hex().upper()
        else:
            _append_extra(out, tag, chunk)
        cursor = next_offset
    return out


def _utf8_or_hex(chunk: bytes) -> dict[str, Any]:
    try:
        return {"text": chunk.decode("utf-8")}
    except UnicodeDecodeError:
        return {"hex": chunk.hex().upper()}


def _decode_network_access_name(chunk: bytes) -> dict[str, Any]:
    labels: list[str] = []
    offset = 0
    while offset < len(chunk):
        label_len = chunk[offset]
        offset += 1
        if label_len == 0:
            break
        end = offset + label_len
        if end > len(chunk):
            return {"hex": chunk.hex().upper()}
        label = chunk[offset:end]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            return {"hex": chunk.hex().upper()}
        offset = end
    if len(labels) == 0:
        return {"hex": chunk.hex().upper()}
    return {"text": ".".join(labels), "encoding": "network_access_name"}


def _encode_network_access_name(value: Any) -> bytes:
    if isinstance(value, dict):
        if "hex" in value:
            return _to_bytes(value["hex"], label="network_access_name")
        value = value.get("text", "")
    text = str(value or "").strip()
    if len(text) == 0:
        return b""
    out = bytearray()
    for label in text.split("."):
        if len(label) == 0:
            continue
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError("network_access_name labels must be at most 63 bytes.")
        out.append(len(encoded))
        out += encoded
    return bytes(out)


def _decode_text_string(chunk: bytes) -> dict[str, Any]:
    if len(chunk) == 0:
        return {"text": "", "coding_scheme_hex": "04"}
    coding = chunk[0]
    payload = chunk[1:] if coding in (0x00, 0x04, 0x08) else chunk
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {"hex": chunk.hex().upper()}
    out: dict[str, Any] = {"text": decoded}
    if payload is not chunk:
        out["coding_scheme_hex"] = f"{coding:02X}"
    return out


def _encode_text_string(value: Any, *, label: str) -> bytes:
    if isinstance(value, dict):
        if "hex" in value:
            return _to_bytes(value["hex"], label=label)
        coding = _to_bytes(value.get("coding_scheme_hex", "04"), label=f"{label}.coding_scheme")
        if len(coding) != 1:
            raise ValueError(f"{label}.coding_scheme_hex must be one byte.")
        return coding + str(value.get("text", "")).encode("utf-8")
    return b"\x04" + str(value or "").encode("utf-8")


def _has_text_or_hex(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        if "hex" in value:
            return len(_strip(value.get("hex"))) > 0
        if "text" in value:
            return len(str(value.get("text") or "")) > 0
        return len(value) > 0
    return len(str(value or "")) > 0


def _encode_named_bearer_body(payload: dict[str, Any]) -> bytes:
    body = bytearray()
    if payload.get("bearer_description_hex"):
        body += _emit_tlv(0x35, _to_bytes(payload["bearer_description_hex"], label="bearer_description"))
    if payload.get("buffer_size") not in (None, ""):
        buffer_size = int(str(payload.get("buffer_size")), 0)
        if not 0 <= buffer_size <= 0xFFFF:
            raise ValueError("buffer_size must fit in two bytes.")
        body += _emit_tlv(0x39, buffer_size.to_bytes(2, "big"))
    if _has_text_or_hex(payload.get("network_access_name")):
        encoded_nan = _encode_network_access_name(payload["network_access_name"])
        if len(encoded_nan) > 0:
            body += _emit_tlv(0x47, encoded_nan)
    if _has_text_or_hex(payload.get("user_login")):
        body += _emit_tlv(0x0D, _encode_text_string(payload["user_login"], label="user_login"))
    if _has_text_or_hex(payload.get("user_password")):
        body += _emit_tlv(0x0D, _encode_text_string(payload["user_password"], label="user_password"))
    body += _encode_extras(payload.get("extras"))
    return bytes(body)


def _coerce_text_or_hex(value: Any, *, label: str) -> bytes:
    if isinstance(value, dict):
        if "text" in value:
            return str(value["text"]).encode("utf-8")
        if "hex" in value:
            return _to_bytes(value["hex"], label=label)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError(f"{label} must be text or hex; got {value!r}")


def _encode_named_bearer(payload: dict[str, Any], *, outer_tag: int) -> bytes:
    return _emit_tlv(outer_tag, _encode_named_bearer_body(payload))


def _append_extra(out: dict[str, Any], tag: int, chunk: bytes) -> None:
    extras = out.setdefault("extras", [])
    extras.append({"tag": f"{tag:02X}", "hex": chunk.hex().upper()})


def _encode_extras(extras: Any) -> bytes:
    if isinstance(extras, list) is False:
        return b""
    out = bytearray()
    for entry in extras:
        if isinstance(entry, dict) is False:
            continue
        tag_bytes = _to_bytes(entry.get("tag"), label="extras.tag")
        if len(tag_bytes) != 1:
            raise ValueError("extras.tag must be a single byte.")
        out += _emit_tlv(tag_bytes[0], _to_bytes(entry.get("hex"), label="extras.hex"))
    return bytes(out)


# ----------------------------------------------------------------------
# Public façade
# ----------------------------------------------------------------------


_BEARER_DECODERS: dict[int, Any] = {
    0xA0: _decode_sms_block,
    0xA1: _decode_https_block,
    0xA2: _decode_cat_tp_block,
}


_BEARER_ENCODERS: dict[str, Any] = {
    "sms": _encode_sms_block,
    "cat_tp": _encode_cat_tp_block,
    "https": _encode_https_block,
}


def decode_connectivity_parameters(hex_value: Any) -> dict[str, Any]:
    """Decode the ProfileHeader ``connectivityParameters`` octet string.

    Returns ``{"bearers": [...], "trailing_hex": "..."}``. Bearer tags
    not in ``_BEARER_DECODERS`` round-trip as ``{"bearer": "unknown",
    "tag_hex": "Ax", "value_hex": "..."}`` so a vendor extension is
    surfaced rather than silently lost.
    """
    raw = _to_bytes(hex_value, label="connectivityParameters")
    bearers: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(raw):
        parsed = _read_tlv(raw, cursor)
        if parsed is None:
            break
        tag, _length, val_offset, next_offset = parsed
        chunk = raw[val_offset:next_offset]
        decoder = _BEARER_DECODERS.get(tag)
        if decoder is None:
            bearers.append(
                {
                    "bearer": "unknown",
                    "tag_hex": f"{tag:02X}",
                    "value_hex": chunk.hex().upper(),
                },
            )
        else:
            bearers.append(decoder(chunk))
        cursor = next_offset
    trailing = raw[cursor:]
    return {
        "bearers": bearers,
        "trailing_hex": trailing.hex().upper(),
    }


def encode_connectivity_parameters(bearers: list[dict[str, Any]]) -> str:
    """Inverse of ``decode_connectivity_parameters``.

    Each entry in ``bearers`` must carry a ``bearer`` key naming one
    of ``sms`` / ``cat_tp`` / ``https``, plus the bearer-specific
    fields the decoder emits. Unknown bearers can be re-injected
    verbatim by supplying ``{"bearer": "unknown", "tag_hex": "...",
    "value_hex": "..."}``.
    """
    if isinstance(bearers, list) is False:
        raise ValueError("bearers must be a list of bearer dicts.")
    out = bytearray()
    for entry in bearers:
        if isinstance(entry, dict) is False:
            raise ValueError("bearer entry must be a dict.")
        bearer = str(entry.get("bearer") or "").strip().lower()
        if bearer == "unknown":
            tag_text = str(entry.get("tag_hex") or "").strip()
            if len(tag_text) == 0:
                raise ValueError("unknown bearer requires tag_hex.")
            tag = _to_bytes(tag_text, label="tag_hex")
            if len(tag) != 1:
                raise ValueError("tag_hex must be a single byte.")
            value_bytes = _to_bytes(entry.get("value_hex"), label="value_hex")
            out += _emit_tlv(tag[0], value_bytes)
            continue
        encoder = _BEARER_ENCODERS.get(bearer)
        if encoder is None:
            raise ValueError(
                f"unknown bearer {bearer!r}; allowed: "
                + ", ".join(sorted(_BEARER_ENCODERS.keys()))
                + " or 'unknown'.",
            )
        out += encoder(entry)
    return bytes(out).hex().upper()


def bearer_catalog() -> list[dict[str, Any]]:
    return [
        {"bearer": "sms",    "tag_hex": "A0", "spec": "ETSI TS 102 225 §5.1 / 3GPP TS 31.115 §4"},
        {"bearer": "https",  "tag_hex": "A1", "spec": "ETSI TS 102 226 §5.7 / GP Amd B §3.2"},
        {"bearer": "cat_tp", "tag_hex": "A2", "spec": "ETSI TS 102 124 / TS 102 127"},
    ]


__all__ = [
    "bearer_catalog",
    "decode_connectivity_parameters",
    "encode_connectivity_parameters",
]
