# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PIN / PUK value coding between operator-typed digits and on-card hex.

ETSI TS 102 221 §9.5.1 / 3GPP TS 31.101 §8 specify that a PIN/PUK value
on the card is an 8-byte octet string holding the ASCII representation
of each digit (0x30..0x39), padded on the right with 0xFF when the
typed value is shorter than eight digits. PUKs follow the same encoding
but are always 8 bytes (4..8 typed digits, FF-padded).

This module is the round-trip primitive the GUI / TUI editor wraps in
its "Digits" / "Hex" toggle. The TCA SAIP carrier value (``pinValue`` /
``pukValue``) is opaque bytes, so the operator chooses which face of
the same byte string to edit.
"""

from __future__ import annotations

import re
from typing import Any


_DIGITS_RE = re.compile(r"^[0-9]+$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


# Accepted byte-string lengths for the on-card image. The CHV slots in
# TS 102 221 are uniformly 8 bytes; certain test profiles double this
# to 16 bytes for application-specific PINs that carry a salt / OTP
# nibble pair. Anything else is rejected so a typo cannot mint an
# unencodable value.
_ALLOWED_BYTE_LENGTHS: tuple[int, ...] = (8, 16)


def _strip_separators(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def encode_digits_to_hex(
    digits: Any,
    *,
    target_byte_length: int = 8,
    pad_byte: int = 0xFF,
) -> str:
    """Encode 1..N decimal digits into an FF-padded ASCII hex string.

    Each input digit becomes its ASCII byte (``0x30 + d``); the result
    is right-padded with ``pad_byte`` (default 0xFF per TS 102 221) up
    to ``target_byte_length`` bytes. ``target_byte_length`` defaults to
    eight which matches a stock CHV slot.
    """
    text = _strip_separators(digits)
    if len(text) == 0:
        raise ValueError("digits string is empty.")
    if _DIGITS_RE.fullmatch(text) is None:
        raise ValueError(f"digits string must be 0-9 only, got {digits!r}")
    if int(target_byte_length) not in _ALLOWED_BYTE_LENGTHS:
        raise ValueError(
            f"target_byte_length must be one of {_ALLOWED_BYTE_LENGTHS}; "
            f"got {target_byte_length!r}.",
        )
    pad_int = int(pad_byte) & 0xFF
    if len(text) > int(target_byte_length):
        raise ValueError(
            f"digits string {text!r} is longer than target_byte_length "
            f"({target_byte_length}).",
        )
    encoded = bytearray(int(target_byte_length))
    encoded[: len(text)] = bytes(0x30 + (ord(c) - 0x30) for c in text)
    encoded[len(text) :] = bytes([pad_int]) * (int(target_byte_length) - len(text))
    return bytes(encoded).hex().upper()


def decode_hex_to_digits(hex_value: Any) -> dict[str, Any]:
    """Decode an on-card PIN/PUK byte string into its digit prefix.

    Returns ``{"hex": <UPPER>, "digits": <str>, "padded_to": <int>,
    "pad_byte_hex": <"FF" | …>, "valid_digits_only": <bool>}``. Bytes
    after the first non-ASCII-digit byte are treated as padding; if
    the padding byte is not 0xFF the caller still gets the prefix and
    the actual pad value so they can audit a non-conforming profile.
    """
    text = _strip_separators(hex_value)
    if len(text) == 0:
        raise ValueError("hex value is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"hex value must be hexadecimal, got {hex_value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"hex value has odd nibble count ({len(text)}); "
            "PIN/PUK octets are always whole bytes.",
        )
    raw = bytes.fromhex(text)
    if len(raw) not in _ALLOWED_BYTE_LENGTHS:
        raise ValueError(
            f"PIN/PUK byte length {len(raw)} is unsupported; expected "
            f"one of {_ALLOWED_BYTE_LENGTHS} (TS 102 221 §9.5.1).",
        )
    digits_chars: list[str] = []
    pad_byte_value: int | None = None
    valid = True
    for byte in raw:
        if 0x30 <= byte <= 0x39:
            if pad_byte_value is None:
                digits_chars.append(chr(byte))
                continue
            # A digit appearing AFTER a pad byte is malformed but does
            # not change the prefix the user typed; just record it.
            valid = False
            continue
        pad_byte_value = byte if pad_byte_value is None else pad_byte_value
    if pad_byte_value is None:
        # All eight (or sixteen) bytes are ASCII digits. Treat the
        # whole image as the typed value and report no padding.
        return {
            "hex": raw.hex().upper(),
            "digits": "".join(digits_chars),
            "padded_to": len(raw),
            "pad_byte_hex": "",
            "valid_digits_only": True,
        }
    return {
        "hex": raw.hex().upper(),
        "digits": "".join(digits_chars),
        "padded_to": len(raw),
        "pad_byte_hex": f"{pad_byte_value:02X}",
        "valid_digits_only": valid and pad_byte_value == 0xFF,
    }


def coerce_to_hex(
    value: Any,
    *,
    coding: str,
    target_byte_length: int = 8,
    pad_byte: int = 0xFF,
) -> str:
    """One-shot dispatcher used by the action layer.

    ``coding`` is the operator's selection on the toggle: ``"digits"``
    routes through ``encode_digits_to_hex``; ``"hex"`` validates the
    submitted hex against the allowed byte lengths and returns it
    upper-cased.
    """
    coding_text = str(coding or "").strip().lower()
    if coding_text == "digits":
        return encode_digits_to_hex(
            value,
            target_byte_length=int(target_byte_length),
            pad_byte=int(pad_byte),
        )
    if coding_text == "hex":
        text = _strip_separators(value)
        if len(text) == 0:
            raise ValueError("hex value is empty.")
        if _HEX_RE.fullmatch(text) is None:
            raise ValueError(f"hex value must be hexadecimal, got {value!r}")
        if len(text) % 2 != 0:
            raise ValueError(
                f"hex value has odd nibble count ({len(text)}); "
                "PIN/PUK octets are always whole bytes.",
            )
        if len(text) // 2 not in _ALLOWED_BYTE_LENGTHS:
            raise ValueError(
                f"PIN/PUK byte length {len(text) // 2} is unsupported; "
                f"expected one of {_ALLOWED_BYTE_LENGTHS}.",
            )
        return text.upper()
    raise ValueError(f"coding must be 'digits' or 'hex'; got {coding!r}.")


__all__ = [
    "coerce_to_hex",
    "decode_hex_to_digits",
    "encode_digits_to_hex",
]
