# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EF_ICCID coding shared by the SCP11 encoders and decoders.

ETSI TS 102 221 v18.4 section 13.2 codes EF_ICCID as ten BCD octets, left
justified and padded with 'F', with the first digit in the low nibble of the
first octet. SGP.22 v3.1 defines ``Iccid`` as ``[APPLICATION 26] OCTET STRING
(SIZE(10))`` "as coded in EFiccid", so every ICCID that reaches an ES10 or
ESipa payload is produced and read through these two functions.
"""

from __future__ import annotations

ICCID_OCTETS = 10
ICCID_MAX_DIGITS = ICCID_OCTETS * 2

_SEPARATORS = " -:._"


def swap_nibbles(value: bytes) -> bytes:
    """Exchange the two nibbles of every octet."""
    return bytes(((octet & 0x0F) << 4) | (octet >> 4) for octet in bytes(value))


def encode_ef_iccid(digits: str) -> bytes:
    """Return the ten EF_ICCID octets for a printed ICCID.

    Separators are ignored; anything else that is not a decimal digit is
    refused, as is an ICCID longer than twenty digits. Shorter ICCIDs are
    padded with 'F' nibbles to the fixed SIZE(10).
    """
    text = str(digits or "").strip()
    cleaned = "".join(character for character in text if character not in _SEPARATORS)
    if len(cleaned) == 0:
        raise ValueError("ICCID must contain at least one digit.")
    if cleaned.isdigit() is False:
        raise ValueError("ICCID must contain decimal digits only.")
    if len(cleaned) > ICCID_MAX_DIGITS:
        raise ValueError(f"ICCID cannot exceed {ICCID_MAX_DIGITS} digits.")
    padded = cleaned + "F" * (ICCID_MAX_DIGITS - len(cleaned))
    return swap_nibbles(bytes.fromhex(padded))


def decode_ef_iccid(value: bytes, *, strict: bool = True) -> str:
    """Return the printed ICCID held in EF_ICCID-coded octets.

    With ``strict`` set, an octet string that is not digits followed by 'F'
    padding raises ``ValueError``. Without it the nibbles are rendered as they
    are, so a malformed value stays visible instead of turning into digits it
    never carried.
    """
    raw = bytes(value or b"")
    if len(raw) == 0:
        return ""
    nibbles = swap_nibbles(raw).hex().upper()
    stripped = nibbles.rstrip("F")
    if strict:
        if len(raw) != ICCID_OCTETS:
            raise ValueError(f"EF_ICCID must be {ICCID_OCTETS} octets, got {len(raw)}.")
        if stripped.isdigit() is False:
            raise ValueError("EF_ICCID contains nibbles that are not BCD digits or trailing 'F' padding.")
        return stripped
    return stripped


def decode_bcd_digits(
    value: bytes,
    *,
    strict: bool = True,
    allow_filler: bool = False,
) -> str:
    """Return the digits of straight (high nibble first) BCD octets.

    An EID or a PE-Header ICCID is stored high nibble first with no
    padding: SGP.22 v3.1 section 3.3.1 puts the first, third and every further
    odd digit into the highest four bits of the first, second and every
    further byte, the reverse of the EF_ICCID order above. With ``strict`` set,
    a nibble above 9 raises ``ValueError``; without it the nibble is rendered
    as its hex letter, so a malformed value stays visible instead of turning
    into digits it never carried.

    ``allow_filler`` accepts one trailing 'F' nibble, the odd-length form of a
    GlobalPlatform Issuer Identification Number (GPC v2.3.1 section 7.4.1.1,
    ISO 7812 coded under tag '42'). A filler anywhere else stays invalid.
    """
    raw = bytes(value or b"")
    text = raw.hex().upper()
    if allow_filler and text.endswith("F"):
        text = text[:-1]
    if strict and text.isdigit() is False:
        raise ValueError("BCD octets contain nibbles that are not decimal digits.")
    return text
