# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Symbolic decoders / encoders for SecurityDomain install-parameter blobs.

The TCA SAIP profile carries SecurityDomain install parameters as raw
bytes (``applicationPrivileges`` 3-byte bitmask, ``lifeCycleState`` 1-byte
enum). This module provides the lossless bytes ↔ symbolic round-trips the
GUI / TUI wrap in their named-bit / named-state drop-downs.

Spec references:
  * Privilege byte layout — GlobalPlatform Card Specification v2.3
    Table 11-49.
  * LCS byte values — GP CS §11.1.1 (Application Life Cycle State).
"""

from __future__ import annotations

import re
from typing import Any


# Bit ordering: per GP CS the b1 label refers to the *most-significant*
# bit of the byte (mask 0x80). The flag tables below pair each privilege
# / state name with the raw byte mask used to set it.

# Privilege bit catalog (GP CS Table 11-49, all 24 bits over 3 bytes).
# RFU bits are intentionally exposed by their numeric label so an
# operator can still flip them when probing card behaviour without
# having to drop to raw hex.
_PRIVILEGE_FLAGS: tuple[tuple[int, int, str], ...] = (
    # (byte_index, bit_mask, label)
    (0, 0x80, "Security Domain"),
    (0, 0x40, "DAP Verification"),
    (0, 0x20, "Delegated Management"),
    (0, 0x10, "Card Lock"),
    (0, 0x08, "Card Terminate"),
    (0, 0x04, "Card Reset"),
    (0, 0x02, "CVM Management"),
    (0, 0x01, "Mandated DAP Verification"),
    (1, 0x80, "Trusted Path"),
    (1, 0x40, "Authorized Management"),
    (1, 0x20, "Token Verification"),
    (1, 0x10, "Global Delete"),
    (1, 0x08, "Global Lock"),
    (1, 0x04, "Global Registry"),
    (1, 0x02, "Final Application"),
    (1, 0x01, "Global Service"),
    (2, 0x80, "Receipt Generation"),
    (2, 0x40, "Ciphered Load File Data Block"),
    (2, 0x20, "Contactless Activation"),
    (2, 0x10, "Contactless Self-Activation"),
    (2, 0x08, "RFU bit 21"),
    (2, 0x04, "RFU bit 22"),
    (2, 0x02, "RFU bit 23"),
    (2, 0x01, "RFU bit 24"),
)


# Life-cycle states the GUI dropdown surfaces. Byte values follow
# GP CS §11.1.1 Application Life Cycle State; SecurityDomain LCS
# (§11.1.2) shares the same byte encoding. Bytes outside this list
# (e.g. application-specific 0x83..0xBF blocked variants) round-trip
# through ``decode_life_cycle`` as ``CUSTOM`` with the raw hex
# preserved.
_LIFE_CYCLE_STATES: tuple[tuple[int, str], ...] = (
    (0x03, "INSTALLED"),
    (0x07, "SELECTABLE"),
    (0x0F, "PERSONALIZED"),
    (0x83, "LOCKED"),
    (0xFF, "TERMINATED"),
)


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


# ----------------------------------------------------------------------
# Catalog accessors — used by the GUI to populate dropdown choices.
# ----------------------------------------------------------------------


def privilege_catalog() -> list[dict[str, Any]]:
    """Return ``[{name, byte_index, bit_mask, hex}]`` for every privilege bit."""
    return [
        {
            "name": name,
            "byte_index": byte_index,
            "bit_mask": bit_mask,
            "hex": f"{bit_mask:02X}",
        }
        for byte_index, bit_mask, name in _PRIVILEGE_FLAGS
    ]


def life_cycle_catalog() -> list[dict[str, Any]]:
    """Return ``[{name, hex}]`` for every named life-cycle state."""
    return [{"name": name, "hex": f"{value:02X}"} for value, name in _LIFE_CYCLE_STATES]


# ----------------------------------------------------------------------
# Privilege bytes
# ----------------------------------------------------------------------


def _normalise_hex_bytes(value: Any, *, length: int, label: str) -> bytes:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return bytes(length)
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"{label} hex must have an even nybble count (got {len(text)}).",
        )
    raw = bytes.fromhex(text)
    if len(raw) > length:
        raise ValueError(
            f"{label} must be {length} bytes; got {len(raw)} bytes.",
        )
    if len(raw) < length:
        # Right-pad with zero bytes so a short string still yields a
        # well-shaped result (mirrors how cards interpret omitted
        # trailing bytes).
        raw = raw + bytes(length - len(raw))
    return raw


def decode_privileges(value: Any) -> dict[str, Any]:
    """Decode a 3-byte privilege blob into named flags + the raw hex.

    Returns ``{"hex": "XXYYZZ", "flags": ["Security Domain", ...]}``.
    """
    raw = _normalise_hex_bytes(value, length=3, label="applicationPrivileges")
    flags = []
    for byte_index, bit_mask, name in _PRIVILEGE_FLAGS:
        if raw[byte_index] & bit_mask:
            flags.append(name)
    return {"hex": raw.hex().upper(), "flags": flags}


def encode_privileges(flags: list[str] | None) -> str:
    """Encode an ordered list of privilege names into a 3-byte hex string."""
    if flags is None:
        flags = []
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a list of privilege-name strings.")
    by_name = {name: (byte_index, bit_mask) for byte_index, bit_mask, name in _PRIVILEGE_FLAGS}
    out = bytearray(3)
    seen: set[str] = set()
    for entry in flags:
        name = str(entry or "").strip()
        if len(name) == 0:
            continue
        if name in seen:
            continue
        seen.add(name)
        if name not in by_name:
            raise ValueError(
                f"unknown privilege flag {name!r}; allowed: "
                + ", ".join(label for *_x, label in _PRIVILEGE_FLAGS),
            )
        byte_index, bit_mask = by_name[name]
        out[byte_index] |= bit_mask
    return bytes(out).hex().upper()


# ----------------------------------------------------------------------
# Life-cycle state byte
# ----------------------------------------------------------------------


def decode_life_cycle(value: Any) -> dict[str, Any]:
    """Decode a 1-byte LCS into its symbolic name (or ``CUSTOM`` fallback)."""
    raw = _normalise_hex_bytes(value, length=1, label="lifeCycleState")
    name_by_value = {byte: name for byte, name in _LIFE_CYCLE_STATES}
    return {
        "hex": raw.hex().upper(),
        "name": name_by_value.get(raw[0], "CUSTOM"),
    }


def encode_life_cycle(name_or_hex: Any) -> str:
    """Encode a symbolic LCS name (or hex byte) into a 1-byte hex string."""
    text = str(name_or_hex or "").strip()
    if len(text) == 0:
        raise ValueError("lifeCycleState is required.")
    value_by_name = {name.upper(): byte for byte, name in _LIFE_CYCLE_STATES}
    upper = text.upper()
    if upper in value_by_name:
        return f"{value_by_name[upper]:02X}"
    raw = _normalise_hex_bytes(text, length=1, label="lifeCycleState")
    return raw.hex().upper()


__all__ = [
    "decode_life_cycle",
    "decode_privileges",
    "encode_life_cycle",
    "encode_privileges",
    "life_cycle_catalog",
    "privilege_catalog",
]
