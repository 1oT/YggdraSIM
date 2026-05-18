# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Symbolic catalogues for SecurityDomain install-parameter blobs.

Companion to ``saip_security_domain_decode`` (privilege byte +
life-cycle byte). This module covers the install-parameter byte
blocks that the GUI / TUI editor surfaces as labelled drop-downs:

* Access Domain ........... ETSI TS 102 226 §8.2.1.3 / GP Amd C §3
* Minimum Security Level .. ETSI TS 102 225 §5.1.2 (SPI1 / KIc / KID)
* Application Family ID ... GP Amd C §6.1.5.1 (B0 contactless)
* Key Usage Qualifier ..... GP CS v2.3 Table 11-17
* Key Access .............. GP CS v2.3 Table 11-19
* Key Component Type ...... GP CS v2.3 §11.1.8 (DGI 00B9 / 8010)
* OPEN Restrict ........... GP CS v2.3 §11.5.4 (RestrictParameter)

Every entry pairs the symbolic name with the raw byte value so a
round-trip ``decode_*`` / ``encode_*`` call is byte-identical to the
on-card image.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _strip(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def _to_byte(value: Any, *, label: str) -> int:
    text = _strip(value)
    if len(text) == 0:
        raise ValueError(f"{label} is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) != 2:
        raise ValueError(f"{label} must be exactly 1 byte (2 hex digits); got {len(text)}.")
    return int(text, 16)


# ----------------------------------------------------------------------
# Access Domain (ETSI TS 102 226 §8.2.1.3)
#
# Access Domain Parameter (ADP) is a single byte selecting the access
# regime the toolkit / RFM application enjoys against the target file
# system. The values below cover the four regimes called out by the
# spec; vendor-specific values pass through as ``CUSTOM`` so an audit
# trace still preserves the byte.
# ----------------------------------------------------------------------

_ACCESS_DOMAIN_VALUES: tuple[tuple[int, str, str], ...] = (
    (0x00, "FULL_ACCESS",   "Application performs file operations under its own access conditions."),
    (0x01, "ALWAYS_ACCESS", "Application bypasses access conditions (use sparingly; logged on the card)."),
    (0x02, "PROFILE_ACCESS","Access conditions evaluated against the issuer profile."),
    (0xFF, "NO_ACCESS",     "Application is denied any file-system access."),
)


def access_domain_catalog() -> list[dict[str, Any]]:
    return [
        {"name": name, "hex": f"{value:02X}", "description": description}
        for value, name, description in _ACCESS_DOMAIN_VALUES
    ]


def decode_access_domain(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="accessDomain")
    name_by_value = {v: n for v, n, _ in _ACCESS_DOMAIN_VALUES}
    return {
        "hex": f"{byte:02X}",
        "name": name_by_value.get(byte, "CUSTOM"),
    }


def encode_access_domain(name_or_hex: Any) -> str:
    text = str(name_or_hex or "").strip()
    if len(text) == 0:
        raise ValueError("accessDomain is required.")
    by_name = {n.upper(): v for v, n, _ in _ACCESS_DOMAIN_VALUES}
    if text.upper() in by_name:
        return f"{by_name[text.upper()]:02X}"
    return f"{_to_byte(text, label='accessDomain'):02X}"


# ----------------------------------------------------------------------
# Minimum Security Level (ETSI TS 102 225 §5.1.2)
#
# MSL is a 1..3 byte structure: SPI1 (mandatory), optional KIc, optional
# KID. SPI1 packs four orthogonal selectors; the bit positions below
# are the YggdraSIM projection over the spec layout, kept disjoint so
# every selector can be flipped without touching its neighbours:
#
#   b1..b2  AuthN-response selector (no_security / RC / CC / DS)
#   b3      Counter present
#   b4      Counter-higher-value required
#   b5..b6  Integrity selector (no_integrity / RC / CC / DS)
#   b7..b8  RFU (cleared on encode)
# ----------------------------------------------------------------------

_MSL_AUTH_RESPONSE: tuple[tuple[int, str], ...] = (
    (0b00, "no_security"),
    (0b01, "redundancy_check"),
    (0b10, "cryptographic_checksum"),
    (0b11, "digital_signature"),
)
_MSL_INTEGRITY: tuple[tuple[int, str], ...] = (
    (0b00, "no_integrity"),
    (0b01, "redundancy_check"),
    (0b10, "cryptographic_checksum"),
    (0b11, "digital_signature"),
)
_MSL_COUNTER_FLAGS: tuple[tuple[int, str], ...] = (
    (0x04, "counter_present"),
    (0x08, "counter_high_value_required"),
)


def msl_catalog() -> dict[str, list[dict[str, Any]]]:
    return {
        "auth_response": [
            {"name": name, "bits": value} for value, name in _MSL_AUTH_RESPONSE
        ],
        "integrity": [
            {"name": name, "bits": value} for value, name in _MSL_INTEGRITY
        ],
        "counter_flags": [
            {"name": name, "bit_mask": mask} for mask, name in _MSL_COUNTER_FLAGS
        ],
    }


def decode_msl(value: Any) -> dict[str, Any]:
    text = _strip(value)
    if len(text) == 0:
        raise ValueError("minimumSecurityLevel is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"minimumSecurityLevel is not hexadecimal: {value!r}")
    if len(text) % 2 != 0 or len(text) > 6:
        raise ValueError(
            f"minimumSecurityLevel must be 1..3 bytes; got {len(text) // 2} bytes.",
        )
    raw = bytes.fromhex(text)
    spi1 = raw[0]
    auth_bits = spi1 & 0b11
    integrity_bits = (spi1 >> 4) & 0b11
    counter_flags: list[str] = []
    # Integrity bits reside in b5..b6 (mask 0x30); see layout note.
    for mask, name in _MSL_COUNTER_FLAGS:
        if spi1 & mask:
            counter_flags.append(name)
    auth_name = next((n for v, n in _MSL_AUTH_RESPONSE if v == auth_bits), "rfu")
    integrity_name = next((n for v, n in _MSL_INTEGRITY if v == integrity_bits), "rfu")
    out: dict[str, Any] = {
        "hex": raw.hex().upper(),
        "spi1_hex": f"{spi1:02X}",
        "auth_response": auth_name,
        "integrity": integrity_name,
        "counter_flags": counter_flags,
    }
    if len(raw) >= 2:
        out["kic_hex"] = f"{raw[1]:02X}"
    if len(raw) >= 3:
        out["kid_hex"] = f"{raw[2]:02X}"
    return out


def encode_msl(
    *,
    auth_response: str | None = None,
    integrity: str | None = None,
    counter_flags: list[str] | None = None,
    kic_hex: Any = None,
    kid_hex: Any = None,
) -> str:
    by_auth = {n: v for v, n in _MSL_AUTH_RESPONSE}
    by_integrity = {n: v for v, n in _MSL_INTEGRITY}
    by_counter = {n: v for v, n in _MSL_COUNTER_FLAGS}
    auth_bits = by_auth.get(auth_response or "no_security")
    if auth_bits is None:
        raise ValueError(
            f"unknown auth_response {auth_response!r}; allowed: "
            + ", ".join(by_auth.keys()),
        )
    integrity_bits = by_integrity.get(integrity or "no_integrity")
    if integrity_bits is None:
        raise ValueError(
            f"unknown integrity {integrity!r}; allowed: "
            + ", ".join(by_integrity.keys()),
        )
    spi1 = (auth_bits & 0b11) | ((integrity_bits & 0b11) << 4)
    for raw in counter_flags or []:
        name = str(raw or "").strip()
        if len(name) == 0:
            continue
        if name not in by_counter:
            raise ValueError(
                f"unknown counter flag {name!r}; allowed: "
                + ", ".join(by_counter.keys()),
            )
        spi1 |= by_counter[name]
    out = bytearray([spi1 & 0xFF])
    if kic_hex is not None and str(kic_hex).strip() != "":
        out.append(_to_byte(kic_hex, label="kic"))
    if kid_hex is not None and str(kid_hex).strip() != "":
        if len(out) == 1:
            # KID requires KIc to precede it. Emit a zero KIc so the
            # byte order remains valid per ETSI TS 102 225 §5.1.2.
            out.append(0x00)
        out.append(_to_byte(kid_hex, label="kid"))
    return bytes(out).hex().upper()


# ----------------------------------------------------------------------
# Application Family Identifier (GP Amd C §6.1.5.1)
#
# Carried in the contactless install parameter block (tag B0). One byte
# pulled from the GSMA-administered family registry; the catalog below
# covers the values published in GP Amd C and ISO 14443-4 §A.
# ----------------------------------------------------------------------

_AFI_VALUES: tuple[tuple[int, str], ...] = (
    (0x00, "GENERIC"),
    (0x10, "PAYMENT"),
    (0x20, "TRANSPORT"),
    (0x30, "GOVERNMENT"),
    (0x40, "LOYALTY"),
    (0x50, "BROADCAST"),
    (0x60, "TELEPHONY"),
    (0x70, "MEDICAL"),
    (0x80, "MULTIMEDIA"),
    (0x90, "GAMING"),
    (0xA0, "DATA_STORAGE"),
    (0xB0, "ACCESS_CONTROL"),
    (0xC0, "EMAIL"),
    (0xD0, "RESERVED_D0"),
    (0xE0, "RESERVED_E0"),
    (0xF0, "PROPRIETARY"),
)


def afi_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "hex": f"{value:02X}"} for value, name in _AFI_VALUES]


def decode_afi(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="applicationFamilyIdentifier")
    name_by_value = {v: n for v, n in _AFI_VALUES}
    return {
        "hex": f"{byte:02X}",
        "name": name_by_value.get(byte, "CUSTOM"),
    }


def encode_afi(name_or_hex: Any) -> str:
    text = str(name_or_hex or "").strip()
    if len(text) == 0:
        raise ValueError("applicationFamilyIdentifier is required.")
    by_name = {n.upper(): v for v, n in _AFI_VALUES}
    if text.upper() in by_name:
        return f"{by_name[text.upper()]:02X}"
    return f"{_to_byte(text, label='applicationFamilyIdentifier'):02X}"


# ----------------------------------------------------------------------
# Key attributes — Usage Qualifier (Table 11-17), Access (Table 11-19),
# Version Number (§11.1.9), Component Type (§11.1.8 DGI 00B9 / 8010).
# ----------------------------------------------------------------------

_KEY_USAGE_BITS: tuple[tuple[int, str], ...] = (
    (0x80, "verification_encryption"),
    (0x40, "computation_decryption"),
    (0x20, "sm_response"),
    (0x10, "sm_command"),
    (0x08, "confidentiality"),
    (0x04, "cryptographic_checksum"),
    (0x02, "digital_signature"),
    (0x01, "cryptographic_authorization"),
)


def key_usage_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "bit_mask": mask} for mask, name in _KEY_USAGE_BITS]


def decode_key_usage(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="keyUsageQualifier")
    flags: list[str] = []
    for mask, name in _KEY_USAGE_BITS:
        if byte & mask:
            flags.append(name)
    return {"hex": f"{byte:02X}", "flags": flags}


def encode_key_usage(flags: list[str] | None) -> str:
    if flags is None:
        flags = []
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a list of usage names.")
    by_name = {n: m for m, n in _KEY_USAGE_BITS}
    out = 0
    for raw in flags:
        name = str(raw or "").strip()
        if len(name) == 0:
            continue
        if name not in by_name:
            raise ValueError(
                f"unknown keyUsage flag {name!r}; allowed: "
                + ", ".join(by_name.keys()),
            )
        out |= by_name[name]
    return f"{out & 0xFF:02X}"


_KEY_ACCESS_VALUES: tuple[tuple[int, str], ...] = (
    (0x00, "ANY_ENTITY"),
    (0x01, "SECURITY_DOMAIN_ONLY"),
    (0x02, "APPLICATION_AND_SD"),
    (0x03, "CONTROLLING_AUTHORITY"),
)


def key_access_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "hex": f"{value:02X}"} for value, name in _KEY_ACCESS_VALUES]


def decode_key_access(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="keyAccess")
    name_by_value = {v: n for v, n in _KEY_ACCESS_VALUES}
    return {"hex": f"{byte:02X}", "name": name_by_value.get(byte, "CUSTOM")}


def encode_key_access(name_or_hex: Any) -> str:
    text = str(name_or_hex or "").strip()
    if len(text) == 0:
        raise ValueError("keyAccess is required.")
    by_name = {n.upper(): v for v, n in _KEY_ACCESS_VALUES}
    if text.upper() in by_name:
        return f"{by_name[text.upper()]:02X}"
    return f"{_to_byte(text, label='keyAccess'):02X}"


def decode_key_version(value: Any) -> dict[str, Any]:
    """Symbolic projection of the key version number byte.

    GP CS §11.1.9 reserves 0x00 for the issuer / OPEN, 0x01..0x7F for
    application-defined version numbers, and 0x71..0x73 for the
    Controlling Authority hierarchy. The decode pass reports the
    bucket so the GUI can colour the chip correctly without enforcing
    the spec restriction at edit-time (some test profiles ship with
    out-of-range values).
    """
    byte = _to_byte(value, label="keyVersionNumber")
    if byte == 0x00:
        bucket = "OPEN_ISSUER"
    elif byte in (0x71, 0x72, 0x73):
        bucket = "CONTROLLING_AUTHORITY"
    elif 0x01 <= byte <= 0x7F:
        bucket = "APPLICATION"
    else:
        bucket = "RESERVED"
    return {"hex": f"{byte:02X}", "value": byte, "bucket": bucket}


_KEY_COMPONENT_TYPES: tuple[tuple[int, str], ...] = (
    (0x80, "DES_ECB"),
    (0x81, "DES_CBC"),
    (0x82, "TRIPLE_DES_ECB"),
    (0x83, "TRIPLE_DES_CBC"),
    (0x84, "DES_CMAC"),
    (0x85, "AES"),
    (0x88, "AES_CMAC"),
    (0x90, "HMAC_SHA1"),
    (0x91, "HMAC_SHA256"),
    (0xA0, "RSA_PUBLIC_EXPONENT"),
    (0xA1, "RSA_PUBLIC_MODULUS"),
    (0xA2, "RSA_PRIVATE_MODULUS"),
    (0xA3, "RSA_PRIVATE_EXPONENT"),
    (0xA4, "RSA_PRIVATE_CRT_P"),
    (0xA5, "RSA_PRIVATE_CRT_Q"),
    (0xA6, "RSA_PRIVATE_CRT_PQ"),
    (0xA7, "RSA_PRIVATE_CRT_DP1"),
    (0xA8, "RSA_PRIVATE_CRT_DQ1"),
    (0xB0, "ECC_PUBLIC"),
    (0xB1, "ECC_PRIVATE"),
    (0xF0, "EXTENDED_HEADER"),
)


def key_component_catalog() -> list[dict[str, Any]]:
    return [
        {"name": name, "hex": f"{value:02X}"} for value, name in _KEY_COMPONENT_TYPES
    ]


def decode_key_component_type(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="keyComponentType")
    name_by_value = {v: n for v, n in _KEY_COMPONENT_TYPES}
    return {"hex": f"{byte:02X}", "name": name_by_value.get(byte, "CUSTOM")}


def encode_key_component_type(name_or_hex: Any) -> str:
    text = str(name_or_hex or "").strip()
    if len(text) == 0:
        raise ValueError("keyComponentType is required.")
    by_name = {n.upper(): v for v, n in _KEY_COMPONENT_TYPES}
    if text.upper() in by_name:
        return f"{by_name[text.upper()]:02X}"
    return f"{_to_byte(text, label='keyComponentType'):02X}"


# ----------------------------------------------------------------------
# OPEN Personalization Restrict (GP CS v2.3 §11.5.4)
#
# RestrictParameter is a one-byte bitmask gating which OPEN-managed
# operations the SD may perform on its own data. Names follow the
# GP CS §11.5.4 enumeration verbatim (spec-defined constants, not
# YggdraSIM coinage).
# ----------------------------------------------------------------------

_RESTRICT_BITS: tuple[tuple[int, str], ...] = (
    (0x80, "RESTRICT_REGISTRY_UPDATE"),
    (0x40, "RESTRICT_SD_REGISTRATION"),
    (0x20, "RESTRICT_SET_STATUS"),
    (0x10, "RESTRICT_LOCK"),
    (0x08, "RESTRICT_PERSONALIZE"),
    (0x04, "RESTRICT_DELETE"),
    (0x02, "RESTRICT_TRUSTED_PATH"),
    (0x01, "RESTRICT_GET_STATUS"),
)


def restrict_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "bit_mask": mask} for mask, name in _RESTRICT_BITS]


def decode_restrict(value: Any) -> dict[str, Any]:
    byte = _to_byte(value, label="restrict")
    flags: list[str] = []
    for mask, name in _RESTRICT_BITS:
        if byte & mask:
            flags.append(name)
    return {"hex": f"{byte:02X}", "flags": flags}


def encode_restrict(flags: list[str] | None) -> str:
    if flags is None:
        flags = []
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a list of restrict-flag names.")
    by_name = {n: m for m, n in _RESTRICT_BITS}
    out = 0
    for raw in flags:
        name = str(raw or "").strip()
        if len(name) == 0:
            continue
        if name not in by_name:
            raise ValueError(
                f"unknown restrict flag {name!r}; allowed: "
                + ", ".join(by_name.keys()),
            )
        out |= by_name[name]
    return f"{out & 0xFF:02X}"


__all__ = [
    "access_domain_catalog",
    "afi_catalog",
    "decode_access_domain",
    "decode_afi",
    "decode_key_access",
    "decode_key_component_type",
    "decode_key_usage",
    "decode_key_version",
    "decode_msl",
    "decode_restrict",
    "encode_access_domain",
    "encode_afi",
    "encode_key_access",
    "encode_key_component_type",
    "encode_key_usage",
    "encode_msl",
    "encode_restrict",
    "key_access_catalog",
    "key_component_catalog",
    "key_usage_catalog",
    "msl_catalog",
    "restrict_catalog",
]
