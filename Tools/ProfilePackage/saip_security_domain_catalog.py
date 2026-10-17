# SPDX-License-Identifier: GPL-3.0-or-later
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
# Access Domain (ETSI TS 102 226 V19.0.0 §8.2.1.3.2.5, page 29)
#
# The Access Domain Parameter (ADP) byte selects the mechanism that
# controls the application's access to the file system; the Access
# Domain Data after it is defined per ADP. Proprietary values ('80'-'FE')
# pass through as ``CUSTOM`` so an audit trace still preserves the byte.
# ----------------------------------------------------------------------

_ACCESS_DOMAIN_VALUES: tuple[tuple[int, str, str], ...] = (
    (0x00, "FULL_ACCESS", "Full access to the file system (no access domain data)."),
    (0x01, "RESERVED_APDU_ACCESS", "Reserved for an APDU access mechanism."),
    (0x02, "UICC_ACCESS_MECHANISM", "UICC access mechanism: three bytes of the keys whose SE ID 01 rules apply."),
    (0xFF, "NO_ACCESS", "No access to the file system (no access domain data)."),
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
# Minimum Security Level (ETSI TS 102 226 V19.0.0 §8.2.1.3.2.4, page 28)
#
# An MSL field is empty (no check), or the MSL parameter and its data: '01'
# Minimum SPI1 takes one byte coded as the first SPI octet (ETSI TS 102 225
# V19.0.0 §5.1.1, page 13): b2-b1 integrity, b3 ciphering, b5-b4 counter,
# b8-b6 reserved. A PE-RFM minimumSecurityLevel is that data byte alone
# (TCA SAIP v3.4.1 §8.8).
# ----------------------------------------------------------------------

_MSL_PARAMETER_MINIMUM_SPI1 = 0x01

_MSL_INTEGRITY: tuple[tuple[int, str], ...] = (
    (0b00, "no_integrity"),
    (0b01, "redundancy_check"),
    (0b10, "cryptographic_checksum"),
    (0b11, "digital_signature_reserved"),
)
_MSL_CIPHERING: tuple[tuple[int, str], ...] = (
    (0, "no_ciphering"),
    (1, "ciphering"),
)
_MSL_COUNTER: tuple[tuple[int, str], ...] = (
    (0b00, "no_counter"),
    (0b01, "counter_not_checked"),
    (0b10, "counter_higher"),
    (0b11, "counter_one_higher"),
)


def msl_catalog() -> dict[str, list[dict[str, Any]]]:
    return {
        "integrity": [{"name": name, "bits": value} for value, name in _MSL_INTEGRITY],
        "ciphering": [{"name": name, "bits": value} for value, name in _MSL_CIPHERING],
        "counter": [{"name": name, "bits": value} for value, name in _MSL_COUNTER],
    }


def decode_msl(value: Any) -> dict[str, Any]:
    """Decode the Minimum SPI1 data byte, or a whole MSL field ('01' + byte)."""
    text = _strip(value)
    if _HEX_RE.fullmatch(text or "0") is None or len(text) % 2 != 0:
        raise ValueError(f"minimumSecurityLevel is not hexadecimal bytes: {value!r}")
    raw = bytes.fromhex(text)
    if len(raw) == 0:
        return {"hex": "", "check": False}
    if len(raw) == 1:
        parameter = None
        spi1 = raw[0]
    elif len(raw) == 2 and raw[0] == _MSL_PARAMETER_MINIMUM_SPI1:
        parameter = "minimum_spi1"
        spi1 = raw[1]
    else:
        raise ValueError(
            "minimumSecurityLevel is the Minimum SPI1 byte or an MSL field of "
            f"parameter '01' and that byte; got {raw.hex().upper()!r}."
        )
    return {
        "hex": raw.hex().upper(),
        "check": True,
        "parameter": parameter,
        "spi1_hex": f"{spi1:02X}",
        "integrity": dict(_MSL_INTEGRITY)[spi1 & 0b11],
        "ciphering": dict(_MSL_CIPHERING)[(spi1 >> 2) & 0b1],
        "counter": dict(_MSL_COUNTER)[(spi1 >> 3) & 0b11],
    }


def encode_msl(
    *,
    integrity: str | None = None,
    ciphering: str | None = None,
    counter: str | None = None,
    field: bool = False,
) -> str:
    """The Minimum SPI1 byte, or with ``field`` the MSL field ('01' + byte)."""
    def pick(table: tuple[tuple[int, str], ...], name: str | None, default: str, label: str) -> int:
        by_name = {n: v for v, n in table}
        chosen = name or default
        if chosen not in by_name:
            raise ValueError(f"unknown {label} {chosen!r}; allowed: " + ", ".join(by_name))
        return by_name[chosen]

    spi1 = (
        pick(_MSL_INTEGRITY, integrity, "no_integrity", "integrity")
        | pick(_MSL_CIPHERING, ciphering, "no_ciphering", "ciphering") << 2
        | pick(_MSL_COUNTER, counter, "no_counter", "counter") << 3
    )
    data = f"{spi1:02X}"
    return f"{_MSL_PARAMETER_MINIMUM_SPI1:02X}{data}" if field else data


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
# Key attributes, GP Card Spec v2.3.1: usage qualifier §11.1.9 Tables 11-17
# and 11-18 (page 156), access Table 11-19 (page 157), type Table 11-16
# (pages 154-155).
# ----------------------------------------------------------------------

# Masks over the two-byte qualifier; a one-byte qualifier is the first byte,
# the second taken as '00'.
_KEY_USAGE_BITS: tuple[tuple[int, str], ...] = (
    (0x8000, "verification_encryption"),
    (0x4000, "computation_decipherment"),
    (0x2000, "sm_response"),
    (0x1000, "sm_command"),
    (0x0800, "confidentiality"),
    (0x0400, "crypto_checksum"),
    (0x0200, "digital_signature"),
    (0x0100, "crypto_authorization"),
    (0x0080, "key_agreement"),
)


def key_usage_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "bit_mask": mask} for mask, name in _KEY_USAGE_BITS]


def decode_key_usage(value: Any) -> dict[str, Any]:
    text = _strip(value)
    if _HEX_RE.fullmatch(text or "x") is None or len(text) not in (2, 4):
        raise ValueError(f"keyUsageQualifier is 1 or 2 bytes of hex: {value!r}")
    qualifier = int(text, 16) << 8 if len(text) == 2 else int(text, 16)
    flags = [name for mask, name in _KEY_USAGE_BITS if qualifier & mask]
    return {"hex": text.upper(), "flags": flags}


def encode_key_usage(flags: list[str] | None) -> str:
    """One byte, or two when key agreement (the second byte's b8) is set."""
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
    return f"{out:04X}" if out & 0xFF else f"{out >> 8:02X}"


_KEY_ACCESS_VALUES: tuple[tuple[int, str], ...] = (
    (0x00, "SD_AND_ASSOCIATED_APPLICATIONS"),
    (0x01, "SECURITY_DOMAIN_ONLY"),
    (0x02, "ASSOCIATED_APPLICATIONS_NOT_SD"),
    (0xFF, "NOT_AVAILABLE"),
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
    """The key version number byte.

    GP Card Spec v2.3.1 §11.8.2.1 (page 194) codes it '01' to '7F'; the
    bucket reports that range without refusing a value outside it (some test
    profiles carry one). ``reserved_for`` is the range label the decoded view
    gives the byte, from the same table.
    """
    from .saip_asn1_decode import _decode_key_version_number

    byte = _to_byte(value, label="keyVersionNumber")
    decoded = _decode_key_version_number(bytes([byte])) or {}
    return {
        "hex": f"{byte:02X}",
        "value": byte,
        "bucket": "IN_RANGE" if 0x01 <= byte <= 0x7F else "OUT_OF_RANGE",
        "reserved_for": decoded.get("reservedFor"),
    }


_KEY_COMPONENT_TYPES: tuple[tuple[int, str], ...] = (
    (0x80, "DES"),
    (0x85, "TLS_PSK"),
    (0x88, "AES"),
    (0x89, "SM4"),
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
    (0xB2, "ECC_FIELD_PARAMETER_P"),
    (0xB3, "ECC_FIELD_PARAMETER_A"),
    (0xB4, "ECC_FIELD_PARAMETER_B"),
    (0xB5, "ECC_FIELD_PARAMETER_G"),
    (0xB6, "ECC_FIELD_PARAMETER_N"),
    (0xB7, "ECC_FIELD_PARAMETER_K"),
    (0xB8, "SM2_PUBLIC"),
    (0xB9, "SM2_PRIVATE"),
    (0xF0, "ECC_KEY_PARAMETERS_REFERENCE"),
    (0xFF, "EXTENDED_FORMAT"),
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
