# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP ``PE-RFM`` structured edit helpers.

The PE-RFM element (TCA SAIP §A.2 / ETSI TS 102 226 §8.4) binds one
RFM applet instance to its OTA dispatch parameters: a list of TAR
values, the minimum security level, two access-domain bitmaps, and an
optional ADF binding. Operators need to grow ``tarList`` whenever a
new SMS OTA service is added; the generic decoded-edit panel cannot do
that safely. This module exposes the spec-aware primitives.

Decoded shape post ``build_decoded_document_from_sequence``::

    {
      "rfm-header": {...},
      "instanceAID": <bytes>,
      "securityDomainAID": <bytes>,         # optional
      "tarList": [<bytes len=3>, ...],      # optional
      "minimumSecurityLevel": <bytes len=1>,
      "uiccAccessDomain": <bytes>,
      "uiccAdminAccessDomain": <bytes>,
      "adfRFMAccess": {                     # optional
        "adfAID": <bytes>,
        "adfAccessDomain": <bytes>,
        "adfAdminAccessDomain": <bytes>,
      },
    }
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _hex_to_bytes(value: Any, *, label: str = "value", expect_length: int | None = None) -> bytes:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return b""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(f"{label} has odd nybble count ({len(text)}).")
    data = bytes.fromhex(text)
    if expect_length is not None and len(data) != expect_length:
        raise ValueError(
            f"{label} must be exactly {expect_length} bytes; got {len(data)}.",
        )
    return data


def _byte_or_default(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        if isinstance(value, str):
            text = value.strip()
            if len(text) == 0:
                return default
            return int(text, 0) & 0xFF
        return int(value) & 0xFF
    except (TypeError, ValueError):
        raise ValueError(f"expected a byte value, got {value!r}")


def locate_rfm_sections(decoded_document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return every ``(section_key, rfm_dict)`` pair from the document."""
    sections = decoded_document.get("sections")
    if isinstance(sections, dict) is False:
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for key, value in sections.items():
        if isinstance(key, str) is False or isinstance(value, dict) is False:
            continue
        # RFM sections always carry an instanceAID + minimumSecurityLevel
        # per SAIP §A.2; sniff that combination to recognise them.
        if "instanceAID" in value and "minimumSecurityLevel" in value:
            out.append((key, value))
    return out


# ----------------------------------------------------------------------
# TAR list mutators
# ----------------------------------------------------------------------


def add_tar(rfm: dict[str, Any], tar_hex: str) -> str:
    """Append a TAR value (ETSI TS 101 220 §6.2, 3-byte identifier).

    Duplicate TARs are rejected: SMS OTA dispatch matches the first
    entry and an extra row would be dead weight that confuses audits.
    """
    tar_bytes = _hex_to_bytes(tar_hex, label="tar", expect_length=3)
    tar_list = rfm.get("tarList")
    if tar_list is None:
        tar_list = []
        rfm["tarList"] = tar_list
    if isinstance(tar_list, list) is False:
        raise ValueError("tarList is not a list; cannot append.")
    for existing in tar_list:
        if isinstance(existing, (bytes, bytearray)) and bytes(existing) == tar_bytes:
            raise ValueError(
                f"TAR {tar_bytes.hex().upper()} already present in tarList.",
            )
    tar_list.append(tar_bytes)
    return f"added TAR {tar_bytes.hex().upper()}; tarList size={len(tar_list)}."


def remove_tar(rfm: dict[str, Any], tar_hex: str) -> str:
    """Drop the matching TAR entry from ``tarList``."""
    target = _hex_to_bytes(tar_hex, label="tar", expect_length=3)
    tar_list = rfm.get("tarList")
    if isinstance(tar_list, list) is False or len(tar_list) == 0:
        raise LookupError("tarList is empty.")
    for index, entry in enumerate(tar_list):
        if isinstance(entry, (bytes, bytearray)) and bytes(entry) == target:
            del tar_list[index]
            if len(tar_list) == 0:
                rfm.pop("tarList", None)
                return f"removed TAR {target.hex().upper()}; tarList now empty."
            return f"removed TAR {target.hex().upper()}; tarList size={len(tar_list)}."
    raise LookupError(f"no TAR {target.hex().upper()} found in tarList.")


def set_tar_list(rfm: dict[str, Any], tar_hex_list: list[str]) -> str:
    """Replace ``tarList`` with the supplied entries (each 3 hex bytes)."""
    if isinstance(tar_hex_list, (list, tuple)) is False:
        raise ValueError("tar_hex_list must be a list of hex strings.")
    out: list[bytes] = []
    seen: set[bytes] = set()
    for entry in tar_hex_list:
        text = str(entry or "").strip()
        if len(text) == 0:
            continue
        tar_bytes = _hex_to_bytes(text, label="tar", expect_length=3)
        if tar_bytes in seen:
            raise ValueError(f"duplicate TAR {tar_bytes.hex().upper()} in input list.")
        seen.add(tar_bytes)
        out.append(tar_bytes)
    if len(out) == 0:
        rfm.pop("tarList", None)
        return "tarList cleared."
    rfm["tarList"] = out
    return f"tarList replaced ({len(out)} entries)."


# ----------------------------------------------------------------------
# Scalar mutators
# ----------------------------------------------------------------------


def set_instance_aid_hex(rfm: dict[str, Any], hex_value: str) -> str:
    """Replace ``instanceAID`` (RFM applet AID)."""
    aid = _hex_to_bytes(hex_value, label="instanceAID")
    if not (5 <= len(aid) <= 16):
        raise ValueError(f"instanceAID must be 5..16 bytes; got {len(aid)}.")
    rfm["instanceAID"] = aid
    return f"instanceAID set to {aid.hex().upper()}."


def set_security_domain_aid_hex(rfm: dict[str, Any], hex_value: str) -> str:
    """Replace ``securityDomainAID`` (associated SD that authorises OTA)."""
    text = (hex_value or "").strip()
    if len(text) == 0:
        rfm.pop("securityDomainAID", None)
        return "securityDomainAID cleared."
    aid = _hex_to_bytes(text, label="securityDomainAID")
    if not (5 <= len(aid) <= 16):
        raise ValueError(f"securityDomainAID must be 5..16 bytes; got {len(aid)}.")
    rfm["securityDomainAID"] = aid
    return f"securityDomainAID set to {aid.hex().upper()}."


def set_minimum_security_level(rfm: dict[str, Any], value: int | str) -> str:
    """Replace ``minimumSecurityLevel`` (ETSI TS 102 225 §5.1.1 MSL byte)."""
    msl = _byte_or_default(value, 0x00)
    rfm["minimumSecurityLevel"] = bytes([msl])
    return f"minimumSecurityLevel set to 0x{msl:02X}."


def set_uicc_access_domain(rfm: dict[str, Any], hex_value: str) -> str:
    """Replace ``uiccAccessDomain`` (TS 102 226 §8.4 access bitmap)."""
    raw = _hex_to_bytes(hex_value, label="uiccAccessDomain")
    rfm["uiccAccessDomain"] = raw
    return f"uiccAccessDomain set ({len(raw)} bytes)."


def set_uicc_admin_access_domain(rfm: dict[str, Any], hex_value: str) -> str:
    """Replace ``uiccAdminAccessDomain``."""
    raw = _hex_to_bytes(hex_value, label="uiccAdminAccessDomain")
    rfm["uiccAdminAccessDomain"] = raw
    return f"uiccAdminAccessDomain set ({len(raw)} bytes)."


# ----------------------------------------------------------------------
# ADF binding
# ----------------------------------------------------------------------


def set_adf_access(
    rfm: dict[str, Any],
    *,
    adf_aid_hex: str,
    adf_access_domain_hex: str = "",
    adf_admin_access_domain_hex: str = "",
) -> str:
    """Install / replace the ``adfRFMAccess`` sub-section.

    ETSI TS 102 226 §8.4 caps each RFM instance to one ADF binding so
    this function replaces the existing section rather than appending.
    """
    aid = _hex_to_bytes(adf_aid_hex, label="adfAID")
    if not (5 <= len(aid) <= 16):
        raise ValueError(f"adfAID must be 5..16 bytes; got {len(aid)}.")
    block: dict[str, Any] = {"adfAID": aid}
    block["adfAccessDomain"] = _hex_to_bytes(adf_access_domain_hex, label="adfAccessDomain")
    block["adfAdminAccessDomain"] = _hex_to_bytes(
        adf_admin_access_domain_hex, label="adfAdminAccessDomain"
    )
    rfm["adfRFMAccess"] = block
    return f"adfRFMAccess set; ADF AID={aid.hex().upper()}."


def remove_adf_access(rfm: dict[str, Any]) -> str:
    """Drop the optional ``adfRFMAccess`` sub-section."""
    if "adfRFMAccess" not in rfm:
        raise LookupError("PE-RFM has no adfRFMAccess to remove.")
    rfm.pop("adfRFMAccess", None)
    return "adfRFMAccess removed."


# ----------------------------------------------------------------------
# Read-side summary
# ----------------------------------------------------------------------


def rfm_summary(rfm: dict[str, Any]) -> dict[str, Any]:
    """Project the PE-RFM section to a JSON-safe summary."""

    def _hex_or_empty(value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex().upper()
        return ""

    tar_list = rfm.get("tarList") or []
    tar_out: list[str] = []
    if isinstance(tar_list, list):
        for tar in tar_list:
            if isinstance(tar, (bytes, bytearray)) and len(tar) == 3:
                tar_out.append(bytes(tar).hex().upper())

    msl_raw = rfm.get("minimumSecurityLevel")
    msl_int = (
        msl_raw[0]
        if isinstance(msl_raw, (bytes, bytearray)) and len(msl_raw) >= 1
        else 0
    )

    adf = rfm.get("adfRFMAccess") if isinstance(rfm.get("adfRFMAccess"), dict) else None
    adf_summary: dict[str, str] | None = None
    if adf is not None:
        adf_summary = {
            "adf_aid_hex": _hex_or_empty(adf.get("adfAID")),
            "adf_access_domain_hex": _hex_or_empty(adf.get("adfAccessDomain")),
            "adf_admin_access_domain_hex": _hex_or_empty(adf.get("adfAdminAccessDomain")),
        }

    return {
        "instance_aid_hex": _hex_or_empty(rfm.get("instanceAID")),
        "security_domain_aid_hex": _hex_or_empty(rfm.get("securityDomainAID")),
        "tar_list": tar_out,
        "minimum_security_level": msl_int,
        "uicc_access_domain_hex": _hex_or_empty(rfm.get("uiccAccessDomain")),
        "uicc_admin_access_domain_hex": _hex_or_empty(rfm.get("uiccAdminAccessDomain")),
        "adf_access": adf_summary,
    }


__all__ = [
    "add_tar",
    "locate_rfm_sections",
    "remove_adf_access",
    "remove_tar",
    "rfm_summary",
    "set_adf_access",
    "set_instance_aid_hex",
    "set_minimum_security_level",
    "set_security_domain_aid_hex",
    "set_tar_list",
    "set_uicc_access_domain",
    "set_uicc_admin_access_domain",
]
