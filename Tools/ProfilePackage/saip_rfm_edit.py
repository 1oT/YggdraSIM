# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SAIP ``PE-RFM`` structured edit helpers.

The PE-RFM element (TCA SAIP v3.4.1 §8.8 / ETSI TS 102 226 v19 §7) binds one
RFM applet instance to its OTA dispatch parameters: a list of TAR
values, the minimum security level, two access-domain bitmaps, and an
optional ADF binding. The binding decides the default directory of an
RFM script: with ``adfRFMAccess`` the named ADF is selected by default
(ADF RFM, TS 102 226 v19 §7.3), without it the MF is (UICC shared file
system RFM, §7.2). Operators need to grow ``tarList`` whenever a new SMS
OTA service is added and to move an instance between the two scopes; the
generic decoded-edit panel can do neither safely. This module exposes
the spec-aware primitives, and the ADF catalogue of a profile so both the
GUI card and the shell verb can name an ADF instead of spelling its AID.

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


def _bytes_or_empty(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return _hex_to_bytes(value)
        except ValueError:
            return b""
    return b""


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
        # per SAIP v3.4.1 §8.8; sniff that combination to recognise them.
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

    TCA SAIP v3.4.1 §8.8 links each RFM instance to at most one ADF, so
    this function replaces the existing section rather than appending.
    An empty access domain inherits the matching UICC domain of the same
    PE, which keeps the field a TS 102 226 v19 §8.2.1.3.2.5 Access Domain
    (an ADP byte, then its ADD) whenever the PE carries one.
    """
    aid = _hex_to_bytes(adf_aid_hex, label="adfAID")
    if not (5 <= len(aid) <= 16):
        raise ValueError(f"adfAID must be 5..16 bytes; got {len(aid)}.")
    block: dict[str, Any] = {"adfAID": aid}
    access = _hex_to_bytes(adf_access_domain_hex, label="adfAccessDomain")
    if len(access) == 0:
        access = _bytes_or_empty(rfm.get("uiccAccessDomain"))
    admin = _hex_to_bytes(adf_admin_access_domain_hex, label="adfAdminAccessDomain")
    if len(admin) == 0:
        admin = _bytes_or_empty(rfm.get("uiccAdminAccessDomain"))
    block["adfAccessDomain"] = access
    block["adfAdminAccessDomain"] = admin
    rfm["adfRFMAccess"] = block
    return f"adfRFMAccess set; ADF AID={aid.hex().upper()}."


def remove_adf_access(rfm: dict[str, Any]) -> str:
    """Drop the optional ``adfRFMAccess`` sub-section."""
    if "adfRFMAccess" not in rfm:
        raise LookupError("PE-RFM has no adfRFMAccess to remove.")
    rfm.pop("adfRFMAccess", None)
    return "adfRFMAccess removed."


# ----------------------------------------------------------------------
# ADF catalogue of the profile
# ----------------------------------------------------------------------

# Section base key -> (member holding the ADF's file list, ADF name).
# TCA SAIP v3.4.1 §8.3.4: PE-USIM carries ``adf-usim``, PE-ISIM
# ``adf-isim`` and PE-CSIM ``adf-csim``; PE-IoT (§8.3.4.8.1) creates the
# MF level and the USIM ADF in one element and reuses ``adf-usim``. The
# ADF's AID is the ``dfName`` of the member's first file descriptor.
_ADF_MEMBER_BY_NAA: dict[str, tuple[str, str]] = {
    "usim": ("adf-usim", "ADF.USIM"),
    "isim": ("adf-isim", "ADF.ISIM"),
    "csim": ("adf-csim", "ADF.CSIM"),
    "iot": ("adf-usim", "ADF.USIM"),
}

_ADF_REFERENCE_RE = re.compile(r"^(?:ADF\.)?(USIM|ISIM|CSIM)$", re.IGNORECASE)


def _first_df_name(files: Any) -> bytes | None:
    """The ``dfName`` of the first file descriptor of a SAIP file list."""
    if isinstance(files, (list, tuple)) is False or len(files) == 0:
        return None
    first = files[0]
    if isinstance(first, (list, tuple)) is False or len(first) != 2:
        return None
    descriptor = first[1]
    if isinstance(descriptor, dict) is False:
        return None
    df_name = _bytes_or_empty(descriptor.get("dfName"))
    if len(df_name) == 0:
        return None
    return df_name


def list_adf_bindings(decoded_document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every ADF the NAA elements of the document create, with its AID.

    One row per PE-USIM / PE-ISIM / PE-CSIM / PE-IoT section:
    ``section_key``, ``pe_index`` (the section's position, which is the
    PE index of an ``all_pe`` document), ``naa``, ``adf`` (``ADF.USIM``
    ...) and ``aid_hex``. A section whose first file carries no
    ``dfName`` is skipped.
    """
    sections = decoded_document.get("sections")
    if isinstance(sections, dict) is False:
        return []
    out: list[dict[str, Any]] = []
    for pe_index, (key, value) in enumerate(sections.items()):
        if isinstance(key, str) is False or isinstance(value, dict) is False:
            continue
        entry = _ADF_MEMBER_BY_NAA.get(re.sub(r"_\d+$", "", key))
        if entry is None:
            continue
        member, adf_name = entry
        aid = _first_df_name(value.get(member))
        if aid is None:
            continue
        out.append(
            {
                "section_key": key,
                "pe_index": pe_index,
                "naa": re.sub(r"_\d+$", "", key),
                "adf": adf_name,
                "aid_hex": aid.hex().upper(),
            }
        )
    return out


def match_adf_binding(
    aid_hex: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """The catalogue row whose AID equals ``aid_hex``, or ``None``."""
    wanted = re.sub(r"\s+", "", str(aid_hex or "")).upper()
    if len(wanted) == 0:
        return None
    for row in bindings:
        if str(row.get("aid_hex", "")).upper() == wanted:
            return row
    return None


def resolve_adf_reference(text: str, bindings: list[dict[str, Any]]) -> str:
    """Turn an ADF name (``USIM``, ``ADF.ISIM``) or an AID into AID hex.

    A name resolves through the catalogue of the profile and fails when
    the profile creates no such ADF; anything else must be a 5..16 byte
    AID (ETSI TS 101 220 v19 §4).
    """
    reference = str(text or "").strip()
    if len(reference) == 0:
        raise ValueError("an ADF name (USIM, ISIM, CSIM) or an AID is required.")
    named = _ADF_REFERENCE_RE.match(reference)
    if named is not None:
        adf_name = "ADF." + named.group(1).upper()
        for row in bindings:
            if row.get("adf") == adf_name:
                return str(row["aid_hex"])
        known = ", ".join(sorted({str(row.get("adf")) for row in bindings})) or "none"
        raise ValueError(f"the profile creates no {adf_name} (ADFs present: {known}).")
    aid = _hex_to_bytes(reference, label="adfAID")
    if not (5 <= len(aid) <= 16):
        raise ValueError(f"adfAID must be 5..16 bytes; got {len(aid)}.")
    return aid.hex().upper()


# ----------------------------------------------------------------------
# Read-side summary
# ----------------------------------------------------------------------


def rfm_summary(
    rfm: dict[str, Any],
    *,
    bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project the PE-RFM section to a JSON-safe summary.

    ``default_directory`` is ``"ADF"`` when ``adfRFMAccess`` is present
    and ``"MF"`` otherwise (TCA SAIP v3.4.1 §8.8). With ``bindings`` (see
    ``list_adf_bindings``) the bound AID is also named (``adf_name``).
    """

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
        aid_hex = _hex_or_empty(adf.get("adfAID"))
        match = match_adf_binding(aid_hex, bindings or [])
        adf_summary = {
            "adf_aid_hex": aid_hex,
            "adf_name": str(match["adf"]) if match is not None else "",
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
        "default_directory": "ADF" if adf_summary is not None else "MF",
        "adf_access": adf_summary,
    }


__all__ = [
    "add_tar",
    "list_adf_bindings",
    "locate_rfm_sections",
    "match_adf_binding",
    "remove_adf_access",
    "remove_tar",
    "resolve_adf_reference",
    "rfm_summary",
    "set_adf_access",
    "set_instance_aid_hex",
    "set_minimum_security_level",
    "set_security_domain_aid_hex",
    "set_tar_list",
    "set_uicc_access_domain",
    "set_uicc_admin_access_domain",
]
