# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP ``ProfileHeader`` structured edit helpers.

The header PE carries the most operator-edited metadata in any SAIP
profile (ICCID, mandatory services, GFSTE list, mandatory AIDs,
connectivity parameters, IoT PIX). Putting the mutation logic here —
rather than spreading it across the GUI action dispatchers — keeps
the spec-aware shape rules in one place and lets the TUI / browser
editor share the same primitives.

ASN.1 reference: ``ProfileHeader`` and ``ServicesList`` in
``pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`` (TCA SAIP §A.2).

Header section layout in the decoded document (post
``build_decoded_document_from_sequence``)::

    {
      "major-version": 2,
      "minor-version": 3,
      "profileType": "<utf8 1..100>",
      "iccid": <bytes len=10>,
      "pol": <bytes optional>,
      "eUICC-Mandatory-services": {"usim": None, "milenage": None, ...},
      "eUICC-Mandatory-GFSTEList": ["2.23.143.1.2.3", ...],
      "connectivityParameters": <bytes optional>,
      "eUICC-Mandatory-AIDs": [{"aid": <bytes>, "version": <bytes len=2>}, ...],
      "iotOptions": {"pix": <bytes len=7..11>},
    }

All mutators operate **in place** on the header dict and return a
short summary string the GUI can surface as a toast. Callers are
responsible for re-encoding the sequence (``build_profile_sequence_from_document``)
and flagging the session dirty.
"""

from __future__ import annotations

import re
from typing import Any


SERVICES_LIST_KEYS: tuple[str, ...] = (
    "contactless",
    "usim",
    "isim",
    "csim",
    "milenage",
    "tuak128",
    "cave",
    "gba-usim",
    "gba-isim",
    "mbms",
    "eap",
    "javacard",
    "multos",
    "multiple-usim",
    "multiple-isim",
    "multiple-csim",
    "tuak256",
    "usim-test-algorithm",
    "ber-tlv",
    "dfLink",
    "cat-tp",
    "get-identity",
    "profile-a-x25519",
    "profile-b-p256",
    "suciCalculatorApi",
    "dns-resolution",
    "scp11ac",
    "scp11c-authorization-mechanism",
    "s16mode",
    "eaka",
)


SERVICES_LIST_LABELS: dict[str, str] = {
    "contactless": "Contactless (SWP / HCI)",
    "usim": "USIM (3GPP)",
    "isim": "ISIM (3GPP)",
    "csim": "CSIM (3GPP2)",
    "milenage": "MILENAGE",
    "tuak128": "TUAK 128-bit",
    "tuak256": "TUAK 256-bit",
    "cave": "CAVE (legacy)",
    "usim-test-algorithm": "USIM test algorithm",
    "gba-usim": "GBA on USIM",
    "gba-isim": "GBA on ISIM",
    "mbms": "MBMS",
    "eap": "EAP",
    "javacard": "JavaCard runtime",
    "multos": "MULTOS runtime",
    "multiple-usim": "Multiple USIM instances",
    "multiple-isim": "Multiple ISIM instances",
    "multiple-csim": "Multiple CSIM instances",
    "ber-tlv": "BER-TLV files",
    "dfLink": "Linked DFs",
    "cat-tp": "CAT_TP transport",
    "get-identity": "5G GET IDENTITY",
    "profile-a-x25519": "5G SUCI Profile A (X25519)",
    "profile-b-p256": "5G SUCI Profile B (P-256)",
    "suciCalculatorApi": "SUCI Calculator API",
    "dns-resolution": "DNS resolution",
    "scp11ac": "GP Amd F SCP11ac",
    "scp11c-authorization-mechanism": "SCP11c authorisation mechanism",
    "s16mode": "GP Amd D / Amd F S16 mode",
    "eaka": "Enhanced AKA (3GPP)",
}


# Header section keys observed in the wild — pySim's encoder uses
# ``"header"`` post-decoding, but legacy / vendor packages sometimes
# write ``"profileHeader"``. Both are accepted for lookup.
_HEADER_SECTION_KEYS: tuple[str, ...] = ("header", "profileHeader")


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_OID_RE = re.compile(r"^[0-9]+(\.[0-9]+)*$")
_DIGITS_RE = re.compile(r"^[0-9]+$")


def locate_header_section(decoded_document: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return ``(section_key, header_dict)`` for the ProfileHeader PE.

    Raises ``LookupError`` when the document carries no ProfileHeader,
    which only happens for malformed test fixtures — every TCA SAIP
    profile MUST start with one (see TCA SAIP §A.2).
    """
    sections = decoded_document.get("sections")
    if isinstance(sections, dict) is False:
        raise LookupError("decoded_document has no 'sections' map.")
    for candidate in _HEADER_SECTION_KEYS:
        if candidate in sections and isinstance(sections[candidate], dict):
            return candidate, sections[candidate]
    raise LookupError(
        "ProfileHeader section not found (looked for "
        + " / ".join(_HEADER_SECTION_KEYS)
        + ").",
    )


# ----------------------------------------------------------------------
# Hex normalisation
# ----------------------------------------------------------------------


def _normalise_hex(value: Any, *, even_length: bool = True, label: str = "value") -> str:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return ""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if even_length and len(text) % 2 != 0:
        raise ValueError(
            f"{label} has odd length ({len(text)} nybbles); expected an even number of hex chars.",
        )
    return text.upper()


def _hex_to_bytes(value: Any, *, label: str = "value") -> bytes:
    cleaned = _normalise_hex(value, even_length=True, label=label)
    return bytes.fromhex(cleaned) if len(cleaned) > 0 else b""


def _bytes_field_repr(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, dict) and "__ygg_saip_bytes__" in value:
        raw = str(value.get("__ygg_saip_bytes__") or "")
        return raw.upper()
    return ""


# ----------------------------------------------------------------------
# ICCID helpers
# ----------------------------------------------------------------------


def _iccid_digits_to_bcd_bytes(digits: str) -> bytes:
    """Encode 19/20-digit ICCID into 10 bytes (manual: encoded, not nibble-swapped)."""
    cleaned = re.sub(r"\s+|-", "", digits or "")
    if _DIGITS_RE.fullmatch(cleaned) is None:
        raise ValueError(f"ICCID must contain digits only: {digits!r}")
    if len(cleaned) not in (19, 20):
        raise ValueError(
            f"ICCID must be 19 or 20 digits per ITU-T E.118 / SGP.22 §A.2 (got {len(cleaned)}).",
        )
    if len(cleaned) == 19:
        cleaned = cleaned + "F"
    out = bytearray(10)
    for index in range(10):
        high = cleaned[index * 2]
        low = cleaned[index * 2 + 1]
        # TS 102 221 §13.2 — ICCID stored as BCD, low nybble first
        # (i.e. swapped); the manual phrasing "encoded, not nibble-
        # swapped" refers to the operator-facing input string, which
        # we preserve as-is and only swap when packing.
        out[index] = (int(low, 16) << 4) | int(high, 16)
    return bytes(out)


def _iccid_bcd_bytes_to_digits(raw: bytes) -> str:
    if len(raw) == 0:
        return ""
    digits = []
    for byte in raw:
        digits.append(f"{byte & 0x0F:X}")
        digits.append(f"{(byte >> 4) & 0x0F:X}")
    text = "".join(digits)
    text = text.rstrip("F")
    return text


# ----------------------------------------------------------------------
# Mutators
# ----------------------------------------------------------------------


def set_major_minor_version(
    header: dict[str, Any],
    *,
    major: int | str | None = None,
    minor: int | str | None = None,
) -> str:
    """Replace the SAIP ``major-version`` / ``minor-version`` UInt8 pair.

    Both arguments are optional: ``None`` leaves the corresponding field
    untouched, an empty string clears it (rare — TCA SAIP §A.2 marks
    both as mandatory but the encoder fills in safe defaults when
    absent). Values are validated against the UInt8 range [0..255].

    Versions are normally pinned by the spec revision the profile
    targets (e.g. 3/3 for SAIP 3.3, 3/4 for SAIP 3.4). Letting an
    operator override them is useful when downgrading a profile for a
    bootstrap that only handles an earlier major revision.
    """
    changes: list[str] = []
    for label, field, value in (("major", "major-version", major), ("minor", "minor-version", minor)):
        if value is None:
            continue
        text = str(value).strip()
        if len(text) == 0:
            header.pop(field, None)
            changes.append(f"{label}-version cleared")
            continue
        try:
            parsed = int(text, 0)
        except ValueError:
            raise ValueError(f"{label}-version must be an integer (got {value!r}).")
        if not (0 <= parsed <= 255):
            raise ValueError(
                f"{label}-version must fit in UInt8 [0..255]; got {parsed}.",
            )
        header[field] = parsed
        changes.append(f"{label}-version={parsed}")
    if len(changes) == 0:
        return "no version fields updated."
    return ", ".join(changes) + "."


def set_profile_type(header: dict[str, Any], value: str | None) -> str:
    """Replace ``profileType`` (free-form 1..100 char UTF-8 label)."""
    text = str(value or "").strip()
    if len(text) == 0:
        header.pop("profileType", None)
        return "profileType cleared."
    if len(text) > 100:
        raise ValueError(
            f"profileType must be 1..100 characters (got {len(text)}); "
            "TCA SAIP §A.2 caps the label.",
        )
    header["profileType"] = text
    return f"profileType set to {text!r}."


def set_iccid_digits(header: dict[str, Any], digits: str | None) -> str:
    """Replace ``iccid`` from a 19/20-digit decimal string."""
    cleaned = re.sub(r"\s+|-", "", str(digits or ""))
    if len(cleaned) == 0:
        raise ValueError("ICCID is mandatory in ProfileHeader (TCA SAIP §A.2).")
    encoded = _iccid_digits_to_bcd_bytes(cleaned)
    header["iccid"] = encoded
    return f"iccid set to {cleaned} ({len(encoded)} bytes)."


def set_iccid_hex(header: dict[str, Any], hex_value: str | None) -> str:
    """Replace ``iccid`` directly from a 20-nybble hex string (already swapped)."""
    cleaned = _normalise_hex(hex_value, even_length=True, label="iccid")
    if len(cleaned) != 20:
        raise ValueError(
            f"iccid hex must be exactly 20 nybbles (10 bytes); got {len(cleaned)}.",
        )
    header["iccid"] = bytes.fromhex(cleaned)
    return f"iccid set to {cleaned}."


def set_pol_hex(header: dict[str, Any], hex_value: str | None) -> str:
    """Replace ``pol`` (policy rules bitmask, SGP.02 §5.1.3.5)."""
    text = _normalise_hex(hex_value, even_length=True, label="pol")
    if len(text) == 0:
        header.pop("pol", None)
        return "pol cleared."
    header["pol"] = bytes.fromhex(text)
    return f"pol set to {text}."


def set_mandatory_services(header: dict[str, Any], services: dict[str, Any]) -> str:
    """Replace ``eUICC-Mandatory-services``.

    Accepts a dict of ``{key: bool}`` (truthy → present, falsy → absent)
    or ``{key: None}`` (always present). Unknown keys raise ``ValueError``
    so the GUI cannot smuggle in misspellings.
    """
    if isinstance(services, dict) is False:
        raise ValueError("services must be a dict mapping service-name -> bool.")
    out: dict[str, None] = {}
    for raw_key, raw_value in services.items():
        key = str(raw_key or "").strip()
        if key not in SERVICES_LIST_KEYS:
            raise ValueError(
                f"unknown mandatory service {key!r}; allowed: "
                + ", ".join(SERVICES_LIST_KEYS),
            )
        present = bool(raw_value) if raw_value is not None else True
        if present:
            out[key] = None
    header["eUICC-Mandatory-services"] = out
    return f"eUICC-Mandatory-services set ({len(out)} entries)."


def set_mandatory_gfste(header: dict[str, Any], oid_list: list[Any] | None) -> str:
    """Replace ``eUICC-Mandatory-GFSTEList`` with a list of OID strings."""
    if oid_list is None:
        oid_list = []
    if isinstance(oid_list, (list, tuple)) is False:
        raise ValueError("oid_list must be a list of OID strings.")
    cleaned: list[str] = []
    for entry in oid_list:
        text = str(entry or "").strip()
        if len(text) == 0:
            continue
        if _OID_RE.fullmatch(text) is None:
            raise ValueError(f"{text!r} is not a valid dotted OID.")
        cleaned.append(text)
    header["eUICC-Mandatory-GFSTEList"] = cleaned
    return f"eUICC-Mandatory-GFSTEList set ({len(cleaned)} OIDs)."


def set_mandatory_aids(header: dict[str, Any], aids: list[Any] | None) -> str:
    """Replace ``eUICC-Mandatory-AIDs`` with a list of {aid_hex, version_hex}."""
    if aids is None:
        aids = []
    if isinstance(aids, (list, tuple)) is False:
        raise ValueError("aids must be a list of {aid, version} entries.")
    out: list[dict[str, bytes]] = []
    for entry in aids:
        if isinstance(entry, dict) is False:
            raise ValueError(f"each AID entry must be a dict: {entry!r}")
        aid_hex = entry.get("aid") if "aid" in entry else entry.get("aid_hex")
        version_hex = entry.get("version") if "version" in entry else entry.get("version_hex")
        aid_bytes = _hex_to_bytes(aid_hex, label="aid")
        if not (5 <= len(aid_bytes) <= 16):
            raise ValueError(
                f"AID must be 5..16 bytes (ISO 7816-5); got {len(aid_bytes)}.",
            )
        version_bytes = _hex_to_bytes(version_hex, label="version")
        if len(version_bytes) != 2:
            raise ValueError(
                f"AID version must be 2 bytes (TCA SAIP §A.2); got {len(version_bytes)}.",
            )
        out.append({"aid": aid_bytes, "version": version_bytes})
    if len(out) == 0:
        header.pop("eUICC-Mandatory-AIDs", None)
    else:
        header["eUICC-Mandatory-AIDs"] = out
    return f"eUICC-Mandatory-AIDs set ({len(out)} entries)."


def set_connectivity_parameters_hex(header: dict[str, Any], hex_value: str | None) -> str:
    """Replace ``connectivityParameters`` (opaque BER-TLV blob, SGP.02 §5.4)."""
    text = _normalise_hex(hex_value, even_length=True, label="connectivityParameters")
    if len(text) == 0:
        header.pop("connectivityParameters", None)
        return "connectivityParameters cleared."
    header["connectivityParameters"] = bytes.fromhex(text)
    return f"connectivityParameters set ({len(text) // 2} bytes)."


def set_iot_pix_hex(header: dict[str, Any], hex_value: str | None) -> str:
    """Replace ``iotOptions.pix`` (IoT Minimal Profile PIX, profile 3.3+)."""
    text = _normalise_hex(hex_value, even_length=True, label="iotOptions.pix")
    if len(text) == 0:
        header.pop("iotOptions", None)
        return "iotOptions cleared."
    pix_bytes = bytes.fromhex(text)
    if not (7 <= len(pix_bytes) <= 11):
        raise ValueError(
            f"iotOptions.pix must be 7..11 bytes per TCA SAIP §A.2; got {len(pix_bytes)}.",
        )
    header["iotOptions"] = {"pix": pix_bytes}
    return f"iotOptions.pix set ({len(pix_bytes)} bytes)."


# ----------------------------------------------------------------------
# Read-side helpers (used by the GUI to render the editor)
# ----------------------------------------------------------------------


def header_summary(header: dict[str, Any]) -> dict[str, Any]:
    """Project the header into a JSON-safe summary the GUI can render."""
    iccid_raw = header.get("iccid")
    iccid_bytes = b""
    if isinstance(iccid_raw, (bytes, bytearray)):
        iccid_bytes = bytes(iccid_raw)
    elif isinstance(iccid_raw, dict) and "__ygg_saip_bytes__" in iccid_raw:
        try:
            iccid_bytes = bytes.fromhex(str(iccid_raw["__ygg_saip_bytes__"]))
        except ValueError:
            iccid_bytes = b""

    services = header.get("eUICC-Mandatory-services") or {}
    if isinstance(services, dict) is False:
        services = {}

    aids_in = header.get("eUICC-Mandatory-AIDs") or []
    aids_out: list[dict[str, str]] = []
    if isinstance(aids_in, list):
        for entry in aids_in:
            if isinstance(entry, dict) is False:
                continue
            aids_out.append(
                {
                    "aid_hex": _bytes_field_repr(entry.get("aid")),
                    "version_hex": _bytes_field_repr(entry.get("version")),
                }
            )

    iot = header.get("iotOptions") or {}
    iot_pix_hex = ""
    if isinstance(iot, dict):
        iot_pix_hex = _bytes_field_repr(iot.get("pix"))

    return {
        "major_version": int(header.get("major-version") or 0),
        "minor_version": int(header.get("minor-version") or 0),
        "profile_type": str(header.get("profileType") or ""),
        "iccid_hex": iccid_bytes.hex().upper(),
        "iccid_digits": _iccid_bcd_bytes_to_digits(iccid_bytes),
        "pol_hex": _bytes_field_repr(header.get("pol")),
        "mandatory_services": {
            key: True for key in services.keys() if key in SERVICES_LIST_KEYS
        },
        "mandatory_gfste": list(header.get("eUICC-Mandatory-GFSTEList") or []),
        "mandatory_aids": aids_out,
        "connectivity_parameters_hex": _bytes_field_repr(
            header.get("connectivityParameters")
        ),
        "iot_pix_hex": iot_pix_hex,
    }


__all__ = [
    "SERVICES_LIST_KEYS",
    "SERVICES_LIST_LABELS",
    "header_summary",
    "locate_header_section",
    "set_connectivity_parameters_hex",
    "set_iccid_digits",
    "set_iccid_hex",
    "set_iot_pix_hex",
    "set_major_minor_version",
    "set_mandatory_aids",
    "set_mandatory_gfste",
    "set_mandatory_services",
    "set_pol_hex",
    "set_profile_type",
]
