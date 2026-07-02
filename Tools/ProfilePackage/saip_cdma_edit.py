# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE-CDMAParameter structured edit helpers.

PE-CDMAParameter (TCA SAIP §6.6.6 / 3GPP2 C.S0023 §3.4) groups the
A-Key (CAVE), SSD, HRPD authentication data, Simple-IP CHAP shared
secret, and Mobile-IP shared secret into a single profile element.
This module gives the GUI / TUI a spec-aware mutator surface for each
field so they can move off the raw-JSON-tree fallback.

ASN.1 reference: ``PE-CDMAParameter`` in
``pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`` (TCA SAIP §A.2)::

    PE-CDMAParameter ::= SEQUENCE {
      cdma-header PEHeader,
      authenticationKey OCTET STRING (SIZE(8)),
      ssd OCTET STRING (SIZE(16)) OPTIONAL,
      hrpdAccessAuthenticationData OCTET STRING (SIZE(2..32)) OPTIONAL,
      simpleIPAuthenticationData OCTET STRING (SIZE(3..483)) OPTIONAL,
      mobileIPAuthenticationData OCTET STRING (SIZE(5..957)) OPTIONAL
    }

External references for the optional fields (manual cites these as
3GPP2 [S0016]):
  * SSD: bytes 1..8 = SSD-A, bytes 9..16 = SSD-B (CAVE).
  * HRPD: 3GPP2 S0016 §4.5.7.10 (HRPD CHAP SS).
  * Simple IP: 3GPP2 S0016 §4.5.7.7 (SimpleIP CHAP SS).
  * Mobile IP: 3GPP2 S0016 §4.5.7.8 (MobileIP SS).
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


_CDMA_FIELD_LIMITS: dict[str, tuple[int, int, bool]] = {
    # field_name -> (min_bytes, max_bytes, mandatory)
    "authenticationKey": (8, 8, True),
    "ssd": (16, 16, False),
    "hrpdAccessAuthenticationData": (2, 32, False),
    "simpleIPAuthenticationData": (3, 483, False),
    "mobileIPAuthenticationData": (5, 957, False),
}


def supported_fields() -> dict[str, dict[str, Any]]:
    """Catalog of CDMA fields with their length constraints + mandatory flag."""
    return {
        name: {
            "min_bytes": min_b,
            "max_bytes": max_b,
            "mandatory": mandatory,
        }
        for name, (min_b, max_b, mandatory) in _CDMA_FIELD_LIMITS.items()
    }


def _normalise_hex(value: Any, *, label: str) -> str:
    text = re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return ""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"{label} is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"{label} hex must have an even nybble count (got {len(text)}).",
        )
    return text.upper()


def _bytes_to_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, dict) and "__ygg_saip_bytes__" in value:
        return str(value.get("__ygg_saip_bytes__") or "").upper()
    return ""


def cdma_summary(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe projection of every CDMA field as hex strings."""
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-CDMAParameter value must be a dict.")
    out: dict[str, Any] = {}
    for field in _CDMA_FIELD_LIMITS.keys():
        hex_text = _bytes_to_hex(pe_value.get(field))
        out[field] = hex_text
        if field == "ssd" and len(hex_text) == 32:
            # Split hint for the GUI: SSD-A first 8 bytes, SSD-B last 8.
            out["ssd_a_hex"] = hex_text[:16]
            out["ssd_b_hex"] = hex_text[16:]
    return out


def set_cdma_field(
    pe_value: dict[str, Any],
    *,
    field: str,
    hex_value: Any,
) -> str:
    """Set one CDMA field. Empty hex on optional fields drops the entry."""
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-CDMAParameter value must be a dict.")
    field_text = str(field or "").strip()
    if field_text not in _CDMA_FIELD_LIMITS:
        raise ValueError(
            f"unknown CDMA field {field!r}; allowed: "
            + ", ".join(sorted(_CDMA_FIELD_LIMITS.keys())),
        )
    min_b, max_b, mandatory = _CDMA_FIELD_LIMITS[field_text]
    cleaned = _normalise_hex(hex_value, label=field_text)
    if len(cleaned) == 0:
        if mandatory:
            raise ValueError(
                f"{field_text} is mandatory (TCA SAIP §A.2); cannot clear.",
            )
        pe_value.pop(field_text, None)
        return f"{field_text} cleared."
    raw = bytes.fromhex(cleaned)
    if len(raw) < min_b or len(raw) > max_b:
        if min_b == max_b:
            constraint = f"exactly {min_b} bytes"
        else:
            constraint = f"{min_b}..{max_b} bytes"
        raise ValueError(
            f"{field_text} must be {constraint} per TCA SAIP §A.2 / 3GPP2 S0016; "
            f"got {len(raw)} bytes.",
        )
    pe_value[field_text] = raw
    return f"{field_text} set ({len(raw)} bytes)."


def set_ssd_split(
    pe_value: dict[str, Any],
    *,
    ssd_a_hex: Any = None,
    ssd_b_hex: Any = None,
) -> str:
    """Set ``ssd`` from the SSD-A / SSD-B 8-byte halves.

    Either half may be cleared by passing an empty string — the
    matching half is preserved (and the field is dropped only when
    both halves end up empty).
    """
    current_hex = _bytes_to_hex(pe_value.get("ssd")) if isinstance(pe_value, dict) else ""
    current_a = current_hex[:16] if len(current_hex) == 32 else ""
    current_b = current_hex[16:] if len(current_hex) == 32 else ""

    a_cleaned = _normalise_hex(ssd_a_hex, label="ssd_a") if ssd_a_hex is not None else current_a
    b_cleaned = _normalise_hex(ssd_b_hex, label="ssd_b") if ssd_b_hex is not None else current_b
    if len(a_cleaned) == 0 and len(b_cleaned) == 0:
        if isinstance(pe_value, dict):
            pe_value.pop("ssd", None)
        return "ssd cleared (both halves empty)."
    if len(a_cleaned) != 16 or len(b_cleaned) != 16:
        raise ValueError(
            "ssd_a and ssd_b must each be 8 bytes (16 hex chars). "
            "Provide both halves or clear ssd entirely.",
        )
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-CDMAParameter value must be a dict.")
    pe_value["ssd"] = bytes.fromhex(a_cleaned + b_cleaned)
    return "ssd set (16 bytes; SSD-A + SSD-B)."


__all__ = [
    "cdma_summary",
    "set_cdma_field",
    "set_ssd_split",
    "supported_fields",
]
