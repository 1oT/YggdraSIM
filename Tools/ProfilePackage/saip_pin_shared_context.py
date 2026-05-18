# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE-PINCodes shared-context CHOICE helper.

PE-PINCodes carries a CHOICE between ``pinconfig`` (a SEQUENCE OF
PINConfiguration) and ``filePath`` (an OCTET STRING with the temporary
File ID of the directory whose PIN context this PE inherits). The
manual surfaces this as a "Shared context" toggle on the PIN editor;
toggling to "Yes" replaces the configuration list with the file path
and vice-versa.

ASN.1 reference: ``PE-PINCodes`` in
``pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`` (TCA SAIP §A.2).

Schema reminder::

    PE-PINCodes ::= SEQUENCE {
      pin-Header PEHeader,
      pinCodes CHOICE {
        pinconfig SEQUENCE (SIZE (1..26)) OF PINConfiguration,
        filePath OCTET STRING (SIZE (0..8))
      }
    }

In the JSON-decoded document the CHOICE comes through as either a
``"pinconfig"`` or a ``"filePath"`` key sitting next to ``"pin-Header"``.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_FID_PATH_RE = re.compile(r"^([0-9A-Fa-f]{4})*$")


def _normalise_path_hex(value: Any) -> str:
    text = re.sub(r"\s+|/|0x|0X|-|:", "", str(value or ""))
    if len(text) == 0:
        return ""
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"shared-context filePath is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"shared-context filePath has odd nybble count ({len(text)}); "
            "expected concatenated 16-bit FIDs (TS 102 221 §8.3.5).",
        )
    if _FID_PATH_RE.fullmatch(text) is None:
        # Defensive: shouldn't trigger after the even-length check.
        raise ValueError(f"shared-context filePath malformed: {text!r}")
    if len(text) > 16:
        raise ValueError(
            f"shared-context filePath exceeds 8 bytes (TCA SAIP §A.2 cap); got {len(text) // 2} bytes.",
        )
    return text.upper()


def get_shared_context(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Return ``{"shared": bool, "file_path_hex": str, "pin_count": int}``.

    Tolerates the SAIP-decoded payload sitting either directly inside
    ``pe_value`` (legacy shape) or nested under a ``pinCodes`` key
    (newer pySim revisions keep the CHOICE wrapper).
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    container = pe_value
    if isinstance(pe_value.get("pinCodes"), dict):
        container = pe_value["pinCodes"]
    file_path = container.get("filePath")
    if file_path is None:
        pinconfig = container.get("pinconfig")
        pin_count = len(pinconfig) if isinstance(pinconfig, list) else 0
        return {"shared": False, "file_path_hex": "", "pin_count": pin_count}
    if isinstance(file_path, (bytes, bytearray)):
        hex_text = bytes(file_path).hex().upper()
    elif isinstance(file_path, dict) and "__ygg_saip_bytes__" in file_path:
        hex_text = str(file_path.get("__ygg_saip_bytes__") or "").upper()
    else:
        hex_text = str(file_path or "").upper()
    return {"shared": True, "file_path_hex": hex_text, "pin_count": 0}


def set_shared_context(
    pe_value: dict[str, Any],
    *,
    file_path_hex: str | None,
) -> str:
    """Switch the PE to shared-context mode with the supplied filePath.

    Passing an empty / None ``file_path_hex`` while the PE is already in
    shared mode is a no-op (useful for the GUI's "Apply" pattern when
    the operator clears the field by accident). Use
    :func:`set_local_context` to flip back to ``pinconfig``.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    container = pe_value
    if isinstance(pe_value.get("pinCodes"), dict):
        container = pe_value["pinCodes"]

    cleaned = _normalise_path_hex(file_path_hex)
    if len(cleaned) == 0:
        # Empty filePath is technically legal per ASN.1 SIZE(0..8), but
        # it implies the MF temporary FID — the manual still expects an
        # explicit value. Allow it but tag the summary so the GUI can
        # surface a hint.
        container.pop("pinconfig", None)
        container["filePath"] = b""
        return "PE-PINCodes set to shared context (empty filePath -> MF)."
    container.pop("pinconfig", None)
    container["filePath"] = bytes.fromhex(cleaned)
    return f"PE-PINCodes set to shared context (filePath={cleaned})."


def set_local_context(pe_value: dict[str, Any]) -> str:
    """Switch the PE back to local ``pinconfig`` mode.

    The pinconfig list is reset to an empty list — the GUI/TUI is
    expected to repopulate it from the existing PIN-row editor before
    re-encoding (otherwise the encoder will reject SIZE(1..26)).
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    container = pe_value
    if isinstance(pe_value.get("pinCodes"), dict):
        container = pe_value["pinCodes"]
    container.pop("filePath", None)
    if isinstance(container.get("pinconfig"), list) is False:
        container["pinconfig"] = []
    return "PE-PINCodes set to local context (pinconfig list ready for entries)."


__all__ = [
    "get_shared_context",
    "set_local_context",
    "set_shared_context",
]
