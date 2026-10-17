# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""PE-PINCodes shared-context CHOICE helper.

PE-PINCodes carries a CHOICE between ``pinconfig`` (a SEQUENCE OF
PINConfiguration) and ``filePath`` (an OCTET STRING with the temporary
File ID of the directory whose PIN context this PE inherits). The
manual surfaces this as a "Shared context" toggle on the PIN editor;
toggling to "Yes" replaces the configuration list with the file path
and vice-versa.

ASN.1 reference: ``PE-PINCodes`` in
``pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`` (TCA SAIP v3.4.1 §8.5.1).

Schema reminder::

    PE-PINCodes ::= SEQUENCE {
      pin-Header PEHeader,
      pinCodes CHOICE {
        pinconfig SEQUENCE (SIZE (1..26)) OF PINConfiguration,
        filePath OCTET STRING (SIZE (0..8))
      }
    }

The SAIP JSON codec and pySim keep the CHOICE as a two-element tuple,
``pinCodes: ("pinconfig", [...])`` or ``pinCodes: ("filePath", b"...")``;
that is the shape every writer here produces. Older documents put a
``"pinconfig"`` or ``"filePath"`` key in a ``pinCodes`` dict or next to
``"pin-Header"``; readers still accept those.
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
            f"shared-context filePath exceeds 8 bytes (TCA SAIP v3.4.1 §8.5.1 cap); got {len(text) // 2} bytes.",
        )
    return text.upper()


def _choice(pe_value: dict[str, Any]) -> tuple[str, Any] | None:
    """The ``pinCodes`` CHOICE as ``(alternative, payload)``, or ``None``."""
    value = pe_value.get("pinCodes")
    if (
        isinstance(value, (tuple, list))
        and len(value) == 2
        and value[0] in ("pinconfig", "filePath")
    ):
        return (str(value[0]), value[1])
    container = value if isinstance(value, dict) else pe_value
    if "filePath" in container:
        return ("filePath", container["filePath"])
    if "pinconfig" in container:
        return ("pinconfig", container["pinconfig"])
    return None


def _write_choice(pe_value: dict[str, Any], alternative: str, payload: Any) -> None:
    """Store the CHOICE in the codec's tuple shape, dropping older spellings."""
    pe_value.pop("filePath", None)
    pe_value.pop("pinconfig", None)
    pe_value["pinCodes"] = (alternative, payload)


def get_shared_context(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Return ``{"shared": bool, "file_path_hex": str, "pin_count": int}``."""
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    choice = _choice(pe_value)
    if choice is None or choice[0] == "pinconfig":
        pinconfig = choice[1] if choice is not None else None
        pin_count = len(pinconfig) if isinstance(pinconfig, list) else 0
        return {"shared": False, "file_path_hex": "", "pin_count": pin_count}
    file_path = choice[1]
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

    TCA SAIP v3.4.1 page 52: ``filePath`` names the DF or ADF whose PINs this
    context shares, an ADF by its temporary file ID. An empty value is legal
    per SIZE (0..8) and names the MF. Use :func:`set_local_context` to flip
    back to ``pinconfig``.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    cleaned = _normalise_path_hex(file_path_hex)
    _write_choice(pe_value, "filePath", bytes.fromhex(cleaned))
    if len(cleaned) == 0:
        return "PE-PINCodes set to shared context (empty filePath -> MF)."
    return f"PE-PINCodes set to shared context (filePath={cleaned})."


def set_local_context(pe_value: dict[str, Any]) -> str:
    """Switch the PE back to local ``pinconfig`` mode.

    A PE already local keeps its PINs; one coming from a shared context
    starts with an empty list, which the PIN editor fills before the PE
    encodes (``pinconfig`` is SIZE (1..26)).
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-PINCodes value must be a dict.")
    choice = _choice(pe_value)
    pins = choice[1] if choice is not None and choice[0] == "pinconfig" else None
    _write_choice(pe_value, "pinconfig", pins if isinstance(pins, list) else [])
    return "PE-PINCodes set to local context (pinconfig list ready for entries)."


__all__ = [
    "get_shared_context",
    "set_local_context",
    "set_shared_context",
]
