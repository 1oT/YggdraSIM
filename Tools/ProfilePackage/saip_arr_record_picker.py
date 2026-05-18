# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""EF.ARR access-rule picker projection.

ETSI TS 102 221 §9.4 / ISO 7816-4 §5.3.3 specify that file security
attributes can be referenced through a 3-byte tuple ``(EF.ARR FID,
record number)``. The FCP editor uses this module to enumerate the
records of a target EF.ARR section so the operator can pick a record
by index without having to manually parse the BER-TLV access rules.

Inputs are a SAIP-decoded document (the output of
``build_decoded_document_from_sequence``) plus a section_key /
field_path selecting the EF.ARR file. Outputs are JSON-shaped record
descriptors with the canonical ``EF.ARR`` decoder summary attached.
"""

from __future__ import annotations

import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


# Mode-byte tags that ETSI TS 102 221 §9.5 / ISO 7816-4 §5.3.3 use to
# label which APDU clusters an access rule applies to. The dispatcher
# in ``saip_asn1_decode._decode_arr_access_modes`` already produces
# these names; they are duplicated here as a stable enumeration so
# upstream callers can render named badges without importing the
# private helper.
ACCESS_MODE_TOKENS: tuple[str, ...] = (
    "READ",
    "UPDATE",
    "DEACTIVATE",
    "ACTIVATE",
    "TERMINATE",
    "INCREASE",
    "RESIZE",
    "DELETE",
    "DELETE_FILE",
    "MANAGE_SECURITY",
)


def _strip(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def _normalise_fid(value: Any) -> str:
    text = _strip(value)
    if len(text) == 0:
        raise ValueError("EF.ARR file_id is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"EF.ARR file_id is not hexadecimal: {value!r}")
    if len(text) != 4:
        raise ValueError(
            f"EF.ARR file_id must be a 16-bit FID (4 hex digits); got {len(text)}.",
        )
    return text.upper()


def _normalise_record_index(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("record_index must be an integer, not bool.")
    if isinstance(value, int):
        idx = int(value)
    else:
        try:
            idx = int(str(value or "").strip(), 0)
        except (TypeError, ValueError) as err:
            raise ValueError(f"record_index is not an integer: {value!r}") from err
    if idx < 1 or idx > 254:
        raise ValueError(
            f"record_index {idx} out of range — TS 102 221 §9.4 caps "
            "linear-fixed records at 1..254.",
        )
    return idx


def encode_arr_reference(file_id: Any, record_index: Any) -> str:
    """Build the 3-byte ``securityAttributesReferenced`` tag-value.

    Output is ``<FID hi><FID lo><record index>`` upper-cased hex.
    """
    fid_hex = _normalise_fid(file_id)
    record = _normalise_record_index(record_index)
    return f"{fid_hex}{record:02X}"


def decode_arr_reference(hex_value: Any) -> dict[str, Any]:
    """Inverse of ``encode_arr_reference`` for 3-byte references."""
    text = _strip(hex_value)
    if len(text) == 0:
        raise ValueError("securityAttributesReferenced hex is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(
            f"securityAttributesReferenced is not hexadecimal: {hex_value!r}",
        )
    if len(text) == 6:
        return {
            "kind": "long",
            "file_id": text[:4].upper(),
            "record_index": int(text[4:], 16),
            "hex": text.upper(),
        }
    if len(text) == 2:
        # Short form (TS 102 221 §11.1.1 8B tag): SFI in upper 5 bits,
        # record number in lower 3 bits.
        byte = int(text, 16)
        return {
            "kind": "short",
            "short_efid": (byte >> 3) & 0x1F,
            "record_index": byte & 0x07,
            "hex": text.upper(),
        }
    raise ValueError(
        f"securityAttributesReferenced must be 1 or 3 bytes; got {len(text) // 2}.",
    )


def _records_from_show_file_payload(records_payload: Any) -> list[dict[str, Any]]:
    """Project ``saip.show_file``-style ``records`` list onto picker rows."""
    if isinstance(records_payload, list) is False:
        return []
    out: list[dict[str, Any]] = []
    for entry in records_payload:
        if isinstance(entry, dict) is False:
            continue
        record_index = entry.get("record")
        if isinstance(record_index, int) is False:
            continue
        if entry.get("empty") is True:
            out.append(
                {
                    "record_index": int(record_index),
                    "summary": "(empty record — FF padding)",
                    "rule_count": 0,
                    "rules": [],
                    "raw_hex": str(entry.get("raw_hex") or "").upper(),
                    "empty": True,
                },
            )
            continue
        decoded = entry.get("decoded") or {}
        rules = decoded.get("rules") if isinstance(decoded, dict) else None
        out.append(
            {
                "record_index": int(record_index),
                "summary": str(decoded.get("summary", "")) if isinstance(decoded, dict) else "",
                "rule_count": int(decoded.get("ruleCount", 0)) if isinstance(decoded, dict) else 0,
                "rules": rules if isinstance(rules, list) else [],
                "raw_hex": str(entry.get("raw_hex") or "").upper(),
                "empty": False,
            },
        )
    return out


def project_records(records_payload: Any) -> list[dict[str, Any]]:
    """Public entry point — same as ``_records_from_show_file_payload``.

    Kept stable for direct callers that hand in the ``records`` field
    from a ``saip.show_file`` response without going through the
    package-walking dispatcher.
    """
    return _records_from_show_file_payload(records_payload)


def find_matching_record(
    records: list[dict[str, Any]],
    *,
    require_modes: list[str] | None = None,
    forbid_modes: list[str] | None = None,
) -> int | None:
    """Return the 1-based record index of the first record that matches.

    A record is considered to match when *every* token in
    ``require_modes`` appears in the rule's ``accessModes`` and *no*
    token in ``forbid_modes`` is present. ``require_modes`` /
    ``forbid_modes`` are case-insensitive against ``ACCESS_MODE_TOKENS``.
    Returns ``None`` when no record satisfies the constraint.
    """
    require: set[str] = set(
        token.strip().upper() for token in (require_modes or []) if token
    )
    forbid: set[str] = set(
        token.strip().upper() for token in (forbid_modes or []) if token
    )
    for record in records:
        if record.get("empty") is True:
            continue
        rules = record.get("rules") or []
        if isinstance(rules, list) is False:
            continue
        for rule in rules:
            if isinstance(rule, dict) is False:
                continue
            modes = {str(m or "").strip().upper() for m in rule.get("accessModes", [])}
            if require and not require.issubset(modes):
                continue
            if forbid and modes & forbid:
                continue
            idx = record.get("record_index")
            if isinstance(idx, int):
                return int(idx)
    return None


__all__ = [
    "ACCESS_MODE_TOKENS",
    "decode_arr_reference",
    "encode_arr_reference",
    "find_matching_record",
    "project_records",
]
