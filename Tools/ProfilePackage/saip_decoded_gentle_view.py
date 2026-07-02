# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Human-facing summaries for round-trip decoded SAIP field payloads.

The wire editor still round-trips JSON-shaped ``payload`` dicts. This
module turns those dicts into short label/value rows for a default
``Decoded`` tab so operators are not forced to read raw JSON first.
"""

from __future__ import annotations

from typing import Any


def operator_field_heading(field_name: str, *, last_ef_key: str | None) -> str:
    """Return a neutral heading for the decoded field (not ASN.1 jargon)."""
    base = str(field_name or "").strip()
    ef = str(last_ef_key or "").strip()
    if base.lower() == "fillfilecontent":
        return f"File data — {ef}" if len(ef) > 0 else "File data"
    if base.lower() == "filedescriptor":
        return "File descriptor (FCP)"
    if len(ef) > 0:
        return f"{base} — {ef}"
    return base or "Field"


def _skip_internal_key(key: str) -> bool:
    return key.startswith("_ygg_")


def _format_scalar(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        text = value.strip()
        return text[:45] + "…" if len(text) > 48 else text
    if isinstance(value, dict):
        return f"{{… {len(value)} keys}}"
    if isinstance(value, list):
        return f"[… {len(value)} items]"
    return str(type(value).__name__)


def gentle_summary_rows(
    field_name: str,
    payload: dict[str, Any] | None,
    *,
    last_ef_key: str | None = None,
    editor_kind: str = "",
) -> list[tuple[str, str]]:
    """Return (label, value) rows for the default decoded tab."""
    rows: list[tuple[str, str]] = []
    base = str(field_name or "").strip().lower()
    if payload is None or (isinstance(payload, (dict, list)) and len(payload) == 0):
        rows.append(("Status", "(empty payload)"))
        return rows
    # Dispatch list-shaped payloads (GFSTEList, AIDs) before the dict guard
    if isinstance(payload, list):
        if "mandatory-gfste" in base or "gfstelist" in base:
            return _summarise_gfste(payload)
        if "mandatory-aids" in base:
            return _summarise_aids(payload)
        rows.append(("Items", f"[{len(payload)} entries]"))
        return rows
    if isinstance(payload, dict) is False:
        rows.append(("Value", _format_scalar(payload)))
        return rows
    if base == "filedescriptor":
        rows.append(("Descriptor", "Same FCP bytes as the File System metadata column — edit there; SHOW JSON keeps the ASN.1-shaped dump for tooling."))
        return rows
    if base == "fillfilecontent":
        return _summarise_fill_file(payload)
    if base == "connectivityparameters":
        return _summarise_connectivity(payload)
    if "mandatory-services" in base:
        return _summarise_services(payload)
    if "mandatory-gfste" in base or base == "euicc-mandatory-gfstelist":
        return _summarise_gfste(payload)
    if "mandatory-aids" in base or base == "euicc-mandatory-aids":
        return _summarise_aids(payload)
    if base in ("iotoptions", "pix", "iot"):
        return _summarise_iot(payload)
    if base in ("pol", "major-version", "minor-version", "profileversion",
                 "serialnumber", "notificationaddress", "iccid", "profiletype"):
        return _summarise_profile_scalar(base, payload)
    if base == "euicc-mandatory-gfstelist":
        return _summarise_gfste(payload)
    kind = str(editor_kind or "").strip().lower()
    if kind == "readonly_json":
        rows.append(("View", "Read-only decode — SHOW JSON for full structure."))
    return _summarise_generic(payload)


def _summarise_fill_file(payload: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    fmt = str(payload.get("format", "") or "").strip()
    if len(fmt) > 0:
        rows.append(("Layout", fmt))
    if "ruleCount" in payload:
        rows.append(("Access rules", _format_scalar(payload.get("ruleCount"))))
    if "records" in payload and isinstance(payload["records"], list):
        rows.append(("Records", str(len(payload["records"]))))
    items = payload.get("items")
    if isinstance(items, list):
        rows.append(("Items", str(len(items))))
    for key in sorted(payload.keys()):
        if _skip_internal_key(key) or key in {"format", "ruleCount", "records", "items", "hex"}:
            continue
        rows.append((key.replace("_", " ").title(), _format_scalar(payload.get(key))))
    return rows


# ---- Connectivity parameters (ultra-compact: one line per section) ----------


def _summarise_connectivity(payload: dict[str, Any]) -> list[tuple[str, str]]:
    items = payload.get("items")
    if isinstance(items, list) is False or len(items) == 0:
        return [("Status", "(empty)")]
    rows: list[tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _connectivity_section_name(str(item.get("tag", "") or "").strip())
        blurb = _connectivity_item_blurb(item)
        rows.append((name, blurb if len(blurb) > 0 else "(empty section)"))
    return rows


def _connectivity_section_name(tag: str) -> str:
    names = {"A0": "SMS Connectivity", "A1": "HTTP Connectivity", "A2": "CAT_TP Connectivity"}
    return names.get(tag.upper(), f"Section {tag}")


def _connectivity_item_blurb(item: dict[str, Any]) -> str:
    children = item.get("items")
    if isinstance(children, list) is False:
        return str(item.get("raw", "") or "")[:32]
    parts: list[str] = []
    for child in children:
        if not isinstance(child, dict):
            continue
        child_tag = str(child.get("tag", "") or "").strip()
        decoded = child.get("decoded")
        if isinstance(decoded, dict):
            part = _connectivity_child_blurb(child_tag, decoded)
        else:
            part = str(child.get("raw", "") or "")[:16]
        if len(part) > 0:
            parts.append(part)
    return " · ".join(parts)


def _connectivity_child_blurb(tag: str, decoded: dict[str, Any]) -> str:
    if tag == "06":
        digits = str(decoded.get("dialingDigits", "") or "").strip()
        ton = str(decoded.get("ton", "") or "").strip()
        return f"SMSC {ton} {digits}" if len(digits) > 0 else ""
    if tag == "81":
        name = str(decoded.get("name", "") or "").strip()
        return name if len(name) > 0 else f"PID {decoded.get('decimal', '?')}"
    if tag == "82":
        grp = str(decoded.get("codingGroup", "") or "").strip()
        cls_ = str(decoded.get("messageClass", "") or "").strip()
        alpha = str(decoded.get("alphabet", "") or "").strip()
        return f"DCS {alpha}/{cls_}" if len(cls_) > 0 else (grp or f"DCS {decoded.get('decimal', '?')}")
    if tag == "35":
        bt = str(decoded.get("bearerType", "") or "").strip()
        return f"Bearer {bt}" if len(bt) > 0 else ""
    if tag == "47":
        name = str(decoded.get("name", "") or "").strip()
        return f"NAN {name}" if len(name) > 0 else ""
    if tag == "0D":
        name = str(decoded.get("name", "") or "").strip()
        return f"Cred {name}" if len(name) > 0 else ""
    if "decimal" in decoded:
        return f"{decoded['decimal']}"
    if "address" in decoded:
        return str(decoded["address"])
    return str(decoded.get("raw", "") or "")[:24]


# ---- Other ProfileHeader fields (ultra-compact) -----------------------------


def _summarise_services(payload: dict[str, Any]) -> list[tuple[str, str]]:
    # The decoded form of services is a dict of {service_name: None} pairs
    if isinstance(payload, dict) is False:
        return [("Services", _format_scalar(payload))]
    names = sorted(k for k in payload.keys() if not _skip_internal_key(k))
    if len(names) == 0:
        return [("Services", "(none)")]
    preview = ", ".join(names[:8])
    if len(names) > 8:
        preview += f" … +{len(names) - 8} more"
    return [("Services", f"{preview} ({len(names)} total)")]


def _summarise_gfste(payload: dict[str, Any]) -> list[tuple[str, str]]:
    items = payload if isinstance(payload, list) else []
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        items = payload["items"]
    if isinstance(items, list) is False or len(items) == 0:
        return [("GFSTEList", "(empty)")]
    oids = [str(i).strip() for i in items if len(str(i).strip()) > 0]
    preview = ", ".join(oids[:4])
    if len(oids) > 4:
        preview += f" … +{len(oids) - 4} more"
    return [("GFSTEList", preview)]


def _summarise_aids(payload: dict[str, Any]) -> list[tuple[str, str]]:
    items = payload if isinstance(payload, list) else []
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        items = payload["items"]
    if isinstance(items, list) is False or len(items) == 0:
        return [("AIDs", "(empty)")]


def _summarise_aids(payload: dict[str, Any]) -> list[tuple[str, str]]:
    items = payload if isinstance(payload, list) else payload.get("items", []) if isinstance(payload, dict) else []
    if isinstance(items, list) is False or len(items) == 0:
        return [("AIDs", "(empty)")]
    rows: list[tuple[str, str]] = []
    for i, entry in enumerate(items):
        if isinstance(entry, dict):
            aid = str(entry.get("aid_hex", entry.get("aid", "")) or "").strip()
            version = str(entry.get("version_hex", entry.get("version", "")) or "").strip()
            label = f"AID #{i + 1}"
            rows.append((label, f"{aid[:32]} (v{version})" if len(version) > 0 else aid[:32]))
        else:
            rows.append((f"AID #{i + 1}", str(entry)[:48]))
    return rows


def _summarise_iot(payload: dict[str, Any]) -> list[tuple[str, str]]:
    pix = ""
    if isinstance(payload, dict):
        pix = str(payload.get("pix", "") or "").strip()
    elif isinstance(payload, str):
        pix = payload.strip()
    return [("IOT PIX", pix)] if len(pix) > 0 else [("IOT PIX", "(empty)")]


def _summarise_profile_scalar(field_name: str, payload: dict[str, Any]) -> list[tuple[str, str]]:
    base = field_name.lower()
    label_map = {
        "pol": "POL (policy rules)",
        "major-version": "Major Version",
        "minor-version": "Minor Version",
        "profileversion": "Profile Version",
        "serialnumber": "Serial Number",
        "notificationaddress": "Notification Address",
        "iccid": "ICCID",
        "profiletype": "Profile Type",
    }
    label = label_map.get(base, field_name)
    if base == "iccid" and "iccid" in payload:
        return [(label, str(payload["iccid"]).strip())]
    if base == "major-version" and "major-version" in payload:
        minor = payload.get("minor-version", "")
        if minor:
            return [(label, f"{payload['major-version']}.{minor}")]
        return [(label, str(payload["major-version"]))]
    val = payload.get("hex") or payload.get("decimal") or payload.get("raw")
    if isinstance(val, str) and len(val) > 0:
        return [(label, val[:48])]
    if isinstance(val, (int, float)):
        return [(label, str(val))]
    # Generic dict — pick first scalar
    for k in ("decimal", "hex", "raw", "iccid", "value"):
        v = payload.get(k)
        if v is not None and not isinstance(v, (dict, list)):
            return [(label, str(v)[:48])]
    return [(label, _format_scalar(payload))]


def _summarise_generic(payload: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    priority = ("format", "state", "decimal", "aid", "rid", "length")
    seen: set[str] = set()
    for key in priority:
        if key in payload and not _skip_internal_key(key):
            rows.append((key.title(), _format_scalar(payload.get(key))))
            seen.add(key)
    for key in sorted(payload.keys()):
        if key in seen or _skip_internal_key(key):
            continue
        rows.append((key.replace("_", " ").title(), _format_scalar(payload.get(key))))
    return rows


TAB_SHOW_STRUCTURE = "SHOW JSON"

__all__ = [
    "TAB_SHOW_STRUCTURE",
    "gentle_summary_rows",
    "operator_field_heading",
]
