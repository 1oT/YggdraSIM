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
        if len(ef) > 0:
            return f"File data — {ef}"
        return "File data"
    if base.lower() == "filedescriptor":
        return "File descriptor (FCP)"
    if len(ef) > 0:
        return f"{base} — {ef}"
    return base or "Field"


def _skip_internal_key(key: str) -> bool:
    if key.startswith("_ygg_"):
        return True
    return False


def _format_scalar(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        text = value.strip()
        if len(text) > 48:
            return text[:45] + "…"
        return text
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
    if isinstance(payload, dict) is False or len(payload) == 0:
        rows.append(("Status", "(empty payload)"))
        return rows
    if base == "filedescriptor":
        rows.append(
            (
                "Descriptor",
                "Same FCP bytes as the File System metadata column — edit there; "
                "SHOW JSON keeps the ASN.1-shaped dump for tooling.",
            ),
        )
        return rows
    if base == "fillfilecontent":
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
            if _skip_internal_key(key):
                continue
            if key in {"format", "ruleCount", "records", "items", "hex"}:
                continue
            rows.append((key.replace("_", " ").title(), _format_scalar(payload.get(key))))
        return rows
    kind = str(editor_kind or "").strip().lower()
    if kind == "readonly_json":
        rows.append(("View", "Read-only decode — SHOW JSON for full structure."))
    priority = ("format", "state", "decimal", "aid", "rid", "length")
    seen: set[str] = set()
    for key in priority:
        if key in payload and _skip_internal_key(key) is False:
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
