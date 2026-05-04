"""Pure helpers backing the TUI token-manager modal.

Kept out of :mod:`Tools.ProfilePackage.saip_transcode_tui` so they can be
unit-tested without importing Textual.
"""

from __future__ import annotations

import json
from typing import Any

from .saip_token_sidecar import (
    TokenSidecarError,
    count_token_references,
    list_token_definitions,
)


_MAX_VALUE_PREVIEW = 48


def format_token_value_preview(entry: Any) -> str:
    """One-line, truncated repr for a token value (hex, dict, or fallback str)."""

    if isinstance(entry, str):
        compact = entry.strip()
        if len(compact) > _MAX_VALUE_PREVIEW:
            return compact[: _MAX_VALUE_PREVIEW - 1] + "..."
        return compact
    if isinstance(entry, dict):
        rendered = json.dumps(entry, ensure_ascii=False)
        if len(rendered) > _MAX_VALUE_PREVIEW:
            return rendered[: _MAX_VALUE_PREVIEW - 1] + "..."
        return rendered
    fallback = str(entry)
    if len(fallback) > _MAX_VALUE_PREVIEW:
        return fallback[: _MAX_VALUE_PREVIEW - 1] + "..."
    return fallback


def build_token_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a list of display rows for the tokens in ``document``.

    Each row is a dict with keys ``name``, ``content``, ``length``,
    ``value_preview``, and ``raw_value``. Rows are sorted case-insensitively
    by name. An empty list is returned when ``document`` has no token defs.
    """

    try:
        defs = list_token_definitions(document)
    except TokenSidecarError:
        return []
    rows: list[dict[str, Any]] = []
    for name in sorted(defs.keys(), key=lambda s: s.lower()):
        try:
            refs = count_token_references(document, name)
        except TokenSidecarError:
            refs = {"content": 0, "length": 0, "total": 0}
        rows.append(
            {
                "name": name,
                "content": int(refs.get("content", 0)),
                "length": int(refs.get("length", 0)),
                "value_preview": format_token_value_preview(defs[name]),
                "raw_value": defs[name],
            }
        )
    return rows


def format_token_row(row: dict[str, Any], *, name_width: int = 12) -> str:
    """Format a single row for OptionList display.

    Column widths adapt to the longest name in the current list. The
    reference counts are right-padded so the value preview stays aligned.
    """

    name = str(row.get("name", ""))
    padded_name = name.ljust(max(name_width, len(name)))
    content_ref = int(row.get("content", 0))
    length_ref = int(row.get("length", 0))
    value_preview = str(row.get("value_preview", ""))
    return (
        f"{padded_name}  content={content_ref:>3} length={length_ref:>3}  "
        f"{value_preview}"
    )


def placeholder_style_from_document(document: dict[str, Any]) -> str:
    raw = document.get("__ygg_placeholder_style__", "brace")
    normalized = str(raw or "brace").strip().lower()
    if normalized == "curly":
        normalized = "brace"
    if normalized not in ("brace", "bracket"):
        normalized = "brace"
    return normalized


def summarize_token_counts(document: dict[str, Any]) -> dict[str, int]:
    """Return a dict of aggregate token counts for subtitle/header display."""

    try:
        defs = list_token_definitions(document)
    except TokenSidecarError:
        defs = {}
    total_content = 0
    total_length = 0
    for name in defs.keys():
        try:
            refs = count_token_references(document, name)
        except TokenSidecarError:
            continue
        total_content += int(refs.get("content", 0))
        total_length += int(refs.get("length", 0))
    return {
        "tokens": len(defs),
        "content_refs": total_content,
        "length_refs": total_length,
    }
