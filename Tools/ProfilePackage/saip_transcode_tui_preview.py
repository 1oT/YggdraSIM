"""Resolved-preview rendering for the transcode TUI.

The preview expands every ``{NAME}``/``{#NAME}`` placeholder inside tagged
bytes ``hex`` fields using ``__ygg_token_defs__`` and
``__ygg_placeholder_style__`` from the same document. Metadata keys are
preserved so the user can still see what tokens are defined, but the
resulting document is meant for read-only inspection only.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from .saip_json_codec import (
    TokenExpansionContext,
    _LEGACY_TAG_BYTES,
    _TAG_BYTES,
    _hex_text_has_placeholder,
    _structural_data_keys,
)


_META_TOKEN_DEFS = "__ygg_token_defs__"
_META_PLACEHOLDER_STYLE = "__ygg_placeholder_style__"


def _resolve_hex_fragment(ctx: TokenExpansionContext, hex_text: str) -> str:
    """Expand placeholders and return the resulting uppercase hex string."""

    expanded = ctx.expand_mixed_hex(hex_text)
    return expanded.hex().upper()


def _walk_and_expand(
    value: Any,
    ctx: TokenExpansionContext,
    *,
    undefined_paths: dict[str, set[str]],
    path: tuple[str, ...],
) -> Any:
    """Recursively rewrite tagged-bytes ``hex`` strings in place.

    ``undefined_paths`` is a mapping of token name to the set of dotted paths
    where the token was referenced but could not be resolved. The mapping is
    populated as a side-effect.
    """

    if isinstance(value, dict):
        structural = _structural_data_keys(value)
        if set(structural) == {_TAG_BYTES}:
            hex_key = _TAG_BYTES if _TAG_BYTES in value else _LEGACY_TAG_BYTES
            raw_hex = value.get(hex_key)
            if isinstance(raw_hex, str) and _hex_text_has_placeholder(raw_hex):
                before = set(ctx.undefined_tokens)
                try:
                    expanded_hex = _resolve_hex_fragment(ctx, raw_hex)
                except Exception:
                    return value
                new_unresolved = ctx.undefined_tokens - before
                if len(new_unresolved) > 0:
                    dotted = _dotted(path)
                    for name in new_unresolved:
                        undefined_paths.setdefault(name, set()).add(dotted)
                updated = copy.deepcopy(value)
                updated[hex_key] = expanded_hex
                return updated
            return value

        new_dict = {}
        for key, inner in value.items():
            new_path = path + (str(key),)
            new_dict[key] = _walk_and_expand(
                inner,
                ctx,
                undefined_paths=undefined_paths,
                path=new_path,
            )
        return new_dict

    if isinstance(value, list):
        new_list = []
        for index, item in enumerate(value):
            new_path = path + (f"[{index}]",)
            new_list.append(
                _walk_and_expand(
                    item,
                    ctx,
                    undefined_paths=undefined_paths,
                    path=new_path,
                )
            )
        return new_list

    return value


def _dotted(path: tuple[str, ...]) -> str:
    if len(path) == 0:
        return "<root>"
    return ".".join(path)


def build_resolved_preview_document(
    document: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, set[str]]]:
    """Return a new document with every placeholder-bearing hex field expanded.

    The returned mapping keeps track of undefined tokens:

    ``{token_name: {dotted-path-of-first-ref, ...}, ...}``

    Undefined content tokens expand to empty bytes and undefined derived
    length tokens expand to a single ``0x00`` octet, matching the behaviour of
    :class:`TokenExpansionContext` in ``tolerate_undefined`` mode.
    """

    if isinstance(document, dict) is False:
        raise TypeError("build_resolved_preview_document expects a dict document.")

    defs = document.get(_META_TOKEN_DEFS, {}) or {}
    style = str(document.get(_META_PLACEHOLDER_STYLE, "brace") or "brace")
    if isinstance(defs, dict) is False:
        defs = {}
    ctx = TokenExpansionContext(defs, style, tolerate_undefined=True)

    undefined_paths: dict[str, set[str]] = {}
    resolved = _walk_and_expand(
        document,
        ctx,
        undefined_paths=undefined_paths,
        path=(),
    )
    return resolved, undefined_paths


def render_resolved_preview_json(document: dict[str, Any]) -> tuple[str, dict[str, set[str]]]:
    """Serialise the resolved document back into pretty-printed JSON."""

    resolved, undefined_paths = build_resolved_preview_document(document)
    pretty = json.dumps(resolved, indent=2, ensure_ascii=False) + "\n"
    return pretty, undefined_paths


def format_preview_banner(undefined_paths: dict[str, set[str]]) -> str:
    """Return a short status banner summarising unresolved placeholders."""

    if len(undefined_paths) == 0:
        return "Resolved preview (read-only) -- all placeholders expanded."
    names = ", ".join(sorted(undefined_paths.keys()))
    return (
        "Resolved preview (read-only) -- unresolved tokens: "
        + names
        + ". Define them under __ygg_token_defs__ (Ctrl+K) or via APPLY-TOKENS."
    )


_PLACEHOLDER_SCAN_RE = re.compile(
    r"\{(#)?([A-Za-z][A-Za-z0-9_]*)\}|\[(#)?([A-Za-z][A-Za-z0-9_]*)\]"
)


def find_placeholder_locations(text: str) -> list[dict[str, Any]]:
    """Scan ``text`` for placeholder tokens and report their locations.

    Each entry is a dictionary with:

    * ``start`` / ``end``   -- 0-based absolute character offsets (Python slice).
    * ``line`` / ``column`` -- 1-based editor coordinates for ``start``.
    * ``name``              -- token name (without braces or ``#``).
    * ``is_length``         -- ``True`` for ``{#NAME}`` / ``[#NAME]``.
    * ``style``             -- ``"brace"`` or ``"bracket"``.
    """

    if isinstance(text, str) is False or len(text) == 0:
        return []

    results: list[dict[str, Any]] = []
    # Pre-compute line starts so offsets can be translated to (line, column).
    line_starts = [0]
    for index, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(index + 1)

    def _line_col(offset: int) -> tuple[int, int]:
        # Binary search over line_starts
        lo = 0
        hi = len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - line_starts[lo] + 1

    for match in _PLACEHOLDER_SCAN_RE.finditer(text):
        hash_brace = match.group(1)
        brace_name = match.group(2)
        hash_bracket = match.group(3)
        bracket_name = match.group(4)
        if brace_name is not None:
            name = brace_name
            is_length = hash_brace is not None
            style = "brace"
        else:
            name = bracket_name or ""
            is_length = hash_bracket is not None
            style = "bracket"
        start = match.start()
        end = match.end()
        line, column = _line_col(start)
        results.append(
            {
                "start": start,
                "end": end,
                "line": line,
                "column": column,
                "name": name,
                "is_length": is_length,
                "style": style,
            }
        )
    return results


def format_placeholder_hud(
    locations: list[dict[str, Any]],
    *,
    undefined_tokens: set[str] | tuple[str, ...] | list[str] | None = None,
) -> str:
    """Format a one-line summary of placeholder occurrences for the HUD strip."""

    if len(locations) == 0:
        return ""
    unresolved = set(undefined_tokens or ())
    content_count = sum(1 for loc in locations if not loc.get("is_length"))
    length_count = len(locations) - content_count
    unresolved_here = sum(
        1 for loc in locations if str(loc.get("name", "")) in unresolved
    )
    segments = [f"{len(locations)} placeholder(s)"]
    if length_count > 0:
        segments.append(f"{content_count} content · {length_count} length")
    if unresolved_here > 0:
        segments.append(f"{unresolved_here} unresolved")
    segments.append("Ctrl+Alt+N / Ctrl+Alt+P to cycle")
    return " · ".join(segments)


def format_template_mode_sub_title(
    base: str,
    *,
    preview_active: bool,
    template_mode: bool,
    undefined_tokens: set[str] | tuple[str, ...] | list[str] | None,
    placeholder_paths: tuple[str, ...] | list[str] | set[str] | None,
) -> str:
    """Compose a sub-title string combining the session hint with status badges.

    Segments are pure strings so the TUI app can assign the result directly to
    ``self.sub_title``. The function is side-effect-free and therefore
    unit-testable without Textual.
    """

    base_text = str(base or "")
    undefined = sorted(set(undefined_tokens or ()))
    placeholders = list(placeholder_paths or ())
    segments: list[str] = []
    if preview_active is True:
        segments.append("PREVIEW MODE")
    if template_mode is True or len(undefined) > 0:
        if len(undefined) == 0:
            segments.append("TEMPLATE MODE")
        else:
            segments.append(f"TEMPLATE MODE · {len(undefined)} unresolved")
    elif len(placeholders) > 0:
        segments.append(f"TEMPLATE · {len(placeholders)} placeholder(s)")
    if len(segments) == 0:
        return base_text
    badge = " · ".join(segments)
    if len(base_text) == 0:
        return badge
    return f"[{badge}] {base_text}"
