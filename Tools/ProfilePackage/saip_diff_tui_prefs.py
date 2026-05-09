# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Persistent preferences for ``DIFF-TUI``.

Stored in the same config file as the transcode TUI
(``Tools/ProfilePackage/saip_transcode_tui_config.json``) so the
``theme`` key is shared across both apps; users who pick Nord in the
transcode TUI see Nord when they open ``DIFF-TUI`` next.

Layout settings specific to ``DIFF-TUI`` (decoded-pane visibility and
height, value rendering toggle) live under a dedicated ``diff_tui``
sub-dict so they cannot collide with transcode-side keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .saip_transcode_tui_prefs import (
    THEME_CYCLE,
    load_transcode_tui_prefs,
    next_theme_in_cycle,
    persist_theme,
    save_transcode_tui_prefs,
)


_DIFF_LAYOUT_KEY: str = "diff_tui"

_DECODED_HEIGHT_MIN: int = 4
_DECODED_HEIGHT_MAX: int = 60
_DECODED_HEIGHT_DEFAULT: int = 14


def clamp_decoded_height(value: int) -> int:
    """Clamp a requested decoded-pane height into the supported range."""
    if value < _DECODED_HEIGHT_MIN:
        return _DECODED_HEIGHT_MIN
    if value > _DECODED_HEIGHT_MAX:
        return _DECODED_HEIGHT_MAX
    return value


def _normalize_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _normalize_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if len(stripped) == 0:
            return None
        try:
            return int(stripped, 10)
        except ValueError:
            return None
    return None


def load_theme_pref(workspace_root: Path) -> str | None:
    """Return the persisted theme name, or ``None`` if unset / unknown."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("theme")
    if isinstance(raw, str) is False:
        return None
    if raw not in THEME_CYCLE:
        return None
    return raw


def load_diff_tui_layout(workspace_root: Path) -> dict[str, Any]:
    """Return the ``diff_tui`` sub-dict from the shared config file.

    Output keys (all optional — caller falls back to defaults):

    * ``decoded_visible`` (bool) — whether the decoded pane was open.
    * ``decoded_height`` (int)   — clamped to the supported range.
    * ``show_values``    (bool) — whether the tree shows leaf values.
    * ``diffs_only``     (bool) — whether the tree was pruned to the
      diff-bearing breadcrumb only (full structure hidden).
    * ``decoded_show_hex_diff`` (bool) — whether the decoded pane
      shows the byte-level hex diff overlay (``True``) or the plain
      decoded view (``False``, default).
    """
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get(_DIFF_LAYOUT_KEY)
    if isinstance(raw, dict) is False:
        return {}
    out: dict[str, Any] = {}
    visible = _normalize_bool(raw.get("decoded_visible"))
    if visible is not None:
        out["decoded_visible"] = visible
    show_values = _normalize_bool(raw.get("show_values"))
    if show_values is not None:
        out["show_values"] = show_values
    diffs_only = _normalize_bool(raw.get("diffs_only"))
    if diffs_only is not None:
        out["diffs_only"] = diffs_only
    decoded_show_hex_diff = _normalize_bool(raw.get("decoded_show_hex_diff"))
    if decoded_show_hex_diff is not None:
        out["decoded_show_hex_diff"] = decoded_show_hex_diff
    decoded_height = _normalize_int(raw.get("decoded_height"))
    if decoded_height is not None:
        out["decoded_height"] = clamp_decoded_height(decoded_height)
    return out


def persist_diff_tui_layout(
    workspace_root: Path,
    *,
    decoded_visible: bool,
    decoded_height: int,
    show_values: bool,
    diffs_only: bool,
    decoded_show_hex_diff: bool,
) -> None:
    """Write the ``diff_tui`` sub-dict, preserving every other top-level key.

    The decoded height is clamped before writing so an out-of-range
    value cannot leak into the on-disk config and brick the next
    launch.
    """
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get(_DIFF_LAYOUT_KEY)
    if isinstance(raw, dict):
        layout = dict(raw)
    else:
        layout = {}
    layout["decoded_visible"] = bool(decoded_visible)
    layout["decoded_height"] = clamp_decoded_height(int(decoded_height))
    layout["show_values"] = bool(show_values)
    layout["diffs_only"] = bool(diffs_only)
    layout["decoded_show_hex_diff"] = bool(decoded_show_hex_diff)
    cur[_DIFF_LAYOUT_KEY] = layout
    save_transcode_tui_prefs(workspace_root, cur)


__all__ = [
    "DECODED_HEIGHT_DEFAULT",
    "DECODED_HEIGHT_MAX",
    "DECODED_HEIGHT_MIN",
    "THEME_CYCLE",
    "clamp_decoded_height",
    "load_diff_tui_layout",
    "load_theme_pref",
    "next_theme_in_cycle",
    "persist_diff_tui_layout",
    "persist_theme",
]


# Re-exported so callers do not need to know whether they live in the
# transcode-prefs or diff-prefs module.
DECODED_HEIGHT_DEFAULT = _DECODED_HEIGHT_DEFAULT
DECODED_HEIGHT_MAX = _DECODED_HEIGHT_MAX
DECODED_HEIGHT_MIN = _DECODED_HEIGHT_MIN
