# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Persistent preferences for TRANSCODE-TUI (theme and split layout state).

Stored next to other ProfilePackage config under ``Tools/ProfilePackage/``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_CONFIG_FILE = "saip_transcode_tui_config.json"
_SPLIT_PREF_KEYS = (
    "json_outline_width",
    "json_col_width",
    "inspect_width",
    "bottom_height",
)
_PANE_MODE_KEYS = (
    "right_mode",
    "bottom_left_mode",
    "bottom_right_mode",
)
_PANE_MODE_VALUES = {"der", "inspect", "lint", "none"}

_OUTLINE_BOOL_KEYS = (
    "fold_redundant_file_paths",
)

THEME_CYCLE: list[str] = [
    "textual-ansi",
    "textual-dark",
    "nord",
    "dracula",
    "catppuccin-mocha",
    "tokyo-night",
    "gruvbox",
    "solarized-dark",
    "rose-pine",
    "textual-light",
    "solarized-light",
    "catppuccin-latte",
]


def transcode_tui_prefs_path(workspace_root: Path) -> Path:
    return Path(workspace_root).resolve() / "Tools" / "ProfilePackage" / _CONFIG_FILE


def load_transcode_tui_prefs(workspace_root: Path) -> dict[str, Any]:
    """Load and return the transcode TUI preferences from the user config file."""
    path = transcode_tui_prefs_path(workspace_root)
    if path.is_file() is False:
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(raw, dict) is False:
        return {}
    return raw


def save_transcode_tui_prefs(workspace_root: Path, prefs: dict[str, Any]) -> None:
    path = transcode_tui_prefs_path(workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prefs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        numeric = value
    elif isinstance(value, str):
        stripped = value.strip()
        if len(stripped) == 0:
            return None
        try:
            numeric = int(stripped, 10)
        except ValueError:
            return None
    else:
        return None
    if numeric <= 0:
        return None
    return numeric


def persist_theme(workspace_root: Path, theme_name: str) -> None:
    cur = load_transcode_tui_prefs(workspace_root)
    cur["theme"] = str(theme_name)
    save_transcode_tui_prefs(workspace_root, cur)


def load_split_size_prefs(workspace_root: Path) -> dict[str, int]:
    """Load and return the pane-split size preferences from the user config file."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("splits")
    if isinstance(raw, dict) is False:
        return {}
    out: dict[str, int] = {}
    for key in _SPLIT_PREF_KEYS:
        value = _positive_int(raw.get(key))
        if value is None:
            continue
        out[key] = value
    return out


def persist_split_sizes(
    workspace_root: Path,
    *,
    json_outline_width: int,
    json_col_width: int,
    inspect_width: int,
    bottom_height: int,
) -> None:
    """Persist the current pane split sizes to the prefs file."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("splits")
    if isinstance(raw, dict):
        splits = dict(raw)
    else:
        splits = {}
    updates = {
        "json_outline_width": json_outline_width,
        "json_col_width": json_col_width,
        "inspect_width": inspect_width,
        "bottom_height": bottom_height,
    }
    for key in _SPLIT_PREF_KEYS:
        value = _positive_int(updates.get(key))
        if value is None:
            continue
        splits[key] = value
    cur["splits"] = splits
    save_transcode_tui_prefs(workspace_root, cur)


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


def _normalize_pane_mode(value: Any) -> str | None:
    if isinstance(value, str) is False:
        return None
    normalized = value.strip().lower()
    if normalized in _PANE_MODE_VALUES:
        return normalized
    return None


def load_pane_layout_prefs(workspace_root: Path) -> dict[str, Any]:
    """Load and return the pane layout preferences from the prefs file."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("panes")
    if isinstance(raw, dict) is False:
        return {}
    out: dict[str, Any] = {}
    outline_visible = _normalize_bool(raw.get("outline_visible"))
    if outline_visible is not None:
        out["outline_visible"] = outline_visible
    for key in _PANE_MODE_KEYS:
        value = _normalize_pane_mode(raw.get(key))
        if value is None:
            continue
        out[key] = value
    return out


def persist_pane_layout_prefs(
    workspace_root: Path,
    *,
    outline_visible: bool,
    right_mode: str,
    bottom_left_mode: str,
    bottom_right_mode: str,
) -> None:
    """Persist the current pane layout preferences to the prefs file."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("panes")
    if isinstance(raw, dict):
        panes = dict(raw)
    else:
        panes = {}
    panes["outline_visible"] = bool(outline_visible)
    updates = {
        "right_mode": right_mode,
        "bottom_left_mode": bottom_left_mode,
        "bottom_right_mode": bottom_right_mode,
    }
    for key in _PANE_MODE_KEYS:
        value = _normalize_pane_mode(updates.get(key))
        if value is None:
            continue
        panes[key] = value
    cur["panes"] = panes
    save_transcode_tui_prefs(workspace_root, cur)


def next_theme_in_cycle(current: str) -> str:
    if current in THEME_CYCLE:
        idx = THEME_CYCLE.index(current)
        nxt = (idx + 1) % len(THEME_CYCLE)
        return THEME_CYCLE[nxt]
    return THEME_CYCLE[0]


def load_outline_prefs(workspace_root: Path) -> dict[str, bool]:
    """Read the ``outline`` prefs sub-object.

    Returns only keys that parsed as a valid ``bool`` so callers can use
    ``dict.get(...)`` without guarding against sentinel values.
    """
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("outline")
    if isinstance(raw, dict) is False:
        return {}
    out: dict[str, bool] = {}
    for key in _OUTLINE_BOOL_KEYS:
        normalized = _normalize_bool(raw.get(key))
        if normalized is None:
            continue
        out[key] = normalized
    return out


def persist_outline_prefs(
    workspace_root: Path,
    *,
    fold_redundant_file_paths: bool,
) -> None:
    """Write the ``outline`` prefs sub-object, preserving other keys."""
    cur = load_transcode_tui_prefs(workspace_root)
    raw = cur.get("outline")
    if isinstance(raw, dict):
        outline = dict(raw)
    else:
        outline = {}
    outline["fold_redundant_file_paths"] = bool(fold_redundant_file_paths)
    cur["outline"] = outline
    save_transcode_tui_prefs(workspace_root, cur)
