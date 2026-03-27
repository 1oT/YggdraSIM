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


def next_theme_in_cycle(current: str) -> str:
    if current in THEME_CYCLE:
        idx = THEME_CYCLE.index(current)
        nxt = (idx + 1) % len(THEME_CYCLE)
        return THEME_CYCLE[nxt]
    return THEME_CYCLE[0]
