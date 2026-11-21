# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Active terminal palette for every CLI and shell surface.

``YGGDRASIM_CLI_THEME`` selects one of the palettes transcribed from
the GUI themes (:mod:`yggdrasim_common.cli_palettes`) plus the two
hand-kept entries defined here: ``nord``, the canonical palette the
CLI has always used, and ``mono``, which emits no colour at all.

Resolution is memoised once per process. The name is read from
``os.environ`` first and from the persisted ``YGGDRASIM_*`` overrides
second, so a theme chosen in the GUI or the launcher ``[E]`` menu
reaches shells that never call
:func:`yggdrasim_common.env_flags.apply_persisted_env_overrides`.

Only foreground colour is emitted. Every palette is internally
consistent against its own theme background, so a light palette on a
dark terminal is a choice the operator makes, not one corrected here.
Whether colour is emitted at all stays with
:func:`yggdrasim_common.terminal_output.should_use_color`.
"""

from __future__ import annotations

import os
import sys
from typing import Final

from yggdrasim_common.cli_palettes import GENERATED_APPEARANCE, GENERATED_PALETTES
from yggdrasim_common.nord_palette import NordAnsi, NordHex, hex_to_ansi


ENV_VAR: Final[str] = "YGGDRASIM_CLI_THEME"
DEFAULT_THEME: Final[str] = "nord"
MONO_THEME: Final[str] = "mono"

# Roles carrying a colour. Style codes (RESET, BOLD, ...) are not
# themed and stay in :class:`yggdrasim_common.nord_palette.NordAnsi`.
COLOUR_ROLES: Final[tuple[str, ...]] = (
    "HEADER",
    "BLUE",
    "CYAN",
    "DEEP_BLUE",
    "GREEN",
    "YELLOW",
    "RED",
    "ORANGE",
    "PURPLE",
    "WHITE",
    "SURFACE",
    "TEXT_DIM",
    "GUIDE",
)

# Legacy role names kept so existing call sites resolve unchanged.
ROLE_ALIASES: Final[dict[str, str]] = {
    "WARNING": "YELLOW",
    "FAIL": "RED",
    "BROWN": "ORANGE",
    "MAGENTA": "PURPLE",
}

# The CLI's Nord palette, unchanged since before the GUI token files
# existed. It is not transcribed from nord-dark.css: that file has no
# frost-teal token, so a transcription would re-tint 134 header call
# sites. ``nord-dark`` is accepted as an alias for this entry.
NORD_PALETTE: Final[dict[str, str]] = {
    "HEADER": NordHex.FROST_TEAL,
    "BLUE": NordHex.FROST_BLUE,
    "CYAN": NordHex.FROST_CYAN,
    "DEEP_BLUE": NordHex.FROST_DEEP,
    "GREEN": NordHex.AURORA_GREEN,
    "YELLOW": NordHex.AURORA_YELLOW,
    "RED": NordHex.AURORA_RED,
    "ORANGE": NordHex.AURORA_ORANGE,
    "PURPLE": NordHex.AURORA_PURPLE,
    "WHITE": NordHex.SNOW_2,
    "SURFACE": NordHex.SNOW_1,
    "TEXT_DIM": NordHex.SNOW_0,
    "GUIDE": NordHex.POLAR_NIGHT_3,
}

THEME_ALIASES: Final[dict[str, str]] = {"nord-dark": DEFAULT_THEME}


def palettes() -> dict[str, dict[str, str]]:
    """Return every selectable palette, keyed by theme id."""
    merged: dict[str, dict[str, str]] = {DEFAULT_THEME: dict(NORD_PALETTE)}
    merged.update({name: dict(roles) for name, roles in GENERATED_PALETTES.items()})
    merged[MONO_THEME] = {role: "" for role in COLOUR_ROLES}
    return merged


def theme_choices() -> tuple[str, ...]:
    """Return the selectable theme ids, default first then sorted."""
    names = sorted(name for name in palettes() if name != DEFAULT_THEME)
    return (DEFAULT_THEME, *names)


def theme_appearance(name: str) -> str:
    """Return ``light``, ``dark`` or ``none`` for a theme id."""
    resolved = THEME_ALIASES.get(name, name)
    if resolved == DEFAULT_THEME:
        return "dark"
    if resolved == MONO_THEME:
        return "none"
    return GENERATED_APPEARANCE.get(resolved, "dark")


def is_known_theme(name: str) -> bool:
    return THEME_ALIASES.get(name, name) in palettes()


_ACTIVE_THEME: str | None = None
_ACTIVE_ANSI: dict[str, str] | None = None
_WARNED_UNKNOWN: set[str] = set()


def _warn_unknown(name: str) -> None:
    """Report an unusable theme name once, then fall back.

    A typo in a cosmetic env flag must not take a shell down, but it
    must not pass unremarked either -- an operator who set the flag and
    saw no change would otherwise have nothing to go on.
    """
    if name in _WARNED_UNKNOWN:
        return
    _WARNED_UNKNOWN.add(name)
    try:
        sys.stderr.write(
            f"[{ENV_VAR}] unknown theme {name!r}; using {DEFAULT_THEME}. "
            f"Known: {', '.join(theme_choices())}\n"
        )
    except (OSError, ValueError):
        pass


def _persisted_theme() -> str:
    """Return the persisted theme name, or an empty string."""
    try:
        from yggdrasim_common.env_flags import load_persisted_overrides

        return str(load_persisted_overrides().get(ENV_VAR, "") or "").strip()
    except (ImportError, OSError, ValueError):
        return ""


def resolve_theme_name() -> str:
    """Return the active theme id: env, then persisted, then default."""
    candidates = (str(os.environ.get(ENV_VAR, "") or "").strip(), _persisted_theme())
    for candidate in candidates:
        if len(candidate) == 0:
            continue
        normalized = candidate.lower()
        if is_known_theme(normalized):
            return THEME_ALIASES.get(normalized, normalized)
        _warn_unknown(candidate)
        return DEFAULT_THEME
    return DEFAULT_THEME


def active_theme() -> str:
    """Return the memoised active theme id."""
    global _ACTIVE_THEME
    if _ACTIVE_THEME is None:
        _ACTIVE_THEME = resolve_theme_name()
    return _ACTIVE_THEME


def active_palette() -> dict[str, str]:
    """Return the active theme's role -> hex mapping."""
    return palettes()[active_theme()]


def _active_ansi() -> dict[str, str]:
    """Return the active theme's role -> ANSI escape mapping."""
    global _ACTIVE_ANSI
    if _ACTIVE_ANSI is None:
        palette = active_palette()
        rendered = {
            role: (hex_to_ansi(value) if len(value) > 0 else "")
            for role, value in palette.items()
        }
        for alias, target in ROLE_ALIASES.items():
            rendered[alias] = rendered.get(target, "")
        _ACTIVE_ANSI = rendered
    return _ACTIVE_ANSI


def role_hex(role: str) -> str:
    """Return the active theme's hex for ``role`` (empty under mono)."""
    key = ROLE_ALIASES.get(role, role)
    return active_palette().get(key, "")


def role_ansi(role: str) -> str:
    """Return the active theme's ANSI escape for ``role``."""
    return _active_ansi().get(role, "")


def set_active_theme(name: str | None) -> str:
    """Switch the process palette; ``None`` re-reads the environment.

    Exported for the launcher, the GUI route and tests. Callers that
    already hold a rendered escape keep the old colour until they next
    read a role, so switching mid-render is not supported by design.
    """
    global _ACTIVE_THEME, _ACTIVE_ANSI
    _ACTIVE_ANSI = None
    if name is None:
        _ACTIVE_THEME = None
        return active_theme()
    normalized = str(name).strip().lower()
    if not is_known_theme(normalized):
        raise ValueError(
            f"unknown CLI theme {name!r}; known: {', '.join(theme_choices())}"
        )
    _ACTIVE_THEME = THEME_ALIASES.get(normalized, normalized)
    return _ACTIVE_THEME


# Style codes are not colour, so a theme switch never changes what
# "reset" or "bold" mean. The one exception is the mono palette: NO_COLOR
# reaches the terminal_output helpers but not the legacy ``Colors``
# classes, so mono is what an operator has to turn off emphasis as well
# as colour on those surfaces, and it must leave no escape behind.
_STYLE_ATTRS: Final[dict[str, str]] = {
    "ENDC": NordAnsi.RESET,
    "END": NordAnsi.RESET,
    "RESET": NordAnsi.RESET,
    "BOLD": NordAnsi.BOLD,
    "DIM": NordAnsi.DIM,
    "ITALIC": NordAnsi.ITALIC,
    "UNDERLINE": NordAnsi.UNDERLINE,
}

STYLE_ATTRS: Final[tuple[str, ...]] = tuple(_STYLE_ATTRS)


def style_code(name: str) -> str:
    """Return a style escape, or an empty string under the mono palette."""
    if active_theme() == MONO_THEME:
        return ""
    return _STYLE_ATTRS.get(name, "")


def _role_map_for(cls: type) -> dict[str, str] | None:
    for base in cls.__mro__:
        role_map = base.__dict__.get("_ROLE_MAP")
        if role_map is not None:
            return role_map
    return None


class ThemedColorsMeta(type):
    """Resolve a ``Colors`` class attribute from the active theme.

    The legacy ``Colors`` classes computed their escapes at class-body
    execution, which is import time. Two of the three live in modules a
    standalone shell imports before any persisted override is read, so
    an eager snapshot would pin the default theme in exactly the shells
    the flag is meant to re-tint. Resolution is deferred to first
    attribute read instead; ``_ROLE_MAP`` on the class names which role
    backs each attribute, and ``<NAME>_HEX`` returns the hex behind
    ``<NAME>``.
    """

    def __getattr__(cls, name: str) -> str:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in _STYLE_ATTRS:
            return style_code(name)
        role_map = _role_map_for(cls)
        if role_map is None:
            raise AttributeError(name)
        if name.endswith("_HEX"):
            role = role_map.get(name[: -len("_HEX")])
            if role is None:
                raise AttributeError(name)
            return role_hex(role)
        role = role_map.get(name)
        if role is None:
            raise AttributeError(name)
        return role_ansi(role)

    def __dir__(cls) -> list[str]:
        role_map = _role_map_for(cls) or {}
        names = set(super().__dir__())
        names.update(_STYLE_ATTRS)
        names.update(role_map)
        names.update(f"{key}_HEX" for key in role_map)
        return sorted(names)


__all__ = [
    "COLOUR_ROLES",
    "DEFAULT_THEME",
    "ENV_VAR",
    "MONO_THEME",
    "NORD_PALETTE",
    "ROLE_ALIASES",
    "STYLE_ATTRS",
    "ThemedColorsMeta",
    "active_palette",
    "active_theme",
    "is_known_theme",
    "palettes",
    "resolve_theme_name",
    "role_ansi",
    "role_hex",
    "set_active_theme",
    "style_code",
    "theme_appearance",
    "theme_choices",
]
