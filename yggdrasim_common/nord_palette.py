# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Canonical Nord palette for YggdraSIM CLI / TUI / docs surfaces.

Single source of truth for the muted Nord look-and-feel. Every CLI
``Colors`` class, TUI theme palette, and demo-script ANSI helper in
the repository should read its hex codes from here so a future
re-skin requires editing exactly one file.

The palette mirrors the upstream specification
(https://www.nordtheme.com/docs/colors-and-palettes); names follow
the Nord lexicon ("Polar Night", "Snow Storm", "Frost", "Aurora")
plus a small number of role aliases (``HEADER``, ``WARNING`` ...) to
make drop-in migration of legacy ``Colors`` classes painless.

Examples
--------
>>> from yggdrasim_common.nord_palette import NordHex, hex_to_ansi
>>> hex_to_ansi(NordHex.AURORA_GREEN)
'\\x1b[38;2;163;190;140m'
>>> from yggdrasim_common.nord_palette import NordAnsi
>>> f"{NordAnsi.GREEN}ok{NordAnsi.RESET}"
'\\x1b[38;2;163;190;140mok\\x1b[0m'
"""

from __future__ import annotations

from dataclasses import dataclass


class NordHex:
    """Canonical Nord hex codes (no ``#`` prefix).

    Constants are uppercase strings so they slot straight into Rich /
    Textual style strings such as ``"bold #A3BE8C"``. Tools that need
    a leading ``#`` should prepend it explicitly.
    """

    # Polar Night - background tones, deepest first.
    POLAR_NIGHT_0 = "#2E3440"
    POLAR_NIGHT_1 = "#3B4252"
    POLAR_NIGHT_2 = "#434C5E"
    POLAR_NIGHT_3 = "#4C566A"

    # Snow Storm - foreground / surface tones.
    SNOW_0 = "#D8DEE9"
    SNOW_1 = "#E5E9F0"
    SNOW_2 = "#ECEFF4"

    # Frost - cool accents.
    FROST_TEAL = "#8FBCBB"
    FROST_CYAN = "#88C0D0"
    FROST_BLUE = "#81A1C1"
    FROST_DEEP = "#5E81AC"

    # Aurora - warm accents.
    AURORA_RED = "#BF616A"
    AURORA_ORANGE = "#D08770"
    AURORA_YELLOW = "#EBCB8B"
    AURORA_GREEN = "#A3BE8C"
    AURORA_PURPLE = "#B48EAD"

    # Role aliases used by the legacy CLI palettes.
    HEADER = FROST_TEAL
    BLUE = FROST_BLUE
    CYAN = FROST_CYAN
    GREEN = AURORA_GREEN
    WARNING = AURORA_YELLOW
    YELLOW = AURORA_YELLOW
    FAIL = AURORA_RED
    RED = AURORA_RED
    BROWN = AURORA_ORANGE
    ORANGE = AURORA_ORANGE
    MAGENTA = AURORA_PURPLE
    PURPLE = AURORA_PURPLE
    WHITE = SNOW_2
    SURFACE = SNOW_1
    TEXT_DIM = SNOW_0
    BG = POLAR_NIGHT_0
    BG_PANEL = POLAR_NIGHT_1
    BG_RAISED = POLAR_NIGHT_2
    GUIDE = POLAR_NIGHT_3


def hex_to_ansi(hex_color: str) -> str:
    """Return a 24-bit ANSI foreground escape for ``hex_color``.

    Accepts ``"#RRGGBB"`` or ``"RRGGBB"``. Raises ``ValueError`` if
    the input is not a 6-digit hex string -- callers should not be
    feeding 3-digit shorthands or named colours into this path.
    """
    normalized = (hex_color or "").lstrip("#").strip()
    if len(normalized) != 6:
        raise ValueError(f"expected 6-digit hex, got {hex_color!r}")
    red = int(normalized[0:2], 16)
    green = int(normalized[2:4], 16)
    blue = int(normalized[4:6], 16)
    return f"\033[38;2;{red};{green};{blue}m"


def hex_to_ansi_bg(hex_color: str) -> str:
    """Return a 24-bit ANSI background escape for ``hex_color``."""
    normalized = (hex_color or "").lstrip("#").strip()
    if len(normalized) != 6:
        raise ValueError(f"expected 6-digit hex, got {hex_color!r}")
    red = int(normalized[0:2], 16)
    green = int(normalized[2:4], 16)
    blue = int(normalized[4:6], 16)
    return f"\033[48;2;{red};{green};{blue}m"


@dataclass(frozen=True)
class NordAnsi:
    """Pre-rendered ANSI sequences for the Nord palette role aliases.

    Frozen so ``Colors``-style consumers can copy attributes onto
    their own classes without worrying about accidental mutation.
    Static, no instantiation required.
    """

    RESET: str = "\033[0m"
    BOLD: str = "\033[1m"
    DIM: str = "\033[2m"
    ITALIC: str = "\033[3m"
    UNDERLINE: str = "\033[4m"

    HEADER: str = "\033[38;2;143;188;187m"   # FROST_TEAL  #8FBCBB
    BLUE: str = "\033[38;2;129;161;193m"     # FROST_BLUE  #81A1C1
    CYAN: str = "\033[38;2;136;192;208m"     # FROST_CYAN  #88C0D0
    DEEP_BLUE: str = "\033[38;2;94;129;172m" # FROST_DEEP  #5E81AC

    GREEN: str = "\033[38;2;163;190;140m"    # AURORA_GREEN  #A3BE8C
    YELLOW: str = "\033[38;2;235;203;139m"   # AURORA_YELLOW #EBCB8B
    WARNING: str = "\033[38;2;235;203;139m"  # alias of YELLOW
    RED: str = "\033[38;2;191;97;106m"       # AURORA_RED    #BF616A
    FAIL: str = "\033[38;2;191;97;106m"      # alias of RED
    ORANGE: str = "\033[38;2;208;135;112m"   # AURORA_ORANGE #D08770
    BROWN: str = "\033[38;2;208;135;112m"    # alias of ORANGE
    PURPLE: str = "\033[38;2;180;142;173m"   # AURORA_PURPLE #B48EAD
    MAGENTA: str = "\033[38;2;180;142;173m"  # alias of PURPLE

    WHITE: str = "\033[38;2;236;239;244m"    # SNOW_2  #ECEFF4
    SURFACE: str = "\033[38;2;229;233;240m"  # SNOW_1  #E5E9F0
    TEXT_DIM: str = "\033[38;2;216;222;233m" # SNOW_0  #D8DEE9
    GUIDE: str = "\033[38;2;76;86;106m"      # POLAR_NIGHT_3 #4C566A


# Module-level singleton; importers can write either ``NordAnsi.RED``
# (class attribute access) or use the instance for mypy-friendly
# attribute resolution. Both are valid because dataclass defaults
# expose the same names on the class object.
NORD = NordAnsi()


__all__ = [
    "NORD",
    "NordAnsi",
    "NordHex",
    "hex_to_ansi",
    "hex_to_ansi_bg",
]
