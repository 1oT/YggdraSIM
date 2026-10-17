# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Render the GUI theme tokens into the generated CLI palette table.

The GUI ships its palettes as CSS custom properties under
``gui_frontend/src/css/tokens/``. That tree is frontend source and is
not packaged into the wheel, so the CLI cannot read it at runtime.
This script transcribes the subset of tokens the terminal roles need
into ``yggdrasim_common/cli_palettes.py``, which is tracked, packaged
and drift-guarded by ``tests/test_cli_theme.py``.

Run it after adding or re-tinting a theme:

    python scripts/generate_cli_palettes.py

Only tokens written as a 6-digit hex literal are read; the regex
matches the one in ``tests/test_gui_design_system_consistency.py`` so
the generator and the design gate agree on what counts as a token.
``nord-dark`` is deliberately absent from the output: the CLI's Nord
palette is the hand-kept canonical one in
:mod:`yggdrasim_common.nord_palette`, which predates the GUI token
files and differs from ``nord-dark.css`` in the header hue.
"""

from __future__ import annotations

import argparse
import os
import re
import sys


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKENS_DIR = os.path.join(REPO_ROOT, "gui_frontend", "src", "css", "tokens")
OUTPUT_PATH = os.path.join(REPO_ROOT, "yggdrasim_common", "cli_palettes.py")

# Token files that carry no palette: the shared alias layer and the
# Matrix typeface override.
SKIP_STEMS = frozenset({"base", "matrix-font-override"})

# The CLI's Nord palette is hand-kept in nord_palette.py. See the
# module docstring for why the GUI's nord-dark is not transcribed.
SKIP_THEMES = frozenset({"nord-dark"})

_HEX_TOKEN_RE = re.compile(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})")
_BRAND_RE = re.compile(r"--gradient-brand:\s*([^;]+)")
_HEX_RE = re.compile(r"#[0-9a-fA-F]{6}")

# Terminal role -> GUI token. Every value is a hex literal a human put
# in the theme file; nothing here is blended or interpolated, so each
# emitted colour keeps the contrast guarantee the design gate already
# holds it to. Roles that share a token do so because the GUI palette
# has no further hue to offer -- see guides/NAMING_CONVENTIONS.md.
ROLE_TOKENS: dict[str, str] = {
    "CYAN": "accent",
    "HEADER": "accent-strong",
    "BLUE": "accent-strong",
    "DEEP_BLUE": "accent-strong",
    "GREEN": "ok",
    "YELLOW": "warn",
    "ORANGE": "warn",
    "RED": "fail",
    "WHITE": "fg",
    "SURFACE": "fg",
    "TEXT_DIM": "fg-dim",
    "GUIDE": "bg-elev-2",
}

# PURPLE has no standalone token; the second stop of --gradient-brand
# is the palette's declared secondary brand hue and is what the GUI
# itself pairs with the accent.
PURPLE_ROLE = "PURPLE"


def _relative_luminance(hex_color: str) -> float:
    """Return the WCAG relative luminance of a ``#RRGGBB`` string."""
    value = hex_color.lstrip("#")
    channels = []
    for offset in (0, 2, 4):
        raw = int(value[offset:offset + 2], 16) / 255.0
        if raw <= 0.03928:
            channels.append(raw / 12.92)
        else:
            channels.append(((raw + 0.055) / 1.055) ** 2.4)
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _read_theme(path: str) -> dict[str, str]:
    """Return the role -> hex mapping for one theme token file."""
    with open(path, "r", encoding="utf-8") as handle:
        css = handle.read()
    tokens = dict(_HEX_TOKEN_RE.findall(css))

    palette: dict[str, str] = {}
    for role, token in ROLE_TOKENS.items():
        if token not in tokens:
            raise ValueError(f"{os.path.basename(path)}: missing --{token}")
        palette[role] = tokens[token].upper()

    brand = _BRAND_RE.search(css)
    if brand is None:
        raise ValueError(f"{os.path.basename(path)}: missing --gradient-brand")
    stops = _HEX_RE.findall(brand.group(1))
    if len(stops) < 2:
        raise ValueError(
            f"{os.path.basename(path)}: --gradient-brand needs two hex stops"
        )
    palette[PURPLE_ROLE] = stops[-1].upper()

    if "bg" not in tokens:
        raise ValueError(f"{os.path.basename(path)}: missing --bg")
    palette["__appearance__"] = (
        "light" if _relative_luminance(tokens["bg"]) > 0.5 else "dark"
    )
    return palette


def collect_palettes() -> dict[str, dict[str, str]]:
    """Return every transcribed theme, keyed by its GUI theme id."""
    if not os.path.isdir(TOKENS_DIR):
        raise RuntimeError(f"token directory not found: {TOKENS_DIR}")
    palettes: dict[str, dict[str, str]] = {}
    for name in sorted(os.listdir(TOKENS_DIR)):
        if not name.endswith(".css"):
            continue
        stem = name[: -len(".css")]
        if stem in SKIP_STEMS or stem in SKIP_THEMES:
            continue
        palettes[stem] = _read_theme(os.path.join(TOKENS_DIR, name))
    if len(palettes) == 0:
        raise RuntimeError(f"no theme token files under {TOKENS_DIR}")
    return palettes


def render_module(palettes: dict[str, dict[str, str]]) -> str:
    """Return the full text of the generated palette module."""
    lines = [
        "# SPDX-License-Identifier: GPL-3.0-or-later",
        "# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.",
        "",
        '"""Terminal palettes transcribed from the GUI theme tokens.',
        "",
        "Generated by ``scripts/generate_cli_palettes.py`` from",
        "``gui_frontend/src/css/tokens/*.css``. Do not edit by hand --",
        "``tests/test_cli_theme.py`` re-runs the transcription and fails on",
        "drift. Re-tinting a theme or adding one means re-running the",
        "generator in the same change.",
        "",
        "``nord-dark`` is absent on purpose: the CLI's Nord palette is the",
        "hand-kept canonical one in :mod:`yggdrasim_common.nord_palette`.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
        "",
        "GENERATED_PALETTES: Final[dict[str, dict[str, str]]] = {",
    ]
    for theme in sorted(palettes):
        palette = palettes[theme]
        lines.append(f'    "{theme}": {{')
        for role in sorted(role for role in palette if role != "__appearance__"):
            lines.append(f'        "{role}": "{palette[role]}",')
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("GENERATED_APPEARANCE: Final[dict[str, str]] = {")
    for theme in sorted(palettes):
        lines.append(f'    "{theme}": "{palettes[theme]["__appearance__"]}",')
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append('__all__ = ["GENERATED_APPEARANCE", "GENERATED_PALETTES"]')
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the tracked module is stale",
    )
    args = parser.parse_args(argv)

    rendered = render_module(collect_palettes())
    if args.check:
        try:
            with open(OUTPUT_PATH, "r", encoding="utf-8") as handle:
                current = handle.read()
        except OSError:
            current = ""
        if current != rendered:
            sys.stderr.write(
                f"{OUTPUT_PATH} is stale; run python scripts/generate_cli_palettes.py\n"
            )
            return 1
        return 0

    with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(f"wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
