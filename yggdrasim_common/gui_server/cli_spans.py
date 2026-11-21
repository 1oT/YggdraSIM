# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A coloured CLI line as spans the page can paint with its own theme.

The shells colour their output with the active CLI palette
(:mod:`yggdrasim_common.cli_theme`), whose roles are transcribed from the GUI
theme tokens. ``line_spans`` reads the SGR sequences of one printed line back
into those roles, so a stream action can show the line as the terminal does
while the page picks the colour from its theme: ``[{"text", "role", "bold",
"dim", "italic", "underline"}, ...]``. A colour that is no palette role
carries no role (default foreground); every other escape sequence is dropped.
"""

from __future__ import annotations

import re
from typing import Any

from yggdrasim_common import cli_theme
from yggdrasim_common.nord_palette import hex_to_ansi

# CSI sequences; the SGR ones (final byte 'm') are the ones read.
_CSI_RE = re.compile(r"\x1b\[([0-9;?]*)([ -/]*[@-~])")
# One role per colour when a palette gives several the same value: the status
# roles first, since a status is what a reader must not misread.
_ROLE_ORDER = (
    "RED", "YELLOW", "ORANGE", "GREEN", "PURPLE", "CYAN", "HEADER", "BLUE", "DEEP_BLUE",
    "TEXT_DIM", "GUIDE", "WHITE", "SURFACE",
)
ROLES: tuple[str, ...] = tuple(role.lower() for role in _ROLE_ORDER)


def _roles_by_colour() -> dict[tuple[int, int, int], str]:
    palette = cli_theme.active_palette()
    table: dict[tuple[int, int, int], str] = {}
    for role in _ROLE_ORDER:
        value = str(palette.get(role, "") or "").lstrip("#")
        if len(value) != 6:
            continue
        try:
            colour = (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))
        except ValueError:
            continue
        table.setdefault(colour, role.lower())
    return table


def role_escape(role: str) -> str:
    """The escape the active palette prints for *role* ('' when it has none); for tests."""
    value = str(cli_theme.active_palette().get(role.upper(), "") or "")
    return hex_to_ansi(value) if len(value) > 0 else ""


def line_spans(line: str) -> list[dict[str, Any]]:
    """Spans of one printed line; the text of a carriage-return redraw is its last state."""
    text = str(line).rsplit("\r", 1)[-1]
    roles = _roles_by_colour()
    spans: list[dict[str, Any]] = []
    state: dict[str, Any] = {"role": "", "bold": False, "dim": False, "italic": False, "underline": False}

    def emit(chunk: str) -> None:
        if len(chunk) == 0:
            return
        if spans and all(spans[-1][key] == state[key] for key in state):
            spans[-1]["text"] += chunk
            return
        spans.append({"text": chunk, **state})

    position = 0
    for match in _CSI_RE.finditer(text):
        emit(text[position:match.start()])
        position = match.end()
        if match.group(2) != "m":
            continue
        codes = [int(part) if part.isdigit() else 0 for part in match.group(1).split(";")] or [0]
        index = 0
        while index < len(codes):
            code = codes[index]
            if code == 0:
                state.update(role="", bold=False, dim=False, italic=False, underline=False)
            elif code == 1:
                state["bold"] = True
            elif code == 2:
                state["dim"] = True
            elif code == 3:
                state["italic"] = True
            elif code == 4:
                state["underline"] = True
            elif code == 22:
                state["bold"] = False
                state["dim"] = False
            elif code == 23:
                state["italic"] = False
            elif code == 24:
                state["underline"] = False
            elif code == 39:
                state["role"] = ""
            elif code == 38 and codes[index + 1:index + 2] == [2] and len(codes) >= index + 5:
                state["role"] = roles.get((codes[index + 2], codes[index + 3], codes[index + 4]), "")
                index += 4
            elif code in (38, 48) and codes[index + 1:index + 2] == [5]:
                index += 2
            elif code == 48 and codes[index + 1:index + 2] == [2]:
                index += 4
            index += 1
    emit(text[position:])
    return spans


def plain_text(spans: list[dict[str, Any]]) -> str:
    return "".join(str(span.get("text", "")) for span in spans)
