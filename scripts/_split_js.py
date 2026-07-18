#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Split the GUI JavaScript monolith at stable semantic boundaries.

The old splitter used absolute line numbers and silently became stale as the
served bundle evolved. This version locates one unique marker per functional
chunk, preserves every byte between markers, and proves that stripping the
per-file SPDX headers reconstructs the input exactly.

Usage:
  python3 scripts/_split_js.py [path/to/app.js]
"""

from __future__ import annotations

import argparse
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "gui_frontend" / "src"
JS_DIR = SRC / "js"
DEFAULT_INPUT = SRC / "app.js"

SPDX_HEADER = (
    "// SPDX-License-Identifier: GPL-3.0-or-later\n"
    "// Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.\n"
    "\n"
)

CHUNK_MARKERS: tuple[tuple[str, str | None], ...] = (
    ("__head.js", None),
    ("core.js", "  // -- Token management "),
    ("command-center.js", "  // -- Command Center (R2-004 Phase C) "),
    ("saip-workbench.js", "  // -- SAIP Workbench (SA-2) "),
    (
        "trailing.js",
        "  // -- Per-reader tab persistence (localStorage) ",
    ),
    ("__foot.js", '  if (document.readyState === "loading") {'),
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT,
        help="monolithic app.js to split",
    )
    return parser.parse_args()


def _unique_marker_offset(text: str, marker: str) -> int:
    offsets: list[int] = []
    start = 0
    while True:
        offset = text.find(marker, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    if len(offsets) != 1:
        raise ValueError(
            f"JavaScript boundary marker must occur exactly once: "
            f"{marker!r} (found {len(offsets)})"
        )
    return offsets[0]


def _strip_source_header(text: str) -> str:
    if text.startswith(SPDX_HEADER):
        return text[len(SPDX_HEADER) :]
    return text


def _include_preceding_blank_lines(text: str, offset: int) -> int:
    """Move blank separator lines from the prior chunk into this chunk."""
    adjusted = offset
    while adjusted > 0:
        previous_line_end = adjusted
        if text[previous_line_end - 1] == "\n":
            previous_line_end -= 1
        previous_line_start = text.rfind(
            "\n",
            0,
            previous_line_end,
        ) + 1
        if text[previous_line_start:adjusted].strip():
            break
        adjusted = previous_line_start
    return adjusted


def split_javascript(input_path: Path) -> tuple[Path, ...]:
    source_path = input_path.expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"source JavaScript not found: {source_path}")
    monolith = source_path.read_text(encoding="utf-8")

    offsets = [0]
    for _filename, marker in CHUNK_MARKERS[1:]:
        assert marker is not None
        offsets.append(
            _include_preceding_blank_lines(
                monolith,
                _unique_marker_offset(monolith, marker),
            )
        )
    if offsets != sorted(offsets) or len(set(offsets)) != len(offsets):
        raise ValueError("JavaScript boundary markers are not strictly ordered")
    offsets.append(len(monolith))

    JS_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    reconstructed: list[str] = []
    for index, (filename, _marker) in enumerate(CHUNK_MARKERS):
        content = monolith[offsets[index] : offsets[index + 1]]
        output_content = content if index == 0 else SPDX_HEADER + content
        output = JS_DIR / filename
        output.write_text(output_content, encoding="utf-8")
        written.append(output)
        reconstructed.append(
            output_content
            if index == 0
            else _strip_source_header(output_content)
        )

    if "".join(reconstructed) != monolith:
        raise RuntimeError("split JavaScript does not reconstruct the input")

    manifest = JS_DIR / ".js_order"
    manifest.write_text(
        "".join(f"{filename}\n" for filename, _marker in CHUNK_MARKERS),
        encoding="utf-8",
    )
    return tuple(written)


def main() -> None:
    args = _parse_args()
    written = split_javascript(args.input)
    print(f"[+] Split {args.input} into {len(written)} JavaScript chunks.")
    for path in written:
        print(f"    {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
