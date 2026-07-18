#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Re-split the GUI CSS monolith using the reviewed chunk boundaries.

Each current chunk contributes a unique leading content anchor. The splitter
finds those anchors in the input monolith, refuses ambiguous or reordered
boundaries, and proves exact reconstruction before returning. This replaces
the former absolute-line-number table, which could not safely process a bundle
after normal feature additions.

Usage:
  python3 scripts/_split_css.py [path/to/app.css]
"""

from __future__ import annotations

import argparse
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "gui_frontend" / "src"
CSS_DIR = SRC / "css"
DEFAULT_INPUT = SRC / "app.css"
MANIFEST = CSS_DIR / ".css_order"

SPDX_HEADER = (
    "/*\n"
    " * SPDX-License-Identifier: GPL-3.0-or-later\n"
    " * Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.\n"
    " */\n"
    "\n"
)

# The wording of this section title was intentionally updated in the served
# bundle, so its older source prefix is not an anchor in the reconciled input.
BOUNDARY_OVERRIDES = {
    "views/scp03-workbench.css": (
        "/* -- Command Center: SCP03 Workbench "
        "(reader-scoped internal tabs) ------- */\n"
    ),
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT,
        help="monolithic app.css to split",
    )
    return parser.parse_args()


def _manifest_entries() -> list[str]:
    entries = [
        line.strip()
        for line in MANIFEST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(entries) == 0 or len(entries) != len(set(entries)):
        raise ValueError("CSS order manifest is empty or contains duplicates")
    return entries


def _strip_source_header(lines: list[str]) -> list[str]:
    header_lines = SPDX_HEADER.splitlines(keepends=True)
    if lines[: len(header_lines)] == header_lines:
        return lines[len(header_lines) :]
    return lines


def _unique_anchor_offset(
    monolith: list[str],
    anchor_source: list[str],
    *,
    name: str,
) -> int:
    max_width = min(24, len(anchor_source))
    for width in range(max_width, 0, -1):
        anchor = anchor_source[:width]
        matches = [
            index
            for index in range(0, len(monolith) - width + 1)
            if monolith[index : index + width] == anchor
        ]
        if len(matches) == 1:
            return matches[0]
    raise ValueError(f"CSS boundary for {name!r} is absent or ambiguous")


def split_css(input_path: Path) -> tuple[Path, ...]:
    source_path = input_path.expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"source CSS not found: {source_path}")
    monolith = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
    entries = _manifest_entries()

    offsets = [0]
    for entry in entries[1:]:
        override = BOUNDARY_OVERRIDES.get(entry)
        if override is not None:
            anchor_source = override.splitlines(keepends=True)
        else:
            current = (CSS_DIR / entry).read_text(
                encoding="utf-8"
            ).splitlines(keepends=True)
            anchor_source = _strip_source_header(current)
        offset = _unique_anchor_offset(monolith, anchor_source, name=entry)
        while offset > 0 and not monolith[offset - 1].strip():
            offset -= 1
        offsets.append(offset)
    if offsets != sorted(offsets) or len(set(offsets)) != len(offsets):
        raise ValueError("CSS chunk boundaries are not strictly ordered")
    offsets.append(len(monolith))

    written: list[Path] = []
    reconstructed: list[str] = []
    for index, entry in enumerate(entries):
        content_lines = monolith[offsets[index] : offsets[index + 1]]
        content = "".join(content_lines)
        output_content = content if index == 0 else SPDX_HEADER + content
        output = CSS_DIR / entry
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(output_content, encoding="utf-8")
        written.append(output)
        reconstructed.extend(
            output_content.splitlines(keepends=True)
            if index == 0
            else _strip_source_header(
                output_content.splitlines(keepends=True)
            )
        )

    if reconstructed != monolith:
        raise RuntimeError("split CSS does not reconstruct the input")
    return tuple(written)


def main() -> None:
    args = _parse_args()
    written = split_css(args.input)
    print(f"[+] Split {args.input} into {len(written)} CSS chunks.")
    for path in written:
        print(f"    {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
