#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Split the monolithic app.js into domain-level chunks under gui_frontend/src/js/.

Produces 4 functional chunks plus IIFE wrapper files. The build script
concatenates them in order (via .js_order manifest) to produce byte-identical output.

Usage:
  python3 scripts/_split_js.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "gui_frontend" / "src"
JS_DIR = SRC / "js"
JS_FILE = SRC / "app.js"

# Chunk definitions: (start_line_1idx, end_line_1idx_inclusive, filename_relative_to_js_dir)
# The IIFE header (lines 1-11) and footer (lines 43348-43353) are handled separately.
CHUNKS: list[tuple[int, int, str]] = [
    # Wrapper head: comment + IIFE opening
    (1,      11,     "__head.js"),

    # Core: token, theme, DOM, routing, data loaders, event wiring,
    # terminal, live readers, card bridge (~1.5K lines)
    (12,     1579,   "core.js"),

    # Command Center + SCP03 workbench + reader bar + output renderers
    # + auth + mutations + C-1 through C-5 (~12K lines)
    (1580,   13600,  "command-center.js"),

    # SAIP Workbench (SA-2 through SA-4) — PE editor, file system tree,
    # typed cards, compare, variable editor (~25.5K lines)
    (13601,  39128,  "saip-workbench.js"),

    # Trailing: per-reader tab persistence, FCP cache, scan rendering,
    # maximize-on-dblclick, log bus, native picker, drag-drop, reader
    # pane, reader context menu, auto-start SCP03, log dock, live APDU
    # bus, about, docs, host shell, init (~4.2K lines)
    (39129,  43347,  "trailing.js"),

    # Wrapper foot: init trigger + IIFE closing
    (43348,  43353,  "__foot.js"),
]


def main() -> None:
    if not JS_FILE.is_file():
        print(f"[!] Source JS not found: {JS_FILE}", file=sys.stderr)
        sys.exit(1)

    raw = JS_FILE.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    num_lines = len(lines)

    # Validate coverage
    expected = 1
    for start, end, relpath in CHUNKS:
        if start != expected:
            print(f"[!] Gap at line {expected} (chunk {relpath} starts at {start})", file=sys.stderr)
            sys.exit(1)
        expected = end + 1

    if expected != num_lines + 1:
        print(f"[!] Trailing gap: chunks end at line {expected - 1}, file has {num_lines} lines", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Coverage validated: lines 1-{num_lines} covered by {len(CHUNKS)} chunks")

    # Create output directory
    JS_DIR.mkdir(parents=True, exist_ok=True)

    # Write each chunk
    order_entries: list[str] = []
    for start, end, relpath in CHUNKS:
        out = JS_DIR / relpath
        chunk = "".join(lines[start - 1 : end])
        out.write_text(chunk, encoding="utf-8")
        order_entries.append(relpath)
        print(f"  {relpath:35s}  lines {start}-{end}  ({end - start + 1} lines)")

    # Write order manifest
    order_file = JS_DIR / ".js_order"
    with order_file.open("w", encoding="utf-8") as ofh:
        for entry in order_entries:
            ofh.write(entry + "\n")
    print(f"\n[+] Order manifest: {order_file}")

    # Rename original
    backup = SRC / "app.js._pre_split"
    JS_FILE.rename(backup)
    print(f"[+] Original renamed to {backup.name}")
    print(f"\n[+] Verify with: scripts/build_gui_frontend.sh")
    print(f"    Then: diff <yggdrasim_common/gui_server/static/app.js> <gui_frontend/src/app.js._pre_split>")


if __name__ == "__main__":
    main()
