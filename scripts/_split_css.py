#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Split the monolithic app.css into modular files under gui_frontend/src/css/.

Usage:
  python3 scripts/_split_css.py

Reads gui_frontend/src/app.css and writes css/tokens/, css/layout/,
css/components/, css/views/. The original file is renamed to
app.css._pre_split.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "gui_frontend" / "src"
CSS_DIR = SRC / "css"
CSS_FILE = SRC / "app.css"

# ---------------------------------------------------------------------------
# Section boundaries — (start_line, end_line, output_path_relative_to_css_dir)
# Line numbers are 1-indexed, end_line is exclusive.
# ---------------------------------------------------------------------------
SECTIONS: list[tuple[int, int, str]] = [
    # Base tokens, keyframes, media queries
    (1,      60,   "tokens/base.css"),

    # Theme blocks
    (60,    137,   "tokens/nord-dark.css"),
    (138,   201,   "tokens/nord-light.css"),
    (202,   238,   "tokens/oneot-dark.css"),
    (239,   275,   "tokens/oneot-light.css"),
    (276,   311,   "tokens/matrix.css"),
    (312,   349,   "tokens/gruv-dark.css"),
    (350,   387,   "tokens/ink-light.css"),
    (388,   425,   "tokens/ocean-dark.css"),
    (426,   463,   "tokens/solarized-dark.css"),
    (464,   501,   "tokens/solarized-light.css"),
    (502,   539,   "tokens/tokyo-night.css"),
    (540,   577,   "tokens/catppuccin-mocha.css"),
    (578,   615,   "tokens/catppuccin-latte.css"),
    (616,   653,   "tokens/dracula.css"),
    (654,   691,   "tokens/github-dark.css"),
    (692,   727,   "tokens/github-light.css"),
    (728,   736,   "tokens/matrix-font-override.css"),

    # Layout: shell, sidebar, readers, log-dock
    (737,   875,   "layout/base-resets.css"),
    (876,   1151,  "layout/shell.css"),
    (1152,  1202,  "layout/theme-picker.css"),
    (1203,  1351,  "layout/sidebar.css"),
    (1352,  1536,  "layout/readers.css"),
    (1537,  1851,  "layout/log-dock.css"),

    # Components: buttons, cards, forms, tables, modals, trees, badges, terminals
    (1852,  2290,  "components/views-base.css"),
    (2291,  2397,  "components/engine-panels.css"),
    (2398,  2458,  "components/tlv-tree.css"),
    (2459,  2538,  "components/findings.css"),
    (2539,  2670,  "components/terminal.css"),
    (2671,  2794,  "components/host-shell.css"),
    (2795,  2853,  "components/flow-log.css"),
    (2854,  2882,  "components/scrollbar-polish.css"),
    (2883,  2889,  "components/text-selection.css"),
    (2890,  2905,  "components/utility-layer.css"),

    # Command Center
    (2906,  2946,  "views/command-center-header.css"),
    (2947,  2961,  "views/command-center-workbench.css"),
    (2962,  3013,  "views/command-center-dense-headers.css"),
    (3014,  3033,  "views/command-center-nav-pulse.css"),
    (3034,  3130,  "views/command-center-nav-tree.css"),
    (3131,  3167,  "views/command-center-scope-chip.css"),
    (3168,  3287,  "views/command-center-compact-workbench.css"),
    (3288,  3424,  "views/command-center-nested-categories.css"),
    (3425,  3578,  "views/command-center-compact-pane.css"),
    (3579,  3713,  "views/command-center-drag-drop.css"),
    (3714,  3795,  "views/command-center-scan-result.css"),
    (3796,  3883,  "views/command-center-per-kind.css"),
    (3884,  3889,  "views/command-center-log-stream.css"),
    (3890,  3990,  "views/command-center-destructive-banner.css"),
    (3991,  4129,  "views/command-center-tlv-tree.css"),
    (4130,  4250,  "views/command-center-findings.css"),
    (4251,  4315,  "views/command-center-keyval.css"),
    (4316,  4461,  "views/scp03-workbench.css"),

    # Workbench
    (4462,  4572,  "views/workbench-ribbon.css"),
    (4573,  4577,  "views/workbench-legacy-tools-hide.css"),
    (4578,  4688,  "views/workbench-shell.css"),
    (4689,  4787,  "views/workbench-breadcrumb.css"),
    (4788,  4869,  "views/workbench-context-menu.css"),
    (4870,  4878,  "views/workbench-legacy-extras.css"),
    (4879,  4915,  "views/workbench-legacy-card.css"),
    (4916,  5007,  "views/scp03-popout-kvl.css"),
    (5008,  5062,  "views/scp03-datasheet-decoded.css"),
    (5063,  5208,  "views/scp03-datasheet-chip.css"),

    # Popouts, records, pretty-value
    (5209,  5352,  "views/floating-action-popouts.css"),
    (5353,  5501,  "views/records-viewer.css"),
    (5502,  5544,  "views/pretty-value-base.css"),
    (5545,  5652,  "views/pretty-value-chips.css"),
]

# ---------------------------------------------------------------------------
# Remaining sections (after line 5653) — large blocks, many SAIP-specific.
# These are kept in broader chunks.
# ---------------------------------------------------------------------------
REMAINING: list[tuple[int, int, str]] = [
    (5653,  5818,  "views/pretty-value-ef.css"),
    (5819,  6284,  "views/scp03-bulk.css"),
    (6285,  6850,  "views/saip/workbench-shell.css"),
    (6851,  6956,  "views/saip/ribbon-bar.css"),
    (6957,  7024,  "views/saip/tab-strip.css"),
    (7025,  7097,  "views/saip/applications-tab.css"),
    (7098,  7248,  "views/saip/variable-editor-modal.css"),
    (7249,  7283,  "views/saip/bitmask-editor.css"),
    (7284,  7391,  "views/saip/find-overlay.css"),
    (7392,  7449,  "views/saip/sd-tlv-breakdown.css"),
    (7450,  7584,  "views/saip/token-editor.css"),
    (7585,  7596,  "views/saip/placeholder-lead.css"),
    (7597,  7821,  "views/saip/pe-card-list.css"),
    (7822,  7853,  "views/saip/pe-detail-head.css"),
    (7854,  8244,  "views/saip/typed-pe-editor.css"),
    (8245,  8301,  "views/saip/sd-dgi-decode.css"),
    (8302,  8458,  "views/saip/file-system-tree.css"),
    (8459,  8520,  "views/saip/encoded-pe-json-tab.css"),
    (8521,  8553,  "views/saip/hex-toolbar.css"),
    (8554,  9709,  "views/saip/applications-tab-cards.css"),
    (9710,  10055, "views/saip/validation-dock.css"),
    (10056, 11612, "views/saip/editor-compare.css"),
    (11613, 11854, "views/saip/variable-editor-polish.css"),
    (11855, 12060, "views/saip/semantic-diff.css"),
    (12061, 12480, "views/cc-status-strip.css"),
    (12481, 12710, "views/scp03-fcp-builder.css"),
    (12711, 12870, "views/eim-local.css"),
    (12871, 13303, "views/scp11-live.css"),
    (13304, 13391, "views/card-bridge.css"),
    (13392, 13502, "views/reader-pill.css"),
    (13503, 13531, "views/breadcrumbs-squish.css"),
    (13532, 13684, "views/env-flags.css"),
    (13685, 14089, "views/guides-modal.css"),
    (14090, 14429, "views/key-value-swatches.css"),
    (14430, 0,     "views/misc-trailing.css"),  # 0 = end of file
]


def main() -> None:
    if not CSS_FILE.is_file():
        print(f"[!] Source CSS not found: {CSS_FILE}", file=sys.stderr)
        sys.exit(1)

    raw = CSS_FILE.read_text(encoding="utf-8")
    lines = raw.splitlines(keepends=True)
    num_lines = len(lines)

    # Combine all section definitions
    all_sections = SECTIONS + REMAINING

    # Resolve end=0 to end-of-file
    all_sections = [
        (s, (e if e > 0 else num_lines + 1), p)
        for s, e, p in all_sections
    ]

    # Sort by start line
    all_sections.sort(key=lambda s: s[0])

    # Absorb small gaps (blank lines between sections) into the preceding section.
    # Modifies all_sections in-place.
    for i in range(len(all_sections) - 1):
        _, prev_end, _ = all_sections[i]
        next_start, _, _ = all_sections[i + 1]
        gap = next_start - prev_end
        if gap == 1:
            # Single blank line between sections — pull into preceding section.
            all_sections[i] = (all_sections[i][0], prev_end + 1, all_sections[i][2])
        elif gap > 1:
            print(f"[!] Gap of {gap} lines at line {prev_end} (between {all_sections[i][2]} and {all_sections[i+1][2]})", file=sys.stderr)
            # Continue anyway — the gap lines won't be in any file.

    # Verify coverage
    expected = 1
    for start, end, relpath in all_sections:
        if start != expected:
            print(f"[!] Gap at line {expected} (section {relpath} starts at {start})", file=sys.stderr)
            sys.exit(1)
        expected = end

    if expected != num_lines + 1:
        print(f"[!] Trailing gap: sections end at line {expected - 1}, file has {num_lines} lines", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Coverage validated: lines 1-{num_lines} covered by {len(all_sections)} sections")

    # Create output directories
    for _, _, relpath in all_sections:
        out = CSS_DIR / relpath
        out.parent.mkdir(parents=True, exist_ok=True)

    # Write each section
    written = set()
    for start, end, relpath in all_sections:
        out = CSS_DIR / relpath
        # 0-indexed slice
        chunk = "".join(lines[start - 1 : end - 1])
        out.write_text(chunk, encoding="utf-8")
        written.add(relpath)
        print(f"  {relpath:60s}  lines {start}-{end-1}  ({end - start} lines)")

    # Write concatenation order manifest for the build script.
    order_file = CSS_DIR / ".css_order"
    with order_file.open("w", encoding="utf-8") as ofh:
        for _, _, relpath in all_sections:
            ofh.write(relpath + "\n")
    print(f"\n[+] Order manifest: {order_file}")

    # Rename original
    backup = SRC / "app.css._pre_split"
    CSS_FILE.rename(backup)
    print(f"[+] Split into {len(written)} files under {CSS_DIR}/")
    print(f"[+] Original renamed to {backup.name}")
    print(f"\n[+] Verify with: scripts/build_gui_frontend.sh")
    print(f"    Then: diff <yggdrasim_common/gui_server/static/app.css> <gui_frontend/src/app.css._pre_split>")


if __name__ == "__main__":
    main()
