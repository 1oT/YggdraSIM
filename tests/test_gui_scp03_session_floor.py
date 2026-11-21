# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The SCP03 session keeps its floor when the panel stack outgrows the column.

In the wide module layout the session (status chips, ribbon, file panes) and
the stack of inline action panels share one scrolling column. The session had
``min-height: 0``, so a stack taller than the column (Applications: Apps, Sec.
domains and AIDs) shrank it to nothing and the panels were laid out over the
ribbon and the APDU console it still painted. The session now keeps its
automatic minimum, and the file panes carry size containment so their rows
stay out of that minimum and keep scrolling inside their own panes.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_CSS = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "css" / "views" / "cc-status-strip.css"


def _wide_layout_rule(css: str, selector: str) -> str:
    """The declarations of ``selector`` inside the wide-layout media query."""
    block = css.split("@media (min-width: 1041px) {", 1)[1]
    match = re.search(re.escape(selector) + r" \{\n(.*?)\n  \}", block, re.S)
    if match is None:
        raise AssertionError(f"{selector} not found in the wide layout")
    return match.group(1)


class SessionFloorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _CSS.read_text(encoding="utf-8")

    def test_the_session_does_not_shrink_below_its_content_floor(self) -> None:
        rule = _wide_layout_rule(self.css, ".main--module-workbench .cc-wb-session")
        self.assertIn("flex: 1 1 auto;", rule)
        self.assertNotIn("min-height", rule)

    def test_the_panes_keep_their_rows_out_of_the_floor(self) -> None:
        rule = _wide_layout_rule(self.css, ".main--module-workbench .cc-wb-session > .cc-scan-layout")
        self.assertIn("min-height: 220px;", rule)
        self.assertIn("contain: size;", rule)

    def test_the_column_still_scrolls_once_the_panes_reach_their_floor(self) -> None:
        rule = _wide_layout_rule(self.css, ".main--module-workbench .scp03-session-main")
        self.assertIn("min-height: 0;", rule)
        self.assertIn("overflow-y: auto;", rule)


if __name__ == "__main__":
    unittest.main()
