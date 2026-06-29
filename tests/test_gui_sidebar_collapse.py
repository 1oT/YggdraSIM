# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression tests for the collapsible Command Center sidebar (SA-G8).

The leftmost 260px sidebar holds the subsystem nav and is now
collapsible via a chevron handle docked in the topbar — mirroring
the existing ``data-log-collapsed`` pattern on ``.app-shell`` for the
log dock. State persists across reloads through
``localStorage["yggdrasim:cc-sidebar-collapsed"]``.
"""

from __future__ import annotations

import unittest
from pathlib import Path


class SidebarCollapseHtmlTests(unittest.TestCase):
    """The HTML scaffold must ship the toggle button + a stable id."""

    def setUp(self) -> None:
        self.html = (
            Path("yggdrasim_common/gui_server/static/index.html")
            .read_text(encoding="utf-8")
        )

    def test_toggle_button_lives_in_topbar(self) -> None:
        self.assertIn('id="sidebar-collapse-toggle"', self.html)
        self.assertIn('class="sidebar-collapse-toggle"', self.html)

    def test_toggle_button_carries_accessible_label(self) -> None:
        # aria-label is required so keyboard / screen-reader users can
        # find the handle without relying on the chevron glyph alone.
        self.assertIn("aria-label=\"Collapse Command Center sidebar\"", self.html)


class SidebarCollapseCssTests(unittest.TestCase):
    """``data-sidebar-collapsed="true"`` collapses the grid column."""

    def setUp(self) -> None:
        self.css = (
            Path("yggdrasim_common/gui_server/static/app.css")
            .read_text(encoding="utf-8")
        )

    def test_collapsed_attribute_zeros_sidebar_column(self) -> None:
        self.assertIn('data-sidebar-collapsed="true"', self.css)
        # The collapsed grid drops the sidebar to zero width so the
        # main content area expands across the full viewport.
        self.assertIn("grid-template-columns: 0 1fr;", self.css)

    def test_collapse_glyph_flips_with_state(self) -> None:
        # The chevron rotates 180deg so the operator gets visual
        # feedback that another click will re-expand the sidebar.
        self.assertIn(".sidebar-collapse-glyph", self.css)
        self.assertIn("transform: rotate(180deg);", self.css)


class SidebarCollapseJsTests(unittest.TestCase):
    """The boot hook persists state to localStorage and restores it."""

    def setUp(self) -> None:
        self.app_js = (
            Path("yggdrasim_common/gui_server/static/app.js")
            .read_text(encoding="utf-8")
        )

    def test_bootstrap_helper_present(self) -> None:
        self.assertIn("sidebarCollapseBootstrap", self.app_js)

    def test_state_persists_via_localstorage(self) -> None:
        self.assertIn(
            'SIDEBAR_COLLAPSED_KEY = "yggdrasim:cc-sidebar-collapsed"',
            self.app_js,
        )
        # Two-way persistence: load on boot, write on toggle.
        self.assertIn("localStorage.getItem(SIDEBAR_COLLAPSED_KEY)", self.app_js)
        self.assertIn("localStorage.setItem(", self.app_js)

    def test_toggle_flips_data_attribute(self) -> None:
        self.assertIn('setAttribute(\n        "data-sidebar-collapsed"', self.app_js)


if __name__ == "__main__":
    unittest.main()
