# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the collapsible Command Center sidebar (SA-G8).

The leftmost 260px sidebar holds the subsystem nav and is now
collapsible via a chevron handle docked in the topbar -- mirroring
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


class PanelAutoHideTests(unittest.TestCase):
    """Auto-hide is a third mode beside shown / collapsed for both panels.

    ``data-sidebar-mode`` / ``data-topbar-mode`` carry ``shown`` |
    ``hidden`` | ``auto``; in ``auto`` the panel leaves the grid, an
    edge strip stays in its track, and ``data-*-revealed`` slides the
    panel back in while the pointer rests on the strip. The mode is
    persisted in the existing collapsed keys as a third value.
    """

    def setUp(self) -> None:
        static = Path("yggdrasim_common/gui_server/static")
        self.html = (static / "index.html").read_text(encoding="utf-8")
        self.css = (static / "app.css").read_text(encoding="utf-8")
        self.app_js = (static / "app.js").read_text(encoding="utf-8")

    def test_edge_strips_ship_for_both_panels(self) -> None:
        self.assertIn(
            'class="panel-hotzone panel-hotzone--left" id="sidebar-hotzone"',
            self.html,
        )
        self.assertIn(
            'class="panel-hotzone panel-hotzone--top" id="topbar-hotzone"',
            self.html,
        )
        # The strips are pointer affordances only; the chevrons stay the
        # accessible controls, so the strips are hidden from AT.
        self.assertRegex(
            self.html, r'id="sidebar-hotzone"\s+aria-hidden="true"'
        )

    def test_auto_mode_overlays_take_their_grid_area_as_containing_block(
        self,
    ) -> None:
        # The overlays are absolutely positioned children of the grid, so
        # the shell itself has to be positioned; the panel's track
        # collapses to the strip width and the strip is rendered only in
        # ``auto``.
        self.assertIn("--panel-hotzone: 8px;", self.css)
        self.assertRegex(
            self.css, r"\.app-shell \{[^}]*position: relative;[^}]*\}"
        )
        self.assertIn(
            '.app-shell[data-sidebar-mode="auto"] {\n'
            "  grid-template-columns: var(--panel-hotzone) minmax(0, 1fr);",
            self.css,
        )
        self.assertIn(
            '.app-shell[data-sidebar-mode="auto"] .sidebar {\n'
            "  position: absolute;",
            self.css,
        )
        self.assertIn(
            '.app-shell[data-topbar-mode="auto"] .topbar {\n'
            "  position: absolute;",
            self.css,
        )
        self.assertIn(
            '.app-shell[data-sidebar-mode="auto"] .panel-hotzone--left,\n'
            '.app-shell[data-topbar-mode="auto"] .panel-hotzone--top {\n'
            "  display: block;",
            self.css,
        )

    def test_revealed_flag_slides_the_panel_in(self) -> None:
        self.assertIn(
            '.app-shell[data-sidebar-mode="auto"][data-sidebar-revealed="true"]'
            " .sidebar {\n  transform: none;",
            self.css,
        )
        self.assertIn(
            '.app-shell[data-topbar-mode="auto"][data-topbar-revealed="true"]'
            " .topbar {\n  transform: none;",
            self.css,
        )
        # The motion is a short slide under a fade, not a sweep from the
        # edge: a sweep turns into visible steps once the compositor drops
        # below 60 frames a second, which the GPU-less desktop shell does.
        self.assertIn("@keyframes ygg-panel-reveal-left", self.css)
        self.assertIn("@keyframes ygg-panel-reveal-top", self.css)
        self.assertNotIn("transition: transform var(--transition-mid);", self.css)

    def test_conceal_fades_out_in_place_before_parking(self) -> None:
        # true -> leaving -> false: the leaving phase lets clicks through
        # while the fade-out plays, then the panel parks past the edge.
        self.assertIn(
            '.app-shell[data-sidebar-mode="auto"][data-sidebar-revealed="leaving"]'
            " .sidebar {\n  transform: none;\n  pointer-events: none;",
            self.css,
        )
        self.assertIn('shell.setAttribute(revealedAttr, "leaving");', self.app_js)
        self.assertIn('panel.addEventListener("animationend", function (event) {', self.app_js)
        self.assertIn("var PANEL_LEAVE_FALLBACK_MS = 400;", self.app_js)

    def test_mode_persists_as_a_third_value_of_the_collapsed_keys(self) -> None:
        # "true" / "false" keep their old meaning so an existing
        # preference survives the upgrade; "auto" is the new value.
        self.assertIn('if (value === "true") return "hidden";', self.app_js)
        self.assertIn('if (value === "false") return "shown";', self.app_js)
        self.assertIn('if (value === "auto") return "auto";', self.app_js)
        self.assertIn(
            "window.localStorage.getItem(TOPBAR_COLLAPSED_KEY)", self.app_js
        )

    def test_both_toggles_offer_the_mode_menu_and_shift_click(self) -> None:
        self.assertIn("function panelAutoHideController(opts)", self.app_js)
        self.assertIn("function showPanelModeMenu(opts)", self.app_js)
        self.assertEqual(
            self.app_js.count('btn.addEventListener("contextmenu", function (event) {'),
            2,
        )
        self.assertEqual(
            self.app_js.count("showPanelModeMenu({"), 2
        )
        self.assertEqual(
            self.app_js.count(
                '_apply(mode === "auto" ? "shown" : "auto"'
            ),
            2,
        )

    def test_reveal_waits_for_a_dwell_and_hides_after_a_grace_period(self) -> None:
        # A pointer crossing the strip on its way to the browser chrome
        # must not flash the panel, and a panel must not vanish the
        # moment the pointer slips past its edge.
        self.assertIn("var PANEL_REVEAL_DWELL_MS = 120;", self.app_js)
        self.assertIn("var PANEL_HIDE_DELAY_MS = 260;", self.app_js)
        self.assertIn(
            'hotzone.addEventListener("pointerenter", function () {', self.app_js
        )
        # Keyboard focus entering the panel reveals it and Escape puts it
        # away again.
        self.assertIn(
            'panel.addEventListener("focusin", function () {', self.app_js
        )
        self.assertIn(
            'if (!active || !revealed || event.key !== "Escape") return;',
            self.app_js,
        )


if __name__ == "__main__":
    unittest.main()
