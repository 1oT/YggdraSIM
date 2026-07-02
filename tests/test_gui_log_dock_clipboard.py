# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the bottom-dock copy-to-clipboard flow.

The bottom event-log dock surfaces every ``logBus`` event in one of
four buckets (Messages / Warnings / Errors / APDU). Operators reported
that the rows were not directly copy-able — they couldn't grab a
stack trace or a ``saip.open_package`` warning to paste into an issue
tracker without re-typing it.

These tests are static-bundle contracts that verify the wiring exists:

* ``index.html`` has a "Copy" toolbar button next to "Clear all".
* ``app.js`` exposes the formatter helpers under ``window.YggdraSim*``.
* Each rendered row gets a per-row copy button + ``dblclick`` handler.
* The CSS makes rows ``user-select: text`` and gives the copy button
  a hover-only opacity transition + a "copied" green flash.
* The Ctrl/Cmd+C key handler prefers a manual selection when one
  exists (so partial-row copy still works through the browser).

The tests don't drive an actual headless browser; they're grep-based
guard rails. The full integration is exercised manually + via the
agent's smoke runs.
"""

from __future__ import annotations

import unittest
from pathlib import Path


_STATIC_DIR = (
    Path(__file__).resolve().parents[1]
    / "yggdrasim_common" / "gui_server" / "static"
)


def _read(name: str) -> str:
    return (_STATIC_DIR / name).read_text(encoding="utf-8")


class LogDockToolbarHtmlContract(unittest.TestCase):
    """The static markup must carry the new "Copy" toolbar button."""

    def test_log_dock_has_copy_button_next_to_clear_all(self) -> None:
        html = _read("index.html")
        # Marker that the new button was injected with a stable id so
        # the JS wiring + this test agree on what to grab.
        self.assertIn('id="log-dock-copy"', html)
        # Ensure both buttons are still rendered side by side.
        self.assertIn('id="log-dock-clear"', html)
        # Stable ordering: the Copy button must appear *before* the
        # Clear button so muscle-memory destructive vs. non-destructive
        # actions stay separated.
        copy_at = html.index('id="log-dock-copy"')
        clear_at = html.index('id="log-dock-clear"')
        self.assertLess(copy_at, clear_at)
        # Tooltip + aria-label are present so the button is screen-
        # reader friendly.
        self.assertIn(
            'title="Copy all rows in the active tab to clipboard"', html,
        )
        self.assertIn('aria-label="Copy active tab to clipboard"', html)


class LogDockClipboardJsContract(unittest.TestCase):
    """``app.js`` must expose formatter + clipboard helpers and wire them."""

    def setUp(self) -> None:
        self.js = _read("app.js")

    def test_format_helpers_exposed_for_tests_and_external_callers(self) -> None:
        self.assertIn("window.YggdraSimFormatLogRowForClipboard", self.js)
        self.assertIn("window.YggdraSimFormatLogRowsForClipboard", self.js)
        self.assertIn("window.YggdraSimCopyTextToClipboard", self.js)
        self.assertIn("window.YggdraSimCopyActiveLogBucket", self.js)

    def test_row_format_uses_tab_separator_for_paste_friendliness(self) -> None:
        # Tab characters paste cleanly into terminals, editors, and
        # spreadsheets alike — much better than fixed-width padding.
        self.assertIn(
            'return ts + "\\t" + src + "\\t" + msg;',
            self.js,
        )

    def test_format_helpers_handle_empty_input_gracefully(self) -> None:
        # Empty array short-circuits to an empty string so the toolbar
        # button doesn't paste a stray newline when the bucket is empty.
        self.assertIn(
            'if (!Array.isArray(rows) || rows.length === 0) return "";',
            self.js,
        )

    def test_clipboard_helper_prefers_async_api_with_fallback(self) -> None:
        # navigator.clipboard.writeText is the modern path; the legacy
        # textarea + execCommand fallback covers older Qt WebEngine
        # builds where the async API is gated behind a permission prompt
        # we don't drive.
        self.assertIn("navigator.clipboard.writeText", self.js)
        self.assertIn("_execCommandCopyFallback", self.js)
        self.assertIn('document.execCommand("copy")', self.js)

    def test_append_log_dock_row_wires_per_row_copy_button(self) -> None:
        # Each row gets a copy button anchored absolutely within the row.
        self.assertIn('"log-dock-row-copy"', self.js)
        self.assertIn(
            'copyBtn.setAttribute("aria-label", "Copy this row to clipboard")',
            self.js,
        )
        # Dataset attributes capture the canonical text so the copy
        # always quotes what the bus emitted, not the (possibly
        # CSS-truncated) DOM text.
        self.assertIn("el.dataset.logTs", self.js)
        self.assertIn("el.dataset.logSource", self.js)
        self.assertIn("el.dataset.logMessage", self.js)

    def test_append_log_dock_row_supports_dblclick_copy(self) -> None:
        # Operators expect double-click to copy the whole row. We must
        # NOT clobber a manual text selection though — this guard is
        # the contract.
        self.assertIn('el.addEventListener("dblclick"', self.js)
        self.assertIn(
            "if (sel && !sel.isCollapsed && sel.toString().length > 0)",
            self.js,
        )

    def test_dock_keydown_handles_ctrl_or_cmd_c(self) -> None:
        # Both Ctrl (Linux/Win) and Cmd (macOS) paths must work, and a
        # selection must take priority so partial-row copies are honoured.
        self.assertIn('isCopyKey = (evt.key === "c" || evt.key === "C")', self.js)
        self.assertIn("(evt.ctrlKey || evt.metaKey)", self.js)
        self.assertIn(
            "if (sel && !sel.isCollapsed && sel.toString().length > 0)",
            self.js,
        )

    def test_copy_active_bucket_emits_audit_breadcrumb(self) -> None:
        # The copy action itself is logged so the operator can see in
        # the bus that the click registered, even if their OS clipboard
        # widget is misbehaving.
        self.assertIn('source: "log-dock"', self.js)
        self.assertIn("Copied ", self.js)
        self.assertIn("Nothing to copy", self.js)

    def test_row_focus_attributes_are_set(self) -> None:
        # tabindex=0 + role=listitem makes rows keyboard-navigable for
        # screen readers and the "Tab to focus + Enter/Ctrl+C" workflow.
        self.assertIn('el.setAttribute("tabindex", "0")', self.js)
        self.assertIn('el.setAttribute("role", "listitem")', self.js)


class LogDockClipboardCssContract(unittest.TestCase):
    """The stylesheet has to enable selection + show the copy chip on hover."""

    def setUp(self) -> None:
        self.css = _read("app.css")

    def test_rows_force_user_select_text(self) -> None:
        # Without these explicit rules a parent ``user-select: none``
        # rule (e.g. on the workbench shell) would leak into the dock.
        self.assertIn("user-select: text;", self.css)
        self.assertIn("-webkit-user-select: text;", self.css)

    def test_per_row_copy_button_hidden_until_hover(self) -> None:
        self.assertIn(".log-dock-row-copy {", self.css)
        # Default state: invisible + non-interactive.
        self.assertIn("opacity: 0;", self.css)
        self.assertIn("pointer-events: none;", self.css)
        # Hover/focus state must enable both visibility AND clicks.
        # We match each selector individually so whitespace tweaks
        # (formatter changes, comma reflow) don't break the contract.
        self.assertIn(".log-dock-row:hover .log-dock-row-copy", self.css)
        self.assertIn(".log-dock-row:focus-within .log-dock-row-copy", self.css)
        self.assertIn(".log-dock-row:focus-visible .log-dock-row-copy", self.css)

    def test_copy_button_uses_theme_tokens_not_hard_coded_colours(self) -> None:
        # Stay consistent with the rest of the GUI's dropdown / button
        # styling pass.
        self.assertIn(
            "background: var(--bg-elev, #2b303b);", self.css,
        )
        self.assertIn(
            "color: var(--fg, #eceff4);", self.css,
        )

    def test_copied_flash_uses_ok_token(self) -> None:
        # Green flash on successful copy — picks up whatever success
        # colour the active theme defines.
        self.assertIn(".log-dock-row.is-copied", self.css)
        self.assertIn(".log-dock-action.is-copied", self.css)
        self.assertIn("var(--ok, #22c55e)", self.css)

    def test_focus_visible_outline_uses_accent_token(self) -> None:
        # Keyboard-focused rows get an inset accent outline so it's
        # obvious which row Ctrl+C will target if no selection exists.
        self.assertIn(".log-dock-row:focus-visible", self.css)
        self.assertIn(
            "box-shadow: inset 0 0 0 1px var(--accent, #3b82f6);",
            self.css,
        )


class LogBucketCapacityContract(unittest.TestCase):
    """Each bucket has its own ring cap. APDU keeps a much larger
    ring than the human buckets because operators explicitly asked
    to see every APDU issued during a session — no throttling.
    """

    def setUp(self) -> None:
        self.js = _read("app.js")

    def test_bucket_caps_are_per_bucket_not_global(self) -> None:
        # Contract: a map keyed by bucket name, not a single number.
        self.assertIn("MAX_PER_BUCKET = {", self.js)
        self.assertIn("messages: 500,", self.js)
        self.assertIn("warnings: 500,", self.js)
        self.assertIn("errors: 500,", self.js)
        self.assertIn("apdu: 5000,", self.js)

    def test_dom_cap_matches_ring_for_apdu_bucket(self) -> None:
        # The DOM trim must not undo what the bus keeps.
        self.assertIn('bucket === "apdu" ? 5000 : 500', self.js)

    def test_default_cap_exists_for_forward_compat(self) -> None:
        # If a future bucket is added without updating the map, fall
        # back to the human default (500) instead of unbounded growth.
        self.assertIn("DEFAULT_CAP = 500", self.js)
        self.assertIn("MAX_PER_BUCKET[bucket] || DEFAULT_CAP", self.js)


if __name__ == "__main__":
    unittest.main()
