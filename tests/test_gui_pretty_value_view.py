# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the polished file-data view.

The SCP03 file-system module used to render FCP fields and decoded
record bodies by ``JSON.stringify``-ing object values into a <pre>
block — a "terminal JSON" look. This was replaced by a type-aware
pretty-value renderer (``renderPrettyValue``) that lays out objects
as definition lists, arrays as chip rows, primitives as type chips,
and hex-looking strings as byte-grouped pills. A toolbar on every
decoded section now lets operators flip between the polished view
and the raw JSON.

These tests pin the JS bundle + CSS bundle structurally so future
edits don't accidentally drop the new contract.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


_REPO = Path(__file__).resolve().parents[1]
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.css"


# ---------------------------------------------------------------------- #
# JS contract: pretty value renderer
# ---------------------------------------------------------------------- #


class PrettyValueRendererJsContract(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_renderer_function_exists(self) -> None:
        self.assertIn("function renderPrettyValue(", self.js)

    def test_primitive_renderer_exists(self) -> None:
        self.assertIn("function renderPrettyPrimitive(", self.js)

    def test_hex_heuristic_helpers_exist(self) -> None:
        self.assertIn("function looksLikeHex(", self.js)
        self.assertIn("function formatHexInline(", self.js)

    def test_hex_heuristic_requires_even_hex(self) -> None:
        # Defensive: if the regex changes, a quoted/escaped hex string
        # could slip past it. Make sure the literal is still anchored
        # + restricted to hex chars.
        self.assertIn("/^[0-9A-Fa-f]+$/", self.js)
        # And the length parity guard remains.
        self.assertIn("if (s.length % 2 !== 0) return false;", self.js)

    def test_primitive_branches_cover_all_types(self) -> None:
        # Each primitive flavour must produce a distinct CSS hook so
        # the operator can read row contents at a glance.
        self.assertIn("cc-pv--null", self.js)
        self.assertIn("cc-pv--bool", self.js)
        self.assertIn("cc-pv--bool-true", self.js)
        self.assertIn("cc-pv--bool-false", self.js)
        self.assertIn("cc-pv--num", self.js)
        self.assertIn("cc-pv--str", self.js)
        self.assertIn("cc-pv--hex", self.js)

    def test_array_chip_path_and_row_path(self) -> None:
        self.assertIn("cc-pv-array--chips", self.js)
        self.assertIn("cc-pv-array-row", self.js)
        # Empty + non-empty branches must coexist.
        self.assertIn('"[ ] (empty)"', self.js)

    def test_array_lines_path_for_human_readable_strings(self) -> None:
        # Arrays of human-readable strings (EF.ARR rules, lint
        # findings, etc.) must stack vertically rather than wrap as
        # chips. The heuristic flips on length, ``:``, whitespace, or
        # ``/`` so ``"READ: ADM1"`` and friends always land in the
        # vertical layout.
        self.assertIn("cc-pv-array--lines", self.js)
        self.assertIn("cc-pv-array-line", self.js)
        # Pin the heuristic checks so a future tightening doesn't
        # silently regress to chip-mode for sentence-style strings.
        self.assertIn("if (v.length > 16) return true;", self.js)
        self.assertIn('if (v.indexOf(":") !== -1) return true;', self.js)
        self.assertIn("if (/\\s/.test(v)) return true;", self.js)
        self.assertIn('if (v.indexOf("/") !== -1) return true;', self.js)

    def test_object_path_uses_definition_list_with_depth_class(self) -> None:
        self.assertIn('dl.className = "cc-pv-object cc-pv-object--depth-" + depthIdx;', self.js)
        # Empty objects render a placeholder chip rather than an empty dl.
        self.assertIn('"{ } (empty)"', self.js)

    def test_object_collapses_below_depth_threshold(self) -> None:
        # The renderer defaults to collapsing beyond depth 2, while
        # structured result views can request an earlier threshold.
        self.assertIn("var collapseFromDepth = Number(prettyOptions.collapseFromDepth);", self.js)
        self.assertIn("collapseFromDepth = 2;", self.js)
        self.assertIn("if (depthIdx >= collapseFromDepth) {", self.js)
        self.assertIn('details.className = "cc-pv-collapsible";', self.js)
        self.assertIn(
            "details.open = prettyOptions.collapseObjects ? false : depthIdx === collapseFromDepth;",
            self.js,
        )


# ---------------------------------------------------------------------- #
# JS contract: FCP + decoded block migrations
# ---------------------------------------------------------------------- #


class FcpDecodedMigrationJsContract(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_old_fcp_dd_jsonify_path_is_gone(self) -> None:
        # The previous code did ``dd.textContent = JSON.stringify(value);``
        # to render object FCP fields. That single-line stringified
        # output looked like terminal JSON and was the explicit
        # complaint we're fixing. Make sure that exact pattern is no
        # longer present anywhere in the bundle.
        self.assertNotIn("dd.textContent = JSON.stringify(value);", self.js)

    def test_old_decoded_pre_path_is_gone(self) -> None:
        # The decoded block used to wrap nested object values in a
        # ``<pre class="cc-decoded-json">JSON.stringify(v, null, 2)</pre>``
        # chunk that read like a debug dump. The new renderer uses a
        # definition list. Pin the old pattern as removed.
        self.assertNotIn(
            'pre.className = "cc-decoded-json";',
            self.js,
        )

    def test_fcp_block_now_uses_pretty_value_renderer(self) -> None:
        # The new FCP block calls ``renderPrettyValue`` for every
        # field and pre-builds a hidden raw-JSON view that the toolbar
        # toggles. Pin both signals.
        self.assertIn(
            'fcpPretty.className = "cc-fcp-fields cc-pv-object cc-pv-object--depth-0";',
            self.js,
        )
        self.assertIn("dd.appendChild(renderPrettyValue(fcp[key], 0));", self.js)
        self.assertIn("buildDecodedToolbar(fcp, fcpPretty, fcpJson)", self.js)

    def test_decoded_block_now_uses_pretty_value_renderer(self) -> None:
        self.assertIn(
            'pretty.className = "cc-decoded-body cc-pv-object cc-pv-object--depth-0";',
            self.js,
        )
        self.assertIn("dd.appendChild(renderPrettyValue(pair[1], 0));", self.js)
        # Toolbar gained a fourth ``meta`` argument so the service-table
        # staging panel can decide whether to surface the "Stage edit"
        # button. Pin both the new call shape and the bypassed-when-null
        # fallback so a future refactor doesn't silently drop it.
        self.assertIn("buildDecodedToolbar(decoded, pretty, json, meta || null)", self.js)


# ---------------------------------------------------------------------- #
# JS contract: toolbar (toggle JSON, copy)
# ---------------------------------------------------------------------- #


class DecodedToolbarJsContract(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_toolbar_builder_function_exists(self) -> None:
        self.assertIn("function buildDecodedToolbar(", self.js)

    def test_toolbar_starts_in_pretty_mode(self) -> None:
        self.assertIn('toggle.setAttribute("data-mode", "pretty");', self.js)
        self.assertIn('toggle.textContent = "Show JSON";', self.js)

    def test_toolbar_swaps_visibility_on_click(self) -> None:
        # When the toggle flips to JSON we hide the pretty panel and
        # show the JSON pane; flipping back inverts the pair.
        self.assertIn('prettyEl.style.display = "none";', self.js)
        self.assertIn('jsonEl.style.display = "";', self.js)
        # And the inverse path.
        self.assertIn('prettyEl.style.display = "";', self.js)
        self.assertIn('jsonEl.style.display = "none";', self.js)

    def test_toolbar_copy_button_uses_clipboard_helper(self) -> None:
        self.assertIn('copyBtn.textContent = "Copy JSON";', self.js)
        self.assertIn("if (typeof copyTextToClipboard === \"function\") {", self.js)
        self.assertIn("navigator.clipboard.writeText(text)", self.js)

    def test_toolbar_copied_flash_class_is_applied_and_removed(self) -> None:
        self.assertIn('copyBtn.classList.add("is-copied");', self.js)
        self.assertIn('copyBtn.classList.remove("is-copied")', self.js)


# ---------------------------------------------------------------------- #
# CSS contracts — make sure the new layout is actually styled
# ---------------------------------------------------------------------- #


class PrettyValueCssContract(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _APP_CSS.read_text(encoding="utf-8")

    def test_primitive_chips_styled(self) -> None:
        self.assertIn(".cc-pv {", self.css)
        self.assertIn(".cc-pv--str", self.css)
        self.assertIn(".cc-pv--num", self.css)
        self.assertIn(".cc-pv--bool", self.css)
        self.assertIn(".cc-pv--bool-true", self.css)
        self.assertIn(".cc-pv--bool-false", self.css)
        self.assertIn(".cc-pv--null", self.css)
        self.assertIn(".cc-pv--hex", self.css)

    def test_hex_inline_uses_monospace_pill(self) -> None:
        # The hex pill rendering must opt into the monospace family +
        # tighten letter-spacing so byte groups line up cleanly.
        block = re.search(
            r"\.cc-pv--hex code\s*\{[^}]*\}",
            self.css,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(block, "missing .cc-pv--hex code block")
        text = block.group(0)
        self.assertIn("letter-spacing:", text)
        self.assertIn("border-radius:", text)

    def test_object_grid_uses_two_column_dl(self) -> None:
        # The pretty object renderer reuses the FCP/decoded grid: a
        # ``key | value`` layout. Pin the grid template so the
        # alignment doesn't regress.
        block = re.search(
            r"\.cc-pv-object\s*\{[^}]*\}",
            self.css,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(block)
        text = block.group(0)
        self.assertIn("grid-template-columns:", text)

    def test_nested_object_borders_indicate_depth(self) -> None:
        # Borders + padding give a visual hierarchy without using a
        # flat colour change for every depth level.
        self.assertIn(".cc-pv-object--depth-1", self.css)
        self.assertIn(".cc-pv-object--depth-2", self.css)
        self.assertIn(".cc-pv-object--depth-3", self.css)
        self.assertIn("border-left:", self.css)

    def test_collapsible_marker_is_themed(self) -> None:
        # Native ▸/▾ are ugly + theme-blind; we draw the marker via
        # a ::before pseudo-element so it follows the theme variables.
        self.assertIn(".cc-pv-collapsible-head::before", self.css)
        self.assertIn(".cc-pv-collapsible[open] > .cc-pv-collapsible-head::before", self.css)

    def test_toolbar_buttons_styled(self) -> None:
        self.assertIn(".cc-decoded-tools {", self.css)
        self.assertIn(".cc-decoded-tools-btn", self.css)
        self.assertIn('.cc-decoded-tools-btn[data-mode="json"]', self.css)
        self.assertIn(".cc-decoded-tools-btn.is-copied", self.css)

    def test_full_json_view_is_styled(self) -> None:
        # The hidden raw-JSON view shown by the toggle is its own
        # block class so we can give it more breathing room than the
        # old inline ``cc-decoded-json`` snippet.
        self.assertIn(".cc-decoded-json-full", self.css)

    def test_lines_layout_styled_vertically(self) -> None:
        # The human-readable string array layout (.cc-pv-array--lines)
        # flips the parent flex container to column so each entry
        # lands on its own row. Sibling .cc-pv-array-line gives every
        # primitive its own block-level wrapper so chips don't
        # collapse onto the previous baseline.
        self.assertIn(".cc-pv-array--lines", self.css)
        self.assertIn(".cc-pv-array-line", self.css)
        block = re.search(
            r"\.cc-pv-array--lines\s*\{[^}]*\}",
            self.css,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(block)
        self.assertIn("flex-direction: column", block.group(0))


if __name__ == "__main__":
    unittest.main()
