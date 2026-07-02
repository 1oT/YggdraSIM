# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Static wiring checks for the PE-GenericFileManagement add-file bar.

The bar implements the *Add file element* affordance for TCA SAIP
``genericFileManagement`` PEs (§6.6.7). These checks guarantee the
JS / CSS symbols stay in lockstep with the registered
``saip.gfm_add_file_element`` backend action so a renamed input or
removed selector trips the suite before it ships.
"""

from __future__ import annotations

import unittest
from pathlib import Path


_APP_JS = Path("yggdrasim_common/gui_server/static/app.js")
_APP_CSS = Path("yggdrasim_common/gui_server/static/app.css")


class GfmAddFileBarJsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(_APP_JS.is_file(), f"missing {_APP_JS}")
        self.text = _APP_JS.read_text()

    def test_builder_function_present(self) -> None:
        self.assertIn("function saipGfmBuildAddFileBar(", self.text)

    def test_renders_inside_gfm_card(self) -> None:
        # The card computes a parent-path summary and threads it
        # into the builder so a ``bound`` GFM can hide the parent
        # input. See ``saipGfmComputeParentSummary``.
        self.assertIn(
            "saipGfmBuildAddFileBar(pkg, sectionKey, parentSummary)",
            self.text,
        )
        self.assertIn(
            "saipEditorRenderGfmCard(wrap, decoded, pkg, sectionKey, peList, validation)",
            self.text,
        )

    def test_parent_summary_helpers_present(self) -> None:
        # Helpers backing the per-GFM "one parent path" UX.
        for sym in (
            "function saipGfmComputeParentSummary(",
            "function saipGfmFormatParentPath(",
            "function saipGfmFidLabel(",
            "_GFM_DF_NAMES",
        ):
            self.assertIn(sym, self.text, sym)

    def test_parent_chip_rendered(self) -> None:
        # The chip surfaces the bound / unbound / mixed state to
        # the operator before they hit Add file.
        for needle in (
            "saip-gfm-parent-chip",
            'parentSummary.state === "mixed"',
            'parentSummary.state === "unbound"',
        ):
            self.assertIn(needle, self.text, needle)

    def test_calls_registered_action(self) -> None:
        self.assertIn(
            "/api/actions/saip.gfm_add_file_element/run", self.text
        )

    def test_packages_inputs_under_inputs_key(self) -> None:
        # Backend dispatcher expects ``{inputs: {...}}`` per ActionRegistry
        # convention — guard against accidental flattening.
        idx = self.text.find("/api/actions/saip.gfm_add_file_element/run")
        self.assertGreater(idx, 0)
        # Look in a 600-char window around the call for the wrapping.
        window = self.text[max(0, idx - 600): idx + 600]
        self.assertIn("inputs: inputs", window)

    def test_field_id_validation(self) -> None:
        # 4-hex-digit gate on the FID input (matches backend rule).
        self.assertIn("/^[0-9A-F]{4}$/.test(fid)", self.text)

    def test_uses_existing_apifetch(self) -> None:
        # Don't hand-roll fetch — go through apiFetch so error
        # handling stays consistent across the app.
        idx = self.text.find("function saipGfmBuildAddFileBar(")
        self.assertGreater(idx, 0)
        end = self.text.find("function saipEditorRenderGfmCard(", idx)
        body = self.text[idx:end]
        self.assertIn("apiFetch(", body)


class GfmAddFileBarCssTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(_APP_CSS.is_file(), f"missing {_APP_CSS}")
        self.text = _APP_CSS.read_text()

    def test_addbar_selectors_present(self) -> None:
        for selector in (
            ".saip-gfm-addbar",
            ".saip-gfm-addbar-field",
            ".saip-gfm-addbar-label",
            ".saip-gfm-addbar-submit",
            ".saip-gfm-addbar-status",
        ):
            self.assertIn(selector, self.text, selector)

    def test_status_state_variants(self) -> None:
        self.assertIn('.saip-gfm-addbar-status[data-state="ok"]', self.text)
        self.assertIn(
            '.saip-gfm-addbar-status[data-state="error"]', self.text
        )

    def test_parent_chip_styling(self) -> None:
        for selector in (
            ".saip-gfm-parent-chip",
            '.saip-gfm-parent-chip[data-state="bound"]',
            '.saip-gfm-parent-chip[data-state="unbound"]',
            '.saip-gfm-parent-chip[data-state="mixed"]',
        ):
            self.assertIn(selector, self.text, selector)


if __name__ == "__main__":
    unittest.main()
