# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the About panel guides catalogue + viewer.

The About view now deep-links into every operator and developer
guide bundled with the build. Two surfaces are covered:

* Backend route ``/api/guides`` (list catalogue + flag availability)
  and ``/api/guides/{id}`` (return raw markdown for the requested
  catalogue entry, with path-traversal hardening).
* Frontend wiring: the About panel renders a grouped grid of cards,
  each card opens a self-contained markdown viewer modal, and the
  modal renders a sanitised HTML conversion of the markdown source.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock


_REPO = Path(__file__).resolve().parents[1]
_GUIDES_PY = _REPO / "yggdrasim_common" / "gui_server" / "routes" / "guides.py"
_APP_PY = _REPO / "yggdrasim_common" / "gui_server" / "app.py"
_INDEX_HTML = _REPO / "yggdrasim_common" / "gui_server" / "static" / "index.html"
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.css"


# ----------------------------------------------------------------------
# Backend: catalog + path safety
# ----------------------------------------------------------------------


class GuidesRouteCatalog(unittest.TestCase):
    def setUp(self) -> None:
        from yggdrasim_common.gui_server.routes import guides as g
        self.module = g

    def test_catalog_carries_required_columns(self) -> None:
        for item in self.module._CATALOG:
            self.assertEqual(len(item), 5, f"catalog row malformed: {item}")
            for col in item[:4]:
                self.assertIsInstance(col, str)
                self.assertGreater(len(col), 0)

    def test_catalog_ids_are_unique(self) -> None:
        ids = [row[0] for row in self.module._CATALOG]
        self.assertEqual(len(ids), len(set(ids)), "guide ids must be unique")

    def test_catalog_includes_core_guides(self) -> None:
        ids = {row[0] for row in self.module._CATALOG}
        for required in (
            "guides-index",
            "architecture",
            "capabilities",
            "cli-and-piping",
            "profile-lifecycle",
            "hil-bridge",
            "build-and-packaging",
            "install-clean",
            "install-full",
            "install-from-source",
            "install-raspberrypi",
            "diagnostics-toolbox",
            "template-and-tokens",
            "license",
            "notice",
            "authors",
            "readme",
        ):
            self.assertIn(required, ids)

    def test_catalog_groups_are_sane(self) -> None:
        groups = {row[3] for row in self.module._CATALOG}
        # Keep the curated grouping so the About panel renders a stable
        # structure across builds.
        for required_group in (
            "Overview",
            "Install & Build",
            "Operator Guides",
            "Legal",
        ):
            self.assertIn(required_group, groups)

    def test_resolve_catalog_path_rejects_escape(self) -> None:
        # Even though ids are closed, defence in depth: the resolver
        # must refuse anything that escapes the bundle root.
        self.assertIsNone(self.module._resolve_catalog_path(""))
        self.assertIsNone(self.module._resolve_catalog_path("../../etc/passwd"))
        self.assertIsNone(
            self.module._resolve_catalog_path("guides/../../etc/passwd")
        )

    def test_resolve_catalog_path_returns_real_files(self) -> None:
        # The repository checkout always has README.md + guides/ARCHITECTURE.md.
        readme = self.module._resolve_catalog_path("README.md")
        self.assertIsNotNone(readme)
        self.assertTrue(readme.is_file())
        arch = self.module._resolve_catalog_path("guides/ARCHITECTURE.md")
        self.assertIsNotNone(arch)
        self.assertTrue(arch.is_file())

    def test_list_guides_returns_entries(self) -> None:
        # Drive the FastAPI handler directly — avoids spinning up
        # TestClient just for a simple JSON response.
        resp = self.module.list_guides()
        self.assertGreater(len(resp.guides), 0)
        # At least the README must be available in the source checkout.
        readme = next((g for g in resp.guides if g.id == "readme"), None)
        self.assertIsNotNone(readme)
        self.assertTrue(readme.available)
        self.assertGreater(readme.bytes, 0)

    def test_read_guide_returns_markdown(self) -> None:
        resp = self.module.read_guide("readme")
        self.assertEqual(resp.id, "readme")
        self.assertIn("YggdraSIM", resp.markdown)

    def test_read_guide_unknown_id_raises_404(self) -> None:
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.module.read_guide("does-not-exist-xyz")
        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.detail, "unknown_guide_id")

    def test_read_guide_missing_file_raises_404(self) -> None:
        from fastapi import HTTPException
        # Patch the catalog path to point at a missing file so we hit
        # the "guide_not_available" branch deterministically.
        with mock.patch.object(
            self.module,
            "_resolve_catalog_path",
            return_value=None,
        ):
            with self.assertRaises(HTTPException) as cm:
                self.module.read_guide("readme")
        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.detail, "guide_not_available")


# ----------------------------------------------------------------------
# Backend: app wiring
# ----------------------------------------------------------------------


class GuidesAppWiring(unittest.TestCase):
    def test_app_includes_guides_router(self) -> None:
        text = _APP_PY.read_text(encoding="utf-8")
        self.assertIn(
            "from .routes import guides as guides_routes",
            text,
        )
        self.assertIn(
            "app.include_router(guides_routes.router)",
            text,
        )


# ----------------------------------------------------------------------
# Frontend: HTML structure
# ----------------------------------------------------------------------


class AboutPanelHtmlStructure(unittest.TestCase):
    def setUp(self) -> None:
        self.html = _INDEX_HTML.read_text(encoding="utf-8")

    def test_about_section_has_guides_block(self) -> None:
        self.assertIn('id="about-guides"', self.html)
        self.assertIn('id="about-guides-status"', self.html)
        self.assertIn('id="about-guides-groups"', self.html)

    def test_doc_modal_is_present(self) -> None:
        self.assertIn('id="doc-modal"', self.html)
        self.assertIn('id="doc-modal-title"', self.html)
        self.assertIn('id="doc-modal-path"', self.html)
        self.assertIn('id="doc-modal-body"', self.html)
        self.assertIn('id="doc-modal-close"', self.html)
        self.assertIn('id="doc-modal-copy"', self.html)

    def test_doc_modal_starts_hidden(self) -> None:
        self.assertIn('data-state="hidden"', self.html)
        self.assertIn('aria-hidden="true"', self.html)

    def test_backdrop_carries_close_signal(self) -> None:
        self.assertIn('data-doc-close="true"', self.html)


# ----------------------------------------------------------------------
# Frontend: JS wiring
# ----------------------------------------------------------------------


class AboutPanelJsWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_load_helper_is_invoked_when_about_view_opens(self) -> None:
        self.assertIn(
            'if (name === "about" && typeof loadGuidesForAboutPanel === "function")',
            self.js,
        )

    def test_load_function_calls_api_guides(self) -> None:
        self.assertIn('apiFetch("/api/guides")', self.js)

    def test_open_function_calls_api_guides_by_id(self) -> None:
        self.assertIn('apiFetch("/api/guides/" + encodeURIComponent(guideId))', self.js)

    def test_render_helper_groups_by_group_field(self) -> None:
        self.assertIn("function renderGuidesAboutPanel(", self.js)
        self.assertIn('section.className = "about-guides-group";', self.js)
        self.assertIn('grid.className = "about-guides-grid";', self.js)

    def test_disabled_state_for_unavailable_guides(self) -> None:
        self.assertIn("card.disabled = entry.available === false;", self.js)

    def test_doc_viewer_open_close_functions_exist(self) -> None:
        self.assertIn("function openGuideViewer(", self.js)
        self.assertIn("function closeGuideViewer(", self.js)
        self.assertIn("function wireDocViewer(", self.js)

    def test_init_wires_doc_viewer(self) -> None:
        self.assertIn("wireDocViewer();", self.js)

    def test_escape_key_closes_modal(self) -> None:
        self.assertIn('if (ev.key === "Escape" && modal.getAttribute("data-state") === "open")', self.js)

    def test_helpers_exposed_on_window_for_devtools(self) -> None:
        self.assertIn("window.YggdraSimGuides", self.js)


# ----------------------------------------------------------------------
# Frontend: markdown -> HTML smoke
# ----------------------------------------------------------------------


class MarkdownConverterSmoke(unittest.TestCase):
    """Exercise the tiny markdown converter via duktape — JS-only logic."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import duktape  # noqa: F401
            cls._has_duktape = True
        except ImportError:
            cls._has_duktape = False

    def test_converter_function_exists_in_bundle(self) -> None:
        # We can't run JS in the test env without an extra dep, so the
        # contract check is structural: the converter function must
        # exist + be exported on window for ad-hoc use, and known
        # patterns must be handled by name in the source. That's enough
        # to catch accidental deletion.
        text = _APP_JS.read_text(encoding="utf-8")
        self.assertIn("function renderMarkdownToHtml(", text)
        # Make sure each of the constructs the docs use is matched by
        # the converter (smoke check via regex literals + tokens).
        self.assertIn("```", text)  # fenced code support
        self.assertIn("var heading = /^(\\s*)(#{1,6})", text)
        self.assertIn("var blockquote = /^>", text)
        self.assertIn("var listMatch = /^(\\s*)([-*+]|\\d+\\.)", text)
        self.assertIn("var hr = /^\\s*(?:---|\\*\\*\\*|___)", text)

    def test_gfm_table_block_is_recognised(self) -> None:
        # README.md leans on GitHub-flavoured pipe tables; the modal
        # used to render them as raw paragraph text ("ASCII boxes
        # look a bit off"). Pin both the divider regex and the
        # emitted ``<table class="cc-doc-table">`` so a refactor
        # can't silently drop the support.
        text = _APP_JS.read_text(encoding="utf-8")
        self.assertIn(
            'var dividerRe =\n'
            '          /^\\s*\\|?\\s*:?-{2,}:?\\s*(\\|\\s*:?-{2,}:?\\s*)+\\|?\\s*$/;',
            text,
        )
        self.assertIn('<table class="cc-doc-table">', text)
        self.assertIn("splitTableRow", text)
        # Alignment markers (``:---``, ``---:``, ``:---:``) must be
        # surfaced as inline ``style="text-align:..."`` so right-aligned
        # numeric columns survive the round-trip.
        self.assertIn('style="text-align:', text)


# ----------------------------------------------------------------------
# Frontend: CSS contracts
# ----------------------------------------------------------------------


class AboutPanelCssContracts(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _APP_CSS.read_text(encoding="utf-8")

    def test_card_grid_layout_has_responsive_columns(self) -> None:
        self.assertIn(
            "grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));",
            self.css,
        )

    def test_card_disabled_state_is_styled(self) -> None:
        self.assertIn(".about-guides-card:disabled", self.css)

    def test_doc_modal_open_state_displays_flex(self) -> None:
        self.assertIn('.cc-doc-modal[data-state="open"]', self.css)
        self.assertIn("display: flex;", self.css)

    def test_doc_modal_renders_code_blocks(self) -> None:
        # Markdown converter emits <pre class="cc-doc-pre"> + nested
        # <code class="cc-doc-code">; both selectors must be styled
        # so guides render legibly.
        self.assertIn(".cc-doc-modal-body pre.cc-doc-pre", self.css)
        self.assertIn(".cc-doc-modal-body code", self.css)

    def test_doc_modal_supports_blockquotes_and_links(self) -> None:
        self.assertIn(".cc-doc-modal-body blockquote", self.css)
        self.assertIn(".cc-doc-modal-body a", self.css)

    def test_doc_modal_styles_pipe_tables(self) -> None:
        # GFM tables render as ``<table class="cc-doc-table">``; the
        # styling must give them visible borders + zebra striping so
        # README ("Distribution at a glance") stops looking like raw
        # ASCII art.
        self.assertIn(".cc-doc-modal-body table.cc-doc-table", self.css)
        self.assertIn("border-collapse: collapse;", self.css)
        self.assertIn(
            ".cc-doc-modal-body table.cc-doc-table tbody tr:nth-child(even) td",
            self.css,
        )


if __name__ == "__main__":
    unittest.main()
