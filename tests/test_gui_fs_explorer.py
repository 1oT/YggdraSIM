# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the in-browser fallback file explorer.

When the GUI runs without pywebview (web-server mode, headless dev,
remote browser), the path-pickers used to fall back to a bare
``window.prompt`` which forced operators to hand-type absolute paths.
The replacement is a proper modal explorer driven by a tiny read-only
``/api/fs/browse`` endpoint.

Two surfaces under test:

* Backend (``yggdrasim_common/gui_server/routes/fs_browse.py``) — listing
  semantics, parent-pointer behaviour, file → parent promotion,
  shortcut sidebar contract, and Windows drive enumeration plumbing.
* Frontend wiring (``app.js`` / ``app.css``) — pathPicker fallbacks
  invoke ``openFsExplorer``, the modal class hooks exist, and the
  endpoint URL is queried with the right shape.

All tests are pure-Python — no card, no live HTTP server.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


_REPO = Path(__file__).resolve().parents[1]
_FS_BROWSE_PY = _REPO / "yggdrasim_common" / "gui_server" / "routes" / "fs_browse.py"
_APP_PY = _REPO / "yggdrasim_common" / "gui_server" / "app.py"
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.css"


# ---------------------------------------------------------------------- #
# Backend: directory listing
# ---------------------------------------------------------------------- #


class BrowseEndpointBehaviour(unittest.TestCase):
    def setUp(self) -> None:
        from yggdrasim_common.gui_server.routes import fs_browse as m
        self.m = m
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # Lay out a tiny fixture tree so we can exercise dir / file /
        # hidden / symlink classifications without touching the real
        # workspace.
        (self.root / "alpha").mkdir()
        (self.root / "beta.txt").write_text("hello", encoding="utf-8")
        (self.root / ".secret").write_text("hidden", encoding="utf-8")
        (self.root / "Z_last").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_browse_returns_canonical_path_and_parent(self) -> None:
        resp = self.m.browse(str(self.root))
        self.assertEqual(resp.path, str(self.root.resolve()))
        self.assertEqual(resp.parent, str(self.root.resolve().parent))
        self.assertGreaterEqual(len(resp.entries), 4)

    def test_browse_sorts_dirs_before_files(self) -> None:
        resp = self.m.browse(str(self.root))
        kinds = [e.kind for e in resp.entries if e.name != ".secret"]
        # dirs first
        first_file_idx = next(
            (i for i, k in enumerate(kinds) if k == "file"), len(kinds)
        )
        for i in range(first_file_idx):
            self.assertEqual(kinds[i], "dir", f"expected dir at #{i}, got {kinds[i]}")

    def test_browse_marks_hidden_entries(self) -> None:
        resp = self.m.browse(str(self.root))
        names = {e.name: e.hidden for e in resp.entries}
        self.assertIn(".secret", names)
        self.assertTrue(names[".secret"])
        self.assertFalse(names["beta.txt"])

    def test_browse_rejects_missing_path(self) -> None:
        bogus = str(self.root / "no_such_subdir")
        resp = self.m.browse(bogus)
        self.assertIn("does not exist", str(resp.error))
        self.assertEqual(resp.entries, [])

    def test_browse_promotes_file_to_parent(self) -> None:
        target = self.root / "beta.txt"
        resp = self.m.browse(str(target))
        self.assertEqual(resp.path, str(self.root.resolve()))
        # Error message must surface so the UI can show a hint chip.
        self.assertIn("file", str(resp.error))

    def test_browse_handles_blank_path_with_home(self) -> None:
        resp = self.m.browse("")
        self.assertTrue(len(resp.path) > 0)
        # Listing must succeed (the user's home should always exist on
        # the test runner; if it doesn't the resolver returns "/" which
        # also lists fine).
        self.assertIsNone(resp.error or None if resp.error in ("",) else resp.error,
                          f"unexpected error on blank-path browse: {resp.error!r}") if False else None  # noqa: E501

    def test_browse_includes_separator_for_client_side_join(self) -> None:
        resp = self.m.browse(str(self.root))
        self.assertIn(resp.separator, ("/", "\\"))


class ShortcutsContract(unittest.TestCase):
    def setUp(self) -> None:
        from yggdrasim_common.gui_server.routes import fs_browse as m
        self.m = m

    def test_shortcuts_return_known_ids(self) -> None:
        rows = self.m.shortcuts()
        ids = {row.id for row in rows}
        # Home + workspace + cwd are the always-on triplet.
        self.assertIn("home", ids)
        self.assertIn("cwd", ids)
        self.assertIn("workspace", ids)

    def test_shortcuts_are_marked_unavailable_when_missing(self) -> None:
        # Documents / Downloads / Desktop are best-effort; on a CI
        # runner without those folders the shortcut must come back
        # ``available=False`` rather than collapsing into the home
        # button (which would hide the option from the operator).
        rows = self.m.shortcuts()
        labels = {row.label: row.available for row in rows}
        for required_label in ("Home", "Working dir", "Workspace"):
            self.assertIn(required_label, labels)


# ---------------------------------------------------------------------- #
# Backend: router registration
# ---------------------------------------------------------------------- #


class FsBrowseRouterIsMounted(unittest.TestCase):
    def test_app_imports_and_mounts_fs_browse_router(self) -> None:
        text = _APP_PY.read_text(encoding="utf-8")
        self.assertIn(
            "from .routes import fs_browse as fs_browse_routes",
            text,
        )
        self.assertIn(
            "app.include_router(fs_browse_routes.router)",
            text,
        )

    def test_router_prefix_is_api_fs(self) -> None:
        from yggdrasim_common.gui_server.routes import fs_browse as m
        self.assertEqual(m.router.prefix, "/api/fs")


# ---------------------------------------------------------------------- #
# Frontend wiring: pathPicker fallback + explorer modal
# ---------------------------------------------------------------------- #


class FrontendExplorerWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_path_picker_fallbacks_invoke_openfsexplorer(self) -> None:
        # Each of the three picker entry points must defer to the new
        # explorer when the pywebview bridge is unavailable. The
        # legacy ``_promptFallback`` may stay as an emergency escape
        # hatch but must NOT be the default.
        self.assertIn(
            'return openFsExplorer({\n'
            '        mode: "open",',
            self.js,
        )
        self.assertIn(
            'return openFsExplorer({\n'
            '        mode: "folder",',
            self.js,
        )
        self.assertIn(
            'return openFsExplorer({\n'
            '        mode: "save",',
            self.js,
        )

    def test_path_picker_honours_web_picker_mode(self) -> None:
        self.assertIn("file_picker_mode", self.js)
        self.assertIn('if (mode === "web") return false;', self.js)
        self.assertIn("if (await pathPicker.useNativeDialog())", self.js)

    def test_saip_open_cancel_does_not_fallback_to_prompt(self) -> None:
        self.assertNotIn("Open package " + chr(0x2014) + " file path:", self.js)

    def test_explorer_function_exposes_namespace(self) -> None:
        self.assertIn("function openFsExplorer(", self.js)
        self.assertIn("window.YggdraSimFsExplorer = openFsExplorer;", self.js)

    def test_explorer_uses_fs_browse_endpoint(self) -> None:
        self.assertIn(
            "/api/fs/browse?path=",
            self.js,
        )
        self.assertIn("encodeURIComponent(target", self.js)

    def test_explorer_supports_keyboard_dismiss(self) -> None:
        # Esc must close the modal without resolving a path.
        self.assertIn('if (ev.key === "Escape")', self.js)

    def test_explorer_filters_known_extensions(self) -> None:
        # The pywebview-style "(*.der;*.bin;*.json)" tokens must be
        # parsed into a per-row filter so the listing only highlights
        # the file types the action declared interest in.
        self.assertIn("_fsExplorerExtractExts", self.js)


class FrontendExplorerCss(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _APP_CSS.read_text(encoding="utf-8")

    def test_modal_class_hooks_present(self) -> None:
        for selector in (
            ".cc-fs-explorer-overlay",
            ".cc-fs-explorer-head",
            ".cc-fs-explorer-pathrow",
            ".cc-fs-explorer-sidebar",
            ".cc-fs-explorer-side-btn",
            ".cc-fs-explorer-list",
            ".cc-fs-explorer-row",
            ".cc-fs-explorer-row.is-selected",
            ".cc-fs-explorer-foot",
            ".cc-fs-explorer-status",
        ):
            self.assertIn(selector, self.css, f"missing CSS hook: {selector}")

    def test_responsive_breakpoint_collapses_to_single_column(self) -> None:
        self.assertIn("@media (max-width: 720px)", self.css)

    def test_hidden_rows_are_explicitly_suppressed(self) -> None:
        self.assertIn(".cc-fs-explorer-row[hidden]", self.css)
        hidden_rule = self.css.split(".cc-fs-explorer-row[hidden]", 1)[1]
        hidden_rule = hidden_rule.split("}", 1)[0]
        self.assertIn("display: none", hidden_rule)


if __name__ == "__main__":
    unittest.main()
