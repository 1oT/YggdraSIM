# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the SCP03 file-system tree polish.

Two issues are covered:

1. **Tree-row labelling**: the frontend used to surface every node
   that wasn't either ``MF`` or a name starting with ``ADF`` as an
   ``EF`` badge, which mislabelled ``ADF.USIM`` (dot, not underscore)
   and every ``DF.*`` entry. The fix:

   * The backend now ships a ``kind`` field per scan-tree node
     (``mf`` / ``adf`` / ``df`` / ``ef`` / ``unknown``), classified
     from the ETSI naming convention used in ``fids.txt``.
   * The frontend ``renderTreeNodes`` honours the new field first and
     falls back to a smarter prefix walk that matches both ``ADF_`` /
     ``ADF.`` and ``DF_`` / ``DF.``.

2. **Tree panel height**: the panel was capped at ``max-height: 460px``
   which left a third of the viewport empty on tall monitors. The
   fix is a viewport-relative cap with a min-height floor so the
   panel grows with the window.
"""

from __future__ import annotations

import unittest
from pathlib import Path


_REPO = Path(__file__).resolve().parents[1]
_FS_PY = _REPO / "SCP03" / "logic" / "fs.py"
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.css"


# ----------------------------------------------------------------------
# Backend: classifier
# ----------------------------------------------------------------------


class FsControllerKindClassifier(unittest.TestCase):
    """Drive ``FileSystemController._classify_tree_node_kind`` directly."""

    def setUp(self) -> None:
        from SCP03.logic.fs import FileSystemController
        self.fn = FileSystemController._classify_tree_node_kind

    def test_mf_is_classified_as_mf(self) -> None:
        self.assertEqual(self.fn("MF"), "mf")

    def test_adf_underscore_prefix(self) -> None:
        self.assertEqual(self.fn("ADF_USIM"), "adf")
        self.assertEqual(self.fn("ADF_ISIM"), "adf")

    def test_adf_dot_prefix(self) -> None:
        # The original bug: ADF.USIM was classified as EF because the
        # prefix walk only matched "ADF" (no separator). Both forms
        # must now resolve to the same kind.
        self.assertEqual(self.fn("ADF.USIM"), "adf")
        self.assertEqual(self.fn("ADF.ISIM"), "adf")

    def test_df_dot_prefix_returns_df(self) -> None:
        # DF.TELECOM was the worst-affected entry — the entire
        # /MF/DF.TELECOM subtree (PHONEBOOK, MSISDN, SMS, ...) was
        # rendered with EF badges.
        self.assertEqual(self.fn("DF.TELECOM"), "df")
        self.assertEqual(self.fn("DF.GSM-ACCESS"), "df")

    def test_df_underscore_prefix_returns_df(self) -> None:
        self.assertEqual(self.fn("DF_TELECOM"), "df")
        self.assertEqual(self.fn("DF_GSM"), "df")

    def test_ef_prefix_returns_ef(self) -> None:
        self.assertEqual(self.fn("EF.ICCID"), "ef")
        self.assertEqual(self.fn("EF_IMSI"), "ef")
        self.assertEqual(self.fn("EF.DIR"), "ef")

    def test_unprefixed_with_children_falls_back_to_df(self) -> None:
        # Heuristic safety net: only directories carry children, so
        # an unprefixed entry that owns children must be a DF.
        self.assertEqual(self.fn("USIM", has_children=True), "df")

    def test_unprefixed_leaf_falls_back_to_ef(self) -> None:
        self.assertEqual(self.fn("ICCID", has_children=False), "ef")

    def test_empty_name_is_unknown(self) -> None:
        self.assertEqual(self.fn(""), "unknown")
        self.assertEqual(self.fn("   "), "unknown")

    def test_lowercase_input_is_normalised(self) -> None:
        # fids.txt entries are uppercased before classification, but
        # we should not crash on lowercase input — the classifier has
        # to cope with hand-rolled callers too.
        self.assertEqual(self.fn("adf_usim"), "adf")
        self.assertEqual(self.fn("df.telecom"), "df")


# ----------------------------------------------------------------------
# Backend: scan_tree wiring
# ----------------------------------------------------------------------


class FsControllerScanTreeKindWiring(unittest.TestCase):
    """The ``scan_tree`` collector must emit ``kind`` on every node."""

    def test_scan_tree_root_entry_includes_mf_kind(self) -> None:
        text = _FS_PY.read_text(encoding="utf-8")
        # Root entry is the literal MF dict embedded in scan_tree.
        # Every field on it has to be present + have the new kind="mf".
        self.assertIn('"name":"MF"', text)
        self.assertIn('"kind":"mf"', text)

    def test_live_scan_entry_includes_kind_field(self) -> None:
        text = _FS_PY.read_text(encoding="utf-8")
        # Recursive descendant collector calls the classifier with the
        # node's name + has_children so DF.TELECOM / ADF.USIM / etc.
        # land with the right kind.
        self.assertIn("self ._classify_tree_node_kind (", text)
        self.assertIn("has_children =bool (node .get ('children')),", text)


# ----------------------------------------------------------------------
# Frontend: classifier + DOM wiring
# ----------------------------------------------------------------------


class FrontendTreeClassifier(unittest.TestCase):
    """``renderTreeNodes`` must honour ``kind`` first, prefix-walk second."""

    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_classifier_function_exists(self) -> None:
        self.assertIn("function scp03ClassifyTreeNode(", self.js)

    def test_classifier_trusts_backend_kind_field(self) -> None:
        # The backend ``kind`` field is the new source of truth; the
        # JS wrapper has to consume it before falling back to prefix
        # matching, otherwise we lose the precise classification.
        self.assertIn('var raw = String((node && node.kind) || "").toLowerCase();', self.js)
        self.assertIn('if (raw === "mf") return "MF";', self.js)
        self.assertIn('if (raw === "df") return "DF";', self.js)
        self.assertIn('if (raw === "adf") return "ADF";', self.js)
        self.assertIn('if (raw === "ef") return "EF";', self.js)

    def test_classifier_prefix_walk_handles_dot_and_underscore(self) -> None:
        # The original bug-fix surface: both ``ADF.`` / ``ADF_`` and
        # both ``DF.`` / ``DF_`` must be matched, where the old code
        # only handled the un-separated prefix.
        self.assertIn('name.indexOf("ADF_") === 0 || name.indexOf("ADF.") === 0', self.js)
        self.assertIn('name.indexOf("DF_") === 0 || name.indexOf("DF.") === 0', self.js)
        self.assertIn('name.indexOf("EF_") === 0 || name.indexOf("EF.") === 0', self.js)

    def test_classifier_falls_back_to_df_when_node_has_children(self) -> None:
        # A directory always has children, an EF never does. Use that
        # invariant when the name carries no prefix.
        self.assertIn(
            'if (node && node.children && node.children.length > 0) return "DF";',
            self.js,
        )

    def test_render_tree_nodes_uses_classifier_for_icon(self) -> None:
        self.assertIn(
            "var kindLabel = scp03ClassifyTreeNode(node);", self.js,
        )
        self.assertIn("icon.textContent = kindLabel;", self.js)

    def test_render_tree_nodes_attaches_data_kind_on_row(self) -> None:
        # Tests + theme CSS need a stable hook on each row.
        self.assertIn('row.setAttribute("data-kind", kindLabel.toLowerCase());', self.js)

    def test_render_tree_nodes_attaches_kind_class_on_icon(self) -> None:
        self.assertIn(
            'icon.className = "cc-tree-icon cc-tree-icon--" + kindLabel.toLowerCase();',
            self.js,
        )

    def test_classifier_exposed_on_window_for_devtools(self) -> None:
        self.assertIn("window.YggdraSimScp03ClassifyTreeNode = scp03ClassifyTreeNode;", self.js)

    def test_old_buggy_classifier_is_gone(self) -> None:
        # Defensive: make sure nobody puts the old line back via a
        # bad merge or revert. The old shape was a single ternary
        # ``startsWith("ADF") ? "ADF" : "EF"``.
        self.assertNotIn(
            'icon.textContent = node.name === "MF" ? "MF" : '
            '(node.name && node.name.startsWith("ADF") ? "ADF" : "EF");',
            self.js,
        )


# ----------------------------------------------------------------------
# CSS: panel height + per-kind theme
# ----------------------------------------------------------------------


class FrontendTreePanelLayout(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _APP_CSS.read_text(encoding="utf-8")

    def test_tree_max_height_is_viewport_relative(self) -> None:
        # Old code: ``max-height: 460px`` flat. New behaviour: cap to
        # window height minus dock + ribbon room so taller monitors
        # actually use the available real estate.
        self.assertIn("max-height: calc(100vh - 280px);", self.css)

    def test_tree_min_height_floor_is_present(self) -> None:
        # A short window must still show a usable tree height — pick
        # a 360px floor so even half-screen Ubuntu tile mode is OK.
        self.assertIn("min-height: 360px;", self.css)

    def test_tree_no_longer_caps_at_460px(self) -> None:
        # Defensive: re-introducing the old cap silently hides nodes
        # below the fold. The 460px line was the only ``max-height``
        # for ``.cc-tree`` — make sure nobody re-added it.
        block_start = self.css.find(".cc-tree {")
        self.assertGreaterEqual(block_start, 0)
        block_end = self.css.find("}", block_start)
        self.assertGreaterEqual(block_end, 0)
        block = self.css[block_start:block_end]
        self.assertNotIn("max-height: 460px", block)

    def test_per_kind_icon_themes_exist(self) -> None:
        # Each ETSI file kind gets a dedicated colour cue so the eye
        # can scan deep hierarchies without re-reading the badge text.
        for selector in (
            ".cc-tree-icon--mf",
            ".cc-tree-icon--adf",
            ".cc-tree-icon--df",
            ".cc-tree-icon--ef",
        ):
            self.assertIn(selector, self.css)

    def test_tree_icon_min_width_locks_badge_alignment(self) -> None:
        # The icon column has to have a fixed minimum so MF / EF / ADF
        # / DF badges line up neatly even when the operator scrolls
        # quickly between depths.
        block_start = self.css.find(".cc-tree-icon {")
        self.assertGreaterEqual(block_start, 0)
        block_end = self.css.find("}", block_start)
        block = self.css[block_start:block_end]
        self.assertIn("min-width:", block)
        self.assertIn("text-align: center", block)


if __name__ == "__main__":
    unittest.main()
