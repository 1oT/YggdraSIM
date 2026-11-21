# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The fields of a profile element in the served bundle.

The Decoded view ends in every member the SAIP ASN.1 module gives the
selected element (``saipRenderPeFieldTree``), edited through
``saip.pe_structure_edit``. These tests pin the wiring between the bundle
and the two actions: where the fields mount, the reads and writes, the edit
names the action accepts, the widget kinds the backend emits, and the styles
the fields use.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_STATIC = _ROOT / "yggdrasim_common" / "gui_server" / "static"
_CHOICES = _ROOT / "Tools" / "ProfilePackage" / "saip_field_choices.py"


def _top_level_function(source: str, name: str) -> str:
    """The text of a function declared at the bundle's top indentation."""
    start = source.index(f"\n  function {name}(")
    end = source.find("\n  function ", start + 1)
    return source[start:end if end != -1 else len(source)]


class FieldTreeBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app_js = (_STATIC / "app.js").read_text(encoding="utf-8")
        self.app_css = (_STATIC / "app.css").read_text(encoding="utf-8")
        self.view = _top_level_function(self.app_js, "saipRenderPeFieldTree")

    def test_the_fields_are_declared_once_and_the_structure_tab_is_gone(self) -> None:
        # One concatenated scope: a second declaration would win silently.
        self.assertEqual(self.app_js.count("function saipRenderPeFieldTree("), 1)
        self.assertNotIn("tabStructure", self.app_js)
        self.assertNotIn("function saipRenderPeStructureView(", self.app_js)
        self.assertIn("[tabEditor, tabJson]", self.app_js)

    def test_every_element_ends_in_its_fields(self) -> None:
        editor = _top_level_function(self.app_js, "renderSaipPeEditor")
        self.assertIn(
            "saipRenderPeFieldTree(data, pkg, peList, validation, { collapsed: fieldsCollapsed })",
            editor,
        )
        # File-system elements and GFM edit their files in a workbench of
        # their own; their fields come folded.
        self.assertGreaterEqual(editor.count("fieldsCollapsed = true;"), 3)

    def test_reads_and_edits_go_through_the_two_actions(self) -> None:
        self.assertIn('"/api/actions/saip.pe_structure/run"', self.view)
        self.assertIn('saipPostAction(pkg, "saip.pe_structure_edit", request)', self.view)

    def test_every_edit_the_view_sends_is_one_the_action_accepts(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as _saip  # noqa: F401 -- registers the specs
        from yggdrasim_common.gui_server.actions.registry import get_registry

        spec = get_registry()._specs["saip.pe_structure_edit"]
        accepted = set(next(field for field in spec.inputs if field.name == "op").choices)
        sent = set(re.findall(r'\bop: "([a-z_]+)"', self.view))
        self.assertTrue(sent)
        self.assertLessEqual(sent, accepted)

    def test_every_widget_the_backend_emits_has_a_control(self) -> None:
        emitted = set(re.findall(r'"kind": "([a-z_]+)"', _CHOICES.read_text(encoding="utf-8")))
        handled = set(re.findall(r'kind === "([a-z_]+)"', self.view))
        self.assertTrue(emitted)
        self.assertLessEqual(emitted, handled)

    def test_a_member_its_card_edits_points_at_the_card(self) -> None:
        # The PE-SD's sdPersoData is edited in SD personalisation data
        # (saip_field_choices marks it "card"); the fields hold no inputs for it.
        self.assertIn(
            'if (node.widget && node.widget.kind === "card") return renderCardPointer(node, parent);',
            self.view,
        )
        self.assertIn('"Edited in " + String(node.widget.title || "its card") + " below."', self.view)
        self.assertNotIn("function dgiControl(", self.app_js)

    def test_a_typed_value_goes_out_once(self) -> None:
        # Enter and leaving the field both fire change; the value is sent once.
        self.assertIn("var sent = initial;", self.view)
        self.assertIn("if (value === sent) return;", self.view)

    def test_a_folded_card_stays_open_across_a_refresh(self) -> None:
        self.assertIn("pkg.fieldTreeFold[sectionKey] = card.open;", self.view)
        self.assertIn("card.open = pkg.fieldTreeFold[sectionKey] === true;", self.view)

    def test_folded_groups_are_built_when_first_opened(self) -> None:
        self.assertIn("if (box.open) build();", self.view)
        self.assertIn("buildGroup(node, depth, body)", self.view)

    def test_the_styles_ship(self) -> None:
        for selector in (
            ".saip-structure-tree",
            ".saip-structure-node",
            ".saip-structure-leaf",
            ".saip-structure-caption",
            ".saip-structure-error",
            ".saip-structure-bits",
            ".saip-structure-placeholder",
        ):
            self.assertIn(selector, self.app_css)


if __name__ == "__main__":
    unittest.main()
