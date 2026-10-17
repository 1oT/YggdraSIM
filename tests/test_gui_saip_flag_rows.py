# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Flag lists and PE-Application instances in the served bundle.

The SAIP workbench lists its bit and service lists one flag per row
(``views/saip/flag-rows.css``), and a PE-Application instance is edited in
place (``saip.update_application_instance``), with the security domain's
parameter editor bound to its ``instanceList`` entry. These tests pin the
row layout against a stylesheet that brings columns back, and the wiring
between the instance card, the instance dialog and the two actions.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_security_domain_decode import decode_privileges

_ROOT = Path(__file__).resolve().parents[1]
_STATIC = _ROOT / "yggdrasim_common" / "gui_server" / "static"

# Every list of check boxes the SAIP workbench renders, by container class.
_FLAG_LISTS = (
    "saip-structure-flags",
    "saip-wizard-ust-grid",
    "saip-wizard-bitgrid",
    "saip-arr-wizard-am",
    "saip-profile-services-grid",
    "saip-decoded-services-list",
    "saip-form-bitmask-wrap",
)


def _top_level_function(source: str, name: str) -> str:
    """The text of a function declared at the bundle's top indentation."""
    match = re.search(r"\n  (?:async )?function " + re.escape(name) + r"\(", source)
    if match is None:
        raise AssertionError(f"function {name} is not declared at the top level")
    end = re.compile(r"\n  (?:async )?function ").search(source, match.end())
    return source[match.start():end.start() if end else len(source)]


def _rules(css: str) -> list[tuple[str, str]]:
    """``(selector list, declarations)`` of every innermost rule."""
    bare = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [(match.group(1).strip(), match.group(2)) for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", bare)]


class FlagRowsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app_css = (_STATIC / "app.css").read_text(encoding="utf-8")
        self.app_js = (_STATIC / "app.js").read_text(encoding="utf-8")

    def test_every_flag_list_is_one_column(self) -> None:
        one_column = [
            selectors for selectors, body in _rules(self.app_css)
            if "grid-template-columns: minmax(0, 1fr);" in body and ".saip-wizard-ust-grid" in selectors
        ]
        self.assertEqual(len(one_column), 1)
        listed = {selector.strip() for selector in one_column[0].split(",")}
        for klass in _FLAG_LISTS:
            with self.subTest(klass=klass):
                self.assertIn("." + klass, listed)
                token = re.compile(r"\." + re.escape(klass) + r"(?![\w-])")
                named = [(selectors, body) for selectors, body in _rules(self.app_css) if token.search(selectors)]
                self.assertTrue(named, f"no rule styles .{klass}")
                for selectors, body in named:
                    self.assertNotIn("repeat(", body, f"{selectors} lays .{klass} out in columns")
                    self.assertNotIn("flex-wrap: wrap", body, f"{selectors} wraps .{klass} like text")

    def test_the_bit_widgets_of_the_fields_are_flag_lists(self) -> None:
        view = _top_level_function(self.app_js, "saipRenderPeFieldTree")
        # The bit fields and an access domain's key bits.
        self.assertEqual(view.count('grid.className = "saip-structure-flags";'), 2)
        # The file descriptor's controls stay on one wrapping line.
        self.assertIn('wrap.className = "saip-structure-bits";', view)
        self.assertIn('row.classList.add("saip-structure-leaf--list");', view)

    def test_only_a_security_domains_privileges_are_a_grid_of_chips(self) -> None:
        # saip_field_choices marks the PE-SD privileges with layout "grid";
        # every other bit field stays a one-column flag list.
        view = _top_level_function(self.app_js, "saipRenderPeFieldTree")
        self.assertIn('if (widget.layout === "grid") return privilegeGridControl(node, widget, ui);', view)
        self.assertIn('chipGrid.className = "saip-priv-grid";', view)
        self.assertIn('row.classList.add("saip-structure-leaf--grid");', view)
        self.assertIn('"Privileges (" + held + " of " + chips.length + " active)"', view)
        self.assertNotIn("saip-priv-grid", _FLAG_LISTS)
        grids = [body for selectors, body in _rules(self.app_css) if selectors == ".saip-priv-grid"]
        self.assertEqual(len(grids), 1)
        self.assertIn("repeat(auto-fill, minmax(180px, 1fr))", grids[0])

    def test_the_aid_directory_shows_a_security_domains_privileges_as_the_grid(self) -> None:
        card = _top_level_function(self.app_js, "saipBuildApplicationCard")
        self.assertIn(
            "var privPanel = row.is_security_domain && privHex ? saipPrivilegeChipPanel(privHex) : null;",
            card,
        )
        # An application's card keeps the list of the privileges it holds.
        self.assertIn('chip.className = "saip-app-priv";', card)
        self.assertEqual(self.app_js.count("function saipPrivilegeChipPanel("), 1)
        panel = _top_level_function(self.app_js, "saipPrivilegeChipPanel")
        self.assertIn('grid.className = "saip-priv-grid";', panel)
        self.assertIn('bit[1].indexOf("RFU") !== 0', panel)
        self.assertIn('"Privileges (" + on + " of " + named.length + " active)"', panel)
        # Its chips are read-only: the pointer and the hover belong to a label.
        self.assertIn(".saip-priv-chip:where(label):hover", self.app_css)
        self.assertNotIn(".saip-priv-chip:hover", self.app_css)

    def test_byte_three_b4_is_self_removal(self) -> None:
        # GP Card Spec v2.3.1 Table 11-9 (page 149): privilege 20.
        self.assertIn('{ byte: 2, mask: 0x08, label: "Self-Removal" }', self.app_js)
        self.assertIn('[0x000008, "Self-Removal"]', self.app_js)
        self.assertNotIn("RFU bit 21", self.app_js)
        self.assertEqual(decode_privileges("000008")["flags"], ["Self-Removal"])
        # A one-byte field is byte 1 (Table 11-43, page 179).
        self.assertEqual(decode_privileges("80")["flags"], ["Security Domain"])


class ApplicationInstanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app_js = (_STATIC / "app.js").read_text(encoding="utf-8")
        self.card = _top_level_function(self.app_js, "saipEditorRenderApplicationCard")

    def test_an_instance_is_edited_in_place(self) -> None:
        self.assertIn('"Edit instance\\u2026"', self.card)
        self.assertIn('run("saip.update_application_instance", identity);', self.card)
        self.assertIn("identity.new_instance_aid_hex", self.card)
        self.assertIn('run("saip.add_application_instance", identity);', self.card)

    def test_the_package_is_the_pe_package(self) -> None:
        self.assertIn("readonly: packageLocked", self.card)
        self.assertIn("String(summary.own_package_hex || \"\")", self.card)
        self.assertIn("String(inst.own_package_hex || \"\")", self.card)

    def test_the_privileges_are_one_check_box_per_bit(self) -> None:
        self.assertIn('type: "bitmask", def: privilegesDef', self.card)
        modal = _top_level_function(self.app_js, "saipShowFormModal")
        self.assertIn('f.type === "bitmask"', modal)
        self.assertIn("saipFormBitmaskInput(values[f.key], f.def,", modal)
        self.assertIn("inp.readOnly = true", modal)
        self.assertIn(".saip-form-text:not([readonly])", modal)

    def test_the_security_domain_parameters_open_and_an_instances_stay_folded(self) -> None:
        editor = _top_level_function(self.app_js, "saipSdParamRenderEditor")
        self.assertIn('if (typeof opts.instanceIndex !== "number") {', editor)
        self.assertIn("card.open = !(pkg && pkg.sdParamFold[foldKey] === false);", editor)
        self.assertIn("pkg.sdParamFold[foldKey] = card.open;", editor)

    def test_each_instance_gets_the_parameter_editor(self) -> None:
        self.assertEqual(self.app_js.count("function saipEditorRenderInstanceParameterCards("), 1)
        self.assertIn(
            "saipEditorRenderInstanceParameterCards(wrap, decoded, pkg, sectionKey, peList, validation, data);",
            self.app_js,
        )
        renderer = _top_level_function(self.app_js, "saipEditorRenderInstanceParameterCards")
        self.assertIn("instanceIndex: index,", renderer)
        self.assertIn("withoutC9: true,", renderer)
        self.assertIn("decoded._instance_parameter_summaries", renderer)
        apply = _top_level_function(self.app_js, "saipSdParamApply")
        self.assertIn("inputs.instance_index = opts.instanceIndex;", apply)
        self.assertIn("delete parameterState.c9_enabled;", apply)


if __name__ == "__main__":
    unittest.main()
