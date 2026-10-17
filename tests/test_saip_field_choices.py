# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Value choices offered for the members of a SAIP profile element.

``Tools/ProfilePackage/saip_field_choices`` attaches a list, a bit editor or
suggestions to the leaves of a ``saip_structure_edit`` projection. These
tests pin which member gets which widget, the codings the tables carry, and
that every value a list offers is one the member's ASN.1 type accepts.
"""

from __future__ import annotations

import copy
import importlib
import unittest
from typing import Any


def _pysim_available() -> bool:
    try:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        importlib.import_module("pySim.esim.saip")
    except Exception:  # noqa: BLE001 -- any import failure means "skip"
        return False
    return True


def _nodes(tree: dict[str, Any]) -> list[dict[str, Any]]:
    out, stack = [], [tree]
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(node.get("children") or [])
    return out


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class FieldChoicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        cls.S = importlib.import_module("Tools.ProfilePackage.saip_structure_edit")
        cls.C = importlib.import_module("Tools.ProfilePackage.saip_field_choices")

    def _tree(self, pe_type: str, edits: tuple[tuple[list[Any], str], ...] = ()) -> dict[str, Any]:
        pe = self.saip._build_default_pe(pe_type)
        section = copy.deepcopy(pe.decoded)
        for path, value in edits:
            self.S.set_leaf(section, pe_type, path, value)
        tree = self.S.structure(section, pe_type)
        self.C.annotate(tree, pe_type, aids=[{"value": "A0000000871002", "label": "ADF.USIM"}])
        return tree

    def _at(self, tree: dict[str, Any], path: list[Any]) -> dict[str, Any]:
        return next(node for node in _nodes(tree) if node["path"] == path)

    def _values(self, widget: dict[str, Any]) -> list[str]:
        return [choice["value"] for choice in widget["choices"]]

    def test_life_cycle_follows_the_element(self) -> None:
        # GP Card Spec v2.3.1 Table 11-5 has PERSONALIZED for a security
        # domain; Table 11-4 has none for an application (page 147).
        sd = self._at(self._tree("securityDomain"), ["instance", "lifeCycleState"])
        self.assertIn("0F", self._values(sd["widget"]))
        app = self._tree("application", ((["instanceList", 0, "instanceAID"], "A000000087100201"),))
        app_state = self._at(app, ["instanceList", 0, "lifeCycleState"])
        self.assertNotIn("0F", self._values(app_state["widget"]))

    def test_privileges_are_three_bytes_of_bits(self) -> None:
        # GP Card Spec v2.3.1 Tables 11-7 to 11-9 (page 149).
        node = self._at(self._tree("securityDomain"), ["instance", "applicationPrivileges"])
        widget = node["widget"]
        self.assertEqual((widget["kind"], widget["width"]), ("bits", 3))
        labels = {(field["byte"], field["shift"]): field["label"] for field in widget["fields"]}
        self.assertEqual(labels[(0, 7)], "Security Domain")
        self.assertEqual(labels[(1, 6)], "Authorized Management")
        self.assertEqual(labels[(2, 3)], "Self-Removal")

    def test_only_a_security_domain_lays_its_privileges_out_as_a_grid(self) -> None:
        sd = self._at(self._tree("securityDomain"), ["instance", "applicationPrivileges"])
        self.assertEqual(sd["widget"].get("layout"), "grid")
        app = self._tree("application", ((["instanceList", 0, "instanceAID"], "A000000087100201"),))
        app_privileges = self._at(app, ["instanceList", 0, "applicationPrivileges"])["widget"]
        self.assertEqual(app_privileges["kind"], "bits")
        self.assertNotIn("layout", app_privileges)
        self.assertNotIn("layout", self._at(app, ["instanceList", 0, "lifeCycleState"])["widget"])

    def test_key_members_get_the_gp_tables_inside_the_key_list_only(self) -> None:
        tree = self._tree("securityDomain", ((["keyList", 0, "keyIdentifier"], "01"),))
        usage = self._at(tree, ["keyList", 0, "keyUsageQualifier"])["widget"]
        self.assertIn({"value": "38", "label": "C-ENC + R-ENC"}, usage["choices"])
        access = self._at(tree, ["keyList", 0, "keyAccess"])["widget"]
        self.assertEqual(self._values(access), ["00", "01", "02", "FF"])
        key_type = self._at(tree, ["keyList", 0, "keyComponents", 0, "keyType"])["widget"]
        # Table 11-16 (page 155): 'A0' is the public exponent, 'A1' the modulus.
        labels = {choice["value"]: choice["label"] for choice in key_type["choices"]}
        self.assertEqual(labels["A0"], "RSA public key, public exponent e")
        self.assertEqual(labels["A1"], "RSA public key, modulus N")

    def test_pin_attributes_and_attempts_are_bit_fields_of_an_integer(self) -> None:
        tree = self._tree("pinCodes", ((["pinCodes", "pinconfig", 0, "keyReference"], "pinAppl1"),))
        attributes = self._at(tree, ["pinCodes", "pinconfig", 0, "pinAttributes"])["widget"]
        self.assertTrue(attributes["integer"])
        self.assertEqual([field["label"] for field in attributes["fields"]][0], "PIN enabled")
        attempts = self._at(tree, ["pinCodes", "pinconfig", 0, "maxNumOfAttemps-retryNumLeft"])["widget"]
        self.assertEqual([(field["shift"], field["mask"]) for field in attempts["fields"]], [(4, 15), (0, 15)])
        reference = self._at(tree, ["pinCodes", "pinconfig", 0, "keyReference"])["widget"]
        self.assertEqual(reference["kind"], "select")
        self.assertIn({"value": "10", "label": "adm1 (10)"}, reference["choices"])

    def test_aka_options(self) -> None:
        tree = self._tree("akaParameter")
        options = self._at(tree, ["algoConfiguration", "algoParameter", "algorithmOptions"])["widget"]
        self.assertEqual([field["label"] for field in options["fields"]],
                         ["RES size", "MAC-A and MAC-S size", "CK and IK size"])
        self.assertEqual(self._at(tree, ["sqnOptions"])["widget"]["kind"], "bits")
        self.assertEqual(
            self._at(tree, ["algoConfiguration", "algoParameter", "algorithmID"])["widget"]["kind"], "select",
        )

    def test_rfm_tars_are_suggested_from_ts_101_220(self) -> None:
        tree = self._tree("rfm", ((["tarList", 0], "B00000"),))
        widget = self._at(tree, ["tarList", 0])["widget"]
        self.assertEqual(widget["kind"], "suggest")
        self.assertIn({"value": "B00001", "label": "ADF, compact format"}, widget["choices"])

    def test_aids_are_suggested_and_flags_are_flags(self) -> None:
        tree = self._tree("rfm")
        self.assertEqual(self._at(tree, ["instanceAID"])["widget"]["kind"], "suggest")
        self.assertEqual(self._at(tree, ["rfm-header", "mandated"])["widget"], {"kind": "flag"})

    def _gfm_fcp(self) -> tuple[dict[str, Any], list[Any]]:
        section = copy.deepcopy(self.saip._build_default_pe("genericFileManagement").decoded)
        command = ["fileManagementCMD", 0, 0]
        self.S.set_choice(section, "genericFileManagement", command, "createFCP")
        return section, command + ["createFCP"]

    def test_a_short_file_identifier_is_picked(self) -> None:
        # ETSI TS 102 221 v18.4 §11.1.1.4.8 (page 98) and §8.3 (page 61).
        section, fcp = self._gfm_fcp()
        tree = self.S.structure(section, "genericFileManagement")
        self.C.annotate(tree, "genericFileManagement")
        widget = self._at(tree, fcp + ["shortEFID"])["widget"]
        self.assertEqual(widget["choices"][0], {"value": "", "label": "No SFI (empty)"})
        self.assertIn({"value": "F0", "label": "SFI 30"}, widget["choices"])
        self.assertIn("file ID", widget["absent_label"])
        schema = self.S.load_schema()
        node = self.S._node_at(schema, "genericFileManagement", fcp + ["shortEFID"])
        for choice in widget["choices"]:
            self.S._parse_leaf(schema, node, choice["value"], "shortEFID")

    def test_rfm_security_level_and_access_domains(self) -> None:
        tree = self._tree("rfm")
        msl = self._at(tree, ["minimumSecurityLevel"])["widget"]
        # ETSI TS 102 225 V19.0.0 §5.1.1 (page 13): b2-b1, b3, b5-b4.
        self.assertEqual([(field["shift"], field["mask"]) for field in msl["fields"]], [(0, 3), (2, 1), (3, 3)])
        domain = self._at(tree, ["uiccAccessDomain"])["widget"]
        self.assertEqual(domain["kind"], "access_domain")
        # ETSI TS 102 226 V19.0.0 §8.2.1.3.2.5 (pages 29-30).
        self.assertEqual([entry["value"] for entry in domain["parameters"]], ["00", "02", "FF"])
        labels = {(field["byte"], field["shift"]): field["label"] for field in domain["keys"]}
        self.assertEqual(labels[(0, 0)], "Application PIN 1")
        self.assertEqual(labels[(1, 7)], "ADM8")
        self.assertEqual(labels[(2, 2)], "ALWAYS")

    def test_perso_data_points_at_the_card_that_edits_it(self) -> None:
        tree = self._tree("securityDomain", ((["sdPersoData", 0], "801003AABBCC"),))
        member = self._at(tree, ["sdPersoData"])
        self.assertEqual(member["widget"], {"kind": "card", "title": "SD personalisation data"})
        self.assertNotIn("widget", self._at(tree, ["sdPersoData", 0]))

    def test_every_rule_of_the_ef_arr_is_offered(self) -> None:
        from pathlib import Path

        sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        profile = Path(__file__).resolve().parents[1] / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        sid = self.saip._dispatch_open_package(ctx=None, path=str(profile))["session_id"]
        self.addCleanup(lambda: sessions.get_manager().close(sid))
        rows = self.saip._dispatch_list_files(ctx=None, session_id=sid)["rows"]
        row = next(row for row in rows if str(row.get("file_id") or "").upper() == "6F07")
        shown = self.saip._dispatch_show_file(
            ctx=None, session_id=sid, section_key=row["section_key"], field_path=row["field_path"],
        )
        rule = shown["access_rule"]
        records = [choice["record"] for choice in rule["choices"]]
        self.assertIn(rule["record"], records)
        self.assertTrue(all(choice["summary"] for choice in rule["choices"] if not choice["empty"]))

    def test_every_offered_value_is_one_the_member_takes(self) -> None:
        rows = self.saip._dispatch_list_pe_types(ctx=None)["rows"]
        schema = self.S.load_schema()
        checked = 0
        for pe_type in [row["pe_type"] for row in rows if row["addable"]]:
            tree = self.S.structure(copy.deepcopy(self.saip._build_default_pe(pe_type).decoded), pe_type)
            self.C.annotate(tree, pe_type)
            for node in _nodes(tree):
                widget = node.get("widget")
                if not widget or widget["kind"] not in ("select", "suggest"):
                    continue
                schema_node = self.S._node_at(schema, pe_type, node["path"])
                for choice in widget["choices"]:
                    with self.subTest(pe_type=pe_type, path=node["path"], value=choice["value"]):
                        self.S._parse_leaf(schema, schema_node, choice["value"], "/".join(map(str, node["path"])))
                        checked += 1
        self.assertGreater(checked, 50)


if __name__ == "__main__":
    unittest.main()
