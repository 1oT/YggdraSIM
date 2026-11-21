# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Every member of every addable profile element is reachable from a blank PE.

``Tools/ProfilePackage/saip_structure_edit`` reads the SAIP ASN.1 module pySim
compiled. The coverage tests start from the blank ``saip.add_pe`` builds for
each type ``saip.list_pe_types`` offers, add every absent member, give every
list an entry, visit every CHOICE alternative, set every leaf to a value of
its own, and check the element encodes and decodes to exactly that. The
projection is checked to name every schema member. TCA SAIP v3.4.1 section 8
defines the elements.
"""

from __future__ import annotations

import copy
import importlib
import tempfile
import unittest
from pathlib import Path
from typing import Any

_REFERENCE_HEX = Path(__file__).resolve().parents[1] / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
# The header ICCID and one PUK of the reference profile, as in
# tests/test_saip_inline_template_values.py.
_HEADER_ICCID_HEX = "89880811111111111112"
_PUK_HEX = b"12345678".hex().upper()


def _pysim_available() -> bool:
    try:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        importlib.import_module("pySim.esim.saip")
    except Exception:  # noqa: BLE001 -- any import failure means "skip"
        return False
    return True


def _leaf_text(schema: Any, node: dict[str, Any]) -> str | None:
    """A valid value of the leaf's own, different from its filler and DEFAULT."""
    kind = node["kind"]
    if kind == "octets":
        size = schema.size(node)
        low, high = size if size is not None else (0, None)
        length = max(low, 1)
        if high is not None:
            length = min(length, high)
        return "5A" * length if length else ""
    if kind in ("integer", "enumerated"):
        named = schema.named_numbers(node)
        if named:
            return max(named, key=lambda name: named[name])
        span = schema.value_range(node)
        low = span[0] if span and span[0] is not None else 0
        high = span[1] if span and span[1] is not None else low + 2
        return str(min(low + 1, high))
    if kind == "oid":
        return "2.999.7"
    if kind == "text":
        size = schema.size(node)
        return "x" * max(1, (size or (1, None))[0])
    if kind == "boolean":
        return "true"
    return None


class _Walker:
    """Materialises every member below a path and records what it set."""

    def __init__(self, module: Any, schema: Any, section: dict[str, Any], pe_type: str) -> None:
        self.S = module
        self.schema = schema
        self.section = section
        self.pe_type = pe_type
        self.expected: dict[tuple, Any] = {}
        self.choices_seen: set[int] = set()

    def fill(self, path: list[Any]) -> None:
        node, value, _parent, _last = self.S._locate(self.schema, self.pe_type, self.section, path)
        kind = node["kind"]
        if kind == "sequence":
            for member in self.schema.members(node):
                current = self.S._locate(self.schema, self.pe_type, self.section, path)[1]
                if member["name"] not in current:
                    self.S.add_member(self.section, self.pe_type, path, member["name"])
                self.fill(path + [member["name"]])
            return
        if kind == "sequence_of":
            size = self.schema.size(node)
            maximum = size[1] if size is not None else None
            entries = self.S._locate(self.schema, self.pe_type, self.section, path)[1]
            # One entry past what the element holds, where SIZE allows it.
            if maximum is None or len(entries) < maximum:
                self.S.add_entry(self.section, self.pe_type, path)
            entries = self.S._locate(self.schema, self.pe_type, self.section, path)[1]
            # One entry proves the element type; a long fixed list (sqnInit)
            # gets its last entry set as well.
            for index in sorted({0, len(entries) - 1}):
                self.fill(path + [index])
            return
        if kind == "choice":
            alternatives = [member["name"] for member in self.schema.members(node)]
            if id(node.get("members")) not in self.choices_seen:
                self.choices_seen.add(id(node.get("members")))
                # Visit every alternative once per CHOICE type; each one must
                # take a value and encode before the next replaces it.
                for alternative in alternatives:
                    self.S.set_choice(self.section, self.pe_type, path, alternative)
                    probe = _Walker(self.S, self.schema, self.section, self.pe_type)
                    probe.choices_seen = self.choices_seen
                    probe.fill(path + [alternative])
                    _assert_round_trip(self.section, self.pe_type, probe.expected)
            active = self.S._choice_parts(self.S._locate(self.schema, self.pe_type, self.section, path)[1])[0]
            self.fill(path + [active])
            return
        if kind == "null":
            self.expected[tuple(path)] = None
            return
        text = _leaf_text(self.schema, node)
        if text is None:
            return
        header = self.S._header_member(self.schema, self.pe_type)
        if header is not None and path == [header, "identification"]:
            return
        self.S.set_leaf(self.section, self.pe_type, path, text)
        self.expected[tuple(path)] = self.S._locate(self.schema, self.pe_type, self.section, path)[1]


def _value_at(decoded: Any, path: tuple) -> Any:
    value = decoded
    for step in path:
        if isinstance(value, tuple):
            assert value[0] == step, (path, value[0])
            value = value[1]
        elif isinstance(value, list):
            value = value[step]
        else:
            value = value[step]
    return value


def _assert_round_trip(section: dict[str, Any], pe_type: str, expected: dict[tuple, Any]) -> None:
    from pySim.esim.saip import asn1

    der = asn1.encode("ProfileElement", (pe_type, section))
    choice, decoded = asn1.decode("ProfileElement", der)
    assert choice == pe_type
    for path, value in expected.items():
        got = _value_at(decoded, path)
        assert got == value, f"{pe_type} {'/'.join(map(str, path))}: {got!r} != {value!r}"


def _schema_member_names(schema: Any, node: dict[str, Any]) -> list[str]:
    return [member["name"] for member in schema.members(node)]


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class EveryMemberIsReachableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        cls.S = importlib.import_module("Tools.ProfilePackage.saip_structure_edit")
        cls.schema = cls.S.load_schema()
        rows = cls.saip._dispatch_list_pe_types(ctx=None)["rows"]
        cls.types = [row["pe_type"] for row in rows if row["addable"]]

    def _blank(self, pe_type: str) -> dict[str, Any]:
        pe = self.saip._build_default_pe(pe_type)
        section = copy.deepcopy(pe.decoded)
        header = self.S._header_member(self.schema, pe_type)
        if header is not None:
            section.setdefault(header, {})["identification"] = 1
        return section

    def test_every_member_of_every_addable_type_takes_a_value_and_round_trips(self) -> None:
        self.assertIn("application", self.types)
        for pe_type in self.types:
            with self.subTest(pe_type=pe_type):
                section = self._blank(pe_type)
                walker = _Walker(self.S, self.schema, section, pe_type)
                walker.fill([])
                self.assertGreater(len(walker.expected), 0)
                _assert_round_trip(section, pe_type, walker.expected)

    def test_the_header_and_end_of_a_profile_take_every_member_too(self) -> None:
        # Neither is offered by saip.add_pe; both are in every package.
        from pathlib import Path

        sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        profile = Path(__file__).resolve().parents[1] / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        sid = self.saip._dispatch_open_package(ctx=None, path=str(profile))["session_id"]
        self.addCleanup(lambda: sessions.get_manager().close(sid))
        document = sessions.get_manager().claim(sid)["decoded_document"]
        for pe_type, section_key in (("header", "header"), ("end", "end")):
            with self.subTest(pe_type=pe_type):
                section = copy.deepcopy(document["sections"][section_key])
                walker = _Walker(self.S, self.schema, section, pe_type)
                walker.fill([])
                self.assertGreater(len(walker.expected), 0)
                _assert_round_trip(section, pe_type, walker.expected)

    def test_the_projection_names_every_schema_member(self) -> None:
        for pe_type in self.types:
            with self.subTest(pe_type=pe_type):
                section = self._blank(pe_type)
                _Walker(self.S, self.schema, section, pe_type).fill([])
                stack = [(self.S.structure(section, pe_type), self.schema.element_node(pe_type))]
                while stack:
                    tree, node = stack.pop()
                    if node["kind"] == "sequence":
                        self.assertEqual(
                            [child["name"] for child in tree["children"]],
                            _schema_member_names(self.schema, node),
                        )
                        for child, member in zip(tree["children"], self.schema.members(node)):
                            if child["present"]:
                                stack.append((child, member))
                    elif node["kind"] == "sequence_of":
                        real = [child for child in tree["children"] if not child.get("phantom")]
                        for child in real[:1]:
                            stack.append((child, self.schema.element(node)))
                    elif node["kind"] == "choice":
                        active = tree["active"]
                        member = next(m for m in self.schema.members(node) if m["name"] == active)
                        stack.append((tree["children"][0], member))


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class StructureGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        cls.S = importlib.import_module("Tools.ProfilePackage.saip_structure_edit")

    def _aka(self) -> dict[str, Any]:
        pe = self.saip._build_default_pe("akaParameter")
        section = copy.deepcopy(pe.decoded)
        section["aka-header"]["identification"] = 1
        return section

    def test_a_size_constraint_is_named_in_the_refusal(self) -> None:
        section = self._aka()
        with self.assertRaisesRegex(self.S.SaipStructureError, r"SIZE \(6\)"):
            self.S.set_leaf(section, "akaParameter", ["sqnDelta"], "0102")

    def test_a_mandatory_member_is_not_removed(self) -> None:
        with self.assertRaises(self.S.SaipStructureError):
            self.S.remove_member(self._aka(), "akaParameter", [], "algoConfiguration")

    def test_the_identification_is_left_to_the_tool(self) -> None:
        with self.assertRaises(self.S.SaipStructureError):
            self.S.set_leaf(self._aka(), "akaParameter", ["aka-header", "identification"], "5")

    def test_a_fixed_size_list_takes_no_extra_entry(self) -> None:
        # sqnInit is SEQUENCE (SIZE (32)) (TCA SAIP v3.4.1 page 48).
        with self.assertRaises(self.S.SaipStructureError):
            self.S.add_entry(self._aka(), "akaParameter", ["sqnInit"])

    def test_a_mandatory_list_keeps_its_minimum(self) -> None:
        pe = self.saip._build_default_pe("pinCodes")
        section = copy.deepcopy(pe.decoded)
        self.S.add_entry(section, "pinCodes", ["pinCodes", "pinconfig"])
        with self.assertRaises(self.S.SaipStructureError):
            self.S.remove_entry(section, "pinCodes", ["pinCodes", "pinconfig"], 0)

    def test_an_optional_list_goes_with_its_last_entry(self) -> None:
        pe = self.saip._build_default_pe("application")
        section = copy.deepcopy(pe.decoded)
        self.S.add_member(section, "application", [], "instanceList")
        self.S.remove_entry(section, "application", ["instanceList"], 0)
        self.assertNotIn("instanceList", section)

    def test_a_named_integer_takes_its_name(self) -> None:
        pe = self.saip._build_default_pe("pinCodes")
        section = copy.deepcopy(pe.decoded)
        self.S.add_entry(section, "pinCodes", ["pinCodes", "pinconfig"])
        self.S.set_leaf(section, "pinCodes", ["pinCodes", "pinconfig", 0, "keyReference"], "adm1")
        self.assertEqual(section["pinCodes"][1][0]["keyReference"], 10)

    def test_only_a_filler_no_profile_carries_is_a_placeholder(self) -> None:
        section = self._aka()
        self.S.set_choice(section, "akaParameter", ["algoConfiguration"], "mappingParameter")
        mapping = self.S.structure(section, "akaParameter")["children"][1]["children"][0]["children"]
        flags = {child["name"]: child["placeholder"] for child in mapping}
        # The zero AID is no AID; mappingOptions '00' is a valid SQN mode.
        self.assertEqual(flags, {"mappingOptions": False, "mappingSource": True})
        self.S.set_leaf(
            section, "akaParameter", ["algoConfiguration", "mappingParameter", "mappingSource"],
            "A0000000871002",
        )
        mapping = self.S.structure(section, "akaParameter")["children"][1]["children"][0]["children"]
        self.assertFalse(mapping[1]["placeholder"])

    def test_a_value_typed_below_absent_members_creates_them(self) -> None:
        pe = self.saip._build_default_pe("application")
        section = copy.deepcopy(pe.decoded)
        path = ["instanceList", 0, "systemSpecificParameters", "volatileMemoryQuotaC7"]
        self.S.set_leaf(section, "application", path, "0400")
        self.assertEqual(section["instanceList"][0]["systemSpecificParameters"]["volatileMemoryQuotaC7"], b"\x04\x00")
        # The index one past the end of a list appends an entry.
        self.S.set_leaf(section, "application", ["instanceList", 1, "instanceAID"], "A000000087100202")
        self.assertEqual(len(section["instanceList"]), 2)
        with self.assertRaises(self.S.SaipStructureError):
            self.S.set_leaf(section, "application", ["instanceList", 5, "instanceAID"], "A000000087100202")

    def test_clearing_the_last_value_of_an_optional_container_removes_it(self) -> None:
        pe = self.saip._build_default_pe("application")
        section = copy.deepcopy(pe.decoded)
        path = ["instanceList", 0, "systemSpecificParameters", "volatileMemoryQuotaC7"]
        self.S.set_leaf(section, "application", path, "0400")
        summary = self.S.clear(section, "application", path)
        self.assertIn("systemSpecificParameters", summary)
        self.assertNotIn("systemSpecificParameters", section["instanceList"][0])
        with self.assertRaisesRegex(self.S.SaipStructureError, "mandatory"):
            self.S.clear(section, "application", ["instanceList", 0, "classAID"])
        self.assertIn("not set", self.S.clear(section, "application", path))

    def test_a_null_member_is_a_flag(self) -> None:
        section = self._aka()
        path = ["aka-header", "mandated"]
        self.S.set_leaf(section, "akaParameter", path, "false")
        self.assertNotIn("mandated", section["aka-header"])
        self.S.set_leaf(section, "akaParameter", path, "true")
        self.assertIn("mandated", section["aka-header"])
        self.assertIsNone(section["aka-header"]["mandated"])

    def test_an_alternative_is_picked_in_a_new_list_entry(self) -> None:
        pe = self.saip._build_default_pe("pinCodes")
        section = copy.deepcopy(pe.decoded)
        self.S.set_choice(section, "pinCodes", ["pinCodes"], "filePath")
        self.assertEqual(section["pinCodes"][0], "filePath")
        # A CHOICE holding a value is switched explicitly, never by a path
        # that runs through another alternative.
        with self.assertRaisesRegex(self.S.SaipStructureError, "switch it"):
            self.S.set_leaf(section, "pinCodes", ["pinCodes", "pinconfig", 0, "keyReference"], "adm1")

    def test_absent_members_and_list_ends_are_projected(self) -> None:
        pe = self.saip._build_default_pe("application")
        tree = self.S.structure(copy.deepcopy(pe.decoded), "application")
        load_block = next(child for child in tree["children"] if child["name"] == "loadBlock")
        self.assertFalse(load_block["present"])
        self.assertIn("loadPackageAID", [child["name"] for child in load_block["children"]])
        instances = next(child for child in tree["children"] if child["name"] == "instanceList")
        phantom = instances["children"][-1]
        self.assertTrue(phantom["phantom"])
        self.assertEqual(phantom["path"], ["instanceList", 0])
        # sqnInit holds the 32 entries its SIZE allows: no phantom entry.
        aka = self.S.structure(self._aka(), "akaParameter")
        self.S.set_leaf(self._aka(), "akaParameter", ["sqnInit", 0], "000000000001")
        sqn = next(child for child in aka["children"] if child["name"] == "sqnInit")
        self.assertFalse(any(child.get("phantom") for child in sqn.get("children", [])) and sqn["present"])

    def test_an_emptied_field_is_an_empty_value_only_where_size_allows_one(self) -> None:
        # ETSI TS 102 221 v18.4 §11.1.1.4.8 (page 98): a shortEFID present and
        # empty says the file has no SFI; absent, the SFI is the file ID's.
        section = copy.deepcopy(self.saip._build_default_pe("genericFileManagement").decoded)
        command = ["fileManagementCMD", 0, 0]
        self.S.set_choice(section, "genericFileManagement", command, "createFCP")
        fcp = command + ["createFCP"]
        self.S.set_leaf(section, "genericFileManagement", fcp + ["shortEFID"], "")
        self.assertEqual(section["fileManagementCMD"][0][0][1]["shortEFID"], b"")
        self.S.clear(section, "genericFileManagement", fcp + ["shortEFID"])
        self.assertNotIn("shortEFID", section["fileManagementCMD"][0][0][1])
        # An OPTIONAL member without SIZE (0..n) goes when emptied.
        self.S.set_leaf(section, "genericFileManagement", fcp + ["efFileSize"], "0010")
        self.S.set_leaf(section, "genericFileManagement", fcp + ["efFileSize"], "")
        self.assertNotIn("efFileSize", section["fileManagementCMD"][0][0][1])
        app = copy.deepcopy(self.saip._build_default_pe("application").decoded)
        self.S.set_leaf(app, "application", ["instanceList", 0, "instanceAID"], "A000000087100201")
        with self.assertRaisesRegex(self.S.SaipStructureError, "mandatory"):
            self.S.set_leaf(app, "application", ["instanceList", 0, "classAID"], "")

    def test_keys_outside_the_schema_are_left_alone(self) -> None:
        section = self._aka()
        section["aka-header"]["pe-name"] = "akaParameter#3"
        self.S.add_member(section, "akaParameter", ["aka-header"], "mandated")
        self.assertEqual(section["aka-header"]["pe-name"], "akaParameter#3")


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class StructureActionsTests(unittest.TestCase):
    """``saip.pe_structure`` / ``saip.pe_structure_edit`` on a session."""

    def setUp(self) -> None:
        from pathlib import Path

        from yggdrasim_common.gui_server.actions.registry import get_registry

        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        profile = Path(__file__).resolve().parents[1] / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        self.sid = self.saip._dispatch_open_package(ctx=None, path=str(profile))["session_id"]
        self.addCleanup(lambda: self.sessions.get_manager().close(self.sid))
        self.edit = get_registry()._specs["saip.pe_structure_edit"].dispatcher
        self.show = get_registry()._specs["saip.pe_structure"].dispatcher

    def _add(self, pe_type: str) -> int:
        rows = self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"]
        return self.saip._dispatch_add_pe(
            ctx=None, session_id=self.sid, pe_type=pe_type, insert_at=len(rows) - 1,
        )["pe_index"]

    def _reencoded(self, index: int) -> dict:
        from pySim.esim.saip import ProfileElementSequence

        handle = self.sessions.get_manager().claim(self.sid)
        return ProfileElementSequence.from_der(handle["pes"].to_der()).pe_list[index].decoded

    def test_an_application_instance_is_built_member_by_member(self) -> None:
        index = self._add("application")
        tree = self.show(None, session_id=self.sid, pe_index=index)["tree"]
        self.assertEqual(
            [child["name"] for child in tree["children"]],
            ["app-Header", "loadBlock", "instanceList"],
        )
        self.edit(None, session_id=self.sid, pe_index=index, op="add", path=[], name="instanceList")
        base = ["instanceList", 0]
        for member, value in (
            ("applicationLoadPackageAID", "A0000000871002"),
            ("classAID", "A000000087100201"),
            ("instanceAID", "A000000087100201"),
            ("applicationPrivileges", "000000"),
        ):
            self.edit(None, session_id=self.sid, pe_index=index, op="set", path=base + [member], value=value)
        self.edit(None, session_id=self.sid, pe_index=index, op="add", path=base, name="systemSpecificParameters")
        result = self.edit(
            None, session_id=self.sid, pe_index=index, op="set",
            path=base + ["systemSpecificParameters", "volatileMemoryQuotaC7"], value="0400",
        )
        self.assertEqual(result["encode_error"], "")
        instance = self._reencoded(index)["instanceList"][0]
        self.assertEqual(instance["instanceAID"], bytes.fromhex("A000000087100201"))
        self.assertEqual(instance["systemSpecificParameters"]["volatileMemoryQuotaC7"], b"\x04\x00")

    def _sd_index(self) -> int:
        rows = self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"]
        return next(row["index"] for row in rows if row["type"] == "securityDomain")

    def _profile_der(self) -> bytes:
        return bytes(self.sessions.get_manager().claim(self.sid)["pes"].to_der())

    def test_an_edit_pysim_cannot_build_yet_is_held_as_a_draft(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        index = self._sd_index()
        path = ["instance", "applicationSpecificParametersC9"]
        profile_before = self._profile_der()
        undo_before = len((self.sessions.get_manager().claim(self.sid).get("history") or {}).get("undo") or [])
        # One byte: pySim reads C9 as a TLV and finds no length.
        held = self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="C9")
        self.assertIn("index out of range", held["draft"]["error"])
        self.assertEqual(self._profile_der(), profile_before)
        shown = self.show(None, session_id=self.sid, pe_index=index)
        self.assertIsNotNone(shown["draft"])
        instance = next(child for child in shown["tree"]["children"] if child["name"] == "instance")
        c9 = next(child for child in instance["children"] if child["name"] == path[1])
        self.assertEqual(c9["value"], "C9")
        # The next edit continues the draft and lands once pySim builds it,
        # as one undo step.
        landed = self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="820100")
        self.assertIsNone(landed["draft"])
        decoded = self._reencoded(index)
        self.assertEqual(decoded["instance"]["applicationSpecificParametersC9"], bytes.fromhex("820100"))
        handle = self.sessions.get_manager().claim(self.sid)
        self.assertEqual(len(handle["history"]["undo"]), undo_before + 1)
        get_registry()._specs["saip.undo"].dispatcher(None, session_id=self.sid)
        self.assertEqual(self._profile_der(), profile_before)

    def test_a_draft_is_discarded_or_dropped_when_the_element_changes(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        index = self._sd_index()
        path = ["instance", "applicationSpecificParametersC9"]
        self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="C9")
        discarded = self.edit(None, session_id=self.sid, pe_index=index, op="discard_draft")
        self.assertIsNone(discarded["draft"])
        self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="C9")
        # Another editor changes the element: the draft no longer fits it,
        # and the view says so once.
        get_registry()._specs["saip.set_pe_mandated"].dispatcher(
            None, session_id=self.sid, pe_index=index, mandated=False,
        )
        shown = self.show(None, session_id=self.sid, pe_index=index)
        self.assertIsNone(shown["draft"])
        self.assertTrue(shown["draft_dropped"])
        self.assertFalse(self.show(None, session_id=self.sid, pe_index=index)["draft_dropped"])

    def test_a_key_list_is_built_over_several_edits(self) -> None:
        # TCA SAIP v3.4.1 page 56: KeyObject. The added entry holds an empty
        # key type pySim cannot read, so the edits stay a draft until the
        # key carries its type and data.
        index = self._add("securityDomain")
        held = self.edit(None, session_id=self.sid, pe_index=index, op="add", path=[], name="keyList")
        self.assertIsNotNone(held["draft"])
        key = ["keyList", 0]
        for member, value in (
            ("keyUsageQualifier", "38"),
            ("keyIdentifier", "01"),
            ("keyVersionNumber", "30"),
        ):
            self.edit(None, session_id=self.sid, pe_index=index, op="set", path=key + [member], value=value)
        component = key + ["keyComponents", 0]
        self.edit(None, session_id=self.sid, pe_index=index, op="set", path=component + ["keyType"], value="88")
        landed = self.edit(
            None, session_id=self.sid, pe_index=index, op="set",
            path=component + ["keyData"], value="00112233445566778899AABBCCDDEEFF",
        )
        self.assertIsNone(landed["draft"])
        stored = self._reencoded(index)["keyList"][0]
        self.assertEqual(stored["keyIdentifier"], b"\x01")
        self.assertEqual(stored["keyComponents"][0]["keyData"], bytes.fromhex("00112233445566778899AABBCCDDEEFF"))

    def test_a_template_file_is_built_over_several_edits(self) -> None:
        # EF.ADN of DF.PHONEBOOK carries no sizes in its template, so it stays
        # a draft until its descriptor and size are set: '42' a shareable
        # linear fixed working EF, data coding byte '21', 34-byte records
        # (ETSI TS 102 221 v18.4 Table 11.5), ten of them.
        index = self._add("phonebook")
        held = self.edit(None, session_id=self.sid, pe_index=index, op="add", path=[], name="ef-adn")
        self.assertIsNotNone(held["draft"])
        entry = ["ef-adn", 0]
        fcp = entry + ["fileDescriptor"]
        self.edit(None, session_id=self.sid, pe_index=index, op="choice", path=entry, alternative="fileDescriptor")
        self.edit(None, session_id=self.sid, pe_index=index, op="add", path=fcp, name="fileDescriptor")
        self.edit(None, session_id=self.sid, pe_index=index, op="set", path=fcp + ["fileDescriptor"], value="42210022")
        self.edit(None, session_id=self.sid, pe_index=index, op="add", path=fcp, name="efFileSize")
        landed = self.edit(
            None, session_id=self.sid, pe_index=index, op="set", path=fcp + ["efFileSize"], value="0154",
        )
        self.assertIsNone(landed["draft"])
        adn = self._reencoded(index)["ef-adn"]
        descriptor = dict(adn)["fileDescriptor"]
        self.assertEqual(descriptor["efFileSize"], bytes.fromhex("0154"))

    def test_a_perso_record_is_whole_dgi_objects(self) -> None:
        # GP Card Spec v2.3.1 §11.1.12: a DGI, its length, then the value.
        index = self._sd_index()
        with self.assertRaisesRegex(ValueError, "sdPersoData record"):
            self.edit(None, session_id=self.sid, pe_index=index, op="set", path=["sdPersoData", 0], value="8010FF")
        landed = self.edit(
            None, session_id=self.sid, pe_index=index, op="set", path=["sdPersoData", 0], value="801003AABBCC",
        )
        self.assertIsNone(landed["draft"])

    def test_a_choice_switch_and_a_list_entry_reach_the_der(self) -> None:
        index = self._add("akaParameter")
        self.edit(
            None, session_id=self.sid, pe_index=index, op="choice",
            path=["algoConfiguration"], alternative="mappingParameter",
        )
        self.edit(
            None, session_id=self.sid, pe_index=index, op="set",
            path=["algoConfiguration", "mappingParameter", "mappingSource"], value="A0000000871002FF33FF0189",
        )
        self.edit(
            None, session_id=self.sid, pe_index=index, op="set",
            path=["sqnInit", 31], value="000000000040",
        )
        decoded = self._reencoded(index)
        self.assertEqual(decoded["algoConfiguration"][0], "mappingParameter")
        self.assertEqual(decoded["sqnInit"][31], bytes.fromhex("000000000040"))


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class StructureTemplatePlaceholderTests(unittest.TestCase):
    """A template placeholder is shown by the Structure view, never overwritten."""

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        text = "".join(_REFERENCE_HEX.read_text(encoding="utf-8").split()).upper()
        text = text.replace(_HEADER_ICCID_HEX, "[iccidICCID10]", 1).replace(_PUK_HEX, "[puk1BINARY8]", 1)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "profile.varder"
        source.write_text(text, encoding="utf-8-sig")
        self.sid = self.saip._dispatch_open_package(None, path=str(source))["session_id"]
        self.addCleanup(lambda: self.sessions.get_manager().close(self.sid))
        self.edit = get_registry()._specs["saip.pe_structure_edit"].dispatcher
        self.show = get_registry()._specs["saip.pe_structure"].dispatcher

    def _index(self, pe_type: str) -> int:
        rows = self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"]
        return next(row["index"] for row in rows if row["type"] == pe_type)

    @staticmethod
    def _child(tree: dict[str, Any], name: str) -> dict[str, Any]:
        return next(child for child in tree["children"] if child["name"] == name)

    def test_a_leaf_holding_a_placeholder_shows_its_literal_read_only(self) -> None:
        iccid = self._child(self.show(None, session_id=self.sid, pe_index=0)["tree"], "iccid")
        self.assertEqual(iccid["value"], "[iccidICCID10]")
        self.assertTrue(iccid["read_only"])
        self.assertTrue(iccid["template_placeholder"])

    def test_overwriting_a_placeholder_is_refused(self) -> None:
        before = self.show(None, session_id=self.sid, pe_index=0)["tree"]
        with self.assertRaisesRegex(ValueError, r"\[iccidICCID10\]"):
            self.edit(None, session_id=self.sid, pe_index=0, op="set", path=["iccid"], value="98" * 10)
        self.assertEqual(self.show(None, session_id=self.sid, pe_index=0)["tree"], before)

    def test_dropping_the_entry_that_holds_a_placeholder_is_refused(self) -> None:
        index = self._index("pukCodes")
        before = self.show(None, session_id=self.sid, pe_index=index)["tree"]
        codes = self._child(before, "pukCodes")
        holder = next(
            position for position, entry in enumerate(codes["children"])
            if self._child(entry, "pukValue")["value"] == "[puk1BINARY8]"
        )
        with self.assertRaisesRegex(ValueError, r"\[puk1BINARY8\]"):
            self.edit(
                None, session_id=self.sid, pe_index=index, op="remove_entry",
                path=["pukCodes"], index=holder,
            )
        self.assertEqual(self.show(None, session_id=self.sid, pe_index=index)["tree"], before)

    def test_a_placeholder_typed_into_a_field_binds_it(self) -> None:
        index = self._index("pukCodes")
        codes = self._child(self.show(None, session_id=self.sid, pe_index=index)["tree"], "pukCodes")
        free = next(
            position for position, entry in enumerate(codes["children"])
            if not entry.get("phantom") and self._child(entry, "pukValue")["value"] != "[puk1BINARY8]"
        )
        path = ["pukCodes", free, "pukValue"]
        # Either spelling is taken; the field shows the typed form.
        result = self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="[puk2BINARY8]")
        entry = self._child(result["tree"], "pukCodes")["children"][free]
        leaf = self._child(entry, "pukValue")
        self.assertEqual(leaf["value"], "{puk2:BINARY:8}")
        self.assertTrue(leaf["read_only"])
        # A field holding a placeholder is not bound over.
        with self.assertRaisesRegex(ValueError, "Variables panel"):
            self.edit(None, session_id=self.sid, pe_index=index, op="set", path=path, value="{puk3:BINARY:8}")

    def test_edits_elsewhere_keep_the_placeholders(self) -> None:
        result = self.edit(
            None, session_id=self.sid, pe_index=0, op="set", path=["minor-version"], value="1",
        )
        self.assertEqual(self._child(result["tree"], "iccid")["value"], "[iccidICCID10]")


if __name__ == "__main__":
    unittest.main()
