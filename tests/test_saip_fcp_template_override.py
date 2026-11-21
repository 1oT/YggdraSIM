# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""FCP overrides on template-inherited fields (``saip.update_file_field``).

A template-backed file inherits most of its FCP from the SAIP template; TCA
SAIP v3.4.1 §8.3.3 overwrites such a parameter by naming it in the Fcp of
the PE. The FCP tab marks those fields TPL and promises that Apply writes an
explicit override, but ``_apply_hex_mutation`` only replaced members the
package already carried, so the override on DF.PHONEBOOK's security
attributes raised ``LookupError: no CHOICE payload carrying
'securityAttributesReferenced'``. The helper now inserts the member, grows a
missing Fcp arm ahead of the fill entries, and the dispatcher checks the
member against pySim's compiled schema first, because asn1tools drops an
unknown key without a word.
"""

from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

from yggdrasim_common.gui_server.actions.saip import (
    _apply_hex_mutation,
    _summarise_file_choices,
)

_REFERENCE_PROFILE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")


def _pysim_available() -> bool:
    try:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        importlib.import_module("pySim.esim.saip")
    except Exception:  # noqa: BLE001 -- any import failure means "skip"
        return False
    return True


class InsertAbsentMemberTests(unittest.TestCase):
    """An absent top-level member lands in the arm that holds the FCP."""

    def test_inserts_into_existing_file_descriptor_arm(self) -> None:
        # The reference profile's DF.PHONEBOOK: pinStatusTemplateDO and
        # lcsi only, the access rule inherited from the template.
        payload = OrderedDict([("pinStatusTemplateDO", b"\x01\x0a"), ("lcsi", b"\x05")])
        choice_list = [("fileDescriptor", payload)]

        applied = _apply_hex_mutation(choice_list, "securityAttributesReferenced", b"\x0e")

        self.assertTrue(applied)
        self.assertIs(choice_list[0][1], payload)
        self.assertEqual(payload["securityAttributesReferenced"], b"\x0e")
        self.assertEqual(payload["pinStatusTemplateDO"], b"\x01\x0a")

    def test_inserts_file_id_override_on_template_file(self) -> None:
        choice_list = [("fileDescriptor", OrderedDict([("efFileSize", b"\x32")]))]

        applied = _apply_hex_mutation(choice_list, "fileID", b"\x4f\x60")

        self.assertTrue(applied)
        self.assertEqual(choice_list[0][1]["fileID"], b"\x4f\x60")

    def test_grows_fcp_arm_at_index_zero_for_fully_inherited_file(self) -> None:
        choice_list = [("fillFileOffset", 0), ("fillFileContent", b"\xff\xff")]

        applied = _apply_hex_mutation(choice_list, "shortEFID", b"\x08")

        self.assertTrue(applied)
        self.assertEqual(choice_list[0], ("fileDescriptor", OrderedDict([("shortEFID", b"\x08")])))
        self.assertEqual([name for name, _ in choice_list[1:]], ["fillFileOffset", "fillFileContent"])

    def test_grows_fcp_arm_for_empty_file_entry(self) -> None:
        choice_list: list = []

        applied = _apply_hex_mutation(choice_list, "securityAttributesReferenced", b"\x0e")

        self.assertTrue(applied)
        self.assertEqual(len(choice_list), 1)
        self.assertEqual(choice_list[0][0], "fileDescriptor")

    def test_refuses_do_not_create(self) -> None:
        choice_list = [("doNotCreate", None)]

        self.assertFalse(_apply_hex_mutation(choice_list, "fileID", b"\x4f\x60"))
        self.assertEqual(choice_list, [("doNotCreate", None)])

    def test_refuses_repeated_file_descriptor_arms(self) -> None:
        # Several EF.ICON files from one File entry (page 28): the target
        # of an insert is ambiguous, so nothing is written.
        choice_list = [
            ("fileDescriptor", OrderedDict([("efFileSize", b"\x10")])),
            ("fillFileContent", b"\x00" * 16),
            ("fileDescriptor", OrderedDict([("efFileSize", b"\x10")])),
        ]

        self.assertFalse(_apply_hex_mutation(choice_list, "shortEFID", b"\x08"))
        self.assertNotIn("shortEFID", choice_list[0][1])
        self.assertNotIn("shortEFID", choice_list[2][1])

    def test_inserts_into_the_only_create_fcp_of_a_gfm_transaction(self) -> None:
        create = OrderedDict([("fileID", b"\x6f\x40"), ("fileDescriptor", b"\x41\x21")])
        transaction = [("filePath", b"\x7f\x10"), ("createFCP", create)]

        applied = _apply_hex_mutation(transaction, "securityAttributesReferenced", b"\x02")

        self.assertTrue(applied)
        self.assertEqual(create["securityAttributesReferenced"], b"\x02")
        self.assertEqual(len(transaction), 2)

    def test_refuses_gfm_transaction_with_several_create_fcps(self) -> None:
        transaction = [
            ("filePath", b"\x7f\x10"),
            ("createFCP", OrderedDict([("fileID", b"\x6f\x40")])),
            ("createFCP", OrderedDict([("fileID", b"\x6f\x41")])),
        ]

        self.assertFalse(_apply_hex_mutation(transaction, "securityAttributesReferenced", b"\x02"))
        self.assertEqual(len(transaction), 3)

    def test_refuses_gfm_transaction_without_create_fcp(self) -> None:
        transaction = [("filePath", b"\x7f\x10")]

        self.assertFalse(_apply_hex_mutation(transaction, "fileID", b"\x6f\x40"))
        self.assertEqual(transaction, [("filePath", b"\x7f\x10")])


class SummaryPinStatusTests(unittest.TestCase):
    """The FCP row carries pinStatusTemplateDO for the PIN status row."""

    def test_summary_carries_pin_status_template(self) -> None:
        choice_list = [
            ("fileDescriptor", OrderedDict([
                ("fileDescriptor", b"\x78\x21"),
                ("pinStatusTemplateDO", b"\x01\x81\x0a"),
            ])),
        ]

        summary = _summarise_file_choices(choice_list)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["pin_status_template"], "01810A")
        self.assertEqual(summary["details"], "")


class SummaryLifeCycleStateTests(unittest.TestCase):
    """The FCP row carries ``Fcp.lcsi`` for the life-cycle state row."""

    def test_summary_carries_lcsi(self) -> None:
        # An EF created deactivated: TS 102 221 Table 11.7b '04' is
        # operational state - deactivated.
        choice_list = [("fileDescriptor", OrderedDict([("lcsi", b"\x04")]))]

        summary = _summarise_file_choices(choice_list)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["lcsi"], "04")

    def test_summary_leaves_lcsi_empty_when_the_member_is_absent(self) -> None:
        # TCA SAIP v3.4.1 §8.3.2: DEFAULT '05'H applies; the row reports the
        # package, not the default.
        choice_list = [("fileDescriptor", OrderedDict([("fileDescriptor", b"\x42\x21")]))]

        summary = _summarise_file_choices(choice_list)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["lcsi"], "")


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class SchemaGuardTests(unittest.TestCase):
    """Members are checked against the compiled SAIP schema before a write."""

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")

    def test_fcp_members_come_from_the_compiled_module(self) -> None:
        members = self.saip._saip_sequence_members("Fcp")
        # TCA SAIP v3.4.1 pages 26-27.
        for name in (
            "fileDescriptor", "fileID", "dfName", "lcsi", "securityAttributesReferenced",
            "efFileSize", "pinStatusTemplateDO", "shortEFID", "proprietaryEFInfo", "linkPath",
        ):
            self.assertIn(name, members)

    def test_every_editable_top_level_field_but_max_size_is_an_fcp_member(self) -> None:
        for sub_key in sorted(self.saip._EDITABLE_SUB_FIELDS):
            if sub_key == "maximumFileSize":
                continue
            self.saip._assert_fcp_member_editable(sub_key)

    def test_top_level_maximum_file_size_is_refused_with_the_proprietary_path(self) -> None:
        # maximumFileSize is a ProprietaryInfo leaf (page 26); asn1tools
        # would drop a top-level copy on encode.
        with self.assertRaises(ValueError) as caught:
            self.saip._assert_fcp_member_editable("maximumFileSize")
        self.assertIn("proprietaryEFInfo.maximumFileSize", str(caught.exception))

    def test_unknown_proprietary_leaf_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._assert_fcp_member_editable("proprietaryEFInfo.noSuchLeaf")


@unittest.skipUnless(
    _pysim_available() and _REFERENCE_PROFILE.exists(),
    "pySim or the reference profile missing -- skipping end-to-end test",
)
class TemplateOverrideEndToEndTests(unittest.TestCase):
    """Drive ``saip.update_file_field`` on the reference profile's DF.PHONEBOOK."""

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        bridge = SaipToolBridge(Path(".").resolve())
        source = bridge.resolve_input_path(str(_REFERENCE_PROFILE), must_exist=True)
        raw = bridge._prepare_input_for_tool(source).read_bytes()
        handle = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        handle.write(raw)
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        opened = self.saip._dispatch_open_package(self.ctx, path=handle.name)
        self.session_id = opened["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)
        self.addCleanup(lambda: self.sessions.get_manager().close(self.session_id))

    def _phonebook_section(self) -> str:
        sections = self.handle["decoded_document"].get("sections") or {}
        for key, value in sections.items():
            if isinstance(value, dict) and "df-phonebook" in value:
                return key
        self.fail("reference profile carries no df-phonebook")

    def test_security_attributes_override_lands_and_reencodes(self) -> None:
        section = self._phonebook_section()
        before = self.saip._dispatch_show_file(
            self.ctx, session_id=self.session_id, section_key=section, field_path="df-phonebook",
        )
        self.assertEqual(before["fcp"]["security_attrs_source"], "template")
        self.assertEqual(before["fcp"]["pin_status_template"], "010A")
        self.assertEqual(before["fcp"]["descriptor"], "7821")
        self.assertEqual(before["fcp"]["descriptor_source"], "template")

        response = self.saip._dispatch_update_file_field(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            field_path="df-phonebook",
            sub_key="securityAttributesReferenced",
            hex_value="0E",
        )

        self.assertEqual(response["row"]["security_attrs"], "0E")
        after = self.saip._dispatch_show_file(
            self.ctx, session_id=self.session_id, section_key=section, field_path="df-phonebook",
        )
        self.assertEqual(after["fcp"]["security_attrs"], "0E")
        self.assertEqual(after["fcp"]["security_attrs_source"], "")

        from pySim.esim.saip import ProfileElementSequence

        encoded = self.handle["pes"].to_der()
        decoded = ProfileElementSequence.from_der(encoded)
        phonebook_pe = next(pe for pe in decoded.pe_list if "df-phonebook" in pe.decoded)
        fcp = dict(phonebook_pe.decoded["df-phonebook"][0][1])
        self.assertEqual(fcp["securityAttributesReferenced"], b"\x0e")
        self.assertEqual(fcp["pinStatusTemplateDO"], b"\x01\x0a")

    def test_file_id_override_on_template_ef(self) -> None:
        section = self._phonebook_section()
        response = self.saip._dispatch_update_file_field(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            field_path="ef-adn",
            sub_key="fileID",
            hex_value="4F59",
        )
        self.assertEqual(response["row"]["file_id"], "4F59")

    def test_top_level_max_size_is_refused_before_touching_the_package(self) -> None:
        section = self._phonebook_section()
        with self.assertRaises(ValueError):
            self.saip._dispatch_update_file_field(
                self.ctx,
                session_id=self.session_id,
                section_key=section,
                field_path="ef-adn",
                sub_key="maximumFileSize",
                hex_value="0100",
            )
        self.assertEqual(len(self.handle["dirty_pes"]), 0)

    def test_life_cycle_state_override_lands_and_reencodes(self) -> None:
        # DF.PHONEBOOK carries lcsi '05' inline (TCA SAIP v3.4.1 §8.3.2:
        # DEFAULT '05'H, operational - activated). The FCP tab reads it from
        # ``fcp.lcsi`` and its Apply writes the member back the same way as
        # every other row; '04' is operational - deactivated (TS 102 221
        # Table 11.7b).
        section = self._phonebook_section()
        before = self.saip._dispatch_show_file(
            self.ctx, session_id=self.session_id, section_key=section, field_path="df-phonebook",
        )
        self.assertEqual(before["fcp"]["lcsi"], "05")

        response = self.saip._dispatch_update_file_field(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            field_path="df-phonebook",
            sub_key="lcsi",
            hex_value="04",
        )

        self.assertEqual(response["row"]["lcsi"], "04")
        after = self.saip._dispatch_show_file(
            self.ctx, session_id=self.session_id, section_key=section, field_path="df-phonebook",
        )
        self.assertEqual(after["fcp"]["lcsi"], "04")

        from pySim.esim.saip import ProfileElementSequence

        encoded = self.handle["pes"].to_der()
        decoded = ProfileElementSequence.from_der(encoded)
        phonebook_pe = next(pe for pe in decoded.pe_list if "df-phonebook" in pe.decoded)
        fcp = dict(phonebook_pe.decoded["df-phonebook"][0][1])
        self.assertEqual(fcp["lcsi"], b"\x04")
        self.assertEqual(fcp["pinStatusTemplateDO"], b"\x01\x0a")



@unittest.skipUnless(
    _pysim_available() and _REFERENCE_PROFILE.exists(),
    "pySim or the reference profile missing -- skipping end-to-end test",
)
class LinkPathEditTests(unittest.TestCase):
    """Link, relink and unlink a file through ``saip.update_file_field``.

    TCA SAIP v3.4.1 page 27 codes ``Fcp.linkPath`` like ``filePath`` (page
    45: 2-byte file identifiers from the MF, an ADF by its temporary file ID,
    SIZE (0..8)). Page 30 note 1 lets a template file become a link; page 46
    makes a generic file management createFCP that names one a Create EF
    Link, which carries neither efFileSize nor proprietaryEFInfo, while a
    plain Create EF needs efFileSize. A link has no body of its own.
    """

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        bridge = SaipToolBridge(Path(".").resolve())
        source = bridge.resolve_input_path(str(_REFERENCE_PROFILE), must_exist=True)
        raw = bridge._prepare_input_for_tool(source).read_bytes()
        handle = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        handle.write(raw)
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        opened = self.saip._dispatch_open_package(self.ctx, path=handle.name)
        self.session_id = opened["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)
        self.addCleanup(lambda: self.sessions.get_manager().close(self.session_id))
        adf_map = self.saip._build_adf_temp_fid_map(self.handle["decoded_document"])
        self.usim_fid = next(fid for fid, name in adf_map.items() if name == "ADF.USIM")

    def _update(self, section: str, path: str, sub_key: str, value: object) -> dict:
        return self.saip._dispatch_update_file_field(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            field_path=path,
            sub_key=sub_key,
            hex_value=value,
        )

    def _entry(self, section: str, path: str) -> list:
        pe = self.handle["pes"].pe_list[self.saip._resolve_pe_index(self.handle, section)]
        return pe.decoded[path]

    def _gfm_transaction(self, section: str) -> list:
        pe = self.handle["pes"].pe_list[self.saip._resolve_pe_index(self.handle, section)]
        return pe.decoded["fileManagementCMD"][0]

    def test_template_ef_becomes_a_link_and_reencodes(self) -> None:
        response = self._update("usim", "ef-keysPS", "linkPath", self.usim_fid + "6F08")

        self.assertEqual(response["row"]["link_path"], self.usim_fid + "6F08")
        self.assertEqual(response["link_change"]["action"], "linked")
        shown = self.saip._dispatch_show_file(
            self.ctx, session_id=self.session_id, section_key="usim", field_path="ef-keysPS",
        )
        self.assertTrue(shown["link_source"]["resolved"])
        self.assertEqual(shown["link_source"]["fid_chain"], "ADF.USIM/6F08")

        from pySim.esim.saip import ProfileElementSequence

        decoded = ProfileElementSequence.from_der(self.handle["pes"].to_der())
        pe = decoded.pe_list[self.saip._resolve_pe_index(self.handle, "usim")]
        fcp = dict(pe.decoded["ef-keysPS"][0][1])
        self.assertEqual(fcp["linkPath"], bytes.fromhex(self.usim_fid + "6F08"))

    def test_linking_drops_the_files_own_content(self) -> None:
        self.assertIn("fillFileContent", [name for name, _ in self._entry("usim", "ef-ust")])

        response = self._update("usim", "ef-ust", "linkPath", "7F206F38")

        self.assertEqual(response["content_reset"]["reason"], "linked")
        self.assertGreater(response["content_reset"]["dropped_bytes"], 0)
        names = [name for name, _ in self._entry("usim", "ef-ust")]
        self.assertEqual(names, ["fileDescriptor"])

    def test_relink_and_unlink_a_template_file(self) -> None:
        self._update("usim", "ef-keysPS", "linkPath", self.usim_fid + "6F08")

        relinked = self._update("usim", "ef-keysPS", "linkPath", self.usim_fid + "6F07")
        self.assertEqual(relinked["link_change"]["action"], "relinked")

        unlinked = self._update("usim", "ef-keysPS", "linkPath", "")
        self.assertEqual(unlinked["link_change"]["action"], "unlinked")
        self.assertEqual(unlinked["row"]["link_path"], "")
        self.assertNotIn("linkPath", self._entry("usim", "ef-keysPS")[0][1])

    def test_removing_a_link_that_is_not_there_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._update("usim", "ef-keysPS", "linkPath", "")
        self.assertEqual(len(self.handle["dirty_pes"]), 0)

    def test_link_path_coding_is_checked(self) -> None:
        for value in ("3F007F206F07AABBCC", "3F007F", "7F2"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self._update("usim", "ef-keysPS", "linkPath", value)
        self.assertEqual(len(self.handle["dirty_pes"]), 0)

    def test_other_fields_still_need_a_value(self) -> None:
        for value in ("", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self._update("usim", "ef-keysPS", "fileID", value)

    def test_gfm_ef_becomes_a_create_ef_link(self) -> None:
        transaction = self._gfm_transaction("genericFileManagement")
        self.assertEqual(transaction[3][0], "createFCP")
        self.assertIn("efFileSize", transaction[3][1])
        length_before = len(transaction)

        response = self._update(
            "genericFileManagement", "fileManagementCMD[0][3]", "linkPath", "7F106F3B",
        )

        self.assertEqual(response["link_change"]["dropped_members"], ["efFileSize"])
        self.assertEqual(response["content_reset"]["reason"], "linked")
        self.assertTrue(response["gfm_reindexed"])
        transaction = self._gfm_transaction("genericFileManagement")
        create = transaction[3][1]
        self.assertNotIn("efFileSize", create)
        self.assertEqual(create["linkPath"], bytes.fromhex("7F106F3B"))
        self.assertEqual(transaction[4][0], "createFCP")
        self.assertLess(len(transaction), length_before)

    def test_gfm_link_removal_takes_the_source_size(self) -> None:
        create = self._gfm_transaction("genericFileManagement_2")[68][1]
        self.assertIn("linkPath", create)
        self.assertNotIn("efFileSize", create)

        response = self._update(
            "genericFileManagement_2", "fileManagementCMD[0][68]", "linkPath", "",
        )

        copied = response["link_change"]["copied_members"]
        self.assertEqual(sorted(copied), ["efFileSize", "fileDescriptor"])
        create = self._gfm_transaction("genericFileManagement_2")[68][1]
        self.assertNotIn("linkPath", create)
        self.assertEqual(create["efFileSize"], bytes.fromhex(copied["efFileSize"]))


if __name__ == "__main__":
    unittest.main()
