# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A profile element added from scratch is configurable without JSON.

``saip.add_pe`` inserts a blank element; every type the Insert dialog offers
must encode as inserted and reach a complete configuration through the
typed actions the PE editor calls. TCA SAIP v3.4.1 §8 names the members each
element needs.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


def _pysim_available() -> bool:
    try:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        importlib.import_module("pySim.esim.saip")
    except Exception:  # noqa: BLE001 -- any import failure means "skip"
        return False
    return True


@unittest.skipUnless(
    _pysim_available() and _REFERENCE_PROFILE.is_file(),
    "pySim or the reference profile missing -- skipping end-to-end test",
)
class AddPeFromScratchTestCase(unittest.TestCase):
    """A session on the reference profile, one blank PE inserted per test."""

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        self.sid = self.saip._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]
        self.addCleanup(lambda: self.sessions.get_manager().close(self.sid))

    def _handle(self) -> dict:
        return self.sessions.get_manager().claim(self.sid)

    def _add(self, pe_type: str) -> dict:
        rows = self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"]
        return self.saip._dispatch_add_pe(
            ctx=None, session_id=self.sid, pe_type=pe_type, insert_at=len(rows) - 1,
        )

    def _pe(self, index: int):
        return self._handle()["pes"].pe_list[index]

    def _reencoded(self, index: int):
        from pySim.esim.saip import ProfileElementSequence

        decoded = ProfileElementSequence.from_der(self._handle()["pes"].to_der())
        return decoded.pe_list[index]


class BlankElementsEncodeTests(AddPeFromScratchTestCase):
    def _addable(self) -> list[str]:
        listed = self.saip._dispatch_list_pe_types(ctx=None)["rows"]
        return [row["pe_type"] for row in listed if row["addable"]]

    def test_every_addable_blank_encodes(self) -> None:
        addable = self._addable()
        self.assertIn("application", addable)
        for pe_type in addable:
            with self.subTest(pe_type=pe_type):
                blank = self.saip._build_default_pe(pe_type)
                # saip.add_pe numbers the header once the PE joins the
                # sequence (TCA SAIP v3.4.1 page 15: identification is
                # mandatory and unique).
                blank.decoded[blank.header_name].setdefault("identification", 1)
                self.assertGreater(len(blank.to_der()), 0)

    def test_every_non_filesystem_blank_inserts_without_a_warning(self) -> None:
        # A file-system PE joins a sequence only once and after its parent
        # (the reference profile already holds the MF, USIM, ...), so the
        # insert covers the elements a profile may carry several of.
        for pe_type in self._addable():
            if "templateID" in self.saip._build_default_pe(pe_type).decoded:
                continue
            with self.subTest(pe_type=pe_type):
                response = self._add(pe_type)
                self.assertEqual(response["warnings"], [])
                self.assertGreater(len(self._pe(response["pe_index"]).to_der()), 0)
                self.saip._dispatch_delete_pe(
                    ctx=None, session_id=self.sid, pe_index=response["pe_index"],
                )

    def test_csim_is_listed_as_unavailable_and_refused(self) -> None:
        listed = {row["pe_type"]: row for row in self.saip._dispatch_list_pe_types(ctx=None)["rows"]}
        for pe_type in ("csim", "opt-csim"):
            with self.subTest(pe_type=pe_type):
                self.assertFalse(listed[pe_type]["addable"])
                self.assertIn("CSIM", listed[pe_type]["unavailable_reason"])
                with self.assertRaises(ValueError):
                    self._add(pe_type)

    def test_blank_rfm_cdma_and_nonstandard_carry_their_mandatory_members(self) -> None:
        # TCA SAIP v3.4.1 page 63 (instanceAID), page 50 (authenticationKey),
        # page 64 (issuerID, content).
        expected = {
            "rfm": ("instanceAID",),
            "cdmaParameter": ("authenticationKey",),
            "nonStandard": ("issuerID", "content"),
        }
        for pe_type, members in expected.items():
            with self.subTest(pe_type=pe_type):
                index = self._add(pe_type)["pe_index"]
                decoded = self._reencoded(index).decoded
                for member in members:
                    self.assertIn(member, decoded)


class InsertNeedsABuildableProfileTests(AddPeFromScratchTestCase):
    """An insert lands only when pySim can build the profile with it.

    Through the registered action: the history wrapper is what restores the
    session after a refused insert.
    """

    def _action(self, action_id: str):
        from yggdrasim_common.gui_server.actions.registry import get_registry

        return get_registry()._specs[action_id].dispatcher

    def _count(self) -> int:
        return len(self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"])

    def _insert(self, pe_type: str, **extra: str) -> dict:
        return self._action("saip.add_pe")(
            None, session_id=self.sid, pe_type=pe_type, insert_at=self._count() - 1, **extra,
        )

    def _session_still_edits(self) -> None:
        # A document pySim cannot rebuild refuses even this unrelated edit.
        rows = self.saip._dispatch_list_pes(ctx=None, session_id=self.sid)["rows"]
        index = next(row["index"] for row in rows if row["type"] == "akaParameter")
        self._action("saip.pe_structure_edit")(
            None, session_id=self.sid, pe_index=index, op="set",
            path=["algoConfiguration", "algoParameter", "algorithmOptions"], value="02",
        )

    def test_an_eap_needs_the_file_id_of_its_df(self) -> None:
        before = self._count()
        with self.assertRaisesRegex(ValueError, "TS 102 310"):
            self._insert("eap")
        self.assertEqual(self._count(), before)

    def test_an_eap_with_its_df_file_id_inserts_and_encodes(self) -> None:
        response = self._insert("eap", df_fid="5F01")
        self.assertEqual(response["warnings"], [])
        df_eap = self._reencoded(response["pe_index"]).decoded["df-eap"]
        self.assertEqual(df_eap[0][0], "fileDescriptor")
        self.assertEqual(df_eap[0][1]["fileID"], bytes.fromhex("5F01"))
        self._session_still_edits()

    def test_an_insert_pysim_cannot_build_is_refused_and_undone(self) -> None:
        # The reference profile holds its MF already.
        before = self._count()
        with self.assertRaisesRegex(ValueError, "not inserted"):
            self._insert("mf")
        self.assertEqual(self._count(), before)
        self._session_still_edits()


class QuickAddEapTests(AddPeFromScratchTestCase):
    """The TUI quick-add path takes the DF.EAP file ID the same way."""

    def test_an_eap_needs_its_df_file_id_on_the_quick_add_path_too(self) -> None:
        import copy

        from Tools.ProfilePackage.saip_json_codec import build_profile_sequence_from_document
        from Tools.ProfilePackage.saip_pe_quick_add import insert_blank_pe_for_menu_id

        document = self._handle()["decoded_document"]
        with self.assertRaisesRegex(ValueError, "TS 102 310"):
            insert_blank_pe_for_menu_id(copy.deepcopy(document), _REPO_ROOT, menu_id="eap")
        inserted = insert_blank_pe_for_menu_id(
            copy.deepcopy(document), _REPO_ROOT, menu_id="eap", df_fid="5F01",
        )
        sequence = build_profile_sequence_from_document(inserted, workspace_root=_REPO_ROOT)
        self.assertIn("eap", [pe.type for pe in sequence.pe_list])


_PACKAGE_AID = "A0000000871002"
_APPLET_AID = "A000000087100201"


def _component(tag: int, payload: bytes) -> bytes:
    """One CAP component: u1 tag, u2 size, then the payload (JCVM 3.1 §6.1)."""
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


def _header_component() -> bytes:
    # JCVM 3.1 §6.4: magic DECAFFED, CAP version, flags, package version + AID.
    aid = bytes.fromhex(_PACKAGE_AID)
    return _component(1, b"\xDE\xCA\xFF\xED" + bytes([0x02, 0x02, 0x04, 0x00, 0x01, len(aid)]) + aid)


def _applet_component() -> bytes:
    # JCVM 3.1 §6.6 applet_component_compact: count, AID, install method offset.
    aid = bytes.fromhex(_APPLET_AID)
    return _component(3, bytes([1, len(aid)]) + aid + b"\x00\x10")


def _ijc() -> bytes:
    return _header_component() + _applet_component()


def _cap(path: Path) -> bytes:
    """A CAP archive with the components pySim's ``CapFile`` requires; returns
    the load file pySim concatenates from it."""
    import zipfile

    parts = {
        "Header": _header_component(),
        "Directory": _component(2, b"\x00" * 4),
        "Import": _component(4, b"\x00"),
        "Applet": _applet_component(),
        "Class": _component(6, b"\x00\x00"),
        "Method": _component(7, b"\x00"),
        "StaticField": _component(8, b"\x00" * 10),
        "ConstantPool": _component(5, b"\x00\x00"),
        "RefLocation": _component(9, b"\x00" * 4),
        "Descriptor": _component(11, b"\x00\x00"),
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, blob in parts.items():
            archive.writestr(f"pkg/javacard/{name}.cap", blob)
    order = (
        "Header", "Directory", "Import", "Applet", "Class", "Method",
        "StaticField", "ConstantPool", "RefLocation", "Descriptor",
    )
    return b"".join(parts[name] for name in order)


class ApplicationFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.7 (pages 59-61): a load package and instances."""

    def setUp(self) -> None:
        super().setUp()
        import tempfile

        self.tmp = Path(tempfile.mkdtemp(prefix="ygg_app_pe_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.index = self._add("application")["pe_index"]

    def _get(self) -> dict:
        return self.saip._dispatch_get_application(ctx=None, session_id=self.sid, pe_index=self.index)

    def test_a_fresh_application_has_neither_load_block_nor_instances(self) -> None:
        summary = self._get()
        self.assertIsNone(summary["load_block"])
        self.assertEqual(summary["instances"], [])
        self.assertIsNone(summary["load_block_inspection"])

    def test_load_block_from_an_ijc_file_takes_its_package_aid(self) -> None:
        path = self.tmp / "applet.ijc"
        path.write_bytes(_ijc())

        self.saip._dispatch_set_application_load_block(
            ctx=None, session_id=self.sid, pe_index=self.index, load_block_path=str(path),
        )

        summary = self._get()
        self.assertEqual(summary["load_block"]["load_package_aid_hex"], _PACKAGE_AID)
        self.assertEqual(summary["load_block"]["load_block_object_size"], len(_ijc()))
        self.assertEqual(summary["load_block_inspection"]["applet_aids"], [_APPLET_AID])
        block = self._reencoded(self.index).decoded["loadBlock"]
        self.assertEqual(block["loadBlockObject"], _ijc())

    def test_load_block_from_a_cap_archive_is_its_load_file(self) -> None:
        path = self.tmp / "applet.cap"
        load_file = _cap(path)

        self.saip._dispatch_set_application_load_block(
            ctx=None, session_id=self.sid, pe_index=self.index, load_block_path=str(path),
        )

        block = self._reencoded(self.index).decoded["loadBlock"]
        self.assertEqual(block["loadBlockObject"], load_file)
        self.assertEqual(block["loadPackageAID"], bytes.fromhex(_PACKAGE_AID))

    def test_an_instance_is_added_and_removed(self) -> None:
        self.saip._dispatch_add_application_instance(
            ctx=None, session_id=self.sid, pe_index=self.index,
            load_package_aid_hex=_PACKAGE_AID, class_aid_hex=_APPLET_AID,
            instance_aid_hex=_APPLET_AID, privileges_hex="00",
            application_specific_parameters_hex="",
        )
        self.assertEqual([row["instance_aid_hex"] for row in self._get()["instances"]], [_APPLET_AID])
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["instanceList"][0]["classAID"], bytes.fromhex(_APPLET_AID))

        self.saip._dispatch_remove_application_instance(
            ctx=None, session_id=self.sid, pe_index=self.index, instance_aid_hex=_APPLET_AID,
        )
        self.assertEqual(self._get()["instances"], [])
        self.assertNotIn("instanceList", self._reencoded(self.index).decoded)

    def _loaded_with_instance(self) -> None:
        path = self.tmp / "applet.ijc"
        path.write_bytes(_ijc())
        self.saip._dispatch_set_application_load_block(
            ctx=None, session_id=self.sid, pe_index=self.index, load_block_path=str(path),
        )
        self.saip._dispatch_add_application_instance(
            ctx=None, session_id=self.sid, pe_index=self.index,
            load_package_aid_hex=_PACKAGE_AID, class_aid_hex=_APPLET_AID,
            instance_aid_hex=_APPLET_AID, privileges_hex="00",
            application_specific_parameters_hex="",
        )

    def _section_key(self) -> str:
        return self.saip._sections_by_pe_index(self._handle()["decoded_document"])[self.index]

    def test_an_instance_is_edited_in_place(self) -> None:
        self._loaded_with_instance()
        renamed = _APPLET_AID + "01"
        result = self.saip._dispatch_update_application_instance(
            ctx=None, session_id=self.sid, pe_index=self.index,
            instance_aid_hex=_APPLET_AID, load_package_aid_hex=_PACKAGE_AID,
            class_aid_hex=_APPLET_AID, new_instance_aid_hex=renamed,
            privileges_hex="800000", lifecycle_state=0x07,
            application_specific_parameters_hex="", extradite_sd_aid_hex="",
        )
        self.assertNotIn("warnings", result)
        entry = self._reencoded(self.index).decoded["instanceList"][0]
        self.assertEqual(entry["instanceAID"], bytes.fromhex(renamed))
        self.assertEqual(entry["applicationPrivileges"], bytes.fromhex("800000"))

    def test_an_instance_of_another_package_is_refused(self) -> None:
        self._loaded_with_instance()
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_application_instance(
                ctx=None, session_id=self.sid, pe_index=self.index,
                load_package_aid_hex="A0000000871003", class_aid_hex=_APPLET_AID,
                instance_aid_hex=_APPLET_AID + "02", privileges_hex="00",
                application_specific_parameters_hex="",
            )

    def test_the_parameter_editor_writes_one_instance(self) -> None:
        self._loaded_with_instance()
        result = self.saip._dispatch_update_sd_parameters(
            ctx=None, session_id=self.sid, section_key=self._section_key(),
            parameter_state={"process_data": ["0A0B"]}, instance_index=0,
        )
        self.assertEqual(result["instance_index"], 0)
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["instanceList"][0]["processData"], [bytes.fromhex("0A0B")])
        self.assertNotIn("instance", self._handle()["decoded_document"]["sections"][self._section_key()])
        with self.assertRaises(LookupError):
            self.saip._dispatch_update_sd_parameters(
                ctx=None, session_id=self.sid, section_key=self._section_key(),
                parameter_state={"process_data": []}, instance_index=1,
            )

    def test_show_pe_carries_one_parameter_summary_per_instance(self) -> None:
        self._loaded_with_instance()
        decoded = self.saip._dispatch_show_pe(
            ctx=None, session_id=self.sid, pe_index=self.index,
        )["decoded"]
        self.assertEqual(len(decoded["_instance_parameter_summaries"]), 1)

    def test_a_structure_edit_keeps_the_instances_on_the_package(self) -> None:
        self._loaded_with_instance()
        added = self.saip._dispatch_pe_structure_edit(
            ctx=None, session_id=self.sid, pe_index=self.index,
            op="add_entry", path=["instanceList"],
        )
        self.assertIn(_PACKAGE_AID, added["summary"])
        section = self._handle()["decoded_document"]["sections"][self._section_key()]
        held = self._handle().get("structure_drafts", {}).get(self._section_key())
        entries = (held["section"] if held else section)["instanceList"]
        self.assertEqual(entries[1]["applicationLoadPackageAID"], bytes.fromhex(_PACKAGE_AID))
        with self.assertRaises(ValueError):
            self.saip._dispatch_pe_structure_edit(
                ctx=None, session_id=self.sid, pe_index=self.index,
                op="set", path=["instanceList", 0, "applicationLoadPackageAID"],
                value="A0000000871003",
            )


class SecurityDomainFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.6 (pages 55-56): keys and the life cycle state."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("securityDomain")["pe_index"]

    def _get(self) -> dict:
        return self.saip._dispatch_get_security_domain(ctx=None, session_id=self.sid, pe_index=self.index)

    def test_a_blank_sd_omits_the_empty_key_list(self) -> None:
        # keyList is SEQUENCE (SIZE (1..MAX)) OF KeyObject OPTIONAL.
        self.assertNotIn("keyList", self._reencoded(self.index).decoded)
        summary = self._get()
        self.assertEqual(summary["keys"], [])
        self.assertFalse(summary["lifecycle_state_set"])
        # GP Card Spec v2.3.1 Table 11-16 (page 154).
        self.assertIn({"value": 0x88, "label": "AES (16, 24 or 32-byte keys)"}, summary["key_types"])

    def test_a_key_is_added_replaced_and_removed(self) -> None:
        component = [{"keyType": "0x88", "keyData": "00112233445566778899AABBCCDDEEFF", "macLength": 8}]
        self.saip._dispatch_add_security_domain_key(
            ctx=None, session_id=self.sid, pe_index=self.index, key_version=0x30,
            key_identifier=1, usage_qualifier_hex="38", key_components=component,
        )
        keys = self._reencoded(self.index).decoded["keyList"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["keyVersionNumber"], b"\x30")

        component[0]["keyData"] = "FFEEDDCCBBAA99887766554433221100"
        self.saip._dispatch_replace_security_domain_key(
            ctx=None, session_id=self.sid, pe_index=self.index, key_version=0x30,
            key_identifier=1, usage_qualifier_hex="34", key_components=component,
        )
        replaced = self._reencoded(self.index).decoded["keyList"][0]
        self.assertEqual(replaced["keyUsageQualifier"], b"\x34")

        self.saip._dispatch_remove_security_domain_key(
            ctx=None, session_id=self.sid, pe_index=self.index, key_version=0x30, key_identifier=1,
        )
        self.assertNotIn("keyList", self._reencoded(self.index).decoded)

    def test_the_life_cycle_is_set_to_personalized(self) -> None:
        # GP Card Specification v2.3.1 Table 11-5: '0F' PERSONALIZED.
        self.saip._dispatch_set_security_domain_instance_field(
            ctx=None, session_id=self.sid, pe_index=self.index, field="lifecycle_state", value="0x0F",
        )
        self.assertTrue(self._get()["lifecycle_state_set"])
        self.assertEqual(self._reencoded(self.index).decoded["instance"]["lifeCycleState"], b"\x0f")


class RfmFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.8 (pages 62-64): the RFM instance and its domains."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("rfm")["pe_index"]

    def _set(self, field: str, value: str) -> None:
        self.saip._dispatch_set_rfm_field(
            ctx=None, session_id=self.sid, pe_index=self.index, field=field, value=value,
        )

    def test_the_placeholder_aids_are_replaced_and_the_sd_cleared(self) -> None:
        self._set("instance_aid", "A000000151000010")
        self._set("security_domain_aid", "")
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["instanceAID"], bytes.fromhex("A000000151000010"))
        self.assertNotIn("securityDomainAID", decoded)

    def test_the_security_level_and_access_domains_are_set(self) -> None:
        self._set("minimum_security_level", "0x16")
        self._set("uicc_access_domain", "00")
        self._set("uicc_admin_access_domain", "00")
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["minimumSecurityLevel"], b"\x16")
        self.assertEqual(decoded["uiccAccessDomain"], b"\x00")
        self.assertEqual(decoded["uiccAdminAccessDomain"], b"\x00")


class CdmaFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.4.3 (page 50): the A-key and optional secrets."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("cdmaParameter")["pe_index"]

    def _set(self, field: str, hex_value: str) -> None:
        self.saip._dispatch_set_cdma_field(
            ctx=None, session_id=self.sid, pe_index=self.index, field=field, hex_value=hex_value,
        )

    def test_the_a_key_and_ssd_are_set_and_the_ssd_cleared(self) -> None:
        self._set("authenticationKey", "0102030405060708")
        self._set("ssd", "00" * 16)
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["authenticationKey"], bytes.fromhex("0102030405060708"))
        self.assertEqual(decoded["ssd"], bytes(16))
        self._set("ssd", "")
        self.assertNotIn("ssd", self._reencoded(self.index).decoded)

    def test_the_mandatory_a_key_is_not_cleared(self) -> None:
        with self.assertRaises(ValueError):
            self._set("authenticationKey", "")


class NonStandardFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.9 (page 64): issuerID and content."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("nonStandard")["pe_index"]

    def _set(self, field: str, value: str) -> dict:
        return self.saip._dispatch_set_nonstandard_field(
            ctx=None, session_id=self.sid, pe_index=self.index, field=field, value=value,
        )

    def test_issuer_and_content_are_set(self) -> None:
        response = self._set("issuer_id", "2.999.1")
        self.assertEqual(response["issuer_id"], "2.999.1")
        self._set("content", "A1B2C3")
        decoded = self._reencoded(self.index).decoded
        self.assertEqual(decoded["issuerID"], "2.999.1")
        self.assertEqual(decoded["content"], bytes.fromhex("A1B2C3"))

    def test_a_malformed_identifier_is_refused(self) -> None:
        for value in ("", "3.1", "1.40.5", "1..2", "abc"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self._set("issuer_id", value)


class PinContextFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.5.1 (page 52): pinconfig or a shared filePath."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("pinCodes")["pe_index"]

    def _state(self) -> dict:
        return self.saip._dispatch_get_pin_shared_context(ctx=None, session_id=self.sid, pe_index=self.index)

    def test_the_pins_are_shared_and_then_defined_here_again(self) -> None:
        self.saip._dispatch_set_pin_shared_context(
            ctx=None, session_id=self.sid, pe_index=self.index, file_path_hex="7FF0",
        )
        self.assertEqual(self._state()["file_path_hex"], "7FF0")
        self.assertEqual(self._reencoded(self.index).decoded["pinCodes"], ("filePath", bytes.fromhex("7FF0")))

        self.saip._dispatch_clear_pin_shared_context(ctx=None, session_id=self.sid, pe_index=self.index)
        self.assertFalse(self._state()["shared"])


class AkaFromScratchTests(AddPeFromScratchTestCase):
    """TCA SAIP v3.4.1 §8.4.2 (pages 47-49): algoParameter or mappingParameter."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self._add("akaParameter")["pe_index"]

    def _choice(self) -> dict:
        return self.saip._dispatch_aka_get_choice(ctx=None, session_id=self.sid, pe_index=self.index)

    def test_a_fresh_element_reads_as_milenage(self) -> None:
        self.assertEqual(self._choice()["choice"], "algoParameter")
        self.assertEqual(self._choice()["algorithm_id"], 1)

    def test_milenage_with_its_constants_and_an_sqn_seed(self) -> None:
        self.saip._dispatch_aka_configure(
            ctx=None, session_id=self.sid, pe_index=self.index, algorithm="milenage",
            key_hex="00112233445566778899AABBCCDDEEFF", opc_hex="FF" * 16,
            rotation_constants_hex="4000204060", sqn_init_hex="000000000020",
        )
        decoded = self._reencoded(self.index).decoded
        name, payload = decoded["algoConfiguration"]
        self.assertEqual(name, "algoParameter")
        self.assertEqual(payload["key"], bytes.fromhex("00112233445566778899AABBCCDDEEFF"))
        self.assertEqual(payload["rotationConstants"], bytes.fromhex("4000204060"))
        self.assertEqual(decoded["sqnInit"], [bytes.fromhex("000000000020")] * 32)

    def test_tuak_carries_constants_the_euicc_ignores(self) -> None:
        # Page 47: rotationConstants "only apply for Milenage; ignored in case
        # of TUAK" -- ignored, not forbidden, so they are written as given.
        self.saip._dispatch_aka_configure(
            ctx=None, session_id=self.sid, pe_index=self.index, algorithm="tuak",
            key_hex="00" * 16, opc_hex="00" * 32, rotation_constants_hex="4000204060",
        )
        name, payload = self._reencoded(self.index).decoded["algoConfiguration"]
        self.assertEqual(payload["algorithmID"], 2)
        self.assertEqual(payload["rotationConstants"], bytes.fromhex("4000204060"))

    def test_an_oversized_sqn_seed_is_refused(self) -> None:
        # Page 48: the maximum for any sqnInit value is '07FFFFFFFFFF'H.
        with self.assertRaises(ValueError):
            self.saip._dispatch_aka_configure(
                ctx=None, session_id=self.sid, pe_index=self.index, algorithm="milenage",
                key_hex="00" * 16, opc_hex="00" * 16, sqn_init_hex="080000000000",
            )

    def test_a_mapping_is_set_and_the_own_algorithm_comes_back(self) -> None:
        self.saip._dispatch_aka_set_mapping_parameter(
            ctx=None, session_id=self.sid, pe_index=self.index,
            mapping_source_aid="A0000000871002FF33FF018900000100", mapping_options_hex="06",
        )
        self.assertEqual(self._choice()["mapping_options_mode"], "share-sqn-parameters-and-array")
        name, payload = self._reencoded(self.index).decoded["algoConfiguration"]
        self.assertEqual(name, "mappingParameter")
        self.assertEqual(payload["mappingOptions"], b"\x06")

        self.saip._dispatch_aka_set_algo_parameter(
            ctx=None, session_id=self.sid, pe_index=self.index, restore_stash=True,
        )
        name, payload = self._reencoded(self.index).decoded["algoConfiguration"]
        self.assertEqual(name, "algoParameter")
        self.assertEqual(payload["algorithmID"], 1)


if __name__ == "__main__":
    unittest.main()
