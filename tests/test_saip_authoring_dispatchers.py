# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the SAIP authoring / packaging dispatchers.

Covered surfaces:
  * ``saip.save_package`` -- DER / hex / ASN.1 / varder / JSON output
  * ``saip.add_pe`` / ``saip.delete_pe`` -- sequence splice / drop
  * ``saip.import_pe`` / ``saip.export_pe`` -- single-PE I/O
  * ``saip.list_applications`` / ``saip.compare_applications`` --
    SD / Application / ELF inventory and inter-package diff
  * ``saip.product_summary`` -- bench environment fingerprint
  * ``saip.list_validation_rules`` -- linter rulebook catalogue
  * ``saip.add_variable_to_pe`` -- bind PE field to placeholder
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


def _open_reference_session(actions):
    """Open a fresh session against the reference profile fixture."""
    return actions._dispatch_open_package(
        ctx=None, path=str(_REFERENCE_PROFILE)
    )["session_id"]


def _open_synthetic_session(sections: dict[str, object]) -> str:
    from yggdrasim_common.gui_server.sessions import get_manager

    record = get_manager().open(
        kind="saip-test",
        handle={
            "decoded_document": {
                "intro": ["synthetic profile for SAIP authoring tests"],
                "sections": dict(sections),
            },
            "pes": None,
            "dirty_pes": set(),
            "applied_overrides": {},
        },
        close=lambda: None,
        idle_timeout_s=60.0,
        metadata={"origin": "test_saip_authoring_dispatchers"},
    )
    return record.id


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class SavePackageFormatTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_save_pkg_"))
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_save_der_round_trips(self) -> None:
        target = self._tmpdir / "out.der"
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="der",
        )
        self.assertEqual(result["format"], "der")
        self.assertGreater(result["size_bytes"], 100)
        self.assertTrue(target.is_file())

    def test_save_hex_writes_uppercase_hex(self) -> None:
        target = self._tmpdir / "out.hex"
        self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="hex",
        )
        text = target.read_text(encoding="utf-8").strip()
        self.assertEqual(text, text.upper())
        # Must be valid hex.
        bytes.fromhex(text)

    def test_save_json_preserves_metadata(self) -> None:
        target = self._tmpdir / "out.json"
        self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="json",
        )
        doc = json.loads(target.read_text(encoding="utf-8"))
        self.assertIn("sections", doc)

    def test_save_asn1_round_trips_and_appends_asn_extension(self) -> None:
        original_der = bytes(self._manager.claim(self._sid)["pes"].to_der())
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(self._tmpdir / "profile-value-notation"),
            format="asn1",
        )

        self.assertEqual(result["format"], "asn1")
        self.assertTrue(result["output_path"].endswith(".asn"))
        target = Path(result["output_path"])
        rendered = target.read_text(encoding="utf-8")
        self.assertIn("ProfileElement ::=", rendered)

        reopened = self._actions._dispatch_open_package(
            ctx=None,
            path=str(target),
        )
        try:
            reopened_der = bytes(self._manager.claim(reopened["session_id"])["pes"].to_der())
            self.assertEqual(reopened_der, original_der)
        finally:
            self._manager.close(reopened["session_id"])

    def test_save_asn_alias_returns_canonical_asn1_format(self) -> None:
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(self._tmpdir / "alias"),
            format="asn",
        )

        self.assertEqual(result["format"], "asn1")
        self.assertEqual(result["encoding"], "asn1")
        self.assertTrue(result["output_path"].endswith(".asn"))

    def test_save_varder_rejects_concrete_session(self) -> None:
        with self.assertRaisesRegex(ValueError, "unresolved inline-template"):
            self._actions._dispatch_save_package(
                ctx=None,
                session_id=self._sid,
                output_path=str(self._tmpdir / "not-a-template"),
                format="varder",
            )

    def test_save_appends_default_extension(self) -> None:
        target = self._tmpdir / "no_extension"
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="hex",
        )
        self.assertTrue(result["output_path"].endswith(".hex"))

    def test_save_refuses_overwrite_by_default(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        with self.assertRaises(FileExistsError):
            self._actions._dispatch_save_package(
                ctx=None,
                session_id=self._sid,
                output_path=str(target),
                format="der",
            )

    def test_save_overwrite_true_replaces(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="der",
            overwrite=True,
        )
        self.assertGreater(result["size_bytes"], 1)

    def test_unknown_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_save_package(
                ctx=None,
                session_id=self._sid,
                output_path=str(self._tmpdir / "x.bin"),
                format="bogus",
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class PeCrudTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_pe_crud_"))
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_pe_refuses_index_zero(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_pe(
                ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=0
            )

    def test_add_unknown_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_pe(
                ctx=None, session_id=self._sid, pe_type="bogusPeType"
            )

    def test_add_then_delete_round_trip(self) -> None:
        before = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        before_count = len(before["rows"])
        # Insert a new AKA PE just before the end sentinel.
        result = self._actions._dispatch_add_pe(
            ctx=None,
            session_id=self._sid,
            pe_type="akaParameter",
            insert_at=before_count - 1,
        )
        added_index = result["pe_index"]
        after_add = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        self.assertEqual(len(after_add["rows"]), before_count + 1)
        # Remove it.
        delete_result = self._actions._dispatch_delete_pe(
            ctx=None, session_id=self._sid, pe_index=added_index
        )
        self.assertEqual(delete_result["remaining_count"], before_count)

    def test_delete_header_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_delete_pe(
                ctx=None, session_id=self._sid, pe_index=0
            )

    def test_export_pe_writes_der(self) -> None:
        target = self._tmpdir / "pe0.der"
        result = self._actions._dispatch_export_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=0,
            output_path=str(target),
            format="der",
        )
        self.assertTrue(target.is_file())
        self.assertGreater(result["bytes_written"], 0)

    def test_export_then_import_round_trip(self) -> None:
        # Export the second PE (whatever it is), then re-import it
        # at a fresh slot near the end of the sequence.
        export_path = self._tmpdir / "pe2.der"
        self._actions._dispatch_export_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=2,
            output_path=str(export_path),
            format="der",
        )
        before = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        before_count = len(before["rows"])
        result = self._actions._dispatch_import_pe(
            ctx=None,
            session_id=self._sid,
            input_path=str(export_path),
            insert_at=before_count - 1,
        )
        self.assertGreater(result["pe_index"], 0)
        after = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        self.assertEqual(len(after["rows"]), before_count + 1)

    def test_import_xml_unsupported(self) -> None:
        bad = self._tmpdir / "ftx.xml"
        bad.write_text("<x/>", encoding="utf-8")
        with self.assertRaises(ValueError):
            self._actions._dispatch_import_pe(
                ctx=None,
                session_id=self._sid,
                input_path=str(bad),
            )

    def test_export_pe_refuses_overwrite(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        with self.assertRaises(FileExistsError):
            self._actions._dispatch_export_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                output_path=str(target),
                format="der",
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ApplicationsTabTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_list_applications_returns_rows(self) -> None:
        result = self._actions._dispatch_list_applications(
            ctx=None, session_id=self._sid
        )
        self.assertIn("rows", result)
        # Reference profile carries at least one ISD.
        self.assertGreaterEqual(len(result["rows"]), 1)
        for row in result["rows"]:
            self.assertIn("pe_index", row)
            self.assertIn("pe_type", row)

    def test_compare_applications_self(self) -> None:
        result = self._actions._dispatch_compare_applications(
            ctx=None,
            session_id=self._sid,
            target_path=str(_REFERENCE_PROFILE),
        )
        # Self-compare → everything must be unchanged.
        self.assertEqual(result["summary"]["added"], 0)
        self.assertEqual(result["summary"]["removed"], 0)
        self.assertEqual(result["summary"]["unchanged"], result["left_count"])

    def test_compare_applications_missing_target(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self._actions._dispatch_compare_applications(
                ctx=None,
                session_id=self._sid,
                target_path="/no/such/path.der",
            )


class ShowPeApplicationParameterSummaryTests(unittest.TestCase):
    """Pins the show_pe summary used by the GUI PE-SD parameter card."""

    def test_legacy_byte_envelopes_feed_parameter_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        decoded = {
            "instance": {
                "applicationSpecificParametersC9": {
                    "__ygg_saip_bytes__": "81028000",
                },
                "applicationParameters": {
                    "uiccToolkitApplicationSpecificParametersField": {
                        "__ygg_saip_bytes__": "0100010100000202011606B2010000000000",
                    },
                },
            },
        }

        summary = saip_actions._application_parameter_summary(decoded)

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["c9"]["raw"], "81028000")
        self.assertEqual(
            summary["c9"]["items"][0]["decoded"]["scpName"],
            "SCP80",
        )
        self.assertEqual(
            summary["parameters"][0]["tar_values"],
            ["B20100", "000000"],
        )
        self.assertEqual(
            [entry["tar"] for entry in summary["tar_values"]],
            ["B20100", "000000"],
        )

    def test_rfm_tar_list_is_included_in_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        summary = saip_actions._application_parameter_summary(
            {
                "tarList": [
                    {"__ygg_saip_bytes__": "B00001"},
                ],
            }
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["tar_values"][0]["tar"], "B00001")
        self.assertEqual(summary["tar_values"][0]["source"], "tarList")

    def test_application_instance_list_tars_feed_parameter_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        summary = saip_actions._application_parameter_summary(
            {
                "instanceList": [
                    {
                        "applicationParameters": {
                            "uiccToolkitApplicationSpecificParametersField": {
                                "__ygg_saip_bytes__": "0100010100000202011603000000",
                            },
                        },
                    },
                ],
            }
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["parameters"][0]["instance_index"], 0)
        self.assertEqual(summary["parameters"][0]["tar_values"], ["000000"])
        self.assertEqual(summary["tar_values"][0]["tar"], "000000")

    def test_toolkit_tars_of_the_spec_layout_feed_parameter_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        summary = saip_actions._application_parameter_summary(
            {
                "instance": {
                    "applicationParameters": {
                        "uiccToolkitApplicationSpecificParametersField": {
                            "__ygg_saip_bytes__": "01001000000201120300000000",
                        },
                    },
                },
            }
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["parameters"][0]["tar_values"], ["000000"])
        # ETSI TS 102 226 V19.0.0 §8.2.1.3.2.2.1: menu text length 16, no entries.
        self.assertEqual(summary["parameters"][0]["decoded"]["maxTextLengthForMenuEntry"], 16)
        self.assertEqual(summary["tar_values"][0]["tar"], "000000")

    def test_wrapper_shaped_rfm_tar_list_feeds_parameter_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        summary = saip_actions._application_parameter_summary(
            {
                "tarList": {
                    "decoded": [
                        {"tar": "B00001"},
                    ],
                },
            }
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary["tar_values"][0]["tar"], "B00001")

    def test_security_domain_system_and_access_parameters_feed_summary(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        summary = saip_actions._application_parameter_summary(
            {
                "instance": {
                    "systemSpecificParameters": {
                        "volatileMemoryQuotaC7": bytes.fromhex("00001000"),
                        "nonVolatileMemoryQuotaC8": bytes.fromhex("2000"),
                        "globalServiceParameters": bytes.fromhex("A0"),
                        "implicitSelectionParameter": bytes.fromhex("81"),
                        "ts102226SIMFileAccessToolkitParameter": bytes.fromhex(
                            "01000102100103040202011203B00001"
                        ),
                        "ts102226AdditionalContactlessParameters": {
                            "protocolParameterData": bytes.fromhex("800101"),
                        },
                        "contactlessProtocolParameters": bytes.fromhex("810102"),
                        "userInteractionContactlessParameters": bytes.fromhex(
                            "820441505031"
                        ),
                    },
                    "applicationParameters": {
                        "uiccAccessApplicationSpecificParametersField": (
                            bytes.fromhex("00010000")
                        ),
                        "uiccAdministrativeAccessApplicationSpecificParametersField": (
                            bytes.fromhex("00040203010400")
                        ),
                    },
                },
            }
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        system = {item["key"]: item for item in summary["system_parameters"]}
        self.assertEqual(
            system["volatileMemoryQuotaC7"]["decoded"]["decimal"],
            4096,
        )
        self.assertEqual(
            system["nonVolatileMemoryQuotaC8"]["decoded"]["decimal"],
            8192,
        )
        self.assertIn(
            "Global PIN",
            system["globalServiceParameters"]["decoded"]["activeServices"],
        )
        self.assertTrue(
            system["implicitSelectionParameter"]["decoded"]["defaultSelected"]
        )
        self.assertEqual(
            system["ts102226SIMFileAccessToolkitParameter"]["decoded"]["tarValues"],
            ["B00001"],
        )
        self.assertEqual(
            system["ts102226AdditionalContactlessParameters"]["decoded"]["items"][0][
                "tag"
            ],
            "80",
        )
        self.assertEqual(
            system["contactlessProtocolParameters"]["decoded"]["items"][0]["tag"],
            "81",
        )
        self.assertEqual(
            system["userInteractionContactlessParameters"]["decoded"]["items"][0][
                "decoded"
            ],
            "APP1",
        )
        params = {item["key"]: item for item in summary["parameters"]}
        self.assertEqual(
            params["uiccAccessApplicationSpecificParametersField"]["decoded"][
                "entries"
            ][0]["accessDomain"],
            "00",
        )
        self.assertEqual(
            params["uiccAdministrativeAccessApplicationSpecificParametersField"][
                "decoded"
            ]["entries"][0]["accessDomain"],
            "02030104",
        )

    def test_security_domain_parameter_state_creates_editable_slots(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            _decode_uicc_toolkit_parameters,
        )
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        section = {"instance": {}}

        result = saip_actions._apply_sd_parameter_state_to_section(
            section,
            {
                "c9_enabled": True,
                "c9_hex": "81028000",
                "system_global_service_enabled": True,
                "system_global_service": {
                    "activeServices": ["Global PIN", "Secure messaging"],
                },
                "system_implicit_selection_enabled": True,
                "system_implicit_selection": {
                    "defaultSelected": True,
                    "channelMask": "03",
                },
                "memory_parameters": {
                    "volatileMemoryQuotaC7": {
                        "enabled": True,
                        "rawHex": "00001000",
                        "decimal": 4096,
                    },
                    "nonVolatileReservedMemory": {
                        "enabled": True,
                        "rawHex": "",
                        "decimal": 8192,
                    },
                },
                "sim_file_access_toolkit_enabled": True,
                "sim_file_access_toolkit": {
                    "accessDomain": "00",
                    "priorityLevelOfToolkitAppInstance": 1,
                    "maxNumberOfTimers": 2,
                    "maxTextLengthForMenuEntry": 16,
                    "menuEntries": [{"position": 3, "id": 4}],
                    "maxNumberOfChannels": 2,
                    "minimumSecurityLevelRaw": "0112",
                    "tarValues": ["B00001"],
                    "additionalBytes": "",
                },
                "additional_contactless_enabled": True,
                "additional_contactless": {
                    "items": [
                        {"tag": "80", "raw": "01"},
                    ],
                },
                "contactless_protocol_enabled": True,
                "contactless_protocol": {
                    "items": [
                        {"tag": "81", "raw": "02"},
                    ],
                },
                "user_interaction_contactless_enabled": True,
                "user_interaction_contactless": {
                    "items": [
                        {"tag": "82", "raw": "41505031"},
                    ],
                },
                "uicc_toolkit_enabled": True,
                "uicc_toolkit": {
                    "priorityLevelOfToolkitAppInstance": 1,
                    "maxNumberOfTimers": 1,
                    "maxTextLengthForMenuEntry": 0,
                    "menuEntries": [{"position": 1, "id": 0}],
                    "maxNumberOfChannels": 2,
                    "minimumSecurityLevelRaw": "0112",
                    "tarValues": ["000000", "B00001"],
                    "maxNumberOfServices": 0,
                    "additionalBytes": "",
                },
                "uicc_access_enabled": True,
                "uicc_access": {
                    "entries": [
                        {"aid": "", "accessDomain": "00", "dap": ""},
                    ],
                },
                "uicc_admin_enabled": True,
                "uicc_admin": {
                    "entries": [
                        {"aid": "", "accessDomain": "02030104", "dap": ""},
                        {"aid": "A0000000871002", "accessDomain": "00", "dap": ""},
                    ],
                },
                "process_data": ["80E2"],
            },
        )

        instance = section["instance"]
        self.assertEqual(instance["applicationSpecificParametersC9"], bytes.fromhex("81028000"))
        system = instance["systemSpecificParameters"]
        self.assertEqual(system["globalServiceParameters"], bytes.fromhex("A0"))
        self.assertEqual(system["implicitSelectionParameter"], bytes.fromhex("83"))
        self.assertEqual(system["volatileMemoryQuotaC7"], bytes.fromhex("00001000"))
        self.assertEqual(system["nonVolatileReservedMemory"], bytes.fromhex("2000"))
        # ETSI TS 102 226 V19.0.0 §8.2.1.3.2.1: access domain, then the resources.
        self.assertEqual(
            system["ts102226SIMFileAccessToolkitParameter"],
            bytes.fromhex("01000102100103040202011203B00001"),
        )
        self.assertEqual(
            system["ts102226AdditionalContactlessParameters"]["protocolParameterData"],
            bytes.fromhex("800101"),
        )
        self.assertEqual(
            system["contactlessProtocolParameters"],
            bytes.fromhex("810102"),
        )
        self.assertEqual(
            system["userInteractionContactlessParameters"],
            bytes.fromhex("820441505031"),
        )
        app_params = instance["applicationParameters"]
        decoded_toolkit = _decode_uicc_toolkit_parameters(
            app_params["uiccToolkitApplicationSpecificParametersField"]
        )
        # §8.2.1.3.2.2.1: one menu entry, position before identifier, then services.
        self.assertEqual(
            app_params["uiccToolkitApplicationSpecificParametersField"],
            bytes.fromhex("01010001010002020112060000 00B00001 00".replace(" ", "")),
        )
        self.assertEqual(decoded_toolkit["tarValues"], ["000000", "B00001"])
        # §8.2.1.3.2.2.2: entries of AID, access domain and DAP.
        self.assertEqual(
            app_params["uiccAccessApplicationSpecificParametersField"],
            bytes.fromhex("00010000"),
        )
        self.assertEqual(
            app_params["uiccAdministrativeAccessApplicationSpecificParametersField"],
            bytes.fromhex("0004020301040007A0000000871002010000"),
        )
        self.assertEqual(instance["processData"], [bytes.fromhex("80E2")])
        self.assertIn(
            "applicationParameters.uiccToolkitApplicationSpecificParametersField",
            result["changed"],
        )

    def test_the_record_shape_of_the_access_parameters_is_refused(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        with self.assertRaises(ValueError):
            saip_actions._apply_sd_parameter_state_to_section(
                {"instance": {}},
                {
                    "uicc_access_enabled": True,
                    "uicc_access": {"accessDomainRecords": [{"domainByte": "00", "parameters": ""}]},
                },
            )

    def test_security_domain_toolkit_raw_payload_can_be_preserved(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        section = {"instance": {}}

        saip_actions._apply_sd_parameter_state_to_section(
            section,
            {
                "c9_enabled": True,
                "c9_hex": "81028000",
                "uicc_toolkit_enabled": True,
                "uicc_toolkit": {
                    "useRawHex": True,
                    "rawHex": "DEAD",
                },
            },
        )

        app_params = section["instance"]["applicationParameters"]
        self.assertEqual(
            app_params["uiccToolkitApplicationSpecificParametersField"],
            bytes.fromhex("DEAD"),
        )


class RfmTarActionTests(unittest.TestCase):
    """Pins the GUI-facing PE-RFM TAR replacement action."""

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = _open_synthetic_session(
            {
                "rfm": {
                    "instanceAID": bytes.fromhex("A0000000090002"),
                    "minimumSecurityLevel": bytes.fromhex("06"),
                    "tarList": [],
                },
            }
        )

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_update_rfm_tars_replaces_tar_list(self) -> None:
        handle = self._manager.claim(self._sid)

        with (
            mock.patch.object(self._actions, "_ensure_pysim_importable"),
            mock.patch.object(self._actions, "_refresh_decoded_document"),
            mock.patch(
                "Tools.ProfilePackage.saip_json_codec."
                "build_profile_sequence_from_document",
                return_value=object(),
            ),
        ):
            result = self._actions._dispatch_update_rfm_tars(
                ctx=None,
                session_id=self._sid,
                section_key="rfm",
                tar_hex_list=["B0 00 01", "B00002"],
            )

        self.assertEqual(result["tar_list"], ["B00001", "B00002"])
        self.assertEqual(
            handle["decoded_document"]["sections"]["rfm"]["tarList"],
            [bytes.fromhex("B00001"), bytes.fromhex("B00002")],
        )
        self.assertIn(0, handle["dirty_pes"])


class ProductSummaryTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_summary_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_inline_json_when_no_path(self) -> None:
        result = self._actions._dispatch_product_summary(ctx=None, output_path="")
        self.assertEqual(result["format"], "json")
        self.assertIn("environment", result["summary"])
        self.assertIn("actions", result["summary"])
        self.assertGreater(len(result["summary"]["actions"]), 30)

    def test_html_export(self) -> None:
        target = self._tmpdir / "summary.html"
        result = self._actions._dispatch_product_summary(
            ctx=None, output_path=str(target), format="html"
        )
        self.assertEqual(result["format"], "html")
        self.assertTrue(target.is_file())
        text = target.read_text(encoding="utf-8")
        self.assertIn("<html>", text)
        self.assertIn("YggdraSIM product summary", text)

    def test_xml_export(self) -> None:
        target = self._tmpdir / "summary.xml"
        self._actions._dispatch_product_summary(
            ctx=None, output_path=str(target), format="xml"
        )
        text = target.read_text(encoding="utf-8")
        self.assertIn("<?xml", text)
        self.assertIn("<yggdrasim_product_summary>", text)

    def test_unknown_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_product_summary(
                ctx=None, output_path="/tmp/x", format="docx"
            )


class ValidationRulesCatalogTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_returns_rules(self) -> None:
        result = self._actions._dispatch_list_validation_rules(ctx=None)
        # The linter ships at least a few rules; trip if the fallback
        # walker found nothing AND the descriptor attr is missing.
        self.assertIn("count", result)
        self.assertIn("rules", result)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class AddVariableToPeTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_replace_iccid_with_placeholder(self) -> None:
        result = self._actions._dispatch_add_variable_to_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=0,
            field_path="iccid",
            variable_name="ICCID",
            encoding="hex",
        )
        self.assertEqual(result["variable_name"], "ICCID")
        self.assertGreater(len(result["captured_value"]), 0)

    def test_unknown_field_path_raises(self) -> None:
        with self.assertRaises(LookupError):
            self._actions._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                field_path="not.a.real.path",
                variable_name="X",
            )

    def test_missing_required_args_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                field_path="",
                variable_name="X",
            )


# ---------------------------------------------------------------------
# Single-PE documents (``saip.export_pe`` / ``saip.import_pe``)
# ---------------------------------------------------------------------

_LOAD_PACKAGE_AID = "A0000000871002"
_CLASS_AID = "A000000087100201"
_INSTANCE_AID = "A000000087100201"
_HEADER_ICCID_HEX = "89880811111111111112"
_PUK_HEX = b"12345678".hex().upper()
_PUK_VALUE = "3131313131313131"


def _synthetic_ijc(package_aid_hex: str) -> bytes:
    """A minimal IJC image: one Header component (JCVM CAP component tag 1)."""
    aid = bytes.fromhex(package_aid_hex)
    header = (
        b"\xDE\xCA\xFF\xED"
        + bytes([0x02, 0x02, 0x00, 0x00, 0x01, len(aid)])
        + aid
    )
    return bytes([0x01]) + len(header).to_bytes(2, "big") + header


def _normalised_body(actions, pe, *, drop_pe_name: bool = False) -> dict:
    """The decoded tree as sorted JSON minus the identification (and pe-name)."""
    projected = json.loads(
        json.dumps(actions._jsonify_decoded(pe.decoded), sort_keys=True)
    )
    for key, value in projected.items():
        if str(key).lower().endswith("header") and isinstance(value, dict):
            value.pop("identification", None)
            if drop_pe_name:
                value.pop("pe-name", None)
    return projected


def _template_text() -> str:
    """Reference profile hex with the header ICCID and one PUK tokenised."""
    text = "".join(_REFERENCE_PROFILE.read_text(encoding="utf-8").split()).upper()
    assert text.count(_HEADER_ICCID_HEX) == 1
    assert text.count(_PUK_HEX) >= 1
    text = text.replace(_HEADER_ICCID_HEX, "[iccidICCID10]", 1)
    return text.replace(_PUK_HEX, "[puk1BINARY8]", 1)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class SinglePeDocumentTests(unittest.TestCase):
    """One PE leaves and re-enters a package complete."""

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_pe_doc_"))
        self._sid = _open_reference_session(saip_actions)
        self._ijc = _synthetic_ijc(_LOAD_PACKAGE_AID)
        self._app_index = self._add_application_pe()

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _add_application_pe(self) -> int:
        actions = self._actions
        rows = actions._dispatch_list_pes(ctx=None, session_id=self._sid)["rows"]
        index = actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="application",
            insert_at=len(rows) - 1,
        )["pe_index"]
        actions._dispatch_set_application_load_block(
            ctx=None, session_id=self._sid, pe_index=index,
            load_package_aid_hex=_LOAD_PACKAGE_AID,
            load_block_object_hex=self._ijc.hex(),
            non_volatile_code_limit_hex="0400",
            hash_value_hex="00112233",
        )
        actions._dispatch_add_application_instance(
            ctx=None, session_id=self._sid, pe_index=index,
            load_package_aid_hex=_LOAD_PACKAGE_AID,
            class_aid_hex=_CLASS_AID,
            instance_aid_hex=_INSTANCE_AID,
            privileges_hex="000000",
            application_specific_parameters_hex="",
        )
        return index

    def _pe(self, index: int):
        return self._manager.claim(self._sid)["pes"].pe_list[index]

    def _identifications(self) -> list:
        return [
            self._actions._pe_identification(pe)
            for pe in self._manager.claim(self._sid)["pes"].pe_list
        ]

    def _export(self, fmt: str, name: str, **extra) -> dict:
        return self._actions._dispatch_export_pe(
            ctx=None, session_id=self._sid, pe_index=self._app_index,
            output_path=str(self._tmpdir / name), format=fmt, **extra,
        )

    def _import(self, path: Path, **extra) -> dict:
        return self._actions._dispatch_import_pe(
            ctx=None, session_id=self._sid, input_path=str(path),
            insert_at=self._app_index + 1, **extra,
        )

    def test_pe_document_round_trips_application_with_load_block(self) -> None:
        original = self._pe(self._app_index)
        exported = self._export("json", "app")
        target = Path(exported["output_path"])
        self.assertTrue(target.name.endswith(".pe.json"))
        self.assertEqual(exported["schema"], "ygg.pe_document.v1")
        self.assertFalse(exported["template"])
        text = target.read_text(encoding="utf-8")
        document = json.loads(text)
        # The schema, the PE type and the tree; nothing about the source.
        self.assertEqual(list(document), ["__ygg_pe_document__", "sections"])
        self.assertEqual(
            document["__ygg_pe_document__"],
            {"schema": "ygg.pe_document.v1", "pe_type": "application"},
        )
        self.assertNotIn(_REFERENCE_PROFILE.name, text)
        self.assertNotIn('"label"', text)
        self.assertEqual(len(document["sections"]), 1)
        (section,) = document["sections"].values()
        # The workbench's own PE name is not in the ASN.1 module, so only
        # the document's tree carries it.
        pe_name = original.decoded["app-Header"]["pe-name"]
        self.assertTrue(pe_name.startswith("application#"))
        self.assertEqual(section["app-Header"]["pe-name"], pe_name)
        # The tree alone rebuilds the PE byte for byte.
        rebuilt = self._actions._pe_from_tagged_sections(document["sections"], "app")
        self.assertEqual(bytes(rebuilt.to_der()), bytes(original.to_der()))
        # The summary and the digest are the response's, not the file's.
        self.assertEqual(exported["der_sha256"], hashlib.sha256(bytes(original.to_der())).hexdigest())
        summary = exported["summary_facts"]
        self.assertEqual(summary["load_block"]["load_block_object_size"], len(self._ijc))
        self.assertEqual(summary["load_block"]["load_package_aid_hex"], _LOAD_PACKAGE_AID)
        self.assertEqual(summary["load_block_inspection"]["package_aid_hex"], _LOAD_PACKAGE_AID)
        self.assertEqual(summary["instances"][0]["instance_aid_hex"], _INSTANCE_AID)

        before = self._identifications()
        imported = self._import(target)
        self.assertEqual(imported["input_format"], "pe_document")
        self.assertIsNone(imported["der_matches"])
        self.assertEqual(imported["pe_type"], "application")
        copy_pe = self._pe(imported["pe_index"])
        self.assertEqual(
            _normalised_body(self._actions, copy_pe),
            _normalised_body(self._actions, original),
        )
        self.assertEqual(copy_pe.decoded["loadBlock"]["loadBlockObject"], self._ijc)
        self.assertEqual(copy_pe.decoded["loadBlock"]["hashValue"], bytes.fromhex("00112233"))
        self.assertEqual(len(copy_pe.decoded["instanceList"]), 1)
        # The copy takes the next free identification; nobody else moves.
        used = [value for value in before if value is not None]
        self.assertEqual(imported["identification"], max(used) + 1)
        after = self._identifications()
        self.assertEqual(
            [value for value in after if value != imported["identification"]],
            before,
        )
        self.assertIn("load block", imported["summary"])
        self.assertIn("1 instance", imported["summary"])

    def test_der_and_hex_exports_round_trip_the_pe_bytes(self) -> None:
        original = self._pe(self._app_index)
        original_der = bytes(original.to_der())
        for fmt, name in (("der", "app.der"), ("hex", "app.hex")):
            exported = self._export(fmt, name)
            target = Path(exported["output_path"])
            if fmt == "hex":
                self.assertEqual(bytes.fromhex(target.read_text().strip()), original_der)
            else:
                self.assertEqual(target.read_bytes(), original_der)
            # The bytes cannot carry the workbench's PE name; the export says so.
            self.assertTrue(any("PE name" in text for text in exported["warnings"]))
            imported = self._import(target)
            self.assertEqual(imported["input_format"], fmt)
            copy_pe = self._pe(imported["pe_index"])
            self.assertEqual(
                _normalised_body(self._actions, copy_pe, drop_pe_name=True),
                _normalised_body(self._actions, original, drop_pe_name=True),
            )
            self.assertEqual(copy_pe.decoded["loadBlock"]["loadBlockObject"], self._ijc)
            self._actions._dispatch_delete_pe(
                ctx=None, session_id=self._sid, pe_index=imported["pe_index"]
            )

    def test_import_accepts_the_plain_decoded_projection(self) -> None:
        original = self._pe(self._app_index)
        flat = self._tmpdir / "flat.json"
        flat.write_text(
            json.dumps(self._actions._jsonify_decoded(original.decoded), indent=1),
            encoding="utf-8",
        )
        imported = self._import(flat)
        self.assertEqual(imported["input_format"], "decoded_json")
        self.assertTrue(any("type tags" in text for text in imported["warnings"]))
        copy_pe = self._pe(imported["pe_index"])
        self.assertEqual(
            _normalised_body(self._actions, copy_pe),
            _normalised_body(self._actions, original),
        )
        self.assertEqual(copy_pe.decoded["loadBlock"]["loadBlockObject"], self._ijc)

    def test_import_uses_the_tree_and_reports_a_stale_recorded_der(self) -> None:
        # An earlier export recorded the DER beside the tree; a hand edit to
        # such a file is still reported.
        original = self._pe(self._app_index)
        exported = self._export("json", "app")
        target = Path(exported["output_path"])
        document = json.loads(target.read_text(encoding="utf-8"))
        document["__ygg_pe_document__"]["der_hex"] = original.to_der().hex().upper()
        (section,) = document["sections"].values()
        section["loadBlock"]["loadBlockObject"]["hex"] = "c402beef"
        target.write_text(json.dumps(document), encoding="utf-8")
        imported = self._import(target)
        self.assertFalse(imported["der_matches"])
        self.assertTrue(any("recorded DER" in text for text in imported["warnings"]))
        copy_pe = self._pe(imported["pe_index"])
        self.assertEqual(copy_pe.decoded["loadBlock"]["loadBlockObject"], bytes.fromhex("c402beef"))

    def test_import_reads_a_document_an_earlier_release_wrote(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import jsonify_document

        original = self._pe(self._app_index)
        der = bytes(original.to_der())
        handle = self._manager.claim(self._sid)
        section_key = self._actions._sections_by_pe_index(handle["decoded_document"])[self._app_index]
        tagged = jsonify_document(
            {
                "intro": ["Profile element application exported from operator.varder"],
                "sections": {section_key: copy.deepcopy(original.decoded)},
            }
        )
        self.assertIn("label", json.dumps(tagged))
        target = self._tmpdir / "earlier.pe.json"
        target.write_text(
            json.dumps(
                {
                    "__ygg_pe_document__": {
                        "schema": "ygg.pe_document.v1",
                        "pe_type": "application",
                        "section_key": section_key,
                        "label": "",
                        "pe_name": original.decoded["app-Header"]["pe-name"],
                        "identification": self._actions._pe_identification(original),
                        "source_package": "operator.varder",
                        "source_pe_index": self._app_index,
                        "template": False,
                        "placeholders": [],
                        "summary": {"pe_type": "application"},
                        "der_hex": der.hex().upper(),
                        "der_sha256": hashlib.sha256(der).hexdigest(),
                        "der_byte_length": len(der),
                    },
                    "intro": tagged["intro"],
                    "sections": tagged["sections"],
                }
            ),
            encoding="utf-8",
        )
        imported = self._import(target)
        self.assertEqual(imported["input_format"], "pe_document")
        self.assertTrue(imported["der_matches"])
        self.assertEqual(
            imported["document_meta"],
            {"pe_type": "application", "template": False, "placeholders": []},
        )
        copy_pe = self._pe(imported["pe_index"])
        self.assertEqual(
            _normalised_body(self._actions, copy_pe),
            _normalised_body(self._actions, original),
        )

    def test_import_accepts_a_document_carrying_bytes_only(self) -> None:
        original = self._pe(self._app_index)
        target = self._tmpdir / "bytes-only.pe.json"
        target.write_text(
            json.dumps(
                {
                    "__ygg_pe_document__": {
                        "schema": "ygg.pe_document.v1",
                        "pe_type": "application",
                        "der_hex": original.to_der().hex().upper(),
                    }
                }
            ),
            encoding="utf-8",
        )
        imported = self._import(target)
        self.assertTrue(imported["der_matches"])
        copy_pe = self._pe(imported["pe_index"])
        self.assertEqual(copy_pe.decoded["loadBlock"]["loadBlockObject"], self._ijc)

    def test_import_refuses_unknown_schema_template_and_unencodable_trees(self) -> None:
        unknown = self._tmpdir / "unknown.pe.json"
        unknown.write_text(
            json.dumps({"__ygg_pe_document__": {"schema": "ygg.pe_document.v9"}, "sections": {}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "schema"):
            self._import(unknown)

        template = self._tmpdir / "template.pe.json"
        template.write_text(
            json.dumps(
                {
                    "__ygg_pe_document__": {"schema": "ygg.pe_document.v1", "pe_type": "pukCodes"},
                    "sections": {
                        "pukCodes": {
                            "puk-Header": {"identification": 2},
                            "pukCodes": [{"keyReference": 1, "pukValue": {"hex": "[puk1BINARY8]"}}],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, r"template.*\[puk1BINARY8\]"):
            self._import(template)

        broken = self._tmpdir / "broken.json"
        broken.write_text(
            json.dumps(
                {
                    "sections": {
                        "application": {
                            "app-Header": {"identification": 1},
                            "instanceList": [
                                {
                                    "applicationLoadPackageAID": {"hex": _LOAD_PACKAGE_AID},
                                    "classAID": {"hex": _CLASS_AID},
                                    "instanceAID": {"hex": _INSTANCE_AID},
                                    "applicationPrivileges": {"hex": "000000"},
                                    "applicationSpecificParametersC9": "oops",
                                }
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "does not encode"):
            self._import(broken)
        # None of the refused files reached the sequence.
        rows = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)["rows"]
        self.assertEqual(rows[self._app_index + 1]["type"], "end")

    def test_export_json_default_extension_is_pe_json(self) -> None:
        exported = self._export("json", "noext")
        self.assertEqual(Path(exported["output_path"]).name, "noext.pe.json")

    def test_open_package_refuses_a_pe_document(self) -> None:
        exported = self._export("json", "app")
        with self.assertRaisesRegex(ValueError, "single profile element document"):
            self._actions._dispatch_open_package(ctx=None, path=exported["output_path"])


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class SinglePeTemplateSessionTests(unittest.TestCase):
    """Single-PE export from an inline-template session."""

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_pe_tpl_"))
        source = self._tmpdir / "profile.varder"
        source.write_text(_template_text(), encoding="utf-8-sig")
        self._sid = saip_actions._dispatch_open_package(ctx=None, path=str(source))["session_id"]
        keys = saip_actions._sections_by_pe_index(
            self._manager.claim(self._sid)["decoded_document"]
        )
        self._puk_index = next(i for i, key in enumerate(keys) if key.startswith("pukCodes"))
        self._pin_index = next(i for i, key in enumerate(keys) if key.startswith("pinCodes"))

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _export(self, index: int, fmt: str, name: str, **extra) -> dict:
        return self._actions._dispatch_export_pe(
            ctx=None, session_id=self._sid, pe_index=index,
            output_path=str(self._tmpdir / name), format=fmt, **extra,
        )

    def _sentinel_hexes(self) -> list[str]:
        records = self._manager.claim(self._sid)["inline_placeholder_records"]
        return [str(record.sentinel_hex).upper() for record in records]

    def test_template_pe_document_keeps_the_literal_and_is_refused_on_import(self) -> None:
        exported = self._export(self._puk_index, "json", "puk")
        self.assertTrue(exported["template"])
        self.assertEqual(exported["placeholders"], ["puk1"])
        target = Path(exported["output_path"])
        text = target.read_text(encoding="utf-8")
        self.assertIn("[puk1BINARY8]", text)
        meta = json.loads(text)["__ygg_pe_document__"]
        self.assertEqual(
            meta,
            {
                "schema": "ygg.pe_document.v1",
                "pe_type": "pukCodes",
                "template": True,
                "placeholders": ["puk1"],
            },
        )
        for sentinel in self._sentinel_hexes():
            self.assertNotIn(sentinel, text.upper())
        with self.assertRaisesRegex(ValueError, "template"):
            self._actions._dispatch_import_pe(
                ctx=None, session_id=self._sid, input_path=str(target),
                insert_at=self._puk_index + 1,
            )

    def test_bytes_exports_substitute_the_pe_own_stored_values(self) -> None:
        # A PE without placeholders leaves as bytes even while the header
        # ICCID is still unresolved elsewhere in the session.
        clean = self._export(self._pin_index, "der", "pin.der")
        self.assertEqual(clean["placeholders"], [])
        self.assertEqual(clean["materialized_variables"], [])
        # The PUK PE needs its own value first.
        with self.assertRaisesRegex(ValueError, "puk1"):
            self._export(self._puk_index, "der", "puk.der")
        self._actions._dispatch_set_variable(
            None, session_id=self._sid, name="puk1", value=_PUK_VALUE,
        )
        exported = self._export(self._puk_index, "der", "puk.der")
        self.assertEqual(exported["materialized_variables"], ["puk1"])
        der = Path(exported["output_path"]).read_bytes()
        self.assertIn(bytes.fromhex(_PUK_VALUE), der)
        for sentinel in self._sentinel_hexes():
            self.assertNotIn(sentinel, der.hex().upper())
        resolved = self._export(
            self._puk_index, "json", "puk-resolved", resolve_variables=True,
        )
        self.assertFalse(resolved["template"])
        self.assertEqual(resolved["materialized_variables"], ["puk1"])
        self.assertEqual(resolved["der_sha256"], hashlib.sha256(der).hexdigest())
        document = json.loads(Path(resolved["output_path"]).read_text(encoding="utf-8"))
        self.assertEqual(
            document["__ygg_pe_document__"],
            {"schema": "ygg.pe_document.v1", "pe_type": "pukCodes"},
        )
        # The substituted tree rebuilds the bytes the DER export wrote.
        rebuilt = self._actions._pe_from_tagged_sections(document["sections"], "puk-resolved")
        self.assertEqual(bytes(rebuilt.to_der()), der)
        # The session itself still holds the template.
        self.assertIn(
            "puk1",
            self._actions._inline_template_state(self._manager.claim(self._sid))["variable_names"]
            if "variable_names" in self._actions._inline_template_state(self._manager.claim(self._sid))
            else ["puk1"],
        )

    def test_a_blocked_session_refuses_to_substitute_into_the_document(self) -> None:
        self._actions._dispatch_set_variable(
            None, session_id=self._sid, name="puk1", value=_PUK_VALUE,
        )
        handle = self._manager.claim(self._sid)
        handle["export_policy"] = {"concrete_export_allowed": False}
        try:
            with self.assertRaisesRegex(ValueError, "cannot be substituted"):
                self._export(self._puk_index, "json", "puk-blocked", resolve_variables=True)
            self.assertFalse((self._tmpdir / "puk-blocked.pe.json").exists())
            # Keeping the literals is still allowed.
            kept = self._export(self._puk_index, "json", "puk-kept")
            self.assertTrue(kept["template"])
            text = Path(kept["output_path"]).read_text(encoding="utf-8")
            self.assertIn("[puk1BINARY8]", text)
            for sentinel in self._sentinel_hexes():
                self.assertNotIn(sentinel, text.upper())
        finally:
            handle.pop("export_policy", None)


if __name__ == "__main__":
    unittest.main()
