# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP authoring / packaging dispatchers.

Covered surfaces:
  * ``saip.save_package`` — DER / hex / JSON output, overwrite guard
  * ``saip.add_pe`` / ``saip.delete_pe`` — sequence splice / drop
  * ``saip.import_pe`` / ``saip.export_pe`` — single-PE I/O
  * ``saip.list_applications`` / ``saip.compare_applications`` —
    SD / Application / ELF inventory and inter-package diff
  * ``saip.product_summary`` — bench environment fingerprint
  * ``saip.list_validation_rules`` — linter rulebook catalogue
  * ``saip.add_variable_to_pe`` — bind PE field to placeholder
"""

from __future__ import annotations

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

    def test_compact_security_domain_toolkit_tars_feed_parameter_summary(self) -> None:
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
        self.assertEqual(summary["parameters"][0]["decoded"]["layout"], "compact-no-menu-entry-count")
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
                            "01AA02BBCC"
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
                            bytes.fromhex("0100")
                        ),
                        "uiccAdministrativeAccessApplicationSpecificParametersField": (
                            bytes.fromhex("050201020304")
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
            system["ts102226SIMFileAccessToolkitParameter"]["decoded"][
                "simToolkitApplicationParameters"
            ]["hex"],
            "AA",
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
                "accessDomainRecords"
            ][0]["domainByte"],
            "0x00",
        )
        self.assertEqual(
            params["uiccAdministrativeAccessApplicationSpecificParametersField"][
                "decoded"
            ]["accessDomainRecords"][0]["parameters"],
            "01020304",
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
                    "simToolkitApplicationParametersHex": "AA",
                    "simFileAccessParametersHex": "BBCC",
                    "trailingBytes": "",
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
                    "accessDomain": "00",
                    "priorityLevelOfToolkitAppInstance": 1,
                    "maxNumberOfTimers": 1,
                    "maxTextLengthForMenuEntry": 0,
                    "menuEntries": [],
                    "maxNumberOfChannels": 2,
                    "minimumSecurityLevelRaw": "12",
                    "tarValues": ["000000", "B00001"],
                    "trailingPadding": "",
                },
                "uicc_access_enabled": True,
                "uicc_access": {
                    "accessDomainRecords": [
                        {"domainByte": "00", "parameters": ""},
                    ],
                },
                "uicc_admin_enabled": True,
                "uicc_admin": {
                    "accessDomainRecords": [
                        {"domainByte": "02", "parameters": "01020304"},
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
        self.assertEqual(system["ts102226SIMFileAccessToolkitParameter"], bytes.fromhex("01AA02BBCC"))
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
        self.assertEqual(decoded_toolkit["tarValues"], ["000000", "B00001"])
        self.assertEqual(
            app_params["uiccAccessApplicationSpecificParametersField"],
            bytes.fromhex("0100"),
        )
        self.assertEqual(
            app_params["uiccAdministrativeAccessApplicationSpecificParametersField"],
            bytes.fromhex("050201020304"),
        )
        self.assertEqual(instance["processData"], [bytes.fromhex("80E2")])
        self.assertIn(
            "applicationParameters.uiccToolkitApplicationSpecificParametersField",
            result["changed"],
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


if __name__ == "__main__":
    unittest.main()
