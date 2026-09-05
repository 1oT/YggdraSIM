# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.gui_server.actions.saip import (
    _build_decoded_document,
    _dispatch_list_variables,
    _dispatch_open_package,
    _dispatch_save_package,
    _dispatch_set_variable,
    _new_empty_pes,
)
from yggdrasim_common.gui_server.sessions import get_manager


class VarderConcreteExportGuardTests(unittest.TestCase):
    def test_opened_inline_template_cannot_export_placeholder_sentinels(self) -> None:
        iccid_hex = "01234567890123456789"
        pes = _new_empty_pes(iccid_hex=iccid_hex)
        der = bytes(pes.to_der())
        needle = bytes.fromhex(iccid_hex)
        self.assertEqual(der.count(needle), 1)
        template = (
            der.hex()
            .upper()
            .replace(
                iccid_hex,
                "{ICCIDICCID10}",
                1,
            )
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "profile.varder"
            source.write_text(template, encoding="utf-8-sig")
            opened = _dispatch_open_package(None, path=str(source))
            session_id = opened["session_id"]
            try:
                handle = get_manager().claim(session_id)
                self.assertEqual(len(handle["inline_placeholder_records"]), 1)
                sentinel_der = bytes(handle["pes"].to_der())
                for format_name, suffix in (("der", ".der"), ("hex", ".hex")):
                    with self.assertRaisesRegex(
                        ValueError,
                        "unresolved inline placeholder",
                    ):
                        _dispatch_save_package(
                            None,
                            session_id=session_id,
                            output_path=str(Path(temp_dir) / f"blocked{suffix}"),
                            format=format_name,
                        )

                varder_result = _dispatch_save_package(
                    None,
                    session_id=session_id,
                    output_path=str(Path(temp_dir) / "projected-template"),
                    format="varder",
                )
                self.assertEqual(varder_result["format"], "varder")
                self.assertEqual(
                    varder_result["remaining_inline_placeholder_count"],
                    1,
                )
                self.assertTrue(varder_result["output_path"].endswith(".varder"))
                varder_path = Path(varder_result["output_path"])
                varder_text = varder_path.read_text(encoding="utf-8-sig")
                self.assertIn("{ICCIDICCID10}", varder_text)
                self.assertNotIn("\n", varder_text)

                reopened_varder = _dispatch_open_package(
                    None,
                    path=str(varder_path),
                )
                try:
                    self.assertEqual(reopened_varder["inline_placeholder_count"], 1)
                    reopened_handle = get_manager().claim(reopened_varder["session_id"])
                    self.assertEqual(bytes(reopened_handle["pes"].to_der()), sentinel_der)
                finally:
                    get_manager().close(reopened_varder["session_id"])

                asn_result = _dispatch_save_package(
                    None,
                    session_id=session_id,
                    output_path=str(Path(temp_dir) / "projected-template-asn"),
                    format="asn",
                )
                self.assertEqual(asn_result["format"], "asn1")
                self.assertTrue(asn_result["output_path"].endswith(".asn"))
                asn_path = Path(asn_result["output_path"])
                self.assertIn(
                    "{ICCIDICCID10}",
                    asn_path.read_text(encoding="utf-8"),
                )
                reopened_asn = _dispatch_open_package(None, path=str(asn_path))
                try:
                    self.assertEqual(reopened_asn["inline_placeholder_count"], 1)
                finally:
                    get_manager().close(reopened_asn["session_id"])

                json_path = Path(temp_dir) / "authoring.json"
                json_result = _dispatch_save_package(
                    None,
                    session_id=session_id,
                    output_path=str(json_path),
                    format="json",
                )
                self.assertEqual(json_result["format"], "json")
                json_text = json_path.read_text(encoding="utf-8")
                self.assertIn("{ICCIDICCID10}", json_text)
                self.assertIn("__ygg_inline_placeholders__", json_text)
                reopened = _dispatch_open_package(
                    None,
                    path=str(json_path),
                )
                try:
                    self.assertEqual(reopened["inline_placeholder_count"], 1)
                    reopened_handle = get_manager().claim(reopened["session_id"])
                    self.assertEqual(bytes(reopened_handle["pes"].to_der()), sentinel_der)
                    with self.assertRaisesRegex(
                        ValueError,
                        "unresolved inline placeholder",
                    ):
                        _dispatch_save_package(
                            None,
                            session_id=reopened["session_id"],
                            output_path=str(Path(temp_dir) / "reopened-blocked.der"),
                            format="der",
                        )
                finally:
                    get_manager().close(reopened["session_id"])
            finally:
                get_manager().close(session_id)

    def test_opened_inline_template_materializes_in_live_workbench(self) -> None:
        placeholder_seed = "01234567890123456789"
        pes = _new_empty_pes(iccid_hex=placeholder_seed)
        template = bytes(pes.to_der()).hex().upper().replace(placeholder_seed, "{ICCIDICCID10}", 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "profile.varder"
            source.write_text(template, encoding="utf-8-sig")
            opened = _dispatch_open_package(None, path=str(source))
            session_id = opened["session_id"]
            try:
                listed = _dispatch_list_variables(None, session_id=session_id)
                self.assertEqual(listed["count"], 1)
                self.assertEqual(listed["variables"][0]["name"], "ICCID")
                self.assertEqual(listed["variables"][0]["source"], "inline_varder")

                applied = _dispatch_set_variable(
                    None,
                    session_id=session_id,
                    name="ICCID",
                    value="8947000000000000001",
                )
                self.assertEqual(applied["remaining_inline_placeholder_count"], 0)
                self.assertEqual(applied["materialization_source"], "inline_varder")

                output = Path(temp_dir) / "materialized.der"
                saved = _dispatch_save_package(
                    None,
                    session_id=session_id,
                    output_path=str(output),
                    format="der",
                )
                self.assertEqual(saved["format"], "der")
                self.assertEqual(
                    saved["remaining_inline_placeholder_count"],
                    0,
                )
                self.assertTrue(output.is_file())

                with self.assertRaisesRegex(ValueError, "unresolved inline-template"):
                    _dispatch_save_package(
                        None,
                        session_id=session_id,
                        output_path=str(Path(temp_dir) / "materialized-template"),
                        format="varder",
                    )
            finally:
                get_manager().close(session_id)

    def test_semantic_catalog_materializes_header_field(self) -> None:
        pes = _new_empty_pes(iccid_hex="00" * 10)
        document = _build_decoded_document(pes, Path("catalog-source.der"))
        document["__ygg_variable_catalog__"] = {
            "schema_version": "yggdrasim.saip-variable-catalog/v1",
            "variables": [
                {
                    "id": "ICCID",
                    "aliases": ["PROFILE_ID::<ICCID>"],
                    "label": "ICCID",
                    "classification": "PROFILE_IDENTITY",
                    "required": True,
                    "input": {
                        "kind": "DECIMAL_DIGITS",
                        "format": "ICCID",
                        "constraints": {"min_characters": 19, "max_characters": 20},
                    },
                    "status": "BOUND_SENTINEL",
                    "bindings": [
                        {
                            "encoder": "ICCID_HEADER_BCD_V1",
                            "output_length_bytes": 10,
                            "locator": {
                                "pe_type": "header",
                                "context": "PROFILE",
                                "field": "iccid",
                            },
                        }
                    ],
                }
            ],
        }
        handle = {
            "pes": pes,
            "decoded_document": document,
            "encoding": "json",
            "source_path": "",
            "inline_placeholder_records": [],
        }
        session = get_manager().open(kind="saip", handle=handle, close=lambda: None)
        try:
            listed = _dispatch_list_variables(None, session_id=session.id)
            self.assertEqual(listed["variables"][0]["source"], "semantic_catalog")
            applied = _dispatch_set_variable(
                None,
                session_id=session.id,
                name="profile_id::<iccid>",
                value="8947000000000000001",
            )
            self.assertEqual(applied["materialization_source"], "semantic_catalog")
            self.assertEqual(applied["name"], "ICCID")
            live = get_manager().claim(session.id)
            header = live["pes"].pe_list[0]
            self.assertEqual(
                bytes(header.decoded["iccid"]),
                bytes.fromhex("8947000000000000001F"),
            )
        finally:
            get_manager().close(session.id)

    def test_secret_catalog_values_are_redacted_from_listing(self) -> None:
        pes = _new_empty_pes(iccid_hex="00" * 10)
        document = _build_decoded_document(pes, Path("secret-source.der"))
        document["__ygg_variable_catalog__"] = {
            "schema_version": "yggdrasim.saip-variable-catalog/v1",
            "variables": [
                {
                    "id": "KI",
                    "aliases": ["K"],
                    "label": "Authentication key",
                    "classification": "AUTHENTICATION_SECRET",
                    "required": True,
                    "input": {
                        "kind": "HEX_BYTES",
                        "format": "RAW_HEX",
                        "constraints": {"exact_bytes": 16},
                    },
                    "status": "BOUND_SENTINEL",
                    "bindings": [],
                }
            ],
        }
        secret_value = "00112233445566778899AABBCCDDEEFF"
        handle = {
            "pes": pes,
            "decoded_document": document,
            "encoding": "json",
            "source_path": "",
            "inline_placeholder_records": [],
            "applied_overrides": {"KI": secret_value},
        }
        session = get_manager().open(kind="saip", handle=handle, close=lambda: None)
        try:
            listed = _dispatch_list_variables(None, session_id=session.id)
            self.assertTrue(listed["variables"][0]["secret"])
            self.assertEqual(listed["variables"][0]["value"], "")
            self.assertEqual(listed["overrides_applied"], {"KI": ""})
            self.assertNotIn(secret_value, str(listed))
        finally:
            get_manager().close(session.id)


if __name__ == "__main__":
    unittest.main()
