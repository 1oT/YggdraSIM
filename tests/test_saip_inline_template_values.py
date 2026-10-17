# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Inline template placeholders: literal display, stored values, exports.

A varder / ASN.1 / tagged-JSON template keeps its ``[nameTYPElen]``
placeholders for the whole session. Every projection shows the literal
instead of the sentinel bytes, the token editor stores values without
consuming the placeholders, and DER / HEX exports substitute the stored
values into a copy of the sequence.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_hex_template import (
    locate_sentinels_in_bytes,
    splice_literals_into_hex_text,
    splice_literals_into_projection,
    substitute_inline_placeholders,
)
from Tools.ProfilePackage.saip_variable_materialization import (
    SaipVariableMaterializationError,
    inline_variable_sidecar_path_for,
    match_inline_variable_values,
    materialize_inline_records,
    read_inline_variable_sidecar,
    validate_inline_variable_value,
    write_inline_variable_sidecar,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_HEX = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
_HEADER_ICCID_HEX = "89880811111111111112"
_EF_ICCID_HEX = "98888011111111111111"
_PUK_HEX = b"12345678".hex().upper()
_ICCID_VALUE = "8988201234567890123"
_PUK_VALUE = "3131313131313131"


def _template_text() -> str:
    """Reference profile hex with the header ICCID, EF.ICCID and one PUK tokenised."""
    text = "".join(_REFERENCE_HEX.read_text(encoding="utf-8").split()).upper()
    assert text.count(_HEADER_ICCID_HEX) == 1
    assert text.count(_EF_ICCID_HEX) == 1
    assert text.count(_PUK_HEX) >= 1
    text = text.replace(_HEADER_ICCID_HEX, "[iccidICCID10]", 1)
    text = text.replace(_EF_ICCID_HEX, "[iccidICCID10nibbleswap]", 1)
    return text.replace(_PUK_HEX, "[puk1BINARY8]", 1)


class InlineTemplateHelperTests(unittest.TestCase):
    def test_projection_splice_rewrites_plain_hex_strings_only(self) -> None:
        _text, records = substitute_inline_placeholders("[iccidICCID10]")
        sentinel = records[0].sentinel_hex
        tree = {
            "iccid": sentinel.upper(),
            "nested": [sentinel.lower(), "not hex " + sentinel, "00"],
            "count": 3,
        }
        hits = splice_literals_into_projection(tree, records)
        self.assertEqual(hits, 2)
        self.assertEqual(tree["iccid"], "[iccidICCID10]")
        self.assertEqual(tree["nested"][0], "[iccidICCID10]")
        self.assertEqual(tree["nested"][1], "not hex " + sentinel)
        self.assertEqual(tree["nested"][2], "00")
        self.assertEqual(splice_literals_into_projection(tree, []), 0)

    def test_hex_text_splice_and_byte_ranges(self) -> None:
        _text, records = substitute_inline_placeholders("AA[iccidICCID10]BB")
        sentinel = bytes.fromhex(records[0].sentinel_hex)
        spliced, hits = splice_literals_into_hex_text("aa" + sentinel.hex() + "bb", records)
        self.assertEqual(hits, 1)
        self.assertEqual(spliced, "aa[iccidICCID10]bb")
        ranges = locate_sentinels_in_bytes(b"\xaa" + sentinel + b"\xbb", records)
        self.assertEqual(len(ranges), 1)
        self.assertEqual((ranges[0]["start"], ranges[0]["end"]), (1, 11))
        self.assertEqual(ranges[0]["literal"], "[iccidICCID10]")
        self.assertEqual(ranges[0]["variable"], "iccid")

    def test_materialize_records_matches_names_case_insensitively(self) -> None:
        _text, records = substitute_inline_placeholders("[iccidICCID10]00[puk1BINARY8]")
        iccid_sentinel = bytes.fromhex(records[0].sentinel_hex)
        puk_sentinel = bytes.fromhex(records[1].sentinel_hex)
        document = {
            "sections": {
                "header": {"iccid": iccid_sentinel},
                "pukCodes": {"pukCodes": [{"pukValue": puk_sentinel}]},
            }
        }
        matched, unresolved = match_inline_variable_values(records, {"ICCID": _ICCID_VALUE})
        self.assertEqual(matched, {"iccid": _ICCID_VALUE})
        self.assertEqual(unresolved, ["puk1"])
        with self.assertRaisesRegex(SaipVariableMaterializationError, "puk1"):
            materialize_inline_records(document, records, {"ICCID": _ICCID_VALUE})
        resolved, remaining, results = materialize_inline_records(
            document,
            records,
            {"ICCID": _ICCID_VALUE, "PUK1": _PUK_VALUE},
        )
        self.assertEqual(remaining, [])
        self.assertEqual([item.variable_name for item in results], ["iccid", "puk1"])
        self.assertEqual(
            bytes(resolved["sections"]["header"]["iccid"]),
            bytes.fromhex(_ICCID_VALUE + "F"),
        )
        self.assertEqual(
            bytes(resolved["sections"]["pukCodes"]["pukCodes"][0]["pukValue"]),
            bytes.fromhex(_PUK_VALUE),
        )
        # The input document is left untouched.
        self.assertEqual(bytes(document["sections"]["header"]["iccid"]), iccid_sentinel)

    def test_validate_value_rejects_unknown_names_and_bad_input(self) -> None:
        _text, records = substitute_inline_placeholders("[iccidICCID10]")
        self.assertEqual(len(validate_inline_variable_value(records, "ICCID", _ICCID_VALUE)), 1)
        with self.assertRaisesRegex(SaipVariableMaterializationError, "decimal digits"):
            validate_inline_variable_value(records, "iccid", "not-digits")
        with self.assertRaisesRegex(SaipVariableMaterializationError, "no occurrence"):
            validate_inline_variable_value(records, "imsi", "001010000000001")

    def test_sidecar_round_trip_and_schema_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            template = Path(temp_dir) / "profile.varder"
            sidecar = inline_variable_sidecar_path_for(template)
            self.assertEqual(sidecar.name, "profile.variables.json")
            write_inline_variable_sidecar(
                sidecar,
                {"iccid": _ICCID_VALUE},
                created_from="profile.varder",
            )
            loaded = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema"], "yggdrasim.saip-inline-variables/v1")
            self.assertEqual(read_inline_variable_sidecar(sidecar), {"iccid": _ICCID_VALUE})
            sidecar.write_text(json.dumps({"schema": "other", "values": {}}), encoding="utf-8")
            with self.assertRaisesRegex(SaipVariableMaterializationError, "schema"):
                read_inline_variable_sidecar(sidecar)


class InlineTemplateWorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if _REFERENCE_HEX.is_file() is False:
            raise unittest.SkipTest("No tracked reference SAIP profile fixture")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.saip = saip_actions
        cls.manager = get_manager()
        cls.template_text = _template_text()

    def _open(self, temp_dir: Path, name: str = "profile.varder") -> tuple[str, Path]:
        source = temp_dir / name
        source.write_text(self.template_text, encoding="utf-8-sig")
        opened = self.saip._dispatch_open_package(None, path=str(source))
        return opened["session_id"], source

    def _pe_index(self, session_id: str, pe_type: str) -> int:
        handle = self.manager.claim(session_id)
        keys = self.saip._sections_by_pe_index(handle["decoded_document"])
        return next(index for index, key in enumerate(keys) if key.startswith(pe_type))

    def test_projections_show_placeholder_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_id, _source = self._open(Path(temp_dir))
            try:
                shown = self.saip._dispatch_show_pe(None, session_id=session_id, pe_index=0)
                self.assertEqual(shown["decoded"]["iccid"], "[iccidICCID10]")
                self.assertIn("[iccidICCID10]", shown["pe_hex_template"])
                self.assertEqual(len(shown["pe_inline_placeholders"]), 1)
                self.assertFalse(shown["pe_inline_placeholders"][0]["resolved"])
                self.assertNotIn("[", shown["pe_hex"])

                header = self.saip._dispatch_get_profile_header(None, session_id=session_id)["header"]
                self.assertEqual(header["iccid_digits"], "[iccidICCID10]")
                self.assertEqual(header["iccid_placeholders"][0]["variable"], "iccid")

                shown_file = self.saip._dispatch_show_file(
                    None,
                    session_id=session_id,
                    section_key="mf",
                    field_path="ef-iccid",
                )
                self.assertIn("[iccidICCID10nibbleswap]", json.dumps(shown_file["payload"]))
                self.assertEqual(shown_file["inline_placeholders"][0]["end"], 10)
                self.assertEqual(shown_file["decoded"]["format"], "Inline template placeholder")
                self.assertEqual(
                    shown_file["decoded"]["placeholders"][0]["literal"],
                    "[iccidICCID10nibbleswap]",
                )

                fields = self.saip._dispatch_list_decoded_fields(
                    None,
                    session_id=session_id,
                    section_key="mf",
                    rel_path_prefix=["ef-iccid"],
                )
                content_entries = [
                    entry for entry in fields["fields"] if entry["field_name"] == "fillFileContent"
                ]
                self.assertEqual(len(content_entries), 1)
                self.assertEqual(content_entries[0]["editor_kind"], "readonly_json")
                self.assertTrue(content_entries[0]["read_only"])
                self.assertEqual(
                    content_entries[0]["model"]["payload"]["placeholders"][0]["literal"],
                    "[iccidICCID10nibbleswap]",
                )

                puk_index = self._pe_index(session_id, "pukCodes")
                puk = self.saip._dispatch_show_pe(None, session_id=session_id, pe_index=puk_index)
                self.assertEqual(puk["decoded"]["pukCodes"][0]["pukValue"], "[puk1BINARY8]")

                export_path = Path(temp_dir) / "header.json"
                self.saip._dispatch_export_pe(
                    None,
                    session_id=session_id,
                    pe_index=0,
                    output_path=str(export_path),
                    format="json",
                )
                self.assertIn("[iccidICCID10]", export_path.read_text(encoding="utf-8"))
            finally:
                self.manager.close(session_id)

    def test_store_values_then_export_complete_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            session_id, source = self._open(root)
            try:
                listed = self.saip._dispatch_list_variables(None, session_id=session_id)
                self.assertEqual(listed["inline_template"]["unresolved_variables"], ["iccid", "puk1"])
                self.assertEqual(listed["inline_template"]["occurrence_count"], 3)

                applied = self.saip._dispatch_set_variable(
                    None, session_id=session_id, name="ICCID", value=_ICCID_VALUE,
                )
                self.assertEqual(applied["name"], "iccid")
                self.assertEqual(applied["remaining_inline_placeholder_count"], 1)
                self.assertEqual(applied["inline_template"]["unresolved_variables"], ["puk1"])
                with self.assertRaisesRegex(ValueError, "puk1"):
                    self.saip._dispatch_save_package(
                        None, session_id=session_id, output_path=str(root / "blocked.der"), format="der",
                    )
                with self.assertRaisesRegex(SaipVariableMaterializationError, "hexadecimal"):
                    self.saip._dispatch_set_variable(
                        None, session_id=session_id, name="puk1", value="not-hex",
                    )
                applied = self.saip._dispatch_set_variable(
                    None, session_id=session_id, name="PUK1", value=_PUK_VALUE,
                )
                self.assertTrue(applied["value_redacted"])
                # Sensitive names keep their classification but the workbench
                # shows the stored value in full.
                self.assertEqual(
                    applied["inline_template"]["stored_values"]["puk1"], "3131313131313131"
                )
                self.assertTrue(applied["inline_template"]["complete_export_ready"])
                # The echo of the submitted value stays blank; the listing state
                # carries the stored value because the workbench shows it.
                self.assertEqual(applied["value"], "")
                # The workbench shows sensitive values in full; only the
                # submitted-value echo and log lines stay clear of them.
                self.assertIn(
                    _PUK_VALUE,
                    json.dumps(self.saip._dispatch_list_variables(None, session_id=session_id)),
                )

                saved = self.saip._dispatch_save_package(
                    None, session_id=session_id, output_path=str(root / "complete.der"), format="der",
                )
                self.assertTrue(saved["materialized"])
                self.assertEqual(saved["materialized_variables"], ["iccid", "puk1"])
                self.assertEqual(saved["inline_placeholder_count"], 3)
                der = (root / "complete.der").read_bytes()
                self.assertIn(bytes.fromhex(_ICCID_VALUE + "F"), der)
                self.assertIn(bytes.fromhex("988802214365870921F3"), der)
                self.assertIn(bytes.fromhex(_PUK_VALUE), der)
                live = self.manager.claim(session_id)
                self.assertEqual(len(live["inline_placeholder_records"]), 3)
                self.assertEqual(live["source_path"], str(source.resolve()))
                shown = self.saip._dispatch_show_pe(None, session_id=session_id, pe_index=0)
                self.assertEqual(shown["decoded"]["iccid"], "[iccidICCID10]")
                self.assertTrue(shown["pe_inline_placeholders"][0]["resolved"])
                self.assertEqual(shown["pe_inline_placeholders"][0]["stored_value"], _ICCID_VALUE)

                json_saved = self.saip._dispatch_save_package(
                    None, session_id=session_id, output_path=str(root / "template.json"), format="json",
                )
                self.assertFalse(json_saved["materialized"])
                json_text = (root / "template.json").read_text(encoding="utf-8")
                self.assertIn("[iccidICCID10]", json_text)
                self.assertIn('"values"', json_text)
                reopened = self.saip._dispatch_open_package(None, path=str(root / "template.json"))
                try:
                    self.assertEqual(
                        reopened["inline_template"]["resolved_variables"], ["iccid", "puk1"],
                    )
                    again = self.saip._dispatch_save_package(
                        None,
                        session_id=reopened["session_id"],
                        output_path=str(root / "complete-again.der"),
                        format="der",
                    )
                    self.assertTrue(again["materialized"])
                    self.assertEqual((root / "complete-again.der").read_bytes(), der)
                finally:
                    self.manager.close(reopened["session_id"])

                varder_saved = self.saip._dispatch_save_package(
                    None, session_id=session_id, output_path=str(root / "template.varder"), format="varder",
                )
                self.assertTrue(varder_saved["session_source_rebound"])
                sidecar = Path(varder_saved["variable_sidecar_path"])
                self.assertEqual(sidecar, root / "template.variables.json")
                self.assertEqual(
                    read_inline_variable_sidecar(sidecar),
                    {"iccid": _ICCID_VALUE, "puk1": _PUK_VALUE},
                )
                reopened = self.saip._dispatch_open_package(None, path=str(root / "template.varder"))
                try:
                    self.assertTrue(reopened["inline_template"]["complete_export_ready"])
                    self.assertEqual(reopened["load_warnings"], [])
                finally:
                    self.manager.close(reopened["session_id"])

                asn_saved = self.saip._dispatch_save_package(
                    None,
                    session_id=session_id,
                    output_path=str(root / "complete.asn"),
                    format="asn1",
                    resolve_variables=True,
                )
                self.assertTrue(asn_saved["materialized"])
                asn_text = (root / "complete.asn").read_text(encoding="utf-8")
                self.assertNotIn("[iccidICCID10]", asn_text)
                self.assertIn(_ICCID_VALUE + "F", asn_text.upper())

                reset = self.saip._dispatch_reset_variable(None, session_id=session_id, name="iccid")
                self.assertTrue(reset["removed"])
                self.assertEqual(reset["inline_template"]["unresolved_variables"], ["iccid"])
                self.assertEqual(len(self.manager.claim(session_id)["inline_placeholder_records"]), 3)

                csv_path = root / "variables.csv"
                exported = self.saip._dispatch_export_variables_csv(
                    None, session_id=session_id, output_path=str(csv_path),
                )
                self.assertEqual(exported["exported_count"], 2)
                csv_text = csv_path.read_text(encoding="utf-8")
                self.assertNotIn(_PUK_VALUE, csv_text)
                csv_path.write_text(
                    "name,value\niccid," + _ICCID_VALUE + "\npuk1,\n",
                    encoding="utf-8",
                )
                imported = self.saip._dispatch_import_variables_csv(
                    None, session_id=session_id, input_path=str(csv_path),
                )
                self.assertEqual(imported["applied_count"], 1)
                self.assertEqual(imported["skipped_rows"][0]["reason"], "empty value")
                self.assertEqual(imported["inline_template"]["unresolved_variables"], [])
            finally:
                self.manager.close(session_id)


class MaterializeTemplateShellTests(unittest.TestCase):
    def setUp(self) -> None:
        if _REFERENCE_HEX.is_file() is False:
            self.skipTest("No tracked reference SAIP profile fixture")
        from Tools.ProfilePackage.shell import ProfilePackageShell

        self._workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.workspace_root)
        self.template_path = self.workspace_root / "tpl.varder"
        self.template_path.write_text(_template_text(), encoding="utf-8-sig")

    def tearDown(self) -> None:
        self._workspace.cleanup()

    def _run(self, arg: str) -> str:
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_materialize_template(arg)
        return captured.getvalue()

    def test_materializes_with_assignments_and_sidecar(self) -> None:
        output = self.workspace_root / "out.der"
        text = self._run(
            f'"{self.template_path}" "{output}" iccid={_ICCID_VALUE} puk1={_PUK_VALUE}'
        )
        der = output.read_bytes()
        self.assertIn(bytes.fromhex(_ICCID_VALUE + "F"), der)
        self.assertIn(bytes.fromhex(_PUK_VALUE), der)
        self.assertIn("iccid: 2 occurrence(s)", text)
        self.assertNotIn(_PUK_VALUE, text)

        write_inline_variable_sidecar(
            inline_variable_sidecar_path_for(self.template_path),
            {"iccid": _ICCID_VALUE, "puk1": _PUK_VALUE},
        )
        from_sidecar = self.workspace_root / "from-sidecar.der"
        self._run(f'"{self.template_path}" "{from_sidecar}"')
        self.assertEqual(from_sidecar.read_bytes(), der)

    def test_missing_value_and_plain_profile_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "puk1"):
            self._run(f'"{self.template_path}" "{self.workspace_root / "x.der"}" iccid={_ICCID_VALUE}')
        plain = self.workspace_root / "plain.hex"
        plain.write_text(_REFERENCE_HEX.read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no inline typed placeholders"):
            self._run(f'"{plain}" "{self.workspace_root / "y.der"}"')


if __name__ == "__main__":
    unittest.main()
