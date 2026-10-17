# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Placeholders declared in place: a literal typed into any hex field.

The JSON tab, the decoded editors, the raw body and record editors and the
header take ``{var:TYPE:len[:modifier]}`` where the bytes go, register the
occurrence, answer it from the test-value lists and flag it until a value
exists; the projections show the literal and a varder save writes it. The
typed bind of ``saip.add_variable_to_pe`` turns a dict field into a placeholder,
``saip.define_variable`` adds one to the universal list, and the validate run
reports an unresolved one as ``YRL-VAR-001``.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REFERENCE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")
_EF_ICCID_HEX = "98888011111111111111"
_ICCID_LITERAL = "{iccid:ICCID:10:nibble_swap}"


@unittest.skipUnless(_REFERENCE.is_file(), "reference test profile fixture is required")
class InlinePlaceholderAuthoringTests(unittest.TestCase):
    """A plain DER profile becomes a template through its editors."""

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self._actions = saip_actions
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.list_path = self.root / "universal.csv"
        self.list_path.write_text(
            "{ki:BINARY:16},00112233445566778899AABBCCDDEEFF\n{smsc:MSISDN:6:nibble_swap},\n",
            encoding="utf-8",
        )
        self._env = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path),
                "YGGDRASIM_RUNTIME_ROOT": str(self.root / "runtime"),
            },
        )
        self._env.start()
        self.sid = self._actions._dispatch_open_package(ctx=None, path=str(_REFERENCE))["session_id"]

    def tearDown(self) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        try:
            get_manager().close(self.sid)
        except Exception:
            pass
        self._env.stop()
        self._tmp.cleanup()

    def _handle(self) -> dict:
        from yggdrasim_common.gui_server.sessions import get_manager

        return get_manager().claim(self.sid)

    def _json_fill(self, section: str, field: str) -> tuple[list, list]:
        shown = self._actions._dispatch_show_file(
            ctx=None, session_id=self.sid, section_key=section, field_path=field
        )
        payload = shown["payload"]
        fill = next(item for item in payload if item[0] == "fillFileContent")
        return payload, fill

    def _apply_json(self, section: str, field: str, payload: list) -> dict:
        return self._actions._dispatch_update_file_decoded(
            ctx=None, session_id=self.sid, section_key=section, field_path=field, payload=payload
        )

    def test_json_tab_literal_registers_and_round_trips(self) -> None:
        payload, fill = self._json_fill("mf", "ef-iccid")
        self.assertEqual(fill[1], _EF_ICCID_HEX)
        fill[1] = _ICCID_LITERAL
        result = self._apply_json("mf", "ef-iccid", payload)
        added = result["placeholders"]["added"]
        self.assertEqual([item["literal"] for item in added], [_ICCID_LITERAL])
        self.assertFalse(added[0]["resolved"])
        self.assertEqual(result["inline_template"]["unresolved_variables"], ["iccid"])
        self.assertTrue(any(text.startswith("iccid: no value yet") for text in result["warnings"]))
        # The projection shows the literal, and applying it unchanged keeps
        # the same occurrence: this is what the JSON tab round-trips.
        payload2, fill2 = self._json_fill("mf", "ef-iccid")
        self.assertEqual(fill2[1], _ICCID_LITERAL)
        again = self._apply_json("mf", "ef-iccid", payload2)
        self.assertEqual(again["placeholders"]["reused"], 1)
        self.assertEqual(again["placeholders"]["added"], [])
        self.assertEqual(len(self._handle()["inline_placeholder_records"]), 1)
        # The Data tab shows the placeholder view, not a decoder on sentinel bytes.
        fields = self._actions._dispatch_list_decoded_fields(ctx=None, session_id=self.sid, section_key="mf")
        content = next(
            item
            for item in fields["fields"]
            if str(item.get("last_ef_key") or "") == "ef-iccid" and item["field_name"] == "fillFileContent"
        )
        self.assertEqual(content["editor_kind"], "readonly_json")
        self.assertIn("placeholder", str(content["model"]["title"]))

    def test_unset_placeholder_blocks_export_and_is_flagged_until_a_value_exists(self) -> None:
        payload, fill = self._json_fill("mf", "ef-iccid")
        fill[1] = _ICCID_LITERAL
        self._apply_json("mf", "ef-iccid", payload)
        findings = self._actions._dispatch_validate(ctx=None, session_id=self.sid)["findings"]
        var_findings = [item for item in findings if item["code"] == "YRL-VAR-001"]
        self.assertEqual(len(var_findings), 1)
        self.assertEqual(var_findings[0]["section_key"], "mf")
        self.assertIn(_ICCID_LITERAL, var_findings[0]["message"])
        with self.assertRaises(ValueError):
            self._actions._dispatch_save_package(
                ctx=None, session_id=self.sid, output_path=str(self.root / "out.der"), format="der", overwrite=True
            )
        template = self.root / "out.varder"
        self._actions._dispatch_save_package(
            ctx=None, session_id=self.sid, output_path=str(template), format="varder", overwrite=True
        )
        self.assertIn(_ICCID_LITERAL, template.read_text(encoding="utf-8-sig"))
        self._actions._dispatch_set_variable(ctx=None, session_id=self.sid, name="iccid", value="89880811111111111111")
        self._actions._dispatch_save_package(
            ctx=None, session_id=self.sid, output_path=str(self.root / "out.der"), format="der", overwrite=True
        )
        self.assertIn(bytes.fromhex(_EF_ICCID_HEX), (self.root / "out.der").read_bytes())
        findings = self._actions._dispatch_validate(ctx=None, session_id=self.sid)["findings"]
        self.assertEqual([item for item in findings if item["code"] == "YRL-VAR-001"], [])

    def test_a_list_entry_answers_a_new_occurrence_and_a_declaration_does_not(self) -> None:
        payload, fill = self._json_fill("mf", "ef-dir")
        hex_text = fill[1]
        fill[1] = "{ki:BINARY:16}" + hex_text[32:]
        result = self._apply_json("mf", "ef-dir", payload)
        self.assertTrue(result["placeholders"]["added"][0]["resolved"])
        self.assertEqual(result["inline_template"]["unresolved_variables"], [])
        rows = self._actions._dispatch_list_variables(ctx=None, session_id=self.sid)["variables"]
        ki = next(row for row in rows if row["name"] == "ki")
        self.assertEqual(ki["test_value_source"], "universal")
        self.assertEqual(ki["value"], "00112233445566778899AABBCCDDEEFF")
        # A declared-only entry lists the placeholder but answers nothing, and
        # an MSISDN without a value is flagged for the length byte it decides.
        payload2, fill2 = self._json_fill("usim", "ef-start-hfn")
        self.assertEqual(len(fill2[1]), 12)
        fill2[1] = "{smsc:MSISDN:6:nibble_swap}"
        declared = self._apply_json("usim", "ef-start-hfn", payload2)
        self.assertFalse(declared["placeholders"]["added"][0]["resolved"])
        self.assertEqual(declared["inline_template"]["unresolved_variables"], ["smsc"])
        self.assertTrue(
            any("length byte that counts it cannot be reconciled" in text for text in declared["warnings"])
        )
        rows = self._actions._dispatch_list_variables(ctx=None, session_id=self.sid)["variables"]
        smsc = next(row for row in rows if row["name"] == "smsc")
        self.assertEqual(smsc["status"], "BOUND_INLINE_UNRESOLVED")
        self.assertEqual(smsc["input_format"], "MSISDN")

    def test_removing_the_literal_drops_the_occurrence_and_its_values(self) -> None:
        payload, fill = self._json_fill("mf", "ef-iccid")
        fill[1] = _ICCID_LITERAL
        self._apply_json("mf", "ef-iccid", payload)
        self._actions._dispatch_set_variable(ctx=None, session_id=self.sid, name="iccid", value="89880811111111111111")
        payload2, fill2 = self._json_fill("mf", "ef-iccid")
        fill2[1] = _EF_ICCID_HEX
        result = self._apply_json("mf", "ef-iccid", payload2)
        self.assertEqual(result["placeholders"]["dropped"], [_ICCID_LITERAL])
        handle = self._handle()
        self.assertEqual(handle["inline_placeholder_records"], [])
        self.assertEqual(handle["applied_overrides"], {})
        self.assertEqual(result["inline_template"]["occurrence_count"], 0)

    def test_decoded_editor_takes_a_literal_and_refuses_one_an_editor_ignores(self) -> None:
        fields = self._actions._dispatch_list_decoded_fields(ctx=None, session_id=self.sid, section_key="mf")
        iccid = next(
            item
            for item in fields["fields"]
            if str(item.get("last_ef_key") or "") == "ef-iccid" and item["field_name"] == "fillFileContent"
        )
        # The ICCID editor's digits box takes the literal as the field's bytes.
        result = self._actions._dispatch_apply_decoded_edit(
            ctx=None,
            session_id=self.sid,
            section_key="mf",
            rel_path=iccid["rel_path"],
            field_name=iccid["field_name"],
            last_ef_key=iccid["last_ef_key"],
            editor_kind=iccid["editor_kind"],
            editor_payload={"iccid": _ICCID_LITERAL},
        )
        self.assertEqual([item["literal"] for item in result["placeholders"]["added"]], [_ICCID_LITERAL])
        usim = self._actions._dispatch_list_decoded_fields(ctx=None, session_id=self.sid, section_key="usim")
        hfn = next(
            item
            for item in usim["fields"]
            if str(item.get("last_ef_key") or "") == "ef-start-hfn" and item["field_name"] == "fillFileContent"
        )
        payload = dict(hfn["model"]["payload"])
        payload["hex"] = "{hfn:BINARY:6}"
        with self.assertRaises(ValueError) as refused:
            self._actions._dispatch_apply_decoded_edit(
                ctx=None,
                session_id=self.sid,
                section_key="usim",
                rel_path=hfn["rel_path"],
                field_name=hfn["field_name"],
                last_ef_key=hfn["last_ef_key"],
                editor_kind=hfn["editor_kind"],
                editor_payload=payload,
            )
        self.assertIn("did not reach the bytes", str(refused.exception))
        # The refused placeholder left no record behind.
        names = {record.variable_name for record in self._handle()["inline_placeholder_records"]}
        self.assertEqual(names, {"iccid"})

    def test_a_decoded_mirror_of_the_literal_is_withdrawn_quietly(self) -> None:
        import copy

        fields = self._actions._dispatch_list_decoded_fields(ctx=None, session_id=self.sid, section_key="mf")
        ef_dir = next(
            item
            for item in fields["fields"]
            if str(item.get("last_ef_key") or "") == "ef-dir" and item["field_name"] == "fillFileContent"
        )
        payload = copy.deepcopy(ef_dir["model"]["payload"])
        aid = payload["items"][0]["items"][0]
        aid["raw"] = "A000{aid:BINARY:5}" + aid["raw"][14:]
        # The decoded view mirrors the raw bytes; the copies never reach bytes.
        aid["decoded"]["aid"] = aid["raw"]
        aid["decoded"]["summary"] = aid["raw"] + " (RID A000000087)"
        result = self._actions._dispatch_apply_decoded_edit(
            ctx=None,
            session_id=self.sid,
            section_key="mf",
            rel_path=ef_dir["rel_path"],
            field_name=ef_dir["field_name"],
            last_ef_key=ef_dir["last_ef_key"],
            editor_kind=ef_dir["editor_kind"],
            editor_payload=payload,
        )
        self.assertEqual([item["literal"] for item in result["placeholders"]["added"]], ["{aid:BINARY:5}"])
        self.assertEqual(len(self._handle()["inline_placeholder_records"]), 1)
        self.assertEqual(result["inline_template"]["variables"], ["aid"])

    def test_body_record_and_header_editors_take_a_literal(self) -> None:
        body = self._actions._dispatch_update_file_content(
            ctx=None, session_id=self.sid, section_key="mf", field_path="ef-pl", hex_value="{lang:TEXT:2}"
        )
        self.assertEqual([item["literal"] for item in body["placeholders"]["added"]], ["{lang:TEXT:2}"])
        record = self._actions._dispatch_update_record_bytes(
            ctx=None,
            session_id=self.sid,
            section_key="telecom",
            field_path="ef-ext1",
            record_index=1,
            hex_value="{ext:BINARY:13}",
        )
        self.assertEqual([item["literal"] for item in record["placeholders"]["added"]], ["{ext:BINARY:13}"])
        header = self._actions._dispatch_update_profile_header_field(
            ctx=None, session_id=self.sid, field="iccid_hex", value="{iccid:ICCID:10}"
        )
        self.assertEqual([item["literal"] for item in header["placeholders"]["added"]], ["{iccid:ICCID:10}"])
        state = self._actions._dispatch_list_variables(ctx=None, session_id=self.sid)["inline_template"]
        self.assertEqual(sorted(state["variables"]), ["ext", "iccid", "lang"])
        # Digits typed over the header placeholder retire it.
        retired = self._actions._dispatch_update_profile_header_field(
            ctx=None, session_id=self.sid, field="iccid_digits", value="8988201234567890123"
        )
        self.assertEqual(retired["placeholders"]["dropped"], ["{iccid:ICCID:10}"])

    def test_header_syncs_follow_the_files_placeholders(self) -> None:
        from Tools.ProfilePackage.saip_connectivity_parameters import decode_connectivity_parameters
        from Tools.ProfilePackage.saip_profile_header_edit import ef_smsp_service_centre_bytes

        self.list_path.write_text(
            "{smsc:MSISDN:6:nibble_swap},550181107000\n{iccid:ICCID:10:nibble_swap},98888011111111111111\n",
            encoding="utf-8",
        )
        handle = self._handle()
        smsp, _sca = ef_smsp_service_centre_bytes(handle["decoded_document"])
        record = bytes(smsp.image)[: smsp.record_size].hex().upper()
        digits_start = (smsp.record_size - 28) * 2 + 13 * 2 + 4
        edited = record[:digits_start] + "{smsc:MSISDN:6:nibble_swap}" + record[digits_start + 12 :]
        # The USIM template row links to the generic-file-management body.
        self._actions._dispatch_update_record_bytes(
            ctx=None, session_id=self.sid, section_key="usim", field_path="ef-smsp", record_index=1, hex_value=edited
        )
        synced = self._actions._dispatch_update_profile_header_field(
            ctx=None, session_id=self.sid, field="smsc_from_ef_smsp", value=""
        )
        self.assertIn("{smsc:MSISDN:6:nibble_swap}", synced["summaries"][0])
        self.assertEqual(
            [(item["literal"], item["resolved"]) for item in synced["placeholders"]["added"]],
            [("{smsc:MSISDN:6:nibble_swap}", True)],
        )
        projection = self._actions._dispatch_show_pe(ctx=None, session_id=self.sid, pe_index=0)["decoded"]
        bearer = decode_connectivity_parameters(projection["connectivityParameters"])["bearers"][-1]
        self.assertEqual(bearer["dialing_number"]["digits"], "{smsc:MSISDN:6:nibble_swap}")
        # EF.ICCID: the header takes the variable in its own order, and the
        # value the file resolves to becomes the variable's typed value.
        payload, fill = self._json_fill("mf", "ef-iccid")
        fill[1] = _ICCID_LITERAL
        self._apply_json("mf", "ef-iccid", payload)
        followed = self._actions._dispatch_update_profile_header_field(
            ctx=None, session_id=self.sid, field="iccid_from_ef"
        )
        self.assertIn("follows EF.ICCID's variable as {iccid:ICCID:10}", followed["summaries"][0])
        self.assertEqual(followed["inline_template"]["unresolved_variables"], [])
        # The list's EF-form entry answers the header occurrence by name, re-encoded
        # in header order, so the follow needs no typed value of its own.
        self.assertEqual(self._handle()["applied_overrides"], {})
        self.assertEqual(self._handle()["inline_raw_values"].get("iccidICCID10"), "89880811111111111111")
        self._actions._dispatch_save_package(
            ctx=None, session_id=self.sid, output_path=str(self.root / "out.der"), format="der", overwrite=True
        )
        der = (self.root / "out.der").read_bytes()
        self.assertEqual(der.count(bytes.fromhex("550181107000")), 2)
        self.assertIn(bytes.fromhex("89880811111111111111"), der)
        self.assertIn(bytes.fromhex(_EF_ICCID_HEX), der)

    def test_a_dialing_number_placeholder_travels_through_the_connectivity_hex(self) -> None:
        from Tools.ProfilePackage.saip_connectivity_parameters import (
            decode_connectivity_parameters,
            encode_connectivity_parameters,
        )

        projection = self._actions._dispatch_show_pe(ctx=None, session_id=self.sid, pe_index=0)["decoded"]
        decoded = decode_connectivity_parameters(projection["connectivityParameters"])
        sms = next(item for item in decoded["bearers"] if item.get("bearer") == "sms")
        sms["dialing_number"]["digits"] = "{smsc:MSISDN:6:nibble_swap}"
        encoded = encode_connectivity_parameters(decoded["bearers"]) + decoded["trailing_hex"]
        self.assertIn("{smsc:MSISDN:6:nibble_swap}", encoded)
        result = self._actions._dispatch_update_profile_header_field(
            ctx=None, session_id=self.sid, field="connectivity_parameters_hex", value=encoded
        )
        self.assertEqual([item["literal"] for item in result["placeholders"]["added"]], ["{smsc:MSISDN:6:nibble_swap}"])
        self.assertEqual(result["inline_template"]["unresolved_variables"], ["smsc"])

    def test_tokenize_binds_a_typed_placeholder_and_keeps_the_bytes_as_its_value(self) -> None:
        result = self._actions._dispatch_add_variable_to_pe(
            ctx=None,
            session_id=self.sid,
            section_key="header",
            field_path="iccid",
            variable_name="iccid",
            placeholder_type="ICCID",
            save_to_list=True,
        )
        self.assertEqual(result["grammar"], "inline")
        self.assertEqual(result["literal"], "{iccid:ICCID:10}")
        self.assertEqual(result["value_source"], "typed")
        self.assertTrue(result["resolved"])
        self.assertEqual(self._handle()["applied_overrides"], {"iccid": "89880811111111111112"})
        self.assertIn("{iccid:ICCID:10},89880811111111111112", self.list_path.read_text(encoding="utf-8"))
        # The legacy grammar stays behind an empty placeholder type.
        legacy = self._actions._dispatch_add_variable_to_pe(
            ctx=None, session_id=self.sid, section_key="header", field_path="profileType", variable_name="PTYPE", encoding="utf8"
        )
        self.assertEqual(legacy["variable_name"], "PTYPE")
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=self.sid,
                section_key="header",
                field_path="profileType",
                variable_name="ptype",
                placeholder_type="TEXT",
            )

    def test_set_by_name_refuses_a_name_no_placeholder_carries(self) -> None:
        with self.assertRaises(ValueError) as refused:
            self._actions._dispatch_set_variable(ctx=None, session_id=self.sid, name="KI", value="00" * 16)
        self.assertIn("No placeholder named 'KI'", str(refused.exception))
        self.assertNotIn("KI", self._handle()["decoded_document"].get("__ygg_token_defs__") or {})

    def test_define_variable_writes_the_list_and_feeds_the_open_package(self) -> None:
        declared = self._actions._dispatch_define_variable(ctx=None, name="{opc:BINARY:16}")
        self.assertTrue(declared["declared_only"])
        self.assertIn("{opc:BINARY:16},\n", self.list_path.read_text(encoding="utf-8"))
        payload, fill = self._json_fill("mf", "ef-dir")
        fill[1] = "{opc:BINARY:16}" + fill[1][32:]
        result = self._apply_json("mf", "ef-dir", payload)
        self.assertEqual(result["inline_template"]["unresolved_variables"], ["opc"])
        defined = self._actions._dispatch_define_variable(
            ctx=None,
            variable="opc",
            placeholder_type="BINARY",
            byte_length=16,
            value="FF" * 16,
            session_id=self.sid,
        )
        self.assertEqual(defined["value_hex"], "FF" * 16)
        self.assertEqual(defined["inline_template"]["unresolved_variables"], [])
        typed = self._actions._dispatch_define_variable(ctx=None, name="{pin1:TEXT:4}", value="1234")
        self.assertEqual(typed["value_hex"], "31323334")
        with self.assertRaises(ValueError):
            self._actions._dispatch_define_variable(ctx=None, name="{x:BOGUS:4}")
        with self.assertRaises(ValueError):
            self._actions._dispatch_define_variable(ctx=None, name="{pin1:TEXT:4}", value="12345")

    def test_generate_test_profile_takes_the_lists_current_values_and_names_what_it_used(self) -> None:
        # A declared placeholder lands in EF.PL; nothing answers it yet.
        self.list_path.write_text("{lang:TEXT:2},\n", encoding="utf-8")
        self._actions._dispatch_update_file_content(
            ctx=None, session_id=self.sid, section_key="mf", field_path="ef-pl", hex_value="{lang:TEXT:2}"
        )
        with self.assertRaisesRegex(ValueError, r"No value for lang.*declared without a value"):
            self._actions._dispatch_generate_test_profile(
                ctx=None, session_id=self.sid, output_path=str(self.root / "t.der"), overwrite=True
            )
        # The list gains a value after the package opened: the run reads it now,
        # without an Apply test values round.
        self.list_path.write_text("{lang:TEXT:2},656E\n", encoding="utf-8")
        result = self._actions._dispatch_generate_test_profile(
            ctx=None, session_id=self.sid, output_path=str(self.root / "t.der"), overwrite=True
        )
        self.assertEqual(
            [(row["name"], row["value"], row["source"], row["literals"]) for row in result["values"]],
            [("lang", "656E", "universal.csv", ["{lang:TEXT:2}"])],
        )
        self.assertTrue(result["materialized"])
        self.assertEqual(result["inline_template"]["unresolved_variables"], [])
        self.assertIn("Generated DER test profile", result["summaries"][0])
        self.assertIn("1 from universal.csv", result["summaries"][1])
        generated = self._actions._dispatch_open_package(ctx=None, path=str(self.root / "t.der"))["session_id"]
        shown = self._actions._dispatch_show_file(
            ctx=None, session_id=generated, section_key="mf", field_path="ef-pl"
        )
        fill = next(item for item in shown["payload"] if item[0] == "fillFileContent")
        # EF.PL keeps its width: the two language bytes, then the file's filler.
        self.assertTrue(str(fill[1]).replace(" ", "").upper().startswith("656E"))
        # The session keeps its template, the panel row shows the value used.
        self.assertEqual(self._handle()["inline_raw_values"], {"langTEXT2": "656E"})
        rows = self._actions._dispatch_list_variables(ctx=None, session_id=self.sid)["variables"]
        lang = next(row for row in rows if row["name"] == "lang")
        self.assertEqual((lang["value"], lang["test_value_source"]), ("656E", "universal"))
        # A typed value wins, and a HEX target takes the ASCII hex of the DER.
        self._actions._dispatch_set_variable(ctx=None, session_id=self.sid, name="lang", value="sv")
        result = self._actions._dispatch_generate_test_profile(
            ctx=None, session_id=self.sid, output_path=str(self.root / "t.hex"), format="hex", overwrite=True
        )
        self.assertEqual([(row["value"], row["source"]) for row in result["values"]], [("sv", "typed")])
        self.assertEqual(result["format"], "hex")
        text = (self.root / "t.hex").read_text(encoding="utf-8").strip()
        self.assertTrue(text and set(text) <= set("0123456789ABCDEF"))
        self.assertNotIn("{lang", text)
        self.assertEqual(result["inline_template"]["occurrence_count"], 1)
        with self.assertRaises(ValueError):
            self._actions._dispatch_generate_test_profile(
                ctx=None, session_id=self.sid, output_path=str(self.root / "t.json"), format="json", overwrite=True
            )

    def test_action_is_registered(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

        registry = ensure_builtin_actions_loaded()
        spec = registry.get("saip.define_variable")
        self.assertIsNotNone(spec)
        self.assertIn("name", {field.name for field in spec.inputs})
        bind = registry.get("saip.add_variable_to_pe")
        self.assertIn("placeholder_type", {field.name for field in bind.inputs})
        generate = registry.get("saip.generate_test_profile")
        self.assertEqual(
            [field.name for field in generate.inputs],
            ["session_id", "output_path", "format", "overwrite"],
        )
        self.assertEqual(generate.title, "Generate test profile")


if __name__ == "__main__":
    unittest.main()
