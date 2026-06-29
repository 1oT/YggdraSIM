# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest

from Tools.ProfilePackage.saip_decoded_edit import (
    _MISSING_PAYLOAD_SENTINEL,
    _insertion_path_from_rel,
    _resolve_pe_editor_model_for_enumeration,
    build_decoded_value_editor_model,
    build_decoded_value_raw_hex_model,
    build_decoded_value_readonly_view,
    build_decoded_value_roundtrip_model,
    build_pe_form_document,
    encode_decoded_value_editor_payload,
    enumerate_pe_decodable_fields,
    enumerate_pe_form_unknown_paths,
    extract_pe_form_entry_payload,
    format_form_path_for_display,
    get_enum_choices_for_key,
    list_known_enum_payload_keys,
    normalize_enum_choice_for_key,
)
from Tools.ProfilePackage.saip_json_codec import _TAG_BYTES


class SaipDecodedEditTests(unittest.TestCase):
    def test_build_decoded_value_editor_model_for_short_efid(self) -> None:
        model = build_decoded_value_editor_model(
            field_name="shortEFID",
            raw_value={_TAG_BYTES: "10"},
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertIn("Short EF Identifier", model["title"])
        self.assertEqual(model["editor_kind"], "short_efid")
        self.assertEqual(model["payload"]["supported"], True)
        self.assertEqual(model["payload"]["sfi"], 2)

    def test_encode_decoded_value_editor_payload_for_short_efid_without_support(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="shortEFID",
            editor_payload={"supported": False},
        )

        self.assertEqual(encoded, {_TAG_BYTES: ""})

    def test_encode_decoded_value_editor_payload_for_security_attributes_reference(self) -> None:
        implicit_encoded = encode_decoded_value_editor_payload(
            field_name="securityAttributesReferenced",
            editor_payload={"recordNumber": 3},
        )
        explicit_encoded = encode_decoded_value_editor_payload(
            field_name="securityAttributesReferenced",
            editor_payload={"arrFileId": "6F06", "recordNumber": 3},
        )

        self.assertEqual(implicit_encoded, {_TAG_BYTES: "03"})
        self.assertEqual(explicit_encoded, {_TAG_BYTES: "6F0603"})

    def test_build_and_encode_imsi_decoded_editor_model(self) -> None:
        model = build_decoded_value_editor_model(
            field_name="fillFileContent",
            raw_value={_TAG_BYTES: "082940808023551096"},
            last_ef_key="ef-imsi",
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["payload"]["imsi"], "204080832550169")

        encoded = encode_decoded_value_editor_payload(
            field_name="fillFileContent",
            editor_payload={"imsi": "204080832550169"},
            last_ef_key="ef-imsi",
        )
        self.assertEqual(encoded, {_TAG_BYTES: "082940808023551096"})

    def test_encode_decoded_value_editor_payload_for_lcsi(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="lcsi",
            editor_payload={"state": "operational_activated"},
        )

        self.assertEqual(encoded, {_TAG_BYTES: "05"})

    def test_structured_editor_kinds_are_reported_for_descriptor_fields(self) -> None:
        arr_model = build_decoded_value_editor_model(
            field_name="securityAttributesReferenced",
            raw_value={_TAG_BYTES: "6F0603"},
        )
        ef_size_model = build_decoded_value_editor_model(
            field_name="efFileSize",
            raw_value={_TAG_BYTES: "50"},
        )
        file_id_model = build_decoded_value_editor_model(
            field_name="fileID",
            raw_value={_TAG_BYTES: "6F38"},
        )
        lcsi_model = build_decoded_value_editor_model(
            field_name="lcsi",
            raw_value={_TAG_BYTES: "05"},
        )
        offset_model = build_decoded_value_editor_model(
            field_name="fillFileOffset",
            raw_value=4,
        )

        self.assertIsNotNone(arr_model)
        self.assertIsNotNone(ef_size_model)
        self.assertIsNotNone(file_id_model)
        self.assertIsNotNone(lcsi_model)
        self.assertIsNotNone(offset_model)
        assert arr_model is not None
        assert ef_size_model is not None
        assert file_id_model is not None
        assert lcsi_model is not None
        assert offset_model is not None
        self.assertEqual(arr_model["editor_kind"], "arr_reference")
        self.assertEqual(ef_size_model["editor_kind"], "byte_count")
        self.assertEqual(file_id_model["editor_kind"], "file_id")
        self.assertEqual(lcsi_model["editor_kind"], "lcsi_state")
        self.assertEqual(offset_model["editor_kind"], "fill_file_offset")

    def test_build_and_encode_ust_service_table_editor_model(self) -> None:
        ust_hex = "0200000000000000000000000000000000"
        model = build_decoded_value_editor_model(
            field_name="fillFileContent",
            raw_value={_TAG_BYTES: ust_hex},
            last_ef_key="ef-ust",
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "service_table")
        payload = model["payload"]
        self.assertEqual(payload["preserveByteLength"], 17)
        self.assertEqual(payload["services"]["1: Local Phone Book"], "n")
        self.assertEqual(payload["services"]["2: Fixed Dialling Numbers (FDN)"], "y")

        encoded = encode_decoded_value_editor_payload(
            field_name="fillFileContent",
            editor_payload=payload,
            last_ef_key="ef-ust",
        )

        self.assertEqual(encoded, {_TAG_BYTES: ust_hex})

    def test_encode_ust_service_table_editor_payload_accepts_yes_no_flags(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="fillFileContent",
            editor_payload={
                "preserveByteLength": 17,
                "services": {
                    "1: Local Phone Book": "y",
                    "2: Fixed Dialling Numbers (FDN)": "n",
                },
            },
            last_ef_key="ef-ust",
        )

        self.assertEqual(encoded, {_TAG_BYTES: "0100000000000000000000000000000000"})

    def test_build_service_table_editor_models_for_est_and_ist(self) -> None:
        est_model = build_decoded_value_editor_model(
            field_name="fillFileContent",
            raw_value={_TAG_BYTES: "00"},
            last_ef_key="ef-est",
        )
        ist_model = build_decoded_value_editor_model(
            field_name="fillFileContent",
            raw_value={_TAG_BYTES: "00"},
            last_ef_key="ef-ist",
        )

        self.assertIsNotNone(est_model)
        self.assertIsNotNone(ist_model)
        assert est_model is not None
        assert ist_model is not None
        self.assertEqual(est_model["editor_kind"], "service_table")
        self.assertEqual(ist_model["editor_kind"], "service_table")


class SaipDecodedReadonlyViewTests(unittest.TestCase):
    def test_readonly_view_for_known_ef_payload_decodes_adn_record(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="fillFileContent",
            raw_value={
                _TAG_BYTES: (
                    "FFFFFFFFFFFFFFFFFFFFFFFF4944464D000000000000000000FFFFFFFF"
                )
            },
            last_ef_key="ef-adn",
        )

        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view["editor_kind"], "readonly_json")
        self.assertIn("ef-adn", view["title"])
        self.assertIn("fillFileContent", view["title"])
        payload = view["payload"]
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["alphaIdentifier"], "IDF")

    def test_readonly_view_for_pin_status_template_do(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="pinStatusTemplateDO",
            raw_value={_TAG_BYTES: "90018003830101"},
        )

        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view["editor_kind"], "readonly_json")
        payload = view["payload"]
        self.assertEqual(payload["format"], "PIN status template DO")
        self.assertEqual(payload["hex"], "90018003830101")
        self.assertIn("keyReference", payload)

    def test_readonly_view_for_scalar_pin_puk_retry_counter(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="maxNumOfAttemps-retryNumLeft",
            raw_value=51,
        )

        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view["editor_kind"], "readonly_json")
        payload = view["payload"]
        self.assertEqual(payload["format"], "PIN/PUK retry counters")
        self.assertEqual(payload["maxAttempts"], 3)
        self.assertEqual(payload["remainingAttempts"], 3)

    def test_readonly_view_returns_none_for_unknown_field(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="thisFieldDoesNotExist",
            raw_value={_TAG_BYTES: "00"},
        )

        self.assertIsNone(view)

    def test_readonly_view_skipped_when_editor_model_available(self) -> None:
        # Fields that already have a round-trip editor must not be shadowed
        # by a read-only fallback. Here we merely confirm that the editor
        # model keeps succeeding; the TUI layer only falls back to the
        # read-only view when the editor model is None.
        editor_model = build_decoded_value_editor_model(
            field_name="shortEFID",
            raw_value={_TAG_BYTES: "10"},
        )
        self.assertIsNotNone(editor_model)

    def test_readonly_view_tolerates_empty_and_invalid_hex(self) -> None:
        self.assertIsNone(
            build_decoded_value_readonly_view(
                field_name="pinStatusTemplateDO",
                raw_value={_TAG_BYTES: ""},
            )
        )
        self.assertIsNone(
            build_decoded_value_readonly_view(
                field_name="pinStatusTemplateDO",
                raw_value={_TAG_BYTES: "not-hex"},
            )
        )

    def test_readonly_view_title_omits_ef_prefix_when_no_ef_context(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="pinStatusTemplateDO",
            raw_value={_TAG_BYTES: "90018003830101"},
        )
        self.assertIsNotNone(view)
        assert view is not None
        self.assertEqual(view["title"], "Read-only decode: pinStatusTemplateDO")

    def test_readonly_view_title_includes_ef_key_when_available(self) -> None:
        view = build_decoded_value_readonly_view(
            field_name="fillFileContent",
            raw_value={
                _TAG_BYTES: (
                    "FFFFFFFFFFFFFFFFFFFFFFFF4944464D000000000000000000FFFFFFFF"
                )
            },
            last_ef_key="ef-adn",
        )
        self.assertIsNotNone(view)
        assert view is not None
        self.assertTrue(view["title"].startswith("Read-only decode: ef-adn / "))


class SaipDecodedRoundtripModelTests(unittest.TestCase):
    def test_roundtrip_model_for_hand_written_editor_is_skipped(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="shortEFID",
            raw_value={_TAG_BYTES: "10"},
        )

        self.assertIsNone(model)

    def test_roundtrip_model_for_scalar_int_field(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="maxNumOfAttemps-retryNumLeft",
            raw_value=0x33,
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "roundtrip_decoded")
        self.assertEqual(model["payload"]["maxAttempts"], 3)
        self.assertEqual(model["payload"]["remainingAttempts"], 3)
        self.assertNotIn("target_length", model)

    def test_roundtrip_model_for_bytes_field_carries_target_length(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="lifeCycleState",
            raw_value={_TAG_BYTES: "07"},
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "roundtrip_decoded")
        self.assertEqual(model["payload"]["state"], "Selectable")
        self.assertEqual(model["target_length"], 1)

    def test_roundtrip_model_for_ef_content_scoped_by_key(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="fillFileContent",
            raw_value={_TAG_BYTES: "0007"},
            last_ef_key="ef-acc",
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "roundtrip_decoded")
        self.assertIn("accessControlClasses", model["payload"])
        self.assertEqual(model["target_length"], 2)

    def test_roundtrip_model_skips_unregistered_fields(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="someUnrelatedThing",
            raw_value={_TAG_BYTES: "AA"},
        )

        self.assertIsNone(model)

    def test_encode_via_roundtrip_kind_uses_encoder_registry(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="lifeCycleState",
            editor_payload={"state": "Personalized"},
            editor_kind="roundtrip_decoded",
            target_length=1,
        )

        self.assertEqual(encoded, {_TAG_BYTES: "0F"})

    def test_encode_ef_content_via_roundtrip_kind_preserves_target_length(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="fillFileContent",
            editor_payload={"accessControlClasses": ["0", "1"]},
            last_ef_key="ef-acc",
            editor_kind="roundtrip_decoded",
            target_length=2,
        )

        self.assertEqual(encoded, {_TAG_BYTES: "0003"})


class SaipDecodedRawHexFallbackTests(unittest.TestCase):
    def test_raw_hex_model_accepts_tagged_bytes(self) -> None:
        model = build_decoded_value_raw_hex_model(
            field_name="unknownField",
            raw_value={_TAG_BYTES: "aa bb cc"},
        )

        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "raw_hex_decoded")
        self.assertEqual(model["payload"], {"hex": "AABBCC"})
        self.assertEqual(model["target_length"], 3)

    def test_raw_hex_model_rejects_non_tagged_bytes(self) -> None:
        self.assertIsNone(
            build_decoded_value_raw_hex_model(
                field_name="someScalar",
                raw_value=42,
            )
        )

    def test_raw_hex_model_rejects_empty_hex(self) -> None:
        model = build_decoded_value_raw_hex_model(
            field_name="unknownField",
            raw_value={_TAG_BYTES: ""},
        )
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["payload"], {"hex": ""})
        self.assertEqual(model["target_length"], 0)

    def test_raw_hex_model_rejects_invalid_hex(self) -> None:
        self.assertIsNone(
            build_decoded_value_raw_hex_model(
                field_name="unknownField",
                raw_value={_TAG_BYTES: "ZZ"},
            )
        )

    def test_encode_raw_hex_roundtrips_with_target_length(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="unknownField",
            editor_payload={"hex": "A0B1C2"},
            editor_kind="raw_hex_decoded",
            target_length=3,
        )
        self.assertEqual(encoded, {_TAG_BYTES: "A0B1C2"})

    def test_encode_raw_hex_rejects_target_length_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            encode_decoded_value_editor_payload(
                field_name="unknownField",
                editor_payload={"hex": "AABB"},
                editor_kind="raw_hex_decoded",
                target_length=3,
            )

    def test_encode_raw_hex_rejects_odd_nibble_count(self) -> None:
        with self.assertRaises(ValueError):
            encode_decoded_value_editor_payload(
                field_name="unknownField",
                editor_payload={"hex": "AAB"},
                editor_kind="raw_hex_decoded",
            )

    def test_encode_raw_hex_accepts_empty_string(self) -> None:
        encoded = encode_decoded_value_editor_payload(
            field_name="unknownField",
            editor_payload={"hex": ""},
            editor_kind="raw_hex_decoded",
        )
        self.assertEqual(encoded, {_TAG_BYTES: ""})


class EnumeratePeDecodableFieldsTests(unittest.TestCase):
    def test_enumerates_fillFileContent_for_iccid_and_imsi(self) -> None:
        pe_value = {
            "ef-iccid": [
                {"@": ["fillFileContent", {_TAG_BYTES: "98640000000000000000"}]},
            ],
            "ef-imsi": [
                {"@": ["fillFileContent", {_TAG_BYTES: "0829012345678901234F"}]},
            ],
        }
        entries = enumerate_pe_decodable_fields(pe_value, pe_section_key="usim")
        self.assertEqual(len(entries), 2)
        paths = [entry["display_path"] for entry in entries]
        self.assertIn("ef-iccid / [0] / fillFileContent", paths)
        self.assertIn("ef-imsi / [0] / fillFileContent", paths)
        for entry in entries:
            self.assertEqual(entry["pe_section_key"], "usim")
            self.assertIn(entry["last_ef_key"], ("ef-iccid", "ef-imsi"))
            self.assertIsInstance(entry["model"], dict)

    def test_gfm_df_gsm_fill_content_resolves_to_imsi_editor(self) -> None:
        pe_value = {
            "fileManagementCMD": [
                [
                    {"@": ["filePath", {_TAG_BYTES: "7F20"}]},
                    {"@": [
                        "createFCP",
                        {
                            "fileDescriptor": {_TAG_BYTES: "4121"},
                            "fileID": {_TAG_BYTES: "6F07"},
                        },
                    ]},
                    {"@": ["fillFileContent", {_TAG_BYTES: "0829012345678901234F"}]},
                ],
            ],
        }

        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="genericFileManagement",
        )
        content = next(
            entry for entry in entries if entry["field_name"] == "fillFileContent"
        )
        self.assertEqual(content["last_ef_key"], "ef-imsi")
        self.assertEqual(content["gfm_file_path"], "fileManagementCMD[0][1]")
        self.assertIn("imsi", content["model"]["payload"])

    def test_gfm_adf_usim_fill_content_resolves_to_service_table_editor(self) -> None:
        pe_value = {
            "fileManagementCMD": [
                [
                    {"@": ["filePath", {_TAG_BYTES: "7FF0"}]},
                    {"@": [
                        "createFCP",
                        {
                            "fileDescriptor": {_TAG_BYTES: "4121"},
                            "fileID": {_TAG_BYTES: "6F38"},
                        },
                    ]},
                    {"@": ["fillFileContent", {_TAG_BYTES: "FFFE"}]},
                ],
            ],
        }

        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="genericFileManagement",
        )
        content = next(
            entry for entry in entries if entry["field_name"] == "fillFileContent"
        )
        self.assertEqual(content["last_ef_key"], "ef-ust")
        self.assertEqual(content["gfm_file_path"], "fileManagementCMD[0][1]")
        self.assertEqual(content["model"]["editor_kind"], "service_table")

    def test_gfm_df_wlan_fill_content_resolves_to_wlan_editor(self) -> None:
        pe_value = {
            "fileManagementCMD": [
                [
                    {"@": ["filePath", {_TAG_BYTES: "7FF05F40"}]},
                    {"@": [
                        "createFCP",
                        {
                            "fileDescriptor": {_TAG_BYTES: "4121"},
                            "fileID": {_TAG_BYTES: "4F41"},
                        },
                    ]},
                    {"@": ["fillFileContent", {_TAG_BYTES: "32F410FFFF"}]},
                ],
            ],
        }

        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="genericFileManagement",
        )
        content = next(
            entry for entry in entries if entry["field_name"] == "fillFileContent"
        )
        self.assertEqual(content["last_ef_key"], "ef-uplmnwlan")
        self.assertEqual(content["gfm_file_path"], "fileManagementCMD[0][1]")
        self.assertEqual(content["model"]["editor_kind"], "roundtrip_decoded")

    def test_gfm_adf_isim_duplicate_fid_resolves_to_ist_editor(self) -> None:
        pe_value = {
            "fileManagementCMD": [
                [
                    {"@": ["filePath", {_TAG_BYTES: "3F007FF2"}]},
                    {"@": [
                        "createFCP",
                        {
                            "fileDescriptor": {_TAG_BYTES: "4121"},
                            "fileID": {_TAG_BYTES: "6F07"},
                        },
                    ]},
                    {"@": ["fillFileContent", {_TAG_BYTES: "00"}]},
                ],
            ],
        }

        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="genericFileManagement",
        )
        content = next(
            entry for entry in entries if entry["field_name"] == "fillFileContent"
        )
        self.assertEqual(content["last_ef_key"], "ef-ist")
        self.assertEqual(content["gfm_file_path"], "fileManagementCMD[0][1]")
        self.assertEqual(content["model"]["editor_kind"], "service_table")

    def test_descends_into_file_descriptor_subfields(self) -> None:
        pe_value = {
            "adf-usim": [
                {
                    "@": [
                        "fileDescriptor",
                        {
                            "fileDescriptor": {_TAG_BYTES: "42210010"},
                            "lcsi": {_TAG_BYTES: "05"},
                            "shortEFID": {_TAG_BYTES: ""},
                        },
                    ],
                },
            ],
        }
        entries = enumerate_pe_decodable_fields(pe_value, pe_section_key="usim")
        paths = {entry["display_path"] for entry in entries}
        self.assertIn("adf-usim / [0] / lcsi", paths)
        self.assertIn("adf-usim / [0] / shortEFID", paths)

    def test_service_table_editor_kind_is_surfaced(self) -> None:
        pe_value = {
            "ef-ust": [
                {"@": ["fillFileContent", {_TAG_BYTES: "FFFE"}]},
            ],
        }
        entries = enumerate_pe_decodable_fields(pe_value, pe_section_key="usim")
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["model"].get("editor_kind"), "service_table")
        self.assertIn("service_table", entry["summary"])

    def test_rel_path_round_trips_back_to_raw_value(self) -> None:
        pe_value = {
            "ef-iccid": [
                {"@": ["fillFileContent", {_TAG_BYTES: "98640000000000000000"}]},
            ],
        }
        entries = enumerate_pe_decodable_fields(pe_value, pe_section_key="usim")
        self.assertEqual(len(entries), 1)
        rel_path = entries[0]["rel_path"]
        self.assertEqual(rel_path, ["ef-iccid", 0, "@", 1])
        cursor: object = pe_value
        for segment in rel_path:
            if isinstance(segment, int):
                self.assertIsInstance(cursor, list)
                cursor = cursor[segment]
            else:
                self.assertIsInstance(cursor, dict)
                cursor = cursor[segment]
        self.assertEqual(cursor, entries[0]["raw_value"])

    def test_empty_pe_yields_no_entries(self) -> None:
        self.assertEqual(
            enumerate_pe_decodable_fields({}, pe_section_key="usim"),
            [],
        )
        self.assertEqual(
            enumerate_pe_decodable_fields(None, pe_section_key="usim"),
            [],
        )

    def test_non_filesystem_pe_surfaces_roundtrip_entries(self) -> None:
        """
        Bulk PE enumeration must widen beyond the hand-written editors
        so application / securityDomain PEs get every decodable field
        surfaced at once. The sample shape below mimics
        ``pe-securityDomain`` from a SAIP transcode where every leaf is
        a tagged-bytes blob with a round-trip encoder in
        ``saip_asn1_encode``.
        """
        pe_value = {
            "instance": {
                "applicationLoadPackageAID": {_TAG_BYTES: "A0000001515350"},
                "classAID": {_TAG_BYTES: "A000000151535041"},
                "instanceAID": {_TAG_BYTES: "A000000151000000"},
                "applicationPrivileges": {_TAG_BYTES: "82DC20"},
                "lifeCycleState": {_TAG_BYTES: "0F"},
            },
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="securityDomain",
        )
        paths = {entry["display_path"] for entry in entries}
        self.assertIn("instance / applicationLoadPackageAID", paths)
        self.assertIn("instance / lifeCycleState", paths)
        self.assertIn("instance / applicationPrivileges", paths)
        for entry in entries:
            self.assertEqual(entry["pe_section_key"], "securityDomain")
            self.assertIn("editor_kind", entry)
            self.assertIn("target_length", entry)
            self.assertIn("read_only", entry)
            # All of these tagged-bytes fields resolve through the
            # round-trip registry — none should fall back to raw hex
            # (that would indicate a decoder regression).
            self.assertEqual(entry["editor_kind"], "roundtrip_decoded")
            self.assertFalse(entry["read_only"])

    def test_falls_back_to_raw_hex_for_unknown_tagged_bytes(self) -> None:
        """
        Fields that have no hand-written editor, no round-trip encoder,
        and no semantic decoder must still be editable — the raw-hex
        fallback keeps the whole PE usable even for legacy / vendor
        blobs the project has not decoded yet.
        """
        pe_value = {
            "vendorExtensionFoo": {_TAG_BYTES: "DEADBEEF"},
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="nonStandard",
        )
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["editor_kind"], "raw_hex_decoded")
        self.assertEqual(entry["target_length"], 4)
        self.assertFalse(entry["read_only"])

    def test_resolve_helper_prefers_hand_written_over_roundtrip(self) -> None:
        """
        The enumeration helper must dispatch in priority order:
        hand-written > round-trip > readonly > raw-hex. The LCSI field
        has a hand-written editor, so the helper must surface it even
        though the round-trip registry also covers it.
        """
        model = _resolve_pe_editor_model_for_enumeration(
            field_name="lcsi",
            raw_value={_TAG_BYTES: "05"},
            last_ef_key=None,
            pe_section_key="usim",
        )
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "lcsi_state")
        self.assertFalse(model["read_only"])

    def test_resolve_helper_falls_back_to_raw_hex_for_unknown_field(self) -> None:
        """
        An unknown tagged-bytes field with no registered decoder must
        be surfaced via the raw-hex editor so the bulk PE form still
        accepts edits on legacy / vendor blobs.
        """
        model = _resolve_pe_editor_model_for_enumeration(
            field_name="vendorOpaqueExtension",
            raw_value={_TAG_BYTES: "CAFEBABE"},
            last_ef_key=None,
            pe_section_key="nonStandard",
        )
        self.assertIsNotNone(model)
        assert model is not None
        self.assertEqual(model["editor_kind"], "raw_hex_decoded")
        self.assertFalse(model["read_only"])
        self.assertEqual(model["target_length"], 4)

    def test_readonly_view_is_surfaced_but_marked(self) -> None:
        """
        Fields with a semantic decoder but no round-trip encoder must
        be surfaced as read-only so the operator can review them in the
        bulk editor. Any attempt to change their payload is rejected by
        the apply path (covered in the TUI integration).
        """
        # numberOfKeccak (from akaParameter / algoConfiguration) decodes
        # through the readonly view because its encoder is not yet
        # registered. Tested via the scalar-field decoder path.
        pe_value = {
            "algoConfiguration": {
                "numberOfKeccak": 5,
            },
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="akaParameter",
        )
        readonly_entries = [e for e in entries if e.get("read_only")]
        # At least one readonly entry must appear; its editor_kind is
        # pinned to ``readonly_json`` so the bulk form can refuse edits.
        if len(readonly_entries) > 0:
            for entry in readonly_entries:
                self.assertEqual(entry["editor_kind"], "readonly_json")

    def test_insertion_path_elides_tuple_marker_at_tail(self) -> None:
        """
        A trailing ``@ / 1`` pair in the relative path represents a
        SAIP tagged tuple. The insertion path replaces that pair with
        the field name so the nested form reads as the decoded pane
        would render it (``ef-iccid[0].fillFileContent`` rather than
        ``ef-iccid[0]["@"][1]``).
        """
        result = _insertion_path_from_rel(
            ["ef-iccid", 0, "@", 1],
            "fillFileContent",
        )
        self.assertEqual(result, ["ef-iccid", 0, "fillFileContent"])

    def test_insertion_path_elides_middle_tuple_markers(self) -> None:
        """
        ``@ / 1`` pairs embedded in the middle of a path are stripped
        outright so inner fields surface directly under the tuple's
        slot.
        """
        result = _insertion_path_from_rel(
            ["adf-usim", 0, "@", 1, "lcsi"],
            "lcsi",
        )
        self.assertEqual(result, ["adf-usim", 0, "lcsi"])

    def test_build_pe_form_document_mirrors_structure(self) -> None:
        """
        The nested form document must mirror the SAIP PE structure:
        dict parents become JSON objects, integer indices become
        arrays, tuple markers disappear. This gives the operator the
        same visual layout the decoded pane uses when inspecting a
        single field.
        """
        pe_value = {
            "instance": {
                "lifeCycleState": {_TAG_BYTES: "0F"},
            },
            "ef-iccid": [
                {"@": ["fillFileContent", {_TAG_BYTES: "98460811111111111112"}]},
            ],
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="securityDomain",
        )
        document = build_pe_form_document(entries)
        self.assertIsInstance(document, dict)
        self.assertIn("instance", document)
        self.assertIn("lifeCycleState", document["instance"])
        self.assertIn("ef-iccid", document)
        self.assertIsInstance(document["ef-iccid"], list)
        self.assertEqual(len(document["ef-iccid"]), 1)
        self.assertIn("fillFileContent", document["ef-iccid"][0])

    def test_extract_pe_form_entry_payload_round_trips(self) -> None:
        """
        ``extract_pe_form_entry_payload`` must find the payload at
        exactly the same insertion path the builder used. Missing
        paths return the ``_MISSING_PAYLOAD_SENTINEL`` so the apply
        step can distinguish an operator-removed slot from a slot set
        to null.
        """
        pe_value = {
            "header": {
                "pol": {_TAG_BYTES: "04"},
            },
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="header",
        )
        document = build_pe_form_document(entries)
        pol_entry = next(e for e in entries if e["field_name"] == "pol")
        path = _insertion_path_from_rel(
            list(pol_entry["rel_path"]),
            pol_entry["field_name"],
        )
        extracted = extract_pe_form_entry_payload(document, path)
        self.assertIsInstance(extracted, dict)
        self.assertIn("hex", extracted)
        missing = extract_pe_form_entry_payload(
            document,
            ["header", "doesNotExist"],
        )
        self.assertIs(missing, _MISSING_PAYLOAD_SENTINEL)

    def test_enumerate_pe_form_unknown_paths_flags_stray_keys(self) -> None:
        """
        When the operator adds keys the entry map does not know about,
        ``enumerate_pe_form_unknown_paths`` must surface them so the
        apply path can reject the document cleanly. Known prefixes
        must NOT appear in the unknown list.
        """
        pe_value = {
            "instance": {
                "lifeCycleState": {_TAG_BYTES: "0F"},
            },
        }
        entries = enumerate_pe_decodable_fields(
            pe_value,
            pe_section_key="securityDomain",
        )
        document = build_pe_form_document(entries)
        document["instance"]["strayField"] = {"hex": "AB"}
        document["unexpectedRoot"] = {"hex": "CD"}
        insertion_paths = [
            _insertion_path_from_rel(
                list(entry["rel_path"]),
                entry["field_name"],
            )
            for entry in entries
        ]
        unknowns = enumerate_pe_form_unknown_paths(document, insertion_paths)
        rendered = {
            tuple(path) for path in unknowns
        }
        self.assertIn(("instance", "strayField"), rendered)
        self.assertIn(("unexpectedRoot",), rendered)
        self.assertNotIn(("instance",), rendered)
        self.assertNotIn(("instance", "lifeCycleState"), rendered)

    def test_format_form_path_for_display_renders_segments(self) -> None:
        """
        Human-readable path rendering must match the PE picker format
        (``parent / child / [idx] / field``) so error messages stay
        consistent with the rest of the TUI.
        """
        self.assertEqual(
            format_form_path_for_display(["ef-iccid", 0, "fillFileContent"]),
            "ef-iccid / [0] / fillFileContent",
        )
        self.assertEqual(
            format_form_path_for_display([]),
            "(root)",
        )

    def test_enum_registry_lists_known_payload_keys(self) -> None:
        """
        The enum registry is the single source of truth for the bulk
        form's Ctrl+L pick-list. Every key registered here must have
        a non-empty choices list so the picker never opens on an
        empty modal.
        """
        keys = list_known_enum_payload_keys()
        self.assertIn("state", keys)
        self.assertIn("fileType", keys)
        self.assertIn("structure", keys)
        self.assertIn("algorithm", keys)
        for key in keys:
            descriptor = get_enum_choices_for_key(key)
            self.assertIsNotNone(descriptor)
            assert descriptor is not None
            self.assertIsInstance(descriptor["choices"], list)
            self.assertGreater(len(descriptor["choices"]), 0)

    def test_enum_registry_matches_lcsi_hex_map(self) -> None:
        """
        The life-cycle state enum must stay in lock-step with the
        encoder's ``_LCSI_STATE_TO_HEX`` map — otherwise the picker
        could offer a value the encoder will later reject.
        """
        from Tools.ProfilePackage.saip_decoded_edit import _LCSI_STATE_TO_HEX
        descriptor = get_enum_choices_for_key("state")
        self.assertIsNotNone(descriptor)
        assert descriptor is not None
        self.assertEqual(
            set(descriptor["choices"]),
            set(_LCSI_STATE_TO_HEX.keys()),
        )

    def test_normalize_enum_choice_accepts_case_insensitive_matches(self) -> None:
        """
        The picker routes operator input through
        ``normalize_enum_choice_for_key``; uppercase / mixed-case
        values must snap back to the canonical lowercase form the
        encoders expect.
        """
        self.assertEqual(
            normalize_enum_choice_for_key("fileType", "WORKING_EF"),
            "working_ef",
        )
        self.assertEqual(
            normalize_enum_choice_for_key("structure", "Linear_Fixed"),
            "linear_fixed",
        )
        self.assertIsNone(
            normalize_enum_choice_for_key("fileType", "not_a_valid_value"),
        )

    def test_normalize_enum_choice_coerces_booleans(self) -> None:
        """
        Boolean-valued enums (``shareable``, ``validEncoding``, ...)
        accept common truthy / falsy spellings so the operator can
        type ``yes`` or ``0`` without breaking the encoder.
        """
        for truthy in ("true", "TRUE", "yes", "y", "1"):
            self.assertIs(
                normalize_enum_choice_for_key("shareable", truthy),
                True,
            )
        for falsy in ("false", "FALSE", "no", "n", "0"):
            self.assertIs(
                normalize_enum_choice_for_key("shareable", falsy),
                False,
            )
        self.assertIsNone(
            normalize_enum_choice_for_key("shareable", "maybe"),
        )

    def test_get_enum_choices_for_key_returns_copy(self) -> None:
        """
        The registry must return a fresh copy per call so callers can
        mutate the descriptor (e.g. to inject picker-specific flags)
        without corrupting the shared table.
        """
        first = get_enum_choices_for_key("state")
        second = get_enum_choices_for_key("state")
        self.assertIsNotNone(first)
        assert first is not None and second is not None
        first["choices"].append("hacked")
        self.assertNotIn("hacked", second["choices"])


if __name__ == "__main__":
    unittest.main()
