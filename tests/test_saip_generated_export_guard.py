# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import (
    assert_concrete_export_allowed,
    dejsonify_document,
    jsonify_document,
)
from yggdrasim_common.gui_server.actions import saip as saip_actions
from yggdrasim_common.gui_server.sessions import get_manager

_TEST_SCOPE = "TEST_GENERATED_AUTHORING"


def _guarded_document() -> dict:
    from Tools.ProfilePackage.saip_json_codec import (
        build_decoded_document_from_sequence,
    )

    document = build_decoded_document_from_sequence(
        saip_actions._new_empty_pes(ver_major=3, ver_minor=3),
    )
    document["__ygg_generation__"] = {
        "schema_version": "test/v1",
        "generation_scope": _TEST_SCOPE,
        "completeness": "PARTIAL_AUTHORING_ARTIFACT",
        "unresolved_requirements": ["ICCID", "KEYS"],
        "concrete_export_allowed": False,
        "export_block_reason": "test artifact",
    }
    document["__ygg_generation_lock__"] = {
        "schema_version": "test-lock/v1",
        "generation_scope": _TEST_SCOPE,
        "completeness": "PARTIAL_AUTHORING_ARTIFACT",
        "concrete_export_allowed": False,
    }
    return document


def _filesystem_guarded_document(
    middle_menu_ids: tuple[str, ...] = (),
) -> dict:
    from Tools.ProfilePackage.saip_profile_scaffold import (
        build_scaffold_profile_document_from_menu_ids,
    )

    document = build_scaffold_profile_document_from_menu_ids(
        "test-filesystem-guard",
        ("header", "mf", *middle_menu_ids, "end"),
        Path(__file__).resolve().parents[1],
    )
    markers = _guarded_document()
    generation = dict(markers["__ygg_generation__"])
    generation_lock = dict(markers["__ygg_generation_lock__"])
    generation["generation_scope"] = "FILESYSTEM_ONLY"
    generation_lock["generation_scope"] = "FILESYSTEM_ONLY"
    document["__ygg_generation__"] = generation
    document["__ygg_generation_lock__"] = generation_lock
    return document


class GenerationMetadataCodecTests(unittest.TestCase):
    def test_ordinary_ungenerated_document_keeps_concrete_export_behavior(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
        )

        document = build_decoded_document_from_sequence(
            saip_actions._new_empty_pes(ver_major=3, ver_minor=3),
        )

        self.assertIsNone(assert_concrete_export_allowed(document))

    def test_generation_metadata_survives_tagged_json_roundtrip(self) -> None:
        document = _guarded_document()

        tagged = jsonify_document(document)
        reopened = dejsonify_document(json.loads(json.dumps(tagged)))

        self.assertEqual(
            reopened["__ygg_generation__"],
            document["__ygg_generation__"],
        )
        self.assertEqual(
            reopened["__ygg_generation_lock__"],
            document["__ygg_generation_lock__"],
        )

    def test_concrete_export_guard_reports_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, _TEST_SCOPE):
            assert_concrete_export_allowed(_guarded_document())

    def test_partial_marker_is_one_way_even_if_boolean_is_mutated(self) -> None:
        document = _guarded_document()
        document["__ygg_generation__"]["concrete_export_allowed"] = True

        with self.assertRaisesRegex(ValueError, _TEST_SCOPE):
            assert_concrete_export_allowed(document)

    def test_redundant_lock_blocks_when_generation_envelope_is_removed(self) -> None:
        document = _guarded_document()
        del document["__ygg_generation__"]

        with self.assertRaisesRegex(ValueError, _TEST_SCOPE):
            assert_concrete_export_allowed(document)

    def test_coordinated_scope_edits_do_not_unlock_concrete_export(self) -> None:
        document = _guarded_document()
        for marker_name in ("__ygg_generation__", "__ygg_generation_lock__"):
            document[marker_name]["generation_scope"] = "FILESYSTEM_ONLY"
            document[marker_name]["concrete_export_allowed"] = True

        with self.assertRaisesRegex(ValueError, "FILESYSTEM_ONLY"):
            assert_concrete_export_allowed(document)


class GeneratedSessionGuardTests(unittest.TestCase):
    def test_generated_handoff_requires_intact_envelope_and_lock(self) -> None:
        document = _guarded_document()
        del document["__ygg_generation_lock__"]

        with self.assertRaisesRegex(ValueError, "generation envelope and generation lock"):
            saip_actions.open_saip_document_session(document)

    def test_json_save_is_allowed_but_der_and_single_pe_export_are_blocked(self) -> None:
        result = saip_actions.open_saip_document_session(
            _guarded_document(),
            file_name="guarded.json",
        )
        sid = result["session_id"]
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                json_path = root / "guarded.json"
                der_path = root / "guarded.der"
                hex_path = root / "guarded.hex"
                asn_path = root / "guarded.asn"
                pe_path = root / "header.der"
                pe_hex_path = root / "header.hex"

                saved = saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=sid,
                    output_path=str(json_path),
                    format="json",
                )
                self.assertEqual(saved["format"], "json")
                self.assertTrue(json_path.is_file())

                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=sid,
                        output_path=str(der_path),
                        format="der",
                    )
                self.assertFalse(der_path.exists())

                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=sid,
                        output_path=str(hex_path),
                        format="hex",
                    )
                self.assertFalse(hex_path.exists())

                with self.assertRaisesRegex(
                    ValueError,
                    "ASN.1 value-notation export is blocked",
                ):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=sid,
                        output_path=str(asn_path),
                        format="asn1",
                    )
                self.assertFalse(asn_path.exists())

                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_export_pe(
                        ctx=None,
                        session_id=sid,
                        pe_index=0,
                        output_path=str(pe_path),
                        format="der",
                    )
                self.assertFalse(pe_path.exists())

                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_export_pe(
                        ctx=None,
                        session_id=sid,
                        pe_index=0,
                        output_path=str(pe_hex_path),
                        format="hex",
                    )
                self.assertFalse(pe_hex_path.exists())

                shown = saip_actions._dispatch_show_pe(
                    ctx=None,
                    session_id=sid,
                    pe_index=0,
                )
                self.assertEqual(shown["pe_hex"], "")
                self.assertEqual(shown["pe_size"], 0)
                self.assertTrue(shown["pe_hex_export_blocked"])
        finally:
            get_manager().close(sid)

    def test_batch_personalization_rejects_guarded_tagged_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            template_path = root / "guarded-template.json"
            data_path = root / "records.csv"
            output_dir = root / "output"
            template_path.write_text(
                json.dumps(jsonify_document(_guarded_document())),
                encoding="utf-8",
            )
            data_path.write_text("ICCID\n8901000000000000000\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, _TEST_SCOPE):
                saip_actions._dispatch_batch_personalize(
                    ctx=None,
                    template_path=str(template_path),
                    data_path=str(data_path),
                    output_dir=str(output_dir),
                )
            self.assertFalse(output_dir.exists())

    def test_refresh_and_json_reopen_keep_server_side_scope_lock(self) -> None:
        result = saip_actions.open_saip_document_session(_guarded_document())
        sid = result["session_id"]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "guarded.json"
            try:
                handle = get_manager().claim(sid)
                saip_actions._refresh_decoded_document(handle)
                self.assertIn("__ygg_generation__", handle["decoded_document"])
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=sid,
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(sid)

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                self.assertEqual(reopened["scope_lock"], _TEST_SCOPE)
                self.assertFalse(reopened["export_guard"]["concrete_export_allowed"])
            finally:
                get_manager().close(reopened["session_id"])

    def test_removing_both_primary_markers_stays_blocked_via_provenance(self) -> None:
        created = saip_actions.open_saip_document_session(_guarded_document())
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "guarded-both-markers-removed.json"
            try:
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=created["session_id"],
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(created["session_id"])

            tagged = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("__ygg_generation_provenance__", tagged)
            del tagged["__ygg_generation__"]
            del tagged["__ygg_generation_lock__"]
            path.write_text(json.dumps(tagged), encoding="utf-8")

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                self.assertEqual(reopened["scope_lock"], _TEST_SCOPE)
                self.assertEqual(
                    reopened["export_guard"]["integrity_state"],
                    "UNTRUSTED_PARTIAL",
                )
                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=reopened["session_id"],
                        output_path=str(root / "must-not-exist.der"),
                        format="der",
                    )
                with self.assertRaisesRegex(ValueError, "UNTRUSTED_PARTIAL"):
                    saip_actions._dispatch_add_pe(
                        ctx=None,
                        session_id=reopened["session_id"],
                        pe_type="pinCodes",
                        insert_at=1,
                    )
            finally:
                get_manager().close(reopened["session_id"])

    def test_coordinated_scope_and_completeness_edits_cannot_widen_scope(self) -> None:
        created = saip_actions.open_saip_document_session(_filesystem_guarded_document())
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "guarded-coordinated-edits.json"
            try:
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=created["session_id"],
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(created["session_id"])

            tagged = json.loads(path.read_text(encoding="utf-8"))
            for marker_name in (
                "__ygg_generation__",
                "__ygg_generation_lock__",
            ):
                tagged[marker_name]["generation_scope"] = "BROADER_AUTHORING"
                tagged[marker_name]["completeness"] = "COMPLETE"
            path.write_text(json.dumps(tagged), encoding="utf-8")

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                self.assertEqual(reopened["scope_lock"], "FILESYSTEM_ONLY")
                self.assertEqual(
                    reopened["export_guard"]["integrity_state"],
                    "UNTRUSTED_PARTIAL",
                )
                with self.assertRaisesRegex(ValueError, "UNTRUSTED_PARTIAL"):
                    saip_actions._dispatch_add_pe(
                        ctx=None,
                        session_id=reopened["session_id"],
                        pe_type="pinCodes",
                        insert_at=2,
                    )
            finally:
                get_manager().close(reopened["session_id"])

    def test_generated_json_cannot_overwrite_excel_workbook_path(self) -> None:
        created = saip_actions.open_saip_document_session(_guarded_document())
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.xlsx"
            original = b"PK\x03\x04original-workbook"
            source.write_bytes(original)
            try:
                with self.assertRaisesRegex(ValueError, "Excel workbook path"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=created["session_id"],
                        output_path=str(source),
                        format="json",
                        overwrite=True,
                    )
                self.assertEqual(source.read_bytes(), original)
            finally:
                get_manager().close(created["session_id"])

    def test_reopen_stays_blocked_if_generation_envelope_was_removed(self) -> None:
        result = saip_actions.open_saip_document_session(_guarded_document())
        sid = result["session_id"]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "guarded-tampered.json"
            try:
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=sid,
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(sid)

            tagged = json.loads(path.read_text(encoding="utf-8"))
            del tagged["__ygg_generation__"]
            path.write_text(json.dumps(tagged), encoding="utf-8")

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                self.assertEqual(reopened["scope_lock"], _TEST_SCOPE)
                self.assertEqual(
                    reopened["export_guard"]["integrity_state"],
                    "UNTRUSTED_PARTIAL",
                )
                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=reopened["session_id"],
                        output_path=str(path.with_suffix(".der")),
                        format="der",
                    )
                with self.assertRaisesRegex(ValueError, "UNTRUSTED_PARTIAL"):
                    saip_actions._dispatch_add_pe(
                        ctx=None,
                        session_id=reopened["session_id"],
                        pe_type="mf",
                        insert_at=1,
                    )
                with self.assertRaisesRegex(ValueError, "UNTRUSTED_PARTIAL"):
                    saip_actions.SET_SECURITY_DOMAIN_INSTANCE_FIELD_SPEC.dispatcher(
                        None,
                        session_id=reopened["session_id"],
                        pe_index=0,
                        field="applicationPrivileges",
                        value="000000",
                    )
            finally:
                get_manager().close(reopened["session_id"])

    def test_revert_cannot_downgrade_an_existing_server_side_lock(self) -> None:
        created = saip_actions.open_saip_document_session(_guarded_document())
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "guarded-live-revert.json"
            try:
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=created["session_id"],
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(created["session_id"])

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                tagged = json.loads(path.read_text(encoding="utf-8"))
                del tagged["__ygg_generation__"]
                del tagged["__ygg_generation_lock__"]
                path.write_text(json.dumps(tagged), encoding="utf-8")

                saip_actions._dispatch_revert_changes(
                    ctx=None,
                    session_id=reopened["session_id"],
                )
                handle = get_manager().claim(reopened["session_id"])
                self.assertEqual(handle["scope_lock"], _TEST_SCOPE)
                self.assertFalse(handle["export_policy"]["concrete_export_allowed"])
                shown = saip_actions._dispatch_show_pe(
                    ctx=None,
                    session_id=reopened["session_id"],
                    pe_index=0,
                )
                self.assertEqual(shown["pe_hex"], "")
                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=reopened["session_id"],
                        output_path=str(path.with_suffix(".der")),
                        format="der",
                    )
            finally:
                get_manager().close(reopened["session_id"])

    def test_mismatched_redundant_markers_reject_generated_handoff(self) -> None:
        document = _guarded_document()
        document["__ygg_generation_lock__"]["generation_scope"] = "FILESYSTEM_ONLY"

        with self.assertRaisesRegex(ValueError, "generation envelope and generation lock"):
            saip_actions.open_saip_document_session(document)

    def test_filesystem_scope_rejects_security_domain_pe_addition(self) -> None:
        result = saip_actions.open_saip_document_session(_filesystem_guarded_document())
        try:
            with self.assertRaisesRegex(ValueError, "outside the FILESYSTEM_ONLY"):
                saip_actions._dispatch_add_pe(
                    ctx=None,
                    session_id=result["session_id"],
                    pe_type="securityDomain",
                    insert_at=1,
                    preset="mno_sd_scp_all",
                )
        finally:
            get_manager().close(result["session_id"])

    def test_filesystem_scope_rejects_disallowed_initial_sequence(self) -> None:
        from Tools.ProfilePackage.saip_profile_scaffold import (
            build_scaffold_profile_document_from_menu_ids,
        )

        document = build_scaffold_profile_document_from_menu_ids(
            "test-filesystem-forgery",
            ("header", "mf", "securityDomain", "end"),
            Path(__file__).resolve().parents[1],
        )
        markers = _guarded_document()
        generation = dict(markers["__ygg_generation__"])
        generation_lock = dict(markers["__ygg_generation_lock__"])
        generation["generation_scope"] = "FILESYSTEM_ONLY"
        generation_lock["generation_scope"] = "FILESYSTEM_ONLY"
        document["__ygg_generation__"] = generation
        document["__ygg_generation_lock__"] = generation_lock

        with self.assertRaisesRegex(ValueError, "outside the FILESYSTEM_ONLY"):
            saip_actions.open_saip_document_session(document)

    def test_filesystem_scope_accepts_complete_filesystem_pe_matrix(self) -> None:
        allowed = {
            "header",
            "end",
            "mf",
            "telecom",
            "cd",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "csim",
            "opt-csim",
            "phonebook",
            "gsm-access",
            "df-5gs",
            "eap",
            "df-saip",
            "df-snpn",
            "df-5gprose",
            "iot",
            "opt-iot",
            "genericFileManagement",
        }
        for pe_type in sorted(allowed):
            with self.subTest(pe_type=pe_type):
                saip_actions._assert_pe_type_allowed_for_scope(
                    "FILESYSTEM_ONLY",
                    pe_type,
                )

        for pe_type in (
            "pinCodes",
            "pukCodes",
            "akaParameter",
            "securityDomain",
            "securityDomain_ssd",
            "application",
            "rfm",
            "cdmaParameter",
        ):
            with self.subTest(pe_type=pe_type):
                with self.assertRaisesRegex(ValueError, "outside the FILESYSTEM_ONLY"):
                    saip_actions._assert_pe_type_allowed_for_scope(
                        "FILESYSTEM_ONLY",
                        pe_type,
                    )

    def test_generated_sequence_rejects_duplicate_anchor_additions(self) -> None:
        result = saip_actions.open_saip_document_session(_filesystem_guarded_document())
        try:
            for pe_type in ("header", "end"):
                with self.subTest(pe_type=pe_type):
                    with self.assertRaisesRegex(ValueError, "sequence anchors"):
                        saip_actions._dispatch_add_pe(
                            ctx=None,
                            session_id=result["session_id"],
                            pe_type=pe_type,
                            insert_at=1,
                        )
        finally:
            get_manager().close(result["session_id"])

    def test_filesystem_scope_keeps_single_mf_after_header(self) -> None:
        result = saip_actions.open_saip_document_session(_filesystem_guarded_document(("telecom",)))
        try:
            with self.assertRaisesRegex(ValueError, "exactly one PE-MF"):
                saip_actions._dispatch_add_pe(
                    ctx=None,
                    session_id=result["session_id"],
                    pe_type="mf",
                    insert_at=2,
                )
            with self.assertRaisesRegex(ValueError, "exactly one PE-MF"):
                saip_actions._dispatch_delete_pe(
                    ctx=None,
                    session_id=result["session_id"],
                    pe_index=1,
                )
            with self.assertRaisesRegex(ValueError, "directly after ProfileHeader"):
                saip_actions._dispatch_reorder_pes(
                    ctx=None,
                    session_id=result["session_id"],
                    from_index=1,
                    to_index=2,
                )
        finally:
            get_manager().close(result["session_id"])

    def test_move_pe_then_json_reopen_keeps_server_side_scope_lock(self) -> None:
        result = saip_actions.open_saip_document_session(_guarded_document())
        sid = result["session_id"]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "guarded-after-move.json"
            try:
                saip_actions._dispatch_add_pe(
                    ctx=None,
                    session_id=sid,
                    pe_type="pinCodes",
                    insert_at=1,
                )
                saip_actions._dispatch_add_pe(
                    ctx=None,
                    session_id=sid,
                    pe_type="pukCodes",
                    insert_at=2,
                )
                saip_actions._dispatch_reorder_pes(
                    ctx=None,
                    session_id=sid,
                    from_index=1,
                    to_index=2,
                )
                handle = get_manager().claim(sid)
                self.assertIn("__ygg_generation__", handle["decoded_document"])
                saip_actions._dispatch_save_package(
                    ctx=None,
                    session_id=sid,
                    output_path=str(path),
                    format="json",
                )
            finally:
                get_manager().close(sid)

            reopened = saip_actions._dispatch_open_package(ctx=None, path=str(path))
            try:
                self.assertEqual(reopened["scope_lock"], _TEST_SCOPE)
                with self.assertRaisesRegex(ValueError, "Concrete DER/HEX export"):
                    saip_actions._dispatch_save_package(
                        ctx=None,
                        session_id=reopened["session_id"],
                        output_path=str(path.with_suffix(".der")),
                        format="der",
                    )
            finally:
                get_manager().close(reopened["session_id"])


if __name__ == "__main__":
    unittest.main()
