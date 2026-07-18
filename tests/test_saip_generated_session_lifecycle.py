# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
)
from yggdrasim_common.gui_server.actions import saip as saip_actions
from yggdrasim_common.gui_server.sessions import get_manager

_TEST_SCOPE = "TEST_GENERATED_AUTHORING"


def _guarded_document() -> dict:
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


def test_generated_open_reports_dirty_and_protects_live_authoring_state() -> None:
    opened = saip_actions.open_saip_document_session(_guarded_document())
    session_id = opened["session_id"]
    try:
        session = get_manager().get(session_id)

        assert opened["dirty"] is True
        assert opened["dirty_pe_indices"] == []
        assert opened["dirty_sequence_wide"] is True
        assert session.is_auto_close_protected() is True
    finally:
        get_manager().close(session_id)


def test_generated_open_ingests_inline_template_and_preserves_metadata() -> None:
    placeholder_seed = "01234567890123456789"
    template_sequence = saip_actions._new_empty_pes(
        ver_major=3,
        ver_minor=3,
        iccid_hex=placeholder_seed,
    )
    template_text = (
        bytes(template_sequence.to_der())
        .hex()
        .upper()
        .replace(placeholder_seed, "{ICCIDICCID10}", 1)
    )
    document = _guarded_document()
    document["__ygg_token_defs__"] = {"PROBE": {"hex": "01"}}

    opened = saip_actions.open_saip_document_session(
        document,
        inline_template_text=template_text,
    )
    session_id = opened["session_id"]
    try:
        handle = get_manager().claim(session_id)
        records = handle["inline_placeholder_records"]

        assert opened["inline_placeholder_count"] == 1
        assert len(records) == 1
        assert records[0].literal == "{ICCIDICCID10}"
        assert records[0].sentinel_hex in bytes(handle["pes"].to_der()).hex().upper()
        assert handle["decoded_document"]["__ygg_token_defs__"] == {
            "PROBE": {"hex": "01"},
        }
        assert "__ygg_generation_provenance__" in handle["decoded_document"]

        from Tools.ProfilePackage.saip_json_codec import (
            build_profile_sequence_from_document,
        )

        rebuilt = build_profile_sequence_from_document(
            handle["decoded_document"],
            workspace_root=saip_actions._workspace_root(),
        )
        assert rebuilt.to_der() == handle["pes"].to_der()
    finally:
        get_manager().close(session_id)


def test_generated_open_rejects_inline_template_pe_order_mismatch() -> None:
    template_sequence = saip_actions._new_empty_pes(ver_major=3, ver_minor=3)
    template_sequence.pe_list.insert(
        1,
        saip_actions._build_default_pe("pinCodes"),
    )
    template_sequence.renumber_identification()

    with pytest.raises(ValueError, match="type/order does not match"):
        saip_actions.open_saip_document_session(
            _guarded_document(),
            inline_template_text=bytes(template_sequence.to_der()).hex(),
        )


def test_in_memory_source_operations_explain_required_save() -> None:
    opened = saip_actions.open_saip_document_session(_guarded_document())
    session_id = opened["session_id"]
    try:
        handle = get_manager().claim(session_id)
        handle["applied_overrides"] = {"FOO": "01"}

        with pytest.raises(RuntimeError, match="tagged JSON"):
            saip_actions._dispatch_revert_changes(
                ctx=None,
                session_id=session_id,
            )
        with pytest.raises(RuntimeError, match="tagged JSON"):
            saip_actions._dispatch_diff_against_source(
                ctx=None,
                session_id=session_id,
            )
        with pytest.raises(RuntimeError, match="tagged JSON"):
            saip_actions._dispatch_reset_variable(
                ctx=None,
                session_id=session_id,
                name="FOO",
            )

        assert handle["applied_overrides"] == {"FOO": "01"}
    finally:
        get_manager().close(session_id)


def test_json_save_establishes_source_and_revert_preserves_generation_guard(
    tmp_path: Path,
) -> None:
    opened = saip_actions.open_saip_document_session(_guarded_document())
    session_id = opened["session_id"]
    target = tmp_path / "generated-authoring.json"
    try:
        session = get_manager().get(session_id)
        saved = saip_actions._dispatch_save_package(
            ctx=None,
            session_id=session_id,
            output_path=str(target),
            format="json",
        )

        assert target.is_file()
        assert saved["source_path"] == str(target)
        assert saved["encoding"] == "json"
        assert saved["dirty"] is False
        assert session.handle["source_path"] == str(target)
        assert session.handle["encoding"] == "json"
        assert session.metadata["source_path"] == str(target)
        assert session.metadata["encoding"] == "json"
        assert session.is_auto_close_protected() is False
        assert saved["export_guard"]["concrete_export_allowed"] is False

        saip_actions._mark_dirty(session.handle, 0)
        assert session.is_auto_close_protected() is True
        reverted = saip_actions._dispatch_revert_changes(
            ctx=None,
            session_id=session_id,
        )

        assert reverted["dirty"] is False
        assert reverted["source_path"] == str(target)
        assert session.is_auto_close_protected() is False
        assert reverted["export_guard"]["concrete_export_allowed"] is False
        with pytest.raises(ValueError, match="Concrete DER/HEX export"):
            saip_actions._dispatch_save_package(
                ctx=None,
                session_id=session_id,
                output_path=str(tmp_path / "forbidden.der"),
                format="der",
            )
    finally:
        get_manager().close(session_id)


def test_history_restores_document_overrides_and_inline_records_together() -> None:
    opened = saip_actions._dispatch_create_package(ctx=None)
    session_id = opened["session_id"]
    try:
        handle = get_manager().claim(session_id)
        handle["decoded_document"]["__ygg_token_defs__"] = {
            "FOO": {"value": "before"},
        }
        handle["applied_overrides"] = {"FOO": "before"}
        handle["inline_placeholder_records"] = [{"probe": "before"}]
        saip_actions._history_snapshot(handle)

        handle["decoded_document"]["__ygg_token_defs__"] = {
            "FOO": {"value": "after"},
        }
        handle["applied_overrides"] = {"FOO": "after"}
        handle["inline_placeholder_records"] = [{"probe": "after"}]

        undone = saip_actions._dispatch_undo(ctx=None, session_id=session_id)
        assert undone["applied"] is True
        assert handle["decoded_document"]["__ygg_token_defs__"]["FOO"] == {
            "value": "before",
        }
        assert handle["applied_overrides"] == {"FOO": "before"}
        assert handle["inline_placeholder_records"] == [{"probe": "before"}]

        redone = saip_actions._dispatch_redo(ctx=None, session_id=session_id)
        assert redone["applied"] is True
        assert handle["decoded_document"]["__ygg_token_defs__"]["FOO"] == {
            "value": "after",
        }
        assert handle["applied_overrides"] == {"FOO": "after"}
        assert handle["inline_placeholder_records"] == [{"probe": "after"}]
    finally:
        get_manager().close(session_id)


def test_invalid_history_snapshot_leaves_authoring_state_and_stacks_unchanged() -> None:
    opened = saip_actions._dispatch_create_package(ctx=None)
    session_id = opened["session_id"]
    try:
        handle = get_manager().claim(session_id)
        handle["applied_overrides"] = {"FOO": "current"}
        handle["inline_placeholder_records"] = [{"probe": "current"}]
        invalid_snapshot = {
            "schema": saip_actions._SESSION_HISTORY_SNAPSHOT_SCHEMA,
            "decoded_document": {"not_sections": {}},
            "applied_overrides": {"FOO": "stale"},
            "inline_placeholder_records": [{"probe": "stale"}],
        }
        handle["history"] = {"undo": [invalid_snapshot], "redo": []}
        before_document = copy.deepcopy(handle["decoded_document"])
        before_overrides = copy.deepcopy(handle["applied_overrides"])
        before_inline = copy.deepcopy(handle["inline_placeholder_records"])

        with pytest.raises(RuntimeError, match="could not be restored"):
            saip_actions._dispatch_undo(ctx=None, session_id=session_id)

        assert handle["decoded_document"] == before_document
        assert handle["applied_overrides"] == before_overrides
        assert handle["inline_placeholder_records"] == before_inline
        assert handle["history"]["undo"] == [invalid_snapshot]
        assert handle["history"]["redo"] == []
    finally:
        get_manager().close(session_id)
