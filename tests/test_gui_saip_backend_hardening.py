# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import base64
import copy
import json
import threading
import time
from pathlib import Path

import pytest

from yggdrasim_common.gui_server.actions import saip
from yggdrasim_common.gui_server.actions.registry import ActionContext, get_registry
from yggdrasim_common.gui_server.sessions import get_manager


def _minimal_der() -> bytes:
    return bytes(
        saip._new_empty_pes(
            ver_major=3,
            ver_minor=3,
            iccid_hex="01234567890123456789",
        ).to_der()
    )


def test_json_loader_rejects_invalid_utf8_without_replacement(
    tmp_path: Path,
) -> None:
    source = tmp_path / "profile.json"
    source.write_bytes(b'{"sections": {"header": "\\xff"}}'.replace(b"\\xff", b"\xff"))

    with pytest.raises(ValueError, match=r"valid UTF-8.*offset"):
        saip._load_package_payload_impl(source)


def test_single_pe_hex_import_rejects_invalid_utf8(tmp_path: Path) -> None:
    source = tmp_path / "pe.hex"
    source.write_bytes(b"AA\xffBB")

    with pytest.raises(ValueError, match=r"hex text must be valid UTF-8"):
        saip._decode_imported_pe_bytes(source)


def test_add_variable_requires_lossless_selected_text_encoding() -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    try:
        handle = get_manager().claim(sid)
        header_key = next(iter(handle["decoded_document"]["sections"]))
        handle["decoded_document"]["sections"][header_key]["iccid"] = b"\xff"

        with pytest.raises(ValueError, match=r"choose hex encoding"):
            saip._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=sid,
                section_key=header_key,
                field_path="iccid",
                variable_name="ICCID",
                encoding="utf8",
            )

        assert (
            handle["decoded_document"]["sections"][header_key]["iccid"]
            == b"\xff"
        )
    finally:
        get_manager().close(sid)


def test_uploaded_package_retains_private_backing_for_revert_and_save(
    tmp_path: Path,
) -> None:
    opened = saip._dispatch_open_package_upload(
        ctx=None,
        filename="../../uploaded.der",
        content_base64=base64.b64encode(_minimal_der()).decode("ascii"),
    )
    sid = opened["session_id"]
    old_backing: Path | None = None
    try:
        session = get_manager().get(sid)
        handle = session.handle
        old_backing = Path(handle["source_backing_path"])
        assert opened["source_path"] == "upload:uploaded.der"
        assert handle["source_path"] == "upload:uploaded.der"
        assert old_backing.is_file()

        saip._mark_dirty(handle, 0)
        reverted = saip._dispatch_revert_changes(ctx=None, session_id=sid)
        assert reverted["source_path"] == "upload:uploaded.der"
        assert reverted["dirty"] is False
        assert old_backing.is_file()

        target = tmp_path / "saved.json"
        saved = saip._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(target),
            format="json",
        )
        assert saved["source_path"] == str(target)
        assert handle["source_backing_path"] == str(target)
        # Save As must not remove the upload until the owning session closes.
        assert old_backing.is_file()

        closed = saip._dispatch_close_package(ctx=None, session_id=sid)
        assert closed["closed"] is True
        assert old_backing.exists() is False
    finally:
        get_manager().close(sid)
        if old_backing is not None:
            assert old_backing.exists() is False


def test_close_requires_explicit_discard_and_rejects_other_session_kinds() -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    try:
        with pytest.raises(ValueError, match="unsaved changes"):
            saip._dispatch_close_package(ctx=None, session_id=sid)
        assert get_manager().has(sid)

        result = saip._dispatch_close_package(
            ctx=None,
            session_id=sid,
            discard_changes=True,
        )
        assert result["closed"] is True
        assert result["discarded_changes"] is True
    finally:
        get_manager().close(sid)

    foreign = get_manager().open(
        kind="scp03",
        handle={"transporter": object()},
        close=lambda: None,
    )
    try:
        with pytest.raises(ValueError, match="not a SAIP"):
            saip._dispatch_close_package(
                ctx=None,
                session_id=foreign.id,
                discard_changes=True,
            )
        assert get_manager().has(foreign.id)
    finally:
        get_manager().close(foreign.id)


def test_open_with_missing_or_duplicate_sidecar_does_not_leak_session(
    tmp_path: Path,
) -> None:
    package = tmp_path / "profile.der"
    package.write_bytes(_minimal_der())
    before = {row["id"] for row in get_manager().list()}

    with pytest.raises(FileNotFoundError):
        saip._dispatch_open_package_with_variables(
            ctx=None,
            path=str(package),
            variables_path=str(tmp_path / "missing.csv"),
        )
    assert {row["id"] for row in get_manager().list()} == before

    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text("ICCID,1\niccid,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="more than once"):
        saip._dispatch_open_package_with_variables(
            ctx=None,
            path=str(package),
            variables_path=str(duplicate),
        )
    assert {row["id"] for row in get_manager().list()} == before


def test_mutation_and_save_are_serialized_on_the_session_lock(
    tmp_path: Path,
) -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    session = get_manager().get(sid)
    saip._replace_dirty_pes(session.handle, set())
    entered = threading.Event()
    release = threading.Event()
    save_finished = threading.Event()
    failures: list[BaseException] = []

    def mutation(_ctx: object, *, session_id: str) -> dict[str, bool]:
        handle = get_manager().claim(session_id)
        entered.set()
        assert release.wait(timeout=5)
        handle["decoded_document"]["__ygg_token_defs__"] = {
            "CONCURRENCY_PROBE": {"value": "committed", "encoding": "utf8"}
        }
        saip._mark_dirty(handle, -1)
        return {"ok": True}

    wrapped = saip._with_history(mutation)
    target = tmp_path / "coherent.json"

    def run_mutation() -> None:
        try:
            wrapped(None, session_id=sid)
        except BaseException as error:  # pragma: no cover - assertion reports it
            failures.append(error)

    def run_save() -> None:
        try:
            saip._dispatch_save_package(
                ctx=None,
                session_id=sid,
                output_path=str(target),
                format="json",
            )
        except BaseException as error:  # pragma: no cover - assertion reports it
            failures.append(error)
        finally:
            save_finished.set()

    mutation_thread = threading.Thread(target=run_mutation)
    save_thread = threading.Thread(target=run_save)
    try:
        mutation_thread.start()
        assert entered.wait(timeout=5)
        save_thread.start()
        time.sleep(0.1)
        assert save_finished.is_set() is False
        assert target.exists() is False

        release.set()
        mutation_thread.join(timeout=5)
        save_thread.join(timeout=5)
        assert failures == []
        assert save_finished.is_set()
        saved = json.loads(target.read_text(encoding="utf-8"))
        assert saved["__ygg_token_defs__"]["CONCURRENCY_PROBE"]["value"] == "committed"
    finally:
        release.set()
        mutation_thread.join(timeout=5)
        save_thread.join(timeout=5)
        get_manager().close(sid)


def test_failed_mutation_rolls_back_document_dirty_state_and_history() -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    handle = get_manager().claim(sid)
    saip._replace_dirty_pes(handle, set())
    before = copy.deepcopy(handle["decoded_document"])

    def failing(_ctx: object, *, session_id: str) -> dict[str, bool]:
        live = get_manager().claim(session_id)
        live["decoded_document"]["partial"] = "must disappear"
        saip._mark_dirty(live, -1)
        raise ValueError("simulated mutation failure")

    try:
        with pytest.raises(ValueError, match="simulated mutation failure"):
            saip._with_history(failing)(None, session_id=sid)
        assert handle["decoded_document"] == before
        assert handle["dirty_pes"] == set()
        assert handle["history"] == {"undo": [], "redo": []}
    finally:
        get_manager().close(sid)


def test_json_save_does_not_mutate_live_placeholder_sidecar(
    tmp_path: Path,
) -> None:
    seed = "01234567890123456789"
    varder = (
        _minimal_der().hex().upper().replace(seed, "{ICCIDICCID10}", 1)
    )
    source = tmp_path / "template.varder"
    source.write_text(varder, encoding="utf-8")
    opened = saip._dispatch_open_package(ctx=None, path=str(source))
    sid = opened["session_id"]
    try:
        handle = get_manager().claim(sid)
        assert len(handle["inline_placeholder_records"]) == 1
        assert "__ygg_inline_placeholders__" not in handle["decoded_document"]

        saip._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(tmp_path / "template.json"),
            format="json",
        )

        assert "__ygg_inline_placeholders__" not in handle["decoded_document"]
        snapshot = saip.snapshot_saip_session(sid)
        assert "__ygg_inline_placeholders__" not in snapshot["decoded_document"]
    finally:
        get_manager().close(sid)


@pytest.mark.parametrize("wrapper_name", ["_with_history", "_with_session_lock"])
def test_active_saip_operations_temporarily_prevent_auto_close(
    wrapper_name: str,
) -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    session = get_manager().get(sid)
    saip._replace_dirty_pes(session.handle, set())
    assert session.protect_from_auto_close is False

    observed: list[bool] = []

    def operation(_ctx: object, *, session_id: str) -> dict[str, bool]:
        observed.append(get_manager().get(session_id).protect_from_auto_close)
        return {"ok": True}

    try:
        wrapped = getattr(saip, wrapper_name)(operation)
        assert wrapped(None, session_id=sid) == {"ok": True}
        assert observed == [True]
        assert session.protect_from_auto_close is False
    finally:
        get_manager().close(sid)


@pytest.mark.parametrize("wrapper_name", ["_with_history", "_with_session_lock"])
def test_saip_operation_does_not_use_handle_after_concurrent_close(
    wrapper_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    session = get_manager().get(sid)
    handle = session.handle
    invoked = False

    def resolve_then_close(_session_id: str) -> tuple[object, dict[str, object]]:
        assert get_manager().close(sid) is True
        return session, handle

    def operation(_ctx: object, *, session_id: str) -> dict[str, bool]:
        nonlocal invoked
        invoked = True
        return {"ok": True}

    monkeypatch.setattr(saip, "_require_saip_session", resolve_then_close)
    wrapped = getattr(saip, wrapper_name)(operation)
    with pytest.raises(KeyError, match="unknown session"):
        wrapped(None, session_id=sid)
    assert invoked is False


def test_atomic_save_failure_preserves_existing_artifact_and_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yggdrasim_common.secure_files as secure_files

    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    target = tmp_path / "existing.json"
    target.write_bytes(b"original")
    handle = get_manager().claim(sid)
    original_source = handle.get("source_path")

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(secure_files.os, "replace", fail_replace)
    try:
        with pytest.raises(OSError, match="publication failure"):
            saip._dispatch_save_package(
                ctx=None,
                session_id=sid,
                output_path=str(target),
                format="json",
                overwrite=True,
            )
        assert target.read_bytes() == b"original"
        assert handle.get("source_path") == original_source
        assert handle["dirty_pes"]
    finally:
        get_manager().close(sid)


def test_varder_save_advice_respects_guarded_partial_policy(
    tmp_path: Path,
) -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    handle = get_manager().claim(sid)
    handle["export_policy"] = {
        "concrete_export_allowed": False,
        "integrity_state": "LOCKED_PARTIAL",
        "generation_scope": "filesystem",
    }
    try:
        with pytest.raises(
            ValueError,
            match=r"tagged JSON.*explicit completion flow",
        ):
            saip._dispatch_save_package(
                ctx=None,
                session_id=sid,
                output_path=str(tmp_path / "guarded.varder"),
                format="varder",
            )
    finally:
        get_manager().close(sid)


def test_secret_variable_definition_responses_are_redacted() -> None:
    opened = saip._dispatch_create_package(ctx=None)
    sid = opened["session_id"]
    secret_value = "00112233445566778899AABBCCDDEEFF"
    try:
        added = saip._dispatch_add_variable_definition(
            ctx=None,
            session_id=sid,
            name="KI",
            value=secret_value,
            encoding="hex",
        )
        assert added["value"] == ""
        assert added["value_redacted"] is True
        assert secret_value not in str(added)

        removed = saip._dispatch_remove_variable_definition(
            ctx=None,
            session_id=sid,
            name="KI",
        )
        assert removed["removed_value"] == ""
        assert removed["removed_value_redacted"] is True
        assert secret_value not in str(removed)
    finally:
        get_manager().close(sid)


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-10", "@SUM(A1:A2)"])
def test_spreadsheet_csv_formula_neutralization_round_trips(value: str) -> None:
    exported = saip._spreadsheet_safe_csv_cell(value)
    assert exported.startswith("'")
    assert saip._restore_spreadsheet_safe_csv_cell(exported) == value


def test_saip_action_schema_uses_supported_controls_and_overwrite_guards() -> None:
    search = get_registry().get("saip.search_files")
    regex = next(field for field in search.inputs if field.name == "regex")
    assert regex.kind == "bool"

    gfm = get_registry().get("saip.gfm_add_file_element")
    transaction = next(
        field for field in gfm.inputs if field.name == "transaction_index"
    )
    assert transaction.kind == "int"

    close = get_registry().get("saip.close_package")
    assert any(field.name == "discard_changes" for field in close.inputs)
    for action_id in (
        "saip.export_variables_csv",
        "saip.compare_report_html",
        "saip.decode_to_json",
    ):
        spec = get_registry().get(action_id)
        assert any(field.name == "overwrite" for field in spec.inputs)


def test_corrupt_token_mapping_store_is_not_silently_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    store = saip._token_mapping_store_path()
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="corrupt"):
        saip._dispatch_set_token_mapping(
            ctx=None,
            filename="profile.der",
            tokens_path=str(tmp_path / "tokens.csv"),
        )
    assert store.read_text(encoding="utf-8") == "{broken"


def test_local_saip_inputs_have_a_bounded_gui_limit(tmp_path: Path) -> None:
    source = tmp_path / "oversized.der"
    with source.open("wb") as stream:
        stream.truncate(saip._MAX_SAIP_UPLOAD_BYTES + 1)

    with pytest.raises(ValueError, match="64 MiB"):
        saip._load_package_payload_impl(source)


def test_long_running_saip_helpers_honor_cancellation() -> None:
    event = threading.Event()
    event.set()
    ctx = ActionContext(extras={"cancel_event": event})

    with pytest.raises(ValueError, match="cancelled"):
        saip._dispatch_batch_lint_paths(
            ctx=ctx,
            paths=["/does/not/matter.der"],
        )
