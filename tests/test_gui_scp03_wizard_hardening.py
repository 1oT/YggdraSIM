# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Correctness and secret-handling regressions for SCP03 GUI wizards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
GUI_SOURCE = ROOT / "gui_frontend" / "src" / "js" / "command-center.js"


class _SecureSessionState:
    is_authenticated = True


class _FakeTransporter:
    def __init__(self) -> None:
        self.session = _SecureSessionState()
        self.calls: list[str] = []
        self.replies: dict[str, tuple[bytes, int, int]] = {}

    def transmit(self, apdu: str, silent: bool = True) -> tuple[bytes, int, int]:
        command = str(apdu).upper()
        self.calls.append(command)
        return self.replies.get(command, (b"", 0x90, 0x00))


class _FakeFs:
    def __init__(self) -> None:
        self.current_fid = "6F07"
        self.current_path_hint = "MF/ADF_USIM/EF_IMSI"
        self.selected: list[str] = []

    def select(self, path: str, silent: bool = False) -> bool:
        self.selected.append(path)
        return True


class _FakeGuiSession:
    kind = "scp03"
    id = "wizard-session"

    def __init__(self, transporter: _FakeTransporter) -> None:
        self.handle = {"transporter": transporter, "fs": _FakeFs()}


class _FakeManager:
    def __init__(self, session: _FakeGuiSession) -> None:
        self.session = session

    def get(self, session_id: str) -> _FakeGuiSession:
        assert session_id == self.session.id
        return self.session


class _Ctx:
    pass


def _install_session(monkeypatch) -> tuple[_FakeGuiSession, _FakeTransporter]:
    from yggdrasim_common.gui_server import sessions

    transporter = _FakeTransporter()
    session = _FakeGuiSession(transporter)
    monkeypatch.setattr(sessions, "get_manager", lambda: _FakeManager(session))
    return session, transporter


def _js_function(source: str, name: str, next_name: str) -> str:
    start = source.index(name)
    end = source.index(next_name, start)
    return source[start:end]


def test_pin_encoder_rejects_empty_overlength_and_non_ascii() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import _pad_pin_ascii

    assert _pad_pin_ascii("1234") == "31323334FFFFFFFF"
    with pytest.raises(ValueError, match="is required"):
        _pad_pin_ascii("")
    with pytest.raises(ValueError, match="at most 8"):
        _pad_pin_ascii("123456789")
    with pytest.raises(ValueError, match="ASCII"):
        _pad_pin_ascii("12å4")


def test_manage_pin_never_returns_credential_bearing_apdu(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    result = scp03._dispatch_manage_pin(
        _Ctx(),
        session_id=session.id,
        op="VERIFY",
        pin_ref="01",
        pin="1234",
    )

    assert transporter.calls == ["002000010831323334FFFFFFFF"]
    assert result["payload_redacted"] is True
    assert result["payload_length"] == 8
    assert result["apdu"] == "0020000108[REDACTED:8B]"
    rendered = json.dumps(result)
    assert "31323334" not in rendered
    assert "1234" not in rendered


def test_manage_pin_rejects_bad_length_before_transmit(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    with pytest.raises(ValueError, match="at most 8"):
        scp03._dispatch_manage_pin(
            _Ctx(),
            session_id=session.id,
            op="UNBLOCK",
            pin_ref="01",
            puk="123456789",
            new_pin="4321",
            confirm=True,
        )
    assert transporter.calls == []


def test_manage_pin_disable_and_unblock_require_confirmation(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    for operation in ("DISABLE", "UNBLOCK"):
        with pytest.raises(ValueError, match="confirm must be true"):
            scp03._dispatch_manage_pin(
                _Ctx(),
                session_id=session.id,
                op=operation,
                pin_ref="01",
                pin="1234",
                puk="12345678",
                new_pin="4321",
                confirm=False,
            )
    assert transporter.calls == []


def test_put_key_fields_are_declared_secret() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import PUT_KEY_SPEC

    fields = {field.name: field for field in PUT_KEY_SPEC.inputs}
    assert all(fields[name].secret for name in ("enc_key", "mac_key", "dek_key"))


def test_manage_pin_help_uses_standard_key_references() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import MANAGE_PIN_SPEC

    pin_ref = next(field for field in MANAGE_PIN_SPEC.inputs if field.name == "pin_ref")
    assert "01 = PIN1" in pin_ref.help
    assert "81 = PIN2" in pin_ref.help
    assert "0A = ADM1" in pin_ref.help
    assert "02 = PIN2" not in pin_ref.help


def test_store_data_payload_is_declared_secret() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import STORE_DATA_SPEC

    data_field = next(field for field in STORE_DATA_SPEC.inputs if field.name == "data")
    assert data_field.secret is True


def test_reset_defaults_terminates_authenticated_secure_sessions(monkeypatch) -> None:
    from types import SimpleNamespace

    from yggdrasim_common.gui_server.actions import scp03

    class _Inventory:
        def get_module_state(self, _name):
            return {}

        def replace_module_state(self, _name, _state):
            return None

    class _Transport:
        def __init__(self):
            self.session = SimpleNamespace(is_authenticated=True)
            self.reset_calls = 0

        def reset_session_state(self):
            self.reset_calls += 1
            self.session.is_authenticated = False

    transport = _Transport()
    handle = {"gp": object(), "transporter": transport}

    class _Manager:
        @staticmethod
        def list():
            return [{"kind": "scp03", "id": "session-1"}]

        @staticmethod
        def claim(_session_id):
            return handle

    monkeypatch.setattr(
        "yggdrasim_common.device_inventory.DeviceInventoryStore",
        _Inventory,
    )
    monkeypatch.setattr(
        "yggdrasim_common.gui_server.sessions.get_manager",
        lambda: _Manager(),
    )

    result = scp03._dispatch_set_defaults(_Ctx(), confirm="RESET")

    assert transport.reset_calls == 1
    assert result["sessions_invalidated"] == 1
    assert result["gp_controllers_reloaded"] == 1
    assert handle["gp"] is None


def test_put_key_rejects_32_byte_3des_keys_before_gp_call(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    long_key = "11" * 32
    with pytest.raises(ValueError, match="invalid for 3DES"):
        scp03._dispatch_put_key(
            _Ctx(),
            session_id=session.id,
            old_kvn="00",
            new_kvn="01",
            new_key_id="01",
            enc_key=long_key,
            mac_key=long_key,
            dek_key=long_key,
            algorithm="3DES",
            confirm="PUT-KEY",
        )
    assert transporter.calls == []


def test_auth_overrides_validate_protocol_lengths_and_return_names_only() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _apply_auth_key_overrides,
    )

    class _Gp:
        scp02_keys: dict[str, bytes] = {}
        scp03_keys: dict[str, bytes] = {}
        scp02_kvn = 0
        scp03_kvn = 0

    gp = _Gp()
    with pytest.raises(ValueError, match="16 or 24 bytes for SCP02"):
        _apply_auth_key_overrides(
            gp,
            "SCP02",
            kvn_override="",
            enc_override="11" * 32,
            mac_override="",
            dek_override="",
        )

    applied = _apply_auth_key_overrides(
        gp,
        "SCP03",
        kvn_override="0x30",
        enc_override=("11 " * 16),
        mac_override="",
        dek_override="",
    )
    assert applied == {"enc_key", "kvn"}
    assert gp.scp03_keys["kenc"] == bytes.fromhex("11" * 16)
    assert gp.scp03_kvn == 0x30
    assert "11" * 16 not in repr(applied)


def test_gp_factory_refreshes_from_persisted_workspace_keys(monkeypatch) -> None:
    import configparser
    from types import SimpleNamespace

    from yggdrasim_common.gui_server.actions.scp03 import _get_or_make_gp_ctrl

    parser = configparser.ConfigParser()
    parser["KEYS"] = {
        "scp03_kenc": "AA" * 16,
        "scp03_kmac": "BB" * 16,
        "scp03_dek": "CC" * 16,
        "scp03_kvn": "42",
        "aid": "A000000151000042",
    }
    monkeypatch.setattr(
        "SCP03.config.load_scp03_runtime_parser",
        lambda: parser,
    )
    session = SimpleNamespace(
        handle={"gp": object(), "transporter": SimpleNamespace()}
    )

    first = _get_or_make_gp_ctrl(session, refresh=True)
    assert first.scp03_keys["kenc"] == bytes.fromhex("AA" * 16)
    assert first.scp03_kvn == 0x42
    assert first.target_aid == bytes.fromhex("A000000151000042")

    first.scp03_keys["kenc"] = bytes.fromhex("11" * 16)
    first.target_aid = bytes.fromhex("A000000151000099")
    second = _get_or_make_gp_ctrl(session, refresh=True)
    assert second is not first
    assert second.scp03_keys["kenc"] == bytes.fromhex("AA" * 16)
    assert second.target_aid == bytes.fromhex("A000000151000042")


def test_umts_auth_decoder_accepts_complete_lv_fields() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _decode_umts_auth_response,
    )

    raw = bytes.fromhex(
        "DB"
        "08" + "11" * 8
        + "10" + "22" * 16
        + "10" + "33" * 16
        + "08" + "44" * 8
    )
    decoded = _decode_umts_auth_response(raw)
    assert decoded["valid"] is True
    assert decoded["res"] == "11" * 8
    assert decoded["ck"] == "22" * 16
    assert decoded["ik"] == "33" * 16
    assert decoded["kc"] == "44" * 8
    assert "parse_warning" not in decoded


def test_umts_auth_decoder_rejects_truncated_lv_without_partial_value() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _decode_umts_auth_response,
    )

    decoded = _decode_umts_auth_response(bytes.fromhex("DB081122"))
    assert decoded["valid"] is False
    assert "declares 8" in decoded["parse_warning"]
    assert "res" not in decoded


def test_umts_auth_decoder_validates_auts_declared_length() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _decode_umts_auth_response,
    )

    valid = _decode_umts_auth_response(bytes.fromhex("DC0E" + "AA" * 14))
    assert valid["valid"] is True
    assert valid["auts"] == "AA" * 14

    truncated = _decode_umts_auth_response(bytes.fromhex("DC0E" + "AA" * 13))
    assert truncated["valid"] is False
    assert "declares 14" in truncated["parse_warning"]
    assert "auts" not in truncated


def test_gsm_auth_decoder_requires_ts_31_102_lv_framing() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _decode_umts_auth_response,
    )

    valid = _decode_umts_auth_response(
        bytes.fromhex("04A1A2A3A4080102030405060708")
    )
    assert valid["valid"] is True
    assert valid["sres"] == "A1A2A3A4"
    assert valid["kc"] == "0102030405060708"

    raw_without_lengths = _decode_umts_auth_response(
        bytes.fromhex("A1A2A3A40102030405060708")
    )
    assert raw_without_lengths["valid"] is False
    assert "LV-encoded" in raw_without_lengths["parse_warning"]


def test_live_auth_redacts_derived_keys_unless_explicitly_revealed(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    response = bytes.fromhex(
        "DB04A1A2A3A410" + ("11" * 16) + "10" + ("22" * 16)
    )
    apdu = "008800812210" + ("AA" * 16) + "10" + ("BB" * 16) + "00"
    transporter.replies[apdu] = (response, 0x90, 0x00)

    redacted = scp03._dispatch_run_auth_live(
        _Ctx(),
        session_id=session.id,
        context="USIM",
        rand="AA" * 16,
        autn="BB" * 16,
    )
    assert redacted["response"]["derived_keys_redacted"] is True
    assert "ck" not in redacted["response"]
    assert "ik" not in redacted["response"]
    assert "raw_hex" not in redacted["response"]

    revealed = scp03._dispatch_run_auth_live(
        _Ctx(),
        session_id=session.id,
        context="USIM",
        rand="AA" * 16,
        autn="BB" * 16,
        reveal_sensitive=True,
    )
    assert revealed["response"]["ck"] == "11" * 16
    assert revealed["response"]["ik"] == "22" * 16
    assert revealed["response"]["derived_keys_revealed"] is True


def test_configured_address_decoder_falls_back_to_hex_without_dropping_bytes() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _decode_configured_address,
    )

    assert _decode_configured_address(b"smdp.example", "smdp") == (
        "smdp.example",
        None,
    )
    value, error = _decode_configured_address(b"smdp.\xff.example", "smdp")
    assert value == "736D64702EFF2E6578616D706C65"
    assert error is not None and "valid UTF-8" in error


def test_update_binary_honours_offset_and_reports_wire_status(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    result = scp03._dispatch_update_binary(
        _Ctx(),
        session_id=session.id,
        hex_data="AA BB",
        offset=0x0123,
        confirm=True,
    )

    assert transporter.calls == ["00D6012302AABB"]
    assert result["offset"] == 0x0123
    assert result["bytes"] == 2
    assert result["bytes_written"] == 2
    assert result["chunk_count"] == 1
    assert result["sw"] == "9000"
    assert result["ok"] is True


def test_update_binary_chunks_payloads_without_wrapping_lc(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    result = scp03._dispatch_update_binary(
        _Ctx(),
        session_id=session.id,
        hex_data="AA" * 256,
        offset=0,
        confirm=True,
    )

    assert len(transporter.calls) == 2
    assert transporter.calls[0].startswith("00D60000FF")
    assert transporter.calls[1] == "00D600FF01AA"
    assert result["bytes_written"] == 256
    assert result["chunk_count"] == 2


def test_update_binary_spec_exposes_offset_and_confirm() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import UPDATE_BINARY_SPEC

    fields = {field.name: field for field in UPDATE_BINARY_SPEC.inputs}
    assert fields["offset"].min_value == 0
    assert fields["offset"].max_value == 0x7FFF
    assert fields["confirm"].required is True


def test_linear_fixed_fcp_descriptor_contains_record_count() -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _build_fcp_template_fields,
    )

    result = _build_fcp_template_fields(
        file_type="LINEAR_FIXED_EF",
        full_path="3F007F206F3A",
        sec_attr_hex="8C0140",
        rec_len_hex="14",
        num_rec_hex="0A",
    )
    assert "8205422100140A" in result["fcp_hex"]


def test_create_file_uses_extended_lc_for_large_valid_fcp(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    fcp = "6281FD" + ("AA" * 253)
    result = scp03._dispatch_fs_create_file(
        _Ctx(),
        session_id=session.id,
        fcp_hex=fcp,
    )

    expected = "00E00000000100" + fcp
    assert transporter.calls == [expected]
    assert result["apdu"] == expected
    assert result["ok"] is True


@pytest.mark.parametrize("bad_size", ("00", "010000"))
def test_resize_rejects_zero_or_oversized_sizes_before_transmit(
    monkeypatch,
    bad_size,
) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    with pytest.raises(ValueError, match="range 1..65535"):
        scp03._dispatch_fs_resize(
            _Ctx(),
            session_id=session.id,
            target_fid="6F07",
            new_file_size=bad_size,
        )
    assert transporter.calls == []


def test_resize_encodes_bounded_two_byte_sizes(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    result = scp03._dispatch_fs_resize(
        _Ctx(),
        session_id=session.id,
        target_fid="6F07",
        new_file_size="40",
        new_total_size="80",
    )

    fcp = "620C83026F078002004081020080"
    assert transporter.calls == ["80D400000E" + fcp]
    assert result["tag_80"] == "80020040"
    assert result["tag_81"] == "81020080"


def test_search_record_uses_extended_lc_without_wrapping(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    needle = "AA" * 256
    result = scp03._dispatch_fs_search_record(
        _Ctx(),
        session_id=session.id,
        search_hex=needle,
    )

    expected = "00A20104000100" + needle
    assert transporter.calls == [expected]
    assert result["apdu"] == expected


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {
                "file_type": "TRANSPARENT_EF",
                "full_path": "3F002F00",
                "sec_attr_hex": "8C02FF",
                "file_size_hex": "0010",
            },
            "declares 2",
        ),
        (
            {
                "file_type": "DF_ADF",
                "full_path": "3F007F10",
                "file_size_hex": "0010",
                "c6_hex": "C602AA",
            },
            "declares 2",
        ),
        (
            {
                "file_type": "DF_ADF",
                "full_path": "3F007F10",
                "file_size_hex": "0010",
                "aid_hex": "A0000000",
                "c6_hex": "C601AA",
            },
            "5..16",
        ),
    ],
)
def test_fcp_builder_rejects_malformed_structured_fields(kwargs, message) -> None:
    from yggdrasim_common.gui_server.actions.scp03 import (
        _build_fcp_template_fields,
    )

    with pytest.raises(ValueError, match=message):
        _build_fcp_template_fields(**kwargs)


def test_manage_channel_rejects_invalid_close_channel(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    with pytest.raises(ValueError, match="range 1..19"):
        scp03._dispatch_manage_channel(
            _Ctx(),
            session_id=session.id,
            op="CLOSE",
            channel="00",
        )
    assert transporter.calls == []


def test_manage_channel_rejects_malformed_open_response(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import scp03

    session, transporter = _install_session(monkeypatch)
    transporter.replies["0070000001"] = (b"\x01\x02", 0x90, 0x00)
    result = scp03._dispatch_manage_channel(
        _Ctx(),
        session_id=session.id,
        op="OPEN",
    )
    assert result["ok"] is False
    assert "Malformed MANAGE CHANNEL response" in result["status"]


def test_hex_coercion_accepts_multiline_trace_format() -> None:
    from yggdrasim_common.gui_server.actions.registry import ActionField, coerce_input

    field = ActionField(name="value", label="Value", kind="hex", required=True)
    assert coerce_input(field, "0xAA BB:\nCC-DD_EE") == "AABBCCDDEE"


def test_custom_wizards_send_required_confirmation_values() -> None:
    source = GUI_SOURCE.read_text(encoding="utf-8")

    lock_block = _js_function(
        source,
        "async function scp03ShowLockUnlock",
        "async function scp03ShowDelete",
    )
    assert "confirm: isLock ? !!values.confirm" in lock_block

    store_block = _js_function(
        source,
        "async function scp03ShowStoreData",
        "async function scp03ShowUpdateBinary",
    )
    assert "confirm: !!values.confirm" in store_block

    binary_block = _js_function(
        source,
        "async function scp03ShowFsUpdateBinary",
        "async function scp03ShowFsUpdateRecord",
    )
    assert "confirm: !!inputs.confirm.checked" in binary_block

    record_block = _js_function(
        source,
        "async function scp03ShowFsUpdateRecord",
        "function scp03InferServiceTableKind",
    )
    assert "confirm: !!inputs.confirm.checked" in record_block


def test_custom_secret_fields_are_password_inputs_and_pin_form_is_conditional() -> None:
    source = GUI_SOURCE.read_text(encoding="utf-8")
    helper = _js_function(
        source,
        "function scp03BuildInlineForm",
        "async function scp03AuthFlow",
    )
    assert 'input.type = (field.secret || kind === "secret")' in helper
    assert 'input.autocomplete = field.secret ? "new-password" : "off"' in helper
    assert "form.checkValidity()" in helper

    pin_block = _js_function(
        source,
        "async function scp03ShowManagePin",
        "async function scp03ShowManageChannel",
    )
    assert "secret: true" in pin_block
    assert 'op === "DISABLE" || op === "UNBLOCK"' in pin_block
    assert "confirm:" in pin_block


def test_frontend_apdu_preview_supports_extended_cases() -> None:
    source = GUI_SOURCE.read_text(encoding="utf-8")
    block = _js_function(
        source,
        "function scp03BreakdownApdu",
        "function scp03HexToAscii",
    )
    for case_name in ('"2E"', '"3E"', '"4E"'):
        assert case_name in block
    assert "65536" in block
    assert "expected 0 or 2" in block
