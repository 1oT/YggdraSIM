# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest

from SCP03.core.cap import CapFileParser
from SCP03.interface.shell import ShellDispatcher
from SCP03.logic.fs import FileSystemController
from SCP03.logic.gp import GlobalPlatformManager
from SCP03.logic.security import AUTH_TEST_VECTOR, SecurityController
from SCP03.logic.sgp22 import Sgp22Manager
from SCP03.logic.stk import StkController
from SCP03.transport.card import CardTransporter


def _cap_component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload


def _header_component(package_aid: bytes = bytes.fromhex("A000000151")) -> bytes:
    payload = (b"\x00" * 9) + bytes([len(package_aid)]) + package_aid
    return _cap_component(0x01, payload)


def test_cap_parser_accepts_case_insensitive_windows_member_names() -> None:
    package_aid = bytes.fromhex("A000000151")
    with tempfile.TemporaryDirectory() as temp_dir:
        archive = Path(temp_dir) / "mixed-case.cap"
        with zipfile.ZipFile(archive, "w") as cap_zip:
            cap_zip.writestr("pkg\\header.CAP", _header_component(package_aid))
        parsed = CapFileParser.parse_with_metadata(str(archive))

    assert parsed.package_aid == package_aid
    assert [component.name for component in parsed.components] == ["Header.cap"]


def test_cap_parser_rejects_trailing_load_file_data() -> None:
    wrapped = CapFileParser._wrap_load_file_block(_header_component()) + b"\x00"
    with pytest.raises(ValueError, match="trailing data"):
        CapFileParser._unwrap_load_file_block(wrapped)


def test_cap_parser_rejects_truncated_package_aid() -> None:
    malformed_header = _cap_component(
        0x01,
        (b"\x00" * 9) + b"\x10" + bytes.fromhex("A000000151"),
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        ijc_path = Path(temp_dir) / "truncated.ijc"
        ijc_path.write_bytes(CapFileParser._wrap_load_file_block(malformed_header))
        with pytest.raises(ValueError, match="package AID exceeds"):
            CapFileParser.parse_with_metadata(str(ijc_path))


def test_cap_parser_rejects_component_tag_mismatch() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        archive = Path(temp_dir) / "wrong-tag.cap"
        with zipfile.ZipFile(archive, "w") as cap_zip:
            cap_zip.writestr("Header.cap", _cap_component(0x02, b"\x00" * 16))
        with pytest.raises(ValueError, match="expected 01"):
            CapFileParser.parse_with_metadata(str(archive))


def _manager_without_init() -> GlobalPlatformManager:
    return GlobalPlatformManager.__new__(GlobalPlatformManager)


def test_gp_registry_parser_accepts_long_form_e3_length() -> None:
    body = (
        bytes.fromhex("4F05A0000001519F700107C503010203")
        + b"\x53\x70"
        + (b"A" * 112)
    )
    assert len(body) == 130
    response = b"\xE3\x81\x82" + body

    rows = _manager_without_init()._registry_rows_from_data(response, "APPS")

    assert rows == [("A000000151", 0x07, "010203")]


def test_gp_registry_pagination_reuses_get_next_occurrence_p2() -> None:
    class _Transport:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.responses = iter(
                [
                    (b"", 0x63, 0x10),
                    (b"", 0x63, 0x10),
                    (b"", 0x90, 0x00),
                ]
            )

        def transmit(self, apdu: str, **_kwargs):
            self.calls.append(apdu)
            return next(self.responses)

    manager = _manager_without_init()
    manager.tp = _Transport()

    result = manager.get_registry_data("apps")

    assert [apdu[6:8] for apdu in manager.tp.calls] == ["00", "01", "01"]
    assert result["pages"] == 3
    assert result["truncated"] is False


def test_gp_registry_pagination_is_bounded() -> None:
    class _Transport:
        def transmit(self, _apdu: str, **_kwargs):
            return b"", 0x63, 0x10

    manager = _manager_without_init()
    manager.tp = _Transport()
    manager.MAX_GET_STATUS_PAGES = 2

    result = manager.get_registry_data("SD")

    assert result["pages"] == 2
    assert result["status"] == "6310"
    assert result["truncated"] is True


def test_gp_registry_parser_does_not_return_plausible_partial_rows() -> None:
    valid = bytes.fromhex("E30B4F05A0000001519F700107")
    malformed = valid + bytes.fromhex("E3024F")

    assert _manager_without_init()._registry_rows_from_data(malformed, "APPS") == []


def test_gp_key_template_decodes_all_basic_key_components() -> None:
    response = bytes.fromhex(
        "E010"
        "C006010188108820"
        "C006020380108118"
    )

    entries = _manager_without_init()._parse_key_template_entries(response)

    assert len(entries) == 2
    assert entries[0]["id"] == "01"
    assert entries[0]["version"] == "01"
    assert entries[0]["components"] == [
        {"type": "AES", "type_code": "88", "length": 0x10},
        {"type": "AES", "type_code": "88", "length": 0x20},
    ]
    assert entries[1]["components"][1]["type"] == "81"
    assert entries[1]["components"][1]["length"] == 0x18


def test_gp_key_template_validates_complete_extended_attributes() -> None:
    valid = bytes.fromhex(
        "E010"
        "C00E0102FF880010FF89002001AA01BB"
    )
    entries = _manager_without_init()._parse_key_template_entries(valid)

    assert len(entries) == 1
    assert [component["type"] for component in entries[0]["components"]] == [
        "FF88",
        "FF89",
    ]
    assert entries[0]["key_usage_qualifier"] == "AA"
    assert entries[0]["key_access_condition"] == "BB"

    missing_attributes = bytes.fromhex("E008C0060102FF880010")
    assert _manager_without_init()._parse_key_template_entries(missing_attributes) == []


def test_gp_basic_key_length_zero_is_not_reported_as_zero_bytes() -> None:
    response = bytes.fromhex("E006C00401018800")
    entry = _manager_without_init()._parse_key_template_entries(response)[0]

    assert entry["length"] == ">=256"
    assert entry["components"][0]["length"] == ">=256"


@pytest.mark.parametrize(
    ("i_parameter", "security_level"),
    [
        (0x00, 0x03),
        (0x10, 0x03),
        (0x20, 0x13),
        (0x30, 0x13),
        (0x60, 0x33),
        (0x70, 0x33),
    ],
)
def test_gp_scp03_security_level_tracks_card_capabilities(
    i_parameter: int,
    security_level: int,
) -> None:
    assert (
        GlobalPlatformManager._preferred_scp03_security_level(i_parameter)
        == security_level
    )


def test_gp_scp03_security_level_rejects_reserved_response_mode() -> None:
    with pytest.raises(ValueError, match="reserved"):
        GlobalPlatformManager._preferred_scp03_security_level(0x40)


class _ScriptedConnection:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = list(responses)
        self.calls: list[list[int]] = []

    def transmit(self, command: list[int]) -> tuple[bytes, int, int]:
        self.calls.append(list(command))
        return self.responses.pop(0)


def _transporter(connection: _ScriptedConnection) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.connection = connection
    return transporter


def test_6c_retry_preserves_short_case4_data() -> None:
    command = list(bytes.fromhex("00D6000002AABB00"))
    corrected = CardTransporter._correct_apdu_le(command, 0x10)
    assert bytes(corrected).hex().upper() == "00D6000002AABB10"


def test_6c_retry_encodes_256_correctly_for_extended_apdu() -> None:
    command = list(bytes.fromhex("00D60000000002AABB0000"))
    corrected = CardTransporter._correct_apdu_le(command, 0x00)
    assert bytes(corrected).hex().upper() == "00D60000000002AABB0100"


def test_get_response_honours_6c_without_losing_accumulated_data() -> None:
    connection = _ScriptedConnection(
        [
            (b"\xAA", 0x61, 0x03),
            (b"", 0x6C, 0x02),
            (b"\xBB\xCC", 0x90, 0x00),
        ]
    )
    transporter = _transporter(connection)

    data, sw1, sw2 = transporter._transmit_recursive(
        list(bytes.fromhex("00B0000000"))
    )

    assert bytes(data) == b"\xAA\xBB\xCC"
    assert (sw1, sw2) == (0x90, 0x00)
    assert connection.calls == [
        list(bytes.fromhex("00B0000000")),
        list(bytes.fromhex("00C0000003")),
        list(bytes.fromhex("00C0000002")),
    ]


def test_atr_decoder_reports_truncated_interface_bytes() -> None:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.get_atr_bytes = lambda: bytes.fromhex("3B11")

    assert any("announces TA(1)" in line for line in transporter.describe_atr())


def test_atr_decoder_checks_required_tck() -> None:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.get_atr_bytes = lambda: bytes.fromhex("3B800181")

    assert any(
        "TCK = 81 (correct checksum)" in line
        for line in transporter.describe_atr()
    )


def test_compact_atr_tlv_reports_declared_length_overrun() -> None:
    lines = CardTransporter._decode_compact_tlv_historical(
        bytes.fromhex("8035AA")
    )
    assert any("Malformed compact TLV" in line for line in lines)


def test_atr_card_capability_uses_iso_logical_channel_bit_fields() -> None:
    by_card = CardTransporter._decode_card_capabilities(0x92)
    assert any("assignment: by the card" in line for line in by_card)
    assert any("Maximum number of logical channels: 3" in line for line in by_card)

    by_interface = CardTransporter._decode_card_capabilities(0x0F)
    assert any("assignment: by the interface device" in line for line in by_interface)
    assert any("Maximum number of logical channels: 8 or more" in line for line in by_interface)


def test_auth_response_decoder_parses_ts_31_102_success_vector() -> None:
    decoded = SecurityController._decode_auth_response_data(
        bytes.fromhex(AUTH_TEST_VECTOR["USIM_AUTH_RESPONSE"])
    )

    assert decoded["status"] == "success"
    assert decoded["res"].hex().upper() == AUTH_TEST_VECTOR["RES"]
    assert decoded["ck"].hex().upper() == AUTH_TEST_VECTOR["CK"]
    assert decoded["ik"].hex().upper() == AUTH_TEST_VECTOR["IK"]
    assert decoded["kc"].hex().upper() == AUTH_TEST_VECTOR["Kc"]


def test_auth_response_decoder_parses_sync_failure_and_gsm_lv_fields() -> None:
    auts = bytes.fromhex("00112233445566778899AABBCCDD")
    sync = SecurityController._decode_auth_response_data(
        b"\xDC" + bytes([len(auts)]) + auts
    )
    gsm = SecurityController._decode_auth_response_data(
        bytes.fromhex("0411223344080102030405060708")
    )

    assert sync == {"status": "synchronization_failure", "auts": auts}
    assert gsm["sres"] == bytes.fromhex("11223344")
    assert gsm["kc"] == bytes.fromhex("0102030405060708")


def test_auth_response_decoder_rejects_truncated_lv() -> None:
    with pytest.raises(ValueError, match="CK length"):
        SecurityController._decode_auth_response_data(
            bytes.fromhex("DB04AABBCCDD10AABB")
        )


def test_security_pin_encoder_never_truncates_or_sends_empty_ascii() -> None:
    controller = SecurityController(None)

    assert controller._pad_pin("1234") == "31323334FFFFFFFF"
    with pytest.raises(ValueError, match="must not be empty"):
        controller._pad_pin("")
    with pytest.raises(ValueError, match="at most 8"):
        controller._pad_pin("123456789")
    with pytest.raises(ValueError, match="ASCII"):
        controller._pad_pin("１２３４")
    assert controller._normalize_pin_ref("A") == 0x0A


def test_cli_auth_output_requires_explicit_derived_key_reveal(capsys) -> None:
    controller = SecurityController(None)
    response = bytes.fromhex(
        "DB04A1A2A3A410" + ("11" * 16) + "10" + ("22" * 16)
    )

    controller._parse_auth_response(response)
    redacted = capsys.readouterr().out
    assert "A1A2A3A4" in redacted
    assert "11" * 16 not in redacted
    assert "22" * 16 not in redacted
    assert "redacted" in redacted

    controller._parse_auth_response(response, reveal_sensitive=True)
    revealed = capsys.readouterr().out
    assert "11" * 16 in revealed
    assert "22" * 16 in revealed


def test_stk_tlv_reader_rejects_nonminimal_lengths() -> None:
    with pytest.raises(ValueError, match="Non-minimal"):
        StkController._read_tlv(bytes.fromhex("81810100"), 0)


def test_stk_extra_tlv_parser_rejects_truncated_values() -> None:
    controller = StkController(None)
    with pytest.raises(ValueError, match="malformed"):
        controller._parse_extra_tlvs("8102AA")


def test_stk_proactive_parser_exposes_trailing_data_error() -> None:
    controller = StkController(None)
    command_type, qualifier, fields = controller._parse_proactive_command(
        bytes.fromhex("D0058103010100FF")
    )

    assert (command_type, qualifier) == (None, 0)
    assert "trailing byte" in fields["parse_error"]


def test_stk_proactive_chain_has_a_continuation_limit() -> None:
    controller = StkController(None)
    controller.MAX_PROACTIVE_COMMANDS = 2
    controller._raw_transmit = lambda _apdu, label: (
        (b"", 0x90, 0x00) if "[FETCH]" in label else (b"", 0x91, 0x01)
    )
    controller._parse_proactive_command = lambda _data: (0x02, 0x00, {})
    controller._build_terminal_response = lambda *_args: b""

    with pytest.raises(RuntimeError, match="exceeded 2 proactive commands"):
        controller._drain_proactive_chain("test", 0x91, 0x01)


def test_sgp22_bit_string_decoder_rejects_invalid_padding() -> None:
    manager = Sgp22Manager.__new__(Sgp22Manager)

    assert "unused-bit count" in manager._decode_value(0x03, b"\x08\x00", None)
    assert "non-zero padding" in manager._decode_value(0x03, b"\x03\x07", None)


def test_sgp22_raw_profile_fallback_rejects_nonminimal_ber_length() -> None:
    manager = Sgp22Manager.__new__(Sgp22Manager)
    profile = bytes.fromhex("4F01AA5A01F19F700101")
    malformed = b"\xE3\x81" + bytes([len(profile)]) + profile

    assert manager._scan_profile_blobs_from_raw(malformed) == []


def test_malformed_fcp_replaces_stale_state_with_actionable_error() -> None:
    controller = FileSystemController.__new__(FileSystemController)
    controller.current_fcp = {"template": "FCP", "size": 99}
    controller._parse_fcp_internal(bytes.fromhex("620282"))

    assert controller.current_fcp["template"] == "Unknown"
    assert controller.current_fcp["raw"] == "620282"
    assert "parse_error" in controller.current_fcp


def test_shell_iccid_decoder_rejects_invalid_or_misplaced_fillers() -> None:
    assert ShellDispatcher._decode_iccid_bcd(bytes.fromhex("9876F5")) == "89675"

    with pytest.raises(ValueError, match="Invalid ICCID"):
        ShellDispatcher._decode_iccid_bcd(bytes.fromhex("9A"))
    with pytest.raises(ValueError, match="only valid at the end"):
        ShellDispatcher._decode_iccid_bcd(bytes.fromhex("F598"))


def test_shell_redacts_pin_and_put_key_apdu_payloads() -> None:
    assert ShellDispatcher._redact_apdu_for_display(
        "002000010831323334FFFFFFFF"
    ) == "00200001 [credential payload redacted]"
    assert ShellDispatcher._redact_apdu_for_display(
        "80D8000004DEADBEEF"
    ) == "80D80000 [credential payload redacted]"
    assert ShellDispatcher._redact_apdu_for_display(
        "80E2000004DEADBEEF"
    ) == "80E20000 [credential payload redacted]"
    assert ShellDispatcher._is_sensitive_command_line(
        "80E2000004DEADBEEF"
    ) is True


def test_shell_recognizes_sensitive_macro_expansions() -> None:
    shell = ShellDispatcher.__new__(ShellDispatcher)

    class _Binder:
        @staticmethod
        def resolve(line: str) -> list[str]:
            if line.startswith("adm "):
                return [f"manage-pin verify 0a {line.split()[-1]}"]
            return [line]

    shell.binder = _Binder()

    assert shell._history_line_is_sensitive("adm 12345678") is True
    assert shell._history_line_is_sensitive("HELP") is False


def test_sgp22_oid_decoder_handles_large_second_arc_and_truncation() -> None:
    manager = Sgp22Manager.__new__(Sgp22Manager)

    assert manager._decode_oid(bytes.fromhex("883703")) == "2.999.3"
    assert "truncated subidentifier" in manager._decode_oid(
        bytes.fromhex("2A86")
    )


def test_sgp22_decoders_do_not_hide_invalid_bcd_or_text_bytes() -> None:
    manager = Sgp22Manager.__new__(Sgp22Manager)

    assert manager._decode_bcd_digits(bytes.fromhex("89049032")) == "89049032"
    assert manager._decode_bcd_digits(bytes.fromhex("89A4")) == ""
    assert manager._swap_nibbles("98F7") == "897"
    with pytest.raises(ValueError, match="Invalid BCD"):
        manager._swap_nibbles("9A")
    assert manager._decode_value(0x0C, b"\xFF", None) == "FF"


def test_sgp22_key_info_decoder_renders_every_component() -> None:
    manager = Sgp22Manager.__new__(Sgp22Manager)

    rendered = manager._decode_value(
        0xC0,
        bytes.fromhex("010188108820"),
        0xE0,
    )

    assert "AES/16" in rendered
    assert "AES/32" in rendered

    extended = manager._decode_value(
        0xC0,
        bytes.fromhex("0102FF880010FF89002001AA01BB"),
        0xE0,
    )
    assert "FF88/16" in extended
    assert "FF89/32" in extended
    assert "Usage:AA" in extended
    assert "Access:BB" in extended
    assert "Malformed" in manager._decode_value(
        0xC0,
        bytes.fromhex("0102FF880010"),
        0xE0,
    )


def test_gp_tlv_preview_does_not_display_partial_invalid_utf8(capsys) -> None:
    manager = _manager_without_init()

    manager.print_tlv_data({0x50: b"US\xffIM"})

    rendered = capsys.readouterr().out
    assert "5553FF494D" in rendered
    assert "USIM" not in rendered


def test_ef_dir_decoder_preserves_invalid_label_bytes_as_hex() -> None:
    controller = FileSystemController.__new__(FileSystemController)

    decoded = controller._decode_ef_dir_application_template(
        {
            0x4F: bytes.fromhex("A0000000871002"),
            0x50: b"US\xffIM",
        }
    )

    assert decoded is not None
    assert decoded["label"] == "HEX:5553FF494D"
    assert "USIM" in decoded["aliases"]


def test_smart_app_selection_does_not_match_dropped_invalid_label_bytes() -> None:
    app_template = bytes.fromhex("610D4F05A000000151500447FF534D")

    class _Transport:
        def __init__(self) -> None:
            self.responses = iter(
                [
                    (b"", 0x90, 0x00),
                    (b"", 0x90, 0x00),
                    (app_template, 0x90, 0x00),
                    (b"", 0x6A, 0x83),
                ]
            )

        def transmit(self, _apdu: str, **_kwargs):
            return next(self.responses)

    controller = SecurityController.__new__(SecurityController)
    controller.tp = _Transport()
    controller.fs = None

    assert controller._smart_select_app("GSM") is False
