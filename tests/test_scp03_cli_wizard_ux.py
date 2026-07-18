# SPDX-License-Identifier: GPL-3.0-or-later
"""Correctness and usability regressions for SCP03 terminal wizards."""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from SCP03.config import Config
from SCP03.interface.shell_wizards import ShellInteractiveWizards
from SCP03.interface.stk_shell import StkShell
from SCP03.interface.wizards import InteractiveWizards
from SCP03.interface.wizards_ui import InteractiveWizard
from SCP03.logic.fs import FileSystemController


COLORS = SimpleNamespace(
    HEADER="",
    ENDC="",
    CYAN="",
    GREEN="",
    WARNING="",
    FAIL="",
    BOLD="",
)


def _run_wizard(wizard: InteractiveWizard, answers: list[str]):
    with patch("builtins.input", side_effect=answers):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = wizard.run()
    return result, output.getvalue()


def test_bool_prompt_accepts_words_and_retries_typos() -> None:
    wizard = InteractiveWizard("Boolean", COLORS)
    wizard.add_step("execute", "Execute? [y/N]:", default=False, is_bool=True)

    result, output = _run_wizard(wizard, ["maybe", "yes"])

    assert result == {"execute": True}
    assert "Enter Y/YES or N/NO" in output


def test_explicit_text_kind_allows_friendly_pin_reference() -> None:
    wizard = InteractiveWizard("PIN", COLORS)
    wizard.add_step(
        "pin_id",
        "PIN ID [Hex/name, Default: 01]:",
        default="01",
        input_kind="text",
    )

    result, _output = _run_wizard(wizard, ["ADM1"])

    assert result == {"pin_id": "ADM1"}
    assert InteractiveWizard._looks_like_hex_prompt("PIN ID [Hex/name]") is False


def test_secret_value_is_masked_and_never_echoed() -> None:
    wizard = InteractiveWizard("Secret", COLORS)
    wizard.add_step(
        "key",
        "Key [Hex]:",
        input_kind="hex",
        secret=True,
        is_mandatory=True,
    )

    with patch("SCP03.interface.wizards_ui.getpass.getpass", return_value="00:11"):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = wizard.run()

    assert result == {"key": "0011"}
    assert "0011" not in output.getvalue()
    assert "00:11" not in output.getvalue()
    assert "<hidden>" in output.getvalue()


@pytest.mark.parametrize("cancel_value", ["CANCEL", "/abort"])
def test_cancel_words_abort_without_results(cancel_value: str) -> None:
    wizard = InteractiveWizard("Cancel", COLORS)
    wizard.add_step("value", "Value:", is_mandatory=True)

    result, output = _run_wizard(wizard, [cancel_value])

    assert result is None
    assert "no action taken" in output


def test_keyboard_interrupt_is_a_clean_cancel() -> None:
    wizard = InteractiveWizard("Cancel", COLORS)
    wizard.add_step("value", "Value:", is_mandatory=True)

    with patch("builtins.input", side_effect=KeyboardInterrupt):
        with contextlib.redirect_stdout(io.StringIO()):
            assert wizard.run() is None


def test_skip_sentinel_remains_safe_for_legacy_callers() -> None:
    wizard = InteractiveWizard("Skip", COLORS)
    wizard.add_step("optional", "Optional [Hex]:", default="SKIP")

    result, _output = _run_wizard(wizard, [""])

    assert result == {"optional": "SKIP"}


@pytest.mark.parametrize(
    "entered",
    [
        "0xAA:bb",
        "0xAA-bb",
        "0xAA_bb",
        "0xAA bb",
    ],
)
def test_hex_input_accepts_common_separators_and_normalizes(entered: str) -> None:
    wizard = InteractiveWizard("Hex", COLORS)
    wizard.add_step("value", "Value:", input_kind="hex", is_mandatory=True)

    result, _output = _run_wizard(wizard, [entered])

    assert result == {"value": "AABB"}


@pytest.mark.parametrize(
    "tlv_hex",
    [
        "808100",
        "808101AA",
        "80820080" + ("AA" * 128),
    ],
)
def test_wizard_tlv_validator_rejects_nonminimal_ber_lengths(
    tlv_hex: str,
) -> None:
    validator = ShellInteractiveWizards._single_byte_tlv_validator(
        "TLV",
        (0x80,),
    )

    assert "non-minimal" in str(validator(tlv_hex))


class _PinController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def verify_pin(self, *args: str) -> None:
        self.calls.append(("verify", args))

    def change_pin(self, *args: str) -> None:
        self.calls.append(("change", args))

    def disable_pin(self, *args: str) -> None:
        self.calls.append(("disable", args))

    def enable_pin(self, *args: str) -> None:
        self.calls.append(("enable", args))

    def unblock_pin(self, *args: str) -> None:
        self.calls.append(("unblock", args))


def test_manage_pin_wizard_uses_masked_input_and_accepts_named_reference() -> None:
    shell = SimpleNamespace(sec_ctrl=_PinController())
    normal_answers = iter(["1", "ADM1", "1"])

    with patch("builtins.input", lambda _prompt="": next(normal_answers)):
        with patch(
            "SCP03.interface.wizards_ui.getpass.getpass",
            return_value="1234",
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                ShellInteractiveWizards.run_manage_pin_wizard(shell)

    assert shell.sec_ctrl.calls == [("verify", ("ADM1", "1234", "ascii"))]
    assert "1234" not in output.getvalue()


def test_manage_pin_wizard_requires_confirmation_for_state_change() -> None:
    shell = SimpleNamespace(sec_ctrl=_PinController())
    normal_answers = iter(["2", "01", "1", "no"])

    with patch("builtins.input", lambda _prompt="": next(normal_answers)):
        with patch(
            "SCP03.interface.wizards_ui.getpass.getpass",
            side_effect=["1234", "5678"],
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                ShellInteractiveWizards.run_manage_pin_wizard(shell)

    assert shell.sec_ctrl.calls == []
    assert "PIN state change aborted by user" in output.getvalue()
    assert "1234" not in output.getvalue()
    assert "5678" not in output.getvalue()


def test_manage_pin_macro_rejects_missing_credentials_before_transmit() -> None:
    shell = SimpleNamespace(sec_ctrl=_PinController())

    with contextlib.redirect_stdout(io.StringIO()) as output:
        ShellInteractiveWizards.run_manage_pin_wizard(shell, "change 01 1234")

    assert shell.sec_ctrl.calls == []
    assert "requires a PIN reference" in output.getvalue()


def test_manage_pin_macro_accepts_encoding_option_after_reference() -> None:
    shell = SimpleNamespace(sec_ctrl=_PinController())

    with contextlib.redirect_stdout(io.StringIO()):
        ShellInteractiveWizards.run_manage_pin_wizard(
            shell,
            "verify 0A --encoding=hex 1234",
        )

    assert shell.sec_ctrl.calls == [("verify", ("0A", "1234", "hex"))]


@pytest.mark.parametrize("option", ["--unknown", "--encoding"])
def test_manage_pin_macro_rejects_bad_encoding_options(option: str) -> None:
    shell = SimpleNamespace(sec_ctrl=_PinController())

    with contextlib.redirect_stdout(io.StringIO()):
        ShellInteractiveWizards.run_manage_pin_wizard(
            shell,
            f"verify 0A 1234 {option}",
        )

    assert shell.sec_ctrl.calls == []


def test_profile_state_change_requires_explicit_confirmation() -> None:
    calls: list[str] = []
    shell = SimpleNamespace(
        _handle_delete_profile=lambda target: calls.append(target),
        _handle_reset=lambda: calls.append("reset"),
    )
    answers = iter(["2", "5", "profile-alias", "no"])

    with patch("builtins.input", lambda _prompt="": next(answers)):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            ShellInteractiveWizards.run_manage_profile_wizard(shell)

    assert calls == []
    assert "aborted by user" in output.getvalue()


def test_configuration_secret_is_not_saved_without_confirmation() -> None:
    calls: list[tuple[str, str]] = []
    shell = SimpleNamespace(
        _update_config=lambda key, value: calls.append((key, value)),
    )
    answers = iter(["1", "no"])

    with patch("builtins.input", lambda _prompt="": next(answers)):
        with patch(
            "SCP03.interface.wizards_ui.getpass.getpass",
            return_value="00112233445566778899AABBCCDDEEFF",
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                ShellInteractiveWizards.run_config_wizard(shell)

    assert calls == []
    assert "00112233445566778899AABBCCDDEEFF" not in output.getvalue()


def test_put_key_replace_does_not_prompt_for_an_ignored_new_key_id() -> None:
    key = "00112233445566778899AABBCCDDEEFF"
    shell = SimpleNamespace()
    answers = iter(["3", "01", "02", "03", "AES", "no"])

    with patch("builtins.input", lambda _prompt="": next(answers)):
        with patch(
            "SCP03.interface.wizards_ui.getpass.getpass",
            side_effect=[key, key, key],
        ):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                ShellInteractiveWizards.run_put_key_wizard(shell)

    assert "Execution aborted by user" in output.getvalue()
    assert key not in output.getvalue()


def test_file_system_delete_requires_explicit_confirmation() -> None:
    deleted: list[str] = []
    fs_ctrl = SimpleNamespace(delete_file=lambda target: deleted.append(target))
    shell = SimpleNamespace(fs_ctrl=fs_ctrl)
    answers = iter(["6", "6F07", "no"])

    with patch("builtins.input", lambda _prompt="": next(answers)):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            ShellInteractiveWizards.run_fs_admin_wizard(shell)

    assert deleted == []
    assert "aborted by user" in output.getvalue()


def test_linear_fixed_fcp_contains_record_count_in_file_descriptor() -> None:
    answers = iter(
        [
            "3",  # Linear fixed
            "3F007F106F3A",
            "8C0100",
            "",  # no SFI
            "0026",
            "04",
            "",  # no proprietary information
        ]
    )
    with patch("builtins.input", lambda _prompt="": next(answers)):
        with contextlib.redirect_stdout(io.StringIO()):
            result = ShellInteractiveWizards._build_fcp_template()

    assert "82054221002604" in result["fcp"]
    assert result["file_size"] == 0x26 * 4
    assert result["rec_len"] == 0x26
    assert result["num_rec"] == 4


class _RecordingTransport:
    def __init__(self) -> None:
        self.apdus: list[str] = []

    def transmit(self, apdu: str):
        self.apdus.append(apdu)
        return b"", 0x90, 0x00


def _fs_controller() -> tuple[FileSystemController, _RecordingTransport]:
    transport = _RecordingTransport()
    controller = FileSystemController.__new__(FileSystemController)
    controller.tp = transport
    return controller, transport


@pytest.mark.parametrize(
    ("method_name", "header"),
    [
        ("create_file", "00E00000"),
        ("resize_file", "80D40000"),
        ("search_record", "00A20104"),
    ],
)
def test_fs_writes_use_extended_case3_lc_above_255_bytes(
    method_name: str,
    header: str,
) -> None:
    controller, transport = _fs_controller()
    payload = "AA" * 256

    getattr(controller, method_name)(payload)

    assert transport.apdus == [f"{header}000100{payload}"]


def test_fs_write_uses_short_lc_at_255_bytes() -> None:
    controller, transport = _fs_controller()
    payload = "AA" * 255

    controller.create_file(payload)

    assert transport.apdus == [f"00E00000FF{payload}"]


@pytest.mark.parametrize("payload", ["", "A", "ZZ"])
def test_fs_write_rejects_invalid_payload_before_transmit(payload: str) -> None:
    controller, transport = _fs_controller()

    with pytest.raises(ValueError):
        controller.create_file(payload)

    assert transport.apdus == []


def test_fs_write_rejects_payload_over_extended_apdu_limit() -> None:
    controller, transport = _fs_controller()

    with pytest.raises(ValueError, match="65535-byte"):
        controller.resize_file("AA" * 65536)

    assert transport.apdus == []


def test_dgi_patch_replaces_only_matching_tlv_and_recomputes_length() -> None:
    base = "3F00075A01AA9F3301BB"

    result = InteractiveWizards._patch_dgi(base, "5A01CC")

    assert result == "3F00079F3301BB5A01CC"


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "80",
        "82FF",
        "83000100",
        "820001",
    ],
)
def test_ber_length_decoder_rejects_unsafe_forms(encoded: str) -> None:
    with pytest.raises(ValueError):
        InteractiveWizards._decode_ber_tlv_length(encoded)


def test_tlv_removal_supports_multibyte_high_tag_number() -> None:
    payload = "9F810101AA5A01BB"

    result = InteractiveWizards._remove_tag_from_payload(payload, "9F8101")

    assert result == "5A01BB"


@pytest.mark.parametrize("encoded", ["0000", "FF0100", "1F1E00", "9F81"])
def test_wizard_tlv_parser_rejects_reserved_or_nonminimal_tags(encoded: str) -> None:
    with pytest.raises(ValueError):
        InteractiveWizards._extract_tag_from_tlv(encoded)


def test_tlv_removal_rejects_truncated_value() -> None:
    with pytest.raises(ValueError, match="exceeds the remaining payload"):
        InteractiveWizards._remove_tag_from_payload("5A02AA", "5A")


def test_malformed_dgi_is_not_reconstructed() -> None:
    with contextlib.redirect_stdout(io.StringIO()) as output:
        result = InteractiveWizards._patch_dgi("3F00055A01AA", "5A01CC")

    assert result == ""
    assert "declares 5 bytes" in output.getvalue()


def test_flat_tag_builder_does_not_prompt_for_value_when_not_selected() -> None:
    with patch("builtins.input", side_effect=["no"]):
        with contextlib.redirect_stdout(io.StringIO()):
            result = InteractiveWizards._prompt_flat_tag("42", "Issuer ID")

    assert result == ""


def test_tag_67_builder_encodes_scp_fields_and_additional_tlv_stream() -> None:
    answers = ["yes", "03", "7071", "", "9F3301AA"]

    with patch("builtins.input", side_effect=answers):
        with contextlib.redirect_stdout(io.StringIO()):
            result = InteractiveWizards._build_tag_67()

    assert result == "670DA007800103810270719F3301AA"


def test_tag_67_builder_retries_truncated_capability_tlv() -> None:
    answers = ["no", "5A02AA", "5A01BB"]

    with patch("builtins.input", side_effect=answers):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = InteractiveWizards._build_tag_67()

    assert result == "67035A01BB"
    assert "length exceeds the remaining payload" in output.getvalue()


class _StkController:
    def __init__(self) -> None:
        self.state = SimpleNamespace(
            initialized=True,
            open_channel_active=False,
        )
        self.debug = False

    def format_state_lines(self):
        return []

    def format_history_lines(self):
        return []


def test_stk_exit_returns_to_parent_shell_without_system_exit() -> None:
    shell = StkShell(SimpleNamespace())
    shell.controller = _StkController()

    with contextlib.redirect_stdout(io.StringIO()):
        shell.run_commands("EXIT; HELP")

    assert shell._exit_requested is True


def test_real_colors_support_new_wizard_status_messages() -> None:
    # Guard against adding a wizard color attribute not present in packaged config.
    assert all(
        hasattr(Config.Colors, name)
        for name in ("HEADER", "ENDC", "CYAN", "GREEN", "WARNING", "BOLD")
    )
