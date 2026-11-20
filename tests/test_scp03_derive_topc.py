# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""DERIVE-TOPC: the TUAK TOPc derivation on the command line, beside DERIVE-OPC.

The GUI had the derivation (Offline Tools, ``simcard.tuak_derive_topc``) and
the CLI had none. Both now call ``SIMCARD.tuak.derive_topc_from_text``, so they
take and refuse the same input; the derivation itself is pinned against the
TS 35.232 test set in ``tests/test_simcard_tuak_kat.py``.
"""

from __future__ import annotations

import contextlib
import io

import pytest

from SIMCARD.tuak import MAX_KECCAK_ITERATIONS, derive_topc, derive_topc_from_text

TOP_HEX = "5F" * 32
KEY_128_HEX = "AB" * 16
KEY_256_HEX = "CD" * 32


def test_the_shared_function_returns_the_derivation() -> None:
    result = derive_topc_from_text(TOP_HEX, KEY_128_HEX)
    expected = derive_topc(bytes.fromhex(TOP_HEX), bytes.fromhex(KEY_128_HEX), number_of_keccak=1)
    assert result == {"key_length_bits": 128, "number_of_keccak": 1, "topc_hex": expected.hex().upper()}
    deep = derive_topc_from_text(TOP_HEX.lower(), KEY_256_HEX, "3")
    assert deep["key_length_bits"] == 256 and deep["number_of_keccak"] == 3


@pytest.mark.parametrize(
    ("top", "key", "rounds", "message"),
    [
        ("", KEY_128_HEX, None, "top: hex string is empty"),
        ("5F" * 31, KEY_128_HEX, None, "top: length must be one of [32] bytes, got 31"),
        (TOP_HEX, "AB" * 20, None, "key: length must be one of [16, 32] bytes, got 20"),
        (TOP_HEX, "ABC", None, "key: hex string has odd length"),
        (TOP_HEX, KEY_128_HEX, "two", "number_of_keccak: not an integer"),
        (TOP_HEX, KEY_128_HEX, 0, "number_of_keccak must be in [1, 16]"),
        (TOP_HEX, KEY_128_HEX, MAX_KECCAK_ITERATIONS + 1, "number_of_keccak must be in [1, 16]"),
    ],
)
def test_both_surfaces_refuse_the_same_input(top, key, rounds, message) -> None:
    from yggdrasim_common.gui_server.actions.simcard import _dispatch_tuak_derive_topc

    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        derive_topc_from_text(top, key, rounds)
    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        _dispatch_tuak_derive_topc(None, top=top, key=key, number_of_keccak=rounds)


def _shell():
    pytest.importorskip("smartcard")
    from SCP03.interface.shell import ShellDispatcher

    return ShellDispatcher.__new__(ShellDispatcher)


def _run(shell, argument: str) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        shell._handle_derive_topc(argument)
    return buffer.getvalue()


def test_the_verb_prints_the_topc() -> None:
    expected = derive_topc_from_text(TOP_HEX, KEY_256_HEX, 2)["topc_hex"]
    printed = _run(_shell(), f"{TOP_HEX} {KEY_256_HEX} 2")
    assert f"TOPc: {expected}" in printed
    assert "K of 256 bits, 2 Keccak iteration(s)." in printed


@pytest.mark.parametrize("argument", ["", TOP_HEX, f"{TOP_HEX} {KEY_128_HEX} 1 extra", f"{TOP_HEX} AB"])
def test_a_refused_input_prints_a_failure_line(argument: str) -> None:
    from yggdrasim_common.batch_outcome import is_failure_line

    printed = _run(_shell(), argument)
    assert any(is_failure_line(line) for line in printed.splitlines()), printed
    assert "TOPc:" not in printed


def test_the_verb_is_registered_helped_and_kept_out_of_history() -> None:
    pytest.importorskip("smartcard")
    from SCP03.interface import shell as shell_module
    from SCP03.interface.commands import CommandRegistry
    from SCP03.interface.help_menu import HelpMenu

    assert "DERIVE-TOPC" in shell_module.CREDENTIAL_COMMANDS
    assert "DERIVE-TOPC" in shell_module.HISTORY_SENSITIVE_COMMANDS
    assert "DERIVE-TOPC" in CommandRegistry.get_arg_requirements()[0]
    assert shell_module.ShellDispatcher._is_credential_command_line(f"DERIVE-TOPC {TOP_HEX} {KEY_128_HEX}")
    help_text = io.StringIO()
    with contextlib.redirect_stdout(help_text):
        HelpMenu.print_help()
    assert "DERIVE-TOPC" in help_text.getvalue()
    source = shell_module.__file__.replace("shell.py", "commands.py")
    with open(source, encoding="utf-8") as handle:
        assert '"DERIVE-TOPC": (shell._handle_derive_topc,' in handle.read()
