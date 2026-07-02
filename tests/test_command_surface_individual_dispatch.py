# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import contextlib
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from yggdrasim_common.quit_control import QuitAllRequested


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return

    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")
    atr_module = types.ModuleType("smartcard.ATR")

    class _CardConnection:
        T0_protocol = 0
        T1_protocol = 1
        RAW_protocol = 2

    class _Atr:
        def __init__(self, _raw):
            pass

        @staticmethod
        def getSupportedProtocols():
            return {"T=1": True}

    system_module.readers = lambda: []
    card_connection_module.CardConnection = _CardConnection
    atr_module.ATR = _Atr

    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module
    smartcard_module.ATR = atr_module

    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module
    sys.modules["smartcard.ATR"] = atr_module


_install_smartcard_stubs()

from SCP03.interface.commands import CommandRegistry
from SCP03.interface.shell import ShellDispatcher
from SCP11.console import SCP11Console as RelayConsole
from SCP11.eim_local.main import EimLocalShell
from SCP11.live.console import SCP11Console as LiveConsole
from SCP11.local_access.main import LocalAccessShell, _COMMANDS as LOCAL_ACCESS_COMMANDS
from SCP11.test.console import SCP11Console as RelayTestConsole
from Tools.ProfilePackage.shell import ProfilePackageShell
from Tools.SuciTool.shell import SuciToolShell


class _CallableProxy:
    def __call__(self, *args, **kwargs):
        del args
        del kwargs
        return None

    def __getattr__(self, _name: str):
        return _CallableProxy()


class _DummyCfg:
    RSP_SERVER_URL = "rsp.example.com"
    ES9_BASE_URL = "https://rsp.example.com"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


def _dummy_client() -> SimpleNamespace:
    provider = SimpleNamespace(
        set_base_url=lambda value: None,
        set_verify_tls=lambda enabled: None,
        set_ca_bundle_path=lambda path: None,
    )
    orchestrator = SimpleNamespace(profile_provider=provider)
    return SimpleNamespace(
        cfg=_DummyCfg(),
        apdu_channel=None,
        orchestrator=orchestrator,
    )


def _make_scp03_shell() -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.commands = {}
    shell.transport = None
    shell.prompt_updates = 0
    shell.synced = []
    shell._update_prompt_state = lambda: setattr(
        shell,
        "prompt_updates",
        shell.prompt_updates + 1,
    )
    shell._sync_manual_command = lambda apdu, data: shell.synced.append((apdu, data))
    return shell


class SCP03CommandSurfaceDispatchTests(unittest.TestCase):
    def test_each_registered_command_dispatches_individually(self) -> None:
        command_map = CommandRegistry.build(_CallableProxy())
        required_commands, optional_commands = CommandRegistry.get_arg_requirements()
        required_set = set(required_commands)
        optional_set = set(optional_commands)

        for command_name in sorted(command_map.keys()):
            with self.subTest(command=command_name):
                shell = _make_scp03_shell()
                captured_calls: list[tuple[str, ...]] = []
                shell.commands = {
                    command_name: lambda *args: captured_calls.append(tuple(str(part) for part in args))
                }

                if command_name in required_set or command_name in optional_set:
                    shell._exec_line(f"{command_name} sample-arg")
                    self.assertEqual(captured_calls, [("sample-arg",)])
                else:
                    shell._exec_line(command_name)
                    self.assertEqual(captured_calls, [()])

                self.assertEqual(shell.prompt_updates, 1)


class SCP11ConsoleCommandSurfaceDispatchTests(unittest.TestCase):
    def _assert_console_command_dispatch(self, console_cls, command_name: str) -> None:
        console = console_cls(_dummy_client())
        console._initialize_session = lambda: None
        console._deactivate_locked_help_pane = lambda: None
        captured: list[tuple[str, str]] = []
        console._commands[command_name].handler = (
            lambda argument, current=command_name: captured.append((current, argument)) or True
        )

        with contextlib.redirect_stdout(io.StringIO()):
            console.run_commands(f"{command_name} sample-arg")

        self.assertEqual(captured, [(command_name, "sample-arg")])

    def test_relay_console_dispatches_each_registered_command_token(self) -> None:
        console = RelayConsole(_dummy_client())
        for command_name in sorted(console._commands.keys()):
            with self.subTest(command=command_name):
                self._assert_console_command_dispatch(RelayConsole, command_name)

    def test_live_console_dispatches_each_registered_command_token(self) -> None:
        console = LiveConsole(_dummy_client())
        for command_name in sorted(console._commands.keys()):
            with self.subTest(command=command_name):
                self._assert_console_command_dispatch(LiveConsole, command_name)

    def test_test_console_dispatches_each_registered_command_token(self) -> None:
        console = RelayTestConsole(_dummy_client())
        for command_name in sorted(console._commands.keys()):
            with self.subTest(command=command_name):
                self._assert_console_command_dispatch(RelayTestConsole, command_name)


class LocalAccessCommandSurfaceDispatchTests(unittest.TestCase):
    _COMMAND_CASES = {
        "CERTS": ("_cmd_certs", ["sample-arg"], [["sample-arg"]]),
        "SMDP-CERTS": ("_cmd_certs", ["sample-arg"], [["sample-arg"]]),
        # SCP11 command harmonisation: SCAN is the primary, INFO is its
        # alias and renders the quick card overview instead of the full
        # SGP.32 consolidated dump that DISCOVER (and EIM-DISCOVER) emit.
        "SCAN": ("_cmd_scan", ["sample-arg"], [None]),
        "INFO": ("_cmd_scan", ["sample-arg"], [None]),
        "DISCOVER": ("_cmd_discover", ["sample-arg"], [None]),
        "EIM-DISCOVER": ("_cmd_discover", ["sample-arg"], [None]),
        "EXPLAIN-LAST": ("_cmd_explain_last", ["sample-arg"], [["sample-arg"]]),
        "LIST": ("_cmd_list", ["sample-arg"], [None]),
        "LOAD-PROFILE": ("_cmd_load_profile", ["sample-arg"], [["sample-arg"]]),
        "ENABLE-PROFILE": ("_cmd_enable_profile", ["sample-arg"], [["sample-arg"]]),
        "ENABLE": ("_cmd_enable_profile", ["sample-arg"], [["sample-arg"]]),
        "DISABLE-PROFILE": ("_cmd_disable_profile", ["sample-arg"], [["sample-arg"]]),
        "DISABLE": ("_cmd_disable_profile", ["sample-arg"], [["sample-arg"]]),
        "DELETE-PROFILE": ("_cmd_delete_profile", ["sample-arg"], [["sample-arg"]]),
        "DELETE": ("_cmd_delete_profile", ["sample-arg"], [["sample-arg"]]),
        "STORE-METADATA": ("_cmd_store_metadata", ["sample-arg"], [["sample-arg"]]),
        "STORE-METADATA-CUSTOM": (
            "_cmd_store_metadata_custom",
            ["sample-arg"],
            [["sample-arg"]],
        ),
        "STORE-METADATA-CUSTOM-ALL": (
            "_cmd_store_metadata_custom_all",
            ["sample-arg"],
            [["sample-arg"]],
        ),
        "UPDATE-METADATA": ("_cmd_update_metadata", ["sample-arg"], [["sample-arg"]]),
        "PROFILE": ("_cmd_profile", ["sample-arg"], [["sample-arg"]]),
        "PROFILE-CLEAR": ("_cmd_profile_clear", [], [None]),
        "METADATA": ("_cmd_metadata", ["sample-arg"], [["sample-arg"]]),
        "METADATA-LINT": ("_cmd_metadata_lint", ["sample-arg"], [["sample-arg"]]),
        "METADATA-CLEAR": ("_cmd_metadata_clear", [], [None]),
        "RECORD": ("_cmd_record", ["sample-arg"], [["sample-arg"]]),
        "EXPORT-KEYBAG": ("_cmd_export_keybag", ["sample-arg"], [["sample-arg"]]),
        "STATUS": ("_print_status", [], [None]),
        "HELP": ("_cmd_help", ["sample-arg"], [["sample-arg"]]),
    }

    def test_local_access_cases_cover_all_declared_command_tokens(self) -> None:
        covered = set(self._COMMAND_CASES.keys()) | {"EXIT", "QA"}
        self.assertEqual(covered, set(LOCAL_ACCESS_COMMANDS))

    def test_each_non_exit_local_access_command_dispatches_individually(self) -> None:
        for command_name, (target_name, arguments, expected_calls) in sorted(self._COMMAND_CASES.items()):
            with self.subTest(command=command_name):
                shell = LocalAccessShell()
                recorded_calls: list[object] = []

                if expected_calls == [None]:
                    setattr(shell, target_name, lambda: recorded_calls.append(None))
                else:
                    setattr(
                        shell,
                        target_name,
                        lambda payload: recorded_calls.append(list(payload)),
                    )

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._execute_command(command_name, list(arguments))

                self.assertTrue(keep_running)
                self.assertEqual(recorded_calls, expected_calls)

    def test_exit_aliases_close_session_and_stop_dispatch(self) -> None:
        for command_name in ("EXIT", "QUIT", "Q"):
            with self.subTest(command=command_name):
                shell = LocalAccessShell()
                close_calls: list[str] = []
                shell._close_session_quietly = lambda: close_calls.append(command_name)

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._execute_command(command_name, [])

                self.assertFalse(keep_running)
                self.assertEqual(close_calls, [command_name])

    def test_qa_closes_session_and_raises_global_quit(self) -> None:
        shell = LocalAccessShell()
        close_calls: list[str] = []
        shell._close_session_quietly = lambda: close_calls.append("QA")

        with mock.patch(
            "SCP11.local_access.main.quit_all",
            side_effect=QuitAllRequested(),
        ):
            with self.assertRaises(QuitAllRequested):
                with contextlib.redirect_stdout(io.StringIO()):
                    shell._execute_command("QA", [])

        self.assertEqual(close_calls, ["QA"])


class EimLocalCommandSurfaceDispatchTests(unittest.TestCase):
    @staticmethod
    def _build_shell() -> EimLocalShell:
        fake_session = SimpleNamespace(apdu_channel=None)
        with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=fake_session):
            return EimLocalShell()

    def test_each_canonical_eim_local_command_dispatches_individually(self) -> None:
        shell = self._build_shell()
        for command_name in sorted(shell._commands.keys()):
            with self.subTest(command=command_name):
                shell = self._build_shell()
                captured: list[tuple[str, str]] = []
                shell._commands[command_name] = (
                    lambda argument, current=command_name: captured.append((current, argument))
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._execute_command_line(f"{command_name} sample-arg")

                self.assertTrue(keep_running)
                self.assertEqual(captured, [(command_name, "sample-arg")])

    def test_each_eim_local_alias_dispatches_to_canonical_command(self) -> None:
        shell = self._build_shell()
        for alias_name, canonical_name in sorted(shell._command_aliases.items()):
            with self.subTest(alias=alias_name, canonical=canonical_name):
                shell = self._build_shell()
                captured: list[tuple[str, str]] = []
                shell._commands[canonical_name] = (
                    lambda argument, current=canonical_name: captured.append((current, argument))
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._execute_command_line(f"{alias_name} sample-arg")

                self.assertTrue(keep_running)
                self.assertEqual(captured, [(canonical_name, "sample-arg")])


class ProfilePackageCommandSurfaceDispatchTests(unittest.TestCase):
    def test_each_registered_profile_package_command_token_dispatches_individually(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(ProfilePackageShell, "_setup_readline", lambda self: None):
                shell = ProfilePackageShell(workspace_root=Path(temp_dir))
                command_names = list(shell._commands.keys())

            for command_name in sorted(command_names):
                with self.subTest(command=command_name):
                    with mock.patch.object(ProfilePackageShell, "_setup_readline", lambda self: None):
                        shell = ProfilePackageShell(workspace_root=Path(temp_dir))
                    shell._print_banner = lambda: None
                    captured: list[tuple[str, str]] = []
                    shell._commands[command_name] = (
                        lambda argument, current=command_name: captured.append((current, argument))
                    )

                    with contextlib.redirect_stdout(io.StringIO()):
                        shell.run_commands(f"{command_name} sample-arg")

                    self.assertEqual(captured, [(command_name, "sample-arg")])


class SuciToolCommandSurfaceDispatchTests(unittest.TestCase):
    def test_each_registered_suci_tool_command_token_dispatches_individually(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            shell = SuciToolShell(workspace_root=Path(temp_dir))
            command_names = list(shell._commands.keys())

            for command_name in sorted(command_names):
                with self.subTest(command=command_name):
                    shell = SuciToolShell(workspace_root=Path(temp_dir))
                    shell._print_banner = lambda: None
                    captured: list[tuple[str, str]] = []
                    shell._commands[command_name] = (
                        lambda argument, current=command_name: captured.append((current, argument))
                    )

                    with contextlib.redirect_stdout(io.StringIO()):
                        shell.run_commands(f"{command_name} sample-arg")

                    self.assertEqual(captured, [(command_name, "sample-arg")])


if __name__ == "__main__":
    unittest.main()
