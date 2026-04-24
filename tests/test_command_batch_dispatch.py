import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from SCP11.console import SCP11Console as RelayConsole
from SCP11.eim_local.main import EimLocalShell
from SCP11.live.console import SCP11Console as LiveConsole
from SCP11.local_access.main import LocalAccessShell
from SCP11.test.console import SCP11Console as RelayTestConsole
from Tools.ProfilePackage.shell import ProfilePackageShell
from Tools.SuciTool.shell import SuciToolShell


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


class CommandBatchDispatchTests(unittest.TestCase):
    @staticmethod
    def _build_eim_shell() -> EimLocalShell:
        fake_session = SimpleNamespace(apdu_channel=None)
        with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=fake_session):
            return EimLocalShell()

    def _exercise_scp11_console(self, console_cls) -> None:
        console = console_cls(_dummy_client())
        console._initialize_session = lambda: None
        console._deactivate_locked_help_pane = lambda: None
        recorded: list[str] = []
        expected = list(console._primary_commands)
        for command_name in expected:
            spec = console._commands[command_name]

            def _handler(argument: str, name: str = command_name) -> bool:
                recorded.append(name)
                return True

            spec.handler = _handler
        console.run_commands("; ".join(expected))
        self.assertEqual(recorded, expected)

    def test_relay_console_run_commands_dispatches_all_primary_commands(self) -> None:
        self._exercise_scp11_console(RelayConsole)

    def test_live_console_run_commands_dispatches_all_primary_commands(self) -> None:
        self._exercise_scp11_console(LiveConsole)

    def test_test_console_run_commands_dispatches_all_primary_commands(self) -> None:
        self._exercise_scp11_console(RelayTestConsole)

    def test_local_smdpp_run_commands_dispatches_all_documented_commands(self) -> None:
        shell = LocalAccessShell()
        shell._build_session = lambda: None
        recorded: list[str] = []
        command_map = {
            "CERTS": "_cmd_certs",
            "DISCOVER": "_cmd_discover",
            "EXPLAIN-LAST": "_cmd_explain_last",
            "LOAD-PROFILE": "_cmd_load_profile",
            "ENABLE-PROFILE": "_cmd_enable_profile",
            "DISABLE-PROFILE": "_cmd_disable_profile",
            "DELETE-PROFILE": "_cmd_delete_profile",
            "REFRESH-MODEM": "_cmd_refresh_modem",
            "STORE-METADATA": "_cmd_store_metadata",
            "UPDATE-METADATA": "_cmd_update_metadata",
            "STORE-METADATA-CUSTOM": "_cmd_store_metadata_custom",
            "STORE-METADATA-CUSTOM-ALL": "_cmd_store_metadata_custom_all",
            "PROFILE": "_cmd_profile",
            "PROFILE-CLEAR": "_cmd_profile_clear",
            "METADATA": "_cmd_metadata",
            "METADATA-LINT": "_cmd_metadata_lint",
            "METADATA-CLEAR": "_cmd_metadata_clear",
            "RECORD": "_cmd_record",
            "STATUS": "_print_status",
            "HELP": "_cmd_help",
        }
        for command_name, handler_name in command_map.items():
            if handler_name == "_print_status":
                setattr(shell, handler_name, lambda name=command_name: recorded.append(name))
                continue
            setattr(shell, handler_name, lambda arguments=None, name=command_name: recorded.append(name))
        shell.run_commands("; ".join(command_map.keys()))
        self.assertEqual(recorded, list(command_map.keys()))

    def test_local_eim_run_commands_dispatches_all_registered_commands(self) -> None:
        shell = self._build_eim_shell()
        recorded: list[str] = []
        expected = list(shell._commands.keys())
        for command_name in expected:
            shell._commands[command_name] = lambda argument, name=command_name: recorded.append(name)
        shell.run_commands("; ".join(expected))
        self.assertEqual(recorded, expected)

    def test_profile_package_run_commands_dispatches_all_registered_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            shell = ProfilePackageShell(workspace_root=Path(temp_dir))
            recorded: list[str] = []
            expected = list(shell._commands.keys())
            for command_name in expected:
                shell._commands[command_name] = lambda argument, name=command_name: recorded.append(name)
            shell.run_commands("; ".join(expected))
            self.assertEqual(recorded, expected)

    def test_suci_tool_run_commands_dispatches_all_registered_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            shell = SuciToolShell(workspace_root=Path(temp_dir))
            recorded: list[str] = []
            expected = list(shell._commands.keys())
            for command_name in expected:
                shell._commands[command_name] = lambda argument, name=command_name: recorded.append(name)
            shell.run_commands("; ".join(expected))
            self.assertEqual(recorded, expected)


if __name__ == "__main__":
    unittest.main()
