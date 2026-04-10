import contextlib
import io
import os
import unittest
from unittest import mock

import SCP03.main as scp03_main
import SCP11.live.main as scp11_live_main
import SCP11.local_access.main as scp11_local_access_main
import SCP11.relay.main as scp11_relay_main
import SCP11.test.main as scp11_test_main
import SCP11.eim_local.main as scp11_eim_local_main
import SCP80.main as scp80_main
import Tools.ProfilePackage.main as profile_package_main
import Tools.SuciTool.main as suci_tool_main
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV


class CliBatchEntrypointTests(unittest.TestCase):
    def _assert_scp11_entry_route(
        self,
        module,
        argv: list[str],
        expected_route: str,
        *,
        patch_plugins: bool = False,
    ) -> None:
        if patch_plugins:
            plugin_context = mock.patch.object(module, "ensure_plugins_loaded")
        else:
            plugin_context = contextlib.nullcontext()

        with plugin_context:
            with mock.patch.object(module.SGP22Client, "run_commands") as mocked_batch:
                with mock.patch.object(module.SGP22Client, "run_shell") as mocked_shell:
                    with mock.patch.object(module.SGP22Client, "run_flow") as mocked_flow:
                        with mock.patch("sys.argv", argv):
                            module.entry()

        if expected_route == "commands":
            mocked_batch.assert_called_once_with("HELP; EXIT")
            mocked_shell.assert_not_called()
            mocked_flow.assert_not_called()
            return

        if expected_route == "flow":
            mocked_flow.assert_called_once_with()
            mocked_batch.assert_not_called()
            mocked_shell.assert_not_called()
            return

        if expected_route == "shell":
            mocked_shell.assert_called_once_with()
            mocked_batch.assert_not_called()
            mocked_flow.assert_not_called()
            return

        raise AssertionError(f"Unsupported expected route: {expected_route}")

    def test_scp11_live_entry_routes_cmd_to_batch_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_live_main,
            ["prog", "--cmd", "HELP; EXIT"],
            "commands",
            patch_plugins=True,
        )

    def test_scp11_live_entry_accepts_debug_flag_for_batch_mode(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(scp11_live_main, "ensure_plugins_loaded"):
                with mock.patch.object(
                    scp11_live_main.SGP22Client, "run_commands"
                ) as mocked_batch:
                    with mock.patch("sys.argv", ["prog", "--debug", "--cmd", "HELP; EXIT"]):
                        scp11_live_main.entry()
                    debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_batch.assert_called_once_with("HELP; EXIT")

    def test_scp11_live_entry_routes_stdin_to_batch_mode(self) -> None:
        with mock.patch.object(scp11_live_main, "ensure_plugins_loaded"):
            with mock.patch.object(scp11_live_main.SGP22Client, "run_commands") as mocked_batch:
                with mock.patch("sys.argv", ["prog", "--stdin"]):
                    with mock.patch("sys.stdin", io.StringIO("HELP\n# comment\nEXIT\n")):
                        scp11_live_main.entry()
        mocked_batch.assert_called_once_with("HELP; EXIT")

    def test_scp11_live_entry_routes_flow_to_one_shot_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_live_main,
            ["prog", "--flow"],
            "flow",
            patch_plugins=True,
        )

    def test_scp11_live_entry_without_flags_routes_to_shell(self) -> None:
        self._assert_scp11_entry_route(
            scp11_live_main,
            ["prog"],
            "shell",
            patch_plugins=True,
        )

    def test_scp11_test_entry_routes_cmd_to_batch_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_test_main,
            ["prog", "--cmd", "HELP; EXIT"],
            "commands",
            patch_plugins=True,
        )

    def test_scp11_test_entry_routes_flow_to_one_shot_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_test_main,
            ["prog", "--flow"],
            "flow",
            patch_plugins=True,
        )

    def test_scp11_test_entry_without_flags_routes_to_shell(self) -> None:
        self._assert_scp11_entry_route(
            scp11_test_main,
            ["prog"],
            "shell",
            patch_plugins=True,
        )

    def test_scp11_relay_entry_routes_cmd_to_batch_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_relay_main,
            ["prog", "--cmd", "HELP; EXIT"],
            "commands",
        )

    def test_scp11_relay_entry_routes_flow_to_one_shot_mode(self) -> None:
        self._assert_scp11_entry_route(
            scp11_relay_main,
            ["prog", "--flow"],
            "flow",
        )

    def test_scp11_relay_entry_without_flags_routes_to_shell(self) -> None:
        self._assert_scp11_entry_route(
            scp11_relay_main,
            ["prog"],
            "shell",
        )

    def test_local_smdpp_standalone_routes_cmd(self) -> None:
        with mock.patch.object(scp11_local_access_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.argv", ["prog", "--cmd", "HELP; EXIT"]):
                scp11_local_access_main.run_standalone()
        mocked_entry_cmd.assert_called_once_with("HELP; EXIT")

    def test_local_smdpp_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(scp11_local_access_main, "entry_cmd") as mocked_entry_cmd:
                with mock.patch("sys.argv", ["prog", "--debug", "--cmd", "HELP; EXIT"]):
                    scp11_local_access_main.run_standalone()
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("HELP; EXIT")

    def test_local_smdpp_standalone_routes_stdin(self) -> None:
        with mock.patch.object(scp11_local_access_main, "entry_stdin") as mocked_entry_stdin:
            with mock.patch("sys.argv", ["prog", "--stdin"]):
                scp11_local_access_main.run_standalone()
        mocked_entry_stdin.assert_called_once_with()

    def test_local_smdpp_standalone_without_flags_routes_entry(self) -> None:
        with mock.patch.object(scp11_local_access_main, "entry") as mocked_entry:
            with mock.patch("sys.argv", ["prog"]):
                scp11_local_access_main.run_standalone()
        mocked_entry.assert_called_once_with()

    def test_local_eim_standalone_routes_cmd(self) -> None:
        with mock.patch.object(scp11_eim_local_main, "ensure_plugins_loaded"):
            with mock.patch.object(scp11_eim_local_main, "entry_cmd") as mocked_entry_cmd:
                with mock.patch("sys.argv", ["prog", "--cmd", "HELP; EXIT"]):
                    scp11_eim_local_main.run_standalone()
        mocked_entry_cmd.assert_called_once_with("HELP; EXIT")

    def test_local_eim_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(scp11_eim_local_main, "ensure_plugins_loaded"):
                with mock.patch.object(scp11_eim_local_main, "entry_cmd") as mocked_entry_cmd:
                    with mock.patch(
                        "sys.argv",
                        ["prog", "--debug", "--cmd", "HELP; EXIT"],
                    ):
                        scp11_eim_local_main.run_standalone()
                    debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("HELP; EXIT")

    def test_local_eim_standalone_routes_stdin(self) -> None:
        with mock.patch.object(scp11_eim_local_main, "ensure_plugins_loaded"):
            with mock.patch.object(scp11_eim_local_main, "entry_stdin") as mocked_entry_stdin:
                with mock.patch("sys.argv", ["prog", "--stdin"]):
                    scp11_eim_local_main.run_standalone()
        mocked_entry_stdin.assert_called_once_with()

    def test_local_eim_standalone_without_flags_routes_shell(self) -> None:
        with mock.patch.object(scp11_eim_local_main, "ensure_plugins_loaded"):
            with mock.patch.object(scp11_eim_local_main, "EimLocalShell") as mocked_shell_cls:
                with mock.patch("sys.argv", ["prog"]):
                    scp11_eim_local_main.run_standalone()
        mocked_shell_cls.return_value.run.assert_called_once_with()

    def test_scp80_standalone_routes_cmd(self) -> None:
        with mock.patch("SCP80.cli.OtaShell.run_commands", autospec=True) as mocked_batch:
            with mock.patch("sys.argv", ["prog", "--cmd", "help; quit"]):
                scp80_main.run_standalone()
        mocked_batch.assert_called_once()
        self.assertEqual(mocked_batch.call_args.args[1], "help; quit")

    def test_scp80_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch("SCP80.cli.OtaShell.run_commands", autospec=True) as mocked_batch:
                with mock.patch("sys.argv", ["prog", "--debug", "--cmd", "help; quit"]):
                    scp80_main.run_standalone()
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_batch.assert_called_once()
        self.assertEqual(mocked_batch.call_args.args[1], "help; quit")

    def test_scp80_standalone_without_flags_routes_shell(self) -> None:
        with mock.patch("SCP80.cli.OtaShell") as mocked_shell_cls:
            with mock.patch("sys.argv", ["prog"]):
                scp80_main.run_standalone()
        mocked_shell_cls.return_value.run.assert_called_once_with()

    def test_scp03_standalone_routes_stdin(self) -> None:
        with mock.patch.object(scp03_main, "entry_stdin") as mocked_entry_stdin:
            with mock.patch("sys.argv", ["prog", "--stdin"]):
                scp03_main.run_standalone()
        mocked_entry_stdin.assert_called_once_with(yaml_out=None)

    def test_scp03_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(scp03_main, "entry_cmd") as mocked_entry_cmd:
                with mock.patch(
                    "sys.argv",
                    ["prog", "--debug", "--cmd", "AUTH-SD; LIST"],
                ):
                    scp03_main.run_standalone()
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out=None)

    def test_scp03_standalone_without_flags_routes_entry(self) -> None:
        with mock.patch.object(scp03_main, "entry") as mocked_entry:
            with mock.patch("sys.argv", ["prog"]):
                scp03_main.run_standalone()
        mocked_entry.assert_called_once_with()

    def test_profile_package_standalone_routes_stdin(self) -> None:
        with mock.patch.object(profile_package_main, "entry_stdin") as mocked_entry_stdin:
            with mock.patch("sys.argv", ["prog", "--stdin"]):
                profile_package_main.run_standalone()
        mocked_entry_stdin.assert_called_once_with()

    def test_profile_package_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(profile_package_main, "entry_cmd") as mocked_entry_cmd:
                with mock.patch("sys.argv", ["prog", "--debug", "--cmd", "STATUS; EXIT"]):
                    profile_package_main.run_standalone()
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")

    def test_profile_package_standalone_without_flags_routes_entry(self) -> None:
        with mock.patch.object(profile_package_main, "entry") as mocked_entry:
            with mock.patch("sys.argv", ["prog"]):
                profile_package_main.run_standalone()
        mocked_entry.assert_called_once_with()

    def test_suci_tool_standalone_routes_stdin(self) -> None:
        with mock.patch.object(suci_tool_main, "entry_stdin") as mocked_entry_stdin:
            with mock.patch("sys.argv", ["prog", "--stdin"]):
                suci_tool_main.run_standalone()
        mocked_entry_stdin.assert_called_once_with()

    def test_suci_tool_standalone_accepts_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(suci_tool_main, "entry_cmd") as mocked_entry_cmd:
                with mock.patch("sys.argv", ["prog", "--debug", "--cmd", "STATUS; EXIT"]):
                    suci_tool_main.run_standalone()
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")

    def test_suci_tool_standalone_without_flags_routes_entry(self) -> None:
        with mock.patch.object(suci_tool_main, "entry") as mocked_entry:
            with mock.patch("sys.argv", ["prog"]):
                suci_tool_main.run_standalone()
        mocked_entry.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
