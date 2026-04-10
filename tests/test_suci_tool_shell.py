import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.quit_control import QuitAllRequested
from Tools.SuciTool.shell import SuciToolShell
from Tools.SuciTool.tool import SuciCommandResult


class SuciToolShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        workspace_root = Path(self._temp_workspace.name)
        self.shell = SuciToolShell(workspace_root=workspace_root)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_status_uses_concise_key_file_summary(self) -> None:
        self.shell.bridge.current_key_file = (
            self.shell.bridge.workspace_root / "keys" / "demo_suci.key"
        )

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_status("")

        text = captured.getvalue()
        self.assertIn("Active key file: keys/demo_suci.key", text)
        self.assertNotIn("tool=", text)
        self.assertNotIn("key_file=", text)

    def test_cmd_tool_without_argument_shows_tool_command_only(self) -> None:
        self.shell.bridge._tool_command = ["suci-keytool.py", "--demo"]

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            self.shell._cmd_tool("")

        text = captured.getvalue()
        self.assertIn("Tool command: suci-keytool.py --demo", text)
        self.assertNotIn("Active key file:", text)

    def test_cmd_quit_all_raises_quit_all_requested(self) -> None:
        with self.assertRaises(QuitAllRequested):
            self.shell._cmd_quit_all("")

    def test_print_result_reports_success_and_stderr(self) -> None:
        result = SuciCommandResult(
            command=["suci-keytool.py", "--key-file", "demo.key", "dump-pub-key"],
            returncode=0,
            stdout="public-key\n",
            stderr="warning\n",
        )
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            self.shell._print_result(result)

        rendered = buffer.getvalue()
        self.assertIn("public-key", rendered)
        self.assertIn("warning", rendered)
        self.assertIn("Command completed successfully", rendered)

    def test_print_result_reports_nonzero_exit_code(self) -> None:
        result = SuciCommandResult(
            command=["suci-keytool.py", "--key-file", "demo.key", "dump-pub-key"],
            returncode=2,
            stdout="",
            stderr="failed\n",
        )
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            self.shell._print_result(result)

        rendered = buffer.getvalue()
        self.assertIn("failed", rendered)
        self.assertIn("exited with code 2", rendered)

    def test_exec_line_reports_unknown_command(self) -> None:
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            self.shell._exec_line("wat")

        self.assertIn("Unknown command: WAT", buffer.getvalue())

    def test_run_commands_stops_after_exit(self) -> None:
        recorded: list[str] = []
        self.shell._print_banner = lambda: None
        self.shell._commands["STATUS"] = lambda argument: recorded.append("STATUS")
        self.shell._commands["HELP"] = lambda argument: recorded.append("HELP")

        def _raise_exit(_argument: str) -> None:
            raise SystemExit(0)

        self.shell._commands["EXIT"] = _raise_exit

        self.shell.run_commands("STATUS; EXIT; HELP")

        self.assertEqual(recorded, ["STATUS"])


if __name__ == "__main__":
    unittest.main()
