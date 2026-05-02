import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from Tools.SuciTool.shell import SuciToolShell
from Tools.SuciTool.tool import SuciCommandResult


class SuciToolShellCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._temp_workspace.name)
        self.shell = SuciToolShell(workspace_root=self.workspace_root)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    @staticmethod
    def _result(command: list[str]) -> SuciCommandResult:
        return SuciCommandResult(
            command=command,
            returncode=0,
            stdout="ok\n",
            stderr="",
        )

    def test_cmd_help_lists_expected_workflow_and_curves(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.shell._cmd_help("")

        rendered = output.getvalue()
        self.assertIn("SUCI Tool commands:", rendered)
        self.assertIn("GENERATE <SECP256R1|CURVE25519>", rendered)
        self.assertIn("DUMP [COMPRESSED]", rendered)
        self.assertIn("curve25519", rendered.lower())

    def test_cmd_tool_sets_override_command(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.shell._cmd_tool("python -m suci_keytool")

        self.assertEqual(self.shell.bridge.get_tool_command(), ["python", "-m", "suci_keytool"])
        self.assertIn("Tool command set to: python -m suci_keytool", output.getvalue())

    def test_cmd_use_sets_active_key_file_inside_workspace(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.shell._cmd_use("keys/demo_suci.key")

        expected_path = (self.workspace_root / "keys" / "demo_suci.key").resolve()
        self.assertEqual(self.shell.bridge.current_key_file, expected_path)
        self.assertIn(str(expected_path), output.getvalue())

    def test_cmd_generate_invokes_bridge_with_normalized_curve(self) -> None:
        recorded_args: list[list[str]] = []
        printed_results: list[SuciCommandResult] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or self._result(
            ["suci-keytool", *args]
        )
        self.shell._print_result = lambda result: printed_results.append(result)

        self.shell._cmd_generate("CURVE25519")

        self.assertEqual(recorded_args, [["generate-key", "--curve", "curve25519"]])
        self.assertEqual(len(printed_results), 1)

    def test_cmd_generate_rejects_unknown_curve(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: GENERATE <SECP256R1\\|CURVE25519>"):
            self.shell._cmd_generate("P-384")

    def test_cmd_dump_invokes_bridge_without_compression_by_default(self) -> None:
        recorded_args: list[list[str]] = []
        printed_results: list[SuciCommandResult] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or self._result(
            ["suci-keytool", *args]
        )
        self.shell._print_result = lambda result: printed_results.append(result)

        self.shell._cmd_dump("")

        self.assertEqual(recorded_args, [["dump-pub-key"]])
        self.assertEqual(len(printed_results), 1)

    def test_cmd_dump_invokes_bridge_with_compression_flag(self) -> None:
        recorded_args: list[list[str]] = []
        self.shell.bridge.run_current = lambda args: recorded_args.append(list(args)) or self._result(
            ["suci-keytool", *args]
        )
        self.shell._print_result = lambda result: None

        self.shell._cmd_dump("COMPRESSED")
        self.shell._cmd_dump("--compressed")

        self.assertEqual(
            recorded_args,
            [
                ["dump-pub-key", "--compressed"],
                ["dump-pub-key", "--compressed"],
            ],
        )

    def test_cmd_dump_rejects_unknown_argument(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: DUMP \\[COMPRESSED\\]"):
            self.shell._cmd_dump("RAW")

    def test_cmd_pwd_reports_workspace_and_selected_key_file(self) -> None:
        selected_key = (self.workspace_root / "keys" / "selected.key").resolve()
        self.shell.bridge.current_key_file = selected_key

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.shell._cmd_pwd("")

        rendered = output.getvalue()
        self.assertIn(f"Workspace: {self.workspace_root}", rendered)
        self.assertIn(f"Key file: {selected_key}", rendered)

    def test_cmd_exit_raises_system_exit(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            self.shell._cmd_exit("")

        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
