import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.quit_control import QuitAllRequested
from Tools.SuciTool.shell import SuciToolShell


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


if __name__ == "__main__":
    unittest.main()
