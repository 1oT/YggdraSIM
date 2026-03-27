import subprocess
import unittest
from pathlib import Path

from Tools.SuciTool.tool import SuciKeyToolBridge


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command):
        normalized = [str(part) for part in command]
        self.commands.append(normalized)
        return subprocess.CompletedProcess(normalized, 0, stdout="ok\n", stderr="")


class SuciKeyToolBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace_root = Path(__file__).resolve().parents[1]
        self.runner = FakeRunner()
        self.bridge = SuciKeyToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["suci-keytool.py"],
        )

    def test_run_current_builds_expected_command(self) -> None:
        key_file = self.workspace_root / "tests" / "tmp_suci.key"
        self.bridge.set_key_file(str(key_file))

        result = self.bridge.run_current(["generate-key", "--curve", "secp256r1"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            self.runner.commands[0],
            [
                "suci-keytool.py",
                "--key-file",
                str(key_file),
                "generate-key",
                "--curve",
                "secp256r1",
            ],
        )

    def test_resolve_path_rejects_outside_workspace(self) -> None:
        outside_path = self.workspace_root.parent / "outside.key"

        with self.assertRaises(ValueError):
            self.bridge.resolve_path(str(outside_path), must_exist=False)

    def test_set_key_file_accepts_nonexistent_workspace_file(self) -> None:
        key_file = self.bridge.set_key_file("tests/generated_suci.key")
        self.assertTrue(str(key_file).startswith(str(self.workspace_root)))


if __name__ == "__main__":
    unittest.main()
