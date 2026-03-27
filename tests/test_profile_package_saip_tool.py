import subprocess
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_tool import SaipToolBridge


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command):
        normalized = [str(part) for part in command]
        self.commands.append(normalized)
        return subprocess.CompletedProcess(normalized, 0, stdout="ok\n", stderr="")


class SaipToolBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._temp_workspace.name)
        self.runner = FakeRunner()
        self.bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
        )

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_run_current_builds_expected_command(self) -> None:
        input_file = Path(__file__).resolve()
        self.bridge.set_input_file(str(input_file))

        result = self.bridge.run_current(["info", "--apps"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            self.runner.commands[0],
            ["saip-tool.py", str(input_file), "info", "--apps"],
        )

    def test_run_current_converts_hex_text_input_to_cached_der(self) -> None:
        hex_input = self.workspace_root / "tests" / "profile_package_hex_input.txt"
        hex_input.parent.mkdir(parents=True, exist_ok=True)
        hex_input.write_text("DE AD BE EF\n", encoding="utf-8")
        try:
            self.bridge.set_input_file(str(hex_input))
            self.bridge.run_current(["tree"])
            prepared_input = Path(self.runner.commands[0][1])
            self.assertEqual(prepared_input.suffix, ".der")
            self.assertNotEqual(prepared_input, hex_input)
            self.assertTrue(prepared_input.exists())
            self.assertEqual(prepared_input.read_bytes(), bytes.fromhex("DEADBEEF"))
        finally:
            if hex_input.exists():
                hex_input.unlink()

    def test_set_input_file_allows_existing_absolute_path_outside_workspace(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".der") as handle:
            resolved = self.bridge.set_input_file(handle.name)
            self.assertEqual(resolved, Path(handle.name).resolve())

    def test_set_input_file_prefers_default_profile_dir_for_bare_filename(self) -> None:
        profile_dir = self.workspace_root / "Tools" / "ProfilePackage" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_file = profile_dir / "default_profile.der"
        profile_file.write_bytes(b"\x01\x02\x03")
        try:
            resolved = self.bridge.set_input_file("default_profile.der")
            self.assertEqual(resolved, profile_file.resolve())
        finally:
            if profile_file.exists():
                profile_file.unlink()

    def test_default_profile_dir_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Tools" / "ProfilePackage" / "saip_tool_config.json"
        first_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )
        persisted_dir = first_bridge.set_default_profile_dir("Tools/ProfilePackage/custom_profiles")

        second_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(second_bridge.default_profile_dir, persisted_dir)

    def test_default_transcode_dir_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Tools" / "ProfilePackage" / "saip_tool_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            '{"default_transcode_dir": "Tools/ProfilePackage/custom_transcode"}',
            encoding="utf-8",
        )

        bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(
            bridge.default_transcode_dir,
            (self.workspace_root / "Tools" / "ProfilePackage" / "custom_transcode").resolve(),
        )

    def test_set_default_transcode_dir_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Tools" / "ProfilePackage" / "saip_tool_config.json"
        first_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )
        persisted_dir = first_bridge.set_default_transcode_dir(
            "Tools/ProfilePackage/custom_transcode"
        )

        second_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(second_bridge.default_transcode_dir, persisted_dir)

    def test_describe_status_mentions_transcode_dir(self) -> None:
        self.bridge.set_default_transcode_dir("Tools/ProfilePackage/custom_transcode")

        status = self.bridge.describe_status()

        self.assertIn("Active profile:", status)
        self.assertIn("Transcode dir:", status)
        self.assertIn("Tools/ProfilePackage/custom_transcode", status)

    def test_list_default_profiles_ignores_transcode_sidecars(self) -> None:
        profile_dir = self.workspace_root / "Tools" / "ProfilePackage" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "profile.der").write_bytes(b"\x01\x02")
        (profile_dir / "profile.transcode.json").write_text("{}", encoding="utf-8")
        (profile_dir / "profile.transcode.der").write_bytes(b"\xAA")

        listed = self.bridge.list_default_profiles()

        self.assertEqual([item.name for item in listed], ["profile.der"])

    def test_resolve_transcode_sidecar_paths_use_dedicated_folder(self) -> None:
        source = self.workspace_root / "Tools" / "ProfilePackage" / "profile" / "demo.der"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"\x01")

        json_path, der_path = self.bridge.resolve_transcode_sidecar_paths(source)

        self.assertEqual(
            json_path,
            (self.workspace_root / "Tools" / "ProfilePackage" / "transcode" / "demo.transcode.json").resolve(),
        )
        self.assertEqual(
            der_path,
            (self.workspace_root / "Tools" / "ProfilePackage" / "transcode" / "demo.transcode.der").resolve(),
        )

    def test_resolve_workspace_path_rejects_outside_workspace(self) -> None:
        outside_path = self.workspace_root.parent / "outside.der"

        with self.assertRaises(ValueError):
            self.bridge.resolve_workspace_path(str(outside_path), must_exist=False)

    def test_normalize_raw_arguments_resolves_output_paths_inside_workspace(self) -> None:
        normalized = self.bridge.normalize_raw_arguments(
            ["split", "--output-prefix", "tests/profile_package_export"]
        )

        self.assertEqual(normalized[0], "split")
        self.assertEqual(normalized[1], "--output-prefix")
        self.assertTrue(normalized[2].startswith(str(self.workspace_root)))


if __name__ == "__main__":
    unittest.main()
