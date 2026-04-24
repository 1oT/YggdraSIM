import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        profile_dir = self.workspace_root / "Workspace" / "SAIP" / "profile"
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
        config_path = self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json"
        first_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )
        persisted_dir = first_bridge.set_default_profile_dir("Workspace/SAIP/custom_profiles")

        second_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(second_bridge.default_profile_dir, persisted_dir)

    def test_default_transcode_dir_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            '{"default_transcode_dir": "Workspace/SAIP/custom_transcode"}',
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
            (self.workspace_root / "Workspace" / "SAIP" / "custom_transcode").resolve(),
        )

    def test_set_default_transcode_dir_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json"
        first_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )
        persisted_dir = first_bridge.set_default_transcode_dir(
            "Workspace/SAIP/custom_transcode"
        )

        second_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(second_bridge.default_transcode_dir, persisted_dir)

    def test_last_input_open_directory_persists_in_config(self) -> None:
        config_path = self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json"
        profile_dir = self.workspace_root / "captures" / "recent"
        profile_dir.mkdir(parents=True, exist_ok=True)
        profile_path = profile_dir / "picked_profile.der"
        profile_path.write_bytes(b"\x01\x02\x03")

        first_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )
        first_bridge.set_input_file(str(profile_path))

        second_bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            runner=self.runner,
            tool_command=["saip-tool.py"],
            config_path=config_path,
        )

        self.assertEqual(second_bridge.last_input_open_directory, profile_dir.resolve())

    def test_describe_status_mentions_transcode_dir(self) -> None:
        self.bridge.set_default_transcode_dir("Workspace/SAIP/custom_transcode")

        status = self.bridge.describe_status()

        self.assertIn("Active profile:", status)
        self.assertIn("Transcode dir:", status)
        self.assertIn("Workspace/SAIP/custom_transcode", status)

    def test_pick_input_file_uses_last_open_directory_when_available(self) -> None:
        remembered_directory = self.workspace_root / "captures" / "recent"
        remembered_directory.mkdir(parents=True, exist_ok=True)
        selected_path = remembered_directory / "offline_profile.der"
        selected_path.write_bytes(b"\x01\x02")
        self.bridge.last_input_open_directory = remembered_directory.resolve()
        completed = subprocess.CompletedProcess(
            ["zenity"],
            0,
            stdout=f"{selected_path}\n",
            stderr="",
        )

        with mock.patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False):
            with mock.patch(
                "Tools.ProfilePackage.saip_tool.shutil.which",
                side_effect=lambda name: "/usr/bin/zenity" if name == "zenity" else None,
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_tool.subprocess.run",
                    return_value=completed,
                ) as mocked_run:
                    resolved = self.bridge.pick_input_file()

        self.assertEqual(resolved, selected_path.resolve())
        self.assertEqual(self.bridge.current_input_file, selected_path.resolve())
        self.assertIn(
            f"--filename={remembered_directory.resolve()}/",
            mocked_run.call_args.args[0],
        )

    def test_list_default_profiles_ignores_transcode_sidecars(self) -> None:
        profile_dir = self.workspace_root / "Workspace" / "SAIP" / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        (profile_dir / "profile.der").write_bytes(b"\x01\x02")
        (profile_dir / "profile.transcode.json").write_text("{}", encoding="utf-8")
        (profile_dir / "profile.transcode.der").write_bytes(b"\xAA")
        (profile_dir / "profile.transcode.txt").write_text("AABB\n", encoding="utf-8")

        listed = self.bridge.list_default_profiles()

        self.assertEqual([item.name for item in listed], ["profile.der"])

    def test_resolve_transcode_sidecar_paths_use_dedicated_folder(self) -> None:
        source = self.workspace_root / "Workspace" / "SAIP" / "profile" / "demo.der"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"\x01")

        json_path, der_path, txt_path = self.bridge.resolve_transcode_sidecar_paths(source)

        self.assertEqual(
            json_path,
            (self.workspace_root / "Workspace" / "SAIP" / "transcode" / "demo.transcode.json").resolve(),
        )
        self.assertEqual(
            der_path,
            (self.workspace_root / "Workspace" / "SAIP" / "transcode" / "demo.transcode.der").resolve(),
        )
        self.assertEqual(
            txt_path,
            (self.workspace_root / "Workspace" / "SAIP" / "transcode" / "demo.transcode.txt").resolve(),
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

    def test_subprocess_env_with_pysim_prepends_workspace_dir_and_preserves_pythonpath(self) -> None:
        workspace_pysim = self.workspace_root / "pysim"
        workspace_pysim.mkdir(parents=True, exist_ok=True)

        with mock.patch.dict(os.environ, {"PYTHONPATH": "existing/pythonpath"}, clear=False):
            env = self.bridge._subprocess_env_with_pysim()

        pythonpath_entries = env["PYTHONPATH"].split(os.pathsep)
        self.assertEqual(pythonpath_entries[0], str(workspace_pysim))
        self.assertEqual(pythonpath_entries[-1], "existing/pythonpath")

    def test_run_subprocess_passes_capture_text_and_env(self) -> None:
        workspace_pysim = self.workspace_root / "pysim"
        workspace_pysim.mkdir(parents=True, exist_ok=True)
        completed = subprocess.CompletedProcess(
            ["saip-tool.py", "demo.der", "info"],
            0,
            stdout="ok\n",
            stderr="",
        )

        with mock.patch(
            "Tools.ProfilePackage.saip_tool.subprocess.run",
            return_value=completed,
        ) as mocked_run:
            result = self.bridge._run_subprocess(["saip-tool.py", "demo.der", "info"])

        self.assertIs(result, completed)
        mocked_run.assert_called_once()
        self.assertEqual(
            mocked_run.call_args.args[0],
            ["saip-tool.py", "demo.der", "info"],
        )
        self.assertFalse(mocked_run.call_args.kwargs["check"])
        self.assertTrue(mocked_run.call_args.kwargs["capture_output"])
        self.assertTrue(mocked_run.call_args.kwargs["text"])
        self.assertEqual(
            mocked_run.call_args.kwargs["timeout"],
            self.bridge.command_timeout_seconds,
        )
        pythonpath_entries = mocked_run.call_args.kwargs["env"]["PYTHONPATH"].split(os.pathsep)
        self.assertEqual(pythonpath_entries[0], str(workspace_pysim))

    def test_run_subprocess_returns_timeout_error_instead_of_hanging(self) -> None:
        timeout = self.bridge.command_timeout_seconds
        with mock.patch(
            "Tools.ProfilePackage.saip_tool.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                ["saip-tool.py", "demo.der", "dump"],
                timeout,
                output="partial output\n",
                stderr="decoder stalled",
            ),
        ):
            result = self.bridge._run_subprocess(["saip-tool.py", "demo.der", "dump"])

        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "partial output\n")
        self.assertIn("timed out", result.stderr)
        self.assertIn("decoder stalled", result.stderr)

    def test_bundle_root_seeds_default_profile_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_bundle:
            bundle_root = Path(temp_bundle)
            source_profile_dir = bundle_root / "Tools" / "ProfilePackage" / "profile"
            source_profile_dir.mkdir(parents=True, exist_ok=True)
            (source_profile_dir / "seed.der").write_bytes(b"\x01\x02")

            bridge = SaipToolBridge(
                workspace_root=self.workspace_root,
                runner=self.runner,
                tool_command=["saip-tool.py"],
                bundle_root_path=bundle_root,
            )

            seeded_path = self.workspace_root / "Workspace" / "SAIP" / "profile" / "seed.der"
            self.assertTrue(seeded_path.is_file())
            self.assertEqual(bridge.list_default_profiles()[0].name, "seed.der")

    def test_get_tool_command_falls_back_to_bundle_root_pysim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_bundle:
            bundle_root = Path(temp_bundle)
            bundled_tool = bundle_root / "pysim" / "contrib" / "saip-tool.py"
            bundled_tool.parent.mkdir(parents=True, exist_ok=True)
            bundled_tool.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with mock.patch("Tools.ProfilePackage.saip_tool.shutil.which", return_value=None):
                bridge = SaipToolBridge(
                    workspace_root=self.workspace_root,
                    runner=self.runner,
                    bundle_root_path=bundle_root,
                )
                command = bridge.get_tool_command()

            self.assertEqual(command, [sys.executable, str(bundled_tool.resolve())])


if __name__ == "__main__":
    unittest.main()
