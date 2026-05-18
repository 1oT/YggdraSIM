# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.ProfilePackage.saip_tool.SaipToolBridge`` utility methods.

Covers: is_transcode_sidecar, get_input_file, set_tool_command,
describe_tool_command.  All tests use a temporary directory for the
workspace root; no file I/O outside tmp and no subprocesses are spawned.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from Tools.ProfilePackage.saip_tool import SaipToolBridge


def _make_bridge(tmp: pathlib.Path) -> SaipToolBridge:
    return SaipToolBridge(workspace_root=tmp)


class IsTranscodeSidecarTests(unittest.TestCase):

    def test_transcode_json_is_sidecar(self) -> None:
        self.assertTrue(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("profile.transcode.json"))
        )

    def test_transcode_der_is_sidecar(self) -> None:
        self.assertTrue(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("profile.transcode.der"))
        )

    def test_transcode_txt_is_sidecar(self) -> None:
        self.assertTrue(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("profile.transcode.txt"))
        )

    def test_plain_der_is_not_sidecar(self) -> None:
        self.assertFalse(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("profile.der"))
        )

    def test_plain_json_is_not_sidecar(self) -> None:
        self.assertFalse(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("profile.json"))
        )

    def test_uppercase_extension_detected(self) -> None:
        # Name is lowercased before comparison.
        self.assertTrue(
            SaipToolBridge.is_transcode_sidecar(pathlib.Path("PROFILE.TRANSCODE.DER"))
        )

    def test_returns_bool(self) -> None:
        result = SaipToolBridge.is_transcode_sidecar(pathlib.Path("x.der"))
        self.assertIsInstance(result, bool)


class GetInputFileTests(unittest.TestCase):

    def test_raises_when_no_file_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bridge = _make_bridge(pathlib.Path(td))
            with self.assertRaises(ValueError):
                bridge.get_input_file()

    def test_returns_path_after_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            bridge = _make_bridge(tmp)
            target = tmp / "sample.der"
            target.write_bytes(b"\x01\x02")
            bridge.set_input_file(str(target))
            result = bridge.get_input_file()
            self.assertEqual(result.resolve(), target.resolve())


class SetToolCommandTests(unittest.TestCase):

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._bridge = _make_bridge(pathlib.Path(self._td.name))

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_parses_command_string(self) -> None:
        result = self._bridge.set_tool_command("python3 /tmp/saip-tool.py")
        self.assertEqual(result, ["python3", "/tmp/saip-tool.py"])

    def test_returns_list(self) -> None:
        result = self._bridge.set_tool_command("saip-tool --verbose")
        self.assertIsInstance(result, list)

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._bridge.set_tool_command("")

    def test_whitespace_only_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._bridge.set_tool_command("   ")

    def test_persisted_across_calls(self) -> None:
        self._bridge.set_tool_command("custom-tool --arg1")
        # describe_tool_command uses the persisted command.
        desc = self._bridge.describe_tool_command()
        self.assertIn("custom-tool", desc)


class DescribeToolCommandTests(unittest.TestCase):

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._bridge = _make_bridge(pathlib.Path(self._td.name))

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_returns_string(self) -> None:
        self._bridge.set_tool_command("mock-tool")
        self.assertIsInstance(self._bridge.describe_tool_command(), str)

    def test_reflects_set_command(self) -> None:
        self._bridge.set_tool_command("tool-a --flag")
        desc = self._bridge.describe_tool_command()
        self.assertIn("tool-a", desc)
        self.assertIn("--flag", desc)

    def test_graceful_when_tool_not_found(self) -> None:
        # No tool configured and no saip-tool binary on PATH in CI.
        # describe_tool_command must not raise — it returns a "unavailable" string.
        import os
        saved = os.environ.pop("YGGDRASIM_SAIP_TOOL", None)
        self._bridge._tool_command = None
        try:
            desc = self._bridge.describe_tool_command()
            self.assertIsInstance(desc, str)
        finally:
            if saved is not None:
                os.environ["YGGDRASIM_SAIP_TOOL"] = saved


if __name__ == "__main__":
    unittest.main()
