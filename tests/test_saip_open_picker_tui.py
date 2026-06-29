# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_open_picker_tui import (
    picker_entries_for_directory,
    picker_start_directory,
)
from Tools.ProfilePackage.saip_tool import SaipToolBridge


class SaipOpenPickerTuiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._temp_workspace.name)
        self.bridge = SaipToolBridge(
            workspace_root=self.workspace_root,
            tool_command=["saip-tool.py"],
        )

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_picker_start_directory_prefers_last_input_open_directory(self) -> None:
        remembered_directory = self.workspace_root / "captures" / "recent"
        remembered_directory.mkdir(parents=True, exist_ok=True)
        self.bridge.last_input_open_directory = remembered_directory.resolve()

        start_directory = picker_start_directory(self.bridge)

        self.assertEqual(start_directory, remembered_directory.resolve())

    def test_picker_entries_include_parent_directories_and_supported_files(self) -> None:
        browse_directory = self.workspace_root / "profiles" / "nested"
        browse_directory.mkdir(parents=True, exist_ok=True)
        (browse_directory / "alpha.der").write_bytes(b"\x01")
        (browse_directory / "beta.upp").write_bytes(b"\x02")
        (browse_directory / "gamma.varder").write_text("A0", encoding="utf-8")
        (browse_directory / "notes.md").write_text("ignore\n", encoding="utf-8")
        (browse_directory / ".hidden.der").write_bytes(b"\x03")
        (browse_directory / "subdir").mkdir()

        entries = picker_entries_for_directory(browse_directory)
        labels = [entry.label for entry in entries]

        self.assertEqual(labels[0], "DIR  ../")
        self.assertIn("DIR  subdir/", labels)
        self.assertIn("alpha.der", labels)
        self.assertIn("beta.upp", labels)
        self.assertIn("gamma.varder", labels)
        self.assertNotIn("notes.md", labels)
        self.assertNotIn(".hidden.der", labels)


if __name__ == "__main__":
    unittest.main()
