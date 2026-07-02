# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the ``--dry-run`` and automatic-backup safety net on destructive
token commands (``REMOVE-TOKEN``, ``RENAME-TOKEN``, ``RETOKENISE-LENGTHS``).
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.shell import ProfilePackageShell


def _make_template(directory: Path, *, name: str = "template.json") -> Path:
    path = directory / name
    doc = {
        "__ygg_token_defs__": {
            "ICCID": {"hex": "89881111111111111112"},
            "SPARE": {"hex": "FF"},
        },
        "__ygg_placeholder_style__": "brace",
        "sections": {
            "a": {"hex": "0A{ICCID}{ICCID}"},
            "b": {"hex": "{ICCID}"},
            "c": {"hex": "01{SPARE}"},
        },
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


class _BaseSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self._workspace_root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self._workspace_root)

    def tearDown(self) -> None:
        self._workspace.cleanup()

    def _template(self) -> Path:
        return _make_template(self._workspace_root)

    def _run(self, handler, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            handler(arg)
        return buffer.getvalue()


class RetokeniseLengthsSafetyTests(_BaseSafetyTest):

    def test_dry_run_does_not_touch_file_or_create_backup(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")
        mtime_before = path.stat().st_mtime_ns

        output = self._run(
            self.shell._cmd_retokenise_lengths,
            f"{path.name} --dry-run",
        )

        self.assertIn("Dry-run", output)
        self.assertIn("1", output)
        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertEqual(path.stat().st_mtime_ns, mtime_before)
        self.assertFalse(path.with_suffix(".json.bak").exists())

    def test_default_run_creates_bak_with_original_contents(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")

        output = self._run(
            self.shell._cmd_retokenise_lengths,
            f"{path.name}",
        )

        bak = path.with_suffix(".json.bak")
        self.assertIn("Rewrote", output)
        self.assertIn("backup written to", output)
        self.assertTrue(bak.exists())
        self.assertEqual(bak.read_text(encoding="utf-8"), original)
        updated = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            updated["sections"]["a"]["hex"], "{#ICCID}{ICCID}{ICCID}"
        )

    def test_no_backup_flag_skips_bak(self) -> None:
        path = self._template()
        self._run(
            self.shell._cmd_retokenise_lengths,
            f"{path.name} --no-backup",
        )
        self.assertFalse(path.with_suffix(".json.bak").exists())

    def test_separate_output_does_not_create_bak_for_source(self) -> None:
        path = self._template()
        out = self._workspace_root / "out.json"
        self._run(
            self.shell._cmd_retokenise_lengths,
            f"{path.name} {out.name}",
        )
        self.assertFalse(path.with_suffix(".json.bak").exists())
        self.assertFalse(out.with_suffix(".json.bak").exists())


class RemoveTokenSafetyTests(_BaseSafetyTest):

    def test_dry_run_with_referenced_token_does_not_prompt_or_write(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")

        output = self._run(
            self.shell._cmd_remove_token,
            f"{path.name} ICCID --dry-run",
        )

        self.assertIn("Dry-run", output)
        self.assertIn("left unresolved", output)
        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertFalse(path.with_suffix(".json.bak").exists())

    def test_default_removal_of_unreferenced_token_backs_up(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")

        # SPARE is referenced by `c`. Remove SPARE reference first by hand so
        # the default no-prompt path is exercised.
        loaded = json.loads(original)
        loaded["sections"]["c"]["hex"] = "0102"
        path.write_text(json.dumps(loaded, indent=2) + "\n", encoding="utf-8")
        baseline = path.read_text(encoding="utf-8")

        output = self._run(
            self.shell._cmd_remove_token,
            f"{path.name} SPARE",
        )

        bak = path.with_suffix(".json.bak")
        self.assertIn("Removed token SPARE", output)
        self.assertIn("backup written to", output)
        self.assertTrue(bak.exists())
        self.assertEqual(bak.read_text(encoding="utf-8"), baseline)
        updated = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn("SPARE", updated["__ygg_token_defs__"])


class RenameTokenSafetyTests(_BaseSafetyTest):

    def test_dry_run_reports_rewrite_plan_without_touching_file(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")

        output = self._run(
            self.shell._cmd_rename_token,
            f"{path.name} ICCID NEW_ICCID --dry-run",
        )

        self.assertIn("Dry-run", output)
        self.assertIn("would rename ICCID → NEW_ICCID", output)
        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertFalse(path.with_suffix(".json.bak").exists())

    def test_rename_in_place_creates_bak(self) -> None:
        path = self._template()
        original = path.read_text(encoding="utf-8")

        self.shell._input_fn = lambda _prompt: "y"
        output = self._run(
            self.shell._cmd_rename_token,
            f"{path.name} ICCID NEW_ICCID",
        )

        bak = path.with_suffix(".json.bak")
        self.assertIn("Renamed ICCID → NEW_ICCID", output)
        self.assertIn("backup written to", output)
        self.assertTrue(bak.exists())
        self.assertEqual(bak.read_text(encoding="utf-8"), original)
        updated = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("NEW_ICCID", updated["__ygg_token_defs__"])
        self.assertNotIn("ICCID", updated["__ygg_token_defs__"])

    def test_rename_to_separate_output_does_not_back_up_source(self) -> None:
        path = self._template()
        output_path = self._workspace_root / "renamed.json"

        self.shell._input_fn = lambda _prompt: "y"
        self._run(
            self.shell._cmd_rename_token,
            f"{path.name} ICCID NEW_ICCID {output_path.name}",
        )

        self.assertFalse(path.with_suffix(".json.bak").exists())
        self.assertFalse(output_path.with_suffix(".json.bak").exists())


if __name__ == "__main__":
    unittest.main()
