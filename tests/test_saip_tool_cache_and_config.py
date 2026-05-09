"""Regression tests for two QoL fixes in ``Tools.ProfilePackage.saip_tool``:

1. ``_prune_profile_package_cache`` caps ``.profilepackage-cache/`` to
   ``_MAX_CACHE_FILES`` newest entries and a total-byte budget. Without it
   the cache grew unbounded across a long-running session.
2. ``SaipTool._load_config`` now quarantines a corrupt ``saip_tool.json``
   to a timestamped sidecar instead of silently discarding it — we want
   the hand-edit preserved so the operator can recover from a typo.

Neither test needs ``pySim`` or a live card; both operate purely on disk.
"""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

saip_tool = importlib.import_module("Tools.ProfilePackage.saip_tool")


class SaipToolCachePruneTests(unittest.TestCase):
    def test_prune_keeps_kept_file_and_drops_older_over_count_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            created: list[Path] = []
            base_mtime = time.time() - 1_000
            for index in range(80):
                cache_path = cache_dir / f"entry-{index:03d}.der"
                cache_path.write_bytes(b"\x00" * 16)
                # Stagger mtimes so "newest first" is deterministic.
                os.utime(cache_path, (base_mtime + index, base_mtime + index))
                created.append(cache_path)

            # Mark the oldest file as the one we just wrote; the prune must
            # preserve it regardless of its mtime rank.
            keep = created[0]
            os.utime(keep, (base_mtime - 10_000, base_mtime - 10_000))

            with mock.patch.object(saip_tool, "_MAX_CACHE_FILES", 16):
                saip_tool._prune_profile_package_cache(cache_dir, keep=keep)

            remaining = sorted(p.name for p in cache_dir.iterdir())
            # Kept file survives unconditionally, even when its mtime ranks
            # older than the rest of the cache.
            self.assertIn(keep.name, remaining)
            # The cap tolerates +1 because ``keep`` is appended outside of
            # the count budget; anything beyond ``_MAX_CACHE_FILES + 1``
            # means the prune failed to drop older entries.
            self.assertLessEqual(len(remaining), 16 + 1)
            # And obviously much smaller than the 80 files we wrote in.
            self.assertLess(len(remaining), 80)

    def test_prune_respects_byte_budget_env(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir)
            base_mtime = time.time() - 500
            entries: list[Path] = []
            for index in range(10):
                cache_path = cache_dir / f"entry-{index}.der"
                # 1024 bytes each; budget set below to ~3 KiB so we expect
                # at most three files to survive.
                cache_path.write_bytes(b"\x42" * 1024)
                os.utime(cache_path, (base_mtime + index, base_mtime + index))
                entries.append(cache_path)

            keep = entries[-1]
            with mock.patch.dict(
                os.environ,
                {saip_tool._CACHE_MAX_BYTES_ENV: "3072"},
                clear=False,
            ):
                saip_tool._prune_profile_package_cache(cache_dir, keep=keep)

            remaining = sorted(p.name for p in cache_dir.iterdir())
            self.assertIn(keep.name, remaining)
            self.assertLessEqual(len(remaining), 3)


class SaipToolConfigQuarantineTests(unittest.TestCase):
    def test_corrupt_config_is_renamed_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            config_path = workspace / "saip_tool.json"
            config_path.write_text("{not valid json", encoding="utf-8")

            # Construct a SaipTool bound to this workspace without walking
            # the real SCP03 or SIMCARD paths; only ``_load_config`` and
            # ``_quarantine_corrupt_config`` are under test here.
            tool = saip_tool.SaipToolBridge.__new__(saip_tool.SaipToolBridge)
            tool.workspace_root = workspace
            tool.config_path = config_path
            tool.config = {}
            tool._load_config()

            # Original path should be gone; a corrupt sidecar should exist.
            self.assertFalse(config_path.exists())
            siblings = [
                p.name
                for p in workspace.iterdir()
                if p.name.startswith("saip_tool.json.corrupt.")
            ]
            self.assertEqual(len(siblings), 1)

    def test_valid_config_is_loaded_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            config_path = workspace / "saip_tool.json"
            config_path.write_text(
                json.dumps({"default_profile_dir": "profiles"}, indent=2),
                encoding="utf-8",
            )

            tool = saip_tool.SaipToolBridge.__new__(saip_tool.SaipToolBridge)
            tool.workspace_root = workspace
            tool.config_path = config_path
            tool.config = {}
            tool.default_profile_dir = workspace
            tool.default_transcode_dir = workspace
            tool.last_input_open_directory = workspace
            tool._load_config()

            # Valid config must leave the on-disk file in place; no quarantine
            # sidecar should have been created.
            self.assertTrue(config_path.exists())
            corrupt_siblings = [
                p.name
                for p in workspace.iterdir()
                if p.name.startswith("saip_tool.json.corrupt.")
            ]
            self.assertEqual(corrupt_siblings, [])


if __name__ == "__main__":
    unittest.main()
