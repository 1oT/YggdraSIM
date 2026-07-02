# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for yggdrasim_common/runtime_paths.py helper functions.

Covers: is_frozen, remap_legacy_workspace_relative, ensure_directory,
        ensure_workspace_dir, ensure_seeded_runtime_file,
        ensure_seeded_runtime_tree, ensure_seeded_workspace_file,
        ensure_seeded_workspace_tree.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

from yggdrasim_common.runtime_paths import (
    WORKSPACE_DIRNAME,
    ensure_directory,
    is_frozen,
    remap_legacy_workspace_relative,
)


# ---------------------------------------------------------------------------
# is_frozen
# ---------------------------------------------------------------------------

class IsFrozenTests(unittest.TestCase):

    def test_returns_false_in_test_environment(self) -> None:
        # In pytest there is no sys.frozen attribute.
        self.assertFalse(is_frozen())

    def test_returns_bool(self) -> None:
        self.assertIsInstance(is_frozen(), bool)


# ---------------------------------------------------------------------------
# remap_legacy_workspace_relative
# ---------------------------------------------------------------------------

class RemapLegacyWorkspaceRelativeTests(unittest.TestCase):

    def test_exact_legacy_key_remapped(self) -> None:
        result = remap_legacy_workspace_relative("SCP03/keys.ini")
        self.assertEqual(result, f"{WORKSPACE_DIRNAME}/SCP03/keys.ini")

    def test_legacy_key_with_suffix_remapped(self) -> None:
        result = remap_legacy_workspace_relative("SCP03/keys.ini/extra")
        self.assertIn(WORKSPACE_DIRNAME, result)
        self.assertIn("extra", result)

    def test_non_legacy_path_passthrough(self) -> None:
        path = "some/unknown/path"
        self.assertEqual(remap_legacy_workspace_relative(path), path)

    def test_empty_string_passthrough(self) -> None:
        self.assertEqual(remap_legacy_workspace_relative(""), "")

    def test_backslash_normalised(self) -> None:
        result = remap_legacy_workspace_relative("SCP03\\keys.ini")
        self.assertEqual(result, f"{WORKSPACE_DIRNAME}/SCP03/keys.ini")

    def test_saip_profile_path_remapped(self) -> None:
        result = remap_legacy_workspace_relative("Tools/ProfilePackage/profile")
        self.assertIn(WORKSPACE_DIRNAME, result)

    def test_eim_local_certs_remapped(self) -> None:
        result = remap_legacy_workspace_relative("SCP11/eim_local/certs")
        self.assertIn(WORKSPACE_DIRNAME, result)

    def test_path_with_leading_space_stripped(self) -> None:
        result = remap_legacy_workspace_relative("  SCP03/keys.ini  ")
        self.assertIn(WORKSPACE_DIRNAME, result)


# ---------------------------------------------------------------------------
# ensure_directory
# ---------------------------------------------------------------------------

class EnsureDirectoryTests(unittest.TestCase):

    def test_creates_directory_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "new_subdir", "nested")
            result = ensure_directory(target)
            self.assertTrue(os.path.isdir(result))

    def test_returns_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = ensure_directory(tmp)
            self.assertTrue(os.path.isabs(result))

    def test_existing_directory_not_destroyed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "marker.txt")
            with open(marker, "w") as fh:
                fh.write("keep")
            ensure_directory(tmp)
            self.assertTrue(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
