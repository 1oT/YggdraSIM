# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression coverage for the token-list ↔ filename mapping store.

The store backs ``saip.list_token_mappings`` /
``saip.set_token_mapping`` / ``saip.remove_token_mapping`` and is
consulted by ``saip.open_package_with_variables`` before the
documented sibling-CSV convention. Tests cover the JSON file
round-trip, the resolver match order (absolute path → basename →
stem), and the dispatcher CRUD surface.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.gui_server.actions import saip


_RUNTIME_ENV = "YGGDRASIM_RUNTIME_ROOT"


class _StoreTempRoot:
    """Redirect the runtime root for a single test so the store
    lands in a throwaway directory and the active workspace stays
    clean. ``runtime_path`` reads ``YGGDRASIM_RUNTIME_ROOT`` at
    call time so swapping the env-var is enough.
    """

    def __enter__(self) -> str:
        self.tmp = tempfile.mkdtemp(prefix="ygg-tok-map-")
        self.prev = os.environ.get(_RUNTIME_ENV)
        os.environ[_RUNTIME_ENV] = self.tmp
        return self.tmp

    def __exit__(self, exc_type, exc, tb):
        if self.prev is None:
            os.environ.pop(_RUNTIME_ENV, None)
        else:
            os.environ[_RUNTIME_ENV] = self.prev
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestStoreRoundTrip(unittest.TestCase):
    def test_load_returns_empty_when_missing(self):
        with _StoreTempRoot():
            self.assertEqual(saip._load_token_mappings(), {})

    def test_save_then_load_preserves_entries(self):
        with _StoreTempRoot():
            saip._save_token_mappings(
                {"profile.der": {"tokens_path": "/tmp/x.csv", "last_used": 42}}
            )
            self.assertEqual(
                saip._load_token_mappings(),
                {"profile.der": {"tokens_path": "/tmp/x.csv", "last_used": 42}},
            )

    def test_load_drops_malformed_entries(self):
        with _StoreTempRoot():
            store = saip._token_mapping_store_path()
            store.parent.mkdir(parents=True, exist_ok=True)
            # tokens_path missing → entry should be dropped on load.
            store.write_text(
                json.dumps(
                    {"mappings": {"a.der": {"foo": "bar"}, "b.der": {"tokens_path": "/c.csv"}}}
                ),
                encoding="utf-8",
            )
            loaded = saip._load_token_mappings()
            self.assertNotIn("a.der", loaded)
            self.assertEqual(loaded["b.der"]["tokens_path"], "/c.csv")

    def test_load_returns_empty_for_corrupt_json(self):
        with _StoreTempRoot():
            store = saip._token_mapping_store_path()
            store.parent.mkdir(parents=True, exist_ok=True)
            store.write_text("{ broken", encoding="utf-8")
            self.assertEqual(saip._load_token_mappings(), {})


class TestDispatchers(unittest.TestCase):
    def test_set_lists_and_removes_mapping(self):
        with _StoreTempRoot():
            r1 = saip._dispatch_set_token_mapping(
                None, filename="a.der", tokens_path="/tmp/a.csv"
            )
            self.assertEqual(r1["count"], 1)
            r2 = saip._dispatch_list_token_mappings(None)
            self.assertEqual(r2["count"], 1)
            self.assertEqual(r2["mappings"][0]["filename"], "a.der")
            self.assertEqual(r2["mappings"][0]["tokens_path"], "/tmp/a.csv")
            r3 = saip._dispatch_remove_token_mapping(None, filename="a.der")
            self.assertTrue(r3["removed"])
            self.assertEqual(r3["count"], 0)

    def test_remove_unknown_is_noop(self):
        with _StoreTempRoot():
            r = saip._dispatch_remove_token_mapping(None, filename="ghost.der")
            self.assertFalse(r["removed"])
            self.assertEqual(r["count"], 0)

    def test_set_requires_both_fields(self):
        with _StoreTempRoot():
            with self.assertRaises(ValueError):
                saip._dispatch_set_token_mapping(None, filename="", tokens_path="/x.csv")
            with self.assertRaises(ValueError):
                saip._dispatch_set_token_mapping(None, filename="a.der", tokens_path="")

    def test_remove_requires_filename(self):
        with _StoreTempRoot():
            with self.assertRaises(ValueError):
                saip._dispatch_remove_token_mapping(None, filename="")


class TestResolveTokenMapping(unittest.TestCase):
    """``_resolve_token_mapping`` walks the candidate keys in order
    (absolute path → basename → stem) and returns the first match.
    """

    def test_absolute_path_match_wins(self):
        with _StoreTempRoot(), tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            tf.write(b"X,1\n")
            tf.flush()
            csv_path = tf.name
        try:
            saip._save_token_mappings(
                {"/foo/profile.der": {"tokens_path": csv_path, "last_used": None}}
            )
            resolved = saip._resolve_token_mapping(Path("/foo/profile.der"))
            self.assertEqual(str(resolved), csv_path)
        finally:
            os.unlink(csv_path)

    def test_basename_fallback(self):
        with _StoreTempRoot(), tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            tf.write(b"X,1\n")
            tf.flush()
            csv_path = tf.name
        try:
            saip._save_token_mappings(
                {"profile.der": {"tokens_path": csv_path, "last_used": None}}
            )
            resolved = saip._resolve_token_mapping(Path("/some/other/dir/profile.der"))
            self.assertEqual(str(resolved), csv_path)
        finally:
            os.unlink(csv_path)

    def test_stem_fallback(self):
        with _StoreTempRoot(), tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            tf.write(b"X,1\n")
            tf.flush()
            csv_path = tf.name
        try:
            saip._save_token_mappings(
                {"profile": {"tokens_path": csv_path, "last_used": None}}
            )
            resolved = saip._resolve_token_mapping(Path("/some/dir/profile.der"))
            self.assertEqual(str(resolved), csv_path)
        finally:
            os.unlink(csv_path)

    def test_no_match_returns_none(self):
        with _StoreTempRoot():
            saip._save_token_mappings(
                {"other.der": {"tokens_path": "/tmp/o.csv", "last_used": None}}
            )
            self.assertIsNone(saip._resolve_token_mapping(Path("/x/profile.der")))

    def test_missing_target_still_returned(self):
        # A pinned mapping pointing at a path that vanished from
        # disk is surfaced (not silently dropped) so the open
        # dispatcher can warn the operator about the broken bind.
        with _StoreTempRoot():
            saip._save_token_mappings(
                {"profile.der": {"tokens_path": "/nope/missing.csv", "last_used": None}}
            )
            resolved = saip._resolve_token_mapping(Path("/x/profile.der"))
            self.assertEqual(str(resolved), "/nope/missing.csv")


class TestActionSpecsRegistered(unittest.TestCase):
    def test_three_specs_present(self):
        from yggdrasim_common.gui_server.actions.registry import get_registry

        ids = {spec.id for spec in get_registry().all()}
        self.assertIn("saip.list_token_mappings", ids)
        self.assertIn("saip.set_token_mapping", ids)
        self.assertIn("saip.remove_token_mapping", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
