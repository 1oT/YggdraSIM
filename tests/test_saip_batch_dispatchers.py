# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Integration tests for ``saip.batch_lint_paths`` and ``saip.batch_personalize``.

These dispatchers are the GUI-side equivalents of the CLI verbs
``LINT-BATCH`` / ``GENERATE-BATCH`` and the ``epcval -p`` workflow
the manual documents under "Batch Validation" / "Batch Personalization".
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class BatchLintPathsTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions
        # Materialise the hex fixture as a real .der so the path-based
        # dispatcher resolves it like any other on-disk profile.
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_batch_lint_"))
        hex_text = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        cleaned = "".join(hex_text.split())
        self._der_path = self._tmpdir / "reference.der"
        self._der_path.write_bytes(bytes.fromhex(cleaned))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_single_path_lints(self) -> None:
        result = self._actions._dispatch_batch_lint_paths(
            ctx=None,
            paths=str(self._der_path),
        )
        self.assertEqual(result["aggregate"]["total"], 1)
        self.assertEqual(len(result["results"]), 1)
        entry = result["results"][0]
        self.assertEqual(entry["path"], str(self._der_path))
        self.assertIn("findings", entry)
        self.assertIn("score", entry)

    def test_glob_expansion(self) -> None:
        # Drop a duplicate so the glob matches two files.
        copy_path = self._tmpdir / "second.der"
        copy_path.write_bytes(self._der_path.read_bytes())
        result = self._actions._dispatch_batch_lint_paths(
            ctx=None,
            paths=str(self._tmpdir / "*.der"),
        )
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["aggregate"]["total"], 2)

    def test_missing_path_reports_error(self) -> None:
        bogus = self._tmpdir / "does_not_exist.der"
        result = self._actions._dispatch_batch_lint_paths(
            ctx=None,
            paths=[str(bogus)],
        )
        self.assertEqual(result["aggregate"]["errored"], 1)
        self.assertIn("error", result["results"][0])

    def test_paths_required(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_batch_lint_paths(ctx=None, paths="")

    def test_strict_mode_propagates(self) -> None:
        result = self._actions._dispatch_batch_lint_paths(
            ctx=None,
            paths=str(self._der_path),
            strict=True,
        )
        self.assertTrue(result["strict"])


class BatchLintPathsExpansionTests(unittest.TestCase):
    """Argument-shape tests that don't need a real package."""

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_comma_separated_string_dedups(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ygg_dedup_") as tmp:
            path = Path(tmp) / "foo.der"
            path.write_bytes(b"")
            paths = f"{path},{path}"
            expanded = self._actions._expand_path_list(paths)
            self.assertEqual(len(expanded), 1)
            self.assertEqual(expanded[0], path.resolve())

    def test_json_array_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ygg_arr_") as tmp:
            a = Path(tmp) / "a.der"
            b = Path(tmp) / "b.der"
            a.write_bytes(b"")
            b.write_bytes(b"")
            expanded = self._actions._expand_path_list([str(a), str(b)])
            self.assertEqual(set(expanded), {a.resolve(), b.resolve()})

    def test_invalid_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._expand_path_list(42)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class BatchPersonalizeTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_batch_pers_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_template(self) -> Path:
        # Minimal placeholder-bearing template — the engine expects a
        # transcoded JSON document with __ygg_token_defs__ + at least
        # one occurrence of each placeholder.
        template_path = self._tmpdir / "template.json"
        template_path.write_text(
            '{"__ygg_token_defs__": {}, "intro": [], "sections": {}}',
            encoding="utf-8",
        )
        return template_path

    def test_missing_template_rejected(self) -> None:
        data_path = self._tmpdir / "data.csv"
        data_path.write_text("ICCID\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            self._actions._dispatch_batch_personalize(
                ctx=None,
                template_path=str(self._tmpdir / "missing.json"),
                data_path=str(data_path),
                output_dir=str(self._tmpdir / "out"),
            )

    def test_missing_required_args_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_batch_personalize(
                ctx=None,
                template_path="",
                data_path="x",
                output_dir="y",
            )

    def test_no_placeholders_in_template_rejected(self) -> None:
        # The template above carries no placeholders, so this should
        # surface the engine's "no placeholders" error.
        template_path = self._make_template()
        data_path = self._tmpdir / "data.csv"
        data_path.write_text("ICCID\n8988201234567890123\n", encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            self._actions._dispatch_batch_personalize(
                ctx=None,
                template_path=str(template_path),
                data_path=str(data_path),
                output_dir=str(self._tmpdir / "out"),
            )
        self.assertIn("placeholder", str(caught.exception).lower())


if __name__ == "__main__":
    unittest.main()
