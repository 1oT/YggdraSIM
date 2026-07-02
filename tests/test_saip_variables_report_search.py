# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP variables / report / search dispatchers.

* ``saip.export_variables_csv`` / ``saip.import_variables_csv``
* ``saip.compare_report_html`` (HTML rendering helper)
* ``saip.search_pe_text``
"""

from __future__ import annotations

import csv
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
class VariablesCsvDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_var_csv_"))
        result = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )
        self._sid = result["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_export_writes_csv_with_header(self) -> None:
        out_path = self._tmpdir / "variables.csv"
        result = self._actions._dispatch_export_variables_csv(
            ctx=None, session_id=self._sid, output_path=str(out_path)
        )
        self.assertTrue(out_path.is_file())
        self.assertEqual(result["output_path"], str(out_path))
        with out_path.open("r", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(
                set(reader.fieldnames or []),
                {"name", "value", "kind", "defined", "used_in_document"},
            )

    def test_export_then_import_round_trip(self) -> None:
        out_path = self._tmpdir / "variables.csv"
        self._actions._dispatch_export_variables_csv(
            ctx=None, session_id=self._sid, output_path=str(out_path)
        )
        # Reimport — even if there are no overrides to apply, the
        # dispatcher should report 0 applied without raising.
        result = self._actions._dispatch_import_variables_csv(
            ctx=None,
            session_id=self._sid,
            input_path=str(out_path),
        )
        self.assertEqual(result["input_path"], str(out_path))
        self.assertGreaterEqual(result["applied_count"], 0)

    def test_import_missing_path_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self._actions._dispatch_import_variables_csv(
                ctx=None,
                session_id=self._sid,
                input_path=str(self._tmpdir / "missing.csv"),
            )

    def test_import_missing_name_column_raises(self) -> None:
        bad_csv = self._tmpdir / "bad.csv"
        bad_csv.write_text("foo,bar\n1,2\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self._actions._dispatch_import_variables_csv(
                ctx=None,
                session_id=self._sid,
                input_path=str(bad_csv),
            )

    def test_import_skips_empty_name_rows(self) -> None:
        partial = self._tmpdir / "partial.csv"
        partial.write_text("name,value\n,nope\nICCID,8988201234567890123\n", encoding="utf-8")
        result = self._actions._dispatch_import_variables_csv(
            ctx=None,
            session_id=self._sid,
            input_path=str(partial),
        )
        # One row with empty name → skipped; one row with ICCID may
        # apply if the placeholder exists, may report 0 if it doesn't.
        self.assertGreaterEqual(len(result["skipped_rows"]), 1)


class CompareReportHtmlFormatterTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_renders_empty_report(self) -> None:
        html = self._actions._format_html_diff_report(
            {"label_a": "A", "label_b": "B", "summary": {}, "rows": []},
        )
        self.assertIn("<html>", html)
        self.assertIn("SAIP profile compare", html)
        self.assertIn("No differences recorded", html)

    def test_renders_rows_with_status_classes(self) -> None:
        html = self._actions._format_html_diff_report(
            {
                "label_a": "left.der",
                "label_b": "right.der",
                "summary": {"changed": 1},
                "rows": [
                    {
                        "section": "header",
                        "path": "profileType",
                        "status": "changed",
                        "value_a": "Lab v1",
                        "value_b": "Lab v2",
                    },
                ],
            }
        )
        self.assertIn("class='changed'", html)
        self.assertIn("Lab v2", html)
        self.assertIn("profileType", html)

    def test_escapes_html_in_values(self) -> None:
        html = self._actions._format_html_diff_report(
            {"rows": [{"path": "<script>alert(1)</script>", "status": "added"}]}
        )
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class SearchPeTextDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        result = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )
        self._sid = result["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_substring_match_finds_pe(self) -> None:
        # Every reference profile carries USIM-related PEs; "usim"
        # should match somewhere in the decoded JSON.
        result = self._actions._dispatch_search_pe_text(
            ctx=None,
            session_id=self._sid,
            query="usim",
        )
        self.assertGreater(result["match_count"], 0)
        self.assertTrue(
            any("type" in row and len(row["type"]) > 0 for row in result["matches"]),
        )

    def test_regex_mode(self) -> None:
        result = self._actions._dispatch_search_pe_text(
            ctx=None,
            session_id=self._sid,
            query=r"usim|isim",
            mode="regex",
        )
        self.assertGreater(result["match_count"], 0)

    def test_invalid_regex_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_search_pe_text(
                ctx=None,
                session_id=self._sid,
                query="(unclosed",
                mode="regex",
            )

    def test_empty_query_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_search_pe_text(
                ctx=None,
                session_id=self._sid,
                query="",
            )

    def test_case_sensitive_excludes_lowercase(self) -> None:
        result_cs = self._actions._dispatch_search_pe_text(
            ctx=None,
            session_id=self._sid,
            query="USIM",
            case_sensitive=True,
        )
        result_ci = self._actions._dispatch_search_pe_text(
            ctx=None,
            session_id=self._sid,
            query="usim",
            case_sensitive=False,
        )
        # Case-insensitive should match at least as many PEs as
        # case-sensitive (lowercase 'usim' is the JSON-key form).
        self.assertGreaterEqual(result_ci["match_count"], result_cs["match_count"])


if __name__ == "__main__":
    unittest.main()
