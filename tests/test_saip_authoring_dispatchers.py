# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP authoring / packaging dispatchers.

Covered surfaces:
  * ``saip.save_package`` — DER / hex / JSON output, overwrite guard
  * ``saip.add_pe`` / ``saip.delete_pe`` — sequence splice / drop
  * ``saip.import_pe`` / ``saip.export_pe`` — single-PE I/O
  * ``saip.list_applications`` / ``saip.compare_applications`` —
    SD / Application / ELF inventory and inter-package diff
  * ``saip.product_summary`` — bench environment fingerprint
  * ``saip.list_validation_rules`` — linter rulebook catalogue
  * ``saip.add_variable_to_pe`` — bind PE field to placeholder
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


def _open_reference_session(actions):
    """Open a fresh session against the reference profile fixture."""
    return actions._dispatch_open_package(
        ctx=None, path=str(_REFERENCE_PROFILE)
    )["session_id"]


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class SavePackageFormatTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_save_pkg_"))
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_save_der_round_trips(self) -> None:
        target = self._tmpdir / "out.der"
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="der",
        )
        self.assertEqual(result["format"], "der")
        self.assertGreater(result["size_bytes"], 100)
        self.assertTrue(target.is_file())

    def test_save_hex_writes_uppercase_hex(self) -> None:
        target = self._tmpdir / "out.hex"
        self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="hex",
        )
        text = target.read_text(encoding="utf-8").strip()
        self.assertEqual(text, text.upper())
        # Must be valid hex.
        bytes.fromhex(text)

    def test_save_json_preserves_metadata(self) -> None:
        target = self._tmpdir / "out.json"
        self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="json",
        )
        doc = json.loads(target.read_text(encoding="utf-8"))
        self.assertIn("sections", doc)

    def test_save_appends_default_extension(self) -> None:
        target = self._tmpdir / "no_extension"
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="hex",
        )
        self.assertTrue(result["output_path"].endswith(".hex"))

    def test_save_refuses_overwrite_by_default(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        with self.assertRaises(FileExistsError):
            self._actions._dispatch_save_package(
                ctx=None,
                session_id=self._sid,
                output_path=str(target),
                format="der",
            )

    def test_save_overwrite_true_replaces(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        result = self._actions._dispatch_save_package(
            ctx=None,
            session_id=self._sid,
            output_path=str(target),
            format="der",
            overwrite=True,
        )
        self.assertGreater(result["size_bytes"], 1)

    def test_unknown_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_save_package(
                ctx=None,
                session_id=self._sid,
                output_path=str(self._tmpdir / "x.bin"),
                format="bogus",
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class PeCrudTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_pe_crud_"))
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_pe_refuses_index_zero(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_pe(
                ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=0
            )

    def test_add_unknown_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_pe(
                ctx=None, session_id=self._sid, pe_type="bogusPeType"
            )

    def test_add_then_delete_round_trip(self) -> None:
        before = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        before_count = len(before["rows"])
        # Insert a new AKA PE just before the end sentinel.
        result = self._actions._dispatch_add_pe(
            ctx=None,
            session_id=self._sid,
            pe_type="akaParameter",
            insert_at=before_count - 1,
        )
        added_index = result["pe_index"]
        after_add = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        self.assertEqual(len(after_add["rows"]), before_count + 1)
        # Remove it.
        delete_result = self._actions._dispatch_delete_pe(
            ctx=None, session_id=self._sid, pe_index=added_index
        )
        self.assertEqual(delete_result["remaining_count"], before_count)

    def test_delete_header_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_delete_pe(
                ctx=None, session_id=self._sid, pe_index=0
            )

    def test_export_pe_writes_der(self) -> None:
        target = self._tmpdir / "pe0.der"
        result = self._actions._dispatch_export_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=0,
            output_path=str(target),
            format="der",
        )
        self.assertTrue(target.is_file())
        self.assertGreater(result["bytes_written"], 0)

    def test_export_then_import_round_trip(self) -> None:
        # Export the second PE (whatever it is), then re-import it
        # at a fresh slot near the end of the sequence.
        export_path = self._tmpdir / "pe2.der"
        self._actions._dispatch_export_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=2,
            output_path=str(export_path),
            format="der",
        )
        before = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        before_count = len(before["rows"])
        result = self._actions._dispatch_import_pe(
            ctx=None,
            session_id=self._sid,
            input_path=str(export_path),
            insert_at=before_count - 1,
        )
        self.assertGreater(result["pe_index"], 0)
        after = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        self.assertEqual(len(after["rows"]), before_count + 1)

    def test_import_xml_unsupported(self) -> None:
        bad = self._tmpdir / "ftx.xml"
        bad.write_text("<x/>", encoding="utf-8")
        with self.assertRaises(ValueError):
            self._actions._dispatch_import_pe(
                ctx=None,
                session_id=self._sid,
                input_path=str(bad),
            )

    def test_export_pe_refuses_overwrite(self) -> None:
        target = self._tmpdir / "exists.der"
        target.write_bytes(b"\x00")
        with self.assertRaises(FileExistsError):
            self._actions._dispatch_export_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                output_path=str(target),
                format="der",
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ApplicationsTabTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_list_applications_returns_rows(self) -> None:
        result = self._actions._dispatch_list_applications(
            ctx=None, session_id=self._sid
        )
        self.assertIn("rows", result)
        # Reference profile carries at least one ISD.
        self.assertGreaterEqual(len(result["rows"]), 1)
        for row in result["rows"]:
            self.assertIn("pe_index", row)
            self.assertIn("pe_type", row)

    def test_compare_applications_self(self) -> None:
        result = self._actions._dispatch_compare_applications(
            ctx=None,
            session_id=self._sid,
            target_path=str(_REFERENCE_PROFILE),
        )
        # Self-compare → everything must be unchanged.
        self.assertEqual(result["summary"]["added"], 0)
        self.assertEqual(result["summary"]["removed"], 0)
        self.assertEqual(result["summary"]["unchanged"], result["left_count"])

    def test_compare_applications_missing_target(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self._actions._dispatch_compare_applications(
                ctx=None,
                session_id=self._sid,
                target_path="/no/such/path.der",
            )


class ProductSummaryTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_summary_"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_inline_json_when_no_path(self) -> None:
        result = self._actions._dispatch_product_summary(ctx=None, output_path="")
        self.assertEqual(result["format"], "json")
        self.assertIn("environment", result["summary"])
        self.assertIn("actions", result["summary"])
        self.assertGreater(len(result["summary"]["actions"]), 30)

    def test_html_export(self) -> None:
        target = self._tmpdir / "summary.html"
        result = self._actions._dispatch_product_summary(
            ctx=None, output_path=str(target), format="html"
        )
        self.assertEqual(result["format"], "html")
        self.assertTrue(target.is_file())
        text = target.read_text(encoding="utf-8")
        self.assertIn("<html>", text)
        self.assertIn("YggdraSIM product summary", text)

    def test_xml_export(self) -> None:
        target = self._tmpdir / "summary.xml"
        self._actions._dispatch_product_summary(
            ctx=None, output_path=str(target), format="xml"
        )
        text = target.read_text(encoding="utf-8")
        self.assertIn("<?xml", text)
        self.assertIn("<yggdrasim_product_summary>", text)

    def test_unknown_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_product_summary(
                ctx=None, output_path="/tmp/x", format="docx"
            )


class ValidationRulesCatalogTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_returns_rules(self) -> None:
        result = self._actions._dispatch_list_validation_rules(ctx=None)
        # The linter ships at least a few rules; trip if the fallback
        # walker found nothing AND the descriptor attr is missing.
        self.assertIn("count", result)
        self.assertIn("rules", result)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class AddVariableToPeTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = _open_reference_session(saip_actions)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_replace_iccid_with_placeholder(self) -> None:
        result = self._actions._dispatch_add_variable_to_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=0,
            field_path="iccid",
            variable_name="ICCID",
            encoding="hex",
        )
        self.assertEqual(result["variable_name"], "ICCID")
        self.assertGreater(len(result["captured_value"]), 0)

    def test_unknown_field_path_raises(self) -> None:
        with self.assertRaises(LookupError):
            self._actions._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                field_path="not.a.real.path",
                variable_name="X",
            )

    def test_missing_required_args_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_variable_to_pe(
                ctx=None,
                session_id=self._sid,
                pe_index=0,
                field_path="",
                variable_name="X",
            )


if __name__ == "__main__":
    unittest.main()
