# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP package-scaffold + variable-definition surface.

Covered surfaces:
  * ``saip.create_package`` — fresh in-memory session with header + end
  * ``saip.open_package_with_variables`` — DER + CSV sidecar combo
  * ``saip.add_variable_definition`` — pre-define a placeholder
  * ``saip.remove_variable_definition`` — drop one (with binding guard)
  * ``saip.add_pe`` — auto-renumber identification + auto-name on insert
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


def _have_asn1tools() -> bool:
    try:
        import asn1tools  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_have_asn1tools(), "asn1tools required")
class CreatePackageTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sessions: list[str] = []

    def tearDown(self) -> None:
        for sid in self._sessions:
            try:
                self._manager.release(sid)
            except Exception:
                pass

    def _track(self, sid: str) -> str:
        self._sessions.append(sid)
        return sid

    def test_default_scaffold_has_header_and_end(self) -> None:
        result = self._actions._dispatch_create_package(ctx=None)
        sid = self._track(result["session_id"])
        self.assertEqual(result["pe_count"], 2)
        self.assertEqual(result["encoding"], "scaffold")
        self.assertEqual(result["profile_version"], "2.3")
        rows = self._actions._dispatch_list_pes(ctx=None, session_id=sid)["rows"]
        types = [r["type"] for r in rows]
        self.assertEqual(types[0], "header")
        self.assertEqual(types[-1], "end")

    def test_custom_version_and_iccid(self) -> None:
        result = self._actions._dispatch_create_package(
            ctx=None,
            profile_version="3.3",
            iccid="89881234567890",
            profile_type="testing",
        )
        self._track(result["session_id"])
        self.assertEqual(result["profile_version"], "3.3")
        self.assertTrue(result["iccid_hex"].startswith("89881234567890"))
        self.assertEqual(len(result["iccid_hex"]), 20)
        self.assertEqual(result["iccid_hex"][14:], "FFFFFF")

    def test_invalid_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_create_package(ctx=None, profile_version="not.a.version")

    def test_invalid_iccid_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_create_package(ctx=None, iccid="89XYZ123")

    def test_oversized_iccid_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_create_package(ctx=None, iccid="0" * 22)

    def test_scaffold_then_add_pe(self) -> None:
        scaffold = self._actions._dispatch_create_package(ctx=None)
        sid = self._track(scaffold["session_id"])
        added = self._actions._dispatch_add_pe(
            ctx=None, session_id=sid, pe_type="akaParameter", insert_at=1
        )
        self.assertEqual(added["pe_index"], 1)
        rows = self._actions._dispatch_list_pes(ctx=None, session_id=sid)["rows"]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1]["type"], "akaParameter")

    def test_scaffold_then_save_round_trip(self) -> None:
        tmpdir = Path(tempfile.mkdtemp(prefix="ygg_create_"))
        try:
            scaffold = self._actions._dispatch_create_package(ctx=None)
            sid = self._track(scaffold["session_id"])
            target = tmpdir / "scaffold.der"
            saved = self._actions._dispatch_save_package(
                ctx=None,
                session_id=sid,
                output_path=str(target),
                format="der",
            )
            self.assertTrue(target.is_file())
            self.assertGreater(saved["size_bytes"], 0)
            # Reopen — must produce a session with the same PE count.
            reopened = self._actions._dispatch_open_package(ctx=None, path=str(target))
            self._track(reopened["session_id"])
            self.assertEqual(reopened["pe_count"], 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file() and _have_asn1tools(),
    "reference profile + asn1tools required",
)
class OpenWithVariablesTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_openvars_"))
        self._sessions: list[str] = []

    def tearDown(self) -> None:
        for sid in self._sessions:
            try:
                self._manager.release(sid)
            except Exception:
                pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _track(self, sid: str) -> str:
        self._sessions.append(sid)
        return sid

    def test_no_sidecar_present(self) -> None:
        # Copy the reference profile into a clean tmp dir so no sibling
        # CSV exists, then check the no-op summary fires.
        target = self._tmpdir / "isolated.txt"
        target.write_bytes(_REFERENCE_PROFILE.read_bytes())
        result = self._actions._dispatch_open_package_with_variables(
            ctx=None, path=str(target)
        )
        self._track(result["session_id"])
        self.assertEqual(result["variables_loaded"]["applied_count"], 0)
        # Token-mapping store now uses "no token-list pinned … no sibling csv".
        summary = result["variables_loaded"]["summary"].lower()
        self.assertIn("no sibling csv", summary)
        self.assertIn("no token-list pinned", summary)

    def test_explicit_csv_applied(self) -> None:
        target = self._tmpdir / "with_vars.txt"
        target.write_bytes(_REFERENCE_PROFILE.read_bytes())
        csv = self._tmpdir / "with_vars.csv"
        csv.write_text("ICCID,8988201234567890123F\nIMSI,001010000000001\n", encoding="utf-8")
        result = self._actions._dispatch_open_package_with_variables(
            ctx=None,
            path=str(target),
            variables_path=str(csv),
        )
        self._track(result["session_id"])
        self.assertGreaterEqual(result["variables_loaded"]["applied_count"], 1)

    def test_missing_variables_path_raises(self) -> None:
        target = self._tmpdir / "p.txt"
        target.write_bytes(_REFERENCE_PROFILE.read_bytes())
        with self.assertRaises(FileNotFoundError):
            self._actions._dispatch_open_package_with_variables(
                ctx=None,
                path=str(target),
                variables_path="/no/such.csv",
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file() and _have_asn1tools(),
    "reference profile + asn1tools required",
)
class VariableDefinitionTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = self._actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_register_then_list(self) -> None:
        self._actions._dispatch_add_variable_definition(
            ctx=None,
            session_id=self._sid,
            name="K_AUTH",
            value="00112233445566778899AABBCCDDEEFF",
            encoding="hex",
        )
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=self._sid)
        names = {entry["name"].upper() for entry in listing["variables"]}
        self.assertIn("K_AUTH", names)

    def test_duplicate_register_rejected_unless_overwrite(self) -> None:
        self._actions._dispatch_add_variable_definition(
            ctx=None, session_id=self._sid, name="DUP", value="00",
        )
        with self.assertRaises(ValueError):
            self._actions._dispatch_add_variable_definition(
                ctx=None, session_id=self._sid, name="DUP", value="11",
            )
        # Overwrite path succeeds.
        result = self._actions._dispatch_add_variable_definition(
            ctx=None, session_id=self._sid, name="DUP", value="11", overwrite=True,
        )
        self.assertEqual(result["value"], "11")

    def test_remove_unknown_raises(self) -> None:
        self._actions._dispatch_add_variable_definition(
            ctx=None, session_id=self._sid, name="REAL", value="00",
        )
        with self.assertRaises(LookupError):
            self._actions._dispatch_remove_variable_definition(
                ctx=None, session_id=self._sid, name="NONEXISTENT",
            )

    def test_remove_unbound_succeeds(self) -> None:
        self._actions._dispatch_add_variable_definition(
            ctx=None, session_id=self._sid, name="UNBOUND", value="00",
        )
        result = self._actions._dispatch_remove_variable_definition(
            ctx=None, session_id=self._sid, name="UNBOUND",
        )
        self.assertEqual(result["name"], "UNBOUND")

    def test_remove_bound_requires_force(self) -> None:
        # Register, then bind by replacing a real PE field with [BOUND_VAR].
        self._actions._dispatch_add_variable_definition(
            ctx=None, session_id=self._sid, name="BOUND_VAR", value="00",
        )
        self._actions._dispatch_add_variable_to_pe(
            ctx=None,
            session_id=self._sid,
            pe_index=0,
            field_path="iccid",
            variable_name="BOUND_VAR",
        )
        with self.assertRaises(ValueError):
            self._actions._dispatch_remove_variable_definition(
                ctx=None, session_id=self._sid, name="BOUND_VAR",
            )
        # Force path drops it anyway.
        forced = self._actions._dispatch_remove_variable_definition(
            ctx=None, session_id=self._sid, name="BOUND_VAR", force=True,
        )
        self.assertEqual(forced["name"], "BOUND_VAR")


@unittest.skipUnless(_have_asn1tools(), "asn1tools required")
class AddPeRenumberTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = self._actions._dispatch_create_package(ctx=None)["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_add_pe_returns_identification(self) -> None:
        result = self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=1,
        )
        # After renumber, the inserted PE should carry a positive
        # identification (1-based per TCA SAIP §A.3).
        self.assertIsNotNone(result["identification"])
        self.assertGreater(result["identification"], 0)

    def test_sequential_inserts_get_unique_identifications(self) -> None:
        first = self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=1,
        )
        second = self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="pinCodes", insert_at=2,
        )
        self.assertNotEqual(first["identification"], second["identification"])

    def test_insert_at_middle_shifts_existing_pe_rows(self) -> None:
        self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=1,
        )
        self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="pinCodes", insert_at=2,
        )
        self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="pukCodes", insert_at=3,
        )
        before = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)
        self.assertEqual(before["rows"][2]["type"], "pinCodes")

        inserted = self._actions._dispatch_add_pe(
            ctx=None, session_id=self._sid, pe_type="akaParameter", insert_at=2,
        )
        after = self._actions._dispatch_list_pes(ctx=None, session_id=self._sid)

        self.assertEqual(inserted["pe_index"], 2)
        self.assertEqual(after["rows"][2]["type"], "akaParameter")
        self.assertEqual(after["rows"][3]["type"], "pinCodes")
        self.assertEqual(after["rows"][4]["type"], "pukCodes")


if __name__ == "__main__":
    unittest.main()
