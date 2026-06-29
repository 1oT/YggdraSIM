# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP UX dispatchers (file listing, PE info, reorder).

* ``saip.list_files`` — extended with ``sort_by`` / ``descending``
* ``saip.pe_info`` — contextual PE-type info pane
* ``saip.reorder_pes`` — move a PE within the sequence (header / end
  anchors are protected)
"""

from __future__ import annotations

import base64
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ListFilesSortTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_natural_sort_default(self) -> None:
        result = self._actions._dispatch_list_files(ctx=None, session_id=self._sid)
        self.assertEqual(result["sort_by"], "natural")
        self.assertGreater(result["count"], 0)

    def test_sort_by_file_id_ascending(self) -> None:
        result = self._actions._dispatch_list_files(
            ctx=None, session_id=self._sid, sort_by="file_id"
        )
        ids = [str(row.get("file_id") or "") for row in result["rows"] if row.get("file_id")]
        self.assertEqual(ids, sorted(ids))

    def test_sort_by_file_id_descending(self) -> None:
        result = self._actions._dispatch_list_files(
            ctx=None, session_id=self._sid, sort_by="file_id", descending=True
        )
        ids = [str(row.get("file_id") or "") for row in result["rows"] if row.get("file_id")]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_sort_by_name(self) -> None:
        result = self._actions._dispatch_list_files(
            ctx=None, session_id=self._sid, sort_by="name"
        )
        names = [
            str(row.get("friendly_name") or "").lower()
            for row in result["rows"]
            if row.get("friendly_name")
        ]
        self.assertEqual(names, sorted(names))

    def test_unknown_sort_key_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_list_files(
                ctx=None, session_id=self._sid, sort_by="bogus"
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class OpenPackageUploadTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid: str | None = None

    def tearDown(self) -> None:
        if self._sid is not None:
            try:
                self._manager.release(self._sid)
            except Exception:
                pass

    def test_browser_upload_opens_reference_profile(self) -> None:
        payload = base64.b64encode(_REFERENCE_PROFILE.read_bytes()).decode("ascii")
        result = self._actions._dispatch_open_package_upload(
            ctx=None,
            filename="reference_test_profile.txt",
            content_base64=payload,
        )
        self._sid = result["session_id"]
        self.assertTrue(result["uploaded"])
        self.assertEqual(result["uploaded_file_name"], "reference_test_profile.txt")
        self.assertGreater(result["pe_count"], 0)
        self.assertIn("source_path", result)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class PeInfoTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_pe_info_for_header(self) -> None:
        result = self._actions._dispatch_pe_info(
            ctx=None, session_id=self._sid, pe_index=0
        )
        self.assertEqual(result["pe_index"], 0)
        self.assertIn("ProfileHeader", result["asn1"])
        self.assertIn("TCA SAIP", result["spec"])
        self.assertIn("ICCID", result["summary"])

    def test_pe_info_unknown_type_falls_back(self) -> None:
        # Last PE is the end sentinel — exercise the fallback for
        # registered known types.
        from yggdrasim_common.gui_server.sessions import get_manager
        handle = self._manager.claim(self._sid)
        last = len(handle["pes"].pe_list) - 1
        result = self._actions._dispatch_pe_info(
            ctx=None, session_id=self._sid, pe_index=last
        )
        self.assertEqual(result["pe_index"], last)
        self.assertIn("title", result)

    def test_pe_info_index_out_of_range(self) -> None:
        with self.assertRaises(IndexError):
            self._actions._dispatch_pe_info(
                ctx=None, session_id=self._sid, pe_index=999
            )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class PinPukReferenceUxTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_reference_catalog_surfaces_defined_puks(self) -> None:
        result = self._actions._dispatch_pin_puk_reference_catalog(
            ctx=None,
            session_id=self._sid,
        )
        self.assertEqual(len(result["pin_options"]), 26)
        self.assertEqual(len(result["puk_options"]), 16)
        defined = {row["decimal"] for row in result["defined_puk_references"]}
        self.assertIn(1, defined)
        self.assertIn(129, defined)

    def test_add_remove_pin_entry_refreshes_decoded_fields(self) -> None:
        before = self._actions._dispatch_list_decoded_fields(
            ctx=None,
            session_id=self._sid,
            section_key="pinCodes",
        )
        add = self._actions._dispatch_pin_puk_mutate_entry(
            ctx=None,
            session_id=self._sid,
            section_key="pinCodes",
            operation="add",
        )
        self.assertEqual(add["entry_count"], 3)
        after_add = self._actions._dispatch_list_decoded_fields(
            ctx=None,
            session_id=self._sid,
            section_key="pinCodes",
        )
        self.assertGreater(len(after_add["fields"]), len(before["fields"]))
        remove = self._actions._dispatch_pin_puk_mutate_entry(
            ctx=None,
            session_id=self._sid,
            section_key="pinCodes",
            operation="remove",
            index=2,
        )
        self.assertEqual(remove["entry_count"], 2)

    def test_add_puk_entry_uses_next_unused_reference(self) -> None:
        result = self._actions._dispatch_pin_puk_mutate_entry(
            ctx=None,
            session_id=self._sid,
            section_key="pukCodes",
            operation="add",
        )
        self.assertEqual(result["entry_count"], 3)
        catalog = self._actions._dispatch_pin_puk_reference_catalog(
            ctx=None,
            session_id=self._sid,
        )
        defined = {row["decimal"] for row in catalog["defined_puk_references"]}
        self.assertIn(2, defined)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class AddPePresetTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_security_domain_presets_are_listed(self) -> None:
        result = self._actions._dispatch_list_pe_presets(
            ctx=None,
            pe_type="securityDomain",
        )
        ids = {row["preset_id"] for row in result["rows"]}
        self.assertIn("", ids)
        self.assertIn("mno_sd_scp_all", ids)
        self.assertIn("sd_scp03_minimal", ids)

    def test_add_security_domain_preset_populates_c9_and_keys(self) -> None:
        result = self._actions._dispatch_add_pe(
            ctx=None,
            session_id=self._sid,
            pe_type="securityDomain",
            preset="mno_sd_scp_all",
        )
        self.assertEqual(result["preset"], "mno_sd_scp_all")
        handle = self._manager.claim(self._sid)
        pe = handle["pes"].pe_list[result["pe_index"]]
        decoded = pe.decoded
        c9 = decoded["instance"]["applicationSpecificParametersC9"]
        self.assertEqual(c9.hex().upper(), "810203008102800081028100")
        self.assertEqual(decoded["instance"]["applicationPrivileges"].hex().upper(), "82DC20")
        self.assertEqual(len(decoded["keyList"]), 3)
        self.assertEqual(
            [entry["keyComponents"][0]["keyType"].hex().upper() for entry in decoded["keyList"]],
            ["88", "88", "88"],
        )


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ReorderPesTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = saip_actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]
        self._handle = self._manager.claim(self._sid)
        self._n = len(self._handle["pes"].pe_list)

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass

    def test_refuses_moving_header(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_reorder_pes(
                ctx=None, session_id=self._sid, from_index=0, to_index=2
            )

    def test_refuses_displacing_header(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_reorder_pes(
                ctx=None, session_id=self._sid, from_index=2, to_index=0
            )

    def test_refuses_moving_end_sentinel(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_reorder_pes(
                ctx=None,
                session_id=self._sid,
                from_index=self._n - 1,
                to_index=2,
            )

    def test_refuses_displacing_end_sentinel(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_reorder_pes(
                ctx=None,
                session_id=self._sid,
                from_index=2,
                to_index=self._n - 1,
            )

    def test_noop_when_indices_equal(self) -> None:
        result = self._actions._dispatch_reorder_pes(
            ctx=None, session_id=self._sid, from_index=2, to_index=2
        )
        self.assertFalse(result["moved"])

    def test_legal_swap_succeeds(self) -> None:
        # Use indices 1 and 2 (well clear of the anchors).
        result = self._actions._dispatch_reorder_pes(
            ctx=None, session_id=self._sid, from_index=1, to_index=2
        )
        self.assertTrue(result["moved"])
        self.assertEqual(result["from_index"], 1)
        self.assertEqual(result["to_index"], 2)

    def test_index_out_of_range_rejected(self) -> None:
        with self.assertRaises(IndexError):
            self._actions._dispatch_reorder_pes(
                ctx=None, session_id=self._sid, from_index=999, to_index=2
            )


if __name__ == "__main__":
    unittest.main()
