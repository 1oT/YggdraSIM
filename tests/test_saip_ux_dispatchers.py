# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the SAIP UX dispatchers (file listing, PE info, reorder).

* ``saip.list_files`` — extended with ``sort_by`` / ``descending``
* ``saip.pe_info`` — contextual PE-type info pane
* ``saip.reorder_pes`` — move a PE within the sequence (header / end
  anchors are protected)
"""

from __future__ import annotations

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
