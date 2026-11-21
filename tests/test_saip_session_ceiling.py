# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SAIP authoring sessions are bounded by their own ceiling, not the reader cap.

Opening a ninth package used to evict the first: the manager's shared
cap of eight bounds sessions holding a PC/SC handle and evicts the oldest
clean one to admit a newcomer. An authoring session counts against
``_AUTHORING_SESSION_CAP`` instead, is refused at that ceiling rather
than evicted, and leaves the reader cap untouched however many packages
are open.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock


_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = (
    _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class AuthoringSessionCeilingTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server import sessions as sessions_module
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self._actions = saip_actions
        # A manager of its own with a reader cap of one: any authoring
        # session counted against that cap would be evicted by the next
        # open, so the ceiling has to be doing the bounding.
        self._manager = sessions_module.SessionManager(
            max_sessions=1, default_idle_timeout_s=600.0
        )
        self._patches = [
            mock.patch.object(sessions_module, "_MANAGER", self._manager),
            mock.patch.object(saip_actions, "_AUTHORING_SESSION_CAP", 2),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self) -> None:
        self._manager.close_all()
        for patch in self._patches:
            patch.stop()

    def _open(self) -> str:
        return self._actions._dispatch_open_package(
            ctx=None, path=str(_REFERENCE_PROFILE)
        )["session_id"]

    def test_ceiling_refuses_the_next_package_and_keeps_the_open_ones(self) -> None:
        first = self._open()
        second = self._open()
        self.assertTrue(self._manager.has(first))
        self.assertTrue(self._manager.has(second))

        with self.assertRaisesRegex(RuntimeError, r"saip session ceiling reached \(2 open\)"):
            self._open()

        self.assertTrue(self._manager.has(first))
        self.assertTrue(self._manager.has(second))
        self.assertEqual(self._manager.get(first).max_of_kind, 2)

    def test_card_sessions_neither_count_nor_evict_authoring_sessions(self) -> None:
        first = self._open()
        second = self._open()

        card = self._manager.open(kind="scp03", handle={}, close=lambda: None)
        self.assertTrue(self._manager.has(first))
        self.assertTrue(self._manager.has(second))
        self.assertTrue(self._manager.has(card.id))

        replacement = self._manager.open(kind="scp03", handle={}, close=lambda: None)
        self.assertFalse(self._manager.has(card.id))
        self.assertTrue(self._manager.has(replacement.id))
        self.assertTrue(self._manager.has(first))
        self.assertTrue(self._manager.has(second))


if __name__ == "__main__":
    unittest.main()
