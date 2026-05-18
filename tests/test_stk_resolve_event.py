# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP03/logic/stk.py StkController.resolve_event_code.

The method is stateless (reads only CLASS-level EVENT_NAME_MAP),
so a bare __new__ instance is sufficient — no transport required.
"""

from __future__ import annotations

import unittest

from SCP03.logic.stk import StkController


class ResolveEventCodeTests(unittest.TestCase):

    def setUp(self) -> None:
        self._ctrl = StkController.__new__(StkController)

    def test_known_name_mt_call(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("MT-CALL"), 0)

    def test_known_name_call_connected(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("CALL-CONNECTED"), 1)

    def test_known_name_call_disconnected(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("CALL-DISCONNECTED"), 2)

    def test_known_name_location_status(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("LOCATION-STATUS"), 3)

    def test_underscore_separator_accepted(self) -> None:
        # Underscores are normalised to hyphens before lookup
        self.assertEqual(self._ctrl.resolve_event_code("MT_CALL"), 0)

    def test_lowercase_accepted(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("mt-call"), 0)

    def test_hex_string_with_0x_prefix(self) -> None:
        # 0x03 == LOCATION-STATUS
        self.assertEqual(self._ctrl.resolve_event_code("0x03"), 3)

    def test_two_digit_bare_hex(self) -> None:
        self.assertEqual(self._ctrl.resolve_event_code("03"), 3)

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._ctrl.resolve_event_code("")

    def test_unknown_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._ctrl.resolve_event_code("UNKNOWN-EVENT")

    def test_none_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._ctrl.resolve_event_code(None)


if __name__ == "__main__":
    unittest.main()
