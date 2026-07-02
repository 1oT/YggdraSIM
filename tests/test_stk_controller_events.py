# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SCP03.logic.stk.StkController`` event-dispatch methods.

Covers: send_event, send_location_status, simulate_call_connected,
simulate_call_disconnected.
The card transport connection is replaced with a MagicMock so no
physical or simulated card is required.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from SCP03.logic.stk import StkController


def _make_controller(*, sw_response=(b"", 0x90, 0x00)) -> StkController:
    conn = MagicMock()
    conn.transmit.return_value = sw_response
    tp = MagicMock()
    tp.connection = conn
    return StkController(transport=tp)


class SendEventTests(unittest.TestCase):

    def test_known_event_returns_sw(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_event("CALL-CONNECTED")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_records_trigger_history(self) -> None:
        ctrl = _make_controller()
        ctrl.send_event("CALL-CONNECTED")
        self.assertGreater(len(ctrl.state.trigger_history), 0)
        self.assertIn("EVENT", ctrl.state.trigger_history[0])

    def test_unknown_event_raises(self) -> None:
        ctrl = _make_controller()
        with self.assertRaises(ValueError):
            ctrl.send_event("TOTALLY-UNKNOWN-EVENT-XYZ")

    def test_returns_three_tuple(self) -> None:
        ctrl = _make_controller()
        result = ctrl.send_event("DATA-AVAILABLE")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)

    def test_data_available_event_dispatched(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_event("DATA-AVAILABLE")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_location_status_event_dispatched(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_event("LOCATION-STATUS")
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class SendLocationStatusTests(unittest.TestCase):

    def test_default_status_returns_sw(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_location_status()
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_records_location_status_trigger(self) -> None:
        ctrl = _make_controller()
        ctrl.send_location_status(status_value=0x00)
        self.assertIn("LOCATION STATUS", ctrl.state.trigger_history)

    def test_custom_status_value_accepted(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_location_status(status_value=0x01)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_custom_location_hex_applied(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.send_location_status(
            status_value=0x00,
            location_hex="001F100001000001",
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # The state should reflect the new location.
        self.assertEqual(ctrl.state.location_information, bytes.fromhex("001F100001000001"))

    def test_invalid_location_hex_raises(self) -> None:
        ctrl = _make_controller()
        with self.assertRaises(ValueError):
            ctrl.send_location_status(location_hex="ZZZZ")

    def test_returns_three_tuple(self) -> None:
        ctrl = _make_controller()
        result = ctrl.send_location_status()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)


class SimulateCallConnectedTests(unittest.TestCase):

    def test_returns_sw_9000(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.simulate_call_connected()
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_delegates_to_send_event(self) -> None:
        ctrl = _make_controller()
        ctrl.simulate_call_connected()
        # Trigger history entry is set by send_event.
        self.assertTrue(
            any("Call Connected" in entry for entry in ctrl.state.trigger_history)
        )

    def test_extra_tlvs_hex_forwarded(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.simulate_call_connected(extra_tlvs_hex="")
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class SimulateCallDisconnectedTests(unittest.TestCase):

    def test_returns_sw_9000(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.simulate_call_disconnected()
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_delegates_to_send_event(self) -> None:
        ctrl = _make_controller()
        ctrl.simulate_call_disconnected()
        self.assertTrue(
            any("Call Disconnected" in entry for entry in ctrl.state.trigger_history)
        )

    def test_extra_tlvs_hex_forwarded(self) -> None:
        ctrl = _make_controller()
        _, sw1, sw2 = ctrl.simulate_call_disconnected(extra_tlvs_hex="")
        self.assertEqual((sw1, sw2), (0x90, 0x00))


if __name__ == "__main__":
    unittest.main()
