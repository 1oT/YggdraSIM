# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 223 conformance regressions for the STK trace surface.

These tests pin the parser to the spec values for the Duration TLV
(``§8.8``) and the Type-of-Command / Event-List name maps so a future
trim of the lookup tables cannot silently regress trace output.
"""

from __future__ import annotations

import unittest

from SCP03.logic.stk import StkController
from SIMCARD.toolkit import ToolkitLogic


class DurationTlvDecodingTests(unittest.TestCase):
    """ETSI TS 102 223 §8.8 Duration TLV decoding on both ends."""

    def test_controller_decodes_one_minute_duration_correctly(self):
        # POLL INTERVAL D008 8103010300 8202 8182 8402 0001
        # The 84 02 00 01 trailer is "1 minute" (unit=minutes, value=1),
        # not the 1-second value the previous big-endian shortcut
        # produced.
        proactive_command = bytes.fromhex("D00D8103010300820281828402 0001".replace(" ", ""))
        controller = StkController(transport=None)

        command_type, _qualifier, fields = controller._parse_proactive_command(proactive_command)

        self.assertEqual(command_type, 0x03)
        self.assertEqual(fields["duration_unit"], 0x00)
        self.assertEqual(fields["duration_value"], 0x01)
        self.assertEqual(fields["poll_interval_seconds"], 60)

    def test_controller_decodes_seconds_duration_correctly(self):
        proactive_command = bytes.fromhex("D00D81030103008202818284020105")
        controller = StkController(transport=None)

        _command_type, _qualifier, fields = controller._parse_proactive_command(proactive_command)

        self.assertEqual(fields["duration_unit"], 0x01)
        self.assertEqual(fields["duration_value"], 0x05)
        self.assertEqual(fields["poll_interval_seconds"], 5)

    def test_controller_decodes_tenths_of_seconds_with_ceiling_round(self):
        # 84 02 02 05 = 0.5s; we round up to 1s so trace output never
        # collapses sub-second poll intervals to "0s".
        proactive_command = bytes.fromhex("D00D81030103008202818284020205")
        controller = StkController(transport=None)

        _command_type, _qualifier, fields = controller._parse_proactive_command(proactive_command)

        self.assertEqual(fields["duration_unit"], 0x02)
        self.assertEqual(fields["duration_value"], 0x05)
        self.assertEqual(fields["poll_interval_seconds"], 1)

    def test_simulator_parser_reports_minutes_correctly(self):
        toolkit = ToolkitLogic.__new__(ToolkitLogic)

        proactive_command = bytes.fromhex("D00D81030103008202818284020001")
        fields = toolkit._parse_proactive_command(proactive_command)

        self.assertIsNotNone(fields)
        self.assertEqual(fields["duration_unit"], 0x00)
        self.assertEqual(fields["duration_value"], 0x01)
        self.assertEqual(fields["poll_interval_seconds"], 60)


class ProactiveNameMapTests(unittest.TestCase):
    """Spot-check the proactive-command name map covers the codes the
    simulator can emit at bootstrap and in the management chain."""

    def test_set_up_menu_is_named(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._proactive_command_name(0x25), "SET UP MENU")

    def test_open_close_send_receive_channels_are_named(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._proactive_command_name(0x40), "OPEN CHANNEL")
        self.assertEqual(controller._proactive_command_name(0x41), "CLOSE CHANNEL")
        self.assertEqual(controller._proactive_command_name(0x42), "RECEIVE DATA")
        self.assertEqual(controller._proactive_command_name(0x43), "SEND DATA")
        self.assertEqual(controller._proactive_command_name(0x44), "GET CHANNEL STATUS")

    def test_select_item_and_set_up_idle_text_are_named(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._proactive_command_name(0x24), "SELECT ITEM")
        self.assertEqual(controller._proactive_command_name(0x28), "SET UP IDLE MODE TEXT")

    def test_unknown_codes_still_render_as_hex(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._proactive_command_name(0xEE), "UNKNOWN 0xEE")


class EventNameMapTests(unittest.TestCase):
    """Spot-check the event-download name map for the events the
    default ToolkitState pre-arms (``[0x03, 0x09, 0x0A, 0x12]``)."""

    def test_network_rejection_event_is_named(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._stk_event_name(0x12), "Network Rejection")

    def test_card_reader_status_event_is_named(self):
        controller = StkController(transport=None)
        self.assertEqual(controller._stk_event_name(0x06), "Card Reader Status")

    def test_default_event_list_renders_with_friendly_names(self):
        controller = StkController(transport=None)
        rendered = [controller._stk_event_name(value) for value in (0x03, 0x09, 0x0A, 0x12)]
        self.assertEqual(
            rendered,
            ["Location Status", "Data Available", "Channel Status", "Network Rejection"],
        )


if __name__ == "__main__":
    unittest.main()
