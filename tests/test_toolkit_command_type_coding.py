# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Proactive Type of Command values, pinned to ETSI TS 102 223 table 9.4.

These bytes go on the wire in the Command Details TLV, so the terminal
acts on the value, not on the constant's name. The existing tests pass
the constants symbolically, which means a wrong value round-trips
through them and out to the terminal without any of them noticing.
"""

from __future__ import annotations

import unittest

from SIMCARD import toolkit
from SIMCARD.toolkit import ToolkitLogic

#: Transcribed from table 9.4, not from the implementation.
TABLE_9_4 = {
    0x01: "REFRESH",
    0x02: "MORE TIME",
    0x03: "POLL INTERVAL",
    0x04: "POLLING OFF",
    0x05: "SET UP EVENT LIST",
    0x10: "SET UP CALL",
    0x11: "SEND SS",
    0x12: "SEND USSD",
    0x13: "SEND SHORT MESSAGE",
    0x14: "SEND DTMF",
    0x15: "LAUNCH BROWSER",
    0x20: "PLAY TONE",
    0x21: "DISPLAY TEXT",
    0x22: "GET INKEY",
    0x23: "GET INPUT",
    0x24: "SELECT ITEM",
    0x25: "SET UP MENU",
    0x26: "PROVIDE LOCAL INFORMATION",
    0x27: "TIMER MANAGEMENT",
    0x28: "SET UP IDLE MODE TEXT",
    0x30: "PERFORM CARD APDU",
    0x31: "POWER ON CARD",
    0x32: "POWER OFF CARD",
    0x33: "GET READER STATUS",
    0x34: "RUN AT COMMAND",
    0x35: "LANGUAGE NOTIFICATION",
    0x40: "OPEN CHANNEL",
    0x41: "CLOSE CHANNEL",
    0x42: "RECEIVE DATA",
    0x43: "SEND DATA",
    0x44: "GET CHANNEL STATUS",
    0x45: "SERVICE SEARCH",
    0x46: "GET SERVICE INFORMATION",
    0x47: "DECLARE SERVICE",
    0x50: "SET FRAMES",
    0x51: "GET FRAMES STATUS",
}

#: Values table 9.4 assigns to something this module does not implement.
#: Naming them keeps a future constant off an identifier already taken.
NOT_IMPLEMENTED = {
    0x16: "GEOGRAPHICAL LOCATION REQUEST",
    0x60: "RETRIEVE MULTIMEDIA MESSAGE",
    0x61: "SUBMIT MULTIMEDIA MESSAGE",
    0x62: "DISPLAY MULTIMEDIA MESSAGE",
    0x70: "ACTIVATE",
    0x71: "CONTACTLESS STATE CHANGED",
    0x72: "COMMAND CONTAINER",
    0x73: "ENCAPSULATED SESSION CONTROL",
    0x79: "LSI COMMAND",
}


def _constant_name(command_name: str) -> str:
    return command_name.replace(" ", "_") + "_COMMAND"


class ToolkitCommandTypeCoding(unittest.TestCase):
    def test_each_constant_carries_its_table_value(self) -> None:
        for value, name in TABLE_9_4.items():
            attr = _constant_name(name)
            if name == "RUN AT COMMAND":
                attr = "RUN_AT_COMMAND"
            if not hasattr(toolkit, attr):
                continue
            with self.subTest(name=name):
                self.assertEqual(getattr(toolkit, attr), value)

    def test_no_constant_lands_on_another_commands_value(self) -> None:
        """POWER ON and POWER OFF were swapped, and the frame commands sat
        on the multimedia message values."""

        for attr in dir(toolkit):
            if not attr.endswith("_COMMAND"):
                continue
            value = getattr(toolkit, attr)
            if not isinstance(value, int):
                continue
            with self.subTest(attr):
                self.assertNotIn(
                    value,
                    NOT_IMPLEMENTED,
                    f"{attr} is on 0x{value:02X}, which table 9.4 assigns to "
                    f"{NOT_IMPLEMENTED.get(value)}",
                )

    def test_names_agree_with_the_table(self) -> None:
        for value, name in ToolkitLogic.COMMAND_NAMES.items():
            with self.subTest(value=f"0x{value:02X}"):
                self.assertEqual(TABLE_9_4.get(value), name)

    def test_values_are_unique(self) -> None:
        seen: dict[int, str] = {}
        for attr in dir(toolkit):
            if not attr.endswith("_COMMAND"):
                continue
            value = getattr(toolkit, attr)
            if not isinstance(value, int):
                continue
            with self.subTest(attr):
                self.assertNotIn(value, seen, f"{attr} collides with {seen.get(value)}")
            seen[value] = attr


if __name__ == "__main__":
    unittest.main()
