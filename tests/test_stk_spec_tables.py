# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""StkController lookup tables, pinned to ETSI TS 102 223.

Both tables map a code the card put on the wire to a name an operator
reads in a trace, so a wrong entry misreports what the card did. Neither
had a test, and the values are the kind that shift as a run when one
entry is inserted or dropped.
"""

from __future__ import annotations

import re
import unittest

from SCP03.logic.stk import StkController

#: Table 9.4, Type of Command coding.
TABLE_9_4 = {
    0x01: "REFRESH", 0x02: "MORE TIME", 0x03: "POLL INTERVAL",
    0x04: "POLLING OFF", 0x05: "SET UP EVENT LIST", 0x10: "SET UP CALL",
    0x11: "SEND SS", 0x12: "SEND USSD", 0x13: "SEND SHORT MESSAGE",
    0x14: "SEND DTMF", 0x15: "LAUNCH BROWSER",
    0x16: "GEOGRAPHICAL LOCATION REQUEST", 0x20: "PLAY TONE",
    0x21: "DISPLAY TEXT", 0x22: "GET INKEY", 0x23: "GET INPUT",
    0x24: "SELECT ITEM", 0x25: "SET UP MENU",
    0x26: "PROVIDE LOCAL INFORMATION", 0x27: "TIMER MANAGEMENT",
    0x28: "SET UP IDLE MODE TEXT", 0x30: "PERFORM CARD APDU",
    0x31: "POWER ON CARD", 0x32: "POWER OFF CARD", 0x33: "GET READER STATUS",
    0x34: "RUN AT COMMAND", 0x35: "LANGUAGE NOTIFICATION",
    0x40: "OPEN CHANNEL", 0x41: "CLOSE CHANNEL", 0x42: "RECEIVE DATA",
    0x43: "SEND DATA", 0x44: "GET CHANNEL STATUS", 0x45: "SERVICE SEARCH",
    0x46: "GET SERVICE INFORMATION", 0x47: "DECLARE SERVICE",
    0x50: "SET FRAMES", 0x51: "GET FRAMES STATUS",
    0x60: "RETRIEVE MULTIMEDIA MESSAGE", 0x61: "SUBMIT MULTIMEDIA MESSAGE",
    0x62: "DISPLAY MULTIMEDIA MESSAGE", 0x70: "ACTIVATE",
    0x71: "CONTACTLESS STATE CHANGED", 0x72: "COMMAND CONTAINER",
    0x73: "ENCAPSULATED SESSION CONTROL", 0x79: "LSI COMMAND",
}

#: Clause 8.25, Event list coding. '1A' is Void and carries no name.
EVENT_LIST = {
    0x00: "MT-CALL", 0x01: "CALL-CONNECTED", 0x02: "CALL-DISCONNECTED",
    0x03: "LOCATION-STATUS", 0x04: "USER-ACTIVITY", 0x05: "IDLE-SCREEN",
    0x06: "CARD-READER-STATUS", 0x07: "LANGUAGE-SELECTION",
    0x08: "BROWSER-TERMINATION", 0x09: "DATA-AVAILABLE",
    0x0A: "CHANNEL-STATUS", 0x0B: "ACCESS-TECHNOLOGY-CHANGE",
    0x0C: "DISPLAY-PARAMETERS-CHANGED", 0x0D: "LOCAL-CONNECTION",
    0x0E: "NETWORK-SEARCH-MODE-CHANGE", 0x0F: "BROWSING-STATUS",
    0x10: "FRAMES-INFORMATION-CHANGE", 0x11: "I-WLAN-ACCESS-STATUS-CHANGE",
    0x12: "NETWORK-REJECTION", 0x13: "HCI-CONNECTIVITY",
    0x14: "ACCESS-TECHNOLOGY-CHANGE-MULTI", 0x15: "CSG-CELL-SELECTION",
    0x16: "CONTACTLESS-STATE-REQUEST", 0x17: "IMS-REGISTRATION",
    0x18: "IMS-INCOMING-DATA", 0x19: "PROFILE-CONTAINER",
    0x1B: "SECURED-PROFILE-CONTAINER", 0x1C: "POLL-INTERVAL-NEGOTIATION",
}

VOID_EVENT_CODE = 0x1A


def _norm(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


class ProactiveCommandNames(unittest.TestCase):
    def test_every_name_matches_table_9_4(self) -> None:
        for code, name in StkController.PROACTIVE_NAME_MAP.items():
            with self.subTest(code=f"0x{code:02X}"):
                self.assertIn(code, TABLE_9_4)
                self.assertEqual(_norm(TABLE_9_4[code]), _norm(name))

    def test_the_session_end_value_is_not_a_command(self) -> None:
        """'81' is allowed for Next Action Indicator coding only."""

        self.assertNotIn(0x81, StkController.PROACTIVE_NAME_MAP)


class EventListCoding(unittest.TestCase):
    def test_every_event_matches_clause_8_25(self) -> None:
        for name, code in StkController.EVENT_NAME_MAP.items():
            with self.subTest(name=name):
                self.assertIn(code, EVENT_LIST)
                self.assertEqual(_norm(EVENT_LIST[code]), _norm(name))

    def test_the_void_code_carries_no_name(self) -> None:
        claimed = [n for n, c in StkController.EVENT_NAME_MAP.items()
                   if c == VOID_EVENT_CODE]
        self.assertEqual(claimed, [], "'1A' is Void in clause 8.25")

    def test_codes_are_unique(self) -> None:
        codes = list(StkController.EVENT_NAME_MAP.values())
        self.assertEqual(len(codes), len(set(codes)))


if __name__ == "__main__":
    unittest.main()
