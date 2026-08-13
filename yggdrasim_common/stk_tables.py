# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 223 lookup tables shared by every CAT/STK consumer.

Both tables map a code the card put on the wire to a name an operator
reads in a trace, so a wrong entry misreports what the card did. They
lived in ``tests/test_stk_spec_tables.py`` while the runtime kept a
twelve-entry subset in ``Tools.HilBridge.live_decode_state``; a trace
could therefore name a command one way in the terminal view and another
in the test that was supposed to police it.

Keeping one table means the Wireshark dissector's generated Lua, the
HIL-Bridge decode view, and the conformance test cannot disagree.
"""

from __future__ import annotations

import re

__all__ = [
    "EVENT_LIST",
    "PROACTIVE_COMMANDS",
    "VOID_EVENT_CODE",
    "normalise_spec_name",
]


#: Table 9.4, Type of Command coding.
PROACTIVE_COMMANDS: dict[int, str] = {
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
    0x16: "GEOGRAPHICAL LOCATION REQUEST",
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
    0x60: "RETRIEVE MULTIMEDIA MESSAGE",
    0x61: "SUBMIT MULTIMEDIA MESSAGE",
    0x62: "DISPLAY MULTIMEDIA MESSAGE",
    0x70: "ACTIVATE",
    0x71: "CONTACTLESS STATE CHANGED",
    0x72: "COMMAND CONTAINER",
    0x73: "ENCAPSULATED SESSION CONTROL",
    0x79: "LSI COMMAND",
}

#: Clause 8.25, Event list coding. ``0x1A`` is Void and carries no name.
EVENT_LIST: dict[int, str] = {
    0x00: "MT-CALL",
    0x01: "CALL-CONNECTED",
    0x02: "CALL-DISCONNECTED",
    0x03: "LOCATION-STATUS",
    0x04: "USER-ACTIVITY",
    0x05: "IDLE-SCREEN",
    0x06: "CARD-READER-STATUS",
    0x07: "LANGUAGE-SELECTION",
    0x08: "BROWSER-TERMINATION",
    0x09: "DATA-AVAILABLE",
    0x0A: "CHANNEL-STATUS",
    0x0B: "ACCESS-TECHNOLOGY-CHANGE",
    0x0C: "DISPLAY-PARAMETERS-CHANGED",
    0x0D: "LOCAL-CONNECTION",
    0x0E: "NETWORK-SEARCH-MODE-CHANGE",
    0x0F: "BROWSING-STATUS",
    0x10: "FRAMES-INFORMATION-CHANGE",
    0x11: "I-WLAN-ACCESS-STATUS-CHANGE",
    0x12: "NETWORK-REJECTION",
    0x13: "HCI-CONNECTIVITY",
    0x14: "ACCESS-TECHNOLOGY-CHANGE-MULTI",
    0x15: "CSG-CELL-SELECTION",
    0x16: "CONTACTLESS-STATE-REQUEST",
    0x17: "IMS-REGISTRATION",
    0x18: "IMS-INCOMING-DATA",
    0x19: "PROFILE-CONTAINER",
    0x1B: "SECURED-PROFILE-CONTAINER",
    0x1C: "POLL-INTERVAL-NEGOTIATION",
}

#: Clause 8.25 reserves this code with no assigned event.
VOID_EVENT_CODE = 0x1A

_NON_ALPHANUMERIC = re.compile(r"[^A-Z0-9]")


def normalise_spec_name(value: str) -> str:
    """Fold a spec name to letters and digits for comparison.

    ``POLLING OFF``, ``POLL OFF`` and ``polling-off`` all differ in
    punctuation across the specifications and the codebase, so equality
    checks between them have to ignore it.
    """
    return _NON_ALPHANUMERIC.sub("", str(value or "").upper())
