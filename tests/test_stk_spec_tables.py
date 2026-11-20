# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""StkController lookup tables, pinned to ETSI TS 102 223.

Both tables map a code the card put on the wire to a name an operator
reads in a trace, so a wrong entry misreports what the card did. The
values are the kind that shift as a run when one entry is inserted or
dropped.

The spec tables live in :mod:`yggdrasim_common.stk_tables`, which the
Wireshark dissector's generated Lua and the context decoder read.
``TableCoverage`` checks them against every value the specification
defines. The HIL-Bridge decode view keeps a subset, checked below name
by name.
"""

from __future__ import annotations

import unittest

from SCP03.logic.stk import StkController
from Tools.HilBridge.live_decode_state import (
    _EVENT_NAMES,
    _PROACTIVE_COMMAND_NAMES,
)
from yggdrasim_common.stk_tables import (
    EVENT_LIST,
    PROACTIVE_COMMANDS as TABLE_9_4,
    VOID_EVENT_CODE,
    normalise_spec_name as _norm,
)


#: TS 102 223 v18.3 Table 9.4 (page-207, page-208): every value marked
#: "Used for Type of Command coding" except the reserved and proprietary rows.
TABLE_9_4_DEFINED = frozenset(
    (0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16)
    + (0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28)
    + (0x30, 0x31, 0x32, 0x33, 0x34, 0x35)
    + (0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x50, 0x51)
    + (0x60, 0x61, 0x62, 0x70, 0x71, 0x72, 0x73, 0x79)
)
#: TS 102 223 v18.3 §8.25 (page-168, page-169) with TS 31.111 v19.4 §8.25
#: (page-107) naming the values reserved for 3GPP: '00'-'1F', '1A' Void.
EVENT_LIST_DEFINED = frozenset(range(0x00, 0x20)) - {VOID_EVENT_CODE}


class TableCoverage(unittest.TestCase):
    def test_every_defined_command_type_has_a_name(self) -> None:
        self.assertEqual(len(TABLE_9_4_DEFINED), 45)
        self.assertEqual(set(TABLE_9_4), set(TABLE_9_4_DEFINED))

    def test_every_defined_event_has_a_name(self) -> None:
        self.assertEqual(set(EVENT_LIST), set(EVENT_LIST_DEFINED))


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


class LiveDecodeStateConformance(unittest.TestCase):
    """The HIL-Bridge decode view names commands the same way the spec does.

    That view only carries the subset of commands a bridged trace tends
    to show, so it is checked as a subset rather than for equality.
    Punctuation is ignored: the decode view writes ``LOCATION STATUS``
    where clause 8.25 writes ``LOCATION-STATUS``, and both are correct.
    """

    def test_proactive_names_match_table_9_4(self) -> None:
        for code, name in _PROACTIVE_COMMAND_NAMES.items():
            with self.subTest(code=f"0x{code:02X}"):
                self.assertIn(code, TABLE_9_4)
                self.assertEqual(_norm(TABLE_9_4[code]), _norm(name))

    def test_event_names_match_clause_8_25(self) -> None:
        for code, name in _EVENT_NAMES.items():
            with self.subTest(code=f"0x{code:02X}"):
                self.assertIn(code, EVENT_LIST)
                self.assertEqual(_norm(EVENT_LIST[code]), _norm(name))


if __name__ == "__main__":
    unittest.main()
