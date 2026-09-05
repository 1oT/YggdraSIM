# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""StkController lookup tables, pinned to ETSI TS 102 223.

Both tables map a code the card put on the wire to a name an operator
reads in a trace, so a wrong entry misreports what the card did. The
values are the kind that shift as a run when one entry is inserted or
dropped.

The spec tables themselves now live in :mod:`yggdrasim_common.stk_tables`
so the Wireshark dissector's generated Lua, the HIL-Bridge decode view,
and this conformance test all read the same source.
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
