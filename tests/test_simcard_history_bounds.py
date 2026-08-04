# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounds on the toolkit history accumulators.

``SimulatedSimCardEngine`` is a process-wide singleton, so a list that
grows once per envelope grows for the life of the process. These cases
pin the cap and the semantics callers rely on: the list type stays
``list``, the newest entry stays at ``[-1]``, and only entries older
than the cap disappear.
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.state import (
    MAX_HISTORY_ENTRIES,
    SimCardState,
    _resolve_history_cap,
    append_bounded,
)
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import tlv


def _envelope(*body: bytes) -> bytes:
    joined = b"".join(body)
    return bytes((0xD6, len(joined))) + joined


def _fallback(payload: bytes) -> tuple[bytes, int, int]:
    del payload
    return b"", 0x90, 0x00


class AppendBoundedTests(unittest.TestCase):
    def test_stays_a_plain_list(self) -> None:
        target: list[int] = []
        append_bounded(target, 1, maxlen=4)
        self.assertIsInstance(target, list)
        self.assertEqual(target, [1])

    def test_drops_the_oldest_entry_past_the_cap(self) -> None:
        target: list[int] = []
        for value in range(6):
            append_bounded(target, value, maxlen=4)
        self.assertEqual(target, [2, 3, 4, 5])
        self.assertEqual(target[-1], 5)
        self.assertEqual(len(target), 4)

    def test_a_pre_oversized_list_is_trimmed_to_the_cap(self) -> None:
        target = list(range(10))
        append_bounded(target, 99, maxlen=3)
        self.assertEqual(target, [8, 9, 99])

    def test_zero_maxlen_uses_the_module_cap(self) -> None:
        target: list[int] = []
        for value in range(MAX_HISTORY_ENTRIES + 5):
            append_bounded(target, value)
        self.assertEqual(len(target), MAX_HISTORY_ENTRIES)
        self.assertEqual(target[-1], MAX_HISTORY_ENTRIES + 4)


class HistoryCapResolutionTests(unittest.TestCase):
    def _with_env(self, value: str | None) -> int:
        previous = os.environ.get("YGGDRASIM_SIM_HISTORY_CAP")
        if value is None:
            os.environ.pop("YGGDRASIM_SIM_HISTORY_CAP", None)
        else:
            os.environ["YGGDRASIM_SIM_HISTORY_CAP"] = value
        try:
            return _resolve_history_cap()
        finally:
            if previous is None:
                os.environ.pop("YGGDRASIM_SIM_HISTORY_CAP", None)
            else:
                os.environ["YGGDRASIM_SIM_HISTORY_CAP"] = previous

    def test_default_is_256(self) -> None:
        self.assertEqual(self._with_env(None), 256)

    def test_env_override_is_honoured(self) -> None:
        self.assertEqual(self._with_env("32"), 32)

    def test_garbage_and_non_positive_fall_back_to_the_default(self) -> None:
        for raw in ("", "   ", "abc", "0", "-5", "1.5"):
            with self.subTest(raw=raw):
                self.assertEqual(self._with_env(raw), 256)


class ToolkitHistoryBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901235",
            iccid="8988000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)

    def _send_events(self, count: int) -> None:
        for index in range(count):
            code = 0x03 if index % 2 == 0 else 0x05
            self.toolkit.handle_envelope(
                _envelope(tlv("99", bytes((code,)))),
                _fallback,
            )

    def test_event_history_stops_at_the_cap(self) -> None:
        self._send_events(MAX_HISTORY_ENTRIES + 40)
        self.assertEqual(len(self.state.toolkit.event_history), MAX_HISTORY_ENTRIES)

    def test_envelope_history_stops_at_the_cap(self) -> None:
        self._send_events(MAX_HISTORY_ENTRIES + 40)
        self.assertEqual(len(self.state.toolkit.envelope_history), MAX_HISTORY_ENTRIES)

    def test_the_newest_envelope_is_still_last(self) -> None:
        self._send_events(MAX_HISTORY_ENTRIES + 3)
        last = _envelope(tlv("99", bytes((0x06,))))
        self.toolkit.handle_envelope(last, _fallback)
        self.assertEqual(self.state.toolkit.envelope_history[-1], last)
        self.assertEqual(self.state.toolkit.last_event_code, 0x06)

    def test_a_short_run_keeps_every_entry(self) -> None:
        self._send_events(4)
        self.assertEqual(self.state.toolkit.event_history, [0x03, 0x05, 0x03, 0x05])


if __name__ == "__main__":
    unittest.main()
