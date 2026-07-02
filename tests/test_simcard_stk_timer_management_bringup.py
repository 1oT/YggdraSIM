# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 223 / 3GPP TS 31.111 STK timer-management bring-up.

Pins the bootstrap proactive-command sequence the simulator emits
right after TERMINAL PROFILE so the modem is steered toward
TIMER EXPIRATION (D7) envelopes instead of the silent POLL INTERVAL
heartbeats.

The tests cover:

* default ``poll_strategy`` (``timer``) emits TIMER MANAGEMENT START
  with the configured timer id / value and *no* POLL INTERVAL,
* explicit ``poll_interval`` strategy is the legacy escape hatch
  that brings POLL INTERVAL back unchanged,
* ``both`` strategy queues TIMER MANAGEMENT first, POLL INTERVAL
  second so proactive bring-up remains deterministic,
* the auto-rearm hook re-enqueues TIMER MANAGEMENT START whenever
  a TIMER EXPIRATION (D7) envelope is delivered,
* auto-rearm honours ``timer_management_auto_rearm = False`` and
  the ``poll_strategy`` selector.
"""

from __future__ import annotations

import unittest

from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    POLL_INTERVAL_COMMAND,
    PROVIDE_LOCAL_INFORMATION_COMMAND,
    TIMER_MANAGEMENT_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _make_toolkit() -> ToolkitLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901234",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    toolkit_logic = ToolkitLogic(state)
    # Strip optional bring-up triggers that would otherwise dilute
    # the assertions; this suite is only interested in timer dispatch.
    toolkit_logic.state.toolkit.provide_imei = False
    toolkit_logic.state.toolkit.event_list = []
    toolkit_logic.state.toolkit.menu_items = []
    toolkit_logic.state.toolkit.menu_title = ""
    return toolkit_logic


def _proactive_kind(payload: bytes) -> tuple[int, int]:
    """Return ``(command_type, qualifier)`` from a D0 proactive frame."""
    assert payload[:1] == b"\xD0", payload.hex()
    body = payload[2:] if payload[1] < 0x80 else payload[3:]
    assert body[:1] == b"\x81", body.hex()
    inner = body[2 : 2 + body[1]]
    return inner[1], inner[2]


def _timer_value_bcd(seconds: int) -> bytes:
    hours = seconds // 3600
    remainder = seconds - hours * 3600
    minutes = remainder // 60
    secs = remainder - minutes * 60

    def _swap(value: int) -> int:
        units = value % 10
        tens = (value // 10) % 10
        return ((units & 0x0F) << 4) | (tens & 0x0F)

    return bytes((_swap(hours), _swap(minutes), _swap(secs)))


def _timer_expiration_envelope(timer_id: int, seconds: int = 0) -> bytes:
    return tlv(
        "D7",
        tlv("A4", bytes((timer_id,))) + tlv("A5", _timer_value_bcd(seconds)),
    )


class TimerManagementBootstrapTests(unittest.TestCase):
    """ETSI TS 102 223 §6.6.21 TIMER MANAGEMENT bootstrap."""

    def test_default_strategy_emits_timer_management_start(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_id = 1
        toolkit_logic.state.toolkit.poll_interval_seconds = 60

        commands = toolkit_logic._bootstrap_commands()

        kinds = [_proactive_kind(c) for c in commands]
        self.assertIn((TIMER_MANAGEMENT_COMMAND, 0x00), kinds)
        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, POLL_INTERVAL_COMMAND)

    def test_default_strategy_encodes_timer_id_and_value(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 65
        toolkit_logic.state.toolkit.timer_management_id = 3

        commands = toolkit_logic._bootstrap_commands()
        timer_command = next(
            c for c in commands if _proactive_kind(c)[0] == TIMER_MANAGEMENT_COMMAND
        )

        # Timer Identifier TLV (24) + Timer Value TLV (25) must trail
        # the Command Details / Device Identities pair. Reference IPA
        # cards emit the comprehension-clear form so picky modems do
        # not reject the proactive command; the simulator now mirrors
        # that.
        self.assertIn(b"\x24\x01\x03", timer_command)
        self.assertIn(b"\x25\x03" + _timer_value_bcd(65), timer_command)
        self.assertEqual(toolkit_logic.state.toolkit.timer_table.get(3), 65)

    def test_poll_interval_strategy_keeps_legacy_path(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "poll_interval"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        self.assertIn((POLL_INTERVAL_COMMAND, 0x00), kinds)
        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, TIMER_MANAGEMENT_COMMAND)

    def test_both_strategy_orders_timer_before_poll_interval(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "both"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        self.assertEqual(
            kinds,
            [(TIMER_MANAGEMENT_COMMAND, 0x00), (POLL_INTERVAL_COMMAND, 0x00)],
        )

    def test_off_strategy_emits_no_polling_command(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "off"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, TIMER_MANAGEMENT_COMMAND)
            self.assertNotEqual(command_type, POLL_INTERVAL_COMMAND)

    def test_provide_imei_is_still_emitted_alongside_timer(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.provide_imei = True
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        # Bootstrap order is fixed: PROVIDE LOCAL INFO -> menu/event ->
        # polling. Pin the contract so a future re-shuffle is caught.
        self.assertEqual(
            [k for k, _ in kinds],
            [PROVIDE_LOCAL_INFORMATION_COMMAND, TIMER_MANAGEMENT_COMMAND],
        )


class TimerExpirationAutoRearmTests(unittest.TestCase):
    """3GPP TS 31.111 §7.5.6 TIMER EXPIRATION re-arm."""

    def test_d7_envelope_triggers_rearm_when_enabled(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_id = 1
        toolkit_logic.state.toolkit.timer_management_auto_rearm = True
        # Bootstrap to consume the initial TIMER MANAGEMENT START.
        for command in toolkit_logic._bootstrap_commands():
            toolkit_logic._enqueue_command(command)
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        queue = list(toolkit_logic.state.pending_fetch_queue)
        self.assertEqual(len(queue), 1)
        self.assertEqual(_proactive_kind(queue[0]), (TIMER_MANAGEMENT_COMMAND, 0x00))
        self.assertEqual(toolkit_logic.state.toolkit.timer_table.get(1), 30)

    def test_auto_rearm_disabled_keeps_queue_empty(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_auto_rearm = False
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        self.assertEqual(list(toolkit_logic.state.pending_fetch_queue), [])

    def test_poll_interval_strategy_does_not_rearm_timer(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "poll_interval"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_auto_rearm = True
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        self.assertEqual(list(toolkit_logic.state.pending_fetch_queue), [])


if __name__ == "__main__":
    unittest.main()
