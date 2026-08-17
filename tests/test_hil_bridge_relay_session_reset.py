# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Relay-session boundaries power-cycle the physical card.

Operator shells drive the card through the APDU relay while a modem
session may be live, and they leave selected AIDs, open logical
channels, and established SCP03 / SCP11 secure channels behind. The
SIMtrace2 board reset cannot clear any of that -- the card sits in the
PC/SC reader, not on the board -- so the bridge resets the card when a
relay session starts, is replaced, or ends.

No reader, no sockets, and no HTTP server: the bridge is assembled from
fakes so every boundary can be driven directly.
"""

from __future__ import annotations

import queue
import threading
import types
import unittest
from unittest import mock

from Tools.HilBridge.proactive import ProactiveRefreshBroker
from Tools.HilBridge.router import (
    BridgeConfig,
    HilBridgeServer,
    resolve_relay_session_reset_enabled,
)


def _build_server(*, relay_session_reset_enabled: bool = True, bankd=None) -> HilBridgeServer:
    """Assemble the minimum of HilBridgeServer the boundary paths touch."""
    card = types.SimpleNamespace(
        backend_name="reader",
        reset_card=mock.Mock(return_value={"mode": "pcsc-reconnect-unpower"}),
        get_atr=mock.Mock(return_value=bytes.fromhex("3B9F")),
        reader_label="PCSC test reader",
    )
    worker = types.SimpleNamespace(drain=mock.Mock(), nudge=mock.Mock())
    server = object.__new__(HilBridgeServer)
    server._config = BridgeConfig(relay_session_reset_enabled=relay_session_reset_enabled)
    server._card_lock = threading.RLock()
    server._proactive_lock = threading.Lock()
    server._card = card
    server._card_worker = worker
    server._relay_session_id = ""
    server._relay_session_lock = threading.Lock()
    server._pending_card_resync = queue.SimpleQueue()
    server._session = types.SimpleNamespace(
        proactive=ProactiveRefreshBroker(),
        atr_bytes=b"",
        atr_sent=True,
        control=None,
        bankd=bankd,
    )
    server._apdu_relay = types.SimpleNamespace(
        card_reset_url="http://127.0.0.1:44215/card/reset",
    )
    return server


def _drain_resync_reasons(server: HilBridgeServer) -> list[str]:
    reasons: list[str] = []
    while True:
        try:
            reasons.append(str(server._pending_card_resync.get_nowait()))
        except queue.Empty:
            return reasons


class ResolveRelaySessionResetEnabledTests(unittest.TestCase):

    def test_enabled_by_default(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(resolve_relay_session_reset_enabled())

    def test_explicit_value_wins(self) -> None:
        self.assertFalse(resolve_relay_session_reset_enabled(False))

    def test_falsey_environment_disables(self) -> None:
        for value in ("0", "false", "no", "OFF", "disabled"):
            with mock.patch.dict(
                "os.environ",
                {"YGGDRASIM_HIL_RELAY_SESSION_RESET": value},
                clear=True,
            ):
                self.assertFalse(resolve_relay_session_reset_enabled())

    def test_unrecognised_environment_stays_enabled(self) -> None:
        # The safe direction: leaving card state behind is the failure
        # this guards, so anything ambiguous keeps the guard on.
        with mock.patch.dict(
            "os.environ",
            {"YGGDRASIM_HIL_RELAY_SESSION_RESET": "maybe"},
            clear=True,
        ):
            self.assertTrue(resolve_relay_session_reset_enabled())


class RelaySessionBoundaryTests(unittest.TestCase):

    def test_first_session_id_power_cycles_the_card(self) -> None:
        server = _build_server()

        server._note_relay_session_activity("scp11-a")

        server._card.reset_card.assert_called_once_with()
        self.assertEqual(server._relay_session_id, "scp11-a")
        self.assertEqual(server._session.atr_bytes, bytes.fromhex("3B9F"))

    def test_further_apdus_in_the_same_session_do_not_reset(self) -> None:
        server = _build_server()

        server._note_relay_session_activity("scp11-a")
        server._note_relay_session_activity("scp11-a")
        server._note_relay_session_activity("scp11-a")

        server._card.reset_card.assert_called_once_with()

    def test_switching_session_id_power_cycles_again(self) -> None:
        server = _build_server()

        server._note_relay_session_activity("scp11-a")
        server._note_relay_session_activity("scp03-b")

        self.assertEqual(server._card.reset_card.call_count, 2)
        self.assertEqual(server._relay_session_id, "scp03-b")

    def test_blank_session_id_is_left_alone(self) -> None:
        # Unidentified callers cannot be tracked; resetting on each of
        # their APDUs would be worse than the state they might leave.
        server = _build_server()

        server._note_relay_session_activity("")

        server._card.reset_card.assert_not_called()
        self.assertEqual(server._relay_session_id, "")

    def test_disabled_config_skips_the_reset(self) -> None:
        server = _build_server(relay_session_reset_enabled=False)

        server._note_relay_session_activity("scp11-a")

        server._card.reset_card.assert_not_called()
        self.assertEqual(server._relay_session_id, "")

    def test_session_end_power_cycles_and_clears_the_active_session(self) -> None:
        server = _build_server()
        server._note_relay_session_activity("scp11-a")
        server._card.reset_card.reset_mock()

        payload = server.end_relay_session("scp11-a")

        server._card.reset_card.assert_called_once_with()
        self.assertEqual(payload["status"], "reset")
        self.assertEqual(payload["boundary"], "end")
        self.assertEqual(payload["sessionId"], "scp11-a")
        self.assertEqual(payload["atr"], "3B9F")
        self.assertEqual(server._relay_session_id, "")

    def test_session_end_for_a_superseded_session_is_ignored(self) -> None:
        # The session that replaced it already reset the card on its
        # way in; resetting again would bounce a live modem for nothing.
        server = _build_server()
        server._note_relay_session_activity("scp11-a")
        server._note_relay_session_activity("scp03-b")
        server._card.reset_card.reset_mock()

        payload = server.end_relay_session("scp11-a")

        server._card.reset_card.assert_not_called()
        self.assertEqual(payload["status"], "ignored")
        self.assertEqual(server._relay_session_id, "scp03-b")

    def test_session_end_without_an_id_is_ignored(self) -> None:
        server = _build_server()

        payload = server.end_relay_session("")

        server._card.reset_card.assert_not_called()
        self.assertEqual(payload["status"], "ignored")

    def test_card_reset_endpoint_routes_the_end_boundary(self) -> None:
        server = _build_server()
        server._note_relay_session_activity("scp11-a")

        payload = server._handle_relay_card_reset(session_id="scp11-a", boundary="end")

        self.assertEqual(payload["boundary"], "end")
        self.assertEqual(server._relay_session_id, "")

    def test_card_reset_endpoint_without_a_boundary_stays_a_plain_reset(self) -> None:
        server = _build_server()
        server._note_relay_session_activity("scp11-a")

        payload = server._handle_relay_card_reset(session_id="scp11-a")

        self.assertEqual(payload["status"], "reset")
        self.assertNotIn("boundary", payload)
        # A plain reset does not end the session.
        self.assertEqual(server._relay_session_id, "scp11-a")


class ConcurrentRelaySessionTests(unittest.TestCase):
    """The relay serves concurrent HTTP threads."""

    def test_same_session_from_many_threads_resets_once(self) -> None:
        server = _build_server()
        barrier = threading.Barrier(8)

        def _worker() -> None:
            barrier.wait()
            server._note_relay_session_activity("scp11-a")

        threads = [threading.Thread(target=_worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)

        server._card.reset_card.assert_called_once_with()
        self.assertEqual(server._relay_session_id, "scp11-a")

    def test_distinct_sessions_from_many_threads_settle_on_one_winner(self) -> None:
        server = _build_server()
        barrier = threading.Barrier(6)

        def _worker(index: int) -> None:
            barrier.wait()
            server._note_relay_session_activity(f"session-{index}")

        threads = [threading.Thread(target=_worker, args=(index,)) for index in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)

        # Each distinct id claims the slot exactly once, so the resets
        # match the ids seen rather than exceeding them.
        self.assertEqual(server._card.reset_card.call_count, 6)
        self.assertTrue(server._relay_session_id.startswith("session-"))


class CardResyncHandoffTests(unittest.TestCase):
    """The card half runs inline; the socket half is deferred."""

    def test_reset_queues_the_bankd_close_instead_of_doing_it_inline(self) -> None:
        bankd = object()
        server = _build_server(bankd=bankd)

        with mock.patch.object(HilBridgeServer, "_close_bankd_side") as close_bankd:
            server._note_relay_session_activity("scp11-a")
            # The selector belongs to the event loop, so nothing may
            # touch it from the relay thread.
            close_bankd.assert_not_called()

        self.assertEqual(_drain_resync_reasons(server), ["relay session start (scp11-a)"])

    def test_reset_wakes_the_event_loop(self) -> None:
        server = _build_server()

        server._note_relay_session_activity("scp11-a")

        server._card_worker.nudge.assert_called_once_with()

    def test_atr_sent_is_cleared_before_the_handoff(self) -> None:
        # A clientSlotStatusInd racing the reset must not be answered
        # with an ATR captured before the card lost power.
        server = _build_server()

        server._note_relay_session_activity("scp11-a")

        self.assertFalse(server._session.atr_sent)

    def test_drain_closes_the_bankd_side_on_the_event_loop(self) -> None:
        bankd = object()
        server = _build_server(bankd=bankd)
        server._note_relay_session_activity("scp11-a")

        with mock.patch.object(HilBridgeServer, "_close_bankd_side") as close_bankd:
            server._drain_pending_card_resync()

        close_bankd.assert_called_once()
        self.assertIn("scp11-a", close_bankd.call_args[0][0])

    def test_drain_collapses_several_resyncs_into_one_close(self) -> None:
        bankd = object()
        server = _build_server(bankd=bankd)
        server._note_relay_session_activity("scp11-a")
        server._note_relay_session_activity("scp03-b")

        with mock.patch.object(HilBridgeServer, "_close_bankd_side") as close_bankd:
            server._drain_pending_card_resync()

        close_bankd.assert_called_once()
        self.assertIn("scp03-b", close_bankd.call_args[0][0])

    def test_drain_without_a_modem_attached_does_nothing(self) -> None:
        server = _build_server(bankd=None)
        server._note_relay_session_activity("scp11-a")

        with mock.patch.object(HilBridgeServer, "_close_bankd_side") as close_bankd:
            server._drain_pending_card_resync()

        close_bankd.assert_not_called()

    def test_drain_with_an_empty_queue_is_a_no_op(self) -> None:
        server = _build_server(bankd=object())

        with mock.patch.object(HilBridgeServer, "_close_bankd_side") as close_bankd:
            server._drain_pending_card_resync()

        close_bankd.assert_not_called()


if __name__ == "__main__":
    unittest.main()
