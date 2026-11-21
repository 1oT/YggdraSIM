# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for ``Tools.HilBridge.router.BridgeSession`` instance methods.

Covers: allocate_tag, reset_runtime_state, server_identity, bankd_identity,
note_modem_slot_status, the modem-reset propagation to the card and the
REFRESH "UICC Reset" expectation.
No network sockets or card transport are touched; all external collaborators
are replaced with ``MagicMock``.
"""

from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import MagicMock

from Tools.HilBridge.router import (
    MODEM_RESET_EDGE_RST_ASSERTED,
    MODEM_RESET_EDGE_VCC_REMOVED,
    BridgeConfig,
    BridgeSession,
    CardWorker,
    HilBridgeServer,
    _malformed_envelope_rejection_reason,
)
from Tools.HilBridge.protocol import (
    SlotPhysStatus,
    build_rspro_pdu,
    get_pdu_message_body,
    get_pdu_message_name,
)


def _make_session(**kwargs: object) -> BridgeSession:
    config = BridgeConfig(**{k: v for k, v in kwargs.items() if hasattr(BridgeConfig, k)})
    card = MagicMock()
    gsmtap = MagicMock()
    return BridgeSession(config=config, card=card, gsmtap=gsmtap)


def _make_modem_session_server(
    *,
    atr_before: str = "3B9F",
    atr_after: str = "3B9F",
    atr_sent: bool = True,
) -> tuple[HilBridgeServer, BridgeSession, MagicMock, MagicMock]:
    """A server with a live modem session and a card that answers a reset with *atr_after*."""
    card = MagicMock()
    card.reader_label = "PCSC test reader"
    card.reset_card.return_value = {"mode": "pcsc-reconnect-unpower"}
    card.get_atr.return_value = bytes.fromhex(atr_after)
    gsmtap = MagicMock()
    session = BridgeSession(config=BridgeConfig(), card=card, gsmtap=gsmtap)
    session.atr_bytes = bytes.fromhex(atr_before)
    session.atr_sent = atr_sent
    server = object.__new__(HilBridgeServer)
    server._session = session
    server._card = card
    server._card_lock = threading.Lock()
    server._proactive_lock = threading.Lock()
    server._card_worker = MagicMock()
    server._queue_rspro_pdu = MagicMock()
    return server, session, card, gsmtap


def _slot_status_pdu(tag: int, **status: object) -> dict:
    return build_rspro_pdu(tag, "clientSlotStatusInd", {"slotPhysStatus": dict(status)})


class AllocateTagTests(unittest.TestCase):

    def test_starts_at_one(self) -> None:
        session = _make_session()
        self.assertEqual(session.allocate_tag(), 1)

    def test_increments_monotonically(self) -> None:
        session = _make_session()
        tags = [session.allocate_tag() for _ in range(5)]
        self.assertEqual(tags, [1, 2, 3, 4, 5])

    def test_returns_int(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.allocate_tag(), int)

    def test_independent_sessions_do_not_share_counter(self) -> None:
        a = _make_session()
        b = _make_session()
        a.allocate_tag()
        a.allocate_tag()
        self.assertEqual(b.allocate_tag(), 1)


class ResetRuntimeStateTests(unittest.TestCase):

    def setUp(self) -> None:
        self._session = _make_session()
        self._session.control = MagicMock()
        self._session.bankd = MagicMock()
        self._session.control_stage = "active"
        self._session.atr_sent = True

    def test_control_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.control)

    def test_bankd_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.bankd)

    def test_control_stage_reset_to_idle(self) -> None:
        self._session.reset_runtime_state()
        self.assertEqual(self._session.control_stage, "idle")

    def test_atr_sent_cleared(self) -> None:
        self._session.reset_runtime_state()
        self.assertFalse(self._session.atr_sent)

    def test_idempotent(self) -> None:
        self._session.reset_runtime_state()
        self._session.reset_runtime_state()
        self.assertIsNone(self._session.control)
        self.assertEqual(self._session.control_stage, "idle")


class NoteModemSlotStatusTests(unittest.TestCase):

    def setUp(self) -> None:
        self._session = _make_session()

    def test_rst_rising_edge(self) -> None:
        transition = self._session.note_modem_slot_status(
            SlotPhysStatus(reset_active=True, vcc_present=True)
        )
        self.assertEqual(transition.edge, MODEM_RESET_EDGE_RST_ASSERTED)
        self.assertTrue(transition.changed)

    def test_rst_level_is_no_edge(self) -> None:
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=True, vcc_present=True))
        transition = self._session.note_modem_slot_status(
            SlotPhysStatus(reset_active=True, vcc_present=True)
        )
        self.assertEqual(transition.edge, "")
        self.assertFalse(transition.changed)

    def test_rst_release_is_a_change_but_no_edge(self) -> None:
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=True, vcc_present=True))
        transition = self._session.note_modem_slot_status(
            SlotPhysStatus(reset_active=False, vcc_present=True)
        )
        self.assertEqual(transition.edge, "")
        self.assertTrue(transition.changed)

    def test_vcc_falling_edge_wins_over_rst(self) -> None:
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=False, vcc_present=True))
        transition = self._session.note_modem_slot_status(
            SlotPhysStatus(reset_active=True, vcc_present=False)
        )
        self.assertEqual(transition.edge, MODEM_RESET_EDGE_VCC_REMOVED)

    def test_vcc_absent_from_the_start_is_no_edge(self) -> None:
        transition = self._session.note_modem_slot_status(
            SlotPhysStatus(reset_active=False, vcc_present=False)
        )
        self.assertEqual(transition.edge, "")

    def test_unreported_vcc_keeps_the_last_known_value(self) -> None:
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=False, vcc_present=True))
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=False))
        self.assertTrue(self._session.modem_vcc_present)

    def test_reset_runtime_state_forgets_the_slot_and_the_expectation(self) -> None:
        self._session.note_modem_slot_status(SlotPhysStatus(reset_active=True, vcc_present=True))
        self._session.expect_uicc_reset("REFRESH (uicc-reset)", deadline=1.0)
        self._session.reset_runtime_state()
        self.assertFalse(self._session.modem_reset_active)
        self.assertIsNone(self._session.modem_vcc_present)
        self.assertEqual(self._session.pending_uicc_reset_reason, "")
        self.assertEqual(self._session.pending_uicc_reset_deadline, 0.0)


class ServerIdentityTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.server_identity(), dict)

    def test_contains_name(self) -> None:
        session = _make_session(bridge_name="test-bridge")
        identity = session.server_identity()
        import json
        serialised = json.dumps(identity)
        self.assertIn("test-bridge", serialised)

    def test_result_is_not_empty(self) -> None:
        session = _make_session()
        self.assertGreater(len(session.server_identity()), 0)

    def test_separate_calls_return_equal_dicts(self) -> None:
        session = _make_session()
        self.assertEqual(session.server_identity(), session.server_identity())


class BankdIdentityTests(unittest.TestCase):

    def test_returns_dict(self) -> None:
        session = _make_session()
        self.assertIsInstance(session.bankd_identity(), dict)

    def test_contains_bankd_suffix(self) -> None:
        session = _make_session(bridge_name="my-bridge")
        import json
        serialised = json.dumps(session.bankd_identity())
        self.assertIn("bankd", serialised)

    def test_differs_from_server_identity(self) -> None:
        session = _make_session()
        self.assertNotEqual(session.server_identity(), session.bankd_identity())

    def test_result_is_not_empty(self) -> None:
        session = _make_session()
        self.assertGreater(len(session.bankd_identity()), 0)


class EnvelopeTlvGuardTests(unittest.TestCase):

    def test_accepts_observed_valid_envelope(self) -> None:
        apdu = bytes.fromhex("80C200000ED70C82028281A40101A503000000")
        self.assertIsNone(_malformed_envelope_rejection_reason(apdu))

    def test_rejects_observed_corrupted_envelope(self) -> None:
        apdu = bytes.fromhex("80C200000ED78282028281A40101A503000000")
        reason = _malformed_envelope_rejection_reason(apdu)
        self.assertIsNotNone(reason)
        self.assertIn("invalid ENVELOPE BER-TLV", str(reason))
        self.assertIn("exceeds remaining data", str(reason))

    def test_ignores_non_envelope_apdu(self) -> None:
        apdu = bytes.fromhex("80F2000000")
        self.assertIsNone(_malformed_envelope_rejection_reason(apdu))

    def test_malformed_envelope_is_not_submitted_to_card(self) -> None:
        config = BridgeConfig()
        card = MagicMock()
        card.backend_name = "reader"
        gsmtap = MagicMock()
        session = BridgeSession(config=config, card=card, gsmtap=gsmtap)
        server = object.__new__(HilBridgeServer)
        server._session = session
        server._card = card
        server._card_worker = MagicMock()
        server._queue_rspro_pdu = MagicMock()

        context = MagicMock()
        pdu = {
            "tag": 42,
            "msg": (
                "tpduModemToCard",
                {"data": bytes.fromhex("80C200000ED78282028281A40101A503000000")},
            ),
        }

        server._handle_apdu_exchange(context, pdu)

        server._card_worker.submit_async.assert_not_called()
        server._queue_rspro_pdu.assert_called_once()
        queued_pdu = server._queue_rspro_pdu.call_args.args[1]
        self.assertEqual(get_pdu_message_body(queued_pdu)["data"], b"\x6F\x00")


class ModemSessionResetTests(unittest.TestCase):

    def test_first_slot_status_resets_card_and_sends_fresh_atr(self) -> None:
        config = BridgeConfig()
        card = MagicMock()
        card.reader_label = "PCSC test reader"
        card.reset_card.return_value = {"mode": "pcsc-reconnect-unpower"}
        card.get_atr.return_value = bytes.fromhex("3B9F")
        gsmtap = MagicMock()
        session = BridgeSession(config=config, card=card, gsmtap=gsmtap)
        session.atr_bytes = bytes.fromhex("3B00")
        session.proactive.queue_refresh(source="test")

        server = object.__new__(HilBridgeServer)
        server._session = session
        server._card = card
        server._card_lock = MagicMock()
        server._card_lock.__enter__.return_value = None
        server._card_lock.__exit__.return_value = None
        server._card_worker = MagicMock()
        server._queue_rspro_pdu = MagicMock()

        context = MagicMock()
        pdu = build_rspro_pdu(7, "clientSlotStatusInd", {})

        server._handle_bankd_pdu(context, pdu)

        server._card_worker.drain.assert_called_once_with(timeout=5.0)
        card.reset_card.assert_called_once_with()
        card.get_atr.assert_called_once_with()
        self.assertEqual(session.atr_bytes, bytes.fromhex("3B9F"))
        self.assertEqual(session.proactive.status_payload()["pendingCount"], 0)
        self.assertTrue(session.atr_sent)
        queued_pdu = server._queue_rspro_pdu.call_args.args[1]
        self.assertEqual(get_pdu_message_body(queued_pdu)["atr"], bytes.fromhex("3B9F"))


class ModemResetPropagationTests(unittest.TestCase):
    """A modem-side UICC reset reaches the card in the reader."""

    def test_rst_rising_edge_power_cycles_the_card(self) -> None:
        server, session, card, gsmtap = _make_modem_session_server()
        session.proactive.queue_refresh(source="test")

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=True, vccPresent=True))

        server._card_worker.drain.assert_called_once_with(timeout=5.0)
        card.reset_card.assert_called_once_with()
        self.assertEqual(session.atr_bytes, bytes.fromhex("3B9F"))
        self.assertEqual(session.proactive.status_payload()["pendingCount"], 0)
        # The board answered the modem with the ATR it holds; the trace
        # records that one.
        gsmtap.send_atr.assert_called_once_with(bytes.fromhex("3B9F"))
        # An unchanged ATR is not pushed to the board again.
        server._queue_rspro_pdu.assert_not_called()
        self.assertTrue(session.atr_sent)

    def test_rst_held_active_resets_once(self) -> None:
        server, _session, card, _gsmtap = _make_modem_session_server()
        context = MagicMock()

        server._handle_bankd_pdu(context, _slot_status_pdu(8, resetActive=True, vccPresent=True))
        server._handle_bankd_pdu(context, _slot_status_pdu(9, resetActive=True, vccPresent=True))

        card.reset_card.assert_called_once_with()

    def test_rst_release_is_not_a_reset(self) -> None:
        server, session, card, _gsmtap = _make_modem_session_server()
        session.modem_reset_active = True

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=False, vccPresent=True))

        card.reset_card.assert_not_called()
        self.assertFalse(session.modem_reset_active)

    def test_vcc_falling_edge_power_cycles_the_card(self) -> None:
        server, session, card, _gsmtap = _make_modem_session_server()
        session.modem_vcc_present = True

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=False, vccPresent=False))

        card.reset_card.assert_called_once_with()

    def test_rst_edge_with_unreported_vcc_power_cycles_the_card(self) -> None:
        # vccPresent is OPTIONAL in RSPRO; a client that cannot sense VCC
        # still reports RST.
        server, _session, card, _gsmtap = _make_modem_session_server()

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=True))

        card.reset_card.assert_called_once_with()

    def test_changed_atr_is_pushed_to_the_board(self) -> None:
        server, session, _card, gsmtap = _make_modem_session_server(atr_before="3B9F", atr_after="3B9E")

        with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
            server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=True, vccPresent=True))

        self.assertEqual(session.atr_bytes, bytes.fromhex("3B9E"))
        queued_pdu = server._queue_rspro_pdu.call_args.args[1]
        self.assertEqual(get_pdu_message_name(queued_pdu), "setAtrReq")
        self.assertEqual(get_pdu_message_body(queued_pdu)["atr"], bytes.fromhex("3B9E"))
        gsmtap.send_atr.assert_called_once_with(bytes.fromhex("3B9F"))
        self.assertIn("3B9F -> 3B9E", "\n".join(logs.output))

    def test_first_indication_is_the_handshake_and_seeds_the_edge_tracker(self) -> None:
        server, session, card, _gsmtap = _make_modem_session_server(atr_sent=False)

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(7, resetActive=True, vccPresent=True))

        # One power-cycle, the handshake's: the edge this indication
        # carried is not served a second time.
        card.reset_card.assert_called_once_with()
        self.assertTrue(session.atr_sent)
        self.assertTrue(session.modem_reset_active)
        self.assertTrue(session.modem_vcc_present)

    def test_empty_indication_after_handshake_does_nothing(self) -> None:
        server, _session, card, _gsmtap = _make_modem_session_server()

        server._handle_bankd_pdu(MagicMock(), build_rspro_pdu(8, "clientSlotStatusInd", {}))

        card.reset_card.assert_not_called()


class RefreshUiccResetExpectationTests(unittest.TestCase):
    """A REFRESH in "UICC Reset" mode must be followed by a modem reset."""

    FETCH = bytes.fromhex("801200000B")
    STATUS = bytes.fromhex("80F2000000")
    # FETCH responses observed on the rig.
    REFRESH_UICC_RESET = bytes.fromhex("D0098103010104820281829000")
    REFRESH_PROFILE_STATE_CHANGE = bytes.fromhex("D0098103010109820281829000")
    CLOSE_CHANNEL = bytes.fromhex("D0098103014100820281219000")

    def test_refresh_uicc_reset_arms_the_expectation(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()

        with self.assertLogs("Tools.HilBridge.router", level="INFO") as logs:
            server._note_card_response(self.FETCH, self.REFRESH_UICC_RESET)

        self.assertEqual(session.pending_uicc_reset_reason, "REFRESH (uicc-reset)")
        self.assertGreater(session.pending_uicc_reset_deadline, time.monotonic())
        self.assertIn("REFRESH (uicc-reset)", "\n".join(logs.output))

    def test_other_refresh_modes_do_not_arm(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()

        with self.assertLogs("Tools.HilBridge.router", level="INFO") as logs:
            server._note_card_response(self.FETCH, self.REFRESH_PROFILE_STATE_CHANGE)

        self.assertEqual(session.pending_uicc_reset_reason, "")
        self.assertIn("euicc-profile-state-change", "\n".join(logs.output))

    def test_other_proactive_commands_and_other_apdus_are_ignored(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()

        server._note_card_response(self.FETCH, self.CLOSE_CHANNEL)
        server._note_card_response(self.STATUS, self.REFRESH_UICC_RESET)
        server._note_card_response(b"", self.REFRESH_UICC_RESET)

        self.assertEqual(session.pending_uicc_reset_reason, "")

    def test_modem_reset_clears_the_expectation(self) -> None:
        server, session, card, _gsmtap = _make_modem_session_server()
        server._note_card_response(self.FETCH, self.REFRESH_UICC_RESET)

        with self.assertLogs("Tools.HilBridge.router", level="INFO") as logs:
            server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(8, resetActive=True, vccPresent=True))

        card.reset_card.assert_called_once_with()
        self.assertEqual(session.pending_uicc_reset_reason, "")
        self.assertIn("after REFRESH (uicc-reset)", "\n".join(logs.output))

    def test_handshake_power_cycle_clears_the_expectation(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server(atr_sent=False)
        server._note_card_response(self.FETCH, self.REFRESH_UICC_RESET)

        server._handle_bankd_pdu(MagicMock(), _slot_status_pdu(7, resetActive=False, vccPresent=True))

        self.assertEqual(session.pending_uicc_reset_reason, "")

    def test_overdue_expectation_is_reported_once(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()
        session.expect_uicc_reset("REFRESH (uicc-reset)", deadline=time.monotonic() - 1.0)

        with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
            server._warn_if_uicc_reset_overdue()

        self.assertIn("reported no UICC reset", "\n".join(logs.output))
        self.assertEqual(session.pending_uicc_reset_reason, "")
        with self.assertNoLogs("Tools.HilBridge.router", level="WARNING"):
            server._warn_if_uicc_reset_overdue()

    def test_expectation_within_grace_is_silent(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()
        session.expect_uicc_reset("REFRESH (uicc-reset)", deadline=time.monotonic() + 60.0)

        with self.assertNoLogs("Tools.HilBridge.router", level="WARNING"):
            server._warn_if_uicc_reset_overdue()

        self.assertEqual(session.pending_uicc_reset_reason, "REFRESH (uicc-reset)")

    def test_modem_apdu_runs_the_overdue_check_and_still_reaches_the_card(self) -> None:
        server, session, _card, _gsmtap = _make_modem_session_server()
        session.expect_uicc_reset("REFRESH (uicc-reset)", deadline=time.monotonic() - 1.0)
        pdu = {
            "tag": 42,
            "msg": ("tpduModemToCard", {"data": bytes.fromhex("00A40004023F00")}),
        }

        with self.assertLogs("Tools.HilBridge.router", level="WARNING"):
            server._handle_apdu_exchange(MagicMock(), pdu)

        server._card_worker.submit_async.assert_called_once()
        self.assertEqual(session.pending_uicc_reset_reason, "")


class CardBoundaryTraceTests(unittest.TestCase):

    def test_card_worker_logs_physical_boundary_when_enabled(self) -> None:
        class _Card:
            def transmit(self, apdu: bytes, *, timeout_ms: int | None = None):
                self.apdu = bytes(apdu)
                self.timeout_ms = timeout_ms
                return bytes.fromhex("AA"), 0x90, 0x00

        card = _Card()
        worker = CardWorker(
            card,
            threading.Lock(),
            card_trace_enabled=True,
        )
        try:
            with self.assertLogs("Tools.HilBridge.router", level="INFO") as logs:
                response_data, sw1, sw2 = worker.submit_sync(bytes.fromhex("00A4000000"))
        finally:
            worker.shutdown()

        self.assertEqual(card.apdu, bytes.fromhex("00A4000000"))
        self.assertEqual(response_data, bytes.fromhex("AA"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        rendered = "\n".join(logs.output)
        self.assertIn("Card boundary -> card [relay] APDU 00A4000000", rendered)
        self.assertIn("Card boundary <- card [relay] APDU AA9000", rendered)


if __name__ == "__main__":
    unittest.main()
