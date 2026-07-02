# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.HilBridge.router.BridgeSession`` instance methods.

Covers: allocate_tag, reset_runtime_state, server_identity, bankd_identity.
No network sockets or card transport are touched; all external collaborators
are replaced with ``MagicMock``.
"""

from __future__ import annotations

import threading
import unittest
from unittest.mock import MagicMock

from Tools.HilBridge.router import (
    BridgeConfig,
    BridgeSession,
    CardWorker,
    HilBridgeServer,
    _malformed_envelope_rejection_reason,
)
from Tools.HilBridge.protocol import build_rspro_pdu, get_pdu_message_body


def _make_session(**kwargs: object) -> BridgeSession:
    config = BridgeConfig(**{k: v for k, v in kwargs.items() if hasattr(BridgeConfig, k)})
    card = MagicMock()
    gsmtap = MagicMock()
    return BridgeSession(config=config, card=card, gsmtap=gsmtap)


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
