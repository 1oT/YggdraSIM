# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A TPDU the modem has abandoned is never answered.

osmo-remsim-client-st2 1.2.0 hands the card's next answer to whatever
command the modem is on. A SIMtrace2 board on firmware 0.9.0 holds a
128-, 192- or 256-byte USB message until it sends another, so a TERMINAL
RESPONSE with Lc 'B2' reached the bridge only after the modem had waited
120 s and reset the UICC. Answered, its 6F00 landed on the modem's first
SELECT and every later answer was one command late. Built from fakes: no
reader, no sockets, no board.
"""
from __future__ import annotations

import queue
import threading
import unittest
from unittest.mock import MagicMock

from Tools.HilBridge.router import (
    BridgeConfig,
    BridgeSession,
    CardWorker,
    HilBridgeServer,
    MODEM_RESET_EDGE_RST_ASSERTED,
    _CompletedApduExchange,
    _PendingApduExchange,
    _simtrace2_unterminated_message_size,
)

# The TERMINAL RESPONSE to RECEIVE DATA the board held on 2026-10-23:
# 18 bytes of TLVs around 160 bytes of channel data, Lc 'B2'.
HELD_TERMINAL_RESPONSE = bytes.fromhex("80140000B2" "8103014200" "02028281" "030100" "3681A0") + bytes(160) + bytes.fromhex("370100")
SELECT_MF = bytes.fromhex("00A40004023F00")


def _tpdu(apdu: bytes, tag: int = 1) -> dict:
    return {"tag": tag, "msg": ("tpduModemToCard", {"data": apdu})}


def _server() -> tuple[HilBridgeServer, BridgeSession]:
    card = MagicMock()
    card.backend_name = "reader"
    card.reader_label = "PCSC test reader"
    card.reset_card.return_value = {"mode": "pcsc-reconnect-unpower"}
    card.get_atr.return_value = bytes.fromhex("3B9F96803FC7828031E073FE211367274000B4000001A8")
    session = BridgeSession(config=BridgeConfig(), card=card, gsmtap=MagicMock())
    session.atr_bytes = card.get_atr.return_value
    session.atr_sent = True
    server = object.__new__(HilBridgeServer)
    server._session = session
    server._card = card
    server._card_lock = threading.Lock()
    server._proactive_lock = threading.Lock()
    server._card_worker = MagicMock()
    server._queue_rspro_pdu = MagicMock()
    server._pending_card_resync = queue.SimpleQueue()
    return server, session


class HeldTpduAfterResetTests(unittest.TestCase):
    def test_the_held_terminal_response_is_dropped_and_the_select_is_answered(self) -> None:
        server, session = _server()
        server._reset_card_for_modem_reset(MagicMock(), MODEM_RESET_EDGE_RST_ASSERTED)
        context = MagicMock()

        with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
            server._handle_apdu_exchange(context, _tpdu(HELD_TERMINAL_RESPONSE))
        server._card_worker.submit_async.assert_not_called()
        server._queue_rspro_pdu.assert_not_called()
        rendered = "\n".join(logs.output)
        self.assertIn("Dropping modem APDU 80140000B2", rendered)
        self.assertIn("192-byte SIMtrace2 USB message", rendered)

        server._handle_apdu_exchange(context, _tpdu(SELECT_MF, tag=2))
        server._card_worker.submit_async.assert_called_once()
        kwargs = server._card_worker.submit_async.call_args.kwargs
        self.assertEqual(kwargs["card_session"], session.card_session)
        self.assertEqual(kwargs["sequence"], session.modem_tpdu_sequence)
        self.assertFalse(session.awaiting_first_tpdu)

    def test_fetch_and_get_response_cannot_open_a_session_either(self) -> None:
        for apdu in (bytes.fromhex("8012000010"), bytes.fromhex("00C0000032")):
            with self.subTest(apdu=apdu.hex()):
                server, session = _server()
                session.start_card_session()
                with self.assertLogs("Tools.HilBridge.router", level="WARNING"):
                    server._handle_apdu_exchange(MagicMock(), _tpdu(apdu))
                server._card_worker.submit_async.assert_not_called()
                self.assertTrue(session.awaiting_first_tpdu)

    def test_a_terminal_response_inside_a_session_reaches_the_card(self) -> None:
        server, session = _server()
        session.start_card_session()
        server._handle_apdu_exchange(MagicMock(), _tpdu(SELECT_MF))
        server._handle_apdu_exchange(MagicMock(), _tpdu(HELD_TERMINAL_RESPONSE, tag=2))
        self.assertEqual(server._card_worker.submit_async.call_count, 2)

    def test_the_reset_starts_the_session_before_it_waits_for_the_worker(self) -> None:
        server, session = _server()
        seen: list[tuple[int, bool]] = []
        server._card_worker.drain.side_effect = lambda timeout: seen.append(
            (session.card_session, session.awaiting_first_tpdu)
        )
        server._reset_card_for_modem_reset(MagicMock(), MODEM_RESET_EDGE_RST_ASSERTED)
        self.assertEqual(seen, [(1, True)])


class AbandonedAnswerTests(unittest.TestCase):
    def _complete(self, server: HilBridgeServer, pending: _PendingApduExchange, response: bytes) -> None:
        server._card_worker.poll_responses.return_value = [
            _CompletedApduExchange(response=response, error=None, pending=pending)
        ]
        server._process_completed_exchanges()

    def _pending(self, session: BridgeSession, apdu: bytes, *, card_session: int, sequence: int) -> _PendingApduExchange:
        context = MagicMock()
        context.closed = False
        return _PendingApduExchange(
            context=context,
            tag=7,
            bank_slot=session.bank_slot,
            client_slot=session.client_slot,
            request_apdu=apdu,
            card_session=card_session,
            sequence=sequence,
        )

    def test_the_answer_to_a_tpdu_sent_before_a_reset_stays_off_the_modem(self) -> None:
        server, session = _server()
        session.modem_tpdu_sequence = 4
        pending = self._pending(session, HELD_TERMINAL_RESPONSE, card_session=0, sequence=4)
        session.start_card_session()
        with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
            self._complete(server, pending, bytes.fromhex("6F00"))
        server._queue_rspro_pdu.assert_not_called()
        session.gsmtap.mirror_exchange.assert_called_once_with(HELD_TERMINAL_RESPONSE, bytes.fromhex("6F00"))
        self.assertIn("the modem reset the UICC after sending it", "\n".join(logs.output))

    def test_the_answer_to_a_superseded_tpdu_stays_off_the_modem(self) -> None:
        server, session = _server()
        session.modem_tpdu_sequence = 6
        pending = self._pending(session, HELD_TERMINAL_RESPONSE, card_session=0, sequence=5)
        with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
            self._complete(server, pending, bytes.fromhex("6F00"))
        server._queue_rspro_pdu.assert_not_called()
        self.assertIn("the modem has sent another command since", "\n".join(logs.output))

    def test_the_answer_to_the_latest_tpdu_is_forwarded(self) -> None:
        server, session = _server()
        session.modem_tpdu_sequence = 6
        pending = self._pending(session, SELECT_MF, card_session=0, sequence=6)
        self._complete(server, pending, bytes.fromhex("6132"))
        server._queue_rspro_pdu.assert_called_once()


class CardWorkerSkipTests(unittest.TestCase):
    def test_an_abandoned_tpdu_never_reaches_the_card(self) -> None:
        sent: list[bytes] = []

        class _Card:
            def transmit(self, apdu: bytes, *, timeout_ms: int | None = None):
                sent.append(bytes(apdu))
                return b"", 0x90, 0x00

        worker = CardWorker(
            _Card(),
            threading.Lock(),
            abandoned_reason=lambda pending: "the modem reset the UICC after sending it"
            if pending.request_apdu == HELD_TERMINAL_RESPONSE
            else "",
        )
        try:
            context = MagicMock()
            # The worker thread logs the skip, so listen before submitting.
            with self.assertLogs("Tools.HilBridge.router", level="WARNING") as logs:
                for apdu in (HELD_TERMINAL_RESPONSE, SELECT_MF):
                    worker.submit_async(apdu, context=context, tag=1, bank_slot={}, client_slot={})
                worker.drain(timeout=5.0)
            completed = worker.poll_responses()
        finally:
            worker.shutdown()
        self.assertEqual(sent, [SELECT_MF])
        self.assertEqual([item.pending.request_apdu for item in completed], [SELECT_MF])
        self.assertIn("Not sending modem APDU 80140000B2", "\n".join(logs.output))


class UnterminatedUsbMessageTests(unittest.TestCase):
    """14 header bytes plus the command data, on 64-byte packets."""

    def test_only_whole_multi_packet_messages_are_named(self) -> None:
        def command(lc: int) -> bytes:
            return bytes.fromhex("80140000") + bytes([lc]) + bytes(lc)

        self.assertEqual(_simtrace2_unterminated_message_size(command(0x72)), 128)
        self.assertEqual(_simtrace2_unterminated_message_size(command(0xB2)), 192)
        self.assertEqual(_simtrace2_unterminated_message_size(command(0xF2)), 256)
        # One packet: the firmware does send a zero-length packet after it.
        self.assertEqual(_simtrace2_unterminated_message_size(command(0x32)), 0)
        self.assertEqual(_simtrace2_unterminated_message_size(command(0xB1)), 0)

    def test_commands_without_matching_data_are_not_named(self) -> None:
        self.assertEqual(_simtrace2_unterminated_message_size(b""), 0)
        self.assertEqual(_simtrace2_unterminated_message_size(bytes.fromhex("8012000010")), 0)
        self.assertEqual(_simtrace2_unterminated_message_size(bytes.fromhex("80140000B2") + bytes(10)), 0)


if __name__ == "__main__":
    unittest.main()
