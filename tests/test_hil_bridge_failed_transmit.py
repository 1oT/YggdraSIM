# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A modem TPDU whose card transmit fails is answered, not a reason to drop the SIM.

osmo-remsim-client-st2 1.2.0 forwards a TPDU whose APDU case libosmosim cannot
tell (a proprietary case 3 command with INS '00', sent with AT+CSIM) as a bare
header; PC/SC then sends it as a case 2 command to a card that
presumably waits for data, and the transmit fails. The bridge used to reset the card side, which
took the SIM away from the modem. A failure PC/SC reports is now answered with
'6F00' once; a second in a row, or a bridge timeout, still resets. Built from
fakes: no reader, no sockets.
"""
from __future__ import annotations

import types
import unittest
from unittest import mock

from Tools.HilBridge.pcsc import PcscBridgeError
from Tools.HilBridge.router import (
    TECHNICAL_PROBLEM_SW,
    BridgeConfig,
    BridgeSession,
    HilBridgeServer,
    _CompletedApduExchange,
    _PendingApduExchange,
)


def _pcsc_failure() -> PcscBridgeError:
    error = PcscBridgeError("PC/SC APDU transmit failed.")
    error.__cause__ = OSError("Card not transacted")
    return error


def _bridge_timeout() -> PcscBridgeError:
    return PcscBridgeError("PC/SC APDU transmit timed out after 30000ms.")


class _Rig:
    def __init__(self) -> None:
        self.server = object.__new__(HilBridgeServer)
        self.server._session = BridgeSession(config=BridgeConfig(), card=mock.Mock(), gsmtap=mock.Mock())
        self.server._drain_pending_card_resync = mock.Mock()
        self.server._card_worker = mock.Mock()
        self.server._queue_rspro_pdu = mock.Mock()
        self.server._reset_card_side = mock.Mock()
        self.link = types.SimpleNamespace(closed=False)

    def complete(self, request_hex: str, *, response_hex: str = "", error: Exception | None = None) -> None:
        session = self.server._session
        session.modem_tpdu_sequence += 1
        pending = _PendingApduExchange(
            context=self.link,
            tag=session.modem_tpdu_sequence,
            bank_slot=session.bank_slot,
            client_slot=session.client_slot,
            request_apdu=bytes.fromhex(request_hex),
            card_session=session.card_session,
            sequence=session.modem_tpdu_sequence,
        )
        self.server._card_worker.poll_responses.return_value = [
            _CompletedApduExchange(response=bytes.fromhex(response_hex), error=error, pending=pending)
        ]
        self.server._process_completed_exchanges()

    def answers(self) -> list[bytes]:
        return [call.args[1]["msg"][1]["data"] for call in self.server._queue_rspro_pdu.call_args_list]


class FailedTransmitTests(unittest.TestCase):
    def test_a_failed_transmit_is_answered_and_the_session_stays(self) -> None:
        rig = _Rig()
        with self.assertLogs("Tools.HilBridge.router", level="ERROR") as logs:
            rig.complete("0100000003", error=_pcsc_failure())
        self.assertEqual(rig.answers(), [TECHNICAL_PROBLEM_SW])
        rig.server._reset_card_side.assert_not_called()
        self.assertIn("OSError: Card not transacted", "\n".join(logs.output))

    def test_a_second_failure_in_a_row_resets_the_card_side(self) -> None:
        rig = _Rig()
        rig.complete("0100000003", error=_pcsc_failure())
        rig.complete("0100000003", error=_pcsc_failure())
        self.assertEqual(rig.answers(), [TECHNICAL_PROBLEM_SW])
        rig.server._reset_card_side.assert_called_once()

    def test_a_card_answer_in_between_starts_the_count_again(self) -> None:
        rig = _Rig()
        rig.complete("0100000003", error=_pcsc_failure())
        rig.complete("0070800100", response_hex="9000")
        rig.complete("0100000003", error=_pcsc_failure())
        self.assertEqual(rig.answers(), [TECHNICAL_PROBLEM_SW, bytes.fromhex("9000"), TECHNICAL_PROBLEM_SW])
        rig.server._reset_card_side.assert_not_called()

    def test_a_bridge_timeout_resets_the_card_side_at_once(self) -> None:
        rig = _Rig()
        rig.complete("80f2000000", error=_bridge_timeout())
        self.assertEqual(rig.answers(), [])
        rig.server._reset_card_side.assert_called_once()

    def test_the_count_starts_again_after_the_card_side_reset(self) -> None:
        rig = _Rig()
        del rig.server._reset_card_side
        rig.server._close_bankd_side = mock.Mock()
        rig.server._refresh_card = mock.Mock()
        rig.complete("0100000003", error=_pcsc_failure())
        rig.complete("0100000003", error=_pcsc_failure())
        rig.complete("0100000003", error=_pcsc_failure())
        self.assertEqual(rig.answers(), [TECHNICAL_PROBLEM_SW, TECHNICAL_PROBLEM_SW])
        rig.server._close_bankd_side.assert_called_once()

    def test_a_new_card_session_starts_the_count_again(self) -> None:
        rig = _Rig()
        rig.complete("0100000003", error=_pcsc_failure())
        rig.server._session.start_card_session()
        rig.complete("0100000003", error=_pcsc_failure())
        self.assertEqual(rig.answers(), [TECHNICAL_PROBLEM_SW, TECHNICAL_PROBLEM_SW])
        rig.server._reset_card_side.assert_not_called()


if __name__ == "__main__":
    unittest.main()
