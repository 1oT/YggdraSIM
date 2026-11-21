# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""RSPRO link roles survive a failure and a re-dial in either order.

osmo-remsim-client-st2 1.2.0 sends byte-identical connectClientReq PDUs on its
server and bankd links, so the bridge classifies a new connection by the role
still open. Closing both links after a one-sided failure made the client
re-dial both at once; with its bankd link first, each link got the other
role's answer, and the client closed both for good. Built from fakes: no
reader, no sockets.
"""
from __future__ import annotations

import types
import unittest
from unittest import mock

from Tools.HilBridge.pcsc import PcscBridgeError
from Tools.HilBridge.protocol import COMPONENT_REMSIM_BANKD, COMPONENT_REMSIM_SERVER
from Tools.HilBridge.router import (
    BridgeConfig,
    BridgeSession,
    ConnectionContext,
    ConnectionRole,
    HilBridgeServer,
)


def _context(label: str):
    return types.SimpleNamespace(label=label, role=None, closed=False, sock=None)


class _Session:
    def __init__(self, control, bankd) -> None:
        self.control = control
        self.bankd = bankd
        self.control_stage = "configured"
        self.atr_sent = True
        self.full_resets = 0

    def reset_runtime_state(self) -> None:
        self.full_resets += 1
        self.control = None
        self.bankd = None
        self.control_stage = "idle"
        self.atr_sent = False


def _server():
    control = _context("control@127.0.0.1:40001")
    bankd = _context("bankd@127.0.0.1:40002")
    control.role = ConnectionRole.CONTROL
    bankd.role = ConnectionRole.BANKD
    server = object.__new__(HilBridgeServer)
    server._session = _Session(control, bankd)
    server.closed = []
    server._close_socket = lambda context: server.closed.append(context.label)
    server._publish_card_relay_marker = mock.Mock()
    server._refresh_card = mock.Mock()
    return server, control, bankd


class OneLinkAtATimeTests(unittest.TestCase):
    def test_losing_the_bankd_link_keeps_the_control_link(self) -> None:
        server, control, bankd = _server()
        server._handle_connection_loss(bankd, "peer closed socket")
        self.assertEqual(server.closed, [bankd.label])
        self.assertIs(server._session.control, control)
        self.assertIsNone(server._session.bankd)
        self.assertFalse(server._session.atr_sent)
        self.assertEqual(server._session.full_resets, 0)

    def test_losing_the_control_link_keeps_the_bankd_link_and_the_card(self) -> None:
        server, control, bankd = _server()
        server._handle_connection_loss(control, "peer closed socket")
        self.assertEqual(server.closed, [control.label])
        self.assertIs(server._session.bankd, bankd)
        self.assertIsNone(server._session.control)
        self.assertEqual(server._session.control_stage, "idle")
        server._refresh_card.assert_not_called()

    def test_a_card_transmit_failure_closes_bankd_and_reopens_the_reader(self) -> None:
        server, control, bankd = _server()
        server._reset_card_side("Card APDU transmit failed: PC/SC APDU transmit timed out")
        self.assertEqual(server.closed, [bankd.label])
        self.assertIs(server._session.control, control)
        server._refresh_card.assert_called_once_with(reconnect=True)

    def test_a_failing_modem_tpdu_keeps_the_control_link(self) -> None:
        server, control, bankd = _server()
        with mock.patch("Tools.HilBridge.router.get_pdu_message_name", return_value="tpduModemToCard"):
            with mock.patch.object(
                HilBridgeServer,
                "_handle_apdu_exchange",
                side_effect=PcscBridgeError("PC/SC APDU transmit failed."),
            ):
                server._handle_bankd_pdu(bankd, {})
        self.assertEqual(server.closed, [bankd.label])
        self.assertIs(server._session.control, control)

    def test_the_re_dialled_link_takes_the_one_role_left_open(self) -> None:
        server, control, bankd = _server()
        server._reset_card_side("Card APDU transmit failed")
        redial = _context("unassigned@127.0.0.1:40003")
        server._classify_connection(redial, "connectClientReq")
        self.assertEqual(redial.role, ConnectionRole.BANKD)
        self.assertIs(server._session.bankd, redial)
        self.assertIs(server._session.control, control)

    def test_server_shutdown_still_closes_both(self) -> None:
        server, control, bankd = _server()
        server._reset_session("server shutdown", refresh_card=False)
        self.assertEqual(sorted(server.closed), sorted([control.label, bankd.label]))


class _Handshake:
    """A bridge with a real BridgeSession, fed one RSPRO PDU at a time."""

    def __init__(self) -> None:
        server = object.__new__(HilBridgeServer)
        server._config = BridgeConfig()
        server._session = BridgeSession(config=server._config, card=None, gsmtap=None)
        server._publish_card_relay_marker = mock.Mock()
        server._refresh_card = mock.Mock()
        server._close_socket = self._close
        self.answers: list[tuple[ConnectionContext, str, dict]] = []
        server._queue_rspro_pdu = lambda context, pdu: self.answers.append((context, *pdu["msg"]))
        self.server = server
        self._ports = iter(range(40001, 40100))

    @staticmethod
    def _close(context: ConnectionContext) -> None:
        context.closed = True

    def dial(self) -> ConnectionContext:
        context = ConnectionContext(sock=None, address=("127.0.0.1", next(self._ports)))
        self.send(context, "connectClientReq", {})
        return context

    def send(self, context: ConnectionContext, message_name: str, body: dict) -> None:
        self.server._handle_rspro_pdu(context, {"tag": 7, "msg": (message_name, body)})

    def identity_answered(self, context: ConnectionContext) -> str:
        for target, message_name, body in self.answers:
            if target is context and message_name == "connectClientRes":
                return body["identity"]["type"]
        return ""


class RoleAssignmentRaceTests(unittest.TestCase):
    """The client checks the identity type in connectClientRes on each link.

    A link answered with the other role's identity is closed by the client
    and not re-dialled on its own, so no link may get that answer.
    """

    def test_a_starting_client_is_answered_in_order(self) -> None:
        rig = _Handshake()
        server_link = rig.dial()
        rig.send(server_link, "configClientIdRes", {"result": "ok"})
        bankd_link = rig.dial()
        rig.send(server_link, "configClientBankRes", {"result": "ok"})
        self.assertEqual(rig.identity_answered(server_link), COMPONENT_REMSIM_SERVER)
        self.assertEqual(rig.identity_answered(bankd_link), COMPONENT_REMSIM_BANKD)
        self.assertEqual(rig.server._session.control_stage, "configured")
        self.assertFalse(server_link.closed or bankd_link.closed)

    def test_the_bankd_link_dialling_first_cannot_strand_the_server_link(self) -> None:
        # The order seen live after a session reset closed both links.
        rig = _Handshake()
        bankd_link = rig.dial()
        server_link = rig.dial()
        self.assertEqual(rig.identity_answered(bankd_link), COMPONENT_REMSIM_SERVER)
        # Closed unanswered, so the client re-dials it rather than rejecting
        # the bankd identity and leaving its server link down.
        self.assertEqual(rig.identity_answered(server_link), "")
        self.assertTrue(server_link.closed)
        self.assertIsNone(server_link.role)

        rig.server._handle_connection_loss(bankd_link, "peer closed socket")
        server_link = rig.dial()
        self.assertEqual(rig.identity_answered(server_link), COMPONENT_REMSIM_SERVER)
        rig.send(server_link, "configClientIdRes", {"result": "ok"})
        bankd_link = rig.dial()
        self.assertEqual(rig.identity_answered(bankd_link), COMPONENT_REMSIM_BANKD)
        self.assertIs(rig.server._session.control, server_link)
        self.assertIs(rig.server._session.bankd, bankd_link)

    def test_the_server_link_dialling_first_settles_once_it_answers(self) -> None:
        rig = _Handshake()
        server_link = rig.dial()
        early_bankd_link = rig.dial()
        self.assertEqual(rig.identity_answered(server_link), COMPONENT_REMSIM_SERVER)
        self.assertEqual(rig.identity_answered(early_bankd_link), "")
        self.assertTrue(early_bankd_link.closed)
        rig.send(server_link, "configClientIdRes", {"result": "ok"})
        bankd_link = rig.dial()
        self.assertEqual(rig.identity_answered(bankd_link), COMPONENT_REMSIM_BANKD)
        self.assertIs(rig.server._session.bankd, bankd_link)


if __name__ == "__main__":
    unittest.main()
