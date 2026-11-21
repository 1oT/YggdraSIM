# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The IPAd declaration an ES10 card session starts with (GSMA SGP.32 v1.3 §3.8.2)."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from SCP11.eim_local.config import EimLocalConfig
from SCP11.eim_local.engine_shell import EngineVerbs
from SCP11.eim_local.session import EimLocalSession
from SCP11.local_access.session import LocalIsdrSession
from SCP11.shared.ipad_declaration import declare_ipad, forget_ipad_declaration
from SCP11.transport import PcscApduChannel
from tests.local_smdp_card_support import (
    ECASD_AID,
    INS_GET_DATA,
    INS_SELECT,
    INS_STORE_DATA,
    INS_TERMINAL_CAPABILITY,
    ISD_R_AID,
    TEST_EID,
    ScriptedEuicc,
    declares_ipad,
)

SELECT_ISD_R = bytes.fromhex("00A4040010A0000005591010FFFFFFFF8900000100")
GET_EUICC_INFO1 = bytes.fromhex("80E2910003BF2000")
GET_EID = bytes.fromhex("BF3E035C015A")


def _gating_card() -> ScriptedEuicc:
    """A card that gates ES10 on the declaration and still answers GET DATA on its ECASD.

    The card refuses the declaration once an application is selected, the
    strict reading of ETSI TS 102 221 v18.4 §11.1.19.2.4 (before the first
    application selection of a card session).
    """
    return ScriptedEuicc(ecasd_get_data=True)


class _AnsweringConnection:
    """A PC/SC connection that answers '9000' to everything and keeps what it was sent."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        self.calls.append(bytes(apdu))
        return [], 0x90, 0x00

    def disconnect(self) -> None:
        return None


def _pcsc_channel(connection: _AnsweringConnection) -> PcscApduChannel:
    channel = PcscApduChannel.__new__(PcscApduChannel)
    channel._conn = connection
    channel._reader_index = 0
    channel._raw_apdu_logging = False
    channel._quiet_apdu_logging = True
    return channel


class LocalSessionIpadDeclarationTests(unittest.TestCase):
    def test_the_card_refuses_es10_after_a_bare_select(self) -> None:
        # The exchange of the report: SELECT ISD-R, then GetEUICCInfo1 answered '69 85'.
        card = _gating_card()
        card.send(SELECT_ISD_R, "SELECT ISD-R")
        with self.assertRaises(IOError) as refused:
            card.send(GET_EUICC_INFO1, "GetEuiccInfo1")
        self.assertIn("6985", str(refused.exception))

    def test_the_first_es10_command_of_a_session_is_answered(self) -> None:
        card = _gating_card()
        session = LocalIsdrSession(apdu_channel=card)

        session.select_isdr()
        info1 = session.get_euicc_info1()

        self.assertEqual(info1[:2], bytes.fromhex("BF20"))
        self.assertEqual(card.sent[0][:4], bytes.fromhex("80AA0000"))
        self.assertTrue(declares_ipad(card.sent[0][5:]))
        self.assertEqual(card.sent[1], SELECT_ISD_R)
        self.assertEqual(card.sent[2], GET_EUICC_INFO1)

    def test_one_declaration_serves_every_command_of_the_card_session(self) -> None:
        card = _gating_card()
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session.collect_profile_metadata(), [])
        self.assertEqual(session.get_eid(), TEST_EID)
        self.assertEqual(session.collect_profile_metadata(), [])

        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)
        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.count(INS_SELECT), 2)

    def test_an_eid_read_that_opens_the_card_session_declares_first(self) -> None:
        card = _gating_card()
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session._read_card_eid(), TEST_EID)
        self.assertEqual(session.collect_profile_metadata(), [])

        self.assertEqual(
            [command[1] for command in card.sent[:3]],
            [INS_TERMINAL_CAPABILITY, INS_SELECT, INS_STORE_DATA],
        )
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)

    def test_an_ecasd_read_after_an_unseen_reset_declares_before_it_selects(self) -> None:
        # The card was reset under a session whose state still says the ISD-R
        # is selected: GetEID is refused, and the ECASD read that follows is
        # the first application selection of the new card session. A
        # declaration after it would come too late for the ISD-R commands.
        card = _gating_card()
        session = LocalIsdrSession(apdu_channel=card)
        session.select_isdr()
        card.reset()
        forget_ipad_declaration(card)
        before = len(card.sent)

        self.assertEqual(session._read_card_eid(), TEST_EID)
        self.assertEqual(session.collect_profile_metadata(), [])

        self.assertEqual(
            [command[1] for command in card.sent[before : before + 5]],
            [INS_STORE_DATA, INS_TERMINAL_CAPABILITY, INS_SELECT, INS_GET_DATA, INS_SELECT],
        )
        self.assertEqual(card.selected_aids()[-3:], [ECASD_AID, ISD_R_AID, ISD_R_AID])

    def test_an_issuer_read_that_opens_the_card_session_declares_first(self) -> None:
        card = _gating_card()
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session._read_card_ecasd_issuer_identity()["issuer_number"], TEST_EID[:8])
        self.assertEqual(session.collect_profile_metadata(), [])

        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.selected_aids()[0], ECASD_AID)
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)

    def test_a_channel_reset_brings_the_declaration_again(self) -> None:
        first = _AnsweringConnection()
        second = _AnsweringConnection()
        channel = _pcsc_channel(first)
        session = LocalIsdrSession(apdu_channel=channel)

        session.select_isdr()
        self.assertTrue(channel.ipad_declared)
        with mock.patch.object(PcscApduChannel, "_connect", return_value=second):
            with mock.patch("SCP11.transport.time.sleep"):
                self.assertTrue(channel.reset())
        self.assertFalse(channel.ipad_declared)
        session.select_isdr()
        session.select_isdr()

        self.assertEqual([call[1] for call in first.calls], [INS_TERMINAL_CAPABILITY, INS_SELECT])
        self.assertEqual([call[1] for call in second.calls], [INS_TERMINAL_CAPABILITY, INS_SELECT, INS_SELECT])
        self.assertTrue(declares_ipad(second.calls[0][5:]))

    def test_a_failed_reconnect_leaves_the_declaration_owed(self) -> None:
        channel = _pcsc_channel(_AnsweringConnection())
        LocalIsdrSession(apdu_channel=channel).select_isdr()
        self.assertTrue(channel.ipad_declared)

        with mock.patch.object(PcscApduChannel, "_connect", side_effect=RuntimeError("no reader")):
            with mock.patch("SCP11.transport.time.sleep"):
                with self.assertRaises(RuntimeError):
                    channel.reset()

        self.assertFalse(channel.ipad_declared)

    def test_a_card_that_refuses_the_command_is_noted_once_and_the_select_goes_on(self) -> None:
        class NoTerminalCapability(ScriptedEuicc):
            def send(self, apdu: bytes, log_name: str) -> bytes:
                if bytes(apdu)[1] == INS_TERMINAL_CAPABILITY:
                    self.sent.append(bytes(apdu))
                    raise IOError("APDU Failed: 6D00")
                return super().send(apdu, log_name)

        card = NoTerminalCapability()
        session = LocalIsdrSession(apdu_channel=card)
        printed = io.StringIO()

        with redirect_stdout(printed):
            session.select_isdr()
            session.select_isdr()

        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)
        self.assertEqual(card.count(INS_SELECT), 2)
        self.assertEqual(printed.getvalue().count("TERMINAL CAPABILITY not taken (APDU Failed: 6D00)"), 1)
        self.assertIn("SGP.32 v1.3 §3.8.2", printed.getvalue())

    def test_a_failure_that_is_no_card_answer_is_raised_and_leaves_the_declaration_owed(self) -> None:
        class LostReader(ScriptedEuicc):
            def __init__(self) -> None:
                super().__init__()
                self.lost = True

            def send(self, apdu: bytes, log_name: str) -> bytes:
                if self.lost:
                    raise LookupError("reader gone")
                return super().send(apdu, log_name)

        card = LostReader()
        session = LocalIsdrSession(apdu_channel=card)

        with self.assertRaises(LookupError):
            session.select_isdr()
        card.lost = False
        session.select_isdr()

        self.assertEqual([command[1] for command in card.sent], [INS_TERMINAL_CAPABILITY, INS_SELECT])

    def test_no_channel_means_no_declaration(self) -> None:
        self.assertEqual(declare_ipad(None, "none"), "")
        forget_ipad_declaration(None)


class CardSessionPerChannelTests(unittest.TestCase):
    """A channel opened beside another one is a card session of its own.

    A poll opens its channel after the shell read the EID over another one;
    the declaration made there must not be in force for the poll, whose
    eUICC keeps the IPAe off behind it (GSMA SGP.32 v1.3 §3.8.4).
    """

    def test_another_channel_starts_without_the_declaration(self) -> None:
        first = _pcsc_channel(_AnsweringConnection())
        LocalIsdrSession(apdu_channel=first).select_isdr()
        second = _pcsc_channel(_AnsweringConnection())

        self.assertTrue(first.ipad_declared)
        self.assertFalse(second.ipad_declared)
        self.assertFalse(PcscApduChannel.ipad_declared)

    def test_a_pcsc_connect_resets_the_card(self) -> None:
        class Connection:
            def connect(self, disposition: int | None = None) -> None:
                return None

        class Reader:
            def createConnection(self) -> Connection:  # noqa: N802 - pyscard's name
                return connection

            def __str__(self) -> str:
                return "Scripted Reader 00 00"

        connection = Connection()
        with mock.patch("SCP11.transport.is_simulated_card_backend", return_value=False):
            with mock.patch("smartcard.System.readers", return_value=[Reader()]):
                with mock.patch("SCP11.transport.wrap_connection", side_effect=lambda conn, source: conn):
                    with mock.patch.object(PcscApduChannel, "_reset_connected_card") as reset_card:
                        channel = PcscApduChannel(reader_index=0, quiet_apdu_logging=True)

        reset_card.assert_called_once_with(connection)
        self.assertIs(channel._conn, connection)
        self.assertFalse(channel.ipad_declared)

    def test_the_connect_reset_is_a_card_reset(self) -> None:
        try:
            from smartcard import scard
        except ImportError:
            self.skipTest("pyscard is not installed")

        class Connection:
            hcard = 7
            protocol = 2

        channel = PcscApduChannel.__new__(PcscApduChannel)
        with mock.patch.object(scard, "SCardReconnect", return_value=(scard.SCARD_S_SUCCESS, 2)) as reconnect:
            channel._reset_connected_card(Connection())

        reconnect.assert_called_once_with(7, scard.SCARD_SHARE_SHARED, 2, scard.SCARD_RESET_CARD)


class EimLocalIpadDeclarationTests(unittest.TestCase):
    def test_the_shell_and_its_session_send_one_declaration_between_them(self) -> None:
        card = _gating_card()
        session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=card)
        verbs = EngineVerbs(type("Shell", (), {"session": session})(), emit=lambda _line: None)

        verbs._exchange(GET_EID, "GetEID")
        session.exchange_isdr_command(GET_EID, "GetEID again", sync_notifications=False)

        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)
        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.labels[0], "EIM-LOCAL: TERMINAL CAPABILITY (IPAd)")

    def test_a_session_driven_without_the_shell_declares_by_itself(self) -> None:
        # The Command Center's direct ISD-R actions call the session with no shell around it.
        card = _gating_card()
        session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=card)

        answer = session.exchange_isdr_command(GET_EID, "GetEID", sync_notifications=False)

        self.assertEqual(answer, bytes.fromhex("BF3E125A10" + TEST_EID))
        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.labels[0], "LOCAL: TERMINAL CAPABILITY (IPAd)")

    def test_the_shell_reset_of_a_channel_with_its_own_reset_declares_again(self) -> None:
        card = _gating_card()
        session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=card)
        verbs = EngineVerbs(type("Shell", (), {"session": session})(), emit=lambda _line: None)

        verbs._exchange(GET_EID, "GetEID")
        self.assertTrue(verbs._reset_card())
        verbs._exchange(GET_EID, "GetEID after the reset")

        self.assertEqual(card.resets, 1)
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 2)

    def test_the_shell_reads_the_card_eid_over_es10(self) -> None:
        # The card of a live report answers no GET DATA on its ECASD.
        card = ScriptedEuicc()
        session = EimLocalSession(cfg=EimLocalConfig(), apdu_channel=card)

        self.assertEqual(session._read_card_eid_safe(), TEST_EID)

        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(card.count(INS_GET_DATA), 0)


if __name__ == "__main__":
    unittest.main()
