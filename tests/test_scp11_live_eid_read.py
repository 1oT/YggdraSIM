# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The EID read of the eSIM Management orchestrator: ES10 GetEID behind the connect phase, the ECASD read otherwise."""

from __future__ import annotations

import unittest
from unittest import mock

from SCP11.live.config import SGPConfig
from SCP11.live.orchestrator import SGP22Orchestrator
from tests.local_smdp_card_support import (
    ECASD_AID,
    INS_GET_DATA,
    INS_MANAGE_CHANNEL,
    INS_SELECT,
    INS_STATUS,
    INS_STORE_DATA,
    INS_TERMINAL_CAPABILITY,
    ISD_R_AID,
    SW_CONDITIONS_NOT_SATISFIED,
    TEST_EID,
    ScriptedEuicc,
)

INS_TERMINAL_PROFILE = 0x10
# ES10 GetEID as one STORE DATA on logical channel 1, where the connect phase selects the ISD-R.
GET_EID_ON_CHANNEL_1 = bytes.fromhex("81E2910006BF3E035C015A")
GET_DATA_EID_ON_CHANNEL_1 = bytes.fromhex("81CA005A00")
CONNECT_PHASE = [INS_TERMINAL_CAPABILITY, INS_MANAGE_CHANNEL, INS_SELECT, INS_STATUS]


def _orchestrator(card: ScriptedEuicc) -> SGP22Orchestrator:
    return SGP22Orchestrator(cfg=SGPConfig(), apdu_channel=card)


def _instructions(card: ScriptedEuicc, start: int = 0) -> list[int]:
    return [command[1] for command in card.sent[start:]]


def _read(orchestrator: SGP22Orchestrator, **options: bool) -> tuple[str, list[str]]:
    """The EID and what the read printed."""
    printed: list[str] = []
    with mock.patch("SCP11.live.orchestrator.print", side_effect=lambda *parts, **_: printed.append(" ".join(map(str, parts)))):
        eid = orchestrator._read_card_eid(**options)
    return eid, printed


class ConnectedEidReadTests(unittest.TestCase):
    def test_behind_the_connect_phase_the_eid_is_one_es10_command_on_the_isdr(self) -> None:
        # The card of a live report: ES10 behind the IPAd declaration, '6D 00' to GET DATA on the ECASD.
        card = ScriptedEuicc()
        orchestrator = _orchestrator(card)

        orchestrator._phase_connect()
        eid, printed = _read(orchestrator)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(_instructions(card), CONNECT_PHASE + [INS_STORE_DATA])
        self.assertEqual(card.sent[-1], GET_EID_ON_CHANNEL_1)
        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(printed, [])

    def test_the_two_calls_a_listener_opens_with_give_it_the_eid(self) -> None:
        # run_eim_listen runs the connect phase, reads the EID and refuses to listen without 32 digits.
        card = ScriptedEuicc()
        orchestrator = _orchestrator(card)

        orchestrator._phase_connect()
        eid = orchestrator._read_card_eid()

        self.assertEqual(len(eid), 32)
        self.assertEqual(card.count(INS_GET_DATA), 0)

    def test_a_refused_get_eid_costs_one_command_then_the_ecasd_is_read(self) -> None:
        # '69 85' is a status the other ES10 sends answer with a reset and
        # the STK-mode cascade; the EID read asks once and moves on.
        class RefusesGetEid(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                if payload[:2] == bytes.fromhex("BF3E"):
                    self.es10.append(payload)
                    self._refuse(SW_CONDITIONS_NOT_SATISFIED)
                return super()._es10(payload)

        card = RefusesGetEid(ecasd_get_data=True)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()
        before = len(card.sent)

        eid, printed = _read(orchestrator)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(_instructions(card, before), [INS_STORE_DATA, INS_SELECT, INS_GET_DATA, INS_SELECT])
        self.assertEqual(card.sent[before + 2], GET_DATA_EID_ON_CHANNEL_1)
        self.assertEqual(card.selected_aids()[-2:], [ECASD_AID, ISD_R_AID])
        self.assertEqual(card.resets, 0)
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)
        self.assertEqual(card.count(INS_TERMINAL_PROFILE), 0)
        self.assertEqual(printed, [])

    def test_the_fallback_leaves_the_ecasd_selected_when_asked_to(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True, es10_get_eid=False)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()

        eid, _printed = _read(orchestrator, reselect_isdr=False)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(card.selected_aids()[-1], ECASD_AID)

    def test_a_card_that_gives_no_eid_either_way_answers_nothing_and_both_refusals_are_printed(self) -> None:
        card = ScriptedEuicc(es10_get_eid=False)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()

        eid, printed = _read(orchestrator)

        self.assertEqual(eid, "")
        self.assertEqual(
            printed,
            [
                "[*] EIM metadata: failed to read EID (ES10 GetEID on the ISD-R: APDU Failed: 6A88; "
                "GET DATA '5A' on the ECASD: APDU Failed: 6D00)."
            ],
        )
        self.assertEqual(card.selected_aids()[-1], ISD_R_AID)

    def test_an_answer_without_an_eid_falls_back_as_a_refusal_does(self) -> None:
        class EmptyAnswer(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                if payload[:2] == bytes.fromhex("BF3E"):
                    self.es10.append(payload)
                    return bytes.fromhex("BF3E00")
                return super()._es10(payload)

        card = EmptyAnswer(ecasd_get_data=True)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()

        eid, _printed = _read(orchestrator)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(card.count(INS_GET_DATA), 1)

    def test_a_failure_of_the_link_answers_nothing_and_asks_the_ecasd_nothing(self) -> None:
        class LostLink(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                raise IOError("PC/SC channel is disconnected.")

        card = LostLink(ecasd_get_data=True)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()

        eid, printed = _read(orchestrator)

        self.assertEqual(eid, "")
        self.assertEqual(printed, ["[*] EIM metadata: failed to read EID (PC/SC channel is disconnected.)."])
        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(card.count(INS_GET_DATA), 0)

    def test_the_read_raises_nothing_whatever_the_channel_raises(self) -> None:
        class Broken(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                raise LookupError("reader gone")

        card = Broken()
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()

        eid, printed = _read(orchestrator)

        self.assertEqual(eid, "")
        self.assertEqual(printed, ["[*] EIM metadata: failed to read EID (reader gone)."])


class UnconnectedEidReadTests(unittest.TestCase):
    """Without the connect phase the read sends what it always sent.

    A card session that has to stay without the IPAd declaration, a poll's,
    must not get a TERMINAL CAPABILITY or an ES10 command from this read.
    """

    def test_the_read_is_the_ecasd_one_alone(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True)
        orchestrator = _orchestrator(card)

        eid, printed = _read(orchestrator, reselect_isdr=False)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(_instructions(card), [INS_SELECT, INS_GET_DATA])
        self.assertEqual(card.sent[1], bytes.fromhex("80CA005A00"))
        self.assertEqual(card.selected_aids(), [ECASD_AID])
        self.assertEqual(printed, [])

    def test_the_reselect_follows_when_asked(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True)
        orchestrator = _orchestrator(card)

        eid, _printed = _read(orchestrator)

        self.assertEqual(eid, TEST_EID)
        self.assertEqual(_instructions(card), [INS_SELECT, INS_GET_DATA, INS_SELECT])
        self.assertEqual(card.selected_aids(), [ECASD_AID, ISD_R_AID])

    def test_a_card_without_get_data_gets_no_es10_command_and_no_declaration(self) -> None:
        card = ScriptedEuicc()
        orchestrator = _orchestrator(card)

        eid, printed = _read(orchestrator, reselect_isdr=False)

        self.assertEqual(eid, "")
        self.assertEqual(_instructions(card), [INS_SELECT, INS_GET_DATA])
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 0)
        self.assertEqual(card.count(INS_STORE_DATA), 0)
        self.assertEqual(printed, ["[*] EIM metadata: failed to read EID (APDU Failed: 6D00)."])

    def test_a_reset_for_recovery_takes_the_es10_read_away_again(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True)
        orchestrator = _orchestrator(card)
        orchestrator._phase_connect()
        self.assertTrue(orchestrator._phase_connect_complete)

        restarted = orchestrator._reset_apdu_channel_for_recovery(
            "TEST", "a lost link", IOError("PC/SC channel is disconnected.")
        )
        before = len(card.sent)
        eid, _printed = _read(orchestrator, reselect_isdr=False)

        self.assertTrue(restarted)
        self.assertFalse(orchestrator._phase_connect_complete)
        self.assertEqual(eid, TEST_EID)
        self.assertEqual(_instructions(card, before), [INS_SELECT, INS_GET_DATA])


if __name__ == "__main__":
    unittest.main()
