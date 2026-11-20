# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eSIM Management Get EID and Status actions on a card that answers no GET DATA on its ECASD."""

from __future__ import annotations

import unittest
from unittest import mock

from tests.local_smdp_card_support import (
    DEFAULT_DP_ADDRESS,
    ECASD_AID,
    INS_GET_DATA,
    INS_SELECT,
    INS_STORE_DATA,
    INS_TERMINAL_CAPABILITY,
    ISD_R_AID,
    SW_FILE_NOT_FOUND,
    TEST_EID,
    ScriptedEuicc,
)
from yggdrasim_common.gui_server.actions import scp11_live
from yggdrasim_common.gui_server.actions.registry import ActionContext


def _run(dispatcher, card: ScriptedEuicc) -> dict:
    with mock.patch.object(scp11_live, "_resolve_reader_index", return_value=0):
        with mock.patch.object(scp11_live, "_build_apdu_channel", return_value=card):
            return dispatcher(ActionContext(), reader="")


def _lines(answer: dict) -> dict[str, str]:
    return {line["label"]: line["value"] for line in answer["detail_lines"]}


class GetEidActionTests(unittest.TestCase):
    def test_the_eid_is_read_over_es10_behind_the_connect_phase(self) -> None:
        # The card of a live report: ES10 behind the IPAd declaration, '6D 00' to GET DATA on the ECASD.
        card = ScriptedEuicc()

        answer = _run(scp11_live._dispatch_get_eid, card)

        self.assertTrue(answer["ok"])
        self.assertEqual(answer["eid"], TEST_EID)
        self.assertEqual(answer["eid_length"], 32)
        self.assertIn("ES10 GetEID", answer["note"])
        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(card.count(INS_GET_DATA), 0)

    def test_a_card_without_get_eid_is_read_through_the_ecasd(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True, es10_get_eid=False)

        answer = _run(scp11_live._dispatch_get_eid, card)

        self.assertTrue(answer["ok"])
        self.assertEqual(answer["eid"], TEST_EID)
        self.assertEqual(card.selected_aids(), [ISD_R_AID, ECASD_AID])

    def test_a_connect_phase_that_fails_leaves_the_ecasd_read_and_the_answer_shape(self) -> None:
        class NoIsdR(ScriptedEuicc):
            def send(self, apdu: bytes, log_name: str) -> bytes:
                command = bytes(apdu)
                if command[1] == INS_SELECT and command[5:] == ISD_R_AID:
                    self.sent.append(command)
                    self._refuse(SW_FILE_NOT_FOUND)
                return super().send(apdu, log_name)

        card = NoIsdR(ecasd_get_data=True)

        answer = _run(scp11_live._dispatch_get_eid, card)

        self.assertTrue(answer["ok"])
        self.assertEqual(answer["eid"], TEST_EID)
        self.assertIn("connect phase failed", answer["note"])
        self.assertEqual(card.count(INS_STORE_DATA), 0)

    def test_a_card_that_gives_no_eid_is_answered_without_raising(self) -> None:
        card = ScriptedEuicc(es10_get_eid=False)

        answer = _run(scp11_live._dispatch_get_eid, card)

        self.assertFalse(answer["ok"])
        self.assertEqual(answer["eid"], "")
        self.assertIn("No EID returned", answer["note"])
        self.assertIn("GET DATA '5A' on the ECASD: APDU Failed: 6D00", answer["trace"])


class StatusActionTests(unittest.TestCase):
    def test_status_connects_before_it_reads_the_eid(self) -> None:
        card = ScriptedEuicc()

        answer = _run(scp11_live._dispatch_status, card)

        self.assertEqual(answer["note"], "ok")
        self.assertEqual(answer["eid"], TEST_EID)
        lines = _lines(answer)
        self.assertEqual(lines["EID"], TEST_EID)
        self.assertEqual(lines["Default SM-DP+"], DEFAULT_DP_ADDRESS.decode("ascii"))
        # The declaration leads the card session, and no application was selected before the ISD-R.
        self.assertEqual(card.sent[0][1], INS_TERMINAL_CAPABILITY)
        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(card.es10_tags(), ["BF3E", "BF3C"])

    def test_status_still_reads_the_addresses_after_an_ecasd_fallback(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True, es10_get_eid=False)

        answer = _run(scp11_live._dispatch_status, card)

        self.assertEqual(answer["note"], "ok")
        self.assertEqual(answer["eid"], TEST_EID)
        self.assertEqual(_lines(answer)["Default SM-DP+"], DEFAULT_DP_ADDRESS.decode("ascii"))
        # The fallback returned to the ISD-R, so the configured-data read was answered.
        self.assertEqual(card.selected_aids(), [ISD_R_AID, ECASD_AID, ISD_R_AID])

    def test_status_without_an_eid_still_shows_the_addresses(self) -> None:
        card = ScriptedEuicc(es10_get_eid=False)

        answer = _run(scp11_live._dispatch_status, card)

        lines = _lines(answer)
        self.assertEqual(lines["EID"], "(unavailable)")
        self.assertEqual(lines["Default SM-DP+"], DEFAULT_DP_ADDRESS.decode("ascii"))


if __name__ == "__main__":
    unittest.main()
