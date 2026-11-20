# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The EID read of a local ISD-R session: ES10 GetEID first, the ECASD read behind it."""

from __future__ import annotations

import unittest

from SCP11.eim_local.engine import delivery
from SCP11.local_access.session import LocalIsdrSession
from SCP11.shared.get_eid import EID_OCTETS, GET_EID_REQUEST, eid_value
from SCP11.transport import card_status_word
from tests.local_smdp_card_support import (
    ECASD_AID,
    INS_GET_DATA,
    INS_SELECT,
    INS_STORE_DATA,
    INS_TERMINAL_CAPABILITY,
    ISD_R_AID,
    TEST_EID,
    ScriptedEuicc,
)

# The one STORE DATA of ES10 GetEID: last block, BER-TLV, case 4, the request of SGP.22 v3.1 §5.7.20.
GET_EID_APDU = bytes.fromhex("80E2910006BF3E035C015A")
GOOD_ANSWER = bytes.fromhex("BF3E125A10" + TEST_EID)


def _instructions(card: ScriptedEuicc) -> list[int]:
    return [command[1] for command in card.sent]


class GetEidCodecTests(unittest.TestCase):
    def test_the_request_is_the_tag_list_naming_the_eid(self) -> None:
        # GetEuiccDataRequest 'BF3E' { tagList '5C' = '5A' }.
        self.assertEqual(GET_EID_REQUEST, bytes.fromhex("BF3E035C015A"))
        self.assertEqual(EID_OCTETS, 16)

    def test_the_answer_gives_its_sixteen_octets(self) -> None:
        self.assertEqual(eid_value(GOOD_ANSWER), bytes.fromhex(TEST_EID))
        # Another member ahead of the EID does not hide it.
        self.assertEqual(eid_value(bytes.fromhex("BF3E15800100" + "5A10" + TEST_EID)), bytes.fromhex(TEST_EID))

    def test_an_answer_that_is_no_eid_is_refused_by_name(self) -> None:
        refused = {
            "nothing": b"",
            "one octet": bytes.fromhex("BF"),
            "a tag without a length": bytes.fromhex("BF3E"),
            "a length that claims more than there is": bytes.fromhex("BF3E125A10" + "00" * 15),
            "an EID that is too short": bytes.fromhex("BF3E055A03112233"),
            "an EID that is too long": bytes.fromhex("BF3E135A11" + "00" * 17),
            "no EID inside": bytes.fromhex("BF3E03800100"),
            "octets after the answer": GOOD_ANSWER + b"\x00",
        }
        for name, answer in refused.items():
            with self.subTest(name):
                with self.assertRaises(ValueError) as failure:
                    eid_value(answer)
                self.assertTrue(str(failure.exception).startswith("GetEID answer"), str(failure.exception))

    def test_the_local_eim_delivery_reads_through_the_same_codec(self) -> None:
        self.assertIs(delivery.GET_EID_REQUEST, GET_EID_REQUEST)
        self.assertEqual(delivery.read_eid(lambda _payload, _label: GOOD_ANSWER), TEST_EID)
        with self.assertRaises(delivery.DeliveryError) as undecodable:
            delivery.read_eid(lambda _payload, _label: bytes.fromhex("BF3E"))
        self.assertEqual(str(undecodable.exception), "GetEID answer does not decode: Missing TLV length.")
        with self.assertRaises(delivery.DeliveryError) as empty:
            delivery.read_eid(lambda _payload, _label: bytes.fromhex("BF3E03800100"))
        self.assertEqual(str(empty.exception), "GetEID answer carries no EID '5A'.")
        with self.assertRaises(delivery.DeliveryError) as short:
            delivery.read_eid(lambda _payload, _label: bytes.fromhex("BF3E055A03112233"))
        self.assertEqual(str(short.exception), "GetEID answer does not decode: eidValue must be 16 octets, got 3.")


class CardStatusWordTests(unittest.TestCase):
    def test_a_refusal_carries_its_status_word(self) -> None:
        self.assertEqual(card_status_word(IOError("APDU Failed: 6D00")), 0x6D00)
        self.assertEqual(card_status_word(IOError("APDU Failed: 6985")), 0x6985)

    def test_a_failure_of_the_link_carries_none(self) -> None:
        for error in (
            IOError("PC/SC channel is disconnected."),
            RuntimeError("Card was reset. (0x80100068)"),
            ValueError("malformed answer"),
            IOError("APDU Failed: 69"),
        ):
            with self.subTest(str(error)):
                self.assertIsNone(card_status_word(error))


class SessionEidReadTests(unittest.TestCase):
    def test_the_eid_comes_from_the_isdr_without_a_visit_to_the_ecasd(self) -> None:
        card = ScriptedEuicc()
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session.get_eid(), TEST_EID)

        self.assertEqual(_instructions(card), [INS_TERMINAL_CAPABILITY, INS_SELECT, INS_STORE_DATA])
        self.assertEqual(card.sent[2], GET_EID_APDU)
        self.assertEqual(card.selected_aids(), [ISD_R_AID])

    def test_a_read_that_opens_the_card_session_selects_the_isdr_itself(self) -> None:
        card = ScriptedEuicc()
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session._read_card_eid(), TEST_EID)

        self.assertEqual(_instructions(card), [INS_TERMINAL_CAPABILITY, INS_SELECT, INS_STORE_DATA])
        self.assertTrue(session.state.isdr_selected)

    def test_a_read_with_the_isdr_selected_sends_the_one_command(self) -> None:
        # Between PrepareDownload and the package nothing but GetEID reaches the card.
        card = ScriptedEuicc()
        session = LocalIsdrSession(apdu_channel=card)
        session.select_isdr()
        before = len(card.sent)

        self.assertEqual(session._read_card_eid(), TEST_EID)

        self.assertEqual(card.sent[before:], [GET_EID_APDU])

    def test_a_refused_get_eid_falls_back_to_the_ecasd_and_returns_to_the_isdr(self) -> None:
        card = ScriptedEuicc(ecasd_get_data=True, es10_get_eid=False)
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session.get_eid(), TEST_EID)

        self.assertEqual(card.selected_aids(), [ISD_R_AID, ECASD_AID, ISD_R_AID])
        self.assertEqual(card.sent[-2], bytes.fromhex("80CA005A00"))
        self.assertEqual(card.count(INS_TERMINAL_CAPABILITY), 1)
        self.assertEqual(card.labels[-2], "LOCAL: GetEID (ECASD)")

    def test_an_answer_without_an_eid_falls_back_as_a_refusal_does(self) -> None:
        class EmptyAnswer(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                if payload[:2] == bytes.fromhex("BF3E"):
                    self.es10.append(payload)
                    return bytes.fromhex("BF3E00")
                return super()._es10(payload)

        card = EmptyAnswer(ecasd_get_data=True)
        session = LocalIsdrSession(apdu_channel=card)

        self.assertEqual(session.get_eid(), TEST_EID)
        self.assertEqual(card.count(INS_GET_DATA), 1)

    def test_a_card_that_gives_no_eid_either_way_is_reported_with_both_answers(self) -> None:
        card = ScriptedEuicc(es10_get_eid=False)
        session = LocalIsdrSession(apdu_channel=card)

        with self.assertRaises(RuntimeError) as failure:
            session.get_eid()

        self.assertEqual(
            str(failure.exception),
            "The card gave no EID. ES10 GetEID on the ISD-R: APDU Failed: 6A88; "
            "GET DATA '5A' on the ECASD: APDU Failed: 6D00.",
        )
        # The ISD-R is the selected application again.
        self.assertEqual(card.selected_aids()[-1], ISD_R_AID)

    def test_a_failure_of_the_link_is_raised_as_it_is_and_asks_the_ecasd_nothing(self) -> None:
        class LostLink(ScriptedEuicc):
            def _es10(self, payload: bytes) -> bytes:
                raise IOError("PC/SC channel is disconnected.")

        card = LostLink(ecasd_get_data=True)
        session = LocalIsdrSession(apdu_channel=card)

        with self.assertRaises(IOError) as failure:
            session.get_eid()

        self.assertEqual(str(failure.exception), "PC/SC channel is disconnected.")
        self.assertEqual(card.selected_aids(), [ISD_R_AID])
        self.assertEqual(card.count(INS_GET_DATA), 0)

    def test_a_link_that_fails_during_the_fallback_is_raised_as_it_is(self) -> None:
        class LostAfterTheRefusal(ScriptedEuicc):
            def send(self, apdu: bytes, log_name: str) -> bytes:
                if bytes(apdu)[1] == INS_SELECT and bytes(apdu)[5:] == ECASD_AID:
                    raise IOError("PC/SC channel is disconnected.")
                return super().send(apdu, log_name)

        card = LostAfterTheRefusal(ecasd_get_data=True, es10_get_eid=False)
        session = LocalIsdrSession(apdu_channel=card)

        with self.assertRaises(IOError) as failure:
            session.get_eid()

        self.assertEqual(str(failure.exception), "PC/SC channel is disconnected.")

    def test_discovery_completes_on_a_card_that_answers_no_get_data_on_the_ecasd(self) -> None:
        # The issuer number is a GET DATA '42' on the ECASD; a card that
        # refuses it still gives its snapshot, with the EID read over ES10.
        card = ScriptedEuicc()
        session = LocalIsdrSession(apdu_channel=card)

        snapshot = session.discover_card()

        self.assertEqual(snapshot["eid"], TEST_EID)
        self.assertEqual(snapshot["issuer_number"], "")
        self.assertEqual([command for command in card.sent if command[1] == INS_GET_DATA], [bytes.fromhex("80CA004200")])
        # After the refused issuer read the ISD-R answers the rest of the snapshot.
        self.assertEqual(card.selected_aids(), [ISD_R_AID, ECASD_AID, ISD_R_AID])
        self.assertEqual(card.es10_tags()[-1], "BF56")

    def test_the_overview_read_completes_on_the_same_card(self) -> None:
        card = ScriptedEuicc()
        session = LocalIsdrSession(apdu_channel=card)

        overview = session.collect_quick_overview()

        self.assertEqual(overview["eid"], TEST_EID)
        self.assertEqual(overview["issuer_number"], "")


if __name__ == "__main__":
    unittest.main()
