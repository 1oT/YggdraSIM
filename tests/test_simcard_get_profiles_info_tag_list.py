# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Simulated eUICC GetProfilesInfo with search criteria and a tag list.

SGP.22 v3.1 §5.7.15 defines ProfileInfoListRequest (searchCriteria, tagList
'5C') and the default (*) set; SGP.32 v1.3 §5.9.14 keeps the function for
ES10b, §4.4 adds ecallIndication '9F7B', fallbackAttribute '9F26' and
fallbackAllowed '9F67' to ProfileInfo, and §2.11.1.1.3 gives the
listProfileInfo PSMO its own default list. pySim's compiled RSP module is
the second reference for the request and error encodings.
"""

from __future__ import annotations

import unittest

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic, parse_profile_info_list_request, split_tag_list
from SIMCARD.utils import encode_iccid_ef, read_tlv, tlv

# What the SCP11 console sends (SCP11/live/console.py PROFILE_INFO_TAG_LIST).
CONSOLE_TAG_LIST = bytes.fromhex("5A4F9F7090919295999F269F679F7B")


def _request(*fields: bytes) -> bytes:
    return tlv("BF2D", b"".join(fields))


def _entries(response: bytes) -> list[dict[bytes, bytes]]:
    """Map each ProfileInfo of a profileInfoListOk to {tag: value}, keeping order."""
    tag, value, _raw, end = read_tlv(response, 0)
    assert tag == bytes.fromhex("BF2D") and end == len(response)
    ok_tag, ok_value, _raw, ok_end = read_tlv(value, 0)
    assert ok_tag == b"\xA0" and ok_end == len(value)
    entries = []
    offset = 0
    while offset < len(ok_value):
        entry_tag, entry_value, _raw, offset = read_tlv(ok_value, offset)
        assert entry_tag == b"\xE3"
        fields: dict[bytes, bytes] = {}
        inner = 0
        while inner < len(entry_value):
            field_tag, field_value, _raw, inner = read_tlv(entry_value, inner)
            fields[bytes(field_tag)] = bytes(field_value)
        entries.append(fields)
    return entries


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.state = build_default_state()
        # The default simulated eUICC: an enabled operational Profile and a
        # disabled test Profile.
        self.primary, self.secondary = self.state.profiles
        self.assertEqual(self.primary.profile_class, "operational")
        self.assertEqual(self.secondary.profile_class, "test")
        self.logic = SgpLogic(self.state)

    def _ask(self, request: bytes) -> bytes:
        response, sw1, sw2 = self.logic.handle_store_data(request)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response


class DefaultSetTests(_Base):
    def test_bare_request_returns_the_sgp22_default_set_only(self) -> None:
        self.secondary.fallback_attribute = True
        self.secondary.fallback_allowed = True
        entries = _entries(self._ask(bytes.fromhex("BF2D00")))
        self.assertEqual(len(entries), 2)
        for fields in entries:
            self.assertEqual(
                list(fields),
                [bytes.fromhex(tag) for tag in ("5A", "4F", "9F70", "90", "91", "92", "95")],
            )

    def test_psmo_default_list_carries_the_fallback_items(self) -> None:
        self.secondary.fallback_attribute = True
        self.secondary.fallback_allowed = True
        response = self.logic._psmo_list_profile_info(bytes.fromhex("BF2D00"))
        entries = _entries(response)
        self.assertNotIn(b"\x90", entries[1])  # no nickname in the PSMO default list
        self.assertEqual(entries[1][bytes.fromhex("9F26")], b"\xFF")
        self.assertEqual(entries[1][bytes.fromhex("9F67")], b"\xFF")


class TagListTests(_Base):
    def test_console_tag_list_reports_fallback_items(self) -> None:
        self.secondary.fallback_attribute = True
        self.secondary.fallback_allowed = True
        self.primary.fallback_allowed = False
        entries = _entries(self._ask(_request(tlv("5C", CONSOLE_TAG_LIST))))
        primary, secondary = entries
        # fallbackAttribute is DEFAULT FALSE: DER leaves it out unless TRUE.
        self.assertNotIn(bytes.fromhex("9F26"), primary)
        self.assertEqual(primary[bytes.fromhex("9F67")], b"\x00")
        self.assertEqual(secondary[bytes.fromhex("9F26")], b"\xFF")
        self.assertEqual(secondary[bytes.fromhex("9F67")], b"\xFF")
        # Absent fallbackAllowed metadata stays absent.
        self.secondary.fallback_allowed = None
        entries = _entries(self._ask(_request(tlv("5C", CONSOLE_TAG_LIST))))
        self.assertNotIn(bytes.fromhex("9F67"), entries[1])

    def test_response_keeps_profile_info_order_whatever_the_tag_list_order(self) -> None:
        entries = _entries(self._ask(_request(tlv("5C", bytes.fromhex("9F70955A")))))
        self.assertEqual(list(entries[0]), [b"\x5A", bytes.fromhex("9F70"), b"\x95"])

    def test_unknown_and_unheld_tags_are_omitted(self) -> None:
        entries = _entries(self._ask(_request(tlv("5C", bytes.fromhex("5AB7999F25DF7F")))))
        self.assertEqual(list(entries[0]), [b"\x5A"])

    def test_empty_tag_list_returns_empty_profile_info(self) -> None:
        entries = _entries(self._ask(_request(tlv("5C", b""))))
        self.assertEqual(entries, [{}, {}])

    def test_notification_configuration_round_trips(self) -> None:
        self.primary.notification_configuration = [
            (1, "smdp.example.test"),
            (2, "smdp.example.test"),
            (5, "eim.example.test"),
        ]
        entries = _entries(self._ask(_request(tlv("5C", bytes.fromhex("B6")))))
        parsed = self.logic._parse_notification_configuration_info(entries[0][bytes.fromhex("B6")])
        self.assertEqual(parsed, self.primary.notification_configuration)
        self.assertNotIn(bytes.fromhex("B6"), entries[1])


class SearchCriteriaTests(_Base):
    def test_iccid_aid_and_class_select_profiles(self) -> None:
        by_iccid = _request(tlv("A0", tlv("5A", encode_iccid_ef(self.secondary.iccid))))
        by_aid = _request(tlv("A0", tlv("4F", bytes.fromhex(self.primary.aid))))
        by_class = _request(tlv("A0", tlv("95", b"\x00")))
        self.assertEqual(
            [fields[b"\x4F"].hex().upper() for fields in _entries(self._ask(by_iccid))],
            [self.secondary.aid],
        )
        self.assertEqual(
            [fields[b"\x4F"].hex().upper() for fields in _entries(self._ask(by_aid))],
            [self.primary.aid],
        )
        self.assertEqual(
            [fields[b"\x4F"].hex().upper() for fields in _entries(self._ask(by_class))],
            [self.secondary.aid],
        )

    def test_no_match_returns_an_empty_list(self) -> None:
        request = _request(tlv("A0", tlv("5A", encode_iccid_ef("89880000000000009905"))))
        self.assertEqual(self._ask(request), bytes.fromhex("BF2D02A000"))


class MalformedRequestTests(_Base):
    INCORRECT_INPUT = bytes.fromhex("BF2D03810101")

    def test_malformed_requests_answer_incorrect_input_values(self) -> None:
        for request in (
            bytes.fromhex("BF2D015C"),                      # over-claiming length
            bytes.fromhex("BF2D035C019F"),                  # truncated tag in the list
            bytes.fromhex("BF2D03810100"),                  # not a request member
            _request(tlv("5C", b"\x5A"), tlv("A0", tlv("5A", b"\x98" * 10))),  # order
            _request(tlv("A0", tlv("5A", b"\x98" * 10) + tlv("95", b"\x02"))),  # two alternatives
            _request(tlv("A0", tlv("5A", b"\x98" * 9))),    # Iccid is SIZE(10)
            _request(tlv("A0", tlv("80", b"\x01"))),        # unknown alternative
            _request(tlv("A0", b"")),                       # empty searchCriteria
            bytes.fromhex("BF2D00") + b"\x00",              # trailing octet
        ):
            with self.subTest(request=request.hex().upper()):
                self.assertEqual(self._ask(request), self.INCORRECT_INPUT)


class DecodeBoundaryTests(unittest.TestCase):
    def test_parser_rejects_empty_short_and_overclaiming_input(self) -> None:
        for raw in (b"", b"\xBF", b"\xBF\x2D", bytes.fromhex("BF2D05A0"), bytes.fromhex("BF2D815C")):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    parse_profile_info_list_request(raw)

    def test_tag_list_splits_one_and_multi_octet_tags(self) -> None:
        self.assertEqual(split_tag_list(b""), ())
        self.assertEqual(
            split_tag_list(bytes.fromhex("5A9F70BF2295")),
            (b"\x5A", bytes.fromhex("9F70"), bytes.fromhex("BF22"), b"\x95"),
        )
        for raw in (b"\x9F", bytes.fromhex("BF81")):
            with self.subTest(raw=raw.hex()):
                with self.assertRaises(ValueError):
                    split_tag_list(raw)


class PySimCrossCheckTests(_Base):
    def setUp(self) -> None:
        super().setUp()
        try:
            from pySim.esim import rsp
        except ImportError as error:  # pragma: no cover - pySim is a runtime dependency
            self.skipTest(f"pySim unavailable: {error}")
        self.asn1 = rsp.asn1

    def test_requests_pysim_encodes_are_understood(self) -> None:
        request = self.asn1.encode(
            "ProfileInfoListRequest",
            {
                "searchCriteria": ("iccid", encode_iccid_ef(self.secondary.iccid)),
                "tagList": bytes.fromhex("5A9F70"),
            },
        )
        criterion, tag_list = parse_profile_info_list_request(request)
        self.assertEqual(criterion, (b"\x5A", encode_iccid_ef(self.secondary.iccid)))
        self.assertEqual(tag_list, (b"\x5A", bytes.fromhex("9F70")))
        entries = _entries(self._ask(request))
        self.assertEqual(list(entries[0]), [b"\x5A", bytes.fromhex("9F70")])

    def test_error_and_response_match_pysim(self) -> None:
        self.assertEqual(
            self._ask(bytes.fromhex("BF2D015C")),
            self.asn1.encode("ProfileInfoListResponse", ("profileInfoListError", 1)),
        )
        response = self._ask(_request(tlv("5C", CONSOLE_TAG_LIST)))
        kind, profiles = self.asn1.decode("ProfileInfoListResponse", response)
        self.assertEqual(kind, "profileInfoListOk")
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0]["iccid"], encode_iccid_ef(self.primary.iccid))


if __name__ == "__main__":
    unittest.main()


class EuiccConfiguredDataTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.3: the simulator's BF3C decodes under the v3.1 module."""

    def test_additional_sm_ds_and_ci_list_decode_with_pysim(self) -> None:
        from SCP11.pysim_support import pysim_rsp_v3_asn1

        spec = pysim_rsp_v3_asn1()
        if spec is None:  # pragma: no cover - pinned fork carries it
            self.skipTest("pySim SGP.22 v3.1 module unavailable")
        state = build_default_state()
        state.configured_data.additional_root_smds_addresses = ["smds2.example.test", "smds3.example.test"]
        logic = SgpLogic(state)
        response, sw1, sw2 = logic.handle_store_data(bytes.fromhex("BF3C00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        decoded = spec.decode("EuiccConfiguredDataResponse", response)
        self.assertEqual(decoded["additionalRootDsAddresses"], ["smds2.example.test", "smds3.example.test"])
        self.assertTrue(decoded["ciList"])
        for entry in decoded["ciList"]:
            self.assertEqual(len(entry["ciPKId"]), 20)
            self.assertTrue(entry["ciName"])
