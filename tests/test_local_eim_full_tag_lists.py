# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""LIST-PROFILES asks for every ProfileInfo member; IPA-DATA asks for every data item on ``tags=all``.

Without a tagList an eUICC answers listProfileInfo with a default set that
leaves out the Profile Policy Rules, the Profile Owner and the Notification
configuration (SGP.32 v1.3 §2.11.1.1, p.35), so the eIM names every member of
the ProfileInfo of the SGP.32 version the eUICC declares: §4.4 of v1.2 ends at
fallbackAllowed, v1.3 adds iotSpecificProfileInfo. A card of v1.2 answered the
v1.3 list with incorrectInputValues, so a list the eIM chose and the eUICC
refused is asked again without a tagList and remembered on the record.
IPA-DATA keeps its default and takes ``all`` for the eleven items of SGP.32
v1.3 §2.11.1.2, the two lists the eUICC deletes once acknowledged included.
``OP <id> --decode`` and the operation view's fold show the Decoder's reading
of what came back.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from SCP03.logic.euicc_info2 import declared_iot_versions
from SCP11.eim_local.engine import codec, overview, traffic
from SCP11.eim_local.engine.catalogue import (
    DEFAULT_IPA_DATA_TAGS,
    IPA_DATA_TAGS,
    REFUSED_TAG_LIST,
    TAG_LIST_ALL,
    TAG_LIST_DEFAULT,
    OperationError,
    build_items,
    build_unsigned_request,
    normalize_params,
    operation_type,
    profile_list_tag_list,
    record_iot_versions,
)
from SCP11.eim_local.engine.delivery import deliver
from SCP11.eim_local.engine.esipa import handle_asn1
from SCP11.eim_local.engine.service import STATE_CREATED, STATE_ERROR, STATE_SUCCESS, OperationRequest
from SCP11.eim_local.engine.store import EuiccRecord
from SCP11.shared.ber_tlv import read_single_ber_tlv
from SCP11.shared.profile_info import (
    PROFILE_INFO_ALL_TAGS,
    PROFILE_INFO_MEMBER_ADDED_IN,
    PROFILE_INFO_MEMBERS,
    PROFILE_INFO_SGP22_V3_ONLY,
    SGP32_V1_3,
    profile_info_members,
    profile_info_tag_list,
)
from SIMCARD.sgp import PROFILE_INFO_LIST_INCORRECT_INPUT, parse_profile_info_list_request
from tests.test_local_eim_service import ServiceTestBase

REPO = Path(__file__).resolve().parents[1]

# SGP.32 v1.3 §4.4, p.108: the ProfileInfo of an IoT eUICC, member by member.
SGP32_PROFILE_INFO = (
    ("5A", "iccid"), ("4F", "isdpAid"), ("9F70", "profileState"), ("90", "profileNickname"),
    ("91", "serviceProviderName"), ("92", "profileName"), ("93", "iconType"), ("94", "icon"),
    ("95", "profileClass"), ("B6", "notificationConfigurationInfo"), ("B7", "profileOwner"),
    ("B8", "dpProprietaryData"), ("99", "profilePolicyRules"), ("BF22", "serviceSpecificDataStoredInEuicc"),
    ("9F7B", "ecallIndication"), ("9F26", "fallbackAttribute"), ("9F67", "fallbackAllowed"),
    ("BF64", "iotSpecificProfileInfo"),
)
# SGP.32 v1.2 §4.4, p.102-103: the ProfileInfo of that version, member by member. It ends at fallbackAllowed.
SGP32_V1_2_PROFILE_INFO = (
    ("5A", "iccid"), ("4F", "isdpAid"), ("9F70", "profileState"), ("90", "profileNickname"),
    ("91", "serviceProviderName"), ("92", "profileName"), ("93", "iconType"), ("94", "icon"),
    ("95", "profileClass"), ("B6", "notificationConfigurationInfo"), ("B7", "profileOwner"),
    ("B8", "dpProprietaryData"), ("99", "profilePolicyRules"), ("BF22", "serviceSpecificDataStoredInEuicc"),
    ("9F7B", "ecallIndication"), ("9F26", "fallbackAttribute"), ("9F67", "fallbackAllowed"),
)
V1_2_TAGS = "".join(tag for tag, _name in SGP32_V1_2_PROFILE_INFO)
# SGP.22 v3.1 §5.7.15, p.343: the tags an eUICC supports in the tag list, all 22 rows.
SGP22_TAG_LIST = ("5A", "4F", "9F70", "90", "91", "92", "93", "94", "95", "B6", "B7", "B8", "99", "BF22", "BA",
                  "9B", "BC", "BD", "9F1F", "BF20", "9F24", "9F25")
# SGP.32 v1.3 §2.11.1.2, p.36: the IPA and eUICC data items, all 11.
SGP32_IPA_DATA_TAGS = ("A0", "81", "A2", "BF20", "BF22", "83", "84", "A5", "A6", "A8", "A9")


class TagTableTests(unittest.TestCase):
    def test_the_profile_info_members_are_section_4_4_whole(self) -> None:
        self.assertEqual(PROFILE_INFO_MEMBERS, SGP32_PROFILE_INFO)
        self.assertEqual(PROFILE_INFO_ALL_TAGS, "".join(tag for tag, _name in SGP32_PROFILE_INFO))

    def test_every_sgp22_tag_list_row_is_asked_for_or_named_as_left_out(self) -> None:
        asked = {tag for tag, _name in PROFILE_INFO_MEMBERS}
        self.assertEqual(set(SGP22_TAG_LIST), (asked & set(SGP22_TAG_LIST)) | set(PROFILE_INFO_SGP22_V3_ONLY))
        self.assertEqual(asked & set(PROFILE_INFO_SGP22_V3_ONLY), set())
        # What section 4.4 adds to the SGP.22 rows.
        self.assertEqual(asked - set(SGP22_TAG_LIST), {"9F7B", "9F26", "9F67", "BF64"})

    def test_the_members_of_v1_2_are_its_section_4_4_whole(self) -> None:
        self.assertEqual(profile_info_members([(1, 2, 0)]), SGP32_V1_2_PROFILE_INFO)
        self.assertEqual(profile_info_tag_list([(1, 2, 0)]), V1_2_TAGS)
        # What v1.3 adds to v1.2 is exactly the member the table names, and every named member exists.
        added = {tag for tag, _name in SGP32_PROFILE_INFO} - {tag for tag, _name in SGP32_V1_2_PROFILE_INFO}
        self.assertEqual(added, set(PROFILE_INFO_MEMBER_ADDED_IN))
        self.assertEqual(PROFILE_INFO_MEMBER_ADDED_IN, {"BF64": SGP32_V1_3})

    def test_an_euicc_is_asked_for_the_members_of_the_newest_version_it_declares(self) -> None:
        self.assertEqual(profile_info_members([(1, 3, 0)]), SGP32_PROFILE_INFO)
        self.assertEqual(profile_info_tag_list([(1, 2, 0), (1, 3, 0)]), PROFILE_INFO_ALL_TAGS)
        self.assertEqual(profile_info_tag_list([(1, 3, 1)]), PROFILE_INFO_ALL_TAGS)
        self.assertEqual(profile_info_tag_list([(2, 0, 0)]), PROFILE_INFO_ALL_TAGS)
        # No version on hand, and a version before v1.2, read as v1.2: the smaller list.
        for versions in ((), [(1, 0, 1)], [(1, 1, 0)], [(1, 2, 9)]):
            with self.subTest(versions=versions):
                self.assertEqual(profile_info_tag_list(versions), V1_2_TAGS)

    def test_the_ipa_data_items_are_section_2_11_1_2_whole(self) -> None:
        self.assertEqual(IPA_DATA_TAGS, SGP32_IPA_DATA_TAGS)
        # The default leaves out exactly the two lists the eUICC deletes once acknowledged.
        self.assertEqual(set(SGP32_IPA_DATA_TAGS) - set(DEFAULT_IPA_DATA_TAGS.split()), {"A0", "A2"})


def _euicc_info2(*versions: tuple[int, int, int]) -> str:
    """An EUICCInfo2 'BF22' that declares *versions* in iotSpecificInfo 'B4' (SGP.32 v1.3 §5.9.2), as hex."""
    declared = b"".join(codec.tlv(b"\x04", bytes(version)) for version in versions)
    iot = codec.tlv(b"\xB4", codec.tlv(b"\xA0", declared) + bytes.fromhex("81008200"))
    return codec.tlv(b"\xBF\x22", bytes.fromhex("81030203018203020500") + iot).hex().upper()


def _record(*versions: tuple[int, int, int], refused: str = "") -> EuiccRecord:
    record = EuiccRecord(eid="89049032123451234512345678901235", created_at="2026-11-20T00:00:00+00:00")
    if versions:
        record.data["euicc_info2_hex"] = _euicc_info2(*versions)
    if refused:
        record.data[REFUSED_TAG_LIST] = {"tags": refused, "at": "2026-11-20T00:00:00+00:00", "operation": 7}
    return record


class DeclaredVersionTests(unittest.TestCase):
    def test_the_versions_are_read_from_iot_specific_info(self) -> None:
        self.assertEqual(declared_iot_versions(bytes.fromhex(_euicc_info2((1, 2, 0)))), ((1, 2, 0),))
        self.assertEqual(declared_iot_versions(bytes.fromhex(_euicc_info2((1, 3, 0), (1, 2, 0)))),
                         ((1, 3, 0), (1, 2, 0)))
        # The members without the 'BF22' wrapper read the same; an entry that is no VersionType is left out.
        _tag, members, _raw = read_single_ber_tlv(bytes.fromhex(_euicc_info2((1, 3, 0))))
        self.assertEqual(declared_iot_versions(members), ((1, 3, 0),))
        odd = codec.tlv(b"\xBF\x22", codec.tlv(b"\xB4", codec.tlv(b"\xA0", bytes.fromhex("040201020403010300"))))
        self.assertEqual(declared_iot_versions(odd), ((1, 3, 0),))
        # A consumer eUICC has no iotSpecificInfo, and an empty list declares nothing.
        self.assertEqual(declared_iot_versions(bytes.fromhex("BF220A81030203018203020500")), ())
        self.assertEqual(declared_iot_versions(bytes.fromhex("BF2204B402A000")), ())

    def test_input_that_does_not_parse_declares_nothing(self) -> None:
        whole = bytes.fromhex(_euicc_info2((1, 2, 0)))
        for data in (b"", b"\xBF", b"\xBF\x22", b"\xBF\x22\x81", whole[:-1], whole[:-3], bytes.fromhex("BF2205B410A005"),
                     bytes.fromhex("BF2281FF00"), None):
            with self.subTest(data=data):
                self.assertEqual(declared_iot_versions(data), ())

    def test_the_record_gives_the_versions_of_its_euicc_info2(self) -> None:
        self.assertEqual(record_iot_versions(_record((1, 2, 0))), ((1, 2, 0),))
        self.assertEqual(record_iot_versions(_record()), ())
        self.assertEqual(record_iot_versions(None), ())
        broken = _record()
        broken.data["euicc_info2_hex"] = "not hex"
        self.assertEqual(record_iot_versions(broken), ())


class RequestTests(unittest.TestCase):
    def test_list_profiles_names_every_member_of_the_cards_version_unless_told_otherwise(self) -> None:
        kind = operation_type("PROFILE_INFO_LIST")
        v1_2 = bytes.fromhex("BF2D185C16" + V1_2_TAGS)
        v1_3 = bytes.fromhex("BF2D1A5C18" + PROFILE_INFO_ALL_TAGS)
        for params in ({}, {"tags": "All"}):
            with self.subTest(params=params):
                # No record, a record without EUICCInfo2 and a card of v1.2 get the v1.2 members.
                self.assertEqual(build_items(kind, normalize_params(kind, params)), v1_2)
                self.assertEqual(build_items(kind, normalize_params(kind, params), record=_record()), v1_2)
                self.assertEqual(build_items(kind, normalize_params(kind, params), record=_record((1, 2, 0))), v1_2)
                self.assertEqual(build_items(kind, normalize_params(kind, params), record=_record((1, 3, 0))), v1_3)
        by_hand = build_items(kind, normalize_params(kind, {"tags": "5A 9F70"}), record=_record((1, 3, 0)))
        self.assertEqual(by_hand, bytes.fromhex("BF2D055C035A9F70"))
        # A tag the card's version lacks still goes when it is asked for by hand.
        self.assertEqual(build_items(kind, normalize_params(kind, {"tags": "5A BF64"}), record=_record((1, 2, 0))),
                         bytes.fromhex("BF2D055C035ABF64"))
        with_iccid = build_items(kind, normalize_params(kind, {"iccid": "8988201234567890123"}))
        # searchCriteria 'A0' (14 octets) and the tagList '5C' (24 octets).
        self.assertTrue(with_iccid.startswith(bytes.fromhex("BF2D26A00C5A0A")))
        self.assertTrue(with_iccid.endswith(bytes.fromhex("5C16" + V1_2_TAGS)))

    def test_a_list_the_card_refused_is_left_out_until_all_asks_for_it(self) -> None:
        kind = operation_type("PROFILE_INFO_LIST")
        refused = _record((1, 2, 0), refused=V1_2_TAGS)
        self.assertEqual(profile_list_tag_list({}, refused), "")
        self.assertEqual(build_items(kind, {}, record=refused), bytes.fromhex("BF2D00"))
        self.assertEqual(build_items(kind, {"iccid": "8988201234567890123"}, record=refused),
                         bytes.fromhex("BF2D0EA00C5A0A988802214365870921F3"))
        # all is the operator's word for the full list: it goes whatever the card said before.
        self.assertEqual(profile_list_tag_list({"tags": TAG_LIST_ALL}, refused), V1_2_TAGS)
        self.assertEqual(profile_list_tag_list({"tags": "5A9F70"}, refused), "5A9F70")
        # A refusal of another list says nothing about the one the eIM chooses now.
        self.assertEqual(profile_list_tag_list({}, _record((1, 2, 0), refused=PROFILE_INFO_ALL_TAGS)), V1_2_TAGS)
        self.assertEqual(profile_list_tag_list({}, _record((1, 3, 0), refused=V1_2_TAGS)), PROFILE_INFO_ALL_TAGS)
        self.assertEqual(profile_list_tag_list({}, _record((1, 3, 0), refused=PROFILE_INFO_ALL_TAGS)), "")
        broken = _record((1, 2, 0))
        broken.data[REFUSED_TAG_LIST] = "5A"
        self.assertEqual(profile_list_tag_list({}, broken), V1_2_TAGS)

    def test_the_tag_list_of_a_served_package_is_read_back(self) -> None:
        def package(items: bytes, kind: str = codec.PACKAGE_PSMO) -> bytes:
            signed = codec.build_euicc_package_signed(
                eim_id="1.3.6.1.4.1.32473.999.10.7", eid="89049032123451234512345678901235", counter_value=1,
                transaction_id=bytes(8), kind=kind, items=items,
            )
            return codec.build_euicc_package_request(signed, bytes(64))

        listing = operation_type("PROFILE_INFO_LIST")
        self.assertEqual(codec.list_profile_info_tag_list(package(build_items(listing, {}))), V1_2_TAGS)
        self.assertEqual(codec.list_profile_info_tag_list(package(bytes.fromhex("BF2D00"))), "")
        with_iccid = build_items(listing, {"iccid": "8988201234567890123", "tags": "5A9F70"})
        self.assertEqual(codec.list_profile_info_tag_list(package(with_iccid)), "5A9F70")
        # No listProfileInfo, two of them, an eCO package: nothing to read.
        self.assertIsNone(codec.list_profile_info_tag_list(package(bytes.fromhex("A600"))))
        self.assertIsNone(codec.list_profile_info_tag_list(package(bytes.fromhex("BF2D00BF2D00"))))
        self.assertIsNone(codec.list_profile_info_tag_list(package(bytes.fromhex("BF2D00"), codec.PACKAGE_ECO)))
        whole = package(bytes.fromhex("BF2D055C035A9F70"))
        for data in (b"", b"\xBF", b"\xBF\x51", b"\xBF\x51\x81", whole[:-70], bytes.fromhex("BF5181FF00"),
                     bytes.fromhex("BF5100"), bytes.fromhex("BF5204A0028700")):
            with self.subTest(data=data):
                self.assertIsNone(codec.list_profile_info_tag_list(data))

    def test_ipa_data_keeps_its_default_and_takes_all(self) -> None:
        kind = operation_type("IPA_EUICC_DATA")
        transaction = bytes(8)
        default = build_unsigned_request(kind, normalize_params(kind, {}), transaction)
        self.assertIn(bytes.fromhex("5C0B" + DEFAULT_IPA_DATA_TAGS.replace(" ", "")), default)
        params = normalize_params(kind, {"tags": "ALL"})
        self.assertEqual(params["tags"], TAG_LIST_ALL)
        every = build_unsigned_request(kind, params, transaction)
        self.assertIn(bytes.fromhex("5C0D" + "".join(SGP32_IPA_DATA_TAGS)), every)

    def test_default_sends_the_bare_request_for_the_cards_own_set(self) -> None:
        kind = operation_type("PROFILE_INFO_LIST")
        params = normalize_params(kind, {"tags": "Default"})
        self.assertEqual(params["tags"], TAG_LIST_DEFAULT)
        self.assertEqual(build_items(kind, params), bytes.fromhex("BF2D00"))
        with_iccid = build_items(kind, normalize_params(kind, {"tags": "default", "iccid": "8988201234567890123"}))
        self.assertEqual(with_iccid, bytes.fromhex("BF2D0EA00C5A0A988802214365870921F3"))
        ipa = operation_type("IPA_EUICC_DATA")
        request = build_unsigned_request(ipa, normalize_params(ipa, {"tags": "default"}), bytes(8))
        self.assertIn(bytes.fromhex("5C0B" + DEFAULT_IPA_DATA_TAGS.replace(" ", "")), request)

    def test_a_word_other_than_all_is_still_refused(self) -> None:
        for name in ("PROFILE_INFO_LIST", "IPA_EUICC_DATA"):
            with self.subTest(operation=name), self.assertRaises(OperationError):
                normalize_params(operation_type(name), {"tags": "everything"})


def _result_frame(profile_info: bytes) -> bytes:
    """A signed eUICC Package Result around one listProfileInfo answer that holds ``profile_info`` (an 'E3')."""
    signed = codec.tlv(b"\x30", codec.tlv(b"\x80", b"1.3.6.1.4.1.32473.999.10.7") + codec.tlv(b"\x81", b"\x01")
                       + codec.tlv(b"\x82", bytes(8)) + codec.tlv(b"\x83", b"\x01")
                       + codec.tlv(b"\x30", codec.tlv(b"\xBF\x2D", codec.tlv(b"\xA0", profile_info))))
    return codec.tlv(b"\xBF\x51", codec.tlv(b"\xA0", signed + codec.tlv(b"\x5F\x37", bytes(64))))


def _full_profile_info_result() -> bytes:
    """A signed-result frame around one ProfileInfo with every §4.4 member, as the schema encodes them, and 9F7F."""
    from Tools.Asn1TlvDecode import context, gsma_schema

    if not gsma_schema.rsp_specification_status().get("available"):
        raise unittest.SkipTest("the compiled RSP schema is not available")
    value = {
        "iccid": bytes.fromhex("988802214365870921F3"),
        "isdpAid": bytes.fromhex("A0000005591010FFFFFFFF8900001100"),
        "profileState": 1, "profileNickname": "Lab nickname", "serviceProviderName": "Example SP",
        "profileName": "Example profile", "iconType": 1, "icon": bytes.fromhex("89504E470D0A1A0A"), "profileClass": 2,
        "notificationConfigurationInfo": [
            {"profileManagementOperation": (bytes.fromhex("F0"), 4), "notificationAddress": "smdp.example.test"}],
        "profileOwner": {"mccMnc": bytes.fromhex("00F110"), "gid1": b"\x01", "gid2": b"\x02"},
        "dpProprietaryData": {"dpOid": "2.999.1"},
        "profilePolicyRules": (bytes.fromhex("40"), 3),
        "serviceSpecificDataStoredInEuicc": [],
        "ecallIndication": False, "fallbackAttribute": True, "fallbackAllowed": True,
        "iotSpecificProfileInfo": {},
    }
    # asn1tools leaves out a member its schema lacks. Without the SGP.32 v1.3 module (a library asset
    # under the ignored docs/ tree, so not in a clean checkout) the compiled ProfileInfo is pySim's SGP.22 v2 one.
    missing = sorted(set(value) - set(context._type_members(gsma_schema.type_tree("ProfileInfo"))))
    if missing:
        raise unittest.SkipTest("the compiled ProfileInfo has no " + ", ".join(missing))
    _tag, members, _raw = read_single_ber_tlv(gsma_schema.encode_type("ProfileInfo", value))
    return _result_frame(codec.tlv(b"\xE3", members + bytes.fromhex("9F7F0101")))


class EveryMemberTests(unittest.TestCase):
    def test_every_member_shows_in_one_reader_or_the_other(self) -> None:
        from SCP11.eim_local.engine_shell import _decoder_reading

        result = _full_profile_info_result()
        profile = codec.decode_euicc_package_result(result).items[0].detail["profiles"][0]
        self.assertEqual((profile["state"], profile["fallback"], profile["fallback_allowed"], profile["nickname"]),
                         ("enabled", True, True, "Lab nickname"))
        rows = [(row.tag, row.name, row.value) for row in traffic.describe_result(result)]
        # A member outside section 4.4 is a row of its own: the schema decode skips it.
        self.assertIn(("9F7F", "member outside SGP.32 v1.3 §4.4", "01"), rows)
        reading = "\n".join(_decoder_reading(result.hex()))
        for name in ("notificationConfigurationInfo", "profileOwner", "dpProprietaryData", "profilePolicyRules",
                     "iconType", "icon", "serviceSpecificDataStoredInEuicc", "iotSpecificProfileInfo",
                     "fallbackAttribute", "fallbackAllowed", "ecallIndication", "smdp.example.test"):
            with self.subTest(member=name):
                self.assertIn(name, reading)

    def test_the_eim_reads_a_member_outside_section_4_4_without_the_schema(self) -> None:
        profile_info = codec.tlv(b"\xE3", codec.tlv(b"\x5A", bytes.fromhex("988802214365870921F3"))
                                 + codec.tlv(b"\x9F\x70", b"\x01") + codec.tlv(b"\x9F\x67", b"\xFF")
                                 + bytes.fromhex("9F7F0101"))
        result = _result_frame(profile_info)
        profile = codec.decode_euicc_package_result(result).items[0].detail["profiles"][0]
        self.assertEqual((profile["state"], profile["fallback_allowed"], profile["other_members"]),
                         ("enabled", True, {"9F7F": "01"}))
        rows = [(row.tag, row.name, row.value) for row in traffic.describe_result(result)]
        self.assertIn(("9F7F", "member outside SGP.32 v1.3 §4.4", "01"), rows)

    def test_the_reading_never_raises_on_bad_input(self) -> None:
        from SCP11.eim_local.engine_shell import _decoder_reading

        for text in ("", "zz", "BF", "BF51", "BF5181FF00", "BF54058003020101", "BF5103A20102"):
            with self.subTest(text=text):
                lines = _decoder_reading(text)
                self.assertGreater(len(lines), 0)


class ServedTests(ServiceTestBase):
    def _poll(self) -> bytes:
        _status, answer = handle_asn1(self.engine, codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))))
        return answer

    def test_the_card_gets_every_member_named_and_op_decode_reads_its_answer(self) -> None:
        self.engine.apply_card_reads(self.card.eid, {"euicc_info2_hex": _euicc_info2((1, 3, 0))})
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0].id
        answer = self._poll()
        self.assertIn(bytes.fromhex("5C18" + PROFILE_INFO_ALL_TAGS), answer)
        _tag, package, _raw = read_single_ber_tlv(answer)
        provide = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + self.card.exchange(package))
        handle_asn1(self.engine, provide)
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)
        from SCP11.eim_local.engine_shell import EngineVerbs

        plain: list[str] = []
        EngineVerbs(SimpleNamespace(session=None), emit=plain.append).cmd_op(str(operation_id))
        self.assertFalse(any("Decoder reading" in line for line in plain))
        lines: list[str] = []
        EngineVerbs(SimpleNamespace(session=None), emit=lines.append).cmd_op(f"{operation_id} --decode")
        self.assertIn("    Decoder reading of the served package:", lines)
        self.assertIn("    Decoder reading of the result:", lines)
        reading = "\n".join(lines[lines.index("    Decoder reading of the result:"):])
        self.assertIn("EuiccPackageResult", reading)
        from Tools.Asn1TlvDecode import gsma_schema

        if gsma_schema.has_type("EuiccPackageResult"):
            self.assertIn("listProfileInfoResult", reading)
            self.assertIn("profileState", reading)
        else:
            # Without the SGP.32 v1.3 module (a library asset) the Decoder shows the BER tree and says so.
            self.assertIn("No compiled type for EuiccPackageResult", reading)

    def test_capabilities_asked_for_by_all_and_not_given_are_dropped(self) -> None:
        record = self.engine.record(self.card.eid)
        record.data["ipa_capabilities_hex"] = "800206C0"
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        self.engine.submit([OperationRequest(eid=self.card.eid, type="IPA_EUICC_DATA", params={"tags": "all"})])
        served = self.engine.next_package(self.card.eid)
        self.assertIn(bytes.fromhex("5C0D" + "".join(SGP32_IPA_DATA_TAGS)), served.package)
        answer = codec.tlv(b"\xBF\x52", codec.tlv(b"\xA0", codec.tlv(b"\x87", bytes.fromhex(served.operation.transaction_id))))
        self.assertIsNone(self.engine.accept_result(self.card.eid, answer).error)
        self.assertNotIn("ipa_capabilities_hex", self.engine.record(self.card.eid).data)


def _check_the_tag_list(card: object, known: frozenset[str] | None) -> None:
    """Make the simulated eUICC of *card* check the tagList of a listProfileInfo PSMO, as a card was seen to.

    It answers incorrectInputValues to a tagList that names a tag outside
    *known*, and to any tagList when *known* is None; the simulator alone
    leaves out what it does not hold and answers ok.
    """
    logic = card.logic
    # The simulator's own method, whatever an earlier call here put in its place.
    lenient = type(logic)._psmo_list_profile_info.__get__(logic)

    def checking(request: bytes) -> bytes:
        _criterion, tag_list = parse_profile_info_list_request(request)
        if tag_list is not None and (known is None or any(tag.hex().upper() not in known for tag in tag_list)):
            return logic._profile_info_list_error(PROFILE_INFO_LIST_INCORRECT_INPUT)
        return lenient(request)

    logic._psmo_list_profile_info = checking


V1_2_KNOWN = frozenset(tag for tag, _name in SGP32_V1_2_PROFILE_INFO)


class RefusedTagListTests(ServiceTestBase):
    """A card that checks the tagList, on every route, through to the profile list on the record."""

    def _list(self, **params: object) -> int:
        request = OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST", params=dict(params))
        return self.engine.submit([request])[0].id

    def _poll(self, *, notify_state_change: bool = False) -> bytes | None:
        """One GetEimPackage; a package goes to the card and its result back. The package, None without one."""
        eid = codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))
        request = eid + (codec.tlv(b"\x80", b"") if notify_state_change else b"")
        _status, answer = handle_asn1(self.engine, codec.tlv(b"\xBF\x4F", request))
        _tag, package, _raw = read_single_ber_tlv(answer)
        if not package.startswith(codec.TAG_EUICC_PACKAGE):
            return None
        handle_asn1(self.engine, codec.tlv(b"\xBF\x50", eid + self.card.exchange(package)))
        return package

    def _refusal(self) -> dict:
        return dict(self.engine.record(self.card.eid).data.get(REFUSED_TAG_LIST) or {})

    def _profiles(self) -> list:
        return list(self.engine.record(self.card.eid).data.get("profiles") or [])

    def test_a_card_of_v1_2_is_asked_for_its_own_members_and_answers(self) -> None:
        _check_the_tag_list(self.card, V1_2_KNOWN)
        for label, info2 in (("no EUICCInfo2 on record", None), ("v1.2 declared", _euicc_info2((1, 2, 0)))):
            with self.subTest(record=label):
                if info2 is not None:
                    self.engine.apply_card_reads(self.card.eid, {"euicc_info2_hex": info2})
                operation_id = self._list()
                package = self._poll()
                self.assertEqual(codec.list_profile_info_tag_list(package), V1_2_TAGS)
                operation = self.engine.operation(operation_id)
                self.assertEqual((operation.state, operation.result["items"]), (STATE_SUCCESS, ["listProfileInfoResult: ok"]))
                self.assertEqual(self.engine.queue(self.card.eid), [])
                self.assertEqual(self._refusal(), {})
                self.assertEqual({profile["state"] for profile in self._profiles()}, {"enabled", "disabled"})
                # A member outside the default set of SGP.32 v1.3 §2.11.1.1 (p.35) came back: the tagList was used.
                self.assertTrue(all("nickname" in profile for profile in self._profiles()))

    def test_the_list_of_v1_3_is_what_such_a_card_refuses(self) -> None:
        # The record says v1.3, the card takes the v1.2 members only: the case the first test keeps from happening.
        _check_the_tag_list(self.card, V1_2_KNOWN)
        self.engine.apply_card_reads(self.card.eid, {"euicc_info2_hex": _euicc_info2((1, 3, 0))})
        operation_id = self._list()
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), PROFILE_INFO_ALL_TAGS)
        operation = self.engine.operation(operation_id)
        self.assertEqual((operation.state, operation.result["items"]),
                         (STATE_ERROR, ["listProfileInfoResult: incorrectInputValues (1)"]))
        self.assertEqual(self._refusal()["tags"], PROFILE_INFO_ALL_TAGS)

    def test_a_refused_list_is_asked_again_without_one_and_remembered(self) -> None:
        _check_the_tag_list(self.card, None)
        first = self._list()
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)
        refused = self.engine.operation(first)
        self.assertEqual(refused.state, STATE_ERROR)
        self.assertNotIn("profiles", self.engine.record(self.card.eid).data)
        (again,) = self.engine.queue(self.card.eid)
        self.assertEqual((again.type, again.state, again.system, again.params, again.recovery_for),
                         ("PROFILE_INFO_LIST", STATE_CREATED, True, {"tags": TAG_LIST_DEFAULT}, None))
        self.assertIn(f"operation {again.id} asks again without one", refused.history[-1]["event"])
        self.assertIn(f"of operation {first}", again.history[0]["event"])
        self.assertEqual(self._refusal(), {"tags": V1_2_TAGS, "at": refused.finished_at, "operation": first})
        # The next poll takes the repeat, and the record has its profile list.
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "")
        self.assertEqual(self.engine.operation(again.id).state, STATE_SUCCESS)
        self.assertEqual(len(self._profiles()), 2)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        # From now on a list without tags goes without a tagList at once: one package, no error.
        second = self._list()
        entry = self.engine.plan([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0]
        self.assertEqual(entry.preview_hex, "BF2D00")
        self.assertTrue(any(f"answered the tagList {V1_2_TAGS} with incorrectInputValues (operation {first})" in warning
                            for warning in entry.warnings))
        view = overview.operation_detail(self.engine, second)
        self.assertEqual((view["package_hex"], view["package_state"]), ("BF2D00", "fixed so far"))
        self.assertTrue(any(warning.startswith("sent without a tagList: ") and "tags=all sends it again" in warning
                            for warning in view["plan_warnings"]))
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "")
        self.assertEqual(self.engine.operation(second).state, STATE_SUCCESS)
        self.assertEqual(self.engine.queue(self.card.eid), [])

    def test_all_sends_the_list_again_and_an_accepted_one_clears_the_entry(self) -> None:
        _check_the_tag_list(self.card, None)
        self._list()
        self._poll()
        self._poll()
        marked = self._refusal()
        # all is face value: the list goes, the refusal stands as the answer, nothing is queued behind it.
        by_word = self._list(tags="all")
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)
        operation = self.engine.operation(by_word)
        self.assertEqual(operation.state, STATE_ERROR)
        self.assertIn("goes without a tagList from now on", operation.history[-1]["event"])
        self.assertEqual(self.engine.queue(self.card.eid), [])
        self.assertEqual((self._refusal()["tags"], self._refusal()["operation"]), (marked["tags"], by_word))
        # The card takes the list after all (new firmware, say): all finds out, and the entry goes.
        _check_the_tag_list(self.card, V1_2_KNOWN)
        accepted = self._list(tags="all")
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)
        self.assertEqual(self.engine.operation(accepted).state, STATE_SUCCESS)
        self.assertEqual(self._refusal(), {})
        self.assertIn("accepted the tagList", self.engine.operation(accepted).history[-1]["event"])
        self._list()
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)

    def test_a_tag_list_given_by_hand_is_neither_repeated_nor_remembered(self) -> None:
        _check_the_tag_list(self.card, None)
        operation_id = self._list(tags="5A 9F70")
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "5A9F70")
        self.assertEqual(self.engine.operation(operation_id).state, STATE_ERROR)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        self.assertEqual(self._refusal(), {})
        # Nor is a list without a tagList that the card refuses: there is nothing left to leave out.
        self.card.logic._psmo_list_profile_info = lambda _request: self.card.logic._profile_info_list_error(
            PROFILE_INFO_LIST_INCORRECT_INPUT)
        bare = self._list(tags="default")
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "")
        self.assertEqual(self.engine.operation(bare).state, STATE_ERROR)
        self.assertEqual((self.engine.queue(self.card.eid), self._refusal()), ([], {}))

    def test_a_bare_request_the_card_refuses_is_neither_repeated_nor_kept(self) -> None:
        _check_the_tag_list(self.card, None)
        self._list()
        self._poll()
        self._poll()
        marked = self._refusal()
        # The eIM's choice is now no tagList, and the card refuses that too: the entry stays as it is,
        # or the next list would name the refused tags again.
        self.card.logic._psmo_list_profile_info = lambda _request: self.card.logic._profile_info_list_error(
            PROFILE_INFO_LIST_INCORRECT_INPUT)
        bare = self._list()
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "")
        self.assertEqual(self.engine.operation(bare).state, STATE_ERROR)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        self.assertEqual(self._refusal(), marked)

    def test_another_error_than_incorrect_input_values_changes_nothing(self) -> None:
        # profileChangeOngoing (11) and undefinedError (127) say nothing about the tagList (SGP.22 v3.1 §5.7.15).
        for code in (11, 127):
            with self.subTest(code=code):
                self.card.logic._psmo_list_profile_info = lambda _request, code=code: (
                    self.card.logic._profile_info_list_error(code))
                operation_id = self._list()
                self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)
                self.assertEqual(self.engine.operation(operation_id).state, STATE_ERROR)
                self.assertEqual((self.engine.queue(self.card.eid), self._refusal()), ([], {}))

    def test_the_search_criterion_goes_into_the_repeat(self) -> None:
        _check_the_tag_list(self.card, None)
        iccid = self.card.state.profiles[0].iccid
        self._list(iccid=iccid)
        self._poll()
        (again,) = self.engine.queue(self.card.eid)
        self.assertEqual(again.params, {"tags": TAG_LIST_DEFAULT, "iccid": iccid})
        self._poll()
        self.assertEqual([profile["iccid"] for profile in self._profiles()], [iccid])
        # Which of the two the card objected to is not known, so nothing is kept: a list of every
        # Profile still names its tags, and only its refusal is remembered.
        self.assertEqual(self._refusal(), {})
        whole = self._list()
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), V1_2_TAGS)
        self.assertEqual(self._refusal()["operation"], whole)

    def test_a_list_the_eim_queues_for_itself_takes_the_same_path(self) -> None:
        # notifyStateChange in GetEimPackage queues a List profiles of the eIM's own (SGP.32 v1.3 §5.14.5).
        _check_the_tag_list(self.card, None)
        self.assertEqual(codec.list_profile_info_tag_list(self._poll(notify_state_change=True)), V1_2_TAGS)
        (again,) = self.engine.queue(self.card.eid)
        self.assertEqual(again.params, {"tags": TAG_LIST_DEFAULT})
        self.assertEqual(codec.list_profile_info_tag_list(self._poll()), "")
        self.assertEqual(len(self._profiles()), 2)
        # The next state change costs one package.
        self.assertEqual(codec.list_profile_info_tag_list(self._poll(notify_state_change=True)), "")
        self.assertEqual(self.engine.queue(self.card.eid), [])

    def test_the_reader_route_runs_the_repeat_in_the_same_delivery(self) -> None:
        _check_the_tag_list(self.card, None)
        operation_id = self._list()
        lines: list[str] = []
        steps = deliver(self.engine, self.card.exchange, self.card.eid, emit=lines.append)
        self.assertEqual(len(steps), 2)
        self.assertEqual(self.engine.operation(operation_id).state, STATE_ERROR)
        self.assertEqual(len(self._profiles()), 2)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        said = "\n".join(lines)
        self.assertIn(f"[+] operation {operation_id}: the eUICC refused the tagList {V1_2_TAGS} (incorrectInputValues); "
                      f"operation {steps[1].operation_id} asks again without one", said)
        # A refused first step with the list delivered after it is no failed batch (batch_outcome counts these).
        self.assertFalse(any(line.startswith(("[!]", "[-]")) for line in lines), said)

    def test_an_imported_result_is_remembered_and_queues_nothing(self) -> None:
        _check_the_tag_list(self.card, None)
        operation_id = self._list()
        package, _steps = self.engine.export(operation_id)
        accepted = self.engine.import_result(operation_id, self.card.exchange(package).hex())
        self.assertEqual(self.engine.operation(operation_id).state, STATE_ERROR)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        self.assertEqual(self._refusal()["tags"], V1_2_TAGS)
        self.assertTrue(any("goes without a tagList from now on" in message for message in accepted.messages))
        # The next one exported has no tagList.
        package, _steps = self.engine.export(self._list())
        self.assertEqual(codec.list_profile_info_tag_list(package), "")

    def test_a_result_read_back_from_the_card_is_remembered_and_queues_nothing(self) -> None:
        _check_the_tag_list(self.card, None)
        operation_id = self._list()
        served = self.engine.next_package(self.card.eid)
        self.card.exchange(served.package, "LoadEuiccPackage, answer dropped")
        deliver(self.engine, self.card.exchange, self.card.eid)
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_ERROR)
        self.assertTrue(any(flag.startswith("recovered-by-") for flag in operation.flags))
        self.assertEqual(self._refusal()["tags"], V1_2_TAGS)
        self.assertEqual(self.engine.queue(self.card.eid), [])
        self.assertFalse(any(entry.type == "PROFILE_INFO_LIST" and entry.system
                             for entry in self.engine.operations(eid=self.card.eid)))

    def test_a_second_copy_of_the_refusal_queues_no_second_repeat(self) -> None:
        _check_the_tag_list(self.card, None)
        self._list()
        eid = codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))
        _status, answer = handle_asn1(self.engine, codec.tlv(b"\xBF\x4F", eid))
        _tag, package, _raw = read_single_ber_tlv(answer)
        result = self.card.exchange(package)
        for _ in range(2):
            handle_asn1(self.engine, codec.tlv(b"\xBF\x50", eid + result))
        self.assertEqual(len(self.engine.queue(self.card.eid)), 1)


class PageTests(unittest.TestCase):
    def test_the_operation_view_folds_the_decoder_reading_beside_the_rows(self) -> None:
        page = (REPO / "gui_frontend" / "src" / "js" / "local-eim-page.js").read_text(encoding="utf-8")
        block = page[page.index("  function lepDecodedBlock("):page.index("  function ccCreateLocalEimPage(")]
        self.assertIn('lepFold("Decoder reading"', block)
        self.assertIn("lepDecodeInto(hooks, reading, hex, context);", block)
        self.assertIn('"The card\'s answer", operation.result_hex,\n          "es10", operation.result_rows', page)
        self.assertIn('operation.package_state === "served" ? "es10" : "tlv"', page)
        naming = (REPO / "guides" / "NAMING_CONVENTIONS.md").read_text(encoding="utf-8")
        self.assertIn("| Decoder reading |", naming)


if __name__ == "__main__":
    unittest.main()
