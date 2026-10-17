# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP03's ES10 helpers decode through the shared SCP11 implementations.

One encoding must not have two readings, so the SCP03 shell reuses
``SCP11.shared`` for BER lengths (ITU-T X.690 (02/2021) clause 8.1.3),
ProfileInfoListResponse framing (SGP.22 v3.1 §5.7.15), the single-bit
NotificationEvent of a NotificationMetadata (§5.7.9), the Enable / Disable /
Delete result enumerations (§5.7.16-§5.7.18 with the SGP.32 v1.3 additions)
and the EF_ICCID / EID BCD codings (ETSI TS 102 221 v18.4 §13.2, SGP.22 v3.1
§3.3.1). These tests pin the reuse and the behaviour it has to preserve.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from SCP03.logic import sgp32_decode
from SCP03.logic.sgp22 import Sgp22Manager
from SCP03.logic.sgp32_decode import (
    certificate_der_from_choice_value,
    decode_compact_installation_result_entry,
    decode_notification_entry,
    decode_notifications_response,
    decode_pending_notification_list,
    NOTIFICATION_EVENT_FLAGS,
)
from SCP11.shared.ber_tlv import encode_ber_length, restore_sequence
from SCP11.shared.gsma_error_codes import (
    SGP22_DELETE_PROFILE_RESULT,
    SGP22_DISABLE_PROFILE_RESULT,
    SGP22_ENABLE_PROFILE_RESULT,
    SGP22_ES10B_PROFILE_STATE_RESULT,
    resolve_sgp22_profile_state_result_code,
)
from SCP11.shared.iccid import decode_bcd_digits, decode_ef_iccid
from SCP11.shared.notification_event import NOTIFICATION_EVENT_ASN1_NAME_BY_BIT
from SCP11.shared.profile_info import split_profile_info_list

# EF_ICCID coding of 89880221436587092143 (the project's 8988 test IIN).
ICCID_EF_HEX = "98882012345678901234"
ISDP_AID_HEX = "A0000005591010FFFFFFFF8900001000"
# SGP.22 v3.1 Annex A.2 test EID body.
TEST_EID_HEX = "89049032123451234512345678901235"


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + encode_ber_length(len(value)) + value


def _profile_info(iccid_hex: str, name: bytes, state: int) -> bytes:
    return _tlv(
        "E3",
        _tlv("5A", bytes.fromhex(iccid_hex))
        + _tlv("4F", bytes.fromhex(ISDP_AID_HEX))
        + _tlv("9F70", bytes([state]))
        + _tlv("90", name),
    )


class _CaptureManager(Sgp22Manager):
    """Record the STORE DATA payloads instead of reaching a card."""

    def __init__(self, response: bytes) -> None:
        super().__init__(transport=None)
        self.sent: list[str] = []
        self.response = response

    def _select_isd_r(self) -> None:
        return None

    def _send_store_data_with_retry_ladder(self, payload, *args, **kwargs):
        self.sent.append(str(payload).upper())
        return self.response, 0x90, 0x00


class BerLengthReuseTests(unittest.TestCase):
    """The SCP03 length encoder is the shared one (X.690 clause 8.1.3)."""

    def test_lengths_match_the_shared_encoder(self) -> None:
        for length in (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000):
            with self.subTest(length=length):
                self.assertEqual(
                    sgp32_decode._encode_length(length), encode_ber_length(length)
                )

    def test_certificate_header_is_restored_by_the_shared_helper(self) -> None:
        contents = (
            _tlv("30", _tlv("02", b"\x01"))
            + _tlv("30", _tlv("06", bytes.fromhex("2A0304")))
            + _tlv("03", bytes.fromhex("00FF"))
        )
        self.assertEqual(
            certificate_der_from_choice_value(contents), restore_sequence(contents)
        )

    def test_complete_certificate_passes_through(self) -> None:
        contents = (
            _tlv("30", _tlv("02", b"\x01"))
            + _tlv("30", _tlv("06", bytes.fromhex("2A0304")))
            + _tlv("03", bytes.fromhex("00FF"))
        )
        certificate = restore_sequence(contents)
        self.assertEqual(certificate_der_from_choice_value(certificate), certificate)


class ProfileInfoListFramingTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.15: 'BF2D' -> profileInfoListOk 'A0' -> 'E3' items."""

    def _manager(self) -> Sgp22Manager:
        return Sgp22Manager.__new__(Sgp22Manager)

    def test_profiles_come_from_the_shared_splitter(self) -> None:
        first = _profile_info(ICCID_EF_HEX, b"first", 0x01)
        second = _profile_info("98882012345678901299", b"second", 0x00)
        response = _tlv("BF2D", _tlv("A0", first + second))

        nodes = self._manager()._profile_nodes_from_data(response)

        profiles, error_code = split_profile_info_list(response)
        self.assertIsNone(error_code)
        self.assertEqual(nodes, list(profiles))
        self.assertEqual(len(nodes), 2)

    def test_length_octet_that_reads_as_e3_is_not_a_second_profile(self) -> None:
        # A ProfileInfo 0xE3 octets long makes its own length octet 'E3'; the
        # framed walk yields one Profile where a byte scan could see two.
        body = _tlv("5A", bytes.fromhex(ICCID_EF_HEX)) + _tlv("90", b"n" * 0xD4)
        self.assertEqual(len(body), 0xE3)
        response = _tlv("BF2D", _tlv("A0", _tlv("E3", body)))

        nodes = self._manager()._profile_nodes_from_data(response)

        self.assertEqual(nodes, [body])

    def test_profile_with_one_member_is_not_dropped(self) -> None:
        # SGP.22 v3.1 §5.7.15 makes every ProfileInfo member OPTIONAL, so a
        # Profile carrying only its nickname is well formed. The tag-matching
        # heuristic wants two recognised members and used to drop it.
        body = _tlv("90", b"only-a-nickname")
        response = _tlv("BF2D", _tlv("A0", _tlv("E3", body)))
        manager = self._manager()

        self.assertEqual(manager._profile_nodes_from_data(response), [body])
        self.assertEqual(
            manager._collect_profile_nodes(manager._safe_parse_tlv(response)), []
        )

    def test_non_conformant_response_still_falls_back_to_the_heuristic(self) -> None:
        # No 'BF2D' and no 'A0' wrapper: the raw-byte scan is what reads it.
        bare = _profile_info(ICCID_EF_HEX, b"bare", 0x01)
        wrapped = _tlv("BF3C", bare)

        nodes = self._manager()._profile_nodes_from_data(wrapped)

        self.assertEqual(len(nodes), 1)

    def test_profile_rows_survive_the_framed_walk(self) -> None:
        response = _tlv("BF2D", _tlv("A0", _profile_info(ICCID_EF_HEX, b"row", 0x01)))

        rows = self._manager()._profile_list_to_dicts(response)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["iccid"], "89880221436587092143")
        self.assertEqual(rows[0]["state"], "ENABLED")
        self.assertEqual(rows[0]["name"], "row")


class NotificationOperationTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.9: "Only one bit SHALL be set to 1"."""

    def test_bit_names_are_the_shared_asn1_names(self) -> None:
        self.assertEqual(NOTIFICATION_EVENT_FLAGS, NOTIFICATION_EVENT_ASN1_NAME_BY_BIT)

    def test_each_single_bit_value_is_named(self) -> None:
        for bit_index, name in NOTIFICATION_EVENT_ASN1_NAME_BY_BIT.items():
            unused_bits = 7 - bit_index
            contents = bytes([unused_bits, 0x80 >> bit_index])
            with self.subTest(bit=bit_index):
                entry = decode_notification_entry(_tlv("81", contents))
                self.assertEqual(
                    entry["operation"], f"{contents.hex().upper()} (set: {name})"
                )
                self.assertNotIn("notificationParseError", entry)

    def test_two_bits_are_refused_and_reported(self) -> None:
        entry = decode_notification_entry(_tlv("81", bytes.fromhex("04C0")))
        self.assertEqual(entry["operation"], "04C0")
        self.assertIn("one event bit", entry["notificationParseError"])

    def test_no_bit_set_is_refused_and_reported(self) -> None:
        entry = decode_notification_entry(_tlv("81", bytes.fromhex("0800")))
        self.assertEqual(entry["operation"], "0800")
        self.assertIn("notificationParseError", entry)

    def test_non_zero_padding_bits_are_refused(self) -> None:
        entry = decode_notification_entry(_tlv("81", bytes.fromhex("0781")))
        self.assertEqual(entry["operation"], "0781")
        self.assertIn("notificationParseError", entry)


class PendingNotificationAlternativeTests(unittest.TestCase):
    """SGP.32 v1.3 PendingNotification CHOICE: 'BF37', '30', 'A0', 'A1'."""

    def _metadata(self, seq_number: int) -> bytes:
        return _tlv(
            "BF2F",
            _tlv("80", bytes([seq_number]))
            + _tlv("81", bytes.fromhex("0780"))
            + _tlv("0C", b"notify.example.test"),
        )

    def test_profile_installation_result_alternative_is_summarised(self) -> None:
        # ProfileInstallationResult ::= [55] SEQUENCE, holding
        # ProfileInstallationResultData [39] ('BF27') with the metadata.
        item = _tlv("BF37", _tlv("BF27", self._metadata(1)) + _tlv("5F37", b"\x01\x02"))
        decoded = decode_notifications_response(_tlv("BF2B", _tlv("A0", item)))
        self.assertEqual([e["seqNumber"] for e in decoded["notifications"]], ["1"])

    def test_other_signed_notification_alternative_keeps_the_sequence_tag(self) -> None:
        # OtherSignedNotification ::= SEQUENCE { tbsOtherNotification
        # NotificationMetadata, euiccNotificationSignature EuiccSign, ... }
        # (SGP.22 v3.1 §5.7.10). None of its members is written as a
        # TaggedType, so whether ITU-T X.680 (02/2021) clause 25.2 counts the
        # referenced EuiccSign tag is compiler dependent; the member tags here
        # are the ones pySim's compiled module produces ('BF2F', '5F37').
        item = _tlv("30", self._metadata(2) + _tlv("5F37", b"\x01\x02"))
        decoded = decode_notifications_response(_tlv("BF2B", _tlv("A0", item)))
        self.assertEqual([e["seqNumber"] for e in decoded["notifications"]], ["2"])

    def test_compact_other_signed_notification_alternative_is_summarised(self) -> None:
        item = _tlv(
            "A1",
            _tlv("5A", bytes.fromhex(TEST_EID_HEX))
            + self._metadata(3)
            + _tlv("5F37", b"\x01\x02"),
        )
        decoded = decode_notifications_response(_tlv("BF2B", _tlv("A0", item)))
        self.assertEqual([e["seqNumber"] for e in decoded["notifications"]], ["3"])

    def test_compact_installation_result_alternative_is_summarised(self) -> None:
        # CompactProfileInstallationResultData tags transactionId [0] and
        # compactFinalResult [2], so seqNumber keeps the INTEGER tag '02'.
        data = (
            _tlv("80", bytes.fromhex("A1B2C3"))
            + _tlv("02", b"\x04")
            + _tlv("A2", _tlv("30", _tlv("4F", bytes.fromhex("0102"))))
        )
        item = _tlv("A0", _tlv("A0", data) + _tlv("5F37", b"\x01\x02"))

        decoded = decode_notifications_response(_tlv("BF2B", _tlv("A0", item)))

        self.assertEqual(len(decoded["notifications"]), 1)
        entry = decoded["notifications"][0]
        self.assertEqual(entry["notificationType"], "compactProfileInstallationResult")
        self.assertEqual(entry["seqNumber"], "4")
        self.assertEqual(entry["transactionId"], "A1B2C3")

    def test_bare_metadata_items_still_read(self) -> None:
        # SGP.22 v3.1 §5.7.9 ListNotificationResponse is a SEQUENCE OF
        # NotificationMetadata with no PendingNotification wrapper.
        entries = decode_pending_notification_list(
            self._metadata(5) + self._metadata(6)
        )
        self.assertEqual([e["seqNumber"] for e in entries], ["5", "6"])

    def test_compact_entry_without_data_still_names_the_alternative(self) -> None:
        entry = decode_compact_installation_result_entry(b"")
        self.assertEqual(entry, {"notificationType": "compactProfileInstallationResult"})


class ProfileStateResultTableTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.16-§5.7.18 plus the SGP.32 v1.3 result INTEGERs."""

    def test_enable_enumeration(self) -> None:
        self.assertEqual(
            SGP22_ENABLE_PROFILE_RESULT,
            {
                0: "ok",
                1: "iccidOrAidNotFound",
                2: "profileNotInDisabledState",
                3: "disallowedByPolicy",
                4: "wrongProfileReenabling",
                5: "catBusy",
                6: "disallowedByEnterpriseRule",
                7: "commandError",
                9: "disallowedForRpm",
                10: "noEsimPortAvailable",
                20: "rollbackNotAvailable",
                127: "undefinedError",
            },
        )

    def test_disable_enumeration(self) -> None:
        self.assertEqual(
            SGP22_DISABLE_PROFILE_RESULT,
            {
                0: "ok",
                1: "iccidOrAidNotFound",
                2: "profileNotInEnabledState",
                3: "disallowedByPolicy",
                5: "catBusy",
                6: "disallowedByEnterpriseRule",
                7: "commandError",
                9: "disallowedForRpm",
                127: "undefinedError",
            },
        )

    def test_delete_enumeration(self) -> None:
        self.assertEqual(
            SGP22_DELETE_PROFILE_RESULT,
            {
                0: "ok",
                1: "iccidOrAidNotFound",
                2: "profileNotInDisabledState",
                3: "disallowedByPolicy",
                4: "disallowedInTestMode",
                7: "commandError",
                20: "rollbackNotAvailable",
                21: "returnFallbackProfile",
                127: "undefinedError",
            },
        )

    def test_value_two_differs_between_enable_and_disable(self) -> None:
        self.assertEqual(SGP22_ENABLE_PROFILE_RESULT[2], "profileNotInDisabledState")
        self.assertEqual(SGP22_DISABLE_PROFILE_RESULT[2], "profileNotInEnabledState")
        self.assertEqual(SGP22_DELETE_PROFILE_RESULT[2], "profileNotInDisabledState")

    def test_value_four_differs_between_enable_and_delete(self) -> None:
        self.assertEqual(SGP22_ENABLE_PROFILE_RESULT[4], "wrongProfileReenabling")
        self.assertEqual(SGP22_DELETE_PROFILE_RESULT[4], "disallowedInTestMode")
        self.assertNotIn(4, SGP22_DISABLE_PROFILE_RESULT)

    def test_manager_tables_are_the_shared_ones(self) -> None:
        self.assertIs(
            Sgp22Manager._profile_result_names(Sgp22Manager.TAG_ENABLE_PROFILE),
            SGP22_ENABLE_PROFILE_RESULT,
        )
        self.assertIs(
            Sgp22Manager._profile_result_names(Sgp22Manager.TAG_DISABLE_PROFILE),
            SGP22_DISABLE_PROFILE_RESULT,
        )
        self.assertIs(
            Sgp22Manager._profile_result_names(Sgp22Manager.TAG_DELETE_PROFILE),
            SGP22_DELETE_PROFILE_RESULT,
        )

    def test_shell_names_the_function_specific_result(self) -> None:
        for tag_hex, code, expected in (
            ("BF31", 2, "profileNotInDisabledState"),
            ("BF32", 2, "profileNotInEnabledState"),
            ("BF33", 4, "disallowedInTestMode"),
        ):
            with self.subTest(tag=tag_hex):
                manager = _CaptureManager(_tlv(tag_hex, _tlv("80", bytes([code]))))
                manager.profile_cache["BY-AID"] = (manager.TAG_AID, ISDP_AID_HEX)
                action = {
                    "BF31": manager.enable_profile,
                    "BF32": manager.disable_profile,
                    "BF33": manager.delete_profile,
                }[tag_hex]
                with redirect_stdout(io.StringIO()) as output:
                    self.assertFalse(action("BY-AID"))
                self.assertIn(expected, output.getvalue())


class MergedProfileStateTableTests(unittest.TestCase):
    """The union table names both readings of the two ambiguous values."""

    def test_ambiguous_values_name_both_functions(self) -> None:
        self.assertEqual(
            SGP22_ES10B_PROFILE_STATE_RESULT[2],
            "profileNotInDisabledState/profileNotInEnabledState",
        )
        self.assertEqual(
            SGP22_ES10B_PROFILE_STATE_RESULT[4],
            "wrongProfileReenabling/disallowedInTestMode",
        )

    def test_union_covers_every_per_function_code(self) -> None:
        for table in (
            SGP22_ENABLE_PROFILE_RESULT,
            SGP22_DISABLE_PROFILE_RESULT,
            SGP22_DELETE_PROFILE_RESULT,
        ):
            for code in table:
                self.assertIn(code, SGP22_ES10B_PROFILE_STATE_RESULT)

    def test_each_per_function_spelling_resolves_back_to_its_code(self) -> None:
        for name, code in (
            ("profileNotInDisabledState", 2),
            ("profileNotInEnabledState", 2),
            ("wrongProfileReenabling", 4),
            ("disallowedInTestMode", 4),
            ("catBusy", 5),
            ("returnFallbackProfile", 21),
        ):
            with self.subTest(name=name):
                self.assertEqual(resolve_sgp22_profile_state_result_code(name), code)

    def test_unknown_name_still_returns_the_default(self) -> None:
        self.assertEqual(
            resolve_sgp22_profile_state_result_code("notAResultName", 127), 127
        )


class IccidAndEidCodingTests(unittest.TestCase):
    """TS 102 221 v18.4 §13.2 swaps nibbles; SGP.22 v3.1 §3.3.1 does not."""

    def _manager(self) -> Sgp22Manager:
        return Sgp22Manager.__new__(Sgp22Manager)

    def test_iccid_matches_the_shared_ef_iccid_decoder(self) -> None:
        self.assertEqual(
            self._manager()._swap_nibbles(ICCID_EF_HEX),
            decode_ef_iccid(bytes.fromhex(ICCID_EF_HEX)),
        )

    def test_single_filler_nibble_is_dropped(self) -> None:
        self.assertEqual(self._manager()._swap_nibbles("98F7"), "897")

    def test_two_filler_nibbles_are_dropped(self) -> None:
        # An eighteen-digit ICCID pads the last octet with two 'F' nibbles,
        # which TS 102 221 v18.4 §13.2 allows.
        self.assertEqual(
            self._manager()._swap_nibbles("988820123456789012FF"),
            "898802214365870921",
        )

    def test_filler_before_the_end_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._manager()._swap_nibbles("6F12")

    def test_non_bcd_nibble_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._manager()._swap_nibbles("9A")

    def test_odd_length_input_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._manager()._swap_nibbles("988")

    def test_straight_bcd_keeps_the_shared_reading(self) -> None:
        manager = self._manager()
        self.assertEqual(
            manager._decode_bcd_digits(bytes.fromhex("89049032")),
            decode_bcd_digits(bytes.fromhex("89049032")),
        )
        self.assertEqual(manager._decode_bcd_digits(bytes.fromhex("98765F")), "98765")
        self.assertEqual(manager._decode_bcd_digits(bytes.fromhex("89A4")), "")
        self.assertEqual(manager._decode_bcd_digits(b""), "")

    def test_eid_is_not_nibble_swapped(self) -> None:
        response = _tlv("BF3E", _tlv("5A", bytes.fromhex(TEST_EID_HEX)))
        self.assertEqual(self._manager()._extract_eid_hex(response), TEST_EID_HEX)


class DeadEimBranchTests(unittest.TestCase):
    """'E1' is GP Individual Key Information (GPC v2.3.1 §11.3.3.1.2)."""

    def _manager(self) -> Sgp22Manager:
        return Sgp22Manager.__new__(Sgp22Manager)

    def test_e1_children_are_not_read_as_eim_configuration(self) -> None:
        manager = self._manager()
        self.assertEqual(manager._decode_value(0x82, b"\x02", 0xE1), "02")
        self.assertEqual(manager._decode_value(0x83, b"\x05", 0xE1), "05")
        self.assertEqual(manager._decode_value(0x89, b"", 0xE1), "")

    def test_e1_is_named_after_the_globalplatform_template(self) -> None:
        self.assertEqual(
            self._manager()._resolve_tag_name(0xE1, None), "Individual Key Info"
        )


class Sgp02ProbeTests(unittest.TestCase):
    """SGP.02 v4.2 §2.2.2 / §2.2.3 and GPC v2.3.1 §11.3.2.1."""

    class _Transport:
        """Answer every APDU '9000' with no data and record what was sent."""

        def __init__(self) -> None:
            self.sent: list[str] = []

        def transmit(self, apdu, silent=False):
            self.sent.append(str(apdu).upper())
            return b"", 0x90, 0x00

    def _probe(self) -> list[str]:
        transport = self._Transport()
        Sgp22Manager(transport)._run_sgp02_domain_probe("basic", False)
        return transport.sent

    def test_probe_selects_the_specified_aids(self) -> None:
        sent = self._probe()
        # SGP.02 v4.2 §2.2.3 ECASD and ISD-R application AIDs.
        self.assertIn("00A4040010A0000005591010FFFFFFFF8900000200", sent)
        self.assertIn("00A4040010A0000005591010FFFFFFFF8900000100", sent)

    def test_eid_is_read_with_a_get_data_for_tag_5a(self) -> None:
        # SGP.02 v4.2 §2.2.2: select the ECASD, then GET DATA tag '5A'.
        sent = self._probe()
        select_index = sent.index("00A4040010A0000005591010FFFFFFFF8900000200")
        self.assertIn("00CA005A00", sent[select_index:])

    def test_security_domain_objects_follow_globalplatform(self) -> None:
        # GPC v2.3.1 §11.3.2.1: '42', '45', '66' and 'E0' are the objects a
        # Security Domain has to answer; '67' is Card Capability Information.
        sent = self._probe()
        for apdu in ("00CA004200", "00CA004500", "00CA006600", "00CA006700"):
            self.assertIn(apdu, sent)
        self.assertIn("00CA00E000", sent)

    def test_issuer_number_is_read_from_tag_42(self) -> None:
        manager = Sgp22Manager.__new__(Sgp22Manager)
        result_entry = {"raw_hex": "4203898802"}
        self.assertEqual(
            manager._decode_ecasd_issuer_number_from_result(result_entry), "898802"
        )

    def test_odd_digit_count_keeps_its_trailing_filler_nibble(self) -> None:
        # GPC v2.3.1 §7.4.1.1 carries an ISO 7812 identifier of variable
        # length, so an odd digit count ends in one 'F' filler nibble.
        manager = Sgp22Manager.__new__(Sgp22Manager)
        self.assertEqual(
            manager._decode_ecasd_issuer_number_from_result({"raw_hex": "42048988021F"}),
            "8988021",
        )

    def test_bare_issuer_number_without_the_tag_is_still_read(self) -> None:
        manager = Sgp22Manager.__new__(Sgp22Manager)
        self.assertEqual(
            manager._decode_ecasd_issuer_number_from_result({"raw_hex": "898802"}),
            "898802",
        )

    def test_missing_result_yields_no_number(self) -> None:
        manager = Sgp22Manager.__new__(Sgp22Manager)
        self.assertEqual(manager._decode_ecasd_issuer_number_from_result({}), "")
        self.assertEqual(manager._decode_ecasd_issuer_number_from_result(None), "")


if __name__ == "__main__":
    unittest.main()
