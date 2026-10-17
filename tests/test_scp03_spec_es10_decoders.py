# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10 request shapes and response decoders pinned to the library ASN.1.

Vectors follow SGP.22 v3.1 §5.7.16-§5.7.18 (Enable/Disable/DeleteProfile),
§5.7.20 (GetEID), §5.7.8 (EUICCInfo2 CertificationDataObject), §2.9.2.1 with
3GPP TS 24.008 v19.5 §10.5.1.3 (RAT mccMnc), and SGP.32 v1.3 §5.9.11
(euiccPackageResultList) and §5.9.18 (EimConfigurationData key material).
Encodings were cross-checked against the SGP.22 v2 module compiled by pySim.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
from SCP03.logic.sgp22 import Sgp22Manager
from SCP03.logic.sgp32_decode import (
    decode_eim_configuration_entries,
    decode_mcc_mnc,
    decode_notifications_response,
    decode_public_key_data_choice,
    decode_rat_rules,
    split_euicc_package_results,
)

# EF ICCID coding of 89880221436587092143 (the project's 8988 test IIN).
ICCID_EF_HEX = "98882012345678901234"
ISDP_AID_HEX = "A0000005591010FFFFFFFF8900001000"
# SGP.22 v3.1 Annex A.2 test EID body.
TEST_EID_HEX = "89049032123451234512345678901235"


def _tlv(tag_hex: str, value: bytes) -> bytes:
    if len(value) < 0x80:
        length = bytes([len(value)])
    else:
        length = bytes([0x81, len(value)])
    return bytes.fromhex(tag_hex) + length + value


def _certificate_contents() -> bytes:
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
    # SEQUENCE, signature BIT STRING } (RFC 5280 section 4.1), reduced to the
    # shape the decoder inspects.
    return (
        _tlv("30", _tlv("02", b"\x01"))
        + _tlv("30", _tlv("06", bytes.fromhex("2A0304")))
        + _tlv("03", bytes.fromhex("00FF"))
    )


def _spki_contents() -> bytes:
    return _tlv("30", _tlv("06", bytes.fromhex("2A0304"))) + _tlv(
        "03", bytes.fromhex("0004")
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


class ProfileStateRequestShapeTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.16-§5.7.18 request encodings."""

    def _manager(self, tag_hex: str, result: int = 0) -> _CaptureManager:
        manager = _CaptureManager(_tlv(tag_hex, _tlv("80", bytes([result]))))
        manager.profile_cache["BY-ICCID"] = (manager.TAG_ICCID, ICCID_EF_HEX)
        manager.profile_cache["BY-AID"] = (manager.TAG_AID, ISDP_AID_HEX)
        return manager

    def test_delete_profile_by_iccid_is_a_bare_choice(self) -> None:
        manager = self._manager("BF33")
        with redirect_stdout(io.StringIO()):
            self.assertTrue(manager.delete_profile("BY-ICCID"))
        # DeleteProfileRequest ::= [51] CHOICE { isdpAid '4F', iccid '5A' }:
        # no [0] wrapper and no refreshFlag.
        self.assertEqual(manager.sent, ["BF330C5A0A" + ICCID_EF_HEX])

    def test_delete_profile_by_aid_is_a_bare_choice(self) -> None:
        manager = self._manager("BF33")
        with redirect_stdout(io.StringIO()):
            self.assertTrue(manager.delete_profile("BY-AID"))
        self.assertEqual(manager.sent, ["BF33124F10" + ISDP_AID_HEX])

    def test_enable_profile_keeps_explicit_choice_wrapper_and_refresh_flag(self) -> None:
        manager = self._manager("BF31")
        with redirect_stdout(io.StringIO()):
            self.assertTrue(manager.enable_profile("BY-ICCID"))
        self.assertEqual(manager.sent, ["BF3111A00C5A0A" + ICCID_EF_HEX + "810100"])

    def test_disable_profile_keeps_explicit_choice_wrapper_and_refresh_flag(self) -> None:
        manager = self._manager("BF32")
        with redirect_stdout(io.StringIO()):
            self.assertTrue(manager.disable_profile("BY-AID"))
        self.assertEqual(manager.sent, ["BF3217A0124F10" + ISDP_AID_HEX + "810100"])

    def _error_text(self, tag_hex: str, result: int, action) -> str:
        manager = self._manager(tag_hex, result)
        with redirect_stdout(io.StringIO()) as output:
            self.assertFalse(action(manager))
        return output.getvalue()

    def test_enable_result_names_follow_the_response_enumeration(self) -> None:
        text = self._error_text("BF31", 4, lambda m: m.enable_profile("BY-AID"))
        self.assertIn("wrongProfileReenabling", text)
        text = self._error_text("BF31", 20, lambda m: m.enable_profile("BY-AID"))
        self.assertIn("rollbackNotAvailable", text)

    def test_disable_result_names_follow_the_response_enumeration(self) -> None:
        text = self._error_text("BF32", 2, lambda m: m.disable_profile("BY-AID"))
        self.assertIn("profileNotInEnabledState", text)

    def test_delete_result_names_follow_the_response_enumeration(self) -> None:
        text = self._error_text("BF33", 4, lambda m: m.delete_profile("BY-AID"))
        self.assertIn("disallowedInTestMode", text)
        text = self._error_text("BF33", 21, lambda m: m.delete_profile("BY-AID"))
        self.assertIn("returnFallbackProfile", text)


class _ScriptedEidManager(_CaptureManager):
    """Answer each GetEID form from a table of (data, sw1, sw2)."""

    def __init__(self, answers: dict[str, tuple[bytes, int, int]]) -> None:
        super().__init__(b"")
        self.answers = answers

    def _send_store_data_with_retry_ladder(self, payload, *args, **kwargs):
        self.sent.append(str(payload).upper())
        return self.answers[str(payload).upper()]


# A BF3E answer that carries no '5A', returned under a success status word.
NO_EID_BODY = bytes.fromhex("BF3E0380017F")


class GetEuiccDataRequestTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.20: tagList '5C' with value '5A' is mandatory."""

    def test_spec_request_is_sent_first(self) -> None:
        manager = _CaptureManager(_tlv("BF3E", _tlv("5A", bytes.fromhex(TEST_EID_HEX))))
        data, sw1, _sw2 = manager._retrieve_eid_response()
        self.assertEqual(manager.sent, ["BF3E035C015A"])
        self.assertEqual(sw1, 0x90)
        self.assertEqual(manager._extract_eid_hex(data), TEST_EID_HEX)

    def test_answer_without_eid_falls_back_to_the_bare_request(self) -> None:
        manager = _ScriptedEidManager(
            {
                "BF3E035C015A": (NO_EID_BODY, 0x90, 0x00),
                "BF3E00": (_tlv("BF3E", _tlv("5A", bytes.fromhex(TEST_EID_HEX))), 0x90, 0x00),
            }
        )
        data, sw1, _sw2 = manager._retrieve_eid_response()
        self.assertEqual(manager.sent, ["BF3E035C015A", "BF3E00"])
        self.assertEqual(sw1, 0x90)
        self.assertEqual(manager._extract_eid_hex(data), TEST_EID_HEX)

    def test_answer_without_eid_is_never_printed_as_the_eid(self) -> None:
        manager = _ScriptedEidManager(
            {
                "BF3E035C015A": (NO_EID_BODY, 0x90, 0x00),
                "BF3E00": (NO_EID_BODY, 0x90, 0x00),
            }
        )
        output = io.StringIO()
        with redirect_stdout(output):
            manager.get_eid()
        self.assertIn("No EID in response: BF3E0380017F", output.getvalue())
        self.assertNotIn("--- EID ---", output.getvalue())

    def test_only_a_sixteen_octet_eid_is_extracted(self) -> None:
        manager = _CaptureManager(b"")
        eid = bytes.fromhex(TEST_EID_HEX)
        cases = {
            _tlv("BF3E", _tlv("5A", eid)): TEST_EID_HEX,
            # GET DATA '5A' on the ECASD (SGP.02 v4.2 §2.2.2), with and
            # without its TLV header.
            _tlv("5A", eid): TEST_EID_HEX,
            eid: TEST_EID_HEX,
            NO_EID_BODY: "",
            _tlv("BF3E", _tlv("5A", eid[:15])): "",
            _tlv("5A", eid + b"\x00"): "",
            bytes.fromhex("AA" * 16): "",
            bytes.fromhex("11" * 16): "",
            b"": "",
            bytes.fromhex("BF"): "",
            bytes.fromhex("BF3E"): "",
            bytes.fromhex("BF3E105A10"): "",
        }
        for data, expected in cases.items():
            with self.subTest(data=data.hex().upper()):
                self.assertEqual(manager._extract_eid_hex(data), expected)


class CertificationDataObjectTests(unittest.TestCase):
    """SGP.22 v3.1 §5.7.8: certificationDataObject [12] carries automatic tags."""

    def _info2(self, cdo_value: bytes) -> bytes:
        body = _tlv("81", bytes.fromhex("020300")) + _tlv("AC", cdo_value)
        return _tlv("BF22", body)

    def test_platform_label_and_discovery_url_use_tags_80_and_81(self) -> None:
        cdo = _tlv("80", b"lbl") + _tlv("81", b"https://dloa.example.test")
        lines = build_euicc_info2_detail_lines(self._info2(cdo))
        self.assertIn((1, "Platform Label", '"lbl"'), lines)
        self.assertIn((1, "Discovery Base URL", '"https://dloa.example.test"'), lines)

    def test_universal_utf8string_children_stay_readable_by_position(self) -> None:
        cdo = _tlv("0C", b"lbl") + _tlv("0C", b"https://dloa.example.test")
        lines = build_euicc_info2_detail_lines(self._info2(cdo))
        self.assertIn((1, "Platform Label", '"lbl"'), lines)
        self.assertIn((1, "Discovery Base URL", '"https://dloa.example.test"'), lines)


class MccMncTests(unittest.TestCase):
    """3GPP TS 24.008 v19.5 §10.5.1.3 PLMN coding with SGP.22 'E' wildcards."""

    def test_two_digit_mnc_uses_filler_in_mnc_digit_3(self) -> None:
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("00F110")), "00101")

    def test_three_digit_mnc_orders_digits_per_figure_10_5_3(self) -> None:
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("001100")), "001001")

    def test_full_wildcard(self) -> None:
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("EEEEEE")), "EEEEEE")

    def test_partial_wildcard_digit_is_kept(self) -> None:
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("00F1E0")), "0010E")

    def test_other_non_decimal_nibbles_return_hex(self) -> None:
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("00A110")), "00A110")
        self.assertEqual(decode_mcc_mnc(bytes.fromhex("0001")), "0001")

    def test_rat_rule_operator_uses_plmn_coding(self) -> None:
        rule = _tlv(
            "30",
            _tlv("80", bytes.fromhex("0560"))
            + _tlv("A1", _tlv("30", _tlv("80", bytes.fromhex("00F110"))))
            + _tlv("82", bytes.fromhex("0780")),
        )
        rules = decode_rat_rules(_tlv("BF43", _tlv("A0", rule)))
        self.assertEqual(rules[0]["allowedOperators"][0]["mccMnc"], "00101")


class EuiccPackageResultListTests(unittest.TestCase):
    """SGP.32 v1.3 §5.9.11: euiccPackageResultList holds 'BF51' items."""

    def test_each_package_result_is_returned_as_a_complete_tlv(self) -> None:
        first = _tlv("BF51", bytes.fromhex("010203"))
        second = _tlv("BF51", bytes.fromhex("AABB"))
        response = _tlv("BF2B", _tlv("A2", first + second))
        decoded = decode_notifications_response(response)
        self.assertEqual(decoded["package_results"], [first, second])
        self.assertEqual(split_euicc_package_results(first + second), [first, second])

    def test_list_without_package_results_falls_back_to_raw_value(self) -> None:
        for list_value in (bytes.fromhex("040102"), bytes.fromhex("0102")):
            response = _tlv("BF2B", _tlv("A2", list_value))
            decoded = decode_notifications_response(response)
            self.assertEqual(decoded["package_results"], [list_value])


class EimKeyMaterialTests(unittest.TestCase):
    """SGP.32 v1.3 §5.9.18: [5]/[6] CHOICE alternatives are IMPLICIT [0]/[1]."""

    def test_certificate_alternative_restores_the_sequence_header(self) -> None:
        contents = _certificate_contents()
        kind, der = decode_public_key_data_choice(_tlv("A1", contents))
        self.assertEqual(kind, "certificate")
        self.assertEqual(der, _tlv("30", contents))

    def test_public_key_alternative_restores_the_sequence_header(self) -> None:
        contents = _spki_contents()
        kind, der = decode_public_key_data_choice(_tlv("A0", contents))
        self.assertEqual(kind, "publicKey")
        self.assertEqual(der, _tlv("30", contents))

    def test_alternative_wrapping_a_complete_der_passes_through(self) -> None:
        certificate = _tlv("30", _certificate_contents())
        kind, der = decode_public_key_data_choice(_tlv("A1", certificate))
        self.assertEqual(kind, "certificate")
        self.assertEqual(der, certificate)

    def test_bare_sequence_passes_through_without_a_kind(self) -> None:
        certificate = _tlv("30", _certificate_contents())
        kind, der = decode_public_key_data_choice(certificate)
        self.assertEqual(kind, "")
        self.assertEqual(der, certificate)

    def test_unrecognised_shape_yields_nothing(self) -> None:
        self.assertEqual(decode_public_key_data_choice(bytes.fromhex("0401")), ("", b""))
        self.assertEqual(decode_public_key_data_choice(b""), ("", b""))

    def test_entry_exposes_restored_der_and_proprietary_information(self) -> None:
        contents = _certificate_contents()
        entry = (
            _tlv("80", b"eim.example.test")
            + _tlv("A5", _tlv("A1", contents))
            + _tlv("A6", _tlv("A0", _spki_contents()))
            + _tlv("AA", bytes.fromhex("3000"))
        )
        response = _tlv("BF55", _tlv("A0", _tlv("30", entry)))
        entries = decode_eim_configuration_entries(response)
        self.assertEqual(len(entries), 1)
        first = entries[0]
        self.assertEqual(first["eim_public_key_data"], _tlv("A1", contents))
        self.assertEqual(first["eim_public_key_kind"], "certificate")
        self.assertEqual(first["eim_public_key_der"], _tlv("30", contents))
        self.assertEqual(first["trusted_tls_public_key_kind"], "publicKey")
        self.assertEqual(first["trusted_tls_public_key_der"], _tlv("30", _spki_contents()))
        self.assertEqual(first["esipa_proprietary_protocol_information"], "3000")


if __name__ == "__main__":
    unittest.main()
