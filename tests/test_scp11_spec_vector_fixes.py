# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Wire shapes and decodes pinned to the official ASN.1 modules.

Every hex vector below was produced with asn1tools from the SGP.32 v1.3
module, pySim's SGP.22 module or the TCA eUICC Profile Package module, or is
a hand-built BER value whose structure is given next to it. The tests cover
the builders and decoders that used to disagree with those modules.
"""

from __future__ import annotations

import base64
import datetime
import json
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.x509.oid import NameOID

from SCP11.eim_local.psmo_builders import PsmoBuildError, _der_integer, build_eco, build_psmo, encode_iccid_bcd
from SCP11.eim_packages import (
    DOWNLOAD_DATA_ACTIVATION_CODE,
    DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP,
    DOWNLOAD_DATA_CONTACT_SMDS,
    TYPE_GENERIC,
    TYPE_PROFILE_DOWNLOAD_TRIGGER,
    parse_eim_package,
)
from SCP11.live.console import SCP11Console
from SCP11.eim_local.eim_package_codec import _lint_eim_package_result_spec, lint_eim_package_document
from SCP11.live.es9_client import ES9_USER_AGENT, ESIPA_USER_AGENT, Es9LikeClient
from SCP11.live.models import EIM_TRANSPORT_MODE_ESIPA_JSON, AuthenticateClientRequest, EimPollRequest
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.local_access.metadata_codec import build_store_metadata_request_payload
from SCP11.local_access.session import LocalIsdrSession
from SCP11.shared.ber_tlv import (
    decode_object_identifier,
    encode_ber_length,
    read_ber_tlv,
    restore_sequence,
    retag_sequence,
)
from SCP11.shared.gsma_error_codes import (
    SGP32_PROFILE_DOWNLOAD_ERROR_REASON,
    describe_sgp22_bpp_command_id,
    describe_sgp22_download_error,
    describe_sgp22_profile_installation_reason,
    resolve_sgp22_profile_installation_reason_code,
)
from SCP11.shared.iccid import decode_bcd_digits, decode_ef_iccid, encode_ef_iccid
from SCP11.shared.profile_info import split_profile_info_list
from SCP11.shared.rsp_roles import (
    PROFILE_BINDING_ROLES,
    RSP_ROLE_OIDS,
    SERVER_AUTH_ROLES,
    certificate_rsp_roles,
    check_rsp_role,
)
from SCP11.shared.sima_response import decode_sima_response
from SCP11.shared.trace_dump import _decode_der_oid
from SCP03.logic.euicc_info2 import EUICC_INFO2_NESTED_TAG_NAMES, EUICC_INFO2_TAG_NAMES
from SCP03.logic.sgp32_decode import certificate_der_from_choice_value, decode_get_certs_response
from SIMCARD.sgp32_packages import signature_payload, unwrap_eim_key_material, verify_eim_signature

PKID = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
EID = bytes.fromhex("89049032123451234512345678901235")
EF_ICCID = bytes.fromhex("988802214365870921F3")

# SGP.32 v1.3 module: ProfileDownloadTriggerRequest, one vector per
# ProfileDownloadData alternative, each with eimTransactionId '1122'.
PDTR_ACTIVATION_CODE = "BF5432A02C802A3124534D44502E4558414D504C452E434F4D2430343338362D41475946542D41373459382D334638313582021122"
PDTR_EMPTY_TOKEN = "BF542DA02780253124534D44502E4558414D504C452E434F4D2424312E332E362E312E342E312E333137343682021122"
PDTR_CONTACT_DEFAULT_SMDP = "BF5408A002810082021122"
PDTR_CONTACT_SMDS = "BF541BA015A2138011736D64732E6578616D706C652E7465737482021122"
PDTR_CONTACT_SMDS_NO_ADDRESS = "BF5408A002A20082021122"
PDTR_EMPTY = "BF540482021122"
PDTR_DOLLAR_TRANSACTION_ID = "BF540AA0028100820424412442"
# SGP.32 v1.3 module: IpaEuiccDataRequest with euiccCiPKIdentifierToBeUsed.
IPA_EUICC_DATA_REQUEST = "BF52245C08A0A2BF20BF22A5A60414F54172BDF98A95D65CBEB88A38A1C11D800A85C383020102"
# SGP.32 v1.3 module: ProvideEimPackageResultResponse carrying acknowledgements.
PROVIDE_EIM_PACKAGE_RESULT_RESPONSE = "BF5009BF5306800101800102"
# pySim SGP.22 module: ProfileInstallationResult with an errorResult and a successResult.
PIR_ERROR = "BF374CBF273E8003010203BF2F26800107810207800C11736D64702E6578616D706C652E746573745A0A988802214365870921F3060467810F01A208A10680010581010A5F37085555555555555555"
PIR_SUCCESS = "BF3757BF27498003010203BF2F1A800107810207800C11736D64702E6578616D706C652E74657374060467810F01A21FA01D4F10A0000005591010FFFFFFFF890000100004093007A00530038001005F37085555555555555555"
# TCA eUICC Profile Package V3.4.1 module: EUICCResponse values.
EUICC_RESPONSE_OK = "3007A0053003800100"
EUICC_RESPONSE_FAILURE = "3026A016300980010381010583010C30098001068101078201028100820A6261642076616C756573"


def _self_signed_certificate() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "eim.example.test"),
        ]
    )
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


def _spki(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class ProvideEimPackageResultErrorTests(unittest.TestCase):
    """eimPackageResultResponseError [0] is A0 { [80 txid] 02 01 code }."""

    def test_orchestrator_error_branch_matches_module(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(
            orchestrator._build_provide_eim_package_result_error_tlv(1).hex().upper(),
            "BF5005A003020101",
        )
        self.assertEqual(
            orchestrator._build_provide_eim_package_result_error_tlv(127, b"\x01\x02").hex().upper(),
            "BF5009A0078002010202017F",
        )

    def test_orchestrator_unrecognised_card_response_uses_error_branch(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        built = orchestrator._build_provide_eim_package_result_tlv(b"\x30\x00", eid="")
        self.assertEqual(built.hex().upper(), "BF5005A003020101")

    def test_eim_local_error_branch_matches_module(self) -> None:
        from SCP11.eim_local.session import EimLocalSession

        session = object.__new__(EimLocalSession)
        self.assertEqual(
            session._build_eim_package_result_response_error_tlv(error_code=127).hex().upper(),
            "BF5005A00302017F",
        )
        self.assertEqual(
            session._build_eim_package_result_response_error_tlv(
                error_code=2, eim_transaction_id=b"\x01\x02"
            ).hex().upper(),
            "BF5009A00780020102020102",
        )


class GetCertsRequestTests(unittest.TestCase):
    def test_ci_public_key_identifier_takes_context_tag_zero(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(
            orchestrator._build_get_certs_request_payload(PKID).hex().upper(),
            "BF56168014F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
        )
        self.assertEqual(orchestrator._build_get_certs_request_payload(b"").hex().upper(), "BF5600")

    def test_ipa_euicc_data_request_exposes_the_identifier(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(IPA_EUICC_DATA_REQUEST))
        self.assertEqual(parsed.euicc_ci_pkid_to_be_used, PKID)
        self.assertEqual(parsed.request_token, b"\x01\x02")
        self.assertEqual(parsed.requested_tags[0], b"\xA0")


class AddEimKeyMaterialTests(unittest.TestCase):
    """eimPublicKeyData / trustedPublicKeyDataTls: A5 { A0 <SPKI> } or A5 { A1 <Certificate> }."""

    def test_public_key_alternative_replaces_the_sequence_tag(self) -> None:
        key, _certificate = _self_signed_certificate()
        spki = _spki(key)
        eco = build_eco({"operation": "add_eim", "eim_id": "eim.example.test", "counter_value": 1, "eim_public_key_data": spki.hex()})
        expected = b"\xA5" + bytes([len(spki)]) + b"\xA0" + spki[1:]
        self.assertIn(expected, eco)
        self.assertNotIn(b"\xA5" + bytes([len(spki) + 2]) + b"\x30", eco)

    def test_certificate_alternative_replaces_the_sequence_tag(self) -> None:
        _key, certificate = _self_signed_certificate()
        eco = build_eco({"operation": "add_eim", "eim_id": "eim.example.test", "trusted_tls_public_key_data": certificate.hex()})
        retagged = retag_sequence(b"\xA1", certificate)
        self.assertIn(b"\xA6" + b"\x82" + len(retagged).to_bytes(2, "big") + retagged, eco)
        _tag, contents, _raw, _end = read_ber_tlv(retagged, 0)
        self.assertEqual(restore_sequence(contents), certificate)

    def test_garbage_material_is_refused(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_eco({"operation": "add_eim", "eim_id": "eim.example.test", "eim_public_key_data": "0102"})

    def test_simulator_verifies_a_signature_against_the_spec_shape(self) -> None:
        key, certificate = _self_signed_certificate()
        spki = _spki(key)
        signed_blob = b"\xA0\x03\x80\x01\x01"
        payload = signature_payload(signed_blob, 5)
        der_signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = asym_utils.decode_dss_signature(der_signature)
        raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        for material in (retag_sequence(b"\xA0", spki), retag_sequence(b"\xA1", certificate), spki, certificate):
            with self.subTest(head=material[:1].hex()):
                self.assertTrue(verify_eim_signature(material, signed_blob, raw_signature, 5))
        self.assertEqual(unwrap_eim_key_material(retag_sequence(b"\xA1", certificate)), certificate)


class PsmoSelectorTests(unittest.TestCase):
    def test_enable_carries_a_ten_octet_iccid(self) -> None:
        encoded = build_psmo({"operation": "enable", "iccid": "8988201234567890123"})
        self.assertEqual(encoded.hex().upper(), "A30C5A0A988802214365870921F3")

    def test_short_iccid_is_padded_to_size_ten(self) -> None:
        self.assertEqual(len(encode_iccid_bcd("898820123456789012")), 10)
        self.assertEqual(encode_iccid_bcd("123").hex().upper(), "21F3FFFFFFFFFFFFFFFF")

    def test_aid_is_not_a_psmo_selector(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"operation": "disable", "aid": "A0000005591010FFFFFFFF8900001000"})

    def test_negative_integers_are_minimal(self) -> None:
        self.assertEqual(_der_integer(-1).hex().upper(), "FF")
        self.assertEqual(_der_integer(-128).hex().upper(), "80")
        self.assertEqual(_der_integer(-32768).hex().upper(), "8000")
        self.assertEqual(_der_integer(128).hex().upper(), "0080")


class MetadataIccidTests(unittest.TestCase):
    def _document(self) -> dict:
        return {
            "profile": {"iccid": "89880811111111111112", "name": "Test", "profile_class": "operational"},
            "operator": {"name": "Operator"},
        }

    def test_store_metadata_iccid_is_ef_coded(self) -> None:
        payload = build_store_metadata_request_payload(self._document())
        self.assertEqual(payload["iccid"].hex().upper(), "98888011111111111121")
        self.assertNotIn("profileOwner", payload)

    def test_owner_needs_a_plmn(self) -> None:
        document = self._document()
        document["operator"]["mcc"] = "001"
        document["operator"]["mnc"] = "01"
        payload = build_store_metadata_request_payload(document)
        self.assertEqual(payload["profileOwner"]["mccMnc"].hex().upper(), "00F110")
        document = self._document()
        document["operator"]["gid1"] = "AA"
        with self.assertRaises(ValueError):
            build_store_metadata_request_payload(document)

    def test_shared_ef_iccid_round_trip(self) -> None:
        self.assertEqual(encode_ef_iccid("8988201234567890123"), EF_ICCID)
        self.assertEqual(decode_ef_iccid(EF_ICCID), "8988201234567890123")
        with self.assertRaises(ValueError):
            decode_ef_iccid(bytes.fromhex("A1"))
        self.assertEqual(decode_ef_iccid(bytes.fromhex("A1"), strict=False), "1A")


class ProfileDownloadTriggerTests(unittest.TestCase):
    def test_activation_code_alternative(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(PDTR_ACTIVATION_CODE))
        self.assertEqual(parsed.package_type, TYPE_PROFILE_DOWNLOAD_TRIGGER)
        self.assertEqual(parsed.download_data_choice, DOWNLOAD_DATA_ACTIVATION_CODE)
        self.assertEqual(parsed.smdp_address, "SMDP.EXAMPLE.COM")
        self.assertEqual(parsed.matching_id, "04386-AGYFT-A74Y8-3F815")
        self.assertEqual(parsed.eim_transaction_id, b"\x11\x22")

    def test_zero_length_matching_id_is_valid(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(PDTR_EMPTY_TOKEN))
        self.assertEqual(parsed.smdp_address, "SMDP.EXAMPLE.COM")
        self.assertEqual(parsed.matching_id, "")

    def test_contact_default_smdp_and_contact_smds(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(PDTR_CONTACT_DEFAULT_SMDP))
        self.assertEqual(parsed.download_data_choice, DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP)
        self.assertIsNone(parsed.activation_code)
        parsed = parse_eim_package(bytes.fromhex(PDTR_CONTACT_SMDS))
        self.assertEqual(parsed.download_data_choice, DOWNLOAD_DATA_CONTACT_SMDS)
        self.assertEqual(parsed.smds_address, "smds.example.test")
        parsed = parse_eim_package(bytes.fromhex(PDTR_CONTACT_SMDS_NO_ADDRESS))
        self.assertEqual(parsed.download_data_choice, DOWNLOAD_DATA_CONTACT_SMDS)
        self.assertIsNone(parsed.smds_address)
        parsed = parse_eim_package(bytes.fromhex(PDTR_EMPTY))
        self.assertEqual(parsed.download_data_choice, "")
        self.assertEqual(parsed.eim_transaction_id, b"\x11\x22")

    def test_transaction_id_bytes_are_never_an_activation_code(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(PDTR_DOLLAR_TRANSACTION_ID))
        self.assertEqual(parsed.download_data_choice, DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP)
        self.assertIsNone(parsed.activation_code)
        self.assertIsNone(parsed.smdp_address)
        self.assertEqual(parsed.eim_transaction_id, b"$A$B")

    def test_provide_eim_package_result_is_not_a_download_trigger(self) -> None:
        parsed = parse_eim_package(bytes.fromhex(PROVIDE_EIM_PACKAGE_RESULT_RESPONSE))
        self.assertEqual(parsed.package_type, TYPE_GENERIC)

    def test_activation_code_format_must_be_one(self) -> None:
        console = object.__new__(SCP11Console)
        self.assertEqual(console._parse_activation_code("1$SMDP.EXAMPLE.COM$$1.3.6.1.4.1.31746"), ("SMDP.EXAMPLE.COM", ""))
        self.assertEqual(console._parse_activation_code("LPA:1$rsp.example.com$MATCH-1"), ("rsp.example.com", "MATCH-1"))
        self.assertIsNone(console._parse_activation_code("2$SMDP.EXAMPLE.COM$ABC"))


class ProfileInstallationResultTests(unittest.TestCase):
    def _consumers(self):
        return (object.__new__(SGP22Orchestrator), object.__new__(LocalIsdrSession))

    def test_error_result_members_and_signature(self) -> None:
        for consumer in self._consumers():
            with self.subTest(consumer=type(consumer).__name__):
                details = consumer._decode_profile_installation_result(bytes.fromhex(PIR_ERROR))
                self.assertEqual(details["bppCommandId"], 5)
                self.assertEqual(details["bppCommandIdName"], "loadProfileElements")
                self.assertEqual(details["errorReason"], 10)
                self.assertEqual(details["errorReasonName"], "installFailedDueToInsufficientMemoryForProfile")
                self.assertEqual(details["resultCode"], 5)
                self.assertEqual(details["resultDetail"], 10)
                self.assertEqual(details["iccid"], "8988201234567890123")
                self.assertEqual(details["smdpOid"], "2.23.143.1")
                self.assertEqual(details["euiccSignPIR"], b"\x55" * 8)
                self.assertEqual(details["finalResultTag"], b"\xA1")

    def test_error_result_ppi_response_is_kept(self) -> None:
        # ErrorResult { bppCommandId 80, errorReason 81, ppiResponse 82 }.
        final_result = bytes.fromhex("A213A11180010581010A82093007A0053003800104")
        body = bytes.fromhex("8003010203") + final_result
        raw = bytes.fromhex("BF37") + bytes([len(body) + 3]) + bytes.fromhex("BF27") + bytes([len(body)]) + body
        for consumer in self._consumers():
            with self.subTest(consumer=type(consumer).__name__):
                details = consumer._decode_profile_installation_result(raw)
                self.assertEqual(details["simaResponse"].hex().upper(), "3007A0053003800104")

    def test_success_result_members(self) -> None:
        for consumer in self._consumers():
            with self.subTest(consumer=type(consumer).__name__):
                details = consumer._decode_profile_installation_result(bytes.fromhex(PIR_SUCCESS))
                self.assertEqual(details["aid"].hex().upper(), "A0000005591010FFFFFFFF8900001000")
                self.assertEqual(details["simaResponse"].hex().upper(), EUICC_RESPONSE_OK)
                self.assertIsNone(details["resultCode"])
                self.assertEqual(details["finalResultTag"], b"\xA0")

    def test_describer_names_command_and_reason(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(
            orchestrator._describe_profile_installation_result_code(5, 10, b"\xA1"),
            "card failed loadProfileElements with installFailedDueToInsufficientMemoryForProfile(10)",
        )
        self.assertEqual(
            orchestrator._describe_profile_installation_result_code(5, 9, b"\xA1"),
            "card rejected the profile because its ICCID is already installed",
        )


class EuiccResponseTests(unittest.TestCase):
    def test_all_ok_response(self) -> None:
        decoded = decode_sima_response(bytes.fromhex(EUICC_RESPONSE_OK))
        self.assertTrue(decoded["semantic"]["ok"])
        self.assertEqual(decoded["summary"], "peStatus[0].status=ok(0)")

    def test_failure_response_lists_every_pe_status(self) -> None:
        decoded = decode_sima_response(bytes.fromhex(EUICC_RESPONSE_FAILURE))
        semantic = decoded["semantic"]
        self.assertFalse(semantic["ok"])
        self.assertTrue(semantic["profile_installation_aborted"])
        self.assertEqual(semantic["status_message"], "bad values")
        self.assertEqual([entry["status_name"] for entry in semantic["pe_status"]], ["bad-values", "invalid-parameter"])
        self.assertEqual(semantic["pe_status"][0]["offset"], 12)
        self.assertEqual(semantic["pe_status"][1]["additional_information"], 2)
        self.assertIn("profileInstallationAborted", decoded["summary"])
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._decode_sima_response_semantics(bytes.fromhex(EUICC_RESPONSE_FAILURE)), decoded["summary"])


class ObjectIdentifierTests(unittest.TestCase):
    def test_first_subidentifier_may_span_octets(self) -> None:
        self.assertEqual(decode_object_identifier(bytes.fromhex("8837")), "2.999")
        self.assertEqual(decode_object_identifier(bytes.fromhex("7F")), "2.47")
        self.assertEqual(decode_object_identifier(bytes.fromhex("67810F01")), "2.23.143.1")
        self.assertEqual(_decode_der_oid(bytes.fromhex("8837")), "2.999")
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._decode_oid(bytes.fromhex("883701")), "2.999.1")
        self.assertEqual(LocalIsdrSession._decode_oid(bytes.fromhex("2A864886F70D")), "1.2.840.113549")

    def test_truncated_and_non_minimal_subidentifiers_are_refused(self) -> None:
        for bad in ("2A86", "2A8001"):
            with self.assertRaises(ValueError):
                decode_object_identifier(bytes.fromhex(bad))
        self.assertEqual(_decode_der_oid(bytes.fromhex("2A86")), "")


class ProfileInfoListTests(unittest.TestCase):
    def _response_with_e3_length_octet(self) -> bytes:
        # BF2D 81 E3 { A0 81 E0 { E3 81 DD { 5A 0A iccid, 9F70 01 01, 92 81 CA name } } }
        name = b"N" * 202
        profile = bytes.fromhex("5A0A") + EF_ICCID + bytes.fromhex("9F700101") + bytes.fromhex("9281CA") + name
        self.assertEqual(len(profile), 0xDD)
        ok_list = b"\xE3\x81\xDD" + profile
        raw = b"\xBF\x2D\x81\xE3" + b"\xA0\x81\xE0" + ok_list
        self.assertEqual(len(raw), 4 + 3 + 3 + 0xDD)
        return raw

    def test_length_octet_e3_is_not_a_profile(self) -> None:
        raw = self._response_with_e3_length_octet()
        profiles, error_code = split_profile_info_list(raw)
        self.assertEqual(len(profiles), 1)
        self.assertIsNone(error_code)
        console = object.__new__(SCP11Console)
        rows = console._decode_profiles_with_local_parser(raw)
        self.assertEqual(len(rows), 1)
        session = object.__new__(LocalIsdrSession)
        self.assertEqual(len(session.decode_profile_metadata_rows(raw)), 1)

    def test_error_alternative_is_not_an_empty_list(self) -> None:
        profiles, error_code = split_profile_info_list(bytes.fromhex("BF2D0381017F"))
        self.assertEqual(profiles, [])
        self.assertEqual(error_code, 127)


class EuiccConfiguredDataTests(unittest.TestCase):
    def test_additional_root_ds_addresses_are_utf8strings(self) -> None:
        # BF3C { 80 dp, 81 ds, A2 { 0C ds2, 0C ds3 }, 83 pkid }: SEQUENCE OF UTF8String
        # elements keep the universal tag 0C (SGP.22 v3.1 EuiccConfiguredDataResponse).
        addresses = b"\x0C\x10ds2.example.test" + b"\x0C\x10ds3.example.test"
        body = b"\x80\x11smdp.example.test" + b"\x81\x0Fds.example.test" + b"\xA2" + bytes([len(addresses)]) + addresses + b"\x83\x04\xAA\xBB\xCC\xDD"
        raw = b"\xBF\x3C" + bytes([len(body)]) + body
        console = object.__new__(SCP11Console)
        decoded = console._decode_euicc_configured_data(raw)
        self.assertEqual(decoded["root_smds_additional"], ["ds2.example.test", "ds3.example.test"])
        session = object.__new__(LocalIsdrSession)
        self.assertEqual(session.decode_euicc_configured_data(raw)["root_smds_additional"], ["ds2.example.test", "ds3.example.test"])


class NotificationIccidTests(unittest.TestCase):
    def test_local_session_reads_ef_coded_iccid(self) -> None:
        session = object.__new__(LocalIsdrSession)
        details = session._decode_notification_metadata_fields(bytes.fromhex("8001075A0A") + EF_ICCID)
        self.assertEqual(details["iccid"], "8988201234567890123")


class ErrorTableTests(unittest.TestCase):
    def test_error_reason_values_follow_v3(self) -> None:
        self.assertEqual(describe_sgp22_profile_installation_reason(23), "lprNotSupported(23)")
        self.assertEqual(describe_sgp22_profile_installation_reason(26), "unknownTlvInMetadata(26)")
        self.assertEqual(describe_sgp22_profile_installation_reason(7), "bspStructureError(7)")
        self.assertEqual(resolve_sgp22_profile_installation_reason_code("scp03tStructureError"), 7)
        self.assertEqual(resolve_sgp22_profile_installation_reason_code("lprNotSupported"), 23)
        self.assertEqual(describe_sgp22_bpp_command_id(5), "loadProfileElements(5)")
        self.assertEqual(describe_sgp22_download_error(4), "noSession(4)")
        self.assertEqual(set(SGP32_PROFILE_DOWNLOAD_ERROR_REASON), {104, 127})


class Es9TransactionIdTests(unittest.TestCase):
    def test_authenticate_client_reads_the_schema_key(self) -> None:
        client = Es9LikeClient(base_url="https://rsp.example.com")
        client._post_json = lambda _path, _payload: {"transactionId": "AABB", "smdpSigned2": "", "smdpSignature2": "", "smdpCertificate": ""}
        response = client.authenticate_client(AuthenticateClientRequest(transaction_id="0011", authenticate_server_response="", smdp_address=""))
        self.assertEqual(response.transaction_id, "AABB")


class RplmnSourceTests(unittest.TestCase):
    def test_euicc_info2_is_no_longer_read_for_a_plmn(self) -> None:
        self.assertFalse(hasattr(SGP22Orchestrator, "_extract_candidate_rplmn_from_euicc_info2"))


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + encode_ber_length(len(value)) + value


def _certificate_with_rsp_role(
    role: str | None,
    *,
    ca: bool = False,
    policy_oid: str | None = None,
) -> bytes:
    """Self-signed test certificate carrying one certificatePolicies OID, or none.

    ``policy_oid`` names the OID literally so a test can pin the arc the
    specification gives instead of echoing the module's own table.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"), x509.NameAttribute(NameOID.COMMON_NAME, "role test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if policy_oid is None and role is not None:
        policy_oid = RSP_ROLE_OIDS[role]
    if policy_oid is not None:
        policy = x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), None)
        builder = builder.add_extension(x509.CertificatePolicies([policy]), critical=True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _sgp26_certificate_der(*parts: str) -> bytes:
    """Load a bundled SGP.26 certificate, or skip when the checkout has none.

    ``*.der`` under the bundle is gitignored, and an encrypted checkout
    keeps a wrapped copy at the same path, so the bytes go through the
    secret-file reader the certificate store uses.
    """
    from tests.sgp26_support import SGP26_VALID_ROOT
    from yggdrasim_common.inventory_crypto import read_secret_file_bytes

    path = SGP26_VALID_ROOT.joinpath(*parts)
    if not path.is_file():
        raise unittest.SkipTest(f"SGP.26 certificate absent: {path.name}")
    try:
        der = read_secret_file_bytes(path)
        x509.load_der_x509_certificate(der)
    except Exception as error:  # noqa: BLE001 -- an unreadable bundle is a skip, not a role defect
        raise unittest.SkipTest(f"SGP.26 certificate unreadable: {path.name}: {error}") from error
    return der


class ReservedLengthOctetTests(unittest.TestCase):
    """X.690 8.1.3.5 c): the length octet FF is reserved; 80 is the indefinite form."""

    def test_shared_reader_refuses_ff(self) -> None:
        with self.assertRaises(ValueError):
            read_ber_tlv(bytes.fromhex("30FF"), 0)

    def test_relay_and_console_lengths_refuse_ff(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        console = object.__new__(SCP11Console)
        for reader in (orchestrator._decode_length, console._decode_length):
            self.assertEqual(reader(bytes.fromhex("FF00"), 0), (0, 0))
            self.assertEqual(reader(bytes.fromhex("80"), 0), (0, 0))
            self.assertEqual(reader(bytes.fromhex("8201F4"), 0), (500, 3))

    def test_es9_reader_takes_four_length_octets_and_refuses_ff(self) -> None:
        client = object.__new__(Es9LikeClient)
        tlv, end = client._read_tlv_at(bytes.fromhex("048400000002AABB"), 0)
        self.assertEqual(tlv[1], bytes.fromhex("AABB"))
        self.assertEqual(end, 8)
        for broken in ("04FF", "0480", "048500000000020000"):
            self.assertIsNone(client._read_tlv_at(bytes.fromhex(broken), 0)[0])


class AuthenticateServerChoiceTests(unittest.TestCase):
    """SGP.22 v3.1 section 5.7.13: the response alternatives are [0] and [1]."""

    def test_only_context_tags_select_an_alternative(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._extract_choice_payload(bytes.fromhex("BF3803A00100")), ("ok", b"\x00"))
        self.assertEqual(orchestrator._extract_choice_payload(bytes.fromhex("BF3803A10100")), ("error", b"\x00"))
        self.assertEqual(orchestrator._extract_choice_payload(bytes.fromhex("BF3803610100")), ("", b""))


class PendingNotificationTests(unittest.TestCase):
    """SGP.22 v3.1 section 5.7.10 notificationList entries, plus the SGP.32 compact forms."""

    def test_every_pending_notification_form_is_returned_raw(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        for entry in ("BF37028000", "30028000", "A0028000", "A1028000"):
            response = _tlv("BF2B", _tlv("A0", bytes.fromhex(entry)))
            self.assertEqual(orchestrator._extract_pending_notification_payload(response), bytes.fromhex(entry))

    def test_error_and_foreign_entries_yield_nothing(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._extract_pending_notification_payload(bytes.fromhex("BF2B0381017F")), b"")
        self.assertEqual(orchestrator._extract_pending_notification_payload(_tlv("BF2B", _tlv("A0", bytes.fromhex("04028000")))), b"")
        self.assertEqual(orchestrator._extract_pending_notification_payload(b""), b"")


class ProviderStringPayloadTests(unittest.TestCase):
    """A provider field is hex or base64; the alphabets overlap, so structure decides."""

    def test_hex_and_base64_forms_of_one_tlv_decode_alike(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        expected = bytes.fromhex("BF2B00")
        self.assertEqual(orchestrator._decode_string_payload("BF2B00"), expected)
        self.assertEqual(orchestrator._decode_string_payload(base64.b64encode(expected).decode("ascii")), expected)

    def test_hex_looking_base64_is_read_as_base64_when_only_that_is_a_tlv(self) -> None:
        # "0AEA" is base64 for D00100; read as hex it is an incomplete long-form TLV.
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._decode_string_payload("0AEA"), bytes.fromhex("D00100"))

    def test_hex_wins_when_neither_reading_is_a_tlv(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        self.assertEqual(orchestrator._decode_string_payload("ABCD0000"), bytes.fromhex("ABCD0000"))


class BcdDigitTests(unittest.TestCase):
    """ETSI TS 102 221 v18.4 section 13.2: BCD nibbles are digits, F pads."""

    def test_non_digit_nibbles_are_not_turned_into_digits(self) -> None:
        orchestrator = object.__new__(SGP22Orchestrator)
        session = object.__new__(LocalIsdrSession)
        for decoder in (orchestrator._decode_bcd_digits, session._decode_bcd_digits):
            self.assertEqual(decoder(bytes.fromhex("123F")), "123")
            self.assertEqual(decoder(bytes.fromhex("1A")), "1A")
        with self.assertRaises(ValueError):
            decode_bcd_digits(bytes.fromhex("1A"))
        self.assertEqual(decode_bcd_digits(bytes.fromhex("1A"), strict=False), "1A")


class RspRoleTests(unittest.TestCase):
    """SGP.22 v3.1 section 4.5.2.1: certificatePolicies names the RSP role."""

    def test_server_auth_roles_pass_in_both_arcs(self) -> None:
        for role in ("dp-auth", "ds-auth", "dp-auth-v2", "ds-auth-v2"):
            der = _certificate_with_rsp_role(role)
            self.assertEqual(certificate_rsp_roles(der), {role})
            self.assertEqual(check_rsp_role(der, SERVER_AUTH_ROLES, "server"), "")
        self.assertEqual(RSP_ROLE_OIDS["dp-auth"], "2.23.146.1.2.1.0.0.1.1")
        self.assertEqual(RSP_ROLE_OIDS["ds-auth-v2"], "2.23.146.1.2.1.7")

    def test_roles_sit_under_the_gsma_arc_not_the_tca_profile_arc(self) -> None:
        """id-rsp is {2 23 gsma(146) 1} (SGP.22 v3.1 section 2.4a.1.0 and Annex K).

        The policies are built from literal OIDs here: a fixture derived from
        the module's own table cannot tell a wrong root from a right one, and
        2.23.143.1 next door is the TCA eUICC Profile Package arc.
        """
        literal_roles = {
            "2.23.146.1.2.1.4": "dp-auth-v2",
            "2.23.146.1.2.1.7": "ds-auth-v2",
            "2.23.146.1.2.1.0.0.1.1": "dp-auth",
            "2.23.146.1.2.1.0.0.1.2": "dp-pb",
            "2.23.146.1.2.1.0.0.2.1": "ds-auth",
        }
        for oid, role in literal_roles.items():
            der = _certificate_with_rsp_role(None, policy_oid=oid)
            self.assertEqual(certificate_rsp_roles(der), {role}, oid)
        for wrong_arc in ("2.23.143.1.2.1.4", "2.23.143.1.2.1.0.0.1.1"):
            der = _certificate_with_rsp_role(None, policy_oid=wrong_arc)
            self.assertEqual(certificate_rsp_roles(der), set(), wrong_arc)
            with self.assertRaises(ValueError):
                check_rsp_role(der, SERVER_AUTH_ROLES, "server")

    def test_sgp26_reference_certificates_carry_recognised_roles(self) -> None:
        """The GSMA SGP.26 material is the ground truth for the arc."""
        variant_o_ds_auth = _sgp26_certificate_der(
            "Variant O", "SM-DS", "SM_DSauth", "CERT_S_SM_DSauth_VARO_SIG_NIST.der"
        )
        self.assertEqual(certificate_rsp_roles(variant_o_ds_auth), {"ds-auth-v2"})
        self.assertEqual(check_rsp_role(variant_o_ds_auth, SERVER_AUTH_ROLES, "server"), "")
        variant_ov3_euicc = _sgp26_certificate_der("Variant Ov3", "eUICC", "CERT_EUICC_SIG_NIST.der")
        self.assertEqual(certificate_rsp_roles(variant_ov3_euicc), {"euicc"})
        variant_ov3_eum = _sgp26_certificate_der("Variant Ov3", "EUM", "CERT_EUM_SIG_NIST.der")
        self.assertEqual(certificate_rsp_roles(variant_ov3_eum), {"eum"})

    def test_profile_binding_certificate_is_refused_for_server_auth(self) -> None:
        der = _certificate_with_rsp_role("dp-pb")
        with self.assertRaises(ValueError):
            check_rsp_role(der, SERVER_AUTH_ROLES, "server")
        self.assertEqual(check_rsp_role(der, PROFILE_BINDING_ROLES, "CERT.DPpb.SIG"), "")

    def test_missing_extension_is_noted_not_refused(self) -> None:
        der = _certificate_with_rsp_role(None)
        self.assertIsNone(certificate_rsp_roles(der))
        self.assertIn("not verified", check_rsp_role(der, SERVER_AUTH_ROLES, "server"))


class ConsoleReaderTests(unittest.TestCase):
    def test_utf8_text_beyond_ascii_is_shown_as_text(self) -> None:
        console = object.__new__(SCP11Console)
        self.assertEqual(console._decode_text_or_hex("Télé".encode("utf-8")), "Télé")
        self.assertEqual(console._decode_text_or_hex(b"ab\x01"), "616201")
        self.assertEqual(console._decode_text_or_hex(b"\xff\xfe"), "FFFE")

    def test_ppr_bit_string_edge_cases(self) -> None:
        console = object.__new__(SCP11Console)
        self.assertEqual(console._decode_ppr_ids("00"), "none")
        self.assertEqual(console._decode_ppr_ids("07"), "invalid")
        self.assertEqual(console._decode_ppr_ids("0880"), "invalid")

    def test_iccid_longer_than_ef_iccid_is_refused(self) -> None:
        console = object.__new__(SCP11Console)
        self.assertEqual(console._extract_decimal_iccid("8988201234567890123"), "8988201234567890123")
        self.assertIsNone(console._extract_decimal_iccid("898820123456789012345"))

    def test_short_metadata_values_are_not_hex_dumped(self) -> None:
        console = object.__new__(SCP11Console)
        rendered = console._decode_profile_metadata_extra_value(0x99, b"abc")
        self.assertIn("abc", rendered)
        self.assertNotEqual(rendered, "616263")

    def test_collector_skips_signatures_but_reads_octet_string_wrappers(self) -> None:
        console = object.__new__(SCP11Console)
        entry = _tlv("BF2F", bytes.fromhex("800107"))
        signature = _tlv("5F37", _tlv("BF2F", bytes.fromhex("800109")))
        self.assertEqual(console._find_tlv_values_recursive(_tlv("A0", entry) + signature, 0xBF2F), [bytes.fromhex("800107")])
        self.assertEqual(console._find_tlv_values_recursive(_tlv("04", entry), 0xBF2F), [bytes.fromhex("800107")])


class EuiccInfo2NameTests(unittest.TestCase):
    def test_sgp32_tags_are_named(self) -> None:
        self.assertEqual(EUICC_INFO2_TAG_NAMES[0x95], "eUICC Minimum Security Level")
        self.assertEqual(EUICC_INFO2_NESTED_TAG_NAMES[0xB4][0x83], "Fallback Allowed Update Supported")


class EimPackageLintTests(unittest.TestCase):
    def test_every_eim_package_result_alternative_is_a_result_family(self) -> None:
        for choice in ("epr_and_notifications", "ipa_euicc_data_response", "eim_package_result_response_error"):
            errors = _lint_eim_package_result_spec({"sgp32": {"eim_package_result": {"include": True, "choice": choice}}})
            self.assertFalse([error for error in errors if "valid result family" in error], choice)

    def test_add_eim_template_carries_the_constructed_eco_tag(self) -> None:
        with open("SCP11/eim_local/eim_packages/templates/template_add_eim.json", "r", encoding="utf-8") as handle:
            document = json.load(handle)
        rows = [row for row in lint_eim_package_document(document)["spec_checks"] if "eco_choice_tag_hex" in row["detail"]]
        self.assertEqual([row["status"] for row in rows], ["PASS"])
        document["sgp32"]["add_eim_request"]["eco_choice_tag_hex"] = "88"
        rows = [row for row in lint_eim_package_document(document)["spec_checks"] if "eco_choice_tag_hex" in row["detail"]]
        self.assertEqual([row["status"] for row in rows], ["FAIL"])


class GetCertsShapeTests(unittest.TestCase):
    """SGP.32 v1.3 GetCertsResponse: certs [0] { eumCertificate [5], euiccCertificate [6] }, implicit tags."""

    def test_implicit_tag_shape_and_legacy_full_der_both_decode(self) -> None:
        _, eum_der = _self_signed_certificate()
        _, euicc_der = _self_signed_certificate()
        spec_shape = _tlv("BF56", _tlv("A0", retag_sequence(b"\xA5", eum_der) + retag_sequence(b"\xA6", euicc_der)))
        decoded = decode_get_certs_response(spec_shape)
        self.assertEqual(decoded["eumCertificate"], eum_der)
        self.assertEqual(decoded["euiccCertificate"], euicc_der)
        legacy_shape = _tlv("BF56", _tlv("A0", _tlv("A5", eum_der)) + _tlv("A1", _tlv("A6", euicc_der)))
        decoded = decode_get_certs_response(legacy_shape)
        self.assertEqual(decoded["eumCertificate"], eum_der)
        self.assertEqual(decoded["euiccCertificate"], euicc_der)
        self.assertEqual(certificate_der_from_choice_value(b"\x01\x02"), b"\x01\x02")


class Es9HttpBindingTests(unittest.TestCase):
    """SGP.22 v3.1 section 6.5.1.4 headers and section 6.5.2 bodies."""

    def test_json_headers_name_the_product_and_charset(self) -> None:
        client = object.__new__(Es9LikeClient)
        headers = client._build_json_headers("gsma/rsp/v2.1.0")
        self.assertEqual(headers["User-Agent"], ES9_USER_AGENT)
        self.assertEqual(headers["Content-Type"], "application/json;charset=UTF-8")
        self.assertEqual(headers["X-Admin-Protocol"], "gsma/rsp/v2.1.0")
        self.assertEqual(client._build_json_headers("gsma/rsp/v1.3.0", ESIPA_USER_AGENT)["User-Agent"], "gsma-rsp-ipad")

    def test_authenticate_client_body_carries_no_smdp_address(self) -> None:
        client = Es9LikeClient(base_url="https://rsp.example.test")
        bodies = []

        def capture(_path, payload):
            bodies.append(payload)
            return {"transactionId": "AABB", "smdpSigned2": "", "smdpSignature2": "", "smdpCertificate": ""}

        client._post_json = capture
        client.authenticate_client(AuthenticateClientRequest(transaction_id="0011", authenticate_server_response="", smdp_address="rsp.example.test"))
        self.assertEqual(sorted(bodies[0]), ["authenticateServerResponse", "transactionId"])


class EsipaJsonBindingTests(unittest.TestCase):
    """SGP.32 v1.3 section 6.4: the JSON binding of GetEimPackage and ProvideEimPackageResult."""

    def _client(self, response: dict) -> tuple[Es9LikeClient, list]:
        client = Es9LikeClient(base_url="https://rsp.example.test", eim_transport_mode=EIM_TRANSPORT_MODE_ESIPA_JSON)
        calls: list = []

        def record(base_url, path, payload, **kwargs):
            calls.append({"base_url": base_url, "path": path, "payload": payload, **kwargs})
            return response

        client._post_json_to_base_url = record
        return client, calls

    def _request(self, raw_body: bytes | None) -> EimPollRequest:
        return EimPollRequest(
            eim_fqdn="eim.example.test",
            eim_id="",
            eim_id_type="",
            counter_value="",
            association_token="",
            supported_protocol="",
            euicc_ci_pkid="",
            indirect_profile_download="",
            euicc_configured_data="",
            eim_configuration_data="",
            eid=EID.hex(),
            raw_body=raw_body,
        )

    def test_get_eim_package_posts_the_request_members(self) -> None:
        client, calls = self._client({"euiccPackageRequest": "QUJDRA=="})
        body = _tlv("BF4F", _tlv("5A", EID) + bytes.fromhex("8000810103820300F110"))
        response = client.poll_eim(self._request(body))
        self.assertEqual(calls[0]["path"], "/gsma/rsp2/esipa/getEimPackage")
        self.assertEqual(
            calls[0]["payload"],
            {"eidValue": EID.hex(), "notifyStateChange": True, "stateChangeCause": 3, "rPlmn": base64.b64encode(bytes.fromhex("00F110")).decode("ascii")},
        )
        self.assertEqual(calls[0]["user_agent"], ESIPA_USER_AGENT)
        self.assertEqual(calls[0]["protocol_header"], "gsma/rsp/v1.3.0")
        self.assertEqual(response.euicc_package_list, ["QUJDRA=="])

    def test_get_eim_package_without_a_body_posts_the_eid_alone(self) -> None:
        client, calls = self._client({"eimPackageError": 127})
        response = client.poll_eim(self._request(None))
        self.assertEqual(calls[0]["payload"], {"eidValue": EID.hex()})
        self.assertEqual(response.euicc_package_list, [])
        self.assertEqual(response.eim_result_code, 127)

    def test_provide_eim_package_result_posts_the_base64_result(self) -> None:
        client, calls = self._client({"eimAcknowledgements": "MAA="})
        body = _tlv("BF50", _tlv("5A", EID) + bytes.fromhex("A003020105"))
        response = client.poll_eim(self._request(body))
        self.assertEqual(calls[0]["path"], "/gsma/rsp2/esipa/provideEimPackageResult")
        self.assertEqual(calls[0]["payload"], {"eidValue": EID.hex(), "eimPackageResult": base64.b64encode(bytes.fromhex("A003020105")).decode("ascii")})
        self.assertEqual(response.package_format, "eimAcknowledgements")

    def test_handle_notification_posts_the_base64_provide_eim_package_result(self) -> None:
        # Section 6.4.1.7; a Notification function, so the eIM's answer has no body.
        client, calls = self._client({})
        provide = _tlv("BF50", _tlv("5A", EID) + _tlv("BF54", bytes.fromhex("300380017F")))
        response = client.handle_notification_esipa(self._request(_tlv("BF3D", provide)))
        self.assertEqual(calls[0]["path"], "/gsma/rsp2/esipa/handleNotification")
        self.assertEqual(calls[0]["payload"], {"provideEimPackageResult": base64.b64encode(provide).decode("ascii")})
        self.assertEqual(calls[0]["user_agent"], ESIPA_USER_AGENT)
        self.assertEqual(response, {})

    def test_handle_notification_refuses_any_other_body(self) -> None:
        client, calls = self._client({})
        for body in (
            _tlv("BF50", _tlv("5A", EID)),
            _tlv("BF3D", _tlv("A0", bytes.fromhex("BF3700"))),
            bytes.fromhex("BF3D"),
        ):
            with self.subTest(body=body.hex().upper()):
                with self.assertRaises(ValueError):
                    client.handle_notification_esipa(self._request(body))
        self.assertEqual(calls, [])


class PemBundleTests(unittest.TestCase):
    def test_every_certificate_of_a_bundle_is_read_and_the_ca_is_the_anchor(self) -> None:
        leaf = x509.load_der_x509_certificate(_certificate_with_rsp_role("dp-auth")).public_bytes(serialization.Encoding.PEM)
        root = x509.load_der_x509_certificate(_certificate_with_rsp_role("ci", ca=True)).public_bytes(serialization.Encoding.PEM)
        client = object.__new__(Es9LikeClient)
        with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as handle:
            handle.write(leaf + root)
            path = handle.name
        infos = client._load_pem_certificate_infos(path)
        self.assertEqual([info["is_ca"] for info in infos], [False, True])
        self.assertTrue(client._load_pem_certificate_info(path)["is_ca"])


if __name__ == "__main__":
    unittest.main()
