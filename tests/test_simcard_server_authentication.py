# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10b.AuthenticateServer and ES10b.PrepareDownload of the simulated eUICC (SGP.22 v3.1).

Checks the RSP Server certificate chain against a held eSIM CA RootCA, the role OIDs, the
error codes and their order (§5.7.13 p.334-339, §5.7.5 p.327-328), the transactionId in
every error body, and the end of the RSP Session on an error. Strict mode is used throughout;
the lenient default is covered by tests/test_simcard_backend.py.
"""

from __future__ import annotations

import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.utils import read_tlv, tlv

TRANSACTION_ID = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90")
# SGP.22 v3.1 §2.4a.1.0 (p.42): id-rspRole-dp-auth-v2 {id-rspRole 4}, id-rspRole-dp-pb-v2 {id-rspRole 5}.
DP_AUTH_ROLE = "2.23.146.1.2.1.4"
DP_PB_ROLE = "2.23.146.1.2.1.5"
# SGP.33-1 v1.2 #S_SM_DP+_OID1 (A.1 p.150); 2.999.11 is a second OID under the same example arc.
SMDP_OID = "2.999.10"
OTHER_SMDP_OID = "2.999.11"
NOW = datetime.datetime.now(datetime.timezone.utc)


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_usage(*, digital_signature: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _root_ca(common_name: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_key_usage(key_cert_sign=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def _server_certificate(
    issuer: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    role_oid: str,
    smdp_oid: str = SMDP_OID,
    digital_signature: bool = True,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(f"Test SM-DP+ {role_oid}"))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_key_usage(digital_signature=digital_signature), critical=True)
        .add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(role_oid), None)]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(smdp_oid))]),
            critical=False,
        )
        .sign(signing_key or issuer_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER), key


def _raw_signature(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    r_value, s_value = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def _authenticate_server(
    euicc_challenge: bytes,
    certificate_der: bytes,
    key: ec.EllipticCurvePrivateKey,
    *,
    ci_pkid: bytes,
    ci_pkid_v3: bytes | None = None,
    transaction_id: bytes = TRANSACTION_ID,
    signature: bytes | None = None,
) -> bytes:
    signed1_body = (
        tlv("80", transaction_id)
        + tlv("81", euicc_challenge)
        + tlv("83", b"testsmdpplus1.example.com")
        + tlv("84", b"\x55" * 16)
    )
    if ci_pkid_v3 is not None:
        # sessionContext [5] { serverSvn [0], crlStaplingV3Used [1], euiccCiPKIdToBeUsedV3 [2] }
        signed1_body += tlv("A5", tlv("80", bytes.fromhex("030100")) + tlv("81", b"\x00") + tlv("82", ci_pkid_v3))
    server_signed1 = tlv("30", signed1_body)
    body = server_signed1 + tlv("5F37", signature or _raw_signature(key, server_signed1))
    body += tlv("04", ci_pkid) + certificate_der
    # ctxParamsForCommonAuthentication [0] { deviceInfo [1] { tac [0], deviceCapabilities [1] } }
    body += tlv("A0", tlv("A1", tlv("80", bytes.fromhex("01020304")) + tlv("A1", b"")))
    return tlv("BF38", body)


def _prepare_download(
    euicc_signature1: bytes,
    certificate_der: bytes,
    key: ec.EllipticCurvePrivateKey,
    *,
    transaction_id: bytes = TRANSACTION_ID,
    signature: bytes | None = None,
) -> bytes:
    # smdpSigned2 { transactionId [0], ccRequiredFlag BOOLEAN }
    smdp_signed2 = tlv("30", tlv("80", transaction_id) + tlv("01", b"\x00"))
    signed_data = smdp_signed2 + tlv("5F37", euicc_signature1)
    body = smdp_signed2 + tlv("5F37", signature or _raw_signature(key, signed_data)) + certificate_der
    return tlv("BF21", body)


def _error(tag: str, transaction_id: bytes, code: int) -> bytes:
    return tlv(tag, tlv("A1", tlv("80", transaction_id) + tlv("02", bytes([code]))))


def _ok_value(response: bytes) -> bytes:
    """Content of the Ok alternative 'A0' of an AuthenticateServer or PrepareDownload response."""
    _, value, _, _ = read_tlv(response, 0)
    choice_tag, choice_value, _, _ = read_tlv(value, 0)
    if choice_tag != b"\xA0":
        raise AssertionError(f"expected the Ok alternative, got {response.hex().upper()}")
    return choice_value


class _StrictRig(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.state.conformance_strict = True
        self.ci, self.ci_key = _root_ca("Test CI")
        self.state.ci_certificates = [self.ci.public_bytes(serialization.Encoding.DER)]
        self.logic = SgpLogic(self.state)
        self.signing_ci_pkid = bytes(self.state.root_ci_pkid)
        self.dpauth_der, self.dpauth_key = _server_certificate(self.ci, self.ci_key, role_oid=DP_AUTH_ROLE)

    def _challenge(self) -> bytes:
        response, _, _ = self.logic.handle_store_data(bytes.fromhex("BF2E00"))
        _, value, _, _ = read_tlv(response, 0)
        _, challenge, _, _ = read_tlv(value, 0)
        return challenge

    def _authenticate(self, certificate_der: bytes, key: ec.EllipticCurvePrivateKey, **kwargs: object) -> bytes:
        kwargs.setdefault("ci_pkid", self.signing_ci_pkid)
        request = _authenticate_server(self._challenge(), certificate_der, key, **kwargs)
        response, sw1, sw2 = self.logic.handle_store_data(request)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response


class StrictAuthenticateServerTests(_StrictRig):
    def test_chain_to_a_held_root_ca_is_accepted(self) -> None:
        response = self._authenticate(self.dpauth_der, self.dpauth_key)

        signed1_tag, _, _, _ = read_tlv(_ok_value(response), 0)
        self.assertEqual(signed1_tag, b"\x30")
        self.assertTrue(self.state.sgp_session.session_open)

    def test_root_ca_the_euicc_does_not_hold_is_ci_pk_unknown(self) -> None:
        other_ci, other_ci_key = _root_ca("Unknown CI")
        certificate_der, key = _server_certificate(other_ci, other_ci_key, role_oid=DP_AUTH_ROLE)

        response = self._authenticate(certificate_der, key)

        self.assertEqual(response, _error("BF38", TRANSACTION_ID, 7))
        self.assertEqual(self.state.sgp_session.card_challenge, b"")

    def test_certificate_the_named_issuer_did_not_sign_is_invalid_certificate(self) -> None:
        forged_der, key = _server_certificate(
            self.ci,
            self.ci_key,
            role_oid=DP_AUTH_ROLE,
            signing_key=ec.generate_private_key(ec.SECP256R1()),
        )

        self.assertEqual(self._authenticate(forged_der, key), _error("BF38", TRANSACTION_ID, 1))

    def test_certificate_without_digital_signature_is_invalid_certificate(self) -> None:
        certificate_der, key = _server_certificate(
            self.ci,
            self.ci_key,
            role_oid=DP_AUTH_ROLE,
            digital_signature=False,
        )

        self.assertEqual(self._authenticate(certificate_der, key), _error("BF38", TRANSACTION_ID, 1))

    def test_dppb_certificate_offered_for_authentication_is_invalid_oid(self) -> None:
        certificate_der, key = _server_certificate(self.ci, self.ci_key, role_oid=DP_PB_ROLE)

        self.assertEqual(self._authenticate(certificate_der, key), _error("BF38", TRANSACTION_ID, 5))

    def test_wrong_server_signature_is_invalid_signature(self) -> None:
        response = self._authenticate(self.dpauth_der, self.dpauth_key, signature=b"\x11" * 64)

        self.assertEqual(response, _error("BF38", TRANSACTION_ID, 2))

    def test_challenge_of_another_session_is_euicc_challenge_mismatch(self) -> None:
        self._challenge()
        request = _authenticate_server(b"\x33" * 16, self.dpauth_der, self.dpauth_key, ci_pkid=self.signing_ci_pkid)

        response, _, _ = self.logic.handle_store_data(request)

        self.assertEqual(response, _error("BF38", TRANSACTION_ID, 6))

    def test_unsupported_or_empty_ci_pkid_to_be_used_is_ci_pk_unknown(self) -> None:
        for ci_pkid in (b"\x42" * 20, b""):
            with self.subTest(ci_pkid=ci_pkid.hex()):
                response = self._authenticate(self.dpauth_der, self.dpauth_key, ci_pkid=ci_pkid)
                self.assertEqual(response, _error("BF38", TRANSACTION_ID, 7))

    def test_ci_pkid_in_the_session_context_is_accepted(self) -> None:
        response = self._authenticate(self.dpauth_der, self.dpauth_key, ci_pkid=b"", ci_pkid_v3=self.signing_ci_pkid)

        signed1_tag, _, _, _ = read_tlv(_ok_value(response), 0)
        self.assertEqual(signed1_tag, b"\x30")

    def test_missing_transaction_id_is_reported_with_an_empty_transaction_id(self) -> None:
        # transactionIdError(8) is #SupportedFromV3.0.0#; a v2 card answers undefinedError(127).
        for svn, code in ((bytes.fromhex("030100"), 8), (bytes.fromhex("020600"), 127)):
            with self.subTest(svn=svn.hex()):
                self.state.euicc_info.svn = svn
                response = self._authenticate(self.dpauth_der, self.dpauth_key, transaction_id=b"")
                self.assertEqual(response, _error("BF38", b"", code))

    def test_authenticate_server_without_get_euicc_challenge_is_no_session(self) -> None:
        request = _authenticate_server(b"\x33" * 16, self.dpauth_der, self.dpauth_key, ci_pkid=self.signing_ci_pkid)

        response, _, _ = self.logic.handle_store_data(request)

        self.assertEqual(response, _error("BF38", TRANSACTION_ID, 4))


class StrictPrepareDownloadTests(_StrictRig):
    def setUp(self) -> None:
        super().setUp()
        self.dppb_der, self.dppb_key = _server_certificate(self.ci, self.ci_key, role_oid=DP_PB_ROLE)

    def _authenticated_signature1(self) -> bytes:
        ok_value = _ok_value(self._authenticate(self.dpauth_der, self.dpauth_key))
        _, _, _, offset = read_tlv(ok_value, 0)
        _, euicc_signature1, _, _ = read_tlv(ok_value, offset)
        return euicc_signature1

    def _prepare(self, certificate_der: bytes, key: ec.EllipticCurvePrivateKey, **kwargs: object) -> bytes:
        request = _prepare_download(self._authenticated_signature1(), certificate_der, key, **kwargs)
        response, sw1, sw2 = self.logic.handle_store_data(request)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response

    def test_dppb_of_the_authenticated_sm_dp_is_accepted(self) -> None:
        response = self._prepare(self.dppb_der, self.dppb_key)

        euicc_signed2_tag, euicc_signed2, _, _ = read_tlv(_ok_value(response), 0)
        self.assertEqual(euicc_signed2_tag, b"\x30")
        self.assertEqual(read_tlv(euicc_signed2, 0)[:2], (b"\x80", TRANSACTION_ID))
        self.assertTrue(self.state.sgp_session.prepare_download_done)

    def test_dpauth_certificate_offered_for_binding_is_invalid_certificate(self) -> None:
        response = self._prepare(self.dpauth_der, self.dpauth_key)

        self.assertEqual(response, _error("BF21", TRANSACTION_ID, 1))
        self.assertFalse(self.state.sgp_session.session_open)

    def test_dppb_of_another_sm_dp_is_invalid_certificate(self) -> None:
        certificate_der, key = _server_certificate(self.ci, self.ci_key, role_oid=DP_PB_ROLE, smdp_oid=OTHER_SMDP_OID)

        self.assertEqual(self._prepare(certificate_der, key), _error("BF21", TRANSACTION_ID, 1))

    def test_dppb_certified_by_another_issuer_is_invalid_certificate(self) -> None:
        second_ci, second_ci_key = _root_ca("Second Test CI")
        self.state.ci_certificates.append(second_ci.public_bytes(serialization.Encoding.DER))
        certificate_der, key = _server_certificate(second_ci, second_ci_key, role_oid=DP_PB_ROLE)

        self.assertEqual(self._prepare(certificate_der, key), _error("BF21", TRANSACTION_ID, 1))

    def test_wrong_smdp_signature2_is_invalid_signature(self) -> None:
        response = self._prepare(self.dppb_der, self.dppb_key, signature=b"\x22" * 64)

        self.assertEqual(response, _error("BF21", TRANSACTION_ID, 2))

    def test_other_transaction_id_is_answered_with_the_session_transaction_id(self) -> None:
        response = self._prepare(self.dppb_der, self.dppb_key, transaction_id=b"\x99" * 16)

        self.assertEqual(response, _error("BF21", TRANSACTION_ID, 5))
        self.assertFalse(self.state.sgp_session.session_open)

    def test_prepare_download_before_authentication_is_no_session(self) -> None:
        request = _prepare_download(b"\x44" * 64, self.dppb_der, self.dppb_key)

        response, _, _ = self.logic.handle_store_data(request)

        self.assertEqual(response, _error("BF21", TRANSACTION_ID, 4))


if __name__ == "__main__":
    unittest.main()
