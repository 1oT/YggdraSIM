# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Direct profile download from the local SM-DP+: ES9+ in the ASN.1 binding and the SM-DP+ TLS certificate.

A card's IPAe that downloads directly posts a RemoteProfileProvisioningRequest
'A2' to the SM-DP+ over TLS (SGP.22 v3.1 §6.6.1; SGP.32 v1.3 §5.6). The codec
is checked against encodings produced by the SGP.22 v3.1 module of the pinned
pySim, the binding against a stub SM-DP+, and the certificate selection
against a bundle built here. The last test runs the whole download from a
simulated eUICC, over the card-facing listener, when the SGP.26 material of
this runtime is one that eUICC accepts.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import io
import os
import socket
import ssl
import stat
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.eim_local.engine import codec, smdp_tls
from SCP11.eim_local.engine.es9_binding import function_name, handle_es9_asn1
from SCP11.eim_local.engine.esipa import LocalEimCardTlsServer, LocalEimHttpServer, card_tls_context
from SCP11.eim_local.engine.server import card_port, restart_background, smdp_card_port, start_background, stop_background
from SCP11.eim_local.engine.service import LocalEim
from SCP11.eim_local.engine.smdp import LocalSmdp, SmdpError, bound_package_metadata, host_of
from SCP11.payload_builder import PayloadBuilder
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from tests.test_local_eim_service import EIM_FQDN, EIM_ID, ServiceTestBase, _free_port

SMDP_HOST = "smdpp.example.test"
SMDP_OID = "2.999.10"
TX = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
CI_PKID = bytes(range(20))
tlv = esipa.tlv

SIGNED1 = tlv(b"\x30", tlv(b"\x80", TX) + tlv(b"\x81", b"\x01" * 16) + tlv(b"\x83", SMDP_HOST.encode())
              + tlv(b"\x84", b"\x02" * 16))
SIGNED2 = tlv(b"\x30", tlv(b"\x80", TX) + bytes.fromhex("010100"))
SIGNATURE = bytes(range(64))
# ICCID 8988201234567890123 as coded in EF.ICCID.
METADATA = tlv(b"\xBF\x25", tlv(b"\x5A", bytes.fromhex("988802214365870921F3")) + tlv(b"\x91", b"Test SP")
               + tlv(b"\x92", b"Test profile"))
AUTHENTICATE_SERVER_RESPONSE = bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")
PREPARE_DOWNLOAD_RESPONSE = bytes.fromhex("BF2117A115801000112233445566778899AABBCCDDEEFF02017F")
CANCEL_SESSION_RESPONSE = bytes.fromhex("BF4103810105")
INSTALLATION_RESULT = tlv(b"\xBF\x37", tlv(b"\xBF\x27", tlv(b"\x80", TX)) + tlv(b"\x5F\x37", SIGNATURE))
BOUND_PACKAGE = tlv(b"\xBF\x36", tlv(b"\xBF\x23", b"\x00") + tlv(b"\xA0", tlv(b"\x87", b"\x11" * 12))
                    + tlv(b"\xA1", tlv(b"\x88", METADATA[:9] + b"\xEE" * 8) + tlv(b"\x88", METADATA[9:] + b"\xEE" * 8))
                    + tlv(b"\xA3", tlv(b"\x86", b"\x22" * 12)))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _name(common_name: str, organisation: str = "Test") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_pair(folder: Path, stem: str, certificate: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"CERT_{stem}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (folder / f"SK_{stem}.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _authority(subject: x509.Name, issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
               ) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    signer = issuer[1] if issuer is not None else key
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer[0].subject if issuer is not None else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False), critical=True)
    )
    return builder.sign(signer, hashes.SHA256()), key


def _authentication_certificate(
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey], *, role: str = "2.23.146.1.2.1.4",
) -> x509.Certificate:
    """A CERT.DPauth shaped like the SGP.26 one: SM-DP+ OID in the subjectAltName, role policy, CRL points."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder().subject_name(_name("TEST SM-DP+", "ACME")).issuer_name(issuer[0].subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[1].public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(SMDP_OID))]),
                       critical=False)
        .add_extension(x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(role), None)]),
                       critical=True)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier("http://ci.example.test/CRL-1.crl")], relative_name=None,
            reasons=None, crl_issuer=None)]), critical=False)
        .sign(issuer[1], hashes.SHA256())
    )


class Bundle:
    """A certificate bundle laid out like the SGP.26 one: a test CI with its key, and a CERT.DPauth under it."""

    def __init__(self, root: Path, *, sub_ca: bool = False) -> None:
        self.root = root
        self.ci = _authority(_name("Test CI"))
        _write_pair(root / "Variant T" / "CI", "CI_SIG_NIST", *self.ci)
        self.issuer = self.ci
        if sub_ca:
            self.issuer = _authority(_name("Test CI SM_DPSubCA"), self.ci)
            _write_pair(root / "Variant T" / "SM-DP+" / "SM_DPSubCA", "SM_DPSubCA_VART_SIG_NIST", *self.issuer)
        role = "2.23.146.1.2.1.0.0.1.1" if sub_ca else "2.23.146.1.2.1.4"
        self.auth = _authentication_certificate(self.issuer, role=role)
        self.auth_der = self.auth.public_bytes(serialization.Encoding.DER)

    def client_context(self) -> ssl.SSLContext:
        """A TLS client that trusts the test CI alone, as an eUICC carrying it does."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=self.ci[0].public_bytes(serialization.Encoding.DER))
        return context

    def add_tls_certificate(self, host: str, *, expired: bool = False) -> x509.Certificate:
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=400 if expired else 1)
        certificate, key = smdp_tls.issue_certificate(self.auth, self.issuer[0], self.issuer[1], host, now=start)
        _write_pair(self.root / "Variant T" / "SM-DP+" / "SM_DPtls", "S_SM_DP_VART_TLS_NIST", certificate, key)
        return certificate


def _leaf(material: smdp_tls.ServingMaterial) -> x509.Certificate:
    return x509.load_pem_x509_certificates(Path(material.chain_path).read_bytes())[0]


def _post(tls: ssl.SSLSocket, host: str, body: bytes) -> tuple[int, dict[str, str], bytes]:
    """One ES9+ request in the ASN.1 binding over an open session (SGP.22 v3.1 §6.6.1)."""
    head = (f"POST /gsma/rsp2/asn1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gsma-rsp-ipae\r\n"
            f"X-Admin-Protocol: gsma/rsp/v2.1.0\r\nContent-Type: application/x-gsma-rsp-asn1\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
    tls.sendall(head + body)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if len(chunk) == 0:
            raise AssertionError("the listener closed the session before answering")
        data += chunk
    header, _, rest = data.partition(b"\r\n\r\n")
    lines = header.decode("iso-8859-1").split("\r\n")
    fields = {key.strip().lower(): value.strip() for key, value in (line.split(":", 1) for line in lines[1:])}
    while len(rest) < int(fields.get("content-length", "0")):
        rest += tls.recv(65536)
    return int(lines[0].split()[1]), fields, rest


class StubSmdp:
    """The calls ``handle_es9_asn1`` makes on a ``LocalSmdp``, with fixed answers."""

    def __init__(self, certificate: bytes = b"") -> None:
        self.certificate = certificate or _authority(_name("Stub"))[0].public_bytes(serialization.Encoding.DER)
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.lines: list[str] = []
        self.log = self.lines.append
        self.open = {TX.hex().upper()}
        self.metadata = METADATA
        self.failing = ""

    def address(self) -> str:
        return SMDP_HOST

    def host(self) -> str:
        return SMDP_HOST

    def transaction(self, transaction_id: bytes) -> dict[str, object] | None:
        return {} if bytes(transaction_id).hex().upper() in self.open else None

    def handle(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        name = path.rsplit("/", 1)[-1]
        self.calls.append((name, dict(payload)))
        if name == self.failing:
            raise SmdpError("stub failure")
        if name == "initiateAuthentication":
            return {"transactionId": _b64(TX), "serverSigned1": _b64(SIGNED1), "serverSignature1": _b64(SIGNATURE),
                    "serverCertificate": _b64(self.certificate), "euiccCiPKIdToBeUsed": CI_PKID.hex().upper()}
        if name == "authenticateClient":
            answer = {"transactionId": _b64(TX), "smdpSigned2": _b64(SIGNED2),
                      "smdpSignature2": _b64(tlv(b"\x5F\x37", SIGNATURE)), "smdpCertificate": _b64(self.certificate)}
            if self.metadata:
                answer["profileMetadata"] = _b64(self.metadata)
            return answer
        if name == "getBoundProfilePackage":
            return {"transactionId": _b64(TX), "boundProfilePackage": _b64(BOUND_PACKAGE)}
        return {}


class CodecReferenceTests(unittest.TestCase):
    def test_encodings_match_the_compiled_module(self) -> None:
        cases = {
            "A206BF390381017F": es9_asn1.encode_initiate_authentication_error(127),
            "A206BF3B0381010A": es9_asn1.encode_authenticate_client_error(10),
            "A206BF3A0381015F": es9_asn1.encode_get_bound_profile_package_error(95),
            "A205BF4102A000": es9_asn1.encode_cancel_session_ok(),
            "A206BF4103810101": es9_asn1.encode_cancel_session_error(1),
            "A21ABF4117801000112233445566778899AABBCCDDEEFFA103810105":
                es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE),
        }
        for expected, encoded in cases.items():
            with self.subTest(expected=expected[:14]):
                self.assertEqual(encoded.hex().upper(), expected)

    def test_the_compiled_module_reads_what_the_codec_writes(self) -> None:
        from SCP11.pysim_support import pysim_rsp_v3_asn1

        spec = pysim_rsp_v3_asn1()
        if spec is None:
            self.skipTest("the SGP.22 v3.1 module of the pinned pySim is not available")
        info1 = tlv(b"\xBF\x20", tlv(b"\x82", bytes.fromhex("020201")) + tlv(b"\xA9", tlv(b"\x04", CI_PKID))
                    + tlv(b"\xAA", tlv(b"\x04", CI_PKID)))
        name, request = spec.decode("RemoteProfileProvisioningRequest",
                                    es9_asn1.encode_initiate_authentication_request(b"\x01" * 16, SMDP_HOST, info1))
        self.assertEqual(name, "initiateAuthenticationRequest")
        self.assertEqual((request["euiccChallenge"], request["smdpAddress"]), (b"\x01" * 16, SMDP_HOST))
        certificate = StubSmdp().certificate
        name, (choice, answer) = spec.decode("RemoteProfileProvisioningResponse", es9_asn1.encode_initiate_authentication_ok(
            TX, SIGNED1, SIGNATURE, CI_PKID, certificate))
        self.assertEqual((name, choice), ("initiateAuthenticationResponse", "initiateAuthenticationOk"))
        self.assertEqual((answer["transactionId"], answer["serverSignature1"], answer["euiccCiPKIdToBeUsed"]),
                         (TX, SIGNATURE, CI_PKID))
        self.assertEqual(answer["serverSigned1"]["serverAddress"], SMDP_HOST)
        name, (choice, answer) = spec.decode("RemoteProfileProvisioningResponse", es9_asn1.encode_authenticate_client_ok(
            TX, METADATA, SIGNED2, SIGNATURE, certificate))
        self.assertEqual((name, choice), ("authenticateClientResponseEs9", "authenticateClientOk"))
        self.assertEqual((answer["transactionId"], answer["smdpSignature2"]), (TX, SIGNATURE))
        self.assertEqual(answer["profileMetadata"]["serviceProviderName"], "Test SP")
        name, request = spec.decode("RemoteProfileProvisioningRequest",
                                    es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE))
        self.assertEqual((name, request["transactionId"]), ("cancelSessionRequestEs9", TX))
        self.assertEqual(request["cancelSessionResponse"], ("cancelSessionResponseError", 5))

    def test_answers_read_back(self) -> None:
        certificate = StubSmdp().certificate
        ok = es9_asn1.decode_initiate_authentication_response(
            es9_asn1.encode_initiate_authentication_ok(TX, SIGNED1, SIGNATURE, CI_PKID, certificate))
        self.assertEqual((ok.transaction_id, ok.server_signed1, ok.server_signature1, ok.euicc_ci_pkid,
                          ok.server_certificate), (TX, SIGNED1, SIGNATURE, CI_PKID, certificate))
        client = es9_asn1.decode_authenticate_client_response(
            es9_asn1.encode_authenticate_client_ok(TX, METADATA, SIGNED2, tlv(b"\x5F\x37", SIGNATURE), certificate))
        self.assertEqual((client.transaction_id, client.profile_metadata, client.smdp_signed2,
                          client.smdp_signature2, client.smdp_certificate),
                         (TX, METADATA, SIGNED2, tlv(b"\x5F\x37", SIGNATURE), certificate))
        self.assertEqual(es9_asn1.decode_get_bound_profile_package_response(
            es9_asn1.encode_get_bound_profile_package_ok(TX, BOUND_PACKAGE)), BOUND_PACKAGE)
        self.assertIsNone(es9_asn1.decode_cancel_session_response(es9_asn1.encode_cancel_session_ok()))
        self.assertEqual(es9_asn1.decode_handle_notification(
            es9_asn1.unwrap(es9_asn1.encode_handle_notification(INSTALLATION_RESULT))), INSTALLATION_RESULT)

    def test_error_answers_raise_their_named_code(self) -> None:
        for answer, decoder, code, name in (
            ("A206BF3903810103", es9_asn1.decode_initiate_authentication_response, 3, "ciPKIdNotSupported"),
            ("A206BF3B0381010A", es9_asn1.decode_authenticate_client_response, 10, "invalidTransactionId"),
            ("A206BF3B0381017F", es9_asn1.decode_authenticate_client_response, 127, "undefinedError"),
            ("A206BF3A0381015F", es9_asn1.decode_get_bound_profile_package_response, 95, "invalidTransactionId"),
            ("A206BF4103810101", es9_asn1.decode_cancel_session_response, 1, "invalidTransactionId"),
        ):
            with self.subTest(answer=answer):
                with self.assertRaises(es9_asn1.Es9Asn1Error) as caught:
                    decoder(bytes.fromhex(answer))
                self.assertEqual((caught.exception.code, caught.exception.name), (code, name))
        # authenticateClientOkRpm 'A2': an answer of another procedure, not an error code.
        with self.assertRaisesRegex(es9_asn1.Es9Asn1Error, "no profile download answer"):
            es9_asn1.decode_authenticate_client_response(bytes.fromhex("A205BF3B02A200"))

    def test_malformed_messages_are_refused(self) -> None:
        for data in (b"", b"\xA2", bytes.fromhex("A281"), bytes.fromhex("A20ABF3903"), bytes.fromhex("A200"),
                     bytes.fromhex("A206BF390381017F00"), bytes.fromhex("BF390381017F"),
                     bytes.fromhex("A20CBF390381017FBF390381017F"), bytes.fromhex("A205BF4F025A00")):
            with self.subTest(data=data.hex()):
                with self.assertRaises(es9_asn1.Es9Asn1Error):
                    es9_asn1.unwrap(data)
                self.assertEqual(handle_es9_asn1(StubSmdp(), data), (400, b""))
                self.assertEqual(function_name(data), "?")
        for data in (b"", b"\xBF", bytes.fromhex("BF3D05A003BF3701"), bytes.fromhex("BF3D00"), bytes.fromhex("BF3A00")):
            with self.subTest(notification=data.hex()):
                with self.assertRaises(es9_asn1.Es9Asn1Error):
                    es9_asn1.decode_handle_notification(data)
        with self.assertRaisesRegex(es9_asn1.Es9Asn1Error, "BF25"):
            es9_asn1.encode_authenticate_client_ok(TX, b"", SIGNED2, SIGNATURE, b"\x30\x00")


class BindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.smdp = StubSmdp()

    def test_each_step_is_answered_from_the_sm_dp(self) -> None:
        info1 = tlv(b"\xBF\x20", tlv(b"\x82", bytes.fromhex("020201")))
        status, body = handle_es9_asn1(
            self.smdp, es9_asn1.encode_initiate_authentication_request(b"\x01" * 16, SMDP_HOST, info1))
        ok = es9_asn1.decode_initiate_authentication_response(body)
        self.assertEqual((status, ok.transaction_id, ok.euicc_ci_pkid, ok.server_certificate),
                         (200, TX, CI_PKID, self.smdp.certificate))
        self.assertEqual(self.smdp.calls[-1], ("initiateAuthentication", {
            "euiccChallenge": "01" * 16, "smdpAddress": SMDP_HOST, "euiccInfo1": info1.hex()}))
        status, body = handle_es9_asn1(
            self.smdp, es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE))
        client = es9_asn1.decode_authenticate_client_response(body)
        self.assertEqual((status, client.profile_metadata, client.smdp_signed2), (200, METADATA, SIGNED2))
        self.assertEqual(self.smdp.calls[-1][1]["authenticateServerResponse"], AUTHENTICATE_SERVER_RESPONSE.hex())
        status, body = handle_es9_asn1(
            self.smdp, es9_asn1.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE))
        self.assertEqual((status, es9_asn1.decode_get_bound_profile_package_response(body)), (200, BOUND_PACKAGE))
        status, body = handle_es9_asn1(self.smdp, es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE))
        self.assertEqual((status, body), (200, es9_asn1.encode_cancel_session_ok()))
        self.assertEqual(self.smdp.calls[-1], ("cancelSession", {
            "transactionId": TX.hex().upper(), "cancelSessionResponse": CANCEL_SESSION_RESPONSE.hex()}))
        self.assertEqual(handle_es9_asn1(self.smdp, es9_asn1.encode_handle_notification(INSTALLATION_RESULT)), (204, b""))
        self.assertEqual(self.smdp.calls[-1], ("handleNotification", {
            "pendingNotification": INSTALLATION_RESULT.hex(), "transactionId": TX.hex().upper()}))

    def test_a_transaction_this_sm_dp_did_not_open_is_named_as_such(self) -> None:
        self.smdp.open.clear()
        for request, expected in (
            (es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE), "A206BF3B0381010A"),
            (es9_asn1.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE), "A206BF3A0381015F"),
            (es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE), "A206BF4103810101"),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(handle_es9_asn1(self.smdp, request), (200, bytes.fromhex(expected)))
        self.assertEqual(self.smdp.calls, [])

    def test_a_failing_step_is_answered_undefined_error_with_the_cause_logged(self) -> None:
        requests = {
            "initiateAuthentication": (es9_asn1.encode_initiate_authentication_request(b"\x01" * 16, SMDP_HOST, b""),
                                       "A206BF390381017F"),
            "authenticateClient": (es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE),
                                   "A206BF3B0381017F"),
            "getBoundProfilePackage": (es9_asn1.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE),
                                       "A206BF3A0381017F"),
            "cancelSession": (es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE), "A206BF410381017F"),
        }
        for name, (request, expected) in requests.items():
            with self.subTest(name=name):
                self.smdp.failing = name
                self.assertEqual(handle_es9_asn1(self.smdp, request), (200, bytes.fromhex(expected)))
                self.assertIn("stub failure", self.smdp.lines[-1])
        self.smdp.failing = "handleNotification"
        self.assertEqual(handle_es9_asn1(self.smdp, es9_asn1.encode_handle_notification(INSTALLATION_RESULT)), (204, b""))

    def test_authenticate_client_is_refused_without_profile_metadata(self) -> None:
        self.smdp.metadata = b""
        status, body = handle_es9_asn1(
            self.smdp, es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE))
        self.assertEqual((status, body), (200, bytes.fromhex("A206BF3B0381017F")))
        self.assertIn("Profile Metadata", self.smdp.lines[-1])


class MetadataTests(unittest.TestCase):
    def test_the_metadata_of_a_bound_package_reads_back(self) -> None:
        self.assertEqual(bound_package_metadata(BOUND_PACKAGE), METADATA)
        without = tlv(b"\xBF\x36", tlv(b"\xBF\x23", b"\x00") + tlv(b"\xA0", tlv(b"\x87", b"\x11" * 12)))
        for data in (b"", b"\xBF", BOUND_PACKAGE[:20], bytes.fromhex("BF368201FF00"), without, METADATA,
                     tlv(b"\xBF\x36", tlv(b"\xA1", tlv(b"\x88", b"\x30\x00" + b"\xEE" * 8)))):
            with self.subTest(data=data.hex()[:24]):
                self.assertEqual(bound_package_metadata(data), b"")

    def test_host_names(self) -> None:
        self.assertEqual(host_of("https://SMDPP.example.test:443/gsma/rsp2/es9plus"), SMDP_HOST)
        self.assertEqual(host_of("smdpp.example.test."), SMDP_HOST)
        self.assertEqual(host_of(""), "")


class HttpTests(ServiceTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.smdp = StubSmdp()
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=self.smdp)
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)

    def _post(self, body: bytes) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            self.server.url + "/gsma/rsp2/asn1", data=body, method="POST",
            headers={"Content-Type": "application/x-gsma-rsp-asn1", "User-Agent": "gsma-rsp-ipae"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            return response.status, {key.lower(): value for key, value in response.headers.items()}, response.read()

    def test_the_wrapper_selects_the_binding_on_the_shared_path(self) -> None:
        status, headers, body = self._post(es9_asn1.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE))
        self.assertEqual((status, headers["content-type"], headers["x-admin-protocol"]),
                         (200, "application/x-gsma-rsp-asn1", "gsma/rsp/v2.1.0"))
        self.assertEqual(es9_asn1.decode_get_bound_profile_package_response(body), BOUND_PACKAGE)
        status, headers, body = self._post(es9_asn1.encode_handle_notification(INSTALLATION_RESULT))
        self.assertEqual((status, body, "content-type" in headers), (204, b"", False))
        # The same step without the wrapper is ESipa: the relay answers it, not the SM-DP+.
        calls = len(self.smdp.calls)
        status, headers, body = self._post(esipa.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE))
        self.assertEqual((status, headers["x-admin-protocol"], body.hex().upper()),
                         (200, "gsma/rsp/v1.3.0", "BF3A0381015F"))
        self.assertEqual(len(self.smdp.calls), calls)
        get = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)))
        self.assertEqual(self._post(get)[2][:2], b"\xBF\x4F")


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name) / "store"
        self.directory.mkdir()
        self.bundle_root = Path(folder.name) / "bundle"

    def select(self, bundle: Bundle, host: str = SMDP_HOST, **options: object) -> smdp_tls.ServingMaterial:
        return smdp_tls.select_material(self.directory, auth_certificate=bundle.auth_der, host=host,
                                        bundle_root=bundle.root, **options)


class CertificateTests(_Store):
    def test_a_certificate_is_issued_under_the_issuer_of_the_authentication_certificate(self) -> None:
        bundle = Bundle(self.bundle_root)
        material = self.select(bundle)
        leaf = _leaf(material)
        self.assertEqual(material.label, f"issued for {SMDP_HOST} under Test CI")
        self.assertEqual(leaf.subject.rfc4514_string(), f"O=ACME,CN={SMDP_HOST}")
        self.assertEqual(leaf.issuer, bundle.ci[0].subject)
        bundle.ci[0].public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertFalse(names.critical)
        self.assertEqual(names.value.get_values_for_type(x509.DNSName), [SMDP_HOST])
        self.assertEqual([oid.dotted_string for oid in names.value.get_values_for_type(x509.RegisteredID)], [SMDP_OID])
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertTrue(usage.critical)
        self.assertEqual(list(usage.value), [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(key_usage.critical and key_usage.value.digital_signature)
        self.assertFalse(key_usage.value.key_cert_sign)
        policies = leaf.extensions.get_extension_for_class(x509.CertificatePolicies)
        self.assertFalse(policies.critical)
        self.assertEqual([policy.policy_identifier.dotted_string for policy in policies.value], ["2.23.146.1.2.1.3"])
        self.assertEqual(
            leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
            bundle.ci[0].extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
        )
        self.assertEqual(leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value,
                         bundle.auth.extensions.get_extension_for_class(x509.CRLDistributionPoints).value)
        self.assertEqual(len(x509.load_pem_x509_certificates(Path(material.chain_path).read_bytes())), 1)
        self.assertEqual(stat.S_IMODE(os.stat(material.key_path).st_mode), 0o600)

    def test_the_certificate_is_kept_until_what_it_was_issued_for_changes(self) -> None:
        bundle = Bundle(self.bundle_root)
        first = _leaf(self.select(bundle))
        self.assertEqual(_leaf(self.select(bundle)).serial_number, first.serial_number)
        other = _leaf(self.select(bundle, host="SMDPP2.example.test."))
        self.assertNotEqual(other.serial_number, first.serial_number)
        self.assertEqual(other.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                         .get_values_for_type(x509.DNSName), ["smdpp2.example.test"])
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=smdp_tls.VALIDITY_DAYS)
        renewed = _leaf(self.select(bundle, host="smdpp2.example.test", now=later))
        self.assertNotEqual(renewed.serial_number, other.serial_number)
        self.assertGreater(renewed.not_valid_after_utc, later)

    def test_a_sub_ca_is_sent_after_the_leaf(self) -> None:
        bundle = Bundle(self.bundle_root, sub_ca=True)
        material = self.select(bundle)
        chain = x509.load_pem_x509_certificates(Path(material.chain_path).read_bytes())
        self.assertEqual([item.subject for item in chain[1:]], [bundle.issuer[0].subject])
        self.assertEqual(chain[0].issuer, bundle.issuer[0].subject)
        self.assertEqual([policy.policy_identifier.dotted_string for policy in
                          chain[0].extensions.get_extension_for_class(x509.CertificatePolicies).value],
                         ["2.23.146.1.2.1.0.0.1.0"])
        self.assertIn("Test CI SM_DPSubCA", material.label)

    def test_the_bundle_certificate_serves_while_it_names_the_host_and_is_valid(self) -> None:
        bundle = Bundle(self.bundle_root)
        bundled = bundle.add_tls_certificate(SMDP_HOST)
        material = self.select(bundle)
        self.assertEqual(material.label, "SGP.26 bundle CERT_S_SM_DP_VART_TLS_NIST.pem")
        self.assertEqual(_leaf(material).serial_number, bundled.serial_number)
        self.assertNotEqual(_leaf(self.select(bundle, host="other.example.test")).serial_number, bundled.serial_number)
        expired = bundle.add_tls_certificate(SMDP_HOST, expired=True)
        material = self.select(bundle)
        self.assertNotEqual(_leaf(material).serial_number, expired.serial_number)
        self.assertIn("issued for", material.label)

    def test_operator_files_serve_as_they_are(self) -> None:
        bundle = Bundle(self.bundle_root)
        issued = self.select(bundle)
        (Path(issued.chain_path).parent / smdp_tls.RECORD_FILE).unlink()
        chain = Path(issued.chain_path).read_bytes()
        material = self.select(bundle, host="other.example.test")
        self.assertEqual((material.label, Path(material.chain_path).read_bytes()), ("operator files", chain))

    def test_what_is_missing_is_named(self) -> None:
        bundle = Bundle(self.bundle_root)
        for kwargs, message in (
            ({"auth_certificate": bundle.auth_der, "host": "", "bundle_root": bundle.root}, "no address"),
            ({"auth_certificate": b"", "host": SMDP_HOST, "bundle_root": bundle.root}, "does not parse"),
            ({"auth_certificate": b"\x30", "host": SMDP_HOST, "bundle_root": bundle.root}, "does not parse"),
            ({"auth_certificate": bundle.auth_der, "host": SMDP_HOST, "bundle_root": ""}, smdp_tls.CHAIN_FILE),
            ({"auth_certificate": bundle.auth_der, "host": SMDP_HOST, "bundle_root": self.directory / "none"},
             "no private key of the issuer"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(smdp_tls.SmdpTlsError, message):
                    smdp_tls.select_material(self.directory, **kwargs)
        (bundle.root / "Variant T" / "CI" / "SK_CI_SIG_NIST.pem").unlink()
        with self.assertRaisesRegex(smdp_tls.SmdpTlsError, "no private key of the issuer"):
            self.select(bundle)

        class Unloaded:
            def session(self) -> object:
                raise FileNotFoundError("No matching SGP.26 local credential set was found.")

        with self.assertRaisesRegex(smdp_tls.SmdpTlsError, "no certificate material"):
            smdp_tls.serving_material(self.directory, Unloaded())


class ListenerTests(_Store):
    def test_a_client_holding_the_test_ci_reaches_the_sm_dp_by_its_name(self) -> None:
        bundle = Bundle(self.bundle_root, sub_ca=True)
        material = self.select(bundle)
        engine = LocalEim(self.directory)
        smdp = StubSmdp()
        listener = LocalEimCardTlsServer(engine, ("127.0.0.1", 0), card_tls_context(material.chain_path, material.key_path),
                                         smdp=smdp, socket_timeout_s=10.0)
        listener.start_in_thread()
        self.addCleanup(listener.stop)
        address = ("127.0.0.1", listener.server_address[1])
        with socket.create_connection(address, timeout=10) as raw:
            with bundle.client_context().wrap_socket(raw, server_hostname=SMDP_HOST) as tls:
                status, headers, body = _post(
                    tls, SMDP_HOST, es9_asn1.encode_initiate_authentication_request(b"\x01" * 16, SMDP_HOST, b""))
                self.assertEqual((status, headers["x-admin-protocol"]), (200, "gsma/rsp/v2.1.0"))
                self.assertEqual(es9_asn1.decode_initiate_authentication_response(body).transaction_id, TX)
                # The session stays open for the next step of the same download.
                status, _headers, body = _post(
                    tls, SMDP_HOST, es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE))
                self.assertEqual(es9_asn1.decode_authenticate_client_response(body).profile_metadata, METADATA)
        with socket.create_connection(address, timeout=10) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                bundle.client_context().wrap_socket(raw, server_hostname=EIM_FQDN)
        stranger = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        stranger.load_verify_locations(cadata=_authority(_name("Another CI"))[0].public_bytes(serialization.Encoding.DER))
        with socket.create_connection(address, timeout=10) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                stranger.wrap_socket(raw, server_hostname=SMDP_HOST)


class ServiceTests(ServiceTestBase):
    def test_the_port_options(self) -> None:
        self.assertEqual((smdp_card_port(8743, "auto"), smdp_card_port(0, None), smdp_card_port(8743, "off")),
                         (8745, 0, None))
        self.assertEqual((smdp_card_port(8743, "9443"), card_port(8743, "auto")), (9443, 8744))
        with self.assertRaisesRegex(RuntimeError, "smdp_tls_port"):
            smdp_card_port(8743, "tomorrow")

    def test_the_service_reports_its_sm_dp_listener_and_a_restart_keeps_the_choice(self) -> None:
        port = _free_port()
        self.addCleanup(lambda: stop_background(self.directory))
        status = start_background(self.directory, port=port, tls_port="off", smdp_tls_port="off")
        self.assertEqual((status["smdp_tls_url"], status["smdp_tls_requested"]), ("", "off"))
        self.assertIn("smdp_tls_port=off", status["smdp_tls_note"])
        self.assertEqual(restart_background(self.directory)["smdp_tls_requested"], "off")
        stop_background(self.directory)
        smdp_port = _free_port()
        status = start_background(self.directory, port=port, tls_port="off", smdp_tls_port=smdp_port)
        self.assertEqual(status["smdp_tls_requested"], smdp_port)
        if status["smdp_tls_url"]:
            self.assertEqual((status["smdp_tls_url"], status["smdp_tls_port"]),
                             (f"https://127.0.0.1:{smdp_port}", smdp_port))
            self.assertTrue(status["smdp_tls_material"] and status["smdp_fqdn"])
            self.assertEqual(restart_background(self.directory)["smdp_tls_port"], smdp_port)
        else:
            # A runtime without SM-DP+ certificate material says so and keeps serving the rest.
            self.assertIn("no SM-DP+ card-facing TLS listener", status["smdp_tls_note"])


class SurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        LocalEim(Path(folder.name)).new_identity(eim_id=EIM_ID, eim_fqdn=EIM_FQDN)
        self.status = {"url": "http://127.0.0.1:8743", "pid": 1, "eim_fqdn": EIM_FQDN, "smdp_address": SMDP_HOST,
                       "smdp_fqdn": SMDP_HOST, "tls_url": "", "tls_note": "card-facing TLS listener off",
                       "smdp_tls_url": "https://127.0.0.1:8745", "smdp_tls_port": 8745,
                       "smdp_tls_material": f"issued for {SMDP_HOST} under Test CI"}

    def test_the_shell_verb(self) -> None:
        from SCP11.eim_local import engine_shell
        from SCP11.eim_local.main import EimLocalShell

        shell = EimLocalShell()
        with mock.patch.object(engine_shell, "start_background", return_value=self.status) as start:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                shell._dispatch_command_line("SERVE start smdp_tls_port=8745 tls_port=off", source="test")
        self.assertEqual((start.call_args.kwargs["smdp_tls_port"], start.call_args.kwargs["tls_port"]), ("8745", "off"))
        printed = buffer.getvalue()
        self.assertIn("SM-DP+ card-facing TLS https://127.0.0.1:8745", printed)
        self.assertIn(f"downloads directly from {SMDP_HOST}", printed)
        without = dict(self.status, smdp_tls_url="", smdp_tls_note="no SM-DP+ card-facing TLS listener: no key")
        with mock.patch.object(engine_shell, "start_background", return_value=without) as start:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                shell._dispatch_command_line("SERVE start", source="test")
        self.assertEqual(start.call_args.kwargs["smdp_tls_port"], "auto")
        self.assertIn("no SM-DP+ card-facing TLS listener: no key", buffer.getvalue())

    def test_the_gui_action(self) -> None:
        from SCP11.eim_local import engine_shell
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        spec = next(entry for entry in SPECS if entry.id == "eim_local.service_start")
        self.assertIn("smdp_tls_port", [field.name for field in spec.inputs])
        with mock.patch.object(engine_shell, "start_background", return_value=self.status) as start:
            lines = "\n".join(spec.dispatcher(ActionContext(), port=8743, smdp_tls_port="8745")["lines"])
        self.assertEqual(start.call_args.kwargs["smdp_tls_port"], "8745")
        self.assertIn("SM-DP+ card-facing TLS https://127.0.0.1:8745", lines)


class DirectDownloadTests(ServiceTestBase):
    """A simulated eUICC downloads from the local SM-DP+ of this runtime, the way a card's IPAe does."""

    def test_a_download_runs_over_the_sm_dp_listener_in_the_asn1_binding(self) -> None:
        smdp = LocalSmdp(self.directory)
        try:
            material = smdp_tls.serving_material(self.directory, smdp)
        except smdp_tls.SmdpTlsError as error:
            self.skipTest(f"SGP.26 SM-DP+ material not usable here: {error}")
        # The eUICC holds the root alone: the certificate the last one the listener sends chains to.
        last = x509.load_pem_x509_certificates(Path(material.chain_path).read_bytes())[-1]
        root_key = last.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        roots = []
        for path in sorted(Path(smdp.session().cfg.SGP26_VALID_CERT_DIR).rglob("CERT_CI_SIG_*.pem")):
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
            if certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == root_key:
                roots.append(certificate)
        if not roots:
            self.skipTest("the SGP.26 bundle holds no CI certificate above the SM-DP+ material")
        lines: list[str] = []
        listener = LocalEimCardTlsServer(self.engine, ("127.0.0.1", 0),
                                         card_tls_context(material.chain_path, material.key_path),
                                         smdp=smdp, log=lines.append, socket_timeout_s=30.0)
        listener.start_in_thread()
        self.addCleanup(listener.stop)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=roots[0].public_bytes(serialization.Encoding.DER))
        host = smdp.host()
        challenge = self.card.exchange(bytes.fromhex("BF2E00"))[-16:]
        info1 = self.card.exchange(bytes.fromhex("BF2000"))
        with socket.create_connection(("127.0.0.1", listener.server_address[1]), timeout=30) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                _status, _headers, body = _post(
                    tls, host, es9_asn1.encode_initiate_authentication_request(challenge, host, info1))
                ok = es9_asn1.decode_initiate_authentication_response(body)
                request = PayloadBuilder.build_auth_server(
                    ok.server_signed1, ok.server_signature1, ok.server_certificate,
                    {"matchingId": "MID-DIRECT", "deviceInfo": {"tac": bytes.fromhex("35290611"), "deviceCapabilities": {}}},
                    root_ci_id=ok.euicc_ci_pkid,
                )
                authenticated = self.card.exchange(request, "AuthenticateServer")
                if authenticated[:2] != b"\xBF\x38" or b"\x5F\x37" not in authenticated:
                    self.skipTest("the simulated eUICC does not hold the CI of the SM-DP+ material here")
                _status, _headers, body = _post(
                    tls, host, es9_asn1.encode_authenticate_client_request(ok.transaction_id, authenticated))
                client = es9_asn1.decode_authenticate_client_response(body)
                self.assertEqual(client.profile_metadata[:2], b"\xBF\x25")
                prepared = self.card.exchange(PayloadBuilder.build_prepare_download_remote(
                    client.smdp_signed2, client.smdp_signature2, client.smdp_certificate), "PrepareDownload")
                _status, _headers, body = _post(
                    tls, host, es9_asn1.encode_get_bound_profile_package_request(ok.transaction_id, prepared))
                package = es9_asn1.decode_get_bound_profile_package_response(body)
                self.assertEqual(bound_package_metadata(package), client.profile_metadata)
                result = b""
                for segment in smdp._builder()._segment_bound_profile_package(package):
                    result = self.card.exchange(segment, "LoadBoundProfilePackage")
                self.assertEqual(result[:2], b"\xBF\x37")
                self.assertEqual(esipa.installation_result_transaction_id(result), ok.transaction_id)
                status, _headers, body = _post(tls, host, es9_asn1.encode_handle_notification(result))
                self.assertEqual((status, body), (204, b""))
                self.assertIsNone(smdp.transaction(ok.transaction_id))
                _status, _headers, body = _post(
                    tls, host, es9_asn1.encode_get_bound_profile_package_request(ok.transaction_id, prepared))
                self.assertEqual(body.hex().upper(), "A206BF3A0381015F")
        self.assertTrue(any("MID-DIRECT" in line for line in lines), lines[-8:])


if __name__ == "__main__":
    unittest.main()
