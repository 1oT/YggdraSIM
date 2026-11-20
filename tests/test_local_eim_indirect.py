# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Indirect profile download (SGP.32 v1.3 §3.2.3.2): ESipa codec, eIM relay and IPA provider.

The reference encodings were produced by the SGP.32 v1.3 ASN.1 module compiled
with the SGP.22 v3.1 module of the pinned pySim. The relay runs against a stub
SM-DP+; the IPA provider talks to the relay directly, so both ends are tested
together without a card.
"""

from __future__ import annotations

import base64
import hashlib
import datetime
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import compact as compact_forms
from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.esipa import handle_asn1
from SCP11.eim_local.engine.indirect import IndirectRelay, activation_code_fields
from SCP11.eim_local.engine.service import STATE_ERROR, STATE_SUCCESS, LocalEim, OperationRequest
from SCP11.eim_local.engine.smdp import euicc_eid
from SCP11.live.indirect_download import EsipaProfileProvider
from SCP11.live.models import (
    AuthenticateClientRequest,
    AuthenticateClientResponse,
    CancelSessionRequest,
    GetBoundProfilePackageRequest,
    GetBoundProfilePackageResponse,
    HandleNotificationRequest,
    InitiateAuthenticationRequest,
    InitiateAuthenticationResponse,
)
from SCP11.shared import esipa_download as esipa

EID = "89049032123451234512345678901235"
TX = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
SMDP_TX = bytes.fromhex("AA" * 16)
tlv = esipa.tlv


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _certificate(*, oid: str = "", serial_number: str = "", key: ec.EllipticCurvePrivateKey | None = None,
                 issuer_key_id: bytes = b"", subject_key_id: bytes = b"") -> bytes:
    """A self-signed test certificate; *issuer_key_id* / *subject_key_id* set the RFC 5280 §4.2.1.1 / §4.2.1.2
    key identifiers the chain-variant check reads."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, "Test")]
    if serial_number:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    name = x509.Name(attributes)
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
    if oid:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(oid))]), critical=False
        )
    if issuer_key_id:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier(issuer_key_id, None, None), critical=False)
    if subject_key_id:
        builder = builder.add_extension(x509.SubjectKeyIdentifier(subject_key_id), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


# The eSIM CA RootCA PKID the SM-DP+ stub selects, and the key identifier of an EUM SubCA under it
CI_PKID = b"\xF5" * 20
SUBCA_KEY_ID = b"\x33" * 20


def _declare_capabilities(engine: LocalEim, capabilities_hex: str, **data: str) -> None:
    """The IPA Capabilities (IpaCapabilities contents) and other data an IPA data request would have recorded."""
    record = engine.record(EID) or engine.register(EID)
    if capabilities_hex:
        record.data["ipa_capabilities_hex"] = capabilities_hex
    record.data.update(data)
    with engine.store.transaction() as connection:
        engine.store.save_record(record, connection)


def _serve_download(engine: LocalEim, capabilities_hex: str = "") -> Any:
    """Serve the next download as an IPA meets it: the IPA data request first, answered with
    *capabilities_hex* as ipaCapabilities 'A8' (left out when empty), then the trigger."""
    first = engine.next_package(EID)
    if first.operation is None or not first.operation.system or first.package[:2] != b"\xBF\x52":
        raise AssertionError(f"an IPA data request comes before the download, not {first.package[:2].hex()}")
    members = tlv(b"\x87", bytes.fromhex(first.operation.transaction_id))
    if capabilities_hex:
        members += tlv(b"\xA8", bytes.fromhex(capabilities_hex))
    accepted = engine.accept_result(EID, tlv(b"\xBF\x52", tlv(b"\xA0", members)))
    if accepted.error is not None:
        raise AssertionError(f"IPA data answer refused: {accepted.messages}")
    return engine.next_package(EID)


class StubSmdp:
    """The ES9+ calls of an SM-DP+ at *address*, with fixed answers."""

    def __init__(self, address: str = "smdpp.example.test", certificate: bytes = b"") -> None:
        self.address = address
        self.certificate = certificate or _certificate(oid="2.999.10")
        self.calls: list[tuple[str, object]] = []

    def initiate_authentication(self, request: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        self.calls.append(("initiate", request))
        signed1 = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x81", b"\x01" * 16)
                      + tlv(b"\x83", self.address.encode()) + tlv(b"\x84", b"\x02" * 16))
        return InitiateAuthenticationResponse(
            transaction_id=SMDP_TX.hex().upper(), server_signed1=_b64(signed1),
            server_signature1=_b64(tlv(b"\x5F\x37", b"\x05" * 64)), server_certificate=_b64(self.certificate),
            euicc_ci_pkid_to_be_used=_b64(tlv(b"\x04", b"\xF5" * 20)),
        )

    def authenticate_client(self, request: AuthenticateClientRequest) -> AuthenticateClientResponse:
        self.calls.append(("authenticate", request))
        return AuthenticateClientResponse(
            transaction_id=SMDP_TX.hex().upper(), smdp_signed2=_b64(tlv(b"\x30", tlv(b"\x80", SMDP_TX))),
            smdp_signature2=_b64(b"\x06" * 64), smdp_certificate=_b64(self.certificate),
            profile_metadata=_b64(tlv(b"\xBF\x25", tlv(b"\x5A", b"\x98" * 10))),
        )

    def get_bound_profile_package(self, request: GetBoundProfilePackageRequest) -> GetBoundProfilePackageResponse:
        self.calls.append(("bpp", request))
        return GetBoundProfilePackageResponse(bound_profile_package=_b64(tlv(b"\xBF\x36", b"\x00" * 8)))

    def cancel_session(self, request: CancelSessionRequest) -> dict:
        self.calls.append(("cancel", request))
        return {}

    def handle_notification(self, request: HandleNotificationRequest) -> dict:
        self.calls.append(("notification", request))
        return {}


class CodecReferenceTests(unittest.TestCase):
    def test_encodings_match_the_compiled_module(self) -> None:
        cases = {
            "BF39378110010101010101010101010101010101018311736D64702E6578616D706C652E74657374821000112233445566778899AABBCCDDEEFF":
                esipa.encode_initiate_authentication_request(
                    esipa.InitiateAuthenticationRequest(b"\x01" * 16, "smdp.example.test", b"", TX)),
            "BF3903810134": esipa.encode_initiate_authentication_error(52),
            "BF3B0382010A": esipa.encode_authenticate_client_error(10),
            "BF3A0381015F": esipa.encode_get_bound_profile_package_error(95),
            "BF4103810101": esipa.encode_cancel_session_error(1),
            "BF4102A000": esipa.encode_cancel_session_ok(),
            "BF4117801000112233445566778899AABBCCDDEEFFA103810105":
                esipa.encode_cancel_session_request(TX, bytes.fromhex("BF4103810105")),
            "BF3B2C801000112233445566778899AABBCCDDEEFFBF3817A115801000112233445566778899AABBCCDDEEFF020107":
                esipa.encode_authenticate_client_request(
                    TX, bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")),
            "BF3A2C801000112233445566778899AABBCCDDEEFFBF2117A115801000112233445566778899AABBCCDDEEFF02017F":
                esipa.encode_get_bound_profile_package_request(
                    TX, bytes.fromhex("BF2117A115801000112233445566778899AABBCCDDEEFF02017F")),
        }
        for expected, encoded in cases.items():
            with self.subTest(expected=expected[:12]):
                self.assertEqual(encoded.hex().upper(), expected)

    def test_error_answers_raise_their_named_code(self) -> None:
        for answer, decoder, code, name in (
            ("BF3903810134", esipa.decode_initiate_authentication_response, 52, "invalidEimTransactionId"),
            ("BF3B0382010A", esipa.decode_authenticate_client_response, 10, "invalidTransactionId"),
            ("BF3A0381015F", esipa.decode_get_bound_profile_package_response, 95, "invalidTransactionId"),
            ("BF4103810101", esipa.decode_cancel_session_response, 1, "invalidTransactionId"),
        ):
            with self.subTest(answer=answer):
                with self.assertRaises(esipa.EsipaDownloadError) as caught:
                    decoder(bytes.fromhex(answer))
                self.assertEqual((caught.exception.code, caught.exception.name), (code, name))

    def test_cancel_session_request_gives_back_the_card_answer(self) -> None:
        encoded = esipa.encode_cancel_session_request(TX, bytes.fromhex("BF4103810105"))
        self.assertEqual(esipa.decode_cancel_session_request(encoded), (TX, bytes.fromhex("BF4103810105")))

    def test_malformed_messages_are_refused(self) -> None:
        for data in (b"", b"\xBF\x39", bytes.fromhex("BF390181"), bytes.fromhex("BF3900"), bytes.fromhex("BF39058103010203")):
            with self.subTest(data=data.hex()):
                with self.assertRaises(esipa.EsipaDownloadError):
                    esipa.decode_initiate_authentication_request(data)

    def test_activation_code_fields(self) -> None:
        self.assertEqual(activation_code_fields("1$smdpp.example.test$MID-1$2.999.10"),
                         ("smdpp.example.test", "MID-1", "2.999.10"))
        self.assertEqual(activation_code_fields("2$smdpp.example.test$MID-1"), ("", "", ""))


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.engine = LocalEim(Path(folder.name))
        self.smdp = StubSmdp()
        self.addresses: list[str] = []

        def factory(address: str) -> StubSmdp:
            self.addresses.append(address)
            return self.smdp

        self.relay = IndirectRelay(self.engine, provider_factory=factory)
        # An IPA that handles the download data the eIM keeps: it gets an empty trigger and the
        # Matching ID from the eIM (SGP.32 v1.3 §2.11.1.3, §5.14.1 Table 13 NOTE 3).
        self.capabilities = "800205E0"

    def _served_download(self, code: str = "1$smdpp.example.test$MID-9") -> tuple[int, bytes, bytes]:
        operation = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER", params={"activation_code": code, "indirect": True},
        )])[0]
        served = _serve_download(self.engine, self.capabilities)
        self.assertEqual(served.operation.id, operation.id)
        return operation.id, bytes.fromhex(operation.transaction_id), served.package

    def _initiate(self, transaction_id: bytes, smdp_address: str = "") -> bytes:
        return self.relay.handle(esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
            euicc_challenge=b"\x01" * 16, smdp_address=smdp_address, euicc_info1=bytes.fromhex("BF2000"),
            eim_transaction_id=transaction_id,
        )))

    def test_the_trigger_is_served_without_download_data(self) -> None:
        _operation_id, transaction_id, package = self._served_download()
        self.assertEqual(package, tlv(b"\xBF\x54", tlv(b"\x82", transaction_id)))

    def test_a_result_the_sm_dp_plus_did_not_take_is_tried_again_by_the_eim(self) -> None:
        # The IPA is acknowledged and removes the result from the eUICC (SGP.32 v1.3 §3.2.3.2 step 23),
        # so the eIM keeps a result its SM-DP+ call lost and its Notification forwarding sends it again.
        from tests.local_eim_notification_support import Receiver, SigningEuicc

        euicc = SigningEuicc(EID)
        _operation_id, transaction_id, _package = self._served_download()
        self.engine.apply_card_reads(EID, {"euicc_certificate": euicc.certificate,
                                           "eum_certificate": euicc.eum_certificate})
        self._initiate(transaction_id)
        result = euicc.installation_result(7, "smdpp.example.test", transaction_id=SMDP_TX)
        with mock.patch.object(self.smdp, "handle_notification", side_effect=OSError("connection reset")):
            self.assertTrue(self.relay.forward_notification(result))
        self.assertEqual([(row["seq_number"], row["state"], row["address"]) for row in self.engine.notifications(EID)],
                         [(7, "pending", "smdpp.example.test")])
        receiver = Receiver()
        self.assertTrue(self.engine.forward_notifications(sender=receiver)[0].delivered)
        self.assertEqual(receiver.calls, [("smdpp.example.test", result)])
        self.assertEqual(self.engine.forward_notifications(sender=receiver, explicit=True), [])

    def test_a_result_the_sm_dp_plus_took_is_not_kept_for_sending_again(self) -> None:
        from tests.local_eim_notification_support import SigningEuicc

        euicc = SigningEuicc(EID)
        _operation_id, transaction_id, _package = self._served_download()
        self.engine.apply_card_reads(EID, {"euicc_certificate": euicc.certificate,
                                           "eum_certificate": euicc.eum_certificate})
        self._initiate(transaction_id)
        self.assertTrue(self.relay.forward_notification(
            euicc.installation_result(7, "smdpp.example.test", transaction_id=SMDP_TX)))
        self.assertEqual(self.smdp.calls[-1][0], "notification")
        self.assertEqual(self.engine.notifications(EID), [])

    def test_the_eim_relays_a_download_it_holds_the_code_for(self) -> None:
        operation_id, transaction_id, _package = self._served_download()
        answer = esipa.decode_initiate_authentication_response(self._initiate(transaction_id))
        self.assertEqual((answer.transaction_id, answer.matching_id), (SMDP_TX, "MID-9"))
        self.assertEqual(self.addresses, ["smdpp.example.test"])
        self.assertEqual(self.smdp.calls[0][1].smdp_address, "smdpp.example.test")

        response = bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")
        client = esipa.decode_authenticate_client_response(
            self.relay.handle(esipa.encode_authenticate_client_request(SMDP_TX, response)))
        self.assertEqual(client.profile_metadata[:2], b"\xBF\x25")
        self.assertEqual(base64.b64decode(self.smdp.calls[1][1].authenticate_server_response), response)

        prepare = bytes.fromhex("BF2117A115801000112233445566778899AABBCCDDEEFF02017F")
        package = esipa.decode_get_bound_profile_package_response(
            self.relay.handle(esipa.encode_get_bound_profile_package_request(SMDP_TX, prepare)))
        self.assertEqual(package, tlv(b"\xBF\x36", b"\x00" * 8))

        success = tlv(b"\xA2", tlv(b"\xA0", tlv(b"\x4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                                      + tlv(b"\x04", bytes.fromhex("3007A0053003800100"))))
        result = tlv(b"\xBF\x37", tlv(b"\xBF\x27", tlv(b"\x80", SMDP_TX) + success) + tlv(b"\x5F\x37", b"\x00" * 64))
        self.assertTrue(self.relay.forward_notification(result))
        self.assertEqual(self.smdp.calls[-1][0], "notification")
        # No eUICC certificate on record: the download closes, flagged unverified.
        closed = self.engine.operation(operation_id)
        self.assertEqual(closed.state, STATE_SUCCESS)
        self.assertIn("unverified", closed.flags)
        events = [entry["event"] for entry in self.engine.operation(operation_id).history]
        self.assertTrue(any(event.startswith("indirect: InitiateAuthentication relayed") for event in events))
        self.assertIn("indirect: ProfileInstallationResult forwarded to smdpp.example.test", events)

    def test_an_ipa_with_ctx_params1_generation_gets_them_from_the_eim(self) -> None:
        # ipaFeatures bits 0-3, eimCtxParams1Generation included (SGP.32 v1.3 §4.1, p.106).
        device_info = tlv(b"\x80", bytes.fromhex("35290611")) + tlv(b"\xA1", b"")
        _declare_capabilities(self.engine, "", device_info_hex=device_info.hex().upper())
        self.capabilities = "800204F0"
        _operation_id, transaction_id, package = self._served_download()
        self.assertEqual(package, tlv(b"\xBF\x54", tlv(b"\x82", transaction_id)))
        answer = esipa.decode_initiate_authentication_response(self._initiate(transaction_id))
        # §5.14.1: ctxParams1 from the Matching ID and DeviceInfo; the Matching ID is not sent on its own.
        self.assertEqual(answer.matching_id, "")
        self.assertEqual(answer.ctx_params1,
                         tlv(b"\xA2", tlv(b"\xA0", tlv(b"\x80", b"MID-9") + tlv(b"\xA1", device_info))))

    def test_the_provider_takes_the_answers_of_an_ipa_with_minimize_esipa_bytes(self) -> None:
        # The IPA Capabilities of the eSIM Management IPA: direct, indirect, eimDownloadDataHandling and
        # minimizeEsipaBytes.
        self.capabilities = "800202E4"
        _operation_id, transaction_id, _package = self._served_download()
        relay = self.relay

        class Client:
            def post_esipa(self, eim_fqdn: str, body: bytes, pinned: bytes = b"") -> bytes:
                return relay.handle(body)

            def set_base_url(self, base_url: str) -> None:
                self.base_url = base_url

        provider = EsipaProfileProvider(Client(), eim_fqdn="eim.example.test", eim_transaction_id=transaction_id)
        seed = provider.initiate_authentication(InitiateAuthenticationRequest(
            euicc_challenge=_b64(b"\x01" * 16), euicc_info1=_b64(EUICC_INFO1), smdp_address=""))
        # §5.14.1: no transactionId and a zero-length CI PKID (one signing PKID in euiccInfo1) go to this
        # IPA; it reads the one from serverSigned1 and expands the other (Table 13 NOTE 2, p.159).
        self.assertEqual(seed.transaction_id, SMDP_TX.hex().upper())
        self.assertEqual(seed.euicc_ci_pkid_to_be_used, SIGNING_PKID.hex().upper())
        self.assertEqual(seed.matching_id, "MID-9")
        client = provider.authenticate_client(AuthenticateClientRequest(
            transaction_id=seed.transaction_id,
            authenticate_server_response=_b64(bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")),
            smdp_address=""))
        self.assertEqual(client.transaction_id, SMDP_TX.hex().upper())

    def test_the_provider_resolves_a_truncated_identifier_or_refuses_it(self) -> None:
        answers: list[bytes] = []

        class Client:
            def post_esipa(self, eim_fqdn: str, body: bytes, pinned: bytes = b"") -> bytes:
                return answers.pop(0)

        signed1 = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x83", b"smdpp.example.test"))

        def answer(pkid: bytes) -> bytes:
            return esipa.encode_initiate_authentication_ok(esipa.InitiateAuthenticationOk(
                transaction_id=b"", server_signed1=signed1, server_signature1=b"\x05" * 64, euicc_ci_pkid=pkid,
                server_certificate=self.smdp.certificate))

        provider = EsipaProfileProvider(Client(), eim_fqdn="eim.example.test")
        two = tlv(b"\xBF\x20", tlv(b"\xAA", tlv(b"\x04", SIGNING_PKID) + tlv(b"\x04", b"\x01" * 20)))
        request = InitiateAuthenticationRequest(euicc_challenge=_b64(b"\x01" * 16), euicc_info1=_b64(two), smdp_address="")
        # Two signing PKIDs: the leading byte that tells them apart.
        answers.append(answer(SIGNING_PKID[:1]))
        self.assertEqual(provider.initiate_authentication(request).euicc_ci_pkid_to_be_used, SIGNING_PKID.hex().upper())
        answers.append(answer(b""))
        with self.assertRaises(esipa.EsipaDownloadError):
            provider.initiate_authentication(request)

    def test_refusals_carry_the_esipa_codes(self) -> None:
        self.assertEqual(self._initiate(b"\x09" * 8), esipa.encode_initiate_authentication_error(52))
        operation_id, transaction_id, _package = self._served_download()
        self.smdp.address = "other.example.test"
        self.assertEqual(self._initiate(transaction_id), esipa.encode_initiate_authentication_error(50))
        self.smdp.address = "smdpp.example.test"
        self.engine.cancel(operation_id)
        _operation_id, transaction_id, _package = self._served_download("1$smdpp.example.test$MID-9$2.999.11")
        self.assertEqual(self._initiate(transaction_id), esipa.encode_initiate_authentication_error(51))
        unknown = bytes.fromhex("CC" * 16)
        self.assertEqual(
            self.relay.handle(esipa.encode_authenticate_client_request(unknown, bytes.fromhex("BF3800"))),
            esipa.encode_authenticate_client_error(10))
        self.assertEqual(
            self.relay.handle(esipa.encode_get_bound_profile_package_request(unknown, bytes.fromhex("BF2100"))),
            esipa.encode_get_bound_profile_package_error(95))
        self.assertEqual(
            self.relay.handle(esipa.encode_cancel_session_request(unknown, bytes.fromhex("BF4103810105"))),
            esipa.encode_cancel_session_error(1))

    def test_the_ipa_provider_runs_against_the_relay(self) -> None:
        _operation_id, transaction_id, _package = self._served_download()
        relay = self.relay

        class Client:
            base_url = ""

            def post_esipa(self, eim_fqdn: str, body: bytes, pinned: bytes = b"") -> bytes:
                return b"" if body[:2] == esipa.TAG_HANDLE_NOTIFICATION else relay.handle(body)

            def set_base_url(self, base_url: str) -> None:
                self.base_url = base_url

        client_object = Client()
        provider = EsipaProfileProvider(client_object, eim_fqdn="eim.example.test", eim_transaction_id=transaction_id)
        seed = provider.initiate_authentication(InitiateAuthenticationRequest(
            euicc_challenge=_b64(b"\x01" * 16), euicc_info1=_b64(bytes.fromhex("BF2000")), smdp_address=""))
        self.assertEqual((seed.transaction_id, seed.matching_id), (SMDP_TX.hex().upper(), "MID-9"))
        self.assertEqual(base64.b64decode(seed.server_signature1), b"\x05" * 64)
        # The SM-DP+ certificate is checked against the trust of the host it names.
        self.assertEqual(client_object.base_url, "https://smdpp.example.test")
        client = provider.authenticate_client(AuthenticateClientRequest(
            transaction_id=seed.transaction_id,
            authenticate_server_response=_b64(bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")),
            smdp_address=""))
        self.assertEqual(base64.b64decode(client.smdp_signature2), tlv(b"\x5F\x37", b"\x06" * 64))
        package = provider.get_bound_profile_package(GetBoundProfilePackageRequest(
            transaction_id=seed.transaction_id,
            prepare_download_response=_b64(bytes.fromhex("BF2117A115801000112233445566778899AABBCCDDEEFF02017F")),
            smdp_address=""))
        self.assertEqual(base64.b64decode(package.bound_profile_package)[:2], b"\xBF\x36")
        self.assertEqual(provider.cancel_session(CancelSessionRequest(
            transaction_id=seed.transaction_id, cancel_session_response=_b64(bytes.fromhex("BF4103810105")))), {})


def _raw_signature(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """An eUICC signature as the card returns it: r || s, 32 bytes each."""
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


SIGNING_PKID = b"\xF5" * 20
EUICC_INFO1 = tlv(b"\xBF\x20", tlv(b"\x82", bytes.fromhex("020300")) + tlv(b"\xA9", tlv(b"\x04", SIGNING_PKID))
                  + tlv(b"\xAA", tlv(b"\x04", SIGNING_PKID)))
OLD_EXT, NEW_EXT = bytes.fromhex("810100820400010000"), bytes.fromhex("8101008204000100FF8302F000")


def _euicc_info2(ext_card_resource: bytes) -> bytes:
    return tlv(b"\xBF\x22", tlv(b"\x81", bytes.fromhex("020300")) + tlv(b"\x82", bytes.fromhex("020300"))
               + tlv(b"\x84", ext_card_resource) + tlv(b"\xA9", tlv(b"\x04", SIGNING_PKID)))


# 8988201234567890123 in EF.ICCID order; profileOwner 001/01 (TS 24.008 packing).
ICCID_BCD = bytes.fromhex("988802214365870921F3")
OWNER = tlv(b"\xB7", tlv(b"\x80", bytes.fromhex("00F110")))
# PPR2 set (SGP.22 v3.1 §2.4a.1.1); notificationInstall goes to notify.example.test.
METADATA = tlv(b"\xBF\x25", tlv(b"\x5A", ICCID_BCD) + tlv(b"\x91", b"Test SP") + tlv(b"\x92", b"Test profile")
               + tlv(b"\xB6", tlv(b"\x30", tlv(b"\x80", bytes.fromhex("0780")) + tlv(b"\x81", b"notify.example.test")))
               + OWNER + tlv(b"\x99", bytes.fromhex("0520")))
# 2.999.10, the OID of the stub's certificate (X.690 §8.19).
SMDP_OID = bytes.fromhex("88370A")


def _rat(mcc_mnc: bytes) -> bytes:
    """The RulesAuthorisationTable the engine keeps: PPR2 allowed for one Profile Owner."""
    rule = tlv(b"\x80", bytes.fromhex("0520")) + tlv(b"\xA1", tlv(b"\x30", tlv(b"\x80", mcc_mnc))) + tlv(b"\x82", bytes.fromhex("0700"))
    return tlv(b"\x30", tlv(b"\x30", rule))


def _bpp(metadata: bytes) -> bytes:
    """A BoundProfilePackage whose sequenceOf88 carries *metadata* and an 8-byte C-MAC."""
    return tlv(b"\xBF\x36", tlv(b"\xBF\x23", b"\x00" * 4) + tlv(b"\xA0", tlv(b"\x87", b"\x00" * 4))
               + tlv(b"\xA1", tlv(b"\x88", metadata + b"\xEE" * 8)) + tlv(b"\xA3", tlv(b"\x86", b"\x00" * 4)))


class CompactSmdp(StubSmdp):
    """The stub with Profile Metadata, and a BPP that carries *carried*."""

    def __init__(self) -> None:
        super().__init__()
        self.carried = METADATA

    def authenticate_client(self, request: AuthenticateClientRequest) -> AuthenticateClientResponse:
        self.calls.append(("authenticate", request))
        return AuthenticateClientResponse(
            transaction_id=SMDP_TX.hex().upper(), smdp_signed2=_b64(tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x01", b"\x00"))),
            smdp_signature2=_b64(tlv(b"\x5F\x37", b"\x06" * 64)), smdp_certificate=_b64(self.certificate),
            profile_metadata=_b64(METADATA),
        )

    def get_bound_profile_package(self, request: GetBoundProfilePackageRequest) -> GetBoundProfilePackageResponse:
        self.calls.append(("bpp", request))
        return GetBoundProfilePackageResponse(bound_profile_package=_b64(_bpp(self.carried)))


class CompactRelayTests(unittest.TestCase):
    """The relay for the IPA Capabilities of the test card's IPAe (ipaFeatures '02CC': direct, indirect,
    eimProfileMetadataVerification, minimizeEsipaBytes): the compact forms of SGP.32 v1.3 §5.14 are
    restored and their eUICC signatures checked, and the answers carry what such an IPA expects."""

    CTX_PARAMS1 = tlv(b"\xA0", tlv(b"\x80", b"MID-9") + tlv(b"\xA1", tlv(b"\x80", bytes.fromhex("35290611"))))

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.engine = LocalEim(Path(folder.name))
        self.smdp = CompactSmdp()
        self.relay = IndirectRelay(self.engine, provider_factory=lambda address: self.smdp)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.euicc_certificate = _certificate(key=self.key, serial_number=EID)
        self.eum_certificate = _certificate()
        self.set_record(rat=_rat(bytes.fromhex("00F110")))

    def set_record(self, *, rat: bytes) -> None:
        record = self.engine.record(EID) or self.engine.register(EID)
        record.euicc_certificate = self.euicc_certificate
        record.eum_certificate = self.eum_certificate
        record.data.update({
            "ipa_capabilities_hex": "800202CC",
            "euicc_info1_hex": EUICC_INFO1.hex().upper(),
            "euicc_info2_hex": _euicc_info2(OLD_EXT).hex().upper(),
            "rat_hex": rat.hex().upper(),
            "profiles": [{"iccid": "89882012345678901234", "class": "test"}],
        })
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)

    def initiate(self, **params: object) -> esipa.InitiateAuthenticationOk:
        operation = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"activation_code": "1$smdpp.example.test$MID-9", "indirect": True, **params},
        )])[0]
        served = _serve_download(self.engine, "800202CC")
        self.assertEqual(served.operation.id, operation.id)
        self.operation = operation
        # No eimDownloadDataHandling: the trigger carries the Activation Code (§2.11.1.3).
        self.assertIn(b"1$smdpp.example.test$MID-9", served.package)
        # §5.14.1: euiccChallenge and eimTransactionId only, as the IPAe sends it.
        return esipa.decode_initiate_authentication_response(self.relay.handle(
            esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
                euicc_challenge=b"\x01" * 16, eim_transaction_id=bytes.fromhex(operation.transaction_id)))))

    def signed1(self) -> bytes:
        """EuiccSigned1 (SGP.22 v3.1 p.450) the card signs, with the extCardResource it reports now."""
        return tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x83", b"smdpp.example.test") + tlv(b"\x84", b"\x02" * 16)
                   + _euicc_info2(NEW_EXT) + self.CTX_PARAMS1)

    def authenticate(self, *, ext_card_resource: bytes = NEW_EXT) -> tuple[bytes, bytes]:
        signature = _raw_signature(self.key, self.signed1())
        compact = tlv(b"\xBF\x38", tlv(b"\xA2", tlv(b"\xA0", tlv(b"\x84", ext_card_resource) + tlv(b"\xA2", self.CTX_PARAMS1))
                                         + tlv(b"\x5F\x37", signature)))
        return self.relay.handle(esipa.encode_authenticate_client_request(SMDP_TX, compact)), signature

    def test_a_compact_download_runs_end_to_end(self) -> None:
        seed = self.initiate()
        # §5.14.1: no transactionId, the CI PKID truncated (one signing PKID: zero length), no Matching ID
        # for an IPA holding the Activation Code; euiccInfo1 comes from the record.
        self.assertEqual((seed.transaction_id, seed.euicc_ci_pkid, seed.matching_id, seed.ctx_params1), (b"", b"", "", b""))
        self.assertEqual(base64.b64decode(self.smdp.calls[0][1].euicc_info1), EUICC_INFO1)

        answer, signature1 = self.authenticate()
        self.assertEqual(base64.b64decode(self.smdp.calls[1][1].authenticate_server_response),
                         tlv(b"\xBF\x38", tlv(b"\xA0", self.signed1() + tlv(b"\x5F\x37", signature1)
                                                + self.euicc_certificate + self.eum_certificate)))
        client = esipa.decode_authenticate_client_response(answer)
        # §5.14.3: no transactionId, and no profileMetadata for an IPA that leaves the check to the eIM.
        self.assertEqual((client.transaction_id, client.profile_metadata), (b"", b""))

        otpk = tlv(b"\x5F\x49", b"\x04" + b"\x11" * 64)
        signed2 = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + otpk)
        # SGP.22 v3.1 §5.7.5 (p.328): euiccSignature2 covers euiccSigned2 and the smdpSignature2 data object.
        signature2 = _raw_signature(self.key, signed2 + tlv(b"\x5F\x37", b"\x06" * 64))
        compact = tlv(b"\xBF\x21", tlv(b"\xA2", tlv(b"\x30", otpk) + tlv(b"\x5F\x37", signature2)))
        reply = self.relay.handle(esipa.encode_get_bound_profile_package_request(SMDP_TX, compact))
        self.assertEqual(base64.b64decode(self.smdp.calls[2][1].prepare_download_response),
                         tlv(b"\xBF\x21", tlv(b"\xA0", signed2 + tlv(b"\x5F\x37", signature2))))
        # §5.14.2: no transactionId for this IPA.
        self.assertEqual(reply, tlv(b"\xBF\x3A", tlv(b"\xA0", _bpp(METADATA))))

        result_data = tlv(b"\xBF\x27", tlv(b"\x80", SMDP_TX) + tlv(b"\xBF\x2F", tlv(b"\x80", b"\x05")
                                                             + tlv(b"\x81", bytes.fromhex("0780")) + tlv(b"\x0C", b"notify.example.test")
                                                             + tlv(b"\x5A", ICCID_BCD))
                          + tlv(b"\x06", SMDP_OID) + tlv(b"\xA2", tlv(b"\xA0", tlv(b"\x4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                                                                     + tlv(b"\x04", bytes.fromhex("3007A0053003800100")))))
        signature_pir = _raw_signature(self.key, result_data)
        # §5.14.7: compactProfileInstallationResult with the 2-byte compactAid and the default simaResponse left out.
        compact_pir = tlv(b"\xA0", tlv(b"\xA0", tlv(b"\x80", SMDP_TX) + tlv(b"\x02", b"\x05")
                                       + tlv(b"\xA2", tlv(b"\xA0", tlv(b"\x4F", bytes.fromhex("0011")))))
                          + tlv(b"\x5F\x37", signature_pir))
        self.assertEqual(codec.notification_seq_number(compact_pir), 5)
        status, body = handle_asn1(self.engine, tlv(b"\xBF\x3D", tlv(b"\xA0", compact_pir)), relay=self.relay)
        self.assertEqual((status, body), (204, b""))
        self.assertEqual(self.smdp.calls[-1][0], "notification")
        self.assertEqual(base64.b64decode(self.smdp.calls[-1][1].pending_notification),
                         tlv(b"\xBF\x37", result_data + tlv(b"\x5F\x37", signature_pir)))
        # §3.2.3.2 step 23: that result closes the download; ProfileDownloadTriggerResult belongs to a
        # direct download (§2.11.2.3, p.44), so the eIM serves nothing more.
        closed = self.engine.operation(self.operation.id)
        self.assertEqual(closed.state, STATE_SUCCESS)
        self.assertNotIn("unverified", closed.flags)
        self.assertIsNone(self.engine.next_package(EID).operation)
        # An IPA that still sends ProfileDownloadTriggerResult: noted, not flagged late.
        trigger_result = tlv(b"\xBF\x54", tlv(b"\x82", bytes.fromhex(self.operation.transaction_id))
                             + tlv(b"\xBF\x37", result_data + tlv(b"\x5F\x37", signature_pir)))
        self.assertIsNone(self.engine.accept_result(EID, trigger_result).error)
        again = self.engine.operation(self.operation.id)
        self.assertEqual(again.state, STATE_SUCCESS)
        self.assertNotIn("late-result", again.flags)
        self.assertTrue(any("ProfileDownloadTriggerResult as well" in entry["event"] for entry in again.history))

    def test_a_full_result_that_does_not_verify_leaves_the_download_open(self) -> None:
        self.initiate()
        self.authenticate()
        forged = tlv(b"\xBF\x37", tlv(b"\xBF\x27", tlv(b"\x80", SMDP_TX)) + tlv(b"\x5F\x37", b"\x00" * 64))
        self.relay.forward_notification(forged)
        still = self.engine.operation(self.operation.id)
        self.assertFalse(still.final)
        self.assertTrue(any("does not verify" in entry["event"] for entry in still.history))

    def test_a_compact_answer_that_does_not_verify_is_refused(self) -> None:
        self.initiate()
        answer, _signature = self.authenticate(ext_card_resource=OLD_EXT)
        self.assertEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        self.assertEqual([call[0] for call in self.smdp.calls], ["initiate"])

    def test_the_eim_refuses_a_ppr_the_rat_does_not_allow(self) -> None:
        # §3.2.3.2 step 15 / §5.14.3: pprNotAllowed; the IPA then cancels with reason pprNotAllowed.
        self.set_record(rat=_rat(bytes.fromhex("99F999")))
        self.initiate()
        answer, _signature = self.authenticate()
        self.assertEqual(answer, esipa.encode_authenticate_client_error(50))
        cancel_signed = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x81", SMDP_OID) + tlv(b"\x82", b"\x03"))
        signature = _raw_signature(self.key, cancel_signed)
        compact = tlv(b"\xBF\x41", tlv(b"\xA2", tlv(b"\x30", tlv(b"\x80", b"\x03")) + tlv(b"\x5F\x37", signature)))
        self.assertEqual(self.relay.handle(esipa.encode_cancel_session_request(SMDP_TX, compact)),
                         esipa.encode_cancel_session_ok())
        # SGP.22 v3.1 p.451: EuiccCancelSessionSigned { transactionId, smdpOid, reason }.
        self.assertEqual(base64.b64decode(self.smdp.calls[-1][1].cancel_session_response),
                         tlv(b"\xBF\x41", tlv(b"\xA0", cancel_signed + tlv(b"\x5F\x37", signature))))

    def chain(self, *, variant_o: bool) -> bytes:
        """Give the record an EUM certificate issued by the CI RootCA (Variant O, SGP.22 v3.1 §4.5.2.0a) or by
        an EUM SubCA; returns the SubCA certificate, the rest of the chain in the second case."""
        self.eum_certificate = _certificate(issuer_key_id=CI_PKID if variant_o else SUBCA_KEY_ID)
        self.set_record(rat=_rat(bytes.fromhex("00F110")))
        return _certificate(subject_key_id=SUBCA_KEY_ID, issuer_key_id=CI_PKID)

    def relayed_response(self) -> bytes:
        """The AuthenticateServerResponse the relay sent to the SM-DP+."""
        return base64.b64decode(self.smdp.calls[-1][1].authenticate_server_response)

    def test_restore_omits_other_certs_in_chain_for_a_variant_o_chain(self) -> None:
        # SGP.22 v3.1 p.337: otherCertsInChain is omitted when the chain is Variant O.
        self.chain(variant_o=True)
        self.initiate()
        self.authenticate()
        relayed = self.relayed_response()
        self.assertTrue(relayed.endswith(self.eum_certificate))
        self.assertEqual(compact_forms.response_other_certs(relayed), b"")

    def test_restore_refuses_a_chain_beyond_variant_o_that_is_not_on_record(self) -> None:
        # The compact form (SGP.32 v1.3 §5.14.3) cannot carry the rest of the chain; without it on record the
        # SM-DP+ could not verify the eUICC certificate chain (SGP.22 v3.1 §5.7.13), so the answer is refused.
        self.chain(variant_o=False)
        self.initiate()
        answer, _signature = self.authenticate()
        self.assertEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        self.assertEqual([call[0] for call in self.smdp.calls], ["initiate"])
        events = [entry["event"] for entry in self.engine.operation(self.operation.id).history]
        self.assertTrue(any("otherCertsInChain" in event for event in events), events)

    def test_restore_appends_the_chain_on_record(self) -> None:
        subca = self.chain(variant_o=False)
        record = self.engine.record(EID)
        record.data["other_certs_in_chain_hex"] = subca.hex().upper()
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        self.initiate()
        answer, _signature = self.authenticate()
        self.assertNotEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        relayed = self.relayed_response()
        # SGP.22 v3.1 §5.7.13: euiccSigned1, euiccSignature1, euiccCertificate, nextCertInChain, otherCertsInChain
        self.assertTrue(relayed.endswith(self.eum_certificate + tlv(b"\xA0", subca)))
        self.assertEqual(compact_forms.response_other_certs(relayed), subca)

    def test_a_full_answer_teaches_the_eim_the_chain(self) -> None:
        subca = self.chain(variant_o=False)
        self.initiate()
        signature = _raw_signature(self.key, self.signed1())
        full = tlv(b"\xBF\x38", tlv(b"\xA0", self.signed1() + tlv(b"\x5F\x37", signature) + self.euicc_certificate
                                     + self.eum_certificate + tlv(b"\xA0", subca)))
        answer = self.relay.handle(esipa.encode_authenticate_client_request(SMDP_TX, full))
        self.assertNotEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        self.assertEqual(self.relayed_response(), full)
        self.assertEqual(self.engine.record(EID).data.get("other_certs_in_chain_hex"), subca.hex().upper())
        # the compact form of the same eUICC is restored with the chain learnt
        self.authenticate()
        self.assertEqual(compact_forms.response_other_certs(self.relayed_response()), subca)

    def require_confirmation_code(self) -> None:
        """The SM-DP+ answers AuthenticateClient with ccRequiredFlag TRUE (SGP.22 v3.1 §5.7.5)."""
        smdp = self.smdp

        def authenticate_client(request: AuthenticateClientRequest) -> AuthenticateClientResponse:
            smdp.calls.append(("authenticate", request))
            return AuthenticateClientResponse(
                transaction_id=SMDP_TX.hex().upper(),
                smdp_signed2=_b64(tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x01", b"\xFF"))),
                smdp_signature2=_b64(tlv(b"\x5F\x37", b"\x06" * 64)), smdp_certificate=_b64(smdp.certificate),
                profile_metadata=_b64(METADATA),
            )

        smdp.authenticate_client = authenticate_client  # type: ignore[method-assign]

    def test_the_eim_hands_the_ipa_the_hashed_confirmation_code(self) -> None:
        self.require_confirmation_code()
        self.initiate(confirmation_code="1234")
        answer, _signature = self.authenticate()
        # SGP.22 v3.1 §3.1.3.2 (p.104): SHA256(SHA256(UTF-8 Confirmation Code) | TransactionID)
        expected = hashlib.sha256(hashlib.sha256(b"1234").digest() + SMDP_TX).digest()
        self.assertEqual(esipa.decode_authenticate_client_response(answer).hash_cc, expected)
        # §5.14.2: compactEuiccSigned2 leaves hashCc out when the eIM sent it; the restore puts it back.
        otpk = tlv(b"\x5F\x49", b"\x04" + b"\x11" * 64)
        signed2 = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + otpk + tlv(b"\x04", expected))
        signature2 = _raw_signature(self.key, signed2 + tlv(b"\x5F\x37", b"\x06" * 64))
        compact = tlv(b"\xBF\x21", tlv(b"\xA2", tlv(b"\x30", otpk) + tlv(b"\x5F\x37", signature2)))
        self.relay.handle(esipa.encode_get_bound_profile_package_request(SMDP_TX, compact))
        self.assertEqual(base64.b64decode(self.smdp.calls[-1][1].prepare_download_response),
                         tlv(b"\xBF\x21", tlv(b"\xA0", signed2 + tlv(b"\x5F\x37", signature2))))
        # the code itself stays out of the operation listing
        self.assertNotIn("1234", str(self.engine.operation(self.operation.id).history))

    def test_a_required_confirmation_code_the_eim_lacks_is_left_to_the_ipa(self) -> None:
        self.require_confirmation_code()
        self.initiate()
        answer, _signature = self.authenticate()
        self.assertEqual(esipa.decode_authenticate_client_response(answer).hash_cc, b"")
        events = [entry["event"] for entry in self.engine.operation(self.operation.id).history]
        self.assertTrue(any("Confirmation Code required" in event for event in events), events)

    def test_a_package_with_other_metadata_is_refused(self) -> None:
        # §5.14.2: the Profile Metadata the eIM checked is the one the Bound Profile Package carries.
        self.smdp.carried = METADATA.replace(b"Test profile", b"Other profile")
        self.initiate()
        self.authenticate()
        otpk = tlv(b"\x5F\x49", b"\x04" + b"\x11" * 64)
        signature2 = _raw_signature(self.key, tlv(b"\x30", tlv(b"\x80", SMDP_TX) + otpk) + tlv(b"\x5F\x37", b"\x06" * 64))
        compact = tlv(b"\xBF\x21", tlv(b"\xA2", tlv(b"\x30", otpk) + tlv(b"\x5F\x37", signature2)))
        self.assertEqual(self.relay.handle(esipa.encode_get_bound_profile_package_request(SMDP_TX, compact)),
                         esipa.encode_get_bound_profile_package_error(50))


class StubSmds(StubSmdp):
    """An SM-DS: ES11 is bound as ES9+ (SGP.22 v3.1 p.397) and AuthenticateClient answers Event Records."""

    def __init__(self) -> None:
        super().__init__(address="smds.example.test", certificate=_certificate(oid="2.999.20"))
        self.events = [{"eventId": "EV-1", "rspServerAddress": "smdpp.example.test"}]
        self.fail = False

    def authenticate_client(self, request: AuthenticateClientRequest) -> AuthenticateClientResponse:
        self.calls.append(("authenticate", request))
        if self.fail:
            raise RuntimeError("SM-DS down")
        return AuthenticateClientResponse(transaction_id=SMDP_TX.hex().upper(), smdp_signed2="", smdp_signature2="",
                                          smdp_certificate="", event_entries=list(self.events))


class SmdsRelayTests(unittest.TestCase):
    """Event Retrieval by the eIM (SGP.32 v1.3 §3.9.2.2): the relay runs ES11' against the SM-DS, turns the
    Event Records into downloads and answers authenticateClientOkDSEsipa (§6.3.2.2)."""

    CTX_PARAMS1 = tlv(b"\xA0", tlv(b"\xA1", tlv(b"\x80", bytes.fromhex("35290611"))))

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.engine = LocalEim(Path(folder.name))
        self.smds = StubSmds()
        self.relay = IndirectRelay(self.engine, provider_factory=lambda address: self.smds)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.euicc_certificate = _certificate(key=self.key, serial_number=EID)
        record = self.engine.register(EID)
        record.euicc_certificate = self.euicc_certificate
        record.eum_certificate = _certificate()
        record.data.update({"ipa_capabilities_hex": "800202CC", "euicc_info1_hex": EUICC_INFO1.hex().upper(),
                            "euicc_info2_hex": _euicc_info2(OLD_EXT).hex().upper()})
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)

    def retrieve(self) -> bytes:
        self.operation = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": "smds.example.test", "indirect": True},
        )])[0]
        served = _serve_download(self.engine, "800202CC")
        self.assertEqual(served.operation.id, self.operation.id)
        # no eimDownloadDataHandling: the trigger carries contactSmds with the SM-DS address (§3.9.2.2 step 2)
        self.assertIn(b"smds.example.test", served.package)
        self.relay.handle(esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
            euicc_challenge=b"\x01" * 16, eim_transaction_id=bytes.fromhex(self.operation.transaction_id))))
        self.assertEqual(self.smds.calls[0][1].smdp_address, "smds.example.test")
        signed1 = tlv(b"\x30", tlv(b"\x80", SMDP_TX) + tlv(b"\x83", b"smds.example.test") + tlv(b"\x84", b"\x02" * 16)
                      + _euicc_info2(NEW_EXT) + self.CTX_PARAMS1)
        self.full = tlv(b"\xBF\x38", tlv(b"\xA0", signed1 + tlv(b"\x5F\x37", _raw_signature(self.key, signed1))
                                           + self.euicc_certificate + _certificate()))
        return self.relay.handle(esipa.encode_authenticate_client_request(SMDP_TX, self.full))

    def downloads_from_events(self) -> list:
        return [op for op in self.engine.operations()
                if op.type == "PROFILE_DOWNLOAD_TRIGGER" and op.params.get("event_id")]

    def test_an_event_becomes_a_download_whose_trigger_rides_in_the_answer(self) -> None:
        answer = esipa.decode_authenticate_client_ds_response(self.retrieve())
        self.assertEqual(answer.transaction_id, SMDP_TX)
        # SGP.22 v3.1 §3.1.3 (p.101): the EventID is the Matching ID; §3.6.2 step 10: one download per record
        download, = self.downloads_from_events()
        self.assertEqual(download.params["activation_code"], "1$smdpp.example.test$EV-1")
        self.assertEqual((download.params["event_id"], download.params["smds_oid"], download.params["indirect"]),
                         ("EV-1", "2.999.20", True))
        self.assertEqual(answer.profile_download_trigger[:2], b"\xBF\x54")
        self.assertIn(b"1$smdpp.example.test$EV-1", answer.profile_download_trigger)
        self.assertIn(tlv(b"\x82", bytes.fromhex(download.transaction_id)), answer.profile_download_trigger)
        self.assertIsNotNone(self.engine.operation(download.id).served_at)
        retrieval = self.engine.operation(self.operation.id)
        self.assertEqual(retrieval.state, STATE_SUCCESS)
        self.assertEqual(retrieval.result["events"], [{"eventId": "EV-1", "rspServerAddress": "smdpp.example.test"}])
        # the RSP session with the SM-DS ended with the answer (§3.9.2.2 step 14)
        self.assertEqual(self.relay.handle(esipa.encode_authenticate_client_request(SMDP_TX, self.full)),
                         esipa.encode_authenticate_client_error(10))

    def test_no_event_answers_the_transaction_id_alone(self) -> None:
        self.smds.events = []
        answer = esipa.decode_authenticate_client_ds_response(self.retrieve())
        self.assertEqual((answer.transaction_id, answer.profile_download_trigger), (SMDP_TX, b""))
        self.assertEqual(self.downloads_from_events(), [])
        self.assertEqual(self.engine.operation(self.operation.id).state, STATE_SUCCESS)

    def test_an_smds_failure_fails_the_retrieval(self) -> None:
        self.smds.fail = True
        self.assertEqual(self.retrieve(), esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        failed = self.engine.operation(self.operation.id)
        self.assertEqual(failed.state, STATE_ERROR)
        self.assertIn("SM-DS down", failed.error)
        self.assertEqual(self.downloads_from_events(), [])


class QueueTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.engine = LocalEim(Path(folder.name))

    def test_an_sm_ds_retrieval_queues_through_the_relay(self) -> None:
        # SGP.32 v1.3 §3.9.2.2: the eIM retrieves the events itself; the trigger names the SM-DS (step 2)
        operation = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": "smds.example.test", "indirect": True},
        )])[0]
        self.assertEqual(operation.params["contact_smds"], True)
        served = _serve_download(self.engine, "800202CC")
        self.assertEqual(served.operation.id, operation.id)
        self.assertIn(b"smds.example.test", served.package)

    def test_an_indirect_trigger_carries_the_code_unless_the_ipa_handles_download_data(self) -> None:
        # SGP.32 v1.3 §2.11.1.3 (p.38): the empty trigger "If and only if" eimDownloadDataHandling;
        # an IPA that gives no IPA Capabilities gets the code as well.
        code = "1$smdpp.example.test$MID-9"
        for capabilities, empty in (("800206C0", False), ("800205E0", True), ("", False)):
            with self.subTest(capabilities=capabilities):
                operation = self.engine.submit([OperationRequest(
                    eid=EID, type="PROFILE_DOWNLOAD_TRIGGER", params={"activation_code": code, "indirect": True},
                )])[0]
                served = _serve_download(self.engine, capabilities)
                self.assertEqual(served.operation.id, operation.id)
                transaction_id = bytes.fromhex(operation.transaction_id)
                if empty:
                    self.assertEqual(served.package, tlv(b"\xBF\x54", tlv(b"\x82", transaction_id)))
                else:
                    self.assertIn(code.encode(), served.package)
                self.engine.cancel(operation.id)

    def test_the_ipa_capabilities_are_asked_for_before_each_download(self) -> None:
        for round_number in (1, 2):
            with self.subTest(download=round_number):
                operation = self.engine.submit([OperationRequest(
                    eid=EID, type="PROFILE_DOWNLOAD_TRIGGER", params={"activation_code": "1$smdpp.example.test$MID-9"},
                )])[0]
                first = self.engine.next_package(EID)
                self.assertTrue(first.operation.system)
                # tagList '5C' in IpaEuiccData order: what the record lacks, and 'A8' every time.
                self.assertIn(bytes.fromhex("5C08BF20BF22A5A6A8A9"), first.package)
                answer = tlv(b"\xBF\x52", tlv(b"\xA0", tlv(b"\x87", bytes.fromhex(first.operation.transaction_id))
                                              + tlv(b"\xA8", bytes.fromhex("800206C0"))))
                self.assertIsNone(self.engine.accept_result(EID, answer).error)
                self.assertEqual(self.engine.record(EID).data["ipa_capabilities_hex"], "800206C0")
                self.assertEqual(self.engine.next_package(EID).operation.id, operation.id)
                self.engine.cancel(operation.id)

    def test_capabilities_asked_for_and_not_given_are_dropped(self) -> None:
        _declare_capabilities(self.engine, "800205E0")
        operation = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER", params={"activation_code": "1$smdpp.example.test$MID-9", "indirect": True},
        )])[0]
        served = _serve_download(self.engine, "")
        self.assertEqual(served.operation.id, operation.id)
        self.assertNotIn("ipa_capabilities_hex", self.engine.record(EID).data)
        self.assertIn(b"1$smdpp.example.test$MID-9", served.package)

    def test_ipa_capabilities_without_the_bits_warn(self) -> None:
        record = self.engine.register(EID)
        # ipaFeatures direct and indirect only, as an IpaEuiccData answer would record them.
        record.data["ipa_capabilities_hex"] = "800206C0"
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        plan = self.engine.plan([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"activation_code": "1$smdpp.example.test$MID-9", "indirect": True},
        )])[0]
        self.assertIn("indirect", plan.description)
        self.assertTrue(any("eimDownloadDataHandling" in warning for warning in plan.warnings))


class SmdpEidTests(unittest.TestCase):
    def test_the_eid_comes_from_the_euicc_certificate(self) -> None:
        signed1 = tlv(b"\x30", tlv(b"\x80", TX))
        response = tlv(b"\xBF\x38", tlv(b"\xA0", signed1 + tlv(b"\x5F\x37", b"\x00" * 64)
                                       + _certificate(serial_number=EID) + _certificate()))
        self.assertEqual(euicc_eid(response), EID)
        self.assertEqual(euicc_eid(b""), "")


if __name__ == "__main__":
    unittest.main()
