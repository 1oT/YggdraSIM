# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DS in the Local eIM service: both ES11 bindings, the listeners, the relay and the SM-DP+.

ES11 shares the ES9+ paths and the 'A2' wrapper (SGP.22 v3.1 §6.5.2 Table 57,
§6.6.2.6-§6.6.2.8), so these tests hold the dispatch to its rule: a request is
the SM-DS's by the address it names, by who handed out its transactionId, or
by the CheckEvent tag, and everything else still reaches the SM-DP+. The
ASN.1 vectors were written by the SGP.22 v3.1 module of the pinned pySim.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import socket
import ssl
import tempfile
import types
import unittest
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from SCP11.eim_local.engine import es11_binding, smdp_tls, smds
from SCP11.eim_local.engine import server as service_runner
from SCP11.eim_local.engine.esipa import LocalEimHttpServer, default_relay
from SCP11.eim_local.engine.indirect import IndirectRelay, LocalSmdpEs9, LocalSmdsEs11
from SCP11.eim_local.engine.server import STATUS_FILE, local_route
from SCP11.eim_local.engine.service import (
    EVENT_RETRIEVAL_CLOSED_FLAG,
    SETTING_SMDS_ADDRESS,
    LocalEim,
    LocalEimError,
    OperationRequest,
)
from SCP11.eim_local.engine.smdp import LocalSmdp, cancel_reason
from SCP11.eim_local.engine.store import STATE_SUCCESS
from SCP11.local_access.cert_store import LocalSgp26CertStore
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from tests.smds_support import (
    DS_AUTH_ROLE,
    EID,
    OTHER_EID,
    SMDP_ADDRESS,
    SMDS_ADDRESS,
    SMDS_OID,
    Pki,
    ScriptedEuicc,
    _name,
    der,
    issue,
)

tlv = esipa.tlv
TX = bytes(range(1, 17))
INITIATE = "/gsma/rsp2/es9plus/initiateAuthentication"
AUTHENTICATE = "/gsma/rsp2/es9plus/authenticateClient"


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class StubSmdp:
    """What the listener and the relay call on a ``LocalSmdp``, with fixed answers and a record of the calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lines: list[str] = []
        self.log = self.lines.append
        self.smds: Any = None

    def address(self) -> str:
        return SMDP_ADDRESS

    def host(self) -> str:
        return SMDP_ADDRESS

    def transaction(self, transaction_id: bytes) -> dict[str, Any] | None:
        return {} if bytes(transaction_id) == TX else None

    def handle(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        name = path.rsplit("/", 1)[-1]
        self.calls.append((name, dict(payload)))
        if name == "initiateAuthentication":
            signed1 = tlv(b"\x30", tlv(b"\x80", TX) + tlv(b"\x81", b"\x01" * 16) + tlv(b"\x83", SMDP_ADDRESS.encode())
                          + tlv(b"\x84", b"\x02" * 16))
            return {"transactionId": _b64(TX), "serverSigned1": _b64(signed1), "serverSignature1": _b64(b"\x05" * 64),
                    "serverCertificate": _b64(tlv(b"\x30", b"\x00")), "euiccCiPKIdToBeUsed": ("F5" * 20)}
        return {}


class _Service(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.pki = Pki()

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.engine = LocalEim(self.directory)
        material = self.pki.material()
        self.smds = smds.LocalSmds(self.directory, store=self.engine.store, material_factory=lambda: material)
        self.euicc = ScriptedEuicc(self.pki)
        self.smdp = StubSmdp()


class VectorTests(unittest.TestCase):
    """The ES11 answers of the ASN.1 binding against encodings of the compiled SGP.22 v3.1 module."""

    EVENTS = [("EVENT-1", "smdpp.example.test"), ("EVENT-2", "smdp2.example.test")]

    def test_authenticate_client_response_es11(self) -> None:
        # RemoteProfileProvisioningResponse 'A2' { authenticateClientResponseEs11 'BF40' { authenticateClientOk
        # 'A0' { transactionId '80', eventEntries 'A1' { EventRecord { eventId '80', rspServerAddress '81' } } } } }
        encoded = es9_asn1.encode_authenticate_client_es11_ok(TX, self.EVENTS)
        self.assertEqual(encoded.hex().upper(), (
            "A257BF4054A05280100102030405060708090A0B0C0D0E0F10A13E"
            "301D80074556454E542D318112736D6470702E6578616D706C652E74657374"
            "301D80074556454E542D328112736D6470322E6578616D706C652E74657374"))
        self.assertEqual(es9_asn1.decode_authenticate_client_es11_response(encoded), (TX, self.EVENTS))
        empty = es9_asn1.encode_authenticate_client_es11_ok(TX, [])
        self.assertEqual(empty.hex().upper(), "A219BF4016A01480100102030405060708090A0B0C0D0E0F10A100")
        self.assertEqual(es9_asn1.decode_authenticate_client_es11_response(empty), (TX, []))

    def test_authenticate_client_error(self) -> None:
        self.assertEqual(es9_asn1.encode_authenticate_client_es11_error(6).hex().upper(), "A206BF4003810106")
        self.assertEqual(es9_asn1.encode_authenticate_client_es11_error(127).hex().upper(), "A206BF400381017F")
        with self.assertRaises(es9_asn1.Es9Asn1Error) as caught:
            es9_asn1.decode_authenticate_client_es11_response(es9_asn1.encode_authenticate_client_es11_error(6))
        self.assertEqual((caught.exception.code, caught.exception.name), (6, "eventIdUnknown"))

    def test_check_event(self) -> None:
        request = es9_asn1.encode_check_event_request(bytes(16), SMDS_ADDRESS)
        self.assertEqual(request.hex().upper(),
                         "A228BF46258010000000000000000000000000000000008111736D64732E6578616D706C652E74657374")
        self.assertEqual(es9_asn1.decode_check_event_request(es9_asn1.unwrap(request)), (bytes(16), SMDS_ADDRESS))
        self.assertEqual(es9_asn1.encode_check_event_error(2).hex().upper(), "A206BF4603810102")
        self.assertEqual(es9_asn1.encode_check_event_ok(True).hex().upper(), "A208BF4605A0038001FF")
        self.assertIs(es9_asn1.decode_check_event_response(es9_asn1.encode_check_event_ok(True)), True)
        self.assertIs(es9_asn1.decode_check_event_response(es9_asn1.encode_check_event_ok(False)), False)
        with self.assertRaises(es9_asn1.Es9Asn1Error) as caught:
            es9_asn1.decode_check_event_response(es9_asn1.encode_check_event_error(2))
        self.assertEqual((caught.exception.code, caught.exception.name), (2, "eventCheckingNotSupported"))

    def test_the_wrapper_carries_the_two_es11_tags(self) -> None:
        # RemoteProfileProvisioningRequest lists checkEventRequest [70], the Response
        # authenticateClientResponseEs11 [64] and checkEventResponse [70] (§6.6.1)
        self.assertIn(es9_asn1.TAG_CHECK_EVENT, es9_asn1.FUNCTION_TAGS)
        self.assertIn(es9_asn1.TAG_AUTHENTICATE_CLIENT_ES11, es9_asn1.FUNCTION_TAGS)
        self.assertEqual((es9_asn1.TAG_AUTHENTICATE_CLIENT_ES11, es9_asn1.TAG_CHECK_EVENT), (b"\xBF\x40", b"\xBF\x46"))

    def test_answers_that_do_not_read_are_refused_not_crashed_on(self) -> None:
        broken = (b"", b"\xA2", b"\xA2\x82", b"\xA2\x05\xBF\x40\x10", b"\xA2\x03\xBF\x40\x00", b"\xA2\x05\xBF\x40\x02\xA0\x00",
                  bytes.fromhex("A208BF4005A003A10130"), bytes.fromhex("A206BF4003810100")[:-1])
        for data in broken:
            with self.subTest(data=data.hex()):
                with self.assertRaises(es9_asn1.Es9Asn1Error):
                    es9_asn1.decode_authenticate_client_es11_response(data)
                with self.assertRaises(es9_asn1.Es9Asn1Error):
                    es9_asn1.decode_check_event_response(data)
        for function in (b"", b"\xBF", b"\xBF\x46", b"\xBF\x46\x82", b"\xBF\x46\x05\x80\x10", b"\xBF\x46\x02\x80\x00"):
            with self.subTest(function=function.hex()):
                with self.assertRaises(es9_asn1.Es9Asn1Error):
                    es9_asn1.decode_check_event_request(function)
        for response in (b"", b"\xBF", b"\xBF\x41", b"\xBF\x41\x82", b"\xBF\x41\x05\xA0\x10\x30", b"\x30\x00"):
            with self.subTest(response=response.hex()):
                self.assertIsNone(cancel_reason(response))


class BindingTests(_Service):
    """``es11_binding``: which requests the SM-DS claims, and its answers in the ASN.1 binding."""

    def initiate(self, address: str = SMDS_ADDRESS) -> esipa.InitiateAuthenticationOk:
        body = es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, address, self.pki.euicc_info1())
        self.assertTrue(es11_binding.claims_asn1(self.smds, body))
        status, answer = es11_binding.handle_es11_asn1(self.smds, body)
        self.assertEqual(status, 200)
        return es9_asn1.decode_initiate_authentication_response(answer)

    def response_for(self, ok: esipa.InitiateAuthenticationOk, **script: Any) -> bytes:
        return self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)}, **script)

    def test_event_retrieval_in_the_asn1_binding(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        ok = self.initiate("SMDS.example.test")
        self.assertEqual(ok.server_certificate, der(self.pki.ds))
        self.assertEqual(ok.euicc_ci_pkid, self.pki.ci_pkid)
        self.assertEqual(len(ok.server_signature1), 64)
        body = es9_asn1.encode_authenticate_client_request(ok.transaction_id, self.response_for(ok))
        self.assertTrue(es11_binding.claims_asn1(self.smds, body))
        self.assertEqual(es11_binding.function_name(body), "AuthenticateClient")
        status, answer = es11_binding.handle_es11_asn1(self.smds, body)
        self.assertEqual(status, 200)
        self.assertEqual(es9_asn1.decode_authenticate_client_es11_response(answer),
                         (ok.transaction_id, [("EVENT-1", SMDP_ADDRESS)]))
        # the session ended: the same request is no longer the SM-DS's
        self.assertFalse(es11_binding.claims_asn1(self.smds, body))

    def test_a_refusal_is_the_error_integer_of_the_function(self) -> None:
        ok = self.initiate()
        body = es9_asn1.encode_authenticate_client_request(ok.transaction_id,
                                                           self.response_for(ok, matching_id="NO-SUCH-EVENT"))
        _status, answer = es11_binding.handle_es11_asn1(self.smds, body)
        self.assertEqual(answer, es9_asn1.encode_authenticate_client_es11_error(6))
        other = Pki()
        body = es9_asn1.encode_initiate_authentication_request(
            self.euicc.challenge, SMDS_ADDRESS, self.pki.euicc_info1(signing=(other.ci_pkid,)))
        _status, answer = es11_binding.handle_es11_asn1(self.smds, body)
        self.assertEqual(answer, es9_asn1.encode_initiate_authentication_error(3))

    def test_the_lpa_rsp_capability_of_the_request_is_carried_through(self) -> None:
        # InitiateAuthenticationRequest lpaRspCapability [5] is '85' on the wire
        request = es9_asn1.unwrap(es9_asn1.encode_initiate_authentication_request(
            self.euicc.challenge, SMDS_ADDRESS, self.pki.euicc_info1()))
        _tag, value, _raw = es9_asn1._single(request, "request")
        body = es9_asn1.wrap(tlv(b"\xBF\x39", value + tlv(b"\x85", bytes.fromhex("0204"))))
        _status, answer = es11_binding.handle_es11_asn1(self.smds, body)
        ok = es9_asn1.decode_initiate_authentication_response(answer)
        changed = es9_asn1.encode_authenticate_client_request(
            ok.transaction_id, self.response_for(ok, lpa_rsp_capability=bytes.fromhex("0780")))
        _status, answer = es11_binding.handle_es11_asn1(self.smds, changed)
        self.assertEqual(answer, es9_asn1.encode_authenticate_client_es11_error(11))

    def test_check_event_is_always_the_sm_dss_and_always_unsupported(self) -> None:
        body = es9_asn1.encode_check_event_request(bytes(16), "another.example.test")
        self.assertTrue(es11_binding.claims_asn1(self.smds, body))
        self.assertEqual(es11_binding.handle_es11_asn1(self.smds, body), (200, es9_asn1.encode_check_event_error(2)))
        # a CheckEvent that does not read gets the same answer (§5.8.3: the refusal comes first)
        self.assertEqual(es11_binding.handle_es11_asn1(self.smds, es9_asn1.wrap(tlv(b"\xBF\x46", b""))),
                         (200, es9_asn1.encode_check_event_error(2)))

    def test_what_the_sm_ds_does_not_claim(self) -> None:
        other = es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, SMDP_ADDRESS,
                                                                self.pki.euicc_info1())
        unknown = es9_asn1.encode_authenticate_client_request(TX, tlv(b"\xBF\x38", b""))
        package = es9_asn1.encode_get_bound_profile_package_request(TX, tlv(b"\xBF\x21", b""))
        for body in (other, unknown, package, b"", b"\xA2", b"\xA2\x05\xBF\x39", es9_asn1.wrap(b"\x30\x00")):
            with self.subTest(body=body.hex()[:24]):
                self.assertFalse(es11_binding.claims_asn1(self.smds, body))
        self.assertFalse(es11_binding.claims_asn1(None, es9_asn1.encode_check_event_request(bytes(16), SMDS_ADDRESS)))
        self.assertFalse(es11_binding.claims_json(None, INITIATE, {"smdpAddress": SMDS_ADDRESS}))
        self.assertFalse(es11_binding.claims_json(self.smds, INITIATE, {"smdpAddress": SMDP_ADDRESS}))
        self.assertFalse(es11_binding.claims_json(self.smds, INITIATE, {}))
        self.assertFalse(es11_binding.claims_json(self.smds, AUTHENTICATE, {"transactionId": TX.hex()}))
        self.assertFalse(es11_binding.claims_json(self.smds, AUTHENTICATE, {"transactionId": "not hex"}))
        self.assertFalse(es11_binding.claims_json(self.smds, "/gsma/rsp2/es9plus/getBoundProfilePackage",
                                                  {"smdpAddress": SMDS_ADDRESS}))
        self.assertTrue(es11_binding.claims_json(self.smds, INITIATE + "/", {"smdpAddress": "SMDS.EXAMPLE.TEST"}))


class HttpTests(_Service):
    """One listener, two servers: what goes to the SM-DS and what stays with the SM-DP+."""

    def setUp(self) -> None:
        super().setUp()
        self.lines: list[str] = []
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=self.smdp, smds=self.smds,
                                         log=self.lines.append)
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)

    def _post(self, path: str, body: bytes, content_type: str) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(self.server.url + path, data=body, method="POST",
                                         headers={"Content-Type": content_type, "User-Agent": "gsma-rsp-lpad"})
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            return response.status, {key.lower(): value for key, value in response.headers.items()}, response.read()

    def post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        status, headers, body = self._post(path, json.dumps(payload).encode("utf-8"), "application/json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-admin-protocol"], "gsma/rsp/v2.1.0")
        return json.loads(body)

    def post_asn1(self, body: bytes) -> bytes:
        status, headers, answer = self._post("/gsma/rsp2/asn1", body, "application/x-gsma-rsp-asn1")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/x-gsma-rsp-asn1")
        return answer

    def test_the_server_ties_the_sm_dp_to_the_sm_ds(self) -> None:
        self.assertIs(self.server.smds, self.smds)
        self.assertIs(self.smdp.smds, self.smds)
        self.assertIs(self.smds.smdp, self.smdp)
        self.assertIs(self.server.relay.smds, self.smds)
        self.assertEqual(self.server.status()["smds_address"], SMDS_ADDRESS)

    def test_event_retrieval_in_the_json_binding_on_the_es9_paths(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        answer = self.post_json(INITIATE, self.euicc.initiate(
            euiccChallenge=_b64(self.euicc.challenge), euiccInfo1=_b64(self.pki.euicc_info1())))
        self.assertEqual(answer["header"], {"functionExecutionStatus": {"status": "Executed-Success"}})
        self.assertEqual(base64.b64decode(answer["serverCertificate"]), der(self.pki.ds))
        result = self.post_json(AUTHENTICATE, {
            "transactionId": answer["transactionId"],
            "authenticateServerResponse": _b64(self.euicc.respond(answer)),
        })
        # SGP.22 v3.1 §6.5.2.12: transactionId and eventEntries of EVENT_RECORD
        self.assertEqual(result["eventEntries"], [{"eventId": "EVENT-1", "rspServerAddress": SMDP_ADDRESS}])
        self.assertEqual(result["transactionId"], answer["transactionId"])
        self.assertEqual(result["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(self.smdp.calls, [])
        notes = [record.note for record in self.engine.store.traffic(limit=10)]
        self.assertEqual(sorted(notes), ["ES11 authenticateClient", "ES11 initiateAuthentication"])

    def test_a_refusal_in_the_json_binding_carries_the_status_code_pair(self) -> None:
        answer = self.post_json(INITIATE, self.euicc.initiate())
        result = self.post_json(AUTHENTICATE, {
            "transactionId": answer["transactionId"],
            "authenticateServerResponse": _b64(self.euicc.respond(answer, matching_id="NO-SUCH-EVENT")),
        })
        status = result["header"]["functionExecutionStatus"]
        self.assertEqual(status["status"], "Failed")
        self.assertEqual((status["statusCodeData"]["subjectCode"], status["statusCodeData"]["reasonCode"]),
                         ("8.9.5", "3.9"))
        self.assertNotIn("eventEntries", result)
        self.assertTrue(any("ES11 authenticateClient refused" in line for line in self.lines), self.lines)

    def test_another_address_and_another_transaction_stay_with_the_sm_dp(self) -> None:
        self.post_json(INITIATE, self.euicc.initiate(smdpAddress=SMDP_ADDRESS))
        self.post_json(AUTHENTICATE, {"transactionId": TX.hex().upper(), "authenticateServerResponse": "BF3800"})
        self.post_json("/gsma/rsp2/es9plus/cancelSession", {"transactionId": TX.hex().upper(),
                                                            "cancelSessionResponse": "BF4100"})
        self.assertEqual([name for name, _payload in self.smdp.calls],
                         ["initiateAuthentication", "authenticateClient", "cancelSession"])
        self.assertEqual(self.smds._transactions, {})

    def test_event_retrieval_in_the_asn1_binding_on_the_shared_path(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-2")
        ok = es9_asn1.decode_initiate_authentication_response(self.post_asn1(
            es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, SMDS_ADDRESS,
                                                            self.pki.euicc_info1())))
        response = self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)})
        answer = self.post_asn1(es9_asn1.encode_authenticate_client_request(ok.transaction_id, response))
        self.assertEqual(es9_asn1.decode_authenticate_client_es11_response(answer),
                         (ok.transaction_id, [("EVENT-1", SMDP_ADDRESS), ("EVENT-2", "smdp2.example.test")]))
        self.assertEqual(self.smdp.calls, [])
        self.assertEqual(self.post_asn1(es9_asn1.encode_check_event_request(bytes(16), SMDS_ADDRESS)),
                         es9_asn1.encode_check_event_error(2))
        self.assertTrue(any("ES11 ASN.1 CheckEvent" in line for line in self.lines), self.lines)

    def test_the_traffic_view_names_the_interface_the_listener_noted(self) -> None:
        from SCP11.eim_local.engine import traffic

        self.post_asn1(es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, SMDS_ADDRESS,
                                                                       self.pki.euicc_info1()))
        self.post_asn1(es9_asn1.encode_check_event_request(bytes(16), SMDS_ADDRESS))
        self.post_asn1(es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, SMDP_ADDRESS,
                                                                       self.pki.euicc_info1()))
        self.post_json(INITIATE, self.euicc.initiate())
        records = sorted(self.engine.store.traffic(limit=10), key=lambda record: record.id)
        summaries = [traffic.describe_record(record).summary for record in records]
        # the bytes of an InitiateAuthentication do not say which server it was for: the note does
        self.assertEqual(summaries[0], "ES11 InitiateAuthenticationRequest -> InitiateAuthenticationResponse")
        self.assertEqual(summaries[1], "ES11 CheckEventRequest -> CheckEventResponse")
        self.assertEqual(summaries[2], "ES9+ InitiateAuthenticationRequest -> InitiateAuthenticationResponse")
        self.assertTrue(summaries[3].startswith("ES11 initiateAuthentication ("), summaries[3])
        rows = traffic.describe_record(records[0]).rows
        self.assertTrue(rows[0].value.startswith("ES11 over the ASN.1 binding"), rows[0].value)

    def test_an_asn1_request_for_the_sm_dp_still_reaches_it(self) -> None:
        self.post_asn1(es9_asn1.encode_initiate_authentication_request(self.euicc.challenge, SMDP_ADDRESS,
                                                                       self.pki.euicc_info1()))
        self.assertEqual([name for name, _payload in self.smdp.calls], ["initiateAuthentication"])

    def test_a_listener_without_an_sm_ds_answers_as_before(self) -> None:
        plain = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=StubSmdp())
        plain.start_in_thread()
        self.addCleanup(plain.stop)
        self.assertIsNone(plain.smds)
        request = urllib.request.Request(
            plain.url + INITIATE, data=json.dumps(self.euicc.initiate()).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            self.assertEqual(response.status, 200)
        self.assertEqual([name for name, _payload in plain.smdp.calls], ["initiateAuthentication"])


class RelayTests(_Service):
    """Event Retrieval by the eIM against the local SM-DS, then the download at the local SM-DP+ (SGP.32 v1.3 §3.9.2.2)."""

    def setUp(self) -> None:
        super().setUp()
        self.relay = IndirectRelay(self.engine, self.smdp, smds=self.smds)
        record = self.engine.register(EID)
        record.euicc_certificate = der(self.pki.euicc)
        record.eum_certificate = der(self.pki.eum)
        # IpaCapabilities with indirectRspServerCommunication alone: full forms, the trigger names the SM-DS
        record.data.update({"ipa_capabilities_hex": "80020640",
                            "euicc_info1_hex": self.pki.euicc_info1().hex().upper()})
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)

    def serve(self) -> Any:
        """The next package as an IPA meets it: the eIM's own IPA data request is answered first."""
        served = self.engine.next_package(EID)
        if served.operation is not None and served.operation.system and served.package[:2] == b"\xBF\x52":
            members = tlv(b"\x87", bytes.fromhex(served.operation.transaction_id)) + tlv(b"\xA8", bytes.fromhex("80020640"))
            self.assertIsNone(self.engine.accept_result(EID, tlv(b"\xBF\x52", tlv(b"\xA0", members))).error)
            served = self.engine.next_package(EID)
        return served

    def test_the_two_local_servers_are_reached_in_process(self) -> None:
        self.assertIsInstance(self.relay._provider_for("SMDS.example.test"), LocalSmdsEs11)
        self.assertIsInstance(self.relay._provider_for(SMDP_ADDRESS), LocalSmdpEs9)
        self.smds.set_address("smds2.example.test")
        self.assertIsInstance(self.relay._provider_for("smds2.example.test"), LocalSmdsEs11)
        self.assertNotIsInstance(self.relay._provider_for(SMDS_ADDRESS), (LocalSmdsEs11, LocalSmdpEs9))

    def test_a_registered_event_becomes_a_download_at_the_local_sm_dp(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-OTHER")
        retrieval = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": SMDS_ADDRESS, "indirect": True})])[0]
        served = self.serve()
        self.assertEqual(served.operation.id, retrieval.id)
        self.assertIn(SMDS_ADDRESS.encode(), served.package)
        answer = self.relay.handle(esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
            euicc_challenge=self.euicc.challenge, euicc_info1=self.pki.euicc_info1(),
            eim_transaction_id=bytes.fromhex(retrieval.transaction_id))))
        ok = esipa.decode_initiate_authentication_response(answer)
        self.assertEqual(ok.server_certificate, der(self.pki.ds))
        response = self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)})
        result = esipa.decode_authenticate_client_ds_response(
            self.relay.handle(esipa.encode_authenticate_client_request(ok.transaction_id, response)))
        self.assertEqual(result.transaction_id, ok.transaction_id)
        closed = self.engine.operation(retrieval.id)
        self.assertEqual(closed.state, STATE_SUCCESS)
        self.assertEqual(closed.result["events"], [{"eventId": "EVENT-1", "rspServerAddress": SMDP_ADDRESS}])
        download, = [operation for operation in self.engine.operations() if operation.params.get("event_id")]
        # SGP.22 v3.1 §3.6.2 step 10: the EventID is the Matching ID, its source the OID of the SM-DS
        self.assertEqual((download.params["activation_code"], download.params["smds_oid"]),
                         (f"1${SMDP_ADDRESS}$EVENT-1", SMDS_OID))
        self.assertIn(f"1${SMDP_ADDRESS}$EVENT-1".encode(), result.profile_download_trigger)
        # the download the trigger starts is relayed to the SM-DP+ of this service, in process
        self.assertEqual(self.smdp.calls, [])
        self.relay.handle(esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
            euicc_challenge=self.euicc.challenge, euicc_info1=self.pki.euicc_info1(),
            eim_transaction_id=bytes.fromhex(download.transaction_id))))
        self.assertEqual([(name, payload["smdpAddress"]) for name, payload in self.smdp.calls],
                         [("initiateAuthentication", SMDP_ADDRESS)])

    def test_a_name_both_servers_were_given_stays_the_sm_dps(self) -> None:
        # ES11 and ES9+ share their paths, so one name can stand for one server only
        self.smds.smdp = self.smdp
        self.smds.set_address(SMDP_ADDRESS)
        self.assertTrue(self.smds.taken_by_the_smdp())
        self.assertFalse(self.smds.owns_address(SMDP_ADDRESS))
        self.assertIsInstance(self.relay._provider_for(SMDP_ADDRESS), LocalSmdpEs9)
        self.assertFalse(es11_binding.claims_json(self.smds, INITIATE, {"smdpAddress": SMDP_ADDRESS}))
        self.assertFalse(es11_binding.claims_asn1(self.smds, es9_asn1.encode_initiate_authentication_request(
            self.euicc.challenge, SMDP_ADDRESS, self.pki.euicc_info1())))
        with self.assertRaises(smds.SmdsError) as caught:
            self.smds.handle(INITIATE, self.euicc.initiate(smdpAddress=SMDP_ADDRESS))
        self.assertEqual(caught.exception.status, smds.ADDRESS_REFUSED)
        self.smds.set_address(SMDS_ADDRESS)
        self.assertFalse(self.smds.taken_by_the_smdp())
        self.assertTrue(self.smds.owns_address(SMDS_ADDRESS))

    def test_a_refusal_of_the_sm_ds_fails_the_retrieval(self) -> None:
        retrieval = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": SMDS_ADDRESS, "indirect": True})])[0]
        self.serve()
        ok = esipa.decode_initiate_authentication_response(self.relay.handle(
            esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
                euicc_challenge=self.euicc.challenge, euicc_info1=self.pki.euicc_info1(),
                eim_transaction_id=bytes.fromhex(retrieval.transaction_id)))))
        forged = self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)},
                                    signing_key=ec.generate_private_key(ec.SECP256R1()))
        answer = self.relay.handle(esipa.encode_authenticate_client_request(ok.transaction_id, forged))
        self.assertEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        failed = self.engine.operation(retrieval.id)
        self.assertNotEqual(failed.state, STATE_SUCCESS)
        self.assertIn("euiccSignature1 does not verify", failed.error)
        # the IPA cancels and reports a failed download (SGP.32 v1.3 §3.9.2.2 step 14): the retrieval keeps the
        # SM-DS's refusal as its error, on this branch too
        self.assertIn(EVENT_RETRIEVAL_CLOSED_FLAG, failed.flags)
        self.engine.accept_result(EID, self.download_error(retrieval.transaction_id))
        after = self.engine.operation(retrieval.id)
        self.assertEqual((after.state, after.error), (failed.state, failed.error))
        self.assertFalse(after.result_hex)

    @staticmethod
    def download_error(transaction_id: str) -> bytes:
        """ProfileDownloadTriggerResult 'BF54' with profileDownloadError undefinedError(127) (SGP.32 v1.3
        §2.11.2.3), as an IPA sends it that took the eIM's Event Retrieval answer for a failed download."""
        return tlv(b"\xBF\x54", tlv(b"\x82", bytes.fromhex(transaction_id)) + bytes.fromhex("300380017F"))

    def test_a_download_result_for_a_retrieval_the_eim_closed_is_noted_not_applied(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        retrieval = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": SMDS_ADDRESS, "indirect": True})])[0]
        self.serve()
        ok = esipa.decode_initiate_authentication_response(self.relay.handle(
            esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
                euicc_challenge=self.euicc.challenge, euicc_info1=self.pki.euicc_info1(),
                eim_transaction_id=bytes.fromhex(retrieval.transaction_id)))))
        self.relay.handle(esipa.encode_authenticate_client_request(
            ok.transaction_id, self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)})))
        closed = self.engine.operation(retrieval.id)
        self.assertEqual(closed.state, STATE_SUCCESS)
        self.assertIn(EVENT_RETRIEVAL_CLOSED_FLAG, closed.flags)
        accepted = self.engine.accept_result(EID, self.download_error(retrieval.transaction_id))
        after = self.engine.operation(retrieval.id)
        self.assertEqual(after.state, STATE_SUCCESS)
        self.assertEqual(after.result, {"events": [{"eventId": "EVENT-1", "rspServerAddress": SMDP_ADDRESS}]})
        self.assertFalse(after.error)
        self.assertFalse(after.result_hex)
        self.assertTrue(any("the event retrieval is closed" in message for message in accepted.messages),
                        accepted.messages)
        self.assertTrue(any("ProfileDownloadTriggerResult as well" in str(entry) for entry in after.history),
                        after.history)

    def test_the_default_relay_of_an_engine_has_both_local_servers(self) -> None:
        relay = default_relay(self.engine)
        self.assertIsInstance(relay.smds, smds.LocalSmds)
        self.assertIs(relay.smdp.smds, relay.smds)
        self.assertIs(relay.smds.smdp, relay.smdp)
        self.assertIs(default_relay(self.engine), relay)
        self.assertIsInstance(relay._provider_for(relay.smds.address()), LocalSmdsEs11)


class HttpClientRelayTests(RelayTests):
    """The same retrieval with the tree's own ES9+ client between the relay and the SM-DS: the JSON binding over
    HTTP, as the relay reaches an SM-DS that is not this service's."""

    def setUp(self) -> None:
        super().setUp()
        from SCP11.live.es9_client import Es9LikeClient

        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=self.smdp, smds=self.smds)
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)
        self.clients: list[Any] = []

        def client(address: str) -> Any:
            self.clients.append(address)
            return Es9LikeClient(base_url=self.server.url)

        self.relay = IndirectRelay(self.engine, None, provider_factory=client)

    def retrieve(self, **script: Any) -> tuple[Any, bytes, bytes]:
        retrieval = self.engine.submit([OperationRequest(
            eid=EID, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"contact_smds": True, "smds_address": SMDS_ADDRESS, "indirect": True})])[0]
        self.serve()
        ok = esipa.decode_initiate_authentication_response(self.relay.handle(
            esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
                euicc_challenge=self.euicc.challenge, euicc_info1=self.pki.euicc_info1(),
                eim_transaction_id=bytes.fromhex(retrieval.transaction_id)))))
        response = self.euicc.respond({"serverSigned1": _b64(ok.server_signed1)}, **script)
        return retrieval, ok.transaction_id, self.relay.handle(
            esipa.encode_authenticate_client_request(ok.transaction_id, response))

    def test_the_es9_client_reads_the_answers_of_the_sm_ds(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        retrieval, transaction_id, answer = self.retrieve()
        result = esipa.decode_authenticate_client_ds_response(answer)
        # an answer without smdpSigned2 is an SM-DS one: transactionId and eventEntries (SGP.22 v3.1 §6.5.2.12)
        self.assertEqual(result.transaction_id, transaction_id)
        self.assertIn(f"1${SMDP_ADDRESS}$EVENT-1".encode(), result.profile_download_trigger)
        self.assertEqual(self.engine.operation(retrieval.id).state, STATE_SUCCESS)
        self.assertEqual(self.clients, [SMDS_ADDRESS])
        download, = [operation for operation in self.engine.operations() if operation.params.get("event_id")]
        self.assertEqual(download.params["smds_oid"], SMDS_OID)
        notes = sorted(record.note for record in self.engine.store.traffic(limit=10))
        self.assertEqual(notes, ["ES11 authenticateClient", "ES11 initiateAuthentication"])

    def test_a_refusal_over_http_fails_the_retrieval_with_its_status_code(self) -> None:
        retrieval, _transaction_id, answer = self.retrieve(matching_id="NO-SUCH-EVENT")
        self.assertEqual(answer, esipa.encode_authenticate_client_error(esipa.UNDEFINED_ERROR))
        failed = self.engine.operation(retrieval.id)
        self.assertNotEqual(failed.state, STATE_SUCCESS)
        # the function execution status of the JSON binding names the row: Event Record - Unknown
        self.assertIn("8.9.5", failed.error)
        self.assertIn("3.9", failed.error)

    # The in-process cases of the base class do not apply to a relay without the local servers.
    test_the_two_local_servers_are_reached_in_process = None  # type: ignore[assignment]
    test_a_registered_event_becomes_a_download_at_the_local_sm_dp = None  # type: ignore[assignment]
    test_a_refusal_of_the_sm_ds_fails_the_retrieval = None  # type: ignore[assignment]
    test_a_name_both_servers_were_given_stays_the_sm_dps = None  # type: ignore[assignment]
    test_the_default_relay_of_an_engine_has_both_local_servers = None  # type: ignore[assignment]


class _Session:
    """What ``LocalSmdp`` asks of its session for an address."""

    def _effective_smdp_address(self) -> str:
        return SMDP_ADDRESS


class EventDeletionTests(_Service):
    """The SM-DP+ deletes the Event Record a download came from (SGP.22 v3.1 §3.1.3.3 step 10, §3.0.2 step 8)."""

    def setUp(self) -> None:
        super().setUp()
        self.local = LocalSmdp(self.directory, session_factory=_Session)
        self.local.smds = self.smds
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-2")

    @staticmethod
    def installation_result(transaction_id: bytes) -> bytes:
        # ProfileInstallationResult 'BF37' { profileInstallationResultData 'BF27' { transactionId '80', ... } }
        return tlv(b"\xBF\x37", tlv(b"\xBF\x27", tlv(b"\x80", transaction_id) + tlv(b"\xBF\x2F", b"")))

    @staticmethod
    def cancel_response(reason: int) -> bytes:
        signed = tlv(b"\x30", tlv(b"\x80", TX) + tlv(b"\x81", bytes.fromhex("883703")) + tlv(b"\x82", bytes([reason])))
        return tlv(b"\xBF\x41", tlv(b"\xA0", signed + tlv(b"\x5F\x37", b"\x00" * 64)))

    def remaining(self) -> list[tuple[str, str, str]]:
        return [(event.eid, event.event_id, event.rsp_server_address) for event in self.smds.events()]

    def test_the_installation_result_of_a_served_package_deletes_the_event(self) -> None:
        self.local._note_delivered(TX.hex().upper(), EID, "EVENT-1")
        # another Notification, and a result of a session this SM-DP+ served no package in, delete nothing
        self.local.handle("/gsma/rsp2/es9plus/handleNotification", {"pendingNotification": _b64(tlv(b"\x30", b""))})
        self.local.handle("/gsma/rsp2/es9plus/handleNotification",
                          {"pendingNotification": _b64(self.installation_result(b"\xEE" * 16))})
        self.assertEqual(len(self.remaining()), 3)
        # the JSON binding carries the result alone; its transactionId is read from it
        self.local.handle("/gsma/rsp2/es9plus/handleNotification",
                          {"pendingNotification": _b64(self.installation_result(TX))})
        self.assertEqual(self.remaining(), [(EID, "EVENT-1", "smdp2.example.test"), (OTHER_EID, "EVENT-2", SMDP_ADDRESS)])
        # once: the same result again finds no session
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.local.handle("/gsma/rsp2/es9plus/handleNotification",
                          {"pendingNotification": _b64(self.installation_result(TX))})
        self.assertEqual(len(self.remaining()), 3)

    def test_the_asn1_binding_names_the_transaction_itself(self) -> None:
        self.local._note_delivered(TX.hex().upper(), OTHER_EID, "EVENT-2")
        self.local.handle("/gsma/rsp2/es9plus/handleNotification", {
            "pendingNotification": self.installation_result(TX).hex(), "transactionId": TX.hex().upper()})
        self.assertEqual([event_id for _eid, event_id, _address in self.remaining()], ["EVENT-1", "EVENT-1"])

    def test_a_cancelled_session_deletes_the_event_unless_the_order_stays_pending(self) -> None:
        for reason, kept in ((1, True), (2, True), (0, False), (5, False), (127, False)):
            with self.subTest(reason=reason):
                if (EID, "EVENT-1", SMDP_ADDRESS) not in self.remaining():
                    self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
                self.local._remember(TX.hex().upper(), {"matching_id": "EVENT-1", "eid": EID})
                self.local.handle("/gsma/rsp2/es9plus/cancelSession", {
                    "transactionId": TX.hex().upper(), "cancelSessionResponse": self.cancel_response(reason).hex()})
                self.assertEqual((EID, "EVENT-1", SMDP_ADDRESS) in self.remaining(), kept)
                self.assertIsNone(self.local.transaction(TX))

    def test_a_cancel_that_carries_no_reason_keeps_the_event(self) -> None:
        self.local._remember(TX.hex().upper(), {"matching_id": "EVENT-1", "eid": EID})
        self.local.handle("/gsma/rsp2/es9plus/cancelSession", {"transactionId": TX.hex().upper(),
                                                               "cancelSessionResponse": "BF4103810105"})
        self.assertEqual(len(self.remaining()), 3)

    def test_an_sm_dp_without_an_sm_ds_and_a_failing_sm_ds_both_answer(self) -> None:
        self.local._note_delivered(TX.hex().upper(), EID, "EVENT-1")
        self.local.smds = None
        self.assertEqual(self.local.handle("/gsma/rsp2/es9plus/handleNotification",
                                           {"pendingNotification": _b64(self.installation_result(TX))}), {})
        lines: list[str] = []
        self.local.log = lines.append
        self.local.smds = types.SimpleNamespace(download_ended=mock.Mock(side_effect=OSError("store gone")))
        self.local._note_delivered(TX.hex().upper(), EID, "EVENT-1")
        self.assertEqual(self.local.handle("/gsma/rsp2/es9plus/handleNotification",
                                           {"pendingNotification": _b64(self.installation_result(TX))}), {})
        self.assertTrue(any("Event Deletion at the local SM-DS failed" in line for line in lines), lines)

    def test_delivered_sessions_are_bounded(self) -> None:
        from SCP11.eim_local.engine.smdp import MAX_OPEN_TRANSACTIONS

        for number in range(MAX_OPEN_TRANSACTIONS + 5):
            self.local._note_delivered(f"{number:032X}", EID, "EVENT-1")
        self.assertEqual(len(self.local._delivered), MAX_OPEN_TRANSACTIONS)


class SettingAndRouteTests(_Service):
    def test_the_address_is_an_engine_setting(self) -> None:
        self.assertEqual(self.engine.setting(SETTING_SMDS_ADDRESS), smds.DEFAULT_ADDRESS)
        self.assertEqual(self.engine.set_setting(SETTING_SMDS_ADDRESS, "SMDS2.Example.Test"), "smds2.example.test")
        self.assertEqual(self.smds.address(), "smds2.example.test")
        self.assertEqual(self.engine.settings()[SETTING_SMDS_ADDRESS], "smds2.example.test")
        with self.assertRaises(LocalEimError):
            self.engine.set_setting(SETTING_SMDS_ADDRESS, "https://smds.example.test/")

    def test_another_process_finds_the_service_by_the_sm_ds_name(self) -> None:
        status = {"pid": os.getpid(), "url": "http://127.0.0.1:8743", "eim_fqdn": "eim.yggdrasim.local",
                  "smdp_address": SMDP_ADDRESS, "smds_address": "smds2.example.test"}
        (self.directory / STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")
        self.assertEqual(local_route("SMDS2.example.test", self.directory), "http://127.0.0.1:8743")
        self.assertEqual(local_route("https://smds2.example.test/gsma/rsp2/es9plus", self.directory),
                         "http://127.0.0.1:8743")
        self.assertEqual(local_route(SMDS_ADDRESS, self.directory), "")
        # a status file written before the service had an SM-DS names none
        del status["smds_address"]
        (self.directory / STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")
        self.assertEqual(local_route("smds2.example.test", self.directory), "")
        self.assertEqual(local_route(SMDP_ADDRESS, self.directory), "http://127.0.0.1:8743")


class BundleTests(unittest.TestCase):
    """The SGP.26 bundle as the source of CERT.DSauth.SIG: the Variant O pairs under a root of the bundle."""

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.pki = Pki()
        self._write("Variant O/CI/CERT_CI_SIG_NIST.pem", self.pki.ci.public_bytes(serialization.Encoding.PEM))
        self._write("Variant O/CI/SK_CI_SIG_NIST.pem", self.pki.ci_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self._pair("Variant O/SM-DS/SM_DSauth", "S_SM_DSauth_VARO_SIG_NIST", self.pki.ds, self.pki.ds_key)
        # a pair under a SubCA, with the role of the other chain variants: not served
        sub_key = ec.generate_private_key(ec.SECP256R1())
        sub = issue(_name("Test SM-DS SubCA"), sub_key, (self.pki.ci, self.pki.ci_key), ca=True)
        self._write("Variants A_B_C/Variant A/SM-DS/SM_DSSubCA/CERT_SM_DSSubCA_VARA_SIG_NIST.pem",
                    sub.public_bytes(serialization.Encoding.PEM))
        role = x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.146.1.2.1.0.0.2.1"), None)])
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = issue(_name("Test SM-DS A"), leaf_key, (sub, sub_key), extensions=((role, True),))
        self._pair("Variants A_B_C/Variant A/SM-DS/SM_DSauth", "S_SM_DSauth_VARA_SIG_NIST", leaf, leaf_key)

    def _write(self, relative: str, data: bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _pair(self, folder: str, stem: str, certificate: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
        self._write(f"{folder}/CERT_{stem}.der", der(certificate))
        key_stem = stem.replace("_VARO", "").replace("_VARA", "")
        self._write(f"{folder}/SK_{key_stem}.pem", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def test_the_certificate_store_finds_the_sm_ds_pairs(self) -> None:
        store = LocalSgp26CertStore(valid_cert_root=str(self.root))
        records = store.ds_auth_records()
        self.assertEqual(sorted(record.variant_name for record in records), ["Variant A", "Variant O"])
        self.assertTrue(all(record.role == "ds_auth" for record in records))
        direct = store.resolve_ds_auth_record([self.pki.ci_pkid.hex().upper()])
        self.assertEqual(direct.der_bytes, der(self.pki.ds))
        # the SM-DP+ records are as before: none here
        self.assertEqual(store.auth_records(), [])
        self.assertEqual(LocalSgp26CertStore(valid_cert_root=str(self.root / "missing")).ds_auth_records(), [])

    def test_the_bundle_material_is_the_variant_o_pair_and_the_roots(self) -> None:
        config = types.SimpleNamespace(SGP26_VALID_CERT_DIR=str(self.root), CERT_CURVE_PREFERENCE="NIST")
        with mock.patch("SCP11.eim_local.config.EimLocalConfig", return_value=config):
            material = smds.bundle_material()
        self.assertEqual([credential.certificate for credential in material.credentials], [der(self.pki.ds)])
        self.assertEqual(material.credentials[0].root_ci_pkid, self.pki.ci_pkid)
        self.assertEqual(material.credentials[0].label, "CERT_S_SM_DSauth_VARO_SIG_NIST.der")
        self.assertEqual(list(material.ci_certificates), [der(self.pki.ci)])
        self.assertEqual(DS_AUTH_ROLE, "2.23.146.1.2.1.7")

    def test_a_bundle_without_sm_ds_material_serves_nothing(self) -> None:
        config = types.SimpleNamespace(SGP26_VALID_CERT_DIR=str(self.root / "missing"), CERT_CURVE_PREFERENCE="NIST")
        with mock.patch("SCP11.eim_local.config.EimLocalConfig", return_value=config):
            material = smds.bundle_material()
        self.assertEqual((material.credentials, material.ci_certificates), ((), ()))
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        empty = smds.LocalSmds(Path(folder.name), material_factory=lambda: material)
        with self.assertRaises(smds.SmdsError) as caught:
            empty.handle(INITIATE, ScriptedEuicc(self.pki).initiate())
        self.assertEqual(caught.exception.status, smds.SECURITY_CONFIGURATION_UNSUPPORTED)


class CardFacingTlsTests(BundleTests):
    """CERT.DS.TLS and the listener a card's IPAe reaches the SM-DS on (SGP.22 v3.1 §4.5.2.1.0.7, SGP.32 v1.3 §3.9.2.1)."""

    def setUp(self) -> None:
        super().setUp()
        store = tempfile.TemporaryDirectory()
        self.addCleanup(store.cleanup)
        self.directory = Path(store.name)
        config = types.SimpleNamespace(SGP26_VALID_CERT_DIR=str(self.root), CERT_CURVE_PREFERENCE="NIST")
        patched = mock.patch("SCP11.eim_local.config.EimLocalConfig", return_value=config)
        patched.start()
        self.addCleanup(patched.stop)
        self.engine = LocalEim(self.directory)
        self.smds = smds.LocalSmds(self.directory, store=self.engine.store)

    def select(self, host: str = SMDS_ADDRESS, **options: Any) -> smdp_tls.ServingMaterial:
        return smdp_tls.select_material(self.directory, auth_certificate=der(self.pki.ds), host=host,
                                        bundle_root=self.root, server=smdp_tls.SMDS, **options)

    @staticmethod
    def leaf(material: smdp_tls.ServingMaterial) -> x509.Certificate:
        return x509.load_pem_x509_certificates(Path(material.chain_path).read_bytes())[0]

    def test_the_certificate_issued_follows_table_16(self) -> None:
        material = self.select()
        leaf = self.leaf(material)
        self.assertEqual(Path(material.chain_path).parent, self.directory / "smds_tls")
        # subject: the attributes of CERT.DSauth.SIG with 'cn' the host name
        common_name = x509.oid.NameOID.COMMON_NAME
        self.assertEqual([attribute.value for attribute in leaf.subject.get_attributes_for_oid(common_name)],
                         [SMDS_ADDRESS])
        self.assertEqual({(attribute.oid, attribute.value) for attribute in leaf.subject if attribute.oid != common_name},
                         {(attribute.oid, attribute.value) for attribute in self.pki.ds.subject
                          if attribute.oid != common_name})
        self.assertEqual(leaf.issuer, self.pki.ci.subject)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertFalse(names.critical)
        self.assertEqual(names.value.get_values_for_type(x509.DNSName), [SMDS_ADDRESS])
        self.assertEqual([oid.dotted_string for oid in names.value.get_values_for_type(x509.RegisteredID)], [SMDS_OID])
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical and usage.value.digital_signature and not usage.value.key_cert_sign)
        extended = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertTrue(extended.critical)
        self.assertEqual(sorted(item.dotted_string for item in extended.value),
                         ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"])
        policies = leaf.extensions.get_extension_for_class(x509.CertificatePolicies)
        self.assertFalse(policies.critical)
        # id-rspRole-ds-tls-v2 {id-rspRole 6}: the Variant O role beside id-rspRole-ds-auth-v2 {7}
        self.assertEqual([policy.policy_identifier.dotted_string for policy in policies.value], ["2.23.146.1.2.1.6"])
        authority = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self.assertEqual(authority.value.key_identifier, self.pki.ci_pkid)
        leaf.verify_directly_issued_by(self.pki.ci)
        record = json.loads((self.directory / "smds_tls" / smdp_tls.RECORD_FILE).read_text(encoding="utf-8"))
        self.assertEqual((record["host"], record["smds_oid"]), (SMDS_ADDRESS, SMDS_OID))
        self.assertNotIn("smdp_oid", record)
        self.assertEqual(os.stat(material.key_path).st_mode & 0o777, 0o600)

    def test_the_certificate_is_kept_until_the_name_changes(self) -> None:
        first = self.leaf(self.select())
        self.assertEqual(self.leaf(self.select()).serial_number, first.serial_number)
        renamed = self.leaf(self.select("smds2.example.test"))
        self.assertNotEqual(renamed.serial_number, first.serial_number)
        self.assertEqual(renamed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                         .get_values_for_type(x509.DNSName), ["smds2.example.test"])
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=smdp_tls.VALIDITY_DAYS)
        self.assertNotEqual(self.leaf(self.select("smds2.example.test", now=later)).serial_number,
                            renamed.serial_number)

    def test_the_sm_dp_material_is_untouched_by_the_sm_ds_one(self) -> None:
        self.select()
        self.assertFalse((self.directory / smdp_tls.MATERIAL_DIR).exists())
        self.assertEqual(smdp_tls.material_directory(self.directory), self.directory / "smdp_tls")
        self.assertEqual(smdp_tls.material_directory(self.directory, smdp_tls.SMDS), self.directory / "smds_tls")

    def test_what_is_missing_is_named(self) -> None:
        with self.assertRaisesRegex(smdp_tls.SmdpTlsError, "the local SM-DS has no address"):
            self.select("")
        with self.assertRaisesRegex(smdp_tls.SmdpTlsError, "CERT.DSauth does not parse"):
            smdp_tls.select_material(self.directory, auth_certificate=b"\x30\x00", host=SMDS_ADDRESS,
                                     bundle_root=self.root, server=smdp_tls.SMDS)
        (self.root / "Variant O" / "CI" / "SK_CI_SIG_NIST.pem").unlink()
        with self.assertRaisesRegex(smdp_tls.SmdpTlsError,
                                    "no CERT.DS.TLS for smds.example.test and no private key of the issuer of CERT.DSauth"):
            self.select()
        empty = types.SimpleNamespace(material=lambda: smds.SmdsMaterial(), address=lambda: SMDS_ADDRESS)
        with self.assertRaisesRegex(smdp_tls.SmdpTlsError, "no CERT.DSauth to issue a TLS certificate beside"):
            smdp_tls.smds_serving_material(self.directory, empty)

    def test_a_card_reaches_the_sm_ds_over_its_own_listener(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        lines: list[str] = []
        listener, status = service_runner._smds_card_listener(
            self.engine, StubSmdp(), self.smds, "127.0.0.1", 0, None, lines.append)
        self.assertIsNotNone(listener, status)
        listener.start_in_thread()
        self.addCleanup(listener.stop)
        self.assertEqual(status["smds_tls_url"], listener.url)
        self.assertEqual(status["smds_tls_port"], listener.server_address[1])
        self.assertIn(f"issued for {SMDS_ADDRESS} under", status["smds_tls_material"])
        # A client that trusts the eSIM CA alone, as an eUICC carrying it does, and checks the host name.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=der(self.pki.ci))
        euicc = ScriptedEuicc(self.pki)

        def post(tls: ssl.SSLSocket, body: bytes) -> bytes:
            head = (f"POST /gsma/rsp2/asn1 HTTP/1.1\r\nHost: {SMDS_ADDRESS}\r\nUser-Agent: gsma-rsp-ipae\r\n"
                    "X-Admin-Protocol: gsma/rsp/v2.1.0\r\nContent-Type: application/x-gsma-rsp-asn1\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
            tls.sendall(head + body)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                self.assertTrue(chunk, "the listener closed the session before answering")
                data += chunk
            header, _, rest = data.partition(b"\r\n\r\n")
            fields = dict(line.split(":", 1) for line in header.decode("iso-8859-1").split("\r\n")[1:])
            length = int({key.strip().lower(): value.strip() for key, value in fields.items()}["content-length"])
            while len(rest) < length:
                rest += tls.recv(65536)
            return rest

        with socket.create_connection(("127.0.0.1", listener.server_address[1]), timeout=30) as raw:
            with context.wrap_socket(raw, server_hostname=SMDS_ADDRESS) as tls:
                self.assertIn(tls.version(), ("TLSv1.2", "TLSv1.3"))
                ok = es9_asn1.decode_initiate_authentication_response(post(tls, (
                    es9_asn1.encode_initiate_authentication_request(euicc.challenge, SMDS_ADDRESS,
                                                                    self.pki.euicc_info1()))))
                response = euicc.respond({"serverSigned1": _b64(ok.server_signed1)})
                answer = post(tls, es9_asn1.encode_authenticate_client_request(ok.transaction_id, response))
        self.assertEqual(es9_asn1.decode_authenticate_client_es11_response(answer),
                         (ok.transaction_id, [("EVENT-1", SMDP_ADDRESS)]))
        self.assertTrue(any("ES11 ASN.1 AuthenticateClient" in line for line in lines), lines[-6:])
        handshake, = self.engine.store.handshakes()
        self.assertEqual((handshake.leaf, handshake.outcome, handshake.requests), ("CERT.DS.TLS", "completed", 2))

    def test_the_listener_is_left_out_with_its_reason(self) -> None:
        lines: list[str] = []
        listener, status = service_runner._smds_card_listener(
            self.engine, StubSmdp(), self.smds, "127.0.0.1", None, None, lines.append)
        self.assertIsNone(listener)
        self.assertEqual(status, {"smds_tls_url": "",
                                  "smds_tls_note": "SM-DS card-facing TLS listener off (smds_tls_port=off)"})
        self.smds.smdp = StubSmdp()
        self.smds.set_address(SMDP_ADDRESS)
        listener, status = service_runner._smds_card_listener(
            self.engine, self.smds.smdp, self.smds, "127.0.0.1", 0, None, lines.append)
        self.assertIsNone(listener)
        self.assertIn("is also the address of the SM-DP+, which keeps the name", status["smds_tls_note"])
        self.smds.set_address(SMDS_ADDRESS)
        lines.clear()
        (self.root / "Variant O" / "CI" / "SK_CI_SIG_NIST.pem").unlink()
        listener, status = service_runner._smds_card_listener(
            self.engine, StubSmdp(), self.smds, "127.0.0.1", 0, None, lines.append)
        self.assertIsNone(listener)
        self.assertIn("no SM-DS card-facing TLS listener: the SGP.26 bundle holds no CERT.DS.TLS",
                      status["smds_tls_note"])
        self.assertEqual(lines, [status["smds_tls_note"]])

    def test_the_port_is_four_past_the_plain_one_and_survives_a_restart(self) -> None:
        # three past it is the default port of the IPAd's EIM-LISTEN
        self.assertEqual(service_runner.smds_card_port(8743, "auto"), 8747)
        self.assertEqual(service_runner.smdp_card_port(8743, "auto"), 8745)
        self.assertEqual(service_runner.smds_card_port(0, "auto"), 0)
        self.assertIsNone(service_runner.smds_card_port(8743, "off"))
        self.assertEqual(service_runner.smds_card_port(8743, "9000"), 9000)
        with self.assertRaisesRegex(service_runner.ServiceError, "smds_tls_port"):
            service_runner.smds_card_port(8743, "many")
        running = {"pid": os.getpid(), "url": "http://127.0.0.1:8743", "host": "127.0.0.1", "port": 8743,
                   "tls_url": "", "tls_requested": "off", "smdp_tls_url": "", "smdp_tls_requested": "off",
                   "smds_tls_url": "https://127.0.0.1:9000", "smds_tls_port": 9000}
        for status, expected in ((running, 9000),
                                 ({**running, "smds_tls_url": "", "smds_tls_requested": "off"}, "off"),
                                 ({key: value for key, value in running.items() if not key.startswith("smds")}, "auto")):
            with self.subTest(expected=expected), \
                    mock.patch.object(service_runner, "read_status", return_value=status), \
                    mock.patch.object(service_runner, "stop_background"), \
                    mock.patch.object(service_runner, "start_background", return_value={}) as start:
                service_runner.restart_background(self.directory)
                self.assertEqual(start.call_args.kwargs["smds_tls_port"], expected)
                self.assertEqual(start.call_args.kwargs["smdp_tls_port"], "off")


if __name__ == "__main__":
    unittest.main()
