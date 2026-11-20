# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ESipa in the JSON binding on the Local eIM service (SGP.32 v1.3 §6.1.2, §6.4).

Each function is posted to its path of Table 28 and answered through the ASN.1
handler; the answers carry the responseHeader of SGP.22 v3.1 §6.5.1.4 and the
status codes the function tables map to the ASN.1 error values.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.esipa import LocalEimHttpServer, handle_asn1
from SCP11.eim_local.engine.esipa_json import JsonRequestError, handle_json
from SCP11.eim_local.engine.indirect import IndirectRelay
from SCP11.eim_local.engine.service import STATE_SUCCESS, OperationRequest
from SCP11.eim_local.engine.smdp import LocalSmdp
from SCP11.shared import esipa_download as esipa
from tests.test_local_eim_indirect import SMDP_TX, StubSmdp
from tests.test_local_eim_service import ServiceTestBase


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class JsonBindingTests(ServiceTestBase):
    def call(self, function: str, body: dict) -> tuple[int, dict | None]:
        status, answer = handle_json(function, json.dumps(body).encode(),
                                     lambda message: handle_asn1(self.engine, message))
        return int(status), (json.loads(answer) if answer else None)

    def test_an_operation_goes_round_the_json_binding(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0].id
        status, answer = self.call("getEimPackage", {"eidValue": self.card.eid})
        self.assertEqual(status, 200)
        self.assertEqual(answer["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        package = base64.b64decode(answer["euiccPackageRequest"])
        self.assertEqual(package[:2], codec.TAG_EUICC_PACKAGE)
        result = self.card.exchange(package)
        status, answer = self.call("provideEimPackageResult", {"eidValue": self.card.eid, "eimPackageResult": _b64(result)})
        self.assertEqual(answer["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)
        # §6.4.1.5: the error value in the body, and the status code of §5.14.5 (p.170) in the header.
        status, answer = self.call("getEimPackage", {"eidValue": self.card.eid})
        self.assertEqual(answer["eimPackageError"], codec.NO_EIM_PACKAGE_AVAILABLE)
        self.assertEqual(answer["header"]["functionExecutionStatus"]["statusCodeData"]["subjectCode"], "8.1.1")
        self.assertEqual(answer["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"], "3.7")

    def test_a_result_as_a_notification_answers_204(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0].id
        _status, answer = self.call("getEimPackage", {"eidValue": self.card.eid})
        result = self.card.exchange(base64.b64decode(answer["euiccPackageRequest"]))
        provide = codec.tlv(codec.TAG_PROVIDE_EIM_PACKAGE_RESULT, codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + result)
        self.assertEqual(self.call("handleNotification", {"provideEimPackageResult": _b64(provide)}), (204, None))
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)

    def test_eid_errors_carry_their_status_codes(self) -> None:
        # §5.14.5 (p.170): missingEid 8.1.1 / 2.2, invalidEid 8.1.1 / 2.1.
        _status, missing = self.call("getEimPackage", {})
        self.assertEqual((missing["eimPackageError"],
                          missing["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"]),
                         (codec.MISSING_EID, "2.2"))
        _status, invalid = self.call("getEimPackage", {"eidValue": "8904903212345"})
        self.assertEqual((invalid["eimPackageError"],
                          invalid["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"]),
                         (codec.INVALID_EID, "2.1"))
        _status, provide = self.call("provideEimPackageResult", {"eidValue": "X" * 32, "eimPackageResult": _b64(b"\x30\x00")})
        self.assertEqual(provide["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"], "2.1")
        self.assertNotIn("eimPackageError", provide)

    def test_a_request_off_its_schema_is_a_bad_request(self) -> None:
        for function, body in (
            ("getEimPackage", b"not json"),
            ("getEimPackage", b"[]"),
            ("authenticateClient", json.dumps({"transactionId": "00", "authenticateServerResponse": "%%"}).encode()),
            ("authenticateClient", json.dumps({"authenticateServerResponse": _b64(b"\xBF\x38\x00")}).encode()),
            ("initiateAuthentication", json.dumps({"euiccChallenge": _b64(b"\x01" * 16), "eimTransactionId": "XYZ"}).encode()),
            ("handleNotification", b"{}"),
        ):
            with self.subTest(function=function, body=body[:40]):
                status, answer = handle_json(function, body, lambda message: handle_asn1(self.engine, message))
                self.assertEqual(int(status), 400)
                self.assertEqual(json.loads(answer)["header"]["functionExecutionStatus"]["status"], "Failed")
        with self.assertRaises(JsonRequestError):
            handle_json("transferEimPackage", b"{}", lambda message: handle_asn1(self.engine, message))


class JsonRelayTests(ServiceTestBase):
    """The indirect download functions of the JSON binding, relayed to a stub SM-DP+."""

    def setUp(self) -> None:
        super().setUp()
        self.smdp = StubSmdp()
        self.relay = IndirectRelay(self.engine, provider_factory=lambda address: self.smdp)

    def call(self, function: str, body: dict) -> tuple[int, dict | None]:
        status, answer = handle_json(function, json.dumps(body).encode(),
                                     lambda message: handle_asn1(self.engine, message, relay=self.relay))
        return int(status), (json.loads(answer) if answer else None)

    def test_a_download_is_relayed_in_the_json_binding(self) -> None:
        operation = self.engine.submit([OperationRequest(
            eid=self.card.eid, type="PROFILE_DOWNLOAD_TRIGGER",
            params={"activation_code": "1$smdpp.example.test$MID-9", "indirect": True},
        )])[0]
        status, seed = self.call("initiateAuthentication", {
            "euiccChallenge": _b64(b"\x01" * 16), "euiccInfo1": _b64(bytes.fromhex("BF2000")),
            "eimTransactionId": operation.transaction_id,
        })
        self.assertEqual(seed["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(seed["transactionId"], SMDP_TX.hex().upper())
        # §6.4: DER data objects with their tag and length.
        self.assertEqual(base64.b64decode(seed["serverSignature1"]), codec.tlv(b"\x5F\x37", b"\x05" * 64))
        self.assertEqual(base64.b64decode(seed["euiccCiPKIdentifierToBeUsed"]), codec.tlv(b"\x04", b"\xF5" * 20))
        self.assertEqual(base64.b64decode(seed["serverSigned1"])[:1], b"\x30")
        self.assertEqual(base64.b64decode(seed["serverCertificate"]), self.smdp.certificate)
        response = bytes.fromhex("BF3817A115801000112233445566778899AABBCCDDEEFF020107")
        status, client = self.call("authenticateClient", {"transactionId": seed["transactionId"],
                                                          "authenticateServerResponse": _b64(response)})
        self.assertEqual(base64.b64decode(client["profileMetadata"])[:2], b"\xBF\x25")
        self.assertEqual(base64.b64decode(client["smdpSignature2"]), codec.tlv(b"\x5F\x37", b"\x06" * 64))
        self.assertEqual(base64.b64decode(self.smdp.calls[1][1].authenticate_server_response), response)
        prepare = bytes.fromhex("BF2117A115801000112233445566778899AABBCCDDEEFF02017F")
        status, package = self.call("getBoundProfilePackage", {"transactionId": seed["transactionId"],
                                                               "prepareDownloadResponse": _b64(prepare)})
        self.assertEqual(base64.b64decode(package["boundProfilePackage"]), codec.tlv(b"\xBF\x36", b"\x00" * 8))
        status, cancel = self.call("cancelSession", {"transactionId": seed["transactionId"],
                                                     "cancelSessionResponse": _b64(bytes.fromhex("BF4103810105"))})
        self.assertEqual(cancel, {"header": {"functionExecutionStatus": {"status": "Executed-Success"}}})

    def test_relay_refusals_carry_the_status_codes_of_the_tables(self) -> None:
        # Table 13a (p.159): invalidEimTransactionId 8.31.2 / 3.10.
        _status, refused = self.call("initiateAuthentication", {"euiccChallenge": _b64(b"\x01" * 16),
                                                                 "eimTransactionId": "09" * 8})
        data = refused["header"]["functionExecutionStatus"]
        self.assertEqual((data["status"], data["statusCodeData"]["subjectCode"], data["statusCodeData"]["reasonCode"]),
                         ("Failed", "8.31.2", "3.10"))
        self.assertEqual(data["statusCodeData"]["message"], esipa.INITIATE_AUTHENTICATION_ERRORS[52])
        # SGP.22 v3.1 p.303: invalidTransactionId 8.10.1 / 3.9.
        _status, unknown = self.call("getBoundProfilePackage", {"transactionId": "CC" * 16,
                                                                "prepareDownloadResponse": _b64(b"\xBF\x21\x00")})
        self.assertEqual(unknown["header"]["functionExecutionStatus"]["statusCodeData"]["reasonCode"], "3.9")


class JsonHttpTests(ServiceTestBase):
    """The paths of Table 28 on the HTTP service, with the headers of §6.1."""

    def setUp(self) -> None:
        super().setUp()
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=LocalSmdp(self.directory))
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)

    def post(self, function: str, body: dict) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            self.server.url + "/gsma/rsp2/esipa/" + function, data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json;charset=UTF-8", "User-Agent": "gsma-rsp-ipad",
                     "X-Admin-Protocol": "gsma/rsp/v1.3.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def test_the_service_answers_the_json_paths(self) -> None:
        status, headers, body = self.post("getEimPackage", {"eidValue": self.card.eid})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json;charset=UTF-8")
        self.assertEqual(headers.get("X-Admin-Protocol"), "gsma/rsp/v1.3.0")
        self.assertEqual(json.loads(body)["eimPackageError"], codec.NO_EIM_PACKAGE_AVAILABLE)
        result = codec.tlv(codec.TAG_PROVIDE_EIM_PACKAGE_RESULT, codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + b"\x30\x00")
        status, headers, body = self.post("handleNotification", {"provideEimPackageResult": _b64(result)})
        self.assertEqual((status, body), (204, b""))
        self.assertNotIn("Content-Type", headers)
        status, _headers, _body = self.post("unknownFunction", {})
        self.assertEqual(status, 404)
