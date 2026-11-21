# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ESipa.TransferEimPackage messages: every alternative, both bindings, malformed input.

The hexadecimal vectors were written by the SGP.32 v1.3 ASN.1 module compiled
with SGP.22 v3.1 and are pinned here, so the encodings hold on a machine
without the specification library; ``SchemaAgreement`` repeats the comparison
where the module is at hand.
"""

from __future__ import annotations

import base64
import unittest

from SCP11.eim_packages import parse_eim_package
from SCP11.shared import esipa_transfer as transfer

TXID = bytes.fromhex("A1A2A3A4")
EID = "89049032123451234512345678901235"


def _tlv(tag: str, value: bytes) -> bytes:
    assert len(value) < 0x80
    return bytes.fromhex(tag) + bytes([len(value)]) + value


EUICC_PACKAGE_RESULT = bytes.fromhex("BF511AA218801065696D2E6578616D706C652E746573748204A1A2A3A4")
RESULT_AND_NOTIFICATIONS = bytes.fromhex("301F") + EUICC_PACKAGE_RESULT + bytes.fromhex("A000")
IPA_EUICC_DATA_RESPONSE = bytes.fromhex("BF520BA1098004A1A2A3A4020101")

# TransferEimPackageResponse (SGP.32 v1.3 §6.3.3.1): one vector or more per alternative.
RESPONSE_VECTORS: tuple[tuple[str, str, dict[str, object]], ...] = (
    ("BF4E1D" + EUICC_PACKAGE_RESULT.hex(), transfer.RESULT_EUICC_PACKAGE, {"result": EUICC_PACKAGE_RESULT}),
    ("BF4E21" + RESULT_AND_NOTIFICATIONS.hex(), transfer.RESULT_WITH_NOTIFICATIONS, {"result": RESULT_AND_NOTIFICATIONS}),
    ("BF4E0E" + IPA_EUICC_DATA_RESPONSE.hex(), transfer.RESULT_IPA_EUICC_DATA, {"result": IPA_EUICC_DATA_RESPONSE}),
    ("BF4E020500", transfer.RECEIVED, {}),
    ("BF4E0BBF6008A0068004A1A2A3A4", transfer.RECEIVED_WITH_CID, {"transaction_id": TXID}),
    ("BF4E17BF6014A0125A1089049032123451234512345678901235", transfer.RECEIVED_WITH_CID, {"eid": EID}),
    ("BF4E03BF6000", transfer.RECEIVED_WITH_CID, {}),
    ("BF4E03020102", transfer.ERROR, {"error_code": 2}),
    ("BF4E0EBF610BA0068004A1A2A3A4810101", transfer.ERROR_WITH_CID, {"transaction_id": TXID, "error_code": 1}),
    ("BF4E1ABF6117A0125A1089049032123451234512345678901235810102", transfer.ERROR_WITH_CID,
     {"eid": EID, "error_code": 2}),
    ("BF4E06BF610381017F", transfer.ERROR_WITH_CID, {"error_code": 127}),
)

# TransferEimPackageRequest (§6.3.3.1): the four eIM Packages of Table 18 (§5.14.4).
REQUEST_VECTORS: tuple[tuple[str, str, str], ...] = (
    ("BF4E05BF51023000", "euiccPackageRequest", "BF51023000"),
    ("BF4E0FBF520C5C04BF20BF228304A1A2A3A4", "ipaEuiccDataRequest", "BF520C5C04BF20BF228304A1A2A3A4"),
    ("BF4E09BF5306800101800102", "eimAcknowledgements", "BF5306800101800102"),
    ("BF4E0DBF540AA00281008204A1A2A3A4", "profileDownloadTriggerRequest", "BF540AA00281008204A1A2A3A4"),
)

MALFORMED: tuple[bytes, ...] = (
    b"",
    b"\xBF",
    b"\xBF\x4E",
    bytes.fromhex("BF4E05"),
    bytes.fromhex("BF4E0505"),
    bytes.fromhex("BF4EFF"),
    bytes.fromhex("BF4E00"),
    bytes.fromhex("BF4E0405000500"),
    bytes.fromhex("BF4F020500"),
    bytes.fromhex("BF4E02050000"),
)


class Tables(unittest.TestCase):
    def test_request_alternatives_are_the_four_of_the_choice(self) -> None:
        self.assertEqual(
            {tag.hex().upper(): name for tag, name in transfer.REQUEST_ALTERNATIVES.items()},
            {"BF51": "euiccPackageRequest", "BF52": "ipaEuiccDataRequest", "BF53": "eimAcknowledgements",
             "BF54": "profileDownloadTriggerRequest"},
        )
        self.assertEqual({name for _hex, name, _package in REQUEST_VECTORS}, set(transfer.REQUEST_ALTERNATIVES.values()))

    def test_response_alternatives_are_the_seven_of_the_choice(self) -> None:
        self.assertEqual(
            transfer.RESPONSE_ALTERNATIVES,
            ("euiccPackageResult", "ePRAndNotifications", "ipaEuiccDataResponse", "eimPackageReceived",
             "eimPackageReceivedWithCid", "eimPackageError", "eimPackageErrorWithCid"),
        )
        self.assertEqual({kind for _hex, kind, _fields in RESPONSE_VECTORS}, set(transfer.RESPONSE_ALTERNATIVES))

    def test_error_codes_and_status_codes(self) -> None:
        self.assertEqual(transfer.EIM_PACKAGE_ERRORS,
                         {1: "invalidPackageFormat", 2: "unknownPackage", 127: "undefinedError"})
        # Table 19a (§5.14.4): both rows are subject code 8.31.1.
        self.assertEqual(transfer.STATUS_CODES, {1: ("8.31.1", "2.1"), 2: ("8.31.1", "1.1")})

    def test_paths_and_content_types(self) -> None:
        self.assertEqual(transfer.PATH_ASN1, "/gsma/rsp2/asn1")
        self.assertEqual(transfer.PATH_JSON, "/gsma/rsp2/esipa/transferEimPackage")
        self.assertEqual(transfer.CONTENT_TYPE_ASN1, "application/x-gsma-rsp-asn1")
        self.assertEqual(transfer.CONTENT_TYPE_JSON, "application/json;charset=UTF-8")
        self.assertEqual(transfer.ADMIN_PROTOCOL, "gsma/rsp/v1.3.0")

    def test_loopback_addresses(self) -> None:
        for host in ("127.0.0.1", "127.8.9.10", "::1", "localhost", "LOCALHOST", " 127.0.0.1 "):
            self.assertTrue(transfer.is_loopback(host), host)
        for host in ("", "0.0.0.0", "192.0.2.4", "::", "eim.example.test", "localhost.example.test", "127.0.0.1.example.test"):
            self.assertFalse(transfer.is_loopback(host), host)


class Requests(unittest.TestCase):
    def test_every_alternative_builds_and_reads_back(self) -> None:
        for whole, kind, package in REQUEST_VECTORS:
            with self.subTest(kind=kind):
                built = transfer.build_request(bytes.fromhex(package))
                self.assertEqual(built.hex().upper(), whole)
                decoded = transfer.decode_request(built)
                self.assertEqual((decoded.kind, decoded.package.hex().upper()), (kind, package))

    def test_a_data_object_outside_the_table_is_unknown(self) -> None:
        with self.assertRaises(transfer.UnknownPackage):
            transfer.decode_request(bytes.fromhex("BF4E04BF500100"))
        with self.assertRaises(transfer.TransferError):
            transfer.build_request(bytes.fromhex("BF500100"))

    def test_malformed_requests_are_refused(self) -> None:
        for data in MALFORMED:
            with self.subTest(data=data.hex()):
                with self.assertRaises(transfer.TransferError):
                    transfer.decode_request(data)

    def test_the_package_parser_names_the_transaction_of_each_package(self) -> None:
        # EuiccPackageRequest 'BF51' { euiccPackageSigned '30' { eimId, eidValue, counterValue, eimTransactionId,
        # psmoList }, eimSignature } (SGP.32 v1.3 §2.11.1.1).
        signed = _tlv("30", _tlv("80", b"eim") + _tlv("5A", bytes.fromhex(EID)) + _tlv("81", b"\x01")
                      + _tlv("82", TXID) + _tlv("A0", b""))
        package = _tlv("BF51", signed + _tlv("5F37", b"\x00"))
        self.assertEqual(parse_eim_package(package).eim_transaction_id, TXID)
        without = _tlv("BF51", _tlv("30", _tlv("80", b"eim") + _tlv("5A", bytes.fromhex(EID)) + _tlv("81", b"\x01")
                                   + _tlv("A0", b"")) + _tlv("5F37", b"\x00"))
        self.assertEqual(parse_eim_package(without).eim_transaction_id, b"")
        self.assertEqual(parse_eim_package(bytes.fromhex("BF520C5C04BF20BF228304A1A2A3A4")).eim_transaction_id, TXID)
        self.assertEqual(parse_eim_package(bytes.fromhex("BF540AA00281008204A1A2A3A4")).eim_transaction_id, TXID)
        self.assertEqual(parse_eim_package(bytes.fromhex("BF52045C02BF20")).eim_transaction_id, b"")


class Responses(unittest.TestCase):
    def test_every_vector_reads(self) -> None:
        for whole, kind, fields in RESPONSE_VECTORS:
            with self.subTest(vector=whole[:24]):
                decoded = transfer.decode_response(bytes.fromhex(whole))
                self.assertEqual(decoded.kind, kind)
                self.assertEqual(decoded.result, fields.get("result", b""))
                self.assertEqual(decoded.transaction_id, fields.get("transaction_id", b""))
                self.assertEqual(decoded.eid, fields.get("eid", ""))
                self.assertEqual(decoded.error_code, fields.get("error_code"))

    def test_every_vector_is_built_bit_for_bit(self) -> None:
        for whole, kind, fields in RESPONSE_VECTORS:
            with self.subTest(vector=whole[:24]):
                transaction_id = bytes(fields.get("transaction_id", b""))  # type: ignore[arg-type]
                eid = str(fields.get("eid", ""))
                if "result" in fields:
                    built = transfer.build_result_response(bytes(fields["result"]))  # type: ignore[arg-type]
                elif kind in (transfer.RECEIVED, transfer.RECEIVED_WITH_CID):
                    built = transfer.build_received_response(transaction_id=transaction_id, eid=eid,
                                                             with_cid=kind == transfer.RECEIVED_WITH_CID)
                else:
                    built = transfer.build_error_response(int(fields["error_code"]),  # type: ignore[arg-type]
                                                          transaction_id=transaction_id, eid=eid,
                                                          with_cid=kind == transfer.ERROR_WITH_CID)
                self.assertEqual(built.hex().upper(), whole.upper())

    def test_the_transaction_wins_over_the_eid_as_correlation(self) -> None:
        both = transfer.decode_response(transfer.build_received_response(transaction_id=TXID, eid=EID))
        self.assertEqual((both.transaction_id, both.eid), (TXID, ""))

    def test_malformed_responses_are_refused(self) -> None:
        more = (
            bytes.fromhex("BF4E03BF6200"),
            bytes.fromhex("BF4E020200"),
            bytes.fromhex("BF4E05BF6002A000"),
            bytes.fromhex("BF4E07BF6004A0028100"),
            bytes.fromhex("BF4E06BF6103A00100"),
            bytes.fromhex("BF4E03BF6100"),
            bytes.fromhex("BF4E06BF6103810101" + "00"),
            bytes.fromhex("BF4E0430020500"),
        )
        for data in (*MALFORMED, *more):
            with self.subTest(data=data.hex()):
                with self.assertRaises(transfer.TransferError):
                    transfer.decode_response(data)

    def test_an_undefined_error_value_is_not_built(self) -> None:
        with self.assertRaises(transfer.TransferError):
            transfer.build_error_response(3)
        with self.assertRaises(transfer.TransferError):
            transfer.build_received_response(eid="8904903212345")

    def test_a_download_result_has_no_alternative(self) -> None:
        with self.assertRaises(transfer.TransferError):
            transfer.build_result_response(bytes.fromhex("BF54023000"))
        with self.assertRaises(transfer.TransferError):
            transfer.build_result_response(bytes.fromhex("3003BF5100"))


class ResultForms(unittest.TestCase):
    """EimPackageResult (§6.3.2.7) to TransferEimPackageResponse and back for the error form."""

    def test_results_pass_through(self) -> None:
        for result in (EUICC_PACKAGE_RESULT, RESULT_AND_NOTIFICATIONS, IPA_EUICC_DATA_RESPONSE):
            response = transfer.decode_response(transfer.result_as_response(result, transaction_id=TXID, eid=EID))
            self.assertEqual(response.result, result)

    def test_the_error_form_becomes_an_error_with_correlation(self) -> None:
        named = transfer.decode_response(transfer.result_as_response(bytes.fromhex("A0098004A1A2A3A4020101"), eid=EID))
        self.assertEqual((named.kind, named.error_code, named.transaction_id, named.eid),
                         (transfer.ERROR_WITH_CID, 1, TXID, ""))
        by_package = transfer.decode_response(
            transfer.result_as_response(bytes.fromhex("A003020102"), transaction_id=TXID, eid=EID))
        self.assertEqual((by_package.error_code, by_package.transaction_id), (2, TXID))
        by_eid = transfer.decode_response(transfer.result_as_response(bytes.fromhex("A00302017F"), eid=EID))
        self.assertEqual((by_eid.error_code, by_eid.transaction_id, by_eid.eid), (127, b"", EID))

    def test_an_error_value_outside_the_enumeration_goes_out_as_undefined(self) -> None:
        response = transfer.decode_response(transfer.result_as_response(bytes.fromhex("A003020105"), eid=EID))
        self.assertEqual(response.error_code, transfer.UNDEFINED_ERROR)

    def test_an_error_form_without_a_code_is_refused(self) -> None:
        for data in (bytes.fromhex("A000"), bytes.fromhex("A0068004A1A2A3A4"), bytes.fromhex("A0020200")):
            with self.subTest(data=data.hex()):
                with self.assertRaises(transfer.TransferError):
                    transfer.result_as_response(data, eid=EID)

    def test_an_error_answer_reads_as_the_error_form(self) -> None:
        with_transaction = transfer.decode_response(transfer.build_error_response(2, transaction_id=TXID))
        self.assertEqual(transfer.error_as_result(with_transaction).hex().upper(), "A0098004A1A2A3A4020102")
        plain = transfer.decode_response(transfer.build_error_response(127, with_cid=False))
        self.assertEqual(transfer.error_as_result(plain).hex().upper(), "A00302017F")
        with self.assertRaises(transfer.TransferError):
            transfer.error_as_result(transfer.decode_response(transfer.build_received_response()))


class JsonBinding(unittest.TestCase):
    """SGP.32 v1.3 §6.4.1.4: one member per alternative, Binary as base64."""

    def test_every_request_alternative_round_trips(self) -> None:
        for whole, kind, package in REQUEST_VECTORS:
            with self.subTest(kind=kind):
                body = transfer.request_to_json(bytes.fromhex(whole))
                self.assertEqual(body, {kind: base64.b64encode(bytes.fromhex(package)).decode("ascii")})
                self.assertEqual(transfer.request_from_json(body).hex().upper(), whole)

    def test_request_bodies_that_do_not_follow_the_schema(self) -> None:
        package = base64.b64encode(bytes.fromhex("BF5306800101800102")).decode("ascii")
        for body in (
            None, [], "text", {},
            {"eimAcknowledgements": package, "ipaEuiccDataRequest": package},
            {"eimAcknowledgements": 5},
            {"eimAcknowledgements": "not base64 !"},
            {"ipaEuiccDataRequest": package},
            {"eimAcknowledgements": base64.b64encode(b"\xBF\x53").decode("ascii")},
        ):
            with self.subTest(body=repr(body)[:60]):
                with self.assertRaises(transfer.TransferError):
                    transfer.request_from_json(body)

    def test_every_response_alternative_has_its_member(self) -> None:
        seen: set[str] = set()
        for whole, kind, fields in RESPONSE_VECTORS:
            with self.subTest(vector=whole[:24]):
                message = transfer.response_to_json(bytes.fromhex(whole))
                members = [name for name in message if name != "header"]
                self.assertEqual(members, [kind])
                seen.add(kind)
                status = message["header"]["functionExecutionStatus"]
                if "error_code" in fields:
                    self.assertEqual(status["status"], "Failed")
                    code = int(fields["error_code"])  # type: ignore[arg-type]
                    if code in transfer.STATUS_CODES:
                        self.assertEqual((status["statusCodeData"]["subjectCode"], status["statusCodeData"]["reasonCode"]),
                                         transfer.STATUS_CODES[code])
                    else:
                        self.assertNotIn("statusCodeData", status)
                else:
                    self.assertEqual(status, {"status": "Executed-Success"})
        self.assertEqual(seen, set(transfer.RESPONSE_ALTERNATIVES))

    def test_responses_come_back_from_json(self) -> None:
        for whole, kind, fields in RESPONSE_VECTORS:
            with self.subTest(vector=whole[:24]):
                back = transfer.decode_response(transfer.response_from_json(transfer.response_to_json(bytes.fromhex(whole))))
                self.assertEqual(back.kind, kind)
                self.assertEqual(back.result, fields.get("result", b""))
                self.assertEqual(back.error_code, fields.get("error_code"))
                if kind == transfer.RECEIVED_WITH_CID:
                    # The schema gives eimPackageReceivedWithCid as an object without members: no correlation.
                    self.assertEqual((back.transaction_id, back.eid), (b"", ""))
                else:
                    self.assertEqual(back.transaction_id, fields.get("transaction_id", b""))
                    self.assertEqual(back.eid, fields.get("eid", ""))

    def test_a_failed_header_without_a_member_reads_through_table_19a(self) -> None:
        def failed(subject: str = "", reason: str = "") -> dict[str, object]:
            status: dict[str, object] = {"status": "Failed"}
            if subject:
                status["statusCodeData"] = {"subjectCode": subject, "reasonCode": reason}
            return {"header": {"functionExecutionStatus": status}}

        for message, code in ((failed("8.31.1", "2.1"), 1), (failed("8.31.1", "1.1"), 2), (failed("8.1", "3.8"), 127),
                              (failed(), 127)):
            with self.subTest(code=code):
                self.assertEqual(transfer.decode_response(transfer.response_from_json(message)).error_code, code)

    def test_response_messages_that_do_not_follow_the_schema(self) -> None:
        result = base64.b64encode(EUICC_PACKAGE_RESULT).decode("ascii")
        for message in (
            None, [], {},
            {"header": {"functionExecutionStatus": {"status": "Executed-Success"}}},
            {"header": "text"},
            {"euiccPackageResult": result, "eimPackageReceived": {}},
            {"euiccPackageResult": 7},
            {"ipaEuiccDataResponse": result},
            {"ePRAndNotifications": result},
            {"ePRAndNotifications": {"euiccPackageResult": result}},
            {"eimPackageError": "2"},
            {"eimPackageError": True},
            {"eimPackageError": 9},
            {"eimPackageErrorWithCid": result},
            {"eimPackageErrorWithCid": "%%%"},
        ):
            with self.subTest(message=repr(message)[:70]):
                with self.assertRaises(transfer.TransferError):
                    transfer.response_from_json(message)


class SchemaAgreement(unittest.TestCase):
    """The pinned vectors against the compiled SGP.32 v1.3 module, where the library holds it."""

    def setUp(self) -> None:
        from Tools.Asn1TlvDecode import gsma_schema

        if not gsma_schema.has_type("TransferEimPackageResponse"):
            self.skipTest("the SGP.32 v1.3 ASN.1 module is not in the specification library")
        self.schema = gsma_schema

    def test_the_module_reads_what_the_codec_builds(self) -> None:
        unsigned = ("euiccPackageErrorUnsigned", {"eimId": "eim.example.test", "eimTransactionId": TXID})
        expected = {
            transfer.build_result_response(EUICC_PACKAGE_RESULT): ("euiccPackageResult", unsigned),
            transfer.build_received_response(with_cid=False): ("eimPackageReceived", None),
            transfer.build_received_response(transaction_id=TXID):
                ("eimPackageReceivedWithCid", {"correlationId": ("eimTransactionId", TXID)}),
            transfer.build_received_response(eid=EID):
                ("eimPackageReceivedWithCid", {"correlationId": ("eidValue", bytes.fromhex(EID))}),
            transfer.build_received_response(): ("eimPackageReceivedWithCid", {}),
            transfer.build_error_response(2, with_cid=False): ("eimPackageError", 2),
            transfer.build_error_response(1, transaction_id=TXID):
                ("eimPackageErrorWithCid", {"correlationId": ("eimTransactionId", TXID), "eimPackageError": 1}),
            transfer.build_error_response(127): ("eimPackageErrorWithCid", {"eimPackageError": 127}),
        }
        for built, value in expected.items():
            with self.subTest(alternative=value[0], built=built.hex()[:24]):
                self.assertEqual(self.schema.decode_type("TransferEimPackageResponse", built), value)
                self.assertEqual(self.schema.encode_type("TransferEimPackageResponse", value), built)

    def test_the_module_writes_the_request_vectors(self) -> None:
        values = {
            "ipaEuiccDataRequest": {"tagList": bytes.fromhex("BF20BF22"), "eimTransactionId": TXID},
            "eimAcknowledgements": [1, 2],
            "profileDownloadTriggerRequest": {"profileDownloadData": ("contactDefaultSmdp", None),
                                              "eimTransactionId": TXID},
        }
        for whole, kind, _package in REQUEST_VECTORS:
            if kind not in values:
                continue
            with self.subTest(kind=kind):
                self.assertEqual(self.schema.encode_type("TransferEimPackageRequest", (kind, values[kind])).hex().upper(),
                                 whole)


if __name__ == "__main__":
    unittest.main()
