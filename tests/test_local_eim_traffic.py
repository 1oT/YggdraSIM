# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM traffic: the exchange records the listeners write, the renderer the surfaces share, the TLS key log.

Every POST a listener answers is recorded before the answer goes out, with
the peer's port (the number an IPAe terminal reads off its own channel socket),
the chain the server name picked and what the engine made of the request.
The renderer turns a record into names and values: the Psmo and Eco CHOICEs
of SGP.32 v1.3 (ASN.1 module, pages 204-205) are read whole.
"""

from __future__ import annotations

import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from SCP11.eim_local.engine import codec, esipa, tls_setup, traffic
from SCP11.eim_local.engine.catalogue import OperationError
from SCP11.eim_local.engine.esipa import LocalEimHttpServer, card_tls_context, card_tls_contexts, handle_asn1
from SCP11.eim_local.engine.server import KEYLOG_FILE, _keylog_path
from SCP11.eim_local.engine.service import SETTING_TLS_KEYLOG, STATE_SUCCESS, OperationRequest
from SCP11.eim_local.engine.store import TRAFFIC_CAP, EimStore, StoreError, TrafficRecord
from SCP11.shared import es9_asn1
from SCP11.shared.ber_tlv import read_single_ber_tlv
from tests.test_local_eim_service import EIM_FQDN, ServiceTestBase

EID = "89049032123451234512345678901235"
OTHER_EID = "89049032123451234512345678901243"
TEST_PLMN = bytes.fromhex("00F110")  # 001/01, the test PLMN


def _request(eid: str, *, rplmn: bytes = b"") -> bytes:
    body = codec.tlv(b"\x5A", bytes.fromhex(eid))
    if len(rplmn) > 0:
        body += codec.tlv(b"\x82", rplmn)
    return codec.tlv(b"\xBF\x4F", body)


def _record(record_id: int = 0, **values: object) -> TrafficRecord:
    fields = dict(
        id=record_id, at="2026-11-08T20:25:05.911+00:00", peer_host="127.0.0.1", peer_port=40000,
        listener_port=8744, tls_setup="alpha", tls_version="TLSv1.2", tls_cipher="ECDHE-ECDSA-AES256-GCM-SHA384",
        binding=traffic.BINDING_ESIPA_ASN1, path=esipa.ASN1_PATH, request=_request(EID), status=200,
        response=codec.build_get_eim_package_error(codec.NO_EIM_PACKAGE_AVAILABLE), duration_ms=2, eid=EID,
        operation_id=None, note="noEimPackageAvailable",
    )
    fields.update(values)
    return TrafficRecord(**fields)  # type: ignore[arg-type]


class TrafficStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.store = EimStore(Path(folder.name) / "local_eim.sqlite3")

    def test_records_are_written_queried_by_peer_eid_and_operation_and_capped(self) -> None:
        first = self.store.insert_traffic(_record(peer_port=40000, operation_id=7))
        second = self.store.insert_traffic(_record(peer_port=40001, eid=OTHER_EID))
        third = self.store.insert_traffic(_record(peer_port=40000, operation_id=8, status=204, response=b""))
        self.assertEqual((first, second, third), (1, 2, 3))
        newest = self.store.traffic(limit=2)
        self.assertEqual([record.id for record in newest], [3, 2])
        self.assertEqual([record.id for record in self.store.traffic(peer_port=40000, newest_first=False)], [1, 3])
        self.assertEqual([record.id for record in self.store.traffic(peer_port=40000, after_id=1)], [3])
        self.assertEqual([record.id for record in self.store.traffic(eid=OTHER_EID)], [2])
        self.assertEqual([record.id for record in self.store.traffic(operation_id=8)], [3])
        stored = self.store.traffic_record(1)
        self.assertEqual((stored.request, stored.response, stored.tls_setup, stored.note),
                         (_record().request, _record().response, "alpha", "noEimPackageAvailable"))
        self.assertEqual((stored.status, stored.response, stored.operation_id), (200, _record().response, 7))
        self.assertEqual(self.store.traffic_record(3).response, b"")
        with self.assertRaises(StoreError):
            self.store.traffic_record(99)
        # The newest *cap* rows stay; the oldest go as a new one is written.
        for _ in range(4):
            self.store.insert_traffic(_record(), cap=3)
        self.assertEqual([record.id for record in self.store.traffic(limit=10)], [7, 6, 5])
        self.assertGreaterEqual(TRAFFIC_CAP, 1000)


class ExchangeRendererTests(ServiceTestBase):
    def _serve(self, rplmn: bytes = b"") -> tuple[bytes, bytes]:
        request = _request(self.card.eid, rplmn=rplmn)
        _status, answer = handle_asn1(self.engine, request)
        return request, answer

    def _result_of(self, answer: bytes) -> bytes:
        _tag, package, _raw = read_single_ber_tlv(answer)
        return codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + self.card.exchange(package))

    def test_the_psmo_and_eco_choices_are_named_whole(self) -> None:
        # SGP.32 v1.3 ASN.1 module, pages 204-205: the nine Psmo and four Eco alternatives, by their context tags.
        self.assertEqual(traffic.PSMO_NAMES, {
            b"\xA3": "enable", b"\xA4": "disable", b"\xA5": "delete", b"\xBF\x2D": "listProfileInfo",
            b"\xA6": "getRAT", b"\xA7": "configureImmediateEnable", b"\xA8": "setFallbackAttribute",
            b"\xA9": "unsetFallbackAttribute", b"\xBF\x65": "setDefaultDpAddress",
        })
        self.assertEqual(traffic.ECO_NAMES, {b"\xA8": "addEim", b"\xA9": "deleteEim", b"\xAA": "updateEim",
                                             b"\xAB": "listEim"})
        names = traffic.tag_names()
        self.assertEqual(len(names["download"]), 5)
        self.assertEqual(names["bindings"], ("esipa-asn1", "esipa-json", "es9-asn1", "es9-json", "refused"))

    def test_a_get_eim_package_exchange_reads_as_names_and_values(self) -> None:
        disabled = next(profile.iccid for profile in self.card.state.profiles if profile.iccid != self.card.state.iccid)
        operation_id = self.engine.submit([OperationRequest(
            eid=self.card.eid, type="ENABLE_PROFILE", params={"iccid": disabled, "rollback": True})])[0].id
        request, answer = self._serve(rplmn=TEST_PLMN)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, request, answer, 200)
        self.assertEqual(view.summary, "GetEimPackageRequest (rPLMN 001/01) -> euiccPackageRequest: "
                                       f"enable ICCID {disabled}, rollback, counter 1")
        self.assertEqual((view.request, view.error), ("GetEimPackageRequest", ""))
        rows = [(row.tag, row.name) for row in view.rows]
        self.assertEqual(rows, [("BF4F", "GetEimPackageRequest"), ("5A", "eidValue"), ("82", "rPLMN"),
                                ("BF4F", "GetEimPackageResponse"), ("BF51", "EuiccPackageRequest"),
                                ("A3", "enable"), ("5F37", "eimSignature")])
        self.assertEqual(view.rows[2].value, "001/01")
        self.assertEqual(view.rows[5].value, f"ICCID {disabled}, rollback")
        self.assertIn("counter 1", view.rows[4].value)
        # The root rows carry the whole bodies, for the trace block that echoes them.
        self.assertEqual((view.rows[0].whole, view.rows[3].whole), (request, answer))
        operation = self.engine.operation(operation_id)
        package_rows = traffic.describe_package(bytes.fromhex(operation.served_hex))
        self.assertEqual([(row.tag, row.name) for row in package_rows],
                         [("BF51", "EuiccPackageRequest"), ("A3", "enable"), ("5F37", "eimSignature")])
        # OP shows the same rows under the served package.
        from SCP11.eim_local.engine_shell import EngineVerbs

        lines: list[str] = []
        EngineVerbs(SimpleNamespace(session=None), emit=lines.append).cmd_op(str(operation_id))
        self.assertIn("    served     : " + operation.served_hex, lines)
        self.assertIn(f"      A3    enable                         ICCID {disabled}, rollback", lines)

    def test_a_result_exchange_its_acknowledgement_and_the_stored_result(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="GET_RAT")])[0].id
        _request_body, answer = self._serve()
        provide = self._result_of(answer)
        status, acknowledgement = handle_asn1(self.engine, provide)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, provide, acknowledgement, status)
        self.assertRegex(view.summary, r"^ProvideEimPackageResult \(getRATResult: ok\) -> eimAcknowledgements seqNumber \d+$")
        self.assertEqual(view.error, "")
        self.assertIn(("A6", "getRATResult", "ok"), [(row.tag, row.name, row.value) for row in view.rows])
        self.assertEqual(view.rows[-1].name, "eimAcknowledgements")
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertEqual([(row.tag, row.name) for row in traffic.describe_result(bytes.fromhex(operation.result_hex))],
                         [("BF51", "euiccPackageResultSigned"), ("A6", "getRATResult"), ("5F37", "euiccSignEPR")])

    def test_errors_reports_and_refusals_are_named(self) -> None:
        request, answer = self._serve()
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, request, answer, 200)
        # The answer to an empty queue is the normal end of a poll, not an error.
        self.assertEqual((view.summary, view.error), ("GetEimPackageRequest -> noEimPackageAvailable", ""))
        unknown = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(OTHER_EID)))
        self.engine.set_setting("learn_unknown_eids", "off")
        status, answer = handle_asn1(self.engine, unknown)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, unknown, answer, status)
        self.assertEqual((view.answer, view.error), ("eidNotFound", "eidNotFound"))
        report = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + _request(self.card.eid, rplmn=TEST_PLMN))
        status, answer = handle_asn1(self.engine, report)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, report, answer, status)
        self.assertEqual(view.summary, "ProvideEimPackageResult (state report (GetEimPackageRequest, rPLMN 001/01)) -> emptyResponse")
        self.assertEqual(view.error, "")
        refused = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + codec.tlv(b"\xBF\x4F", b"\x01"))
        status, answer = handle_asn1(self.engine, refused)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, refused, answer, status)
        self.assertEqual((view.answer, view.error), ("undefinedError", "undefinedError"))
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, b"\x01\x02", b"", 400)
        self.assertEqual((view.summary, view.error), ("01 -> HTTP 400", "HTTP 400"))

    def test_handle_notification_json_and_es9_exchanges(self) -> None:
        self.engine.submit([OperationRequest(eid=self.card.eid, type="LIST_EIM")])
        _request_body, answer = self._serve()
        provide = self._result_of(answer)
        notification = codec.tlv(b"\xBF\x3D", provide)
        status, body = handle_asn1(self.engine, notification)
        view = traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, notification, body, status)
        self.assertEqual(view.summary, "HandleNotificationEsipa (listEimResult: ok) -> HTTP 204, no body")
        self.assertEqual(view.error, "")
        self.assertEqual(view.rows[1].name, "provideEimPackageResult")
        view = traffic.describe_exchange(
            traffic.BINDING_ESIPA_JSON, b'{"eidValue": "' + EID.encode() + b'"}',
            b'{"header": {"functionExecutionStatus": {"status": "Executed-Success"}}, "euiccPackageRequest": "..."}',
            200, path="/gsma/rsp2/esipa/getEimPackage")
        self.assertEqual(view.summary, "getEimPackage (eidValue) -> HTTP 200: euiccPackageRequest, Executed-Success")
        wrapped = es9_asn1.encode_initiate_authentication_request(bytes(16), "smdpp.example.test", b"\xBF\x20\x00")
        view = traffic.describe_exchange(traffic.BINDING_ES9_ASN1, wrapped, b"", 500)
        self.assertEqual((view.summary, view.error), ("ES9+ InitiateAuthenticationRequest -> HTTP 500", "HTTP 500"))

    def test_listing_lines_and_rows_as_text(self) -> None:
        record = _record(7)
        view = traffic.describe_record(record)
        line = traffic.summary_line(record, view)
        self.assertTrue(line.startswith("#7     20:25:05.911  127.0.0.1:40000       alpha        GetEimPackageRequest -> noEimPackageAvailable"), line)
        self.assertEqual(view.rows[-1].name, "exchange")
        self.assertIn("alpha TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384", view.rows[-1].value)
        text = traffic.rows_as_text(view, hex_bodies=True)
        self.assertIn(f"            {_request(EID).hex().upper()}", text)
        self.assertFalse(traffic.is_error(view))
        self.assertTrue(traffic.is_error(traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, _request(EID), b"", 500)))


class RecordedExchangeTests(ServiceTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.log: list[str] = []
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), log=self.log.append)
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)

    def _post(self, body: bytes) -> tuple[int, bytes, int]:
        head = (f"POST {esipa.ASN1_PATH} HTTP/1.1\r\nHost: {EIM_FQDN}\r\nContent-Type: {esipa.ASN1_CONTENT_TYPE}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
        with socket.create_connection(self.server.server_address[:2], timeout=10) as connection:
            local_port = int(connection.getsockname()[1])
            connection.sendall(head + body)
            reader = connection.makefile("rb")
            status = int(reader.readline().split()[1])
            length = 0
            while True:
                line = reader.readline().strip()
                if not line:
                    break
                name, _sep, value = line.decode("latin-1").partition(":")
                if name.lower() == "content-length":
                    length = int(value.strip())
            return status, reader.read(length) if length else b"", local_port

    def test_every_post_is_recorded_with_its_peer_port_before_the_answer_is_read(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="GET_RAT")])[0].id
        request = _request(self.card.eid)
        status, answer, port = self._post(request)
        self.assertEqual(status, 200)
        served = self.engine.store.traffic(limit=1)[0]
        self.assertEqual(
            (served.binding, served.path, served.status, served.peer_host, served.peer_port, served.listener_port),
            (traffic.BINDING_ESIPA_ASN1, esipa.ASN1_PATH, 200, "127.0.0.1", port, int(self.server.server_address[1])),
        )
        self.assertEqual((served.request, served.response, served.eid, served.operation_id), (request, answer, self.card.eid, operation_id))
        self.assertEqual((served.tls_setup, served.tls_version, served.note), ("", "", f"served operation {operation_id} (GET_RAT)"))
        self.assertGreaterEqual(served.duration_ms, 0)
        self.assertTrue(any(line.endswith(f"peer :{port} #{served.id}") for line in self.log), self.log)
        _tag, package, _raw = read_single_ber_tlv(answer)
        provide = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + self.card.exchange(package))
        status, _acknowledgement, port = self._post(provide)
        closed = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((status, closed.operation_id, closed.note), (200, operation_id, f"result of operation {operation_id} (GET_RAT): SUCCESS"))
        status, _body, port = self._post(b"\x01\x02")
        refused = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((status, refused.status, refused.eid), (400, 400, ""))
        # The request line and headers travel with the refusal: what the IPA sent around the body.
        self.assertTrue(refused.note.startswith("refused: not an ESipa message; request POST "), refused.note)
        self.assertIn("Content-Length", refused.note)
        # An empty ESipa POST (a live IPAe sends one now and then) is answered 204, not 400, so the IPA goes on.
        status, body, _port = self._post(b"")
        empty = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((status, body, empty.status, len(empty.request)), (204, b"", 204, 0))
        self.assertTrue(empty.note.startswith("empty ESipa request; answered 204"), empty.note)
        self.assertEqual([record.id for record in self.engine.store.traffic(after_id=served.id, newest_first=False)],
                         [closed.id, refused.id, empty.id])
        self.assertEqual(self.engine.store.traffic(peer_port=port)[0].id, refused.id)

    def test_a_body_the_listener_will_not_read_is_recorded_as_a_refusal(self) -> None:
        head = (f"POST {esipa.ASN1_PATH} HTTP/1.1\r\nHost: {EIM_FQDN}\r\nContent-Type: {esipa.ASN1_CONTENT_TYPE}\r\n"
                "Transfer-Encoding: chunked\r\n\r\nzz\r\n").encode("ascii")
        with socket.create_connection(self.server.server_address[:2], timeout=10) as connection:
            connection.sendall(head)
            status = int(connection.makefile("rb").readline().split()[1])
        self.assertEqual(status, 400)
        record = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((record.binding, record.status, record.request, record.response, record.path),
                         (traffic.BINDING_REFUSED, 400, b"", b"", esipa.ASN1_PATH))
        self.assertTrue(record.note.startswith("refused: a chunk size that is not hexadecimal; request POST "), record.note)
        self.assertIn("Transfer-Encoding: chunked", record.note)
        view = traffic.describe_record(record)
        self.assertEqual((view.summary, view.error), ("request refused -> HTTP 400", "HTTP 400"))
        self.assertTrue(any("refused: a chunk size" in line for line in self.log), self.log)


class KeyLogTests(ServiceTestBase):
    def test_the_setting_decides_the_key_log_and_every_context_takes_it(self) -> None:
        lines: list[str] = []
        self.assertEqual(_keylog_path(self.engine, self.directory, lines.append), "")
        self.assertFalse((self.directory / KEYLOG_FILE).exists())
        self.assertIs(self.engine.set_setting(SETTING_TLS_KEYLOG, "on"), True)
        path = _keylog_path(self.engine, self.directory, lines.append)
        self.assertEqual(path, str(self.directory / KEYLOG_FILE))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertTrue(lines and lines[-1].startswith("TLS key log"), lines)
        with self.assertRaises(OperationError):
            self.engine.set_setting(SETTING_TLS_KEYLOG, "maybe")
        identity = self.engine.identity()
        context = card_tls_context(identity.tls_certificate_path, identity.tls_key_path, keylog_path=path)
        self.assertEqual(context.keylog_filename, path)
        self.assertIsNone(card_tls_context(identity.tls_certificate_path, identity.tls_key_path).keylog_filename)
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options("alpha", {"fqdn": "alpha.example.test"}))
        materials = tls_setup.served_materials(self.directory, identity)
        self.assertEqual(len(materials), 2)
        seen: list[str] = []
        real = esipa.card_tls_context

        def _spy(*args: object, **kwargs: object) -> object:
            seen.append(str(kwargs.get("keylog_path", "")))
            return real(*args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(esipa, "card_tls_context", _spy):
            card_tls_contexts(materials, keylog_path=path)
        self.assertEqual(seen, [path, path])


if __name__ == "__main__":
    unittest.main()
