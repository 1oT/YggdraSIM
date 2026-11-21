# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM service: ESipa over HTTP, the background process, and the IPAd's route to it.

The IPAd client of the eSIM Management console polls the service by the eIM
FQDN in the card's eIM configuration; the service answers from the queue and
takes the result back (SGP.32 v1.3 §5.14.5, §5.14.6). The local SM-DP+ answers
ES9+ on the same address.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.esipa import LocalEimHttpServer, handle_asn1
from SCP11.eim_local.engine.server import STATUS_FILE, describe, local_route, start_background, stop_background
from SCP11.eim_local.engine.service import STATE_SUCCESS, LocalEim, OperationRequest
from SCP11.eim_local.engine.smdp import LocalSmdp, matching_id
from SCP11.live.es9_client import Es9LikeClient, local_eim_service_route
from SCP11.live.models import EimPollRequest
from SCP11.shared.ber_tlv import read_single_ber_tlv
from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic

EIM_ID = "1.3.6.1.4.1.32473.999.10.124"
EIM_FQDN = "eim.yggdrasim.local"


class SimCard:
    def __init__(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)

    @property
    def eid(self) -> str:
        return self.state.eid

    def exchange(self, payload: bytes, label: str = "") -> bytes:
        response, sw1, sw2 = self.logic.handle_store_data(bytes(payload))
        if (sw1, sw2) != (0x90, 0x00):
            raise AssertionError(f"{label}: status word {sw1:02X}{sw2:02X}")
        return response


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _poll_request(eid: str, body: bytes) -> EimPollRequest:
    return EimPollRequest(
        eim_fqdn=EIM_FQDN, eim_id=EIM_ID, eim_id_type="1", counter_value="", association_token="",
        supported_protocol="", euicc_ci_pkid="", indirect_profile_download="", euicc_configured_data="",
        eim_configuration_data="", eid=eid, raw_body=body,
    )


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(self.directory)})
        environment.start()
        self.addCleanup(environment.stop)
        self.engine = LocalEim(self.directory)
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn=EIM_FQDN)
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        eum, euicc = codec.decode_get_certs_response(self.card.exchange(codec.build_get_certs_request()))
        self.engine.apply_card_reads(self.card.eid, {"euicc_certificate": euicc, "eum_certificate": eum})


class RequestFramingTests(ServiceTestBase):
    """How an IPA's HTTP client may frame a POST: Content-Length, chunked, a chunk terminator left over."""

    def setUp(self) -> None:
        super().setUp()
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=LocalSmdp(self.directory))
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)
        self.request = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)))

    def _exchange(self, raw: bytes, answers: int = 1) -> list[tuple[int, bytes]]:
        with socket.create_connection(self.server.server_address[:2], timeout=10) as connection:
            connection.sendall(raw)
            reader = connection.makefile("rb")
            results: list[tuple[int, bytes]] = []
            for _ in range(answers):
                status = int(reader.readline().split()[1])
                length = 0
                while True:
                    line = reader.readline().strip()
                    if not line:
                        break
                    name, _sep, value = line.decode("latin-1").partition(":")
                    if name.lower() == "content-length":
                        length = int(value.strip())
                results.append((status, reader.read(length) if length else b""))
            return results

    def _post(self, body: bytes, *, chunked: bool = False, keep_alive: bool = False) -> bytes:
        head = (f"POST /gsma/rsp2/asn1 HTTP/1.1\r\nHost: {EIM_FQDN}\r\nContent-Type: application/x-gsma-rsp-asn1\r\n"
                + ("Connection: keep-alive\r\n" if keep_alive else ""))
        if chunked:
            half = len(body) // 2
            return (head + "Transfer-Encoding: chunked\r\n\r\n").encode("ascii") + \
                f"{half:x}\r\n".encode("ascii") + body[:half] + b"\r\n" + \
                f"{len(body) - half:x}\r\n".encode("ascii") + body[half:] + b"\r\n0\r\n\r\n"
        return (head + f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body

    def test_a_chunked_body_is_read_whole(self) -> None:
        # No package queued: GetEimPackage answers noEimPackageAvailable (SGP.32 v1.3 §5.14.5), which needs the whole EID.
        self.assertEqual(self._exchange(self._post(self.request, chunked=True)), [(200, bytes.fromhex("BF4F03020101"))])

    def test_a_chunk_terminator_left_before_the_next_request_is_skipped(self) -> None:
        first = self._post(self.request, keep_alive=True)
        second = self._post(self.request)
        answers = self._exchange(first + b"0\r\n\r\n" + second, answers=2)
        self.assertEqual(answers, [(200, bytes.fromhex("BF4F03020101"))] * 2)

    def test_an_oversized_or_malformed_chunked_body_is_refused(self) -> None:
        bad = (f"POST /gsma/rsp2/asn1 HTTP/1.1\r\nHost: {EIM_FQDN}\r\nTransfer-Encoding: chunked\r\n\r\n"
               "zz\r\n").encode("ascii")
        self.assertEqual(self._exchange(bad)[0][0], 400)


class HandlerTests(ServiceTestBase):
    def test_a_state_report_inside_provide_eim_package_result_is_acknowledged(self) -> None:
        # A live IPAe sends GetEimPackageRequest { eid, rPLMN } under 'BF50' after a Profile state change;
        # SGP.32 v1.3 §5.14.6 defines no such EimPackageResult, so it is acknowledged, not refused.
        eid = codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))
        plmn = codec.tlv(b"\x82", bytes.fromhex("00F110"))
        report = codec.tlv(b"\xBF\x50", eid + codec.tlv(b"\xBF\x4F", eid + plmn))
        notes: list[str] = []
        status, body = handle_asn1(self.engine, report, log=notes.append)
        self.assertEqual((status, body), (200, bytes.fromhex("BF50023000")))
        self.assertEqual(self.engine.record(self.card.eid).data["rplmn_hex"], "00F110")
        self.assertIn("rPLMN 00F110", notes[0])
        self.assertEqual([entry.type for entry in self.engine.queue(self.card.eid)], [])
        notice = codec.tlv(b"\xBF\x50", eid + codec.tlv(b"\xBF\x4F", eid + codec.tlv(b"\x80", b"") + plmn))
        self.assertEqual(handle_asn1(self.engine, notice)[1], bytes.fromhex("BF50023000"))
        queued = self.engine.queue(self.card.eid)
        self.assertEqual([(entry.type, entry.system) for entry in queued], [("PROFILE_INFO_LIST", True)])
        # Anything else the codec cannot read is still undefinedError.
        garbage = codec.tlv(b"\xBF\x50", eid + codec.tlv(b"\xBF\x4F", b"\x01"))
        self.assertEqual(handle_asn1(self.engine, garbage, log=notes.append)[1], bytes.fromhex("BF500302017F"))
        self.assertIn("refused", notes[-1])

    def test_unknown_eid_and_missing_eid(self) -> None:
        stranger = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex("89049032123451234512345678901299")))
        self.engine.set_setting("learn_unknown_eids", "off")
        status, body = handle_asn1(self.engine, stranger)
        self.assertEqual((status, body), (200, bytes.fromhex("BF4F03020102")))
        status, body = handle_asn1(self.engine, bytes.fromhex("BF4F00"))
        self.assertEqual(body, bytes.fromhex("BF4F03020104"))

    def test_an_unknown_eid_is_learned_by_default(self) -> None:
        stranger = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex("89049032123451234512345678901299")))
        status, body = handle_asn1(self.engine, stranger)
        self.assertEqual((status, body), (200, bytes.fromhex("BF4F03020101")))
        self.assertIsNotNone(self.engine.record("89049032123451234512345678901299"))

    def test_handle_notification_carries_a_result_and_answers_no_content(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="GET_RAT")])[0].id
        _status, body = handle_asn1(self.engine, codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))))
        _tag, package, _raw = read_single_ber_tlv(body)
        result = self.card.exchange(package)
        provide = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + result)
        status, answer = handle_asn1(self.engine, codec.tlv(b"\xBF\x3D", provide))
        self.assertEqual((status, answer), (204, b""))
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)


class IpadRouteTests(ServiceTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=LocalSmdp(self.directory))
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)
        status = {"pid": os.getpid(), "url": self.server.url, "eim_fqdn": EIM_FQDN, "smdp_address": "smdpp.example.test"}
        (self.directory / STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")

    def test_route_names(self) -> None:
        self.assertEqual(local_route(EIM_FQDN), self.server.url)
        self.assertEqual(local_route("https://EIM.yggdrasim.local:443/gsma/rsp2/asn1"), self.server.url)
        self.assertEqual(local_route("smdpp.example.test"), self.server.url)
        for unlisted in ("eim2.yggdrasim.local", "eim42.yggdrasim.local"):
            self.assertEqual(local_route(unlisted), self.server.url, unlisted)
        self.assertEqual(local_route("other.example.test"), "")
        # Only eim*.yggdrasim.local is the Local eIM's, whatever a status file claims.
        status = json.loads((self.directory / STATUS_FILE).read_text(encoding="utf-8"))
        status["eim_fqdns"] = ["eim1.operator.example.com", "eim.example.test", EIM_FQDN]
        status["eim_fqdn"] = "eim3.lab.example.net"
        (self.directory / STATUS_FILE).write_text(json.dumps(status), encoding="utf-8")
        for name in ("eim1.operator.example.com", "eim.example.test", "eim3.lab.example.net", "eim.lab.yggdrasim.local"):
            self.assertEqual(local_route(name), "", name)
            self.assertEqual(local_eim_service_route(name), "", name)
        self.assertEqual(local_route(EIM_FQDN), self.server.url)
        self.assertEqual(local_eim_service_route(EIM_FQDN), self.server.url)
        dead = {"pid": 0, "url": self.server.url, "eim_fqdn": EIM_FQDN}
        (self.directory / STATUS_FILE).write_text(json.dumps(dead), encoding="utf-8")
        self.assertEqual(local_route(EIM_FQDN), "")

    def test_the_eim_management_ipad_client_polls_the_service(self) -> None:
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0].id
        client = Es9LikeClient(base_url="https://rsp.example.com")
        get = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)))
        decoded = client._dispatch_eim_request(_poll_request(self.card.eid, get))
        packages = decoded.get("euiccPackageList", [])
        self.assertEqual(len(packages), 1)
        result = self.card.exchange(base64.b64decode(packages[0]))
        provide = codec.tlv(b"\xBF\x50", codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + result)
        answer = client._dispatch_eim_request(_poll_request(self.card.eid, provide))
        self.assertEqual(answer.get("packageFormat"), "eimAcknowledgements")
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)
        empty = client._dispatch_eim_request(_poll_request(self.card.eid, get))
        self.assertEqual(empty.get("eimResultCode"), codec.NO_EIM_PACKAGE_AVAILABLE)

    def test_local_smdp_answers_es9_on_the_same_address(self) -> None:
        try:
            self.server.smdp.session()._ensure_local_material_loaded()
        except (OSError, RuntimeError, ValueError) as error:
            self.skipTest(f"SGP.26 SM-DP+ material not readable here: {error}")
        challenge = self.card.exchange(bytes.fromhex("BF2E00"))[-16:]
        body = json.dumps({"euiccChallenge": base64.b64encode(challenge).decode(), "smdpAddress": "smdpp.example.test"})
        request = urllib.request.Request(
            self.server.url + "/gsma/rsp2/es9plus/initiateAuthentication",
            data=body.encode(), method="POST", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            answer = json.loads(response.read().decode())
        self.assertEqual(answer["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        for name in ("transactionId", "serverSigned1", "serverSignature1", "serverCertificate"):
            self.assertTrue(answer[name], name)


    def test_an_es9_failure_is_answered_not_dropped(self) -> None:
        request = urllib.request.Request(
            self.server.url + "/gsma/rsp2/es9plus/getBoundProfilePackage",
            data=b"{}", method="POST", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            answer = json.loads(response.read().decode())
        self.assertEqual(answer["header"]["functionExecutionStatus"]["status"], "Failed")


class MatchingIdTests(unittest.TestCase):
    def test_matching_id_is_read_from_ctx_params1(self) -> None:
        tlv = codec.tlv
        # SGP.22 v3.1 EuiccSigned1: ctxParams1 is an untagged CHOICE, so the
        # ctxParamsForCommonAuthentication 'A0' sits directly in euiccSigned1.
        common = tlv(b"\xA0", tlv(b"\x80", b"MID-1") + tlv(b"\xA1", b""))
        signed1 = tlv(b"\x30", tlv(b"\x80", b"\x01" * 16) + tlv(b"\x83", b"smdpp.example.test") + common)
        response = tlv(b"\xBF\x38", tlv(b"\xA0", signed1 + tlv(b"\x5F\x37", b"\x00" * 64)))
        self.assertEqual(matching_id(response), "MID-1")
        self.assertEqual(matching_id(b""), "")


class BackgroundProcessTests(ServiceTestBase):
    def test_start_route_status_stop(self) -> None:
        port = _free_port()
        status = start_background(self.directory, port=port)
        self.addCleanup(stop_background, self.directory)
        self.assertEqual(status["url"], f"http://127.0.0.1:{port}")
        self.assertTrue(describe(self.directory)["answers"])
        self.assertEqual(local_route(EIM_FQDN, self.directory), f"http://127.0.0.1:{port}")
        self.assertTrue(stop_background(self.directory))
        self.assertFalse(describe(self.directory)["running"])
        self.assertFalse(stop_background(self.directory))


if __name__ == "__main__":
    unittest.main()
