# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES9+ a card sends to the eIM's own address for another SM-DP+: passed through, or refused.

A card's IPAe ran the direct download of a trigger over its connection to the
eIM, naming the trigger's SM-DP+ in InitiateAuthentication (SGP.22 v3.1 §5.6.1);
the local SM-DP+ answered as that server and the eUICC refused it (ciPKUnknown).
The listener now carries such a session to the SM-DP+ a served download trigger
names and refuses any other address (invalidDpAddress), and the local SM-DP+
never answers for an address it is not. No test leaves the process: the
SM-DP+ on the other side is a recorder.
"""

from __future__ import annotations

import json
import urllib.request
from http import HTTPStatus

from SCP11.eim_local.engine.es9_binding import ES9_PREFIX, handle_es9_asn1
from SCP11.eim_local.engine.es9_passthrough import MAX_SESSIONS, Es9PassThrough
from SCP11.eim_local.engine.esipa import LocalEimHttpServer
from SCP11.eim_local.engine.service import OperationRequest
from SCP11.eim_local.engine.smdp import LocalSmdp, SmdpAddressError
from SCP11.eim_local.engine.store import STATE_SENT
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from tests.test_local_eim_service import ServiceTestBase
from tests.test_local_eim_smdp_direct import (
    AUTHENTICATE_SERVER_RESPONSE,
    BOUND_PACKAGE,
    CANCEL_SESSION_RESPONSE,
    CI_PKID,
    INSTALLATION_RESULT,
    METADATA,
    PREPARE_DOWNLOAD_RESPONSE,
    SIGNATURE,
    SIGNED1,
    SIGNED2,
    SMDP_HOST,
    TX,
    StubSmdp,
)

FOREIGN = "dp.example.test"
PROTOCOL = "gsma/rsp/v2.5.0"
tlv = esipa.tlv


class Upstream:
    """The SM-DP+ a session is passed through to: records each call and answers as told."""

    def __init__(self) -> None:
        self.certificate = StubSmdp().certificate
        self.calls: list[tuple[str, bytes, str]] = []
        self.transaction = TX
        self.failing: Exception | None = None
        self.authenticate_client = es9_asn1.encode_authenticate_client_ok(
            TX, METADATA, SIGNED2, tlv(b"\x5F\x37", SIGNATURE), self.certificate)

    def __call__(self, host: str, body: bytes, protocol: str) -> bytes:
        self.calls.append((host, bytes(body), protocol))
        if self.failing is not None:
            raise self.failing
        tag = es9_asn1.unwrap(body)[:2]
        if tag == esipa.TAG_INITIATE_AUTHENTICATION:
            return es9_asn1.encode_initiate_authentication_ok(self.transaction, SIGNED1, SIGNATURE, CI_PKID,
                                                              self.certificate)
        if tag == esipa.TAG_AUTHENTICATE_CLIENT:
            return self.authenticate_client
        if tag == esipa.TAG_GET_BOUND_PROFILE_PACKAGE:
            return es9_asn1.encode_get_bound_profile_package_ok(TX, BOUND_PACKAGE)
        if tag == esipa.TAG_CANCEL_SESSION:
            return es9_asn1.encode_cancel_session_ok()
        return b""


def _initiate(address: str = FOREIGN) -> bytes:
    return es9_asn1.encode_initiate_authentication_request(b"\x01" * 16, address, b"")


class PassThroughTestBase(ServiceTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.upstream = Upstream()
        self.lines: list[str] = []
        self.passthrough = Es9PassThrough(self.engine, StubSmdp(), log=self.lines.append, poster=self.upstream)
        self.trigger = self.queue_trigger(f"1${FOREIGN}$MATCH-PASS-1")

    def queue_trigger(self, code: str, *, served: bool = True) -> object:
        operation = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_DOWNLOAD_TRIGGER",
                                                         params={"activation_code": code})])[0]
        if served:
            # What serving it to the IPA leaves (the eIM first asks the IPA Capabilities): a SENT trigger.
            with self.engine.store.transaction() as connection:
                stored = self.engine.store.operation(operation.id, connection)
                stored.state = STATE_SENT
                self.engine.store.save_operation(stored, connection)
        return operation

    def timeline(self) -> list[str]:
        return [str(item.get("event", "")) for item in self.engine.operation(self.trigger.id).history]


class PassThroughTests(PassThroughTestBase):
    def test_an_initiate_authentication_for_the_trigger_s_sm_dp_plus_goes_there_unchanged(self) -> None:
        body = _initiate()
        self.assertTrue(self.passthrough.claims(body))
        status, answer, note = self.passthrough.handle(body, PROTOCOL)
        self.assertEqual(self.upstream.calls, [(FOREIGN, body, PROTOCOL)])
        self.assertEqual((status, answer), (HTTPStatus.OK, self.upstream(FOREIGN, body, PROTOCOL)))
        self.assertEqual(self.passthrough.sessions(), 1)
        self.assertEqual(note, f"ES9+ InitiateAuthentication passed through to {FOREIGN} (transactionId {TX.hex().upper()})")
        self.assertIn(note, self.timeline())

    def test_the_later_steps_follow_the_transaction_id_and_the_installation_result_ends_it(self) -> None:
        self.passthrough.handle(_initiate(), PROTOCOL)
        steps = (es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE),
                 es9_asn1.encode_get_bound_profile_package_request(TX, PREPARE_DOWNLOAD_RESPONSE))
        for body in steps:
            self.assertTrue(self.passthrough.claims(body))
            status, answer, _note = self.passthrough.handle(body, PROTOCOL)
            self.assertEqual(status, HTTPStatus.OK)
            self.assertEqual(answer, self.upstream(FOREIGN, body, PROTOCOL))
        self.assertIn(f"ES9+ GetBoundProfilePackage passed through to {FOREIGN} "
                      f"({len(es9_asn1.encode_get_bound_profile_package_ok(TX, BOUND_PACKAGE))} bytes)", self.timeline())
        notification = es9_asn1.encode_handle_notification(INSTALLATION_RESULT)
        self.assertTrue(self.passthrough.claims(notification))
        self.assertEqual(self.passthrough.handle(notification, PROTOCOL)[:2], (HTTPStatus.NO_CONTENT, b""))
        self.assertEqual(self.passthrough.sessions(), 0)
        self.assertFalse(self.passthrough.claims(notification))
        self.assertEqual({host for host, _body, _protocol in self.upstream.calls}, {FOREIGN})

    def test_a_cancel_session_ends_the_session_too(self) -> None:
        self.passthrough.handle(_initiate(), PROTOCOL)
        cancel = es9_asn1.encode_cancel_session_request(TX, CANCEL_SESSION_RESPONSE)
        self.assertTrue(self.passthrough.claims(cancel))
        self.assertEqual(self.passthrough.handle(cancel, PROTOCOL)[1], es9_asn1.encode_cancel_session_ok())
        self.assertEqual(self.passthrough.sessions(), 0)

    def test_a_step_of_a_session_nobody_passed_through_is_left_to_the_local_sm_dp_plus(self) -> None:
        self.assertFalse(self.passthrough.claims(
            es9_asn1.encode_authenticate_client_request(bytes(16), AUTHENTICATE_SERVER_RESPONSE)))
        self.assertFalse(self.passthrough.claims(es9_asn1.encode_handle_notification(INSTALLATION_RESULT)))
        self.assertFalse(self.passthrough.claims(b"\x30\x00"))

    def test_the_local_sm_dp_plus_s_own_address_is_not_claimed(self) -> None:
        self.assertFalse(self.passthrough.claims(_initiate(SMDP_HOST)))
        self.assertFalse(self.passthrough.claims(_initiate(SMDP_HOST.upper() + ".")))

    def test_an_address_no_served_trigger_names_is_refused_and_nobody_is_called(self) -> None:
        # Queued but not served yet: the card cannot have it, so it opens nothing either.
        self.queue_trigger("1$queued.example.test$MATCH-PASS-2", served=False)
        for address in ("other.example.test", "queued.example.test"):
            body = _initiate(address)
            self.assertTrue(self.passthrough.claims(body))
            status, answer, note = self.passthrough.handle(body, PROTOCOL)
            self.assertEqual((status, answer), (HTTPStatus.OK, es9_asn1.encode_initiate_authentication_error(
                es9_asn1.INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS)))
            self.assertIn("refused (invalidDpAddress)", note)
        self.assertEqual(self.upstream.calls, [])
        self.assertEqual(self.passthrough.sessions(), 0)

    def test_a_finished_trigger_opens_no_pass_through(self) -> None:
        self.engine.cancel(self.trigger.id)
        status, answer, _note = self.passthrough.handle(_initiate(), PROTOCOL)
        self.assertEqual(answer, es9_asn1.encode_initiate_authentication_error(
            es9_asn1.INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS))
        self.assertEqual(self.upstream.calls, [])

    def test_an_sm_dp_plus_that_cannot_be_reached_is_answered_undefined_error_with_the_cause_noted(self) -> None:
        self.upstream.failing = OSError("connection refused")
        status, answer, note = self.passthrough.handle(_initiate(), PROTOCOL)
        self.assertEqual((status, answer), (HTTPStatus.OK, es9_asn1.encode_initiate_authentication_error(
            es9_asn1.UNDEFINED_ERROR)))
        self.assertEqual(note, f"ES9+ InitiateAuthentication not passed through to {FOREIGN}: connection refused")
        self.assertIn(note, self.timeline())
        self.assertEqual(self.passthrough.sessions(), 0)

    def test_the_sm_dp_plus_s_refusal_is_named_on_the_timeline_in_either_integer_form(self) -> None:
        self.passthrough.handle(_initiate(), PROTOCOL)
        body = es9_asn1.encode_authenticate_client_request(TX, AUTHENTICATE_SERVER_RESPONSE)
        explicit = es9_asn1.wrap(tlv(esipa.TAG_AUTHENTICATE_CLIENT, tlv(b"\xA1", tlv(b"\x02", b"\x06"))))
        for answer in (explicit, es9_asn1.encode_authenticate_client_error(6)):
            self.upstream.authenticate_client = answer
            _status, passed, note = self.passthrough.handle(body, PROTOCOL)
            self.assertEqual(passed, answer)
            self.assertEqual(note, f"ES9+ AuthenticateClient passed through to {FOREIGN}: it answered matchingIdRefused (6)")

    def test_an_installation_result_the_sm_dp_plus_did_not_take_and_no_record_verifies_stays_with_the_card(self) -> None:
        self.passthrough.handle(_initiate(), PROTOCOL)
        self.upstream.failing = OSError("timed out")
        status, answer, note = self.passthrough.handle(es9_asn1.encode_handle_notification(INSTALLATION_RESULT), PROTOCOL)
        self.assertEqual((status, answer), (HTTPStatus.INTERNAL_SERVER_ERROR, b""))
        self.assertTrue(note.endswith("; left with the card"))

    def test_the_sessions_kept_are_bounded(self) -> None:
        for number in range(MAX_SESSIONS + 3):
            self.upstream.transaction = number.to_bytes(16, "big")
            self.passthrough.handle(_initiate(), PROTOCOL)
        self.assertEqual(self.passthrough.sessions(), MAX_SESSIONS)
        # The oldest made room: its later steps are no longer this pass-through's.
        self.assertFalse(self.passthrough.claims(
            es9_asn1.encode_authenticate_client_request(bytes(16), AUTHENTICATE_SERVER_RESPONSE)))


class LocalSmdpAddressTests(ServiceTestBase):
    def test_the_local_sm_dp_plus_refuses_to_answer_for_another_server(self) -> None:
        smdp = LocalSmdp(self.directory)
        payload = {"euiccChallenge": "01" * 16, "smdpAddress": FOREIGN, "euiccInfo1": ""}
        with self.assertRaises(SmdpAddressError) as refusal:
            smdp.handle(ES9_PREFIX + "initiateAuthentication", payload)
        self.assertEqual((refusal.exception.subject_code, refusal.exception.reason_code), ("8.8.1", "3.8"))
        self.assertEqual(handle_es9_asn1(smdp, _initiate()), (HTTPStatus.OK, es9_asn1.encode_initiate_authentication_error(
            es9_asn1.INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS)))


class ListenerTests(PassThroughTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.smdp = StubSmdp()
        self.server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=self.smdp)
        self.server.es9_passthrough = Es9PassThrough(self.engine, self.smdp, log=self.server.log, poster=self.upstream)
        self.server.start_in_thread()
        self.addCleanup(self.server.stop)

    def post(self, path: str, body: bytes, content_type: str) -> tuple[int, bytes]:
        request = urllib.request.Request(self.server.url + path, data=body, method="POST",
                                         headers={"Content-Type": content_type, "X-Admin-Protocol": PROTOCOL})
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback test server
            return response.status, response.read()

    def test_the_listener_passes_another_sm_dp_plus_s_session_through_and_keeps_its_own(self) -> None:
        status, answer = self.post("/gsma/rsp2/asn1", _initiate(), "application/x-gsma-rsp-asn1")
        self.assertEqual((status, answer), (200, self.upstream(FOREIGN, _initiate(), PROTOCOL)))
        self.assertEqual(self.upstream.calls[0], (FOREIGN, _initiate(), PROTOCOL))
        self.assertEqual(self.smdp.calls, [])
        record = self.engine.store.traffic(limit=1)[0]
        self.assertEqual(record.note, f"ES9+ InitiateAuthentication passed through to {FOREIGN} "
                                      f"(transactionId {TX.hex().upper()})")
        # The local SM-DP+'s own address is still its own.
        status, _answer = self.post("/gsma/rsp2/asn1", _initiate(SMDP_HOST), "application/x-gsma-rsp-asn1")
        self.assertEqual((status, [name for name, _payload in self.smdp.calls]), (200, ["initiateAuthentication"]))

    def test_the_json_binding_names_the_status_code_of_an_address_refused(self) -> None:
        self.server.smdp = LocalSmdp(self.directory)
        body = json.dumps({"euiccChallenge": "01" * 16, "smdpAddress": FOREIGN, "euiccInfo1": ""}).encode()
        _status, answer = self.post(ES9_PREFIX + "initiateAuthentication", body, "application/json")
        status = json.loads(answer)["header"]["functionExecutionStatus"]
        self.assertEqual((status["status"], status["statusCodeData"]["subjectCode"],
                          status["statusCodeData"]["reasonCode"]), ("Failed", "8.8.1", "3.8"))
