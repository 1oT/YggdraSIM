# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""eIM Package Injection: the Local eIM calls ESipa.TransferEimPackage on an IPA.

The eIM side is the real engine and ``inject``; the IPA side is
``answer_transfer`` over the simulated eUICC, first in process and then behind
the loopback listener in both bindings (SGP.32 v1.3 §3.1.1.2, §5.14.4).
"""

from __future__ import annotations

import contextlib
import datetime
import http.client
import io
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import codec, traffic
from SCP11.eim_local.engine.delivery import answer_ipa_euicc_data_request
from SCP11.eim_local.engine.inject import (
    AnswerLost,
    HttpTransport,
    InjectError,
    TargetUnreachable,
    TrafficLog,
    inject,
    parse_target,
)
from SCP11.eim_local.engine.service import (
    ROUTE_INJECT,
    STATE_CREATED,
    STATE_ERROR,
    STATE_SENT,
    STATE_SUCCESS,
    LocalEimError,
    OperationRequest,
)
from SCP11.eim_local.main import EimLocalShell
from SCP11.live.transfer_provider import TransferListener, answer_transfer
from SCP11.shared import esipa_transfer as transfer
from SCP11.shared.ber_tlv import retag_sequence
from tests.test_local_eim_engine import DISABLED, EIM_ID, ENABLED, EngineTestBase, SimCard
from yggdrasim_common.gui_server.actions import eim_local_ops
from yggdrasim_common.gui_server.actions.registry import ActionContext

TXID = bytes.fromhex("A1A2A3A4")
EID = "89049032123451234512345678901235"


class SimIpa:
    """An IPAd over the simulated eUICC: what ``answer_transfer`` needs, and a count of what ran."""

    def __init__(self, card: SimCard) -> None:
        self.card = card
        self.packages: list[bytes] = []
        self.removed: list[int] = []
        self.log: list[str] = []

    def run_package(self, package: bytes) -> bytes:
        self.packages.append(bytes(package))
        if package.startswith(codec.TAG_IPA_EUICC_DATA):
            return answer_ipa_euicc_data_request(self.card.exchange, package, EIM_ID)
        answer = self.card.exchange(package, "LoadEuiccPackage")
        if codec.holds_psmos(package):
            notifications = codec.decode_notification_list(
                self.card.exchange(codec.build_retrieve_notifications_request(), "RetrieveNotificationsList"))
            if notifications:
                # ePRAndNotifications: the pending Notifications after the signed result (§5.14.4).
                return codec.tlv(b"\x30", answer + codec.tlv(b"\xA0", b"".join(notifications)))
        return answer

    def remove_acknowledged(self, seq_number: int) -> None:
        self.removed.append(int(seq_number))
        self.card.exchange(codec.build_notification_sent(seq_number), "RemoveNotificationFromList")

    def answer(self, request: bytes) -> bytes:
        return answer_transfer(request, eid=self.card.eid, run_package=self.run_package,
                               remove_acknowledged=self.remove_acknowledged, log=self.log.append)


class LoopTransport:
    """The injector's transport without a socket: every call goes straight to the IPA."""

    def __init__(self, ipa: SimIpa) -> None:
        self.ipa = ipa
        self.requests: list[bytes] = []
        self.opened = 0
        self.unreachable = False
        self.lose_answers = 0
        self.replace_answer: bytes | None = None

    def open(self) -> None:
        if self.unreachable:
            raise TargetUnreachable("no IPA listens there")
        self.opened += 1

    def call(self, request: bytes) -> bytes:
        self.requests.append(bytes(request))
        answer = self.ipa.answer(request)
        if self.lose_answers > 0:
            self.lose_answers -= 1
            raise AnswerLost("the connection went away before the answer")
        if self.replace_answer is not None:
            answer, self.replace_answer = self.replace_answer, None
        return answer

    def close(self) -> None:
        return

    def kinds(self) -> list[str]:
        return [transfer.decode_request(request).kind for request in self.requests]


class InjectBase(EngineTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.ipa = SimIpa(self.card)
        self.transport = LoopTransport(self.ipa)

    def run_inject(self, **options: object) -> list:
        self.lines: list[str] = []
        return inject(self.engine, self.card.eid, self.transport, emit=self.lines.append, **options)  # type: ignore[arg-type]

    def prime(self) -> None:
        """Run one signed operation, so the record holds the eUICC certificate and the queue is empty."""
        operation_id = self.queue("PROFILE_INFO_LIST")
        self.run_inject()
        self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)
        self.transport.requests.clear()
        self.ipa.packages.clear()
        self.ipa.removed.clear()


class InjectLoopTests(InjectBase):
    def test_the_certificate_is_asked_for_before_the_first_signed_package(self) -> None:
        # The injecting eIM has no reader: what it verifies results with comes through the IPA as well.
        self.assertEqual(self.engine.record(self.card.eid).euicc_certificate, b"")
        operation_id = self.queue("PROFILE_INFO_LIST")
        steps = self.run_inject()
        self.assertEqual(self.transport.kinds()[:2], ["ipaEuiccDataRequest", "euiccPackageRequest"])
        self.assertNotEqual(self.engine.record(self.card.eid).euicc_certificate, b"")
        self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)
        self.assertNotIn("unverified", self.engine.operation(operation_id).flags)
        self.assertEqual(len(steps), 2)

    def test_queued_operations_run_through_transfer_eim_package(self) -> None:
        self.prime()
        enable = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        listing = self.queue("PROFILE_INFO_LIST")
        data = self.queue("IPA_EUICC_DATA", tags="BF22")
        steps = self.run_inject()
        for operation_id in (listing, enable, data):
            operation = self.engine.operation(operation_id)
            self.assertEqual((operation.state, operation.route), (STATE_SUCCESS, ROUTE_INJECT), operation.error)
            self.assertTrue(any("served over inject" in str(entry.get("event")) for entry in operation.history))
        self.assertTrue(all(step.answer in transfer.RESPONSE_ALTERNATIVES for step in steps))
        profiles = {profile["iccid"]: profile["state"] for profile in self.engine.record(self.card.eid).profiles}
        self.assertEqual((profiles[DISABLED], profiles[ENABLED]), ("enabled", "disabled"))
        # Every package went out once, as its own alternative of the request.
        self.assertEqual(len(set(self.transport.requests)), len(self.transport.requests))
        self.assertIn("euiccPackageRequest", self.transport.kinds())
        self.assertIn("ipaEuiccDataRequest", self.transport.kinds())

    def test_an_injection_is_not_counted_as_a_poll(self) -> None:
        self.prime()
        before = self.engine.record(self.card.eid)
        self.queue("PROFILE_INFO_LIST")
        self.run_inject()
        after = self.engine.record(self.card.eid)
        self.assertEqual((after.poll_count, after.last_poll_at), (before.poll_count, before.last_poll_at))

    def test_what_the_engine_acknowledges_is_the_next_call(self) -> None:
        self.prime()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        steps = self.run_inject()
        step = next(step for step in steps if step.operation_id == operation_id)
        self.assertTrue(step.acknowledged)
        self.assertEqual(self.ipa.removed, step.acknowledged)
        kinds = self.transport.kinds()
        position = kinds.index("euiccPackageRequest")
        self.assertEqual(kinds[position + 1], "eimAcknowledgements")
        # SGP.32 v1.3 §3.3.1 steps 15-16: the acknowledged entries are gone from the eUICC.
        left = {entry.seq_number for entry in self.card.state.euicc_package_results}
        self.assertFalse(left & set(step.acknowledged))

    def test_a_target_that_cannot_be_reached_costs_nothing(self) -> None:
        self.prime()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        counter = self.engine.record(self.card.eid).counter_value
        self.transport.unreachable = True
        with self.assertRaises(TargetUnreachable):
            self.run_inject()
        operation = self.engine.operation(operation_id)
        self.assertEqual((operation.state, operation.counter_value), (STATE_CREATED, None))
        self.assertEqual(self.engine.record(self.card.eid).counter_value, counter)

    def test_a_lost_answer_is_recovered_before_anything_new_is_served(self) -> None:
        self.prime()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        later = self.queue("PROFILE_INFO_LIST")
        self.transport.lose_answers = 1
        steps = self.run_inject()
        self.assertEqual([step.answer for step in steps], ["no answer"])
        self.assertEqual((self.state_of(operation_id), self.state_of(later)), (STATE_SENT, STATE_CREATED))
        sent_once = list(self.transport.requests)
        steps = self.run_inject()
        # The first call of the next run asks the eUICC for its stored results.
        self.assertEqual(transfer.decode_request(self.transport.requests[len(sent_once)]).kind, "ipaEuiccDataRequest")
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertTrue(any(flag.startswith("recovered-by-") for flag in operation.flags))
        self.assertEqual(self.state_of(later), STATE_SUCCESS)
        # The signed package went out once: no request was sent twice.
        self.assertEqual(len(set(self.transport.requests)), len(self.transport.requests))
        self.assertEqual(sum(1 for package in self.ipa.packages if package.startswith(codec.TAG_EUICC_PACKAGE)
                             and codec.changes_profile_state(package)), 1)

    def test_an_error_answer_closes_the_operation(self) -> None:
        self.prime()
        operation_id = self.queue("PROFILE_INFO_LIST")
        self.transport.replace_answer = transfer.build_error_response(transfer.INVALID_PACKAGE_FORMAT, eid=self.card.eid)
        steps = self.run_inject()
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_ERROR)
        self.assertIn("invalidPackageFormat", operation.error)
        self.assertEqual(steps[0].answer, transfer.ERROR_WITH_CID)

    def test_an_acknowledgement_in_place_of_a_result_keeps_the_operation_in_flight(self) -> None:
        self.prime()
        operation_id = self.queue("PROFILE_INFO_LIST")
        self.transport.replace_answer = transfer.build_received_response(eid=self.card.eid)
        steps = self.run_inject()
        self.assertEqual(len(steps), 1)
        self.assertEqual(self.state_of(operation_id), STATE_SENT)
        self.assertTrue(any("without a result" in line for line in self.lines))

    def test_an_answer_that_does_not_read_keeps_the_operation_in_flight(self) -> None:
        self.prime()
        for answer in (b"", b"\x00", bytes.fromhex("BF4E00"), bytes.fromhex("BF4E03BF5100")):
            with self.subTest(answer=answer.hex()):
                operation_id = self.queue("PROFILE_INFO_LIST")
                self.transport.replace_answer = answer
                steps = self.run_inject()
                self.assertEqual(self.state_of(operation_id), STATE_SENT)
                self.assertEqual(steps[-1].operation_id, operation_id)
                self.engine.cancel(operation_id)

    def test_a_download_stays_queued(self) -> None:
        self.prime()
        operation_id = self.queue("PROFILE_DOWNLOAD_TRIGGER", activation_code="1$smdp.example.test$MATCHING-ID")
        self.run_inject()
        self.assertEqual(self.state_of(operation_id), STATE_CREATED)
        self.assertNotIn("profileDownloadTriggerRequest", self.transport.kinds())
        self.assertTrue(any("a profile download" in line for line in self.lines), self.lines)

    def test_once_sends_one_package(self) -> None:
        self.prime()
        first = self.queue("PROFILE_INFO_LIST")
        second = self.queue("PROFILE_INFO_LIST")
        steps = self.run_inject(once=True)
        self.assertEqual(len(steps), 1)
        self.assertEqual((self.state_of(first), self.state_of(second)), (STATE_SUCCESS, STATE_CREATED))


def _certificate(serial_number: str = "") -> bytes:
    """A self-signed certificate whose subject carries *serial_number*, the place of the EID (SGP.22 v3.1 §4.5.2.1.0.2)."""
    key = ec.generate_private_key(ec.SECP256R1())
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, "Test eUICC"), x509.NameAttribute(NameOID.COUNTRY_NAME, "XX")]
    if serial_number:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    name = x509.Name(attributes)
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class WrongCardTests(InjectBase):
    """The eIM chose the address, so the answer has to show which eUICC is behind it."""

    OTHER = "89049032123451234512345678901299"

    def _data_response(self, certificate: bytes) -> bytes:
        """IpaEuiccDataResponse 'BF52' { ipaEuiccData 'A0' { euiccCertificate 'A6' } }."""
        return codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", retag_sequence(b"\xA6", certificate)))

    def _ask_for_the_certificate(self) -> int:
        request = OperationRequest(eid=self.card.eid, type="IPA_EUICC_DATA", params={"tags": "A6"})
        return self.engine.submit([request])[0].id

    def test_a_certificate_of_another_eid_is_not_kept(self) -> None:
        self.prime()
        kept = self.engine.record(self.card.eid).euicc_certificate
        operation_id = self._ask_for_the_certificate()
        self.transport.replace_answer = transfer.build_result_response(self._data_response(_certificate(self.OTHER)))
        steps = self.run_inject()
        self.assertEqual(len(steps), 1)
        self.assertTrue(any(f"answers for EID {self.OTHER}, not {self.card.eid}" in line for line in self.lines), self.lines)
        self.assertEqual(self.engine.record(self.card.eid).euicc_certificate, kept)
        self.assertEqual(self.state_of(operation_id), STATE_SENT)

    def test_after_a_wrong_card_the_certificate_is_asked_for_again(self) -> None:
        # The first signed operation makes the engine ask for the certificate, once per record.
        operation_id = self.queue("PROFILE_INFO_LIST")
        self.transport.replace_answer = transfer.build_result_response(self._data_response(_certificate(self.OTHER)))
        self.run_inject()
        self.assertTrue(any(f"answers for EID {self.OTHER}" in line for line in self.lines), self.lines)
        self.assertEqual(self.engine.record(self.card.eid).euicc_certificate, b"")
        self.assertEqual(self.state_of(operation_id), STATE_CREATED)
        # With the right IPA behind the target the certificate is read and the result verified.
        self.transport.requests.clear()
        self.run_inject()
        self.assertEqual(self.transport.kinds()[:2], ["ipaEuiccDataRequest", "euiccPackageRequest"])
        self.assertNotEqual(self.engine.record(self.card.eid).euicc_certificate, b"")
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertNotIn("unverified", operation.flags)

    def test_a_certificate_of_this_eid_or_of_none_is_kept(self) -> None:
        self.prime()
        for certificate in (_certificate(self.card.eid), _certificate()):
            with self.subTest(eid=codec.certificate_eid(certificate)):
                operation_id = self._ask_for_the_certificate()
                self.transport.replace_answer = transfer.build_result_response(self._data_response(certificate))
                self.run_inject()
                self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)
                self.assertEqual(self.engine.record(self.card.eid).euicc_certificate, certificate)

    def test_an_answer_correlated_to_another_eid_is_not_taken(self) -> None:
        self.prime()
        operation_id = self.queue("PROFILE_INFO_LIST")
        for answer in (transfer.build_error_response(transfer.UNDEFINED_ERROR, eid=self.OTHER),
                       transfer.build_received_response(eid=self.OTHER)):
            with self.subTest(answer=answer.hex()[:16]):
                self.transport.replace_answer = answer
                steps = self.run_inject()
                self.assertTrue(any(f"answers for EID {self.OTHER}" in line for line in self.lines), self.lines)
                self.assertEqual(self.state_of(operation_id), STATE_SENT)
                self.assertEqual(steps[-1].acknowledged, [])
                self.engine.cancel(operation_id)
                operation_id = self.queue("PROFILE_INFO_LIST")

    def test_the_eid_of_a_certificate(self) -> None:
        euicc = _certificate(self.card.eid)
        self.assertEqual(codec.certificate_eid(euicc), self.card.eid)
        # 32 digits or nothing: a subject without the attribute, or with another kind of serial number.
        for other in (_certificate(), _certificate("8904903212345"), _certificate("SN-" + self.card.eid[3:])):
            self.assertEqual(codec.certificate_eid(other), "")
        for data in (b"", b"\x30", b"\x30\x00", b"\x30\x82\xFF\xFF", euicc[:40], euicc[:-1]):
            with self.subTest(data=data.hex()[:16]):
                self.assertEqual(codec.certificate_eid(data), "")


class TrafficViewTests(unittest.TestCase):
    """The TRAFFIC view of an exchange the eIM started (TransferEimPackage 'BF4E')."""

    RESULT = bytes.fromhex("BF511AA218801065696D2E6578616D706C652E746573748204A1A2A3A4")

    def view(self, request: bytes, response: bytes, status: int = 200) -> traffic.ExchangeView:
        return traffic.describe_exchange(traffic.BINDING_ESIPA_ASN1, request, response, status)

    def test_every_request_alternative_is_named(self) -> None:
        answer = transfer.build_received_response(eid=EID)
        for package, expected in (
            ("BF51023000", "TransferEimPackageRequest (euiccPackageRequest: no operation)"),
            ("BF520C5C04BF20BF228304A1A2A3A4",
             "TransferEimPackageRequest (IpaEuiccDataRequest tagList euiccInfo1, euiccInfo2, transaction A1A2A3A4)"),
            ("BF5306800101800102", "TransferEimPackageRequest (eimAcknowledgements seqNumber 1, 2)"),
            ("BF540AA00281008204A1A2A3A4",
             "TransferEimPackageRequest (ProfileDownloadTriggerRequest contactDefaultSmdp, transaction A1A2A3A4)"),
        ):
            with self.subTest(package=package[:4]):
                view = self.view(transfer.build_request(bytes.fromhex(package)), answer)
                self.assertEqual(view.request, "TransferEimPackageRequest")
                self.assertEqual(view.summary, expected + " -> eimPackageReceivedWithCid")
                self.assertEqual(view.error, "")
                self.assertEqual([row.tag for row in view.rows if row.name.startswith("TransferEimPackage")],
                                 ["BF4E", "BF4E"])

    def test_every_answer_alternative_is_named(self) -> None:
        request = transfer.build_request(bytes.fromhex("BF51023000"))
        for response, answer, error, row in (
            (transfer.build_result_response(self.RESULT), None, "", None),
            (transfer.build_received_response(with_cid=False), "eimPackageReceived", "", ("05", "")),
            (transfer.build_received_response(transaction_id=TXID), "eimPackageReceivedWithCid", "",
             ("BF60", "transaction A1A2A3A4")),
            (transfer.build_error_response(2, with_cid=False), "eimPackageError unknownPackage", "unknownPackage",
             ("02", "unknownPackage (2)")),
            (transfer.build_error_response(1, eid=EID), "eimPackageErrorWithCid invalidPackageFormat",
             "invalidPackageFormat", ("BF61", f"invalidPackageFormat (1), EID {EID}")),
        ):
            with self.subTest(response=response.hex()[:16]):
                view = self.view(request, response)
                self.assertEqual(view.error, error)
                if answer is not None:
                    self.assertEqual(view.answer, answer)
                if row is not None:
                    self.assertEqual((view.rows[-1].tag, view.rows[-1].value), row)

    def test_bodies_that_do_not_read_are_described_and_never_raise(self) -> None:
        good_request = transfer.build_request(bytes.fromhex("BF51023000"))
        good_answer = transfer.build_received_response()
        for body in (b"\xBF\x4E", bytes.fromhex("BF4E00"), bytes.fromhex("BF4E05"), bytes.fromhex("BF4E04BF500100"),
                     bytes.fromhex("BF4E05BF53028100"), bytes.fromhex("BF4E03BF5100"), bytes.fromhex("BF4E0430020500")):
            with self.subTest(body=body.hex()):
                self.assertIn("TransferEimPackageRequest", self.view(body, good_answer).summary)
                self.assertTrue(self.view(good_request, body).summary)
        self.assertEqual(self.view(good_request, bytes.fromhex("BF4E00")).error, "not readable")
        self.assertEqual(self.view(good_request, b"", 0).answer, "no answer")
        self.assertEqual(self.view(good_request, b"", 500).error, "HTTP 500")


class TargetTests(InjectBase):
    def test_a_target_is_a_loopback_address_with_a_port(self) -> None:
        for url, binding, expected in (
            ("http://127.0.0.1:8750", "asn1", ("http://127.0.0.1:8750", "asn1", "127.0.0.1", 8750)),
            (" http://localhost:9/ ", "JSON", ("http://localhost:9", "json", "localhost", 9)),
            ("http://[::1]:8750", "", ("http://[::1]:8750", "asn1", "::1", 8750)),
        ):
            with self.subTest(url=url):
                target = parse_target(url, binding)
                self.assertEqual((target.url, target.binding, target.host, target.port), expected)
                self.assertFalse(target.secure)

    def test_an_https_target_is_any_address_with_a_port(self) -> None:
        for url, expected in (
            ("https://192.0.2.4:8746", ("https://192.0.2.4:8746", "192.0.2.4", 8746)),
            ("https://ipad.example.test:8746/", ("https://ipad.example.test:8746", "ipad.example.test", 8746)),
            ("https://127.0.0.1:8750", ("https://127.0.0.1:8750", "127.0.0.1", 8750)),
            ("https://[2001:db8::4]:8746", ("https://[2001:db8::4]:8746", "2001:db8::4", 8746)),
        ):
            with self.subTest(url=url):
                target = parse_target(url)
                self.assertEqual((target.url, target.host, target.port), expected)
                self.assertTrue(target.secure)

    def test_other_targets_are_refused(self) -> None:
        for url, binding in (
            ("http://192.0.2.4:8750", "asn1"), ("http://eim.example.test:8750", "asn1"),
            ("https://192.0.2.4", "asn1"), ("https://:8746", "asn1"), ("https://user:word@192.0.2.4:8746", "asn1"),
            ("https://192.0.2.4:8746/gsma/rsp2/asn1", "asn1"), ("ftp://192.0.2.4:8746", "asn1"),
            ("http://127.0.0.1", "asn1"), ("http://127.0.0.1:8750/gsma/rsp2/asn1", "asn1"),
            ("http://127.0.0.1:8750?x=1", "asn1"), ("127.0.0.1:8750", "asn1"), ("", "asn1"),
            ("http://127.0.0.1:port", "asn1"), ("http://127.0.0.1:8750", "coap"),
        ):
            with self.subTest(url=url, binding=binding):
                with self.assertRaises(InjectError):
                    parse_target(url, binding)

    def test_the_record_keeps_the_target(self) -> None:
        self.assertIsNone(self.engine.inject_target(self.card.eid))
        self.engine.set_inject_target(self.card.eid, "http://127.0.0.1:8750/", "json")
        self.assertEqual(self.engine.inject_target(self.card.eid), {"url": "http://127.0.0.1:8750", "binding": "json"})
        with self.assertRaises(LocalEimError):
            self.engine.set_inject_target(self.card.eid, "http://192.0.2.4:8750")
        self.assertEqual(self.engine.inject_target(self.card.eid)["binding"], "json")
        self.engine.set_inject_target(self.card.eid, "")
        self.assertIsNone(self.engine.inject_target(self.card.eid))


class ProviderTests(unittest.TestCase):
    """``answer_transfer`` per eIM Package of Table 18 (SGP.32 v1.3 §5.14.4)."""

    def setUp(self) -> None:
        self.ran: list[bytes] = []
        self.removed: list[int] = []
        self.result: bytes | Exception = bytes.fromhex("BF5100")

    def _run(self, package: bytes) -> bytes:
        self.ran.append(package)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def answer(self, request: bytes) -> transfer.TransferResponse:
        return transfer.decode_response(answer_transfer(
            request, eid=EID, run_package=self._run, remove_acknowledged=self.removed.append))

    def test_an_euicc_package_and_a_data_request_are_run_and_their_result_returned(self) -> None:
        for package, result in ((bytes.fromhex("BF51023000"), bytes.fromhex("BF5100")),
                                (bytes.fromhex("BF52045C02BF20"), bytes.fromhex("BF5200"))):
            with self.subTest(package=package.hex()):
                self.result = result
                response = self.answer(transfer.build_request(package))
                self.assertEqual((response.is_result, response.result), (True, result))
                self.assertEqual(self.ran[-1], package)

    def test_acknowledgements_are_removed_and_answered_with_the_eid(self) -> None:
        response = self.answer(bytes.fromhex("BF4E09BF5306800101800102"))
        self.assertEqual((response.kind, response.eid, response.transaction_id), (transfer.RECEIVED_WITH_CID, EID, b""))
        self.assertEqual((self.removed, self.ran), ([1, 2], []))

    def test_a_download_trigger_is_not_run(self) -> None:
        response = self.answer(bytes.fromhex("BF4E0DBF540AA00281008204A1A2A3A4"))
        self.assertEqual((response.kind, response.error_code, response.transaction_id),
                         (transfer.ERROR_WITH_CID, transfer.UNDEFINED_ERROR, TXID))
        self.assertEqual(self.ran, [])

    def test_a_data_object_outside_the_table_is_unknown(self) -> None:
        response = self.answer(bytes.fromhex("BF4E04BF500100"))
        self.assertEqual((response.error_code, response.eid), (transfer.UNKNOWN_PACKAGE, EID))

    def test_a_request_that_does_not_read_is_invalid(self) -> None:
        for request in (b"", b"\xBF", bytes.fromhex("BF4E00"), bytes.fromhex("BF4E0405000500"), bytes.fromhex("3000"),
                        bytes.fromhex("BF4E05BF53028100"), bytes.fromhex("BF4E05BF53028000")):
            with self.subTest(request=request.hex()):
                response = self.answer(request)
                self.assertEqual((response.kind, response.error_code, response.eid),
                                 (transfer.ERROR_WITH_CID, transfer.INVALID_PACKAGE_FORMAT, EID))
        self.assertEqual((self.ran, self.removed), ([], []))

    def test_an_error_names_the_transaction_of_the_package_or_the_eid(self) -> None:
        with_transaction = transfer.build_request(bytes.fromhex("BF520C5C04BF20BF228304A1A2A3A4"))
        without = transfer.build_request(bytes.fromhex("BF52045C02BF20"))
        self.result = RuntimeError("the card went away")
        response = self.answer(with_transaction)
        self.assertEqual((response.error_code, response.transaction_id, response.eid), (127, TXID, ""))
        response = self.answer(without)
        self.assertEqual((response.error_code, response.transaction_id, response.eid), (127, b"", EID))

    def test_the_error_form_of_a_result_becomes_an_error_answer(self) -> None:
        self.result = bytes.fromhex("A003020101")
        response = self.answer(transfer.build_request(bytes.fromhex("BF520C5C04BF20BF228304A1A2A3A4")))
        self.assertEqual((response.kind, response.error_code, response.transaction_id),
                         (transfer.ERROR_WITH_CID, transfer.INVALID_PACKAGE_FORMAT, TXID))

    def test_a_card_answer_that_is_no_result_is_undefined(self) -> None:
        for result in (b"", b"\x00", bytes.fromhex("BF54023000"), bytes.fromhex("BF2D00")):
            with self.subTest(result=result.hex()):
                self.result = result
                response = self.answer(transfer.build_request(bytes.fromhex("BF51023000")))
                self.assertEqual((response.kind, response.error_code), (transfer.ERROR_WITH_CID, 127))

    def test_a_failing_removal_is_answered(self) -> None:
        def refuse(_number: int) -> None:
            raise RuntimeError("the card went away")

        response = transfer.decode_response(answer_transfer(
            bytes.fromhex("BF4E09BF5306800101800102"), eid=EID, run_package=self._run, remove_acknowledged=refuse))
        self.assertEqual((response.kind, response.error_code), (transfer.ERROR_WITH_CID, 127))


class ListenerBase(unittest.TestCase):
    def serve(self, handler, **options: object) -> TransferListener:
        self.log: list[str] = []
        listener = TransferListener(handler, log=self.log.append)
        stop = threading.Event()
        if options.get("stop", stop) is None:
            # The test wants to see the listener end by itself; the event still ends it at clean-up.
            options.pop("stop")
            listener_stop = None
        else:
            listener_stop = stop
        thread = threading.Thread(target=listener.serve, kwargs={**options, "stop": listener_stop}, daemon=True)
        thread.start()

        def finish() -> None:
            stop.set()
            if listener_stop is None:
                # No event to set: one more call, or the idle limit, ends the loop.
                try:
                    self.post(listener, "/", b"")
                except OSError:
                    pass
            thread.join(timeout=5)
            listener.close()
            self.assertFalse(thread.is_alive())

        self.addCleanup(finish)
        self.thread = thread
        return listener

    def post(self, listener: TransferListener, path: str, body: bytes, content_type: str = transfer.CONTENT_TYPE_ASN1,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        """POST as an eIM does (SGP.32 v1.3 §6.1.1); a header given as '' is left out."""
        sent = {"Content-Type": content_type, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL, **(headers or {})}
        connection = http.client.HTTPConnection(listener.host, listener.port, timeout=5)
        try:
            connection.request("POST", path, body=body, headers={key: value for key, value in sent.items() if value})
            response = connection.getresponse()
            return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
        finally:
            connection.close()


class ListenerTests(ListenerBase):
    def setUp(self) -> None:
        self.requests: list[bytes] = []

    def handler(self, request: bytes) -> bytes:
        self.requests.append(request)
        return answer_transfer(request, eid=EID, run_package=lambda _package: bytes.fromhex("BF5100"),
                               remove_acknowledged=lambda _number: None)

    def test_the_asn1_binding(self) -> None:
        listener = self.serve(self.handler)
        request = transfer.build_request(bytes.fromhex("BF51023000"))
        status, headers, body = self.post(listener, transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1)
        self.assertEqual((status, headers["content-type"], headers["x-admin-protocol"]),
                         (200, transfer.CONTENT_TYPE_ASN1, transfer.ADMIN_PROTOCOL))
        self.assertEqual(transfer.decode_response(body).result, bytes.fromhex("BF5100"))
        self.assertEqual(self.requests, [request])

    def test_the_json_binding(self) -> None:
        listener = self.serve(self.handler)
        request = transfer.build_request(bytes.fromhex("BF5306800101800102"))
        status, headers, body = self.post(listener, transfer.PATH_JSON,
                                          json.dumps(transfer.request_to_json(request)).encode("utf-8"),
                                          transfer.CONTENT_TYPE_JSON)
        message = json.loads(body.decode("utf-8"))
        self.assertEqual((status, headers["content-type"]), (200, transfer.CONTENT_TYPE_JSON))
        self.assertEqual(message, {"header": {"functionExecutionStatus": {"status": "Executed-Success"}},
                                   "eimPackageReceivedWithCid": {}})
        self.assertEqual(self.requests, [request])

    def test_a_json_body_that_does_not_read_is_answered_as_an_invalid_package(self) -> None:
        listener = self.serve(self.handler)
        for body in (b"", b"{", b"[]", b'{"euiccPackageRequest": 5}', b"\xff\xfe"):
            with self.subTest(body=body):
                status, _headers, answer = self.post(listener, transfer.PATH_JSON, body, transfer.CONTENT_TYPE_JSON)
                message = json.loads(answer.decode("utf-8"))
                status_data = message["header"]["functionExecutionStatus"]
                self.assertEqual((status, status_data["status"]), (200, "Failed"))
                self.assertEqual((status_data["statusCodeData"]["subjectCode"], status_data["statusCodeData"]["reasonCode"]),
                                 ("8.31.1", "2.1"))
                self.assertEqual(transfer.decode_response(transfer.response_from_json(message)).error_code,
                                 transfer.INVALID_PACKAGE_FORMAT)

    def test_other_paths_and_oversized_bodies(self) -> None:
        listener = self.serve(self.handler)
        status, _headers, _body = self.post(listener, "/gsma/rsp2/esipa/getEimPackage", b"{}", transfer.CONTENT_TYPE_JSON)
        self.assertEqual(status, 404)
        status, _headers, _body = self.post(listener, transfer.PATH_ASN1, b"", headers={"Content-Length": "2000000"})
        self.assertEqual(status, 413)
        self.assertEqual((self.requests, listener.calls), ([], 0))

    def test_a_request_a_page_in_a_browser_could_send_is_refused(self) -> None:
        # A cross-origin POST goes out without a preflight only with a form or text/plain Content-Type and
        # no header of its own; a name rebound to the loopback shows in Host. None of them reaches the card.
        listener = self.serve(self.handler)
        request = transfer.build_request(bytes.fromhex("BF5306800101800102"))
        as_json = json.dumps(transfer.request_to_json(request)).encode("utf-8")
        for path, body, content_type, headers, expected in (
            (transfer.PATH_ASN1, request, "text/plain", {}, 415),
            (transfer.PATH_ASN1, request, "application/x-www-form-urlencoded", {}, 415),
            (transfer.PATH_ASN1, request, "", {}, 415),
            (transfer.PATH_JSON, as_json, "text/plain;charset=UTF-8", {}, 415),
            (transfer.PATH_JSON, as_json, transfer.CONTENT_TYPE_ASN1, {}, 415),
            (transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1, {"X-Admin-Protocol": ""}, 400),
            (transfer.PATH_JSON, as_json, transfer.CONTENT_TYPE_JSON, {"X-Admin-Protocol": ""}, 400),
            (transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1, {"Host": "eim.example.test"}, 403),
            (transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1, {"Host": f"eim.example.test:{listener.port}"}, 403),
            (transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1, {"Host": "192.0.2.4"}, 403),
            (transfer.PATH_ASN1, request, transfer.CONTENT_TYPE_ASN1, {"Host": "[::1"}, 403),
        ):
            with self.subTest(content_type=content_type, headers=headers):
                status, _headers, answer = self.post(listener, path, body, content_type, headers)
                self.assertEqual((status, answer), (expected, b""))
        self.assertEqual((self.requests, listener.calls), ([], 0))
        self.assertTrue(all("request refused" in line for line in self.log), self.log)
        # The same requests as an eIM sends them are taken, under either loopback name.
        for host in (f"127.0.0.1:{listener.port}", f"localhost:{listener.port}"):
            status, _headers, _answer = self.post(listener, transfer.PATH_ASN1, request, headers={"Host": host})
            self.assertEqual(status, 200)
        status, _headers, _answer = self.post(listener, transfer.PATH_JSON, as_json, "application/json")
        self.assertEqual((status, listener.calls), (200, 3))

    def test_other_methods_are_not_served(self) -> None:
        listener = self.serve(self.handler)
        for method in ("OPTIONS", "GET", "PUT"):
            connection = http.client.HTTPConnection(listener.host, listener.port, timeout=5)
            try:
                connection.request(method, transfer.PATH_ASN1, headers={"Origin": "https://page.example.test",
                                                                        "Access-Control-Request-Method": "POST"})
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 501, method)
                self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))
            finally:
                connection.close()
        self.assertEqual(listener.calls, 0)

    def test_it_stops_after_the_calls_it_was_given_even_on_a_kept_connection(self) -> None:
        listener = self.serve(self.handler, max_calls=2, stop=None)
        connection = http.client.HTTPConnection(listener.host, listener.port, timeout=5)
        self.addCleanup(connection.close)
        request = transfer.build_request(bytes.fromhex("BF51023000"))
        for _ in range(2):
            connection.request("POST", transfer.PATH_ASN1, body=request, headers={
                "Content-Type": transfer.CONTENT_TYPE_ASN1, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL})
            self.assertEqual(connection.getresponse().read(), self.handler(request))
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(listener.calls, 2)

    def test_it_stops_when_nothing_calls(self) -> None:
        listener = self.serve(self.handler, idle_seconds=0.3, stop=None)
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(listener.calls, 0)

    def test_it_binds_the_loopback_without_tls_only(self) -> None:
        for options in ({"host": "0.0.0.0"}, {"host": "192.0.2.4"}, {"host": "eim.example.test"},
                        {"tls_context": object()}):
            with self.subTest(options=str(options)):
                with self.assertRaises(ValueError):
                    TransferListener(self.handler, **options)  # type: ignore[arg-type]


class EndToEndTests(InjectBase, ListenerBase):
    """The engine, HTTP on the loopback and the simulated eUICC, in both bindings."""

    def _inject(self, binding: str) -> tuple[list, HttpTransport]:
        listener = self.serve(self.ipa.answer)
        target = parse_target(listener.url, binding)
        log = TrafficLog(self.engine, target, self.card.eid)
        transport = HttpTransport(target, timeout=5, record=log)
        self.lines = []
        return inject(self.engine, self.card.eid, transport, emit=self.lines.append, on_serve=log.serving), transport

    def test_an_enable_runs_over_both_bindings(self) -> None:
        for binding, iccid in (("asn1", DISABLED), ("json", ENABLED)):
            with self.subTest(binding=binding):
                operation_id = self.queue("ENABLE_PROFILE", iccid=iccid)
                self.queue("PROFILE_INFO_LIST")
                steps, _transport = self._inject(binding)
                operation = self.engine.operation(operation_id)
                self.assertEqual((operation.state, operation.route), (STATE_SUCCESS, ROUTE_INJECT), operation.error)
                step = next(step for step in steps if step.operation_id == operation_id)
                self.assertIn(step.answer, (transfer.RESULT_EUICC_PACKAGE, transfer.RESULT_WITH_NOTIFICATIONS))
                self.assertTrue(step.acknowledged)
                start = self.ipa.removed.index(step.acknowledged[0])
                self.assertEqual(self.ipa.removed[start:start + len(step.acknowledged)], step.acknowledged)
                profiles = {profile["iccid"]: profile["state"] for profile in self.engine.record(self.card.eid).profiles}
                self.assertEqual(profiles[iccid], "enabled")
                rows = self.engine.store.traffic(limit=50, operation_id=operation_id)
                self.assertTrue(rows)
                for row in rows:
                    self.assertEqual((row.listener_port, row.status, row.eid), (0, 200, self.card.eid))
                    self.assertIn("injected", row.note)
                    self.assertEqual(row.binding, "esipa-json" if binding == "json" else "esipa-asn1")
                    self.assertIn(" inject ", traffic.summary_line(row))
                described = [traffic.describe_record(row) for row in rows]
                if binding == "asn1":
                    self.assertTrue(any(view.summary.startswith("TransferEimPackageRequest (euiccPackageRequest: enable")
                                        for view in described), [view.summary for view in described])
                    self.assertTrue(any("eimAcknowledgements seqNumber" in view.summary for view in described))
                    self.assertFalse(any(view.error for view in described))
                else:
                    self.assertTrue(any(view.summary.startswith("transferEimPackage (euiccPackageRequest)")
                                        for view in described), [view.summary for view in described])

    def test_nothing_listening_raises_before_a_package_is_served(self) -> None:
        self.prime()
        listener = TransferListener(self.ipa.answer)
        url = listener.url
        listener.close()
        operation_id = self.queue("PROFILE_INFO_LIST")
        with self.assertRaises(TargetUnreachable):
            inject(self.engine, self.card.eid, HttpTransport(parse_target(url), timeout=2))
        self.assertEqual(self.state_of(operation_id), STATE_CREATED)

    def test_an_ipa_that_drops_the_connection_leaves_the_operation_in_flight(self) -> None:
        def drop(_request: bytes) -> bytes:
            raise ConnectionError("gone")

        self.prime()
        listener = self.serve(drop)
        operation_id = self.queue("PROFILE_INFO_LIST")
        self.lines = []
        steps = inject(self.engine, self.card.eid, HttpTransport(parse_target(listener.url), timeout=5),
                       emit=self.lines.append)
        self.assertEqual((len(steps), steps[0].answer), (1, "no answer"))
        self.assertEqual(self.state_of(operation_id), STATE_SENT)


class ShellVerbTests(ListenerBase):
    """INJECT in the eIM-local shell, on a store of the test's own and without a reader."""

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.shell = EimLocalShell()
        self.engine = self.shell._engine_verbs.engine
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        self.ipa = SimIpa(self.card)
        # A reader call from INJECT would be a defect: the IPA holds the card.
        reader = mock.patch.object(type(self.shell._engine_verbs), "_with_reader",
                                   side_effect=AssertionError("INJECT opened the reader"))
        reader.start()
        self.addCleanup(reader.stop)

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def test_inject_runs_the_queue_and_keeps_the_target(self) -> None:
        listener = self.serve(self.ipa.answer)
        eid = self.card.eid
        self.run_line(f"QUEUE ENABLE {eid} {DISABLED}")
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        output = self.run_line(f"INJECT {eid} target={listener.url}")
        self.assertIn(f"[*] {eid}: injecting to {listener.url} (asn1 binding, plain HTTP on the loopback).", output)
        self.assertIn("package(s) injected.", output)
        self.assertNotIn("[!]", output)
        states = {operation.type: operation.state for operation in self.engine.operations(eid=eid)}
        self.assertEqual((states["ENABLE_PROFILE"], states["PROFILE_INFO_LIST"]), (STATE_SUCCESS, STATE_SUCCESS))
        self.assertIn(f"inject target {listener.url}  (asn1 binding)", self.run_line(f"EUICC {eid}"))
        # The target is kept: the eUICC need not be named again, and the binding can change alone.
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        output = self.run_line("INJECT binding=json --once")
        self.assertIn("(json binding", output)
        self.assertIn("[*] 1 package(s) injected.", output)
        listed = self.run_line("TRAFFIC 50")
        self.assertIn(" inject ", listed)
        self.assertIn("TransferEimPackageRequest (euiccPackageRequest: enable", listed)
        self.assertIn("plain, the eIM called", listed)
        self.assertIn("transferEimPackage (euiccPackageRequest)", listed)

    def test_the_target_is_checked_cleared_and_asked_for(self) -> None:
        eid = self.card.eid
        self.assertIn("[!] No eUICC has an inject target.", self.run_line("INJECT"))
        self.assertIn(f"[!] No inject target for {eid}.", self.run_line(f"INJECT {eid}"))
        for line in (f"INJECT {eid} target=https://192.0.2.4", f"INJECT {eid} target=http://192.0.2.4:8746",
                     f"INJECT {eid} target=http://127.0.0.1:8746 binding=coap", f"INJECT {eid} bogus=1",
                     f"INJECT {eid} extra", f"INJECT {eid} timeout=soon", f"INJECT {eid} timeout=0",
                     f"INJECT {eid} --twice", "INJECT 89049032123451234512345678901299 target=http://127.0.0.1:8746",
                     f"INJECT {eid} binding=json"):
            with self.subTest(line=line):
                self.assertIn("[!]", self.run_line(line))
                self.assertIsNone(self.engine.inject_target(eid))
        listener = TransferListener(self.ipa.answer)
        url = listener.url
        listener.close()
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        output = self.run_line(f"INJECT {eid} target={url}")
        self.assertIn("Nothing was served; is EIM-LISTEN running there?", output)
        self.assertEqual([operation.state for operation in self.engine.operations(eid=eid)], [STATE_CREATED])
        self.assertIn(f"[+] {eid}: inject target cleared.", self.run_line(f"INJECT {eid} target=none"))
        self.assertIsNone(self.engine.inject_target(eid))

    def test_help_lists_the_verb(self) -> None:
        self.assertIn("INJECT", self.run_line("HELP"))
        self.assertIn("ESipa.TransferEimPackage", self.run_line("HELP INJECT"))

    def action(self, **values: object) -> list[str]:
        spec = next(entry for entry in eim_local_ops.SPECS if entry.id == "eim_local.inject")
        return list(spec.dispatcher(ActionContext(), **values)["lines"])

    def test_the_gui_action_runs_the_same_verb_without_a_reader(self) -> None:
        spec = next(entry for entry in eim_local_ops.SPECS if entry.id == "eim_local.inject")
        self.assertEqual((spec.title, spec.requires_card, [field.name for field in spec.inputs]),
                         ("Inject to IPA", False, ["eid", "target", "binding", "once"]))
        listener = self.serve(self.ipa.answer)
        eid = self.card.eid
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        # A card session opened for this action would be a defect: the IPA holds the card.
        with mock.patch.object(eim_local_ops, "_card_session", side_effect=AssertionError("a reader was opened")):
            lines = self.action(eid=eid, target=listener.url, binding="json", once=False)
            self.assertIn(f"[*] {eid}: injecting to {listener.url} (json binding, plain HTTP on the loopback).", lines)
            self.assertTrue(any("package(s) injected." in line for line in lines), lines)
            self.assertFalse(any(line.startswith("[!]") for line in lines), lines)
            self.assertEqual(self.engine.inject_target(eid), {"url": listener.url, "binding": "json"})
            self.assertTrue(all(operation.state == STATE_SUCCESS for operation in self.engine.operations(eid=eid)))
            # Later runs need neither the EID nor the target; "none" clears it.
            self.run_line(f"QUEUE LIST-PROFILES {eid}")
            lines = self.action(eid="", target="", binding="asn1", once=True)
            self.assertIn("[*] 1 package(s) injected.", lines)
            self.assertEqual(self.engine.inject_target(eid)["binding"], "asn1")
            self.assertEqual(self.action(eid=eid, target="none"), [f"[+] {eid}: inject target cleared."])
            with self.assertRaises(Exception) as refused:
                self.action(eid=eid, target="http://192.0.2.4:8746")
            self.assertIn("loopback", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
