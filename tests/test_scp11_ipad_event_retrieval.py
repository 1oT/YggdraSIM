# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eSIM Management IPA and an SM-DS: contactSmds triggers and the eIM's Event Retrieval answer.

A ProfileDownloadTriggerRequest with contactSmds starts an Event Retrieval
(GSMA SGP.32 v1.3 §2.11.1.3, §3.9.2), by the IPA over ES11 or through the eIM.
The flow ends at AuthenticateClient when the server is an SM-DS, the Event
Records become downloads, and the eIM gets one result per trigger, or none
when it ran the retrieval itself.
"""

from __future__ import annotations

import base64
import contextlib
import io
import os
import unittest
from unittest import mock

from SCP11.eim_local.engine import codec as eim_codec
from SCP11.live.indirect_download import EsipaProfileProvider, _answered_by_smds
from SCP11.live.models import AuthenticateClientRequest, AuthenticateClientResponse, EimPollResponse
from SCP11.live.orchestrator import (
    INDIRECT_DOWNLOAD_ENV,
    MAX_EVENT_RETRIEVAL_TRIGGER_DEPTH,
    EventRetrievalAnswer,
    SGP22Orchestrator,
)
from SCP11.payload_builder import PayloadBuilder
from SCP11.shared import esipa_download as esipa
from tests.test_scp11_orchestrator import FakeApduChannel, FakeCfg, FakeProvider, wrap_tlv

EID = "89049032123451234512345678901235"
SMDS = "smds.example.test"
SMDP = "smdpp.example.test"
EIM = "eim.example.test"
RETRIEVAL = bytes.fromhex("A1A2A3A4")
DOWNLOAD = bytes.fromhex("B1B2B3B4")
SMDS_TRANSACTION = bytes(range(0x30, 0x40))
# EimPackageResultResponseError invalidPackageFormat(1) with the eimTransactionId of the retrieval trigger.
INVALID_PACKAGE_FORMAT = bytes.fromhex("A0098004") + RETRIEVAL + bytes.fromhex("020101")


def installation_result(seq_number: int, *, failed: bool = False) -> bytes:
    """ProfileInstallationResult 'BF37' with finalResult successResult 'A0' or errorResult 'A1' (SGP.22 v3.1 §2.5.6)."""
    if failed:
        # bppCommandId installPE(5), errorReason installFailedDueToIccidAlreadyExistsOnEuicc(9)
        final = wrap_tlv("A1", wrap_tlv("80", b"\x05") + wrap_tlv("81", b"\x09"))
    else:
        final = wrap_tlv("A0", wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                         + wrap_tlv("04", bytes.fromhex("3007A0053003800100")))
    data = wrap_tlv(
        "BF27",
        wrap_tlv("80", b"\x10" * 8)
        + wrap_tlv("BF2F", wrap_tlv("80", bytes([seq_number])) + wrap_tlv("81", b"\x07\x80") + wrap_tlv("0C", SMDP.encode()))
        + wrap_tlv("06", bytes.fromhex("2B0601040183A40F0004"))
        + wrap_tlv("A2", final),
    )
    return wrap_tlv("BF37", data + wrap_tlv("5F37", b"\x22" * 64))


def trigger_result(transaction_id: bytes, result: bytes) -> bytes:
    """ProfileDownloadTriggerResult 'BF54' with a ProfileInstallationResult (SGP.32 v1.3 §2.11.2.3)."""
    return wrap_tlv("BF54", wrap_tlv("82", transaction_id) + result)


def download_error(transaction_id: bytes) -> bytes:
    """ProfileDownloadTriggerResult with profileDownloadError undefinedError(127)."""
    return wrap_tlv("BF54", wrap_tlv("82", transaction_id) + bytes.fromhex("300380017F"))


def contact_smds(address: str = SMDS, transaction_id: bytes = RETRIEVAL) -> bytes:
    return eim_codec.build_profile_download_trigger_request(
        contact_smds=True, smds_address=address, transaction_id=transaction_id)


def empty_trigger(transaction_id: bytes = RETRIEVAL) -> bytes:
    return eim_codec.build_profile_download_trigger_request(transaction_id=transaction_id)


def activation_code_trigger(matching_id: str = "MID-1", transaction_id: bytes = DOWNLOAD) -> bytes:
    return eim_codec.build_profile_download_trigger_request(
        activation_code=f"1${SMDP}${matching_id}", transaction_id=transaction_id)


class EsipaClient(FakeProvider):
    """The ES9+ client of a poll, able to carry ESipa messages to the eIM."""

    def __init__(self, answers: list[bytes] | None = None) -> None:
        super().__init__(bpp_bytes=b"")
        self.answers = list(answers or [])
        self.posted: list[bytes] = []

    def post_esipa(self, eim_fqdn: str, body: bytes, pinned_tls_public_key_data: bytes = b"") -> bytes:
        self.posted.append(bytes(body))
        if not self.answers:
            raise AssertionError("no ESipa answer scripted")
        return self.answers.pop(0)


class Flows:
    """run_flow stood in for by a script: one step per call, each seeing the orchestrator as the flow would."""

    def __init__(self, orchestrator: SGP22Orchestrator, steps: list) -> None:
        self.orchestrator = orchestrator
        self.steps = list(steps)
        self.calls: list[tuple[str, str]] = []
        self.providers: list[str] = []
        self.transactions: list[bytes] = []

    def __call__(self, matching_id: str = "", smdp_address: str = "") -> None:
        self.calls.append((matching_id, smdp_address))
        provider = self.orchestrator.profile_provider
        self.providers.append(type(provider).__name__)
        self.transactions.append(bytes(getattr(provider, "eim_transaction_id", b"") or b""))
        if not self.steps:
            raise AssertionError(f"no flow scripted for {matching_id!r} at {smdp_address!r}")
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        if isinstance(step, EventRetrievalAnswer):
            self.orchestrator._event_retrieval = step
        elif isinstance(step, bytes):
            self.orchestrator.state.load_bpp_response = step


def orchestrator_with(provider=None, *, cfg=None, channel=None) -> SGP22Orchestrator:
    return SGP22Orchestrator(
        cfg=cfg or FakeCfg(),
        apdu_channel=channel or FakeApduChannel(),
        profile_provider=provider if provider is not None else FakeProvider(bpp_bytes=b""),
    )


def relay(orchestrator: SGP22Orchestrator, package: bytes) -> tuple[bytes, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)
    return response, output.getvalue()


class AnswerReadingTests(unittest.TestCase):
    """What the AuthenticateClient answer says about the server (SGP.22 v3.1 §5.8.2, SGP.32 v1.3 §6.3.2.2)."""

    @staticmethod
    def answer(**members) -> AuthenticateClientResponse:
        values = {"transaction_id": "AA", "smdp_signed2": "", "smdp_signature2": "", "smdp_certificate": ""}
        values.update(members)
        return AuthenticateClientResponse(**values)

    def test_event_entries_are_an_sm_ds_answer(self) -> None:
        read = SGP22Orchestrator._event_retrieval_answer(self.answer(event_entries=[
            {"eventId": "MID-1", "rspServerAddress": SMDP}, {"eventId": "MID-2", "rspServerAddress": "smdp2.example.test"},
        ]))
        self.assertEqual(read, EventRetrievalAnswer(events=(("MID-1", SMDP), ("MID-2", "smdp2.example.test"))))
        self.assertFalse(read.by_eim)

    def test_an_empty_list_is_still_an_sm_ds_answer(self) -> None:
        # "The resulting list MAY be empty" (SGP.22 v3.1 §3.6.2 step 2): no record, not no SM-DS
        self.assertEqual(SGP22Orchestrator._event_retrieval_answer(self.answer(event_entries=[])), EventRetrievalAnswer())

    def test_an_sm_dp_answer_is_none(self) -> None:
        self.assertIsNone(SGP22Orchestrator._event_retrieval_answer(self.answer(smdp_signed2="MDA=")))
        self.assertIsNone(SGP22Orchestrator._event_retrieval_answer(self.answer()))

    def test_smdp_signed2_makes_it_a_download_whatever_else_is_there(self) -> None:
        self.assertIsNone(SGP22Orchestrator._event_retrieval_answer(
            self.answer(smdp_signed2="MDA=", event_entries=[{"eventId": "MID-1", "rspServerAddress": SMDP}])))

    def test_a_record_without_both_members_is_left_out(self) -> None:
        read = SGP22Orchestrator._event_retrieval_answer(self.answer(event_entries=[
            {"eventId": "MID-1"}, {"rspServerAddress": SMDP}, "text", {"eventId": " MID-3 ", "rspServerAddress": SMDP},
        ]))
        self.assertEqual(read.events, (("MID-3", SMDP),))

    def test_the_eims_answer_carries_its_trigger(self) -> None:
        trigger = activation_code_trigger()
        read = SGP22Orchestrator._event_retrieval_answer(self.answer(
            event_retrieval_by_eim=True, profile_download_trigger=base64.b64encode(trigger).decode()))
        self.assertEqual(read, EventRetrievalAnswer(by_eim=True, trigger=trigger))
        without = SGP22Orchestrator._event_retrieval_answer(self.answer(event_retrieval_by_eim=True))
        self.assertEqual(without, EventRetrievalAnswer(by_eim=True))
        unreadable = SGP22Orchestrator._event_retrieval_answer(self.answer(
            event_retrieval_by_eim=True, profile_download_trigger="not base64 !"))
        self.assertEqual(unreadable, EventRetrievalAnswer(by_eim=True))

    def test_a_stand_in_provider_answer_is_not_mistaken_for_one(self) -> None:
        # a Mock answers every attribute with something truthy
        self.assertIsNone(SGP22Orchestrator._event_retrieval_answer(mock.Mock()))
        self.assertIsNone(SGP22Orchestrator._event_retrieval_answer(object()))


class EsipaProviderTests(unittest.TestCase):
    """EsipaProfileProvider.authenticate_client and authenticateClientOkDSEsipa."""

    def provider(self, answer: bytes) -> tuple[EsipaProfileProvider, EsipaClient]:
        client = EsipaClient([answer])
        return EsipaProfileProvider(client, eim_fqdn=EIM, eim_transaction_id=RETRIEVAL), client

    @staticmethod
    def request() -> AuthenticateClientRequest:
        return AuthenticateClientRequest(
            transaction_id=SMDS_TRANSACTION.hex().upper(),
            authenticate_server_response=base64.b64encode(bytes.fromhex("BF3800")).decode(),
            smdp_address="",
        )

    def test_the_sm_ds_alternative_ends_the_download_calls(self) -> None:
        trigger = activation_code_trigger()
        provider, client = self.provider(esipa.encode_authenticate_client_ds_ok(
            esipa.AuthenticateClientDsOk(SMDS_TRANSACTION, trigger)))
        answer = provider.authenticate_client(self.request())
        self.assertTrue(answer.event_retrieval_by_eim)
        self.assertEqual(base64.b64decode(answer.profile_download_trigger), trigger)
        self.assertEqual(answer.transaction_id, SMDS_TRANSACTION.hex().upper())
        self.assertEqual((answer.smdp_signed2, answer.smdp_signature2, answer.smdp_certificate), ("", "", ""))
        self.assertEqual(len(client.posted), 1)

    def test_no_trigger_in_the_answer(self) -> None:
        provider, _client = self.provider(esipa.encode_authenticate_client_ds_ok(
            esipa.AuthenticateClientDsOk(SMDS_TRANSACTION)))
        answer = provider.authenticate_client(self.request())
        self.assertTrue(answer.event_retrieval_by_eim)
        self.assertIsNone(answer.profile_download_trigger)

    def test_the_sm_dp_alternative_is_read_as_before(self) -> None:
        ok = esipa.AuthenticateClientOk(
            transaction_id=SMDS_TRANSACTION, smdp_signed2=wrap_tlv("30", b"\x80\x01\x01"),
            smdp_signature2=wrap_tlv("5F37", b"\x33" * 64), smdp_certificate=wrap_tlv("30", b"\x02\x01\x05"))
        provider, _client = self.provider(esipa.encode_authenticate_client_ok(ok))
        answer = provider.authenticate_client(self.request())
        self.assertFalse(answer.event_retrieval_by_eim)
        self.assertIsNone(answer.profile_download_trigger)
        self.assertEqual(base64.b64decode(answer.smdp_signed2), ok.smdp_signed2)

    def test_an_error_alternative_still_raises(self) -> None:
        # eventIdUnknown(56), SGP.32 v1.3 §6.3.2.2
        provider, _client = self.provider(esipa.encode_authenticate_client_error(56))
        with self.assertRaises(esipa.EsipaDownloadError) as caught:
            provider.authenticate_client(self.request())
        self.assertIn("eventIdUnknown", str(caught.exception))

    def test_the_alternative_is_told_apart_at_its_boundaries(self) -> None:
        ds_ok = esipa.encode_authenticate_client_ds_ok(esipa.AuthenticateClientDsOk(SMDS_TRANSACTION))
        self.assertTrue(_answered_by_smds(ds_ok))
        for label, data in (
            ("empty", b""), ("one byte", b"\xBF"), ("a tag and no length", b"\xBF\x3B"),
            ("an empty choice", bytes.fromhex("BF3B00")), ("a truncated alternative", bytes.fromhex("BF3B02A1")),
            ("a length past the end", bytes.fromhex("BF3B81F0A100")),
            ("the error alternative", esipa.encode_authenticate_client_error(127)),
            ("a download's", bytes.fromhex("BF3B02A000")), ("no ESipa message", b"text"),
        ):
            with self.subTest(case=label):
                self.assertFalse(_answered_by_smds(data))


class FlowStopTests(unittest.TestCase):
    """The flow ends at AuthenticateClient when the server is an SM-DS (SGP.22 v3.1 §3.6.2 step 8)."""

    def orchestrator(self, answer) -> tuple[SGP22Orchestrator, FakeApduChannel]:
        provider = FakeProvider(bpp_bytes=b"")
        provider.authenticate_client = mock.Mock(return_value=answer)
        channel = FakeApduChannel()
        orchestrator = orchestrator_with(provider, channel=channel)
        orchestrator.state.transaction_id = SMDS_TRANSACTION
        orchestrator.state.authenticate_server_response_b64 = "vzgA"
        return orchestrator, channel

    @staticmethod
    def events(*entries: tuple[str, str]) -> AuthenticateClientResponse:
        return AuthenticateClientResponse(
            transaction_id="AA", smdp_signed2="", smdp_signature2="", smdp_certificate="",
            event_entries=[{"eventId": event, "rspServerAddress": address} for event, address in entries])

    def test_no_prepare_download_reaches_the_card(self) -> None:
        orchestrator, channel = self.orchestrator(self.events(("MID-1", SMDP)))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(orchestrator._phase_prepare_download(smdp_address=SMDS))
        self.assertEqual(orchestrator._event_retrieval, EventRetrievalAnswer(events=(("MID-1", SMDP),)))
        self.assertEqual(channel.chunked_calls, [])

    def test_local_signing_does_not_stand_in_for_a_download_nobody_offered(self) -> None:
        # FakeCfg runs the local SGP.26 backend, where an unusable AuthenticateClient answer falls back to
        # a PrepareDownload signed with local credentials
        orchestrator, channel = self.orchestrator(self.events())
        self.assertTrue(orchestrator._local_fallback_enabled())
        orchestrator._ensure_local_credentials_loaded = mock.Mock(side_effect=AssertionError("no local signing"))
        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator._phase_prepare_download(smdp_address=SMDS)
        self.assertEqual(channel.chunked_calls, [])
        self.assertEqual(orchestrator._event_retrieval, EventRetrievalAnswer())

    def test_the_fallback_still_serves_an_answer_that_is_merely_unusable(self) -> None:
        answer = AuthenticateClientResponse(transaction_id="AA", smdp_signed2="", smdp_signature2="", smdp_certificate="")
        orchestrator, channel = self.orchestrator(answer)
        orchestrator._ensure_local_credentials_loaded = mock.Mock()
        with mock.patch.object(PayloadBuilder, "build_prepare_download", return_value=b"\xBF\x21\x00"):
            with contextlib.redirect_stdout(io.StringIO()):
                orchestrator._phase_prepare_download(smdp_address=SMDP)
        self.assertIsNone(orchestrator._event_retrieval)
        self.assertEqual([name for name, _payload in channel.chunked_calls], ["DOWNLOAD: PrepareDownload"])

    def flow(self, prepare, *, for_a_trigger: bool = True) -> tuple[SGP22Orchestrator, mock.Mock, str]:
        orchestrator = orchestrator_with()
        orchestrator._es10b_logical_channel = 1
        orchestrator._phase_connect = lambda: None
        orchestrator._phase_load_credentials = lambda: None
        orchestrator._phase_authentication_seed = lambda **kwargs: {}
        orchestrator._phase_authenticate_server = lambda auth_seed, matching_id="": None
        orchestrator._phase_prepare_download = prepare(orchestrator)
        later = mock.Mock(return_value=True)
        orchestrator._phase_get_bound_profile_package = later
        orchestrator._phase_install_package = later
        orchestrator._event_retrieval = EventRetrievalAnswer(events=(("STALE", SMDP),))
        orchestrator._event_retrieval_expected = for_a_trigger
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertIsNone(orchestrator.run_flow(matching_id="", smdp_address=SMDS))
        return orchestrator, later, output.getvalue()

    def test_the_flow_returns_before_the_bound_profile_package(self) -> None:
        def prepare(orchestrator):
            def phase(smdp_address=None):
                # what an earlier flow left is gone by the time this one asks
                self.assertIsNone(orchestrator._event_retrieval)
                orchestrator._event_retrieval = EventRetrievalAnswer(events=(("MID-1", SMDP),))
            return phase

        orchestrator, later, rendered = self.flow(prepare)
        later.assert_not_called()
        self.assertIn("the RSP Server answered as an SM-DS, no profile download on this session", rendered)
        self.assertNotIn("[SUCCESS]", rendered)
        self.assertEqual(orchestrator._event_retrieval.events, (("MID-1", SMDP),))

    def test_a_flow_whose_server_is_an_sm_dp_goes_on_as_before(self) -> None:
        for for_a_trigger in (True, False):
            with self.subTest(for_a_trigger=for_a_trigger):
                orchestrator, later, rendered = self.flow(
                    lambda orchestrator: (lambda smdp_address=None: None), for_a_trigger=for_a_trigger)
                self.assertEqual(later.call_count, 2)
                self.assertIn("[SUCCESS] Sequence Completed.", rendered)
                self.assertIsNone(orchestrator._event_retrieval)

    def test_a_download_flow_that_meets_an_sm_ds_fails(self) -> None:
        # the console's FLOW and DOWNLOAD-PROFILE, the one-shot --flow and the GUI's flow route call run_flow
        # for a download: each reports an exception as its failure, and none of them looks at Event Records
        def prepare(orchestrator):
            def phase(smdp_address=None):
                orchestrator._event_retrieval = EventRetrievalAnswer(events=(("MID-1", SMDP),))
            return phase

        with self.assertRaises(RuntimeError) as caught:
            self.flow(prepare, for_a_trigger=False)
        self.assertEqual(
            str(caught.exception),
            f"{SMDS} answered as an SM-DS with 1 Event Record(s) (EventID 'MID-1' at {SMDP}); no Profile was downloaded")

    def test_the_failure_says_what_the_sm_ds_answered(self) -> None:
        text = SGP22Orchestrator._unexpected_event_retrieval_text
        self.assertEqual(text(SMDS, EventRetrievalAnswer()),
                         f"{SMDS} answered as an SM-DS with no Event Record for this eUICC; no Profile was downloaded")
        self.assertIn("the eIM answered for the RSP Server as for an SM-DS", text("", EventRetrievalAnswer(by_eim=True)))
        many = EventRetrievalAnswer(events=tuple((f"MID-{index}", SMDP) for index in range(11)))
        self.assertIn("with 11 Event Record(s)", text(SMDS, many))
        self.assertIn("EventID 'MID-7' at smdpp.example.test and 3 more)", text(SMDS, many))
        self.assertNotIn("MID-8", text(SMDS, many))

    def test_the_trigger_handlers_flag_does_not_outlive_their_flow(self) -> None:
        orchestrator = orchestrator_with()
        seen = []

        def flow(matching_id="", smdp_address=""):
            seen.append(orchestrator._event_retrieval_expected)
            if matching_id == "boom":
                raise RuntimeError("flow failed")
            orchestrator._event_retrieval = EventRetrievalAnswer(events=((matching_id, smdp_address),))

        orchestrator.run_flow = flow
        self.assertFalse(orchestrator._event_retrieval_expected)
        self.assertEqual(orchestrator._run_flow_for_trigger("MID-1", SMDP), EventRetrievalAnswer(events=(("MID-1", SMDP),)))
        self.assertIsNone(orchestrator._event_retrieval)
        self.assertFalse(orchestrator._event_retrieval_expected)
        with self.assertRaises(RuntimeError):
            orchestrator._run_flow_for_trigger("boom", SMDP)
        self.assertFalse(orchestrator._event_retrieval_expected)
        self.assertEqual(seen, [True, True])


class MatchingIdTests(unittest.TestCase):
    def test_an_event_retrieval_signs_no_matching_id(self) -> None:
        # SGP.22 v3.1 §3.6.2 step 1, case a): "the MatchingID SHALL be missing"
        device_info = {"tac": bytes.fromhex("35290611"), "deviceCapabilities": {}}
        absent = PayloadBuilder._normalize_pysim_ctx_params(
            PayloadBuilder._normalize_ctx_params({"matchingId": "", "deviceInfo": device_info}))
        named = PayloadBuilder._normalize_pysim_ctx_params(
            PayloadBuilder._normalize_ctx_params({"matchingId": "MID-1", "deviceInfo": device_info}))
        self.assertNotIn("matchingId", absent)
        self.assertEqual(named["matchingId"], "MID-1")


class ContactSmdsTests(unittest.TestCase):
    """contactSmds run by the IPA over ES11 (SGP.32 v1.3 §3.9.2.1, SGP.22 v3.1 §3.6.2)."""

    def setUp(self) -> None:
        self.provider = FakeProvider(bpp_bytes=b"")
        self.orchestrator = orchestrator_with(self.provider)
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(INDIRECT_DOWNLOAD_ENV, None)

    def run_trigger(self, steps: list, package: bytes | None = None) -> tuple[bytes, str, Flows]:
        flows = Flows(self.orchestrator, steps)
        self.orchestrator.run_flow = flows
        response, rendered = relay(self.orchestrator, contact_smds() if package is None else package)
        return response, rendered, flows

    def test_one_record_is_one_download_with_the_event_id_as_matching_id(self) -> None:
        installed = installation_result(0x21)
        response, rendered, flows = self.run_trigger([EventRetrievalAnswer(events=(("MID-1", SMDP),)), installed])
        self.assertEqual(flows.calls, [("", SMDS), ("MID-1", SMDP)])
        self.assertEqual(response, trigger_result(RETRIEVAL, installed))
        self.assertEqual(self.provider.base_url_calls, [f"https://{SMDS}", f"https://{SMDP}"])
        self.assertIn(f"contactSmds -> {SMDS} (named by the eIM); running the Event Retrieval.", rendered)
        self.assertIn(f"Event Record 1 of 1: EventID 'MID-1' at {SMDP}", rendered)
        self.assertIsNone(self.orchestrator._event_retrieval)

    def test_records_are_taken_in_the_order_received(self) -> None:
        first, second = installation_result(0x21), installation_result(0x22)
        response, _rendered, flows = self.run_trigger([
            EventRetrievalAnswer(events=(("MID-1", SMDP), ("MID-2", "smdp2.example.test"))), first, second])
        self.assertEqual(flows.calls, [("", SMDS), ("MID-1", SMDP), ("MID-2", "smdp2.example.test")])
        # ProfileDownloadTriggerResult has room for one result: the last download tried
        self.assertEqual(response, trigger_result(RETRIEVAL, second))

    def test_a_download_that_installs_nothing_ends_the_run(self) -> None:
        failed = installation_result(0x21, failed=True)
        response, rendered, flows = self.run_trigger([
            EventRetrievalAnswer(events=(("MID-1", SMDP), ("MID-2", SMDP), ("MID-3", SMDP))), failed])
        self.assertEqual(flows.calls, [("", SMDS), ("MID-1", SMDP)])
        self.assertEqual(response, trigger_result(RETRIEVAL, failed))
        self.assertIn("2 Event Record(s) left untried after that.", rendered)

    def test_a_later_failure_is_what_the_eim_is_told(self) -> None:
        first = installation_result(0x21)
        response, rendered, flows = self.run_trigger([
            EventRetrievalAnswer(events=(("MID-1", SMDP), ("MID-2", SMDP))), first, RuntimeError("ES9+ unreachable")])
        self.assertEqual(len(flows.calls), 3)
        # the first download's result is not passed off as the second one's
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn("Download for EventID 'MID-2' at smdpp.example.test failed: ES9+ unreachable", rendered)

    def test_no_record_is_a_download_error(self) -> None:
        # SGP.32 v1.3 §2.11.2.3: without a ProfileInstallationResult the IPA returns profileDownloadError
        response, rendered, flows = self.run_trigger([EventRetrievalAnswer()])
        self.assertEqual(flows.calls, [("", SMDS)])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn(f"Event Retrieval at {SMDS}: no Event Record for this eUICC.", rendered)

    def test_an_sm_ds_that_cannot_be_asked_is_a_download_error(self) -> None:
        response, rendered, flows = self.run_trigger([RuntimeError("Server Auth Refused by Card")])
        self.assertEqual(flows.calls, [("", SMDS)])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn(f"Event Retrieval at {SMDS} failed: Server Auth Refused by Card", rendered)

    def test_a_server_that_is_no_sm_ds_gives_no_records(self) -> None:
        response, rendered, flows = self.run_trigger([None])
        self.assertEqual(flows.calls, [("", SMDS)])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn(f"{SMDS} did not answer as an SM-DS", rendered)

    def test_what_an_earlier_flow_left_is_not_taken_for_this_ones_answer(self) -> None:
        self.orchestrator._event_retrieval = EventRetrievalAnswer(events=(("STALE", SMDP),))
        response, rendered, flows = self.run_trigger([None])
        self.assertEqual(flows.calls, [("", SMDS)])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn(f"{SMDS} did not answer as an SM-DS", rendered)

    def test_a_record_that_leads_to_another_sm_ds_is_not_followed(self) -> None:
        response, rendered, flows = self.run_trigger([
            EventRetrievalAnswer(events=(("MID-1", "smds2.example.test"), ("MID-2", SMDP))),
            EventRetrievalAnswer(events=(("MID-9", SMDP),)),
        ])
        self.assertEqual(flows.calls, [("", SMDS), ("MID-1", "smds2.example.test")])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn("a cascaded Event Record, which this IPA does not follow", rendered)
        self.assertIsNone(self.orchestrator._event_retrieval)

    def test_a_result_left_by_an_earlier_download_is_not_reported(self) -> None:
        self.orchestrator.state.load_bpp_response = installation_result(0x20)
        response, _rendered, _flows = self.run_trigger([EventRetrievalAnswer()])
        self.assertEqual(response, download_error(RETRIEVAL))

    def configured(self, *members: bytes) -> None:
        self.orchestrator._cached_or_retrieve_eim_metadata = mock.Mock(return_value=wrap_tlv("BF3C", b"".join(members)))

    def test_without_an_address_the_root_sm_ds_of_the_euicc_is_asked(self) -> None:
        # SGP.22 v3.1 §5.7.3: defaultDpAddress '80', rootDsAddress '81'
        self.configured(wrap_tlv("80", b"rsp.example.com"), wrap_tlv("81", b"rootsmds.example.test"))
        installed = installation_result(0x21)
        response, rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(events=(("MID-1", SMDP),)), installed], contact_smds(address=""))
        self.assertEqual(flows.calls, [("", "rootsmds.example.test"), ("MID-1", SMDP)])
        self.assertEqual(response, trigger_result(RETRIEVAL, installed))
        self.assertIn("contactSmds -> rootsmds.example.test (the eUICC's Root SM-DS)", rendered)
        self.assertEqual(self.orchestrator._read_default_smdp_address(), "rsp.example.com")

    def test_no_sm_ds_address_anywhere_is_an_invalid_package(self) -> None:
        for label, members in (
            ("a zero-length rootDsAddress", (wrap_tlv("80", b"rsp.example.com"), wrap_tlv("81", b""))),
            ("no rootDsAddress", (wrap_tlv("80", b"rsp.example.com"),)),
            ("only further Root SM-DS addresses", (wrap_tlv("81", b""), wrap_tlv("A2", wrap_tlv("0C", b"smds3.example.test")))),
        ):
            with self.subTest(case=label):
                self.configured(*members)
                response, rendered, flows = self.run_trigger([], contact_smds(address=""))
                self.assertEqual(flows.calls, [])
                self.assertEqual(response, INVALID_PACKAGE_FORMAT)
                self.assertIn("neither the trigger nor the eUICC names an SM-DS address", rendered)

    def test_an_activation_code_that_names_an_sm_ds_downloads_nothing(self) -> None:
        response, rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(events=(("MID-1", SMDP),))], activation_code_trigger("MID-AC", RETRIEVAL))
        self.assertEqual(flows.calls, [("MID-AC", SMDP)])
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertIn("answered as an SM-DS where the trigger named an SM-DP+", rendered)
        self.assertIsNone(self.orchestrator._event_retrieval)


class ThroughTheEimTests(unittest.TestCase):
    """Event Retrieval by the eIM (SGP.32 v1.3 §3.9.2.2): the IPA's side of steps 6 to 14."""

    def setUp(self) -> None:
        self.client = EsipaClient()
        self.orchestrator = orchestrator_with(self.client)
        self.orchestrator._active_eim_poll_request = mock.Mock(eim_fqdn=EIM, trusted_tls_public_key_data=b"")
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(INDIRECT_DOWNLOAD_ENV, None)

    def run_trigger(self, steps: list, package: bytes) -> tuple[bytes, str, Flows]:
        flows = Flows(self.orchestrator, steps)
        self.orchestrator.run_flow = flows
        response, rendered = relay(self.orchestrator, package)
        return response, rendered, flows

    def test_the_trigger_in_the_answer_is_run_and_its_result_reported(self) -> None:
        installed = installation_result(0x21)
        response, rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(by_eim=True, trigger=empty_trigger(DOWNLOAD)), installed], empty_trigger())
        # both flows go through the eIM, each under the eimTransactionId of its own trigger
        self.assertEqual(flows.calls, [("", ""), ("", "")])
        self.assertEqual(flows.providers, ["EsipaProfileProvider", "EsipaProfileProvider"])
        self.assertEqual(flows.transactions, [RETRIEVAL, DOWNLOAD])
        self.assertEqual(response, trigger_result(DOWNLOAD, installed))
        self.assertIn("Event Retrieval by the eIM completed; running the profile download trigger in its answer.", rendered)
        self.assertNotIn("failed", rendered)
        self.assertIs(self.orchestrator.profile_provider, self.client)
        self.assertEqual(self.orchestrator._event_retrieval_trigger_depth, 0)
        self.assertEqual(self.orchestrator._no_eim_package_result_owed, "")

    def test_a_trigger_with_an_activation_code_is_run_as_one_from_a_package(self) -> None:
        installed = installation_result(0x21)
        response, _rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(by_eim=True, trigger=activation_code_trigger("MID-1")), installed], empty_trigger())
        self.assertEqual(flows.calls, [("", ""), ("MID-1", SMDP)])
        self.assertEqual(flows.providers, ["EsipaProfileProvider", "EsipaClient"])
        self.assertEqual(response, trigger_result(DOWNLOAD, installed))

    def test_no_trigger_in_the_answer_owes_the_eim_no_result(self) -> None:
        response, rendered, flows = self.run_trigger([EventRetrievalAnswer(by_eim=True)], empty_trigger())
        self.assertEqual(flows.calls, [("", "")])
        self.assertEqual(response, b"")
        self.assertEqual(self.orchestrator._no_eim_package_result_owed,
                         "the eIM ran the Event Retrieval and holds its outcome")
        self.assertIn("its answer carries no profile download trigger", rendered)
        self.assertNotIn("profileDownloadError", rendered)

    def test_a_failed_retrieval_is_still_reported_as_a_failure(self) -> None:
        response, rendered, _flows = self.run_trigger(
            [RuntimeError("Provider authenticateClient failed: ESipa.AuthenticateClient: eventIdUnknown (56)")],
            empty_trigger())
        self.assertEqual(response, download_error(RETRIEVAL))
        self.assertEqual(self.orchestrator._no_eim_package_result_owed, "")
        self.assertIn("eIM-triggered indirect profile download failed", rendered)

    def test_a_second_retrieval_in_a_row_is_not_followed(self) -> None:
        self.assertEqual(MAX_EVENT_RETRIEVAL_TRIGGER_DEPTH, 1)
        response, rendered, flows = self.run_trigger([
            EventRetrievalAnswer(by_eim=True, trigger=empty_trigger(DOWNLOAD)),
            EventRetrievalAnswer(by_eim=True, trigger=empty_trigger(bytes.fromhex("C1C2C3C4"))),
        ], empty_trigger())
        self.assertEqual(len(flows.calls), 2)
        self.assertEqual(response, b"")
        self.assertEqual(self.orchestrator._no_eim_package_result_owed, "a second Event Retrieval in a row is not followed")
        self.assertIn("the profile download trigger in its answer is not run", rendered)
        self.assertEqual(self.orchestrator._event_retrieval_trigger_depth, 0)

    def test_an_answer_that_carries_something_else_is_not_run(self) -> None:
        for label, trigger, text in (
            ("no eIM package", b"\x30\x03\x02\x01\x05", "not a profile download trigger"),
            ("a truncated trigger", bytes.fromhex("BF5408A0"), "not"),
        ):
            with self.subTest(case=label):
                response, rendered, flows = self.run_trigger([EventRetrievalAnswer(by_eim=True, trigger=trigger)], empty_trigger())
                self.assertEqual(len(flows.calls), 1)
                self.assertEqual(response, b"")
                self.assertNotEqual(self.orchestrator._no_eim_package_result_owed, "")
                self.assertIn(text, rendered)

    def test_contact_smds_goes_through_the_eim_when_asked_to(self) -> None:
        # an IPA supporting both may choose (SGP.32 v1.3 §2.11.1.3); the SM-DS FQDN then goes in step 6
        os.environ[INDIRECT_DOWNLOAD_ENV] = "1"
        installed = installation_result(0x21)
        response, rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(by_eim=True, trigger=empty_trigger(DOWNLOAD)), installed], contact_smds())
        self.assertEqual(flows.calls, [("", SMDS), ("", "")])
        self.assertEqual(flows.providers, ["EsipaProfileProvider", "EsipaProfileProvider"])
        self.assertEqual(flows.transactions, [RETRIEVAL, DOWNLOAD])
        self.assertEqual(response, trigger_result(DOWNLOAD, installed))
        self.assertIn(f"contactSmds -> {SMDS}; Event Retrieval through eIM {EIM}.", rendered)

    def test_contact_smds_stays_direct_for_an_ipa_that_declares_no_indirect_download(self) -> None:
        class DirectOnlyCfg(FakeCfg):
            # ipaFeatures directRspServerCommunication(0) alone
            IPA_CAPABILITIES_BER_TLV = bytes.fromhex("80020780")

        os.environ[INDIRECT_DOWNLOAD_ENV] = "1"
        self.orchestrator = orchestrator_with(self.client, cfg=DirectOnlyCfg())
        self.orchestrator._active_eim_poll_request = mock.Mock(eim_fqdn=EIM, trusted_tls_public_key_data=b"")
        installed = installation_result(0x21)
        response, _rendered, flows = self.run_trigger(
            [EventRetrievalAnswer(events=(("MID-1", SMDP),)), installed], contact_smds())
        self.assertEqual(flows.providers, ["EsipaClient", "EsipaClient"])
        self.assertEqual(response, trigger_result(RETRIEVAL, installed))

    def test_the_real_provider_stops_the_real_flow_at_the_eims_answer(self) -> None:
        # run_flow down to its phases: the provider reads authenticateClientOkDSEsipa off the wire and
        # the flow never asks the card for a PrepareDownload
        trigger = empty_trigger(DOWNLOAD)
        self.client.answers = [esipa.encode_authenticate_client_ds_ok(esipa.AuthenticateClientDsOk(SMDS_TRANSACTION, trigger))]
        channel = self.orchestrator.apdu_channel
        self.orchestrator._es10b_logical_channel = 1
        self.orchestrator._phase_connect = lambda: None
        self.orchestrator._phase_load_credentials = lambda: None
        self.orchestrator._phase_authentication_seed = lambda **kwargs: {}

        def authenticated(auth_seed, matching_id=""):
            self.orchestrator.state.transaction_id = SMDS_TRANSACTION
            self.orchestrator.state.authenticate_server_response_b64 = "vzgA"

        self.orchestrator._phase_authenticate_server = authenticated
        later = mock.Mock(side_effect=AssertionError("no download step after an Event Retrieval"))
        self.orchestrator._phase_get_bound_profile_package = later
        self.orchestrator._phase_install_package = later
        seen = {}
        handle = self.orchestrator._handle_profile_download_trigger

        def nested(parsed):
            if bytes(parsed.eim_transaction_id) == DOWNLOAD:
                seen["nested"] = parsed
                return trigger_result(DOWNLOAD, installation_result(0x21))
            return handle(parsed)

        self.orchestrator._handle_profile_download_trigger = nested
        response, rendered = relay(self.orchestrator, empty_trigger())
        self.assertEqual(response, trigger_result(DOWNLOAD, installation_result(0x21)))
        self.assertEqual(bytes(seen["nested"].eim_transaction_id), DOWNLOAD)
        self.assertEqual([name for name, _payload in channel.chunked_calls], [])
        self.assertEqual(len(self.client.posted), 1)
        self.assertEqual(self.client.posted[0][:2], bytes.fromhex("BF3B"))
        self.assertIn("the RSP Server answered as an SM-DS", rendered)


class PollRoundTests(unittest.TestCase):
    """What the poll round sends the eIM for a package that started an Event Retrieval."""

    def round(self, steps: list, packages: list[bytes]) -> tuple[SGP22Orchestrator, EsipaClient, str, Flows]:
        client = EsipaClient()
        client._eim_poll_responses = [
            EimPollResponse(transaction_id=f"tx-{index}", euicc_package_list=[package.hex().upper()], polling_complete=False)
            for index, package in enumerate(packages, start=1)
        ] + [EimPollResponse(transaction_id="tx-end", polling_complete=True, eim_result_code=1)]
        orchestrator = orchestrator_with(client)
        orchestrator._es10b_logical_channel = 1
        orchestrator._phase_connect_complete = True
        flows = Flows(orchestrator, steps)
        orchestrator.run_flow = flows
        from tests.test_scp11_orchestrator import OrchestratorFlowTests

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            orchestrator._run_single_eim_poll_round(OrchestratorFlowTests._minimal_eim_poll_request())
        return orchestrator, client, output.getvalue(), flows

    def test_a_retrieval_the_eim_ran_draws_no_result_and_the_poll_goes_on(self) -> None:
        orchestrator, client, rendered, _flows = self.round([EventRetrievalAnswer(by_eim=True)], [empty_trigger()])
        self.assertEqual(client.handle_notification_esipa_calls, [])
        self.assertEqual(client.provide_eim_package_result_calls, [])
        self.assertEqual(len(client.poll_eim_calls), 2)
        self.assertIn("No eIM Package Result for package 1 in poll round 1: the eIM ran the Event Retrieval "
                      "and holds its outcome.", rendered)
        self.assertEqual(orchestrator._no_eim_package_result_owed, "")

    def test_the_download_the_answer_started_is_reported_under_its_own_transaction(self) -> None:
        installed = installation_result(0x21)
        _orchestrator, client, _rendered, _flows = self.round(
            [EventRetrievalAnswer(by_eim=True, trigger=empty_trigger(DOWNLOAD)), installed], [empty_trigger()])
        expected = wrap_tlv("BF3D", wrap_tlv("BF50", wrap_tlv("5A", bytes.fromhex(EID)) + trigger_result(DOWNLOAD, installed)))
        self.assertEqual([call.raw_body for call in client.handle_notification_esipa_calls], [expected])
        self.assertEqual(client.provide_eim_package_result_calls, [])

    def test_an_empty_answer_nobody_accounted_for_still_stops_the_poll(self) -> None:
        client = EsipaClient()
        client._eim_poll_responses = [EimPollResponse(
            transaction_id="tx-1", euicc_package_list=[empty_trigger().hex().upper()], polling_complete=False)]
        orchestrator = orchestrator_with(client)
        orchestrator._es10b_logical_channel = 1
        orchestrator._phase_connect_complete = True
        orchestrator._handle_profile_download_trigger = lambda parsed: b""
        from tests.test_scp11_orchestrator import OrchestratorFlowTests

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError) as caught:
                orchestrator._run_single_eim_poll_round(OrchestratorFlowTests._minimal_eim_poll_request())
        self.assertIn("requires a card package result", str(caught.exception))

    def test_the_mark_of_one_package_does_not_cover_the_next(self) -> None:
        orchestrator = orchestrator_with(EsipaClient())
        orchestrator._active_eim_poll_request = mock.Mock(eim_fqdn=EIM, trusted_tls_public_key_data=b"")
        orchestrator.run_flow = Flows(orchestrator, [EventRetrievalAnswer(by_eim=True)])
        response, _rendered = relay(orchestrator, empty_trigger())
        self.assertEqual(response, b"")
        self.assertNotEqual(orchestrator._no_eim_package_result_owed, "")
        # the next package: a trigger this IPA cannot use, answered with a result of its own
        orchestrator.run_flow = mock.Mock(side_effect=AssertionError("no flow for a malformed trigger"))
        malformed = wrap_tlv("BF54", wrap_tlv("A0", wrap_tlv("80", b"2$rsp.example.com$MID")) + wrap_tlv("82", RETRIEVAL))
        response, _rendered = relay(orchestrator, malformed)
        self.assertEqual(response, INVALID_PACKAGE_FORMAT)
        self.assertEqual(orchestrator._no_eim_package_result_owed, "")


if __name__ == "__main__":
    unittest.main()
