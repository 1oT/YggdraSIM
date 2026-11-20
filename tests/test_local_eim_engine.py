# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM engine against the simulated eUICC: queue, sign when served, read results back.

Operations are queued, served, executed by the simulator's
ES10b.LoadEuiccPackage (SGP.32 v1.3 §5.9.1) and checked the way an eIM checks
them (§3.3.1 step 11). The engine's encodings are cross-checked against the
simulator's own decoder, which shares no code with them.
"""

from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.catalogue import OperationError
from SCP11.eim_local.engine.delivery import answer_ipa_euicc_data_request, deliver
from SCP11.eim_local.engine.service import (
    STATE_CANCELED,
    STATE_CREATED,
    STATE_ERROR,
    STATE_SENT,
    STATE_SUCCESS,
    LocalEim,
    LocalEimError,
    OperationRequest,
)
from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.sgp32_packages import decode_euicc_package_request, verify_eim_signature

ENABLED = "89881111111111111112"
DISABLED = "89881111111111111129"
EIM_ID = "1.3.6.1.4.1.32473.999.10.124"


class SimCard:
    """The simulated eUICC behind an ES10b exchange, the shape the direct route sends through."""

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


def _other_eim_certificate() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other eIM")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER).hex().upper()


class EngineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.now = datetime.datetime(2026, 11, 4, 12, 0, tzinfo=datetime.timezone.utc)
        self.engine = LocalEim(Path(directory.name), clock=lambda: self.now)
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)

    def queue(self, type_name: str, **params: object) -> int:
        request = OperationRequest(eid=self.card.eid, type=type_name, params=dict(params))
        return self.engine.submit([request])[0].id

    def run_queue(self) -> list:
        return deliver(self.engine, self.card.exchange, self.card.eid)

    def state_of(self, operation_id: int) -> str:
        return self.engine.operation(operation_id).state

    def sim_entry(self):
        return next(entry for entry in self.card.state.eim_entries if entry.eim_id == EIM_ID)


class RecordFieldTests(EngineTestBase):
    def test_the_chain_beyond_the_eum_certificate_is_set_and_cleared(self) -> None:
        # SGP.22 v3.1 5.7.13 otherCertsInChain, for an IPA that only ever sends the compact form
        certificate = bytes.fromhex("3003020100")
        record = self.engine.update_record(self.card.eid, {"other_certs_in_chain": " 30 03 02 01 00 "})
        self.assertEqual(record.data["other_certs_in_chain_hex"], certificate.hex().upper())
        self.assertEqual(self.engine.record(self.card.eid).data["other_certs_in_chain_hex"], "3003020100")
        record = self.engine.update_record(self.card.eid, {"other_certs_in_chain": ""})
        self.assertNotIn("other_certs_in_chain_hex", record.data)

    def test_the_chain_must_be_der_certificates(self) -> None:
        with self.assertRaises(LocalEimError):
            self.engine.update_record(self.card.eid, {"other_certs_in_chain": "zz"})
        with self.assertRaises(LocalEimError):
            self.engine.update_record(self.card.eid, {"other_certs_in_chain": "0400"})
        with self.assertRaises(LocalEimError):
            self.engine.update_record(self.card.eid, {"no_such_field": "1"})


class AssociationTests(EngineTestBase):
    def test_associate_seeds_the_record_with_the_token_the_card_assigned(self) -> None:
        record = self.engine.record(self.card.eid)
        entry = self.sim_entry()
        self.assertEqual(record.association_token, entry.association_token)
        self.assertEqual(record.counter_value, 0)
        self.assertTrue(record.data["associated"])
        # The simulator's resetEimConfigData restores its own default entry
        # rather than clearing the list, so the Local eIM is one of two.
        self.assertIn(EIM_ID, [item.eim_id for item in self.card.state.eim_entries])
        self.assertEqual(entry.counter_value, 0)


class RoundTripTests(EngineTestBase):
    def test_profile_operations_run_and_update_the_record(self) -> None:
        listing = self.queue("PROFILE_INFO_LIST")
        enable = self.queue("ENABLE_PROFILE", iccid=DISABLED, rollback="on")
        steps = self.run_queue()
        self.assertEqual(self.state_of(listing), STATE_SUCCESS)
        self.assertEqual(self.state_of(enable), STATE_SUCCESS)
        self.assertEqual(len(steps), 2)  # the direct route reads the certificate with GetCerts itself
        profiles = {entry["iccid"]: entry["state"] for entry in self.engine.record(self.card.eid).profiles}
        self.assertEqual(profiles[DISABLED], "enabled")
        self.assertEqual(profiles[ENABLED], "disabled")
        disable = self.queue("DISABLE_PROFILE", iccid=DISABLED)
        delete = self.queue("DELETE_PROFILE", iccid=DISABLED)
        self.run_queue()
        self.assertEqual(self.state_of(disable), STATE_SUCCESS)
        self.assertEqual(self.state_of(delete), STATE_SUCCESS)
        remaining = [entry["iccid"] for entry in self.engine.record(self.card.eid).profiles]
        self.assertNotIn(DISABLED, remaining)

    def test_every_remaining_psmo_is_answered(self) -> None:
        operations = {
            "GET_RAT": self.queue("GET_RAT"),
            "CONFIGURE_IMMEDIATE_ENABLE": self.queue(
                "CONFIGURE_IMMEDIATE_ENABLE", enabled="on", default_smdp_address="smdpp.example.test"
            ),
            "SET_DEFAULT_DP_ADDRESS": self.queue("SET_DEFAULT_DP_ADDRESS", address="smdpp.example.test"),
            "UNSET_FALLBACK_ATTRIBUTE": self.queue("UNSET_FALLBACK_ATTRIBUTE"),
        }
        self.run_queue()
        for name in ("GET_RAT", "CONFIGURE_IMMEDIATE_ENABLE", "SET_DEFAULT_DP_ADDRESS"):
            self.assertEqual(self.state_of(operations[name]), STATE_SUCCESS, name)
        record = self.engine.record(self.card.eid)
        self.assertEqual(record.data["default_smdp_address"], "smdpp.example.test")
        self.assertTrue(record.data["immediate_enable"])
        # No profile carries the attribute: the eUICC answers noFallbackAttribute(2).
        unset = self.engine.operation(operations["UNSET_FALLBACK_ATTRIBUTE"])
        self.assertEqual(unset.state, STATE_ERROR)
        self.assertIn("noFallbackAttribute", " ".join(unset.result["items"]))

    def test_eim_configuration_operations(self) -> None:
        listing = self.queue("LIST_EIM")
        add = self.queue("ADD_EIM", eim_id="2.999.1", eim_fqdn="other.example.test",
                         certificate=_other_eim_certificate(), association_token="on")
        self.run_queue()
        self.assertEqual(self.state_of(listing), STATE_SUCCESS)
        self.assertEqual(self.state_of(add), STATE_SUCCESS)
        self.assertIn("2.999.1", [entry.eim_id for entry in self.card.state.eim_entries])
        update = self.queue("UPDATE_EIM", eim_id="2.999.1", counter_value="5")
        delete = self.queue("DELETE_EIM", eim_id="2.999.1")
        self.run_queue()
        self.assertEqual(self.state_of(update), STATE_SUCCESS)
        self.assertEqual(self.state_of(delete), STATE_SUCCESS)
        self.assertNotIn("2.999.1", [entry["eim_id"] for entry in self.engine.record(self.card.eid).eims])

    def test_only_an_enable_or_disable_resets_the_card_before_the_notifications(self) -> None:
        # SGP.32 v1.3 §3.3.1 steps 8a-8b: the eUICC generates the Notification of an enable or a
        # disable after the RESET when a reader session gives it no proactive session for the REFRESH.
        self.run_queue()
        resets: list[str] = []

        def reset() -> bool:
            resets.append("reset")
            return True

        self.queue("PROFILE_INFO_LIST")
        enable = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        self.queue("GET_RAT")
        lines: list[str] = []
        deliver(self.engine, self.card.exchange, self.card.eid, emit=lines.append, reset=reset)
        self.assertEqual(self.state_of(enable), STATE_SUCCESS)
        self.assertEqual(resets, ["reset"])
        self.assertIn("[*] card reset to complete the Profile state change (SGP.32 v1.3 §3.3.1 step 8b)", lines)

    def test_counter_goes_up_by_one_per_package_and_results_verify(self) -> None:
        self.run_queue()  # fetch the certificate first
        ids = [self.queue("PROFILE_INFO_LIST") for _ in range(3)]
        self.run_queue()
        counters = [self.engine.operation(operation_id).counter_value for operation_id in ids]
        self.assertEqual(counters, [1, 2, 3])
        self.assertEqual(self.engine.record(self.card.eid).counter_value, 3)
        for operation_id in ids:
            operation = self.engine.operation(operation_id)
            self.assertNotIn("unverified", operation.flags)
            self.assertEqual(operation.state, STATE_SUCCESS)


class EncodingCrossCheckTests(EngineTestBase):
    def test_served_package_decodes_and_verifies_with_the_simulator_code(self) -> None:
        self.run_queue()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED, rollback="on")
        served = self.engine.next_package(self.card.eid)
        self.assertIsNone(served.error)
        self.assertEqual(served.response[:2], b"\xBF\x4F")
        envelope = decode_euicc_package_request(served.package)
        self.assertEqual(envelope.eim_id, EIM_ID)
        self.assertEqual(envelope.counter_value, 1)
        self.assertEqual(envelope.eim_transaction_id.hex().upper(), self.engine.operation(operation_id).transaction_id)
        public_key = self.engine.identity().signing_public_key_der()
        token = self.engine.record(self.card.eid).association_token
        self.assertTrue(verify_eim_signature(public_key, envelope.signed_blob, envelope.eim_signature, token or 0))


class FaultTests(EngineTestBase):
    def _fault(self, fault: str) -> str:
        self.run_queue()
        request = OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST", fault=fault)
        operation_id = self.engine.submit([request])[0].id
        self.run_queue()
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_ERROR, fault)
        return operation.history[-1]["event"]

    def test_injected_faults_draw_the_errors_sgp32_names(self) -> None:
        self.assertIn("replayError", self._fault("stale-counter"))
        self.assertIn("invalidEid", self._fault("wrong-eid"))
        self.assertIn("euiccPackageErrorUnsigned", self._fault("bad-signature"))
        self.assertIn("euiccPackageErrorUnsigned", self._fault("wrong-token"))
        self.assertIn("euiccPackageErrorUnsigned", self._fault("unknown-eim"))
        self.assertIn("counterValueOutOfRange", self._fault("counter-overflow"))

    def test_unknown_fault_is_refused(self) -> None:
        with self.assertRaises(OperationError):
            self.engine.submit([OperationRequest(eid=self.card.eid, type="GET_RAT", fault="nonsense")])


class EditingTests(EngineTestBase):
    def test_relaxed_preconditions_queue_with_warnings(self) -> None:
        # Outside conformance_strict the simulator answers ok to an enable of
        # the enabled profile, as cards in the field do.
        self.card.state.conformance_strict = True
        self.queue("PROFILE_INFO_LIST")
        self.run_queue()
        operation = self.engine.submit([OperationRequest(eid=self.card.eid, type="ENABLE_PROFILE",
                                                         params={"iccid": ENABLED})])[0]
        self.assertTrue(any("already enabled" in warning for warning in operation.warnings))
        self.run_queue()
        self.assertEqual(self.state_of(operation.id), STATE_ERROR)

    def test_edit_changes_parameters_and_recomputes_warnings(self) -> None:
        self.queue("PROFILE_INFO_LIST")
        self.run_queue()
        operation_id = self.queue("ENABLE_PROFILE", iccid="8988000000000000000")
        self.assertTrue(any("not in the record" in warning for warning in self.engine.operation(operation_id).warnings))
        edited = self.engine.edit(operation_id, {"iccid": DISABLED, "rollback": "on"})
        self.assertEqual(edited.params, {"iccid": DISABLED, "rollback": True})
        self.assertEqual(edited.warnings, [])
        self.assertIn("edited", edited.history[-1]["event"])
        self.run_queue()
        self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)

    def test_edit_raw_items_and_type(self) -> None:
        self.run_queue()
        operation_id = self.queue("GET_RAT")
        self.engine.edit(operation_id, {"type": "PSMO_RAW", "items": "A600BF2D00"})
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.type, "PSMO_RAW")
        self.run_queue()
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertEqual(len(operation.result["items"]), 2)

    def test_edit_refuses_a_finished_operation_and_copy_requeues_it(self) -> None:
        self.run_queue()
        operation_id = self.queue("GET_RAT")
        self.run_queue()
        with self.assertRaises(LocalEimError):
            self.engine.edit(operation_id, {"iccid": DISABLED})
        copied = self.engine.copy(operation_id, {"type": "PROFILE_INFO_LIST"})
        self.assertEqual(copied.state, STATE_CREATED)
        self.assertEqual(copied.type, "PROFILE_INFO_LIST")

    def test_move_and_cancel_decide_the_serving_order(self) -> None:
        self.run_queue()
        first = self.queue("GET_RAT")
        second = self.queue("PROFILE_INFO_LIST")
        third = self.queue("LIST_EIM")
        self.engine.move(third, "first")
        self.engine.cancel(second)
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, third)
        self.assertEqual(self.state_of(second), STATE_CANCELED)
        self.assertEqual([entry.id for entry in self.engine.queue(self.card.eid)], [third, first])

    def test_not_before_holds_an_operation_until_its_time(self) -> None:
        self.run_queue()
        later = (self.now + datetime.timedelta(hours=1)).isoformat()
        operation_id = self.engine.submit(
            [OperationRequest(eid=self.card.eid, type="GET_RAT", not_before=later)]
        )[0].id
        self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        self.now = self.now + datetime.timedelta(hours=2)
        self.assertEqual(self.engine.next_package(self.card.eid).operation.id, operation_id)


class LostResultTests(EngineTestBase):
    def _serve_and_lose(self, operation_id: int) -> None:
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, operation_id)
        self.card.exchange(served.package, "LoadEuiccPackage, answer dropped")
        self.assertEqual(self.state_of(operation_id), STATE_SENT)

    def test_a_lost_result_is_recovered_from_the_card(self) -> None:
        self.run_queue()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        self._serve_and_lose(operation_id)
        stored_before = len(self.card.state.euicc_package_results)
        self.run_queue()
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertTrue(any(flag.startswith("recovered-by-") for flag in operation.flags))
        self.assertEqual(operation.counter_value, 1)
        self.assertLess(len(self.card.state.euicc_package_results), stored_before)

    def test_a_profile_state_change_is_held_until_its_result_and_never_served_again(self) -> None:
        # SGP.32 v1.3 §3.3.1 steps 8a-8b: the result of an enable follows the eUICC's REFRESH, so an IPAe
        # polls again before it can report it; the eIM must not run the state change a second time.
        self.run_queue()
        operation_id = self.queue("ENABLE_PROFILE", iccid=DISABLED)
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, operation_id)
        kept_back = self.card.exchange(served.package, "LoadEuiccPackage, result reported later")
        recovery = self.engine.next_package(self.card.eid)
        self.assertEqual(recovery.operation.recovery_for, operation_id)
        for _ in range(3):
            self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        operation = self.engine.operation(operation_id)
        self.assertEqual((operation.state, operation.retries, operation.counter_value), (STATE_SENT, 0, 1))
        self.assertTrue(any("held: a Profile state change" in str(entry.get("event")) for entry in operation.history))
        self.assertEqual(self.engine.operation(recovery.operation.id).state, STATE_SENT)
        accepted = self.engine.accept_result(self.card.eid, kept_back)
        self.assertEqual(accepted.operation.id, operation_id)
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertNotIn("late-result", operation.flags)
        self.assertEqual(self.engine.operation(recovery.operation.id).state, STATE_SUCCESS)
        self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        # Without recovery the same hold applies.
        self.engine.set_setting("recover_lost_results", "off")
        second = self.queue("DISABLE_PROFILE", iccid=DISABLED)
        served = self.engine.next_package(self.card.eid)
        kept_back = self.card.exchange(served.package, "LoadEuiccPackage, result reported later")
        self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        self.assertEqual((self.state_of(second), self.engine.operation(second).retries), (STATE_SENT, 0))
        self.engine.accept_result(self.card.eid, kept_back)
        self.assertEqual(self.state_of(second), STATE_SUCCESS)

    def test_without_recovery_the_package_is_served_again_with_a_fresh_counter(self) -> None:
        self.engine.set_setting("recover_lost_results", "off")
        self.run_queue()
        operation_id = self.queue("PROFILE_INFO_LIST")
        self._serve_and_lose(operation_id)
        self.run_queue()
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_SUCCESS)
        self.assertEqual(operation.counter_value, 2)
        self.assertEqual(operation.retries, 1)

    def test_retry_limit_ends_in_error(self) -> None:
        self.engine.set_setting("recover_lost_results", "off")
        self.run_queue()
        operation_id = self.engine.submit(
            [OperationRequest(eid=self.card.eid, type="GET_RAT", max_retries=1)]
        )[0].id
        self._serve_and_lose(operation_id)
        self._serve_and_lose(operation_id)
        self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_ERROR)
        self.assertIn("no result after 2 serves", operation.error)

    def test_hold_mode_waits_for_the_operator(self) -> None:
        self.run_queue()
        held = self.engine.submit([OperationRequest(eid=self.card.eid, type="GET_RAT", max_retries=0)])[0].id
        waiting = self.queue("LIST_EIM")
        self._serve_and_lose(held)
        self.assertEqual(self.engine.next_package(self.card.eid).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        self.assertEqual(self.state_of(waiting), STATE_CREATED)
        self.engine.edit(held, {"max_retries": "1"})
        self.run_queue()
        self.assertEqual(self.state_of(held), STATE_SUCCESS)
        self.assertEqual(self.state_of(waiting), STATE_SUCCESS)


class PollingRuleTests(EngineTestBase):
    def test_unknown_eid_and_learning(self) -> None:
        stranger = "89049032123451234512345678901299"
        self.engine.set_setting("learn_unknown_eids", "off")
        served = self.engine.next_package(stranger)
        self.assertEqual(served.error, codec.EID_NOT_FOUND)
        self.assertEqual(served.response, bytes.fromhex("BF4F03020102"))
        self.engine.set_setting("learn_unknown_eids", "on")
        self.assertEqual(self.engine.next_package(stranger).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        self.assertIsNotNone(self.engine.record(stranger))

    def test_learning_is_on_by_default(self) -> None:
        stranger = "89049032123451234512345678901288"
        self.assertTrue(self.engine.settings()["learn_unknown_eids"])
        self.assertEqual(self.engine.next_package(stranger).error, codec.NO_EIM_PACKAGE_AVAILABLE)
        self.assertEqual(self.engine.record(stranger).label, "registered on first poll")

    def test_missing_certificate_is_asked_for_first(self) -> None:
        operation_id = self.queue("GET_RAT")
        served = self.engine.next_package(self.card.eid)
        self.assertTrue(served.package.startswith(codec.TAG_IPA_EUICC_DATA))
        answer = answer_ipa_euicc_data_request(self.card.exchange, served.package, EIM_ID)
        self.engine.accept_result(self.card.eid, answer)
        self.assertGreater(len(self.engine.record(self.card.eid).euicc_certificate), 0)
        self.assertEqual(self.engine.next_package(self.card.eid).operation.id, operation_id)

    def test_notify_state_change_serves_a_profile_list_first(self) -> None:
        self.run_queue()
        self.queue("GET_RAT")
        served = self.engine.next_package(self.card.eid, notify_state_change=True, state_change_cause=4)
        self.assertEqual(served.operation.type, "PROFILE_INFO_LIST")
        self.assertTrue(served.operation.system)


class DetectedEidTests(EngineTestBase):
    """An EID a YggdraSIM surface reads from a card is registered without an EUICC ADD."""

    STRANGER = "89049032123451234512345678901277"

    def test_a_new_eid_is_registered_once_with_where_it_was_seen(self) -> None:
        record = self.engine.note_detected_eid(self.STRANGER, source="the eSIM Management console")
        self.assertEqual(record.eid, self.STRANGER)
        self.assertEqual(record.label, "detected by the eSIM Management console")
        stored = self.engine.record(self.STRANGER)
        self.assertEqual(stored.data["first_seen"]["by"], "the eSIM Management console")
        self.assertEqual(stored.counter_value, 0)
        self.assertIsNone(self.engine.note_detected_eid(self.STRANGER, source="the SCP03 admin shell"))
        self.assertEqual(self.engine.record(self.STRANGER).label, "detected by the eSIM Management console")

    def test_a_known_eid_is_left_as_it_is(self) -> None:
        before = self.engine.record(self.card.eid)
        self.assertIsNone(self.engine.note_detected_eid(self.card.eid, source="the eSIM Management console"))
        after = self.engine.record(self.card.eid)
        self.assertEqual((after.label, after.association_token), (before.label, before.association_token))

    def test_learning_off_registers_nothing(self) -> None:
        self.engine.set_setting("learn_unknown_eids", "off")
        self.assertIsNone(self.engine.note_detected_eid(self.STRANGER, source="the eSIM Management console"))
        self.assertIsNone(self.engine.record(self.STRANGER))

    def test_a_malformed_eid_is_refused(self) -> None:
        for bad in ("", "1234", "8904903212345123451234567890127X"):
            with self.assertRaises(ValueError, msg=bad):
                self.engine.note_detected_eid(bad, source="the eSIM Management console")


class ResultWithoutEidTests(EngineTestBase):
    """ProvideEimPackageResult without eidValue (optional, SGP.32 v1.3 §6.3.2.7), the way an IPAe sends it."""

    def test_ipa_data_result_is_placed_by_its_transaction_id(self) -> None:
        self.run_queue()
        operation_id = self.queue("IPA_EUICC_DATA")
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, operation_id)
        answer = answer_ipa_euicc_data_request(self.card.exchange, served.package, EIM_ID)
        accepted = self.engine.accept_result("", answer)
        self.assertIsNone(accepted.error)
        self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)

    def test_download_trigger_result_is_placed_by_its_transaction_id(self) -> None:
        self.run_queue()
        operation_id = self.queue("PROFILE_DOWNLOAD_TRIGGER", activation_code="1$smdpp.example.test$MID")
        served = self.engine.next_package(self.card.eid)
        # No IPA Capabilities on record yet: the eIM asks for the IPA data a download depends on, once.
        self.assertTrue(served.operation.system)
        self.assertIsNone(self.engine.accept_result(
            "", answer_ipa_euicc_data_request(self.card.exchange, served.package, EIM_ID)).error)
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, operation_id)
        transaction_id = bytes.fromhex(self.engine.operation(operation_id).transaction_id)
        # §2.11.2.3 (p.44): profileDownloadError { profileDownloadErrorReason [0] undefinedError(127) }.
        result = codec.tlv(codec.TAG_PROFILE_DOWNLOAD_TRIGGER,
                           codec.tlv(b"\x82", transaction_id) + bytes.fromhex("300380017F"))
        accepted = self.engine.accept_result("", result)
        self.assertIsNone(accepted.error)
        operation = self.engine.operation(operation_id)
        self.assertEqual(operation.state, STATE_ERROR)
        self.assertIn("127", operation.error)

    def test_unidentified_result_is_missing_eid_and_an_unknown_eid_is_eid_not_found(self) -> None:
        stray = codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", codec.tlv(b"\x87", b"\x0F" * 8)))
        self.assertEqual(self.engine.accept_result("", stray).error, codec.MISSING_EID)
        self.assertEqual(self.engine.accept_result("89049032123451234512345678901299", stray).error,
                         codec.EID_NOT_FOUND)


class ExportImportTests(EngineTestBase):
    def test_export_script_carries_the_package_and_an_imported_result_closes_it(self) -> None:
        self.run_queue()
        operation_id = self.queue("PROFILE_INFO_LIST")
        package, steps = self.engine.export(operation_id)
        blocks = [step.apdu for step in steps if step.label.startswith("STORE DATA")]
        self.assertEqual(b"".join(block[5:] for block in blocks), package)
        answer = self.card.exchange(package, "LoadEuiccPackage")
        accepted = self.engine.import_result(operation_id, answer.hex())
        self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)
        self.assertEqual(len(accepted.acknowledgements), 1)

    def test_plan_stores_nothing(self) -> None:
        entries = self.engine.plan([OperationRequest(eid=self.card.eid, type="DELETE_PROFILE",
                                                     params={"iccid": DISABLED})])
        self.assertEqual(entries[0].description, f"Delete {DISABLED}")
        self.assertEqual(self.engine.queue(self.card.eid), [])


class CodecTests(unittest.TestCase):
    def test_esipa_responses(self) -> None:
        self.assertEqual(codec.build_get_eim_package_error(1), bytes.fromhex("BF4F03020101"))
        self.assertEqual(codec.build_provide_result_response([5]), bytes.fromhex("BF5006BF5303800105"))
        self.assertEqual(codec.build_provide_result_response([]), bytes.fromhex("BF50023000"))
        self.assertEqual(codec.build_provide_result_response(error=2), bytes.fromhex("BF5003020102"))

    def test_profile_download_trigger_puts_the_data_first_and_wraps_it(self) -> None:
        request = codec.build_profile_download_trigger_request(
            activation_code="1$smdpp.example.test$MID", transaction_id=b"\x01\x02"
        )
        code = b"1$smdpp.example.test$MID"
        expected = codec.tlv(b"\xBF\x54", codec.tlv(b"\xA0", codec.tlv(b"\x80", code)) + bytes.fromhex("82020102"))
        self.assertEqual(request, expected)

    def test_decoders_refuse_short_and_overclaiming_input(self) -> None:
        decoders = (
            codec.decode_euicc_package_result,
            codec.decode_ipa_euicc_data_response,
            codec.decode_get_eim_package_request,
            codec.decode_provide_eim_package_result,
            codec.decode_profile_download_trigger_result,
            codec.decode_get_certs_response,
            codec.decode_eim_package_result,
        )
        for data in (b"", b"\x01", b"\xBF\x51", b"\xBF\x51\x05\x01"):
            for decoder in decoders:
                with self.assertRaises(ValueError, msg=f"{decoder.__name__}({data.hex()})"):
                    decoder(data)


class HandOverTests(EngineTestBase):
    def test_associate_records_the_fqdn_and_the_trust_source(self) -> None:
        record = self.engine.record(self.card.eid)
        self.assertEqual(record.eims, [{"eim_id": EIM_ID, "eim_fqdn": "eim.yggdrasim.local",
                                        "association_token": record.association_token, "tls_setup": "identity"}])
        lines = self.engine.associate(self.card.exchange, self.card.eid)
        self.assertTrue(lines[0].startswith("eimFqdn eim.yggdrasim.local (the identity); trustedPublicKeyDataTls from the identity"),
                        lines[0])

    def test_a_wildcard_setup_gives_a_card_any_local_eim_name(self) -> None:
        from SCP11.eim_local.engine import tls_setup

        identity = self.engine.identity()
        tls_setup.build_setup(self.engine.directory, identity, tls_setup.parse_options(
            "wild", {"fqdn": "eim1.yggdrasim.local", "san": "*.yggdrasim.local", "chain": "root", "trust": "root"}))
        tls_setup.build_setup(self.engine.directory, identity, tls_setup.parse_options(
            "exact", {"fqdn": "eim-other.yggdrasim.local", "chain": "root", "trust": "root"}))
        self.assertEqual(self.engine.association_configuration(setup="wild").eim_fqdn, "eim1.yggdrasim.local")
        self.assertEqual(self.engine.association_configuration(setup="wild", fqdn="EIM42.yggdrasim.local").eim_fqdn,
                         "eim42.yggdrasim.local")
        with self.assertRaisesRegex(LocalEimError, "not a Local eIM name"):
            self.engine.association_configuration(setup="wild", fqdn="eim1.operator.example.com")
        with self.assertRaisesRegex(LocalEimError, "not named by the leaf"):
            self.engine.association_configuration(setup="exact", fqdn="eim42.yggdrasim.local")
        lines = self.engine.associate(self.card.exchange, self.card.eid, setup="wild", fqdn="eim7.yggdrasim.local")
        self.assertIn("eimFqdn eim7.yggdrasim.local", lines[0])
        self.assertEqual(self.sim_entry().eim_fqdn, "eim7.yggdrasim.local")

    def test_associate_remembers_the_setup_per_card(self) -> None:
        from SCP11.eim_local.engine import tls_setup

        identity = self.engine.identity()
        tls_setup.build_setup(self.engine.directory, identity, tls_setup.parse_options(
            "other", {"fqdn": "eim-other.yggdrasim.local", "chain": "root", "trust": "root"}))
        lines = self.engine.associate(self.card.exchange, self.card.eid, setup="other")
        self.assertIn("eimFqdn eim-other.yggdrasim.local (TLS setup other)", lines[0])
        self.assertIn("remembered for this card", lines[0])
        self.assertEqual(self.engine.record(self.card.eid).data["tls_setup"], "other")
        self.assertEqual(self.sim_entry().eim_fqdn, "eim-other.yggdrasim.local")
        # No setup named: the card keeps the one it holds, whatever is in use.
        self.assertEqual(tls_setup.active_name(self.engine.directory), "")
        self.assertEqual(self.engine.association_setup(self.card.eid), "other")
        lines = self.engine.associate(self.card.exchange, self.card.eid)
        self.assertIn("(TLS setup other)", lines[0])
        # A card the eIM has not seen takes the setup in use; identity is spelled out.
        self.assertEqual(self.engine.association_setup("89049032123451234512345678901299"), "")
        tls_setup.use_setup(self.engine.directory, "other")
        self.assertEqual(self.engine.association_setup("89049032123451234512345678901299"), "other")
        lines = self.engine.associate(self.card.exchange, self.card.eid, setup="identity")
        self.assertIn("(the identity)", lines[0])
        self.assertEqual(self.engine.record(self.card.eid).data["tls_setup"], "identity")
        self.assertEqual(self.engine.association_setup(self.card.eid), "")
        with self.assertRaises(LocalEimError):
            self.engine.associate(self.card.exchange, self.card.eid, setup="no-such")

    def test_hand_over_binds_the_card_to_another_eim_and_marks_the_record_foreign(self) -> None:
        from SCP11.shared.eim_configuration_data import KEY_FORM_CERTIFICATE, EimConfigurationData, KeyData

        other = bytes.fromhex(_other_eim_certificate())
        configuration = EimConfigurationData(
            eim_id="2.999.1", eim_fqdn="eim-other.example.test", eim_id_type=1, counter_value=5, association_token=-1,
            eim_public_key_data=KeyData(form=KEY_FORM_CERTIFICATE, der=other), trusted_public_key_data_tls=None,
            eim_supported_protocol=("eimRetrieveHttps",), euicc_ci_pk_id=None, indirect_profile_download=True,
        )
        lines = self.engine.hand_over(self.card.exchange, self.card.eid, configuration, how={"sign": "OTHER-EIM"})
        self.assertTrue(any("belongs to 2.999.1" in line and "euiccPackageErrorUnsigned" in line for line in lines), lines)
        record = self.engine.record(self.card.eid)
        self.assertFalse(record.data["associated"])
        self.assertEqual(record.counter_value, 5)
        self.assertEqual(record.eims[0]["eim_id"], "2.999.1")
        self.assertTrue(record.eims[0]["foreign"])
        self.assertEqual(record.eims[0]["association_token"], record.association_token)
        self.assertEqual(record.data["handover"]["sign"], "OTHER-EIM")
        entry = next(item for item in self.card.state.eim_entries if item.eim_id == "2.999.1")
        self.assertEqual((entry.eim_fqdn, entry.counter_value), ("eim-other.example.test", 5))
        self.assertNotIn(EIM_ID, [item.eim_id for item in self.card.state.eim_entries if item.eim_id == EIM_ID
                                  and item.association_token == record.association_token])
        # ASSOCIATE puts the identity back and the record follows.
        self.engine.associate(self.card.exchange, self.card.eid)
        record = self.engine.record(self.card.eid)
        self.assertTrue(record.data["associated"])
        self.assertNotIn("handover", record.data)
        self.assertEqual(record.eims[0]["eim_id"], EIM_ID)


if __name__ == "__main__":
    unittest.main()
