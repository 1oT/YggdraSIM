# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DS engine: Event Records, ES11 and the status codes it answers with.

SGP.22 v3.1 §3.6 (Event Registration, Retrieval and Deletion), §5.8 (ES11),
§5.9 (ES12) and §5.6.1 / §5.7.13 for the Common Mutual Authentication the
SM-DS runs in the SM-DP+'s place. The eUICC side is scripted with a test PKI
(``tests.smds_support``); one class runs the simulated eUICC instead, so the
card's own checks of CERT.DSauth.SIG are part of what is proven.
"""

from __future__ import annotations

import base64
import datetime
import inspect
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import smds
from SCP11.eim_local.engine.compact import verify_euicc_signature
from SCP11.eim_local.engine.store import DATABASE_FILE, EimStore, SmdsEvent, StoreError
from SCP11.shared import es9_asn1
from SCP11.shared.ber_tlv import read_single_ber_tlv
from SCP11.shared.esipa_download import tlv
from tests.smds_support import (
    EID,
    EIN,
    OTHER_EIN,
    NOW,
    OTHER_EID,
    SMDP_ADDRESS,
    SMDS_ADDRESS,
    SMDS_OID,
    Pki,
    ScriptedEuicc,
    _members,
    _name,
    der,
    eum_constraints,
    issue,
    key_identifier,
)

INITIATE = "/gsma/rsp2/es9plus/initiateAuthentication"
AUTHENTICATE = "/gsma/rsp2/es9plus/authenticateClient"


class _Rig(unittest.TestCase):
    """A local SM-DS over a scratch store with the test PKI, and the scripted eUICC that talks to it."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.pki = Pki()

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.material = self.pki.material()
        self.now = NOW
        self.lines: list[str] = []
        self.smds = smds.LocalSmds(self.directory, material_factory=lambda: self.material, clock=lambda: self.now)
        self.smds.log = self.lines.append
        self.euicc = ScriptedEuicc(self.pki)

    def use_material(self, material: smds.SmdsMaterial) -> None:
        """Give the SM-DS other certificates than the rig's: it reads its material once."""
        self.material = material
        self.smds._material = None

    def initiate(self, **overrides: Any) -> dict[str, Any]:
        return self.smds.handle(INITIATE, self.euicc.initiate(**overrides))

    def authenticate(self, answer: dict[str, Any] | None = None, **script: Any) -> dict[str, Any]:
        answer = answer if answer is not None else self.initiate()
        return self.smds.handle(AUTHENTICATE, {
            "transactionId": answer["transactionId"],
            "authenticateServerResponse": self.euicc.respond(answer, **script).hex(),
        })

    def refused(self, call: Callable[[], Any]) -> smds.SmdsError:
        with self.assertRaises(smds.SmdsError) as caught:
            call()
        return caught.exception

    def assertRefusal(self, call: Callable[[], Any], status: smds.Status, asn1: int | None = None) -> None:
        error = self.refused(call)
        self.assertEqual(error.status, status, str(error))
        self.assertEqual(error.asn1, status.asn1 if asn1 is None else asn1, str(error))


class EventRecordTests(_Rig):
    """ES12.RegisterEvent and ES12.DeleteEvent of a Root SM-DS, called in process (SGP.22 v3.1 §5.9)."""

    def test_records_are_kept_in_the_order_registered(self) -> None:
        first = self.smds.register_event(EID, "SMDPP.Example.Test.", "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-2")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-3", event_type=smds.EVENT_TYPE_RPM)
        self.assertEqual((first.eid, first.rsp_server_address, first.event_type, first.caller),
                         (EID, SMDP_ADDRESS, smds.EVENT_TYPE_PROFILE_DOWNLOAD, SMDP_ADDRESS))
        self.assertEqual([event.event_id for event in self.smds.events()], ["EVENT-1", "EVENT-2", "EVENT-3"])
        self.assertEqual([(event.event_id, event.event_type) for event in self.smds.events(EID)],
                         [("EVENT-1", 1), ("EVENT-3", 2)])
        # the registry is the store's: another instance over the same directory reads the same records
        again = smds.LocalSmds(self.directory, material_factory=lambda: self.material)
        self.assertEqual(len(again.events()), 3)

    def test_an_event_id_is_unique_within_its_caller(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        # §5.9.1: "Verify that the EventID is not already used by the function caller."
        self.assertRefusal(lambda: self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-1"),
                           smds.EVENT_RECORD_IN_USE)
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-1")
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1", caller="2.999.10")
        self.assertEqual(len(self.smds.events(EID)), 3)

    def test_input_that_is_no_event_record_is_refused(self) -> None:
        cases: list[tuple[tuple[Any, ...], dict[str, Any], smds.Status]] = [
            (("8904903212345", SMDP_ADDRESS, "E"), {}, smds.FUNCTION_INVALID),
            ((EID, "https://smdpp.example.test/gsma", "E"), {}, smds.FUNCTION_INVALID),
            ((EID, "smdpp.example.test:8443", "E"), {}, smds.FUNCTION_INVALID),
            ((EID, "192.0.2.4", "E"), {}, smds.FUNCTION_INVALID),
            ((EID, SMDP_ADDRESS, ""), {}, smds.MANDATORY_ELEMENT_MISSING),
            ((EID, SMDP_ADDRESS, "EV 1"), {}, smds.FUNCTION_INVALID),
            ((EID, SMDP_ADDRESS, "EV$1"), {}, smds.FUNCTION_INVALID),
            ((EID, SMDP_ADDRESS, "E" * 256), {}, smds.FUNCTION_INVALID),
            ((EID, SMDP_ADDRESS, "E"), {"event_type": 3}, smds.FUNCTION_INVALID),
        ]
        for arguments, options, status in cases:
            with self.subTest(arguments=arguments, options=options):
                self.assertRefusal(lambda: self.smds.register_event(*arguments, **options), status)
        self.assertEqual(self.smds.events(), [])

    def test_every_input_of_register_event_is_taken_ignored_or_named(self) -> None:
        # SGP.22 v3.1 §5.9.1 Table 53: the ten input data names of ES12.RegisterEvent
        table = ["eid", "rspServerAddress", "eventId", "forwardingIndicator", "rootSmdsAddress", "eventType",
                 "hashedIccids", "salt", "serviceProviderName", "operatorId"]
        taken = {"eid": "eid", "rspServerAddress": "rsp_server_address", "eventId": "event_id",
                 "eventType": "event_type", "forwardingIndicator": "forwarding_indicator",
                 "rootSmdsAddress": "root_smds_address"}
        parameters = set(inspect.signature(smds.LocalSmds.register_event).parameters)
        left_out = " ".join(smds.NOT_SUPPORTED)
        for name in table:
            with self.subTest(name=name):
                if name in taken:
                    self.assertIn(taken[name], parameters)
                else:
                    self.assertIn(name, left_out)
        self.assertEqual(len(table), 10)

    def test_a_root_sm_ds_ignores_the_cascade_inputs(self) -> None:
        # §5.9.1: "A Root SM-DS SHALL ignore 'forwardingIndicator' and 'rootSmdsAddress'."
        event = self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1", forwarding_indicator=True,
                                         root_smds_address="not a host name")
        self.assertEqual(self.smds.events(), [event])

    def test_delete_takes_the_record_of_its_caller(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-1")
        # §5.9.2: the record of the Event ID and the function caller identity; none is Event Record - Unknown
        self.assertRefusal(lambda: self.smds.delete_event(EID, "EVENT-1", caller="2.999.10"),
                           smds.DELETE_EVENT_RECORD_UNKNOWN)
        self.assertRefusal(lambda: self.smds.delete_event(OTHER_EID, "EVENT-1", caller=SMDP_ADDRESS),
                           smds.DELETE_EVENT_RECORD_UNKNOWN)
        removed = self.smds.delete_event(EID, "EVENT-1", caller=SMDP_ADDRESS)
        self.assertEqual([event.rsp_server_address for event in removed], [SMDP_ADDRESS])
        self.assertEqual([event.rsp_server_address for event in self.smds.events()], ["smdp2.example.test"])

    def test_the_operator_deletes_whoever_registered(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-1")
        self.assertEqual(len(self.smds.delete_event(EID, "EVENT-1")), 2)
        self.assertRefusal(lambda: self.smds.delete_event(EID, "EVENT-1"), smds.DELETE_EVENT_RECORD_UNKNOWN)
        self.assertRefusal(lambda: self.smds.delete_event(EID, ""), smds.MANDATORY_ELEMENT_MISSING)
        self.assertRefusal(lambda: self.smds.delete_event("12", "EVENT-1"), smds.FUNCTION_INVALID)

    def test_the_registry_refuses_a_record_past_its_cap(self) -> None:
        store = EimStore(self.directory / DATABASE_FILE)
        with store.transaction() as connection:
            for number in range(2):
                store.insert_smds_event(SmdsEvent(0, "", EID, f"E{number}", SMDP_ADDRESS, 1, SMDP_ADDRESS),
                                        connection, cap=2)
        with self.assertRaises(StoreError):
            with store.transaction() as connection:
                store.insert_smds_event(SmdsEvent(0, "", EID, "E2", SMDP_ADDRESS, 1, SMDP_ADDRESS), connection, cap=2)
        # no pending record was dropped to make room
        self.assertEqual([event.event_id for event in store.smds_events()], ["E0", "E1"])

    def test_a_download_that_ended_deletes_its_record_at_that_server_only(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-2")
        # SGP.22 v3.1 §3.1.3.3 step 10: the SM-DP+ deletes the event its download came from
        self.assertEqual(self.smds.download_ended(EID, "MATCHING-ID-OF-AN-ACTIVATION-CODE", SMDP_ADDRESS), [])
        self.assertEqual(self.smds.download_ended(EID, "", SMDP_ADDRESS), [])
        removed = self.smds.download_ended(EID, "EVENT-1", "SMDPP.example.test")
        self.assertEqual([(event.eid, event.rsp_server_address) for event in removed], [(EID, SMDP_ADDRESS)])
        self.assertEqual(len(self.smds.events()), 2)


class AddressTests(_Rig):
    def test_the_address_is_a_setting_of_the_store(self) -> None:
        self.assertEqual(self.smds.address(), smds.DEFAULT_ADDRESS)
        self.assertEqual(self.smds.set_address("SMDS2.Example.Test."), "smds2.example.test")
        self.assertTrue(self.smds.owns_address("smds2.EXAMPLE.test"))
        self.assertFalse(self.smds.owns_address(smds.DEFAULT_ADDRESS))
        self.assertFalse(self.smds.owns_address(""))
        again = smds.LocalSmds(self.directory, material_factory=lambda: self.material)
        self.assertEqual(again.address(), "smds2.example.test")
        for bad in ("", "smds", "https://smds.example.test", "smds.example.test:443", "smds example.test"):
            with self.subTest(bad=bad):
                self.assertRefusal(lambda: self.smds.set_address(bad), smds.FUNCTION_INVALID)

    def test_the_oid_is_the_one_of_cert_dsauth(self) -> None:
        self.assertEqual(self.smds.oid(), SMDS_OID)


class InitiateAuthenticationTests(_Rig):
    """ES11.InitiateAuthentication (SGP.22 v3.1 §5.8.1): §5.6.1 with the SM-DS in the SM-DP+'s place."""

    def test_the_answer_is_signed_with_cert_dsauth_for_the_address_named(self) -> None:
        answer = self.initiate(smdpAddress="SMDS.Example.Test")
        signed1 = base64.b64decode(answer["serverSigned1"])
        members = _members(read_single_ber_tlv(signed1)[1])
        # ServerSigned1 of version 2: transactionId, euiccChallenge, serverAddress, serverChallenge (§5.7.13)
        self.assertEqual(sorted(members), [b"\x80", b"\x81", b"\x83", b"\x84"])
        self.assertEqual(members[b"\x80"].hex().upper(), answer["transactionId"])
        self.assertEqual(members[b"\x81"], self.euicc.challenge)
        self.assertEqual(members[b"\x83"], b"SMDS.Example.Test")
        self.assertEqual(len(members[b"\x84"]), 16)
        tag, signature, _raw = read_single_ber_tlv(base64.b64decode(answer["serverSignature1"]))
        self.assertEqual(tag, b"\x5F\x37")
        self.assertTrue(verify_euicc_signature(der(self.pki.ds), signed1, signature))
        self.assertEqual(base64.b64decode(answer["serverCertificate"]), der(self.pki.ds))
        self.assertEqual(base64.b64decode(answer["euiccCiPKIdToBeUsed"]), tlv(b"\x04", self.pki.ci_pkid))
        self.assertIsNotNone(self.smds.transaction(bytes.fromhex(answer["transactionId"])))

    def test_each_session_gets_its_own_transaction_id_and_challenge(self) -> None:
        first, second = self.initiate(), self.initiate()
        self.assertNotEqual(first["transactionId"], second["transactionId"])
        self.assertNotEqual(first["serverSigned1"], second["serverSigned1"])

    def test_open_sessions_are_bounded(self) -> None:
        first = self.initiate()
        for _ in range(smds.MAX_OPEN_TRANSACTIONS):
            self.initiate()
        self.assertIsNone(self.smds.transaction(bytes.fromhex(first["transactionId"])))
        self.assertEqual(len(self.smds._transactions), smds.MAX_OPEN_TRANSACTIONS)

    def test_the_euicc_priority_picks_among_two_esim_ca_keys(self) -> None:
        other = Pki()
        self.use_material(smds.SmdsMaterial(
            credentials=(*self.pki.material().credentials, *other.material().credentials),
            ci_certificates=(der(self.pki.ci), der(other.ci)),
        ))
        info1 = self.pki.euicc_info1(verification=(other.ci_pkid, self.pki.ci_pkid),
                                     signing=(self.pki.ci_pkid, other.ci_pkid))
        answer = self.initiate(euiccInfo1=info1.hex())
        # §5.6.1: the certificate by the eUICC's priority for verification, the signing key by its priority
        self.assertEqual(base64.b64decode(answer["serverCertificate"]), der(other.ds))
        self.assertEqual(base64.b64decode(answer["euiccCiPKIdToBeUsed"]), tlv(b"\x04", self.pki.ci_pkid))

    def test_malformed_input_is_refused_by_name(self) -> None:
        cases: list[tuple[dict[str, Any], smds.Status]] = [
            ({"euiccChallenge": ""}, smds.MANDATORY_ELEMENT_MISSING),
            ({"euiccInfo1": ""}, smds.MANDATORY_ELEMENT_MISSING),
            ({"smdpAddress": ""}, smds.MANDATORY_ELEMENT_MISSING),
            ({"euiccChallenge": "0011"}, smds.FUNCTION_INVALID),
            ({"euiccInfo1": "3000"}, smds.FUNCTION_INVALID),
            ({"euiccInfo1": "BF20"}, smds.FUNCTION_INVALID),
            ({"euiccInfo1": "BF208201"}, smds.FUNCTION_INVALID),
            ({"lpaRspCapability": "not hex or base64 !"}, smds.FUNCTION_INVALID),
        ]
        for overrides, status in cases:
            with self.subTest(overrides=overrides):
                self.assertRefusal(lambda: self.initiate(**overrides), status)

    def test_unreadable_material_is_certificate_unavailable(self) -> None:
        def failing() -> smds.SmdsMaterial:
            raise FileNotFoundError("no bundle here")

        broken = smds.LocalSmds(self.directory, material_factory=failing)
        self.assertRefusal(lambda: broken.handle(INITIATE, self.euicc.initiate()), smds.CERTIFICATE_UNAVAILABLE)
        self.assertEqual(broken.oid(), "")


class AuthenticateClientTests(_Rig):
    """ES11.AuthenticateClient (SGP.22 v3.1 §5.8.2) and the Event Retrieval of §3.6.2."""

    def setUp(self) -> None:
        super().setUp()
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-OTHER")
        self.smds.register_event(EID, "smdp2.example.test", "EVENT-2")
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-RPM", event_type=smds.EVENT_TYPE_RPM)

    def test_the_records_of_the_euicc_come_back_in_the_order_registered(self) -> None:
        answer = self.initiate()
        result = self.authenticate(answer)
        # §3.6.2 step 8: TransactionID and unsigned Event Records, ordered as registered; operationType
        # absent is a Profile download request (§5.8.2), so the RPM record stays out
        self.assertEqual(result, {"transactionId": answer["transactionId"], "eventEntries": [
            {"eventId": "EVENT-1", "rspServerAddress": SMDP_ADDRESS},
            {"eventId": "EVENT-2", "rspServerAddress": "smdp2.example.test"},
        ]})
        self.assertTrue(any("2 Event Record(s)" in line for line in self.lines), self.lines)

    def test_no_record_is_an_empty_list(self) -> None:
        self.smds.delete_event(EID, "EVENT-1")
        self.smds.delete_event(EID, "EVENT-2")
        self.assertEqual(self.authenticate()["eventEntries"], [])

    def test_an_event_id_asks_for_that_record(self) -> None:
        self.assertEqual(self.authenticate(matching_id="EVENT-2")["eventEntries"],
                         [{"eventId": "EVENT-2", "rspServerAddress": "smdp2.example.test"}])
        # an empty matchingId is the missing one (§5.8.2)
        self.assertEqual(len(self.authenticate(matching_id="")["eventEntries"]), 2)

    def test_the_operation_type_picks_the_event_type(self) -> None:
        # OperationType ::= BIT STRING { profileDownload(0), rpm(1) } (§5.7.13)
        rpm = self.authenticate(operation_type=bytes.fromhex("0640"))
        self.assertEqual([entry["eventId"] for entry in rpm["eventEntries"]], ["EVENT-RPM"])
        download = self.authenticate(operation_type=bytes.fromhex("0780"))
        self.assertEqual([entry["eventId"] for entry in download["eventEntries"]], ["EVENT-1", "EVENT-2"])
        both = self.authenticate(operation_type=bytes.fromhex("06C0"))
        self.assertEqual(len(both["eventEntries"]), 3)

    def test_the_rsp_session_ends_with_the_answer(self) -> None:
        answer = self.initiate()
        self.authenticate(answer)
        self.assertIsNone(self.smds.transaction(bytes.fromhex(answer["transactionId"])))
        self.assertRefusal(lambda: self.authenticate(answer), smds.TRANSACTION_ID_UNKNOWN)

    def test_a_refused_session_ends_too(self) -> None:
        answer = self.initiate()
        self.assertRefusal(lambda: self.authenticate(answer, matching_id="NO-SUCH-EVENT"), smds.EVENT_RECORD_UNKNOWN)
        self.assertRefusal(lambda: self.authenticate(answer), smds.TRANSACTION_ID_UNKNOWN)

    def test_the_euicc_is_named_by_its_certificate_not_by_the_caller(self) -> None:
        other = Pki(eid=OTHER_EID)
        # the same eSIM CA: the other eUICC's chain is issued under this rig's root
        other.ci, other.ci_key = self.pki.ci, self.pki.ci_key
        other.eum = other.eum_certificate()
        other.euicc = other.euicc_certificate()
        answer = self.initiate()
        response = ScriptedEuicc(other).respond(answer)
        result = self.smds.handle(AUTHENTICATE, {"transactionId": answer["transactionId"],
                                                 "authenticateServerResponse": response.hex()})
        self.assertEqual([entry["eventId"] for entry in result["eventEntries"]], ["EVENT-OTHER"])

    def test_a_chain_through_other_certs_in_chain_is_followed(self) -> None:
        sub_key = ec.generate_private_key(ec.SECP256R1())
        sub = issue(_name("Test EUM SubCA", organization="RSP Test EUM"), sub_key,
                    (self.pki.eum, self.pki.eum_key), ca=True)
        euicc = issue(_name("Test eUICC", organization="RSP Test EUM", serial_number=EID), self.pki.euicc_key,
                      (sub, sub_key))
        # AuthenticateResponseOk: euiccCertificate, nextCertInChain, otherCertsInChain (§5.7.13)
        result = self.authenticate(certificates=(der(euicc), der(sub)), other_certificates=(der(self.pki.eum),))
        self.assertEqual(len(result["eventEntries"]), 2)

    def test_certificates_that_declare_their_roles_pass(self) -> None:
        # id-rspRole-euicc-v2 {id-rspRole 1} and id-rspRole-eum-v2 {id-rspRole 2}: a Variant O chain (§2.4a.1.0)
        def role(oid: str) -> tuple[Any, bool]:
            return (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(oid), None)]), True)

        eum = self.pki.eum_certificate(extensions=(eum_constraints(), role("2.23.146.1.2.1.2")))
        euicc = self.pki.euicc_certificate(eum=eum, extensions=(role("2.23.146.1.2.1.1"),))
        self.assertEqual(len(self.authenticate(certificates=(der(euicc), der(eum)))["eventEntries"]), 2)

    def test_an_eum_certificate_without_constraints_permits_any_eid(self) -> None:
        eum = self.pki.eum_certificate(extensions=())
        euicc = self.pki.euicc_certificate(eum=eum)
        self.assertEqual(len(self.authenticate(certificates=(der(euicc), der(eum)))["eventEntries"]), 2)

    def test_the_permitted_eins_extension_is_read_for_the_other_chain_variants(self) -> None:
        # id-rsp-extension-permitted-eins, PermittedEins ::= SEQUENCE OF PrintableString (SGP.22 v3.1 Table 12)
        def eins(*values: str) -> tuple[Any, bool]:
            body = b"".join(tlv(b"\x13", value.encode("ascii")) for value in values)
            return (x509.UnrecognizedExtension(x509.ObjectIdentifier("2.23.146.1.2.2.0"), tlv(b"\x30", body)), False)

        permitted = self.pki.eum_certificate(extensions=(eins(OTHER_EIN, EIN),))
        euicc = self.pki.euicc_certificate(eum=permitted)
        self.assertEqual(len(self.authenticate(certificates=(der(euicc), der(permitted)))["eventEntries"]), 2)
        other = self.pki.eum_certificate(extensions=(eins(OTHER_EIN),))
        euicc = self.pki.euicc_certificate(eum=other)
        self.assertRefusal(lambda: self.authenticate(certificates=(der(euicc), der(other))),
                           smds.CERTIFICATE_VERIFICATION_FAILED)

    def test_matching_capabilities_pass(self) -> None:
        # EuiccRspCapability with euiccRspCapInInfo1 (bit 18) set, the same in euiccInfo1 and euiccInfo2
        capability = bytes.fromhex("05000020")
        answer = self.initiate(euiccInfo1=self.pki.euicc_info1(capability=capability).hex(),
                               lpaRspCapability=tlv(b"\x85", bytes.fromhex("0204")).hex())
        result = self.authenticate(answer, euicc_rsp_capability=capability, lpa_rsp_capability=bytes.fromhex("0204"))
        self.assertEqual(len(result["eventEntries"]), 2)
        # a capability without the bit is not compared (§5.8.2: "If ... euiccRspCapInInfo1 is set to '1'")
        self.assertEqual(len(self.authenticate(euicc_rsp_capability=bytes.fromhex("0780"))["eventEntries"]), 2)


class RefusalTests(_Rig):
    """Every row of the status code tables the SM-DS answers with, and the ASN.1 value beside it."""

    def setUp(self) -> None:
        super().setUp()
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")

    # -- what makes each row happen ---------------------------------------

    def _other_ci_chain(self) -> tuple[bytes, bytes]:
        other = Pki()
        return der(other.euicc), der(other.eum)

    def _second_trusted_ci(self) -> Pki:
        second = Pki()
        self.use_material(smds.SmdsMaterial(credentials=self.pki.material().credentials,
                                            ci_certificates=(der(self.pki.ci), der(second.ci))))
        return second

    def _expired(self, what: str) -> tuple[bytes, bytes]:
        window = {"not_before": NOW - datetime.timedelta(days=30), "not_after": NOW - datetime.timedelta(days=1)}
        eum = self.pki.eum_certificate(**window) if what == "eum" else self.pki.eum
        euicc = self.pki.euicc_certificate(eum=eum, **(window if what == "euicc" else {}))
        return der(euicc), der(eum)

    def _not_yet_valid(self) -> tuple[bytes, bytes]:
        euicc = self.pki.euicc_certificate(not_before=NOW + datetime.timedelta(days=1),
                                           not_after=NOW + datetime.timedelta(days=30))
        return der(euicc), der(self.pki.eum)

    def _forged_euicc_certificate(self) -> tuple[bytes, bytes]:
        subject = _name("Test eUICC", organization="RSP Test EUM", serial_number=EID)
        forged = issue(subject, self.pki.euicc_key, (self.pki.eum, ec.generate_private_key(ec.SECP256R1())))
        return der(forged), der(self.pki.eum)

    def _forged_eum_certificate(self) -> tuple[bytes, bytes]:
        eum = issue(_name("Test EUM", organization="RSP Test EUM"), self.pki.eum_key,
                    (self.pki.ci, ec.generate_private_key(ec.SECP256R1())), ca=True, extensions=(eum_constraints(),))
        return der(self.pki.euicc_certificate(eum=eum)), der(eum)

    @staticmethod
    def _role(oid: str) -> tuple[Any, bool]:
        return (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(oid), None)]), True)

    def _euicc_with_a_server_role(self) -> tuple[bytes, bytes]:
        # id-rspRole-dp-auth-v2 {id-rspRole 4} on a certificate presented as the eUICC's
        return der(self.pki.euicc_certificate(extensions=(self._role("2.23.146.1.2.1.4"),))), der(self.pki.eum)

    def _eum_with_a_euicc_role(self) -> tuple[bytes, bytes]:
        # id-rspRole-euicc-v2 {id-rspRole 1} on the certificate certifying the eUICC's
        eum = self.pki.eum_certificate(extensions=(eum_constraints(), self._role("2.23.146.1.2.1.1")))
        return der(self.pki.euicc_certificate(eum=eum)), der(eum)

    def _euicc_key_not_for_signatures(self) -> tuple[bytes, bytes]:
        usage = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                              data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                              encipher_only=False, decipher_only=False)
        subject = _name("Test eUICC", organization="RSP Test EUM", serial_number=EID)
        now = NOW
        certificate = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(self.pki.eum.subject)
            .public_key(self.pki.euicc_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.pki.eum.public_key()), critical=False)
            .add_extension(usage, critical=True)
            .sign(self.pki.eum_key, hashes.SHA256())
        )
        return der(certificate), der(self.pki.eum)

    def _eid_outside_the_eins_of_the_eum(self) -> tuple[bytes, bytes]:
        eum = self.pki.eum_certificate(extensions=(eum_constraints(ein=OTHER_EIN),))
        return der(self.pki.euicc_certificate(eum=eum)), der(eum)

    def _eid_outside_the_eins_above_a_sub_ca(self) -> dict[str, Any]:
        # the EUM permits another EIN; its SubCA, which issued the eUICC certificate, names none
        eum = self.pki.eum_certificate(extensions=(eum_constraints(ein=OTHER_EIN),))
        sub_key = ec.generate_private_key(ec.SECP256R1())
        sub = issue(_name("Test EUM SubCA", organization="RSP Test EUM"), sub_key, (eum, self.pki.eum_key), ca=True)
        euicc = issue(_name("Test eUICC", organization="RSP Test EUM", serial_number=EID), self.pki.euicc_key,
                      (sub, sub_key))
        return {"certificates": (der(euicc), der(sub)), "other_certificates": (der(eum),)}

    def _eum_that_is_no_ca(self) -> tuple[bytes, bytes]:
        eum = issue(_name("Test EUM", organization="RSP Test EUM"), self.pki.eum_key, (self.pki.ci, self.pki.ci_key))
        return der(self.pki.euicc_certificate(eum=eum)), der(eum)

    def _rows(self) -> list[tuple[smds.Status, int | None, Callable[[], Any]]]:
        """(status row, ASN.1 value, what makes the SM-DS answer it)."""
        second = Pki()
        return [
            # ES11.InitiateAuthentication, Table 48a
            (smds.ADDRESS_REFUSED, 1, lambda: self.initiate(smdpAddress="other.example.test")),
            (smds.SECURITY_CONFIGURATION_UNSUPPORTED, 3,
             lambda: self.initiate(euiccInfo1=self.pki.euicc_info1(signing=(second.ci_pkid,)).hex())),
            (smds.CERTIFICATE_UNAVAILABLE, 3,
             lambda: self.initiate(euiccInfo1=self.pki.euicc_info1(verification=(second.ci_pkid,)).hex())),
            # ES11.AuthenticateClient, Table 52
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=self._forged_euicc_certificate())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3, lambda: self.authenticate(certificates=self._not_yet_valid())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=self._eid_outside_the_eins_of_the_eum())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=(der(self.pki.euicc_certificate(organization="Another EUM")),
                                                     der(self.pki.eum)))),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=(der(self.pki.euicc_certificate(eid="")), der(self.pki.eum)))),
            (smds.CERTIFICATE_VERIFICATION_FAILED, smds.ASN1_EUM_CERTIFICATE_INVALID,
             lambda: self.authenticate(certificates=(der(self.pki.euicc), der(second.eum)))),
            (smds.CERTIFICATE_VERIFICATION_FAILED, smds.ASN1_EUM_CERTIFICATE_INVALID,
             lambda: self.authenticate(certificates=self._forged_eum_certificate())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, smds.ASN1_EUM_CERTIFICATE_INVALID,
             lambda: self.authenticate(certificates=self._eum_that_is_no_ca())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=self._euicc_with_a_server_role())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, smds.ASN1_EUM_CERTIFICATE_INVALID,
             lambda: self.authenticate(certificates=self._eum_with_a_euicc_role())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(certificates=self._euicc_key_not_for_signatures())),
            (smds.CERTIFICATE_VERIFICATION_FAILED, 3,
             lambda: self.authenticate(**self._eid_outside_the_eins_above_a_sub_ca())),
            (smds.CERTIFICATE_EXPIRED, 4, lambda: self.authenticate(certificates=self._expired("euicc"))),
            (smds.CERTIFICATE_EXPIRED, smds.ASN1_EUM_CERTIFICATE_EXPIRED,
             lambda: self.authenticate(certificates=self._expired("eum"))),
            (smds.EUICC_VERIFICATION_FAILED, 5,
             lambda: self.authenticate(signing_key=ec.generate_private_key(ec.SECP256R1()))),
            (smds.EUICC_VERIFICATION_FAILED, 5, lambda: self.authenticate(server_challenge=b"\x00" * 16)),
            (smds.EUICC_VERIFICATION_FAILED, 5, lambda: self.authenticate(transaction_id=b"\x00" * 16)),
            (smds.TRANSACTION_ID_UNKNOWN, 7,
             lambda: self.smds.handle(AUTHENTICATE, {"transactionId": "AB" * 16,
                                                     "authenticateServerResponse": "BF3800"})),
            (smds.CI_PUBLIC_KEY_UNKNOWN, 8, lambda: self.authenticate(certificates=self._other_ci_chain())),
            (smds.CI_PUBLIC_KEY_UNKNOWN, smds.ASN1_CI_PK_MISMATCH,
             lambda: self.authenticate(certificates=(lambda pki: (der(pki.euicc), der(pki.eum)))(
                 self._second_trusted_ci()))),
            (smds.EVENT_RECORD_UNKNOWN, 6, lambda: self.authenticate(matching_id="NO-SUCH-EVENT")),
            (smds.EUICC_VALUE_HAS_CHANGED, 10,
             lambda: self.authenticate(euicc_rsp_capability=bytes.fromhex("05000020"))),
            (smds.LPA_VALUE_HAS_CHANGED, 11,
             lambda: self.authenticate(self.initiate(lpaRspCapability=tlv(b"\x85", bytes.fromhex("0204")).hex()),
                                       lpa_rsp_capability=bytes.fromhex("0780"))),
            (smds.LPA_VALUE_HAS_CHANGED, 11,
             lambda: self.authenticate(self.initiate(lpaRspCapability="0204"))),
            (smds.PUSH_SERVICE_UNSUPPORTED, 12,
             lambda: self.authenticate(ctx_params1=tlv(b"\xA3", tlv(b"\x80", bytes.fromhex("883703")) + tlv(b"\x81", b"t")))),
            (smds.FUNCTION_UNSUPPORTED, 127,
             lambda: self.authenticate(ctx_params1=tlv(b"\xA1", tlv(b"\x5A", b"\x98" * 10)))),
            # ES11.CheckEvent, Table 52c
            (smds.EVENT_CHECKING_UNSUPPORTED, 2, lambda: self.smds.check_event(b"\x00" * 16, SMDS_ADDRESS)),
            # ES12.RegisterEvent and ES12.DeleteEvent, Tables 54 and 56
            (smds.EVENT_RECORD_IN_USE, None, lambda: self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")),
            (smds.DELETE_EVENT_RECORD_UNKNOWN, None, lambda: self.smds.delete_event(EID, "NO-SUCH-EVENT")),
            # the common status codes, SGP.02 v4.2 Table 117
            (smds.FUNCTION_INVALID, 124, lambda: self.initiate(euiccChallenge="0011")),
            (smds.FUNCTION_INVALID, 124,
             lambda: self.smds.handle(AUTHENTICATE, {"transactionId": self.initiate()["transactionId"],
                                                     "authenticateServerResponse": "BF3803A10100"})),
            (smds.MANDATORY_ELEMENT_MISSING, 125, lambda: self.initiate(smdpAddress="")),
            (smds.EXECUTION_ERROR, 127, self._registry_at_its_cap),
        ]

    def _registry_at_its_cap(self) -> None:
        original = EimStore.insert_smds_event

        def capped(store: EimStore, event: SmdsEvent, connection: Any, cap: int = 1) -> int:
            return original(store, event, connection, cap=1)

        EimStore.insert_smds_event = capped  # type: ignore[method-assign]
        try:
            self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-PAST-THE-CAP")
        finally:
            EimStore.insert_smds_event = original  # type: ignore[method-assign]

    def test_each_row_is_answered_with_its_status_and_asn1_value(self) -> None:
        for status, asn1, trigger in self._rows():
            with self.subTest(row=f"{status.function} {status.subject_code}/{status.reason_code}", asn1=asn1):
                # every row starts from the rig's own material and one record
                self.use_material(self.pki.material())
                error = self.refused(trigger)
                self.assertEqual(error.status, status, str(error))
                self.assertEqual(error.asn1, asn1, str(error))
                header = error.header()["functionExecutionStatus"]
                self.assertEqual(header["status"], "Failed")
                self.assertEqual((header["statusCodeData"]["subjectCode"], header["statusCodeData"]["reasonCode"]),
                                 (status.subject_code, status.reason_code))

    def test_every_row_of_the_tables_is_answered_or_named_as_never_returned(self) -> None:
        # The rows as SGP.22 v3.1 prints them: (subject code, reason code, subject, reason).
        tables = {
            "InitiateAuthentication": [  # §5.8.1 Table 48a
                ("8.9.1", "3.8", "SM-DS Address", "Refused"),
                ("8.9.2", "3.1", "Security configuration", "Unsupported"),
                ("8.9.4", "3.7", "SM-DS Certificate", "Unavailable"),
            ],
            "AuthenticateClient": [  # §5.8.2 Table 52
                ("8.1.3", "6.1", "eUICC Certificate", "Verification Failed"),
                ("8.1.3", "6.3", "eUICC Certificate", "Expired"),
                ("8.1", "6.1", "eUICC", "Verification Failed"),
                ("8.10.1", "3.9", "TransactionId", "Unknown"),
                ("8.11.1", "3.9", "CI Public Key", "Unknown"),
                ("8.9.5", "3.9", "Event Record", "Unknown"),
                ("8.1", "3.11", "eUICC", "Value has Changed"),
                ("8.12", "3.11", "LPA", "Value has Changed"),
                ("8.9.7", "3.1", "Push Service", "Unsupported"),
                ("8.10.6", "3.1", "Push Service Registration", "Unsupported"),
                ("8.10.6", "3.12", "Push Service Registration", "Invalid Match"),
                ("1.6", "3.1", "Function", "Unsupported"),
            ],
            "CheckEvent": [  # §5.8.3 Table 52c
                ("8.10.4", "3.1", "Event Checking", "Unsupported"),
                ("8.9.6", "6.3", "ECID", "Expired"),
                ("8.9.6", "3.9", "ECID", "Unknown"),
                ("8.9.1", "3.8", "SM-DS Address", "Refused"),
            ],
            "RegisterEvent": [  # §5.9.1 Table 54
                ("8.9.5", "3.3", "Event Record", "Already in Use"),
                ("8.9", "5.1", "SM-DS", "Inaccessible"),
                ("8.9", "4.2", "SM-DS", "Execution Error"),
            ],
            "DeleteEvent": [  # §5.9.2 Table 56
                ("8.9.5", "3.9", "Event Record", "Unknown"),
                ("8.9", "5.1", "SM-DS", "Inaccessible"),
                ("8.9", "4.2", "SM-DS", "Execution Error"),
            ],
            # SGP.02 v4.2 §5.1.6.4 Table 117 without the two Function Requester rows and the Validity
            # Period one, which SGP.22 v3.1 §6.6.1.1 calls not relevant on ES9+ and ES11
            "common": [
                ("1.6", "2.1", "Function", "Invalid"),
                ("1.6", "2.2", "Function", "Mandatory Element Missing"),
                ("1.6", "2.3", "Function", "Conditional Element Missing"),
                ("1.2", "4.4", "Function Provider", "Busy"),
                ("1.2", "4.2", "Function Provider", "Execution Error"),
            ],
        }
        declared = {
            "InitiateAuthentication": smds.INITIATE_AUTHENTICATION_STATUS,
            "AuthenticateClient": smds.AUTHENTICATE_CLIENT_STATUS, "CheckEvent": smds.CHECK_EVENT_STATUS,
            "RegisterEvent": smds.REGISTER_EVENT_STATUS, "DeleteEvent": smds.DELETE_EVENT_STATUS,
            "common": smds.COMMON_STATUS,
        }
        for function, rows in tables.items():
            with self.subTest(function=function):
                self.assertEqual([(row.subject_code, row.reason_code, row.subject, row.reason)
                                  for row in declared[function]], rows)
                self.assertTrue(all(row.function == function for row in declared[function]))
        every = {row for rows in declared.values() for row in rows}
        answered = {status for status, _asn1, _trigger in self._rows()}
        never = set(smds.STATUS_NEVER_RETURNED)
        self.assertEqual(answered | never, every)
        self.assertEqual(answered & never, set())
        self.assertEqual(len(every), 30)

    def test_every_asn1_error_value_is_answered_or_named_as_never_returned(self) -> None:
        enumerations = {
            "InitiateAuthentication": es9_asn1.INITIATE_AUTHENTICATION_ERRORS,
            "AuthenticateClient": es9_asn1.ES11_AUTHENTICATE_CLIENT_ERRORS,
            "CheckEvent": es9_asn1.CHECK_EVENT_ERRORS,
        }
        # SGP.22 v3.1 §6.6.2.1, §6.6.2.7 and §6.6.2.8, each list whole
        self.assertEqual(enumerations["InitiateAuthentication"], {
            1: "invalidDpAddress", 2: "euiccVersionNotSupportedByDp", 3: "ciPKIdNotSupported",
            124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError"})
        self.assertEqual(enumerations["AuthenticateClient"], {
            1: "eumCertificateInvalid", 2: "eumCertificateExpired", 3: "euiccCertificateInvalid",
            4: "euiccCertificateExpired", 5: "euiccSignatureInvalid", 6: "eventIdUnknown", 7: "invalidTransactionId",
            8: "ciPKUnknown", 9: "ciPKMismatch", 10: "euiccRspCapabilityHasChanged",
            11: "lpaRspCapabilityHasChanged", 12: "pushServiceNotSupport",
            13: "pushServiceRegistrationNotSupported", 124: "invalidInputData", 125: "missingInputData",
            126: "functionProviderBusy", 127: "undefinedError"})
        self.assertEqual(enumerations["CheckEvent"], {
            1: "invalidDsAddress", 2: "eventCheckingNotSupported", 3: "expiredEcid", 4: "unknownEcid",
            124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError"})
        answered: dict[str, set[int]] = {name: set() for name in enumerations}
        for status, asn1, _trigger in self._rows():
            if asn1 is None:
                continue
            functions = [status.function] if status.function in answered else ["InitiateAuthentication",
                                                                              "AuthenticateClient"]
            for function in functions:
                answered[function].add(asn1)
        # a missing input of AuthenticateClient, and what the binding answers when a step fails outside the tables
        self.assertRefusal(lambda: self.smds.handle(AUTHENTICATE, {"transactionId": ""}),
                           smds.MANDATORY_ELEMENT_MISSING)
        answered["AuthenticateClient"].add(125)
        answered["InitiateAuthentication"].add(127)
        for function, values in enumerations.items():
            never = {value for name, value in smds.ASN1_NEVER_RETURNED if name == function}
            with self.subTest(function=function):
                self.assertEqual(answered[function] & set(values) | never, set(values))
                self.assertEqual(answered[function] & never, set())

    def test_what_is_left_out_is_named(self) -> None:
        self.assertEqual(len(smds.NOT_SUPPORTED), 12)
        for feature, instead in smds.NOT_SUPPORTED.items():
            self.assertTrue(feature and instead)


class DecodeBoundaryTests(_Rig):
    """Input that is no data object at all: empty, one octet, a cut header, a length past the end."""

    BROKEN = (b"", b"\xBF", b"\xBF\x38", b"\xBF\x38\x82", b"\xBF\x38\x82\x05\x5E\xA0\x00", b"\xBF\x38\x05\xA0\x10\x30")

    def test_an_authenticate_server_response_that_does_not_read_is_function_invalid(self) -> None:
        for broken in self.BROKEN[1:]:
            with self.subTest(broken=broken.hex()):
                answer = self.initiate()
                self.assertRefusal(lambda: self.smds.handle(AUTHENTICATE, {
                    "transactionId": answer["transactionId"], "authenticateServerResponse": broken.hex()}),
                    smds.FUNCTION_INVALID)
        answer = self.initiate()
        self.assertRefusal(lambda: self.smds.handle(AUTHENTICATE, {
            "transactionId": answer["transactionId"], "authenticateServerResponse": ""}),
            smds.MANDATORY_ELEMENT_MISSING)

    def test_a_key_identifier_list_that_does_not_read_raises_value_error(self) -> None:
        for broken in (b"", b"\xBF", b"\xBF\x20", b"\xBF\x20\x82", b"\xBF\x20\x05\xA9\x10\x04", b"\x30\x00"):
            with self.subTest(broken=broken.hex()):
                with self.assertRaises((ValueError, IndexError)):
                    smds.key_identifier_list(broken, b"\xA9")
        self.assertEqual(smds.key_identifier_list(bytes.fromhex("BF2000"), b"\xA9"), [])

    def test_certificates_that_do_not_parse_fail_the_chain(self) -> None:
        roots = {self.pki.ci_pkid: der(self.pki.ci)}
        for chain in ([], [b""], [b"\x30"], [b"\x30\x82\x05", der(self.pki.eum)], [der(self.pki.euicc), b"\x30\x03\x02\x01"]):
            with self.subTest(chain=[item.hex()[:12] for item in chain]):
                error = self.refused(lambda: smds.verify_euicc_chain(chain, roots, NOW))
                self.assertEqual(error.status, smds.CERTIFICATE_VERIFICATION_FAILED)
        self.assertEqual(smds.verify_euicc_chain([der(self.pki.euicc), der(self.pki.eum)], roots, NOW),
                         (self.pki.ci_pkid, EID))


class SimulatedEuiccTests(unittest.TestCase):
    """The Common Mutual Authentication with the simulated eUICC: the card checks CERT.DSauth.SIG itself."""

    def setUp(self) -> None:
        from SIMCARD.etsi_fs import build_default_state
        from SIMCARD.sgp import SgpLogic

        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.pki = Pki()
        material = self.pki.material()
        self.smds = smds.LocalSmds(Path(folder.name), material_factory=lambda: material)
        self.state = build_default_state()
        self.state.eid = EID
        self.state.ci_certificates = [der(self.pki.ci)]
        self.state.root_ci_pkid = self.pki.ci_pkid
        self.logic = SgpLogic(self.state)
        self.logic._euicc_private_key = self.pki.euicc_key
        self.state.euicc_certificate_der = der(self.pki.euicc)
        self.state.eum_certificate_der = der(self.pki.eum)

    def card(self, command: bytes) -> bytes:
        response, sw1, sw2 = self.logic.handle_store_data(command)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response

    def authenticate_server(self, answer: dict[str, Any]) -> bytes:
        # ctxParamsForCommonAuthentication { deviceInfo { tac, deviceCapabilities } }, no matchingId
        ctx_params1 = tlv(b"\xA0", tlv(b"\xA1", tlv(b"\x80", bytes.fromhex("35290611")) + tlv(b"\xA1", b"")))
        return self.card(tlv(b"\xBF\x38", b"".join(base64.b64decode(answer[name]) for name in (
            "serverSigned1", "serverSignature1", "euiccCiPKIdToBeUsed", "serverCertificate")) + ctx_params1))

    def initiate(self) -> dict[str, Any]:
        info1 = self.card(bytes.fromhex("BF2000"))
        challenge = read_single_ber_tlv(read_single_ber_tlv(self.card(bytes.fromhex("BF2E00")))[1])[1]
        return self.smds.handle(INITIATE, {"euiccChallenge": challenge.hex(), "euiccInfo1": info1.hex(),
                                           "smdpAddress": SMDS_ADDRESS})

    def test_the_card_and_the_sm_ds_authenticate_each_other(self) -> None:
        self.smds.register_event(EID, SMDP_ADDRESS, "EVENT-1")
        self.smds.register_event(OTHER_EID, SMDP_ADDRESS, "EVENT-OTHER")
        answer = self.initiate()
        response = self.authenticate_server(answer)
        self.assertEqual(response[:2], b"\xBF\x38")
        self.assertEqual(read_single_ber_tlv(response)[1][:1], b"\xA0", response.hex()[:40])
        result = self.smds.handle(AUTHENTICATE, {"transactionId": answer["transactionId"],
                                                 "authenticateServerResponse": response.hex()})
        self.assertEqual(result["eventEntries"], [{"eventId": "EVENT-1", "rspServerAddress": SMDP_ADDRESS}])

    def test_the_card_refuses_a_cert_dsauth_its_esim_ca_did_not_issue(self) -> None:
        stranger = Pki()
        answer = self.initiate()
        answer["serverCertificate"] = base64.b64encode(der(stranger.ds)).decode("ascii")
        response = self.authenticate_server(answer)
        # authenticateResponseError 'A1' (SGP.22 v3.1 §5.7.13)
        self.assertEqual(read_single_ber_tlv(response)[1][:1], b"\xA1", response.hex()[:40])


class Sgp26BundleChainTests(unittest.TestCase):
    """The eUICC certificates the SGP.26 bundle itself carries: the chain a real test eUICC presents."""

    def test_the_variant_o_euicc_chain_of_the_bundle_verifies(self) -> None:
        from tests.sgp26_support import SGP26_VALID_ROOT

        variant = SGP26_VALID_ROOT / "Variant O"
        verified = []
        for curve in ("NIST", "BRP"):
            paths = (variant / "CI" / f"CERT_CI_SIG_{curve}.der", variant / "eUICC" / f"CERT_EUICC_SIG_{curve}.der",
                     variant / "EUM" / f"CERT_EUM_SIG_{curve}.der")
            if not all(path.is_file() for path in paths):
                continue
            try:
                root = x509.load_der_x509_certificate(paths[0].read_bytes())
                chain = [der(x509.load_der_x509_certificate(path.read_bytes())) for path in paths[1:]]
            except ValueError:
                # a file kept encrypted at rest is not this test's to open
                continue
            pkid, eid = smds.verify_euicc_chain(chain, {key_identifier(root): der(root)}, NOW)
            self.assertEqual(pkid, key_identifier(root))
            # SGP.26 v3.0.2 section 3.2.1 Table 5: the EID of the test eUICC
            self.assertEqual(eid, EID)
            verified.append(curve)
        if not verified:
            self.skipTest("the SGP.26 bundle holds no readable Variant O eUICC chain here")


class PkiSanityTests(unittest.TestCase):
    def test_the_test_chain_is_shaped_like_a_variant_o_one(self) -> None:
        pki = Pki()
        self.assertEqual(key_identifier(pki.ci), pki.ci_pkid)
        self.assertEqual(pki.euicc.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value, EID)
        self.assertTrue(smds.eid_permitted(pki.euicc, pki.eum, EID))
        narrower = pki.eum_certificate(extensions=(eum_constraints(ein=OTHER_EIN),))
        self.assertFalse(smds.eid_permitted(pki.euicc, narrower, EID))
        loose = pki.eum_certificate(extensions=(eum_constraints(ein=""),))
        self.assertTrue(smds.eid_permitted(pki.euicc, loose, EID))
        self.assertFalse(EID.startswith(OTHER_EIN))


if __name__ == "__main__":
    unittest.main()
