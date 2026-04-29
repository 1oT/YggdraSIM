"""ES10b.LoadEuiccPackage (SGP.32 v1.2 §5.9.1) coverage.

The eUICC verification ladder is exercised end-to-end:

- Unknown ``eimId`` and bad ``5F37`` signature → ``A2`` unsigned error.
- ``eidValue`` mismatch → ``A1`` signed error with ``invalidEid(3)``.
- Stale ``counterValue`` / over-range counter → ``A1`` signed error.
- PSMO / eCO inner batches execute sequentially and emit a signed
  ``A0`` ``euiccPackageResultSigned`` whose ``seqNumber [3]`` is
  recoverable through ``BF2B`` / ``BF30``.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.sgp32_packages import (
    encode_der_integer,
    encode_euicc_package_result_signed,
    package_result_seq_number,
    signature_payload,
)
from SIMCARD.state import SimCardState, SimEimEntry
from SIMCARD.utils import encode_iccid_ef, find_first_tlv, read_tlv, tlv


def _build_state_with_test_eim() -> tuple[SimCardState, ec.EllipticCurvePrivateKey, str]:
    state = build_default_state()
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    eim_id = "test-eim.cold-start.local"
    state.eim_entries = [
        SimEimEntry(
            eim_id=eim_id,
            eim_fqdn="cold-start.local",
            eim_id_type=2,
            counter_value=0,
            association_token=0,
            supported_protocol_bits=[0, 2],
            euicc_ci_pkid=bytes(state.root_ci_pkid),
            indirect_profile_download=True,
            eim_public_key_data=public_spki,
            trusted_tls_public_key_data=public_spki,
        )
    ]
    return state, private_key, eim_id


def _sign_euicc_package(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    eim_id: str,
    eid_hex: str,
    counter_value: int,
    inner_choice_tag: bytes,
    inner_items: bytes,
    eim_transaction_id: bytes = b"",
    association_token: int = 0,
) -> bytes:
    """Build a complete, signed ``BF51 EuiccPackageRequest``."""

    body = b""
    body += tlv(b"\x80", eim_id.encode("utf-8"))
    body += tlv(b"\x5A", bytes.fromhex(eid_hex))
    body += tlv(b"\x81", encode_der_integer(int(counter_value)))
    if len(eim_transaction_id) > 0:
        body += tlv(b"\x82", bytes(eim_transaction_id))
    body += tlv(inner_choice_tag, inner_items)
    signed_blob = tlv(b"\x30", body)
    payload = signature_payload(signed_blob, association_token)
    signature_der = private_key.sign(
        payload,
        ec.ECDSA(__import__("cryptography").hazmat.primitives.hashes.SHA256()),
    )
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    r_value, s_value = asym_utils.decode_dss_signature(signature_der)
    raw_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    return tlv(b"\xBF\x51", signed_blob + tlv(b"\x5F\x37", raw_signature))


class _Sgp32TestBase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.state, self.eim_key, self.eim_id = _build_state_with_test_eim()
        self.state.next_notification_seq = 1
        self.logic = SgpLogic(self.state)

    def _peel_outer(self, response: bytes) -> tuple[bytes, bytes]:
        tag, value, _raw, _next = read_tlv(response, 0)
        return tag, value


class Sgp32LoadPackageVerificationTests(_Sgp32TestBase):
    def test_unknown_eim_id_returns_a2_unsigned_error(self) -> None:
        request = _sign_euicc_package(
            self.eim_key,
            eim_id="unknown-eim",
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=b"",
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = self._peel_outer(response)
        self.assertEqual(outer_tag, b"\xBF\x51")
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA2")  # euiccPackageErrorUnsigned
        eim_id_raw = find_first_tlv(choice_value, "80")
        _, eim_id_value, _, _ = read_tlv(eim_id_raw, 0)
        self.assertEqual(eim_id_value.decode("utf-8"), "unknown-eim")

    def test_bad_signature_returns_a2_unsigned_error_with_eim_id(self) -> None:
        request = bytearray(
            _sign_euicc_package(
                self.eim_key,
                eim_id=self.eim_id,
                eid_hex=self.state.eid,
                counter_value=1,
                inner_choice_tag=b"\xA0",
                inner_items=b"",
            )
        )
        request[-1] ^= 0xFF

        response, _sw1, _sw2 = self.logic.handle_store_data(bytes(request))

        outer_tag, outer_value = self._peel_outer(response)
        self.assertEqual(outer_tag, b"\xBF\x51")
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA2")
        eim_id_raw = find_first_tlv(choice_value, "80")
        _, eim_id_value, _, _ = read_tlv(eim_id_raw, 0)
        self.assertEqual(eim_id_value.decode("utf-8"), self.eim_id)

    def test_eid_mismatch_returns_signed_invalid_eid(self) -> None:
        bogus_eid = "00" * 16
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=bogus_eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=b"",
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        outer_tag, outer_value = self._peel_outer(response)
        self.assertEqual(outer_tag, b"\xBF\x51")
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA1")  # euiccPackageErrorSigned
        # Inside: SEQUENCE { eimId 80, counterValue 81, errorCode 02 }, then 5F37 sig
        seq_tag, seq_value, _raw_seq, _seq_next = read_tlv(choice_value, 0)
        self.assertEqual(seq_tag, b"\x30")
        error_raw = find_first_tlv(seq_value, "02")
        self.assertGreater(len(error_raw), 0)
        _, error_value, _, _ = read_tlv(error_raw, 0)
        self.assertEqual(int.from_bytes(error_value, "big"), 3)

    def test_replayed_counter_returns_signed_replay_error(self) -> None:
        # Stored counter is already 5; sending counter=5 must reject.
        self.state.eim_entries[0].counter_value = 5
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=5,
            inner_choice_tag=b"\xA0",
            inner_items=b"",
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        outer_tag, outer_value = self._peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA1")
        seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        error_raw = find_first_tlv(seq_value, "02")
        _, error_value, _, _ = read_tlv(error_raw, 0)
        self.assertEqual(int.from_bytes(error_value, "big"), 4)

    def test_counter_overflow_returns_signed_out_of_range(self) -> None:
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=0x800000,
            inner_choice_tag=b"\xA0",
            inner_items=b"",
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        outer_tag, outer_value = self._peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA1")
        seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        error_raw = find_first_tlv(seq_value, "02")
        _, error_value, _, _ = read_tlv(error_raw, 0)
        self.assertEqual(int.from_bytes(error_value, "big"), 6)


class Sgp32PsmoBatchTests(_Sgp32TestBase):
    def test_disable_then_delete_emits_signed_result_and_advances_counter(self) -> None:
        target = self.state.profiles[0]
        target.state = "enabled"
        iccid_bytes = encode_iccid_ef(target.iccid)
        psmo_disable = tlv(b"\xA4", tlv(b"\x5A", iccid_bytes))
        psmo_delete = tlv(b"\xA5", tlv(b"\x5A", iccid_bytes))

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=10,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_disable + psmo_delete,
            eim_transaction_id=bytes.fromhex("01020304"),
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = self._peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA0")  # euiccPackageResultSigned
        seq_tag, seq_value, _seq_raw, seq_next = read_tlv(choice_value, 0)
        self.assertEqual(seq_tag, b"\x30")
        # eimId, counterValue, eimTransactionId, seqNumber, results
        eim_id_raw = find_first_tlv(seq_value, "80")
        _, eim_id_value, _, _ = read_tlv(eim_id_raw, 0)
        self.assertEqual(eim_id_value.decode("utf-8"), self.eim_id)
        counter_raw = find_first_tlv(seq_value, "81")
        _, counter_value, _, _ = read_tlv(counter_raw, 0)
        self.assertEqual(int.from_bytes(counter_value, "big"), 10)
        txid_raw = find_first_tlv(seq_value, "82")
        _, txid_value, _, _ = read_tlv(txid_raw, 0)
        self.assertEqual(txid_value, bytes.fromhex("01020304"))
        seq_number_raw = find_first_tlv(seq_value, "83")
        _, seq_number_value, _, _ = read_tlv(seq_number_raw, 0)
        self.assertGreaterEqual(int.from_bytes(seq_number_value, "big"), 1)
        # Signature TLV is the trailing 5F37 of the result-signed body.
        sig_tlv = find_first_tlv(choice_value, "5F37")
        _, sig_value, _, _ = read_tlv(sig_tlv, 0)
        self.assertEqual(len(sig_value), 64)
        # Counter advanced.
        self.assertEqual(int(self.state.eim_entries[0].counter_value), 10)
        # Profile got deleted.
        self.assertEqual(
            sum(1 for profile in self.state.profiles if profile.iccid == target.iccid),
            0,
        )
        # Stored package result is retained.
        self.assertEqual(len(self.state.euicc_package_results), 1)


class Sgp32EcoBatchTests(_Sgp32TestBase):
    def test_add_eim_with_listEim_round_trip(self) -> None:
        new_eim_id = "added-eim.local"
        new_eim_key = ec.generate_private_key(ec.SECP256R1())
        new_eim_spki = new_eim_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        eim_config_data = (
            tlv(b"\x80", new_eim_id.encode("utf-8"))
            + tlv(b"\x83", encode_der_integer(1))
            + tlv(b"\xA5", new_eim_spki)
        )
        eco_add = tlv(b"\xA8", eim_config_data)
        eco_list = tlv(b"\xAB", b"")

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=2,
            inner_choice_tag=b"\xA1",
            inner_items=eco_add + eco_list,
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = self._peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA0")
        seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        results_raw = b""
        offset = 0
        while offset < len(seq_value):
            tag_bytes, value, raw, next_offset = read_tlv(seq_value, offset)
            if tag_bytes == b"\x30":
                results_raw = raw
            offset = next_offset
        self.assertGreater(len(results_raw), 0)
        # AddEimResult ([8] = A8) and ListEimResult ([11] = AB) present
        # in the result SEQUENCE.
        self.assertIn(b"\xA8", results_raw)
        self.assertIn(b"\xAB", results_raw)
        # New eIM is stored.
        eim_ids = {entry.eim_id for entry in self.state.eim_entries}
        self.assertIn(new_eim_id, eim_ids)


class Sgp32ResultListAndAckTests(_Sgp32TestBase):
    def test_results_list_returns_a2_with_stored_payload_and_ack_drains(self) -> None:
        target = self.state.profiles[0]
        target.state = "enabled"
        psmo_disable = tlv(b"\xA4", tlv(b"\x5A", encode_iccid_ef(target.iccid)))
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_disable,
        )
        load_response, _sw1, _sw2 = self.logic.handle_store_data(request)
        # Recover seqNumber from the just-emitted result.
        outer_tag, outer_value = self._peel_outer(load_response)
        seq_number = package_result_seq_number(outer_value)
        self.assertGreaterEqual(seq_number, 1)
        self.assertEqual(len(self.state.euicc_package_results), 1)

        list_response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF2B028200"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        list_outer_tag, list_outer_value = self._peel_outer(list_response)
        self.assertEqual(list_outer_tag, b"\xBF\x2B")
        a2_tag, a2_value, _raw, _next = read_tlv(list_outer_value, 0)
        self.assertEqual(a2_tag, b"\xA2")
        # First inner element is the original A0 euiccPackageResultSigned.
        first_tag, _first_value, first_raw, _first_next = read_tlv(a2_value, 0)
        self.assertEqual(first_tag, b"\xA0")
        self.assertEqual(first_raw, self.state.euicc_package_results[0].payload)

        # ES10b.RemoveNotificationFromList over BF30 with seqNumber drains
        # the package result list as well as notifications.
        ack_payload = tlv(b"\xBF\x30", tlv(b"\x80", encode_der_integer(seq_number)))
        ack_response, _ack_sw1, _ack_sw2 = self.logic.handle_store_data(ack_payload)
        self.assertEqual(ack_response[:2], b"\xBF\x30")
        self.assertEqual(len(self.state.euicc_package_results), 0)


class Sgp32SeqNumberRecoveryTests(unittest.TestCase):
    def test_package_result_seq_number_round_trips_under_a0(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        outer, _payload = encode_euicc_package_result_signed(
            eim_id="round-trip-eim",
            counter_value=123,
            seq_number=42,
            euicc_results=[tlv(b"\x83", encode_der_integer(0))],
            private_key=private_key,
            association_token=0,
        )

        _outer_tag, outer_value = read_tlv(outer, 0)[0:2]
        # outer_value is the A0 / A1 / A2 choice envelope.
        self.assertEqual(package_result_seq_number(outer_value), 42)


if __name__ == "__main__":
    unittest.main()
