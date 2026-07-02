# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""End-to-end tests for the YggdraCore stub AUSF (Tools/YggdraCore/ausf_stub.py).

The stub AUSF is exercised exactly the way an external test rig
would drive it: a SUPI is registered in the in-memory subscription
store, ``start_ue_authentication`` produces a 5G HE AV, the test
acts as the UE -- runs Milenage on the same K / OPc to recover
``(RES, CK, IK)`` and computes RES* per TS 33.501 Annex A.4 -- and
``confirm_5g_aka`` is asked to verify the answer.

The same pattern surfaces every guarantee that matters for downstream
clients (UERANSIM, free5GC, etc.) without needing a network on the
table: SQN freshness, AKMA-on-success registration, and rejection
of forged / replayed RES*.
"""

from __future__ import annotations

import unittest

from SIMCARD.aka_5g import derive_res_star
from SIMCARD.akma import derive_k_akma
from SIMCARD.auth import milenage_vectors
from Tools.YggdraCore.aanf_stub import AAnFStub
from Tools.YggdraCore.ausf_stub import (
    AuthContextNotFoundError,
    AuthVerificationError,
    AusfStub,
)
from Tools.YggdraCore.subscription_store import SubscriptionStore


# Test Set 1 from TS 35.208 -- gives us a deterministic RAND for the
# whole stub by using a fixed rand_source.
_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
_FIXED_RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
_AMF = bytes.fromhex("B9B9")
_INITIAL_SQN = bytes.fromhex("FF9BB4D0B606")  # +1 lands at FF9BB4D0B607.

_SUPI = "imsi-001010000000001"
_MCC = "001"
_MNC = "01"
_SN_NAME = "5G:mnc001.mcc001.3gppnetwork.org"


def _build_stub(*, akma_enabled: bool = True) -> tuple[AusfStub, SubscriptionStore, AAnFStub]:
    subscriptions = SubscriptionStore()
    aanf = AAnFStub()
    subscriptions.upsert(
        supi=_SUPI,
        k=_K,
        opc=_OPC,
        amf=_AMF,
        sqn=_INITIAL_SQN,
        mcc=_MCC,
        mnc=_MNC,
        routing_indicator="0",
        akma_enabled=akma_enabled,
    )
    stub = AusfStub(
        subscription_store=subscriptions,
        aanf_stub=aanf,
        rand_source=lambda: _FIXED_RAND,
    )
    return stub, subscriptions, aanf


def _ue_compute_res_star(rand: bytes, sqn_used: bytes) -> bytes:
    vectors = milenage_vectors(_K, _OPC, rand, sqn_used, _AMF)
    return derive_res_star(vectors.ck, vectors.ik, _SN_NAME, rand, vectors.res)


class StartAuthenticationTests(unittest.TestCase):
    def test_returns_rand_and_autn_with_sqn_bumped(self) -> None:
        stub, subscriptions, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        self.assertEqual(response.av.rand, _FIXED_RAND)
        # SQN should have been incremented from the initial value to FF9BB4D0B607.
        self.assertEqual(subscriptions.get(_SUPI).sqn, bytes.fromhex("FF9BB4D0B607"))
        self.assertEqual(len(response.av.autn), 16)
        self.assertEqual(response.av.autn[6:8], _AMF)

    def test_xres_star_matches_independent_ue_computation(self) -> None:
        stub, _, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        expected = _ue_compute_res_star(_FIXED_RAND, bytes.fromhex("FF9BB4D0B607"))
        self.assertEqual(response.av.xres_star, expected)

    def test_unknown_supi_raises(self) -> None:
        stub, _, _ = _build_stub()
        with self.assertRaises(Exception) as guard:
            stub.start_ue_authentication(supi="imsi-000000000000000", sn_name=_SN_NAME)
        self.assertIn("unknown SUPI", str(guard.exception))

    def test_empty_sn_name_rejected(self) -> None:
        stub, _, _ = _build_stub()
        with self.assertRaises(Exception):
            stub.start_ue_authentication(supi=_SUPI, sn_name="")


class ConfirmAuthenticationTests(unittest.TestCase):
    def test_correct_res_star_succeeds_and_returns_k_seaf(self) -> None:
        stub, _, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        ue_res_star = _ue_compute_res_star(_FIXED_RAND, bytes.fromhex("FF9BB4D0B607"))
        confirm = stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=ue_res_star)
        self.assertEqual(confirm.supi, _SUPI)
        self.assertEqual(len(confirm.k_seaf), 32)

    def test_wrong_res_star_rejected(self) -> None:
        stub, _, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        forged = bytes(b ^ 0xFF for b in response.av.xres_star)
        with self.assertRaises(AuthVerificationError):
            stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=forged)

    def test_short_res_star_rejected(self) -> None:
        stub, _, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        with self.assertRaises(AuthVerificationError):
            stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=b"\x00" * 8)

    def test_context_consumed_on_use(self) -> None:
        # Confirming the same context twice must fail; replay protection
        # for the auth round trip.
        stub, _, _ = _build_stub()
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        ue_res_star = _ue_compute_res_star(_FIXED_RAND, bytes.fromhex("FF9BB4D0B607"))
        stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=ue_res_star)
        with self.assertRaises(AuthContextNotFoundError):
            stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=ue_res_star)

    def test_unknown_ctx_id_raises(self) -> None:
        stub, _, _ = _build_stub()
        with self.assertRaises(AuthContextNotFoundError):
            stub.confirm_5g_aka(ctx_id="deadbeefdeadbeef", res_star=b"\x00" * 16)


class AkmaIntegrationTests(unittest.TestCase):
    def test_successful_confirm_registers_akma_when_enabled(self) -> None:
        stub, _, aanf = _build_stub(akma_enabled=True)
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        ue_res_star = _ue_compute_res_star(_FIXED_RAND, bytes.fromhex("FF9BB4D0B607"))
        confirm = stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=ue_res_star)
        self.assertIsNotNone(confirm.a_kid)
        self.assertEqual(confirm.k_akma, derive_k_akma(response.av.k_ausf, _SUPI))
        # AAnF state machine has the registration stored under our A-KID.
        entry = aanf.lookup(confirm.a_kid)
        self.assertEqual(entry.supi, _SUPI)
        self.assertEqual(entry.k_akma, confirm.k_akma)

    def test_disabled_akma_skips_aanf_registration(self) -> None:
        stub, _, aanf = _build_stub(akma_enabled=False)
        response = stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        ue_res_star = _ue_compute_res_star(_FIXED_RAND, bytes.fromhex("FF9BB4D0B607"))
        confirm = stub.confirm_5g_aka(ctx_id=response.ctx_id, res_star=ue_res_star)
        self.assertIsNone(confirm.a_kid)
        self.assertIsNone(confirm.k_akma)
        self.assertEqual(aanf.snapshot(), [])


class DiagnosticsTests(unittest.TestCase):
    def test_in_flight_count_tracks_starts(self) -> None:
        stub, _, _ = _build_stub()
        self.assertEqual(stub.in_flight_context_count(), 0)
        stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        self.assertEqual(stub.in_flight_context_count(), 1)

    def test_clear_contexts_returns_count(self) -> None:
        stub, _, _ = _build_stub()
        stub.start_ue_authentication(supi=_SUPI, sn_name=_SN_NAME)
        self.assertEqual(stub.clear_contexts(), 1)
        self.assertEqual(stub.in_flight_context_count(), 0)


if __name__ == "__main__":
    unittest.main()
