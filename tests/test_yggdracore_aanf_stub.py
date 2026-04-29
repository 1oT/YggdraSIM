"""AAnF stub state-machine tests (Tools/YggdraCore/aanf_stub.py).

Locks the in-process AKMA Anchor Function the GUI Command Center
actions depend on:

* ``register`` mirrors ``Naanf_AKMA_KeyRegistration`` and stores
  ``(SUPI, A-KID, KAKMA)`` with an explicit expiration.
* ``application_key_get`` mirrors ``Naanf_AKMA_ApplicationKey_Get``,
  derives a fresh KAF via :func:`SIMCARD.akma.derive_k_af`, and
  bounds the KAF lifetime by the AAnF entry's own.
* Expired entries are pruned on read.
* Validation rejects malformed SUPI / A-KID / KAKMA inputs.
"""

from __future__ import annotations

import time
import unittest

from SIMCARD.akma import derive_k_af
from Tools.YggdraCore.aanf_stub import AAnFLookupError, AAnFStub


_SUPI = "imsi-001010000000001"
_A_KID = "0.QUJDREVGR0g@akma.5gc.mnc001.mcc001.3gppnetwork.org"
_KAKMA = bytes.fromhex(
    "11223344556677889900AABBCCDDEEFF"
    "11223344556677889900AABBCCDDEEFF"
)
_AF_ID = "af.example.com" + "\x01\x00\x01\x00"


class RegistrationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = AAnFStub()

    def test_register_and_lookup_round_trip(self) -> None:
        entry = self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=_KAKMA)
        looked_up = self.stub.lookup(_A_KID)
        self.assertEqual(looked_up.supi, _SUPI)
        self.assertEqual(looked_up.a_kid, _A_KID)
        self.assertEqual(looked_up.k_akma, _KAKMA)
        self.assertGreaterEqual(looked_up.expires_at, entry.registered_at)

    def test_register_twice_overwrites(self) -> None:
        first = self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=_KAKMA)
        second_kakma = bytes(b ^ 0xFF for b in _KAKMA)
        second = self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=second_kakma)
        self.assertNotEqual(first.k_akma, second.k_akma)
        self.assertEqual(self.stub.lookup(_A_KID).k_akma, second_kakma)

    def test_lookup_unknown_a_kid_raises(self) -> None:
        with self.assertRaises(AAnFLookupError):
            self.stub.lookup("0.UNKNOWN@akma.5gc.mnc001.mcc001.3gppnetwork.org")

    def test_expired_entry_is_pruned_on_lookup(self) -> None:
        entry = self.stub.register(
            supi=_SUPI,
            a_kid=_A_KID,
            k_akma=_KAKMA,
            lifetime_seconds=1,
        )
        # Force expiration by rewriting the wall clock the stub sees:
        # the entry is frozen, so we wait the lifetime out instead.
        del entry
        time.sleep(1.1)
        with self.assertRaises(AAnFLookupError):
            self.stub.lookup(_A_KID)

    def test_deregister_removes_entry(self) -> None:
        self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=_KAKMA)
        self.assertTrue(self.stub.deregister(_A_KID))
        with self.assertRaises(AAnFLookupError):
            self.stub.lookup(_A_KID)

    def test_clear_returns_count(self) -> None:
        self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=_KAKMA)
        self.assertEqual(self.stub.clear(), 1)
        self.assertEqual(self.stub.snapshot(), [])

    def test_snapshot_excludes_expired_entries(self) -> None:
        self.stub.register(
            supi=_SUPI,
            a_kid=_A_KID,
            k_akma=_KAKMA,
            lifetime_seconds=1,
        )
        time.sleep(1.1)
        self.assertEqual(self.stub.snapshot(), [])


class ApplicationKeyGetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = AAnFStub()
        self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=_KAKMA)

    def test_application_key_get_matches_derive_k_af(self) -> None:
        response = self.stub.application_key_get(a_kid=_A_KID, af_id=_AF_ID)
        expected = derive_k_af(_KAKMA, _AF_ID)
        self.assertEqual(response.k_af, expected)
        self.assertEqual(response.supi, _SUPI)
        self.assertEqual(response.af_id, _AF_ID)

    def test_application_key_get_with_unknown_a_kid_raises(self) -> None:
        with self.assertRaises(AAnFLookupError):
            self.stub.application_key_get(
                a_kid="0.UNKNOWN@akma.5gc.mnc001.mcc001.3gppnetwork.org",
                af_id=_AF_ID,
            )

    def test_kaf_lifetime_bounded_by_aanf_entry(self) -> None:
        self.stub.clear()
        self.stub.register(
            supi=_SUPI,
            a_kid=_A_KID,
            k_akma=_KAKMA,
            lifetime_seconds=2,
        )
        # Ask for a 1-hour KAF lifetime. The stub must clamp it down
        # to <=2s because the AAnF entry expires sooner.
        response = self.stub.application_key_get(
            a_kid=_A_KID,
            af_id=_AF_ID,
            kaf_lifetime_seconds=3600,
        )
        self.assertLess(response.k_af_expires_at - time.time(), 3.0)


class InputValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = AAnFStub()

    def test_register_rejects_empty_supi(self) -> None:
        with self.assertRaises(ValueError):
            self.stub.register(supi="", a_kid=_A_KID, k_akma=_KAKMA)

    def test_register_rejects_a_kid_without_realm(self) -> None:
        with self.assertRaises(ValueError):
            self.stub.register(supi=_SUPI, a_kid="not-a-nai", k_akma=_KAKMA)

    def test_register_rejects_short_kakma(self) -> None:
        with self.assertRaises(ValueError):
            self.stub.register(supi=_SUPI, a_kid=_A_KID, k_akma=b"\x00" * 16)

    def test_register_rejects_non_positive_lifetime(self) -> None:
        with self.assertRaises(ValueError):
            self.stub.register(
                supi=_SUPI,
                a_kid=_A_KID,
                k_akma=_KAKMA,
                lifetime_seconds=0,
            )


if __name__ == "__main__":
    unittest.main()
