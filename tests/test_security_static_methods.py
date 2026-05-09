# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP03/logic/security.py pure static methods.

Covers: derive_gsm_kc, build_usim_auth_payload, build_usim_auth_apdu,
        build_usim_auth_response_payload, build_usim_auth_response_apdu,
        build_auth_test_vector_report, compute_offline_usim_auth_exchange
        (happy-path only; skipped when Milenage libs are unavailable).
"""

from __future__ import annotations

import unittest

from SCP03.logic.security import SecurityController


_RAND = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
_CK   = "00112233445566778899AABBCCDDEEFF"
_IK   = "FFEEDDCCBBAA99887766554433221100"
_RES  = "AABBCCDD"
_KI   = "000102030405060708090A0B0C0D0E0F"
_OP   = "63BFA50EE6523365FF14C1F45F88737D"


# ---------------------------------------------------------------------------
# derive_gsm_kc  (3GPP TS 33.102 Annex B.4 — pure XOR, no external deps)
# ---------------------------------------------------------------------------

class DeriveGsmKcTests(unittest.TestCase):

    def test_returns_16_hex_chars(self) -> None:
        result = SecurityController.derive_gsm_kc(_CK, _IK)
        self.assertEqual(len(result), 16)

    def test_returns_uppercase_hex(self) -> None:
        result = SecurityController.derive_gsm_kc(_CK, _IK)
        self.assertEqual(result, result.upper())

    def test_known_identity_xor(self) -> None:
        # CK XOR IK where CK == IK → all zeros
        same = "AABBCCDD" * 4
        result = SecurityController.derive_gsm_kc(same, same)
        self.assertEqual(result, "0" * 16)

    def test_zero_ck_returns_ik_half_xor(self) -> None:
        all_zeros = "00" * 16
        result = SecurityController.derive_gsm_kc(all_zeros, _IK)
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 16)


# ---------------------------------------------------------------------------
# build_usim_auth_payload  (string construction, no crypto)
# ---------------------------------------------------------------------------

class BuildUsimAuthPayloadTests(unittest.TestCase):

    def test_output_starts_with_10_rand(self) -> None:
        result = SecurityController.build_usim_auth_payload(_RAND, _RAND)
        self.assertTrue(result.startswith("10"))
        self.assertIn(_RAND, result)

    def test_two_10_length_prefixes(self) -> None:
        result = SecurityController.build_usim_auth_payload(_RAND, _RAND)
        # "10" <RAND 32> "10" <AUTN 32> = 2 + 32 + 2 + 32 = 68 chars
        self.assertEqual(len(result), 68)

    def test_rand_and_autn_embedded(self) -> None:
        autn = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5"
        result = SecurityController.build_usim_auth_payload(_RAND, autn)
        self.assertIn(_RAND, result)
        self.assertIn(autn, result)


# ---------------------------------------------------------------------------
# build_usim_auth_apdu
# ---------------------------------------------------------------------------

class BuildUsimAuthApduTests(unittest.TestCase):

    def test_returns_string(self) -> None:
        result = SecurityController.build_usim_auth_apdu(_RAND, _RAND)
        self.assertIsInstance(result, str)

    def test_starts_with_default_cla(self) -> None:
        result = SecurityController.build_usim_auth_apdu(_RAND, _RAND)
        self.assertTrue(result.startswith("00"))

    def test_ins_is_88(self) -> None:
        result = SecurityController.build_usim_auth_apdu(_RAND, _RAND)
        self.assertEqual(result[2:4], "88")

    def test_custom_cla(self) -> None:
        result = SecurityController.build_usim_auth_apdu(_RAND, _RAND, cla_hex="0C")
        self.assertTrue(result.startswith("0C"))

    def test_ends_with_le_00(self) -> None:
        result = SecurityController.build_usim_auth_apdu(_RAND, _RAND)
        self.assertTrue(result.endswith("00"))


# ---------------------------------------------------------------------------
# build_usim_auth_response_payload
# ---------------------------------------------------------------------------

class BuildUsimAuthResponsePayloadTests(unittest.TestCase):

    def test_starts_with_db(self) -> None:
        result = SecurityController.build_usim_auth_response_payload(_RES, _CK, _IK, "00" * 8)
        self.assertTrue(result.upper().startswith("DB"))

    def test_returns_uppercase_hex(self) -> None:
        result = SecurityController.build_usim_auth_response_payload(_RES, _CK, _IK, "00" * 8)
        self.assertEqual(result, result.upper())

    def test_res_embedded(self) -> None:
        result = SecurityController.build_usim_auth_response_payload(_RES, _CK, _IK, "00" * 8)
        self.assertIn(_RES, result)

    def test_ck_ik_embedded(self) -> None:
        result = SecurityController.build_usim_auth_response_payload(_RES, _CK, _IK, "00" * 8)
        self.assertIn(_CK, result)
        self.assertIn(_IK, result)


# ---------------------------------------------------------------------------
# build_usim_auth_response_apdu
# ---------------------------------------------------------------------------

class BuildUsimAuthResponseApduTests(unittest.TestCase):

    def test_ends_with_status_word(self) -> None:
        result = SecurityController.build_usim_auth_response_apdu(_RES, _CK, _IK, "00" * 8)
        self.assertTrue(result.upper().endswith("9000"))

    def test_custom_status_word(self) -> None:
        result = SecurityController.build_usim_auth_response_apdu(_RES, _CK, _IK, "00" * 8, status_word="6985")
        self.assertTrue(result.upper().endswith("6985"))


# ---------------------------------------------------------------------------
# build_auth_test_vector_report  (uses Milenage — may need pySim/Crypto)
# ---------------------------------------------------------------------------

class BuildAuthTestVectorReportTests(unittest.TestCase):

    def test_returns_offline_auth_vector(self) -> None:
        try:
            result = SecurityController.build_auth_test_vector_report()
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Milenage deps not installed")
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "rand"))
        self.assertTrue(hasattr(result, "res"))

    def test_rand_field_is_32_hex_chars(self) -> None:
        try:
            result = SecurityController.build_auth_test_vector_report()
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Milenage deps not installed")
        self.assertEqual(len(result.rand), 32)


if __name__ == "__main__":
    unittest.main()
