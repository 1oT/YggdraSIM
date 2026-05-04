"""3GPP TS 33.535 AKMA key-derivation conformance tests.

Locks the simulator's AKMA Annex A implementation:

* Annex A.2 -- KAKMA derivation
* Annex A.3 -- A-TID derivation
* Annex A.4 -- KAF derivation
* \u00a76.1 / TS 23.003 \u00a728.7.3 -- A-KID NAI envelope (RID + A-TID + realm)

3GPP does not publish official KAT vectors for AKMA, so the tests
seed KAUSF from the canonical TS 35.208 Test Set 1 + TS 33.501 Annex
A.2 (5G AKA) chain we already lock in
:mod:`tests.test_simcard_5g_aka`, then assert each AKMA derivation
against a fresh, in-line reference implementation of the TS 33.220
\u00a7B.2.1 KDF. The reference is intentionally re-derived per test so a
mistake in :mod:`SIMCARD.akma` cannot mask itself by reusing the
same helper it is verifying.
"""

from __future__ import annotations

import base64
import hmac
import unittest
from hashlib import sha256

from SIMCARD.aka_5g import derive_k_ausf, format_sn_name
from SIMCARD.akma import (
    FC_A_TID,
    FC_KAF,
    FC_KAKMA,
    derive_a_tid,
    derive_k_af,
    derive_k_akma,
    format_a_kid,
    format_home_network_identifier,
)
from SIMCARD.auth import milenage_vectors


# -- Canonical anchor ---------------------------------------------------
# The TS 35.208 Test Set 1 Milenage triple, lifted verbatim out of
# tests/test_simcard_aka_milenage_kat.py. Combined with the canonical
# TS 33.501 Annex A.2 KAUSF derivation this gives a single, deterministic
# 32-byte KAUSF every test below can root off of.

_TS1_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_TS1_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
_TS1_RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
_TS1_SQN = bytes.fromhex("FF9BB4D0B607")
_TS1_AMF = bytes.fromhex("B9B9")

# TS 33.501 \u00a76.1.1.4 canonical SN-name for MNC=01 / MCC=001.
_SN_NAME = format_sn_name(mnc="01", mcc="001")

# A textbook SUPI in IMSI form (TS 33.501 Annex A.7.0 P0).
_SUPI = "imsi-001010000000001"


def _kausf_from_test_set_1() -> bytes:
    vectors = milenage_vectors(_TS1_K, _TS1_OPC, _TS1_RAND, _TS1_SQN, _TS1_AMF)
    concealed_sqn = bytes(a ^ b for a, b in zip(_TS1_SQN, vectors.ak))
    return derive_k_ausf(vectors.ck, vectors.ik, _SN_NAME, concealed_sqn)


def _kdf_reference(key: bytes, fc: int, *parameters: bytes) -> bytes:
    """Independent TS 33.220 \u00a7B.2.1 reference KDF.

    Re-derived here so the tests assert behaviour against a
    by-the-spec construction, not against the very helper being
    verified.
    """
    payload = bytearray([fc & 0xFF])
    for parameter in parameters:
        payload.extend(parameter)
        payload.extend(len(parameter).to_bytes(2, "big"))
    return hmac.new(bytes(key), bytes(payload), sha256).digest()


class KAkmaDerivationTests(unittest.TestCase):
    """TS 33.535 Annex A.2 -- KAKMA = KDF(KAUSF, FC=0x80, "AKMA", SUPI)."""

    def setUp(self) -> None:
        self.k_ausf = _kausf_from_test_set_1()

    def test_kakma_matches_inline_reference(self) -> None:
        reference = _kdf_reference(
            self.k_ausf,
            FC_KAKMA,
            b"AKMA",
            _SUPI.encode("utf-8"),
        )
        self.assertEqual(derive_k_akma(self.k_ausf, _SUPI), reference)

    def test_kakma_is_thirty_two_bytes(self) -> None:
        self.assertEqual(len(derive_k_akma(self.k_ausf, _SUPI)), 32)

    def test_kakma_rejects_wrong_kausf_length(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_akma(b"\x00" * 16, _SUPI)

    def test_kakma_rejects_empty_supi(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_akma(self.k_ausf, "")

    def test_kakma_accepts_pre_encoded_supi(self) -> None:
        encoded = _SUPI.encode("utf-8")
        self.assertEqual(
            derive_k_akma(self.k_ausf, encoded),
            derive_k_akma(self.k_ausf, _SUPI),
        )

    def test_kakma_changes_with_supi(self) -> None:
        other = derive_k_akma(self.k_ausf, "imsi-001010000000002")
        self.assertNotEqual(derive_k_akma(self.k_ausf, _SUPI), other)


class ATidDerivationTests(unittest.TestCase):
    """TS 33.535 Annex A.3 -- A-TID = KDF(KAUSF, FC=0x81, "A-TID", SUPI)."""

    def setUp(self) -> None:
        self.k_ausf = _kausf_from_test_set_1()

    def test_a_tid_matches_inline_reference(self) -> None:
        reference = _kdf_reference(
            self.k_ausf,
            FC_A_TID,
            b"A-TID",
            _SUPI.encode("utf-8"),
        )
        self.assertEqual(derive_a_tid(self.k_ausf, _SUPI), reference)

    def test_a_tid_is_thirty_two_bytes(self) -> None:
        self.assertEqual(len(derive_a_tid(self.k_ausf, _SUPI)), 32)

    def test_a_tid_independent_of_kakma(self) -> None:
        # FC bytes differ (0x80 vs 0x81), so the two outputs must too.
        self.assertNotEqual(
            derive_a_tid(self.k_ausf, _SUPI),
            derive_k_akma(self.k_ausf, _SUPI),
        )


class KafDerivationTests(unittest.TestCase):
    """TS 33.535 Annex A.4 -- KAF = KDF(KAKMA, FC=0x82, AF_ID)."""

    def setUp(self) -> None:
        k_ausf = _kausf_from_test_set_1()
        self.k_akma = derive_k_akma(k_ausf, _SUPI)
        # Annex A.4: AF_ID = FQDN || Ua* security protocol identifier.
        # We append a four-octet protocol identifier so the test
        # exercises a realistic concatenation rather than a bare FQDN.
        self.af_id_bytes = b"af.example.com" + b"\x01\x00\x01\x00"

    def test_k_af_matches_inline_reference(self) -> None:
        reference = _kdf_reference(self.k_akma, FC_KAF, self.af_id_bytes)
        self.assertEqual(derive_k_af(self.k_akma, self.af_id_bytes), reference)

    def test_k_af_accepts_str_af_id(self) -> None:
        text_af = "af.example.com"
        self.assertEqual(
            derive_k_af(self.k_akma, text_af),
            derive_k_af(self.k_akma, text_af.encode("utf-8")),
        )

    def test_k_af_rejects_wrong_kakma_length(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_af(b"\x00" * 16, "af.example.com")

    def test_k_af_rejects_empty_af_id(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_af(self.k_akma, "")


class AKidNaiFormattingTests(unittest.TestCase):
    """TS 33.535 \u00a76.1 + TS 23.003 \u00a728.7.3 -- A-KID NAI envelope."""

    def setUp(self) -> None:
        self.a_tid = derive_a_tid(_kausf_from_test_set_1(), _SUPI)

    def test_realm_matches_ts_23_003_format(self) -> None:
        realm = format_home_network_identifier(mcc="001", mnc="01")
        self.assertEqual(realm, "akma.5gc.mnc001.mcc001.3gppnetwork.org")

    def test_realm_pads_two_digit_mnc_to_three(self) -> None:
        realm = format_home_network_identifier(mcc="234", mnc="15")
        self.assertEqual(realm, "akma.5gc.mnc015.mcc234.3gppnetwork.org")

    def test_realm_rejects_short_mcc(self) -> None:
        with self.assertRaises(ValueError):
            format_home_network_identifier(mcc="12", mnc="01")

    def test_a_kid_default_uses_base64url_no_padding(self) -> None:
        a_kid = format_a_kid(
            self.a_tid,
            routing_indicator="1234",
            mcc="001",
            mnc="01",
        )
        username, _, realm = a_kid.partition("@")
        self.assertEqual(realm, "akma.5gc.mnc001.mcc001.3gppnetwork.org")
        rid, _, encoded = username.partition(".")
        self.assertEqual(rid, "1234")
        # Re-decode the base64url segment and assert it round-trips.
        padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        self.assertEqual(decoded, self.a_tid)

    def test_a_kid_hex_mode_lowercase(self) -> None:
        a_kid = format_a_kid(
            self.a_tid,
            routing_indicator="0",
            mcc="001",
            mnc="01",
            encoding="hex",
        )
        username, _, _ = a_kid.partition("@")
        rid, _, encoded = username.partition(".")
        self.assertEqual(rid, "0")
        self.assertEqual(encoded, self.a_tid.hex())

    def test_a_kid_rejects_non_digit_rid(self) -> None:
        with self.assertRaises(ValueError):
            format_a_kid(self.a_tid, routing_indicator="ab12", mcc="001", mnc="01")

    def test_a_kid_rejects_overlong_rid(self) -> None:
        with self.assertRaises(ValueError):
            format_a_kid(self.a_tid, routing_indicator="12345", mcc="001", mnc="01")

    def test_a_kid_rejects_unsupported_encoding(self) -> None:
        with self.assertRaises(ValueError):
            format_a_kid(
                self.a_tid,
                routing_indicator="1",
                mcc="001",
                mnc="01",
                encoding="ascii85",
            )


if __name__ == "__main__":
    unittest.main()
