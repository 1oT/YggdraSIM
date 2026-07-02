# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""5G AKA / EAP-AKA' key-derivation conformance tests.

Locks the simulator's TS 33.501 Annex A implementation:

* Generic TS 33.220 §B.2.1 KDF byte layout (FC || P0 || L0 || ...).
* RES*  -- Annex A.4
* KAUSF -- Annex A.2
* KSEAF -- Annex A.6
* CK'/IK' for EAP-AKA' -- Annex A.3 / TS 33.402 Annex A
* End-to-end ``AuthLogic.derive_5g_vector`` against an in-engine
  USIM AUTHENTICATE (P2=0x81) round-trip, asserting that the
  ME-side anchor keys match an independent textbook computation
  performed inline in the test.
"""

from __future__ import annotations

import hmac
import os
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.aka_5g import (
    FC_EAP_AKA_PRIME,
    FC_KAUSF,
    FC_KSEAF,
    FC_RES_STAR,
    derive_eap_aka_prime_keys,
    derive_k_ausf,
    derive_k_seaf,
    derive_res_star,
    format_sn_name,
    kdf,
)
from SIMCARD.auth import build_milenage_autn, milenage_vectors
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID


# --- TS 35.208 Annex 4 Test Set 1 ---------------------------------------
# These are the canonical Milenage KAT inputs/outputs reused as the
# anchor for every 5G derivation below; they avoid pulling in an extra
# KAT module just for one set of vectors.

TS_35_208_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
TS_35_208_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
TS_35_208_RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
TS_35_208_SQN = bytes.fromhex("FF9BB4D0B607")
TS_35_208_AMF = bytes.fromhex("B9B9")

TS_35_208_RES = bytes.fromhex("A54211D5E3BA50BF")
TS_35_208_CK = bytes.fromhex("B40BA9A3C58B2A05BBF0D987B21BF8CB")
TS_35_208_IK = bytes.fromhex("F769BCD751044604127672711C6D3441")
TS_35_208_AK = bytes.fromhex("AA689C648370")
TS_35_208_MAC_A = bytes.fromhex("4A9FFAC354DFAFB3")


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big")


def _kdf_reference(key: bytes, fc: int, *parameters: bytes) -> bytes:
    """Independent re-implementation of the TS 33.220 Annex B.2.1 KDF.

    Kept inline here so the test asserts behaviour against a
    by-the-spec construction rather than against the very helper it
    is verifying.
    """
    payload = bytearray([fc & 0xFF])
    for parameter in parameters:
        payload.extend(parameter)
        payload.extend(_length_prefix(parameter))
    return hmac.new(bytes(key), bytes(payload), sha256).digest()


class GenericKdfTests(unittest.TestCase):
    """The Annex A helpers all sit on this one byte layout."""

    def test_kdf_matches_textbook_construction(self) -> None:
        key = bytes(range(32))
        result = kdf(key, 0x42, b"alpha", b"beta", b"")
        expected = _kdf_reference(key, 0x42, b"alpha", b"beta", b"")
        self.assertEqual(result, expected)

    def test_kdf_zero_length_parameter_emits_zero_length_field(self) -> None:
        key = b"\x11" * 16
        result = kdf(key, 0x10, b"")
        # FC || 0x0000 -- a single P0 of length 0.
        s = bytes([0x10, 0x00, 0x00])
        expected = hmac.new(key, s, sha256).digest()
        self.assertEqual(result, expected)

    def test_kdf_rejects_oversized_fc(self) -> None:
        with self.assertRaises(ValueError):
            kdf(b"\x00" * 16, 0x100, b"x")

    def test_kdf_rejects_empty_key(self) -> None:
        with self.assertRaises(ValueError):
            kdf(b"", 0x6A, b"sn")


class FormatSnNameTests(unittest.TestCase):
    """Canonical SN-name formatting per TS 33.501 §6.1.1.4."""

    def test_two_digit_mnc_is_left_padded_with_zero(self) -> None:
        self.assertEqual(
            format_sn_name(mnc="01", mcc="001"),
            "5G:mnc001.mcc001.3gppnetwork.org",
        )

    def test_three_digit_mnc_is_kept_verbatim(self) -> None:
        self.assertEqual(
            format_sn_name(mnc="012", mcc="901"),
            "5G:mnc012.mcc901.3gppnetwork.org",
        )

    def test_short_mcc_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            format_sn_name(mnc="01", mcc="00")

    def test_excess_mnc_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            format_sn_name(mnc="0001", mcc="001")


class AnnexADerivationTests(unittest.TestCase):
    """Each helper must agree with an inline reference KDF call."""

    def setUp(self) -> None:
        self.sn_name = "5G:mnc001.mcc001.3gppnetwork.org"
        self.sn_bytes = self.sn_name.encode("utf-8")
        self.ck = TS_35_208_CK
        self.ik = TS_35_208_IK
        self.rand = TS_35_208_RAND
        self.res = TS_35_208_RES
        # SQN XOR AK is what the AUTN field carries straight into the
        # KDFs that need it; build it the same way the ME would.
        self.sqn_xor_ak = bytes(left ^ right for left, right in zip(TS_35_208_SQN, TS_35_208_AK))

    def test_res_star_matches_annex_a_4_reference(self) -> None:
        expected_full = _kdf_reference(
            self.ck + self.ik,
            FC_RES_STAR,
            self.sn_bytes,
            self.rand,
            self.res,
        )
        self.assertEqual(
            derive_res_star(self.ck, self.ik, self.sn_name, self.rand, self.res),
            expected_full[16:32],
        )

    def test_k_ausf_matches_annex_a_2_reference(self) -> None:
        expected = _kdf_reference(
            self.ck + self.ik,
            FC_KAUSF,
            self.sn_bytes,
            self.sqn_xor_ak,
        )
        result = derive_k_ausf(self.ck, self.ik, self.sn_name, self.sqn_xor_ak)
        self.assertEqual(result, expected)
        self.assertEqual(len(result), 32)

    def test_k_seaf_matches_annex_a_6_reference(self) -> None:
        k_ausf = derive_k_ausf(self.ck, self.ik, self.sn_name, self.sqn_xor_ak)
        expected = _kdf_reference(k_ausf, FC_KSEAF, self.sn_bytes)
        result = derive_k_seaf(k_ausf, self.sn_name)
        self.assertEqual(result, expected)
        self.assertEqual(len(result), 32)

    def test_eap_aka_prime_split_matches_annex_a_3_reference(self) -> None:
        expected_full = _kdf_reference(
            self.ck + self.ik,
            FC_EAP_AKA_PRIME,
            self.sn_bytes,
            self.sqn_xor_ak,
        )
        ck_prime, ik_prime = derive_eap_aka_prime_keys(
            self.ck,
            self.ik,
            self.sn_name,
            self.sqn_xor_ak,
        )
        self.assertEqual(ck_prime, expected_full[:16])
        self.assertEqual(ik_prime, expected_full[16:32])
        self.assertEqual(len(ck_prime), 16)
        self.assertEqual(len(ik_prime), 16)


class AnnexAValidationTests(unittest.TestCase):
    """Negative cases must raise so misuse can't silently produce
    garbage anchor keys."""

    def setUp(self) -> None:
        self.sn = "5G:mnc001.mcc001.3gppnetwork.org"
        self.ck = b"\x00" * 16
        self.ik = b"\x11" * 16
        self.rand = b"\x22" * 16
        self.res = b"\x33" * 8
        self.sqn_ak = b"\x44" * 6

    def test_res_star_rejects_short_ck(self) -> None:
        with self.assertRaises(ValueError):
            derive_res_star(self.ck[:8], self.ik, self.sn, self.rand, self.res)

    def test_res_star_rejects_short_rand(self) -> None:
        with self.assertRaises(ValueError):
            derive_res_star(self.ck, self.ik, self.sn, self.rand[:8], self.res)

    def test_res_star_rejects_too_short_res(self) -> None:
        with self.assertRaises(ValueError):
            derive_res_star(self.ck, self.ik, self.sn, self.rand, b"\x00" * 3)

    def test_res_star_rejects_too_long_res(self) -> None:
        with self.assertRaises(ValueError):
            derive_res_star(self.ck, self.ik, self.sn, self.rand, b"\x00" * 17)

    def test_k_ausf_rejects_wrong_sqn_ak_length(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_ausf(self.ck, self.ik, self.sn, b"\x00" * 5)

    def test_k_seaf_rejects_short_kausf(self) -> None:
        with self.assertRaises(ValueError):
            derive_k_seaf(b"\x00" * 16, self.sn)

    def test_eap_aka_prime_rejects_empty_sn(self) -> None:
        with self.assertRaises(ValueError):
            derive_eap_aka_prime_keys(self.ck, self.ik, "", self.sqn_ak)


class AuthLogicFiveGVectorTests(unittest.TestCase):
    """End-to-end: AuthLogic round-trip vs. inline textbook derivation.

    Builds an in-memory engine with the default Milenage profile,
    selects ADF.USIM, runs AUTHENTICATE P2=0x81 with a fresh
    RAND/AUTN that the test forges itself, then asks
    ``derive_5g_vector`` for the ME-side anchor keys and checks each
    output against an independently-computed reference.
    """

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "missing_quirks.py"),
            isdr_config_path=str(root / "missing_isdr.json"),
            sim_eim_identity_path=str(root / "missing_eim_identity.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "profile_store"),
        )
        # Pin a fresh SQN under the 35.208 vector so the in-engine
        # AUTHENTICATE accepts the AUTN we forge below.
        config = self.engine.state.profiles[0].auth_config
        self.assertIsNotNone(config)
        config.ki = TS_35_208_K
        config.opc = TS_35_208_OPC
        config.amf = TS_35_208_AMF
        config.sqn = b"\x00" * 6  # accept any forged AUTN above 0
        self.engine.state.profiles[0].auth_config = config

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select_usim(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        apdu = bytes([0x00, 0xA4, 0x04, 0x04, len(aid_bytes)]) + aid_bytes
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _autn_for(self, sqn: bytes, amf: bytes) -> bytes:
        return build_milenage_autn(
            TS_35_208_K,
            TS_35_208_OPC,
            TS_35_208_RAND,
            sqn,
            amf,
        )

    def _authenticate_via_apdu(self, autn: bytes) -> tuple[bytes, bytes, bytes]:
        payload = b"\x10" + TS_35_208_RAND + b"\x10" + autn
        apdu = bytes([0x00, 0x88, 0x00, 0x81, len(payload)]) + payload
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Successful USIM AUTHENTICATE response: DB || L_RES || RES
        # || 10 || CK || 10 || IK || 08 || Kc.
        self.assertEqual(data[0], 0xDB)
        res_len = data[1]
        offset = 2 + res_len
        self.assertEqual(data[offset], 0x10)
        ck = data[offset + 1 : offset + 17]
        offset += 17
        self.assertEqual(data[offset], 0x10)
        ik = data[offset + 1 : offset + 17]
        return data[2 : 2 + res_len], ck, ik

    def test_round_trip_anchor_keys_match_textbook(self) -> None:
        sn_name = "5G:mnc001.mcc001.3gppnetwork.org"
        sqn = bytes.fromhex("000000000010")
        amf = TS_35_208_AMF
        autn = self._autn_for(sqn, amf)
        sqn_xor_ak = autn[:6]

        self._select_usim()
        res, ck, ik = self._authenticate_via_apdu(autn)

        self.assertEqual(res, TS_35_208_RES)
        self.assertEqual(ck, TS_35_208_CK)
        self.assertEqual(ik, TS_35_208_IK)

        # Reset SQN so derive_5g_vector accepts the same AUTN again
        # (the previous APDU bumped it to sqn+1).
        self.engine.state.profiles[0].auth_config.sqn = b"\x00" * 6

        vector = self.engine.auth.derive_5g_vector(sn_name, TS_35_208_RAND, autn)
        self.assertIsNotNone(vector)
        assert vector is not None

        sn_bytes = sn_name.encode("utf-8")
        expected_res_star = _kdf_reference(
            ck + ik, FC_RES_STAR, sn_bytes, TS_35_208_RAND, res
        )[16:32]
        expected_k_ausf = _kdf_reference(
            ck + ik, FC_KAUSF, sn_bytes, sqn_xor_ak
        )
        expected_k_seaf = _kdf_reference(
            expected_k_ausf, FC_KSEAF, sn_bytes
        )
        expected_eap = _kdf_reference(
            ck + ik, FC_EAP_AKA_PRIME, sn_bytes, sqn_xor_ak
        )

        self.assertEqual(vector.res, res)
        self.assertEqual(vector.ck, ck)
        self.assertEqual(vector.ik, ik)
        self.assertEqual(vector.res_star, expected_res_star)
        self.assertEqual(vector.k_ausf, expected_k_ausf)
        self.assertEqual(vector.k_seaf, expected_k_seaf)
        self.assertEqual(vector.ck_prime, expected_eap[:16])
        self.assertEqual(vector.ik_prime, expected_eap[16:32])
        self.assertEqual(vector.sn_name, sn_name)
        self.assertEqual(vector.sqn_xor_ak, sqn_xor_ak)
        self.assertEqual(len(vector.res_star), 16)
        self.assertEqual(len(vector.k_ausf), 32)
        self.assertEqual(len(vector.k_seaf), 32)

    def test_bad_mac_returns_none(self) -> None:
        autn = bytearray(self._autn_for(bytes.fromhex("000000000020"), TS_35_208_AMF))
        autn[-1] ^= 0xFF
        vector = self.engine.auth.derive_5g_vector(
            "5G:mnc001.mcc001.3gppnetwork.org",
            TS_35_208_RAND,
            bytes(autn),
        )
        self.assertIsNone(vector)

    def test_wrong_lengths_return_none(self) -> None:
        sn_name = "5G:mnc001.mcc001.3gppnetwork.org"
        self.assertIsNone(self.engine.auth.derive_5g_vector(sn_name, b"\x00" * 8, b"\x00" * 16))
        self.assertIsNone(self.engine.auth.derive_5g_vector(sn_name, b"\x00" * 16, b"\x00" * 8))

    def test_no_active_profile_returns_none(self) -> None:
        self.engine.state.profiles.clear()
        self.engine.state.active_profile_aid = ""
        autn = self._autn_for(bytes.fromhex("000000000030"), TS_35_208_AMF)
        self.assertIsNone(
            self.engine.auth.derive_5g_vector(
                "5G:mnc001.mcc001.3gppnetwork.org",
                TS_35_208_RAND,
                autn,
            )
        )


if __name__ == "__main__":
    unittest.main()
