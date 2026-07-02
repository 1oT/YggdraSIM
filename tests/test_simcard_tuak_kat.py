# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
TUAK known-answer tests against 3GPP TS 35.232 Test Set 1 + Keccak-f[1600] KAT.

These tests gate the simulator's TUAK implementation to the published reference
outputs so future refactors cannot silently regress on state layout, INSTANCE
byte derivation, byte reversal, or domain-separation padding.
"""

from __future__ import annotations

import unittest

from SIMCARD.tuak import (
    derive_topc,
    keccak_f_1600,
    tuak_f1,
    tuak_f1_star,
    tuak_f2345,
    tuak_f5_star,
    tuak_vectors,
)


_KECCAK_KAT_IN_HEX = (
    "2476d2dac59e2e9349df3255a9dab1b69eb5c208f151c7309e8c8f17db456d0b5e"
    "b0afb6c73e37ce8ccccf20b79d8a672941491748 09e4297093 30c4ad23 1d3e5211"
    "ae0bd80520c43ad4b436625792a76c52089d0f739271151a37594df66de4429f3c"
    "970a3456b6ce2c78cd1128717f4bdb731a4c97dbe5eb7353fe81e37c33ac60b821"
    "22eac611a98e0e7442b99964752293e4f9c696ba05f07a21451f90730c9678c645"
    "ad4be44c4d2d981a3412081c9c6b05c993ff1c561a0d242b4706d501c34765b37a"
    "0b50"
)

_KECCAK_KAT_OUT_HEX = (
    "2fdc58d4d94a884c1cb03a8e63acab8375e856b561ba3a0625e830acdb55734286"
    "646f87189b435425b5d6654e228228b697b81cbead655b71aaccc25e3d7e51b5cb"
    "5ac227f67f2ad8a062976782b08a7ec3f1b538d6008c0babef83da64366b62a53f"
    "88a3dc0629bded795f3220f3c65c76bdd01243e88f63d6912e5fb5cda167b71f9b"
    "aaa742dc193ff78c1767a38a1c96408cce169239b077f2903a07b8c46a048d6631"
    "8e595ea4bb92992c7c2d3dcd381975b6e05f85ba18152096cc30ed22140ff3b671"
    "1ea7"
)


def _hex_clean(text: str) -> bytes:
    return bytes.fromhex("".join(text.split()))


TUAK_TS1_KEY = bytes.fromhex("abababababababababababababababab")
TUAK_TS1_RAND = bytes.fromhex("42424242424242424242424242424242")
TUAK_TS1_SQN = bytes.fromhex("111111111111")
TUAK_TS1_AMF = bytes.fromhex("ffff")
TUAK_TS1_TOP = bytes.fromhex(
    "5555555555555555555555555555555555555555555555555555555555555555"
)

TUAK_TS1_TOPC = bytes.fromhex(
    "bd04d9530e87513c5d837ac2ad954623a8e2330c115305a73eb45d1f40cccbff"
)
TUAK_TS1_MAC_A = bytes.fromhex("f9a54e6aeaa8618d")
TUAK_TS1_MAC_S = bytes.fromhex("e94b4dc6c7297df3")
TUAK_TS1_RES = bytes.fromhex("657acd64")
TUAK_TS1_CK = bytes.fromhex("d71a1e5c6caffe986a26f783e5c78be1")


class KeccakKatTests(unittest.TestCase):
    def test_keccak_f_1600_matches_ts35232_vector(self) -> None:
        state_in = _hex_clean(_KECCAK_KAT_IN_HEX)
        state_out = _hex_clean(_KECCAK_KAT_OUT_HEX)
        self.assertEqual(len(state_in), 200)
        self.assertEqual(len(state_out), 200)
        self.assertEqual(keccak_f_1600(state_in), state_out)

    def test_keccak_f_1600_rejects_short_state(self) -> None:
        with self.assertRaises(ValueError):
            keccak_f_1600(b"\x00" * 199)


class TuakTs1KatTests(unittest.TestCase):
    def test_derive_topc_matches_reference(self) -> None:
        computed = derive_topc(TUAK_TS1_TOP, TUAK_TS1_KEY, number_of_keccak=1)
        self.assertEqual(computed, TUAK_TS1_TOPC)

    def test_tuak_f1_mac_a_matches_reference(self) -> None:
        mac_a = tuak_f1(
            topc=TUAK_TS1_TOPC,
            rand=TUAK_TS1_RAND,
            sqn=TUAK_TS1_SQN,
            amf=TUAK_TS1_AMF,
            key=TUAK_TS1_KEY,
            mac_size_bytes=8,
        )
        self.assertEqual(mac_a, TUAK_TS1_MAC_A)

    def test_tuak_f1_star_mac_s_matches_reference(self) -> None:
        mac_s = tuak_f1_star(
            topc=TUAK_TS1_TOPC,
            rand=TUAK_TS1_RAND,
            sqn=TUAK_TS1_SQN,
            amf=TUAK_TS1_AMF,
            key=TUAK_TS1_KEY,
            mac_size_bytes=8,
        )
        self.assertEqual(mac_s, TUAK_TS1_MAC_S)

    def test_tuak_f2345_res_ck_match_reference(self) -> None:
        res, ck, _ik, _ak = tuak_f2345(
            topc=TUAK_TS1_TOPC,
            rand=TUAK_TS1_RAND,
            key=TUAK_TS1_KEY,
            res_size_bytes=4,
            ck_size_bytes=16,
            ik_size_bytes=16,
        )
        self.assertEqual(res, TUAK_TS1_RES)
        self.assertEqual(ck, TUAK_TS1_CK)

    def test_tuak_f5_star_is_deterministic_and_bounded(self) -> None:
        ak_star_a = tuak_f5_star(topc=TUAK_TS1_TOPC, rand=TUAK_TS1_RAND, key=TUAK_TS1_KEY)
        ak_star_b = tuak_f5_star(topc=TUAK_TS1_TOPC, rand=TUAK_TS1_RAND, key=TUAK_TS1_KEY)
        self.assertEqual(ak_star_a, ak_star_b)
        self.assertEqual(len(ak_star_a), 6)

    def test_tuak_vectors_aggregates_individual_outputs(self) -> None:
        bundled = tuak_vectors(
            topc=TUAK_TS1_TOPC,
            rand=TUAK_TS1_RAND,
            sqn=TUAK_TS1_SQN,
            amf=TUAK_TS1_AMF,
            key=TUAK_TS1_KEY,
            res_size_bytes=4,
            mac_size_bytes=8,
            ck_ik_size_bytes=16,
        )
        self.assertEqual(bundled.mac_a, TUAK_TS1_MAC_A)
        self.assertEqual(bundled.mac_s, TUAK_TS1_MAC_S)
        self.assertEqual(bundled.res, TUAK_TS1_RES)
        self.assertEqual(bundled.ck, TUAK_TS1_CK)
        self.assertEqual(len(bundled.ak), 6)
        self.assertEqual(len(bundled.ak_star), 6)


class TuakInputValidationTests(unittest.TestCase):
    def test_rejects_wrong_topc_length(self) -> None:
        with self.assertRaises(ValueError):
            derive_topc(b"\x00" * 16, TUAK_TS1_KEY)

    def test_rejects_wrong_key_length(self) -> None:
        with self.assertRaises(ValueError):
            tuak_f1(
                topc=TUAK_TS1_TOPC,
                rand=TUAK_TS1_RAND,
                sqn=TUAK_TS1_SQN,
                amf=TUAK_TS1_AMF,
                key=b"\x00" * 12,
            )

    def test_rejects_wrong_rand_length(self) -> None:
        with self.assertRaises(ValueError):
            tuak_f2345(topc=TUAK_TS1_TOPC, rand=b"\x00" * 15, key=TUAK_TS1_KEY)

    def test_rejects_wrong_sqn_length(self) -> None:
        with self.assertRaises(ValueError):
            tuak_f1(
                topc=TUAK_TS1_TOPC,
                rand=TUAK_TS1_RAND,
                sqn=b"\x00" * 5,
                amf=TUAK_TS1_AMF,
                key=TUAK_TS1_KEY,
            )


if __name__ == "__main__":
    unittest.main()
