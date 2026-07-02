# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SUPI / SUCI conformance tests.

Covers:

* ANSI-X9.63 KDF (TS 33.501 §C.3.2) byte layout vs. an inline reference
  using SHA-256.
* Null scheme SUCI body byte layout (TS 24.501 §9.11.3.4).
* Profile A (X25519) ECIES round-trip: encrypt with a pinned ephemeral
  key, decrypt with the home-network private key, recover the MSIN.
* Profile B (P-256) ECIES round-trip with point compression.
* MAC-tag tampering rejection on both protected schemes.
* EF.SUCI_Calc_Info encode/decode round-trip + priority-list ordering.
* GET IDENTITY APDU returning a null-scheme SUCI on a default
  simulator (no operator HN keys provisioned).
* GET IDENTITY APDU returning a Profile A SUCI when EF.SUCI_Calc_Info
  carries a single Profile A key entry.
* AuthLogic.derive_5g_vector populates EF.5GAUTHKEYS with the TLV
  layout of TS 31.102 §4.4.11.5 and bumps EF.KAUSF-DERIVATION.
"""

from __future__ import annotations

import hmac
import os
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from SIMCARD.auth import build_milenage_autn
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID, _resolve_active_profile
from SIMCARD.suci import (
    HomeNetworkPublicKey,
    ProtectionScheme,
    SuciCalcInfo,
    _profile_a_decrypt,
    _profile_b_decrypt,
    build_suci_from_imsi,
    decode_ef_suci_calc_info,
    decode_msin_bcd,
    encode_ef_suci_calc_info,
    encode_msin_bcd,
    encode_suci_mobile_identity,
    split_imsi,
    x963_kdf_sha256,
)


def _x963_reference(z: bytes, info: bytes, length: int) -> bytes:
    out = b""
    counter = 1
    while len(out) < length:
        out += sha256(z + counter.to_bytes(4, "big") + info).digest()
        counter += 1
    return out[:length]


class X963KdfTests(unittest.TestCase):
    def test_matches_textbook_reference(self) -> None:
        z = b"\x11" * 32
        info = b"shared-info"
        for length in (16, 32, 48, 64, 80):
            self.assertEqual(
                x963_kdf_sha256(z, info, length),
                _x963_reference(z, info, length),
            )

    def test_zero_length_returns_empty(self) -> None:
        self.assertEqual(x963_kdf_sha256(b"\x00" * 32, b"", 0), b"")

    def test_rejects_empty_z(self) -> None:
        with self.assertRaises(ValueError):
            x963_kdf_sha256(b"", b"info", 32)

    def test_rejects_negative_length(self) -> None:
        with self.assertRaises(ValueError):
            x963_kdf_sha256(b"\x11" * 32, b"info", -1)


class MsinBcdTests(unittest.TestCase):
    def test_even_length_round_trip(self) -> None:
        digits = "1234567890"
        encoded = encode_msin_bcd(digits)
        self.assertEqual(encoded.hex(), "2143658709")
        self.assertEqual(decode_msin_bcd(encoded), digits)

    def test_odd_length_pads_with_f(self) -> None:
        digits = "12345"
        encoded = encode_msin_bcd(digits)
        self.assertEqual(encoded.hex().lower(), "2143f5")
        self.assertEqual(decode_msin_bcd(encoded), digits)

    def test_rejects_non_digits(self) -> None:
        with self.assertRaises(ValueError):
            encode_msin_bcd("12X45")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            encode_msin_bcd("")


class SplitImsiTests(unittest.TestCase):
    def test_two_digit_mnc(self) -> None:
        # 3GPP TS 23.003 §2.2 test PLMN (MCC=001 / MNC=01).
        mcc, mnc, msin = split_imsi("001017830012345", 2)
        self.assertEqual((mcc, mnc, msin), ("001", "01", "7830012345"))

    def test_three_digit_mnc(self) -> None:
        # 3GPP TS 23.003 §2.2 alternate test PLMN (MCC=999 / MNC=999).
        mcc, mnc, msin = split_imsi("999999123456789", 3)
        self.assertEqual((mcc, mnc, msin), ("999", "999", "123456789"))

    def test_rejects_invalid_mnc_length(self) -> None:
        with self.assertRaises(ValueError):
            split_imsi("001017830012345", 4)

    def test_rejects_short_imsi(self) -> None:
        with self.assertRaises(ValueError):
            split_imsi("12345", 2)


class SuciMobileIdentityNullSchemeTests(unittest.TestCase):
    """Null scheme is the canary for the entire byte layout."""

    def test_null_scheme_layout_matches_ts_24_501(self) -> None:
        identity = build_suci_from_imsi(
            imsi="001017830012345",
            mnc_length=2,
            routing_indicator="678",
            protection_scheme=ProtectionScheme.NULL,
        )
        # 1 (octet1) + 3 (MCC/MNC) + 2 (RI) + 1 (scheme) + 1 (key-id) + 5 (MSIN)
        self.assertEqual(len(identity), 13)
        # Octet 1: SUPI format=0 (IMSI, upper nibble), type-of-identity=001 (SUCI)
        self.assertEqual(identity[0], 0x01)
        # MCC+MNC for 001/01 (3GPP TS 23.003 §2.2 test PLMN):
        #   o2 = (m[1]<<4)|m[0] = 0x00
        #   o3 = (mnc[2]<<4)|m[2] = 0xF1
        #   o4 = (mnc[1]<<4)|mnc[0] = 0x10
        self.assertEqual(identity[1:4].hex().upper(), "00F110")
        # RI '678' -> [6,7,8,F] -> 0x76 0xF8
        self.assertEqual(identity[4:6].hex().upper(), "76F8")
        self.assertEqual(identity[6], int(ProtectionScheme.NULL))
        self.assertEqual(identity[7], 0)
        # MSIN '7830012345' -> 5 bytes
        self.assertEqual(identity[8:].hex().upper(), "8703103254")

    def test_three_digit_mnc_packs_third_digit(self) -> None:
        identity = build_suci_from_imsi(
            imsi="999999123456789",
            mnc_length=3,
            routing_indicator="0",
            protection_scheme=ProtectionScheme.NULL,
        )
        # MCC=999, MNC=999 (3GPP TS 23.003 §2.2 alternate test PLMN):
        #   o2 = (m[1]<<4)|m[0] = 0x99
        #   o3 = (mnc[2]<<4)|m[2] = 0x99
        #   o4 = (mnc[1]<<4)|mnc[0] = 0x99
        self.assertEqual(identity[1:4].hex().upper(), "999999")

    def test_routing_indicator_with_one_digit(self) -> None:
        identity = build_suci_from_imsi(
            imsi="001010000000001",
            mnc_length=2,
            routing_indicator="3",
            protection_scheme=ProtectionScheme.NULL,
        )
        # RI '3' -> [3,F,F,F] -> 0xF3 0xFF
        self.assertEqual(identity[4:6].hex().upper(), "F3FF")

    def test_routing_indicator_too_long_rejected(self) -> None:
        with self.assertRaises(ValueError):
            encode_suci_mobile_identity(
                supi_format=0,
                mcc="001",
                mnc="01",
                routing_indicator="12345",
                protection_scheme=ProtectionScheme.NULL,
                hn_public_key_id=0,
                scheme_output=b"",
            )

    def test_nai_format_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            encode_suci_mobile_identity(
                supi_format=1,
                mcc="001",
                mnc="01",
                routing_indicator="0",
                protection_scheme=ProtectionScheme.NULL,
                hn_public_key_id=0,
                scheme_output=b"",
            )


class ProfileARoundTripTests(unittest.TestCase):
    """X25519 ECIES round-trip with HN private-key recovery."""

    def setUp(self) -> None:
        # Pin a deterministic HN keypair via a known scalar so the
        # test does not depend on system entropy timing.
        self.hn_private = x25519.X25519PrivateKey.from_private_bytes(b"\x42" * 32)
        self.hn_pub = self.hn_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.hn_priv_bytes = self.hn_private.private_bytes_raw()
        # 3GPP TS 23.003 §2.2 test PLMN (MCC=001 / MNC=01) — never allocated.
        self.imsi = "001017830012345"
        self.mnc_length = 2
        self.expected_msin_bcd = encode_msin_bcd("7830012345")

    def test_round_trip_recovers_msin(self) -> None:
        identity = build_suci_from_imsi(
            imsi=self.imsi,
            mnc_length=self.mnc_length,
            routing_indicator="678",
            protection_scheme=ProtectionScheme.PROFILE_A,
            home_network_public_key=HomeNetworkPublicKey(
                key_identifier=0x27,
                protection_scheme=ProtectionScheme.PROFILE_A,
                public_key=self.hn_pub,
            ),
        )
        # 8-byte header + 32-byte eph-pub + 5-byte ciphertext + 8-byte MAC
        self.assertEqual(len(identity), 8 + 32 + 5 + 8)
        scheme_output = identity[8:]
        recovered = _profile_a_decrypt(scheme_output, self.hn_priv_bytes)
        self.assertEqual(recovered, self.expected_msin_bcd)

    def test_mac_tamper_is_rejected(self) -> None:
        identity = bytearray(
            build_suci_from_imsi(
                imsi=self.imsi,
                mnc_length=self.mnc_length,
                routing_indicator="678",
                protection_scheme=ProtectionScheme.PROFILE_A,
                home_network_public_key=HomeNetworkPublicKey(
                    key_identifier=0x27,
                    protection_scheme=ProtectionScheme.PROFILE_A,
                    public_key=self.hn_pub,
                ),
            )
        )
        identity[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            _profile_a_decrypt(bytes(identity[8:]), self.hn_priv_bytes)

    def test_pinned_ephemeral_key_makes_output_deterministic(self) -> None:
        eph_priv = b"\x11" * 32
        first = build_suci_from_imsi(
            imsi=self.imsi,
            mnc_length=self.mnc_length,
            routing_indicator="0",
            protection_scheme=ProtectionScheme.PROFILE_A,
            home_network_public_key=HomeNetworkPublicKey(
                0x01, ProtectionScheme.PROFILE_A, self.hn_pub
            ),
            ephemeral_private_key=eph_priv,
        )
        second = build_suci_from_imsi(
            imsi=self.imsi,
            mnc_length=self.mnc_length,
            routing_indicator="0",
            protection_scheme=ProtectionScheme.PROFILE_A,
            home_network_public_key=HomeNetworkPublicKey(
                0x01, ProtectionScheme.PROFILE_A, self.hn_pub
            ),
            ephemeral_private_key=eph_priv,
        )
        self.assertEqual(first, second)


class ProfileBRoundTripTests(unittest.TestCase):
    """secp256r1 ECIES with point compression."""

    def setUp(self) -> None:
        self.hn_private = ec.generate_private_key(ec.SECP256R1())
        self.hn_pub_compressed = self.hn_private.public_key().public_bytes(
            Encoding.X962, PublicFormat.CompressedPoint
        )
        self.hn_priv_scalar = self.hn_private.private_numbers().private_value.to_bytes(
            32, "big"
        )
        self.imsi = "001010000000001"
        self.expected_msin_bcd = encode_msin_bcd("0000000001")

    def test_round_trip_recovers_msin(self) -> None:
        identity = build_suci_from_imsi(
            imsi=self.imsi,
            mnc_length=2,
            routing_indicator="42",
            protection_scheme=ProtectionScheme.PROFILE_B,
            home_network_public_key=HomeNetworkPublicKey(
                key_identifier=0x99,
                protection_scheme=ProtectionScheme.PROFILE_B,
                public_key=self.hn_pub_compressed,
            ),
        )
        # 8-byte header + 33-byte compressed eph-pub + 5-byte ciphertext + 8-byte MAC
        self.assertEqual(len(identity), 8 + 33 + 5 + 8)
        recovered = _profile_b_decrypt(identity[8:], self.hn_priv_scalar)
        self.assertEqual(recovered, self.expected_msin_bcd)

    def test_mac_tamper_is_rejected(self) -> None:
        identity = bytearray(
            build_suci_from_imsi(
                imsi=self.imsi,
                mnc_length=2,
                routing_indicator="42",
                protection_scheme=ProtectionScheme.PROFILE_B,
                home_network_public_key=HomeNetworkPublicKey(
                    0x99, ProtectionScheme.PROFILE_B, self.hn_pub_compressed
                ),
            )
        )
        identity[-3] ^= 0x55
        with self.assertRaises(ValueError):
            _profile_b_decrypt(bytes(identity[8:]), self.hn_priv_scalar)

    def test_uncompressed_key_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_suci_from_imsi(
                imsi=self.imsi,
                mnc_length=2,
                routing_indicator="0",
                protection_scheme=ProtectionScheme.PROFILE_B,
                home_network_public_key=HomeNetworkPublicKey(
                    0x99,
                    ProtectionScheme.PROFILE_B,
                    b"\x04" + b"\x00" * 64,  # uncompressed form, 65 bytes
                ),
            )


class EfSuciCalcInfoTests(unittest.TestCase):
    """EF.SUCI_Calc_Info byte layout and round-trip."""

    def setUp(self) -> None:
        self.hn_pub_a = b"\xAA" * 32
        self.hn_pub_b = b"\x02" + b"\xBB" * 32
        self.info = SuciCalcInfo(
            priority_list=[
                (1, ProtectionScheme.PROFILE_A, 0x10),
                (2, ProtectionScheme.PROFILE_B, 0x20),
                (3, ProtectionScheme.NULL, 0x00),
            ],
            public_keys=[
                HomeNetworkPublicKey(0x10, ProtectionScheme.PROFILE_A, self.hn_pub_a),
                HomeNetworkPublicKey(0x20, ProtectionScheme.PROFILE_B, self.hn_pub_b),
            ],
        )

    def test_round_trip_preserves_lists(self) -> None:
        encoded = encode_ef_suci_calc_info(self.info)
        decoded = decode_ef_suci_calc_info(encoded)
        self.assertEqual(decoded.priority_list, self.info.priority_list)
        self.assertEqual(len(decoded.public_keys), 2)
        self.assertEqual(decoded.public_keys[0].key_identifier, 0x10)
        self.assertEqual(decoded.public_keys[0].public_key, self.hn_pub_a)
        self.assertEqual(decoded.public_keys[0].protection_scheme, ProtectionScheme.PROFILE_A)
        self.assertEqual(decoded.public_keys[1].key_identifier, 0x20)
        self.assertEqual(decoded.public_keys[1].public_key, self.hn_pub_b)
        self.assertEqual(decoded.public_keys[1].protection_scheme, ProtectionScheme.PROFILE_B)

    def test_empty_input_yields_empty_lists(self) -> None:
        decoded = decode_ef_suci_calc_info(b"")
        self.assertEqual(decoded.priority_list, [])
        self.assertEqual(decoded.public_keys, [])

    def test_truncated_priority_section_does_not_raise(self) -> None:
        # Length byte advertises 6 bytes of priority entries but only
        # 3 follow; the decoder should bail gracefully.
        decoded = decode_ef_suci_calc_info(b"\x06\x01\x01\x10")
        self.assertEqual(decoded.priority_list, [])

    def test_priority_byte_overflow_is_rejected(self) -> None:
        info = SuciCalcInfo(
            priority_list=[(1, ProtectionScheme.NULL, 0)] * 100,  # 300 bytes -> > 0xFF
            public_keys=[],
        )
        with self.assertRaises(ValueError):
            encode_ef_suci_calc_info(info)


class GetIdentityApduTests(unittest.TestCase):
    """End-to-end GET IDENTITY (CLA=80 INS=78 P2=01) over the engine."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "q.py"),
            isdr_config_path=str(root / "i.json"),
            sim_eim_identity_path=str(root / "e.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "ps"),
        )
        aid = bytes.fromhex(USIM_AID)
        _data, sw1, sw2 = self.engine.transmit(bytes([0, 0xA4, 0x04, 0x04, len(aid)]) + aid)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_default_returns_null_scheme_suci(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("80780001") + b"\x00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # default IMSI = 001010000000001, MNC length 2
        # MCC=001 MNC=01 MSIN=0000000001
        self.assertEqual(data[0], 0x01)  # SUCI / IMSI
        self.assertEqual(data[1:4].hex().upper(), "00F110")
        self.assertEqual(data[6], int(ProtectionScheme.NULL))
        self.assertEqual(data[7], 0)
        self.assertEqual(data[8:].hex().upper(), "0000000010")

    def test_profile_a_when_provisioned(self) -> None:
        hn_priv = x25519.X25519PrivateKey.from_private_bytes(b"\x33" * 32)
        hn_pub = hn_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        info = SuciCalcInfo(
            priority_list=[(1, ProtectionScheme.PROFILE_A, 0x55)],
            public_keys=[HomeNetworkPublicKey(0x55, ProtectionScheme.PROFILE_A, hn_pub)],
        )
        ok = self.engine.fs.write_ef_transparent_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.SUCI_Calc_Info"),
            encode_ef_suci_calc_info(info),
        )
        self.assertTrue(ok)
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("80780001") + b"\x00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[6], int(ProtectionScheme.PROFILE_A))
        self.assertEqual(data[7], 0x55)
        scheme_output = data[8:]
        recovered = _profile_a_decrypt(scheme_output, hn_priv.private_bytes_raw())
        # Default IMSI MSIN '0000000001'
        self.assertEqual(decode_msin_bcd(recovered), "0000000001")

    def test_invalid_p2_returns_6a86(self) -> None:
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("80780002") + b"\x00")
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_invalid_p1_returns_6a86(self) -> None:
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("80780101") + b"\x00")
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class FiveGAuthKeysPersistenceTests(unittest.TestCase):
    """derive_5g_vector should write KAUSF/KSEAF into EF.5GAUTHKEYS
    and bump EF.KAUSF-DERIVATION."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "q.py"),
            isdr_config_path=str(root / "i.json"),
            sim_eim_identity_path=str(root / "e.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "ps"),
        )
        profile = _resolve_active_profile(self.engine.state)
        assert profile is not None
        profile.auth_config.sqn = b"\x00" * 6
        self.profile = profile

    def tearDown(self) -> None:
        self._td.cleanup()

    def _build_autn(self, sqn: bytes) -> bytes:
        return build_milenage_autn(
            self.profile.auth_config.ki,
            self.profile.auth_config.opc,
            b"\x11" * 16,
            sqn,
            b"\x80\x00",
        )

    def test_kausf_kseaf_persisted_in_efs(self) -> None:
        autn = self._build_autn(bytes.fromhex("000000000010"))
        vector = self.engine.auth.derive_5g_vector(
            "5G:mnc001.mcc001.3gppnetwork.org",
            b"\x11" * 16,
            autn,
        )
        self.assertIsNotNone(vector)
        node = self.engine.fs.find_node_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.5GAUTHKEYS"),
        )
        self.assertIsNotNone(node)
        body = bytes(node.data)
        # Tag '80' || len 0x20 || KAUSF || tag '81' || len 0x20 || KSEAF
        self.assertEqual(len(body), 2 + 32 + 2 + 32)
        self.assertEqual(body[0], 0x80)
        self.assertEqual(body[1], 0x20)
        self.assertEqual(body[2:34], vector.k_ausf)
        self.assertEqual(body[34], 0x81)
        self.assertEqual(body[35], 0x20)
        self.assertEqual(body[36:68], vector.k_seaf)

    def test_kausf_derivation_counter_bumped(self) -> None:
        node = self.engine.fs.find_node_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.KAUSF-DERIVATION"),
        )
        self.assertEqual(bytes(node.data), b"\x00\x00\x00\x00")
        for expected in (1, 2, 3):
            sqn_value = expected * 0x10
            autn = self._build_autn(sqn_value.to_bytes(6, "big"))
            self.engine.auth.derive_5g_vector(
                "5G:mnc001.mcc001.3gppnetwork.org",
                b"\x11" * 16,
                autn,
            )
            node = self.engine.fs.find_node_by_path(
                ("MF", "ADF.USIM", "DF.5GS", "EF.KAUSF-DERIVATION"),
            )
            self.assertEqual(int.from_bytes(node.data[:4], "big"), expected)

    def test_failed_5g_aka_does_not_clobber_keys(self) -> None:
        # Prime EF.5GAUTHKEYS with a successful run.
        autn_ok = self._build_autn(bytes.fromhex("000000000010"))
        vector = self.engine.auth.derive_5g_vector(
            "5G:mnc001.mcc001.3gppnetwork.org",
            b"\x11" * 16,
            autn_ok,
        )
        self.assertIsNotNone(vector)
        node_after_ok = self.engine.fs.find_node_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.5GAUTHKEYS"),
        )
        body_after_ok = bytes(node_after_ok.data)
        # Now feed a tampered AUTN; derive_5g_vector returns None and
        # must NOT touch EF.5GAUTHKEYS.
        autn_bad = bytearray(self._build_autn(bytes.fromhex("000000000020")))
        autn_bad[-1] ^= 0xFF
        result = self.engine.auth.derive_5g_vector(
            "5G:mnc001.mcc001.3gppnetwork.org",
            b"\x11" * 16,
            bytes(autn_bad),
        )
        self.assertIsNone(result)
        node_after_bad = self.engine.fs.find_node_by_path(
            ("MF", "ADF.USIM", "DF.5GS", "EF.5GAUTHKEYS"),
        )
        self.assertEqual(bytes(node_after_bad.data), body_after_ok)


if __name__ == "__main__":
    unittest.main()
