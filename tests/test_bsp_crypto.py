# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SIMCARD/bsp.py — BSP key derivation and BspInstance crypto.

Covers: bsp_key_derivation, BspInstance.demac_and_decrypt_one,
        BspInstance.demac_and_decrypt, BspInstance.demac_only_one,
        BspInstance.demac_only.
The encrypt/mac path is exercised as a fixture factory so we can produce
valid protected TLVs to drive the demac/decrypt methods.
"""

from __future__ import annotations

import unittest

from SIMCARD.bsp import BspCryptoError, BspInstance, bsp_key_derivation


_SHARED_SECRET = bytes(32)
_HOST_ID = bytes(8)
_EID = bytes.fromhex("8904903200000000000000000000000000")
_KEY_TYPE = 0x88
_KEY_LENGTH = 0x10
_TAG = 0x86


def _fresh_instance() -> BspInstance:
    s_enc, s_mac, mcv = bsp_key_derivation(
        shared_secret=_SHARED_SECRET,
        key_type=_KEY_TYPE,
        key_length=_KEY_LENGTH,
        host_id=_HOST_ID,
        eid=_EID,
    )
    return BspInstance(s_enc, s_mac, mcv)


def _paired_instances() -> tuple[BspInstance, BspInstance]:
    """Return two instances sharing the same key material (encrypt / decrypt pair)."""
    s_enc, s_mac, mcv = bsp_key_derivation(
        shared_secret=_SHARED_SECRET,
        key_type=_KEY_TYPE,
        key_length=_KEY_LENGTH,
        host_id=_HOST_ID,
        eid=_EID,
    )
    return BspInstance(s_enc, s_mac, mcv), BspInstance(s_enc, s_mac, mcv)


# ---------------------------------------------------------------------------
# bsp_key_derivation
# ---------------------------------------------------------------------------

class BspKeyDerivationTests(unittest.TestCase):

    def test_returns_three_16_byte_values(self) -> None:
        s_enc, s_mac, mcv = bsp_key_derivation(
            _SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, _EID
        )
        self.assertEqual(len(s_enc), 16)
        self.assertEqual(len(s_mac), 16)
        self.assertEqual(len(mcv), 16)

    def test_different_host_ids_produce_different_keys(self) -> None:
        s1, _, _ = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, b"\x01" * 8, _EID)
        s2, _, _ = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, b"\x02" * 8, _EID)
        self.assertNotEqual(s1, s2)

    def test_different_eids_produce_different_keys(self) -> None:
        eid_a = bytes.fromhex("8904903200000000000000000000000000")
        eid_b = bytes.fromhex("8904903200000000000000000000000001")
        s1, _, _ = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, eid_a)
        s2, _, _ = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, eid_b)
        self.assertNotEqual(s1, s2)

    def test_custom_length_32(self) -> None:
        s_enc, s_mac, mcv = bsp_key_derivation(
            _SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, _EID, length=32
        )
        self.assertEqual(len(s_enc), 32)
        self.assertEqual(len(s_mac), 32)
        self.assertEqual(len(mcv), 32)

    def test_deterministic_output(self) -> None:
        r1 = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, _EID)
        r2 = bsp_key_derivation(_SHARED_SECRET, _KEY_TYPE, _KEY_LENGTH, _HOST_ID, _EID)
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# demac_and_decrypt_one / demac_and_decrypt
# ---------------------------------------------------------------------------

class DemacAndDecryptOneTests(unittest.TestCase):

    def test_round_trip_single_chunk(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        plaintext = bytes(range(16))
        protected = enc_inst.encrypt_and_mac_one(_TAG, plaintext)
        recovered = dec_inst.demac_and_decrypt_one(protected)
        self.assertEqual(recovered, plaintext)

    def test_mac_corruption_raises(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        protected = enc_inst.encrypt_and_mac_one(_TAG, b"\xAA" * 16)
        corrupted = bytearray(protected)
        corrupted[-1] ^= 0xFF
        with self.assertRaises(BspCryptoError):
            dec_inst.demac_and_decrypt_one(bytes(corrupted))

    def test_empty_plaintext_round_trip(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        protected = enc_inst.encrypt_and_mac_one(_TAG, b"")
        recovered = dec_inst.demac_and_decrypt_one(protected)
        self.assertEqual(recovered, b"")


class DemacAndDecryptTests(unittest.TestCase):

    def test_multi_chunk_round_trip(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        # Force two chunks by using more bytes than max_payload_size
        plaintext = bytes(range(256)) * 4  # 1024 bytes
        protected_list = enc_inst.encrypt_and_mac(0x86, plaintext)
        self.assertGreater(len(protected_list), 1)
        recovered = dec_inst.demac_and_decrypt(protected_list)
        self.assertEqual(recovered, plaintext)

    def test_empty_list_returns_empty_bytes(self) -> None:
        inst = _fresh_instance()
        result = inst.demac_and_decrypt([])
        self.assertEqual(result, b"")


# ---------------------------------------------------------------------------
# demac_only_one / demac_only
# ---------------------------------------------------------------------------

class DemacOnlyOneTests(unittest.TestCase):

    def test_round_trip_single_chunk(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        plaintext = bytes(range(16))
        protected = enc_inst.mac_only_one(_TAG, plaintext)
        recovered = dec_inst.demac_only_one(protected)
        self.assertEqual(recovered, plaintext)

    def test_mac_corruption_raises(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        protected = enc_inst.mac_only_one(_TAG, b"\xBB" * 16)
        corrupted = bytearray(protected)
        corrupted[-1] ^= 0xFF
        with self.assertRaises(BspCryptoError):
            dec_inst.demac_only_one(bytes(corrupted))


class DemacOnlyTests(unittest.TestCase):

    def test_multi_chunk_round_trip(self) -> None:
        enc_inst, dec_inst = _paired_instances()
        plaintext = bytes(range(256)) * 4
        protected_list = enc_inst.mac_only(0x86, plaintext)
        recovered = dec_inst.demac_only(protected_list)
        self.assertEqual(recovered, plaintext)

    def test_empty_list_returns_empty_bytes(self) -> None:
        inst = _fresh_instance()
        self.assertEqual(inst.demac_only([]), b"")


if __name__ == "__main__":
    unittest.main()
