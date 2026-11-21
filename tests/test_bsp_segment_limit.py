# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""BSP segments of a Bound Profile Package stay within 1020 bytes (SGP.22 v3.1 section 2.5.3)."""

from __future__ import annotations

import types
import unittest

import SCP11.local_access.session as local_access_session
from SCP11.shared.ber_tlv import encode_ber_length
from SCP11.shared.bsp_segment_limit import (
    MAX_SEGMENT_SIZE,
    BspSegmentTooLong,
    check_segment_sizes,
    encrypted_payload_limit,
    install_encrypted_segment_limit,
)
from SIMCARD.bsp import BspInstance as CardBspInstance
from SIMCARD.sgp import SgpLogic

KEYS = (bytes(range(16)), bytes(range(16, 32)), bytes(16))
LENGTHS = (1, 1006, 1007, 1008, 1009, 2014, 2015, 5000)


def _tlv(tag: bytes, value: bytes) -> bytes:
    return tag + encode_ber_length(len(value)) + value


def _package(profile_segments: list[bytes]) -> bytes:
    body = _tlv(bytes.fromhex("BF23"), b"\x80\x01\x00")
    body += _tlv(b"\xA0", _tlv(b"\x87", bytes(24)))
    body += _tlv(b"\xA1", _tlv(b"\x88", bytes(40)))
    body += _tlv(b"\xA3", b"".join(profile_segments))
    return _tlv(bytes.fromhex("BF36"), body)


class _BspBeforeTheFix:
    """The shape of a pySim ``BspInstance`` that fills an encrypted segment with 1008 bytes."""

    def __init__(self, s_enc: bytes, s_mac: bytes, initial_mcv: bytes) -> None:
        self.c_algo = types.SimpleNamespace(blocksize=16)
        self.max_payload_size = 1008
        self.cuts: list[int] = []

    def encrypt_and_mac_one(self, tag: int, plaintext: bytes) -> bytes:
        self.cuts.append(len(plaintext))
        return bytes([tag])

    def encrypt_and_mac(self, tag: int, plaintext: bytes) -> list[bytes]:
        return [self.encrypt_and_mac_one(tag, plaintext[start : start + 1008]) for start in range(0, len(plaintext), 1008)]


class PySimSegmentTests(unittest.TestCase):
    def setUp(self) -> None:
        local_access_session._ensure_pysim_session_bound_support()
        self.bsp_class = local_access_session.BspInstance
        if self.bsp_class is None:
            self.skipTest("pySim eSIM support is not installed")

    def test_no_encrypted_segment_is_above_1020_bytes_and_the_card_side_reads_them(self):
        for length in LENGTHS:
            with self.subTest(length=length):
                plaintext = bytes(index % 251 for index in range(length))
                segments = self.bsp_class(*KEYS).encrypt_and_mac(0x86, plaintext)
                self.assertEqual(len(segments), -(-length // 1007))
                self.assertLessEqual(max(len(segment) for segment in segments), MAX_SEGMENT_SIZE)
                self.assertEqual(CardBspInstance(*KEYS).demac_and_decrypt(segments), plaintext)

    def test_a_full_encrypted_segment_is_1020_bytes(self):
        bsp = self.bsp_class(*KEYS)
        self.assertEqual(encrypted_payload_limit(bsp), 1007)
        self.assertEqual(len(bsp.encrypt_and_mac(0x86, bytes(1007))[0]), MAX_SEGMENT_SIZE)

    def test_a_mac_only_segment_still_carries_1008_bytes(self):
        segments = self.bsp_class(*KEYS).mac_only(0x88, bytes(2500))
        self.assertEqual([len(segment) for segment in segments], [1020, 1020, 496])


class CompensationTests(unittest.TestCase):
    def test_a_class_without_the_limit_is_made_to_cut_at_1007(self):
        bsp_class = type("Bsp", (_BspBeforeTheFix,), {})

        self.assertTrue(install_encrypted_segment_limit(bsp_class))
        self.assertTrue(install_encrypted_segment_limit(bsp_class))

        bsp = bsp_class(*KEYS)
        bsp.encrypt_and_mac(0x86, bytes(2500))
        self.assertEqual(bsp.cuts, [1007, 1007, 486])

    def test_a_method_put_back_by_other_code_is_replaced_again(self):
        bsp_class = type("Bsp", (_BspBeforeTheFix,), {})
        install_encrypted_segment_limit(bsp_class)
        bsp_class.encrypt_and_mac = _BspBeforeTheFix.encrypt_and_mac

        install_encrypted_segment_limit(bsp_class)

        bsp = bsp_class(*KEYS)
        bsp.encrypt_and_mac(0x86, bytes(1008))
        self.assertEqual(bsp.cuts, [1007, 1])

    def test_a_class_that_declares_the_limit_is_left_alone(self):
        """The compensation retires itself once the pinned pySim carries the fix."""

        class Fixed(_BspBeforeTheFix):
            def __init__(self, s_enc: bytes, s_mac: bytes, initial_mcv: bytes) -> None:
                super().__init__(s_enc, s_mac, initial_mcv)
                self.max_encrypted_payload_size = 1007

        method = Fixed.encrypt_and_mac

        self.assertFalse(install_encrypted_segment_limit(Fixed))

        self.assertIs(Fixed.encrypt_and_mac, method)
        self.assertEqual(encrypted_payload_limit(Fixed(*KEYS)), 1007)


class PackageCheckTests(unittest.TestCase):
    def test_segments_up_to_1020_bytes_pass(self):
        full = _tlv(b"\x86", bytes(1016))
        self.assertEqual(len(full), MAX_SEGMENT_SIZE)
        self.assertEqual(check_segment_sizes(_package([full, full, _tlv(b"\x86", bytes(24))])), 5)

    def test_a_longer_segment_is_named(self):
        for value_length in (1017, 1032):
            with self.subTest(value_length=value_length):
                long = _tlv(b"\x86", bytes(value_length))
                with self.assertRaises(BspSegmentTooLong) as failure:
                    check_segment_sizes(_package([_tlv(b"\x86", bytes(1016)), long]))
                self.assertIn(f"segment 4 (tag '86' in 'A3') is {len(long)} bytes", str(failure.exception))

    def test_input_that_is_no_package_is_refused(self):
        whole = _package([_tlv(b"\x86", bytes(24))])
        for data in (b"", b"\xBF", bytes.fromhex("BF3682"), bytes.fromhex("BF36820400A000"), whole[:-1], _tlv(b"\x30", b"")):
            with self.subTest(data=data[:8].hex()):
                with self.assertRaises(ValueError):
                    check_segment_sizes(data)


class SimulatedCardTests(unittest.TestCase):
    def test_the_card_side_copy_cuts_encrypted_plaintext_at_1007(self):
        for length in LENGTHS:
            with self.subTest(length=length):
                plaintext = bytes(index % 251 for index in range(length))
                segments = CardBspInstance(*KEYS).encrypt_and_mac(0x86, plaintext)
                self.assertLessEqual(max(len(segment) for segment in segments), MAX_SEGMENT_SIZE)
                self.assertEqual(CardBspInstance(*KEYS).demac_and_decrypt(segments), plaintext)
        self.assertEqual([len(item) for item in CardBspInstance(*KEYS).mac_only(0x88, bytes(1009))], [1020, 11])

    def test_a_full_segment_does_not_end_a_profile_of_undeclared_length(self):
        """Segments of 1007 and of 1008 bytes are both full; only a shorter one ends the profile."""
        session = types.SimpleNamespace(bpp_section="a3", bpp_section_remaining=-1, bpp_bsp=CardBspInstance(*KEYS))
        logic = types.SimpleNamespace(state=types.SimpleNamespace(sgp_session=session))
        self.assertFalse(SgpLogic._is_final_a3_chunk(logic, bytes(1007)))
        self.assertFalse(SgpLogic._is_final_a3_chunk(logic, bytes(1008)))
        self.assertTrue(SgpLogic._is_final_a3_chunk(logic, bytes(1006)))


if __name__ == "__main__":
    unittest.main()
