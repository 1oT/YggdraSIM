# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SIMCARD.sgp32_packages`` pure-function helpers.

Covers: encoded_length, encode_euicc_package_error_unsigned,
decode_euicc_package_request, and package_result_seq_number.
All functions are stateless; no card transport is involved.
"""

from __future__ import annotations

import unittest

from SIMCARD.sgp32_packages import (
    EuiccPackageDecodeError,
    decode_euicc_package_request,
    encode_euicc_package_error_unsigned,
    encoded_length,
    package_result_seq_number,
)


def _tlv(tag: bytes, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return tag + bytes([length]) + value
    if length <= 0xFF:
        return tag + bytes([0x81, length]) + value
    return tag + bytes([0x82, length >> 8, length & 0xFF]) + value


def _make_package_request(
    *,
    eim_id: bytes = b"test-eim",
    eid: bytes = b"\x00" * 16,
    counter: bytes = b"\x01",
    psmo_body: bytes = b"",
    sig: bytes = b"\xAB" * 64,
) -> bytes:
    """Assemble a minimal valid ``BF51 EuiccPackageRequest`` blob."""
    signed_inner = (
        _tlv(bytes.fromhex("80"), eim_id)
        + _tlv(bytes.fromhex("5A"), eid)
        + _tlv(bytes.fromhex("81"), counter)
        + _tlv(bytes.fromhex("A0"), psmo_body)
    )
    signed = _tlv(b"\x30", signed_inner)
    sig_tlv = _tlv(bytes.fromhex("5F37"), sig)
    inner = signed + sig_tlv
    return _tlv(bytes.fromhex("BF51"), inner)


class EncodedLengthTests(unittest.TestCase):

    def test_zero(self) -> None:
        self.assertEqual(encoded_length(0), b"\x00")

    def test_single_byte_boundary(self) -> None:
        self.assertEqual(encoded_length(127), b"\x7F")

    def test_128_uses_long_form(self) -> None:
        # ISO 8825-1: 128 must use 0x81 0x80.
        result = encoded_length(128)
        self.assertEqual(result, bytes([0x81, 0x80]))

    def test_255_long_form(self) -> None:
        self.assertEqual(encoded_length(255), bytes([0x81, 0xFF]))

    def test_256_two_byte_long_form(self) -> None:
        self.assertEqual(encoded_length(256), bytes([0x82, 0x01, 0x00]))

    def test_65535_max_two_byte(self) -> None:
        result = encoded_length(0xFFFF)
        self.assertEqual(result, bytes([0x82, 0xFF, 0xFF]))

    def test_returns_bytes(self) -> None:
        self.assertIsInstance(encoded_length(10), bytes)


class EncodeEuiccPackageErrorUnsignedTests(unittest.TestCase):

    def test_returns_bytes(self) -> None:
        result = encode_euicc_package_error_unsigned("test-eim")
        self.assertIsInstance(result, bytes)

    def test_starts_with_bf51(self) -> None:
        result = encode_euicc_package_error_unsigned("test-eim")
        self.assertTrue(result[:2].hex().upper() == "BF51")

    def test_with_transaction_id_longer(self) -> None:
        without = encode_euicc_package_error_unsigned("test-eim")
        with_txn = encode_euicc_package_error_unsigned(
            "test-eim", eim_transaction_id=b"\xAB\xCD"
        )
        self.assertGreater(len(with_txn), len(without))

    def test_with_association_token_longer(self) -> None:
        without = encode_euicc_package_error_unsigned("test-eim")
        with_token = encode_euicc_package_error_unsigned(
            "test-eim", association_token=42
        )
        self.assertGreater(len(with_token), len(without))

    def test_no_token_omits_token_field(self) -> None:
        # TAG_ASSOCIATION_TOKEN is 0x84; verify it does not appear when omitted.
        result = encode_euicc_package_error_unsigned("test-eim")
        # 0x84 may appear as a length byte; check it does not appear as a tag
        # by verifying the with-token form is genuinely larger.
        without = result
        with_token = encode_euicc_package_error_unsigned(
            "test-eim", association_token=0
        )
        self.assertGreater(len(with_token), len(without))

    def test_empty_eim_id_still_builds(self) -> None:
        result = encode_euicc_package_error_unsigned("")
        self.assertTrue(result[:2].hex().upper() == "BF51")

    def test_transaction_id_and_token_combined(self) -> None:
        result = encode_euicc_package_error_unsigned(
            "test-eim",
            eim_transaction_id=b"\x01\x02",
            association_token=7,
        )
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 10)


class DecodeEuiccPackageRequestTests(unittest.TestCase):

    def test_empty_payload_raises(self) -> None:
        with self.assertRaises(EuiccPackageDecodeError):
            decode_euicc_package_request(b"")

    def test_wrong_outer_tag_raises(self) -> None:
        with self.assertRaises(EuiccPackageDecodeError):
            decode_euicc_package_request(bytes([0x01, 0x01, 0x00]))

    def test_truncated_payload_raises(self) -> None:
        # Tag BF51 claims more bytes than are present.
        with self.assertRaises((EuiccPackageDecodeError, ValueError)):
            decode_euicc_package_request(bytes.fromhex("BF5110"))

    def test_valid_request_decoded(self) -> None:
        blob = _make_package_request()
        result = decode_euicc_package_request(blob)
        self.assertEqual(result.eim_id, "test-eim")
        self.assertEqual(result.counter_value, 1)
        self.assertEqual(result.eim_signature, b"\xAB" * 64)

    def test_eid_present_in_envelope(self) -> None:
        blob = _make_package_request(eid=b"\x11" * 16)
        result = decode_euicc_package_request(blob)
        self.assertEqual(result.eid_value, b"\x11" * 16)

    def test_signed_blob_is_not_empty(self) -> None:
        blob = _make_package_request()
        result = decode_euicc_package_request(blob)
        self.assertGreater(len(result.signed_blob), 0)

    def test_signature_wrong_length_raises(self) -> None:
        blob = _make_package_request(sig=b"\xAB" * 32)
        with self.assertRaises(EuiccPackageDecodeError):
            decode_euicc_package_request(blob)

    def test_missing_required_fields_raises(self) -> None:
        # SEQUENCE body containing only eimId — missing eidValue, counterValue, package.
        signed_inner = _tlv(bytes.fromhex("80"), b"eim")
        signed = _tlv(b"\x30", signed_inner)
        sig_tlv = _tlv(bytes.fromhex("5F37"), b"\xAB" * 64)
        inner = signed + sig_tlv
        blob = _tlv(bytes.fromhex("BF51"), inner)
        with self.assertRaises(EuiccPackageDecodeError):
            decode_euicc_package_request(blob)


class PackageResultSeqNumberTests(unittest.TestCase):

    def test_empty_returns_zero(self) -> None:
        self.assertEqual(package_result_seq_number(b""), 0)

    def test_garbage_returns_zero(self) -> None:
        self.assertEqual(package_result_seq_number(b"\xFF\xFE\xFD"), 0)

    def test_well_formed_seq_extracted(self) -> None:
        # Build the A0 { 30 { 83 <seq> } } structure the function parses.
        seq_tlv = _tlv(b"\x83", bytes([0x05]))
        inner = _tlv(b"\x30", seq_tlv)
        blob = _tlv(b"\xA0", inner)
        self.assertEqual(package_result_seq_number(blob), 5)

    def test_no_seq_tag_returns_zero(self) -> None:
        inner = _tlv(b"\x30", _tlv(b"\x84", b"\x00"))
        blob = _tlv(b"\xA0", inner)
        self.assertEqual(package_result_seq_number(blob), 0)


if __name__ == "__main__":
    unittest.main()
