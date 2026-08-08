# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Encoders and parsers produce spec-correct output for valid input.

This is the complement to tests/test_decoder_boundary_contract.py: that
suite asserts malformed input is rejected cleanly, this one asserts valid
input is encoded and parsed exactly as the standards define.

Ground truth comes only from real references, never recall:

* ``pySim.utils`` -- an independent implementation of the same ETSI/3GPP
  BCD, ICCID, IMSI, and PLMN codecs. Skipped if pySim is absent.
* ``asn1crypto`` -- an independent DER encoder for length / INTEGER / OID.
* Oracle-free properties: round-trip identity, and the ISO/IEC 7816-4
  5.1 APDU case structure, which is derivable from the encoding rules.

The PLMN check exists because a real defect shipped here:
``metadata_codec._encode_mcc_mnc`` used to concatenate the digits and
F-pad the tail (001/01 -> 00101F) instead of the 3GPP TS 24.008 10.5.1.3
nibble-swapped layout (00F110), so the SGP.22 profileOwner.mccMnc read
back as the wrong PLMN. Nothing checked the encoders against an oracle.
"""

from __future__ import annotations

import unittest

from asn1crypto.core import Integer as A1Integer, ObjectIdentifier as A1Oid

from SIMCARD.utils import (
    parse_apdu,
    tlv,
    read_tlv,
    read_tlv_header,
    encode_length,
    encode_iccid_ef,
    encode_imsi_ef,
    swap_bcd_nibbles,
)
from SIMCARD.suci import _pack_mcc_mnc
from SCP11.local_access.metadata_codec import _encode_mcc_mnc
from SCP11.eim_local.psmo_builders import _encode_length, _der_integer, _encode_oid
from Tools.ProfilePackage.saip_asn1_encode import _encode_plmn_hex

try:
    import pySim.utils as _ps

    PYSIM_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import failure disables the oracle
    PYSIM_AVAILABLE = False


# 3-digit MCC with 2- and 3-digit MNCs; the 2-digit cases exercise the
# 0xF filler placement that the shipped bug got wrong.
_PLMN_CASES = [("001", "01"), ("001", "001"), ("999", "99"), ("262", "15"), ("234", "015")]
_ICCIDS = ["8988211234567890123", "89882112345678901234"]
_IMSIS = ["001010000000001", "00101000000001"]


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class PysimCodecParityTests(unittest.TestCase):
    """The ETSI/3GPP BCD codecs must match pySim byte for byte."""

    def test_nibble_swap_matches_pysim(self) -> None:
        for hx in ["1234", "89", "0123456789ABCDEF", "F0", "00"]:
            with self.subTest(hex=hx):
                self.assertEqual(swap_bcd_nibbles(hx).upper(), _ps.swap_nibbles(hx).upper())

    def test_iccid_encoding_matches_pysim(self) -> None:
        for iccid in _ICCIDS:
            with self.subTest(iccid=iccid):
                self.assertEqual(encode_iccid_ef(iccid).hex().upper(), _ps.enc_iccid(iccid).upper())

    def test_imsi_encoding_matches_pysim(self) -> None:
        for imsi in _IMSIS:
            with self.subTest(imsi=imsi):
                self.assertEqual(encode_imsi_ef(imsi).hex().upper(), _ps.enc_imsi(imsi).upper())

    def test_plmn_encoders_match_pysim_ts24008(self) -> None:
        """Every in-repo PLMN encoder must agree with pySim.enc_plmn.

        TS 24.008 10.5.1.3: nibble-swapped TBCD, 0xF filler for a 2-digit
        MNC in the high nibble of octet 2.
        """
        for mcc, mnc in _PLMN_CASES:
            ref = _ps.enc_plmn(mcc, mnc).upper()
            with self.subTest(mcc=mcc, mnc=mnc):
                self.assertEqual(_pack_mcc_mnc(mcc, mnc).hex().upper(), ref, "suci._pack_mcc_mnc")
                self.assertEqual(_encode_plmn_hex(f"{mcc}-{mnc}").hex().upper(), ref, "saip._encode_plmn_hex")
                self.assertEqual(
                    _encode_mcc_mnc(mcc, mnc).hex().upper(), ref, "metadata._encode_mcc_mnc"
                )


class DerEncoderParityTests(unittest.TestCase):
    """DER length / INTEGER / OID against asn1crypto and ISO/IEC 8825-1."""

    @staticmethod
    def _der_value(tlv_bytes: bytes) -> bytes:
        length_octet = tlv_bytes[1]
        start = 2 if length_octet < 0x80 else 2 + (length_octet & 0x7F)
        return tlv_bytes[start:]

    def test_definite_length_matches_iso8825(self) -> None:
        def ref(n: int) -> bytes:
            if n < 0x80:
                return bytes([n])
            body = n.to_bytes((n.bit_length() + 7) // 8, "big")
            return bytes([0x80 | len(body)]) + body

        for n in [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1234, 0xFFFF, 0x10000]:
            with self.subTest(n=n):
                self.assertEqual(encode_length(n), ref(n))
                self.assertEqual(_encode_length(n), ref(n))

    def test_integer_matches_asn1crypto(self) -> None:
        for n in [0, 1, 127, 128, 255, 256, 32767, 32768, 65535]:
            with self.subTest(n=n):
                self.assertEqual(_der_integer(n), self._der_value(A1Integer(n).dump()))

    def test_oid_matches_asn1crypto(self) -> None:
        for oid in ["1.2.840.113549", "2.999.10", "1.3.6.1.4.1.11111", "2.25.999999999"]:
            with self.subTest(oid=oid):
                self.assertEqual(_encode_oid(oid), self._der_value(A1Oid(oid).dump()))


class ApduCaseParsingTests(unittest.TestCase):
    """ISO/IEC 7816-4 5.1: parse_apdu extracts the right Lc/Le/data."""

    HDR = "00A40004"

    def _parse(self, apdu_hex: str):
        return parse_apdu(bytes.fromhex(apdu_hex))

    def test_case1_header_only(self) -> None:
        p = self._parse(self.HDR)
        self.assertEqual(p["data"], b"")
        self.assertIsNone(p["le"])

    def test_case2s_short_le(self) -> None:
        self.assertEqual(self._parse(self.HDR + "05")["le"], 5)
        self.assertEqual(self._parse(self.HDR + "00")["le"], 256)

    def test_case3s_short_lc(self) -> None:
        p = self._parse(self.HDR + "03AABBCC")
        self.assertEqual(p["data"].hex().upper(), "AABBCC")
        self.assertIsNone(p["le"])

    def test_case4s_lc_and_le(self) -> None:
        p = self._parse(self.HDR + "03AABBCC07")
        self.assertEqual(p["data"].hex().upper(), "AABBCC")
        self.assertEqual(p["le"], 7)

    def test_case2e_extended_le(self) -> None:
        self.assertEqual(self._parse(self.HDR + "00012C")["le"], 300)
        self.assertEqual(self._parse(self.HDR + "000000")["le"], 65536)

    def test_case3e_and_4e_extended_lc(self) -> None:
        body = "AB" * 300
        p3 = self._parse(self.HDR + "00012C" + body)
        self.assertEqual(p3["data"].hex().upper(), body)
        self.assertIsNone(p3["le"])
        p4 = self._parse(self.HDR + "00012C" + body + "00FF")
        self.assertEqual(p4["data"].hex().upper(), body)
        self.assertEqual(p4["le"], 255)


class TlvRoundTripTests(unittest.TestCase):
    """decode(encode(x)) == x for the BER-TLV primitives."""

    def test_tlv_round_trips_including_long_form(self) -> None:
        for tag in ["80", "5A", "BF20", "BF37", "9F65"]:
            for length in [0, 1, 2, 127, 128, 200, 300]:
                value = bytes(range(256))[:1] * length
                with self.subTest(tag=tag, length=length):
                    encoded = tlv(tag, value)
                    tag_b, val_b, _raw, nxt = read_tlv(encoded, 0)
                    self.assertEqual(tag_b, bytes.fromhex(tag))
                    self.assertEqual(val_b, value)
                    self.assertEqual(nxt, len(encoded))
                    _, length_val, _, _ = read_tlv_header(encoded, 0)
                    self.assertEqual(length_val, length)


if __name__ == "__main__":
    unittest.main()
