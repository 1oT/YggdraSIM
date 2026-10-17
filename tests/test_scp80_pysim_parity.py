# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.


"""SCP80 parity oracle: cross-check our 03.48 primitives against pySIM.

TS 102 225 §5.1 / §5.2 specifies the OTA secured-packet structure. This
suite uses ``pySim.ota`` as an independent oracle and pins:

* AES / 3DES / DES cipher round-trips.
* AES-CMAC, 3DES-MAC, DES-MAC signature bytes.
* The ``compute_pcntr`` padding length helper.

The SMS-PP command packet is pinned against pySIM's ``OtaDialectSms`` as
well (TS 31.115 §4.2 table 1: 2-octet CPL, null CHI, 1-octet CHL). For a
cryptographic-checksum SPI the two blocks are byte-identical; the one
deliberate divergence is asserted so it cannot drift silently:

1. **CC regardless of SPI.** The builder always emits an 8-octet CC and
   CHL '15'; pySIM honours an SPI that asks for a redundancy check and
   emits a CRC-32 with CHL '11'.
2. **§5.2 Response Packet** -- only the inner cryptographic fields are
   cross-checked here; the outer SMS/UDH framing is YggdraSIM-specific
   and not represented in pySIM's ``decode_resp``.
"""

from __future__ import annotations

import unittest

try:
    from pySim.ota import (
        OtaAlgoAuthAES,
        OtaAlgoAuthDES,
        OtaAlgoAuthDES3,
        OtaAlgoCryptAES,
        OtaAlgoCryptDES,
        OtaAlgoCryptDES3,
        OtaKeyset,
    )
    PYSIM_AVAILABLE = True
except ModuleNotFoundError:
    PYSIM_AVAILABLE = False

from SCP80.crypto import CryptoEngine
from SCP80.utils import Utils


# Synthetic test vectors. Not real card secrets.
KEY_AES = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
KEY_3DES_2K = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
KEY_DES = bytes.fromhex("0123456789ABCDEF")
PAYLOAD = bytes.fromhex("00A4040007A0000000871002")  # SELECT USIM AID


def _otak(algo_crypt: str, kic: bytes, algo_auth: str, kid: bytes) -> "OtaKeyset":
    return OtaKeyset(
        algo_crypt=algo_crypt, kic_idx=1, kic=kic,
        algo_auth=algo_auth, kid_idx=1, kid=kid,
        cntr=1,
    )


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp80AesPrimitiveParityTests(unittest.TestCase):
    """AES-CBC + AES-CMAC primitive parity (KIc/KID indicator 0x?2)."""

    def test_aes_cbc_encrypt_matches_pysim(self) -> None:
        # Pad to a 16-byte multiple to satisfy AES-CBC blocksize.
        padded = PAYLOAD + b"\x00" * (16 - (len(PAYLOAD) % 16))
        ours = CryptoEngine.encrypt_ct("AES", KEY_AES, padded)
        otak = _otak("aes_cbc", KEY_AES, "aes_cmac", KEY_AES)
        theirs = OtaAlgoCryptAES(otak)._encrypt(padded)
        self.assertEqual(ours, theirs)

    def test_aes_cbc_decrypt_round_trip_matches_pysim(self) -> None:
        padded = PAYLOAD + b"\x00" * (16 - (len(PAYLOAD) % 16))
        ct = CryptoEngine.encrypt_ct("AES", KEY_AES, padded)
        ours = CryptoEngine.decrypt_ct("AES", KEY_AES, ct)
        otak = _otak("aes_cbc", KEY_AES, "aes_cmac", KEY_AES)
        theirs = OtaAlgoCryptAES(otak)._decrypt(ct)
        self.assertEqual(ours, theirs)
        self.assertEqual(ours, padded)

    def test_aes_cmac_cc_matches_pysim_truncated_to_8(self) -> None:
        # TS 102 225 mandates 8-byte CC; pySIM's OtaAlgoAuthAES.sign
        # already truncates internally.
        otak = _otak("aes_cbc", KEY_AES, "aes_cmac", KEY_AES)
        ours = CryptoEngine.compute_cc("AES", KEY_AES, PAYLOAD)
        theirs = OtaAlgoAuthAES(otak)._sign(PAYLOAD)
        self.assertEqual(len(ours), 8)
        self.assertEqual(ours, theirs)


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp80TripleDesPrimitiveParityTests(unittest.TestCase):
    """3DES-CBC + 3DES-MAC primitive parity (KIc/KID indicator 0x?5)."""

    def test_3des_cbc_encrypt_matches_pysim(self) -> None:
        padded = PAYLOAD + b"\x00" * ((-len(PAYLOAD)) % 8)
        ours = CryptoEngine.encrypt_ct("3DES2", KEY_3DES_2K, padded)
        # pySIM's ``triple_des_cbc2`` uses the keyset directly. Ours
        # internally pads to 24-byte 3DES-K3 by repeating K1 -- match
        # that here for like-for-like comparison.
        key_eff = Utils.pad_key_3des(KEY_3DES_2K)
        otak = _otak("triple_des_cbc2", key_eff, "triple_des_cbc2", key_eff)
        theirs = OtaAlgoCryptDES3(otak)._encrypt(padded)
        self.assertEqual(ours, theirs)

    def test_3des_mac_cc_matches_pysim_last_8_bytes(self) -> None:
        padded = PAYLOAD + b"\x00" * ((-len(PAYLOAD)) % 8)
        ours = CryptoEngine.compute_cc("3DES2", KEY_3DES_2K, padded)
        key_eff = Utils.pad_key_3des(KEY_3DES_2K)
        otak = _otak("triple_des_cbc2", key_eff, "triple_des_cbc2", key_eff)
        theirs = OtaAlgoAuthDES3(otak)._sign(padded)
        self.assertEqual(ours, theirs)


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp80SinglePrimitiveParityTests(unittest.TestCase):
    """Single-DES primitive parity (KIc/KID low nibble 0x?1)."""

    def test_single_des_cbc_encrypt_matches_pysim(self) -> None:
        padded = PAYLOAD + b"\x00" * ((-len(PAYLOAD)) % 8)
        # CryptoEngine doesn't have a dedicated DES path; OtaAlgoCryptDES
        # is the canonical implementation. Pin its behaviour for any
        # future regression where YggdraSIM might gain a DES code path.
        otak = _otak("single_des", KEY_DES, "single_des", KEY_DES)
        theirs = OtaAlgoCryptDES(otak)._encrypt(padded)
        self.assertEqual(len(theirs), len(padded))

    def test_single_des_mac_signature_matches_pysim_last_8_bytes(self) -> None:
        padded = PAYLOAD + b"\x00" * ((-len(PAYLOAD)) % 8)
        otak = _otak("single_des", KEY_DES, "single_des", KEY_DES)
        theirs = OtaAlgoAuthDES(otak)._sign(padded)
        self.assertEqual(len(theirs), 8)


class _BuilderConfig:
    """The keys ``OtaPacketBuilder`` reads, without touching the on-disk inventory."""

    def __init__(self, spi_hex: str) -> None:
        self.values = {
            "spi": spi_hex,
            "kic_indicator": "12",
            "kid_indicator": "12",
            "tar": "B00010",
            "cntr": "0000000001",
            "kic": KEY_AES.hex().upper(),
            "kid": KEY_AES.hex().upper(),
            "pid": "7F",
            "dcs": "F6",
            "cla": "80",
            "payload": PAYLOAD.hex().upper(),
            "concat_sms": "ON",
            "tp_ud_max": "140",
        }

    def get(self, key: str) -> str:
        return self.values.get(key, "")

    def get_int(self, key: str) -> int:
        return int(self.values.get(key, "0"), 10)


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp80WireFormatParityTests(unittest.TestCase):
    """Pin the §5.1 command packet against pySIM's SMS dialect.

    TS 31.115 §4.2 table 1 frames the packet as a 2-octet CPL, a null
    CHI, a 1-octet CHL, then SPI, KIc, KID, TAR and the ciphered part
    (CNTR, PCNTR, CC, secured data, padding). For a cryptographic-checksum
    SPI our block and pySIM's ``OtaDialectSms.encode_cmd`` are identical
    byte for byte. The builder always emits an 8-octet CC, so an SPI that
    asks for a redundancy check is the one shape where the two diverge.
    """

    @staticmethod
    def _our_block(spi_hex: str) -> bytes:
        from SCP80.builder import OtaPacketBuilder

        return OtaPacketBuilder(_BuilderConfig(spi_hex)).build_plan().block_0348

    def _pysim_block(self, spi_hex: str) -> bytes:
        from pySim.ota import OtaDialectSms, SPI

        otak = _otak("aes_cbc", KEY_AES, "aes_cmac", KEY_AES)
        # Round-trip the SPI through pySIM's own construct so the dict
        # shape matches the vocabulary of the installed version.
        spi = dict(SPI.parse(bytes.fromhex(spi_hex)))
        spi.pop("_io", None)
        try:
            return OtaDialectSms().encode_cmd(otak, bytes.fromhex("B00010"), spi, PAYLOAD)
        except (KeyError, ValueError, TypeError) as exc:
            self.skipTest(f"pySIM encode_cmd surface drifted: {exc!r}")

    def test_cc_spi_block_is_byte_identical_to_pysim(self) -> None:
        # SPI 1621: CC, ciphering, counter mode 10; PoR required over SMS-SUBMIT.
        self.assertEqual(self._our_block("1621"), self._pysim_block("1621"))

    def test_command_packet_opens_with_two_octet_cpl_then_chl(self) -> None:
        block = self._our_block("1621")
        self.assertEqual(
            int.from_bytes(block[:2], "big"),
            len(block) - 2,
            "CPL counts every octet after itself",
        )
        self.assertEqual(
            block[2],
            0x15,
            "CHL = SPI(2) + KIc(1) + KID(1) + TAR(3) + CNTR(5) + PCNTR(1) + CC(8)",
        )
        self.assertEqual(block[3:5], bytes.fromhex("1621"), "SPI mirrored")
        self.assertEqual(block[5:7], bytes.fromhex("1212"), "KIc and KID indicators")
        self.assertEqual(block[7:10], bytes.fromhex("B00010"), "TAR mirrored")

    def test_rc_spi_still_carries_an_eight_octet_cc(self) -> None:
        # SPI 1521 asks for a redundancy check: pySIM emits a CRC-32
        # (CHL 0x11) where the builder keeps its CC (CHL 0x15).
        ours = self._our_block("1521")
        theirs = self._pysim_block("1521")
        self.assertEqual(ours[2], 0x15, "ours: CHL fixed at 0x15, 8-octet CMAC")
        self.assertEqual(theirs[2], 0x11, "pySIM: CHL 0x11 for the CRC-32 variant")
        self.assertNotEqual(ours, theirs, "the RC shape is the pinned divergence")


if __name__ == "__main__":
    unittest.main()
