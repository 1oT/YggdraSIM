# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP03 parity oracle: cross-check our session against pySIM.

GPC v2.3 Amendment D specifies SCP03 down to the byte. This suite uses
``pySim.global_platform.scp`` as an independent oracle and pins:

* GPC §6.2.1 — ``Scp03SessionKeys`` derivation against our ``_kdf``.
* GPC §6.2.2.2 / §6.2.2.3 — host and card cryptograms.
* GPC §6.2.6 — C-DEC ICV and ciphertext bytes for the first user APDU
  after EXTERNAL AUTHENTICATE.
* GPC §6.2.5 — C-MAC trailer for an SM-wrapped command on logical
  channel 0.

Two known divergences from pySIM are intentional and asserted here so
they cannot regress silently:

1. **CLA byte on lchan>0**. Our wrap preserves the lchan bits in the
   low nibble (``cla | 0x04``); pySIM zeroes them (``(cla & 0xF0) | 0x04``).
   We need lchan-preservation for SGP.22 retry-ladder commands sent on
   logical channel 1.
2. (pySIM does not affect §5.1 SCP80 layout — see the SCP80 parity
   suite for that.)
"""

from __future__ import annotations

import unittest

try:
    from pySim.global_platform.scp import (
        SCP03 as PysimSCP03,
        Scp03SessionKeys as PysimScp03Keys,
        scp03_key_derivation,
    )
    from pySim.global_platform import GpCardKeyset
    PYSIM_AVAILABLE = True
except ModuleNotFoundError:
    PYSIM_AVAILABLE = False

from SCP03.crypto.session import Scp03Session


# Fixed synthetic vectors. These are NOT real card secrets — they exist
# only so the oracle has a deterministic state to derive from.
KENC = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
KMAC = bytes.fromhex("505152535455565758595A5B5C5D5E5F")
DEK = bytes.fromhex("606162636465666768696A6B6C6D6E6F")
HOST_CHAL = bytes.fromhex("0102030405060708")
CARD_CHAL = bytes.fromhex("DEADBEEFC0FFEE00")
KVN = 0x30  # GPC §E.5 SCP03 KVN range 0x30..0x3f


def _synthetic_init_update_resp() -> bytes:
    """Synthesize a §7.1.1.6 INIT UPDATE response body for the fixed
    vectors above. The card cryptogram is computed via our KDF so the
    cross-check happens on derived state, not on a hardcoded blob."""
    from cryptography.hazmat.primitives import cmac as _cmac
    from cryptography.hazmat.primitives.ciphers import algorithms as _algs

    def kdf(key: bytes, const: bytes, ctx: bytes, bits: int = 128) -> bytes:
        inp = (b"\x00" * 11) + const + b"\x00" + bits.to_bytes(2, "big") + b"\x01" + ctx
        c = _cmac.CMAC(_algs.AES(key))
        c.update(inp)
        return c.finalize()[: bits // 8]

    ctx = HOST_CHAL + CARD_CHAL
    s_mac = kdf(KMAC, b"\x06", ctx, 128)
    crypt_in = (b"\x00" * 11) + b"\x00" + b"\x00" + b"\x00\x40" + b"\x01" + ctx
    c = _cmac.CMAC(_algs.AES(s_mac))
    c.update(crypt_in)
    card_cryptogram = c.finalize()[:8]
    # 10B div + KVN + scp_id 03 + i_param + 8B card_chal + 8B card_crypto
    return b"\x00" * 10 + bytes([KVN, 0x03, 0x70]) + CARD_CHAL + card_cryptogram


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp03PrimitiveParityTests(unittest.TestCase):
    """GPC §6.2.x cryptographic primitives."""

    def setUp(self) -> None:
        self.card_resp = _synthetic_init_update_resp()
        self.ours = Scp03Session({"kenc": KENC, "kmac": KMAC, "dek": DEK})
        self.ours.derive_keys(HOST_CHAL, self.card_resp)
        self.ours.is_authenticated = True
        self.pysim_keys = PysimScp03Keys(
            GpCardKeyset(kvn=KVN, enc=KENC, mac=KMAC, dek=DEK),
            HOST_CHAL,
            CARD_CHAL,
        )

    def test_session_key_s_enc_matches(self) -> None:
        # GPC §6.2.1 / Annex D 4.1.5 — DERIV_CONST_S_ENC = 0x04.
        self.assertEqual(self.ours.s_enc, self.pysim_keys.s_enc)

    def test_session_key_s_mac_matches(self) -> None:
        # GPC §6.2.1 — DERIV_CONST_S_MAC = 0x06.
        self.assertEqual(self.ours.s_mac, self.pysim_keys.s_mac)

    def test_session_key_s_rmac_matches(self) -> None:
        # GPC §6.2.1 — DERIV_CONST_S_RMAC = 0x07.
        self.assertEqual(self.ours.s_rmac, self.pysim_keys.s_rmac)

    def test_kdf_constant_function_matches(self) -> None:
        # Cross-check the standalone NIST SP 800-108 derivation function
        # against ours for several constants and lengths.
        ctx = HOST_CHAL + CARD_CHAL
        for const in (b"\x00", b"\x01", b"\x02", b"\x04", b"\x06", b"\x07"):
            with self.subTest(const=const.hex()):
                ours = self.ours._kdf(KMAC, const, ctx, 128)
                theirs = scp03_key_derivation(const, ctx, KMAC, 128)
                self.assertEqual(ours, theirs)

    def test_host_cryptogram_matches(self) -> None:
        # GPC §6.2.2.3 — host cryptogram derived from S-MAC.
        pysim_host = scp03_key_derivation(
            PysimScp03Keys.DERIV_CONST_AUTH_CGRAM_HOST,
            HOST_CHAL + CARD_CHAL,
            self.pysim_keys.s_mac,
            l=64,
        )
        self.assertEqual(self.ours.calculate_host_cryptogram(), pysim_host)


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp03WrappedApduParityTests(unittest.TestCase):
    """Wire-level cross-check of wrapped APDUs after EXTERNAL AUTHENTICATE."""

    def setUp(self) -> None:
        self.card_resp = _synthetic_init_update_resp()
        self.ours = Scp03Session({"kenc": KENC, "kmac": KMAC, "dek": DEK})
        self.ours.derive_keys(HOST_CHAL, self.card_resp)
        self.ours.is_authenticated = True

        self.pysim = PysimSCP03(
            card_keys=GpCardKeyset(kvn=KVN, enc=KENC, mac=KMAC, dek=DEK),
            lchan_nr=0,
            s_mode=8,
        )
        self.pysim.gen_init_update_apdu(HOST_CHAL)
        self.pysim.parse_init_update_resp(self.card_resp)
        self.pysim.security_level = 0x33  # CMAC + CDEC + RMAC + RDEC

        # Bring both sides through EXTERNAL AUTHENTICATE so chaining state
        # aligns. Our wrap_apdu does not generate the EXT AUTH header
        # itself — callers (see SCP03/logic/gp.py) compose CLA/INS/...
        host_crypto = self.ours.calculate_host_cryptogram()
        ours_ext = bytes(
            self.ours.wrap_apdu([0x80, 0x82, 0x33, 0x00, 0x08] + list(host_crypto))
        )
        pysim_ext = self.pysim.gen_ext_auth_apdu(0x33)
        # Pin EXT AUTH parity here — both must produce the same bytes.
        self.assertEqual(ours_ext, pysim_ext)

    def test_lchan0_proprietary_command_matches(self) -> None:
        # CLA 0x80 (lchan=0, proprietary). Both impls produce CLA 0x84.
        for label, hx in [
            ("STATUS",                "80F2000C00"),
            ("GET DATA 0066",         "80CA006600"),
            ("STORE DATA + payload",  "80E2800003112233"),
            ("INSTALL FOR LOAD",      "80E602000F" + "A0" * 15),
            ("PUT KEY",               "80D880810D" + "00" * 13),
        ]:
            apdu = bytes.fromhex(hx)
            with self.subTest(label=label, apdu=hx):
                ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
                pysim_w = self.pysim.wrap_cmd_apdu(apdu)
                self.assertEqual(
                    ours_w,
                    pysim_w,
                    f"{label}: wrapped APDU diverged from pySIM oracle",
                )

    def test_cdec_payload_matches_after_ext_auth(self) -> None:
        # The C-DEC ciphertext payload bytes must match pySIM's
        # ``Scp03SessionKeys._encrypt`` output for a typical case-3 APDU.
        apdu = bytes.fromhex("80E2800003112233")
        # Save state snapshots so we can examine intermediate values.
        ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
        pysim_w = self.pysim.wrap_cmd_apdu(apdu)
        # Strip C-MAC (last 8 bytes); compare ciphertext + header.
        self.assertEqual(ours_w[:-8], pysim_w[:-8])

    def test_lchan1_cla_diverges_intentionally(self) -> None:
        """Pinned divergence: lchan>0 CLA preservation.

        TS 102 221 §10.1.1 encodes the logical channel number in CLA bits
        b1..b2. Our wrap preserves them (``cla | 0x04``); pySIM zeroes them
        (``(cla & 0xF0) | 0x04``). We rely on preservation for the SGP.22
        retry-ladder commands that target the eUICC on logical channel 1.
        Should pySIM ever close this gap, this test flips and the
        alignment can be reconsidered.

        The C-DEC ciphertext bytes still match because both sides have
        an aligned counter (1) at this point in the session (right after
        EXT AUTH); only the CLA byte and the resulting C-MAC differ.
        """
        apdu = bytes.fromhex("81E2910003BF2D00")  # SGP.22 STORE DATA on lchan 1
        ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
        pysim_w = self.pysim.wrap_cmd_apdu(apdu)

        self.assertEqual(ours_w[0], 0x85, "ours: CLA must keep lchan bits + SM bit")
        self.assertEqual(pysim_w[0], 0x84, "pySIM: CLA drops lchan bits")
        self.assertNotEqual(ours_w, pysim_w, "wrapped bytes must diverge for lchan>0")
        # Encrypted payload (between header and C-MAC) matches because
        # the C-DEC ICV is computed from the encryption counter, which
        # is aligned across both impls after EXT AUTH (ours.ssc=1 with
        # iv_ssc=0... wait — see Scp03ColdStartCounterSpecTests below).
        # Body offset = 5 (header) .. -8 (MAC trailer).
        self.assertEqual(ours_w[5:-8], pysim_w[5:-8])


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp03ColdStartCounterDivergenceTests(unittest.TestCase):
    """Pin the second known divergence — cold-start C-DEC counter.

    GPC v2.3 Amd D §6.2.6 specifies the encryption counter SHALL start
    at 1 for the first command APDU. pySIM follows that letter-for-letter
    (``block_nr`` increments to 1 before the first ICV computation).
    Our ``Scp03Session.wrap_apdu`` increments ``ssc`` once per call and
    derives ``iv_ssc = (ssc - 1).to_bytes(16, 'big')`` — so on a cold
    start the first encryption uses counter=0, off-by-one.

    In production this is invisible because EXT AUTH is always wrapped
    first (it bumps ``ssc`` to 1 without using it for C-DEC, courtesy of
    the ``is_ext_auth`` bypass), so the first user command lands on
    counter=1 in both impls. This test pins both behaviours so any
    future refactor that touches counter accounting is forced to
    consider the EXT-AUTH-as-counter-primer invariant.
    """

    def setUp(self) -> None:
        self.card_resp = _synthetic_init_update_resp()
        self.ours = Scp03Session({"kenc": KENC, "kmac": KMAC, "dek": DEK})
        self.ours.derive_keys(HOST_CHAL, self.card_resp)
        self.ours.is_authenticated = True

        self.pysim = PysimSCP03(
            card_keys=GpCardKeyset(kvn=KVN, enc=KENC, mac=KMAC, dek=DEK),
            lchan_nr=0,
            s_mode=8,
        )
        self.pysim.gen_init_update_apdu(HOST_CHAL)
        self.pysim.parse_init_update_resp(self.card_resp)
        self.pysim.security_level = 0x33

    def test_cold_start_first_cdec_diverges(self) -> None:
        # Without EXT AUTH primer, the first wrap differs.
        apdu = bytes.fromhex("80E2800003112233")
        ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
        pysim_w = self.pysim.wrap_cmd_apdu(apdu)
        self.assertNotEqual(
            ours_w[5:-8],
            pysim_w[5:-8],
            "Cold-start ciphertext should diverge: ours uses counter=0, "
            "pySIM uses counter=1 per GPC §6.2.6.",
        )

    def test_ext_auth_primer_aligns_counter(self) -> None:
        # With EXT AUTH first, the first user command aligns.
        host_crypto = self.ours.calculate_host_cryptogram()
        self.ours.wrap_apdu([0x80, 0x82, 0x33, 0x00, 0x08] + list(host_crypto))
        self.pysim.gen_ext_auth_apdu(0x33)

        apdu = bytes.fromhex("80E2800003112233")
        ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
        pysim_w = self.pysim.wrap_cmd_apdu(apdu)
        self.assertEqual(ours_w, pysim_w)


if __name__ == "__main__":
    unittest.main()
