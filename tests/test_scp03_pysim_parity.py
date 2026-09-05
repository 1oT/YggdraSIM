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

The implementation additionally binds a Secure Channel Session to the
logical channel on which it was authenticated. Cross-channel command
wrapping is rejected rather than silently reusing session state.
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
    return b"\x00" * 10 + bytes([KVN, 0x03, 0x60]) + CARD_CHAL + card_cryptogram


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

    def test_lchan1_rejected_when_session_was_authenticated_on_lchan0(self) -> None:
        """A Secure Channel Session cannot be reused on another channel."""
        apdu = bytes.fromhex("81E2910003BF2D00")  # SGP.22 STORE DATA on lchan 1
        with self.assertRaisesRegex(RuntimeError, "bound to logical channel 0"):
            self.ours.wrap_apdu(list(apdu))


@unittest.skipUnless(PYSIM_AVAILABLE, "pySim not installed (saip extra)")
class Scp03ColdStartCounterSpecTests(unittest.TestCase):
    """GPC §6.2.6 requires counter 1 for the first protected command."""

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

    def test_cold_start_first_cdec_uses_counter_one(self) -> None:
        apdu = bytes.fromhex("80E2800003112233")
        ours_w = bytes(self.ours.wrap_apdu(list(apdu)))
        pysim_w = self.pysim.wrap_cmd_apdu(apdu)
        self.assertEqual(
            ours_w[5:-8],
            pysim_w[5:-8],
            "Both implementations must use counter 1 per GPC §6.2.6.",
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
