# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP03 session key length, pinned to GPC 2.3 Amendment D §6.2.1.

"The length of the session keys shall be reflected in the parameter L
(i.e. '0080' for AES-128 keys, '00C0' for AES-192 keys and '0100' for
AES-256 keys)." A session derived at the wrong length still produces a
cryptogram, just not the one the card computed, so the failure surfaces
as a cryptogram mismatch and reads like a wrong key rather than an
unsupported key length.

The derivation here is written out from clause 4.1.5 rather than called
from the implementation, so the test fails if both drift together.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

from SCP03.crypto.session import Scp03Session

HOST_CHAL = bytes.fromhex("0102030405060708")
CARD_CHAL = bytes.fromhex("DEADBEEFC0FFEE00")
KVN = 0x30


def _kdf(key: bytes, constant: bytes, context: bytes, bits: int) -> bytes:
    """NIST SP 800-108 counter mode with an AES-CMAC PRF, per §4.1.5."""

    out = b""
    counter = 1
    while len(out) < bits // 8:
        block = cmac.CMAC(algorithms.AES(key))
        block.update(
            (b"\x00" * 11)
            + constant
            + b"\x00"
            + bits.to_bytes(2, "big")
            + bytes([counter])
            + context
        )
        out += block.finalize()
        counter += 1
    return out[: bits // 8]


def _init_update_response(k_mac: bytes) -> bytes:
    """Synthesize the §7.1.1.6 response body for the given Key-MAC."""

    context = HOST_CHAL + CARD_CHAL
    s_mac = _kdf(k_mac, b"\x06", context, len(k_mac) * 8)
    card_cryptogram = _kdf(s_mac, b"\x00", context, 64)
    # 10B key diversification data, KVN, SCP id '03', i '60', challenge,
    # cryptogram. i '60' is R-MAC with R-ENCRYPTION and a random challenge,
    # so no sequence counter follows.
    return b"\x00" * 10 + bytes([KVN, 0x03, 0x60]) + CARD_CHAL + card_cryptogram


class Scp03SessionKeyLength(unittest.TestCase):
    def _session(self, key_len: int) -> Scp03Session:
        k_enc = bytes(range(0x40, 0x40 + key_len))
        k_mac = bytes(range(0x50, 0x50 + key_len))
        session = Scp03Session({
            "kenc": k_enc,
            "kmac": k_mac,
            "dek": bytes(range(0x60, 0x60 + key_len)),
        })
        session.derive_keys(HOST_CHAL, _init_update_response(k_mac))
        return session

    def test_session_keys_match_the_static_key_length(self) -> None:
        for key_len in (16, 24, 32):
            with self.subTest(bits=key_len * 8):
                session = self._session(key_len)
                self.assertEqual(len(session.s_enc), key_len)
                self.assertEqual(len(session.s_mac), key_len)
                self.assertEqual(len(session.s_rmac), key_len)

    def test_card_cryptogram_verifies_at_every_length(self) -> None:
        """A mismatch here means the two sides derived different keys."""

        for key_len in (16, 24, 32):
            with self.subTest(bits=key_len * 8):
                self._session(key_len)

    def test_host_cryptogram_stays_eight_bytes(self) -> None:
        """§6.2.2: cryptograms match the challenge length, not the key."""

        for key_len in (16, 24, 32):
            with self.subTest(bits=key_len * 8):
                session = self._session(key_len)
                self.assertEqual(len(session.calculate_host_cryptogram()), 8)


if __name__ == "__main__":
    unittest.main()
