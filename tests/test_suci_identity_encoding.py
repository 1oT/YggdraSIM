# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SUCI Mobile Identity encoding rules from 3GPP TS 23.003 §2.2B."""

from __future__ import annotations

import unittest

from SIMCARD.suci import ProtectionScheme, encode_suci_mobile_identity


class SuciHomeNetworkKeyIdentifier(unittest.TestCase):
    """Item 5: the identifier "shall be set to the value 0 if and only if
    null protection scheme is used".

    Both halves matter. A null-scheme SUCI carrying an identifier names a
    key that was never used; a protected SUCI carrying 0 names none at
    all. Neither is something a UDM has to accept.
    """

    def _encode(self, scheme: ProtectionScheme, key_id: int) -> bytes:
        return encode_suci_mobile_identity(
            supi_format=0,
            mcc="001",
            mnc="01",
            routing_indicator="0",
            protection_scheme=scheme,
            hn_public_key_id=key_id,
            scheme_output=b"\x21\x43\x65",
        )

    def test_null_scheme_requires_identifier_zero(self) -> None:
        self._encode(ProtectionScheme.NULL, 0)
        with self.assertRaises(ValueError):
            self._encode(ProtectionScheme.NULL, 7)

    def test_protected_scheme_rejects_identifier_zero(self) -> None:
        for scheme in (ProtectionScheme.PROFILE_A, ProtectionScheme.PROFILE_B):
            with self.subTest(scheme=scheme.name):
                self._encode(scheme, 27)
                with self.assertRaises(ValueError):
                    self._encode(scheme, 0)


if __name__ == "__main__":
    unittest.main()
