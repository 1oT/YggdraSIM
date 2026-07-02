# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_security_domain_catalog``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_security_domain_catalog as C


class AccessDomainTests(unittest.TestCase):

    def test_round_trip_named(self) -> None:
        encoded = C.encode_access_domain("FULL_ACCESS")
        self.assertEqual(encoded, "00")
        self.assertEqual(C.decode_access_domain(encoded)["name"], "FULL_ACCESS")

    def test_unknown_byte_round_trips_as_custom(self) -> None:
        decoded = C.decode_access_domain("7F")
        self.assertEqual(decoded["name"], "CUSTOM")

    def test_catalog_lengths(self) -> None:
        self.assertEqual(len(C.access_domain_catalog()), 4)


class MslTests(unittest.TestCase):

    def test_round_trip_three_byte(self) -> None:
        msl = C.encode_msl(
            auth_response="cryptographic_checksum",
            integrity="digital_signature",
            counter_flags=["counter_present"],
            kic_hex="12",
            kid_hex="34",
        )
        decoded = C.decode_msl(msl)
        self.assertEqual(decoded["auth_response"], "cryptographic_checksum")
        self.assertEqual(decoded["integrity"], "digital_signature")
        self.assertEqual(decoded["counter_flags"], ["counter_present"])
        self.assertEqual(decoded["kic_hex"], "12")
        self.assertEqual(decoded["kid_hex"], "34")

    def test_kid_without_kic_inserts_zero_kic(self) -> None:
        msl = C.encode_msl(
            auth_response="no_security",
            integrity="no_integrity",
            kid_hex="34",
        )
        self.assertEqual(len(msl) // 2, 3)
        self.assertEqual(msl[2:4], "00")

    def test_decode_rejects_too_long(self) -> None:
        with self.assertRaises(ValueError):
            C.decode_msl("00112233")


class AfiTests(unittest.TestCase):

    def test_named_round_trip(self) -> None:
        self.assertEqual(C.encode_afi("PAYMENT"), "10")
        self.assertEqual(C.decode_afi("10")["name"], "PAYMENT")

    def test_invalid_byte(self) -> None:
        with self.assertRaises(ValueError):
            C.encode_afi("ZZ")


class KeyAttributeTests(unittest.TestCase):

    def test_key_usage_flags(self) -> None:
        encoded = C.encode_key_usage(["confidentiality", "digital_signature"])
        self.assertEqual(encoded, "0A")
        self.assertEqual(C.decode_key_usage(encoded)["flags"],
                         ["confidentiality", "digital_signature"])

    def test_key_access_named(self) -> None:
        self.assertEqual(C.encode_key_access("CONTROLLING_AUTHORITY"), "03")

    def test_key_version_buckets(self) -> None:
        self.assertEqual(C.decode_key_version("00")["bucket"], "OPEN_ISSUER")
        self.assertEqual(C.decode_key_version("72")["bucket"], "CONTROLLING_AUTHORITY")
        self.assertEqual(C.decode_key_version("10")["bucket"], "APPLICATION")
        self.assertEqual(C.decode_key_version("FF")["bucket"], "RESERVED")

    def test_key_component_named(self) -> None:
        self.assertEqual(C.encode_key_component_type("AES"), "85")
        self.assertEqual(C.decode_key_component_type("85")["name"], "AES")


class RestrictTests(unittest.TestCase):

    def test_flags_round_trip(self) -> None:
        encoded = C.encode_restrict(["RESTRICT_LOCK", "RESTRICT_DELETE"])
        self.assertEqual(encoded, "14")
        self.assertEqual(C.decode_restrict(encoded)["flags"],
                         ["RESTRICT_LOCK", "RESTRICT_DELETE"])

    def test_unknown_flag_rejected(self) -> None:
        with self.assertRaises(ValueError):
            C.encode_restrict(["RESTRICT_NONSENSE"])


if __name__ == "__main__":
    unittest.main()
