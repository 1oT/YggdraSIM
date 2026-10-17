# SPDX-License-Identifier: GPL-3.0-or-later
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
    """ETSI TS 102 226 V19.0.0 §8.2.1.3.2.4 and TS 102 225 V19.0.0 §5.1.1."""

    def test_the_data_byte_is_the_first_spi_octet(self) -> None:
        # b2-b1 cryptographic checksum, b3 ciphering, b5-b4 counter higher.
        self.assertEqual(
            C.encode_msl(integrity="cryptographic_checksum", ciphering="ciphering", counter="counter_higher"),
            "16",
        )
        decoded = C.decode_msl("16")
        self.assertEqual(
            (decoded["integrity"], decoded["ciphering"], decoded["counter"]),
            ("cryptographic_checksum", "ciphering", "counter_higher"),
        )
        self.assertIsNone(decoded["parameter"])

    def test_a_field_leads_with_the_minimum_spi1_parameter(self) -> None:
        field = C.encode_msl(integrity="cryptographic_checksum", counter="counter_higher", field=True)
        self.assertEqual(field, "0112")
        self.assertEqual(C.decode_msl(field)["parameter"], "minimum_spi1")
        self.assertFalse(C.decode_msl("")["check"])

    def test_decode_rejects_what_is_neither(self) -> None:
        for value in ("0212", "00112233"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                C.decode_msl(value)


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
        # GP Card Spec v2.3.1 Table 11-19: '03'-'1F' are RFU.
        self.assertEqual(C.encode_key_access("ASSOCIATED_APPLICATIONS_NOT_SD"), "02")
        self.assertEqual(C.encode_key_access("NOT_AVAILABLE"), "FF")
        self.assertEqual(C.decode_key_access("03")["name"], "CUSTOM")

    def test_key_usage_takes_two_bytes(self) -> None:
        # Tables 11-17 and 11-18: a one-byte qualifier is the first byte.
        self.assertEqual(C.decode_key_usage("38")["flags"], ["sm_response", "sm_command", "confidentiality"])
        self.assertEqual(C.encode_key_usage(["crypto_checksum", "key_agreement"]), "0480")

    def test_key_component_types_follow_table_11_16(self) -> None:
        self.assertEqual(C.encode_key_component_type("AES"), "88")
        self.assertEqual(C.decode_key_component_type("85")["name"], "TLS_PSK")

    def test_key_version_range_and_labels(self) -> None:
        # GP Card Spec v2.3.1 §11.8.2.1: '01' to '7F'. TCA SAIP v3.4.1 page
        # 136 loads a token key under '70' and a receipt key under '71'.
        from Tools.ProfilePackage.saip_asn1_decode import _decode_key_version_number

        self.assertEqual(C.decode_key_version("71")["bucket"], "IN_RANGE")
        self.assertEqual(C.decode_key_version("00")["bucket"], "OUT_OF_RANGE")
        self.assertEqual(C.decode_key_version("FF")["bucket"], "OUT_OF_RANGE")
        for byte in (0x01, 0x11, 0x30, 0x71, 0xFF):
            with self.subTest(kvn=byte):
                self.assertEqual(
                    C.decode_key_version(f"{byte:02X}")["reserved_for"],
                    (_decode_key_version_number(bytes([byte])) or {}).get("reservedFor"),
                )


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
