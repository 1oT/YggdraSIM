# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_ssim_eaptls`` — TLS bundle import helpers."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_ssim_eaptls as E


try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False


def _build_self_signed_pair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TestState"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "TestLocality"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM-Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "eaptls.example.test"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@unittest.skipUnless(_HAVE_CRYPTOGRAPHY, "cryptography library not installed")
class CryptographyBackedTests(unittest.TestCase):

    def test_parse_self_signed_certificate(self) -> None:
        cert_pem, _key_pem = _build_self_signed_pair()
        info = E.parse_pem_or_der(cert_pem)
        self.assertEqual(info["kind"], "certificate")
        self.assertIn("CN=eaptls.example.test", info["metadata"]["subject"])

    def test_keys_match_true(self) -> None:
        cert_pem, key_pem = _build_self_signed_pair()
        result = E.keys_match(cert_pem, key_pem)
        self.assertTrue(result["match"])

    def test_keys_match_false_for_unrelated_pair(self) -> None:
        cert_pem, _key_a = _build_self_signed_pair()
        _cert_b, key_b = _build_self_signed_pair()
        result = E.keys_match(cert_pem, key_b)
        self.assertFalse(result["match"])

    def test_build_bundle_rejects_mismatched_pair(self) -> None:
        cert_pem, _key_a = _build_self_signed_pair()
        _cert_b, key_b = _build_self_signed_pair()
        with self.assertRaises(ValueError):
            E.build_eaptls_payload(device_cert=cert_pem, device_key=key_b)

    def test_build_bundle_with_chain(self) -> None:
        cert_pem, key_pem = _build_self_signed_pair()
        bundle = E.build_eaptls_payload(
            device_cert=cert_pem,
            device_key=key_pem,
            ca_chain=cert_pem,
        )
        self.assertEqual(len(bundle["ca_chain"]), 1)
        self.assertTrue(bundle["match_status"]["match"])


class InputValidationTests(unittest.TestCase):

    def test_parse_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            E.parse_pem_or_der(b"")

    def test_parse_rejects_garbage(self) -> None:
        with self.assertRaises(ValueError):
            E.parse_pem_or_der(b"not-a-pem")


if __name__ == "__main__":
    unittest.main()
