# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import datetime
import os
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.providers import Sgp26LocalProvider


def build_cert(subject_cn, issuer_name, issuer_key, public_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                ]
            )
        )
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


class Sgp26ProviderTests(unittest.TestCase):
    def test_chain_validation_success(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            ]
        )
        root_cert = build_cert("Root CA", root_name, root_key, root_key.public_key())

        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_cert = build_cert("Inter CA", root_cert.subject, root_key, inter_key.public_key())

        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer_cert = build_cert("Issuer", inter_cert.subject, inter_key, issuer_key.public_key())

        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = os.path.join(temp_dir, "root.pem")
            inter_path = os.path.join(temp_dir, "inter.pem")
            issuer_path = os.path.join(temp_dir, "issuer.pem")

            for cert_obj, cert_path in [
                (root_cert, root_path),
                (inter_cert, inter_path),
                (issuer_cert, issuer_path),
            ]:
                with open(cert_path, "wb") as cert_file:
                    cert_file.write(cert_obj.public_bytes(serialization.Encoding.PEM))

            provider = Sgp26LocalProvider(
                trust_anchor_path=root_path,
                intermediate_paths=[inter_path],
                issuer_cert_path=issuer_path,
            )

            provider.validate_chain_time_window()
            provider.validate_chain_subject_issuers()

    def test_chain_validation_detects_issuer_mismatch(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
            ]
        )
        root_cert = build_cert("Root CA", root_name, root_key, root_key.public_key())

        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_cert = build_cert("Inter CA", root_cert.subject, root_key, inter_key.public_key())

        wrong_issuer_key = ec.generate_private_key(ec.SECP256R1())
        wrong_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Wrong Issuer"),
            ]
        )
        issuer_cert = build_cert("Issuer", wrong_name, wrong_issuer_key, wrong_issuer_key.public_key())

        with tempfile.TemporaryDirectory() as temp_dir:
            root_path = os.path.join(temp_dir, "root.pem")
            inter_path = os.path.join(temp_dir, "inter.pem")
            issuer_path = os.path.join(temp_dir, "issuer.pem")

            for cert_obj, cert_path in [
                (root_cert, root_path),
                (inter_cert, inter_path),
                (issuer_cert, issuer_path),
            ]:
                with open(cert_path, "wb") as cert_file:
                    cert_file.write(cert_obj.public_bytes(serialization.Encoding.PEM))

            provider = Sgp26LocalProvider(
                trust_anchor_path=root_path,
                intermediate_paths=[inter_path],
                issuer_cert_path=issuer_path,
            )

            with self.assertRaises(ValueError):
                provider.validate_chain_subject_issuers()


if __name__ == "__main__":
    unittest.main()
