# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Certificate layouts: the shape of a reference certificate on a certificate of the Local eIM's own.

The references are built here with the extension set an operator's eIM PKI
gives its TLS leaf and root (AuthorityKeyIdentifier, a critical KeyUsage, a
critical ExtendedKeyUsage with both TLS purposes, a SubjectAltName with the
host and a registeredID, CRL distribution points, SubjectKeyIdentifier; the
root with critical BasicConstraints and certificate policies), under names
from the reserved ranges. What must follow the Local eIM (host, eimId, keys,
serial) and what must stay as the reference has it are checked member by member.
"""

from __future__ import annotations

import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID, ObjectIdentifier

from SCP11.eim_local.engine import cert_layout
from SCP11.shared.eim_builder_store import import_certificates

REFERENCE_HOST = "eim-reference.example.test"
REFERENCE_OID = "2.999.20"
LOCAL_HOST = "eim.example.test"
LOCAL_OID = "1.3.6.1.4.1.32473.999.10.124"
CRL_URI = "http://crl.example.test/CRL-A.crl"
# Test geography and organisation only (CLAUDE.md, real-identifier rule).
_SUBJECT_TAIL = (
    (NameOID.COUNTRY_NAME, "XX"),
    (NameOID.STATE_OR_PROVINCE_NAME, "TestState"),
    (NameOID.LOCALITY_NAME, "TestLocality"),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Subscription management"),
    (NameOID.ORGANIZATION_NAME, "Example Org"),
    (NameOID.EMAIL_ADDRESS, "eim@example.test"),
)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
                     + [x509.NameAttribute(oid, value) for oid, value in _SUBJECT_TAIL])


def _crl() -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(CRL_URI)], relative_name=None, reasons=None, crl_issuer=None,
    )])


def reference_ca(common_name: str = "EXAMPLE SM IoT ROOT") -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A root in the shape of an operator PKI's: SKI, critical cA, critical policies, certSign + cRLSign, a registeredID."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _name(common_name)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(0x50000000).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 35))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier("2.999.1.2"), None)]),
                       critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RegisteredID(ObjectIdentifier("2.999.100"))]), critical=False)
        .add_extension(_crl(), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def reference_leaf(
    *,
    common_name: str = "EXAMPLE SM-EIM - CERT.EIM.TLS",
    host: str = REFERENCE_HOST,
    oid: str = REFERENCE_OID,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
) -> x509.Certificate:
    """A TLS leaf in the shape of an operator PKI's: AKI, KU!, EKU! (server and client), SAN host + registeredID, CRL DP, SKI."""
    ca, ca_key = issuer if issuer is not None else reference_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(0x50000002).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=397))
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                       critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host), x509.RegisteredID(ObjectIdentifier(oid))]),
                       critical=False)
        .add_extension(_crl(), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def shaped(layout: cert_layout.CertificateLayout, *, host: str = LOCAL_HOST, eim_id: str = LOCAL_OID,
           self_signed: bool = False) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, ec.EllipticCurvePrivateKey]:
    """A certificate built from *layout* the way the TLS setup builder does; returns it with its key and issuer key."""
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = key if self_signed else ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(layout.subject(host)).issuer_name(_name("issuer"))
        .public_key(key.public_key()).serial_number(layout.serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
    )
    builder = layout.add_extensions(builder, public_key=key.public_key(), issuer_public_key=issuer_key.public_key(),
                                    host=host, eim_id=eim_id)
    return builder.sign(issuer_key, layout.hash_algorithm() or hashes.SHA256()), key, issuer_key


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


class LayoutReadingTests(unittest.TestCase):
    def test_the_layout_reads_the_shape_not_the_identity(self) -> None:
        layout = cert_layout.from_certificate(reference_leaf(), "leaf")
        self.assertFalse(layout.is_ca)
        self.assertEqual(layout.host_names, (REFERENCE_HOST,))
        self.assertEqual((layout.hash_name, layout.key_name, layout.serial_octets), ("sha256", "secp256r1", 4))
        self.assertEqual(layout.validity_days, 398)
        described = layout.describe()
        for word in ("end entity", "AKI, KU!, EKU!, SAN, CRL DP, SKI", "serial 4 octets", "sha256", "secp256r1"):
            self.assertIn(word, described)
        ca = cert_layout.from_certificate(reference_ca()[0], "root")
        self.assertTrue(ca.is_ca)
        self.assertEqual(ca.host_names, ())
        self.assertIn("SKI, BC!, Policies!, KU!, SAN, CRL DP", ca.describe())

    def test_a_host_in_the_common_name_counts_as_the_references_host(self) -> None:
        layout = cert_layout.from_certificate(reference_leaf(common_name=REFERENCE_HOST), "leaf")
        self.assertEqual(layout.host_names, (REFERENCE_HOST,))
        self.assertEqual(layout.subject(LOCAL_HOST).get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, LOCAL_HOST)


class LayoutApplicationTests(unittest.TestCase):
    def test_the_subject_keeps_every_attribute_in_order_and_a_product_name_cn(self) -> None:
        reference = reference_leaf()
        layout = cert_layout.from_certificate(reference, "leaf")
        subject = layout.subject(LOCAL_HOST)
        self.assertEqual([attribute.oid for rdn in subject.rdns for attribute in rdn],
                         [attribute.oid for rdn in reference.subject.rdns for attribute in rdn])
        self.assertEqual(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "EXAMPLE SM-EIM - CERT.EIM.TLS")
        self.assertEqual(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, "Example Org")
        self.assertEqual(subject.public_bytes()[:2], reference.subject.public_bytes()[:2])
        renamed = layout.subject(LOCAL_HOST, common_name="EXAMPLE SM-EIM intermediate CA")
        self.assertEqual(renamed.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "EXAMPLE SM-EIM intermediate CA")

    def test_the_extensions_follow_the_reference_with_the_local_values(self) -> None:
        reference = reference_leaf()
        layout = cert_layout.from_certificate(reference, "leaf")
        certificate, key, issuer_key = shaped(layout)
        self.assertEqual([(extension.oid, extension.critical) for extension in certificate.extensions],
                         [(extension.oid, extension.critical) for extension in reference.extensions])
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [LOCAL_HOST])
        self.assertEqual([item.dotted_string for item in san.get_values_for_type(x509.RegisteredID)], [LOCAL_OID])
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
                         x509.SubjectKeyIdentifier.from_public_key(key.public_key()))
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
                         x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()).digest)
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.KeyUsage).value,
                         reference.extensions.get_extension_for_class(x509.KeyUsage).value)
        self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value,
                         reference.extensions.get_extension_for_class(x509.CRLDistributionPoints).value)
        self.assertEqual((certificate.serial_number.bit_length() + 8) // 8, 4)
        self.assertNotEqual(certificate.serial_number, reference.serial_number)
        self.assertEqual(certificate.signature_hash_algorithm.name, "sha256")

    def test_a_registered_id_is_dropped_when_the_eim_id_is_not_an_oid(self) -> None:
        layout = cert_layout.from_certificate(reference_leaf(), "leaf")
        certificate, _key, _issuer = shaped(layout, eim_id="")
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(list(san), [x509.DNSName(LOCAL_HOST)])

    def test_a_ca_layout_keeps_policies_and_constraints_and_gets_fresh_identifiers(self) -> None:
        reference, _key = reference_ca()
        layout = cert_layout.from_certificate(reference, "root")
        certificate, key, _issuer = shaped(layout, host="", self_signed=True)
        self.assertEqual([(extension.oid, extension.critical) for extension in certificate.extensions],
                         [(extension.oid, extension.critical) for extension in reference.extensions])
        self.assertTrue(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.CertificatePolicies).value,
                         reference.extensions.get_extension_for_class(x509.CertificatePolicies).value)
        self.assertEqual(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
                         x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest)
        self.assertEqual(certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                         .get_values_for_type(x509.RegisteredID)[0].dotted_string, LOCAL_OID)
        self.assertEqual(certificate.subject, reference.subject)

    def test_serial_numbers_are_positive_and_of_the_reference_length(self) -> None:
        layout = cert_layout.from_certificate(reference_leaf(), "leaf")
        for _ in range(50):
            serial = layout.serial_number()
            self.assertGreater(serial, 0)
            self.assertLessEqual((serial.bit_length() + 8) // 8, 4)


class LayoutSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)

    def test_a_reference_comes_from_the_builder_store_or_a_file(self) -> None:
        leaf = reference_leaf()
        store = self.directory / "store"
        import_certificates(_pem(leaf), name="EXAMPLE-EIM-TLS", directory=store)
        from_store = cert_layout.load_reference("EXAMPLE-EIM-TLS", store_directory=store)
        self.assertEqual(from_store.label, "stored certificate EXAMPLE-EIM-TLS")
        self.assertEqual(from_store.sha256_hex, leaf.fingerprint(hashes.SHA256()).hex().upper())
        path = self.directory / "leaf.pem"
        path.write_bytes(_pem(leaf))
        from_file = cert_layout.load_reference(str(path), store_directory=store)
        self.assertTrue(from_file.label.startswith("file "))
        self.assertEqual(from_file.sha256_hex, from_store.sha256_hex)
        der = self.directory / "leaf.der"
        der.write_bytes(leaf.public_bytes(serialization.Encoding.DER))
        self.assertEqual(cert_layout.load_reference(str(der), store_directory=store).serial_octets, 4)

    def test_what_is_neither_stored_nor_a_certificate_file_is_refused(self) -> None:
        store = self.directory / "store"
        with self.assertRaisesRegex(cert_layout.LayoutError, "neither a stored certificate"):
            cert_layout.load_reference("no-such-entry", store_directory=store)
        empty = self.directory / "empty.pem"
        empty.write_text("nothing here\n")
        with self.assertRaises(cert_layout.LayoutError):
            cert_layout.load_reference(str(empty), store_directory=store)
        with self.assertRaises(cert_layout.LayoutError):
            cert_layout.load_reference("", store_directory=store)


if __name__ == "__main__":
    unittest.main()
