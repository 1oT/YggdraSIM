# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The certificate text codec: RFC 5280 tables whole, text read and written, certificates decoded without loss.

The rows of each table are carried here with the clause they were read from,
so the comparison holds without the specification library. The lossless
contract is checked on octets: a certificate decoded to text, read back and
built with the same keys has the same subject and the same extensions.
"""

from __future__ import annotations

import datetime
import ipaddress
import itertools
import json
import unittest
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.eim_local.engine import cert_spec
from SCP11.shared import certificate_view
from tests.test_local_eim_cert_layout import reference_ca, reference_leaf
from yggdrasim_common import x509_tables

NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
HOST = "eim5.yggdrasim.local"
EIM_ID = "2.999.10.1"


class _ExtensionRow(NamedTuple):
    clause: str
    name: str
    oid: str


# RFC 5280 §4.2.1.1 - §4.2.1.15 and §4.2.2.1 - §4.2.2.2, identifiers from Appendix A.2.
RFC5280_EXTENSIONS = tuple(
    _ExtensionRow(**row)
    for row in (
        {"clause": "4.2.1.1", "name": "authorityKeyIdentifier", "oid": "2.5.29.35"},
        {"clause": "4.2.1.2", "name": "subjectKeyIdentifier", "oid": "2.5.29.14"},
        {"clause": "4.2.1.3", "name": "keyUsage", "oid": "2.5.29.15"},
        {"clause": "4.2.1.4", "name": "certificatePolicies", "oid": "2.5.29.32"},
        {"clause": "4.2.1.5", "name": "policyMappings", "oid": "2.5.29.33"},
        {"clause": "4.2.1.6", "name": "subjectAltName", "oid": "2.5.29.17"},
        {"clause": "4.2.1.7", "name": "issuerAltName", "oid": "2.5.29.18"},
        {"clause": "4.2.1.8", "name": "subjectDirectoryAttributes", "oid": "2.5.29.9"},
        {"clause": "4.2.1.9", "name": "basicConstraints", "oid": "2.5.29.19"},
        {"clause": "4.2.1.10", "name": "nameConstraints", "oid": "2.5.29.30"},
        {"clause": "4.2.1.11", "name": "policyConstraints", "oid": "2.5.29.36"},
        {"clause": "4.2.1.12", "name": "extKeyUsage", "oid": "2.5.29.37"},
        {"clause": "4.2.1.13", "name": "cRLDistributionPoints", "oid": "2.5.29.31"},
        {"clause": "4.2.1.14", "name": "inhibitAnyPolicy", "oid": "2.5.29.54"},
        {"clause": "4.2.1.15", "name": "freshestCRL", "oid": "2.5.29.46"},
        {"clause": "4.2.2.1", "name": "authorityInfoAccess", "oid": "1.3.6.1.5.5.7.1.1"},
        {"clause": "4.2.2.2", "name": "subjectInfoAccess", "oid": "1.3.6.1.5.5.7.1.11"},
    )
)
# RFC 5280 §4.2.1.3 KeyUsage ::= BIT STRING.
RFC5280_KEY_USAGE = ("digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
                     "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly")
# RFC 5280 §4.2.1.12.
RFC5280_KEY_PURPOSES = {
    "anyExtendedKeyUsage": "2.5.29.37.0", "id-kp-serverAuth": "1.3.6.1.5.5.7.3.1",
    "id-kp-clientAuth": "1.3.6.1.5.5.7.3.2", "id-kp-codeSigning": "1.3.6.1.5.5.7.3.3",
    "id-kp-emailProtection": "1.3.6.1.5.5.7.3.4", "id-kp-timeStamping": "1.3.6.1.5.5.7.3.8",
    "id-kp-OCSPSigning": "1.3.6.1.5.5.7.3.9",
}
# RFC 5280 §4.2.1.6 GeneralName ::= CHOICE.
RFC5280_GENERAL_NAMES = ("otherName", "rfc822Name", "dNSName", "x400Address", "directoryName", "ediPartyName",
                         "uniformResourceIdentifier", "iPAddress", "registeredID")
# RFC 5280 §4.1.2.4 (MUST, SHOULD, domainComponent), §4.1.2.6 (emailAddress); identifiers from Appendix A.1.
RFC5280_ATTRIBUTES = {
    "countryName": "2.5.4.6", "organizationName": "2.5.4.10", "organizationalUnitName": "2.5.4.11",
    "dnQualifier": "2.5.4.46", "stateOrProvinceName": "2.5.4.8", "commonName": "2.5.4.3", "serialNumber": "2.5.4.5",
    "localityName": "2.5.4.7", "title": "2.5.4.12", "surname": "2.5.4.4", "givenName": "2.5.4.42",
    "initials": "2.5.4.43", "pseudonym": "2.5.4.65", "generationQualifier": "2.5.4.44",
    "domainComponent": "0.9.2342.19200300.100.1.25", "emailAddress": "1.2.840.113549.1.9.1",
}
# RFC 4514 §3: the short names a string form of a name uses.
RFC4514_SHORT_NAMES = {
    "CN": "2.5.4.3", "L": "2.5.4.7", "ST": "2.5.4.8", "O": "2.5.4.10", "OU": "2.5.4.11", "C": "2.5.4.6",
    "STREET": "2.5.4.9", "DC": "0.9.2342.19200300.100.1.25", "UID": "0.9.2342.19200300.100.1.1",
}
# RFC 5280 §4.1.2.4 DirectoryString ::= CHOICE.
RFC5280_DIRECTORY_STRINGS = ("teletexString", "printableString", "universalString", "utf8String", "bmpString")


class TableTests(unittest.TestCase):
    def test_the_extension_table_is_the_whole_clause(self) -> None:
        self.assertEqual([(info.clause, info.name, info.oid) for info in x509_tables.STANDARD_EXTENSIONS],
                         list(RFC5280_EXTENSIONS))
        # Every row has a value line or is named as written in DER only: 12 + 5 of 17.
        typed = set(cert_spec.typed_extension_names())
        raw_only = set(cert_spec.RAW_ONLY_EXTENSIONS)
        self.assertEqual(typed | raw_only, {name for _clause, name, _oid in RFC5280_EXTENSIONS})
        self.assertEqual(typed & raw_only, set())
        self.assertEqual((len(typed), len(raw_only)), (12, 5))
        catalogue = {row["name"]: row for row in cert_spec.catalogue()["extensions"]}
        self.assertEqual(list(catalogue), [name for _clause, name, _oid in RFC5280_EXTENSIONS])
        for name in typed:
            row = catalogue[name]
            self.assertNotEqual(row["widget"], "raw", name)
            # The default an editor adds reads as it stands.
            spec = cert_spec.parse_text(f"{name} = {row['default']}")
            self.assertEqual(spec.extensions[0].form, cert_spec.FORM_TYPED, name)
        for name in raw_only:
            self.assertEqual((catalogue[name]["widget"], bool(catalogue[name]["note"])), ("raw", True), name)

    def test_key_usage_purposes_names_and_strings(self) -> None:
        self.assertEqual([(bit.bit, bit.name) for bit in x509_tables.KEY_USAGE_BITS], list(enumerate(RFC5280_KEY_USAGE)))
        self.assertEqual({name: oid for oid, name in x509_tables.EXTENDED_KEY_USAGES.items()}, RFC5280_KEY_PURPOSES)
        self.assertEqual([(form.tag, form.name) for form in x509_tables.GENERAL_NAME_FORMS],
                         list(enumerate(RFC5280_GENERAL_NAMES)))
        # Seven alternatives have a line form; the two without are named.
        written = {form.name for form in x509_tables.GENERAL_NAME_FORMS if form.prefix}
        self.assertEqual(written | set(cert_spec.UNSUPPORTED_GENERAL_NAMES), set(RFC5280_GENERAL_NAMES))
        self.assertEqual((len(written), sorted(cert_spec.UNSUPPORTED_GENERAL_NAMES)), (7, ["ediPartyName", "x400Address"]))
        self.assertEqual(x509_tables.DIRECTORY_STRING_TYPES, RFC5280_DIRECTORY_STRINGS)
        self.assertEqual(x509_tables.ANY_POLICY, "2.5.29.32.0")

    def test_attribute_types(self) -> None:
        by_name = {info.name: info.oid for info in x509_tables.NAME_ATTRIBUTES}
        for name, oid in RFC5280_ATTRIBUTES.items():
            self.assertEqual(by_name.get(name), oid, name)
        short = {info.short: info.oid for info in x509_tables.NAME_ATTRIBUTES if info.short}
        self.assertEqual(short, RFC4514_SHORT_NAMES)
        self.assertEqual(len(x509_tables.NAME_ATTRIBUTES), len(RFC5280_ATTRIBUTES) + 2)
        # Each one is a subject attribute by its name, its short name and its identifier.
        for info in x509_tables.NAME_ATTRIBUTES:
            for key in filter(None, (info.name, info.short, info.oid)):
                spec = cert_spec.parse_text(f"rdn = {key}:UTF8String:x")
                self.assertEqual(spec.subject[0][0].oid, info.oid, key)
        self.assertEqual({row["oid"] for row in cert_spec.catalogue()["attributes"]}, set(by_name.values()))

    def test_the_certificate_view_reads_the_same_tables(self) -> None:
        names = certificate_view._EXTENSION_NAMES  # noqa: SLF001 - the table the views print from
        for info in x509_tables.STANDARD_EXTENSIONS:
            self.assertEqual(names[info.oid], info.heading)
        self.assertIs(certificate_view._EXTENDED_KEY_USAGES, x509_tables.EXTENDED_KEY_USAGES)  # noqa: SLF001
        self.assertIs(certificate_view._ACCESS_METHODS, x509_tables.ACCESS_METHODS)  # noqa: SLF001
        self.assertEqual([name for _attribute, name in certificate_view._KEY_USAGE_BITS],  # noqa: SLF001
                         list(RFC5280_KEY_USAGE[:7]))


class TextTests(unittest.TestCase):
    def test_a_text_reads_and_writes_in_its_canonical_form(self) -> None:
        text = "\n".join([
            "# a comment and a blank line are skipped",
            "",
            "  SUBJECT = CN={host},OU=Lab,O=Example Org,C=XX",
            "KEYUSAGE = Critical , keyAgreement,digitalSignature",
            "extendedKeyUsage = serverAuth, 1.3.6.1.5.5.7.3.2 , 2.999.5",
            "subjectAltName=DNS:{host},dns:second.example.test, ip:192.0.2.4,RID:{eim_id}, URI:https://x.example.test/a,b",
            "basicConstraints = critical, ca:false",
            "subjectKeyIdentifier = HASH",
            "authorityKeyIdentifier = 0A0b0C",
            "certificatePolicies = 2.5.29.32.0, 2.999.9",
            "authorityInfoAccess = OCSP:URI:http://ocsp.example.test, 1.3.6.1.5.5.7.48.2:URI:http://ca.example.test",
            "2.999.7.1 = critical, DER: 04 03 01 02 03",
            "nameConstraints = DER:3000",
        ])
        spec = cert_spec.parse_text(text)
        self.assertEqual(cert_spec.to_text(spec).splitlines(), [
            "subject = CN={host},OU=Lab,O=Example Org,C=XX",
            "keyUsage = critical, digitalSignature, keyAgreement",
            "extKeyUsage = serverAuth, clientAuth, 2.999.5",
            "subjectAltName = DNS:{host}, DNS:second.example.test, IP:192.0.2.4, RID:{eim_id}, "
            "URI:https://x.example.test/a,b",
            "basicConstraints = critical, CA:FALSE",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = 0A0B0C",
            "certificatePolicies = anyPolicy, 2.999.9",
            "authorityInfoAccess = ocsp:URI:http://ocsp.example.test, caIssuers:URI:http://ca.example.test",
            "2.999.7.1 = critical, DER:0403010203",
            "nameConstraints = DER:3000",
        ])
        # The canonical text reads back to the same value, and no value line holds the batch separator.
        self.assertEqual(cert_spec.parse_text(cert_spec.to_text(spec)), spec)
        self.assertNotIn(";", cert_spec.to_text(spec))
        self.assertEqual(cert_spec.describe(spec),
                         "subject given; extensions given: keyUsage!, extKeyUsage, subjectAltName, basicConstraints!, "
                         "subjectKeyIdentifier, authorityKeyIdentifier, certificatePolicies, authorityInfoAccess, "
                         "2.999.7.1!, nameConstraints")

    def test_what_is_not_written_stays_open(self) -> None:
        self.assertTrue(cert_spec.parse_text("").empty)
        self.assertTrue(cert_spec.parse_text("\n  \n# nothing\n").empty)
        self.assertEqual(cert_spec.to_text(cert_spec.CertificateSpec()), "")
        only_subject = cert_spec.parse_text("subject = CN=a")
        self.assertEqual((only_subject.subject is None, only_subject.extensions), (False, None))
        only_extensions = cert_spec.parse_text("keyUsage = digitalSignature")
        self.assertEqual((only_extensions.subject, len(only_extensions.extensions)), (None, 1))
        # An empty name and an empty extension set are written out, not left open.
        bare = cert_spec.parse_text("subject = none\nextensions = none")
        self.assertEqual((bare.subject, bare.extensions), ((), ()))
        self.assertEqual(cert_spec.to_text(bare), "subject = none\nextensions = none")
        self.assertEqual(cert_spec.describe(bare), "empty subject; extensions given: none")

    def test_the_subject_keeps_its_string_types_in_rdn_lines(self) -> None:
        text = "\n".join([
            "rdn = C:PrintableString:XX",
            "rdn = O:printablestring:Org + ou:UTF8String:hex:556E6974202B206D6F7265",
            "rdn = 2.5.4.5:PrintableString:0123",
            "rdn = commonName:IA5String:{host}",
            "rdn = title:TeletexString:Dr",
        ])
        spec = cert_spec.parse_text(text)
        self.assertEqual([[(item.oid, item.string_type, item.value) for item in rdn] for rdn in spec.subject], [
            [("2.5.4.6", "PrintableString", "XX")],
            [("2.5.4.10", "PrintableString", "Org"), ("2.5.4.11", "UTF8String", "Unit + more")],
            [("2.5.4.5", "PrintableString", "0123")],
            [("2.5.4.3", "IA5String", "{host}")],
            [("2.5.4.12", "TeletexString", "Dr")],
        ])
        # The one-line form cannot say IA5String for a CN, so the rdn lines stay.
        self.assertEqual(cert_spec.to_text(spec).splitlines(), [
            "rdn = C:PrintableString:XX",
            "rdn = O:PrintableString:Org + OU:UTF8String:hex:556E6974202B206D6F7265",
            "rdn = serialNumber:PrintableString:0123",
            "rdn = CN:IA5String:{host}",
            "rdn = title:TeletexString:Dr",
        ])
        # With the string types the one-line form gives, the one line is written.
        plain = cert_spec.parse_text("rdn = C:PrintableString:XX\nrdn = O:UTF8String:Org\nrdn = CN:UTF8String:a")
        self.assertEqual(cert_spec.to_text(plain), "subject = CN=a,O=Org,C=XX")
        # Bounds are not applied to an rdn line: the text builds what it says.
        long_name = cert_spec.parse_text("rdn = C:PrintableString:ZZZ\nrdn = CN:UTF8String:" + "a" * 70)
        key = ec.generate_private_key(ec.SECP256R1())
        resolved = cert_spec.resolve(long_name, cert_spec.BuildContext(HOST, EIM_ID, key.public_key(), key.public_key()))
        self.assertEqual(len(resolved.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value), 70)

    def test_a_line_that_does_not_read_is_refused_by_name(self) -> None:
        for text, message in (
            ("colour = red", "'colour' names no extension"),
            ("just words", "is not key = value"),
            ("= value", "is not key = value"),
            ("keyUsage = critical, digitalSignature, flying", "line 1: keyUsage: no bit 'flying'"),
            ("keyUsage =", "line 1: keyUsage: no value"),
            ("keyUsage = critical", "line 1: keyUsage: no value"),
            ("keyUsage = digitalSignature\nKEYUSAGE = keyAgreement", "line 2: KEYUSAGE is given twice"),
            ("extendedKeyUsage = serverAuth\nextKeyUsage = clientAuth", "is given twice"),
            ("extKeyUsage = teleportation", "no purpose 'teleportation'"),
            ("subjectAltName = DNS:", "DNS: has no value"),
            ("subjectAltName = carrier-pigeon:x", "is not a name"),
            ("subjectAltName = IP:300.1.1.1", "IP:300.1.1.1 does not build"),
            ("subjectAltName = RID:not-an-oid", "RID takes an object identifier"),
            ("subjectAltName = otherName:2.999.3", "otherName is written"),
            ("basicConstraints = maybe", "reads CA:TRUE or CA:FALSE"),
            ("basicConstraints = pathlen:1", "needs CA:TRUE or CA:FALSE"),
            ("subjectKeyIdentifier = sha1", "A key identifier is hash"),
            ("authorityKeyIdentifier = hash", "A key identifier is keyid"),
            ("certificatePolicies = gold", "lists object identifiers or anyPolicy"),
            ("authorityInfoAccess = smoke:URI:http://x.example.test", "is not <access method>:<name>"),
            ("nameConstraints = something", "written as DER:<hex of its value> (permitted and excluded subtrees"),
            ("2.999.1 = hello", "only the RFC 5280 extensions have a value line"),
            ("2.999.1 = DER:zz", "DER: takes the value's octets in hex"),
            ("2.999.1 = DER:", "DER: takes the value's octets in hex"),
            ("extensions = some", "extensions takes only none"),
            ("extensions = none\nkeyUsage = digitalSignature", "extensions = none stands alone"),
            ("subject = CN=a\nrdn = CN:UTF8String:a", "the subject is given once"),
            ("subject = CN=a\nsubject = CN=b", "the subject is given once"),
            ("subject =", "an empty name is written subject = none"),
            ("subject = this is not a name", "does not read as an RFC 4514 name"),
            ("subject = CN=a, O=b", "no space around ',', '+' or '='"),
            ("rdn = CN:Klingon:a", "'Klingon' is no string type"),
            ("rdn = flavour:UTF8String:a", "'flavour' names no attribute type"),
            ("rdn = CN:a", "is not type:string type:value"),
            ("rdn = CN:UTF8String:hex:zz", "hex value 'zz' is not hex"),
            ("rdn = CN:BitString:plain", "value is written hex:<hex>"),
        ):
            with self.subTest(text):
                with self.assertRaises(cert_spec.SpecError) as refused:
                    cert_spec.parse_text(text)
                self.assertIn(message, str(refused.exception))
        with self.assertRaisesRegex(cert_spec.SpecError, "at most 64 extensions"):
            cert_spec.parse_text("\n".join(f"2.999.{index} = DER:0500" for index in range(65)))
        with self.assertRaisesRegex(cert_spec.SpecError, "at most 32 rdn lines"):
            cert_spec.parse_text("\n".join("rdn = OU:UTF8String:x" for _index in range(33)))

    def test_every_key_usage_set_and_basic_constraints_form_is_der(self) -> None:
        names = [bit.name for bit in x509_tables.KEY_USAGE_BITS]
        key = ec.generate_private_key(ec.SECP256R1())
        context = cert_spec.BuildContext(HOST, EIM_ID, key.public_key(), key.public_key())
        for size in range(1, len(names) + 1):
            for chosen in itertools.combinations(names, size):
                spec = cert_spec.parse_text("keyUsage = " + ", ".join(chosen))
                der = cert_spec.resolve(spec, context).extensions[0][2]
                flags = {bit.attribute: bit.name in chosen for bit in x509_tables.KEY_USAGE_BITS}
                # A BIT STRING: the count of unused bits, then the bits from the most significant on, with
                # the trailing zero bits of a named bit list left out (ITU-T X.690 (02/2021) clause 11.2.2).
                highest = max(names.index(name) for name in chosen)
                self.assertEqual((der[0], der[1], der[2]), (0x03, highest // 8 + 2, 7 - highest % 8), chosen)
                for bit, name in enumerate(names):
                    octet = der[3 + bit // 8] if 3 + bit // 8 < len(der) else 0
                    self.assertEqual(bool(octet & (0x80 >> (bit % 8))), name in chosen, (chosen, name))
                try:
                    expected = x509.KeyUsage(**flags).public_bytes()
                except ValueError:
                    # encipherOnly / decipherOnly without keyAgreement has no class in the certificate library.
                    self.assertNotIn("keyAgreement", chosen)
                    continue
                self.assertEqual(der, expected, chosen)
        self.assertEqual(cert_spec.to_text(cert_spec.parse_text("keyUsage = decipherOnly, digitalSignature")),
                         "keyUsage = digitalSignature, decipherOnly")
        for text, expected in (
            ("CA:TRUE", x509.BasicConstraints(True, None).public_bytes()),
            ("CA:TRUE, pathlen:0", x509.BasicConstraints(True, 0).public_bytes()),
            ("CA:TRUE, pathlen:300", x509.BasicConstraints(True, 300).public_bytes()),
            ("CA:FALSE", x509.BasicConstraints(False, None).public_bytes()),
            # A path length without cA has no class in the certificate library; it is DER all the same.
            ("CA:FALSE, pathlen:3", bytes.fromhex("3003020103")),
        ):
            spec = cert_spec.parse_text(f"basicConstraints = {text}")
            self.assertEqual(cert_spec.resolve(spec, context).extensions[0][2], expected, text)

    def test_placeholders_and_key_identifiers_are_filled_for_one_leaf(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        issuer = ec.generate_private_key(ec.SECP256R1())
        spec = cert_spec.parse_text("subject = CN={host},serialNumber={eim_id},C=XX\n"
                                    "subjectAltName = DNS:{host}, RID:{eim_id}, URI:https://{host}/x\n"
                                    "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid")
        resolved = cert_spec.resolve(spec, cert_spec.BuildContext(HOST, EIM_ID, key.public_key(), issuer.public_key()))
        self.assertEqual(resolved.subject.rfc4514_string(), f"CN={HOST},2.5.4.5={EIM_ID},C=XX")
        by_oid = {oid: der for oid, _critical, der in resolved.extensions}
        self.assertEqual(by_oid["2.5.29.17"], x509.SubjectAlternativeName([
            x509.DNSName(HOST), x509.RegisteredID(x509.ObjectIdentifier(EIM_ID)),
            x509.UniformResourceIdentifier(f"https://{HOST}/x")]).public_bytes())
        self.assertEqual(by_oid["2.5.29.14"], x509.SubjectKeyIdentifier.from_public_key(key.public_key()).public_bytes())
        self.assertEqual(by_oid["2.5.29.35"],
                         x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()).public_bytes())
        # A placeholder without a value, or one that does not fit where it stands, is refused by name.
        with self.assertRaisesRegex(cert_spec.SpecError, r"\{host\} has no value \(the setup has no eIM FQDN\)"):
            cert_spec.resolve(spec, cert_spec.BuildContext("", EIM_ID, key.public_key(), issuer.public_key()))
        with self.assertRaisesRegex(cert_spec.SpecError, r"\{eim_id\} has no value"):
            cert_spec.resolve(spec, cert_spec.BuildContext(HOST, "", key.public_key(), issuer.public_key()))
        with self.assertRaisesRegex(cert_spec.SpecError,
                                    r"subjectAltName: RID:eim.example.test does not build.*which is not an object"):
            cert_spec.resolve(spec, cert_spec.BuildContext(HOST, "eim.example.test", key.public_key(), issuer.public_key()))


class CertificateTests(unittest.TestCase):
    def _rebuilt(self, certificate: x509.Certificate, key: ec.EllipticCurvePrivateKey,
                 issuer_key: ec.EllipticCurvePrivateKey) -> tuple[x509.Certificate, str]:
        """*certificate* decoded, written, read back (as text and as an editor's rows) and built with the same keys."""
        spec = cert_spec.from_certificate(certificate, issuer_public_key=issuer_key.public_key())
        text = cert_spec.to_text(spec)
        self.assertEqual(cert_spec.parse_text(text), spec)
        self.assertEqual(cert_spec.from_model(json.loads(json.dumps(cert_spec.to_model(spec)))), spec)
        resolved = cert_spec.resolve(cert_spec.parse_text(text), cert_spec.BuildContext(
            "other.example.test", "2.999.1", key.public_key(), issuer_key.public_key()))
        builder = (x509.CertificateBuilder().subject_name(resolved.subject).issuer_name(certificate.issuer)
                   .public_key(key.public_key()).serial_number(7).not_valid_before(NOW)
                   .not_valid_after(NOW + datetime.timedelta(days=1)))
        built = cert_spec.add_extensions(builder, resolved).sign(issuer_key, hashes.SHA256())
        cert_spec.check_built(built, resolved)
        return built, text

    def assert_same(self, certificate: x509.Certificate, key: ec.EllipticCurvePrivateKey,
                    issuer_key: ec.EllipticCurvePrivateKey) -> str:
        built, text = self._rebuilt(certificate, key, issuer_key)
        self.assertEqual(built.subject.public_bytes(), certificate.subject.public_bytes())
        self.assertEqual(cert_spec.raw_extensions(built), cert_spec.raw_extensions(certificate))
        return text

    def _handmade(self, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
        name = x509.Name([
            x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COUNTRY_NAME, "XX")]),
            x509.RelativeDistinguishedName([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org", _type=_ASN1Type.PrintableString),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Unit + more")]),
            x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.SERIAL_NUMBER, "0123")]),
            x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, HOST, _type=_ASN1Type.IA5String)]),
        ])
        return (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(9)
            .not_valid_before(NOW).not_valid_after(NOW + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, True, False, False, False, True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, x509.ObjectIdentifier("1.2.3.4.5")]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(HOST), x509.DNSName("*.yggdrasim.local"), x509.IPAddress(ipaddress.ip_address("192.0.2.4")),
                x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
                x509.UniformResourceIdentifier("https://eim.example.test/a,b"), x509.RFC822Name("ops@example.test"),
                x509.RegisteredID(x509.ObjectIdentifier(EIM_ID)),
                x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir, name")])),
                x509.OtherName(x509.ObjectIdentifier("2.999.3"), bytes.fromhex("0C0161"))]), critical=False)
            .add_extension(x509.IssuerAlternativeName([x509.DNSName("issuer.example.test")]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .add_extension(x509.CertificatePolicies([
                x509.PolicyInformation(x509.ObjectIdentifier("2.999.9"), None),
                x509.PolicyInformation(x509.ObjectIdentifier("2.5.29.32.0"), None)]), critical=False)
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crl.example.test/ca.crl")], None, None, None)]), critical=False)
            .add_extension(x509.FreshestCRL([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crl.example.test/delta.crl")], None, None, None)]), critical=False)
            .add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
                                       x509.UniformResourceIdentifier("http://ocsp.example.test")),
                x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"),
                                       x509.UniformResourceIdentifier("http://ca.example.test/ca.cer"))]), critical=False)
            .add_extension(x509.SubjectInformationAccess([
                x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.5"),
                                       x509.UniformResourceIdentifier("http://repository.example.test"))]), critical=False)
            .add_extension(x509.InhibitAnyPolicy(2), critical=True)
            .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("2.999.7.1"), bytes.fromhex("0403010203")),
                           critical=False)
            .sign(key, hashes.SHA256())
        )

    def test_the_reference_shapes_decode_and_build_the_same_octets(self) -> None:
        ca, ca_key = reference_ca()
        text = self.assert_same(ca, ca_key, ca_key)
        self.assertIn("basicConstraints = critical, CA:TRUE", text)
        self.assertIn("keyUsage = critical, keyCertSign, cRLSign", text)
        self.assertNotIn("DER:", text)
        # The reference leaf's key is not handed out: its text reads back, and a new key gets the same shape.
        leaf = reference_leaf()
        spec = cert_spec.from_certificate(leaf)
        text = cert_spec.to_text(spec)
        self.assertEqual(cert_spec.parse_text(text), spec)
        self.assertEqual(text.splitlines()[1:], [
            "authorityKeyIdentifier = keyid", "keyUsage = critical, digitalSignature",
            "extKeyUsage = critical, serverAuth, clientAuth",
            "subjectAltName = DNS:eim-reference.example.test, RID:2.999.20",
            "cRLDistributionPoints = URI:http://crl.example.test/CRL-A.crl", "subjectKeyIdentifier = hash",
        ])
        key = ec.generate_private_key(ec.SECP256R1())
        resolved = cert_spec.resolve(spec, cert_spec.BuildContext(HOST, EIM_ID, key.public_key(), ca_key.public_key()))
        self.assertEqual(resolved.subject.public_bytes(), leaf.subject.public_bytes())
        self.assertEqual([(oid, critical) for oid, critical, _der in resolved.extensions],
                         [(oid, critical) for oid, critical, _der in cert_spec.raw_extensions(leaf)])

    def test_a_handmade_certificate_decodes_line_by_line(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        text = self.assert_same(self._handmade(key), key, key)
        self.assertEqual(text.splitlines(), [
            "rdn = C:PrintableString:XX",
            "rdn = O:PrintableString:Org + OU:UTF8String:hex:556E6974202B206D6F7265",
            "rdn = serialNumber:PrintableString:0123",
            f"rdn = CN:IA5String:{HOST}",
            "basicConstraints = critical, CA:FALSE",
            "keyUsage = critical, digitalSignature, keyAgreement, decipherOnly",
            "extKeyUsage = serverAuth, 1.2.3.4.5",
            f"subjectAltName = DNS:{HOST}, DNS:*.yggdrasim.local, IP:192.0.2.4, IP:2001:db8::1, "
            f"URI:https://eim.example.test/a,b, email:ops@example.test, RID:{EIM_ID}, DirName:CN=dir\\, name, "
            "otherName:2.999.3:0C0161",
            "issuerAltName = DNS:issuer.example.test",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid",
            "certificatePolicies = 2.999.9, anyPolicy",
            "cRLDistributionPoints = URI:http://crl.example.test/ca.crl",
            "freshestCRL = URI:http://crl.example.test/delta.crl",
            "authorityInfoAccess = ocsp:URI:http://ocsp.example.test, caIssuers:URI:http://ca.example.test/ca.cer",
            "subjectInfoAccess = caRepository:URI:http://repository.example.test",
            "inhibitAnyPolicy = critical, DER:020102",
            "2.999.7.1 = DER:0403010203",
        ])

    def test_a_value_the_line_form_cannot_carry_keeps_its_octets(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")])
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(9)
            .not_valid_before(NOW).not_valid_after(NOW + datetime.timedelta(days=1))
            .add_extension(x509.CertificatePolicies([x509.PolicyInformation(
                x509.ObjectIdentifier("2.999.9"), ["https://cps.example.test"])]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier(None, [x509.DNSName("ca.example.test")], 5), critical=False)
            .add_extension(x509.SubjectKeyIdentifier(bytes.fromhex("0102030405")), critical=False)
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://a.example.test"),
                 x509.UniformResourceIdentifier("http://b.example.test")], None, None, None)]), critical=False)
            .add_extension(x509.NameConstraints([x509.DNSName("example.test")], None), critical=True)
            .sign(key, hashes.SHA256())
        )
        lines = self.assert_same(certificate, key, key).splitlines()
        self.assertEqual(lines[0], "subject = CN=a")
        # A policy qualifier, an authority named by issuer and serial, two names in one distribution point
        # and a name constraint have no line form; a key identifier that is not the computed one is literal.
        self.assertTrue(lines[1].startswith("certificatePolicies = DER:30"), lines[1])
        self.assertTrue(lines[2].startswith("authorityKeyIdentifier = DER:30"), lines[2])
        self.assertEqual(lines[3], "subjectKeyIdentifier = 0102030405")
        self.assertTrue(lines[4].startswith("cRLDistributionPoints = DER:30"), lines[4])
        self.assertTrue(lines[5].startswith("nameConstraints = critical, DER:30"), lines[5])
        # Without the issuer's key a key identifier alone is taken as the computed one.
        handmade = self._handmade(key)
        self.assertIn("authorityKeyIdentifier = keyid", cert_spec.to_text(cert_spec.from_certificate(handmade)))
        other = ec.generate_private_key(ec.SECP256R1())
        told = cert_spec.to_text(cert_spec.from_certificate(handmade, issuer_public_key=other.public_key()))
        self.assertRegex(told, r"authorityKeyIdentifier = [0-9A-F]{40}")

    def test_one_value_the_library_cannot_read_does_not_cost_the_others_their_lines(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a")])

        def certificate(*extensions: tuple[str, str, bool]) -> x509.Certificate:
            builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(9).not_valid_before(NOW).not_valid_after(NOW + datetime.timedelta(days=1)))
            for oid, der, critical in extensions:
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), bytes.fromhex(der)), critical=critical)
            return builder.sign(key, hashes.SHA256())

        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
        san = x509.SubjectAlternativeName([x509.DNSName(HOST)])
        for label, odd, line in (
            # A SubjectAltName that is no GeneralNames at all.
            ("no names", ("2.5.29.18", "0500", True), "issuerAltName = critical, DER:0500"),
            # encipherOnly without keyAgreement, and a path length without cA: valid octets the library has
            # no class for. Both are read from their own octets, so they keep a line.
            ("key usage", ("2.5.29.15", "03020001", True), "keyUsage = critical, encipherOnly"),
            ("path length", ("2.5.29.19", "3003020101", True), "basicConstraints = critical, CA:FALSE, pathlen:1"),
        ):
            with self.subTest(label):
                subject = certificate(odd, ("2.5.29.17", san.public_bytes().hex(), False),
                                      ("2.5.29.14", ski.public_bytes().hex(), False),
                                      ("2.5.29.35", aki.public_bytes().hex(), False),
                                      ("2.999.7.2", "", False))
                with self.assertRaises(ValueError):
                    list(subject.extensions)
                text = self.assert_same(subject, key, key)
                self.assertEqual(text.splitlines(), [
                    "subject = CN=a", line, f"subjectAltName = DNS:{HOST}", "subjectKeyIdentifier = hash",
                    "authorityKeyIdentifier = keyid", "2.999.7.2 = DER:empty",
                ])
        # A basicConstraints the line form would not write back the same way keeps its octets:
        # an encoded FALSE, a TRUE that is not 'FF', a negative path length.
        for der in ("3003010100", "3003010101", "30030201FF"):
            with self.subTest(der):
                text = self.assert_same(certificate(("2.5.29.19", der, False)), key, key)
                self.assertEqual(text.splitlines()[1], f"basicConstraints = DER:{der}")

    def test_an_empty_value_has_its_own_word(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        # A value left out is still a mistake.
        spec = cert_spec.parse_text("2.999.7.2 = DER: Empty")
        self.assertEqual((spec.extensions[0].text, cert_spec.to_text(spec)), ("", "2.999.7.2 = DER:empty"))
        self.assertEqual(cert_spec.to_model(spec)["extensions"][0]["text"], "empty")
        self.assertEqual(cert_spec.from_model(cert_spec.to_model(spec)), spec)
        self.assertEqual(cert_spec.resolve(spec, cert_spec.BuildContext(HOST, EIM_ID, key.public_key(),
                                                                       key.public_key())).extensions[0][2], b"")
        for key_text, known in (("subject", True), ("RDN", True), ("extensions", True), ("keyUsage", True),
                                ("extendedKeyUsage", True), ("2.999.7.2", True), ("colour", False), ("", False),
                                ("root:x:0:0", False)):
            self.assertEqual(cert_spec.is_key(key_text), known, key_text)

    def test_a_built_certificate_is_read_back_against_the_text(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        context = cert_spec.BuildContext(HOST, EIM_ID, key.public_key(), key.public_key())
        wanted = cert_spec.resolve(cert_spec.parse_text("subject = CN={host}\nkeyUsage = critical, digitalSignature"), context)
        other = cert_spec.resolve(cert_spec.parse_text("subject = CN=other\nkeyUsage = digitalSignature"), context)

        def build(resolved: cert_spec.ResolvedSpec) -> x509.Certificate:
            builder = (x509.CertificateBuilder().subject_name(resolved.subject).issuer_name(resolved.subject)
                       .public_key(key.public_key()).serial_number(3).not_valid_before(NOW)
                       .not_valid_after(NOW + datetime.timedelta(days=1)))
            return cert_spec.add_extensions(builder, resolved).sign(key, hashes.SHA256())

        cert_spec.check_built(build(wanted), wanted)
        with self.assertRaisesRegex(cert_spec.SpecError, "subject is not the one the text gives"):
            cert_spec.check_built(build(other), wanted)
        same_subject = cert_spec.ResolvedSpec(wanted.subject, other.extensions)
        with self.assertRaisesRegex(cert_spec.SpecError, "extensions are not the ones the text gives"):
            cert_spec.check_built(build(same_subject), wanted)
        # A part the text leaves open is not compared.
        cert_spec.check_built(build(other), cert_spec.ResolvedSpec(None, None))


class ModelTests(unittest.TestCase):
    def test_an_editor_reads_rows_and_writes_them_back(self) -> None:
        spec = cert_spec.parse_text("subject = CN={host},O=Org,C=XX\nkeyUsage = critical, digitalSignature\n"
                                    "subjectAltName = DNS:{host}, RID:{eim_id}\nbasicConstraints = critical, CA:FALSE\n"
                                    "subjectKeyIdentifier = hash\nauthorityInfoAccess = ocsp:URI:http://o.example.test\n"
                                    "certificatePolicies = anyPolicy\n2.999.7.1 = DER:0500")
        model = json.loads(json.dumps(cert_spec.to_model(spec)))
        self.assertEqual([[(item["type"], item["string"], item["value"]) for item in rdn] for rdn in model["subject"]],
                         [[("C", "PrintableString", "XX")], [("O", "UTF8String", "Org")], [("CN", "UTF8String", "{host}")]])
        rows = {row["name"]: row for row in model["extensions"]}
        self.assertEqual({name: row["widget"] for name, row in rows.items()}, {
            "keyUsage": "choice-set", "subjectAltName": "name-list", "basicConstraints": "basic",
            "subjectKeyIdentifier": "key-id", "authorityInfoAccess": "access-list", "certificatePolicies": "text-list",
            "2.999.7.1": "raw"})
        self.assertEqual(rows["subjectAltName"]["items"], [{"kind": "DNS", "value": "{host}"},
                                                           {"kind": "RID", "value": "{eim_id}"}])
        self.assertEqual(rows["basicConstraints"]["items"], {"ca": False, "pathlen": ""})
        self.assertEqual(cert_spec.from_model(model), spec)
        # An edit is made on the items; the text of a row is then ignored.
        rows["keyUsage"]["items"].append("keyAgreement")
        rows["keyUsage"]["text"] = "stale"
        rows["subjectAltName"]["items"].append({"kind": "IP", "value": "192.0.2.4"})
        rows["basicConstraints"]["items"] = {"ca": True, "pathlen": "1"}
        rows["subjectKeyIdentifier"]["items"] = {"mode": "hex", "hex": "0a0b"}
        model["subject"][1].append({"oid": "2.5.4.11", "string": "PrintableString", "value": "Unit"})
        edited = cert_spec.to_text(cert_spec.from_model(model)).splitlines()
        self.assertEqual(edited[:2], ["rdn = C:PrintableString:XX", "rdn = O:UTF8String:Org + OU:PrintableString:Unit"])
        self.assertIn("keyUsage = critical, digitalSignature, keyAgreement", edited)
        self.assertIn("subjectAltName = DNS:{host}, RID:{eim_id}, IP:192.0.2.4", edited)
        self.assertIn("basicConstraints = critical, CA:TRUE, pathlen:1", edited)
        self.assertIn("subjectKeyIdentifier = 0A0B", edited)
        # Open parts stay open, and written-out empty parts stay empty.
        self.assertTrue(cert_spec.from_model({"subject": None, "extensions": None}).empty)
        self.assertEqual(cert_spec.to_model(cert_spec.parse_text("subject = none\nextensions = none")),
                         {"subject": [], "extensions": []})

    def test_rows_that_do_not_read_are_refused_with_the_row_named(self) -> None:
        for model, message in (
            ("rows", "A certificate model is an object"),
            ({"subject": "CN=a"}, "items are a list"),
            ({"subject": [[]]}, "subject RDN 1 has no attribute"),
            ({"subject": [["CN=a"]]}, "subject RDN 1: an attribute is an object"),
            ({"subject": [[{"oid": "flavour", "value": "a"}]]}, "'flavour' names no attribute type"),
            ({"subject": [[{"oid": "2.5.4.3", "string": "Klingon", "value": "a"}]]}, "'Klingon' is no string type"),
            ({"subject": [[{"oid": "2.5.4.3", "value": "zz", "hex": True}]]}, "hex value is not hex"),
            ({"extensions": [{"oid": "2.5.29.15", "items": ["flying"]}]}, "extension 1 (keyUsage): no bit 'flying'"),
            ({"extensions": [{"oid": "2.5.29.15", "items": ["digitalSignature"]},
                             {"name": "keyUsage", "items": ["keyAgreement"]}]}, "extension 2 (keyUsage) is given twice"),
            ({"extensions": [{"oid": "2.5.29.17", "items": [{"kind": "IP", "value": "300.1.1.1"}]}]},
             "extension 1 (subjectAltName): IP:300.1.1.1 does not build"),
            ({"extensions": [{"oid": "2.999.1", "form": "raw", "text": "zz"}]},
             "extension 1 (2.999.1): DER: takes the value's octets in hex"),
            ({"extensions": [{"oid": "2.999.1", "form": "raw", "text": ""}]}, "or empty for a value without any"),
            ({"extensions": [{"oid": "2.999.1", "text": "hello"}]}, "extension 1 (2.999.1): written as DER"),
            ({"extensions": [{"oid": "colour"}]}, "'colour' names no extension"),
            ({"extensions": ["keyUsage"]}, "extension 1: a row is an object"),
            ({"extensions": [{"oid": "2.5.29.19", "items": ["ca"]}]}, "basicConstraints items are an object"),
        ):
            with self.subTest(str(model)[:60]):
                with self.assertRaises(cert_spec.SpecError) as refused:
                    cert_spec.from_model(model)
                self.assertIn(message, str(refused.exception))

    def test_the_catalogue_is_plain_data(self) -> None:
        catalogue = json.loads(json.dumps(cert_spec.catalogue()))
        self.assertEqual(sorted(catalogue), ["attributes", "extensions", "placeholders", "string_types"])
        self.assertEqual(catalogue["placeholders"], ["{host}", "{eim_id}"])
        self.assertIn("UTF8String", catalogue["string_types"])
        self.assertIn("TeletexString", catalogue["string_types"])
        self.assertNotIn("BitString", catalogue["string_types"])
        rows = {row["name"]: row for row in catalogue["extensions"]}
        self.assertEqual(rows["keyUsage"]["choices"], list(RFC5280_KEY_USAGE))
        self.assertEqual(rows["extKeyUsage"]["choices"][:3], ["anyExtendedKeyUsage", "serverAuth", "clientAuth"])
        self.assertEqual(rows["subjectAltName"]["kinds"], ["otherName", "email", "DNS", "DirName", "URI", "IP", "RID"])
        self.assertEqual(rows["authorityInfoAccess"]["methods"], ["ocsp", "caIssuers", "timeStamping", "caRepository"])
        self.assertEqual((rows["keyUsage"]["critical"], rows["basicConstraints"]["critical"]), (True, True))
        self.assertEqual({row["label"] for row in catalogue["attributes"]} >= {"CN", "O", "OU", "C", "serialNumber"}, True)


if __name__ == "__main__":
    unittest.main()
