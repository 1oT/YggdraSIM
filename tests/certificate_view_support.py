# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Synthetic CI / EUM / eUICC certificates and a GetCertsResponse for the certificate-view tests.

The role and extension OIDs are literals read from SGP.22 v3.1 §2.4a.1.0 (pages 41-42), not
values taken from ``SCP11.shared.rsp_roles``, so a wrong constant there cannot pass its own
test. Names use the reserved test identifiers: ``C=XX``, the eUICC DN example of SGP.22 v3.1
§4.5.2.1.0.2 Table 11 (``o = ACME``, its EID) and that EID's EIN.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROLE_CI = "2.23.146.1.2.1.0"
ROLE_EUM = "2.23.146.1.2.1.0.0.0"
ROLE_EUICC = "2.23.146.1.2.1.0.0.0.0.0"
ROLE_EUM_V2 = "2.23.146.1.2.1.2"
# id-rspRole-dp-tls-v2 ::= {id-rspRole 3}, SGP.22 v3.1 §2.4a.1.0 (page 42).
ROLE_DP_TLS_V2 = "2.23.146.1.2.1.3"
PERMITTED_EINS = "2.23.146.1.2.2.0"
SERVER_HOST = "smdp.example.test"
EID = "89049032123451234512345678901235"
EIN = "89049032"
NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class Chain:
    ci: bytes
    eum: bytes
    euicc: bytes


def build_chain(*, eum_role: str = ROLE_EUM) -> Chain:
    """A CI, an EUM with a name constraint and Permitted EINs, and an eUICC whose subject holds the EID."""
    ci_key = ec.generate_private_key(ec.SECP256R1())
    eum_key = ec.generate_private_key(ec.SECP256R1())
    euicc_key = ec.generate_private_key(ec.SECP256R1())
    ci_name = _name((NameOID.ORGANIZATION_NAME, "Test CI"), (NameOID.COMMON_NAME, "Test CI"))
    eum_name = _name(
        (NameOID.COUNTRY_NAME, "XX"),
        (NameOID.ORGANIZATION_NAME, "ACME"),
        (NameOID.COMMON_NAME, "ACME EUM"),
    )
    euicc_name = _name((NameOID.ORGANIZATION_NAME, "ACME"), (NameOID.SERIAL_NUMBER, EID))
    # PermittedEins ::= SEQUENCE OF PrintableString, one EIN.
    permitted_eins = bytes.fromhex("300A1308") + EIN.encode("ascii")
    eum_extensions = [
        (
            x509.NameConstraints(
                permitted_subtrees=[x509.DirectoryName(_name((NameOID.ORGANIZATION_NAME, "ACME")))],
                excluded_subtrees=None,
            ),
            True,
        ),
        (x509.UnrecognizedExtension(x509.ObjectIdentifier(PERMITTED_EINS), permitted_eins), False),
    ]
    ci = certificate(ci_name, ci_name, ci_key, ci_key, ca=True, role=ROLE_CI)
    eum = certificate(eum_name, ci_name, eum_key, ci_key, ca=True, role=eum_role, extensions=eum_extensions)
    euicc = certificate(euicc_name, eum_name, euicc_key, eum_key, ca=False, role=ROLE_EUICC)
    return Chain(ci=ci, eum=eum, euicc=euicc)


def certificate(
    subject: x509.Name,
    issuer: x509.Name,
    key: ec.EllipticCurvePrivateKey,
    signer: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    role: str | None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    not_before: dt.datetime = NOW - dt.timedelta(days=1),
    not_after: dt.datetime = NOW + dt.timedelta(days=400),
    serial_number: int = 1,
) -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if role is not None:
        policies = x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(role), None)])
        builder = builder.add_extension(policies, critical=True)
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def leaf(*, not_before: dt.datetime, not_after: dt.datetime, serial_number: int = 1) -> bytes:
    """A self-signed certificate without an RSP role, for the validity and serial checks."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name((NameOID.COMMON_NAME, "validity probe"))
    return certificate(
        name,
        name,
        key,
        key,
        ca=False,
        role=None,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
    )


def get_certs_response(eum: bytes, euicc: bytes) -> bytes:
    """GetCertsResponse ::= [86] CHOICE { certs SEQUENCE { eumCertificate [5], euiccCertificate [6] } }.

    SGP.32 v1.3 §5.9.10: 'BF56' { 'A0' { 'A5' ..., 'A6' ... } }; the implicit [5] / [6] replace
    each certificate's SEQUENCE tag, so only the SEQUENCE contents follow them.
    """
    certs = _tlv(b"\xa5", _sequence_contents(eum)) + _tlv(b"\xa6", _sequence_contents(euicc))
    return _tlv(b"\xbf\x56", _tlv(b"\xa0", certs))


@dataclass(frozen=True)
class TlsChain:
    root: bytes
    server: bytes


def build_tls_chain(
    *,
    dns_names: tuple[str, ...] = (SERVER_HOST,),
    common_name: str = SERVER_HOST,
    not_before: dt.datetime = NOW - dt.timedelta(days=1),
    not_after: dt.datetime = NOW + dt.timedelta(days=400),
) -> TlsChain:
    """A CI and an SM-DP+ TLS certificate it signed, as a server's Certificate message carries them.

    SGP.22 v3.1 §4.5.2.1.0.5 Table 14 has a CERT.DP.TLS hold the host name as a dNSName and
    in its CN; *dns_names* empty leaves the subjectAltName out.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name((NameOID.ORGANIZATION_NAME, "Test CI"), (NameOID.COMMON_NAME, "Test CI"))
    server_name = _name(
        (NameOID.COUNTRY_NAME, "XX"),
        (NameOID.ORGANIZATION_NAME, "ACME"),
        (NameOID.COMMON_NAME, common_name),
    )
    extensions: list[tuple[x509.ExtensionType, bool]] = []
    if len(dns_names) > 0:
        extensions.append((x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]), False))
    root = certificate(root_name, root_name, root_key, root_key, ca=True, role=ROLE_CI)
    server = certificate(
        server_name,
        root_name,
        server_key,
        root_key,
        ca=False,
        role=ROLE_DP_TLS_V2,
        extensions=extensions,
        not_before=not_before,
        not_after=not_after,
    )
    return TlsChain(root=root, server=server)


def tampered(der: bytes) -> bytes:
    """The certificate with the last octet of its signature flipped."""
    return der[:-1] + bytes([der[-1] ^ 0x01])


def _name(*attributes: tuple[x509.ObjectIdentifier, str]) -> x509.Name:
    return x509.Name([x509.NameAttribute(oid, value) for oid, value in attributes])


def _tlv(tag: bytes, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return tag + bytes([length]) + value
    if length < 0x100:
        return tag + bytes([0x81, length]) + value
    return tag + bytes([0x82, length >> 8, length & 0xFF]) + value


def _sequence_contents(der: bytes) -> bytes:
    if der[1] < 0x80:
        return der[2:]
    return der[2 + (der[1] & 0x7F):]
