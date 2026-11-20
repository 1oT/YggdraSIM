# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A self-signed TLS certificate for one end of an eIM Package Injection link over HTTPS.

The IPA's listener serves HTTPS with one, and an eIM that calls it presents
one as its client certificate. The key is on NIST P-256, the curve SGP.32 v1.3
§2.6.3.2 has both ends support. A certificate made here is trusted by naming
its file on the other end, never through a CA.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os
import re
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLE_SERVER = "server"
ROLE_CLIENT = "client"
ROLES = (ROLE_SERVER, ROLE_CLIENT)
VALID_DAYS = 3650

_DNS_NAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9*]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$")
_PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class TlsIdentityError(ValueError):
    """A certificate that cannot be made, written or read as asked."""


def _general_name(name: str) -> x509.GeneralName:
    text = str(name or "").strip()
    try:
        return x509.IPAddress(ipaddress.ip_address(text))
    except ValueError:
        pass
    if _DNS_NAME.match(text) is None:
        raise TlsIdentityError(f"{name!r} is neither a host name nor an IP address.")
    return x509.DNSName(text)


def issue_self_signed(common_name: str, names: Sequence[str] = (), *, role: str) -> tuple[bytes, bytes]:
    """A self-signed certificate and its private key, both PEM.

    *names* become the subjectAltName (an IP address as iPAddress, anything
    else as dNSName). *role* sets the one extended key usage: ``server`` for
    the end that listens, ``client`` for the end that calls.
    """
    if role not in ROLES:
        raise TlsIdentityError(f"Unknown role {role!r}; known: {', '.join(ROLES)}.")
    subject_name = str(common_name or "").strip()
    if not subject_name or len(subject_name) > 64:
        raise TlsIdentityError("A certificate needs a common name of 1 to 64 characters.")
    alternative_names = [_general_name(name) for name in names]
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    usage = ExtendedKeyUsageOID.SERVER_AUTH if role == ROLE_SERVER else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
    )
    if alternative_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
    certificate = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return certificate.public_bytes(serialization.Encoding.PEM), key_pem


def pair_paths(directory: Path | str, stem: str) -> tuple[Path, Path]:
    """Where ``write_pair`` puts the certificate and the key of *stem*."""
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", str(stem or "")) is None:
        raise TlsIdentityError(f"{stem!r} cannot name a certificate file.")
    folder = Path(directory)
    return folder / f"{stem}-cert.pem", folder / f"{stem}-key.pem"


def write_pair(directory: Path | str, stem: str, certificate: bytes, key: bytes) -> tuple[Path, Path]:
    """Write ``<stem>-cert.pem`` and ``<stem>-key.pem`` (mode 0600); a file that exists is never replaced."""
    certificate_path, key_path = pair_paths(directory, stem)
    for path in (certificate_path, key_path):
        if path.exists():
            raise TlsIdentityError(f"{path} exists; it is not replaced.")
    try:
        certificate_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(bytes(key))
        with open(certificate_path, "xb") as handle:
            handle.write(bytes(certificate))
    except OSError as error:
        raise TlsIdentityError(f"The certificate files could not be written: {error}") from error
    return certificate_path, key_path


def load_certificate(path: Path | str) -> x509.Certificate:
    """The first certificate of a PEM file, or the certificate of a DER file."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise TlsIdentityError(f"{path} does not read: {error.strerror or error}") from error
    block = _PEM_CERTIFICATE.search(raw)
    try:
        if block is not None:
            return x509.load_pem_x509_certificate(block.group(0))
        return x509.load_der_x509_certificate(raw)
    except ValueError as error:
        raise TlsIdentityError(f"{path} holds no certificate.") from error


def certificate_sha256(path: Path | str) -> str:
    """SHA-256 of the DER of the first certificate in *path*, as upper-case hex."""
    der = load_certificate(path).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest().upper()


def describe(path: Path | str) -> str:
    """One line for an operator: subject, names, end of validity, SHA-256."""
    certificate = load_certificate(path)
    common = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject = str(common[0].value) if common else certificate.subject.rfc4514_string()
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(entry.value) for entry in extension]
    except x509.ExtensionNotFound:
        names = []
    until = certificate.not_valid_after_utc.date().isoformat()
    der = certificate.public_bytes(serialization.Encoding.DER)
    named = f", names {', '.join(names)}" if names else ""
    return f"CN={subject}{named}, valid until {until}, SHA-256 {hashlib.sha256(der).hexdigest().upper()}"


__all__ = [
    "ROLES", "ROLE_CLIENT", "ROLE_SERVER", "TlsIdentityError", "VALID_DAYS", "certificate_sha256", "describe",
    "issue_self_signed", "load_certificate", "pair_paths", "write_pair",
]
