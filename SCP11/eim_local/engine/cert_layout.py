# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The layout of a reference certificate, applied to a certificate of the Local eIM's own.

A TLS client, a card's IPAe included, judges an eIM certificate by its shape
as much as by its key: which attributes the subject carries and in what order,
which extensions are present and which of them are critical, whether the host
and the eimId appear in the SubjectAltName, how long the serial number is.
``CertificateLayout`` reads that shape from a reference certificate (a name in
the AddInitialEim builder store, or a PEM / DER / hex file) and the TLS setup
builder applies it to a certificate it issues itself. The Local eIM's own
material replaces what identifies the reference's owner: a fresh key,
SubjectKeyIdentifier and AuthorityKeyIdentifier, a fresh serial number of the
same length, the setup's FQDN where the reference named its host, the Local
eIM's eimId where the reference carried one as a registeredID (SGP.32 v1.3
§2.11.1.1.1 names the SubjectKeyIdentifier the trusted certificate carries;
RFC 5280 §4.2.1.6 the SubjectAltName forms). Everything else (the other
subject attributes, the KeyUsage bits, the ExtendedKeyUsage purposes, the CRL
distribution points, the certificate policies, an extension this module does
not know) is kept as the reference has it, with the same criticality and in
the same order.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

MAX_SERIAL_OCTETS = 20
_HOST_LIKE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")

_EXTENSION_LABELS: dict[ObjectIdentifier, str] = {
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: "SKI",
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "AKI",
    ExtensionOID.KEY_USAGE: "KU",
    ExtensionOID.EXTENDED_KEY_USAGE: "EKU",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "SAN",
    ExtensionOID.BASIC_CONSTRAINTS: "BC",
    ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL DP",
    ExtensionOID.CERTIFICATE_POLICIES: "Policies",
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "AIA",
    ExtensionOID.NAME_CONSTRAINTS: "NameConstraints",
}


class LayoutError(ValueError):
    """A reference certificate that cannot be found, read or applied."""


@dataclass(frozen=True)
class CertificateLayout:
    """What a reference certificate looks like, with the values that will be substituted marked."""

    label: str
    reference: x509.Certificate
    is_ca: bool
    host_names: tuple[str, ...]
    hash_name: str
    key_name: str
    serial_octets: int
    validity_days: int

    @property
    def subject_text(self) -> str:
        return self.reference.subject.rfc4514_string()

    @property
    def common_name(self) -> str:
        values = self.reference.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(values[0].value) if values else ""

    @property
    def sha256_hex(self) -> str:
        return self.reference.fingerprint(hashes.SHA256()).hex().upper()

    def subject(self, host: str, *, common_name: str | None = None) -> x509.Name:
        """The reference subject with its own host replaced by *host* and the CN by *common_name* when given.

        The attribute types, their order and their string encodings stay as the
        reference has them. A CN that names the reference's host (or looks like
        one) becomes *host*; any other CN is kept, because a certificate whose
        CN is a product name rather than its FQDN is a layout of its own.
        """
        rdns: list[x509.RelativeDistinguishedName] = []
        for rdn in self.reference.subject.rdns:
            attributes: list[x509.NameAttribute] = []
            for attribute in rdn:
                value = attribute.value
                if isinstance(value, str):
                    if attribute.oid == NameOID.COMMON_NAME and common_name is not None:
                        value = common_name
                    elif len(host) > 0 and (value.lower() in self.host_names or
                                            (attribute.oid == NameOID.COMMON_NAME and _HOST_LIKE.match(value) is not None)):
                        value = host
                attributes.append(x509.NameAttribute(attribute.oid, value, _type=attribute._type))  # noqa: SLF001 - keeps the reference's string type
            rdns.append(x509.RelativeDistinguishedName(attributes))
        return x509.Name(rdns)

    def serial_number(self) -> int:
        """A fresh positive serial number of the reference's octet length (RFC 5280 §4.1.2.2)."""
        octets = min(max(self.serial_octets, 1), MAX_SERIAL_OCTETS)
        return max(1, secrets.randbits(8 * octets - 1))

    def hash_algorithm(self) -> hashes.HashAlgorithm | None:
        """The reference's signature hash for an ECDSA key; None for Ed25519, which hashes internally."""
        return {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}.get(self.hash_name)

    def add_extensions(
        self,
        builder: x509.CertificateBuilder,
        *,
        public_key: Any,
        issuer_public_key: Any,
        host: str,
        eim_id: str,
    ) -> x509.CertificateBuilder:
        """The reference's extensions in its order and criticality, with the Local eIM's own values.

        SubjectKeyIdentifier and AuthorityKeyIdentifier are computed from the
        new keys. In the SubjectAltName the DNS names collapse to *host*, a
        registeredID becomes *eim_id* (dropped when the Local eIM's eimId is
        not an OID), the other forms stay. Every other extension is copied.
        """
        for extension in self.reference.extensions:
            value: x509.ExtensionType
            if extension.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                value = x509.SubjectKeyIdentifier.from_public_key(public_key)
            elif extension.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                value = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key)
            elif extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                names = self._alternative_names(extension.value, host=host, eim_id=eim_id)
                if len(names) == 0:
                    continue
                value = x509.SubjectAlternativeName(names)
            else:
                value = extension.value
            builder = builder.add_extension(value, critical=extension.critical)
        return builder

    @staticmethod
    def _alternative_names(reference: Any, *, host: str, eim_id: str) -> list[x509.GeneralName]:
        names: list[x509.GeneralName] = []
        host_done = False
        for name in reference:
            if isinstance(name, x509.DNSName):
                if host_done or len(host) == 0:
                    continue
                names.append(x509.DNSName(host))
                host_done = True
            elif isinstance(name, x509.RegisteredID):
                if len(eim_id) > 0:
                    names.append(x509.RegisteredID(ObjectIdentifier(eim_id)))
            else:
                names.append(name)
        return names

    def describe(self) -> str:
        """One line for SHOW: what the layout is taken from and what it carries."""
        parts = []
        for extension in self.reference.extensions:
            label = _EXTENSION_LABELS.get(extension.oid, extension.oid.dotted_string)
            parts.append(label + ("!" if extension.critical else ""))
        subject = self.common_name or self.subject_text
        return (f"{self.label}: {'CA' if self.is_ca else 'end entity'} {subject}; extensions "
                f"{', '.join(parts) or 'none'} (! critical); serial {self.serial_octets} octets; "
                f"{self.hash_name or 'no hash (Ed25519)'}; key {self.key_name}; valid {self.validity_days} days; "
                f"SHA-256 {self.sha256_hex[:16]}")


def from_certificate(certificate: x509.Certificate, label: str) -> CertificateLayout:
    """Read the layout of *certificate*."""
    try:
        is_ca = bool(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    hosts: set[str] = set()
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        hosts.update(name.lower() for name in san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if isinstance(attribute.value, str) and _HOST_LIKE.match(attribute.value) is not None:
            hosts.add(attribute.value.lower())
    key = certificate.public_key()
    if isinstance(key, ed25519.Ed25519PublicKey):
        key_name = "Ed25519"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_name = key.curve.name
    else:
        key_name = type(key).__name__
    algorithm = certificate.signature_hash_algorithm
    validity = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    serial_octets = (max(certificate.serial_number, 1).bit_length() + 8) // 8
    return CertificateLayout(
        label=label,
        reference=certificate,
        is_ca=is_ca,
        host_names=tuple(sorted(hosts)),
        hash_name=algorithm.name if algorithm is not None else "",
        key_name=key_name,
        serial_octets=serial_octets,
        validity_days=max(validity.days, 1),
    )


def load_reference(spec: str, *, store_directory: Path | None = None) -> CertificateLayout:
    """The layout of a stored certificate (AddInitialEim builder store name) or of the first certificate in a file."""
    from SCP11.shared.eim_builder_store import (
        MAX_SOURCE_BYTES,
        EimBuilderStoreError,
        certificates_from_source,
        read_certificate,
    )
    from yggdrasim_common.secure_files import read_bounded_regular_file

    text = str(spec or "").strip()
    if len(text) == 0:
        raise LayoutError("A layout names a stored certificate or a certificate file.")
    try:
        stored = read_certificate(text, store_directory)
    except EimBuilderStoreError:
        stored = None
    if stored is not None:
        try:
            return from_certificate(x509.load_der_x509_certificate(stored.der), f"stored certificate {stored.name}")
        except ValueError as error:
            raise LayoutError(f"Stored certificate {stored.name} does not parse: {error}") from error
    path = Path(text).expanduser()
    if not path.is_file():
        raise LayoutError(f"{text!r} is neither a stored certificate (EIM-CERT-STORE) nor a readable file.")
    try:
        raw = read_bounded_regular_file(path, MAX_SOURCE_BYTES)
        certificates, _private_keys = certificates_from_source(raw)
    except (OSError, ValueError) as error:
        raise LayoutError(f"{path} could not be read as a certificate: {error}") from error
    if len(certificates) == 0:
        raise LayoutError(f"{path} holds no certificate.")
    try:
        return from_certificate(x509.load_der_x509_certificate(certificates[0]), f"file {path}")
    except ValueError as error:
        raise LayoutError(f"{path} does not parse as a certificate: {error}") from error


__all__ = ["CertificateLayout", "LayoutError", "from_certificate", "load_reference"]
