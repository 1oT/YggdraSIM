# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Local eIM's own identity: eimId, signing key, and the certificates a card is given.

One identity is active. It lives in the engine store directory
(``identity.json`` plus ``keys/``, private keys at mode 0600) and is either
generated -- a P-256 key with a self-signed signing certificate and a TLS
server certificate for the eIM FQDN -- or imported from PEM files. The
EimConfigurationData built from it is what AddInitialEim or an addEim eCO puts
on a card (SGP.32 v1.3 §2.11.1.1.1); the card then verifies every eUICC
Package against this key.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.shared.eim_configuration_data import (
    EIM_ID_TYPE_NAMES,
    EIM_SUPPORTED_PROTOCOL_BITS,
    KEY_FORM_CERTIFICATE,
    KEY_FORM_PUBLIC_KEY,
    EimConfigurationData,
    KeyData,
    infer_eim_id_type,
)

IDENTITY_FILE = "identity.json"
KEYS_DIR = "keys"
SIGNING_KEY_FILE = "eim_signing_key.pem"
SIGNING_CERT_FILE = "eim_signing_cert.pem"
TLS_KEY_FILE = "eim_tls_key.pem"
TLS_CERT_FILE = "eim_tls_cert.pem"

# SGP.32 v1.3 §4.3 gives this OID as its example eIM identifier.
EXAMPLE_EIM_ID = "1.3.6.1.4.1.32473.999.10.124"
DEFAULT_EIM_FQDN = "eim.yggdrasim.local"
# The only eIM names the Local eIM answers for and tells a card to poll: one
# label that starts with "eim", under yggdrasim.local. ".local" is not
# delegated in the public DNS, so no such name is another party's eIM. Any other name, a production or test
# eIM's included, is never resolved or redirected to the Local eIM.
LOCAL_EIM_NAME_PATTERN = "eim*.yggdrasim.local"
_LOCAL_EIM_NAME = re.compile(r"^eim[a-z0-9-]{0,60}\.yggdrasim\.local$")


def local_eim_name(host: Any) -> bool:
    """Whether *host* is a name the Local eIM may answer for (``LOCAL_EIM_NAME_PATTERN``, one label, any case)."""
    name = str(host or "").strip().lower().rstrip(".")
    return _LOCAL_EIM_NAME.match(name) is not None
CERTIFICATE_DAYS = 3650


class IdentityError(RuntimeError):
    """The identity is missing, incomplete, or its key material does not load."""


@dataclass
class EimIdentity:
    """eIM identifier, addresses and the paths of the key material."""

    eim_id: str
    eim_id_type: int
    eim_fqdn: str
    signing_key_path: str
    signing_certificate_path: str
    tls_key_path: str = ""
    tls_certificate_path: str = ""
    supported_protocols: list[str] = field(default_factory=lambda: ["eimRetrieveHttps"])
    indirect_profile_download: bool = True
    euicc_ci_pkid_hex: str = ""
    created_at: str = ""

    def describe(self) -> dict[str, Any]:
        summary = asdict(self)
        summary["eim_id_type_name"] = EIM_ID_TYPE_NAMES.get(self.eim_id_type, str(self.eim_id_type))
        try:
            certificate = x509.load_der_x509_certificate(self.signing_certificate_der())
        except (IdentityError, ValueError):
            return summary
        summary["signing_certificate_subject"] = certificate.subject.rfc4514_string()
        summary["signing_certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
        summary["signing_public_key_hex"] = self.signing_public_key_der().hex().upper()
        return summary

    def signing_key(self) -> ec.EllipticCurvePrivateKey:
        return _load_private_key(Path(self.signing_key_path))

    def signing_certificate_der(self) -> bytes:
        return _load_certificate_der(Path(self.signing_certificate_path))

    def signing_public_key_der(self) -> bytes:
        return self.signing_key().public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def tls_certificate_der(self) -> bytes:
        if len(self.tls_certificate_path) == 0:
            return b""
        return _load_certificate_der(Path(self.tls_certificate_path))

    def configuration_data(
        self,
        *,
        counter_value: int = 0,
        request_association_token: bool = True,
        key_form: str = KEY_FORM_CERTIFICATE,
        include_tls: bool = True,
    ) -> EimConfigurationData:
        """Return the EimConfigurationData that associates a card with this eIM.

        SGP.32 v1.3 §2.11.1.1.2 (p.33-34): eimId, counterValue and
        eimPublicKeyData are present; eimFqdn only when eimIdType is not
        eimIdTypeFqdn; associationToken only as -1, asking the eUICC for one.
        """
        if key_form == KEY_FORM_CERTIFICATE:
            key = KeyData(form=KEY_FORM_CERTIFICATE, der=self.signing_certificate_der())
        elif key_form == KEY_FORM_PUBLIC_KEY:
            key = KeyData(form=KEY_FORM_PUBLIC_KEY, der=self.signing_public_key_der())
        else:
            raise ValueError(f"key_form is {KEY_FORM_CERTIFICATE!r} or {KEY_FORM_PUBLIC_KEY!r}, not {key_form!r}.")
        tls: KeyData | None = None
        tls_der = self.tls_certificate_der() if include_tls else b""
        if len(tls_der) > 0:
            tls = KeyData(form=KEY_FORM_CERTIFICATE, der=tls_der)
        fqdn = None if self.eim_id_type == 2 else (self.eim_fqdn or None)
        ci_pkid = bytes.fromhex(self.euicc_ci_pkid_hex) if len(self.euicc_ci_pkid_hex) > 0 else None
        return EimConfigurationData(
            eim_id=self.eim_id,
            eim_fqdn=fqdn,
            eim_id_type=self.eim_id_type,
            counter_value=int(counter_value),
            association_token=-1 if request_association_token else None,
            eim_public_key_data=key,
            trusted_public_key_data_tls=tls,
            eim_supported_protocol=tuple(self.supported_protocols),
            euicc_ci_pk_id=ci_pkid,
            indirect_profile_download=self.indirect_profile_download,
        )


def _load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except FileNotFoundError as error:
        raise IdentityError(f"eIM signing key not found: {path}") from error
    except (ValueError, TypeError) as error:
        raise IdentityError(f"eIM key {path} does not load as an unencrypted PEM private key: {error}") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise IdentityError(f"eIM key {path} is not a P-256 EC key.")
    return key


def _load_certificate_der(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except FileNotFoundError as error:
        raise IdentityError(f"Certificate not found: {path}") from error
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificate(data).public_bytes(serialization.Encoding.DER)
        return x509.load_der_x509_certificate(data).public_bytes(serialization.Encoding.DER)
    except ValueError as error:
        raise IdentityError(f"{path} is not a PEM or DER certificate: {error}") from error


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def _certificate(
    key: ec.EllipticCurvePrivateKey,
    *,
    common_name: str,
    fqdn: str,
    server_auth: bool,
) -> x509.Certificate:
    # Test geography only (CLAUDE.md, real-identifier rule).
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM Local eIM"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERTIFICATE_DAYS))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if len(fqdn) > 0:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
    if server_auth:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(key, hashes.SHA256())


def generate_identity(
    directory: Path,
    *,
    eim_id: str = EXAMPLE_EIM_ID,
    eim_fqdn: str = DEFAULT_EIM_FQDN,
    eim_id_type: int | None = None,
) -> EimIdentity:
    """Generate a P-256 key with a signing and a TLS certificate and save the identity."""
    if len(eim_id.encode("utf-8")) == 0 or len(eim_id.encode("utf-8")) > 128:
        raise ValueError("eimId must be 1..128 octets of UTF-8.")
    keys = Path(directory) / KEYS_DIR
    key = ec.generate_private_key(ec.SECP256R1())
    tls_key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    tls_key_pem = tls_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    signing_certificate = _certificate(key, common_name=f"{eim_fqdn or eim_id} eIM signing", fqdn="",
                                       server_auth=False)
    tls_certificate = _certificate(tls_key, common_name=eim_fqdn or eim_id, fqdn=eim_fqdn, server_auth=True)
    _write_private(keys / SIGNING_KEY_FILE, key_pem)
    _write_private(keys / TLS_KEY_FILE, tls_key_pem)
    (keys / SIGNING_CERT_FILE).write_bytes(signing_certificate.public_bytes(serialization.Encoding.PEM))
    (keys / TLS_CERT_FILE).write_bytes(tls_certificate.public_bytes(serialization.Encoding.PEM))
    identity = EimIdentity(
        eim_id=eim_id,
        eim_id_type=int(eim_id_type) if eim_id_type is not None else infer_eim_id_type(eim_id),
        eim_fqdn=eim_fqdn,
        signing_key_path=str(keys / SIGNING_KEY_FILE),
        signing_certificate_path=str(keys / SIGNING_CERT_FILE),
        tls_key_path=str(keys / TLS_KEY_FILE),
        tls_certificate_path=str(keys / TLS_CERT_FILE),
        created_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    )
    save_identity(directory, identity)
    return identity


def import_identity(
    directory: Path,
    *,
    eim_id: str,
    eim_fqdn: str,
    signing_key_path: str,
    signing_certificate_path: str,
    tls_key_path: str = "",
    tls_certificate_path: str = "",
    eim_id_type: int | None = None,
) -> EimIdentity:
    """Record an identity whose key material already exists as PEM files."""
    identity = EimIdentity(
        eim_id=eim_id,
        eim_id_type=int(eim_id_type) if eim_id_type is not None else infer_eim_id_type(eim_id),
        eim_fqdn=eim_fqdn,
        signing_key_path=str(Path(signing_key_path).expanduser()),
        signing_certificate_path=str(Path(signing_certificate_path).expanduser()),
        tls_key_path=str(Path(tls_key_path).expanduser()) if tls_key_path else "",
        tls_certificate_path=str(Path(tls_certificate_path).expanduser()) if tls_certificate_path else "",
        created_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    )
    identity.signing_key()
    identity.signing_certificate_der()
    save_identity(directory, identity)
    return identity


NEXT_SIGNING_KEY_FILE = "eim_signing_key.next.pem"
NEXT_SIGNING_CERT_FILE = "eim_signing_cert.next.pem"
PREVIOUS_SIGNING_KEY_FILE = "eim_signing_key.previous.pem"
PREVIOUS_SIGNING_CERT_FILE = "eim_signing_cert.previous.pem"


def prepare_signing_key_rotation(directory: Path) -> bytes:
    """Generate the next signing key and certificate, kept beside the current pair; return the key's SubjectPublicKeyInfo.

    An eIM key rotation is an updateEim eCO carrying the new eimPublicKeyData,
    signed with the key the eUICC still trusts (SGP.32 v1.3 §2.11.1.1.2); the
    next pair waits on disk until ``commit_signing_key_rotation`` makes it the
    identity's.
    """
    identity = load_identity(directory)
    if identity is None:
        raise IdentityError("The Local eIM has no identity to rotate.")
    keys = Path(directory) / KEYS_DIR
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(key, common_name=f"{identity.eim_fqdn or identity.eim_id} eIM signing", fqdn="",
                               server_auth=False)
    _write_private(keys / NEXT_SIGNING_KEY_FILE, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (keys / NEXT_SIGNING_CERT_FILE).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def commit_signing_key_rotation(directory: Path) -> EimIdentity:
    """Make the prepared next pair the identity's signing key; the pair it replaces stays as the previous one."""
    identity = load_identity(directory)
    keys = Path(directory) / KEYS_DIR
    next_key, next_cert = keys / NEXT_SIGNING_KEY_FILE, keys / NEXT_SIGNING_CERT_FILE
    if identity is None or not next_key.exists() or not next_cert.exists():
        raise IdentityError("No signing key rotation is prepared.")
    _write_private(keys / PREVIOUS_SIGNING_KEY_FILE, Path(identity.signing_key_path).read_bytes())
    (keys / PREVIOUS_SIGNING_CERT_FILE).write_bytes(Path(identity.signing_certificate_path).read_bytes())
    _write_private(keys / SIGNING_KEY_FILE, next_key.read_bytes())
    (keys / SIGNING_CERT_FILE).write_bytes(next_cert.read_bytes())
    next_key.unlink()
    next_cert.unlink()
    identity.signing_key_path = str(keys / SIGNING_KEY_FILE)
    identity.signing_certificate_path = str(keys / SIGNING_CERT_FILE)
    save_identity(directory, identity)
    return identity


def abandon_signing_key_rotation(directory: Path) -> None:
    """Drop a prepared next pair that the eUICC did not take."""
    keys = Path(directory) / KEYS_DIR
    for name in (NEXT_SIGNING_KEY_FILE, NEXT_SIGNING_CERT_FILE):
        try:
            (keys / name).unlink()
        except FileNotFoundError:
            pass


def restore_previous_signing_key(directory: Path) -> EimIdentity:
    """Sign with the pair a rotation replaced again (the eUICC still holds that key)."""
    identity = load_identity(directory)
    keys = Path(directory) / KEYS_DIR
    previous_key, previous_cert = keys / PREVIOUS_SIGNING_KEY_FILE, keys / PREVIOUS_SIGNING_CERT_FILE
    if identity is None or not previous_key.exists() or not previous_cert.exists():
        raise IdentityError("No previous signing key is kept.")
    _write_private(keys / SIGNING_KEY_FILE, previous_key.read_bytes())
    (keys / SIGNING_CERT_FILE).write_bytes(previous_cert.read_bytes())
    previous_key.unlink()
    previous_cert.unlink()
    identity.signing_key_path = str(keys / SIGNING_KEY_FILE)
    identity.signing_certificate_path = str(keys / SIGNING_CERT_FILE)
    save_identity(directory, identity)
    return identity


def save_identity(directory: Path, identity: EimIdentity) -> None:
    path = Path(directory) / IDENTITY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(identity), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_identity(directory: Path) -> EimIdentity | None:
    path = Path(directory) / IDENTITY_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as error:
        raise IdentityError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise IdentityError(f"{path} does not hold an identity object.")
    known = set(EimIdentity.__dataclass_fields__)
    values = {key: value for key, value in document.items() if key in known}
    try:
        identity = EimIdentity(**values)
    except TypeError as error:
        raise IdentityError(f"{path} lacks identity fields: {error}") from error
    unknown = [name for name in identity.supported_protocols if name not in EIM_SUPPORTED_PROTOCOL_BITS]
    if unknown:
        raise IdentityError(f"{path} names unknown eimSupportedProtocol bits: {', '.join(unknown)}.")
    return identity
