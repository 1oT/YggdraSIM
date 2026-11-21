# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The TLS certificate the local SM-DP+ serves to a card that downloads directly (CERT.DP.TLS).

A card's IPAe that downloads directly opens its own TLS session to the SM-DP+
(SGP.32 v1.3 §5.6) and authenticates the server by a chain to an eSIM CA the
eUICC holds: that is the chain an SM-DP+ serves a client that names no v3
server name (SGP.22 v3.1 §2.6.6.2). For the local SM-DP+ the CA is the SGP.26
test CI its CERT.DPauth chains to, so only an eUICC that carries that test CI
accepts the session.

``select_material`` settles what the SM-DP+ card-facing listener loads, first match wins:

1. ``smdp_tls/chain.pem`` and ``smdp_tls/key.pem`` in the engine store, when
   the operator put them there (no ``issued.json`` beside them);
2. the CERT.DP.TLS of the SGP.26 bundle that the issuer of the CERT.DPauth in
   use signed, when it names this SM-DP+'s host and is valid today;
3. a CERT.DP.TLS issued for the host with the bundle's private key of that
   issuer, laid out as SGP.22 v3.1 §4.5.2.1.0.5 Table 14 has it, kept in the
   store and issued again when the host, the issuer or the SM-DP+ OID changes
   or its validity runs out.

The local SM-DS gets its CERT.DS.TLS the same way (``smds_serving_material``,
``server=SMDS``): Table 16 of §4.5.2.1.0.7 is Table 14 with the SM-DS roles,
the CERT.DSauth.SIG in use stands where CERT.DPauth does, and the files live
in ``smds_tls/``. A card's IPAe that retrieves its Event Records itself
(SGP.32 v1.3 §3.9.2.1) authenticates the SM-DS by that chain.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.eim_local.engine.tls_setup import ServingMaterial
from yggdrasim_common.inventory_crypto import read_secret_file_bytes

MATERIAL_DIR = "smdp_tls"
CHAIN_FILE = "chain.pem"
KEY_FILE = "key.pem"
RECORD_FILE = "issued.json"
VALIDITY_DAYS = 365
_REISSUE_MARGIN = datetime.timedelta(days=1)
_CERTIFICATE_SUFFIXES = (".der", ".pem", ".crt", ".cer")

# SGP.22 v3.1 Annex ASN.1 (p.437): id-rspRole is 2.23.146.1.2.1; the -v2 roles are the Variant O ones.
_ROLE_DP_AUTH = x509.ObjectIdentifier("2.23.146.1.2.1.0.0.1.1")
_ROLE_DP_TLS = x509.ObjectIdentifier("2.23.146.1.2.1.0.0.1.0")
_ROLE_DP_AUTH_V2 = x509.ObjectIdentifier("2.23.146.1.2.1.4")
_ROLE_DP_TLS_V2 = x509.ObjectIdentifier("2.23.146.1.2.1.3")
# The SM-DS roles of the same clause: ds-auth {id-rspRole 0 0 2 1}, ds-tls {... 2 0}, ds-auth-v2 {7}, ds-tls-v2 {6}.
_ROLE_DS_AUTH = x509.ObjectIdentifier("2.23.146.1.2.1.0.0.2.1")
_ROLE_DS_TLS = x509.ObjectIdentifier("2.23.146.1.2.1.0.0.2.0")
_ROLE_DS_AUTH_V2 = x509.ObjectIdentifier("2.23.146.1.2.1.7")
_ROLE_DS_TLS_V2 = x509.ObjectIdentifier("2.23.146.1.2.1.6")
_TLS_ROLE_FOR = {_ROLE_DP_AUTH: _ROLE_DP_TLS, _ROLE_DP_AUTH_V2: _ROLE_DP_TLS_V2,
                 _ROLE_DS_AUTH: _ROLE_DS_TLS, _ROLE_DS_AUTH_V2: _ROLE_DS_TLS_V2}


class SmdpTlsError(ValueError):
    """No TLS certificate can be served for the local SM-DP+ or SM-DS; the message says what is missing."""


@dataclass(frozen=True)
class RspServer:
    """Which of the two RSP Servers a TLS certificate is for: its names, its folder and its OID's record key."""

    name: str
    auth: str
    tls: str
    directory: str
    oid_key: str


SMDP = RspServer("SM-DP+", "CERT.DPauth", "CERT.DP.TLS", MATERIAL_DIR, "smdp_oid")
SMDS = RspServer("SM-DS", "CERT.DSauth", "CERT.DS.TLS", "smds_tls", "smds_oid")


@dataclass(frozen=True)
class _Issuer:
    """The certificate that signed CERT.DPauth; ``key`` is None when the bundle holds no private key for it."""

    certificate: x509.Certificate
    key: Any
    path: Path


def material_directory(directory: Path, server: RspServer = SMDP) -> Path:
    return Path(directory) / server.directory


def _load_certificate(path: Path) -> x509.Certificate:
    data = read_secret_file_bytes(path)
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _spki(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _subject_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        return bytes(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
    except x509.ExtensionNotFound:
        return b""


def _authority_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        value = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return b""
    return bytes(value.key_identifier or b"")


def _alternative_names(certificate: x509.Certificate) -> tuple[list[str], list[str]]:
    """(dNSName values in lower case, registeredID values) of the subjectAltName."""
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    hosts = [str(name).lower().rstrip(".") for name in names.get_values_for_type(x509.DNSName)]
    return hosts, [oid.dotted_string for oid in names.get_values_for_type(x509.RegisteredID)]


def _key_beside(certificate: x509.Certificate, folder: Path) -> tuple[Any, Path] | None:
    """The private key in *folder* whose public key is the certificate's, with its path."""
    wanted = _spki(certificate.public_key())
    for candidate in sorted(folder.glob("*.pem")):
        try:
            data = read_secret_file_bytes(candidate)
            if b"PRIVATE KEY" not in data:
                continue
            key = serialization.load_pem_private_key(data, password=None)
            if _spki(key.public_key()) == wanted:
                return key, candidate
        except (ValueError, TypeError, OSError):
            continue
    return None


def _certificates_under(root: Path) -> list[tuple[Path, x509.Certificate]]:
    found: list[tuple[Path, x509.Certificate]] = []
    if not root.is_dir():
        return found
    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in _CERTIFICATE_SUFFIXES or not path.is_file():
            continue
        if any(part.lower().startswith("old_") for part in path.relative_to(root).parts):
            continue
        try:
            found.append((path, _load_certificate(path)))
        except (ValueError, OSError):
            continue
    return found


def _valid_at(certificate: x509.Certificate, now: datetime.datetime) -> bool:
    return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc - _REISSUE_MARGIN


def _bundle_certificate(
    certificates: list[tuple[Path, x509.Certificate]], issuer_ski: bytes, host: str, now: datetime.datetime,
) -> tuple[Path, x509.Certificate, Path] | None:
    """A TLS server certificate of the bundle for *host* under *issuer_ski*, with its key file."""
    for path, certificate in certificates:
        if _authority_key_identifier(certificate) != issuer_ski or not _valid_at(certificate, now):
            continue
        hosts, _oids = _alternative_names(certificate)
        if host not in hosts:
            continue
        try:
            usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.SERVER_AUTH not in usages:
            continue
        key = _key_beside(certificate, path.parent)
        if key is not None:
            return path, certificate, key[1]
    return None


def _find_issuer(certificates: list[tuple[Path, x509.Certificate]], issuer_ski: bytes) -> _Issuer | None:
    found: _Issuer | None = None
    for path, certificate in certificates:
        if _subject_key_identifier(certificate) != issuer_ski:
            continue
        key = _key_beside(certificate, path.parent)
        if key is not None:
            return _Issuer(certificate=certificate, key=key[0], path=path)
        found = found or _Issuer(certificate=certificate, key=None, path=path)
    return found


def _tls_subject(auth_certificate: x509.Certificate, host: str) -> x509.Name:
    """The CERT.DPauth subject with 'cn' set to the host name (§4.5.2.1.0.5: identical attributes except 'cn')."""
    attributes = [attribute for attribute in auth_certificate.subject if attribute.oid != NameOID.COMMON_NAME]
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64]), *attributes])


def issue_certificate(
    auth_certificate: x509.Certificate,
    issuer: x509.Certificate,
    issuer_key: Any,
    host: str,
    *,
    now: datetime.datetime,
    server: RspServer = SMDP,
) -> tuple[x509.Certificate, Any]:
    """A CERT.DP.TLS for *host* signed by *issuer_key*, per SGP.22 v3.1 §4.5.2.1.0.5 Table 14; with its key.

    With ``server=SMDS`` it is a CERT.DS.TLS under the issuer of CERT.DSauth
    (§4.5.2.1.0.7 Table 16, the same fields with the SM-DS role and OID).
    """
    if not isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        raise SmdpTlsError(f"The issuer of {server.auth} has no elliptic curve key; no {server.tls} is issued "
                           "with it.")
    _hosts, oids = _alternative_names(auth_certificate)
    if len(oids) != 1:
        raise SmdpTlsError(f"{server.auth} carries no single {server.name} OID in its subjectAltName.")
    key = ec.generate_private_key(issuer_key.curve)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_tls_subject(auth_certificate, host))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.AuthorityKeyIdentifier(_subject_key_identifier(issuer), None, None), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host), x509.RegisteredID(x509.ObjectIdentifier(oids[0]))]),
            critical=False,
        )
    )
    try:
        policies = auth_certificate.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        policies = []
    roles = [_TLS_ROLE_FOR[policy.policy_identifier] for policy in policies if policy.policy_identifier in _TLS_ROLE_FOR]
    if roles:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(roles[0], None)]), critical=False
        )
    try:
        # Present on the CERT.DPauth exactly when its issuer manages revocation (Table 14, last row).
        builder = builder.add_extension(
            auth_certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value, critical=False
        )
    except x509.ExtensionNotFound:
        pass
    digest = hashes.SHA384() if issuer_key.curve.key_size > 256 else hashes.SHA256()
    return builder.sign(issuer_key, digest), key


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _read_record(folder: Path) -> dict[str, Any] | None:
    try:
        record = json.loads((folder / RECORD_FILE).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return record if isinstance(record, dict) else None


def _kept_material(folder: Path, record: dict[str, Any], wanted: dict[str, str], now: datetime.datetime) -> bool:
    """True when the store already holds the chain *wanted* describes and its leaf is valid."""
    if any(str(record.get(key, "")) != value for key, value in wanted.items()):
        return False
    try:
        leaf = x509.load_pem_x509_certificate((folder / CHAIN_FILE).read_bytes())
    except (ValueError, OSError):
        return False
    return (folder / KEY_FILE).is_file() and _valid_at(leaf, now)


def select_material(
    directory: Path,
    *,
    auth_certificate: bytes,
    host: str,
    bundle_root: Path | str,
    now: datetime.datetime | None = None,
    server: RspServer = SMDP,
) -> ServingMaterial:
    """What the card-facing listener of *server* serves for *host*; SmdpTlsError names what is missing."""
    moment = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    folder = material_directory(directory, server)
    record = _read_record(folder)
    if record is None and (folder / CHAIN_FILE).is_file() and (folder / KEY_FILE).is_file():
        return ServingMaterial(label="operator files", chain_path=str(folder / CHAIN_FILE),
                               key_path=str(folder / KEY_FILE))
    name = str(host or "").strip().lower().rstrip(".")
    if len(name) == 0:
        raise SmdpTlsError(f"the local {server.name} has no address to issue a TLS certificate for")
    try:
        auth = x509.load_der_x509_certificate(bytes(auth_certificate or b""))
    except ValueError as error:
        raise SmdpTlsError(f"{server.auth} does not parse: {error}") from error
    issuer_ski = _authority_key_identifier(auth)
    if len(issuer_ski) == 0:
        raise SmdpTlsError(f"{server.auth} names no issuer key (no authorityKeyIdentifier)")
    wanted = {"host": name, "issuer_ski": issuer_ski.hex().upper(),
              server.oid_key: ",".join(_alternative_names(auth)[1])}
    if record is not None and _kept_material(folder, record, wanted, moment):
        return ServingMaterial(label=str(record.get("label", "issued")), chain_path=str(folder / CHAIN_FILE),
                               key_path=str(folder / KEY_FILE))
    root = str(bundle_root or "").strip()
    certificates = _certificates_under(Path(root)) if len(root) > 0 else []
    issuer = _find_issuer(certificates, issuer_ski)
    # A SubCA that issued the authentication certificate is sent after the leaf; the eUICC holds only the root.
    intermediates: list[x509.Certificate] = []
    if issuer is not None and issuer.certificate.subject != issuer.certificate.issuer:
        intermediates.append(issuer.certificate)
    bundled = _bundle_certificate(certificates, issuer_ski, name, moment)
    if bundled is not None:
        path, leaf, key_path = bundled
        key_data = read_secret_file_bytes(key_path)
        label = f"SGP.26 bundle {path.name}"
    elif issuer is not None and issuer.key is not None:
        leaf, key = issue_certificate(auth, issuer.certificate, issuer.key, name, now=moment, server=server)
        key_data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
        try:
            issuer_name = issuer.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer_name = issuer.path.name
        label = f"issued for {name} under {issuer_name}"
    else:
        raise SmdpTlsError(
            f"the SGP.26 bundle holds no {server.tls} for {name} and no private key of the issuer of {server.auth} "
            f"({auth.issuer.rfc4514_string()}); put a chain and its key in {folder} as {CHAIN_FILE} and {KEY_FILE}"
        )
    folder.mkdir(parents=True, exist_ok=True)
    _write_private(folder / KEY_FILE, key_data)
    (folder / CHAIN_FILE).write_bytes(_pem(leaf) + b"".join(_pem(item) for item in intermediates))
    (folder / RECORD_FILE).write_text(
        json.dumps({**wanted, "label": label, "created_at": moment.isoformat()}, indent=2) + "\n", encoding="utf-8"
    )
    return ServingMaterial(label=label, chain_path=str(folder / CHAIN_FILE), key_path=str(folder / KEY_FILE))


def serving_material(directory: Path, smdp: Any) -> ServingMaterial:
    """``select_material`` for a ``LocalSmdp``: its CERT.DPauth in use, its host and its SGP.26 bundle."""
    try:
        session = smdp.session()
        session._ensure_local_material_loaded()
        auth_certificate = bytes(session._cert_auth or b"")
        bundle_root = str(getattr(session.cfg, "SGP26_VALID_CERT_DIR", "") or "")
    except (OSError, RuntimeError, AttributeError) as error:
        raise SmdpTlsError(f"the local SM-DP+ has no certificate material: {error}") from error
    return select_material(directory, auth_certificate=auth_certificate, host=smdp.host(), bundle_root=bundle_root)


def smds_serving_material(directory: Path, smds: Any) -> ServingMaterial:
    """``select_material`` for a ``LocalSmds``: its first CERT.DSauth.SIG, its address and the SGP.26 bundle.

    The first credential is the one of the preferred curve, so the TLS chain
    ends at the same eSIM CA RootCA an eUICC of that curve is authenticated
    under.
    """
    from SCP11.eim_local.config import EimLocalConfig

    try:
        credentials = smds.material().credentials
        bundle_root = str(getattr(EimLocalConfig(), "SGP26_VALID_CERT_DIR", "") or "")
    except (OSError, RuntimeError, ValueError, AttributeError) as error:
        raise SmdpTlsError(f"the local SM-DS has no certificate material: {error}") from error
    if len(credentials) == 0:
        raise SmdpTlsError("the local SM-DS has no CERT.DSauth to issue a TLS certificate beside")
    return select_material(directory, auth_certificate=bytes(credentials[0].certificate), host=smds.address(),
                           bundle_root=bundle_root, server=SMDS)


__all__ = [
    "CHAIN_FILE", "KEY_FILE", "MATERIAL_DIR", "RECORD_FILE", "RspServer", "SMDP", "SMDS", "SmdpTlsError",
    "issue_certificate", "material_directory", "select_material", "serving_material", "smds_serving_material",
]
