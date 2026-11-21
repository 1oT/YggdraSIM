# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Named TLS setups for the Local eIM: the chain its card-facing listener serves and what the card trusts.

A card's IPAe authenticates the eIM's TLS server with the trustedPublicKeyDataTls
AddInitialEim gave it: the eIM's public key, its certificate, or a CA certificate
the chain ends at (SGP.32 v1.3 §2.11.1.1.1, p.32-33; §2.6.3.2, p.21). A setup
generates one such chain (a self-signed leaf; root and leaf; root, intermediate
and leaf), records which member the card is told to trust and which the listener
sends, and may break a rule on purpose (no SubjectKeyIdentifier, a CA without
BasicConstraints, an expired leaf, another name) to see what a card accepts.

A setup may stand for an eIM of its own: ``fqdn`` is the eIM FQDN the card is
given in AddInitialEim (``eimFqdn``) and the leaf is issued for, and ``layout``
/ ``ca_layout`` name reference certificates (``cert_layout``) whose shape the
leaf and the CA members take, so a chain can look like the one another eIM
serves while every key stays the Local eIM's.

One setup is in use at a time (``tls_setups/active.json``); without one the
listener serves the identity's own TLS certificate and AddInitialEim carries it
with the identity's FQDN. Using a setup changes what the listener serves at
once; the card follows only after AddInitialEim carries the new trust and name.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, fields
from dataclasses import replace as with_changes
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.eim_local.engine import cert_layout, cert_spec
from SCP11.eim_local.engine.identity import LOCAL_EIM_NAME_PATTERN, EimIdentity, local_eim_name
from SCP11.shared.eim_configuration_data import KEY_FORM_CERTIFICATE, KEY_FORM_PUBLIC_KEY, KeyData

SETUPS_DIR = "tls_setups"
ACTIVE_FILE = "active.json"
SETUP_FILE = "setup.json"
CHAIN_FILE = "chain.pem"
LEAF_FILE = "leaf.pem"
LEAF_KEY_FILE = "leaf_key.pem"
MAX_SETUPS = 64
# Further leaves issued under a setup's own CA live in <setup>/leaves/<name>/; the top-level leaf files are
# always the one the listener serves. BUILT_LEAF names the leaf the setup was built with.
LEAVES_DIR = "leaves"
LEAF_INFO_FILE = "leaf.json"
BUILT_LEAF = "built"
MAX_LEAVES = 32

CHAINS = ("self", "root", "intermediate")
TRUSTS = ("leaf", "leaf_key", "root", "intermediate", "none")
CURVES = ("p256", "p384", "brainpoolp256r1", "ed25519")
VALIDITIES = ("valid", "expired", "not_yet_valid")
SENDS = ("leaf", "chain", "full")
VERSIONS = ("1.2+", "1.2", "1.3")
# Client authentication on the card-facing listener: §2.6.3.2 asks for server
# authentication only, so none is the conforming shape; optional asks the client
# for a certificate and takes a connection without one; required refuses that.
CLIENT_AUTHS = ("none", "optional", "required")
# any: a client that sends no server_name or another one is served; required:
# the listener answers only a ClientHello naming the leaf (RFC 6066 §3).
SNIS = ("any", "required")
# How a leaf names its owner: the registeredID in its SubjectAltName (auto: as
# the layout reference has it, none for a generic leaf; on: the Local eIM's
# eimId when that is an OID, next to the DNS name; off: left out, the practice
# of an EUM that takes a DNS-only SAN), and a shaped leaf's CN (auto: the
# reference's CN unless it names the reference's host; host: the setup's FQDN;
# keep: the reference's CN whatever it is), or any leaf's CN (eim_id: the Local
# eIM's eimId, the host then being named by the SubjectAltName alone).
REGISTERED_IDS = ("auto", "on", "off")
COMMON_NAMES = ("auto", "host", "keep", "eim_id")
CLIENT_CA_FILE = "client_ca.pem"
CLIENT_CA_KEY_FILE = "client_ca_key.pem"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_CERTIFICATE_DAYS = 3650
# Names a test may use without reaching anyone: the four TLDs of RFC 2606 §2 and
# the second-level names of §3.
RESERVED_TEST_TLDS = ("test", "example", "invalid", "localhost")
RESERVED_TEST_DOMAINS = ("example.com", "example.net", "example.org")
# Fields the operator sets; the rest of TlsSetup is recorded by the build.
_RECORDED_FIELDS = ("name", "eim_fqdn", "created_at", "layout_reference", "ca_layout_reference", "client_ca_reference",
                    "leaf")
# What a leaf variant may set; anything left out is taken from its setup.
_LEAF_OPTIONS = ("cn", "san", "registered_id", "layout", "validity", "ski", "server_auth", "curve", "send")


class TlsSetupError(ValueError):
    """A setup that cannot be built, found or used as asked."""


@dataclass
class TlsSetup:
    """How one chain is built and used; ``san`` empty means the setup's FQDN, ``none`` no SAN.

    ``fqdn`` is the eIM FQDN this setup stands for (empty: the identity's);
    ``layout`` and ``ca_layout`` name the reference certificates the leaf and
    the CA members are shaped after (empty: the generic shape).
    """

    name: str
    chain: str = "self"
    trust: str = "leaf"
    curve: str = "p256"
    san: str = ""
    validity: str = "valid"
    ski: bool = True
    ca_basic_constraints: bool = True
    server_auth: bool = True
    send: str = "chain"
    versions: str = "1.2+"
    ciphers: str = ""
    fqdn: str = ""
    layout: str = ""
    ca_layout: str = ""
    registered_id: str = "auto"
    cn: str = "auto"
    client_auth: str = "none"
    client_ca: str = ""
    sni: str = "any"
    eim_fqdn: str = ""
    created_at: str = ""
    layout_reference: str = ""
    ca_layout_reference: str = ""
    client_ca_reference: str = ""
    # The leaf variant the top-level leaf files hold ('' while it is the one the setup was built with).
    leaf: str = ""

    def check(self) -> None:
        if _NAME.match(self.name) is None:
            raise TlsSetupError(f"A setup name is 1-48 of A-Z a-z 0-9 . _ -, starting alphanumeric; got {self.name!r}.")
        for label, value, allowed in (
            ("chain", self.chain, CHAINS), ("trust", self.trust, TRUSTS), ("curve", self.curve, CURVES),
            ("validity", self.validity, VALIDITIES), ("send", self.send, SENDS), ("versions", self.versions, VERSIONS),
            ("client_auth", self.client_auth, CLIENT_AUTHS), ("sni", self.sni, SNIS),
            ("registered_id", self.registered_id, REGISTERED_IDS), ("cn", self.cn, COMMON_NAMES),
        ):
            if value not in allowed:
                raise TlsSetupError(f"{label} is one of {', '.join(allowed)}; got {value!r}.")
        if self.trust == "root" and self.chain == "self":
            raise TlsSetupError("trust=root needs chain=root or chain=intermediate.")
        if self.trust == "intermediate" and self.chain != "intermediate":
            raise TlsSetupError("trust=intermediate needs chain=intermediate.")
        if len(self.fqdn) > 0 and _HOST.match(self.fqdn) is None:
            raise TlsSetupError(f"fqdn is a host name such as eim1.yggdrasim.local; got {self.fqdn!r}.")

    @property
    def effective_fqdn(self) -> str:
        """The eIM FQDN this setup stands for: its own, else the identity's it was built for."""
        return self.fqdn or self.eim_fqdn

    @property
    def leaf_name(self) -> str:
        if self.san == "none":
            return self.effective_fqdn or self.name
        return self.san or self.effective_fqdn or self.name


def reserved_test_name(host: str) -> bool:
    """Whether *host* can only ever name a test: RFC 2606 §2 TLDs or §3 second-level domains."""
    name = str(host or "").strip().lower().rstrip(".")
    if len(name) == 0:
        return False
    labels = name.split(".")
    if labels[-1] in RESERVED_TEST_TLDS:
        return True
    return any(name == domain or name.endswith("." + domain) for domain in RESERVED_TEST_DOMAINS)


@dataclass(frozen=True)
class ServingMaterial:
    """What the card-facing listener loads for one chain: files, protocol limits, what it asks of the client, its names.

    ``names`` are the host names the chain answers for (the setup's eIM FQDN
    and its leaf name), ``patterns`` a wildcard leaf name; a ClientHello's
    server_name picks the chain by them.
    """

    label: str
    chain_path: str
    key_path: str
    versions: str = "1.2+"
    ciphers: str = ""
    client_auth: str = "none"
    client_ca_path: str = ""
    sni_names: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    # The leaf this chain serves: its variant name and the SHA-256 of its DER ('' when the file does not read).
    leaf: str = ""
    leaf_sha256: str = ""


def setups_directory(directory: Path) -> Path:
    return Path(directory) / SETUPS_DIR


def setup_directory(directory: Path, name: str) -> Path:
    if _NAME.match(str(name or "")) is None:
        raise TlsSetupError(f"No TLS setup can be called {name!r}.")
    return setups_directory(directory) / name


def parse_options(name: str, pairs: dict[str, str]) -> TlsSetup:
    """A setup from ``key=value`` pairs; booleans take on/off, yes/no, true/false, 1/0."""
    known = {item.name for item in fields(TlsSetup)} - set(_RECORDED_FIELDS)
    unknown = sorted(set(pairs) - known)
    if unknown:
        raise TlsSetupError(f"Unknown TLS setup option(s) {', '.join(unknown)}; known: {', '.join(sorted(known))}.")
    values: dict[str, Any] = {}
    for key, raw in pairs.items():
        if key in ("ski", "ca_basic_constraints", "server_auth"):
            values[key] = _parse_bool(key, raw)
        else:
            values[key] = str(raw).strip()
    setup = TlsSetup(name=name, **values)
    setup.check()
    return setup


def _parse_bool(key: str, raw: str) -> bool:
    text = str(raw).strip().lower()
    if text in ("on", "yes", "true", "1"):
        return True
    if text in ("off", "no", "false", "0"):
        return False
    raise TlsSetupError(f"{key} is on or off, not {raw!r}.")


def _new_key(curve: str) -> Any:
    if curve == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key({
        "p256": ec.SECP256R1(), "p384": ec.SECP384R1(), "brainpoolp256r1": ec.BrainpoolP256R1(),
    }[curve])


def _subject(common_name: str) -> x509.Name:
    # Test geography only (CLAUDE.md, real-identifier rule).
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM Local eIM"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
    ])


def _sign(builder: x509.CertificateBuilder, key: Any, curve: str,
          layout: cert_layout.CertificateLayout | None = None) -> x509.Certificate:
    if curve == "ed25519":
        return builder.sign(key, None)
    algorithm = layout.hash_algorithm() if layout is not None else None
    if algorithm is None:
        algorithm = hashes.SHA384() if curve == "p384" else hashes.SHA256()
    return builder.sign(key, algorithm)


def _issue(
    setup: TlsSetup,
    *,
    key: Any,
    subject: x509.Name,
    issuer_key: Any,
    issuer: x509.Name,
    ca: bool,
    window: tuple[datetime.datetime, datetime.datetime],
    san: str = "",
    layout: cert_layout.CertificateLayout | None = None,
    eim_id: str = "",
    issuer_curve: str = "",
    written: cert_spec.ResolvedSpec | None = None,
) -> x509.Certificate:
    # The signature follows the issuer's key; a leaf variant may carry a key on another curve than its CA.
    signing_curve = issuer_curve or setup.curve
    if written is not None and written.extensions is not None:
        # The extension set is the one the leaf's text gives, in its order; a layout still decides the
        # serial length and the signature hash.
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(layout.serial_number() if layout is not None else x509.random_serial_number())
            .not_valid_before(window[0])
            .not_valid_after(window[1])
        )
        return _sign(cert_spec.add_extensions(builder, written), issuer_key, signing_curve, layout)
    if layout is not None:
        # The reference decides the extensions, their order and criticality, and the serial length;
        # the rule switches (ski, ca_basic_constraints, server_auth) do not apply to a shaped member.
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(layout.serial_number())
            .not_valid_before(window[0])
            .not_valid_after(window[1])
        )
        builder = layout.add_extensions(builder, public_key=key.public_key(), issuer_public_key=issuer_key.public_key(),
                                        host=san, eim_id=eim_id)
        return _sign(builder, issuer_key, signing_curve, layout)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(window[0])
        .not_valid_after(window[1])
    )
    if setup.ski:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        if issuer_key is not key:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
            )
    if ca:
        if setup.ca_basic_constraints:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        return _sign(builder, issuer_key, signing_curve)
    names: list[x509.GeneralName] = [x509.DNSName(san)] if len(san) > 0 else []
    if setup.registered_id == "on" and len(eim_id) > 0:
        names.append(x509.RegisteredID(x509.ObjectIdentifier(eim_id)))
    if len(names) > 0:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if setup.server_auth:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=setup.curve != "ed25519", key_cert_sign=False,
                      crl_sign=False, encipher_only=False, decipher_only=False),
        critical=True,
    )
    return _sign(builder, issuer_key, signing_curve)


def _leaf_window(validity: str, now: datetime.datetime) -> tuple[datetime.datetime, datetime.datetime]:
    if validity == "expired":
        return now - datetime.timedelta(days=730), now - datetime.timedelta(days=1)
    if validity == "not_yet_valid":
        return now + datetime.timedelta(days=365), now + datetime.timedelta(days=365 + _CERTIFICATE_DAYS)
    return now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=_CERTIFICATE_DAYS)


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _write_key(path: Path, key: Any) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _layouts(
    setup: TlsSetup,
) -> tuple[cert_layout.CertificateLayout | None, cert_layout.CertificateLayout | None]:
    """The (leaf, CA) layouts *setup* names; a CA certificate given as ``layout`` shapes the CA members."""
    leaf: cert_layout.CertificateLayout | None = None
    ca: cert_layout.CertificateLayout | None = None
    try:
        if len(setup.layout) > 0:
            reference = cert_layout.load_reference(setup.layout)
            if reference.is_ca:
                if len(setup.ca_layout) > 0:
                    raise TlsSetupError(f"layout {setup.layout} is a CA certificate; give it as ca_layout, and an "
                                        "end-entity certificate as layout.")
                ca = reference
            else:
                leaf = reference
        if len(setup.ca_layout) > 0:
            ca = cert_layout.load_reference(setup.ca_layout)
            if not ca.is_ca:
                raise TlsSetupError(f"ca_layout {setup.ca_layout} is not a CA certificate (no BasicConstraints cA).")
    except cert_layout.LayoutError as error:
        raise TlsSetupError(str(error)) from error
    setup.layout_reference = leaf.describe() if leaf is not None else ""
    setup.ca_layout_reference = ca.describe() if ca is not None else ""
    return leaf, ca


def _leaf_subject(setup: TlsSetup, identity: EimIdentity, leaf_layout: cert_layout.CertificateLayout | None) -> x509.Name:
    """The subject of *setup*'s leaf as its ``cn`` knob and its layout reference decide."""
    if setup.cn == "eim_id":
        if len(identity.eim_id) > 64:
            raise TlsSetupError(f"cn=eim_id needs an eimId of at most 64 characters (X.520 ub-common-name); "
                                f"{identity.eim_id!r} has {len(identity.eim_id)}.")
        if leaf_layout is None:
            return _subject(identity.eim_id)
        return leaf_layout.subject(setup.leaf_name, common_name=identity.eim_id)
    if leaf_layout is None:
        return _subject(setup.leaf_name)
    if setup.cn == "host":
        return leaf_layout.subject(setup.leaf_name, common_name=setup.leaf_name)
    if setup.cn == "keep":
        return leaf_layout.subject("", common_name=leaf_layout.common_name or setup.leaf_name)
    return leaf_layout.subject(setup.leaf_name)


def build_setup(directory: Path, identity: EimIdentity, setup: TlsSetup, *, replace: bool = False) -> TlsSetup:
    """Generate the chain of *setup* in the store and record it; the setup is not put in use."""
    setup.check()
    folder = setup_directory(directory, setup.name)
    if folder.exists() and not replace:
        raise TlsSetupError(f"TLS setup {setup.name} exists; REMOVE it first or rebuild with --replace.")
    if not folder.exists() and len(list_setups(directory)) >= MAX_SETUPS:
        raise TlsSetupError(f"At most {MAX_SETUPS} TLS setups are kept; remove one first.")
    setup.eim_fqdn = identity.eim_fqdn
    # A rebuild replaces the folder, the leaves issued under the earlier CA included.
    setup.leaf = ""
    leaf_layout, ca_layout = _layouts(setup)
    # A registeredID in a shaped SubjectAltName carries the Local eIM's eimId when that is an OID.
    eim_id = identity.eim_id if identity.eim_id_type == 1 and setup.registered_id != "off" else ""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    setup.created_at = now.isoformat()
    ca_window = (now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=_CERTIFICATE_DAYS))
    leaf_key = _new_key(setup.curve)
    san = "" if setup.san == "none" else setup.leaf_name
    leaf_subject = _leaf_subject(setup, identity, leaf_layout)
    members: dict[str, tuple[x509.Certificate, Any]] = {}
    if setup.chain == "self":
        leaf = _issue(setup, key=leaf_key, subject=leaf_subject, issuer_key=leaf_key, issuer=leaf_subject,
                      ca=False, window=_leaf_window(setup.validity, now), san=san, layout=leaf_layout, eim_id=eim_id)
    else:
        root_key = _new_key(setup.curve)
        root_subject = (ca_layout.subject("") if ca_layout is not None else _subject(f"{setup.name} root CA"))
        root = _issue(setup, key=root_key, subject=root_subject, issuer_key=root_key, issuer=root_subject,
                      ca=True, window=ca_window, layout=ca_layout, eim_id=eim_id)
        members["root"] = (root, root_key)
        issuer_key, issuer_subject = root_key, root_subject
        if setup.chain == "intermediate":
            intermediate_key = _new_key(setup.curve)
            if ca_layout is not None:
                intermediate_subject = ca_layout.subject("", common_name=f"{ca_layout.common_name or setup.name} intermediate CA")
            else:
                intermediate_subject = _subject(f"{setup.name} intermediate CA")
            intermediate = _issue(setup, key=intermediate_key, subject=intermediate_subject, issuer_key=root_key,
                                  issuer=root_subject, ca=True, window=ca_window, layout=ca_layout, eim_id=eim_id)
            members["intermediate"] = (intermediate, intermediate_key)
            issuer_key, issuer_subject = intermediate_key, intermediate_subject
        leaf = _issue(setup, key=leaf_key, subject=leaf_subject, issuer_key=issuer_key, issuer=issuer_subject,
                      ca=False, window=_leaf_window(setup.validity, now), san=san, layout=leaf_layout, eim_id=eim_id)
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    _write_key(folder / LEAF_KEY_FILE, leaf_key)
    (folder / LEAF_FILE).write_bytes(_pem(leaf))
    chain = [leaf]
    for role, (certificate, key) in members.items():
        (folder / f"{role}.pem").write_bytes(_pem(certificate))
        _write_key(folder / f"{role}_key.pem", key)
    if setup.send in ("chain", "full") and "intermediate" in members:
        chain.append(members["intermediate"][0])
    if setup.send == "full" and "root" in members:
        chain.append(members["root"][0])
    (folder / CHAIN_FILE).write_bytes(b"".join(_pem(item) for item in chain))
    if setup.client_auth != "none":
        anchors, setup.client_ca_reference = _client_anchors(setup, folder, ca_window)
        (folder / CLIENT_CA_FILE).write_bytes(b"".join(_pem(item) for item in anchors))
    else:
        setup.client_ca_reference = ""
    (folder / SETUP_FILE).write_text(json.dumps(asdict(setup), indent=2) + "\n", encoding="utf-8")
    return setup


def _client_anchors(
    setup: TlsSetup, folder: Path, window: tuple[datetime.datetime, datetime.datetime],
) -> tuple[list[x509.Certificate], str]:
    """The CA certificates the listener trusts client certificates under: ``client_ca`` refs, else a client CA of the setup's own.

    The server chain is not reused: a leaf cannot issue (no cA, no keyCertSign),
    and a deployment keeps its client CA apart from its server CA.
    """
    if len(setup.client_ca) > 0:
        anchors: list[x509.Certificate] = []
        labels: list[str] = []
        for spec in (item.strip() for item in setup.client_ca.split(",") if item.strip()):
            try:
                layout = cert_layout.load_reference(spec)
            except cert_layout.LayoutError as error:
                raise TlsSetupError(f"client_ca: {error}") from error
            anchors.append(layout.reference)
            labels.append(f"{layout.label} ({layout.common_name or layout.subject_text})")
        return anchors, "; ".join(labels)
    key = _new_key(setup.curve)
    subject = _subject(f"{setup.name} client CA")
    certificate = _issue(setup, key=key, subject=subject, issuer_key=key, issuer=subject, ca=True, window=window)
    _write_key(folder / CLIENT_CA_KEY_FILE, key)
    return [certificate], "the setup's own client CA (TLS-SETUP CLIENT-CERT issues a client certificate under it)"


def issue_client_certificate(directory: Path, name: str, *, common_name: str = "") -> tuple[Path, Path]:
    """Issue a TLS client certificate under setup *name*'s own client CA; returns the (certificate, key) paths.

    For a client of the mutual-TLS form: KeyUsage digitalSignature, ExtendedKeyUsage
    clientAuth, a SubjectKeyIdentifier, valid ten years. The pair lands in the
    setup folder as ``client.pem`` / ``client_key.pem`` (mode 0600). A setup
    without client authentication, or one whose ``client_ca`` names another
    CA, has no key to issue with.
    """
    setup = load_setup(directory, name)
    folder = setup_directory(directory, name)
    if setup.client_auth == "none":
        raise TlsSetupError(f"TLS setup {name} has client_auth=none; rebuild it with client_auth=optional or required.")
    if not (folder / CLIENT_CA_KEY_FILE).is_file():
        raise TlsSetupError(f"TLS setup {name} trusts client certificates of {setup.client_ca_reference or setup.client_ca}; "
                            "that CA issues them, not this setup.")
    try:
        issuer_key = serialization.load_pem_private_key((folder / CLIENT_CA_KEY_FILE).read_bytes(), password=None)
        issuer = x509.load_pem_x509_certificate((folder / CLIENT_CA_FILE).read_bytes())
    except (OSError, ValueError, TypeError) as error:
        raise TlsSetupError(f"TLS setup {name}: its client CA material does not load: {error}") from error
    key = _new_key(setup.curve)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    subject = _subject(common_name or f"{name} TLS client")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=_CERTIFICATE_DAYS))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
    )
    certificate = _sign(builder, issuer_key, setup.curve)
    certificate_path = folder / "client.pem"
    key_path = folder / "client_key.pem"
    _write_key(key_path, key)
    certificate_path.write_bytes(_pem(certificate))
    return certificate_path, key_path


def load_setup(directory: Path, name: str) -> TlsSetup:
    path = setup_directory(directory, name) / SETUP_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise TlsSetupError(f"No TLS setup {name}.") from error
    except json.JSONDecodeError as error:
        raise TlsSetupError(f"{path} is not JSON: {error}") from error
    known = {item.name for item in fields(TlsSetup)}
    return TlsSetup(**{key: value for key, value in data.items() if key in known})


def list_setups(directory: Path) -> list[TlsSetup]:
    folder = setups_directory(directory)
    if not folder.is_dir():
        return []
    found: list[TlsSetup] = []
    for child in sorted(folder.iterdir()):
        if child.is_dir() and (child / SETUP_FILE).is_file():
            try:
                found.append(load_setup(directory, child.name))
            except TlsSetupError:
                continue
    return found


def active_name(directory: Path) -> str:
    """The setup in use, or '' when the identity's own TLS certificate is."""
    try:
        data = json.loads((setups_directory(directory) / ACTIVE_FILE).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return ""
    name = str(data.get("name", "")) if isinstance(data, dict) else ""
    if len(name) == 0 or not (setups_directory(directory) / name / SETUP_FILE).is_file():
        return ""
    return name


def use_setup(directory: Path, name: str) -> str:
    """Put *name* in use ('' or ``identity`` for the identity's own certificate); return the previous one."""
    previous = active_name(directory)
    folder = setups_directory(directory)
    if name in ("", "identity"):
        (folder / ACTIVE_FILE).unlink(missing_ok=True)
        return previous
    load_setup(directory, name)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / ACTIVE_FILE).write_text(json.dumps({"name": name}) + "\n", encoding="utf-8")
    return previous


def remove_setup(directory: Path, name: str) -> None:
    folder = setup_directory(directory, name)
    if not (folder / SETUP_FILE).is_file():
        raise TlsSetupError(f"No TLS setup {name}.")
    if active_name(directory) == name:
        raise TlsSetupError(f"TLS setup {name} is in use; TLS-SETUP USE identity (or another) first.")
    shutil.rmtree(folder)


# -- leaf variants ----------------------------------------------------------


@dataclass
class LeafVariant:
    """One leaf certificate under a setup's own CA: certificate options and what is sent with it.

    The setup's name, its CA and what the card was told to trust stay as they
    are while the leaf on the name is swapped, so a card that trusts the root
    or the intermediate meets the next leaf without a new AddInitialEim.
    ``sha256`` is the SHA-256 of the leaf's DER, the name the handshake
    records know it by.
    """

    name: str
    cn: str = "auto"
    san: str = ""
    registered_id: str = "auto"
    layout: str = ""
    validity: str = "valid"
    ski: bool = True
    server_auth: bool = True
    curve: str = "p256"
    send: str = "chain"
    created_at: str = ""
    layout_reference: str = ""
    sha256: str = ""
    # The subject and the extensions given literally (``cert_spec`` text); '' when the options decide both.
    spec: str = ""


def certificate_sha256(path: Path) -> str:
    """SHA-256 (upper-case hex) of the DER of the first certificate in PEM file *path*; '' when it does not read."""
    try:
        certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
    except (OSError, ValueError):
        return ""
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest().upper()


def served_leaf(setup: TlsSetup) -> str:
    """The name of the leaf *setup*'s top-level files hold, which is the one the listener serves."""
    return setup.leaf or BUILT_LEAF


def trust_follows_leaf(setup: TlsSetup) -> bool:
    """Whether the card was told to trust the leaf itself, so that another leaf needs a write to the card."""
    return setup.trust in ("leaf", "leaf_key")


def _built_variant(setup: TlsSetup, folder: Path) -> LeafVariant:
    """The leaf *setup* was built with, described by the setup's own options."""
    kept = folder / LEAVES_DIR / BUILT_LEAF / LEAF_FILE
    return LeafVariant(
        name=BUILT_LEAF, created_at=setup.created_at, layout_reference=setup.layout_reference,
        sha256=certificate_sha256(kept if kept.is_file() else folder / LEAF_FILE),
        **{key: getattr(setup, key) for key in _LEAF_OPTIONS},
    )


def _keep_built_leaf(folder: Path) -> None:
    """Copy the leaf the setup was built with into leaves/built, once, before another one can take its place."""
    target = folder / LEAVES_DIR / BUILT_LEAF
    if target.is_dir():
        return
    target.mkdir(parents=True)
    for file_name in (LEAF_KEY_FILE, LEAF_FILE, CHAIN_FILE):
        shutil.copy2(folder / file_name, target / file_name)


def _read_leaf(folder: Path) -> LeafVariant:
    path = folder / LEAF_INFO_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TlsSetupError(f"{path} does not read: {error}") from error
    if not isinstance(data, dict):
        raise TlsSetupError(f"{path} does not hold a leaf description.")
    known = {item.name for item in fields(LeafVariant)}
    return LeafVariant(**{key: value for key, value in data.items() if key in known})


# The options that shape what a leaf's text gives literally: naming both is a contradiction.
_SUBJECT_OPTIONS = ("cn",)
_EXTENSION_OPTIONS = ("san", "registered_id", "ski", "server_auth")


def _leaf_text(spec: str, pairs: dict[str, str]) -> str:
    """*spec* in its canonical form, refused when it does not read or an option shapes the same part."""
    if len(str(spec or "").strip()) == 0:
        return ""
    try:
        parsed = cert_spec.parse_text(spec)
    except cert_spec.SpecError as error:
        raise TlsSetupError(f"The leaf's text does not read: {error}") from error
    for given, options, part in ((parsed.subject is not None, _SUBJECT_OPTIONS, "subject"),
                                 (parsed.extensions is not None, _EXTENSION_OPTIONS, "extensions")):
        clash = [key for key in options if key in pairs]
        if given and clash:
            raise TlsSetupError(f"The text gives the {part}, so {', '.join(clash)} cannot shape "
                                f"{'it' if part == 'subject' else 'them'} as well; leave "
                                f"{'it' if len(clash) == 1 else 'them'} out.")
    return cert_spec.to_text(parsed)


def parse_leaf_options(setup: TlsSetup, name: str, pairs: dict[str, str], *, spec: str = "") -> LeafVariant:
    """A leaf variant of *setup* from ``key=value`` pairs; an option left out is the setup's own, ``layout=none`` drops its layout.

    *spec* is the leaf's subject and extensions as text (``cert_spec``): what it
    gives is built as written, and the options decide the rest.
    """
    if _NAME.match(str(name or "")) is None:
        raise TlsSetupError(f"A leaf name is 1-48 of A-Z a-z 0-9 . _ -, starting alphanumeric; got {name!r}.")
    if name == BUILT_LEAF:
        raise TlsSetupError(f"{BUILT_LEAF} names the leaf the setup was built with; give the new one another name.")
    unknown = sorted(set(pairs) - set(_LEAF_OPTIONS))
    if unknown:
        raise TlsSetupError(f"Unknown leaf option(s) {', '.join(unknown)}; known: {', '.join(sorted(_LEAF_OPTIONS))}. "
                            "The chain, the trust, the TLS versions and the client authentication belong to the setup.")
    values: dict[str, Any] = {key: getattr(setup, key) for key in _LEAF_OPTIONS}
    for key, raw in pairs.items():
        values[key] = _parse_bool(key, raw) if key in ("ski", "server_auth") else str(raw).strip()
    if str(values["layout"]).lower() == "none":
        values["layout"] = ""
    variant = LeafVariant(name=name, spec=_leaf_text(spec, pairs), **values)
    with_changes(setup, **{key: getattr(variant, key) for key in _LEAF_OPTIONS}).check()
    return variant


def issue_leaf(directory: Path, identity: EimIdentity, setup_name: str, variant: LeafVariant, *,
               replace: bool = False) -> LeafVariant:
    """Issue *variant* under setup *setup_name*'s own CA and keep it beside the others; what the listener serves does not change.

    The issuer is the setup's intermediate when it has one, else its root; a
    self-signed setup gets another self-signed leaf. The leaf the setup was
    built with is kept as ``built`` the first time another one is issued.
    """
    setup = load_setup(directory, setup_name)
    folder = setup_directory(directory, setup_name)
    target = folder / LEAVES_DIR / variant.name
    if variant.name == BUILT_LEAF:
        raise TlsSetupError(f"{BUILT_LEAF} names the leaf the setup was built with; give the new one another name.")
    if served_leaf(setup) == variant.name:
        raise TlsSetupError(f"Leaf {variant.name} is the one TLS setup {setup_name} serves; put another on the name first.")
    if target.exists() and not replace:
        raise TlsSetupError(f"TLS setup {setup_name} has a leaf {variant.name}; REMOVE it first or issue it with --replace.")
    if not target.exists() and len(list_leaves(directory, setup_name)) >= MAX_LEAVES:
        raise TlsSetupError(f"At most {MAX_LEAVES} leaves are kept per TLS setup; remove one first.")
    shaped = with_changes(setup, **{key: getattr(variant, key) for key in _LEAF_OPTIONS})
    shaped.check()
    leaf_layout: cert_layout.CertificateLayout | None = None
    if len(shaped.layout) > 0:
        try:
            reference = cert_layout.load_reference(shaped.layout)
        except cert_layout.LayoutError as error:
            raise TlsSetupError(str(error)) from error
        if not reference.is_ca:
            leaf_layout = reference
        elif shaped.layout != setup.layout:
            raise TlsSetupError(f"layout {shaped.layout} is a CA certificate; a leaf takes an end-entity certificate's layout.")
        # Else the setup's own layout is a CA reference: it shaped the CA members, and the leaves are generic.
    variant.layout_reference = leaf_layout.describe() if leaf_layout is not None else ""
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    variant.created_at = now.isoformat()
    leaf_key = _new_key(shaped.curve)
    eim_id = identity.eim_id if identity.eim_id_type == 1 and shaped.registered_id != "off" else ""
    above: list[tuple[str, x509.Certificate]] = []
    issuer_subject: x509.Name | None = None
    try:
        for role in ("intermediate", "root"):
            if (folder / f"{role}.pem").is_file():
                above.append((role, x509.load_pem_x509_certificate((folder / f"{role}.pem").read_bytes())))
        if setup.chain == "self":
            issuer_key, issuer_curve = leaf_key, shaped.curve
        else:
            issuer_role = "intermediate" if setup.chain == "intermediate" else "root"
            issuer_key = serialization.load_pem_private_key((folder / f"{issuer_role}_key.pem").read_bytes(), password=None)
            issuer_subject = x509.load_pem_x509_certificate((folder / f"{issuer_role}.pem").read_bytes()).subject
            issuer_curve = setup.curve
    except (OSError, ValueError, TypeError) as error:
        raise TlsSetupError(f"TLS setup {setup_name}: its CA material does not load: {error}") from error
    written: cert_spec.ResolvedSpec | None = None
    if len(variant.spec) > 0:
        # Placeholders and key identifiers are filled for this leaf: its host, the eimId, its key and its issuer's.
        try:
            written = cert_spec.resolve(cert_spec.parse_text(variant.spec), cert_spec.BuildContext(
                host=setup.effective_fqdn, eim_id=identity.eim_id, public_key=leaf_key.public_key(),
                issuer_public_key=issuer_key.public_key()))
        except cert_spec.SpecError as error:
            raise TlsSetupError(f"The leaf's text does not build: {error}") from error
    if written is not None and written.subject is not None:
        subject = written.subject
    else:
        subject = _leaf_subject(shaped, identity, leaf_layout)
    if issuer_subject is None:
        issuer_subject = subject
    try:
        leaf = _issue(shaped, key=leaf_key, subject=subject, issuer_key=issuer_key, issuer=issuer_subject, ca=False,
                      window=_leaf_window(shaped.validity, now), san="" if shaped.san == "none" else shaped.leaf_name,
                      layout=leaf_layout, eim_id=eim_id, issuer_curve=issuer_curve, written=written)
        if written is not None:
            # What was signed is read back: a leaf that is not the text's octets is not kept.
            cert_spec.check_built(leaf, written)
    except cert_spec.SpecError as error:
        raise TlsSetupError(f"The leaf was not built as written: {error}") from error
    except (ValueError, TypeError) as error:
        if len(variant.spec) == 0:
            raise
        raise TlsSetupError(f"The leaf's text does not build: {error}") from error
    _keep_built_leaf(folder)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    _write_key(target / LEAF_KEY_FILE, leaf_key)
    (target / LEAF_FILE).write_bytes(_pem(leaf))
    chain = [leaf]
    for role, certificate in above:
        if shaped.send == "full" or (shaped.send == "chain" and role == "intermediate"):
            chain.append(certificate)
    (target / CHAIN_FILE).write_bytes(b"".join(_pem(item) for item in chain))
    variant.sha256 = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    (target / LEAF_INFO_FILE).write_text(json.dumps(asdict(variant), indent=2) + "\n", encoding="utf-8")
    return variant


def list_leaves(directory: Path, setup_name: str) -> list[LeafVariant]:
    """The leaves of setup *setup_name*: the one it was built with first, then those issued since, by name."""
    setup = load_setup(directory, setup_name)
    folder = setup_directory(directory, setup_name)
    leaves = [_built_variant(setup, folder)]
    kept = folder / LEAVES_DIR
    if kept.is_dir():
        for child in sorted(kept.iterdir()):
            if child.name == BUILT_LEAF or not (child / LEAF_INFO_FILE).is_file():
                continue
            try:
                leaves.append(_read_leaf(child))
            except TlsSetupError:
                continue
    return leaves


def load_leaf(directory: Path, setup_name: str, name: str) -> LeafVariant:
    for variant in list_leaves(directory, setup_name):
        if variant.name == name:
            return variant
    raise TlsSetupError(f"TLS setup {setup_name} has no leaf {name}.")


def use_leaf(directory: Path, setup_name: str, name: str) -> str:
    """Put leaf *name* on setup *setup_name*'s name and return the one it replaces.

    The setup's top-level leaf, key and chain files become that leaf's, which
    is what the listener loads when it starts and what AddInitialEim reads for
    a setup whose trust is the leaf. The three files are staged first, so a
    copy that fails changes nothing.
    """
    setup = load_setup(directory, setup_name)
    folder = setup_directory(directory, setup_name)
    previous = served_leaf(setup)
    load_leaf(directory, setup_name, name)
    if name == previous:
        return previous
    source = folder / LEAVES_DIR / name
    _keep_built_leaf(folder)
    staged: list[tuple[Path, Path]] = []
    try:
        for file_name in (LEAF_KEY_FILE, LEAF_FILE, CHAIN_FILE):
            temporary = folder / f"{file_name}.new"
            shutil.copy2(source / file_name, temporary)
            staged.append((temporary, folder / file_name))
    except OSError as error:
        for temporary, _final in staged:
            temporary.unlink(missing_ok=True)
        raise TlsSetupError(f"Leaf {name} of TLS setup {setup_name} does not copy: {error}") from error
    for temporary, final in staged:
        os.replace(temporary, final)
    setup.leaf = "" if name == BUILT_LEAF else name
    (folder / SETUP_FILE).write_text(json.dumps(asdict(setup), indent=2) + "\n", encoding="utf-8")
    return previous


def remove_leaf(directory: Path, setup_name: str, name: str) -> None:
    setup = load_setup(directory, setup_name)
    if name == BUILT_LEAF:
        raise TlsSetupError("The leaf a setup was built with stays with it; removing the setup removes it.")
    if served_leaf(setup) == name:
        raise TlsSetupError(f"Leaf {name} is the one TLS setup {setup_name} serves; put another on the name first.")
    target = setup_directory(directory, setup_name) / LEAVES_DIR / name
    if not (target / LEAF_INFO_FILE).is_file():
        raise TlsSetupError(f"TLS setup {setup_name} has no leaf {name}.")
    shutil.rmtree(target)


def leaf_certificate_path(directory: Path, setup_name: str, name: str) -> Path:
    """The certificate file of leaf *name*; the leaf a setup was built with is the top-level one until another is issued."""
    load_leaf(directory, setup_name, name)
    folder = setup_directory(directory, setup_name)
    kept = folder / LEAVES_DIR / name / LEAF_FILE
    return kept if kept.is_file() else folder / LEAF_FILE


def leaf_der(directory: Path, setup_name: str, name: str) -> tuple[bytes, bytes]:
    """(certificate, SubjectPublicKeyInfo) of leaf *name* in DER: what trustedCertificateTls and trustedEimPkTls carry for it."""
    path = leaf_certificate_path(directory, setup_name, name)
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as error:
        raise TlsSetupError(f"{path} does not read: {error}") from error
    spki = certificate.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    return certificate.public_bytes(serialization.Encoding.DER), spki


def leaf_summary(variant: LeafVariant) -> str:
    """One line on how *variant* is shaped: by its options, by its text, or by both."""
    subject_written = extensions_written = False
    if len(variant.spec) > 0:
        try:
            parsed = cert_spec.parse_text(variant.spec)
            subject_written, extensions_written = parsed.subject is not None, parsed.extensions is not None
        except cert_spec.SpecError:
            pass
    parts = ["subject as written" if subject_written else f"CN {variant.cn}"]
    if extensions_written:
        parts.append("extensions as written")
    else:
        parts.append(f"leaf name {variant.san or 'the setup FQDN'}, registeredID {variant.registered_id}, "
                     f"SKI {'on' if variant.ski else 'off'}, serverAuth {'on' if variant.server_auth else 'off'}")
    parts.append(f"leaf {variant.validity}, key {variant.curve}, listener sends {variant.send}")
    return ", ".join(parts)


def leaf_text(directory: Path, setup_name: str, name: str) -> str:
    """Leaf *name*'s subject and extensions as text (``cert_spec``), decoded from its certificate.

    A key identifier computed from the leaf's key or its issuer's is written
    ``hash`` / ``keyid``, so the text issues a further leaf as it stands.
    """
    setup = load_setup(directory, setup_name)
    folder = setup_directory(directory, setup_name)
    path = leaf_certificate_path(directory, setup_name, name)
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        issuer_key = certificate.public_key()
        if setup.chain != "self":
            issuer_role = "intermediate" if setup.chain == "intermediate" else "root"
            issuer_key = x509.load_pem_x509_certificate((folder / f"{issuer_role}.pem").read_bytes()).public_key()
        return cert_spec.to_text(cert_spec.from_certificate(certificate, issuer_public_key=issuer_key))
    except (OSError, ValueError, TypeError) as error:
        raise TlsSetupError(f"Leaf {name} of TLS setup {setup_name} does not decode: {error}") from error


def reference_text(reference: str, *, stored_only: bool = False) -> str:
    """The subject and extensions of a stored certificate or a certificate file as text (``cert_spec``).

    *stored_only* looks in the AddInitialEim builder store alone: a caller
    that takes the name from a request opens no file for it.
    """
    try:
        if stored_only:
            from SCP11.shared.eim_builder_store import EimBuilderStoreError, read_certificate

            try:
                certificate = x509.load_der_x509_certificate(read_certificate(str(reference or "").strip()).der)
            except (EimBuilderStoreError, ValueError) as error:
                raise TlsSetupError(str(error)) from error
        else:
            certificate = cert_layout.load_reference(reference).reference
        return cert_spec.to_text(cert_spec.from_certificate(certificate))
    except (cert_layout.LayoutError, cert_spec.SpecError) as error:
        raise TlsSetupError(str(error)) from error


def describe_leaf(directory: Path, setup_name: str, variant: LeafVariant) -> list[str]:
    setup = load_setup(directory, setup_name)
    source = leaf_certificate_path(directory, setup_name, variant.name)
    lines = [leaf_summary(variant)]
    if variant.layout_reference:
        lines.append(f"leaf layout   {variant.layout_reference}")
    try:
        lines.append(_certificate_line("leaf", x509.load_pem_x509_certificate(source.read_bytes())))
    except (OSError, ValueError) as error:
        lines.append(f"leaf         does not read: {error}")
    lines.append(f"SHA-256 {variant.sha256 or '-'}" + ("; served on the setup's name" if served_leaf(setup) == variant.name else ""))
    lines.append(f"file {source}")
    return lines


def _resolve_name(directory: Path, name: str | None) -> str:
    """The setup a caller means: None for the one in use, '' or ``identity`` for the identity's own, else *name*."""
    if name is None:
        return active_name(directory)
    if name in ("", "identity"):
        return ""
    load_setup(directory, name)
    return name


def effective_fqdn(directory: Path, identity: EimIdentity | None, name: str | None = None) -> str:
    """The eIM FQDN the card is given under setup *name* (None: the one in use): the setup's own, else the identity's."""
    resolved = _resolve_name(directory, name)
    if len(resolved) > 0:
        setup = load_setup(directory, resolved)
        if len(setup.fqdn) > 0:
            return setup.fqdn
    return identity.eim_fqdn if identity is not None else ""


def fqdn_source(directory: Path, name: str | None = None) -> str:
    """Where the effective FQDN comes from: ``TLS setup <name>`` or ``the identity``."""
    resolved = _resolve_name(directory, name)
    if len(resolved) > 0 and len(load_setup(directory, resolved).fqdn) > 0:
        return f"TLS setup {resolved}"
    return "the identity"


def _setup_material(directory: Path, setup: TlsSetup) -> ServingMaterial:
    folder = setup_directory(directory, setup.name)
    client_ca = folder / CLIENT_CA_FILE
    leaf_name = setup.leaf_name
    names = tuple(dict.fromkeys(item.lower() for item in (setup.effective_fqdn, leaf_name)
                                if item and not item.startswith("*.")))
    patterns = (leaf_name.lower(),) if leaf_name.startswith("*.") else ()
    return ServingMaterial(
        label=setup.name, chain_path=str(folder / CHAIN_FILE), key_path=str(folder / LEAF_KEY_FILE),
        versions=setup.versions, ciphers=setup.ciphers, client_auth=setup.client_auth,
        client_ca_path=str(client_ca) if setup.client_auth != "none" and client_ca.is_file() else "",
        sni_names=(leaf_name,) if setup.sni == "required" else (), names=names, patterns=patterns,
        leaf=served_leaf(setup), leaf_sha256=certificate_sha256(folder / LEAF_FILE),
    )


def _identity_material(identity: EimIdentity | None) -> ServingMaterial | None:
    if identity is None or not identity.tls_certificate_path or not identity.tls_key_path:
        return None
    return ServingMaterial(label="identity", chain_path=identity.tls_certificate_path, key_path=identity.tls_key_path,
                           names=(identity.eim_fqdn.lower(),) if identity.eim_fqdn else (),
                           leaf="identity", leaf_sha256=certificate_sha256(Path(identity.tls_certificate_path)))


def serving_material(directory: Path, identity: EimIdentity | None, name: str | None = None) -> ServingMaterial | None:
    """What the card-facing listener serves by default: setup *name* (None: the one in use), else the identity's pair, else None."""
    resolved = _resolve_name(directory, name)
    if len(resolved) > 0:
        return _setup_material(directory, load_setup(directory, resolved))
    return _identity_material(identity)


def served_materials(directory: Path, identity: EimIdentity | None) -> list[ServingMaterial]:
    """Every chain the card-facing listener serves at once: the default first, then each other setup, then the identity's.

    A card keeps the name and trust its AddInitialEim carried, so the listener
    answers every setup's name with that setup's chain (the ClientHello's
    server_name picks it) and a card swap needs no change of the service. The
    default is the setup in use, for a client that names no host.
    """
    default = serving_material(directory, identity)
    materials: list[ServingMaterial] = [default] if default is not None else []
    for setup in list_setups(directory):
        if default is not None and setup.name == default.label:
            continue
        materials.append(_setup_material(directory, setup))
    own = _identity_material(identity)
    if own is not None and (default is None or default.label != "identity"):
        materials.append(own)
    return materials


def listener_groups(materials: list[ServingMaterial]) -> list[list[ServingMaterial]]:
    """How the served chains spread over listeners.

    The chains that authenticate the server only share one listener and are
    picked by server name; a chain that asks the client for a certificate
    gets a listener of its own, because the verify mode belongs to the
    listening context, not to the name a ClientHello asks for. The group
    holding the default comes first.
    """
    if len(materials) == 0:
        return []
    plain = [item for item in materials if item.client_auth == "none"]
    mutual = [[item] for item in materials if item.client_auth != "none"]
    groups = ([plain] if plain else []) + mutual
    groups.sort(key=lambda group: 0 if materials[0] in group else 1)
    return groups


def trusted_tls_key_data(directory: Path, identity: EimIdentity, name: str | None = None) -> KeyData | None:
    """trustedPublicKeyDataTls for AddInitialEim: per setup *name* (None: the one in use), else the identity's TLS certificate."""
    resolved = _resolve_name(directory, name)
    if len(resolved) == 0:
        der = identity.tls_certificate_der()
        return KeyData(form=KEY_FORM_CERTIFICATE, der=der) if len(der) > 0 else None
    setup = load_setup(directory, resolved)
    folder = setup_directory(directory, resolved)
    if setup.trust == "none":
        return None
    if setup.trust == "leaf_key":
        leaf = x509.load_pem_x509_certificate((folder / LEAF_FILE).read_bytes())
        spki = leaf.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        return KeyData(form=KEY_FORM_PUBLIC_KEY, der=spki)
    member = LEAF_FILE if setup.trust == "leaf" else f"{setup.trust}.pem"
    certificate = x509.load_pem_x509_certificate((folder / member).read_bytes())
    return KeyData(form=KEY_FORM_CERTIFICATE, der=certificate.public_bytes(serialization.Encoding.DER))


def _certificate_line(role: str, certificate: x509.Certificate) -> str:
    try:
        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        common_name = "-"
    # A written leaf may carry a value the certificate library has no class for; the line still says the rest.
    try:
        san = ",".join(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                       .get_values_for_type(x509.DNSName)) or "-"
    except x509.ExtensionNotFound:
        san = "none"
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        san = "see TEXT"
    try:
        ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex().upper()
    except x509.ExtensionNotFound:
        ski = "none"
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        ski = "see TEXT"
    key = certificate.public_key()
    key_name = "Ed25519" if isinstance(key, ed25519.Ed25519PublicKey) else getattr(getattr(key, "curve", None), "name", "?")
    return (f"{role:<12} CN {common_name}; SAN {san}; key {key_name}; SKI {ski}; "
            f"valid {certificate.not_valid_before_utc:%Y-%m-%d} to {certificate.not_valid_after_utc:%Y-%m-%d}")


def describe_setup(directory: Path, setup: TlsSetup) -> list[str]:
    folder = setup_directory(directory, setup.name)
    lines = [
        f"chain {setup.chain}, card trusts {setup.trust}, listener sends {setup.send}, curve {setup.curve}, "
        f"TLS {setup.versions}{', ciphers ' + setup.ciphers if setup.ciphers else ''}",
        f"rules: SKI {'on' if setup.ski else 'off'}, CA BasicConstraints {'on' if setup.ca_basic_constraints else 'off'}, "
        f"serverAuth {'on' if setup.server_auth else 'off'}, leaf {setup.validity}; built for eIM FQDN "
        f"{setup.eim_fqdn or '-'} at {setup.created_at or '-'}",
        f"eIM FQDN {setup.effective_fqdn or '-'} ({'the setup' + chr(39) + 's own' if setup.fqdn else 'the identity' + chr(39) + 's'}): "
        "AddInitialEim carries it as eimFqdn and the leaf is issued for it",
        f"client auth {setup.client_auth}"
        + (f" (client CA: {setup.client_ca_reference})" if setup.client_auth != "none" else " (server authentication only)")
        + f"; SNI {setup.sni}" + (f" (the ClientHello has to name {setup.leaf_name})" if setup.sni == "required" else ""),
    ]
    if setup.layout_reference:
        lines.append(f"leaf layout   {setup.layout_reference}")
    if setup.layout_reference or setup.registered_id != "auto":
        lines.append(f"leaf naming   registeredID {setup.registered_id}, CN {setup.cn}")
    if setup.ca_layout_reference:
        lines.append(f"CA layout     {setup.ca_layout_reference}")
    issued = [variant.name for variant in list_leaves(directory, setup.name)][1:]
    if issued or setup.leaf:
        lines.append(f"leaf variants {', '.join([BUILT_LEAF, *issued])}; on the name: {served_leaf(setup)}")
    if (folder / "client.pem").is_file():
        lines.append(_certificate_line("client", x509.load_pem_x509_certificate((folder / "client.pem").read_bytes())))
    for role, file_name in (("leaf", LEAF_FILE), ("intermediate", "intermediate.pem"), ("root", "root.pem")):
        path = folder / file_name
        if path.is_file():
            lines.append(_certificate_line(role, x509.load_pem_x509_certificate(path.read_bytes())))
    lines.append(f"files {folder}")
    return lines


__all__ = [
    "BUILT_LEAF", "CHAINS", "CLIENT_AUTHS", "COMMON_NAMES", "CURVES", "MAX_LEAVES", "REGISTERED_IDS", "RESERVED_TEST_DOMAINS",
    "RESERVED_TEST_TLDS", "SENDS", "SNIS", "TRUSTS", "VALIDITIES", "VERSIONS", "LeafVariant", "ServingMaterial", "TlsSetup",
    "TlsSetupError", "active_name", "build_setup", "certificate_sha256", "describe_leaf", "describe_setup", "effective_fqdn",
    "fqdn_source", "issue_client_certificate", "issue_leaf", "leaf_certificate_path", "leaf_der", "leaf_summary",
    "leaf_text", "list_leaves", "reference_text",
    "list_setups", "listener_groups", "LOCAL_EIM_NAME_PATTERN", "load_leaf", "load_setup", "local_eim_name", "parse_leaf_options", "parse_options",
    "remove_leaf", "remove_setup", "reserved_test_name", "served_leaf", "served_materials", "serving_material",
    "setup_directory", "trust_follows_leaf", "trusted_tls_key_data", "use_leaf", "use_setup",
]
