# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""X.509 certificate rows for the eSIM shells: RFC 5280 fields, named extensions and a chain check.

The ES10b GetCerts printers of the SCP03 eSIM manager, the eSIM Live console and the
local-access discovery snapshot render the EUM and eUICC certificates through these rows.
Every extension is named and decoded, the GSMA RSP role and the Permitted EINs extension
are spelled out, and a certificate whose issuer sits in the same response has its
signature verified against that issuer. A TLS server's Certificate message, as a BIP
observer reads it off the wire, gets a shorter view of the same facts plus the RFC 2818
server identity check (:func:`tls_certificate_rows`). Nothing here raises on malformed
input: a certificate that does not parse becomes a ``Decode error`` row.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import warnings
from collections.abc import Mapping, Sequence
from typing import NamedTuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv
from SCP11.shared.rsp_roles import ID_RSP, RSP_ROLE_OIDS

# SGP.22 v3.1 §2.4a.1.0: id-rsp-extensions ::= {id-rsp-cert-objects 2}, id-rsp-cert-objects
# ::= {id-rsp 2}, id-rsp-extension-permitted-eins ::= {id-rsp-extensions 0}; its extnValue is
# PermittedEins ::= SEQUENCE OF PrintableString.
ID_RSP_EXTENSION_PERMITTED_EINS = ID_RSP + ".2.2.0"

_ROLE_NAMES = {oid: f"id-rspRole-{role}" for role, oid in RSP_ROLE_OIDS.items()}
# SGP.22 v3.1 §4.5.2.1.0.2 Table 11: the subject serialNumber of an eUICC certificate is the EID.
_EUICC_ROLES = frozenset({RSP_ROLE_OIDS["euicc"], RSP_ROLE_OIDS["euicc-v2"]})

# RFC 5280 Appendix A: id-ce ::= {2 5 29}, id-pkix ::= {1 3 6 1 5 5 7}, id-pe ::= {id-pkix 1},
# id-kp ::= {id-pkix 3}, id-ad ::= {id-pkix 48}.
_ID_CE = "2.5.29"
_ID_PKIX = "1.3.6.1.5.5.7"

# Extension names as RFC 5280 §4.2.1.1 - §4.2.1.15 and §4.2.2.1 head them.
_EXTENSION_NAMES = {
    _ID_CE + ".14": "Subject Key Identifier",
    _ID_CE + ".15": "Key Usage",
    _ID_CE + ".17": "Subject Alternative Name",
    _ID_CE + ".18": "Issuer Alternative Name",
    _ID_CE + ".19": "Basic Constraints",
    _ID_CE + ".30": "Name Constraints",
    _ID_CE + ".31": "CRL Distribution Points",
    _ID_CE + ".32": "Certificate Policies",
    _ID_CE + ".33": "Policy Mappings",
    _ID_CE + ".35": "Authority Key Identifier",
    _ID_CE + ".36": "Policy Constraints",
    _ID_CE + ".37": "Extended Key Usage",
    _ID_CE + ".46": "Freshest CRL",
    _ID_CE + ".54": "Inhibit anyPolicy",
    _ID_PKIX + ".1.1": "Authority Information Access",
    ID_RSP_EXTENSION_PERMITTED_EINS: "Permitted EINs",
}
# KeyUsage bit names, RFC 5280 §4.2.1.3, against the cryptography attribute that holds each.
_KEY_USAGE_BITS = (
    ("digital_signature", "digitalSignature"),
    ("content_commitment", "nonRepudiation"),
    ("key_encipherment", "keyEncipherment"),
    ("data_encipherment", "dataEncipherment"),
    ("key_agreement", "keyAgreement"),
    ("key_cert_sign", "keyCertSign"),
    ("crl_sign", "cRLSign"),
)
# RFC 5280 §4.2.1.12.
_EXTENDED_KEY_USAGES = {
    _ID_CE + ".37.0": "anyExtendedKeyUsage",
    _ID_PKIX + ".3.1": "id-kp-serverAuth",
    _ID_PKIX + ".3.2": "id-kp-clientAuth",
    _ID_PKIX + ".3.3": "id-kp-codeSigning",
    _ID_PKIX + ".3.4": "id-kp-emailProtection",
    _ID_PKIX + ".3.8": "id-kp-timeStamping",
    _ID_PKIX + ".3.9": "id-kp-OCSPSigning",
}
# RFC 5280 §4.2.2.1.
_ACCESS_METHODS = {
    _ID_PKIX + ".48.1": "id-ad-ocsp",
    _ID_PKIX + ".48.2": "id-ad-caIssuers",
    _ID_PKIX + ".48.3": "id-ad-timeStamping",
    _ID_PKIX + ".48.5": "id-ad-caRepository",
}
_ANY_POLICY = _ID_CE + ".32.0"
_ATTRIBUTE_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "2.5.4.97": "organizationIdentifier",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}
_INDENT = "  "
_MAX_LABEL_WIDTH = 40
_EXPIRY_WARNING = dt.timedelta(days=30)


class CertificateRow(NamedTuple):
    """One line of a certificate view: depth, label, value and a tone ('ok', 'warn', 'fail' or '')."""

    indent: int
    label: str
    value: str
    tone: str = ""


def certificate_rows(
    der: bytes,
    *,
    now: dt.datetime | None = None,
    include_der: bool = False,
) -> list[CertificateRow]:
    """Rows for one DER certificate; a value that is not a certificate yields a ``Decode error`` row."""
    raw = bytes(der or b"")
    try:
        cert, serial, parser_warnings = _load_certificate(raw)
    except (ValueError, x509.InvalidVersion) as error:
        rows = [CertificateRow(0, "Decode error", f"not an X.509 certificate ({error})", "fail")]
        if include_der and len(raw) > 0:
            rows.append(CertificateRow(0, "DER Hex", raw.hex().upper()))
        return rows
    moment = now or dt.datetime.now(dt.timezone.utc)
    status, tone = _validity(cert, moment)
    key_text, key_bytes = _public_key(cert)
    rows = [
        CertificateRow(0, "Version", str(cert.version.value + 1)),
        CertificateRow(0, "Subject", _format_name(cert.subject)),
        CertificateRow(0, "Issuer", _format_name(cert.issuer)),
        _serial_row(serial),
        CertificateRow(0, "Valid From", _format_time(cert.not_valid_before_utc)),
        CertificateRow(0, "Valid Until", f"{_format_time(cert.not_valid_after_utc)} ({status})", tone),
        CertificateRow(0, "Public Key", key_text),
        CertificateRow(0, "Signature Algorithm", _signature_algorithm(cert)),
    ]
    roles = certificate_role_oids(cert)
    if len(roles) > 0:
        rows.append(CertificateRow(0, "RSP Role", ", ".join(f"{_ROLE_NAMES[oid]} ({oid})" for oid in roles)))
    eid = _name_attribute(cert.subject, "2.5.4.5")
    if eid is not None and len(_EUICC_ROLES.intersection(roles)) > 0:
        rows.append(CertificateRow(0, "EID", eid))
    for message in parser_warnings:
        if "serial number" not in message:
            rows.append(CertificateRow(0, "Parser Warning", message, "warn"))
    rows.append(CertificateRow(0, "SHA-256 Fingerprint", hashlib.sha256(raw).hexdigest().upper()))
    rows.append(CertificateRow(0, "SHA-1 Fingerprint", hashlib.sha1(raw).hexdigest().upper()))
    rows.extend(_extension_rows(cert))
    rows.append(CertificateRow(0, "Public Key Bytes", key_bytes.hex().upper() or "-"))
    for index, line in enumerate(_signature_lines(cert)):
        rows.append(CertificateRow(0, "Signature Value" if index == 0 else "", line))
    if include_der:
        rows.append(CertificateRow(0, "DER Hex", raw.hex().upper()))
    return rows


def chain_rows(
    certificates: Sequence[tuple[str, bytes]],
    *,
    missing_issuer: str = "issuer not supplied",
) -> list[CertificateRow]:
    """Issuer linkage of named certificates: each one is verified against an issuer found among the others.

    The issuer is the certificate whose subject key identifier equals the authority key
    identifier, then the one whose subject equals the issuer name. A self-signed
    certificate is verified against itself; one whose issuer is absent names its
    authority key identifier so it can be matched against a CI PKID list.
    """
    parsed: list[tuple[str, x509.Certificate]] = []
    for name, der in certificates:
        try:
            parsed.append((name, _load_certificate(bytes(der or b""))[0]))
        except (ValueError, x509.InvalidVersion):
            continue
    parents: dict[int, int] = {}
    results: dict[int, tuple[str, str]] = {}
    for index, (_, cert) in enumerate(parsed):
        aki = _key_identifier(cert, x509.AuthorityKeyIdentifier)
        ski = _key_identifier(cert, x509.SubjectKeyIdentifier)
        if cert.subject == cert.issuer and (aki is None or ski is None or aki == ski):
            text, tone = _verify_signature(cert, cert)
            results[index] = (f"self-signed, {text}", tone)
            continue
        issuer_index = _find_issuer(index, parsed, aki)
        if issuer_index is None:
            note = missing_issuer if aki is None else f"{missing_issuer}, AKI {aki.hex().upper()}"
            results[index] = (note, "")
            continue
        parents[index] = issuer_index
        text, tone = _verify_signature(cert, parsed[issuer_index][1])
        if parsed[issuer_index][1].subject != cert.issuer:
            text += "; issuer name differs from that certificate's subject"
            tone = "warn" if tone == "ok" else tone
        results[index] = (text, tone)
    rows: list[CertificateRow] = []
    seen: set[int] = set()

    def walk(index: int, depth: int) -> None:
        if index in seen:
            return
        seen.add(index)
        connector = "" if depth == 0 else "`-- "
        text, tone = results[index]
        rows.append(CertificateRow(depth, f"{connector}{parsed[index][0]}", text, tone))
        for child in sorted(child for child, parent in parents.items() if parent == index):
            walk(child, depth + 1)

    for index in range(len(parsed)):
        if index not in parents:
            walk(index, 0)
    # A certificate caught in an issuer loop has no root above it; list it flat.
    for index in range(len(parsed)):
        walk(index, 0)
    return rows


def get_certs_rows(
    eum_der: bytes | None,
    euicc_der: bytes | None,
    *,
    now: dt.datetime | None = None,
    include_der: bool = False,
) -> list[CertificateRow]:
    """Rows for the two certificates of a GetCertsResponse (SGP.32 v1.3 §5.9.10) and their chain."""
    present = [
        (name, bytes(der))
        for name, der in (("EUM Certificate", eum_der), ("eUICC Certificate", euicc_der))
        if isinstance(der, (bytes, bytearray)) and len(der) > 0
    ]
    rows: list[CertificateRow] = []
    for name, der in present:
        rows.append(CertificateRow(0, name, _certificate_label(der)))
        rows.extend(row._replace(indent=row.indent + 1) for row in certificate_rows(der, now=now, include_der=include_der))
    links = chain_rows(present, missing_issuer="issuer not in the response")
    if len(links) > 0:
        rows.append(CertificateRow(0, "Chain", ""))
        rows.extend(row._replace(indent=row.indent + 1) for row in links)
    return rows


def tls_certificate_rows(
    certificates: Sequence[bytes],
    *,
    server_name: str = "",
    now: dt.datetime | None = None,
) -> list[CertificateRow]:
    """Rows for the certificate_list of a TLS Certificate message, sender first (RFC 5246 §7.4.2).

    Each certificate gets a heading with its subject and rows for its issuer, validity,
    subjectAltName, key and RSP role; the signatures of the chain follow
    (:func:`chain_rows`). With *server_name*, the name the client sent, the sender's
    certificate is held against it as RFC 2818 §3.1 prescribes. A certificate that does
    not parse becomes a ``fail`` heading.
    """
    moment = now or dt.datetime.now(dt.timezone.utc)
    rows: list[CertificateRow] = []
    parsed: list[tuple[str, bytes]] = []
    for index, der in enumerate(certificates):
        raw = bytes(der or b"")
        heading = f"certificate [{index}]"
        try:
            cert = _load_certificate(raw)[0]
        except (ValueError, x509.InvalidVersion) as error:
            rows.append(CertificateRow(0, heading, f"not an X.509 certificate ({error})", "fail"))
            continue
        parsed.append((f"[{index}]", raw))
        rows.append(CertificateRow(0, heading, _certificate_label(raw)))
        rows.extend(_tls_certificate_fields(cert, moment))
    if len(parsed) > 0:
        rows.append(CertificateRow(0, "chain", ""))
        links = chain_rows(parsed, missing_issuer="issuer not sent")
        rows.extend(row._replace(indent=row.indent + 1) for row in links)
    if len(server_name.strip()) > 0 and len(certificates) > 0:
        rows.append(_server_name_row(bytes(certificates[0] or b""), server_name))
    return rows


def finding_rows(rows: Sequence[CertificateRow]) -> list[CertificateRow]:
    """The ``warn`` and ``fail`` rows of a view, each named after the heading it sits under."""
    found: list[CertificateRow] = []
    heading = ""
    for row in rows:
        label = row.label.removeprefix("`-- ").strip()
        if row.indent == 0:
            heading = label
        if row.tone not in ("warn", "fail"):
            continue
        if row.indent > 0 and len(heading) > 0:
            label = f"{heading} {label}"
        found.append(CertificateRow(0, label, row.value, row.tone))
    return found


def _tls_certificate_fields(cert: x509.Certificate, now: dt.datetime) -> list[CertificateRow]:
    status, tone = _validity(cert, now)
    window = f"{_format_time(cert.not_valid_before_utc)} to {_format_time(cert.not_valid_after_utc)}"
    rows = [
        CertificateRow(1, "issuer", _name_attribute(cert.issuer, "2.5.4.3") or _format_name(cert.issuer)),
        CertificateRow(1, "valid", f"{window} ({status})", tone),
    ]
    names = _subject_alt_names(cert)
    if names is None:
        rows.append(CertificateRow(1, "subjectAltName", "does not decode", "warn"))
    elif len(names) > 0:
        rows.append(CertificateRow(1, "subjectAltName", ", ".join(_general_name(name) for name in names)))
    rows.append(CertificateRow(1, "public key", _public_key(cert)[0]))
    roles = certificate_role_oids(cert)
    if len(roles) > 0:
        rows.append(CertificateRow(1, "RSP role", ", ".join(_ROLE_NAMES[oid] for oid in roles)))
    return rows


def _subject_alt_names(cert: x509.Certificate) -> list[x509.GeneralName] | None:
    """The subjectAltName entries; empty without the extension, None when it does not decode."""
    try:
        return list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []
    except ValueError:
        return None


def _server_name_row(der: bytes, server_name: str) -> CertificateRow:
    """RFC 2818 §3.1: the dNSName entries are the identity when present, else the most specific CN.

    SGP.22 v3.1 §4.5.2.1.0.5 Table 14 has a CERT.DP.TLS carry the SM-DP+ host name as a
    dNSName, with the '*' that RFC 2818 allows.
    """
    host = server_name.strip().rstrip(".").lower()
    label = "server name"
    try:
        cert = _load_certificate(der)[0]
    except (ValueError, x509.InvalidVersion):
        return CertificateRow(0, label, f"{host} not checked: certificate [0] does not parse", "fail")
    names = _subject_alt_names(cert)
    if names is None:
        return CertificateRow(0, label, f"{host} not checked: subjectAltName does not decode", "warn")
    dns_names = [name.value for name in names if isinstance(name, x509.DNSName)]
    if len(dns_names) > 0:
        for pattern in dns_names:
            if _host_matches(pattern, host):
                return CertificateRow(0, label, f"{host} matches DNS:{pattern}", "ok")
        listed = ", ".join(f"DNS:{pattern}" for pattern in dns_names)
        return CertificateRow(0, label, f"{host} matches no dNSName ({listed})", "fail")
    common_names = [
        attribute.value
        for attribute in cert.subject
        if attribute.oid.dotted_string == "2.5.4.3" and isinstance(attribute.value, str)
    ]
    if len(common_names) == 0:
        return CertificateRow(0, label, f"{host}: certificate [0] has no dNSName and no CN", "fail")
    # The last CN in DER order is the most specific one.
    common_name = common_names[-1]
    if _host_matches(common_name, host):
        return CertificateRow(0, label, f"{host} matches CN={common_name} (no dNSName)", "ok")
    return CertificateRow(0, label, f"{host} does not match CN={common_name} (no dNSName)", "fail")


def _host_matches(pattern: str, host: str) -> bool:
    """RFC 2818 §3.1: '*' matches one domain name component or a fragment of one, case-insensitively."""
    pattern_labels = pattern.strip().rstrip(".").lower().split(".")
    host_labels = host.split(".")
    if len(pattern_labels) != len(host_labels):
        return False
    for pattern_label, host_label in zip(pattern_labels, host_labels):
        expression = "[^.]*".join(re.escape(part) for part in pattern_label.split("*"))
        if re.fullmatch(expression, host_label) is None:
            return False
    return True


def format_certificate_rows(
    rows: Sequence[CertificateRow],
    *,
    prefix: str = "    | ",
    min_label_width: int = 20,
    palette: Mapping[str, str] | None = None,
) -> list[str]:
    """Lay rows out as ``label: value`` lines under *prefix*, with every value in one column.

    *palette* maps ``value`` (the plain value colour), ``ok``, ``warn``, ``fail`` and
    ``end`` to escape sequences; without it the lines carry no colour. A row without a
    value is a heading, a row without a label continues the value above it.
    """
    colours = dict(palette or {})
    end = colours.get("end", "")
    # One column of padding past the longest label keeps a space before every colon.
    widths = [len(_INDENT * row.indent + row.label) + 1 for row in rows if len(row.value) > 0]
    width = min(max([min_label_width, *widths]), _MAX_LABEL_WIDTH)
    lines: list[str] = []
    for row in rows:
        label = _INDENT * row.indent + row.label
        if len(row.value) == 0:
            lines.append(f"{prefix}{label}")
            continue
        colour = colours.get(row.tone or "value", "")
        value = f"{colour}{row.value}{end}" if len(colour) > 0 else row.value
        if len(row.label) == 0:
            lines.append(f"{prefix}{' ' * width}  {value}")
        else:
            lines.append(f"{prefix}{label:<{width}}: {value}")
    return lines


def certificate_role_oids(cert: x509.Certificate) -> list[str]:
    """The id-rspRole OIDs (SGP.22 v3.1 §2.4a.1.0) among the certificate's policies."""
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except (x509.ExtensionNotFound, ValueError):
        return []
    return [
        policy.policy_identifier.dotted_string
        for policy in policies
        if policy.policy_identifier.dotted_string in _ROLE_NAMES
    ]


def _load_certificate(der: bytes) -> tuple[x509.Certificate, int, list[str]]:
    """Parse a DER certificate; return it, its serial number and cryptography's deprecation warnings.

    cryptography warns when the serial number is read, not when the certificate loads, so the
    serial is read here once. The warnings become rows in :func:`certificate_rows` (a
    non-positive serial number marks its own row), so the shell output carries them instead of
    stderr.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", CryptographyDeprecationWarning)
        cert = x509.load_der_x509_certificate(der)
        serial = cert.serial_number
    messages = [str(entry.message) for entry in caught if issubclass(entry.category, CryptographyDeprecationWarning)]
    return cert, serial, messages


def _certificate_label(der: bytes) -> str:
    try:
        cert = _load_certificate(der)[0]
    except (ValueError, x509.InvalidVersion):
        return f"{len(der)} bytes"
    common_name = _name_attribute(cert.subject, "2.5.4.3")
    if common_name is not None:
        return common_name
    serial_number = _name_attribute(cert.subject, "2.5.4.5")
    if serial_number is not None and len(_EUICC_ROLES.intersection(certificate_role_oids(cert))) > 0:
        return f"EID {serial_number}"
    return _format_name(cert.subject)


def _format_name(name: x509.Name, der_order: bool = False) -> str:
    rdns = list(name.rdns) if der_order else list(reversed(name.rdns))
    parts = []
    for rdn in rdns:
        attributes = []
        for attribute in rdn:
            key = _ATTRIBUTE_NAMES.get(attribute.oid.dotted_string, attribute.oid.dotted_string)
            value = attribute.value if isinstance(attribute.value, str) else bytes(attribute.value).hex().upper()
            attributes.append(f"{key}={value}")
        parts.append(" + ".join(attributes))
    return ", ".join(parts) if len(parts) > 0 else "(empty)"


def _name_attribute(name: x509.Name, dotted: str) -> str | None:
    for attribute in name:
        if attribute.oid.dotted_string == dotted and isinstance(attribute.value, str):
            return attribute.value
    return None


def _format_time(moment: dt.datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _span(delta: dt.timedelta) -> str:
    days = delta.days
    if days >= 365:
        years = days // 365
        return f"{years} year{'s' if years != 1 else ''}"
    if days >= 60:
        return f"{days // 30} months"
    if days >= 2:
        return f"{days} days"
    hours = int(delta.total_seconds() // 3600)
    return f"{hours} hours" if hours >= 2 else "under 2 hours"


def _validity(cert: x509.Certificate, now: dt.datetime) -> tuple[str, str]:
    start = cert.not_valid_before_utc
    end = cert.not_valid_after_utc
    if now < start:
        return f"not yet valid, starts in {_span(start - now)}", "fail"
    if now > end:
        return f"EXPIRED {_span(now - end)} ago", "fail"
    left = end - now
    return f"valid, {_span(left)} left", "ok" if left > _EXPIRY_WARNING else "warn"


def _serial_row(serial: int) -> CertificateRow:
    # RFC 5280 §4.1.2.2: the serial number MUST be a positive integer.
    if serial <= 0:
        return CertificateRow(0, "Serial Number", f"{_serial_hex(serial)} (not positive, RFC 5280 §4.1.2.2)", "warn")
    return CertificateRow(0, "Serial Number", _serial_hex(serial))


def _serial_hex(serial: int) -> str:
    digits = format(abs(serial), "X")
    digits = digits.zfill(len(digits) + len(digits) % 2)
    return ("-" if serial < 0 else "") + digits


def _signature_algorithm(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    if oid._name == "Unknown OID":
        return oid.dotted_string
    return f"{oid._name} ({oid.dotted_string})"


def _public_key(cert: x509.Certificate) -> tuple[str, bytes]:
    try:
        key = cert.public_key()
    except (UnsupportedAlgorithm, ValueError) as error:
        return f"{cert.public_key_algorithm_oid.dotted_string} (not decoded: {error})", b""
    if isinstance(key, ec.EllipticCurvePublicKey):
        point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return f"EC {key.curve.key_size} bits, {key.curve.name}", point
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return f"RSA {key.key_size} bits, e={numbers.e}", numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if isinstance(key, dsa.DSAPublicKey):
        y = key.public_numbers().y
        return f"DSA {key.key_size} bits", y.to_bytes((y.bit_length() + 7) // 8, "big")
    return type(key).__name__, b""


def _signature_lines(cert: x509.Certificate) -> list[str]:
    # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (RFC 5480 Appendix A).
    if cert.signature_algorithm_oid.dotted_string.startswith("1.2.840.10045.4."):
        try:
            r, s = decode_dss_signature(cert.signature)
        except ValueError:
            return [cert.signature.hex().upper()]
        size = (max(r.bit_length(), s.bit_length(), 1) + 7) // 8
        return [f"r {r.to_bytes(size, 'big').hex().upper()}", f"s {s.to_bytes(size, 'big').hex().upper()}"]
    return [cert.signature.hex().upper()]


def _key_identifier(cert: x509.Certificate, kind: type) -> bytes | None:
    try:
        value = cert.extensions.get_extension_for_class(kind).value
    except (x509.ExtensionNotFound, ValueError):
        return None
    if kind is x509.SubjectKeyIdentifier:
        return value.digest
    return value.key_identifier


def _find_issuer(
    index: int,
    parsed: Sequence[tuple[str, x509.Certificate]],
    aki: bytes | None,
) -> int | None:
    cert = parsed[index][1]
    by_key = [
        other
        for other, (_, candidate) in enumerate(parsed)
        if other != index and aki is not None and _key_identifier(candidate, x509.SubjectKeyIdentifier) == aki
    ]
    if len(by_key) > 0:
        return by_key[0]
    by_name = [other for other, (_, candidate) in enumerate(parsed) if other != index and candidate.subject == cert.issuer]
    return by_name[0] if len(by_name) > 0 else None


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> tuple[str, str]:
    try:
        key = issuer.public_key()
        tbs = cert.tbs_certificate_bytes
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, tbs, cert.signature_algorithm_parameters, cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, tbs, cert.signature_algorithm_parameters)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, tbs)
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature, tbs, cert.signature_hash_algorithm)
        else:
            return f"signature not checked ({type(key).__name__})", "warn"
    except InvalidSignature:
        return "signature INVALID", "fail"
    except (UnsupportedAlgorithm, ValueError, TypeError) as error:
        return f"signature not checked ({error})", "warn"
    return "signature valid", "ok"


def _extension_rows(cert: x509.Certificate) -> list[CertificateRow]:
    try:
        extensions = list(cert.extensions)
    except ValueError as error:
        return [CertificateRow(0, "Extensions", f"not decoded ({error})", "warn")]
    if len(extensions) == 0:
        return []
    rows = [CertificateRow(0, "Extensions", "")]
    for extension in extensions:
        oid = extension.oid.dotted_string
        lines = _extension_value_lines(oid, extension.value)
        if extension.critical:
            lines[0] = f"[critical] {lines[0]}"
        rows.append(CertificateRow(1, _EXTENSION_NAMES.get(oid, oid), lines[0]))
        rows.extend(CertificateRow(1, "", line) for line in lines[1:])
    return rows


def _extension_value_lines(oid: str, value: x509.ExtensionType) -> list[str]:
    """The decoded value of one extension, one entry per line; never empty."""
    lines: list[str]
    if isinstance(value, x509.SubjectKeyIdentifier):
        lines = [value.digest.hex().upper()]
    elif isinstance(value, x509.AuthorityKeyIdentifier):
        lines = [value.key_identifier.hex().upper()] if value.key_identifier is not None else []
        lines.extend(f"issuer {_general_name(name)}" for name in value.authority_cert_issuer or ())
        if value.authority_cert_serial_number is not None:
            lines.append(f"serial {_serial_hex(value.authority_cert_serial_number)}")
    elif isinstance(value, x509.BasicConstraints):
        if value.ca:
            limit = "no path length limit" if value.path_length is None else f"path length {value.path_length}"
            lines = [f"CA, {limit}"]
        else:
            lines = ["end entity"]
    elif isinstance(value, x509.KeyUsage):
        lines = [", ".join(_key_usage_names(value)) or "(none)"]
    elif isinstance(value, x509.ExtendedKeyUsage):
        lines = [_oid_label(usage.dotted_string, _EXTENDED_KEY_USAGES) for usage in value]
    elif isinstance(value, x509.CertificatePolicies):
        lines = _policy_lines(value)
    elif isinstance(value, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        lines = [_general_name(name) for name in value]
    elif isinstance(value, x509.NameConstraints):
        # A permitted subtree stays in DER order, top-down, so an EUM constraint leads with its O.
        lines = [f"permitted {_general_name(name, der_order=True)}" for name in value.permitted_subtrees or ()]
        lines.extend(f"excluded {_general_name(name, der_order=True)}" for name in value.excluded_subtrees or ())
    elif isinstance(value, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        lines = _distribution_point_lines(value)
    elif isinstance(value, x509.AuthorityInformationAccess):
        lines = [
            f"{_oid_label(entry.access_method.dotted_string, _ACCESS_METHODS)} {_general_name(entry.access_location)}"
            for entry in value
        ]
    elif isinstance(value, x509.PolicyConstraints):
        lines = [
            f"requireExplicitPolicy {value.require_explicit_policy}, "
            f"inhibitPolicyMapping {value.inhibit_policy_mapping}"
        ]
    elif isinstance(value, x509.InhibitAnyPolicy):
        lines = [f"skipCerts {value.skip_certs}"]
    elif oid == ID_RSP_EXTENSION_PERMITTED_EINS and isinstance(value, x509.UnrecognizedExtension):
        lines = [_permitted_eins_text(value.value)]
    elif isinstance(value, x509.UnrecognizedExtension):
        lines = [value.value.hex().upper()]
    else:
        lines = [str(value)]
    return lines if len(lines) > 0 else ["(empty)"]


def _key_usage_names(value: x509.KeyUsage) -> list[str]:
    names = [name for attribute, name in _KEY_USAGE_BITS if getattr(value, attribute)]
    # encipherOnly and decipherOnly carry meaning only with keyAgreement set; cryptography raises
    # when they are read without it.
    if value.key_agreement:
        if value.encipher_only:
            names.append("encipherOnly")
        if value.decipher_only:
            names.append("decipherOnly")
    return names


def _policy_lines(value: x509.CertificatePolicies) -> list[str]:
    lines = []
    for policy in value:
        dotted = policy.policy_identifier.dotted_string
        name = _ROLE_NAMES.get(dotted) or ("anyPolicy" if dotted == _ANY_POLICY else None)
        lines.append(f"{name} ({dotted})" if name is not None else dotted)
        for qualifier in policy.policy_qualifiers or ():
            if isinstance(qualifier, str):
                lines.append(f"  CPS {qualifier}")
            elif qualifier.explicit_text:
                lines.append(f"  userNotice {qualifier.explicit_text}")
    return lines


def _distribution_point_lines(value: x509.CRLDistributionPoints | x509.FreshestCRL) -> list[str]:
    lines = []
    for point in value:
        lines.extend(_general_name(name) for name in point.full_name or ())
        if point.relative_name is not None:
            lines.append(f"nameRelativeToCRLIssuer {point.relative_name.rfc4514_string()}")
        if point.reasons:
            lines.append("reasons " + ", ".join(sorted(reason.value for reason in point.reasons)))
        lines.extend(f"cRLIssuer {_general_name(name)}" for name in point.crl_issuer or ())
    return lines


def _general_name(name: x509.GeneralName, der_order: bool = False) -> str:
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName:{_format_name(name.value, der_order)}"
    if isinstance(name, x509.RegisteredID):
        return f"RID:{_oid_label(name.value.dotted_string, _ROLE_NAMES)}"
    if isinstance(name, x509.OtherName):
        return f"otherName:{name.type_id.dotted_string}:{name.value.hex().upper()}"
    return str(name)


def _oid_label(dotted: str, names: Mapping[str, str]) -> str:
    name = names.get(dotted)
    return f"{name} ({dotted})" if name is not None else dotted


def _permitted_eins_text(extn_value: bytes) -> str:
    try:
        eins = _permitted_eins(extn_value)
    except (ValueError, TypeError):
        return f"not decoded: {extn_value.hex().upper()}"
    return ", ".join(eins) if len(eins) > 0 else "(none)"


def _permitted_eins(extn_value: bytes) -> list[str]:
    tag, sequence, _ = read_single_ber_tlv(extn_value)
    if tag != b"\x30":
        raise ValueError("PermittedEins is not a SEQUENCE")
    eins = []
    offset = 0
    while offset < len(sequence):
        item_tag, item, _, offset = read_ber_tlv(sequence, offset)
        if item_tag != b"\x13":
            raise ValueError("PermittedEins entry is not a PrintableString")
        eins.append(item.decode("ascii"))
    return eins
