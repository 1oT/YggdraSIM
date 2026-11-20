# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Operator store of the AddInitialEim builder: certificates and the values typed into it.

Certificates live one per file as ``<name>.pem`` under
``~/.yggdrasim/eim_builder/certificates/``; the values typed into the builder
(eimId, eimFqdn, euiccCiPKId and the certificate names last used) live in
``values.json`` beside that directory, newest first and bounded per field.
``YGGDRASIM_EIM_BUILDER_STORE`` names another directory. The store lives
outside every checkout and is never tracked. It holds certificates only: a
private key block in an imported file is counted and dropped.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

STORE_DIR_ENV = "YGGDRASIM_EIM_BUILDER_STORE"
STORE_DIR_NAME = "eim_builder"
CERTIFICATE_DIR_NAME = "certificates"
CERTIFICATE_SUFFIX = ".pem"
VALUES_FILE_NAME = "values.json"
VALUES_SCHEMA = "ygg.eim_builder_values.v1"
CONFIGURATIONS_FILE_NAME = "configurations.json"
CONFIGURATIONS_SCHEMA = "ygg.eim_builder_configurations.v1"
# The whole form of the last build or send, which the forms and the wizard
# start from; values.json keeps the typed values alone.
LAST_CONFIGURATION_FILE_NAME = "last_configuration.json"
LAST_CONFIGURATION_SCHEMA = "ygg.eim_builder_last_configuration.v1"
MAX_CONFIGURATIONS = 64
MAX_CONFIGURATIONS_FILE_BYTES = 512 * 1024
MAX_CONFIGURATION_KEYS = 32
MAX_CONFIGURATION_LIST = 16
# Saved-value fields and configuration keys that name a stored certificate.
CERTIFICATE_REFERENCE_FIELDS: tuple[str, ...] = ("eim_certificate", "tls_certificate")
VALUE_FIELDS: tuple[str, ...] = (
    "eim_id",
    "eim_fqdn",
    "euicc_ci_pk_id",
    "eim_certificate",
    "tls_certificate",
)
MAX_VALUES_PER_FIELD = 16
MAX_VALUE_LENGTH = 255
MAX_SOURCE_BYTES = 1024 * 1024
MAX_VALUES_FILE_BYTES = 256 * 1024
MAX_CERTIFICATES_PER_IMPORT = 16

_USER_DIR_NAME = ".yggdrasim"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NAME_INVALID_RUN = re.compile(r"[^A-Za-z0-9._-]+")
_PEM_BLOCK_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)
_HEX_TEXT_RE = re.compile(rb"^[0-9A-Fa-f\s:]+$")
# Base64 without PEM armor, standard or URL-safe alphabet (RFC 4648 §4, §5).
_BASE64_TEXT_RE = re.compile(rb"^[A-Za-z0-9+/\-_\s]+={0,2}\s*$")


class EimBuilderStoreError(ValueError):
    """A store request the operator can correct: a name, a missing entry, an unreadable source."""


def store_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Return the store directory: the env override, else ``~/.yggdrasim/eim_builder``."""
    env = os.environ if environ is None else environ
    override = str(env.get(STORE_DIR_ENV, "") or "").strip()
    if override:
        return Path(os.path.expanduser(override))
    return Path(os.path.expanduser("~")) / _USER_DIR_NAME / STORE_DIR_NAME


def certificates_dir(directory: Path | None = None) -> Path:
    base = store_dir() if directory is None else Path(directory)
    return base / CERTIFICATE_DIR_NAME


def values_path(directory: Path | None = None) -> Path:
    base = store_dir() if directory is None else Path(directory)
    return base / VALUES_FILE_NAME


def normalise_name(name: Any, kind: str = "certificate") -> str:
    """Return a valid store name or raise; a typed ``.pem`` suffix is dropped."""
    text = str(name or "").strip()
    if text.casefold().endswith(CERTIFICATE_SUFFIX):
        text = text[: -len(CERTIFICATE_SUFFIX)]
    if not text:
        raise EimBuilderStoreError(f"A {kind} name is required.")
    if _NAME_RE.match(text) is None:
        raise EimBuilderStoreError(
            f"{kind.capitalize()} name {text!r} must be letters, digits, '.', '_' or '-' "
            "(64 characters at most) and start with a letter or digit."
        )
    return text


def name_from_subject(common_name: str) -> str:
    """Derive a store name from a subject common name: ``TEST SM eIM - CERT.EIM`` -> ``TEST-SM-eIM-CERT.EIM``."""
    text = _NAME_INVALID_RUN.sub("-", str(common_name or "").strip())
    text = re.sub(r"-{2,}", "-", text).strip("-._")
    text = text[:64].rstrip("-._")
    if not text or _NAME_RE.match(text) is None:
        return "certificate"
    return text


@dataclass(frozen=True)
class StoredCertificate:
    """One certificate of the store, with the fields the builder shows."""

    name: str
    der: bytes
    subject: str
    subject_cn: str
    issuer: str
    serial_hex: str
    not_before: str
    not_after: str
    key: str
    ski_hex: str
    aki_hex: str
    is_ca: bool
    sha256_hex: str
    spki_der: bytes
    san_registered_ids: tuple[str, ...] = ()

    def summary(self) -> str:
        role = "CA" if self.is_ca else "end entity"
        return f"{self.subject_cn or self.subject} ({self.key}, {role}, until {self.not_after[:10]})"


@dataclass(frozen=True)
class ImportReport:
    """What an import stored, and what it left out."""

    stored: tuple[StoredCertificate, ...]
    private_keys_dropped: int = 0
    same_as: dict[str, str] = field(default_factory=dict)


def _subject_public_key_info(der: bytes) -> bytes:
    """Return the subjectPublicKeyInfo of a Certificate exactly as it is encoded.

    X.509 TBSCertificate: [0] version (optional), serialNumber, signature,
    issuer, validity, subject, subjectPublicKeyInfo.
    """
    _tag, certificate, _raw = read_single_ber_tlv(der)
    tbs_tag, tbs, _tbs_raw, _next = read_ber_tlv(certificate, 0)
    if tbs_tag != b"\x30":
        raise ValueError("The certificate does not start with a TBSCertificate SEQUENCE.")
    offset = 0
    index = 0
    while offset < len(tbs):
        tag, _value, raw, offset = read_ber_tlv(tbs, offset)
        if index == 0 and tag == b"\xA0":
            continue
        if index == 5:
            if tag != b"\x30":
                break
            return raw
        index += 1
    raise ValueError("The certificate carries no subjectPublicKeyInfo where X.509 places it.")


def _time_text(certificate: Any, attribute: str) -> str:
    value = getattr(certificate, f"{attribute}_utc", None)
    if value is None:
        value = getattr(certificate, attribute)
    return value.strftime("%Y-%m-%d %H:%M:%SZ")


def describe_certificate(der: bytes, name: str = "") -> StoredCertificate:
    """Parse one DER certificate into the fields the store lists."""
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    raw = bytes(der or b"")
    try:
        certificate = x509.load_der_x509_certificate(raw)
    except ValueError as error:
        raise EimBuilderStoreError(f"Not an X.509 certificate: {error}") from error
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject_cn = str(common_names[0].value) if common_names else ""
    # The request carries the subjectPublicKeyInfo verbatim, so a curve this
    # build cannot load (brainpool on some OpenSSL builds) only loses the label.
    try:
        public_key = certificate.public_key()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        key_text = "unsupported key"
    else:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            key_text = f"EC {public_key.curve.name}"
        elif isinstance(public_key, rsa.RSAPublicKey):
            key_text = f"RSA {public_key.key_size}"
        else:
            key_text = type(public_key).__name__
    ski_hex = ""
    aki_hex = ""
    is_ca = False
    try:
        ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        ski_hex = ski.value.digest.hex().upper()
    except x509.ExtensionNotFound:
        pass
    try:
        aki = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        if aki.value.key_identifier is not None:
            aki_hex = aki.value.key_identifier.hex().upper()
    except x509.ExtensionNotFound:
        pass
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(constraints.value.ca)
    except x509.ExtensionNotFound:
        pass
    registered_ids: tuple[str, ...] = ()
    try:
        alt_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        registered_ids = tuple(oid.dotted_string for oid in alt_names.value.get_values_for_type(x509.RegisteredID))
    except x509.ExtensionNotFound:
        pass
    try:
        spki = _subject_public_key_info(raw)
    except ValueError as error:
        raise EimBuilderStoreError(f"The certificate's subjectPublicKeyInfo could not be read: {error}") from error
    return StoredCertificate(
        name=name,
        der=raw,
        subject=certificate.subject.rfc4514_string(),
        subject_cn=subject_cn,
        issuer=certificate.issuer.rfc4514_string(),
        serial_hex=format(certificate.serial_number, "X"),
        not_before=_time_text(certificate, "not_valid_before"),
        not_after=_time_text(certificate, "not_valid_after"),
        key=key_text,
        ski_hex=ski_hex,
        aki_hex=aki_hex,
        is_ca=is_ca,
        sha256_hex=hashlib.sha256(raw).hexdigest().upper(),
        spki_der=spki,
        san_registered_ids=registered_ids,
    )


def certificates_from_source(raw: bytes) -> tuple[list[bytes], int]:
    """Return the DER certificates in a PEM, DER, hex or base64 source, and the private key blocks seen.

    PEM may hold several CERTIFICATE blocks; a private key block is counted
    and never returned. Hex is tried before base64: the base64 of a DER
    SEQUENCE starts with 'M', which is not a hex digit.
    """
    data = bytes(raw or b"")
    if len(data) == 0:
        raise EimBuilderStoreError("The certificate source is empty.")
    if len(data) > MAX_SOURCE_BYTES:
        raise EimBuilderStoreError(f"The certificate source is {len(data)} bytes; at most {MAX_SOURCE_BYTES}.")
    if b"-----BEGIN" in data:
        certificates: list[bytes] = []
        private_keys = 0
        for match in _PEM_BLOCK_RE.finditer(data):
            label = match.group(1).decode("ascii")
            if "PRIVATE KEY" in label:
                private_keys += 1
                continue
            if label != "CERTIFICATE":
                continue
            body = b"".join(match.group(2).split())
            try:
                certificates.append(binascii.a2b_base64(body))
            except binascii.Error as error:
                raise EimBuilderStoreError(f"A CERTIFICATE block is not valid base64: {error}") from error
        if not certificates:
            raise EimBuilderStoreError("The PEM source holds no CERTIFICATE block.")
        return certificates, private_keys
    stripped = data.strip()
    if _HEX_TEXT_RE.match(stripped) is not None:
        compact = re.sub(rb"[\s:]", b"", stripped)
        try:
            data = binascii.unhexlify(compact)
        except binascii.Error as error:
            raise EimBuilderStoreError(f"The hex certificate source is not valid hex: {error}") from error
    elif _BASE64_TEXT_RE.match(stripped) is not None:
        compact = re.sub(rb"\s", b"", stripped).replace(b"-", b"+").replace(b"_", b"/")
        compact += b"=" * (-len(compact) % 4)
        try:
            data = base64.b64decode(compact, validate=True)
        except binascii.Error as error:
            raise EimBuilderStoreError(f"The base64 certificate source is not valid base64: {error}") from error
    # DER certificates may follow one another (a chain saved as one blob).
    certificates = []
    offset = 0
    while offset < len(data):
        try:
            tag, _value, raw_tlv, next_offset = read_ber_tlv(data, offset)
        except ValueError as error:
            if not certificates:
                raise EimBuilderStoreError(f"The source is neither PEM nor DER: {error}") from error
            raise EimBuilderStoreError(
                f"The source holds {len(certificates)} DER object(s) in its first {offset} bytes, then "
                f"{len(data) - offset} bytes that do not form another ({error})."
            ) from error
        if tag != b"\x30":
            raise EimBuilderStoreError(
                f"The DER object at byte {offset} has tag {tag.hex().upper()}, not a certificate SEQUENCE."
            )
        certificates.append(raw_tlv)
        offset = next_offset
    return certificates, 0


def _read_entry_file(path: Path) -> bytes:
    from yggdrasim_common.secure_files import read_bounded_regular_file

    try:
        raw = read_bounded_regular_file(path, MAX_SOURCE_BYTES)
    except (OSError, ValueError) as error:
        raise EimBuilderStoreError(f"{path.name} could not be read: {error}") from error
    certificates, _private_keys = certificates_from_source(raw)
    if len(certificates) != 1:
        raise EimBuilderStoreError(f"{path.name} holds {len(certificates)} certificates; the store keeps one per file.")
    return certificates[0]


def list_certificates(directory: Path | None = None) -> tuple[list[StoredCertificate], list[str]]:
    """Return the stored certificates by name, and a line for each file that did not read."""
    base = certificates_dir(directory)
    if base.is_dir() is False:
        return [], []
    entries: list[StoredCertificate] = []
    problems: list[str] = []
    for path in sorted(base.glob("*" + CERTIFICATE_SUFFIX), key=lambda item: item.name.casefold()):
        name = path.name[: -len(CERTIFICATE_SUFFIX)]
        if _NAME_RE.match(name) is None:
            problems.append(f"{path.name}: not a valid store name; skipped.")
            continue
        try:
            entries.append(describe_certificate(_read_entry_file(path), name))
        except EimBuilderStoreError as error:
            problems.append(f"{path.name}: {error}")
    return entries, problems


def read_certificate(name: Any, directory: Path | None = None) -> StoredCertificate:
    entry_name = normalise_name(name)
    path = certificates_dir(directory) / (entry_name + CERTIFICATE_SUFFIX)
    if path.is_file() is False:
        raise EimBuilderStoreError(f"No stored certificate named {entry_name!r}.")
    return describe_certificate(_read_entry_file(path), entry_name)


def import_certificates(
    raw: bytes,
    *,
    name: Any = "",
    overwrite: bool = False,
    directory: Path | None = None,
) -> ImportReport:
    """Store every certificate of a PEM, DER, hex or base64 source.

    The first certificate takes ``name`` (or a name derived from its subject
    CN); further ones take ``<name>-2``, ``<name>-3``, ... An existing name is
    refused unless ``overwrite``. Nothing is written before every certificate
    in the source has parsed.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from yggdrasim_common.secure_files import atomic_write_bytes, ensure_private_directory

    certificates, private_keys = certificates_from_source(raw)
    if len(certificates) > MAX_CERTIFICATES_PER_IMPORT:
        raise EimBuilderStoreError(
            f"The source holds {len(certificates)} certificates; one import stores at most "
            f"{MAX_CERTIFICATES_PER_IMPORT}."
        )
    described = [describe_certificate(der) for der in certificates]
    requested = str(name or "").strip()
    base_name = normalise_name(requested) if requested else ""
    existing, _problems = list_certificates(directory)
    by_digest = {entry.sha256_hex: entry.name for entry in existing}
    names: list[str] = []
    for index, entry in enumerate(described):
        stem = base_name or name_from_subject(entry.subject_cn)
        candidate = stem
        if base_name and index > 0:
            candidate = f"{stem[:60]}-{index + 1}"
        suffix = 2
        while candidate in names:
            candidate = f"{stem[:60]}-{suffix}"
            suffix += 1
        names.append(normalise_name(candidate))
    target_dir = certificates_dir(directory)
    if overwrite is False:
        taken = [entry_name for entry_name in names if (target_dir / (entry_name + CERTIFICATE_SUFFIX)).exists()]
        if taken:
            raise EimBuilderStoreError(
                "A stored certificate already uses the name(s) " + ", ".join(taken) + "; choose another name or overwrite."
            )
    ensure_private_directory(target_dir.parent)
    ensure_private_directory(target_dir)
    stored: list[StoredCertificate] = []
    same_as: dict[str, str] = {}
    for entry_name, entry in zip(names, described):
        pem = x509.load_der_x509_certificate(entry.der).public_bytes(serialization.Encoding.PEM)
        atomic_write_bytes(target_dir / (entry_name + CERTIFICATE_SUFFIX), pem, overwrite=overwrite)
        previous = by_digest.get(entry.sha256_hex)
        if previous is not None and previous != entry_name:
            same_as[entry_name] = previous
        stored.append(describe_certificate(entry.der, entry_name))
    return ImportReport(stored=tuple(stored), private_keys_dropped=private_keys, same_as=same_as)


def remove_certificate(name: Any, directory: Path | None = None) -> str:
    """Delete one certificate and drop its name from the saved values; configurations keep it."""
    entry_name = normalise_name(name)
    path = certificates_dir(directory) / (entry_name + CERTIFICATE_SUFFIX)
    if path.is_file() is False:
        raise EimBuilderStoreError(f"No stored certificate named {entry_name!r}.")
    lists, last = _load_document(directory)
    path.unlink()
    if _rename_in_values(lists, last, entry_name, ""):
        _write_document(lists, last, directory)
    return entry_name


def rename_certificate(old: Any, new: Any, directory: Path | None = None) -> tuple[str, list[str]]:
    """Rename one certificate; saved values and configurations follow. Returns the configurations updated."""
    old_name = normalise_name(old)
    new_name = normalise_name(new)
    base = certificates_dir(directory)
    source = base / (old_name + CERTIFICATE_SUFFIX)
    target = base / (new_name + CERTIFICATE_SUFFIX)
    if source.is_file() is False:
        raise EimBuilderStoreError(f"No stored certificate named {old_name!r}.")
    if old_name == new_name:
        return new_name, []
    if target.exists():
        raise EimBuilderStoreError(f"A stored certificate already uses the name {new_name!r}.")
    # Every file is read first, so an unreadable one stops the rename before anything moves.
    lists, last = _load_document(directory)
    configurations = load_configurations(directory)
    last_configuration = load_last_configuration(directory)
    source.rename(target)
    if _rename_in_values(lists, last, old_name, new_name):
        _write_document(lists, last, directory)
    if any(last_configuration.get(member) == old_name for member in CERTIFICATE_REFERENCE_FIELDS):
        for member in CERTIFICATE_REFERENCE_FIELDS:
            if last_configuration.get(member) == old_name:
                last_configuration[member] = new_name
        remember_last_configuration(last_configuration, directory)
    updated = [
        name
        for name, values in configurations.items()
        if any(values.get(member) == old_name for member in CERTIFICATE_REFERENCE_FIELDS)
    ]
    for name in updated:
        for member in CERTIFICATE_REFERENCE_FIELDS:
            if configurations[name].get(member) == old_name:
                configurations[name][member] = new_name
    if updated:
        _write_configurations(configurations, directory)
    return new_name, updated


def configurations_using_certificate(name: Any, directory: Path | None = None) -> list[str]:
    entry_name = normalise_name(name)
    return [
        configuration
        for configuration, values in load_configurations(directory).items()
        if any(values.get(member) == entry_name for member in CERTIFICATE_REFERENCE_FIELDS)
    ]


def _rename_in_values(lists: dict[str, list[str]], last: dict[str, str], old: str, new: str) -> bool:
    """Replace (or with ``new`` empty, drop) a certificate name in the saved values; True when anything changed."""
    changed = False
    for field_name in CERTIFICATE_REFERENCE_FIELDS:
        items: list[str] = []
        for item in lists.get(field_name, []):
            replacement = new if item == old else item
            if replacement and replacement not in items:
                items.append(replacement)
        if items != lists.get(field_name, []):
            lists[field_name] = items
            changed = True
        if last.get(field_name) == old:
            last[field_name] = new
            changed = True
    return changed


def _clean_value(field_name: str, value: Any) -> str:
    if field_name not in VALUE_FIELDS:
        raise EimBuilderStoreError(f"Unknown saved-value field {field_name!r}; expected one of: {', '.join(VALUE_FIELDS)}.")
    text = str(value if value is not None else "").strip()
    if len(text) > MAX_VALUE_LENGTH:
        raise EimBuilderStoreError(f"{field_name} value is {len(text)} characters; at most {MAX_VALUE_LENGTH}.")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise EimBuilderStoreError(f"{field_name} value carries a control character.")
    return text


def _load_document(directory: Path | None) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Return the per-field lists and the last build's values; a missing file is an empty store."""
    from yggdrasim_common.secure_files import read_bounded_regular_file

    path = values_path(directory)
    lists: dict[str, list[str]] = {name: [] for name in VALUE_FIELDS}
    last: dict[str, str] = {}
    if path.exists() is False:
        return lists, last
    try:
        raw = read_bounded_regular_file(path, MAX_VALUES_FILE_BYTES)
    except (OSError, ValueError) as error:
        raise EimBuilderStoreError(f"{path.name} could not be read: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EimBuilderStoreError(f"{path} is not readable JSON: {error}") from error
    if isinstance(document, dict) is False or document.get("schema") != VALUES_SCHEMA:
        raise EimBuilderStoreError(f"{path} is not a {VALUES_SCHEMA} document.")
    stored = document.get("values")
    if isinstance(stored, dict) is False:
        raise EimBuilderStoreError(f"{path} carries no values object.")
    for field_name in VALUE_FIELDS:
        items = stored.get(field_name, [])
        if isinstance(items, list) is False:
            raise EimBuilderStoreError(f"{path}: {field_name} is not a list.")
        cleaned: list[str] = []
        for item in items:
            if isinstance(item, str) is False:
                raise EimBuilderStoreError(f"{path}: {field_name} holds a non-text value.")
            text = _clean_value(field_name, item)
            if text and text not in cleaned:
                cleaned.append(text)
        lists[field_name] = cleaned[:MAX_VALUES_PER_FIELD]
    stored_last = document.get("last", {})
    if isinstance(stored_last, dict) is False:
        raise EimBuilderStoreError(f"{path}: last is not an object.")
    for field_name in VALUE_FIELDS:
        item = stored_last.get(field_name)
        if item is None:
            continue
        if isinstance(item, str) is False:
            raise EimBuilderStoreError(f"{path}: last.{field_name} is not text.")
        last[field_name] = _clean_value(field_name, item)
    return lists, last


def load_values(directory: Path | None = None) -> dict[str, list[str]]:
    """Return the saved values per field, newest first."""
    lists, _last = _load_document(directory)
    return lists


def load_last_build(directory: Path | None = None) -> dict[str, str]:
    """Return the values of the last build per field; an empty string marks a member left out."""
    _lists, last = _load_document(directory)
    return last


def _write_document(lists: Mapping[str, list[str]], last: Mapping[str, str], directory: Path | None) -> None:
    from yggdrasim_common.secure_files import atomic_write_bytes, ensure_private_directory

    path = values_path(directory)
    ensure_private_directory(path.parent)
    document = {
        "schema": VALUES_SCHEMA,
        "values": {name: list(lists.get(name, []))[:MAX_VALUES_PER_FIELD] for name in VALUE_FIELDS},
        "last": {name: str(last[name]) for name in VALUE_FIELDS if name in last},
    }
    payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload, overwrite=True)


def remember_values(values: Mapping[str, Any], directory: Path | None = None) -> dict[str, list[str]]:
    """Record one build: each non-empty value goes first in its list, and ``values`` becomes the last build.

    Returns the new lists. An unreadable ``values.json`` is reported, never overwritten.
    """
    lists, last = _load_document(directory)
    new_last = dict(last)
    for field_name, value in values.items():
        text = _clean_value(field_name, value)
        new_last[field_name] = text
        if not text:
            continue
        items = [item for item in lists[field_name] if item != text]
        items.insert(0, text)
        lists[field_name] = items[:MAX_VALUES_PER_FIELD]
    _write_document(lists, new_last, directory)
    return lists


def forget_value(field_name: str, value: Any, directory: Path | None = None) -> bool:
    """Drop one saved value, from its list and from the last build; False when it was not saved."""
    text = _clean_value(field_name, value)
    lists, last = _load_document(directory)
    if text not in lists[field_name] and last.get(field_name) != text:
        return False
    lists[field_name] = [item for item in lists[field_name] if item != text]
    if last.get(field_name) == text:
        last[field_name] = ""
    _write_document(lists, last, directory)
    return True


def edit_value(field_name: str, old: Any, new: Any, directory: Path | None = None) -> bool:
    """Replace one saved value in place, in its list and in the last build; False when it was not saved."""
    old_text = _clean_value(field_name, old)
    new_text = _clean_value(field_name, new)
    if not new_text:
        raise EimBuilderStoreError("A new value is required; forget removes a value.")
    lists, last = _load_document(directory)
    if old_text not in lists[field_name] and last.get(field_name) != old_text:
        return False
    items: list[str] = []
    for item in lists[field_name]:
        replacement = new_text if item == old_text else item
        if replacement not in items:
            items.append(replacement)
    lists[field_name] = items
    if last.get(field_name) == old_text:
        last[field_name] = new_text
    _write_document(lists, last, directory)
    return True


def configurations_path(directory: Path | None = None) -> Path:
    base = store_dir() if directory is None else Path(directory)
    return base / CONFIGURATIONS_FILE_NAME


def _clean_configuration(values: Any) -> dict[str, Any]:
    """Keep the JSON scalars and short text lists a configuration is made of; refuse anything else."""
    if isinstance(values, Mapping) is False:
        raise EimBuilderStoreError("A configuration is an object of named values.")
    if len(values) > MAX_CONFIGURATION_KEYS:
        raise EimBuilderStoreError(f"A configuration holds at most {MAX_CONFIGURATION_KEYS} values.")
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if isinstance(key, str) is False or _NAME_RE.match(key) is None:
            raise EimBuilderStoreError(f"Configuration key {key!r} is not a plain name.")
        if value is None or isinstance(value, (bool, int)):
            cleaned[key] = value
        elif isinstance(value, str):
            if len(value) > MAX_VALUE_LENGTH or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
                raise EimBuilderStoreError(f"Configuration value {key} is too long or carries a control character.")
            cleaned[key] = value
        elif isinstance(value, (list, tuple)):
            items = list(value)
            if len(items) > MAX_CONFIGURATION_LIST or not all(
                isinstance(item, str) and _NAME_RE.match(item) for item in items
            ):
                raise EimBuilderStoreError(f"Configuration value {key} is not a short list of names.")
            cleaned[key] = items
        else:
            raise EimBuilderStoreError(f"Configuration value {key} has an unsupported type.")
    return cleaned


def load_configurations(directory: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return the saved configurations by name; a missing file is none."""
    from yggdrasim_common.secure_files import read_bounded_regular_file

    path = configurations_path(directory)
    if path.exists() is False:
        return {}
    try:
        raw = read_bounded_regular_file(path, MAX_CONFIGURATIONS_FILE_BYTES)
    except (OSError, ValueError) as error:
        raise EimBuilderStoreError(f"{path.name} could not be read: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EimBuilderStoreError(f"{path} is not readable JSON: {error}") from error
    if isinstance(document, dict) is False or document.get("schema") != CONFIGURATIONS_SCHEMA:
        raise EimBuilderStoreError(f"{path} is not a {CONFIGURATIONS_SCHEMA} document.")
    stored = document.get("configurations")
    if isinstance(stored, dict) is False:
        raise EimBuilderStoreError(f"{path} carries no configurations object.")
    if len(stored) > MAX_CONFIGURATIONS:
        raise EimBuilderStoreError(f"{path} holds more than {MAX_CONFIGURATIONS} configurations.")
    return {normalise_name(name, "configuration"): _clean_configuration(values) for name, values in stored.items()}


def _write_configurations(configurations: Mapping[str, Mapping[str, Any]], directory: Path | None) -> None:
    from yggdrasim_common.secure_files import atomic_write_bytes, ensure_private_directory

    path = configurations_path(directory)
    ensure_private_directory(path.parent)
    document = {
        "schema": CONFIGURATIONS_SCHEMA,
        "configurations": {name: dict(values) for name, values in sorted(configurations.items())},
    }
    payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload, overwrite=True)


def last_configuration_path(directory: Path | None = None) -> Path:
    base = store_dir() if directory is None else Path(directory)
    return base / LAST_CONFIGURATION_FILE_NAME


def load_last_configuration(directory: Path | None = None) -> dict[str, Any]:
    """The whole form of the last build or send, in the configuration form; a missing file is none."""
    from yggdrasim_common.secure_files import read_bounded_regular_file

    path = last_configuration_path(directory)
    if path.exists() is False:
        return {}
    try:
        raw = read_bounded_regular_file(path, MAX_CONFIGURATIONS_FILE_BYTES)
    except (OSError, ValueError) as error:
        raise EimBuilderStoreError(f"{path.name} could not be read: {error}") from error
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EimBuilderStoreError(f"{path} is not readable JSON: {error}") from error
    if isinstance(document, dict) is False or document.get("schema") != LAST_CONFIGURATION_SCHEMA:
        raise EimBuilderStoreError(f"{path} is not a {LAST_CONFIGURATION_SCHEMA} document.")
    return _clean_configuration(document.get("configuration", {}))


def remember_last_configuration(values: Mapping[str, Any], directory: Path | None = None) -> None:
    """Record the whole form of one build or send, replacing the previous one."""
    from yggdrasim_common.secure_files import atomic_write_bytes, ensure_private_directory

    path = last_configuration_path(directory)
    ensure_private_directory(path.parent)
    document = {"schema": LAST_CONFIGURATION_SCHEMA, "configuration": _clean_configuration(values)}
    payload = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload, overwrite=True)


def save_configuration(name: Any, values: Mapping[str, Any], directory: Path | None = None) -> str:
    """Store ``values`` under ``name``, replacing a configuration of that name."""
    entry_name = normalise_name(name, "configuration")
    configurations = load_configurations(directory)
    if entry_name not in configurations and len(configurations) >= MAX_CONFIGURATIONS:
        raise EimBuilderStoreError(f"The store holds {MAX_CONFIGURATIONS} configurations; delete one first.")
    configurations[entry_name] = _clean_configuration(values)
    _write_configurations(configurations, directory)
    return entry_name


def rename_configuration(old: Any, new: Any, directory: Path | None = None) -> str:
    old_name = normalise_name(old, "configuration")
    new_name = normalise_name(new, "configuration")
    configurations = load_configurations(directory)
    if old_name not in configurations:
        raise EimBuilderStoreError(f"No configuration named {old_name!r}.")
    if new_name != old_name and new_name in configurations:
        raise EimBuilderStoreError(f"A configuration named {new_name!r} already exists.")
    configurations[new_name] = configurations.pop(old_name)
    _write_configurations(configurations, directory)
    return new_name


def delete_configuration(name: Any, directory: Path | None = None) -> str:
    entry_name = normalise_name(name, "configuration")
    configurations = load_configurations(directory)
    if entry_name not in configurations:
        raise EimBuilderStoreError(f"No configuration named {entry_name!r}.")
    del configurations[entry_name]
    _write_configurations(configurations, directory)
    return entry_name
