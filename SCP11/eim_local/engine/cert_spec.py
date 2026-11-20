# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A certificate's subject and extensions as text: read, written and decoded without loss.

A TLS leaf of the Local eIM can be given its subject and its extension set
literally. The text has one ``key = value`` line per item: ``subject`` (an RFC
4514 string) or ``rdn`` lines that also name each attribute's string type,
then one line per extension, in certificate order, under its RFC 5280 name or
its object identifier. ``from_certificate`` decodes any certificate into the
same text. A value is written in its readable form only when reading that
form back gives the certificate's own octets, and as ``DER:<hex>`` otherwise,
so what is decoded and fed back builds the same subject and extensions.

Values are taken as written: the upper bounds of RFC 5280 Appendix A are not
applied to an ``rdn`` line, and an extension given as DER is not looked into.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from osmocom.tlv import bertlv_encode_len

from SCP11.shared.ber_tlv import decode_object_identifier, read_ber_tlv, read_single_ber_tlv
from yggdrasim_common.x509_tables import (
    ACCESS_METHODS,
    ANY_POLICY,
    EXTENDED_KEY_USAGES,
    GENERAL_NAME_FORMS,
    KEY_USAGE_BITS,
    NAME_ATTRIBUTES,
    STANDARD_EXTENSIONS,
)

PLACEHOLDER_HOST = "{host}"
PLACEHOLDER_EIM_ID = "{eim_id}"
FORM_TYPED = "typed"
FORM_RAW = "raw"
# An extension whose value is no octets at all is written DER:empty, so a forgotten value is not one.
EMPTY_VALUE = "empty"
MAX_EXTENSIONS = 64
MAX_RDNS = 32

#: RFC 5280 §4.2.1.5, §4.2.1.8, §4.2.1.10, §4.2.1.11 and §4.2.1.14: extensions written as DER only.
#: They belong to CA certificates or carry values of any type, and have no line form here.
RAW_ONLY_EXTENSIONS: dict[str, str] = {
    "policyMappings": "issuer and subject policy pairs of a CA certificate",
    "subjectDirectoryAttributes": "attribute values of any type",
    "nameConstraints": "permitted and excluded subtrees of a CA certificate",
    "policyConstraints": "skip counts of a CA certificate",
    "inhibitAnyPolicy": "a skip count of a CA certificate",
}
#: RFC 5280 §4.2.1.6 GeneralName alternatives without a line form: the certificate library builds neither.
UNSUPPORTED_GENERAL_NAMES: dict[str, str] = {
    "x400Address": "ORAddress has no builder in the certificate library",
    "ediPartyName": "EDIPartyName has no builder in the certificate library",
}

_OID = re.compile(r"^[0-2](\.\d+)+$")
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_EXTENSION_BY_NAME = {info.name.lower(): info for info in STANDARD_EXTENSIONS}
_EXTENSION_BY_OID = {info.oid: info for info in STANDARD_EXTENSIONS}
# The spelling OpenSSL configuration files use for id-ce-extKeyUsage.
_EXTENSION_ALIASES = {"extendedkeyusage": "extkeyusage"}
_ATTRIBUTE_BY_OID = {info.oid: info for info in NAME_ATTRIBUTES}
_ATTRIBUTE_BY_NAME = {key.lower(): info for info in NAME_ATTRIBUTES for key in (info.name, info.short) if key}
_STRING_TYPES = {member.name.lower(): member for member in _ASN1Type}
# RFC 5280 §4.1.2.4 calls it TeletexString; the certificate library keeps the older name.
_STRING_TYPES["teletexstring"] = _ASN1Type.T61String
_STRING_TYPE_NAMES = {_ASN1Type.T61String: "TeletexString"}
_OCTET_TYPES = (_ASN1Type.BitString, _ASN1Type.OctetString)
_GENERAL_NAME_PREFIXES = {form.prefix.lower(): form.prefix for form in GENERAL_NAME_FORMS if form.prefix}
_GENERAL_NAME_SPLIT = re.compile(
    r",\s*(?=(?:" + "|".join(re.escape(prefix) for prefix in _GENERAL_NAME_PREFIXES) + r")\s*:)", re.IGNORECASE)
# An access description is <method>:<name>; no value line uses ';', which a batch command line splits on.
_ACCESS_SPLIT = re.compile(
    r",\s*(?=[A-Za-z0-9.-]+\s*:\s*(?:" + "|".join(re.escape(prefix) for prefix in _GENERAL_NAME_PREFIXES)
    + r")\s*:)", re.IGNORECASE)
_KEY_USAGE_BY_NAME = {bit.name.lower(): bit for bit in KEY_USAGE_BITS}
_KEY_PURPOSES = {name.removeprefix("id-kp-"): oid for oid, name in EXTENDED_KEY_USAGES.items()}
_KEY_PURPOSE_BY_NAME = {name.lower(): (name, oid) for name, oid in _KEY_PURPOSES.items()}
_KEY_PURPOSE_BY_OID = {oid: name for name, oid in _KEY_PURPOSES.items()}
_ACCESS_BY_NAME = {name.removeprefix("id-ad-").lower(): (name.removeprefix("id-ad-"), oid)
                   for oid, name in ACCESS_METHODS.items()}
_ACCESS_BY_OID = {oid: name.removeprefix("id-ad-") for oid, name in ACCESS_METHODS.items()}
# Names the one-line subject reads and writes beside the RFC 4514 short names.
_NAME_OVERRIDES_IN = {info.name: x509.ObjectIdentifier(info.oid) for info in NAME_ATTRIBUTES if not info.short}
_NAME_OVERRIDES_OUT = {oid: name for name, oid in _NAME_OVERRIDES_IN.items()}


class SpecError(ValueError):
    """A certificate text that does not read, or that names something it cannot build."""


@dataclass(frozen=True)
class AttributeSpec:
    """One attribute of a relative distinguished name: its type, its string type and its value."""

    oid: str
    string_type: str
    value: str | bytes


@dataclass(frozen=True)
class ExtensionSpec:
    """One extension: ``text`` is its value line when ``form`` is typed, its DER in hex when raw."""

    oid: str
    critical: bool
    form: str
    text: str

    @property
    def name(self) -> str:
        info = _EXTENSION_BY_OID.get(self.oid)
        return info.name if info is not None else self.oid


@dataclass(frozen=True)
class CertificateSpec:
    """A subject and an extension set; None for a part the text does not give.

    ``subject`` holds the relative distinguished names in certificate order,
    an empty tuple for an empty name. ``extensions`` is in certificate order,
    an empty tuple for a certificate without any.
    """

    subject: tuple[tuple[AttributeSpec, ...], ...] | None = None
    extensions: tuple[ExtensionSpec, ...] | None = None

    @property
    def empty(self) -> bool:
        return self.subject is None and self.extensions is None


@dataclass(frozen=True)
class BuildContext:
    """What a text is resolved against: the two placeholder values and the keys the identifiers are computed from."""

    host: str
    eim_id: str
    public_key: Any
    issuer_public_key: Any


@dataclass(frozen=True)
class ResolvedSpec:
    """A text with its placeholders filled: the subject and each extension as (identifier, critical, DER)."""

    subject: x509.Name | None
    extensions: tuple[tuple[str, bool, bytes], ...] | None


@dataclass(frozen=True)
class _Values:
    host: str
    eim_id: str
    subject_key_id: bytes
    authority_key_id: bytes

    def fill(self, text: str, where: str) -> str:
        for token, value, source in ((PLACEHOLDER_HOST, self.host, "the setup has no eIM FQDN"),
                                     (PLACEHOLDER_EIM_ID, self.eim_id, "the Local eIM has no eimId")):
            if token in text:
                if len(value) == 0:
                    raise SpecError(f"{where}: {token} has no value ({source}).")
                text = text.replace(token, value)
        return text


# What a text is checked against when it is read: every placeholder has a value that fits where it may stand.
_PROBE = _Values(host="host.invalid", eim_id="2.999", subject_key_id=bytes(20), authority_key_id=bytes(20))
# What a name is written with: each placeholder stays as it stands.
_LITERAL = _Values(host=PLACEHOLDER_HOST, eim_id=PLACEHOLDER_EIM_ID, subject_key_id=b"", authority_key_id=b"")


def _values(context: BuildContext) -> _Values:
    return _Values(
        host=str(context.host or ""), eim_id=str(context.eim_id or ""),
        subject_key_id=x509.SubjectKeyIdentifier.from_public_key(context.public_key).digest,
        authority_key_id=x509.SubjectKeyIdentifier.from_public_key(context.issuer_public_key).digest,
    )


# -- DER ---------------------------------------------------------------------


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + bertlv_encode_len(len(content)) + content


def _integer(value: int) -> bytes:
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def raw_extensions(certificate: x509.Certificate) -> list[tuple[str, bool, bytes]]:
    """(identifier, critical, extnValue contents) of each extension, in certificate order.

    Read from the TBSCertificate itself (RFC 5280 §4.1: extensions [3]
    EXPLICIT, each Extension a SEQUENCE of extnID, critical DEFAULT FALSE and
    extnValue), so the octets are the certificate's own and not a re-encoding.
    """
    try:
        _tag, body, _raw = read_single_ber_tlv(certificate.tbs_certificate_bytes)
        found: list[tuple[str, bool, bytes]] = []
        offset = 0
        while offset < len(body):
            tag, value, _raw, offset = read_ber_tlv(body, offset)
            if tag != b"\xA3":
                continue
            _tag, sequence, _raw = read_single_ber_tlv(value)
            inner = 0
            while inner < len(sequence):
                _tag, extension, _raw, inner = read_ber_tlv(sequence, inner)
                tag, identifier, _raw, position = read_ber_tlv(extension, 0)
                if tag != b"\x06":
                    raise ValueError("an Extension does not start with its extnID")
                tag, member, _raw, position = read_ber_tlv(extension, position)
                critical = False
                if tag == b"\x01":
                    critical = member != b"\x00"
                    tag, member, _raw, position = read_ber_tlv(extension, position)
                if tag != b"\x04":
                    raise ValueError("an Extension has no extnValue")
                found.append((decode_object_identifier(identifier), critical, bytes(member)))
        return found
    except (ValueError, TypeError, IndexError) as error:
        raise SpecError(f"The certificate's extensions do not read: {error}") from error


# -- names -------------------------------------------------------------------


def _attribute_oid(text: str) -> str:
    known = _ATTRIBUTE_BY_NAME.get(text.strip().lower())
    if known is not None:
        return known.oid
    if _OID.match(text.strip()) is None:
        names = ", ".join(info.short or info.name for info in NAME_ATTRIBUTES)
        raise SpecError(f"{text.strip()!r} names no attribute type; known: {names}, or an object identifier.")
    return text.strip()


def attribute_label(oid: str) -> str:
    """The short name of attribute type *oid*, its name when it has no short one, else the identifier."""
    info = _ATTRIBUTE_BY_OID.get(oid)
    if info is None:
        return oid
    return info.short or info.name


def _string_type(text: str) -> _ASN1Type:
    member = _STRING_TYPES.get(text.strip().lower())
    if member is None:
        names = ", ".join(sorted({_STRING_TYPE_NAMES.get(item, item.name) for item in _ASN1Type}))
        raise SpecError(f"{text.strip()!r} is no string type; known: {names}.")
    return member


def string_type_label(member: _ASN1Type) -> str:
    return _STRING_TYPE_NAMES.get(member, member.name)


def default_string_type(oid: str) -> str:
    """The string type the one-line subject gives attribute type *oid*: the certificate library's default."""
    from cryptography.x509.name import _NAMEOID_DEFAULT_TYPE

    return string_type_label(_NAMEOID_DEFAULT_TYPE.get(x509.ObjectIdentifier(oid), _ASN1Type.UTF8String))


def _name_attribute(spec: AttributeSpec, values: _Values, where: str) -> x509.NameAttribute:
    value = spec.value
    if isinstance(value, str):
        value = values.fill(value, where)
    try:
        # Taken as written: the attribute's bounds are for whoever judges the certificate.
        return x509.NameAttribute(x509.ObjectIdentifier(spec.oid), value, _type=_string_type(spec.string_type),
                                  _validate=False)
    except (ValueError, TypeError) as error:
        raise SpecError(f"{where}: {attribute_label(spec.oid)} does not build: {error}") from error


def _name(rdns: Sequence[Sequence[AttributeSpec]], values: _Values) -> x509.Name:
    built: list[x509.RelativeDistinguishedName] = []
    for index, rdn in enumerate(rdns, start=1):
        try:
            built.append(x509.RelativeDistinguishedName(
                [_name_attribute(attribute, values, f"subject RDN {index}") for attribute in rdn]))
        except (ValueError, TypeError) as error:
            if isinstance(error, SpecError):
                raise
            raise SpecError(f"subject RDN {index} does not build: {error}") from error
    return x509.Name(built)


def subject_from_name(name: x509.Name) -> tuple[tuple[AttributeSpec, ...], ...]:
    """*name* as relative distinguished names in certificate order, each attribute with its string type."""
    rdns: list[tuple[AttributeSpec, ...]] = []
    for rdn in name.rdns:
        rdns.append(tuple(
            AttributeSpec(attribute.oid.dotted_string,
                          string_type_label(attribute._type),  # noqa: SLF001 - the type the certificate encodes
                          attribute.value)
            for attribute in rdn
        ))
    return tuple(rdns)


def _one_line_subject(text: str) -> tuple[tuple[AttributeSpec, ...], ...]:
    try:
        name = x509.Name.from_rfc4514_string(text, _NAME_OVERRIDES_IN)
    except (ValueError, TypeError) as error:
        detail = f": {error}" if str(error) else ""
        raise SpecError(f"subject {text!r} does not read as an RFC 4514 name{detail}. The form is "
                        "CN=eim.example.test,O=Example Org,C=XX: no space around ',', '+' or '=', and a ',' "
                        "inside a value written '\\,'.") from error
    return subject_from_name(name)


def _parse_rdn(text: str, number: int) -> tuple[AttributeSpec, ...]:
    attributes: list[AttributeSpec] = []
    for part in text.split(" + "):
        pieces = part.strip().split(":", 2)
        if len(pieces) != 3:
            raise SpecError(f"line {number}: {part.strip()!r} is not type:string type:value; a value holding ' + ' "
                            "is written hex:<hex of its UTF-8>.")
        oid = _attribute_oid(pieces[0])
        member = _string_type(pieces[1])
        value: str | bytes = pieces[2].strip()
        if isinstance(value, str) and value.lower().startswith("hex:"):
            digits = value[4:].strip()
            if _HEX.match(digits) is None and len(digits) > 0:
                raise SpecError(f"line {number}: {attribute_label(oid)} hex value {digits!r} is not hex.")
            octets = bytes.fromhex(digits)
            if member in _OCTET_TYPES:
                value = octets
            else:
                try:
                    value = octets.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise SpecError(f"line {number}: {attribute_label(oid)} hex value is not UTF-8: {error}") from error
        elif member in _OCTET_TYPES:
            raise SpecError(f"line {number}: a {string_type_label(member)} value is written hex:<hex>.")
        attributes.append(AttributeSpec(oid, string_type_label(member), value))
    if len(attributes) == 0:
        raise SpecError(f"line {number}: an rdn line names at least one attribute.")
    return tuple(attributes)


def _rdn_value(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return "hex:" + value.hex().upper()
    plain = (value == value.strip() and " + " not in value and len(value) > 0 and not value.lower().startswith("hex:")
             and "\n" not in value and "\r" not in value)
    return value if plain else "hex:" + value.encode("utf-8").hex().upper()


def _rdn_line(rdn: Sequence[AttributeSpec]) -> str:
    return " + ".join(f"{attribute_label(item.oid)}:{item.string_type}:{_rdn_value(item.value)}" for item in rdn)


def _subject_lines(rdns: tuple[tuple[AttributeSpec, ...], ...]) -> list[str]:
    """The subject as one line when that line reads back to the same name, as rdn lines otherwise."""
    if len(rdns) == 0:
        return ["subject = none"]
    try:
        name = _name(rdns, _LITERAL)
        text = name.rfc4514_string(_NAME_OVERRIDES_OUT)
        again = x509.Name.from_rfc4514_string(text, _NAME_OVERRIDES_IN)
        if again.public_bytes() == name.public_bytes() and "\n" not in text and text.strip() == text \
                and text.lower() != "none":
            return [f"subject = {text}"]
    except (SpecError, ValueError, TypeError):
        pass
    return [f"rdn = {_rdn_line(rdn)}" for rdn in rdns]


# -- general names -----------------------------------------------------------


def _split_general_names(text: str) -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = []
    for part in _GENERAL_NAME_SPLIT.split(text.strip()):
        prefix, separator, value = part.partition(":")
        canonical = _GENERAL_NAME_PREFIXES.get(prefix.strip().lower())
        if not separator or canonical is None:
            known = ", ".join(form.prefix for form in GENERAL_NAME_FORMS if form.prefix)
            raise SpecError(f"{part.strip()!r} is not a name; a name is one of {known} followed by ':' and its value.")
        if len(value.strip()) == 0:
            raise SpecError(f"{canonical}: has no value.")
        names.append((canonical, value.strip()))
    return names


def _general_name(prefix: str, raw: str, values: _Values) -> x509.GeneralName:
    value = values.fill(raw, f"{prefix}:{raw}")
    try:
        if prefix == "DNS":
            return x509.DNSName(value)
        if prefix == "email":
            return x509.RFC822Name(value)
        if prefix == "URI":
            return x509.UniformResourceIdentifier(value)
        if prefix == "IP":
            return x509.IPAddress(ipaddress.ip_address(value))
        if prefix == "RID":
            if _OID.match(value) is None:
                raise ValueError("RID takes an object identifier")
            return x509.RegisteredID(x509.ObjectIdentifier(value))
        if prefix == "DirName":
            return x509.DirectoryName(x509.Name.from_rfc4514_string(value, _NAME_OVERRIDES_IN))
        identifier, separator, octets = value.partition(":")
        if not separator or _HEX.match(octets.strip()) is None:
            raise ValueError("otherName is written <object identifier>:<hex of its DER value>")
        return x509.OtherName(x509.ObjectIdentifier(identifier.strip()), bytes.fromhex(octets.strip()))
    except (ValueError, TypeError) as error:
        note = ""
        if prefix == "RID" and PLACEHOLDER_EIM_ID in raw:
            note = f" ({PLACEHOLDER_EIM_ID} is the Local eIM's eimId, which is not an object identifier)"
        raise SpecError(f"{prefix}:{value} does not build: {error}{note}") from error


def _general_name_text(name: x509.GeneralName) -> tuple[str, str] | None:
    if isinstance(name, x509.DNSName):
        return "DNS", name.value
    if isinstance(name, x509.RFC822Name):
        return "email", name.value
    if isinstance(name, x509.UniformResourceIdentifier):
        return "URI", name.value
    if isinstance(name, x509.IPAddress):
        if not isinstance(name.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return None
        return "IP", str(name.value)
    if isinstance(name, x509.RegisteredID):
        return "RID", name.value.dotted_string
    if isinstance(name, x509.DirectoryName):
        return "DirName", name.value.rfc4514_string(_NAME_OVERRIDES_OUT)
    if isinstance(name, x509.OtherName):
        return "otherName", f"{name.type_id.dotted_string}:{name.value.hex().upper()}"
    return None


def _join_general_names(names: Sequence[x509.GeneralName]) -> str | None:
    parts: list[str] = []
    for name in names:
        written = _general_name_text(name)
        if written is None:
            return None
        parts.append(f"{written[0]}:{written[1]}")
    return ", ".join(parts)


def _name_items(text: str) -> list[dict[str, str]]:
    return [{"kind": prefix, "value": value} for prefix, value in _split_general_names(text)]


def _name_text(items: Any) -> str:
    return ", ".join(f"{_item(entry, 'kind')}:{_item(entry, 'value')}" for entry in _sequence(items))


# -- extension values ----------------------------------------------------------


def _sequence(items: Any) -> list[Any]:
    if not isinstance(items, (list, tuple)):
        raise SpecError("An extension's items are a list.")
    return list(items)


def _item(entry: Any, key: str) -> str:
    if not isinstance(entry, Mapping):
        raise SpecError("An item is an object.")
    return str(entry.get(key, "") or "").strip()


def _parts(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if len(part.strip()) > 0]


def _basic_items(text: str) -> dict[str, Any]:
    ca: bool | None = None
    pathlen = ""
    for part in _parts(text):
        key, separator, value = part.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "ca" and separator and value.upper() in ("TRUE", "FALSE"):
            ca = value.upper() == "TRUE"
        elif key == "pathlen" and separator and value.isdigit():
            pathlen = str(int(value))
        else:
            raise SpecError(f"reads CA:TRUE or CA:FALSE and pathlen:<n>; got {part!r}.")
    if ca is None:
        raise SpecError("needs CA:TRUE or CA:FALSE.")
    return {"ca": ca, "pathlen": pathlen}


def _basic_text(items: Any) -> str:
    if not isinstance(items, Mapping):
        raise SpecError("basicConstraints items are an object.")
    pathlen = str(items.get("pathlen", "") or "").strip()
    return f"CA:{'TRUE' if items.get('ca') else 'FALSE'}" + (f", pathlen:{pathlen}" if pathlen else "")


def _basic_encode(text: str, _values: _Values) -> bytes:
    # BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    # (RFC 5280 §4.2.1.9); DER leaves a FALSE cA out.
    items = _basic_items(text)
    content = b"\x01\x01\xff" if items["ca"] else b""
    if items["pathlen"]:
        content += _integer(int(items["pathlen"]))
    return _tlv(0x30, content)


def _basic_describe(_value: Any, der: bytes, _values: _Values) -> str | None:
    # Read from the octets themselves: the certificate library has no class for a path length without cA.
    tag, content, _raw = read_single_ber_tlv(der)
    if tag != b"\x30":
        return None
    ca, pathlen, offset = False, "", 0
    while offset < len(content):
        tag, member, _raw, offset = read_ber_tlv(content, offset)
        if tag == b"\x01" and len(member) == 1 and not pathlen:
            ca = member != b"\x00"
        elif tag == b"\x02" and len(member) > 0 and member[0] < 0x80:
            pathlen = str(int.from_bytes(member, "big"))
        else:
            return None
    return _basic_text({"ca": ca, "pathlen": pathlen})


def _key_usage_items(text: str) -> list[str]:
    names: list[str] = []
    for part in _parts(text):
        bit = _KEY_USAGE_BY_NAME.get(part.lower())
        if bit is None:
            raise SpecError(f"no bit {part!r}; the bits are {', '.join(item.name for item in KEY_USAGE_BITS)}.")
        if bit.name not in names:
            names.append(bit.name)
    if len(names) == 0:
        # RFC 5280 §4.2.1.3: at least one bit is set when the extension appears.
        raise SpecError("names at least one bit.")
    return sorted(names, key=lambda name: _KEY_USAGE_BY_NAME[name.lower()].bit)


def _list_text(items: Any) -> str:
    return ", ".join(str(entry).strip() for entry in _sequence(items) if len(str(entry).strip()) > 0)


def _key_usage_encode(text: str, _values: _Values) -> bytes:
    bits = [_KEY_USAGE_BY_NAME[name.lower()].bit for name in _key_usage_items(text)]
    octets = bytearray(max(bits) // 8 + 1)
    for bit in bits:
        octets[bit // 8] |= 0x80 >> (bit % 8)
    # A named bit list drops its trailing zero bits (ITU-T X.690 (02/2021) clause 11.2.2).
    return _tlv(0x03, bytes([7 - max(bits) % 8]) + bytes(octets))


def _key_usage_describe(_value: Any, der: bytes, _values: _Values) -> str | None:
    tag, content, _raw = read_single_ber_tlv(der)
    if tag != b"\x03" or len(content) < 2:
        return None
    names = [bit.name for bit in KEY_USAGE_BITS
             if bit.bit // 8 < len(content) - 1 and content[1 + bit.bit // 8] & (0x80 >> (bit.bit % 8))]
    return ", ".join(names) if names else None


def _purpose_items(text: str) -> list[str]:
    names: list[str] = []
    for part in _parts(text):
        known = _KEY_PURPOSE_BY_NAME.get(part.lower())
        if known is None and _OID.match(part) is None:
            raise SpecError(f"no purpose {part!r}; known: {', '.join(_KEY_PURPOSES)}, or an object identifier.")
        names.append(known[0] if known is not None else _KEY_PURPOSE_BY_OID.get(part, part))
    if len(names) == 0:
        raise SpecError("names at least one purpose.")
    return names


def _purpose_encode(text: str, _values: _Values) -> bytes:
    purposes = [x509.ObjectIdentifier(_KEY_PURPOSES.get(name, name)) for name in _purpose_items(text)]
    return x509.ExtendedKeyUsage(purposes).public_bytes()


def _purpose_describe(value: Any, _der: bytes, _values: _Values) -> str | None:
    if not isinstance(value, x509.ExtendedKeyUsage):
        return None
    return ", ".join(_KEY_PURPOSE_BY_OID.get(item.dotted_string, item.dotted_string) for item in value)


def _alt_names_encode(kind: type) -> Callable[[str, _Values], bytes]:
    def encode(text: str, values: _Values) -> bytes:
        names = [_general_name(prefix, value, values) for prefix, value in _split_general_names(text)]
        return kind(names).public_bytes()

    return encode


def _alt_names_describe(value: Any, _der: bytes, _values: _Values) -> str | None:
    if not isinstance(value, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        return None
    return _join_general_names(list(value))


def _key_id_items(keyword: str) -> Callable[[str], dict[str, str]]:
    def items(text: str) -> dict[str, str]:
        value = text.strip()
        if value.lower() == keyword:
            return {"mode": keyword, "hex": ""}
        if _HEX.match(value) is None:
            raise SpecError(f"A key identifier is {keyword} (computed from the key) or its octets in hex; got {value!r}.")
        return {"mode": "hex", "hex": value.upper()}

    return items


def _key_id_text(keyword: str) -> Callable[[Any], str]:
    def text(items: Any) -> str:
        if not isinstance(items, Mapping):
            raise SpecError("A key identifier's items are an object.")
        if str(items.get("mode", "") or keyword) == keyword:
            return keyword
        return str(items.get("hex", "") or "").strip().upper()

    return text


def _subject_key_encode(text: str, values: _Values) -> bytes:
    # SubjectKeyIdentifier ::= KeyIdentifier, an OCTET STRING (RFC 5280 §4.2.1.2).
    items = _key_id_items("hash")(text)
    return _tlv(0x04, values.subject_key_id if items["mode"] == "hash" else bytes.fromhex(items["hex"]))


def _subject_key_describe(value: Any, _der: bytes, values: _Values) -> str | None:
    if not isinstance(value, x509.SubjectKeyIdentifier):
        return None
    return "hash" if value.digest == values.subject_key_id else value.digest.hex().upper()


def _authority_key_encode(text: str, values: _Values) -> bytes:
    # AuthorityKeyIdentifier with keyIdentifier [0] alone (RFC 5280 §4.2.1.1).
    items = _key_id_items("keyid")(text)
    return _tlv(0x30, _tlv(0x80, values.authority_key_id if items["mode"] == "keyid" else bytes.fromhex(items["hex"])))


def _authority_key_describe(value: Any, _der: bytes, values: _Values) -> str | None:
    if not isinstance(value, x509.AuthorityKeyIdentifier) or value.key_identifier is None:
        return None
    if value.authority_cert_issuer is not None or value.authority_cert_serial_number is not None:
        return None
    return "keyid" if value.key_identifier == values.authority_key_id else value.key_identifier.hex().upper()


def _policy_items(text: str) -> list[str]:
    names: list[str] = []
    for part in _parts(text):
        if part.lower() == "anypolicy":
            names.append("anyPolicy")
        elif _OID.match(part) is not None:
            names.append("anyPolicy" if part == ANY_POLICY else part)
        else:
            raise SpecError(f"lists object identifiers or anyPolicy; got {part!r}.")
    if len(names) == 0:
        raise SpecError("names at least one policy.")
    return names


def _policy_encode(text: str, _values: _Values) -> bytes:
    policies = [x509.PolicyInformation(x509.ObjectIdentifier(ANY_POLICY if name == "anyPolicy" else name), None)
                for name in _policy_items(text)]
    return x509.CertificatePolicies(policies).public_bytes()


def _policy_describe(value: Any, _der: bytes, _values: _Values) -> str | None:
    if not isinstance(value, x509.CertificatePolicies):
        return None
    if any(policy.policy_qualifiers for policy in value):
        return None
    return ", ".join("anyPolicy" if policy.policy_identifier.dotted_string == ANY_POLICY
                     else policy.policy_identifier.dotted_string for policy in value)


def _points_encode(kind: type) -> Callable[[str, _Values], bytes]:
    def encode(text: str, values: _Values) -> bytes:
        # One DistributionPoint per name, each with that name as its fullName (RFC 5280 §4.2.1.13).
        points = [x509.DistributionPoint([_general_name(prefix, value, values)], None, None, None)
                  for prefix, value in _split_general_names(text)]
        return kind(points).public_bytes()

    return encode


def _points_describe(value: Any, _der: bytes, _values: _Values) -> str | None:
    if not isinstance(value, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        return None
    names: list[x509.GeneralName] = []
    for point in value:
        if point.full_name is None or len(point.full_name) != 1 or point.relative_name is not None \
                or point.reasons is not None or point.crl_issuer is not None:
            return None
        names.append(point.full_name[0])
    return _join_general_names(names)


def _access_items(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for part in _ACCESS_SPLIT.split(text.strip()):
        method, separator, location = part.partition(":")
        known = _ACCESS_BY_NAME.get(method.strip().lower())
        if not separator or (known is None and _OID.match(method.strip()) is None):
            raise SpecError(f"{part.strip()!r} is not <access method>:<name>; the methods are "
                            f"{', '.join(name for name, _oid in _ACCESS_BY_NAME.values())}, or an object identifier.")
        names = _split_general_names(location)
        if len(names) != 1:
            raise SpecError(f"{part.strip()!r} carries one name per access method.")
        entries.append({"method": known[0] if known is not None else _ACCESS_BY_OID.get(method.strip(), method.strip()),
                        "kind": names[0][0], "value": names[0][1]})
    return entries


def _access_text(items: Any) -> str:
    return ", ".join(f"{_item(entry, 'method')}:{_item(entry, 'kind')}:{_item(entry, 'value')}"
                     for entry in _sequence(items))


def _access_encode(kind: type) -> Callable[[str, _Values], bytes]:
    def encode(text: str, values: _Values) -> bytes:
        descriptions = []
        for entry in _access_items(text):
            known = _ACCESS_BY_NAME.get(entry["method"].lower())
            method = x509.ObjectIdentifier(known[1] if known is not None else entry["method"])
            descriptions.append(x509.AccessDescription(method, _general_name(entry["kind"], entry["value"], values)))
        return kind(descriptions).public_bytes()

    return encode


def _access_describe(value: Any, _der: bytes, _values: _Values) -> str | None:
    if not isinstance(value, (x509.AuthorityInformationAccess, x509.SubjectInformationAccess)):
        return None
    parts: list[str] = []
    for description in value:
        written = _general_name_text(description.access_location)
        if written is None:
            return None
        method = description.access_method.dotted_string
        parts.append(f"{_ACCESS_BY_OID.get(method, method)}:{written[0]}:{written[1]}")
    return ", ".join(parts)


@dataclass(frozen=True)
class _Codec:
    """How one extension's value line is read and written, and what an editor shows for it."""

    widget: str
    encode: Callable[[str, _Values], bytes]
    describe: Callable[[Any, bytes, _Values], str | None]
    items: Callable[[str], Any]
    text: Callable[[Any], str]
    default: str
    critical: bool = False
    choices: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()


_NAME_KINDS = tuple(form.prefix for form in GENERAL_NAME_FORMS if form.prefix)
_OID_OF = {info.name: info.oid for info in STANDARD_EXTENSIONS}
_CODECS: dict[str, _Codec] = {
    _OID_OF["authorityKeyIdentifier"]: _Codec(
        "key-id", _authority_key_encode, _authority_key_describe, _key_id_items("keyid"), _key_id_text("keyid"),
        "keyid", choices=("keyid", "hex")),
    _OID_OF["subjectKeyIdentifier"]: _Codec(
        "key-id", _subject_key_encode, _subject_key_describe, _key_id_items("hash"), _key_id_text("hash"),
        "hash", choices=("hash", "hex")),
    _OID_OF["keyUsage"]: _Codec(
        "choice-set", _key_usage_encode, _key_usage_describe, _key_usage_items, _list_text,
        "digitalSignature", critical=True, choices=tuple(bit.name for bit in KEY_USAGE_BITS)),
    _OID_OF["certificatePolicies"]: _Codec(
        "text-list", _policy_encode, _policy_describe, _policy_items, _list_text, "anyPolicy"),
    _OID_OF["subjectAltName"]: _Codec(
        "name-list", _alt_names_encode(x509.SubjectAlternativeName), _alt_names_describe, _name_items, _name_text,
        f"DNS:{PLACEHOLDER_HOST}", kinds=_NAME_KINDS),
    _OID_OF["issuerAltName"]: _Codec(
        "name-list", _alt_names_encode(x509.IssuerAlternativeName), _alt_names_describe, _name_items, _name_text,
        "DNS:issuer.example.test", kinds=_NAME_KINDS),
    _OID_OF["basicConstraints"]: _Codec(
        "basic", _basic_encode, _basic_describe, _basic_items, _basic_text, "CA:FALSE", critical=True),
    _OID_OF["extKeyUsage"]: _Codec(
        "choice-set", _purpose_encode, _purpose_describe, _purpose_items, _list_text,
        "serverAuth", choices=tuple(_KEY_PURPOSES)),
    _OID_OF["cRLDistributionPoints"]: _Codec(
        "name-list", _points_encode(x509.CRLDistributionPoints), _points_describe, _name_items, _name_text,
        "URI:http://crl.example.test/ca.crl", kinds=_NAME_KINDS),
    _OID_OF["freshestCRL"]: _Codec(
        "name-list", _points_encode(x509.FreshestCRL), _points_describe, _name_items, _name_text,
        "URI:http://crl.example.test/delta.crl", kinds=_NAME_KINDS),
    _OID_OF["authorityInfoAccess"]: _Codec(
        "access-list", _access_encode(x509.AuthorityInformationAccess), _access_describe, _access_items, _access_text,
        "ocsp:URI:http://ocsp.example.test", kinds=_NAME_KINDS, methods=tuple(name for name, _oid in _ACCESS_BY_NAME.values())),
    _OID_OF["subjectInfoAccess"]: _Codec(
        "access-list", _access_encode(x509.SubjectInformationAccess), _access_describe, _access_items, _access_text,
        "caRepository:URI:http://repository.example.test", kinds=_NAME_KINDS,
        methods=tuple(name for name, _oid in _ACCESS_BY_NAME.values())),
}


def typed_extension_names() -> tuple[str, ...]:
    """The RFC 5280 extensions that have a value line, in clause order."""
    return tuple(info.name for info in STANDARD_EXTENSIONS if info.oid in _CODECS)


def _extension_oid(key: str) -> str:
    lowered = key.strip().lower()
    info = _EXTENSION_BY_NAME.get(_EXTENSION_ALIASES.get(lowered, lowered))
    if info is not None:
        return info.oid
    if _OID.match(key.strip()) is None:
        names = ", ".join(item.name for item in STANDARD_EXTENSIONS)
        raise SpecError(f"{key.strip()!r} names no extension; known: {names}, or an object identifier.")
    return key.strip()


def is_key(key: str) -> bool:
    """Whether *key* is one a certificate text line starts with: subject, rdn, extensions, or an extension."""
    lowered = str(key or "").strip().lower()
    if lowered in ("subject", "rdn", "extensions"):
        return True
    return _EXTENSION_ALIASES.get(lowered, lowered) in _EXTENSION_BY_NAME or _OID.match(lowered) is not None


def _typed(oid: str, text: str, where: str) -> str:
    """*text* as the canonical value line of extension *oid*, checked by encoding it."""
    codec = _CODECS.get(oid)
    if codec is None:
        reason = RAW_ONLY_EXTENSIONS.get(_EXTENSION_BY_OID[oid].name if oid in _EXTENSION_BY_OID else "")
        raise SpecError(f"{where}: written as DER:<hex of its value>"
                        + (f" ({reason})." if reason else "; only the RFC 5280 extensions have a value line."))
    try:
        canonical = codec.text(codec.items(text))
        codec.encode(canonical, _PROBE)
    except SpecError as error:
        raise SpecError(f"{where}: {error}") from error
    except (ValueError, TypeError) as error:
        raise SpecError(f"{where}: does not build: {error}") from error
    return canonical


def _raw_value(text: str, where: str) -> str:
    """The hex of a value given as DER; '' for the explicit ``empty``."""
    digits = "".join(str(text or "").split())
    if digits.lower() == EMPTY_VALUE:
        return ""
    if _HEX.match(digits) is None:
        raise SpecError(f"{where}: DER: takes the value's octets in hex, or {EMPTY_VALUE} for a value without any.")
    return digits.upper()


def _extension(oid: str, value: str, where: str) -> ExtensionSpec:
    critical = False
    head, separator, rest = value.partition(",")
    if head.strip().lower() == "critical":
        critical = True
        value = rest.strip() if separator else ""
    value = value.strip()
    if value.lower().startswith("der:"):
        return ExtensionSpec(oid, critical, FORM_RAW, _raw_value(value[4:], where))
    if len(value) == 0:
        raise SpecError(f"{where}: no value.")
    return ExtensionSpec(oid, critical, FORM_TYPED, _typed(oid, value, where))


# -- text ----------------------------------------------------------------------


def parse_text(text: str) -> CertificateSpec:
    """Read the ``key = value`` lines of *text*; a line that does not read is refused, never skipped."""
    subject: tuple[tuple[AttributeSpec, ...], ...] | None = None
    one_line = False
    rdns: list[tuple[AttributeSpec, ...]] = []
    extensions: list[ExtensionSpec] = []
    none_given = False
    seen: set[str] = set()
    for number, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        if len(line) == 0 or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or len(key.strip()) == 0:
            raise SpecError(f"line {number}: {line!r} is not key = value.")
        key, value = key.strip(), value.strip()
        lowered = key.lower()
        if lowered == "subject":
            if one_line or rdns:
                raise SpecError(f"line {number}: the subject is given once, as one subject line or as rdn lines.")
            one_line = True
            if len(value) == 0:
                raise SpecError(f"line {number}: subject has no value; an empty name is written subject = none.")
            subject = () if value.lower() == "none" else _one_line_subject(value)
        elif lowered == "rdn":
            if one_line:
                raise SpecError(f"line {number}: the subject is given once, as one subject line or as rdn lines.")
            if len(rdns) >= MAX_RDNS:
                raise SpecError(f"line {number}: a subject takes at most {MAX_RDNS} rdn lines.")
            rdns.append(_parse_rdn(value, number))
        elif lowered == "extensions":
            if value.lower() != "none":
                raise SpecError(f"line {number}: extensions takes only none; an extension is a line of its own.")
            none_given = True
        else:
            oid = _extension_oid(key)
            if oid in seen:
                raise SpecError(f"line {number}: {key} is given twice; a certificate carries an extension once.")
            if len(extensions) >= MAX_EXTENSIONS:
                raise SpecError(f"line {number}: at most {MAX_EXTENSIONS} extensions.")
            seen.add(oid)
            extensions.append(_extension(oid, value, f"line {number}: {key}"))
    if none_given and extensions:
        raise SpecError("extensions = none stands alone; the text also lists extensions.")
    if rdns:
        subject = tuple(rdns)
    if subject is not None:
        # A name that cannot be built is refused where it is written, not when a leaf is issued.
        _name(subject, _PROBE)
    return CertificateSpec(subject=subject, extensions=tuple(extensions) if extensions or none_given else None)


def extension_line(extension: ExtensionSpec) -> str:
    value = f"DER:{extension.text or EMPTY_VALUE}" if extension.form == FORM_RAW else extension.text
    return f"{extension.name} = {'critical, ' if extension.critical else ''}{value}"


def to_text(spec: CertificateSpec) -> str:
    """The canonical text of *spec*: what ``parse_text`` reads back to the same value."""
    lines: list[str] = []
    if spec.subject is not None:
        lines.extend(_subject_lines(spec.subject))
    if spec.extensions is not None:
        if len(spec.extensions) == 0:
            lines.append("extensions = none")
        lines.extend(extension_line(extension) for extension in spec.extensions)
    return "\n".join(lines)


def describe(spec: CertificateSpec) -> str:
    """One line for a listing: which parts the text gives."""
    parts: list[str] = []
    if spec.subject is not None:
        parts.append("subject given" if spec.subject else "empty subject")
    if spec.extensions is not None:
        names = [extension.name + ("!" if extension.critical else "") for extension in spec.extensions]
        parts.append(f"extensions given: {', '.join(names) or 'none'}")
    return "; ".join(parts)


# -- certificates --------------------------------------------------------------


def resolve(spec: CertificateSpec, context: BuildContext) -> ResolvedSpec:
    """*spec* with its placeholders filled and its key identifiers computed, ready for a certificate builder."""
    values = _values(context)
    subject = _name(spec.subject, values) if spec.subject is not None else None
    extensions: tuple[tuple[str, bool, bytes], ...] | None = None
    if spec.extensions is not None:
        built: list[tuple[str, bool, bytes]] = []
        for extension in spec.extensions:
            if extension.form == FORM_RAW:
                built.append((extension.oid, extension.critical, bytes.fromhex(extension.text)))
                continue
            try:
                built.append((extension.oid, extension.critical, _CODECS[extension.oid].encode(extension.text, values)))
            except SpecError as error:
                raise SpecError(f"{extension.name}: {error}") from error
            except (ValueError, TypeError, KeyError) as error:
                raise SpecError(f"{extension.name} does not build: {error}") from error
        extensions = tuple(built)
    return ResolvedSpec(subject=subject, extensions=extensions)


def add_extensions(builder: x509.CertificateBuilder, resolved: ResolvedSpec) -> x509.CertificateBuilder:
    """*builder* with exactly the extensions of *resolved*, in their order."""
    for oid, critical, der in resolved.extensions or ():
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der), critical=critical)
    return builder


def check_built(certificate: x509.Certificate, resolved: ResolvedSpec) -> None:
    """Refuse a certificate whose subject or extensions are not the octets *resolved* asked for."""
    if resolved.subject is not None and certificate.subject.public_bytes() != resolved.subject.public_bytes():
        raise SpecError("The certificate's subject is not the one the text gives: "
                        f"{certificate.subject.rfc4514_string()} for {resolved.subject.rfc4514_string()}.")
    if resolved.extensions is not None:
        carried = raw_extensions(certificate)
        if carried != list(resolved.extensions):
            wanted = ", ".join(oid for oid, _critical, _der in resolved.extensions) or "none"
            got = ", ".join(oid for oid, _critical, _der in carried) or "none"
            raise SpecError(f"The certificate's extensions are not the ones the text gives: {got} for {wanted}.")


_PROBE_NAME = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "probe")])
_PROBE_FROM = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)


def _typed_values(certificate: x509.Certificate, carried: Sequence[tuple[str, bool, bytes]]) -> dict[str, Any]:
    """Each extension's value as the certificate library's own class, by identifier, where it can read it.

    The library reads a certificate's extensions as a set and gives up on all
    of them over one value it has no class for (a key usage with encipherOnly
    alone, a general name form it does not know). Then each extension that
    has a line form is read on its own, in a certificate made to carry it, so
    one value keeps its octets and the others keep their lines.
    """
    try:
        return {extension.oid.dotted_string: extension.value for extension in certificate.extensions}
    except (ValueError, TypeError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        pass
    values: dict[str, Any] = {}
    key = ec.generate_private_key(ec.SECP256R1())
    for oid, critical, der in carried:
        if oid not in _CODECS or oid in values:
            continue
        try:
            probe = (
                x509.CertificateBuilder().subject_name(_PROBE_NAME).issuer_name(_PROBE_NAME)
                .public_key(key.public_key()).serial_number(1).not_valid_before(_PROBE_FROM)
                .not_valid_after(_PROBE_FROM + datetime.timedelta(days=1))
                .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der), critical=critical)
                .sign(key, hashes.SHA256())
            )
            values[oid] = probe.extensions[0].value
        except (ValueError, TypeError, x509.UnsupportedGeneralNameType):
            continue
    return values


def from_certificate(certificate: x509.Certificate, *, issuer_public_key: Any = None) -> CertificateSpec:
    """Decode *certificate* into a subject and an extension set that build the same octets.

    A key identifier is written ``hash`` / ``keyid`` when it is the one
    computed from the certificate's key (from *issuer_public_key*; taken as
    such without it), so the text stays right for a new key. Every other
    value keeps its own octets.
    """
    subject = subject_from_name(certificate.subject)
    try:
        if _name(subject, _LITERAL).public_bytes() != certificate.subject.public_bytes():
            raise SpecError("the name does not read back to its own octets")
    except SpecError as error:
        raise SpecError(f"The certificate's subject cannot be written as text: {error}") from error
    carried = raw_extensions(certificate)
    typed = _typed_values(certificate, carried)
    own_key_id = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest
    authority_key_id = b""
    if issuer_public_key is not None:
        authority_key_id = x509.SubjectKeyIdentifier.from_public_key(issuer_public_key).digest
    else:
        value = typed.get(_OID_OF["authorityKeyIdentifier"])
        if isinstance(value, x509.AuthorityKeyIdentifier) and value.key_identifier is not None:
            authority_key_id = value.key_identifier
    values = _Values("", "", own_key_id, authority_key_id)
    extensions: list[ExtensionSpec] = []
    for oid, critical, der in carried:
        text: str | None = None
        codec = _CODECS.get(oid)
        if codec is not None:
            try:
                candidate = codec.describe(typed.get(oid), der, values)
                if candidate is not None:
                    canonical = codec.text(codec.items(candidate))
                    if codec.encode(canonical, values) == der:
                        text = canonical
            except (SpecError, ValueError, TypeError):
                text = None
        if text is not None:
            extensions.append(ExtensionSpec(oid, critical, FORM_TYPED, text))
        else:
            extensions.append(ExtensionSpec(oid, critical, FORM_RAW, der.hex().upper()))
    return CertificateSpec(subject=subject, extensions=tuple(extensions))


# -- the editor's model ----------------------------------------------------------


def to_model(spec: CertificateSpec) -> dict[str, Any]:
    """*spec* as plain data for an editor: attribute rows and extension rows with their items."""
    subject: list[list[dict[str, Any]]] | None = None
    if spec.subject is not None:
        subject = [[{"type": attribute_label(item.oid), "oid": item.oid, "string": item.string_type,
                     "value": item.value.hex().upper() if isinstance(item.value, bytes) else item.value,
                     "hex": isinstance(item.value, bytes)} for item in rdn] for rdn in spec.subject]
    extensions: list[dict[str, Any]] | None = None
    if spec.extensions is not None:
        extensions = []
        for extension in spec.extensions:
            codec = _CODECS.get(extension.oid)
            text = extension.text or EMPTY_VALUE if extension.form == FORM_RAW else extension.text
            row: dict[str, Any] = {"oid": extension.oid, "name": extension.name, "critical": extension.critical,
                                   "form": extension.form, "text": text, "widget": "raw", "items": None}
            if extension.form == FORM_TYPED and codec is not None:
                row["widget"] = codec.widget
                row["items"] = codec.items(extension.text)
            extensions.append(row)
    return {"subject": subject, "extensions": extensions}


def from_model(model: Any) -> CertificateSpec:
    """Read an editor's rows back; the same checks as ``parse_text``, with the row named in a refusal."""
    if not isinstance(model, Mapping):
        raise SpecError("A certificate model is an object with subject and extensions.")
    subject: tuple[tuple[AttributeSpec, ...], ...] | None = None
    if model.get("subject") is not None:
        rdns: list[tuple[AttributeSpec, ...]] = []
        for number, rdn in enumerate(_sequence(model.get("subject")), start=1):
            attributes: list[AttributeSpec] = []
            for entry in _sequence(rdn):
                if not isinstance(entry, Mapping):
                    raise SpecError(f"subject RDN {number}: an attribute is an object.")
                oid = _attribute_oid(str(entry.get("oid") or entry.get("type") or ""))
                member = _string_type(str(entry.get("string") or default_string_type(oid)))
                value: str | bytes = str(entry.get("value", "") if entry.get("value") is not None else "")
                if entry.get("hex") or member in _OCTET_TYPES:
                    if _HEX.match(str(value)) is None and len(str(value)) > 0:
                        raise SpecError(f"subject RDN {number}: {attribute_label(oid)} hex value is not hex.")
                    value = bytes.fromhex(str(value))
                    if member not in _OCTET_TYPES:
                        raise SpecError(f"subject RDN {number}: only a BitString or OctetString value is given in hex.")
                attributes.append(AttributeSpec(oid, string_type_label(member), value))
            if len(attributes) == 0:
                raise SpecError(f"subject RDN {number} has no attribute.")
            rdns.append(tuple(attributes))
        if len(rdns) > MAX_RDNS:
            raise SpecError(f"A subject takes at most {MAX_RDNS} relative distinguished names.")
        subject = tuple(rdns)
        _name(subject, _PROBE)
    extensions: tuple[ExtensionSpec, ...] | None = None
    if model.get("extensions") is not None:
        rows: list[ExtensionSpec] = []
        seen: set[str] = set()
        for number, entry in enumerate(_sequence(model.get("extensions")), start=1):
            if not isinstance(entry, Mapping):
                raise SpecError(f"extension {number}: a row is an object.")
            oid = _extension_oid(str(entry.get("oid") or entry.get("name") or ""))
            where = f"extension {number} ({_EXTENSION_BY_OID[oid].name if oid in _EXTENSION_BY_OID else oid})"
            if oid in seen:
                raise SpecError(f"{where} is given twice; a certificate carries an extension once.")
            seen.add(oid)
            critical = bool(entry.get("critical"))
            if str(entry.get("form") or FORM_TYPED) == FORM_RAW:
                rows.append(ExtensionSpec(oid, critical, FORM_RAW, _raw_value(str(entry.get("text") or ""), where)))
                continue
            codec = _CODECS.get(oid)
            text = str(entry.get("text") or "")
            if codec is not None and entry.get("items") is not None:
                try:
                    text = codec.text(entry.get("items"))
                except SpecError as error:
                    raise SpecError(f"{where}: {error}") from error
            rows.append(ExtensionSpec(oid, critical, FORM_TYPED, _typed(oid, text, where)))
        if len(rows) > MAX_EXTENSIONS:
            raise SpecError(f"At most {MAX_EXTENSIONS} extensions.")
        extensions = tuple(rows)
    return CertificateSpec(subject=subject, extensions=extensions)


def catalogue() -> dict[str, Any]:
    """What an editor offers: attribute types, string types, the extensions and how each one's value is edited."""
    extensions: list[dict[str, Any]] = []
    for info in STANDARD_EXTENSIONS:
        codec = _CODECS.get(info.oid)
        row: dict[str, Any] = {"oid": info.oid, "name": info.name, "heading": info.heading, "clause": info.clause,
                               "widget": "raw", "default": "", "critical": False}
        if codec is not None:
            row.update({"widget": codec.widget, "default": codec.default, "critical": codec.critical,
                        "items": codec.items(codec.default), "choices": list(codec.choices),
                        "kinds": list(codec.kinds), "methods": list(codec.methods)})
        else:
            row["note"] = RAW_ONLY_EXTENSIONS.get(info.name, "")
        extensions.append(row)
    return {
        "attributes": [{"oid": info.oid, "name": info.name, "label": info.short or info.name,
                        "string": default_string_type(info.oid)} for info in NAME_ATTRIBUTES],
        "string_types": [string_type_label(member) for member in _ASN1Type if member not in _OCTET_TYPES
                         and member not in (_ASN1Type.UTCTime, _ASN1Type.GeneralizedTime)],
        "extensions": extensions,
        "placeholders": [PLACEHOLDER_HOST, PLACEHOLDER_EIM_ID],
    }


__all__ = [
    "EMPTY_VALUE", "FORM_RAW", "FORM_TYPED", "PLACEHOLDER_EIM_ID", "PLACEHOLDER_HOST", "RAW_ONLY_EXTENSIONS",
    "UNSUPPORTED_GENERAL_NAMES", "AttributeSpec", "BuildContext", "CertificateSpec", "ExtensionSpec", "ResolvedSpec",
    "SpecError", "add_extensions", "attribute_label", "catalogue", "check_built", "default_string_type", "describe",
    "extension_line", "from_certificate", "from_model", "is_key", "parse_text", "raw_extensions", "resolve",
    "string_type_label", "subject_from_name", "to_model", "to_text", "typed_extension_names",
]
