# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Typed constructors for SGP.32 PSMOs and eIM Configuration Operations.

The eIM package templates used to carry PSMO and eCO payloads as opaque
``value_hex``, which meant an operator had to hand-assemble DER and the
package lint could only check that the list was non-empty. These builders
produce the same bytes from named fields, so the lint has typed values to
validate and the shell can offer the operations by name.

Tag assignments follow SGP.32 v1.2 §2.11.1.1 (PSMO) and §2.11.2.1 (eCO),
and match what ``SIMCARD/sgp.py`` accepts on the execute side:

    PSMO                        command tag
    enable                      A3
    disable                     A4
    delete                      A5
    listProfileInfo             BF2D
    getRAT                      A6
    configureImmediateEnable    A7
    setFallbackAttribute        A8
    unsetFallbackAttribute      A9
    setDefaultDpAddress         BF65

    eCO                         command tag
    addEim                      A8
    deleteEim                   A9
    updateEim                   AA
    listEim                     AB

This module deliberately carries its own minimal DER helpers rather than
importing from ``SIMCARD``; the eIM side has no other dependency on the
card simulator and keeping it that way lets the package tooling run
without the simulator present.
"""

from __future__ import annotations

from typing import Any
from collections.abc import Iterable

from cryptography import x509 as crypto_x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from SCP11.shared.ber_tlv import retag_sequence
from SCP11.shared.iccid import encode_ef_iccid

__all__ = [
    "PsmoBuildError",
    "build_psmo",
    "build_eco",
    "PSMO_OPERATIONS",
    "ECO_OPERATIONS",
    "encode_iccid_bcd",
]


class PsmoBuildError(ValueError):
    """Raised when a typed PSMO / eCO cannot be encoded as specified."""


# --- minimal DER helpers -------------------------------------------------


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise PsmoBuildError("TLV length cannot be negative.")
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(body) > 4:
        raise PsmoBuildError("TLV length exceeds the four-octet long form.")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: bytes | str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag) if isinstance(tag, str) else bytes(tag)
    payload = bytes(value or b"")
    return tag_bytes + _encode_length(len(payload)) + payload


def _der_integer(value: int) -> bytes:
    """Minimal-length two's-complement INTEGER contents octets."""
    number = int(value)
    width = 1
    while True:
        try:
            return number.to_bytes(width, "big", signed=True)
        except OverflowError:
            width += 1


def _utf8(text: str) -> bytes:
    return str(text or "").encode("utf-8")


def encode_iccid_bcd(digits: str) -> bytes:
    """Pack an ICCID as the ten EF_ICCID octets (ETSI TS 102 221 v18.4 section 13.2).

    ``Iccid`` is ``[APPLICATION 26] OCTET STRING (SIZE(10))`` in SGP.22 v3.1, so
    a shorter ICCID is padded with 'F' nibbles up to the fixed size.
    """
    try:
        return encode_ef_iccid(digits)
    except ValueError as error:
        raise PsmoBuildError(str(error)) from error


def _base128(value: int) -> bytes:
    """Encode one OID subidentifier in base-128, ISO/IEC 8825-1 8.19.2."""
    chunk = bytearray([value & 0x7F])
    remainder = value >> 7
    while remainder > 0:
        chunk.insert(0, (remainder & 0x7F) | 0x80)
        remainder >>= 7
    return bytes(chunk)


def _encode_oid(dotted: str) -> bytes:
    """Encode a dotted OID as an ASN.1 OBJECT IDENTIFIER body.

    ISO/IEC 8825-1 8.19.4: the first two arcs combine into a single
    subidentifier ``arc0 * 40 + arc1``, which is then base-128 encoded
    like any other. Arcs under 2.x are unbounded, so the combined value
    routinely exceeds one octet (2.999.x gives 1079).
    """
    parts = [segment for segment in str(dotted or "").split(".") if len(segment) > 0]
    if len(parts) < 2:
        raise PsmoBuildError(f"OID {dotted!r} needs at least two components.")
    try:
        components = [int(segment) for segment in parts]
    except ValueError as error:
        raise PsmoBuildError(f"OID {dotted!r} has a non-numeric component.") from error
    if any(component < 0 for component in components):
        raise PsmoBuildError(f"OID {dotted!r} has a negative component.")
    if components[0] > 2:
        raise PsmoBuildError(f"OID {dotted!r} has a leading arc above 2.")
    if components[0] < 2 and components[1] > 39:
        raise PsmoBuildError(f"OID {dotted!r} has a second arc above 39 under arc {components[0]}.")
    body = bytearray(_base128(components[0] * 40 + components[1]))
    for component in components[2:]:
        body.extend(_base128(component))
    return bytes(body)


def _encode_key_material_choice(hex_value: str, field_name: str) -> bytes:
    """Encode the eimPublicKeyData / trustedPublicKeyDataTls CHOICE contents.

    Both CHOICEs offer an untagged SubjectPublicKeyInfo and an untagged
    Certificate (SGP.32 v1.3 EimConfigurationData), so automatic tagging carries
    the key as ``A0`` and the certificate as ``A1``, each replacing the DER
    SEQUENCE tag of the material the operator supplied.
    """
    try:
        der = bytes.fromhex(hex_value)
    except ValueError as error:
        raise PsmoBuildError(f"{field_name} is not valid hex.") from error
    try:
        crypto_x509.load_der_x509_certificate(der)
    except ValueError:
        is_certificate = False
    else:
        is_certificate = True
    if is_certificate is False:
        try:
            serialization.load_der_public_key(der)
        except (ValueError, TypeError, UnsupportedAlgorithm) as error:
            raise PsmoBuildError(
                f"{field_name} is neither a DER Certificate nor a DER SubjectPublicKeyInfo."
            ) from error
    try:
        return retag_sequence(b"\xA1" if is_certificate else b"\xA0", der)
    except ValueError as error:
        raise PsmoBuildError(f"{field_name}: {error}") from error


def _profile_reference(spec: dict[str, Any]) -> bytes:
    """Encode the ``iccid [APPLICATION 26]`` selector shared by several PSMOs.

    SGP.32 v1.3 Psmo enable, disable, delete and setFallbackAttribute carry an
    ICCID only; an ISD-P AID is not a PSMO selector.
    """
    aid = str(spec.get("aid") or "").strip()
    iccid = str(spec.get("iccid") or "").strip()
    if len(aid) > 0:
        raise PsmoBuildError("PSMOs select a Profile by ICCID only; 'aid' is not an SGP.32 selector.")
    if len(iccid) > 0:
        return _tlv("5A", encode_iccid_bcd(iccid))
    raise PsmoBuildError("A profile reference needs 'iccid'.")


# --- PSMO builders -------------------------------------------------------


def _psmo_enable(spec: dict[str, Any]) -> bytes:
    body = _profile_reference(spec)
    if bool(spec.get("rollback", False)) is True:
        # enable ::= SEQUENCE { iccid [APPLICATION 26] Iccid, rollbackFlag NULL
        # OPTIONAL }. SGP32Definitions is AUTOMATIC TAGS, but X.680 §12.3
        # withholds automatic tagging from a component list that already tags a
        # component -- and iccid does, which is why it goes out as '5A' rather
        # than the '80' an auto-tagged [0] would give. rollbackFlag is untagged
        # in that same list, so it keeps the universal NULL tag '05'.
        body += _tlv("05", b"")
    return _tlv("A3", body)


def _psmo_disable(spec: dict[str, Any]) -> bytes:
    return _tlv("A4", _profile_reference(spec))


def _psmo_delete(spec: dict[str, Any]) -> bytes:
    return _tlv("A5", _profile_reference(spec))


def _psmo_list_profile_info(spec: dict[str, Any]) -> bytes:
    # An empty search criteria selects every profile.
    return _tlv("BF2D", b"")


def _psmo_get_rat(spec: dict[str, Any]) -> bytes:
    return _tlv("A6", b"")


def _psmo_configure_immediate_enable(spec: dict[str, Any]) -> bytes:
    body = b""
    if bool(spec.get("immediate_enable_flag", False)) is True:
        body += _tlv("80", b"")
    oid = str(spec.get("default_smdp_oid") or "").strip()
    if len(oid) > 0:
        body += _tlv("81", _encode_oid(oid))
    address = str(spec.get("default_smdp_address") or "").strip()
    if len(address) > 0:
        body += _tlv("82", _utf8(address))
    return _tlv("A7", body)


def _psmo_set_fallback_attribute(spec: dict[str, Any]) -> bytes:
    return _tlv("A8", _profile_reference(spec))


def _psmo_unset_fallback_attribute(spec: dict[str, Any]) -> bytes:
    return _tlv("A9", b"")


def _psmo_set_default_dp_address(spec: dict[str, Any]) -> bytes:
    address = str(spec.get("default_dp_address") or "").strip()
    if len(address) == 0:
        raise PsmoBuildError("setDefaultDpAddress needs 'default_dp_address'.")
    if len(address) > 128:
        raise PsmoBuildError("setDefaultDpAddress address cannot exceed 128 characters.")
    return _tlv("BF65", _tlv("80", _utf8(address)))


PSMO_OPERATIONS: dict[str, Any] = {
    "enable": _psmo_enable,
    "disable": _psmo_disable,
    "delete": _psmo_delete,
    "list_profile_info": _psmo_list_profile_info,
    "get_rat": _psmo_get_rat,
    "configure_immediate_enable": _psmo_configure_immediate_enable,
    "set_fallback_attribute": _psmo_set_fallback_attribute,
    "unset_fallback_attribute": _psmo_unset_fallback_attribute,
    "set_default_dp_address": _psmo_set_default_dp_address,
}


# --- eIM configuration rows and eCO builders -----------------------------

# EimSupportedProtocol ::= BIT STRING { eimRetrieveHttps(0), eimRetrieveCoaps(1),
# eimInjectHttps(2), eimInjectCoaps(3), eimProprietary(4) } (SGP.32 §2.11.1).
# Retrieval takes bits 0 and 1, injection bits 2 and 3 -- the two transports do
# not alternate. Bits 1 and 2 were transposed here, so a row asking for CoAPS
# retrieval encoded HTTPS injection, which is what the decoders in
# ``SCP03/logic/sgp32_decode.py`` and ``Tools/Asn1TlvDecode`` then read back.
SUPPORTED_PROTOCOL_BITS: dict[str, int] = {
    "https_over_tcp_retrieval": 0,
    "coap_dtls_over_udp_retrieval": 1,
    "https_over_tcp_injection": 2,
    "coap_dtls_over_udp_injection": 3,
    "proprietary": 4,
}


def _encode_named_bit_string(names: Iterable[str]) -> bytes:
    positions: list[int] = []
    for name in names:
        key = str(name or "").strip().lower()
        if key not in SUPPORTED_PROTOCOL_BITS:
            raise PsmoBuildError(f"Unknown supported protocol {name!r}.")
        positions.append(SUPPORTED_PROTOCOL_BITS[key])
    if len(positions) == 0:
        return b"\x00"
    width = max(positions) // 8 + 1
    bits = bytearray(width)
    for position in positions:
        bits[position // 8] |= 0x80 >> (position % 8)
    unused = (width * 8) - (max(positions) + 1)
    return bytes([unused]) + bytes(bits)


def _eim_configuration_row(spec: dict[str, Any]) -> bytes:
    eim_id = str(spec.get("eim_id") or "").strip()
    if len(eim_id) == 0:
        raise PsmoBuildError("An eIM configuration row needs 'eim_id'.")
    row = _tlv("80", _utf8(eim_id))
    fqdn = str(spec.get("eim_fqdn") or "").strip()
    if len(fqdn) > 0:
        row += _tlv("81", _utf8(fqdn))
    if spec.get("eim_id_type") is not None:
        row += _tlv("82", _der_integer(int(spec["eim_id_type"])))
    if spec.get("counter_value") is not None:
        row += _tlv("83", _der_integer(int(spec["counter_value"])))
    if spec.get("association_token") is not None:
        row += _tlv("84", _der_integer(int(spec["association_token"])))
    protocols = spec.get("supported_protocols")
    if protocols:
        row += _tlv("87", _encode_named_bit_string(protocols))
    ci_pkid = str(spec.get("euicc_ci_pkid") or "").strip()
    if len(ci_pkid) > 0:
        try:
            row += _tlv("88", bytes.fromhex(ci_pkid))
        except ValueError as error:
            raise PsmoBuildError(f"euicc_ci_pkid {ci_pkid!r} is not valid hex.") from error
    if bool(spec.get("indirect_profile_download", False)) is True:
        row += _tlv("89", b"")
    public_key = str(spec.get("eim_public_key_data") or "").strip()
    if len(public_key) > 0:
        row += _tlv("A5", _encode_key_material_choice(public_key, "eim_public_key_data"))
    tls_key = str(spec.get("trusted_tls_public_key_data") or "").strip()
    if len(tls_key) > 0:
        row += _tlv("A6", _encode_key_material_choice(tls_key, "trusted_tls_public_key_data"))
    return row


def _eco_add_eim(spec: dict[str, Any]) -> bytes:
    return _tlv("A8", _eim_configuration_row(spec))


def _eco_delete_eim(spec: dict[str, Any]) -> bytes:
    eim_id = str(spec.get("eim_id") or "").strip()
    if len(eim_id) == 0:
        raise PsmoBuildError("deleteEim needs 'eim_id'.")
    return _tlv("A9", _tlv("80", _utf8(eim_id)))


def _eco_update_eim(spec: dict[str, Any]) -> bytes:
    return _tlv("AA", _eim_configuration_row(spec))


def _eco_list_eim(spec: dict[str, Any]) -> bytes:
    return _tlv("AB", b"")


ECO_OPERATIONS: dict[str, Any] = {
    "add_eim": _eco_add_eim,
    "delete_eim": _eco_delete_eim,
    "update_eim": _eco_update_eim,
    "list_eim": _eco_list_eim,
}


def _build(table: dict[str, Any], spec: dict[str, Any], *, kind: str) -> bytes:
    if not isinstance(spec, dict):
        raise PsmoBuildError(f"{kind} entry must be a mapping, got {type(spec).__name__}.")
    operation = str(spec.get("operation") or "").strip().lower()
    if len(operation) == 0:
        raise PsmoBuildError(f"{kind} entry needs an 'operation' field.")
    builder = table.get(operation)
    if builder is None:
        known = ", ".join(sorted(table))
        raise PsmoBuildError(f"Unknown {kind} operation {operation!r}. Known: {known}.")
    return builder(spec)


def build_psmo(spec: dict[str, Any]) -> bytes:
    """Encode one typed PSMO entry as its SGP.32 command TLV."""
    return _build(PSMO_OPERATIONS, spec, kind="PSMO")


def build_eco(spec: dict[str, Any]) -> bytes:
    """Encode one typed eIM Configuration Operation as its command TLV."""
    return _build(ECO_OPERATIONS, spec, kind="eCO")
