# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SGP.32 EuiccPackageRequest / EuiccPackageResult helpers.

Implements the wire-level encoding and decoding the eUICC needs for
ES10b.LoadEuiccPackage (SGP.32 v1.2 §5.9.1) and the matching
EuiccPackageResult emission (§2.11.2.1). The IPA-side / eIM-side
transformations of these structures live in :mod:`SCP11.eim_local`;
this module deals strictly with the bytes that cross the eUICC boundary.

Tag map cross-referenced against the spec:

- ``BF51`` ``EuiccPackageRequest [81]`` -- top-level outer tag in the STORE
  DATA payload (§2.11.1.1) and also the outer tag of the
  ``EuiccPackageResult [81]`` CHOICE (§2.11.2.1).
- ``5F37`` ``[APPLICATION 55] OCTET STRING`` -- ``eimSignature`` /
  ``euiccSignEPR`` / ``euiccSignEPE`` raw ECDSA r||s, 64 bytes.
- ``5A``   ``[APPLICATION 26] Octet16`` -- ``eidValue``.
- ``80``   ``[0]`` -- ``eimId`` UTF-8 string.
- ``81``   ``[1]`` -- ``counterValue`` INTEGER (DER, but tolerated as
  unsigned big-endian when produced by other implementations).
- ``82``   ``[2]`` -- optional ``eimTransactionId`` OCTET STRING.
- ``84``   ``[4]`` -- optional ``associationToken`` INTEGER (used for the
  signature payload extension and in the unsigned error result).
- ``A0``   ``[0]`` SEQUENCE OF -- ``psmoList`` alternative of EuiccPackage.
- ``A1``   ``[1]`` SEQUENCE OF -- ``ecoList`` alternative of EuiccPackage.

The simulator deliberately keeps this layer dependency-free of the
``cryptography`` package's high-level X.509 types. Only the public-key
verification path imports ``cryptography``; that path tolerates both a
SubjectPublicKeyInfo and a full ``Certificate`` (X.509) ``eim_public_key_data``
payload as defined by SGP.32 §2.11.1.1.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

from SIMCARD.utils import encode_length, read_tlv, tlv


TAG_EUICC_PACKAGE = bytes.fromhex("BF51")
TAG_EIM_SIGNATURE = bytes.fromhex("5F37")
TAG_EID_VALUE = bytes.fromhex("5A")
TAG_EIM_ID = bytes.fromhex("80")
TAG_COUNTER_VALUE = bytes.fromhex("81")
TAG_TRANSACTION_ID = bytes.fromhex("82")
TAG_ASSOCIATION_TOKEN = bytes.fromhex("84")
TAG_PSMO_LIST = bytes.fromhex("A0")
TAG_ECO_LIST = bytes.fromhex("A1")
TAG_RESULT_SIGNED = bytes.fromhex("A0")
TAG_ERROR_SIGNED = bytes.fromhex("A1")
TAG_ERROR_UNSIGNED = bytes.fromhex("A2")

MAX_COUNTER_VALUE = 0x7FFFFF


@dataclass
class EuiccPackageEnvelope:
    """Decoded ``EuiccPackageRequest`` ready for the eUICC dispatcher."""

    eim_id: str = ""
    eid_value: bytes = b""
    counter_value: int = 0
    eim_transaction_id: bytes = b""
    psmo_items: list[bytes] = field(default_factory=list)
    eco_items: list[bytes] = field(default_factory=list)
    signed_blob: bytes = b""
    eim_signature: bytes = b""
    has_psmo_list: bool = False
    has_eco_list: bool = False


class EuiccPackageDecodeError(Exception):
    pass


def decode_euicc_package_request(payload: bytes) -> EuiccPackageEnvelope:
    """Parse a ``BF51 EuiccPackageRequest`` blob. Strict on tag order.

    The two top-level inner TLVs are required to appear in spec order:
    ``euiccPackageSigned`` (the SEQUENCE) followed by the ``5F37``
    ``eimSignature`` octet string.
    """

    raw = bytes(payload or b"")
    if len(raw) == 0:
        raise EuiccPackageDecodeError("Empty payload.")
    try:
        tag_bytes, value, _raw_outer, _next = read_tlv(raw, 0)
    except ValueError as error:
        raise EuiccPackageDecodeError(f"Outer TLV malformed: {error}") from error
    if tag_bytes != TAG_EUICC_PACKAGE:
        raise EuiccPackageDecodeError(
            f"Outer tag {tag_bytes.hex().upper()} is not EuiccPackageRequest BF51."
        )

    try:
        signed_tag, signed_value, signed_raw, signed_next = read_tlv(value, 0)
    except ValueError as error:
        raise EuiccPackageDecodeError(f"euiccPackageSigned TLV malformed: {error}") from error
    if signed_tag != b"\x30":
        raise EuiccPackageDecodeError(
            f"Inner euiccPackageSigned tag must be 30, got {signed_tag.hex().upper()}."
        )

    try:
        sig_tag, sig_value, _raw_sig, sig_next = read_tlv(value, signed_next)
    except ValueError as error:
        raise EuiccPackageDecodeError(f"eimSignature TLV malformed: {error}") from error
    if sig_tag != TAG_EIM_SIGNATURE:
        raise EuiccPackageDecodeError(
            f"eimSignature tag must be 5F37, got {sig_tag.hex().upper()}."
        )
    if sig_next != len(value):
        raise EuiccPackageDecodeError("Trailing bytes after eimSignature.")
    if len(sig_value) != 64:
        raise EuiccPackageDecodeError(
            f"eimSignature must be 64 raw r||s bytes, got {len(sig_value)}."
        )

    envelope = _decode_euicc_package_signed(signed_value)
    envelope.signed_blob = signed_raw
    envelope.eim_signature = bytes(sig_value)
    return envelope


def _decode_euicc_package_signed(value: bytes) -> EuiccPackageEnvelope:
    envelope = EuiccPackageEnvelope()
    offset = 0
    seen_eim_id = False
    seen_eid = False
    seen_counter = False
    seen_package = False

    while offset < len(value):
        try:
            tag_bytes, inner_value, _raw, next_offset = read_tlv(value, offset)
        except ValueError as error:
            raise EuiccPackageDecodeError(
                f"euiccPackageSigned inner TLV malformed: {error}"
            ) from error

        if tag_bytes == TAG_EIM_ID:
            envelope.eim_id = _decode_utf8(inner_value)
            seen_eim_id = True
        elif tag_bytes == TAG_EID_VALUE:
            if len(inner_value) != 16:
                raise EuiccPackageDecodeError(
                    f"eidValue must be 16 bytes, got {len(inner_value)}."
                )
            envelope.eid_value = bytes(inner_value)
            seen_eid = True
        elif tag_bytes == TAG_COUNTER_VALUE:
            envelope.counter_value = _decode_unsigned_integer(inner_value)
            seen_counter = True
        elif tag_bytes == TAG_TRANSACTION_ID:
            envelope.eim_transaction_id = bytes(inner_value)
        elif tag_bytes == TAG_PSMO_LIST:
            envelope.has_psmo_list = True
            envelope.psmo_items = list(_split_top_level_tlvs(inner_value))
            seen_package = True
        elif tag_bytes == TAG_ECO_LIST:
            envelope.has_eco_list = True
            envelope.eco_items = list(_split_top_level_tlvs(inner_value))
            seen_package = True
        else:
            raise EuiccPackageDecodeError(
                f"Unexpected tag {tag_bytes.hex().upper()} inside euiccPackageSigned."
            )
        offset = next_offset

    missing: list[str] = []
    if seen_eim_id is False:
        missing.append("eimId")
    if seen_eid is False:
        missing.append("eidValue")
    if seen_counter is False:
        missing.append("counterValue")
    if seen_package is False:
        missing.append("euiccPackage")
    if len(missing) > 0:
        raise EuiccPackageDecodeError("Missing required fields: " + ", ".join(missing))
    if envelope.has_psmo_list and envelope.has_eco_list:
        raise EuiccPackageDecodeError(
            "EuiccPackage CHOICE must be either psmoList or ecoList, not both."
        )
    return envelope


def _split_top_level_tlvs(payload: bytes) -> Iterable[bytes]:
    offset = 0
    while offset < len(payload):
        _tag, _value, raw, next_offset = read_tlv(payload, offset)
        yield raw
        offset = next_offset


def _decode_utf8(payload: bytes) -> str:
    try:
        return bytes(payload).decode("utf-8")
    except UnicodeDecodeError as error:
        raise EuiccPackageDecodeError(f"UTF-8 decode failed: {error}") from error


def _decode_unsigned_integer(payload: bytes) -> int:
    """Accept DER INTEGER (with optional leading 00 padding) and unsigned BE."""

    if len(payload) == 0:
        return 0
    return int.from_bytes(bytes(payload), "big", signed=False)


def encode_der_integer(value: int) -> bytes:
    """Minimal DER INTEGER encoding for non-negative values."""

    if value < 0:
        raise ValueError("Negative integers not supported in this codec.")
    if value == 0:
        return b"\x00"
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        return b"\x00" + raw
    return raw


def signature_payload(signed_blob: bytes, association_token: int) -> bytes:
    """Concatenate ``euiccPackageSigned`` || ``associationToken``.

    Per SGP.32 §2.11.1.1: when no association token is configured for the
    eIM, the data object SHALL be ``84 01 00`` for signature material. The
    same convention applies to result-side signatures (§2.11.2.1).
    """

    token_value = max(0, int(association_token))
    token_tlv = tlv(TAG_ASSOCIATION_TOKEN, encode_der_integer(token_value))
    return bytes(signed_blob) + token_tlv


def verify_eim_signature(
    public_key_payload: bytes,
    signed_blob: bytes,
    signature_rs: bytes,
    association_token: int,
) -> bool:
    """Verify the 64-byte raw r||s ECDSA signature with SHA-256.

    Accepts ``public_key_payload`` as either:

    - A SubjectPublicKeyInfo (the raw eIM public key form, §2.11.1.1
      ``eimPublicKey`` choice).
    - A full X.509 Certificate DER (the ``eimCertificate`` choice).
    """

    if len(signature_rs) != 64:
        return False
    try:
        public_key = _load_eim_public_key(public_key_payload)
    except Exception:
        return False
    if isinstance(public_key, ec.EllipticCurvePublicKey) is False:
        return False

    r_value = int.from_bytes(signature_rs[:32], "big")
    s_value = int.from_bytes(signature_rs[32:], "big")
    if r_value <= 0 or s_value <= 0:
        return False
    try:
        signature_der = asym_utils.encode_dss_signature(r_value, s_value)
    except Exception:
        return False
    payload = signature_payload(signed_blob, association_token)
    try:
        public_key.verify(signature_der, payload, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False
    return True


def _load_eim_public_key(payload: bytes):
    raw = bytes(payload or b"")
    if len(raw) == 0:
        raise ValueError("Empty eIM public key data.")
    try:
        certificate = crypto_x509.load_der_x509_certificate(raw)
    except Exception:
        certificate = None
    if certificate is not None:
        return certificate.public_key()
    return serialization.load_der_public_key(raw)


def encode_euicc_package_result_signed(
    eim_id: str,
    counter_value: int,
    seq_number: int,
    euicc_results: Sequence[bytes],
    *,
    eim_transaction_id: bytes = b"",
    private_key: ec.EllipticCurvePrivateKey,
    association_token: int,
) -> tuple[bytes, bytes]:
    """Build a complete ``BF51 euiccPackageResultSigned`` TLV.

    Returns ``(outer_tlv, payload_tlv)`` where ``payload_tlv`` is the
    ``A0 euiccPackageResultSigned`` body that the eUICC stores.
    """

    data_signed = _encode_result_data_signed(
        eim_id=eim_id,
        counter_value=counter_value,
        seq_number=seq_number,
        eim_transaction_id=eim_transaction_id,
        euicc_results=euicc_results,
    )
    signature = _raw_ecdsa_sign(
        private_key=private_key,
        signed_blob=data_signed,
        association_token=association_token,
    )
    result_signed_body = data_signed + tlv(TAG_EIM_SIGNATURE, signature)
    payload_tlv = tlv(TAG_RESULT_SIGNED, result_signed_body)
    outer_tlv = tlv(TAG_EUICC_PACKAGE, payload_tlv)
    return outer_tlv, payload_tlv


def _encode_result_data_signed(
    *,
    eim_id: str,
    counter_value: int,
    seq_number: int,
    eim_transaction_id: bytes,
    euicc_results: Sequence[bytes],
) -> bytes:
    body = b""
    body += tlv(TAG_EIM_ID, eim_id.encode("utf-8"))
    body += tlv(TAG_COUNTER_VALUE, encode_der_integer(int(counter_value)))
    if len(eim_transaction_id) > 0:
        body += tlv(TAG_TRANSACTION_ID, bytes(eim_transaction_id))
    body += tlv(b"\x83", encode_der_integer(int(seq_number)))
    results_blob = b"".join(bytes(item) for item in euicc_results)
    body += tlv(b"\x30", results_blob)
    return tlv(b"\x30", body)


def encode_euicc_package_error_signed(
    eim_id: str,
    counter_value: int,
    error_code: int,
    *,
    eim_transaction_id: bytes = b"",
    private_key: ec.EllipticCurvePrivateKey,
    association_token: int,
) -> bytes:
    """Build ``BF51 euiccPackageErrorSigned``.

    Used for ``invalidEid`` (§2.11.2.1 EuiccPackageErrorCode 3) and
    ``replayError`` / ``counterValueOutOfRange`` (codes 4 / 6) per
    SGP.32 §5.9.1 verification ladder.
    """

    body = b""
    body += tlv(TAG_EIM_ID, eim_id.encode("utf-8"))
    body += tlv(TAG_COUNTER_VALUE, encode_der_integer(int(counter_value)))
    if len(eim_transaction_id) > 0:
        body += tlv(TAG_TRANSACTION_ID, bytes(eim_transaction_id))
    body += tlv(b"\x02", encode_der_integer(int(error_code) & 0xFF))
    error_data_signed = tlv(b"\x30", body)
    signature = _raw_ecdsa_sign(
        private_key=private_key,
        signed_blob=error_data_signed,
        association_token=association_token,
    )
    error_signed_body = error_data_signed + tlv(TAG_EIM_SIGNATURE, signature)
    return tlv(TAG_EUICC_PACKAGE, tlv(TAG_ERROR_SIGNED, error_signed_body))


def encode_euicc_package_error_unsigned(
    eim_id: str,
    *,
    eim_transaction_id: bytes = b"",
    association_token: int | None = None,
) -> bytes:
    """Build ``BF51 euiccPackageErrorUnsigned``.

    Per SGP.32 §5.9.1 this variant is returned when the eIM is unknown or
    the signature does not verify. ``associationToken`` is only included
    when one is configured for the targeted eIM (§5.9.1 paragraph 3).
    """

    body = b""
    body += tlv(TAG_EIM_ID, str(eim_id or "").encode("utf-8"))
    if len(eim_transaction_id) > 0:
        body += tlv(TAG_TRANSACTION_ID, bytes(eim_transaction_id))
    if association_token is not None:
        body += tlv(TAG_ASSOCIATION_TOKEN, encode_der_integer(int(association_token)))
    return tlv(TAG_EUICC_PACKAGE, tlv(TAG_ERROR_UNSIGNED, body))


def _raw_ecdsa_sign(
    *,
    private_key: ec.EllipticCurvePrivateKey,
    signed_blob: bytes,
    association_token: int,
) -> bytes:
    payload = signature_payload(signed_blob, association_token)
    der_signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r_value, s_value = asym_utils.decode_dss_signature(der_signature)
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def package_result_seq_number(payload_tlv: bytes) -> int:
    """Recover the ``seqNumber [3]`` from a stored ``A0`` result body."""

    try:
        _outer_tag, outer_value, _raw, _next = read_tlv(payload_tlv, 0)
    except ValueError:
        return 0
    try:
        _data_tag, data_value, _data_raw, _data_next = read_tlv(outer_value, 0)
    except ValueError:
        return 0
    offset = 0
    while offset < len(data_value):
        try:
            tag_bytes, value, _value_raw, next_offset = read_tlv(data_value, offset)
        except ValueError:
            return 0
        if tag_bytes == b"\x83":
            return _decode_unsigned_integer(value)
        offset = next_offset
    return 0


def encoded_length(value: int) -> bytes:
    """Public re-export for callers that build TLV chains around helpers."""

    return encode_length(value)
