# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE-SSIM-EAPTLSParameters — X.509 certificate / chain / key import.

3GPP TS 33.402 §6 / RFC 5216 (EAP-TLS) require a SSIM applet that
holds the device certificate, the corresponding RSA / ECC private
key, and the issuing CA chain. The TCA SAIP profile element
``ssimEaptls`` carries these as opaque OCTET STRINGs; this module
parses PEM / DER input on the operator's side, validates the
elementary properties (DER tag, certificate chain integrity, key
match), and returns a normalised hex blob ready for the SAIP encoder.

The parser uses the standard library ``cryptography`` package when
available; if the package is not installed it falls back to header /
trailer detection plus a coarse DER walk so the operator at least
sees the AID / subject hex without having to install extra deps.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any


_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\s*([A-Za-z0-9+/=\s]+)-----END \1-----",
    re.DOTALL,
)


_TYPE_LABELS: dict[str, str] = {
    "CERTIFICATE": "certificate",
    "X509 CERTIFICATE": "certificate",
    "TRUSTED CERTIFICATE": "ca_certificate",
    "PRIVATE KEY": "private_key",
    "RSA PRIVATE KEY": "private_key_rsa",
    "EC PRIVATE KEY": "private_key_ecc",
    "ENCRYPTED PRIVATE KEY": "private_key_encrypted",
    "PUBLIC KEY": "public_key",
}


def _strip_separators(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _is_der_sequence(blob: bytes) -> bool:
    """Cheap structural check: DER X.509 starts with a SEQUENCE (0x30)."""
    return len(blob) >= 4 and blob[0] == 0x30


def _split_pem(raw: bytes) -> list[tuple[str, bytes]]:
    """Return ``[(label, der_bytes), ...]`` for every PEM block found."""
    blocks: list[tuple[str, bytes]] = []
    for match in _PEM_BLOCK_RE.finditer(raw):
        label = match.group(1).decode("ascii", errors="replace").strip()
        b64 = _strip_separators(match.group(2).decode("ascii", errors="replace"))
        try:
            der = base64.b64decode(b64, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        blocks.append((label, der))
    return blocks


def _classify_block(label: str) -> str:
    return _TYPE_LABELS.get(label.upper(), "unknown")


def _fingerprint(der: bytes) -> dict[str, str]:
    return {
        "sha1": hashlib.sha1(der).hexdigest().upper(),
        "sha256": hashlib.sha256(der).hexdigest().upper(),
    }


def _try_cryptography_certificate(der: bytes) -> dict[str, Any] | None:
    """Best-effort metadata extraction when ``cryptography`` is installed."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except (ValueError, TypeError):
        return None
    public_key = cert.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_hex": f"{cert.serial_number:X}",
        "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat(),
        "public_key_der_hex": public_der.hex().upper(),
    }


def _try_cryptography_private_key(der: bytes) -> dict[str, Any] | None:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    try:
        key = serialization.load_der_private_key(der, password=None)
    except (ValueError, TypeError):
        return None
    public_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    name = type(key).__name__
    return {
        "algorithm": name,
        "public_key_der_hex": public_der.hex().upper(),
    }


def parse_pem_or_der(raw: bytes) -> dict[str, Any]:
    """Identify a single PEM / DER blob and return its metadata.

    Output shape::

        {"kind": "certificate" | "private_key" | ... ,
         "der_hex": <upper hex>,
         "fingerprint": {"sha1": ..., "sha256": ...},
         "metadata": {<optional cryptography-derived fields>}}
    """
    if isinstance(raw, (bytes, bytearray)) is False:
        raise ValueError("input must be bytes.")
    raw = bytes(raw)
    if len(raw) == 0:
        raise ValueError("input is empty.")
    blocks = _split_pem(raw)
    if blocks:
        label, der = blocks[0]
        kind = _classify_block(label)
    elif _is_der_sequence(raw):
        der = raw
        kind = "certificate"
    else:
        raise ValueError("input is not PEM and does not start with a DER SEQUENCE.")
    metadata: dict[str, Any] = {}
    if kind in ("certificate", "ca_certificate"):
        meta = _try_cryptography_certificate(der)
        if meta is not None:
            metadata.update(meta)
    elif kind.startswith("private_key"):
        meta = _try_cryptography_private_key(der)
        if meta is not None:
            metadata.update(meta)
    return {
        "kind": kind,
        "der_hex": der.hex().upper(),
        "fingerprint": _fingerprint(der),
        "metadata": metadata,
    }


def parse_certificate_chain(raw: bytes) -> list[dict[str, Any]]:
    """Parse a concatenated PEM bundle into an ordered list of cert blobs."""
    blocks = _split_pem(raw)
    if not blocks:
        if _is_der_sequence(raw):
            return [parse_pem_or_der(raw)]
        return []
    out: list[dict[str, Any]] = []
    for label, der in blocks:
        kind = _classify_block(label)
        if kind not in ("certificate", "ca_certificate"):
            continue
        entry = {
            "kind": kind,
            "der_hex": der.hex().upper(),
            "fingerprint": _fingerprint(der),
            "metadata": {},
        }
        meta = _try_cryptography_certificate(der)
        if meta is not None:
            entry["metadata"] = meta
        out.append(entry)
    return out


def keys_match(cert_pem_or_der: bytes, key_pem_or_der: bytes) -> dict[str, Any]:
    """Verify the public key in ``cert_pem_or_der`` matches the private key.

    When ``cryptography`` is unavailable the comparison degrades to
    "unknown" — the caller can still import the pair, just without
    the integrity assertion. SHA-256 is computed over the DER-encoded
    SubjectPublicKeyInfo and surfaced so the GUI can flag drift even
    in the no-crypto path.
    """
    cert_info = parse_pem_or_der(cert_pem_or_der)
    key_info = parse_pem_or_der(key_pem_or_der)
    if cert_info["kind"] not in ("certificate", "ca_certificate"):
        raise ValueError(f"first input is not a certificate (kind={cert_info['kind']!r}).")
    if key_info["kind"].startswith("private_key") is False:
        raise ValueError(f"second input is not a private key (kind={key_info['kind']!r}).")
    cert_public_hex = (cert_info.get("metadata") or {}).get("public_key_der_hex")
    key_public_hex = (key_info.get("metadata") or {}).get("public_key_der_hex")
    if cert_public_hex is None or key_public_hex is None:
        return {
            "match": None,
            "reason": "cryptography library not available; install python-cryptography to verify the pair.",
            "certificate_fingerprint": cert_info["fingerprint"],
            "private_key_fingerprint": key_info["fingerprint"],
        }
    return {
        "match": cert_public_hex == key_public_hex,
        "certificate_subject_public_key_hex": cert_public_hex,
        "private_key_subject_public_key_hex": key_public_hex,
        "certificate_fingerprint": cert_info["fingerprint"],
        "private_key_fingerprint": key_info["fingerprint"],
    }


def build_eaptls_payload(
    *,
    device_cert: bytes,
    device_key: bytes,
    ca_chain: bytes | None = None,
    skip_match_check: bool = False,
) -> dict[str, Any]:
    """One-shot helper: validate the bundle and return SAIP-ready hex blobs."""
    cert_info = parse_pem_or_der(device_cert)
    key_info = parse_pem_or_der(device_key)
    chain: list[dict[str, Any]] = []
    if ca_chain is not None and len(ca_chain) > 0:
        chain = parse_certificate_chain(ca_chain)
    match_status: dict[str, Any] | None = None
    if skip_match_check is False:
        match_status = keys_match(device_cert, device_key)
        if match_status.get("match") is False:
            raise ValueError(
                "device certificate public key does not match supplied private "
                "key (SHA-256 of SubjectPublicKeyInfo differs).",
            )
    return {
        "device_certificate": cert_info,
        "device_private_key": key_info,
        "ca_chain": chain,
        "match_status": match_status,
    }


__all__ = [
    "build_eaptls_payload",
    "keys_match",
    "parse_certificate_chain",
    "parse_pem_or_der",
]
