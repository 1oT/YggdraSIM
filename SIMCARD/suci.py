# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SUPI / SUCI handling per TS 33.501 §6.12 + Annex C and TS 24.501 §9.11.3.4.

Coverage in this module:

* :class:`ProtectionScheme` -- enumeration of the three SUCI scheme
  identifiers (null, Profile A / X25519, Profile B / secp256r1).
* :class:`HomeNetworkPublicKey` and :class:`SuciCalcInfo` -- runtime
  shape of EF.SUCI_Calc_Info (TS 31.102 §4.4.11.8).
* :func:`encode_ef_suci_calc_info` / :func:`decode_ef_suci_calc_info`
  -- byte layout of that EF.
* :func:`encode_msin_bcd` / :func:`decode_msin_bcd` -- shared MSIN
  packing for both null and protected SUCIs.
* :func:`x963_kdf_sha256` -- ANSI-X9.63 KDF used by both Profile A
  and Profile B (TS 33.501 §C.3.2).
* :func:`compute_scheme_output` -- top-level dispatcher that takes an
  MSIN string, an MNC length, and an optional :class:`HomeNetworkPublicKey`
  and returns the SUCI Scheme Output bytes.
* :func:`encode_suci_mobile_identity` -- byte layout of the SUCI
  Mobile Identity IE per TS 24.501 §9.11.3.4.
* :func:`build_suci_from_imsi` -- one-shot helper used by
  ``GET IDENTITY`` and the test bench: takes IMSI + serving-network
  context and returns the full mobile-identity bytes ready to ship
  in a NAS Identity Response.

The Profile A / Profile B encryption paths use the project's existing
``cryptography`` dependency. Profile A uses raw X25519; Profile B uses
secp256r1 with point compression. Both use AES-128-CTR for the MSIN
ciphertext and HMAC-SHA-256 truncated to 64 bits for the integrity tag,
matching TS 33.501 Annex C.3.4.

A note on randomness: ``compute_scheme_output`` and
``build_suci_from_imsi`` take an optional ``ephemeral_private_key``
argument so the caller can pin determinism for testing. Production
callers leave it ``None`` and the helper allocates a fresh ephemeral
keypair via the ``cryptography`` library's CSPRNG, exactly as required
by TS 33.501 (a fresh ephemeral key per SUCI computation).
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import sha256
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


class ProtectionScheme(IntEnum):
    """SUCI Protection Scheme identifiers per TS 33.501 §6.12.2."""

    NULL = 0x00
    PROFILE_A = 0x01  # X25519 (Curve25519) ECIES
    PROFILE_B = 0x02  # secp256r1 (NIST P-256) ECIES


@dataclass
class HomeNetworkPublicKey:
    """A single home-network public-key entry from EF.SUCI_Calc_Info.

    ``key_identifier`` is the 1-byte HN-public-key identifier carried
    in the SUCI on the wire. ``protection_scheme`` selects the ECIES
    profile; ``public_key`` is the raw key octet string that the
    KDF feeds as ``SharedInfo`` -- 32 bytes for Profile A (X25519
    public key) or 33 bytes for Profile B (compressed secp256r1
    point).
    """

    key_identifier: int
    protection_scheme: ProtectionScheme
    public_key: bytes


@dataclass
class SuciCalcInfo:
    """Decoded EF.SUCI_Calc_Info image (TS 31.102 §4.4.11.8).

    ``priority_list`` is an ordered list of (priority, scheme_id,
    key_identifier) triples; the ME walks it top-down picking the
    first scheme/key it can handle. ``public_keys`` is the catalogue
    of HN public keys referenced from the priority list.
    """

    priority_list: list[tuple[int, ProtectionScheme, int]] = field(default_factory=list)
    public_keys: list[HomeNetworkPublicKey] = field(default_factory=list)


# ---------------------------------------------------------------------------
# EF.SUCI_Calc_Info encode / decode
# ---------------------------------------------------------------------------


def encode_ef_suci_calc_info(info: SuciCalcInfo) -> bytes:
    """Serialise a :class:`SuciCalcInfo` to the on-card byte image.

    Layout (TS 31.102 §4.4.11.8):
        Length-of-priority-list (1 byte) ||
            { priority(1) | scheme_id(1) | key_id(1) } * N ||
        Length-of-public-key-list (1 byte) ||
            { key_id(1) | key_len(2 BE) | key(key_len) } * M

    The TS specifies the priority-list length as the *number of bytes*
    occupied by the list (always ``3 * N``); we honour that to stay
    bit-compatible with the SAIP profiles already in the field.
    """
    priority_count = len(info.priority_list)
    if priority_count > 0xFFFF // 3:
        raise ValueError("Priority list too long to encode in 16-bit length.")
    priority_bytes = bytearray()
    for priority, scheme, key_identifier in info.priority_list:
        if priority < 0 or priority > 0xFF:
            raise ValueError("Priority must fit in a single byte.")
        if key_identifier < 0 or key_identifier > 0xFF:
            raise ValueError("Key identifier must fit in a single byte.")
        priority_bytes.append(int(priority) & 0xFF)
        priority_bytes.append(int(scheme) & 0xFF)
        priority_bytes.append(int(key_identifier) & 0xFF)
    public_bytes = bytearray()
    for key in info.public_keys:
        material = bytes(key.public_key or b"")
        if len(material) > 0xFFFF:
            raise ValueError("Home-network public key too long.")
        if key.key_identifier < 0 or key.key_identifier > 0xFF:
            raise ValueError("Key identifier must fit in a single byte.")
        public_bytes.append(int(key.key_identifier) & 0xFF)
        public_bytes.extend(len(material).to_bytes(2, "big"))
        public_bytes.extend(material)
    if len(priority_bytes) > 0xFF or len(public_bytes) > 0xFF:
        # TS 31.102 §4.4.11.8 leaves the outer lengths as 1 byte each.
        # Anything bigger is a profile-image error caught early so we
        # don't emit a spec-noncompliant EF on disk.
        raise ValueError("EF.SUCI_Calc_Info section length exceeds 8 bits.")
    out = bytearray()
    out.append(len(priority_bytes) & 0xFF)
    out.extend(priority_bytes)
    out.append(len(public_bytes) & 0xFF)
    out.extend(public_bytes)
    return bytes(out)


def decode_ef_suci_calc_info(data: bytes) -> SuciCalcInfo:
    """Inverse of :func:`encode_ef_suci_calc_info`.

    Returns an empty :class:`SuciCalcInfo` for empty / malformed input
    so the caller can keep going (a freshly-personalised eSIM may have
    not yet been told about home-network keys).
    """
    raw = bytes(data or b"")
    info = SuciCalcInfo()
    if len(raw) < 1:
        return info
    cursor = 0
    priority_length = raw[cursor]
    cursor += 1
    priority_end = cursor + priority_length
    if priority_end > len(raw):
        return info
    while cursor + 3 <= priority_end:
        priority = raw[cursor]
        scheme = raw[cursor + 1]
        key_identifier = raw[cursor + 2]
        cursor += 3
        try:
            scheme_enum = ProtectionScheme(scheme)
        except ValueError:
            continue
        info.priority_list.append((priority, scheme_enum, key_identifier))
    cursor = priority_end
    if cursor >= len(raw):
        return info
    public_length = raw[cursor]
    cursor += 1
    public_end = cursor + public_length
    if public_end > len(raw):
        return info
    while cursor + 3 <= public_end:
        key_identifier = raw[cursor]
        key_len = int.from_bytes(raw[cursor + 1 : cursor + 3], "big")
        cursor += 3
        if cursor + key_len > public_end:
            break
        material = bytes(raw[cursor : cursor + key_len])
        cursor += key_len
        # Pair the public-key with the first priority-list entry
        # that points at it; this is the lookup the ME does at
        # SUCI-build time. We default the scheme to NULL when there
        # is no matching priority entry so the caller still sees the
        # raw key bytes.
        scheme = ProtectionScheme.NULL
        for _, candidate_scheme, candidate_id in info.priority_list:
            if candidate_id == key_identifier:
                scheme = candidate_scheme
                break
        info.public_keys.append(
            HomeNetworkPublicKey(
                key_identifier=key_identifier,
                protection_scheme=scheme,
                public_key=material,
            )
        )
    return info


# ---------------------------------------------------------------------------
# MSIN / MCC / MNC BCD encoding helpers
# ---------------------------------------------------------------------------


def split_imsi(imsi: str, mnc_length: int) -> tuple[str, str, str]:
    """Split an IMSI string into ``(mcc, mnc, msin)``.

    ``mnc_length`` is the configured MNC length (2 or 3) per
    EF.AD octet 4 (TS 31.102 §4.2.18). The simulator already
    normalises this elsewhere; we re-validate here so a bogus
    profile cannot produce a malformed SUCI.
    """
    digits = "".join(ch for ch in str(imsi or "").strip() if ch.isdigit())
    if len(digits) < 6 or len(digits) > 15:
        raise ValueError("IMSI must be 6..15 digits.")
    mnc_len = int(mnc_length)
    if mnc_len not in (2, 3):
        raise ValueError("MNC length must be 2 or 3 (TS 31.102 §4.2.18).")
    mcc = digits[:3]
    mnc = digits[3 : 3 + mnc_len]
    msin = digits[3 + mnc_len :]
    if len(msin) == 0:
        raise ValueError("IMSI did not contain an MSIN portion.")
    return mcc, mnc, msin


def encode_msin_bcd(msin: str) -> bytes:
    """Pack a decimal-digit MSIN string into BCD per TS 23.003.

    Each pair of digits becomes one byte with the **first** digit in
    the low nibble and the **second** digit in the high nibble. An
    odd-length MSIN gets a 0xF padding nibble in the final high
    position. This matches the MSIN field both in the null-scheme
    SUCI Scheme Output and in the EF.IMSI body.
    """
    digits = str(msin or "").strip()
    if len(digits) == 0 or digits.isdigit() is False:
        raise ValueError("MSIN must be non-empty decimal digits.")
    if len(digits) % 2 == 1:
        digits = digits + "F"
    out = bytearray()
    for index in range(0, len(digits), 2):
        low = digits[index]
        high = digits[index + 1]
        low_nibble = int(low, 16)
        high_nibble = int(high, 16) if high != "F" else 0xF
        out.append((high_nibble << 4) | low_nibble)
    return bytes(out)


def decode_msin_bcd(data: bytes) -> str:
    """Inverse of :func:`encode_msin_bcd`.

    Stops at the first 0xF nibble so an odd-length MSIN round-trips
    cleanly.
    """
    digits: list[str] = []
    for byte in bytes(data or b""):
        low = byte & 0x0F
        high = (byte >> 4) & 0x0F
        if low == 0xF:
            break
        digits.append(str(low))
        if high == 0xF:
            break
        digits.append(str(high))
    return "".join(digits)


def _pack_mcc_mnc(mcc: str, mnc: str) -> bytes:
    """Pack MCC + MNC into the 3-byte form used in the SUCI IE.

    The encoding follows TS 24.501 §9.11.3.4 / TS 24.008 §10.5.1.3:

        Octet 2: MCC digit 2 (high nibble) | MCC digit 1 (low nibble)
        Octet 3: MNC digit 3 (high nibble) | MCC digit 3 (low nibble)
        Octet 4: MNC digit 2 (high nibble) | MNC digit 1 (low nibble)

    A 2-digit MNC pads the third digit with 0xF (high nibble of
    octet 3); a 3-digit MNC packs all three digits.
    """
    if len(mcc) != 3 or mcc.isdigit() is False:
        raise ValueError("MCC must be exactly 3 decimal digits.")
    if len(mnc) not in (2, 3) or mnc.isdigit() is False:
        raise ValueError("MNC must be 2 or 3 decimal digits.")
    mcc_digit_1 = int(mcc[0])
    mcc_digit_2 = int(mcc[1])
    mcc_digit_3 = int(mcc[2])
    mnc_digit_1 = int(mnc[0])
    mnc_digit_2 = int(mnc[1])
    mnc_digit_3 = int(mnc[2]) if len(mnc) == 3 else 0xF
    octet_2 = (mcc_digit_2 << 4) | mcc_digit_1
    octet_3 = (mnc_digit_3 << 4) | mcc_digit_3
    octet_4 = (mnc_digit_2 << 4) | mnc_digit_1
    return bytes((octet_2, octet_3, octet_4))


def _pack_routing_indicator(routing_indicator: str) -> bytes:
    """Pack the routing indicator into the two-byte BCD form.

    Per TS 23.003 §28.7.1.1 the routing indicator is up to four
    decimal digits; missing trailing positions are padded with 0xF.
    Within each byte the **first** digit is the low nibble.
    """
    digits = str(routing_indicator or "").strip()
    if len(digits) == 0:
        digits = "0"
    if digits.isdigit() is False:
        raise ValueError("Routing indicator must be decimal digits.")
    if len(digits) > 4:
        raise ValueError("Routing indicator must be at most 4 digits.")
    padded = digits + "F" * (4 - len(digits))
    nibbles = [int(d, 16) if d != "F" else 0xF for d in padded]
    octet_1 = (nibbles[1] << 4) | nibbles[0]
    octet_2 = (nibbles[3] << 4) | nibbles[2]
    return bytes((octet_1, octet_2))


# ---------------------------------------------------------------------------
# Annex C ANSI-X9.63 KDF and AES-128-CTR helpers
# ---------------------------------------------------------------------------


def x963_kdf_sha256(shared_secret: bytes, shared_info: bytes, key_data_len: int) -> bytes:
    """ANSI-X9.63 KDF with SHA-256 (TS 33.501 §C.3.2).

        counter = 1
        T = ""
        while len(T) < key_data_len:
            T = T || SHA-256(Z || counter_be32 || SharedInfo)
            counter += 1
        return T[:key_data_len]
    """
    if key_data_len < 0:
        raise ValueError("key_data_len must be non-negative.")
    if key_data_len == 0:
        return b""
    z = bytes(shared_secret or b"")
    if len(z) == 0:
        raise ValueError("Shared secret must not be empty.")
    info = bytes(shared_info or b"")
    output = bytearray()
    counter = 1
    while len(output) < key_data_len:
        digest = sha256()
        digest.update(z)
        digest.update(counter.to_bytes(4, "big"))
        digest.update(info)
        output.extend(digest.digest())
        counter += 1
        if counter > 0xFFFFFFFF:
            raise ValueError("X9.63 KDF counter overflowed 32 bits.")
    return bytes(output[:key_data_len])


def _split_kdf_output(material: bytes) -> tuple[bytes, bytes, bytes]:
    """Split the 64-byte X9.63 KDF output into (enc_key, icb, mac_key).

    Layout per TS 33.501 §C.3.4.1 / §C.3.4.2:

        material[0:16]  -> AES-128 encryption key
        material[16:32] -> 16-byte initial counter block (IV) for AES-CTR
        material[32:64] -> 32-byte HMAC-SHA-256 integrity key
    """
    if len(material) != 64:
        raise ValueError("Profile A/B KDF output must be 64 bytes.")
    return material[0:16], material[16:32], material[32:64]


def _aes_ctr_encrypt(key: bytes, icb: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(bytes(key)), modes.CTR(bytes(icb)))
    encryptor = cipher.encryptor()
    return encryptor.update(bytes(plaintext)) + encryptor.finalize()


def _aes_ctr_decrypt(key: bytes, icb: bytes, ciphertext: bytes) -> bytes:
    return _aes_ctr_encrypt(key, icb, ciphertext)


def _hmac_sha256_truncated(key: bytes, payload: bytes, length: int = 8) -> bytes:
    digest = hmac.new(bytes(key), bytes(payload), sha256).digest()
    return digest[:length]


# ---------------------------------------------------------------------------
# Profile A (X25519) and Profile B (secp256r1) ECIES helpers
# ---------------------------------------------------------------------------


def _profile_a_encrypt(
    plaintext: bytes,
    hn_public_key_bytes: bytes,
    *,
    ephemeral_private_key: Optional[bytes] = None,
) -> bytes:
    if len(hn_public_key_bytes) != 32:
        raise ValueError("Profile A home-network key must be 32 bytes (X25519).")
    if ephemeral_private_key is None:
        eph_private = x25519.X25519PrivateKey.generate()
    else:
        eph_private = x25519.X25519PrivateKey.from_private_bytes(bytes(ephemeral_private_key))
    eph_public_bytes = eph_private.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    hn_public = x25519.X25519PublicKey.from_public_bytes(bytes(hn_public_key_bytes))
    shared_secret = eph_private.exchange(hn_public)
    kdf_input = eph_public_bytes
    kdf_material = x963_kdf_sha256(shared_secret, kdf_input, 64)
    enc_key, icb, mac_key = _split_kdf_output(kdf_material)
    ciphertext = _aes_ctr_encrypt(enc_key, icb, plaintext)
    mac_tag = _hmac_sha256_truncated(mac_key, ciphertext, 8)
    return eph_public_bytes + ciphertext + mac_tag


def _profile_a_decrypt(
    scheme_output: bytes,
    hn_private_key_bytes: bytes,
) -> bytes:
    """Round-trip helper for tests. Production deconcealment lives in
    the home-network UDM, not on the UICC; this lets the test bench
    confirm the ciphertext is recoverable without standing up a UDM."""
    if len(scheme_output) < 32 + 8:
        raise ValueError("Profile A scheme output is too short.")
    eph_public_bytes = scheme_output[:32]
    mac_tag = scheme_output[-8:]
    ciphertext = scheme_output[32:-8]
    hn_private = x25519.X25519PrivateKey.from_private_bytes(bytes(hn_private_key_bytes))
    eph_public = x25519.X25519PublicKey.from_public_bytes(eph_public_bytes)
    shared_secret = hn_private.exchange(eph_public)
    kdf_material = x963_kdf_sha256(shared_secret, eph_public_bytes, 64)
    enc_key, icb, mac_key = _split_kdf_output(kdf_material)
    expected_tag = _hmac_sha256_truncated(mac_key, ciphertext, 8)
    if hmac.compare_digest(expected_tag, mac_tag) is False:
        raise ValueError("Profile A MAC verification failed.")
    return _aes_ctr_decrypt(enc_key, icb, ciphertext)


def _profile_b_encrypt(
    plaintext: bytes,
    hn_public_key_compressed: bytes,
    *,
    ephemeral_private_key: Optional[bytes] = None,
) -> bytes:
    if len(hn_public_key_compressed) != 33 or hn_public_key_compressed[0] not in (0x02, 0x03):
        raise ValueError("Profile B home-network key must be a 33-byte compressed P-256 point.")
    curve = ec.SECP256R1()
    if ephemeral_private_key is None:
        eph_private = ec.generate_private_key(curve)
    else:
        scalar = int.from_bytes(bytes(ephemeral_private_key), "big")
        eph_private = ec.derive_private_key(scalar, curve)
    eph_public_compressed = eph_private.public_key().public_bytes(
        Encoding.X962,
        PublicFormat.CompressedPoint,
    )
    hn_public = ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes(hn_public_key_compressed))
    shared_point_x = eph_private.exchange(ec.ECDH(), hn_public)
    kdf_input = eph_public_compressed
    kdf_material = x963_kdf_sha256(shared_point_x, kdf_input, 64)
    enc_key, icb, mac_key = _split_kdf_output(kdf_material)
    ciphertext = _aes_ctr_encrypt(enc_key, icb, plaintext)
    mac_tag = _hmac_sha256_truncated(mac_key, ciphertext, 8)
    return eph_public_compressed + ciphertext + mac_tag


def _profile_b_decrypt(
    scheme_output: bytes,
    hn_private_scalar: bytes,
) -> bytes:
    if len(scheme_output) < 33 + 8:
        raise ValueError("Profile B scheme output is too short.")
    eph_public_compressed = scheme_output[:33]
    mac_tag = scheme_output[-8:]
    ciphertext = scheme_output[33:-8]
    curve = ec.SECP256R1()
    scalar = int.from_bytes(bytes(hn_private_scalar), "big")
    hn_private = ec.derive_private_key(scalar, curve)
    eph_public = ec.EllipticCurvePublicKey.from_encoded_point(curve, eph_public_compressed)
    shared_point_x = hn_private.exchange(ec.ECDH(), eph_public)
    kdf_material = x963_kdf_sha256(shared_point_x, eph_public_compressed, 64)
    enc_key, icb, mac_key = _split_kdf_output(kdf_material)
    expected_tag = _hmac_sha256_truncated(mac_key, ciphertext, 8)
    if hmac.compare_digest(expected_tag, mac_tag) is False:
        raise ValueError("Profile B MAC verification failed.")
    return _aes_ctr_decrypt(enc_key, icb, ciphertext)


# ---------------------------------------------------------------------------
# High-level dispatcher
# ---------------------------------------------------------------------------


def compute_scheme_output(
    msin: str,
    *,
    protection_scheme: ProtectionScheme,
    home_network_public_key: Optional[HomeNetworkPublicKey] = None,
    ephemeral_private_key: Optional[bytes] = None,
) -> bytes:
    """Compute the SUCI Scheme Output portion of the mobile identity.

    For ``ProtectionScheme.NULL`` the Scheme Output is simply the
    BCD-packed MSIN; ``home_network_public_key`` is ignored. For the
    protected schemes the helper plaintext-encrypts the BCD-packed
    MSIN with the chosen home-network key.
    """
    plaintext = encode_msin_bcd(msin)
    if protection_scheme == ProtectionScheme.NULL:
        return plaintext
    if home_network_public_key is None:
        raise ValueError("Protected SUCI requires a home-network public key.")
    if protection_scheme == ProtectionScheme.PROFILE_A:
        return _profile_a_encrypt(
            plaintext,
            bytes(home_network_public_key.public_key),
            ephemeral_private_key=ephemeral_private_key,
        )
    if protection_scheme == ProtectionScheme.PROFILE_B:
        return _profile_b_encrypt(
            plaintext,
            bytes(home_network_public_key.public_key),
            ephemeral_private_key=ephemeral_private_key,
        )
    raise ValueError(f"Unsupported protection scheme {int(protection_scheme):#x}.")


# ---------------------------------------------------------------------------
# SUCI Mobile Identity IE (TS 24.501 §9.11.3.4)
# ---------------------------------------------------------------------------


SUPI_FORMAT_IMSI = 0
SUPI_FORMAT_NAI = 1
SUPI_FORMAT_GCI = 2
SUPI_FORMAT_GLI = 3

# bits 3..1 of octet 1 = type-of-identity. SUCI = 1.
TYPE_OF_IDENTITY_SUCI = 0b001


def encode_suci_mobile_identity(
    *,
    supi_format: int,
    mcc: str,
    mnc: str,
    routing_indicator: str,
    protection_scheme: ProtectionScheme,
    hn_public_key_id: int,
    scheme_output: bytes,
) -> bytes:
    """Encode the SUCI Mobile Identity body per TS 24.501 §9.11.3.4.

    Returns the IE *contents* (no outer length prefix). The first
    octet packs the SUPI format in the upper nibble and the
    type-of-identity in the lower three bits; subsequent fields are
    the standard 5GS layout. The function only implements the
    IMSI-based SUCI today (``supi_format=0``); NAI / GCI / GLI
    formats raise ``NotImplementedError`` so callers see the gap
    rather than receiving a silently-malformed identity.
    """
    if int(supi_format) != SUPI_FORMAT_IMSI:
        raise NotImplementedError(
            "Only IMSI-based SUCI (supi_format=0) is implemented; "
            f"got {int(supi_format)}."
        )
    if int(hn_public_key_id) < 0 or int(hn_public_key_id) > 0xFF:
        raise ValueError("HN public key identifier must fit in one byte.")
    octet_1 = (int(supi_format) & 0x0F) << 4
    octet_1 |= TYPE_OF_IDENTITY_SUCI & 0x07
    out = bytearray()
    out.append(octet_1)
    out.extend(_pack_mcc_mnc(mcc, mnc))
    out.extend(_pack_routing_indicator(routing_indicator))
    out.append(int(protection_scheme) & 0x0F)
    out.append(int(hn_public_key_id) & 0xFF)
    out.extend(bytes(scheme_output or b""))
    return bytes(out)


def build_suci_from_imsi(
    *,
    imsi: str,
    mnc_length: int,
    routing_indicator: str,
    protection_scheme: ProtectionScheme,
    home_network_public_key: Optional[HomeNetworkPublicKey] = None,
    ephemeral_private_key: Optional[bytes] = None,
) -> bytes:
    """One-shot helper: IMSI -> SUCI Mobile Identity bytes.

    Used by both ``GET IDENTITY`` (USIM-side calculation) and the
    test bench. ``home_network_public_key`` is required for any
    non-NULL ``protection_scheme``.
    """
    mcc, mnc, msin = split_imsi(imsi, mnc_length)
    scheme_output = compute_scheme_output(
        msin,
        protection_scheme=protection_scheme,
        home_network_public_key=home_network_public_key,
        ephemeral_private_key=ephemeral_private_key,
    )
    hn_pubkey_id = (
        home_network_public_key.key_identifier
        if home_network_public_key is not None
        else 0
    )
    return encode_suci_mobile_identity(
        supi_format=SUPI_FORMAT_IMSI,
        mcc=mcc,
        mnc=mnc,
        routing_indicator=routing_indicator,
        protection_scheme=protection_scheme,
        hn_public_key_id=hn_pubkey_id,
        scheme_output=scheme_output,
    )


__all__ = [
    "ProtectionScheme",
    "HomeNetworkPublicKey",
    "SuciCalcInfo",
    "SUPI_FORMAT_IMSI",
    "SUPI_FORMAT_NAI",
    "SUPI_FORMAT_GCI",
    "SUPI_FORMAT_GLI",
    "TYPE_OF_IDENTITY_SUCI",
    "encode_ef_suci_calc_info",
    "decode_ef_suci_calc_info",
    "split_imsi",
    "encode_msin_bcd",
    "decode_msin_bcd",
    "x963_kdf_sha256",
    "compute_scheme_output",
    "encode_suci_mobile_identity",
    "build_suci_from_imsi",
]
