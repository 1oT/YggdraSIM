# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""TLS record-layer lookup tables shared by every BIP observer.

A card driven over a BIP channel puts its TLS records on a transport the
toolchain watches from more than one place -- the BIP stream decoder, the
HIL-Bridge decode view and the Wireshark dissector among them. Each kept
its own copy of these tables, and the copies disagreed -- the
dissector named thirty-seven AlertDescription values, the decode view
named two. The same fatal alert therefore read as ``bad_certificate`` in
a capture and ``0x2A`` in the terminal.

Names follow the registries verbatim (RFC 8446 §4, §5.1, §6; RFC 5246
§7.2, §7.4), so a value carries the same name here, in a trace, and in
the specification an operator checks it against. Callers that print
YggdraSIM's older CamelCase spelling derive it with
:func:`display_name`.

Every AlertDescription number below is decimal. ``bad_certificate`` is
42, which is 0x2A; reading it as hex 0x42 gives 66, which is unassigned,
so an operator chasing a certificate failure would see nothing at all.
"""

from __future__ import annotations

__all__ = [
    "TLS_ALERT_DESCRIPTIONS",
    "TLS_ALERT_LEVELS",
    "TLS_CIPHER_SUITES",
    "TLS_CONTENT_TYPES",
    "TLS_DEFAULT_MAX_FRAGMENT_LENGTH",
    "TLS_EXTENSION_TYPES",
    "TLS_HANDSHAKE_TYPES",
    "TLS_MAX_FRAGMENT_LENGTHS",
    "TLS_MAX_RECORD_LENGTH",
    "TLS_NAMED_GROUPS",
    "TLS_PROTOCOL_VERSIONS",
    "TLS_SIGNATURE_SCHEMES",
    "alert_description_name",
    "alert_level_name",
    "cipher_suite_name",
    "content_type_name",
    "display_name",
    "extension_type_name",
    "handshake_type_name",
    "named_group_name",
    "protocol_version_name",
    "signature_scheme_name",
]


#: RFC 8446 §5.1 ContentType, plus the RFC 6520 heartbeat type.
TLS_CONTENT_TYPES: dict[int, str] = {
    20: "change_cipher_spec",
    21: "alert",
    22: "handshake",
    23: "application_data",
    24: "heartbeat",
}

#: RFC 5246 §7.2 AlertLevel. TLS 1.3 keeps the field but fixes its meaning.
TLS_ALERT_LEVELS: dict[int, str] = {
    1: "warning",
    2: "fatal",
}

#: RFC 8446 §6 AlertDescription registry. Decimal, as the registry states.
TLS_ALERT_DESCRIPTIONS: dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    52: "too_many_cids_requested",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    117: "general_error",
    120: "no_application_protocol",
    121: "ech_required",
}

#: RFC 8446 §4 HandshakeType, with the RFC 5246 §7.4 messages a TLS 1.2
#: session still puts on the wire. ``compressed_certificate`` (RFC 8879)
#: earns its place here: an SM-DP+ chain runs to kilobytes across roughly
#: 236-byte channel-data blocks, which is the pressure that gets
#: certificate compression turned on.
TLS_HANDSHAKE_TYPES: dict[int, str] = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    3: "hello_verify_request",
    4: "new_session_ticket",
    5: "end_of_early_data",
    8: "encrypted_extensions",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
    21: "certificate_url",
    22: "certificate_status",
    24: "key_update",
    25: "compressed_certificate",
    254: "message_hash",
}

#: RFC 8446 §5.1 caps a plaintext record body at 2^14 and §5.2 a
#: ciphertext one at 2^14 + 256. A longer claim is not a record header,
#: which is what keeps a five-byte sniff from buffering arbitrary bytes.
TLS_MAX_RECORD_LENGTH = 16640

#: ProtocolVersion: RFC 8446 §5.1 names 0x0300 and 0x0301, §4.1.3 0x0303,
#: §4.2.1 0x0304. A version outside these prints as its hex value.
TLS_PROTOCOL_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

#: CipherSuite code points as the documents in the library define them:
#: RFC 5246 Appendix A.5 (the AES suites), RFC 5746 §3.3 (the
#: renegotiation SCSV), RFC 4785 §5, RFC 4279 §6, RFC 5487 §2 and §3,
#: RFC 8422 §6, RFC 5289 §3.1 and §3.2, RFC 8446 §B.4. This is not the
#: IANA registry: a suite outside it prints as its hex value.
TLS_CIPHER_SUITES: dict[int, str] = {
    0x002C: "TLS_PSK_WITH_NULL_SHA",
    0x002D: "TLS_DHE_PSK_WITH_NULL_SHA",
    0x002E: "TLS_RSA_PSK_WITH_NULL_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x008A: "TLS_PSK_WITH_RC4_128_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x008E: "TLS_DHE_PSK_WITH_RC4_128_SHA",
    0x008F: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0090: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    0x0091: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    0x0092: "TLS_RSA_PSK_WITH_RC4_128_SHA",
    0x0093: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0094: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    0x0095: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0x00AA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    0x00AB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    0x00AC: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    0x00AD: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    0x00AE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x00AF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0x00B0: "TLS_PSK_WITH_NULL_SHA256",
    0x00B1: "TLS_PSK_WITH_NULL_SHA384",
    0x00B2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    0x00B3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    0x00B4: "TLS_DHE_PSK_WITH_NULL_SHA256",
    0x00B5: "TLS_DHE_PSK_WITH_NULL_SHA384",
    0x00B6: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    0x00B7: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    0x00B8: "TLS_RSA_PSK_WITH_NULL_SHA256",
    0x00B9: "TLS_RSA_PSK_WITH_NULL_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
}

#: ExtensionType: RFC 6066 §1.1 (0-5), RFC 8446 §4.2 (the TLS 1.3 set,
#: which also renames 10 to supported_groups), RFC 8422 §5.1 (11),
#: RFC 7627 §5.1 (23), RFC 8879 §3 (27), RFC 5077 §3.2 (35, spelled as
#: that clause spells it), RFC 5746 §3.2 (0xFF01).
TLS_EXTENSION_TYPES: dict[int, str] = {
    0: "server_name",
    1: "max_fragment_length",
    2: "client_certificate_url",
    3: "trusted_ca_keys",
    4: "truncated_hmac",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    35: "SessionTicket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    48: "oid_filters",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    0xFF01: "renegotiation_info",
}

#: NamedGroup: RFC 8446 §4.2.7, plus the brainpool curves of RFC 7027 §2
#: (SGP.32 v1.3 §2.6.3.2 lists brainpoolP256r1(26) for ESipa).
TLS_NAMED_GROUPS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001A: "brainpoolP256r1",
    0x001B: "brainpoolP384r1",
    0x001C: "brainpoolP512r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
}

#: SignatureScheme: RFC 8446 §4.2.3. A TLS 1.2 SignatureAndHashAlgorithm
#: (RFC 5246 §7.4.1.4.1) is the same two bytes, hash first, so the
#: ECDSA and RSA PKCS #1 code points read the same in both versions.
TLS_SIGNATURE_SCHEMES: dict[int, str] = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
}

#: RFC 6066 §4 MaxFragmentLength: the code a hello carries and the
#: plaintext bytes it allows.
TLS_MAX_FRAGMENT_LENGTHS: dict[int, int] = {
    1: 512,
    2: 1024,
    3: 2048,
    4: 4096,
}

#: RFC 6066 §4: without the extension a plaintext fragment runs to 2^14.
TLS_DEFAULT_MAX_FRAGMENT_LENGTH = 16384


def display_name(registry_name: str) -> str:
    """Return the CamelCase spelling YggdraSIM trace lines have always used.

    ``application_data`` becomes ``ApplicationData``. The registry name is
    the stored form because the dissector and the specifications both use
    it; this exists so the terminal output does not change spelling under
    operators who read it every day.
    """
    parts = [part for part in str(registry_name or "").split("_") if len(part) > 0]
    return "".join(part[:1].upper() + part[1:] for part in parts)


def content_type_name(value: int) -> str:
    """Return the registry name for a ContentType, or an empty string."""
    return TLS_CONTENT_TYPES.get(int(value), "")


def alert_level_name(value: int) -> str:
    """Return the registry name for an AlertLevel, or ``0xNN``."""
    return TLS_ALERT_LEVELS.get(int(value), f"0x{int(value):02X}")


def alert_description_name(value: int) -> str:
    """Return the registry name for an AlertDescription, or ``0xNN``."""
    return TLS_ALERT_DESCRIPTIONS.get(int(value), f"0x{int(value):02X}")


def handshake_type_name(value: int) -> str:
    """Return the registry name for a HandshakeType, or an empty string."""
    return TLS_HANDSHAKE_TYPES.get(int(value), "")


def protocol_version_name(value: int) -> str:
    """Return ``TLS 1.2`` and the like for a ProtocolVersion, or ``0xNNNN``."""
    return TLS_PROTOCOL_VERSIONS.get(int(value), f"0x{int(value):04X}")


def cipher_suite_name(value: int) -> str:
    """Return the defining document's name for a CipherSuite, or ``0xNNNN``."""
    return TLS_CIPHER_SUITES.get(int(value), f"0x{int(value):04X}")


def extension_type_name(value: int) -> str:
    """Return the registry name for an ExtensionType, or ``0xNNNN``."""
    return TLS_EXTENSION_TYPES.get(int(value), f"0x{int(value):04X}")


def named_group_name(value: int) -> str:
    """Return the registry name for a NamedGroup, or ``0xNNNN``."""
    return TLS_NAMED_GROUPS.get(int(value), f"0x{int(value):04X}")


def signature_scheme_name(value: int) -> str:
    """Return the registry name for a SignatureScheme, or ``0xNNNN``."""
    return TLS_SIGNATURE_SCHEMES.get(int(value), f"0x{int(value):04X}")
