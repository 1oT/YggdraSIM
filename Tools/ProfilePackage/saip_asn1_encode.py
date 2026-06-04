# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Pair-encoder module: inverse of ``saip_asn1_decode``.

For every ``_decode_<field>`` in ``saip_asn1_decode`` that can be inverted
losslessly, this module exports ``encode_<field>(decoded)`` which returns
the byte (or scalar) form the SAIP JSON should carry.

Lossy decoders (ADN records, SMSP, EF.ARR TLVs) are handled by the
companion "splice" helpers in ``saip_decoded_edit`` — they take the
decoded form plus the original raw bytes and substitute only the changed
sub-fields. Encoders here assume the decoded payload came from the
matching ``_decode_*`` function in the same repository.

Conventions:

- Encoders return ``bytes`` for fields whose JSON form is a tagged-bytes
  OCTET STRING.
- Encoders return ``int`` for fields whose JSON form is an ASN.1 INTEGER
  (i.e. fields handled by ``_decode_scalar_special_field``'s int path).
- Roundtrip is covered by ``tests/test_saip_asn1_encode.py`` — every
  encoder must satisfy ``decode(encode(decode(x))) == decode(x)``.
"""

from __future__ import annotations

from typing import Any, Iterable

from Tools.ProfilePackage.saip_asn1_decode import (
    _AID_FIELD_NAMES,
    _AKA_ALGORITHM_ID_NAMES,
    _APPLICATION_PRIVILEGE_FLAGS,
    _KEY_ACCESS_NAMES,
    _KEY_TYPE_NAMES,
    _KEY_USAGE_FLAGS,
    _LIFE_CYCLE_STATE_NAMES,
    _MEMORY_LIMIT_FIELD_LABELS,
)


class RoundtripEncoderError(ValueError):
    """Raised when an encoder cannot faithfully invert a decoded payload."""


# ---------------------------------------------------------------------------
# Low-level helpers


def _int_to_be_bytes(value: int, *, min_length: int = 1) -> bytes:
    if value < 0:
        raise RoundtripEncoderError("integer must be >= 0")
    width = max(min_length, (value.bit_length() + 7) // 8)
    if width == 0:
        width = 1
    return value.to_bytes(width, "big", signed=False)


def _int_to_fixed_bytes(value: int, *, length: int) -> bytes:
    if value < 0:
        raise RoundtripEncoderError("integer must be >= 0")
    if length <= 0:
        raise RoundtripEncoderError("fixed-length target must be positive")
    try:
        return value.to_bytes(length, "big", signed=False)
    except OverflowError as exc:
        raise RoundtripEncoderError(
            f"integer {value} does not fit in {length} byte(s)"
        ) from exc


def _require_int(payload: dict[str, Any], key: str) -> int:
    if key not in payload:
        raise RoundtripEncoderError(f"missing required field {key!r}")
    value = payload[key]
    if isinstance(value, bool):
        raise RoundtripEncoderError(f"field {key!r} must be an integer, not bool")
    if isinstance(value, int) is False:
        raise RoundtripEncoderError(f"field {key!r} must be an integer")
    return int(value)


def _require_hex(payload: dict[str, Any], key: str) -> str:
    if key not in payload:
        raise RoundtripEncoderError(f"missing required field {key!r}")
    value = payload[key]
    if isinstance(value, str) is False:
        raise RoundtripEncoderError(f"field {key!r} must be a hex string")
    cleaned = str(value).strip().upper()
    if len(cleaned) == 0:
        raise RoundtripEncoderError(f"field {key!r} must not be empty")
    if len(cleaned) % 2 != 0:
        raise RoundtripEncoderError(f"field {key!r} must have an even number of hex digits")
    if any(character not in "0123456789ABCDEF" for character in cleaned):
        raise RoundtripEncoderError(f"field {key!r} contains non-hex characters")
    return cleaned


def _hex_to_bytes(hex_text: str) -> bytes:
    return bytes.fromhex(hex_text)


# ---------------------------------------------------------------------------
# Enum-style encoders (name -> single byte)


def _encode_enum_name(
    payload: dict[str, Any],
    *,
    name_key: str,
    name_to_code: dict[int, str],
    format_label: str,
) -> bytes:
    name = payload.get(name_key)
    if isinstance(name, str) is False:
        raise RoundtripEncoderError(
            f"{format_label}: missing required string field {name_key!r}"
        )
    name_clean = str(name).strip()
    if len(name_clean) == 0:
        raise RoundtripEncoderError(f"{format_label}: {name_key!r} must not be empty")
    reverse = {value: key for key, value in name_to_code.items()}
    if name_clean in reverse:
        return bytes([reverse[name_clean]])
    # Some decoded payloads carry an explicit hex for unknown codes.
    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    raise RoundtripEncoderError(
        f"{format_label}: unknown {name_key} {name_clean!r}; supply 'hex' instead"
    )


def encode_life_cycle_state(payload: dict[str, Any]) -> bytes:
    """Encode a lifecycle-state integer as the ASN.1 OCTET STRING for lcsState (GSMA SGP.22 §A.1)."""
    return _encode_enum_name(
        payload,
        name_key="state",
        name_to_code=_LIFE_CYCLE_STATE_NAMES,
        format_label="life cycle state",
    )


def encode_key_access(payload: dict[str, Any]) -> bytes:
    """Encode a key-access byte as the ASN.1 OCTET STRING for keyAccess."""
    return _encode_enum_name(
        payload,
        name_key="access",
        name_to_code=_KEY_ACCESS_NAMES,
        format_label="key access",
    )


def encode_key_type(payload: dict[str, Any]) -> bytes:
    """Encode a key-type identifier byte as the ASN.1 OCTET STRING for keyType."""
    return _encode_enum_name(
        payload,
        name_key="type",
        name_to_code=_KEY_TYPE_NAMES,
        format_label="key type",
    )


# ---------------------------------------------------------------------------
# Simple byte/counter encoders


def encode_key_identifier(payload: dict[str, Any]) -> bytes:
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError("key identifier must fit in 1 byte")
    return bytes([decimal_value])


def encode_key_version_number(payload: dict[str, Any]) -> bytes:
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError("key version number must fit in 1 byte")
    return bytes([decimal_value])


def encode_key_counter_value(payload: dict[str, Any]) -> bytes:
    """Encode a key counter value into the keyCounterValue SEQUENCE."""
    if "decimal" in payload:
        decimal_value = _require_int(payload, "decimal")
        if "hex" in payload:
            # Preserve the original byte width when the user only touches decimal.
            try:
                width_hint = len(_hex_to_bytes(_require_hex(payload, "hex")))
            except RoundtripEncoderError:
                width_hint = 0
            if width_hint > 0:
                return _int_to_fixed_bytes(decimal_value, length=width_hint)
        return _int_to_be_bytes(decimal_value)
    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    raise RoundtripEncoderError("key counter value: provide 'decimal' or 'hex'")


def encode_pin_attributes(payload: dict[str, Any]) -> bytes:
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError("pinAttributes must fit in 1 byte")
    return bytes([decimal_value])


def encode_minimum_security_level(payload: dict[str, Any]) -> bytes:
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError("minimumSecurityLevel must fit in 1 byte")
    return bytes([decimal_value])


def encode_pin_puk_retry_counter(payload: dict[str, Any]) -> int:
    """Return the packed counter as an int (SAIP stores it as INTEGER)."""

    max_attempts = _require_int(payload, "maxAttempts")
    remaining_attempts = _require_int(payload, "remainingAttempts")
    if not 0 <= max_attempts <= 0x0F:
        raise RoundtripEncoderError("maxAttempts must fit in 4 bits")
    if not 0 <= remaining_attempts <= 0x0F:
        raise RoundtripEncoderError("remainingAttempts must fit in 4 bits")
    return ((max_attempts & 0x0F) << 4) | (remaining_attempts & 0x0F)


def encode_mac_length(payload: dict[str, Any]) -> int:
    decimal_value = _require_int(payload, "decimal")
    if decimal_value < 0:
        raise RoundtripEncoderError("macLength must be >= 0")
    return decimal_value


def encode_fill_file_offset(payload: dict[str, Any]) -> int:
    decimal_value = _require_int(payload, "decimal")
    if decimal_value < 0:
        raise RoundtripEncoderError("fillFileOffset must be >= 0")
    return decimal_value


def encode_puk_key_reference(payload: dict[str, Any]) -> int:
    return _require_int(payload, "decimal")


def encode_pin_puk_adm_key_reference(payload: dict[str, Any]) -> int:
    return _require_int(payload, "decimal")


def encode_algorithm_id(payload: dict[str, Any]) -> int:
    """AKA algorithm ID — SAIP stores it as INTEGER."""

    if "decimal" in payload:
        return _require_int(payload, "decimal")
    algorithm_name = payload.get("algorithm")
    if isinstance(algorithm_name, str) is False:
        raise RoundtripEncoderError(
            "algorithmID: provide either 'decimal' or 'algorithm' name"
        )
    reverse = {value: key for key, value in _AKA_ALGORITHM_ID_NAMES.items()}
    name_clean = str(algorithm_name).strip().lower()
    if name_clean in reverse:
        return reverse[name_clean]
    raise RoundtripEncoderError(
        f"algorithmID: unknown algorithm name {algorithm_name!r}"
    )


# ---------------------------------------------------------------------------
# Multi-byte counter encoders (AKA counters, memory limits)


def encode_counter_field(payload: dict[str, Any]) -> bytes:
    """Width-preserving counter encoder.

    Prefers semantic fields when present: if ``decimal`` + ``length`` are
    both provided, emit that exact width; otherwise fall back to ``hex``.
    """

    if "decimal" in payload and "length" in payload:
        decimal_value = _require_int(payload, "decimal")
        length = _require_int(payload, "length")
        if length < 1:
            raise RoundtripEncoderError("counter length must be >= 1")
        return _int_to_fixed_bytes(decimal_value, length=length)
    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    if "decimal" in payload:
        decimal_value = _require_int(payload, "decimal")
        return _int_to_be_bytes(decimal_value)
    raise RoundtripEncoderError("counter field: provide 'hex' or 'decimal' + 'length'")


def encode_memory_limit_field(payload: dict[str, Any]) -> bytes:
    return encode_counter_field(payload)


def encode_number_of_keccak(payload: dict[str, Any]) -> bytes:
    return encode_counter_field(payload)


# ---------------------------------------------------------------------------
# Flag-octet encoders


def encode_aka_option_octet(payload: dict[str, Any]) -> bytes:
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError("AKA option octet must fit in 1 byte")
    return bytes([decimal_value])


def encode_profile_policy_rules(payload: dict[str, Any]) -> bytes:
    """Profile policy rules — byte-flag field, usually 1 byte."""

    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    set_bits = payload.get("setBits")
    if isinstance(set_bits, list) is False:
        raise RoundtripEncoderError(
            "profile policy rules: provide 'hex' or 'setBits'"
        )
    if any(isinstance(bit, int) is False for bit in set_bits):
        raise RoundtripEncoderError(
            "profile policy rules: setBits must contain integers"
        )
    if len(set_bits) == 0:
        return b"\x00"
    highest_bit = max(int(bit) for bit in set_bits)
    length = max(1, (highest_bit // 8) + 1)
    accumulator = bytearray(length)
    for bit_value in set_bits:
        bit_index = int(bit_value)
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        accumulator[byte_index] |= 1 << bit_offset
    return bytes(accumulator)


# ---------------------------------------------------------------------------
# Bitmask encoders (by "active id" lists)


def _encode_active_flags(
    payload: dict[str, Any],
    *,
    active_key: str,
    flag_table: Iterable[tuple[int, str, str]],
    fixed_width: int | None = None,
    format_label: str,
) -> bytes:
    active_ids = payload.get(active_key)
    if isinstance(active_ids, list) is False:
        raise RoundtripEncoderError(
            f"{format_label}: '{active_key}' must be a list of flag ids"
        )
    id_to_mask: dict[str, int] = {}
    max_mask = 0
    for mask_value, flag_id, _flag_name in flag_table:
        id_to_mask[flag_id] = mask_value
        if mask_value > max_mask:
            max_mask = mask_value
    acc_value = 0
    for entry in active_ids:
        if isinstance(entry, str) is False:
            raise RoundtripEncoderError(
                f"{format_label}: '{active_key}' entries must be strings"
            )
        flag_key = str(entry).strip()
        if flag_key not in id_to_mask:
            raise RoundtripEncoderError(
                f"{format_label}: unknown flag id {flag_key!r}"
            )
        acc_value |= id_to_mask[flag_key]
    if fixed_width is not None:
        return _int_to_fixed_bytes(acc_value, length=fixed_width)
    width = max(1, (max_mask.bit_length() + 7) // 8)
    return _int_to_fixed_bytes(acc_value, length=width)


def encode_application_privileges(payload: dict[str, Any]) -> bytes:
    """Encode a set of application-privilege flags into the ApplicationPrivileges BIT STRING."""
    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    return _encode_active_flags(
        payload,
        active_key="activePrivilegeIds",
        flag_table=_APPLICATION_PRIVILEGE_FLAGS,
        fixed_width=3,
        format_label="applicationPrivileges",
    )


def encode_key_usage_qualifier(payload: dict[str, Any]) -> bytes:
    """Key usage qualifier is 1 or 2 bytes; preserve original hex length."""

    if "hex" in payload:
        return _hex_to_bytes(_require_hex(payload, "hex"))
    active_ids = payload.get("activeUsageIds")
    if isinstance(active_ids, list) is False:
        raise RoundtripEncoderError(
            "keyUsageQualifier: provide 'hex' or 'activeUsageIds'"
        )
    id_to_mask = {flag_id: mask for mask, flag_id, _ in _KEY_USAGE_FLAGS}
    acc_value = 0
    for entry in active_ids:
        if isinstance(entry, str) is False:
            raise RoundtripEncoderError(
                "keyUsageQualifier: 'activeUsageIds' entries must be strings"
            )
        flag_key = str(entry).strip()
        if flag_key not in id_to_mask:
            raise RoundtripEncoderError(
                f"keyUsageQualifier: unknown flag id {flag_key!r}"
            )
        acc_value |= id_to_mask[flag_key]
    # All currently-known usage flags fit in 1 byte unless bit 0x80xx is set.
    width = 2 if acc_value > 0xFF else 1
    return _int_to_fixed_bytes(acc_value, length=width)


# ---------------------------------------------------------------------------
# Fixed / variable hex passthrough


def encode_aka_secret_material(payload: dict[str, Any]) -> bytes:
    return _hex_to_bytes(_require_hex(payload, "hex"))


def encode_rotation_constants(payload: dict[str, Any]) -> bytes:
    """Encode a list of rotation-constant hex strings into the rotationConstants SEQUENCE."""
    if all(f"r{index}" in payload for index in range(1, 6)):
        values: list[int] = []
        for index in range(1, 6):
            byte_value = _require_int(payload, f"r{index}")
            if not 0 <= byte_value <= 0xFF:
                raise RoundtripEncoderError(
                    f"rotationConstants: r{index} must fit in 1 byte"
                )
            values.append(byte_value)
        return bytes(values)
    if "hex" in payload:
        data = _hex_to_bytes(_require_hex(payload, "hex"))
        if len(data) != 5:
            raise RoundtripEncoderError("rotationConstants must be 5 bytes")
        return data
    raise RoundtripEncoderError("rotationConstants: provide 'hex' or r1..r5")


def encode_xoring_constants(payload: dict[str, Any]) -> bytes:
    """Encode a list of XOR-constant hex strings into the xoringConstants SEQUENCE."""
    if "blockCount" in payload:
        block_count = _require_int(payload, "blockCount")
        if block_count < 1:
            raise RoundtripEncoderError("xoringConstants blockCount must be >= 1")
        accumulator = bytearray()
        for index in range(1, block_count + 1):
            key = f"c{index}"
            if key not in payload:
                raise RoundtripEncoderError(
                    f"xoringConstants: missing block {key!r}"
                )
            block_hex = _require_hex(payload, key)
            block_bytes = _hex_to_bytes(block_hex)
            if len(block_bytes) != 16:
                raise RoundtripEncoderError(
                    f"xoringConstants: block {key} must be 16 bytes"
                )
            accumulator.extend(block_bytes)
        return bytes(accumulator)
    if "hex" in payload:
        data = _hex_to_bytes(_require_hex(payload, "hex"))
        if len(data) == 0 or len(data) % 16 != 0:
            raise RoundtripEncoderError(
                "xoringConstants must be a non-empty multiple of 16 bytes"
            )
        return data
    raise RoundtripEncoderError("xoringConstants: provide 'hex' or 'blockCount'")


def encode_tar_value(payload: dict[str, Any]) -> bytes:
    return _hex_to_bytes(_require_hex(payload, "hex"))


def encode_access_domain(payload: dict[str, Any]) -> bytes:
    return _hex_to_bytes(_require_hex(payload, "hex"))


def encode_application_identifier(payload: dict[str, Any]) -> bytes:
    return _hex_to_bytes(_require_hex(payload, "aid"))


# ---------------------------------------------------------------------------
# EF content encoders (fillFileContent, keyed on last_ef_key)


_EHPLMNPI_NAME_TO_CODE: dict[str, int] = {
    "no_preference": 0x00,
    "display_highest_prio_only": 0x01,
    "display_all": 0x02,
}


_AD_MODE_NAME_TO_CODE: dict[str, int] = {
    "Normal": 0x00,
    "Type Approval": 0x01,
    "Normal/Internal": 0x02,
    "Proprietary": 0x80,
}

# Bytes whose decoder mode name is NOT the "canonical" value in the map
# above. We only rewrite the first byte when the existing byte maps to a
# different mode name than what the payload requests.
_AD_MODE_CODE_ALIASES: dict[int, str] = {
    0x00: "Normal",
    0x01: "Type Approval",
    0x02: "Normal/Internal",
    0x04: "Normal/Internal",
    0x80: "Proprietary",
}


def _pad_ff(data: bytes, *, target_length: int | None) -> bytes:
    """Pad ``data`` with ``0xFF`` to ``target_length`` when provided."""

    if target_length is None:
        return data
    if len(data) > target_length:
        raise RoundtripEncoderError(
            f"encoded content ({len(data)} bytes) exceeds target length ({target_length})"
        )
    if len(data) == target_length:
        return data
    return data + b"\xFF" * (target_length - len(data))


def encode_ef_acc(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.ACC content: Access Control Class bitmask (3GPP TS 31.102 §4.2.15)."""
    classes = payload.get("accessControlClasses")
    if isinstance(classes, list) is False:
        if "raw" in payload and isinstance(payload["raw"], str):
            data = _hex_to_bytes(_require_hex(payload, "raw"))
            return _pad_ff(data, target_length=target_length)
        raise RoundtripEncoderError("EF.ACC: provide 'raw' or 'accessControlClasses'")
    acc_value = 0
    for entry in classes:
        try:
            index = int(entry)
        except (TypeError, ValueError) as exc:
            raise RoundtripEncoderError(
                f"EF.ACC: class entry {entry!r} is not an integer"
            ) from exc
        if not 0 <= index <= 15:
            raise RoundtripEncoderError(
                f"EF.ACC: class {index} out of range (0-15)"
            )
        acc_value |= 1 << index
    data = acc_value.to_bytes(2, "big", signed=False)
    return _pad_ff(data, target_length=target_length)


def encode_ef_ehplmnpi(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.EHPLMNPI content: EHPLMN presentation indication byte (3GPP TS 31.102 §4.2.85)."""
    name = str(payload.get("presentationIndication", "") or "").strip()
    if name in _EHPLMNPI_NAME_TO_CODE:
        return _pad_ff(
            bytes([_EHPLMNPI_NAME_TO_CODE[name]]),
            target_length=target_length,
        )
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    raise RoundtripEncoderError(
        f"EF.EHPLMNPI: unknown presentationIndication {name!r}"
    )


def encode_ef_start_hfn(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.START-HFN content: RRC/MM/CN HFN start values (3GPP TS 31.102 §4.2.51)."""
    if "startCs" in payload or "startPs" in payload:
        start_cs = _require_int(payload, "startCs")
        start_ps = _require_int(payload, "startPs")
        data = (
            _int_to_fixed_bytes(start_cs, length=3)
            + _int_to_fixed_bytes(start_ps, length=3)
        )
        return _pad_ff(data, target_length=target_length)
    if "hex" in payload:
        data = _hex_to_bytes(_require_hex(payload, "hex"))
        if len(data) != 6:
            raise RoundtripEncoderError("EF.START-HFN must be exactly 6 bytes")
        return _pad_ff(data, target_length=target_length)
    raise RoundtripEncoderError("EF.START-HFN: provide startCs + startPs or 'hex'")


def encode_ef_smss(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SMSS content: SMS status byte and SMSP pointer (3GPP TS 31.102 §4.2.57)."""
    if "lastUsedTpMr" in payload or "memoryCapacityExceeded" in payload:
        last_used = _require_int(payload, "lastUsedTpMr")
        if not 0 <= last_used <= 0xFF:
            raise RoundtripEncoderError("EF.SMSS lastUsedTpMr must fit in 1 byte")
        memory_exceeded = bool(payload.get("memoryCapacityExceeded", False))
        # Convention in the decoder: bit0 clear => exceeded=True. Preserve that.
        flag_byte = 0xFE if memory_exceeded else 0xFF
        data = bytes([last_used, flag_byte])
        return _pad_ff(data, target_length=target_length)
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    raise RoundtripEncoderError(
        "EF.SMSS: provide 'lastUsedTpMr' + 'memoryCapacityExceeded' or 'raw'"
    )


def encode_ef_ad(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    # EF.AD only decodes the first byte; raw carries the full multi-byte
    # original (including MNC length + spare bytes) so prefer raw to keep
    # those bytes intact. Rewrite byte 0 only when the requested mode name
    # differs from what the existing byte already decodes to.
    """Encode EF.AD content: administrative data including MNC length (3GPP TS 31.102 §4.2.18)."""
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        mode_name = str(payload.get("administrativeMode", "") or "").strip()
        if (
            len(data) >= 1
            and mode_name in _AD_MODE_NAME_TO_CODE
            and _AD_MODE_CODE_ALIASES.get(data[0]) != mode_name
        ):
            data = bytes([_AD_MODE_NAME_TO_CODE[mode_name]]) + data[1:]
        return _pad_ff(data, target_length=target_length)
    mode_name = str(payload.get("administrativeMode", "") or "").strip()
    if mode_name in _AD_MODE_NAME_TO_CODE:
        mode_byte = _AD_MODE_NAME_TO_CODE[mode_name]
    elif mode_name.startswith("0x"):
        mode_byte = int(mode_name, 16)
    else:
        raise RoundtripEncoderError(
            f"EF.AD: unknown administrativeMode {mode_name!r}"
        )
    data = bytes([mode_byte])
    return _pad_ff(data, target_length=target_length)


def encode_ef_hpplmn_search_interval(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.HPPLMN content: higher-priority PLMN search interval byte (3GPP TS 31.102 §4.2.12)."""
    if "intervalMinutes" in payload:
        minutes = _require_int(payload, "intervalMinutes")
        if not 0 <= minutes <= 0xFF:
            raise RoundtripEncoderError("EF.HPPLMN interval must fit in 1 byte")
        return _pad_ff(bytes([minutes]), target_length=target_length)
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    raise RoundtripEncoderError("EF.HPPLMN: provide 'intervalMinutes' or 'raw'")


def encode_ef_three_byte_counter(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a generic three-byte counter EF (e.g. EF.THRESHOLD) from an integer value."""
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    # Decoder writes the counter under a field-specific key (acm/acmMax/...),
    # so accept any integer-valued key.
    for key, value in payload.items():
        if key in {"format", "raw"}:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return _pad_ff(
                _int_to_fixed_bytes(value, length=3),
                target_length=target_length,
            )
    raise RoundtripEncoderError(
        "three-byte counter: no integer counter field found in payload"
    )


def encode_ef_language_records(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF language preference records into packed ISO 639-1 two-letter strings."""
    languages = payload.get("languages")
    if isinstance(languages, list) is False:
        raise RoundtripEncoderError("language records: 'languages' must be a list")
    accumulator = bytearray()
    for entry in languages:
        if isinstance(entry, str) is False:
            raise RoundtripEncoderError(
                "language records: entries must be 2-char language strings"
            )
        tag = str(entry).strip()
        if len(tag) != 2:
            raise RoundtripEncoderError(
                f"language records: entry {entry!r} must be exactly 2 chars"
            )
        accumulator.extend(tag.encode("ascii"))
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_tlv80_text(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode TLV80 text fields (EF.IMPI/DOMAIN/IMPU/NAFKCA)."""

    text_value: str | None = None
    for candidate_key in ("identity", "domain", "address", "Identity", "Domain", "Address"):
        candidate = payload.get(candidate_key)
        if isinstance(candidate, str) and candidate != "":
            text_value = candidate
            break
    if text_value is not None:
        text_bytes = text_value.encode("utf-8")
        if len(text_bytes) > 0xFF:
            raise RoundtripEncoderError(
                "TLV80 text: payload longer than 255 bytes (primitive length coding only)"
            )
        tlv = bytes([0x80, len(text_bytes)]) + text_bytes
        return _pad_ff(tlv, target_length=target_length)
    if "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    raise RoundtripEncoderError(
        "TLV80 text: provide a string 'identity'/'domain'/'address' or 'raw'"
    )


_KNOWN_ACCESS_TECHNOLOGIES = {
    "UTRAN",
    "E-UTRAN WB-S1",
    "E-UTRAN NB-S1",
    "NG-RAN",
    "GSM",
    "GSM COMPACT",
    "EC-GSM-IoT",
    "cdma2000 HRPD",
    "cdma2000 1xRTT",
}


def _encode_access_technologies(act_names: list[str]) -> bytes:
    """Encode an AcT name set to 2 bytes, matching the decoder's bit pattern.

    The decoder treats certain bit combinations as joint entries (e.g. GSM
    family bits 0x008C have four legal encodings that map to different name
    sets). This encoder picks the canonical encoding that round-trips through
    the decoder without losing information.
    """

    names = {str(name or "").strip() for name in act_names}
    unknown = names - _KNOWN_ACCESS_TECHNOLOGIES
    if len(unknown) > 0:
        raise RoundtripEncoderError(
            f"PLMN AcT: unknown access technologies {sorted(unknown)!r}"
        )
    value = 0
    if "UTRAN" in names:
        value |= 0x8000
    has_wb = "E-UTRAN WB-S1" in names
    has_nb = "E-UTRAN NB-S1" in names
    if has_wb and has_nb:
        value |= 0x4000
    elif has_nb:
        value |= 0x5000
    elif has_wb:
        value |= 0x6000
    has_gsm = "GSM" in names
    has_ec_gsm = "EC-GSM-IoT" in names
    if has_gsm and has_ec_gsm:
        value |= 0x0080
    elif has_gsm:
        value |= 0x0084
    elif has_ec_gsm:
        value |= 0x0086
    if "GSM COMPACT" in names:
        value |= 0x0040
    if "cdma2000 HRPD" in names:
        value |= 0x0020
    if "cdma2000 1xRTT" in names:
        value |= 0x0010
    if "NG-RAN" in names:
        value |= 0x0008
    return value.to_bytes(2, "big", signed=False)


def _encode_plmn_hex(plmn: str) -> bytes:
    """Encode a decoded PLMN string (e.g. '234-15') back to 3 TBCD bytes.

    Accepts either the canonical ``MCC-MNC`` form or a 6-digit raw hex. Falls
    back to interpreting the value as raw hex when it contains only hex chars.
    """

    token = str(plmn or "").strip().upper()
    if len(token) == 0:
        raise RoundtripEncoderError("PLMN: empty value")
    if "-" in token:
        mcc_part, _, mnc_part = token.partition("-")
        mcc = mcc_part.strip()
        mnc = mnc_part.strip()
        if len(mcc) != 3 or mcc.isdigit() is False:
            raise RoundtripEncoderError(f"PLMN: MCC {mcc!r} must be 3 digits")
        if len(mnc) not in (2, 3) or mnc.isdigit() is False:
            raise RoundtripEncoderError(f"PLMN: MNC {mnc!r} must be 2 or 3 digits")
        mnc_digits = mnc if len(mnc) == 3 else mnc + "F"
        # TBCD: swap nibbles per 3GPP TS 24.008.
        byte0 = int(mcc[1] + mcc[0], 16)
        byte1 = int(mnc_digits[2] + mcc[2], 16)
        byte2 = int(mnc_digits[1] + mnc_digits[0], 16)
        return bytes([byte0, byte1, byte2])
    if len(token) == 6 and all(character in "0123456789ABCDEF" for character in token):
        return _hex_to_bytes(token)
    raise RoundtripEncoderError(f"PLMN: unrecognised format {token!r}")


def encode_ef_plmn_list(
    payload: dict[str, Any],
    *,
    with_act: bool,
    target_length: int | None = None,
) -> bytes:
    """Encode a PLMN-list EF (e.g. EF.PLMNWACT) from a list of PLMN+ACT dicts."""
    entries = payload.get("entries")
    if isinstance(entries, list) is False:
        raise RoundtripEncoderError("PLMN list: 'entries' must be a list")
    accumulator = bytearray()
    for entry in entries:
        if isinstance(entry, dict) is False:
            raise RoundtripEncoderError("PLMN list: each entry must be a dict")
        plmn_value = entry.get("plmn")
        if isinstance(plmn_value, str) is False:
            raise RoundtripEncoderError("PLMN list: entry missing 'plmn'")
        accumulator.extend(_encode_plmn_hex(plmn_value))
        if with_act:
            act_list = entry.get("act")
            if isinstance(act_list, list) is False:
                act_list = []
            accumulator.extend(_encode_access_technologies(act_list))
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_plmn_list_with_act(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    return encode_ef_plmn_list(payload, with_act=True, target_length=target_length)


def encode_ef_plmn_list_no_act(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    return encode_ef_plmn_list(payload, with_act=False, target_length=target_length)


def encode_ef_wlan_plmn_list(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.UPLMNWLAN / EF.OPLMNWLAN records (TS 31.102 §4.2.82/83)."""

    entries = payload.get("entries")
    if isinstance(entries, list) is False:
        if "raw" in payload and isinstance(payload["raw"], str):
            return _pad_ff(
                _hex_to_bytes(_require_hex(payload, "raw")),
                target_length=target_length,
            )
        raise RoundtripEncoderError("I-WLAN PLMN list: 'entries' must be a list")
    accumulator = bytearray()
    for entry in entries:
        if isinstance(entry, dict) is False:
            raise RoundtripEncoderError("I-WLAN PLMN list: each entry must be a dict")
        if "raw" in entry and isinstance(entry["raw"], str):
            raw_record = _hex_to_bytes(_require_hex(entry, "raw"))
            if len(raw_record) != 5:
                raise RoundtripEncoderError(
                    "I-WLAN PLMN list: raw record must be exactly 5 bytes"
                )
            accumulator.extend(raw_record)
            continue
        plmn_value = entry.get("plmn")
        if isinstance(plmn_value, str) is False:
            raise RoundtripEncoderError("I-WLAN PLMN list: entry missing 'plmn'")
        reserved_hex = str(entry.get("reserved", "FFFF") or "FFFF").strip().upper()
        if len(reserved_hex) != 4:
            raise RoundtripEncoderError(
                "I-WLAN PLMN list: reserved must be exactly 2 bytes"
            )
        try:
            reserved = bytes.fromhex(reserved_hex)
        except ValueError as exc:
            raise RoundtripEncoderError(
                "I-WLAN PLMN list: reserved must be hex"
            ) from exc
        accumulator.extend(_encode_plmn_hex(plmn_value))
        accumulator.extend(reserved)
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_wlrplmn(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.WLRPLMN (TS 31.102 §4.2.91)."""

    plmn_value = payload.get("plmn")
    if isinstance(plmn_value, str) and len(plmn_value.strip()) > 0:
        data = _encode_plmn_hex(plmn_value)
    elif "hex" in payload and isinstance(payload["hex"], str):
        data = _hex_to_bytes(_require_hex(payload, "hex"))
    elif "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
    else:
        data = b"\xFF\xFF\xFF"
    if len(data) < 3:
        raise RoundtripEncoderError("EF.WLRPLMN: value must contain at least 3 bytes")
    return _pad_ff(data[:3], target_length=target_length)


# ---------------------------------------------------------------------------
# Lossy splicers (ADN / SMSP / EF.ARR)
#
# These encoders handle EFs whose decoder does not preserve every bit of the
# source record:
#
# - ADN/FDN/SDN:  alpha identifier may carry GSM-7 / UCS-2 bytes that the
#                 decoder rendered lossily as UTF-8. The CCI byte sitting
#                 between the 10-byte BCD number and the extension record id
#                 is not exposed by the decoder.
# - SMSP:         same alpha-id roundtrip pitfall.
# - EF.ARR:       sub-TLVs inside ``A4`` groups and any vendor tags outside
#                 the small whitelist (80/90/97/84/A4) are exposed as opaque
#                 ``items`` lists rather than explicit semantic fields.
#
# The strategy is to carry the original bytes through the editor model under
# the ``_ygg_original_hex`` key (populated by
# ``build_decoded_value_roundtrip_model`` for these EFs). The splicer then
# patches only the bytes whose decoded representation actually changed — any
# user payload without ``_ygg_original_hex`` falls back to a best-effort
# scratch rebuild.


_ADN_FOOTER_LEN = 14


def _encode_bcd_swapped_digits(digits: str, *, byte_length: int) -> bytes:
    """Pack decimal digits as BCD with TS 31.102 nibble-swap and 0xF padding."""

    cleaned = "".join(ch for ch in str(digits or "") if ch.isdigit())
    if len(cleaned) > byte_length * 2:
        raise RoundtripEncoderError(
            f"dialling digits: {len(cleaned)} > {byte_length * 2} nibbles"
        )
    out = bytearray(b"\xFF" * byte_length)
    for pair_index in range(byte_length):
        nibble_low_pos = pair_index * 2
        nibble_high_pos = nibble_low_pos + 1
        low = 0x0F if nibble_low_pos >= len(cleaned) else int(cleaned[nibble_low_pos])
        high = 0x0F if nibble_high_pos >= len(cleaned) else int(cleaned[nibble_high_pos])
        out[pair_index] = ((high & 0x0F) << 4) | (low & 0x0F)
    return bytes(out)


def _parse_hex_byte_text(value: Any, *, label: str) -> int:
    text = str(value or "").strip()
    if len(text) == 0:
        raise RoundtripEncoderError(f"{label}: empty value")
    if text.lower().startswith("0x"):
        text = text[2:]
    if len(text) != 2 or any(ch not in "0123456789abcdefABCDEF" for ch in text):
        raise RoundtripEncoderError(
            f"{label}: expected a single hex byte (e.g. '0x81'), got {value!r}"
        )
    return int(text, 16)


def _encode_alpha_identifier(
    alpha: str,
    *,
    alpha_len: int,
) -> bytes:
    """Best-effort alpha-id rewrite, padded with 0xFF."""

    if alpha_len <= 0:
        return b""
    try:
        encoded = str(alpha or "").encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RoundtripEncoderError(f"alphaIdentifier: {exc}") from exc
    if len(encoded) > alpha_len:
        raise RoundtripEncoderError(
            f"alphaIdentifier: {len(encoded)} bytes exceeds alpha slot of {alpha_len}"
        )
    return encoded + (b"\xFF" * (alpha_len - len(encoded)))


def _decoded_alpha_equals_original(original_alpha_bytes: bytes, alpha_text: str) -> bool:
    """Return ``True`` when the decoder's UTF-8 strip-and-trim of the alpha
    bytes matches the text currently in the decoded payload.

    Used to avoid rewriting alpha bytes when the user didn't actually edit
    them — UTF-8 decoding drops trailing ``0x00``/``0xFF`` padding which we
    must preserve byte-for-byte otherwise.
    """

    reference = original_alpha_bytes.decode("utf-8", "ignore").strip("\x00").strip()
    return reference == str(alpha_text or "")


def encode_ef_adn_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Splice an ADN/FDN/SDN record using the decoded + original bytes."""

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) == 0:
        raise RoundtripEncoderError(
            "ADN splicer requires '_ygg_original_hex' (original record bytes) "
            "to preserve CCI and alpha padding. Open the record via the decoded "
            "editor instead of pasting a bare decoded payload."
        )
    try:
        original = bytes.fromhex(original_hex)
    except ValueError as exc:
        raise RoundtripEncoderError(f"ADN splicer: invalid original hex ({exc})") from exc
    if len(original) < _ADN_FOOTER_LEN + 1:
        raise RoundtripEncoderError(
            f"ADN splicer: original record must be >= {_ADN_FOOTER_LEN + 1} bytes"
        )
    alpha_len = len(original) - _ADN_FOOTER_LEN
    original_alpha = original[:alpha_len]
    original_footer = bytearray(original[alpha_len:])

    if "alphaIdentifier" in payload:
        alpha_text = str(payload.get("alphaIdentifier", "") or "")
        if _decoded_alpha_equals_original(original_alpha, alpha_text):
            alpha_bytes = bytes(original_alpha)
        else:
            alpha_bytes = _encode_alpha_identifier(alpha_text, alpha_len=alpha_len)
    else:
        alpha_bytes = bytes(original_alpha)

    number_len = original_footer[0]
    if "numberLength" in payload:
        new_len = payload.get("numberLength")
        if isinstance(new_len, bool) or isinstance(new_len, int) is False:
            raise RoundtripEncoderError("ADN splicer: numberLength must be an integer")
        if not 0 <= int(new_len) <= 0xFF:
            raise RoundtripEncoderError("ADN splicer: numberLength must fit in 1 byte")
        number_len = int(new_len)

    ton_npi = original_footer[1]
    if "tonNpi" in payload:
        ton_npi = _parse_hex_byte_text(payload.get("tonNpi"), label="ADN tonNpi")

    number_bytes = bytes(original_footer[2:12])
    if "number" in payload:
        number_bytes = _encode_bcd_swapped_digits(
            str(payload.get("number", "") or ""),
            byte_length=10,
        )

    cci_byte = original_footer[12]
    if "capabilityConfigurationIdentifier" in payload:
        cci_byte = _parse_hex_byte_text(
            payload.get("capabilityConfigurationIdentifier"),
            label="ADN CCI",
        )

    ext_byte = original_footer[13]
    if "extensionRecordIdentifier" in payload:
        ext_byte = _parse_hex_byte_text(
            payload.get("extensionRecordIdentifier"),
            label="ADN extensionRecordIdentifier",
        )

    footer = bytes([number_len, ton_npi]) + number_bytes + bytes([cci_byte, ext_byte])
    spliced = alpha_bytes + footer
    # ADN record length is fixed per file; the editor target_length must
    # match the original unless the caller explicitly overrode it.
    effective_target = target_length
    if effective_target is None:
        effective_target = len(original)
    if len(spliced) != effective_target:
        raise RoundtripEncoderError(
            f"ADN splicer: produced {len(spliced)} bytes, expected {effective_target}"
        )
    return spliced


_SMSP_FOOTER_LEN = 28


def encode_ef_smsp_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Splice an SMSP parameter record using the decoded + original bytes."""

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) == 0:
        raise RoundtripEncoderError(
            "SMSP splicer requires '_ygg_original_hex' (original record bytes) "
            "to preserve alpha-id padding. Open the record via the decoded "
            "editor instead of pasting a bare decoded payload."
        )
    try:
        original = bytes.fromhex(original_hex)
    except ValueError as exc:
        raise RoundtripEncoderError(f"SMSP splicer: invalid original hex ({exc})") from exc
    if len(original) < _SMSP_FOOTER_LEN:
        raise RoundtripEncoderError(
            f"SMSP splicer: original record must be >= {_SMSP_FOOTER_LEN} bytes"
        )
    alpha_len = len(original) - _SMSP_FOOTER_LEN
    original_alpha = original[:alpha_len]
    footer = bytearray(original[alpha_len:])

    if "alphaIdentifier" in payload:
        alpha_text = str(payload.get("alphaIdentifier", "") or "")
        if _decoded_alpha_equals_original(original_alpha, alpha_text):
            alpha_bytes = bytes(original_alpha)
        else:
            alpha_bytes = _encode_alpha_identifier(alpha_text, alpha_len=alpha_len)
    else:
        alpha_bytes = bytes(original_alpha)

    if "parameterIndicators" in payload:
        footer[0] = _parse_hex_byte_text(
            payload.get("parameterIndicators"),
            label="SMSP parameterIndicators",
        )
    if "tpDestinationAddress" in payload:
        dest_hex = _require_hex(payload, "tpDestinationAddress")
        if len(dest_hex) != 24:
            raise RoundtripEncoderError(
                "SMSP tpDestinationAddress: must be 12 bytes (24 hex chars)"
            )
        footer[1:13] = bytes.fromhex(dest_hex)
    if "serviceCenterAddress" in payload:
        sc_hex = _require_hex(payload, "serviceCenterAddress")
        if len(sc_hex) != 24:
            raise RoundtripEncoderError(
                "SMSP serviceCenterAddress: must be 12 bytes (24 hex chars)"
            )
        footer[13:25] = bytes.fromhex(sc_hex)
    if "tpPid" in payload:
        footer[25] = _parse_hex_byte_text(payload.get("tpPid"), label="SMSP tpPid")
    if "tpDcs" in payload:
        footer[26] = _parse_hex_byte_text(payload.get("tpDcs"), label="SMSP tpDcs")
    if "tpValidity" in payload:
        footer[27] = _parse_hex_byte_text(
            payload.get("tpValidity"),
            label="SMSP tpValidity",
        )

    spliced = alpha_bytes + bytes(footer)
    effective_target = target_length
    if effective_target is None:
        effective_target = len(original)
    if len(spliced) != effective_target:
        raise RoundtripEncoderError(
            f"SMSP splicer: produced {len(spliced)} bytes, expected {effective_target}"
        )
    return spliced


_ARR_ACCESS_MODE_FLAGS: tuple[tuple[int, str], ...] = (
    (0x01, "READ"),
    (0x02, "UPDATE"),
    (0x04, "APPEND"),
    (0x08, "DEACTIVATE"),
    (0x10, "ACTIVATE"),
    (0x40, "TERMINATE"),
)


def _encode_arr_access_mode_byte(modes: Any) -> bytes:
    if isinstance(modes, list) is False:
        raise RoundtripEncoderError(
            "ARR rule: accessModes must be a list (use [] for default)."
        )
    byte_value = 0
    name_to_bit: dict[str, int] = {name: bit for bit, name in _ARR_ACCESS_MODE_FLAGS}
    for entry in modes:
        name = str(entry or "").strip()
        if len(name) == 0:
            continue
        if name.startswith("Proprietary(") and name.endswith(")"):
            hex_token = name[len("Proprietary(") : -1].strip()
            try:
                byte_value |= int(hex_token, 16) & 0xFF
            except ValueError as exc:
                raise RoundtripEncoderError(
                    f"ARR rule: invalid Proprietary token {name!r}"
                ) from exc
            continue
        if name not in name_to_bit:
            raise RoundtripEncoderError(
                f"ARR rule: unknown access mode {name!r}"
            )
        byte_value |= name_to_bit[name]
    return bytes([byte_value])


def _encode_arr_tlv(tag_hex: str, value_bytes: bytes) -> bytes:
    try:
        tag = bytes.fromhex(tag_hex)
    except ValueError as exc:
        raise RoundtripEncoderError(
            f"ARR rule: invalid tag {tag_hex!r}"
        ) from exc
    if len(tag) == 0:
        raise RoundtripEncoderError("ARR rule: TLV tag must not be empty")
    # EF.ARR rules never exceed short-form length in practice, but fall back
    # to the shared BER-TLV length helper if a caller hands us > 127 bytes.
    if len(value_bytes) < 0x80:
        length_bytes = bytes([len(value_bytes)])
    else:
        from .saip_json_codec import _encode_ber_tlv_length
        length_bytes = _encode_ber_tlv_length(len(value_bytes))
    return tag + length_bytes + value_bytes


def _encode_arr_items(items: Any) -> bytes:
    """Re-emit the inner TLVs of an ``A4`` security condition wrapper."""

    if isinstance(items, list) is False:
        return b""
    accumulator = bytearray()
    for item in items:
        if isinstance(item, dict) is False:
            continue
        tag = str(item.get("tag") or "").strip()
        raw_value = item.get("raw") or item.get("value") or ""
        hex_text = str(raw_value).strip().upper()
        if len(tag) == 0 or (len(hex_text) % 2) != 0:
            continue
        try:
            value_bytes = bytes.fromhex(hex_text)
        except ValueError as exc:
            raise RoundtripEncoderError(
                f"ARR items: invalid hex under tag {tag!r}: {exc}"
            ) from exc
        accumulator.extend(_encode_arr_tlv(tag, value_bytes))
    return bytes(accumulator)


_ARR_CONDITION_KEY_REFERENCE: dict[str, int] = {
    "PIN1": 0x01,
    "PIN2": 0x81,
    "ADM1": 0x0A,
    "ADM2": 0x0B,
    "ADM3": 0x0C,
    "ADM4": 0x0D,
}


def _default_arr_items_for_condition(condition: str) -> list[dict[str, str]]:
    key_ref = _ARR_CONDITION_KEY_REFERENCE.get(str(condition or "").strip().upper())
    if key_ref is None:
        return []
    return [{"tag": "83", "raw": f"{key_ref:02X}"}]


def _encode_arr_rules_from_scratch(rules: list[dict[str, Any]]) -> bytes:
    accumulator = bytearray()
    last_access_byte: bytes | None = None
    for rule in rules:
        if isinstance(rule, dict) is False:
            raise RoundtripEncoderError("ARR rule: each rule must be a dict")
        access_byte = _encode_arr_access_mode_byte(rule.get("accessModes", []))
        if access_byte != last_access_byte:
            accumulator.extend(_encode_arr_tlv("80", access_byte))
            last_access_byte = access_byte
        command_header = rule.get("commandHeader")
        if isinstance(command_header, str) and len(command_header) > 0:
            accumulator.extend(
                _encode_arr_tlv("84", bytes.fromhex(str(command_header).strip()))
            )
            continue
        condition = str(rule.get("condition") or "").strip()
        if condition == "Always":
            accumulator.extend(_encode_arr_tlv("90", b""))
            continue
        if condition == "Never":
            accumulator.extend(_encode_arr_tlv("97", b""))
            continue
        items_value = rule.get("items")
        if isinstance(items_value, list) is False or len(items_value) == 0:
            items_value = _default_arr_items_for_condition(condition)
        accumulator.extend(_encode_arr_tlv("A4", _encode_arr_items(items_value)))
    return bytes(accumulator)


def encode_ef_arr_rules(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Splice an EF.ARR record preserving original bytes when decoded stream
    hasn't changed, otherwise re-emitting the rule stream from the decoded
    ``rules`` list and padding to ``target_length`` with ``0xFF``."""

    rules = payload.get("rules")
    if isinstance(rules, list) is False:
        raise RoundtripEncoderError("ARR splicer: 'rules' must be a list")

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) > 0:
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""
        if len(original_bytes) > 0:
            # If the decoded form of the original still matches the payload
            # rules exactly, preserve the original bytes byte-for-byte. This
            # avoids churn from non-canonical tag orderings in the source.
            from .saip_asn1_decode import _decode_ef_arr  # local import: avoid cycles
            reference = _decode_ef_arr(original_hex)
            if isinstance(reference, dict):
                reference_rules = reference.get("rules") or []
                if reference_rules == rules:
                    if target_length is None or len(original_bytes) == target_length:
                        return original_bytes

    rebuilt = _encode_arr_rules_from_scratch(rules)
    if target_length is None:
        return rebuilt
    if len(rebuilt) > target_length:
        raise RoundtripEncoderError(
            f"ARR splicer: rebuilt {len(rebuilt)} bytes exceeds target {target_length}"
        )
    return rebuilt + (b"\xFF" * (target_length - len(rebuilt)))


# ---------------------------------------------------------------------------
# Tier 1 — straightforward roundtripable EFs (SPN, MSISDN, ECC, PUCT, LOCI,
# OPL, PNN and the three service tables).


def encode_ef_spn(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SPN (TS 31.102 §4.2.12): 1-byte display condition + UTF-8
    provider name padded with ``0xFF``. ``raw`` is accepted as a last-resort
    passthrough for non-ASCII alphabets the decoder rendered lossily."""

    display_condition = payload.get("displayCondition")
    if display_condition is not None:
        display_byte = _parse_hex_byte_text(display_condition, label="EF.SPN displayCondition")
    else:
        # Legacy payloads sometimes only carry the two decoded flags.
        display_byte = 0
        if bool(payload.get("displayInHplmnRequired", False)) is False:
            display_byte |= 0x01
        if bool(payload.get("hideInOplmnIfEquivalentPlmn", False)):
            display_byte |= 0x02
    if "serviceProviderName" in payload:
        name_bytes = str(payload.get("serviceProviderName", "") or "").encode("utf-8")
        data = bytes([display_byte]) + name_bytes
    elif "raw" in payload and isinstance(payload["raw"], str):
        data = _hex_to_bytes(_require_hex(payload, "raw"))
    else:
        raise RoundtripEncoderError(
            "EF.SPN: provide 'serviceProviderName' (+ 'displayCondition') or 'raw'"
        )
    return _pad_ff(data, target_length=target_length)


def encode_ef_msisdn_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.MSISDN (TS 31.102 §4.2.26): identical footer layout to ADN
    so we reuse the ADN splicer (including CCI + alpha passthrough)."""

    return encode_ef_adn_record(payload, target_length=target_length)


def encode_ef_ecc(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.ECC (TS 31.102 §4.2.24): list of 3-byte BCD emergency
    codes, padded with ``FFFFFF`` repeat blocks up to ``target_length``.

    Note: the decoder exposes only the BCD digits; the 2-octet category
    byte + alpha identifier per entry (R99+ format) are NOT preserved.
    Pass ``_ygg_original_hex`` to preserve them alongside the edited codes."""

    codes = payload.get("emergencyCodes")
    if isinstance(codes, list) is False:
        if "raw" in payload and isinstance(payload["raw"], str):
            data = _hex_to_bytes(_require_hex(payload, "raw"))
            return _pad_ff(data, target_length=target_length)
        raise RoundtripEncoderError(
            "EF.ECC: provide 'emergencyCodes' (list of decimal strings) or 'raw'"
        )

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    original_blocks: list[bytes] = []
    if len(original_hex) > 0:
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""
        for offset in range(0, len(original_bytes), 3):
            block = original_bytes[offset : offset + 3]
            if len(block) == 3:
                original_blocks.append(block)

    accumulator = bytearray()
    for index, digits in enumerate(codes):
        code_text = str(digits or "").strip()
        if code_text == "":
            accumulator.extend(b"\xFF\xFF\xFF")
            continue
        if any(ch.isdigit() is False for ch in code_text):
            raise RoundtripEncoderError(
                f"EF.ECC: code {code_text!r} must contain decimal digits only"
            )
        if len(code_text) > 6:
            raise RoundtripEncoderError(
                f"EF.ECC: code {code_text!r} exceeds 6 BCD digits"
            )
        # Preserve the original BCD block when the user didn't actually
        # edit this entry — safer than re-packing padding nibbles.
        if index < len(original_blocks):
            reference_digits = _decode_bcd_digits_local(original_blocks[index])
            if reference_digits == code_text:
                accumulator.extend(original_blocks[index])
                continue
        accumulator.extend(_encode_bcd_swapped_digits(code_text, byte_length=3))

    # Pad any untouched trailing blocks with the original bytes when we
    # have them — preserves the vendor's category byte layout for the
    # common R99+ MSISDN-style footer.
    consumed_blocks = len(codes)
    while consumed_blocks < len(original_blocks):
        accumulator.extend(original_blocks[consumed_blocks])
        consumed_blocks += 1

    return _pad_ff(bytes(accumulator), target_length=target_length)


def _decode_bcd_digits_local(block: bytes) -> str:
    """Inline re-implementation of the decoder's BCD helper."""

    digits: list[str] = []
    for byte_value in block:
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        if low != 0x0F:
            digits.append(str(low))
        if high != 0x0F:
            digits.append(str(high))
    return "".join(digits)


def encode_ef_puct(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.PUCT (TS 31.102 §4.2.18): 3-byte ASCII currency + 2-byte
    packed EPPU/exponent."""

    currency = str(payload.get("currency", "") or "").strip()
    if "raw" in payload and currency == "" and "eppu" not in payload:
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    if len(currency.encode("ascii", "ignore")) != 3:
        # Allow hex fallback for currency when the original decoder
        # rendered it as hex (non-printable ASCII).
        if len(currency) == 6 and all(ch in "0123456789ABCDEFabcdef" for ch in currency):
            currency_bytes = bytes.fromhex(currency)
        else:
            raise RoundtripEncoderError(
                f"EF.PUCT: currency {currency!r} must be 3 ASCII chars or 6 hex nibbles"
            )
    else:
        currency_bytes = currency.encode("ascii")
    if "eppu" not in payload and "exponent" not in payload:
        raise RoundtripEncoderError(
            "EF.PUCT: provide 'eppu' + 'exponent' (or 'raw')"
        )
    eppu = _require_int(payload, "eppu")
    exponent = _require_int_signed(payload, "exponent")
    if not 0 <= eppu <= 0xFFF:
        raise RoundtripEncoderError("EF.PUCT: eppu must fit in 12 bits")
    if not -7 <= exponent <= 7:
        raise RoundtripEncoderError("EF.PUCT: exponent must be in -7..+7")
    sign_bit = 0x08 if exponent < 0 else 0x00
    exp_nibble = (sign_bit | (abs(exponent) & 0x07)) & 0x0F
    byte3 = (eppu >> 4) & 0xFF
    byte4 = ((exp_nibble & 0x0F) << 4) | (eppu & 0x0F)
    data = currency_bytes + bytes([byte3, byte4])
    return _pad_ff(data, target_length=target_length)


def _require_int_signed(payload: dict[str, Any], key: str) -> int:
    if key not in payload:
        raise RoundtripEncoderError(f"missing required field {key!r}")
    value = payload[key]
    if isinstance(value, bool):
        raise RoundtripEncoderError(f"field {key!r} must be an integer, not bool")
    if isinstance(value, int):
        return int(value)
    text = str(value or "").strip()
    if text.lstrip("-+").isdigit() is False:
        raise RoundtripEncoderError(f"field {key!r} must be a signed integer")
    return int(text)


_LOCI_STATUS_CODES: dict[str, int] = {
    "Updated": 0x00,
    "Not Updated": 0x01,
    "PLMN not allowed": 0x02,
    "Location area not allowed": 0x03,
}


def encode_ef_loci(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.LOCI / EF.PSLOCI / EF.EPSLOCI (TS 31.102 §4.2.17 / §4.2.21
    / §4.2.23): 11 bytes (TMSI[4] + LAI[5] + LAC[2]? + status[1]).

    Layout according to the decoder:
      raw[0:4]   = TMSI (4 bytes)
      raw[4:7]   = LAI  (3 TBCD bytes)
      raw[7:9]   = LAC  (2 bytes)
      raw[9]     = reserved / routing area code (opaque)
      raw[10]    = status byte (low 2 bits)
    """

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    original_bytes: bytes = b""
    if len(original_hex) > 0:
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""

    # The decoder never exposes the routing area / reserved byte at
    # offset 9; fall back to original or 0xFF when absent.
    if len(original_bytes) >= 10:
        reserved_byte = original_bytes[9]
    else:
        reserved_byte = 0xFF

    tmsi_text = str(payload.get("tmsi", "") or "").strip()
    if len(tmsi_text) != 8 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in tmsi_text
    ):
        raise RoundtripEncoderError(
            "EF.LOCI: 'tmsi' must be exactly 4 bytes (8 hex chars)"
        )
    tmsi_bytes = bytes.fromhex(tmsi_text)

    lai_field = str(payload.get("lai", "") or "").strip()
    if len(lai_field) == 6 and all(
        ch in "0123456789ABCDEFabcdef" for ch in lai_field
    ):
        lai_bytes = bytes.fromhex(lai_field)
    elif "-" in lai_field or lai_field.isdigit():
        lai_bytes = _encode_plmn_hex(lai_field)
    else:
        raise RoundtripEncoderError(
            "EF.LOCI: 'lai' must be 'MCC-MNC' or 6 hex nibbles"
        )

    lac_text = str(payload.get("lac", "") or "").strip()
    if len(lac_text) != 4 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in lac_text
    ):
        raise RoundtripEncoderError(
            "EF.LOCI: 'lac' must be exactly 2 bytes (4 hex chars)"
        )
    lac_bytes = bytes.fromhex(lac_text)

    status_text = str(payload.get("status", "") or "").strip()
    if status_text in _LOCI_STATUS_CODES:
        status_byte = _LOCI_STATUS_CODES[status_text]
    elif status_text.lower().startswith("0x"):
        status_byte = _parse_hex_byte_text(status_text, label="EF.LOCI status")
    else:
        raise RoundtripEncoderError(
            f"EF.LOCI: unknown status {status_text!r}; use "
            f"{sorted(_LOCI_STATUS_CODES.keys())!r} or '0xNN'"
        )

    data = tmsi_bytes + lai_bytes + lac_bytes + bytes([reserved_byte, status_byte])
    return _pad_ff(data, target_length=target_length)


def encode_ef_opl_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.OPL record (TS 31.102 §4.2.59): 3 TBCD PLMN + 2-byte
    LAC range start + 2-byte LAC range end + 1-byte PNN record identifier."""

    if "raw" in payload and "plmn" not in payload:
        data = _hex_to_bytes(_require_hex(payload, "raw"))
        return _pad_ff(data, target_length=target_length)
    plmn_bytes = _encode_plmn_hex(str(payload.get("plmn", "") or ""))
    for key in ("lacStart", "lacEnd"):
        if key not in payload:
            raise RoundtripEncoderError(f"EF.OPL: missing required field {key!r}")
    lac_start_text = str(payload.get("lacStart", "") or "").strip()
    lac_end_text = str(payload.get("lacEnd", "") or "").strip()
    if len(lac_start_text) != 4 or len(lac_end_text) != 4:
        raise RoundtripEncoderError(
            "EF.OPL: 'lacStart' and 'lacEnd' must be 2-byte hex strings (4 nibbles)"
        )
    try:
        lac_start = bytes.fromhex(lac_start_text)
        lac_end = bytes.fromhex(lac_end_text)
    except ValueError as exc:
        raise RoundtripEncoderError(f"EF.OPL: invalid LAC hex ({exc})") from exc
    pnn_id_raw = payload.get("pnnRecordIdentifier")
    if isinstance(pnn_id_raw, bool) or isinstance(pnn_id_raw, int) is False:
        raise RoundtripEncoderError(
            "EF.OPL: 'pnnRecordIdentifier' must be a non-negative integer"
        )
    if not 0 <= int(pnn_id_raw) <= 0xFF:
        raise RoundtripEncoderError(
            "EF.OPL: 'pnnRecordIdentifier' must fit in one byte"
        )
    data = plmn_bytes + lac_start + lac_end + bytes([int(pnn_id_raw)])
    return _pad_ff(data, target_length=target_length)


def _encode_tlv_primitive(tag_hex: str, payload_bytes: bytes) -> bytes:
    try:
        tag = bytes.fromhex(tag_hex)
    except ValueError as exc:
        raise RoundtripEncoderError(f"invalid TLV tag {tag_hex!r}") from exc
    if len(payload_bytes) < 0x80:
        length = bytes([len(payload_bytes)])
    else:
        from .saip_json_codec import _encode_ber_tlv_length
        length = _encode_ber_tlv_length(len(payload_bytes))
    return tag + length + payload_bytes


def encode_ef_pnn_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.PNN record (TS 31.102 §4.2.58): TLV stream containing
    a 0x43 full-name TLV (network-coding-dependent) and an optional 0x45
    short-name TLV.

    The decoded form does NOT preserve the full-name coding scheme byte
    (0x80 / 0x81 prefix), so when ``_ygg_original_hex`` is provided we
    preserve the original TLV bytes as-is unless the decoded text changed.
    """

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) > 0:
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""
        if len(original_bytes) > 0:
            from .saip_asn1_decode import _decode_pnn_record
            reference = _decode_pnn_record(original_hex)
            if isinstance(reference, dict):
                if (
                    reference.get("fullName") == payload.get("fullName")
                    and reference.get("shortName") == payload.get("shortName")
                ):
                    if target_length is None or len(original_bytes) == target_length:
                        return original_bytes

    accumulator = bytearray()
    if "fullName" in payload:
        full_bytes = str(payload.get("fullName", "") or "").encode("utf-8")
        accumulator.extend(_encode_tlv_primitive("43", full_bytes))
    if "shortName" in payload:
        short_bytes = str(payload.get("shortName", "") or "").encode("utf-8")
        accumulator.extend(_encode_tlv_primitive("45", short_bytes))
    if len(accumulator) == 0:
        if "raw" in payload and isinstance(payload["raw"], str):
            return _pad_ff(
                _hex_to_bytes(_require_hex(payload, "raw")),
                target_length=target_length,
            )
        raise RoundtripEncoderError(
            "EF.PNN: provide 'fullName' / 'shortName' or 'raw'"
        )
    return _pad_ff(bytes(accumulator), target_length=target_length)


def _encode_service_table_bitmap(
    active_services: Any,
    *,
    original_bytes: bytes,
) -> bytes:
    """Recompute the service-table bitmap from a list of ``N: Service name``
    strings. Preserves the original byte length when no higher service
    number is enabled."""

    if isinstance(active_services, list) is False:
        raise RoundtripEncoderError(
            "service table: 'activeServices' must be a list of 'N: name' strings"
        )
    enabled: set[int] = set()
    for entry in active_services:
        text = str(entry or "").strip()
        if len(text) == 0:
            continue
        head, _, _ = text.partition(":")
        head = head.strip()
        if head.isdigit() is False:
            raise RoundtripEncoderError(
                f"service table: entry {entry!r} must start with 'N:'"
            )
        service_number = int(head)
        if service_number < 1:
            raise RoundtripEncoderError(
                "service table: service numbers must be >= 1"
            )
        enabled.add(service_number)
    highest = max(enabled) if len(enabled) > 0 else 0
    required_bytes = (highest + 7) // 8
    byte_length = max(len(original_bytes), required_bytes)
    if byte_length == 0:
        return b""
    buffer = bytearray(byte_length)
    for service_number in enabled:
        zero_based = service_number - 1
        byte_index = zero_based // 8
        bit_index = zero_based % 8
        if byte_index >= len(buffer):
            continue
        buffer[byte_index] |= 1 << bit_index
    return bytes(buffer)


def encode_ef_service_table(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.UST / EF.EST / EF.IST service-table payload.

    Accepts either:
      - ``raw`` / ``hex`` — used verbatim (useful for non-editable reloads).
      - ``activeServices`` — list of ``"<number>: <name>"`` strings as
        produced by the decoder.

    The existing hand-written ``service_table`` editor in
    ``saip_decoded_edit`` remains the primary UI; this encoder exists so
    that the round-trip dispatcher can handle the decoded dict shape."""

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) == 0 and isinstance(payload.get("hex"), str):
        original_hex = str(payload["hex"]).strip().upper()
    if len(original_hex) == 0 and isinstance(payload.get("raw"), str):
        original_hex = str(payload["raw"]).strip().upper()
    try:
        original_bytes = bytes.fromhex(original_hex) if len(original_hex) > 0 else b""
    except ValueError:
        original_bytes = b""

    if "activeServices" in payload:
        data = _encode_service_table_bitmap(
            payload.get("activeServices"),
            original_bytes=original_bytes,
        )
        return _pad_ff(data, target_length=target_length)

    if len(original_bytes) > 0:
        return _pad_ff(original_bytes, target_length=target_length)

    raise RoundtripEncoderError(
        "service table: provide 'activeServices' or 'raw'"
    )


# ---------------------------------------------------------------------------
# Tier 2 — TLV-structured EFs (PCSCF, SPDI, EPSNSC, SMS, SMSR, DIR).


_PCSCF_ADDRESS_TYPE_CODES: dict[str, int] = {
    "FQDN": 0x00,
    "IPv4": 0x01,
    "IPv6": 0x02,
}


def encode_ef_pcscf_address(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.P-CSCF address (TS 31.103 §4.2.8):
    ``80 <len> <typeByte> <address>``."""

    if "raw" in payload and "address" not in payload and "rawAddress" not in payload:
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    type_name = str(payload.get("addressType", "") or "").strip()
    if type_name in _PCSCF_ADDRESS_TYPE_CODES:
        type_byte = _PCSCF_ADDRESS_TYPE_CODES[type_name]
    elif type_name.lower().startswith("0x"):
        type_byte = _parse_hex_byte_text(type_name, label="PCSCF addressType")
    else:
        raise RoundtripEncoderError(
            f"EF.P-CSCF: unknown addressType {type_name!r}"
        )
    if "address" in payload:
        address_text = str(payload.get("address", "") or "").strip()
        if type_byte == 0x00:
            address_bytes = address_text.encode("utf-8")
        elif type_byte == 0x01:
            parts = address_text.split(".")
            if len(parts) != 4 or any(part.isdigit() is False for part in parts):
                raise RoundtripEncoderError(
                    "EF.P-CSCF: IPv4 address must be dotted quad"
                )
            try:
                octets = [int(part) for part in parts]
            except ValueError as exc:
                raise RoundtripEncoderError(f"EF.P-CSCF IPv4: {exc}") from exc
            if any(octet < 0 or octet > 255 for octet in octets):
                raise RoundtripEncoderError("EF.P-CSCF: IPv4 octet out of range")
            address_bytes = bytes(octets)
        elif type_byte == 0x02:
            try:
                address_bytes = ipaddress_packed_bytes(address_text)
            except ValueError as exc:
                raise RoundtripEncoderError(f"EF.P-CSCF IPv6: {exc}") from exc
        else:
            raise RoundtripEncoderError(
                f"EF.P-CSCF: cannot encode address as type 0x{type_byte:02X}"
            )
    elif "rawAddress" in payload:
        address_bytes = _hex_to_bytes(_require_hex(payload, "rawAddress"))
    else:
        raise RoundtripEncoderError(
            "EF.P-CSCF: provide 'address' or 'rawAddress'"
        )
    tlv_value = bytes([type_byte]) + address_bytes
    data = _encode_tlv_primitive("80", tlv_value)
    return _pad_ff(data, target_length=target_length)


def ipaddress_packed_bytes(address: str) -> bytes:
    import ipaddress
    return ipaddress.IPv6Address(address).packed


def encode_ef_spdi(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SPDI (TS 31.102 §4.2.66): ``A3 <len> 80 <len> <PLMN list>``.

    The decoded form exposes a ``serviceProviderPlmnList`` of MCC-MNC
    strings; when present and non-empty the encoder rebuilds the TLV
    stream verbatim. If ``_ygg_original_hex`` is provided and the decoded
    list still matches, the original bytes are returned byte-for-byte
    (which also keeps any vendor ``items`` the re-encoder cannot model)."""

    plmn_list = payload.get("serviceProviderPlmnList")
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) > 0 and isinstance(plmn_list, list):
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""
        if len(original_bytes) > 0:
            from .saip_asn1_decode import _decode_spdi
            reference = _decode_spdi(original_hex)
            if (
                isinstance(reference, dict)
                and reference.get("serviceProviderPlmnList") == plmn_list
            ):
                if target_length is None or len(original_bytes) == target_length:
                    return original_bytes

    if isinstance(plmn_list, list) is False:
        if "raw" in payload and isinstance(payload["raw"], str):
            return _pad_ff(
                _hex_to_bytes(_require_hex(payload, "raw")),
                target_length=target_length,
            )
        raise RoundtripEncoderError(
            "EF.SPDI: provide 'serviceProviderPlmnList' (list of MCC-MNC) or 'raw'"
        )
    plmn_buffer = bytearray()
    for entry in plmn_list:
        plmn_buffer.extend(_encode_plmn_hex(str(entry or "")))
    inner = _encode_tlv_primitive("80", bytes(plmn_buffer))
    data = _encode_tlv_primitive("A3", inner)
    return _pad_ff(data, target_length=target_length)


def encode_ef_eps_nas_security_context(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.EPSNSC (TS 31.102 §4.2.101): ``KSI header(1) + KASME(16)
    + optional remainder``."""

    if "raw" in payload and "ksiHeader" not in payload:
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    if "ksiHeader" not in payload:
        raise RoundtripEncoderError(
            "EF.EPSNSC: provide 'ksiHeader' + 'kasmeFirst16Bytes' or 'raw'"
        )
    ksi_byte = _parse_hex_byte_text(payload["ksiHeader"], label="EF.EPSNSC ksiHeader")
    kasme_hex = str(payload.get("kasmeFirst16Bytes", "") or "").strip()
    if kasme_hex == "":
        kasme_bytes = b""
    else:
        if len(kasme_hex) != 32 or any(ch not in "0123456789ABCDEFabcdef" for ch in kasme_hex):
            raise RoundtripEncoderError(
                "EF.EPSNSC: 'kasmeFirst16Bytes' must be exactly 16 bytes (32 hex chars)"
            )
        kasme_bytes = bytes.fromhex(kasme_hex)
    remainder_hex = str(payload.get("remainder", "") or "").strip()
    if remainder_hex == "":
        remainder_bytes = b""
    elif len(remainder_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in remainder_hex
    ):
        raise RoundtripEncoderError(
            "EF.EPSNSC: 'remainder' must be a hex string with even length"
        )
    else:
        remainder_bytes = bytes.fromhex(remainder_hex)
    data = bytes([ksi_byte]) + kasme_bytes + remainder_bytes
    return _pad_ff(data, target_length=target_length)


_SMS_RECORD_STATE_CODES: dict[str, int] = {
    "Free": 0x00,
    "Received read": 0x01,
    "Received unread": 0x03,
    "Stored sent": 0x05,
    "Stored unsent": 0x07,
}


def encode_ef_sms_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SMS record (TS 31.102 §4.2.25): 1-byte status + opaque
    TP-DU payload preserved verbatim from the decoded ``tpduHex``."""

    if "recordStatus" in payload:
        status_byte = _parse_hex_byte_text(
            payload.get("recordStatus"),
            label="EF.SMS recordStatus",
        )
    elif "recordState" in payload:
        state_name = str(payload.get("recordState", "") or "").strip()
        if state_name not in _SMS_RECORD_STATE_CODES:
            raise RoundtripEncoderError(
                f"EF.SMS: unknown recordState {state_name!r}"
            )
        status_byte = _SMS_RECORD_STATE_CODES[state_name]
    elif "raw" in payload and isinstance(payload["raw"], str):
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    else:
        raise RoundtripEncoderError(
            "EF.SMS: provide 'recordStatus' or 'recordState' or 'raw'"
        )
    tpdu_text = str(payload.get("tpduHex", "") or "").strip()
    if tpdu_text == "":
        tpdu_bytes = b""
    elif len(tpdu_text) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in tpdu_text
    ):
        raise RoundtripEncoderError(
            "EF.SMS: 'tpduHex' must be an even-length hex string"
        )
    else:
        tpdu_bytes = bytes.fromhex(tpdu_text)
    data = bytes([status_byte]) + tpdu_bytes
    return _pad_ff(data, target_length=target_length)


def encode_ef_sms_status_report(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SMSR record (TS 31.102 §4.2.28): 1-byte identifier +
    opaque status-report TPDU."""

    if "recordIdentifier" not in payload and "raw" in payload:
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    record_id = payload.get("recordIdentifier")
    if isinstance(record_id, bool) or isinstance(record_id, int) is False:
        raise RoundtripEncoderError(
            "EF.SMSR: 'recordIdentifier' must be a non-negative integer"
        )
    if not 0 <= int(record_id) <= 0xFF:
        raise RoundtripEncoderError(
            "EF.SMSR: 'recordIdentifier' must fit in one byte"
        )
    tpdu_text = str(payload.get("statusReportTpdu", "") or "").strip()
    if tpdu_text == "":
        tpdu_bytes = b""
    elif len(tpdu_text) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in tpdu_text
    ):
        raise RoundtripEncoderError(
            "EF.SMSR: 'statusReportTpdu' must be an even-length hex string"
        )
    else:
        tpdu_bytes = bytes.fromhex(tpdu_text)
    data = bytes([int(record_id)]) + tpdu_bytes
    return _pad_ff(data, target_length=target_length)


def _encode_dir_item(item: dict[str, Any]) -> bytes:
    tag = str(item.get("tag") or "").strip()
    if len(tag) == 0:
        raise RoundtripEncoderError("EF.DIR: each item must carry a 'tag'")
    raw_value = item.get("raw")
    if isinstance(raw_value, str) and len(raw_value) > 0:
        hex_text = str(raw_value).strip()
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                f"EF.DIR tag {tag!r}: 'raw' must be a hex string"
            )
        return _encode_tlv_primitive(tag, bytes.fromhex(hex_text))
    # Nested constructed templates keep their child TLVs in 'items'.
    nested = item.get("items")
    if isinstance(nested, list):
        inner = bytearray()
        for child in nested:
            if isinstance(child, dict) is False:
                continue
            inner.extend(_encode_dir_item(child))
        return _encode_tlv_primitive(tag, bytes(inner))
    raise RoundtripEncoderError(
        f"EF.DIR tag {tag!r}: missing 'raw' hex and 'items' list"
    )


# ---------------------------------------------------------------------------
# Round 1: file-structure field encoders (filePath, linkPath,
# fileDescriptor, specialFileInformation, fillPattern, repeatPattern,
# fileDetails). These invert the matching ``_decode_*`` helpers in
# ``saip_asn1_decode`` for primitive OCTET STRING values.


def _path_bytes_from_segments(segments: Any, *, field_label: str) -> bytes:
    if isinstance(segments, list) is False:
        raise RoundtripEncoderError(
            f"{field_label}: 'segments' must be a list of {{'fid': 'NNNN'}} objects"
        )
    accumulator = bytearray()
    for segment in segments:
        if isinstance(segment, dict) is False:
            raise RoundtripEncoderError(
                f"{field_label}: each segment must be a dict"
            )
        fid_text = str(segment.get("fid", "") or "").strip()
        if len(fid_text) != 4 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in fid_text
        ):
            raise RoundtripEncoderError(
                f"{field_label}: segment 'fid' must be 4 hex characters (got {fid_text!r})"
            )
        accumulator.extend(bytes.fromhex(fid_text))
    return bytes(accumulator)


def _encode_path_field(payload: dict[str, Any], *, field_label: str) -> bytes:
    """Shared encoder for ``filePath`` / ``linkPath``. Empty-hex with
    ``independentFile = True`` collapses back to the zero-length path."""

    if bool(payload.get("independentFile", False)):
        return b""
    if "segments" in payload:
        return _path_bytes_from_segments(payload.get("segments"), field_label=field_label)
    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if hex_text == "":
            return b""
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                f"{field_label}: 'hex' must be an even-length hex string"
            )
        return bytes.fromhex(hex_text)
    raise RoundtripEncoderError(
        f"{field_label}: provide 'segments' list, 'hex' string, or 'independentFile: true'"
    )


def encode_file_path(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_file_path``. Empty bytes means 'MF'."""

    return _encode_path_field(payload, field_label="filePath")


def encode_link_path(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_link_path``. Empty bytes means 'independent file'."""

    return _encode_path_field(payload, field_label="linkPath")


def encode_file_descriptor(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_file_descriptor``.

    The decoder exposes both structured fields (shareable/fileType/
    structure + descriptor coding byte + optional recordLength /
    numberOfRecords) and the raw ``hex``. We prefer the raw form when
    present (byte-exact round-trip); otherwise we recompose the descriptor
    byte from the structured fields.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "fileDescriptor: 'hex' must be an even-length hex string"
                )
            value_bytes = bytes.fromhex(hex_text)
            if len(value_bytes) < 2:
                raise RoundtripEncoderError(
                    "fileDescriptor: 'hex' must be at least 2 bytes"
                )
            return value_bytes
    file_type = str(payload.get("fileType", "") or "").strip()
    structure = str(payload.get("structure", "") or "").strip()
    shareable = bool(payload.get("shareable", False))
    if structure == "ber_tlv":
        descriptor_byte = 0x39
    else:
        type_bits = {
            "working_ef": 0,
            "internal_ef": 1,
            "df": 7,
        }
        structure_bits = {
            "no_info_given": 0,
            "transparent": 1,
            "linear_fixed": 2,
            "cyclic": 6,
        }
        if file_type not in type_bits or structure not in structure_bits:
            raise RoundtripEncoderError(
                "fileDescriptor: provide 'hex' or ('fileType' + 'structure' + "
                "'shareable') with recognised enum values"
            )
        descriptor_byte = (type_bits[file_type] << 3) | structure_bits[structure]
    if shareable:
        descriptor_byte |= 0x40
    coding_byte = _parse_hex_byte_text(
        payload.get("descriptorCodingByte", "0x21"),
        label="fileDescriptor descriptorCodingByte",
    )
    buffer = bytearray([descriptor_byte, coding_byte])
    record_length = payload.get("recordLength")
    number_of_records = payload.get("numberOfRecords")
    if isinstance(record_length, int) and isinstance(record_length, bool) is False:
        if not 0 <= record_length <= 0xFFFF:
            raise RoundtripEncoderError(
                "fileDescriptor: recordLength must fit in 2 bytes"
            )
        buffer.extend(int(record_length).to_bytes(2, "big"))
        if isinstance(number_of_records, int) and isinstance(number_of_records, bool) is False:
            if not 0 <= number_of_records <= 0xFF:
                raise RoundtripEncoderError(
                    "fileDescriptor: numberOfRecords must fit in 1 byte"
                )
            buffer.append(int(number_of_records))
    return bytes(buffer)


def encode_special_file_information(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_special_file_information``. Prefers the raw
    ``decimal``/``hex`` byte; else recomposes from the two decoded flags."""

    if "decimal" in payload:
        value = payload["decimal"]
        if isinstance(value, bool) or isinstance(value, int) is False:
            raise RoundtripEncoderError(
                "specialFileInformation: 'decimal' must be an integer"
            )
        if not 0 <= int(value) <= 0xFF:
            raise RoundtripEncoderError(
                "specialFileInformation: 'decimal' must fit in one byte"
            )
        return bytes([int(value)])
    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) != 2 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                "specialFileInformation: 'hex' must be exactly 1 byte (2 nibbles)"
            )
        return bytes.fromhex(hex_text)
    byte_value = 0
    if bool(payload.get("highUpdateActivity", False)):
        byte_value |= 0x80
    if bool(payload.get("readAndUpdateWhenDeactivated", False)):
        byte_value |= 0x40
    return bytes([byte_value])


def _encode_arbitrary_pattern(payload: dict[str, Any], *, field_label: str) -> bytes:
    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) == 0:
            raise RoundtripEncoderError(
                f"{field_label}: 'hex' must not be empty"
            )
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                f"{field_label}: 'hex' must be an even-length hex string"
            )
        return bytes.fromhex(hex_text)
    if "ascii" in payload and isinstance(payload["ascii"], str):
        return str(payload["ascii"]).encode("ascii", "strict")
    if "byteValue" in payload:
        byte_value = _parse_hex_byte_text(
            payload.get("byteValue"),
            label=f"{field_label} byteValue",
        )
        return bytes([byte_value])
    raise RoundtripEncoderError(
        f"{field_label}: provide 'hex', 'ascii', or 'byteValue'"
    )


def encode_fill_pattern(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_fill_pattern(repeat_pattern=False)``."""

    return _encode_arbitrary_pattern(payload, field_label="fillPattern")


def encode_repeat_pattern(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_fill_pattern(repeat_pattern=True)``."""

    return _encode_arbitrary_pattern(payload, field_label="repeatPattern")


def encode_file_details(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_file_details``. One byte (0x01 = DER coding)."""

    if "decimal" in payload:
        value = payload["decimal"]
        if isinstance(value, bool) or isinstance(value, int) is False:
            raise RoundtripEncoderError(
                "fileDetails: 'decimal' must be an integer"
            )
        if not 0 <= int(value) <= 0xFF:
            raise RoundtripEncoderError(
                "fileDetails: 'decimal' must fit in one byte"
            )
        return bytes([int(value)])
    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) != 2 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                "fileDetails: 'hex' must be exactly 1 byte (2 nibbles)"
            )
        return bytes.fromhex(hex_text)
    coding = str(payload.get("coding", "") or "").strip()
    if coding == "DER coding":
        return bytes([0x01])
    raise RoundtripEncoderError(
        "fileDetails: provide 'decimal', 'hex', or 'coding'"
    )


# ---------------------------------------------------------------------------
# Round 3: PIN/PUK/key-material bytes fields.


def encode_pin_secret_value(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_pin_secret_value``. The decoder strips trailing
    0xFF padding but preserves the count via ``paddingHex``; the encoder
    restores it exactly."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "pinValue/pukValue: 'hex' must be an even-length hex string"
                )
            return bytes.fromhex(hex_text)
    padding_hex = str(payload.get("paddingHex", "") or "").strip()
    if len(padding_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in padding_hex
    ):
        raise RoundtripEncoderError(
            "pinValue/pukValue: 'paddingHex' must be an even-length hex string"
        )
    padding_bytes = bytes.fromhex(padding_hex) if len(padding_hex) > 0 else b""
    if "digits" in payload and isinstance(payload["digits"], str):
        digits = str(payload["digits"]).strip()
        if digits.isdigit() is False:
            raise RoundtripEncoderError(
                "pinValue/pukValue: 'digits' must be ASCII decimal"
            )
        content = digits.encode("ascii")
    elif "ascii" in payload and isinstance(payload["ascii"], str):
        content = str(payload["ascii"]).encode("ascii", "strict")
    else:
        raise RoundtripEncoderError(
            "pinValue/pukValue: provide 'hex', or 'digits'/'ascii' + 'paddingHex'"
        )
    return content + padding_bytes


def encode_key_data(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_key_data``. Verbatim passthrough of ``hex``."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) == 0:
            raise RoundtripEncoderError("keyData: 'hex' must not be empty")
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                "keyData: 'hex' must be an even-length hex string"
            )
        return bytes.fromhex(hex_text)
    raise RoundtripEncoderError("keyData: 'hex' is required")


def encode_pin_status_template_do(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_pin_status_template_do``.

    The decoded form may carry either a full TLV ``items`` list (when the
    PS-template starts with a known tag) or a flat ``statusBytes`` +
    optional trailing key reference. We prefer verbatim ``hex`` when
    present, otherwise we re-emit the TLV stream or flat bytes from the
    decoded fields.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "pinStatusTemplateDO: 'hex' must be an even-length hex string"
                )
            return bytes.fromhex(hex_text)
    items = payload.get("items")
    if isinstance(items, list) and len(items) > 0:
        accumulator = bytearray()
        for item in items:
            if isinstance(item, dict) is False:
                continue
            tag = str(item.get("tag") or "").strip()
            if len(tag) == 0:
                raise RoundtripEncoderError(
                    "pinStatusTemplateDO: each item must carry a 'tag'"
                )
            raw = str(item.get("raw") or "").strip()
            if len(raw) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in raw
            ):
                raise RoundtripEncoderError(
                    f"pinStatusTemplateDO: item {tag!r} 'raw' must be hex"
                )
            inner_bytes = bytes.fromhex(raw) if len(raw) > 0 else b""
            accumulator.extend(_encode_tlv_primitive(tag, inner_bytes))
        return bytes(accumulator)
    status_hex = str(payload.get("statusBytes", "") or "").strip()
    if status_hex != "":
        if len(status_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in status_hex
        ):
            raise RoundtripEncoderError(
                "pinStatusTemplateDO: 'statusBytes' must be an even-length hex string"
            )
        result = bytearray(bytes.fromhex(status_hex))
        key_reference = payload.get("keyReference")
        if isinstance(key_reference, dict) and "decimal" in key_reference:
            decimal = key_reference.get("decimal")
            if isinstance(decimal, int) and isinstance(decimal, bool) is False:
                if 0 <= int(decimal) <= 0xFF:
                    result.append(int(decimal))
        return bytes(result)
    raise RoundtripEncoderError(
        "pinStatusTemplateDO: provide 'hex', 'items', or 'statusBytes'"
    )


# ---------------------------------------------------------------------------
# Round 4: install parameters + connectivity parameters (BER-TLV / length-
# prefixed structures whose decoders are lossless at the byte level).


def encode_connectivity_parameters(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_connectivity_parameters``. The decoded form
    preserves the TLV stream under ``items``; we re-emit each item via
    its tag+raw pair. A verbatim ``hex`` passthrough is accepted."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "connectivityParameters: 'hex' must be an even-length hex string"
                )
            return bytes.fromhex(hex_text)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError(
            "connectivityParameters: provide 'hex' or 'items'"
        )
    return _encode_decoded_ber_items(items, field_label="connectivityParameters")


def _encode_decoded_ber_items(items: list[Any], *, field_label: str) -> bytes:
    accumulator = bytearray()
    for item in items:
        if isinstance(item, dict) is False:
            continue
        tag = str(item.get("tag") or item.get("tagHex") or "").strip()
        if len(tag) == 0:
            raise RoundtripEncoderError(
                f"{field_label}: each item must carry a 'tag'"
            )
        inner_bytes = _decoded_ber_inner_bytes(item, field_label=field_label)
        accumulator.extend(_encode_tlv_primitive(tag, inner_bytes))
    return bytes(accumulator)


def _decoded_ber_inner_bytes(item: dict[str, Any], *, field_label: str) -> bytes:
    # When the operator edited the semantic 'decoded' fields (e.g.
    # PID decimal), synthesise bytes from those fields. The encoding
    # mirrors the value decoders in saip_asn1_decode so the round-trip
    # is lossless when only decoded fields are changed.
    decoded = item.get("decoded")
    if isinstance(decoded, dict) and len(decoded) > 0:
        raw_bytes = _encode_decoded_connectivity_primitive(decoded, field_label=field_label)
        if raw_bytes is not None:
            return raw_bytes
    raw_value = item.get("raw")
    if isinstance(raw_value, str) and len(raw_value) > 0:
        hex_text = str(raw_value).strip()
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                f"{field_label}: 'raw' must be an even-length hex string"
            )
        return bytes.fromhex(hex_text)
    nested = item.get("items")
    if isinstance(nested, list):
        return _encode_decoded_ber_items(nested, field_label=field_label)
    return b""


def _encode_decoded_connectivity_primitive(
    decoded: dict[str, Any],
    *,
    field_label: str,
) -> bytes | None:
    """Encode a connectivity sub-field from its semantic decoded form.

    Handles the value-decoders declared in ``_decode_connectivity_parameters``:
    PID (single-byte integer), DCS (single-byte integer), SMSC address, bearer
    description, and small integer. Returns ``None`` when the decoded shape is
    not recognised, signalling the caller to fall back to ``raw``.
    """
    if "decimal" in decoded:
        value = int(decoded["decimal"])
        if value < 0 or value > 255:
            raise RoundtripEncoderError(
                f"{field_label}: 'decimal' must be in 0..255 for a connectivity primitive"
            )
        return bytes([value])
    return None


def encode_sd_install_parameters(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_sd_install_parameters``."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "applicationSpecificParametersC9: 'hex' must be even-length hex"
                )
            return bytes.fromhex(hex_text)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError(
            "applicationSpecificParametersC9: provide 'hex' or 'items'"
        )
    return _encode_decoded_ber_items(
        items,
        field_label="applicationSpecificParametersC9",
    )


def encode_uicc_toolkit_parameters(payload: dict[str, Any]) -> bytes:
    """Inverse of ``_decode_uicc_toolkit_parameters``.

    The decoder exposes a parsed view of the flat ETSI TS 102 226 record
    but also keeps the original bytes under ``rawHex``; we prefer that
    verbatim path. Callers wanting to edit individual fields should set
    ``rawHex`` to an empty string and populate the structured fields; in
    that case we re-pack the record end-to-end.
    """

    raw_hex = str(payload.get("rawHex", "") or "").strip()
    if len(raw_hex) > 0:
        if len(raw_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in raw_hex
        ):
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'rawHex' must be even-length hex"
            )
        return bytes.fromhex(raw_hex)

    try:
        access_domain_hex = str(payload.get("accessDomain", "") or "").strip()
        if len(access_domain_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in access_domain_hex
        ):
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'accessDomain' must be hex"
            )
        access_domain = bytes.fromhex(access_domain_hex) if len(access_domain_hex) > 0 else b""
        if len(access_domain) > 0xFF:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: access domain > 255 bytes"
            )
        priority = _require_byte_field(payload, "priorityLevelOfToolkitAppInstance")
        max_timers = _require_byte_field(payload, "maxNumberOfTimers")
        max_text = _require_byte_field(payload, "maxTextLengthForMenuEntry")
        menu_entries = payload.get("menuEntries") or []
        if isinstance(menu_entries, list) is False:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'menuEntries' must be a list"
            )
        if len(menu_entries) > 0xFF:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: menuEntries > 255"
            )
        max_channels = _require_byte_field(payload, "maxNumberOfChannels")
        msl_hex = str(payload.get("minimumSecurityLevelRaw", "") or "").strip()
        if len(msl_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in msl_hex
        ):
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'minimumSecurityLevelRaw' must be hex"
            )
        msl_bytes = bytes.fromhex(msl_hex) if len(msl_hex) > 0 else b""
        if len(msl_bytes) > 0xFF:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: MSL length > 255 bytes"
            )
        tar_values = payload.get("tarValues") or []
        if isinstance(tar_values, list) is False:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'tarValues' must be a list"
            )
        tar_bytes = bytearray()
        for tar in tar_values:
            tar_hex = str(tar or "").strip()
            if len(tar_hex) != 6 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in tar_hex
            ):
                raise RoundtripEncoderError(
                    f"uiccToolkitApplicationSpecificParametersField: TAR {tar!r} must be 3 bytes (6 hex)"
                )
            tar_bytes.extend(bytes.fromhex(tar_hex))
        if len(tar_bytes) > 0xFF:
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: TAR block > 255 bytes"
            )

        menu_bytes = bytearray()
        for entry in menu_entries:
            if isinstance(entry, dict) is False:
                raise RoundtripEncoderError(
                    "uiccToolkitApplicationSpecificParametersField: each menu entry must be a dict"
                )
            entry_id = entry.get("id")
            position = entry.get("position")
            if (
                isinstance(entry_id, bool)
                or isinstance(entry_id, int) is False
                or isinstance(position, bool)
                or isinstance(position, int) is False
            ):
                raise RoundtripEncoderError(
                    "uiccToolkitApplicationSpecificParametersField: menu entry id/position must be ints"
                )
            if not (0 <= int(entry_id) <= 0xFF and 0 <= int(position) <= 0xFF):
                raise RoundtripEncoderError(
                    "uiccToolkitApplicationSpecificParametersField: menu id/position must fit in 1 byte"
                )
            menu_bytes.append(int(entry_id))
            menu_bytes.append(int(position))

        trailing_hex = str(payload.get("trailingPadding", "") or "").strip()
        if len(trailing_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in trailing_hex
        ):
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: 'trailingPadding' must be hex"
            )
        trailing_bytes = bytes.fromhex(trailing_hex) if len(trailing_hex) > 0 else b""
        if any(byte_value != 0x00 for byte_value in trailing_bytes):
            raise RoundtripEncoderError(
                "uiccToolkitApplicationSpecificParametersField: trailingPadding must be zero bytes"
            )

        buffer = bytearray()
        buffer.append(len(access_domain))
        buffer.extend(access_domain)
        buffer.append(priority)
        buffer.append(max_timers)
        buffer.append(max_text)
        buffer.append(len(menu_entries))
        buffer.extend(menu_bytes)
        buffer.append(max_channels)
        buffer.append(len(msl_bytes))
        buffer.extend(msl_bytes)
        buffer.append(len(tar_bytes))
        buffer.extend(tar_bytes)
        buffer.extend(trailing_bytes)
        return bytes(buffer)
    except KeyError as exc:
        raise RoundtripEncoderError(
            f"uiccToolkitApplicationSpecificParametersField: missing field {exc}"
        ) from exc


def _require_byte_field(payload: dict[str, Any], key: str) -> int:
    if key not in payload:
        raise RoundtripEncoderError(f"missing required field {key!r}")
    value = payload[key]
    if isinstance(value, bool) or isinstance(value, int) is False:
        raise RoundtripEncoderError(f"field {key!r} must be a non-negative integer")
    if not 0 <= int(value) <= 0xFF:
        raise RoundtripEncoderError(f"field {key!r} must fit in one byte")
    return int(value)


# ---------------------------------------------------------------------------
# Round 2: PKCS#15 EFs (ODF/DODF/ACM/ACCF). The decoders render a lossy
# summary (object-type buckets, path/reference lists, hash buckets), so
# every encoder here accepts a mandatory ``hex`` passthrough and treats
# the decoded summary fields as read-only. Dedicated editors can round-
# trip the raw DER bytes while still giving the user a structured preview.


def _encode_pkcs15_passthrough(
    payload: dict[str, Any],
    *,
    field_label: str,
    target_length: int | None = None,
) -> bytes:
    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    f"{field_label}: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip()
    if len(original_hex) > 0:
        if len(original_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in original_hex
        ):
            raise RoundtripEncoderError(
                f"{field_label}: '_ygg_original_hex' must be even-length hex"
            )
        return _pad_ff(bytes.fromhex(original_hex), target_length=target_length)
    raise RoundtripEncoderError(
        f"{field_label}: provide 'hex' (raw PKCS#15 DER bytes). The decoded "
        "view is lossy; use the raw-hex editor to rewrite the DER stream."
    )


def encode_ef_pkcs15_odf(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a PKCS#15 ODF (EF 5031) — raw DER passthrough."""

    return _encode_pkcs15_passthrough(
        payload,
        field_label="PKCS#15 ODF",
        target_length=target_length,
    )


def encode_ef_pkcs15_dodf(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a PKCS#15 DODF (EF 5207) — raw DER passthrough."""

    return _encode_pkcs15_passthrough(
        payload,
        field_label="PKCS#15 DODF",
        target_length=target_length,
    )


def encode_ef_pkcs15_acm(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a PKCS#15 ACM (EF 4200) — raw DER passthrough."""

    return _encode_pkcs15_passthrough(
        payload,
        field_label="PKCS#15 ACM",
        target_length=target_length,
    )


def encode_ef_pkcs15_accf(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a PKCS#15 ACCF (EF 4310) — raw DER passthrough."""

    return _encode_pkcs15_passthrough(
        payload,
        field_label="PKCS#15 ACCF",
        target_length=target_length,
    )


# ---------------------------------------------------------------------------
# Round 5: common 3GPP EFs that previously had no decoder (GID1, GID2,
# CBMI, CBMID, CBMIR). Each pairs with the matching ``_decode_*`` in
# ``saip_asn1_decode`` added at the same time.


def encode_ef_group_identifier(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.GID1 / EF.GID2. The payload may carry:

    - ``hex``          — verbatim bytes (preferred).
    - ``ascii``        — ASCII content; padded to ``target_length`` with 0xFF.
    - ``_ygg_original_hex`` — fall back when no other field is present.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.GID: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    if "ascii" in payload and isinstance(payload["ascii"], str):
        content = str(payload["ascii"]).encode("ascii", "strict")
        padding_hex = str(payload.get("paddingHex", "") or "").strip()
        if len(padding_hex) > 0:
            if len(padding_hex) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in padding_hex
            ):
                raise RoundtripEncoderError(
                    "EF.GID: 'paddingHex' must be an even-length hex string"
                )
            content = content + bytes.fromhex(padding_hex)
        return _pad_ff(content, target_length=target_length)
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip()
    if len(original_hex) > 0:
        if len(original_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in original_hex
        ):
            raise RoundtripEncoderError(
                "EF.GID: '_ygg_original_hex' must be even-length hex"
            )
        return _pad_ff(bytes.fromhex(original_hex), target_length=target_length)
    raise RoundtripEncoderError(
        "EF.GID: provide 'hex', 'ascii', or '_ygg_original_hex'"
    )


def _encode_cbmi_entries(
    payload: dict[str, Any],
    *,
    item_bytes: int,
    field_label: str,
    target_length: int | None,
) -> bytes:
    """Shared encoder body for EF.CBMI/CBMID (item_bytes=2) and EF.CBMIR
    (item_bytes=4)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    f"{field_label}: 'hex' must be an even-length hex string"
                )
            encoded = bytes.fromhex(hex_text)
            if len(encoded) % item_bytes != 0:
                raise RoundtripEncoderError(
                    f"{field_label}: 'hex' must be a multiple of {item_bytes} bytes"
                )
            return _pad_ff(encoded, target_length=target_length)
    entries = payload.get("entries")
    if isinstance(entries, list) is False:
        raise RoundtripEncoderError(
            f"{field_label}: provide 'hex' or 'entries' list"
        )
    accumulator = bytearray()
    for entry in entries:
        if isinstance(entry, dict) is False:
            raise RoundtripEncoderError(
                f"{field_label}: each entry must be a dict"
            )
        entry_hex = str(entry.get("hex", "") or "").strip()
        if len(entry_hex) > 0:
            if len(entry_hex) != item_bytes * 2 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in entry_hex
            ):
                raise RoundtripEncoderError(
                    f"{field_label}: entry 'hex' must be {item_bytes} bytes ({item_bytes * 2} nibbles)"
                )
            accumulator.extend(bytes.fromhex(entry_hex))
            continue
        if bool(entry.get("unused", False)):
            accumulator.extend(b"\xFF" * item_bytes)
            continue
        if item_bytes == 2:
            if "code" not in entry:
                raise RoundtripEncoderError(
                    f"{field_label}: entry without 'hex' needs 'code' or 'unused'"
                )
            code = entry["code"]
            if isinstance(code, bool) or isinstance(code, int) is False:
                raise RoundtripEncoderError(
                    f"{field_label}: 'code' must be an integer"
                )
            if not 0 <= int(code) <= 0xFFFF:
                raise RoundtripEncoderError(
                    f"{field_label}: 'code' must fit in 16 bits"
                )
            accumulator.extend(int(code).to_bytes(2, "big"))
        else:
            lower = entry.get("lower")
            upper = entry.get("upper")
            if (
                isinstance(lower, bool)
                or isinstance(lower, int) is False
                or isinstance(upper, bool)
                or isinstance(upper, int) is False
            ):
                raise RoundtripEncoderError(
                    f"{field_label}: entry needs integer 'lower' + 'upper'"
                )
            if not (0 <= int(lower) <= 0xFFFF and 0 <= int(upper) <= 0xFFFF):
                raise RoundtripEncoderError(
                    f"{field_label}: 'lower'/'upper' must fit in 16 bits"
                )
            accumulator.extend(int(lower).to_bytes(2, "big"))
            accumulator.extend(int(upper).to_bytes(2, "big"))
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_cbmi(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.CBMI / EF.CBMID."""

    return _encode_cbmi_entries(
        payload,
        item_bytes=2,
        field_label="EF.CBMI",
        target_length=target_length,
    )


def encode_ef_cbmir(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.CBMIR."""

    return _encode_cbmi_entries(
        payload,
        item_bytes=4,
        field_label="EF.CBMIR",
        target_length=target_length,
    )


# ---------------------------------------------------------------------------
# 5x5 Pass A: call/phonebook + keys + network/config + 5G + obscure EFs.
# Every encoder pairs with the matching ``_decode_*`` helper added in the
# same commit to ``saip_asn1_decode``. Opaque EFs (CMI, S7, SUME, NETPAR,
# CPBCCH, PKCS#15 ACRF) use a hex passthrough; structured records rebuild
# the exact bytes from the decoded view.


def encode_ef_lnd_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.LND record. Identical structure to ADN, so we reuse
    the ADN splicer which preserves CCI and alpha padding verbatim."""

    return encode_ef_adn_record(payload, target_length=target_length)


def encode_ef_ici_oci_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.ICI / EF.OCI record.

    The ADN-like prefix is spliced via the ADN encoder; the trailing
    timestamp/duration/status/link-timer block comes from the decoded
    ``trailerHex`` or individual ``trailerFields`` entries.
    """

    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) == 0:
        raise RoundtripEncoderError(
            "ICI/OCI splicer requires '_ygg_original_hex' (original record bytes)"
        )
    try:
        original = bytes.fromhex(original_hex)
    except ValueError as exc:
        raise RoundtripEncoderError(
            f"ICI/OCI splicer: invalid original hex ({exc})"
        ) from exc

    trailer_hex = str(payload.get("trailerHex", "") or "").strip()
    if len(trailer_hex) > 0:
        if len(trailer_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in trailer_hex
        ):
            raise RoundtripEncoderError(
                "ICI/OCI splicer: 'trailerHex' must be even-length hex"
            )
        trailer_bytes = bytes.fromhex(trailer_hex)
    elif isinstance(payload.get("trailerFields"), dict):
        trailer_fields = payload["trailerFields"]
        chunks: list[bytes] = []
        for field_name, field_hex in trailer_fields.items():
            text = str(field_hex or "").strip()
            if len(text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in text
            ):
                raise RoundtripEncoderError(
                    f"ICI/OCI splicer: trailer field {field_name!r} must be hex"
                )
            chunks.append(bytes.fromhex(text))
        trailer_bytes = b"".join(chunks)
    else:
        # Fall back to the verbatim trailer slice of the original record.
        # The decoded view always carries trailerHex when available, so
        # this branch only fires if a caller dropped it.
        raise RoundtripEncoderError(
            "ICI/OCI splicer: provide 'trailerHex' or 'trailerFields'"
        )

    effective_target = target_length if target_length is not None else len(original)
    adn_prefix_length = effective_target - len(trailer_bytes)
    if adn_prefix_length <= 0:
        raise RoundtripEncoderError(
            "ICI/OCI splicer: trailer consumes the whole record"
        )
    prefix_original = original[:adn_prefix_length]
    prefix_payload = dict(payload)
    prefix_payload["_ygg_original_hex"] = prefix_original.hex().upper()
    for drop_key in ("trailerHex", "trailerFields", "format"):
        prefix_payload.pop(drop_key, None)
    prefix_bytes = encode_ef_adn_record(
        prefix_payload,
        target_length=adn_prefix_length,
    )
    result = prefix_bytes + trailer_bytes
    if len(result) != effective_target:
        raise RoundtripEncoderError(
            f"ICI/OCI splicer: produced {len(result)} bytes, expected {effective_target}"
        )
    return result


def encode_ef_extension_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.EXT1 / EXT2 / EXT3 record (13 bytes)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) == 26 and all(
            ch in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            encoded = bytes.fromhex(hex_text)
            if target_length is None or target_length == len(encoded):
                return encoded
    record_type = _parse_hex_byte_text(
        payload.get("recordType", "0x00"),
        label="extension recordType",
    )
    data_hex = str(payload.get("extensionDataHex", "") or "").strip()
    if len(data_hex) == 0:
        data_hex = "FF" * 11
    if len(data_hex) != 22 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in data_hex
    ):
        raise RoundtripEncoderError(
            "extension record: 'extensionDataHex' must be exactly 11 bytes (22 nibbles)"
        )
    extension_data = bytes.fromhex(data_hex)
    identifier = _parse_hex_byte_text(
        payload.get("identifier", "0x00"),
        label="extension identifier",
    )
    result = bytes([record_type]) + extension_data + bytes([identifier])
    if target_length is not None and target_length != len(result):
        raise RoundtripEncoderError(
            f"extension record: produced {len(result)} bytes, expected {target_length}"
        )
    return result


def encode_ef_ccp_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a Capability Configuration Parameters record (15 bytes)."""

    hex_text = str(payload.get("bearerCapabilityHex", payload.get("hex", "")) or "").strip()
    if len(hex_text) == 30 and all(
        ch in "0123456789ABCDEFabcdef" for ch in hex_text
    ):
        encoded = bytes.fromhex(hex_text)
        if target_length is None or target_length == len(encoded):
            return encoded
    raise RoundtripEncoderError(
        "CCP record: provide 'bearerCapabilityHex' or 'hex' of exactly 15 bytes"
    )


def encode_ef_usim_keys_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.KEYS / EF.KEYSPS (33 bytes: KSI + CK + IK)."""

    hex_text = str(payload.get("hex", "") or "").strip()
    if len(hex_text) == 66 and all(
        ch in "0123456789ABCDEFabcdef" for ch in hex_text
    ):
        encoded = bytes.fromhex(hex_text)
        if target_length is None or target_length == len(encoded):
            return encoded
    ksi = _parse_hex_byte_text(payload.get("ksi", payload.get("ksiDecimal", 0x07)), label="KEYS ksi")
    ciphering_hex = str(payload.get("cipheringKeyHex", "") or "").strip()
    integrity_hex = str(payload.get("integrityKeyHex", "") or "").strip()
    if len(ciphering_hex) != 32 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in ciphering_hex
    ):
        raise RoundtripEncoderError(
            "EF.KEYS: 'cipheringKeyHex' must be exactly 16 bytes (32 nibbles)"
        )
    if len(integrity_hex) != 32 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in integrity_hex
    ):
        raise RoundtripEncoderError(
            "EF.KEYS: 'integrityKeyHex' must be exactly 16 bytes (32 nibbles)"
        )
    result = bytes([ksi]) + bytes.fromhex(ciphering_hex) + bytes.fromhex(integrity_hex)
    if target_length is not None and target_length != len(result):
        raise RoundtripEncoderError(
            f"EF.KEYS: produced {len(result)} bytes, expected {target_length}"
        )
    return result


def encode_ef_gsm_kc_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.KC / EF.KCGPRS (9 bytes: Kc + CKSN)."""

    hex_text = str(payload.get("hex", "") or "").strip()
    if len(hex_text) == 18 and all(
        ch in "0123456789ABCDEFabcdef" for ch in hex_text
    ):
        encoded = bytes.fromhex(hex_text)
        if target_length is None or target_length == len(encoded):
            return encoded
    kc_hex = str(payload.get("kcHex", "") or "").strip()
    if len(kc_hex) != 16 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in kc_hex
    ):
        raise RoundtripEncoderError(
            "EF.KC: 'kcHex' must be exactly 8 bytes (16 nibbles)"
        )
    if "cksnRaw" in payload:
        cksn_byte = _parse_hex_byte_text(payload.get("cksnRaw"), label="CKSN")
    else:
        cksn_value = payload.get("cksn", 0)
        if isinstance(cksn_value, bool) or isinstance(cksn_value, int) is False:
            raise RoundtripEncoderError("EF.KC: 'cksn' must be an integer")
        if not 0 <= int(cksn_value) <= 0xFF:
            raise RoundtripEncoderError("EF.KC: 'cksn' must fit in 1 byte")
        cksn_byte = int(cksn_value)
    result = bytes.fromhex(kc_hex) + bytes([cksn_byte])
    if target_length is not None and target_length != len(result):
        raise RoundtripEncoderError(
            f"EF.KC: produced {len(result)} bytes, expected {target_length}"
        )
    return result


def encode_ef_hidden_key(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.HIDDENKEY (9 bytes: attempts counter + 8-byte hidden key)."""

    hex_text = str(payload.get("hex", "") or "").strip()
    if len(hex_text) == 18 and all(
        ch in "0123456789ABCDEFabcdef" for ch in hex_text
    ):
        encoded = bytes.fromhex(hex_text)
        if target_length is None or target_length == len(encoded):
            return encoded
    if "attemptsRaw" in payload:
        attempts_byte = _parse_hex_byte_text(payload.get("attemptsRaw"), label="HIDDENKEY attempts")
    else:
        attempts_value = payload.get("attemptsRemaining", 0)
        if isinstance(attempts_value, bool) or isinstance(attempts_value, int) is False:
            raise RoundtripEncoderError(
                "EF.HIDDENKEY: 'attemptsRemaining' must be an integer"
            )
        if not 0 <= int(attempts_value) <= 0xFF:
            raise RoundtripEncoderError(
                "EF.HIDDENKEY: 'attemptsRemaining' must fit in one byte"
            )
        attempts_byte = int(attempts_value)
    key_hex = str(payload.get("hiddenKeyHex", "") or "").strip()
    if len(key_hex) != 16 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in key_hex
    ):
        raise RoundtripEncoderError(
            "EF.HIDDENKEY: 'hiddenKeyHex' must be exactly 8 bytes (16 nibbles)"
        )
    result = bytes([attempts_byte]) + bytes.fromhex(key_hex)
    if target_length is not None and target_length != len(result):
        raise RoundtripEncoderError(
            f"EF.HIDDENKEY: produced {len(result)} bytes, expected {target_length}"
        )
    return result


def encode_ef_opaque(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an opaque EF (CMI, S7, SUME, NETPAR, CPBCCH, PKCS#15 ACRF).

    Accepts ``hex`` verbatim or falls back to ``_ygg_original_hex``.
    ``ascii`` is allowed when a string field is stored (padded with 0xFF
    to ``target_length``).
    """

    hex_text = str(payload.get("hex", "") or "").strip()
    if len(hex_text) > 0:
        if len(hex_text) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                "opaque EF: 'hex' must be an even-length hex string"
            )
        return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    if "ascii" in payload and isinstance(payload["ascii"], str):
        return _pad_ff(
            str(payload["ascii"]).encode("ascii", "strict"),
            target_length=target_length,
        )
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip()
    if len(original_hex) > 0:
        if len(original_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in original_hex
        ):
            raise RoundtripEncoderError(
                "opaque EF: '_ygg_original_hex' must be even-length hex"
            )
        return _pad_ff(bytes.fromhex(original_hex), target_length=target_length)
    raise RoundtripEncoderError(
        "opaque EF: provide 'hex', 'ascii', or '_ygg_original_hex'"
    )


def encode_ef_one_byte_indicator(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a single-byte indicator EF (NIA, LRPLMNSI, INVSCAN)."""

    if "decimal" in payload:
        value = payload["decimal"]
        if isinstance(value, bool) or isinstance(value, int) is False:
            raise RoundtripEncoderError(
                "one-byte indicator: 'decimal' must be an integer"
            )
        if not 0 <= int(value) <= 0xFF:
            raise RoundtripEncoderError(
                "one-byte indicator: 'decimal' must fit in one byte"
            )
        result = bytes([int(value)])
    elif "byte" in payload:
        result = bytes([_parse_hex_byte_text(payload.get("byte"), label="indicator byte")])
    elif "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) != 2 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in hex_text
        ):
            raise RoundtripEncoderError(
                "one-byte indicator: 'hex' must be exactly 1 byte (2 nibbles)"
            )
        result = bytes.fromhex(hex_text)
    else:
        raise RoundtripEncoderError(
            "one-byte indicator: provide 'decimal', 'byte', or 'hex'"
        )
    if target_length is not None and target_length != len(result):
        raise RoundtripEncoderError(
            f"one-byte indicator: expected {target_length} bytes, got {len(result)}"
        )
    return result


def encode_ef_nasconfig(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.NASCONFIG — BER-TLV stream."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.NASCONFIG: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError("EF.NASCONFIG: provide 'hex' or 'items'")
    return _pad_ff(
        _encode_decoded_ber_items(items, field_label="EF.NASCONFIG"),
        target_length=target_length,
    )


def encode_ef_suci_calc_info(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SUCI_Calc_Info (TS 31.102 Annex N) — BER-TLV stream."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.SUCI_Calc_Info: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError("EF.SUCI_Calc_Info: provide 'hex' or 'items'")
    return _pad_ff(
        _encode_decoded_ber_items(items, field_label="EF.SUCI_Calc_Info"),
        target_length=target_length,
    )


def encode_ef_supinai(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.SUPI_NAI — ``80 LL <UTF-8 NAI>`` TLV."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.SUPI_NAI: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    if "nai" in payload and isinstance(payload["nai"], str):
        nai_bytes = str(payload["nai"]).encode("utf-8")
        if len(nai_bytes) > 0xFF:
            raise RoundtripEncoderError("EF.SUPI_NAI: NAI exceeds 255 bytes")
        result = bytes([0x80, len(nai_bytes)]) + nai_bytes
        return _pad_ff(result, target_length=target_length)
    raise RoundtripEncoderError("EF.SUPI_NAI: provide 'hex' or 'nai'")


def encode_ef_apn_control_list(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.ACL (TS 31.102 §4.2.48): ``count`` byte followed by an
    opaque BER-TLV stream. Only the count byte is semantically exposed;
    the TLV bytes are passed through from ``tlvBytes``.
    """

    if "raw" in payload and "apnCount" not in payload:
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    count_value = payload.get("apnCount")
    if isinstance(count_value, bool) or isinstance(count_value, int) is False:
        raise RoundtripEncoderError(
            "EF.ACL: 'apnCount' must be a non-negative integer"
        )
    if not 0 <= int(count_value) <= 0xFF:
        raise RoundtripEncoderError("EF.ACL: 'apnCount' must fit in one byte")
    tlv_hex = str(payload.get("tlvBytes", "") or "").strip()
    if tlv_hex == "":
        tlv_bytes = b""
    elif len(tlv_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in tlv_hex
    ):
        raise RoundtripEncoderError(
            "EF.ACL: 'tlvBytes' must be an even-length hex string"
        )
    else:
        tlv_bytes = bytes.fromhex(tlv_hex)
    data = bytes([int(count_value)]) + tlv_bytes
    return _pad_ff(data, target_length=target_length)


def encode_ef_gbanl(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.GBANL (TS 31.102 §4.2.93): ``80 <NAF-Id> 81 <B-TID>`` TLV
    stream. Raw hex passthrough is supported for vendor-extended records.
    """

    if "raw" in payload and ("nafId" not in payload and "bTid" not in payload):
        return _pad_ff(
            _hex_to_bytes(_require_hex(payload, "raw")),
            target_length=target_length,
        )
    accumulator = bytearray()
    if "nafId" in payload:
        naf_hex = str(payload.get("nafId", "") or "").strip()
        if len(naf_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in naf_hex
        ):
            raise RoundtripEncoderError(
                "EF.GBANL: 'nafId' must be an even-length hex string"
            )
        accumulator.extend(_encode_tlv_primitive("80", bytes.fromhex(naf_hex)))
    if "bTid" in payload:
        btid_hex = str(payload.get("bTid", "") or "").strip()
        if len(btid_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in btid_hex
        ):
            raise RoundtripEncoderError(
                "EF.GBANL: 'bTid' must be an even-length hex string"
            )
        accumulator.extend(_encode_tlv_primitive("81", bytes.fromhex(btid_hex)))
    if len(accumulator) == 0:
        raise RoundtripEncoderError(
            "EF.GBANL: provide 'nafId' / 'bTid' or 'raw'"
        )
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_dir_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.DIR record (TS 102 221 §13.1). The decoded form carries
    the TLV stream verbatim under ``items`` (each with its own ``tag`` and
    ``raw`` bytes). Unknown / vendor tags round-trip through their ``raw``
    payload; constructed templates may recurse via a child ``items`` list.

    When ``_ygg_original_hex`` is provided and the decoded items match the
    re-decoded reference we prefer returning the original bytes verbatim.
    """

    items = payload.get("items")
    if isinstance(items, list) is False:
        if "raw" in payload and isinstance(payload["raw"], str):
            return _pad_ff(
                _hex_to_bytes(_require_hex(payload, "raw")),
                target_length=target_length,
            )
        raise RoundtripEncoderError(
            "EF.DIR: provide 'items' (decoded TLV list) or 'raw'"
        )
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip().upper()
    if len(original_hex) > 0:
        try:
            original_bytes = bytes.fromhex(original_hex)
        except ValueError:
            original_bytes = b""
        if len(original_bytes) > 0:
            from .saip_asn1_decode import _decode_ef_dir_record
            reference = _decode_ef_dir_record(original_hex)
            if (
                isinstance(reference, dict)
                and reference.get("items") == items
            ):
                if target_length is None or len(original_bytes) == target_length:
                    return original_bytes

    accumulator = bytearray()
    for item in items:
        if isinstance(item, dict) is False:
            continue
        accumulator.extend(_encode_dir_item(item))
    return _pad_ff(bytes(accumulator), target_length=target_length)


def encode_ef_uri_tlv(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode a generic ``80 LL <UTF-8 URI>`` EF (FDN_URI, SDN_URI, LND_URI,
    TN3GPPSNN, ISIM EHURI / MUDDOMAIN / UICCSI).

    Accepts ``hex`` verbatim, or ``uri``/``nai`` as UTF-8 text, or falls back
    to ``_ygg_original_hex``.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "URI EF: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    uri_text: str | None = None
    for key_name in ("uri", "nai", "text"):
        if key_name in payload and isinstance(payload[key_name], str):
            uri_text = str(payload[key_name])
            break
    if uri_text is not None:
        uri_bytes = uri_text.encode("utf-8")
        if len(uri_bytes) > 0xFF:
            raise RoundtripEncoderError(
                "URI EF: URI exceeds 255 bytes (80-tag length)"
            )
        result = bytes([0x80, len(uri_bytes)]) + uri_bytes
        return _pad_ff(result, target_length=target_length)
    original_hex = str(payload.get("_ygg_original_hex", "") or "").strip()
    if len(original_hex) > 0:
        if len(original_hex) % 2 != 0 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in original_hex
        ):
            raise RoundtripEncoderError(
                "URI EF: '_ygg_original_hex' must be even-length hex"
            )
        return _pad_ff(bytes.fromhex(original_hex), target_length=target_length)
    raise RoundtripEncoderError("URI EF: provide 'hex', 'uri', or '_ygg_original_hex'")


def encode_ef_routing_indicator(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.Routing_Indicator (TS 31.102 §4.4.11.8). 4 bytes."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) != 8 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.Routing_Indicator: 'hex' must be 4 bytes (8 nibbles)"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    ri_text = str(payload.get("routingIndicator", "") or "").strip()
    flag_value = payload.get("flagByteDecimal", payload.get("flagByte"))
    reserved_text = str(payload.get("reservedByte", "0xFF") or "0xFF").strip()
    if len(ri_text) == 0:
        raise RoundtripEncoderError(
            "EF.Routing_Indicator: provide 'hex' or 'routingIndicator'+'flagByte'"
        )
    if len(ri_text) > 4 or any(ch not in "0123456789" for ch in ri_text):
        raise RoundtripEncoderError(
            "EF.Routing_Indicator: 'routingIndicator' must be 1-4 decimal digits"
        )
    padded = ri_text.ljust(4, "F")
    ri_nibbles = bytearray(2)
    for pair_index in range(2):
        low = padded[pair_index * 2]
        high = padded[pair_index * 2 + 1]
        try:
            low_val = int(low, 16)
            high_val = int(high, 16)
        except ValueError as exc:
            raise RoundtripEncoderError(
                f"EF.Routing_Indicator: invalid digit ({exc})"
            ) from exc
        ri_nibbles[pair_index] = (high_val << 4) | low_val
    if isinstance(flag_value, str):
        flag_byte = _parse_hex_byte_text(flag_value, label="flagByte")
    elif isinstance(flag_value, int) and isinstance(flag_value, bool) is False:
        if not 0 <= int(flag_value) <= 0xFF:
            raise RoundtripEncoderError(
                "EF.Routing_Indicator: 'flagByteDecimal' must fit in one byte"
            )
        flag_byte = int(flag_value)
    else:
        raise RoundtripEncoderError(
            "EF.Routing_Indicator: 'flagByte' or 'flagByteDecimal' required"
        )
    reserved_byte = _parse_hex_byte_text(reserved_text, label="reservedByte")
    result = bytes(ri_nibbles) + bytes([flag_byte, reserved_byte])
    return _pad_ff(result, target_length=target_length)


def encode_ef_uac_aic(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.UAC_AIC (TS 31.102 §4.4.11.6). 4 bytes of access-identity
    bitmap; bit (byte*8+bit) is set for each listed identity.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) != 8 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.UAC_AIC: 'hex' must be 4 bytes (8 nibbles)"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    identities = payload.get("accessIdentities")
    if isinstance(identities, list) is False:
        raise RoundtripEncoderError(
            "EF.UAC_AIC: provide 'hex' or 'accessIdentities' list"
        )
    bitmap = bytearray(4)
    for identity in identities:
        if isinstance(identity, bool) or isinstance(identity, int) is False:
            raise RoundtripEncoderError(
                "EF.UAC_AIC: 'accessIdentities' entries must be integers"
            )
        value = int(identity)
        if not 0 <= value < 32:
            raise RoundtripEncoderError(
                "EF.UAC_AIC: access identity must be 0..31"
            )
        bitmap[value // 8] |= 1 << (value % 8)
    return _pad_ff(bytes(bitmap), target_length=target_length)


def encode_ef_opl5g_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode an EF.OPL5G record (10 bytes: PLMN(3) + TAC_start(3) +
    TAC_end(3) + PNN_id(1)).
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) != 20 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.OPL5G: 'hex' must be 10 bytes (20 nibbles)"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    plmn_hex = str(payload.get("plmnHex", "") or "").strip()
    if len(plmn_hex) != 6 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in plmn_hex
    ):
        raise RoundtripEncoderError(
            "EF.OPL5G: 'plmnHex' must be 3 bytes (6 nibbles)"
        )
    tac_start = payload.get("tacStart")
    tac_end = payload.get("tacEnd")
    pnn_id = payload.get("pnnRecordId")
    for field_name, field_value, upper in (
        ("tacStart", tac_start, 0xFFFFFF),
        ("tacEnd", tac_end, 0xFFFFFF),
        ("pnnRecordId", pnn_id, 0xFF),
    ):
        if isinstance(field_value, bool) or isinstance(field_value, int) is False:
            raise RoundtripEncoderError(
                f"EF.OPL5G: {field_name!r} must be a non-negative integer"
            )
        if not 0 <= int(field_value) <= upper:
            raise RoundtripEncoderError(
                f"EF.OPL5G: {field_name!r} out of range"
            )
    result = (
        bytes.fromhex(plmn_hex)
        + int(tac_start).to_bytes(3, "big")
        + int(tac_end).to_bytes(3, "big")
        + bytes([int(pnn_id)])
    )
    return _pad_ff(result, target_length=target_length)


def encode_ef_mwis_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.MWIS record (5 bytes)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) != 10 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.MWIS: 'hex' must be 5 bytes (10 nibbles)"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    indicator_raw = payload.get("indicatorByte")
    if isinstance(indicator_raw, str):
        indicator = _parse_hex_byte_text(indicator_raw, label="indicatorByte")
    else:
        indicator = 0
        for bit_name, mask in (
            ("voicemailWaiting", 0x01),
            ("faxWaiting", 0x02),
            ("emailWaiting", 0x04),
            ("otherWaiting", 0x08),
        ):
            if bool(payload.get(bit_name, False)):
                indicator |= mask
    counters = bytearray(4)
    for index, key_name in enumerate(
        ("voicemailCount", "faxCount", "emailCount", "otherCount")
    ):
        value = payload.get(key_name, 0)
        if isinstance(value, bool) or isinstance(value, int) is False:
            raise RoundtripEncoderError(
                f"EF.MWIS: {key_name!r} must be integer"
            )
        if not 0 <= int(value) <= 0xFF:
            raise RoundtripEncoderError(
                f"EF.MWIS: {key_name!r} out of range"
            )
        counters[index] = int(value)
    result = bytes([indicator]) + bytes(counters)
    return _pad_ff(result, target_length=target_length)


def encode_ef_mbi_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.MBI record — one byte per slot (voicemail/fax/email/other/...)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.MBI: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    slots = payload.get("slots")
    if isinstance(slots, dict) is False:
        raise RoundtripEncoderError("EF.MBI: provide 'hex' or 'slots'")
    slot_order = ("voicemail", "fax", "email", "other")
    out = bytearray()
    for slot_name in slot_order:
        if slot_name in slots:
            value = slots[slot_name]
            if isinstance(value, bool) or isinstance(value, int) is False:
                raise RoundtripEncoderError(
                    f"EF.MBI: slot {slot_name!r} must be integer"
                )
            if not 0 <= int(value) <= 0xFF:
                raise RoundtripEncoderError(
                    f"EF.MBI: slot {slot_name!r} out of range"
                )
            out.append(int(value))
    for extra_key in sorted(
        k for k in slots if k not in slot_order and k.startswith("slot")
    ):
        value = slots[extra_key]
        if isinstance(value, bool) or isinstance(value, int) is False:
            raise RoundtripEncoderError(
                f"EF.MBI: slot {extra_key!r} must be integer"
            )
        out.append(int(value) & 0xFF)
    return _pad_ff(bytes(out), target_length=target_length)


def encode_ef_cfis_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.CFIS / EF.CFIS2 record.

    Semantic fields: ``mspNumber`` (byte 0), ``cfIndicator`` or the four
    ``*ForwardActive`` flags (byte 1). ``tailHex`` carries the remainder
    verbatim for byte-identical round-trip.
    """

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.CFIS: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    msp = payload.get("mspNumber")
    if isinstance(msp, bool) or isinstance(msp, int) is False:
        raise RoundtripEncoderError(
            "EF.CFIS: 'mspNumber' must be an integer"
        )
    if not 0 <= int(msp) <= 0xFF:
        raise RoundtripEncoderError("EF.CFIS: 'mspNumber' must fit in one byte")
    indicator_raw = payload.get("cfIndicator")
    if isinstance(indicator_raw, str):
        indicator = _parse_hex_byte_text(indicator_raw, label="cfIndicator")
    else:
        indicator = 0
        for flag_name, mask in (
            ("voiceForwardActive", 0x01),
            ("faxForwardActive", 0x02),
            ("dataForwardActive", 0x04),
            ("smsForwardActive", 0x08),
        ):
            if bool(payload.get(flag_name, False)):
                indicator |= mask
    tail_hex = str(payload.get("tailHex", "") or "").strip()
    if len(tail_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in tail_hex
    ):
        raise RoundtripEncoderError(
            "EF.CFIS: 'tailHex' must be an even-length hex string"
        )
    tail_bytes = bytes.fromhex(tail_hex)
    result = bytes([int(msp), indicator]) + tail_bytes
    return _pad_ff(result, target_length=target_length)


def encode_ef_emlpp_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.eMLPP record (2 bytes + optional trailer)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.eMLPP: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    supported = 0
    for level in payload.get("supportedPriorityLevels", []) or []:
        if isinstance(level, bool) or isinstance(level, int) is False:
            raise RoundtripEncoderError(
                "EF.eMLPP: 'supportedPriorityLevels' entries must be int"
            )
        if not 0 <= int(level) < 8:
            raise RoundtripEncoderError(
                "EF.eMLPP: priority level out of range (0..7)"
            )
        supported |= 1 << int(level)
    fast_cs = 0
    for level in payload.get("fastCallSetupLevels", []) or []:
        if isinstance(level, bool) or isinstance(level, int) is False:
            raise RoundtripEncoderError(
                "EF.eMLPP: 'fastCallSetupLevels' entries must be int"
            )
        if not 0 <= int(level) < 8:
            raise RoundtripEncoderError(
                "EF.eMLPP: fast-CS level out of range (0..7)"
            )
        fast_cs |= 1 << int(level)
    trailer_hex = str(payload.get("trailerHex", "") or "").strip()
    if len(trailer_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in trailer_hex
    ):
        raise RoundtripEncoderError(
            "EF.eMLPP: 'trailerHex' must be an even-length hex string"
        )
    result = bytes([supported, fast_cs]) + bytes.fromhex(trailer_hex)
    return _pad_ff(result, target_length=target_length)


def encode_ef_aaem_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.AAeM record."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.AAeM: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    bitmap = 0
    for level in payload.get("aaEnabledLevels", []) or []:
        if isinstance(level, bool) or isinstance(level, int) is False:
            raise RoundtripEncoderError(
                "EF.AAeM: 'aaEnabledLevels' entries must be int"
            )
        if not 0 <= int(level) < 8:
            raise RoundtripEncoderError(
                "EF.AAeM: level out of range (0..7)"
            )
        bitmap |= 1 << int(level)
    trailer_hex = str(payload.get("trailerHex", "") or "").strip()
    if len(trailer_hex) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in trailer_hex
    ):
        raise RoundtripEncoderError(
            "EF.AAeM: 'trailerHex' must be an even-length hex string"
        )
    result = bytes([bitmap]) + bytes.fromhex(trailer_hex)
    return _pad_ff(result, target_length=target_length)


def encode_ef_dck_record(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.DCK record (16 bytes = 4 × 4-byte keys)."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) != 32 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.DCK: 'hex' must be 16 bytes (32 nibbles)"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    chunks = bytearray()
    for key_name in (
        "networkKey",
        "networkSubsetKey",
        "serviceProviderKey",
        "corporateKey",
    ):
        key_hex = str(payload.get(key_name, "") or "").strip()
        if len(key_hex) != 8 or any(
            ch not in "0123456789ABCDEFabcdef" for ch in key_hex
        ):
            raise RoundtripEncoderError(
                f"EF.DCK: {key_name!r} must be 4 bytes (8 nibbles)"
            )
        chunks.extend(bytes.fromhex(key_hex))
    return _pad_ff(bytes(chunks), target_length=target_length)


def encode_ef_pbr(
    payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes:
    """Encode EF.PBR — BER-TLV stream identical in shape to EF.NASCONFIG."""

    if "hex" in payload and isinstance(payload["hex"], str):
        hex_text = str(payload["hex"]).strip()
        if len(hex_text) > 0:
            if len(hex_text) % 2 != 0 or any(
                ch not in "0123456789ABCDEFabcdef" for ch in hex_text
            ):
                raise RoundtripEncoderError(
                    "EF.PBR: 'hex' must be an even-length hex string"
                )
            return _pad_ff(bytes.fromhex(hex_text), target_length=target_length)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError("EF.PBR: provide 'hex' or 'items'")
    return _pad_ff(
        _encode_decoded_ber_items(items, field_label="EF.PBR"),
        target_length=target_length,
    )


_EF_CONTENT_DISPATCHER: dict[str, Any] = {
    "ef-acc": encode_ef_acc,
    "ef-ehplmnpi": encode_ef_ehplmnpi,
    "ef-start-hfn": encode_ef_start_hfn,
    "ef-smss": encode_ef_smss,
    "ef-ad": encode_ef_ad,
    "ef-hpplmn": encode_ef_hpplmn_search_interval,
    "ef-acm": encode_ef_three_byte_counter,
    "ef-acmax": encode_ef_three_byte_counter,
    "ef-ict": encode_ef_three_byte_counter,
    "ef-oct": encode_ef_three_byte_counter,
    "ef-li": encode_ef_language_records,
    "ef-pl": encode_ef_language_records,
    "ef-impi": encode_ef_tlv80_text,
    "ef-domain": encode_ef_tlv80_text,
    "ef-impu": encode_ef_tlv80_text,
    "ef-nafkca": encode_ef_tlv80_text,
    "ef-fplmn": encode_ef_plmn_list_no_act,
    "ef-ehplmn": encode_ef_plmn_list_no_act,
    "ef-plmnwact": encode_ef_plmn_list_with_act,
    "ef-oplmnwact": encode_ef_plmn_list_with_act,
    "ef-hplmnwact": encode_ef_plmn_list_with_act,
    "ef-uplmnwlan": encode_ef_wlan_plmn_list,
    "ef-oplmnwlan": encode_ef_wlan_plmn_list,
    "ef-wlrplmn": encode_ef_wlrplmn,
    "ef-adn": encode_ef_adn_record,
    "ef-fdn": encode_ef_adn_record,
    "ef-sdn": encode_ef_adn_record,
    "ef-smsp": encode_ef_smsp_record,
    "ef-arr": encode_ef_arr_rules,
    "ef-spn": encode_ef_spn,
    "ef-msisdn": encode_ef_msisdn_record,
    "ef-ecc": encode_ef_ecc,
    "ef-puct": encode_ef_puct,
    "ef-loci": encode_ef_loci,
    "ef-psloci": encode_ef_loci,
    "ef-epsloci": encode_ef_loci,
    "ef-opl": encode_ef_opl_record,
    "ef-pnn": encode_ef_pnn_record,
    "ef-ust": encode_ef_service_table,
    "ef-est": encode_ef_service_table,
    "ef-ist": encode_ef_service_table,
    "ef-pcscf": encode_ef_pcscf_address,
    "ef-spdi": encode_ef_spdi,
    "ef-epsnsc": encode_ef_eps_nas_security_context,
    "ef-sms": encode_ef_sms_record,
    "ef-smsr": encode_ef_sms_status_report,
    "ef-dir": encode_ef_dir_record,
    "ef-acl": encode_ef_apn_control_list,
    "ef-gbanl": encode_ef_gbanl,
    "ef-pkcs15-odf": encode_ef_pkcs15_odf,
    "ef-pkcs15-dodf": encode_ef_pkcs15_dodf,
    "ef-pkcs15-acm": encode_ef_pkcs15_acm,
    "ef-pkcs15-accf": encode_ef_pkcs15_accf,
    "ef-gid1": encode_ef_group_identifier,
    "ef-gid2": encode_ef_group_identifier,
    "ef-cbmi": encode_ef_cbmi,
    "ef-cbmid": encode_ef_cbmi,
    "ef-cbmir": encode_ef_cbmir,
    # 5x5 Pass A — call/phonebook family.
    "ef-lnd": encode_ef_lnd_record,
    "ef-ici": encode_ef_ici_oci_record,
    "ef-oci": encode_ef_ici_oci_record,
    "ef-ext1": encode_ef_extension_record,
    "ef-ext2": encode_ef_extension_record,
    "ef-ext3": encode_ef_extension_record,
    "ef-ccp1": encode_ef_ccp_record,
    "ef-ccp2": encode_ef_ccp_record,
    "ef-cmi": encode_ef_opaque,
    # 5x5 Pass A — key material.
    "ef-keys": encode_ef_usim_keys_record,
    "ef-keysPS": encode_ef_usim_keys_record,
    "ef-kc": encode_ef_gsm_kc_record,
    "ef-kcgprs": encode_ef_gsm_kc_record,
    "ef-hiddenkey": encode_ef_hidden_key,
    # 5x5 Pass A — network config.
    "ef-netpar": encode_ef_opaque,
    "ef-nia": encode_ef_one_byte_indicator,
    "ef-lrplmnsi": encode_ef_one_byte_indicator,
    "ef-nasconfig": encode_ef_nasconfig,
    "ef-sume": encode_ef_opaque,
    # 5x5 Pass A — 5G + obscure.
    "ef-suci-calc-info-usim": encode_ef_suci_calc_info,
    "ef-supinai": encode_ef_supinai,
    "ef-pkcs15-acrf": encode_ef_opaque,
    "ef-cpbcch": encode_ef_opaque,
    "ef-invscan": encode_ef_one_byte_indicator,
    "ef-s7": encode_ef_opaque,
    # 5x10 Pass A — 5G EFs (DF.5GS).
    "ef-5gs3gpploci": encode_ef_opaque,
    "ef-5gsn3gpploci": encode_ef_opaque,
    "ef-5gs3gppnsc": encode_ef_opaque,
    "ef-5gsn3gppnsc": encode_ef_opaque,
    "ef-5gauthkeys": encode_ef_opaque,
    "ef-uac-aic": encode_ef_uac_aic,
    "ef-5g-suci-calc-info": encode_ef_suci_calc_info,
    "ef-opl5g": encode_ef_opl5g_record,
    "ef-routing-indicator": encode_ef_routing_indicator,
    "ef-ursp": encode_ef_opaque,
    # 5x10 Pass C — 5G extras.
    "ef-tn3gppsnn": encode_ef_uri_tlv,
    "ef-5gsedrx": encode_ef_opaque,
    "ef-5gnswo-conf": encode_ef_opaque,
    # 5x10 Pass B / D — Phonebook family.
    "ef-pbr": encode_ef_pbr,
    "ef-iap": encode_ef_opaque,
    "ef-anr": encode_ef_adn_record,
    "ef-anra": encode_ef_adn_record,
    "ef-anrb": encode_ef_adn_record,
    "ef-anrc": encode_ef_adn_record,
    "ef-sne": encode_ef_opaque,
    "ef-snea": encode_ef_opaque,
    "ef-sneb": encode_ef_opaque,
    "ef-email": encode_ef_opaque,
    "ef-emailb": encode_ef_opaque,
    "ef-gas": encode_ef_opaque,
    "ef-grp": encode_ef_opaque,
    "ef-psc": encode_ef_opaque,
    "ef-cc": encode_ef_opaque,
    "ef-puid": encode_ef_opaque,
    # 5x10 Pass C — additional 3GPP / legacy.
    "ef-phase": encode_ef_one_byte_indicator,
    "ef-plmnsel": encode_ef_plmn_list_no_act,
    "ef-bcch": encode_ef_opaque,
    "ef-locigprs": encode_ef_opaque,
    "ef-fdnuri": encode_ef_uri_tlv,
    "ef-sdnuri": encode_ef_uri_tlv,
    "ef-lnduri": encode_ef_uri_tlv,
    # 5x10 Pass D — ISIM + multimedia extras.
    "ef-pcscf-urn": encode_ef_pcscf_address,
    "ef-muddomain": encode_ef_uri_tlv,
    "ef-psismsc": encode_ef_opaque,
    "ef-uiccsi": encode_ef_uri_tlv,
    "ef-ehuri": encode_ef_uri_tlv,
    "ef-impdf": encode_ef_opaque,
    "ef-nafkca-list": encode_ef_opaque,
    "ef-earfcnlist": encode_ef_opaque,
    "ef-fcst": encode_ef_opaque,
    "ef-phist": encode_ef_opaque,
    # 5x20 Pass A — Mailbox / CF / VGCS / VBS / eMLPP / DCK / CNL.
    "ef-mbdn": encode_ef_adn_record,
    "ef-ext6": encode_ef_extension_record,
    "ef-mbi": encode_ef_mbi_record,
    "ef-mwis": encode_ef_mwis_record,
    "ef-cfis": encode_ef_cfis_record,
    "ef-ext7": encode_ef_extension_record,
    "ef-mbparam": encode_ef_opaque,
    "ef-cfis2": encode_ef_cfis_record,
    "ef-dck": encode_ef_dck_record,
    "ef-cnl": encode_ef_opaque,
    "ef-vgcs": encode_ef_opaque,
    "ef-vgcss": encode_ef_opaque,
    "ef-vbs": encode_ef_opaque,
    "ef-vbss": encode_ef_opaque,
    "ef-emlpp": encode_ef_emlpp_record,
    "ef-aaem": encode_ef_aaem_record,
    "ef-anl": encode_ef_opaque,
    "ef-mexe-st": encode_ef_opaque,
    "ef-prose-pfsr": encode_ef_opaque,
    "ef-vsuri": encode_ef_uri_tlv,
    # 5x20 Pass B — CSIM family.
    "ef-csim-spc": encode_ef_opaque,
    "ef-csim-smscap": encode_ef_opaque,
    "ef-csim-min": encode_ef_opaque,
    "ef-csim-min1": encode_ef_opaque,
    "ef-csim-accolc": encode_ef_opaque,
    "ef-csim-imsi-t": encode_ef_opaque,
    "ef-csim-home-sidnid": encode_ef_opaque,
    "ef-csim-curr-sidnid": encode_ef_opaque,
    "ef-csim-nam-lock": encode_ef_opaque,
    "ef-csim-3gpd": encode_ef_opaque,
    "ef-csim-hpplmnact": encode_ef_opaque,
    "ef-csim-prl": encode_ef_opaque,
    "ef-csim-eprl": encode_ef_opaque,
    "ef-csim-namgam": encode_ef_opaque,
    "ef-csim-mdn": encode_ef_opaque,
    "ef-csim-plslpp": encode_ef_opaque,
    "ef-csim-hrpdcap": encode_ef_opaque,
    "ef-csim-ssci": encode_ef_opaque,
    "ef-csim-mlpl": encode_ef_opaque,
    "ef-csim-meruiid": encode_ef_opaque,
    # 5x20 Pass C — Specialized (ISIM/MCPTT/V2X/ProSe/MCS).
    "ef-prose-pfidg": encode_ef_opaque,
    "ef-prose-pfddn": encode_ef_opaque,
    "ef-v2x-cfg": encode_ef_opaque,
    "ef-v2x-pre-cfg": encode_ef_opaque,
    "ef-v2x-cert": encode_ef_opaque,
    "ef-v2x-auth-keys": encode_ef_opaque,
    "ef-mcs-root": encode_ef_opaque,
    "ef-mcptt-cfg": encode_ef_opaque,
    "ef-mcptt-sip": encode_ef_opaque,
    "ef-mcs-user-id": encode_ef_opaque,
    "ef-mcs-app-list": encode_ef_opaque,
    "ef-mcs-gms": encode_ef_opaque,
    "ef-mcs-cmsi": encode_ef_opaque,
    "ef-mcs-media-cfg": encode_ef_opaque,
    "ef-mcs-pub-id": encode_ef_opaque,
    "ef-mcs-profile": encode_ef_opaque,
    "ef-mcs-emergency": encode_ef_opaque,
    "ef-mcs-keyset": encode_ef_opaque,
    "ef-mcs-stat": encode_ef_opaque,
    "ef-mcs-sec-profile": encode_ef_opaque,
    # 5x20 Pass D — Operator / vendor / auxiliary extensions.
    "ef-opcust1": encode_ef_opaque,
    "ef-opcust2": encode_ef_opaque,
    "ef-opcust3": encode_ef_opaque,
    "ef-opcust4": encode_ef_opaque,
    "ef-opcust5": encode_ef_opaque,
    "ef-vendor1": encode_ef_opaque,
    "ef-vendor2": encode_ef_opaque,
    "ef-vendor3": encode_ef_opaque,
    "ef-vendor4": encode_ef_opaque,
    "ef-vendor5": encode_ef_opaque,
    "ef-scp11key": encode_ef_opaque,
    "ef-scp80ctr": encode_ef_opaque,
    "ef-simlock-state": encode_ef_opaque,
    "ef-ota-state": encode_ef_opaque,
    "ef-ota-keys": encode_ef_opaque,
    "ef-provconfig": encode_ef_opaque,
    "ef-selfservice": encode_ef_opaque,
    "ef-appconfig": encode_ef_opaque,
    "ef-acmp": encode_ef_opaque,
    "ef-tui": encode_ef_opaque,
}


# ---------------------------------------------------------------------------
# Wave B: opaque-passthrough catalog registration.
#
# The decode-side source of truth is
# ``Tools.ProfilePackage.saip_asn1_decode._OPAQUE_PASSTHROUGH_EF_CATALOG``.
# We pull the catalog here and register every entry against
# ``encode_ef_opaque`` so that ``encode_decoded_roundtrip_ef_content``
# accepts the same EF keys the decoder can read. The dispatcher lookup
# normalises to lowercase, so catalog entries with mixed case (e.g.
# ``ef-v2xp-Uu``) are stored under their lowercase form.
from Tools.ProfilePackage.saip_asn1_decode import (
    _OPAQUE_PASSTHROUGH_EF_CATALOG as _DECODE_OPAQUE_CATALOG,
)


def _register_opaque_passthrough_ef_dispatchers() -> None:
    """Extend ``_EF_CONTENT_DISPATCHER`` with every catalog entry.

    Bespoke encoders already present in the dispatcher win — the catalog
    is additive only, never overrides.
    """

    for raw_key in _DECODE_OPAQUE_CATALOG.keys():
        normalized = str(raw_key or "").strip().lower()
        if normalized == "":
            continue
        if normalized in _EF_CONTENT_DISPATCHER:
            continue
        _EF_CONTENT_DISPATCHER[normalized] = encode_ef_opaque


_register_opaque_passthrough_ef_dispatchers()


def encode_decoded_roundtrip_ef_content(
    last_ef_key: str,
    decoded_payload: dict[str, Any],
    *,
    target_length: int | None = None,
) -> bytes | None:
    """Encode ``fillFileContent`` for a known EF.

    Returns ``None`` when no encoder is registered for ``last_ef_key``.
    """

    normalized = str(last_ef_key or "").strip().lower()
    encoder = _EF_CONTENT_DISPATCHER.get(normalized)
    if encoder is None:
        return None
    result = encoder(dict(decoded_payload), target_length=target_length)
    if isinstance(result, bytes) is False:
        raise RoundtripEncoderError(
            f"{normalized}: encoder returned non-bytes value"
        )
    return result


def roundtrip_capable_ef_keys() -> tuple[str, ...]:
    return tuple(sorted(_EF_CONTENT_DISPATCHER))


# ---------------------------------------------------------------------------
# 5x20 Pass D — PE-level subtag/field encoders.
#
# These round-trip the ``{"hex": "..."}`` tagged-bytes form used throughout
# the SAIP JSON for OCTET STRING fields that carry profile metadata or
# structural hints (iccid, hashValue, efFileSize, etc.).


def _encode_tagged_hex_passthrough(
    payload: dict[str, Any],
    *,
    field_label: str,
    min_length: int | None = None,
    max_length: int | None = None,
) -> bytes:
    """Round-trip a ``{"hex": "..."}`` OCTET STRING field.

    Enforces optional length bounds in bytes when provided. The ``label``
    key on the payload is ignored — it is UI metadata only.
    """

    if "hex" not in payload:
        raise RoundtripEncoderError(
            f"{field_label}: missing required 'hex' field"
        )
    raw = _hex_to_bytes(_require_hex(payload, "hex"))
    if min_length is not None and len(raw) < min_length:
        raise RoundtripEncoderError(
            f"{field_label}: must be at least {min_length} byte(s), got {len(raw)}"
        )
    if max_length is not None and len(raw) > max_length:
        raise RoundtripEncoderError(
            f"{field_label}: must be at most {max_length} byte(s), got {len(raw)}"
        )
    return raw


def encode_iccid_field(payload: dict[str, Any]) -> bytes:
    """Profile-header ICCID (BCD, typically 10 bytes / 20 nibbles)."""

    return _encode_tagged_hex_passthrough(
        payload, field_label="iccid", min_length=1, max_length=10
    )


def encode_hash_value_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="hashValue", min_length=1
    )


def encode_lcsi_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="lcsi", min_length=1, max_length=1
    )


def encode_ef_file_size_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="efFileSize", min_length=1, max_length=2
    )


def encode_adf_rfm_access_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="adfRFMAccess", min_length=1
    )


def encode_mapping_options_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="mappingOptions", min_length=1, max_length=1
    )


def encode_mapping_source_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="mappingSource", min_length=1
    )


def encode_process_data_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="processData", min_length=1
    )


def encode_sd_perso_data_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="sdPersoData", min_length=1
    )


def encode_proprietary_ef_info_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="proprietaryEFInfo", min_length=1
    )


def encode_tlv_bytes_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="tlvBytes", min_length=1
    )


def encode_profile_version_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="profileVersion", min_length=1
    )


def encode_custom_field_octets(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="customFieldOctets", min_length=1
    )


def encode_serial_number_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="serialNumber", min_length=1
    )


def encode_notification_address_field(payload: dict[str, Any]) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload, field_label="notificationAddress", min_length=1
    )


# ---------------------------------------------------------------------------
# Wave A — generic tagged-bytes pass-through fields.
#
# These fields are already carried as raw OCTET STRINGs in the SAIP JSON
# (GlobalPlatform 9F70 / TS 102 226 / GSMA SAIP Annex D tagged bytes).
# The decoded view and round-trip encoder both operate on the hex blob
# without parsing the internal TLV — this is the "pass-through" contract
# the user approved for Wave A (deeper TLV decoding is out of scope).
#
# Each entry here pairs with a ``_summarize_binary_blob`` dispatch entry
# in ``_decode_special_field`` (see ``saip_asn1_decode.py``). Length
# bounds are intentionally left open because the fields target vendor /
# profile-specific payloads whose upper bound is not standardised.


_PASSTHROUGH_BYTES_FIELD_NAMES: tuple[str, ...] = (
    # GP / TS 102 226 system-specific install parameters. The fields
    # listed here stay as hex pass-through because their structure is
    # implementation-specific. Fields with Round-6 structured encoders
    # (``globalServiceParameters``, ``implicitSelectionParameter``,
    # ``contactlessProtocolParameters``,
    # ``userInteractionContactlessParameters``,
    # ``applicationProviderIdentifier``, GP memory quotas, TS 102 226
    # SIM file access/toolkit parameter, UICC access application-specific
    # parameters, ``restrictParameter``) are registered explicitly in
    # ``_BYTES_DISPATCHER`` further down.
    # PE-Application load block binary.
    "loadBlockObject",
    # PE-NonStandard opaque vendor content.
    "content",
    # PE-CDMAParameter — GSMA SAIP Annex D authentication material.
    # These are security credentials; we only pass-through the hex on
    # the editor surface. Any cryptographic use goes through the CDMA
    # personalisation path elsewhere in the toolkit.
    "authenticationKey",
    "ssd",
    "hrpdAccessAuthenticationData",
    "simpleIPAuthenticationData",
    "mobileIPAuthenticationData",
    # ProfileHeader.eUICC-Mandatory-AIDs.version (inner-AID version byte).
    "version",
    # TS102226AdditionalContactlessParameters.protocolParameterData.
    "protocolParameterData",
    # IotOptions.pix (IoT PIX identifier).
    "pix",
)


def _encode_passthrough_bytes_field(
    field_label: str,
    payload: dict[str, Any],
) -> bytes:
    return _encode_tagged_hex_passthrough(
        payload,
        field_label=field_label,
        min_length=1,
    )


def _make_passthrough_bytes_encoder(field_label: str):
    """Return a ``_BYTES_DISPATCHER`` encoder bound to ``field_label``.

    Closures are used here deliberately: the encoder behaviour is
    uniform across every ``_PASSTHROUGH_BYTES_FIELD_NAMES`` entry, so
    duplicating 24 near-identical ``def encode_<field>_field`` wrappers
    would hide the shared contract and make future length-rule changes
    much more tedious to track.
    """

    def _encoder(payload: dict[str, Any]) -> bytes:
        return _encode_passthrough_bytes_field(field_label, payload)

    _encoder.__name__ = f"encode_{field_label}_passthrough"
    return _encoder


# ---------------------------------------------------------------------------
# Round-6 Sweep 4 — structured round-trip encoders for the fields whose
# Round-4 / Round-5 decoders surface a rich decoded view (OID dotted
# string, single-byte bit flags, BER-TLV streams). Each encoder accepts
# the pre-existing ``{"hex": ...}`` verbatim form so documents authored
# before this sweep round-trip unchanged. When ``hex`` is absent or
# empty, the structured fields produced by the matching decoder are
# re-packed back to on-card bytes.


def _hex_string_or_none(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if isinstance(value, str) is False:
        return None
    stripped = value.strip()
    if len(stripped) == 0:
        return None
    if len(stripped) % 2 != 0 or any(
        ch not in "0123456789ABCDEFabcdef" for ch in stripped
    ):
        return None
    return stripped


def _encode_oid_dotted_to_bytes(oid_text: str) -> bytes:
    """X.690 §8.19 BER encoding of an OID dotted-decimal string."""

    parts = [segment.strip() for segment in oid_text.split(".") if segment.strip() != ""]
    if len(parts) < 2:
        raise RoundtripEncoderError(
            "applicationProviderIdentifier: OID must carry at least two arcs"
        )
    try:
        arcs = [int(segment, 10) for segment in parts]
    except ValueError as exc:
        raise RoundtripEncoderError(
            f"applicationProviderIdentifier: invalid OID arc in {oid_text!r}"
        ) from exc
    if any(arc < 0 for arc in arcs):
        raise RoundtripEncoderError(
            "applicationProviderIdentifier: OID arcs must be non-negative"
        )
    first = arcs[0]
    second = arcs[1]
    if not 0 <= first <= 2:
        raise RoundtripEncoderError(
            "applicationProviderIdentifier: first OID arc must be 0, 1 or 2"
        )
    if first in (0, 1) and second > 39:
        raise RoundtripEncoderError(
            "applicationProviderIdentifier: second OID arc must be <= 39 when first is 0/1"
        )
    accumulator = bytearray()
    accumulator.append(40 * first + second)
    for arc in arcs[2:]:
        if arc == 0:
            accumulator.append(0x00)
            continue
        chunks: list[int] = []
        remaining = arc
        while remaining > 0:
            chunks.append(remaining & 0x7F)
            remaining >>= 7
        chunks.reverse()
        for index, chunk in enumerate(chunks):
            if index < len(chunks) - 1:
                accumulator.append(chunk | 0x80)
            else:
                accumulator.append(chunk)
    return bytes(accumulator)


def encode_application_provider_identifier_field(payload: dict[str, Any]) -> bytes:
    """SAIP §2.8.2 — re-encode the Application Provider OID.

    Preferred inputs (first non-empty wins):
    1. ``hex`` — verbatim passthrough (keeps bytes identical even for
       non-canonical encodings found in the wild).
    2. ``oid`` — dotted-decimal text; re-encoded per X.690 §8.19.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    oid_text = payload.get("oid")
    if isinstance(oid_text, str) and len(oid_text.strip()) > 0:
        return _encode_oid_dotted_to_bytes(oid_text.strip())
    raise RoundtripEncoderError(
        "applicationProviderIdentifier: provide 'hex' or 'oid'"
    )


_GLOBAL_SERVICE_BITMAP: dict[str, int] = {
    "Global PIN": 0x80,
    "Universal PIN": 0x40,
    "Secure messaging": 0x20,
    "OMA DM": 0x10,
    "Application selection assisted": 0x08,
    "Data object management (DOR)": 0x04,
    "Reserved bit 1": 0x02,
    "Reserved bit 0": 0x01,
}


def encode_global_service_parameters_field(payload: dict[str, Any]) -> bytes:
    """SAIP §2.6.3 Table 2-6 — single-byte bitmap of global services.

    Accepts ``hex`` (any length; verbatim passthrough so non-canonical
    payloads authored before the Round-6 structured decoder still
    round-trip), ``bitmap`` (``"0xNN"`` or ``"NN"``), or
    ``activeServices`` (list of service names matching the decoder's
    ``_GLOBAL_SERVICE_BITS`` table). Length-1 constraints only apply to
    the structured paths — the hex path stays lossless.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    bitmap_text = payload.get("bitmap")
    if isinstance(bitmap_text, str):
        text = bitmap_text.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        if len(text) > 0:
            try:
                value = int(text, 16)
            except ValueError as exc:
                raise RoundtripEncoderError(
                    "globalServiceParameters: 'bitmap' must be a hex byte"
                ) from exc
            if not 0 <= value <= 0xFF:
                raise RoundtripEncoderError(
                    "globalServiceParameters: 'bitmap' must fit in 1 byte"
                )
            return bytes([value])
    active = payload.get("activeServices")
    if isinstance(active, list):
        mask = 0
        for entry in active:
            if isinstance(entry, str) is False:
                raise RoundtripEncoderError(
                    "globalServiceParameters: 'activeServices' entries must be strings"
                )
            bit = _GLOBAL_SERVICE_BITMAP.get(entry.strip())
            if bit is None:
                raise RoundtripEncoderError(
                    f"globalServiceParameters: unknown service name {entry!r}"
                )
            mask |= bit
        return bytes([mask])
    raise RoundtripEncoderError(
        "globalServiceParameters: provide 'hex', 'bitmap', or 'activeServices'"
    )


def encode_implicit_selection_parameter_field(payload: dict[str, Any]) -> bytes:
    """GlobalPlatform Card Spec Amd A §A.3 — single-byte selection flags.

    Bit 8 (``defaultSelected``) distinguishes default-application
    selection from explicit AID selection; bits 1-5 carry the channel
    mask. Accepts ``hex`` (any length; verbatim passthrough) or
    structured ``defaultSelected`` (bool) + ``channelMask``
    (``"0xNN"`` / int). Length constraints only apply to the
    structured path — the hex path stays lossless so legacy profiles
    round-trip unchanged.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    if "defaultSelected" not in payload and "channelMask" not in payload:
        raise RoundtripEncoderError(
            "implicitSelectionParameter: provide 'hex' or "
            "'defaultSelected' + 'channelMask'"
        )
    default_selected_raw = payload.get("defaultSelected", False)
    if isinstance(default_selected_raw, bool) is False:
        raise RoundtripEncoderError(
            "implicitSelectionParameter: 'defaultSelected' must be boolean"
        )
    channel_raw = payload.get("channelMask", 0)
    channel_value: int
    if isinstance(channel_raw, bool) is True:
        raise RoundtripEncoderError(
            "implicitSelectionParameter: 'channelMask' must be integer or hex string"
        )
    if isinstance(channel_raw, int):
        channel_value = int(channel_raw)
    elif isinstance(channel_raw, str):
        text = channel_raw.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            channel_value = int(text, 16) if len(text) > 0 else 0
        except ValueError as exc:
            raise RoundtripEncoderError(
                "implicitSelectionParameter: 'channelMask' must be a hex byte"
            ) from exc
    else:
        raise RoundtripEncoderError(
            "implicitSelectionParameter: 'channelMask' must be integer or hex string"
        )
    if not 0 <= channel_value <= 0x1F:
        raise RoundtripEncoderError(
            "implicitSelectionParameter: 'channelMask' must be in 0x00..0x1F"
        )
    encoded = channel_value & 0x1F
    if default_selected_raw is True:
        encoded |= 0x80
    return bytes([encoded])


def encode_contactless_protocol_parameters_field(payload: dict[str, Any]) -> bytes:
    """GlobalPlatform Card Spec Amd C §5 — BER-TLV contactless protocol
    parameters.

    Preferred input is ``hex`` (verbatim). When ``hex`` is absent the
    encoder re-packs the ``items`` TLV list produced by the matching
    decoder.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError(
            "contactlessProtocolParameters: provide 'hex' or 'items'"
        )
    return _encode_decoded_ber_items(
        items,
        field_label="contactlessProtocolParameters",
    )


def encode_user_interaction_contactless_parameters_field(
    payload: dict[str, Any],
) -> bytes:
    """GlobalPlatform Card Spec Amd C §6 — BER-TLV user-interaction
    contactless parameters. Accepts ``hex`` (verbatim) or ``items``."""

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    items = payload.get("items")
    if isinstance(items, list) is False:
        raise RoundtripEncoderError(
            "userInteractionContactlessParameters: provide 'hex' or 'items'"
        )
    return _encode_decoded_ber_items(
        items,
        field_label="userInteractionContactlessParameters",
    )


# ---------------------------------------------------------------------------
# Remaining-gap structured encoders (follow-up to Round-6 Sweep 4).
#
# Each encoder matches a semantic decoder added to ``saip_asn1_decode.py``
# for the previously hex-only pass-through fields. The encoders preserve
# the ``hex`` verbatim form so existing documents round-trip unchanged
# and accept the structured form produced by the decoder when ``hex`` is
# absent.


_RESTRICT_PARAMETER_NAME_TO_BIT: dict[str, int] = {
    "Restrict Open Personalisation": 0x01,
    "Restrict Contactless Self-Activation": 0x02,
}


def encode_restrict_parameter_field(payload: dict[str, Any]) -> bytes:
    """SAIP §8.6.6 / GlobalPlatform Amd F §A.4 — single-byte bitmap.

    Accepted inputs (first non-empty wins):
    1. ``hex`` — verbatim passthrough (any length) so legacy profiles
       round-trip unchanged.
    2. ``bitmap`` — ``"0xNN"`` or ``"NN"``; must fit in one byte.
    3. ``activeRestrictions`` — list of labels from
       :data:`_RESTRICT_PARAMETER_NAME_TO_BIT`.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    bitmap_text = payload.get("bitmap")
    if isinstance(bitmap_text, str):
        text = bitmap_text.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        if len(text) > 0:
            try:
                value = int(text, 16)
            except ValueError as exc:
                raise RoundtripEncoderError(
                    "restrictParameter: 'bitmap' must be a hex byte"
                ) from exc
            if not 0 <= value <= 0xFF:
                raise RoundtripEncoderError(
                    "restrictParameter: 'bitmap' must fit in 1 byte"
                )
            return bytes([value])
    active = payload.get("activeRestrictions")
    if isinstance(active, list):
        mask = 0
        for entry in active:
            if isinstance(entry, str) is False:
                raise RoundtripEncoderError(
                    "restrictParameter: 'activeRestrictions' entries must be strings"
                )
            bit = _RESTRICT_PARAMETER_NAME_TO_BIT.get(entry.strip())
            if bit is None:
                raise RoundtripEncoderError(
                    f"restrictParameter: unknown restriction name {entry!r}"
                )
            mask |= bit
        return bytes([mask])
    raise RoundtripEncoderError(
        "restrictParameter: provide 'hex', 'bitmap', or 'activeRestrictions'"
    )


def _encode_memory_quota_bytes(
    field_label: str,
    payload: dict[str, Any],
) -> bytes:
    """Shared encoder for the six GP memory-quota OCTET STRING fields.

    ``hex`` always takes precedence so existing payloads round-trip
    verbatim. If the decoder-produced ``decimal`` is present the encoder
    re-emits the value using 2..4 bytes so the result is ASN.1 SIZE
    compliant (GP Amd A §5.1.2 / Amd C).
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    decimal_raw = payload.get("decimal")
    if isinstance(decimal_raw, bool):
        raise RoundtripEncoderError(
            f"{field_label}: 'decimal' must be an unsigned integer"
        )
    if isinstance(decimal_raw, int) is False:
        raise RoundtripEncoderError(
            f"{field_label}: provide 'hex' or 'decimal'"
        )
    if decimal_raw < 0:
        raise RoundtripEncoderError(
            f"{field_label}: 'decimal' must be >= 0"
        )
    if decimal_raw > (2**32 - 1):
        raise RoundtripEncoderError(
            f"{field_label}: 'decimal' must fit in 4 bytes"
        )
    byte_length = max(2, (decimal_raw.bit_length() + 7) // 8)
    if byte_length > 4:
        byte_length = 4
    return decimal_raw.to_bytes(byte_length, "big", signed=False)


def _make_memory_quota_encoder(field_label: str):
    def _encoder(payload: dict[str, Any]) -> bytes:
        return _encode_memory_quota_bytes(field_label, payload)

    _encoder.__name__ = f"encode_{field_label}_field"
    return _encoder


_GP_MEMORY_QUOTA_FIELD_NAMES: tuple[str, ...] = (
    "volatileMemoryQuotaC7",
    "nonVolatileMemoryQuotaC8",
    "volatileReservedMemory",
    "nonVolatileReservedMemory",
    "cumulativeGrantedVolatileMemory",
    "cumulativeGrantedNonVolatileMemory",
)


def encode_ts102226_sim_file_access_toolkit_parameter_field(
    payload: dict[str, Any],
) -> bytes:
    """TS 102 226 §8.2.1.3.2.3 — SIM File Access + Toolkit Application
    combined parameters.

    Structure: ``len(N1) || SIM Toolkit params || len(N2) || SIM File
    Access params``. ``hex`` passthrough always wins; the structured
    path re-emits from the ``simToolkitApplicationParameters.hex`` +
    ``simFileAccessParameters.hex`` pair produced by the decoder.
    Optional ``trailingBytes`` (also hex) is appended verbatim.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    toolkit_section = payload.get("simToolkitApplicationParameters")
    file_access_section = payload.get("simFileAccessParameters")
    if (
        isinstance(toolkit_section, dict) is False
        or isinstance(file_access_section, dict) is False
    ):
        raise RoundtripEncoderError(
            "ts102226SIMFileAccessToolkitParameter: provide 'hex' or both "
            "'simToolkitApplicationParameters' and 'simFileAccessParameters'"
        )
    toolkit_hex = _hex_string_or_none(toolkit_section, "hex") or ""
    file_access_hex = _hex_string_or_none(file_access_section, "hex") or ""
    toolkit_bytes = bytes.fromhex(toolkit_hex) if len(toolkit_hex) > 0 else b""
    file_access_bytes = (
        bytes.fromhex(file_access_hex) if len(file_access_hex) > 0 else b""
    )
    if len(toolkit_bytes) > 0xFF or len(file_access_bytes) > 0xFF:
        raise RoundtripEncoderError(
            "ts102226SIMFileAccessToolkitParameter: section lengths must fit in 1 byte"
        )
    accumulator = bytearray()
    accumulator.append(len(toolkit_bytes))
    accumulator.extend(toolkit_bytes)
    accumulator.append(len(file_access_bytes))
    accumulator.extend(file_access_bytes)
    trailing_hex = _hex_string_or_none(payload, "trailingBytes")
    if trailing_hex is not None:
        accumulator.extend(bytes.fromhex(trailing_hex))
    return bytes(accumulator)


def _encode_uicc_access_records(
    field_label: str,
    payload: dict[str, Any],
) -> bytes:
    """Shared body for the regular + administrative UICC access encoders.

    Re-emits the length-prefixed Access Domain records produced by the
    matching decoder. ``hex`` passthrough on the outer payload always
    wins so legacy profiles round-trip verbatim.
    """

    hex_text = _hex_string_or_none(payload, "hex")
    if hex_text is not None:
        return bytes.fromhex(hex_text)
    records = payload.get("accessDomainRecords")
    if isinstance(records, list) is False or len(records) == 0:
        raise RoundtripEncoderError(
            f"{field_label}: provide 'hex' or a non-empty 'accessDomainRecords' list"
        )
    accumulator = bytearray()
    for index, record in enumerate(records):
        if isinstance(record, dict) is False:
            raise RoundtripEncoderError(
                f"{field_label}: accessDomainRecords[{index}] must be an object"
            )
        record_hex = _hex_string_or_none(record, "hex")
        if record_hex is None:
            raise RoundtripEncoderError(
                f"{field_label}: accessDomainRecords[{index}] must carry 'hex'"
            )
        record_bytes = bytes.fromhex(record_hex)
        if len(record_bytes) > 0xFF:
            raise RoundtripEncoderError(
                f"{field_label}: accessDomainRecords[{index}] exceeds 255 bytes"
            )
        accumulator.append(len(record_bytes))
        accumulator.extend(record_bytes)
    return bytes(accumulator)


def encode_uicc_access_application_specific_parameters_field(
    payload: dict[str, Any],
) -> bytes:
    """TS 102 226 §8.2.1.3.2.2 — UICC access application-specific
    parameters (regular variant)."""

    return _encode_uicc_access_records(
        "uiccAccessApplicationSpecificParametersField",
        payload,
    )


def encode_uicc_administrative_access_application_specific_parameters_field(
    payload: dict[str, Any],
) -> bytes:
    """TS 102 226 §8.2.1.3.2.2 — UICC access application-specific
    parameters (administrative variant)."""

    return _encode_uicc_access_records(
        "uiccAdministrativeAccessApplicationSpecificParametersField",
        payload,
    )


# ---------------------------------------------------------------------------
# 5x20 Pass D — scalar field encoders (PE-level INTEGERs).


def encode_major_version_field(payload: dict[str, Any]) -> int:
    """Encode the major-version integer field into its tag/length/value byte sequence."""
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError(
            "major-version must fit in 1 byte"
        )
    return decimal_value


def encode_minor_version_field(payload: dict[str, Any]) -> int:
    """Encode the minor-version integer field into its tag/length/value byte sequence."""
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0xFF:
        raise RoundtripEncoderError(
            "minor-version must fit in 1 byte"
        )
    return decimal_value


def encode_identification_field(payload: dict[str, Any]) -> int:
    decimal_value = _require_int(payload, "decimal")
    if decimal_value < 0:
        raise RoundtripEncoderError("identification must be >= 0")
    return decimal_value


def encode_short_efid_field(payload: dict[str, Any]) -> int:
    """Encode the short EF-ID field into its tag/length/value byte sequence."""
    decimal_value = _require_int(payload, "decimal")
    if not 0 <= decimal_value <= 0x1F:
        raise RoundtripEncoderError(
            "shortEFID must fit in 5 bits (0..31)"
        )
    return decimal_value


def encode_template_id_field(payload: dict[str, Any]) -> int:
    decimal_value = _require_int(payload, "decimal")
    if decimal_value < 0:
        raise RoundtripEncoderError("templateID must be >= 0")
    return decimal_value


# ---------------------------------------------------------------------------
# Public dispatcher


_BYTES_DISPATCHER: dict[str, Any] = {
    "minimumSecurityLevel": encode_minimum_security_level,
    "pol": encode_profile_policy_rules,
    "sqnOptions": encode_aka_option_octet,
    "algorithmOptions": encode_aka_option_octet,
    "authCounterMax": encode_counter_field,
    "sqnDelta": encode_counter_field,
    "sqnAgeLimit": encode_counter_field,
    "sqnInit": encode_counter_field,
    "numberOfKeccak": encode_number_of_keccak,
    "tarList": encode_tar_value,
    "key": encode_aka_secret_material,
    "opc": encode_aka_secret_material,
    "rotationConstants": encode_rotation_constants,
    "xoringConstants": encode_xoring_constants,
    "uiccAccessDomain": encode_access_domain,
    "uiccAdminAccessDomain": encode_access_domain,
    "adfAccessDomain": encode_access_domain,
    "adfAdminAccessDomain": encode_access_domain,
    # Round 1 — file-structure fields.
    "filePath": encode_file_path,
    "linkPath": encode_link_path,
    "fileDescriptor": encode_file_descriptor,
    "specialFileInformation": encode_special_file_information,
    "fillPattern": encode_fill_pattern,
    "repeatPattern": encode_repeat_pattern,
    "fileDetails": encode_file_details,
    # Round 3 — PIN/PUK/key-material.
    "pinValue": encode_pin_secret_value,
    "pukValue": encode_pin_secret_value,
    "keyData": encode_key_data,
    "pinStatusTemplateDO": encode_pin_status_template_do,
    # Round 4 — install/connectivity parameters.
    "connectivityParameters": encode_connectivity_parameters,
    "applicationSpecificParametersC9": encode_sd_install_parameters,
    "uiccToolkitApplicationSpecificParametersField": encode_uicc_toolkit_parameters,
    # 5x20 Pass D — PE-level OCTET STRING subtag encoders.
    "iccid": encode_iccid_field,
    "hashValue": encode_hash_value_field,
    "lcsi": encode_lcsi_field,
    "efFileSize": encode_ef_file_size_field,
    "adfRFMAccess": encode_adf_rfm_access_field,
    "mappingOptions": encode_mapping_options_field,
    "mappingSource": encode_mapping_source_field,
    "processData": encode_process_data_field,
    "sdPersoData": encode_sd_perso_data_field,
    "proprietaryEFInfo": encode_proprietary_ef_info_field,
    "tlvBytes": encode_tlv_bytes_field,
    "profileVersion": encode_profile_version_field,
    "customFieldOctets": encode_custom_field_octets,
    "serialNumber": encode_serial_number_field,
    "notificationAddress": encode_notification_address_field,
    # Round-6 Sweep 4 — structured round-trip encoders paired with the
    # Round-4/Round-5 semantic decoders.
    "applicationProviderIdentifier": encode_application_provider_identifier_field,
    "globalServiceParameters": encode_global_service_parameters_field,
    "implicitSelectionParameter": encode_implicit_selection_parameter_field,
    "contactlessProtocolParameters": encode_contactless_protocol_parameters_field,
    "userInteractionContactlessParameters": encode_user_interaction_contactless_parameters_field,
    # Remaining-gap structured encoders — previously hex-only pass-through.
    "restrictParameter": encode_restrict_parameter_field,
    "ts102226SIMFileAccessToolkitParameter": encode_ts102226_sim_file_access_toolkit_parameter_field,
    "uiccAccessApplicationSpecificParametersField": encode_uicc_access_application_specific_parameters_field,
    "uiccAdministrativeAccessApplicationSpecificParametersField": (
        encode_uicc_administrative_access_application_specific_parameters_field
    ),
}

# Remaining-gap: GP memory quota encoders share a helper because they
# all share the same 2..4 byte unsigned integer contract.
for _quota_field in _GP_MEMORY_QUOTA_FIELD_NAMES:
    _BYTES_DISPATCHER[_quota_field] = _make_memory_quota_encoder(_quota_field)

# AID-family fields all share the same encoder.
for _aid_field in _AID_FIELD_NAMES:
    _BYTES_DISPATCHER[_aid_field] = encode_application_identifier

# Memory-limit fields share the counter encoder.
for _memory_field in _MEMORY_LIMIT_FIELD_LABELS:
    _BYTES_DISPATCHER[_memory_field] = encode_memory_limit_field

# Wave A — register generic tagged-bytes pass-through encoders.
for _passthrough_field in _PASSTHROUGH_BYTES_FIELD_NAMES:
    _BYTES_DISPATCHER[_passthrough_field] = _make_passthrough_bytes_encoder(
        _passthrough_field
    )


_SCALAR_DISPATCHER: dict[str, Any] = {
    # Scalar fields that SAIP JSON stores as ASN.1 INTEGER.
    "fillFileOffset": encode_fill_file_offset,
    "macLength": encode_mac_length,
    "algorithmID": encode_algorithm_id,
    "unblockingPINReference": encode_puk_key_reference,
    "keyReference": encode_pin_puk_adm_key_reference,
    "maxNumOfAttemps-retryNumLeft": encode_pin_puk_retry_counter,
    "maxNumOfAttempts-retryNumLeft": encode_pin_puk_retry_counter,
    # 5x20 Pass D — PE-level INTEGER subtag encoders.
    "major-version": encode_major_version_field,
    "minor-version": encode_minor_version_field,
    "identification": encode_identification_field,
    "shortEFID": encode_short_efid_field,
    "templateID": encode_template_id_field,
}


# Scalar fields whose SAIP JSON form is a tagged-bytes OCTET STRING even
# though the decoder is in the scalar dispatcher (the decoder accepts
# both representations; SAIP stores them as OCTET STRING).
_SCALAR_AS_BYTES_DISPATCHER: dict[str, Any] = {
    "lifeCycleState": encode_life_cycle_state,
    "keyUsageQualifier": encode_key_usage_qualifier,
    "keyAccess": encode_key_access,
    "keyIdentifier": encode_key_identifier,
    "keyVersionNumber": encode_key_version_number,
    "keyCounterValue": encode_key_counter_value,
    "keyType": encode_key_type,
    "pinAttributes": encode_pin_attributes,
    "applicationPrivileges": encode_application_privileges,
}


def encode_decoded_roundtrip_bytes(
    field_name: str,
    decoded_payload: dict[str, Any],
) -> bytes | None:
    """Return the encoded ``bytes`` for a roundtrip-capable OCTET STRING field.

    Returns ``None`` when the field has no registered encoder.
    """

    normalized = str(field_name or "").strip()
    encoder = _BYTES_DISPATCHER.get(normalized)
    if encoder is None:
        encoder = _SCALAR_AS_BYTES_DISPATCHER.get(normalized)
    if encoder is None:
        return None
    result = encoder(dict(decoded_payload))
    if isinstance(result, bytes) is False:
        raise RoundtripEncoderError(
            f"{normalized}: encoder returned non-bytes value"
        )
    return result


def encode_decoded_roundtrip_scalar(
    field_name: str,
    decoded_payload: dict[str, Any],
) -> int | None:
    """Return the encoded integer for a roundtrip-capable INTEGER field.

    Returns ``None`` when the field has no registered encoder.
    """

    normalized = str(field_name or "").strip()
    encoder = _SCALAR_DISPATCHER.get(normalized)
    if encoder is None:
        return None
    result = encoder(dict(decoded_payload))
    if isinstance(result, int) is False or isinstance(result, bool):
        raise RoundtripEncoderError(
            f"{normalized}: encoder returned non-int value"
        )
    return result


def roundtrip_capable_fields() -> dict[str, str]:
    """Return a mapping of field name -> natural output kind.

    ``kind`` is one of:
    - ``"bytes"`` — field is stored as tagged-bytes OCTET STRING.
    - ``"scalar"`` — field is stored as an ASN.1 INTEGER.
    """

    kinds: dict[str, str] = {}
    for field_name in _BYTES_DISPATCHER:
        kinds[field_name] = "bytes"
    for field_name in _SCALAR_AS_BYTES_DISPATCHER:
        kinds[field_name] = "bytes"
    for field_name in _SCALAR_DISPATCHER:
        kinds[field_name] = "scalar"
    return kinds
