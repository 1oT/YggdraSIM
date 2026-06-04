# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP decoded-field editor: model builders and payload encoders.

``build_decoded_value_editor_model`` maps a raw JSON field value to a
typed editor model (enum, bitmask, roundtrip, raw-hex, …) that the GUI
renders as a structured form.  ``encode_decoded_value_editor_payload``
is its inverse — it converts a submitted editor payload back to a
tagged-bytes JSON value ready for splice into the document tree.
"""
from __future__ import annotations

import copy
import re
from typing import Any

from .saip_asn1_decode import (
    _5G_PROSE_ST_SERVICES,
    _CSIM_SERVICE_NAMES,
    _EF_BST_SERVICE_NAMES,
    _EF_MST_SERVICE_NAMES,
    _EF_PST_SERVICE_NAMES,
    _EF_VST_SERVICE_NAMES,
    _decode_file_descriptor,
    _EST_SERVICE_NAMES,
    _ISIM_SERVICE_NAMES,
    _decode_ef_file_size,
    _decode_fill_file_offset,
    _decode_file_identifier,
    _decode_imsi,
    _decode_known_ef_payload,
    _decode_lcsi,
    _decode_profile_iccid,
    _decode_scalar_special_field,
    _decode_security_attributes_referenced,
    _decode_short_efid,
    _decode_special_field,
    _UST_SERVICE_NAMES,
    _resolve_ef_key_for_fid,
    _hex_from_tagged_bytes,
    parent_token_for_container_fid,
    parent_token_from_file_path_hex,
)
from .saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_bytes,
    encode_decoded_roundtrip_ef_content,
    encode_decoded_roundtrip_scalar,
    roundtrip_capable_ef_keys,
    roundtrip_capable_fields,
)
from .saip_json_codec import _TAG_BYTES
from .saip_profile_template import encode_iccid_ef_hex, encode_imsi_ef_hex

_LCSI_STATE_TO_HEX = {
    "no_information": "00",
    "creation": "01",
    "initialization": "03",
    "operational_activated": "05",
    "operational_deactivated": "04",
    "termination": "C0",
}

_SERVICE_TABLE_FILE_DEFS: dict[str, tuple[str, dict[int, str]]] = {
    "ef-ust": ("EF.UST", _UST_SERVICE_NAMES),
    "ef-est": ("EF.EST", _EST_SERVICE_NAMES),
    "ef-ist": ("EF.IST", _ISIM_SERVICE_NAMES),
    # P1.7 — generic service-table editor scaffold extended to the
    # remaining 3GPP / TCA service-table EFs. Each pair reuses the
    # service-name dictionary already defined in saip_asn1_decode so
    # the bit-list editor surfaces human-readable labels instead of
    # bare "Service N" placeholders.
    "ef-bst":             ("EF.BST",            _EF_BST_SERVICE_NAMES),
    "ef-mst":             ("EF.MST",            _EF_MST_SERVICE_NAMES),
    "ef-pst":             ("EF.PST",            _EF_PST_SERVICE_NAMES),
    "ef-vst":             ("EF.VST",            _EF_VST_SERVICE_NAMES),
    "ef-csim-st":         ("EF.CSIM_ST",        _CSIM_SERVICE_NAMES),
    "ef-5g-prose-st":     ("EF.5G_PROSE_ST",    _5G_PROSE_ST_SERVICES),
}


# ---------------------------------------------------------------------------
# Enum registry for the decoded form editor
#
# Certain decoded payload keys only accept a fixed set of string values
# (life-cycle state, file descriptor flags, algorithm identifiers, …).
# Typing them by hand is error-prone, so the bulk form editor exposes
# a pick-list (Ctrl+L) whenever the cursor lands on one. The registry
# below is the single source of truth for the valid choices — the
# TUI picker, the encoder, and the documentation all read from the
# same table.
#
# A key may be declared as a plain list (simple enums) or as a
# structured entry carrying short labels / descriptions that the
# picker will surface to the operator. Keys are matched against the
# payload's leaf key name rather than a full JSON path so the same
# declaration works for scalar fields and for fields nested inside
# tagged tuples.
# ---------------------------------------------------------------------------


_COMMON_ENUM_CHOICES: dict[str, dict[str, Any]] = {
    "state": {
        "choices": sorted(_LCSI_STATE_TO_HEX.keys()),
        "description": "Life Cycle Status Integer (ETSI TS 102 221 §11.1.1.4.9)",
        "labels": {
            "no_information": "0x00 — No information",
            "creation": "0x01 — Creation",
            "initialization": "0x03 — Initialization",
            "operational_activated": "0x05 — Operational (activated)",
            "operational_deactivated": "0x04 — Operational (deactivated)",
            "termination": "0xC0 — Termination",
        },
    },
    "fileType": {
        "choices": ["working_ef", "internal_ef", "df"],
        "description": "File descriptor — file type (ETSI TS 102 221 §11.1.1.4.3)",
        "labels": {
            "working_ef": "Working EF",
            "internal_ef": "Internal EF",
            "df": "DF / ADF",
        },
    },
    "structure": {
        "choices": [
            "no_info_given",
            "transparent",
            "linear_fixed",
            "cyclic",
            "ber_tlv",
        ],
        "description": "File descriptor — EF structure",
        "labels": {
            "no_info_given": "No information given",
            "transparent": "Transparent",
            "linear_fixed": "Linear fixed",
            "cyclic": "Cyclic",
            "ber_tlv": "BER-TLV (0x39)",
        },
    },
    "algorithm": {
        "choices": ["milenage", "tuak", "xor", "comp128v1", "comp128v2", "comp128v3"],
        "description": "AKA algorithm identifier",
        "labels": {
            "milenage": "MILENAGE (3GPP TS 35.206)",
            "tuak": "TUAK (3GPP TS 35.231)",
            "xor": "XOR test (3GPP TS 34.108 §8.1.2)",
            "comp128v1": "COMP128 v1 (2G, legacy)",
            "comp128v2": "COMP128 v2 (2G)",
            "comp128v3": "COMP128 v3 (2G)",
        },
    },
    "shareable": {
        "choices": ["true", "false"],
        "description": "Shareable file flag (bool is accepted as true/false)",
    },
    "validEncoding": {
        "choices": ["true", "false"],
        "description": "Short EF identifier — reserved low bits are zero",
    },
    "supported": {
        "choices": ["true", "false"],
        "description": "Short EF identifier — present on the card",
    },
    # Connectivity parameters — protocol identifiers (3GPP TS 23.040 §9.2.3.9)
    "connectivityPid": {
        "choices": [
            "sme_to_sme",
            "telematic_implicit",
            "telematic_telex",
            "telematic_group3_fax",
            "telematic_group4_fax",
            "telematic_voice",
            "telematic_ermes",
            "telematic_national_paging",
            "telematic_videotex",
            "telematic_teletex_unspec",
            "telematic_teletex_pspdn",
            "telematic_teletex_cspdn",
            "telematic_teletex_pstn",
            "telematic_teletex_isdn",
            "telematic_uci",
            "message_handling",
            "x400",
            "internet_email",
            "sc_specific_38",
            "sc_specific_39",
            "sc_specific_3A",
            "sc_specific_3B",
            "sc_specific_3C",
            "sc_specific_3D",
            "sc_specific_3E",
            "gsm_umts_ms",
            "sm_type_0",
            "replace_sm_1",
            "replace_sm_2",
            "replace_sm_3",
            "replace_sm_4",
            "replace_sm_5",
            "replace_sm_6",
            "replace_sm_7",
            "device_triggering",
            "ansi_136",
            "me_data_download",
            "me_depersonalization",
            "usim_data_download",
        ],
        "description": "SMS Protocol Identifier (3GPP TS 23.040 §9.2.3.9)",
        "labels": {
            "sme_to_sme": "0x00 — SME-to-SME (no interworking)",
            "telematic_implicit": "0x20 — Telematic (implicit)",
            "telematic_telex": "0x21 — Telematic (Telex)",
            "telematic_group3_fax": "0x22 — Telematic (Group 3 Fax)",
            "telematic_group4_fax": "0x23 — Telematic (Group 4 Fax)",
            "telematic_voice": "0x24 — Telematic (Voice)",
            "telematic_ermes": "0x25 — Telematic (ERMES)",
            "telematic_national_paging": "0x26 — Telematic (National Paging)",
            "telematic_videotex": "0x27 — Telematic (Videotex)",
            "telematic_teletex_unspec": "0x28 — Telematic (Teletex, unspecified)",
            "telematic_teletex_pspdn": "0x29 — Telematic (Teletex, PSPDN)",
            "telematic_teletex_cspdn": "0x2A — Telematic (Teletex, CSPDN)",
            "telematic_teletex_pstn": "0x2B — Telematic (Teletex, analog PSTN)",
            "telematic_teletex_isdn": "0x2C — Telematic (Teletex, digital ISDN)",
            "telematic_uci": "0x2D — Telematic (UCI)",
            "message_handling": "0x30 — Message Handling Facility",
            "x400": "0x31 — Any public X.400",
            "internet_email": "0x32 — Internet Electronic Mail",
            "sc_specific_38": "0x38 — SC-specific (mutual agreement)",
            "gsm_umts_ms": "0x3F — GSM/UMTS MS",
            "sm_type_0": "0x40 — Short Message Type 0",
            "replace_sm_1": "0x41 — Replace SM Type 1",
            "replace_sm_2": "0x42 — Replace SM Type 2",
            "replace_sm_3": "0x43 — Replace SM Type 3",
            "replace_sm_4": "0x44 — Replace SM Type 4",
            "replace_sm_5": "0x45 — Replace SM Type 5",
            "replace_sm_6": "0x46 — Replace SM Type 6",
            "replace_sm_7": "0x47 — Replace SM Type 7",
            "device_triggering": "0x48 — Device Triggering",
            "ansi_136": "0x7C — ANSI-136 R-DATA",
            "me_data_download": "0x7D — ME Data Download",
            "me_depersonalization": "0x7E — ME De-personalization",
            "usim_data_download": "0x7F — (U)SIM Data Download",
        },
    },
    # Connectivity parameters — bearer types (ETSI TS 102 223)
    "bearerType": {
        "choices": [
            "gsm_3gpp_01", "gsm_3gpp_02", "default_bearer", "local_link",
            "bluetooth", "irda", "rs232", "cdma2000", "gsm_3gpp_09",
            "iwlan", "eutran", "usb",
        ],
        "description": "Bearer type (ETSI TS 102 223 §8.16)",
        "labels": {
            "gsm_3gpp_01": "0x01 — GSM/3GPP",
            "gsm_3gpp_02": "0x02 — GSM/3GPP",
            "default_bearer": "0x03 — Default bearer for requested transport",
            "local_link": "0x04 — Local link (technology independent)",
            "bluetooth": "0x05 — Bluetooth",
            "irda": "0x06 — IrDA",
            "rs232": "0x07 — RS232",
            "cdma2000": "0x08 — cdma2000 packet data",
            "gsm_3gpp_09": "0x09 — GSM/3GPP",
            "iwlan": "0x0A — 3GPP I-WLAN",
            "eutran": "0x0B — 3GPP E-UTRAN / Mapped UTRAN",
            "usb": "0x10 — USB",
        },
    },
    # Connectivity parameters — DCS coding groups (3GPP TS 23.038)
    "dcsCodingGroup": {
        "choices": [
            "general_7bit", "general_8bit", "general_ucs2",
            "compressed_7bit", "compressed_8bit", "compressed_ucs2",
            "msg_waiting_discard", "msg_waiting_store", "msg_waiting_store_ucs2",
            "data_coding_class",
        ],
        "description": "DCS coding group (3GPP TS 23.038 §4)",
        "labels": {
            "general_7bit": "General — GSM 7-bit (uncompressed)",
            "general_8bit": "General — 8-bit data (uncompressed)",
            "general_ucs2": "General — UCS2 (uncompressed)",
            "compressed_7bit": "General — GSM 7-bit (compressed)",
            "compressed_8bit": "General — 8-bit data (compressed)",
            "compressed_ucs2": "General — UCS2 (compressed)",
            "msg_waiting_discard": "Message Waiting — Discard",
            "msg_waiting_store": "Message Waiting — Store",
            "msg_waiting_store_ucs2": "Message Waiting — Store (UCS2)",
            "data_coding_class": "Data coding / message class",
        },
    },
    # Connectivity parameters — TON (Type of Number)
    "ton": {
        "choices": ["unknown", "international", "national", "network_specific"],
        "description": "Type of Number (3GPP TS 31.102 / EF.ADN)",
        "labels": {
            "unknown": "0x0 — Unknown",
            "international": "0x1 — International Number",
            "national": "0x2 — National Number",
            "network_specific": "0x3 — Network Specific Number",
        },
    },
    # Connectivity parameters — NPI (Numbering Plan Identifier)
    "npi": {
        "choices": ["unknown", "isdn_e164", "data_x121", "telex_f69", "private", "extension"],
        "description": "Numbering Plan Identifier (3GPP TS 31.102 / EF.ADN)",
        "labels": {
            "unknown": "0x0 — Unknown",
            "isdn_e164": "0x1 — ISDN/Telephony (E.164/E.163)",
            "data_x121": "0x3 — Data (X.121)",
            "telex_f69": "0x4 — Telex (F.69)",
            "private": "0x9 — Private",
            "extension": "0xF — Reserved for extension",
        },
    },
    # Connectivity section type (add/remove sections)
    "connectivitySection": {
        "choices": ["sms", "http", "cat_tp"],
        "description": "Connectivity parameter section type",
        "labels": {
            "sms": "SMS Connectivity (tag A0)",
            "http": "HTTP Connectivity (tag A1)",
            "cat_tp": "CAT_TP Connectivity (tag A2)",
        },
    },
    # Message class for DCS
    "messageClass": {
        "choices": ["class0", "class1", "class2", "class3"],
        "description": "DCS message class (3GPP TS 23.038)",
        "labels": {
            "class0": "Class 0",
            "class1": "Class 1 (ME-specific)",
            "class2": "Class 2 (U)SIM-specific",
            "class3": "Class 3 (TE-specific)",
        },
    },
}


def get_enum_choices_for_key(payload_key: str) -> dict[str, Any] | None:
    """
    Return the enum descriptor registered for ``payload_key`` or
    ``None`` if the key is free-form. Used by the bulk form editor's
    pick-list modal to surface the valid values without the operator
    having to remember the exact spelling.
    """
    if isinstance(payload_key, str) is False:
        return None
    descriptor = _COMMON_ENUM_CHOICES.get(payload_key)
    if descriptor is None:
        return None
    return copy.deepcopy(descriptor)


def list_known_enum_payload_keys() -> list[str]:
    """
    Return all payload keys the enum picker knows about. Sorted so
    the output stays stable for tests and documentation.
    """
    return sorted(_COMMON_ENUM_CHOICES.keys())


def normalize_enum_choice_for_key(payload_key: str, value: Any) -> str | bool | None:
    """
    Coerce ``value`` into the canonical form for ``payload_key``.
    Boolean-valued enums accept the strings ``"true"`` / ``"false"``
    (case-insensitive) and fall back to the native ``bool`` for the
    JSON encoder. Returns ``None`` when the value doesn't match the
    enum — callers may surface the valid set instead.
    """
    descriptor = _COMMON_ENUM_CHOICES.get(payload_key)
    if descriptor is None:
        return None
    choices = descriptor.get("choices", [])
    if isinstance(choices, list) is False:
        return None
    text = str(value if value is not None else "").strip()
    if len(text) == 0:
        return None
    lowered = text.lower()
    if choices == ["true", "false"]:
        if lowered in ("true", "1", "yes", "y"):
            return True
        if lowered in ("false", "0", "no", "n"):
            return False
        return None
    for candidate in choices:
        if str(candidate).lower() == lowered:
            return str(candidate)
    return None


def _tagged_bytes(hex_value: str) -> dict[str, str]:
    return {_TAG_BYTES: str(hex_value or "").strip().upper()}


def _clean_hex(text: Any, *, label: str, expected_nibbles: int | None = None) -> str:
    compact = re.sub(r"\s+", "", str(text or "")).upper()
    if len(compact) == 0:
        raise ValueError(f"{label} must not be empty.")
    if re.fullmatch(r"[0-9A-F]+", compact) is None:
        raise ValueError(f"{label} must be hexadecimal.")
    if expected_nibbles is not None and len(compact) != expected_nibbles:
        raise ValueError(f"{label} must be exactly {expected_nibbles} hex characters.")
    if len(compact) % 2 != 0:
        raise ValueError(f"{label} must have even-length hex.")
    return compact


def _positive_int(value: Any, *, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer.")
    if isinstance(value, int):
        normalized = int(value)
    else:
        text = str(value or "").strip()
        if len(text) == 0 or text.isdigit() is False:
            raise ValueError(f"{label} must be a decimal integer.")
        normalized = int(text)
    if normalized < minimum:
        raise ValueError(f"{label} must be >= {minimum}.")
    if maximum is not None and normalized > maximum:
        raise ValueError(f"{label} must be <= {maximum}.")
    return normalized


def _service_table_definition(
    last_ef_key: str | None,
) -> tuple[str, dict[int, str]] | None:
    normalized_key = str(last_ef_key or "").strip().lower()
    if normalized_key == "":
        return None
    return _SERVICE_TABLE_FILE_DEFS.get(normalized_key)


def _service_table_active_numbers(raw_bytes: bytes) -> set[int]:
    active_numbers: set[int] = set()
    for byte_index, byte_value in enumerate(raw_bytes):
        for bit_index in range(8):
            if byte_value & (1 << bit_index):
                active_numbers.add((byte_index * 8) + bit_index + 1)
    return active_numbers


def _service_table_editor_payload(
    raw_hex: str,
    *,
    service_names: dict[int, str],
) -> dict[str, Any] | None:
    try:
        raw_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    active_numbers = _service_table_active_numbers(raw_bytes)
    highest_active = 0
    if len(active_numbers) > 0:
        highest_active = max(active_numbers)
    highest_known = 0
    if len(service_names) > 0:
        highest_known = max(service_names)
    highest_service_number = max(highest_active, highest_known)
    services: dict[str, str] = {}
    for service_number in range(1, highest_service_number + 1):
        service_name = service_names.get(service_number, f"Service {service_number}")
        services[f"{service_number}: {service_name}"] = (
            "y" if service_number in active_numbers else "n"
        )
    return {
        "preserveByteLength": len(raw_bytes),
        "services": services,
    }


def _yes_no_flag(value: Any, *, label: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in {"y", "yes", "true", "1", "on", "enabled"}:
        return True
    if normalized in {"n", "no", "false", "0", "off", "disabled"}:
        return False
    raise ValueError(f"{label} must be 'y' or 'n'.")


def _encode_service_table_payload(
    editor_payload: dict[str, Any],
) -> dict[str, str]:
    payload = dict(editor_payload)
    preserve_byte_length = _positive_int(
        payload.get("preserveByteLength", 0),
        label="preserveByteLength",
        minimum=0,
    )
    services_payload = payload.get("services")
    if isinstance(services_payload, dict) is False:
        raise ValueError("services must be a JSON object.")
    enabled_numbers: set[int] = set()
    highest_service_number = 0
    for raw_key, raw_value in services_payload.items():
        key_text = str(raw_key or "").strip()
        match = re.match(r"^(\d+)\s*:", key_text)
        if match is None:
            raise ValueError(
                f"Service key {key_text!r} must start with '<number>:'."
            )
        service_number = int(match.group(1))
        if service_number <= 0:
            raise ValueError("Service numbers must be >= 1.")
        if _yes_no_flag(raw_value, label=key_text):
            enabled_numbers.add(service_number)
            highest_service_number = max(highest_service_number, service_number)
    byte_length = preserve_byte_length
    if highest_service_number > 0:
        byte_length = max(byte_length, (highest_service_number + 7) // 8)
    if byte_length == 0:
        return _tagged_bytes("")
    encoded = bytearray(byte_length)
    for service_number in enabled_numbers:
        zero_based = service_number - 1
        byte_index = zero_based // 8
        bit_index = zero_based % 8
        if byte_index >= len(encoded):
            continue
        encoded[byte_index] |= 1 << bit_index
    return _tagged_bytes(bytes(encoded).hex().upper())


def build_decoded_value_editor_model(
    *,
    field_name: str,
    raw_value: Any,
    last_ef_key: str | None = None,
    pe_section_key: str | None = None,
) -> dict[str, Any] | None:
    """Build a typed editor model for a single decoded profile field.

    Returns a dict with ``title``, ``editor_kind``, and ``payload`` keys
    that the GUI renders as a form, or ``None`` when no typed editor is
    available for the field.  ``last_ef_key`` (e.g. ``"ef-acc"``) narrows
    the editor for fields whose meaning depends on the containing EF.
    """
    normalized_field = str(field_name or "").strip()
    if normalized_field == "shortEFID":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        decoded = _decode_short_efid(bytes.fromhex(raw_hex or ""))
        if isinstance(decoded, dict) is False:
            return None
        payload = {"supported": bool(decoded.get("supported", False))}
        if payload["supported"]:
            payload["sfi"] = int(decoded.get("sfi", 0))
        return {
            "title": "Decoded editor: Short EF Identifier",
            "note": (
                "Edit the SFI in decimal. When support is disabled, the field is "
                "encoded as empty bytes."
            ),
            "editor_kind": "short_efid",
            "payload": payload,
        }
    if normalized_field == "efFileSize":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_ef_file_size(bytes.fromhex(raw_hex))
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: EF file size",
            "note": "Edit the file size in bytes. It will be written back as minimal big-endian hex.",
            "editor_kind": "byte_count",
            "payload": {"byteCount": int(decoded.get("decimal", 0))},
        }
    if normalized_field == "securityAttributesReferenced":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_security_attributes_referenced(
            bytes.fromhex(raw_hex),
            parent_hint=pe_section_key,
        )
        if isinstance(decoded, dict) is False:
            return None
        payload: dict[str, Any] = {
            "recordNumber": int(decoded.get("recordNumber", 0)),
        }
        arr_file_id = str(decoded.get("arrFileId", "") or "").strip()
        if len(arr_file_id) > 0 and arr_file_id != "implicit":
            payload["arrFileId"] = arr_file_id
        return {
            "title": "Decoded editor: Referenced security attributes",
            "note": (
                "Set the record number for local EF.ARR, or add an ARR file ID "
                "for explicit 3-byte coding."
            ),
            "editor_kind": "arr_reference",
            "payload": payload,
        }
    if normalized_field == "lcsi":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_lcsi(bytes.fromhex(raw_hex))
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: Life Cycle Status Integer",
            "note": (
                "Supported states: no information, creation, initialization, "
                "operational activated, operational deactivated, termination."
            ),
            "editor_kind": "lcsi_state",
            "payload": {"state": str(decoded.get("state", "") or "").strip()},
        }
    if normalized_field == "fillFileOffset":
        decoded = _decode_fill_file_offset(raw_value)
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: Fill file offset",
            "note": "Offset is edited as a decimal integer.",
            "editor_kind": "fill_file_offset",
            "payload": {"offset": int(decoded.get("decimal", 0))},
        }
    if normalized_field == "fileID":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_file_identifier(
            bytes.fromhex(raw_hex),
            parent_hint=pe_section_key,
        )
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: File ID",
            "note": "Edit the FID as four hex characters.",
            "editor_kind": "file_id",
            "payload": {"fid": str(decoded.get("hex", raw_hex) or raw_hex)},
        }
    if normalized_field == "iccid":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_profile_iccid(bytes.fromhex(raw_hex))
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: ICCID",
            "note": "Edit the ICCID digits. The editor writes back swapped-BCD EF bytes.",
            "payload": {"iccid": str(decoded.get("iccid", "") or "").strip()},
        }
    service_table_def = _service_table_definition(last_ef_key)
    if normalized_field == "fillFileContent" and service_table_def is not None:
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        table_label, service_names = service_table_def
        payload = _service_table_editor_payload(
            raw_hex,
            service_names=service_names,
        )
        if payload is None:
            return None
        return {
            "title": f"Decoded editor: {table_label} service table",
            "note": (
                "Edit service flags with 'y' or 'n'. "
                "Preserve byte length keeps the encoded table size stable."
            ),
            "editor_kind": "service_table",
            "payload": payload,
        }
    if normalized_field == "fillFileContent" and str(last_ef_key or "").strip() == "ef-imsi":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_imsi(raw_hex)
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: EF.IMSI",
            "note": "Edit the IMSI digits. The editor writes back EF.IMSI bytes.",
            "payload": {"imsi": str(decoded.get("imsi", "") or "").strip()},
        }
    if normalized_field == "fillFileContent" and str(last_ef_key or "").strip() == "ef-iccid":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None:
            return None
        decoded = _decode_profile_iccid(bytes.fromhex(raw_hex))
        if isinstance(decoded, dict) is False:
            return None
        return {
            "title": "Decoded editor: EF.ICCID",
            "note": "Edit the ICCID digits. The editor writes back swapped-BCD EF bytes.",
            "payload": {"iccid": str(decoded.get("iccid", "") or "").strip()},
        }
    return None


_READONLY_VIEW_EDITOR_KIND = "readonly_json"
_READONLY_VIEW_NOTE = (
    "Read-only decoded view. No round-trip editor is available for this "
    "field yet. Edit via the raw JSON / DER panes and the decoded output "
    "refreshes on the next selection."
)


def _readonly_view_title(field_name: str, last_ef_key: str | None) -> str:
    base = str(field_name or "").strip() or "field"
    ef_token = str(last_ef_key or "").strip()
    if len(ef_token) > 0:
        return f"Read-only decode: {ef_token} / {base}"
    return f"Read-only decode: {base}"


def _readonly_view_payload(decoded: Any) -> dict[str, Any]:
    if isinstance(decoded, dict):
        return dict(decoded)
    if isinstance(decoded, list):
        return {"items": list(decoded)}
    return {"value": decoded}


def build_decoded_value_readonly_view(
    *,
    field_name: str,
    raw_value: Any,
    last_ef_key: str | None = None,
    pe_section_key: str | None = None,
) -> dict[str, Any] | None:
    """Return a read-only decoded view when no round-trip editor exists.

    The view dispatches to the three registries in `saip_asn1_decode`:
    per-EF content, named hex-bytes fields, and named scalar fields.
    ``pe_section_key`` is forwarded as the ``parent_hint`` so FIDs that
    collide across applications (e.g. 6F3A ``ef-adn`` appears under
    DF.Telecom *and* under ADF.USIM.DF.PhoneBook) resolve against the
    enclosing DF / ADF rather than against the first match in the
    catalogue. Returns ``None`` when no decoder recognises the field.
    """

    normalized_field = str(field_name or "").strip()
    normalized_ef_raw = str(last_ef_key or "").strip()
    normalized_ef = normalized_ef_raw.lower() if len(normalized_ef_raw) > 0 else None
    normalized_pe = str(pe_section_key or "").strip() or None

    if normalized_field == "sdPersoData":
        # GlobalPlatform Amendment A DGI personalisation blocks. The
        # SAIP shell's INFO renderer goes through the same decoder so
        # the Decoded pane in either TUI shows the SCP80 connectivity
        # tags (84/85/86/89) and the GP Amendment A DGI names
        # (0070, 8010, ...) without diverging from CLI output.
        from .saip_dgi_decode import decode_dgi_records as _decode_dgi_records

        candidate_value = raw_value
        if isinstance(raw_value, dict):
            tagged_hex = _hex_from_tagged_bytes(raw_value)
            if tagged_hex is not None:
                candidate_value = [tagged_hex]
        elif isinstance(raw_value, list):
            collected: list[str] = []
            for item in raw_value:
                if isinstance(item, dict):
                    item_hex = _hex_from_tagged_bytes(item)
                    if item_hex is not None:
                        collected.append(item_hex)
                        continue
                if isinstance(item, str):
                    collected.append(item)
            candidate_value = collected
        try:
            decoded_dgi = _decode_dgi_records(candidate_value)
        except Exception:
            decoded_dgi = None
        if isinstance(decoded_dgi, list) and len(decoded_dgi) > 0:
            return {
                "title": _readonly_view_title(normalized_field, normalized_ef_raw),
                "note": _READONLY_VIEW_NOTE,
                "editor_kind": _READONLY_VIEW_EDITOR_KIND,
                "payload": {
                    "format": "DGI",
                    "blocks": decoded_dgi,
                },
            }

    if normalized_field == "fillFileContent" and normalized_ef is not None:
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is not None and len(raw_hex) > 0:
            try:
                decoded_ef = _decode_known_ef_payload(
                    ef_key=normalized_ef,
                    fid=None,
                    hex_clean=raw_hex,
                    parent_hint=normalized_pe,
                )
            except Exception:
                decoded_ef = None
            if isinstance(decoded_ef, (dict, list)):
                return {
                    "title": _readonly_view_title(normalized_field, normalized_ef_raw),
                    "note": _READONLY_VIEW_NOTE,
                    "editor_kind": _READONLY_VIEW_EDITOR_KIND,
                    "payload": _readonly_view_payload(decoded_ef),
                }

    raw_hex = _hex_from_tagged_bytes(raw_value)
    if raw_hex is not None and len(raw_hex) > 0:
        try:
            value_bytes = bytes.fromhex(raw_hex)
        except ValueError:
            value_bytes = None
        if value_bytes is not None and len(normalized_field) > 0:
            try:
                decoded_bytes = _decode_special_field(
                    normalized_field,
                    value_bytes,
                    parent_hint=normalized_pe,
                )
            except Exception:
                decoded_bytes = None
            if isinstance(decoded_bytes, (dict, list)):
                return {
                    "title": _readonly_view_title(normalized_field, normalized_ef_raw),
                    "note": _READONLY_VIEW_NOTE,
                    "editor_kind": _READONLY_VIEW_EDITOR_KIND,
                    "payload": _readonly_view_payload(decoded_bytes),
                }

    if len(normalized_field) > 0 and isinstance(raw_value, (dict, list)) is False:
        try:
            decoded_scalar = _decode_scalar_special_field(normalized_field, raw_value)
        except Exception:
            decoded_scalar = None
        if isinstance(decoded_scalar, (dict, list)):
            return {
                "title": _readonly_view_title(normalized_field, normalized_ef_raw),
                "note": _READONLY_VIEW_NOTE,
                "editor_kind": _READONLY_VIEW_EDITOR_KIND,
                "payload": _readonly_view_payload(decoded_scalar),
            }

    return None


_ROUNDTRIP_EDITOR_KIND = "roundtrip_decoded"
_ROUNDTRIP_EDITOR_NOTE = (
    "The default decoded tab shows a short layout summary. Full ASN.1-shaped "
    "structure is under SHOW JSON; edits there re-encode back to tagged bytes on save."
)

# Record-structured EFs whose decoders are intentionally lossy (alpha-id
# UTF-8 renders, CCI byte for ADN, opaque sub-TLVs inside A4 wrappers for
# ARR). Their splice-encoders in ``saip_asn1_encode`` need the original
# bytes to preserve the undecoded slices verbatim, so the editor model
# carries them under a ``_ygg_original_hex`` hint.
_LOSSY_SPLICE_EF_KEYS: frozenset[str] = frozenset(
    {
        "ef-adn",
        "ef-fdn",
        "ef-sdn",
        "ef-smsp",
        "ef-arr",
        "ef-msisdn",
        "ef-ecc",
        "ef-lnd",
        "ef-ici",
        "ef-oci",
        "ef-anr",
        "ef-anra",
        "ef-anrb",
        "ef-anrc",
        "ef-mbdn",
    }
)

# Non-lossy encoders that still benefit from seeing the original bytes so
# they can short-circuit to byte-identical output when the decoded form
# hasn't been modified. Only the hex hint is injected for these; the note
# remains the regular round-trip note (nothing special to warn about).
_HEX_HINTED_EF_KEYS: frozenset[str] = frozenset(
    {
        "ef-spn",
        "ef-pnn",
        "ef-opl",
        "ef-spdi",
        "ef-epsnsc",
        "ef-pcscf",
        "ef-sms",
        "ef-smsr",
        "ef-dir",
        "ef-ust",
        "ef-est",
        "ef-ist",
        "ef-loci",
        "ef-psloci",
        "ef-epsloci",
        "ef-puct",
        "ef-acl",
        "ef-gbanl",
        "ef-pkcs15-odf",
        "ef-pkcs15-dodf",
        "ef-pkcs15-acm",
        "ef-pkcs15-accf",
        "ef-gid1",
        "ef-gid2",
        "ef-cbmi",
        "ef-cbmid",
        "ef-cbmir",
        # 5x5 Pass A additions.
        "ef-ext1",
        "ef-ext2",
        "ef-ext3",
        "ef-ccp1",
        "ef-ccp2",
        "ef-cmi",
        "ef-keys",
        "ef-keysPS",
        "ef-kc",
        "ef-kcgprs",
        "ef-hiddenkey",
        "ef-netpar",
        "ef-nia",
        "ef-lrplmnsi",
        "ef-nasconfig",
        "ef-sume",
        "ef-suci-calc-info-usim",
        "ef-supinai",
        "ef-pkcs15-acrf",
        "ef-cpbcch",
        "ef-invscan",
        "ef-s7",
        # 5x10 additions — 5G EFs (DF.5GS).
        "ef-5gs3gpploci",
        "ef-5gsn3gpploci",
        "ef-5gs3gppnsc",
        "ef-5gsn3gppnsc",
        "ef-5gauthkeys",
        "ef-uac-aic",
        "ef-5g-suci-calc-info",
        "ef-opl5g",
        "ef-routing-indicator",
        "ef-ursp",
        "ef-tn3gppsnn",
        "ef-uplmnwlan",
        "ef-oplmnwlan",
        "ef-wlrplmn",
        "ef-5gsedrx",
        "ef-5gnswo-conf",
        # 5x10 additions — Phonebook family.
        "ef-pbr",
        "ef-iap",
        "ef-sne",
        "ef-snea",
        "ef-sneb",
        "ef-email",
        "ef-emailb",
        "ef-gas",
        "ef-grp",
        "ef-psc",
        "ef-cc",
        "ef-puid",
        # 5x10 additions — legacy 3GPP.
        "ef-phase",
        "ef-plmnsel",
        "ef-bcch",
        "ef-locigprs",
        "ef-fdnuri",
        "ef-sdnuri",
        "ef-lnduri",
        # 5x10 additions — ISIM + multimedia extras.
        "ef-pcscf-urn",
        "ef-muddomain",
        "ef-psismsc",
        "ef-uiccsi",
        "ef-ehuri",
        "ef-impdf",
        "ef-nafkca-list",
        "ef-earfcnlist",
        "ef-fcst",
        "ef-phist",
        # 5x20 Pass A additions (Mailbox / CF / VGCS / VBS / eMLPP / DCK).
        "ef-ext6",
        "ef-ext7",
        "ef-mbi",
        "ef-mwis",
        "ef-cfis",
        "ef-cfis2",
        "ef-mbparam",
        "ef-dck",
        "ef-cnl",
        "ef-vgcs",
        "ef-vgcss",
        "ef-vbs",
        "ef-vbss",
        "ef-emlpp",
        "ef-aaem",
        "ef-anl",
        "ef-mexe-st",
        "ef-prose-pfsr",
        "ef-vsuri",
        # 5x20 Pass B — CSIM family.
        "ef-csim-spc",
        "ef-csim-smscap",
        "ef-csim-min",
        "ef-csim-min1",
        "ef-csim-accolc",
        "ef-csim-imsi-t",
        "ef-csim-home-sidnid",
        "ef-csim-curr-sidnid",
        "ef-csim-nam-lock",
        "ef-csim-3gpd",
        "ef-csim-hpplmnact",
        "ef-csim-prl",
        "ef-csim-eprl",
        "ef-csim-namgam",
        "ef-csim-mdn",
        "ef-csim-plslpp",
        "ef-csim-hrpdcap",
        "ef-csim-ssci",
        "ef-csim-mlpl",
        "ef-csim-meruiid",
        # 5x20 Pass C — Specialized (ISIM/MCPTT/V2X/ProSe/MCS).
        "ef-prose-pfidg",
        "ef-prose-pfddn",
        "ef-v2x-cfg",
        "ef-v2x-pre-cfg",
        "ef-v2x-cert",
        "ef-v2x-auth-keys",
        "ef-mcs-root",
        "ef-mcptt-cfg",
        "ef-mcptt-sip",
        "ef-mcs-user-id",
        "ef-mcs-app-list",
        "ef-mcs-gms",
        "ef-mcs-cmsi",
        "ef-mcs-media-cfg",
        "ef-mcs-pub-id",
        "ef-mcs-profile",
        "ef-mcs-emergency",
        "ef-mcs-keyset",
        "ef-mcs-stat",
        "ef-mcs-sec-profile",
        # 5x20 Pass D — Operator / vendor / auxiliary.
        "ef-opcust1",
        "ef-opcust2",
        "ef-opcust3",
        "ef-opcust4",
        "ef-opcust5",
        "ef-vendor1",
        "ef-vendor2",
        "ef-vendor3",
        "ef-vendor4",
        "ef-vendor5",
        "ef-scp11key",
        "ef-scp80ctr",
        "ef-simlock-state",
        "ef-ota-state",
        "ef-ota-keys",
        "ef-provconfig",
        "ef-selfservice",
        "ef-appconfig",
        "ef-acmp",
        "ef-tui",
    }
)
_LOSSY_SPLICE_EDITOR_NOTE = (
    "Lossy-splice decoded editor. Undecoded bytes (alpha-id padding, CCI, "
    "inner security TLVs) are preserved from the original record via the "
    "'_ygg_original_hex' hint — do not edit or remove that field. Edit only "
    "the semantic fields you want to change; the splicer rewrites only the "
    "bytes whose decoded value differs from the original."
)


# Friendly titles for EFs whose roundtrip editor benefits from a spec
# citation in the editor header. The gap analysis flagged these as
# "missing dedicated wizards" — the underlying editor is already
# round-trip capable, so the only thing missing was a per-EF label that
# named the file plus the standards section it implements. New entries
# go here rather than scattering them across the EF decoders.
_EF_FRIENDLY_TITLES: dict[str, str] = {
    "ef-dir": "EF.DIR — Application Directory · TS 102 221 §13.1",
    "ef-routing-indicator": (
        "EF.Routing_Indicator — TS 31.102 §4.4.11.10"
    ),
    "ef-suci-calc-info": (
        "EF.SUCI_Calc_Info — 5GS SUCI Calculation · TS 31.102 §4.4.11.8"
    ),
    "ef-suci-calc-info-usim": (
        "EF.SUCI_Calc_Info (USIM 4F01) — TS 31.102 §4.4.11.8"
    ),
    "ef-ursp": (
        "EF.URSP — UE Route Selection Policy · TS 31.102 §4.4.11.10 / TS 24.526"
    ),
    "ef-imsi": "EF.IMSI — TS 31.102 §4.4.11.1",
    "ef-iccid": "EF.ICCID — TS 102 221 §13.2",
    "ef-arr": "EF.ARR — Access Rule Reference · TS 102 221 §11.1.1.4",
    "ef-ust": "EF.UST — USIM Service Table · TS 31.102 §4.2.8",
    "ef-est": "EF.EST — Enabled Services Table · TS 31.102 §4.2.24",
    "ef-ist": "EF.IST — ISIM Service Table · TS 31.103 §4.2.7",
    "ef-spn": "EF.SPN — Service Provider Name · TS 31.102 §4.2.12",
    "ef-pl": "EF.PL — Preferred Languages · TS 102 221 §13.3",
    "ef-li": "EF.LI — Language Indication · TS 31.102 §4.2.6",
    "ef-acc": "EF.ACC — Access Control Class · TS 31.102 §4.2.15",
    "ef-ad": "EF.AD — Administrative Data · TS 31.102 §4.2.18",
    "ef-pnn": "EF.PNN — PLMN Network Name · TS 31.102 §4.2.58",
    "ef-opl": "EF.OPL — Operator PLMN List · TS 31.102 §4.2.59",
    "ef-spdi": "EF.SPDI — Service Provider Display · TS 31.102 §4.2.66",
    "ef-msisdn": "EF.MSISDN — TS 31.102 §4.2.26",
    "ef-fdn": "EF.FDN — Fixed Dialling Numbers · TS 31.102 §4.4.2",
    "ef-adn": "EF.ADN — Abbreviated Dialling Numbers · TS 31.102 §4.4.2",
    "ef-sdn": "EF.SDN — Service Dialling Numbers · TS 31.102 §4.4.2",
    "ef-ecc": "EF.ECC — Emergency Call Codes · TS 31.102 §4.2.43",
    "ef-impi": "EF.IMPI — IMS Private User Identity · TS 31.103 §4.2.2",
    "ef-impu": "EF.IMPU — IMS Public User Identity · TS 31.103 §4.2.4",
    "ef-domain": "EF.DOMAIN — IMS Home Network Domain · TS 31.103 §4.2.3",
    "ef-pcscf": "EF.P-CSCF — IMS P-CSCF Address · TS 31.103 §4.2.8",
    "ef-5g-suci-calc-info": "EF.5G_SUCI_Calc_Info — TS 31.102 §4.4.11.8",
    "ef-5gauthkeys": "EF.5G_AUTH_KEYS — TS 31.102 §4.4.11.6",
    "ef-uac-aic": "EF.UAC_AIC — Access Identities Configuration · TS 31.102 §4.4.11.7",
    "ef-opl5g": "EF.OPL5G — 5GS Operator PLMN List · TS 31.102 §4.4.11.9",
    "ef-uplmnwlan": "EF.UPLMNWLAN — I-WLAN User PLMN List · TS 31.102 §4.2.82",
    "ef-oplmnwlan": "EF.OPLMNWLAN — I-WLAN Operator PLMN List · TS 31.102 §4.2.83",
    "ef-wlrplmn": "EF.WLRPLMN — I-WLAN Last Registered PLMN · TS 31.102 §4.2.91",
    "ef-tn3gppsnn": "EF.TN3GPPSNN — Trusted Non-3GPP SSID · TS 31.102 §4.4.11.11",
    "ef-supinai": "EF.SUPI_NAI — TS 31.102 §4.4.11.13",
    "ef-cag": "EF.CAG — Pre-configured CAG list · TS 31.102 §4.4.11.14",
}


def _roundtrip_editor_title(field_name: str, last_ef_key: str | None) -> str:
    base = str(field_name or "").strip() or "field"
    ef_token_raw = str(last_ef_key or "").strip()
    ef_token_lower = ef_token_raw.lower()
    friendly = _EF_FRIENDLY_TITLES.get(ef_token_lower)
    if base == "fillFileContent" and friendly is not None:
        return f"File data — {friendly}"
    if base == "fillFileContent" and len(ef_token_raw) > 0:
        return f"File data — {ef_token_raw}"
    if base == "fillFileContent":
        return "File data"
    if len(ef_token_raw) > 0:
        if friendly is not None:
            return f"Decoded — {friendly} / {base}"
        return f"Decoded — {ef_token_raw} / {base}"
    return f"Decoded — {base}"


def _roundtrip_editor_payload(decoded: Any) -> dict[str, Any]:
    if isinstance(decoded, dict):
        return dict(decoded)
    if isinstance(decoded, list):
        return {"items": list(decoded)}
    return {"value": decoded}


def build_decoded_value_roundtrip_model(
    *,
    field_name: str,
    raw_value: Any,
    last_ef_key: str | None = None,
    pe_section_key: str | None = None,
) -> dict[str, Any] | None:
    """Return an editable roundtrip-decoded model for a registered field.

    This dispatches to the pair-encoders in ``saip_asn1_encode`` and is
    only tried after the hand-written editors in
    ``build_decoded_value_editor_model`` decline the field.

    ``pe_section_key`` carries the enclosing PE section (``usim``,
    ``telecom``, ``isim``, ``csim`` …) through to
    ``_decode_known_ef_payload`` / ``_decode_special_field`` as the
    ``parent_hint`` so colliding FIDs resolve correctly.

    Returns ``None`` when the field has no registered roundtrip encoder.
    """

    normalized_field = str(field_name or "").strip()
    normalized_ef_raw = str(last_ef_key or "").strip()
    normalized_ef = normalized_ef_raw.lower() if len(normalized_ef_raw) > 0 else None
    normalized_pe = str(pe_section_key or "").strip() or None

    if normalized_field == "fillFileContent" and normalized_ef is not None:
        if normalized_ef not in roundtrip_capable_ef_keys():
            return None
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is None or len(raw_hex) == 0:
            return None
        try:
            decoded_ef = _decode_known_ef_payload(
                ef_key=normalized_ef,
                fid=None,
                hex_clean=raw_hex,
                parent_hint=normalized_pe,
            )
        except Exception:
            return None
        if isinstance(decoded_ef, (dict, list)) is False:
            return None
        target_length = len(raw_hex) // 2
        editor_payload = _roundtrip_editor_payload(decoded_ef)
        editor_note = _ROUNDTRIP_EDITOR_NOTE
        if normalized_ef in _LOSSY_SPLICE_EF_KEYS and isinstance(editor_payload, dict):
            editor_payload["_ygg_original_hex"] = str(raw_hex).upper()
            editor_note = _LOSSY_SPLICE_EDITOR_NOTE
        elif normalized_ef in _HEX_HINTED_EF_KEYS and isinstance(editor_payload, dict):
            editor_payload["_ygg_original_hex"] = str(raw_hex).upper()
        return {
            "title": _roundtrip_editor_title(normalized_field, normalized_ef_raw),
            "note": editor_note,
            "editor_kind": _ROUNDTRIP_EDITOR_KIND,
            "payload": editor_payload,
            "target_length": target_length,
        }

    capable_fields = roundtrip_capable_fields()
    kind = capable_fields.get(normalized_field)
    if kind is None:
        return None

    if kind == "bytes":
        raw_hex = _hex_from_tagged_bytes(raw_value)
        if raw_hex is not None and len(raw_hex) > 0:
            try:
                value_bytes = bytes.fromhex(raw_hex)
            except ValueError:
                return None
            try:
                decoded_bytes = _decode_special_field(
                    normalized_field,
                    value_bytes,
                    parent_hint=normalized_pe,
                )
            except Exception:
                decoded_bytes = None
            if isinstance(decoded_bytes, (dict, list)) is False:
                # Scalar-as-bytes fields (lifeCycleState etc.) are dispatched
                # through the scalar decoder because SAIP stores them as
                # tagged-bytes even though the decoder lives in the scalar
                # registry.
                try:
                    decoded_bytes = _decode_scalar_special_field(
                        normalized_field,
                        value_bytes,
                    )
                except Exception:
                    decoded_bytes = None
            if isinstance(decoded_bytes, (dict, list)) is False:
                return None
            return {
                "title": _roundtrip_editor_title(normalized_field, normalized_ef_raw),
                "note": _ROUNDTRIP_EDITOR_NOTE,
                "editor_kind": _ROUNDTRIP_EDITOR_KIND,
                "payload": _roundtrip_editor_payload(decoded_bytes),
                "target_length": len(value_bytes),
            }
        return None

    if kind == "scalar":
        if isinstance(raw_value, (dict, list)) is True:
            return None
        try:
            decoded_scalar = _decode_scalar_special_field(normalized_field, raw_value)
        except Exception:
            return None
        if isinstance(decoded_scalar, (dict, list)) is False:
            return None
        return {
            "title": _roundtrip_editor_title(normalized_field, normalized_ef_raw),
            "note": _ROUNDTRIP_EDITOR_NOTE,
            "editor_kind": _ROUNDTRIP_EDITOR_KIND,
            "payload": _roundtrip_editor_payload(decoded_scalar),
        }

    return None


def _encode_roundtrip_replacement(
    *,
    field_name: str,
    editor_payload: dict[str, Any],
    last_ef_key: str | None,
    target_length: int | None,
) -> Any:
    normalized_field = str(field_name or "").strip()
    normalized_ef = str(last_ef_key or "").strip().lower() if last_ef_key else ""

    if normalized_field == "fillFileContent" and normalized_ef != "":
        try:
            encoded_bytes = encode_decoded_roundtrip_ef_content(
                normalized_ef,
                editor_payload,
                target_length=target_length,
            )
        except RoundtripEncoderError as exc:
            raise ValueError(str(exc)) from exc
        if encoded_bytes is None:
            raise ValueError(
                f"No round-trip encoder registered for EF {normalized_ef!r}."
            )
        return _tagged_bytes(encoded_bytes.hex().upper())

    capable_fields = roundtrip_capable_fields()
    kind = capable_fields.get(normalized_field)
    if kind == "bytes":
        try:
            encoded_bytes = encode_decoded_roundtrip_bytes(
                normalized_field,
                editor_payload,
            )
        except RoundtripEncoderError as exc:
            raise ValueError(str(exc)) from exc
        if encoded_bytes is None:
            raise ValueError(
                f"No round-trip byte encoder registered for field {normalized_field!r}."
            )
        return _tagged_bytes(encoded_bytes.hex().upper())

    if kind == "scalar":
        try:
            encoded_scalar = encode_decoded_roundtrip_scalar(
                normalized_field,
                editor_payload,
            )
        except RoundtripEncoderError as exc:
            raise ValueError(str(exc)) from exc
        if encoded_scalar is None:
            raise ValueError(
                f"No round-trip scalar encoder registered for field {normalized_field!r}."
            )
        return encoded_scalar

    raise ValueError(
        f"Round-trip decoded editor does not support field {normalized_field!r}."
    )


_RAW_HEX_EDITOR_KIND = "raw_hex_decoded"
_RAW_HEX_EDITOR_NOTE = (
    "Raw hex editor. Replace the 'hex' string with the desired hex octets "
    "(e.g. 'A0B1C2'). The editor applies the bytes verbatim; no field-level "
    "decoding is performed."
)


def _raw_hex_editor_title(field_name: str, last_ef_key: str | None) -> str:
    base = str(field_name or "").strip() or "field"
    ef_token = str(last_ef_key or "").strip()
    if base == "fillFileContent" and len(ef_token) > 0:
        return f"Raw hex editor: {ef_token} file content"
    if len(ef_token) > 0:
        return f"Raw hex editor: {ef_token} / {base}"
    return f"Raw hex editor: {base}"


def build_decoded_value_raw_hex_model(
    *,
    field_name: str,
    raw_value: Any,
    last_ef_key: str | None = None,
) -> dict[str, Any] | None:
    """Return a raw-hex fallback editor for any tagged-bytes value.

    This is the final catch-all after the hand-written, roundtrip, and
    read-only decoded surfaces have all declined the field. It exposes
    the underlying hex string as the only editable field, which is still
    useful for rare or legacy fields that the project does not yet decode.

    Returns ``None`` when the value does not carry tagged bytes.
    """

    normalized_field = str(field_name or "").strip()
    normalized_ef_raw = str(last_ef_key or "").strip()
    raw_hex = _hex_from_tagged_bytes(raw_value)
    if raw_hex is None:
        return None
    compact = str(raw_hex).strip().upper()
    try:
        byte_len = len(bytes.fromhex(compact))
    except ValueError:
        return None
    return {
        "title": _raw_hex_editor_title(normalized_field, normalized_ef_raw),
        "note": _RAW_HEX_EDITOR_NOTE,
        "editor_kind": _RAW_HEX_EDITOR_KIND,
        "payload": {"hex": compact},
        "target_length": byte_len,
    }


def _encode_raw_hex_replacement(
    *,
    editor_payload: dict[str, Any],
    target_length: int | None,
) -> dict[str, str]:
    payload = dict(editor_payload)
    candidate = payload.get("hex")
    if candidate is None:
        candidate = payload.get("raw")
    if isinstance(candidate, str) is False:
        raise ValueError("Raw hex editor: provide 'hex' as a string.")
    compact = re.sub(r"\s+", "", candidate).upper()
    if len(compact) == 0:
        return _tagged_bytes("")
    if re.fullmatch(r"[0-9A-F]+", compact) is None:
        raise ValueError("Raw hex editor: 'hex' must contain only 0-9A-F characters.")
    if len(compact) % 2 != 0:
        raise ValueError("Raw hex editor: 'hex' must contain an even number of nibbles.")
    if (
        isinstance(target_length, int)
        and isinstance(target_length, bool) is False
        and target_length >= 0
        and len(compact) // 2 != target_length
    ):
        raise ValueError(
            f"Raw hex editor: expected {target_length} bytes, got {len(compact) // 2} bytes."
        )
    return _tagged_bytes(compact)


def encode_decoded_value_editor_payload(
    *,
    field_name: str,
    editor_payload: dict[str, Any],
    last_ef_key: str | None = None,
    target_length: int | None = None,
    editor_kind: str | None = None,
) -> Any:
    """Encode a submitted editor payload back to a tagged-bytes JSON value.

    Inverse of ``build_decoded_value_editor_model``.  ``editor_kind``
    selects the encoding path; when ``None`` it is inferred from
    ``field_name``.  Raises ``ValueError`` for invalid or out-of-range
    input values.
    """
    normalized_field = str(field_name or "").strip()
    payload = dict(editor_payload)
    if normalized_field == "shortEFID":
        supported = bool(payload.get("supported", False))
        if supported is False:
            return _tagged_bytes("")
        sfi = _positive_int(payload.get("sfi"), label="sfi", minimum=1, maximum=30)
        return _tagged_bytes(f"{sfi << 3:02X}")
    if normalized_field == "efFileSize":
        byte_count = _positive_int(
            payload.get("byteCount"),
            label="byteCount",
            minimum=1,
        )
        width = max(1, (byte_count.bit_length() + 7) // 8)
        return _tagged_bytes(byte_count.to_bytes(width, "big", signed=False).hex().upper())
    if normalized_field == "securityAttributesReferenced":
        record_number = _positive_int(
            payload.get("recordNumber"),
            label="recordNumber",
            minimum=1,
            maximum=255,
        )
        arr_file_id = str(payload.get("arrFileId", "") or "").strip()
        if len(arr_file_id) == 0:
            return _tagged_bytes(f"{record_number:02X}")
        fid_hex = _clean_hex(arr_file_id, label="arrFileId", expected_nibbles=4)
        return _tagged_bytes(fid_hex + f"{record_number:02X}")
    if normalized_field == "lcsi":
        state = str(payload.get("state", "") or "").strip().lower()
        lcsi_hex = _LCSI_STATE_TO_HEX.get(state)
        if lcsi_hex is None:
            raise ValueError(
                "state must be one of: "
                + ", ".join(sorted(_LCSI_STATE_TO_HEX.keys()))
            )
        return _tagged_bytes(lcsi_hex)
    if normalized_field == "fillFileOffset":
        return _positive_int(payload.get("offset"), label="offset", minimum=0)
    if normalized_field == "fileID":
        return _tagged_bytes(_clean_hex(payload.get("fid"), label="fid", expected_nibbles=4))
    if normalized_field == "iccid":
        iccid = str(payload.get("iccid", "") or "").strip()
        return _tagged_bytes(encode_iccid_ef_hex(iccid).upper())
    if normalized_field == "fillFileContent" and _service_table_definition(last_ef_key) is not None:
        return _encode_service_table_payload(payload)
    if normalized_field == "fillFileContent" and str(last_ef_key or "").strip() == "ef-imsi":
        imsi = str(payload.get("imsi", "") or "").strip()
        return _tagged_bytes(encode_imsi_ef_hex(imsi).upper())
    if normalized_field == "fillFileContent" and str(last_ef_key or "").strip() == "ef-iccid":
        iccid = str(payload.get("iccid", "") or "").strip()
        return _tagged_bytes(encode_iccid_ef_hex(iccid).upper())
    # Fall through: try the roundtrip encoder registry for any field that
    # isn't wired to a hand-written editor above.
    normalized_kind = str(editor_kind or "").strip().lower()
    if (
        normalized_kind == _ROUNDTRIP_EDITOR_KIND
        or normalized_field in roundtrip_capable_fields()
        or (
            normalized_field == "fillFileContent"
            and str(last_ef_key or "").strip().lower() in roundtrip_capable_ef_keys()
        )
    ):
        return _encode_roundtrip_replacement(
            field_name=normalized_field,
            editor_payload=payload,
            last_ef_key=last_ef_key,
            target_length=target_length,
        )
    if normalized_kind == _RAW_HEX_EDITOR_KIND:
        return _encode_raw_hex_replacement(
            editor_payload=payload,
            target_length=target_length,
        )
    raise ValueError(f"Decoded editor does not support field {normalized_field!r}.")


_TUPLE_TAG_KEYS = ("@", "__ygg_saip_tuple__")
_BYTES_TAG_KEYS = ("hex", "__ygg_saip_bytes__")


def _summarize_for_picker(
    *,
    field_name: str,
    raw_value: Any,
    model_kind: str,
    payload: Any,
) -> str:
    """
    One-line summary for the PE-field picker. Shows the decoder's editor
    kind plus a short value preview (hex prefix for byte blobs, direct
    representation for scalars), truncated to keep the OptionList rows
    scannable at typical terminal widths.
    """
    kind_label = str(model_kind or "").strip() or "decoded"
    hex_value = _hex_from_tagged_bytes(raw_value)
    if hex_value is not None:
        compact = str(hex_value or "").upper()
        byte_len = len(compact) // 2
        preview = compact[:24] + ("…" if len(compact) > 24 else "")
        return f"{kind_label} · {byte_len}B · {preview}"
    if isinstance(payload, dict):
        flat_parts: list[str] = []
        for key, value in list(payload.items())[:3]:
            value_text = str(value)
            if len(value_text) > 24:
                value_text = value_text[:24] + "…"
            flat_parts.append(f"{key}={value_text}")
        if len(payload) > 3:
            flat_parts.append("…")
        return f"{kind_label} · {' '.join(flat_parts)}" if flat_parts else kind_label
    if isinstance(payload, (list, tuple)):
        return f"{kind_label} · [{len(payload)} entries]"
    if payload is None:
        return kind_label
    value_text = str(payload)
    if len(value_text) > 48:
        value_text = value_text[:48] + "…"
    return f"{kind_label} · {value_text}"


def _display_path_from_rel(rel_path: list[Any], field_name: str) -> str:
    """
    Human-readable rendering of a relative path inside a profile element.
    Every ``[<tag-marker>, 1]`` pair (the SAIP tagged-tuple value slot)
    is elided, and a trailing tuple slot is replaced with the field name
    so ``['ef-iccid', 0, '@', 1]`` becomes ``ef-iccid / [0] / fillFileContent``
    and ``['adf-usim', 0, '@', 1, 'lcsi']`` becomes ``adf-usim / [0] / lcsi``.
    """
    parts: list[str] = []
    work = list(rel_path)
    replaced_tail_with_field = False
    if (
        len(work) >= 2
        and work[-1] == 1
        and work[-2] in _TUPLE_TAG_KEYS
    ):
        work = work[:-2]
        replaced_tail_with_field = True
    idx = 0
    while idx < len(work):
        segment = work[idx]
        if (
            segment in _TUPLE_TAG_KEYS
            and idx + 1 < len(work)
            and work[idx + 1] == 1
        ):
            idx += 2
            continue
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        else:
            parts.append(str(segment))
        idx += 1
    if replaced_tail_with_field:
        parts.append(str(field_name or "(tagged)"))
    elif len(parts) == 0:
        parts.append(str(field_name or "(root)"))
    return " / ".join(parts)


_GFM_LEGACY_EF_KEYS_BY_PARENT_FID: dict[tuple[str, str], str] = {
    # MF-level EFs, ETSI TS 102 221 §13.
    ("3F00", "2FE2"): "ef-iccid",
    ("3F00", "2F00"): "ef-dir",
    ("3F00", "2F05"): "ef-pl",
    ("3F00", "2F06"): "ef-arr",
    ("7F10", "6F06"): "ef-arr",
    ("7FF2", "6F06"): "ef-arr",
    ("7FF3", "6F06"): "ef-arr",
    # DF.TELECOM, TS 51.011 §10.4. These share content layouts with
    # the modern 3GPP EF tokens and must still reach the same editors.
    ("7F10", "6F3A"): "ef-adn",
    ("7F10", "6F3B"): "ef-fdn",
    ("7F10", "6F3C"): "ef-sms",
    ("7F10", "6F40"): "ef-msisdn",
    ("7F10", "6F42"): "ef-smsp",
    ("7F10", "6F43"): "ef-smss",
    ("7F10", "6F44"): "ef-lnd",
    ("7F10", "6F47"): "ef-smsr",
    ("7F10", "6F49"): "ef-sdn",
    ("7F10", "6F4A"): "ef-ext1",
    ("7F10", "6F4B"): "ef-ext2",
    ("7F10", "6F4C"): "ef-ext3",
    ("7F10", "6F53"): "ef-rma",
    ("7F10", "6F54"): "ef-sume",
    # DF.GSM, TS 51.011 §10.3. Parent-token lookup alone is ambiguous
    # because 7F20 is also reused by DF.EAP in newer templates.
    ("7F20", "6F05"): "ef-li",
    ("7F20", "6F07"): "ef-imsi",
    ("7F20", "6F20"): "ef-kc",
    ("7F20", "6F30"): "ef-plmnsel",
    ("7F20", "6F31"): "ef-hpplmn",
    ("7F20", "6F37"): "ef-acmax",
    ("7F20", "6F38"): "ef-ust",
    ("7F20", "6F39"): "ef-acm",
    ("7F20", "6F41"): "ef-puct",
    ("7F20", "6F45"): "ef-cbmi",
    ("7F20", "6F46"): "ef-spn",
    ("7F20", "6F74"): "ef-bcch",
    ("7F20", "6F78"): "ef-acc",
    ("7F20", "6F7B"): "ef-fplmn",
    ("7F20", "6F7E"): "ef-loci",
    ("7F20", "6FAD"): "ef-ad",
    # DF.GSM-ACCESS under USIM.
    ("5F3B", "4F20"): "ef-kc",
    ("5F3B", "4F52"): "ef-kcgprs",
    ("5F3B", "4F63"): "ef-cpbcch",
    ("5F3B", "4F64"): "ef-invscan",
}


def _gfm_choice_tuple(node: Any) -> tuple[str, Any, str] | None:
    if isinstance(node, dict) is False:
        return None
    for tuple_tag_key in _TUPLE_TAG_KEYS:
        tagged = node.get(tuple_tag_key)
        if (
            isinstance(tagged, list)
            and len(tagged) == 2
            and isinstance(tagged[0], str)
        ):
            return str(tagged[0]), tagged[1], tuple_tag_key
    return None


def _gfm_path_segments(path_value: Any) -> list[str]:
    raw_hex = _hex_from_tagged_bytes(path_value)
    if raw_hex is None:
        return ["3F00"]
    compact = re.sub(r"\s+", "", raw_hex).upper()
    if compact == "":
        return ["3F00"]
    if len(compact) % 4 != 0:
        return ["3F00"]
    segments = [
        compact[offset : offset + 4]
        for offset in range(0, len(compact), 4)
    ]
    if len(segments) > 0 and segments[0] == "3F00":
        return segments
    return ["3F00"] + segments


def _gfm_parent_token(parent_chain: list[str]) -> str | None:
    if len(parent_chain) == 0:
        return None
    parent_hex = "".join(part for part in parent_chain if re.fullmatch(r"[0-9A-F]{4}", part))
    token = parent_token_from_file_path_hex(parent_hex)
    if token is not None:
        return token
    tail = parent_chain[-1]
    return parent_token_for_container_fid(tail)


def _gfm_ef_key_from_create_fcp(
    create_fcp_value: Any,
    parent_chain: list[str],
) -> str | None:
    if isinstance(create_fcp_value, dict) is False:
        return None
    fid_hex = _hex_from_tagged_bytes(create_fcp_value.get("fileID"))
    if fid_hex is None:
        return None
    fid = re.sub(r"\s+", "", fid_hex).upper()[:4]
    if len(fid) != 4:
        return None
    if len(parent_chain) > 0:
        legacy_key = _GFM_LEGACY_EF_KEYS_BY_PARENT_FID.get((parent_chain[-1], fid))
        if legacy_key is not None:
            return legacy_key
    parent_token = _gfm_parent_token(parent_chain)
    resolved = _resolve_ef_key_for_fid(fid, parent_token)
    if resolved is not None:
        return resolved
    return _GFM_LEGACY_EF_KEYS_BY_PARENT_FID.get(("3F00", fid))


def _gfm_create_fcp_is_container(create_fcp_value: Any) -> bool:
    if isinstance(create_fcp_value, dict) is False:
        return False
    if _hex_from_tagged_bytes(create_fcp_value.get("dfName")) is not None:
        return True
    desc_hex = _hex_from_tagged_bytes(create_fcp_value.get("fileDescriptor"))
    if desc_hex is None:
        return False
    try:
        desc = _decode_file_descriptor(bytes.fromhex(desc_hex))
    except ValueError:
        return False
    return isinstance(desc, dict) and desc.get("fileType") == "df"


def _resolve_pe_editor_model_for_enumeration(
    *,
    field_name: str,
    raw_value: Any,
    last_ef_key: str | None,
    pe_section_key: str | None,
) -> dict[str, Any] | None:
    """
    Resolve the best-available editor model for a field during PE
    enumeration. Order of preference mirrors the single-selection
    dispatch in the TUI so that ``enumerate_pe_decodable_fields``
    returns the exact set the operator would see by clicking through
    each field one at a time:

    1. Hand-written ``build_decoded_value_editor_model`` (service
       tables, shortEFID, ICCID, IMSI, LCSI, file ID, fillFileOffset,
       ARR reference, EF file size).
    2. Registered round-trip encoder
       (``build_decoded_value_roundtrip_model``) for every EF / field
       wired into the ``saip_asn1_encode`` registry.
    3. Read-only decoded view (``build_decoded_value_readonly_view``)
       for fields with a semantic decoder but no encoder yet. The
       model is tagged with ``read_only=True`` so the bulk form can
       surface it without accepting edits.
    4. Raw-hex fallback (``build_decoded_value_raw_hex_model``) for
       any remaining tagged-bytes field so the whole PE stays
       editable — even legacy or niche fields the project hasn't
       decoded yet.

    Returns ``None`` only when the field carries no tagged bytes and
    no scalar decoder recognises it (i.e. nothing editable is left).
    """
    hand_written = build_decoded_value_editor_model(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
        pe_section_key=pe_section_key,
    )
    if isinstance(hand_written, dict):
        enriched = dict(hand_written)
        enriched.setdefault(
            "editor_kind", str(hand_written.get("editor_kind", "json") or "json"),
        )
        enriched.setdefault("read_only", False)
        return enriched

    roundtrip = build_decoded_value_roundtrip_model(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
        pe_section_key=pe_section_key,
    )
    if isinstance(roundtrip, dict):
        enriched = dict(roundtrip)
        enriched.setdefault("editor_kind", _ROUNDTRIP_EDITOR_KIND)
        enriched.setdefault("read_only", False)
        return enriched

    readonly = build_decoded_value_readonly_view(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
        pe_section_key=pe_section_key,
    )
    if isinstance(readonly, dict):
        # Fall through to raw-hex — semantic decode succeeded but no
        # round-trip encoder exists. The decoded form is surfaced as a
        # reference summary; editing happens via the raw hex surface.
        pass

    raw_hex = build_decoded_value_raw_hex_model(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
    )
    if isinstance(raw_hex, dict):
        enriched = dict(raw_hex)
        enriched.setdefault("editor_kind", _RAW_HEX_EDITOR_KIND)
        enriched.setdefault("read_only", False)
        return enriched

    return None


def enumerate_pe_decodable_fields(
    pe_value: Any,
    *,
    pe_section_key: str,
) -> list[dict[str, Any]]:
    """
    Walk a profile-element JSON value and return every decodable field
    together with the data needed to splice an edit back into the
    top-level JSON document.

    Each returned entry has::

        {
            "field_name": "<tag>",
            "rel_path": [...],           # path inside the PE value
            "raw_value": <json sub-tree>,
            "last_ef_key": "ef-xxx" or None,
            "pe_section_key": "<pe key>",
            "model": {...},              # result of the editor model
            "editor_kind": "...",        # lifted from model for convenience
            "target_length": int | None, # lifted from model (bytes)
            "read_only": bool,           # True for pure readonly views
            "display_path": "...",
            "summary": "...",
        }

    The entry set is intentionally broad: hand-written editors,
    round-trip encoders, read-only decoders, and raw-hex fallbacks
    are all surfaced. The bulk PE form can therefore present every
    non-trivial field of the PE in one place (application / domain
    PEs benefit the most — file-system PEs still route through the
    EF-scoped form).

    Recognised shapes:

    * ``{"<field>": {"hex": "..."}}`` — plain hex-valued field on a dict.
    * ``{"@": ["<field>", <value>]}`` — tagged tuple (SAIP profile-element
      items commonly used for ``fillFileContent`` and similar).

    Duplicate field names across different EFs are retained (each is a
    distinct editable instance with a unique ``rel_path``).
    """
    normalized_pe_key = str(pe_section_key or "").strip() or None
    entries: list[dict[str, Any]] = []
    seen_paths: set[tuple[Any, ...]] = set()

    def register(
        *,
        field_name: str,
        rel_path: list[Any],
        raw_value: Any,
        last_ef_key: str | None,
        gfm_file_path: str | None = None,
    ) -> None:
        """Register a decoded-field editor class for the given PE type and tag path."""
        key = tuple(rel_path)
        if key in seen_paths:
            return
        model = _resolve_pe_editor_model_for_enumeration(
            field_name=field_name,
            raw_value=raw_value,
            last_ef_key=last_ef_key,
            pe_section_key=normalized_pe_key,
        )
        if isinstance(model, dict) is False:
            return
        seen_paths.add(key)
        editor_kind = str(model.get("editor_kind", "") or "").strip().lower() or "json"
        target_length = model.get("target_length")
        if isinstance(target_length, int) is False or isinstance(target_length, bool):
            target_length = None
        entries.append({
            "field_name": str(field_name),
            "rel_path": list(rel_path),
            "raw_value": raw_value,
            "last_ef_key": last_ef_key,
            "pe_section_key": normalized_pe_key,
            "model": model,
            "editor_kind": editor_kind,
            "target_length": target_length,
            "read_only": bool(model.get("read_only", False)),
            "display_path": _display_path_from_rel(rel_path, str(field_name)),
            "summary": _summarize_for_picker(
                field_name=field_name,
                raw_value=raw_value,
                model_kind=editor_kind,
                payload=model.get("payload"),
            ),
        })
        if gfm_file_path is not None:
            entries[-1]["gfm_file_path"] = gfm_file_path

    def walk_gfm_commands(commands: Any, rel_path: list[Any]) -> None:
        if isinstance(commands, list) is False:
            walk(commands, rel_path, None, None)
            return
        select_chain: list[str] = ["3F00"]
        for transaction_index, transaction in enumerate(commands):
            if isinstance(transaction, list) is False:
                walk(transaction, rel_path + [transaction_index], None, None)
                continue
            transaction_container_chain: list[str] | None = None
            active_ef_key: str | None = None
            active_gfm_file_path: str | None = None
            for command_index, item in enumerate(transaction):
                tuple_info = _gfm_choice_tuple(item)
                item_path = rel_path + [transaction_index, command_index]
                if tuple_info is None:
                    walk(item, item_path, active_ef_key, active_gfm_file_path)
                    continue
                tag_name, value, tuple_tag_key = tuple_info
                value_path = item_path + [tuple_tag_key, 1]
                if tag_name == "filePath":
                    register(
                        field_name=tag_name,
                        rel_path=value_path,
                        raw_value=value,
                        last_ef_key=None,
                    )
                    walk(value, value_path, None, None)
                    select_chain = _gfm_path_segments(value)
                    transaction_container_chain = None
                    active_ef_key = None
                    active_gfm_file_path = None
                    continue
                if tag_name == "createFCP":
                    parent_chain = transaction_container_chain or select_chain
                    create_ef_key = _gfm_ef_key_from_create_fcp(value, parent_chain)
                    create_gfm_file_path = f"fileManagementCMD[{transaction_index}][{command_index}]"
                    register(
                        field_name=tag_name,
                        rel_path=value_path,
                        raw_value=value,
                        last_ef_key=create_ef_key,
                        gfm_file_path=create_gfm_file_path,
                    )
                    walk(value, value_path, create_ef_key, create_gfm_file_path)
                    if _gfm_create_fcp_is_container(value):
                        fid_hex = _hex_from_tagged_bytes(
                            value.get("fileID") if isinstance(value, dict) else None
                        )
                        fid = re.sub(r"\s+", "", fid_hex or "").upper()[:4]
                        if len(fid) == 4:
                            transaction_container_chain = list(parent_chain) + [fid]
                        active_ef_key = None
                        active_gfm_file_path = None
                    else:
                        active_ef_key = create_ef_key
                        active_gfm_file_path = create_gfm_file_path
                    continue
                register(
                    field_name=tag_name,
                    rel_path=value_path,
                    raw_value=value,
                    last_ef_key=active_ef_key,
                    gfm_file_path=active_gfm_file_path,
                )
                walk(value, value_path, active_ef_key, active_gfm_file_path)

    def walk(
        node: Any,
        rel_path: list[Any],
        last_ef_key: str | None,
        gfm_file_path: str | None,
    ) -> None:
        """Walk the decoded JSON tree and collect all editable field paths."""
        if isinstance(node, dict):
            for tuple_tag_key in _TUPLE_TAG_KEYS:
                if tuple_tag_key in node and isinstance(node[tuple_tag_key], list):
                    tagged = node[tuple_tag_key]
                    if (
                        len(tagged) == 2
                        and isinstance(tagged[0], str)
                    ):
                        register(
                            field_name=tagged[0],
                            rel_path=rel_path + [tuple_tag_key, 1],
                            raw_value=tagged[1],
                            last_ef_key=last_ef_key,
                            gfm_file_path=gfm_file_path,
                        )
                        walk(
                            tagged[1],
                            rel_path + [tuple_tag_key, 1],
                            last_ef_key,
                            gfm_file_path,
                        )
                    return
            for key, value in node.items():
                if key in _TUPLE_TAG_KEYS or key in _BYTES_TAG_KEYS:
                    continue
                if key == "fileManagementCMD":
                    walk_gfm_commands(value, rel_path + [key])
                    continue
                new_ef_key = last_ef_key
                if isinstance(key, str) and key.startswith("ef-"):
                    new_ef_key = key
                register(
                    field_name=str(key),
                    rel_path=rel_path + [key],
                    raw_value=value,
                    last_ef_key=new_ef_key,
                    gfm_file_path=gfm_file_path,
                )
                walk(value, rel_path + [key], new_ef_key, gfm_file_path)
            return
        if isinstance(node, list):
            for idx, item in enumerate(node):
                walk(item, rel_path + [idx], last_ef_key, gfm_file_path)

    walk(pe_value, [], None, None)
    return entries


# ---------------------------------------------------------------------------
# Nested form document helpers
#
# The bulk PE form mirrors the decoded pane's layout by laying every entry
# out inside a JSON tree that matches the SAIP PE structure. ``@`` / ``1``
# tuple markers are elided so the output is pure semantic hierarchy (same
# as the decoded pane would display for a single field). The apply path
# round-trips through ``extract_pe_form_entry_payload`` using the same
# insertion-path helper, so every entry's relative position in the tree
# stays stable across refreshes.
# ---------------------------------------------------------------------------


_MISSING_PAYLOAD_SENTINEL = object()


def _insertion_path_from_rel(
    rel_path: list[Any],
    field_name: str,
) -> list[Any]:
    """
    Turn a raw ``rel_path`` into the position the entry should occupy
    inside the nested form document. SAIP ``@`` / ``1`` tuple markers
    are elided; a trailing pair is replaced with ``field_name`` so the
    nested tree reads the same way the decoded pane displays the
    selected field.

    Example::

        rel_path = ["ef-iccid", 0, "@", 1]  # fillFileContent tuple
        field_name = "fillFileContent"
        -> ["ef-iccid", 0, "fillFileContent"]

    Middle ``@`` / ``1`` pairs (inner-tuple descents) are stripped
    outright because their field name is carried by the enclosing
    tuple's own entry; the nested tree surfaces the inner fields
    directly under the tuple's slot.
    """
    result: list[Any] = []
    work = list(rel_path)
    replaced_tail_with_field = False
    if (
        len(work) >= 2
        and work[-1] == 1
        and work[-2] in _TUPLE_TAG_KEYS
    ):
        work = work[:-2]
        replaced_tail_with_field = True
    idx = 0
    while idx < len(work):
        segment = work[idx]
        if (
            segment in _TUPLE_TAG_KEYS
            and idx + 1 < len(work)
            and work[idx + 1] == 1
        ):
            idx += 2
            continue
        result.append(segment)
        idx += 1
    if replaced_tail_with_field:
        result.append(str(field_name or ""))
    return result


def _ensure_container_for_next_segment(container: Any, next_segment: Any) -> Any:
    if isinstance(next_segment, int):
        return []
    return {}


def _insert_payload_at_path(
    root: Any,
    path: list[Any],
    payload: Any,
) -> None:
    """
    Insert ``payload`` into ``root`` at ``path``. Integer segments
    extend a list; string segments create/use a dict. Pre-existing
    container mismatches raise ``ValueError`` because that would
    indicate two entries pointing at the same slot with different
    structures — a decoder bug worth surfacing.
    """
    if len(path) == 0:
        raise ValueError("Cannot insert payload at an empty path.")
    cursor = root
    for idx, segment in enumerate(path):
        is_last = idx == len(path) - 1
        if isinstance(segment, int):
            if isinstance(cursor, list) is False:
                raise ValueError(
                    f"Path segment {idx} expected a list container, got {type(cursor).__name__}."
                )
            while len(cursor) <= segment:
                cursor.append(None)
            if is_last:
                cursor[segment] = payload
                return
            if cursor[segment] is None:
                cursor[segment] = _ensure_container_for_next_segment(
                    cursor[segment],
                    path[idx + 1],
                )
            cursor = cursor[segment]
            continue
        if isinstance(cursor, dict) is False:
            raise ValueError(
                f"Path segment {idx} expected a dict container, got {type(cursor).__name__}."
            )
        if is_last:
            cursor[segment] = payload
            return
        if segment not in cursor or cursor[segment] is None:
            cursor[segment] = _ensure_container_for_next_segment(
                cursor.get(segment),
                path[idx + 1],
            )
        cursor = cursor[segment]


def build_pe_form_document(
    entries: list[dict[str, Any]],
) -> dict[str, Any] | list[Any]:
    """
    Build a nested JSON document that mirrors the PE structure, with
    each entry's decoded payload placed at its insertion path. Matches
    the visual layout of the decoded pane — the operator sees the same
    semantic tree they would navigate field-by-field, just laid out in
    full so they can edit everything in one pass.
    """
    if len(entries) == 0:
        return {}
    first_path = _insertion_path_from_rel(
        list(entries[0].get("rel_path", []) or []),
        str(entries[0].get("field_name", "") or "").strip(),
    )
    if len(first_path) == 0:
        return {}
    root: dict[str, Any] | list[Any]
    if isinstance(first_path[0], int):
        root = []
    else:
        root = {}
    for entry in entries:
        rel_path = list(entry.get("rel_path", []) or [])
        field_name = str(entry.get("field_name", "") or "").strip()
        model = entry.get("model", {})
        payload = {}
        if isinstance(model, dict):
            payload = copy.deepcopy(model.get("payload", {}))
        insertion = _insertion_path_from_rel(rel_path, field_name)
        if len(insertion) == 0:
            continue
        _insert_payload_at_path(root, insertion, payload)
    return root


def extract_pe_form_entry_payload(
    document: Any,
    insertion_path: list[Any],
) -> Any:
    """
    Pull the payload at ``insertion_path`` out of ``document``. Returns
    the private ``_MISSING_PAYLOAD_SENTINEL`` when the path is absent so
    the apply path can distinguish "operator removed this slot" from
    "operator set the slot to null".
    """
    cursor = document
    for segment in insertion_path:
        if isinstance(segment, int):
            if isinstance(cursor, list) is False:
                return _MISSING_PAYLOAD_SENTINEL
            if segment < 0 or segment >= len(cursor):
                return _MISSING_PAYLOAD_SENTINEL
            cursor = cursor[segment]
            continue
        if isinstance(cursor, dict) is False:
            return _MISSING_PAYLOAD_SENTINEL
        if segment not in cursor:
            return _MISSING_PAYLOAD_SENTINEL
        cursor = cursor[segment]
    return cursor


def enumerate_pe_form_unknown_paths(
    document: Any,
    entry_insertion_paths: list[list[Any]],
) -> list[list[Any]]:
    """
    Walk ``document`` and return paths that do not correspond to any
    entry (neither as a terminal leaf nor as a prefix of one). Used by
    the apply step to flag unknown keys before any encoding happens.
    Descent stops at every terminal path so the payload dicts
    themselves are not scrutinised — their schema is the encoder's
    concern.
    """
    expected: set[tuple[Any, ...]] = {
        tuple(path) for path in entry_insertion_paths
    }
    prefixes: set[tuple[Any, ...]] = set()
    for path in expected:
        for length in range(len(path) + 1):
            prefixes.add(path[:length])
    unknown: list[list[Any]] = []

    def walk(node: Any, path: list[Any]) -> None:
        """Walk the decoded JSON tree recursively, yielding (path, value) tuples."""
        if tuple(path) in expected:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = path + [key]
                key_tuple = tuple(child_path)
                if key_tuple in expected:
                    continue
                if key_tuple in prefixes:
                    walk(value, child_path)
                    continue
                unknown.append(child_path)
            return
        if isinstance(node, list):
            for index, item in enumerate(node):
                child_path = path + [index]
                key_tuple = tuple(child_path)
                if key_tuple in expected:
                    continue
                if key_tuple in prefixes:
                    walk(item, child_path)
                    continue
                unknown.append(child_path)
            return

    walk(document, [])
    return unknown


def format_form_path_for_display(path: list[Any]) -> str:
    """
    Render an insertion path as a human-readable string for error
    messages. Mirrors ``_display_path_from_rel`` output style so
    messages from the form agree with the rest of the TUI.
    """
    parts: list[str] = []
    for segment in path:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
            continue
        parts.append(str(segment))
    if len(parts) == 0:
        return "(root)"
    return " / ".join(parts)
