# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ASN.1/TLV decoder: renders pasted BER/DER hex as JSON and value notation."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, TextIO


_UNIVERSAL_TAG_NAMES: dict[int, str] = {
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    10: "ENUMERATED",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "ASN1_SEQUENCE",
    17: "ASN1_SET",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    30: "BMPString",
}

_TAG_CLASS_NAMES: dict[int, str] = {
    0: "universal",
    1: "application",
    2: "context",
    3: "private",
}

_FALLBACK_TAGS: dict[str, tuple[str, str]] = {
    "2F00": ("APPLICATIONS_IN_SECURITY_DOMAIN", "GlobalPlatform / SGP.02"),
    "42": ("IIN", "SGP.02 / SGP.22 ECASD"),
    "45": ("CIN", "SGP.02 / SGP.22 ECASD"),
    "4F": ("AID", "ISO 7816-5 / GlobalPlatform"),
    "5A": ("EID_OR_ICCID", "SGP context dependent"),
    "5C": ("TAG_LIST", "GlobalPlatform / GSMA"),
    "66": ("SECURITY_DOMAIN_MANAGEMENT_DATA", "GlobalPlatform / SGP.02"),
    "67": ("CARD_CAPABILITY_INFORMATION", "GlobalPlatform / SGP.02"),
    "5F20": ("APPLICATION_PROVIDER_IDENTIFIER", "GlobalPlatform"),
    "5F37": ("SIGNATURE", "GSMA / GlobalPlatform"),
    "5F49": ("PUBLIC_KEY", "GSMA / GlobalPlatform"),
    "7F21": ("CERTIFICATE", "GlobalPlatform / SGP.02 ECASD"),
    "90": ("PROFILE_NICKNAME", "GSMA"),
    "91": ("SERVICE_PROVIDER_NAME", "GSMA"),
    "92": ("PROFILE_NAME", "GSMA"),
    "93": ("ICON_TYPE", "GSMA"),
    "94": ("ICON", "GSMA"),
    "95": ("PROFILE_CLASS", "GSMA"),
    "99": ("PROFILE_POLICY_RULES", "GSMA"),
    "9F26": ("FALLBACK_ATTRIBUTE", "SGP.32"),
    "9F2A": ("UPDATE_METADATA_RESPONSE", "SGP.22"),
    "9F67": ("FALLBACK_ALLOWED", "SGP.32"),
    "9F70": ("PROFILE_STATE", "SGP.22"),
    "9F7F": ("CPLC", "GlobalPlatform / ETSI TS 102 226"),
    "9F7B": ("E_CALL_INDICATION", "SGP.32"),
    "AC": ("CERTIFICATION_DATA_OBJECT", "GSMA"),
    "E0": ("KEY_INFORMATION_TEMPLATE", "GlobalPlatform / SGP.02"),
    "BF20": ("EUICC_INFO_1", "SGP.22"),
    "BF21": ("PREPARE_DOWNLOAD_RESPONSE", "SGP.22"),
    "BF22": ("EUICC_INFO_2", "SGP.22"),
    "BF23": ("INITIALIZE_SECURE_CHANNEL", "SGP.22"),
    "BF24": ("CONFIGURE_ISD_P", "SGP.22"),
    "BF25": ("STORE_METADATA", "SGP.22"),
    "BF26": ("REPLACE_SESSION_KEYS", "SGP.22"),
    "BF27": ("PROFILE_INSTALLATION_RESULT_DATA", "SGP.22"),
    "BF28": ("LIST_NOTIFICATION", "SGP.22"),
    "BF29": ("SET_NICKNAME", "SGP.22"),
    "BF2A": ("UPDATE_METADATA", "SGP.22"),
    "BF2B": ("PENDING_NOTIFICATIONS_LIST", "SGP.22"),
    "BF2D": ("PROFILE_INFO_LIST", "SGP.22"),
    "BF2E": ("GET_EUICC_CHALLENGE", "SGP.22"),
    "BF2F": ("NOTIFICATION_METADATA", "SGP.22"),
    "BF30": ("NOTIFICATION_SENT", "SGP.22"),
    "BF31": ("ENABLE_PROFILE", "SGP.22"),
    "BF32": ("DISABLE_PROFILE", "SGP.22"),
    "BF33": ("DELETE_PROFILE", "SGP.22"),
    "BF34": ("EUICC_MEMORY_RESET", "SGP.22"),
    "BF35": ("LOAD_CRL", "SGP.22"),
    "BF36": ("BOUND_PROFILE_PACKAGE", "SGP.22"),
    "BF37": ("PROFILE_INSTALLATION", "SGP.22"),
    "BF38": ("AUTHENTICATE_SERVER", "SGP.22"),
    "BF39": ("INITIATE_AUTHENTICATION", "SGP.22"),
    "BF3A": ("GET_BOUND_PROFILE_PACKAGE", "SGP.22"),
    "BF3B": ("AUTHENTICATE_CLIENT", "SGP.22"),
    "BF3C": ("EUICC_CONFIGURED_ADDRESSES", "SGP.22"),
    "BF3D": ("HANDLE_NOTIFICATION", "SGP.22"),
    "BF3E": ("GET_EUICC_DATA", "SGP.22"),
    "BF3F": ("SET_DEFAULT_DP_ADDRESS", "SGP.22"),
    "BF40": ("AUTHENTICATE_CLIENT_ES11", "SGP.22"),
    "BF41": ("CANCEL_SESSION", "SGP.22 / SGP.32"),
    "BF42": ("LPA_E_ACTIVATION", "SGP.22"),
    "BF43": ("GET_RAT", "SGP.22"),
    "BF44": ("LOAD_RPM_PACKAGE", "SGP.22"),
    "BF45": ("VERIFY_SMDS_RESPONSE", "SGP.22"),
    "BF46": ("CHECK_EVENT", "SGP.22"),
    "BF4A": ("ALERT_DATA", "SGP.22"),
    "BF4B": ("VERIFY_DEVICE_CHANGE", "SGP.22"),
    "BF4C": ("CONFIRM_DEVICE_CHANGE", "SGP.22"),
    "BF4D": ("PREPARE_DEVICE_CHANGE", "SGP.22"),
    "BF4E": ("TRANSFER_EIM_PACKAGE", "SGP.32"),
    "BF4F": ("GET_EIM_PACKAGE", "SGP.32"),
    "BF50": ("PROVIDE_EIM_PACKAGE_RESULT", "SGP.32"),
    "BF51": ("EIM_PACKAGE", "SGP.32 §6.3.2.6/§6.3.2.7"),
    "BF52": ("PACKAGE_DATA", "SGP.32"),
    "BF53": ("EIM_ACKNOWLEDGEMENTS", "SGP.32"),
    "BF54": ("PROFILE_DOWNLOAD_TRIGGER", "SGP.32"),
    "BF55": ("GET_EIM_CONFIGURATION_DATA", "SGP.32"),
    "BF56": ("GET_CERTS", "SGP.32"),
    "BF57": ("ADD_INITIAL_EIM", "SGP.32"),
    "BF58": ("PROFILE_ROLLBACK_OR_ADD_EIM", "SGP.32"),
    "BF59": ("CONFIGURE_IMMEDIATE_PROFILE_ENABLING", "SGP.32"),
    "BF5A": ("IMMEDIATE_ENABLE", "SGP.32"),
    "BF5B": ("ENABLE_EMERGENCY_PROFILE", "SGP.32"),
    "BF5C": ("DISABLE_EMERGENCY_PROFILE", "SGP.32"),
    "BF5D": ("EXECUTE_FALLBACK_MECHANISM", "SGP.32"),
    "BF5E": ("RETURN_FROM_FALLBACK", "SGP.32"),
    "BF5F": ("GET_CONNECTIVITY_PARAMETERS_OR_MEMORY_RESET", "SGP.32"),
    "BF60": ("VERIFY_SMDP_RESPONSE", "SGP.22 / reserved in SGP.32"),
    "BF61": ("CHECK_PROGRESS", "SGP.22 / reserved in SGP.32"),
    "BF62": ("VERIFY_PROFILE_RECOVERY", "SGP.22 / reserved in SGP.32"),
    "BF63": ("DELETE_NOTIFICATION_FOR_DC", "SGP.22 / reserved in SGP.32"),
    "BF64": ("EUICC_MEMORY_RESET", "SGP.32"),
    "BF65": ("SET_DEFAULT_DP_ADDRESS", "SGP.32"),
}

_FALLBACK_ALIASES: dict[str, tuple[str, ...]] = {
    "BF51": ("EUICC_PACKAGE",),
}


@dataclass(frozen=True)
class ApduCommandInfo:
    name: str
    source: str
    aliases: tuple[str, ...] = ()


_APDU_COMMANDS: dict[tuple[int | None, int], ApduCommandInfo] = {
    (None, 0xA4): ApduCommandInfo("SELECT", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0xB0): ApduCommandInfo("READ_BINARY", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0xD6): ApduCommandInfo("UPDATE_BINARY", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0xB2): ApduCommandInfo("READ_RECORD", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0xDC): ApduCommandInfo("UPDATE_RECORD", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x20): ApduCommandInfo("VERIFY", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x24): ApduCommandInfo("CHANGE_REFERENCE_DATA", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x26): ApduCommandInfo("DISABLE_VERIFICATION_REQUIREMENT", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x28): ApduCommandInfo("ENABLE_VERIFICATION_REQUIREMENT", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x2C): ApduCommandInfo("RESET_RETRY_COUNTER", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0x84): ApduCommandInfo("GET_CHALLENGE", "ISO 7816-4 / GlobalPlatform"),
    (None, 0x88): ApduCommandInfo("INTERNAL_AUTHENTICATE", "ISO 7816-4 / 3GPP TS 31.102"),
    (None, 0xC0): ApduCommandInfo("GET_RESPONSE", "ISO 7816-4 / ETSI TS 102 221"),
    (None, 0xCA): ApduCommandInfo("GET_DATA", "ISO 7816-4 / GlobalPlatform"),
    (None, 0xCB): ApduCommandInfo("GET_DATA_ODD", "ISO 7816-4"),
    (None, 0xDA): ApduCommandInfo("PUT_DATA", "ISO 7816-4 / GlobalPlatform"),
    (0x00, 0x70): ApduCommandInfo("MANAGE_CHANNEL", "ISO 7816-4 / GlobalPlatform"),
    (0x01, 0x70): ApduCommandInfo("MANAGE_CHANNEL", "ISO 7816-4 / GlobalPlatform"),
    (0x00, 0xE0): ApduCommandInfo("CREATE_FILE", "ETSI TS 102 222"),
    (0x00, 0xE4): ApduCommandInfo("DELETE_FILE", "ETSI TS 102 222"),
    (0x80, 0x10): ApduCommandInfo("TERMINAL_PROFILE", "ETSI TS 102 223"),
    (0x80, 0x12): ApduCommandInfo("FETCH", "ETSI TS 102 223"),
    (0x80, 0x14): ApduCommandInfo("TERMINAL_RESPONSE", "ETSI TS 102 223"),
    (0x80, 0x50): ApduCommandInfo("INITIALIZE_UPDATE", "GlobalPlatform Card Spec / SCP02 / SCP03"),
    (0x80, 0x82): ApduCommandInfo("EXTERNAL_AUTHENTICATE", "GlobalPlatform Card Spec / SCP02 / SCP03"),
    (0x84, 0x82): ApduCommandInfo("EXTERNAL_AUTHENTICATE", "GlobalPlatform Card Spec / SCP02 / SCP03"),
    (0x80, 0xAA): ApduCommandInfo("TERMINAL_CAPABILITY", "ETSI TS 102 221 / ETSI TS 102 223"),
    (0x80, 0xC2): ApduCommandInfo("ENVELOPE", "ETSI TS 102 223"),
    (0x80, 0xD8): ApduCommandInfo("PUT_KEY", "GlobalPlatform Card Spec"),
    (0x84, 0xD8): ApduCommandInfo("PUT_KEY", "GlobalPlatform Card Spec"),
    (0x80, 0xE2): ApduCommandInfo("STORE_DATA", "GlobalPlatform Card Spec / GSMA SGP.02 / SGP.22 / SGP.32"),
    (0x84, 0xE2): ApduCommandInfo("STORE_DATA", "GlobalPlatform Card Spec / GSMA SGP.02 / SGP.22 / SGP.32"),
    (0x80, 0xE4): ApduCommandInfo("DELETE", "GlobalPlatform Card Spec"),
    (0x84, 0xE4): ApduCommandInfo("DELETE", "GlobalPlatform Card Spec"),
    (0x80, 0xE6): ApduCommandInfo("INSTALL", "GlobalPlatform Card Spec"),
    (0x84, 0xE6): ApduCommandInfo("INSTALL", "GlobalPlatform Card Spec"),
    (0x80, 0xE8): ApduCommandInfo("LOAD", "GlobalPlatform Card Spec"),
    (0x84, 0xE8): ApduCommandInfo("LOAD", "GlobalPlatform Card Spec"),
    (0x80, 0xF0): ApduCommandInfo("SET_STATUS", "GlobalPlatform Card Spec"),
    (0x84, 0xF0): ApduCommandInfo("SET_STATUS", "GlobalPlatform Card Spec"),
    (0x80, 0xF2): ApduCommandInfo("GET_STATUS", "GlobalPlatform Card Spec"),
    (0x84, 0xF2): ApduCommandInfo("GET_STATUS", "GlobalPlatform Card Spec"),
}


class DecodeError(ValueError):
    """Raised when BER/DER input cannot be parsed."""


@dataclass(frozen=True)
class TagInfo:
    tag: str
    name: str
    aliases: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class ParsedTag:
    tag_hex: str
    tag_class: str
    tag_number: int
    constructed: bool
    next_offset: int


@dataclass(frozen=True)
class ParsedLength:
    length: int | None
    indefinite: bool
    next_offset: int
    encoded_hex: str


def run_cli(argv: list[str] | None = None, *, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    """Parse CLI arguments and write the requested decode output."""

    out_stream = stdout if stdout is not None else sys.stdout
    err_stream = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    args = parser.parse_args(argv)
    if _missing_input_from_tty(args):
        parser.print_usage(err_stream)
        err_stream.write(
            "asn1-tlv-decode: error: hex input is required; pass hex bytes as an argument, "
            "with --file, or pipe stdin\n"
        )
        return 2
    try:
        raw_input = _read_input(args)
        data = normalise_hex(raw_input)
        tag_registry = TagRegistry.load()
        result = decode_bytes(
            data,
            registry=tag_registry,
            schema_paths=_schema_paths(args.schema),
            type_name=args.type,
            codec=args.codec,
        )
        output_format = str(args.format)
        if _interactive_stdout(out_stream):
            out_stream.write("\n")
        if output_format == "json":
            out_stream.write(json.dumps(result, indent=2, sort_keys=False) + "\n")
        elif output_format == "asn1":
            out_stream.write(str(result["asn1Notation"]) + "\n")
        else:
            out_stream.write(json.dumps(result, indent=2, sort_keys=False) + "\n")
            out_stream.write("\nASN.1 value notation\n")
            out_stream.write(str(result["asn1Notation"]) + "\n")
    except (DecodeError, OSError, ValueError) as error:
        err_stream.write(f"asn1-tlv-decode: {error}\n")
        return 2
    return 0


def decode_bytes(
    data: bytes,
    *,
    registry: "TagRegistry | None" = None,
    schema_paths: list[Path] | None = None,
    type_name: str | None = None,
    codec: str = "der",
) -> dict[str, Any]:
    """Decode BER/DER bytes into a JSON-safe dict plus ASN.1 value notation."""

    tag_registry = registry if registry is not None else TagRegistry.load()
    try:
        items, next_offset = _parse_ber_stream(data, 0, tag_registry, depth=0, allow_eoc=False)
        if next_offset != len(data):
            raise DecodeError(f"parser stopped at offset {next_offset}, input has {len(data)} bytes")
    except DecodeError as tlv_error:
        try:
            return decode_apdu(data, registry=tag_registry)
        except DecodeError as apdu_error:
            if len(data) >= 4:
                raise DecodeError(f"input is neither BER/DER TLV nor a valid APDU: {tlv_error}; {apdu_error}") from apdu_error
            raise tlv_error
    asn1_notation = render_asn1_notation(items)
    schema_result = None
    if schema_paths and type_name:
        schema_result = _decode_with_asn1tools(schema_paths, type_name=type_name, data=data, codec=codec)
    return {
        "format": "BER/DER TLV",
        "inputHex": data.hex().upper(),
        "byteCount": len(data),
        "complete": True,
        "items": items,
        "asn1Notation": asn1_notation,
        "schemaDecode": schema_result,
        "tagRegistry": {
            "entryCount": tag_registry.entry_count,
            "sources": tag_registry.sources,
        },
    }


def decode_apdu(data: bytes, *, registry: "TagRegistry | None" = None) -> dict[str, Any]:
    """Decode an ISO 7816 command APDU and any BER-TLV data field."""

    if len(data) < 4:
        raise DecodeError("APDU input must be at least 4 bytes")
    tag_registry = registry if registry is not None else TagRegistry.load()
    body = _parse_apdu_body(data)
    cla = data[0]
    ins = data[1]
    p1 = data[2]
    p2 = data[3]
    command_info = _lookup_apdu_command(cla, ins)
    apdu: dict[str, Any] = {
        "cla": f"{cla:02X}",
        "ins": f"{ins:02X}",
        "p1": f"{p1:02X}",
        "p2": f"{p2:02X}",
        "commandName": command_info.name,
        "aliases": list(command_info.aliases),
        "source": command_info.source,
        "case": body["case"],
        "extendedLength": body["extendedLength"],
        "secureMessaging": _cla_uses_secure_messaging(cla),
        "logicalChannel": cla & 0x03,
    }
    if body["lc"] is not None:
        apdu["lc"] = body["lc"]
    if body["le"] is not None:
        apdu["le"] = body["le"]
        apdu["leRaw"] = body["leRaw"]
    data_field = body["data"]
    if len(data_field) > 0:
        apdu["dataHex"] = data_field.hex().upper()
        data_items = _try_decode_tlv_items(data_field, tag_registry)
        if data_items is not None:
            apdu["dataTlv"] = data_items
    referenced_tag = _referenced_apdu_tag(ins, p1, p2, tag_registry, data_field=data_field)
    if referenced_tag is not None:
        apdu["referencedTag"] = referenced_tag
    profile_context = _apdu_profile_context(cla, ins, p1, p2, data_field)
    if profile_context is not None:
        apdu["profileContext"] = profile_context
    store_data_context = _store_data_context(ins, p1, p2, apdu)
    if store_data_context is not None:
        apdu["storeData"] = store_data_context
    return {
        "format": "APDU",
        "inputHex": data.hex().upper(),
        "byteCount": len(data),
        "complete": True,
        "apdu": apdu,
        "asn1Notation": render_apdu_notation(apdu),
        "tagRegistry": {
            "entryCount": tag_registry.entry_count,
            "sources": tag_registry.sources,
        },
    }


class TagRegistry:
    """Lookup table assembled from converted telecom specs and fallbacks."""

    def __init__(self, entries: dict[str, TagInfo], sources: list[str]) -> None:
        self._entries = dict(entries)
        self.sources = list(dict.fromkeys(sources))

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @classmethod
    def load(cls, root: Path | None = None) -> "TagRegistry":
        spec_root = root if root is not None else _default_spec_root()
        entries: dict[str, TagInfo] = {}
        sources: list[str] = []
        for tag_hex, (name, source) in _FALLBACK_TAGS.items():
            entries[tag_hex] = TagInfo(
                tag=tag_hex,
                name=name,
                aliases=_FALLBACK_ALIASES.get(tag_hex, ()),
                source=source,
            )
        sources.append("built-in fallback")
        if spec_root.is_dir():
            for source_name, loaded in _load_spec_tag_entries(spec_root).items():
                sources.append(source_name)
                for info in loaded:
                    existing = entries.get(info.tag)
                    if existing is None:
                        entries[info.tag] = info
                        continue
                    aliases = _merge_aliases(existing.aliases, (existing.name, info.name, *info.aliases))
                    entries[info.tag] = TagInfo(
                        tag=info.tag,
                        name=existing.name,
                        aliases=aliases,
                        source=_join_source(existing.source, info.source),
                    )
        return cls(entries, sources)

    def lookup(self, tag_hex: str, tag_class: str, tag_number: int) -> TagInfo:
        normalized = tag_hex.upper()
        info = self._entries.get(normalized)
        if info is not None:
            return info
        if tag_class == "universal":
            name = _UNIVERSAL_TAG_NAMES.get(tag_number, f"UNIVERSAL_{tag_number}")
            return TagInfo(tag=normalized, name=_identifier_name(name), source="ASN.1 universal")
        if tag_class == "context":
            return TagInfo(tag=normalized, name=f"CONTEXT_{tag_number}", source="BER tag class")
        if tag_class == "application":
            return TagInfo(tag=normalized, name=f"APPLICATION_{tag_number}", source="BER tag class")
        return TagInfo(tag=normalized, name=f"PRIVATE_{tag_number}", source="BER tag class")

    def lookup_exact(self, tag_hex: str) -> TagInfo | None:
        return self._entries.get(tag_hex.upper())


def normalise_hex(raw_text: str) -> bytes:
    """Return bytes from a pasted hex string."""

    text = str(raw_text or "").strip()
    if len(text) == 0:
        raise DecodeError("hex input is empty")
    compact = re.sub(r"(?i)0x", "", text)
    compact = re.sub(r"[\s:,_'\"`.-]+", "", compact)
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) is None:
        raise DecodeError("input must contain only hex bytes and common separators")
    if len(compact) % 2 != 0:
        raise DecodeError("hex input has an odd number of digits")
    try:
        return bytes.fromhex(compact)
    except ValueError as error:
        raise DecodeError(f"invalid hex input: {error}") from error


def render_asn1_notation(items: list[dict[str, Any]]) -> str:
    """Render decoded TLV nodes as readable ASN.1-like value notation."""

    lines: list[str] = []
    for index, item in enumerate(items):
        if index > 0:
            lines.append("")
        if _is_sgp32_eim_package(item):
            lines.extend(_render_sgp32_eim_package(item, indent=0))
        else:
            lines.extend(_render_item_notation(item, indent=0, assignment=True))
    return "\n".join(lines)


def _is_sgp32_eim_package(item: dict[str, Any]) -> bool:
    return item.get("tag") == "BF51" and item.get("name") == "EIM_PACKAGE"


def _render_sgp32_eim_package(item: dict[str, Any], *, indent: int) -> list[str]:
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}EIM_PACKAGE [BF51] ::= {{}}"]
    lines = [f"{prefix}EIM_PACKAGE [BF51] ::= EuiccPackageRequest {{"]
    for index, child in enumerate(children):
        if child.get("tag") == "30":
            child_lines = _render_euicc_package_signed(child, indent=indent + 2)
        elif child.get("tag") == "5F37":
            child_lines = [_summary_line(child, indent + 2, "eimSignature", _signature_summary(_item_raw_bytes(child)))]
        else:
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


def _render_euicc_package_signed(item: dict[str, Any], *, indent: int) -> list[str]:
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}euiccPackageSigned [30] {{}}"]
    lines = [f"{prefix}euiccPackageSigned [30] {{"]
    for index, child in enumerate(children):
        tag = str(child.get("tag", ""))
        if tag == "80":
            child_lines = [_value_line(child, indent + 2, "eimId", _text_or_hex_value(child))]
        elif tag == "5A":
            child_lines = [_value_line(child, indent + 2, "eidValue", _hex_value(child))]
        elif tag == "81":
            child_lines = [_value_line(child, indent + 2, "counterValue", _integer_value(child))]
        elif tag == "82":
            child_lines = [_value_line(child, indent + 2, "eimTransactionId", _hex_value(child))]
        elif tag in {"A0", "A1", "30"}:
            child_lines = _render_euicc_package_choice(child, indent=indent + 2)
        else:
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


def _render_euicc_package_choice(item: dict[str, Any], *, indent: int) -> list[str]:
    tag = str(item.get("tag", ""))
    if tag == "A1":
        label = "ecoList"
        mode = "eco"
    elif tag == "A0":
        label = "psmoList"
        mode = "psmo"
    else:
        label = "euiccPackage"
        mode = "generic"
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}{label} [{tag}] {{}}"]
    lines = [f"{prefix}{label} [{tag}] {{"]
    for index, child in enumerate(children):
        if mode == "eco":
            child_lines = _render_eco_choice(child, indent=indent + 2)
        elif mode == "psmo":
            child_lines = _render_psmo_choice(child, indent=indent + 2)
        else:
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


def _render_eco_choice(item: dict[str, Any], *, indent: int) -> list[str]:
    tag = str(item.get("tag", ""))
    labels = {
        "A8": "addEim",
        "A9": "deleteEim",
        "AA": "updateEim",
        "AB": "listEim",
    }
    label = labels.get(tag)
    if label is None:
        return _render_item_notation(item, indent=indent, assignment=False)
    if tag in {"A8", "AA"}:
        return _render_eim_configuration_data(item, indent=indent, label=label)
    return _render_named_constructed(item, indent=indent, label=label)


def _render_psmo_choice(item: dict[str, Any], *, indent: int) -> list[str]:
    tag = str(item.get("tag", ""))
    labels = {
        "A3": "enable",
        "A4": "disable",
        "A5": "delete",
        "BF2D": "listProfileInfo",
        "A6": "getRAT",
        "A7": "configureImmediateEnable",
        "A8": "setFallbackAttribute",
        "A9": "unsetFallbackAttribute",
        "BF65": "setDefaultDpAddress",
    }
    label = labels.get(tag)
    if label is None:
        return _render_item_notation(item, indent=indent, assignment=False)
    return _render_named_constructed(item, indent=indent, label=label)


def _render_eim_configuration_data(item: dict[str, Any], *, indent: int, label: str) -> list[str]:
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}{label} [{item['tag']}] EimConfigurationData {{}}"]
    lines = [f"{prefix}{label} [{item['tag']}] EimConfigurationData {{"]
    for index, child in enumerate(children):
        tag = str(child.get("tag", ""))
        if tag == "80":
            child_lines = [_value_line(child, indent + 2, "eimId", _text_or_hex_value(child))]
        elif tag == "81":
            child_lines = [_value_line(child, indent + 2, "eimFqdn", _text_or_hex_value(child))]
        elif tag == "82":
            child_lines = [_value_line(child, indent + 2, "eimIdType", _named_integer_value(child, _EIM_ID_TYPE_NAMES))]
        elif tag == "83":
            child_lines = [_value_line(child, indent + 2, "counterValue", _integer_value(child))]
        elif tag == "84":
            child_lines = [_value_line(child, indent + 2, "associationToken", _integer_value(child))]
        elif tag == "A5":
            child_lines = _render_public_key_data(child, indent=indent + 2, label="eimPublicKeyData")
        elif tag == "A6":
            child_lines = _render_public_key_data(child, indent=indent + 2, label="trustedPublicKeyDataTls")
        elif tag == "87":
            child_lines = [_value_line(child, indent + 2, "eimSupportedProtocol", _eim_supported_protocol_value(child))]
        elif tag == "88":
            child_lines = [_value_line(child, indent + 2, "euiccCiPKId", _hex_value(child))]
        elif tag == "89":
            child_lines = [_value_line(child, indent + 2, "indirectProfileDownload", "NULL")]
        else:
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


def _render_public_key_data(item: dict[str, Any], *, indent: int, label: str) -> list[str]:
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}{label} [{item['tag']}] {{}}"]
    lines = [f"{prefix}{label} [{item['tag']}] {{"]
    for index, child in enumerate(children):
        tag = str(child.get("tag", ""))
        raw = _item_raw_bytes(child)
        if tag == "A0":
            child_lines = [_summary_line(child, indent + 2, "eimPublicKey", _binary_summary(raw, "SubjectPublicKeyInfo"))]
        elif tag == "A1":
            child_lines = [_summary_line(child, indent + 2, "eimCertificate", _certificate_summary(raw))]
        else:
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


def _render_named_constructed(item: dict[str, Any], *, indent: int, label: str) -> list[str]:
    prefix = " " * indent
    children = _child_items(item)
    if not children:
        return [f"{prefix}{label} [{item['tag']}] {{}}"]
    lines = [f"{prefix}{label} [{item['tag']}] {{"]
    for index, child in enumerate(children):
        child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
        if index < len(children) - 1:
            child_lines[-1] += ","
        lines.extend(child_lines)
    lines.append(f"{prefix}}}")
    return lines


_EIM_ID_TYPE_NAMES = {
    1: "eimIdTypeOid",
    2: "eimIdTypeFqdn",
    3: "eimIdTypeProprietary",
}


_EIM_SUPPORTED_PROTOCOL_BITS = {
    0: "eimRetrieveHttps",
    1: "eimRetrieveCoaps",
    2: "eimInjectHttps",
    3: "eimInjectCoaps",
    4: "eimProprietary",
}


def _child_items(item: dict[str, Any]) -> list[dict[str, Any]]:
    children = item.get("items")
    return children if isinstance(children, list) else []


def _item_raw_bytes(item: dict[str, Any]) -> bytes:
    raw = str(item.get("raw", ""))
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return b""


def _value_line(item: dict[str, Any], indent: int, label: str, value: str) -> str:
    prefix = " " * indent
    return f"{prefix}{label} [{item['tag']}] = {value}"


def _summary_line(item: dict[str, Any], indent: int, label: str, summary: str) -> str:
    prefix = " " * indent
    return f"{prefix}{label} [{item['tag']}] = {summary}"


def _text_or_hex_value(item: dict[str, Any]) -> str:
    raw = _item_raw_bytes(item)
    text = _decode_utf8_or_ascii(raw)
    if text is not None:
        return json.dumps(text)
    return _quoted_hex(raw)


def _hex_value(item: dict[str, Any]) -> str:
    return _quoted_hex(_item_raw_bytes(item))


def _integer_value(item: dict[str, Any]) -> str:
    raw = _item_raw_bytes(item)
    return str(int.from_bytes(raw, "big", signed=False)) if raw else "0"


def _named_integer_value(item: dict[str, Any], names: dict[int, str]) -> str:
    value = int(_integer_value(item))
    name = names.get(value)
    return f"{name}({value})" if name is not None else str(value)


def _eim_supported_protocol_value(item: dict[str, Any]) -> str:
    raw = _item_raw_bytes(item)
    if not raw:
        return "{}"
    unused_bits = raw[0]
    bits = raw[1:]
    enabled: list[str] = []
    bit_count = max((len(bits) * 8) - unused_bits, 0)
    for bit_index in range(bit_count):
        byte_value = bits[bit_index // 8]
        mask = 0x80 >> (bit_index % 8)
        if byte_value & mask:
            enabled.append(_EIM_SUPPORTED_PROTOCOL_BITS.get(bit_index, f"bit{bit_index}"))
    return "{ " + ", ".join(enabled) + " }" if enabled else "{}"


def _signature_summary(raw: bytes) -> str:
    return _binary_summary(raw, "Signature")


def _certificate_summary(raw: bytes) -> str:
    sha = hashlib.sha256(raw).hexdigest().upper()[:16] if raw else ""
    try:
        from cryptography import x509
    except ImportError:
        return _binary_summary(raw, "Certificate")
    try:
        cert = x509.load_der_x509_certificate(raw)
    except ValueError:
        return _binary_summary(raw, "Certificate")
    return (
        "Certificate("
        f"len={len(raw)}, "
        f"serial={cert.serial_number}, "
        f"subject={json.dumps(cert.subject.rfc4514_string())}, "
        f"issuer={json.dumps(cert.issuer.rfc4514_string())}, "
        f"sha256={sha}"
        ")"
    )


def _binary_summary(raw: bytes, label: str) -> str:
    if not raw:
        return f"{label}(len=0)"
    sha = hashlib.sha256(raw).hexdigest().upper()[:16]
    return f"{label}(len={len(raw)}, sha256={sha})"


def _quoted_hex(raw: bytes) -> str:
    return f"'{raw.hex().upper()}'H"


def render_apdu_notation(apdu: dict[str, Any]) -> str:
    """Render a decoded APDU as concise notation."""

    header = (
        f"APDU {apdu['commandName']} [{apdu['cla']} {apdu['ins']}] "
        f"P1={apdu['p1']} P2={apdu['p2']} case={apdu['case']}"
    )
    lines = [header]
    if "lc" in apdu:
        lines.append(f"  Lc={apdu['lc']}")
    if "le" in apdu:
        lines.append(f"  Le={apdu['le']} raw={apdu['leRaw']}")
    if "profileContext" in apdu:
        lines.append(f"  profileContext={apdu['profileContext']}")
    referenced_tag = apdu.get("referencedTag")
    if isinstance(referenced_tag, dict):
        lines.append(f"  references {referenced_tag['name']} [{referenced_tag['tag']}]")
    store_data = apdu.get("storeData")
    if isinstance(store_data, dict):
        lines.append(f"  profileContext={store_data['profileContext']}")
    data_items = apdu.get("dataTlv")
    if isinstance(data_items, list):
        lines.append("  data:")
        for item in data_items:
            lines.extend(_render_item_notation(item, indent=4, assignment=True))
    elif "dataHex" in apdu:
        lines.append(f"  data='{apdu['dataHex']}'H")
    return "\n".join(lines)


def _parse_apdu_body(data: bytes) -> dict[str, Any]:
    if len(data) == 4:
        return {
            "case": "1",
            "extendedLength": False,
            "lc": None,
            "le": None,
            "leRaw": "",
            "data": b"",
        }
    if len(data) == 5:
        return {
            "case": "2S",
            "extendedLength": False,
            "lc": None,
            "le": _short_le_value(data[4]),
            "leRaw": f"{data[4]:02X}",
            "data": b"",
        }
    first_length = data[4]
    if first_length != 0:
        lc = first_length
        data_start = 5
        data_end = data_start + lc
        if data_end > len(data):
            raise DecodeError("short APDU Lc exceeds supplied input")
        data_field = data[data_start:data_end]
        trailing = len(data) - data_end
        if trailing == 0:
            return {
                "case": "3S",
                "extendedLength": False,
                "lc": lc,
                "le": None,
                "leRaw": "",
                "data": data_field,
            }
        if trailing == 1:
            le_raw = data[data_end]
            return {
                "case": "4S",
                "extendedLength": False,
                "lc": lc,
                "le": _short_le_value(le_raw),
                "leRaw": f"{le_raw:02X}",
                "data": data_field,
            }
        raise DecodeError("short APDU has extra bytes after data and Le")
    if len(data) == 7:
        raw_le = data[5:7]
        return {
            "case": "2E",
            "extendedLength": True,
            "lc": None,
            "le": _extended_le_value(raw_le),
            "leRaw": raw_le.hex().upper(),
            "data": b"",
        }
    if len(data) < 7:
        raise DecodeError("extended APDU is missing two-byte Lc or Le")
    lc = int.from_bytes(data[5:7], "big")
    if lc == 0:
        raise DecodeError("extended APDU Lc is zero outside case 2E")
    data_start = 7
    data_end = data_start + lc
    if data_end > len(data):
        raise DecodeError("extended APDU Lc exceeds supplied input")
    data_field = data[data_start:data_end]
    trailing = len(data) - data_end
    if trailing == 0:
        return {
            "case": "3E",
            "extendedLength": True,
            "lc": lc,
            "le": None,
            "leRaw": "",
            "data": data_field,
        }
    if trailing == 2:
        raw_le = data[data_end : data_end + 2]
        return {
            "case": "4E",
            "extendedLength": True,
            "lc": lc,
            "le": _extended_le_value(raw_le),
            "leRaw": raw_le.hex().upper(),
            "data": data_field,
        }
    raise DecodeError("extended APDU has extra bytes after data and Le")


def _short_le_value(value: int) -> int:
    return 256 if value == 0 else value


def _extended_le_value(value: bytes) -> int:
    raw = int.from_bytes(value, "big")
    return 65536 if raw == 0 else raw


def _lookup_apdu_command(cla: int, ins: int) -> ApduCommandInfo:
    exact = _APDU_COMMANDS.get((cla, ins))
    if exact is not None:
        return exact
    normalized_cla = cla & 0xFC
    normalized = _APDU_COMMANDS.get((normalized_cla, ins))
    if normalized is not None:
        return normalized
    generic = _APDU_COMMANDS.get((None, ins))
    if generic is not None:
        return generic
    return ApduCommandInfo(name=f"INS_{ins:02X}", source="unknown APDU instruction")


def _cla_uses_secure_messaging(cla: int) -> bool:
    return (cla & 0x04) != 0 or (cla & 0x0C) == 0x0C


def _try_decode_tlv_items(data: bytes, registry: TagRegistry) -> list[dict[str, Any]] | None:
    try:
        items, offset = _parse_ber_stream(data, 0, registry, depth=0, allow_eoc=False)
    except DecodeError:
        return None
    if offset != len(data):
        return None
    return items


def _referenced_apdu_tag(
    ins: int,
    p1: int,
    p2: int,
    registry: TagRegistry,
    *,
    data_field: bytes,
) -> dict[str, Any] | None:
    if ins not in {0xCA, 0xCB, 0xDA}:
        return None
    if p1 == 0xBF and p2 == 0x30:
        return _sgp02_ecasd_bf30_reference(data_field)
    candidates = [f"{p1:02X}{p2:02X}"]
    if p1 == 0x00 and p2 != 0x00:
        candidates.append(f"{p2:02X}")
    for tag_hex in candidates:
        exact = registry.lookup_exact(tag_hex)
        if exact is not None:
            return {
                "tag": exact.tag,
                "name": exact.name,
                "aliases": list(exact.aliases),
                "source": exact.source,
            }
        tag_bytes = bytes.fromhex(tag_hex)
        try:
            parsed = _read_tag(tag_bytes, 0)
        except DecodeError:
            continue
        if parsed.next_offset != len(tag_bytes):
            continue
        info = registry.lookup(parsed.tag_hex, parsed.tag_class, parsed.tag_number)
        return {
            "tag": parsed.tag_hex,
            "name": info.name,
            "aliases": list(info.aliases),
            "source": info.source,
        }
    return None


def _sgp02_ecasd_bf30_reference(data_field: bytes) -> dict[str, Any]:
    if data_field == bytes.fromhex("5C0166"):
        name = "ECASD_RECOGNITION_DATA"
    elif data_field == bytes.fromhex("5C027F21"):
        name = "ECASD_CERTIFICATE_STORE"
    else:
        name = "ECASD_DATA"
    return {
        "tag": "BF30",
        "name": name,
        "aliases": ["NOTIFICATION_SENT"],
        "source": "SGP.02 ECASD GET DATA context; BF30 is NotificationSent in SGP.22 STORE DATA context",
    }


def _apdu_profile_context(cla: int, ins: int, p1: int, p2: int, data_field: bytes) -> str | None:
    del cla
    if ins in {0xCA, 0xCB} and p1 == 0xBF and p2 == 0x30:
        if data_field == bytes.fromhex("5C0166"):
            return "SGP.02 eCASD recognition data probe"
        if data_field == bytes.fromhex("5C027F21"):
            return "SGP.02 eCASD certificate-store probe"
        return "SGP.02 eCASD data probe"
    if ins == 0xF2 and p1 == 0x40:
        return "SGP.02 / GlobalPlatform application registry list"
    return None


def _store_data_context(ins: int, p1: int, p2: int, apdu: dict[str, Any]) -> dict[str, Any] | None:
    if ins != 0xE2:
        return None
    root_tags = []
    data_items = apdu.get("dataTlv")
    if isinstance(data_items, list):
        for item in data_items:
            root_tags.append(
                {
                    "tag": item.get("tag"),
                    "name": item.get("name"),
                    "source": item.get("source"),
                }
            )
    if p1 == 0x91 and p2 == 0x00:
        context = "SGP.02/SGP.22/SGP.32 profile-management STORE DATA"
    elif p1 & 0x80:
        context = "GlobalPlatform STORE DATA block"
    else:
        context = "STORE DATA"
    return {
        "profileContext": context,
        "rootTags": root_tags,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asn1-tlv-decode",
        description="Decode BER/DER ASN.1/TLV or command APDU hex into JSON and readable notation.",
    )
    parser.add_argument(
        "hex_data",
        nargs="?",
        help="Hex bytes to decode. If omitted, bytes are read from stdin.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Read hex bytes from a file instead of the positional argument or stdin.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "asn1", "both"),
        default="asn1",
        help="Output JSON, ASN.1-like value notation, or both. Default: asn1.",
    )
    parser.add_argument(
        "--schema",
        action="append",
        type=Path,
        default=[],
        help="ASN.1 schema file or directory to compile with asn1tools. Can be repeated.",
    )
    parser.add_argument(
        "--type",
        default="",
        help="ASN.1 type name to decode with asn1tools when --schema is set.",
    )
    parser.add_argument(
        "--codec",
        default="der",
        help="asn1tools codec for schema decode, default: der.",
    )
    return parser


def _read_input(args: argparse.Namespace) -> str:
    if args.file is not None:
        return Path(args.file).read_text(encoding="utf-8")
    if args.hex_data is not None:
        return str(args.hex_data)
    return sys.stdin.read()


def _missing_input_from_tty(args: argparse.Namespace) -> bool:
    if args.file is not None or args.hex_data is not None:
        return False
    isatty = getattr(sys.stdin, "isatty", None)
    return bool(isatty is not None and isatty())


def _interactive_stdout(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    return bool(isatty is not None and isatty())


def _schema_paths(raw_paths: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for raw_path in raw_paths:
        path = Path(raw_path)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.asn")))
            paths.extend(sorted(path.glob("*.asn1")))
        else:
            paths.append(path)
    return paths


def _default_spec_root() -> Path:
    return Path(__file__).resolve().parents[2] / "docs" / "tel-docs" / "converted"


def _load_spec_tag_entries(root: Path) -> dict[str, list[TagInfo]]:
    loaded: dict[str, list[TagInfo]] = {}
    gsma_index = root / "_indexes" / "gsma-asn1-tags.md"
    if gsma_index.is_file():
        loaded[str(gsma_index.relative_to(root))] = _parse_gsma_index(gsma_index)
    table_candidates = [
        root / "SGP.22-v3.1" / "tables" / "table-107-page-467-Table_66_Tag_Allocation.md",
        root / "SGP.32-v1.2" / "tables" / "table-038-page-221-Table_32_Tag_Allocation.md",
    ]
    table_candidates.extend(_discover_tag_table_files(root))
    for table_path in dict.fromkeys(table_candidates):
        if table_path.is_file():
            entries = _parse_tag_table(table_path, root=root)
            if entries:
                loaded[str(table_path.relative_to(root))] = entries
    return loaded


def _discover_tag_table_files(root: Path) -> list[Path]:
    tables: list[Path] = []
    for table_path in sorted(root.glob("*/tables/*.md")):
        name = table_path.name.lower()
        if "tag" in name or "tlv" in name:
            tables.append(table_path)
    return tables


def _parse_gsma_index(path: Path) -> list[TagInfo]:
    entries: list[TagInfo] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        columns = _markdown_columns(line)
        if len(columns) < 2:
            continue
        tag = _clean_tag(columns[0])
        if tag is None:
            continue
        name = _clean_name(columns[1])
        aliases = tuple(_split_aliases(columns[2])) if len(columns) > 2 else ()
        entries.append(TagInfo(tag=tag, name=name, aliases=aliases, source="_indexes/gsma-asn1-tags.md"))
    return entries


def _parse_tag_table(path: Path, *, root: Path) -> list[TagInfo]:
    entries: list[TagInfo] = []
    source = str(path.relative_to(root))
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if len(line) == 0:
            continue
        columns = _markdown_columns(line)
        if len(columns) >= 2:
            tag = _clean_tag(columns[0])
            if tag is not None:
                name = _clean_name(_tag_table_name_column(columns))
                if name not in {"NAME", "DATA NAME", "DATA OBJECT", "LENGTH"}:
                    entries.append(TagInfo(tag=tag, name=name, source=source))
                    continue
        match = re.search(r"['‘`]([0-9A-Fa-f]{2,6})['’`]\s+(?:to\s+['‘`][0-9A-Fa-f]{2,6}['’`]\s+)?(.+)", line)
        if match is None:
            continue
        tag = _clean_tag(match.group(1))
        if tag is None:
            continue
        name = _clean_name(_trim_table_tail(match.group(2)))
        if len(name) == 0 or name.upper() in {"RESERVED", "TO"}:
            continue
        entries.append(TagInfo(tag=tag, name=name, source=source))
    return entries


def _markdown_columns(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or "---" in stripped:
        return []
    return [column.strip() for column in stripped.strip("|").split("|")]


def _tag_table_name_column(columns: list[str]) -> str:
    if len(columns) >= 3 and _looks_like_length_column(columns[1]):
        return columns[2]
    return columns[1]


def _looks_like_length_column(text: str) -> bool:
    cleaned = _clean_name(text)
    if cleaned in {"LENGTH", "PRESENCE", "M", "O", "C"}:
        return True
    return re.fullmatch(r"(?:\d+|N|0_N|1_N|2_N|0_16|1_16|5_16|2_OR_4|\d+_\d+|\d+_N)", cleaned) is not None


def _clean_tag(text: str) -> str | None:
    match = re.search(r"(?i)(?:0x)?([0-9a-f]{2,6})", text.replace(" ", ""))
    if match is None:
        return None
    tag = match.group(1).upper()
    if len(tag) % 2 != 0:
        return None
    return tag


def _clean_name(text: str) -> str:
    cleaned = re.sub(r"`|'", "", str(text or "")).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) == 0:
        return "UNKNOWN"
    return _identifier_name(cleaned)


def _identifier_name(text: str) -> str:
    name = re.sub(r"[^0-9A-Za-z]+", "_", text.strip())
    name = re.sub(r"_+", "_", name).strip("_")
    return name.upper() if name else "UNKNOWN"


def _split_aliases(text: str) -> list[str]:
    aliases: list[str] = []
    for part in re.split(r",|/|;", str(text or "")):
        cleaned = _clean_name(part)
        if cleaned not in {"", "UNKNOWN"}:
            aliases.append(cleaned)
    return aliases


def _merge_aliases(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = []
    for alias in (*left, *right):
        cleaned = _clean_name(alias)
        if cleaned not in merged and cleaned != "UNKNOWN" and not _is_noise_alias(cleaned):
            merged.append(cleaned)
    return tuple(merged)


def _is_noise_alias(text: str) -> bool:
    if text in {"LENGTH", "PRESENCE", "MANDATORY", "OPTIONAL", "CONDITIONAL"}:
        return True
    return re.fullmatch(r"(?:\d+|N|0_N|1_N|2_N|0_16|1_16|5_16|2_OR_4|\d+_\d+|\d+_N)", text) is not None


def _join_source(left: str, right: str) -> str:
    parts = [part for part in (left, right) if len(part) > 0]
    return "; ".join(dict.fromkeys(parts))


def _trim_table_tail(text: str) -> str:
    cleaned = re.sub(r"\s{2,}.+$", "", text).strip()
    cleaned = re.sub(
        r"^(?:\d+\s+or\s+\d+|\d+\s*-\s*(?:\d+|n)|\d+|n)\s+",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"\b(?:Mandatory|Optional|Conditional|SGP\.\d+|Reserved)\b.*$", "", cleaned).strip()
    return cleaned


def _parse_ber_stream(
    data: bytes,
    offset: int,
    registry: TagRegistry,
    *,
    depth: int,
    allow_eoc: bool,
) -> tuple[list[dict[str, Any]], int]:
    if depth > 32:
        raise DecodeError("ASN.1 nesting depth exceeds 32 levels")
    items: list[dict[str, Any]] = []
    while offset < len(data):
        if allow_eoc and offset + 2 <= len(data) and data[offset : offset + 2] == b"\x00\x00":
            return items, offset + 2
        start_offset = offset
        parsed_tag = _read_tag(data, offset)
        parsed_length = _read_length(data, parsed_tag.next_offset)
        header_end = parsed_length.next_offset
        info = registry.lookup(parsed_tag.tag_hex, parsed_tag.tag_class, parsed_tag.tag_number)
        item: dict[str, Any] = {
            "offset": start_offset,
            "headerLength": header_end - start_offset,
            "tag": parsed_tag.tag_hex,
            "name": info.name,
            "aliases": list(info.aliases),
            "source": info.source,
            "class": parsed_tag.tag_class,
            "tagNumber": parsed_tag.tag_number,
            "constructed": parsed_tag.constructed,
            "length": "indefinite" if parsed_length.indefinite else parsed_length.length,
            "lengthEncoding": parsed_length.encoded_hex,
        }
        if parsed_length.indefinite:
            if not parsed_tag.constructed:
                raise DecodeError(f"primitive tag {parsed_tag.tag_hex} uses indefinite length at offset {start_offset}")
            children, next_offset = _parse_ber_stream(
                data,
                header_end,
                registry,
                depth=depth + 1,
                allow_eoc=True,
            )
            item["items"] = children
            item["raw"] = data[header_end : next_offset - 2].hex().upper()
            item["totalLength"] = next_offset - start_offset
            items.append(item)
            offset = next_offset
            continue
        length = parsed_length.length
        if length is None:
            raise DecodeError(f"missing length for tag {parsed_tag.tag_hex} at offset {start_offset}")
        value_end = header_end + length
        if value_end > len(data):
            raise DecodeError(f"tag {parsed_tag.tag_hex} value overruns input at offset {start_offset}")
        value_bytes = data[header_end:value_end]
        item["raw"] = value_bytes.hex().upper()
        item["totalLength"] = value_end - start_offset
        if parsed_tag.constructed:
            if len(value_bytes) > 0:
                item["items"] = _parse_ber_stream(
                    value_bytes,
                    0,
                    registry,
                    depth=depth + 1,
                    allow_eoc=False,
                )[0]
            else:
                item["items"] = []
        else:
            decoded = _decode_primitive(item, value_bytes, registry)
            if decoded is not None:
                item["decoded"] = decoded
        items.append(item)
        offset = value_end
    return items, offset


def _read_tag(data: bytes, offset: int) -> ParsedTag:
    if offset >= len(data):
        raise DecodeError("missing tag field")
    first = data[offset]
    cursor = offset + 1
    tag_bytes = bytearray([first])
    tag_class = _TAG_CLASS_NAMES[(first >> 6) & 0x03]
    constructed = (first & 0x20) != 0
    tag_number = first & 0x1F
    if tag_number != 0x1F:
        return ParsedTag(
            tag_hex=bytes(tag_bytes).hex().upper(),
            tag_class=tag_class,
            tag_number=tag_number,
            constructed=constructed,
            next_offset=cursor,
        )
    tag_number = 0
    while cursor < len(data):
        current = data[cursor]
        cursor += 1
        tag_bytes.append(current)
        tag_number = (tag_number << 7) | (current & 0x7F)
        if (current & 0x80) == 0:
            return ParsedTag(
                tag_hex=bytes(tag_bytes).hex().upper(),
                tag_class=tag_class,
                tag_number=tag_number,
                constructed=constructed,
                next_offset=cursor,
            )
    raise DecodeError("truncated high-tag-number field")


def _read_length(data: bytes, offset: int) -> ParsedLength:
    if offset >= len(data):
        raise DecodeError("missing length field")
    first = data[offset]
    cursor = offset + 1
    if first == 0x80:
        return ParsedLength(length=None, indefinite=True, next_offset=cursor, encoded_hex="80")
    if (first & 0x80) == 0:
        return ParsedLength(length=first, indefinite=False, next_offset=cursor, encoded_hex=f"{first:02X}")
    length_octets = first & 0x7F
    if length_octets == 0:
        raise DecodeError("invalid BER length 0x80 long-form marker")
    if cursor + length_octets > len(data):
        raise DecodeError("truncated long-form length")
    length = int.from_bytes(data[cursor : cursor + length_octets], "big")
    encoded = data[offset : cursor + length_octets].hex().upper()
    return ParsedLength(
        length=length,
        indefinite=False,
        next_offset=cursor + length_octets,
        encoded_hex=encoded,
    )


def _decode_primitive(item: dict[str, Any], value: bytes, registry: TagRegistry) -> Any:
    tag_class = str(item["class"])
    tag_number = int(item["tagNumber"])
    tag_hex = str(item["tag"])
    if tag_class == "universal":
        return _decode_universal_value(tag_number, value, registry)
    if tag_hex == "5C":
        return {"tags": _decode_tag_list(value, registry)}
    if tag_hex in {"90", "91", "92"}:
        text = _decode_utf8_or_ascii(value)
        if text is not None:
            return text
    if tag_hex == "93" and len(value) == 1:
        return {"iconType": value[0], "name": {0: "JPG", 1: "PNG"}.get(value[0], "unknown")}
    if tag_hex == "95" and len(value) == 1:
        return {"profileClass": value[0], "name": {0: "operational", 1: "test", 2: "provisioning"}.get(value[0], "unknown")}
    if tag_hex == "9F70" and len(value) == 1:
        return {"profileState": value[0], "name": {0: "disabled", 1: "enabled", 2: "deleted"}.get(value[0], "unknown")}
    if tag_hex in {"5A", "9F26", "9F67", "9F7B"} and len(value) > 0:
        return {"hex": value.hex().upper(), "integer": int.from_bytes(value, "big", signed=False)}
    if tag_hex == "4F":
        return {"aid": value.hex().upper()}
    return None


def _decode_universal_value(tag_number: int, value: bytes, registry: TagRegistry) -> Any:
    if tag_number == 1:
        if len(value) != 1:
            return {"raw": value.hex().upper(), "error": "BOOLEAN length is not 1"}
        return value[0] != 0
    if tag_number in (2, 10):
        return int.from_bytes(value, "big", signed=True) if value else 0
    if tag_number == 3:
        decoded: dict[str, Any] = {
            "unusedBits": value[0] if value else 0,
            "payloadHex": value[1:].hex().upper() if value else "",
        }
        if len(value) > 1 and value[0] == 0:
            embedded = _try_decode_embedded(value[1:], registry)
            if embedded is not None:
                decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 4:
        decoded = {"hex": value.hex().upper()}
        text = _decode_utf8_or_ascii(value)
        if text is not None and len(value) >= 3:
            decoded["text"] = text
        embedded = _try_decode_embedded(value, registry)
        if embedded is not None:
            decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 5:
        return None if len(value) == 0 else {"raw": value.hex().upper(), "error": "NULL has non-empty value"}
    if tag_number == 6:
        return _decode_oid(value) or {"raw": value.hex().upper(), "error": "invalid OID"}
    if tag_number == 12:
        return _decode_utf8_or_ascii(value) or value.hex().upper()
    if tag_number in (18, 19, 20, 21, 22, 25, 26, 27):
        return _decode_ascii(value) or value.hex().upper()
    if tag_number == 23:
        return _decode_time(value, "%y%m%d%H%M%SZ")
    if tag_number == 24:
        return _decode_generalized_time(value)
    if tag_number == 28:
        try:
            return value.decode("utf-32-be")
        except UnicodeDecodeError:
            return value.hex().upper()
    if tag_number == 30:
        try:
            return value.decode("utf-16-be")
        except UnicodeDecodeError:
            return value.hex().upper()
    return {"hex": value.hex().upper()}


def _decode_oid(value: bytes) -> str | None:
    if len(value) == 0:
        return None
    first = value[0]
    first_arc = min(first // 40, 2)
    second_arc = first - (first_arc * 40)
    arcs = [str(first_arc), str(second_arc)]
    accumulator = 0
    pending = False
    for byte_value in value[1:]:
        pending = True
        accumulator = (accumulator << 7) | (byte_value & 0x7F)
        if byte_value & 0x80:
            continue
        arcs.append(str(accumulator))
        accumulator = 0
        pending = False
    if pending:
        return None
    return ".".join(arcs)


def _decode_utf8_or_ascii(value: bytes) -> str | None:
    for encoding in ("utf-8", "ascii"):
        try:
            text = value.decode(encoding)
        except UnicodeDecodeError:
            continue
        if all((character.isprintable() or character in "\r\n\t") for character in text):
            return text
    return None


def _decode_ascii(value: bytes) -> str | None:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if all((character.isprintable() or character in "\r\n\t") for character in text):
        return text
    return None


def _decode_time(value: bytes, fmt: str) -> str:
    text = _decode_ascii(value)
    if text is None:
        return value.hex().upper()
    try:
        return datetime.strptime(text, fmt).isoformat() + "Z"
    except ValueError:
        return text


def _decode_generalized_time(value: bytes) -> str:
    text = _decode_ascii(value)
    if text is None:
        return value.hex().upper()
    for fmt in ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S.%fZ"):
        try:
            return datetime.strptime(text, fmt).isoformat() + "Z"
        except ValueError:
            continue
    return text


def _try_decode_embedded(value: bytes, registry: TagRegistry) -> list[dict[str, Any]] | None:
    if len(value) < 2:
        return None
    try:
        items, offset = _parse_ber_stream(value, 0, registry, depth=0, allow_eoc=False)
    except DecodeError:
        return None
    if offset != len(value) or len(items) == 0:
        return None
    return items


def _decode_tag_list(value: bytes, registry: TagRegistry) -> list[dict[str, Any]]:
    tags: list[dict[str, Any]] = []
    offset = 0
    while offset < len(value):
        parsed = _read_tag(value, offset)
        info = registry.lookup(parsed.tag_hex, parsed.tag_class, parsed.tag_number)
        tags.append(
            {
                "tag": parsed.tag_hex,
                "name": info.name,
                "aliases": list(info.aliases),
                "class": parsed.tag_class,
                "tagNumber": parsed.tag_number,
            }
        )
        offset = parsed.next_offset
    return tags


def _decode_with_asn1tools(
    schema_paths: list[Path],
    *,
    type_name: str,
    data: bytes,
    codec: str,
) -> dict[str, Any]:
    try:
        import asn1tools
    except ImportError as error:
        return {"ok": False, "error": f"asn1tools is not importable: {error}"}
    try:
        spec = asn1tools.compile_files([str(path) for path in schema_paths], codec=codec)
        decoded = spec.decode(type_name, data)
    except Exception as error:  # noqa: BLE001 - asn1tools raises parser/codec-specific exceptions.
        return {
            "ok": False,
            "codec": codec,
            "type": type_name,
            "schemaFiles": [str(path) for path in schema_paths],
            "error": str(error),
        }
    decoded_json = _json_safe(decoded)
    return {
        "ok": True,
        "codec": codec,
        "type": type_name,
        "schemaFiles": [str(path) for path in schema_paths],
        "value": decoded_json,
        "asn1Notation": _render_schema_value(type_name, decoded_json),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex().upper()}
    if isinstance(value, tuple):
        if len(value) == 2 and isinstance(value[0], str):
            return {"choice": value[0], "value": _json_safe(value[1])}
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _render_schema_value(type_name: str, value: Any) -> str:
    return f"{type_name} ::= {_render_value(value, 0)}"


def _render_item_notation(item: dict[str, Any], *, indent: int, assignment: bool) -> list[str]:
    prefix = " " * indent
    label = f"{item['name']} [{item['tag']}]"
    children = item.get("items")
    if isinstance(children, list):
        if len(children) == 0:
            operator = "::=" if assignment else "="
            return [f"{prefix}{label} {operator} {{}}"]
        first_line = f"{prefix}{label} ::= {{" if assignment else f"{prefix}{label} {{"
        lines = [first_line]
        for index, child in enumerate(children):
            child_lines = _render_item_notation(child, indent=indent + 2, assignment=False)
            if index < len(children) - 1:
                child_lines[-1] = child_lines[-1] + ","
            lines.extend(child_lines)
        lines.append(f"{prefix}}}")
        return lines
    value = item.get("decoded")
    rendered_value = _render_value(value, indent) if "decoded" in item else f"'{item.get('raw', '')}'H"
    operator = "::=" if assignment else "="
    return [f"{prefix}{label} {operator} {rendered_value}"]


def _render_value(value: Any, indent: int) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if re.fullmatch(r"\d+(?:\.\d+)+", value):
            return "{ " + " ".join(value.split(".")) + " }"
        return json.dumps(value)
    if isinstance(value, list):
        if len(value) == 0:
            return "{}"
        child_indent = " " * (indent + 2)
        closing_indent = " " * indent
        rendered = [f"{child_indent}{_render_value(item, indent + 2)}" for item in value]
        return "{\n" + ",\n".join(rendered) + f"\n{closing_indent}}}"
    if isinstance(value, dict):
        if set(value.keys()) == {"hex"}:
            return f"'{value['hex']}'H"
        if len(value) == 0:
            return "{}"
        child_indent = " " * (indent + 2)
        closing_indent = " " * indent
        lines = []
        for key, item in value.items():
            safe_key = _field_name(str(key))
            lines.append(f"{child_indent}{safe_key} {_render_value(item, indent + 2)}")
        return "{\n" + ",\n".join(lines) + f"\n{closing_indent}}}"
    return json.dumps(value)


def _field_name(text: str) -> str:
    clean = re.sub(r"[^0-9A-Za-z-]+", "-", text.strip()).strip("-")
    if len(clean) == 0:
        return "field"
    if clean[0].isdigit():
        return f"field-{clean}"
    return clean


if __name__ == "__main__":
    raise SystemExit(run_cli())
