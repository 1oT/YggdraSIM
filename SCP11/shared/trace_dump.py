# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 trace dump helpers: render card-bound payloads and STORE DATA chunk plans."""
from __future__ import annotations

import builtins
from typing import Any

from yggdrasim_common.nord_palette import NORD
from yggdrasim_common.process_debug import is_global_debug_enabled
from yggdrasim_common.terminal_output import colorize_hex_dump_line
from yggdrasim_common.terminal_output import should_use_color
from yggdrasim_common.terminal_output import status_print as print

try:
    from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
except Exception:
    build_euicc_info2_detail_lines = None

try:
    from SCP03.logic.sgp32_decode import decode_euicc_info1_summary
    from SCP03.logic.sgp32_decode import decode_notifications_response
except Exception:
    decode_euicc_info1_summary = None
    decode_notifications_response = None


_TAG_NAMES: dict[str, str] = {
    "02": "INTEGER",
    "03": "BIT STRING",
    "04": "OCTET STRING",
    "05": "NULL",
    "06": "OBJECT IDENTIFIER",
    "0C": "UTF8String",
    "13": "PrintableString",
    "17": "UTCTime",
    "18": "GeneralizedTime",
    "30": "SEQUENCE",
    "31": "SET",
    "4F": "AID",
    "5A": "eidValue",
    "5C": "tagList",
    "5F37": "signature",
    "80": "eimId",
    "81": "counterValue",
    "82": "eimTransactionId",
    "83": "seqNumber",
    "84": "associationToken",
    "A7": "psmo",
    "A8": "eCO",
    "E3": "ProfileInfo",
    "90": "profileNickname",
    "91": "serviceProviderName",
    "92": "profileName",
    "93": "iconType",
    "95": "profileClass",
    "99": "profilePolicyRules",
    "BF2D": "GetProfilesInfo",
    "BF36": "BoundProfilePackage",
    "BF3C": "EuiccConfiguredData",
    "BF50": "ProvideEimPackageResult",
    "BF51": "EuiccPackageRequest/Result",
    "BF52": "PackageData",
    "BF53": "EimAcknowledgements",
    "BF54": "ProfileDownloadTrigger",
    "BF55": "EimConfigurationData",
    "BF56": "GetCertsResponse",
    "9F67": "fallbackAllowed",
    "9F70": "profileState",
    "9F7B": "eCallIndication",
}


def format_hex_dump(
    payload: bytes,
    width: int = 32,
    indent: str = "    ",
    *,
    show_offsets: bool = False,
) -> list[str]:
    """Return an uppercase hex dump for a binary payload."""
    data = bytes(payload)
    row_width = int(width)
    if row_width <= 0:
        row_width = 32
    if len(data) == 0:
        return [f"{indent}<empty>"]

    lines: list[str] = []
    for offset in range(0, len(data), row_width):
        chunk = data[offset : offset + row_width]
        hex_bytes = " ".join(f"{item:02X}" for item in chunk)
        if show_offsets:
            lines.append(f"{indent}{offset:06X}: {hex_bytes}")
        else:
            lines.append(f"{indent}{hex_bytes}")
    return lines


def print_hex_payload(
    label: str,
    payload: bytes,
    width: int = 32,
    *,
    show_offsets: bool = False,
) -> None:
    """Print a full binary payload with deterministic hex formatting."""
    data = bytes(payload)
    clean_label = str(label or "payload").strip() or "payload"
    print(f"[*] {clean_label}: {len(data)} bytes")
    for line in format_hex_dump(data, width=width, show_offsets=show_offsets):
        print(colorize_hex_dump_line(line))


def format_tlv_decode(
    payload: bytes,
    *,
    indent: str = "    ",
    max_depth: int = 8,
    max_lines: int = 120,
    max_value_bytes: int = 32,
) -> list[str]:
    """Return a bounded BER-TLV decode tree for an operator trace."""
    data = bytes(payload)
    if len(data) == 0:
        return [f"{indent}<empty>"]

    semantic_lines = _format_semantic_tlv_decode(data, indent=indent)
    if semantic_lines is not None:
        return semantic_lines

    lines: list[str] = []
    offset = 0
    while offset < len(data):
        if len(lines) >= max_lines:
            _append_decode_truncated_line(lines, indent, max_lines)
            return lines
        parsed = _read_tlv_header(data, offset, len(data))
        if parsed is None:
            lines.append(f"{indent}<BER parse stopped at byte {offset}>")
            return lines
        _append_tlv_decode_node(
            lines,
            data,
            parsed,
            depth=0,
            path=(),
            indent=indent,
            max_depth=max_depth,
            max_lines=max_lines,
            max_value_bytes=max_value_bytes,
        )
        _, _, _, next_offset, _ = parsed
        if next_offset <= offset:
            lines.append(f"{indent}<BER parser made no progress at byte {offset}>")
            return lines
        offset = next_offset
    return lines


def print_tlv_decode(label: str, payload: bytes) -> None:
    """Print a BER-TLV decode tree for a binary payload."""
    clean_label = str(label or "payload").strip() or "payload"
    print(f"[*] {clean_label} decode:")
    for line in format_tlv_decode(payload):
        builtins.print(colorize_tlv_decode_line(line))


def colorize_tlv_decode_line(text: str) -> str:
    """Apply light inline accents to a BER-TLV decode row."""
    value = str(text)
    if should_use_color() is False:
        return value
    if "\033[" in value:
        return value

    indent_len = len(value) - len(value.lstrip(" "))
    indent = value[:indent_len]
    body = value[indent_len:]
    if len(body) == 0:
        return value
    if body.startswith("<"):
        return f"{indent}{NORD.GUIDE}{body}{NORD.RESET}"
    if body.startswith("[+]"):
        return f"{indent}{NORD.HEADER}{body}{NORD.RESET}"
    if body.startswith("|"):
        return _colorize_pipe_decode_line(indent, body)

    value_index = body.find(" value=")
    prefix = body
    value_part = ""
    if value_index >= 0:
        prefix = body[:value_index]
        value_part = body[value_index + 1 :]

    parts = prefix.split()
    if len(parts) == 0:
        return value
    len_index = next((index for index, part in enumerate(parts) if part.startswith("len=")), -1)
    if len_index < 0:
        return value

    rendered: list[str] = []
    if parts[0] in {"SEQUENCE", "SET"}:
        rendered.append(f"{NORD.HEADER}{parts[0]}{NORD.RESET}")
    else:
        rendered.append(f"{NORD.BLUE}{parts[0]}{NORD.RESET}")
        if len_index > 1:
            rendered.append(f"{NORD.HEADER}{' '.join(parts[1:len_index])}{NORD.RESET}")
    rendered.append(f"{NORD.GUIDE}{parts[len_index]}{NORD.RESET}")
    if len(parts) > len_index + 1:
        rendered.extend(parts[len_index + 1 :])
    if len(value_part) > 0:
        rendered.append(_colorize_decode_value(value_part))
    return indent + " ".join(rendered)


def _colorize_decode_value(value_part: str) -> str:
    if not value_part.startswith("value="):
        return value_part
    prefix = "value="
    rendered_value = value_part[len(prefix) :]
    if len(rendered_value) == 0:
        return f"{NORD.GUIDE}{prefix}{NORD.RESET}"
    if rendered_value.startswith('"'):
        color = NORD.GREEN
    elif rendered_value.startswith(("true", "false", "enabled", "disabled", "operational")):
        color = NORD.GREEN
    elif rendered_value.startswith(("unknown", "deleted")):
        color = NORD.WARNING
    else:
        color = NORD.SURFACE
    return f"{NORD.GUIDE}{prefix}{NORD.RESET}{color}{rendered_value}{NORD.RESET}"


def _colorize_pipe_decode_line(indent: str, body: str) -> str:
    separator = body.find(":")
    if separator < 0:
        return f"{indent}{NORD.GUIDE}{body}{NORD.RESET}"
    label = body[:separator]
    rendered_value = body[separator + 1 :]
    value_text = rendered_value.strip()
    if len(value_text) == 0:
        value_color = NORD.SURFACE
    elif value_text in {"Present", "PASS"} or value_text.startswith(("v", '"')):
        value_color = NORD.GREEN
    elif value_text.startswith(("Absent", "Missing", "Failed", "WARN")):
        value_color = NORD.WARNING
    else:
        value_color = NORD.SURFACE
    return (
        f"{indent}{NORD.GUIDE}{label}{NORD.RESET}:"
        f"{value_color}{rendered_value}{NORD.RESET}"
    )


def _format_semantic_tlv_decode(data: bytes, *, indent: str) -> list[str] | None:
    root = _read_tlv_header(data, 0, len(data))
    if root is None:
        return None
    tag_start, tag_end, value_start, value_end, _ = root
    if value_end != len(data):
        return None
    tag_hex = data[tag_start:tag_end].hex().upper()
    if tag_hex == "BF52":
        return _format_package_data_decode(data, root, indent=indent)
    return None


def _format_package_data_decode(
    data: bytes,
    root: tuple[int, int, int, int, bool],
    *,
    indent: str,
) -> list[str]:
    tag_start, tag_end, value_start, value_end, _ = root
    tag_hex = data[tag_start:tag_end].hex().upper()
    lines = [f"{indent}{tag_hex} PackageData len={value_end - value_start}"]
    root_children = _iter_tlv_headers(data, value_start, value_end)
    if len(root_children) == 0:
        lines.append(f"{indent}  <empty>")
        return lines

    for child in root_children:
        child_tag_start, child_tag_end, child_value_start, child_value_end, _ = child
        child_tag_hex = data[child_tag_start:child_tag_end].hex().upper()
        if child_tag_hex != "A0":
            _append_compact_tlv_item(lines, data, child, indent=indent + "  ")
            continue

        lines.append(f"{indent}  A0 packageDataResponse len={child_value_end - child_value_start}")
        items = _collect_package_data_items(data, child_value_start, child_value_end)
        _append_ipa_notifications_section(lines, items, indent=indent + "    ")
        _append_ipa_configured_data_section(lines, items, indent=indent + "    ")
        _append_package_info1_section(lines, items, indent=indent + "    ")
        _append_package_info2_section(lines, items, indent=indent + "    ")
        _append_ipa_link_data_section(lines, items, indent=indent + "    ")
        _append_ipa_package_results_section(lines, items, indent=indent + "    ")
        _append_ipa_get_certs_section(lines, items, indent=indent + "    ")
        _append_ipa_unknown_items(lines, items, indent=indent + "    ")
    return lines


def _collect_package_data_items(
    data: bytes,
    start: int,
    end: int,
) -> dict[str, list[dict[str, bytes]]]:
    items: dict[str, list[dict[str, bytes]]] = {}
    for parsed in _iter_tlv_headers(data, start, end):
        tag_start, tag_end, value_start, value_end, _ = parsed
        tag_hex = data[tag_start:tag_end].hex().upper()
        items.setdefault(tag_hex, []).append(
            {
                "raw": data[tag_start:value_end],
                "value": data[value_start:value_end],
            }
        )
    return items


def _append_ipa_notifications_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    item = _first_ipa_item(items, "A0")
    if item is None:
        return
    _append_section(lines, indent, "RetrieveNotificationsList")
    raw_response = _wrap_ber_tlv(bytes.fromhex("BF2B"), item["raw"])
    if decode_notifications_response is None:
        _append_pipe_value(lines, indent, "Raw", _hex_preview(item["raw"], 48))
        return
    decoded = decode_notifications_response(raw_response)
    error_text = str(decoded.get("error", "")).strip()
    if len(error_text) > 0:
        _append_pipe_value(lines, indent, "Result", error_text)
        return
    notifications = decoded.get("notifications", [])
    package_results = decoded.get("package_results", [])
    notification_count = len(notifications) if isinstance(notifications, list) else 0
    package_result_count = len(package_results) if isinstance(package_results, list) else 0
    _append_pipe_value(lines, indent, "Notification Entries", _format_count_or_empty(notification_count))
    if package_result_count > 0:
        _append_pipe_value(lines, indent, "Package Results", package_result_count)
    if isinstance(notifications, list) and len(notifications) > 0:
        first = notifications[0]
        if isinstance(first, dict):
            for key, label in (
                ("seqNumber", "First Seq Number"),
                ("operation", "First Operation"),
                ("notificationAddress", "First Server/FQDN"),
                ("iccid", "First ICCID"),
            ):
                if key in first:
                    _append_pipe_value(lines, indent, label, first[key])


def _append_ipa_configured_data_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    default_smdp = _first_ipa_value(items, "81")
    root_smds = _first_ipa_value(items, "83")
    if default_smdp is None and root_smds is None:
        return
    _append_section(lines, indent, "EuiccConfiguredData")
    if default_smdp is not None:
        _append_pipe_value(lines, indent, "SM-DP+ Address", _decode_text_or_hex(default_smdp) or "-")
    if root_smds is not None:
        _append_pipe_value(lines, indent, "Root SM-DS Address", _decode_text_or_hex(root_smds) or "-")


def _append_package_info1_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    item = _first_ipa_item(items, "BF20")
    if item is None:
        return
    _append_section(lines, indent, "EuiccInfo1")
    if decode_euicc_info1_summary is None:
        _append_pipe_value(lines, indent, "Raw", _hex_preview(item["raw"], 48))
        return
    summary = decode_euicc_info1_summary(item["raw"])
    if len(summary) == 0:
        _append_pipe_value(lines, indent, "Raw", _hex_preview(item["raw"], 48))
        return
    svn = str(summary.get("svn", "")).strip()
    if len(svn) > 0:
        _append_pipe_value(lines, indent, "Ver Supported", svn)
    _append_pipe_value(lines, indent, "CI PK Verify Entries", summary.get("ci_pk_verify_entries", 0))
    _append_pipe_value(lines, indent, "CI PK Sign Entries", summary.get("ci_pk_sign_entries", 0))


def _append_package_info2_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    item = _first_ipa_item(items, "BF22")
    if item is None:
        return
    _append_section(lines, indent, "EuiccInfo2")
    if build_euicc_info2_detail_lines is None:
        _append_pipe_value(lines, indent, "Raw", _hex_preview(item["raw"], 48))
        return
    detail_lines = build_euicc_info2_detail_lines(item["raw"])
    if len(detail_lines) == 0:
        _append_pipe_value(lines, indent, "Raw", _hex_preview(item["raw"], 48))
        return
    for depth, label, value in detail_lines:
        _append_pipe_value(lines, indent, _normalize_euicc_info2_label(str(label)), value, depth=int(depth))


def _append_ipa_link_data_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    association_token = _first_ipa_value(items, "84")
    request_token = _first_ipa_value(items, "87")
    ipa_capabilities = _first_ipa_value(items, "A8")
    device_information = _first_ipa_value(items, "A9")
    if (
        association_token is None
        and request_token is None
        and ipa_capabilities is None
        and device_information is None
    ):
        return
    _append_section(lines, indent, "IPA/eIM Link Data")
    if association_token is not None:
        _append_pipe_value(lines, indent, "Association Token", _format_unsigned_int(association_token))
    if request_token is not None:
        _append_pipe_value(lines, indent, "Request Token", _hex_preview(request_token, 32))
    if ipa_capabilities is not None:
        _append_pipe_value(lines, indent, "IPA Capabilities", _hex_preview(ipa_capabilities, 48))
    if device_information is not None:
        _append_pipe_value(lines, indent, "Device Information", _hex_preview(device_information, 48))


def _append_ipa_package_results_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    item = _first_ipa_item(items, "A2")
    if item is None:
        return
    _append_section(lines, indent, "EuiccPackageResults")
    child_count = len(_iter_tlv_headers(item["value"], 0, len(item["value"])))
    _append_pipe_value(lines, indent, "Result Entries", _format_count_or_empty(child_count))


def _append_ipa_get_certs_section(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    eum_cert = _first_ipa_value(items, "A5")
    euicc_cert = _first_ipa_value(items, "A6")
    if eum_cert is None and euicc_cert is None:
        return
    _append_section(lines, indent, "GetCerts")
    if eum_cert is not None:
        _append_certificate_container_summary(lines, indent, "EUM Certificate", eum_cert)
    if euicc_cert is not None:
        _append_certificate_container_summary(lines, indent, "eUICC Certificate", euicc_cert)


def _append_ipa_unknown_items(
    lines: list[str],
    items: dict[str, list[dict[str, bytes]]],
    *,
    indent: str,
) -> None:
    known_tags = {"A0", "81", "A2", "BF20", "BF22", "83", "84", "A5", "A6", "87", "A8", "A9"}
    unknown_tags = [tag_hex for tag_hex in items if tag_hex not in known_tags]
    if len(unknown_tags) == 0:
        return
    _append_section(lines, indent, "Unmapped IPA Data")
    for tag_hex in unknown_tags:
        for item in items[tag_hex]:
            _append_pipe_value(lines, indent, tag_hex, f"{len(item['value'])} byte(s)")


def _append_certificate_container_summary(
    lines: list[str],
    indent: str,
    section_name: str,
    value: bytes,
) -> None:
    summary = _summarize_der_material(value)
    _append_pipe_value(lines, indent, section_name, "Present")
    _append_pipe_value(lines, indent, "Certificate Bytes", len(value), depth=1)
    _append_pipe_value(lines, indent, "Certificate Objects", summary["certificate_objects"], depth=1)
    _append_pipe_value(lines, indent, "Public Key Entries", len(summary["public_keys"]), depth=1)
    _append_pipe_value(lines, indent, "Signature Entries", len(summary["signatures"]), depth=1)
    _append_pipe_value(lines, indent, "Identifier OIDs", len(summary["oids"]), depth=1)

    public_keys = summary["public_keys"]
    if isinstance(public_keys, list) and len(public_keys) > 0:
        _append_pipe_value(lines, indent, "Public Key (1st)", "0x" + str(public_keys[0]), depth=1)
    signatures = summary["signatures"]
    if isinstance(signatures, list) and len(signatures) > 0:
        _append_pipe_value(lines, indent, "Signature DER (1st)", "0x" + str(signatures[0]), depth=1)
    oid_preview = _format_oid_preview(summary["oids"])
    if len(oid_preview) > 0:
        _append_pipe_value(lines, indent, "Object Identifiers", oid_preview, depth=1)
    subject_hints = summary["subject_hints"]
    if isinstance(subject_hints, list) and len(subject_hints) > 0:
        _append_pipe_value(lines, indent, "Subject Hints", "; ".join(str(item) for item in subject_hints[:4]), depth=1)
    times = summary["times"]
    if isinstance(times, list) and len(times) >= 2:
        _append_pipe_value(lines, indent, "Validity", f"{times[0]} -> {times[1]}", depth=1)


def _summarize_der_material(value: bytes) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "certificate_objects": _count_certificate_objects(value),
        "oids": [],
        "public_keys": [],
        "signatures": [],
        "subject_hints": [],
        "times": [],
    }
    _collect_der_material(value, summary, depth=0)
    return summary


def _collect_der_material(value: bytes, summary: dict[str, Any], *, depth: int) -> None:
    if depth > 10:
        return
    headers = _iter_tlv_headers(value, 0, len(value))
    if len(headers) == 0:
        return
    for parsed in headers:
        tag_start, tag_end, value_start, value_end, constructed = parsed
        tag = value[tag_start:tag_end]
        child_value = value[value_start:value_end]
        tag_hex = tag.hex().upper()
        if constructed:
            _collect_der_material(child_value, summary, depth=depth + 1)
            continue
        if tag_hex == "06":
            oid = _decode_der_oid(child_value)
            if len(oid) > 0:
                _append_unique_text(summary["oids"], oid)
            continue
        if tag_hex in {"0C", "13"}:
            decoded = _decode_printable_text(child_value)
            if len(decoded) > 0:
                _append_unique_text(summary["subject_hints"], decoded)
            continue
        if tag_hex in {"17", "18"}:
            decoded = _decode_printable_text(child_value)
            if len(decoded) > 0:
                _append_unique_text(summary["times"], decoded)
            continue
        if tag_hex == "03":
            _collect_bit_string_material(child_value, summary)


def _collect_bit_string_material(value: bytes, summary: dict[str, Any]) -> None:
    if len(value) < 2:
        return
    unused_bits = value[0]
    payload = value[1:]
    if unused_bits != 0:
        return
    if len(payload) in {33, 65} and payload[0] in {0x02, 0x03, 0x04}:
        _append_unique_text(summary["public_keys"], _hex_preview(payload, 48))
        return
    if payload.startswith(b"\x30"):
        _append_unique_text(summary["signatures"], _hex_preview(payload, 48))


def _count_certificate_objects(value: bytes) -> int:
    root = _read_tlv_header(value, 0, len(value))
    if root is None:
        return 0
    tag_start, tag_end, value_start, value_end, _ = root
    tag = value[tag_start:tag_end]
    child_value = value[value_start:value_end]
    if value_end == len(value) and _looks_like_der_certificate(tag, child_value):
        return 1
    count = 0
    for parsed in _iter_tlv_headers(value, 0, len(value)):
        child_tag_start, child_tag_end, child_value_start, child_value_end, _ = parsed
        child_tag = value[child_tag_start:child_tag_end]
        parsed_value = value[child_value_start:child_value_end]
        if _looks_like_der_certificate(child_tag, parsed_value):
            count += 1
    return count


def _format_oid_preview(oids: Any) -> str:
    if isinstance(oids, list) is False:
        return ""
    preview: list[str] = []
    for oid in oids:
        oid_text = str(oid)
        if oid_text.startswith("2.5.4.") or oid_text.startswith("2.5.29."):
            continue
        preview.append(_format_oid_name(oid_text))
        if len(preview) >= 3:
            break
    return ", ".join(preview)


def _format_oid_name(oid: str) -> str:
    names = {
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.2.1": "id-ecPublicKey",
        "1.2.840.10045.3.1.7": "prime256v1",
    }
    name = names.get(oid)
    if name is None:
        return oid
    return f"{name} ({oid})"


def _append_unique_text(values: Any, value: str) -> None:
    if isinstance(values, list) is False:
        return
    if value in values:
        return
    values.append(value)


def _append_section(lines: list[str], indent: str, title: str) -> None:
    lines.append(f"{indent}[+] {title}")


def _append_pipe_value(
    lines: list[str],
    indent: str,
    label: str,
    value: Any,
    *,
    depth: int = 0,
    label_width: int = 24,
) -> None:
    value_text = str(value)
    line_indent = indent + "  " + ("  " * max(0, int(depth)))
    lines.append(f"{line_indent}| {str(label):<{label_width}}: {value_text}")


def _normalize_euicc_info2_label(label: str) -> str:
    label_map = {
        "Ver Supported (SGP.22 SVN)": "Ver Supported",
        "TS102.241 Version": "TS102.241 Ver",
        "GlobalPlatform Version": "GP Version",
        "Forbidden Profile Policy Rules": "Forbidden PPR",
        "Additional eUICC Profile Package Versions": "Additional PP Vers.",
        "CI PKId List For Verification": "CI PKId Verify",
        "CI PKId List For Signing": "CI PKId Sign",
    }
    return label_map.get(label, label)


def _append_compact_tlv_item(
    lines: list[str],
    data: bytes,
    parsed: tuple[int, int, int, int, bool],
    *,
    indent: str,
) -> None:
    tag_start, tag_end, value_start, value_end, constructed = parsed
    tag_hex = data[tag_start:tag_end].hex().upper()
    name = _display_name(tag_hex, ())
    fragments = [tag_hex]
    if len(name) > 0:
        fragments.append(name)
    fragments.append(f"len={value_end - value_start}")
    summary = _tlv_value_summary(data[tag_start:tag_end], data[value_start:value_end], constructed, 32, ())
    if len(summary) > 0:
        fragments.append(summary)
    lines.append(indent + " ".join(fragments))


def _first_ipa_item(
    items: dict[str, list[dict[str, bytes]]],
    tag_hex: str,
) -> dict[str, bytes] | None:
    values = items.get(tag_hex)
    if isinstance(values, list) is False or len(values) == 0:
        return None
    return values[0]


def _first_ipa_value(
    items: dict[str, list[dict[str, bytes]]],
    tag_hex: str,
) -> bytes | None:
    item = _first_ipa_item(items, tag_hex)
    if item is None:
        return None
    return item["value"]


def _format_count_or_empty(value: int) -> str:
    if value == 0:
        return "(Empty)"
    return str(value)


def _wrap_ber_tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + _encode_ber_length(len(value)) + bytes(value)


def _encode_ber_length(length: int) -> bytes:
    clean_length = max(0, int(length))
    if clean_length < 0x80:
        return bytes([clean_length])
    length_bytes = clean_length.to_bytes((clean_length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def summarize_eim_package_wrapper(payload: bytes) -> dict[str, str]:
    """Return a BER-grounded summary of an eIM package wrapper."""
    data = bytes(payload)
    summary: dict[str, str] = {
        "root_tag": "",
        "root_len": "0",
        "complete": "no",
        "outer_eim_id": "",
        "eid": "",
        "counter": "",
        "eim_transaction_id": "",
        "inner_choice": "",
        "inner_card_request": "",
        "inner_card_request_len": "",
        "signature_present": "no",
        "signature_len": "0",
    }
    if len(data) == 0:
        return summary

    root = _read_tlv_header(data, 0, len(data))
    if root is None:
        return summary
    root_tag_start, root_tag_end, root_value_start, root_value_end, _ = root
    summary["root_tag"] = data[root_tag_start:root_tag_end].hex().upper()
    summary["root_len"] = str(root_value_end - root_value_start)
    summary["complete"] = "yes" if root_value_end == len(data) else "no"

    signed_value = b""
    for child in _iter_tlv_headers(data, root_value_start, root_value_end):
        child_tag_start, child_tag_end, child_value_start, child_value_end, _ = child
        child_tag = data[child_tag_start:child_tag_end]
        child_value = data[child_value_start:child_value_end]
        if child_tag == b"\x30" and len(signed_value) == 0:
            signed_value = child_value
            continue
        if child_tag == b"\x5F\x37":
            summary["signature_present"] = "yes"
            summary["signature_len"] = str(len(child_value))

    if len(signed_value) == 0:
        return summary

    for field in _iter_tlv_headers(signed_value, 0, len(signed_value)):
        field_tag_start, field_tag_end, field_value_start, field_value_end, _ = field
        field_tag = signed_value[field_tag_start:field_tag_end]
        field_value = signed_value[field_value_start:field_value_end]
        if field_tag == b"\x80":
            summary["outer_eim_id"] = _decode_text_or_hex(field_value)
        elif field_tag == b"\x5A":
            summary["eid"] = field_value.hex().upper()
        elif field_tag == b"\x81":
            summary["counter"] = _format_unsigned_int(field_value)
        elif field_tag == b"\x82":
            summary["eim_transaction_id"] = field_value.hex().upper()
        elif len(field_tag) > 0 and field_tag[0] in range(0xA0, 0xB0):
            summary["inner_choice"] = field_tag.hex().upper()
            inner = _first_tlv_header(field_value)
            if inner is not None:
                inner_tag_start, inner_tag_end, inner_value_start, inner_value_end, _ = inner
                summary["inner_card_request"] = field_value[inner_tag_start:inner_tag_end].hex().upper()
                summary["inner_card_request_len"] = str(inner_value_end - inner_value_start)
    return summary


def print_eim_package_wrapper_summary(payload: bytes) -> None:
    """Print wrapper fields that the card can validate from the BER bytes."""
    summary = summarize_eim_package_wrapper(payload)
    fragments = [
        f"root={summary['root_tag'] or '(unparsed)'}",
        f"root_len={summary['root_len']}",
        f"complete={summary['complete']}",
    ]
    if summary["outer_eim_id"]:
        fragments.append(f"outer_eimId={summary['outer_eim_id']}")
    if summary["eid"]:
        fragments.append(f"eid={summary['eid']}")
    if summary["counter"]:
        fragments.append(f"counter={summary['counter']}")
    if summary["eim_transaction_id"]:
        fragments.append(f"eimTransactionId={summary['eim_transaction_id']}")
    if summary["inner_choice"]:
        fragments.append(f"inner_choice={summary['inner_choice']}")
    if summary["inner_card_request"]:
        fragments.append(
            f"inner_card_request={summary['inner_card_request']}"
            f"/{summary['inner_card_request_len']}"
        )
    fragments.append(
        f"signature={summary['signature_present']}"
        f"/{summary['signature_len']}B"
    )
    print("[*] eIM signed wrapper summary: " + " ".join(fragments))


def split_tlv_aware_chunks(payload: bytes, chunk_size: int) -> list[bytes]:
    """Split a BER-TLV stream on TLV boundaries when possible."""
    data = bytes(payload)
    if len(data) == 0:
        return []
    effective_chunk_size = int(chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = 1

    boundaries = _tlv_end_boundaries(data)
    chunks: list[bytes] = []
    offset = 0
    total = len(data)
    while offset < total:
        fixed_limit = min(total, offset + effective_chunk_size)
        next_offset = fixed_limit
        if fixed_limit < total:
            candidates = [
                boundary
                for boundary in boundaries
                if offset < boundary <= fixed_limit
            ]
            if len(candidates) > 0:
                next_offset = max(candidates)
        if next_offset <= offset:
            next_offset = fixed_limit
        chunks.append(data[offset:next_offset])
        offset = next_offset
    return chunks


def _tlv_end_boundaries(data: bytes) -> set[int]:
    boundaries: set[int] = {len(data)}
    _collect_tlv_end_boundaries(data, 0, len(data), boundaries)
    return boundaries


def _collect_tlv_end_boundaries(
    data: bytes,
    start: int,
    end: int,
    boundaries: set[int],
) -> None:
    offset = start
    while offset < end:
        parsed = _read_tlv_header(data, offset, end)
        if parsed is None:
            return
        tag_start, _, value_start, value_end, constructed = parsed
        if value_end > end:
            return
        if value_end > tag_start:
            boundaries.add(value_end)
        if constructed:
            _collect_tlv_end_boundaries(data, value_start, value_end, boundaries)
        offset = value_end
    if offset == end:
        boundaries.add(end)


def _read_tlv_header(
    data: bytes,
    offset: int,
    end: int,
) -> tuple[int, int, int, int, bool] | None:
    if offset >= end:
        return None
    tag_start = offset
    first_tag_byte = data[offset]
    constructed = bool(first_tag_byte & 0x20)
    offset += 1
    if first_tag_byte & 0x1F == 0x1F:
        while offset < end:
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            return None
    tag_end = offset
    if offset >= end:
        return None

    first_length_byte = data[offset]
    offset += 1
    if first_length_byte & 0x80 == 0:
        value_length = first_length_byte
    else:
        length_octets = first_length_byte & 0x7F
        if length_octets == 0:
            return None
        if length_octets > 4:
            return None
        if offset + length_octets > end:
            return None
        value_length = int.from_bytes(data[offset : offset + length_octets], "big")
        offset += length_octets

    value_start = offset
    value_end = value_start + value_length
    if value_end > end:
        return None
    return tag_start, tag_end, value_start, value_end, constructed


def _iter_tlv_headers(
    data: bytes,
    start: int,
    end: int,
) -> list[tuple[int, int, int, int, bool]]:
    headers: list[tuple[int, int, int, int, bool]] = []
    offset = start
    while offset < end:
        parsed = _read_tlv_header(data, offset, end)
        if parsed is None:
            break
        headers.append(parsed)
        _, _, _, value_end, _ = parsed
        if value_end <= offset:
            break
        offset = value_end
    return headers


def _first_tlv_header(data: bytes) -> tuple[int, int, int, int, bool] | None:
    return _read_tlv_header(data, 0, len(data))


def _append_tlv_decode_node(
    lines: list[str],
    data: bytes,
    parsed: tuple[int, int, int, int, bool],
    *,
    depth: int,
    path: tuple[str, ...],
    indent: str,
    max_depth: int,
    max_lines: int,
    max_value_bytes: int,
) -> None:
    if len(lines) >= max_lines:
        return
    tag_start, tag_end, value_start, value_end, constructed = parsed
    tag = data[tag_start:tag_end]
    value = data[value_start:value_end]
    tag_hex = tag.hex().upper()
    line_indent = indent + ("  " * depth)
    name = _display_name(tag_hex, path)
    if tag_hex in {"30", "31"} and len(name) > 0:
        fragments = [name]
    else:
        fragments = [tag_hex]
        if len(name) > 0:
            fragments.append(name)
    fragments.append(f"len={len(value)}")
    summary = _tlv_value_summary(tag, value, constructed, max_value_bytes, path)
    if len(summary) > 0:
        fragments.append(summary)
    lines.append(line_indent + " ".join(fragments))

    if constructed is False:
        return
    if depth >= max_depth:
        if len(lines) < max_lines:
            lines.append(line_indent + "  <max decode depth reached>")
        return
    if _looks_like_der_certificate(tag, value):
        if len(lines) < max_lines:
            lines.append(line_indent + "  <X.509 certificate DER omitted>")
        return

    offset = value_start
    truncated = False
    while offset < value_end:
        if len(lines) >= max_lines:
            truncated = True
            break
        child = _read_tlv_header(data, offset, value_end)
        if child is None:
            lines.append(line_indent + f"  <BER parse stopped at byte {offset - value_start}>")
            return
        _append_tlv_decode_node(
            lines,
            data,
            child,
            depth=depth + 1,
            path=path + (tag_hex,),
            indent=indent,
            max_depth=max_depth,
            max_lines=max_lines,
            max_value_bytes=max_value_bytes,
        )
        _, _, _, child_end, _ = child
        if child_end <= offset:
            lines.append(line_indent + f"  <BER parser made no progress at byte {offset - value_start}>")
            return
        offset = child_end
    if offset < value_end and len(lines) < max_lines:
        lines.append(line_indent + f"  <{value_end - offset} trailing byte(s)>")
    if truncated:
        _append_decode_truncated_line(lines, indent, max_lines)


def _append_decode_truncated_line(lines: list[str], indent: str, max_lines: int) -> None:
    marker = f"<decode truncated at {max_lines} lines>"
    if any(line.strip() == marker for line in lines):
        return
    lines.append(indent + marker)


def _display_name(tag_hex: str, path: tuple[str, ...]) -> str:
    if _inside_profile_info(path):
        profile_names = {
            "5A": "ICCID",
            "4F": "isdpAid",
            "90": "profileNickname",
            "91": "serviceProviderName",
            "92": "profileName",
            "93": "iconType",
            "95": "profileClass",
            "99": "profilePolicyRules",
            "9F67": "fallbackAllowed",
            "9F70": "profileState",
            "9F7B": "eCallIndication",
        }
        name = profile_names.get(tag_hex)
        if name is not None:
            return name
    if _inside_eim_configuration_data(path):
        eim_config_names = {
            "80": "eimId",
            "81": "eimFqdn",
            "82": "eimIdType",
            "83": "counterValue",
            "84": "associationToken",
            "87": "eimSupportedProtocol",
            "88": "euiccCiPKId",
            "89": "indirectProfileDownload",
            "A5": "eimPublicKeyData",
            "A6": "trustedPublicKeyDataTls",
        }
        name = eim_config_names.get(tag_hex)
        if name is not None:
            return name
    return _TAG_NAMES.get(tag_hex, "")


def _inside_profile_info(path: tuple[str, ...]) -> bool:
    if "E3" in path:
        return True
    return "BF2D" in path


def _inside_eim_configuration_data(path: tuple[str, ...]) -> bool:
    if len(path) >= 4 and path[-4:] in {
        ("BF51", "30", "A1", "A8"),
        ("BF51", "30", "A1", "AA"),
    }:
        return True
    if len(path) >= 3 and path[-3:] == ("BF57", "A0", "30"):
        return True
    if len(path) >= 3 and path[-3:] == ("BF58", "A0", "30"):
        return True
    if len(path) >= 1 and path[-1:] == ("BF55",):
        return True
    if len(path) >= 2 and path[-2:] == ("BF55", "30"):
        return True
    if len(path) >= 3 and path[-3:] == ("BF55", "A0", "30"):
        return True
    return False


def _tlv_value_summary(
    tag: bytes,
    value: bytes,
    constructed: bool,
    max_value_bytes: int,
    path: tuple[str, ...],
) -> str:
    if len(value) == 0:
        return ""
    tag_hex = tag.hex().upper()
    if constructed:
        if _looks_like_der_certificate(tag, value):
            return "X.509 certificate DER"
        return ""
    if _inside_eim_configuration_data(path):
        if tag_hex in {"81", "80"}:
            decoded = _decode_printable_text(value)
            if len(decoded) > 0:
                return f'value="{decoded}"'
        if tag_hex == "82" and len(value) <= 8:
            return f"value={_format_eim_id_type(value)}"
        if tag_hex in {"83", "84"} and len(value) <= 8:
            return f"value={int.from_bytes(value, 'big', signed=False)} ({value.hex().upper()})"
        if tag_hex == "87":
            return f"value={_format_eim_supported_protocol(value)}"
    if tag_hex == "06":
        oid = _decode_der_oid(value)
        if len(oid) > 0:
            return f"value={oid}"
    if tag_hex == "5A" and _inside_profile_info(path):
        return f"value={_decode_bcd_digits(value)}"
    if tag_hex == "9F70" and len(value) == 1:
        names = {0: "disabled", 1: "enabled", 2: "deleted"}
        return f"value={names.get(value[0], 'unknown')} ({value.hex().upper()})"
    if tag_hex == "95" and len(value) == 1:
        names = {0: "test", 1: "provisioning", 2: "operational"}
        return f"value={names.get(value[0], 'unknown')} ({value.hex().upper()})"
    if tag_hex in {"9F67", "9F7B"} and len(value) == 1:
        return f"value={_format_bool_byte(value[0])} ({value.hex().upper()})"
    if tag_hex in {"02", "81", "83", "84"} and len(value) <= 8:
        return f"value={int.from_bytes(value, 'big', signed=False)} ({value.hex().upper()})"
    if tag_hex == "82":
        return f"value={value.hex().upper()}"
    if tag_hex == "5A":
        return f"value={value.hex().upper()}"
    if tag_hex == "5C":
        return f"value={_decode_tag_list(value)}"
    if tag_hex == "5F37":
        return _signature_summary(value)
    if tag_hex in {"0C", "13", "17", "18", "80"}:
        decoded = _decode_printable_text(value)
        if len(decoded) > 0:
            return f'value="{decoded}"'
    decoded = _decode_printable_text(value)
    if len(decoded) > 0 and len(value) <= max_value_bytes:
        return f'value="{decoded}"'
    return f"value={_hex_preview(value, max_value_bytes)}"


def _decode_bcd_digits(value: bytes) -> str:
    digits: list[str] = []
    for item in value:
        for nibble in (item & 0x0F, (item >> 4) & 0x0F):
            if nibble == 0x0F:
                continue
            if nibble <= 9:
                digits.append(str(nibble))
    return "".join(digits)


def _format_bool_byte(value: int) -> str:
    if value == 0:
        return "false"
    if value == 1:
        return "true"
    return str(value)


def _format_eim_id_type(value: bytes) -> str:
    if len(value) == 0:
        return "0 (00)"
    integer_value = int.from_bytes(value, "big", signed=False)
    names = {
        1: "eimIdTypeOid",
        2: "eimIdTypeFqdn",
        3: "eimIdTypeProprietary",
    }
    label = names.get(integer_value)
    if label is None:
        return f"{integer_value} ({value.hex().upper()})"
    return f"{label} ({value.hex().upper()})"


def _format_eim_supported_protocol(value: bytes) -> str:
    if len(value) == 0:
        return ""
    unused_bits = value[0]
    bit_payload = value[1:]
    if len(bit_payload) == 0:
        return f"none ({value.hex().upper()})"
    names = {
        0: "eimRetrieveHttps",
        1: "eimRetrieveCoaps",
        2: "eimInjectHttps",
        3: "eimInjectCoaps",
        4: "eimProprietary",
    }
    enabled: list[str] = []
    bit_count = max((len(bit_payload) * 8) - int(unused_bits), 0)
    for bit_index in range(bit_count):
        byte_value = bit_payload[bit_index // 8]
        mask = 0x80 >> (bit_index % 8)
        if byte_value & mask:
            enabled.append(names.get(bit_index, f"bit{bit_index}"))
    if len(enabled) == 0:
        return f"none ({value.hex().upper()})"
    return f"{','.join(enabled)} ({value.hex().upper()})"


def _decode_der_oid(value: bytes) -> str:
    if len(value) == 0:
        return ""
    first = value[0]
    if first < 40:
        numbers = [0, first]
    elif first < 80:
        numbers = [1, first - 40]
    else:
        numbers = [2, first - 80]
    current = 0
    for item in value[1:]:
        current = (current << 7) | (item & 0x7F)
        if item & 0x80 == 0:
            numbers.append(current)
            current = 0
    if current != 0:
        numbers.append(current)
    return ".".join(str(item) for item in numbers)


def _decode_tag_list(value: bytes) -> str:
    tags: list[str] = []
    offset = 0
    while offset < len(value):
        tag_start = offset
        offset += 1
        if value[tag_start] & 0x1F == 0x1F:
            while offset < len(value):
                current = value[offset]
                offset += 1
                if current & 0x80 == 0:
                    break
        tags.append(value[tag_start:offset].hex().upper())
    return ",".join(tags)


def _signature_summary(value: bytes) -> str:
    if len(value) == 64:
        r_preview = value[:32].hex().upper()[:16]
        s_preview = value[32:].hex().upper()[:16]
        return f"value=64B ECDSA-rs r={r_preview}... s={s_preview}..."
    return f"value={_hex_preview(value, 32)}"


def _decode_printable_text(value: bytes) -> str:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if decoded.isprintable() is False:
        return ""
    return decoded.replace('"', '\\"')


def _hex_preview(value: bytes, max_value_bytes: int) -> str:
    cap = int(max_value_bytes)
    if cap <= 0:
        cap = 32
    if len(value) <= cap:
        return value.hex().upper()
    return value[:cap].hex().upper() + f"...({len(value)}B)"


def _looks_like_der_certificate(tag: bytes, value: bytes) -> bool:
    if tag != b"\x30":
        return False
    if len(value) < 16:
        return False
    if value.startswith(b"\xA0\x03\x02\x01") is False:
        return False
    return b"\x30" in value[4:16]


def _decode_text_or_hex(value: bytes) -> str:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    if decoded.isprintable():
        return decoded
    return value.hex().upper()


def _format_unsigned_int(value: bytes) -> str:
    if len(value) == 0:
        return "0"
    integer_value = int.from_bytes(value, "big", signed=False)
    return f"{integer_value} ({value.hex().upper()})"


def print_store_data_chunk_plan(
    log_name: str,
    payload: bytes,
    *,
    cla: int,
    ins: int,
    final_p1: int,
    p2_start: int,
    chunk_size: int,
    more_p1: int = 0x11,
    p2_wrap: bool = False,
    width: int = 32,
    chunks: list[bytes] | None = None,
) -> None:
    """Print the STORE DATA segmentation that will be used before transmission."""
    data = bytes(payload)
    clean_label = str(log_name or "STORE DATA").strip() or "STORE DATA"
    effective_chunk_size = int(chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = 1

    total = len(data)
    planned_chunks = list(chunks) if chunks is not None else split_tlv_aware_chunks(data, effective_chunk_size)
    chunk_count = len(planned_chunks)
    if is_global_debug_enabled() is False:
        print(
            f"[*] STORE DATA chunks for {clean_label}: "
            f"total_bytes={total} chunk_size={effective_chunk_size} chunks={chunk_count} "
            f"CLA={int(cla) & 0xFF:02X} INS={int(ins) & 0xFF:02X}"
        )
        print(f"  > {_format_store_data_chunk_sequence(planned_chunks)}")
        return

    print(
        f"[*] STORE DATA chunk plan for {clean_label}: "
        f"total_bytes={total} chunk_size={effective_chunk_size} chunks={chunk_count} "
        f"strategy=tlv-aware "
        f"CLA={int(cla) & 0xFF:02X} INS={int(ins) & 0xFF:02X} "
        f"P1_more={int(more_p1) & 0xFF:02X} P1_final={int(final_p1) & 0xFF:02X} "
        f"P2_start={int(p2_start) & 0xFF:02X}"
    )
    print_hex_payload(f"{clean_label} full payload", data, width=width)

    tlv_boundaries = _tlv_end_boundaries(data)
    offset = 0
    block = int(p2_start)
    for chunk_index, chunk in enumerate(planned_chunks, start=1):
        chunk_bytes = bytes(chunk)
        end_offset = offset + len(chunk_bytes)
        is_last_chunk = chunk_index == chunk_count
        current_p1 = final_p1 if is_last_chunk else more_p1
        current_p2 = block & 0xFF if p2_wrap else block
        if p2_wrap and current_p2 != block:
            p2_text = f"{block:02X}->{current_p2:02X}"
        else:
            p2_text = f"{current_p2:02X}"
        last_text = "yes" if is_last_chunk else "no"
        boundary_text = "tlv" if end_offset in tlv_boundaries else "max"
        print(
            f"  > Chunk {chunk_index}/{chunk_count}: "
            f"offset={offset} len={len(chunk_bytes)} P1={int(current_p1) & 0xFF:02X} "
            f"P2={p2_text} last={last_text} boundary={boundary_text}"
        )
        for line in format_hex_dump(chunk_bytes, width=width, indent="      "):
            print(colorize_hex_dump_line(line))
        offset = end_offset
        block += 1


def _format_store_data_chunk_sequence(chunks: list[bytes]) -> str:
    if len(chunks) == 0:
        return "<no chunks>"
    chunk_count = len(chunks)
    return " -> ".join(
        f"Chunk {index}/{chunk_count} ({len(bytes(chunk))}B)"
        for index, chunk in enumerate(chunks, start=1)
    )
