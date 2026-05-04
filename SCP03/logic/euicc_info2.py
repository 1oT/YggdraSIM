from typing import Dict, List, Optional, Tuple


EUICC_INFO2_TAG_NAMES: dict[int, str] = {
    0x81: "Profile Version",
    0x82: "Ver Supported (SGP.22 SVN)",
    0x83: "Firmware Ver",
    0x84: "Ext Card Res",
    0x85: "UICC Capability",
    0x86: "TS102.241 Version",
    0x87: "GlobalPlatform Version",
    0x88: "RSP Capability",
    0x8B: "eUICC Category",
    0x99: "Forbidden Profile Policy Rules",
    0x04: "PP Version",
    0x0C: "SAS Accreditation Number",
    0xAC: "Certification Data Object",
    0x8D: "TRE Properties",
    0x8E: "TRE Product Reference",
    0xAF: "Additional eUICC Profile Package Versions",
    0x90: "IPA Mode",
    0x91: "CI PKId List For Signing V3",
    0x92: "Additional eUICC Info",
    0x93: "Highest SVN",
    0xB4: "IoT Specific Info",
    0xA9: "CI PKId List For Verification",
    0xAA: "CI PKId List For Signing",
}

EUICC_INFO2_NESTED_TAG_NAMES: dict[int, dict[int, str]] = {
    0x84: {
        0x81: "Installed Apps",
        0x82: "Free NVM",
        0x83: "Free RAM",
    },
    0xA0: {
        0x04: "IoT Version",
    },
    0xA9: {
        0x04: "CI PKId",
    },
    0xAA: {
        0x04: "CI PKId",
    },
    0xAF: {
        0x04: "Additional PP Version",
    },
    0xB4: {
        0xA0: "IoT Version List",
        0x81: "eCall Supported",
        0x82: "Fallback Supported",
    },
}

RSP_CAPABILITY_FLAGS: dict[int, str] = {
    0: "additionalProfile",
    1: "crlSupport",
    2: "rpmSupport",
    3: "testProfileSupport",
}

UICC_CAPABILITY_FLAGS: dict[int, str] = {
    0: "contactlessSupport",
    1: "usimSupport",
    2: "isimSupport",
    3: "csimSupport",
    4: "akaMilenage",
    5: "akaCave",
    6: "akaTuak128",
    7: "akaTuak256",
    8: "rfu1",
    9: "rfu2",
    10: "gbaAuthenUsim",
    11: "gbaAuthenISim",
    12: "mbmsAuthenUsim",
    13: "eapClient",
    14: "javacard",
    15: "multos",
    16: "multipleUsimSupport",
    17: "multipleIsimSupport",
    18: "multipleCsimSupport",
}

PPR_FLAGS: dict[int, str] = {
    0: "pprUpdateControl",
    1: "ppr1 (disable not allowed)",
    2: "ppr2 (delete not allowed)",
    3: "ppr3 (delete required after disable)",
}

TRE_PROPERTY_FLAGS: dict[int, str] = {
    0: "isDiscrete",
    1: "isIntegrated",
    2: "usesRemoteMemory",
}

EUICC_INFO2_MANDATORY_TAGS: tuple[int, ...] = (
    0x81,
    0x82,
    0x83,
    0x84,
    0x85,
    0x88,
    0xA9,
    0xAA,
    0x04,
    0x0C,
    0x90,
    0xB4,
)


def parse_tlv_nodes(data: bytes) -> List[Tuple[int, bytes, bool]]:
    nodes: List[Tuple[int, bytes, bool]] = []
    index = 0
    while index < len(data):
        tag, index_after_tag, constructed = _read_tag(data, index)
        if index_after_tag <= index:
            break
        length, length_size = _decode_length(data, index_after_tag)
        if length_size == 0:
            break
        value_start = index_after_tag + length_size
        value_end = value_start + length
        if value_end > len(data):
            break
        value = data[value_start:value_end]
        nodes.append((tag, value, constructed))
        index = value_end
    return nodes


def parse_tlv_simple(data: bytes) -> Dict[int, object]:
    parsed: Dict[int, object] = {}
    for tag, value, _constructed in parse_tlv_nodes(data):
        if tag in parsed:
            existing = parsed[tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                parsed[tag] = [existing, value]
            continue
        parsed[tag] = value
    return parsed


def unwrap_euicc_info2_payload(data: bytes) -> bytes:
    nodes = parse_tlv_nodes(data)
    if len(nodes) == 1 and nodes[0][0] == 0xBF22:
        return nodes[0][1]
    return data


def resolve_euicc_info2_tag_name(tag: int, parent_tag: Optional[int]) -> Optional[str]:
    if parent_tag == 0xBF22:
        return EUICC_INFO2_TAG_NAMES.get(tag)
    nested = EUICC_INFO2_NESTED_TAG_NAMES.get(parent_tag)
    if nested is not None:
        return nested.get(tag)
    return None


def decode_euicc_info2_value(tag: int, value: bytes, parent_tag: Optional[int]) -> Optional[str]:
    if parent_tag == 0xBF22:
        if tag in (0x81, 0x82, 0x83, 0x86, 0x87, 0x04):
            return format_version_bytes(value)
        if tag == 0x85:
            return format_named_bit_string(value, UICC_CAPABILITY_FLAGS)
        if tag == 0x88:
            return format_named_bit_string(value, RSP_CAPABILITY_FLAGS)
        if tag == 0x8B:
            return decode_euicc_category(value)
        if tag == 0x99:
            return format_named_bit_string(value, PPR_FLAGS)
        if tag == 0x0C:
            return quote_text(value)
        if tag == 0x90:
            return decode_ipa_mode(value)
        if tag == 0x92:
            return value.hex().upper()
        if tag == 0x93:
            return format_version_bytes(value)
    if parent_tag == 0x84:
        return decode_ext_card_resource_value(tag, value)
    if parent_tag == 0xA0 and tag == 0x04:
        return format_version_bytes(value)
    if parent_tag in (0xA9, 0xAA) and tag == 0x04:
        return value.hex().upper()
    if parent_tag == 0xAF and tag == 0x04:
        return format_version_bytes(value)
    if parent_tag == 0xB4:
        if tag == 0x81:
            return "Present (eCall supported)"
        if tag == 0x82:
            return "Present (fallback supported)"
    if parent_tag == 0x8D:
        return format_named_bit_string(value, TRE_PROPERTY_FLAGS)
    return None


def build_euicc_info2_detail_lines(response: bytes) -> List[Tuple[int, str, str]]:
    root_value = unwrap_euicc_info2_payload(response)
    root_map = parse_tlv_simple(root_value)
    lines: List[Tuple[int, str, str]] = []

    ordered_tags = [
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0xA9,
        0xAA,
        0x8B,
        0x99,
        0x04,
        0x0C,
        0xAC,
        0x8D,
        0x8E,
        0xAF,
        0x90,
        0xB4,
        0x91,
        0x92,
        0x93,
    ]
    for tag in ordered_tags:
        value = _first_bytes(root_map.get(tag))
        if value is None:
            continue
        label = resolve_euicc_info2_tag_name(tag, 0xBF22) or f"{tag:02X}"
        lines.extend(_build_root_detail_lines(tag, label, value))

    validation_lines = build_euicc_info2_validation_lines(root_value)
    lines.extend(validation_lines)
    return lines


def build_euicc_info2_validation_lines(response: bytes) -> List[Tuple[int, str, str]]:
    root_value = unwrap_euicc_info2_payload(response)
    root_map = parse_tlv_simple(root_value)
    warnings: List[str] = []
    validation: List[Tuple[int, str, str]] = []

    has_iot_specific_fields = False
    if _first_bytes(root_map.get(0x90)) is not None:
        has_iot_specific_fields = True
    if _first_bytes(root_map.get(0xB4)) is not None:
        has_iot_specific_fields = True
    if has_iot_specific_fields is False:
        return validation

    missing_mandatory: List[str] = []
    for tag in EUICC_INFO2_MANDATORY_TAGS:
        if _first_bytes(root_map.get(tag)) is None:
            label = resolve_euicc_info2_tag_name(tag, 0xBF22) or f"{tag:02X}"
            missing_mandatory.append(label)

    if len(missing_mandatory) > 0:
        warnings.append("Missing mandatory fields: " + ", ".join(missing_mandatory))

    if _first_bytes(root_map.get(0x91)) is not None:
        warnings.append("CI PKId List For Signing V3 is present, but SGP.32 v1.2 marks it as not used.")
    if _first_bytes(root_map.get(0x92)) is not None:
        warnings.append("Additional eUICC Info is present, but SGP.32 v1.2 marks it as not used.")
    if _first_bytes(root_map.get(0x93)) is not None:
        warnings.append("Highest SVN is present, but SGP.32 v1.2 marks it as not used.")

    iot_value = _first_bytes(root_map.get(0xB4))
    if iot_value is not None:
        iot_map = parse_tlv_simple(iot_value)
        if _first_bytes(iot_map.get(0xA0)) is None:
            warnings.append("IoT Specific Info is present, but IoT Version List is missing.")
        if 0x81 not in iot_map:
            warnings.append("IoT Specific Info is present, but eCall Supported flag is missing.")

    status = "PASS"
    if len(warnings) > 0:
        status = "WARN"
    validation.append((0, "SGP.32 Validation", status))

    if len(warnings) == 0:
        validation.append((1, "Mandatory Fields", "All required SGP.32 v1.2 fields are present."))
    else:
        warning_index = 1
        for warning_text in warnings:
            validation.append((1, f"Warning {warning_index}", warning_text))
            warning_index += 1
    return validation


def format_version_bytes(value: bytes) -> str:
    hex_text = value.hex().upper()
    if len(value) != 3:
        return hex_text
    return f"v{value[0]}.{value[1]}.{value[2]} ({hex_text})"


def decode_euicc_category(value: bytes) -> str:
    if len(value) != 1:
        return value.hex().upper()
    categories = {
        0: "other",
        1: "basicEuicc",
        2: "mediumEuicc",
        3: "contactlessEuicc",
    }
    category_value = value[0]
    category_name = categories.get(category_value, "unknown")
    return f"{category_name} ({category_value})"


def decode_ipa_mode(value: bytes) -> str:
    if len(value) != 1:
        return value.hex().upper()
    ipa_modes = {
        0: "ipad (IPAd is active)",
        1: "ipae (IPAe is active)",
    }
    ipa_value = value[0]
    ipa_name = ipa_modes.get(ipa_value, "unknown")
    return f"{ipa_name} ({ipa_value})"


def format_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> str:
    hex_text = value.hex().upper()
    bit_details = decode_named_bit_string(value, bit_names)
    if len(bit_details) == 0:
        return f"{hex_text} (set: none)"
    return f"{hex_text} (set: {', '.join(bit_details)})"


def decode_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> List[str]:
    if len(value) == 0:
        return []
    unused_bits = value[0]
    payload = value[1:]
    if len(payload) == 0:
        return []

    results: List[str] = []
    total_bits = (len(payload) * 8) - unused_bits
    bit_index = 0
    while bit_index < total_bits:
        byte_index = bit_index // 8
        mask = 1 << (7 - (bit_index % 8))
        if payload[byte_index] & mask:
            results.append(bit_names.get(bit_index, f"bit{bit_index}"))
        bit_index += 1
    return results


def decode_ext_card_resource_value(tag: int, value: bytes) -> Optional[str]:
    if tag == 0x81:
        return str(int.from_bytes(value, "big", signed=False))
    if tag in (0x82, 0x83):
        byte_count = int.from_bytes(value, "big", signed=False)
        if byte_count < 1024:
            return f"{byte_count} B"
        return f"{byte_count / 1024:.1f} KB"
    return None


def quote_text(value: bytes) -> str:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    return f"\"{decoded}\""


def _build_root_detail_lines(tag: int, label: str, value: bytes) -> List[Tuple[int, str, str]]:
    lines: List[Tuple[int, str, str]] = []
    rendered = decode_euicc_info2_value(tag, value, 0xBF22)
    if rendered is not None and tag not in (0x84, 0xA9, 0xAA, 0xAF, 0xB4, 0xAC):
        lines.append((0, label, rendered))
        return lines

    if tag == 0x84:
        lines.append((0, label, value.hex().upper()))
        nested_map = parse_tlv_simple(value)
        for child_tag in (0x81, 0x82, 0x83):
            child_value = _first_bytes(nested_map.get(child_tag))
            if child_value is None:
                continue
            child_label = resolve_euicc_info2_tag_name(child_tag, 0x84) or f"{child_tag:02X}"
            child_rendered = decode_euicc_info2_value(child_tag, child_value, 0x84)
            if child_rendered is None:
                child_rendered = child_value.hex().upper()
            lines.append((1, child_label, child_rendered))
        return lines

    if tag in (0xA9, 0xAA):
        child_nodes = parse_tlv_nodes(value)
        lines.append((0, label, f"{len(child_nodes)} item(s)"))
        item_index = 1
        for child_tag, child_value, _constructed in child_nodes:
            child_label = resolve_euicc_info2_tag_name(child_tag, tag) or f"{child_tag:02X}"
            child_rendered = decode_euicc_info2_value(child_tag, child_value, tag)
            if child_rendered is None:
                child_rendered = child_value.hex().upper()
            lines.append((1, f"{child_label} {item_index}", child_rendered))
            item_index += 1
        return lines

    if tag == 0xAF:
        child_nodes = parse_tlv_nodes(value)
        if len(child_nodes) == 0:
            lines.append((0, label, value.hex().upper()))
            return lines
        lines.append((0, label, f"{len(child_nodes)} item(s)"))
        item_index = 1
        for child_tag, child_value, _constructed in child_nodes:
            child_label = resolve_euicc_info2_tag_name(child_tag, tag) or f"{child_tag:02X}"
            child_rendered = decode_euicc_info2_value(child_tag, child_value, tag)
            if child_rendered is None:
                child_rendered = child_value.hex().upper()
            lines.append((1, f"{child_label} {item_index}", child_rendered))
            item_index += 1
        return lines

    if tag == 0xB4:
        lines.append((0, label, "Present"))
        nested_map = parse_tlv_simple(value)
        version_list_value = _first_bytes(nested_map.get(0xA0))
        if version_list_value is not None:
            version_nodes = parse_tlv_nodes(version_list_value)
            version_index = 1
            for child_tag, child_value, _constructed in version_nodes:
                child_label = resolve_euicc_info2_tag_name(child_tag, 0xA0) or f"{child_tag:02X}"
                child_rendered = decode_euicc_info2_value(child_tag, child_value, 0xA0)
                if child_rendered is None:
                    child_rendered = child_value.hex().upper()
                lines.append((1, f"{child_label} {version_index}", child_rendered))
                version_index += 1
        if 0x81 in nested_map:
            lines.append((1, "eCall Supported", "Present"))
        else:
            lines.append((1, "eCall Supported", "Missing"))
        if 0x82 in nested_map:
            lines.append((1, "Fallback Supported", "Present"))
        else:
            lines.append((1, "Fallback Supported", "Absent"))
        return lines

    if tag == 0xAC:
        lines.append((0, label, "Present"))
        child_nodes = parse_tlv_nodes(value)
        string_index = 1
        for child_tag, child_value, _constructed in child_nodes:
            if child_tag != 0x0C:
                lines.append((1, f"{child_tag:02X}", child_value.hex().upper()))
                continue
            label_text = "Platform Label"
            if string_index == 2:
                label_text = "Discovery Base URL"
            lines.append((1, label_text, quote_text(child_value)))
            string_index += 1
        return lines

    if rendered is None:
        lines.append((0, label, value.hex().upper()))
        return lines
    lines.append((0, label, rendered))
    return lines


def _first_bytes(value: object) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, list):
        if len(value) == 0:
            return None
        first_item = value[0]
        if isinstance(first_item, bytes):
            return first_item
    return None


def _read_tag(data: bytes, offset: int) -> Tuple[int, int, bool]:
    if offset >= len(data):
        return 0, offset, False
    first = data[offset]
    tag_value = first
    index = offset + 1
    constructed = (first & 0x20) != 0

    if (first & 0x1F) == 0x1F:
        while index < len(data):
            octet = data[index]
            tag_value = (tag_value << 8) | octet
            index += 1
            if (octet & 0x80) == 0:
                break
    return tag_value, index, constructed


def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        return 0, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if count == 0:
        return 0, 0
    end = offset + 1 + count
    if end > len(data):
        return 0, 0
    return int.from_bytes(data[offset + 1 : end], "big"), 1 + count
