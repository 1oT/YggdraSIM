# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.32 eIM response decoders: EUICCInfo1, GetRAT, GetCerts, and eIM configuration TLV parsers."""
from typing import Any, Dict, List, Optional

from SCP03.logic.euicc_info2 import format_version_bytes
from SCP03.logic.euicc_info2 import parse_tlv_nodes
from SCP03.logic.euicc_info2 import parse_tlv_simple
from SCP03.logic.euicc_info2 import quote_text


NOTIFICATION_EVENT_FLAGS: dict[int, str] = {
    0: "notificationInstall",
    1: "notificationEnable",
    2: "notificationDisable",
    3: "notificationDelete",
}

PPR_FLAGS: dict[int, str] = {
    0: "pprUpdateControl",
    1: "ppr1-disable-not-allowed",
    2: "ppr2-delete-not-allowed",
    3: "ppr3-delete-after-disable",
}

RAT_FLAG_NAMES: dict[int, str] = {
    0: "consentRequired",
}

EIM_SUPPORTED_PROTOCOL_FLAGS: dict[int, str] = {
    0: "eimRetrieveHttps",
    1: "eimRetrieveCoaps",
    2: "eimInjectHttps",
    3: "eimInjectCoaps",
    4: "eimProprietary",
}

GET_CERTS_ERROR_NAMES: dict[int, str] = {
    1: "invalidCiPKId",
    127: "undefinedError",
}

NOTIFICATIONS_ERROR_NAMES: dict[int, str] = {
    127: "undefinedError",
}

_MAX_TLV_WALK_DEPTH = 32


def decode_euicc_info1_summary(response: bytes) -> Dict[str, Any]:
    """Decode an EUICCInfo1 TLV response into a summary dict (SGP.32 §6.3.3)."""
    summary: Dict[str, Any] = {}
    root_value = unwrap_root_tag(response, 0xBF20)
    if root_value is None:
        return summary

    root_map = parse_tlv_simple(root_value)
    svn_value = first_bytes(root_map.get(0x82))
    if svn_value is not None:
        summary["svn"] = format_version_bytes(svn_value)

    verify_items = count_child_tag(root_map.get(0xA9), 0x04)
    sign_items = count_child_tag(root_map.get(0xAA), 0x04)
    summary["ci_pk_verify_entries"] = verify_items
    summary["ci_pk_sign_entries"] = sign_items
    return summary


def decode_notifications_response(response: bytes) -> Dict[str, Any]:
    """Decode a ListNotifications response body into a list of notification dicts (SGP.32 §5.6.2)."""
    result: Dict[str, Any] = {
        "notifications": [],
        "package_results": [],
        "error": "",
    }
    root_value = unwrap_root_tag(response, 0xBF2B)
    if root_value is None:
        return result

    root_nodes = parse_tlv_nodes(root_value)
    for tag, value, _constructed in root_nodes:
        if tag == 0x81:
            error_value = decode_integer(value)
            error_name = NOTIFICATIONS_ERROR_NAMES.get(error_value, str(error_value))
            result["error"] = error_name
            continue
        if tag == 0xA0:
            notifications = collect_nested_tag_values(value, 0xBF2F)
            for item in notifications:
                result["notifications"].append(decode_notification_entry(item))
            continue
        if tag == 0xA2:
            result["package_results"] = collect_nested_tag_values(value, 0xBF31)
            if len(result["package_results"]) == 0:
                result["package_results"] = collect_nested_tag_values(value, 0xBF32)
            if len(result["package_results"]) == 0:
                result["package_results"] = collect_nested_tag_values(value, 0xBF33)
            if len(result["package_results"]) == 0:
                result["package_results"] = [value]
    return result


def decode_notification_entry(value: bytes) -> Dict[str, str]:
    """Decode a single NotificationEntry TLV into a structured dict."""
    entry_map = parse_tlv_simple(value)
    entry: Dict[str, str] = {}
    seq_value = first_bytes(entry_map.get(0x80))
    if seq_value is not None:
        entry["seqNumber"] = str(decode_integer(seq_value))
    op_value = first_bytes(entry_map.get(0x81))
    if op_value is not None:
        entry["operation"] = format_named_bit_string(op_value, NOTIFICATION_EVENT_FLAGS)
    address_value = first_bytes(entry_map.get(0x0C))
    if address_value is not None:
        entry["notificationAddress"] = quote_text(address_value)
    iccid_value = first_bytes(entry_map.get(0x5A))
    if iccid_value is not None:
        entry["iccid"] = decode_bcd_digits(iccid_value)
    return entry


def decode_rat_rules(response: bytes) -> List[Dict[str, Any]]:
    """Decode a GetRulesAuthorizationTable response into a list of RAT-rule dicts (SGP.22 §5.7.16)."""
    root_value = unwrap_root_tag(response, 0xBF43)
    if root_value is None:
        return []

    rules: List[Dict[str, Any]] = []
    seen_fingerprints: set[str] = set()

    def looks_like_rule(nodes: List[tuple[int, bytes, bool]]) -> bool:
        immediate = {tag: value for tag, value, _constructed in nodes}
        ppr_ids = immediate.get(0x80)
        if ppr_ids is None or not any(tag in immediate for tag in (0xA1, 0x82)):
            return False
        try:
            decode_named_bit_string(ppr_ids, PPR_FLAGS)
            flags = immediate.get(0x82)
            if flags is not None:
                decode_named_bit_string(flags, RAT_FLAG_NAMES)
        except ValueError:
            return False
        return True

    def walk(node_bytes: bytes, depth: int = 0) -> None:
        """Depth-first walk of RAT rule permission TLVs; appends decoded dicts to the outer list."""
        if depth > _MAX_TLV_WALK_DEPTH:
            raise ValueError(
                f"RAT rule TLV nesting exceeds {_MAX_TLV_WALK_DEPTH} levels."
            )
        nodes = parse_tlv_nodes(node_bytes)
        if len(nodes) == 0:
            return

        if looks_like_rule(nodes):
            fingerprint = node_bytes.hex().upper()
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                rules.append(decode_rat_rule(node_bytes))

        for _tag, value, constructed in nodes:
            if constructed:
                walk(value, depth + 1)

    walk(root_value)
    return rules


def decode_rat_rule(value: bytes) -> Dict[str, Any]:
    """Decode a single RAT rule TLV block into a human-readable dict."""
    rule_map = parse_tlv_simple(value)
    rule: Dict[str, Any] = {}
    ppr_ids_value = first_bytes(rule_map.get(0x80))
    if ppr_ids_value is not None:
        rule["pprIdsRaw"] = ppr_ids_value.hex().upper()
        rule["pprIds"] = format_named_bit_string(ppr_ids_value, PPR_FLAGS)

    allowed_operators_value = first_bytes(rule_map.get(0xA1))
    operators: List[Dict[str, str]] = []
    if allowed_operators_value is not None:
        for tag, operator_value, _ in parse_tlv_nodes(allowed_operators_value):
            if tag != 0x30:
                continue
            operator_map = parse_tlv_simple(operator_value)
            operator: Dict[str, str] = {}
            mcc_mnc_value = first_bytes(operator_map.get(0x80))
            if mcc_mnc_value is not None:
                operator["mccMnc"] = decode_bcd_digits(mcc_mnc_value)
            gid1_value = first_bytes(operator_map.get(0x81))
            if gid1_value is not None:
                operator["gid1"] = gid1_value.hex().upper()
            gid2_value = first_bytes(operator_map.get(0x82))
            if gid2_value is not None:
                operator["gid2"] = gid2_value.hex().upper()
            operators.append(operator)
    if len(operators) > 0:
        rule["allowedOperators"] = operators

    flags_value = first_bytes(rule_map.get(0x82))
    if flags_value is not None:
        rule["pprFlagsRaw"] = flags_value.hex().upper()
        rule["pprFlags"] = format_named_bit_string(flags_value, RAT_FLAG_NAMES)
    return rule


def decode_eim_configuration_entries(response: bytes) -> List[Dict[str, Any]]:
    """Decode a GetEimConfigurationData response into a list of eIM config entry dicts (SGP.32 §6.3.8)."""
    root_value = unwrap_root_tag(response, 0xBF55)
    if root_value is None:
        return []

    # GetEimConfigurationDataResponse ::= [85] SEQUENCE {
    #   eimConfigurationDataList [0] SEQUENCE OF EimConfigurationData
    # }
    # Decode that shape directly. A heuristic recursive walk used to descend
    # into A5/A6 certificate choices and could mistake DER internals for
    # another eIM entry; it also dropped a valid minimal entry containing only
    # its mandatory eimId.
    root_nodes = parse_tlv_nodes(root_value)
    list_nodes = [value for tag, value, _constructed in root_nodes if tag == 0xA0]
    if not list_nodes:
        return []

    entries: List[Dict[str, Any]] = []
    for list_value in list_nodes:
        for tag, value, constructed in parse_tlv_nodes(list_value):
            if tag != 0x30 or not constructed:
                continue
            entry_map = parse_tlv_simple(value)
            if first_bytes(entry_map.get(0x80)) is None:
                continue
            entries.append(decode_eim_configuration_entry(value))
    return entries


def decode_eim_configuration_entry(value: bytes) -> Dict[str, Any]:
    """Decode a single eIM configuration entry TLV into a structured dict."""
    entry_map = parse_tlv_simple(value)
    entry: Dict[str, Any] = {}

    eim_id_value = first_bytes(entry_map.get(0x80))
    if eim_id_value is not None:
        entry["eim_id"] = decode_text_or_hex(eim_id_value)

    eim_fqdn_value = first_bytes(entry_map.get(0x81))
    if eim_fqdn_value is not None:
        entry["eim_fqdn"] = decode_text_or_hex(eim_fqdn_value)

    eim_id_type_value = first_bytes(entry_map.get(0x82))
    if eim_id_type_value is not None:
        id_type = decode_integer(eim_id_type_value)
        id_type_names = {
            1: "eimIdTypeOid",
            2: "eimIdTypeFqdn",
            3: "eimIdTypeProprietary",
        }
        entry["eim_id_type"] = f"{id_type_names.get(id_type, 'unknown')} ({id_type})"

    counter_value = first_bytes(entry_map.get(0x83))
    if counter_value is not None:
        entry["counter_value"] = str(decode_integer(counter_value))

    association_token = first_bytes(entry_map.get(0x84))
    if association_token is not None:
        entry["association_token"] = str(decode_integer(association_token))

    supported_protocol = first_bytes(entry_map.get(0x87))
    if supported_protocol is not None:
        entry["supported_protocol"] = format_named_bit_string(
            supported_protocol,
            EIM_SUPPORTED_PROTOCOL_FLAGS,
        )

    euicc_ci_pkid = first_bytes(entry_map.get(0x88))
    if euicc_ci_pkid is not None:
        entry["euicc_ci_pkid"] = euicc_ci_pkid.hex().upper()

    if 0x89 in entry_map:
        entry["indirect_profile_download"] = "Present"

    eim_pub = first_bytes(entry_map.get(0xA5))
    if eim_pub is not None:
        entry["eim_public_key_data"] = eim_pub

    tls_pub = first_bytes(entry_map.get(0xA6))
    if tls_pub is not None:
        entry["trusted_tls_public_key_data"] = tls_pub

    return entry


def decode_get_certs_response(response: bytes) -> Dict[str, Any]:
    """Decode a GetCertsResponse TLV into a dict keyed by certificate role (SGP.32 §6.3.6)."""
    root_value = unwrap_root_tag(response, 0xBF56)
    if root_value is None:
        return {}

    result: Dict[str, Any] = {}
    root_nodes = parse_tlv_nodes(root_value)
    if len(root_nodes) == 1 and root_nodes[0][0] == 0x81:
        error_code = decode_integer(root_nodes[0][1])
        result["error"] = GET_CERTS_ERROR_NAMES.get(error_code, str(error_code))
        return result

    eum_values = collect_nested_tag_values(root_value, 0xA5)
    if len(eum_values) > 0:
        result["eumCertificate"] = eum_values[0]

    euicc_values = collect_nested_tag_values(root_value, 0xA6)
    if len(euicc_values) > 0:
        result["euiccCertificate"] = euicc_values[0]
    return result


def unwrap_root_tag(data: bytes, root_tag: int) -> Optional[bytes]:
    """Strip an expected outer root tag from *data* and return the payload, raising on mismatch."""
    nodes = parse_tlv_nodes(data)
    if len(nodes) == 1 and nodes[0][0] == root_tag:
        return nodes[0][1]
    if len(nodes) == 0 and root_tag == 0:
        return data
    return None


def decode_integer(value: bytes) -> int:
    if len(value) == 0:
        return 0
    return int.from_bytes(value, "big", signed=False)


def decode_text_or_hex(value: bytes) -> str:
    """Return the UTF-8 text of a BER-TLV value, falling back to hex if decoding fails."""
    if len(value) == 0:
        return ""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    if text.isprintable():
        return text
    return value.hex().upper()


def decode_bcd_digits(value: bytes) -> str:
    """Decode BCD-encoded bytes to a digit string (3GPP TS 24.008 §10.5.1.3)."""
    digits: List[str] = []
    for index, byte_value in enumerate(value):
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        # TBCD filler is permitted only in the high nibble of the final
        # octet. Accepting a low-nibble F used to append the literal string
        # "15", producing a plausible but incorrect ICCID/MCC-MNC.
        if low > 9:
            return value.hex().upper()
        if high == 0x0F:
            if index != len(value) - 1:
                return value.hex().upper()
        elif high > 9:
            return value.hex().upper()
        digits.append(str(low))
        if high != 0x0F:
            digits.append(str(high))
    return "".join(digits)


def format_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> str:
    """Format a named-bit-string value as a comma-separated list of set bit names."""
    if len(value) == 0:
        return "none"
    labels = decode_named_bit_string(value, bit_names)
    hex_text = value.hex().upper()
    if len(labels) == 0:
        return f"{hex_text} (set: none)"
    return f"{hex_text} (set: {', '.join(labels)})"


def decode_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> List[str]:
    """Decode a named-bit-string BER value and return a list of set bit names."""
    if len(value) == 0:
        return []
    unused_bits = value[0]
    payload = value[1:]
    if unused_bits > 7:
        raise ValueError("BIT STRING unused-bit count must be in range 0..7.")
    if len(payload) == 0:
        if unused_bits != 0:
            raise ValueError("Empty BIT STRING payload must have zero unused bits.")
        return []
    if unused_bits and payload[-1] & ((1 << unused_bits) - 1):
        raise ValueError("BIT STRING contains non-zero padding bits.")
    labels: List[str] = []
    bit_index = 0
    for byte_index, byte_value in enumerate(payload):
        for mask_bit in range(7, -1, -1):
            if byte_index == len(payload) - 1 and mask_bit < unused_bits:
                continue
            if ((byte_value >> mask_bit) & 0x01) == 0x01:
                labels.append(bit_names.get(bit_index, f"bit{bit_index}"))
            bit_index += 1
    return labels


def first_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, list) and len(value) > 0 and isinstance(value[0], bytes):
        return value[0]
    return None


def count_child_tag(value: Any, child_tag: int) -> int:
    """Count occurrences of *tag* as direct children of *container_bytes*."""
    blob = first_bytes(value)
    if blob is None:
        return 0
    count = 0
    for tag, _child_value, _constructed in parse_tlv_nodes(blob):
        if tag == child_tag:
            count += 1
    return count


def collect_nested_tag_values(data: bytes, wanted_tag: int) -> List[bytes]:
    """Recursively collect all values of *tag* found anywhere within *container_bytes*."""
    values: List[bytes] = []

    def walk(node_bytes: bytes, depth: int = 0) -> None:
        if depth > _MAX_TLV_WALK_DEPTH:
            raise ValueError(
                f"TLV nesting exceeds {_MAX_TLV_WALK_DEPTH} levels."
            )
        for tag, value, constructed in parse_tlv_nodes(node_bytes):
            if tag == wanted_tag:
                values.append(value)
                # Certificate/public-key containers are opaque at this layer.
                # Recursing into their DER payload can reinterpret arbitrary
                # certificate bytes as sibling TLVs.
                continue
            if tag in (0xA5, 0xA6):
                # These SGP.32 choices carry opaque certificate/public-key
                # encodings even though their context tag is constructed.
                continue
            if constructed:
                walk(value, depth + 1)

    walk(data)
    return values
