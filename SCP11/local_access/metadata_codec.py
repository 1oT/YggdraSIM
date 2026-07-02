# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
StoreMetadataRequest codec for local profile metadata.

ASN.1 (SGP.22/GSMA): StoreMetadataRequest ::= [37] SEQUENCE { -- Tag 'BF25'
  iccid Iccid,
  serviceProviderName [17] UTF8String (SIZE(0..32)),   -- Tag '91'
  profileName [18] UTF8String (SIZE(0..64)),          -- Tag '92' (Short Description SGP.21)
  iconType [19] IconType OPTIONAL,                     -- Tag '93' (JPG or PNG)
  icon [20] OCTET STRING (SIZE(0..1024)) OPTIONAL,    -- Tag '94' (only if iconType present)
  profileClass [21] ProfileClass DEFAULT operational,  -- Tag '95'
  notificationConfigurationInfo [22] SEQUENCE OF NotificationConfigurationInformation OPTIONAL,
  profileOwner [23] OperatorId OPTIONAL,               -- Tag 'B7'
  profilePolicyRules [25] PprIds OPTIONAL,             -- Tag '99'
  serviceSpecificDataStoredInEuicc [34] VendorSpecificExtension OPTIONAL,
  serviceSpecificDataNotStoredInEuicc [35] VendorSpecificExtension OPTIONAL,
  ...
}
NotificationEvent ::= BIT STRING {
  notificationInstall(0), notificationLocalEnable(1), notificationLocalDisable(2),
  notificationLocalDelete(3), notificationRpmEnable(4), notificationRpmDisable(5),
  notificationRpmDelete(6), loadRpmPackageResult(7)
}
NotificationConfigurationInformation ::= SEQUENCE {
  profileManagementOperation NotificationEvent,
  notificationAddress UTF8String
}
"""
import json
from typing import Any

try:
    from ..shared.pysim_support import encode_rsp_type
except ImportError:
    from SCP11.shared.pysim_support import encode_rsp_type


SERVICE_PROVIDER_NAME_MAX = 32
PROFILE_NAME_MAX = 64
ICON_MAX_OCTETS = 1024

PROFILE_CLASS_MAP = {
    "TEST": 0,
    "TESTING": 0,
    "PROV": 1,
    "PROVISIONING": 1,
    "OPER": 2,
    "OPERATIONAL": 2,
}

ICON_TYPE_MAP = {
    "NONE": 0,
    "JPEG": 1,
    "JPG": 1,
    "PNG": 2,
}

# NotificationEvent bit order per ASN.1: (0)=install, (1)=localEnable, (2)=localDisable,
# (3)=localDelete, (4)=rpmEnable, (5)=rpmDisable, (6)=rpmDelete, (7)=loadRpmPackageResult
NOTIFICATION_EVENT_ORDER = [
    "install",           # notificationInstall(0)
    "enable",            # notificationLocalEnable(1) -- alias local_enable
    "disable",           # notificationLocalDisable(2)
    "delete",            # notificationLocalDelete(3)
    "rpm_enable",        # notificationRpmEnable(4)
    "rpm_disable",       # notificationRpmDisable(5)
    "rpm_delete",        # notificationRpmDelete(6)
    "load_rpm_package_result",  # loadRpmPackageResult(7)
]

PROFILE_POLICY_RULE_ORDER = [
    "update_control_forbidden",
    "disable_not_allowed",
    "delete_not_allowed",
]


def load_metadata_json_document(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if isinstance(document, dict) is False:
        raise ValueError("Metadata JSON root must be an object.")
    return document


def collect_enabled_custom_metadata_tags(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of custom metadata tag names that are marked enabled in the metadata JSON."""
    custom_root = document.get("custom")
    if custom_root is None:
        return []
    if isinstance(custom_root, dict) is False:
        raise ValueError("Metadata field custom must be a JSON object.")

    matches: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], path_parts: list[str]) -> None:
        """Walk the metadata document tree and yield (path, value) tuples."""
        for key, value in node.items():
            if isinstance(value, dict):
                if _is_tag_entry(key, value):
                    include = _bool_value(value.get("include"))
                    if include is False:
                        continue
                    value_hex = _normalize_compact_string(value.get("value_hex"))
                    if len(value_hex) == 0:
                        raise ValueError(
                            f"custom tag {key} is enabled but value_hex is empty "
                            f"at custom.{'.'.join(path_parts + [key])}"
                        )
                    if _is_hex_string(value_hex) is False:
                        raise ValueError(
                            f"custom tag {key} has non-hex value_hex at "
                            f"custom.{'.'.join(path_parts + [key])}"
                        )
                    if len(value_hex) % 2 != 0:
                        raise ValueError(
                            f"custom tag {key} has odd-length value_hex at "
                            f"custom.{'.'.join(path_parts + [key])}"
                        )
                    matches.append(
                        {
                            "tag_hex": key.upper(),
                            "value_hex": value_hex.upper(),
                            "path": ".".join(path_parts + [key]),
                        }
                    )
                    continue
                walk(value, path_parts + [key])

    walk(custom_root, [])
    return matches


def encode_store_metadata_request_from_file(path: str) -> bytes:
    document = load_metadata_json_document(path)
    return encode_store_metadata_request(document)


def encode_store_metadata_request(document: dict[str, Any]) -> bytes:
    payload = build_store_metadata_request_payload(document)
    encoded = encode_rsp_type("StoreMetadataRequest", payload)
    if len(encoded) == 0:
        raise RuntimeError("pySIM ASN.1 encoder is not available for StoreMetadataRequest.")
    return encoded


def encode_update_metadata_request_from_file(path: str) -> bytes:
    document = load_metadata_json_document(path)
    return encode_update_metadata_request(document)


def encode_update_metadata_request(document: dict[str, Any]) -> bytes:
    payload = build_update_metadata_request_payload(document)
    encoded = encode_rsp_type("UpdateMetadataRequest", payload)
    if len(encoded) == 0:
        raise RuntimeError("pySIM ASN.1 encoder is not available for UpdateMetadataRequest.")
    return encoded


def build_store_metadata_request_payload(document: dict[str, Any]) -> dict[str, Any]:
    """Build a StoreMetadata ES2+ request payload from a metadata JSON document."""
    profile = _require_mapping(document, "profile")
    operator = _require_mapping(document, "operator")
    policy_rules = _optional_mapping(document.get("policy_rules"))
    notification_events = _optional_mapping(document.get("notification_events"))
    icon = _optional_mapping(profile.get("icon"))

    service_provider_name = _string_value(operator.get("name"))
    if len(service_provider_name) == 0:
        raise ValueError("Metadata field operator.name must not be empty.")
    if len(service_provider_name) > SERVICE_PROVIDER_NAME_MAX:
        raise ValueError(
            f"serviceProviderName exceeds SIZE(0..{SERVICE_PROVIDER_NAME_MAX}): {len(service_provider_name)}"
        )

    profile_name = _string_value(profile.get("name"))
    if len(profile_name) == 0:
        profile_name = _string_value(profile.get("profile_type"))
    if len(profile_name) == 0:
        raise ValueError("Metadata field profile.name or profile.profile_type must not be empty.")
    if len(profile_name) > PROFILE_NAME_MAX:
        raise ValueError(
            f"profileName exceeds SIZE(0..{PROFILE_NAME_MAX}): {len(profile_name)}"
        )

    notification_address = _string_value(notification_events.get("address"))
    notification_bits = _bitstring_from_named_flags(notification_events, NOTIFICATION_EVENT_ORDER)
    notification_configuration = []
    if _bitstring_has_payload(notification_bits) or len(notification_address) > 0:
        notification_configuration.append(
            {
                "profileManagementOperation": notification_bits,
                "notificationAddress": notification_address,
            }
        )

    owner = {
        "mccMnc": _encode_mcc_mnc(operator.get("mcc"), operator.get("mnc")),
        "gid1": _encode_octet_string(operator.get("gid1")),
        "gid2": _encode_octet_string(operator.get("gid2")),
    }

    icon_type = _encode_icon_type(icon.get("type"))
    icon_bytes = _encode_octet_string(icon.get("data_hex"))
    if len(icon_bytes) > ICON_MAX_OCTETS:
        raise ValueError(
            f"icon exceeds OCTET STRING SIZE(0..{ICON_MAX_OCTETS}): {len(icon_bytes)}"
        )

    payload = {
        "iccid": _encode_iccid(profile.get("iccid")),
        "serviceProviderName": service_provider_name,
        "profileName": profile_name,
        "iconType": icon_type,
        "icon": icon_bytes,
        "profileClass": _encode_profile_class(profile.get("profile_class")),
        "notificationConfigurationInfo": notification_configuration,
        "profileOwner": owner,
        "profilePolicyRules": _bitstring_from_named_flags(
            policy_rules,
            PROFILE_POLICY_RULE_ORDER,
        ),
    }
    return payload


def build_update_metadata_request_payload(document: dict[str, Any]) -> dict[str, Any]:
    """Build an UpdateMetadata ES2+ request payload from a partial metadata JSON document."""
    profile = _optional_mapping(document.get("profile"))
    operator = _optional_mapping(document.get("operator"))
    policy_rules = _optional_mapping(document.get("policy_rules"))
    icon = _optional_mapping(profile.get("icon"))

    payload: dict[str, Any] = {}

    if "name" in operator:
        service_provider_name = _string_value(operator.get("name"))
        if len(service_provider_name) > SERVICE_PROVIDER_NAME_MAX:
            raise ValueError(
                f"serviceProviderName exceeds SIZE(0..{SERVICE_PROVIDER_NAME_MAX}): {len(service_provider_name)}"
            )
        payload["serviceProviderName"] = service_provider_name

    if "name" in profile or "profile_type" in profile:
        profile_name = _string_value(profile.get("name"))
        if len(profile_name) == 0 and "profile_type" in profile:
            profile_name = _string_value(profile.get("profile_type"))
        if len(profile_name) > PROFILE_NAME_MAX:
            raise ValueError(
                f"profileName exceeds SIZE(0..{PROFILE_NAME_MAX}): {len(profile_name)}"
            )
        payload["profileName"] = profile_name

    if "type" in icon:
        payload["iconType"] = _encode_icon_type(icon.get("type"))

    if "data_hex" in icon:
        icon_bytes = _encode_octet_string(icon.get("data_hex"))
        if len(icon_bytes) > ICON_MAX_OCTETS:
            raise ValueError(
                f"icon exceeds OCTET STRING SIZE(0..{ICON_MAX_OCTETS}): {len(icon_bytes)}"
            )
        payload["icon"] = icon_bytes

    if "policy_rules" in document:
        payload["profilePolicyRules"] = _bitstring_from_named_flags(
            policy_rules,
            PROFILE_POLICY_RULE_ORDER,
        )

    if len(payload) == 0:
        raise ValueError(
            "UpdateMetadata JSON did not project any ASN.1 fields. "
            "Provide at least one of operator.name, profile.name/profile.profile_type, "
            "profile.icon.type, profile.icon.data_hex, or policy_rules."
        )

    return payload


def _require_mapping(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if isinstance(value, dict) is False:
        raise ValueError(f"Metadata field {key} must be an object.")
    return value


def _optional_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict) is False:
        raise ValueError("Expected a JSON object for a metadata mapping field.")
    return value


def _is_tag_entry(key: str, value: dict[str, Any]) -> bool:
    if _looks_like_tag_hex(key) is False:
        return False
    if "include" not in value:
        return False
    if "value_hex" not in value:
        return False
    return True


def _looks_like_tag_hex(value: str) -> bool:
    compact = _normalize_compact_string(value)
    if len(compact) < 2:
        return False
    if len(compact) % 2 != 0:
        return False
    if _is_hex_string(compact) is False:
        return False
    return True


def _string_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _encode_profile_class(value: Any) -> int:
    if isinstance(value, int):
        return value
    normalized = _string_value(value).upper()
    if normalized in PROFILE_CLASS_MAP:
        return PROFILE_CLASS_MAP[normalized]
    raise ValueError(f"Unsupported profile class: {value}")


def _encode_icon_type(value: Any) -> int:
    if value is None:
        return ICON_TYPE_MAP["NONE"]
    if isinstance(value, int):
        return value
    normalized = _string_value(value).upper()
    if len(normalized) == 0:
        return ICON_TYPE_MAP["NONE"]
    if normalized in ICON_TYPE_MAP:
        return ICON_TYPE_MAP[normalized]
    raise ValueError(f"Unsupported icon type: {value}")


def _encode_iccid(value: Any) -> bytes:
    normalized = _normalize_compact_string(value)
    if len(normalized) == 0:
        raise ValueError("Metadata field profile.iccid must not be empty.")
    if _is_hex_string(normalized) is False:
        raise ValueError("Metadata field profile.iccid must contain hexadecimal-compatible digits.")
    if len(normalized) % 2 != 0:
        normalized = normalized + "F"
    return bytes.fromhex(normalized)


def _encode_mcc_mnc(mcc: Any, mnc: Any) -> bytes:
    mcc_text = _normalize_compact_string(mcc)
    mnc_text = _normalize_compact_string(mnc)
    if len(mcc_text) == 0 and len(mnc_text) == 0:
        return b""
    if len(mcc_text) == 0 or len(mnc_text) == 0:
        raise ValueError("Metadata operator.mcc and operator.mnc must either both be set or both be empty.")
    combined = mcc_text + mnc_text
    if _is_hex_string(combined) is False:
        raise ValueError("Metadata operator.mcc/operator.mnc must be hexadecimal-compatible digits.")
    if len(combined) % 2 != 0:
        combined = combined + "F"
    return bytes.fromhex(combined)


def _encode_octet_string(value: Any) -> bytes:
    normalized = _normalize_compact_string(value)
    if len(normalized) == 0:
        return b""
    if _is_hex_string(normalized):
        if len(normalized) % 2 != 0:
            normalized = normalized + "F"
        return bytes.fromhex(normalized)
    return normalized.encode("utf-8")


def _normalize_compact_string(value: Any) -> str:
    text = _string_value(value)
    return text.replace(" ", "").replace(":", "").replace("-", "").upper()


def _is_hex_string(value: str) -> bool:
    if len(value) == 0:
        return False
    for char in value:
        if char not in "0123456789ABCDEF":
            return False
    return True


def _bitstring_from_named_flags(source: dict[str, Any], ordered_names: list[str]) -> tuple[bytes, int]:
    flag_values = []
    for name in ordered_names:
        flag_values.append(_bool_value(source.get(name)))
    return _pack_bitstring(flag_values)


def _pack_bitstring(flag_values: list[bool]) -> tuple[bytes, int]:
    if len(flag_values) == 0:
        return b"", 0

    byte_count = (len(flag_values) + 7) // 8
    encoded = bytearray(byte_count)
    index = 0
    while index < len(flag_values):
        if flag_values[index]:
            byte_index = index // 8
            bit_index = index % 8
            encoded[byte_index] |= 1 << (7 - bit_index)
        index += 1

    unused_bits = (byte_count * 8) - len(flag_values)
    return bytes(encoded), unused_bits


def _bitstring_has_payload(value: tuple[bytes, int]) -> bool:
    data, _unused_bits = value
    for byte_value in data:
        if byte_value != 0:
            return True
    return False


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = _string_value(value).lower()
    if normalized in ("1", "true", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "no", "n", "off", ""):
        return False
    raise ValueError(f"Unsupported boolean value: {value}")
