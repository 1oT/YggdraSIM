# SPDX-License-Identifier: GPL-3.0-or-later
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
  profilePolicyRules [25] PprIds OPTIONAL               -- Tag '99'
}

SGP.22 v3.1 §5.5.3 adds ten more members on top of those nine:
serviceSpecificDataStoredInEuicc [34] 'BF22', serviceSpecificDataNotStoredInEuicc
[35] 'BF23', rpmConfiguration [26] 'BA', hriServerAddress [27] '9B',
lprConfiguration [28] 'BC', enterpriseConfiguration [29] 'BD',
serviceProviderMessage [30] 'BE', serviceDescription [31] '9F1F',
deviceChangeConfiguration [32] 'BF20' and estimatedProfileSize [33] '9F21'.
``build_v3_metadata_members`` emits all ten from the document's ``v3`` block.

They depend on the vendored pySim schema carrying them: ``encode_rsp_type``
compiles ``pysim/pySim/esim/asn1/rsp/rsp.asn``, which upstream still defines at
SGP.22 v2. The extension lives in
``upstream_patches/osmocom-pysim-rsp-v3-metadata/``. Re-apply it after any
pySim update, because asn1tools **silently drops** a payload key the compiled
schema does not define -- the encoder returns the same bytes it would without
the key, raising nothing, so an unpatched tree loses these fields without a
word. ``tests/test_metadata_codec_v3_members.py`` fails closed if that happens.
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
from SCP11.shared.iccid import encode_ef_iccid

try:
    from ..shared.pysim_support import encode_rsp_type, rsp_type_members
except ImportError:
    from SCP11.shared.pysim_support import encode_rsp_type, rsp_type_members


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

# SGP.22 IconType ::= INTEGER {jpg(0), png(1)}. The field is OPTIONAL and
# only meaningful alongside an icon, so "no icon" omits it rather than
# claiming a format.
ICON_TYPE_MAP = {
    "JPEG": 0,
    "JPG": 0,
    "PNG": 1,
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

# ServiceDescription ::= BIT STRING { voice(0), data(1) } (SGP.22 v3.1 §5.5.3).
SERVICE_DESCRIPTION_ORDER = ["voice", "data"]

# RpmType ::= BIT STRING { enable(0), disable(1), delete(2), listProfileInfo(3),
# contactPcmp(4) }. 'Update Metadata' is not a bit -- it is granted by listing
# the updatable data objects in tagList instead.
RPM_TYPE_ORDER = ["enable", "disable", "delete", "list_profile_info", "contact_pcmp"]

# EnterpriseConfiguration.enterpriseRules.enterpriseRuleBits.
ENTERPRISE_RULE_ORDER = [
    "reference_enterprise_rule",
    "priority_enterprise_profile",
    "only_enterprise_profiles_can_be_installed",
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


def _reject_members_the_schema_lacks(type_name: str, payload: dict[str, Any]) -> None:
    """Refuse to encode a member the compiled schema cannot represent.

    asn1tools drops a payload key its schema does not define and returns the
    bytes it would have produced without it, raising nothing. An unpatched
    pySim therefore writes a profile with the field silently missing, and a
    caller that asked for it has no way to tell. The SGP.22 v3.1 members are
    the ones this catches in practice -- upstream defines StoreMetadataRequest
    at v2, and the extension lives in
    ``upstream_patches/osmocom-pysim-rsp-v3-metadata/``.
    """
    defined = rsp_type_members(type_name)
    if len(defined) == 0:
        # Codec unavailable, or the type is not a SEQUENCE. The empty-encoding
        # check below reports the unavailable codec with a clearer message.
        return
    missing = sorted(key for key in payload if key not in defined)
    if len(missing) == 0:
        return
    raise RuntimeError(
        f"The compiled pySim schema defines no {', '.join(missing)} in "
        f"{type_name}, so encoding would drop "
        f"{'them' if len(missing) > 1 else 'it'} without a word. Apply "
        "upstream_patches/osmocom-pysim-rsp-v3-metadata/ to the pySim in use, "
        "or remove the field from the document."
    )


def encode_store_metadata_request_from_file(path: str) -> bytes:
    document = load_metadata_json_document(path)
    return encode_store_metadata_request(document)


def encode_store_metadata_request(document: dict[str, Any]) -> bytes:
    payload = build_store_metadata_request_payload(document)
    _reject_members_the_schema_lacks("StoreMetadataRequest", payload)
    encoded = encode_rsp_type("StoreMetadataRequest", payload)
    if len(encoded) == 0:
        raise RuntimeError("pySIM ASN.1 encoder is not available for StoreMetadataRequest.")
    return encoded


def encode_update_metadata_request_from_file(path: str) -> bytes:
    document = load_metadata_json_document(path)
    return encode_update_metadata_request(document)


def encode_update_metadata_request(document: dict[str, Any]) -> bytes:
    payload = build_update_metadata_request_payload(document)
    _reject_members_the_schema_lacks("UpdateMetadataRequest", payload)
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

    # OperatorId.mccMnc is OCTET STRING (SIZE(3)) (SGP.22 v3.1), so profileOwner
    # is only emitted when the document names a PLMN.
    mcc_mnc = _encode_mcc_mnc(operator.get("mcc"), operator.get("mnc"))
    gid1 = _encode_octet_string(operator.get("gid1"))
    gid2 = _encode_octet_string(operator.get("gid2"))
    owner = None
    if len(mcc_mnc) > 0:
        owner = {"mccMnc": mcc_mnc, "gid1": gid1, "gid2": gid2}
    elif len(gid1) > 0 or len(gid2) > 0:
        raise ValueError(
            "Metadata operator.gid1 / operator.gid2 require operator.mcc and operator.mnc."
        )

    icon_type = _encode_icon_type(icon.get("type"))
    icon_bytes = _encode_octet_string(icon.get("data_hex"))
    if len(icon_bytes) > ICON_MAX_OCTETS:
        raise ValueError(
            f"icon exceeds OCTET STRING SIZE(0..{ICON_MAX_OCTETS}): {len(icon_bytes)}"
        )
    if icon_type is None and len(icon_bytes) > 0:
        raise ValueError("icon.type is required when icon.data_hex is present.")

    payload = {
        "iccid": _encode_iccid(profile.get("iccid")),
        "serviceProviderName": service_provider_name,
        "profileName": profile_name,
        "profileClass": _encode_profile_class(profile.get("profile_class")),
        "notificationConfigurationInfo": notification_configuration,
        "profileOwner": owner,
        "profilePolicyRules": _bitstring_from_named_flags(
            policy_rules,
            PROFILE_POLICY_RULE_ORDER,
        ),
    }
    if icon_type is not None:
        payload["iconType"] = icon_type
        payload["icon"] = icon_bytes
    if owner is None:
        payload.pop("profileOwner", None)
    payload.update(build_v3_metadata_members(document))
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
        update_icon_type = _encode_icon_type(icon.get("type"))
        if update_icon_type is not None:
            payload["iconType"] = update_icon_type

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


def build_v3_metadata_members(document: dict[str, Any]) -> dict[str, Any]:
    """Build the SGP.22 v3.1 §5.5.3 StoreMetadataRequest members from ``v3``.

    Every member is optional, so an absent or empty ``v3`` block yields an
    empty mapping and the request encodes exactly as it did before. Each key
    is omitted rather than sent empty, because an OPTIONAL member present with
    a default-looking value is not the same statement as an absent one.
    """

    section = _optional_mapping(document.get("v3"))
    if len(section) == 0:
        return {}
    members: dict[str, Any] = {}

    hri_address = _string_value(section.get("hri_server_address"))
    if len(hri_address) > 0:
        members["hriServerAddress"] = hri_address

    size = section.get("estimated_profile_size")
    if isinstance(size, bool) is False and isinstance(size, int):
        if size < 0:
            raise ValueError("v3.estimated_profile_size must not be negative.")
        members["estimatedProfileSize"] = size

    description = _optional_mapping(section.get("service_description"))
    if len(description) > 0:
        bits = _bitstring_from_named_flags(description, SERVICE_DESCRIPTION_ORDER)
        members["serviceDescription"] = bits

    message = _optional_mapping(section.get("service_provider_message"))
    message_text = _string_value(message.get("message"))
    if len(message_text) > 0:
        entry: dict[str, Any] = {"message": message_text}
        language = _string_value(message.get("language_tag"))
        # The ASN.1 default is "en"; sending it explicitly says nothing extra.
        if len(language) > 0 and language != "en":
            entry["languageTag"] = language
        members["serviceProviderMessage"] = entry

    lpr = _optional_mapping(section.get("lpr_configuration"))
    pcmp_address = _string_value(lpr.get("pcmp_address"))
    if len(pcmp_address) > 0:
        lpr_entry: dict[str, Any] = {"pcmpAddress": pcmp_address}
        dpi = _string_value(lpr.get("dpi_enable"))
        if len(dpi) > 0:
            lpr_entry["dpiEnable"] = dpi
        if _bool_value(lpr.get("trigger_lpr_on_enable_profile")):
            lpr_entry["triggerLprOnEnableProfile"] = None
        members["lprConfiguration"] = lpr_entry

    enterprise = _optional_mapping(section.get("enterprise_configuration"))
    enterprise_oid = _string_value(enterprise.get("enterprise_oid"))
    enterprise_name = _string_value(enterprise.get("enterprise_name"))
    if len(enterprise_oid) > 0:
        if len(enterprise_name) > 64:
            raise ValueError(
                "v3.enterprise_configuration.enterprise_name exceeds SIZE(0..64)"
            )
        enterprise_entry: dict[str, Any] = {
            "enterpriseOid": enterprise_oid,
            "enterpriseName": enterprise_name,
        }
        rules = _optional_mapping(enterprise.get("enterprise_rules"))
        if len(rules) > 0:
            count = rules.get("number_of_non_enterprise_profiles")
            if isinstance(count, bool) or isinstance(count, int) is False:
                raise ValueError(
                    "v3.enterprise_configuration.enterprise_rules needs an integer "
                    "number_of_non_enterprise_profiles."
                )
            enterprise_entry["enterpriseRules"] = {
                "enterpriseRuleBits": _bitstring_from_named_flags(
                    rules, ENTERPRISE_RULE_ORDER
                ),
                "numberOfNonEnterpriseProfiles": count,
            }
        members["enterpriseConfiguration"] = enterprise_entry

    rpm = _optional_mapping(section.get("rpm_configuration"))
    owner_oid = _string_value(rpm.get("profile_owner_oid"))
    if len(owner_oid) > 0:
        managing: list[dict[str, Any]] = []
        for index, raw in enumerate(rpm.get("managing_dp_list") or []):
            row = _optional_mapping(raw)
            dp_oid = _string_value(row.get("managing_dp_oid"))
            if len(dp_oid) == 0:
                raise ValueError(
                    f"v3.rpm_configuration.managing_dp_list[{index}] needs managing_dp_oid."
                )
            dp_entry: dict[str, Any] = {"managingDpOid": dp_oid}
            rpm_types = _optional_mapping(row.get("rpm_type"))
            if len(rpm_types) > 0:
                dp_entry["rpmType"] = _bitstring_from_named_flags(
                    rpm_types, RPM_TYPE_ORDER
                )
            tag_list = _normalize_compact_string(row.get("tag_list_hex"))
            if len(tag_list) > 0:
                if _is_hex_string(tag_list) is False or len(tag_list) % 2 != 0:
                    raise ValueError(
                        f"v3.rpm_configuration.managing_dp_list[{index}].tag_list_hex "
                        "must be even-length hex."
                    )
                dp_entry["tagList"] = bytes.fromhex(tag_list)
            managing.append(dp_entry)
        rpm_entry: dict[str, Any] = {
            "managingDpList": managing,
            "profileOwnerOid": owner_oid,
        }
        polling = _string_value(rpm.get("polling_address"))
        if len(polling) > 0:
            rpm_entry["pollingAddress"] = polling
        allowed = _normalize_compact_string(rpm.get("allowed_ci_pk_id"))
        if len(allowed) > 0:
            if _is_hex_string(allowed) is False or len(allowed) % 2 != 0:
                raise ValueError(
                    "v3.rpm_configuration.allowed_ci_pk_id must be even-length hex."
                )
            rpm_entry["allowedCiPKId"] = bytes.fromhex(allowed)
        members["rpmConfiguration"] = rpm_entry

    device_change = _optional_mapping(section.get("device_change_configuration"))
    if len(device_change) > 0:
        members["deviceChangeConfiguration"] = _encode_device_change(device_change)

    for key, source in (
        ("serviceSpecificDataStoredInEuicc", "service_specific_data_stored_in_euicc"),
        (
            "serviceSpecificDataNotStoredInEuicc",
            "service_specific_data_not_stored_in_euicc",
        ),
    ):
        entries = _encode_vendor_specific(section.get(source), path=source)
        if len(entries) > 0:
            members[key] = entries

    return members


def _encode_device_change(section: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Encode the DeviceChangeConfiguration CHOICE.

    asn1tools spells a CHOICE as ``(alternative, value)``.
    """

    stored = _optional_mapping(section.get("using_stored_ac"))
    activation_code = _string_value(stored.get("activation_code"))
    if len(activation_code) > 0:
        if len(activation_code) > 255:
            raise ValueError(
                "v3.device_change_configuration.using_stored_ac.activation_code "
                "exceeds SIZE(0..255)"
            )
        entry: dict[str, Any] = {"activationCodeForDc": activation_code}
        if _bool_value(stored.get("delete_old_profile")):
            entry["deleteOldProfile"] = None
        return ("usingStoredAc", entry)

    request = _optional_mapping(section.get("request_to_dp"))
    address = _string_value(request.get("smdp_address"))
    if len(address) == 0:
        raise ValueError(
            "v3.device_change_configuration needs either request_to_dp.smdp_address "
            "or using_stored_ac.activation_code."
        )
    request_entry: dict[str, Any] = {"smdpAddressForDc": address}
    allowed = _normalize_compact_string(request.get("allowed_ci_pk_id"))
    if len(allowed) > 0:
        if _is_hex_string(allowed) is False or len(allowed) % 2 != 0:
            raise ValueError(
                "v3.device_change_configuration.request_to_dp.allowed_ci_pk_id "
                "must be even-length hex."
            )
        request_entry["allowedCiPKId"] = bytes.fromhex(allowed)
    if _bool_value(request.get("eid_required")):
        request_entry["eidRequired"] = None
    if _bool_value(request.get("tac_required")):
        request_entry["tacRequired"] = None
    return ("requestToDp", request_entry)


def _encode_vendor_specific(value: Any, *, path: str) -> list[dict[str, Any]]:
    """Encode a VendorSpecificExtension list.

    ``vendor_data_hex`` is the vendor's own DER, carried verbatim -- the
    published module types it as an open type, so nothing here can validate
    its contents beyond it being well-formed hex.
    """

    if value is None:
        return []
    if isinstance(value, list) is False:
        raise ValueError(f"v3.{path} must be a list.")
    entries: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        row = _optional_mapping(raw)
        oid = _string_value(row.get("vendor_oid"))
        data_hex = _normalize_compact_string(row.get("vendor_data_hex"))
        if len(oid) == 0:
            raise ValueError(f"v3.{path}[{index}] needs vendor_oid.")
        if _is_hex_string(data_hex) is False or len(data_hex) % 2 != 0:
            raise ValueError(
                f"v3.{path}[{index}].vendor_data_hex must be even-length hex."
            )
        entries.append(
            {"vendorOid": oid, "vendorSpecificData": bytes.fromhex(data_hex)}
        )
    return entries


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


def _encode_icon_type(value: Any) -> int | None:
    """Return the IconType integer, or None when no icon type is given."""

    if value is None:
        return None
    if isinstance(value, int):
        return value
    normalized = _string_value(value).upper()
    # "NONE" is what the metadata documents carry for a profile with no
    # icon. IconType has no such member, so it omits the field.
    if len(normalized) == 0 or normalized == "NONE":
        return None
    if normalized in ICON_TYPE_MAP:
        return ICON_TYPE_MAP[normalized]
    raise ValueError(f"Unsupported icon type: {value}")


def _encode_iccid(value: Any) -> bytes:
    """Encode the printed ICCID as the EF_ICCID octets StoreMetadataRequest expects.

    SGP.22 v3.1 defines Iccid as "ICCID as coded in EFiccid" and section 5.5.3
    has the eUICC compare it with EF_ICCID of the Profile, so the digits are
    nibble-swapped and F-padded here (ETSI TS 102 221 v18.4 section 13.2).
    """
    normalized = _normalize_compact_string(value)
    if len(normalized) == 0:
        raise ValueError("Metadata field profile.iccid must not be empty.")
    try:
        return encode_ef_iccid(normalized)
    except ValueError as error:
        raise ValueError(f"Metadata field profile.iccid: {error}") from error


def _encode_mcc_mnc(mcc: Any, mnc: Any) -> bytes:
    """Encode MCC + MNC into the SGP.22 ``OperatorId.mccMnc`` octet string.

    ``mccMnc`` follows 3GPP TS 24.008 10.5.1.3 (BCD, nibble-swapped, with a
    0xF filler for a 2-digit MNC in the high nibble of the second octet):

        octet 1: MCC digit 2 | MCC digit 1
        octet 2: MNC digit 3 (0xF if 2-digit MNC) | MCC digit 3
        octet 3: MNC digit 2 | MNC digit 1

    A previous version concatenated the digits and F-padded the tail
    (001/01 -> 00101F), which is not the TS 24.008 layout: a spec-compliant
    eUICC or LPA would read the wrong PLMN back out.
    """
    mcc_text = _normalize_compact_string(mcc)
    mnc_text = _normalize_compact_string(mnc)
    if len(mcc_text) == 0 and len(mnc_text) == 0:
        return b""
    if len(mcc_text) == 0 or len(mnc_text) == 0:
        raise ValueError("Metadata operator.mcc and operator.mnc must either both be set or both be empty.")
    if len(mcc_text) != 3 or mcc_text.isdigit() is False:
        raise ValueError("Metadata operator.mcc must be exactly 3 decimal digits.")
    if len(mnc_text) not in (2, 3) or mnc_text.isdigit() is False:
        raise ValueError("Metadata operator.mnc must be 2 or 3 decimal digits.")
    mcc_digits = [int(character) for character in mcc_text]
    mnc_digits = [int(character) for character in mnc_text]
    mnc_digit_3 = mnc_digits[2] if len(mnc_digits) == 3 else 0xF
    octet_1 = (mcc_digits[1] << 4) | mcc_digits[0]
    octet_2 = (mnc_digit_3 << 4) | mcc_digits[2]
    octet_3 = (mnc_digits[1] << 4) | mnc_digits[0]
    return bytes((octet_1, octet_2, octet_3))


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

    # asn1tools spells a BIT STRING as (payload, number-of-significant-bits),
    # not (payload, unused-bits) -- it derives the DER unused-bits octet from
    # the former. Returning the latter understated every named bit string:
    # PprIds went out claiming five bits where the type defines three, and a
    # NotificationEvent with all eight flags set collapsed to a zero-length
    # BIT STRING, so the card received no notification configuration at all.
    return bytes(encoded), len(flag_values)


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
