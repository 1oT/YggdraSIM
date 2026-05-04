import json
import os
from typing import Any


def load_eim_package_document(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if isinstance(document, dict) is False:
        raise ValueError("eIM package JSON root must be an object.")
    return document


def lint_eim_package_document(document: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    package_type = _compact_string(document.get("package_type"))
    if len(package_type) == 0:
        errors.append("package_type must be present and non-empty.")

    package_version = _compact_string(document.get("package_version"))
    if len(package_version) == 0:
        warnings.append("package_version is empty.")

    command_tag_hex = ""
    try:
        command_tag_hex = _compact_hex(document.get("command_tag_hex"))
    except ValueError as error:
        errors.append(str(error))
    if len(command_tag_hex) > 0 and len(command_tag_hex) % 2 != 0:
        errors.append("command_tag_hex must contain an even number of hex characters.")

    cert_der_path = _compact_string(document.get("cert_der_path"))
    if len(cert_der_path) > 0 and _path_exists_flexible(cert_der_path) is False:
        warnings.append(f"cert_der_path does not exist yet: {cert_der_path}")

    transaction_id_hex = ""
    try:
        transaction_id_hex = _compact_hex(document.get("transaction_id_hex"))
    except ValueError as error:
        errors.append(str(error))
    if len(transaction_id_hex) > 0 and len(transaction_id_hex) % 2 != 0:
        errors.append("transaction_id_hex must contain an even number of hex characters.")

    matching_id = _compact_string(document.get("matching_id"))
    if len(matching_id) == 0:
        runtime_hints = resolve_package_runtime_hints(document)
        matching_id = _compact_string(runtime_hints.get("matching_id"))
    if len(matching_id) == 0:
        warnings.append("matching_id is empty.")

    tlv_rows = document.get("additional_tlvs", [])
    if tlv_rows is None:
        tlv_rows = []
    if isinstance(tlv_rows, list) is False:
        errors.append("additional_tlvs must be an array when present.")
        tlv_rows = []

    row_count = 0
    for index, row in enumerate(tlv_rows):
        if isinstance(row, dict) is False:
            errors.append(f"additional_tlvs[{index}] must be an object.")
            continue
        tag_hex = ""
        try:
            tag_hex = _compact_hex(row.get("tag_hex"))
        except ValueError as error:
            errors.append(f"additional_tlvs[{index}].tag_hex: {error}")
        value_hex = ""
        try:
            value_hex = _compact_hex(row.get("value_hex"))
        except ValueError as error:
            errors.append(f"additional_tlvs[{index}].value_hex: {error}")
        include = _bool_value(row.get("include"), default=True)
        if include and len(tag_hex) == 0:
            errors.append(f"additional_tlvs[{index}].tag_hex must be non-empty.")
        if include and len(value_hex) == 0:
            errors.append(f"additional_tlvs[{index}].value_hex must be non-empty when include=true.")
        if include and len(value_hex) % 2 != 0:
            errors.append(f"additional_tlvs[{index}].value_hex must be even-length hex.")
        if include:
            row_count += 1

    optional_tags = document.get("optional_tags", {})
    if optional_tags is None:
        optional_tags = {}
    if isinstance(optional_tags, dict) is False:
        errors.append("optional_tags must be an object when present.")
        optional_tags = {}
    optional_enabled_count = 0
    for key, row in optional_tags.items():
        if isinstance(row, dict) is False:
            errors.append(f"optional_tags.{key} must be an object.")
            continue
        include = _bool_value(row.get("include"), default=False)
        if include is False:
            continue
        tag_hex = ""
        value_hex = ""
        try:
            tag_hex = _compact_hex(row.get("tag_hex"))
        except ValueError as error:
            errors.append(f"optional_tags.{key}.tag_hex: {error}")
        try:
            value_hex = _compact_hex(row.get("value_hex"))
        except ValueError as error:
            errors.append(f"optional_tags.{key}.value_hex: {error}")
        if len(tag_hex) == 0:
            errors.append(f"optional_tags.{key}.tag_hex must be non-empty when include=true.")
        if len(value_hex) == 0:
            errors.append(f"optional_tags.{key}.value_hex must be non-empty when include=true.")
        optional_enabled_count += 1

    package_type_lc = package_type.strip().lower()
    if package_type_lc == "add_initial_eim":
        errors.extend(_lint_add_initial_eim_spec(document))
    elif package_type_lc == "add_eim":
        errors.extend(_lint_add_eim_spec(document))
    elif package_type_lc == "get_eim_package":
        errors.extend(_lint_get_eim_package_spec(document))
    elif package_type_lc == "provide_eim_package_result":
        errors.extend(_lint_provide_eim_package_result_spec(document))
    elif package_type_lc in ("ipae_handover", "ipae_download"):
        errors.extend(_lint_ipae_handover_spec(document))
    elif package_type_lc == "eim_package_request":
        errors.extend(_lint_eim_package_request_spec(document))
    elif package_type_lc == "euicc_package_request_eim_configuration_data":
        errors.extend(_lint_euicc_package_request_eim_configuration_data_spec(document))
    elif package_type_lc == "euicc_package_request_ecos":
        errors.extend(_lint_euicc_package_request_ecos_spec(document))
    elif package_type_lc == "euicc_package_request_psmos":
        errors.extend(_lint_euicc_package_request_psmos_spec(document))
    elif package_type_lc == "ipa_euicc_data_request":
        errors.extend(_lint_ipa_euicc_data_request_spec(document))
    elif package_type_lc == "profile_download_trigger_request":
        errors.extend(_lint_profile_download_trigger_request_spec(document))
    elif package_type_lc in ("bound_profile_package", "direct_profile_download"):
        errors.extend(_lint_bound_profile_package_spec(document))
    elif package_type_lc == "euicc_memory_reset":
        errors.extend(_lint_euicc_memory_reset_spec(document))
    elif package_type_lc == "eim_acknowledgements":
        errors.extend(_lint_eim_acknowledgements_spec(document))
    elif package_type_lc == "eim_package_result":
        errors.extend(_lint_eim_package_result_spec(document))
    elif package_type_lc == "euicc_package_result":
        errors.extend(_lint_euicc_package_result_spec(document))
    elif package_type_lc == "ipa_euicc_data_response":
        errors.extend(_lint_ipa_euicc_data_response_spec(document))
    elif package_type_lc == "profile_download_trigger_result":
        errors.extend(_lint_profile_download_trigger_result_spec(document))
    spec_checks = _build_spec_checks(document, package_type_lc)
    spec_passed = 0
    spec_failed = 0
    for check in spec_checks:
        status = str(check.get("status", "")).upper()
        if status == "PASS":
            spec_passed += 1
        elif status == "FAIL":
            spec_failed += 1

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "package_type": package_type,
        "package_version": package_version,
        "matching_id": matching_id,
        "has_transaction_id": len(transaction_id_hex) > 0,
        "additional_tlv_count": row_count,
        "optional_tlv_count": optional_enabled_count,
        "spec_checks": spec_checks,
        "spec_passed": spec_passed,
        "spec_failed": spec_failed,
    }


def encode_additional_tlvs(document: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    rows = document.get("additional_tlvs", [])
    if rows is None:
        return []
    encoded_rows: list[tuple[bytes, bytes]] = []
    for row in rows:
        if isinstance(row, dict) is False:
            continue
        include = _bool_value(row.get("include"), default=True)
        if include is False:
            continue
        tag_hex = _compact_hex(row.get("tag_hex"))
        if len(tag_hex) == 0:
            continue
        value_hex = _compact_hex(row.get("value_hex"))
        if len(value_hex) % 2 != 0:
            raise ValueError(f"additional_tlvs value_hex is odd-length for tag {tag_hex}.")
        encoded_rows.append((bytes.fromhex(tag_hex), bytes.fromhex(value_hex)))
    return encoded_rows


def encode_optional_tlvs(document: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    optional_tags = document.get("optional_tags", {})
    if optional_tags is None:
        return []
    if isinstance(optional_tags, dict) is False:
        raise ValueError("optional_tags must be an object when present.")
    encoded_rows: list[tuple[bytes, bytes]] = []
    for _, row in optional_tags.items():
        if isinstance(row, dict) is False:
            continue
        include = _bool_value(row.get("include"), default=False)
        if include is False:
            continue
        tag_hex = _compact_hex(row.get("tag_hex"))
        value_hex = _compact_hex(row.get("value_hex"))
        if len(tag_hex) == 0:
            raise ValueError("optional_tags include=true requires tag_hex.")
        if len(value_hex) == 0:
            raise ValueError("optional_tags include=true requires value_hex.")
        encoded_rows.append((bytes.fromhex(tag_hex), bytes.fromhex(value_hex)))
    return encoded_rows


def resolve_package_runtime_hints(document: dict[str, Any]) -> dict[str, Any]:
    hints = {
        "cert_der_path": _compact_string(document.get("cert_der_path")),
        "matching_id": _compact_string(document.get("matching_id")),
        "transaction_id_hex": _compact_hex_lenient(document.get("transaction_id_hex")),
        "profile_path": _compact_string(document.get("profile_path")),
        "smdp_address": _compact_string(document.get("smdp_address")),
        "bip_endpoint": _compact_string(document.get("bip_endpoint")),
        "bip_endpoints": _mapping_value(document.get("bip_endpoints")),
    }
    runtime = _mapping_value(document.get("runtime"))
    if isinstance(runtime, dict):
        if len(hints["cert_der_path"]) == 0:
            hints["cert_der_path"] = _compact_string(runtime.get("cert_der_path"))
        if len(hints["matching_id"]) == 0:
            hints["matching_id"] = _compact_string(runtime.get("matching_id"))
        if len(hints["transaction_id_hex"]) == 0:
            hints["transaction_id_hex"] = _compact_hex_lenient(runtime.get("transaction_id_hex"))
        if len(hints["profile_path"]) == 0:
            hints["profile_path"] = _compact_string(runtime.get("profile_path"))
        if len(hints["smdp_address"]) == 0:
            hints["smdp_address"] = _compact_string(runtime.get("smdp_address"))
        if len(hints["bip_endpoint"]) == 0:
            hints["bip_endpoint"] = _compact_string(runtime.get("bip_endpoint"))
        runtime_endpoints = _mapping_value(runtime.get("bip_endpoints"))
        if isinstance(runtime_endpoints, dict) and len(runtime_endpoints) > 0:
            hints["bip_endpoints"] = runtime_endpoints

    sgp32 = _mapping_value(document.get("sgp32"))
    add_initial = _mapping_value(sgp32.get("add_initial_eim_request")) if isinstance(sgp32, dict) else {}
    add_eim = _mapping_value(sgp32.get("add_eim_request")) if isinstance(sgp32, dict) else {}
    candidates = []
    if isinstance(add_initial, dict):
        candidates.append(add_initial)
    if isinstance(add_eim, dict):
        candidates.append(add_eim)
    for candidate in candidates:
        rows = candidate.get("eim_configuration_data_list", [])
        if isinstance(rows, list) is False or len(rows) == 0:
            continue
        first = rows[0]
        if isinstance(first, dict) is False:
            continue
        eim_id_field = _mapping_value(first.get("eim_id"))
        if len(hints["matching_id"]) == 0 and _bool_value(eim_id_field.get("include"), True):
            hints["matching_id"] = _compact_string(eim_id_field.get("value"))
        eim_pk = _mapping_value(first.get("eim_public_key_data"))
        choice = _compact_string(eim_pk.get("choice")).lower()
        if len(hints["cert_der_path"]) == 0 and choice == "eim_certificate":
            hints["cert_der_path"] = _compact_string(eim_pk.get("eim_certificate_der_path"))
        trusted_tls = _mapping_value(first.get("trusted_public_key_data_tls"))
        tls_choice = _compact_string(trusted_tls.get("choice")).lower()
        if len(hints["cert_der_path"]) == 0 and tls_choice == "trusted_certificate_tls":
            hints["cert_der_path"] = _compact_string(trusted_tls.get("trusted_certificate_der_path"))
    get_pkg = _mapping_value(sgp32.get("get_eim_package_request")) if isinstance(sgp32, dict) else {}
    if isinstance(get_pkg, dict):
        txid_field = _mapping_value(get_pkg.get("eim_transaction_id"))
        if len(hints["transaction_id_hex"]) == 0 and _bool_value(txid_field.get("include"), False):
            hints["transaction_id_hex"] = _compact_hex_lenient(txid_field.get("value_hex"))
    provide_result = _mapping_value(sgp32.get("provide_eim_package_result")) if isinstance(sgp32, dict) else {}
    if isinstance(provide_result, dict):
        txid_field = _mapping_value(provide_result.get("eim_transaction_id"))
        if len(hints["transaction_id_hex"]) == 0 and _bool_value(txid_field.get("include"), False):
            hints["transaction_id_hex"] = _compact_hex_lenient(txid_field.get("value_hex"))
        profile_trigger = _mapping_value(provide_result.get("profile_download_trigger_result"))
        if len(hints["transaction_id_hex"]) == 0 and isinstance(profile_trigger, dict):
            txid_hex = _compact_hex_lenient(profile_trigger.get("transaction_id_hex"))
            if len(txid_hex) > 0:
                hints["transaction_id_hex"] = txid_hex
    profile_trigger_result = _mapping_value(sgp32.get("profile_download_trigger_result")) if isinstance(sgp32, dict) else {}
    if isinstance(profile_trigger_result, dict):
        txid = _mapping_value(profile_trigger_result.get("transaction_id"))
        if len(hints["transaction_id_hex"]) == 0 and _bool_value(txid.get("include"), False):
            txid_hex = _compact_hex_lenient(txid.get("value_hex"))
            if len(txid_hex) > 0:
                hints["transaction_id_hex"] = txid_hex
    return hints


def _compact_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return str(value).strip()


def _compact_hex(value: Any) -> str:
    text = _compact_string(value).replace(" ", "")
    if len(text) == 0:
        return ""
    try:
        bytes.fromhex(text)
    except ValueError as error:
        raise ValueError(f"Invalid hex string: {text}") from error
    return text.upper()


def _compact_hex_lenient(value: Any) -> str:
    text = _compact_string(value).replace(" ", "")
    if len(text) == 0:
        return ""
    if len(text) % 2 != 0:
        return text.upper()
    try:
        bytes.fromhex(text)
    except ValueError:
        return text.upper()
    return text.upper()


def _bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    text = _compact_string(value).lower()
    if text in ("1", "true", "yes", "y", "on"):
        return True
    if text in ("0", "false", "no", "n", "off"):
        return False
    return default


def _mapping_value(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _path_exists_flexible(path_text: str) -> bool:
    candidate = _compact_string(path_text)
    if len(candidate) == 0:
        return False
    if os.path.exists(candidate):
        return True
    expanded = os.path.abspath(os.path.expanduser(candidate))
    if os.path.exists(expanded):
        return True
    workspace_root = _detect_workspace_root()
    if len(workspace_root) > 0:
        from_workspace = os.path.abspath(os.path.join(workspace_root, candidate))
        if os.path.exists(from_workspace):
            return True
    return False


def _detect_workspace_root() -> str:
    start = os.path.dirname(os.path.abspath(__file__))
    current = start
    while True:
        marker = os.path.join(current, ".git")
        if os.path.isdir(marker):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return ""
        current = parent


def _lint_add_initial_eim_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("add_initial_eim_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.add_initial_eim_request.include must be true for package_type add_initial_eim.")
    rows = request.get("eim_configuration_data_list")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.add_initial_eim_request.eim_configuration_data_list must contain at least one entry.")
        return errors
    enabled_rows = [row for row in rows if isinstance(row, dict) and _bool_value(row.get("include"), True)]
    if len(enabled_rows) == 0:
        errors.append("At least one eim_configuration_data_list entry must have include=true.")
        return errors
    for index, row in enumerate(enabled_rows):
        errors.extend(_lint_eim_configuration_row(row, f"sgp32.add_initial_eim_request.eim_configuration_data_list[{index}]"))
    return errors


def _lint_add_eim_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("add_eim_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.add_eim_request.include must be true for package_type add_eim.")
    rows = request.get("eim_configuration_data_list")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.add_eim_request.eim_configuration_data_list must contain at least one entry.")
        return errors
    enabled_rows = [row for row in rows if isinstance(row, dict) and _bool_value(row.get("include"), True)]
    if len(enabled_rows) == 0:
        errors.append("At least one add_eim eim_configuration_data_list entry must have include=true.")
        return errors
    for index, row in enumerate(enabled_rows):
        errors.extend(_lint_eim_configuration_row(row, f"sgp32.add_eim_request.eim_configuration_data_list[{index}]"))
    return errors


def _lint_get_eim_package_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("get_eim_package_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.get_eim_package_request.include must be true for package_type get_eim_package.")
    eid_value = _mapping_value(request.get("eid_value"))
    if _bool_value(eid_value.get("include"), True) is False:
        errors.append("sgp32.get_eim_package_request.eid_value.include must be true.")
    eid_hex = _compact_hex_lenient(eid_value.get("value_hex"))
    if len(eid_hex) != 32:
        errors.append("sgp32.get_eim_package_request.eid_value.value_hex must be 16 bytes (32 hex chars).")
    notify_state_change = _mapping_value(request.get("notify_state_change"))
    if _bool_value(notify_state_change.get("include"), False):
        state_change_cause = _mapping_value(request.get("state_change_cause"))
        if _bool_value(state_change_cause.get("include"), False) is False:
            errors.append("state_change_cause.include should be true when notify_state_change.include is true.")
    rplmn = _mapping_value(request.get("rplmn"))
    if _bool_value(rplmn.get("include"), False):
        rplmn_hex = _compact_hex_lenient(rplmn.get("value_hex"))
        if len(rplmn_hex) != 6:
            errors.append("sgp32.get_eim_package_request.rplmn.value_hex must be 3 bytes (6 hex chars).")
    return errors


def _lint_provide_eim_package_result_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("provide_eim_package_result"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.provide_eim_package_result.include must be true for package_type provide_eim_package_result.")
    result_choice = _compact_string(request.get("result_choice")).lower()
    allowed = (
        "euicc_package_result",
        "epr_and_notifications",
        "ipa_euicc_data_response",
        "profile_download_trigger_result",
        "eim_package_result_response_error",
    )
    if result_choice not in allowed:
        errors.append(
            "sgp32.provide_eim_package_result.result_choice must be one of: "
            + ", ".join(allowed)
        )
    eid_value = _mapping_value(request.get("eid_value"))
    if _bool_value(eid_value.get("include"), False):
        eid_hex = _compact_hex_lenient(eid_value.get("value_hex"))
        if len(eid_hex) != 32:
            errors.append("sgp32.provide_eim_package_result.eid_value.value_hex must be 16 bytes (32 hex chars).")
    txid = _mapping_value(request.get("eim_transaction_id"))
    if _bool_value(txid.get("include"), False):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.provide_eim_package_result.eim_transaction_id.value_hex must be non-empty even-length hex.")
    return errors


def _lint_ipae_handover_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    txid = _compact_hex_lenient(document.get("transaction_id_hex"))
    if len(txid) > 0 and len(txid) % 2 != 0:
        errors.append("transaction_id_hex must be even-length hex for ipae_handover.")
    profile_path = _compact_string(document.get("profile_path"))
    if len(profile_path) == 0:
        errors.append("profile_path should be set for ipae_handover package_type.")
    return errors


def _lint_eim_package_request_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("eim_package_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.eim_package_request.include must be true for package_type eim_package_request.")
    choice = _compact_string(request.get("choice")).lower()
    allowed = (
        "euicc_package_request",
        "ipa_euicc_data_request",
        "profile_download_trigger_request",
        "eim_acknowledgements",
    )
    if choice not in allowed:
        errors.append("sgp32.eim_package_request.choice must be a valid request family.")
    return errors


def _lint_euicc_package_request_eim_configuration_data_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("euicc_package_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.euicc_package_request.include must be true.")
    choice = _compact_string(request.get("choice")).lower()
    if choice != "eim_configuration_data":
        errors.append("sgp32.euicc_package_request.choice must be eim_configuration_data.")
    section = _mapping_value(request.get("eim_configuration_data"))
    rows = section.get("rows")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.euicc_package_request.eim_configuration_data.rows must contain at least one entry.")
    return errors


def _lint_euicc_package_request_ecos_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("euicc_package_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.euicc_package_request.include must be true.")
    choice = _compact_string(request.get("choice")).lower()
    if choice != "euicc_package_request_containing_ecos":
        errors.append("sgp32.euicc_package_request.choice must be euicc_package_request_containing_ecos.")
    section = _mapping_value(request.get("euicc_package_request_containing_ecos"))
    rows = section.get("ecos")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.euicc_package_request_containing_ecos.ecos must contain at least one entry.")
    return errors


def _lint_euicc_package_request_psmos_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("euicc_package_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.euicc_package_request.include must be true.")
    choice = _compact_string(request.get("choice")).lower()
    if choice != "euicc_package_request_containing_psmos":
        errors.append("sgp32.euicc_package_request.choice must be euicc_package_request_containing_psmos.")
    section = _mapping_value(request.get("euicc_package_request_containing_psmos"))
    rows = section.get("psmos")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.euicc_package_request_containing_psmos.psmos must contain at least one entry.")
    return errors


def _lint_ipa_euicc_data_request_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("ipa_euicc_data_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.ipa_euicc_data_request.include must be true.")
    txid = _mapping_value(request.get("transaction_id"))
    if _bool_value(txid.get("include"), True):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.ipa_euicc_data_request.transaction_id.value_hex must be non-empty even-length hex.")
    return errors


def _lint_profile_download_trigger_request_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("profile_download_trigger_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.profile_download_trigger_request.include must be true.")
    txid = _mapping_value(request.get("transaction_id"))
    if _bool_value(txid.get("include"), True):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.profile_download_trigger_request.transaction_id.value_hex must be non-empty even-length hex.")
    matching_id = _mapping_value(request.get("matching_id"))
    if _bool_value(matching_id.get("include"), True):
        if len(_compact_string(matching_id.get("value"))) == 0:
            errors.append("sgp32.profile_download_trigger_request.matching_id.value must be non-empty.")
    return errors


def _lint_bound_profile_package_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    runtime_hints = resolve_package_runtime_hints(document)
    profile_path = _compact_string(runtime_hints.get("profile_path"))
    if len(profile_path) == 0:
        errors.append("runtime.profile_path should point to a UPP/BPP source for direct profile download.")
    txid_hex = _compact_hex_lenient(runtime_hints.get("transaction_id_hex"))
    if len(txid_hex) > 0 and len(txid_hex) % 2 != 0:
        errors.append("runtime.transaction_id_hex must be even-length hex for bound_profile_package.")
    return errors


def _lint_euicc_memory_reset_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp22 = _mapping_value(document.get("sgp22"))
    request = _mapping_value(sgp22.get("euicc_memory_reset_request"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp22.euicc_memory_reset_request.include must be true.")
    option_source = _mapping_value(request.get("options"))
    if len(option_source) == 0:
        option_source = request
    option_names = (
        "delete_operational_profiles",
        "delete_field_loaded_test_profiles",
        "reset_default_smdp_address",
        "delete_preloaded_test_profiles",
        "delete_provisioning_profiles",
        "reset_eim_config_data",
        "reset_immediate_enable_config",
    )
    if len(option_source) == 0:
        errors.append("sgp22.euicc_memory_reset_request.options must be present.")
        return errors
    enabled = 0
    for key in option_names:
        if key in option_source:
            if _bool_value(option_source.get(key), False):
                enabled += 1
            continue
        camel_key = "".join(
            [part.capitalize() if index > 0 else part for index, part in enumerate(key.split("_"))]
        )
        if camel_key in option_source and _bool_value(option_source.get(camel_key), False):
            enabled += 1
    if enabled == 0:
        errors.append("sgp22.euicc_memory_reset_request.options must enable at least one reset option.")
    return errors


def _lint_eim_acknowledgements_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    request = _mapping_value(sgp32.get("eim_acknowledgements"))
    if _bool_value(request.get("include"), True) is False:
        errors.append("sgp32.eim_acknowledgements.include must be true.")
    rows = request.get("ack_rows")
    if isinstance(rows, list) is False or len(rows) == 0:
        errors.append("sgp32.eim_acknowledgements.ack_rows must contain at least one entry.")
        return errors
    for index, row in enumerate(rows):
        if isinstance(row, dict) is False:
            errors.append(f"sgp32.eim_acknowledgements.ack_rows[{index}] must be an object.")
            continue
        if _bool_value(row.get("include"), True) is False:
            continue
        txid_hex = _compact_hex_lenient(row.get("transaction_id_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append(f"sgp32.eim_acknowledgements.ack_rows[{index}].transaction_id_hex must be non-empty even-length hex.")
    return errors


def _lint_eim_package_result_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    result = _mapping_value(sgp32.get("eim_package_result"))
    if _bool_value(result.get("include"), True) is False:
        errors.append("sgp32.eim_package_result.include must be true for package_type eim_package_result.")
    choice = _compact_string(result.get("choice")).lower()
    allowed = (
        "euicc_package_result",
        "ipa_euicc_data_response",
        "profile_download_trigger_result",
    )
    if choice not in allowed:
        errors.append("sgp32.eim_package_result.choice must be a valid result family.")
    return errors


def _lint_euicc_package_result_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    result = _mapping_value(sgp32.get("euicc_package_result"))
    if _bool_value(result.get("include"), True) is False:
        errors.append("sgp32.euicc_package_result.include must be true.")
    txid = _mapping_value(result.get("transaction_id"))
    if _bool_value(txid.get("include"), True):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.euicc_package_result.transaction_id.value_hex must be non-empty even-length hex.")
    return errors


def _lint_ipa_euicc_data_response_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    result = _mapping_value(sgp32.get("ipa_euicc_data_response"))
    if _bool_value(result.get("include"), True) is False:
        errors.append("sgp32.ipa_euicc_data_response.include must be true.")
    txid = _mapping_value(result.get("transaction_id"))
    if _bool_value(txid.get("include"), True):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.ipa_euicc_data_response.transaction_id.value_hex must be non-empty even-length hex.")
    return errors


def _lint_profile_download_trigger_result_spec(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sgp32 = _mapping_value(document.get("sgp32"))
    result = _mapping_value(sgp32.get("profile_download_trigger_result"))
    if _bool_value(result.get("include"), True) is False:
        errors.append("sgp32.profile_download_trigger_result.include must be true.")
    txid = _mapping_value(result.get("transaction_id"))
    if _bool_value(txid.get("include"), True):
        txid_hex = _compact_hex_lenient(txid.get("value_hex"))
        if len(txid_hex) == 0 or len(txid_hex) % 2 != 0:
            errors.append("sgp32.profile_download_trigger_result.transaction_id.value_hex must be non-empty even-length hex.")
    result_code = _mapping_value(result.get("result_code"))
    if _bool_value(result_code.get("include"), True):
        if len(_compact_string(result_code.get("value"))) == 0:
            errors.append("sgp32.profile_download_trigger_result.result_code.value must be non-empty.")
    return errors


def _lint_eim_configuration_row(row: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    eim_id = _mapping_value(row.get("eim_id"))
    if _bool_value(eim_id.get("include"), True) is False:
        errors.append(f"{path}.eim_id.include must be true.")
    if len(_compact_string(eim_id.get("value"))) == 0:
        errors.append(f"{path}.eim_id.value must be non-empty.")
    counter_value = _mapping_value(row.get("counter_value"))
    if _bool_value(counter_value.get("include"), True) is False:
        errors.append(f"{path}.counter_value.include must be true.")
    if _is_int_like(counter_value.get("value")) is False:
        errors.append(f"{path}.counter_value.value must be an integer.")
    key_data = _mapping_value(row.get("eim_public_key_data"))
    if _bool_value(key_data.get("include"), True) is False:
        errors.append(f"{path}.eim_public_key_data.include must be true.")
    choice = _compact_string(key_data.get("choice")).lower()
    if choice not in ("eim_public_key", "eim_certificate"):
        errors.append(f"{path}.eim_public_key_data.choice must be eim_public_key or eim_certificate.")
    if choice == "eim_public_key":
        value_hex = _compact_hex_lenient(key_data.get("eim_public_key_spki_hex"))
        if len(value_hex) == 0:
            errors.append(f"{path}.eim_public_key_data.eim_public_key_spki_hex must be set when choice=eim_public_key.")
    if choice == "eim_certificate":
        cert_path = _compact_string(key_data.get("eim_certificate_der_path"))
        cert_hex = _compact_hex_lenient(key_data.get("eim_certificate_der_hex"))
        if len(cert_path) == 0 and len(cert_hex) == 0:
            errors.append(
                f"{path}.eim_public_key_data requires eim_certificate_der_path or "
                "eim_certificate_der_hex when choice=eim_certificate."
            )
    return errors


def _is_int_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    text = _compact_string(value)
    if len(text) == 0:
        return False
    if text.startswith("-"):
        text = text[1:]
    return text.isdigit()


def _build_spec_checks(document: dict[str, Any], package_type_lc: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    sgp32 = _mapping_value(document.get("sgp32"))

    if package_type_lc == "add_initial_eim":
        request = _mapping_value(sgp32.get("add_initial_eim_request"))
        checks.append(
            _spec_check(
                "SGP.32 ES10b AddInitialEimRequest tag BF57",
                _compact_string(request.get("command_tag_hex")).upper() == "BF57",
                "command_tag_hex should be BF57.",
            )
        )
        rows = request.get("eim_configuration_data_list", [])
        checks.append(
            _spec_check(
                "EimConfigurationData list present",
                isinstance(rows, list) and len(rows) > 0,
                "eim_configuration_data_list must contain at least one entry.",
            )
        )
        if isinstance(rows, list) and len(rows) > 0 and isinstance(rows[0], dict):
            row = rows[0]
            checks.append(_spec_check("eimId present", len(_compact_string(_mapping_value(row.get("eim_id")).get("value"))) > 0, "eimId is required."))
            checks.append(_spec_check("counterValue present", _is_int_like(_mapping_value(row.get("counter_value")).get("value")), "counterValue is required."))
            key_data = _mapping_value(row.get("eim_public_key_data"))
            key_choice = _compact_string(key_data.get("choice")).lower()
            checks.append(
                _spec_check(
                    "eimPublicKeyData choice set",
                    key_choice in ("eim_public_key", "eim_certificate"),
                    "choice must be eim_public_key or eim_certificate.",
                )
            )

    elif package_type_lc == "add_eim":
        request = _mapping_value(sgp32.get("add_eim_request"))
        checks.append(
            _spec_check(
                "SGP.32 addEim eCO choice [8]",
                _compact_string(request.get("eco_choice_tag_hex")).upper() in ("08", "88"),
                "eco_choice_tag_hex should encode addEim [8].",
            )
        )
        rows = request.get("eim_configuration_data_list", [])
        checks.append(_spec_check("EimConfigurationData list present", isinstance(rows, list) and len(rows) > 0, "eim_configuration_data_list must exist."))

    elif package_type_lc in ("get_eim_package", "ipad_discover", "ipad"):
        request = _mapping_value(sgp32.get("get_eim_package_request"))
        checks.append(_spec_check("SGP.32 ESipa GetEimPackage tag BF4F", _compact_string(request.get("command_tag_hex")).upper() == "BF4F", "command_tag_hex should be BF4F."))
        eid_hex = _compact_hex_lenient(_mapping_value(request.get("eid_value")).get("value_hex"))
        checks.append(_spec_check("eidValue length 16 bytes", len(eid_hex) == 32, "eid_value.value_hex must be 32 hex chars."))
        rplmn = _mapping_value(request.get("rplmn"))
        if _bool_value(rplmn.get("include"), False):
            checks.append(_spec_check("rPLMN size 3 bytes", len(_compact_hex_lenient(rplmn.get("value_hex"))) == 6, "rplmn.value_hex must be 6 hex chars."))

    elif package_type_lc in ("provide_eim_package_result", "ipae_handover", "ipae_download"):
        request = _mapping_value(sgp32.get("provide_eim_package_result"))
        checks.append(_spec_check("SGP.32 ESipa ProvideEimPackageResult tag BF50", _compact_string(request.get("command_tag_hex")).upper() == "BF50", "command_tag_hex should be BF50."))
        choice = _compact_string(request.get("result_choice")).lower()
        checks.append(
            _spec_check(
                "EimPackageResult CHOICE valid",
                choice
                in (
                    "euicc_package_result",
                    "epr_and_notifications",
                    "ipa_euicc_data_response",
                    "profile_download_trigger_result",
                    "eim_package_result_response_error",
                ),
                "result_choice is within allowed ESipa ProvideEimPackageResult CHOICE values.",
            )
        )
        if choice == "profile_download_trigger_result":
            trigger = _mapping_value(request.get("profile_download_trigger_result"))
            txid_hex = _compact_hex_lenient(trigger.get("transaction_id_hex"))
            checks.append(_spec_check("ProfileDownloadTriggerResult transactionId present", len(txid_hex) > 0 and len(txid_hex) % 2 == 0, "transaction_id_hex should be non-empty even-length hex."))

    elif package_type_lc in ("bound_profile_package", "direct_profile_download"):
        runtime_hints = resolve_package_runtime_hints(document)
        profile_path = _compact_string(runtime_hints.get("profile_path"))
        checks.append(
            _spec_check(
                "Direct profile source path present",
                len(profile_path) > 0,
                "runtime.profile_path should reference the UPP/BPP input for direct download.",
            )
        )

    elif package_type_lc == "euicc_memory_reset":
        sgp22 = _mapping_value(document.get("sgp22"))
        request = _mapping_value(sgp22.get("euicc_memory_reset_request"))
        option_source = _mapping_value(request.get("options"))
        if len(option_source) == 0:
            option_source = request
        enabled = 0
        for key in (
            "delete_operational_profiles",
            "delete_field_loaded_test_profiles",
            "reset_default_smdp_address",
            "delete_preloaded_test_profiles",
            "delete_provisioning_profiles",
            "reset_eim_config_data",
            "reset_immediate_enable_config",
        ):
            if _bool_value(option_source.get(key), False):
                enabled += 1
                continue
            camel_key = "".join(
                [part.capitalize() if index > 0 else part for index, part in enumerate(key.split("_"))]
            )
            if _bool_value(option_source.get(camel_key), False):
                enabled += 1
        checks.append(
            _spec_check(
                "SGP.22 eUICCMemoryReset options present",
                enabled > 0,
                "At least one reset option should be enabled.",
            )
        )
        checks.append(
            _spec_check(
                "Selective eIM reset flag available",
                True,
                "reset_eim_config_data maps to the extended ES10c reset option bit.",
            )
        )

    elif package_type_lc in ("ipae_authenticate", "ipae_auth"):
        request = _mapping_value(sgp32.get("initiate_authentication_request_esipa"))
        checks.append(
            _spec_check(
                "SGP.32 ESipa InitiateAuthenticationRequest tag BF39",
                _compact_string(request.get("command_tag_hex")).upper() == "BF39",
                "command_tag_hex should be BF39.",
            )
        )
        challenge = _mapping_value(request.get("euicc_challenge"))
        include_challenge = _bool_value(challenge.get("include"), False)
        if include_challenge:
            value_hex = _compact_hex_lenient(challenge.get("value_hex"))
            checks.append(
                _spec_check(
                    "euiccChallenge length 16 bytes",
                    len(value_hex) == 32,
                    "euicc_challenge.value_hex should be 32 hex chars when include=true.",
                )
            )
        else:
            checks.append(
                _spec_check(
                    "euiccChallenge deferred to runtime",
                    True,
                    "euicc_challenge.include is false; challenge expected from runtime flow.",
                )
            )

    elif package_type_lc == "eim_package_request":
        request = _mapping_value(sgp32.get("eim_package_request"))
        choice = _compact_string(request.get("choice")).lower()
        checks.append(
            _spec_check(
                "eIM Package Request family CHOICE valid",
                choice in (
                    "euicc_package_request",
                    "ipa_euicc_data_request",
                    "profile_download_trigger_request",
                    "eim_acknowledgements",
                ),
                "choice must be one of the SGP.32 eIM Package Request families.",
            )
        )
    elif package_type_lc == "euicc_package_request_eim_configuration_data":
        request = _mapping_value(sgp32.get("euicc_package_request"))
        choice = _compact_string(request.get("choice")).lower()
        rows = _mapping_value(request.get("eim_configuration_data")).get("rows", [])
        checks.append(
            _spec_check(
                "EuiccPackageRequest CHOICE set to eIM Configuration Data",
                choice == "eim_configuration_data",
                "choice should be eim_configuration_data.",
            )
        )
        checks.append(
            _spec_check(
                "eIM Configuration Data rows present",
                isinstance(rows, list) and len(rows) > 0,
                "rows must contain at least one entry.",
            )
        )
    elif package_type_lc == "euicc_package_request_ecos":
        request = _mapping_value(sgp32.get("euicc_package_request"))
        choice = _compact_string(request.get("choice")).lower()
        rows = _mapping_value(request.get("euicc_package_request_containing_ecos")).get("ecos", [])
        checks.append(
            _spec_check(
                "EuiccPackageRequest CHOICE set to eCOs",
                choice == "euicc_package_request_containing_ecos",
                "choice should be euicc_package_request_containing_ecos.",
            )
        )
        checks.append(
            _spec_check(
                "eCO list present",
                isinstance(rows, list) and len(rows) > 0,
                "ecos must contain at least one entry.",
            )
        )
    elif package_type_lc == "euicc_package_request_psmos":
        request = _mapping_value(sgp32.get("euicc_package_request"))
        choice = _compact_string(request.get("choice")).lower()
        rows = _mapping_value(request.get("euicc_package_request_containing_psmos")).get("psmos", [])
        checks.append(
            _spec_check(
                "EuiccPackageRequest CHOICE set to PSMOs",
                choice == "euicc_package_request_containing_psmos",
                "choice should be euicc_package_request_containing_psmos.",
            )
        )
        checks.append(
            _spec_check(
                "PSMO list present",
                isinstance(rows, list) and len(rows) > 0,
                "psmos must contain at least one entry.",
            )
        )
    elif package_type_lc == "ipa_euicc_data_request":
        request = _mapping_value(sgp32.get("ipa_euicc_data_request"))
        txid_hex = _compact_hex_lenient(_mapping_value(request.get("transaction_id")).get("value_hex"))
        checks.append(
            _spec_check(
                "IPAeUiccDataRequest transactionId present",
                len(txid_hex) > 0 and len(txid_hex) % 2 == 0,
                "transaction_id.value_hex should be non-empty even-length hex.",
            )
        )
    elif package_type_lc == "profile_download_trigger_request":
        request = _mapping_value(sgp32.get("profile_download_trigger_request"))
        txid_hex = _compact_hex_lenient(_mapping_value(request.get("transaction_id")).get("value_hex"))
        matching_id = _compact_string(_mapping_value(request.get("matching_id")).get("value"))
        checks.append(
            _spec_check(
                "ProfileDownloadTriggerRequest transactionId present",
                len(txid_hex) > 0 and len(txid_hex) % 2 == 0,
                "transaction_id.value_hex should be non-empty even-length hex.",
            )
        )
        checks.append(
            _spec_check(
                "ProfileDownloadTriggerRequest matchingId present",
                len(matching_id) > 0,
                "matching_id.value should be non-empty.",
            )
        )
    elif package_type_lc == "eim_acknowledgements":
        request = _mapping_value(sgp32.get("eim_acknowledgements"))
        rows = request.get("ack_rows", [])
        checks.append(
            _spec_check(
                "EimAcknowledgements list present",
                isinstance(rows, list) and len(rows) > 0,
                "ack_rows must contain at least one entry.",
            )
        )
    elif package_type_lc == "eim_package_result":
        result = _mapping_value(sgp32.get("eim_package_result"))
        choice = _compact_string(result.get("choice")).lower()
        checks.append(
            _spec_check(
                "eIM Package Result family CHOICE valid",
                choice in (
                    "euicc_package_result",
                    "ipa_euicc_data_response",
                    "profile_download_trigger_result",
                ),
                "choice must be one of the SGP.32 eIM Package Result families.",
            )
        )
    elif package_type_lc == "euicc_package_result":
        result = _mapping_value(sgp32.get("euicc_package_result"))
        txid_hex = _compact_hex_lenient(_mapping_value(result.get("transaction_id")).get("value_hex"))
        checks.append(
            _spec_check(
                "EuiccPackageResult transactionId present",
                len(txid_hex) > 0 and len(txid_hex) % 2 == 0,
                "transaction_id.value_hex should be non-empty even-length hex.",
            )
        )
    elif package_type_lc == "ipa_euicc_data_response":
        result = _mapping_value(sgp32.get("ipa_euicc_data_response"))
        txid_hex = _compact_hex_lenient(_mapping_value(result.get("transaction_id")).get("value_hex"))
        checks.append(
            _spec_check(
                "IpaEuiccDataResponse transactionId present",
                len(txid_hex) > 0 and len(txid_hex) % 2 == 0,
                "transaction_id.value_hex should be non-empty even-length hex.",
            )
        )
    elif package_type_lc == "profile_download_trigger_result":
        result = _mapping_value(sgp32.get("profile_download_trigger_result"))
        txid_hex = _compact_hex_lenient(_mapping_value(result.get("transaction_id")).get("value_hex"))
        checks.append(
            _spec_check(
                "ProfileDownloadTriggerResult transactionId present",
                len(txid_hex) > 0 and len(txid_hex) % 2 == 0,
                "transaction_id.value_hex should be non-empty even-length hex.",
            )
        )
    else:
        checks.append(_spec_check("Package type recognized by spec checker", False, f"No spec checker profile for package_type={package_type_lc}"))

    return checks


def _spec_check(check: str, ok: bool, detail: str) -> dict[str, Any]:
    return {
        "check": check,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
    }
