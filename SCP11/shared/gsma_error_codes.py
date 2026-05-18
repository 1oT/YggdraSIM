# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""GSMA error-code descriptions: maps SGP.22 profile-state and notification result codes to human-readable strings."""
from typing import Any, Dict

# SGP.22 / RSP (ES10b) operation result codes currently surfaced by card flows.
SGP22_ES10B_PROFILE_STATE_RESULT: Dict[int, str] = {
    0: "ok",
    1: "iccidOrAidNotFound",
    2: "profileNotInRequestedState",
    3: "disallowedByPolicy",
    4: "wrongProfileReenabling",
    5: "catBusy",
    7: "commandDataStructureError",
    127: "undefinedError",
}

# SGP.22 / RSP (ES10b) RemoveNotificationFromList deleteNotificationStatus
SGP22_NOTIFICATION_SENT_RESULT: Dict[int, str] = {
    0: "ok",
    1: "nothingToDelete",
    127: "undefinedError",
}

# SGP.22 PrepareDownload / DownloadErrorCode
SGP22_DOWNLOAD_ERROR_CODE: Dict[int, str] = {
    1: "invalidCertificate",
    2: "invalidSignature",
    3: "unsupportedCurve",
    4: "noSessionContext",
    5: "invalidTransactionId",
    127: "undefinedError",
}

# SGP.22 / SGP.02 profile installation result reason reported by card.
# Codes 1..15 and 127 are SGP.22 v2 (the upstream pySim ASN.1 module is v2.0).
# Codes 16..23 are the v3.x extensions — harmless on v2 cards because they
# will never appear there; useful when the card firmware moves forward.
SGP22_PROFILE_INSTALLATION_RESULT_REASON: Dict[int, str] = {
    1: "incorrectInputValues",
    2: "invalidSignature",
    3: "invalidTransactionId",
    4: "unsupportedCrtValues",
    5: "unsupportedRemoteOperationType",
    6: "unsupportedProfileClass",
    7: "scp03tStructureError",
    8: "scp03tSecurityError",
    9: "installFailedDueToIccidAlreadyExistsOnEuicc",
    10: "installFailedDueToInsufficientMemoryForProfile",
    11: "installFailedDueToInterruption",
    12: "installFailedDueToPEProcessingError",
    13: "installFailedDueToIccidMismatch",
    14: "testProfileInstallFailedDueToInvalidNaaKey",
    15: "pprNotAllowed",
    16: "enterpriseProfilesNotSupported",
    17: "enterpriseRulesNotAllowed",
    18: "enterpriseProfileNotAllowed",
    19: "enterpriseOidMismatch",
    20: "enterpriseRulesError",
    21: "enterpriseProfilesOnly",
    22: "lprNotSupported",
    23: "unknownTlvInMetadata",
    127: "installFailedDueToUnknownError",
}

# SGP.32 ESipa GetEimPackageResponse eimPackageError
SGP32_EIM_PACKAGE_ERROR: Dict[int, str] = {
    1: "noEimPackageAvailable",
    2: "eidNotFound",
    3: "invalidEid",
    4: "missingEid",
    127: "undefinedError",
}

# SGP.32 ESipa ProvideEimPackageResult error branch
SGP32_EIM_PACKAGE_RESULT_ERROR: Dict[int, str] = {
    1: "invalidPackageFormat",
    2: "unknownPackage",
    127: "undefinedError",
}

# SGP.32 ProfileDownloadTriggerResult.profileDownloadErrorReason
SGP32_PROFILE_DOWNLOAD_ERROR_REASON: Dict[int, str] = {
    1: "transactionIdError",
    2: "unknownEimId",
    3: "eimIdNotAllowed",
    4: "undefinedDataError",
    104: "ecallActive",
    127: "undefinedError",
}


def _describe_code(table: Dict[int, str], code: int, label: str) -> str:
    name = table.get(code, "unknown")
    if name == "unknown":
        return f"{label}({code})"
    return f"{name}({code})"


def describe_sgp22_profile_state_result(code: int) -> str:
    return _describe_code(SGP22_ES10B_PROFILE_STATE_RESULT, code, "resultCode")


def describe_sgp22_notification_sent_result(code: int) -> str:
    return _describe_code(SGP22_NOTIFICATION_SENT_RESULT, code, "deleteNotificationStatus")


def describe_sgp22_download_error(code: int) -> str:
    return _describe_code(SGP22_DOWNLOAD_ERROR_CODE, code, "downloadErrorCode")


def describe_sgp22_profile_installation_reason(code: int) -> str:
    return _describe_code(SGP22_PROFILE_INSTALLATION_RESULT_REASON, code, "profileInstallationErrorReason")


def describe_sgp32_eim_package_error(code: int) -> str:
    return _describe_code(SGP32_EIM_PACKAGE_ERROR, code, "eimPackageError")


def describe_sgp32_eim_package_result_error(code: int) -> str:
    return _describe_code(SGP32_EIM_PACKAGE_RESULT_ERROR, code, "eimPackageResultErrorCode")


def describe_sgp32_profile_download_error_reason(code: int) -> str:
    return _describe_code(SGP32_PROFILE_DOWNLOAD_ERROR_REASON, code, "profileDownloadErrorReason")


def _resolve_code_value(table: Dict[int, str], value: Any, default_code: int) -> int:
    if isinstance(value, bool):
        return int(default_code)
    if isinstance(value, int):
        if value in table:
            return int(value)
        return int(default_code)
    text = str(value or "").strip()
    if len(text) == 0:
        return int(default_code)
    if text.isdigit():
        parsed = int(text, 10)
        if parsed in table:
            return parsed
        return int(default_code)
    if "(" in text and text.endswith(")"):
        suffix = text[text.rfind("(") + 1 : -1].strip()
        if suffix.isdigit():
            parsed = int(suffix, 10)
            if parsed in table:
                return parsed
    normalized = text.replace("-", "").replace("_", "").replace(" ", "").lower()
    for code, name in table.items():
        candidate = str(name).replace("-", "").replace("_", "").replace(" ", "").lower()
        if normalized == candidate:
            return int(code)
    return int(default_code)


def resolve_sgp22_profile_state_result_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP22_ES10B_PROFILE_STATE_RESULT, value, default_code)


def resolve_sgp22_download_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP22_DOWNLOAD_ERROR_CODE, value, default_code)


def resolve_sgp22_profile_installation_reason_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP22_PROFILE_INSTALLATION_RESULT_REASON, value, default_code)


def resolve_sgp32_eim_package_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_EIM_PACKAGE_ERROR, value, default_code)


def resolve_sgp32_eim_package_result_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_EIM_PACKAGE_RESULT_ERROR, value, default_code)


def resolve_sgp32_profile_download_error_reason_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_PROFILE_DOWNLOAD_ERROR_REASON, value, default_code)
