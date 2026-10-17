# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GSMA error-code descriptions: maps SGP.22 profile-state and notification result codes to human-readable strings."""
from __future__ import annotations

from typing import Any, Dict

# SGP.22 v3.1 section 5.7.16 EnableProfileResponse.enableResult, with the
# rollbackNotAvailable(20) that the SGP.32 v1.3 EnableProfileResult adds for
# the eUICC-package PSMO.
SGP22_ENABLE_PROFILE_RESULT: Dict[int, str] = {
    0: "ok",
    1: "iccidOrAidNotFound",
    2: "profileNotInDisabledState",
    3: "disallowedByPolicy",
    4: "wrongProfileReenabling",
    5: "catBusy",
    6: "disallowedByEnterpriseRule",
    7: "commandError",
    9: "disallowedForRpm",
    10: "noEsimPortAvailable",
    20: "rollbackNotAvailable",
    127: "undefinedError",
}

# SGP.22 v3.1 section 5.7.17 DisableProfileResponse.disableResult. Value 2 is
# profileNotInEnabledState here, the opposite state to Enable and Delete. The
# SGP.32 v1.3 DisableProfileResult enumerates a subset and adds nothing.
SGP22_DISABLE_PROFILE_RESULT: Dict[int, str] = {
    0: "ok",
    1: "iccidOrAidNotFound",
    2: "profileNotInEnabledState",
    3: "disallowedByPolicy",
    5: "catBusy",
    6: "disallowedByEnterpriseRule",
    7: "commandError",
    9: "disallowedForRpm",
    127: "undefinedError",
}

# SGP.22 v3.1 section 5.7.18 DeleteProfileResponse.deleteResult, with the
# rollbackNotAvailable(20) and returnFallbackProfile(21) that the SGP.32 v1.3
# DeleteProfileResult adds. Value 4 is disallowedInTestMode here, not the
# wrongProfileReenabling of Enable.
SGP22_DELETE_PROFILE_RESULT: Dict[int, str] = {
    0: "ok",
    1: "iccidOrAidNotFound",
    2: "profileNotInDisabledState",
    3: "disallowedByPolicy",
    4: "disallowedInTestMode",
    7: "commandError",
    20: "rollbackNotAvailable",
    21: "returnFallbackProfile",
    127: "undefinedError",
}

# Union of the three tables above, for surfaces that hold a result code
# without knowing which ES10c function produced it. Two values are function
# dependent and are spelled with both names rather than an invented one:
# 2 is profileNotInDisabledState for Enable and Delete but
# profileNotInEnabledState for Disable, and 4 is wrongProfileReenabling for
# Enable but disallowedInTestMode for Delete. Prefer the per-function table
# whenever the function is known.
SGP22_ES10B_PROFILE_STATE_RESULT: Dict[int, str] = {
    0: "ok",
    1: "iccidOrAidNotFound",
    2: "profileNotInDisabledState/profileNotInEnabledState",
    3: "disallowedByPolicy",
    4: "wrongProfileReenabling/disallowedInTestMode",
    5: "catBusy",
    6: "disallowedByEnterpriseRule",
    7: "commandError",
    9: "disallowedForRpm",
    10: "noEsimPortAvailable",
    # SGP.32 v1.3 EnableProfileResult / DeleteProfileResult additions.
    20: "rollbackNotAvailable",
    21: "returnFallbackProfile",
    127: "undefinedError",
}

# Each per-function spelling of a value the union above names twice, so a
# stored result name still resolves back to its code.
_PROFILE_STATE_RESULT_NAMES: Dict[str, int] = {
    "profilenotindisabledstate": 2,
    "profilenotinenabledstate": 2,
    "wrongprofilereenabling": 4,
    "disallowedintestmode": 4,
}

# SGP.22 / RSP (ES10b) RemoveNotificationFromList deleteNotificationStatus
SGP22_NOTIFICATION_SENT_RESULT: Dict[int, str] = {
    0: "ok",
    1: "nothingToDelete",
    127: "undefinedError",
}

# SGP.22 / RSP (ES10b) RetrieveNotificationsListResponse notificationsListResultError
SGP22_NOTIFICATIONS_LIST_RESULT_ERROR: Dict[int, str] = {
    127: "undefinedError",
}

# SGP.22 PrepareDownload / DownloadErrorCode
SGP22_DOWNLOAD_ERROR_CODE: Dict[int, str] = {
    1: "invalidCertificate",
    2: "invalidSignature",
    3: "unsupportedCurve",
    4: "noSession",
    5: "invalidTransactionId",
    127: "undefinedError",
}

# SGP.22 v3.1 section 2.5.6 ErrorReason. The v3 values start at 17; the v2
# module spelt 7, 8 and 13 scp03tStructureError, scp03tSecurityError and
# installFailedDueToIccidMismatch, which the resolver still accepts.
SGP22_PROFILE_INSTALLATION_RESULT_REASON: Dict[int, str] = {
    1: "incorrectInputValues",
    2: "invalidSignature",
    3: "invalidTransactionId",
    4: "unsupportedCrtValues",
    5: "unsupportedRemoteOperationType",
    6: "unsupportedProfileClass",
    7: "bspStructureError",
    8: "bspSecurityError",
    9: "installFailedDueToIccidAlreadyExistsOnEuicc",
    10: "installFailedDueToInsufficientMemoryForProfile",
    11: "installFailedDueToInterruption",
    12: "installFailedDueToPEProcessingError",
    13: "installFailedDueToDataMismatch",
    14: "testProfileInstallFailedDueToInvalidNaaKey",
    15: "pprNotAllowed",
    17: "enterpriseProfilesNotSupported",
    18: "enterpriseRulesNotAllowed",
    19: "enterpriseProfileNotAllowed",
    20: "enterpriseOidMismatch",
    21: "enterpriseRulesError",
    22: "enterpriseProfilesOnly",
    23: "lprNotSupported",
    26: "unknownTlvInMetadata",
    127: "installFailedDueToUnknownError",
}

_LEGACY_PROFILE_INSTALLATION_REASON_NAMES: Dict[str, int] = {
    "scp03tstructureerror": 7,
    "scp03tsecurityerror": 8,
    "installfailedduetoiccidmismatch": 13,
}

# SGP.22 v3.1 section 2.5.6 BppCommandId, the ErrorResult member that names
# the Bound Profile Package command the eUICC was processing.
SGP22_BPP_COMMAND_ID: Dict[int, str] = {
    0: "initialiseSecureChannel",
    1: "configureISDP",
    2: "storeMetadata",
    3: "storeMetadata2",
    4: "replaceSessionKeys",
    5: "loadProfileElements",
}

# SGP.32 ESipa GetEimPackageResponse eimPackageError
SGP32_EIM_PACKAGE_ERROR: Dict[int, str] = {
    1: "noEimPackageAvailable",
    2: "eidNotFound",
    3: "invalidEid",
    4: "missingEid",
    127: "undefinedError",
}

# SGP.32 EimPackageResultErrorCode, carried by eimPackageResultResponseError
# inside ProvideEimPackageResult.
SGP32_EIM_PACKAGE_RESULT_ERROR: Dict[int, str] = {
    1: "invalidPackageFormat",
    2: "unknownPackage",
    127: "undefinedError",
}

# SGP.32 ProfileDownloadTriggerResult.profileDownloadErrorReason
SGP32_PROFILE_DOWNLOAD_ERROR_REASON: Dict[int, str] = {
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


def describe_sgp22_enable_profile_result(code: int) -> str:
    return _describe_code(SGP22_ENABLE_PROFILE_RESULT, code, "enableResult")


def describe_sgp22_disable_profile_result(code: int) -> str:
    return _describe_code(SGP22_DISABLE_PROFILE_RESULT, code, "disableResult")


def describe_sgp22_delete_profile_result(code: int) -> str:
    return _describe_code(SGP22_DELETE_PROFILE_RESULT, code, "deleteResult")


def describe_sgp22_notification_sent_result(code: int) -> str:
    return _describe_code(SGP22_NOTIFICATION_SENT_RESULT, code, "deleteNotificationStatus")


def describe_sgp22_notifications_list_result_error(code: int) -> str:
    return _describe_code(SGP22_NOTIFICATIONS_LIST_RESULT_ERROR, code, "notificationsListResultError")


def describe_sgp22_download_error(code: int) -> str:
    return _describe_code(SGP22_DOWNLOAD_ERROR_CODE, code, "downloadErrorCode")


def describe_sgp22_profile_installation_reason(code: int) -> str:
    return _describe_code(SGP22_PROFILE_INSTALLATION_RESULT_REASON, code, "profileInstallationErrorReason")


def describe_sgp22_bpp_command_id(code: int) -> str:
    return _describe_code(SGP22_BPP_COMMAND_ID, code, "bppCommandId")


def describe_sgp32_eim_package_error(code: int) -> str:
    return _describe_code(SGP32_EIM_PACKAGE_ERROR, code, "eimPackageError")


def describe_sgp32_eim_package_result_error(code: int) -> str:
    return _describe_code(SGP32_EIM_PACKAGE_RESULT_ERROR, code, "eimPackageResultErrorCode")


def describe_sgp32_profile_download_error_reason(code: int) -> str:
    return _describe_code(SGP32_PROFILE_DOWNLOAD_ERROR_REASON, code, "profileDownloadErrorReason")


def _resolve_code_value(
    table: Dict[int, str],
    value: Any,
    default_code: int,
    aliases: Dict[str, int] | None = None,
) -> int:
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
    if aliases is not None and normalized in aliases:
        return int(aliases[normalized])
    return int(default_code)


def resolve_sgp22_profile_state_result_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(
        SGP22_ES10B_PROFILE_STATE_RESULT,
        value,
        default_code,
        aliases=_PROFILE_STATE_RESULT_NAMES,
    )


def resolve_sgp22_download_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP22_DOWNLOAD_ERROR_CODE, value, default_code)


def resolve_sgp22_profile_installation_reason_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(
        SGP22_PROFILE_INSTALLATION_RESULT_REASON,
        value,
        default_code,
        aliases=_LEGACY_PROFILE_INSTALLATION_REASON_NAMES,
    )


def resolve_sgp32_eim_package_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_EIM_PACKAGE_ERROR, value, default_code)


def resolve_sgp32_eim_package_result_error_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_EIM_PACKAGE_RESULT_ERROR, value, default_code)


def resolve_sgp32_profile_download_error_reason_code(value: Any, default_code: int = 127) -> int:
    return _resolve_code_value(SGP32_PROFILE_DOWNLOAD_ERROR_REASON, value, default_code)
