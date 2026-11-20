# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Turn an eIM package document (a template or hotfolder file) into queued operations.

The JSON documents of ``SCP11/eim_local/eim_packages`` describe a PSMO or eCO
list, an IpaEuiccDataRequest or a ProfileDownloadTriggerRequest. Importing one
queues the matching operation for an eUICC, so the package is signed and served
like any other: PSMO and eCO rows keep their typed or raw items (RAW-PSMO /
RAW-ECO), the data request keeps its tag list, and a download trigger becomes
an activation code ``1$<SM-DP+ address>$<Matching ID>``.
"""

from __future__ import annotations

from typing import Any

from SCP11.eim_local.eim_package_codec import ipa_euicc_data_request_tag_list, resolve_package_runtime_hints
from SCP11.eim_local.engine.catalogue import OperationError
from SCP11.eim_local.engine.service import OperationRequest
from SCP11.eim_local.psmo_builders import PsmoBuildError, build_eco, build_psmo


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _included(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    flag = row.get("include", True)
    if isinstance(flag, str):
        return flag.strip().lower() not in ("0", "false", "no", "off")
    return bool(flag)


def _items(rows: Any, *, kind: str) -> str:
    builder = build_psmo if kind == "psmo" else build_eco
    encoded = b""
    for index, row in enumerate(rows if isinstance(rows, list) else []):
        if not _included(row):
            continue
        operation = str(row.get("operation") or "").strip()
        if operation:
            try:
                encoded += builder(row)
            except PsmoBuildError as error:
                raise OperationError(f"{kind} row {index}: {error}") from error
            continue
        value = "".join(str(row.get("value_hex") or "").split())
        if not value:
            continue
        try:
            encoded += bytes.fromhex(value)
        except ValueError as error:
            raise OperationError(f"{kind} row {index}: value_hex is not hex.") from error
    if not encoded:
        raise OperationError(f"The document holds no included {kind.upper()} row.")
    return encoded.hex().upper()


def _download(document: dict[str, Any], section: dict[str, Any], default_smdp: str) -> dict[str, Any]:
    hints = resolve_package_runtime_hints(document)
    code = str(section.get("activation_code") or hints.get("activation_code") or "").strip()
    if code:
        return {"activation_code": code}
    matching = str(_mapping(section.get("matching_id")).get("value") or hints.get("matching_id") or "").strip()
    address = str(hints.get("smdp_address") or default_smdp or "").strip()
    if not address:
        raise OperationError("No SM-DP+ address for the trigger: set runtime.smdp_address or pass one.")
    return {"activation_code": f"1${address}${matching}"}


NOT_A_PACKAGE = (
    "EimConfigurationData rows are no eUICC Package content: an EuiccPackage is a psmoList or an ecoList "
    "(SGP.32 v1.3 §2.11.1.1). Queue ADD-EIM or UPDATE-EIM instead."
)
_PACKAGE_TYPE_CHOICES = {
    "euicc_package_request_psmos": "euicc_package_request_containing_psmos",
    "euicc_package_request_ecos": "euicc_package_request_containing_ecos",
    "euicc_package_request_eim_configuration_data": "eim_configuration_data",
}


def _euicc_package(section: dict[str, Any], eid: str, default_choice: str) -> OperationRequest:
    choice = str(section.get("choice") or default_choice).strip().lower()
    body = _mapping(section.get(choice))
    if choice == "euicc_package_request_containing_psmos":
        return OperationRequest(eid=eid, type="PSMO_RAW", params={"items": _items(body.get("psmos"), kind="psmo")})
    if choice == "euicc_package_request_containing_ecos":
        return OperationRequest(eid=eid, type="ECO_RAW", params={"items": _items(body.get("ecos"), kind="eco")})
    if choice == "eim_configuration_data":
        raise OperationError(NOT_A_PACKAGE)
    raise OperationError(f"Unknown eUICC Package choice {choice or '(none)'}.")


def _request(
    name: str, section: dict[str, Any], document: dict[str, Any], eid: str, default_smdp: str, default_choice: str = "",
) -> OperationRequest:
    if name == "euicc_package_request":
        return _euicc_package(section, eid, default_choice)
    if name == "ipa_euicc_data_request":
        tags = ipa_euicc_data_request_tag_list(section)
        return OperationRequest(eid=eid, type="IPA_EUICC_DATA", params={"tags": tags.hex().upper()} if tags else {})
    if name == "profile_download_trigger_request":
        return OperationRequest(eid=eid, type="PROFILE_DOWNLOAD_TRIGGER", params=_download(document, section, default_smdp))
    if name == "eim_acknowledgements":
        raise OperationError("The Local eIM acknowledges a result when it accepts it; there is nothing to queue.")
    raise OperationError(
        f"A {name or 'typeless'} document is not an eIM Package the queue serves; import a PSMO or eCO list, "
        "an IPA eUICC data request or a profile download trigger."
    )


def requests_from_document(document: dict[str, Any], eid: str, *, default_smdp: str = "") -> list[OperationRequest]:
    """Return the operation(s) one package document stands for."""
    package_type = str(document.get("package_type", "")).strip().lower()
    sgp32 = _mapping(document.get("sgp32"))
    if package_type == "eim_package_request":
        request = _mapping(sgp32.get("eim_package_request"))
        choice = str(request.get("choice", "")).strip().lower()
        return [_request(choice, _mapping(request.get(choice)), document, eid, default_smdp)]
    if package_type in _PACKAGE_TYPE_CHOICES:
        section = _mapping(sgp32.get("euicc_package_request"))
        return [_request("euicc_package_request", section, document, eid, default_smdp,
                         _PACKAGE_TYPE_CHOICES[package_type])]
    return [_request(package_type, _mapping(sgp32.get(package_type)), document, eid, default_smdp)]
