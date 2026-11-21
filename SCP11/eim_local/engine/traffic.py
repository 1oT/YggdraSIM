# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What an exchange on a Local eIM listener said, by names and values.

One renderer for the three places an exchange is read: an IPAe terminal trace's
``eIM:`` block, the shell's ``TRAFFIC`` and ``OP`` views and the GUI action
behind them. The request and the answer are decoded with the codec and laid
out as rows (tag, name, value); the one-line summary folds them. The ESipa
messages are GetEimPackageRequest / GetEimPackageResponse 'BF4F',
ProvideEimPackageResult / ProvideEimPackageResultResponse 'BF50' and
HandleNotificationEsipa 'BF3D' (SGP.32 v1.3 §6.3.2.6, §6.3.2.7, §5.14.7); a
EuiccPackageRequest's PSMOs and eCOs are read by the tags of the Psmo and Eco
CHOICEs (§2.11.1.1, the ASN.1 module pages 204-205). An exchange the eIM
started is TransferEimPackageRequest / TransferEimPackageResponse 'BF4E'
(§6.3.3.1); its record has no listener port, since no listener answered it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.store import TrafficRecord
from SCP11.shared import es9_asn1, esipa_download, esipa_transfer
from SCP11.shared.ber_tlv import decode_object_identifier, read_ber_tlv, read_single_ber_tlv
from SCP11.shared.eim_configuration_data import decode_der_integer
from SCP11.shared.iccid import decode_ef_iccid

BINDING_ESIPA_ASN1 = "esipa-asn1"
BINDING_ESIPA_JSON = "esipa-json"
BINDING_ES9_ASN1 = "es9-asn1"
BINDING_ES9_JSON = "es9-json"
# A request whose body the listener would not read (a chunk size that is not hexadecimal, a body past the
# limit): recorded with no bodies, so the refusal is on file next to the answered exchanges.
BINDING_REFUSED = "refused"

# Bodies longer than this are described but not echoed in full by the trace rows
# (a Bound Profile Package runs to tens of kilobytes); the store keeps them whole.
ECHO_LIMIT = 2048

# Psmo CHOICE (SGP.32 v1.3 ASN.1 module, pages 204-205): context tag -> name.
PSMO_NAMES: dict[bytes, str] = {
    b"\xA3": "enable",
    b"\xA4": "disable",
    b"\xA5": "delete",
    b"\xBF\x2D": "listProfileInfo",
    b"\xA6": "getRAT",
    b"\xA7": "configureImmediateEnable",
    b"\xA8": "setFallbackAttribute",
    b"\xA9": "unsetFallbackAttribute",
    b"\xBF\x65": "setDefaultDpAddress",
}
# Eco CHOICE (page 204).
ECO_NAMES: dict[bytes, str] = {
    b"\xA8": "addEim",
    b"\xA9": "deleteEim",
    b"\xAA": "updateEim",
    b"\xAB": "listEim",
}
# The ESipa download functions an IPA relays through the eIM (§3.2.3.2) and the ES9+
# functions the local SM-DP+ answers, by their request tag.
_DOWNLOAD_NAMES: dict[bytes, str] = {
    esipa_download.TAG_INITIATE_AUTHENTICATION: "InitiateAuthentication",
    esipa_download.TAG_AUTHENTICATE_CLIENT: "AuthenticateClient",
    esipa_download.TAG_GET_BOUND_PROFILE_PACKAGE: "GetBoundProfilePackage",
    esipa_download.TAG_CANCEL_SESSION: "CancelSession",
    esipa_download.TAG_HANDLE_NOTIFICATION: "HandleNotification",
}
# IpaEuiccDataRequest tagList members (§2.11.1.2), as the codec names them.
_TAG_LIST_NAMES: dict[bytes, str] = {
    b"\x81": "defaultSmdpAddress",
    b"\xBF\x20": "euiccInfo1",
    b"\xBF\x22": "euiccInfo2",
    b"\x83": "rootSmdsAddress",
    b"\x84": "associationToken",
    b"\xA5": "eumCertificate",
    b"\xA6": "euiccCertificate",
    b"\xA8": "ipaCapabilities",
    b"\xA9": "deviceInfo",
}


@dataclass(frozen=True)
class Detail:
    """One row of a described exchange: the data object's tag, its name and what it says.

    ``whole`` carries the complete bytes of a root row (a request or an answer),
    for the trace block that echoes them so an analysis can re-decode the exchange.
    """

    tag: str
    name: str
    value: str
    whole: bytes = b""


@dataclass
class ExchangeView:
    """A described exchange: the function, what it answered, one line and the rows behind it."""

    request: str
    answer: str
    summary: str
    rows: list[Detail] = field(default_factory=list)
    # The error name when the answer was an error, '' otherwise.
    error: str = ""


@dataclass
class Verdict:
    """What the engine made of one request, filled in by the handler while it answers: for the exchange record."""

    eid: str = ""
    operation_id: int | None = None
    note: str = ""
    # Notifications the request put on a record: the listener starts a forwarding pass after its answer.
    notifications: int = 0

    def served(self, served: Any) -> None:
        operation = getattr(served, "operation", None)
        if operation is not None:
            self.operation_id = int(operation.id)
        error = getattr(served, "error", None)
        if error is not None:
            name = codec.EIM_PACKAGE_ERRORS.get(int(error), str(error))
            self.note = name + (f" (operation {operation.id} kept back)" if operation is not None else "")
        elif operation is not None:
            self.note = f"served operation {operation.id} ({operation.type})"

    def accepted(self, accepted: Any) -> None:
        self.notifications += int(getattr(accepted, "notifications", 0) or 0)
        operation = getattr(accepted, "operation", None)
        if operation is not None:
            self.operation_id = int(operation.id)
        error = getattr(accepted, "error", None)
        messages = list(getattr(accepted, "messages", []) or [])
        if error is not None:
            self.note = codec.PROVIDE_RESULT_ERRORS.get(int(error), str(error))
        elif operation is not None:
            self.note = f"result of operation {operation.id} ({operation.type}): {operation.state}"
        elif messages:
            self.note = "; ".join(str(message) for message in messages)
        else:
            self.note = "accepted"


def _items(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item_value, raw, offset = read_ber_tlv(value, offset)
        items.append((bytes(tag), bytes(item_value), bytes(raw)))
    return items


def _text(value: bytes) -> str:
    return bytes(value).decode("utf-8", errors="replace")


def _integer(value: bytes) -> int:
    return int(decode_der_integer(bytes(value)))


def _iccid(value: bytes) -> str:
    try:
        return decode_ef_iccid(value, strict=False)
    except ValueError:
        return value.hex().upper()


def _plmn(value: bytes) -> str:
    """'MCC/MNC' from the three octets of a PLMN as 3GPP TS 24.008 codes them (the codec of pySim)."""
    try:
        from pySim.utils import dec_plmn

        decoded = dec_plmn(bytes(value).hex())
        return f"{decoded['mcc']}/{decoded['mnc']}"
    except (ImportError, KeyError, ValueError, TypeError):
        return bytes(value).hex().upper()


def _oid(value: bytes) -> str:
    try:
        return decode_object_identifier(bytes(value))
    except ValueError:
        return bytes(value).hex().upper()


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _tag_list(value: bytes) -> str:
    names: list[str] = []
    offset = 0
    data = bytes(value)
    while offset < len(data):
        width = 2 if (data[offset] & 0x1F) == 0x1F else 1
        tag = data[offset:offset + width]
        offset += width
        names.append(_TAG_LIST_NAMES.get(tag, tag.hex().upper()))
    return ", ".join(names) or "(empty)"


# -- requests ---------------------------------------------------------------


def _psmo_rows(items: list[tuple[bytes, bytes, bytes]]) -> tuple[list[Detail], list[str]]:
    rows: list[Detail] = []
    names: list[str] = []
    for tag, value, _raw in items:
        name = PSMO_NAMES.get(tag, f"Psmo {tag.hex().upper()}")
        parts: list[str] = []
        if tag in (b"\xA3", b"\xA4", b"\xA5", b"\xA8"):
            for inner_tag, inner_value, _inner_raw in _items(value):
                if inner_tag == b"\x5A":
                    parts.append(f"ICCID {_iccid(inner_value)}")
                elif inner_tag == b"\x4F":
                    parts.append(f"AID {inner_value.hex().upper()}")
                elif inner_tag == b"\x05":
                    parts.append("rollback")
        elif tag == b"\xBF\x2D":
            for inner_tag, inner_value, _inner_raw in _items(value):
                if inner_tag == b"\xA0":
                    for key_tag, key_value, _key_raw in _items(inner_value):
                        if key_tag == b"\x5A":
                            parts.append(f"ICCID {_iccid(key_value)}")
                        elif key_tag == b"\x4F":
                            parts.append(f"AID {key_value.hex().upper()}")
                        else:
                            parts.append(f"profileClass {_integer(key_value)}")
                elif inner_tag == b"\x5C":
                    parts.append(f"tags {inner_value.hex().upper()}")
            if len(parts) == 0:
                parts.append("every Profile")
        elif tag == b"\xA7":
            for inner_tag, inner_value, _inner_raw in _items(value):
                if inner_tag == b"\x80":
                    parts.append("immediateEnableFlag")
                elif inner_tag == b"\x81":
                    parts.append(f"defaultSmdpOid {_oid(inner_value)}")
                elif inner_tag == b"\x82":
                    parts.append(f"defaultSmdpAddress {_text(inner_value)}")
            if len(parts) == 0:
                parts.append("off")
        elif tag == b"\xBF\x65":
            for inner_tag, inner_value, _inner_raw in _items(value):
                if inner_tag == b"\x80":
                    parts.append(_text(inner_value))
        summary = f"{name} {', '.join(parts)}".strip()
        names.append(summary)
        rows.append(Detail(tag.hex().upper(), name, ", ".join(parts)))
    return rows, names


def _eco_rows(items: list[tuple[bytes, bytes, bytes]]) -> tuple[list[Detail], list[str]]:
    rows: list[Detail] = []
    names: list[str] = []
    for tag, value, _raw in items:
        name = ECO_NAMES.get(tag, f"Eco {tag.hex().upper()}")
        parts: list[str] = []
        if tag in (b"\xA8", b"\xAA", b"\xA9"):
            for inner_tag, inner_value, _inner_raw in _items(value):
                if inner_tag == b"\x80":
                    parts.append(f"eimId {_text(inner_value)}")
                elif inner_tag == b"\x81":
                    parts.append(f"eimFqdn {_text(inner_value)}")
                elif inner_tag == b"\x83":
                    parts.append(f"counter {_integer(inner_value)}")
                elif inner_tag == b"\x84":
                    parts.append(f"associationToken {_integer(inner_value)}")
                elif inner_tag == b"\xA5":
                    parts.append("eimPublicKeyData")
                elif inner_tag == b"\xA6":
                    parts.append("trustedPublicKeyDataTls")
                elif inner_tag == b"\x89":
                    parts.append("indirectProfileDownload")
        summary = f"{name} {', '.join(parts)}".strip()
        names.append(summary)
        rows.append(Detail(tag.hex().upper(), name, ", ".join(parts)))
    return rows, names


def _package_request_rows(raw: bytes) -> tuple[list[Detail], str]:
    """Rows for a EuiccPackageRequest 'BF51', and the text its line folds them into."""
    rows: list[Detail] = []
    try:
        _tag, value, _raw = read_single_ber_tlv(raw)
        parts = _items(value)
    except ValueError as error:
        return [Detail("BF51", "EuiccPackageRequest", f"not readable: {error}")], "EuiccPackageRequest (not readable)"
    heading: list[str] = []
    item_names: list[str] = []
    signature = b""
    for tag, item_value, _item_raw in parts:
        if tag == b"\x30":
            for member_tag, member_value, _member_raw in _items(item_value):
                if member_tag == b"\x80":
                    heading.append(f"eimId {_text(member_value)}")
                elif member_tag == b"\x5A":
                    heading.append(f"EID {codec.eid_from_bytes(member_value)}")
                elif member_tag == b"\x81":
                    heading.append(f"counter {_integer(member_value)}")
                elif member_tag == b"\x82":
                    heading.append(f"transaction {member_value.hex().upper()}")
                elif member_tag == b"\xA0":
                    psmo_rows, item_names = _psmo_rows(_items(member_value))
                    rows.extend(psmo_rows)
                elif member_tag == b"\xA1":
                    eco_rows, item_names = _eco_rows(_items(member_value))
                    rows.extend(eco_rows)
        elif tag == codec.TAG_SIGNATURE:
            signature = item_value
    rows.insert(0, Detail("BF51", "EuiccPackageRequest", ", ".join(heading)))
    if len(signature) > 0:
        rows.append(Detail("5F37", "eimSignature", _count(len(signature), "byte")))
    counter = next((part for part in heading if part.startswith("counter ")), "")
    folded = "; ".join(item_names) or "no operation"
    return rows, folded + (f", {counter}" if counter else "")


def _ipa_data_request_rows(raw: bytes) -> tuple[list[Detail], str]:
    rows: list[Detail] = []
    parts: list[str] = []
    try:
        _tag, value, _raw = read_single_ber_tlv(raw)
        for tag, item_value, _item_raw in _items(value):
            if tag == b"\x5C":
                parts.append(f"tagList {_tag_list(item_value)}")
            elif tag == b"\x04":
                parts.append(f"euiccCiPKIdentifierToBeUsed {item_value.hex().upper()}")
            elif tag == b"\xA1":
                for inner_tag, inner_value, _inner_raw in _items(item_value):
                    if inner_tag == b"\x80":
                        parts.append(f"notifications from seqNumber {_integer(inner_value)}")
                    elif inner_tag == b"\x81":
                        parts.append(f"notifications of operation {inner_value.hex().upper()}")
            elif tag == b"\xA2":
                for inner_tag, inner_value, _inner_raw in _items(item_value):
                    if inner_tag == b"\x80":
                        parts.append(f"package results from seqNumber {_integer(inner_value)}")
            elif tag == b"\x83":
                parts.append(f"transaction {item_value.hex().upper()}")
    except ValueError as error:
        parts.append(f"not readable: {error}")
    rows.append(Detail("BF52", "IpaEuiccDataRequest", ", ".join(parts)))
    return rows, "IpaEuiccDataRequest " + ", ".join(parts)


def _download_trigger_request_rows(raw: bytes) -> tuple[list[Detail], str]:
    parts: list[str] = []
    try:
        _tag, value, _raw = read_single_ber_tlv(raw)
        for tag, item_value, _item_raw in _items(value):
            if tag == b"\xA0":
                for inner_tag, inner_value, _inner_raw in _items(item_value):
                    if inner_tag == b"\x80":
                        parts.append(f"activationCode {_text(inner_value)}")
                    elif inner_tag == b"\x81":
                        parts.append("contactDefaultSmdp")
                    elif inner_tag == b"\xA2":
                        address = next((_text(v) for t, v, _r in _items(inner_value) if t == b"\x80"), "")
                        parts.append("contactSmds" + (f" {address}" if address else ""))
            elif tag == b"\x82":
                parts.append(f"transaction {item_value.hex().upper()}")
    except ValueError as error:
        parts.append(f"not readable: {error}")
    if len(parts) == 0 or all(part.startswith("transaction") for part in parts):
        parts.insert(0, "no profileDownloadData: the IPA downloads through the eIM")
    return [Detail("BF54", "ProfileDownloadTriggerRequest", ", ".join(parts))], "ProfileDownloadTriggerRequest " + ", ".join(parts)


def _get_eim_package_request_rows(body: bytes) -> tuple[list[Detail], str]:
    rows: list[Detail] = []
    parts: list[str] = []
    try:
        request = codec.decode_get_eim_package_request(body)
    except codec.CodecError as error:
        return [Detail("BF4F", "GetEimPackageRequest", f"not readable: {error}")], "not readable"
    if len(request.eid) > 0:
        rows.append(Detail("5A", "eidValue", request.eid))
    if request.notify_state_change:
        rows.append(Detail("80", "notifyStateChange", "present"))
        parts.append("notifyStateChange")
    if request.state_change_cause is not None:
        cause = codec.STATE_CHANGE_CAUSES.get(request.state_change_cause, "unknown")
        rows.append(Detail("81", "stateChangeCause", f"{cause} ({request.state_change_cause})"))
        parts.append(f"cause {cause}")
    if len(request.rplmn) > 0:
        rows.append(Detail("82", "rPLMN", _plmn(request.rplmn)))
        parts.append(f"rPLMN {_plmn(request.rplmn)}")
    return rows, ", ".join(parts)


def _euicc_package_result_rows(raw: bytes) -> tuple[list[Detail], str]:
    """Rows for a EuiccPackageResult 'BF51' (§2.11.2.1), and its folded text."""
    try:
        result = codec.decode_euicc_package_result(raw)
    except codec.CodecError as error:
        return [Detail("BF51", "EuiccPackageResult", f"not readable: {error}")], "EuiccPackageResult (not readable)"
    heading: list[str] = []
    if result.eim_id:
        heading.append(f"eimId {result.eim_id}")
    if result.counter_value is not None:
        heading.append(f"counter {result.counter_value}")
    if result.transaction_id:
        heading.append(f"transaction {result.transaction_id.hex().upper()}")
    if result.seq_number is not None:
        heading.append(f"seqNumber {result.seq_number}")
    rows: list[Detail] = []
    if result.kind == "result":
        rows.append(Detail("BF51", "euiccPackageResultSigned", ", ".join(heading)))
        texts = [item.describe() for item in result.items]
        for item in result.items:
            rows.append(Detail(item.tag, item.name, item.text + (f" ({item.code})" if item.code is not None else "")))
            for profile in item.detail.get("profiles", []) if isinstance(item.detail, dict) else []:
                rows.append(Detail("E3", "ProfileInfo", f"ICCID {profile.get('iccid', '?')} {profile.get('state', '?')} "
                                                       f"{profile.get('class', '')} {profile.get('name', '')}".strip()))
                for other_tag, other_value in (profile.get("other_members") or {}).items():
                    rows.append(Detail(other_tag, "member outside SGP.32 v1.3 §4.4", other_value))
            for eim in item.detail.get("eims", []) if isinstance(item.detail, dict) else []:
                rows.append(Detail("30", "eimId", f"{eim.get('eim_id', '?')} ({eim.get('eim_id_type', '?')})"))
            token = item.detail.get("association_token") if isinstance(item.detail, dict) else None
            if token is not None:
                rows.append(Detail("84", "associationToken", str(token)))
        folded = "; ".join(texts) or "no result data"
    elif result.kind == "error_signed":
        name = codec.EUICC_PACKAGE_ERRORS.get(result.error_code or -1, "unknown")
        rows.append(Detail("BF51", "euiccPackageErrorSigned", ", ".join(heading)))
        rows.append(Detail("02", "euiccPackageErrorCode", f"{name} ({result.error_code})"))
        folded = f"euiccPackageErrorSigned {name}"
    else:
        name = codec.EUICC_PACKAGE_UNSIGNED_ERRORS.get(result.error_code or -1, "unknown")
        rows.append(Detail("BF51", "euiccPackageErrorUnsigned", ", ".join(heading)))
        rows.append(Detail("8F", "euiccPackageUnsignedErrorCode", f"{name} ({result.error_code})"))
        if result.association_token is not None:
            rows.append(Detail("84", "associationToken", str(result.association_token)))
        folded = f"euiccPackageErrorUnsigned {name}"
    if len(result.signature) > 0:
        rows.append(Detail("5F37", "euiccSignEPR" if result.kind == "result" else "euiccSignEPE",
                           _count(len(result.signature), "byte")))
    return rows, folded


def _notification_rows(raw_items: list[bytes]) -> tuple[list[Detail], str]:
    from SCP03.logic.sgp32_decode import decode_pending_notification_list

    rows: list[Detail] = []
    texts: list[str] = []
    for raw in raw_items:
        entries = decode_pending_notification_list(codec.tlv(b"\xA0", raw))
        if len(entries) == 0:
            tag = raw[:2].hex().upper() if raw[:1] and (raw[0] & 0x1F) == 0x1F else raw[:1].hex().upper()
            rows.append(Detail(tag, "PendingNotification", _count(len(raw), "byte")))
            texts.append("PendingNotification")
            continue
        for entry in entries:
            text = " ".join(part for part in (
                entry.get("operation", ""), f"seqNumber {entry['seqNumber']}" if entry.get("seqNumber") else "",
                f"ICCID {entry['iccid']}" if entry.get("iccid") else "",
            ) if part)
            rows.append(Detail("BF2F", "NotificationMetadata", text or "(no fields)"))
            texts.append(text or "notification")
    return rows, "; ".join(texts)


def _eim_package_result_rows(result: codec.EimPackageResult) -> tuple[list[Detail], str]:
    if result.kind in ("euicc_package_result", "epr_and_notifications"):
        rows, folded = _euicc_package_result_rows(result.euicc_package_result)
        if result.kind == "epr_and_notifications":
            rows.insert(0, Detail("30", "ePRAndNotifications", _count(len(result.notifications), "notification")))
            note_rows, note_text = _notification_rows(result.notifications)
            rows.extend(note_rows)
            if note_text:
                folded += f"; {note_text}"
        return rows, folded
    if result.kind == "ipa_euicc_data_response":
        data = codec.decode_ipa_euicc_data_response(result.raw)
        if not data.ok:
            name = codec.IPA_EUICC_DATA_ERRORS.get(data.error_code or -1, "unknown")
            return [Detail("BF52", "ipaEuiccDataResponseError", f"{name} ({data.error_code})")], f"ipaEuiccDataResponse {name}"
        parts = [f"{name} {_count(len(value), 'byte')}" for name, value in data.members.items()]
        if data.package_results:
            parts.append(_count(len(data.package_results), "stored package result"))
        if data.notifications:
            parts.append(_count(len(data.notifications), "notification"))
        rows = [Detail("BF52", "ipaEuiccData", ", ".join(parts) or "nothing")]
        for stored in data.package_results:
            stored_rows, _stored_text = _euicc_package_result_rows(stored)
            rows.extend(stored_rows)
        return rows, "ipaEuiccData: " + (", ".join(parts) or "nothing")
    if result.kind == "profile_download_trigger_result":
        trigger = codec.decode_profile_download_trigger_result(result.raw)
        if trigger.ok:
            return [Detail("BF54", "profileDownloadTriggerResult",
                           f"ProfileInstallationResult {_count(len(trigger.installation_result), 'byte')}")], \
                "profileDownloadTriggerResult: installation result"
        return [Detail("BF54", "profileDownloadTriggerResult", f"error reason {trigger.error_reason}")], \
            f"profileDownloadTriggerResult error {trigger.error_reason}"
    name = codec.EIM_PACKAGE_RESULT_ERRORS.get(result.error_code or -1, "unknown")
    return [Detail("A0", "eimPackageResultResponseError", f"{name} ({result.error_code})")], f"eimPackageResultResponseError {name}"


def _provide_result_request_rows(body: bytes) -> tuple[list[Detail], str]:
    rows: list[Detail] = []
    try:
        request = codec.decode_provide_eim_package_result(body)
    except codec.CodecError as error:
        report = codec.misplaced_get_eim_package_request(body)
        if report is not None:
            inner_rows, inner_text = _get_eim_package_request_rows(codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(report.eid)) if report.eid else b""))
            rows.append(Detail("BF4F", "GetEimPackageRequest", "an IPA state report, not an EimPackageResult (SGP.32 v1.3 §5.14.6)"))
            if report.eid:
                rows.append(Detail("5A", "eidValue", report.eid))
            if len(report.rplmn) > 0:
                rows.append(Detail("82", "rPLMN", _plmn(report.rplmn)))
            if report.notify_state_change:
                rows.append(Detail("80", "notifyStateChange", "present"))
            _ = inner_rows, inner_text
            return rows, "state report (GetEimPackageRequest" + (f", rPLMN {_plmn(report.rplmn)}" if report.rplmn else "") + ")"
        return [Detail("BF50", "ProvideEimPackageResult", f"not readable: {error}")], "not readable"
    if request.eid:
        rows.append(Detail("5A", "eidValue", request.eid))
    result_rows, folded = _eim_package_result_rows(request.result)
    rows.extend(result_rows)
    return rows, folded


def _handle_notification_rows(body: bytes) -> tuple[list[Detail], str]:
    try:
        kind, inner = codec.decode_handle_notification_esipa(body)
    except codec.CodecError as error:
        return [Detail("BF3D", "HandleNotificationEsipa", f"not readable: {error}")], "not readable"
    if kind == "provide_result":
        rows, folded = _provide_result_request_rows(inner)
        rows.insert(0, Detail("BF50", "provideEimPackageResult", ""))
        return rows, folded
    rows, folded = _notification_rows([inner])
    rows.insert(0, Detail("A0", "pendingNotification", ""))
    return rows, folded


# -- answers ----------------------------------------------------------------


def _get_eim_package_response_rows(body: bytes) -> tuple[list[Detail], str, str]:
    """Rows, folded text and the error name ('' when the answer carried a package)."""
    try:
        _tag, value, _raw = read_single_ber_tlv(body)
        inner = _items(value)
    except ValueError as error:
        return [Detail("BF4F", "GetEimPackageResponse", f"not readable: {error}")], "not readable", "not readable"
    if len(inner) == 0:
        return [Detail("BF4F", "GetEimPackageResponse", "empty")], "empty", "empty"
    tag, item_value, item_raw = inner[0]
    if tag == b"\x02":
        code = _integer(item_value)
        name = codec.EIM_PACKAGE_ERRORS.get(code, "unknown")
        # noEimPackageAvailable is the answer to an empty queue, the normal end of a poll: not an error.
        return [Detail("02", "eimPackageError", f"{name} ({code})")], name, "" if code == codec.NO_EIM_PACKAGE_AVAILABLE else name
    if tag == codec.TAG_EUICC_PACKAGE:
        rows, folded = _package_request_rows(item_raw)
        return rows, f"euiccPackageRequest: {folded}", ""
    if tag == codec.TAG_IPA_EUICC_DATA:
        rows, folded = _ipa_data_request_rows(item_raw)
        return rows, folded, ""
    if tag == codec.TAG_PROFILE_DOWNLOAD_TRIGGER:
        rows, folded = _download_trigger_request_rows(item_raw)
        return rows, folded, ""
    return [Detail(tag.hex().upper(), "GetEimPackageResponse", "an alternative SGP.32 v1.3 does not define")], "unknown alternative", "unknown alternative"


def _provide_result_response_rows(body: bytes) -> tuple[list[Detail], str, str]:
    try:
        _tag, value, _raw = read_single_ber_tlv(body)
        inner = _items(value)
    except ValueError as error:
        return [Detail("BF50", "ProvideEimPackageResultResponse", f"not readable: {error}")], "not readable", "not readable"
    if len(inner) == 0:
        return [Detail("BF50", "ProvideEimPackageResultResponse", "empty")], "empty", "empty"
    tag, item_value, _item_raw = inner[0]
    if tag == b"\x02":
        code = _integer(item_value)
        name = codec.PROVIDE_RESULT_ERRORS.get(code, "unknown")
        return [Detail("02", "provideEimPackageResultError", f"{name} ({code})")], name, name
    if tag == b"\x30":
        return [Detail("30", "emptyResponse", "")], "emptyResponse", ""
    if tag == codec.TAG_EIM_ACKNOWLEDGEMENTS:
        text = _acknowledged_text(item_value)
        return [Detail("BF53", "eimAcknowledgements", text)], f"eimAcknowledgements {text}", ""
    return [Detail(tag.hex().upper(), "ProvideEimPackageResultResponse", "an alternative SGP.32 v1.3 does not define")], "unknown alternative", "unknown alternative"


def _acknowledged_text(value: bytes) -> str:
    """The SequenceNumbers of an EimAcknowledgements value (SGP.32 v1.3 §2.11.1.4)."""
    numbers = [_integer(v) for t, v, _r in _items(value) if t == b"\x80"]
    return "seqNumber " + ", ".join(str(number) for number in numbers) if numbers else "none"


def _transfer_request_rows(body: bytes) -> tuple[list[Detail], str]:
    """Rows and folded text for the eIM Package of a TransferEimPackageRequest (SGP.32 v1.3 §6.3.3.1)."""
    try:
        request = esipa_transfer.decode_request(body)
    except esipa_transfer.TransferError as error:
        return [Detail("BF4E", "TransferEimPackageRequest", f"not readable: {error}")], "not readable"
    tag = request.package[:2]
    if tag == codec.TAG_EUICC_PACKAGE:
        rows, folded = _package_request_rows(request.package)
        return rows, f"euiccPackageRequest: {folded}"
    if tag == codec.TAG_IPA_EUICC_DATA:
        return _ipa_data_request_rows(request.package)
    if tag == codec.TAG_PROFILE_DOWNLOAD_TRIGGER:
        return _download_trigger_request_rows(request.package)
    try:
        _tag, value, _raw = read_single_ber_tlv(request.package)
        text = _acknowledged_text(value)
    except ValueError as error:
        text = f"not readable: {error}"
    return [Detail("BF53", "eimAcknowledgements", text)], f"eimAcknowledgements {text}"


def _transfer_response_rows(body: bytes) -> tuple[list[Detail], str, str]:
    """Rows, folded text and the error name ('' unless the IPA answered an error) of a TransferEimPackageResponse."""
    try:
        response = esipa_transfer.decode_response(body)
    except esipa_transfer.TransferError as error:
        return [Detail("BF4E", "TransferEimPackageResponse", f"not readable: {error}")], "not readable", "not readable"
    if response.is_result:
        try:
            rows, folded = _eim_package_result_rows(codec.decode_eim_package_result(response.result))
        except codec.CodecError as error:
            return [Detail(_tag_hex(response.result), response.kind, f"not readable: {error}")], "not readable", "not readable"
        return rows, folded, ""
    correlation = ""
    if len(response.transaction_id) > 0:
        correlation = f"transaction {response.transaction_id.hex().upper()}"
    elif response.eid:
        correlation = f"EID {response.eid}"
    if response.is_received:
        tag = "05" if response.kind == esipa_transfer.RECEIVED else "BF60"
        return [Detail(tag, response.kind, correlation)], response.kind, ""
    tag = "02" if response.kind == esipa_transfer.ERROR else "BF61"
    text = f"{response.error_name} ({response.error_code})"
    return [Detail(tag, response.kind, ", ".join(part for part in (text, correlation) if part))], \
        f"{response.kind} {response.error_name}", response.error_name


# -- the exchange -----------------------------------------------------------


def _root(tag_hex: str, name: str, body: bytes, text: str) -> Detail:
    whole = bytes(body) if 0 < len(body) <= ECHO_LIMIT else b""
    size = _count(len(body), "byte")
    return Detail(tag_hex, name, f"{text}, {size}" if text else size, whole)


def _tag_hex(body: bytes) -> str:
    if len(body) == 0:
        return ""
    width = 2 if (body[0] & 0x1F) == 0x1F and len(body) > 1 else 1
    return body[:width].hex().upper()


def _esipa_asn1(request: bytes, response: bytes, status: int) -> ExchangeView:
    tag = request[:2]
    if tag == esipa_transfer.TAG_TRANSFER_EIM_PACKAGE:
        request_rows, request_text = _transfer_request_rows(request)
        # Status 0: the eIM's call got no HTTP answer at all.
        unanswered = f"HTTP {status}" if status else "no answer"
        answer_rows, answer_text, error = ([], unanswered, unanswered) if len(response) == 0 \
            else _transfer_response_rows(response)
        view = ExchangeView("TransferEimPackageRequest", answer_text, "", error=error)
        view.rows = [_root("BF4E", "TransferEimPackageRequest", request, "sent by the eIM"), *request_rows,
                     _root("BF4E", "TransferEimPackageResponse", response, answer_text), *answer_rows]
        view.summary = f"TransferEimPackageRequest ({request_text}) -> {answer_text}"
        return view
    if tag == codec.TAG_GET_EIM_PACKAGE:
        request_rows, request_text = _get_eim_package_request_rows(request)
        answer_rows, answer_text, error = ([], f"HTTP {status}", f"HTTP {status}") if len(response) == 0 \
            else _get_eim_package_response_rows(response)
        view = ExchangeView("GetEimPackageRequest", answer_text, "", error=error)
        view.rows = [_root("BF4F", "GetEimPackageRequest", request, request_text), *request_rows,
                     _root("BF4F", "GetEimPackageResponse", response, answer_text), *answer_rows]
        view.summary = f"GetEimPackageRequest{f' ({request_text})' if request_text else ''} -> {answer_text}"
        return view
    if tag == codec.TAG_PROVIDE_EIM_PACKAGE_RESULT:
        request_rows, request_text = _provide_result_request_rows(request)
        answer_rows, answer_text, error = ([], f"HTTP {status}", f"HTTP {status}") if len(response) == 0 \
            else _provide_result_response_rows(response)
        view = ExchangeView("ProvideEimPackageResult", answer_text, "", error=error)
        view.rows = [_root("BF50", "ProvideEimPackageResult", request, request_text), *request_rows,
                     _root("BF50", "ProvideEimPackageResultResponse", response, answer_text), *answer_rows]
        view.summary = f"ProvideEimPackageResult ({request_text}) -> {answer_text}"
        return view
    if tag == codec.TAG_HANDLE_NOTIFICATION_ESIPA:
        request_rows, request_text = _handle_notification_rows(request)
        answer_text = f"HTTP {status}" + (", no body" if len(response) == 0 and status == 204 else "")
        error = "" if status == 204 else f"HTTP {status}"
        view = ExchangeView("HandleNotificationEsipa", answer_text, "", error=error)
        view.rows = [_root("BF3D", "HandleNotificationEsipa", request, request_text), *request_rows]
        view.summary = f"HandleNotificationEsipa ({request_text}) -> {answer_text}"
        return view
    if tag in _DOWNLOAD_NAMES:
        name = _DOWNLOAD_NAMES[tag]
        answer_tag = _tag_hex(response)
        answer_text = f"{name}Response" if len(response) > 0 else f"HTTP {status}"
        error = "" if status == 200 and len(response) > 0 else f"HTTP {status}"
        view = ExchangeView(f"{name}Request", answer_text, "", error=error)
        view.rows = [_root(tag.hex().upper(), f"{name}Request", request, "indirect download step (SGP.32 v1.3 §3.2.3.2)"),
                     _root(answer_tag, answer_text, response, "")]
        view.summary = f"{name}Request -> {answer_text}"
        return view
    view = ExchangeView(_tag_hex(request) or "empty", f"HTTP {status}", "", error=f"HTTP {status}" if status != 200 else "")
    view.rows = [_root(_tag_hex(request), "request", request, "not an ESipa message"), _root(_tag_hex(response), "answer", response, "")]
    view.summary = f"{view.request} -> HTTP {status}"
    return view


def _json_keys(body: bytes) -> str:
    try:
        decoded = json.loads(bytes(body).decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return "not JSON"
    if not isinstance(decoded, dict):
        return type(decoded).__name__
    status = decoded.get("header", {}).get("functionExecutionStatus", {}) if isinstance(decoded.get("header"), dict) else {}
    keys = ", ".join(key for key in decoded if key != "header")
    outcome = str(status.get("status", "")) if isinstance(status, dict) else ""
    return ", ".join(part for part in (keys, outcome) if part) or "empty object"


def _json(function: str, request: bytes, response: bytes, status: int) -> ExchangeView:
    answer_text = f"HTTP {status}" + (f": {_json_keys(response)}" if len(response) > 0 else "")
    error = "" if status in (200, 204) else f"HTTP {status}"
    view = ExchangeView(function, answer_text, f"{function} ({_json_keys(request)}) -> {answer_text}", error=error)
    view.rows = [_root("", f"{function} request", request, _json_keys(request)),
                 _root("", f"{function} response", response, _json_keys(response) if response else "")]
    return view


def _es9_asn1(request: bytes, response: bytes, status: int) -> ExchangeView:
    from SCP11.eim_local.engine.es9_binding import function_name

    name = function_name(request)
    answer_text = f"{name}Response" if len(response) > 0 else f"HTTP {status}"
    error = "" if status == 200 and len(response) > 0 or status == 204 else f"HTTP {status}"
    view = ExchangeView(f"{name}Request", answer_text, f"ES9+ {name}Request -> {answer_text}", error=error)
    view.rows = [_root("A2", f"{name}Request", request, "ES9+ over the ASN.1 binding"),
                 _root(_tag_hex(response), answer_text, response, "")]
    return view


def describe_exchange(binding: str, request: bytes, response: bytes, status: int, *, path: str = "") -> ExchangeView:
    """Describe one exchange of *binding*: ``esipa-asn1``, ``esipa-json``, ``es9-asn1`` or ``es9-json``."""
    request = bytes(request or b"")
    response = bytes(response or b"")
    if binding == BINDING_REFUSED:
        view = ExchangeView("request refused", f"HTTP {status}", f"request refused -> HTTP {status}",
                            error=f"HTTP {status}")
        view.rows = [Detail("", "refused", f"HTTP {status}" + (f" on {path}" if path else ""))]
        return view
    if binding == BINDING_ESIPA_ASN1:
        return _esipa_asn1(request, response, int(status))
    if binding == BINDING_ES9_ASN1:
        return _es9_asn1(request, response, int(status))
    function = path.rsplit("/", 1)[-1] or binding
    return _json(function, request, response, int(status))


def describe_record(record: TrafficRecord) -> ExchangeView:
    """The exchange of *record*, with the record's own facts (when, who, over which chain) as the last row."""
    view = describe_exchange(record.binding, record.request, record.response, record.status, path=record.path)
    if record.note.startswith("ES11 "):
        # ES11 shares the ES9+ bindings (SGP.22 v3.1 §6.5.2 Table 57, §6.6.2.6); the listener noted which
        # server took the request, and the bytes of an InitiateAuthentication do not say.
        view.summary = view.summary.replace("ES9+ ", "ES11 ", 1) if view.summary.startswith("ES9+ ") \
            else f"ES11 {view.summary}"
        view.rows = [replace(row, value=row.value.replace("ES9+ over", "ES11 over")) for row in view.rows]
    facts = [f"#{record.id}", f"at {record.at}", f"{record.duration_ms} ms", f"HTTP {record.status}"]
    if record.peer_host or record.peer_port:
        facts.append(f"peer {record.peer_host}:{record.peer_port}")
    if _injected(record):
        secured = " ".join(part for part in (record.tls_version, record.tls_cipher) if part)
        facts.append(f"{secured or 'plain'}, the eIM called")
    elif record.tls_setup or record.tls_version:
        # The first octets of the served leaf's SHA-256, as TLS-SETUP RESULTS lists it.
        leaf = f"leaf {record.tls_leaf[:8]}" if record.tls_leaf else ""
        facts.append(" ".join(part for part in (record.tls_setup, record.tls_version, record.tls_cipher, leaf) if part))
    elif record.listener_port:
        facts.append(f"plain listener :{record.listener_port}")
    else:
        facts.append("plain, the eIM called")
    if record.operation_id is not None:
        facts.append(f"operation {record.operation_id}")
    if record.note:
        facts.append(record.note)
    view.rows.append(Detail("", "exchange", ", ".join(facts)))
    return view


def _injected(record: TrafficRecord) -> bool:
    """Whether the eIM made this call (injection): no listener took it."""
    if record.listener_port:
        return False
    return not record.tls_version or record.note.startswith("injected")


def summary_line(record: TrafficRecord, view: ExchangeView | None = None) -> str:
    """One line for a listing: id, time, peer, chain, the summary."""
    shown = view if view is not None else describe_record(record)
    chain = record.tls_setup or ("plain" if not record.tls_version else record.tls_version)
    if _injected(record):
        # No listener answered: the eIM made the call (injection).
        chain = "inject TLS" if record.tls_version else "inject"
    where = f"{record.peer_host}:{record.peer_port}" if record.peer_host else f":{record.listener_port}"
    return f"#{record.id:<5} {record.at[11:23]}  {where:<21} {chain:<12} {shown.summary}"


def is_error(view: ExchangeView) -> bool:
    return len(view.error) > 0


def rows_as_text(view: ExchangeView, *, hex_bodies: bool = False) -> list[str]:
    """The rows as indented lines for a shell listing; the whole bodies in hex when asked."""
    lines: list[str] = []
    for row in view.rows:
        tag = f"{row.tag:<5}" if row.tag else "     "
        lines.append(f"      {tag} {row.name:<30} {row.value}".rstrip())
        if hex_bodies and len(row.whole) > 0:
            lines.append(f"            {row.whole.hex().upper()}")
    return lines


def describe_package(package: bytes) -> list[Detail]:
    """Rows for a served package: EuiccPackageRequest 'BF51', IpaEuiccDataRequest 'BF52' or ProfileDownloadTriggerRequest 'BF54'."""
    package = bytes(package or b"")
    tag = package[:2]
    if tag == codec.TAG_EUICC_PACKAGE:
        return _package_request_rows(package)[0]
    if tag == codec.TAG_IPA_EUICC_DATA:
        return _ipa_data_request_rows(package)[0]
    if tag == codec.TAG_PROFILE_DOWNLOAD_TRIGGER:
        return _download_trigger_request_rows(package)[0]
    return [Detail(_tag_hex(package), "package", _count(len(package), "byte"))]


def describe_result(result: bytes) -> list[Detail]:
    """Rows for a stored EimPackageResult: the eUICC's result, IPA data or a download trigger result."""
    result = bytes(result or b"")
    try:
        decoded = codec.decode_eim_package_result(result)
    except codec.CodecError as error:
        return [Detail(_tag_hex(result), "result", f"not readable: {error}")]
    return _eim_package_result_rows(decoded)[0]


def tag_names() -> dict[str, Any]:
    """The name tables this module reads a package by, for a test that enumerates the CHOICEs."""
    return {"psmo": dict(PSMO_NAMES), "eco": dict(ECO_NAMES), "download": dict(_DOWNLOAD_NAMES),
            "tag_list": dict(_TAG_LIST_NAMES), "bindings": (BINDING_ESIPA_ASN1, BINDING_ESIPA_JSON,
                                                             BINDING_ES9_ASN1, BINDING_ES9_JSON, BINDING_REFUSED),
            "wrapped": es9_asn1.TAG_REMOTE_PROFILE_PROVISIONING}
