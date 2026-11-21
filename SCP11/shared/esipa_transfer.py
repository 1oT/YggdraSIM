# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ESipa.TransferEimPackage messages, for the eIM that calls and the IPA that answers.

eIM Package Injection (SGP.32 v1.3 §3.1.1.2): the eIM sends one eIM Package in
TransferEimPackageRequest and the IPA returns the eIM Package Result in
TransferEimPackageResponse (§5.14.4), both tag 'BF4E' (§6.3.3.1). The request
is an alternative of EsipaMessageFromEimToIpa and the response one of
EsipaMessageFromIpaToEim (§6.3.1), so neither has a wrapper of its own. The
module is AUTOMATIC TAGS: the response alternatives without a tag keep their
universal one (ePRAndNotifications '30', eimPackageReceived '05',
eimPackageError '02'), and inside the two "WithCid" SEQUENCEs correlationId is
'A0' around its alternative and eimPackageError is '81'. These encodings were
checked against the SGP.32 v1.3 ASN.1 module compiled with SGP.22 v3.1.

The three result alternatives are the forms EimPackageResult has as well
(§6.3.2.7), so a response hands its result on as that TLV and the eIM reads it
with the decoder it has for ProvideEimPackageResult.

JSON binding: §6.4.1.4, on the path of Table 28 (§6.4.1).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv, read_single_ber_tlv

TAG_TRANSFER_EIM_PACKAGE = b"\xBF\x4E"
TAG_EUICC_PACKAGE = b"\xBF\x51"
TAG_IPA_EUICC_DATA = b"\xBF\x52"
TAG_EIM_ACKNOWLEDGEMENTS = b"\xBF\x53"
TAG_PROFILE_DOWNLOAD_TRIGGER = b"\xBF\x54"
TAG_RECEIVED_WITH_CID = b"\xBF\x60"
TAG_ERROR_WITH_CID = b"\xBF\x61"
_TAG_SEQUENCE = b"\x30"
_TAG_NULL = b"\x05"
_TAG_INTEGER = b"\x02"
_TAG_CORRELATION = b"\xA0"
_TAG_TRANSACTION_ID = b"\x80"
_TAG_EID = b"\x5A"
_TAG_ERROR_IN_SEQUENCE = b"\x81"

# TransferEimPackageRequest (SGP.32 v1.3 §6.3.3.1): the eIM Package by its tag, 4 of 4.
REQUEST_ALTERNATIVES: dict[bytes, str] = {
    TAG_EUICC_PACKAGE: "euiccPackageRequest",
    TAG_IPA_EUICC_DATA: "ipaEuiccDataRequest",
    TAG_EIM_ACKNOWLEDGEMENTS: "eimAcknowledgements",
    TAG_PROFILE_DOWNLOAD_TRIGGER: "profileDownloadTriggerRequest",
}

# TransferEimPackageResponse (SGP.32 v1.3 §6.3.3.1), 7 of 7, in the order of the CHOICE.
RESULT_EUICC_PACKAGE = "euiccPackageResult"
RESULT_WITH_NOTIFICATIONS = "ePRAndNotifications"
RESULT_IPA_EUICC_DATA = "ipaEuiccDataResponse"
RECEIVED = "eimPackageReceived"
RECEIVED_WITH_CID = "eimPackageReceivedWithCid"
ERROR = "eimPackageError"
ERROR_WITH_CID = "eimPackageErrorWithCid"
RESPONSE_ALTERNATIVES: tuple[str, ...] = (
    RESULT_EUICC_PACKAGE, RESULT_WITH_NOTIFICATIONS, RESULT_IPA_EUICC_DATA, RECEIVED, RECEIVED_WITH_CID, ERROR,
    ERROR_WITH_CID,
)
_RESULT_TAGS: dict[bytes, str] = {
    TAG_EUICC_PACKAGE: RESULT_EUICC_PACKAGE,
    _TAG_SEQUENCE: RESULT_WITH_NOTIFICATIONS,
    TAG_IPA_EUICC_DATA: RESULT_IPA_EUICC_DATA,
}

# EimPackageResultErrorCode (SGP.32 v1.3 Annex C), 3 of 3.
INVALID_PACKAGE_FORMAT = 1
UNKNOWN_PACKAGE = 2
UNDEFINED_ERROR = 127
EIM_PACKAGE_ERRORS: dict[int, str] = {
    INVALID_PACKAGE_FORMAT: "invalidPackageFormat",
    UNKNOWN_PACKAGE: "unknownPackage",
    UNDEFINED_ERROR: "undefinedError",
}

# Table 19a (SGP.32 v1.3 §5.14.4), 2 of 2: error value -> (subject code, reason code).
# undefinedError has no row and goes out as "Failed" without statusCodeData.
STATUS_CODES: dict[int, tuple[str, str]] = {
    INVALID_PACKAGE_FORMAT: ("8.31.1", "2.1"),
    UNKNOWN_PACKAGE: ("8.31.1", "1.1"),
}

PATH_ASN1 = "/gsma/rsp2/asn1"
PATH_JSON = "/gsma/rsp2/esipa/transferEimPackage"
CONTENT_TYPE_ASN1 = "application/x-gsma-rsp-asn1"
CONTENT_TYPE_JSON = "application/json;charset=UTF-8"
# SGP.32 v1.3 §6.1: X-Admin-Protocol is the highest version of SGP.32 the sender supports.
ADMIN_PROTOCOL = "gsma/rsp/v1.3.0"

_EID_DIGITS = re.compile(r"^[0-9]{32}$")


def is_loopback(host: str) -> bool:
    """Whether *host* is ``localhost`` or an address of the loopback network.

    Both ends of this version keep to it: the eIM calls no other address and
    the IPA binds no other one.
    """
    text = str(host or "").strip()
    if text.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


class TransferError(ValueError):
    """A TransferEimPackage message that does not follow SGP.32 v1.3 §6.3.3.1 or §6.4.1.4."""


class UnknownPackage(TransferError):
    """A request whose data object is none of Table 18: "8.31.1 eIM Package - 1.1 Unknown" (§5.14.4)."""


@dataclass(frozen=True)
class TransferRequest:
    """One eIM Package on its way to the IPA: its alternative and the package TLV."""

    kind: str
    package: bytes


@dataclass(frozen=True)
class TransferResponse:
    """What the IPA answered.

    ``result`` is set for the three result alternatives and is the TLV an
    EimPackageResult carries for the same alternative. ``transaction_id`` and
    ``eid`` are the correlationId of a "WithCid" alternative, at most one of them.
    """

    kind: str
    result: bytes = b""
    transaction_id: bytes = b""
    eid: str = ""
    error_code: int | None = None

    @property
    def is_result(self) -> bool:
        return self.kind in (RESULT_EUICC_PACKAGE, RESULT_WITH_NOTIFICATIONS, RESULT_IPA_EUICC_DATA)

    @property
    def is_received(self) -> bool:
        return self.kind in (RECEIVED, RECEIVED_WITH_CID)

    @property
    def is_error(self) -> bool:
        return self.kind in (ERROR, ERROR_WITH_CID)

    @property
    def error_name(self) -> str:
        if self.error_code is None:
            return ""
        return EIM_PACKAGE_ERRORS.get(self.error_code, f"error {self.error_code}")


def _tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + encode_ber_length(len(value)) + bytes(value)


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item, raw, offset = read_ber_tlv(value, offset)
        items.append((bytes(tag), bytes(item), bytes(raw)))
    return items


def _single(data: bytes, label: str) -> tuple[bytes, bytes, bytes]:
    try:
        tag, value, raw = read_single_ber_tlv(bytes(data or b""))
    except ValueError as error:
        raise TransferError(f"{label}: {error}") from error
    return bytes(tag), bytes(value), bytes(raw)


def _alternative(data: bytes, label: str) -> tuple[bytes, bytes, bytes]:
    """The one alternative inside a 'BF4E' message as (tag, contents, TLV)."""
    tag, value, _raw = _single(data, label)
    if tag != TAG_TRANSFER_EIM_PACKAGE:
        raise TransferError(f"{label}: tag '{tag.hex().upper()}' is not 'BF4E'")
    try:
        alternatives = _children(value)
    except ValueError as error:
        raise TransferError(f"{label}: {error}") from error
    if len(alternatives) != 1:
        raise TransferError(f"{label}: one CHOICE alternative expected, {len(alternatives)} found")
    return alternatives[0]


def _eid_bytes(eid: str) -> bytes:
    text = str(eid or "").strip()
    if not _EID_DIGITS.match(text):
        raise TransferError("an EID is 32 digits")
    return bytes.fromhex(text)


def _correlation(transaction_id: bytes, eid: str) -> bytes:
    """correlationId as it sits in a "WithCid" SEQUENCE: 'A0' around its alternative, or nothing.

    The eimTransactionId when the eIM Package carried one, the EID otherwise
    (SGP.32 v1.3 §5.14.4), so a caller may pass both.
    """
    if len(transaction_id) > 0:
        return _tlv(_TAG_CORRELATION, _tlv(_TAG_TRANSACTION_ID, bytes(transaction_id)))
    if eid:
        return _tlv(_TAG_CORRELATION, _tlv(_TAG_EID, _eid_bytes(eid)))
    return b""


def _read_correlation(contents: bytes, label: str) -> tuple[bytes, str]:
    try:
        inner = _children(contents)
    except ValueError as error:
        raise TransferError(f"{label}: {error}") from error
    if len(inner) != 1:
        raise TransferError(f"{label}: correlationId holds one alternative")
    tag, value, _raw = inner[0]
    if tag == _TAG_TRANSACTION_ID:
        return value, ""
    if tag == _TAG_EID and len(value) == 16:
        return b"", value.hex().upper()
    raise TransferError(f"{label}: correlationId alternative '{tag.hex().upper()}' is not defined")


def _integer(contents: bytes, label: str) -> int:
    if len(contents) == 0:
        raise TransferError(f"{label}: an INTEGER has contents")
    return int.from_bytes(contents, "big", signed=True)


# ---- ASN.1 binding ----------------------------------------------------------------------------------

def build_request(package: bytes) -> bytes:
    """TransferEimPackageRequest 'BF4E' around one eIM Package TLV."""
    tag, _value, raw = _single(package, "eIM Package")
    if tag not in REQUEST_ALTERNATIVES:
        raise TransferError(f"eIM Package tag '{tag.hex().upper()}' is no alternative of TransferEimPackageRequest")
    return _tlv(TAG_TRANSFER_EIM_PACKAGE, raw)


def decode_request(data: bytes) -> TransferRequest:
    """The eIM Package of a TransferEimPackageRequest."""
    tag, _value, raw = _alternative(data, "TransferEimPackageRequest")
    if tag not in REQUEST_ALTERNATIVES:
        raise UnknownPackage(f"TransferEimPackageRequest alternative '{tag.hex().upper()}' is not defined")
    return TransferRequest(kind=REQUEST_ALTERNATIVES[tag], package=raw)


def build_result_response(result: bytes) -> bytes:
    """TransferEimPackageResponse around a result TLV: 'BF51', '30' { 'BF51', 'A0' } or 'BF52'."""
    tag, value, raw = _single(result, "eIM Package Result")
    if tag not in _RESULT_TAGS:
        raise TransferError(f"result tag '{tag.hex().upper()}' is no result alternative of TransferEimPackageResponse")
    if tag == _TAG_SEQUENCE:
        _check_result_with_notifications(value)
    return _tlv(TAG_TRANSFER_EIM_PACKAGE, raw)


def _check_result_with_notifications(contents: bytes) -> None:
    try:
        tags = [tag for tag, _value, _raw in _children(contents)]
    except ValueError as error:
        raise TransferError(f"ePRAndNotifications: {error}") from error
    if tags != [TAG_EUICC_PACKAGE, _TAG_CORRELATION]:
        raise TransferError("ePRAndNotifications is euiccPackageResult 'BF51' followed by notificationList 'A0'")


def build_received_response(*, transaction_id: bytes = b"", eid: str = "", with_cid: bool = True) -> bytes:
    """eimPackageReceivedWithCid, or the plain eimPackageReceived of IPAs of earlier versions."""
    if not with_cid:
        return _tlv(TAG_TRANSFER_EIM_PACKAGE, _tlv(_TAG_NULL, b""))
    return _tlv(TAG_TRANSFER_EIM_PACKAGE, _tlv(TAG_RECEIVED_WITH_CID, _correlation(bytes(transaction_id), eid)))


def build_error_response(code: int, *, transaction_id: bytes = b"", eid: str = "", with_cid: bool = True) -> bytes:
    """eimPackageErrorWithCid, or the plain eimPackageError of IPAs of earlier versions."""
    if code not in EIM_PACKAGE_ERRORS:
        raise TransferError(f"eimPackageError {code} is not defined")
    value = int(code).to_bytes(1, "big")
    if not with_cid:
        return _tlv(TAG_TRANSFER_EIM_PACKAGE, _tlv(_TAG_INTEGER, value))
    body = _correlation(bytes(transaction_id), eid) + _tlv(_TAG_ERROR_IN_SEQUENCE, value)
    return _tlv(TAG_TRANSFER_EIM_PACKAGE, _tlv(TAG_ERROR_WITH_CID, body))


def decode_response(data: bytes) -> TransferResponse:
    """One TransferEimPackageResponse alternative."""
    label = "TransferEimPackageResponse"
    tag, value, raw = _alternative(data, label)
    if tag in _RESULT_TAGS:
        if tag == _TAG_SEQUENCE:
            _check_result_with_notifications(value)
        return TransferResponse(kind=_RESULT_TAGS[tag], result=raw)
    if tag == _TAG_NULL:
        if len(value) != 0:
            raise TransferError(f"{label}: eimPackageReceived is NULL")
        return TransferResponse(kind=RECEIVED)
    if tag == _TAG_INTEGER:
        return TransferResponse(kind=ERROR, error_code=_integer(value, label))
    if tag not in (TAG_RECEIVED_WITH_CID, TAG_ERROR_WITH_CID):
        raise TransferError(f"{label} alternative '{tag.hex().upper()}' is not defined")
    try:
        members = _children(value)
    except ValueError as error:
        raise TransferError(f"{label}: {error}") from error
    transaction_id, eid = b"", ""
    if members and members[0][0] == _TAG_CORRELATION:
        transaction_id, eid = _read_correlation(members[0][1], label)
        members = members[1:]
    if tag == TAG_RECEIVED_WITH_CID:
        if members:
            raise TransferError(f"{label}: eimPackageReceivedWithCid holds a correlationId and nothing else")
        return TransferResponse(kind=RECEIVED_WITH_CID, transaction_id=transaction_id, eid=eid)
    if len(members) != 1 or members[0][0] != _TAG_ERROR_IN_SEQUENCE:
        raise TransferError(f"{label}: eimPackageErrorWithCid ends with eimPackageError '81'")
    return TransferResponse(kind=ERROR_WITH_CID, transaction_id=transaction_id, eid=eid,
                            error_code=_integer(members[0][1], label))


def result_as_response(result: bytes, *, transaction_id: bytes = b"", eid: str = "") -> bytes:
    """A TransferEimPackageResponse for what an EimPackageResult would carry (§6.3.2.7).

    'BF51', '30' { 'BF51', 'A0' } and 'BF52' go out as they are. The error
    form 'A0' { ['80' eimTransactionId] '02' code } becomes
    eimPackageErrorWithCid, with the transaction it names or *transaction_id*,
    else *eid*. A ProfileDownloadTriggerResult 'BF54' has no alternative here.
    """
    tag, value, _raw = _single(result, "eIM Package Result")
    if tag != _TAG_CORRELATION:
        return build_result_response(result)
    try:
        members = _children(value)
    except ValueError as error:
        raise TransferError(f"eimPackageResultResponseError: {error}") from error
    named = b""
    code: int | None = None
    for member_tag, member, _member_raw in members:
        if member_tag == _TAG_TRANSACTION_ID:
            named = member
        elif member_tag == _TAG_INTEGER:
            code = _integer(member, "eimPackageResultResponseError")
    if code is None:
        raise TransferError("eimPackageResultResponseError carries no error code")
    if code not in EIM_PACKAGE_ERRORS:
        code = UNDEFINED_ERROR
    return build_error_response(code, transaction_id=named or bytes(transaction_id), eid=eid)


def error_as_result(response: TransferResponse) -> bytes:
    """An error answer as the eimPackageResultResponseError of EimPackageResult (§6.3.2.7).

    'A0' { ['80' eimTransactionId] '02' code }: the form the eIM's result
    decoder takes for a package the IPA could not run.
    """
    if not response.is_error or response.error_code is None:
        raise TransferError("only an error answer has an error form")
    body = b""
    if len(response.transaction_id) > 0:
        body += _tlv(_TAG_TRANSACTION_ID, response.transaction_id)
    body += _tlv(_TAG_INTEGER, int(response.error_code).to_bytes(1, "big", signed=True))
    return _tlv(_TAG_CORRELATION, body)


# ---- JSON binding (SGP.32 v1.3 §6.4.1.4) --------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _from_b64(body: dict[str, Any], name: str) -> bytes:
    value = body.get(name)
    if not isinstance(value, str):
        raise TransferError(f"{name} is a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise TransferError(f"{name} is not base64: {error}") from error


def request_to_json(data: bytes) -> dict[str, Any]:
    """The <JSON requestBody> of a TransferEimPackageRequest."""
    request = decode_request(data)
    return {request.kind: _b64(request.package)}


def request_from_json(body: Any) -> bytes:
    """A TransferEimPackageRequest from its <JSON requestBody>: exactly one of the four members."""
    if not isinstance(body, dict):
        raise TransferError("the request body is a JSON object")
    present = [name for name in REQUEST_ALTERNATIVES.values() if name in body]
    if len(present) != 1:
        raise TransferError("the request body holds exactly one eIM Package member")
    package = _from_b64(body, present[0])
    tag, _value, _raw = _single(package, present[0])
    if REQUEST_ALTERNATIVES.get(tag) != present[0]:
        raise TransferError(f"{present[0]} does not hold a '{tag.hex().upper()}' data object")
    return build_request(package)


def _header(error_code: int | None) -> dict[str, Any]:
    if error_code is None:
        return {"functionExecutionStatus": {"status": "Executed-Success"}}
    status: dict[str, Any] = {"status": "Failed"}
    found = STATUS_CODES.get(error_code)
    if found is not None:
        status["statusCodeData"] = {"subjectCode": found[0], "reasonCode": found[1],
                                    "message": EIM_PACKAGE_ERRORS.get(error_code, f"error {error_code}")}
    return {"functionExecutionStatus": status}


def response_to_json(data: bytes) -> dict[str, Any]:
    """The <JSON responseMessage> (header and body) of a TransferEimPackageResponse."""
    response = decode_response(data)
    message: dict[str, Any] = {"header": _header(response.error_code if response.is_error else None)}
    if response.kind == RESULT_WITH_NOTIFICATIONS:
        _tag, value, _raw = _single(response.result, RESULT_WITH_NOTIFICATIONS)
        result, notifications = _children(value)
        message[RESULT_WITH_NOTIFICATIONS] = {"euiccPackageResult": _b64(result[2]), "notificationList": _b64(notifications[2])}
    elif response.is_result:
        message[response.kind] = _b64(response.result)
    elif response.is_received:
        # The schema gives both acknowledgements as an object without members.
        message[response.kind] = {}
    elif response.kind == ERROR:
        message[ERROR] = int(response.error_code or UNDEFINED_ERROR)
    else:
        _tag, _value, alternative = _alternative(data, "TransferEimPackageResponse")
        message[ERROR_WITH_CID] = _b64(alternative)
    return message


def response_from_json(message: Any) -> bytes:
    """A TransferEimPackageResponse from a <JSON responseMessage>.

    A body member wins. Without one, a "Failed" header is read through Table
    19a, and "Failed" without a code it names is undefinedError.
    """
    if not isinstance(message, dict):
        raise TransferError("the response message is a JSON object")
    present = [name for name in RESPONSE_ALTERNATIVES if name in message]
    if len(present) > 1:
        raise TransferError("the response body holds one member")
    if not present:
        status = ((message.get("header") or {}).get("functionExecutionStatus") or {}) if isinstance(
            message.get("header"), dict) else {}
        if not isinstance(status, dict) or status.get("status") != "Failed":
            raise TransferError("the response body holds no member and the header reports no failure")
        data = status.get("statusCodeData") if isinstance(status.get("statusCodeData"), dict) else {}
        pair = (str(data.get("subjectCode", "")), str(data.get("reasonCode", "")))
        code = next((value for value, found in STATUS_CODES.items() if found == pair), UNDEFINED_ERROR)
        return build_error_response(code, with_cid=False)
    name = present[0]
    if name == RESULT_WITH_NOTIFICATIONS:
        member = message[name]
        if not isinstance(member, dict):
            raise TransferError("ePRAndNotifications is an object")
        result = _from_b64(member, "euiccPackageResult")
        notifications = _from_b64(member, "notificationList")
        return build_result_response(_tlv(_TAG_SEQUENCE, result + notifications))
    if name in (RESULT_EUICC_PACKAGE, RESULT_IPA_EUICC_DATA):
        result = _from_b64(message, name)
        tag, _value, _raw = _single(result, name)
        if _RESULT_TAGS.get(tag) != name:
            raise TransferError(f"{name} does not hold a '{tag.hex().upper()}' data object")
        return build_result_response(result)
    if name == RECEIVED:
        return build_received_response(with_cid=False)
    if name == RECEIVED_WITH_CID:
        return build_received_response()
    if name == ERROR:
        code = message[name]
        if isinstance(code, bool) or not isinstance(code, int):
            raise TransferError("eimPackageError is an integer")
        if code not in EIM_PACKAGE_ERRORS:
            raise TransferError(f"eimPackageError {code} is not defined")
        return build_error_response(code, with_cid=False)
    alternative = _from_b64(message, ERROR_WITH_CID)
    data = _tlv(TAG_TRANSFER_EIM_PACKAGE, alternative)
    if decode_response(data).kind != ERROR_WITH_CID:
        raise TransferError("eimPackageErrorWithCid does not hold a 'BF61' data object")
    return data


__all__ = [
    "ADMIN_PROTOCOL", "CONTENT_TYPE_ASN1", "CONTENT_TYPE_JSON", "EIM_PACKAGE_ERRORS", "ERROR", "ERROR_WITH_CID",
    "INVALID_PACKAGE_FORMAT",
    "PATH_ASN1", "PATH_JSON", "RECEIVED", "RECEIVED_WITH_CID", "REQUEST_ALTERNATIVES", "RESPONSE_ALTERNATIVES",
    "RESULT_EUICC_PACKAGE", "RESULT_IPA_EUICC_DATA", "RESULT_WITH_NOTIFICATIONS", "STATUS_CODES", "TAG_TRANSFER_EIM_PACKAGE",
    "TransferError", "TransferRequest", "TransferResponse", "UNDEFINED_ERROR", "UNKNOWN_PACKAGE", "UnknownPackage",
    "build_error_response", "build_received_response", "build_request", "build_result_response", "decode_request",
    "decode_response", "error_as_result", "is_loopback", "request_from_json", "request_to_json",
    "response_from_json", "response_to_json", "result_as_response",
]
