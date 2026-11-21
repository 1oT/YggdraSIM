# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ESipa in the JSON binding (SGP.32 v1.3 §6.1.2, §6.4) for the Local eIM.

A function arrives as a POST to its path of Table 28 (§6.4.1) with the <JSON
requestBody> and no requestHeader (§6.1.2). The body is encoded as the
EsipaMessageFromIpaToEim of the ASN.1 binding (§6.3) and answered by the
ASN.1 handler, so both bindings share the engine and the indirect download
relay; the answer is transcoded back. A base64 field carries a DER data object
with its tag and length, the euiccChallenge its value only; transactionId and
eimTransactionId are hexadecimal (§6.4). An error alternative becomes
functionExecutionStatus "Failed" with the status code the function's table
maps to it (SGP.22 v3.1 §6.5.1.4), and GetEimPackage carries it in its body as
eimPackageError too (§6.4.1.5). HandleNotification answers HTTP 204 without a
body. TransferEimPackage is a function of the IPA, not served here; the eIM
calls it from ``inject.py``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from http import HTTPStatus
from typing import Any, Callable

from SCP11.eim_local.engine import codec
from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

CONTENT_TYPE = "application/json;charset=UTF-8"
PATH_PREFIX = "/gsma/rsp2/esipa/"
FUNCTIONS = (
    "initiateAuthentication",
    "authenticateClient",
    "getBoundProfilePackage",
    "getEimPackage",
    "provideEimPackageResult",
    "handleNotification",
    "cancelSession",
)
JSON_PATHS = {PATH_PREFIX + name: name for name in FUNCTIONS}

# (subject code, reason code) per error value of the ASN.1 binding. The ESipa
# codes are the "maps to" rows of SGP.32 v1.3 Table 13a (p.159), §5.14.2 (p.162),
# §5.14.3 (p.165), §5.14.5 (p.170) and §5.14.6 (p.172); the rest are the ES9+
# codes of SGP.22 v3.1 (8.8.1 / 3.8 p.300, 8.10.1 / 3.9 p.303). A value without
# a row (undefinedError) goes out as "Failed" without statusCodeData.
STATUS_CODES: dict[str, dict[int, tuple[str, str]]] = {
    "initiateAuthentication": {
        1: ("8.8.1", "3.8"),
        50: ("8.8.1", "3.10"),
        51: ("8.8", "3.10"),
        52: ("8.31.2", "3.10"),
    },
    "authenticateClient": {10: ("8.10.1", "3.9"), 50: ("8.2.8", "1.2")},
    "getBoundProfilePackage": {50: ("8.2.9", "3.11"), 95: ("8.10.1", "3.9")},
    "cancelSession": {1: ("8.10.1", "3.9")},
    "getEimPackage": {
        codec.NO_EIM_PACKAGE_AVAILABLE: ("8.1.1", "3.7"),
        codec.EID_NOT_FOUND: ("8.1.1", "3.9"),
        codec.INVALID_EID: ("8.1.1", "2.1"),
        codec.MISSING_EID: ("8.1.1", "2.2"),
    },
    "provideEimPackageResult": {
        codec.EID_NOT_FOUND: ("8.1.1", "3.9"),
        codec.INVALID_EID: ("8.1.1", "2.1"),
        codec.MISSING_EID: ("8.1.1", "2.2"),
    },
}

# The error INTEGER alternative of each answer (§6.3.2).
_ERROR_TAGS = {
    "initiateAuthentication": b"\x81",
    "authenticateClient": b"\x82",
    "getBoundProfilePackage": b"\x81",
    "cancelSession": b"\x81",
    "getEimPackage": b"\x02",
    "provideEimPackageResult": b"\x02",
}
_ANSWER_TAGS = {
    "initiateAuthentication": esipa.TAG_INITIATE_AUTHENTICATION,
    "authenticateClient": esipa.TAG_AUTHENTICATE_CLIENT,
    "getBoundProfilePackage": esipa.TAG_GET_BOUND_PROFILE_PACKAGE,
    "cancelSession": esipa.TAG_CANCEL_SESSION,
    "getEimPackage": codec.TAG_GET_EIM_PACKAGE,
    "provideEimPackageResult": codec.TAG_PROVIDE_EIM_PACKAGE_RESULT,
}
_HEX = re.compile(r"^[0-9A-Fa-f]{2,32}$")
_EID = re.compile(r"^[0-9]{32}$")


class JsonRequestError(ValueError):
    """A <JSON requestBody> that does not follow its schema (§6.4.1)."""


class _ErrorAnswer(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def handle_json(function: str, body: bytes, asn1: Callable[[bytes], tuple[int, bytes]]) -> tuple[int, bytes]:
    """Answer one ESipa function of the JSON binding; return (HTTP status, JSON body).

    *asn1* answers an EsipaMessageFromIpaToEim with (HTTP status, answer
    bytes), the handler of the ASN.1 binding.
    """
    if function not in FUNCTIONS:
        raise JsonRequestError(f"ESipa has no JSON function {function!r} served by the eIM")
    try:
        request = json.loads(bytes(body or b"").decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return _malformed(f"the request body is not JSON: {error}")
    if not isinstance(request, dict):
        return _malformed("the request body is not a JSON object")
    try:
        message = encode_request(function, request)
    except _ErrorAnswer as error:
        return HTTPStatus.OK, _dump(_failure(function, error.code))
    except JsonRequestError as error:
        return _malformed(str(error))
    status, answer = asn1(message)
    if function == "handleNotification":
        return (HTTPStatus.NO_CONTENT, b"") if status == HTTPStatus.NO_CONTENT else _malformed(
            "the notification does not decode")
    if status != HTTPStatus.OK or len(answer) == 0:
        return _malformed(f"the ASN.1 handler answered HTTP {int(status)}")
    return HTTPStatus.OK, _dump(decode_response(function, answer))


# -- <JSON requestBody> -> EsipaMessageFromIpaToEim --------------------------


def encode_request(function: str, body: dict[str, Any]) -> bytes:
    """The EsipaMessageFromIpaToEim (§6.3) of a <JSON requestBody>."""
    tlv = codec.tlv
    if function == "initiateAuthentication":
        return esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
            euicc_challenge=_base64(body, "euiccChallenge", required=True),
            smdp_address=_text(body, "smdpAddress"),
            euicc_info1=_base64(body, "euiccInfo1"),
            eim_transaction_id=_hex(body, "eimTransactionId"),
        ))
    if function == "authenticateClient":
        return esipa.encode_authenticate_client_request(
            _hex(body, "transactionId", required=True), _base64(body, "authenticateServerResponse", required=True))
    if function == "getBoundProfilePackage":
        return esipa.encode_get_bound_profile_package_request(
            _hex(body, "transactionId", required=True), _base64(body, "prepareDownloadResponse", required=True))
    if function == "cancelSession":
        return esipa.encode_cancel_session_request(
            _hex(body, "transactionId", required=True), _base64(body, "cancelSessionResponse", required=True))
    if function == "getEimPackage":
        # GetEimPackageRequest 'BF4F' { eidValue '5A', notifyStateChange '80' NULL, stateChangeCause '81',
        # rPLMN '82' } (§6.3.2.6); a request without eidValue is answered missingEid.
        value = _eid(body, function)
        if body.get("notifyStateChange") is True:
            value += tlv(b"\x80", b"")
        cause = body.get("stateChangeCause")
        if cause is not None:
            if not isinstance(cause, int) or isinstance(cause, bool):
                raise JsonRequestError("stateChangeCause is not an integer")
            value += codec.integer_tlv(b"\x81", cause)
        rplmn = _base64(body, "rPlmn")
        if rplmn:
            value += tlv(b"\x82", rplmn)
        return tlv(codec.TAG_GET_EIM_PACKAGE, value)
    if function == "provideEimPackageResult":
        return tlv(codec.TAG_PROVIDE_EIM_PACKAGE_RESULT,
                   _eid(body, function) + _base64(body, "eimPackageResult", required=True))
    if function == "handleNotification":
        pending = _base64(body, "pendingNotification")
        provide = _base64(body, "provideEimPackageResult")
        if bool(pending) == bool(provide):
            raise JsonRequestError("one of pendingNotification and provideEimPackageResult is required")
        # pendingNotification [0] is an untagged CHOICE, so its tag is explicit (§6.3.2.4).
        return tlv(codec.TAG_HANDLE_NOTIFICATION_ESIPA, tlv(b"\xA0", pending) if pending else provide)
    raise JsonRequestError(f"ESipa has no JSON function {function!r} served by the eIM")


def _base64(body: dict[str, Any], name: str, *, required: bool = False) -> bytes:
    value = body.get(name)
    if value is None or value == "":
        if required:
            raise JsonRequestError(f"{name} is missing")
        return b""
    if not isinstance(value, str):
        raise JsonRequestError(f"{name} is not a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise JsonRequestError(f"{name} is not base64: {error}") from error


def _hex(body: dict[str, Any], name: str, *, required: bool = False) -> bytes:
    value = body.get(name)
    if value is None or value == "":
        if required:
            raise JsonRequestError(f"{name} is missing")
        return b""
    if not isinstance(value, str) or not _HEX.match(value) or len(value) % 2:
        raise JsonRequestError(f"{name} is not 1 to 16 bytes in hexadecimal")
    return bytes.fromhex(value)


def _text(body: dict[str, Any], name: str) -> str:
    value = body.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise JsonRequestError(f"{name} is not a string")
    return value


def _eid(body: dict[str, Any], function: str) -> bytes:
    """eidValue '5A' of the request, b'' when absent; a malformed EID is answered invalidEid (p.170, p.172)."""
    value = body.get("eidValue")
    if value is None or value == "":
        return b""
    if not isinstance(value, str) or not _EID.match(value):
        raise _ErrorAnswer(codec.INVALID_EID)
    return codec.tlv(b"\x5A", bytes.fromhex(value))


# -- EsipaMessageFromEimToIpa -> <JSON responseMessage> -----------------------


def decode_response(function: str, answer: bytes) -> dict[str, Any]:
    """The <JSON responseMessage> (header and body) of the ASN.1 answer to *function*."""
    tag, value, _raw = read_single_ber_tlv(bytes(answer))
    if bytes(tag) != _ANSWER_TAGS[function]:
        raise ValueError(f"{function}: the answer is a '{bytes(tag).hex().upper()}'")
    alternatives = _children(bytes(value))
    if len(alternatives) != 1:
        raise ValueError(f"{function}: the answer is one CHOICE alternative")
    alternative, contents, alternative_raw = alternatives[0]
    if alternative == _ERROR_TAGS[function]:
        return _failure(function, int.from_bytes(contents, "big", signed=True))
    body: dict[str, Any] = {}
    if function == "getEimPackage":
        names = {codec.TAG_EUICC_PACKAGE: "euiccPackageRequest", codec.TAG_IPA_EUICC_DATA: "ipaEuiccDataRequest",
                 codec.TAG_PROFILE_DOWNLOAD_TRIGGER: "profileDownloadTriggerRequest"}
        if alternative not in names:
            raise ValueError(f"getEimPackage: unknown alternative '{alternative.hex().upper()}'")
        body[names[alternative]] = _b64(alternative_raw)
    elif function == "provideEimPackageResult":
        if alternative == codec.TAG_EIM_ACKNOWLEDGEMENTS:
            body["eimAcknowledgements"] = _b64(alternative_raw)
    elif function == "cancelSession":
        pass
    else:
        body = _ok_body(function, alternative, contents)
    return {"header": {"functionExecutionStatus": {"status": "Executed-Success"}}, **body}


def _ok_body(function: str, alternative: bytes, contents: bytes) -> dict[str, Any]:
    body: dict[str, Any] = {}
    sequences: list[bytes] = []
    for tag, value, raw in _children(contents):
        if tag == b"\x80":
            body["transactionId"] = value.hex().upper()
        elif tag == b"\x30":
            sequences.append(raw)
        elif tag == b"\x5F\x37":
            body["serverSignature1" if function == "initiateAuthentication" else "smdpSignature2"] = _b64(raw)
        elif tag == b"\x04":
            body["euiccCiPKIdentifierToBeUsed" if function == "initiateAuthentication" else "hashCc"] = _b64(raw)
        elif tag == b"\x0C":
            body["matchingId"] = value.decode("utf-8", errors="replace")
        elif tag == b"\xA2":
            # ctxParams1 [2] is explicit around the CtxParams1 CHOICE; JSON carries the CHOICE.
            body["ctxParams1"] = _b64(value)
        elif tag == b"\xBF\x25":
            body["profileMetadata"] = _b64(raw)
        elif tag == b"\xBF\x36":
            body["boundProfilePackage"] = _b64(raw)
        elif tag == b"\xBF\x54":
            body["profileDownloadTrigger"] = _b64(raw)
    if function == "initiateAuthentication" and len(sequences) == 2:
        body["serverSigned1"], body["serverCertificate"] = _b64(sequences[0]), _b64(sequences[1])
    elif function == "authenticateClient" and alternative == b"\xA0" and len(sequences) == 2:
        body["smdpSigned2"], body["smdpCertificate"] = _b64(sequences[0]), _b64(sequences[1])
    elif sequences:
        raise ValueError(f"{function}: {len(sequences)} SEQUENCE members where the answer has none or two")
    return body


def _failure(function: str, code: int) -> dict[str, Any]:
    status: dict[str, Any] = {"status": "Failed"}
    found = STATUS_CODES.get(function, {}).get(code)
    if found is not None:
        status["statusCodeData"] = {"subjectCode": found[0], "reasonCode": found[1],
                                    "message": _error_name(function, code)}
    message: dict[str, Any] = {"header": {"functionExecutionStatus": status}}
    if function == "getEimPackage":
        message["eimPackageError"] = code
    return message


def _error_name(function: str, code: int) -> str:
    names = {
        "initiateAuthentication": esipa.INITIATE_AUTHENTICATION_ERRORS,
        "authenticateClient": esipa.AUTHENTICATE_CLIENT_ERRORS,
        "getBoundProfilePackage": esipa.GET_BOUND_PROFILE_PACKAGE_ERRORS,
        "cancelSession": esipa.CANCEL_SESSION_ERRORS,
    }.get(function, {})
    return str(names.get(code, f"error {code}"))


def _malformed(reason: str) -> tuple[int, bytes]:
    return HTTPStatus.BAD_REQUEST, _dump({"header": {"functionExecutionStatus": {"status": "Failed"}},
                                          "message": reason})


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item, raw, offset = read_ber_tlv(value, offset)
        items.append((bytes(tag), bytes(item), bytes(raw)))
    return items


def _b64(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _dump(message: dict[str, Any]) -> bytes:
    # §6.4.1.1: only the characters JSON must escape are escaped.
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


__all__ = ["CONTENT_TYPE", "FUNCTIONS", "JSON_PATHS", "STATUS_CODES", "JsonRequestError", "decode_response",
           "encode_request", "handle_json"]
