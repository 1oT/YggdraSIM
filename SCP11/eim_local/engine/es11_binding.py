# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES11 of the local SM-DS on both bindings, told apart from the ES9+ of the SM-DP+ beside it.

ES11 has no path and no wrapper of its own: in the JSON binding its two
functions are posted to the ES9+ paths (SGP.22 v3.1 §6.5.2 Table 57), in the
ASN.1 binding they ride in the same RemoteProfileProvisioningRequest 'A2' on
``/gsma/rsp2/asn1`` (§6.6.2.6, §6.6.2.7). One listener serves both servers, so
a request is the SM-DS's by what it carries: InitiateAuthentication by the
address it names, AuthenticateClient by who handed out its transactionId, and
CheckEvent 'BF46' by its tag (§6.6.2.8). ``claims_json`` and ``claims_asn1``
make that call; everything else stays with the SM-DP+.

A refused function is answered inside its own response: the status code pair
in the JSON header, the function's error INTEGER in the ASN.1 CHOICE. Only a
body that is no function at all is refused at the HTTP layer.
"""

from __future__ import annotations

import base64
import binascii
from http import HTTPStatus
from typing import Any

from SCP11.eim_local.engine.smds import EXECUTION_ERROR, LocalSmds, SmdsError
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

INITIATE_AUTHENTICATION_PATH = "/gsma/rsp2/es9plus/initiateAuthentication"
AUTHENTICATE_CLIENT_PATH = "/gsma/rsp2/es9plus/authenticateClient"
_FAILURES = (ValueError, OSError, RuntimeError, LookupError)
_UNDEFINED_ERROR = 127


def _transaction_id(value: Any) -> bytes:
    """A transactionId as the JSON binding carries it: hex, or base64 from a client that sends that."""
    text = str(value or "").strip()
    if len(text) == 0:
        return b""
    try:
        if len(text) % 2 == 0 and all(character in "0123456789abcdefABCDEF" for character in text):
            return bytes.fromhex(text)
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        return b""


def claims_json(smds: LocalSmds | None, path: str, payload: dict[str, Any]) -> bool:
    """Whether a request posted to an ES9+ path is ES11 for *smds*."""
    if smds is None:
        return False
    name = path.rstrip("/")
    if name == INITIATE_AUTHENTICATION_PATH:
        return smds.owns_address(payload.get("smdpAddress"))
    if name == AUTHENTICATE_CLIENT_PATH:
        transaction_id = _transaction_id(payload.get("transactionId"))
        return len(transaction_id) > 0 and smds.transaction(transaction_id) is not None
    return False


def claims_asn1(smds: LocalSmds | None, body: bytes) -> bool:
    """Whether an 'A2' body is ES11 for *smds*; a body that does not read is left to the SM-DP+ to refuse."""
    if smds is None:
        return False
    try:
        function = es9_asn1.unwrap(body)
        tag = function[:2]
        if tag == es9_asn1.TAG_CHECK_EVENT:
            return True
        if tag == esipa.TAG_INITIATE_AUTHENTICATION:
            return smds.owns_address(esipa.decode_initiate_authentication_request(function).smdp_address)
        if tag == esipa.TAG_AUTHENTICATE_CLIENT:
            transaction_id, _response = esipa.decode_authenticate_client_request(function)
            return smds.transaction(transaction_id) is not None
    except es9_asn1.Es9Asn1Error:
        return False
    return False


def function_name(body: bytes) -> str:
    """The ES11 function an 'A2' body carries, for a log line; '?' when it is none."""
    names = {
        esipa.TAG_INITIATE_AUTHENTICATION: "InitiateAuthentication",
        esipa.TAG_AUTHENTICATE_CLIENT: "AuthenticateClient",
        es9_asn1.TAG_CHECK_EVENT: "CheckEvent",
    }
    try:
        return names.get(es9_asn1.unwrap(body)[:2], "?")
    except es9_asn1.Es9Asn1Error:
        return "?"


def handle_es11_json(smds: LocalSmds, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Answer one ES11 function of the JSON binding; a refusal is the Failed header with its status code pair."""
    try:
        answer = smds.handle(path, payload)
    except SmdsError as error:
        smds.log(f"ES11 {path.rsplit('/', 1)[-1]} refused: {error.status.subject} - {error.status.reason}: {error}")
        return {"header": error.header()}
    except _FAILURES as error:
        smds.log(f"ES11 {path.rsplit('/', 1)[-1]} failed: {type(error).__name__}: {error}")
        return {"header": SmdsError(EXECUTION_ERROR, str(error)).header()}
    answer.setdefault("header", {"functionExecutionStatus": {"status": "Executed-Success"}})
    return answer


def _der(value: Any) -> bytes:
    """A field of a LocalSmds answer: base64 of the encoded data object, as the JSON binding returns it."""
    return base64.b64decode(str(value or ""), validate=True)


def _lpa_rsp_capability(function: bytes) -> bytes:
    """lpaRspCapability '85' of an InitiateAuthenticationRequest 'BF39' as its complete TLV, or b''."""
    _tag, value, _raw = read_single_ber_tlv(function)
    offset = 0
    while offset < len(value):
        tag, _item, raw, offset = read_ber_tlv(value, offset)
        if tag == b"\x85":
            return bytes(raw)
    return b""


def _initiate_authentication(smds: LocalSmds, function: bytes) -> bytes:
    try:
        request = esipa.decode_initiate_authentication_request(function)
        payload: dict[str, Any] = {
            "euiccChallenge": request.euicc_challenge.hex(), "smdpAddress": request.smdp_address,
            "euiccInfo1": request.euicc_info1.hex(),
        }
        capability = _lpa_rsp_capability(function)
        if capability:
            payload["lpaRspCapability"] = capability.hex()
        answer = smds.initiate_authentication(payload)
        key_identifier = _der(answer["euiccCiPKIdToBeUsed"])
        return es9_asn1.encode_initiate_authentication_ok(
            transaction_id=bytes.fromhex(answer["transactionId"]),
            server_signed1=_der(answer["serverSigned1"]),
            server_signature1=_der(answer["serverSignature1"]),
            euicc_ci_pkid=read_single_ber_tlv(key_identifier)[1],
            server_certificate=_der(answer["serverCertificate"]),
        )
    except SmdsError as error:
        smds.log(f"ES11 ASN.1 InitiateAuthentication refused: {error.status.subject} - {error.status.reason}: {error}")
        return es9_asn1.encode_initiate_authentication_error(_UNDEFINED_ERROR if error.asn1 is None else error.asn1)
    except _FAILURES as error:
        smds.log(f"ES11 ASN.1 InitiateAuthentication failed: {type(error).__name__}: {error}")
        return es9_asn1.encode_initiate_authentication_error(_UNDEFINED_ERROR)


def _authenticate_client(smds: LocalSmds, function: bytes) -> bytes:
    try:
        transaction_id, response = esipa.decode_authenticate_client_request(function)
        answer = smds.authenticate_client({
            "transactionId": transaction_id.hex(), "authenticateServerResponse": response.hex(),
        })
        return es9_asn1.encode_authenticate_client_es11_ok(
            transaction_id, [(entry["eventId"], entry["rspServerAddress"]) for entry in answer["eventEntries"]],
        )
    except SmdsError as error:
        smds.log(f"ES11 ASN.1 AuthenticateClient refused: {error.status.subject} - {error.status.reason}: {error}")
        return es9_asn1.encode_authenticate_client_es11_error(_UNDEFINED_ERROR if error.asn1 is None else error.asn1)
    except _FAILURES as error:
        smds.log(f"ES11 ASN.1 AuthenticateClient failed: {type(error).__name__}: {error}")
        return es9_asn1.encode_authenticate_client_es11_error(_UNDEFINED_ERROR)


def _check_event(smds: LocalSmds, function: bytes) -> bytes:
    """CheckEvent: the SM-DS's refusal comes before any look at the input (SGP.22 v3.1 §5.8.3, first bullet),
    so a request that does not read is answered the same way."""
    try:
        ecid, address = es9_asn1.decode_check_event_request(function)
    except es9_asn1.Es9Asn1Error:
        ecid, address = b"", ""
    try:
        return es9_asn1.encode_check_event_ok(smds.check_event(ecid, address))
    except SmdsError as error:
        smds.log(f"ES11 ASN.1 CheckEvent refused: {error.status.subject} - {error.status.reason}")
        return es9_asn1.encode_check_event_error(_UNDEFINED_ERROR if error.asn1 is None else error.asn1)


def handle_es11_asn1(smds: LocalSmds, body: bytes) -> tuple[int, bytes]:
    """Answer one ES11 request in the ASN.1 binding; return (HTTP status, body)."""
    try:
        function = es9_asn1.unwrap(body)
    except es9_asn1.Es9Asn1Error as error:
        smds.log(f"ES11 ASN.1 request refused: {error}")
        return HTTPStatus.BAD_REQUEST, b""
    tag = function[:2]
    if tag == esipa.TAG_INITIATE_AUTHENTICATION:
        return HTTPStatus.OK, _initiate_authentication(smds, function)
    if tag == esipa.TAG_AUTHENTICATE_CLIENT:
        return HTTPStatus.OK, _authenticate_client(smds, function)
    if tag == es9_asn1.TAG_CHECK_EVENT:
        return HTTPStatus.OK, _check_event(smds, function)
    smds.log(f"ES11 ASN.1 request refused: '{tag.hex().upper()}' is no ES11 function")
    return HTTPStatus.BAD_REQUEST, b""


__all__ = ["claims_asn1", "claims_json", "function_name", "handle_es11_asn1", "handle_es11_json"]
