# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DP+ on the ES9+ ASN.1 binding, the one a card's own IPAe speaks.

A direct profile download has the IPA call the SM-DP+ itself (SGP.32 v1.3
§5.6): for an IPAe that is an HTTPS POST of a RemoteProfileProvisioningRequest
'A2' to ``/gsma/rsp2/asn1`` over the bearer the card opened (SGP.22 v3.1 §6,
§6.6.1). ``handle_es9_asn1`` answers one such request from ``LocalSmdp``, the
same SM-DP+ the JSON binding serves, so a download started on either binding
binds the same profile for the same Matching ID.

A step that fails is answered inside the function's own CHOICE: a
transactionId this SM-DP+ did not hand out as invalidTransactionId, anything
else as undefinedError(127) with the cause in the service log. Only a body
that is not one ES9+ function is refused at the HTTP layer.
"""

from __future__ import annotations

import base64
import binascii
from http import HTTPStatus
from typing import Any

from SCP11.eim_local.engine.smdp import LocalSmdp, SmdpAddressError, SmdpError
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_single_ber_tlv

ES9_PREFIX = "/gsma/rsp2/es9plus/"
_FAILURES = (SmdpError, ValueError, OSError, RuntimeError, LookupError)


def _der(value: Any) -> bytes:
    """A field of a LocalSmdp answer: base64, the form its JSON binding returns."""
    text = str(value or "").strip()
    if not text:
        return b""
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SmdpError("The SM-DP+ answered a field that is not base64.") from error


def _key_identifier(value: Any) -> bytes:
    """euiccCiPKIdToBeUsed as LocalSmdp names it: the hex of the identifier or of its '04' data object."""
    text = str(value or "").strip()
    try:
        data = bytes.fromhex(text)
    except ValueError:
        data = _der(text)
    if data[:1] == b"\x04":
        try:
            tag, inner, raw = read_single_ber_tlv(data)
        except (ValueError, IndexError):
            return data
        if tag == b"\x04" and len(raw) == len(data):
            return bytes(inner)
    return data


def function_name(body: bytes) -> str:
    """The ES9+ or ES11 function a wrapped body carries, for a log line; '?' when it is none."""
    names = {
        esipa.TAG_INITIATE_AUTHENTICATION: "InitiateAuthentication",
        esipa.TAG_AUTHENTICATE_CLIENT: "AuthenticateClient",
        esipa.TAG_GET_BOUND_PROFILE_PACKAGE: "GetBoundProfilePackage",
        esipa.TAG_CANCEL_SESSION: "CancelSession",
        esipa.TAG_HANDLE_NOTIFICATION: "HandleNotification",
        # ES11 rides in the same wrapper (SGP.22 v3.1 §6.6.2.8); the SM-DS answers it.
        es9_asn1.TAG_CHECK_EVENT: "CheckEvent",
    }
    try:
        return names.get(es9_asn1.unwrap(body)[:2], "?")
    except es9_asn1.Es9Asn1Error:
        return "?"


def handle_es9_asn1(smdp: LocalSmdp, body: bytes) -> tuple[int, bytes]:
    """Answer one ES9+ request in the ASN.1 binding; return (HTTP status, body)."""
    try:
        function = es9_asn1.unwrap(body)
    except es9_asn1.Es9Asn1Error as error:
        smdp.log(f"ES9+ ASN.1 request refused: {error}")
        return HTTPStatus.BAD_REQUEST, b""
    tag = function[:2]
    if tag == esipa.TAG_INITIATE_AUTHENTICATION:
        return HTTPStatus.OK, _initiate_authentication(smdp, function)
    if tag == esipa.TAG_AUTHENTICATE_CLIENT:
        return HTTPStatus.OK, _authenticate_client(smdp, function)
    if tag == esipa.TAG_GET_BOUND_PROFILE_PACKAGE:
        return HTTPStatus.OK, _bound_profile_package(smdp, function)
    if tag == esipa.TAG_CANCEL_SESSION:
        return HTTPStatus.OK, _cancel_session(smdp, function)
    return _handle_notification(smdp, function)


def _initiate_authentication(smdp: LocalSmdp, function: bytes) -> bytes:
    try:
        request = esipa.decode_initiate_authentication_request(function)
        answer = smdp.handle(ES9_PREFIX + "initiateAuthentication", {
            "euiccChallenge": request.euicc_challenge.hex(),
            "smdpAddress": request.smdp_address,
            "euiccInfo1": request.euicc_info1.hex(),
        })
        return es9_asn1.encode_initiate_authentication_ok(
            transaction_id=_der(answer["transactionId"]),
            server_signed1=_der(answer["serverSigned1"]),
            server_signature1=_der(answer["serverSignature1"]),
            euicc_ci_pkid=_key_identifier(answer.get("euiccCiPKIdToBeUsed")),
            server_certificate=_der(answer["serverCertificate"]),
        )
    except SmdpAddressError as error:
        smdp.log(f"ES9+ ASN.1 InitiateAuthentication refused: {error}")
        return es9_asn1.encode_initiate_authentication_error(es9_asn1.INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS)
    except _FAILURES as error:
        smdp.log(f"ES9+ ASN.1 InitiateAuthentication failed: {error}")
        return es9_asn1.encode_initiate_authentication_error(es9_asn1.UNDEFINED_ERROR)


def _authenticate_client(smdp: LocalSmdp, function: bytes) -> bytes:
    try:
        transaction_id, response = esipa.decode_authenticate_client_request(function)
    except es9_asn1.Es9Asn1Error as error:
        smdp.log(f"ES9+ ASN.1 AuthenticateClient refused: {error}")
        return es9_asn1.encode_authenticate_client_error(es9_asn1.UNDEFINED_ERROR)
    if smdp.transaction(transaction_id) is None:
        smdp.log(f"ES9+ ASN.1 AuthenticateClient: unknown transactionId {transaction_id.hex().upper()}")
        return es9_asn1.encode_authenticate_client_error(es9_asn1.AUTHENTICATE_CLIENT_INVALID_TRANSACTION_ID)
    try:
        answer = smdp.handle(ES9_PREFIX + "authenticateClient", {
            "transactionId": transaction_id.hex(), "authenticateServerResponse": response.hex(),
        })
        metadata = _der(answer.get("profileMetadata"))
        if not metadata:
            # AuthenticateClientOk cannot be encoded without it (SGP.22 v3.1 §6.6.2.2).
            raise SmdpError("no Profile Metadata for the profile this Matching ID selects")
        return es9_asn1.encode_authenticate_client_ok(
            transaction_id=transaction_id,
            profile_metadata=metadata,
            smdp_signed2=_der(answer["smdpSigned2"]),
            smdp_signature2=_der(answer["smdpSignature2"]),
            smdp_certificate=_der(answer["smdpCertificate"]),
        )
    except _FAILURES as error:
        smdp.log(f"ES9+ ASN.1 AuthenticateClient failed: {error}")
        return es9_asn1.encode_authenticate_client_error(es9_asn1.UNDEFINED_ERROR)


def _bound_profile_package(smdp: LocalSmdp, function: bytes) -> bytes:
    try:
        transaction_id, response = esipa.decode_get_bound_profile_package_request(function)
    except es9_asn1.Es9Asn1Error as error:
        smdp.log(f"ES9+ ASN.1 GetBoundProfilePackage refused: {error}")
        return es9_asn1.encode_get_bound_profile_package_error(es9_asn1.UNDEFINED_ERROR)
    if smdp.transaction(transaction_id) is None:
        smdp.log(f"ES9+ ASN.1 GetBoundProfilePackage: unknown transactionId {transaction_id.hex().upper()}")
        return es9_asn1.encode_get_bound_profile_package_error(
            es9_asn1.GET_BOUND_PROFILE_PACKAGE_INVALID_TRANSACTION_ID
        )
    try:
        answer = smdp.handle(ES9_PREFIX + "getBoundProfilePackage", {
            "transactionId": transaction_id.hex(), "prepareDownloadResponse": response.hex(),
        })
        return es9_asn1.encode_get_bound_profile_package_ok(transaction_id, _der(answer["boundProfilePackage"]))
    except _FAILURES as error:
        smdp.log(f"ES9+ ASN.1 GetBoundProfilePackage failed: {error}")
        return es9_asn1.encode_get_bound_profile_package_error(es9_asn1.UNDEFINED_ERROR)


def _cancel_session(smdp: LocalSmdp, function: bytes) -> bytes:
    try:
        transaction_id, response = esipa.decode_cancel_session_request(function)
    except es9_asn1.Es9Asn1Error as error:
        smdp.log(f"ES9+ ASN.1 CancelSession refused: {error}")
        return es9_asn1.encode_cancel_session_error(es9_asn1.UNDEFINED_ERROR)
    if smdp.transaction(transaction_id) is None:
        smdp.log(f"ES9+ ASN.1 CancelSession: unknown transactionId {transaction_id.hex().upper()}")
        return es9_asn1.encode_cancel_session_error(es9_asn1.CANCEL_SESSION_INVALID_TRANSACTION_ID)
    try:
        smdp.handle(ES9_PREFIX + "cancelSession", {
            "transactionId": transaction_id.hex().upper(), "cancelSessionResponse": response.hex(),
        })
    except _FAILURES as error:
        smdp.log(f"ES9+ ASN.1 CancelSession failed: {error}")
        return es9_asn1.encode_cancel_session_error(es9_asn1.UNDEFINED_ERROR)
    return es9_asn1.encode_cancel_session_ok()


def _handle_notification(smdp: LocalSmdp, function: bytes) -> tuple[int, bytes]:
    """HandleNotification has no response (SGP.22 v3.1 §6.6.2.4): HTTP 204, the session it closes dropped."""
    try:
        notification = es9_asn1.decode_handle_notification(function)
    except es9_asn1.Es9Asn1Error as error:
        smdp.log(f"ES9+ ASN.1 HandleNotification refused: {error}")
        return HTTPStatus.BAD_REQUEST, b""
    payload = {"pendingNotification": notification.hex()}
    transaction_id = esipa.installation_result_transaction_id(notification)
    if transaction_id:
        payload["transactionId"] = transaction_id.hex().upper()
    try:
        smdp.handle(ES9_PREFIX + "handleNotification", payload)
    except _FAILURES as error:
        smdp.log(f"ES9+ ASN.1 HandleNotification failed: {error}")
    return HTTPStatus.NO_CONTENT, b""


__all__ = ["function_name", "handle_es9_asn1"]
