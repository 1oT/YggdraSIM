# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ESipa messages of the indirect profile download, for the IPA and the eIM alike.

SGP.32 v1.3 §3.2.3.2 (p.57-64) relays the SGP.22 download through the eIM:
InitiateAuthentication 'BF39', AuthenticateClient 'BF3B', GetBoundProfilePackage
'BF3A' and CancelSession 'BF41' (§5.14.1-§5.14.3, §5.14.8), each a request from
the IPA and a CHOICE answer from the eIM. The module is AUTOMATIC TAGS: a
response's OK alternative is 'A0' and its error INTEGER '81' ('82' for
AuthenticateClient, whose second alternative is the SM-DS one). Inside an OK
SEQUENCE the members carry their universal tags, because some members are
tagged explicitly. The card's AuthenticateServerResponse 'BF38' and
PrepareDownloadResponse 'BF21' travel unchanged; its CancelSessionResponse
'BF41' is re-tagged 'A1', since CancelSessionRequestEsipa has no explicit tag
and gets automatic ones. These encodings were checked against the SGP.32 v1.3
ASN.1 module compiled with SGP.22 v3.1.
"""

from __future__ import annotations

from dataclasses import dataclass

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv, read_single_ber_tlv

TAG_INITIATE_AUTHENTICATION = b"\xBF\x39"
TAG_AUTHENTICATE_CLIENT = b"\xBF\x3B"
TAG_GET_BOUND_PROFILE_PACKAGE = b"\xBF\x3A"
TAG_CANCEL_SESSION = b"\xBF\x41"
TAG_HANDLE_NOTIFICATION = b"\xBF\x3D"
DOWNLOAD_TAGS = (TAG_INITIATE_AUTHENTICATION, TAG_AUTHENTICATE_CLIENT, TAG_GET_BOUND_PROFILE_PACKAGE,
                 TAG_CANCEL_SESSION)

INITIATE_AUTHENTICATION_ERRORS = {
    1: "invalidDpAddress", 2: "euiccVersionNotSupportedByDp", 3: "ciPKIdNotSupported",
    50: "smdpAddressMismatch", 51: "smdpOidMismatch", 52: "invalidEimTransactionId", 127: "undefinedError",
}
AUTHENTICATE_CLIENT_ERRORS = {
    1: "eumCertificateInvalid", 2: "eumCertificateExpired", 3: "euiccCertificateInvalid",
    4: "euiccCertificateExpired", 5: "euiccSignatureInvalid", 6: "matchingIdRefused", 7: "eidMismatch",
    8: "noEligibleProfile", 9: "ciPKUnknown", 10: "invalidTransactionId", 11: "insufficientMemory",
    18: "downloadOrderExpired", 50: "pprNotAllowed", 56: "eventIdUnknown", 127: "undefinedError",
}
GET_BOUND_PROFILE_PACKAGE_ERRORS = {
    1: "euiccSignatureInvalid", 2: "confirmationCodeMissing", 3: "confirmationCodeRefused",
    4: "confirmationCodeRetriesExceeded", 5: "bppRebindingRefused", 6: "deprecated", 50: "metadataMismatch",
    95: "invalidTransactionId", 127: "undefinedError",
}
CANCEL_SESSION_ERRORS = {1: "invalidTransactionId", 2: "euiccSignatureInvalid", 127: "undefinedError"}
UNDEFINED_ERROR = 127


class EsipaDownloadError(ValueError):
    """An indirect download message is malformed, or the eIM answered it with an error code."""

    def __init__(self, message: str, *, code: int | None = None, name: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.name = name


def tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + encode_ber_length(len(value)) + bytes(value)


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        try:
            tag, item_value, raw, offset = read_ber_tlv(value, offset)
        except (ValueError, IndexError) as error:
            raise EsipaDownloadError(f"truncated TLV inside an ESipa message: {error}") from error
        items.append((tag, item_value, raw))
    return items


def _outer(data: bytes, tag: bytes) -> bytes:
    try:
        found, value, raw = read_single_ber_tlv(bytes(data or b""))
    except (ValueError, IndexError) as error:
        raise EsipaDownloadError(f"not one complete TLV: {error}") from error
    if found != tag:
        raise EsipaDownloadError(f"expected '{tag.hex().upper()}', got '{found.hex().upper()}'")
    if len(raw) != len(data):
        raise EsipaDownloadError("trailing bytes after the ESipa message")
    return value


def _integer(value: bytes) -> int:
    if len(value) == 0:
        raise EsipaDownloadError("empty INTEGER")
    return int.from_bytes(value, "big", signed=True)


def _answer_error(step: str, code: int, names: dict[int, str]) -> EsipaDownloadError:
    name = names.get(code, "unknown")
    return EsipaDownloadError(f"ESipa.{step} error {name}({code})", code=code, name=name)


def _error_answer(tag: bytes, error_tag: bytes, code: int) -> bytes:
    body = code.to_bytes(max(1, (code.bit_length() + 8) // 8), "big", signed=True)
    return tlv(tag, tlv(error_tag, body))


def signature_value(data: bytes) -> bytes:
    """The bare signature of a '5F37' data object, or *data* itself when it is already bare."""
    data = bytes(data or b"")
    if data[:2] == b"\x5F\x37":
        try:
            tag, value, raw = read_single_ber_tlv(data)
        except (ValueError, IndexError):
            return data
        if tag == b"\x5F\x37" and len(raw) == len(data):
            return bytes(value)
    return data


# -- InitiateAuthentication 'BF39' (§5.14.1) -------------------------------


@dataclass
class InitiateAuthenticationRequest:
    euicc_challenge: bytes
    smdp_address: str = ""
    euicc_info1: bytes = b""
    eim_transaction_id: bytes = b""


@dataclass
class InitiateAuthenticationOk:
    transaction_id: bytes
    server_signed1: bytes
    server_signature1: bytes
    euicc_ci_pkid: bytes
    server_certificate: bytes
    matching_id: str = ""
    ctx_params1: bytes = b""


def encode_initiate_authentication_request(request: InitiateAuthenticationRequest) -> bytes:
    """'BF39' { '81' euiccChallenge, '83' smdpAddress?, 'BF20' euiccInfo1?, '82' eimTransactionId? }."""
    if len(request.euicc_challenge) != 16:
        raise EsipaDownloadError("euiccChallenge is 16 octets")
    body = tlv(b"\x81", request.euicc_challenge)
    if request.smdp_address:
        body += tlv(b"\x83", request.smdp_address.encode("utf-8"))
    if request.euicc_info1:
        body += bytes(request.euicc_info1)
    if request.eim_transaction_id:
        body += tlv(b"\x82", request.eim_transaction_id)
    return tlv(TAG_INITIATE_AUTHENTICATION, body)


def decode_initiate_authentication_request(data: bytes) -> InitiateAuthenticationRequest:
    request = InitiateAuthenticationRequest(euicc_challenge=b"")
    for tag, value, raw in _children(_outer(data, TAG_INITIATE_AUTHENTICATION)):
        if tag == b"\x81":
            request.euicc_challenge = bytes(value)
        elif tag == b"\x83":
            request.smdp_address = value.decode("utf-8", errors="replace")
        elif tag == b"\xBF\x20":
            request.euicc_info1 = bytes(raw)
        elif tag == b"\x82":
            request.eim_transaction_id = bytes(value)
    if len(request.euicc_challenge) != 16:
        raise EsipaDownloadError("InitiateAuthenticationRequestEsipa without a 16-octet euiccChallenge")
    return request


def encode_initiate_authentication_ok(answer: InitiateAuthenticationOk) -> bytes:
    body = b""
    if answer.transaction_id:
        body += tlv(b"\x80", answer.transaction_id)
    body += bytes(answer.server_signed1)
    body += tlv(b"\x5F\x37", signature_value(answer.server_signature1))
    body += tlv(b"\x04", answer.euicc_ci_pkid)
    body += bytes(answer.server_certificate)
    if answer.matching_id:
        body += tlv(b"\x0C", answer.matching_id.encode("utf-8"))
    if answer.ctx_params1:
        body += bytes(answer.ctx_params1)
    return tlv(TAG_INITIATE_AUTHENTICATION, tlv(b"\xA0", body))


def encode_initiate_authentication_error(code: int) -> bytes:
    return _error_answer(TAG_INITIATE_AUTHENTICATION, b"\x81", code)


def decode_initiate_authentication_response(data: bytes) -> InitiateAuthenticationOk:
    """The OK answer; an error answer raises EsipaDownloadError with its code."""
    choices = _children(_outer(data, TAG_INITIATE_AUTHENTICATION))
    if len(choices) != 1:
        raise EsipaDownloadError("InitiateAuthenticationResponseEsipa is one CHOICE alternative")
    tag, value, _raw = choices[0]
    if tag == b"\x81":
        raise _answer_error("InitiateAuthentication", _integer(value), INITIATE_AUTHENTICATION_ERRORS)
    if tag != b"\xA0":
        raise EsipaDownloadError(f"unknown InitiateAuthenticationResponseEsipa alternative '{tag.hex().upper()}'")
    answer = InitiateAuthenticationOk(b"", b"", b"", b"", b"")
    sequences: list[bytes] = []
    for item_tag, item_value, item_raw in _children(value):
        if item_tag == b"\x80":
            answer.transaction_id = bytes(item_value)
        elif item_tag == b"\x30":
            sequences.append(bytes(item_raw))
        elif item_tag == b"\x5F\x37":
            answer.server_signature1 = bytes(item_value)
        elif item_tag == b"\x04":
            answer.euicc_ci_pkid = bytes(item_value)
        elif item_tag == b"\x0C":
            answer.matching_id = item_value.decode("utf-8", errors="replace")
        elif item_tag == b"\xA2":
            answer.ctx_params1 = bytes(item_raw)
    if len(sequences) != 2 or not answer.server_signature1:
        raise EsipaDownloadError("InitiateAuthenticationOkEsipa lacks serverSigned1, serverSignature1 or the certificate")
    answer.server_signed1, answer.server_certificate = sequences
    return answer


# -- AuthenticateClient 'BF3B' (§5.14.3) -----------------------------------


@dataclass
class AuthenticateClientOk:
    transaction_id: bytes
    smdp_signed2: bytes
    smdp_signature2: bytes
    smdp_certificate: bytes
    profile_metadata: bytes = b""
    hash_cc: bytes = b""


def encode_authenticate_client_request(transaction_id: bytes, authenticate_server_response: bytes) -> bytes:
    """'BF3B' { '80' transactionId, the card's AuthenticateServerResponse 'BF38' unchanged }."""
    if bytes(authenticate_server_response or b"")[:2] != b"\xBF\x38":
        raise EsipaDownloadError("authenticateServerResponse is the card's 'BF38'")
    return tlv(TAG_AUTHENTICATE_CLIENT, tlv(b"\x80", transaction_id) + bytes(authenticate_server_response))


def decode_authenticate_client_request(data: bytes) -> tuple[bytes, bytes]:
    transaction_id = b""
    response = b""
    for tag, value, raw in _children(_outer(data, TAG_AUTHENTICATE_CLIENT)):
        if tag == b"\x80":
            transaction_id = bytes(value)
        elif tag == b"\xBF\x38":
            response = bytes(raw)
    if not transaction_id or not response:
        raise EsipaDownloadError("AuthenticateClientRequestEsipa lacks transactionId or authenticateServerResponse")
    return transaction_id, response


def encode_authenticate_client_ok(answer: AuthenticateClientOk) -> bytes:
    """authenticateClientOkDPEsipa 'A0'; profileMetaData '[37]' keeps the 'BF25' of StoreMetadataRequest."""
    body = tlv(b"\x80", answer.transaction_id) if answer.transaction_id else b""
    if answer.profile_metadata:
        body += bytes(answer.profile_metadata)
    body += bytes(answer.smdp_signed2)
    body += tlv(b"\x5F\x37", signature_value(answer.smdp_signature2))
    body += bytes(answer.smdp_certificate)
    if answer.hash_cc:
        body += tlv(b"\x04", answer.hash_cc)
    return tlv(TAG_AUTHENTICATE_CLIENT, tlv(b"\xA0", body))


def encode_authenticate_client_error(code: int) -> bytes:
    return _error_answer(TAG_AUTHENTICATE_CLIENT, b"\x82", code)


def decode_authenticate_client_response(data: bytes) -> AuthenticateClientOk:
    choices = _children(_outer(data, TAG_AUTHENTICATE_CLIENT))
    if len(choices) != 1:
        raise EsipaDownloadError("AuthenticateClientResponseEsipa is one CHOICE alternative")
    tag, value, _raw = choices[0]
    if tag == b"\x82":
        raise _answer_error("AuthenticateClient", _integer(value), AUTHENTICATE_CLIENT_ERRORS)
    if tag == b"\xA1":
        raise EsipaDownloadError("AuthenticateClient answered for an SM-DS (event retrieval), not an SM-DP+; "
                                 "decode_authenticate_client_ds_response reads it")
    if tag != b"\xA0":
        raise EsipaDownloadError(f"unknown AuthenticateClientResponseEsipa alternative '{tag.hex().upper()}'")
    answer = AuthenticateClientOk(b"", b"", b"", b"")
    sequences: list[bytes] = []
    for item_tag, item_value, item_raw in _children(value):
        if item_tag == b"\x80":
            answer.transaction_id = bytes(item_value)
        elif item_tag == b"\xBF\x25":
            answer.profile_metadata = bytes(item_raw)
        elif item_tag == b"\x30":
            sequences.append(bytes(item_raw))
        elif item_tag == b"\x5F\x37":
            answer.smdp_signature2 = bytes(item_raw)
        elif item_tag == b"\x04":
            answer.hash_cc = bytes(item_value)
    if len(sequences) != 2 or not answer.smdp_signature2:
        raise EsipaDownloadError("AuthenticateClientOkDPEsipa lacks smdpSigned2, smdpSignature2 or the certificate")
    answer.smdp_signed2, answer.smdp_certificate = sequences
    return answer


@dataclass
class AuthenticateClientDsOk:
    """authenticateClientOkDSEsipa (SGP.32 v1.3 §6.3.2.2, p.181): the SM-DS transactionId and, when the eIM
    queued a download for an Event Record, the ProfileDownloadTriggerRequest 'BF54' that starts it."""
    transaction_id: bytes
    profile_download_trigger: bytes = b""


def encode_authenticate_client_ds_ok(answer: AuthenticateClientDsOk) -> bytes:
    """authenticateClientOkDSEsipa 'A1' { transactionId '80', profileDownloadTrigger 'BF54' OPTIONAL }."""
    body = tlv(b"\x80", answer.transaction_id) + bytes(answer.profile_download_trigger)
    return tlv(TAG_AUTHENTICATE_CLIENT, tlv(b"\xA1", body))


def decode_authenticate_client_ds_response(data: bytes) -> AuthenticateClientDsOk:
    choices = _children(_outer(data, TAG_AUTHENTICATE_CLIENT))
    if len(choices) != 1:
        raise EsipaDownloadError("AuthenticateClientResponseEsipa is one CHOICE alternative")
    tag, value, _raw = choices[0]
    if tag == b"\x82":
        raise _answer_error("AuthenticateClient", _integer(value), AUTHENTICATE_CLIENT_ERRORS)
    if tag == b"\xA0":
        raise EsipaDownloadError("AuthenticateClient answered for an SM-DP+ (a download), not an SM-DS")
    if tag != b"\xA1":
        raise EsipaDownloadError(f"unknown AuthenticateClientResponseEsipa alternative '{tag.hex().upper()}'")
    answer = AuthenticateClientDsOk(b"")
    for item_tag, item_value, item_raw in _children(value):
        if item_tag == b"\x80":
            answer.transaction_id = bytes(item_value)
        elif item_tag == b"\xBF\x54":
            answer.profile_download_trigger = bytes(item_raw)
    if len(answer.transaction_id) == 0:
        raise EsipaDownloadError("authenticateClientOkDSEsipa lacks the transactionId")
    return answer


# -- GetBoundProfilePackage 'BF3A' (§5.14.2) -------------------------------


def encode_get_bound_profile_package_request(transaction_id: bytes, prepare_download_response: bytes) -> bytes:
    """'BF3A' { '80' transactionId, the card's PrepareDownloadResponse 'BF21' unchanged }."""
    if bytes(prepare_download_response or b"")[:2] != b"\xBF\x21":
        raise EsipaDownloadError("prepareDownloadResponse is the card's 'BF21'")
    return tlv(TAG_GET_BOUND_PROFILE_PACKAGE, tlv(b"\x80", transaction_id) + bytes(prepare_download_response))


def decode_get_bound_profile_package_request(data: bytes) -> tuple[bytes, bytes]:
    transaction_id = b""
    response = b""
    for tag, value, raw in _children(_outer(data, TAG_GET_BOUND_PROFILE_PACKAGE)):
        if tag == b"\x80":
            transaction_id = bytes(value)
        elif tag == b"\xBF\x21":
            response = bytes(raw)
    if not transaction_id or not response:
        raise EsipaDownloadError("GetBoundProfilePackageRequestEsipa lacks transactionId or prepareDownloadResponse")
    return transaction_id, response


def encode_get_bound_profile_package_ok(transaction_id: bytes, bound_profile_package: bytes) -> bytes:
    if bytes(bound_profile_package or b"")[:2] != b"\xBF\x36":
        raise EsipaDownloadError("boundProfilePackage is a 'BF36'")
    body = (tlv(b"\x80", transaction_id) if transaction_id else b"") + bytes(bound_profile_package)
    return tlv(TAG_GET_BOUND_PROFILE_PACKAGE, tlv(b"\xA0", body))


def encode_get_bound_profile_package_error(code: int) -> bytes:
    return _error_answer(TAG_GET_BOUND_PROFILE_PACKAGE, b"\x81", code)


def decode_get_bound_profile_package_response(data: bytes) -> bytes:
    """The 'BF36' BoundProfilePackage of the OK answer."""
    choices = _children(_outer(data, TAG_GET_BOUND_PROFILE_PACKAGE))
    if len(choices) != 1:
        raise EsipaDownloadError("GetBoundProfilePackageResponseEsipa is one CHOICE alternative")
    tag, value, _raw = choices[0]
    if tag == b"\x81":
        raise _answer_error("GetBoundProfilePackage", _integer(value), GET_BOUND_PROFILE_PACKAGE_ERRORS)
    if tag != b"\xA0":
        raise EsipaDownloadError(f"unknown GetBoundProfilePackageResponseEsipa alternative '{tag.hex().upper()}'")
    for item_tag, _item_value, item_raw in _children(value):
        if item_tag == b"\xBF\x36":
            return bytes(item_raw)
    raise EsipaDownloadError("GetBoundProfilePackageOkEsipa lacks the BoundProfilePackage")


# -- CancelSession 'BF41' (§5.14.8) ----------------------------------------


def encode_cancel_session_request(transaction_id: bytes, cancel_session_response: bytes) -> bytes:
    """'BF41' { '80' transactionId, 'A1' { contents of the card's CancelSessionResponse 'BF41' } }."""
    try:
        tag, value, _raw = read_single_ber_tlv(bytes(cancel_session_response or b""))
    except (ValueError, IndexError) as error:
        raise EsipaDownloadError(f"cancelSessionResponse is not one TLV: {error}") from error
    if tag != TAG_CANCEL_SESSION:
        raise EsipaDownloadError("cancelSessionResponse is the card's 'BF41'")
    return tlv(TAG_CANCEL_SESSION, tlv(b"\x80", transaction_id) + tlv(b"\xA1", value))


def decode_cancel_session_request(data: bytes) -> tuple[bytes, bytes]:
    """transactionId and the card's CancelSessionResponse, tagged 'BF41' again for ES9+."""
    transaction_id = b""
    response = b""
    for tag, value, _raw in _children(_outer(data, TAG_CANCEL_SESSION)):
        if tag == b"\x80":
            transaction_id = bytes(value)
        elif tag == b"\xA1":
            response = tlv(TAG_CANCEL_SESSION, value)
    if not transaction_id or not response:
        raise EsipaDownloadError("CancelSessionRequestEsipa lacks transactionId or cancelSessionResponse")
    return transaction_id, response


def encode_cancel_session_ok() -> bytes:
    return tlv(TAG_CANCEL_SESSION, tlv(b"\xA0", b""))


def encode_cancel_session_error(code: int) -> bytes:
    return _error_answer(TAG_CANCEL_SESSION, b"\x81", code)


def decode_cancel_session_response(data: bytes) -> None:
    choices = _children(_outer(data, TAG_CANCEL_SESSION))
    if len(choices) != 1:
        raise EsipaDownloadError("CancelSessionResponseEsipa is one CHOICE alternative")
    tag, value, _raw = choices[0]
    if tag == b"\x81":
        raise _answer_error("CancelSession", _integer(value), CANCEL_SESSION_ERRORS)
    if tag != b"\xA0":
        raise EsipaDownloadError(f"unknown CancelSessionResponseEsipa alternative '{tag.hex().upper()}'")


# -- HandleNotification 'BF3D' (§5.14.7) -----------------------------------


def encode_handle_notification(pending_notification: bytes) -> bytes:
    """'BF3D' { 'A0' { PendingNotification } }: pendingNotification [0] is an untagged CHOICE, so explicit."""
    return tlv(TAG_HANDLE_NOTIFICATION, tlv(b"\xA0", bytes(pending_notification)))


def installation_result_transaction_id(notification: bytes) -> bytes:
    """transactionId '80' of ProfileInstallationResult 'BF37' { 'BF27' { '80' ... } }, or b''."""
    try:
        tag, value, _raw = read_single_ber_tlv(bytes(notification or b""))
        if tag != b"\xBF\x37":
            return b""
        for item_tag, item_value, _item_raw in _children(value):
            if item_tag != b"\xBF\x27":
                continue
            for field_tag, field_value, _field_raw in _children(item_value):
                if field_tag == b"\x80":
                    return bytes(field_value)
    except (ValueError, IndexError, EsipaDownloadError):
        return b""
    return b""
