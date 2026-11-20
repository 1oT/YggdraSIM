# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES9+ in its ASN.1 binding (SGP.22 v3.1 §6.6), for an SM-DP+ and for the LPA or IPA calling it.

One HTTP POST to ``/gsma/rsp2/asn1`` carries a RemoteProfileProvisioningRequest
'A2' and is answered with a RemoteProfileProvisioningResponse 'A2' (§6.6.1);
SGP.32 v1.3 §6 keeps this binding for an IPA on ES9+, and it is the one a
card's own IPAe speaks. Inside the 'A2' sits one function: InitiateAuthentication
'BF39', AuthenticateClient 'BF3B', GetBoundProfilePackage 'BF3A', CancelSession
'BF41' or HandleNotification 'BF3D' (§6.6.2.1-§6.6.2.5).

The functions are the ESipa ones of the indirect download without the eIM's
additions, so ``esipa_download`` encodes and decodes most of them. Two things
differ: the 'A2' wrapper, which ESipa does not have, and the error INTEGER of
AuthenticateClientResponseEs9, which is the second CHOICE alternative '81'
(ESipa puts the SM-DS answer there and the error third, '82'). These encodings
were checked against the SGP.22 v3.1 module of the pinned pySim.

ES11 rides in the same wrapper (§6.6.2.6-§6.6.2.8): its InitiateAuthentication
and its AuthenticateClient request are the ES9+ ones, the SM-DS answers
AuthenticateClient with AuthenticateClientResponseEs11 'BF40', and CheckEvent
'BF46' is its own function.
"""

from __future__ import annotations

from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

TAG_REMOTE_PROFILE_PROVISIONING = b"\xA2"
TAG_AUTHENTICATE_CLIENT_ES11 = b"\xBF\x40"
TAG_CHECK_EVENT = b"\xBF\x46"
FUNCTION_TAGS = (
    esipa.TAG_INITIATE_AUTHENTICATION,
    esipa.TAG_AUTHENTICATE_CLIENT,
    esipa.TAG_GET_BOUND_PROFILE_PACKAGE,
    esipa.TAG_CANCEL_SESSION,
    esipa.TAG_HANDLE_NOTIFICATION,
    TAG_AUTHENTICATE_CLIENT_ES11,
    TAG_CHECK_EVENT,
)

# SGP.22 v3.1 §6.6.2.2-§6.6.2.5; invalidTransactionId has its own number per function.
AUTHENTICATE_CLIENT_INVALID_TRANSACTION_ID = 10
GET_BOUND_PROFILE_PACKAGE_INVALID_TRANSACTION_ID = 95
CANCEL_SESSION_INVALID_TRANSACTION_ID = 1
UNDEFINED_ERROR = esipa.UNDEFINED_ERROR
# initiateAuthenticationError invalidDpAddress (§6.6.2.1, the table below).
INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS = 1

AUTHENTICATE_CLIENT_ERRORS = {
    1: "eumCertificateInvalid", 2: "eumCertificateExpired", 3: "euiccCertificateInvalid",
    4: "euiccCertificateExpired", 5: "euiccSignatureInvalid", 6: "matchingIdRefused", 7: "eidMismatch",
    8: "noEligibleProfile", 9: "ciPKUnknown", 10: "invalidTransactionId", 11: "insufficientMemory",
    12: "ciPKMismatch", 13: "euiccRspCapabilityHasChanged", 14: "lpaRspCapabilityHasChanged",
    124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError",
}

# The error INTEGERs of the functions an SM-DS answers, SGP.22 v3.1 §6.6.2.1, §6.6.2.7 and §6.6.2.8.
INITIATE_AUTHENTICATION_ERRORS = {
    1: "invalidDpAddress", 2: "euiccVersionNotSupportedByDp", 3: "ciPKIdNotSupported",
    124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError",
}
ES11_AUTHENTICATE_CLIENT_ERRORS = {
    1: "eumCertificateInvalid", 2: "eumCertificateExpired", 3: "euiccCertificateInvalid",
    4: "euiccCertificateExpired", 5: "euiccSignatureInvalid", 6: "eventIdUnknown", 7: "invalidTransactionId",
    8: "ciPKUnknown", 9: "ciPKMismatch", 10: "euiccRspCapabilityHasChanged", 11: "lpaRspCapabilityHasChanged",
    12: "pushServiceNotSupport", 13: "pushServiceRegistrationNotSupported",
    124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError",
}
CHECK_EVENT_ERRORS = {
    1: "invalidDsAddress", 2: "eventCheckingNotSupported", 3: "expiredEcid", 4: "unknownEcid",
    124: "invalidInputData", 125: "missingInputData", 126: "functionProviderBusy", 127: "undefinedError",
}

Es9Asn1Error = esipa.EsipaDownloadError
tlv = esipa.tlv


def _single(data: bytes, what: str) -> tuple[bytes, bytes, bytes]:
    try:
        tag, value, raw = read_single_ber_tlv(bytes(data or b""))
    except (ValueError, IndexError) as error:
        raise Es9Asn1Error(f"{what} is not one complete TLV: {error}") from error
    if len(raw) != len(data):
        raise Es9Asn1Error(f"trailing bytes after {what}")
    return tag, value, raw


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        try:
            tag, item_value, raw, offset = read_ber_tlv(value, offset)
        except (ValueError, IndexError) as error:
            raise Es9Asn1Error(f"truncated TLV inside an ES9+ message: {error}") from error
        items.append((tag, item_value, raw))
    return items


def is_wrapped(data: bytes) -> bool:
    """True for a body that opens with the 'A2' of the ES9+ ASN.1 binding."""
    return bytes(data or b"")[:1] == TAG_REMOTE_PROFILE_PROVISIONING


def wrap(function: bytes) -> bytes:
    """RemoteProfileProvisioningRequest or Response 'A2' around one function (§6.6.1)."""
    return tlv(TAG_REMOTE_PROFILE_PROVISIONING, bytes(function))


def unwrap(data: bytes) -> bytes:
    """The one function inside an 'A2', as its complete TLV."""
    tag, value, _raw = _single(data, "the ES9+ message")
    if tag != TAG_REMOTE_PROFILE_PROVISIONING:
        raise Es9Asn1Error(f"expected 'A2', got '{tag.hex().upper()}'")
    functions = _children(value)
    if len(functions) != 1:
        raise Es9Asn1Error("an ES9+ message carries one function")
    function_tag, _value, raw = functions[0]
    if function_tag not in FUNCTION_TAGS:
        raise Es9Asn1Error(f"'{function_tag.hex().upper()}' is no ES9+ or ES11 function this binding carries")
    return bytes(raw)


# -- requests (the LPA or IPA) ---------------------------------------------


def encode_initiate_authentication_request(euicc_challenge: bytes, smdp_address: str, euicc_info1: bytes) -> bytes:
    """'A2' { 'BF39' { '81' euiccChallenge, '83' smdpAddress, 'BF20' euiccInfo1 } } (§6.6.2.1)."""
    return wrap(esipa.encode_initiate_authentication_request(esipa.InitiateAuthenticationRequest(
        euicc_challenge=bytes(euicc_challenge), smdp_address=str(smdp_address), euicc_info1=bytes(euicc_info1),
    )))


def encode_authenticate_client_request(transaction_id: bytes, authenticate_server_response: bytes) -> bytes:
    return wrap(esipa.encode_authenticate_client_request(transaction_id, authenticate_server_response))


def encode_get_bound_profile_package_request(transaction_id: bytes, prepare_download_response: bytes) -> bytes:
    return wrap(esipa.encode_get_bound_profile_package_request(transaction_id, prepare_download_response))


def encode_cancel_session_request(transaction_id: bytes, cancel_session_response: bytes) -> bytes:
    return wrap(esipa.encode_cancel_session_request(transaction_id, cancel_session_response))


def encode_handle_notification(pending_notification: bytes) -> bytes:
    return wrap(esipa.encode_handle_notification(pending_notification))


# -- requests (the SM-DP+) -------------------------------------------------


def decode_handle_notification(function: bytes) -> bytes:
    """The PendingNotification of 'BF3D' { 'A0' { ... } } (§6.6.2.4), as its complete TLV."""
    tag, value, _raw = _single(function, "HandleNotification")
    if tag != esipa.TAG_HANDLE_NOTIFICATION:
        raise Es9Asn1Error(f"expected 'BF3D', got '{tag.hex().upper()}'")
    for item_tag, item_value, _item_raw in _children(value):
        if item_tag == b"\xA0":
            _inner_tag, _inner_value, inner_raw = _single(item_value, "pendingNotification")
            return bytes(inner_raw)
    raise Es9Asn1Error("HandleNotification lacks pendingNotification")


# -- answers (the SM-DP+) --------------------------------------------------


def encode_initiate_authentication_ok(
    transaction_id: bytes,
    server_signed1: bytes,
    server_signature1: bytes,
    euicc_ci_pkid: bytes,
    server_certificate: bytes,
) -> bytes:
    """InitiateAuthenticationOkEs9 (§6.6.2.1): '80', serverSigned1, '5F37', '04', the certificate."""
    return wrap(esipa.encode_initiate_authentication_ok(esipa.InitiateAuthenticationOk(
        transaction_id=bytes(transaction_id), server_signed1=bytes(server_signed1),
        server_signature1=bytes(server_signature1), euicc_ci_pkid=bytes(euicc_ci_pkid),
        server_certificate=bytes(server_certificate),
    )))


def encode_initiate_authentication_error(code: int) -> bytes:
    return wrap(esipa.encode_initiate_authentication_error(code))


def encode_authenticate_client_ok(
    transaction_id: bytes,
    profile_metadata: bytes,
    smdp_signed2: bytes,
    smdp_signature2: bytes,
    smdp_certificate: bytes,
) -> bytes:
    """AuthenticateClientOk (§6.6.2.2); profileMetadata 'BF25' is mandatory in it."""
    if bytes(profile_metadata or b"")[:2] != b"\xBF\x25":
        raise Es9Asn1Error("profileMetadata is a StoreMetadataRequest 'BF25'")
    return wrap(esipa.encode_authenticate_client_ok(esipa.AuthenticateClientOk(
        transaction_id=bytes(transaction_id), smdp_signed2=bytes(smdp_signed2),
        smdp_signature2=bytes(smdp_signature2), smdp_certificate=bytes(smdp_certificate),
        profile_metadata=bytes(profile_metadata),
    )))


def encode_authenticate_client_error(code: int) -> bytes:
    body = int(code).to_bytes(max(1, (int(code).bit_length() + 8) // 8), "big", signed=True)
    return wrap(tlv(esipa.TAG_AUTHENTICATE_CLIENT, tlv(b"\x81", body)))


def encode_get_bound_profile_package_ok(transaction_id: bytes, bound_profile_package: bytes) -> bytes:
    return wrap(esipa.encode_get_bound_profile_package_ok(transaction_id, bound_profile_package))


def encode_get_bound_profile_package_error(code: int) -> bytes:
    return wrap(esipa.encode_get_bound_profile_package_error(code))


def encode_cancel_session_ok() -> bytes:
    return wrap(esipa.encode_cancel_session_ok())


def encode_cancel_session_error(code: int) -> bytes:
    return wrap(esipa.encode_cancel_session_error(code))


# -- answers (the LPA or IPA) ----------------------------------------------


def decode_initiate_authentication_response(data: bytes) -> esipa.InitiateAuthenticationOk:
    return esipa.decode_initiate_authentication_response(unwrap(data))


def decode_authenticate_client_response(data: bytes) -> esipa.AuthenticateClientOk:
    """authenticateClientOk 'A0'; the error '81' raises with its code, the RPM and Device Change answers are refused."""
    function = unwrap(data)
    tag, value, _raw = _single(function, "AuthenticateClientResponseEs9")
    if tag != esipa.TAG_AUTHENTICATE_CLIENT:
        raise Es9Asn1Error(f"expected 'BF3B', got '{tag.hex().upper()}'")
    choices = _children(value)
    if len(choices) != 1:
        raise Es9Asn1Error("AuthenticateClientResponseEs9 is one CHOICE alternative")
    choice_tag, choice_value, _choice_raw = choices[0]
    if choice_tag == b"\x81":
        if len(choice_value) == 0:
            raise Es9Asn1Error("empty INTEGER")
        code = int.from_bytes(choice_value, "big", signed=True)
        name = AUTHENTICATE_CLIENT_ERRORS.get(code, "unknown")
        raise Es9Asn1Error(f"ES9+.AuthenticateClient error {name}({code})", code=code, name=name)
    if choice_tag != b"\xA0":
        raise Es9Asn1Error(
            f"AuthenticateClientResponseEs9 alternative '{choice_tag.hex().upper()}' is no profile download answer"
        )
    return esipa.decode_authenticate_client_response(function)


def decode_get_bound_profile_package_response(data: bytes) -> bytes:
    return esipa.decode_get_bound_profile_package_response(unwrap(data))


def decode_cancel_session_response(data: bytes) -> None:
    esipa.decode_cancel_session_response(unwrap(data))


# -- ES11 (the SM-DS and the LPA, IPA or eIM calling it) --------------------


def _integer_body(code: int) -> bytes:
    return int(code).to_bytes(max(1, (int(code).bit_length() + 8) // 8), "big", signed=True)


def encode_authenticate_client_es11_ok(transaction_id: bytes, events: list[tuple[str, str]]) -> bytes:
    """authenticateClientOk 'A0' { transactionId '80', eventEntries 'A1' } of AuthenticateClientResponseEs11 'BF40'.

    The unsigned list of version 2 (§6.6.2.7): each EventRecord is a SEQUENCE
    of eventId '80' and rspServerAddress '81', in the order given.
    """
    records = b"".join(
        tlv(b"\x30", tlv(b"\x80", str(event_id).encode("utf-8")) + tlv(b"\x81", str(address).encode("utf-8")))
        for event_id, address in events
    )
    body = tlv(b"\x80", bytes(transaction_id)) + tlv(b"\xA1", records)
    return wrap(tlv(TAG_AUTHENTICATE_CLIENT_ES11, tlv(b"\xA0", body)))


def encode_authenticate_client_es11_error(code: int) -> bytes:
    """authenticateClientError '81' of AuthenticateClientResponseEs11 'BF40' (§6.6.2.7)."""
    return wrap(tlv(TAG_AUTHENTICATE_CLIENT_ES11, tlv(b"\x81", _integer_body(code))))


def decode_authenticate_client_es11_response(data: bytes) -> tuple[bytes, list[tuple[str, str]]]:
    """(transactionId, [(eventId, rspServerAddress), ...]) of an SM-DS answer; the error '81' raises with its code.

    The signed answer of version 3 (authenticateClientOkV3 'A2') is refused:
    its Event Records are read from smdsSigned2, which this reader does not do.
    """
    function = unwrap(data)
    tag, value, _raw = _single(function, "AuthenticateClientResponseEs11")
    if tag != TAG_AUTHENTICATE_CLIENT_ES11:
        raise Es9Asn1Error(f"expected 'BF40', got '{tag.hex().upper()}'")
    choices = _children(value)
    if len(choices) != 1:
        raise Es9Asn1Error("AuthenticateClientResponseEs11 is one CHOICE alternative")
    choice_tag, choice_value, _choice_raw = choices[0]
    if choice_tag == b"\x81":
        if len(choice_value) == 0:
            raise Es9Asn1Error("empty INTEGER")
        code = int.from_bytes(choice_value, "big", signed=True)
        name = ES11_AUTHENTICATE_CLIENT_ERRORS.get(code, "unknown")
        raise Es9Asn1Error(f"ES11.AuthenticateClient error {name}({code})", code=code, name=name)
    if choice_tag != b"\xA0":
        raise Es9Asn1Error(
            f"AuthenticateClientResponseEs11 alternative '{choice_tag.hex().upper()}' is no unsigned Event Record list"
        )
    transaction_id = b""
    events: list[tuple[str, str]] = []
    for item_tag, item_value, _item_raw in _children(choice_value):
        if item_tag == b"\x80":
            transaction_id = bytes(item_value)
        elif item_tag == b"\xA1":
            for record_tag, record_value, _record_raw in _children(item_value):
                if record_tag != b"\x30":
                    raise Es9Asn1Error("eventEntries holds something that is no EventRecord")
                members = {member_tag: member_value for member_tag, member_value, _r in _children(record_value)}
                if b"\x80" not in members or b"\x81" not in members:
                    raise Es9Asn1Error("an EventRecord lacks eventId or rspServerAddress")
                events.append((members[b"\x80"].decode("utf-8", errors="replace"),
                               members[b"\x81"].decode("utf-8", errors="replace")))
    if len(transaction_id) == 0:
        raise Es9Asn1Error("authenticateClientOk lacks the transactionId")
    return transaction_id, events


def encode_check_event_request(ecid: bytes, smds_address: str) -> bytes:
    """CheckEventRequest 'BF46' { ecId '80', smdsAddress '81' } (§6.6.2.8)."""
    return wrap(tlv(TAG_CHECK_EVENT, tlv(b"\x80", bytes(ecid)) + tlv(b"\x81", str(smds_address).encode("utf-8"))))


def decode_check_event_request(function: bytes) -> tuple[bytes, str]:
    """(ecId, smdsAddress) of a CheckEventRequest 'BF46', given as its complete TLV."""
    tag, value, _raw = _single(function, "CheckEventRequest")
    if tag != TAG_CHECK_EVENT:
        raise Es9Asn1Error(f"expected 'BF46', got '{tag.hex().upper()}'")
    members = {item_tag: item_value for item_tag, item_value, _item_raw in _children(value)}
    if b"\x80" not in members or b"\x81" not in members:
        raise Es9Asn1Error("CheckEventRequest lacks ecId or smdsAddress")
    return bytes(members[b"\x80"]), members[b"\x81"].decode("utf-8", errors="replace")


def encode_check_event_ok(is_pending_event: bool) -> bytes:
    """checkEventOk 'A0' { isPendingEvent '80' } of CheckEventResponse 'BF46' (§6.6.2.8)."""
    return wrap(tlv(TAG_CHECK_EVENT, tlv(b"\xA0", tlv(b"\x80", b"\xFF" if is_pending_event else b"\x00"))))


def encode_check_event_error(code: int) -> bytes:
    """checkEventError '81' of CheckEventResponse 'BF46' (§6.6.2.8)."""
    return wrap(tlv(TAG_CHECK_EVENT, tlv(b"\x81", _integer_body(code))))


def decode_check_event_response(data: bytes) -> bool:
    """isPendingEvent of a CheckEventResponse; the error '81' raises with its code."""
    function = unwrap(data)
    tag, value, _raw = _single(function, "CheckEventResponse")
    if tag != TAG_CHECK_EVENT:
        raise Es9Asn1Error(f"expected 'BF46', got '{tag.hex().upper()}'")
    choices = _children(value)
    if len(choices) != 1:
        raise Es9Asn1Error("CheckEventResponse is one CHOICE alternative")
    choice_tag, choice_value, _choice_raw = choices[0]
    if choice_tag == b"\x81":
        if len(choice_value) == 0:
            raise Es9Asn1Error("empty INTEGER")
        code = int.from_bytes(choice_value, "big", signed=True)
        name = CHECK_EVENT_ERRORS.get(code, "unknown")
        raise Es9Asn1Error(f"ES11.CheckEvent error {name}({code})", code=code, name=name)
    if choice_tag != b"\xA0":
        raise Es9Asn1Error(f"unknown CheckEventResponse alternative '{choice_tag.hex().upper()}'")
    pending = next((item_value for item_tag, item_value, _r in _children(choice_value) if item_tag == b"\x80"), None)
    if pending is None or len(pending) != 1:
        raise Es9Asn1Error("checkEventOk lacks isPendingEvent")
    return pending != b"\x00"
