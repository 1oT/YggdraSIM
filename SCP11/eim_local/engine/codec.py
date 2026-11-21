# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.32 v1.3 eIM-side encodings: the packages an eIM serves and the answers it reads back.

Encoded here: EuiccPackageRequest 'BF51' (§2.11.1.1), IpaEuiccDataRequest
'BF52' (§2.11.1.2), ProfileDownloadTriggerRequest 'BF54' and the ESipa
responses 'BF4F' / 'BF50' (§6.3.2.6, §6.3.2.7). Decoded here: GetEimPackageRequest,
ProvideEimPackageResult and HandleNotificationEsipa, EuiccPackageResult
(§2.11.2.1), IpaEuiccDataResponse (§2.11.2.2), ProfileDownloadTriggerResult and
the ES10b answers the direct route reads (GetCerts 'BF56', RetrieveNotificationsList
'BF2B'). SGP32Definitions is AUTOMATIC TAGS; a component list that already tags
a member gets no automatic tags, so its untagged members keep the universal tag.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv, read_single_ber_tlv
from SCP11.shared.eim_configuration_data import decode_der_integer, encode_der_integer
from SCP11.shared.iccid import decode_ef_iccid
from SCP11.shared.profile_info import PROFILE_INFO_MEMBERS

EID_OCTETS = 16
TRANSACTION_ID_MAX_OCTETS = 16
SIGNATURE_OCTETS = 64

TAG_EUICC_PACKAGE = b"\xBF\x51"
TAG_IPA_EUICC_DATA = b"\xBF\x52"
TAG_EIM_ACKNOWLEDGEMENTS = b"\xBF\x53"
TAG_PROFILE_DOWNLOAD_TRIGGER = b"\xBF\x54"
TAG_GET_EIM_PACKAGE = b"\xBF\x4F"
TAG_PROVIDE_EIM_PACKAGE_RESULT = b"\xBF\x50"
TAG_HANDLE_NOTIFICATION_ESIPA = b"\xBF\x3D"
TAG_GET_CERTS = b"\xBF\x56"
TAG_RETRIEVE_NOTIFICATIONS = b"\xBF\x2B"
TAG_NOTIFICATION_SENT = b"\xBF\x30"
TAG_SIGNATURE = b"\x5F\x37"
TAG_ASSOCIATION_TOKEN = b"\x84"
# ES10b functions the device (IPAd) calls itself (SGP.32 v1.3 §5.9.16, §5.9.20, §5.9.21).
TAG_PROFILE_ROLLBACK = b"\xBF\x58"
TAG_EXECUTE_FALLBACK = b"\xBF\x5D"
TAG_RETURN_FROM_FALLBACK = b"\xBF\x5E"

# GetEimPackageResponse eimPackageError (§6.3.2.6).
EIM_PACKAGE_ERRORS: dict[int, str] = {
    1: "noEimPackageAvailable",
    2: "eidNotFound",
    3: "invalidEid",
    4: "missingEid",
    127: "undefinedError",
}
NO_EIM_PACKAGE_AVAILABLE = 1
EID_NOT_FOUND = 2
INVALID_EID = 3
MISSING_EID = 4
UNDEFINED_ERROR = 127

# ProvideEimPackageResultResponse provideEimPackageResultError (§6.3.2.7).
PROVIDE_RESULT_ERRORS: dict[int, str] = {
    2: "eidNotFound",
    3: "invalidEid",
    4: "missingEid",
    127: "undefinedError",
}

EUICC_PACKAGE_ERRORS: dict[int, str] = {
    3: "invalidEid",
    4: "replayError",
    6: "counterValueOutOfRange",
    15: "sizeOverflow",
    104: "ecallActive",
    127: "undefinedError",
}
EUICC_PACKAGE_UNSIGNED_ERRORS: dict[int, str] = {
    15: "sizeOverflow",
    127: "undefinedError",
}
EIM_PACKAGE_RESULT_ERRORS: dict[int, str] = {
    1: "invalidPackageFormat",
    2: "unknownPackage",
    127: "undefinedError",
}
IPA_EUICC_DATA_ERRORS: dict[int, str] = {
    1: "incorrectTagList",
    5: "euiccCiPKIdNotFound",
    104: "ecallActive",
    127: "undefinedError",
}
STATE_CHANGE_CAUSES: dict[int, str] = {
    0: "otherEim",
    1: "fallback",
    2: "emergencyProfile",
    3: "local",
    4: "reset",
    5: "immediateEnableProfile",
    6: "deviceChange",
    127: "undefined",
}

# EuiccResultData alternatives (§2.11.2.1): tag -> (name, code names, ok codes).
_ENABLE = {0: "ok", 1: "iccidOrAidNotFound", 2: "profileNotInDisabledState", 3: "disallowedByPolicy",
           5: "catBusy", 20: "rollbackNotAvailable", 127: "undefinedError"}
_DISABLE = {0: "ok", 1: "iccidOrAidNotFound", 2: "profileNotInEnabledState", 3: "disallowedByPolicy",
            5: "catBusy", 127: "undefinedError"}
_DELETE = {0: "ok", 1: "iccidOrAidNotFound", 2: "profileNotInDisabledState", 3: "disallowedByPolicy",
           20: "rollbackNotAvailable", 21: "returnFallbackProfile", 127: "undefinedError"}
_IMMEDIATE = {0: "ok", 1: "insufficientMemory", 7: "commandError", 127: "undefinedError"}
_ADD_EIM = {0: "ok", 1: "insufficientMemory", 2: "associatedEimAlreadyExists", 3: "ciPKUnknown",
            5: "invalidAssociationToken", 6: "counterValueOutOfRange", 7: "commandError", 127: "undefinedError"}
_DELETE_EIM = {0: "ok", 1: "eimNotFound", 2: "lastEimDeleted", 7: "commandError", 127: "undefinedError"}
_UPDATE_EIM = {0: "ok", 1: "eimNotFound", 3: "ciPKUnknown", 6: "counterValueOutOfRange",
               7: "commandError", 127: "undefinedError"}
_ROLLBACK = {0: "ok", 127: "undefinedError"}
_SET_FALLBACK = {0: "ok", 1: "iccidOrAidNotFound", 2: "fallbackNotAllowed", 3: "fallbackProfileEnabled",
                 127: "undefinedError"}
_UNSET_FALLBACK = {0: "ok", 2: "noFallbackAttribute", 3: "fallbackProfileEnabled", 7: "commandError",
                   127: "undefinedError"}
_PROCESSING_TERMINATED = {1: "resultSizeOverflow", 2: "unknownOrDamagedCommand", 3: "interruption",
                          127: "undefinedError"}
_PROFILE_INFO_LIST_ERRORS = {1: "incorrectInputValues", 11: "profileChangeOngoing", 127: "undefinedError"}
PROFILE_INFO_LIST_INCORRECT_INPUT = 1
_PROFILE_INFO_TAGS = frozenset(tag for tag, _name in PROFILE_INFO_MEMBERS)
_SET_DEFAULT_DP = {0: "ok", 127: "undefinedError"}

# Results of the device-side functions: ProfileRollbackResponse cmdResult (SGP.32 v1.3 §5.9.16),
# executeFallbackMechanismResult (§5.9.20), returnFromFallbackResult (§5.9.21).
PROFILE_ROLLBACK_RESULTS = {0: "ok", 1: "rollbackNotAllowed", 5: "catBusy", 7: "commandError", 127: "undefinedError"}
EXECUTE_FALLBACK_RESULTS = {0: "ok", 2: "profileNotInDisabledState", 5: "catBusy", 6: "fallbackNotAvailable",
                            7: "commandError", 104: "ecallActive", 127: "undefinedError"}
RETURN_FROM_FALLBACK_RESULTS = {0: "ok", 5: "catBusy", 6: "fallbackNotAvailable", 7: "commandError",
                                127: "undefinedError"}
DEVICE_FUNCTIONS: dict[bytes, tuple[str, dict[int, str]]] = {
    TAG_PROFILE_ROLLBACK: ("ProfileRollback", PROFILE_ROLLBACK_RESULTS),
    TAG_EXECUTE_FALLBACK: ("ExecuteFallbackMechanism", EXECUTE_FALLBACK_RESULTS),
    TAG_RETURN_FROM_FALLBACK: ("ReturnFromFallback", RETURN_FROM_FALLBACK_RESULTS),
}

_INTEGER_RESULTS: dict[bytes, tuple[str, dict[int, str], tuple[int, ...]]] = {
    b"\x83": ("enableResult", _ENABLE, (0,)),
    b"\x84": ("disableResult", _DISABLE, (0,)),
    b"\x85": ("deleteResult", _DELETE, (0,)),
    b"\x87": ("configureImmediateEnableResult", _IMMEDIATE, (0,)),
    b"\x89": ("deleteEimResult", _DELETE_EIM, (0, 2)),
    b"\x8A": ("updateEimResult", _UPDATE_EIM, (0,)),
    b"\x8C": ("rollbackResult", _ROLLBACK, (0,)),
    b"\x8D": ("setFallbackAttributeResult", _SET_FALLBACK, (0,)),
    b"\x8E": ("unsetFallbackAttributeResult", _UNSET_FALLBACK, (0,)),
}

PROFILE_STATES = {0: "disabled", 1: "enabled"}
PROFILE_CLASSES = {0: "test", 1: "provisioning", 2: "operational"}
EIM_ID_TYPE_NAMES = {1: "oid", 2: "fqdn", 3: "proprietary"}


class CodecError(ValueError):
    """Malformed SGP.32 data: the bytes do not decode as the structure they claim."""


def tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + encode_ber_length(len(value)) + bytes(value)


def integer_tlv(tag: bytes, value: int) -> bytes:
    return tlv(tag, encode_der_integer(int(value)))


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """Return (tag, value, raw) for every TLV in *value*; raise CodecError on a malformed one."""
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    data = bytes(value or b"")
    while offset < len(data):
        try:
            tag, item_value, raw, offset = read_ber_tlv(data, offset)
        except ValueError as error:
            raise CodecError(f"Malformed TLV at offset {offset}: {error}") from error
        items.append((tag, item_value, raw))
    return items


def _single(data: bytes, expected: bytes, label: str) -> bytes:
    try:
        tag, value, _raw = read_single_ber_tlv(bytes(data or b""))
    except ValueError as error:
        raise CodecError(f"{label}: {error}") from error
    if tag != expected:
        raise CodecError(f"{label}: expected tag {expected.hex().upper()}, got {tag.hex().upper()}.")
    return value


def _integer(contents: bytes, label: str) -> int:
    try:
        return decode_der_integer(contents)
    except ValueError as error:
        raise CodecError(f"{label}: {error}") from error


def _text(contents: bytes) -> str:
    return bytes(contents).decode("utf-8", errors="replace")


def eid_to_bytes(eid: str) -> bytes:
    """Return the 16-octet eidValue of a 32-digit EID."""
    digits = "".join(character for character in str(eid or "") if not character.isspace())
    if len(digits) != EID_OCTETS * 2 or any(character not in "0123456789" for character in digits):
        raise ValueError(f"An EID is 32 decimal digits, got {eid!r}.")
    return bytes.fromhex(digits)


def eid_from_bytes(value: bytes) -> str:
    raw = bytes(value or b"")
    if len(raw) != EID_OCTETS:
        raise CodecError(f"eidValue must be {EID_OCTETS} octets, got {len(raw)}.")
    return raw.hex().upper()


def normalize_eid(eid: str) -> str:
    return eid_from_bytes(eid_to_bytes(eid))


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def signature_input(signed_tlv: bytes, association_token: int | None) -> bytes:
    """Return the signed object followed by associationToken '84'.

    §2.11.1.1 (p.31) for the eIM signature and §2.11.2.1 (p.42-43) for the
    eUICC's: when no association token is configured the data object is
    '84 01 00'.
    """
    token = 0 if association_token is None else int(association_token)
    return bytes(signed_tlv) + integer_tlv(TAG_ASSOCIATION_TOKEN, token)


def sign_raw(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ECDSA P-256 / SHA-256 over *data*, as the 64-octet r||s an eUICC expects in '5F37'."""
    der_signature = private_key.sign(bytes(data), ec.ECDSA(hashes.SHA256()))
    r_value, s_value = decode_dss_signature(der_signature)
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def verify_raw(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    raw = bytes(signature or b"")
    if len(raw) != SIGNATURE_OCTETS:
        return False
    r_value = int.from_bytes(raw[:32], "big")
    s_value = int.from_bytes(raw[32:], "big")
    if r_value <= 0 or s_value <= 0:
        return False
    try:
        public_key.verify(encode_dss_signature(r_value, s_value), bytes(data), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def public_key_from_certificate(certificate_der: bytes) -> ec.EllipticCurvePublicKey:
    try:
        certificate = x509.load_der_x509_certificate(bytes(certificate_der))
    except ValueError as error:
        raise CodecError(f"Not a DER certificate: {error}") from error
    key = certificate.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise CodecError("The certificate does not carry an EC public key.")
    return key


def certificate_eid(certificate_der: bytes) -> str:
    """The EID an eUICC certificate is issued to, or '' when it names none.

    SGP.22 v3.1 §4.5.2.1.0.2: the subject 'serialNumber' of the eUICC
    certificate is the EID, 32 digits.
    """
    try:
        certificate = x509.load_der_x509_certificate(bytes(certificate_der))
    except ValueError:
        return ""
    for attribute in certificate.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER):
        digits = str(attribute.value).strip()
        if len(digits) == 32 and digits.isdigit():
            return digits
    return ""


def public_key_der(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# What the eIM sends
# ---------------------------------------------------------------------------

PACKAGE_PSMO = "psmo"
PACKAGE_ECO = "eco"


def build_euicc_package_signed(
    *,
    eim_id: str,
    eid: str,
    counter_value: int,
    transaction_id: bytes,
    kind: str,
    items: bytes,
) -> bytes:
    """Return EuiccPackageSigned '30' (§2.11.1.1, p.30).

    euiccPackage is a CHOICE of two untagged SEQUENCE OF, so automatic tagging
    gives psmoList 'A0' and ecoList 'A1'.
    """
    eim_id_octets = str(eim_id or "").encode("utf-8")
    if not 1 <= len(eim_id_octets) <= 128:
        raise ValueError(f"eimId must be 1..128 octets of UTF-8, got {len(eim_id_octets)}.")
    if kind == PACKAGE_PSMO:
        choice_tag = b"\xA0"
    elif kind == PACKAGE_ECO:
        choice_tag = b"\xA1"
    else:
        raise ValueError(f"An eUICC Package holds PSMOs or eCOs, not {kind!r}.")
    body = tlv(b"\x80", eim_id_octets)
    body += tlv(b"\x5A", eid_to_bytes(eid))
    body += integer_tlv(b"\x81", counter_value)
    if len(transaction_id) > 0:
        body += tlv(b"\x82", bytes(transaction_id))
    body += tlv(choice_tag, bytes(items))
    return tlv(b"\x30", body)


def build_euicc_package_request(signed: bytes, signature: bytes) -> bytes:
    """Return EuiccPackageRequest 'BF51' { euiccPackageSigned, eimSignature '5F37' }."""
    return tlv(TAG_EUICC_PACKAGE, bytes(signed) + tlv(TAG_SIGNATURE, bytes(signature)))


def build_ipa_euicc_data_request(
    *,
    tag_list: bytes,
    transaction_id: bytes = b"",
    euicc_ci_pkid: bytes = b"",
    notification_seq_number: int | None = None,
    result_seq_number: int | None = None,
) -> bytes:
    """Return IpaEuiccDataRequest 'BF52' (§2.11.1.2, p.36).

    The component list tags most members, so euiccCiPKIdentifierToBeUsed stays
    a universal OCTET STRING '04'; the two search criteria are tagged CHOICEs,
    explicit 'A1' / 'A2' around their seqNumber '80'.
    """
    body = tlv(b"\x5C", bytes(tag_list))
    if len(euicc_ci_pkid) > 0:
        body += tlv(b"\x04", bytes(euicc_ci_pkid))
    if notification_seq_number is not None:
        body += tlv(b"\xA1", integer_tlv(b"\x80", notification_seq_number))
    if result_seq_number is not None:
        body += tlv(b"\xA2", integer_tlv(b"\x80", result_seq_number))
    if len(transaction_id) > 0:
        body += tlv(b"\x83", bytes(transaction_id))
    return tlv(TAG_IPA_EUICC_DATA, body)


def build_profile_download_trigger_request(
    *,
    activation_code: str = "",
    contact_default_smdp: bool = False,
    contact_smds: bool = False,
    smds_address: str = "",
    transaction_id: bytes = b"",
) -> bytes:
    """Return ProfileDownloadTriggerRequest 'BF54' (SGP.32 v1.3 ASN.1 module).

    profileDownloadData [0] is a CHOICE, so its tag is explicit: 'A0' around
    activationCode '80', contactDefaultSmdp '81' or contactSmds 'A2'. The
    members go in definition order, eimTransactionId '82' last.
    """
    choices = sum(1 for chosen in (bool(activation_code), contact_default_smdp, contact_smds) if chosen)
    if choices > 1:
        raise ValueError("profileDownloadData is one of activationCode, contactDefaultSmdp or contactSmds.")
    body = b""
    if len(activation_code) > 0:
        code = activation_code.encode("utf-8")
        if len(code) > 255:
            raise ValueError("activationCode is at most 255 octets.")
        body += tlv(b"\xA0", tlv(b"\x80", code))
    elif contact_default_smdp:
        body += tlv(b"\xA0", tlv(b"\x81", b""))
    elif contact_smds:
        # contactSmds SEQUENCE { smdsAddress UTF8String OPTIONAL }: one untagged
        # member, so automatic tagging gives it '80'.
        inner = tlv(b"\x80", smds_address.encode("utf-8")) if len(smds_address) > 0 else b""
        body += tlv(b"\xA0", tlv(b"\xA2", inner))
    if len(transaction_id) > 0:
        body += tlv(b"\x82", bytes(transaction_id))
    return tlv(TAG_PROFILE_DOWNLOAD_TRIGGER, body)


def build_get_eim_package_response(package: bytes) -> bytes:
    """Return GetEimPackageResponse 'BF4F' around one eIM Package; the CHOICE tag is explicit."""
    return tlv(TAG_GET_EIM_PACKAGE, bytes(package))


def build_get_eim_package_error(code: int) -> bytes:
    """Return GetEimPackageResponse 'BF4F' { eimPackageError INTEGER '02' }."""
    return tlv(TAG_GET_EIM_PACKAGE, integer_tlv(b"\x02", code))


def build_eim_acknowledgements(seq_numbers: list[int]) -> bytes:
    """Return EimAcknowledgements 'BF53' { SequenceNumber '80' ... }."""
    return tlv(TAG_EIM_ACKNOWLEDGEMENTS, b"".join(integer_tlv(b"\x80", number) for number in seq_numbers))


def build_provide_result_response(seq_numbers: list[int] | None = None, *, error: int | None = None) -> bytes:
    """Return ProvideEimPackageResultResponse 'BF50' (§6.3.2.7).

    eimAcknowledgements 'BF53' when there are sequence numbers, emptyResponse
    '30 00' when there are none, or provideEimPackageResultError '02'.
    """
    if error is not None:
        return tlv(TAG_PROVIDE_EIM_PACKAGE_RESULT, integer_tlv(b"\x02", error))
    if seq_numbers:
        return tlv(TAG_PROVIDE_EIM_PACKAGE_RESULT, build_eim_acknowledgements(list(seq_numbers)))
    return tlv(TAG_PROVIDE_EIM_PACKAGE_RESULT, tlv(b"\x30", b""))


def build_device_request(tag: bytes, *, refresh: bool = True) -> bytes:
    """ProfileRollbackRequest 'BF58', ExecuteFallbackMechanismRequest 'BF5D' or ReturnFromFallbackRequest 'BF5E'.

    Each is ``SEQUENCE { refreshFlag BOOLEAN }`` (SGP.32 v1.3 §5.9.16, §5.9.20,
    §5.9.21); automatic tagging makes the one member ``[0]``.
    """
    if tag not in DEVICE_FUNCTIONS:
        raise CodecError(f"{tag.hex().upper()} is not a device-side function tag.")
    return tlv(tag, tlv(b"\x80", b"\xFF" if refresh else b"\x00"))


@dataclass(frozen=True)
class DeviceResult:
    """What a device-side function answered: the result code by name, and for a rollback the new result."""

    function: str
    code: int
    text: str
    euicc_package_result: bytes = b""

    @property
    def ok(self) -> bool:
        return self.code == 0

    def describe(self) -> str:
        return f"{self.function[:1].lower()}{self.function[1:]}Result: {self.text} ({self.code})"


def decode_device_response(tag: bytes, data: bytes) -> DeviceResult:
    """Decode the response of a device-side function.

    ProfileRollbackResponse 'BF58' is ``{ cmdResult INTEGER, eUICCPackageResult [81] OPTIONAL }``
    (SGP.32 v1.3 §5.9.16): the second member carries its own tag, so automatic tagging leaves
    cmdResult with the universal tag '02', and the new eUICC Package Result 'BF51' follows it
    when the result is ok. ExecuteFallbackMechanismResponse 'BF5D' (§5.9.20) and
    ReturnFromFallbackResponse 'BF5E' (§5.9.21) hold one ``[0]`` INTEGER each.
    """
    if tag not in DEVICE_FUNCTIONS:
        raise CodecError(f"{tag.hex().upper()} is not a device-side function tag.")
    name, codes = DEVICE_FUNCTIONS[tag]
    value = _single(data, tag, f"{name}Response")
    code: int | None = None
    package_result = b""
    for child_tag, child_value, raw in _children(value):
        if child_tag in (b"\x02", b"\x80") and code is None:
            code = decode_der_integer(child_value)
        elif child_tag == TAG_EUICC_PACKAGE:
            package_result = raw
    if code is None:
        raise CodecError(f"{name}Response carries no result code.")
    return DeviceResult(function=name, code=code, text=codes.get(code, "unknown"), euicc_package_result=package_result)


def build_notification_sent(seq_number: int) -> bytes:
    """Return NotificationSentRequest 'BF30' { seqNumber '80' } (SGP.22 RemoveNotificationFromList)."""
    return tlv(TAG_NOTIFICATION_SENT, integer_tlv(b"\x80", seq_number))


def build_retrieve_package_results_request() -> bytes:
    """Return RetrieveNotificationsListRequest 'BF2B' asking for eUICC Package Results.

    searchCriteria is the only member and untagged, so it is automatically
    tagged [0] -- explicit 'A0', being a CHOICE -- around euiccPackageResults '82 00'.
    """
    return tlv(TAG_RETRIEVE_NOTIFICATIONS, tlv(b"\xA0", tlv(b"\x82", b"")))


def build_retrieve_notifications_request(seq_number: int | None = None) -> bytes:
    if seq_number is None:
        return tlv(TAG_RETRIEVE_NOTIFICATIONS, b"")
    return tlv(TAG_RETRIEVE_NOTIFICATIONS, tlv(b"\xA0", integer_tlv(b"\x80", seq_number)))


def build_get_certs_request(euicc_ci_pkid: bytes = b"") -> bytes:
    """Return GetCertsRequest 'BF56' (§5.9.10); its one optional member is automatically tagged '80'."""
    if len(euicc_ci_pkid) > 0:
        return tlv(TAG_GET_CERTS, tlv(b"\x80", bytes(euicc_ci_pkid)))
    return tlv(TAG_GET_CERTS, b"")


# ---------------------------------------------------------------------------
# What the IPA and the eUICC send back
# ---------------------------------------------------------------------------


@dataclass
class GetEimPackageRequest:
    eid: str
    notify_state_change: bool = False
    state_change_cause: int | None = None
    rplmn: bytes = b""


def decode_get_eim_package_request(data: bytes) -> GetEimPackageRequest:
    """Decode GetEimPackageRequest 'BF4F' { '5A' eid, '80' notify, '81' cause, '82' rPLMN }."""
    value = _single(data, TAG_GET_EIM_PACKAGE, "GetEimPackageRequest")
    eid = ""
    request = GetEimPackageRequest(eid="")
    for tag, item_value, _raw in _children(value):
        if tag == b"\x5A":
            eid = eid_from_bytes(item_value)
        elif tag == b"\x80":
            request.notify_state_change = True
        elif tag == b"\x81":
            request.state_change_cause = _integer(item_value, "stateChangeCause")
        elif tag == b"\x82":
            request.rplmn = bytes(item_value)
    request.eid = eid
    return request


@dataclass
class ResultItem:
    """One EuiccResultData of a signed eUICC Package Result."""

    name: str
    tag: str
    ok: bool
    code: int | None = None
    text: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        if self.code is None:
            return f"{self.name}: {self.text or ('ok' if self.ok else 'error')}"
        return f"{self.name}: {self.text or 'unknown'} ({self.code})"


@dataclass
class EuiccPackageResult:
    """A decoded EuiccPackageResult 'BF51' (§2.11.2.1).

    kind is "result" (euiccPackageResultSigned 'A0'), "error_signed" ('A1') or
    "error_unsigned" ('A2'). signed_data is the '30' TLV the eUICC signed.
    """

    kind: str
    eim_id: str
    transaction_id: bytes = b""
    counter_value: int | None = None
    seq_number: int | None = None
    items: list[ResultItem] = field(default_factory=list)
    error_code: int | None = None
    association_token: int | None = None
    signed_data: bytes = b""
    signature: bytes = b""
    raw: bytes = b""

    @property
    def error_name(self) -> str:
        if self.error_code is None:
            return ""
        table = EUICC_PACKAGE_UNSIGNED_ERRORS if self.kind == "error_unsigned" else EUICC_PACKAGE_ERRORS
        return table.get(self.error_code, "unknown")

    @property
    def signed(self) -> bool:
        return self.kind in ("result", "error_signed")


def _decode_profile_info(value: bytes) -> dict[str, Any]:
    profile: dict[str, Any] = {}
    for tag, item_value, _raw in _children(value):
        if tag == b"\x5A":
            profile["iccid"] = decode_ef_iccid(item_value, strict=False)
        elif tag == b"\x4F":
            profile["aid"] = item_value.hex().upper()
        elif tag == b"\x9F\x70":
            state = _integer(item_value, "profileState")
            profile["state"] = PROFILE_STATES.get(state, str(state))
        elif tag == b"\x90":
            profile["nickname"] = _text(item_value)
        elif tag == b"\x91":
            profile["service_provider"] = _text(item_value)
        elif tag == b"\x92":
            profile["name"] = _text(item_value)
        elif tag == b"\x95":
            profile_class = _integer(item_value, "profileClass")
            profile["class"] = PROFILE_CLASSES.get(profile_class, str(profile_class))
        elif tag == b"\x9F\x26":
            profile["fallback"] = len(item_value) > 0 and item_value[0] != 0
        elif tag == b"\x9F\x67":
            profile["fallback_allowed"] = len(item_value) > 0 and item_value[0] != 0
        elif tag == b"\x9F\x7B":
            profile["ecall"] = len(item_value) > 0 and item_value[0] != 0
        elif tag.hex().upper() not in _PROFILE_INFO_TAGS:
            # Not a member of SGP.32 v1.3 §4.4: kept as it came, since the Decoder's schema skips it too.
            profile.setdefault("other_members", {})[tag.hex().upper()] = item_value.hex().upper()
    profile.setdefault("fallback", False)
    return profile


def decode_profile_info_list(value: bytes) -> list[dict[str, Any]]:
    """Decode the contents of profileInfoListOk: a run of ProfileInfo 'E3'."""
    profiles: list[dict[str, Any]] = []
    for tag, item_value, _raw in _children(value):
        if tag == b"\xE3":
            profiles.append(_decode_profile_info(item_value))
    return profiles


def _decode_eim_id_list(value: bytes) -> list[dict[str, Any]]:
    eims: list[dict[str, Any]] = []
    for tag, item_value, _raw in _children(value):
        if tag != b"\x30":
            continue
        entry: dict[str, Any] = {}
        for inner_tag, inner_value, _inner_raw in _children(item_value):
            if inner_tag == b"\x80":
                entry["eim_id"] = _text(inner_value)
            elif inner_tag == b"\x82":
                id_type = _integer(inner_value, "eimIdType")
                entry["eim_id_type"] = EIM_ID_TYPE_NAMES.get(id_type, str(id_type))
        eims.append(entry)
    return eims


def decode_result_item(tag: bytes, value: bytes) -> ResultItem:
    """Decode one EuiccResultData alternative."""
    tag_hex = tag.hex().upper()
    if tag in _INTEGER_RESULTS:
        name, names, ok_codes = _INTEGER_RESULTS[tag]
        code = _integer(value, name)
        return ResultItem(name=name, tag=tag_hex, ok=code in ok_codes, code=code, text=names.get(code, "unknown"))
    if tag == b"\xBF\x2D":
        # listProfileInfoResult [45] ProfileInfoListResponse: an explicit tag
        # around profileInfoListOk 'A0' or profileInfoListError '81'.
        for inner_tag, inner_value, _raw in _children(value):
            if inner_tag == b"\xA0":
                profiles = decode_profile_info_list(inner_value)
                return ResultItem(name="listProfileInfoResult", tag=tag_hex, ok=True, text="ok",
                                  detail={"profiles": profiles})
            if inner_tag == b"\x81":
                code = _integer(inner_value, "profileInfoListError")
                return ResultItem(name="listProfileInfoResult", tag=tag_hex, ok=False, code=code,
                                  text=_PROFILE_INFO_LIST_ERRORS.get(code, "unknown"))
        return ResultItem(name="listProfileInfoResult", tag=tag_hex, ok=True, text="ok", detail={"profiles": []})
    if tag == b"\xA6":
        return ResultItem(name="getRATResult", tag=tag_hex, ok=True, text="ok",
                          detail={"rat_hex": tlv(b"\x30", value).hex().upper()})
    if tag == b"\xA8":
        # addEimResult [8] AddEimResult: the CHOICE tag is explicit around
        # associationToken '84' or addEimResultCode '02'.
        for inner_tag, inner_value, _raw in _children(value):
            if inner_tag == b"\x84":
                token = _integer(inner_value, "associationToken")
                # The eIM signature of a package covers this value (SGP.32 v1.3 §2.11.1.1,
                # EuiccPackageRequest): whoever adds another eIM has to hand it the number, so the
                # result line carries it.
                return ResultItem(name="addEimResult", tag=tag_hex, ok=True, text=f"associationToken {token}",
                                  detail={"association_token": token})
            if inner_tag == b"\x02":
                code = _integer(inner_value, "addEimResultCode")
                return ResultItem(name="addEimResult", tag=tag_hex, ok=code == 0, code=code,
                                  text=_ADD_EIM.get(code, "unknown"))
        raise CodecError("addEimResult holds neither associationToken '84' nor addEimResultCode '02'.")
    if tag == b"\xAB":
        for inner_tag, inner_value, _raw in _children(value):
            if inner_tag == b"\xA0":
                return ResultItem(name="listEimResult", tag=tag_hex, ok=True, text="ok",
                                  detail={"eims": _decode_eim_id_list(inner_value)})
            if inner_tag == b"\x81":
                code = _integer(inner_value, "listEimError")
                return ResultItem(name="listEimResult", tag=tag_hex, ok=False, code=code,
                                  text="undefinedError" if code == 127 else "unknown")
        return ResultItem(name="listEimResult", tag=tag_hex, ok=True, text="ok", detail={"eims": []})
    if tag == b"\x02":
        code = _integer(value, "processingTerminated")
        return ResultItem(name="processingTerminated", tag=tag_hex, ok=False, code=code,
                          text=_PROCESSING_TERMINATED.get(code, "unknown"))
    if tag == b"\xBF\x65":
        for inner_tag, inner_value, _raw in _children(value):
            if inner_tag == b"\x80":
                code = _integer(inner_value, "setDefaultDpAddressResult")
                return ResultItem(name="setDefaultDpAddressResult", tag=tag_hex, ok=code == 0, code=code,
                                  text=_SET_DEFAULT_DP.get(code, "unknown"))
        raise CodecError("setDefaultDpAddressResult holds no result '80'.")
    return ResultItem(name="unknown", tag=tag_hex, ok=False, text="not an SGP.32 v1.3 EuiccResultData",
                      detail={"raw_hex": tlv(tag, value).hex().upper()})


def _decode_signed_result_data(signed_value: bytes, result: EuiccPackageResult) -> None:
    for tag, item_value, _raw in _children(signed_value):
        if tag == b"\x80":
            result.eim_id = _text(item_value)
        elif tag == b"\x81":
            result.counter_value = _integer(item_value, "counterValue")
        elif tag == b"\x82":
            result.transaction_id = bytes(item_value)
        elif tag == b"\x83":
            result.seq_number = _integer(item_value, "seqNumber")
        elif tag == b"\x30":
            for item_tag, inner_value, _inner_raw in _children(item_value):
                result.items.append(decode_result_item(item_tag, inner_value))


def psmo_tags(package: bytes) -> list[bytes] | None:
    """The tags of the PSMOs in an eUICC Package request, None for an eCO package or one that does not parse."""
    try:
        _tag, value, _raw = read_single_ber_tlv(package)
        _signed_tag, signed, _signed_raw = read_ber_tlv(value, 0)[:3]
        offset = 0
        while offset < len(signed):
            tag, item_value, _item_raw, offset = read_ber_tlv(signed, offset)
            if tag == b"\xA0":
                tags: list[bytes] = []
                inner = 0
                while inner < len(item_value):
                    psmo_tag, _psmo_value, _psmo_raw, inner = read_ber_tlv(item_value, inner)
                    tags.append(bytes(psmo_tag))
                return tags
    except ValueError:
        return None
    return None


def holds_psmos(package: bytes) -> bool:
    return psmo_tags(package) is not None


def list_profile_info_tag_list(package: bytes) -> str | None:
    """The tagList hex of the one listProfileInfo PSMO in an eUICC Package request.

    Empty for a listProfileInfo without a tagList (ProfileInfoListRequest,
    SGP.22 v3.1 §5.7.15: tagList '5C' is optional). None when the package
    holds no listProfileInfo or more than one, or does not parse.
    """
    try:
        signed = _children(_single(package, TAG_EUICC_PACKAGE, "EuiccPackageRequest"))[0][1]
        requests = [
            value
            for list_tag, items, _raw in _children(signed) if list_tag == b"\xA0"
            for tag, value, _item_raw in _children(items) if tag == b"\xBF\x2D"
        ]
        if len(requests) != 1:
            return None
        tag_lists = [value for tag, value, _raw in _children(requests[0]) if tag == b"\x5C"]
    except (CodecError, IndexError):
        return None
    return tag_lists[0].hex().upper() if tag_lists else ""


# Psmo enable [3] and disable [4] (SGP.32 v1.3 §2.11.1.1.3): the PSMOs that mark a Profile "to be
# enabled" or "to be disabled", for which the eUICC sends a REFRESH and generates the result only
# upon its Terminal Response or after the reset (§3.3.1 steps 8a-8b).
STATE_CHANGE_PSMO_TAGS = (b"\xA3", b"\xA4")


def changes_profile_state(package: bytes) -> bool:
    return any(tag in STATE_CHANGE_PSMO_TAGS for tag in (psmo_tags(package) or []))


def decode_euicc_package_result(data: bytes) -> EuiccPackageResult:
    """Decode EuiccPackageResult 'BF51' (§2.11.2.1, p.39-43).

    The CHOICE alternatives are untagged SEQUENCEs, so automatic tagging gives
    'A0' / 'A1' / 'A2'. Inside the signed alternatives the component lists tag
    euiccSignEPR / euiccSignEPE, so the signed data keeps its SEQUENCE tag '30'.
    """
    value = _single(data, TAG_EUICC_PACKAGE, "EuiccPackageResult")
    try:
        choice_tag, choice_value, _choice_raw = read_single_ber_tlv(value)
    except ValueError as error:
        raise CodecError(f"EuiccPackageResult: {error}") from error
    result = EuiccPackageResult(kind="", eim_id="", raw=bytes(data))
    if choice_tag in (b"\xA0", b"\xA1"):
        result.kind = "result" if choice_tag == b"\xA0" else "error_signed"
        parts = _children(choice_value)
        if len(parts) != 2 or parts[0][0] != b"\x30" or parts[1][0] != TAG_SIGNATURE:
            raise CodecError("A signed eUICC Package Result is '30' signed data followed by '5F37'.")
        result.signed_data = parts[0][2]
        result.signature = bytes(parts[1][1])
        if result.kind == "result":
            _decode_signed_result_data(parts[0][1], result)
        else:
            for tag, item_value, _raw in _children(parts[0][1]):
                if tag == b"\x80":
                    result.eim_id = _text(item_value)
                elif tag == b"\x81":
                    result.counter_value = _integer(item_value, "counterValue")
                elif tag == b"\x82":
                    result.transaction_id = bytes(item_value)
                elif tag == b"\x02":
                    result.error_code = _integer(item_value, "euiccPackageErrorCode")
        return result
    if choice_tag == b"\xA2":
        result.kind = "error_unsigned"
        for tag, item_value, _raw in _children(choice_value):
            if tag == b"\x80":
                result.eim_id = _text(item_value)
            elif tag == b"\x82":
                result.transaction_id = bytes(item_value)
            elif tag == b"\x84":
                result.association_token = _integer(item_value, "associationToken")
            elif tag == b"\x8F":
                result.error_code = _integer(item_value, "euiccPackageUnsignedErrorCode")
        return result
    raise CodecError(f"EuiccPackageResult alternative {choice_tag.hex().upper()} is not 'A0', 'A1' or 'A2'.")


def verify_euicc_package_result(
    result: EuiccPackageResult,
    certificate_der: bytes,
    association_token: int | None,
) -> bool:
    """Check euiccSignEPR / euiccSignEPE with PK.EUICC.ECDSA (§2.11.2.1, p.42-43)."""
    if not result.signed:
        return False
    key = public_key_from_certificate(certificate_der)
    return verify_raw(key, signature_input(result.signed_data, association_token), result.signature)


@dataclass
class IpaEuiccData:
    """A decoded IpaEuiccDataResponse 'BF52' (§2.11.2.2)."""

    ok: bool
    error_code: int | None = None
    transaction_id: bytes = b""
    members: dict[str, bytes] = field(default_factory=dict)
    package_results: list[bytes] = field(default_factory=list)
    notifications: list[bytes] = field(default_factory=list)
    raw: bytes = b""

    @property
    def error_name(self) -> str:
        if self.error_code is None:
            return ""
        return IPA_EUICC_DATA_ERRORS.get(self.error_code, "unknown")


_IPA_DATA_MEMBERS = {
    b"\x81": "default_smdp_address",
    b"\xBF\x20": "euicc_info1",
    b"\xBF\x22": "euicc_info2",
    b"\x83": "root_smds_address",
    b"\x84": "association_token",
    b"\xA5": "eum_certificate",
    b"\xA6": "euicc_certificate",
    b"\xA8": "ipa_capabilities",
    b"\xA9": "device_info",
}


def decode_ipa_euicc_data_response(data: bytes) -> IpaEuiccData:
    """Decode IpaEuiccDataResponse 'BF52': ipaEuiccData 'A0' or ipaEuiccDataResponseError 'A1'.

    Both alternatives are untagged SEQUENCEs, hence the automatic tags. A
    Certificate member carries its own SEQUENCE under the implicit tag, so the
    certificate DER is rebuilt as '30' + the member's length and contents.
    """
    value = _single(data, TAG_IPA_EUICC_DATA, "IpaEuiccDataResponse")
    try:
        choice_tag, choice_value, _raw = read_single_ber_tlv(value)
    except ValueError as error:
        raise CodecError(f"IpaEuiccDataResponse: {error}") from error
    if choice_tag == b"\xA1":
        response = IpaEuiccData(ok=False, raw=bytes(data))
        for tag, item_value, _item_raw in _children(choice_value):
            if tag == b"\x80":
                response.transaction_id = bytes(item_value)
            elif tag == b"\x02":
                response.error_code = _integer(item_value, "ipaEuiccDataErrorCode")
        return response
    if choice_tag != b"\xA0":
        raise CodecError(f"IpaEuiccDataResponse alternative {choice_tag.hex().upper()} is not 'A0' or 'A1'.")
    response = IpaEuiccData(ok=True, raw=bytes(data))
    for tag, item_value, item_raw in _children(choice_value):
        if tag == b"\xA0":
            response.notifications = [raw for _t, _v, raw in _children(item_value)]
        elif tag == b"\xA2":
            response.package_results = [as_euicc_package_result(raw) for _t, _v, raw in _children(item_value)]
        elif tag == b"\x87":
            response.transaction_id = bytes(item_value)
        elif tag in (b"\xA5", b"\xA6"):
            response.members[_IPA_DATA_MEMBERS[tag]] = tlv(b"\x30", item_value)
        elif tag in _IPA_DATA_MEMBERS:
            response.members[_IPA_DATA_MEMBERS[tag]] = bytes(item_raw if tag in (b"\xBF\x20", b"\xBF\x22") else item_value)
    return response


@dataclass
class ProfileDownloadTriggerResult:
    ok: bool
    transaction_id: bytes = b""
    error_reason: int | None = None
    installation_result: bytes = b""
    raw: bytes = b""


def decode_profile_download_trigger_result(data: bytes) -> ProfileDownloadTriggerResult:
    """Decode ProfileDownloadTriggerResult 'BF54' { '82' txid, 'BF37' PIR | '30' { '80' reason } }."""
    value = _single(data, TAG_PROFILE_DOWNLOAD_TRIGGER, "ProfileDownloadTriggerResult")
    result = ProfileDownloadTriggerResult(ok=False, raw=bytes(data))
    for tag, item_value, item_raw in _children(value):
        if tag == b"\x82":
            result.transaction_id = bytes(item_value)
        elif tag == b"\xBF\x37":
            result.installation_result = bytes(item_raw)
            result.ok = _installation_succeeded(item_value)
        elif tag == b"\x30":
            for inner_tag, inner_value, _inner_raw in _children(item_value):
                if inner_tag == b"\x80":
                    result.error_reason = _integer(inner_value, "profileDownloadErrorReason")
    return result


def _installation_succeeded(pir_value: bytes) -> bool:
    """True when ProfileInstallationResultData carries successResult 'A0' in finalResult 'A2'."""
    for tag, item_value, _raw in _children(pir_value):
        if tag != b"\xBF\x27":
            continue
        for inner_tag, inner_value, _inner_raw in _children(item_value):
            if inner_tag == b"\xA2":
                return any(final_tag == b"\xA0" for final_tag, _v, _r in _children(inner_value))
    return False


@dataclass
class EimPackageResult:
    """A decoded EimPackageResult CHOICE (§6.3.2.7)."""

    kind: str
    raw: bytes
    euicc_package_result: bytes = b""
    notifications: list[bytes] = field(default_factory=list)
    transaction_id: bytes = b""
    error_code: int | None = None


def decode_eim_package_result(data: bytes) -> EimPackageResult:
    """Decode one EimPackageResult alternative.

    euiccPackageResult 'BF51', ePRAndNotifications '30' (the CHOICE tags some
    alternatives, so this one keeps its SEQUENCE tag) holding 'BF51' and the
    notificationList 'A0', ipaEuiccDataResponse 'BF52',
    profileDownloadTriggerResult 'BF54', eimPackageResultResponseError 'A0'.
    """
    try:
        tag, value, raw = read_single_ber_tlv(bytes(data or b""))
    except ValueError as error:
        raise CodecError(f"EimPackageResult: {error}") from error
    if tag == TAG_EUICC_PACKAGE:
        return EimPackageResult(kind="euicc_package_result", raw=raw, euicc_package_result=raw)
    if tag == b"\x30":
        result = EimPackageResult(kind="epr_and_notifications", raw=raw)
        for item_tag, item_value, item_raw in _children(value):
            if item_tag == TAG_EUICC_PACKAGE:
                result.euicc_package_result = item_raw
            elif item_tag == b"\xA0":
                result.notifications = [entry for _t, _v, entry in _children(item_value)]
        if len(result.euicc_package_result) == 0:
            raise CodecError("ePRAndNotifications carries no euiccPackageResult 'BF51'.")
        return result
    # The eIM identifies the eUICC "by using the received EID or data already
    # available" (SGP.32 v1.3 §5.14.6, p.171): eidValue is optional in
    # ProvideEimPackageResult, so every alternative hands its eimTransactionId on.
    if tag == TAG_IPA_EUICC_DATA:
        return EimPackageResult(kind="ipa_euicc_data_response", raw=raw,
                                transaction_id=decode_ipa_euicc_data_response(raw).transaction_id)
    if tag == TAG_PROFILE_DOWNLOAD_TRIGGER:
        return EimPackageResult(kind="profile_download_trigger_result", raw=raw,
                                transaction_id=decode_profile_download_trigger_result(raw).transaction_id)
    if tag == b"\xA0":
        result = EimPackageResult(kind="eim_package_result_response_error", raw=raw)
        for item_tag, item_value, _item_raw in _children(value):
            if item_tag == b"\x80":
                result.transaction_id = bytes(item_value)
            elif item_tag == b"\x02":
                result.error_code = _integer(item_value, "eimPackageResultErrorCode")
        return result
    raise CodecError(f"EimPackageResult alternative {tag.hex().upper()} is not defined by SGP.32 v1.3.")


@dataclass
class ProvideEimPackageResult:
    eid: str
    result: EimPackageResult


def decode_provide_eim_package_result(data: bytes) -> ProvideEimPackageResult:
    """Decode ProvideEimPackageResult 'BF50' { '5A' eid OPTIONAL, EimPackageResult }."""
    value = _single(data, TAG_PROVIDE_EIM_PACKAGE_RESULT, "ProvideEimPackageResult")
    eid = ""
    result: EimPackageResult | None = None
    for tag, item_value, item_raw in _children(value):
        if tag == b"\x5A":
            eid = eid_from_bytes(item_value)
        elif result is None:
            result = decode_eim_package_result(item_raw)
    if result is None:
        raise CodecError("ProvideEimPackageResult carries no EimPackageResult.")
    return ProvideEimPackageResult(eid=eid, result=result)


def misplaced_get_eim_package_request(data: bytes) -> GetEimPackageRequest | None:
    """A GetEimPackageRequest 'BF4F' carried inside ProvideEimPackageResult 'BF50', or None.

    No EimPackageResult alternative is tagged 'BF4F' (SGP.32 v1.3 §5.14.6);
    a live eUICC's IPAe reports its state this way after a Profile state
    change: eidValue and rPLMN (§5.14.5) under 'BF50'. The outer eidValue
    stands in when the inner request has none.
    """
    try:
        value = _single(data, TAG_PROVIDE_EIM_PACKAGE_RESULT, "ProvideEimPackageResult")
    except CodecError:
        return None
    outer_eid = ""
    request: GetEimPackageRequest | None = None
    for tag, item_value, item_raw in _children(value):
        if tag == b"\x5A":
            outer_eid = eid_from_bytes(item_value)
        elif tag == TAG_GET_EIM_PACKAGE and request is None:
            try:
                request = decode_get_eim_package_request(item_raw)
            except CodecError:
                return None
    if request is not None and len(request.eid) == 0:
        request.eid = outer_eid
    return request


def decode_handle_notification_esipa(data: bytes) -> tuple[str, bytes]:
    """Return ("provide_result", BF50 TLV) or ("notification", PendingNotification TLV) from 'BF3D'."""
    value = _single(data, TAG_HANDLE_NOTIFICATION_ESIPA, "HandleNotificationEsipa")
    try:
        tag, item_value, raw = read_single_ber_tlv(value)
    except ValueError as error:
        raise CodecError(f"HandleNotificationEsipa: {error}") from error
    if tag == TAG_PROVIDE_EIM_PACKAGE_RESULT:
        return "provide_result", raw
    if tag == b"\xA0":
        return "notification", bytes(item_value)
    raise CodecError(f"HandleNotificationEsipa alternative {tag.hex().upper()} is not 'A0' or 'BF50'.")


def decode_get_certs_response(data: bytes) -> tuple[bytes, bytes]:
    """Return (eumCertificate DER, euiccCertificate DER) from GetCertsResponse 'BF56'.

    The certs alternative is automatically tagged 'A0'; each Certificate sits
    under its implicit '[5]' / '[6]' tag, so the DER SEQUENCE is rebuilt.
    """
    value = _single(data, TAG_GET_CERTS, "GetCertsResponse")
    try:
        choice_tag, choice_value, _raw = read_single_ber_tlv(value)
    except ValueError as error:
        raise CodecError(f"GetCertsResponse: {error}") from error
    if choice_tag == b"\x81":
        code = _integer(choice_value, "getCertsError")
        raise CodecError(f"GetCerts answered getCertsError {code}.")
    if choice_tag != b"\xA0":
        raise CodecError(f"GetCertsResponse alternative {choice_tag.hex().upper()} is not 'A0' or '81'.")
    eum = b""
    euicc = b""
    for tag, item_value, _item_raw in _children(choice_value):
        if tag == b"\xA5":
            eum = tlv(b"\x30", item_value)
        elif tag == b"\xA6":
            euicc = tlv(b"\x30", item_value)
    if len(euicc) == 0:
        raise CodecError("GetCertsResponse carries no euiccCertificate 'A6'.")
    return eum, euicc


def as_euicc_package_result(raw: bytes) -> bytes:
    """Return a stored result as EuiccPackageResult 'BF51'.

    EuiccPackageResultList is a SEQUENCE OF EuiccPackageResult, a tagged
    CHOICE whose '[81]' is explicit, so each element is 'BF51'-wrapped; a bare
    'A0' / 'A1' / 'A2' alternative from an eUICC that leaves the wrapper out is
    accepted and wrapped here.
    """
    data = bytes(raw or b"")
    if data[:1] in (b"\xA0", b"\xA1", b"\xA2"):
        return tlv(TAG_EUICC_PACKAGE, data)
    return data


def decode_package_result_list(data: bytes) -> list[bytes]:
    """Return the EuiccPackageResult TLVs of RetrieveNotificationsListResponse 'BF2B' { 'A2' ... }."""
    value = _single(data, TAG_RETRIEVE_NOTIFICATIONS, "RetrieveNotificationsListResponse")
    for tag, item_value, _raw in _children(value):
        if tag == b"\xA2":
            return [as_euicc_package_result(raw) for _t, _v, raw in _children(item_value)]
    return []


def decode_notification_list(data: bytes) -> list[bytes]:
    """Return the PendingNotification TLVs of RetrieveNotificationsListResponse 'BF2B' { 'A0' ... }."""
    value = _single(data, TAG_RETRIEVE_NOTIFICATIONS, "RetrieveNotificationsListResponse")
    for tag, item_value, _raw in _children(value):
        if tag == b"\xA0":
            return [raw for _t, _v, raw in _children(item_value)]
    return []


def notification_seq_number(notification: bytes) -> int | None:
    """Return the seqNumber '80' of a PendingNotification's NotificationMetadata 'BF2F', when found.

    A compactProfileInstallationResult 'A0' (SGP.32 v1.3 §5.14.7) carries it
    as a plain INTEGER of its compact data, there being no NotificationMetadata.
    """
    if bytes(notification or b"")[:1] == b"\xA0":
        from SCP11.eim_local.engine.compact import compact_notification_seq_number

        return compact_notification_seq_number(bytes(notification))
    try:
        _tag, value, _raw = read_single_ber_tlv(bytes(notification or b""))
    except ValueError:
        return None
    stack = [value]
    while stack:
        current = stack.pop()
        try:
            children = _children(current)
        except CodecError:
            continue
        for tag, item_value, _raw in children:
            if tag == b"\xBF\x2F":
                for inner_tag, inner_value, _inner_raw in _children(item_value):
                    if inner_tag == b"\x80":
                        return _integer(inner_value, "seqNumber")
            elif tag[0] & 0x20:
                stack.append(item_value)
    return None
