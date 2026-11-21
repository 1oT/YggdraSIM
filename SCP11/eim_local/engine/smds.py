# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The local SM-DS beside the Local eIM and its SM-DP+: Event Records and ES11.

An SM-DP+ registers an Event Record for an eUICC (SGP.22 v3.1 §3.6.1), and an
LPA, an IPA or an eIM retrieves the records of that eUICC after the Common
Mutual Authentication with CERT.DSauth.SIG (§3.6.2, §5.8; SGP.32 v1.3 §3.9.2),
then goes to the RSP Server each record names with the EventID as its Matching
ID. ``LocalSmds`` keeps the records in the engine store and answers
ES11.InitiateAuthentication and ES11.AuthenticateClient in the shape of the
JSON binding, the way ``LocalSmdp`` answers ES9+; the ASN.1 binding
(``es11_binding``) and the eIM's relay call the same two functions.

It is a Root SM-DS at the level of SGP.22 version 2: one address, Variant O
certificates from the SGP.26 test bundle, unsigned Event Records. Registration
and deletion are the ES12 functions (§5.9) called in process, by the operator
or by the local SM-DP+ when a download it served ends (§3.1.3.3 step 10).
``NOT_SUPPORTED`` names what is left out, each with what the SM-DS answers
instead. Only an eUICC that trusts the SGP.26 test eSIM CA accepts
CERT.DSauth.SIG, so a card under a live eSIM CA refuses the session.
"""

from __future__ import annotations

import datetime
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine.store import DATABASE_FILE, EimStore, SmdsEvent, StoreError, utc_now
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

ADDRESS_SETTING = "smds_address"
DEFAULT_ADDRESS = "smds.example.test"
# Open ES11 sessions are kept per transactionId until AuthenticateClient; a
# client that never finishes is pushed out by newer ones.
MAX_OPEN_TRANSACTIONS = 64
# RegisterEvent eventType (SGP.22 v3.1 §5.9.1, Table 53).
EVENT_TYPE_PROFILE_DOWNLOAD = 1
EVENT_TYPE_RPM = 2
EVENT_TYPES: dict[int, str] = {EVENT_TYPE_PROFILE_DOWNLOAD: "Profile Download", EVENT_TYPE_RPM: "RPM"}
# OperationType bits of ctxParamsForCommonAuthentication (§5.7.13) and the eventType each asks for.
_OPERATION_TYPE_BITS: dict[int, int] = {0: EVENT_TYPE_PROFILE_DOWNLOAD, 1: EVENT_TYPE_RPM}
# EuiccRspCapability euiccRspCapInInfo1 (§5.7.8).
_EUICC_RSP_CAP_IN_INFO1_BIT = 18
# id-rsp-extension-permitted-eins (§2.4a.1.0): the EINs of an EUM certificate outside Variant O.
_PERMITTED_EINS_OID = "2.23.146.1.2.2.0"
_MAX_CHAIN_DEPTH = 4
# The roles of a eUICC certificate chain (§4.5.2.1.0.2, §4.5.2.1.0.3, §2.4a.1.0): the leaf, and the CAs above it.
_EUICC_ROLES = frozenset({"euicc", "euicc-v2"})
_EUICC_CA_ROLES = frozenset({"eum", "eum-v2", "eumSubCa", "ciSubCa"})

_HOST_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
# An EventID travels as a Matching ID and inside an Activation Code built from it (SGP.22 v3.1
# §3.6.2 step 10, §4.1): printable, no blank and no '$', which separates the fields of the code.
_EVENT_ID = re.compile(r"^[\x21-\x23\x25-\x7E]{1,255}$")


@dataclass(frozen=True)
class Status:
    """One row of a status code table: the pair the JSON binding carries and the ASN.1 error it maps to.

    ``asn1`` is the value of the function's error INTEGER in the ASN.1
    binding (SGP.22 v3.1 §6.6.2); None for a function that binding does not
    carry (ES12) and for a row no value stands for.
    """

    function: str
    subject_code: str
    reason_code: str
    subject: str
    reason: str
    asn1: int | None = None


# ES11.InitiateAuthentication, SGP.22 v3.1 §5.8.1 Table 48a. The ASN.1 binding has no value of its own
# for "SM-DS Certificate - Unavailable": it is answered ciPKIdNotSupported, the value of the row beside it.
ADDRESS_REFUSED = Status("InitiateAuthentication", "8.9.1", "3.8", "SM-DS Address", "Refused", 1)
SECURITY_CONFIGURATION_UNSUPPORTED = Status(
    "InitiateAuthentication", "8.9.2", "3.1", "Security configuration", "Unsupported", 3)
CERTIFICATE_UNAVAILABLE = Status("InitiateAuthentication", "8.9.4", "3.7", "SM-DS Certificate", "Unavailable", 3)
INITIATE_AUTHENTICATION_STATUS = (ADDRESS_REFUSED, SECURITY_CONFIGURATION_UNSUPPORTED, CERTIFICATE_UNAVAILABLE)

# ES11.AuthenticateClient, SGP.22 v3.1 §5.8.2 Table 52. A certificate row answers with the value for
# the eUICC certificate here; the raise site gives the EUM one when a certificate further up failed.
CERTIFICATE_VERIFICATION_FAILED = Status(
    "AuthenticateClient", "8.1.3", "6.1", "eUICC Certificate", "Verification Failed", 3)
CERTIFICATE_EXPIRED = Status("AuthenticateClient", "8.1.3", "6.3", "eUICC Certificate", "Expired", 4)
EUICC_VERIFICATION_FAILED = Status("AuthenticateClient", "8.1", "6.1", "eUICC", "Verification Failed", 5)
TRANSACTION_ID_UNKNOWN = Status("AuthenticateClient", "8.10.1", "3.9", "TransactionId", "Unknown", 7)
CI_PUBLIC_KEY_UNKNOWN = Status("AuthenticateClient", "8.11.1", "3.9", "CI Public Key", "Unknown", 8)
EVENT_RECORD_UNKNOWN = Status("AuthenticateClient", "8.9.5", "3.9", "Event Record", "Unknown", 6)
EUICC_VALUE_HAS_CHANGED = Status("AuthenticateClient", "8.1", "3.11", "eUICC", "Value has Changed", 10)
LPA_VALUE_HAS_CHANGED = Status("AuthenticateClient", "8.12", "3.11", "LPA", "Value has Changed", 11)
PUSH_SERVICE_UNSUPPORTED = Status("AuthenticateClient", "8.9.7", "3.1", "Push Service", "Unsupported", 12)
PUSH_REGISTRATION_UNSUPPORTED = Status(
    "AuthenticateClient", "8.10.6", "3.1", "Push Service Registration", "Unsupported", 13)
PUSH_REGISTRATION_INVALID_MATCH = Status(
    "AuthenticateClient", "8.10.6", "3.12", "Push Service Registration", "Invalid Match", None)
FUNCTION_UNSUPPORTED = Status("AuthenticateClient", "1.6", "3.1", "Function", "Unsupported", 127)
AUTHENTICATE_CLIENT_STATUS = (
    CERTIFICATE_VERIFICATION_FAILED, CERTIFICATE_EXPIRED, EUICC_VERIFICATION_FAILED, TRANSACTION_ID_UNKNOWN,
    CI_PUBLIC_KEY_UNKNOWN, EVENT_RECORD_UNKNOWN, EUICC_VALUE_HAS_CHANGED, LPA_VALUE_HAS_CHANGED,
    PUSH_SERVICE_UNSUPPORTED, PUSH_REGISTRATION_UNSUPPORTED, PUSH_REGISTRATION_INVALID_MATCH, FUNCTION_UNSUPPORTED,
)
# The other values of authenticateClientError that a certificate or eSIM CA row answers with (§6.6.2.7).
ASN1_EUM_CERTIFICATE_INVALID = 1
ASN1_EUM_CERTIFICATE_EXPIRED = 2
ASN1_CI_PK_MISMATCH = 9

# ES11.CheckEvent, SGP.22 v3.1 §5.8.3 Table 52c.
EVENT_CHECKING_UNSUPPORTED = Status("CheckEvent", "8.10.4", "3.1", "Event Checking", "Unsupported", 2)
ECID_EXPIRED = Status("CheckEvent", "8.9.6", "6.3", "ECID", "Expired", 3)
ECID_UNKNOWN = Status("CheckEvent", "8.9.6", "3.9", "ECID", "Unknown", 4)
CHECK_EVENT_ADDRESS_REFUSED = Status("CheckEvent", "8.9.1", "3.8", "SM-DS Address", "Refused", 1)
CHECK_EVENT_STATUS = (EVENT_CHECKING_UNSUPPORTED, ECID_EXPIRED, ECID_UNKNOWN, CHECK_EVENT_ADDRESS_REFUSED)

# ES12.RegisterEvent and ES12.DeleteEvent, SGP.22 v3.1 §5.9.1 Table 54 and §5.9.2 Table 56.
EVENT_RECORD_IN_USE = Status("RegisterEvent", "8.9.5", "3.3", "Event Record", "Already in Use")
REGISTER_SMDS_INACCESSIBLE = Status("RegisterEvent", "8.9", "5.1", "SM-DS", "Inaccessible")
REGISTER_SMDS_EXECUTION_ERROR = Status("RegisterEvent", "8.9", "4.2", "SM-DS", "Execution Error")
REGISTER_EVENT_STATUS = (EVENT_RECORD_IN_USE, REGISTER_SMDS_INACCESSIBLE, REGISTER_SMDS_EXECUTION_ERROR)
DELETE_EVENT_RECORD_UNKNOWN = Status("DeleteEvent", "8.9.5", "3.9", "Event Record", "Unknown")
DELETE_SMDS_INACCESSIBLE = Status("DeleteEvent", "8.9", "5.1", "SM-DS", "Inaccessible")
DELETE_SMDS_EXECUTION_ERROR = Status("DeleteEvent", "8.9", "4.2", "SM-DS", "Execution Error")
DELETE_EVENT_STATUS = (DELETE_EVENT_RECORD_UNKNOWN, DELETE_SMDS_INACCESSIBLE, DELETE_SMDS_EXECUTION_ERROR)

# The common status codes any function may answer (SGP.02 v4.2 §5.1.6.4 Table 117) and the ASN.1 values
# SGP.22 v3.1 §6.6.1.1 gives them; the same clause calls the three requester and validity rows not
# relevant on ES11.
FUNCTION_INVALID = Status("common", "1.6", "2.1", "Function", "Invalid", 124)
MANDATORY_ELEMENT_MISSING = Status("common", "1.6", "2.2", "Function", "Mandatory Element Missing", 125)
CONDITIONAL_ELEMENT_MISSING = Status("common", "1.6", "2.3", "Function", "Conditional Element Missing", 125)
FUNCTION_PROVIDER_BUSY = Status("common", "1.2", "4.4", "Function Provider", "Busy", 126)
EXECUTION_ERROR = Status("common", "1.2", "4.2", "Function Provider", "Execution Error", 127)
COMMON_STATUS = (FUNCTION_INVALID, MANDATORY_ELEMENT_MISSING, CONDITIONAL_ELEMENT_MISSING, FUNCTION_PROVIDER_BUSY,
                 EXECUTION_ERROR)

# Rows of the tables above this SM-DS never answers, each with the reason.
STATUS_NEVER_RETURNED: dict[Status, str] = {
    PUSH_REGISTRATION_UNSUPPORTED: "a Push Service Registration is refused as Push Service - Unsupported first",
    PUSH_REGISTRATION_INVALID_MATCH: "a Push Service Registration is refused as Push Service - Unsupported first",
    ECID_EXPIRED: "no ECID is ever handed out: Event Checking is not supported",
    ECID_UNKNOWN: "no ECID is ever handed out: Event Checking is not supported",
    CHECK_EVENT_ADDRESS_REFUSED: "Event Checking - Unsupported is answered before the address is looked at",
    REGISTER_SMDS_INACCESSIBLE: "a Root SM-DS cascades no registration",
    REGISTER_SMDS_EXECUTION_ERROR: "a Root SM-DS cascades no registration",
    DELETE_SMDS_INACCESSIBLE: "a Root SM-DS cascades no deletion",
    DELETE_SMDS_EXECUTION_ERROR: "a Root SM-DS cascades no deletion",
    CONDITIONAL_ELEMENT_MISSING: "ES11 has no conditional input element at the version 2 level",
    FUNCTION_PROVIDER_BUSY: "requests are answered as they arrive; nothing is queued",
}

# Values of the error INTEGERs of the ASN.1 binding (SGP.22 v3.1 §6.6.2.1, §6.6.2.7, §6.6.2.8) this
# SM-DS never answers with, by function, each with the reason.
ASN1_NEVER_RETURNED: dict[tuple[str, int], str] = {
    ("InitiateAuthentication", 2): "euiccVersionNotSupportedByDp is marked as used before version 3 only, and "
                                   "Table 48a has no row for it",
    ("InitiateAuthentication", 126): "requests are answered as they arrive; nothing is queued",
    ("AuthenticateClient", 13): "a Push Service Registration is answered pushServiceNotSupport first",
    ("AuthenticateClient", 126): "requests are answered as they arrive; nothing is queued",
    ("CheckEvent", 1): "eventCheckingNotSupported is answered before the address is looked at",
    ("CheckEvent", 3): "no ECID is ever handed out",
    ("CheckEvent", 4): "no ECID is ever handed out",
    ("CheckEvent", 124): "eventCheckingNotSupported is answered before the input is looked at",
    ("CheckEvent", 125): "eventCheckingNotSupported is answered before the input is looked at",
    ("CheckEvent", 126): "requests are answered as they arrive; nothing is queued",
    ("CheckEvent", 127): "eventCheckingNotSupported is the one answer",
}

# What SGP.22 v3.1 defines for an SM-DS and this one leaves out: the feature, then what it does instead.
NOT_SUPPORTED: dict[str, str] = {
    "signed Event Records (eventListSigningV3Support, smdsSigned2, §3.6.2 steps 3 to 7)":
        "serverSigned1 carries no serverRspCapability, and AuthenticateClient answers the unsigned eventEntries "
        "of version 2 (§3.6.2 step 8)",
    "Event Checking (ES11.CheckEvent, ECID, §3.6.4, §5.8.3)":
        "CheckEvent is answered Event Checking - Unsupported, and no ECID is generated",
    "Push Service (ctxParamsForPushServiceRegistration, §3.6.5)":
        "a Push Service Registration is answered Push Service - Unsupported",
    "certificate chain Variants Ov3, A, B and C (euiccCiPKIdListForSigningV3, sessionContext, §4.5.2.0b)":
        "only CERT.DSauth.SIG of a Variant O chain is served, with euiccCiPKIdToBeUsed",
    "CRL stapling and revocation checks (crlStaplingV3Support, §4.5.2.2, §4.6)":
        "no CRL is retrieved or attached; the eUICC chain is verified without a revocation check",
    "the certificate profile restrictions of the eUICC chain beyond those named here (§4.5.2.1.0, §4.5.2.2)":
        "the signatures, the validity periods, the CA flag, a declared RSP role, the eUICC key usage and the "
        "EID against the permitted EINs are verified; no other field of a certificate is",
    "eUICC Root Public Key update (euiccCiUpdateSupport, §5.6.1)":
        "without a CERT.DSauth.SIG the eUICC can verify the answer is SM-DS Certificate - Unavailable",
    "ES12 and ES15 over HTTP with mutual TLS (§5.9, §5.10)":
        "RegisterEvent and DeleteEvent are called in process, by the operator or the local SM-DP+",
    "cascaded registration to a Root SM-DS (forwardingIndicator, rootSmdsAddress, §3.6.1.2)":
        "both inputs are ignored, as a Root SM-DS does (§5.9.1)",
    "hashedIccids, salt, serviceProviderName and operatorId of an Event Record (§5.9.1 Table 53)":
        "not stored: only the signed EventRecordV3 carries them to an LPA",
    "deleting an Event Record at the SM-DS a matchingIdSource names (§5.8.2)":
        "an unknown EventID is answered Event Record - Unknown and nothing else is contacted",
    "ES11.CheckEvent on the JSON binding":
        "SGP.22 v3.1 §6.5.2 Table 57 gives the function no path; the ASN.1 binding answers it",
}


class SmdsError(RuntimeError):
    """A request the local SM-DS refuses; ``status`` is the code pair and ``asn1`` the ASN.1 error value."""

    def __init__(self, status: Status, message: str = "", *, asn1: int | None = None) -> None:
        super().__init__(message or f"{status.subject} - {status.reason}")
        self.status = status
        self.asn1 = status.asn1 if asn1 is None else int(asn1)

    def header(self) -> dict[str, Any]:
        """The <JSON responseHeader> of a failed function (SGP.22 v3.1 §6.5.1.4)."""
        return {"functionExecutionStatus": {"status": "Failed", "statusCodeData": {
            "subjectCode": self.status.subject_code, "reasonCode": self.status.reason_code,
            "message": str(self)[:200],
        }}}


@dataclass(frozen=True)
class AuthCredential:
    """One CERT.DSauth.SIG with SK.DSauth.SIG and the eSIM CA RootCA key its chain ends at."""

    certificate: bytes
    private_key: Any
    root_ci_pkid: bytes
    label: str = ""


@dataclass(frozen=True)
class SmdsMaterial:
    """What the SM-DS signs with and what it verifies eUICC chains against (eSIM CA RootCA certificates)."""

    credentials: tuple[AuthCredential, ...] = ()
    ci_certificates: tuple[bytes, ...] = ()


def bundle_material() -> SmdsMaterial:
    """The Variant O CERT.DSauth.SIG pairs and the eSIM CA RootCA certificates of the SGP.26 test bundle.

    Variant O is told by the certificate itself: issued by a self-signed
    eSIM CA certificate of the bundle and carrying id-rspRole-ds-auth-v2
    (SGP.22 v3.1 §2.4a.1.0). The preferred curve of the configuration comes
    first, so an eUICC that accepts both is served that one.
    """
    from SCP11.eim_local.config import EimLocalConfig
    from SCP11.local_access.cert_store import LocalSgp26CertStore
    from SCP11.shared.rsp_roles import certificate_rsp_roles

    cfg = EimLocalConfig()
    preferred = str(getattr(cfg, "CERT_CURVE_PREFERENCE", "") or "").strip().upper()
    store = LocalSgp26CertStore(valid_cert_root=cfg.SGP26_VALID_CERT_DIR, prefer_curve=preferred or "NIST")
    roots: dict[str, bytes] = {}
    for record in store.ci_records():
        if record.subject == record.issuer and len(record.ski) > 0:
            roots.setdefault(record.ski, record.der_bytes)
    credentials: list[tuple[int, AuthCredential]] = []
    for record in store.ds_auth_records():
        if record.aki not in roots:
            continue
        roles = certificate_rsp_roles(record.der_bytes)
        if roles is not None and "ds-auth-v2" not in roles:
            continue
        rank = 0 if record.curve == preferred else 1
        credentials.append((rank, AuthCredential(
            certificate=record.der_bytes, private_key=record.private_key,
            root_ci_pkid=bytes.fromhex(record.root_ci_ski), label=os.path.basename(record.certificate_path),
        )))
    credentials.sort(key=lambda item: item[0])
    return SmdsMaterial(credentials=tuple(item[1] for item in credentials), ci_certificates=tuple(roots.values()))


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item_value, raw, offset = read_ber_tlv(value, offset)
        items.append((tag, item_value, raw))
    return items


def _member(value: bytes, tag: bytes) -> bytes | None:
    for item_tag, item_value, _raw in _children(value):
        if item_tag == tag:
            return bytes(item_value)
    return None


def _bits(bit_string: bytes | None) -> tuple[int, ...]:
    """The numbers of the bits set in the value of a BIT STRING (its first octet counts the unused bits)."""
    if not bit_string or len(bit_string) < 2:
        return ()
    found: list[int] = []
    for index, octet in enumerate(bit_string[1:]):
        for bit in range(8):
            if octet & (0x80 >> bit):
                found.append(index * 8 + bit)
    return tuple(found)


def host_name(address: Any, what: str = "address") -> str:
    """*address* as a bare host name in lower case; SmdsError (Function - Invalid) for anything else."""
    host = str(address or "").strip().lower().rstrip(".")
    if _HOST_NAME.match(host) is None:
        raise SmdsError(FUNCTION_INVALID, f"{what} {str(address)[:80]!r} is no host name (an FQDN without scheme, "
                                          "port or path)")
    return host


def key_identifier_list(euicc_info1: bytes, tag: bytes) -> list[bytes]:
    """A SEQUENCE OF SubjectKeyIdentifier of EUICCInfo1 'BF20' (SGP.22 v3.1 §5.7.8): 'A9' the eSIM CA keys the
    eUICC verifies with, 'AA' the ones it signs under in a Variant O chain."""
    found, value, _raw = read_single_ber_tlv(bytes(euicc_info1 or b""))
    if found != b"\xBF\x20":
        raise ValueError("euiccInfo1 is not an EUICCInfo1 'BF20'")
    listed = _member(value, tag)
    if listed is None:
        return []
    return [bytes(item) for item_tag, item, _raw in _children(listed) if item_tag == b"\x04"]


@dataclass
class _Response:
    """authenticateResponseOk of an AuthenticateServerResponse (SGP.22 v3.1 §5.7.13)."""

    signed1: bytes
    signature: bytes
    euicc_certificate: bytes
    next_certificate: bytes
    other_certificates: list[bytes]
    transaction_id: bytes
    server_challenge: bytes
    euicc_info2: bytes
    ctx_tag: bytes
    ctx_value: bytes


def _read_response(authenticate_server_response: bytes) -> _Response:
    """Split 'BF38' { 'A0' { euiccSigned1, '5F37', euiccCertificate, nextCertInChain, ['A0' otherCertsInChain] } }."""
    try:
        tag, value, raw = read_single_ber_tlv(bytes(authenticate_server_response or b""))
        if tag != b"\xBF\x38" or len(raw) != len(authenticate_server_response):
            raise ValueError("not one AuthenticateServerResponse 'BF38'")
        choices = _children(value)
        if len(choices) != 1 or choices[0][0] != b"\xA0":
            raise ValueError("no authenticateResponseOk: the eUICC did not authenticate the SM-DS")
        sequences: list[bytes] = []
        signature = b""
        others: list[bytes] = []
        for item_tag, item_value, item_raw in _children(choices[0][1]):
            if item_tag == b"\x30":
                sequences.append(bytes(item_raw))
            elif item_tag == b"\x5F\x37":
                signature = bytes(item_value)
            elif item_tag == b"\xA0":
                others = [bytes(certificate_raw) for certificate_tag, _v, certificate_raw in _children(item_value)
                          if certificate_tag == b"\x30"]
        if len(sequences) != 3 or len(signature) == 0:
            raise ValueError("authenticateResponseOk lacks euiccSigned1, euiccSignature1 or a certificate")
        _tag, signed_value, _raw = read_single_ber_tlv(sequences[0])
        members = _children(signed_value)
        ctx = [(member_tag, member_value) for member_tag, member_value, _r in members
               if member_tag in (b"\xA0", b"\xA1", b"\xA2", b"\xA3")]
        if len(ctx) != 1:
            raise ValueError("euiccSigned1 carries no single ctxParams1")
        return _Response(
            signed1=sequences[0], signature=signature, euicc_certificate=sequences[1],
            next_certificate=sequences[2], other_certificates=others,
            transaction_id=_member(signed_value, b"\x80") or b"",
            server_challenge=_member(signed_value, b"\x84") or b"",
            euicc_info2=_member(signed_value, b"\xBF\x22") or b"",
            ctx_tag=ctx[0][0], ctx_value=ctx[0][1],
        )
    except (ValueError, IndexError) as error:
        raise SmdsError(FUNCTION_INVALID, f"authenticateServerResponse: {error}") from error


def _subject_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        return bytes(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
    except x509.ExtensionNotFound:
        return b""


def _authority_key_identifier(certificate: x509.Certificate) -> bytes:
    try:
        value = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        return b""
    return bytes(value.key_identifier or b"")


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return bool(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _issued(certificate: x509.Certificate, candidate: x509.Certificate) -> bool:
    """Whether *candidate* is named as the issuer of *certificate*: by name, and by key identifier when both
    carry one (RFC 5280 §4.2.1.1). The SGP.26 eSIM CA certificates share one subject name, so the name alone
    does not tell them apart."""
    if candidate.subject != certificate.issuer:
        return False
    authority = _authority_key_identifier(certificate)
    subject = _subject_key_identifier(candidate)
    return len(authority) == 0 or len(subject) == 0 or authority == subject


def _permitted_eins(eum: x509.Certificate) -> tuple[list[tuple[str, str]], list[str]]:
    """What an EUM certificate permits its eUICC certificates (SGP.22 v3.1 §4.5.2.1.0.3 Table 12).

    Returns the (organization, EIN) pairs of the nameConstraints permitted
    subtrees, the EIN '' where a subtree names none, and the EINs of the
    Permitted EINs extension.
    """
    subtrees: list[tuple[str, str]] = []
    try:
        constraints = eum.extensions.get_extension_for_class(x509.NameConstraints).value
        for subtree in constraints.permitted_subtrees or []:
            if not isinstance(subtree, x509.DirectoryName):
                continue
            organizations = subtree.value.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            serials = subtree.value.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
            subtrees.append((str(organizations[0].value) if organizations else "",
                             str(serials[0].value).strip() if serials else ""))
    except x509.ExtensionNotFound:
        pass
    eins: list[str] = []
    for extension in eum.extensions:
        if extension.oid.dotted_string != _PERMITTED_EINS_OID or not isinstance(
                extension.value, x509.UnrecognizedExtension):
            continue
        try:
            tag, value, _raw = read_single_ber_tlv(bytes(extension.value.value))
            if tag == b"\x30":
                eins.extend(item.decode("ascii", errors="replace").strip() for item_tag, item, _r in _children(value)
                            if item_tag == b"\x13")
        except (ValueError, IndexError):
            continue
    return subtrees, eins


def eid_permitted(euicc: x509.Certificate, eum: x509.Certificate, eid: str) -> bool:
    """Whether *eid* is consistent with the EINs the EUM certificate permits (SGP.22 v3.1 §4.5.2.2).

    Variant O gives the EINs as the 'serialNumber' of the nameConstraints
    subtrees: the EID has to start with one, under the subtree's
    organization, and the 'serialNumber' is not matched as RFC 5280 would
    (the clause forbids that). The other variants list the EINs in the
    Permitted EINs extension. An EUM certificate that names neither permits
    any EID.
    """
    subtrees, eins = _permitted_eins(eum)
    if len(eins) > 0 and not any(eid.startswith(ein) for ein in eins if ein):
        return False
    if len(subtrees) == 0:
        return True
    organizations = [str(item.value) for item in euicc.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    for organization, ein in subtrees:
        if organization and organization not in organizations:
            continue
        if ein and not eid.startswith(ein):
            continue
        return True
    return False


def verify_euicc_chain(
    response_certificates: list[bytes],
    roots: dict[bytes, bytes],
    now: datetime.datetime,
) -> tuple[bytes, str]:
    """Verify CERT.EUICC.SIG up to an eSIM CA RootCA certificate; return (the root's key identifier, the EID).

    *response_certificates* are the eUICC certificate, the one certifying
    it and any further ones of the chain (SGP.22 v3.1 §5.7.13); *roots* maps
    a Subject Key Identifier to an eSIM CA RootCA certificate. Each
    signature, each validity period, the RSP role and key usage a certificate
    declares, and the EID against the EINs every CA of the chain permits are
    checked (§4.5.2.2, §5.8.2); no revocation status is.
    """
    from SCP11.eim_local.engine.codec import certificate_eid
    from SCP11.shared.rsp_roles import check_rsp_role

    if len(response_certificates) < 2:
        raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the eUICC certificate chain lacks a certificate")
    loaded: list[x509.Certificate] = []
    for index, der in enumerate(response_certificates):
        try:
            loaded.append(x509.load_der_x509_certificate(bytes(der)))
        except ValueError as error:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, f"certificate {index + 1} of the eUICC chain does not "
                            f"parse: {error}", asn1=None if index == 0 else ASN1_EUM_CERTIFICATE_INVALID) from error
    euicc = loaded[0]
    eid = certificate_eid(response_certificates[0])
    if len(eid) == 0:
        raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the eUICC certificate names no EID in its subject")
    path = [euicc]
    pool = loaded[1:]
    root: x509.Certificate | None = None
    current = euicc
    while root is None:
        if len(path) > _MAX_CHAIN_DEPTH:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the eUICC certificate chain is too long",
                            asn1=ASN1_EUM_CERTIFICATE_INVALID)
        issuer = next((candidate for candidate in pool if _issued(current, candidate)), None)
        if issuer is None:
            candidate_der = next((der for der in roots.values()
                                  if _issued(current, x509.load_der_x509_certificate(der))), None)
            if candidate_der is None:
                if len(path) == 1:
                    raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the certificate certifying the eUICC "
                                    "certificate is missing from the chain", asn1=ASN1_EUM_CERTIFICATE_INVALID)
                raise SmdsError(CI_PUBLIC_KEY_UNKNOWN, "the eUICC certificate chain ends at no eSIM CA RootCA "
                                                       "certificate this SM-DS trusts")
            issuer = x509.load_der_x509_certificate(candidate_der)
            root = issuer
        else:
            pool = [candidate for candidate in pool if candidate is not issuer]
        failed_asn1 = None if current is euicc else ASN1_EUM_CERTIFICATE_INVALID
        if not _is_ca(issuer):
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "a certificate of the eUICC chain was issued by one "
                            "that is no CA", asn1=ASN1_EUM_CERTIFICATE_INVALID)
        try:
            current.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as error:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "a signature in the eUICC certificate chain does not "
                            f"verify ({type(error).__name__})", asn1=failed_asn1) from error
        if root is None:
            path.append(issuer)
            current = issuer
    for index, certificate in enumerate([*path, root]):
        own = index == 0
        if now > certificate.not_valid_after_utc:
            raise SmdsError(CERTIFICATE_EXPIRED, "a certificate of the eUICC chain has expired",
                            asn1=None if own else ASN1_EUM_CERTIFICATE_EXPIRED)
        if now < certificate.not_valid_before_utc:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "a certificate of the eUICC chain is not valid yet",
                            asn1=None if own else ASN1_EUM_CERTIFICATE_INVALID)
    try:
        usage = euicc.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the eUICC certificate is not one for signatures "
                                                             "(keyUsage without digitalSignature)")
    except x509.ExtensionNotFound:
        pass
    for index, certificate in enumerate(path):
        own = index == 0
        try:
            # A certificate without certificatePolicies passes: a lab chain carries no role at all.
            check_rsp_role(response_certificates[index] if own else certificate.public_bytes(
                serialization.Encoding.DER), _EUICC_ROLES if own else _EUICC_CA_ROLES,
                "the eUICC certificate" if own else "a CA certificate of the eUICC chain")
        except ValueError as error:
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, str(error),
                            asn1=None if own else ASN1_EUM_CERTIFICATE_INVALID) from error
    # The name constraints of a CA bind every certificate below it (§4.5.2.1.0.3 Table 12 NOTE 1), so
    # the EUM's EINs hold through an EUM SubCA as well.
    for authority in path[1:]:
        if not eid_permitted(euicc, authority, eid):
            raise SmdsError(CERTIFICATE_VERIFICATION_FAILED, "the EID is not one the EUM certificate permits")
    return _subject_key_identifier(root), eid


def default_store(directory: Path) -> EimStore:
    return EimStore(Path(directory) / DATABASE_FILE)


class LocalSmds:
    """Event Records and ES11 answers of the local SM-DS; one instance per service process."""

    def __init__(
        self,
        directory: Path,
        *,
        material_factory: Callable[[], SmdsMaterial] | None = None,
        store: EimStore | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.store = store if store is not None else default_store(self.directory)
        self._factory = material_factory or bundle_material
        self._material: SmdsMaterial | None = None
        self._clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self._lock = threading.RLock()
        self._transactions: OrderedDict[str, dict[str, Any]] = OrderedDict()
        # The SM-DP+ of the same service, when there is one: a name both were given stays the SM-DP+'s.
        self.smdp: Any = None
        self.log: Callable[[str], None] = lambda _line: None

    # -- configuration -----------------------------------------------------

    def address(self) -> str:
        """The FQDN this SM-DS answers under (the ``smds_address`` setting of the store)."""
        return str(self.store.setting(ADDRESS_SETTING, DEFAULT_ADDRESS) or "").strip().lower()

    def set_address(self, address: str) -> str:
        host = host_name(address, "The SM-DS address")
        self.store.set_setting(ADDRESS_SETTING, host)
        return host

    def material(self) -> SmdsMaterial:
        with self._lock:
            if self._material is None:
                self._material = self._factory()
            return self._material

    def oid(self) -> str:
        """The SM-DS OID of the first CERT.DSauth.SIG (its subjectAltName registeredID), or ''."""
        from SCP11.eim_local.engine.indirect import certificate_oids

        try:
            credentials = self.material().credentials
        except (OSError, ValueError, RuntimeError):
            return ""
        for credential in credentials:
            oids = sorted(certificate_oids(credential.certificate))
            if oids:
                return oids[0]
        return ""

    def transaction(self, transaction_id: bytes) -> dict[str, Any] | None:
        """What is kept of an open ES11 session, or None for a transactionId this SM-DS did not hand out."""
        with self._lock:
            entry = self._transactions.get(bytes(transaction_id).hex().upper())
            return dict(entry) if entry is not None else None

    def taken_by_the_smdp(self) -> bool:
        """Whether the SM-DS address is also the address of the SM-DP+ beside it.

        One name cannot stand for two servers on the paths they share: the
        SM-DP+ keeps it, every download would otherwise be answered by the
        SM-DS, and the SM-DS then answers no request at all.
        """
        if self.smdp is None:
            return False
        own = self.address()
        try:
            names = {str(self.smdp.address() or "").strip().lower().rstrip("."), str(self.smdp.host() or "")}
        except (OSError, ValueError, RuntimeError, AttributeError):
            return False
        return len(own) > 0 and own in names

    def owns_address(self, address: Any) -> bool:
        """Whether *address* names this SM-DS; the comparison is case-insensitive (SGP.22 v3.1 §5.6.1)."""
        own = self.address()
        if len(own) == 0 or str(address or "").strip().lower().rstrip(".") != own:
            return False
        return not self.taken_by_the_smdp()

    # -- ES12: Event Records (in process) ----------------------------------

    def register_event(
        self,
        eid: str,
        rsp_server_address: str,
        event_id: str,
        *,
        event_type: int | None = None,
        caller: str = "",
        forwarding_indicator: bool = False,
        root_smds_address: str = "",
    ) -> SmdsEvent:
        """ES12.RegisterEvent (SGP.22 v3.1 §5.9.1, Table 53) for a Root SM-DS.

        *caller* is the function caller's identity, within which the EventID
        is unique; without one it is the RSP Server address. A missing
        *event_type* is a version 2 caller's and means a Profile download.
        *forwarding_indicator* and *root_smds_address* are ignored, as the
        clause has a Root SM-DS do.
        """
        from SCP11.eim_local.engine import codec

        del forwarding_indicator, root_smds_address
        try:
            normalized = codec.normalize_eid(str(eid or ""))
        except (codec.CodecError, ValueError) as error:
            raise SmdsError(FUNCTION_INVALID, f"eid: {error}") from error
        host = host_name(rsp_server_address, "rspServerAddress")
        identifier = str(event_id or "").strip()
        if len(identifier) == 0:
            raise SmdsError(MANDATORY_ELEMENT_MISSING, "eventId is missing")
        if _EVENT_ID.match(identifier) is None:
            raise SmdsError(FUNCTION_INVALID, "eventId is 1 to 255 printable characters without a blank or '$'")
        kind = EVENT_TYPE_PROFILE_DOWNLOAD if event_type is None else int(event_type)
        if kind not in EVENT_TYPES:
            raise SmdsError(FUNCTION_INVALID, "eventType is 1 (Profile Download) or 2 (RPM)")
        owner = str(caller or "").strip() or host
        event = SmdsEvent(id=0, at=utc_now(), eid=normalized, event_id=identifier, rsp_server_address=host,
                          event_type=kind, caller=owner)
        try:
            with self.store.transaction() as connection:
                if self.store.smds_events(event_id=identifier, caller=owner, connection=connection):
                    raise SmdsError(EVENT_RECORD_IN_USE, f"EventID {identifier!r} is already registered by {owner}")
                self.store.insert_smds_event(event, connection)
        except StoreError as error:
            raise SmdsError(EXECUTION_ERROR, str(error)) from error
        self.log(f"ES12 registerEvent {identifier} for {normalized} at {host} ({EVENT_TYPES[kind]})")
        return event

    def delete_event(self, eid: str, event_id: str, *, caller: str | None = None) -> list[SmdsEvent]:
        """ES12.DeleteEvent (SGP.22 v3.1 §5.9.2, Table 55): the record of *caller* with this EventID and EID.

        ``caller=None`` is the operator's deletion, which takes the record
        whoever registered it. No record is Event Record - Unknown.
        """
        from SCP11.eim_local.engine import codec

        try:
            normalized = codec.normalize_eid(str(eid or ""))
        except (codec.CodecError, ValueError) as error:
            raise SmdsError(FUNCTION_INVALID, f"eid: {error}") from error
        identifier = str(event_id or "").strip()
        if len(identifier) == 0:
            raise SmdsError(MANDATORY_ELEMENT_MISSING, "eventId is missing")
        with self.store.transaction() as connection:
            found = self.store.smds_events(eid=normalized, event_id=identifier, caller=str(caller or ""),
                                           connection=connection)
            if len(found) == 0:
                raise SmdsError(DELETE_EVENT_RECORD_UNKNOWN, f"no Event Record {identifier!r} for {normalized}")
            self.store.delete_smds_events([event.id for event in found], connection)
        self.log(f"ES12 deleteEvent {identifier} for {normalized}")
        return found

    def events(self, eid: str = "") -> list[SmdsEvent]:
        """The Event Records on file, in the order registered; of one eUICC when *eid* is given."""
        from SCP11.eim_local.engine import codec

        if len(str(eid or "").strip()) == 0:
            return self.store.smds_events()
        try:
            return self.store.smds_events(eid=codec.normalize_eid(str(eid)))
        except (codec.CodecError, ValueError) as error:
            raise SmdsError(FUNCTION_INVALID, f"eid: {error}") from error

    def download_ended(self, eid: str, matching_id: str, rsp_server_address: str) -> list[SmdsEvent]:
        """Event Deletion by the SM-DP+ whose download for *matching_id* ended (SGP.22 v3.1 §3.1.3.3 step 10).

        The records of *eid* with that EventID at this RSP Server go; none is
        the usual case (a download that did not come from an Event Record)
        and is no error.
        """
        identifier = str(matching_id or "").strip()
        host = str(rsp_server_address or "").strip().lower().rstrip(".")
        if len(identifier) == 0 or len(str(eid or "")) == 0 or len(host) == 0:
            return []
        with self.store.transaction() as connection:
            found = [event for event in self.store.smds_events(eid=str(eid), event_id=identifier,
                                                              connection=connection)
                     if event.rsp_server_address == host]
            self.store.delete_smds_events([event.id for event in found], connection)
        for event in found:
            self.log(f"ES12 deleteEvent {event.event_id} for {event.eid}: its download at {host} ended")
        return found

    # -- ES11 --------------------------------------------------------------

    def handle(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """One ES11 function in the shape of the JSON binding; ES11 shares the ES9+ paths (SGP.22 v3.1 §6.5.2)."""
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if name == "initiateAuthentication":
            return self.initiate_authentication(payload)
        if name == "authenticateClient":
            return self.authenticate_client(payload)
        raise SmdsError(FUNCTION_UNSUPPORTED, f"ES11 has no function {name!r}")

    def _remember(self, transaction_hex: str, values: dict[str, Any]) -> None:
        with self._lock:
            self._transactions[transaction_hex] = dict(values)
            self._transactions.move_to_end(transaction_hex)
            while len(self._transactions) > MAX_OPEN_TRANSACTIONS:
                self._transactions.popitem(last=False)

    def _roots(self) -> dict[bytes, bytes]:
        roots: dict[bytes, bytes] = {}
        for der in self.material().ci_certificates:
            try:
                identifier = _subject_key_identifier(x509.load_der_x509_certificate(bytes(der)))
            except ValueError:
                continue
            if identifier:
                roots[identifier] = bytes(der)
        return roots

    def initiate_authentication(self, payload: dict[str, Any]) -> dict[str, Any]:
        """ES11.InitiateAuthentication (SGP.22 v3.1 §5.8.1, the SM-DS in the place of §5.6.1's SM-DP+)."""
        from SCP11.crypto_engine import CryptoEngine
        from SCP11.eim_local.engine.smdp import SmdpError, _b64, _decode_field

        try:
            challenge = _decode_field(payload.get("euiccChallenge"), "euiccChallenge")
            euicc_info1 = _decode_field(payload.get("euiccInfo1"), "euiccInfo1")
        except SmdpError as error:
            raise SmdsError(MANDATORY_ELEMENT_MISSING, str(error)) from error
        if len(challenge) != 16:
            raise SmdsError(FUNCTION_INVALID, "euiccChallenge is 16 octets")
        address = str(payload.get("smdpAddress", "") or "").strip()
        if len(address) == 0:
            raise SmdsError(MANDATORY_ELEMENT_MISSING, "smdpAddress is missing")
        if not self.owns_address(address):
            raise SmdsError(ADDRESS_REFUSED, f"{address[:80]!r} is not this SM-DS ({self.address() or 'no address'})")
        capability = b""
        if payload.get("lpaRspCapability"):
            try:
                capability = _decode_field(payload.get("lpaRspCapability"), "lpaRspCapability")
            except SmdpError as error:
                raise SmdsError(FUNCTION_INVALID, str(error)) from error
        try:
            for_verification = key_identifier_list(euicc_info1, b"\xA9")
            for_signing = key_identifier_list(euicc_info1, b"\xAA")
            _tag, info_value, _raw = read_single_ber_tlv(euicc_info1)
            euicc_capability = _member(info_value, b"\x88")
        except (ValueError, IndexError) as error:
            raise SmdsError(FUNCTION_INVALID, f"euiccInfo1: {error}") from error
        try:
            material = self.material()
        except (OSError, ValueError, RuntimeError) as error:
            raise SmdsError(CERTIFICATE_UNAVAILABLE, f"no CERT.DSauth.SIG could be loaded: {error}") from error
        roots = self._roots()
        # The eUICC's order is the priority among the keys it can sign under (§5.6.1).
        ci_pkid = next((identifier for identifier in for_signing if identifier in roots), None)
        if ci_pkid is None:
            raise SmdsError(SECURITY_CONFIGURATION_UNSUPPORTED, "the SM-DS holds none of the eSIM CA RootCA "
                            "certificates of euiccCiPKIdListForSigning")
        credential = None
        for identifier in for_verification:
            credential = next((item for item in material.credentials if item.root_ci_pkid == identifier), None)
            if credential is not None:
                break
        if credential is None:
            raise SmdsError(CERTIFICATE_UNAVAILABLE, "no CERT.DSauth.SIG chains to an eSIM CA RootCA key of "
                            "euiccCiPKIdListForVerification")
        signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(challenge, address)
        signed1_der = signed1 if isinstance(signed1, bytes) else signed1.dump()
        signature = CryptoEngine.sign_asn1(signed1_der, credential.private_key)
        transaction_hex = bytes(transaction_id).hex().upper()
        self._remember(transaction_hex, {
            "server_challenge": bytes(server_challenge), "ci_pkid": bytes(ci_pkid), "address": address,
            "euicc_rsp_capability": euicc_capability, "lpa_rsp_capability": capability,
        })
        self.log(f"ES11 initiateAuthentication {transaction_hex} for {address} with {credential.label or 'CERT.DSauth'}")
        return {
            "transactionId": transaction_hex,
            "serverSigned1": _b64(signed1_der),
            "serverSignature1": _b64(b"\x5F\x37" + bytes([len(signature)]) + signature),
            "euiccCiPKIdToBeUsed": _b64(b"\x04" + bytes([len(ci_pkid)]) + bytes(ci_pkid)),
            "serverCertificate": _b64(credential.certificate),
        }

    def authenticate_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        """ES11.AuthenticateClient (SGP.22 v3.1 §5.8.2): authenticate the eUICC, then its Event Records.

        The answer is the version 2 one, a transactionId and the unsigned
        eventEntries in the order registered; the RSP session ends with it,
        whatever the outcome.
        """
        from SCP11.eim_local.engine.compact import verify_euicc_signature
        from SCP11.eim_local.engine.smdp import SmdpError, _decode_field

        try:
            transaction_id = _decode_field(payload.get("transactionId"), "transactionId")
            response = _decode_field(payload.get("authenticateServerResponse"), "authenticateServerResponse")
        except SmdpError as error:
            raise SmdsError(MANDATORY_ELEMENT_MISSING, str(error)) from error
        transaction_hex = transaction_id.hex().upper()
        with self._lock:
            session = self._transactions.pop(transaction_hex, None)
        if session is None:
            raise SmdsError(TRANSACTION_ID_UNKNOWN, f"no RSP session {transaction_hex}")
        parsed = _read_response(response)
        root_pkid, eid = verify_euicc_chain(
            [parsed.euicc_certificate, parsed.next_certificate, *parsed.other_certificates],
            self._roots(), self._clock(),
        )
        if root_pkid != session["ci_pkid"]:
            raise SmdsError(CI_PUBLIC_KEY_UNKNOWN, "the eUICC certificate chain ends at another eSIM CA RootCA "
                            "key than the one this SM-DS selected", asn1=ASN1_CI_PK_MISMATCH)
        if not verify_euicc_signature(parsed.euicc_certificate, parsed.signed1, parsed.signature):
            raise SmdsError(EUICC_VERIFICATION_FAILED, "euiccSignature1 does not verify")
        if parsed.transaction_id != transaction_id:
            raise SmdsError(EUICC_VERIFICATION_FAILED, "euiccSigned1 names another transactionId")
        if parsed.server_challenge != session["server_challenge"]:
            raise SmdsError(EUICC_VERIFICATION_FAILED, "serverChallenge is not the one of this RSP session")
        signed_capability = _member(parsed.euicc_info2, b"\x88")
        if _EUICC_RSP_CAP_IN_INFO1_BIT in _bits(signed_capability) and (
                _bits(session["euicc_rsp_capability"]) != _bits(signed_capability)):
            raise SmdsError(EUICC_VALUE_HAS_CHANGED, "euiccRspCapability differs from the one in euiccInfo1")
        if parsed.ctx_tag == b"\xA3":
            raise SmdsError(PUSH_SERVICE_UNSUPPORTED, "this SM-DS supports no Push Service")
        if parsed.ctx_tag != b"\xA0":
            raise SmdsError(FUNCTION_UNSUPPORTED, "ctxParams1 is neither an Event Retrieval nor a Push Service "
                                                  "Registration")
        device_info = _member(parsed.ctx_value, b"\xA1") or b""
        if len(session["lpa_rsp_capability"]) > 0:
            given = session["lpa_rsp_capability"]
            if given[:1] == b"\x85":
                try:
                    _tag, given, _raw = read_single_ber_tlv(given)
                except (ValueError, IndexError) as error:
                    raise SmdsError(FUNCTION_INVALID, f"lpaRspCapability: {error}") from error
            if _bits(given) != _bits(_member(device_info, b"\x85")):
                raise SmdsError(LPA_VALUE_HAS_CHANGED, "lpaRspCapability differs from the one given to "
                                                       "InitiateAuthentication")
        operation = _member(parsed.ctx_value, b"\x82")
        wanted = [_OPERATION_TYPE_BITS[bit] for bit in _bits(operation) if bit in _OPERATION_TYPE_BITS]
        if operation is None or len(wanted) == 0:
            wanted = [EVENT_TYPE_PROFILE_DOWNLOAD]
        matching = (_member(parsed.ctx_value, b"\x80") or b"").decode("utf-8", errors="replace")
        events = [event for event in self.store.smds_events(eid=eid, event_id=matching)
                  if event.event_type in wanted]
        if len(matching) > 0 and len(events) == 0:
            raise SmdsError(EVENT_RECORD_UNKNOWN, f"no Event Record {matching[:80]!r} for {eid}")
        self.log(f"ES11 authenticateClient {transaction_hex} for {eid}: {len(events)} Event Record(s)"
                 + (f" for EventID {matching}" if matching else ""))
        return {
            "transactionId": transaction_hex,
            "eventEntries": [{"eventId": event.event_id, "rspServerAddress": event.rsp_server_address}
                             for event in events],
        }

    def check_event(self, ecid: bytes, smds_address: str) -> bool:
        """ES11.CheckEvent (SGP.22 v3.1 §5.8.3): Event Checking is not supported, which the clause has answered
        before the address and the ECID are looked at."""
        del ecid, smds_address
        raise SmdsError(EVENT_CHECKING_UNSUPPORTED, "this SM-DS supports no Event Checking")


__all__ = [
    "ADDRESS_SETTING", "ASN1_NEVER_RETURNED", "AUTHENTICATE_CLIENT_STATUS", "AuthCredential", "CHECK_EVENT_STATUS",
    "COMMON_STATUS",
    "DEFAULT_ADDRESS", "DELETE_EVENT_STATUS", "EVENT_TYPES", "EVENT_TYPE_PROFILE_DOWNLOAD", "EVENT_TYPE_RPM",
    "INITIATE_AUTHENTICATION_STATUS", "LocalSmds", "MAX_OPEN_TRANSACTIONS", "NOT_SUPPORTED",
    "REGISTER_EVENT_STATUS", "STATUS_NEVER_RETURNED", "SmdsError", "SmdsMaterial", "Status", "bundle_material",
    "eid_permitted", "host_name", "key_identifier_list", "verify_euicc_chain",
]
