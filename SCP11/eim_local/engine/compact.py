# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Compact ESipa forms of an IPA with minimizeEsipaBytes, restored for the SM-DP+.

An IPA that declares minimizeEsipaBytes in its IPA Capabilities sends the
eUICC's answers in the compact forms of SGP.32 v1.3 §5.14.1-5.14.8 and leaves
out what the eIM already holds: euiccInfo1 and the SM-DP+ address, the static
parts of euiccInfo2, the certificates, the transactionId. Before the SM-DP+
sees them the eIM restores the full SGP.22 forms from the session and the
eUICC record. The eUICC signed every restored structure, so each restore is
checked against that signature and refused with ``RestoreError`` when it does
not verify; nothing unverified goes on to the SM-DP+.
"""

from __future__ import annotations

import hashlib

from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv, read_single_ber_tlv

# IpaCapabilities ipaFeatures (SGP.32 v1.3 §4.1, p.105), in bit order.
IPA_FEATURES = (
    "directRspServerCommunication",
    "indirectRspServerCommunication",
    "eimDownloadDataHandling",
    "eimCtxParams1Generation",
    "eimProfileMetadataVerification",
    "minimizeEsipaBytes",
)
MINIMIZE = "minimizeEsipaBytes"
DOWNLOAD_DATA_HANDLING = "eimDownloadDataHandling"
CTX_PARAMS1_GENERATION = "eimCtxParams1Generation"
METADATA_VERIFICATION = "eimProfileMetadataVerification"

# SGP.32 v1.3 CompactSuccessResult: simaResponse is left out when it is this success value.
DEFAULT_SIMA_RESPONSE = bytes.fromhex("3007A0053003800100")
# 16-byte ISD-P AID of RID 'A000000559' (SGP.02 v4.2 §2.2.3); compactAid holds its bytes 14 and 15.
ISDP_AID_HEAD = bytes.fromhex("A0000005591010FFFFFFFF8900")
ISDP_AID_TAIL = b"\x00"
# NotificationEvent notificationInstall(0) (SGP.22 v3.1 NotificationMetadata), as the eUICC encodes it.
NOTIFICATION_INSTALL = bytes.fromhex("0780")


class RestoreError(ValueError):
    """A compact form cannot be restored, or the restored form does not carry a valid eUICC signature."""


def tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + encode_ber_length(len(value)) + bytes(value)


def _children(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        try:
            tag, item, raw, offset = read_ber_tlv(value, offset)
        except (ValueError, IndexError) as error:
            raise RestoreError(f"truncated TLV: {error}") from error
        items.append((bytes(tag), bytes(item), bytes(raw)))
    return items


def _single(data: bytes, tag: bytes, name: str) -> bytes:
    try:
        found, value, raw = read_single_ber_tlv(bytes(data or b""))
    except (ValueError, IndexError) as error:
        raise RestoreError(f"{name}: {error}") from error
    if found != tag or len(raw) != len(data):
        raise RestoreError(f"{name}: expected one '{tag.hex().upper()}' object, got '{bytes(found).hex().upper()}'")
    return bytes(value)


def _member(value: bytes, tag: bytes) -> tuple[bytes, bytes] | None:
    """(value, raw TLV) of the first child with *tag*, or None."""
    for found, item, raw in _children(value):
        if found == tag:
            return item, raw
    return None


def _sequence(implicit_value: bytes) -> bytes:
    """A Certificate carried under an implicit context tag, given back its SEQUENCE tag."""
    return tlv(b"\x30", implicit_value)


# ---------------------------------------------------------------------------
# What the IPA declared and what the eUICC holds
# ---------------------------------------------------------------------------


def ipa_features(capabilities: bytes) -> frozenset[str]:
    """The ipaFeatures bits of IpaCapabilities contents ('80' ipaFeatures, '81' ipaSupportedProtocols)."""
    if len(capabilities) == 0:
        return frozenset()
    found = _member(capabilities, b"\x80")
    if found is None or len(found[0]) == 0:
        return frozenset()
    bits = found[0][1:]
    names = set()
    for index, name in enumerate(IPA_FEATURES):
        octet = index // 8
        if octet < len(bits) and bits[octet] & (0x80 >> (index % 8)):
            names.add(name)
    return frozenset(names)


def record_bytes(data: dict, key: str) -> bytes:
    """A hex member of an eUICC record's data, as bytes; b'' when absent or malformed."""
    value = str((data or {}).get(key, "") or "")
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def record_features(record: object) -> frozenset[str]:
    """The IPA Capabilities an eUICC record holds from an IPA data request ('A8'), as feature names."""
    if record is None:
        return frozenset()
    try:
        return ipa_features(record_bytes(getattr(record, "data", {}), "ipa_capabilities_hex"))
    except RestoreError:
        return frozenset()


def tag_list_names(tag_list: str) -> set[str]:
    """The tags of an IpaEuiccDataRequest tagList as hex names; *tag_list* is hex, spaces allowed
    (a tag of one or two bytes, ISO/IEC 7816-4 BER-TLV, as IpaEuiccData uses)."""
    try:
        data = bytes.fromhex(str(tag_list or "").replace(" ", ""))
    except ValueError:
        return set()
    names: set[str] = set()
    offset = 0
    while offset < len(data):
        width = 2 if data[offset] & 0x1F == 0x1F else 1
        names.add(data[offset:offset + width].hex().upper())
        offset += width
    return names


def download_data_tags(record: object) -> str:
    """The IpaEuiccDataRequest tagList asked before a download (SGP.32 v1.3 IpaEuiccData, p.208).

    ipaCapabilities 'A8' every time, since the IPA polling now is the one that
    runs the download; euiccInfo1 'BF20', euiccInfo2 'BF22', the certificates
    'A5' / 'A6' and deviceInfo 'A9' only while the record lacks them.
    """
    data = getattr(record, "data", {}) or {}
    held = {
        "BF20": len(record_bytes(data, "euicc_info1_hex")) > 0,
        "BF22": len(record_bytes(data, "euicc_info2_hex")) > 0,
        "A5": len(getattr(record, "eum_certificate", b"") or b"") > 0,
        "A6": len(getattr(record, "euicc_certificate", b"") or b"") > 0,
        "A8": False,
        "A9": len(record_bytes(data, "device_info_hex")) > 0,
    }
    # In the order IpaEuiccData defines its members.
    return " ".join(tag for tag, present in held.items() if not present)


def signing_ci_pkids(euicc_info1: bytes) -> list[bytes]:
    """euiccCiPKIdListForSigning ('AA') of EUICCInfo1 'BF20'."""
    value = _single(euicc_info1, b"\xBF\x20", "EUICCInfo1")
    found = _member(value, b"\xAA")
    if found is None:
        return []
    return [item for tag, item, _raw in _children(found[0]) if tag == b"\x04"]


def truncated_ci_pkid(pkid: bytes, signing_list: list[bytes]) -> bytes:
    """The fewest leading bytes of *pkid* that pick it out of *signing_list* (SGP.32 v1.3 §5.14.1 Table 13
    NOTE 2): zero bytes when the list holds one identifier. The full identifier when it is not in the list."""
    if pkid not in signing_list:
        return pkid
    for length in range(0, len(pkid) + 1):
        prefix = pkid[:length]
        if sum(1 for candidate in signing_list if candidate.startswith(prefix)) == 1:
            return prefix
    return pkid


def verify_euicc_signature(certificate: bytes, signed: bytes, signature: bytes) -> bool:
    """ECDSA check of a raw r || s eUICC signature over *signed* with the key of *certificate*."""
    try:
        key = x509.load_der_x509_certificate(certificate).public_key()
    except ValueError:
        return False
    if not isinstance(key, ec.EllipticCurvePublicKey) or len(signature) == 0 or len(signature) % 2:
        return False
    half = len(signature) // 2
    der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
    try:
        key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# Session data
# ---------------------------------------------------------------------------


@dataclass
class CompactSession:
    """What the eIM holds for one relayed download: the eUICC record and the SM-DP+ answers so far."""

    features: frozenset[str] = frozenset()
    euicc_info2: bytes = b""
    euicc_certificate: bytes = b""
    eum_certificate: bytes = b""
    server_signed1: bytes = b""
    server_certificate: bytes = b""
    ctx_params1: bytes = b""
    smdp_signed2: bytes = b""
    smdp_signature2: bytes = b""
    smdp_certificate: bytes = b""
    profile_metadata: bytes = b""
    hash_cc: bytes = b""
    # euiccCiPKIdToBeUsed the SM-DP+ selected (SGP.22 v3.1 5.6.1), untruncated
    ci_pkid: bytes = b""
    # the certificates beyond nextCertInChain, as the contents of otherCertsInChain [0] (SGP.22 v3.1 5.7.13)
    other_certs_in_chain: bytes = b""

    @property
    def minimize(self) -> bool:
        return MINIMIZE in self.features


def _server_signed1_members(server_signed1: bytes) -> dict[bytes, bytes]:
    value = _single(server_signed1, b"\x30", "serverSigned1")
    return {tag: item for tag, item, _raw in _children(value)}


def confirmation_code_required(smdp_signed2: bytes) -> bool:
    """ccRequiredFlag of SmdpSigned2 (SGP.22 v3.1 5.7.5, p.327): the BOOLEAN beside the tagged transactionId."""
    found = _member(_single(smdp_signed2, b"\x30", "smdpSigned2"), b"\x01")
    return found is not None and any(found[0])


def hashed_confirmation_code(code: str, transaction_id: bytes) -> bytes:
    """SHA256(SHA256(Confirmation Code) | TransactionID) over the UTF-8 code (SGP.22 v3.1 3.1.3.2, p.104)."""
    inner = hashlib.sha256(code.encode("utf-8")).digest()
    return hashlib.sha256(inner + transaction_id).digest()


def transaction_id_of(signed: bytes) -> bytes:
    """transactionId '80' of serverSigned1 or smdpSigned2."""
    found = _member(_single(signed, b"\x30", "signed data"), b"\x80")
    if found is None:
        raise RestoreError("no transactionId in the SM-DP+ signed data")
    return found[0]


def certificate_oid(certificate: bytes) -> bytes:
    """The contents octets of the SM-DP+ OID in a CERT.DPpb / CERT.DPauth (subjectAltName registeredID)."""
    try:
        names = x509.load_der_x509_certificate(certificate).extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (ValueError, x509.ExtensionNotFound) as error:
        raise RestoreError(f"SM-DP+ certificate carries no OID: {error}") from error
    oids = names.get_values_for_type(x509.RegisteredID)
    if len(oids) == 0:
        raise RestoreError("SM-DP+ certificate carries no registeredID")
    return _oid_contents(oids[0].dotted_string)


def _oid_contents(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2:
        raise RestoreError(f"OID {dotted!r} has fewer than two arcs")
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(chunk)
    return bytes(body)


def _metadata_member(profile_metadata: bytes, tag: bytes) -> bytes | None:
    if len(profile_metadata) == 0:
        return None
    found = _member(_single(profile_metadata, b"\xBF\x25", "StoreMetadataRequest"), tag)
    return found[0] if found is not None else None


# ---------------------------------------------------------------------------
# ESipa.AuthenticateClient (§5.14.3): AuthenticateServerResponse
# ---------------------------------------------------------------------------


def restore_authenticate_server_response(data: bytes, session: CompactSession) -> bytes:
    """AuthenticateServerResponse 'BF38' with authenticateResponseOk, from compactAuthenticateResponseOk.

    The full form and an error answer come back unchanged. EuiccSigned1 is
    rebuilt from serverSigned1 (transactionId, serverAddress, serverChallenge),
    the record's euiccInfo2 with the extCardResource the IPA sent, and
    ctxParams1 from the IPA or the eIM.
    """
    value = _single(data, b"\xBF\x38", "AuthenticateServerResponse")
    alternatives = _children(value)
    if len(alternatives) != 1:
        raise RestoreError("AuthenticateServerResponse is one CHOICE alternative")
    alternative, contents, _raw = alternatives[0]
    if alternative != b"\xA2":
        return bytes(data)
    members = _children(contents)
    if len(members) < 2:
        raise RestoreError("compactAuthenticateResponseOk lacks signedData or euiccSignature1")
    signed_tag, signed_value, signed_raw = members[0]
    if signed_tag == b"\x30":
        euicc_signed1 = signed_raw
    elif signed_tag == b"\xA0":
        euicc_signed1 = _restore_euicc_signed1(signed_value, session)
    else:
        raise RestoreError(f"signedData alternative '{signed_tag.hex().upper()}' is not '30' or 'A0'")
    signature = next((item for tag, item, _raw in members if tag == b"\x5F\x37"), b"")
    euicc_certificate = next((_sequence(item) for tag, item, _raw in members if tag == b"\xA1"),
                             session.euicc_certificate)
    eum_certificate = next((_sequence(item) for tag, item, _raw in members if tag == b"\xA2"), session.eum_certificate)
    if len(euicc_certificate) == 0 or len(eum_certificate) == 0:
        raise RestoreError("no eUICC or EUM certificate from the IPA or on record")
    if not verify_euicc_signature(euicc_certificate, euicc_signed1, signature):
        raise RestoreError("euiccSignature1 does not verify over the restored euiccSigned1")
    # SGP.22 v3.1 §5.7.13: otherCertsInChain carries the rest of the chain certifying nextCertInChain and is
    # omitted only for Variant O (§4.5.2.0a), where the EUM certificate is issued by the eSIM CA RootCA itself.
    # The compact form (SGP.32 v1.3 §5.14.3) has no place for it, so it comes from what the eIM holds.
    chain = session.other_certs_in_chain
    if len(chain) == 0 and not issued_by(eum_certificate, session.ci_pkid):
        raise RestoreError("nextCertInChain is not issued by the selected eSIM CA RootCA and the rest of the eUICC "
                           "certificate chain (otherCertsInChain) is not on record")
    return tlv(b"\xBF\x38", tlv(b"\xA0", euicc_signed1 + tlv(b"\x5F\x37", signature) + euicc_certificate
                                + eum_certificate + (tlv(b"\xA0", chain) if chain else b"")))


def issued_by(certificate: bytes, ci_pkid: bytes) -> bool:
    """Whether *certificate* names *ci_pkid* as its issuer's key (RFC 5280 §4.2.1.1 Authority Key Identifier;
    the eSIM CA RootCA Public Key Identifier is that certificate's Subject Key Identifier, SGP.22 v3.1
    4.5.2.1). True as well when either side is unknown: no PKID selected, or no identifier in the
    certificate."""
    if len(ci_pkid) == 0:
        return True
    try:
        authority = x509.load_der_x509_certificate(certificate).extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
    except (ValueError, x509.ExtensionNotFound):
        return True
    return authority.key_identifier is None or bytes(authority.key_identifier) == ci_pkid


def response_other_certs(authenticate_server_response: bytes) -> bytes:
    """The contents of otherCertsInChain [0] of an AuthenticateServerResponse 'BF38' with authenticateResponseOk
    (SGP.22 v3.1 5.7.13), b'' when absent or for any other answer."""
    try:
        value = _single(authenticate_server_response, b"\xBF\x38", "AuthenticateServerResponse")
        ok = _member(value, b"\xA0")
    except RestoreError:
        return b""
    if ok is None:
        return b""
    return next((item for tag, item, _raw in _children(ok[0]) if tag == b"\xA0"), b"")


def response_certificates(authenticate_server_response: bytes) -> tuple[bytes, bytes]:
    """(euiccCertificate, nextCertInChain) of an AuthenticateServerResponse 'BF38' with authenticateResponseOk
    'A0' (SGP.22 v3.1 p.450), or (b'', b'') for any other answer."""
    try:
        value = _single(authenticate_server_response, b"\xBF\x38", "AuthenticateServerResponse")
        ok = _member(value, b"\xA0")
        sequences = [raw for tag, _item, raw in _children(ok[0]) if tag == b"\x30"] if ok is not None else []
    except RestoreError:
        return b"", b""
    return (sequences[1], sequences[2]) if len(sequences) >= 3 else (b"", b"")


def _restore_euicc_signed1(compact: bytes, session: CompactSession) -> bytes:
    ext_card_resource = _member(compact, b"\x84")
    if ext_card_resource is None:
        raise RestoreError("compactEuiccSigned1 lacks extCardResource")
    wrapped = _member(compact, b"\xA2")
    if wrapped is not None:
        ctx_params1 = wrapped[0]
    elif session.ctx_params1:
        ctx_params1 = session.ctx_params1
    else:
        raise RestoreError("no ctxParams1 from the IPA or the eIM")
    if len(session.server_signed1) == 0:
        raise RestoreError("no serverSigned1 for the session")
    if len(session.euicc_info2) == 0:
        raise RestoreError("no euiccInfo2 on record")
    server = _server_signed1_members(session.server_signed1)
    for tag, name in ((b"\x80", "transactionId"), (b"\x83", "serverAddress"), (b"\x84", "serverChallenge")):
        if tag not in server:
            raise RestoreError(f"serverSigned1 lacks {name}")
    info2 = _replace_member(session.euicc_info2, b"\xBF\x22", b"\x84", ext_card_resource[0])
    return tlv(b"\x30", tlv(b"\x80", server[b"\x80"]) + tlv(b"\x83", server[b"\x83"]) + tlv(b"\x84", server[b"\x84"])
               + info2 + ctx_params1)


def _replace_member(data: bytes, outer: bytes, tag: bytes, value: bytes) -> bytes:
    """*data* (one *outer* object) with the value of its *tag* member replaced, the order kept."""
    body = b""
    replaced = False
    for found, _item, raw in _children(_single(data, outer, outer.hex().upper())):
        if found == tag and not replaced:
            body += tlv(tag, value)
            replaced = True
        else:
            body += raw
    if not replaced:
        raise RestoreError(f"'{outer.hex().upper()}' on record has no '{tag.hex().upper()}' member")
    return tlv(outer, body)


# ---------------------------------------------------------------------------
# ESipa.GetBoundProfilePackage (§5.14.2): PrepareDownloadResponse
# ---------------------------------------------------------------------------


def restore_prepare_download_response(data: bytes, session: CompactSession) -> bytes:
    """PrepareDownloadResponse 'BF21' with downloadResponseOk, from compactDownloadResponseOk.

    EUICCSigned2 gets the transactionId of smdpSigned2 and the hashCc the IPA
    sent or the eIM holds; euiccSignature2 covers it with smdpSignature2
    (SGP.22 v3.1 §5.7.5, p.328).
    """
    value = _single(data, b"\xBF\x21", "PrepareDownloadResponse")
    alternatives = _children(value)
    if len(alternatives) != 1:
        raise RestoreError("PrepareDownloadResponse is one CHOICE alternative")
    alternative, contents, _raw = alternatives[0]
    if alternative != b"\xA2":
        return bytes(data)
    signed = _member(contents, b"\x30")
    signature = _member(contents, b"\x5F\x37")
    if signed is None or signature is None:
        raise RestoreError("compactDownloadResponseOk lacks compactEuiccSigned2 or euiccSignature2")
    otpk = _member(signed[0], b"\x5F\x49")
    if otpk is None:
        raise RestoreError("compactEuiccSigned2 without euiccOtpk (bppEuiccOtpk) is not restored")
    hash_cc = _member(signed[0], b"\x04")
    hash_value = hash_cc[0] if hash_cc is not None else session.hash_cc
    if len(session.smdp_signed2) == 0 or len(session.smdp_signature2) == 0:
        raise RestoreError("no smdpSigned2 / smdpSignature2 for the session")
    euicc_signed2 = tlv(b"\x30", tlv(b"\x80", transaction_id_of(session.smdp_signed2)) + otpk[1]
                        + (tlv(b"\x04", hash_value) if hash_value else b""))
    if not verify_euicc_signature(session.euicc_certificate, euicc_signed2 + session.smdp_signature2, signature[0]):
        raise RestoreError("euiccSignature2 does not verify over the restored euiccSigned2")
    return tlv(b"\xBF\x21", tlv(b"\xA0", euicc_signed2 + signature[1]))


# ---------------------------------------------------------------------------
# ESipa.HandleNotification (§5.14.7): PendingNotification
# ---------------------------------------------------------------------------


def is_compact_notification(data: bytes) -> bool:
    return bytes(data[:1]) in (b"\xA0", b"\xA1")


def compact_notification_seq_number(data: bytes) -> int | None:
    """seqNumber of a compactProfileInstallationResult 'A0' (a plain INTEGER there), or None."""
    try:
        value = _single(data, b"\xA0", "compactProfileInstallationResult")
        inner = _member(value, b"\xA0")
        number = _member(inner[0], b"\x02") if inner is not None else None
    except RestoreError:
        return None
    return int.from_bytes(number[0], "big", signed=True) if number is not None and number[0] else None


def compact_notification_transaction_id(data: bytes) -> bytes:
    """transactionId of a compactProfileInstallationResult 'A0', or b''."""
    try:
        value = _single(data, b"\xA0", "compactProfileInstallationResult")
        inner = _member(value, b"\xA0")
        found = _member(inner[0], b"\x80") if inner is not None else None
    except RestoreError:
        return b""
    return found[0] if found is not None else b""


def restore_pending_notification(data: bytes, session: CompactSession) -> bytes:
    """A PendingNotification in its full form: ProfileInstallationResult 'BF37' or OtherSignedNotification '30'.

    compactProfileInstallationResult 'A0' gets back notificationMetadata,
    smdpOid and the full ISD-P AID; the notificationAddress is the one the
    Profile Metadata names for the installation, else the SM-DP+ address of
    the session. compactOtherSignedNotification 'A1' gets back the
    certificates. The full forms come back unchanged.
    """
    head = bytes(data[:1])
    if head == b"\xA0":
        return _restore_installation_result(data, session)
    if head == b"\xA1":
        return _restore_other_notification(data, session)
    return bytes(data)


def _restore_installation_result(data: bytes, session: CompactSession) -> bytes:
    value = _single(data, b"\xA0", "compactProfileInstallationResult")
    compact = _member(value, b"\xA0")
    signature = _member(value, b"\x5F\x37")
    if compact is None or signature is None:
        raise RestoreError("compactProfileInstallationResult lacks its data or euiccSignPIR")
    members = {tag: item for tag, item, _raw in _children(compact[0])}
    if b"\x80" not in members or b"\x02" not in members or b"\xA2" not in members:
        raise RestoreError("compactProfileInstallationResultData lacks transactionId, seqNumber or compactFinalResult")
    iccid_present = members.get(b"\x01", b"\xFF") != b"\x00"
    iccid = _metadata_member(session.profile_metadata, b"\x5A") if iccid_present else None
    if iccid_present and iccid is None:
        raise RestoreError("the installed ICCID is not known to the eIM")
    final = _children(members[b"\xA2"])
    if len(final) != 1:
        raise RestoreError("compactFinalResult is one CHOICE alternative")
    result_tag, result_value, result_raw = final[0]
    if result_tag == b"\xA0":
        short_aid = _member(result_value, b"\x4F")
        if short_aid is None or len(short_aid[0]) != 2:
            raise RestoreError("compactSuccessResult lacks the 2-byte compactAid")
        sima = _member(result_value, b"\x04")
        final_result = tlv(b"\xA0", tlv(b"\x4F", ISDP_AID_HEAD + short_aid[0] + ISDP_AID_TAIL)
                           + tlv(b"\x04", sima[0] if sima is not None else DEFAULT_SIMA_RESPONSE))
    else:
        final_result = result_raw
    if len(session.smdp_certificate) == 0:
        raise RestoreError("no SM-DP+ certificate for the smdpOid")
    # smdpOid is untagged here: ProfileInstallationResultData tags other members, so no automatic tags.
    smdp_oid = tlv(b"\x06", certificate_oid(session.smdp_certificate))
    certificate = session.euicc_certificate
    for address in _installation_addresses(session):
        metadata = tlv(b"\x80", members[b"\x02"]) + tlv(b"\x81", NOTIFICATION_INSTALL) + tlv(b"\x0C", address)
        if iccid is not None:
            metadata += tlv(b"\x5A", iccid)
        result_data = tlv(b"\xBF\x27", tlv(b"\x80", members[b"\x80"]) + tlv(b"\xBF\x2F", metadata) + smdp_oid
                          + tlv(b"\xA2", final_result))
        if verify_euicc_signature(certificate, result_data, signature[0]):
            return tlv(b"\xBF\x37", result_data + signature[1])
    raise RestoreError("euiccSignPIR does not verify over the restored ProfileInstallationResultData")


def installation_result_verifies(installation_result: bytes, certificate: bytes) -> bool | None:
    """Whether euiccSignPIR of a ProfileInstallationResult 'BF37' verifies "across the data object
    ProfileInstallationResultData (tag 'BF 27')" (SGP.22 v3.1 §2.5.6, p.51); None without a certificate."""
    if len(certificate) == 0:
        return None
    try:
        value = _single(installation_result, b"\xBF\x37", "ProfileInstallationResult")
        data = _member(value, b"\xBF\x27")
        signature = _member(value, b"\x5F\x37")
    except RestoreError:
        return False
    if data is None or signature is None:
        return False
    return verify_euicc_signature(certificate, data[1], signature[0])


def _installation_addresses(session: CompactSession) -> list[bytes]:
    """notificationAddress candidates: the Profile Metadata's for notificationInstall, then serverAddress."""
    candidates: list[bytes] = []
    configuration = _metadata_member(session.profile_metadata, b"\xB6")
    if configuration is not None:
        for _tag, entry, _raw in _children(configuration):
            members = {tag: item for tag, item, _r in _children(entry)}
            event = members.get(b"\x80", b"")
            if len(event) >= 2 and event[1] & 0x80 and b"\x81" in members:
                candidates.append(members[b"\x81"])
    if session.server_signed1:
        address = _server_signed1_members(session.server_signed1).get(b"\x83")
        if address:
            candidates.append(address)
    unique: list[bytes] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    if not unique:
        raise RestoreError("no notificationAddress candidate")
    return unique


def _restore_other_notification(data: bytes, session: CompactSession) -> bytes:
    value = _single(data, b"\xA1", "compactOtherSignedNotification")
    metadata = _member(value, b"\xBF\x2F")
    signature = _member(value, b"\x5F\x37")
    if metadata is None or signature is None:
        raise RestoreError("compactOtherSignedNotification lacks tbsOtherNotification or its signature")
    if len(session.euicc_certificate) == 0 or len(session.eum_certificate) == 0:
        raise RestoreError("no eUICC or EUM certificate on record")
    if not verify_euicc_signature(session.euicc_certificate, metadata[1], signature[0]):
        raise RestoreError("euiccNotificationSignature does not verify over tbsOtherNotification")
    return tlv(b"\x30", metadata[1] + signature[1] + session.euicc_certificate + session.eum_certificate)


# ---------------------------------------------------------------------------
# ESipa.CancelSession (§5.14.8): CancelSessionResponse
# ---------------------------------------------------------------------------


def restore_cancel_session_response(data: bytes, session: CompactSession) -> bytes:
    """CancelSessionResponse 'BF41' with cancelSessionResponseOk, from compactCancelSessionResponseOk.

    euiccCancelSessionSigned gets the transactionId of serverSigned1 and the
    SM-DP+ OID of CERT.DPauth (SGP.22 v3.1 §5.7.14, p.451). Its three members
    are untagged, so they carry automatic tags '80' '81' '82'; the one member
    of CompactEuiccCancelSessionSigned, reason, carries '80'.
    """
    value = _single(data, b"\xBF\x41", "CancelSessionResponse")
    alternatives = _children(value)
    if len(alternatives) != 1:
        raise RestoreError("CancelSessionResponse is one CHOICE alternative")
    alternative, contents, _raw = alternatives[0]
    if alternative != b"\xA2":
        return bytes(data)
    signed = _member(contents, b"\x30")
    signature = _member(contents, b"\x5F\x37")
    if signed is None or signature is None:
        raise RestoreError("compactCancelSessionResponseOk lacks its signed data or signature")
    reason = _member(signed[0], b"\x80")
    if reason is None:
        raise RestoreError("compactEuiccCancelSessionSigned without a reason is not restored")
    euicc_signed = tlv(b"\x30", tlv(b"\x80", transaction_id_of(session.server_signed1))
                       + tlv(b"\x81", certificate_oid(session.server_certificate)) + tlv(b"\x82", reason[0]))
    if not verify_euicc_signature(session.euicc_certificate, euicc_signed, signature[0]):
        raise RestoreError("euiccCancelSessionSignature does not verify over the restored data")
    return tlv(b"\xBF\x41", tlv(b"\xA0", euicc_signed + signature[1]))


# ---------------------------------------------------------------------------
# ctxParams1 built by the eIM, Profile Metadata checked by the eIM
# ---------------------------------------------------------------------------


def bound_package_metadata(bound_profile_package: bytes) -> bytes:
    """The StoreMetadataRequest 'BF25' a BoundProfilePackage carries, or b'' when it does not parse.

    sequenceOf88 'A1' (SGP.22 v3.1 §2.5.5, p.49) holds it in '88' segments,
    each followed by its C-MAC, the 8 most significant bytes of the AES-CMAC
    (§2.6.4.5, p.59); the metadata is MACed, not encrypted.
    """
    try:
        value = _single(bound_profile_package, b"\xBF\x36", "BoundProfilePackage")
        sequence = _member(value, b"\xA1")
        if sequence is None:
            return b""
        joined = b"".join(item[:-8] for tag, item, _raw in _children(sequence[0]) if tag == b"\x88" and len(item) > 8)
    except RestoreError:
        return b""
    return joined if joined[:2] == b"\xBF\x25" else b""


def ctx_params1_for(matching_id: str, device_info: bytes) -> bytes:
    """ctxParamsForCommonAuthentication 'A0' { matchingId '80', deviceInfo 'A1' } for an IPA with
    eimCtxParams1Generation (SGP.32 v1.3 §5.14.1); *device_info* is the DeviceInfo contents."""
    if len(device_info) == 0:
        raise RestoreError("no deviceInfo on record to build ctxParams1")
    body = tlv(b"\x80", matching_id.encode("utf-8")) if matching_id else b""
    return tlv(b"\xA0", body + tlv(b"\xA1", device_info))


def metadata_refusal(profile_metadata: bytes, rat: bytes, profiles: list[dict]) -> str:
    """Why the eIM refuses a Profile for an IPA with eimProfileMetadataVerification, or '' (SGP.22 v3.1
    §3.1.3 step 7, p.102): a PPR the Rules Authorisation Table does not allow, or PPR1 while an Operational
    Profile is installed. The Enterprise checks of step 7 do not apply: an IoT Device is no Enterprise
    Capable Device. *rat* is a GetRatResponse, a getRatResult or the RulesAuthorisationTable the engine
    keeps; *profiles* the record's Profile list."""
    try:
        rules = _metadata_member(profile_metadata, b"\x99")
        owner = _metadata_member(profile_metadata, b"\xB7")
    except RestoreError as error:
        return f"the Profile Metadata does not decode ({error})"
    # pprUpdateControl (bit 0) is no PPR (SGP.22 v3.1 §2.4a.1.1, p.42).
    requested = _bit_names(rules, ("pprUpdateControl", "ppr1", "ppr2")) - {"pprUpdateControl"} if rules else set()
    if not requested:
        return ""
    if "ppr1" in requested and any(str(profile.get("class", "")).lower() in ("operational", "2")
                                    for profile in profiles):
        return "PPR1 while an Operational Profile is installed"
    if len(rat) == 0:
        return "PPRs in the Profile Metadata and no Rules Authorisation Table on record (GET-RAT first)"
    try:
        table = _rat_rules(rat)
        allowed: set[str] = set()
        for rule in table:
            if _operator_matches(rule["operators"], owner):
                allowed |= rule["pprs"]
    except RestoreError as error:
        return f"the Rules Authorisation Table on record does not decode ({error})"
    missing = sorted(requested - allowed)
    return f"{', '.join(missing)} not allowed by the Rules Authorisation Table" if missing else ""


def _bit_names(bit_string: bytes, names: tuple[str, ...]) -> set[str]:
    bits = bit_string[1:]
    return {name for index, name in enumerate(names)
            if index // 8 < len(bits) and bits[index // 8] & (0x80 >> (index % 8))}


def _rat_rules(rat: bytes) -> list[dict]:
    """The ProfilePolicyAuthorisationRules of a GetRatResponse 'BF43' { rat 'A0' }, a getRatResult 'A6' or a
    RulesAuthorisationTable SEQUENCE OF '30' (SGP.22 v3.1 §5.7.22, p.358); the engine keeps the last form."""
    if rat[:2] == b"\xBF\x43":
        container = _member(_single(rat, b"\xBF\x43", "GetRatResponse"), b"\xA0")
        entries = _children(container[0]) if container is not None else []
    elif rat[:1] in (b"\x30", b"\xA6"):
        entries = _children(_single(rat, rat[:1], "RulesAuthorisationTable"))
    else:
        raise RestoreError(f"RulesAuthorisationTable: unexpected tag '{rat[:1].hex().upper()}'")
    rules = []
    for tag, rule, _raw in entries:
        if tag != b"\x30":
            raise RestoreError(f"RulesAuthorisationTable: '{tag.hex().upper()}' in place of a ProfilePolicyAuthorisationRule")
        members = {member: item for member, item, _r in _children(rule)}
        operators = [item for _t, item, _r in _children(members.get(b"\xA1", b""))]
        rules.append({"pprs": _bit_names(members.get(b"\x80", b"\x00"), ("pprUpdateControl", "ppr1", "ppr2")),
                      "operators": operators})
    return rules


def _operator_matches(operators: list[bytes], owner: bytes | None) -> bool:
    """Whether an 'Allowed Operators' entry matches the profileOwner (SGP.22 v3.1 §2.9.2.1, p.68).

    An 'E' nibble of mccMnc matches any digit. A non-empty gid1 / gid2 has to
    match exactly, an empty one matches any value, and an omitted one only an
    owner without it. A Profile without profileOwner matches only the entry
    that allows every Profile Owner (mccMnc 'EEEEEE').
    """
    owner_members = {tag: item for tag, item, _r in _children(owner)} if owner is not None else {}
    for operator in operators:
        members = {tag: item for tag, item, _r in _children(operator)}
        pattern = members.get(b"\x80", b"")
        if owner is None:
            if pattern.hex().upper().strip("E") != "":
                continue
        elif not _nibbles_match(pattern, owner_members.get(b"\x80", b"")):
            continue
        if all(_gid_matches(members.get(tag), owner_members.get(tag)) for tag in (b"\x81", b"\x82")):
            return True
    return False


def _gid_matches(allowed: bytes | None, owner: bytes | None) -> bool:
    if allowed is None:
        return owner is None
    return len(allowed) == 0 or allowed == owner


def _nibbles_match(pattern: bytes, value: bytes) -> bool:
    pattern_hex, value_hex = pattern.hex().upper(), value.hex().upper()
    if len(pattern_hex) != len(value_hex):
        return False
    return all(p in ("E", v) for p, v in zip(pattern_hex, value_hex))


__all__ = [
    "CompactSession",
    "IPA_FEATURES",
    "RestoreError",
    "ctx_params1_for",
    "ipa_features",
    "is_compact_notification",
    "metadata_refusal",
    "restore_authenticate_server_response",
    "response_other_certs",
    "issued_by",
    "confirmation_code_required",
    "hashed_confirmation_code",
    "restore_cancel_session_response",
    "restore_pending_notification",
    "restore_prepare_download_response",
    "response_certificates",
    "signing_ci_pkids",
    "truncated_ci_pkid",
    "verify_euicc_signature",
]
