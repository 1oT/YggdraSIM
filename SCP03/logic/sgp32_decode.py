# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.32 eIM response decoders: EUICCInfo1, GetRAT, GetCerts, and eIM configuration TLV parsers."""
from typing import Any, Dict, List, Optional

from SCP03.logic.euicc_info2 import format_version_bytes
from SCP03.logic.euicc_info2 import parse_tlv_nodes
from SCP03.logic.euicc_info2 import parse_tlv_simple
from SCP03.logic.euicc_info2 import quote_text
from SCP03.logic.euicc_info2 import RSP_CAPABILITY_FLAGS
from SCP11.shared.ber_tlv import encode_ber_length
from SCP11.shared.ber_tlv import restore_sequence
from SCP11.shared.iccid import swap_nibbles
from SCP11.shared.notification_event import decode_notification_operation_contents
from SCP11.shared.notification_event import NOTIFICATION_EVENT_ASN1_NAME_BY_BIT
from SCP11.shared.notification_event import record_notification_parse_error


# SGP.22 v3.1 §5.7.9 NotificationEvent. The local operations are spelled with
# "Local" in the ASN.1, and bits 4 to 7 carry the RPM operations. The names
# are held once, beside the strict single-bit decoder the SCP11 notification
# consumers use.
NOTIFICATION_EVENT_FLAGS: dict[int, str] = dict(NOTIFICATION_EVENT_ASN1_NAME_BY_BIT)

# SGP.22 PprIds defines three bits. Bit 3 is not allocated.
PPR_FLAGS: dict[int, str] = {
    0: "pprUpdateControl",
    1: "ppr1-disable-not-allowed",
    2: "ppr2-delete-not-allowed",
}

RAT_FLAG_NAMES: dict[int, str] = {
    0: "consentRequired",
}

EIM_SUPPORTED_PROTOCOL_FLAGS: dict[int, str] = {
    0: "eimRetrieveHttps",
    1: "eimRetrieveCoaps",
    2: "eimInjectHttps",
    3: "eimInjectCoaps",
    4: "eimProprietary",
}

# SGP.32 GetCertsResponse. The ASN.1 spells 127 "undfinedError"; the
# spelling here is corrected, the value is the one the spec assigns.
GET_CERTS_ERROR_NAMES: dict[int, str] = {
    1: "invalidCiPKId",
    127: "undefinedError",
}

NOTIFICATIONS_ERROR_NAMES: dict[int, str] = {
    127: "undefinedError",
}

_MAX_TLV_WALK_DEPTH = 32


def decode_euicc_info1_summary(response: bytes) -> Dict[str, Any]:
    """Decode an EUICCInfo1 TLV response into a summary dict (SGP.32 §6.3.3)."""
    summary: Dict[str, Any] = {}
    root_value = unwrap_root_tag(response, 0xBF20)
    if root_value is None:
        return summary

    root_map = parse_tlv_simple(root_value)
    svn_value = first_bytes(root_map.get(0x82))
    if svn_value is not None:
        summary["svn"] = format_version_bytes(svn_value)

    verify_items = count_child_tag(root_map.get(0xA9), 0x04)
    sign_items = count_child_tag(root_map.get(0xAA), 0x04)
    summary["ci_pk_verify_entries"] = verify_items
    summary["ci_pk_sign_entries"] = sign_items
    summary["ci_pk_sign_v3_entries"] = count_child_tag(root_map.get(0xB1), 0x04)

    highest_svn_value = first_bytes(root_map.get(0x93))
    if highest_svn_value is not None:
        summary["highest_svn"] = format_version_bytes(highest_svn_value)

    rsp_capability_value = first_bytes(root_map.get(0x88))
    if rsp_capability_value is not None:
        summary["rsp_capability_hex"] = rsp_capability_value.hex().upper()
        try:
            capabilities = decode_named_bit_string(
                rsp_capability_value, RSP_CAPABILITY_FLAGS
            )
        except ValueError:
            # A card that answers with a malformed BIT STRING still gets its
            # bytes reported above; only the bit names are withheld.
            capabilities = []
        summary["rsp_capability"] = capabilities
    return summary


def decode_notifications_response(response: bytes) -> Dict[str, Any]:
    """Decode a RetrieveNotificationsList response ('BF2B') into notification dicts.

    SGP.22 v3.1 §5.7.10 / SGP.32 v1.3 §5.9.11: ``notificationList`` ('A0') holds
    PendingNotification items whose NotificationMetadata ('BF2F') is collected
    wherever it sits; ``notificationsListResultError`` is '81'; SGP.32 adds
    ``euiccPackageResultList`` ('A2'). Of the four SGP.32 v1.3
    ``PendingNotification`` alternatives only ``compactProfileInstallationResult``
    ('A0') carries no NotificationMetadata; it is summarised by
    :func:`decode_compact_installation_result_entry` instead.
    """
    result: Dict[str, Any] = {
        "notifications": [],
        "package_results": [],
        "error": "",
    }
    root_value = unwrap_root_tag(response, 0xBF2B)
    if root_value is None:
        return result

    root_nodes = parse_tlv_nodes(root_value)
    for tag, value, _constructed in root_nodes:
        if tag == 0x81:
            error_value = decode_integer(value)
            error_name = NOTIFICATIONS_ERROR_NAMES.get(error_value, str(error_value))
            result["error"] = error_name
            continue
        if tag == 0xA0:
            for entry in decode_pending_notification_list(value):
                result["notifications"].append(entry)
            continue
        if tag == 0xA2:
            # SGP.32 v1.3 RetrieveNotificationsListResponse: euiccPackageResultList
            # is SEQUENCE OF EuiccPackageResult, each tagged [81] ('BF51'). One
            # complete TLV per item keeps the signed result verifiable.
            result["package_results"] = split_euicc_package_results(value)
            if len(result["package_results"]) == 0:
                result["package_results"] = [value]
    return result


def split_euicc_package_results(list_value: bytes) -> List[bytes]:
    """Return each ``EuiccPackageResult`` ('BF51') TLV of a package result list."""
    results: List[bytes] = []
    try:
        nodes = parse_tlv_nodes(list_value)
    except ValueError:
        # A list the walker cannot read is reported whole by the caller.
        return results
    for tag, value, _constructed in nodes:
        if tag != 0xBF51:
            continue
        results.append(bytes.fromhex("BF51") + _encode_length(len(value)) + value)
    return results


def decode_pending_notification_list(list_value: bytes) -> List[Dict[str, str]]:
    """Decode every PendingNotification of a notificationList ('A0') value.

    SGP.32 v1.3 ``PendingNotification`` is a CHOICE with textually tagged
    members, so ITU-T X.680 (02/2021) clause 29.2 keeps automatic tagging off
    it: profileInstallationResult [55] stays 'BF37', otherSignedNotification
    keeps the SEQUENCE tag '30', compactProfileInstallationResult [0] is 'A0'
    and compactOtherSignedNotification [1] is 'A1'. Each alternative is
    searched for the NotificationMetadata ('BF2F') it carries rather than at a
    fixed depth; compactProfileInstallationResult carries none and is
    summarised from its own members. A list the walker cannot split is
    searched whole, which is how the SGP.22 v3.1 §5.7.9 ListNotificationResponse
    shape (bare 'BF2F' items) still reads.
    """
    entries: List[Dict[str, str]] = []
    try:
        items = parse_tlv_nodes(list_value)
    except ValueError:
        items = []
    if len(items) == 0:
        for metadata in collect_nested_tag_values(list_value, 0xBF2F):
            entries.append(decode_notification_entry(metadata))
        return entries
    for tag, value, _constructed in items:
        if tag == 0xBF2F:
            entries.append(decode_notification_entry(value))
            continue
        metadata_values = collect_nested_tag_values(value, 0xBF2F)
        if len(metadata_values) > 0:
            for metadata in metadata_values:
                entries.append(decode_notification_entry(metadata))
            continue
        if tag == 0xA0:
            entries.append(decode_compact_installation_result_entry(value))
    return entries


def decode_compact_installation_result_entry(value: bytes) -> Dict[str, str]:
    """Summarise a ``compactProfileInstallationResult`` ('A0') PendingNotification.

    SGP.32 v1.3 CompactProfileInstallationResultData tags transactionId [0]
    ('80') and compactFinalResult [2], so automatic tagging is off and its
    seqNumber keeps the universal INTEGER tag '02'. The alternative carries no
    NotificationMetadata, hence no operation and no notification address.
    """
    entry: Dict[str, str] = {"notificationType": "compactProfileInstallationResult"}
    try:
        nodes = parse_tlv_nodes(value)
    except ValueError:
        return entry
    for tag, node_value, constructed in nodes:
        if tag != 0xA0 or constructed is False:
            continue
        data_map = parse_tlv_simple(node_value)
        transaction_id = first_bytes(data_map.get(0x80))
        if transaction_id is not None:
            entry["transactionId"] = transaction_id.hex().upper()
        seq_value = first_bytes(data_map.get(0x02))
        if seq_value is not None:
            entry["seqNumber"] = str(decode_integer(seq_value))
    return entry


def decode_notification_entry(value: bytes) -> Dict[str, str]:
    """Decode a single NotificationMetadata ('BF2F') TLV into a structured dict."""
    entry_map = parse_tlv_simple(value)
    entry: Dict[str, str] = {}
    seq_value = first_bytes(entry_map.get(0x80))
    if seq_value is not None:
        entry["seqNumber"] = str(decode_integer(seq_value))
    op_value = first_bytes(entry_map.get(0x81))
    if op_value is not None:
        entry["operation"] = _describe_notification_operation(op_value, entry)
    address_value = first_bytes(entry_map.get(0x0C))
    if address_value is not None:
        entry["notificationAddress"] = quote_text(address_value)
    iccid_value = first_bytes(entry_map.get(0x5A))
    if iccid_value is not None:
        entry["iccid"] = decode_bcd_digits(iccid_value)
    return entry


def _describe_notification_operation(value: bytes, entry: Dict[str, str]) -> str:
    """Name the single NotificationEvent bit of a profileManagementOperation.

    SGP.22 v3.1 §5.7.9 states "Only one bit SHALL be set to 1" in the
    NotificationMetadata member, so the shared strict decoder is the one that
    applies here rather than the multi-bit filter form the same BIT STRING
    takes in ListNotificationRequest. A value that sets none or several bits
    keeps its raw hex and records why it was not named.
    """
    hex_text = value.hex().upper()
    try:
        code, _short_name = decode_notification_operation_contents(value)
    except ValueError as error:
        record_notification_parse_error(entry, error)
        return hex_text
    name = NOTIFICATION_EVENT_FLAGS.get(code - 1, f"bit{code - 1}")
    return f"{hex_text} (set: {name})"


def decode_eim_acknowledgements(data: bytes) -> List[int]:
    """Return the sequence numbers an EimAcknowledgements ('BF53') carries (SGP.32 v1.3 §2.11.1.4).

    EimAcknowledgements ::= [83] SEQUENCE OF SequenceNumber with SequenceNumber
    ::= [0] INTEGER, so each entry is an '80' INTEGER. A ProvideEimPackageResultResponse
    ('BF50', §6.3.2.7) is unwrapped first; its emptyResponse and error
    alternatives acknowledge nothing. Malformed BER, a foreign tag, an empty
    or negative INTEGER raise ValueError.
    """
    nodes = parse_tlv_nodes(data)
    if len(nodes) == 0:
        return []
    if len(nodes) != 1:
        raise ValueError(f"EimAcknowledgements must be one TLV, got {len(nodes)}.")
    tag, value, _constructed = nodes[0]
    if tag == 0xBF50:
        inner = parse_tlv_nodes(value)
        if len(inner) != 1 or inner[0][0] != 0xBF53:
            return []
        tag, value, _constructed = inner[0]
    if tag != 0xBF53:
        raise ValueError(f"EimAcknowledgements must be tag 'BF53', got '{tag:X}'.")
    sequence_numbers: List[int] = []
    for item_tag, item_value, _item_constructed in parse_tlv_nodes(value):
        if item_tag != 0x80:
            raise ValueError(f"EimAcknowledgements entry must be tag '80', got '{item_tag:X}'.")
        if len(item_value) == 0:
            raise ValueError("EimAcknowledgements entry carries an empty INTEGER.")
        sequence_number = int.from_bytes(item_value, "big", signed=True)
        if sequence_number < 0:
            raise ValueError(f"EimAcknowledgements entry carries a negative sequence number ({sequence_number}).")
        sequence_numbers.append(sequence_number)
    return sequence_numbers


def decode_rat_rules(response: bytes) -> List[Dict[str, Any]]:
    """Decode a GetRAT response ('BF43') into RAT-rule dicts (SGP.22 v3.1 §5.7.22)."""
    root_value = unwrap_root_tag(response, 0xBF43)
    if root_value is None:
        return []

    rules: List[Dict[str, Any]] = []
    seen_fingerprints: set[str] = set()

    def looks_like_rule(nodes: List[tuple[int, bytes, bool]]) -> bool:
        immediate = {tag: value for tag, value, _constructed in nodes}
        ppr_ids = immediate.get(0x80)
        if ppr_ids is None or not any(tag in immediate for tag in (0xA1, 0x82)):
            return False
        try:
            decode_named_bit_string(ppr_ids, PPR_FLAGS)
            flags = immediate.get(0x82)
            if flags is not None:
                decode_named_bit_string(flags, RAT_FLAG_NAMES)
        except ValueError:
            return False
        return True

    def walk(node_bytes: bytes, depth: int = 0) -> None:
        """Depth-first walk of RAT rule permission TLVs; appends decoded dicts to the outer list."""
        if depth > _MAX_TLV_WALK_DEPTH:
            raise ValueError(
                f"RAT rule TLV nesting exceeds {_MAX_TLV_WALK_DEPTH} levels."
            )
        nodes = parse_tlv_nodes(node_bytes)
        if len(nodes) == 0:
            return

        if looks_like_rule(nodes):
            fingerprint = node_bytes.hex().upper()
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                rules.append(decode_rat_rule(node_bytes))

        for _tag, value, constructed in nodes:
            if constructed:
                walk(value, depth + 1)

    walk(root_value)
    return rules


def decode_rat_rule(value: bytes) -> Dict[str, Any]:
    """Decode a single RAT rule TLV block into a human-readable dict."""
    rule_map = parse_tlv_simple(value)
    rule: Dict[str, Any] = {}
    ppr_ids_value = first_bytes(rule_map.get(0x80))
    if ppr_ids_value is not None:
        rule["pprIdsRaw"] = ppr_ids_value.hex().upper()
        rule["pprIds"] = format_named_bit_string(ppr_ids_value, PPR_FLAGS)

    allowed_operators_value = first_bytes(rule_map.get(0xA1))
    operators: List[Dict[str, str]] = []
    if allowed_operators_value is not None:
        for tag, operator_value, _ in parse_tlv_nodes(allowed_operators_value):
            if tag != 0x30:
                continue
            operator_map = parse_tlv_simple(operator_value)
            operator: Dict[str, str] = {}
            mcc_mnc_value = first_bytes(operator_map.get(0x80))
            if mcc_mnc_value is not None:
                operator["mccMnc"] = decode_mcc_mnc(mcc_mnc_value)
            gid1_value = first_bytes(operator_map.get(0x81))
            if gid1_value is not None:
                operator["gid1"] = gid1_value.hex().upper()
            gid2_value = first_bytes(operator_map.get(0x82))
            if gid2_value is not None:
                operator["gid2"] = gid2_value.hex().upper()
            operators.append(operator)
    if len(operators) > 0:
        rule["allowedOperators"] = operators

    flags_value = first_bytes(rule_map.get(0x82))
    if flags_value is not None:
        rule["pprFlagsRaw"] = flags_value.hex().upper()
        rule["pprFlags"] = format_named_bit_string(flags_value, RAT_FLAG_NAMES)
    return rule


def decode_eim_configuration_entries(response: bytes) -> List[Dict[str, Any]]:
    """Decode a GetEimConfigurationData response ('BF55') into eIM entry dicts (SGP.32 v1.3 §5.9.18)."""
    root_value = unwrap_root_tag(response, 0xBF55)
    if root_value is None:
        return []

    # GetEimConfigurationDataResponse ::= [85] SEQUENCE {
    #   eimConfigurationDataList [0] SEQUENCE OF EimConfigurationData
    # }
    # Decode that shape directly. A heuristic recursive walk used to descend
    # into A5/A6 certificate choices and could mistake DER internals for
    # another eIM entry; it also dropped a valid minimal entry containing only
    # its mandatory eimId.
    root_nodes = parse_tlv_nodes(root_value)
    list_nodes = [value for tag, value, _constructed in root_nodes if tag == 0xA0]
    if not list_nodes:
        return []

    entries: List[Dict[str, Any]] = []
    for list_value in list_nodes:
        for tag, value, constructed in parse_tlv_nodes(list_value):
            if tag != 0x30 or not constructed:
                continue
            entry_map = parse_tlv_simple(value)
            if first_bytes(entry_map.get(0x80)) is None:
                continue
            entries.append(decode_eim_configuration_entry(value))
    return entries


def decode_eim_configuration_entry(value: bytes) -> Dict[str, Any]:
    """Decode a single eIM configuration entry TLV into a structured dict."""
    entry_map = parse_tlv_simple(value)
    entry: Dict[str, Any] = {}

    eim_id_value = first_bytes(entry_map.get(0x80))
    if eim_id_value is not None:
        entry["eim_id"] = decode_text_or_hex(eim_id_value)

    eim_fqdn_value = first_bytes(entry_map.get(0x81))
    if eim_fqdn_value is not None:
        entry["eim_fqdn"] = decode_text_or_hex(eim_fqdn_value)

    eim_id_type_value = first_bytes(entry_map.get(0x82))
    if eim_id_type_value is not None:
        id_type = decode_integer(eim_id_type_value)
        id_type_names = {
            1: "eimIdTypeOid",
            2: "eimIdTypeFqdn",
            3: "eimIdTypeProprietary",
        }
        entry["eim_id_type"] = f"{id_type_names.get(id_type, 'unknown')} ({id_type})"

    counter_value = first_bytes(entry_map.get(0x83))
    if counter_value is not None:
        entry["counter_value"] = str(decode_integer(counter_value))

    association_token = first_bytes(entry_map.get(0x84))
    if association_token is not None:
        entry["association_token"] = str(decode_integer(association_token))

    supported_protocol = first_bytes(entry_map.get(0x87))
    if supported_protocol is not None:
        entry["supported_protocol"] = format_named_bit_string(
            supported_protocol,
            EIM_SUPPORTED_PROTOCOL_FLAGS,
        )

    euicc_ci_pkid = first_bytes(entry_map.get(0x88))
    if euicc_ci_pkid is not None:
        entry["euicc_ci_pkid"] = euicc_ci_pkid.hex().upper()

    if 0x89 in entry_map:
        entry["indirect_profile_download"] = "Present"

    # eSipaProprietaryProtocolInformation [10] VendorSpecificExtension ('AA').
    esipa_info = first_bytes(entry_map.get(0xAA))
    if esipa_info is not None:
        entry["esipa_proprietary_protocol_information"] = esipa_info.hex().upper()

    eim_pub = first_bytes(entry_map.get(0xA5))
    if eim_pub is not None:
        entry["eim_public_key_data"] = eim_pub
        kind, der = decode_public_key_data_choice(eim_pub)
        if len(der) > 0:
            entry["eim_public_key_kind"] = kind
            entry["eim_public_key_der"] = der

    tls_pub = first_bytes(entry_map.get(0xA6))
    if tls_pub is not None:
        entry["trusted_tls_public_key_data"] = tls_pub
        kind, der = decode_public_key_data_choice(tls_pub)
        if len(der) > 0:
            entry["trusted_tls_public_key_kind"] = kind
            entry["trusted_tls_public_key_der"] = der

    return entry


def decode_public_key_data_choice(value: bytes) -> tuple[str, bytes]:
    """Return ``(kind, der)`` for an eimPublicKeyData / trustedPublicKeyDataTls value.

    SGP.32 v1.3 EimConfigurationData declares both as ``CHOICE {
    SubjectPublicKeyInfo, Certificate }`` under AUTOMATIC TAGS, so the
    alternatives travel as ``[0]`` / ``[1]`` IMPLICIT: the context tag
    replaces the SEQUENCE tag and the value holds the SEQUENCE contents
    (``A0 <SubjectPublicKeyInfo contents>`` or ``A1 <Certificate contents>``).
    The DER header is restored here so X.509 tooling can read the result.
    ``kind`` is ``"publicKey"``, ``"certificate"`` or ``""`` when the shape is
    not recognised; ``der`` is empty in that last case. An alternative that
    already wraps a complete SEQUENCE, the shape earlier simulator releases
    produced, passes through unchanged.
    """
    raw = bytes(value or b"")
    try:
        nodes = parse_tlv_nodes(raw)
    except ValueError:
        return "", b""
    if len(nodes) != 1:
        return "", b""
    tag, contents, _constructed = nodes[0]
    if tag == 0x30:
        return "", raw
    if tag not in (0xA0, 0xA1):
        return "", b""
    kind = "publicKey"
    if tag == 0xA1:
        kind = "certificate"
    try:
        inner = parse_tlv_nodes(contents)
    except ValueError:
        inner = []
    if len(inner) == 1 and inner[0][0] == 0x30:
        return kind, contents
    return kind, restore_sequence(contents)


def decode_get_certs_response(response: bytes) -> Dict[str, Any]:
    """Decode a GetCertsResponse ('BF56') into a dict keyed by certificate role (SGP.32 v1.3 §5.9.10).

    ``certs`` is the automatic ``[0]`` alternative ('A0') holding
    ``eumCertificate [5]`` ('A5') and ``euiccCertificate [6]`` ('A6');
    ``getCertsError`` is '81'.
    """
    root_value = unwrap_root_tag(response, 0xBF56)
    if root_value is None:
        return {}

    result: Dict[str, Any] = {}
    root_nodes = parse_tlv_nodes(root_value)
    if len(root_nodes) == 1 and root_nodes[0][0] == 0x81:
        error_code = decode_integer(root_nodes[0][1])
        result["error"] = GET_CERTS_ERROR_NAMES.get(error_code, str(error_code))
        return result

    eum_values, euicc_values = _get_certs_choice_values(root_value)
    if len(eum_values) > 0:
        result["eumCertificate"] = certificate_der_from_choice_value(eum_values[0])
    if len(euicc_values) > 0:
        result["euiccCertificate"] = certificate_der_from_choice_value(euicc_values[0])
    return result


def _get_certs_choice_values(root_value: bytes) -> tuple[list[bytes], list[bytes]]:
    """Collect the [5] / [6] values under certs [0], at most one level down.

    The certificate contents behind those tags are not walked: a walk into
    the signature BIT STRING would read its unused-bits octet as a tag.
    """
    eum_values: list[bytes] = []
    euicc_values: list[bytes] = []

    def take(tag: int, value: bytes) -> None:
        if tag == 0xA5:
            eum_values.append(value)
        elif tag == 0xA6:
            euicc_values.append(value)

    for tag, value, constructed in parse_tlv_nodes(root_value):
        take(tag, value)
        if constructed and tag in (0xA0, 0xA1):
            for inner_tag, inner_value, _ in parse_tlv_nodes(value):
                take(inner_tag, inner_value)
    return eum_values, euicc_values


def _looks_like_certificate(candidate: bytes) -> bool:
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
    # SEQUENCE, signature BIT STRING } (RFC 5280 section 4.1).
    try:
        nodes = parse_tlv_nodes(candidate)
        if len(nodes) != 1 or nodes[0][0] != 0x30:
            return False
        children = parse_tlv_nodes(nodes[0][1])
    except ValueError:
        return False
    return [child[0] for child in children] == [0x30, 0x30, 0x03]


def certificate_der_from_choice_value(value: bytes) -> bytes:
    """Return the Certificate DER behind an implicitly tagged [5] / [6] value.

    The implicit tag replaces the certificate's SEQUENCE tag, so the value
    holds the SEQUENCE contents; the header is restored here. A value that
    already is a complete certificate, the shape earlier simulator releases
    produced, passes through.
    """
    raw = bytes(value or b"")
    if _looks_like_certificate(raw):
        return raw
    restored = restore_sequence(raw)
    if _looks_like_certificate(restored):
        return restored
    return raw


def _encode_length(length: int) -> bytes:
    """Encode a definite BER length (ITU-T X.690 (02/2021) clause 8.1.3)."""
    return encode_ber_length(length)


def unwrap_root_tag(data: bytes, root_tag: int) -> Optional[bytes]:
    """Strip an expected outer root tag from *data* and return the payload, raising on mismatch."""
    nodes = parse_tlv_nodes(data)
    if len(nodes) == 1 and nodes[0][0] == root_tag:
        return nodes[0][1]
    if len(nodes) == 0 and root_tag == 0:
        return data
    return None


def decode_integer(value: bytes) -> int:
    if len(value) == 0:
        return 0
    return int.from_bytes(value, "big", signed=False)


def decode_text_or_hex(value: bytes) -> str:
    """Return the UTF-8 text of a BER-TLV value, falling back to hex if decoding fails."""
    if len(value) == 0:
        return ""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    if text.isprintable():
        return text
    return value.hex().upper()


def decode_bcd_digits(value: bytes) -> str:
    """Decode nibble-swapped BCD to digits (ETSI TS 102 221 v18.4 §13.2 EF ICCID coding)."""
    raw = bytes(value or b"")
    if len(raw) == 0:
        return ""
    text = swap_nibbles(raw).hex().upper()
    # TS 102 221 v18.4 §13.2 pads on the right, so the filler can only be the
    # last nibble of the printed value. Accepting one elsewhere used to append
    # the literal string "15", producing a plausible but incorrect ICCID.
    if text.endswith("F"):
        text = text[:-1]
    if text.isdigit() is False:
        return raw.hex().upper()
    return text


def decode_mcc_mnc(value: bytes) -> str:
    """Decode a 3-octet PLMN identity to its MCC and MNC digits.

    3GPP TS 24.008 v19.5 §10.5.1.3 Figure 10.5.3: octet 1 carries MCC digit 2
    (b8-b5) and MCC digit 1 (b4-b1), octet 2 MNC digit 3 and MCC digit 3,
    octet 3 MNC digit 2 and MNC digit 1; a two-digit MNC codes MNC digit 3
    as 'F'. SGP.22 v3.1 §2.9.2.1 lets any nibble of a RAT ``mccMnc`` be the
    wildcard 'E', which is kept in the output. Any other non-decimal nibble
    returns the raw hex instead of a plausible but wrong PLMN.
    """
    raw = bytes(value or b"")
    if len(raw) != 3:
        return raw.hex().upper()
    mcc_digits = [raw[0] & 0x0F, (raw[0] >> 4) & 0x0F, raw[1] & 0x0F]
    mnc_digit_3 = (raw[1] >> 4) & 0x0F
    mnc_digits = [raw[2] & 0x0F, (raw[2] >> 4) & 0x0F]
    if mnc_digit_3 != 0x0F:
        mnc_digits.append(mnc_digit_3)
    text: List[str] = []
    for nibble in mcc_digits + mnc_digits:
        if nibble <= 9:
            text.append(str(nibble))
        elif nibble == 0x0E:
            text.append("E")
        else:
            return raw.hex().upper()
    return "".join(text)


def format_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> str:
    """Format a named-bit-string value as a comma-separated list of set bit names."""
    if len(value) == 0:
        return "none"
    labels = decode_named_bit_string(value, bit_names)
    hex_text = value.hex().upper()
    if len(labels) == 0:
        return f"{hex_text} (set: none)"
    return f"{hex_text} (set: {', '.join(labels)})"


def decode_named_bit_string(value: bytes, bit_names: Dict[int, str]) -> List[str]:
    """Decode a named-bit-string BER value and return a list of set bit names."""
    if len(value) == 0:
        return []
    unused_bits = value[0]
    payload = value[1:]
    if unused_bits > 7:
        raise ValueError("BIT STRING unused-bit count must be in range 0..7.")
    if len(payload) == 0:
        if unused_bits != 0:
            raise ValueError("Empty BIT STRING payload must have zero unused bits.")
        return []
    if unused_bits and payload[-1] & ((1 << unused_bits) - 1):
        raise ValueError("BIT STRING contains non-zero padding bits.")
    labels: List[str] = []
    bit_index = 0
    for byte_index, byte_value in enumerate(payload):
        for mask_bit in range(7, -1, -1):
            if byte_index == len(payload) - 1 and mask_bit < unused_bits:
                continue
            if ((byte_value >> mask_bit) & 0x01) == 0x01:
                labels.append(bit_names.get(bit_index, f"bit{bit_index}"))
            bit_index += 1
    return labels


def first_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, list) and len(value) > 0 and isinstance(value[0], bytes):
        return value[0]
    return None


def count_child_tag(value: Any, child_tag: int) -> int:
    """Count occurrences of *tag* as direct children of *container_bytes*."""
    blob = first_bytes(value)
    if blob is None:
        return 0
    count = 0
    for tag, _child_value, _constructed in parse_tlv_nodes(blob):
        if tag == child_tag:
            count += 1
    return count


def collect_nested_tag_values(data: bytes, wanted_tag: int) -> List[bytes]:
    """Recursively collect all values of *tag* found anywhere within *container_bytes*."""
    values: List[bytes] = []

    def walk(node_bytes: bytes, depth: int = 0) -> None:
        if depth > _MAX_TLV_WALK_DEPTH:
            raise ValueError(
                f"TLV nesting exceeds {_MAX_TLV_WALK_DEPTH} levels."
            )
        for tag, value, constructed in parse_tlv_nodes(node_bytes):
            if tag == wanted_tag:
                values.append(value)
                # Certificate/public-key containers are opaque at this layer.
                # Recursing into their DER payload can reinterpret arbitrary
                # certificate bytes as sibling TLVs.
                continue
            if tag in (0xA5, 0xA6):
                # These SGP.32 choices carry opaque certificate/public-key
                # encodings even though their context tag is constructed.
                continue
            if constructed:
                walk(value, depth + 1)

    walk(data)
    return values
