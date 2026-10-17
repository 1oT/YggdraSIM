# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 eIM package store: resolves and validates bound profile packages from the configured hot-folder.

Parses the SGP.32 EuiccPackage types as BER-TLV and extracts the activation
code an indirect profile download needs.
"""
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
from dataclasses import dataclass
from typing import Optional, Tuple

from SCP11.shared.ber_tlv import (
    read_ber_tlv,
    read_single_ber_tlv,
    validate_ber_tlv_tree,
)

# SGP.32 EuiccPackage choice tags (BER-TLV)
TAG_BOUND_PROFILE_PACKAGE = bytes.fromhex("BF36")
TAG_INDIRECT_PROFILE_DOWNLOAD_A1 = bytes([0xA1])
TAG_INDIRECT_PROFILE_DOWNLOAD_BF50 = bytes.fromhex("BF50")
TAG_PROFILE_STATE_MANAGEMENT_A2 = bytes([0xA2])
TAG_PROFILE_STATE_MANAGEMENT_BF51 = bytes.fromhex("BF51")
TAG_EUICC_CONFIGURATION_A3 = bytes([0xA3])
TAG_EUICC_CONFIGURATION_BF52 = bytes.fromhex("BF52")
TAG_PROFILE_DOWNLOAD_TRIGGER_A4 = bytes([0xA4])
TAG_PROFILE_DOWNLOAD_TRIGGER_BF54 = bytes.fromhex("BF54")
TAG_ACTIVATION_CODE_80 = bytes([0x80])
TAG_ACTIVATION_CODE_81 = bytes([0x81])
TAG_ACTIVATION_CODE_0C = bytes([0x0C])
TAG_ACTIVATION_CODE_1A = bytes([0x1A])

# SGP.32 §2.11.1.1 EuiccPackage ::= CHOICE { psmoList [0] SEQUENCE OF Psmo,
# ecoList [1] SEQUENCE OF Eco }. The chosen alternative -- not the inner
# command tag -- separates a PSMO package from an eCO package: Psmo and Eco
# reuse the same context numbers, so 'A8' is setFallbackAttribute under
# psmoList and addEim under ecoList.
TAG_PSMO_LIST = bytes([0xA0])
TAG_ECO_LIST = bytes([0xA1])

# Eco alternatives that rewrite the eUICC's eIM configuration list: addEim [8],
# deleteEim [9], updateEim [10]. listEim [11] only reads the list back.
ECO_CONFIGURATION_MUTATING_TAGS = (bytes([0xA8]), bytes([0xA9]), bytes([0xAA]))

# Package type names for dispatch
TYPE_BOUND_PROFILE_PACKAGE = "boundProfilePackage"
TYPE_INDIRECT_PROFILE_DOWNLOAD = "indirectProfileDownload"
TYPE_PROFILE_STATE_MANAGEMENT = "profileStateManagement"
TYPE_EUICC_CONFIGURATION = "eUICCConfiguration"
TYPE_EIM_CONFIGURATION_OBJECT = "eCO"
TYPE_PROFILE_DOWNLOAD_TRIGGER = "profileDownloadTrigger"
TYPE_GENERIC = "generic"

# SGP.32 v1.3 section 2.11.1.3 ProfileDownloadData ::= CHOICE {
# activationCode [0], contactDefaultSmdp [1] NULL, contactSmds [2] SEQUENCE {
# smdsAddress OPTIONAL } }, carried under profileDownloadData [0] of BF54.
DOWNLOAD_DATA_ACTIVATION_CODE = "activationCode"
DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP = "contactDefaultSmdp"
DOWNLOAD_DATA_CONTACT_SMDS = "contactSmds"


@dataclass
class ParsedEimPackage:
    package_type: str
    raw: bytes
    activation_code: Optional[str] = None
    smdp_address: Optional[str] = None
    matching_id: Optional[str] = None
    root_tag: bytes = b""
    card_request: bytes = b""
    requested_tags: tuple[bytes, ...] = ()
    request_token: bytes = b""
    notification_seq_number: Optional[int] = None
    notification_profile_management_operation: bytes = b""
    euicc_package_result_seq_number: Optional[int] = None
    eim_transaction_id: bytes = b""
    eim_id: str = ""
    # ProfileDownloadTriggerRequest: which ProfileDownloadData alternative the
    # eIM chose ("" when profileDownloadData is absent) and the SM-DS address
    # of a contactSmds request.
    download_data_choice: str = ""
    smds_address: Optional[str] = None
    # IpaEuiccDataRequest euiccCiPKIdentifierToBeUsed (universal OCTET STRING,
    # tag 04): the CI Public Key Identifier the IPA hands to ES10b.GetCerts.
    euicc_ci_pkid_to_be_used: bytes = b""


def _read_tlv(data: bytes, offset: int) -> Tuple[bytes, bytes, bytes, int]:
    return read_ber_tlv(data, offset)


def _find_activation_code_in_value(value: bytes) -> Optional[str]:
    offset = 0
    while offset < len(value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(value, offset)
        except ValueError:
            break
        if tag_bytes in (TAG_ACTIVATION_CODE_80, TAG_ACTIVATION_CODE_81, TAG_ACTIVATION_CODE_0C, TAG_ACTIVATION_CODE_1A):
            try:
                text = field_value.decode("utf-8").strip()
            except UnicodeDecodeError:
                try:
                    text = field_value.decode("ascii", errors="ignore").strip()
                except Exception:
                    offset = next_offset
                    continue
            if "$" in text and len(text) >= 5:
                return text
        elif len(field_value) > 2 and (tag_bytes[0] & 0x20) != 0:
            nested = _find_activation_code_in_value(field_value)
            if nested is not None:
                return nested
        offset = next_offset
    return None


def _parse_activation_code_parts(activation_code: str) -> Tuple[Optional[str], Optional[str]]:
    """Split an Activation Code into (SM-DP+ address, MatchingID).

    SGP.22 v3.1 section 4.1: ``AC_Format$SM-DP+ address$AC_Token$...`` with an
    optional ``LPA:`` prefix; an AC_Format other than "1" is invalid and the
    MatchingID "MAY be zero-length".
    """
    if "$" not in activation_code:
        return None, None
    parts = activation_code.split("$")
    if len(parts) < 3:
        return None, None
    ac_format = parts[0].strip()
    if ac_format.upper().startswith("LPA:"):
        ac_format = ac_format[4:].strip()
    if ac_format != "1":
        return None, None
    server = parts[1].strip()
    matching_id = parts[2].strip()
    if len(server) == 0:
        return None, None
    return server, matching_id


def _decode_profile_download_data(root_value: bytes) -> tuple[str, Optional[str], Optional[str]]:
    """Return (choice, activation code, SM-DS address) of a BF54 value.

    ``profileDownloadData [0]`` wraps the CHOICE explicitly (``A0``); inside,
    ``80`` is activationCode, ``81 00`` contactDefaultSmdp and ``A2 { 80 }``
    contactSmds with its optional smdsAddress.
    """
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(root_value, offset)
        except ValueError:
            break
        offset = next_offset
        if tag_bytes != b"\xA0":
            continue
        try:
            choice_tag, choice_value, _, _ = _read_tlv(field_value, 0)
        except ValueError:
            return "", None, None
        if choice_tag == b"\x80":
            return DOWNLOAD_DATA_ACTIVATION_CODE, _decode_text_or_empty(choice_value), None
        if choice_tag == b"\x81":
            return DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP, None, None
        if choice_tag == b"\xA2":
            smds_address = None
            inner_offset = 0
            while inner_offset < len(choice_value):
                try:
                    inner_tag, inner_value, _, inner_offset = _read_tlv(choice_value, inner_offset)
                except ValueError:
                    break
                if inner_tag == b"\x80":
                    smds_address = _decode_text_or_empty(inner_value)
            return DOWNLOAD_DATA_CONTACT_SMDS, None, smds_address
        return "", None, None
    return "", None, None


def _extract_card_request_from_sequence(value: bytes) -> bytes:
    offset = 0
    while offset < len(value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(value, offset)
        except ValueError:
            break
        if tag_bytes in (bytes([0xA0]), bytes([0xA1]), bytes([0xA2]), bytes([0xA3]), bytes([0xA4])):
            try:
                _, _, raw_tlv, _ = _read_tlv(field_value, 0)
            except ValueError:
                offset = next_offset
                continue
            return raw_tlv
        offset = next_offset
    return b""


def _extract_card_request(raw: bytes) -> bytes:
    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return b""
    if root_tag not in (
        TAG_PROFILE_STATE_MANAGEMENT_A2,
        TAG_PROFILE_STATE_MANAGEMENT_BF51,
        TAG_EUICC_CONFIGURATION_A3,
        TAG_EUICC_CONFIGURATION_BF52,
        TAG_PROFILE_DOWNLOAD_TRIGGER_A4,
        TAG_PROFILE_DOWNLOAD_TRIGGER_BF54,
    ):
        return b""
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, field_value, raw_tlv, next_offset = _read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes in (bytes([0x30]), bytes([0x31])):
            nested = _extract_card_request_from_sequence(field_value)
            if len(nested) > 0:
                return nested
        if tag_bytes in (bytes([0xA0]), bytes([0xA1]), bytes([0xA2]), bytes([0xA3]), bytes([0xA4])):
            nested = _extract_card_request_from_sequence(field_value)
            if len(nested) > 0:
                return nested
        if tag_bytes and tag_bytes[0] == 0xBF:
            return raw_tlv
        offset = next_offset
    return b""


def _parse_tag_list(value: bytes) -> tuple[bytes, ...]:
    tags = []
    offset = 0
    while offset < len(value):
        tag_start = offset
        offset += 1
        if value[tag_start] & 0x1F == 0x1F:
            terminated = False
            while offset < len(value):
                current = value[offset]
                offset += 1
                if current & 0x80 == 0:
                    terminated = True
                    break
            if terminated is False:
                raise ValueError("Truncated multi-byte tag in requested tag list.")
        tags.append(value[tag_start:offset])
    return tuple(tags)


def _extract_search_criteria_seq_number(value: bytes) -> Optional[int]:
    if len(value) == 0:
        return None
    try:
        tag_bytes, field_value, _, _ = _read_tlv(value, 0)
    except ValueError:
        return None
    if tag_bytes != b"\x80" or len(field_value) == 0:
        return None
    return int.from_bytes(field_value, "big", signed=False)


def _extract_search_criteria_notification(value: bytes) -> Tuple[Optional[int], bytes]:
    """Split searchCriteriaNotification into its two CHOICE alternatives.

    SGP.32 §2.11.1.2: seqNumber [0] selects one stored Notification,
    profileManagementOperation [1] selects every Notification of the types
    whose bit is set. The NotificationEvent contents are carried through
    verbatim so the IPA can hand them to ES10b.RetrieveNotificationsList.
    """
    if len(value) == 0:
        return None, b""
    try:
        tag_bytes, field_value, _, _ = _read_tlv(value, 0)
    except ValueError:
        return None, b""
    if tag_bytes == b"\x80" and len(field_value) > 0:
        return int.from_bytes(field_value, "big", signed=False), b""
    if tag_bytes == b"\x81" and len(field_value) > 0:
        return None, field_value
    return None, b""


@dataclass(frozen=True)
class PackageDataRequest:
    """SGP.32 §2.11.1.2 IpaEuiccDataRequest fields the IPA acts on."""

    requested_tags: tuple[bytes, ...] = ()
    request_token: bytes = b""
    notification_seq_number: Optional[int] = None
    notification_profile_management_operation: bytes = b""
    euicc_package_result_seq_number: Optional[int] = None
    euicc_ci_pkid_to_be_used: bytes = b""


def _extract_package_data_metadata_from_value(value: bytes) -> PackageDataRequest:
    requested_tags = ()
    request_token = b""
    notification_seq_number = None
    notification_profile_management_operation = b""
    euicc_package_result_seq_number = None
    euicc_ci_pkid_to_be_used = b""
    offset = 0
    while offset < len(value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(value, offset)
        except ValueError:
            break
        if tag_bytes == b"\x5C":
            requested_tags = _parse_tag_list(field_value)
        elif tag_bytes == b"\xA1":
            (
                notification_seq_number,
                notification_profile_management_operation,
            ) = _extract_search_criteria_notification(field_value)
        elif tag_bytes == b"\xA2":
            euicc_package_result_seq_number = _extract_search_criteria_seq_number(field_value)
        elif tag_bytes == b"\x83":
            request_token = field_value
        elif tag_bytes == b"\x04":
            # euiccCiPKIdentifierToBeUsed keeps the universal OCTET STRING tag:
            # tagList carries [APPLICATION 28], so the SEQUENCE is not
            # automatically tagged (SGP.32 v1.3 section 2.11.1.2).
            euicc_ci_pkid_to_be_used = field_value
        offset = next_offset
    return PackageDataRequest(
        requested_tags=requested_tags,
        request_token=request_token,
        notification_seq_number=notification_seq_number,
        notification_profile_management_operation=notification_profile_management_operation,
        euicc_package_result_seq_number=euicc_package_result_seq_number,
        euicc_ci_pkid_to_be_used=euicc_ci_pkid_to_be_used,
    )


def _extract_package_data_metadata(raw: bytes) -> PackageDataRequest:
    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return PackageDataRequest()
    if root_tag not in (TAG_EUICC_CONFIGURATION_A3, TAG_EUICC_CONFIGURATION_BF52):
        return PackageDataRequest()
    metadata = _extract_package_data_metadata_from_value(root_value)
    if len(metadata.requested_tags) > 0 or len(metadata.request_token) > 0:
        return metadata
    card_request = _extract_card_request(raw)
    if len(card_request) > 0 and card_request != raw:
        return _extract_package_data_metadata(card_request)
    return metadata


def _decode_text_or_empty(value: bytes) -> str:
    try:
        return value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return value.decode("ascii", errors="ignore").strip()


def _extract_outer_sequence_value(root_value: bytes) -> bytes:
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes in (b"\x30", b"\x31"):
            return field_value
        offset = next_offset
    return b""


def _extract_outer_eim_id(raw: bytes) -> str:
    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return ""
    if root_tag not in (
        TAG_PROFILE_STATE_MANAGEMENT_A2,
        TAG_PROFILE_STATE_MANAGEMENT_BF51,
        TAG_EUICC_CONFIGURATION_A3,
        TAG_EUICC_CONFIGURATION_BF52,
    ):
        return ""
    sequence_value = _extract_outer_sequence_value(root_value)
    offset = 0
    while offset < len(sequence_value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(sequence_value, offset)
        except ValueError:
            break
        if tag_bytes == b"\x80":
            return _decode_text_or_empty(field_value)
        offset = next_offset
    return ""


def _extract_eim_transaction_id(value: bytes) -> bytes:
    """Extract eimTransactionId [2] (wire tag 0x82) from a BF54 SEQUENCE value."""
    offset = 0
    while offset < len(value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(value, offset)
        except ValueError:
            break
        if tag_bytes == b"\x82":
            return field_value
        offset = next_offset
    return b""


def _find_euicc_package_list(value: bytes) -> Tuple[bytes, bytes]:
    offset = 0
    while offset < len(value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(value, offset)
        except ValueError:
            break
        if tag_bytes in (TAG_PSMO_LIST, TAG_ECO_LIST):
            return tag_bytes, field_value
        offset = next_offset
    return b"", b""


def _euicc_package_list_tlv(raw: bytes) -> Tuple[bytes, bytes]:
    """Return the EuiccPackage CHOICE alternative as (tag, value)."""
    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return b"", b""
    if root_tag not in (TAG_PROFILE_STATE_MANAGEMENT_A2, TAG_PROFILE_STATE_MANAGEMENT_BF51):
        return b"", b""
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes in (bytes([0x30]), bytes([0x31])):
            nested = _find_euicc_package_list(field_value)
            if len(nested[0]) > 0:
                return nested
        if tag_bytes in (TAG_PSMO_LIST, TAG_ECO_LIST):
            return tag_bytes, field_value
        offset = next_offset
    return b"", b""


def euicc_package_choice_tag(raw: bytes) -> bytes:
    """Return the psmoList / ecoList tag of a EuiccPackage, or b"" if absent."""
    try:
        return _euicc_package_list_tlv(raw)[0]
    except Exception:
        return b""


def eco_operation_tags(raw: bytes) -> Tuple[bytes, ...]:
    """Return the Eco CHOICE tags an ecoList package carries, in wire order."""
    try:
        choice_tag, choice_value = _euicc_package_list_tlv(raw)
    except Exception:
        return ()
    if choice_tag != TAG_ECO_LIST:
        return ()
    tags: list[bytes] = []
    offset = 0
    while offset < len(choice_value):
        try:
            tag_bytes, _, _, next_offset = _read_tlv(choice_value, offset)
        except ValueError:
            break
        tags.append(tag_bytes)
        offset = next_offset
    return tuple(tags)


def package_changes_eim_configuration(raw: bytes) -> bool:
    """True when the package carries addEim, deleteEim, or updateEim.

    A cached BF55 entry list read before such a package is stale afterwards,
    so the caller has to re-read GetEimConfigurationData.
    """
    for tag_bytes in eco_operation_tags(raw):
        if tag_bytes in ECO_CONFIGURATION_MUTATING_TAGS:
            return True
    return False


def _classify_euicc_package(raw: bytes, card_request: bytes) -> str:
    """Split PSMO from eCO on the EuiccPackage CHOICE alternative."""
    choice_tag = euicc_package_choice_tag(raw)
    if choice_tag == TAG_ECO_LIST:
        return TYPE_EIM_CONFIGURATION_OBJECT
    if choice_tag == TAG_PSMO_LIST:
        return TYPE_PROFILE_STATE_MANAGEMENT
    # No CHOICE alternative recovered from the wrapper; addEim is the only
    # inner tag that identifies an eCO on its own.
    if _tag_of_tlv(card_request) == bytes([0xA8]):
        return TYPE_EIM_CONFIGURATION_OBJECT
    return TYPE_PROFILE_STATE_MANAGEMENT


def _tag_of_tlv(raw_tlv: bytes) -> bytes:
    if len(raw_tlv) == 0:
        return b""
    try:
        tag_bytes, _, _, _ = _read_tlv(raw_tlv, 0)
    except ValueError:
        return b""
    return tag_bytes


def _parse_eim_package_validated(raw: bytes) -> ParsedEimPackage:
    """
    Parse a single eIM EuiccPackage (BER-TLV) and classify by SGP.32 type.
    Extracts activation code for indirect profile download.
    """
    if len(raw) == 0:
        return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=b"")

    try:
        root_tag, root_value, _ = read_single_ber_tlv(raw)
        validate_ber_tlv_tree(raw)
    except ValueError:
        return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=b"")

    if root_tag == TAG_BOUND_PROFILE_PACKAGE:
        return ParsedEimPackage(
            package_type=TYPE_BOUND_PROFILE_PACKAGE,
            raw=raw,
            root_tag=root_tag,
        )

    if root_tag == TAG_INDIRECT_PROFILE_DOWNLOAD_BF50:
        # [80] is ProvideEimPackageResult / ProvideEimPackageResultResponse in
        # SGP.32 v1.2 and v1.3, an IPA-to-eIM message that is never an eIM
        # package; it is reported as generic instead of as a download trigger.
        return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=root_tag)
    if root_tag == TAG_INDIRECT_PROFILE_DOWNLOAD_A1:
        activation_code = _find_activation_code_in_value(root_value)
        smdp_address = None
        matching_id = None
        if activation_code:
            smdp_address, matching_id = _parse_activation_code_parts(activation_code)
        return ParsedEimPackage(
            package_type=TYPE_INDIRECT_PROFILE_DOWNLOAD,
            raw=raw,
            activation_code=activation_code,
            smdp_address=smdp_address,
            matching_id=matching_id,
            root_tag=root_tag,
        )
    if root_tag in (TAG_PROFILE_STATE_MANAGEMENT_A2, TAG_PROFILE_STATE_MANAGEMENT_BF51):
        card_request = _extract_card_request(raw)
        eim_id = _extract_outer_eim_id(raw)
        package_type = _classify_euicc_package(raw, card_request)
        return ParsedEimPackage(
            package_type=package_type,
            raw=raw,
            root_tag=root_tag,
            card_request=card_request,
            eim_id=eim_id,
        )

    if root_tag in (TAG_EUICC_CONFIGURATION_A3, TAG_EUICC_CONFIGURATION_BF52):
        metadata = _extract_package_data_metadata(raw)
        return ParsedEimPackage(
            package_type=TYPE_EUICC_CONFIGURATION,
            raw=raw,
            root_tag=root_tag,
            card_request=_extract_card_request(raw),
            requested_tags=metadata.requested_tags,
            request_token=metadata.request_token,
            notification_seq_number=metadata.notification_seq_number,
            notification_profile_management_operation=metadata.notification_profile_management_operation,
            euicc_package_result_seq_number=metadata.euicc_package_result_seq_number,
            eim_id=_extract_outer_eim_id(raw),
            euicc_ci_pkid_to_be_used=metadata.euicc_ci_pkid_to_be_used,
        )
    if root_tag in (TAG_PROFILE_DOWNLOAD_TRIGGER_A4, TAG_PROFILE_DOWNLOAD_TRIGGER_BF54):
        download_choice, activation_code, smds_address = _decode_profile_download_data(root_value)
        if download_choice == "" and activation_code is None:
            # Packages built before profileDownloadData [0] was framed as the
            # CHOICE carried the code under a bare 80/81/0C/1A; keep reading
            # those, but never reinterpret arbitrary bytes as a code.
            activation_code = _find_activation_code_in_value(root_value)
            if activation_code is not None:
                download_choice = DOWNLOAD_DATA_ACTIVATION_CODE
        smdp_address = None
        matching_id = None
        if activation_code:
            smdp_address, matching_id = _parse_activation_code_parts(activation_code)
        eim_txid = _extract_eim_transaction_id(root_value)
        return ParsedEimPackage(
            package_type=TYPE_PROFILE_DOWNLOAD_TRIGGER,
            raw=raw,
            activation_code=activation_code,
            smdp_address=smdp_address,
            matching_id=matching_id,
            root_tag=root_tag,
            card_request=_extract_card_request(raw),
            eim_transaction_id=eim_txid,
            download_data_choice=download_choice,
            smds_address=smds_address,
        )
    activation_code = _find_activation_code_in_value(raw)
    if activation_code is not None:
        smdp_address, matching_id = _parse_activation_code_parts(activation_code)
        if smdp_address is not None and matching_id is not None:
            return ParsedEimPackage(
                package_type=TYPE_INDIRECT_PROFILE_DOWNLOAD,
                raw=raw,
                activation_code=activation_code,
                smdp_address=smdp_address,
                matching_id=matching_id,
                root_tag=root_tag,
            )

    return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=root_tag)


def parse_eim_package(raw: bytes) -> ParsedEimPackage:
    """Safely classify one complete eIM package.

    Malformed external input always falls back to ``generic`` rather than
    leaking low-level indexing or decoding exceptions into poll workflows.
    """

    normalized = bytes(raw or b"")
    try:
        return _parse_eim_package_validated(normalized)
    except (IndexError, TypeError, UnicodeError, ValueError):
        return ParsedEimPackage(
            package_type=TYPE_GENERIC,
            raw=normalized,
            root_tag=b"",
        )
