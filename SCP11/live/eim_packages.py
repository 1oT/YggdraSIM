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
"""
SGP.32 eIM package ASN.1 / BER-TLV handling.
Parses all EuiccPackage types and extracts activation code for indirect profile download.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

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

# Package type names for dispatch
TYPE_BOUND_PROFILE_PACKAGE = "boundProfilePackage"
TYPE_INDIRECT_PROFILE_DOWNLOAD = "indirectProfileDownload"
TYPE_PROFILE_STATE_MANAGEMENT = "profileStateManagement"
TYPE_EUICC_CONFIGURATION = "eUICCConfiguration"
TYPE_PROFILE_DOWNLOAD_TRIGGER = "profileDownloadTrigger"
TYPE_GENERIC = "generic"


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
    euicc_package_result_seq_number: Optional[int] = None
    eim_transaction_id: bytes = b""


def _read_tlv(data: bytes, offset: int) -> Tuple[bytes, bytes, bytes, int]:
    if offset >= len(data):
        raise ValueError("TLV offset out of range.")
    tag_start = offset
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            raise ValueError("Truncated multi-byte tag.")
    tag_bytes = data[tag_start:offset]
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_len = length_byte & 0x7F
        if num_len > 2 or offset + num_len > len(data):
            raise ValueError("Invalid long-form length.")
        length = 0
        for _ in range(num_len):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = length_byte
    value_start = offset
    value_end = value_start + length
    if value_end > len(data):
        raise ValueError("TLV value overruns input.")
    raw_tlv = data[tag_start:value_end]
    return tag_bytes, data[value_start:value_end], raw_tlv, value_end


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
    if "$" not in activation_code:
        return None, None
    parts = activation_code.split("$")
    if len(parts) < 3:
        return None, None
    server = parts[1].strip()
    matching_id = parts[2].strip()
    if len(server) == 0 or len(matching_id) == 0:
        return None, None
    return server, matching_id


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
            while offset < len(value):
                current = value[offset]
                offset += 1
                if current & 0x80 == 0:
                    break
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


def _extract_ipa_euicc_data_metadata(raw: bytes) -> tuple[tuple[bytes, ...], bytes, Optional[int], Optional[int]]:
    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return (), b"", None, None
    if root_tag not in (TAG_EUICC_CONFIGURATION_A3, TAG_EUICC_CONFIGURATION_BF52):
        return (), b"", None, None
    requested_tags = ()
    request_token = b""
    notification_seq_number = None
    euicc_package_result_seq_number = None
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, field_value, _, next_offset = _read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes == b"\x5C":
            requested_tags = _parse_tag_list(field_value)
        elif tag_bytes == b"\xA1":
            notification_seq_number = _extract_search_criteria_seq_number(field_value)
        elif tag_bytes == b"\xA2":
            euicc_package_result_seq_number = _extract_search_criteria_seq_number(field_value)
        elif tag_bytes == b"\x83":
            request_token = field_value
        offset = next_offset
    return requested_tags, request_token, notification_seq_number, euicc_package_result_seq_number


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


def parse_eim_package(raw: bytes) -> ParsedEimPackage:
    """
    Parse a single eIM EuiccPackage (BER-TLV) and classify by SGP.32 type.
    Extracts activation code for indirect profile download.
    """
    if len(raw) == 0:
        return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=b"")

    try:
        root_tag, root_value, _, _ = _read_tlv(raw, 0)
    except ValueError:
        return ParsedEimPackage(package_type=TYPE_GENERIC, raw=raw, root_tag=b"")

    if root_tag == TAG_BOUND_PROFILE_PACKAGE:
        return ParsedEimPackage(
            package_type=TYPE_BOUND_PROFILE_PACKAGE,
            raw=raw,
            root_tag=root_tag,
        )

    if root_tag in (TAG_INDIRECT_PROFILE_DOWNLOAD_A1, TAG_INDIRECT_PROFILE_DOWNLOAD_BF50):
        activation_code = _find_activation_code_in_value(root_value)
        if activation_code is None and len(root_value) > 0 and b"$" in root_value:
            try:
                activation_code = root_value.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
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
        return ParsedEimPackage(
            package_type=TYPE_PROFILE_STATE_MANAGEMENT,
            raw=raw,
            root_tag=root_tag,
            card_request=_extract_card_request(raw),
        )

    if root_tag in (TAG_EUICC_CONFIGURATION_A3, TAG_EUICC_CONFIGURATION_BF52):
        (
            requested_tags,
            request_token,
            notification_seq_number,
            euicc_package_result_seq_number,
        ) = _extract_ipa_euicc_data_metadata(raw)
        return ParsedEimPackage(
            package_type=TYPE_EUICC_CONFIGURATION,
            raw=raw,
            root_tag=root_tag,
            card_request=_extract_card_request(raw),
            requested_tags=requested_tags,
            request_token=request_token,
            notification_seq_number=notification_seq_number,
            euicc_package_result_seq_number=euicc_package_result_seq_number,
        )

    if root_tag in (TAG_PROFILE_DOWNLOAD_TRIGGER_A4, TAG_PROFILE_DOWNLOAD_TRIGGER_BF54):
        activation_code = _find_activation_code_in_value(root_value)
        if activation_code is None and len(root_value) > 0 and b"$" in root_value:
            try:
                activation_code = root_value.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
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
