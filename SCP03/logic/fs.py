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

"""UICC file-system operations: SELECT, READ RECORD, UPDATE BINARY, and directory scan helpers (ETSI TS 102 221)."""

import os
import time
import yaml
from typing import Dict, Any, List, Union, Optional, Tuple


from SCP03.config import Config
from SCP03.core.utils import TlvParser
from SCP03.core.decoders import ContentDecoder, AdvancedDecoders
from yggdrasim_common.progress import progress_session


# TS 102 221 v18.4 table 11.5 -- EF structure carried in b3..b1 of the file
# descriptor byte. '111' (DF/ADF) and the BER-TLV row are matched on the whole
# byte before this table is consulted.
_FCP_EF_STRUCTURES: Dict[int, str] = {
    0x00: "No information",
    0x01: "Transparent",
    0x02: "Linear Fixed",
    0x06: "Cyclic",
}

# READ BINARY / UPDATE BINARY address the body through P1 (b7..b1, offset high)
# and P2 (offset low), so the largest reachable offset is 0x7FFF
# (TS 102 221 v18.4 §11.1.3.2, table 11.10).
_BINARY_MAX_OFFSET = 0x7FFF


def _split_ber_tlvs(data: bytes) -> List[Tuple[int, bytes]]:
    """Split one level of BER-TLV objects into ``(tag, value)`` pairs, in order.

    The FCP and FCI templates carry their data objects in a defined order
    (TS 102 221 v18.4 §11.1.1.3.0), and the PIN status template DO pairs a
    usage qualifier with the key reference that follows it (§11.1.1.4.10),
    so a positional split is needed where a tag-keyed dict would lose it.
    Tags use the X.690 high-tag-number form when b5..b1 of the first octet
    are all set; lengths are definite, at most three octets. Truncated or
    malformed input raises ``ValueError``.
    """
    items: List[Tuple[int, bytes]] = []
    offset = 0
    total = len(data)
    while offset < total:
        first = data[offset]
        if first == 0x00:
            raise ValueError(f"reserved tag octet 00 at offset {offset}")
        tag = first
        offset += 1
        if (first & 0x1F) == 0x1F:
            while True:
                if offset >= total:
                    raise ValueError("truncated multi-byte tag")
                subsequent = data[offset]
                offset += 1
                tag = (tag << 8) | subsequent
                if tag > 0xFFFFFFFF:
                    raise ValueError("tag exceeds four octets")
                if (subsequent & 0x80) == 0:
                    break
        if offset >= total:
            raise ValueError(f"missing length for tag {tag:X}")
        length = data[offset]
        offset += 1
        if length & 0x80:
            length_octets = length & 0x7F
            if length_octets == 0 or length_octets > 3:
                raise ValueError(f"unsupported length form for tag {tag:X}")
            if offset + length_octets > total:
                raise ValueError(f"truncated length for tag {tag:X}")
            length = int.from_bytes(data[offset : offset + length_octets], "big")
            offset += length_octets
        if offset + length > total:
            raise ValueError(f"truncated value for tag {tag:X}")
        items.append((tag, bytes(data[offset : offset + length])))
        offset += length
    return items


def _first_tlv_value(items: List[Tuple[int, bytes]], tag: int) -> Optional[bytes]:
    for item_tag, item_value in items:
        if item_tag == tag:
            return item_value
    return None


def _lcs_name(value: int) -> str:
    """Name a life cycle status integer (TS 102 221 v18.4 table 11.7b)."""
    if value == 0x00:
        return "No information given"
    if value == 0x01:
        return "Creation state"
    if value == 0x03:
        return "Initialisation state"
    if value & 0xF0:
        return "Proprietary"
    if (value & 0x0C) == 0x0C:
        return "Termination state"
    if (value & 0x0D) == 0x05:
        return "Operational state - activated"
    if (value & 0x0D) == 0x04:
        return "Operational state - deactivated"
    return "RFU"


def _pin_key_reference_name(key_ref: int) -> str:
    """Name a key reference value (TS 102 221 v18.4 table 9.3)."""
    if 0x01 <= key_ref <= 0x08:
        return f"PIN Appl {key_ref}"
    if 0x0A <= key_ref <= 0x0E:
        return f"ADM{key_ref - 0x09}"
    if key_ref == 0x11:
        return "Universal PIN"
    if 0x81 <= key_ref <= 0x88:
        return f"Second PIN Appl {key_ref - 0x80}"
    if 0x8A <= key_ref <= 0x8E:
        return f"ADM{key_ref - 0x84}"
    return "RFU"


def _decode_file_descriptor(descriptor: bytes) -> Dict[str, Any]:
    """Decode the tag '82' value (TS 102 221 v18.4 §11.1.1.4.3, table 11.5).

    Byte 1 is the file descriptor byte: b7 shareable, b6..b4 file type
    (000 working EF, 001 internal EF, 111 DF/ADF), b3..b1 EF structure. The
    BER-TLV structure EF is coded '0111001' as a whole and must not be read
    as a DF. Bytes 3-4 (record length) and 5 (number of records) are present
    for linear fixed and cyclic EFs; a CREATE FILE template carries only the
    record length (TS 102 222 v17.1 table 4).
    """
    result: Dict[str, Any] = {
        "type": "Unknown",
        "structure": "Unknown",
        "file_kind": None,
        "shareable": None,
        "rec_len": 0,
        "rec_count": 0,
    }
    if len(descriptor) == 0:
        return result
    fd_byte = descriptor[0]
    if fd_byte & 0x80:
        result["file_kind"] = "RFU"
        return result
    result["shareable"] = bool(fd_byte & 0x40)
    type_bits = (fd_byte >> 3) & 0x07
    structure_bits = fd_byte & 0x07
    if type_bits == 0x07:
        if structure_bits == 0x00:
            result["type"] = "DF"
            result["structure"] = "Tree"
            result["file_kind"] = "DF or ADF"
        elif structure_bits == 0x01:
            result["type"] = "EF"
            result["structure"] = "BER-TLV"
            result["file_kind"] = "working EF"
        else:
            result["file_kind"] = "RFU"
    elif type_bits in (0x00, 0x01):
        result["type"] = "EF"
        if type_bits == 0x00:
            result["file_kind"] = "working EF"
        else:
            result["file_kind"] = "internal EF"
        result["structure"] = _FCP_EF_STRUCTURES.get(structure_bits, "RFU")
    else:
        result["file_kind"] = "RFU"
    if len(descriptor) >= 4:
        result["rec_len"] = int.from_bytes(descriptor[2:4], "big")
    if len(descriptor) >= 5:
        result["rec_count"] = descriptor[4]
    return result


def _decode_referenced_security(value: bytes) -> Dict[str, Any]:
    """Decode the tag '8B' value (TS 102 221 v18.4 §11.1.1.4.7.3, table 9.0c).

    Length 3 is ``EF_ARR FID || record number``. Length 2 + 2n is
    ``EF_ARR FID || (SEID, record number) x n``; the record for SE01 is
    chosen because that is the environment with the application PIN enabled
    (§9.3.1, table 9.0d), and the first pair otherwise. A lone record
    number (length 1) is outside the table but is tolerated and resolved
    against the EF_ARR of the current DF.
    """
    result: Dict[str, Any] = {
        "arr_fid": None,
        "arr_record": None,
        "arr_se_records": None,
    }
    length = len(value)
    if length == 3:
        result["arr_fid"] = value[0:2].hex().upper()
        result["arr_record"] = value[2]
        return result
    if length >= 4 and (length - 2) % 2 == 0:
        pairs: Dict[str, int] = {}
        for index in range(2, length, 2):
            pairs[f"{value[index]:02X}"] = value[index + 1]
        result["arr_fid"] = value[0:2].hex().upper()
        result["arr_se_records"] = pairs
        if "01" in pairs:
            result["arr_record"] = pairs["01"]
        else:
            result["arr_record"] = next(iter(pairs.values()))
        return result
    if length == 1:
        result["arr_record"] = value[0]
    return result


def _decode_pin_status_template(value: bytes) -> List[Dict[str, Any]]:
    """Decode the tag 'C6' value (TS 102 221 v18.4 §11.1.1.4.10, §9.5.2).

    The PS_DO ('90') is a bitmap: b8 of its first byte belongs to the first
    key reference DO ('83') that follows, the next bits to the following
    ones. A usage qualifier DO ('95') precedes the key reference it belongs
    to; without one (or with an empty one) an enabled PIN is always
    verified, otherwise b4 of the qualifier says whether the PIN is used
    for verification (table 9.4).
    """
    entries: List[Dict[str, Any]] = []
    ps_bits = b""
    pending_qualifier: Optional[bytes] = None
    index = 0
    for tag, item in _split_ber_tlvs(value):
        if tag == 0x90:
            ps_bits = item
            continue
        if tag == 0x95:
            pending_qualifier = item
            continue
        if tag != 0x83:
            continue
        if len(item) == 0:
            continue
        key_ref = item[0]
        byte_index = index // 8
        bit_mask = 0x80 >> (index % 8)
        enabled = False
        if byte_index < len(ps_bits):
            enabled = bool(ps_bits[byte_index] & bit_mask)
        qualifier_hex: Optional[str] = None
        verify_required = True
        if pending_qualifier is not None and len(pending_qualifier) > 0:
            qualifier_hex = pending_qualifier.hex().upper()
            verify_required = bool(pending_qualifier[0] & 0x08)
        entries.append(
            {
                "key_ref": f"{key_ref:02X}",
                "name": _pin_key_reference_name(key_ref),
                "enabled": enabled,
                "usage_qualifier": qualifier_hex,
                "verify_required": verify_required,
            }
        )
        pending_qualifier = None
        index += 1
    return entries


def _decode_proprietary_information(value: bytes) -> Dict[str, Any]:
    """Decode the tag 'A5' template (TS 102 221 v18.4 §11.1.1.4.6).

    '80' is the UICC characteristics byte, '83' the amount of available
    memory, '85' the reserved and '86' the maximum file size of a BER-TLV
    EF; none of them is a file size for a transparent or record EF, which
    only ever comes from the top-level '80' / '81' objects.
    """
    info: Dict[str, Any] = {}
    for tag, item in _split_ber_tlvs(value):
        if tag == 0x80 and "uicc_characteristics" not in info:
            info["uicc_characteristics"] = item.hex().upper()
        elif tag == 0x83 and "available_memory" not in info:
            info["available_memory"] = int.from_bytes(item, "big")
        elif tag == 0x84 and "file_details" not in info:
            info["file_details"] = item.hex().upper()
        elif tag == 0x85 and "reserved_size" not in info:
            info["reserved_size"] = int.from_bytes(item, "big")
        elif tag == 0x86 and "max_size" not in info:
            info["max_size"] = int.from_bytes(item, "big")
        elif tag == 0x87 and "supported_system_commands" not in info:
            info["supported_system_commands"] = item.hex().upper()
    return info


class FileSystemController:
    # TS 102 221 v18.4 §9.2.7 walks from the current DF up to an ADF or the
    # MF looking for the referenced EF_ARR. A UICC tree is shallow; the bound
    # stops a card that keeps answering SELECT parent DF.
    ARR_PARENT_SEARCH_DEPTH = 8

    DEFAULT_MAP = {
        "MF": "3F00",
        "ROOT": "3F00",
        "DIR": "2F00",
        "EF_DIR": "2F00",
        "PL": "2F05",
        "EF_PL": "2F05",
        "ARR": ["6F06", "2F06"],
        "EF_ARR": ["6F06", "2F06"],
        "ICCID": "2FE2",
        "EF_ICCID": "2FE2",
        "UMPC": "2F08",
        "EF_UMPC": "2F08",
        "TELECOM": "7F10",
        "GSM": "7F20",
        "USIM": ["7FF0", "7FFF"],
        "ADF_USIM": ["7FF0", "7FFF"],
        "ISIM": "7FF2",
        "ADF_ISIM": "7FF2",
        "CSIM": "7FF3",
        "ADF_CSIM": "7FF3",
        "GRAPHICS": "5F50",
        "PHONEBOOK": "5F3A",
        "MULTIMEDIA": "5F3B",
        "MMSS": "5F3C",
        "MCS": "5F3D",
        "V2X": "5F3E",
        "A2X": "5F3F",
        "5GS": "5FC0",
        "SAIP": "5FD0",
        "SNPN": "5FE0",
        "5G_PROSE": "5FF0",
        "5MBSUECONFIG": "5FF1",
        "WLAN": "5F40",
        "HNB": "5F50",
        "SOLSA": "5F70",
        "MEXE": "5F3C",
        "PROSE": "5F90",
        "ACDC": "5FA0",
        "TV": "5FB0",
        "EAP": "7F20",
        "PKCS15": "7F50",
        "CD": "7F11",
        "IMSI": "6F07",
        "EF_IMSI": "6F07",
        "KEYS": "6F08",
        "EF_KEYS": "6F08",
        "KEYSPS": "6F09",
        "EF_KEYSPS": "6F09",
        "HPPLMN": "6F31",
        "EF_HPPLMN": "6F31",
        "UST": "6F38",
        "EF_UST": "6F38",
        "FDN": "6F3B",
        "EF_FDN": "6F3B",
        "SMS": "6F3C",
        "EF_SMS": "6F3C",
        "SMSP": "6F42",
        "EF_SMSP": "6F42",
        "SMSS": "6F43",
        "EF_SMSS": "6F43",
        "SPN": "6F46",
        "EF_SPN": "6F46",
        "EST": "6F56",
        "EF_EST": "6F56",
        "START_HFN": "6F5B",
        "EF_START_HFN": "6F5B",
        "THRESHOLD": "6F5C",
        "EF_THRESHOLD": "6F5C",
        "PSLOCI": "6F73",
        "EF_PSLOCI": "6F73",
        "ACC": "6F78",
        "EF_ACC": "6F78",
        "FPLMN": "6F7B",
        "EF_FPLMN": "6F7B",
        "LOCI": "6F7E",
        "EF_LOCI": "6F7E",
        "AD": "6FAD",
        "EF_AD": "6FAD",
        "ECC": "6FB7",
        "EF_ECC": "6FB7",
        "NETPAR": "6FC4",
        "EF_NETPAR": "6FC4",
        "EPSLOCI": "6FE3",
        "EF_EPSLOCI": "6FE3",
        "EPSNSC": "6FE4",
        "EF_EPSNSC": "6FE4",
        "LI": "6F05",
        "EF_LI": "6F05",
        "ACMMAX": "6F37",
        "EF_ACMMAX": "6F37",
        "ACM": "6F39",
        "EF_ACM": "6F39",
        "GID1": "6F3E",
        "EF_GID1": "6F3E",
        "GID2": "6F3F",
        "EF_GID2": "6F3F",
        "MSISDN": "6F40",
        "EF_MSISDN": "6F40",
        "PUCT": "6F41",
        "EF_PUCT": "6F41",
        "CBMI": "6F45",
        "EF_CBMI": "6F45",
        "CBMID": "6F48",
        "EF_CBMID": "6F48",
        "SDN": "6F49",
        "EF_SDN": "6F49",
        "EXT2": "6F4B",
        "EF_EXT2": "6F4B",
        "EXT3": "6F4C",
        "EF_EXT3": "6F4C",
        "CBMIR": "6F50",
        "EF_CBMIR": "6F50",
        "PLMNWACT": "6F60",
        "EF_PLMNWACT": "6F60",
        "OPLMNWACT": "6F61",
        "EF_OPLMNWACT": "6F61",
        "HPLMNWACT": "6F62",
        "EF_HPLMNWACT": "6F62",
        "DCK": "6F2C",
        "EF_DCK": "6F2C",
        "CNL": "6F32",
        "EF_CNL": "6F32",
        "SMSR": "6F47",
        "EF_SMSR": "6F47",
        "BDN": "6F4D",
        "EF_BDN": "6F4D",
        "EXT5": "6F4E",
        "EF_EXT5": "6F4E",
        "CCP2": "6F4F",
        "EF_CCP2": "6F4F",
        "EXT4": "6F55",
        "EF_EXT4": "6F55",
        "ACL": "6F57",
        "EF_ACL": "6F57",
        "CMI": "6F58",
        "EF_CMI": "6F58",
        "ICI": "6F80",
        "EF_ICI": "6F80",
        "OCI": "6F81",
        "EF_OCI": "6F81",
        "ICT": "6F82",
        "EF_ICT": "6F82",
        "OCT": "6F83",
        "EF_OCT": "6F83",
        "VGCS": "6FB1",
        "EF_VGCS": "6FB1",
        "VGCSS": "6FB2",
        "EF_VGCSS": "6FB2",
        "VBS": "6FB3",
        "EF_VBS": "6FB3",
        "VBSS": "6FB4",
        "EF_VBSS": "6FB4",
        "EMLPP": "6FB5",
        "EF_EMLPP": "6FB5",
        "AAEM": "6FB6",
        "EF_AAEM": "6FB6",
        "HIDDENKEY": "6FC3",
        "EF_HIDDENKEY": "6FC3",
        "PNN": "6FC5",
        "EF_PNN": "6FC5",
        "OPL": "6FC6",
        "EF_OPL": "6FC6",
        "MBDN": "6FC7",
        "EF_MBDN": "6FC7",
        "EXT6": "6FC8",
        "EF_EXT6": "6FC8",
        "MBI": "6FC9",
        "EF_MBI": "6FC9",
        "MWIS": "6FCA",
        "EF_MWIS": "6FCA",
        "CFIS": "6FCB",
        "EF_CFIS": "6FCB",
        "EXT7": "6FCC",
        "EF_EXT7": "6FCC",
        "SPDI": "6FCD",
        "EF_SPDI": "6FCD",
        "MMSN": "6FCE",
        "EF_MMSN": "6FCE",
        "EXT8": "6FCF",
        "EF_EXT8": "6FCF",
        "MMSICP": "6FD0",
        "EF_MMSICP": "6FD0",
        "MMSUP": "6FD1",
        "EF_MMSUP": "6FD1",
        "MMSUCP": "6FD2",
        "EF_MMSUCP": "6FD2",
        "NIA": "6FD3",
        "EF_NIA": "6FD3",
        "VGCSCA": "6FD4",
        "EF_VGCSCA": "6FD4",
        "VBSCA": "6FD5",
        "EF_VBSCA": "6FD5",
        "GBABP": ["6FD6", "6FD5"],
        "EF_GBABP": ["6FD6", "6FD5"],
        "MSK": "6FD7",
        "EF_MSK": "6FD7",
        "MUK": "6FD8",
        "EF_MUK": "6FD8",
        "EHPLMN": "6FD9",
        "EF_EHPLMN": "6FD9",
        "GBANL": ["6FDA", "6FD7"],
        "EF_GBANL": ["6FDA", "6FD7"],
        "EHPLMNPI": "6FDB",
        "EF_EHPLMNPI": "6FDB",
        "LRPLMNSI": "6FDC",
        "EF_LRPLMNSI": "6FDC",
        "NAFKCA": "6FDD",
        "EF_NAFKCA": "6FDD",
        "SPNI": "6FDE",
        "EF_SPNI": "6FDE",
        "PNNI": "6FDF",
        "EF_PNNI": "6FDF",
        "NCP_IP": "6FE2",
        "EF_NCP_IP": "6FE2",
        "UFC": "6FE6",
        "EF_UFC": "6FE6",
        "NASCONFIG": "6FE8",
        "EF_NASCONFIG": "6FE8",
        "UICCIARI": "6FE7",
        "EF_UICCIARI": "6FE7",
        "PWS": "6FEC",
        "EF_PWS": "6FEC",
        "FDNURI": "6FED",
        "EF_FDNURI": "6FED",
        "BDNURI": "6FEE",
        "EF_BDNURI": "6FEE",
        "SDNURI": "6FEF",
        "EF_SDNURI": "6FEF",
        "IAL": "6FF0",
        "EF_IAL": "6FF0",
        "IPS": "6FF1",
        "EF_IPS": "6FF1",
        "IPD": "6FF2",
        "EF_IPD": "6FF2",
        "EPDGID": "6FF3",
        "EF_EPDGID": "6FF3",
        "EPDGSELECTION": "6FF4",
        "EF_EPDGSELECTION": "6FF4",
        "EPDGIDEM": "6FF5",
        "EF_EPDGIDEM": "6FF5",
        "EPDGSELECTIONEM": "6FF6",
        "EF_EPDGSELECTIONEM": "6FF6",
        "FROMPREFERRED": "6FF7",
        "EF_FROMPREFERRED": "6FF7",
        "IMSCONFIGDATA": "6FF8",
        "EF_IMSCONFIGDATA": "6FF8",
        "3GPPPSDATAOFF": "6FF9",
        "EF_3GPPPSDATAOFF": "6FF9",
        "3GPPPSDATAOFFSERVICELIST": "6FFA",
        "EF_3GPPPSDATAOFFSERVICELIST": "6FFA",
        "XCAPCONFIGDATA": "6FFC",
        "EF_XCAPCONFIGDATA": "6FFC",
        "EARFCNLIST": "6FFD",
        "EF_EARFCNLIST": "6FFD",
        "MUDMIDCONFIGDATA": "6FFE",
        "EF_MUDMIDCONFIGDATA": "6FFE",
        "EAKA": "6F01",
        "EF_EAKA": "6F01",
        "OCST": "6F02",
        "EF_OCST": "6F02",
        "AC_GBAUAPI": "6F0A",
        "EF_AC_GBAUAPI": "6F0A",
        "IMSDCI": "6F0B",
        "EF_IMSDCI": "6F0B",
        "OPLMNWACT_LSP": "6F0C",
        "EF_OPLMNWACT_LSP": "6F0C",
        "LSPPLMN": "6F0D",
        "EF_LSPPLMN": "6F0D",
        "TVCONFIG": "6FFB",
        "EF_TVCONFIG": "6FFB",
        "RMA": "6F53",
        "EF_RMA": "6F53",
        "SUME": "6F54",
        "EF_SUME": "6F54",
        "ICE_DN": "6FE0",
        "EF_ICE_DN": "6FE0",
        "ICE_FF": "6FE1",
        "EF_ICE_FF": "6FE1",
        "PSISMSC": "6FE5",
        "EF_PSISMSC": "6FE5",
        "ADN": "6F3A",
        "EF_ADN": "6F3A",
        "EXT1": "6F4A",
        "EF_EXT1": "6F4A",
        "PBR": "4F30",
        "EF_PBR": "4F30",
        "IAP": "4F50",
        "EF_IAP": "4F50",
        "GAS": "4F48",
        "EF_GAS": "4F48",
        "PSC": "4F22",
        "EF_PSC": "4F22",
        "CC": "4F23",
        "EF_CC": "4F23",
        "PUID": "4F24",
        "EF_PUID": "4F24",
        "PBC": "4F60",
        "EF_PBC": "4F60",
        "ANR": "4F68",
        "EF_ANR": "4F68",
        "PURI": "4F70",
        "EF_PURI": "4F70",
        "EMAIL": "4F78",
        "EF_EMAIL": "4F78",
        "SNE": "4F80",
        "EF_SNE": "4F80",
        "UID": "4F88",
        "EF_UID": "4F88",
        "GRP": "4F90",
        "EF_GRP": "4F90",
        "CCP1": "4F98",
        "EF_CCP1": "4F98",
        "5GS3GPPLOCI": "4F01",
        "EF_5GS3GPPLOCI": "4F01",
        "5GSN3GPPLOCI": "4F02",
        "EF_5GSN3GPPLOCI": "4F02",
        "5GS3GPPNSC": "4F03",
        "EF_5GS3GPPNSC": "4F03",
        "5GSN3GPPNSC": "4F04",
        "EF_5GSN3GPPNSC": "4F04",
        "5GAUTHKEYS": "4F05",
        "EF_5GAUTHKEYS": "4F05",
        "UAC_AIC": "4F06",
        "EF_UAC_AIC": "4F06",
        "SUCI_CALC_INFO": "4F07",
        "EF_SUCI_CALC_INFO": "4F07",
        "OPL5G": "4F08",
        "EF_OPL5G": "4F08",
        "SUPINAI": "4F09",
        "EF_SUPINAI": "4F09",
        "ROUTING_INDICATOR": "4F0A",
        "EF_ROUTING_INDICATOR": "4F0A",
        "URSP": "4F0B",
        "EF_URSP": "4F0B",
        "TN3GPPSNN": "4F0C",
        "EF_TN3GPPSNN": "4F0C",
        "CAG": "4F0D",
        "EF_CAG": "4F0D",
        "SOR_CMCI": "4F0E",
        "EF_SOR_CMCI": "4F0E",
        "DRI": "4F0F",
        "EF_DRI": "4F0F",
        "5GSEDRX": "4F10",
        "EF_5GSEDRX": "4F10",
        "5GNSWO_CONF": "4F11",
        "EF_5GNSWO_CONF": "4F11",
        "MCHPPLMN": "4F15",
        "EF_MCHPPLMN": "4F15",
        "KAUSF_DERIVATION": "4F16",
        "EF_KAUSF_DERIVATION": "4F16",
    }

    def __init__(self, transport, aid_registry: Dict[str, str] = None):
        self.tp = transport
        self.fid_map = self._load_fid_map()

        if aid_registry is not None:
            self.aid_registry = aid_registry
        else:
            self.aid_registry = {}

        self.current_fcp = {}
        self.current_fid = None
        self.scan_cache = {}
        self.current_path_hint = ""
        self._selection_restore_commands = []

        ContentDecoder.init_registry()

    def _load_fid_map(self) -> Dict[str, List[str]]:
        """
        Parses fids.txt into a Dict[Name, List[FIDs]].
        Merges file content with defaults to prevent overwriting multi-candidate defaults.
        """
        mapping = {}

        for k, v in self.DEFAULT_MAP.items():
            if isinstance(v, list):
                mapping[k] = list(v)
            else:
                mapping[k] = [v]

        self._merge_fid_file(mapping, Config.FIDS_FILE)
        # The workspace copy is seeded once and then belongs to the operator,
        # so an install that predates a shipped-seed addition never sees it.
        # Names the shipped seed knows and the workspace file does not are
        # merged in here; existing entries keep their FIDs and their order.
        self._merge_fid_file(mapping, Config.shipped_fids_seed_path(), new_names_only=True)
        return mapping

    def _merge_fid_file(
        self,
        mapping: Dict[str, List[str]],
        path: str,
        *,
        new_names_only: bool = False,
    ) -> None:
        """Fold one ``fids.txt`` into *mapping*, adding FIDs and never dropping any."""
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue

                    if ":" in stripped:
                        parts = stripped.split(":", 1)
                        name_raw = parts[0].strip().upper()
                        rest = parts[1]
                        if "#" in rest:
                            rest = rest.split("#")[0]

                        candidates = [
                            x.strip().upper() for x in rest.split(":") if x.strip()
                        ]

                        if name_raw and candidates:
                            target_names = [name_raw]

                            if name_raw.startswith("ADF_"):
                                base_name = name_raw[4:]
                                if (
                                    base_name in mapping
                                    and base_name not in target_names
                                ):
                                    target_names.append(base_name)
                            else:
                                adf_name = f"ADF_{name_raw}"
                                if (
                                    adf_name in mapping
                                    and adf_name not in target_names
                                ):
                                    target_names.append(adf_name)

                            for target_name in target_names:
                                if target_name in mapping:
                                    if new_names_only:
                                        continue
                                    for c in candidates:
                                        if c not in mapping[target_name]:
                                            mapping[target_name].append(c)
                                else:
                                    mapping[target_name] = list(candidates)

                            if name_raw.startswith("EF_"):
                                short_name = name_raw[3:]
                                if short_name in mapping:
                                    if new_names_only:
                                        continue
                                    for c in candidates:
                                        if c not in mapping[short_name]:
                                            mapping[short_name].append(c)
                                else:
                                    mapping[short_name] = list(candidates)

        except Exception as e:
            print(f"[Warning] Failed to load fids.txt: {e}")

    def _load_tree_structure(self):
        """Build the scan tree from the workspace ``fids.txt``, then the shipped seed.

        The workspace copy is seeded once and then belongs to the operator, so
        an install that predates a shipped-seed addition would otherwise be
        able to select a name that never appears in the tree. Sub-trees whose
        root name the workspace file does not carry are appended; nothing the
        operator wrote is moved or dropped.
        """
        roots = self._parse_tree_file(Config.FIDS_FILE)
        known = {str(node.get("name", "")) for node in roots}
        for node in self._parse_tree_file(Config.shipped_fids_seed_path()):
            if str(node.get("name", "")) in known:
                continue
            roots.append(node)
        return roots

    @staticmethod
    def _parse_tree_file(path: str):
        roots = []
        stack = [(-1, roots)]
        if not path or not os.path.exists(path):
            return roots
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                expanded = line.expandtabs(4)
                stripped = expanded.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if ":" in stripped:
                    parts = expanded.split(":", 1)
                    left_side = parts[0]
                    right_side = parts[1]
                    indent = len(left_side) - len(left_side.lstrip())
                    name = left_side.strip().upper()
                    if "#" in right_side:
                        right_side = right_side.split("#")[0]
                    candidates = [
                        x.strip().upper() for x in right_side.split(":") if x.strip()
                    ]
                    if not name or not candidates:
                        continue
                    node = {"name": name, "fids": candidates, "children": []}
                    while stack and stack[-1][0] >= indent:
                        stack.pop()
                    stack[-1][1].append(node)
                    stack.append((indent, node["children"]))
        return roots

    @staticmethod
    def _classify_tree_node_kind(name: str, *, has_children: bool = False) -> str:
        """Classify a scan-tree node by ETSI naming convention.

        ``fids.txt`` follows a stable convention where the type is
        encoded as the prefix of the entry's name:

        * ``MF``                       -- master file
        * ``ADF_<aid>`` / ``ADF.<aid>``  -- application DF (ETSI TS 102 221 §8.2)
        * ``DF_<name>`` / ``DF.<name>``  -- directory file
        * ``EF_<name>`` / ``EF.<name>``  -- elementary file (ETSI TS 102 221 §8.3)

        Returns one of ``"mf"`` / ``"adf"`` / ``"df"`` / ``"ef"`` /
        ``"unknown"``. The fallback rule for entries that don't carry a
        prefix is the only ambiguity-resolver: if the entry has children
        we treat it as a DF (only DF/ADF/MF can hold children), otherwise
        as an EF.
        """
        upper = str(name or "").strip().upper()
        if len(upper) == 0:
            return "unknown"
        if upper == "MF":
            return "mf"
        if upper.startswith("ADF_") or upper.startswith("ADF."):
            return "adf"
        if upper.startswith("DF_") or upper.startswith("DF."):
            return "df"
        if upper.startswith("EF_") or upper.startswith("EF."):
            return "ef"
        if has_children:
            return "df"
        return "ef"

    @staticmethod
    def _split_scan_root_nodes(
        roots: List[Dict[str, Any]],
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        render_nodes = []
        mf_children = []
        saw_mf = False
        for node in roots:
            node_name = str(node.get("name", "")).strip().upper()
            node_fids = []
            for candidate in node.get("fids", []):
                candidate_text = str(candidate or "").strip().upper()
                if len(candidate_text) > 0:
                    node_fids.append(candidate_text)
            is_mf = False
            if node_name == "MF":
                is_mf = True
            if "3F00" in node_fids:
                is_mf = True
            if is_mf and not saw_mf:
                saw_mf = True
                for child in node.get("children", []):
                    mf_children.append(child)
                continue
            render_nodes.append(node)
        if saw_mf:
            return True, mf_children + render_nodes
        return False, list(roots)

    def _parse_record_arg(self, arg: Union[str, int]) -> int:
        """Parses decimal (10), hex-prefix (0x0A), or raw hex (0B) strings into int."""
        if isinstance(arg, int):
            return arg
        arg = str(arg).strip()
        try:
            return int(arg, 0)
        except ValueError:
            return int(arg, 16)

    @staticmethod
    def _is_hex_identifier(value: str) -> bool:
        clean = str(value or "").strip().upper()
        if len(clean) == 0:
            return False
        if len(clean) % 2 != 0:
            return False
        for char in clean:
            if char not in "0123456789ABCDEF":
                return False
        return True

    # SELECT by DF name (P1 '04'). TS 102 221 v18.4 table 11.2 codes "return
    # FCP template" as P2 '04' (b3 set, b2b1 = 00 for the first or only
    # occurrence) and gives P2 '00' no meaning, so a UICC may accept that
    # coding and answer without an FCP. GlobalPlatform Card Specification
    # v2.3.1 table 11-81 codes the same selection as P2 '00', and a security
    # domain may refuse the UICC coding as a parameter error; that form is
    # the fallback, never the first attempt.
    APPLICATION_SELECT_P2: Tuple[str, ...] = ("04", "00")

    # TS 102 221 v18.4 table 10.14 '6A81' (function not supported) and '6A86'
    # (incorrect parameters P1 to P2), table 10.11 '6B00' (wrong parameters
    # P1-P2): the card objected to the coding, not to the AID.
    _SELECT_PARAMETER_REJECTIONS = ((0x6A, 0x81), (0x6A, 0x86), (0x6B, 0x00))

    @staticmethod
    def _build_select_command(identifier: str, p2: str = "04") -> str:
        clean_identifier = str(identifier or "").strip().upper()
        if len(clean_identifier) > 4:
            return f"00A404{p2}{len(clean_identifier) // 2:02X}{clean_identifier}"
        return f"00A4000402{clean_identifier}"

    def _transmit_select(self, identifier: str) -> Tuple[bytes, int, int, str]:
        """SELECT *identifier* and return the response with the command that produced it.

        A four-digit identifier is selected by file ID. A longer one is an
        AID and goes through ``APPLICATION_SELECT_P2`` in order: a coding
        the card rejects as a parameter error hands over to the next, and
        one the card accepts without returning data is kept only when no
        later coding yields the FCP.
        """
        clean_identifier = str(identifier or "").strip().upper()
        if len(clean_identifier) <= 4:
            cmd = self._build_select_command(clean_identifier)
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            return data, sw1, sw2, cmd

        selected_without_data: Optional[Tuple[bytes, int, int, str]] = None
        rejected: Optional[Tuple[bytes, int, int, str]] = None
        for p2 in self.APPLICATION_SELECT_P2:
            cmd = self._build_select_command(clean_identifier, p2=p2)
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if self._is_successful_select_response(sw1, data):
                if len(bytes(data or b"")) > 0:
                    return data, sw1, sw2, cmd
                if selected_without_data is None:
                    selected_without_data = (data, sw1, sw2, cmd)
                continue
            if (sw1, sw2) in self._SELECT_PARAMETER_REJECTIONS:
                rejected = (data, sw1, sw2, cmd)
                continue
            if selected_without_data is not None:
                return selected_without_data
            return data, sw1, sw2, cmd
        if selected_without_data is not None:
            return selected_without_data
        if rejected is not None:
            return rejected
        return b"", 0x6A, 0x82, self._build_select_command(clean_identifier)

    @staticmethod
    def _is_successful_select_response(sw1: int, data: bytes) -> bool:
        if sw1 == 0x90:
            return True
        if sw1 == 0x61:
            return True
        if sw1 == 0x9F:
            return True
        payload = bytes(data or b"")
        if len(payload) == 0:
            return False
        if sw1 == 0x62:
            return True
        if sw1 == 0x63:
            return True
        return False

    @staticmethod
    def _is_retryable_traversal_miss(sw1: int, sw2: int, data: bytes) -> bool:
        payload = bytes(data or b"")
        if len(payload) > 0:
            return False
        if sw1 == 0x6A and sw2 == 0x82:
            return True
        if sw1 == 0x69 and sw2 == 0x85:
            return True
        if sw1 == 0x6F and sw2 == 0x00:
            return True
        return False

    def _select_for_live_traversal(
        self, parent_fid: str, candidate_fid: str
    ) -> Tuple[bytes, int, int]:
        parent_text = str(parent_fid or "").strip().upper()
        candidate_text = str(candidate_fid or "").strip().upper()
        data, sw1, sw2, _cmd = self._transmit_select(candidate_text)
        if parent_text != "3F00":
            return data, sw1, sw2
        if self._is_successful_select_response(sw1, data):
            return data, sw1, sw2
        if not self._is_retryable_traversal_miss(sw1, sw2, data):
            return data, sw1, sw2
        self._transmit_select(parent_text)
        time.sleep(0.01)
        retry_data, retry_sw1, retry_sw2, _retry_cmd = self._transmit_select(
            candidate_text
        )
        return retry_data, retry_sw1, retry_sw2

    def _build_restore_command_trail(
        self,
        selected_fid: str,
        select_command: str,
        previous_commands: List[str],
        previous_fcp: Dict[str, Any],
    ) -> List[str]:
        selected_text = str(selected_fid or "").strip().upper()
        command_text = str(select_command or "").strip().upper()
        if len(command_text) == 0:
            return []
        if selected_text == "3F00":
            return [command_text]
        if len(selected_text) > 4:
            return [command_text]

        base_commands = list(previous_commands or [])
        previous_type = str((previous_fcp or {}).get("type", "")).strip()
        previous_structure = str((previous_fcp or {}).get("structure", "")).strip()
        previous_is_ef = False
        if previous_type == "EF":
            previous_is_ef = True
        if previous_structure in ("Transparent", "Linear Fixed", "Cyclic"):
            previous_is_ef = True
        if previous_is_ef and len(base_commands) > 0:
            base_commands = base_commands[:-1]
        if len(base_commands) > 0:
            return base_commands + [command_text]
        return [command_text]

    def _record_scan_limit(self, hard_limit: int = 254) -> int:
        """Bound a record loop by the FCP's record count when the card gave one.

        TS 102 221 v18.4 table 10.7 codes '6A83' as "Record not found", which
        is what READ RECORD answers past the last record; that is the stop
        when the FCP carried no record count.
        """
        try:
            record_count = int(self.current_fcp.get("rec_count", 0) or 0)
        except (TypeError, ValueError):
            return hard_limit
        if record_count <= 0:
            return hard_limit
        if record_count > hard_limit:
            return hard_limit
        return record_count

    def _restore_selection_after_arr_probe(
        self,
        restore_fid: str,
        restore_commands: Optional[List[str]] = None,
    ) -> None:
        normalized_commands = []
        for command in restore_commands or []:
            command_text = str(command or "").strip().upper()
            if len(command_text) > 0:
                normalized_commands.append(command_text)

        if len(normalized_commands) > 0:
            final_data = b""
            final_sw1 = 0x00
            final_sw2 = 0x00
            for command in normalized_commands:
                final_data, final_sw1, final_sw2 = self.tp.transmit(
                    command, silent=True
                )
            if self._is_successful_select_response(final_sw1, final_data):
                return

        restore_text = str(restore_fid or "").strip().upper()
        if len(restore_text) == 0:
            return
        self._transmit_select(restore_text)

    def _select_parent_for_live_traversal(
        self, parent_fid: str
    ) -> Tuple[bytes, int, int]:
        parent_text = str(parent_fid or "").strip().upper()
        data, sw1, sw2, _cmd = self._transmit_select(parent_text)
        if parent_text != "3F00":
            return data, sw1, sw2
        if self._is_successful_select_response(sw1, data):
            time.sleep(0.01)
            return data, sw1, sw2
        if not self._is_retryable_traversal_miss(sw1, sw2, data):
            return data, sw1, sw2
        time.sleep(0.01)
        retry_data, retry_sw1, retry_sw2, _retry_cmd = self._transmit_select(parent_text)
        if self._is_successful_select_response(retry_sw1, retry_data):
            time.sleep(0.01)
        return retry_data, retry_sw1, retry_sw2

    @staticmethod
    def _normalize_ef_dir_label(label_text: str) -> str:
        return " ".join(str(label_text or "").strip().split())

    def _restore_selection_after_ef_dir_probe(self, previous_fid: str) -> None:
        restore_fid = str(previous_fid or "").strip().upper()
        if len(restore_fid) == 0:
            self.tp.transmit("00A40004023F00", silent=True)
            return
        self._transmit_select(restore_fid)

    def _should_try_ef_dir_fallback(self, target: str) -> bool:
        clean_target = str(target or "").strip().upper()
        if len(clean_target) == 0:
            return False
        if self._is_hex_identifier(clean_target):
            return False
        if clean_target in self.aid_registry:
            return True
        if clean_target in (
            "USIM",
            "ADF_USIM",
            "ISIM",
            "ADF_ISIM",
            "SSIM",
            "ADF_SSIM",
            "CSIM",
            "ADF_CSIM",
            "GSM",
        ):
            return True
        if clean_target.startswith("ADF_"):
            return True
        for candidate in self.fid_map.get(clean_target, []):
            candidate_text = str(candidate or "").strip().upper()
            if len(candidate_text) > 4 and self._is_hex_identifier(candidate_text):
                return True
        return False

    def _derive_ef_dir_aliases(self, aid_hex: str, label_text: str) -> List[str]:
        aliases = set()
        upper_label = self._normalize_ef_dir_label(label_text).upper()
        clean_aid = str(aid_hex or "").strip().upper()
        label_markers = set()
        for marker in ("USIM", "ISIM", "SSIM", "CSIM"):
            if marker in upper_label:
                label_markers.add(marker)

        if "USIM" in label_markers or (
            clean_aid.startswith("A000000087") and "1002" in clean_aid
        ):
            aliases.add("USIM")
            aliases.add("ADF_USIM")

        if "ISIM" in label_markers or (
            clean_aid.startswith("A000000087") and "1004" in clean_aid
        ):
            aliases.add("ISIM")
            aliases.add("ADF_ISIM")

        if "SSIM" in label_markers:
            aliases.add("SSIM")
            aliases.add("ADF_SSIM")

        if (
            "CSIM" in label_markers
            or clean_aid.startswith("A0000003431002")
            or "4353494D" in clean_aid
        ):
            aliases.add("CSIM")
            aliases.add("ADF_CSIM")

        return sorted(aliases)

    def _decode_ef_dir_application_template(
        self, app_template
    ) -> Optional[Dict[str, Any]]:
        try:
            inner = app_template
            if isinstance(app_template, (bytes, bytearray, memoryview)):
                inner = TlvParser.parse(bytes(app_template))
        except Exception:
            return None

        has_get = False
        if hasattr(inner, "get"):
            has_get = True
        if not has_get:
            return None

        aid_value = inner.get(0x4F, b"")
        if isinstance(aid_value, list):
            aid_value = aid_value[0] if aid_value else b""
        aid_hex = aid_value.hex().upper() if hasattr(aid_value, "hex") else ""
        if not self._is_hex_identifier(aid_hex):
            return None

        label_value = inner.get(0x50, b"")
        if isinstance(label_value, list):
            label_value = label_value[0] if label_value else b""

        label_text = ""
        if isinstance(label_value, (bytes, bytearray, memoryview)):
            raw_label = bytes(label_value)
            try:
                decoded_label = raw_label.decode("ascii")
            except UnicodeDecodeError:
                decoded_label = f"HEX:{raw_label.hex().upper()}"
            label_text = self._normalize_ef_dir_label(decoded_label)

        aliases = self._derive_ef_dir_aliases(aid_hex, label_text)
        if len(aliases) == 0:
            return None

        return {
            "aid": aid_hex,
            "label": label_text,
            "aliases": aliases,
        }

    def _discover_ef_dir_applications(self) -> List[Dict[str, Any]]:
        previous_fid = self.current_fid
        discovered_apps = []
        seen_aids = set()
        try:
            self._select_parent_for_live_traversal("3F00")
            data, sw1, sw2 = self._select_for_live_traversal("3F00", "2F00")
            if not self._is_successful_select_response(sw1, data):
                return []

            for record_index in range(1, 33):
                read_cmd = f"00B2{record_index:02X}0400"
                data, sw1, sw2 = self.tp.transmit(read_cmd, silent=True)
                if sw1 == 0x6C:
                    read_cmd = f"00B2{record_index:02X}04{sw2:02X}"
                    data, sw1, sw2 = self.tp.transmit(read_cmd, silent=True)
                if sw1 != 0x90 and sw1 != 0x61:
                    break

                clean_data = bytes(data or b"").rstrip(b"\xff")
                if len(clean_data) == 0:
                    continue

                try:
                    parsed = TlvParser.parse(clean_data)
                except Exception:
                    continue

                app_templates = parsed.get(0x61, [])
                if isinstance(app_templates, bytes):
                    app_templates = [app_templates]
                elif isinstance(app_templates, dict):
                    app_templates = [app_templates]
                if not isinstance(app_templates, list):
                    app_templates = []

                for app_template in app_templates:
                    app_entry = self._decode_ef_dir_application_template(app_template)
                    if app_entry is None:
                        continue
                    aid_hex = str(app_entry.get("aid", "")).strip().upper()
                    if aid_hex in seen_aids:
                        continue
                    seen_aids.add(aid_hex)
                    discovered_apps.append(app_entry)

            return discovered_apps
        except Exception:
            return []
        finally:
            self._restore_selection_after_ef_dir_probe(previous_fid)

    def _cache_ef_dir_aliases(self, app_entries: List[Dict[str, Any]]) -> bool:
        refreshed = False
        for app_entry in app_entries:
            aid_hex = str(app_entry.get("aid", "")).strip().upper()
            if not self._is_hex_identifier(aid_hex):
                continue
            for alias_name in app_entry.get("aliases", []):
                alias_key = str(alias_name or "").strip().upper()
                if len(alias_key) == 0:
                    continue
                existing = str(self.aid_registry.get(alias_key, "")).strip().upper()
                if existing != aid_hex:
                    self.aid_registry[alias_key] = aid_hex
                    refreshed = True
        return refreshed

    @staticmethod
    def _normalize_registry_path_tokens(path_tokens: List[str]) -> List[str]:
        normalized_tokens = []
        for token in path_tokens:
            token_text = str(token or "").strip().upper()
            if len(token_text) > 0:
                normalized_tokens.append(token_text)
        return normalized_tokens

    @staticmethod
    def _parse_fid_registry_line(raw_line: str) -> Optional[Dict[str, Any]]:
        line_text = str(raw_line or "").rstrip("\n")
        expanded = line_text.expandtabs(4)
        stripped = expanded.strip()
        if len(stripped) == 0:
            return None
        if stripped.startswith("#"):
            return None
        if ":" not in expanded:
            return None

        left_side, right_side = expanded.split(":", 1)
        indent = len(left_side) - len(left_side.lstrip())
        name = left_side.strip().upper()
        if len(name) == 0:
            return None

        comment_text = ""
        values_text = right_side
        if "#" in values_text:
            values_text, comment_suffix = values_text.split("#", 1)
            clean_comment = comment_suffix.strip()
            if len(clean_comment) > 0:
                comment_text = f"# {clean_comment}"

        candidates = []
        for candidate in values_text.split(":"):
            candidate_text = str(candidate or "").strip().upper()
            if len(candidate_text) > 0:
                candidates.append(candidate_text)

        return {
            "indent": indent,
            "name": name,
            "candidates": candidates,
            "comment": comment_text,
        }

    @classmethod
    def _iter_fid_registry_paths(cls, lines: List[str]):
        stack = []
        for line_index, raw_line in enumerate(lines):
            parsed = cls._parse_fid_registry_line(raw_line)
            if parsed is None:
                continue

            indent = int(parsed["indent"])
            while len(stack) > 0 and stack[-1][0] >= indent:
                stack.pop()

            path_tokens = [entry[1] for entry in stack] + [parsed["name"]]
            yield line_index, parsed, path_tokens
            stack.append((indent, parsed["name"]))

    @staticmethod
    def _format_fid_registry_line(
        name: str,
        candidates: List[str],
        indent: int = 0,
        comment_text: str = "",
    ) -> str:
        clean_candidates = []
        for candidate in candidates:
            candidate_text = str(candidate or "").strip().upper()
            if len(candidate_text) > 0:
                clean_candidates.append(candidate_text)

        line_text = f"{' ' * max(0, int(indent))}{str(name or '').strip().upper()}:{':'.join(clean_candidates)}"
        normalized_comment = str(comment_text or "").strip()
        if len(normalized_comment) > 0:
            if not normalized_comment.startswith("#"):
                normalized_comment = f"# {normalized_comment}"
            line_text = f"{line_text} {normalized_comment}"
        return line_text + "\n"

    def _find_fid_registry_entry(
        self,
        lines: List[str],
        path_tokens: List[str],
    ) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
        normalized_tokens = self._normalize_registry_path_tokens(path_tokens)
        for line_index, parsed, entry_tokens in self._iter_fid_registry_paths(lines):
            if entry_tokens == normalized_tokens:
                return line_index, parsed
        return None, None

    def _find_fid_registry_subtree_end(
        self, lines: List[str], path_tokens: List[str]
    ) -> int:
        target_index = None
        target_indent = -1
        normalized_tokens = self._normalize_registry_path_tokens(path_tokens)
        for line_index, parsed, entry_tokens in self._iter_fid_registry_paths(lines):
            if entry_tokens == normalized_tokens:
                target_index = line_index
                target_indent = int(parsed["indent"])
                continue
            if target_index is not None:
                if int(parsed["indent"]) <= target_indent:
                    return line_index
        return len(lines)

    def _parent_has_fid_candidate(
        self,
        lines: List[str],
        parent_tokens: List[str],
        fid_value: str,
    ) -> bool:
        normalized_parent = self._normalize_registry_path_tokens(parent_tokens)
        clean_fid = str(fid_value or "").strip().upper()
        parent_depth = len(normalized_parent)
        for _line_index, parsed, entry_tokens in self._iter_fid_registry_paths(lines):
            if len(entry_tokens) != parent_depth + 1:
                continue
            if entry_tokens[:parent_depth] != normalized_parent:
                continue
            if clean_fid in parsed.get("candidates", []):
                return True
        return False

    def _save_fid_registry_lines(self, lines: List[str]) -> bool:
        try:
            with open(Config.FIDS_FILE, "w", encoding="utf-8") as fid_file:
                fid_file.writelines(lines)
        except Exception:
            return False
        self.fid_map = self._load_fid_map()
        return True

    def _persist_fid_registry_candidate(
        self, path_tokens: List[str], fid_value: str
    ) -> bool:
        normalized_tokens = self._normalize_registry_path_tokens(path_tokens)
        clean_fid = str(fid_value or "").strip().upper()
        if len(normalized_tokens) == 0:
            return False
        if not self._is_hex_identifier(clean_fid):
            return False

        try:
            with open(Config.FIDS_FILE, "r", encoding="utf-8") as fid_file:
                lines = fid_file.readlines()
        except Exception:
            return False

        line_index, parsed = self._find_fid_registry_entry(lines, normalized_tokens)
        if line_index is not None and parsed is not None:
            candidates = list(parsed.get("candidates", []))
            if clean_fid in candidates:
                return False
            candidates.append(clean_fid)
            lines[line_index] = self._format_fid_registry_line(
                parsed["name"],
                candidates,
                indent=int(parsed["indent"]),
                comment_text=str(parsed.get("comment", "")),
            )
            return self._save_fid_registry_lines(lines)

        if len(normalized_tokens) == 1:
            if len(lines) > 0:
                if len(str(lines[-1]).strip()) > 0:
                    lines.append("\n")
            lines.append(
                self._format_fid_registry_line(normalized_tokens[0], [clean_fid])
            )
            return self._save_fid_registry_lines(lines)

        parent_tokens = normalized_tokens[:-1]
        parent_index, parent_entry = self._find_fid_registry_entry(lines, parent_tokens)
        if parent_index is None or parent_entry is None:
            return False
        if self._parent_has_fid_candidate(lines, parent_tokens, clean_fid):
            return False

        insert_index = self._find_fid_registry_subtree_end(lines, parent_tokens)
        child_indent = int(parent_entry["indent"]) + 1
        lines.insert(
            insert_index,
            self._format_fid_registry_line(
                normalized_tokens[-1], [clean_fid], indent=child_indent
            ),
        )
        return self._save_fid_registry_lines(lines)

    def _persist_ef_dir_discoveries(self, app_entries: List[Dict[str, Any]]) -> bool:
        persisted = False
        for app_entry in app_entries:
            aid_hex = str(app_entry.get("aid", "")).strip().upper()
            if not self._is_hex_identifier(aid_hex):
                continue
            aliases = app_entry.get("aliases", [])
            root_name = self._preferred_scan_root_name(aliases)
            if len(root_name) == 0:
                continue
            saved = self._persist_fid_registry_candidate([root_name], aid_hex)
            if saved:
                persisted = True
        return persisted

    def _build_dynamic_fid_name(self, fid_value: str) -> str:
        clean_fid = str(fid_value or "").strip().upper()
        file_type = str(self.current_fcp.get("type", "")).strip().upper()
        if file_type == "DF":
            return f"DF_{clean_fid}"
        if file_type == "EF":
            return f"EF_{clean_fid}"
        return f"FILE_{clean_fid}"

    def _persist_dynamic_fid_discovery(
        self, parent_path_tokens: List[str], fid_value: str
    ) -> str:
        dynamic_name = self._build_dynamic_fid_name(fid_value)
        self._persist_fid_registry_candidate(
            parent_path_tokens + [dynamic_name], fid_value
        )
        return dynamic_name

    @staticmethod
    def _scan_root_candidates_from_aliases(aliases: List[str]) -> List[str]:
        candidate_names = []
        for alias_name in aliases:
            alias_text = str(alias_name or "").strip().upper()
            if len(alias_text) == 0:
                continue
            base_name = alias_text
            if alias_text.startswith("ADF_"):
                base_name = alias_text[4:]
            for candidate_name in (base_name, alias_text):
                if candidate_name not in candidate_names:
                    candidate_names.append(candidate_name)
        return candidate_names

    def _preferred_scan_root_name(self, aliases: List[str]) -> str:
        candidate_names = self._scan_root_candidates_from_aliases(aliases)
        for candidate_name in candidate_names:
            if not candidate_name.startswith("ADF_"):
                return candidate_name
        if len(candidate_names) > 0:
            return candidate_names[0]
        return ""

    def _find_scan_root_template(self, roots, aliases: List[str]):
        candidate_names = self._scan_root_candidates_from_aliases(aliases)
        for node in roots:
            node_name = str(node.get("name", "")).strip().upper()
            if node_name in candidate_names:
                return node
        return None

    @staticmethod
    def _clone_scan_tree_node(node: Dict[str, Any]) -> Dict[str, Any]:
        cloned_fids = []
        for fid in node.get("fids", []):
            cloned_fids.append(str(fid or "").strip().upper())

        cloned_children = []
        for child in node.get("children", []):
            cloned_children.append(FileSystemController._clone_scan_tree_node(child))

        return {
            "name": str(node.get("name", "")).strip().upper(),
            "fids": cloned_fids,
            "children": cloned_children,
        }

    def _merge_live_apps_into_scan_tree(
        self, roots, app_entries: List[Dict[str, Any]]
    ) -> None:
        claimed_templates = set()
        used_path_names = set()
        for node in roots:
            node_name = str(node.get("name", "")).strip().upper()
            if len(node_name) > 0:
                used_path_names.add(node_name)

        for app_entry in app_entries:
            aid_hex = str(app_entry.get("aid", "")).strip().upper()
            aliases = []
            for alias_name in app_entry.get("aliases", []):
                alias_text = str(alias_name or "").strip().upper()
                if len(alias_text) > 0:
                    aliases.append(alias_text)

            if not self._is_hex_identifier(aid_hex):
                continue
            if len(aliases) == 0:
                continue

            template_node = self._find_scan_root_template(roots, aliases)
            target_node = None
            path_name = ""

            if template_node is not None and id(template_node) not in claimed_templates:
                target_node = template_node
                claimed_templates.add(id(template_node))
                path_name = str(target_node.get("name", "")).strip().upper()
            else:
                if template_node is not None:
                    target_node = self._clone_scan_tree_node(template_node)
                else:
                    target_node = {
                        "name": self._preferred_scan_root_name(aliases),
                        "fids": [],
                        "children": [],
                    }

                node_name = str(target_node.get("name", "")).strip().upper()
                if len(node_name) == 0:
                    continue

                path_name = node_name
                if path_name in used_path_names:
                    path_name = aid_hex
                roots.append(target_node)
                used_path_names.add(path_name)

            if len(path_name) == 0:
                path_name = str(target_node.get("name", "")).strip().upper()
            target_node["path_name"] = path_name

            merged_fids = [aid_hex]
            for candidate in target_node.get("fids", []):
                candidate_text = str(candidate or "").strip().upper()
                if len(candidate_text) == 0:
                    continue
                if candidate_text == aid_hex:
                    continue
                merged_fids.append(candidate_text)
            target_node["fids"] = merged_fids

            node_name = str(target_node.get("name", "")).strip().upper()
            label_text = self._normalize_ef_dir_label(app_entry.get("label", ""))
            display_name = node_name
            if len(label_text) > 0 and label_text.upper() != node_name:
                display_name = f"{node_name} [{label_text}]"
            target_node["display_name"] = display_name

    def _refresh_aid_registry_from_ef_dir(self, silent: bool = False) -> bool:
        app_entries = self._discover_ef_dir_applications()
        refreshed = self._cache_ef_dir_aliases(app_entries)
        persisted = self._persist_ef_dir_discoveries(app_entries)
        if (refreshed or persisted) and not silent:
            print(
                f"{Config.Colors.CYAN}[*] Refreshed application AIDs from EF.DIR.{Config.Colors.ENDC}"
            )
        if refreshed:
            return True
        return persisted

    def _cache_selected_application_aliases(self, target: str, fid_value: str) -> None:
        clean_target = str(target or "").strip().upper()
        clean_fid = str(fid_value or "").strip().upper()
        if len(clean_target) == 0:
            return
        if self._is_hex_identifier(clean_target):
            return
        if not self._is_hex_identifier(clean_fid):
            return
        if len(clean_fid) <= 4:
            return

        alias_names = []
        if clean_target.startswith("ADF_"):
            alias_names.append(clean_target)
            base_name = clean_target[4:]
            if len(base_name) > 0:
                alias_names.append(base_name)
        else:
            alias_names.append(clean_target)
            if clean_target in ("USIM", "ISIM", "SSIM", "CSIM"):
                alias_names.append(f"ADF_{clean_target}")

        for alias_name in alias_names:
            alias_key = str(alias_name or "").strip().upper()
            if len(alias_key) == 0:
                continue
            self.aid_registry[alias_key] = clean_fid

    def select(self, target_path: str, silent: bool = False) -> bool:
        """Navigate to *target_path* by issuing SELECT-by-FID APDUs (ETSI TS 102 221 §11.1.1); return True on success."""
        target_path = target_path.strip().upper()

        has_cache = False
        if hasattr(self, "scan_cache"):
            has_cache = True

        if has_cache:
            if target_path in self.scan_cache:
                resolved_path = self.scan_cache[target_path]
                if not silent:
                    print(
                        f"{Config.Colors.CYAN}[*] Resolved Index [{target_path}] -> {resolved_path}{Config.Colors.ENDC}"
                    )
                target_path = resolved_path

        if "/" in target_path:
            if not silent:
                print(
                    f"{Config.Colors.CYAN}[*] Path Selection Detected: '{target_path}'{Config.Colors.ENDC}"
                )

            mf_success = self._select_single("MF", silent=True, resolve=False)
            if not mf_success:
                return False

            segments = []
            for x in target_path.split("/"):
                if x:
                    segments.append(x)

            for i, segment in enumerate(segments):
                is_last = False
                if i == len(segments) - 1:
                    is_last = True

                step_silent = True
                if not silent:
                    if not is_last:
                        step_silent = True
                    if is_last:
                        step_silent = False

                segment_success = self._select_single(
                    segment, silent=step_silent, resolve=is_last
                )
                if not segment_success:
                    if not silent:
                        print(
                            f"{Config.Colors.FAIL}[-] Path broken at segment: '{segment}'{Config.Colors.ENDC}"
                        )
                    return False
            self.current_path_hint = target_path
            return True

        if target_path in self.aid_registry:
            aid_hex = self.aid_registry[target_path]
            if not silent:
                print(
                    f"{Config.Colors.CYAN}[*] Resolved Alias '{target_path}' -> {aid_hex}{Config.Colors.ENDC}"
                )

        return self._select_single(target_path, silent=silent, resolve=True)

    def _select_single(
        self, target: str, silent: bool = False, resolve: bool = True
    ) -> bool:
        """
        Iterates through candidate FIDs/AIDs.
        resolve=True means we will try to resolve ARR security rules for the selected file.
        """
        target = target.upper()
        previous_restore_commands = list(
            getattr(self, "_selection_restore_commands", []) or []
        )
        previous_fcp = dict(getattr(self, "current_fcp", {}) or {})
        candidates = []
        alias_candidate = str(self.aid_registry.get(target, "")).strip().upper()
        if self._is_hex_identifier(alias_candidate):
            candidates.append(alias_candidate)

        mapped_candidates = self.fid_map.get(target)
        if not mapped_candidates:
            mapped_candidates = [target]

        for candidate in mapped_candidates:
            normalized_candidate = str(candidate or "").strip().upper()
            if normalized_candidate not in candidates:
                candidates.append(normalized_candidate)

        for fid in candidates:
            if not all(c in "0123456789ABCDEFabcdef" for c in fid):
                continue

            data, sw1, sw2, cmd = self._transmit_select(fid)

            if fid == "3F00":
                if not self._is_successful_select_response(sw1, data):
                    # TS 102 221 §11.1.1: P1=00 resolves the file ID against
                    # the current DF, so the MF identifier is not visible from
                    # inside an ADF (ADF.USIM, ISD-R, ...) and the card answers
                    # 6A82. P1=08 selects by path from MF and works from any
                    # position; the by-FID form is tried first because some
                    # legacy cards implement only that one.
                    data, sw1, sw2 = self.tp.transmit("00A40804023F00", silent=True)

            if self._is_successful_select_response(sw1, data):
                restore_commands = self._build_restore_command_trail(
                    fid,
                    cmd,
                    previous_restore_commands,
                    previous_fcp,
                )
                self.current_fid = fid
                self.current_path_hint = target
                self._selection_restore_commands = restore_commands
                self._cache_selected_application_aliases(target, fid)
                # An empty response must not leave the previous file's FCP in
                # place; the decoder records ``template: Unknown`` for it.
                self._parse_fcp_internal(
                    data,
                    target_fid=fid,
                    resolve=resolve,
                    restore_commands=restore_commands,
                )

                if not silent:
                    print(
                        f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {data.hex().upper()} {sw1:02X}{sw2:02X}"
                    )
                    print(
                        f"{Config.Colors.GREEN}[+] Selected {target} ({fid}){Config.Colors.ENDC}"
                    )
                    self.print_fcp_info()
                return True
            else:
                if not silent and len(candidates) > 1:
                    print(
                        f"{Config.Colors.WARNING}[-] Candidate {fid} failed ({sw1:02X}{sw2:02X}), trying next...{Config.Colors.ENDC}"
                    )

        should_probe_dir = self._should_try_ef_dir_fallback(target)
        if should_probe_dir:
            if not silent:
                print(
                    f"{Config.Colors.CYAN}[*] Probing EF.DIR for application AIDs...{Config.Colors.ENDC}"
                )
            self._refresh_aid_registry_from_ef_dir(silent=silent)
            discovered_aid = str(self.aid_registry.get(target, "")).strip().upper()
            can_retry = False
            if self._is_hex_identifier(discovered_aid):
                if discovered_aid not in candidates:
                    can_retry = True

            if can_retry:
                data, sw1, sw2, retry_cmd = self._transmit_select(discovered_aid)

                if self._is_successful_select_response(sw1, data):
                    restore_commands = self._build_restore_command_trail(
                        discovered_aid,
                        retry_cmd,
                        previous_restore_commands,
                        previous_fcp,
                    )
                    self.current_fid = discovered_aid
                    self.current_path_hint = target
                    self._selection_restore_commands = restore_commands
                    self._cache_selected_application_aliases(target, discovered_aid)
                    self._parse_fcp_internal(
                        data,
                        target_fid=discovered_aid,
                        resolve=resolve,
                        restore_commands=restore_commands,
                    )
                    if not silent:
                        print(
                            f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {data.hex().upper()} {sw1:02X}{sw2:02X}"
                        )
                        print(
                            f"{Config.Colors.GREEN}[+] Selected {target} ({discovered_aid}){Config.Colors.ENDC}"
                        )
                        self.print_fcp_info()
                    return True

        if not silent:
            print(
                f"{Config.Colors.FAIL}[-] Select Failed: '{target}' (Tried: {candidates}){Config.Colors.ENDC}"
            )
        return False

    def _parse_fcp_internal(
        self,
        data: bytes,
        target_fid: str = None,
        resolve: bool = True,
        restore_commands: Optional[List[str]] = None,
    ):
        """Decode a SELECT response into ``current_fcp``.

        A '62' FCP template is decoded per TS 102 221 v18.4 §11.1.1.3 /
        §11.1.1.4; a '6F' FCI template per GlobalPlatform Card Specification
        v2.3.1 table 11-82. Anything else, or malformed input, leaves a
        ``template: Unknown`` entry with the raw bytes and a ``parse_error``.
        """
        raw = bytes(data or b"")
        raw_hex = raw.hex().upper()
        self.current_fcp = {"template": "Unknown", "raw": raw_hex}
        try:
            outer = _split_ber_tlvs(raw)
            fcp_body = _first_tlv_value(outer, 0x62)
            fci_body = _first_tlv_value(outer, 0x6F)
            if fcp_body is not None:
                self.current_fcp = self._decode_fcp_template(fcp_body, raw_hex)
                if resolve and self.current_fcp.get("security_format") == "referenced":
                    self._resolve_fcp_access_rules(target_fid, restore_commands)
            elif fci_body is not None:
                self.current_fcp = self._decode_fci_template(fci_body, raw_hex)
        except Exception as error:
            self.current_fcp["parse_error"] = str(error)

    def _decode_fcp_template(self, body: bytes, raw_hex: str) -> Dict[str, Any]:
        """Decode the value of an FCP template (TS 102 221 v18.4 §11.1.1.4)."""
        items = _split_ber_tlvs(body)
        fcp: Dict[str, Any] = {
            "template": "FCP",
            "raw": raw_hex,
            "type": "Unknown",
            "structure": "Unknown",
            "file_kind": None,
            "shareable": None,
            "size": 0,
            "total_size": None,
            "rec_len": 0,
            "rec_count": 0,
            "fid": None,
            "aid": None,
            "file_descriptor": None,
            "lcs": "Unknown",
            "lcs_name": None,
            "sfi": None,
            "sfi_raw": None,
            "sfi_supported": None,
            "security": "None",
            "security_format": None,
            "arr_fid": None,
            "arr_record": None,
            "arr_se_records": None,
            "rules": None,
            "pin_status": None,
            "proprietary": None,
        }

        descriptor = _first_tlv_value(items, 0x82)
        if descriptor:
            fcp["file_descriptor"] = descriptor.hex().upper()
            fcp.update(_decode_file_descriptor(descriptor))

        fid_value = _first_tlv_value(items, 0x83)
        if fid_value is not None and len(fid_value) == 2:
            fcp["fid"] = fid_value.hex().upper()

        aid_value = _first_tlv_value(items, 0x84)
        if aid_value:
            fcp["aid"] = aid_value.hex().upper()

        # §11.1.1.4.1 / §11.1.1.4.2: '80' is the body size of an EF, '81' the
        # allocated memory including structural information. A DF carries
        # only '81'; it is reported as ``size`` there so directory rows keep
        # showing the one figure the card gives.
        size_value = _first_tlv_value(items, 0x80)
        total_value = _first_tlv_value(items, 0x81)
        if total_value is not None:
            fcp["total_size"] = int.from_bytes(total_value, "big")
        if size_value is not None:
            fcp["size"] = int.from_bytes(size_value, "big")
        elif fcp["type"] == "DF" and total_value is not None:
            fcp["size"] = fcp["total_size"]
        if fcp["rec_len"] > 0 and fcp["rec_count"] == 0 and fcp["size"] > 0:
            fcp["rec_count"] = fcp["size"] // fcp["rec_len"]

        lcs_value = _first_tlv_value(items, 0x8A)
        if lcs_value:
            fcp["lcs"] = lcs_value.hex().upper()
            fcp["lcs_name"] = _lcs_name(lcs_value[0])

        # §11.1.1.4.8: with the TLV absent the SFI is the low five bits of
        # the FID; an empty TLV means no SFI; otherwise b8..b4 carry it.
        sfi_value = _first_tlv_value(items, 0x88)
        if sfi_value is None:
            if fcp["fid"] is not None and fcp["type"] == "EF":
                fcp["sfi"] = f"{int(fcp['fid'], 16) & 0x1F:02X}"
                fcp["sfi_supported"] = True
        elif len(sfi_value) == 0:
            fcp["sfi_supported"] = False
        else:
            fcp["sfi_raw"] = sfi_value.hex().upper()
            fcp["sfi"] = f"{sfi_value[0] >> 3:02X}"
            fcp["sfi_supported"] = True

        proprietary = _first_tlv_value(items, 0xA5)
        if proprietary is not None:
            try:
                fcp["proprietary"] = _decode_proprietary_information(proprietary)
            except ValueError:
                fcp["proprietary"] = {"raw": proprietary.hex().upper()}

        pin_status = _first_tlv_value(items, 0xC6)
        if pin_status is not None:
            try:
                fcp["pin_status"] = _decode_pin_status_template(pin_status)
            except ValueError:
                fcp["pin_status"] = []

        # §11.1.1.4.7: exactly one of '8B' (referenced), '8C' (compact) or
        # 'AB' (expanded) is present. Only the referenced form is resolved
        # into rules; the other two are reported so a blank access-rule
        # panel is not read as "no rules apply".
        referenced = _first_tlv_value(items, 0x8B)
        if referenced is not None:
            fcp["security"] = referenced.hex().upper()
            fcp["security_format"] = "referenced"
            fcp.update(_decode_referenced_security(referenced))
        else:
            for alt_tag, alt_format in ((0x8C, "compact"), (0xAB, "expanded")):
                alt_value = _first_tlv_value(items, alt_tag)
                if alt_value is None:
                    continue
                fcp["security"] = alt_value.hex().upper()
                fcp["security_format"] = alt_format
                fcp["rules"] = (
                    f"Present in {alt_format} format (tag {alt_tag:02X}); not decoded."
                )
                break
        return fcp

    @staticmethod
    def _decode_fci_template(body: bytes, raw_hex: str) -> Dict[str, Any]:
        """Decode a GlobalPlatform FCI (GPC v2.3.1 §11.9.3.1, table 11-82).

        '84' is the application AID; the mandatory 'A5' proprietary template
        holds '9F65' (maximum length of the command data field), '9F6E'
        (application production life cycle data) and '73' (Security Domain
        recognition data). The objects are also accepted at the top level for
        cards that flatten the template.
        """
        items = _split_ber_tlvs(body)
        fci: Dict[str, Any] = {
            "template": "FCI",
            "raw": raw_hex,
            "type": "Application/SD",
            "aid": "Unknown",
            "max_len": "Unknown",
            "lcs": "Unknown",
        }
        aid_value = _first_tlv_value(items, 0x84)
        if aid_value:
            fci["aid"] = aid_value.hex().upper()
        scoped: List[Tuple[int, bytes]] = []
        proprietary = _first_tlv_value(items, 0xA5)
        if proprietary is not None:
            try:
                scoped = _split_ber_tlvs(proprietary)
            except ValueError:
                fci["fci_proprietary"] = proprietary.hex().upper()
        scoped = scoped + items
        max_len = _first_tlv_value(scoped, 0x9F65)
        if max_len:
            fci["max_len"] = int.from_bytes(max_len, "big")
        production = _first_tlv_value(scoped, 0x9F6E)
        if production:
            fci["app_production_lcs"] = production.hex().upper()
        sd_data = _first_tlv_value(scoped, 0x73)
        if sd_data:
            fci["sd_data"] = sd_data.hex().upper()
        return fci

    def _resolve_fcp_access_rules(
        self,
        target_fid: Optional[str],
        restore_commands: Optional[List[str]],
    ) -> None:
        """Read the EF_ARR record that the '8B' object of ``current_fcp`` cites."""
        record_number = self.current_fcp.get("arr_record")
        if record_number is None:
            return
        restore_fid = target_fid if target_fid else self.current_fid
        if not restore_fid:
            return
        # The FCP citing the record fixes which access-mode table it is read
        # with: a DF/ADF reads the low three bits as DELETE CHILD / CREATE EF
        # / CREATE DF.
        arr_scope = "df" if str(self.current_fcp.get("type") or "").upper() == "DF" else "ef"
        restore_trail = list(
            restore_commands
            or getattr(self, "_selection_restore_commands", [])
            or []
        )
        arr_fid = self.current_fcp.get("arr_fid")
        if arr_fid:
            self.current_fcp["rules"] = self._resolve_arr_rules(
                arr_fid,
                int(record_number),
                restore_fid,
                restore_commands=restore_trail,
                scope=arr_scope,
            )
            return
        rules = self._resolve_arr_rules(
            "6F06",
            int(record_number),
            restore_fid,
            restore_commands=restore_trail,
            scope=arr_scope,
        )
        if not rules or "Empty" in rules:
            rules = self._resolve_arr_rules(
                "2F06",
                int(record_number),
                restore_fid,
                restore_commands=restore_trail,
                scope=arr_scope,
            )
        self.current_fcp["rules"] = rules

    def _select_referenced_arr(self, arr_fid: str) -> bool:
        """Locate the EF_ARR cited by tag '8B' the way TS 102 221 v18.4 §9.2.7 describes.

        "For an EF, if the EF(ARR) file with the file ID indicated in tag '8B'
        cannot be found in the current DF, the parent DF shall be searched for
        EF(ARR). This process shall continue until the EF(ARR) is found or
        until an ADF or the MF is reached." SELECT with P1 '03' walks to the
        parent DF and fails at the MF and at an ADF, which ends the walk.
        """
        cmd_sel = f"00A4000402{arr_fid}"
        _, sw1, _sw2 = self.tp.transmit(cmd_sel, silent=True)
        if sw1 == 0x90:
            return True
        for _level in range(self.ARR_PARENT_SEARCH_DEPTH):
            _, parent_sw1, _parent_sw2 = self.tp.transmit("00A4030000", silent=True)
            if parent_sw1 != 0x90:
                return False
            _, sw1, _sw2 = self.tp.transmit(cmd_sel, silent=True)
            if sw1 == 0x90:
                return True
        return False

    def _resolve_arr_rules(
        self,
        arr_fid: str,
        record_num: int,
        restore_fid: str,
        restore_commands: Optional[List[str]] = None,
        scope: str = "ef",
    ) -> Optional[str]:

        cmd_sel = f"00A4000402{arr_fid}"
        sw1 = 0x90 if self._select_referenced_arr(arr_fid) else 0x6A

        is_still_failed = False
        if sw1 != 0x90:
            is_still_failed = True

        if is_still_failed:
            # The §9.2.7 walk did not reach the file. Fall back on the two
            # well-known EF_ARR locations for cards whose SELECT does not
            # answer a parent-DF walk.
            is_mf_arr = False
            if arr_fid == "2F06":
                is_mf_arr = True

            if is_mf_arr:
                self.tp.transmit("00A40004023F00", silent=True)
                _, sw1, _sw2 = self.tp.transmit(cmd_sel, silent=True)

            is_usim_arr = False
            if arr_fid == "6F06":
                is_usim_arr = True

            if is_usim_arr:
                # TS 102 221 v18.4 §8.3: '7FFF' is the reserved FID of the ADF
                # of the application active on this channel; '7FF0' is a
                # proprietary value some cards expose for the same ADF.
                for adf_fid in ("7FFF", "7FF0"):
                    self.tp.transmit("00A40004023F00", silent=True)
                    _, adf_sw1, _ = self.tp.transmit(f"00A4000402{adf_fid}", silent=True)
                    if adf_sw1 != 0x90:
                        continue
                    _, sw1, _sw2 = self.tp.transmit(cmd_sel, silent=True)
                    if sw1 == 0x90:
                        break

        is_fatal = False
        if sw1 != 0x90:
            is_fatal = True

        if is_fatal:
            self._restore_selection_after_arr_probe(restore_fid, restore_commands)
            return None

        cmd_read = f"00B2{record_num:02X}0400"
        data, sw1, sw2 = self.tp.transmit(cmd_read, silent=True)

        self._restore_selection_after_arr_probe(restore_fid, restore_commands)

        is_read_success = False
        if sw1 == 0x90:
            is_read_success = True

        if is_read_success:
            has_data = False
            if data:
                has_data = True

            if has_data:
                decoded = AdvancedDecoders.decode_ef_arr(
                    data.hex().upper(), scope=scope
                )

                is_list = False
                if isinstance(decoded, list):
                    is_list = True

                if is_list:
                    return "\n".join(decoded)

                is_str = False
                if not is_list:
                    is_str = True

                if is_str:
                    return str(decoded)

        return None

    def get_arr(self, path: Optional[str] = None) -> None:
        """
        Read and decode Application Reference Data (ARR) for MF or USIM context.
        path: None (use current), 'MF', 'USIM', or FID. Prints decoded security rules.

        The record is read at the level of the selected file, so that file's kind
        picks the access-mode table: under MF, a DF or an ADF the low three bits
        are DELETE FILE (child) and the two CREATE FILE modes, not READ / UPDATE
        / APPEND (ISO 7816-4 tables 17/18).
        """
        prev_fid = self.current_fid
        arr_fid = "2F06"
        if path:
            path_upper = path.strip().upper()
            if not self.select(path_upper):
                return
            if path_upper in ("USIM", "7FF0", "7FFF", "ADF_USIM") or (
                len(path_upper) == 4 and path_upper.startswith("7FF")
            ):
                arr_fid = "6F06"
            else:
                arr_fid = "2F06"
        else:
            if self.current_fid == "6F06":
                arr_fid = "6F06"
            elif self.current_fid == "2F06":
                arr_fid = "2F06"
            elif self.current_fid and (
                self.current_fid == "7FF0"
                or self.current_fid == "7FFF"
                or (len(self.current_fid) == 4 and self.current_fid.startswith("6F"))
            ):
                arr_fid = "6F06"
            else:
                arr_fid = "2F06"
        arr_scope = (
            "df" if str(self.current_fcp.get("type") or "").upper() == "DF" else "ef"
        )
        # The §9.2.7 walk can leave the card several DF levels above where it
        # started, so the caller's selection is restored by replaying the
        # trail that reached it rather than by one SELECT of its file ID.
        restore_trail = list(getattr(self, "_selection_restore_commands", []) or [])
        if self._select_referenced_arr(arr_fid) is False:
            print(
                f"{Config.Colors.FAIL}[-] Could not select ARR (FID {arr_fid}).{Config.Colors.ENDC}"
            )
            if prev_fid:
                if len(restore_trail) > 0:
                    self._restore_selection_after_arr_probe(prev_fid, restore_trail)
                else:
                    self.select(prev_fid)
            return
        data, sw1, sw2 = self.tp.transmit("00B2010400", silent=True)
        if prev_fid:
            self._restore_selection_after_arr_probe(prev_fid, restore_trail)
        if sw1 == 0x90 and data:
            record_hex = data.hex().upper()
            decoded = AdvancedDecoders.decode_ef_arr(record_hex, scope=arr_scope)
            table = " · MF/DF/ADF rules" if arr_scope == "df" else ""
            print(
                f"{Config.Colors.HEADER}--- ARR (FID {arr_fid}){table} ---{Config.Colors.ENDC}"
            )
            for line in decoded:
                print(f"  {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
            # The record is read at a level, not through one FCP, so the other
            # table is printed too whenever it names different operations.
            other_scope = "ef" if arr_scope == "df" else "df"
            alternate = AdvancedDecoders.decode_ef_arr(record_hex, scope=other_scope)
            if alternate != decoded:
                other_label = (
                    "MF / a DF / an ADF" if other_scope == "df" else "an EF"
                )
                print(f"  {Config.Colors.HEADER}If {other_label} cites this record:{Config.Colors.ENDC}")
                for line in alternate:
                    print(f"    {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
        else:
            print(
                f"{Config.Colors.FAIL}[-] Read ARR failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    def print_fcp_info(self):
        """Print the File Control Parameters of the currently selected file in a human-readable table."""
        tmpl = self.current_fcp.get("template", "Unknown")
        print(f"{Config.Colors.CYAN}--- {tmpl} ---{Config.Colors.ENDC}")
        info = self.current_fcp

        if info.get("aid"):
            print(f"    [AID]      {info.get('aid')}")

        if tmpl == "FCI":
            print(f"    [Type]     {info.get('type')}")
            print(f"    [Max Len]  {info.get('max_len')}")
            print(f"    [LCS]      {info.get('lcs')}")
            if info.get("sd_data"):
                print(f"    [SD Data]  {info.get('sd_data')}")

        if tmpl == "FCP":
            kind_suffix = ""
            file_kind = info.get("file_kind")
            if file_kind and file_kind not in ("DF or ADF", "working EF"):
                kind_suffix = f", {file_kind}"
            if info.get("shareable"):
                kind_suffix += ", shareable"
            print(
                f"    [Type]     {info.get('type')} ({info.get('structure')}{kind_suffix})"
            )
            if info.get("fid"):
                print(f"    [FID]      {info.get('fid')}")
            print(f"    [Size]     {info.get('size')} bytes")
            total_size = info.get("total_size")
            if total_size is not None and total_size != info.get("size"):
                print(f"    [Total]    {total_size} bytes")

            has_rec = False
            if info.get("rec_len", 0) > 0:
                has_rec = True

            if has_rec:
                print(
                    f"    [Rec]      {info.get('rec_count')} records x {info.get('rec_len')} bytes"
                )

            if info.get("sfi_supported") is False:
                print("    [SFI]      not supported")
            elif info.get("sfi"):
                sfi_line = f"    [SFI]      {info.get('sfi')}"
                if info.get("sfi_raw"):
                    sfi_line += f" (tag 88 value {info.get('sfi_raw')})"
                print(sfi_line)

            print(f"    [Sec]      {info.get('security')}")

            rules = info.get("rules")
            if rules:
                is_list = False
                if isinstance(rules, list):
                    is_list = True

                if is_list:
                    for line in rules:
                        print(
                            f"               | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}"
                        )

                is_str = False
                if not is_list:
                    is_str = True

                if is_str:
                    for line in rules.split("\n"):
                        print(
                            f"               | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}"
                        )

            lcs_line = f"    [LCS]      {info.get('lcs')}"
            if info.get("lcs_name"):
                lcs_line += f" ({info.get('lcs_name')})"
            print(lcs_line)

            for entry in info.get("pin_status") or []:
                state = "enabled" if entry.get("enabled") else "disabled"
                pin_line = (
                    f"    [PIN]      {entry.get('key_ref')} {entry.get('name')}: {state}"
                )
                if entry.get("usage_qualifier") is not None:
                    pin_line += f", usage qualifier {entry.get('usage_qualifier')}"
                print(pin_line)

        is_unknown = False
        if tmpl != "FCI":
            if tmpl != "FCP":
                is_unknown = True

        if is_unknown:
            if len(str(info.get("raw") or "")) == 0:
                print(
                    f"    {Config.Colors.WARNING}[!] SELECT returned no FCP template; "
                    f"type and structure are unknown.{Config.Colors.ENDC}"
                )
            else:
                print(f"    (Raw Data): {info.get('raw')}")

        print(f"{Config.Colors.ENDC}")

    def _read_binary_full(self) -> Tuple[bytes, int, int]:
        """READ BINARY over the whole body of the selected transparent EF.

        Le '00' asks for 256 bytes, so a body longer than that needs further
        commands with the offset in P1 (b7..b1, high part) and P2 (low part)
        (TS 102 221 v18.4 §11.1.3.2, table 11.10). The FCP file size bounds
        the Le of the tail when it is known; otherwise reading continues
        until a short chunk or an error. The status of the first command is
        returned when it fails, '9000' once at least one chunk arrived.
        """
        size = 0
        try:
            size = int(self.current_fcp.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        collected = bytearray()
        offset = 0
        while offset <= _BINARY_MAX_OFFSET:
            remaining = size - offset
            if size > 0 and remaining <= 0:
                break
            # The first command keeps Le '00' (the card answers with what
            # exists, up to 256 bytes); only a tail beyond the first chunk
            # is bounded by the FCP size.
            le = 0
            if size > 0 and offset > 0 and remaining < 256:
                le = remaining
            cmd = f"00B0{(offset >> 8) & 0x7F:02X}{offset & 0xFF:02X}{le:02X}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            chunk = bytes(data or b"")
            chunk_ok = sw1 == 0x90
            # '62 82' is "end of file reached before reading Le bytes" and
            # still carries the bytes that exist (TS 102 221 v18.4 §10.2.1).
            if sw1 == 0x62 and sw2 == 0x82 and len(chunk) > 0:
                chunk_ok = True
            if not chunk_ok:
                if offset == 0:
                    return chunk, sw1, sw2
                break
            collected += chunk
            offset += len(chunk)
            expected = 256 if le == 0 else le
            if len(chunk) < expected:
                break
        return bytes(collected), 0x90, 0x00

    def read_binary(self, path: Optional[str] = None):
        """Read and decode a transparent EF via READ BINARY (ETSI TS 102 221 §11.1.3)."""
        if path:
            print(f"{Config.Colors.CYAN}[*] Navigating to: {path}{Config.Colors.ENDC}")
            if not self.select(path):
                return
        if self.current_fcp.get("structure") == "Linear Fixed":
            print(
                f"{Config.Colors.WARNING}[!] Warning: File is Linear Fixed. Use 'RECORD' command.{Config.Colors.ENDC}"
            )

        data, sw1, sw2 = self._read_binary_full()
        status_color = Config.Colors.GREEN if sw1 == 0x90 else Config.Colors.FAIL
        status_text = f"{status_color}{sw1:02X}{sw2:02X}{Config.Colors.ENDC}"

        if sw1 == 0x90:
            hex_data = data.hex().upper()
            print(f"Data [{status_text}]: {hex_data}")
            decoded = ContentDecoder.decode(
                self.current_fid, hex_data, context_path=self.current_path_hint
            )
            if decoded:
                for line in decoded.strip().split("\n"):
                    print(f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")
        else:
            print(f"Data [{status_text}]: Read Failed")

    def read_record(self, arg_line):
        """Read and decode one or all records of the currently selected linear-fixed EF via READ RECORD (ETSI TS 102 221 §11.1.5)."""
        args = str(arg_line).strip().split()

        has_no_args = False
        if len(args) == 0:
            has_no_args = True

        if has_no_args:
            print(
                f"{Config.Colors.FAIL}[-] Usage: RECORD <Num|ALL|Start-End> [Path]{Config.Colors.ENDC}"
            )
            return

        rec_arg = args[0]

        path = None
        has_path_arg = False
        if len(args) > 1:
            has_path_arg = True

        if has_path_arg:
            path = args[1]

        if path:
            print(f"{Config.Colors.CYAN}[*] Navigating to: {path}{Config.Colors.ENDC}")

            sel_res = self.select(path)
            sel_failed = False
            if not sel_res:
                sel_failed = True

            if sel_failed:
                return

        structure = self.current_fcp.get("structure", "Unknown")
        is_linear = False
        if structure == "Linear Fixed":
            is_linear = True
        is_cyclic = False
        if structure == "Cyclic":
            is_cyclic = True
        is_record_file = False
        if is_linear:
            is_record_file = True
        if is_cyclic:
            is_record_file = True
        if not is_record_file:
            print(
                f"{Config.Colors.FAIL}[-] RECORD not allowed on {structure} file. Select a Linear Fixed or Cyclic EF.{Config.Colors.ENDC}"
            )
            return

        le = "00"

        has_fcp = False
        if self.current_fcp:
            has_fcp = True

        if has_fcp:
            has_rec_len = False
            if "rec_len" in self.current_fcp:
                has_rec_len = True

            if has_rec_len:
                le = f"{self.current_fcp['rec_len']:02X}"

        def _read_one(rec_num):
            cmd = f"00B2{rec_num:02X}04{le}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)

            status_color = Config.Colors.FAIL
            is_success = False
            if sw1 == 0x90:
                is_success = True

            if is_success:
                status_color = Config.Colors.GREEN

            status_text = f"{status_color}{sw1:02X}{sw2:02X}{Config.Colors.ENDC}"

            if is_success:
                hex_val = data.hex().upper()
                print(f"Record {rec_num:02} [{status_text}]: {hex_val}")

                is_arr = False
                if self.current_fid == "6F06":
                    is_arr = True
                if self.current_fid == "2F06":
                    is_arr = True

                if is_arr:
                    decoded_arr = AdvancedDecoders.decode_ef_arr(hex_val)

                    has_decoded_arr = False
                    if decoded_arr is not None:
                        has_decoded_arr = True

                    if has_decoded_arr:
                        is_list = False
                        if isinstance(decoded_arr, list):
                            is_list = True

                        if is_list:
                            for rule in decoded_arr:
                                print(
                                    f"               | {Config.Colors.CYAN}{rule}{Config.Colors.ENDC}"
                                )

                        is_str = False
                        if not is_list:
                            is_str = True

                        if is_str:
                            for rule in str(decoded_arr).split("\n"):
                                print(
                                    f"               | {Config.Colors.CYAN}{rule}{Config.Colors.ENDC}"
                                )

                is_not_arr = False
                if not is_arr:
                    is_not_arr = True

                if is_not_arr:
                    decoded = ContentDecoder.decode(
                        self.current_fid, hex_val, context_path=self.current_path_hint
                    )

                    has_decoded = False
                    if decoded:
                        has_decoded = True

                    if has_decoded:
                        is_valid_decode = True
                        if "None" in decoded:
                            is_valid_decode = False

                        if is_valid_decode:
                            for line in decoded.strip().split("\n"):
                                print(
                                    f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}"
                                )

            is_fail = False
            if not is_success:
                is_fail = True

            if is_fail:
                print(f"Record {rec_num:02} [{status_text}]: Read error")

            return sw1, sw2

        arg = rec_arg.upper()

        is_all = False
        if arg == "ALL":
            is_all = True

        if is_all:
            print(f"{Config.Colors.CYAN}[*] Reading All Records...{Config.Colors.ENDC}")

            count = 20

            has_fcp_count = False
            if self.current_fcp:
                has_fcp_count = True

            if has_fcp_count:
                has_count_key = False
                if "rec_count" in self.current_fcp:
                    has_count_key = True

                if has_count_key:
                    count = self.current_fcp["rec_count"]

            is_overflow = False
            if count > 255:
                is_overflow = True

            if is_overflow:
                count = 255

            r = 1
            while r <= count:
                sw1, sw2 = _read_one(r)

                is_end = False
                if sw1 == 0x6A:
                    is_end = True

                if is_end:
                    break

                r += 1

            print(f"{Config.Colors.CYAN}[*] End of file reached.{Config.Colors.ENDC}")

        is_range = False
        if not is_all:
            if "-" in arg:
                is_range = True
        if is_range:
            range_parts = arg.split("-", 1)
            valid_range = False
            if len(range_parts) == 2:
                valid_range = True
            if not valid_range:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid range format: {arg}{Config.Colors.ENDC}"
                )
                return

            start_str = range_parts[0].strip()
            end_str = range_parts[1].strip()
            is_empty_start = False
            if len(start_str) == 0:
                is_empty_start = True
            is_empty_end = False
            if len(end_str) == 0:
                is_empty_end = True
            if is_empty_start:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid range start in: {arg}{Config.Colors.ENDC}"
                )
                return
            if is_empty_end:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid range end in: {arg}{Config.Colors.ENDC}"
                )
                return

            try:
                start_num = self._parse_record_arg(start_str)
                end_num = self._parse_record_arg(end_str)
            except ValueError:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid range number in: {arg}{Config.Colors.ENDC}"
                )
                return

            invalid_start = False
            if start_num < 1:
                invalid_start = True
            if invalid_start:
                print(
                    f"{Config.Colors.FAIL}[!] Range start must be >= 1.{Config.Colors.ENDC}"
                )
                return

            invalid_order = False
            if end_num < start_num:
                invalid_order = True
            if invalid_order:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid range: end < start ({start_num}-{end_num}).{Config.Colors.ENDC}"
                )
                return

            max_end = end_num
            has_known_count = False
            if self.current_fcp:
                if "rec_count" in self.current_fcp:
                    has_known_count = True
            if has_known_count:
                rec_count = self.current_fcp.get("rec_count", 0)
                if rec_count > 0:
                    if max_end > rec_count:
                        max_end = rec_count
            is_overflow = False
            if max_end > 255:
                is_overflow = True
            if is_overflow:
                max_end = 255

            is_empty_after_clamp = False
            if max_end < start_num:
                is_empty_after_clamp = True
            if is_empty_after_clamp:
                print(
                    f"{Config.Colors.WARNING}[!] Requested range has no readable records in current EF.{Config.Colors.ENDC}"
                )
                return

            print(
                f"{Config.Colors.CYAN}[*] Reading record range {start_num}-{max_end}...{Config.Colors.ENDC}"
            )
            r = start_num
            while r <= max_end:
                sw1, sw2 = _read_one(r)
                is_end = False
                if sw1 == 0x6A:
                    is_end = True
                if is_end:
                    break
                r += 1
            print(f"{Config.Colors.CYAN}[*] Range read completed.{Config.Colors.ENDC}")

        is_single = False
        if not is_all:
            if not is_range:
                is_single = True

        if is_single:
            try:
                rec_num = self._parse_record_arg(arg)
                _read_one(rec_num)
            except ValueError:
                print(
                    f"{Config.Colors.FAIL}[!] Invalid record number: {arg}{Config.Colors.ENDC}"
                )

    def update_binary(self, hex_data: str):
        """Write a hex payload to the currently selected transparent EF via UPDATE BINARY (ETSI TS 102 221 §11.1.4).

        A short Lc carries at most 255 bytes, so a longer payload is written
        in consecutive commands whose P1/P2 carry the offset of each chunk
        (§11.1.4.2: P1/P2 coded as for READ BINARY, table 11.10).
        """
        try:
            cleaned_hex = hex_data.replace(" ", "").upper()
            raw_payload = bytes.fromhex(cleaned_hex)
            if len(raw_payload) == 0:
                raise ValueError("payload is empty")
            if len(raw_payload) - 1 > _BINARY_MAX_OFFSET:
                raise ValueError("payload exceeds the 32768-byte offset range of P1/P2")
            for offset in range(0, len(raw_payload), 255):
                chunk = raw_payload[offset : offset + 255]
                cmd = (
                    f"00D6{(offset >> 8) & 0x7F:02X}{offset & 0xFF:02X}"
                    f"{len(chunk):02X}{chunk.hex().upper()}"
                )
                data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
                if sw1 != 0x90:
                    print(
                        f"{Config.Colors.FAIL}[-] Update Failed at offset {offset}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                    )
                    return
            print(
                f"{Config.Colors.GREEN}[+] Binary Update Successful.{Config.Colors.ENDC}"
            )
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Update Error: {e}{Config.Colors.ENDC}")

    def update_record(self, rec_num: Union[int, str], hex_data: str):
        """Write a hex payload to a specific record of the currently selected linear-fixed EF via UPDATE RECORD (ETSI TS 102 221 §11.1.6)."""
        try:
            record_int = self._parse_record_arg(rec_num)
            cleaned_hex = hex_data.replace(" ", "").upper()
            raw_payload = bytes.fromhex(cleaned_hex)
            lc = len(raw_payload)
            # TS 102 221 v18.4 §11.1.1.4.3: a record is '0001'..'00FF' bytes.
            if lc == 0 or lc > 0xFF:
                raise ValueError(f"record payload must be 1..255 bytes (got {lc})")
            cmd = f"00DC{record_int:02X}04{lc:02X}{cleaned_hex}"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90:
                print(
                    f"{Config.Colors.GREEN}[+] Record {record_int} Update Successful.{Config.Colors.ENDC}"
                )
            else:
                print(
                    f"{Config.Colors.FAIL}[-] Update Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                )
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Update Error: {e}{Config.Colors.ENDC}")

    def scan_tree(self, return_tree: bool = False):
        # ``return_tree`` is opt-in. The CLI path (False) is byte-identical
        # to the historical behaviour: print the tree, populate
        # ``self.scan_cache``, return None. The GUI / Command Center path
        # (True) additionally materialises a nested structure describing
        # every resolved node so the frontend can render a clickable tree
        # without re-parsing coloured stdout.
        """Traverse the FID tree defined in fids.txt and decode each file; populates ``scan_cache``."""
        self._reset_before_scan("scan")
        print(
            f"{Config.Colors.HEADER}[*] Auditing File System (Live)...{Config.Colors.ENDC}"
        )

        file_exists = os.path.exists(Config.FIDS_FILE)
        if not file_exists:
            print(f"{Config.Colors.FAIL}fids.txt missing{Config.Colors.ENDC}")
            if return_tree:
                return {"tree": [], "scan_cache": {}}
            return

        roots = self._load_tree_structure()
        live_app_entries = self._discover_ef_dir_applications()
        self._cache_ef_dir_aliases(live_app_entries)
        self._persist_ef_dir_discoveries(live_app_entries)
        self._merge_live_apps_into_scan_tree(roots, live_app_entries)
        _had_explicit_mf_root, render_roots = self._split_scan_root_nodes(roots)
        self.scan_cache = {}
        scan_counter = [0]
        tree_nodes: List[Dict[str, Any]] = []

        def live_scan(nodes, parent_fid, parent_path, level=0, collect_into=None):
            """Perform a live scan of the current DF, reading file headers and returning a summary list."""
            for node in nodes:
                self._select_parent_for_live_traversal(parent_fid)
                selected_fid = None

                has_wildcard = False
                for f in node["fids"]:
                    if "X" in f:
                        has_wildcard = True
                if has_wildcard:
                    continue

                for fid in node["fids"]:
                    data, sw1, sw2 = self._select_for_live_traversal(parent_fid, fid)

                    if self._is_successful_select_response(sw1, data):
                        selected_fid = fid
                        break

                if selected_fid:
                    scan_counter[0] += 1
                    idx = str(scan_counter[0])

                    path_name = str(node.get("path_name", node["name"])).strip().upper()
                    if len(path_name) == 0:
                        path_name = str(node["name"]).strip().upper()

                    # ADF roots are reached via SELECT BY AID, so the
                    # path-walk branch in select() resolves them through the
                    # aid_registry -- they must NOT carry an "MF/" prefix.
                    # Detect them by selected_fid being a long AID (>4 hex
                    # chars) and the node sitting at the top level (level==1
                    # because the root MF is level 0 and is added separately
                    # below). For non-ADF top-level entries (DFs and EFs
                    # under MF) we keep the "MF/" prefix so select()'s
                    # path-walk branch fires and pre-selects MF first.
                    is_adf_root = False
                    if level == 1 and len(str(selected_fid)) > 4:
                        is_adf_root = True

                    if is_adf_root:
                        current_path = path_name
                    elif parent_path != "":
                        current_path = f"{parent_path}/{path_name}"
                    else:
                        current_path = path_name

                    self.scan_cache[idx] = current_path

                    connector = ""
                    if level > 0:
                        connector = "└── "

                    indent = "    " * level
                    display_name = str(node.get("display_name", node["name"])).strip()
                    if len(display_name) == 0:
                        display_name = str(node["name"]).strip().upper()
                    print(
                        f"{indent}{connector}[{Config.Colors.YELLOW}{idx}{Config.Colors.ENDC}] {Config.Colors.GREEN}{display_name}{Config.Colors.ENDC} ({selected_fid})"
                    )

                    child_collector = None
                    if collect_into is not None:
                        node_name_upper = str(node["name"]).strip().upper()
                        entry = {
                            "idx": idx,
                            "fid": selected_fid,
                            "name": node_name_upper,
                            "display_name": display_name,
                            "path": current_path,
                            "level": level,
                            "kind": self._classify_tree_node_kind(
                                node_name_upper,
                                has_children=bool(node.get("children")),
                            ),
                            "children": [],
                        }
                        collect_into.append(entry)
                        child_collector = entry["children"]

                    if node["children"]:
                        live_scan(
                            node["children"],
                            selected_fid,
                            current_path,
                            level + 1,
                            collect_into=child_collector,
                        )

        root_collector = tree_nodes if return_tree else None

        try:
            self.tp.transmit("00A40004023F00", silent=True)
            scan_counter[0] += 1
            root_index = str(scan_counter[0])
            self.scan_cache[root_index] = "MF"
            print(
                f"[{Config.Colors.YELLOW}{root_index}{Config.Colors.ENDC}] {Config.Colors.GREEN}MF{Config.Colors.ENDC} (3F00)"
            )
            if root_collector is not None:
                root_entry = {
                    "idx": root_index,
                    "fid": "3F00",
                    "name": "MF",
                    "display_name": "MF",
                    "path": "MF",
                    "level": 0,
                    "kind": "mf",
                    "children": [],
                }
                root_collector.append(root_entry)
                child_sink = root_entry["children"]
            else:
                child_sink = None
            # Seed traversal with parent_path="MF" so non-ADF top-level
            # entries (DFs/EFs directly under MF) come through as
            # "MF/<name>". Their slash forces select() into the path-walk
            # branch, which pre-selects MF first -- guaranteeing GUI clicks
            # on EFs under MF resolve regardless of which ADF is currently
            # selected. ADF roots are exempted inside live_scan above so
            # they keep their bare alias path (e.g. "USIM", "SSIM") which
            # the AID registry resolves via SELECT BY AID.
            live_scan(render_roots, "3F00", "MF", 1, collect_into=child_sink)
        finally:
            self.tp.transmit("00A40004023F00", silent=True)
            self.current_fid = "3F00"
            print(
                f"\n{Config.Colors.CYAN}Scan complete. Use 'SELECT <ID>' to navigate.{Config.Colors.ENDC}"
            )

        if return_tree:
            return {"tree": tree_nodes, "scan_cache": dict(self.scan_cache)}
        return None

    def _sanitize_yaml(self, data):
        if data is None:
            return None

        if isinstance(data, (bytes, bytearray, memoryview)):
            if hasattr(data, "hex"):
                return data.hex().upper()
            return bytes(data).hex().upper()

        if isinstance(data, str):
            return str(data)

        if isinstance(data, (int, float, bool)):
            return data

        is_dict = False
        if isinstance(data, dict):
            is_dict = True
        if hasattr(data, "items"):
            is_dict = True

        if is_dict:
            clean_dict = {}
            for k, v in data.items():
                if v is not None:
                    clean_dict[str(k)] = self._sanitize_yaml(v)
            return clean_dict

        if isinstance(data, (list, tuple)):
            clean_list = []
            for v in data:
                clean_list.append(self._sanitize_yaml(v))
            return clean_list

        return str(data)

    def generate_report(self, filename: str = "scan_report.yaml"):
        """Perform a deep card scan and write the full decoded file-system to a YAML report file."""
        self._reset_before_scan("report generation")
        print(
            f"{Config.Colors.HEADER}[*] Generating Deep Report to {filename}...{Config.Colors.ENDC}"
        )
        if not os.path.exists(Config.FIDS_FILE):
            print(f"{Config.Colors.FAIL}fids.txt missing{Config.Colors.ENDC}")
            return

        roots = self._load_tree_structure()
        live_app_entries = self._discover_ef_dir_applications()
        self._cache_ef_dir_aliases(live_app_entries)
        self._persist_ef_dir_discoveries(live_app_entries)
        self._merge_live_apps_into_scan_tree(roots, live_app_entries)
        report_data = {}

        def extract_file_content(fid, context_path):
            """Extract and return the raw content bytes of the currently selected EF."""
            content = {}
            struct = self.current_fcp.get("structure", "Unknown")
            if struct == "Transparent":
                data, sw1, sw2 = self._read_binary_full()
                if sw1 == 0x90:
                    hex_data = data.hex().upper()
                    if not all(c == "F" for c in hex_data) and not all(
                        c == "0" for c in hex_data
                    ):
                        content["hex"] = hex_data
                        decoded = ContentDecoder.decode_obj(
                            fid, hex_data, context_path=context_path
                        )
                        if decoded:
                            content["decoded"] = self._sanitize_yaml(decoded)
            elif struct in ["Linear Fixed", "Cyclic"]:
                records = {}
                le = f"{self.current_fcp.get('rec_len', 0):02X}"
                for r in range(1, self._record_scan_limit() + 1):
                    cmd = f"00B2{r:02X}04{le}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
                    if sw1 == 0x90:
                        hex_data = data.hex().upper()
                        if all(c == "F" for c in hex_data) or all(
                            c == "0" for c in hex_data
                        ):
                            continue
                        rec_data = {"hex": hex_data}
                        decoded = ContentDecoder.decode_obj(
                            fid, hex_data, context_path=context_path
                        )
                        if decoded:
                            rec_data["decoded"] = self._sanitize_yaml(decoded)
                        records[r] = rec_data
                    elif (sw1, sw2) == (0x6A, 0x83):
                        break
                    else:
                        break
                if records:
                    content["records"] = records
            return content if content else None

        def deep_scan(nodes, parent_fid, parent_path_list):
            """Perform a deep recursive scan of the file system tree from the current DF."""
            processed_fids = set()
            explicit_nodes = [n for n in nodes if not any("X" in f for f in n["fids"])]
            wildcard_nodes = [n for n in nodes if any("X" in f for f in n["fids"])]

            for node in explicit_nodes:
                p_data, p_sw1, p_sw2 = self._select_parent_for_live_traversal(
                    parent_fid
                )
                selected_fid = None
                data = None

                is_root_self = False
                if len(node["fids"]) > 0:
                    first_fid = node["fids"][0]
                    if first_fid == parent_fid:
                        is_root_self = True
                if is_root_self:
                    parent_ok = False
                    if self._is_successful_select_response(p_sw1, p_data):
                        parent_ok = True
                    if parent_ok:
                        selected_fid = parent_fid
                        data = p_data

                for fid in node["fids"]:
                    if selected_fid is not None:
                        break
                    data, sw1, sw2 = self._select_for_live_traversal(parent_fid, fid)
                    if self._is_successful_select_response(sw1, data):
                        selected_fid = fid
                        break

                if selected_fid:
                    processed_fids.add(selected_fid)
                    self.current_fid = selected_fid
                    self._parse_fcp_internal(data, target_fid=selected_fid)

                    path = "/".join(parent_path_list + [node["name"]])
                    print(f"  > Scanning: {path}")
                    self.current_path_hint = path
                    file_entry = {
                        "fid": selected_fid,
                        "name": node["name"],
                        "meta": self.current_fcp.copy(),
                    }

                    if self.current_fcp.get("type") == "EF":
                        content = extract_file_content(selected_fid, path)
                        if content:
                            file_entry.update(content)

                    report_data[path] = file_entry
                    notify_cb = getattr(self, "_report_scan_progress_cb", None)
                    if notify_cb is not None:
                        try:
                            notify_cb(path)
                        except Exception:
                            pass
                    if node["children"]:
                        deep_scan(
                            node["children"],
                            selected_fid,
                            parent_path_list + [node["name"]],
                        )
                else:
                    path = "/".join(parent_path_list + [node["name"]])
                    print(f"  [-] Skipped: {path} (None of {node['fids']} found)")

            for wc in wildcard_nodes:
                template = wc["fids"][0]
                prefix = template.replace("X", "")
                for i in range(256):
                    target_fid = f"{prefix}{i:02X}"
                    if target_fid in processed_fids:
                        continue

                    self._select_parent_for_live_traversal(parent_fid)

                    cmd = f"00A4000402{target_fid}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)

                    if self._is_successful_select_response(sw1, data):
                        self.current_fid = target_fid
                        self._parse_fcp_internal(data, target_fid=target_fid)

                        name = self._persist_dynamic_fid_discovery(
                            parent_path_list, target_fid
                        )
                        path = "/".join(parent_path_list + [name])
                        print(f"  > Found Wildcard: {path}")
                        self.current_path_hint = path
                        file_entry = {
                            "fid": target_fid,
                            "name": name,
                            "meta": self.current_fcp.copy(),
                        }
                        if self.current_fcp.get("type") == "EF":
                            content = extract_file_content(target_fid, path)
                            if content:
                                file_entry.update(content)
                        report_data[path] = file_entry
                        notify_cb = getattr(self, "_report_scan_progress_cb", None)
                        if notify_cb is not None:
                            try:
                                notify_cb(path)
                            except Exception:
                                pass

        try:
            self.tp.transmit("00A40004023F00", silent=True)
            # Deep report scan has unknown final length until the
            # live tree finishes resolving wildcards -- sticky footer
            # runs indeterminate and updates from deep_scan whenever
            # an EF is persisted into ``report_data``.
            with progress_session("FS YAML report") as bar:
                scan_counter = {"value": 0}

                def _notify_report_entry(scan_path: str) -> None:
                    scan_counter["value"] = scan_counter["value"] + 1
                    bar.set_status(
                        f"{scan_counter['value']} entr(y/ies) scanned · {scan_path}"
                    )

                self._report_scan_progress_cb = _notify_report_entry
                try:
                    deep_scan(roots, "3F00", [])
                finally:
                    self._report_scan_progress_cb = None
            clean_data = self._sanitize_yaml(report_data)
            with open(filename, "w", encoding="utf-8") as outfile:
                yaml.dump(
                    clean_data, outfile, default_flow_style=False, sort_keys=False
                )
            print(
                f"{Config.Colors.GREEN}[+] Report saved to {filename}{Config.Colors.ENDC}"
            )
        except Exception as e:
            print(
                f"{Config.Colors.FAIL}[!] Report Generation Failed: {e}{Config.Colors.ENDC}"
            )
        finally:
            self.tp.transmit("00A40004023F00", silent=True)
            self.current_fid = "3F00"

    def dump_fs_to_yaml(self, filename: str = "fs_report.yaml"):
        """
        Backward-compatible wrapper used by REPORT wizards.
        Produces a full deep file system YAML report.
        """
        self.generate_report(filename)

    def _reset_before_scan(self, operation_name: str) -> None:
        print(
            f"{Config.Colors.WARNING}[*] Resetting card before file system {operation_name}...{Config.Colors.ENDC}"
        )
        reset_ok = self.tp.reset()
        if self.tp.session:
            self.tp.reset_session_state()
        if reset_ok:
            print(f"{Config.Colors.GREEN}[+] Reset Successful.{Config.Colors.ENDC}")
        if not reset_ok:
            print(
                f"{Config.Colors.WARNING}[!] Reset failed. Continuing with best effort traversal.{Config.Colors.ENDC}"
            )

    def _get_live_iccid(self) -> str:
        self.tp.transmit("00A40004023F00", silent=True)
        data, sw1, sw2 = self.tp.transmit("00A40004022FE2", silent=True)

        valid_select = False
        if sw1 == 0x90:
            valid_select = True
        if sw1 == 0x61:
            valid_select = True
        if sw1 == 0x9F:
            valid_select = True

        if not valid_select:
            return "UNKNOWN_ICCID"

        data, sw1, sw2 = self.tp.transmit("00B000000A", silent=True)
        valid_read = False
        if sw1 == 0x90:
            valid_read = True
        if len(bytes(data or b"")) > 0:
            if sw1 == 0x62:
                valid_read = True
            if sw1 == 0x63:
                valid_read = True
        if not valid_read:
            return "UNKNOWN_ICCID"

        hex_str = data.hex().upper()
        remainder = len(hex_str) % 2

        if remainder != 0:
            hex_str = hex_str + "F"

        decoded_iccid = ""
        for i in range(0, len(hex_str), 2):
            nibble1 = hex_str[i]
            nibble2 = hex_str[i + 1]
            decoded_iccid += nibble2 + nibble1

        return decoded_iccid.rstrip("F")

    def dump_live_fs(self, output_dir: str):
        """Read every EF in the current file system and write the raw hex content to *output_dir* as individual files."""
        import shutil
        from pathlib import Path
        import yaml

        print(
            f"{Config.Colors.HEADER}[*] Initiating Deep Live File System Dump...{Config.Colors.ENDC}"
        )

        file_exists = os.path.exists(Config.FIDS_FILE)
        if not file_exists:
            print(
                f"{Config.Colors.FAIL}fids.txt missing. Tree navigation impossible.{Config.Colors.ENDC}"
            )
            return

        iccid_val = self._get_live_iccid()
        root_dir = Path(output_dir).resolve() / iccid_val

        dir_exists = root_dir.exists()
        if dir_exists:
            shutil.rmtree(root_dir)

        root_dir.mkdir(parents=True, exist_ok=True)
        roots = self._load_tree_structure()
        live_app_entries = self._discover_ef_dir_applications()
        self._cache_ef_dir_aliases(live_app_entries)
        self._persist_ef_dir_discoveries(live_app_entries)
        self._merge_live_apps_into_scan_tree(roots, live_app_entries)

        def _write_ef_content(fid: str, file_path_base: Path):
            struct = self.current_fcp.get("structure", "Unknown")
            content_file = file_path_base.with_suffix(".txt")

            with open(content_file, "w", encoding="utf-8") as f:
                f.write("--- File Metadata ---\n")
                f.write(f"FID: {fid}\n")
                f.write(f"Type: {self.current_fcp.get('type')} ({struct})\n\n")
                f.write("--- FCP Data ---\n")
                yaml.dump(
                    self._sanitize_yaml(self.current_fcp),
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                )
                f.write("\n--- File Data ---\n")

                if struct == "Transparent":
                    data, sw1, sw2 = self._read_binary_full()
                    if sw1 == 0x90:
                        hex_data = data.hex().upper()
                        f.write(f"Raw: {hex_data}\n")
                        decoded = ContentDecoder.decode_obj(
                            fid, hex_data, context_path=self.current_path_hint
                        )
                        if decoded:
                            yaml.dump(
                                self._sanitize_yaml(decoded),
                                f,
                                default_flow_style=False,
                                sort_keys=False,
                            )
                    if sw1 != 0x90:
                        f.write(f"Read Error: {sw1:02X}{sw2:02X}\n")

                if struct == "Linear Fixed":
                    _read_records(fid, f)

                if struct == "Cyclic":
                    _read_records(fid, f)

        def _read_records(fid: str, file_handle):
            le = f"{self.current_fcp.get('rec_len', 0):02X}"
            for r in range(1, self._record_scan_limit() + 1):
                cmd = f"00B2{r:02X}04{le}"
                data, sw1, sw2 = self.tp.transmit(cmd, silent=True)

                if sw1 == 0x90:
                    hex_data = data.hex().upper()
                    file_handle.write(f"Record {r:02X}: Raw: {hex_data}\n")
                    decoded = ContentDecoder.decode_obj(
                        fid, hex_data, context_path=self.current_path_hint
                    )
                    if decoded:
                        yaml.dump(
                            self._sanitize_yaml(decoded),
                            file_handle,
                            default_flow_style=False,
                            sort_keys=False,
                        )
                        file_handle.write("\n")

                if (sw1, sw2) == (0x6A, 0x83):
                    break
                if sw1 != 0x90:
                    break

        def _live_deep_scan(
            nodes, parent_fid, current_path: Path, parent_path_tokens: List[str]
        ):
            processed_fids = set()

            explicit_nodes = []
            for n in nodes:
                has_wildcard = False
                for f in n["fids"]:
                    if "X" in f:
                        has_wildcard = True
                if not has_wildcard:
                    explicit_nodes.append(n)

            wildcard_nodes = []
            for n in nodes:
                has_wildcard = False
                for f in n["fids"]:
                    if "X" in f:
                        has_wildcard = True
                if has_wildcard:
                    wildcard_nodes.append(n)

            for node in explicit_nodes:
                p_data, p_sw1, p_sw2 = self._select_parent_for_live_traversal(
                    parent_fid
                )

                selected_fid = None
                last_data = None

                is_root_self = False
                if len(node["fids"]) > 0:
                    first_fid = node["fids"][0]
                    if first_fid == parent_fid:
                        is_root_self = True
                if is_root_self:
                    parent_ok = False
                    if self._is_successful_select_response(p_sw1, p_data):
                        parent_ok = True
                    if parent_ok:
                        selected_fid = parent_fid
                        last_data = p_data

                for fid in node["fids"]:
                    if selected_fid is not None:
                        break
                    data, sw1, sw2 = self._select_for_live_traversal(parent_fid, fid)

                    if self._is_successful_select_response(sw1, data):
                        selected_fid = fid
                        last_data = data
                        break

                if selected_fid:
                    processed_fids.add(selected_fid)
                    self.current_fid = selected_fid
                    self._parse_fcp_internal(last_data, target_fid=selected_fid)

                    node_dir = current_path
                    if self.current_fcp.get("type") == "DF":
                        node_dir = current_path / node["name"]
                        node_dir.mkdir(parents=True, exist_ok=True)

                    if self.current_fcp.get("type") == "EF":
                        file_base = current_path / node["name"]
                        print(f"  > Dumping: {file_base}")
                        self.current_path_hint = str(file_base)
                        _write_ef_content(selected_fid, file_base)
                        notify_cb = getattr(self, "_progress_notify_ef", None)
                        if notify_cb is not None:
                            try:
                                notify_cb(file_base, False)
                            except Exception:
                                pass

                    if node["children"]:
                        _live_deep_scan(
                            node["children"],
                            selected_fid,
                            node_dir,
                            parent_path_tokens + [node["name"]],
                        )

            for wc in wildcard_nodes:
                template = wc["fids"][0]
                prefix = template.replace("X", "")

                for i in range(256):
                    target_fid = f"{prefix}{i:02X}"

                    is_processed = False
                    if target_fid in processed_fids:
                        is_processed = True
                    if is_processed:
                        continue

                    self._select_parent_for_live_traversal(parent_fid)

                    cmd = f"00A4000402{target_fid}"
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=True)

                    if self._is_successful_select_response(sw1, data):
                        self.current_fid = target_fid
                        self._parse_fcp_internal(data, target_fid=target_fid)

                        name = self._persist_dynamic_fid_discovery(
                            parent_path_tokens, target_fid
                        )
                        file_base = current_path / name
                        print(f"  > Found & Dumping Wildcard: {file_base}")
                        self.current_path_hint = str(file_base)

                        if self.current_fcp.get("type") == "EF":
                            _write_ef_content(target_fid, file_base)
                            notify_cb = getattr(self, "_progress_notify_ef", None)
                            if notify_cb is not None:
                                try:
                                    notify_cb(file_base, True)
                                except Exception:
                                    pass

        try:
            self.tp.transmit("00A40004023F00", silent=True)
            # The live tree grows as wildcards resolve, so the total
            # EF count is unknown up front -- run the footer in
            # indeterminate mode and surface the resolved-file count
            # as the status label. Inactive on non-TTY surfaces so
            # scripted dumps stay byte-identical to their baseline.
            with progress_session("FS dump") as bar:
                ef_counter = {"value": 0}

                def _notify_ef(file_base: Path, is_wildcard: bool) -> None:
                    ef_counter["value"] = ef_counter["value"] + 1
                    suffix = "wildcard" if is_wildcard else "explicit"
                    bar.set_status(
                        f"{ef_counter['value']} EF(s) dumped · {file_base.name} ({suffix})"
                    )

                self._progress_notify_ef = _notify_ef
                try:
                    _live_deep_scan(roots, "3F00", root_dir, [])
                finally:
                    self._progress_notify_ef = None
            print(
                f"{Config.Colors.GREEN}[+] Live dump complete. Output saved to {root_dir}{Config.Colors.ENDC}"
            )
        except Exception as e:
            print(
                f"{Config.Colors.FAIL}[!] Dump Execution Failed: {e}{Config.Colors.ENDC}"
            )
        finally:
            self.tp.transmit("00A40004023F00", silent=True)
            self.current_fid = "3F00"

    def activate_file(self, fid: str = "") -> None:
        """TS 102 221: Activate File (0044)."""
        apdu = "00440000"
        has_fid = False
        if len(fid) > 0:
            has_fid = True

        if has_fid:
            apdu = f"0044000002{fid}"

        self.tp.transmit(apdu)

    def deactivate_file(self, fid: str = "") -> None:
        """TS 102 221: Deactivate File (0004)."""
        apdu = "00040000"
        has_fid = False
        if len(fid) > 0:
            has_fid = True

        if has_fid:
            apdu = f"0004000002{fid}"

        self.tp.transmit(apdu)

    @staticmethod
    def _suspend_duration_bytes(value: str, label: str) -> bytes:
        """Validate a SUSPEND UICC duration: time unit byte followed by a count.

        Units are 0 seconds, 1 minutes, 2 hours, 3 days, 4 ten-day periods
        (TS 102 221 v18.4 §11.1.22.2.3).
        """
        clean = str(value or "").strip().replace(" ", "").upper()
        try:
            raw = bytes.fromhex(clean)
        except ValueError as error:
            raise ValueError(f"{label} duration must be 4 hex digits.") from error
        if len(raw) != 2:
            raise ValueError(f"{label} duration must be 2 bytes (unit, count).")
        if raw[0] > 0x04:
            raise ValueError(f"{label} duration unit {raw[0]:02X} is not defined (00..04).")
        return raw

    def suspend_uicc(
        self,
        min_duration_hex: str = "0001",
        max_duration_hex: str = "0201",
    ) -> Tuple[bytes, int, int]:
        """SUSPEND UICC, P1 = '00' (TS 102 221 v18.4 §11.1.22.2.3).

        The data field is the minimum and maximum suspension duration the
        terminal proposes (2 + 2 bytes) and Le is '0A': the card answers with
        the negotiated maximum duration and an 8-byte resume token. The
        defaults propose one second to one hour.
        """
        minimum = self._suspend_duration_bytes(min_duration_hex, "Minimum")
        maximum = self._suspend_duration_bytes(max_duration_hex, "Maximum")
        apdu = f"8076000004{minimum.hex().upper()}{maximum.hex().upper()}0A"
        data, sw1, sw2 = self.tp.transmit(apdu)
        payload = bytes(data or b"")
        if sw1 == 0x90 and len(payload) >= 10:
            print(
                f"    [Duration] unit {payload[0]:02X}, count {payload[1]}"
                f"    [Token] {payload[2:10].hex().upper()}"
            )
        return payload, sw1, sw2

    def resume_uicc(self, resume_token_hex: str) -> Tuple[bytes, int, int]:
        """SUSPEND UICC, P1 = '01' (TS 102 221 v18.4 §11.1.22.3.3): Lc '08', the resume token."""
        clean = str(resume_token_hex or "").strip().replace(" ", "").upper()
        token = bytes.fromhex(clean)
        if len(token) != 8:
            raise ValueError("resume token must be 8 bytes.")
        return self.tp.transmit(f"8076010008{token.hex().upper()}")

    @staticmethod
    def _build_case3_apdu(header_hex: str, data_hex: str, label: str) -> str:
        """Build a short or extended ISO/IEC 7816 case-3 command APDU."""
        header = str(header_hex or "").strip().replace(" ", "").upper()
        if len(header) != 8:
            raise ValueError(f"{label} APDU header must be exactly four bytes.")
        try:
            bytes.fromhex(header)
        except ValueError as error:
            raise ValueError(
                f"{label} APDU header contains invalid hexadecimal data."
            ) from error

        data = str(data_hex or "").strip().replace(" ", "").replace(":", "")
        if data.lower().startswith("0x"):
            data = data[2:]
        if len(data) == 0:
            raise ValueError(f"{label} data cannot be empty.")
        if len(data) % 2 != 0:
            raise ValueError(f"{label} data must contain an even number of hex digits.")
        try:
            data_bytes = bytes.fromhex(data)
        except ValueError as error:
            raise ValueError(
                f"{label} data contains invalid hexadecimal data."
            ) from error

        data_len = len(data_bytes)
        if data_len <= 0xFF:
            lc = f"{data_len:02X}"
        elif data_len <= 0xFFFF:
            lc = f"00{data_len:04X}"
        else:
            raise ValueError(f"{label} data exceeds the 65535-byte APDU limit.")
        return f"{header}{lc}{data_bytes.hex().upper()}"

    @classmethod
    def _build_case4_apdu(cls, header_hex: str, data_hex: str, label: str) -> str:
        """Append the Le of a case-4 command to the case-3 form of the same APDU.

        ISO/IEC 7816-4 pairs a three-byte extended Lc with a two-byte Le and
        a one-byte Lc with a one-byte Le; '00' and '00 00' both ask for the
        maximum response length. ``_build_case3_apdu`` rejects an empty data
        field, so a leading Lc digit pair of '00' can only be the extended
        form.
        """
        command = cls._build_case3_apdu(header_hex, data_hex, label)
        if command[8:10] == "00":
            return command + "0000"
        return command + "00"

    def search_record(self, search_hex: str) -> None:
        """SEARCH RECORD (TS 102 221 v18.4 §11.1.7.1, §11.1.7.2).

        P1 '01' / P2 '04' is a simple forward search from record 1 in the
        current EF (table 11.12). The command carries an Le, because
        §11.1.7.1 returns "at most the number of record(s) number(s) defined
        in Le" and the §11.1.7.2 response table notes that no record numbers
        come back when Le is empty.
        """
        apdu = self._build_case4_apdu("00A20104", search_hex, "SEARCH RECORD")
        data, sw1, sw2 = self.tp.transmit(apdu)
        self._print_search_record_matches(bytes(data or b""), sw1, sw2)

    @staticmethod
    def _print_search_record_matches(data: bytes, sw1: int, sw2: int) -> None:
        """Report the record numbers of a SEARCH RECORD response (§11.1.7.1)."""
        if sw1 != 0x90 and (sw1, sw2) != (0x62, 0x82):
            print(
                f"{Config.Colors.FAIL}[-] SEARCH RECORD failed: "
                f"{sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return
        if len(data) == 0:
            # §11.1.7.1: no match answers '90 00' or the warning '62 82'.
            print(
                f"{Config.Colors.WARNING}[*] SEARCH RECORD: no record matched."
                f"{Config.Colors.ENDC}"
            )
            return
        numbers = ", ".join(str(record_number) for record_number in data)
        print(
            f"{Config.Colors.GREEN}[+] SEARCH RECORD matched record(s): "
            f"{numbers}{Config.Colors.ENDC}"
        )

    def create_file(self, data_hex: str) -> None:
        """TS 102 222: Create File (00E0)."""
        apdu = self._build_case3_apdu("00E00000", data_hex, "CREATE FILE")
        self.tp.transmit(apdu)

    def delete_file(self, fid: str) -> None:
        """TS 102 222: Delete File (00E4)."""
        apdu = f"00E4000002{fid}"
        self.tp.transmit(apdu)

    def terminate_df(self, fid: str = "") -> None:
        """TERMINATE DF (TS 102 222 v17.1 §6.7.2, table 10).

        INS 'E6', P1 = P2 = '00' and no data field: the command acts on the
        currently selected DF/ADF, so a target given here is selected first.
        """
        target = str(fid or "").strip()
        if len(target) > 0:
            if not self.select(target, silent=True):
                print(f"{Config.Colors.FAIL}[-] TERMINATE DF: could not select {target}.{Config.Colors.ENDC}")
                return
        self.tp.transmit("00E60000")

    def terminate_ef(self, fid: str = "") -> None:
        """TERMINATE EF (TS 102 222 v17.1 §6.8.2, table 12).

        INS 'E8', P1 = P2 = '00' and no data field: the command acts on the
        currently selected EF, so a target given here is selected first.
        """
        target = str(fid or "").strip()
        if len(target) > 0:
            if not self.select(target, silent=True):
                print(f"{Config.Colors.FAIL}[-] TERMINATE EF: could not select {target}.{Config.Colors.ENDC}")
                return
        self.tp.transmit("00E80000")

    # TS 102 222 v17.1 §6.10.2.0 table 16a codes P1 for a BER-TLV structured
    # EF: '00' Mode 0, '01' Mode 1, any other value RFU. §6.10.2.1 tag '86'
    # says what they decide when the New Maximum File Size is smaller than
    # the size the existing TLV objects use: Mode 0 deletes every object and
    # assigns the new size, Mode 1 performs no action and returns '6985'.
    RESIZE_FILE_MODE_0 = 0x00
    RESIZE_FILE_MODE_1 = 0x01

    def resize_file(self, data_hex: str, mode: int = RESIZE_FILE_MODE_0) -> None:
        """RESIZE FILE (TS 102 222 v17.1 §6.10.2, INS 'D4').

        *mode* is P1 per table 16a. Table 16a applies to a BER-TLV structured
        EF; for every other file type the same clause requires P1 '00', which
        is the default here.
        """
        mode_byte = int(mode)
        if mode_byte not in (self.RESIZE_FILE_MODE_0, self.RESIZE_FILE_MODE_1):
            raise ValueError(
                "RESIZE FILE mode must be 0 or 1; every other P1 value is RFU "
                "(TS 102 222 v17.1 §6.10.2.0 table 16a)."
            )
        apdu = self._build_case3_apdu(f"80D4{mode_byte:02X}00", data_hex, "RESIZE FILE")
        self.tp.transmit(apdu)
