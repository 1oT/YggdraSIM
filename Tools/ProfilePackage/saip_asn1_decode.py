"""
Pure-Python ASN.1 / TLV decode helpers for tagged SAIP JSON.

This backend is used by the TRANSCODE-TUI inspector and intentionally avoids
imports from ``SCP03`` and ``pySim``. It combines:

- generic BER/DER decoding with universal ASN.1 type rendering,
- selected SAIP field decoders for BER-TLV payloads,
- common UICC EF payload decoders for transparent file content.
"""

from __future__ import annotations

from datetime import datetime
import ipaddress
import re
from typing import Any, Callable

from Tools.ProfilePackage.saip_json_codec import (
    _LEGACY_TAG_BYTES,
    _LEGACY_TAG_TUPLE,
    _TAG_BYTES,
    _TAG_TUPLE,
    _structural_data_keys,
    _value_first,
    base_pe_type,
)

ValueDecoder = Callable[[bytes], object | None]

_EF_KEY_TO_FID: dict[str, str] = {
    "ef-iccid": "2FE2",
    "ef-dir": "2F00",
    "ef-pl": "2F05",
    "ef-imsi": "6F07",
    "ef-ad": "6FAD",
    "ef-msisdn": "6F40",
    "ef-spn": "6F46",
    "ef-ust": "6F38",
    "ef-ust-service-table": "6F38",
    "ef-acc": "6F78",
    "ef-loci": "6F7E",
    "ef-psloci": "6F73",
    "ef-epsloci": "6FE3",
    "ef-plmnwact": "6F60",
    "ef-oplmnwact": "6F61",
    "ef-hplmnwact": "6F62",
    "ef-fplmn": "6F7B",
    "ef-gid1": "6F3E",
    "ef-gid2": "6F3F",
    "ef-smsp": "6F42",
    "ef-smss": "6F43",
    "ef-sms": "6F3C",
    "ef-cbmi": "6F45",
    "ef-cbmir": "6F50",
    "ef-cbmid": "6F48",
    "ef-sume": "6F5B",
    "ef-s7": "6F5C",
    "ef-li": "6F05",
    "ef-acmax": "6F37",
    "ef-acm": "6F39",
    "ef-ecc": "6FB7",
    "ef-adn": "6F3A",
    "ef-fdn": "6F3B",
    "ef-sdn": "6F49",
    "ef-lnd": "6F44",
    "ef-pnn": "6FC5",
    "ef-opl": "6FC6",
    "ef-spdi": "6FCD",
    "ef-epsnsc": "6FE4",
    "ef-gbanl": "6FDA",
    "ef-nafkca": "6FDD",
    "ef-keysPS": "6F09",
    "ef-pcscf": "6F09",
    "ef-suci-calc-info-usim": "4F01",
    "ef-supinai": "4F09",
}

_UNIVERSAL_TAG_NAMES: dict[int, str] = {
    0: "EOC",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    30: "BMPString",
}

_UST_SERVICE_NAMES: dict[int, str] = {
    1: "Local Phone Book",
    2: "FDN",
    3: "Extension 2",
    4: "SDN",
    5: "Extension 3",
    6: "SMS",
    7: "BDN",
    8: "OCI",
    9: "ICI",
    10: "SMS-PP Download",
    11: "SMS-CB Download",
    12: "Call Control by USIM",
    13: "MO-SMS Control",
    14: "RUN AT COMMAND",
    15: "Ignored",
    16: "Enabled Services Table",
    17: "ACL",
    18: "Depersonalisation Keys",
    19: "Co-operative Network List",
    20: "GSM Access",
    21: "OPLMNwAcT",
    22: "LOCI",
    23: "PSLOCI",
    24: "SMSS",
    25: "SPN",
    26: "ECC",
    27: "MCC",
    28: "Extension 5",
    29: "HPLMNwAcT",
    30: "CPBCCH",
    31: "Investigation Scan",
    32: "MexE",
    33: "RPLMNAcT",
    34: "HPLMN",
    38: "Call Control on GPRS",
    39: "MMS",
    52: "GBA",
    57: "Equivalent HPLMN",
    58: "Terminal Profile",
    59: "EHPLMN PI",
    60: "Last RPLMN Selection Indication",
    71: "IPD URI",
    72: "ePDG Configuration (3GPP)",
    73: "ePDG Configuration (Non-3GPP)",
    74: "IMS Configuration Data",
    75: "3GPP PS Data Off",
    76: "3GPP PS Data Off Service List",
    77: "XCAP Configuration Data",
    78: "EARFCN List",
    79: "MuD and MiD configuration data",
    80: "EAKA",
    83: "IMS DCN information",
    85: "Support of UICC access to IMS",
    88: "5GS 3GPP LOCI",
    89: "5GS non-3GPP LOCI",
    90: "5GS 3GPP NSC",
    91: "5GS non-3GPP NSC",
    92: "5G authentication keys",
    93: "UAC access identities support",
    94: "SUCI calculation information",
    95: "Operator controlled PLMN selector for NG-RAN access",
    96: "SUPI NAI",
    97: "Routing Indicator",
    98: "URSP",
    99: "Trusted non-3GPP serving network names",
    100: "CAG information list",
    101: "SOR-CMCI",
    102: "DRI",
    103: "5G SE-DRX parameters",
    104: "5G NSWO configuration",
    105: "MCHPPLMN",
    106: "KAUSF derivation configuration",
    113: "5G parameters",
}

_PLMN_WITH_ACT_KEYS = {
    "ef-plmnwact",
    "ef-oplmnwact",
    "ef-hplmnwact",
}

_APPLICATION_PRIVILEGE_FLAGS = [
    (0x800000, "security_domain", "Security Domain"),
    (0x400000, "dap_verification", "DAP Verification"),
    (0x200000, "delegated_management", "Delegated Management"),
    (0x100000, "card_lock", "Card Lock"),
    (0x080000, "card_terminate", "Card Terminate"),
    (0x040000, "card_reset", "Card Reset"),
    (0x020000, "cvm_management", "CVM Management"),
    (0x010000, "mandated_dap_verification", "Mandated DAP Verification"),
    (0x008000, "trusted_path", "Trusted Path"),
    (0x004000, "authorized_management", "Authorized Management"),
    (0x002000, "token_management", "Token Management"),
    (0x001000, "global_delete", "Global Delete"),
    (0x000800, "global_lock", "Global Lock"),
    (0x000400, "global_registry", "Global Registry"),
    (0x000200, "final_application", "Final Application"),
    (0x000100, "global_service", "Global Service"),
    (0x000080, "receipt_generation", "Receipt Generation"),
    (0x000040, "ciphered_load_file_data_block", "Ciphered Load File Data Block"),
    (0x000020, "contactless_activation", "Contactless Activation"),
    (0x000010, "contactless_self_activation", "Contactless Self-Activation"),
]

_LIFE_CYCLE_STATE_NAMES = {
    0x01: "Loaded",
    0x03: "Installed",
    0x07: "Selectable",
    0x0F: "Personalized",
    0x83: "Locked",
}

_KEY_USAGE_FLAGS = [
    (0x8000, "verification_encryption", "Verification / Encryption"),
    (0x4000, "computation_decipherment", "Computation / Decipherment"),
    (0x2000, "sm_response", "Secure Messaging Response"),
    (0x1000, "sm_command", "Secure Messaging Command"),
    (0x0800, "confidentiality", "Confidentiality"),
    (0x0400, "crypto_checksum", "Cryptographic Checksum"),
    (0x0200, "digital_signature", "Digital Signature"),
    (0x0100, "crypto_authorization", "Cryptographic Authorization"),
    (0x0080, "key_agreement", "Key Agreement"),
]

_KEY_ACCESS_NAMES = {
    0x00: "Security Domain and any associated application",
    0x01: "Security Domain only",
    0x02: "Any associated application but not the Security Domain",
    0xFF: "Not available",
}

_KEY_ID_COMMON_ROLES = {
    0x01: "ENC (common SCP02/SCP03 convention)",
    0x02: "MAC (common SCP02/SCP03 convention)",
    0x03: "DEK (common SCP02/SCP03 convention)",
}

_KEY_TYPE_NAMES = {
    0x80: "DES",
    0x85: "TLS-PSK",
    0x88: "AES",
    0x90: "HMAC-SHA1",
    0x91: "HMAC-SHA1-160",
    0xA0: "RSA Public Exponent",
    0xA1: "RSA Modulus (cleartext)",
    0xA2: "RSA Modulus",
}


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _looks_like_hex(text: str) -> bool:
    stripped = str(text or "").strip().upper()
    if len(stripped) < 8:
        return False
    if len(stripped) % 2 != 0:
        return False
    return all(character in "0123456789ABCDEF" for character in stripped)


def _format_scalar(value: Any) -> str:
    if value is None:
        return "Present"
    if isinstance(value, bool):
        return "True" if value else "False"
    text = str(value).strip()
    if _looks_like_hex(text) and len(text) > 64:
        return f"{text[:32]}...{text[-24:]}"
    if len(text) > 120:
        return f"{text[:60]}...{text[-40:]}"
    return text


def _pad_key(name: str, key_width: int | None) -> str:
    if key_width is None:
        return name
    if len(name) >= key_width:
        return name
    return f"{name:<{key_width}}"


def _compute_key_width(value: dict[Any, Any]) -> int:
    width = 0
    for key in value.keys():
        width = max(width, len(str(key)))
    width = max(width, 18)
    width = min(width, 32)
    return width


def _format_block_header(name: str, indent: int, key_width: int | None = None) -> str:
    prefix = "  " * indent
    padded_name = _pad_key(name, key_width)
    return f"{prefix}| {padded_name}"


def _format_scalar_line(
    name: str | None,
    value: Any,
    indent: int,
    key_width: int | None = None,
) -> str:
    prefix = "  " * indent
    rendered_value = _format_scalar(value)
    if name is None:
        return f"{prefix}| {rendered_value}"
    padded_name = _pad_key(str(name), key_width)
    if key_width is None:
        return f"{prefix}| {padded_name:<28} : {rendered_value}"
    return f"{prefix}| {padded_name} : {rendered_value}"


def _format_inline_scalar_list(values: list[Any]) -> str | None:
    if len(values) == 0:
        return "[]"
    for value in values:
        if _is_scalar(value) is False:
            return None
    parts = [_format_scalar(value) for value in values[:8]]
    if len(values) > 8:
        parts.append(f"... (+{len(values) - 8})")
    text = ", ".join(parts)
    if len(text) > 120:
        text = text[:88] + "..."
    return f"[{text}]"


def _render_compact_value(
    value: Any,
    *,
    indent: int = 0,
    name: str | None = None,
    key_width: int | None = None,
) -> list[str]:
    if _is_scalar(value):
        return [_format_scalar_line(name, value, indent, key_width)]

    if isinstance(value, dict):
        if len(value) == 0:
            return [_format_scalar_line(name, "{}", indent, key_width)]
        lines: list[str] = []
        child_indent = indent
        if name is not None:
            lines.append(_format_block_header(name, indent, key_width))
            child_indent += 1
        child_width = _compute_key_width(value)
        for child_name, child_value in value.items():
            lines.extend(
                _render_compact_value(
                    child_value,
                    indent=child_indent,
                    name=str(child_name),
                    key_width=child_width,
                )
            )
        return lines

    if isinstance(value, list):
        inline = _format_inline_scalar_list(value)
        if inline is not None:
            return [_format_scalar_line(name, inline, indent, key_width)]
        if len(value) == 0:
            return [_format_scalar_line(name, "[]", indent, key_width)]
        lines = []
        child_indent = indent
        if name is not None:
            lines.append(_format_block_header(name, indent, key_width))
            child_indent += 1
        for index, item in enumerate(value):
            lines.extend(
                _render_compact_value(
                    item,
                    indent=child_indent,
                    name=f"[{index}]",
                )
            )
        return lines

    return [_format_scalar_line(name, repr(value), indent, key_width)]


def _compact_decode_lines(lines: list[str]) -> list[str]:
    compacted: list[str] = []
    pending_blank = False
    for raw_line in lines:
        line = str(raw_line).rstrip()
        if len(line) == 0:
            if len(compacted) == 0:
                continue
            pending_blank = True
            continue
        if pending_blank:
            compacted.append("")
            pending_blank = False
        compacted.append(line)
    while compacted and compacted[-1] == "":
        compacted.pop()
    return compacted


def _compact_block(title: str, payload: Any) -> list[str]:
    return [title, *_render_compact_value(payload, indent=1)]


def _format_hits(hits: list[tuple[str, list[str]]]) -> str:
    lines_out: list[str] = []
    for index, (title, chunk) in enumerate(hits):
        if index > 0:
            lines_out.append("")
        lines_out.append(f"[{title}]")
        lines_out.extend(_compact_decode_lines(chunk))
    return "\n".join(lines_out).rstrip() + "\n"


def _swap_nibbles(hex_text: str) -> str:
    compact = re.sub(r"\s+", "", str(hex_text or "")).upper()
    if len(compact) % 2 != 0:
        raise ValueError("hex string has odd length")
    swapped: list[str] = []
    for index in range(0, len(compact), 2):
        swapped.append(compact[index + 1] + compact[index])
    return "".join(swapped)


def _decode_printable_ascii(value_bytes: bytes) -> str | None:
    if len(value_bytes) == 0:
        return ""
    try:
        decoded = value_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None
    for character in decoded:
        if character < " " or character > "~":
            return None
    return decoded


def _looks_like_bcd_bytes(value_bytes: bytes) -> bool:
    if len(value_bytes) == 0:
        return False
    for byte_value in value_bytes:
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        if low > 9 and low != 0x0F:
            return False
        if high > 9 and high != 0x0F:
            return False
    return True


def _decode_bcd_digits(value_bytes: bytes) -> str:
    digits: list[str] = []
    for byte_value in value_bytes:
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        if low != 0x0F:
            digits.append(str(low))
        if high != 0x0F:
            digits.append(str(high))
    return "".join(digits)


def _hex_from_tagged_bytes(value: Any) -> str | None:
    if isinstance(value, dict) is False:
        return None
    if set(_structural_data_keys(value)) != {_TAG_BYTES}:
        return None
    text = str(_value_first(value, _TAG_BYTES, _LEGACY_TAG_BYTES)).strip()
    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[0-9A-Fa-f]*", compact) is None:
        return None
    if len(compact) % 2 != 0:
        return None
    return compact.upper()


def _hex_from_scalar_value(value: Any) -> str | None:
    if isinstance(value, str) is False:
        return None
    compact = re.sub(r"\s+", "", str(value or ""))
    if len(compact) == 0 or len(compact) % 2 != 0:
        return None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) is None:
        return None
    return compact.upper()


def _bytes_from_scalar_value(value: Any) -> bytes | None:
    hex_clean = _hex_from_scalar_value(value)
    if hex_clean is None:
        return None
    try:
        return bytes.fromhex(hex_clean)
    except ValueError:
        return None


def _summary_with_label(code: str, label: str | None) -> str:
    if label is None or label == "":
        return code
    return f"{code} ({label})"


def _summary_with_list(code: str, items: list[str], *, limit: int = 3) -> str:
    if len(items) == 0:
        return code
    preview = ", ".join(items[:limit])
    if len(items) > limit:
        preview += f", ... (+{len(items) - limit})"
    return f"{code} ({preview})"


def _decode_iccid(hex_clean: str) -> dict[str, object] | None:
    try:
        iccid = _swap_nibbles(hex_clean).rstrip("F")
    except ValueError:
        return None
    return {
        "iccid": iccid,
        "encoding": "BCD swapped nibbles",
        "digitCount": len(iccid),
    }


def _decode_imsi(hex_clean: str) -> dict[str, object] | None:
    if len(hex_clean) < 4:
        return None
    try:
        digit_length = (int(hex_clean[0:2], 16) * 2) - 1
        swapped = _swap_nibbles(hex_clean[2:]).rstrip("F")
        if len(swapped) < 1:
            return None
        odd_even = (int(swapped[0], 16) >> 3) & 0x01
        if odd_even == 0:
            digit_length -= 1
        imsi = swapped[1:]
        if digit_length > 0 and digit_length <= len(imsi):
            imsi = imsi[:digit_length]
        return {
            "imsi": imsi,
            "digitCount": len(imsi),
            "oddDigitCount": odd_even == 1,
        }
    except Exception:
        return None


def _decode_plmn_hex(plmn_hex: str) -> str | None:
    compact = re.sub(r"\s+", "", str(plmn_hex or "")).upper()
    if len(compact) != 6:
        return None
    if compact == "FFFFFF":
        return None
    mcc = compact[1] + compact[0] + compact[3]
    mnc = compact[5] + compact[4] + compact[2]
    return f"{mcc}-{mnc.rstrip('F')}"


def _decode_access_technologies(act_hex: str) -> list[str]:
    compact = re.sub(r"\s+", "", str(act_hex or "")).upper()
    if len(compact) != 4:
        return []
    act_bits = int(compact, 16)
    technologies: set[str] = set()
    if act_bits & 0x8000:
        technologies.add("UTRAN")
    eutran_bits = act_bits & 0x7000
    if eutran_bits in (0x4000, 0x7000):
        technologies.add("E-UTRAN WB-S1")
        technologies.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x5000:
        technologies.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x6000:
        technologies.add("E-UTRAN WB-S1")
    gsm_bits = act_bits & 0x008C
    if gsm_bits in (0x0080, 0x008C):
        technologies.add("GSM")
        technologies.add("EC-GSM-IoT")
    elif gsm_bits == 0x0084:
        technologies.add("GSM")
    elif gsm_bits == 0x0086:
        technologies.add("EC-GSM-IoT")
    if act_bits & 0x0020:
        technologies.add("cdma2000 HRPD")
    if act_bits & 0x0010:
        technologies.add("cdma2000 1xRTT")
    if act_bits & 0x0008:
        technologies.add("NG-RAN")
    if act_bits & 0x0040:
        technologies.add("GSM COMPACT")
    return sorted(technologies)


def _decode_plmn_list(hex_clean: str, *, with_act: bool) -> dict[str, object] | None:
    if len(hex_clean) == 0:
        return None
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    step = 5 if with_act else 3
    if len(raw) < step or len(raw) % step != 0:
        return None
    entries: list[dict[str, object]] = []
    for offset in range(0, len(raw), step):
        plmn_bytes = raw[offset : offset + 3]
        if plmn_bytes == b"\xFF\xFF\xFF":
            continue
        entry: dict[str, object] = {
            "plmn": _decode_plmn_hex(plmn_bytes.hex().upper()) or plmn_bytes.hex().upper(),
        }
        if with_act:
            entry["act"] = _decode_access_technologies(raw[offset + 3 : offset + 5].hex().upper())
        entries.append(entry)
    return {
        "entries": entries,
        "entryCount": len(entries),
        "encoding": "PLMN list with AcT" if with_act else "PLMN list",
    }


def _decode_ust(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    active: list[str] = []
    for byte_index, byte_value in enumerate(raw):
        for bit_index in range(8):
            if byte_value & (1 << bit_index):
                service_number = (byte_index * 8) + bit_index + 1
                service_name = _UST_SERVICE_NAMES.get(service_number, f"Service {service_number}")
                active.append(f"{service_number}: {service_name}")
    return {
        "activeServices": active,
        "activeCount": len(active),
    }


def _decode_acc(hex_clean: str) -> dict[str, object] | None:
    try:
        value = int(hex_clean, 16)
    except ValueError:
        return None
    classes: list[str] = []
    for index in range(16):
        if value & (1 << index):
            classes.append(str(index))
    return {
        "accessControlClasses": classes,
        "raw": hex_clean,
    }


def _decode_spn(hex_clean: str) -> dict[str, object] | None:
    if len(hex_clean) < 2:
        return None
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    display_condition = raw[0]
    name_bytes = raw[1:].rstrip(b"\xFF").rstrip(b"\x00")
    try:
        provider_name = name_bytes.decode("utf-8", "ignore")
    except Exception:
        provider_name = name_bytes.hex().upper()
    return {
        "serviceProviderName": provider_name,
        "displayCondition": f"0x{display_condition:02X}",
        "displayInHplmnRequired": (display_condition & 0x01) == 0,
        "hideInOplmnIfEquivalentPlmn": (display_condition & 0x02) != 0,
    }


def _decode_loci(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 11:
        return None
    lai = _decode_plmn_hex(raw[4:7].hex().upper())
    status_map = {
        0: "Updated",
        1: "Not Updated",
        2: "PLMN not allowed",
        3: "Location area not allowed",
    }
    return {
        "tmsi": raw[0:4].hex().upper(),
        "lai": lai or raw[4:7].hex().upper(),
        "lac": f"{int.from_bytes(raw[7:9], 'big'):04X}",
        "status": status_map.get(raw[10] & 0x03, f"0x{raw[10]:02X}"),
    }


def _decode_msisdn(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 14:
        return None
    alpha_len = max(0, len(raw) - 14)
    alpha = raw[:alpha_len].decode("utf-8", "ignore").strip("\x00").strip()
    footer = raw[alpha_len:]
    number_len = footer[0]
    ton_npi = footer[1]
    digits = _decode_bcd_digits(footer[2:12])
    if number_len > 1:
        digits = digits[: (number_len - 1) * 2]
    decoded: dict[str, object] = {
        "number": digits,
        "tonNpi": f"0x{ton_npi:02X}",
        "extensionRecordIdentifier": f"0x{footer[13]:02X}",
    }
    if alpha != "":
        decoded["alphaIdentifier"] = alpha
    return decoded


def _decode_known_ef_payload(
    *,
    ef_key: str | None,
    fid: str | None,
    hex_clean: str,
) -> dict[str, object] | None:
    token = str(ef_key or "").strip().lower()
    fid_upper = str(fid or "").strip().upper()

    if token == "ef-iccid" or fid_upper == "2FE2":
        return _decode_iccid(hex_clean)
    if token == "ef-imsi" or fid_upper == "6F07":
        return _decode_imsi(hex_clean)
    if token == "ef-ust" or fid_upper == "6F38":
        return _decode_ust(hex_clean)
    if token == "ef-acc" or fid_upper == "6F78":
        return _decode_acc(hex_clean)
    if token == "ef-spn" or fid_upper == "6F46":
        return _decode_spn(hex_clean)
    if token == "ef-msisdn" or fid_upper == "6F40":
        return _decode_msisdn(hex_clean)
    if token in _PLMN_WITH_ACT_KEYS:
        return _decode_plmn_list(hex_clean, with_act=True)
    if token == "ef-fplmn" or fid_upper == "6F7B":
        return _decode_plmn_list(hex_clean, with_act=False)
    if token in {"ef-loci", "ef-psloci", "ef-epsloci"}:
        return _decode_loci(hex_clean)
    if fid_upper in {"6F7E", "6F73", "6FE3"}:
        return _decode_loci(hex_clean)
    return None


def _decode_oid(value_bytes: bytes) -> str | None:
    if len(value_bytes) == 0:
        return None
    first = value_bytes[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for byte_value in value_bytes[1:]:
        current = (current << 7) | (byte_value & 0x7F)
        if byte_value & 0x80:
            continue
        parts.append(str(current))
        current = 0
    if current != 0:
        return None
    return ".".join(parts)


def _decode_generalized_time(value_bytes: bytes) -> str | None:
    text = _decode_printable_ascii(value_bytes)
    if text is None:
        return None
    formats = ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S.%fZ")
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).isoformat() + "Z"
        except ValueError:
            continue
    return text


def _decode_utc_time(value_bytes: bytes) -> str | None:
    text = _decode_printable_ascii(value_bytes)
    if text is None:
        return None
    try:
        return datetime.strptime(text, "%y%m%d%H%M%SZ").isoformat() + "Z"
    except ValueError:
        return text


def _try_decode_nested_ber(value_bytes: bytes) -> list[dict[str, object]] | None:
    decoded = _decode_generic_asn1_blob(value_bytes)
    if decoded is None:
        return None
    items = decoded.get("items")
    if isinstance(items, list):
        return items
    return None


def _decode_universal_primitive(tag_number: int, value_bytes: bytes) -> object | None:
    if tag_number == 1:
        if len(value_bytes) != 1:
            return None
        return value_bytes[0] != 0
    if tag_number in (2, 10):
        if len(value_bytes) == 0:
            return 0
        return int.from_bytes(value_bytes, "big", signed=True)
    if tag_number == 3:
        if len(value_bytes) == 0:
            return {"unusedBits": 0, "payloadHex": ""}
        decoded: dict[str, object] = {
            "unusedBits": value_bytes[0],
            "payloadHex": value_bytes[1:].hex().upper(),
        }
        if value_bytes[0] == 0:
            embedded = _try_decode_nested_ber(value_bytes[1:])
            if embedded is not None:
                decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 4:
        decoded = {
            "hex": value_bytes.hex().upper(),
        }
        ascii_text = _decode_printable_ascii(value_bytes)
        if ascii_text not in (None, ""):
            decoded["ascii"] = ascii_text
        embedded = _try_decode_nested_ber(value_bytes)
        if embedded is not None:
            decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 5:
        return "NULL"
    if tag_number == 6:
        return _decode_oid(value_bytes)
    if tag_number == 12:
        try:
            return value_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    if tag_number in (18, 19, 20, 21, 22, 25, 26, 27):
        try:
            return value_bytes.decode("ascii", "ignore")
        except Exception:
            return value_bytes.hex().upper()
    if tag_number == 23:
        return _decode_utc_time(value_bytes)
    if tag_number == 24:
        return _decode_generalized_time(value_bytes)
    if tag_number == 28:
        try:
            return value_bytes.decode("utf-32-be")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    if tag_number == 30:
        try:
            return value_bytes.decode("utf-16-be")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    return None


def _tag_class_name(raw_value: int) -> str:
    mapping = {
        0: "universal",
        1: "application",
        2: "context",
        3: "private",
    }
    return mapping.get(raw_value, f"class-{raw_value}")


def _render_tag_name(tag_class: str, tag_number: int) -> str:
    if tag_class == "universal":
        return _UNIVERSAL_TAG_NAMES.get(tag_number, f"UNIVERSAL {tag_number}")
    if tag_class == "application":
        return f"APPLICATION {tag_number}"
    if tag_class == "context":
        return f"[{tag_number}]"
    return f"PRIVATE {tag_number}"


def _parse_tag_identifier(data: bytes, offset: int) -> tuple[str, int, bool, bytes, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    offset += 1
    tag_bytes = bytearray([first])
    tag_class = _tag_class_name((first >> 6) & 0x03)
    constructed = (first & 0x20) != 0
    tag_number = first & 0x1F
    if tag_number != 0x1F:
        return (tag_class, tag_number, constructed, bytes(tag_bytes), offset)
    tag_number = 0
    while offset < len(data):
        byte_value = data[offset]
        offset += 1
        tag_bytes.append(byte_value)
        tag_number = (tag_number << 7) | (byte_value & 0x7F)
        if (byte_value & 0x80) == 0:
            return (tag_class, tag_number, constructed, bytes(tag_bytes), offset)
    return None


def _parse_ber_length(data: bytes, offset: int) -> tuple[int | None, bool, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    offset += 1
    if first == 0x80:
        return (None, True, offset)
    if (first & 0x80) == 0:
        return (first, False, offset)
    octet_count = first & 0x7F
    if octet_count == 0 or offset + octet_count > len(data):
        return None
    return (int.from_bytes(data[offset : offset + octet_count], "big"), False, offset + octet_count)


def _parse_ber_stream(
    data: bytes,
    offset: int,
    *,
    allow_eoc: bool,
    depth: int,
) -> tuple[list[dict[str, object]], int] | None:
    if depth > 24:
        raise ValueError("ASN.1 nesting depth exceeds 24 levels")
    items: list[dict[str, object]] = []
    while offset < len(data):
        if allow_eoc and offset + 2 <= len(data) and data[offset : offset + 2] == b"\x00\x00":
            return (items, offset + 2)
        parsed_tag = _parse_tag_identifier(data, offset)
        if parsed_tag is None:
            return None
        tag_class, tag_number, constructed, tag_bytes, value_offset = parsed_tag
        parsed_length = _parse_ber_length(data, value_offset)
        if parsed_length is None:
            return None
        length_value, indefinite, content_offset = parsed_length
        item: dict[str, object] = {
            "tag": _render_tag_name(tag_class, tag_number),
            "class": tag_class,
            "tagNumber": tag_number,
            "constructed": constructed,
            "tagHex": tag_bytes.hex().upper(),
        }
        if indefinite:
            if constructed is False:
                return None
            item["length"] = "indefinite"
            parsed_children = _parse_ber_stream(
                data,
                content_offset,
                allow_eoc=True,
                depth=depth + 1,
            )
            if parsed_children is None:
                return None
            children, next_offset = parsed_children
            item["items"] = children
            items.append(item)
            offset = next_offset
            continue
        if length_value is None:
            return None
        if content_offset + length_value > len(data):
            return None
        value_bytes = data[content_offset : content_offset + length_value]
        item["length"] = length_value
        if constructed:
            parsed_children = _parse_ber_stream(
                value_bytes,
                0,
                allow_eoc=False,
                depth=depth + 1,
            )
            if parsed_children is not None:
                item["items"] = parsed_children[0]
            else:
                item["raw"] = value_bytes.hex().upper()
        else:
            item["raw"] = value_bytes.hex().upper()
            decoded_value = None
            if tag_class == "universal":
                decoded_value = _decode_universal_primitive(tag_number, value_bytes)
            if decoded_value is None:
                ascii_text = _decode_printable_ascii(value_bytes)
                if ascii_text not in (None, ""):
                    decoded_value = ascii_text
                elif _looks_like_bcd_bytes(value_bytes):
                    decoded_value = {"digits": _decode_bcd_digits(value_bytes)}
            if decoded_value is not None:
                item["decoded"] = decoded_value
        items.append(item)
        offset = content_offset + length_value
    return (items, offset)


def _decode_generic_asn1_blob(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    try:
        parsed = _parse_ber_stream(value_bytes, 0, allow_eoc=False, depth=0)
    except ValueError:
        return None
    if parsed is None:
        return None
    items, end_offset = parsed
    if end_offset != len(value_bytes) or len(items) == 0:
        return None
    return {
        "format": "BER/DER",
        "items": items,
    }


def _decode_small_integer(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0 or len(value_bytes) > 4:
        return None
    return {
        "hex": value_bytes.hex().upper(),
        "decimal": int.from_bytes(value_bytes, "big"),
    }


def _decode_network_access_name(value_bytes: bytes) -> str:
    labels: list[str] = []
    cursor = 0
    while cursor < len(value_bytes):
        label_length = value_bytes[cursor]
        cursor += 1
        if label_length == 0:
            break
        label_bytes = value_bytes[cursor : cursor + label_length]
        cursor += label_length
        try:
            labels.append(label_bytes.decode("ascii"))
        except UnicodeDecodeError:
            labels.append(label_bytes.hex().upper())
    return ".".join(labels)


def _decode_other_address(value_bytes: bytes) -> dict[str, object] | str:
    if len(value_bytes) == 0:
        return value_bytes.hex().upper()
    address_type = value_bytes[0]
    address_value = value_bytes[1:]
    decoded: dict[str, object] = {
        "type": f"0x{address_type:02X}",
        "rawAddress": address_value.hex().upper(),
    }
    try:
        if address_type == 0x21 and len(address_value) == 4:
            decoded["address"] = str(ipaddress.IPv4Address(address_value))
        elif address_type == 0x57 and len(address_value) == 16:
            decoded["address"] = str(ipaddress.IPv6Address(address_value))
    except ipaddress.AddressValueError:
        pass
    return decoded


def _describe_bearer_description(value_bytes: bytes) -> dict[str, object]:
    description = {
        "raw": value_bytes.hex().upper(),
        "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
    }
    if len(value_bytes) > 0:
        description["bearerType"] = f"0x{value_bytes[0]:02X}"
    return description


def _describe_transport_level(value_bytes: bytes) -> dict[str, object]:
    if len(value_bytes) < 3:
        return {"raw": value_bytes.hex().upper()}
    port = int.from_bytes(value_bytes[1:3], "big")
    decoded = {
        "protocol": f"0x{value_bytes[0]:02X}",
        "port": port,
    }
    if len(value_bytes) > 3:
        decoded["parameters"] = value_bytes[3:].hex().upper()
    return decoded


def _parse_ber_tlv_item(data: bytes, offset: int) -> tuple[dict[str, object], int] | None:
    if offset >= len(data):
        return None
    tag_start = offset
    first = data[offset]
    offset += 1
    if (first & 0x1F) == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if (current & 0x80) == 0:
                break
        else:
            return None
    tag_bytes = data[tag_start:offset]
    if offset >= len(data):
        return None
    length_first = data[offset]
    offset += 1
    if length_first == 0x80:
        return None
    if (length_first & 0x80) == 0:
        value_length = length_first
    else:
        length_len = length_first & 0x7F
        if length_len == 0 or offset + length_len > len(data):
            return None
        value_length = int.from_bytes(data[offset : offset + length_len], "big")
        offset += length_len
    end_offset = offset + value_length
    if end_offset > len(data):
        return None
    tag_hex = tag_bytes.hex().upper()
    return (
        {
            "tag": tag_hex,
            "constructed": (tag_bytes[0] & 0x20) != 0,
            "valueBytes": data[offset:end_offset],
            "length": value_length,
        },
        end_offset,
    )


def _decode_field_ber_tlv_stream(
    value_bytes: bytes,
    *,
    tag_names: dict[str, str],
    force_primitive_tags: set[str] | None = None,
    value_decoders: dict[str, ValueDecoder] | None = None,
) -> list[dict[str, object]]:
    force_primitive = set(force_primitive_tags or set())
    out: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(value_bytes):
        parsed = _parse_ber_tlv_item(value_bytes, cursor)
        if parsed is None:
            out.append({"parseErrorOffset": cursor, "remaining": value_bytes[cursor:].hex().upper()})
            break
        item, cursor = parsed
        tag_hex = str(item["tag"])
        child_bytes = item["valueBytes"]
        constructed = bool(item["constructed"]) and tag_hex not in force_primitive
        rendered: dict[str, object] = {
            "tag": tag_hex,
            "name": tag_names.get(tag_hex, tag_hex),
            "length": int(item["length"]),
        }
        if constructed:
            rendered["items"] = _decode_field_ber_tlv_stream(
                child_bytes,
                tag_names=tag_names,
                force_primitive_tags=force_primitive,
                value_decoders=value_decoders,
            )
            out.append(rendered)
            continue
        rendered["raw"] = child_bytes.hex().upper()
        custom_decoder = None
        if value_decoders is not None:
            custom_decoder = value_decoders.get(tag_hex)
        decoded_value = None
        if custom_decoder is not None:
            decoded_value = custom_decoder(child_bytes)
        elif tag_hex == "06":
            decoded_value = _decode_oid(child_bytes)
        else:
            ascii_text = _decode_printable_ascii(child_bytes)
            if ascii_text not in (None, ""):
                decoded_value = ascii_text
            else:
                decoded_value = _decode_small_integer(child_bytes)
        if decoded_value is not None:
            rendered["decoded"] = decoded_value
        out.append(rendered)
    return out


def _scp_name(scp_value: int) -> str | None:
    mapping = {
        0x80: "SCP80",
        0x82: "SCP02",
        0x02: "SCP02",
        0x03: "SCP03",
    }
    return mapping.get(scp_value)


def _decode_flag_octets(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    set_bits: list[int] = []
    bit_index = 0
    for byte_value in reversed(value_bytes):
        for mask in range(8):
            if ((byte_value >> mask) & 0x01) == 0x01:
                set_bits.append(bit_index)
            bit_index += 1
    set_bits.sort(reverse=True)
    return {"hex": value_bytes.hex().upper(), "setBits": set_bits}


def _decode_application_privileges(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    privilege_value = int.from_bytes(value_bytes, "big", signed=False)
    active_ids: list[str] = []
    active_privileges: list[str] = []
    for mask_value, privilege_id, privilege_name in _APPLICATION_PRIVILEGE_FLAGS:
        if privilege_value & mask_value:
            active_ids.append(privilege_id)
            active_privileges.append(privilege_name)
    hex_value = value_bytes.hex().upper()
    return {
        "format": "GlobalPlatform application privileges",
        "hex": hex_value,
        "summary": _summary_with_list(f"0x{hex_value}", active_privileges),
        "activePrivilegeIds": active_ids,
        "activePrivileges": active_privileges,
    }


def _decode_life_cycle_state(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    state_value = value_bytes[0]
    state_name = _LIFE_CYCLE_STATE_NAMES.get(state_value, "Unknown")
    code = f"0x{state_value:02X}"
    return {
        "format": "GlobalPlatform life cycle state",
        "code": code,
        "summary": _summary_with_label(code, None if state_name == "Unknown" else state_name),
        "state": state_name,
    }


def _decode_key_usage_qualifier(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0 or len(value_bytes) > 2:
        return None
    normalized_bytes = value_bytes
    if len(normalized_bytes) == 1:
        normalized_bytes = normalized_bytes + b"\x00"
    usage_value = int.from_bytes(normalized_bytes, "big", signed=False)
    active_ids: list[str] = []
    active_usages: list[str] = []
    for mask_value, usage_id, usage_name in _KEY_USAGE_FLAGS:
        if usage_value & mask_value:
            active_ids.append(usage_id)
            active_usages.append(usage_name)
    normalized_hex = normalized_bytes.hex().upper()
    return {
        "format": "GlobalPlatform key usage qualifier",
        "hex": value_bytes.hex().upper(),
        "normalizedHex": normalized_hex,
        "summary": _summary_with_list(f"0x{normalized_hex}", active_usages),
        "activeUsageIds": active_ids,
        "activeUsages": active_usages,
    }


def _decode_key_access(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    access_value = value_bytes[0]
    access_name = _KEY_ACCESS_NAMES.get(access_value, "Unknown")
    code = f"0x{access_value:02X}"
    return {
        "format": "GlobalPlatform key access",
        "code": code,
        "summary": _summary_with_label(code, None if access_name == "Unknown" else access_name),
        "access": access_name,
    }


def _decode_key_identifier(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    key_id = value_bytes[0]
    role_name = _KEY_ID_COMMON_ROLES.get(key_id)
    decoded: dict[str, object] = {
        "format": "GlobalPlatform key identifier",
        "hex": value_bytes.hex().upper(),
        "decimal": key_id,
        "summary": _summary_with_label(f"0x{key_id:02X}", role_name),
    }
    if role_name is not None:
        decoded["commonRole"] = role_name
    return decoded


def _decode_key_version_number(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    kvn_value = value_bytes[0]
    reserved_for = None
    if 0x01 <= kvn_value <= 0x0F:
        reserved_for = "SCP80"
    elif kvn_value == 0x11:
        reserved_for = "DAP according to ETSI TS 102 226"
    elif 0x20 <= kvn_value <= 0x2F:
        reserved_for = "SCP02"
    elif 0x30 <= kvn_value <= 0x3F:
        reserved_for = "SCP03"
    elif kvn_value == 0xFF:
        reserved_for = "ISD with SCP02 without SCP80 support"
    decoded: dict[str, object] = {
        "format": "GlobalPlatform key version number",
        "hex": value_bytes.hex().upper(),
        "decimal": kvn_value,
        "summary": _summary_with_label(f"0x{kvn_value:02X}", reserved_for),
    }
    if reserved_for is not None:
        decoded["reservedFor"] = reserved_for
    return decoded


def _decode_key_counter_value(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": "GlobalPlatform key counter value",
        "hex": value_bytes.hex().upper(),
        "decimal": decimal_value,
        "summary": f"{decimal_value} (0x{value_bytes.hex().upper()})",
    }


def _decode_key_type(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    key_type_value = value_bytes[0]
    key_type_name = _KEY_TYPE_NAMES.get(key_type_value, "Unknown")
    code = f"0x{key_type_value:02X}"
    return {
        "format": "GlobalPlatform key type",
        "hex": value_bytes.hex().upper(),
        "summary": _summary_with_label(code, None if key_type_name == "Unknown" else key_type_name),
        "type": key_type_name,
    }


def _decode_connectivity_parameters(value_bytes: bytes) -> dict[str, object]:
    tag_names = {
        "A0": "Transport / Remote Parameters",
        "A1": "Bearer / Access Parameters",
        "06": "Object Identifier",
        "35": "Bearer Description",
        "39": "Buffer Size",
        "3C": "Transport Level",
        "3E": "Other Address",
        "47": "Network Access Name",
        "81": "Parameter 81",
        "82": "Parameter 82",
    }
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names=tag_names,
        force_primitive_tags={"35", "39", "3C", "3E", "47"},
        value_decoders={
            "35": _describe_bearer_description,
            "39": _decode_small_integer,
            "3C": _describe_transport_level,
            "3E": _decode_other_address,
            "47": _decode_network_access_name,
            "81": _decode_small_integer,
            "82": _decode_small_integer,
        },
    )
    return {
        "format": "BER-TLV",
        "items": items,
    }


def _decode_sd_install_scp(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    scp_value = value_bytes[0]
    decoded: dict[str, object] = {
        "scp": f"0x{scp_value:02X}",
    }
    scp_name = _scp_name(scp_value)
    if scp_name is not None:
        decoded["scpName"] = scp_name
    if len(value_bytes) > 1:
        decoded["i"] = f"0x{value_bytes[1]:02X}"
    return decoded


def _decode_sd_install_parameters(value_bytes: bytes) -> dict[str, object]:
    tag_names = {
        "81": "UICC SCP",
        "82": "Accept extradite applications and load files to SD",
        "83": "Accept delete of associated SD",
        "84": "Life cycle transition to personalized",
        "86": "CASD capability information",
        "87": "Accept extradite associated applications and load files",
    }
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names=tag_names,
        value_decoders={
            "81": _decode_sd_install_scp,
            "82": _decode_flag_octets,
            "83": _decode_flag_octets,
            "84": _decode_flag_octets,
            "86": _decode_flag_octets,
            "87": _decode_flag_octets,
        },
    )
    return {
        "format": "BER-TLV",
        "items": items,
    }


def _decode_uicc_toolkit_parameters(value_bytes: bytes) -> dict[str, object]:
    decoded: dict[str, object] = {
        "format": "ETSI TS 102 226 toolkit app specific parameters",
        "rawHex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    try:
        offset = 0
        if offset >= len(value_bytes):
            return decoded
        access_domain_length = value_bytes[offset]
        offset += 1
        if offset + access_domain_length > len(value_bytes):
            raise ValueError("invalid access domain length")
        access_domain = value_bytes[offset : offset + access_domain_length]
        offset += access_domain_length
        if offset + 4 > len(value_bytes):
            raise ValueError("missing toolkit fixed header")
        priority_level = value_bytes[offset]
        offset += 1
        max_num_of_timers = value_bytes[offset]
        offset += 1
        max_text_length = value_bytes[offset]
        offset += 1
        menu_entry_count = value_bytes[offset]
        offset += 1
        menu_entries: list[dict[str, int]] = []
        for _ in range(menu_entry_count):
            if offset + 2 > len(value_bytes):
                raise ValueError("truncated toolkit menu entry")
            menu_entries.append(
                {
                    "id": value_bytes[offset],
                    "position": value_bytes[offset + 1],
                }
            )
            offset += 2
        if offset >= len(value_bytes):
            raise ValueError("missing channel count")
        max_num_of_channels = value_bytes[offset]
        offset += 1
        if offset >= len(value_bytes):
            raise ValueError("missing MSL length")
        msl_length = value_bytes[offset]
        offset += 1
        if offset + msl_length > len(value_bytes):
            raise ValueError("invalid MSL length")
        msl_value_bytes = value_bytes[offset : offset + msl_length]
        offset += msl_length
        if offset >= len(value_bytes):
            raise ValueError("missing TAR length")
        tar_data_length = value_bytes[offset]
        offset += 1
        if offset + tar_data_length > len(value_bytes):
            raise ValueError("invalid TAR length")
        tar_end = offset + tar_data_length
        if tar_data_length % 3 != 0:
            raise ValueError("TAR values must be 3-byte aligned")
        tar_values: list[str] = []
        while offset < tar_end:
            tar_values.append(value_bytes[offset : offset + 3].hex().upper())
            offset += 3
        trailing_padding = b""
        if offset != len(value_bytes):
            trailing_padding = value_bytes[offset:]
            if any(byte_value != 0x00 for byte_value in trailing_padding):
                raise ValueError("invalid non-zero toolkit trailing bytes")
        decoded.update(
            {
                "accessDomain": access_domain.hex().upper(),
                "priorityLevelOfToolkitAppInstance": priority_level,
                "maxNumberOfTimers": max_num_of_timers,
                "maxTextLengthForMenuEntry": max_text_length,
                "menuEntries": menu_entries,
                "maxNumberOfChannels": max_num_of_channels,
                "minimumSecurityLevelRaw": msl_value_bytes.hex().upper(),
                "tarValues": tar_values,
            }
        )
        if len(msl_value_bytes) >= 1:
            decoded["minimumSecurityLevelInferred"] = f"0x{msl_value_bytes[-1]:02X}"
            decoded["minimumSecurityLevelDecimal"] = msl_value_bytes[-1]
        if len(tar_values) > 0:
            decoded["tarInferred"] = tar_values[0]
        if len(trailing_padding) > 0:
            decoded["trailingPadding"] = trailing_padding.hex().upper()
        return decoded
    except Exception:
        decoded["bytes"] = [f"0x{byte_value:02X}" for byte_value in value_bytes]
        for index in range(0, max(0, len(value_bytes) - 2)):
            if value_bytes[index] == 0x02 and value_bytes[index + 1] == 0x01:
                decoded["minimumSecurityLevelInferred"] = f"0x{value_bytes[index + 2]:02X}"
                decoded["minimumSecurityLevelDecimal"] = value_bytes[index + 2]
                break
        tar_index = value_bytes.find(bytes.fromhex("B20100"))
        if tar_index != -1:
            decoded["tarInferred"] = value_bytes[tar_index : tar_index + 3].hex().upper()
        return decoded


def _decode_special_field(field_name: str | None, value_bytes: bytes) -> dict[str, object] | None:
    key = str(field_name or "").strip()
    if key == "connectivityParameters":
        return _decode_connectivity_parameters(value_bytes)
    if key == "applicationSpecificParametersC9":
        return _decode_sd_install_parameters(value_bytes)
    if key == "uiccToolkitApplicationSpecificParametersField":
        return _decode_uicc_toolkit_parameters(value_bytes)
    return None


def _decode_scalar_special_field(field_name: str | None, value: Any) -> dict[str, object] | None:
    key = str(field_name or "").strip()
    if key == "applicationPrivileges":
        return _decode_application_privileges(value)
    if key == "lifeCycleState":
        return _decode_life_cycle_state(value)
    if key == "keyUsageQualifier":
        return _decode_key_usage_qualifier(value)
    if key == "keyAccess":
        return _decode_key_access(value)
    if key == "keyIdentifier":
        return _decode_key_identifier(value)
    if key == "keyVersionNumber":
        return _decode_key_version_number(value)
    if key == "keyCounterValue":
        return _decode_key_counter_value(value)
    if key == "keyType":
        return _decode_key_type(value)
    return None


def _try_decode_x509_certificate(value_bytes: bytes) -> dict[str, object] | None:
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        certificate = x509.load_der_x509_certificate(value_bytes)
    except Exception:
        return None
    not_before = getattr(certificate, "not_valid_before_utc", None) or getattr(
        certificate,
        "not_valid_before",
        None,
    )
    not_after = getattr(certificate, "not_valid_after_utc", None) or getattr(
        certificate,
        "not_valid_after",
        None,
    )
    decoded = {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serialNumber": hex(certificate.serial_number),
    }
    if not_before is not None:
        decoded["notBefore"] = not_before.isoformat()
    if not_after is not None:
        decoded["notAfter"] = not_after.isoformat()
    return decoded


def _summarize_binary_blob(value_bytes: bytes) -> dict[str, object]:
    summary: dict[str, object] = {
        "length": len(value_bytes),
        "hex": value_bytes.hex().upper(),
    }
    ascii_text = _decode_printable_ascii(value_bytes)
    if ascii_text not in (None, ""):
        summary["ascii"] = ascii_text
    if _looks_like_bcd_bytes(value_bytes):
        digits = _decode_bcd_digits(value_bytes)
        if digits != "":
            summary["bcdDigits"] = digits
    return summary


def _filesystem_hint(pe_base: str) -> str | None:
    mapping: dict[str, str] = {
        "telecom": "MF/TELECOM",
        "phonebook": "MF/TELECOM/PHONEBOOK",
        "graphics": "MF/TELECOM/GRAPHICS",
        "multimedia": "MF/TELECOM/MULTIMEDIA",
        "mmss": "MF/TELECOM/MMSS",
        "cd": "MF/CD",
        "df-5gs": "MF/USIM/5GS",
        "df-snpn": "MF/USIM/SNPN",
        "df-saip": "MF/USIM/SAIP",
        "df-5gprose": "MF/USIM/5G_PROSE",
        "eap": "MF/USIM/EAP",
        "isim": "MF/ISIM",
        "opt-isim": "MF/ISIM",
        "mcs": "MF/USIM/MCS",
        "v2x": "MF/USIM/V2X",
        "a2x": "MF/USIM/A2X",
    }
    return mapping.get(pe_base)


def _fid_for_ef_key(pe_section_key: str, ef_key: str) -> str | None:
    pe_base = base_pe_type(pe_section_key)
    if ef_key == "ef-arr":
        if pe_base == "mf":
            return "2F06"
        return "6F06"
    return _EF_KEY_TO_FID.get(ef_key)


def _last_non_index_token(path_tail: list[str]) -> str | None:
    for token in reversed(path_tail):
        text = str(token)
        if text.startswith("["):
            continue
        if text == "fillFileContent":
            continue
        return text
    return None


def _decode_one_blob(
    hex_clean: str,
    *,
    pe_section_key: str,
    path_tail: list[str],
    last_ef_key: str | None,
) -> list[str]:
    value_bytes = bytes.fromhex(hex_clean)
    field_name = _last_non_index_token(path_tail)
    fid = None
    ef_guess = last_ef_key
    if ef_guess is None and field_name is not None and field_name.startswith("ef-"):
        ef_guess = field_name
    if ef_guess is not None:
        fid = _fid_for_ef_key(pe_section_key, ef_guess)

    blocks: list[str] = []
    known_ef = _decode_known_ef_payload(ef_key=ef_guess, fid=fid, hex_clean=hex_clean)
    if known_ef is not None:
        blocks.extend(_compact_block("EF payload", known_ef))

    field_semantics = _decode_special_field(field_name, value_bytes)
    if field_semantics is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("Field semantics", field_semantics))

    certificate = _try_decode_x509_certificate(value_bytes)
    if certificate is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("X.509 certificate", certificate))

    generic_asn1 = _decode_generic_asn1_blob(value_bytes)
    if generic_asn1 is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("ASN.1 / BER", generic_asn1))

    if len(blocks) == 0:
        blocks.extend(_compact_block("Binary summary", _summarize_binary_blob(value_bytes)))
    return blocks


def _walk(
    value: Any,
    pe_section_key: str,
    path_tail: list[str],
    last_ef_key: str | None,
    out: list[tuple[str, list[str]]],
    max_hits: int | None,
) -> None:
    if max_hits is not None and len(out) >= max_hits:
        return

    if isinstance(value, dict):
        keys_structural = set(_structural_data_keys(value))
        if keys_structural == {_TAG_BYTES}:
            hx = _hex_from_tagged_bytes(value)
            if hx is None:
                return
            lines = _decode_one_blob(
                hx,
                pe_section_key=pe_section_key,
                path_tail=path_tail,
                last_ef_key=last_ef_key,
            )
            if len(lines) > 0:
                label = "/".join(path_tail[-4:]) if len(path_tail) > 0 else "(bytes)"
                out.append((f"{pe_section_key} :: {label}", lines))
            return

        if keys_structural == {_TAG_TUPLE}:
            inner = _value_first(value, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            if isinstance(inner, list) and len(inner) >= 2:
                tag = inner[0]
                payload = inner[1]
                if tag == "fillFileContent":
                    _walk(
                        payload,
                        pe_section_key,
                        path_tail + ["fillFileContent"],
                        last_ef_key,
                        out,
                        max_hits,
                    )
                    return
                _walk(
                    payload,
                    pe_section_key,
                    path_tail + [str(tag)],
                    last_ef_key,
                    out,
                    max_hits,
                )
            return

        for key, child in value.items():
            key_text = str(key)
            if key_text.startswith("__ygg_"):
                continue
            next_ef = last_ef_key
            if key_text.startswith("ef-"):
                next_ef = key_text
            _walk(child, pe_section_key, path_tail + [key_text], next_ef, out, max_hits)
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk(
                child,
                pe_section_key,
                path_tail + [f"[{index}]"],
                last_ef_key,
                out,
                max_hits,
            )
        return

    field_name = _last_non_index_token(path_tail)
    scalar_semantics = _decode_scalar_special_field(field_name, value)
    if scalar_semantics is None:
        return
    lines = _compact_block("Field semantics", scalar_semantics)
    label = "/".join(path_tail[-4:]) if len(path_tail) > 0 else "(value)"
    out.append((f"{pe_section_key} :: {label}", lines))


def build_profile_asn1_report(
    tagged_document: dict[str, Any],
    *,
    max_sections: int | None = None,
    max_hits_per_doc: int | None = None,
) -> str:
    """
    Produce plain-text decode lines for the TRANSCODE bottom panel.

    Expects a JSON-loaded root object (``intro`` / ``sections`` / meta).
    """
    sections = tagged_document.get("sections")
    if isinstance(sections, dict) is False:
        return "No sections object - cannot decode."

    hits: list[tuple[str, list[str]]] = []
    count_sections = 0
    for section_key, section_value in sections.items():
        if max_sections is not None and count_sections >= max_sections:
            break
        count_sections += 1
        sk = str(section_key)
        _walk(section_value, sk, [sk], None, hits, max_hits_per_doc)

    if len(hits) == 0:
        return (
            "No decodable tagged bytes or recognized field semantics found. Select a tagged "
            "hex value or open a profile containing EF fill content, BER/DER fields, "
            "certificate payloads, or known GlobalPlatform security domain fields."
        )

    if max_hits_per_doc is not None and len(hits) > max_hits_per_doc:
        visible = hits[:max_hits_per_doc]
        return _format_hits(visible).rstrip() + (
            f"\n\n[truncated: {len(hits)} hits, showing {max_hits_per_doc}]\n"
        )
    return _format_hits(hits)


def build_inspector_report_for_subtree(
    subtree: Any,
    pe_section_key: str,
    *,
    focus_path_hint: list[str] | None = None,
    last_ef_key: str | None = None,
    max_hits: int | None = None,
) -> str:
    """
    Decode tagged ``hex`` / ``__ygg_saip_bytes__`` values under a JSON subtree.

    This path is pure-Python and does not import ``SCP03`` or ``pySim``.
    """
    hits: list[tuple[str, list[str]]] = []
    path_tail = ["selection"]
    if focus_path_hint:
        path_tail = list(focus_path_hint)
    _walk(subtree, pe_section_key, path_tail, last_ef_key, hits, max_hits)
    if len(hits) == 0:
        if isinstance(subtree, dict):
            visible = [
                str(key)
                for key in subtree.keys()
                if str(key).startswith("__ygg_") is False and str(key) != "label"
            ]
            sample = ", ".join(visible[:10])
            suffix = " ..." if len(visible) > 10 else ""
            return (
                f"No decodable tagged bytes or recognized field semantics under this object "
                f"({len(visible)} key(s)).\n"
                f"Keys: {sample}{suffix}"
            )
        if isinstance(subtree, list):
            return (
                f"No decodable tagged bytes or recognized field semantics under this list "
                f"({len(subtree)} item(s))."
            )
        text = repr(subtree)
        if len(text) > 240:
            text = text[:237] + "..."
        return f"No decodable tagged bytes or recognized field semantics under this value: {text}"
    return _format_hits(hits)
