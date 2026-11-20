# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Readings of data fields the context decoder used to leave as hex.

The SMS TPDU of a CAT data object with the secured packet it carries, the
PUT KEY data field, the Key Information Template, the TERMINAL CAPABILITY
template and the SUCI that GET IDENTITY returns. Each function takes the
bytes of one field and gives display nodes or fields; a field that does not
fit its clause is left to the caller's plain reading.
"""

from __future__ import annotations

from typing import Any

# TS 23.040 V19 section 9.2.3.1: the two TP-MTI bits by direction.
TP_MTI_MOBILE_TERMINATED: dict[int, str] = {0: "SMS-DELIVER", 1: "SMS-SUBMIT-REPORT", 2: "SMS-STATUS-REPORT", 3: "Reserved"}
TP_MTI_MOBILE_ORIGINATED: dict[int, str] = {0: "SMS-DELIVER-REPORT", 1: "SMS-SUBMIT", 2: "SMS-COMMAND", 3: "Reserved"}

# The information elements a secured short message uses: TS 31.115 V19
# sections 4.2 and 4.4 for '70' and '71', TS 23.040 V19 section 9.2.3.24.1 for '00'.
SECURED_SMS_ELEMENTS: dict[int, str] = {
    0x00: "Concatenated short messages, 8-bit reference number",
    0x70: "Command Packet Identifier",
    0x71: "Response Packet Identifier",
}

# TS 102 221 V18.4.0 section 11.1.19.2.0: the objects of the terminal capability template 'A9'.
TERMINAL_CAPABILITY_TAGS: dict[int, str] = {
    0x80: "Terminal power supply",
    0x81: "Extended logical channels terminal support",
    0x82: "Additional interfaces support",
    0x83: "Additional Terminal capability indications related to eUICC (GSMA SGP.22)",
    0x84: "Additional Terminal capability indications related to eUICC (GSMA SGP.32)",
}

# SGP.22 v3.1 section 3.4.2 Table 7: byte 1 under tag '83', b1 first.
LPA_DEVICE_CAPABILITIES: tuple[str, ...] = (
    "Local User Interface in the Device (LUId)",
    "Local Profile Download in the Device (LPDd)",
    "Local Discovery Service in the Device (LDSd)",
    "LUIe based on SCWS",
    "Metadata update alerting",
    "Enterprise Capable Device",
    "LUIe using E4E",
    "LPR",
)

# TS 31.102 V19.5 section 7.5.2.1: byte 1 of the SUCI value, the SUPI format.
SUCI_FORMATS: dict[int, str] = {
    0x01: "IMSI",
    0x11: "Network Specific Identifier",
    0x21: "Global Cable Identifier",
    0x31: "Global Line Identifier",
}


# GPC Amd F v1.2 Table 6-2: b2-b1 of the SCP parameters after the SCP identifier '11'.
SCP11_VARIANTS: dict[int, str] = {0: "SCP11b", 1: "SCP11a", 2: "RFU", 3: "SCP11c"}

# GPC Amd F v1.2 Tables 6-17 and 6-23: the Control Reference Template 'A6' of the key agreement.
SCP11_KEY_AGREEMENT_TAGS: dict[str, str] = {
    "90": "SCP identifier and parameters",
    "95": "Key Usage Qualifier",
    "80": "Key Type",
    "81": "Key Length",
    "84": "HostID",
}
SCP11_KEY_USAGE_QUALIFIERS: dict[int, str] = {
    0x34: "secure messaging with C-MAC and R-MAC only",
    0x3C: "secure messaging with C-MAC, R-MAC, and ENCRYPTION",
    0x1C: "secure messaging with C-MAC and DECRYPTION, only for SCP11c",
    0x74: "secure messaging with C-MAC, R-MAC, and DECRYPTION, only for SCP11c",
}

# GPC Amd F v1.2 Table 6-12 (the certificate '7F21') and Table 6-14 (its public key '7F49').
SCP11_CERTIFICATE_TAGS: dict[str, str] = {
    "93": "Certificate Serial Number",
    "42": "CA-KLOC (or KA-KLOC) Identifier",
    "5F20": "Subject Identifier",
    "95": "Key Usage",
    "5F25": "Effective Date",
    "5F24": "Expiration Date",
    "53": "Discretionary Data",
    "73": "Discretionary Data",
    "BF20": "Authorizations under SCP11c",
    "7F49": "Public Key",
    "5F37": "Signature",
}
SCP11_PUBLIC_KEY_TAGS: dict[str, str] = {"B0": "Public key - Q", "F0": "Key Parameter Reference"}
SCP11_CERTIFICATE_KEY_USAGE: dict[str, str] = {"82": "Digital signature verification", "0080": "Key agreement"}

# GPC Amd F v1.2 Table 6-20 (MUTUAL AUTHENTICATE, SCP11a and SCP11c) and Table 6-24 (INTERNAL
# AUTHENTICATE, SCP11b): the response kind of the command, its table and what tag '5F49' holds.
# Under SCP11c the card answers with its static key; the command's template says which it is.
SCP11_RESPONSES: dict[str, tuple[str, str]] = {
    "scp11_internal_authenticate_response": ("Table 6-24", "ePK.SD.ECKA"),
    "scp11a_mutual_authenticate_response": ("Table 6-20", "ePK.SD.ECKA"),
    "scp11c_mutual_authenticate_response": ("Table 6-20", "PK.SD.ECKA"),
    "scp11_mutual_authenticate_response": ("Table 6-20", "ePK.SD.ECKA (SCP11a) or PK.SD.ECKA (SCP11c)"),
}


def _node(name: str, value: bytes, decoded: Any = None, children: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from .context import _part_node

    return _part_node(name, value, decoded=decoded, children=children)


def _packet_nodes(rows: list[Any]) -> list[dict[str, Any]]:
    nodes = []
    for row in rows:
        text = f"'{row.value}'H" if row.value and not row.meaning else (f"{row.value} ({row.meaning})" if row.value else row.meaning)
        # A field inside an octet is shown by its bits, never as an octet of its own.
        octets = bytes.fromhex(row.value) if _is_hex(row.value) and not row.bits else b""
        nodes.append(_node(row.label, octets, decoded=text))
    return nodes


def _is_hex(text: str) -> bool:
    return len(text) % 2 == 0 and len(text) > 0 and all(character in "0123456789ABCDEFabcdef" for character in text)


def user_data_nodes(user_data: bytes, *, has_header: bool) -> list[dict[str, Any]]:
    """TP-User-Data: its header elements and, behind '70' or '71', the secured packet (TS 31.115 V19 sections 4.2, 4.4)."""
    from yggdrasim_common import secured_packet

    if not has_header:
        return [_node("TP-UD", user_data)]
    if len(user_data) < 1 or 1 + user_data[0] > len(user_data):
        return [_node("TP-UD", user_data, decoded="the header length runs past the user data")]
    header, body = user_data[1:1 + user_data[0]], user_data[1 + user_data[0]:]
    nodes: list[dict[str, Any]] = []
    packet = ""
    position = 0
    while position + 2 <= len(header):
        element, length = header[position], header[position + 1]
        value = header[position + 2:position + 2 + length]
        position += 2 + length
        name = SECURED_SMS_ELEMENTS.get(element, f"information element '{element:02X}'")
        nodes.append(_node(f"UDH {element:02X}", value, decoded=name if not value else f"{name}: {value.hex().upper()}"))
        if element in (0x70, 0x71):
            packet = "command" if element == 0x70 else "response"
    if not packet:
        nodes.append(_node("TP-UD", body))
        return nodes
    try:
        rows = secured_packet.command_packet_rows(body) if packet == "command" else secured_packet.response_packet_rows(body)
    except ValueError as error:
        nodes.append(_node(f"Secured {packet} packet", body, decoded=str(error)))
        return nodes
    nodes.append(_node(f"Secured {packet} packet", body, children=_packet_nodes(rows)))
    return nodes


def sms_tpdu_nodes(tpdu: bytes, *, mobile_terminated: bool) -> list[dict[str, Any]] | None:
    """The fields of an SMS TPDU (TS 23.040 V19 sections 9.2.2.1, 9.2.2.2), read with pySim's SMS classes.

    ``mobile_terminated`` says which way the TPDU travels: to the card in an
    SMS-PP download, from it in SEND SHORT MESSAGE. None when pySim cannot
    read the TPDU; the caller keeps the hex.
    """
    if len(tpdu) < 2:
        return None
    try:
        from pySim.sms import SMS_DELIVER, SMS_SUBMIT
    except ImportError:
        return None
    message_type = tpdu[0] & 0x03
    names = TP_MTI_MOBILE_TERMINATED if mobile_terminated else TP_MTI_MOBILE_ORIGINATED
    nodes = [_node("TP-MTI", bytes([message_type]), decoded=names[message_type])]
    # pySim reads the two types a secured packet travels in; the others keep their first octet named.
    if (mobile_terminated and message_type != 0) or (not mobile_terminated and message_type != 1):
        nodes.append(_node("TPDU", tpdu[1:]))
        return nodes
    try:
        message = SMS_DELIVER.from_bytes(tpdu) if mobile_terminated else SMS_SUBMIT.from_bytes(tpdu)
    except Exception:  # noqa: BLE001 - pySim's construct parsers raise library-specific errors on a short TPDU
        return None
    flags = ("tp_mms", "tp_lp", "tp_rp", "tp_udhi", "tp_sri") if mobile_terminated else ("tp_rd", "tp_rp", "tp_udhi", "tp_srr")
    set_flags = [name.replace("tp_", "TP-").upper() for name in flags if getattr(message, name, False)]
    nodes.append(_node("Flags", b"", decoded=", ".join(set_flags) if set_flags else "none set"))
    if not mobile_terminated:
        nodes.append(_node("TP-MR", bytes([int(message.tp_mr) & 0xFF]), decoded=str(int(message.tp_mr))))
    address = message.tp_oa if mobile_terminated else message.tp_da
    nodes.append(_node("TP-OA" if mobile_terminated else "TP-DA", b"", decoded=f"{address.digits} (type of number {address.ton}, numbering plan {address.npi})"))
    nodes.append(_node("TP-PID", bytes([message.tp_pid])))
    nodes.append(_node("TP-DCS", bytes([message.tp_dcs])))
    if mobile_terminated:
        nodes.append(_node("TP-SCTS", bytes(message.tp_scts)))
    user_data = bytes(message.tp_ud or b"")
    nodes.append(_node("TP-UDL", bytes([int(message.tp_udl) & 0xFF]), decoded=f"{int(message.tp_udl)}" + ("" if int(message.tp_udl) == len(user_data) else f"; {len(user_data)} octets follow")))
    nodes.extend(user_data_nodes(user_data, has_header=bool(message.tp_udhi)))
    return nodes


def report_user_data_nodes(data: bytes) -> list[dict[str, Any]] | None:
    """The user data an SMS-PP download answers with, when it opens with a header that names a response packet."""
    if len(data) < 3 or data[0] + 1 > len(data) or 0x71 not in _header_elements(data[1:1 + data[0]]):
        return None
    return user_data_nodes(data, has_header=True)


def _header_elements(header: bytes) -> list[int]:
    elements = []
    position = 0
    while position + 2 <= len(header):
        elements.append(header[position])
        position += 2 + header[position + 1]
    return elements


def terminal_capability_nodes(data: bytes) -> list[dict[str, Any]] | None:
    """The terminal capability template 'A9' by its objects (TS 102 221 V18.4.0 section 11.1.19.2).

    Tag '83' carries the device capabilities of SGP.22 v3.1 section 3.4.2,
    tag '84' those of SGP.32 v1.3 section 3.8.2. None when the data field is
    not one 'A9' template.
    """
    from .context import _iter_tlvs, _node as build, _tlvs_cover

    outer = _iter_tlvs(data)
    if len(outer) != 1 or not _tlvs_cover(data, outer) or outer[0].tag_hex != "A9":
        return None
    inner = _iter_tlvs(outer[0].value)
    if not _tlvs_cover(outer[0].value, inner):
        return None
    children: list[dict[str, Any]] = []
    for item in inner:
        tag = int(item.tag_hex, 16) if len(item.tag_hex) == 2 else -1
        value = item.value
        name = TERMINAL_CAPABILITY_TAGS.get(tag, "private or unknown object")
        decoded: str | None = None
        if tag == 0x80 and len(value) == 3:
            frequency = "no clock frequency indicated" if value[2] == 0xFF else f"{value[2] / 10:.1f} MHz"
            decoded = f"supply voltage class byte {value[0]:02X}, {value[1]} mA available, {frequency}"
        elif tag == 0x81:
            decoded = "supported" if not value else f"supported; {len(value)} byte(s) a UICC of this release reads as none"
        elif tag == 0x82 and len(value) >= 1:
            decoded = "UICC-CLF interface supported" if value[0] & 0x01 else "UICC-CLF interface not supported"
        elif tag == 0x83 and len(value) >= 1:
            supported = [text for bit, text in enumerate(LPA_DEVICE_CAPABILITIES) if value[0] & (1 << bit)]
            decoded = "; ".join(supported) if supported else "no LPA function or capability indicated"
        elif tag == 0x84 and len(value) >= 1:
            decoded = "IPAd supported" if value[0] & 0x01 else "IPAd not supported"
        children.append(build(item.tag_hex, name, value, decoded=decoded))
    return [build("A9", "Terminal capability", outer[0].value, children=children)]


def _put_key_length(data: bytes, position: int) -> tuple[int, int]:
    """A length of the PUT KEY data field: BER, with 128 also allowed on one byte as '80' (GPC v2.4 section 11.8.2.3.1)."""
    first = data[position]
    if first <= 0x80:
        return first, position + 1
    count = first & 0x7F
    if count == 0 or position + 1 + count > len(data):
        raise ValueError("a length field runs past the data field")
    return int.from_bytes(data[position + 1:position + 1 + count], "big"), position + 1 + count


def _key_type_name(key_type: int) -> str:
    """The name of a key type from the one table of GPC v2.4 Table 11-16 the tree keeps."""
    try:
        from Tools.ProfilePackage.saip_security_domain_edit import KEY_TYPE_LABELS
    except ImportError:
        return "key type table not available"
    return str(KEY_TYPE_LABELS.get(key_type, "not a key type of Table 11-16"))


def put_key_fields(data: bytes) -> list[dict[str, Any]]:
    """The PUT KEY data field: the new Key Version Number, then one key data field per key (GPC v2.4 section 11.8.2.3).

    Format 1 and Format 2 (Tables 11-68 and 11-69) are told apart by a key
    type of 'FF xx'. The key component blocks are protected and stay hex.
    Raises ``ValueError`` when the field does not follow either format.
    """
    from .context import _field

    if len(data) < 2:
        raise ValueError("the data field holds no key data field")
    fields = [_field("Key Version Number", f"{data[0]:02X}", "of the keys in this data field")]
    position = 1
    key = 0
    while position < len(data):
        key += 1
        extended = data[position] == 0xFF
        component = 0
        # Standardized key types are above '7F', so the length of the Key Check Value ends the components.
        while position < len(data) and data[position] > 0x7F:
            component += 1
            if extended:
                if position + 2 > len(data):
                    raise ValueError("a two-byte key type is cut short")
                key_type, position = data[position + 1], position + 2
            else:
                key_type, position = data[position], position + 1
            if position >= len(data):
                raise ValueError("a key component has no length")
            length, position = _put_key_length(data, position)
            block = data[position:position + length]
            if len(block) != length:
                raise ValueError("a key component block runs past the data field")
            position += length
            label = f"Key {key} / component {component}"
            fields.append(_field(label, f"{key_type:02X}", f"{_key_type_name(key_type)}; component block of {length} byte(s), protected"))
            fields.append(_field(f"{label} block", block.hex().upper()))
        if component == 0 or position >= len(data):
            raise ValueError("a key data field has no key component or no Key Check Value length")
        for name in (("Key Check Value",) if not extended else ("Key Check Value", "Key Usage Qualifier", "Key Access Condition")):
            if position >= len(data):
                raise ValueError(f"the length of the {name} is missing")
            length = data[position]
            value = data[position + 1:position + 1 + length]
            if length > 0x7F or len(value) != length:
                raise ValueError(f"the {name} runs past the data field")
            position += 1 + length
            fields.append(_field(f"Key {key} / {name}", value.hex().upper() or "(none)", f"{length} byte(s)"))
    return fields


def key_information_text(value: bytes) -> str | None:
    """One Key Information Data entry 'C0' in words (GPC v2.4 section 11.3.3.1, Tables 11-28 and 11-29); None when it does not fit."""
    if len(value) < 4:
        return None
    parts = [f"key identifier {value[0]:02X}, key version number {value[1]:02X}"]
    position = 2
    extended = value[position] == 0xFF
    components = []
    while position < len(value) and (value[position] > 0x7F):
        if extended:
            if position + 4 > len(value):
                return None
            key_type, length = value[position + 1], int.from_bytes(value[position + 2:position + 4], "big")
            position += 4
            size = f"{length} byte(s)"
        else:
            if position + 2 > len(value):
                return None
            key_type, length = value[position], value[position + 1]
            position += 2
            # '00' stands for a component of 256 bytes or more in the basic structure.
            size = "256 byte(s) or more" if length == 0 else f"{length} byte(s)"
        components.append(f"{_key_type_name(key_type)} ('{key_type:02X}'), {size}")
    if not components:
        return None
    parts.append("; ".join(components))
    if extended:
        for name in ("key usage qualifier", "key access condition"):
            if position >= len(value) or position + 1 + value[position] > len(value):
                return None
            length = value[position]
            parts.append(f"{name} {value[position + 1:position + 1 + length].hex().upper() or 'not given'}")
            position += 1 + length
    if position != len(value):
        return None
    return ": ".join(parts[:2]) + ("; " + "; ".join(parts[2:]) if len(parts) > 2 else "")


def suci_fields(data: bytes) -> list[dict[str, Any]] | None:
    """The SUCI TLV data object 'A1' that GET IDENTITY returns (TS 31.102 V19.5 section 7.5.2.1); None for anything else."""
    from .context import _bcd_digits, _field, _iter_tlvs, _tlvs_cover

    items = _iter_tlvs(data)
    if len(items) != 1 or not _tlvs_cover(data, items) or items[0].tag_hex != "A1" or len(items[0].value) < 1:
        return None
    value = items[0].value
    supi_format = SUCI_FORMATS.get(value[0])
    fields = [_field("SUPI format", f"{value[0]:02X}", supi_format or "not a format of this clause")]
    if supi_format != "IMSI":
        # The other formats carry the SUCI as a NAI from byte 2 on.
        try:
            text = value[1:].decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        fields.append(_field("SUCI NAI", value[1:].hex().upper(), text))
        return fields
    if len(value) < 8:
        fields.append(_field("SUCI value", value.hex().upper(), "shorter than the eight octets before the scheme output"))
        return fields
    plmn = value[1:4]
    try:
        from pySim.utils import dec_plmn

        network = dec_plmn(plmn.hex())
        network_text = f"MCC {network['mcc']}, MNC {network['mnc']}"
    except (ImportError, KeyError, ValueError):
        network_text = ""
    scheme = value[6]
    try:
        from SCP03.core.decoders import ContentDecoder

        scheme_name = ContentDecoder._SUCI_PROTECTION_SCHEMES.get(scheme & 0x0F, "")
    except ImportError:
        scheme_name = ""
    fields.extend([
        _field("Home network identifier", plmn.hex().upper(), network_text),
        _field("Routing indicator", value[4:6].hex().upper(), _bcd_digits(value[4:6])),
        _field("Protection scheme identifier", f"{scheme:02X}", scheme_name),
        _field("Home network public key identifier", f"{value[7]:02X}"),
        _field("Scheme output", value[8:].hex().upper(), f"{len(value) - 8} byte(s)"),
    ])
    return fields


def scp11_variant(data: bytes) -> str | None:
    """The SCP11 variant a key agreement command asks for, from tag '90' of its template (GPC Amd F v1.2 Table 6-2)."""
    from .context import _iter_tlvs, _tlvs_cover

    items = _iter_tlvs(data)
    if not items or not _tlvs_cover(data, items) or items[0].tag_hex != "A6":
        return None
    inner = _iter_tlvs(items[0].value)
    if not _tlvs_cover(items[0].value, inner):
        return None
    for child in inner:
        if child.tag_hex == "90" and len(child.value) == 2:
            return SCP11_VARIANTS[child.value[1] & 0x03]
    return None


def mutual_authenticate_response_kind(data: bytes) -> str:
    """The response kind of a MUTUAL AUTHENTICATE command, by the variant its template names."""
    variant = scp11_variant(data)
    if variant == "SCP11a":
        return "scp11a_mutual_authenticate_response"
    if variant == "SCP11c":
        return "scp11c_mutual_authenticate_response"
    return "scp11_mutual_authenticate_response"


def scp11_key_agreement_nodes(data: bytes, *, card_key: str = "") -> list[dict[str, Any]] | None:
    """The data field of MUTUAL AUTHENTICATE or INTERNAL AUTHENTICATE, or of its answer (GPC Amd F v1.2 sections 6.5 and 6.6).

    The command carries the Control Reference Template 'A6' and the ephemeral
    public key of the OCE. The answer carries the card's public key and a
    receipt; ``card_key`` is the name of that key (``SCP11_RESPONSES``) and
    marks the field as an answer. None when the field is not a whole sequence
    of TLVs.
    """
    from .context import _iter_tlvs, _node as build, _tlvs_cover

    response = bool(card_key)
    items = _iter_tlvs(data)
    if not items or not _tlvs_cover(data, items):
        return None
    nodes: list[dict[str, Any]] = []
    for item in items:
        if item.tag_hex == "A6" and not response:
            children = []
            inner = _iter_tlvs(item.value)
            if not _tlvs_cover(item.value, inner):
                return None
            for child in inner:
                value = child.value
                decoded: str | None = None
                if child.tag_hex == "90" and len(value) == 2:
                    variant = SCP11_VARIANTS[value[1] & 0x03]
                    identifiers = "Host and Card ID in the key derivation" if value[1] & 0x04 else "no Host and Card ID in the key derivation"
                    decoded = f"SCP '{value[0]:02X}', {variant}, {identifiers}" + ("" if value[1] & 0xF8 == 0 else ", RFU bits set")
                elif child.tag_hex == "95" and len(value) == 1:
                    decoded = SCP11_KEY_USAGE_QUALIFIERS.get(value[0], "not a qualifier of this command")
                elif child.tag_hex == "80" and len(value) == 1:
                    decoded = _key_type_name(value[0])
                elif child.tag_hex == "81" and len(value) == 1:
                    decoded = f"{value[0]} byte(s)"
                children.append(build(child.tag_hex, SCP11_KEY_AGREEMENT_TAGS.get(child.tag_hex, "data object"), value, decoded=decoded))
            nodes.append(build("A6", "Control Reference Template (Key Agreement)", item.value, children=children))
        elif item.tag_hex == "5F49":
            nodes.append(build("5F49", card_key if response else "ePK.OCE.ECKA", item.value))
        elif item.tag_hex == "86" and response:
            nodes.append(build("86", "Receipt", item.value))
        else:
            nodes.append(build(item.tag_hex, "data object", item.value))
    return nodes


def _bcd_date(value: bytes) -> str | None:
    text = value.hex()
    return f"{text[0:4]}-{text[4:6]}-{text[6:8]}" if len(value) == 4 and text.isdigit() else None


def scp11_certificate_nodes(data: bytes) -> list[dict[str, Any]] | None:
    """The certificates of a PERFORM SECURITY OPERATION data field (GPC Amd F v1.2 Tables 6-11, 6-12 and 6-14).

    None when the field is not whole TLVs: one block of a certificate that
    continues in the next command stays bytes.
    """
    from .context import _iter_tlvs, _node as build, _tlvs_cover

    items = _iter_tlvs(data)
    if not items or not _tlvs_cover(data, items):
        return None
    nodes: list[dict[str, Any]] = []
    for item in items:
        if item.tag_hex != "7F21":
            nodes.append(build(item.tag_hex, "data object", item.value))
            continue
        inner = _iter_tlvs(item.value)
        if not _tlvs_cover(item.value, inner):
            return None
        children = []
        for child in inner:
            value = child.value
            decoded: str | None = None
            grandchildren = None
            if child.tag_hex == "95":
                decoded = SCP11_CERTIFICATE_KEY_USAGE.get(value.hex().upper(), "not a key usage of this table")
            elif child.tag_hex in ("5F25", "5F24"):
                decoded = _bcd_date(value)
            elif child.tag_hex == "7F49":
                parts = _iter_tlvs(value)
                if _tlvs_cover(value, parts):
                    grandchildren = [build(part.tag_hex, SCP11_PUBLIC_KEY_TAGS.get(part.tag_hex, "data object"), part.value) for part in parts]
            children.append(build(child.tag_hex, SCP11_CERTIFICATE_TAGS.get(child.tag_hex, "data object"), value, decoded=decoded, children=grandchildren))
        nodes.append(build("7F21", "Certificate", item.value, children=children))
    return nodes
