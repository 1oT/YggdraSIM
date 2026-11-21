# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Context-aware APDU and TLV decoding.

A card command is read against the specification that governs it. The
CLA/INS pair, refined by P1/P2 and the leading data tag, picks the domain:
UICC file and PIN commands (ETSI TS 102 221), Card Application Toolkit
(ETSI TS 102 223 / TS 101 220), GlobalPlatform card content management
(GPC v2.3.1, SCP03 Amendment D), ES10 remote SIM provisioning carried in
STORE DATA (GSMA SGP.22 / SGP.32) and 3GPP AUTHENTICATE (TS 31.102). The
domain picks the payload decoder, so a tag such as '84' is a DF name in an
FCP, an Executable Module AID in a GET STATUS entry and an AT command in a
CAT envelope, never one flat dictionary lookup.

A pasted trace is decoded as a sequence of exchanges with state carried
forward: the selected file names the EF whose content READ BINARY returns,
a '61 xx' status word chains the following GET RESPONSE data onto the
command that produced it, and segmented STORE DATA blocks are reassembled
before the ES10 request is decoded.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import gsma_schema
from .main import (
    DecodeError,
    TagRegistry,
    _decode_universal_value,
    _json_safe,
    _lookup_apdu_command,
    _parse_apdu_body,
    _parse_ber_stream,
    _read_length,
    _read_tag,
    normalise_hex,
)

# ----------------------------------------------------------------------
# Shared TLV helpers
# ----------------------------------------------------------------------


@dataclass
class Tlv:
    tag_hex: str
    tag_bytes: bytes
    value: bytes
    raw: bytes
    constructed: bool


def _iter_tlvs(data: bytes) -> list[Tlv]:
    """Split ``data`` into BER-TLV objects; stops at the first malformed one."""
    items: list[Tlv] = []
    offset = 0
    while offset < len(data):
        try:
            tag = _read_tag(data, offset)
            length = _read_length(data, tag.next_offset)
        except DecodeError:
            break
        if length.length is None:
            break
        end = length.next_offset + length.length
        if end > len(data):
            break
        items.append(
            Tlv(
                tag_hex=tag.tag_hex,
                tag_bytes=data[offset : tag.next_offset],
                value=data[length.next_offset : end],
                raw=data[offset:end],
                constructed=tag.constructed,
            )
        )
        offset = end
    return items


def _tlvs_cover(data: bytes, items: list[Tlv]) -> bool:
    return len(data) > 0 and sum(len(item.raw) for item in items) == len(data)


def _node(
    tag_hex: str,
    name: str,
    value: bytes,
    *,
    spec: str = "",
    decoded: Any = None,
    children: list[dict[str, Any]] | None = None,
    note: str = "",
) -> dict[str, Any]:
    node: dict[str, Any] = {
        "tag": tag_hex.upper(),
        "name": name,
        "length": len(value),
        "valueHex": value.hex().upper(),
    }
    if spec:
        node["spec"] = spec
    if decoded is not None:
        node["decoded"] = decoded
    if note:
        node["note"] = note
    if children:
        node["children"] = children
    return node


def _field(label: str, value: Any, meaning: str = "", *, spec: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {"label": label, "value": value}
    if meaning:
        entry["meaning"] = meaning
    if spec:
        entry["spec"] = spec
    return entry


def _payload(kind: str, title: str, spec: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"kind": kind, "title": title, "spec": spec}
    payload.update(extra)
    return payload


def _hex(data: bytes) -> str:
    return data.hex().upper()


def _int(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


def _bcd_digits(data: bytes) -> str:
    """Nibble-swapped BCD with 'F' padding, as EF_ICCID stores digits."""
    digits = []
    for byte in data:
        low = byte & 0x0F
        high = byte >> 4
        for nibble in (low, high):
            if nibble == 0x0F:
                continue
            digits.append(f"{nibble:X}")
    return "".join(digits)


def _generic_tree(data: bytes, registry: TagRegistry) -> list[dict[str, Any]] | None:
    try:
        items, offset = _parse_ber_stream(data, 0, registry, depth=0, allow_eoc=False)
    except DecodeError:
        return None
    if offset != len(data):
        return None
    return items


def _tree_to_nodes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    for item in items:
        value_hex = str(item.get("raw") or "")
        node: dict[str, Any] = {
            "tag": str(item.get("tag") or ""),
            "name": str(item.get("name") or ""),
            "length": len(value_hex) // 2,
            "valueHex": value_hex,
        }
        if item.get("source"):
            node["spec"] = str(item["source"])
        if "decoded" in item and not isinstance(item.get("items"), list):
            node["decoded"] = item["decoded"]
        children = item.get("items")
        if isinstance(children, list) and children:
            node["children"] = _tree_to_nodes(children)
        nodes.append(node)
    return nodes


# ----------------------------------------------------------------------
# Well-known application identifiers
# ----------------------------------------------------------------------

# The name file the SCP03 shell seeds (SCP03/seeds/aid.txt) plus the two
# 3GPP application prefixes the simulator uses (SIMCARD/etsi_fs.py).
_AID_PREFIX_NAMES: tuple[tuple[str, str], ...] = (
    ("A0000005591010FFFFFFFF8900000100", "ISD-R"),
    ("A0000005591010FFFFFFFF8900000200", "ECASD"),
    ("A0000005591010FFFFFFFF89000010", "ISD-P"),
    ("A0000005591010FFFFFFFF89000011", "ISD-P"),
    ("A0000005591010FFFFFFFF89000012", "ISD-P"),
    ("A0000005591010FFFFFFFF89000013", "ISD-P"),
    ("A0000005591010FFFFFFFF89000014", "ISD-P"),
    ("A0000005591010FFFFFFFF89000015", "ISD-P"),
    ("A00000015141434C00", "ARA-M"),
    ("A00000015141434C01", "ARA-C"),
    ("A000000151000000", "GlobalPlatform ISD"),
    ("A0000000871002", "USIM (3GPP)"),
    ("A0000000871004", "ISIM (3GPP)"),
)

# Java Card API packages, matched whole: the load files a GET STATUS of
# Executable Load Files lists, and that INSTALL [for load] and DELETE name.
_PACKAGE_AID_NAMES: dict[str, str] = {
    # The AIDs in Oracle's export files (Java Card Development Kit 2.1.1 to
    # 3.1), read with the JCVM 3.1 §5.5 layout.
    "A0000000620001": "java.lang",
    "A0000000620002": "java.io",
    "A0000000620003": "java.rmi",
    "A0000000620101": "javacard.framework",
    "A000000062010101": "javacard.framework.service",
    "A0000000620102": "javacard.security",
    "A0000000620201": "javacardx.crypto",
    "A0000000620202": "javacardx.biometry",
    "A0000000620203": "javacardx.external",
    "A0000000620204": "javacardx.biometry1toN",
    "A0000000620205": "javacardx.security",
    "A000000062020501": "javacardx.security.cert",
    "A000000062020502": "javacardx.security.derivation",
    "A000000062020503": "javacardx.security.util",
    "A000000062020801": "javacardx.framework.util",
    "A00000006202080101": "javacardx.framework.util.intx",
    "A000000062020802": "javacardx.framework.math",
    "A000000062020803": "javacardx.framework.tlv",
    "A000000062020804": "javacardx.framework.string",
    "A000000062020805": "javacardx.framework.event",
    "A000000062020806": "javacardx.framework.nio",
    "A000000062020807": "javacardx.framework.time",
    "A0000000620209": "javacardx.apdu",
    "A000000062020901": "javacardx.apdu.util",
    # GPC v2.4 §A.1.2.
    "A00000015100": "org.globalplatform",
    # ETSI TS 102 241 v18.1 tables C.1a to C.7.
    "A0000000090005FFFFFFFF8911000000": "uicc.access",
    "A0000000090005FFFFFFFF8911010000": "uicc.access.fileadministration",
    "A0000000090005FFFFFFFF8911020000": "uicc.access.bertlvfile",
    "A0000000090005FFFFFFFF8912000000": "uicc.toolkit",
    "A0000000090005FFFFFFFF8912010000": "uicc.toolkit.test",
    "A0000000090005FFFFFFFF8913000000": "uicc.system",
    "A0000000090005FFFFFFFF8917000000": "uicc.suspendresume",
    "A0000000090005FFFFFFFF8918010000": "uicc.services.highupdatearray",
    # ETSI TS 102 588 v17 table C.1.
    "A0000000090005FFFFFFFF8914000000": "uicc.scws",
    # ETSI TS 102 267 v19 table C.1.
    "A0000000090005FFFFFFFF8915000000": "uicc.connection",
    # ETSI TS 102 705 v18 tables C.1 to C.5.
    "A0000000090005FFFFFFFF8916010000": "uicc.hci.framework",
    "A0000000090005FFFFFFFF8916020100": "uicc.hci.services.cardemulation",
    "A0000000090005FFFFFFFF8916020200": "uicc.hci.services.connectivity",
    "A0000000090005FFFFFFFF8916020300": "uicc.hci.services.readermode",
    "A0000000090005FFFFFFFF8916020400": "uicc.hci.services.cltobserver",
    # 3GPP TS 31.130 v19.2 annex C.
    "A0000000871005FFFFFFFF8913100000": "uicc.usim.access",
    "A0000000871005FFFFFFFF8913200000": "uicc.usim.toolkit",
    "A0000000871005FFFFFFFF8913300000": "uicc.usim.geolocation",
    "A0000000871005FFFFFFFF8913400000": "uicc.usim.suci",
    "A0000000871005FFFFFFFF8913500000": "uicc.usim.gba_u",
    # 3GPP TS 43.019 v6.0.0 annex C: TS 03.19 v7.0.0 coded '70' where every
    # later version codes '71'.
    "A0000000090003FFFFFFFF8910700001": "sim.access",
    "A0000000090003FFFFFFFF8910700002": "sim.toolkit",
    "A0000000090003FFFFFFFF8910710001": "sim.access",
    "A0000000090003FFFFFFFF8910710002": "sim.toolkit",
}


def _load_seeded_aids() -> list[tuple[str, str]]:
    seed = Path(__file__).resolve().parents[2] / "SCP03" / "seeds" / "aid.txt"
    entries: list[tuple[str, str]] = []
    try:
        for line in seed.read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            aid = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
            if len(aid) >= 10:
                entries.append((aid, name.strip()))
    except OSError:
        return []
    return entries


_SEEDED_AIDS = _load_seeded_aids()


def aid_name(aid: bytes) -> str:
    aid_hex = _hex(aid)
    for known, name in _SEEDED_AIDS:
        if aid_hex == known:
            return name
    package = _PACKAGE_AID_NAMES.get(aid_hex)
    if package is not None:
        return package
    for prefix, name in _AID_PREFIX_NAMES:
        if aid_hex.startswith(prefix):
            return name
    return ""


# ----------------------------------------------------------------------
# Instruction knowledge
# ----------------------------------------------------------------------

# ETSI TS 102 221 v18.4 table 10.5 (coding of the instruction byte).
_UICC_INS: dict[int, str] = {
    0xA4: "SELECT FILE",
    0xF2: "STATUS",
    0xB0: "READ BINARY",
    0xD6: "UPDATE BINARY",
    0xB2: "READ RECORD",
    0xDC: "UPDATE RECORD",
    0xA2: "SEARCH RECORD",
    0x32: "INCREASE",
    0xCB: "RETRIEVE DATA",
    0xDB: "SET DATA",
    0x20: "VERIFY PIN",
    0x24: "CHANGE PIN",
    0x26: "DISABLE PIN",
    0x28: "ENABLE PIN",
    0x2C: "UNBLOCK PIN",
    0x04: "DEACTIVATE FILE",
    0x44: "ACTIVATE FILE",
    0x88: "AUTHENTICATE",
    0x89: "AUTHENTICATE",
    0x84: "GET CHALLENGE",
    0xAA: "TERMINAL CAPABILITY",
    0x10: "TERMINAL PROFILE",
    0xC2: "ENVELOPE",
    0x12: "FETCH",
    0x14: "TERMINAL RESPONSE",
    0x70: "MANAGE CHANNEL",
    0x73: "MANAGE SECURE CHANNEL",
    0x75: "TRANSACT DATA",
    0x76: "SUSPEND UICC",
    0x78: "GET IDENTITY",
    0x7A: "EXCHANGE CAPABILITIES",
    0x7C: "MANAGE LSI",
    0xC0: "GET RESPONSE",
}
_UICC_SPEC = "ETSI TS 102 221 v18.4 table 10.5"

# TS 102 221 v18.4 table 10.5 lists the CAT commands with CLA '80'; their
# semantics are in ETSI TS 102 223 v18.3.
_CAT_INS = {0x10: "TERMINAL PROFILE", 0x12: "FETCH", 0x14: "TERMINAL RESPONSE", 0xC2: "ENVELOPE"}
_CAT_SPEC = "ETSI TS 102 223 v18.3"

# GlobalPlatform Card Specification v2.3.1 command messages; the table each
# command is defined in is named beside it.
_GP_INS: dict[int, tuple[str, str]] = {
    0xE6: ("INSTALL", "GPC v2.3.1 table 11-40"),
    0xE4: ("DELETE", "GPC v2.3.1 table 11-20"),
    0xF2: ("GET STATUS", "GPC v2.3.1 table 11-32"),
    0xF0: ("SET STATUS", "GPC v2.3.1 table 11-85"),
    0xE2: ("STORE DATA", "GPC v2.3.1 table 11-88"),
    0xCA: ("GET DATA", "GPC v2.3.1 table 11-27"),
    0xCB: ("GET DATA", "GPC v2.3.1 table 11-27"),
    0xD8: ("PUT KEY", "GPC v2.3.1 section 11.8"),
    0xE8: ("LOAD", "GPC v2.3.1 section 11.6"),
    0x50: ("INITIALIZE UPDATE", "GPC Amd D v1.1.2 section 7.1.1"),
    0x82: ("EXTERNAL AUTHENTICATE", "GPC Amd D v1.1.2 section 7.1.2"),
    0x2A: ("PERFORM SECURITY OPERATION", "GPC Amd F v1.2 section 6.4"),
    0x88: ("INTERNAL AUTHENTICATE", "GPC Amd F v1.2 section 6.6"),
}


def _gp_cla(cla: int) -> bool:
    # GPC v2.3.1 command tables: CLA '80'-'8F', 'C0'-'CF' or 'E0'-'EF'.
    return (cla & 0xF0) in (0x80, 0xC0, 0xE0)


def _part_node(
    name: str,
    value: bytes,
    *,
    decoded: Any = None,
    children: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A named part of a structure that is no TLV; a part with no octets of its own carries no length."""
    node = _node("", name, value, decoded=decoded, children=children)
    if not value:
        del node["length"], node["valueHex"]
    return node


def _scp11_key_reference(value: int, what: str) -> str:
    # GPC Amd F v1.2 sections 6.5.2 and 6.6.2: P1 and P2 name the key in bits 1 to 7; bit 8 is RFU.
    text = f"{what} {value & 0x7F:02X} of SK.SD.ECKA"
    return f"{text}; bit 8 is RFU and is set" if value & 0x80 else text


def _iso_cla(cla: int) -> bool:
    # TS 102 221 v18.4 table 10.5: '0X', '4X' or '6X' for the ISO-coded
    # commands; GPC v2.3.1 table 11-27 lists the same ranges for GET DATA.
    return (cla & 0xF0) in (0x00, 0x40, 0x60)


def _cla_fields(cla: int) -> list[dict[str, Any]]:
    """Describe the class byte (TS 102 221 v18.4 tables 10.3, 10.4, 10.4a)."""
    fields: list[dict[str, Any]] = []
    if cla & 0x40:
        channel = (cla & 0x0F) + 4
        sm = "command header not authenticated" if cla & 0x20 else "no secure messaging"
        fields.append(_field("Logical channel", channel, "extended logical channel (b7 = 1)", spec="TS 102 221 v18.4 table 10.4a"))
        fields.append(_field("Secure messaging", "b6 = 1" if cla & 0x20 else "b6 = 0", sm, spec="TS 102 221 v18.4 table 10.4b"))
    else:
        channel = cla & 0x03
        sm_bits = (cla >> 2) & 0x03
        sm = {
            0: "no secure messaging",
            1: "secure messaging in a proprietary format (a GlobalPlatform secure channel wraps the command)",
            2: "ISO/IEC 7816-4 secure messaging, command header not authenticated",
            3: "ISO/IEC 7816-4 secure messaging, command header authenticated",
        }[sm_bits]
        fields.append(_field("Logical channel", channel, "standard logical channel (b1-b2)", spec="TS 102 221 v18.4 table 10.3"))
        fields.append(_field("Secure messaging", f"b3-b4 = {sm_bits:02b}", sm, spec="TS 102 221 v18.4 table 10.4"))
    family = cla & 0xF0
    if family == 0x00:
        fields.append(_field("Class family", "0X", "first interindustry coding of ISO/IEC 7816-4", spec="TS 102 221 v18.4 table 10.3"))
    elif family == 0x80:
        fields.append(_field("Class family", "8X", "structured as '0X'; coding defined by TS 102 221 / GlobalPlatform", spec="TS 102 221 v18.4 table 10.3"))
    elif family == 0xA0:
        fields.append(_field("Class family", "AX", "GSM class, coded as '0X' unless stated otherwise", spec="TS 102 221 v18.4 table 10.3"))
    elif _gp_cla(cla):
        fields.append(_field("Class family", f"{family:02X}", "GlobalPlatform command class range", spec="GPC v2.3.1 command message tables"))
    return fields


# ----------------------------------------------------------------------
# Domain classification
# ----------------------------------------------------------------------


@dataclass
class CommandContext:
    domain: str
    name: str
    spec: str
    summary: str = ""
    payload_kind: str = ""
    response_kind: str = ""
    header: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


_DOMAIN_LABELS = {
    "uicc": "UICC (ETSI TS 102 221)",
    "cat": "Card Application Toolkit (ETSI TS 102 223)",
    "gp": "GlobalPlatform card content management",
    "es10": "GSMA eUICC ES10 (SGP.22 / SGP.32)",
    "auth": "3GPP network authentication (TS 31.102)",
    "tlv": "BER-TLV",
    "unknown": "Unknown command",
}


def _select_p1(p1: int) -> str:
    # TS 102 221 v18.4 table 11.1.
    return {
        0x00: "select DF, EF or MF by file identifier",
        0x01: "select child DF of the current DF",
        0x03: "select parent DF of the current DF",
        0x04: "selection by DF name (AID)",
        0x08: "select by path from the MF",
        0x09: "select by path from the current DF",
    }.get(p1, "reserved selection control")


def _select_p2(p1: int, p2: int) -> str:
    # TS 102 221 v18.4 table 11.2.
    parts: list[str] = []
    if p1 == 0x04:
        session = (p2 >> 5) & 0x03
        parts.append({0: "activation/reset", 2: "termination"}.get(session, "reserved application session control"))
        occurrence = p2 & 0x03
        parts.append({0: "first or only occurrence", 1: "last occurrence", 2: "next occurrence", 3: "previous occurrence"}[occurrence])
    data_bits = (p2 >> 2) & 0x07
    if data_bits == 0x01:
        parts.append("return FCP template")
    elif data_bits == 0x03:
        parts.append("no data returned")
    return ", ".join(parts) if parts else "reserved"


def _record_mode(p2: int) -> str:
    # TS 102 221 v18.4 table 11.11.
    mode = {0x02: "next record", 0x03: "previous record", 0x04: "absolute/current record (P1 = record number, '00' = current)"}.get(p2 & 0x07, "reserved mode")
    sfi = (p2 >> 3) & 0x1F
    target = f"short file identifier {sfi}" if sfi else "currently selected EF"
    return f"{mode}; {target}"


def _binary_offset(p1: int, p2: int) -> str:
    # TS 102 221 v18.4 table 11.10.
    if p1 & 0x80:
        return f"SFI {p1 & 0x1F} referenced, offset {p2}"
    return f"offset {((p1 & 0x7F) << 8) | p2}"


def _gp_get_status_p1(p1: int) -> str:
    # GPC v2.3.1 table 11-33.
    if p1 == 0x80:
        return "Issuer Security Domain"
    if p1 == 0x40:
        return "Applications and Supplementary Security Domains"
    if p1 == 0x20:
        return "Executable Load Files"
    if p1 == 0x10:
        return "Executable Load Files and their Executable Modules"
    if p1 == 0x08:
        return "Executable Load Files logically deleted with references"
    if p1 == 0x04:
        return "OPEN registry data"
    return "combined or reserved subset"


def _gp_install_roles(p1: int) -> list[str]:
    # GPC v2.3.1 table 11-41.
    roles: list[str] = []
    if p1 & 0x40:
        roles.append("for registry update")
    if p1 & 0x20:
        roles.append("for personalization")
    if p1 & 0x10:
        roles.append("for extradition")
    if p1 & 0x08:
        roles.append("for make selectable")
    if p1 & 0x04:
        roles.append("for install")
    if p1 & 0x02:
        roles.append("for load")
    return roles


def _looks_like_gp_get_status(p1: int, p2: int, data: bytes) -> bool:
    # ETSI STATUS uses P1 '00'-'02' and P2 '00', '01' or '0C' with no data
    # (TS 102 221 v18.4 tables 11.8, 11.9); GlobalPlatform GET STATUS sets
    # one subset bit in P1 and carries search criteria (GPC v2.3.1 tables
    # 11-32, 11-33).
    if len(data) > 0:
        return True
    return p1 in (0x80, 0x40, 0x20, 0x10, 0x08, 0x04) or (p2 & 0x02) != 0


def classify_command(cla: int, ins: int, p1: int, p2: int, data: bytes) -> CommandContext:
    """Pick the domain and the header semantics for one command APDU."""
    header = _cla_fields(cla)
    gp = _gp_cla(cla)
    # CAT commands travel on CLA '80' (TS 102 221 v18.4 table 10.5).
    if (cla & 0xF0) == 0x80 and ins in _CAT_INS:
        name = _CAT_INS[ins]
        ctx = CommandContext("cat", name, _CAT_SPEC, header=header)
        if ins == 0x12:
            ctx.summary = "terminal fetches the pending proactive command"
            ctx.response_kind = "cat_proactive"
        elif ins == 0x14:
            ctx.summary = "terminal reports the outcome of a proactive command"
            ctx.payload_kind = "cat_terminal_response"
        elif ins == 0xC2:
            ctx.summary = "terminal hands an event, message or menu selection to the UICC"
            ctx.payload_kind = "cat_envelope"
            ctx.response_kind = "cat_envelope_response"
        else:
            ctx.summary = "terminal declares its toolkit capabilities"
            ctx.payload_kind = "terminal_profile"
        return ctx
    if ins in (0x88, 0x89) and _iso_cla(cla):
        ctx = CommandContext("auth", "AUTHENTICATE", "3GPP TS 31.102 v19.5 section 7.1.2", header=header)
        ctx.summary = _auth_context(ins, p2)
        ctx.payload_kind = "auth_request"
        ctx.response_kind = "auth_response"
        ctx.header.append(_field("P2", f"{p2:02X}", ctx.summary, spec="TS 31.102 v19.5 table 7.1.2-1"))
        return ctx
    if ins == 0xE2 and gp:
        ctx = CommandContext("gp", "STORE DATA", "GPC v2.3.1 table 11-88", header=header)
        ctx.header.extend(_store_data_fields(p1, p2))
        ber_tlv = ((p1 >> 3) & 0x03) == 0x02
        starts_bf = len(data) >= 2 and data[0] == 0xBF
        if p1 in (0x11, 0x91) or starts_bf:
            ctx.domain = "es10"
            ctx.spec = "SGP.22 v3.1 section 5.7.2 table 47"
            ctx.summary = "ES10 transport command: the data field is one ES10x request TLV"
            ctx.payload_kind = "es10_request"
            ctx.response_kind = "es10_response"
            if not ber_tlv:
                ctx.notes.append("P1 does not declare BER-TLV structure (b5-b4 = 10) although SGP.22 table 47 requires it.")
        else:
            ctx.summary = "GlobalPlatform STORE DATA block"
            ctx.payload_kind = "gp_store_data"
        return ctx
    if ins == 0xF2 and gp and _looks_like_gp_get_status(p1, p2, data):
        ctx = CommandContext("gp", "GET STATUS", "GPC v2.3.1 table 11-32", header=header)
        subset = _gp_get_status_p1(p1)
        ctx.summary = f"registry subset: {subset}"
        ctx.header.append(_field("P1", f"{p1:02X}", subset, spec="GPC v2.3.1 table 11-33"))
        p2_parts = ["get next occurrence(s)" if p2 & 0x01 else "get first or all occurrence(s)"]
        p2_parts.append("TLV response format (tables 11-36 / 11-37)" if p2 & 0x02 else "deprecated response format")
        ctx.header.append(_field("P2", f"{p2:02X}", "; ".join(p2_parts), spec="GPC v2.3.1 table 11-34"))
        ctx.payload_kind = "gp_get_status_request"
        ctx.response_kind = "gp_registry"
        return ctx
    if gp and ins in _GP_INS and ins not in (0xF2, 0xCB):
        name, spec = _GP_INS[ins]
        ctx = CommandContext("gp", name, spec, header=header)
        if ins == 0xE6:
            roles = _gp_install_roles(p1)
            ctx.summary = "INSTALL " + " + ".join(f"[{role}]" for role in roles) if roles else "INSTALL with no role bit set"
            more = "more INSTALL commands follow" if p1 & 0x80 else "last (or only) command"
            ctx.header.append(_field("P1", f"{p1:02X}", f"{more}; " + (", ".join(roles) or "no role"), spec="GPC v2.3.1 table 11-41"))
            p2_text = {0x00: "no information", 0x01: "beginning of the combined load, install and make selectable process", 0x03: "end of the combined process"}.get(p2, "reserved")
            ctx.header.append(_field("P2", f"{p2:02X}", p2_text, spec="GPC v2.3.1 section 11.5.2.2"))
            ctx.payload_kind = "gp_install"
            ctx.response_kind = "gp_confirmation"
        elif ins == 0xE4:
            ctx.summary = "delete a card content object or key"
            ctx.header.append(_field("P1", f"{p1:02X}", "more DELETE commands follow" if p1 & 0x80 else "last (or only) command", spec="GPC v2.3.1 table 11-21"))
            p2_parts = ["delete object and related objects" if p2 & 0x80 else "delete object"]
            if p2 & 0x40:
                p2_parts.append("Security Domain and all associated ELFs/Applications")
            if p2 & 0x20:
                p2_parts.append("Security Domain self-removal")
            ctx.header.append(_field("P2", f"{p2:02X}", "; ".join(p2_parts), spec="GPC v2.3.1 table 11-22"))
            ctx.payload_kind = "gp_delete"
            ctx.response_kind = "gp_confirmation"
        elif ins == 0xF0:
            target = {0x80: "Issuer Security Domain", 0x40: "Application or Supplementary Security Domain", 0x60: "Security Domain and its associated Applications"}.get(p1 & 0xE0, "reserved status type")
            ctx.summary = f"set life cycle state of {target}"
            ctx.header.append(_field("P1", f"{p1:02X}", target, spec="GPC v2.3.1 table 11-86"))
            ctx.header.append(_field("P2", f"{p2:02X}", _gp_life_cycle_name(p2, "any"), spec="GPC v2.3.1 section 11.10.2.2"))
            ctx.payload_kind = "gp_aid"
        elif ins == 0xCA:
            tag_hex = f"{p1:02X}{p2:02X}" if p1 else f"{p2:02X}"
            ctx.summary = f"retrieve data object '{tag_hex}'"
            ctx.header.append(_field("P1 P2", tag_hex, _gp_get_data_tag_name(tag_hex), spec="GPC v2.3.1 section 11.3.2.1"))
            ctx.payload_kind = "gp_get_data_request"
            ctx.response_kind = "gp_get_data_response"
            ctx.notes.append(f"tag {tag_hex}")
        elif ins == 0x50:
            ctx.summary = "open a secure channel session: host challenge out, card challenge and cryptogram back"
            ctx.header.append(_field("P1", f"{p1:02X}", "key version number ('00' = default key set)", spec="GPC Amd D v1.1.2 section 7.1.1"))
            ctx.payload_kind = "scp_host_challenge"
            ctx.response_kind = "scp_init_update_response"
        elif ins == 0x82 and p2 != 0x00 and data[:1] == b"\xA6":
            # GPC Amd F v1.2 section 6.5.2: the INS of EXTERNAL AUTHENTICATE, with a P2 that SCP02 and SCP03 keep at '00'.
            ctx.name = "MUTUAL AUTHENTICATE"
            ctx.spec = "GPC Amd F v1.2 section 6.5"
            ctx.summary = "SCP11a or SCP11c key agreement: the ephemeral public key of the OCE in, the card's key and a receipt back"
            ctx.header.append(_field("P1", f"{p1:02X}", _scp11_key_reference(p1, "Key Version Number"), spec="GPC Amd F v1.2 section 6.5.2"))
            ctx.header.append(_field("P2", f"{p2:02X}", _scp11_key_reference(p2, "Key Identifier"), spec="GPC Amd F v1.2 section 6.5.2"))
            ctx.payload_kind = "scp11_key_agreement"
            from . import payload_readings

            ctx.response_kind = payload_readings.mutual_authenticate_response_kind(data)
        elif ins == 0x82:
            ctx.summary = "host cryptogram and C-MAC prove the session keys"
            ctx.payload_kind = "opaque"
        elif ins == 0x88:
            ctx.summary = "SCP11b key agreement: the ephemeral public key of the OCE in, the card's and a receipt back"
            ctx.header.append(_field("P1", f"{p1:02X}", _scp11_key_reference(p1, "Key Version Number"), spec="GPC Amd F v1.2 section 6.6.2"))
            ctx.header.append(_field("P2", f"{p2:02X}", _scp11_key_reference(p2, "Key Identifier"), spec="GPC Amd F v1.2 section 6.6.2"))
            ctx.payload_kind = "scp11_key_agreement"
            ctx.response_kind = "scp11_internal_authenticate_response"
        elif ins == 0x2A:
            ctx.summary = "submit CERT.OCE.ECKA, or one certificate of the chain that ends with it, before an SCP11a or SCP11c session"
            ctx.header.append(_field("P1", f"{p1:02X}", f"Key Version Number {p1 & 0x7F:02X} of PK.CA-KLOC.ECDSA; " + ("more command(s) follow for this certificate" if p1 & 0x80 else "last command of this certificate"), spec="GPC Amd F v1.2 Table 6-8"))
            ctx.header.append(_field("P2", f"{p2:02X}", f"Key Identifier {p2 & 0x7F:02X} of PK.CA-KLOC.ECDSA; " + ("more certificate(s) follow" if p2 & 0x80 else "last certificate"), spec="GPC Amd F v1.2 Table 6-9"))
            ctx.payload_kind = "scp11_certificate"
        elif ins == 0xD8:
            ctx.summary = "load or replace a key set"
            ctx.payload_kind = "gp_put_key"
        elif ins == 0xE8:
            ctx.summary = "load file data block"
            ctx.header.append(_field("P1", f"{p1:02X}", "last block" if p1 & 0x80 else "more blocks follow"))
            ctx.payload_kind = "gp_load"
        return ctx
    if ins in (0xCA, 0xCB) and _iso_cla(cla):
        tag_hex = f"{p1:02X}{p2:02X}" if p1 else f"{p2:02X}"
        ctx = CommandContext("gp", "GET DATA", "GPC v2.3.1 table 11-27", header=header)
        ctx.summary = f"retrieve data object '{tag_hex}'"
        ctx.header.append(_field("P1 P2", tag_hex, _gp_get_data_tag_name(tag_hex), spec="GPC v2.3.1 section 11.3.2.1"))
        ctx.payload_kind = "gp_get_data_request"
        ctx.response_kind = "gp_get_data_response"
        ctx.notes.append(f"tag {tag_hex}")
        return ctx
    if ins in _UICC_INS:
        name = _UICC_INS[ins]
        ctx = CommandContext("uicc", name, _UICC_SPEC, header=header)
        _uicc_header(ctx, ins, p1, p2, data)
        return ctx
    generic = _lookup_apdu_command(cla, ins)
    ctx = CommandContext("unknown", generic.name.replace("_", " "), generic.source, header=header)
    ctx.summary = "no domain decoder for this instruction; data shown as BER-TLV when it parses"
    ctx.payload_kind = "tlv"
    ctx.response_kind = "tlv"
    return ctx


def _uicc_header(ctx: CommandContext, ins: int, p1: int, p2: int, data: bytes) -> None:
    if ins == 0xA4:
        ctx.summary = _select_p1(p1)
        ctx.header.append(_field("P1", f"{p1:02X}", _select_p1(p1), spec="TS 102 221 v18.4 table 11.1"))
        ctx.header.append(_field("P2", f"{p2:02X}", _select_p2(p1, p2), spec="TS 102 221 v18.4 table 11.2"))
        ctx.payload_kind = "select_target"
        ctx.response_kind = "fcp"
    elif ins == 0xF2:
        ctx.summary = "current directory or application status"
        p1_text = {0x00: "no indication", 0x01: "current application is initialised in the terminal", 0x02: "terminal will initiate termination of the current application"}.get(p1, "RFU")
        p2_text = {0x00: "response as for SELECT", 0x01: "DF name TLV of the current application", 0x0C: "no data returned"}.get(p2, "RFU")
        ctx.header.append(_field("P1", f"{p1:02X}", p1_text, spec="TS 102 221 v18.4 table 11.8"))
        ctx.header.append(_field("P2", f"{p2:02X}", p2_text, spec="TS 102 221 v18.4 table 11.9"))
        ctx.response_kind = "fcp" if p2 == 0x00 else ("tlv" if p2 == 0x01 else "")
    elif ins in (0xB0, 0xD6):
        ctx.summary = _binary_offset(p1, p2)
        ctx.header.append(_field("P1 P2", f"{p1:02X} {p2:02X}", _binary_offset(p1, p2), spec="TS 102 221 v18.4 table 11.10"))
        ctx.payload_kind = "file_content" if ins == 0xD6 else ""
        ctx.response_kind = "file_content" if ins == 0xB0 else ""
    elif ins in (0xB2, 0xDC):
        ctx.summary = _record_mode(p2)
        ctx.header.append(_field("P1", f"{p1:02X}", f"record number {p1}" if p1 else "current record / not used", spec="TS 102 221 v18.4 section 11.1.5.2"))
        ctx.header.append(_field("P2", f"{p2:02X}", _record_mode(p2), spec="TS 102 221 v18.4 table 11.11"))
        ctx.payload_kind = "file_record" if ins == 0xDC else ""
        ctx.response_kind = "file_record" if ins == 0xB2 else ""
    elif ins in (0x20, 0x24, 0x26, 0x28, 0x2C):
        key_ref = p2 & 0x1F
        ctx.summary = f"PIN key reference {key_ref:02X}"
        ctx.header.append(_field("P2", f"{p2:02X}", f"PIN key reference number {key_ref:02X} (b1-b5)", spec="TS 102 221 v18.4 section 11.1.9"))
        if ins == 0x26 and p1 & 0x80:
            ctx.header.append(_field("P1", f"{p1:02X}", f"verification data present, use global key reference {p1 & 0x1F:02X} as replacement", spec="TS 102 221 v18.4 table 11.16"))
        if ins in (0x20, 0x2C) and len(data) == 0:
            ctx.notes.append("Empty data field: the command queries the retry counter, answered in SW '63 CX' (TS 102 221 v18.4 section 11.1.13.1.2).")
        ctx.payload_kind = "pin"
    elif ins == 0x70:
        op = "open logical channel" if p1 == 0x00 else ("close logical channel" if p1 == 0x80 else "RFU")
        ctx.summary = op
        ctx.header.append(_field("P1", f"{p1:02X}", op, spec="TS 102 221 v18.4 table 11.19"))
        ctx.header.append(_field("P2", f"{p2:02X}", "channel assigned by the UICC" if p2 == 0 else f"logical channel number {p2}", spec="TS 102 221 v18.4 table 11.20"))
        ctx.response_kind = "channel_number"
    elif ins == 0xC0:
        ctx.summary = "fetch response data left pending by the previous command"
        ctx.response_kind = "chained"
    elif ins == 0xA2:
        ctx.summary = "search records"
        ctx.header.append(_field("P1", f"{p1:02X}", f"record number {p1}" if p1 else "current record"))
    else:
        ctx.summary = name_summary(ins)
        if ins == 0xAA:
            ctx.payload_kind = "terminal_capability"
        elif ins == 0x78:
            ctx.response_kind = "suci"
    if ctx.payload_kind == "" and len(data) > 0:
        ctx.payload_kind = "tlv"


def name_summary(ins: int) -> str:
    return _UICC_INS.get(ins, f"INS {ins:02X}").lower()


def _auth_context(ins: int, p2: int) -> str:
    # TS 31.102 v19.5 tables 7.1.2-1 (even INS) and 7.1.2-2 (odd INS).
    context = p2 & 0x07
    specific = "specific reference data, " if p2 & 0x80 else ""
    if ins == 0x89:
        name = {0x05: "MBMS context", 0x06: "Local Key Establishment mode"}.get(context, "RFU context")
    else:
        name = {0x00: "GSM context", 0x01: "3G/EPS/5G context", 0x02: "VGCS/VBS context", 0x04: "GBA context"}.get(context, "RFU context")
    return specific + name


def _store_data_fields(p1: int, p2: int) -> list[dict[str, Any]]:
    # GPC v2.3.1 table 11-89.
    parts = ["last block" if p1 & 0x80 else "more blocks"]
    enc = (p1 >> 5) & 0x03
    parts.append({0: "no general encryption information or non-encrypted data", 1: "application dependent encryption", 2: "RFU encryption indicator", 3: "encrypted data"}[enc])
    structure = (p1 >> 3) & 0x03
    parts.append({0: "no general data structure information", 1: "DGI format", 2: "BER-TLV format", 3: "RFU data structure"}[structure])
    parts.append("ISO case 4 (response data may be returned)" if p1 & 0x01 else "ISO case 3 (no response data)")
    return [
        _field("P1", f"{p1:02X}", "; ".join(parts), spec="GPC v2.3.1 table 11-89"),
        _field("P2", f"{p2:02X}", f"block number {p2}", spec="GPC v2.3.1 table 11-88"),
    ]


# ----------------------------------------------------------------------
# GlobalPlatform payload decoders
# ----------------------------------------------------------------------


def _gp_life_cycle_name(value: int, kind: str) -> str:
    """GPC v2.3.1 tables 11-3 to 11-6; ``kind`` is elf, app, sd, card or any."""
    if kind == "elf":
        return {0x00: "LOGICALLY DELETED WITH REFERENCES", 0x01: "LOADED"}.get(value, "RFU")
    if kind == "card":
        return {0x01: "OP_READY", 0x07: "INITIALIZED", 0x0F: "SECURED", 0x7F: "CARD_LOCKED", 0xFF: "TERMINATED"}.get(value, "RFU")
    if kind in ("app", "sd", "any"):
        if value & 0x80 and (value & 0x03) == 0x03:
            return "LOCKED"
        if value == 0x03:
            return "INSTALLED"
        if value == 0x07:
            return "SELECTABLE"
        if value == 0x0F and kind != "app":
            return "PERSONALIZED"
        if (value & 0x07) == 0x07 and not value & 0x80:
            return "application specific state"
        if kind == "any":
            card = _gp_life_cycle_name(value, "card")
            if card != "RFU":
                return card
        return "RFU"
    return "RFU"


_PRIVILEGE_BITS: tuple[tuple[int, int, str], ...] = (
    # (byte index, mask, name) per GPC v2.3.1 tables 11-7, 11-8 and 11-9.
    (0, 0x80, "Security Domain"),
    (0, 0x20, "Delegated Management"),
    (0, 0x10, "Card Lock"),
    (0, 0x08, "Card Terminate"),
    (0, 0x04, "Card Reset"),
    (0, 0x02, "CVM Management"),
    (1, 0x80, "Trusted Path"),
    (1, 0x40, "Authorized Management"),
    (1, 0x20, "Token Management"),
    (1, 0x10, "Global Delete"),
    (1, 0x08, "Global Lock"),
    (1, 0x04, "Global Registry"),
    (1, 0x02, "Final Application"),
    (1, 0x01, "Global Service"),
    (2, 0x80, "Receipt Generation"),
    (2, 0x40, "Ciphered Load File Data Block"),
    (2, 0x20, "Contactless Activation"),
    (2, 0x10, "Contactless Self-Activation"),
    (2, 0x08, "Self-Removal"),
)


def _gp_privileges(value: bytes) -> list[str]:
    names: list[str] = []
    if len(value) >= 1 and value[0] & 0x80 and value[0] & 0x40:
        # Table 11-7: b8 b7 set with b1 = 0 is DAP Verification, with b1 = 1
        # Mandated DAP Verification.
        names.append("Mandated DAP Verification" if value[0] & 0x01 else "DAP Verification")
    for index, mask, name in _PRIVILEGE_BITS:
        if index < len(value) and value[index] & mask:
            names.append(name)
    return names


_GP_REGISTRY_TAGS = {
    "4F": "AID",
    "9F70": "Life Cycle State",
    "C5": "Privileges",
    "CF": "Implicit selection parameter",
    "C4": "Executable Load File AID",
    "CC": "Associated Security Domain AID",
    "CE": "Executable Load File version number",
    "84": "Executable Module AID",
}
_GP_REGISTRY_SPEC = "GPC v2.3.1 tables 11-36 / 11-37"


def _registry_kind_from_p1(p1: int | None) -> str:
    if p1 is None:
        return "any"
    if p1 & 0x80:
        return "card"
    if p1 & 0x40:
        return "sd"
    if p1 & 0x38:
        return "elf"
    return "any"


def decode_gp_registry(data: bytes, *, subset_p1: int | None = None) -> dict[str, Any]:
    kind = _registry_kind_from_p1(subset_p1)
    entries = _iter_tlvs(data)
    nodes: list[dict[str, Any]] = []
    for entry in entries:
        if entry.tag_hex != "E3":
            nodes.append(_node(entry.tag_hex, "unexpected object outside E3", entry.value))
            continue
        children: list[dict[str, Any]] = []
        entry_children = _iter_tlvs(entry.value)
        # Within the Applications subset an entry with the Security Domain
        # privilege (GPC v2.3.1 table 11-7) reads its state from table 11-5,
        # any other application from table 11-4.
        entry_kind = kind
        if kind in ("sd", "any"):
            privileges = [child.value for child in entry_children if child.tag_hex == "C5"]
            if privileges and not (privileges[0] and privileges[0][0] & 0x80):
                entry_kind = "app"
            elif privileges:
                entry_kind = "sd"
        for child in entry_children:
            name = _GP_REGISTRY_TAGS.get(child.tag_hex, "")
            decoded: Any = None
            if child.tag_hex in ("4F", "C4", "CC", "84"):
                decoded = aid_name(child.value) or None
            elif child.tag_hex == "9F70" and len(child.value) == 1:
                lcs_kind = entry_kind
                if kind == "elf" and child.value[0] not in (0x00, 0x01):
                    lcs_kind = "any"
                decoded = _gp_life_cycle_name(child.value[0], lcs_kind)
            elif child.tag_hex == "C5":
                decoded = ", ".join(_gp_privileges(child.value)) or "none"
            elif child.tag_hex == "CE":
                decoded = ".".join(str(byte) for byte in child.value) if child.value else None
            children.append(_node(child.tag_hex, name or "data object", child.value, spec=_GP_REGISTRY_SPEC if name else "", decoded=decoded))
        nodes.append(_node("E3", "GlobalPlatform Registry related data", entry.value, spec=_GP_REGISTRY_SPEC, children=children))
    payload = _payload("gp_registry", "GlobalPlatform registry entries", _GP_REGISTRY_SPEC, nodes=nodes)
    if not _tlvs_cover(data, entries):
        payload["notes"] = ["Data is not a complete sequence of E3 templates; the deprecated compact format (P2.b2 = 0) is not decoded."]
    return payload


def _read_lv(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(data):
        raise DecodeError("INSTALL data ends before a length field")
    length = data[offset]
    start = offset + 1
    # GPC v2.3.1 tables 11-42 to 11-46: the parameter and token lengths use
    # the BER form '81 xx' / '82 xx xx' above 127 bytes.
    if length == 0x81:
        length = data[start]
        start += 1
    elif length == 0x82:
        length = int.from_bytes(data[start : start + 2], "big")
        start += 2
    end = start + length
    if end > len(data):
        raise DecodeError("INSTALL length field overruns the data")
    return data[start:end], end


_INSTALL_PARAMETER_TAGS = {
    # GPC v2.3.1 tables 11-48 to 11-52.
    "C9": "Application specific parameters",
    "EF": "System specific parameters",
    "C6": "Non-volatile code minimum memory requirement",
    "C7": "Volatile memory (deprecated)",
    "C8": "Non-volatile memory quota / minimum requirement",
    "CD": "Load File Data Block format id",
    "DD": "Load File Data Block parameters",
    "CB": "Global service parameters",
    "D7": "Volatile reserved memory (deprecated)",
    "D8": "Non-volatile reserved memory (deprecated)",
    "82": "Cumulative granted volatile memory (deprecated)",
    "83": "Cumulative granted non-volatile memory",
    "CA": "TS 102 226 specific parameter",
    "CF": "Implicit selection parameter",
    "EA": "TS 102 226 specific template",
    "B6": "Control Reference Template",
    "42": "Identification number of the SD with Token Verification privilege",
    "45": "Image number of the SD with Token Verification privilege",
    "5F20": "Application Provider Identifier",
    "93": "Token identifier / number",
    "D9": "Restrict parameter",
}


def _install_parameter_nodes(data: bytes) -> list[dict[str, Any]]:
    items = _iter_tlvs(data)
    if not _tlvs_cover(data, items):
        return [_node("", "parameters (not BER-TLV)", data)]
    nodes: list[dict[str, Any]] = []
    for item in items:
        name = _INSTALL_PARAMETER_TAGS.get(item.tag_hex, "parameter")
        children = None
        decoded: Any = None
        if item.tag_hex in ("EF", "B6", "EA") and item.value:
            children = _install_parameter_nodes(item.value)
        elif item.tag_hex in ("C6", "C7", "C8", "D7", "D8", "82", "83") and len(item.value) in (2, 4):
            decoded = f"{_int(item.value)} bytes"
        elif item.tag_hex == "D9" and len(item.value) == 1:
            restrict = []
            for mask, label in ((0x40, "Registry Update"), (0x20, "Personalization"), (0x10, "Extradition"), (0x08, "Make selectable"), (0x04, "Install"), (0x02, "Load"), (0x01, "Delete")):
                if item.value[0] & mask:
                    restrict.append(label)
            decoded = "disable: " + (", ".join(restrict) or "nothing")
        nodes.append(_node(item.tag_hex, name, item.value, spec="GPC v2.3.1 tables 11-48 to 11-52", decoded=decoded, children=children))
    return nodes


def decode_gp_install(p1: int, data: bytes) -> dict[str, Any]:
    roles = _gp_install_roles(p1)
    fields: list[dict[str, Any]] = []
    notes: list[str] = []
    nodes: list[dict[str, Any]] = []

    def take(label: str, offset: int, *, aid: bool = False, privileges: bool = False, params: bool = False) -> int:
        value, next_offset = _read_lv(data, offset)
        meaning = ""
        if aid and value:
            meaning = aid_name(value)
        if privileges and value:
            meaning = ", ".join(_gp_privileges(value)) or "none"
        fields.append(_field(label, _hex(value) if value else "(empty)", meaning))
        if params and value:
            nodes.extend(_install_parameter_nodes(value))
        return next_offset

    try:
        if "for load" in roles and "for install" not in roles:
            # GPC v2.3.1 table 11-42.
            spec = "GPC v2.3.1 table 11-42"
            offset = take("Load File AID", 0, aid=True)
            offset = take("Security Domain AID", offset, aid=True)
            offset = take("Load File Data Block Hash", offset)
            offset = take("Load parameters", offset, params=True)
            offset = take("Load Token", offset)
        elif "for install" in roles:
            # GPC v2.3.1 table 11-43 (also the final combined command).
            spec = "GPC v2.3.1 table 11-43"
            offset = take("Executable Load File AID", 0, aid=True)
            offset = take("Executable Module AID", offset, aid=True)
            offset = take("Application AID", offset, aid=True)
            offset = take("Privileges", offset, privileges=True)
            offset = take("Install parameters", offset, params=True)
            offset = take("Install Token", offset)
        elif "for make selectable" in roles:
            spec = "GPC v2.3.1 table 11-44"
            offset = take("Length of data (00)", 0)
            offset = take("Length of data (00)", offset)
            offset = take("Application AID", offset, aid=True)
            offset = take("Privileges", offset, privileges=True)
            offset = take("Make Selectable parameters", offset, params=True)
            offset = take("Make Selectable Token", offset)
        elif "for extradition" in roles:
            spec = "GPC v2.3.1 table 11-45"
            offset = take("Security Domain AID", 0, aid=True)
            offset = take("Length of data (00)", offset)
            offset = take("Application or Executable Load File AID", offset, aid=True)
            offset = take("Length (00)", offset)
            offset = take("Extradition parameters", offset, params=True)
            offset = take("Extradition Token", offset)
        elif "for registry update" in roles:
            spec = "GPC v2.3.1 table 11-46"
            offset = take("Security Domain AID", 0, aid=True)
            offset = take("Length of data (00)", offset)
            offset = take("Application AID", offset, aid=True)
            offset = take("Privileges", offset, privileges=True)
            offset = take("Registry Update parameters", offset, params=True)
            offset = take("Registry Update Token", offset)
        elif "for personalization" in roles:
            spec = "GPC v2.3.1 table 11-47"
            offset = take("Length of data (00)", 0)
            offset = take("Length of data (00)", offset)
            offset = take("Application AID", offset, aid=True)
            offset = take("Length of data (00)", offset)
            offset = take("Length of data (00)", offset)
            offset = take("Length of data (00)", offset)
        else:
            spec = "GPC v2.3.1 table 11-41"
            offset = len(data)
            notes.append("No INSTALL role bit is set in P1; the data field is shown raw.")
        if offset != len(data):
            notes.append(f"{len(data) - offset} trailing byte(s) after the last field.")
    except DecodeError as error:
        notes.append(f"Data field is shorter than the table requires: {error}")
        spec = "GPC v2.3.1 section 11.5.2.3"
    title = "INSTALL " + " ".join(f"[{role}]" for role in roles) if roles else "INSTALL"
    return _payload("gp_install", title, spec, fields=fields, nodes=nodes, notes=notes)


def decode_gp_delete(data: bytes) -> dict[str, Any]:
    items = _iter_tlvs(data)
    nodes: list[dict[str, Any]] = []
    names = {
        "4F": ("AID of Executable Load File, Application or Security Domain", "GPC v2.3.1 table 11-23"),
        "B6": ("Control Reference Template", "GPC v2.3.1 table 11-23"),
        "9E": ("Delete Token", "GPC v2.3.1 table 11-23"),
        "D0": ("Key Identifier", "GPC v2.3.1 table 11-24"),
        "D2": ("Key Version Number", "GPC v2.3.1 table 11-24"),
    }
    for item in items:
        name, spec = names.get(item.tag_hex, ("data object", ""))
        children = _install_parameter_nodes(item.value) if item.tag_hex == "B6" and item.value else None
        decoded = aid_name(item.value) or None if item.tag_hex == "4F" else None
        if item.tag_hex in ("D0", "D2") and len(item.value) == 1:
            decoded = str(item.value[0])
        nodes.append(_node(item.tag_hex, name, item.value, spec=spec, decoded=decoded, children=children))
    kind = "key" if any(item.tag_hex in ("D0", "D2") for item in items) else "card content"
    payload = _payload("gp_delete", f"DELETE [{kind}] data field", "GPC v2.3.1 tables 11-23 / 11-24", nodes=nodes)
    if not _tlvs_cover(data, items):
        payload["notes"] = ["Data field is not a complete TLV sequence."]
    return payload


def decode_gp_confirmation(data: bytes, command: str) -> dict[str, Any]:
    # GPC v2.3.1 tables 11-25 (DELETE) and 11-54 (INSTALL): a length byte
    # ('81 xx' above 127) followed by the optional confirmation.
    fields: list[dict[str, Any]] = []
    if len(data) == 1 and data[0] == 0x00:
        fields.append(_field("Confirmation", "(none)", "single '00': no additional data"))
    elif data:
        try:
            confirmation, end = _read_lv(data, 0)
            fields.append(_field("Confirmation length", len(confirmation)))
            if confirmation:
                fields.append(_field("Confirmation", _hex(confirmation), "Delegated Management receipt (GPC v2.3.1 section 11.1.6)"))
            if end != len(data):
                fields.append(_field("Trailing bytes", _hex(data[end:])))
        except DecodeError:
            fields.append(_field("Response", _hex(data), "does not follow the length-prefixed layout"))
    spec = "GPC v2.3.1 table 11-25" if command == "DELETE" else "GPC v2.3.1 table 11-54"
    return _payload("gp_confirmation", f"{command} response", spec, fields=fields)


_GP_GET_DATA_TAGS = {
    # GPC v2.3.1 section 11.3.2.1 and tables 11-30 / 11-30b.
    "42": "Issuer Identification Number",
    "45": "Card Image Number",
    "66": "Card Data (Security Domain recognition data)",
    "E0": "Key Information Template",
    "E1": "Individual Key Information",
    "D5": "Key Version Number of the default Secure Channel key set",
    "2F00": "List of applications",
    "FF21": "Extended Card Resources (TS 102 226)",
    "A0": "Token Identifier Deny List",
}


def _gp_get_data_tag_name(tag_hex: str) -> str:
    known = _GP_GET_DATA_TAGS.get(tag_hex.upper())
    if known:
        return known
    exact = _registry().lookup_exact(tag_hex)
    return exact.name.replace("_", " ").lower() if exact is not None else "data object"


def decode_gp_get_data_response(tag_hex: str, data: bytes, registry: TagRegistry) -> dict[str, Any]:
    items = _iter_tlvs(data)
    nodes: list[dict[str, Any]] = []
    if tag_hex.upper() == "2F00" and _tlvs_cover(data, items):
        for item in items:
            children = []
            for child in _iter_tlvs(item.value):
                children.append(_node(child.tag_hex, "Application AID" if child.tag_hex == "4F" else "data object", child.value, spec="GPC v2.3.1 table 11-30", decoded=aid_name(child.value) or None))
            nodes.append(_node(item.tag_hex, "Application Template" if item.tag_hex == "61" else "data object", item.value, spec="GPC v2.3.1 table 11-30", children=children))
        return _payload("gp_get_data", "List of on-card applications", "GPC v2.3.1 table 11-30", nodes=nodes)
    tree = _generic_tree(data, registry)
    if tree is not None:
        nodes = _tree_to_nodes(tree)
        if len(nodes) == 1:
            nodes[0]["name"] = _gp_get_data_tag_name(nodes[0]["tag"])
            nodes[0]["spec"] = "GPC v2.3.1 section 11.3.2.1"
            if nodes[0]["tag"] == "E0":
                _name_key_information(nodes[0])
    else:
        nodes = [_node(tag_hex, _gp_get_data_tag_name(tag_hex), data)]
    return _payload("gp_get_data", f"GET DATA '{tag_hex}' response", "GPC v2.3.1 section 11.3.3", nodes=nodes)


def _name_key_information(template: dict[str, Any]) -> None:
    """Read each Key Information Data entry 'C0' of a Key Information Template in words."""
    from . import payload_readings

    for child in template.get("children") or []:
        if child.get("tag") != "C0":
            continue
        try:
            reading = payload_readings.key_information_text(bytes.fromhex(str(child.get("valueHex") or "")))
        except ImportError:
            reading = None
        child["name"] = "Key Information Data"
        child["spec"] = "GPC v2.4 section 11.3.3.1"
        if reading:
            child["decoded"] = reading


def decode_scp_init_update_response(data: bytes) -> dict[str, Any]:
    # GPC Amd D v1.1.2 table 7-3.
    fields: list[dict[str, Any]] = []
    if len(data) < 29:
        return _payload("scp_init_update", "INITIALIZE UPDATE response", "GPC Amd D v1.1.2 table 7-3", fields=[_field("Response", _hex(data), f"{len(data)} bytes; the table needs 29 or 32")])
    key_info = data[10:13]
    fields.append(_field("Key diversification data", _hex(data[0:10]), "backend input for static key derivation"))
    fields.append(_field("Key version number", f"{key_info[0]:02X}"))
    fields.append(_field("Secure Channel Protocol", f"{key_info[1]:02X}", "SCP03" if key_info[1] == 0x03 else "not SCP03"))
    fields.append(_field("SCP i parameter", f"{key_info[2]:02X}"))
    fields.append(_field("Card challenge", _hex(data[13:21])))
    fields.append(_field("Card cryptogram", _hex(data[21:29])))
    if len(data) >= 32:
        fields.append(_field("Sequence counter", _hex(data[29:32]), "present when SCP03 uses pseudo-random challenges"))
    if len(data) not in (29, 32):
        fields.append(_field("Trailing bytes", _hex(data[32:] if len(data) > 32 else data[29:])))
    return _payload("scp_init_update", "INITIALIZE UPDATE response", "GPC Amd D v1.1.2 table 7-3", fields=fields)


# ----------------------------------------------------------------------
# ETSI TS 102 221 file control parameters
# ----------------------------------------------------------------------

_FCP_TAGS = {
    # TS 102 221 v18.4 tables 11.3 and 11.4, clause numbers per column.
    "80": ("File size", "TS 102 221 v18.4 section 11.1.1.4.1"),
    "81": ("Total file size", "TS 102 221 v18.4 section 11.1.1.4.2"),
    "82": ("File descriptor", "TS 102 221 v18.4 section 11.1.1.4.3"),
    "83": ("File identifier", "TS 102 221 v18.4 section 11.1.1.4.4"),
    "84": ("DF name (AID)", "TS 102 221 v18.4 section 11.1.1.4.5"),
    "A5": ("Proprietary information", "TS 102 221 v18.4 section 11.1.1.4.6"),
    "8B": ("Security attributes (referenced to expanded format)", "TS 102 221 v18.4 section 11.1.1.4.7"),
    "8C": ("Security attributes (compact format)", "TS 102 221 v18.4 section 11.1.1.4.7"),
    "AB": ("Security attributes (expanded format)", "TS 102 221 v18.4 section 11.1.1.4.7"),
    "88": ("Short file identifier", "TS 102 221 v18.4 section 11.1.1.4.8"),
    "8A": ("Life cycle status integer", "TS 102 221 v18.4 section 11.1.1.4.9"),
    "C6": ("PIN status template DO", "TS 102 221 v18.4 section 11.1.1.4.10"),
}


def _lcs_text(value: int) -> str:
    # TS 102 221 v18.4 table 11.7b.
    if value == 0x00:
        return "no information given"
    if value & 0xF0:
        return "proprietary"
    if value & 0x0C == 0x0C:
        return "termination state"
    if value & 0x04:
        return "operational state - activated" if value & 0x01 else "operational state - deactivated"
    if value == 0x01:
        return "creation state"
    if value == 0x03:
        return "initialisation state"
    return "RFU"


def _fs_helpers() -> dict[str, Callable[..., Any]]:
    try:
        from SCP03.logic import fs as fs_module
    except Exception:  # noqa: BLE001 - the shell package is optional here
        return {}
    return {
        "descriptor": getattr(fs_module, "_decode_file_descriptor", None),
        "referenced": getattr(fs_module, "_decode_referenced_security", None),
        "pins": getattr(fs_module, "_decode_pin_status_template", None),
        "proprietary": getattr(fs_module, "_decode_proprietary_information", None),
    }


def decode_fcp(data: bytes) -> dict[str, Any]:
    """Decode a SELECT / STATUS response: '62' FCP template or '6F' FCI."""
    outer = _iter_tlvs(data)
    if len(outer) != 1 or not _tlvs_cover(data, outer):
        return _payload("fcp", "Response is not one FCP template", "TS 102 221 v18.4 section 11.1.1.3", notes=["Expected a single '62' template."])
    template = outer[0]
    if template.tag_hex == "6F":
        return _decode_gp_fci(template.value)
    if template.tag_hex != "62":
        return _payload("fcp", f"Unexpected template '{template.tag_hex}'", "TS 102 221 v18.4 section 11.1.1.3")
    helpers = _fs_helpers()
    nodes: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    for item in _iter_tlvs(template.value):
        name, spec = _FCP_TAGS.get(item.tag_hex, ("data object", ""))
        decoded: Any = None
        children = None
        if item.tag_hex == "82":
            descriptor = helpers.get("descriptor")
            if descriptor is not None:
                info = descriptor(item.value)
                parts = [str(info.get("file_kind") or info.get("type") or "")]
                if info.get("structure") and info.get("structure") != "Tree":
                    parts.append(str(info["structure"]))
                if info.get("shareable") is not None:
                    parts.append("shareable" if info["shareable"] else "not shareable")
                if info.get("rec_len"):
                    parts.append(f"record length {info['rec_len']}, {info.get('rec_count', 0)} record(s)")
                decoded = ", ".join(part for part in parts if part)
                summary["file"] = decoded
        elif item.tag_hex == "83":
            decoded = _hex(item.value)
            summary["fid"] = decoded
        elif item.tag_hex == "84":
            decoded = aid_name(item.value) or None
            summary["aid"] = _hex(item.value)
        elif item.tag_hex in ("80", "81"):
            decoded = f"{_int(item.value)} bytes"
        elif item.tag_hex == "88":
            decoded = "SFI not supported for this file" if len(item.value) == 0 else f"SFI {item.value[0] >> 3}"
        elif item.tag_hex == "8A" and len(item.value) == 1:
            decoded = _lcs_text(item.value[0])
        elif item.tag_hex == "8B":
            referenced = helpers.get("referenced")
            if referenced is not None:
                info = referenced(item.value)
                if info.get("arr_fid"):
                    decoded = f"EF_ARR {info['arr_fid']} record {info.get('arr_record')}"
                    if info.get("arr_se_records"):
                        decoded += " (per SEID: " + ", ".join(f"{seid}->{record}" for seid, record in info["arr_se_records"].items()) + ")"
        elif item.tag_hex == "C6":
            pins = helpers.get("pins")
            if pins is not None:
                entries = pins(item.value)
                decoded = "; ".join(
                    f"{entry.get('name') or entry.get('key_ref')} {'enabled' if entry.get('enabled') else 'disabled'}"
                    + ("" if entry.get("verify_required", True) else " (not used for verification)")
                    for entry in entries
                ) or "no PIN references"
        elif item.tag_hex == "A5":
            proprietary = helpers.get("proprietary")
            if proprietary is not None:
                info = proprietary(item.value)
                decoded = ", ".join(f"{key} {value}" for key, value in info.items()) or None
            children = [_node(child.tag_hex, "proprietary data object", child.value) for child in _iter_tlvs(item.value)]
        nodes.append(_node(item.tag_hex, name, item.value, spec=spec, decoded=decoded, children=children))
    title = "FCP template"
    if summary.get("fid"):
        title += f" for file {summary['fid']}"
    elif summary.get("aid"):
        title += " for ADF " + (aid_name(bytes.fromhex(summary["aid"])) or summary["aid"])
    return _payload("fcp", title, "TS 102 221 v18.4 tables 11.3 / 11.4", nodes=nodes, summary=summary)


def _decode_gp_fci(value: bytes) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    for item in _iter_tlvs(value):
        if item.tag_hex == "84":
            nodes.append(_node("84", "Application / file AID", item.value, decoded=aid_name(item.value) or None))
        elif item.tag_hex == "A5":
            children = [_node(child.tag_hex, "proprietary data object", child.value) for child in _iter_tlvs(item.value)]
            nodes.append(_node("A5", "Proprietary data", item.value, children=children))
        else:
            nodes.append(_node(item.tag_hex, "data object", item.value))
    return _payload("fci", "FCI template (GlobalPlatform SELECT response)", "ISO/IEC 7816-4 FCI, GPC v2.3.1 section 11.9", nodes=nodes)


# ----------------------------------------------------------------------
# Card Application Toolkit
# ----------------------------------------------------------------------

# ETSI TS 101 220 v19 table 7.17: BER-TLV tags in the UICC-to-terminal and
# terminal-to-UICC directions.
_CAT_BER_TAGS = {
    0xD0: "Proactive UICC command",
    0xD1: "SMS-PP download",
    0xD2: "Cell Broadcast download",
    0xD3: "Menu selection",
    0xD4: "Call control",
    0xD5: "MO short message control",
    0xD6: "Event download",
    0xD7: "Timer expiration",
    0xD9: "USSD download",
    0xDA: "MMS transfer status",
    0xDB: "MMS notification download",
    0xDC: "Terminal application",
    0xDD: "Geographical location reporting",
    0xDE: "Envelope container",
    0xDF: "ProSe report",
    0xE0: "5G ProSe report",
}

# ETSI TS 101 220 v19 table 7.23: COMPREHENSION-TLV tag values (bits 1-7).
# Since Release 10 a tag value is context specific, so an entry lists every
# object the table assigns to it, separated by " / ", in table order.
_CTLV_TAGS = {
    0x01: "Command details", 0x02: "Device identities", 0x03: "Result", 0x04: "Duration",
    0x05: "Alpha identifier", 0x06: "Address", 0x07: "Capability configuration parameters",
    0x08: "Subaddress", 0x09: "SS string / BSSID / PLMN ID / E-UTRAN timing advance",
    0x0A: "USSD string / HESSID", 0x0B: "SMS TPDU / PDP-PDN-PDU type",
    0x0C: "Cell Broadcast page / PDU session establishment parameters",
    0x0D: "Text string", 0x0E: "Tone / eCAT client profile", 0x0F: "Item / eCAT client identity",
    0x10: "Item identifier / encapsulated envelope type", 0x11: "Response length / call control result",
    0x12: "File list / CAT service list / LSI numbers", 0x13: "Location information", 0x14: "IMEI",
    0x15: "Help request", 0x16: "Network measurement results", 0x17: "Default text",
    0x18: "Items next action indicator", 0x19: "Event list", 0x1A: "Cause",
    0x1B: "Location status", 0x1C: "Transaction identifier",
    0x1D: "BCCH channel list / data connection status",
    0x1E: "Icon identifier", 0x1F: "Item icon identifier list", 0x20: "Card reader status",
    0x21: "Card ATR / eCAT sequence number", 0x22: "C-APDU / encrypted TLV list",
    0x23: "R-APDU / SA template", 0x24: "Timer identifier",
    0x25: "Timer value", 0x26: "Date-time and time zone", 0x27: "Call control requested action",
    0x28: "AT command", 0x29: "AT response", 0x2A: "BC repeat indicator / data connection type",
    0x2B: "Immediate response", 0x2C: "DTMF string", 0x2D: "Language",
    0x2E: "Timing advance / (E/5G)SM cause",
    0x2F: "AID", 0x30: "Browser identity",
    0x31: "URL / IMS URI / NG-RAN primary timing advance information / rejected slices information",
    0x32: "Bearer", 0x33: "Provisioning reference file",
    0x34: "Browser termination cause / supported radio access technologies",
    0x35: "Bearer description", 0x36: "Channel data", 0x37: "Channel data length",
    0x38: "Channel status", 0x39: "Buffer size",
    0x3A: "Card reader identifier / REFRESH enforcement policy",
    0x3B: "File update information / application specific refresh data",
    0x3C: "UICC/terminal interface transport level", 0x3D: "Not used",
    0x3E: "Other address (data destination address)", 0x3F: "Access technology",
    0x40: "Display parameters / DNS server address", 0x41: "Service record", 0x42: "Device filter",
    0x43: "Service search", 0x44: "Attribute information", 0x45: "Service availability",
    0x46: "Reserved for 3GPP2 (3GPP2 tag 1)", 0x47: "Network access name",
    0x48: "Reserved for 3GPP2 (3GPP2 tag 2)", 0x49: "Remote entity address",
    0x4A: "I-WLAN identifier / SSID", 0x4B: "(I-)WLAN access status / more data",
    0x50: "Text attribute", 0x51: "Item text attribute list",
    0x52: "PDP context activation parameters / surrounding macrocells",
    0x53: "Contactless state request", 0x54: "Contactless functionality state",
    0x55: "CSG cell selection status / IMS call disconnection cause / CAG cell selection status / slice status",
    0x56: "CSG ID / slice information / CAG information list / E-UTRAN TAI list identifier",
    0x57: "HNB name / extended rejection cause code / CAG network name list / NG-RAN TAI list identifier"
    " / rejected slices information with S-NSSAI mapping",
    0x60: "MAC", 0x61: "Reserved for 3GPP2 (3GPP2 tag 3)", 0x62: "IMEISV", 0x63: "Battery state",
    0x64: "Browsing status", 0x65: "Network search mode", 0x66: "Frame layout",
    0x67: "Frames information / profile ID", 0x68: "Frame identifier",
    0x69: "UTRAN/E-UTRAN/NG-RAN measurement qualifier / IP address list",
    0x6A: "Multimedia message reference", 0x6B: "Multimedia message identifier",
    0x6C: "Multimedia message transfer status", 0x6D: "Reserved for 3GPP2 (3GPP2 tag 4)",
    0x6E: "Multimedia message content identifier", 0x6F: "Multimedia message notification",
    0x70: "Last envelope", 0x71: "Registry application data / 5G ProSe report data",
    0x72: "PLMNwAcT list / extended information",
    0x73: "Routing area information / URI truncated / SoR-CMCI",
    0x74: "Update/attach type / ProSe report data", 0x75: "Rejection cause code",
    0x76: "Geographical location parameters / IARI",
    0x77: "GAD shapes / IMPU list / allowed slices information with S-NSSAI mapping",
    0x78: "NMEA sentence / IMS status-code / allowed slices information",
    0x79: "PLMN list / E-UTRAN inter-frequency network measurement results / partial NSSAI",
    0x7A: "Broadcast network information / extended registry application data",
    0x7B: "ACTIVATE descriptor", 0x7C: "EPS PDN connection activation parameters / DNN list",
    0x7D: "Tracking area identification", 0x7E: "CSG ID list / media type",
}
_CTLV_SPEC = "ETSI TS 101 220 v19 table 7.23"

# ETSI TS 102 223 v18.3 section 8.7.
_CAT_DEVICES = {0x01: "Keypad", 0x02: "Display", 0x03: "Earpiece", 0x81: "UICC", 0x82: "Terminal", 0x83: "Network"}

# ETSI TS 102 223 v18.3 section 8.12: general result.
_CAT_RESULTS = {
    0x00: "Command performed successfully",
    0x01: "Command performed with partial comprehension",
    0x02: "Command performed, with missing information",
    0x03: "REFRESH performed with additional EFs read",
    0x04: "Command performed successfully, but requested icon could not be displayed",
    0x05: "Command performed, but modified by call control by NAA",
    0x06: "Command performed successfully, limited service",
    0x07: "Command performed with modification",
    0x08: "REFRESH performed but indicated NAA was not active",
    0x09: "Command performed successfully, tone not played",
    0x10: "Proactive UICC session terminated by the user",
    0x11: "Backward move in the proactive UICC session requested by the user",
    0x12: "No response from user",
    0x13: "Help information required by the user",
    0x20: "Terminal currently unable to process command",
    0x21: "Network currently unable to process command",
    0x22: "User did not accept the proactive command",
    0x23: "User cleared down call before connection or network release",
    0x24: "Action in contradiction with the current timer state",
    0x25: "Interaction with call control by NAA, temporary problem",
    0x26: "Launch browser generic error",
    0x27: "MMS temporary problem",
    0x28: "Bearer Independent Protocol temporary error",
    0x30: "Command beyond terminal's capabilities",
    0x31: "Command type not understood by terminal",
    0x32: "Command data not understood by terminal",
    0x33: "Command number not known by terminal",
    0x36: "Error, required values are missing",
    0x38: "MultipleCard commands error",
    0x39: "Interaction with call control by NAA, permanent problem",
    0x3A: "Bearer Independent Protocol permanent error",
    0x3B: "Access Technology unable to process command",
    0x3C: "Frames error",
    0x3D: "MMS error",
}


def _cat_tables() -> tuple[dict[int, str], dict[int, str]]:
    try:
        from yggdrasim_common.stk_tables import EVENT_LIST, PROACTIVE_COMMANDS
    except Exception:  # noqa: BLE001
        return {}, {}
    return dict(PROACTIVE_COMMANDS), dict(EVENT_LIST)


def _device_name(value: int) -> str:
    if value in _CAT_DEVICES:
        return _CAT_DEVICES[value]
    if 0x10 <= value <= 0x17:
        return f"Additional card reader {value - 0x10}"
    if 0x21 <= value <= 0x27:
        return f"Channel {value - 0x20}"
    if 0x31 <= value <= 0x3F:
        return f"eCAT client {value - 0x30:X}"
    return "reserved"


def _iter_comprehension_tlvs(data: bytes) -> tuple[list[tuple[int, bool, bytes, bytes]], bool]:
    """Yield (tag, comprehension_required, value, raw); flag says all bytes parsed."""
    items: list[tuple[int, bool, bytes, bytes]] = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        start = offset
        if first in (0x00, 0xFF):
            return items, False
        if (first & 0x7F) == 0x7F:
            # Three-byte COMPREHENSION-TLV tag form.
            if offset + 3 > len(data):
                return items, False
            tag = int.from_bytes(data[offset + 1 : offset + 3], "big")
            cr = bool(data[offset + 1] & 0x80)
            offset += 3
        else:
            tag = first & 0x7F
            cr = bool(first & 0x80)
            offset += 1
        if offset >= len(data):
            return items, False
        # TS 102 223 v18.3 Annex C table C.1: one length byte, or '81' then one.
        length = data[offset]
        offset += 1
        if length == 0x81:
            if offset >= len(data):
                return items, False
            length = data[offset]
            offset += 1
        elif length & 0x80:
            return items, False
        end = offset + length
        if end > len(data):
            return items, False
        items.append((tag, cr, data[offset:end], data[start:end]))
        offset = end
    return items, True


def _decode_comprehension_tlvs(data: bytes, *, command_type: int | None = None) -> tuple[list[dict[str, Any]], bool]:
    commands, events = _cat_tables()
    items, complete = _iter_comprehension_tlvs(data)
    nodes: list[dict[str, Any]] = []
    for tag, cr, value, _raw in items:
        name = _CTLV_TAGS.get(tag, "COMPREHENSION-TLV data object")
        decoded: Any = None
        spec = _CTLV_SPEC
        if tag == 0x01 and len(value) >= 3:
            type_name = commands.get(value[1], f"type '{value[1]:02X}'")
            decoded = f"command number {value[0]}, {type_name}, qualifier {value[2]:02X}"
            spec = "TS 102 223 v18.3 section 8.6, table in section 9.4"
        elif tag == 0x02 and len(value) >= 2:
            decoded = f"{_device_name(value[0])} -> {_device_name(value[1])}"
            spec = "TS 102 223 v18.3 section 8.7"
        elif tag == 0x03 and len(value) >= 1:
            decoded = _CAT_RESULTS.get(value[0], f"general result '{value[0]:02X}'")
            if len(value) > 1:
                decoded += f"; additional information {_hex(value[1:])}"
            spec = "TS 102 223 v18.3 section 8.12"
        elif tag == 0x19:
            decoded = ", ".join(events.get(byte, f"'{byte:02X}'") for byte in value) or "empty"
            spec = "TS 102 223 v18.3 section 8.25"
        elif tag == 0x0D and len(value) >= 1:
            dcs = value[0]
            text = value[1:]
            if dcs & 0x0C == 0x04 or dcs == 0x04:
                decoded = text.decode("latin-1", errors="replace")
            else:
                decoded = f"data coding scheme {dcs:02X}, {len(text)} byte(s)"
        elif tag == 0x05:
            try:
                decoded = value.decode("ascii")
            except UnicodeDecodeError:
                decoded = None
        elif tag in (0x24,) and len(value) == 1:
            decoded = f"timer {value[0]}"
        elif tag == 0x25 and len(value) == 3:
            decoded = f"{_bcd_digits(value[0:1])}h {_bcd_digits(value[1:2])}m {_bcd_digits(value[2:3])}s"
        elif tag == 0x37 and len(value) == 1:
            decoded = f"{value[0]} byte(s)"
        elif tag == 0x39 and len(value) == 2:
            decoded = f"{_int(value)} byte(s)"
        elif tag == 0x38 and len(value) >= 2:
            channel = value[0] & 0x07
            decoded = f"channel {channel}, {'link established' if value[0] & 0x80 else 'no link'}, further info {value[1]:02X}"
        elif tag == 0x2F:
            decoded = aid_name(value) or None
        elif tag == 0x10 and len(value) == 1:
            decoded = f"item {value[0]}" if value[0] else "null item identifier"
        elif tag == 0x04 and len(value) == 2:
            unit = {0x00: "minutes", 0x01: "seconds", 0x02: "tenths of seconds"}.get(value[0], "reserved unit")
            decoded = f"{value[1]} {unit}"
        node = _node(f"{tag:02X}", name, value, spec=spec, decoded=decoded)
        if tag == 0x36 and value:
            # Channel data of SEND DATA and RECEIVE DATA, read on its own; a trace follows it as a stream (_follow_channel_data).
            from . import input_forms

            carried = input_forms.channel_payload_nodes(value)
            if carried:
                node["children"] = carried
        node["comprehensionRequired"] = cr
        nodes.append(node)
    return nodes, complete


def _decode_terminal_profile(data: bytes) -> dict[str, Any]:
    """TERMINAL PROFILE: one row per byte naming the facilities it claims, findings as notes."""
    from yggdrasim_common import terminal_profile

    result = terminal_profile.decode(data)
    claimed: dict[int, list[str]] = {}
    for facility, value in result.values:
        if value == 0:
            continue
        shown = facility.describe() if facility.width == 1 else f"{facility.describe()} = {value}"
        claimed.setdefault(facility.byte, []).append(shown)
    fields = [_field("Profile bytes", _hex(data), f"{len(data)} byte(s)")]
    for byte in range(1, len(data) + 1):
        if byte > terminal_profile.LAST_DEFINED_BYTE:
            fields.append(_field(f"Bytes {byte}-{len(data)}", _hex(data[byte - 1 :]), "RFU"))
            break
        title = terminal_profile.BYTE_TITLES.get(byte, "")
        label = f"Byte {byte}" + (f" ({title})" if title else "")
        names = claimed.get(byte, [])
        fields.append(_field(label, f"{data[byte - 1]:02X}", "; ".join(names) if names else "nothing claimed"))
    payload = _payload(
        "terminal_profile",
        "TERMINAL PROFILE",
        "TS 102 223 v18.3 section 5.2, TS 31.111 v19.4 section 5.2",
        fields=fields,
    )
    notes = [
        f"{finding.severity}: {finding.address + ' ' if finding.address else ''}{finding.text}"
        for finding in result.findings
    ]
    if notes:
        payload["notes"] = notes
    return payload


def _follow_channel_data(payload: dict[str, Any], state: TraceState, *, terminal_response: bool) -> dict[str, Any]:
    """Read the channel data of a trace as one stream, so a record cut across data blocks is read once it is whole.

    SEND DATA carries the card's octets in the proactive command (TS 102 223
    v18.3 section 6.4.30); the terminal returns the network's in the TERMINAL
    RESPONSE to RECEIVE DATA (section 6.4.29). Each channel is its own stream:
    a proactive command names its channel in the destination device identity
    (section 8.7, '21' to '27'), and the answer to RECEIVE DATA belongs to the
    channel of the command before it. A channel starts afresh when OPEN
    CHANNEL assigns its identifier (the Channel status of the TERMINAL
    RESPONSE, section 8.56) and when CLOSE CHANNEL names it.
    """
    from yggdrasim_common.bip_stream_decode import BipChannelObserver
    from yggdrasim_common.stk_tables import PROACTIVE_COMMANDS

    def value_of(tag: str) -> bytes:
        node = next((entry for entry in nodes if entry.get("tag") == tag and entry.get("valueHex")), None)
        try:
            return bytes.fromhex(str(node["valueHex"])) if node is not None else b""
        except ValueError:
            return b""

    nodes = list(payload.get("nodes") or [])
    if not terminal_response:
        nodes = list(nodes[0].get("children") or []) if nodes else []
    details = value_of("01")
    command = PROACTIVE_COMMANDS.get(details[1], "") if len(details) == 3 else ""
    identities = value_of("02")
    addressed = identities[1] & 0x07 if len(identities) == 2 and 0x21 <= identities[1] <= 0x27 else 0
    if command == "OPEN CHANNEL":
        status = value_of("38")
        if terminal_response and len(status) == 2 and status[0] & 0x07:
            state.channel_observers.pop(status[0] & 0x07, None)
        return payload
    if command == "CLOSE CHANNEL":
        if not terminal_response:
            state.channel_observers.pop(addressed, None)
        return payload
    if command == "RECEIVE DATA" and not terminal_response:
        state.receive_channel = addressed
        return payload
    if (command, terminal_response) not in (("SEND DATA", False), ("RECEIVE DATA", True)):
        return payload
    data_node = next((node for node in nodes if node.get("tag") == "36" and node.get("valueHex")), None)
    if data_node is None:
        return payload
    from . import input_forms

    channel = state.receive_channel if terminal_response else addressed
    observer = state.channel_observers.setdefault(channel, BipChannelObserver())
    direction = "network to card" if terminal_response else "card to network"
    events = observer.observe(bytes.fromhex(str(data_node["valueHex"])), direction)
    children = input_forms.channel_event_nodes(events)
    waiting = observer.pending_bytes(direction) + observer.held_handshake_bytes(direction)
    held = f"{waiting} byte(s) of a record or handshake message wait for the next data block"
    if children:
        if waiting:
            children.append(_part_node("continues", b"", decoded=held))
        data_node["children"] = children
    else:
        # Nothing completed in this block: the octets stay in view, with what they wait for.
        data_node.pop("children", None)
        if waiting:
            data_node["decoded"] = held
    return payload


def decode_cat(data: bytes, *, expect: str) -> dict[str, Any]:
    """Decode CAT traffic: a proactive command, an envelope or a terminal response."""
    if expect == "cat_terminal_response":
        nodes, complete = _decode_comprehension_tlvs(data)
        payload = _payload("cat", "TERMINAL RESPONSE", "TS 102 223 v18.3 section 6.8", nodes=nodes)
        if not complete:
            payload["notes"] = ["The COMPREHENSION-TLV sequence does not cover the whole data field."]
        return payload
    if expect == "terminal_profile":
        return _decode_terminal_profile(data)
    items = _iter_tlvs(data)
    if len(items) != 1 or not _tlvs_cover(data, items):
        nodes, complete = _decode_comprehension_tlvs(data)
        if nodes and complete:
            return _payload("cat", "COMPREHENSION-TLV objects", _CTLV_SPEC, nodes=nodes)
        return _payload("cat", "CAT data", "TS 101 220 v19 table 7.17", notes=["Expected one BER-TLV data object."], nodes=[])
    outer = items[0]
    tag = outer.tag_bytes[0] if len(outer.tag_bytes) == 1 else -1
    name = _CAT_BER_TAGS.get(tag, "BER-TLV data object")
    nodes, complete = _decode_comprehension_tlvs(outer.value)
    if tag == 0xD1:
        # SMS-PP download: the TPDU comes from the network.
        _attach_sms_tpdu(nodes, mobile_terminated=True)
    elif tag == 0xD0 and any(child.get("tag") == "01" and str(child.get("valueHex", ""))[2:4] == "13" for child in nodes):
        # SEND SHORT MESSAGE: the TPDU is the one the terminal submits.
        _attach_sms_tpdu(nodes, mobile_terminated=False)
    root = _node(outer.tag_hex, name, outer.value, spec="TS 101 220 v19 table 7.17", children=nodes)
    title = name
    for child in nodes:
        if child["tag"] == "01" and child.get("decoded"):
            title = f"{name}: {child['decoded']}"
            break
    payload = _payload("cat", title, "TS 102 223 v18.3 Annex C", nodes=[root])
    if not complete:
        payload["notes"] = ["The COMPREHENSION-TLV sequence does not cover the whole BER-TLV value."]
    return payload


def _attach_sms_tpdu(nodes: list[dict[str, Any]], *, mobile_terminated: bool) -> None:
    """Read the SMS TPDU object among ``nodes`` field by field, with the secured packet it carries."""
    from . import payload_readings

    for node in nodes:
        if node.get("tag") != "0B" or not node.get("valueHex"):
            continue
        children = payload_readings.sms_tpdu_nodes(bytes.fromhex(str(node["valueHex"])), mobile_terminated=mobile_terminated)
        if children:
            node["name"] = "SMS TPDU"
            node["spec"] = "TS 23.040 v19 section 9.2.2"
            node["children"] = children


# ----------------------------------------------------------------------
# 3GPP AUTHENTICATE
# ----------------------------------------------------------------------


def decode_auth_request(ins: int, p2: int, data: bytes) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    context = p2 & 0x07
    if ins == 0x88 and context in (0x00, 0x01) and data:
        # TS 31.102 v19.5 section 7.1.2.1.
        offset = 0
        length = data[offset]
        rand = data[offset + 1 : offset + 1 + length]
        fields.append(_field("RAND", _hex(rand), f"{len(rand)} byte(s)"))
        offset += 1 + length
        if context == 0x01 and offset < len(data):
            length = data[offset]
            autn = data[offset + 1 : offset + 1 + length]
            fields.append(_field("AUTN", _hex(autn), f"{len(autn)} byte(s)"))
            offset += 1 + length
        if offset < len(data):
            fields.append(_field("Trailing bytes", _hex(data[offset:])))
        elif offset > len(data):
            fields.append(_field("Length fields", "inconsistent", "the declared RAND/AUTN lengths exceed the data field"))
        return _payload("auth", "AUTHENTICATE " + _auth_context(ins, p2), "TS 31.102 v19.5 section 7.1.2.1", fields=fields)
    return _payload("auth", "AUTHENTICATE " + _auth_context(ins, p2), "TS 31.102 v19.5 section 7.1.2", fields=[_field("Authentication data", _hex(data))])


def decode_auth_response(ins: int, p2: int, data: bytes) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    context = p2 & 0x07
    if not data:
        return _payload("auth", "AUTHENTICATE response", "TS 31.102 v19.5 section 7.1.2.1", fields=fields)
    if data[0] == 0xDB:
        # Successful 3G authentication: RES, CK, IK and optionally Kc.
        offset = 1
        for label in ("RES", "CK", "IK", "Kc"):
            if offset >= len(data):
                break
            length = data[offset]
            fields.append(_field(label, _hex(data[offset + 1 : offset + 1 + length])))
            offset += 1 + length
        return _payload("auth", "Successful 3G/EPS/5G authentication ('DB')", "TS 31.102 v19.5 section 7.1.2.1", fields=fields)
    if data[0] == 0xDC:
        length = data[1] if len(data) > 1 else 0
        fields.append(_field("AUTS", _hex(data[2 : 2 + length])))
        return _payload("auth", "Synchronisation failure ('DC')", "TS 31.102 v19.5 section 7.1.2.1", fields=fields)
    if context == 0x00 and len(data) >= 14 and data[0] == 0x04 and data[5] == 0x08:
        fields.append(_field("SRES", _hex(data[1:5])))
        fields.append(_field("Kc", _hex(data[6:14])))
        return _payload("auth", "GSM security context response", "TS 31.102 v19.5 section 7.1.2.1", fields=fields)
    return _payload("auth", "AUTHENTICATE response", "TS 31.102 v19.5 section 7.1.2", fields=[_field("Response data", _hex(data))])


# ----------------------------------------------------------------------
# GSMA ES10
# ----------------------------------------------------------------------


def _es10_index() -> dict[str, dict[str, list[str]]]:
    """BF tag -> {"request": [...], "response": [...], "docs": [...]}.

    Built from the generated ``_indexes/gsma-asn1-context-tags.md`` when the
    library is present, with the SGP.22 v3.1 / SGP.32 v1.3 rows as the
    built-in fallback.
    """
    table: dict[str, dict[str, list[str]]] = {}

    def add(doc: str, tag: str, type_name: str) -> None:
        entry = table.setdefault(tag, {"request": [], "response": [], "docs": []})
        bucket = "request" if type_name.endswith("Request") else "response"
        if type_name in ("EUICCInfo1", "EUICCInfo2", "BoundProfilePackage", "ProfileInstallationResultData", "NotificationMetadata", "HandleNotification", "HandleNotificationEsipa", "EimAcknowledgements", "SequenceNumber"):
            bucket = "response"
        # ES9+, ES11 and ESipa requests carry an interface suffix (RequestEs9, RequestEsipa).
        if re.search(r"Request(?:Es\w+)?$", type_name):
            bucket = "request"
        if type_name not in entry[bucket]:
            entry[bucket].append(type_name)
        if doc not in entry["docs"]:
            entry["docs"].append(doc)

    index_path = Path(__file__).resolve().parents[2] / "docs" / "tel-docs" / "converted" / "_indexes" / "gsma-asn1-context-tags.md"
    rows = 0
    try:
        for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.startswith("| SGP."):
                continue
            columns = [column.strip() for column in line.strip("|").split("|")]
            if len(columns) < 3:
                continue
            doc = columns[0]
            if doc not in ("SGP.22-v3.1", "SGP.32-v1.3"):
                continue
            tag = columns[1].strip("`").upper()
            type_name = columns[2].strip("`")
            if not tag.startswith("BF"):
                continue
            add(doc, tag, type_name)
            rows += 1
    except OSError:
        rows = 0
    if rows == 0:
        for doc, tag, type_name in _ES10_FALLBACK:
            add(doc, tag, type_name)
    return table


# Rows of docs/tel-docs/converted/_indexes/gsma-asn1-context-tags.md for the
# ES10 request/response tags, kept so an installed wheel without the library
# still names the function a BF tag belongs to.
_ES10_FALLBACK: tuple[tuple[str, str, str], ...] = (
    ("SGP.22-v3.1", "BF20", "EUICCInfo1"), ("SGP.22-v3.1", "BF20", "GetEuiccInfo1Request"),
    ("SGP.22-v3.1", "BF21", "PrepareDownloadRequest"), ("SGP.22-v3.1", "BF21", "PrepareDownloadResponse"),
    ("SGP.22-v3.1", "BF22", "GetEuiccInfo2Request"), ("SGP.32-v1.3", "BF22", "EUICCInfo2"),
    ("SGP.22-v3.1", "BF23", "InitialiseSecureChannelRequest"), ("SGP.22-v3.1", "BF24", "ConfigureISDPRequest"),
    ("SGP.22-v3.1", "BF25", "StoreMetadataRequest"), ("SGP.22-v3.1", "BF26", "ReplaceSessionKeysRequest"),
    ("SGP.22-v3.1", "BF27", "ProfileInstallationResultData"),
    ("SGP.22-v3.1", "BF28", "ListNotificationRequest"), ("SGP.22-v3.1", "BF28", "ListNotificationResponse"),
    ("SGP.22-v3.1", "BF29", "SetNicknameRequest"), ("SGP.22-v3.1", "BF29", "SetNicknameResponse"),
    ("SGP.22-v3.1", "BF2A", "UpdateMetadataRequest"),
    ("SGP.22-v3.1", "BF2B", "RetrieveNotificationsListRequest"), ("SGP.22-v3.1", "BF2B", "RetrieveNotificationsListResponse"),
    ("SGP.22-v3.1", "BF2D", "ProfileInfoListRequest"), ("SGP.22-v3.1", "BF2D", "ProfileInfoListResponse"),
    ("SGP.22-v3.1", "BF2E", "GetEuiccChallengeRequest"), ("SGP.22-v3.1", "BF2E", "GetEuiccChallengeResponse"),
    ("SGP.22-v3.1", "BF2F", "NotificationMetadata"),
    ("SGP.22-v3.1", "BF30", "NotificationSentRequest"), ("SGP.22-v3.1", "BF30", "NotificationSentResponse"),
    ("SGP.22-v3.1", "BF31", "EnableProfileRequest"), ("SGP.22-v3.1", "BF31", "EnableProfileResponse"),
    ("SGP.22-v3.1", "BF32", "DisableProfileRequest"), ("SGP.22-v3.1", "BF32", "DisableProfileResponse"),
    ("SGP.22-v3.1", "BF33", "DeleteProfileRequest"), ("SGP.22-v3.1", "BF33", "DeleteProfileResponse"),
    ("SGP.22-v3.1", "BF34", "EuiccMemoryResetRequest"), ("SGP.22-v3.1", "BF34", "EuiccMemoryResetResponse"),
    ("SGP.22-v3.1", "BF36", "BoundProfilePackage"), ("SGP.22-v3.1", "BF37", "ProfileInstallationResult"),
    ("SGP.22-v3.1", "BF38", "AuthenticateServerRequest"), ("SGP.22-v3.1", "BF38", "AuthenticateServerResponse"),
    ("SGP.22-v3.1", "BF39", "InitiateAuthenticationRequest"), ("SGP.22-v3.1", "BF39", "InitiateAuthenticationResponse"),
    ("SGP.22-v3.1", "BF3A", "GetBoundProfilePackageRequest"), ("SGP.22-v3.1", "BF3A", "GetBoundProfilePackageResponse"),
    ("SGP.22-v3.1", "BF3B", "AuthenticateClientRequest"), ("SGP.22-v3.1", "BF3B", "AuthenticateClientResponseEs9"),
    ("SGP.22-v3.1", "BF3C", "EuiccConfiguredDataRequest"), ("SGP.22-v3.1", "BF3C", "EuiccConfiguredDataResponse"),
    ("SGP.22-v3.1", "BF3D", "HandleNotification"),
    ("SGP.22-v3.1", "BF3E", "GetEuiccDataRequest"), ("SGP.22-v3.1", "BF3E", "GetEuiccDataResponse"),
    ("SGP.22-v3.1", "BF3F", "SetDefaultDpAddressRequest"), ("SGP.22-v3.1", "BF3F", "SetDefaultDpAddressResponse"),
    ("SGP.32-v1.3", "BF41", "CancelSessionRequestEsipa"), ("SGP.32-v1.3", "BF41", "CancelSessionResponse"),
    ("SGP.32-v1.3", "BF42", "IpaeActivationRequest"), ("SGP.32-v1.3", "BF42", "IpaeActivationResponse"),
    ("SGP.32-v1.3", "BF4E", "TransferEimPackageRequest"), ("SGP.32-v1.3", "BF4E", "TransferEimPackageResponse"),
    ("SGP.32-v1.3", "BF4F", "GetEimPackageRequest"), ("SGP.32-v1.3", "BF4F", "GetEimPackageResponse"),
    ("SGP.32-v1.3", "BF50", "ProvideEimPackageResult"), ("SGP.32-v1.3", "BF50", "ProvideEimPackageResultResponse"),
    ("SGP.32-v1.3", "BF51", "EuiccPackageRequest"), ("SGP.32-v1.3", "BF51", "EuiccPackageResult"),
    ("SGP.32-v1.3", "BF52", "IpaEuiccDataRequest"), ("SGP.32-v1.3", "BF52", "IpaEuiccDataResponse"),
    ("SGP.32-v1.3", "BF53", "EimAcknowledgements"),
    ("SGP.32-v1.3", "BF54", "ProfileDownloadTriggerRequest"), ("SGP.32-v1.3", "BF54", "ProfileDownloadTriggerResult"),
    ("SGP.32-v1.3", "BF55", "GetEimConfigurationDataRequest"), ("SGP.32-v1.3", "BF55", "GetEimConfigurationDataResponse"),
    ("SGP.32-v1.3", "BF56", "GetCertsRequest"), ("SGP.32-v1.3", "BF56", "GetCertsResponse"),
    ("SGP.32-v1.3", "BF57", "AddInitialEimRequest"), ("SGP.32-v1.3", "BF57", "AddInitialEimResponse"),
    ("SGP.32-v1.3", "BF58", "ProfileRollbackRequest"), ("SGP.32-v1.3", "BF58", "ProfileRollbackResponse"),
    ("SGP.32-v1.3", "BF59", "ConfigureImmediateProfileEnablingRequest"), ("SGP.32-v1.3", "BF59", "ConfigureImmediateProfileEnablingResponse"),
    ("SGP.32-v1.3", "BF5A", "ImmediateEnableRequest"), ("SGP.32-v1.3", "BF5A", "ImmediateEnableResponse"),
    ("SGP.32-v1.3", "BF5B", "EnableEmergencyProfileRequest"), ("SGP.32-v1.3", "BF5B", "EnableEmergencyProfileResponse"),
    ("SGP.32-v1.3", "BF5C", "DisableEmergencyProfileRequest"), ("SGP.32-v1.3", "BF5C", "DisableEmergencyProfileResponse"),
    ("SGP.32-v1.3", "BF5D", "ExecuteFallbackMechanismRequest"), ("SGP.32-v1.3", "BF5D", "ExecuteFallbackMechanismResponse"),
    ("SGP.32-v1.3", "BF5E", "ReturnFromFallbackRequest"), ("SGP.32-v1.3", "BF5E", "ReturnFromFallbackResponse"),
    ("SGP.32-v1.3", "BF5F", "GetConnectivityParametersRequest"), ("SGP.32-v1.3", "BF5F", "GetConnectivityParametersResponse"),
    ("SGP.32-v1.3", "BF64", "EuiccMemoryResetRequest"), ("SGP.32-v1.3", "BF64", "EuiccMemoryResetResponse"),
    ("SGP.32-v1.3", "BF65", "SetDefaultDpAddressRequest"), ("SGP.32-v1.3", "BF65", "SetDefaultDpAddressResponse"),
)

_ES10_TABLE: dict[str, dict[str, list[str]]] | None = None


def es10_types_for(tag_hex: str) -> dict[str, list[str]]:
    global _ES10_TABLE
    if _ES10_TABLE is None:
        _ES10_TABLE = _es10_index()
    return _ES10_TABLE.get(tag_hex.upper(), {"request": [], "response": [], "docs": []})


# ``type_name`` asn1tools gives a type written inline; any other value names
# the type a member references (``IpaEuiccData``, ``ProfileState``).
_ASN1_KEYWORDS = gsma_schema.ASN1_KEYWORDS

# A tag list is the tags of another type's members, concatenated without
# delimitation; (holding type, member) -> (type whose members it selects, clause).
_TAG_LIST_TARGETS: dict[tuple[str, str], tuple[str, str]] = {
    # The IPA and eUICC data items the eIM asks for, by their IpaEuiccData tag.
    ("IpaEuiccDataRequest", "tagList"): ("IpaEuiccData", "SGP.32 v1.3 §2.11.1.2"),
    # The data objects each ProfileInfo of the response carries.
    ("ProfileInfoListRequest", "tagList"): ("ProfileInfo", "SGP.22 v3.1 §5.7.15"),
    ("ListProfileInfo", "tagList"): ("ProfileInfo", "SGP.22 v3.1 §5.7.15"),
    # The value is '5A', the EID.
    ("GetEuiccDataRequest", "tagList"): ("GetEuiccDataResponse", "SGP.22 v3.1 §5.7.20"),
}

# A BIT STRING up to this many bits is shown bit by bit, a longer one as hex.
_BITS_SHOWN = 32

# Universal class numbers (X.680 (02/2021) §8.4, Table 1) an ANY value is read
# as: the character string types, then BOOLEAN, INTEGER, NULL, OBJECT
# IDENTIFIER, ENUMERATED, UTCTime and GeneralizedTime.
_ANY_TEXT_TAGS = frozenset({12, 18, 19, 20, 21, 22, 25, 26, 27, 28, 30})
_ANY_VALUE_TAGS = _ANY_TEXT_TAGS | {1, 2, 5, 6, 10, 23, 24}


def _unwrap_type(type_obj: Any) -> Any:
    """The asn1tools type under its ExplicitTag and Recursive wrappers."""
    for _ in range(16):
        if type(type_obj).__name__ not in ("ExplicitTag", "Recursive"):
            break
        inner = getattr(type_obj, "inner", None)
        if inner is None:
            break
        type_obj = inner
    return type_obj


def _type_members(type_obj: Any) -> dict[str, Any]:
    """Members of a SEQUENCE, SET or CHOICE type by name, extension additions included."""
    shape = _unwrap_type(type_obj)
    members: list[Any] = list(getattr(shape, "root_members", None) or getattr(shape, "members", None) or [])
    for addition in getattr(shape, "additions", None) or []:
        members.extend(addition if isinstance(addition, list) else [addition])
    return {str(member.name): member for member in members if getattr(member, "name", "")}


def _type_reference(type_obj: Any) -> tuple[str, str]:
    """The type a member references and its module; ('', '') for an inline type."""
    current = type_obj
    for _ in range(16):
        if current is None:
            return "", ""
        name = str(getattr(current, "type_name", "") or "")
        if name and name not in _ASN1_KEYWORDS:
            return name, str(getattr(current, "module_name", "") or "")
        if type(current).__name__ not in ("ExplicitTag", "Recursive"):
            return "", ""
        current = getattr(current, "inner", None)
    return "", ""


def _type_label(type_obj: Any) -> str:
    """The name of the type a member references; '' for an inline type."""
    return _type_reference(type_obj)[0]


def _member_definition(tree: dict[str, Any] | None, entry: Any, compiled: Any, module: str) -> tuple[dict[str, Any] | None, str]:
    """The parse-tree entry describing a member: the type it references, or its own inline one.

    Walking the parse tree beside the value finds an inline type wherever it
    sits, also inside an anonymous SEQUENCE no type name reaches (SGP.32 v1.3
    ProfileDownloadTriggerResult ... profileDownloadError.profileDownloadErrorReason).
    """
    if tree is None:
        return None, module
    reference, reference_module = _type_reference(compiled)
    if reference:
        return gsma_schema.resolve_definition(tree, {"type": reference}, reference_module or module)
    return gsma_schema.resolve_definition(tree, entry, module) if isinstance(entry, dict) else (None, module)


def _split_tag_list(value: bytes) -> tuple[list[bytes], bytes]:
    """The BER tags of a tag list value, and a trailing tag that is cut short."""
    tags: list[bytes] = []
    offset = 0
    while offset < len(value):
        end = offset + 1
        if value[offset] & 0x1F == 0x1F:
            # X.690 §8.1.2.4: subsequent octets carry bit 8 until the last one.
            while end < len(value) and value[end] & 0x80:
                end += 1
            if end >= len(value):
                return tags, value[offset:]
            end += 1
        tags.append(value[offset:end])
        offset = end
    return tags, b""


def _tag_list_entries(value: bytes, target: str, clause: str) -> tuple[list[dict[str, Any]], str] | None:
    """Name each tag of a tag list after the ``target`` member it selects."""
    tree = gsma_schema.type_tree(target)
    if tree is None:
        return None
    names = {bytes(member.tag): name for name, member in _type_members(tree).items() if getattr(member, "tag", None)}
    tags, tail = _split_tag_list(value)
    entries = [{"name": _hex(tag), "kind": "tag", "value": names.get(tag, f"no {target} member")} for tag in tags]
    if tail:
        entries.append({"name": _hex(tail), "kind": "tag", "value": "tag cut short"})
    summary = f"{len(tags)} {target} tag{'' if len(tags) == 1 else 's'}, {clause}"
    return entries, summary


_EUICC_RESPONSE_SPEC = "TCA eUICC Profile Package V3.4.1 section 8.11"


def _euicc_response_nodes(data: bytes) -> tuple[list[dict[str, Any]], str, dict[str, Any]] | None:
    """Display nodes, summary and result of an EUICCResponse octet string, or None when it is not one."""
    from SCP11.shared.sima_response import decode_sima_response, describe_pe_status_text

    semantic = decode_sima_response(data).get("semantic") or {}
    statuses = semantic.get("pe_status")
    if not isinstance(statuses, list) or len(statuses) == 0:
        return None
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(statuses):
        status = int(entry["status"])
        fields: list[dict[str, Any]] = [{
            "name": "status", "kind": "integer", "number": status,
            "value": f"{status} ({entry['status_name']})", "decoded": entry["status_name"],
        }]
        for key, label in (("identification", "identification"),
                           ("additional_information", "additional-information"), ("offset", "offset")):
            if entry.get(key) is not None:
                fields.append({"name": label, "kind": "integer", "value": int(entry[key])})
        entries.append({"name": f"[{index}]", "kind": "sequence", "children": fields,
                        "decoded": describe_pe_status_text(entry)})
    nodes: list[dict[str, Any]] = [{"name": "peStatus", "kind": "list", "children": entries}]
    if semantic.get("profile_installation_aborted"):
        nodes.append({"name": "profileInstallationAborted", "kind": "null"})
    if semantic.get("status_message"):
        nodes.append({"name": "statusMessage", "kind": "string", "value": str(semantic["status_message"])})
    summary = "all PEs ok" if semantic.get("ok") else str(semantic.get("failure_cause") or "failure")
    result = {"ok": bool(semantic.get("ok")), "text": summary}
    return [{"name": "EUICCResponse", "kind": "sequence", "children": nodes}], summary, result


def _euicc_response_payload(data: bytes) -> dict[str, Any] | None:
    """The payload of a bare EUICCResponse, the simaResponse octets on their own; None for anything else."""
    from SCP11.shared.sima_response import is_euicc_response

    if not is_euicc_response(data):
        return None
    reading = _euicc_response_nodes(data)
    if reading is None:
        return None
    nodes, _summary, result = reading
    tree = _generic_tree(data, _registry())
    return _payload(
        "es10", "EUICCResponse", _EUICC_RESPONSE_SPEC,
        schema=nodes[0], schemaType="EUICCResponse", schemaSource=[_EUICC_RESPONSE_SPEC], result=result,
        nodes=_tree_to_nodes(tree) if tree else [],
        notes=["Read as an EUICCResponse by its structure; a bare SEQUENCE carries no tag that names its type."],
    )


def _installation_result(node: Any) -> dict[str, Any] | None:
    """What the EUICCResponses under ``node`` report together: all ok, or each failure cause."""
    found: list[dict[str, Any]] = []

    def collect(entry: Any) -> None:
        if isinstance(entry, list):
            for item in entry:
                collect(item)
        elif isinstance(entry, dict):
            if isinstance(entry.get("result"), dict):
                found.append(entry["result"])
            collect(entry.get("children"))

    collect(node)
    if not found:
        return None
    failed = [entry for entry in found if not entry.get("ok")]
    if not failed:
        return {"ok": True, "text": "all PEs ok" if len(found) == 1 else f"all PEs ok in {len(found)} results"}
    text = "; ".join(str(entry.get("text") or "failure") for entry in failed)
    if len(found) > 1:
        text = f"{len(failed)} of {len(found)} results failed: {text}"
    return {"ok": False, "text": text}


def _located_installation_result(payload: dict[str, Any], data: bytes) -> None:
    """Head ``payload`` with the outcome of an EUICCResponse found by its tags.

    A ProfileInstallationResult the schema refuses, or one inside a wrapper the
    schema has no type for, still carries the response at fixed tags (SGP.22
    v3.1 section 2.5.6); the added rows say where it was found.
    """
    from SCP11.shared.sima_response import locate_sima_response

    located = locate_sima_response(data)
    if located is None or not located.get("sima_response"):
        return
    response = bytes(located["sima_response"])
    reading = _euicc_response_nodes(response)
    if reading is None:
        return
    payload["result"] = reading[2]
    where = f"found by its tags in the {located.get('result') or 'result'} of a {located.get('source') or 'result'}"
    fields = list(payload.get("fields") or [])
    fields.append(_field("EUICCResponse", _hex(response), where, spec=_EUICC_RESPONSE_SPEC))
    for key, type_name, label in (("bpp_command_id", "BppCommandId", "bppCommandId"), ("error_reason", "ErrorReason", "errorReason")):
        if located.get(key) is not None:
            number = int(located[key])
            fields.append(_field(label, number, gsma_schema.named_values(type_name).get(number, "")))
    payload["fields"] = fields


def _euicc_info2_tag_reading(payload: dict[str, Any], data: bytes) -> None:
    """Read an EUICCInfo2 the schema refuses member by member from its tags, with the SGP.32 check."""
    from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines

    try:
        lines = build_euicc_info2_detail_lines(data)
    except ValueError:
        return
    fields: list[dict[str, Any]] = []
    path: list[str] = []
    for indent, label, value in lines:
        if indent == 0 and label == "SGP.32 Validation":
            # The check follows as notes.
            break
        path = path[:indent] + [str(label)]
        fields.append(_field(" / ".join(path), str(value)))
    if not fields:
        return
    payload["title"] = "EUICCInfo2"
    payload["fields"] = fields
    payload["notes"] = list(payload.get("notes") or []) + _euicc_info2_check_notes(data)


def _euicc_info2_check_notes(data: bytes) -> list[str]:
    """The SGP.32 check of an EUICCInfo2 as notes; a consumer eUICC's answer has none."""
    from SCP03.logic.euicc_info2 import build_euicc_info2_validation_lines

    try:
        lines = build_euicc_info2_validation_lines(data)
    except ValueError as error:
        # The check reads the TLVs strictly and refuses an encoding the schema decode took.
        return [f"SGP.32 check not run: {error}"]
    status = next((str(value) for indent, _label, value in lines if indent == 0), "")
    details = [str(value) for indent, _label, value in lines if indent > 0]
    if not status:
        return []
    return [f"SGP.32 check {status}: {detail}" for detail in details] or [f"SGP.32 check {status}"]


def _any_value_reading(data: bytes) -> tuple[Any, bool] | None:
    """An ANY carries one complete TLV; a primitive universal one is read by its tag.

    Returns the value and whether it is character text, or None.
    """
    items = _iter_tlvs(data)
    if len(items) != 1 or not _tlvs_cover(data, items) or items[0].constructed:
        return None
    first = items[0].tag_bytes[0]
    number = first & 0x1F
    if first & 0xC0 or number not in _ANY_VALUE_TAGS:
        return None
    value = _decode_universal_value(number, items[0].value, _registry())
    if isinstance(value, dict):
        return None
    if number in _ANY_TEXT_TAGS and items[0].value and value == _hex(items[0].value):
        # The decoder's fallback for undecodable text is the hex itself.
        return None
    return ("NULL" if value is None else value), number in _ANY_TEXT_TAGS


def _bit_string_node(name: str, data: bytes, bit_count: int, names: dict[int, str]) -> dict[str, Any]:
    """A BIT STRING with its set bits named; bit 0 is the first bit (X.680 §22.6)."""
    count = max(0, min(bit_count, len(data) * 8))
    bits = "".join("1" if data[index // 8] & (0x80 >> (index % 8)) else "0" for index in range(count))
    node: dict[str, Any] = {"name": name, "kind": "bits", "valueHex": _hex(data), "bitLength": count, "bits": bits}
    shown = f"'{bits}'B" if count <= _BITS_SHOWN else f"'{_hex(data)}'H ({count} bits)"
    if names:
        named = [names.get(index, f"bit {index}") for index, bit in enumerate(bits) if bit == "1"]
        node["set"] = named
        # Every bit the type names, and any set bit it does not, for the coverage view.
        set_bits = {index for index, bit in enumerate(bits) if bit == "1"}
        node["options"] = [
            {"bit": number, "name": names.get(number, f"bit {number}"), "set": number in set_bits}
            for number in sorted(set(names) | set_bits)
        ]
        shown += f" ({', '.join(named) if named else 'none set'})"
    node["value"] = shown
    return node


def _extended_card_resources(data: bytes) -> str | None:
    """ETSI TS 102 226 v19.0 §8.2.1.7.2 Extended Card resources: '81' installed
    applications, '82' free non-volatile and '83' free volatile memory.

    SGP.22 v3.1 §4.3 gives the memory in bytes, for Profile download and installation.
    """
    items = _iter_tlvs(data)
    if not items or not _tlvs_cover(data, items):
        return None
    values = {item.tag_hex: int.from_bytes(item.value, "big") for item in items if item.value}
    if not set(values) <= {"81", "82", "83"} or not values:
        return None
    parts = []
    if "81" in values:
        parts.append(f"{values['81']} installed application{'' if values['81'] == 1 else 's'}")
    if "82" in values:
        parts.append(f"{values['82']} B free non-volatile memory")
    if "83" in values:
        parts.append(f"{values['83']} B free volatile memory")
    return ", ".join(parts)


def _certificate_node(name: str, value: dict[str, Any], source: bytes) -> dict[str, Any] | None:
    """An X.509 certificate as the rows of ``SCP11.shared.certificate_view``.

    asn1tools hands over the decoded fields, not the bytes, so the certificate
    is encoded again and used only when those bytes are the ones in the input:
    after the first octet, which an implicit member tag ('A5', 'A6') replaces.
    """
    try:
        der = gsma_schema.encode_type("Certificate", value)
    except Exception:  # noqa: BLE001 - asn1tools encode errors are library-specific; the field tree stands
        return None
    if len(der) < 2 or der[1:] not in source:
        return None
    try:
        from SCP11.shared.certificate_view import certificate_rows
    except ImportError:
        return None
    rows = [
        {"name": row.label, "kind": "value", "value": row.value, "tone": row.tone, "indent": row.indent}
        for row in certificate_rows(der)
    ]
    return {"name": name, "kind": "certificate", "valueHex": _hex(der), "length": len(der), "children": rows}


def _value_names(definition: dict[str, Any] | None, label: str, owner: str, name: str) -> dict[int, str]:
    """Named bits or numbers from the parse-tree entry; by type and member name without one."""
    if definition is not None:
        return gsma_schema.definition_values(definition, label)
    return gsma_schema.named_values(label, owner=owner, member=name)


def _schema_value_nodes(
    value: Any,
    name: str,
    type_obj: Any = None,
    *,
    type_label: str = "",
    owner: str = "",
    source: bytes = b"",
    definition: dict[str, Any] | None = None,
    tree: dict[str, Any] | None = None,
    module: str = "",
) -> dict[str, Any]:
    """Turn an asn1tools value into display nodes: dicts nest, bytes show hex.

    ``type_obj`` is the asn1tools type the value was decoded with, when known,
    ``type_label`` the name of that type and ``owner`` the name of the type
    whose member ``name`` is; they name the entries of a tag list. ``source``
    is the decoded input, against which a certificate's bytes are checked.
    ``definition`` is the value's entry in the parse ``tree`` (``module`` the
    module it sits in), walked beside the value for the named bits and numbers.
    """
    label = type_label or _type_label(type_obj)
    shape = _unwrap_type(type_obj) if type_obj is not None else None

    def below(item: Any, child: str, compiled: Any, entry: Any) -> dict[str, Any]:
        child_definition, child_module = _member_definition(tree, entry, compiled, module)
        return _schema_value_nodes(
            item, child, compiled, owner=label, source=source,
            definition=child_definition, tree=tree, module=child_module,
        )

    if isinstance(value, dict):
        if label == "Certificate" and source:
            certificate = _certificate_node(name, value, source)
            if certificate is not None:
                return certificate
        members = _type_members(shape) if shape is not None else {}
        entries = gsma_schema.members_of(definition)
        children = [below(item, str(key), members.get(str(key)), entries.get(str(key))) for key, item in value.items()]
        return {"name": name, "kind": "sequence", "children": children}
    if isinstance(value, tuple) and len(value) == 2 and value[0] is None and value[1] is None:
        # asn1tools reads an extensible CHOICE with an unknown tag this way.
        return {"name": name, "kind": "value", "value": "unknown CHOICE alternative"}
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], (bytes, bytearray)) and isinstance(value[1], int):
        return _bit_string_node(name, bytes(value[0]), value[1], _value_names(definition, label, owner, name))
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        member = _type_members(shape).get(value[0]) if shape is not None else None
        inner = below(value[1], value[0], member, gsma_schema.members_of(definition).get(value[0]))
        return {"name": name, "kind": "choice", "choice": value[0], "children": [inner]}
    if isinstance(value, (list, tuple)):
        element = getattr(shape, "element_type", None)
        element_entry = definition.get("element") if isinstance(definition, dict) else None
        # An element is named by its index alone; the list above it carries the name.
        children = [below(item, f"[{index}]", element, element_entry) for index, item in enumerate(value)]
        return {"name": name, "kind": "list", "children": children}
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        node: dict[str, Any] = {"name": name, "kind": "octets", "valueHex": _hex(data), "length": len(data)}
        target = _TAG_LIST_TARGETS.get((owner, name))
        if target is not None:
            listed = _tag_list_entries(data, *target)
            if listed is not None:
                node["children"], node["decoded"] = listed
            return node
        if type(shape).__name__ in ("Any", "AnyDefinedBy"):
            # An ANY reads as nothing until its TLV is, e.g. a certificate's
            # AttributeValue holding a PrintableString.
            reading = _any_value_reading(data)
            if reading is not None:
                node["decoded"], node["decodedText"] = reading
            return node
        if label == "VersionType" and len(data) == 3:
            # SGP.22 v3.1 §2.4a.1.0: major, minor and revision as binary bytes; '02 00 0C' is v2.0.12.
            node["decoded"] = f"v{data[0]}.{data[1]}.{data[2]}"
            return node
        if owner == "DeviceInfo" and name in ("tac", "imei"):
            # SGP.22 v3.1 §4.2: Telephony BCD (TS 29.002), the IMEI's last octet the
            # check digit and an 'F' filler, in either nibble order (v2 swapped them).
            node["decoded"] = _bcd_digits(data)
            return node
        if name == "extCardResource":
            resources = _extended_card_resources(data)
            if resources is not None:
                node["decoded"] = resources
            return node
        if name in ("simaResponse", "ppiResponse"):
            # SGP.22 v3.1 section 2.5.6: the EUICCResponse of the Profile
            # Package Interpreter, read here so the failing PE shows by name.
            reading = _euicc_response_nodes(data)
            if reading is not None:
                node["children"], node["decoded"], node["result"] = reading
            return node
        lowered = name.lower()
        if lowered in ("iccid", "eid", "eidvalue") or lowered.endswith("iccid"):
            node["decoded"] = _bcd_digits(data) if "iccid" in lowered else _hex(data)
        elif lowered.endswith(("aid", "isdpaid")):
            named = aid_name(data)
            if named:
                node["decoded"] = named
        elif all(32 <= byte < 127 for byte in data) and len(data) >= 3:
            node["decoded"] = data.decode("ascii")
        return node
    if isinstance(value, bool):
        return {"name": name, "kind": "boolean", "value": value}
    if isinstance(value, int):
        names = _value_names(definition, label, owner, name) if type_obj is not None else {}
        meaning = names.get(value)
        node = {"name": name, "kind": "integer", "value": value}
        if meaning is not None:
            # A display node: "value" is what a reader sees, "number" the integer.
            node.update(value=f"{value} ({meaning})", number=value, decoded=meaning)
        if names:
            node["options"] = [
                {"number": number, "name": text, "active": number == value} for number, text in sorted(names.items())
            ]
        return node
    if isinstance(value, str):
        return {"name": name, "kind": "string", "value": value}
    if value is None:
        return {"name": name, "kind": "null"}
    return {"name": name, "kind": "value", "value": _json_safe(value)}


def _schema_reading(type_name: str, data: bytes) -> tuple[Any, dict[str, Any]]:
    """Decode ``data`` as ``type_name`` (every byte read) and build its display nodes."""
    decoded = gsma_schema.decode_type_strict(type_name, data)
    tree, definition, module = gsma_schema.parse_tree_for(type_name)
    nodes = _schema_value_nodes(
        decoded, type_name, gsma_schema.type_tree(type_name), type_label=type_name, source=data,
        definition=definition, tree=tree, module=module,
    )
    return decoded, nodes


def decode_es10(data: bytes, *, direction: str, registry: TagRegistry) -> dict[str, Any]:
    """Decode one ES10 TLV; ``direction`` is request or response."""
    items = _iter_tlvs(data)
    if len(items) != 1 or not _tlvs_cover(data, items):
        tree = _generic_tree(data, registry)
        return _payload("es10", "ES10 payload", "SGP.22 v3.1 section 5.7", nodes=_tree_to_nodes(tree) if tree else [], notes=["Expected one BF-tagged data object."])
    root = items[0]
    candidates = es10_types_for(root.tag_hex)
    type_names = list(candidates.get(direction) or [])
    if not type_names:
        type_names = list(candidates.get("response" if direction == "request" else "request") or [])
    docs = ", ".join(candidates.get("docs") or []) or "GSMA SGP.22 / SGP.32"
    title = type_names[0] if type_names else f"ES10 object '{root.tag_hex}'"
    payload = _payload("es10", title, docs, tag=root.tag_hex, direction=direction, typeCandidates=type_names)
    schema_error = ""
    for type_name in type_names:
        if not gsma_schema.has_type(type_name):
            continue
        try:
            decoded, nodes = _schema_reading(type_name, data)
        except Exception as error:  # noqa: BLE001 - asn1tools decode errors are library-specific
            schema_error = f"{type_name}: {error}"
            continue
        if isinstance(decoded, dict) and not decoded and len(root.value) > 0:
            # A type with no member for what the object carries is not a reading of it: the
            # memberless GetEuiccInfo2Request would stand in for an EUICCInfo2 the response type refused.
            schema_error = schema_error or f"{type_name}: no member for the {len(root.value)} byte(s) the object carries"
            continue
        payload["title"] = type_name
        payload["schemaType"] = type_name
        payload["schema"] = nodes
        payload["schemaJson"] = _json_safe(decoded)
        break
    status = gsma_schema.rsp_specification_status()
    if "schemaType" in payload:
        payload["schemaSource"] = gsma_schema.type_source(payload["schemaType"])
        # SGP.22 v3.1 section 2.5.6: the outcome a ProfileInstallationResult
        # holds in its EUICCResponse heads the reading, wherever the result sits.
        result = _installation_result(payload["schema"])
        if result is not None:
            payload["result"] = result
        if payload["schemaType"] == "EUICCInfo2":
            notes = _euicc_info2_check_notes(data)
            if notes:
                payload["notes"] = notes
    else:
        payload["schemaSource"] = status.get("modules") or []
    if "schemaType" not in payload:
        notes = []
        if not status.get("available"):
            notes.append("Schema decode unavailable: " + (status.get("error") or "compiled RSP module missing") + ". Showing the generic BER tree.")
        elif schema_error:
            notes.append("Schema decode failed: " + schema_error + ". Showing the generic BER tree.")
        elif type_names:
            notes.append("No compiled type for " + ", ".join(type_names) + ". Showing the generic BER tree.")
        payload["notes"] = notes
        if root.tag_hex == "BF22":
            _euicc_info2_tag_reading(payload, data)
        _located_installation_result(payload, data)
    tree = _generic_tree(data, registry)
    payload["nodes"] = _tree_to_nodes(tree) if tree else []
    return payload


def _hinted_types(hint: str) -> list[str]:
    """Compiled type names a JSON member name stands for, as given or with its first letter raised."""
    text = re.sub(r"\[\d+\]$", "", str(hint or "").strip())
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", text) is None:
        return []
    names: list[str] = []
    for candidate in (text, text[0].upper() + text[1:]):
        if candidate not in names and gsma_schema.has_type(candidate):
            names.append(candidate)
    return names


def _docs_for_type(type_name: str) -> str:
    if _ES10_TABLE is None:
        es10_types_for("")
    for entry in (_ES10_TABLE or {}).values():
        if type_name in entry.get("request", []) or type_name in entry.get("response", []):
            return ", ".join(entry.get("docs") or [])
    return ""


def decode_rsp_object(data: bytes, *, type_hint: str = "") -> dict[str, Any] | None:
    """Schema-decode one GSMA RSP data object; None when no compiled type reads it.

    A ``type_hint`` that names a compiled type, as given or with its first
    letter raised, is tried first: an ES9+ or ESipa JSON member name is the
    name of its type that way (``smdpSigned2`` -> ``SmdpSigned2``). A single
    BF-tagged object is then read as the response and the request types of its
    tag. A type counts only when it reads every byte, so IpaEuiccDataRequest
    and IpaEuiccDataResponse, both 'BF52', are told apart by their content.
    The payload carries ``notation``, the reading as indented text.
    """
    if not data:
        return None
    data = bytes(data)
    items = _iter_tlvs(data)
    bf_object = len(items) == 1 and _tlvs_cover(data, items) and items[0].tag_hex.startswith("BF")
    # Anything else keeps clear of the schema compile, which costs about a second.
    if not bf_object and not str(type_hint or "").strip():
        return None
    if not gsma_schema.rsp_specification_status().get("available"):
        return None
    payload: dict[str, Any] | None = None
    for type_name in _hinted_types(type_hint):
        try:
            decoded, nodes = _schema_reading(type_name, data)
        except Exception:  # noqa: BLE001 - asn1tools decode errors are library-specific; the hint may simply be wrong
            continue
        payload = _payload(
            "rsp",
            type_name,
            _docs_for_type(type_name),
            schemaType=type_name,
            schema=nodes,
            schemaJson=_json_safe(decoded),
            schemaSource=gsma_schema.type_source(type_name),
        )
        break
    if payload is None and bf_object:
        for direction in ("response", "request"):
            candidate = decode_es10(data, direction=direction, registry=_registry())
            if candidate.get("schemaType"):
                payload = candidate
                break
    if payload is None:
        return None
    payload["notation"] = render_rsp_reading(payload)
    return payload


# ----------------------------------------------------------------------
# Status words
# ----------------------------------------------------------------------


def _sw_translator() -> Callable[[int, int], str] | None:
    try:
        from yggdrasim_common import registry as yggdrasim_registry

        translator = yggdrasim_registry.get("scp03.core.utils.sw")
        return translator.translate
    except Exception:  # noqa: BLE001
        return None


def describe_sw(sw1: int, sw2: int, *, command: str = "") -> dict[str, Any]:
    translate = _sw_translator()
    text = ""
    if translate is not None:
        try:
            text = str(translate(sw1, sw2) or "")
        except Exception:  # noqa: BLE001
            text = ""
    if not text:
        text = _basic_sw_text(sw1, sw2)
    entry: dict[str, Any] = {"sw": f"{sw1:02X}{sw2:02X}", "meaning": text}
    if sw1 == 0x61:
        entry["followUp"] = f"GET RESPONSE with Le = {sw2 or 256}"
    elif sw1 == 0x6C:
        entry["followUp"] = f"re-issue the command with Le = {sw2:02X}"
    elif sw1 == 0x91:
        entry["followUp"] = f"FETCH the pending proactive command ({sw2} byte(s))"
    elif command == "GET STATUS" and sw1 == 0x63 and sw2 == 0x10:
        entry["followUp"] = "GET STATUS [get next occurrence(s)] returns the rest (GPC v2.3.1 table 11-38)"
    entry["ok"] = sw1 in (0x90, 0x91, 0x92, 0x61) or (sw1 == 0x63 and sw2 == 0x10)
    return entry


def _basic_sw_text(sw1: int, sw2: int) -> str:
    # ETSI TS 102 221 v18.4 tables 10.7 to 10.14, the rows a shell without
    # the SCP03 translator still needs.
    table = {
        0x9000: "Normal ending of the command",
        0x6200: "No information given, state of non-volatile memory unchanged",
        0x6281: "Part of returned data may be corrupted",
        0x6282: "End of file/record reached before reading Le bytes or unsuccessful search",
        0x6283: "Selected file invalidated",
        0x6285: "Selected file in termination state",
        0x62F1: "More data available",
        0x62F2: "More data available and proactive command pending",
        0x62F3: "Response data available",
        0x63F1: "More data expected",
        0x63F2: "More data expected and proactive command pending",
        0x6400: "No information given, state of non-volatile memory unchanged",
        0x6500: "No information given, state of non-volatile memory changed",
        0x6581: "Memory problem",
        0x6700: "Wrong length",
        0x6B00: "Wrong parameter(s) P1-P2",
        0x6D00: "Instruction code not supported or invalid",
        0x6E00: "Class not supported",
        0x6F00: "Technical problem, no precise diagnosis",
        0x6800: "No information given (function in CLA not supported)",
        0x6881: "Logical channel not supported",
        0x6882: "Secure messaging not supported",
        0x6900: "No information given (command not allowed)",
        0x6981: "Command incompatible with file structure",
        0x6982: "Security status not satisfied",
        0x6983: "Authentication/PIN method blocked",
        0x6984: "Referenced data invalidated",
        0x6985: "Conditions of use not satisfied",
        0x6986: "Command not allowed (no EF selected)",
        0x6989: "Command not allowed - secure channel - security not satisfied",
        0x6A80: "Incorrect parameters in the data field",
        0x6A81: "Function not supported",
        0x6A82: "File not found",
        0x6A83: "Record not found",
        0x6A84: "Not enough memory space",
        0x6A86: "Incorrect parameters P1 to P2",
        0x6A87: "Lc inconsistent with P1 to P2",
        0x6A88: "Referenced data not found",
        0x9300: "SIM Application Toolkit is busy",
    }
    exact = table.get((sw1 << 8) | sw2)
    if exact:
        return exact
    if sw1 == 0x91:
        return f"Normal ending, proactive command pending ({sw2} bytes)"
    if sw1 == 0x92:
        return "Normal ending, ongoing data transfer session"
    if sw1 == 0x61:
        return f"Response data available ({sw2 or 256} bytes) - GET RESPONSE"
    if sw1 == 0x6C:
        return f"Wrong Le, {sw2} byte(s) available"
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return f"Verification failed, {sw2 & 0x0F} retries remaining (or {sw2 & 0x0F} internal retries)"
    return "Unknown status word"


# ----------------------------------------------------------------------
# Input parsing
# ----------------------------------------------------------------------

_FILE_MARKER = "@file"
_HEX_RUN = re.compile(r"(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,-]*(?:0x)?[0-9A-Fa-f]{2})*")
_COMMAND_MARKERS = ("c-apdu", "capdu", "cmd", "command", "tx", ">>", "->", "→", ">", "c:")
_RESPONSE_MARKERS = ("r-apdu", "rapdu", "rsp", "response", "rx", "<<", "<-", "←", "<", "r:")


# One command per row with ``#`` comments is the script file the SCP03 shell's RUN and the SCP80
# shell's ``script`` read; a bracketed label opens the raw exchange lines the SCP11 transport prints.
_ROW_LABEL = re.compile(r"^\[.*\]\s*(?=[<>])")
_ROW_ESCAPES = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ROW_SW = re.compile(r"(?i)\bsw\s*[=:]\s*([0-9A-F]{4})\b")
_ROW_DATA_LABEL = re.compile(r"(?i)\bdata\s*[=:]")
_ROW_DURATION = re.compile(r"(?i)\b\d+(?:\.\d+)?\s*ms\b")
# TS 102 221 v18.4 section 10.1.0, Table 10.2 case 1: a command is at least CLA INS P1 P2.
_COMMAND_HEADER_LENGTH = 4


@dataclass
class RawExchange:
    command: bytes | None = None
    response: bytes | None = None
    sw: bytes | None = None
    source: str = ""
    # The input row the exchange starts on, counted from 1.
    line: int = 0
    # The file the terminal selected for this command without an APDU of its own
    # (the <fileid> and <pathid> of AT+CRSM); empty when the trace shows the SELECT.
    file_id: str = ""
    file_path: str = ""


def _strip_marker(text: str) -> tuple[str, str]:
    stripped = text.strip()
    lowered = stripped.lower()
    for marker in _COMMAND_MARKERS:
        if lowered.startswith(marker):
            return "command", stripped[len(marker):].strip(" :=\t")
    for marker in _RESPONSE_MARKERS:
        if lowered.startswith(marker):
            return "response", stripped[len(marker):].strip(" :=\t")
    return "", stripped


def _hex_bytes(text: str) -> bytes | None:
    cleaned = re.sub(r"(?i)0x", "", text)
    cleaned = re.sub(r"[\s:,\-\.]", "", cleaned)
    if len(cleaned) == 0 or len(cleaned) % 2 != 0 or re.search(r"[^0-9A-Fa-f]", cleaned):
        return None
    return bytes.fromhex(cleaned)


def _split_line_segments(line: str) -> list[str]:
    # The GUI APDU bus writes "→ 00A4... · ← 6F... · sw=9000 · 1.4 ms"; other
    # tools use "|" or ";" between the two halves.
    return [segment for segment in re.split(r"\s[·|;]\s|\t", line) if segment.strip()]


def _row_text(line: str) -> str:
    """One input row without its ``#`` comment, the way the shells' script runners read a script file."""
    return _ROW_ESCAPES.sub("", line.replace("\ufeff", "")).split("#", 1)[0].strip()


def _is_known_command(data: bytes) -> bool:
    """True for a well-formed command APDU whose instruction the decoder knows for its class."""
    if len(data) < _COMMAND_HEADER_LENGTH or _looks_like_response(data):
        return False
    try:
        body = _parse_apdu_body(data)
    except DecodeError:
        return False
    return classify_command(data[0], data[1], data[2], data[3], body["data"]).domain != "unknown"


def _miswritten_command(data: bytes) -> bool:
    """True for a row that opens like a command the decoder knows and cannot be an answer.

    An answer ends with its status word, and every first status byte starts
    '6' or '9' (TS 102 221 v18.4 section 10.2.1; the procedure bytes '61' and
    '6C' of section 7.3.1.1.5). A row that ends otherwise and carries a known
    class and instruction is a command whose lengths do not add up.
    """
    if len(data) < _COMMAND_HEADER_LENGTH + 1 or (data[-2] >> 4) in (0x6, 0x9) and data[-2] != 0x60:
        return False
    items = _iter_tlvs(data)
    if items and _tlvs_cover(data, items):
        # A whole TLV sequence is an answer written without its status word.
        return False
    return classify_command(data[0], data[1], data[2], data[3], b"").domain != "unknown"


def _unmarked_role(data: bytes, pending: RawExchange | None, hint: str) -> str:
    """Whether a row without a marker is a command or an answer.

    An explicit context is taken at face value: under ``apdu`` every row is a
    command, under ``response`` every row an answer. Otherwise the first row
    is a command unless it has the shape of an answer, and while a command
    waits for its answer, only a row that is itself a command of a known
    instruction starts the next one. That is what reads a script of one
    command per row as that many commands; any other row is the answer,
    except a miswritten command, which is shown as one with what is wrong.
    """
    if len(data) < _COMMAND_HEADER_LENGTH or hint == "response":
        return "response"
    if hint == "apdu":
        return "command"
    if pending is None:
        return "response" if _looks_like_response(data) else "command"
    return "command" if _is_known_command(data) or _miswritten_command(data) else "response"


def parse_exchanges(text: str, hint: str = "auto", unread: list[int] | None = None) -> list[RawExchange]:
    """Split pasted text into command/response exchanges, one row or one pair of rows each.

    A marker (``>``, ``<``, ``C:``, ``R:`` and the like) says what a row is;
    ``_unmarked_role`` decides for a row without one. ``#`` starts a comment.
    The number of every row that held no hex is added to ``unread``.
    """
    exchanges: list[RawExchange] = []
    pending: RawExchange | None = None
    marked_file: tuple[str, str] = ("", "")
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = _row_text(raw_line)
        if not line:
            continue
        if line.startswith(_FILE_MARKER + " "):
            # Written by the AT rewrite before a restricted-access command.
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{4}", parts[1]):
                marked_file = (parts[1].upper(), parts[2].upper() if len(parts) > 2 and _hex_bytes(parts[2]) else "")
            continue
        read = False
        # The exchange a response segment of this row has just closed: a status word written after it joins it.
        answered: RawExchange | None = None
        for segment in _split_line_segments(line):
            marker, body = _strip_marker(_ROW_LABEL.sub("", segment.strip()))
            sw_match = _ROW_SW.search(body)
            body = _ROW_DATA_LABEL.sub("", _ROW_DURATION.sub("", _ROW_SW.sub("", body))).strip()
            data = _hex_bytes(body) if body else None
            role = marker
            if data is not None and not marker:
                role = _unmarked_role(data, pending, hint)
            if sw_match is not None and role != "command":
                # A status word written out closes the exchange, with the data beside it when there is any.
                target = answered if answered is not None and data is None else pending
                if target is None:
                    target = RawExchange(source=line, line=number)
                target.sw = bytes.fromhex(sw_match.group(1))
                if data:
                    target.response = data
                if target is not answered:
                    exchanges.append(target)
                pending = None
                answered = None
                read = True
                continue
            if data is None:
                continue
            read = True
            if role == "command":
                if pending is not None:
                    exchanges.append(pending)
                pending = RawExchange(command=data, source=line, line=number, file_id=marked_file[0], file_path=marked_file[1])
                marked_file = ("", "")
                if sw_match is not None:
                    # "<command> sw=9000" on one row: the command with its status word.
                    pending.sw = bytes.fromhex(sw_match.group(1))
                    exchanges.append(pending)
                    pending = None
                continue
            if pending is None:
                pending = RawExchange(source=line, line=number)
            if len(data) == 2 and pending.response is None and marker != "response":
                pending.sw = data
            else:
                pending.response = data
                answered = pending
            exchanges.append(pending)
            pending = None
        if not read and unread is not None:
            unread.append(number)
    if pending is not None:
        exchanges.append(pending)
    return exchanges


def _unread_rows_note(unread: list[int]) -> str:
    """Which rows held no hex, by number; a row is never quoted, since a script row can carry a credential."""
    spans: list[str] = []
    start = previous = unread[0]
    for number in unread[1:] + [0]:
        if number == previous + 1:
            previous = number
            continue
        spans.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    shown = spans[:12]
    more = f" and {len(spans) - len(shown)} more" if len(spans) > len(shown) else ""
    rows = "row" if len(unread) == 1 else "rows"
    return f"{len(unread)} {rows} held no hex and {'was' if len(unread) == 1 else 'were'} left unread: {rows} {', '.join(shown)}{more}."


def _looks_like_response(data: bytes) -> bool:
    if len(data) == 2:
        return True
    if len(data) >= 4:
        try:
            _parse_apdu_body(data)
        except DecodeError:
            return True
        # A well-formed APDU whose "class" byte is a BER tag ('62', '6F',
        # 'BF', 'D0', 'E3') that also parses as TLV is more plausibly a
        # response body.
        first = data[0]
        if first in (0x62, 0x6F, 0xBF, 0xD0, 0xE3, 0x30, 0xA0):
            items = _iter_tlvs(data[:-2]) or _iter_tlvs(data)
            if items and (_tlvs_cover(data[:-2], items) or _tlvs_cover(data, items)):
                return True
        return False
    return False


def _split_response(data: bytes) -> tuple[bytes, bytes | None]:
    if len(data) >= 2:
        return data[:-2], data[-2:]
    return data, None


# ----------------------------------------------------------------------
# Trace state and exchange decoding
# ----------------------------------------------------------------------


@dataclass
class TraceState:
    selected_fid: str = ""
    selected_adf: str = ""
    # Where the selection came from, when not from a SELECT in the trace.
    selection_origin: str = ""
    selected_aid: bytes = b""
    pending_command: dict[str, Any] | None = None
    pending_context: CommandContext | None = None
    chained_data: bytes = b""
    es10_blocks: bytes = b""
    es10_context: CommandContext | None = None
    last_get_status_p1: int | None = None
    # The BIP channel data of the trace, one stream per channel identifier (a BipChannelObserver each).
    channel_observers: dict[int, Any] = field(default_factory=dict)
    # The channel of the RECEIVE DATA command whose TERMINAL RESPONSE is still to come.
    receive_channel: int = 0


_REGISTRY: TagRegistry | None = None


def _registry() -> TagRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = TagRegistry.load()
    return _REGISTRY


def _secure_messaging(cla: int) -> bool:
    """True when the class byte indicates secure messaging (TS 102 221 v18.4 tables 10.4 and 10.4b)."""
    return bool(cla & 0x20) if cla & 0x40 else bool(cla & 0x0C)


def _protected_command_data(apdu: dict[str, Any], data: bytes, registry: TagRegistry) -> dict[str, Any] | None:
    """An ES10 data field under a secure channel; None when the field reads as it stands.

    GPC Amd D v1.1.2 section 6.2.4 appends a C-MAC of 8 bytes to the data
    field, and section 6.2.6 may encrypt what is before it. A field that is
    one TLV without its last 8 bytes is read as that TLV; anything else is
    shown as the protected block it is, not as an ES10 object.
    """
    if not _secure_messaging(int(apdu["cla"], 16)):
        return None
    whole = _iter_tlvs(data)
    if len(whole) == 1 and _tlvs_cover(data, whole):
        return None
    body, mac = data[:-8], data[-8:]
    items = _iter_tlvs(body) if len(data) > 8 else []
    if len(items) == 1 and _tlvs_cover(body, items):
        payload = decode_es10(body, direction="request", registry=registry)
        payload["notes"] = list(payload.get("notes") or []) + [f"The last 8 bytes are the C-MAC of the secure channel, not checked here: {_hex(mac)}."]
        return payload
    return _payload(
        "protected", "Protected command data", "GPC Amd D v1.1.2 section 6.2.4",
        fields=[_field("Data field", _hex(data), f"{len(data)} byte(s)")],
        notes=["The class byte indicates secure messaging: the data field ends with a C-MAC and may be encrypted, so it is not read as an ES10 object."],
    )


def _decode_command_payload(ctx: CommandContext, apdu: dict[str, Any], data: bytes, state: TraceState) -> dict[str, Any] | None:
    kind = ctx.payload_kind
    registry = _registry()
    if not data:
        return None
    if kind == "es10_request":
        protected = _protected_command_data(apdu, data, registry)
        if protected is not None:
            return protected
        p1 = int(apdu["p1"], 16)
        if not p1 & 0x80:
            state.es10_blocks += data
            state.es10_context = ctx
            return _payload("es10", "ES10 request block (more blocks follow)", "SGP.22 v3.1 section 5.7.2", fields=[_field("Block bytes", len(data)), _field("Accumulated", len(state.es10_blocks))])
        whole = state.es10_blocks + data if state.es10_blocks else data
        state.es10_blocks = b""
        state.es10_context = None
        return decode_es10(whole, direction="request", registry=registry)
    if kind == "gp_store_data":
        tree = _generic_tree(data, registry)
        return _payload("gp_store_data", "STORE DATA block", "GPC v2.3.1 table 11-88", nodes=_tree_to_nodes(tree) if tree else [_node("", "data block", data)])
    if kind == "gp_get_status_request":
        nodes = []
        for item in _iter_tlvs(data):
            if item.tag_hex == "4F":
                nodes.append(_node("4F", "Search criterion: AID", item.value, spec="GPC v2.3.1 table 11-32", decoded=aid_name(item.value) or ("any" if not item.value else None)))
            elif item.tag_hex == "5C":
                nodes.append(_node("5C", "Tag list", item.value, spec="GPC v2.3.1 section 11.4.3.1", decoded=" ".join(f"{tag.tag_hex}" for tag in _iter_tlvs(item.value)) or _hex(item.value)))
            else:
                nodes.append(_node(item.tag_hex, "search criterion", item.value))
        return _payload("gp_get_status_request", "GET STATUS search criteria", "GPC v2.3.1 table 11-32", nodes=nodes)
    if kind == "gp_install":
        return decode_gp_install(int(apdu["p1"], 16), data)
    if kind == "gp_delete":
        return decode_gp_delete(data)
    if kind == "gp_aid":
        return _payload("gp_aid", "Target AID", "GPC v2.3.1 section 11.10.2.3", fields=[_field("AID", _hex(data), aid_name(data))])
    if kind == "gp_get_data_request":
        nodes = [_node(item.tag_hex, "Tag list" if item.tag_hex == "5C" else "data object", item.value) for item in _iter_tlvs(data)]
        return _payload("gp_get_data_request", "GET DATA command data", "GPC v2.3.1 table 11-27", nodes=nodes)
    if kind == "scp_host_challenge":
        return _payload("scp_host_challenge", "Host challenge", "GPC Amd D v1.1.2 section 7.1.1.5", fields=[_field("Host challenge", _hex(data), f"{len(data)} byte(s), 8 expected")])
    if kind == "gp_put_key":
        from . import payload_readings

        try:
            fields = payload_readings.put_key_fields(data)
        except (ValueError, ImportError) as error:
            fields = [_field("Key Version Number", f"{data[0]:02X}"), _field("Key data", _hex(data[1:]), f"not read as a key data field: {error}")]
        return _payload("gp_put_key", "PUT KEY data field", "GPC v2.4 section 11.8.2.3", fields=fields)
    if kind in ("scp11_key_agreement", "scp11_certificate"):
        from . import payload_readings

        if kind == "scp11_key_agreement":
            title, spec, scp11 = "Data for key establishment", "GPC Amd F v1.2 Table 6-17", payload_readings.scp11_key_agreement_nodes(data)
        else:
            title, spec, scp11 = "Certificate(s)", "GPC Amd F v1.2 Table 6-12", payload_readings.scp11_certificate_nodes(data)
        if scp11 is not None:
            return _payload(kind, title, spec, nodes=scp11)
        return _payload(kind, title, spec, fields=[_field("Data field", _hex(data), f"{len(data)} byte(s); not whole TLVs, as in one block of a chained command or under secure messaging")])
    if kind == "terminal_capability":
        from . import payload_readings

        capability = payload_readings.terminal_capability_nodes(data)
        if capability is not None:
            return _payload("terminal_capability", "TERMINAL CAPABILITY", "TS 102 221 v18.4 section 11.1.19.2", nodes=capability)
        tree = _generic_tree(data, registry)
        return _payload("tlv", "Command data (BER-TLV)", "ITU-T X.690", nodes=_tree_to_nodes(tree) if tree else [_node("", "command data", data)])
    if kind == "gp_load":
        tree = _generic_tree(data, registry)
        return _payload("gp_load", "LOAD data block", "GPC v2.3.1 section 11.6", nodes=_tree_to_nodes(tree) if tree else [_node("", "load file data block", data)])
    if kind == "select_target":
        p1 = int(apdu["p1"], 16)
        if p1 == 0x04:
            return _payload("select", "SELECT by DF name", "TS 102 221 v18.4 table 11.1", fields=[_field("AID", _hex(data), aid_name(data))])
        if p1 in (0x08, 0x09) and len(data) >= 2 and len(data) % 2 == 0:
            path = " / ".join(_hex(data[index : index + 2]) for index in range(0, len(data), 2))
            return _payload("select", "SELECT by path", "TS 102 221 v18.4 table 11.1", fields=[_field("Path", path)])
        return _payload("select", "SELECT by file identifier", "TS 102 221 v18.4 table 11.1", fields=[_field("File identifier", _hex(data))])
    if kind == "cat_terminal_response":
        return _follow_channel_data(decode_cat(data, expect="cat_terminal_response"), state, terminal_response=True)
    if kind == "cat_envelope":
        return decode_cat(data, expect="cat_envelope")
    if kind == "terminal_profile":
        return decode_cat(data, expect="terminal_profile")
    if kind == "auth_request":
        return decode_auth_request(int(apdu["ins"], 16), int(apdu["p2"], 16), data)
    if kind == "pin":
        return _payload("pin", "PIN data", "TS 102 221 v18.4 section 11.1.9", fields=[_field("Data", f"{len(data)} byte(s)", "PIN values are not echoed")])
    if kind in ("file_content", "file_record"):
        return _decode_file_content(data, state, apdu)
    tree = _generic_tree(data, registry)
    if tree is not None:
        return _payload("tlv", "Command data (BER-TLV)", "ITU-T X.690", nodes=_tree_to_nodes(tree))
    return _payload("raw", "Command data", "", fields=[_field("Data", _hex(data), f"{len(data)} byte(s)")])


def _decode_file_content(data: bytes, state: TraceState, apdu: dict[str, Any]) -> dict[str, Any]:
    fid = state.selected_fid
    if not fid:
        return _payload("file_content", "File content", "", fields=[_field("Data", _hex(data), f"{len(data)} byte(s); no SELECT seen earlier in the trace")])
    context_path = state.selected_adf or None
    decoded: Any = None
    try:
        from yggdrasim_common import registry as yggdrasim_registry

        content_decoder = yggdrasim_registry.get("scp03.core.decoders.content")
        decoded = content_decoder.decode_obj(fid, _hex(data), context_path=context_path)
    except Exception:  # noqa: BLE001 - the decoder set is optional
        decoded = None
    origin = state.selection_origin or "the last SELECT in the trace"
    fields = [_field("File", fid + (f" under {state.selected_adf}" if state.selected_adf else ""), f"from {origin}")]
    if isinstance(decoded, dict):
        for key, value in decoded.items():
            fields.append(_field(str(key), value if isinstance(value, (int, float, bool)) else str(value)))
        return _payload("file_content", f"EF {fid} content", "3GPP TS 31.102 / TS 51.011 file decoders", fields=fields)
    fields.append(_field("Data", _hex(data), f"{len(data)} byte(s); no content decoder for this file"))
    return _payload("file_content", f"EF {fid} content", "", fields=fields)


def _decode_response_payload(ctx: CommandContext | None, command: dict[str, Any] | None, data: bytes, state: TraceState) -> dict[str, Any] | None:
    if not data:
        return None
    registry = _registry()
    kind = ctx.response_kind if ctx else ""
    if kind == "fcp" or (not ctx and data[0] in (0x62, 0x6F)):
        return decode_fcp(data)
    if kind == "es10_response" or (not ctx and data[0] == 0xBF):
        return decode_es10(data, direction="response", registry=registry)
    if kind == "gp_registry":
        return decode_gp_registry(data, subset_p1=state.last_get_status_p1)
    if kind == "gp_confirmation":
        return decode_gp_confirmation(data, ctx.name if ctx else "INSTALL")
    if kind == "gp_get_data_response":
        tag_hex = ctx.notes[0].replace("tag ", "") if ctx and ctx.notes and ctx.notes[0].startswith("tag ") else ""
        return decode_gp_get_data_response(tag_hex, data, registry)
    if kind == "scp_init_update_response":
        return decode_scp_init_update_response(data)
    if kind == "cat_proactive" or (not ctx and data[0] == 0xD0):
        return _follow_channel_data(decode_cat(data, expect="cat_proactive"), state, terminal_response=False)
    if kind == "cat_envelope_response":
        from . import payload_readings

        report = payload_readings.report_user_data_nodes(data)
        if report is not None:
            # TS 31.115 v19 section 4.4: the response packet rides in the user data of the SMS-DELIVER-REPORT.
            return _payload("cat", "ENVELOPE response: secured response packet", "TS 31.115 v19 section 4.4", nodes=report)
        tree = _generic_tree(data, registry)
        return _payload("cat", "ENVELOPE response data", "TS 102 223 v18.3 section 7", nodes=_tree_to_nodes(tree) if tree else [_node("", "response data", data)])
    if kind == "auth_response":
        return decode_auth_response(int(command["ins"], 16), int(command["p2"], 16), data) if command else None
    if kind.startswith("scp11") and kind.endswith("_authenticate_response"):
        from . import payload_readings

        table, card_key = payload_readings.SCP11_RESPONSES[kind]
        scp11 = payload_readings.scp11_key_agreement_nodes(data, card_key=card_key)
        if scp11 is not None:
            return _payload(kind, "Key establishment response", f"GPC Amd F v1.2 {table}", nodes=scp11)
    if kind == "suci":
        from . import payload_readings

        fields = payload_readings.suci_fields(data)
        if fields is not None:
            return _payload("suci", "SUCI", "TS 31.102 v19.5 section 7.5.2.1", fields=fields)
        tree = _generic_tree(data, registry)
        return _payload("tlv", "Response data (BER-TLV)", "ITU-T X.690", nodes=_tree_to_nodes(tree) if tree else [_node("", "response data", data)])
    if kind in ("file_content", "file_record"):
        return _decode_file_content(data, state, command or {})
    if kind == "channel_number" and len(data) == 1:
        return _payload("channel", "MANAGE CHANNEL response", "TS 102 221 v18.4 section 11.1.17.2", fields=[_field("Assigned logical channel", data[0])])
    if not ctx and data[0] == 0xE3:
        return decode_gp_registry(data)
    tree = _generic_tree(data, registry)
    if tree is not None:
        return _payload("tlv", "Response data (BER-TLV)", "ITU-T X.690", nodes=_tree_to_nodes(tree))
    return _payload("raw", "Response data", "", fields=[_field("Data", _hex(data), f"{len(data)} byte(s)")])


def _update_selection_state(ctx: CommandContext, apdu: dict[str, Any], data: bytes, state: TraceState) -> None:
    if ctx.name != "SELECT FILE":
        return
    state.selection_origin = ""
    p1 = int(apdu["p1"], 16)
    if p1 == 0x04 and data:
        state.selected_aid = data
        name = aid_name(data)
        if name.startswith("USIM"):
            state.selected_adf = "ADF_USIM"
        elif name.startswith("ISIM"):
            state.selected_adf = "ADF_ISIM"
        else:
            state.selected_adf = ""
        state.selected_fid = ""
    elif p1 in (0x00, 0x08, 0x09) and len(data) >= 2:
        state.selected_fid = _hex(data[-2:])
        if state.selected_fid == "3F00":
            state.selected_adf = ""
    elif p1 == 0x03:
        state.selected_fid = ""


def decode_exchange(raw: RawExchange, state: TraceState, index: int) -> dict[str, Any]:
    """Decode one command/response pair, updating the trace state."""
    result: dict[str, Any] = {"index": index}
    ctx: CommandContext | None = None
    command: dict[str, Any] | None = None
    data_field = b""
    if raw.file_id:
        # TS 27.007 V19.6 section 8.18 NOTE 1: the MT selects the file itself before the command.
        state.selected_fid = raw.file_id
        state.selected_adf = "/".join(raw.file_path[i:i + 4] for i in range(0, len(raw.file_path), 4))
        state.selection_origin = "the file identifier of the AT command"
        result["selectedFile"] = raw.file_id + (f" under {raw.file_path}" if raw.file_path else "")
    if raw.command is not None:
        try:
            body = _parse_apdu_body(raw.command)
        except DecodeError as error:
            result["command"] = {"hex": _hex(raw.command), "error": str(error)}
            result["context"] = {"domain": "unknown", "label": _DOMAIN_LABELS["unknown"], "spec": "", "summary": "APDU header could not be parsed"}
            body = None
        if body is not None:
            cla, ins, p1, p2 = raw.command[0], raw.command[1], raw.command[2], raw.command[3]
            data_field = body["data"]
            ctx = classify_command(cla, ins, p1, p2, data_field)
            command = {
                "hex": _hex(raw.command),
                "cla": f"{cla:02X}",
                "ins": f"{ins:02X}",
                "p1": f"{p1:02X}",
                "p2": f"{p2:02X}",
                "case": body["case"],
                "extendedLength": body["extendedLength"],
                "name": ctx.name,
                "spec": ctx.spec,
                "header": [_field("CLA", f"{cla:02X}"), _field("INS", f"{ins:02X}", ctx.name, spec=ctx.spec)] + ctx.header,
            }
            if body["lc"] is not None:
                command["lc"] = body["lc"]
            if body["le"] is not None:
                command["le"] = body["le"]
            if data_field:
                command["dataHex"] = _hex(data_field)
            if ctx.name == "GET RESPONSE" and state.pending_context is not None:
                # The response belongs to the command that answered '61 xx'.
                ctx = CommandContext("chained", "GET RESPONSE", _UICC_SPEC, summary=f"continues the {state.pending_context.name} response", header=ctx.header)
                ctx.response_kind = state.pending_context.response_kind
                command["continues"] = state.pending_context.name
            else:
                # GET RESPONSE comes immediately after the command it completes (TS 102 221 v18.4 section 12.1.1.1),
                # so any other command ends the chain; without this an unanswered row would leave it open.
                state.pending_context = None
                state.pending_command = None
                state.chained_data = b""
                if ctx.name == "GET STATUS":
                    state.last_get_status_p1 = p1
                payload = _decode_command_payload(ctx, command, data_field, state)
                if payload is not None:
                    command["payload"] = payload
                _update_selection_state(ctx, command, data_field, state)
            result["command"] = command
    if ctx is not None:
        result["context"] = {
            "domain": ctx.domain if ctx.domain != "chained" else (state.pending_context.domain if state.pending_context else "uicc"),
            "label": _DOMAIN_LABELS.get(ctx.domain, ctx.domain) if ctx.domain != "chained" else "GET RESPONSE continuation",
            "spec": ctx.spec,
            "summary": ctx.summary,
            "notes": list(ctx.notes),
        }
    response_data = raw.response
    sw = raw.sw
    if response_data is not None and sw is None:
        response_data, sw = _split_response(response_data)
    if response_data is not None or sw is not None:
        response: dict[str, Any] = {}
        if sw is not None and len(sw) == 2:
            response["sw"] = describe_sw(sw[0], sw[1], command=ctx.name if ctx else "")
        payload_bytes = response_data or b""
        effective_ctx = ctx
        effective_command = command
        if ctx is not None and ctx.domain == "chained" and state.pending_context is not None:
            effective_ctx = state.pending_context
            effective_command = state.pending_command
            payload_bytes = state.chained_data + payload_bytes
        if sw is not None and sw[0] == 0x61 and effective_ctx is not None:
            # Keep the partial data until GET RESPONSE completes it.
            state.pending_context = effective_ctx
            state.pending_command = effective_command
            state.chained_data = payload_bytes
            response["chained"] = True
            response["partialBytes"] = len(payload_bytes)
            if payload_bytes:
                response["dataHex"] = _hex(payload_bytes)
        else:
            if payload_bytes:
                response["dataHex"] = _hex(payload_bytes)
                payload = _decode_response_payload(effective_ctx, effective_command, payload_bytes, state)
                if payload is not None:
                    response["payload"] = payload
            state.pending_context = None
            state.pending_command = None
            state.chained_data = b""
        result["response"] = response
    elif raw.command is None:
        result["context"] = {"domain": "unknown", "label": _DOMAIN_LABELS["unknown"], "spec": "", "summary": "empty exchange"}
    return result


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

_HINTS = ("auto", "apdu", "response", "tlv", "es10", "gp", "uicc", "cat", "sw", "ef")


def _standalone_payload(data: bytes, hint: str) -> dict[str, Any]:
    """Decode bytes that are not an APDU: a bare TLV, a response body or a SW."""
    registry = _registry()
    if hint == "sw" or (len(data) == 2 and hint in ("auto", "response")):
        return {"inputKind": "sw", "sw": describe_sw(data[0], data[1])}
    body, sw = data, None
    if hint == "response":
        body, sw = _split_response(data)
    elif hint == "auto" and len(data) > 2:
        # A pasted response body usually keeps its status word: split it
        # off when the bytes only parse as TLV without the last two.
        whole = _iter_tlvs(data)
        sw1_values = (0x90, 0x91, 0x92, 0x61, 0x62, 0x63, 0x6A, 0x69, 0x6E, 0x6D, 0x67, 0x6B, 0x6F, 0x65, 0x64, 0x68, 0x98)
        if not _tlvs_cover(data, whole):
            head = _iter_tlvs(data[:-2])
            if _tlvs_cover(data[:-2], head) and data[-2] in sw1_values:
                body, sw = _split_response(data)
        elif len(whole) >= 2 and whole[-1].raw == data[-2:] and data[-2] in (0x90, 0x91, 0x92) and len(whole[-1].value) == 0:
            # '90 00' also parses as an empty tag-90 object; a trailing
            # success word after a complete object is the likelier reading.
            body, sw = _split_response(data)
    domain = "tlv"
    payload: dict[str, Any] | None = None
    first = body[0] if body else -1
    if first == 0x30 and hint in ("auto", "response", "es10"):
        # The simaResponse octets pasted on their own; the raw BER-TLV context keeps the plain tree.
        payload = _euicc_response_payload(body)
    if payload is not None:
        domain = "es10"
    elif hint == "es10" or (hint in ("auto", "response") and first == 0xBF):
        domain = "es10"
        payload = decode_es10(body, direction="response", registry=registry)
        if payload.get("schemaType") is None and payload.get("typeCandidates") and "result" not in payload:
            alternative = decode_es10(body, direction="request", registry=registry)
            if alternative.get("schemaType"):
                payload = alternative
    elif hint == "uicc" or (hint in ("auto", "response") and first in (0x62, 0x6F)):
        domain = "uicc"
        payload = decode_fcp(body)
    elif hint == "cat" or (hint in ("auto", "response") and first in _CAT_BER_TAGS):
        domain = "cat"
        payload = decode_cat(body, expect="cat_proactive")
    elif hint == "gp" or (hint in ("auto", "response") and first == 0xE3):
        domain = "gp"
        payload = decode_gp_registry(body)
    if payload is None:
        tree = _generic_tree(body, registry)
        if tree is None:
            raise DecodeError("input is neither an APDU, a response with status word, nor a BER-TLV object")
        payload = _payload("tlv", "BER-TLV object", "ITU-T X.690", nodes=_tree_to_nodes(tree))
        if hint != "tlv":
            # A ProfileInstallationResult inside a wrapper the schema has no type for.
            _located_installation_result(payload, body)
    result: dict[str, Any] = {
        "inputKind": "response" if sw is not None else "tlv",
        "context": {"domain": domain, "label": _DOMAIN_LABELS.get(domain, domain), "spec": payload.get("spec", ""), "summary": payload.get("title", "")},
        "payload": payload,
    }
    if sw is not None:
        result["sw"] = describe_sw(sw[0], sw[1])
    return result


def decode_context_text(text: str, *, hint: str = "auto", max_exchanges: int | None = None) -> dict[str, Any]:
    """Decode pasted hex, one APDU, a script of commands or a whole exchange trace with context.

    Hex is the form the decoder reads first. ``input_forms`` adds the others:
    AT command lines that carry APDUs, and for a paste the hex path refuses
    PEM, a JSON body, base64, an identifier in digits and an ATR. A reading
    that names no domain may be replaced there by a certificate or an ATR.
    ``max_exchanges`` bounds the answer for a caller that shows it whole.
    """
    from . import input_forms

    hint = (hint or "auto").strip().lower()
    if hint not in _HINTS:
        hint = "auto"
    normalized = str(text or "").replace("\ufeff", "").strip()
    if not normalized:
        raise DecodeError("input is empty")
    base: dict[str, Any] = {"format": "context", "hint": hint, "schema": gsma_schema.rsp_specification_status()}

    def finish(reading: dict[str, Any]) -> dict[str, Any]:
        result = dict(base)
        result.update(reading)
        result["notation"] = render_context_notation(result)
        return result

    if hint == "ef":
        return finish(_file_content_reading(normalized))
    if hint == "auto":
        code = input_forms.pcsc_reading(normalized)
        if code is not None:
            return finish(code)
    rewritten = input_forms.rewrite_at_lines(normalized)
    notes: list[str] = []
    if rewritten is not None:
        normalized, notes = rewritten
    try:
        result = _decode_hex_text(normalized, hint, base, number_rows=rewritten is None, max_exchanges=max_exchanges)
    except DecodeError:
        other = input_forms.read_refused(normalized, hint)
        if other is None:
            raise
        return finish(other)
    if hint == "auto":
        refined = _refine_plain_reading(result)
        if refined is not None:
            return finish(refined)
    if notes:
        context = dict(result.get("context") or {})
        context["notes"] = list(context.get("notes") or []) + notes
        result["context"] = context
        result["notation"] = render_context_notation(result)
    return result


def _refine_plain_reading(result: dict[str, Any]) -> dict[str, Any] | None:
    """A certificate, a profile package, an ATR or TLS records in place of a reading that names no domain; None to keep it."""
    from . import input_forms

    payload = result.get("payload")
    if isinstance(payload, dict) and payload.get("title") == "BER-TLV object" and "result" not in payload and not result.get("sw"):
        data = bytes.fromhex(str(result.get("inputHex") or ""))
        refined = input_forms.certificate_reading(data) or input_forms.profile_package_reading(data)
        if refined is not None:
            refined["inputHex"] = _hex(data)
            refined["byteCount"] = len(data)
        return refined
    exchanges = result.get("exchanges")
    if isinstance(exchanges, list) and len(exchanges) == 1 and (exchanges[0].get("context") or {}).get("domain") == "unknown":
        exchange = exchanges[0]
        command = exchange.get("command") or {}
        if exchange.get("response") or not command.get("hex"):
            return None
        data = bytes.fromhex(str(command["hex"]))
        refined = input_forms.atr_reading(data) or input_forms.tls_reading(data)
        if refined is not None:
            refined["inputHex"] = _hex(data)
            refined["byteCount"] = len(data)
        return refined
    return None


def _file_content_reading(text: str) -> dict[str, Any]:
    """The "ef" context: the first line names the file (a file identifier, with its path before it), the rest is its content."""
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    if len(lines) < 2:
        raise DecodeError("the EF content context takes the file on the first line (6F07, or ADF_USIM/6F07) and the content in hex below it")
    parts = [part for part in lines[0].replace("\\", "/").split("/") if part.strip()]
    fid = parts[-1].strip().upper() if parts else ""
    if re.fullmatch(r"[0-9A-F]{4}", fid) is None:
        raise DecodeError("the first line is not a file identifier: four hex digits, with the path before it (ADF_USIM/6F07)")
    data = _hex_bytes(" ".join(lines[1:]))
    if not data:
        raise DecodeError("no hex bytes found under the file line")
    state = TraceState(selected_fid=fid, selected_adf="/".join(part.strip().upper() for part in parts[:-1]), selection_origin="the first line of the input")
    payload = _decode_file_content(data, state, {})
    return {
        "inputKind": "file",
        "context": {"domain": "uicc", "label": _DOMAIN_LABELS["uicc"], "spec": payload.get("spec", ""), "summary": payload.get("title", "")},
        "payload": payload,
        "inputHex": _hex(data),
        "byteCount": len(data),
    }


def _decode_hex_text(
    normalized: str,
    hint: str,
    base: dict[str, Any],
    *,
    number_rows: bool = True,
    max_exchanges: int | None = None,
) -> dict[str, Any]:
    """The hex path: one hex string, an APDU, a script of commands or a trace of exchanges.

    ``number_rows`` is off when the rows are not the ones the operator wrote
    (AT lines rewritten into exchanges): a row number would point nowhere.
    ``max_exchanges`` decodes the first that many and says how many the input
    holds: an answer grows by a few thousand characters per exchange, and a
    megabyte of short rows is some ninety thousand of them.
    """
    unread: list[int] = []
    exchanges = parse_exchanges(normalized, hint, unread)
    held = len(exchanges)
    if max_exchanges is not None and held > max_exchanges:
        exchanges = exchanges[:max_exchanges]
    lines = [row for row in (_row_text(line) for line in normalized.splitlines()) if row]
    single_hex = len(lines) == 1 and _hex_bytes(_strip_marker(lines[0])[1]) is not None and _strip_marker(lines[0])[0] == ""
    result: dict[str, Any] = dict(base)
    if single_hex and hint not in ("apdu",):
        data = _hex_bytes(lines[0]) or b""
        treat_as_apdu = hint == "auto" and len(data) >= 4 and not _looks_like_response(data)
        if hint in ("tlv", "es10", "gp", "uicc", "cat", "sw", "response") or not treat_as_apdu:
            standalone = _standalone_payload(data, hint)
            result.update(standalone)
            result["inputHex"] = _hex(data)
            result["byteCount"] = len(data)
            result["notation"] = render_context_notation(result)
            return result
    if not exchanges:
        raise DecodeError("no hex bytes found in the input")
    state = TraceState()
    decoded = [decode_exchange(raw, state, index + 1) for index, raw in enumerate(exchanges)]
    if number_rows and len(lines) > 1:
        # Where each exchange starts in the input: with comments and unread rows the two counts part.
        for item, raw in zip(decoded, exchanges):
            if raw.line:
                item["row"] = raw.line
    domains = sorted({item.get("context", {}).get("domain", "unknown") for item in decoded})
    # A script has no answers: it is counted as commands.
    counted = "exchanges" if any("response" in item for item in decoded) else "commands"
    result.update(
        {
            "inputKind": "trace" if len(decoded) > 1 else "apdu",
            "exchanges": decoded,
            "exchangeCount": len(decoded),
            "domains": domains,
            "context": decoded[0].get("context", {}) if len(decoded) == 1 else {"domain": "trace", "label": f"{len(decoded)} {counted}", "summary": ", ".join(_DOMAIN_LABELS.get(domain, domain) for domain in domains)},
        }
    )
    # Notes about the input as a whole, apart from the notes of any one exchange.
    input_notes: list[str] = []
    if held > len(decoded):
        result["inputExchanges"] = held
        result["context"]["label"] = f"{len(decoded)} of {held} {counted}"
        input_notes.append(f"The input holds {held} {counted}; the first {len(decoded)} are decoded here. Send the rest in parts.")
    if unread and number_rows:
        input_notes.append(_unread_rows_note(unread))
    if input_notes:
        result["inputNotes"] = input_notes
    result["notation"] = render_context_notation(result)
    return result


# ----------------------------------------------------------------------
# Text rendering (CLI, MCP)
# ----------------------------------------------------------------------


def _names_aid(value_hex: str, decoded: Any) -> bool:
    try:
        value = bytes.fromhex(value_hex)
    except ValueError:
        return False
    return len(value) > 0 and aid_name(value) == decoded


# Painter: (role, text) -> text. The notation a payload stores is drawn with
# plain_painter, so the JSON, the GUI and the MCP answers never carry escape
# codes; a terminal gets terminal_painter, which colours the same roles.
Painter = Callable[[str, str], str]

# Reading roles -> (colour role of yggdrasim_common.cli_theme, style).
_ROLE_STYLES: dict[str, tuple[str, str]] = {
    "title": ("HEADER", "BOLD"),
    "spec": ("TEXT_DIM", ""),
    "field": ("BLUE", ""),
    "choice": ("PURPLE", ""),
    "index": ("TEXT_DIM", ""),
    "punct": ("TEXT_DIM", ""),
    "string": ("GREEN", ""),
    "number": ("ORANGE", ""),
    "reading": ("YELLOW", ""),
    "inactive": ("TEXT_DIM", "DIM"),
    "tag": ("TEXT_DIM", ""),
    "note": ("YELLOW", ""),
    "ok": ("GREEN", ""),
    "warn": ("YELLOW", ""),
    "fail": ("RED", ""),
}

# Sibling values line up in one column; a longer name than this keeps its own.
_ALIGN_LIMIT = 28


def plain_painter(role: str, text: str) -> str:
    """No escape codes, whatever the role."""
    return text


def terminal_painter() -> Painter:
    """Colours of the active CLI theme (``YGGDRASIM_CLI_THEME``); the mono theme paints nothing."""
    from yggdrasim_common.cli_theme import role_ansi, style_code

    reset = style_code("RESET")
    prefixes: dict[str, str] = {}

    def paint(role: str, text: str) -> str:
        if not text:
            return text
        prefix = prefixes.get(role)
        if prefix is None:
            colour, style = _ROLE_STYLES.get(role, ("", ""))
            prefix = (role_ansi(colour) if colour else "") + (style_code(style) if style else "")
            prefixes[role] = prefix
        return f"{prefix}{text}{reset}" if prefix else text

    return paint


def _render_nodes(nodes: list[dict[str, Any]], indent: int, lines: list[str], paint: Painter = plain_painter) -> None:
    prefix = " " * indent
    for node in nodes:
        tag = str(node.get("tag", ""))
        name = str(node.get("name", ""))
        label = prefix + " ".join(part for part in (paint("tag", tag), paint("field", name)) if part)
        decoded = node.get("decoded")
        value_hex = str(node.get("valueHex") or "")
        if decoded is not None and not isinstance(decoded, (dict, list)):
            if _names_aid(value_hex, decoded):
                # A named AID keeps its value, which a command needs, in the
                # form the plain decoder gives a decoded string.
                label += f" = '{value_hex}'H " + paint("reading", f"({decoded})")
            else:
                label += " = " + paint("reading", str(decoded))
        elif not node.get("children"):
            label += f" = '{node.get('valueHex', '')}'H"
        lines.append(label)
        if node.get("children"):
            _render_nodes(node["children"], indent + 2, lines, paint)


def _ascii_text(value_hex: str) -> str | None:
    try:
        return bytes.fromhex(value_hex).decode("ascii")
    except ValueError:
        return None


def _schema_leaf_text(node: dict[str, Any], paint: Painter = plain_painter) -> str:
    """The value of a schema leaf as ASN.1 value notation, its reading in parentheses."""
    kind = node.get("kind")
    if kind == "octets":
        value_hex = str(node.get("valueHex") or "")
        text = f"'{value_hex}'H"
        decoded = node.get("decoded")
        if decoded is None or decoded == value_hex:
            return text
        if node.get("decodedText") or decoded == _ascii_text(value_hex):
            return f"{text} " + paint("punct", "(") + paint("string", json.dumps(decoded)) + paint("punct", ")")
        return f"{text} " + paint("reading", f"({decoded})")
    if kind == "bits":
        shown = f"'{node.get('bits', '')}'B" if int(node.get("bitLength") or 0) <= _BITS_SHOWN else f"'{node.get('valueHex', '')}'H ({node.get('bitLength')} bits)"
        options = node.get("options") or []
        if options:
            taken = sum(1 for option in options if option.get("set"))
            return f"{shown} " + paint("reading", f"({taken} of {len(options)} set)")
        return shown
    if kind == "integer":
        if "number" in node:
            return paint("number", str(node["number"])) + " " + paint("reading", f"({node.get('decoded')})")
        return paint("number", str(node.get("value", "")))
    if kind == "boolean":
        return paint("number", "TRUE" if node.get("value") else "FALSE")
    if kind == "null":
        return paint("number", "NULL")
    if kind == "string":
        return paint("string", json.dumps(node.get("value")))
    return str(node.get("value", ""))


def _label_text(chain: list[tuple[str, str]], paint: Painter) -> tuple[str, int]:
    """A node's label (a member and the CHOICE alternatives under it), painted, and its width."""
    plain = ": ".join(text for _, text in chain)
    painted = paint("punct", ": ").join(paint(role, text) for role, text in chain)
    return painted, len(plain)


def _name_role(name: str) -> str:
    return "index" if name.startswith("[") else "field"


def _render_certificate(rows: list[dict[str, Any]], indent: int, lines: list[str], paint: Painter) -> None:
    """``label : value`` rows in one column, as format_certificate_rows lays them out."""
    prefix = " " * indent
    labelled = [len("  " * int(row.get("indent") or 0) + str(row.get("name") or "")) for row in rows if row.get("value")]
    width = min(max([12, *labelled]), 28)
    for row in rows:
        label = "  " * int(row.get("indent") or 0) + str(row.get("name") or "")
        value = str(row.get("value") or "")
        if not value:
            lines.append(prefix + paint("field", label))
            continue
        tone = str(row.get("tone") or "")
        painted = paint(tone, value) if tone else value
        if not row.get("name"):
            lines.append(f"{prefix}{' ' * width}  {painted}")
        else:
            lines.append(f"{prefix}{paint('field', label.ljust(width))}{paint('punct', ':')} {painted}")


def _leaf_label_width(node: dict[str, Any]) -> int | None:
    """Width of the label a node prints before ' = ', or None for a heading line."""
    names = [str(node.get("name", ""))]
    while node.get("kind") == "choice" and node.get("children"):
        names.append(str(node.get("choice")))
        node = node["children"][0]
    kind = node.get("kind")
    if kind == "certificate" or (kind in ("sequence", "list") and node.get("children")):
        return None
    return len(": ".join(names))


def _render_children(children: list[dict[str, Any]], indent: int, lines: list[str], paint: Painter) -> None:
    """Sibling nodes, their values in one column."""
    widths = [width for width in map(_leaf_label_width, children) if width is not None and width <= _ALIGN_LIMIT]
    column = max(widths, default=0)
    for child in children:
        _render_schema(child, indent, lines, paint=paint, column=column)


def _render_options(node: dict[str, Any], indent: int, lines: list[str], paint: Painter) -> None:
    """Every value the type names, the ones taken marked: [x] a set bit, (*) the number."""
    bits = node.get("kind") == "bits"
    key, flag = ("bit", "set") if bits else ("number", "active")
    options = node.get("options") or []
    width = max(len(str(option.get(key))) for option in options)
    for option in options:
        taken = bool(option.get(flag))
        mark = ("[x]" if taken else "[ ]") if bits else ("(*)" if taken else "( )")
        text = f"{mark} {str(option.get(key)).rjust(width)}  {option.get('name')}"
        lines.append(" " * indent + paint("reading" if taken else "inactive", text))


def _render_schema(
    node: dict[str, Any],
    indent: int,
    lines: list[str],
    chain: list[tuple[str, str]] | None = None,
    paint: Painter = plain_painter,
    column: int = 0,
) -> None:
    """One schema node as indented lines; a CHOICE prints as ``member: alternative``.

    ``column`` is the label width the siblings share, so their ' = ' line up.
    """
    prefix = " " * indent
    name = str(node.get("name", ""))
    chain = list(chain or [(_name_role(name), name)])
    kind = node.get("kind")
    children = node.get("children") or []
    if kind == "choice":
        chain.append(("choice", str(node.get("choice"))))
        if children:
            _render_schema(children[0], indent, lines, chain, paint, column)
        else:
            lines.append(prefix + _label_text(chain, paint)[0])
        return
    label, label_width = _label_text(chain, paint)
    pad = " " * max(0, column - label_width)
    if kind in ("sequence", "list"):
        if not children:
            lines.append(f"{prefix}{label}{pad} {paint('punct', '= {}')}")
            return
        lines.append(prefix + label)
        _render_children(children, indent + 2, lines, paint)
        return
    if kind == "certificate":
        lines.append(prefix + label + " " + paint("reading", "(X.509 certificate)"))
        _render_certificate(children, indent + 2, lines, paint)
        return
    lines.append(f"{prefix}{label}{pad} {paint('punct', '=')} {_schema_leaf_text(node, paint)}")
    if node.get("options"):
        _render_options(node, indent + max(column, label_width) + 3, lines, paint)
    # The entries of a tag list, one tag per line.
    width = max((len(str(child.get("name", ""))) for child in children), default=0)
    for child in children:
        entry = str(child.get("value", ""))
        role = "note" if entry.startswith(("no ", "tag cut short")) else "field"
        lines.append(f"{prefix}  {paint('tag', str(child.get('name', '')).ljust(width))}  {paint(role, entry)}")


def _render_schema_body(root: dict[str, Any], indent: int, lines: list[str], paint: Painter = plain_painter) -> None:
    """The members of the decoded type under its title line, which already names the type."""
    kind = root.get("kind")
    children = root.get("children") or []
    if kind == "sequence":
        if not children:
            lines.append(" " * indent + paint("note", "(no members present)"))
        _render_children(children, indent, lines, paint)
        return
    if kind == "choice" and children:
        _render_schema(children[0], indent, lines, paint=paint)
        return
    _render_schema(root, indent, lines, paint=paint)


def _render_payload(payload: dict[str, Any], indent: int, lines: list[str], paint: Painter = plain_painter) -> None:
    prefix = " " * indent
    title = str(payload.get("title", ""))
    spec = str(payload.get("spec", ""))
    lines.append(prefix + paint("title", title) + (f"  {paint('spec', f'[{spec}]')}" if spec else ""))
    result = payload.get("result")
    if isinstance(result, dict):
        outcome = "ok" if result.get("ok") else "failed"
        lines.append(f"{prefix}  {paint('field', 'result')}: {outcome}  " + paint("reading", f"-- {result.get('text', '')}"))
    for field_entry in payload.get("fields", []) or []:
        text = f"{prefix}  {paint('field', str(field_entry.get('label')))}: {field_entry.get('value')}"
        if field_entry.get("meaning"):
            text += "  " + paint("reading", f"-- {field_entry['meaning']}")
        lines.append(text)
    if payload.get("schema"):
        _render_schema_body(payload["schema"], indent + 2, lines, paint)
    elif payload.get("nodes"):
        _render_nodes(payload["nodes"], indent + 2, lines, paint)
    for note in payload.get("notes", []) or []:
        lines.append(f"{prefix}  " + paint("note", f"note: {note}"))


def render_rsp_reading(payload: dict[str, Any], paint: Painter = plain_painter) -> str:
    """The text of a ``decode_rsp_object`` payload, painted for a terminal or plain."""
    lines: list[str] = []
    _render_payload(payload, 0, lines, paint)
    return "\n".join(lines)


_GENERIC_LINE = re.compile(r"^(\s*)([A-Za-z][\w-]*)( \[[0-9A-F]+\])?(.*)$")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def paint_generic_notation(text: str, paint: Painter) -> str:
    """Colour the generic BER notation of ``main.render_asn1_notation``: names, tags and text."""
    painted = []
    for line in text.splitlines():
        match = _GENERIC_LINE.match(line)
        if match is None:
            painted.append(_QUOTED.sub(lambda found: paint("string", found.group(0)), line))
            continue
        indent, name, tag, rest = match.groups()
        rest = _QUOTED.sub(lambda found: paint("string", found.group(0)), rest)
        painted.append(indent + paint("field", name) + (paint("tag", tag) if tag else "") + rest)
    return "\n".join(painted)


def render_context_notation(result: dict[str, Any], paint: Painter = plain_painter) -> str:
    lines: list[str] = []
    if result.get("inputKind") == "sw":
        sw = result.get("sw", {})
        lines.append(f"{paint('field', 'SW')} {paint('number', str(sw.get('sw')))}: {sw.get('meaning')}")
        return "\n".join(lines)
    if "exchanges" not in result:
        context = result.get("context", {})
        lines.append(paint("spec", f"{context.get('label', '')}: {context.get('summary', '')}".strip(": ")))
        if result.get("payload"):
            _render_payload(result["payload"], 2, lines, paint)
        if result.get("sw"):
            lines.append(f"  {paint('field', 'SW')} {paint('number', str(result['sw'].get('sw')))}: {result['sw'].get('meaning')}")
        return "\n".join(lines)
    for exchange in result.get("exchanges", []):
        context = exchange.get("context", {})
        command = exchange.get("command") or {}
        head = paint("title", f"#{exchange.get('index')} {command.get('name', '')}".rstrip())
        if command.get("cla"):
            head += " " + paint("tag", f"[{command['cla']} {command['ins']} {command['p1']} {command['p2']}]")
        if context.get("summary"):
            head += " " + paint("reading", f"-- {context['summary']}")
        lines.append(head)
        if context.get("label"):
            lines.append("  " + paint("spec", f"context: {context['label']}" + (f" ({context.get('spec')})" if context.get("spec") else "")))
        for entry in command.get("header", []):
            if entry.get("meaning"):
                lines.append(f"  {paint('field', str(entry['label']))} {entry['value']}: {entry['meaning']}")
        if command.get("payload"):
            _render_payload(command["payload"], 2, lines, paint)
        response = exchange.get("response") or {}
        if response:
            sw = response.get("sw") or {}
            if sw:
                follow = f" -> {sw['followUp']}" if sw.get("followUp") else ""
                lines.append(f"  {paint('field', 'SW')} {paint('number', str(sw.get('sw')))}: {sw.get('meaning')}{follow}")
            if response.get("chained"):
                lines.append("  " + paint("note", f"response continues in GET RESPONSE ({response.get('partialBytes', 0)} byte(s) held)"))
            if response.get("payload"):
                _render_payload(response["payload"], 2, lines, paint)
    for note in result.get("inputNotes") or []:
        lines.append(paint("note", f"note: {note}"))
    return "\n".join(lines)


def decode_context_hex(hex_text: str, *, hint: str = "auto") -> dict[str, Any]:
    """Convenience for callers that already normalised their input to hex."""
    data = normalise_hex(hex_text)
    return decode_context_text(data.hex(), hint=hint)
