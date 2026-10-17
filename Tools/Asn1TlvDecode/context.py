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

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import gsma_schema
from .main import (
    DecodeError,
    TagRegistry,
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
}


def _gp_cla(cla: int) -> bool:
    # GPC v2.3.1 command tables: CLA '80'-'8F', 'C0'-'CF' or 'E0'-'EF'.
    return (cla & 0xF0) in (0x80, 0xC0, 0xE0)


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
        elif ins == 0x82:
            ctx.summary = "host cryptogram and C-MAC prove the session keys"
            ctx.payload_kind = "opaque"
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
    else:
        nodes = [_node(tag_hex, _gp_get_data_tag_name(tag_hex), data)]
    return _payload("gp_get_data", f"GET DATA '{tag_hex}' response", "GPC v2.3.1 section 11.3.3", nodes=nodes)


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
        node["comprehensionRequired"] = cr
        nodes.append(node)
    return nodes, complete


def decode_cat(data: bytes, *, expect: str) -> dict[str, Any]:
    """Decode CAT traffic: a proactive command, an envelope or a terminal response."""
    if expect == "cat_terminal_response":
        nodes, complete = _decode_comprehension_tlvs(data)
        payload = _payload("cat", "TERMINAL RESPONSE", "TS 102 223 v18.3 section 6.8", nodes=nodes)
        if not complete:
            payload["notes"] = ["The COMPREHENSION-TLV sequence does not cover the whole data field."]
        return payload
    if expect == "terminal_profile":
        return _payload("terminal_profile", "TERMINAL PROFILE", "TS 102 223 v18.3 section 5.2", fields=[_field("Profile bytes", _hex(data), f"{len(data)} byte(s)")])
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
        if type_name.endswith(("Request", "RequestEsipa")):
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


def _schema_value_nodes(value: Any, name: str) -> dict[str, Any]:
    """Turn an asn1tools value into display nodes: dicts nest, bytes show hex."""
    if isinstance(value, dict):
        children = [_schema_value_nodes(item, str(key)) for key, item in value.items()]
        return {"name": name, "kind": "sequence", "children": children}
    if isinstance(value, (list, tuple)) and not (len(value) == 2 and isinstance(value[0], str) and not isinstance(value[1], str) and isinstance(value, tuple)):
        children = [_schema_value_nodes(item, f"{name}[{index}]") for index, item in enumerate(value)]
        return {"name": name, "kind": "list", "children": children}
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        inner = _schema_value_nodes(value[1], value[0])
        return {"name": name, "kind": "choice", "choice": value[0], "children": [inner]}
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        node: dict[str, Any] = {"name": name, "kind": "octets", "valueHex": _hex(data), "length": len(data)}
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
        return {"name": name, "kind": "integer", "value": value}
    if isinstance(value, str):
        return {"name": name, "kind": "string", "value": value}
    if value is None:
        return {"name": name, "kind": "null"}
    return {"name": name, "kind": "value", "value": _json_safe(value)}


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
            decoded = gsma_schema.decode_type(type_name, data)
        except Exception as error:  # noqa: BLE001 - asn1tools decode errors are library-specific
            schema_error = f"{type_name}: {error}"
            continue
        payload["schemaType"] = type_name
        payload["schema"] = _schema_value_nodes(decoded, type_name)
        payload["schemaJson"] = _json_safe(decoded)
        break
    status = gsma_schema.rsp_specification_status()
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
    tree = _generic_tree(data, registry)
    payload["nodes"] = _tree_to_nodes(tree) if tree else []
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

_HEX_RUN = re.compile(r"(?:0x)?[0-9A-Fa-f]{2}(?:[\s:,-]*(?:0x)?[0-9A-Fa-f]{2})*")
_COMMAND_MARKERS = ("c-apdu", "capdu", "cmd", "command", "tx", ">>", "->", "→", ">", "c:")
_RESPONSE_MARKERS = ("r-apdu", "rapdu", "rsp", "response", "rx", "<<", "<-", "←", "<", "r:")


@dataclass
class RawExchange:
    command: bytes | None = None
    response: bytes | None = None
    sw: bytes | None = None
    source: str = ""


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


def parse_exchanges(text: str) -> list[RawExchange]:
    """Split pasted text into command/response exchanges."""
    exchanges: list[RawExchange] = []
    pending: RawExchange | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for segment in _split_line_segments(line):
            kind, body = _strip_marker(segment)
            sw_match = re.search(r"(?i)\bsw\s*[=:]\s*([0-9A-F]{4})\b", body)
            if sw_match and not kind:
                if pending is None:
                    pending = RawExchange(source=line)
                pending.sw = bytes.fromhex(sw_match.group(1))
                exchanges.append(pending)
                pending = None
                continue
            body = re.sub(r"(?i)\bsw\s*[=:]\s*[0-9A-F]{4}\b", "", body).strip()
            body = re.sub(r"(?i)\b\d+(?:\.\d+)?\s*ms\b", "", body).strip()
            data = _hex_bytes(body)
            if data is None:
                continue
            if kind == "command" or (kind == "" and pending is None and not _looks_like_response(data)):
                if pending is not None:
                    exchanges.append(pending)
                pending = RawExchange(command=data, source=line)
                continue
            if pending is None:
                pending = RawExchange(source=line)
            if len(data) == 2 and pending.response is None and kind != "response":
                pending.sw = data
            else:
                pending.response = data
            exchanges.append(pending)
            pending = None
    if pending is not None:
        exchanges.append(pending)
    return exchanges


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
    selected_aid: bytes = b""
    pending_command: dict[str, Any] | None = None
    pending_context: CommandContext | None = None
    chained_data: bytes = b""
    es10_blocks: bytes = b""
    es10_context: CommandContext | None = None
    last_get_status_p1: int | None = None


_REGISTRY: TagRegistry | None = None


def _registry() -> TagRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = TagRegistry.load()
    return _REGISTRY


def _decode_command_payload(ctx: CommandContext, apdu: dict[str, Any], data: bytes, state: TraceState) -> dict[str, Any] | None:
    kind = ctx.payload_kind
    registry = _registry()
    if not data:
        return None
    if kind == "es10_request":
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
        return _payload("gp_put_key", "PUT KEY data field", "GPC v2.3.1 tables 11-68 / 11-69", fields=[_field("Key version number", f"{data[0]:02X}"), _field("Key data", _hex(data[1:]), "key components are encrypted; not decoded")])
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
        return decode_cat(data, expect="cat_terminal_response")
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
    fields = [_field("File", fid + (f" under {state.selected_adf}" if state.selected_adf else ""), "from the last SELECT in the trace")]
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
        return decode_cat(data, expect="cat_proactive")
    if kind == "cat_envelope_response":
        tree = _generic_tree(data, registry)
        return _payload("cat", "ENVELOPE response data", "TS 102 223 v18.3 section 7", nodes=_tree_to_nodes(tree) if tree else [_node("", "response data", data)])
    if kind == "auth_response":
        return decode_auth_response(int(command["ins"], 16), int(command["p2"], 16), data) if command else None
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

_HINTS = ("auto", "apdu", "response", "tlv", "es10", "gp", "uicc", "cat", "sw")


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
    if hint == "es10" or (hint in ("auto", "response") and first == 0xBF):
        domain = "es10"
        payload = decode_es10(body, direction="response", registry=registry)
        if payload.get("schemaType") is None and payload.get("typeCandidates"):
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
    result: dict[str, Any] = {
        "inputKind": "response" if sw is not None else "tlv",
        "context": {"domain": domain, "label": _DOMAIN_LABELS.get(domain, domain), "spec": payload.get("spec", ""), "summary": payload.get("title", "")},
        "payload": payload,
    }
    if sw is not None:
        result["sw"] = describe_sw(sw[0], sw[1])
    return result


def decode_context_text(text: str, *, hint: str = "auto") -> dict[str, Any]:
    """Decode pasted hex, one APDU or a whole exchange trace with context."""
    hint = (hint or "auto").strip().lower()
    if hint not in _HINTS:
        hint = "auto"
    normalized = str(text or "").strip()
    if not normalized:
        raise DecodeError("input is empty")
    exchanges = parse_exchanges(normalized)
    lines = [line for line in normalized.splitlines() if line.strip() and not line.strip().startswith("#")]
    single_hex = len(lines) == 1 and _hex_bytes(_strip_marker(lines[0])[1]) is not None and _strip_marker(lines[0])[0] == ""
    result: dict[str, Any] = {
        "format": "context",
        "hint": hint,
        "schema": gsma_schema.rsp_specification_status(),
    }
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
    domains = sorted({item.get("context", {}).get("domain", "unknown") for item in decoded})
    result.update(
        {
            "inputKind": "trace" if len(decoded) > 1 else "apdu",
            "exchanges": decoded,
            "exchangeCount": len(decoded),
            "domains": domains,
            "context": decoded[0].get("context", {}) if len(decoded) == 1 else {"domain": "trace", "label": f"{len(decoded)} exchanges", "summary": ", ".join(_DOMAIN_LABELS.get(domain, domain) for domain in domains)},
        }
    )
    result["notation"] = render_context_notation(result)
    return result


# ----------------------------------------------------------------------
# Text rendering (CLI, MCP)
# ----------------------------------------------------------------------


def _render_nodes(nodes: list[dict[str, Any]], indent: int, lines: list[str]) -> None:
    prefix = " " * indent
    for node in nodes:
        label = f"{prefix}{node.get('tag', '')} {node.get('name', '')}".rstrip()
        decoded = node.get("decoded")
        if decoded is not None and not isinstance(decoded, (dict, list)):
            label += f" = {decoded}"
        elif not node.get("children"):
            label += f" = '{node.get('valueHex', '')}'H"
        lines.append(label)
        if node.get("children"):
            _render_nodes(node["children"], indent + 2, lines)


def _render_schema(node: dict[str, Any], indent: int, lines: list[str]) -> None:
    prefix = " " * indent
    kind = node.get("kind")
    if kind in ("sequence", "list", "choice"):
        head = f"{prefix}{node.get('name')}"
        if kind == "choice":
            head += f" (choice {node.get('choice')})"
        lines.append(head)
        for child in node.get("children", []):
            _render_schema(child, indent + 2, lines)
        return
    value = node.get("decoded", node.get("value", node.get("valueHex")))
    lines.append(f"{prefix}{node.get('name')} = {value}")


def _render_payload(payload: dict[str, Any], indent: int, lines: list[str]) -> None:
    prefix = " " * indent
    title = payload.get("title", "")
    spec = payload.get("spec", "")
    lines.append(f"{prefix}{title}" + (f"  [{spec}]" if spec else ""))
    for field_entry in payload.get("fields", []) or []:
        text = f"{prefix}  {field_entry.get('label')}: {field_entry.get('value')}"
        if field_entry.get("meaning"):
            text += f"  -- {field_entry['meaning']}"
        lines.append(text)
    if payload.get("schema"):
        lines.append(f"{prefix}  schema {payload.get('schemaType')}:")
        _render_schema(payload["schema"], indent + 4, lines)
    elif payload.get("nodes"):
        _render_nodes(payload["nodes"], indent + 2, lines)
    for note in payload.get("notes", []) or []:
        lines.append(f"{prefix}  note: {note}")


def render_context_notation(result: dict[str, Any]) -> str:
    lines: list[str] = []
    if result.get("inputKind") == "sw":
        sw = result.get("sw", {})
        lines.append(f"SW {sw.get('sw')}: {sw.get('meaning')}")
        return "\n".join(lines)
    if "exchanges" not in result:
        context = result.get("context", {})
        lines.append(f"{context.get('label', '')}: {context.get('summary', '')}".strip(": "))
        if result.get("payload"):
            _render_payload(result["payload"], 2, lines)
        if result.get("sw"):
            lines.append(f"  SW {result['sw'].get('sw')}: {result['sw'].get('meaning')}")
        return "\n".join(lines)
    for exchange in result.get("exchanges", []):
        context = exchange.get("context", {})
        command = exchange.get("command") or {}
        head = f"#{exchange.get('index')} {command.get('name', '')}".rstrip()
        if command.get("cla"):
            head += f" [{command['cla']} {command['ins']} {command['p1']} {command['p2']}]"
        if context.get("summary"):
            head += f" -- {context['summary']}"
        lines.append(head)
        if context.get("label"):
            lines.append(f"  context: {context['label']}" + (f" ({context.get('spec')})" if context.get("spec") else ""))
        for entry in command.get("header", []):
            if entry.get("meaning"):
                lines.append(f"  {entry['label']} {entry['value']}: {entry['meaning']}")
        if command.get("payload"):
            _render_payload(command["payload"], 2, lines)
        response = exchange.get("response") or {}
        if response:
            sw = response.get("sw") or {}
            if sw:
                lines.append(f"  SW {sw.get('sw')}: {sw.get('meaning')}" + (f" -> {sw['followUp']}" if sw.get("followUp") else ""))
            if response.get("chained"):
                lines.append(f"  response continues in GET RESPONSE ({response.get('partialBytes', 0)} byte(s) held)")
            if response.get("payload"):
                _render_payload(response["payload"], 2, lines)
    return "\n".join(lines)


def decode_context_hex(hex_text: str, *, hint: str = "auto") -> dict[str, Any]:
    """Convenience for callers that already normalised their input to hex."""
    data = normalise_hex(hex_text)
    return decode_context_text(data.hex(), hint=hint)
