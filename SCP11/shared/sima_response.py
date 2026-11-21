# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EUICCResponse (Profile Package Interpreter status) decoder for SCP11 flows.

The ``ppiResponse`` / ``simaResponse`` octets of a ProfileInstallationResult
hold one or more ``EUICCResponse`` values from the TCA eUICC Profile Package
specification V3.4.1 section 8.11: ``EUICCResponse ::= SEQUENCE { peStatus
SEQUENCE OF PEStatus, profileInstallationAborted NULL OPTIONAL, statusMessage
UTF8String OPTIONAL }`` with ``PEStatus ::= SEQUENCE { status INTEGER,
identification UInt15 OPTIONAL, additional-information UInt8 OPTIONAL, offset
UInt31 OPTIONAL }``. The module uses AUTOMATIC TAGS, so ``A0`` is the PEStatus
list, ``81`` the abort flag and ``82`` the message; inside a PEStatus ``80``
is the status, ``81`` the PE identification, ``82`` the additional
information and ``83`` the offset. The nine-octet value ``30 07 A0 05 30 03 80
01 00`` is the all-ok response SGP.32 v1.3 names for CompactSuccessResult.
"""

from __future__ import annotations

from typing import Any

from SIMCARD.utils import read_tlv

# TCA eUICC Profile Package V3.4.1 section 8.11 PEStatus.status named values.
PE_STATUS_NAMES: dict[int, str] = {
    0: "ok",
    1: "pe-not-supported",
    2: "memory-failure",
    3: "bad-values",
    4: "not-enough-memory",
    5: "invalid-request-format",
    6: "invalid-parameter",
    7: "runtime-not-supported",
    8: "lib-not-supported",
    9: "template-not-supported",
    10: "feature-not-supported",
    11: "pin-code-missing",
    31: "unsupported-profile-version",
}

_PE_STATUS_FIELDS: dict[bytes, str] = {
    b"\x80": "status",
    b"\x81": "identification",
    b"\x82": "additional-information",
    b"\x83": "offset",
}


def describe_pe_status(status: int) -> str:
    """Name a PEStatus.status value, including the ISO 7816 and proprietary ranges."""
    name = PE_STATUS_NAMES.get(status)
    if name is not None:
        return name
    if 0x6000 <= status <= 0x6FFF or 0x9000 <= status <= 0x9FFF:
        return f"status-word-{status:04X}"
    if 0xA000 <= status <= 0xFFFF:
        return "proprietary"
    return "unknown"


def describe_pe_status_text(entry: dict[str, Any]) -> str:
    """One PEStatus as a sentence: which PE, what status, where."""
    status = int(entry["status"])
    name = str(entry.get("status_name") or describe_pe_status(status))
    if name.startswith("status-word-"):
        # V3.4.1 section 8.11: [24576...28671] and [36864...40959] report the
        # ISO 7816 status values '6xxx' and '9xxx' the card met.
        what = f"ISO 7816 status word '{status:04X}'"
    elif name == "proprietary":
        what = f"proprietary status {status} ('{status:04X}')"
    elif name == "unknown":
        what = f"status {status} (not a value of V3.4.1 section 8.11)"
    else:
        what = f"{name} ({status})"
    text = what
    if entry.get("identification") is not None:
        text = f"PE with identification {entry['identification']}: {what}"
    if entry.get("additional_information") is not None:
        text += f", additional information {entry['additional_information']}"
    if entry.get("offset") is not None:
        text += f", at offset {entry['offset']} of the PE"
    return text


# SGP.22 v3.1 section 2.5.6 (and the ASN.1 annex, page 439): ProfileInstallationResult
# 'BF37' holds ProfileInstallationResultData 'BF27', whose finalResult [2] is a
# SuccessResult ('A0': aid '4F', ppiResponse '04') or an ErrorResult ('A1':
# bppCommandId '80', errorReason '81', the response '82').
_TAG_PIR = b"\xBF\x37"
_TAG_PIR_DATA = b"\xBF\x27"
_TAG_NOTIFICATION_METADATA = b"\xBF\x2F"
_MAX_SEARCH_DEPTH = 6


def _children(value: bytes) -> list[tuple[bytes, bytes]]:
    items: list[tuple[bytes, bytes]] = []
    position = 0
    while position < len(value):
        try:
            tag, inner, _raw, position = read_tlv(value, position)
        except ValueError:
            return []
        items.append((tag, inner))
    return items


def _find_pir_data(data: bytes, depth: int = 0) -> bytes | None:
    for tag, value in _children(data):
        if tag == _TAG_PIR_DATA:
            return value
        if depth < _MAX_SEARCH_DEPTH and _is_constructed_tag(tag):
            found = _find_pir_data(value, depth + 1)
            if found is not None:
                return found
    return None


def locate_sima_response(data: bytes) -> dict[str, Any] | None:
    """Find the EUICCResponse octets inside a ProfileInstallationResult.

    ``data`` may be the result itself ('BF37'), its data ('BF27') or anything
    that wraps one (a notification list, a LoadBoundProfilePackage answer).
    Returns the octets with what the result says around them, or None when no
    ProfileInstallationResultData is found.
    """
    raw = bytes(data or b"")
    pir_data = _find_pir_data(raw)
    if pir_data is None:
        return None
    found: dict[str, Any] = {
        "source": "ProfileInstallationResult",
        "result": "",
        "sima_response": b"",
        "bpp_command_id": None,
        "error_reason": None,
        "aid_hex": "",
        "transaction_id_hex": "",
        "seq_number": None,
        "notification_address": "",
        "iccid_hex": "",
    }
    for tag, value in _children(pir_data):
        if tag == b"\x80":
            found["transaction_id_hex"] = value.hex().upper()
        elif tag == _TAG_NOTIFICATION_METADATA:
            for inner_tag, inner in _children(value):
                if inner_tag == b"\x80":
                    found["seq_number"] = _decode_unsigned(inner)
                elif inner_tag == b"\x0C":
                    found["notification_address"] = inner.decode("utf-8", errors="replace")
                elif inner_tag == b"\x5A":
                    found["iccid_hex"] = inner.hex().upper()
        elif tag == b"\xA2":
            for choice_tag, choice in _children(value):
                if choice_tag == b"\xA0":
                    found["result"] = "successResult"
                    for inner_tag, inner in _children(choice):
                        if inner_tag == b"\x4F":
                            found["aid_hex"] = inner.hex().upper()
                        elif inner_tag == b"\x04":
                            found["sima_response"] = inner
                elif choice_tag == b"\xA1":
                    found["result"] = "errorResult"
                    for inner_tag, inner in _children(choice):
                        if inner_tag == b"\x80":
                            found["bpp_command_id"] = _decode_unsigned(inner)
                        elif inner_tag == b"\x81":
                            found["error_reason"] = _decode_unsigned(inner)
                        elif inner_tag == b"\x82":
                            found["sima_response"] = inner
    return found


def _is_constructed_tag(tag: bytes) -> bool:
    return len(tag) > 0 and (tag[0] & 0x20) != 0


def _describe_tag(tag_bytes: bytes, path: tuple[bytes, ...]) -> str:
    if len(path) == 0 and tag_bytes == b"\x30":
        return "EUICCResponse"
    if path == (b"\x30",):
        if tag_bytes == b"\xA0":
            return "peStatus"
        if tag_bytes == b"\x81":
            return "profileInstallationAborted"
        if tag_bytes == b"\x82":
            return "statusMessage"
    if path == (b"\x30", b"\xA0") and tag_bytes == b"\x30":
        return "PEStatus"
    if path == (b"\x30", b"\xA0", b"\x30"):
        return _PE_STATUS_FIELDS.get(tag_bytes, "")
    if tag_bytes == b"\x30":
        return "SEQUENCE"
    if len(tag_bytes) == 1 and (tag_bytes[0] & 0xC0) == 0x80:
        return f"ctx[{tag_bytes[0] & 0x1F}]"
    return ""


def _parse_sima_nodes(
    data: bytes,
    *,
    path: tuple[bytes, ...] = (),
) -> tuple[list[dict[str, Any]], int, str]:
    nodes: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data):
        try:
            tag_bytes, value_bytes, raw_tlv, next_offset = read_tlv(data, offset)
        except ValueError as error:
            return nodes, offset, str(error)
        label = _describe_tag(tag_bytes, path)
        node: dict[str, Any] = {
            "offset": offset,
            "tag_hex": tag_bytes.hex().upper(),
            "length": len(value_bytes),
            "raw_hex": raw_tlv.hex().upper(),
            "constructed": _is_constructed_tag(tag_bytes),
        }
        if len(label) > 0:
            node["label"] = label
        if node["constructed"]:
            children, _consumed, error_text = _parse_sima_nodes(
                value_bytes,
                path=path + (tag_bytes,),
            )
            if children:
                node["children"] = children
            if error_text:
                node["parse_error"] = error_text
                node["value_hex"] = value_bytes.hex().upper()
        else:
            node["value_hex"] = value_bytes.hex().upper()
        nodes.append(node)
        offset = next_offset
    return nodes, offset, ""


def _translation_from_nodes(nodes: list[dict[str, Any]]) -> str:
    fragments: list[str] = []
    for node in nodes:
        tag_hex = str(node.get("tag_hex", ""))
        label = str(node.get("label", ""))
        prefix = f"{tag_hex}(len={int(node.get('length', 0))}"
        if len(label) > 0:
            prefix += f", {label}"
        prefix += ")"
        children = node.get("children")
        if isinstance(children, list) and len(children) > 0:
            fragments.append(prefix + "{" + _translation_from_nodes(children) + "}")
        elif bool(node.get("constructed", False)):
            fragments.append(prefix)
        else:
            fragments.append(prefix + "=" + str(node.get("value_hex", "")))
    return " -> ".join(fragments)


def _decode_unsigned(value: bytes) -> int | None:
    if len(value) == 0:
        return None
    return int.from_bytes(value, "big", signed=False)


def _decode_pe_status(value: bytes) -> dict[str, Any] | None:
    entry: dict[str, Any] = {
        "status": None,
        "status_name": "",
        "identification": None,
        "additional_information": None,
        "offset": None,
    }
    position = 0
    while position < len(value):
        try:
            tag_bytes, field_value, _raw_tlv, position = read_tlv(value, position)
        except ValueError:
            break
        if tag_bytes == b"\x80":
            entry["status"] = _decode_unsigned(field_value)
        elif tag_bytes == b"\x81":
            entry["identification"] = _decode_unsigned(field_value)
        elif tag_bytes == b"\x82":
            entry["additional_information"] = _decode_unsigned(field_value)
        elif tag_bytes == b"\x83":
            entry["offset"] = _decode_unsigned(field_value)
    if entry["status"] is None:
        return None
    entry["status_name"] = describe_pe_status(int(entry["status"]))
    return entry


def _format_pe_status(index: int, entry: dict[str, Any]) -> str:
    status = int(entry["status"])
    text = f"peStatus[{index}].status={entry['status_name']}({status})"
    for key, label in (
        ("identification", "identification"),
        ("additional_information", "additional-information"),
        ("offset", "offset"),
    ):
        if entry.get(key) is not None:
            text += f" {label}={entry[key]}"
    return text


def _decode_sima_semantics(sima_response: bytes) -> dict[str, Any]:
    """Read one EUICCResponse; an empty dict means the octets are not one."""
    try:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(sima_response, 0)
    except ValueError:
        return {}
    if root_tag != b"\x30":
        return {}
    pe_status: list[dict[str, Any]] = []
    aborted = False
    status_message = ""
    seen_pe_status_list = False
    position = 0
    while position < len(root_value):
        try:
            tag_bytes, field_value, _raw_tlv, position = read_tlv(root_value, position)
        except ValueError:
            break
        if tag_bytes == b"\xA0":
            seen_pe_status_list = True
            inner = 0
            while inner < len(field_value):
                try:
                    item_tag, item_value, _item_raw, inner = read_tlv(field_value, inner)
                except ValueError:
                    break
                if item_tag != b"\x30":
                    continue
                entry = _decode_pe_status(item_value)
                if entry is not None:
                    pe_status.append(entry)
        elif tag_bytes == b"\x81":
            aborted = True
        elif tag_bytes == b"\x82":
            status_message = field_value.decode("utf-8", errors="replace")
    if seen_pe_status_list is False:
        return {}
    fragments = [_format_pe_status(index, entry) for index, entry in enumerate(pe_status)]
    failing = [describe_pe_status_text(entry) for entry in pe_status if int(entry["status"]) != 0]
    failure_cause = "; ".join(failing)
    if aborted:
        fragments.append("profileInstallationAborted")
        failure_cause += ("; " if failure_cause else "") + "the profile installation was aborted"
    if len(status_message) > 0:
        fragments.append(f"statusMessage={status_message!r}")
    ok = aborted is False and len(pe_status) > 0 and all(int(entry["status"]) == 0 for entry in pe_status)
    return {
        "pe_status": pe_status,
        "profile_installation_aborted": aborted,
        "status_message": status_message,
        "ok": ok,
        "failure_cause": "" if ok else failure_cause,
        "summary": ", ".join(fragments),
    }


def is_euicc_response(data: bytes) -> bool:
    """True when ``data`` is one EUICCResponse and every octet of it fits the type.

    ``decode_sima_response`` reads what it can of a damaged response. A reader
    that has only a bare SEQUENCE to go by needs the strict form: one '30' over
    the whole input, a peStatus list of PEStatus entries that each open with a
    status, then at most the abort flag and the status message.
    """
    root = _children(bytes(data or b""))
    if len(root) != 1 or root[0][0] != b"\x30":
        return False
    members = _children(root[0][1])
    if len(members) == 0 or members[0][0] != b"\xA0":
        return False
    if [tag for tag, _value in members[1:]] not in ([], [b"\x81"], [b"\x82"], [b"\x81", b"\x82"]):
        return False
    if any(tag == b"\x81" and len(value) != 0 for tag, value in members[1:]):
        return False
    entries = _children(members[0][1])
    if len(entries) == 0:
        return False
    for tag, value in entries:
        fields = _children(value)
        tags = [field_tag for field_tag, _field_value in fields]
        if tag != b"\x30" or tags[:1] != [b"\x80"] or len(fields[0][1]) == 0:
            return False
        if tags != sorted(set(tags)) or not set(tags) <= set(_PE_STATUS_FIELDS):
            return False
    return True


def decode_sima_response(sima_response: bytes) -> dict[str, Any]:
    """Decode an ``EUICCResponse`` TLV into GUI-friendly fields.

    A ProfileInstallationResult (or anything wrapping one) is accepted too:
    the response inside it is the one decoded, and ``container`` says where
    it was found and what the result reports beside it.
    """
    given = bytes(sima_response or b"")
    container: dict[str, Any] | None = None
    raw = given
    if len(given) > 0 and given[:1] != b"\x30":
        located = locate_sima_response(given)
        if located is not None:
            raw = bytes(located.pop("sima_response"))
            container = located
            container["given_hex"] = given.hex().upper()
            container["given_length"] = len(given)
    decoded = _decode_euicc_response(raw)
    if container is not None:
        decoded["container"] = container
        if len(raw) == 0:
            decoded["error"] = f"the {container['result'] or 'result'} carries no EUICCResponse"
    return decoded


def _decode_euicc_response(raw: bytes) -> dict[str, Any]:
    nodes, consumed, error_text = _parse_sima_nodes(raw)
    translation = _translation_from_nodes(nodes)
    semantic = _decode_sima_semantics(raw)
    parts: list[str] = []
    if len(translation) > 0:
        parts.append(translation)
    summary = str(semantic.get("summary", "") if semantic else "")
    if len(summary) > 0:
        parts.append(summary)
    formatted = raw.hex().upper()
    if parts:
        formatted += " [" + "; ".join(parts) + "]"
    return {
        "format": "EUICCResponse",
        "input_hex": raw.hex().upper(),
        "input_length": len(raw),
        "complete": error_text == "" and consumed == len(raw),
        "consumed": consumed,
        "error": error_text,
        "nodes": nodes,
        "translation": translation,
        "semantic": semantic,
        "summary": summary,
        "formatted": formatted,
    }


def format_sima_response(sima_response: bytes) -> str:
    """Return the compact one-line EUICCResponse format used in flow logs."""
    return str(decode_sima_response(sima_response).get("formatted", ""))
