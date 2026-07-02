# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SIMa response TLV decoder used by SCP11 flows and offline tools."""

from __future__ import annotations

from typing import Any

from SIMCARD.utils import read_tlv


def _is_constructed_tag(tag: bytes) -> bool:
    return len(tag) > 0 and (tag[0] & 0x20) != 0


def _describe_sima_response_tag(
    tag_bytes: bytes,
    path: tuple[bytes, ...],
    child_index: int,
) -> str:
    if len(path) == 0 and tag_bytes == b"\x30":
        return "simaResponse"
    if path == (b"\x30",) and tag_bytes == b"\xA0":
        return "finalResult.successResult"
    if path == (b"\x30",) and tag_bytes == b"\xA1":
        return "finalResult.failureResult"
    if path in ((b"\x30", b"\xA0"), (b"\x30", b"\xA1")) and tag_bytes == b"\x30":
        return "resultData"
    if path in ((b"\x30", b"\xA0"), (b"\x30", b"\xA1")) and tag_bytes == b"\x80":
        return "resultCode"
    if path in ((b"\x30", b"\xA0"), (b"\x30", b"\xA1")) and tag_bytes == b"\x81":
        return "resultDetail"
    if path in (
        (b"\x30", b"\xA0", b"\x30"),
        (b"\x30", b"\xA1", b"\x30"),
    ) and tag_bytes == b"\x80":
        return "resultCode"
    if path in (
        (b"\x30", b"\xA0", b"\x30"),
        (b"\x30", b"\xA1", b"\x30"),
    ) and tag_bytes == b"\x81":
        return "resultDetail"
    if tag_bytes == b"\x30":
        return "SEQUENCE"
    if tag_bytes == b"\xA0":
        return "ctx[0]"
    if tag_bytes == b"\xA1":
        return "ctx[1]"
    if tag_bytes == b"\x80":
        return "ctx[0]"
    if tag_bytes == b"\x81":
        return "ctx[1]"
    return ""


def _parse_sima_nodes(
    data: bytes,
    *,
    path: tuple[bytes, ...] = (),
) -> tuple[list[dict[str, Any]], int, str]:
    nodes: list[dict[str, Any]] = []
    offset = 0
    child_index = 0
    while offset < len(data):
        try:
            tag_bytes, value_bytes, raw_tlv, next_offset = read_tlv(data, offset)
        except ValueError as error:
            return nodes, offset, str(error)
        label = _describe_sima_response_tag(tag_bytes, path, child_index)
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
        child_index += 1
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


def _decode_sima_semantics(sima_response: bytes) -> dict[str, Any]:
    try:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(sima_response, 0)
    except ValueError:
        return {}
    if root_tag != b"\x30":
        return {}
    try:
        result_choice_tag, result_choice_value, _raw_tlv, _next_offset = read_tlv(root_value, 0)
    except ValueError:
        return {}
    if result_choice_tag not in (b"\xA0", b"\xA1"):
        return {}

    sequence_value = result_choice_value
    try:
        sequence_tag, nested_sequence_value, _raw_tlv, sequence_end = read_tlv(
            result_choice_value,
            0,
        )
    except ValueError:
        sequence_tag = b""
        nested_sequence_value = b""
        sequence_end = 0
    if sequence_tag == b"\x30" and sequence_end == len(result_choice_value):
        sequence_value = nested_sequence_value

    try:
        field_tag, field_value, _raw_tlv, next_offset = read_tlv(sequence_value, 0)
    except ValueError:
        return {}
    if field_tag != b"\x80" or len(field_value) == 0:
        return {}

    result_code = int.from_bytes(field_value, "big", signed=False)
    choice_name = "successResult" if result_choice_tag == b"\xA0" else "failureResult"
    result: dict[str, Any] = {
        "choice": choice_name,
        "choice_tag": result_choice_tag.hex().upper(),
        "result_code": result_code,
        "result_code_hex": field_value.hex().upper(),
    }
    fragments = [f"{choice_name}.resultCode={result_code}"]
    if next_offset < len(sequence_value):
        try:
            detail_tag, detail_value, _raw_tlv, _next_detail = read_tlv(
                sequence_value,
                next_offset,
            )
        except ValueError:
            detail_tag = b""
            detail_value = b""
        if detail_tag == b"\x81" and len(detail_value) > 0:
            detail_code = int.from_bytes(detail_value, "big", signed=False)
            result["result_detail"] = detail_code
            result["result_detail_hex"] = detail_value.hex().upper()
            fragments.append(f"{choice_name}.resultDetail={detail_code}")
    result["summary"] = ", ".join(fragments)
    return result


def decode_sima_response(sima_response: bytes) -> dict[str, Any]:
    """Decode a SIMa ``simaResponse`` TLV into GUI-friendly fields."""
    raw = bytes(sima_response or b"")
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
        "format": "SIMa response",
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
    """Return the compact one-line SIMa response format used in flow logs."""
    return str(decode_sima_response(sima_response).get("formatted", ""))
