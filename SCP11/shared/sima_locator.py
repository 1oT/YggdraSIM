# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""PEStatus offset locator for SAIP profile packages.

An ``EUICCResponse`` names the PE it rejected by the identification in that
PE's header and gives an ``offset`` counted from the first byte of the PE (TCA
eUICC Profile Package V3.4.1 section 8.11). The eUICC Profile Package
Interoperable Format Test Specification V3.4 calls that offset approximate
(RQ8.1.11.29), and its test 8.2.11.3 accepts any value from the first byte of
the failing element to the byte after it. :func:`outline_profile_package`
indexes an unprotected profile package by byte span, keeping no value except
file identifiers, paths and object identifiers, and
:func:`describe_pe_status_location` names the element that ends at an offset
and the element that starts at it or holds it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from SCP11.shared.ber_tlv import decode_object_identifier
from SIMCARD.utils import read_tlv_header

# A SAIP PE nests a handful of levels (GFM: PE, command list, command, FCP,
# field); the cap keeps a hostile package off the interpreter recursion limit.
MAX_OUTLINE_DEPTH = 32

# TS 102 221 v18.4 section 11.1.1.4.3 table 11.5: b6..b1 = 111000 is a DF or
# an ADF, b7 only marks the file shareable.
_DF_DESCRIPTOR_MASK = 0x3F
_DF_DESCRIPTOR_VALUE = 0x38

_HEADER_TAG = b"\xA0"
_PE_HEADER_TAG = b"\xA0"
_PE_IDENTIFICATION_TAG = b"\x81"


@dataclass(frozen=True)
class PeSpan:
    """One TLV inside a PE; ``start`` and ``end`` count from the PE's first byte."""

    start: int
    end: int
    depth: int
    path: str
    note: str


@dataclass(frozen=True)
class PeOutline:
    """The byte layout of one PE of an unprotected profile package."""

    position: int
    identification: int | None
    pe_type: str
    package_start: int
    length: int
    spans: tuple[PeSpan, ...]


@dataclass
class _GfmCursor:
    # SAIP V3.4.1 section 8.3.5: the GFM PE starts in the MF, filePath
    # selects from the MF and a created DF or ADF becomes the current DF.
    current_df: str = ""


def _tlv_at(data: bytes, offset: int, end: int) -> tuple[bytes, int, int] | None:
    try:
        tag, length, _header_length, value_start = read_tlv_header(data, offset)
    except ValueError:
        return None
    value_end = value_start + length
    if value_start > end or value_end > end:
        return None
    return tag, value_start, value_end


def _kind(node: Any) -> str:
    return type(node).__name__ if node is not None else ""


def _members(node: Any) -> list[Any]:
    members = list(getattr(node, "root_members", None) or [])
    for addition in getattr(node, "additions", None) or []:
        if isinstance(addition, (list, tuple)):
            members.extend(addition)
        else:
            members.append(addition)
    return members


def _alternative(node: Any, tag: bytes) -> Any:
    table = getattr(node, "tag_to_member", None)
    if isinstance(table, dict):
        return table.get(tag)
    return None


def _child(node: Any, tag: bytes, index: int) -> tuple[str, Any]:
    """Name and schema node of child ``tag`` (the ``index``-th TLV) of ``node``."""
    kind = _kind(node)
    if kind in ("Sequence", "Set"):
        for member in _members(node):
            if getattr(member, "tag", None) == tag:
                return str(member.name), member
            if _kind(member) == "Choice" and getattr(member, "tag", None) is None:
                alternative = _alternative(member, tag)
                if alternative is not None:
                    return f"{member.name}.{alternative.name}", alternative
        return "", None
    if kind in ("SequenceOf", "SetOf"):
        element = getattr(node, "element_type", None)
        if _kind(element) == "Choice" and getattr(element, "tag", None) is None:
            alternative = _alternative(element, tag)
            if alternative is not None:
                return f"[{index}].{alternative.name}", alternative
            return f"[{index}]", None
        return f"[{index}]", element
    if kind == "ExplicitTag":
        inner = getattr(node, "inner", None)
        if _kind(inner) == "Choice":
            alternative = _alternative(inner, tag)
            if alternative is not None:
                return str(alternative.name), alternative
            return "", None
        return "", inner
    return "", None


def _join(path: str, segment: str) -> str:
    if len(path) == 0 or segment.startswith("["):
        return f"{path}{segment}"
    return f"{path}.{segment}"


def _path_text(raw: bytes) -> str:
    text = raw.hex().upper()
    if len(text) == 0:
        return "MF"
    return "/".join(text[index:index + 4] for index in range(0, len(text), 4))


def _fcp_fields(data: bytes, start: int, end: int, node: Any) -> dict[str, bytes]:
    # asn1tools keeps some member tags as bytearray, which is not hashable.
    names = {
        bytes(member.tag): str(member.name)
        for member in _members(node)
        if getattr(member, "tag", None) is not None
    }
    fields: dict[str, bytes] = {}
    offset = start
    while offset < end:
        tlv = _tlv_at(data, offset, end)
        if tlv is None:
            break
        tag, value_start, value_end = tlv
        name = names.get(tag)
        if name is not None:
            fields[name] = data[value_start:value_end]
        offset = value_end
    return fields


def _fcp_note(fields: dict[str, bytes], cursor: _GfmCursor | None) -> str:
    parts: list[str] = []
    if "fileID" in fields:
        parts.append(f"fileID {fields['fileID'].hex().upper()}")
    if "dfName" in fields:
        parts.append(f"dfName {fields['dfName'].hex().upper()}")
    if "linkPath" in fields:
        link = fields["linkPath"]
        parts.append(f"linkPath {_path_text(link)}" if len(link) > 0 else "linkPath (empty)")
    if cursor is not None:
        parts.append(f"in {_path_text(bytes.fromhex(cursor.current_df))}")
    return ", ".join(parts)


def _advance_gfm_cursor(cursor: _GfmCursor, fields: dict[str, bytes]) -> None:
    file_id = fields.get("fileID", b"")
    descriptor = fields.get("fileDescriptor", b"")
    if len(file_id) == 0:
        return
    if len(fields.get("dfName", b"")) > 0:
        cursor.current_df = file_id.hex().upper()
    elif len(descriptor) > 0 and descriptor[0] & _DF_DESCRIPTOR_MASK == _DF_DESCRIPTOR_VALUE:
        cursor.current_df += file_id.hex().upper()


def _walk(
    data: bytes,
    start: int,
    end: int,
    node: Any,
    depth: int,
    path: str,
    spans: list[PeSpan],
    cursor: _GfmCursor | None,
) -> None:
    index = 0
    offset = start
    while offset < end:
        tlv = _tlv_at(data, offset, end)
        if tlv is None:
            return
        tag, value_start, value_end = tlv
        name, child = _child(node, tag, index)
        child_path = _join(path, name or f"{tag.hex().upper()}[{index}]")
        constructed = tag[0] & 0x20 != 0
        note = ""
        fcp_fields: dict[str, bytes] | None = None
        if getattr(child, "type_name", "") == "Fcp":
            fcp_fields = _fcp_fields(data, value_start, value_end, child)
            note = _fcp_note(fcp_fields, cursor)
        elif cursor is not None and getattr(child, "name", "") == "filePath" and not constructed:
            note = f"select {_path_text(data[value_start:value_end])}"
            cursor.current_df = data[value_start:value_end].hex().upper()
        elif _kind(child) == "ObjectIdentifier" and not constructed:
            try:
                note = decode_object_identifier(data[value_start:value_end])
            except ValueError:
                note = ""
        spans.append(PeSpan(offset, value_end, depth, child_path, note))
        if constructed and depth < MAX_OUTLINE_DEPTH:
            _walk(data, value_start, value_end, child, depth + 1, child_path, spans, cursor)
        if cursor is not None and fcp_fields is not None:
            _advance_gfm_cursor(cursor, fcp_fields)
        index += 1
        offset = value_end


def _identification(pe: bytes, value_start: int) -> int | None:
    first = _tlv_at(pe, value_start, len(pe))
    if first is None or first[0] != _PE_HEADER_TAG:
        return None
    offset, header_end = first[1], first[2]
    while offset < header_end:
        tlv = _tlv_at(pe, offset, header_end)
        if tlv is None:
            return None
        tag, field_start, field_end = tlv
        if tag == _PE_IDENTIFICATION_TAG and field_end > field_start:
            return int.from_bytes(pe[field_start:field_end], "big")
        offset = field_end
    return None


def _profile_element_choice(schema: Any) -> Any:
    types = getattr(schema, "types", None)
    if not isinstance(types, dict):
        return None
    compiled = types.get("ProfileElement")
    if compiled is None:
        return None
    return getattr(compiled, "type", None)


def outline_profile_package(upp: bytes, schema: Any | None = None) -> list[PeOutline]:
    """Index every PE of an unprotected profile package by byte span.

    ``schema`` is pySim's compiled SAIP module (``pySim.esim.saip.asn1``); with
    it the spans carry member names, without it tag paths. Input that is not a
    definite-length TLV sequence opening with the Profile header (a BF36 bound
    package, a truncated or over-claiming TLV) yields an empty list.
    """
    data = bytes(upp or b"")
    top: list[tuple[int, bytes, int, int]] = []
    offset = 0
    while offset < len(data):
        tlv = _tlv_at(data, offset, len(data))
        if tlv is None:
            return []
        tag, value_start, value_end = tlv
        top.append((offset, tag, value_start, value_end))
        offset = value_end
    if len(top) == 0 or top[0][1] != _HEADER_TAG:
        return []
    choice = _profile_element_choice(schema)
    outlines: list[PeOutline] = []
    for position, (start, tag, value_start, value_end) in enumerate(top, 1):
        member = _alternative(choice, tag) if choice is not None else None
        pe_type = str(member.name) if member is not None else f"tag {tag.hex().upper()}"
        pe = data[start:value_end]
        cursor = _GfmCursor() if pe_type == "genericFileManagement" else None
        spans: list[PeSpan] = []
        _walk(pe, value_start - start, len(pe), member, 1, "", spans, cursor)
        identification = None if position == 1 else _identification(pe, value_start - start)
        outlines.append(PeOutline(position, identification, pe_type, start, len(pe), tuple(spans)))
    return outlines


def _note_for(outline: PeOutline, span: PeSpan) -> str:
    if len(span.note) > 0:
        return span.note
    owner: PeSpan | None = None
    for other in outline.spans:
        if other.depth >= span.depth or len(other.note) == 0:
            continue
        if other.start <= span.start and span.end <= other.end:
            if owner is None or other.depth > owner.depth:
                owner = other
    return owner.note if owner is not None else ""


def _describe_span(outline: PeOutline, span: PeSpan) -> str:
    note = _note_for(outline, span)
    text = span.path if note == "" else f"{span.path} ({note})"
    return f"{text} bytes[{span.start}:{span.end}]"


def describe_pe_status_location(
    outlines: Iterable[PeOutline],
    identification: int | None,
    offset: int,
) -> list[str]:
    """Name the elements a PEStatus ``offset`` points at, as summary lines.

    ``identification`` ``None`` selects the Profile header, the one PE without
    a PE header. ``endsAt`` is the innermost element whose last byte precedes
    the offset (its path names every enclosing element), ``startsAt`` or
    ``inside`` the innermost one the offset falls on; a card may report either,
    so both are named.
    """
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return []
    outline = next((item for item in outlines if item.identification == identification), None)
    who = "the Profile header" if identification is None else f"PE identification {identification}"
    if outline is None:
        return [f"simaResponseLocation=no PE in the loaded package matches {who}"]
    end = outline.package_start + outline.length
    lines = [
        f"simaResponseLocation={who} = TLV[{outline.position}] {outline.pe_type} "
        f"plaintext[{outline.package_start}:{end}]",
        f"  offset={offset} of {outline.length}; a card reports the rejected "
        "element's first byte or the byte after it",
    ]
    if offset > outline.length:
        lines.append("  pastEnd=the offset lies beyond the PE")
        return lines
    ending = [span for span in outline.spans if span.end == offset]
    if len(ending) > 0:
        chosen = max(ending, key=lambda span: span.depth)
        lines.append(f"  endsAt={_describe_span(outline, chosen)}")
    holding = [span for span in outline.spans if span.start <= offset < span.end]
    if len(holding) > 0:
        chosen = max(holding, key=lambda span: span.depth)
        label = "startsAt" if chosen.start == offset else "inside"
        lines.append(f"  {label}={_describe_span(outline, chosen)}")
    elif offset < outline.length:
        lines.append(f"  inside=the tag and length of {outline.pe_type}")
    return lines
