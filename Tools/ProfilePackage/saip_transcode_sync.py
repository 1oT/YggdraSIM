"""
Map Profile Element boundaries between decoded JSON and concatenated DER hex.

JSON uses pySim ProfileElement.decoded keys (asn1tools shapes) under sections.<peKey>.
DER is successive pe.to_der() bytes in PE order.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any, Optional

from textual.document._document import Location, Selection


def ordered_section_keys_from_pes(pes: Any) -> list[str]:
    """Same PE keys as build_decoded_document_from_sequence (all_pe order)."""
    counts: dict[str, int] = {}

    def unique_key(base_key: str) -> str:
        key_text = str(base_key or "section").strip() or "section"
        current_count = counts.get(key_text, 0) + 1
        counts[key_text] = current_count
        if current_count == 1:
            return key_text
        return f"{key_text}_{current_count}"

    return [unique_key(pe.type) for pe in pes.pe_list]


def pe_byte_ranges(pes: Any) -> list[tuple[str, int, int]]:
    """Byte ranges from re-encoded PEs (may differ from on-wire file length). Prefer raw_der variant."""
    keys = ordered_section_keys_from_pes(pes)
    out: list[tuple[str, int, int]] = []
    offset = 0
    for idx, pe in enumerate(pes.pe_list):
        chunk = pe.to_der()
        nxt = offset + len(chunk)
        out.append((keys[idx], offset, nxt))
        offset = nxt
    return out


def pe_byte_ranges_from_raw_der(raw_der: bytes, pes: Any) -> list[tuple[str, int, int]]:
    """
    (section_key, start inclusive, end exclusive) aligned to the displayed DER bytes.

    Splits ``raw_der`` with the same BER-TLV segmentation as ProfileElementSequence.parse_der,
    so hex pane offsets match the file even when pe.to_der() normalizes encoding.
    """
    from pySim.esim.saip import bertlv_first_segment

    keys = ordered_section_keys_from_pes(pes)
    chunks: list[bytes] = []
    remainder = raw_der
    while len(remainder) > 0:
        first, remainder = bertlv_first_segment(remainder)
        chunks.append(first)
    if len(chunks) != len(keys):
        raise ValueError(
            f"TLV segment count {len(chunks)} does not match profile element count {len(keys)}."
        )
    out: list[tuple[str, int, int]] = []
    offset = 0
    for idx, key in enumerate(keys):
        length = len(chunks[idx])
        end = offset + length
        out.append((key, offset, end))
        offset = end
    return out


def _scan_json_value_end(text: str, start: int) -> int:
    """First index after JSON value starting at start (after opening brace/bracket/quote if any)."""
    i = start
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n:
        return n
    ch = text[i]
    if ch in "{[":
        pairs = {"{": "}", "[": "]"}
        op = ch
        cl = pairs[ch]
        depth = 0
        in_str = False
        esc = False
        j = i
        while j < n:
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                j += 1
                continue
            if c == '"':
                in_str = True
                j += 1
                continue
            if c == op:
                depth += 1
            elif c == cl:
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n
    if ch == '"':
        j = i + 1
        esc = False
        while j < n:
            c = text[j]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                return j + 1
            j += 1
        return n
    j = i
    while j < n and text[j] not in ",}\n]":
        j += 1
    return j


def _skip_json_ws(text: str, pos: int, end: int) -> int:
    while pos < end and text[pos] in " \t\r\n":
        pos += 1
    return pos


def scan_json_object_member_entries(
    text: str,
    start: int,
    end: int,
) -> list[tuple[str, int, int, int, int]]:
    """
    Best-effort object member scan returning both key and value spans.

    Each tuple is ``(key_text, key_start, key_end, value_start, value_end)``.
    """
    out: list[tuple[str, int, int, int, int]] = []
    pos = start + 1
    while pos < end:
        pos = _skip_json_ws(text, pos, end)
        if pos >= end or text[pos] == "}":
            break
        key_start = pos
        try:
            key_end = _scan_json_value_end(text, key_start)
        except (IndexError, ValueError):
            break
        if key_end <= key_start:
            break
        try:
            key_text = json.loads(text[key_start:key_end])
        except (TypeError, ValueError, json.JSONDecodeError):
            break
        if isinstance(key_text, str) is False:
            break
        pos = _skip_json_ws(text, key_end, end)
        if pos >= end or text[pos] != ":":
            break
        pos += 1
        pos = _skip_json_ws(text, pos, end)
        value_start = pos
        try:
            value_end = _scan_json_value_end(text, value_start)
        except (IndexError, ValueError):
            break
        if value_end <= value_start:
            break
        out.append((str(key_text), key_start, key_end, value_start, value_end))
        pos = _skip_json_ws(text, value_end, end)
        if pos < end and text[pos] == ",":
            pos += 1
    return out


def scan_json_object_members(text: str, start: int, end: int) -> list[tuple[str, int, int]]:
    """
    Best-effort object member scan for partially edited JSON.

    Returns only the members that can be parsed safely from the current buffer and
    stops quietly once an incomplete key/value fragment is encountered.
    """
    return [
        (key_text, value_start, value_end)
        for key_text, _key_start, _key_end, value_start, value_end in scan_json_object_member_entries(
            text,
            start,
            end,
        )
    ]


def scan_json_list_items(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Best-effort list item scan for partially edited JSON."""
    out: list[tuple[int, int]] = []
    pos = start + 1
    while pos < end:
        pos = _skip_json_ws(text, pos, end)
        if pos >= end or text[pos] == "]":
            break
        value_start = pos
        try:
            value_end = _scan_json_value_end(text, value_start)
        except (IndexError, ValueError):
            break
        if value_end <= value_start:
            break
        out.append((value_start, value_end))
        pos = _skip_json_ws(text, value_end, end)
        if pos < end and text[pos] == ",":
            pos += 1
    return out


def _looks_like_json_value_start(text: str, s: int) -> bool:
    """True if ``s`` is plausibly the first character of a JSON value."""
    n = len(text)
    if s < 0 or s >= n:
        return False
    ch = text[s]
    if ch in "{[\"":
        return True
    if ch in "-0123456789":
        return True
    if ch == "t" and text.startswith("true", s):
        return True
    if ch == "f" and text.startswith("false", s):
        return True
    if ch == "n" and text.startswith("null", s):
        return True
    return False


def enclosing_json_value_span(text: str, lo: int, hi: int) -> tuple[int, int]:
    """
    Smallest substring ``text[s:e]`` that is one JSON value and covers the selection.

    Keeps JSON↔DER sync scoped to the nearest object/array/string (or primitive) instead
    of an entire profile element when the caret sits inside nested structure.
    """
    if hi < lo:
        lo, hi = hi, lo
    n = len(text)
    if n == 0:
        return (0, 0)
    lo = max(0, min(lo, n))
    hi = max(lo, min(hi, n))

    s_floor = max(0, lo - 500_000)
    candidates: list[tuple[int, int, int, int]] = []
    # (t, e, span_len, kind_rank) — kind_rank 0 = object/array (prefer), 1 = primitive

    s = lo
    while s >= s_floor:
        t = s
        while t < n and text[t] in " \t\r\n":
            t += 1
        if t >= n:
            s -= 1
            continue
        if _looks_like_json_value_start(text, t) is False:
            s -= 1
            continue
        try:
            e = _scan_json_value_end(text, t)
        except (IndexError, ValueError):
            s -= 1
            continue
        if lo == hi:
            covers = t <= lo < e
        else:
            covers = t <= lo and e >= hi
        if covers:
            span_len = e - t
            ch0 = text[t] if t < n else ""
            kind_rank = 0 if ch0 in "{[" else 1
            candidates.append((t, e, span_len, kind_rank))
        s -= 1

    if len(candidates) == 0:
        return (lo, hi)

    struct_cands = [c for c in candidates if c[3] == 0]
    pool = struct_cands if len(struct_cands) > 0 else candidates
    best = min(pool, key=lambda row: row[2])
    return (best[0], best[1])


def build_json_entry_spans(full_text: str, keys_in_order: list[str]) -> dict[str, tuple[int, int, int]]:
    """
    Per profile-element span in pretty-printed JSON (indent=2).

    Returns ``(entry_begin, value_start, value_end)`` character offsets
    ``[entry_begin, value_end)`` covers the full section entry; ``[value_start, value_end)``
    is the JSON value only (used for proportional map to DER bytes within the PE).
    """
    spans: dict[str, tuple[int, int, int]] = {}
    sec = full_text.find('"sections"')
    if sec < 0:
        return spans
    colon = full_text.find(":", sec)
    if colon < 0:
        return spans
    open_brace = full_text.find("{", colon)
    if open_brace < 0:
        return spans
    pos = open_brace + 1
    for key in keys_in_order:
        needle = f'    "{key}":'
        j = full_text.find(needle, pos)
        if j < 0:
            continue
        line_start = full_text.rfind("\n", 0, j)
        if line_start < 0:
            entry_begin = j
        else:
            entry_begin = line_start + 1
        colon_k = full_text.find(":", j)
        if colon_k < 0:
            continue
        value_start = colon_k + 1
        while value_start < len(full_text) and full_text[value_start] in " \t\n":
            value_start += 1
        value_end = _scan_json_value_end(full_text, value_start)
        spans[key] = (entry_begin, value_start, value_end)
        pos = value_end
    return spans


def infer_section_key_from_json_cursor(text: str, cursor_line: int) -> Optional[str]:
    """Last PE key line (4-space indent) at or above cursor_line."""
    lines = text.split("\n")
    if cursor_line < 0 or cursor_line >= len(lines):
        return None
    key_pat = re.compile(r'^ {4}"([^"]+)"\s*:')
    last_key: Optional[str] = None
    for idx in range(0, cursor_line + 1):
        m = key_pat.match(lines[idx])
        if m:
            candidate = m.group(1)
            if candidate == "sections":
                last_key = None
                continue
            last_key = candidate
    return last_key


def location_to_offset(text: str, location: Location) -> int:
    line_index, col = location
    offset = 0
    current_line = 0
    for chunk in text.split("\n"):
        if current_line == line_index:
            return offset + min(col, len(chunk))
        offset += len(chunk) + 1
        current_line += 1
    return offset


def offset_to_location(text: str, offset: int) -> Location:
    if offset <= 0:
        return (0, 0)
    line = 0
    at = 0
    for part in text.split("\n"):
        line_len = len(part) + 1
        if at + line_len > offset:
            return (line, offset - at)
        at += line_len
        line += 1
    return (line, 0)


def _count_hex_bytes_before_offset(hex_text: str, offset: int) -> int:
    count = 0
    i = 0
    n = len(hex_text)
    while i < offset and i < n:
        c = hex_text[i]
        if c in "0123456789abcdefABCDEF":
            if i + 1 < n and hex_text[i + 1] in "0123456789abcdefABCDEF":
                count += 1
                i += 2
                continue
        i += 1
    return count


def hex_selection_to_byte_range(hex_text: str, selection: Selection, width: int = 32) -> Optional[tuple[int, int]]:
    """Map TextArea selection to byte span [start, end) in raw DER."""
    start, end = selection
    start_off = location_to_offset(hex_text, start)
    end_off = location_to_offset(hex_text, end)
    if end_off < start_off:
        start_off, end_off = end_off, start_off

    b0 = _count_hex_bytes_before_offset(hex_text, start_off)
    b1 = _count_hex_bytes_before_offset(hex_text, end_off)
    if b1 < b0:
        b0, b1 = b1, b0
    if selection.is_empty:
        if b0 >= _count_hex_bytes_before_offset(hex_text, len(hex_text)):
            return None
        return (b0, b0 + 1)
    if b0 == b1:
        b1 = b0 + 1
    return (b0, max(b1, b0 + 1))


def byte_range_to_hex_selection(hex_text: str, byte_start: int, byte_end: int, width: int = 32) -> Selection:
    """Select hex character range for bytes [byte_start, byte_end) (end exclusive)."""
    if byte_start < 0:
        byte_start = 0
    if byte_end <= byte_start:
        byte_end = byte_start + 1

    def byte_to_loc(b: int) -> Location:
        line = b // width
        col_in_line = b % width
        lines = hex_text.split("\n")
        if line >= len(lines) or line < 0:
            line = max(0, min(line, len(lines) - 1))
            col_in_line = 0
        line_text = lines[line] if lines else ""
        col = col_in_line * 3
        if col > len(line_text):
            col = max(0, len(line_text))
        return (line, col)

    last_b = byte_end - 1
    start_loc = byte_to_loc(byte_start)
    end_line, end_col_base = byte_to_loc(last_b)
    lines = hex_text.split("\n")
    line_text = lines[end_line] if end_line < len(lines) else ""
    end_col = min(end_col_base + 2, len(line_text))
    end_loc: Location = (end_line, end_col)
    if end_loc <= start_loc and (end_line, end_col_base) == start_loc:
        end_loc = (end_line, min(end_col_base + 2, len(line_text)))
    return Selection(start_loc, end_loc)


def key_for_byte_offset(ranges: list[tuple[str, int, int]], byte_off: int) -> Optional[str]:
    for key, a, b in ranges:
        if a <= byte_off < b:
            return key
    return None


def _clamp_int(value: int, lo: int, hi: int) -> int:
    if hi < lo:
        return lo
    return max(lo, min(value, hi))


def section_keys_touching_json_range(
    keys_in_order: list[str],
    spans: dict[str, tuple[int, int, int]],
    start_off: int,
    end_off: int,
) -> list[str]:
    """PE keys whose JSON span ``[entry_begin, value_end)`` meets ``[start_off, end_off)``."""
    if end_off < start_off:
        start_off, end_off = end_off, start_off
    touched: list[str] = []
    for key in keys_in_order:
        triple = spans.get(key)
        if triple is None:
            continue
        entry_begin, _vs, value_end = triple
        if end_off <= entry_begin or start_off >= value_end:
            continue
        touched.append(key)
    return touched


def json_editor_range_to_der_byte_range(
    keys_in_order: list[str],
    spans: dict[str, tuple[int, int, int]],
    ranges_by_key: dict[str, tuple[int, int]],
    start_off: int,
    end_off: int,
    *,
    empty_selection: bool,
) -> Optional[tuple[int, int]]:
    """
    Map JSON character selection to global DER byte range ``[a, b)``.

    Within a single PE, bytes align by position along the JSON *value* substring
    (linear proportion). Multi-PE selections merge into one contiguous DER span.
    """
    if end_off < start_off:
        start_off, end_off = end_off, start_off

    touched = section_keys_touching_json_range(
        keys_in_order,
        spans,
        start_off,
        end_off,
    )
    if len(touched) == 0:
        return None

    order_index = {key: index for index, key in enumerate(keys_in_order)}
    touched = sorted(touched, key=lambda key: order_index.get(key, 10**9))

    def map_point_in_pe(key: str, offset: int) -> tuple[int, int]:
        entry_begin, value_start, value_end = spans[key]
        byte_a, byte_b = ranges_by_key[key]
        v_span = max(value_end - value_start, 1)
        b_span = max(byte_b - byte_a, 1)
        if offset < value_start and offset >= entry_begin:
            return (byte_a, byte_b)
        pos = _clamp_int(offset, value_start, max(value_start, value_end - 1))
        ratio = (pos - value_start) / v_span
        bi = byte_a + min(int(ratio * b_span), b_span - 1)
        return (bi, bi + 1)

    def map_range_in_pe(key: str, js_lo: int, js_hi: int) -> tuple[int, int]:
        _eb, value_start, value_end = spans[key]
        byte_a, byte_b = ranges_by_key[key]
        v_span = max(value_end - value_start, 1)
        b_span = max(byte_b - byte_a, 1)
        lo = _clamp_int(js_lo, value_start, value_end)
        hi = _clamp_int(js_hi, value_start, value_end)
        if hi <= lo:
            hi = min(lo + 1, value_end)
        r0 = (lo - value_start) / v_span
        r1 = (hi - value_start) / v_span
        bs = byte_a + int(r0 * b_span)
        be = byte_a + max(int(math.ceil(r1 * b_span)), bs + 1)
        be = min(be, byte_b)
        return (bs, be)

    if empty_selection or start_off == end_off:
        key0 = touched[0]
        for candidate in touched:
            eb, vs, ve = spans[candidate]
            if eb <= start_off < ve:
                key0 = candidate
                break
        return map_point_in_pe(key0, start_off)

    k_first = touched[0]
    k_last = touched[-1]
    if k_first == k_last:
        return map_range_in_pe(k_first, start_off, end_off)

    _eb0, _vs0, ve0 = spans[k_first]
    _ebn, vsn, _ven = spans[k_last]
    bs, _ = map_range_in_pe(k_first, start_off, ve0)
    _, be = map_range_in_pe(k_last, vsn, end_off)
    if be <= bs:
        be = min(bs + 1, ranges_by_key[k_last][1])
    return (bs, be)


def der_byte_range_to_json_editor_range(
    keys_in_order: list[str],
    spans: dict[str, tuple[int, int, int]],
    ranges_by_key: dict[str, tuple[int, int]],
    byte_start: int,
    byte_end: int,
) -> Optional[tuple[int, int]]:
    """
    Map global DER byte range ``[byte_start, byte_end)`` to JSON character range.

    Uses the same proportional model as :func:`json_editor_range_to_der_byte_range`.
    """
    if byte_end <= byte_start:
        byte_end = byte_start + 1

    intersecting: list[str] = []
    for key in keys_in_order:
        a, b = ranges_by_key[key]
        if max(byte_start, a) < min(byte_end, b):
            intersecting.append(key)
    if len(intersecting) == 0:
        return None

    k_first = intersecting[0]
    k_last = intersecting[-1]

    def local_bytes_to_json_chars(
        key: str,
        lo_local: int,
        hi_local_exclusive: int,
    ) -> tuple[int, int]:
        _eb, value_start, value_end = spans[key]
        byte_a, byte_b = ranges_by_key[key]
        b_span = max(byte_b - byte_a, 1)
        v_span = max(value_end - value_start, 1)
        lo = _clamp_int(lo_local, 0, b_span)
        hi = _clamp_int(hi_local_exclusive, 0, b_span)
        if hi <= lo:
            hi = min(lo + 1, b_span)
        r0 = lo / b_span
        r1 = hi / b_span
        js = value_start + int(r0 * v_span)
        je = value_start + max(int(math.ceil(r1 * v_span)), js + 1)
        je = min(je, value_end)
        if je <= js:
            je = min(js + 1, value_end)
        return (js, je)

    a_first, b_first = ranges_by_key[k_first]
    a_last, b_last = ranges_by_key[k_last]

    if k_first == k_last:
        return local_bytes_to_json_chars(
            k_first,
            byte_start - a_first,
            byte_end - a_first,
        )

    lo_first = byte_start - a_first
    hi_first = min(b_first, byte_end) - a_first
    js_start, _ = local_bytes_to_json_chars(
        k_first,
        lo_first,
        max(hi_first, lo_first + 1),
    )

    lo_last = max(a_last, byte_start) - a_last
    hi_last = byte_end - a_last
    _, je_end = local_bytes_to_json_chars(
        k_last,
        lo_last,
        max(hi_last, lo_last + 1),
    )

    if je_end <= js_start:
        je_end = min(js_start + 1, spans[k_last][2])
    return (js_start, je_end)
