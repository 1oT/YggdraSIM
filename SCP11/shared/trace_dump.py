# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 trace dump helpers: render card-bound payloads and STORE DATA chunk plans."""
from __future__ import annotations


def format_hex_dump(payload: bytes, width: int = 32, indent: str = "    ") -> list[str]:
    """Return an offset-prefixed uppercase hex dump for a binary payload."""
    data = bytes(payload)
    row_width = int(width)
    if row_width <= 0:
        row_width = 32
    if len(data) == 0:
        return [f"{indent}<empty>"]

    lines: list[str] = []
    for offset in range(0, len(data), row_width):
        chunk = data[offset : offset + row_width]
        hex_bytes = " ".join(f"{item:02X}" for item in chunk)
        lines.append(f"{indent}{offset:06X}: {hex_bytes}")
    return lines


def print_hex_payload(label: str, payload: bytes, width: int = 32) -> None:
    """Print a full binary payload with deterministic hex formatting."""
    data = bytes(payload)
    clean_label = str(label or "payload").strip() or "payload"
    print(f"[*] {clean_label}: {len(data)} bytes")
    for line in format_hex_dump(data, width=width):
        print(line)


def summarize_eim_package_wrapper(payload: bytes) -> dict[str, str]:
    """Return a BER-grounded summary of an eIM package wrapper."""
    data = bytes(payload)
    summary: dict[str, str] = {
        "root_tag": "",
        "root_len": "0",
        "complete": "no",
        "outer_eim_id": "",
        "eid": "",
        "counter": "",
        "eim_transaction_id": "",
        "inner_choice": "",
        "inner_card_request": "",
        "inner_card_request_len": "",
        "signature_present": "no",
        "signature_len": "0",
    }
    if len(data) == 0:
        return summary

    root = _read_tlv_header(data, 0, len(data))
    if root is None:
        return summary
    root_tag_start, root_tag_end, root_value_start, root_value_end, _ = root
    summary["root_tag"] = data[root_tag_start:root_tag_end].hex().upper()
    summary["root_len"] = str(root_value_end - root_value_start)
    summary["complete"] = "yes" if root_value_end == len(data) else "no"

    signed_value = b""
    for child in _iter_tlv_headers(data, root_value_start, root_value_end):
        child_tag_start, child_tag_end, child_value_start, child_value_end, _ = child
        child_tag = data[child_tag_start:child_tag_end]
        child_value = data[child_value_start:child_value_end]
        if child_tag == b"\x30" and len(signed_value) == 0:
            signed_value = child_value
            continue
        if child_tag == b"\x5F\x37":
            summary["signature_present"] = "yes"
            summary["signature_len"] = str(len(child_value))

    if len(signed_value) == 0:
        return summary

    for field in _iter_tlv_headers(signed_value, 0, len(signed_value)):
        field_tag_start, field_tag_end, field_value_start, field_value_end, _ = field
        field_tag = signed_value[field_tag_start:field_tag_end]
        field_value = signed_value[field_value_start:field_value_end]
        if field_tag == b"\x80":
            summary["outer_eim_id"] = _decode_text_or_hex(field_value)
        elif field_tag == b"\x5A":
            summary["eid"] = field_value.hex().upper()
        elif field_tag == b"\x81":
            summary["counter"] = _format_unsigned_int(field_value)
        elif field_tag == b"\x82":
            summary["eim_transaction_id"] = field_value.hex().upper()
        elif len(field_tag) > 0 and field_tag[0] in range(0xA0, 0xB0):
            summary["inner_choice"] = field_tag.hex().upper()
            inner = _first_tlv_header(field_value)
            if inner is not None:
                inner_tag_start, inner_tag_end, inner_value_start, inner_value_end, _ = inner
                summary["inner_card_request"] = field_value[inner_tag_start:inner_tag_end].hex().upper()
                summary["inner_card_request_len"] = str(inner_value_end - inner_value_start)
    return summary


def print_eim_package_wrapper_summary(payload: bytes) -> None:
    """Print wrapper fields that the card can validate from the BER bytes."""
    summary = summarize_eim_package_wrapper(payload)
    fragments = [
        f"root={summary['root_tag'] or '(unparsed)'}",
        f"root_len={summary['root_len']}",
        f"complete={summary['complete']}",
    ]
    if summary["outer_eim_id"]:
        fragments.append(f"outer_eimId={summary['outer_eim_id']}")
    if summary["eid"]:
        fragments.append(f"eid={summary['eid']}")
    if summary["counter"]:
        fragments.append(f"counter={summary['counter']}")
    if summary["eim_transaction_id"]:
        fragments.append(f"eimTransactionId={summary['eim_transaction_id']}")
    if summary["inner_choice"]:
        fragments.append(f"inner_choice={summary['inner_choice']}")
    if summary["inner_card_request"]:
        fragments.append(
            f"inner_card_request={summary['inner_card_request']}"
            f"/{summary['inner_card_request_len']}"
        )
    fragments.append(
        f"signature={summary['signature_present']}"
        f"/{summary['signature_len']}B"
    )
    print("[*] eIM signed wrapper summary: " + " ".join(fragments))


def split_tlv_aware_chunks(payload: bytes, chunk_size: int) -> list[bytes]:
    """Split a BER-TLV stream on TLV boundaries when possible."""
    data = bytes(payload)
    if len(data) == 0:
        return []
    effective_chunk_size = int(chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = 1

    boundaries = _tlv_end_boundaries(data)
    chunks: list[bytes] = []
    offset = 0
    total = len(data)
    while offset < total:
        fixed_limit = min(total, offset + effective_chunk_size)
        next_offset = fixed_limit
        if fixed_limit < total:
            candidates = [
                boundary
                for boundary in boundaries
                if offset < boundary <= fixed_limit
            ]
            if len(candidates) > 0:
                next_offset = max(candidates)
        if next_offset <= offset:
            next_offset = fixed_limit
        chunks.append(data[offset:next_offset])
        offset = next_offset
    return chunks


def _tlv_end_boundaries(data: bytes) -> set[int]:
    boundaries: set[int] = {len(data)}
    _collect_tlv_end_boundaries(data, 0, len(data), boundaries)
    return boundaries


def _collect_tlv_end_boundaries(
    data: bytes,
    start: int,
    end: int,
    boundaries: set[int],
) -> None:
    offset = start
    while offset < end:
        parsed = _read_tlv_header(data, offset, end)
        if parsed is None:
            return
        tag_start, _, value_start, value_end, constructed = parsed
        if value_end > end:
            return
        if value_end > tag_start:
            boundaries.add(value_end)
        if constructed:
            _collect_tlv_end_boundaries(data, value_start, value_end, boundaries)
        offset = value_end
    if offset == end:
        boundaries.add(end)


def _read_tlv_header(
    data: bytes,
    offset: int,
    end: int,
) -> tuple[int, int, int, int, bool] | None:
    if offset >= end:
        return None
    tag_start = offset
    first_tag_byte = data[offset]
    constructed = bool(first_tag_byte & 0x20)
    offset += 1
    if first_tag_byte & 0x1F == 0x1F:
        while offset < end:
            current = data[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            return None
    tag_end = offset
    if offset >= end:
        return None

    first_length_byte = data[offset]
    offset += 1
    if first_length_byte & 0x80 == 0:
        value_length = first_length_byte
    else:
        length_octets = first_length_byte & 0x7F
        if length_octets == 0:
            return None
        if length_octets > 4:
            return None
        if offset + length_octets > end:
            return None
        value_length = int.from_bytes(data[offset : offset + length_octets], "big")
        offset += length_octets

    value_start = offset
    value_end = value_start + value_length
    if value_end > end:
        return None
    return tag_start, tag_end, value_start, value_end, constructed


def _iter_tlv_headers(
    data: bytes,
    start: int,
    end: int,
) -> list[tuple[int, int, int, int, bool]]:
    headers: list[tuple[int, int, int, int, bool]] = []
    offset = start
    while offset < end:
        parsed = _read_tlv_header(data, offset, end)
        if parsed is None:
            break
        headers.append(parsed)
        _, _, _, value_end, _ = parsed
        if value_end <= offset:
            break
        offset = value_end
    return headers


def _first_tlv_header(data: bytes) -> tuple[int, int, int, int, bool] | None:
    return _read_tlv_header(data, 0, len(data))


def _decode_text_or_hex(value: bytes) -> str:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    if decoded.isprintable():
        return decoded
    return value.hex().upper()


def _format_unsigned_int(value: bytes) -> str:
    if len(value) == 0:
        return "0"
    integer_value = int.from_bytes(value, "big", signed=False)
    return f"{integer_value} ({value.hex().upper()})"


def print_store_data_chunk_plan(
    log_name: str,
    payload: bytes,
    *,
    cla: int,
    ins: int,
    final_p1: int,
    p2_start: int,
    chunk_size: int,
    more_p1: int = 0x11,
    p2_wrap: bool = False,
    width: int = 32,
    chunks: list[bytes] | None = None,
) -> None:
    """Print the STORE DATA segmentation that will be used before transmission."""
    data = bytes(payload)
    clean_label = str(log_name or "STORE DATA").strip() or "STORE DATA"
    effective_chunk_size = int(chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = 1

    total = len(data)
    planned_chunks = list(chunks) if chunks is not None else split_tlv_aware_chunks(data, effective_chunk_size)
    chunk_count = len(planned_chunks)

    print(
        f"[*] STORE DATA chunk plan for {clean_label}: "
        f"total_bytes={total} chunk_size={effective_chunk_size} chunks={chunk_count} "
        f"strategy=tlv-aware "
        f"CLA={int(cla) & 0xFF:02X} INS={int(ins) & 0xFF:02X} "
        f"P1_more={int(more_p1) & 0xFF:02X} P1_final={int(final_p1) & 0xFF:02X} "
        f"P2_start={int(p2_start) & 0xFF:02X}"
    )
    print_hex_payload(f"{clean_label} full payload", data, width=width)

    tlv_boundaries = _tlv_end_boundaries(data)
    offset = 0
    block = int(p2_start)
    for chunk_index, chunk in enumerate(planned_chunks, start=1):
        chunk_bytes = bytes(chunk)
        end_offset = offset + len(chunk_bytes)
        is_last_chunk = chunk_index == chunk_count
        current_p1 = final_p1 if is_last_chunk else more_p1
        current_p2 = block & 0xFF if p2_wrap else block
        if p2_wrap and current_p2 != block:
            p2_text = f"{block:02X}->{current_p2:02X}"
        else:
            p2_text = f"{current_p2:02X}"
        last_text = "yes" if is_last_chunk else "no"
        boundary_text = "tlv" if end_offset in tlv_boundaries else "max"
        print(
            f"  > Chunk {chunk_index}/{chunk_count}: "
            f"offset={offset} len={len(chunk_bytes)} P1={int(current_p1) & 0xFF:02X} "
            f"P2={p2_text} last={last_text} boundary={boundary_text}"
        )
        for line in format_hex_dump(chunk_bytes, width=width, indent="      "):
            print(line)
        offset = end_offset
        block += 1
