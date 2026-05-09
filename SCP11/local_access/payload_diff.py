# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 local-access payload diff: computes byte-span differences between two BPP payload files for diagnostics."""
import argparse
import hashlib
from pathlib import Path
from typing import Any

from .session import LocalIsdrSession


def decode_payload_bytes(data: bytes) -> bytes:
    """Decode a raw BPP payload byte string into a list of STORE-DATA segment dicts."""
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return data
    allowed = set("0123456789ABCDEFabcdef \t\n\r")
    if not all(char in allowed for char in text):
        return data
    hex_text = "".join(text.split())
    if len(hex_text) < 4 or len(hex_text) % 2 != 0:
        return data
    try:
        return bytes.fromhex(hex_text)
    except ValueError:
        return data


def read_payload_file(path: str) -> bytes:
    return decode_payload_bytes(Path(path).read_bytes())


def compute_diff_spans(left: bytes, right: bytes) -> list[tuple[int, int]]:
    """Compare two BPP payload byte sequences and return a list of differing byte-range spans."""
    spans: list[tuple[int, int]] = []
    start = None
    limit = min(len(left), len(right))
    for index in range(limit):
        if left[index] == right[index]:
            if start is not None:
                spans.append((start, index))
                start = None
            continue
        if start is None:
            start = index
    if start is not None:
        spans.append((start, limit))
    if len(left) != len(right):
        spans.append((limit, max(len(left), len(right))))
    return spans


def _session_stub() -> LocalIsdrSession:
    return LocalIsdrSession.__new__(LocalIsdrSession)


def build_tlv_ranges(payload: bytes) -> list[tuple[int, int, str]]:
    session = _session_stub()
    return session._describe_upp_element_ranges(payload)


def describe_offset(offset: int, ranges: list[tuple[int, int, str]]) -> str:
    for start, end, label in ranges:
        if start <= offset < end:
            return f"{label} [{start}:{end}]"
    return "no top-level TLV match"


def slice_hex(data: bytes, start: int, size: int = 32) -> str:
    end = min(len(data), start + size)
    return data[start:end].hex().upper()


def analyze_payload_pair(left: bytes, right: bytes) -> dict[str, Any]:
    """Return a structured diff analysis dict for two BPP payload files."""
    left_ranges = build_tlv_ranges(left)
    right_ranges = build_tlv_ranges(right)
    diff_spans = compute_diff_spans(left, right)
    first_diff = diff_spans[0][0] if len(diff_spans) > 0 else None
    return {
        "left_len": len(left),
        "right_len": len(right),
        "left_sha256": hashlib.sha256(left).hexdigest().upper(),
        "right_sha256": hashlib.sha256(right).hexdigest().upper(),
        "equal": left == right,
        "diff_spans": diff_spans,
        "first_diff": first_diff,
        "left_ranges": left_ranges,
        "right_ranges": right_ranges,
    }


def format_analysis(analysis: dict[str, Any], left: bytes, right: bytes, left_name: str, right_name: str) -> str:
    """Format a payload-diff analysis dict as a human-readable multi-line string."""
    lines = [
        f"{left_name}: len={analysis['left_len']} sha256={analysis['left_sha256']}",
        f"{right_name}: len={analysis['right_len']} sha256={analysis['right_sha256']}",
        f"equal={analysis['equal']}",
    ]
    diff_spans = analysis["diff_spans"]
    if len(diff_spans) == 0:
        lines.append("No differing spans.")
        return "\n".join(lines)

    first_diff = analysis["first_diff"]
    assert isinstance(first_diff, int)
    lines.append(f"first_diff_offset={first_diff}")
    lines.append(
        f"{left_name} region={describe_offset(first_diff, analysis['left_ranges'])}"
    )
    lines.append(
        f"{right_name} region={describe_offset(first_diff, analysis['right_ranges'])}"
    )
    left_byte = left[first_diff] if first_diff < len(left) else None
    right_byte = right[first_diff] if first_diff < len(right) else None
    lines.append(
        f"first_diff_bytes={left_name}:{'EOF' if left_byte is None else f'0x{left_byte:02X}'} "
        f"{right_name}:{'EOF' if right_byte is None else f'0x{right_byte:02X}'}"
    )
    window_start = max(0, first_diff - 16)
    lines.append(f"{left_name} window[{window_start}:{window_start + 32}]={slice_hex(left, window_start)}")
    lines.append(f"{right_name} window[{window_start}:{window_start + 32}]={slice_hex(right, window_start)}")
    preview = ", ".join(f"[{start}:{end}]" for start, end in diff_spans[:10])
    if len(diff_spans) > 10:
        preview += ", ..."
    lines.append(f"diff_spans={preview}")
    return "\n".join(lines)


def main() -> int:
    """CLI entry point for the payload-diff diagnostic tool."""
    parser = argparse.ArgumentParser(description="Compare two clear profile payloads.")
    parser.add_argument("left_path", help="First payload file path")
    parser.add_argument("right_path", help="Second payload file path")
    args = parser.parse_args()

    left = read_payload_file(args.left_path)
    right = read_payload_file(args.right_path)
    analysis = analyze_payload_pair(left, right)
    print(format_analysis(analysis, left, right, args.left_path, args.right_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
