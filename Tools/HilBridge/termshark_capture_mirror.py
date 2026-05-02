#!/usr/bin/env python3
from __future__ import annotations

import os
import sys


def _parse_capture_args(argv: list[str]) -> tuple[str, str]:
    input_path = ""
    output_path = ""
    index = 0
    while index < len(argv):
        current = str(argv[index] or "")
        if current == "-i" and index + 1 < len(argv):
            input_path = str(argv[index + 1] or "")
            index += 2
            continue
        if current == "-w" and index + 1 < len(argv):
            output_path = str(argv[index + 1] or "")
            index += 2
            continue
        index += 1
    normalized_output = str(output_path or "").strip()
    if len(normalized_output) == 0:
        raise ValueError("Missing output path for mirrored capture stream.")
    normalized_input = str(input_path or "").strip()
    if len(normalized_input) == 0:
        normalized_input = "/dev/fd/0"
    return normalized_input, normalized_output


def _open_input_stream(input_path: str):
    normalized_input = str(input_path or "").strip()
    if normalized_input in ("", "-", "/dev/stdin", "/dev/fd/0"):
        return sys.stdin.buffer, False
    return open(normalized_input, "rb", buffering=0), True


def mirror_input_to_output(input_path: str, output_path: str) -> int:
    normalized_output = str(output_path or "").strip()
    if len(normalized_output) == 0:
        raise ValueError("Missing output path for mirrored capture stream.")
    output_parent = os.path.dirname(normalized_output)
    if len(output_parent) > 0:
        os.makedirs(output_parent, exist_ok=True)
    source_handle = None
    source_owned = False
    try:
        source_handle, source_owned = _open_input_stream(input_path)
        with open(normalized_output, "wb", buffering=0) as target_handle:
            while True:
                chunk = source_handle.read(65536)
                if not chunk:
                    break
                target_handle.write(chunk)
                target_handle.flush()
        return 0
    finally:
        if source_owned and source_handle is not None:
            source_handle.close()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        input_path, output_path = _parse_capture_args(arguments)
        return mirror_input_to_output(input_path, output_path)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as exc:
        print(f"termshark_capture_mirror: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
