#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import sys


def _resolve_capture_backend() -> str:
    tshark_binary = shutil.which("tshark")
    if tshark_binary is not None:
        return tshark_binary
    dumpcap_binary = shutil.which("dumpcap")
    if dumpcap_binary is not None:
        return dumpcap_binary
    return "tshark"


def build_capture_command(
    argv: list[str],
    *,
    capture_backend: str | None = None,
) -> list[str]:
    backend = str(capture_backend or _resolve_capture_backend()).strip()
    if len(backend) == 0:
        raise ValueError("Missing capture backend for Termshark pcap wrapper.")
    arguments = list(argv)
    if "-F" not in arguments:
        return [backend, "-F", "pcap", *arguments]
    return [backend, *arguments]


def exec_capture_command(command: list[str]) -> None:
    if len(command) == 0:
        raise ValueError("Missing capture command for Termshark pcap wrapper.")
    executable = str(command[0] or "").strip()
    if len(executable) == 0:
        raise ValueError("Missing capture executable for Termshark pcap wrapper.")
    if os.path.sep in executable:
        os.execv(executable, command)
    os.execvp(executable, command)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        command = build_capture_command(arguments)
        exec_capture_command(command)
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as exc:
        print(f"termshark_capture_pcap: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
