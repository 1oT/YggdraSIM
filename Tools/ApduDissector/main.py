# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""CLI entry point for ``yggdrasim-apdu-dissect``.

Sub-commands:

* ``decode`` -- run tshark against a capture with the bundled dissector
  loaded. This is the offline-review path; ``--verbose`` gives the full
  tree, ``--fields`` a tab-separated summary.
* ``install`` / ``uninstall`` -- copy the Lua tree into the Wireshark
  GUI's personal plugin folder. tshark users do not need this.
* ``path`` -- print the resolved dissector path, for pasting into a
  ``-X lua_script:`` argument or a Wireshark launch of your own.
* ``probe`` -- report what the local Wireshark build supports. Useful
  when the dissector is not producing the tree you expect.

Every sub-command warns when it is running as root, because Wireshark
refuses to load Lua scripts for a superuser process and says nothing
about it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .install import InstallError, build_plan, install, uninstall
from .tshark_runner import (
    DEFAULT_TSHARK_BINARY,
    GSMTAP_DECODE_RULE,
    TsharkMissingError,
    build_tshark_invocation,
    lua_directory,
    locate_dissector,
    run_tshark,
    running_as_root,
)

PROBE_FILENAME = "probe_wireshark_env.lua"

_ROOT_WARNING = (
    "warning: running as root. Wireshark refuses to load Lua scripts for a "
    "superuser process and reports no error when it does so, which looks "
    "exactly like a dissector that decodes nothing. Re-run as a normal user."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-apdu-dissect",
        description=(
            "Deep APDU decoding for Wireshark and tshark. Decodes the "
            "GSMTAP SIM frames the HIL bridge mirrors on UDP 4729 down "
            "through BER-TLV, file-control templates and file contents."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    decoder = subparsers.add_parser(
        "decode", help="Run tshark against a capture with the dissector loaded."
    )
    decoder.add_argument("--pcap", required=True, help="Capture file to read.")
    decoder.add_argument(
        "--tshark",
        default=DEFAULT_TSHARK_BINARY,
        help="tshark binary name or absolute path (default: tshark).",
    )
    decoder.add_argument(
        "--sidecar",
        default="",
        help="Decrypted-payload sidecar JSON to overlay on the capture.",
    )
    decoder.add_argument(
        "--filter", default="", help="Display filter passed to tshark as -Y."
    )
    decoder.add_argument(
        "--verbose",
        action="store_true",
        help="Show the full protocol tree (tshark -V).",
    )
    decoder.add_argument(
        "--fields",
        default="",
        help="Comma-separated field names to print instead of the tree.",
    )
    decoder.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Extra argument for tshark. Repeat for multiple.",
    )

    installer = subparsers.add_parser(
        "install", help="Copy the dissector into Wireshark's plugin folder."
    )
    installer.add_argument(
        "--dest", default="", help="Install here instead of the reported folder."
    )
    installer.add_argument(
        "--tshark", default=DEFAULT_TSHARK_BINARY, help="tshark binary to ask."
    )
    installer.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be copied and stop.",
    )

    remover = subparsers.add_parser(
        "uninstall", help="Remove a previously installed copy."
    )
    remover.add_argument("--dest", default="", help="Folder the copy was installed to.")
    remover.add_argument(
        "--tshark", default=DEFAULT_TSHARK_BINARY, help="tshark binary to ask."
    )

    sidecar_parser = subparsers.add_parser(
        "sidecar",
        help="Recover SCP03/SCP11c plaintext from a capture into a sidecar.",
    )
    sidecar_parser.add_argument("--pcap", required=True, help="Capture to read.")
    sidecar_parser.add_argument(
        "--keybag",
        default="",
        help="Keybag JSON with the session keys. Auto-discovered from a "
             "sibling <pcap>*.keys.json when omitted.",
    )
    sidecar_parser.add_argument(
        "--out",
        default="",
        help="Where to write the sidecar. Defaults to <pcap>.sidecar.json.",
    )
    sidecar_parser.add_argument(
        "--tshark", default=DEFAULT_TSHARK_BINARY, help="tshark binary to use."
    )

    subparsers.add_parser("path", help="Print the bundled dissector's path.")

    prober = subparsers.add_parser(
        "probe", help="Report what the local Wireshark build supports."
    )
    prober.add_argument("--pcap", default="", help="Any capture file to read.")
    prober.add_argument(
        "--tshark", default=DEFAULT_TSHARK_BINARY, help="tshark binary to run."
    )

    return parser


def _warn_if_root(stream) -> None:
    if running_as_root():
        print(_ROOT_WARNING, file=stream)


def _run_decode(args: argparse.Namespace, stdout, stderr) -> int:
    pcap_path = Path(args.pcap).expanduser()
    if not pcap_path.is_file():
        print(f"capture not found: {pcap_path}", file=stderr)
        return 1

    extra: list[str] = list(args.extra)
    if args.verbose:
        extra.append("-V")
    if args.fields:
        extra.extend(["-T", "fields"])
        for name in str(args.fields).split(","):
            trimmed = name.strip()
            if trimmed:
                extra.extend(["-e", trimmed])
    if args.filter:
        extra.extend(["-Y", str(args.filter)])

    sidecar = Path(args.sidecar).expanduser() if args.sidecar else None
    if sidecar is not None and not sidecar.is_file():
        print(f"sidecar not found: {sidecar}", file=stderr)
        return 1

    invocation = build_tshark_invocation(
        pcap_path=pcap_path,
        tshark_binary=args.tshark,
        sidecar_path=sidecar,
        decode_rule=GSMTAP_DECODE_RULE,
        extra_args=extra,
    )
    _warn_if_root(stderr)
    try:
        completed = run_tshark(invocation, capture_output=True)
    except TsharkMissingError as error:
        print(str(error), file=stderr)
        return 1

    stdout.write(completed.stdout.decode("utf-8", errors="replace"))
    error_text = completed.stderr.decode("utf-8", errors="replace")
    if error_text.strip():
        stderr.write(error_text)
    if "Lua Error" in error_text:
        return 1
    return int(completed.returncode)


def _run_install(args: argparse.Namespace, stdout, stderr) -> int:
    override = Path(args.dest).expanduser() if args.dest else None
    try:
        if args.dry_run:
            plan = build_plan(tshark_binary=args.tshark, override=override)
            print("dry run, nothing copied:", file=stdout)
            print(plan.describe(), file=stdout)
            return 0
        plan = install(tshark_binary=args.tshark, override=override)
    except (InstallError, TsharkMissingError) as error:
        print(str(error), file=stderr)
        return 1
    print(f"installed {len(plan.files)} file(s) into {plan.destination}", file=stdout)
    print(
        "In a running Wireshark, reload with Analyze > Reload Lua Plugins "
        "(Ctrl+Shift+L).",
        file=stdout,
    )
    return 0


def _run_uninstall(args: argparse.Namespace, stdout, stderr) -> int:
    override = Path(args.dest).expanduser() if args.dest else None
    try:
        destination = uninstall(tshark_binary=args.tshark, override=override)
    except (InstallError, TsharkMissingError) as error:
        print(str(error), file=stderr)
        return 1
    print(f"removed {destination}", file=stdout)
    return 0


def _run_sidecar(args: argparse.Namespace, stdout, stderr) -> int:
    from .sidecar import SidecarError, autodiscover_keybag, build_sidecar

    pcap_path = Path(args.pcap).expanduser()
    if not pcap_path.is_file():
        print(f"capture not found: {pcap_path}", file=stderr)
        return 1

    keybag_path = Path(args.keybag).expanduser() if args.keybag else None
    if keybag_path is None:
        keybag_path = autodiscover_keybag(pcap_path)
        if keybag_path is None:
            print(
                "no keybag given and none found beside the capture. Export "
                "one with EXPORT-KEYBAG in the SCP03 admin shell or "
                "SCP11.local_access, then pass --keybag.",
                file=stderr,
            )
            return 1
        print(f"using keybag {keybag_path}", file=stdout)
    if not keybag_path.is_file():
        print(f"keybag not found: {keybag_path}", file=stderr)
        return 1

    output_path = (
        Path(args.out).expanduser()
        if args.out
        else pcap_path.with_suffix(pcap_path.suffix + ".sidecar.json")
    )
    try:
        summary = build_sidecar(
            pcap_path=pcap_path,
            keybag_path=keybag_path,
            output_path=output_path,
            tshark_binary=args.tshark,
        )
    except (SidecarError, TsharkMissingError) as error:
        print(str(error), file=stderr)
        return 1

    print(summary.describe(), file=stdout)
    if summary.frames_recovered == 0:
        print(
            "nothing was recovered. Check that the keybag matches this "
            "capture and that the session it describes starts at or before "
            "the first wrapped frame.",
            file=stderr,
        )
    return 0


def _run_probe(args: argparse.Namespace, stdout, stderr) -> int:
    probe_path = lua_directory() / PROBE_FILENAME
    if not probe_path.is_file():
        print(f"probe script not found: {probe_path}", file=stderr)
        return 1
    capture = Path(args.pcap).expanduser() if args.pcap else None
    if capture is None or not capture.is_file():
        print(
            "probe needs a capture to read; pass --pcap with any pcap file.",
            file=stderr,
        )
        return 1
    invocation = build_tshark_invocation(
        pcap_path=capture,
        tshark_binary=args.tshark,
        dissector_path=probe_path,
        decode_rule=GSMTAP_DECODE_RULE,
    )
    _warn_if_root(stderr)
    try:
        completed = run_tshark(invocation, capture_output=True)
    except TsharkMissingError as error:
        print(str(error), file=stderr)
        return 1
    report = completed.stderr.decode("utf-8", errors="replace")
    probe_lines = [line for line in report.splitlines() if line.startswith("PROBE ")]
    if not probe_lines:
        print(
            "the probe produced no output. On a superuser process that is "
            "expected: Wireshark refuses -X lua_script: without saying so.",
            file=stderr,
        )
        return 1
    for line in probe_lines:
        print(line, file=stdout)
    return 0


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    stdout=None,
    stderr=None,
) -> int:
    """Parse *argv* and dispatch. Returns a process exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.command == "decode":
        return _run_decode(args, out, err)
    if args.command == "install":
        return _run_install(args, out, err)
    if args.command == "uninstall":
        return _run_uninstall(args, out, err)
    if args.command == "sidecar":
        return _run_sidecar(args, out, err)
    if args.command == "path":
        print(str(locate_dissector()), file=out)
        return 0
    if args.command == "probe":
        return _run_probe(args, out, err)

    parser.print_help(err)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run_cli(argv)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
