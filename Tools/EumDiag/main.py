"""
CLI entry point for ``yggdrasim-eum-diag``.

Sub-commands:

* ``inject-keys`` -- build a session-key repository JSON from
  ``--iccid / --shs-enc / --shs-mac / --dek`` arguments (optionally
  read from ``--bundle-file``) and invoke tshark with the bundled
  Lua dissector. Use this when an EUM operator has a PCAP from the
  network capture and the keys pulled from their server database.

* ``store-keys`` -- same as ``inject-keys`` but skips the tshark
  invocation. Useful for batch builds that feed multiple PCAPs off
  the same key set.

* ``decode-bpp`` -- offline decode of a Bound Profile Package byte
  string via pySim's SAIP ASN.1 machinery. Falls back to a clear
  error message when pySim is not importable.

The CLI never writes outside ``--output-dir`` (default ``reports/eum``
under the workspace root).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Sequence

from .session_keys import (
    SessionKeyBundle,
    SessionKeyError,
    SessionKeyRepository,
    load_repository,
    write_repository_atomic,
)
from .tshark_runner import (
    TsharkMissingError,
    build_tshark_invocation,
    run_tshark,
)


_LOGGER = logging.getLogger(__name__)


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-eum-diag",
        description=(
            "Tier-3 EUM / SM-DP+ diagnostics. Injects session keys into "
            "the bundled Wireshark/tshark Lua dissector so operators "
            "can inspect a failed BF36 Bound Profile Package frame."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inject-keys
    injector = subparsers.add_parser(
        "inject-keys",
        help="Write a session-key repository and invoke tshark on a pcap.",
    )
    _add_bundle_args(injector)
    injector.add_argument("--pcap", required=True, help="Path to the capture.")
    injector.add_argument(
        "--tshark",
        default="tshark",
        help="tshark binary name / absolute path (default: tshark).",
    )
    injector.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Extra argument for tshark. Repeat for multiple.",
    )

    # store-keys
    storer = subparsers.add_parser(
        "store-keys",
        help="Only write the session-key repository; do not invoke tshark.",
    )
    _add_bundle_args(storer)

    # decode-bpp
    decoder = subparsers.add_parser(
        "decode-bpp",
        help="Offline decode a Bound Profile Package binary via pySim.",
    )
    decoder.add_argument("--bpp", required=True, help="Path to BF36 DER bytes.")
    decoder.add_argument(
        "--keys",
        default="",
        help="Optional path to a session-key repository (used for ICCID lookup).",
    )

    parser.add_argument(
        "--workspace-root",
        default="",
        help="Workspace root used for default output resolution.",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Base directory for generated key repositories.",
    )
    return parser


def _add_bundle_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--iccid", help="ICCID for the session-key bundle.")
    parser.add_argument("--shs-enc", help="Hex-encoded ShS-ENC key (16 bytes).")
    parser.add_argument("--shs-mac", help="Hex-encoded ShS-MAC key (16 bytes).")
    parser.add_argument(
        "--dek",
        default="",
        help="Optional hex-encoded DEK (16 bytes).",
    )
    parser.add_argument(
        "--comment",
        default="",
        help="Free-text comment stored with the bundle (e.g. server case id).",
    )
    parser.add_argument(
        "--bundle-file",
        default="",
        help="Path to a repository JSON. Overrides --iccid/--shs-* when set.",
    )
    parser.add_argument(
        "--keys-out",
        default="",
        help="Path to write the generated repository JSON.",
    )


def _resolve_output_dir(args: argparse.Namespace, workspace_root: Path) -> Path:
    if len(str(args.output_dir or "").strip()) > 0:
        return Path(args.output_dir).expanduser().resolve()
    return (workspace_root / "reports" / "eum").resolve()


def _build_repository_from_args(args: argparse.Namespace) -> SessionKeyRepository:
    source_path = str(getattr(args, "bundle_file", "") or "").strip()
    if len(source_path) > 0:
        return load_repository(Path(source_path))
    iccid = str(args.iccid or "").strip()
    shs_enc = str(args.shs_enc or "").strip()
    shs_mac = str(args.shs_mac or "").strip()
    if len(iccid) == 0 or len(shs_enc) == 0 or len(shs_mac) == 0:
        raise SessionKeyError(
            "--iccid, --shs-enc, and --shs-mac are required unless --bundle-file is set."
        )
    bundle = SessionKeyBundle.from_hex(
        iccid=iccid,
        shs_enc=shs_enc,
        shs_mac=shs_mac,
        dek=str(args.dek or "") or None,
        comment=str(args.comment or ""),
    )
    return SessionKeyRepository.from_bundles([bundle])


def _write_repository(
    repository: SessionKeyRepository,
    *,
    args: argparse.Namespace,
    workspace_root: Path,
) -> Path:
    explicit = str(args.keys_out or "").strip()
    if len(explicit) > 0:
        target = Path(explicit).expanduser().resolve()
    else:
        output_dir = _resolve_output_dir(args, workspace_root)
        target = output_dir / "session-keys.json"
    write_repository_atomic(repository, target)
    return target


def _cmd_inject_keys(args: argparse.Namespace, workspace_root: Path) -> int:
    try:
        repository = _build_repository_from_args(args)
    except SessionKeyError as error:
        sys.stderr.write(f"[-] {error}\n")
        return 2
    try:
        target = _write_repository(
            repository,
            args=args,
            workspace_root=workspace_root,
        )
    except OSError as error:
        sys.stderr.write(f"[-] could not write key repository: {error}\n")
        return 2
    sys.stdout.write(f"[+] wrote session-key repository to {target}\n")

    pcap = Path(args.pcap).expanduser().resolve()
    if pcap.is_file() is False:
        sys.stderr.write(f"[-] pcap not found: {pcap}\n")
        return 3
    invocation = build_tshark_invocation(
        pcap_path=pcap,
        keys_path=target,
        tshark_binary=args.tshark,
        extra_args=tuple(args.extra or []),
    )
    sys.stdout.write("[+] invoking tshark: " + " ".join(invocation.command) + "\n")
    try:
        result = run_tshark(invocation, capture_output=False)
    except TsharkMissingError as error:
        sys.stderr.write(f"[-] {error}\n")
        return 4
    return int(result.returncode)


def _cmd_store_keys(args: argparse.Namespace, workspace_root: Path) -> int:
    try:
        repository = _build_repository_from_args(args)
    except SessionKeyError as error:
        sys.stderr.write(f"[-] {error}\n")
        return 2
    try:
        target = _write_repository(
            repository,
            args=args,
            workspace_root=workspace_root,
        )
    except OSError as error:
        sys.stderr.write(f"[-] could not write key repository: {error}\n")
        return 2
    sys.stdout.write(f"[+] wrote session-key repository to {target}\n")
    return 0


def _cmd_decode_bpp(args: argparse.Namespace, workspace_root: Path) -> int:
    bpp_path = Path(args.bpp).expanduser().resolve()
    if bpp_path.is_file() is False:
        sys.stderr.write(f"[-] BPP file not found: {bpp_path}\n")
        return 3
    try:
        from Tools.ProfilePackage.saip_json_codec import (
            ensure_workspace_pysim_on_path,
        )

        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import bpp  # type: ignore[import-not-found]
    except ImportError as error:
        sys.stderr.write(
            "[-] offline BPP decode needs pySim. Install the PyPI wheel "
            "(`pip install pySim`) or clone the upstream tree "
            "(`git clone https://gitlab.com/osmocom/pysim.git pysim`) "
            f"into {workspace_root}. Underlying error: {error}\n"
        )
        return 4
    raw_bytes = bpp_path.read_bytes()
    try:
        parsed = bpp.BoundProfilePackage.from_der(raw_bytes)
    except Exception as error:
        sys.stderr.write(
            f"[-] BPP decode failed: {error.__class__.__name__}: {error}\n"
        )
        return 5
    summary = {
        "pathname": str(bpp_path),
        "byte_length": len(raw_bytes),
        "iccid": getattr(parsed, "iccid", ""),
        "segment_count": len(getattr(parsed, "segments", []) or []),
    }
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


def run_cli(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _build_argparser()
    args = parser.parse_args(argv)
    workspace_root = (
        Path(args.workspace_root).expanduser().resolve()
        if len(str(args.workspace_root or "").strip()) > 0
        else Path.cwd().resolve()
    )
    if args.command == "inject-keys":
        return _cmd_inject_keys(args, workspace_root)
    if args.command == "store-keys":
        return _cmd_store_keys(args, workspace_root)
    if args.command == "decode-bpp":
        return _cmd_decode_bpp(args, workspace_root)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(run_cli())
