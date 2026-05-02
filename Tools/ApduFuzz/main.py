"""
CLI entry point for the APDU mutation fuzzer.

The CLI is intentionally noisy about the safety gates: it prints the
opt-in status, the allow-lists, and the crash-dump directory before
the first APDU is transmitted. Running without ``--i-mean-it`` or
without at least one ``--allow-iccid`` / ``--allow-imsi`` exits
immediately with a non-zero code.

Transport selection:

* ``--transport pcsc`` -- use the first PC/SC reader that matches
  ``--reader`` (substring match). Requires :mod:`pyscard`.
* ``--transport null`` -- in-process smoke test harness. Always
  returns the fake probe ``("fake", "fake")`` and replies ``9000`` to
  every APDU. Useful for CI.

The runner itself lives in :mod:`Tools.ApduFuzz.runner`.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Sequence

from .corpus import Corpus, filter_select_only, load_corpus
from .mutators import MUTATORS
from .runner import FuzzerRunner
from .safety import FuzzerSafetyError, SafetyConfig, build_allow_set


_LOGGER = logging.getLogger(__name__)


class _NullTransport:
    """In-process fake transport that always returns 9000.

    Exists so CI / integration tests can exercise the CLI without a
    live reader. Every :func:`transmit` response is ``(b"", 0x9000)``.
    """

    def __init__(self, *, iccid: str, imsi: str) -> None:
        self._iccid = iccid
        self._imsi = imsi

    def probe_card_identity(self) -> tuple[str, str]:
        return self._iccid, self._imsi

    def transmit(self, _apdu: bytes) -> tuple[bytes, int]:
        return b"", 0x9000

    def close(self) -> None:
        return None


def _build_null_transport(args: argparse.Namespace) -> _NullTransport:
    iccid = str(args.null_iccid or "").strip()
    imsi = str(args.null_imsi or "").strip()
    if len(iccid) == 0 and len(imsi) == 0:
        iccid = "8900000000000000TEST"
    return _NullTransport(iccid=iccid, imsi=imsi)


def _build_pcsc_transport(args: argparse.Namespace):
    try:
        from smartcard.System import readers  # type: ignore[import-not-found]
        from smartcard.CardConnection import CardConnection  # type: ignore[import-not-found]
    except ImportError as error:
        raise SystemExit(
            "[-] PC/SC transport requires pyscard. Install with "
            "`pip install pyscard` and ensure pcscd is running. "
            f"Underlying error: {error}"
        )

    reader_hint = str(args.reader or "").strip().lower()
    available = list(readers())
    if len(available) == 0:
        raise SystemExit("[-] No PC/SC readers detected.")
    chosen = None
    for reader in available:
        if len(reader_hint) == 0 or reader_hint in str(reader).lower():
            chosen = reader
            break
    if chosen is None:
        raise SystemExit(
            f"[-] No PC/SC reader matches hint {reader_hint!r}. "
            f"Available: {[str(r) for r in available]}"
        )
    connection = chosen.createConnection()
    connection.connect(CardConnection.T0_protocol | CardConnection.T1_protocol)

    class _PcscTransport:
        def probe_card_identity(self) -> tuple[str, str]:
            # ICCID read is delegated; a full ETSI SELECT dance is
            # outside the scope of the fuzzer. The operator must supply
            # the identity through --probe-iccid / --probe-imsi when
            # the card is locked and cannot be queried.
            probe_iccid = str(args.probe_iccid or "").strip()
            probe_imsi = str(args.probe_imsi or "").strip()
            return probe_iccid, probe_imsi

        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            response, sw1, sw2 = connection.transmit(list(apdu))
            return bytes(response), (sw1 << 8) | sw2

        def close(self) -> None:
            try:
                connection.disconnect()
            except Exception as disconnect_error:
                _LOGGER.warning(
                    "pcsc disconnect raised: %s: %s",
                    disconnect_error.__class__.__name__,
                    disconnect_error,
                )

    return _PcscTransport()


def _parse_corpus(args: argparse.Namespace) -> Corpus:
    path = Path(args.corpus).expanduser().resolve()
    corpus = load_corpus(path)
    if args.select_only is True:
        return filter_select_only(corpus)
    return corpus


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-apdu-fuzzer",
        description=(
            "APDU mutation fuzzer. Replays a known-good corpus with "
            "random bit/length/tag mutations against a physical or "
            "fake-transport eUICC. Safety-gated: requires --i-mean-it "
            "plus an allow-list."
        ),
    )
    parser.add_argument(
        "--corpus",
        required=True,
        help="Path to a session-recorder JSON dump or a bare APDU list.",
    )
    parser.add_argument(
        "--seed",
        type=lambda s: int(str(s), 0),
        default=0xDEADBEEF,
        help="RNG seed (default 0xDEADBEEF). Integers may be decimal or hex.",
    )
    parser.add_argument(
        "--max-apdus",
        type=int,
        default=100,
        help="Upper bound on APDUs transmitted in this run (default 100).",
    )
    parser.add_argument(
        "--inter-command-delay",
        type=float,
        default=0.0,
        help="Sleep between commands in seconds (default 0).",
    )
    parser.add_argument(
        "--mutator",
        action="append",
        default=[],
        choices=sorted(MUTATORS.keys()),
        help="Enable a specific mutator. Repeat to enable several. Default: all.",
    )
    parser.add_argument(
        "--select-only",
        action="store_true",
        help="Restrict the corpus to SELECT (CLA=00 INS=A4) commands only.",
    )
    parser.add_argument("--i-mean-it", action="store_true", dest="i_mean_it")
    parser.add_argument(
        "--allow-iccid",
        action="append",
        default=[],
        help="Allow-list a card ICCID. Repeat for multiple.",
    )
    parser.add_argument(
        "--allow-imsi",
        action="append",
        default=[],
        help="Allow-list an IMSI. Repeat for multiple.",
    )
    parser.add_argument(
        "--workspace-root",
        default="",
        help="Workspace root used for crash-dump directory (default: cwd).",
    )
    parser.add_argument(
        "--crash-dump-root",
        default="",
        help="Override the crash-dump base directory.",
    )
    parser.add_argument(
        "--max-apdus-per-run",
        type=int,
        default=10_000,
        help="Safety cap on max APDUs per run (policy, default 10_000).",
    )
    parser.add_argument(
        "--transport",
        choices=["pcsc", "null"],
        default="null",
        help="Transport backend. 'null' is a fake that always returns 9000.",
    )
    parser.add_argument(
        "--reader",
        default="",
        help="PC/SC reader substring match (pcsc transport only).",
    )
    parser.add_argument(
        "--probe-iccid",
        default="",
        help="PC/SC only: skip the SELECT dance and declare the ICCID manually.",
    )
    parser.add_argument(
        "--probe-imsi",
        default="",
        help="PC/SC only: skip the SELECT dance and declare the IMSI manually.",
    )
    parser.add_argument(
        "--null-iccid",
        default="",
        help="Null transport only: fake ICCID to report on probe.",
    )
    parser.add_argument(
        "--null-imsi",
        default="",
        help="Null transport only: fake IMSI to report on probe.",
    )
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    workspace_root = (
        Path(args.workspace_root).expanduser().resolve()
        if len(str(args.workspace_root or "").strip()) > 0
        else Path.cwd().resolve()
    )
    crash_dump_root = (
        Path(args.crash_dump_root).expanduser().resolve()
        if len(str(args.crash_dump_root or "").strip()) > 0
        else None
    )
    config = SafetyConfig(
        workspace_root=workspace_root,
        i_mean_it=bool(args.i_mean_it),
        allowed_iccids=build_allow_set(args.allow_iccid),
        allowed_imsis=build_allow_set(args.allow_imsi),
        crash_dump_root=crash_dump_root,
        max_apdus_per_run=max(1, int(args.max_apdus_per_run)),
    )

    try:
        corpus = _parse_corpus(args)
    except FileNotFoundError as error:
        sys.stderr.write(f"[-] {error}\n")
        return 4
    except ValueError as error:
        sys.stderr.write(f"[-] corpus parse error: {error}\n")
        return 4

    if corpus.command_count == 0:
        sys.stderr.write("[-] corpus yielded zero commands. Nothing to fuzz.\n")
        return 4

    if args.transport == "pcsc":
        transport = _build_pcsc_transport(args)
    else:
        transport = _build_null_transport(args)

    enabled_mutators = tuple(args.mutator) if len(args.mutator) > 0 else None
    runner = FuzzerRunner(
        config=config,
        corpus=corpus,
        transport=transport,
        seed=int(args.seed),
        enabled_mutators=enabled_mutators,
        max_apdus=int(args.max_apdus),
        inter_command_delay_seconds=float(args.inter_command_delay),
    )

    try:
        stats = runner.execute()
    except FuzzerSafetyError as gate_error:
        sys.stderr.write(f"[-] safety gate refused the run: {gate_error}\n")
        return 5

    sys.stdout.write(
        f"[+] fuzzer run completed: sent={stats.sent} "
        f"crashes={stats.crashes} halt_reason={stats.halt_reason or 'ok'}\n"
    )
    for dump in stats.crash_records:
        sys.stdout.write(f"    crash-dump: {dump}\n")
    return 1 if stats.crashes > 0 else 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
