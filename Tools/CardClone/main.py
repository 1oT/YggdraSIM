# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""CLI for charting a card's behaviour into a reusable profile.

    yggdrasim-card-clone --transport pcsc --name acme-r3 --out profile.json
    yggdrasim-card-clone --transport sim --name self-check --dry-run

The probe is read-only. Every step is enumerated in
``Tools/CardClone/probe_plan.py`` with the behaviour it charts, and the
runner refuses to transmit anything the risk classifier does not call
read, so there is no flag that lets this write to a card.

The resulting profile pairs with a SAIP profile:

    yggdrasim --card-backend sim \\
        --sim-behaviour-profile acme-r3.json \\
        --sim-profile-store /path/to/saip/store
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from collections.abc import Sequence

from SIMCARD.behaviour_profile import BehaviourProfileError
from Tools.CardClone.clone import clone_card
from Tools.CardClone.probe_plan import PROBE_PLAN, UnsafeProbeStepError


def _pcsc_transport(reader_hint: str):
    try:
        from smartcard.CardConnection import CardConnection  # type: ignore[import-not-found]
        from smartcard.System import readers  # type: ignore[import-not-found]
    except ImportError as error:
        raise SystemExit(
            "[-] The pcsc transport needs pyscard: pip install pyscard "
            f"({error})"
        ) from error
    available = list(readers())
    if len(available) == 0:
        raise SystemExit("[-] No PC/SC readers detected.")
    hint = str(reader_hint or "").strip().lower()
    chosen = None
    for reader in available:
        if len(hint) == 0 or hint in str(reader).lower():
            chosen = reader
            break
    if chosen is None:
        raise SystemExit(
            f"[-] No reader matches {reader_hint!r}. Available: "
            f"{[str(item) for item in available]}"
        )
    connection = chosen.createConnection()
    connection.connect(CardConnection.T0_protocol | CardConnection.T1_protocol)

    class _Pcsc:
        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            data, sw1, sw2 = connection.transmit(list(apdu))
            return bytes(data), (int(sw1) << 8) | int(sw2)

        def atr_hex(self) -> str:
            try:
                return bytes(connection.getATR()).hex().upper()
            except Exception:  # noqa: BLE001 - ATR is a nicety, not required
                return ""

    return _Pcsc()


def _sim_transport():
    from SIMCARD.connection import get_shared_engine

    engine = get_shared_engine()

    class _Sim:
        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            data, sw1, sw2 = engine.transmit(bytes(apdu))
            return bytes(data), (int(sw1) << 8) | int(sw2)

        def atr_hex(self) -> str:
            return bytes(engine.state.atr).hex().upper()

    return _Sim()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-card-clone",
        description=(
            "Chart a card's behaviour into a profile the simulator can "
            "replay. Read-only: the probe plan is a fixed allow-list and "
            "nothing that changes a card can be sent."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=["pcsc", "sim"],
        default="pcsc",
        help="Where to probe. 'sim' charts the simulator against itself.",
    )
    parser.add_argument("--reader", default="", help="PC/SC reader substring match.")
    parser.add_argument("--name", default="", help="Name recorded in the profile.")
    parser.add_argument("--notes", default="", help="Free-text note for the profile.")
    parser.add_argument(
        "--source-card",
        default="",
        help="Model or part number of the charted card. Do not put an ICCID here.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Write the profile here. Omit to print the summary only.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Probe and report without writing a file.",
    )
    parser.add_argument(
        "--show-plan",
        action="store_true",
        help="Print the probe plan and exit without touching a card.",
    )

    control = parser.add_argument_group("profile control")
    control.add_argument(
        "--activate",
        default="",
        metavar="PATH",
        help="Switch the simulator onto this behaviour profile and exit.",
    )
    control.add_argument(
        "--deactivate",
        action="store_true",
        help="Drop the behaviour profile; the simulator returns to default.",
    )
    control.add_argument(
        "--deactivate-all",
        action="store_true",
        help=(
            "Turn off every personality override, both the quirks file and "
            "the behaviour profile, and return to the built-in card."
        ),
    )
    control.add_argument(
        "--status",
        action="store_true",
        help="Report which personality the simulator is running.",
    )
    control.add_argument(
        "--no-persist",
        action="store_true",
        help="Apply the change to this process only, without saving it.",
    )
    return parser


def _print_status() -> int:
    from SIMCARD.behaviour_profile import behaviour_profile_status

    state = behaviour_profile_status()
    print(f"behaviour profile : {state['behaviour_profile_path'] or '(none)'}")
    print(f"  source          : {state['behaviour_profile_source']}")
    print(f"  name            : {state['behaviour_profile_name'] or '(unnamed)'}")
    print(f"  overrides       : {state['behaviour_profile_overrides']}")
    if len(state["behaviour_profile_error"]) > 0:
        print(f"  error           : {state['behaviour_profile_error']}")
    print(f"quirks file       : {state['quirks_path'] or '(none)'}")
    print(f"  disabled        : {state['quirks_disabled']}")
    print(f"process kill sw   : {state['process_kill_switch']}")
    print(f"active            : {state['active']}")
    return 0


def _handle_control(args: argparse.Namespace) -> int | None:
    """Run a profile-control verb, or return None when none was requested."""
    from SIMCARD.behaviour_profile import (
        activate_behaviour_profile,
        deactivate_all_quirks,
        deactivate_behaviour_profile,
    )

    persist = not bool(args.no_persist)

    if args.deactivate_all:
        deactivate_all_quirks(persist=persist)
        print("all personality overrides off; simulator is back to default.")
        return _print_status()
    if args.deactivate:
        deactivate_behaviour_profile(persist=persist)
        print("behaviour profile off; simulator is back to default.")
        return _print_status()
    if len(str(args.activate or "").strip()) > 0:
        try:
            selected = activate_behaviour_profile(args.activate, persist=persist)
        except BehaviourProfileError as error:
            sys.stderr.write(f"[-] cannot activate: {error}\n")
            return 2
        print(f"activated {selected}")
        return _print_status()
    if args.status:
        return _print_status()
    return None


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Chart a card and write a behaviour profile."""
    args = _build_parser().parse_args(argv)

    if args.show_plan:
        print(f"{len(PROBE_PLAN)} probe steps, all read-only:\n")
        for step in PROBE_PLAN:
            print(f"  {step.step_id:<30} {step.apdu_hex:<44} {step.charts}")
        return 0

    control_result = _handle_control(args)
    if control_result is not None:
        return control_result

    transport = _sim_transport() if args.transport == "sim" else _pcsc_transport(args.reader)
    atr_hex = ""
    reader = getattr(transport, "atr_hex", None)
    if callable(reader):
        atr_hex = reader()

    try:
        report = clone_card(
            transport,
            name=args.name,
            notes=args.notes,
            atr_hex=atr_hex,
            source_card=args.source_card,
        )
    except UnsafeProbeStepError as error:
        sys.stderr.write(f"[-] refusing to probe: {error}\n")
        return 2

    print(report.summary())
    if report.transport_errors > 0:
        sys.stderr.write(
            f"[!] {report.transport_errors} step(s) failed to transmit; the "
            "profile may be incomplete.\n"
        )

    for override in report.profile.overrides.values():
        print(f"  {override.step_id:<30} {override.status_hex}  {override.charts}")

    if args.dry_run or len(str(args.out or "").strip()) == 0:
        return 0

    try:
        written = report.profile.write(Path(args.out))
    except (OSError, BehaviourProfileError) as error:
        sys.stderr.write(f"[-] cannot write the profile: {error}\n")
        return 3
    print(f"\nwrote {written}")
    print(
        "pair it with a SAIP profile:\n"
        f"  yggdrasim --card-backend sim --sim-behaviour-profile {written} "
        "--sim-profile-store <saip store>"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
