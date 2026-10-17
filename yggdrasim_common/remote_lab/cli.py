# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Operator-side Remote Lab commands: list rigs, reserve one, release it.

The GUI reaches an agent through ``/api/remote-lab``; this is the same
capability on a terminal, so a rig is usable from either surface. It
covers both rig kinds. A card rig is reserved and streamed from; a modem
rig is reserved and fed a card from the operator's own Card Bridge.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .client import RemoteLabAgentClient, RemoteLabClientError
from .consumer import CardOffer, CardOfferError

DEFAULT_TIMEOUT_SECONDS = 10.0


def _read_token(raw_token: str, token_file: str) -> str:
    token = str(raw_token or "").strip()
    if len(token) > 0:
        return token
    path = str(token_file or "").strip()
    if len(path) == 0:
        return ""
    try:
        return Path(path).expanduser().read_text(encoding="utf-8").strip()
    except OSError as read_error:
        raise SystemExit(f"Cannot read token file {path}: {read_error}")


def _client(args: argparse.Namespace) -> RemoteLabAgentClient:
    token = _read_token(
        getattr(args, "token", ""), getattr(args, "token_file", "")
    )
    if len(token) == 0:
        raise SystemExit(
            "An access token is required. Pass --token or --token-file."
        )
    return RemoteLabAgentClient(
        str(args.agent).rstrip("/"),
        token,
        timeout_seconds=float(getattr(args, "timeout", DEFAULT_TIMEOUT_SECONDS)),
    )


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _print_rig_table(rigs: list[dict[str, Any]]) -> None:
    if len(rigs) == 0:
        print("No rigs published by this agent.")
        return
    width = max(len(str(rig.get("id", ""))) for rig in rigs)
    for rig in rigs:
        kind = str(rig.get("kind") or "card")
        needs = " needs a card offer" if rig.get("requires_card_offer") else ""
        print(
            f"{str(rig.get('id', '')):<{width}}  "
            f"{kind:<5}  {str(rig.get('status', '')):<12}  "
            f"{str(rig.get('name', ''))}{needs}"
        )


def _card_offer(args: argparse.Namespace) -> dict[str, Any] | None:
    url = str(getattr(args, "offer_card_url", "") or "").strip()
    if len(url) == 0:
        return None
    token = _read_token(
        getattr(args, "offer_card_token", ""),
        getattr(args, "offer_card_token_file", ""),
    )
    try:
        offer = CardOffer.from_payload({"url": url, "token": token})
    except CardOfferError as offer_error:
        raise SystemExit(str(offer_error)) from offer_error
    return {"url": offer.url, "token": offer.token}


def _cmd_rigs(args: argparse.Namespace) -> int:
    payload = _client(args).rigs()
    rigs = payload.get("rigs")
    if isinstance(rigs, list) and bool(getattr(args, "json_output", False)) is False:
        _print_rig_table([rig for rig in rigs if isinstance(rig, dict)])
        return 0
    _emit(payload)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    _emit(_client(args).status(args.rig))
    return 0


def _cmd_reserve(args: argparse.Namespace) -> int:
    grant = _client(args).create_session(
        args.rig,
        user=str(getattr(args, "user", "") or ""),
        client_id=str(getattr(args, "client_id", "") or ""),
        requested_ttl_seconds=int(getattr(args, "ttl", 3600)),
        card_offer=_card_offer(args),
    )
    _emit(grant)
    return 0


def _cmd_release(args: argparse.Namespace) -> int:
    _emit(_client(args).release(args.session, args.session_token))
    return 0


def _cmd_heartbeat(args: argparse.Namespace) -> int:
    _emit(_client(args).heartbeat(args.session, args.session_token))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-lab",
        description=(
            "Talk to a YggdraSIM Remote Lab agent: list rigs, reserve one, "
            "release it. A modem rig is reserved with --offer-card-url."
        ),
    )
    parser.add_argument(
        "--agent",
        required=True,
        help="Agent control base URL, for example http://rig.example.test:8700",
    )
    parser.add_argument("--token", default="", help="Access token value.")
    parser.add_argument(
        "--token-file", default="", help="File holding the access token."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Control request timeout in seconds.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    rigs = subparsers.add_parser("rigs", help="List the rigs this agent publishes.")
    rigs.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print the raw response instead of a table.",
    )
    rigs.set_defaults(handler=_cmd_rigs)

    status = subparsers.add_parser("status", help="Show one rig's status.")
    status.add_argument("rig")
    status.set_defaults(handler=_cmd_status)

    reserve = subparsers.add_parser("reserve", help="Take a session on a rig.")
    reserve.add_argument("rig")
    reserve.add_argument("--user", default="", help="Who is taking the rig.")
    reserve.add_argument("--client-id", default="", help="Caller identity.")
    reserve.add_argument(
        "--ttl", type=int, default=3600, help="Requested session seconds."
    )
    reserve.add_argument(
        "--offer-card-url",
        default="",
        help=(
            "Card Bridge /apdu URL the rig should consume. Required for a "
            "modem rig, which holds no card of its own. The rig must be "
            "able to reach it, so open a reverse tunnel first unless the "
            "bridge is published on a routable address."
        ),
    )
    reserve.add_argument(
        "--offer-card-token", default="", help="Bearer token for the offered card."
    )
    reserve.add_argument(
        "--offer-card-token-file",
        default="",
        help="File holding the offered card's bearer token.",
    )
    reserve.set_defaults(handler=_cmd_reserve)

    release = subparsers.add_parser("release", help="Give a session back.")
    release.add_argument("session")
    release.add_argument("session_token")
    release.set_defaults(handler=_cmd_release)

    heartbeat = subparsers.add_parser("heartbeat", help="Keep a session alive.")
    heartbeat.add_argument("session")
    heartbeat.add_argument("session_token")
    heartbeat.set_defaults(handler=_cmd_heartbeat)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except RemoteLabClientError as client_error:
        message = ""
        if isinstance(client_error.payload, dict):
            message = str(
                client_error.payload.get("message")
                or client_error.payload.get("error")
                or ""
            ).strip()
        print(
            f"Agent refused the request (HTTP {client_error.status}): "
            f"{message or client_error}",
            file=sys.stderr,
        )
        return 1


def run_standalone() -> int:
    return main()
