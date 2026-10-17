#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Open a Remote Lab agent to a trusted network. Run ON THE RIG HOST.

Takes the agent's control port and every rig stream proxy off loopback so
peers on a VPN (or a routed internal LAN) can reach them, and pins
``public_host`` so the stream URL the agent advertises is one callers can
actually resolve.

Use this for a rig that is meant to serve everyone holding an access token
and the shared device configuration. The bearer token stays the access
control and the private network is the transport; see "Reach the agent" in
``site-docs/how-to/run-a-remote-lab-agent.md``. A single-operator rig should
stay on loopback behind an SSH tunnel instead.

``public_host`` is the point of this script as much as the bind is. The agent
resolves each rig's advertised stream URL from ``stream_proxy.public_host``,
then ``agent.public_host``, then the request's ``Host`` header, then
``bind_host`` -- rewriting ``0.0.0.0`` to ``127.0.0.1`` on the way. Binding
wide without setting it leaves control calls working while every caller is
handed a loopback stream URL: sessions open and APDUs go nowhere.

Safe by construction: backs the config up, validates the result with the
agent's own loader BEFORE touching the service, and restores the backup if
validation fails. Idempotent -- re-running changes nothing.

    python3 scripts/remote_lab_open_agent_to_vpn.py --dry-run
    python3 scripts/remote_lab_open_agent_to_vpn.py --public-host rig.internal.example
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_CONFIG = "~/.config/yggdrasim/remote-lab.yaml"
DEFAULT_UNIT = "yggdrasim-lab-agent.service"
LOOPBACK = {"127.0.0.1", "0.0.0.0", "::", "::1", "localhost", ""}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--unit", default=DEFAULT_UNIT)
    parser.add_argument(
        "--public-host",
        default="",
        help=(
            "host callers should use; defaults to this machine's FQDN. "
            "Pass 'auto' to leave it unset, which makes the agent answer "
            "each caller with the address that caller used -- the right "
            "choice for a rig reachable by more than one route."
        ),
    )
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="write and validate the config but leave the service alone",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        import yaml
    except ImportError:
        print("! PyYAML missing -- run this with the agent's interpreter", file=sys.stderr)
        return 2

    # "auto" clears the field rather than pinning a name. The agent then
    # falls back to the request's Host header, so a rig reachable over the
    # VPN and over the LAN advertises a working stream URL on both instead
    # of one name that is only right from one side.
    requested_public_host = args.public_host.strip()
    echo_caller_host = requested_public_host.casefold() == "auto"
    public_host = "" if echo_caller_host else (requested_public_host or socket.getfqdn())
    if echo_caller_host is False and (
        public_host in LOOPBACK or "." not in public_host
    ):
        print(
            f"! refusing public_host {public_host!r}: callers could not resolve it.\n"
            "  Pass --public-host with the name this rig answers to on the VPN.",
            file=sys.stderr,
        )
        return 2

    cfg = Path(args.config).expanduser()
    if not cfg.is_file():
        print(f"! config not found: {cfg}", file=sys.stderr)
        return 2

    payload = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        print("! config root must be a mapping", file=sys.stderr)
        return 2

    agent = payload.setdefault("agent", {})
    was = (agent.get("bind_host"), agent.get("public_host"))
    agent["bind_host"] = args.bind_host
    if echo_caller_host is True:
        agent.pop("public_host", None)
    else:
        agent["public_host"] = public_host
    print(f"agent.bind_host  : {was[0]!r} -> {agent['bind_host']!r}")
    print(
        f"agent.public_host: {was[1]!r} -> "
        + ("<unset, echoes the caller>" if echo_caller_host else repr(public_host))
    )

    for rig in payload.get("rigs") or []:
        if not isinstance(rig, dict):
            continue
        rig_id = rig.get("id", "?")
        proxy = rig.setdefault("stream_proxy", {})
        was = (proxy.get("bind_host"), proxy.get("public_host"))
        proxy["bind_host"] = args.bind_host
        if echo_caller_host is True:
            proxy.pop("public_host", None)
        else:
            proxy["public_host"] = public_host
        print(f"rig {rig_id}: stream_proxy.bind_host   {was[0]!r} -> {proxy['bind_host']!r}")
        print(
            f"rig {rig_id}: stream_proxy.public_host {was[1]!r} -> "
            + ("<unset, echoes the caller>" if echo_caller_host else repr(public_host))
        )
        # The card-bridge upstream deliberately stays on loopback: only the
        # agent talks to it and it runs on this same host.
        upstream = rig.get("upstream")
        if isinstance(upstream, dict) and upstream.get("url"):
            print(f"rig {rig_id}: upstream unchanged -> {upstream['url']!r}")

    rendered = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)

    if args.dry_run:
        print("\n--- resulting config (not written) ---")
        print(rendered)
        return 0

    backup = cfg.with_suffix(f".yaml.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(cfg, backup)
    print(f"\nbackup: {backup}")
    cfg.write_text(rendered, encoding="utf-8")

    try:
        from yggdrasim_common.remote_lab.config import load_config

        config = load_config(cfg)
    except Exception as exc:  # noqa: BLE001 -- any load failure must roll back
        shutil.copy2(backup, cfg)
        print(
            f"! config rejected ({type(exc).__name__}: {exc}) -- restored {backup}",
            file=sys.stderr,
        )
        return 1

    print(
        f"validated: agent {config.agent.id} on "
        f"{config.agent.bind_host}:{config.agent.control_port}, {len(config.rigs)} rig(s)"
    )

    if args.no_restart:
        print(f"--no-restart: restart {args.unit} yourself to apply")
        return 0

    restart = subprocess.run(
        ["systemctl", "--user", "restart", args.unit],
        capture_output=True,
        text=True,
    )
    if restart.returncode != 0:
        print(f"! restart failed: {restart.stderr.strip()}", file=sys.stderr)
        print(f"  config is valid and in place; backup at {backup}", file=sys.stderr)
        return 1

    time.sleep(2)
    state = subprocess.run(
        ["systemctl", "--user", "is-active", args.unit],
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"{args.unit}: {state}")

    listening = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    ports = [config.agent.control_port]
    ports.extend(rig.stream_proxy.external_port for rig in config.rigs)
    for port in ports:
        if not port:
            continue
        rows = [line for line in listening.splitlines() if f":{port} " in line]
        wide = any(("0.0.0.0" in r or "*:" in r or "[::]" in r) for r in rows)
        if not rows:
            print(f"port {port}: no listener")
        else:
            print(f"port {port}: {'open to the network' if wide else 'still loopback-only'}")

    return 0 if state == "active" else 1


if __name__ == "__main__":
    raise SystemExit(main())
