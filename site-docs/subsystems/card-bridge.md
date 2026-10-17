---
title: Card Bridge
tags:
  - subsystems
  - card-bridge
  - apdu
  - remote
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Card Bridge

`Tools/CardBridge/` publishes one PC/SC reader over HTTP so a card that sits
in a reader on one machine can be driven from another. The bridge process
owns the reader, the relay service in `Tools/HilBridge/apdu_relay.py` owns
the wire format, and every consumer -- the shells, the Universal GUI, the HIL
supervisor -- speaks the same `/apdu` endpoint.

!!! info "Authored guide"
    [`guides/CARD_BRIDGE_GUIDE.md`](../sources/guides/CARD_BRIDGE_GUIDE.md)
    carries the step-by-step workflow: topology, SSH tunnel, doctor
    preflight, audit records, and the troubleshooting table. This page is the
    subsystem map.

## When to use it

- the reader is attached to a workstation while the work happens on a lab
  host, or the reverse
- a Windows or macOS operator needs a card that lives on the Linux HIL host
- a HIL rig carries a modem but no reader, and must be fed a card over the
  network
- several people share a set of rigs -- then put [Remote Lab](remote-lab.md)
  in front of the bridge, which adds identity, inventory and exclusive
  sessions on top of this same data plane

## Entry points

| Form | Command |
| --- | --- |
| Installed command | `yggdrasim-card-bridge` |
| Module | `python -m Tools.CardBridge` |
| Launcher | `python main/main.py --card-bridge`, or `[CB]` in the menu |
| GUI | the **Card Bridge** view of the [Universal GUI](gui-command-center.md) |

Flags on the bridge process:

| Flag | Effect |
| --- | --- |
| `--host` | Bind interface, `127.0.0.1` by default. Any other address requires a token and is meant only for a TLS-terminating reverse proxy. |
| `--port` | TCP port, `8642` by default. |
| `--reader-index` | Index of the PC/SC reader to publish (`0` by default). |
| `--reader-name` | Substring match on the reader name; overrides `--reader-index`. |
| `--token-file` | Path to a `0600` file holding the bearer token. A missing file is created with a fresh token. Omitted, the bridge writes `${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token`. |
| `--no-token` | Run unauthenticated. Loopback bind only -- the bridge refuses to start otherwise. |
| `--audit` | One structured audit record per exchange: header bytes and status word, never the data payload. |
| `--audit-full-apdu` | Also logs full APDU and response hex. PIN material rides through here; forensic work on test cards only. Implies `--audit`. |
| `--audit-logger-name` | Python logger that receives the audit records. |
| `--apdu-timeout-ms` | Maximum PC/SC wait per APDU. |
| `--pcsc-share-mode` | `shared` by default, so a GUI reader probe does not block startup; `exclusive` when no other local process may touch the reader. |

## HTTP surface

The paths come from `Tools/HilBridge/apdu_relay.py` and are identical whether
the bridge is reached directly, through an SSH forward, or through a Remote
Lab session relay.

| Path | Purpose |
| --- | --- |
| `/apdu` | The data plane: one request carries one APDU, the response carries the data and the status word. |
| `/ping` | Liveness. Answers `pong`. |
| `/status` | Reader name, card presence, ATR, and the lease holder when one exists. |
| `/card/reset` | Power-cycles the card in the published reader. |
| `/lease` | Take, renew or drop the exclusive hold a consumer has on the card. |

## Authentication

The bridge is bearer-token gated. `yggdrasim_common/card_bridge_auth.py`
generates a 32-byte URL-safe token; the token file stays `0600` and the
process never logs more than a six-character fingerprint. A peer that fails
authentication three times inside 30 s is locked out for 60 s.

Binding a non-loopback address without a token is refused outright. There is
no override flag: either keep the SSH-tunnel topology or supply a token and
terminate TLS in front of the bridge.

## Consumers

A YggdraSIM shell, the GUI or the HIL supervisor becomes a Card Bridge
consumer through the shared arguments in
`yggdrasim_common/remote_card_args.py`:

| Argument | Environment variable |
| --- | --- |
| `--remote-card-url` | `YGGDRASIM_CARD_RELAY_URL` |
| `--remote-card-token-file` | `YGGDRASIM_CARD_RELAY_TOKEN_FILE` |
| (token value) | `YGGDRASIM_CARD_RELAY_TOKEN` |
| `--remote-card-lease-file` | -- |
| `--remote-card-restart-backoff` | -- |

Prefer the token file over the raw value: a token passed on the command line
is visible in `ps` output.

## GUI surfaces

The **Card Bridge** view drives both a local bridge and a remote one. Its
actions are registered in `yggdrasim_common/gui_server/actions/card_bridge.py`:

| Action | What it does |
| --- | --- |
| Status, Probe bridge | Read the local bridge state; probe a URL and token pair. |
| Generate token, Configuration | Mint a token file; edit the stored bridge settings. |
| Start local bridge, Stop local bridge | Run the bridge on this host against a chosen reader. |
| Remote rig status | Report the saved remote host, its service, tunnel and lease holder. |
| Start remote HIL rig, Stop remote HIL rig | Bring a saved remote rig up or down, tunnel included. |
| Start RPi tunnel, Stop RPi tunnel | Manage only the SSH forward to the saved host. |
| Sync token to RPi | Copy the bridge token to the remote host. |
| Install RPi HIL service, Control RPi HIL service | Install and drive the `systemd --user` unit on the remote host. |

The remote-rig actions are what the GUI calls **Remote Bridge**: one stored
host, onboarded once, then started and stopped from the same panel. A host
with no SSH target is recorded as a gap to fill rather than rejected, so the
inventory can be written before the access is in place.

## Run it as a service

`guides/systemd/yggdrasim-card-bridge.service.example` is a `systemd --user`
unit for a reader host that should publish its card on boot. Install it on
the reader machine, not on the consumer.

## Pitfalls

- Re-enumerating the reader (a USB reseat, a `pcscd` restart) invalidates the
  handle the bridge holds, and nothing notices. `/status` answers from the
  reader label and ATR captured when the process connected, and defaults its
  `status` to `ok`, so it still reads healthy; `/card/reset` drives the same
  dead channel. Restart the bridge process.
- `--audit-full-apdu` captures PINs and key material in cleartext.
- An SSH forward dies with its session. Set `ServerAliveInterval` and
  `ServerAliveCountMax` in `~/.ssh/config` for a long-running rig link.
- The bridge publishes one reader. Two cards on one host means two bridge
  processes on two ports.

## Related pages

- [Card Bridge over SSH](../how-to/remote-apdu-streaming.md) -- the task guide
- [Remote Lab](remote-lab.md) -- identity, inventory and sessions over this bridge
- [HIL Bridge](hil-bridge.md) -- the remote-card consumer on a rig
- [Install RemSIM / APDU Streaming](../how-to/install-remsim-apdu-streaming.md)
- [Universal GUI Command Center](gui-command-center.md)
- [`guides/CARD_BRIDGE_GUIDE.md`](../sources/guides/CARD_BRIDGE_GUIDE.md) -- the authored operator guide
