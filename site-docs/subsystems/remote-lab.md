---
title: Remote Lab
tags:
  - subsystems
  - remote-lab
  - card-bridge
  - apdu
  - remote
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Remote Lab

`yggdrasim_common/remote_lab/` turns a set of card rigs into a shared
resource. An agent publishes what exists, hands out exclusive sessions, and
fronts each rig with a session relay; operators discover rigs and reserve them
from the CLI or the GUI without ever holding a rig's own Card Bridge token.

The data plane does not change. [Card Bridge](card-bridge.md) still carries
the APDUs; the agent adds identity, inventory, status and locking in front of
it.

```text
operator  --control-->  lab agent      (who exists, may I have it)
operator  --stream--->  session relay  -->  Card Bridge  -->  reader
```

## When to use it

- several people share a set of rigs and need to know who holds what
- a rig should be reachable without distributing the bridge token that grants
  unrestricted access to its card
- a modem rig has no card of its own and an operator wants to feed it one
- a session must expire on its own when the holder's workstation disappears

For a single operator with a single reader, plain [Card Bridge over
SSH](../how-to/remote-apdu-streaming.md) is less machinery.

## Module map

| Module | Responsibility |
| --- | --- |
| `agent.py` | The published process: control API plus one session relay per rig. |
| `config.py` | YAML parsing and validation for agent, rigs, tokens and defaults. |
| `sessions.py` | In-memory lock and session manager: reservation, heartbeat, expiry. |
| `security.py` | Bearer-token hashing and comparison for control and session APIs. |
| `registry.py` | The operator-side invite and device registry the GUI reads. |
| `consumer.py` | The HIL supervisor bound to one reserved modem rig. |
| `client.py` | HTTP client helpers used by the CLI and the GUI routes. |
| `cli.py` | The `yggdrasim-lab` verbs. |

## Two kinds of rig

A rig declares its `kind` in the agent config; absent, it is a card rig.

| Kind | Holds | A session means |
| --- | --- | --- |
| `card` | A reader with a card in it, published through Card Bridge. | The rig streams its card to you. |
| `modem` | A modem and a SIMtrace2, no card of its own. | You offer a card from your own Card Bridge and the rig consumes it. |

A modem rig spawns `yggdrasim-hil-supervisor` on reservation. The executable
and every flag that is not derived from the offer come from rig config, never
from the request.

## Sessions and leases

| Default | Value | Meaning |
| --- | --- | --- |
| `reservation_timeout_seconds` | 30 | How long a reservation attempt waits for the rig to come free. |
| `heartbeat_timeout_seconds` | 60 | A session with no heartbeat inside this window is reclaimed. |
| `max_session_seconds` | 14400 | Hard ceiling on one session, four hours. |

A session carries its own token, separate from the access token used to
reserve it. Releasing is explicit; `force-release` exists for a rig whose
holder has gone away and requires a token with the `admin` role.

## Entry points

| Form | Command |
| --- | --- |
| Agent | `yggdrasim-lab-agent` |
| Operator CLI | `yggdrasim-lab rigs \| status \| reserve \| release \| heartbeat` |
| GUI | the **Remote Lab** view of the [Universal GUI](gui-command-center.md) |

The CLI and the GUI cover the same capability, so a rig is usable from either
surface. `yggdrasim-lab` takes `--agent` (control base URL) and a token, by
value or from a file.

## Control API

The agent answers on its control port, `8700` by default, bound to loopback
unless the config says otherwise.

| Path | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. |
| `GET /api/v1/info` | Agent identity and defaults. |
| `GET /api/v1/rigs` | The published inventory. |
| `GET /api/v1/rigs/{rig}/status` | One rig: presence, card state, current holder. |
| `POST /api/v1/rigs/{rig}/sessions` | Reserve the rig; answers with the session and its relay URL. |
| `POST /api/v1/sessions/{session}/heartbeat` | Keep a session alive. |
| `DELETE /api/v1/sessions/{session}` | Release. |
| `POST /api/v1/rigs/{rig}/force-release` | Admin override for an abandoned session. |

Each rig also carries a session relay that speaks the Card Bridge paths
(`/ping`, `/status`, `/apdu`). Its bind host and external port come from the
rig's `stream_proxy` block; port `0` takes an ephemeral one. A rig can be told
to answer each caller with an address that caller can reach, so one agent
serves both a VPN peer and an SSH-forwarded operator.

The [Run a Remote Lab Agent](../how-to/run-a-remote-lab-agent.md) how-to
carries the request and response bodies.

## GUI surface

`yggdrasim_common/gui_server/routes/remote_lab.py` mounts `/api/remote-lab`.
The view lists devices, opens a link to one, and keeps the session alive while
the link is open:

| Route | Purpose |
| --- | --- |
| `GET /devices`, `POST /devices/{id}/update`, `DELETE /devices/{id}` | The local device registry. |
| `POST /import`, `GET /devices/{id}/export` | Invite exchange. |
| `POST /hosts` | Record a host, including one that has no SSH target yet. |
| `GET /status`, `GET /devices/{id}/status`, `GET /sessions` | What is reachable and who holds it. |
| `POST /devices/{id}/connect` | Reserve and open the link. |
| `POST /devices/{id}/offer-card` | Hand a modem rig a card from this host's Card Bridge. |
| `POST /devices/{id}/release`, `POST /devices/{id}/force-release` | Give the rig back. |

An invite is the JSON an agent owner hands an operator: it names the agent and
the rig and carries an access token. A single invite, an array, or a bundle
imports the same way. The SSH half of a host entry is never part of an invite.

## Configuration

The agent reads a YAML file. The security block stores only SHA-256 hashes of
access tokens, never the token itself; mint a pair with
`yggdrasim_common.card_bridge_auth.generate_token` and
`yggdrasim_common.remote_lab.security.hash_token`. Each token carries an `id`
and a role of `user` or `admin`.

`guides/systemd/yggdrasim-lab-agent.service.example` is a `systemd --user`
unit for an agent host.

## Pitfalls

- A remote rig's reader name does not resolve on the operator's machine.
  Judge a rig by its agent-reported status -- free, busy, reserved -- not by a
  local PC/SC probe, which cannot see it.
- The agent binds loopback by default. Treat a non-loopback bind exactly like
  exposing Card Bridge itself: a private network path or an SSH forward.
- An operator who stops sending heartbeats loses the rig after the heartbeat
  timeout. That is the point; it is what stops an abandoned session from
  holding a rig for four hours.
- The agent adds no confidentiality of its own. Tokens and APDUs ride the
  transport you give it.

## Related pages

- [Run a Remote Lab Agent](../how-to/run-a-remote-lab-agent.md) -- the task guide
- [Card Bridge](card-bridge.md) -- the data plane underneath
- [HIL Bridge](hil-bridge.md) -- what a modem rig runs once it has a card
- [Universal GUI Command Center](gui-command-center.md)
- [Card Bridge over SSH](../how-to/remote-apdu-streaming.md)
