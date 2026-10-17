---
title: Run a Remote Lab Agent
tags:
  - how-to
  - apdu
  - remote
  - card-bridge
  - remote-lab
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Run a Remote Lab Agent

## Goal

Publish one or more card rigs to a team, so an operator can discover what
exists, take exclusive hold of a rig for the length of a session, and stream
APDUs to it -- without every user needing the rig's own Card Bridge token.

The agent does not replace [Card Bridge over SSH](remote-apdu-streaming.md).
It sits in front of it: the data plane is still the Card Bridge HTTP `/apdu`
relay, and the agent adds identity, rig inventory, status, and exclusive
session locking on top.

```text
operator  --control-->  Lab agent :8700        (who exists, may I have it)
operator  --stream--->  rig proxy :8801  -->  Card Bridge :8642  -->  reader
```

Use this when several people share a set of rigs. For a single operator and a
single reader, plain Card Bridge over SSH is less machinery.

## Prerequisites

- YggdraSIM installed on the agent host (`yggdrasim-lab-agent` ships with the
  base install; the YAML parser is a base dependency)
- one reachable Card Bridge `/apdu` endpoint per rig, already working per
  [Card Bridge over SSH](remote-apdu-streaming.md)
- a private network path, or SSH forwards, between operators and the agent

The agent binds loopback by default. Treat a non-loopback bind the same way
you would treat exposing Card Bridge itself: see [Security rules](#security-rules).

## Mint access tokens

The config stores only SHA-256 hashes, never the token itself. Generate a
pair with the shipped helpers:

```bash
python -c "
from yggdrasim_common.card_bridge_auth import generate_token
from yggdrasim_common.remote_lab.security import hash_token
token = generate_token()
print('token      :', token)
print('token_hash :', hash_token(token))
"
```

Give the `token` to the operator and put the `token_hash` in the config. A
`role: admin` token additionally permits `force-release`.

## Two kinds of rig

A rig declares what it offers, and that decides which way APDUs travel.

| Kind | Holds the card | Holds a modem | The operator |
| --- | --- | --- | --- |
| `card` | the rig | no | streams APDUs to the rig |
| `modem` | the operator | yes, plus a SIMtrace2 | offers a card for the rig to drive |

A **card rig** is the original shape and stays the default: leave `kind`
out and nothing changes. A **modem rig** reverses the direction. It has
no card of its own, so a reservation must carry a card offer naming a
Card Bridge the rig can reach, and the rig runs a HIL supervisor against
it for the length of the session.

A host that carries both a reader and a modem publishes two rigs sharing
one lock name, so taking either takes the bench.

## Write the config

```yaml
agent:
  id: lab-01
  name: Bench lab
  bind_host: 127.0.0.1
  control_port: 8700

defaults:
  reservation_timeout_seconds: 30
  heartbeat_timeout_seconds: 60
  max_session_seconds: 14400

security:
  access_tokens:
    - id: alice
      token_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      role: user
    - id: lab-admin
      token_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      role: admin

rigs:
  - id: bench-a
    name: Bench A
    location: TestLocality
    tags: [pcsc, esim]
    capabilities: [scp03, scp11]
    enabled: true
    stream_proxy:
      bind_host: 127.0.0.1
      external_port: 8801
    upstream:
      url: http://127.0.0.1:8642/apdu
      token_file: ~/.config/yggdrasim/card_bridge/8642.token
```

Field notes, all enforced by the loader:

| Key | Required | Behaviour |
| --- | --- | --- |
| `agent.id` | yes | rejected when empty |
| `agent.bind_host` | no | defaults to `127.0.0.1` |
| `agent.control_port` | no | defaults to `8700` |
| `agent.public_host` | no | the host callers are told to use. Not enforced anywhere: left unset, the agent answers each caller with the address that caller used, which is the right setting for a rig reachable by more than one route |
| `defaults.*` | no | `30` / `60` / `14400` seconds; floored at 1 |
| `security.access_tokens` | yes | at least one entry; `token_hash` must start with `sha256:`; `role` is `user` or `admin` |
| `rigs[].id` | yes | must be unique, compared case-insensitively |
| `rigs[].stream_proxy.external_port` | yes | rejected when it collides with another rig or with `agent.control_port` on an overlapping bind |
| `rigs[].stream_proxy.bind_host` | no | defaults to `127.0.0.1` |
| `rigs[].stream_proxy.public_host` | no | overrides `agent.public_host` for this rig's stream URL; falls back to the `Host` header, then `bind_host`, with `0.0.0.0` rewritten to `127.0.0.1` |
| `rigs[].upstream` | yes | either `url`, or `host` + `port` (+ optional `scheme`); `/apdu` is appended when missing |
| `rigs[].locks` | no | defaults to `rig:<id>`; give two rigs a shared lock name when they cannot run at once |
| `rigs[].enabled` | no | defaults to `true` |
| `rigs[].kind` | no | `card` or `modem`; defaults to `card`, so a config written before modem rigs existed is unchanged |
| `rigs[].modem.label` | no | what an operator sees in the inventory; defaults to the rig name |
| `rigs[].modem.simtrace_vidpid` | no | defaults to `1d50:60e3` |
| `rigs[].consumer.enabled` | no | defaults to `false`; must be `true` before a reservation may start a supervisor on this host |
| `rigs[].consumer.supervisor` | no | defaults to `yggdrasim-hil-supervisor`; the only executable a reservation can start |
| `rigs[].consumer.simtrace_reset` | no | `off`, `usb-reset`, `port-power` or `auto`; defaults to `usb-reset` |
| `rigs[].consumer.bridge_host` / `.bridge_port` | no | where the rig-side HIL bridge listens; `127.0.0.1` and `9997` |
| `rigs[].consumer.apdu_timeout_ms` | no | defaults to `30000`, which suits a card reached across a tunnel |

On a modem rig `stream_proxy` and `upstream` are both omitted: the rig
serves no card, so it binds no listener and has no upstream to name.
Declaring an `upstream` on a modem rig, or a `modem` or `consumer` block
on a card rig, is rejected rather than ignored.

```yaml
rigs:
  - id: quectel-a
    name: Quectel bench
    kind: modem
    location: TestLocality
    modem:
      label: Quectel EC25-E
      simtrace_vidpid: 1d50:60e3
    consumer:
      enabled: true
      simtrace_reset: usb-reset
    locks: [bench:pi-1]
```

`upstream.url` must be `http(s)` with no credentials, query, or fragment.
Use `upstream.token_file` rather than inline `token` so the Card Bridge
bearer stays in a `0600` file.

## Start the agent

```bash
yggdrasim-lab-agent --config ~/.config/yggdrasim/remote-lab.yaml
```

`--log-level DEBUG` raises verbosity. A malformed config fails at startup
with the offending key path, so a typo never produces a half-open agent.

## Run it as a service

An unattended rig host runs the agent and its Card Bridge as `systemd --user`
units. Two examples ship beside the HIL one:

```bash
mkdir -p ~/.config/systemd/user
cp guides/systemd/yggdrasim-card-bridge.service.example \
  ~/.config/systemd/user/yggdrasim-card-bridge.service
cp guides/systemd/yggdrasim-lab-agent.service.example \
  ~/.config/systemd/user/yggdrasim-lab-agent.service

systemctl --user daemon-reload
systemctl --user enable --now yggdrasim-card-bridge.service yggdrasim-lab-agent.service
loginctl enable-linger "$USER"
```

`enable-linger` is what makes the units start at boot without a login.

**Never order a unit after `default.target` when that target already wants
it.** The agent is ordered after the Card Bridge, and both are
`WantedBy=default.target`; adding `After=default.target` to either one closes
a cycle, and systemd resolves a cycle by deleting one of the start jobs. The
result is a unit that silently never starts at boot while `systemctl status`
afterwards reports nothing worse than `inactive (dead)`.

`systemctl --user enable --now` does not catch this, because starting a unit
by hand never runs the boot transaction. Rehearse the boot path instead:

```bash
systemctl --user stop yggdrasim-lab-agent.service yggdrasim-card-bridge.service
systemctl --user start default.target
systemctl --user is-active yggdrasim-card-bridge.service yggdrasim-lab-agent.service
journalctl --user -b | grep -i "ordering cycle"
```

Both units should report `active` and the grep should find nothing.

## Reach the agent

Pick one of two shapes. They differ in who the rig is meant to serve, not in
how callers authenticate -- an access token is required either way.

### Pin a name, or echo the caller

A rig's advertised stream URL comes from `stream_proxy.public_host`, then
`agent.public_host`, then the request's `Host` header, then the bind
address. Only the last is rewritten, `0.0.0.0` becoming `127.0.0.1`.

Pinning a name is right for a rig that answers to exactly one. Leaving
both unset is right for a rig reachable more than one way, because the
agent then hands each caller back the address that caller reached it on:

```text
called as esim-rig.example.test  ->  http://esim-rig.example.test:8801/apdu
called as 10.73.184.89           ->  http://10.73.184.89:8801/apdu
```

That matters when a host is reachable over a VPN and over a LAN, or when
it later becomes a VPN peer in its own right. A pinned name that resolves
to an address the caller cannot route is the worst of both: the control
port answers, every stream URL points somewhere unreachable, sessions
open and APDUs go nowhere.

`scripts/remote_lab_open_agent_to_vpn.py --public-host auto` leaves the
field unset for you; passing a name pins it as before.

### A shared rig on a VPN

When a rig is meant to serve everyone who holds a token and the device config,
put it on the VPN the team already runs (NetBird, Tailscale, WireGuard, a
routed office LAN) and bind the agent to a real interface:

```yaml
agent:
  bind_host: 0.0.0.0
  public_host: rig-host.internal.example    # resolvable BY CALLERS

rigs:
  - id: bench-a
    stream_proxy:
      bind_host: 0.0.0.0
      public_host: rig-host.internal.example
```

`public_host` is not optional here. The agent advertises a stream URL for each
rig, and it derives the host from `stream_proxy.public_host`, then
`agent.public_host`, then the request's `Host` header, then `bind_host` --
rewriting `0.0.0.0` to `127.0.0.1` on the way. Leave it unset and control calls
succeed while every caller is handed a loopback stream URL it cannot reach, so
sessions open and APDUs go nowhere.

Point the device registry at the same name rather than at `127.0.0.1`, and
prefer the DNS name over an address so a DHCP lease change does not strand it.

The rig's card-bridge upstream stays on loopback: only the agent talks to it,
and it runs on the same host.

`scripts/remote_lab_open_agent_to_vpn.py` makes both edits on the rig host. It
backs the config up, validates it with the agent's own loader before touching
the service, and restores the backup if that fails:

```bash
python3 scripts/remote_lab_open_agent_to_vpn.py --dry-run
python3 scripts/remote_lab_open_agent_to_vpn.py --public-host rig-host.internal.example
```

From an operator machine, `scripts/remote_lab_verify_over_vpn.sh` checks the
whole path and separates a network problem from a bind problem -- the two
failures the GUI renders identically. It is read-only and never prints the
token:

```bash
scripts/remote_lab_verify_over_vpn.sh rig-host.internal.example path/to/device.token
```

### A single-operator rig over SSH

When the rig serves one person, keep it loopback-bound and forward the control
port and every rig's stream port. Let SSH notice a dead peer rather than hang
on one:

```bash
ssh -fN -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -L 8700:127.0.0.1:8700 -L 8801:127.0.0.1:8801 user@rig-host
```

The forward dies with the remote host, so a rig-host reboot leaves nothing
listening locally and the agent reads as unreachable while it is in fact
healthy. Re-open the tunnel before diagnosing anything further. This is the
shape that strands a rig the moment the tunnel drops, which is why a shared rig
belongs on a VPN instead.

## Take a session

Every control call except `/healthz` needs an access-token bearer.

```bash
AGENT=http://127.0.0.1:8700
TOKEN=<the token you minted>

curl -s "$AGENT/healthz"

curl -s -H "Authorization: Bearer $TOKEN" "$AGENT/api/v1/rigs" | jq .

curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","client_id":"bench-laptop","requested_ttl_seconds":3600}' \
  "$AGENT/api/v1/rigs/bench-a/sessions" | jq .
```

A successful reservation returns `201` with the session identity and the
stream endpoints:

```json
{
  "session_id": "...",
  "session_token": "...",
  "rig_id": "bench-a",
  "expires_at": "2026-07-25T12:00:00Z",
  "heartbeat_interval_seconds": 10,
  "stream": {
    "transport": "http-card-bridge",
    "url": "http://127.0.0.1:8801/apdu",
    "status_url": "http://127.0.0.1:8801/status",
    "card_reset_url": "http://127.0.0.1:8801/card/reset"
  }
}
```

A rig already held by someone else returns `423 Locked` with the holder in
the body. That is the whole point of the agent: two operators cannot drive
one card at the same time.

Keep the session alive at `heartbeat_interval_seconds`:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"session_token\":\"$SESSION_TOKEN\"}" \
  "$AGENT/api/v1/sessions/$SESSION_ID/heartbeat"
```

Release it when done:

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"session_token\":\"$SESSION_TOKEN\"}" \
  "$AGENT/api/v1/sessions/$SESSION_ID"
```

Release requires the `session_token` in the body, so holding an access token
is not enough to drop somebody else's session. That is what `force-release`
is for.

A session that stops heartbeating expires on its own after
`heartbeat_timeout_seconds`, and no session outlives `max_session_seconds`.
An `admin` token can evict a stuck holder:

```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{}' \
  "$AGENT/api/v1/rigs/bench-a/force-release"
```

## Stream APDUs through the session

The per-rig proxy speaks the Card Bridge protocol, so existing consumers
work unchanged -- the bearer is the `session_token`, not the rig's own Card
Bridge token:

```bash
printf '%s' "$SESSION_TOKEN" > ~/.config/yggdrasim/card_bridge/8801.token
chmod 600 ~/.config/yggdrasim/card_bridge/8801.token

python main/main.py \
  --remote-card-url http://127.0.0.1:8801/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8801.token
```

The proxy exposes `/ping` (unauthenticated), `/status`, `/apdu`, and
`/card/reset`. Requests without a live session are rejected with `401`, so a
released or expired session cannot keep driving the card.

## Store a host once

A registered device is a host card, and it records everything about the
box rather than about a run. Two doors can be recorded on one card:

| Field | Door | Notes |
| --- | --- | --- |
| `agent_host`, `agent_control_port`, token file | agent | bearer token, shared, reservable |
| `ssh_target`, `ssh_identity_file` | SSH | this operator's login, for setup and single-operator use |
| `remote_workdir`, `remote_python`, `hil_service_name` | SSH | where the checkout and its service live on the host |
| `card_reachability`, `card_url` | either | `tunnel` opens a reverse forward; `direct` points the host at a card published on a routable address |

### A host you have not set up yet

An invite carries an agent and a token, so there is no invite for a host
that has neither. That is the ordinary state of a rig before somebody
installs an agent on it, and it is exactly the host you want to record
while preparing one.

Remote Bridge stores that host directly: fill the SSH fields, name it,
and add it. The card then carries only the SSH half, reports itself as
`ssh-only` rather than offline, and offers no Connect, because there is
no agent to reserve a rig from. Importing an invite for the same host
later fills in the agent half without changing its identity.

A host needs at least one door. Neither half is rejected, and so is half
an agent: a host without a port would build a control URL nobody can
call.

The SSH half never travels in an invite. An invite hands a colleague an
agent and a token; it must not hand them your login or the path to your
private key.

Naming a host card is what collapses the Remote Bridge action from a
screenful of fields to one choice: every field it used to ask for is a
property of the box. Typed values still win, so the card fills blanks
rather than overriding an answer.

Both surfaces then report one view of the host. Starting a Remote Bridge
setup asks the host's agent whether its bench is already held and stops
before touching anything when it is, so two operators cannot configure
conflicting supervisors on one box. That check closes the setup window;
the lasting exclusion while a rig runs is the card lease.

## Offer a card to a modem rig

The rig has to reach the Card Bridge you name, so open a reverse tunnel
before reserving unless the bridge is already published on an address the
rig can route to:

```bash
ssh -fN -R 8642:127.0.0.1:8642 esim@rig.example.test
yggdrasim-lab --agent http://rig.example.test:8700 --token-file ~/.config/yggdrasim/remote_lab/alice.token \
    reserve quectel-a --user alice --offer-card-url http://127.0.0.1:8642/apdu
```

The token for your own bridge is read from the file
`yggdrasim-card-bridge` wrote for that port, so it does not have to be
passed. Use `--offer-card-token-file` when the bridge runs somewhere
else.

Reachability is checked before the reservation is granted. A tunnel that
is not open fails here with a message saying so, rather than as silence
once the modem powers up. If the card is already leased, the reservation
is refused with `card_leased` and nothing starts.

The grant carries no `stream` block, because the card is already on your
machine and there is nothing for the agent to stream back. It carries a
`consumer` block instead, and the rig releases the card and stops the
supervisor when the session ends, expires or loses its heartbeat.

## Control API reference

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` | none | liveness |
| GET | `/api/v1/info` | access token | agent identity and version |
| GET | `/api/v1/rigs` | access token | inventory with per-rig status |
| GET | `/api/v1/rigs/{id}/status` | access token | one rig |
| POST | `/api/v1/rigs/{id}/sessions` | access token | reserve; `423` when held |
| POST | `/api/v1/sessions/{id}/heartbeat` | access token + `session_token` | extend |
| DELETE | `/api/v1/sessions/{id}` | access token + `session_token` | release |
| POST | `/api/v1/rigs/{id}/force-release` | admin token | evict the holder |

## Use the GUI instead

The [Universal GUI Command Center](../subsystems/gui-command-center.md)
consumes the same agents under `/api/remote-lab`: import an agent, list its
devices, read status, connect, release, and force-release. The client-side
inventory persists to `Workspace/RemoteLab/registry.json`; per-device tokens
live in their own private files, and export redacts them. A device's name,
location, tags and agent address are editable from its card.

Connect behaves like plugging in a local reader. It reserves the rig, starts
the heartbeat, reads the card's ATR from the relay's status endpoint and
publishes the reader as `Remote Lab: <device name>`; it does not scan the
card and it does not move the operator off the Remote Lab page. That
reservation is held by one *link* session that belongs to no module. The
file system, eSIM management, the local SM-DP+ and SCP80 each open their own
card channel through the published name when they need one, and closing any
of them leaves the rig reserved. Disconnect (or the agent expiring the
session) closes the link, which closes those channels first and releases the
rig last, so nothing outlives the reservation it was opened under.

The shells reach the same rig once the GUI has connected it. `yggdrasim-scp03`,
`yggdrasim-scp11` and `yggdrasim-scp11-live` take `--reader "Remote Lab: <device
name>"` (an exact PC/SC reader name works there too); the SCP80 shell takes
`set reader_name Remote Lab: <device name>`, and `set reader_idx N` switches
back to a local reader. The MCP card tools accept the same name in
`reader_name`. A name that resolves to nothing is a startup error, never a
fallback to the first local reader.

## Security rules

- Choose the bind to match who the rig serves. A single-operator rig stays on
  loopback behind SSH. A rig shared by everyone holding a token belongs on a
  trusted network -- a VPN or a routed internal LAN -- and binds to a real
  interface. What must never happen is a non-loopback bind on an untrusted
  network: the agent authenticates callers, but it is not a TLS terminator, so
  the transport has to be private on its own.
- Restrict reachability at the network layer when the VPN can do it. A NetBird
  or Tailscale ACL that exposes the control and stream ports only to a lab
  group beats the all-or-nothing reach an SSH login grants.
- Store only `token_hash` in the config file. The config is not a secret
  store, and a hash is useless to an attacker who reads it.
- Issue one access token per person, not one per team, so revoking a leaver
  is an edit and a restart rather than a rotation for everyone.
- Reserve `role: admin` for the people who should be able to yank a rig out
  from under a colleague mid-session.
- Session tokens are as sensitive as Card Bridge tokens: `0600` files, never
  shell history.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| agent exits at startup naming a key path | config schema error | fix the reported key; the loader reports the exact index, e.g. `rigs[1].upstream` |
| `duplicate stream proxy bind/port` | two rigs share a port, or one collides with `agent.control_port` | give each rig its own `external_port` |
| every control call returns `401` | token not in `security.access_tokens`, or hash mismatch | re-mint the pair and paste the new `token_hash` |
| `POST /sessions` returns `423` | rig held by a live session | wait for expiry, or force-release with an admin token |
| `/apdu` returns `401` mid-run | session expired because heartbeats stopped | heartbeat at `heartbeat_interval_seconds` |
| rig status reports the upstream down | Card Bridge not running or token wrong | validate the rig directly per [Card Bridge over SSH](remote-apdu-streaming.md) |
| `force-release` returns `403` | bearer is a `user` token | use a `role: admin` token |

## Related pages

- [Card Bridge over SSH](remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](install-remsim-apdu-streaming.md)
- [Universal GUI Command Center](../subsystems/gui-command-center.md)
