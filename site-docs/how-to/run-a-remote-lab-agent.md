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

The agent does not replace [Remote APDU Streaming](remote-apdu-streaming.md).
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
  [Remote APDU Streaming](remote-apdu-streaming.md)
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
| `defaults.*` | no | `30` / `60` / `14400` seconds; floored at 1 |
| `security.access_tokens` | yes | at least one entry; `token_hash` must start with `sha256:`; `role` is `user` or `admin` |
| `rigs[].id` | yes | must be unique, compared case-insensitively |
| `rigs[].stream_proxy.external_port` | yes | rejected when it collides with another rig or with `agent.control_port` on an overlapping bind |
| `rigs[].upstream` | yes | either `url`, or `host` + `port` (+ optional `scheme`); `/apdu` is appended when missing |
| `rigs[].locks` | no | defaults to `rig:<id>`; give two rigs a shared lock name when they cannot run at once |
| `rigs[].enabled` | no | defaults to `true` |

`upstream.url` must be `http(s)` with no credentials, query, or fragment.
Use `upstream.token_file` rather than inline `token` so the Card Bridge
bearer stays in a `0600` file.

## Start the agent

```bash
yggdrasim-lab-agent --config ~/.config/yggdrasim/remote-lab.yaml
```

`--log-level DEBUG` raises verbosity. A malformed config fails at startup
with the offending key path, so a typo never produces a half-open agent.

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
live in their own private files, and export redacts them.

## Security rules

- Keep `agent.bind_host` and every `stream_proxy.bind_host` on loopback and
  reach them over SSH. The agent authenticates callers; it is not a TLS
  terminator.
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
| rig status reports the upstream down | Card Bridge not running or token wrong | validate the rig directly per [Remote APDU Streaming](remote-apdu-streaming.md) |
| `force-release` returns `403` | bearer is a `user` token | use a `role: admin` token |

## Related pages

- [Remote APDU Streaming](remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](install-remsim-apdu-streaming.md)
- [Universal GUI Command Center](../subsystems/gui-command-center.md)
