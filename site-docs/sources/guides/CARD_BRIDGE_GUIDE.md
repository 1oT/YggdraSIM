<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Card Bridge — Operator Guide

The Card Bridge lets you run YggdraSIM on one machine while the smart
card reader is plugged into another. The reader-side machine runs
`Tools/CardBridge`, which exposes the card on a loopback HTTP endpoint;
the tool-side machine reaches the bridge through an SSH `LocalForward`.

This document walks through the deployment, security posture, and
common troubleshooting paths.

## Topology

```
+------------------------+        ssh -L                +------------------------+
|  Raspberry Pi or any   |  <===========>               |  PC with PC/SC reader  |
|  YggdraSIM consumer    |  encrypted tunnel            |                        |
|                        |                              |  python -m             |
|  YGGDRASIM_CARD_RELAY_*|  ---- HTTP, loopback ---->   |     Tools.CardBridge   |
|  RelayCardConnection   |                              |                        |
+------------------------+                              +------------------------+
```

* The Card Bridge binds **only** to `127.0.0.1`. The card never sees
  the network directly.
* SSH provides stream encryption, integrity, and peer authentication.
* A bearer token, generated on first run by the bridge, layers
  authorization on top of SSH so a second local user on the PC can't
  also reach the loopback port.

## Prerequisites

* On the **reader-side machine**:
  * `pcscd` running, reader detected by `pcsc_scan`.
  * Python 3.10+ with the `pyscard` wheel installed in the same
    environment that hosts YggdraSIM.
  * SSH server reachable from the consumer side (any standard
    `~/.ssh/authorized_keys` works).
* On the **consumer side**:
  * The YggdraSIM toolchain.
  * SSH client with key access to the reader-side machine.

## Step 1 — Start the bridge on the reader machine

```bash
python main/main.py --card-bridge \
    --card-bridge-port 8642 \
    --card-bridge-reader-name "ACR38U"
```

Installed environments can also use the dedicated command:

```bash
yggdrasim-card-bridge \
    --port 8642 \
    --reader-name "ACR38U"

# equivalent module form from a source checkout
python -m Tools.CardBridge \
    --port 8642 \
    --reader-name "ACR38U"
```

You'll see a banner like:

```
========================================================================
YggdraSIM Card Bridge — ready
========================================================================
  reader     : ACR38U USB Reader (1.00) 00 00
  ATR        : 3B9F95801FC78031E073FE21
  apdu URL   : http://127.0.0.1:8642/apdu
  status URL : http://127.0.0.1:8642/status
  reset URL  : http://127.0.0.1:8642/card/reset
  token      : <redacted, fingerprint a1b2c3>
  token file : /home/example/.config/yggdrasim/card_bridge/8642.token  (written, mode 0600)
  remote use : route via 'ssh -fN -L 8642:127.0.0.1:8642 <pc-host>'
========================================================================
```

The full token is never printed. The fingerprint lets you reconcile
the running daemon with the on-disk token file.

### Reader selection

Use either:

* `--card-bridge-reader-index N` / `--reader-index N` — position in
  the PC/SC reader list (default 0).
* `--card-bridge-reader-name "substring"` / `--reader-name "substring"` — case-insensitive substring match;
  overrides `--reader-index`.
* `--card-bridge-pcsc-share-mode shared|exclusive` /
  `--pcsc-share-mode shared|exclusive` — defaults to `shared` so the
  bridge can start while the GUI or `pcsc_scan` has a non-exclusive
  handle open. Use `exclusive` only for isolated reader hosts where no
  other local process touches the reader.

Run `pcsc_scan -n` on the reader machine to inspect the available
reader names.

## Step 2 — Open the SSH tunnel from the consumer machine

The simplest form:

```bash
ssh -fN -L 8642:127.0.0.1:8642 hampus@pc-host
```

The `-fN` flags background the SSH process without running a remote
command — only the port forward stays alive.

A more durable approach is to add a stanza to `~/.ssh/config` on the
consumer machine:

```
Host pc-card
    HostName pc-host.lan
    User hampus
    LocalForward 8642 127.0.0.1:8642
    ExitOnForwardFailure yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Then `ssh -fN pc-card` opens the tunnel and `ssh pc-card` opens an
interactive session that shares the same forwarded port.

## Step 3 — Point YggdraSIM at the forwarded port

Two environment variables drive the consumer:

```bash
# The relay URL (always loopback on the consumer side, because the
# tunnel terminates there):
export YGGDRASIM_CARD_RELAY_URL=http://127.0.0.1:8642/apdu

# Either the raw token …
export YGGDRASIM_CARD_RELAY_TOKEN="$(ssh pc-card cat ~/.config/yggdrasim/card_bridge/8642.token)"

# … or a 0600 file holding the same value (preferred — avoids the
# token appearing in `ps` output):
export YGGDRASIM_CARD_RELAY_TOKEN_FILE=$HOME/.config/yggdrasim/card_bridge/8642.token
```

Then run the tool as normal:

```bash
python main/main.py \
    --remote-card-url http://127.0.0.1:8642/apdu \
    --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token

yggdrasim ...
```

The `RelayCardConnection` client picks up both variables and presents
`Authorization: Bearer <token>` on every APDU exchange.

### Inline overrides (CB-3 CLI flags)

If you'd rather not export the env variables, the same values can be
passed inline. The flags mirror the env vars and win when both are
set, which makes it easy to override a stale shell environment:

```bash
yggdrasim \
    --remote-card-url http://127.0.0.1:8642/apdu \
    --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
    ...
```

YggdraSIM prints a one-line banner on startup whenever a remote bridge
is configured, so it's obvious at a glance which card the session is
talking to:

```
[i] remote card bridge: http://127.0.0.1:8642/apdu; token file (flag): /home/example/.config/yggdrasim/card_bridge/8642.token
```

Pass `--remote-card-url ""` (empty string) to clear an inherited env
value without rewriting your shell config.

### Unified CLI menu

The main launcher has a Card Bridge menu for operators who prefer a
guided terminal flow:

```bash
python main/main.py
# choose [CB] Card Bridge / Remote APDU Streaming
```

The `[CB]` menu can:

* start or stop the local Card Bridge
* probe the configured remote APDU endpoint
* apply a remote-card URL and token file to the current CLI session
* print the matching `ssh -L` and `ssh -R` tunnel commands
* hand off to the HIL session menu when the HIL runtime is available

### HIL remote-card mode

When the consumer is a HIL rig, keep `yggdrasim-card-bridge` running
on the reader workstation and make the workstation port visible on the
rig's loopback interface:

```bash
# Run on the rig, connecting to the reader workstation:
ssh -fN -L 8642:127.0.0.1:8642 hampus@pc-host

# Or run on the reader workstation, connecting to the rig:
ssh -fN -R 8642:127.0.0.1:8642 hampus@rig-host
```

Then start HIL on the rig:

```bash
yggdrasim-hil-bridge \
    --remote-card-url http://127.0.0.1:8642/apdu \
    --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
    --apdu-timeout-ms 30000
```

The remote card becomes the HIL card source. The rig-side HIL relay
still publishes its normal `apduUrl`, `statusUrl`, and `cardResetUrl`,
so local SCP03 / SAIP consumers on the rig keep using the same relay
surface while the physical card stays on the workstation.

### Doctor preflight

Once the URL/token are configured, `yggdrasim --doctor` includes a
`Remote card bridge` row that probes `/ping` and `/status` with the
resolved bearer token:

```
✔ Remote card bridge — http://127.0.0.1:8642 reachable; auth ok (token fp: a1b2c3); audit on
```

The probe distinguishes the common failure modes (unreachable,
401 token rejected, auth disabled on a non-loopback host) and
short-circuits with a clear `warn` line so misconfiguration is easy
to spot before the first APDU.

### GUI surfaces (CB-4)

When the GUI server is running, Command Center actions expose the
same diagnostics and the remote-HIL rig bootstrap:

| Action id | Purpose |
|---|---|
| `card_bridge.status` | Snapshot of the resolved URL and token posture (no network traffic). |
| `card_bridge.probe`  | Live `/ping` + `/status` probe with latency, ATR, and auth posture. Bearer tokens are never echoed back; only their 6-char fingerprint is returned. |
| `card_bridge.remote_rig_start` | Starts or verifies the PC Card Bridge, refreshes its PC/SC handle, opens the SSH reverse tunnel, syncs the token to the RPi, verifies authenticated card status from the RPi, and installs/restarts the RPi HIL supervisor service. |

A dedicated **Card bridge** panel in the sidebar wraps these actions
in a focused diagnostics surface:

* Configured-target card showing URL, token fingerprint, source, and
  a "Copy URL" button.
* Live probe card with posture badge, ping/status latency, reader
  name + ATR, audit state, and a fingerprint-match indicator (green
  if the local fingerprint matches the bridge's).
* Optional URL/token override (collapsed by default) for ad-hoc
  testing of an alternative endpoint.
* Remote HIL rig controls. **Start full rig** runs the end-to-end setup in
  the background using the SSH target, PC reader selector, RPi repo
  directory, RPi Python, token file, REMSIM binary, SIMtrace2 VID:PID,
  and HIL port fields. It resets the local PC/SC handle before
  restarting the RPi service so a stale reader session is not reused.
  The manual buttons remain available for
  stopping or probing each layer independently.
* Remote HIL GSMTAP capture. The RPi service writes
  `state/hil_termshark/live_capture.pcap` under the remote YggdraSIM
  repo. The GUI HIL module reuses its normal `hil.decode_snapshot`
  path by pulling that pcap over SSH into the local runtime before
  running `tshark`, so the Dissector and Raw APDU tabs display remote
  modem traffic the same way as a local HIL session.
* Remote HIL modem shell. When the remote rig state contains an SSH
  target, the HIL module's **Modem shell** tab uses that target as its
  default command and opens `sudo tio /dev/ttyUSB2` on the RPi through
  `ssh -tt`. Custom modem-shell commands remain editable and are saved
  by the browser.
* Auto-refresh toggle (5 s) — pauses automatically when the operator
  navigates to another view so the GUI doesn't poll in the background.
* Latency history sparkline (60-sample rolling buffer) with stacked
  ping + status polylines and red dots marking failed probes.

The reader picker on `/api/live/readers` also surfaces a
`🌐 remote@<base-url>` row whenever a bridge URL is configured, so
operators can pick a remote bridge from the same control as a local
PC/SC reader.

### GUI-managed remote HIL rig

The Card bridge panel also includes a **Remote HIL rig** block for the
workstation-card / Raspberry Pi-rig topology:

```text
PC reader -> local CardBridge -> ssh -R -> RPi HIL supervisor -> SIMtrace2 -> device
PC browser <- ssh -L <- RPi web-server GUI
```

The block wraps these action ids:

| Action id | Purpose |
|---|---|
| `card_bridge.local_start` / `card_bridge.local_stop` | Start or stop the PC-side `yggdrasim-card-bridge` subprocess. |
| `card_bridge.remote_rig_tunnel_start` / `card_bridge.remote_rig_tunnel_stop` | Open or close the SSH forwards (`-R` for CardBridge, `-L` for the RPi GUI). |
| `card_bridge.remote_rig_sync_token` | Copy the local CardBridge bearer token to the RPi with mode `0600`. |
| `card_bridge.remote_rig_install_service` | Write a `systemd --user` service on the RPi for the HIL supervisor, including `--remote-card-url`. |
| `card_bridge.remote_rig_service` | Start, stop, restart, or query the RPi HIL service through SSH. |
| `card_bridge.remote_rig_status` | Show local process state plus the remote service state when an SSH target is set. |

The GUI process still runs on the PC. It controls the RPi through SSH,
so SSH key login must already work from the PC account that launched
the GUI. The action uses `BatchMode=yes`; it will not block on a
password prompt.

The RPi must have `osmo-remsim-client-st2` installed, or the **RPi
REMSIM binary** field must point to an executable path such as
`/usr/local/bin/osmo-remsim-client-st2`. The full-rig action resolves
that path before writing the systemd unit so the service does not
depend on systemd's default `PATH`.

For unattended use, install the RPi service once from the GUI or by
copying `guides/systemd/yggdrasim-hil-supervisor.service.example` and
adding the remote-card flags:

```text
--remote-card-url http://127.0.0.1:8642/apdu
--remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token
--apdu-timeout-ms 30000
```

Enable linger on the RPi user when the service must survive logout or
start without an interactive SSH session:

```bash
loginctl enable-linger "$USER"
```

The persistent RPi service removes the need to log into the RPi for
normal runs. The PC still needs a live SSH tunnel whenever the card is
on the PC, because the RPi consumes the CardBridge endpoint through
that tunnel.

When the RPi boots before the PC-side CardBridge/tunnel exists, the
supervisor remains active and retries the bridge child with a slower
remote-card backoff. This keeps the service ready for unattended Pi
recovery without burning CPU on a tight restart loop.

## Verifying the link

Cheap liveness check (does **not** require a token):

```bash
curl -s http://127.0.0.1:8642/ping
# → pong
```

Authenticated status (returns the ATR + auth posture):

```bash
curl -s -H "Authorization: Bearer $(cat $YGGDRASIM_CARD_RELAY_TOKEN_FILE)" \
    http://127.0.0.1:8642/status | jq .
```

## Security posture

| Concern | Handled by |
|---|---|
| Confidentiality | OpenSSH transport (ChaCha20-Poly1305 / AES-GCM). |
| Integrity | OpenSSH MAC + sequence numbers. |
| Mutual authentication | OpenSSH public-key auth. |
| Authorization | Bridge bearer token (32 bytes URL-safe base64). |
| Network exposure | Bridge binds only to `127.0.0.1`. Non-loopback bind without a token is refused. |
| DoS / brute-force | Per-peer rate limit: 3 auth failures inside 30 s ⇒ 60 s lockout. |
| Audit | Bridge `--audit` flag (header-only by default); SSH `sshd` access log. |
| Secrets in logs | Token never logged beyond a 6-char fingerprint. APDU bodies redacted unless `--audit-full-apdu` is set explicitly. |

The bridge **refuses to start** if you try to bind anything other than
loopback without a token. There is no `--unsafe-bind` escape hatch by
design — if you need network exposure you must either accept the
SSH-tunnel topology or supply a token (and almost certainly terminate
TLS at a reverse proxy).

## Audit logging

```bash
python -m Tools.CardBridge --port 8642 --audit
```

emits one record per APDU on the `yggdrasim.card_bridge.audit` logger:

```
peer=127.0.0.1 session=- len=7 respLen=2 sw=9000 latMs=12.34 cla=00 ins=A4 p1=04 p2=00 lc=02
```

The data field is **never** logged in this mode. To capture full
hex (e.g. for forensic work on a test card), pass `--audit-full-apdu`
explicitly. The startup banner notes the choice so a casual reader
of `journalctl` can tell whether PIN material rode through the log.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `card-bridge: Refusing to bind …` | `--host` is not loopback and no token was provided. | Drop the host flag, supply `--token-file`, or remove `--no-token`. |
| `401 Missing or invalid bearer token` | Consumer didn't pick up the token file or env var. | Confirm `YGGDRASIM_CARD_RELAY_TOKEN_FILE` resolves and is readable. Verify the fingerprint (`yggdrasim ... --doctor` matches the bridge banner). |
| `429 Too many authentication failures` | The peer hit the 3-failure threshold. | Wait 60 s, then retry with the correct token. The bridge logs which peer locked out. |
| `Cannot open PC/SC reader` | Bridge can't see the reader or another process holds the reader exclusively. | `pcsc_scan -n`; verify the reader name; restart `pcscd`; close other card tools. The GUI-launched bridge uses `--pcsc-share-mode shared` to avoid normal reader-probe conflicts. |
| `REMSIM client failed to start: [Errno 2] No such file or directory` | `osmo-remsim-client-st2` is not installed on the RPi or is outside the service path. | Install the RPi REMSIM package as described in `guides/INSTALL_RASPBERRYPI.md`, or set **RPi REMSIM binary** to the executable's absolute path. |
| Tunnel works but APDUs hang | SSH session closed. | `ServerAliveInterval`/`ServerAliveCountMax` in `~/.ssh/config`. |

## Compatibility with HilBridge

The Card Bridge speaks the same wire protocol as the in-tree HIL
bridge's APDU relay (`Tools/HilBridge/apdu_relay.py`). HilBridge
already auto-publishes a marker file (`hil_bridge_card_relay.json`)
on its host, so a YggdraSIM CLI invocation on the same machine
discovers the relay automatically. The Card Bridge daemon does
**not** write that marker — its address is intentional, explicit,
and operator-supplied, because the relay is being exposed through
SSH rather than auto-discovered on a single host.

## Related runbooks

- `site-docs/how-to/remote-apdu-streaming.md` — compact end-to-end
  recipe for Card Bridge over SSH.
- `site-docs/how-to/install-remsim-apdu-streaming.md` — Linux /
  Raspberry Pi RemSIM, SIMtrace2, Card Bridge, and service setup.
- `guides/HIL_BRIDGE_GUIDE.md` — full HIL operator procedure.
