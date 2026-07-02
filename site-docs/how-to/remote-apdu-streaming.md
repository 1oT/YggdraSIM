---
title: Remote APDU Streaming
tags:
  - how-to
  - apdu
  - remote
  - card-bridge
  - hil
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Remote APDU Streaming

## Goal

Expose a PC/SC reader over a loopback HTTP bridge, carry the traffic through
SSH, and make YggdraSIM use that card as if it were local. The same bridge
can also feed a HIL rig, so a card on a workstation can serve a modem on a
Raspberry Pi or lab host.

## Topologies

### Tool uses a remote reader

```text
YggdraSIM tool host  --ssh -L-->  reader host
local URL :8642                 Card Bridge :8642 -> PC/SC reader
```

Use this when the operator shell or GUI runs on one machine and the card is
plugged into another.

### Remote card feeds a HIL rig

```text
workstation reader -> Card Bridge -> SSH forward -> rig HIL bridge -> RemSIM client -> SIMtrace2 -> modem
```

Use this when the modem/SIMtrace2 rig is remote but the card must stay with
the operator.

## Prerequisites

Reader side:

- Python 3.10+
- YggdraSIM source install or a build that includes `Tools.CardBridge`
- `pcscd` and `pyscard`
- PC/SC reader visible to `pcsc_scan`

Tool or rig side:

- YggdraSIM installed
- SSH access to the reader side
- for HIL: Linux, SIMtrace2, `osmo-remsim-client-st2`, and the full/HIL
  source dependencies

Card Bridge itself is cross-platform: the reader-side bridge and the
remote-card consumer flags are supported on Windows, macOS, Linux, and
Raspberry Pi as long as PC/SC and SSH are available. Only the direct
SIMtrace2/RemSIM HIL rig process is Linux-only.

For a complete dependency install path, use
[Install RemSIM / APDU Streaming](install-remsim-apdu-streaming.md). The
main upstream references are:

| Dependency | Reference |
| --- | --- |
| SSH forwarding | [OpenSSH manual pages](https://www.openssh.org/manual.html) |
| PC/SC middleware and tools | [PCSC-Lite project](https://pcsclite.apdu.fr/), [pcsc-tools](https://pcsc-tools.apdu.fr/) |
| RemSIM client | [Osmocom RemSIM](https://osmocom.org/projects/osmo-remsim/wiki), [Osmocom binary packages](https://osmocom.org/projects/cellular-infrastructure/wiki/Binary_Packages) |
| SIMtrace2 rig | [SIMtrace2 wiki](https://osmocom.org/projects/sim-card/wiki/SIMtrace2), [SIMtrace2 firmware binaries](https://ftp.osmocom.org/binaries/simtrace2/firmware/) |

## Start the Card Bridge

On the reader host, start the bridge from the unified launcher:

```bash
python main/main.py --card-bridge \
  --card-bridge-port 8642 \
  --card-bridge-reader-name "ACR"
```

Installed environments can use the dedicated console script or module form:

```bash
yggdrasim-card-bridge \
  --port 8642 \
  --reader-name "ACR"

# equivalent from a source checkout
python -m Tools.CardBridge \
  --port 8642 \
  --reader-name "ACR"
```

The bridge binds to `127.0.0.1`, writes a bearer token under
`${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token`, and
prints the `/apdu`, `/status`, and `/card/reset` URLs. The token file is
created with mode `0600`.

Use `--reader-index 0` instead of `--reader-name` when reader ordering is
stable. In the interactive launcher, the same controls are available under
`python main/main.py` -> `[CB] Card Bridge / Remote APDU Streaming`.

## Open the SSH tunnel

From the YggdraSIM host to the reader host:

```bash
ssh -fN -L 8642:127.0.0.1:8642 user@reader-host
```

For a HIL rig that must consume a workstation card, either run that command
on the rig, or run the reverse form from the workstation:

```bash
ssh -fN -R 8642:127.0.0.1:8642 user@rig-host
```

## Configure YggdraSIM consumers

Copy or otherwise stage the token file on the consumer side:

```bash
mkdir -p ~/.config/yggdrasim/card_bridge
scp user@reader-host:~/.config/yggdrasim/card_bridge/8642.token \
  ~/.config/yggdrasim/card_bridge/8642.token
chmod 600 ~/.config/yggdrasim/card_bridge/8642.token
```

Then point a shell at the forwarded bridge:

```bash
python main/main.py \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token

python -m SCP03 \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token
```

The first command opens the normal CLI menu with the remote card already
selected for card-consuming tools launched from that process. Other
card-consuming surfaces that use the shared backend accept the same flags.
Environment equivalents are:

```bash
export YGGDRASIM_CARD_RELAY_URL=http://127.0.0.1:8642/apdu
export YGGDRASIM_CARD_RELAY_TOKEN_FILE=~/.config/yggdrasim/card_bridge/8642.token
```

## Feed a HIL rig with the remote card

On the rig, after the SSH tunnel is up:

```bash
yggdrasim-hil-supervisor \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
  --apdu-timeout-ms 30000 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3
```

The HIL bridge now reads and writes the remote card through the tunnel while
still exposing its normal rig-side relay state and GSMTAP mirror. Local
YggdraSIM tools on the rig continue to talk to the HIL relay, not directly
to the Card Bridge.

## Use the GUI instead

The [Universal GUI Command Center](../subsystems/gui-command-center.md) wraps
this flow in the Card bridge panel. The **Start full rig** action can start
the local bridge, open SSH forwards, sync the token, install or restart the
remote HIL service, and verify the final state.

Use the GUI when you need repeated lab sessions against the same rig. Use the
CLI flow above when you need a minimal, auditable setup sequence.

## Validation

Cheap liveness check:

```bash
curl -s http://127.0.0.1:8642/ping
```

Authenticated status:

```bash
curl -s \
  -H "Authorization: Bearer $(cat ~/.config/yggdrasim/card_bridge/8642.token)" \
  http://127.0.0.1:8642/status | jq .
```

YggdraSIM preflight:

```bash
python main/main.py --doctor \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token
```

CLI menu probe:

```bash
python main/main.py
# then choose [CB] -> [3] Probe configured remote APDU bridge
```

For HIL, also check:

```bash
cat state/hil_bridge_supervisor.json
cat state/hil_bridge_card_relay.json
```

Look for a running supervisor, an `ok` card relay, and a non-empty ATR.

## Security rules

- Keep Card Bridge bound to loopback.
- Use SSH for transport encryption and peer authentication.
- Keep bearer tokens in `0600` files, not shell history.
- Enable full APDU audit only on test cards; APDUs can contain PINs and
  operator secrets.
- Do not expose `/apdu` directly on a lab subnet. If a non-loopback bind is
  unavoidable, use a token, TLS termination, and host firewall rules.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `/ping` works, `/status` returns 401 | wrong or missing bearer token | copy the token again and verify mode `0600` |
| YggdraSIM still opens the local reader | remote-card URL not applied | pass `--remote-card-url` on the exact command being run, or export the env vars |
| `reader busy` on the reader host | another process owns the PC/SC reader | close local shells or start Card Bridge with `--pcsc-share-mode shared` |
| HIL starts but no modem APDUs appear | RemSIM/SIMtrace2 side not attached | validate `osmo-remsim-client-st2`, SIMtrace2 firmware, and USB permissions |
| APDUs time out over WAN | SSH path too slow for default timeout | raise `--apdu-timeout-ms` on Card Bridge and HIL |

## Related pages

- [Universal GUI Command Center](../subsystems/gui-command-center.md)
- [Install RemSIM / APDU Streaming](install-remsim-apdu-streaming.md)
- [HIL Bridge](../subsystems/hil-bridge.md)
- [Run a HIL Capture](run-hil-capture.md)
