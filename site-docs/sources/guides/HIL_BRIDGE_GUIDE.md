# HIL Bridge Guide

This guide covers the YggdraSIM hardware-in-the-loop path built around:

- a physical card in a PC/SC reader
- a sysmocom SIMtrace2 flashed for relay / card-emulation use
- `osmo-remsim-client-st2` on the host
- the YggdraSIM HIL bridge on `127.0.0.1:9997`
- GSMTAP mirroring to Wireshark on UDP `4729`
- brokered side access from YggdraSIM through the local APDU relay

> **Naming note.** "sysmocom SIMtrace2" is the USB product identifier
> that the Linux `lsusb` tool reports for VID:PID `1d50:60e3`. It is
> referenced in this guide solely as a device identifier so the HIL
> supervisor can find the physical hardware; it is not a vendor
> endorsement, partnership, or certification. The same applies to
> `osmo-remsim-client-st2`, which is the upstream tool name.

> **Build flavor note.** The HIL bridge is Linux-only and is only
> bundled in the **full** executable and in source checkouts installed
> with the `[hil]` / `[full]` extras. The **clean** executable shipped
> for Windows, macOS, Linux, and Raspberry Pi intentionally omits this
> path; the launcher still renders a menu entry explaining where to
> find the full build. See
> [`INSTALL_FULL.md`](INSTALL_FULL.md),
> [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md), and
> [`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md).

## Operating model

The HIL bridge is a separate OS process.

- It keeps exclusive ownership of the physical reader while it is active.
- It mirrors modem traffic to Wireshark even when no YggdraSIM shell is open.
- YggdraSIM modules that use `yggdrasim_common.card_backend.create_card_connection()` can still talk to the same live card through the relay side-channel.
- Access is serialized, not isolated. YggdraSIM APDUs and modem APDUs share one live card session.

Recommended topology:

```text
physical card
  <->
PC/SC reader
  <->
YggdraSIM HIL bridge
  <-> RSPRO / IPA over TCP : 127.0.0.1:9997
osmo-remsim-client-st2
  <->
SIMtrace2
  <->
modem

YggdraSIM HIL bridge
  -> GSMTAP UDP 127.0.0.1:4729 -> Wireshark
  -> HTTP APDU relay on localhost -> YggdraSIM side access
```

## Prerequisites

Hardware:

- SIMtrace2 running the relay / card-emulation firmware
- one physical UICC / eUICC in a PC/SC reader
- the attached modem on the SIMtrace2 side

Host software:

- `pcscd`
- `osmo-remsim-client-st2`
- optional `simtrace2-list` / `simtrace2-tool`
- optional Wireshark
- optional terminal decoded APDU view
- Python environment with YggdraSIM installed

Python packages used by this path:

- `pyscard`
- `asn1tools`
- `pyudev` for event-driven USB hotplug supervision

`pyudev` is only pulled in automatically on Linux. It is gated behind
the `[hil]` / `[full]` extras in `pyproject.toml` with a
`sys_platform == "linux"` marker, so Windows and macOS installs never
try to compile it. If it is missing on a Linux host the supervisor
falls back to `lsusb` polling; that is slower than udev events but
still valid.

## 1. Install YggdraSIM in the active environment

From a source checkout, install the HIL extra so `pyudev` and the
bridge entry points are present:

```bash
python -m pip install -e '.[hil]'
```

Or install everything needed for development and publishing:

```bash
python -m pip install -e '.[full]'
```

Verify the HIL probes report green:

```bash
yggdrasim --doctor
```

You should see rows for `flavor`, `hil-bridge-runtime`, and
`osmo-remsim-client-st2`. If you use the pre-built **full** Linux
executable instead of a source install, no `pip` step is required; the
doctor report is available as `./yggdrasim-full --doctor`.

Installed bridge commands after editable install:

```bash
yggdrasim-hil-bridge
yggdrasim-hil-supervisor
```

Direct module entry points from the repository root:

```bash
python -m Tools.HilBridge.main
python -m Tools.HilBridge.supervisor
```

## 2. Identify the SIMtrace2 and reader

Check the USB identity:

```bash
lsusb | rg -i 'simtrace|sysmocom|1d50:60e3'
```

Example:

```text
Bus 003 Device 042: ID 1d50:60e3 OpenMoko, Inc. Osmocom SIMtrace 2
```

List PC/SC readers:

```bash
python -m Tools.HilBridge.main --list-readers
```

Example:

```text
0: HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00
1: Broadcom Corp 58200 [Contacted SmartCard] (0123456789ABCD) 01 00
```

Use either:

- `--reader-index <n>` if the reader order is stable on your host
- `--reader-name "<substring>"` if the USB order changes and you want name-based selection

## 3. Start the supervisor-managed bridge

Recommended command:

```bash
yggdrasim-hil-supervisor \
  --reader-index 0 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3
```

Equivalent module form:

```bash
python -m Tools.HilBridge.supervisor \
  --reader-index 0 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3
```

Notes:

- `--usb-vidpid 1d50:60e3` is a good explicit selector for SIMtrace2 on systems where that VID:PID is visible in `lsusb`.
- start and stop HIL sessions manually from the main wrapper when you need modem or trace access
- while a manual HIL session is active, the supervisor spawns the bridge child only while the SIMtrace2 is detected
- the supervisor also spawns `osmo-remsim-client-st2` by default and tears it down together with the bridge child
- use repeated `--remsim-arg` options when the remsim client needs explicit SIMtrace2 selectors
- use `--no-remsim-client` only when you intentionally want manual remsim lifecycle control
- when the supervisor is stopped, or the SIMtrace2 disappears, the bridge child is torn down and the reader lock is released

Manual bridge mode still exists for debugging:

```bash
yggdrasim-hil-bridge --reader-index 0 --host 127.0.0.1 --port 9997 --advertise-host 127.0.0.1
```

Use the supervisor for normal operation. It is the safer lifecycle path.

### Optional `systemd --user` service

An example user service is included at:

- `guides/systemd/yggdrasim-hil-supervisor.service.example`

Typical install flow:

```bash
mkdir -p ~/.config/systemd/user
cp guides/systemd/yggdrasim-hil-supervisor.service.example ~/.config/systemd/user/yggdrasim-hil-supervisor.service
```

Then edit the copied unit and confirm:

- `WorkingDirectory`
- `ExecStart`
- `--reader-index` or `--reader-name`
- `--usb-vidpid`

For manual operation, keep the unit disabled and start it only when needed:

```bash
systemctl --user daemon-reload
systemctl --user disable yggdrasim-hil-supervisor.service
systemctl --user start yggdrasim-hil-supervisor.service
```

Useful commands:

```bash
systemctl --user status yggdrasim-hil-supervisor.service
journalctl --user -u yggdrasim-hil-supervisor.service -f
systemctl --user restart yggdrasim-hil-supervisor.service
systemctl --user stop yggdrasim-hil-supervisor.service
```

Why the example uses `KillMode=mixed`:

- `systemd` sends `SIGTERM` to the supervisor first
- the supervisor shuts the bridge child down cleanly
- if anything remains stuck, `systemd` still force-cleans the rest of the cgroup after `TimeoutStopSec`

Optional:

- run `loginctl enable-linger "$USER"` if you want the user service to survive logout instead of only starting on login

## 4. Confirm the bridge is healthy

Source runs write runtime state under the repository root by default. The key files are:

- `state/hil_bridge_supervisor.json`
- `state/hil_bridge_card_relay.json`

Supervisor state should show:

- `status: running`
- `cardBackendGate: reader` (or `sim`; see below)
- `usbPresent: true`
- a non-zero `bridgePid`

Relay state should show:

- `status: ok`
- `apduUrl`
- `statusUrl`
- `modemRefreshUrl`
- the selected `reader`
- the card `atr`

The bridge log should also print the relay URL:

```text
Card relay available at http://127.0.0.1:45007/apdu
```

### 4.1 Sim-backend launches without SIMtrace2 hardware

When `YGGDRASIM_CARD_BACKEND=sim` is set (via the `[C] Card backend`
menu, the env-flags wizard, or an explicit `Environment=` override),
the supervisor:

- skips the SIMtrace2 USB-presence gate and launches the bridge child
  immediately. The supervisor JSON reports `cardBackendGate: sim`,
  `usbSource: sim-backend`, and `usbPresent: true` with a synthetic
  `usbMatches` entry that documents the bypass.
- refuses to spawn `osmo-remsim-client-st2`. Sim mode has no
  USB-attached modem path, so REMSIM is irrelevant; the JSON reports
  `remsimClientEnabled: false` and `remsimClientCommand: []` for the
  duration of sim-mode operation.

Toggling between `reader` and `sim` between sessions is now
non-destructive: the wizard rewrites the user unit only when the
generated content actually changes, runs `daemon-reload` only on a
change, clears the previous run's relay marker, and triggers a real
`systemctl --user restart` so the new `Environment=YGGDRASIM_CARD_BACKEND=...`
block takes effect. No tool reboot is required.

## 5. Automatic remsim client management

By default, the supervisor launches the remsim client with the bridge and keeps it aligned to the same lifecycle.

Default generated client command:

```bash
osmo-remsim-client-st2 -i 127.0.0.1 -p 9997 -c 0 -n 0
```

If USB auto-selection fails on your host, pass explicit selector arguments through the supervisor.

VID:PID-based supervisor example:

```bash
yggdrasim-hil-supervisor \
  --reader-index 0 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3 \
  --remsim-arg=-V \
  --remsim-arg=0x1d50 \
  --remsim-arg=-P \
  --remsim-arg=0x60e3 \
  --remsim-arg=-C \
  --remsim-arg=1 \
  --remsim-arg=-I \
  --remsim-arg=0 \
  --remsim-arg=-S \
  --remsim-arg=0
```

Path-based selector example:

```bash
yggdrasim-hil-supervisor \
  --reader-index 0 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3 \
  --remsim-arg=-H \
  --remsim-arg=<usb-path> \
  --remsim-arg=-C \
  --remsim-arg=1 \
  --remsim-arg=-I \
  --remsim-arg=0 \
  --remsim-arg=-S \
  --remsim-arg=0
```

Practical notes:

- the remsim client command defaults to the local bridge host / port and the configured client ID / slot
- do not force a fixed ATR for normal bridge use; the bridge pushes the physical card ATR
- if you already know the exact selector that works on your host, keep using it
- `-H`, `-V/-P`, and other SIMtrace2 selectors are host-setup dependent
- when forwarding remsim flags that start with `-`, prefer `--remsim-arg=<value>` form
- if you want to run the remsim client by hand for debugging, disable supervisor management with `--no-remsim-client`

## 6. Attach Wireshark

The bridge mirrors card traffic to GSMTAP on UDP `4729` by default.

From the main YggdraSIM wrapper, the HIL start flow now offers three attach modes:

- raw APDU flow only
- raw APDU flow plus Wireshark
- decoded APDU view in the current terminal instead of the raw APDU log

Useful filters:

```text
udp.port == 4729
```

or:

```text
gsmtap
```

If your Wireshark SIM dissector is older and shows malformed packets, start the bridge with:

```bash
--gsmtap-compat wireshark44
```

## 7. Use YggdraSIM from the side while the bridge is active

When the relay marker exists, card access through `create_card_connection()` is automatically redirected to the bridge relay.

That means these paths can continue to work while the bridge owns the reader:

```bash
python -m SCP11.local_access --cmd "STATUS; EXIT"
python -m SCP11.eim_local --cmd "DISCOVER; EXIT"
python -m SCP11.live --cmd "STATUS; EXIT"
```

Important limitations:

- this is one live card session
- the bridge serializes APDUs, but it does not isolate state
- any APDU you send from YggdraSIM can change what the modem sees next

Do not run raw external `pyscard` scripts directly against the reader while the bridge is active unless they are explicitly coded to use the relay URL.

If you need to point a custom client straight at the relay:

```bash
export YGGDRASIM_CARD_RELAY_URL=http://127.0.0.1:<relay-port>/apdu
```

## 8. Live APDU view

The dedicated tap / file-trace workflow has been removed.

Current behaviour:

- starting the HIL session from the main wrapper starts the supervisor, bridge, and local `osmo-remsim-client-st2`
- the wrapper prompts for one of three attach modes before entering the live session
- `raw APDU flow only` disables GSMTAP and shows only the journal-derived APDU stream in the terminal
- `raw APDU flow + Wireshark` keeps the raw journal-derived APDU stream in the terminal and launches Wireshark for GSMTAP decode
- `decoded APDU view` keeps GSMTAP enabled and opens the in-terminal decoded viewer instead of the raw APDU stream

That means the operator flow is now:

1. start the HIL from the YggdraSIM wrapper
2. choose `raw`, `raw + Wireshark`, or `decoded view`
3. inspect the live modem / card traffic in the selected viewer
4. stop the HIL from the wrapper when the session is complete

The local relay status JSON still exposes bridge health such as:

- `status`
- `apduUrl`
- `statusUrl`
- `modemRefreshUrl`
- `controlConnected`
- `bankdConnected`

## 9. Refresh the modem after card-side changes

The bridge exposes a modem REFRESH path and the SCP11 local shells can use it.

Manual examples:

```bash
python -m SCP11.local_access --cmd "REFRESH-MODEM; EXIT"
python -m SCP11.local_access --cmd "REFRESH-MODEM uicc-reset; EXIT"
python -m SCP11.eim_local --cmd "REFRESH-MODEM euicc-profile-state-change; EXIT"
```

Current default mode is the eUICC-oriented profile state change refresh:

- `euicc-profile-state-change`

More aggressive manual override:

- `uicc-reset`

Automatic queueing is also wired into the relevant local SCP11 flows after successful state changes such as:

- `ENABLE-PROFILE`
- `DISABLE-PROFILE`
- `DELETE-PROFILE`
- `EUICC-MEMORY-RESET`

## 10. Shutdown behavior

Expected safe deactivation behavior:

- stopping the supervisor stops the bridge child
- unplugging the SIMtrace2 causes the supervisor to stop the bridge child
- `state/hil_bridge_card_relay.json` is removed
- direct PC/SC access to the reader works again

This is the main reason to prefer `yggdrasim-hil-supervisor` over the manual bridge command.

## 11. Offline pcap replay and session-key unwrap

The decoded-APDU TUI doubles as an offline review surface. Offline mode
reuses the same `run_live_decode_tui` entry point as the live capture
path but reads a saved pcap via `tshark -r` instead of tailing a live
FIFO. No supervisor, no bridge, no systemd touch; the reader is never
opened.

### 11.1 Launch paths

From the main wrapper:

```bash
python main/main.py --open-pcap /path/to/capture.pcapng
python main/main.py \
    --open-pcap /path/to/capture.pcap \
    --keybag    /path/to/session.keys.json
```

From the `[B]` HIL Bridge Session menu, pick `[3] Open saved .pcap
(offline review, no bridge)`. The prompt first offers a native file
picker, then falls back to manual path entry, and finally asks for an
optional keybag JSON path.

### 11.2 Keybag auto-discovery

When no explicit `--keybag` / prompt path is given, sidecar keybags
are auto-discovered in this order:

1. `<pcap>.keys.json` (capture path + `.keys.json`)
2. `<stem>.keys.json` (capture path with extension stripped + `.keys.json`)

Both locations are checked before the TUI launches. A missing or
unreadable keybag is non-fatal — ciphered APDUs simply stay wrapped
in the TUI.

### 11.3 Producing a keybag

Keybags are produced by the same shells that build the secure
channel.

SCP03, after `AUTH-SD`:

```text
[APDU] > AUTH-SD
[A0...00] > EXPORT-KEYBAG /path/to/session.keys.json case-1234
```

SCP11 Local Access, after any BSP-building verb (`LOAD-PROFILE`,
`ENABLE-PROFILE`, `DISABLE-PROFILE`, `DELETE-PROFILE`,
`STORE-METADATA`, `UPDATE-METADATA`):

```text
[Local SMDPP] > LOAD-PROFILE
[Local SMDPP] > EXPORT-KEYBAG /path/to/session.keys.json case-1234
```

Non-interactively:

```bash
python -m SCP11.local_access --dump-keybag /path/to/session.keys.json
python -m SCP11.local_access --cmd "LOAD-PROFILE" \
    --dump-keybag /path/to/session.keys.json
```

`python -m SCP11.live --dump-keybag /path/...` is an intentional
**no-op stub**. In live mode the SCP11c BSP keys are derived inside
the eUICC during BPP processing and never reach the host, so the live
relay has nothing to export. The flag prints a clear guidance message
and exits with code `2`.

### 11.4 Keybag JSON schema

```json
{
  "format": "yggdrasim-hil-keybag/v1",
  "entries": [
    {
      "label": "case-1234",
      "protocol": "SCP03",
      "aid_hex": "A000000151000000",
      "s_enc_hex": "...32 hex chars...",
      "s_mac_hex": "...32 hex chars...",
      "s_rmac_hex": "...32 hex chars...",
      "ssc_hex": "0000000000000000",
      "chaining_value_hex": "",
      "block_nr": 0
    }
  ]
}
```

Notes:

- `format` must be `yggdrasim-hil-keybag/v1`.
- `entries` is a list. A single file can hold multiple SCP03 and
  SCP11c sessions against the same card; the replay engine matches by
  `protocol` and `aid_hex`.
- `protocol` is either `"SCP03"` or `"SCP11c"`.
- SCP11c entries populate `s_enc_hex` / `s_mac_hex`, the MAC chaining
  value in `chaining_value_hex`, and the per-session block counter in
  `block_nr`. `s_rmac_hex` and `ssc_hex` may be empty for SCP11c.
- SCP03 entries populate all five crypto fields (S-ENC, S-MAC, S-RMAC,
  SSC, chaining value).

### 11.5 Replay engine internals

`Tools.HilBridge.scp_replay.ScpReplayEngine` keeps per-session
runtimes and unwraps APDUs whose CLA has the secure-messaging bit
(`0x04`) set.
`Tools.HilBridge.live_decode_state.LiveDecodeStateTracker` feeds the
engine the current AID based on the SELECT history of the capture.
Matched APDUs gain a `[plaintext]` row in
`StatefulFrameAnnotation.context_lines`; unmatched APDUs stay wrapped.

The engine is instantiated fresh on every annotation rebuild, so
moving between frames in the TUI does not drift the counters.

## 12. Troubleshooting

### SIMtrace2 not detected

Check:

```bash
lsusb | rg -i 'simtrace|sysmocom|1d50:60e3'
```

If the supervisor state file shows `usbPresent: false`, the bridge child will not be started.

### Supervisor uses polling instead of udev

If the log says `falling back to lsusb polling: No module named 'pyudev'`, install `pyudev` in the same environment:

```bash
python -m pip install pyudev
```

### `osmo-remsim-client-st2` cannot open the SIMtrace2

Try the explicit USB selectors:

- `-H <usb-path> -C 1 -I 0 -S 0`
- `-V 0x1d50 -P 0x60e3 -C 1 -I 0 -S 0`

Also confirm the board is really in the relay / card-emulation firmware mode.

### YggdraSIM falls back to direct PC/SC

Check whether `state/hil_bridge_card_relay.json` exists and contains a live `apduUrl`.

If the relay marker is missing, the common backend cannot discover the bridge and will try the direct reader path.

### Sharing violation on the reader

This usually means one of these:

- the bridge is still running and you expected it to be down
- a stale older bridge process is still alive
- a raw direct PC/SC tool is colliding with the bridge

Stop the supervisor, confirm the relay marker disappears, and then retry direct PC/SC access.

### Wireshark is quiet

If the bridge is running but Wireshark sees nothing:

- confirm the modem / remsim client is actually exchanging APDUs
- confirm Wireshark is watching UDP `4729`
- confirm GSMTAP is not disabled with `--no-gsmtap`

## Recommended steady-state workflow

1. Start `yggdrasim-hil-supervisor`.
2. Confirm `state/hil_bridge_supervisor.json` and `state/hil_bridge_card_relay.json`.
3. Start `osmo-remsim-client-st2`.
4. Open Wireshark on UDP `4729`.
5. Use YggdraSIM side commands only through normal module entry points, not raw direct `pyscard`.
6. After card-side state changes, queue `REFRESH-MODEM` if the shell did not already do it for you.
7. Stop the supervisor when you want the reader fully released.
