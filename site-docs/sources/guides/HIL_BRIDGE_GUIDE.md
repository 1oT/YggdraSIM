<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# HIL Bridge Guide

This guide covers the YggdraSIM hardware-in-the-loop path built around:

- a physical card in a PC/SC reader
- a sysmocom SIMtrace2 flashed for relay / card-emulation use
- `osmo-remsim-client-st2` on the host
- the YggdraSIM HIL bridge on `127.0.0.1:9997`
- GSMTAP mirroring to Wireshark on UDP `4729`
- brokered side access from YggdraSIM through the local APDU relay
- optional remote-card input from Card Bridge over an SSH tunnel

> **Naming note.** "sysmocom SIMtrace2" is the USB product identifier
> that the Linux `lsusb` tool reports for VID:PID `1d50:60e3`. It is
> referenced in this guide solely as a device identifier so the HIL
> supervisor can find the physical hardware; it is not a vendor
> endorsement, partnership, or certification. The same applies to
> `osmo-remsim-client-st2`, which is the upstream tool name, and to the
> other board names in section 2, which are the USB product identifiers
> of the upstream SIMtrace2 firmware.

> **Build flavor note.** The direct SIMtrace2/RemSIM HIL bridge is
> Linux-only and is bundled in the **full** executable and in source
> checkouts installed with the `[hil]` / `[full]` extras. The **clean**
> executable shipped for Windows, macOS, Linux, and Raspberry Pi still
> includes Card Bridge / remote APDU streaming, but intentionally omits
> this direct local rig path; the launcher still renders a menu entry
> explaining where to find the full build. See
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

### Optional: stream the card from a remote workstation over SSH

The default topology assumes the physical card sits in the same host
that runs `pcscd` + `simtrace2` + the modem. When the rig lives in a
different room (or a different building) than the operator's
workstation, the card itself can be moved off the rig and streamed
back over the SSH tunnel that already terminates the bridge's HTTP
endpoints. The modem, GSMTAP capture, and `osmo-remsim-client-st2`
keep running on the rig exactly as today; only the card moves.

```text
operator workstation                          rig (modem + simtrace2)
--------------------------                    -------------------------
physical card in PC/SC reader ─┐              ┌─ modem
                               │              │
yggdrasim-card-bridge          │── SSH ─────  YggdraSIM HIL bridge
(publishes /apdu over HTTP)    │  SSH forward (RemoteRelayCardChannel)
                               │              │
                              :8642 ←──────── /apdu
                                              │
                                              ├─ GSMTAP UDP -> Wireshark
                                              └─ HTTP APDU relay
                                                 (rig-side surface
                                                  unchanged: any
                                                  SCP03 / SAIP
                                                  consumer keeps
                                                  using the same
                                                  endpoint)
```

Setup, end-to-end:

1. **On the operator workstation**, plug the card into a local PC/SC
   reader and start the publisher. The first run prints a bearer-
   token fingerprint and writes the actual token under
   `${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token`
   with mode 0600:

   ```bash
   yggdrasim-card-bridge --port 8642
   ```

2. Open the SSH tunnel so the publisher's loopback port is reachable
   on the rig's loopback interface. Use one of these two equivalent
   forms, depending on where you run the `ssh` command:

   ```bash
   # Run on the rig, connecting to the reader workstation:
   ssh -fN -L 8642:127.0.0.1:8642 operator@workstation

   # Or run on the reader workstation, connecting to the rig:
   ssh -fN -R 8642:127.0.0.1:8642 operator@rig-host
   ```

   Copy the token file to the rig, or read it via `scp` and stash it
   with `chmod 600`:

   ```bash
   scp operator@workstation:~/.config/yggdrasim/card_bridge/8642.token \
       ~/.config/yggdrasim/card_bridge/8642.token
   chmod 600 ~/.config/yggdrasim/card_bridge/8642.token
   ```

3. **On the rig**, start the HIL bridge with the remote-card flags.
   The local `--reader-index` / `--reader-name` flags are ignored in
   this mode -- the card lives at the other end of the tunnel:

   ```bash
   yggdrasim-hil-bridge \
     --remote-card-url http://127.0.0.1:8642/apdu \
     --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
     --apdu-timeout-ms 30000
   ```

   The bridge logs its card source on startup
   (`Card source: remote (remote: <reader>)`) so the topology is
   visible at a glance. Equivalent env vars are
   `YGGDRASIM_HIL_REMOTE_CARD_URL` and
   `YGGDRASIM_HIL_REMOTE_CARD_TOKEN_FILE`. `--apdu-timeout-ms` is
   optional (default 30000); raise it for slower eUICC operations or
   high-latency SSH paths.

GSMTAP capture, the bridge's own HTTP `/apdu` relay, the supervisor,
and every YggdraSIM consumer keep working unchanged -- they all sit
upstream of the card-source decision and don't observe the swap.
The rig-side relay exposes `apduUrl`, `statusUrl`, and `cardResetUrl`;
YggdraSIM tools on the rig discover that relay through the runtime
marker while the bridge is active.
Drop the `--remote-card-url` flag to fall back to the local PC/SC
path; the existing physically-connected topology is preserved
byte-for-byte.

For a shorter recipe with only the Card Bridge, SSH, and HIL flags,
see `site-docs/how-to/remote-apdu-streaming.md`. For the full Linux /
Raspberry Pi package checklist, RemSIM setup, and service install
flow, see `site-docs/how-to/install-remsim-apdu-streaming.md`.

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
lsusb -d 1d50:
```

Example:

```text
Bus 003 Device 042: ID 1d50:60e3 OpenMoko, Inc. Osmocom SIMtrace 2
Bus 003 Device 026: ID 1d50:616e OpenMoko, Inc. ngff-cardem
```

The supervisor watches every board that runs the SIMtrace2 firmware by its
USB ID, the list the upstream host tools match (`osmo_st2_compatible_dev_ids`
in simtrace2 `host/lib/usb_util.c`), so no selector is needed for these:

| VID:PID | Board |
|---|---|
| `1d50:60e3` | SIMtrace2 |
| `1d50:616e` | ngff-cardem (M.2 modem carrier with card emulation) |
| `1d50:4004` | QMOD |
| `1d50:4001` | OWHW |
| `1d50:616d` | octsimtest |

The REMSIM client and the pre-session reset (section 5.1) take the board
whose active configuration has the card-emulation interface (class `ff`,
subclass `02`; `simtrace2-list` shows it as `CardEmulator Modem 1`). A board
running the sniffer firmware, or one in its DFU bootloader, which keeps the
same USB ID, gets no client and no reset, and the supervisor state says so.
With two card-emulation boards attached the supervisor takes the first one
and logs a warning; pin one with `--remsim-arg` selectors (section 5 shows
the form).

List PC/SC readers:

```bash
python -m Tools.HilBridge.main --list-readers
```

Example:

```text
0: Example USB Smart Card Reader [Example Reader] 00 00
1: Example Contacted SmartCard Reader (0123456789ABCD) 01 00
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

- `--usb-vidpid` adds a USB ID to the boards of section 2, which the supervisor watches without it; `1d50:60e3` above is one of them, so the line changes nothing and is kept for existing units.
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
- `cardResetUrl`
- the selected `reader`
- the card `atr`

The bridge log should also print the relay URL:

```text
Card relay available at http://127.0.0.1:45007/apdu
```

### 4.1 Sim-backend interaction with SIMtrace2 / REMSIM

`YGGDRASIM_CARD_BACKEND` only changes which card the bridge talks to.
It does **not** disable the modem-in-the-loop path. The supervisor
keeps two independent gates:

| Card backend | SIMtrace2 USB | Bridge child | REMSIM client |
|--------------|---------------|--------------|---------------|
| reader       | present       | running      | running       |
| reader       | absent        | down (`waiting-usb`) | down  |
| sim          | present       | running      | running (modem-in-loop sim) |
| sim          | absent        | running (relay-only sim) | down |

Practical consequences:

- Sim mode with the SIMtrace2 cable still attached behaves exactly
  like reader mode from the modem's point of view -- REMSIM stays
  alive so the modem keeps getting answers from the bridge -- except
  the bridge serves APDUs from the simulator instead of the PC/SC
  reader.
- Sim mode without SIMtrace2 attached still serves the YggdraSIM-side
  HTTP relay (`apduUrl`, `statusUrl`, `cardResetUrl`); REMSIM is
  intentionally absent because there is nothing for it to connect
  to.
- Yanking the SIMtrace2 cable while sim mode is active drops REMSIM
  but leaves the bridge running. Plugging it back in spawns REMSIM
  again on the next reconcile pass.

The supervisor JSON reports the new `cardBackendGate` field
(`reader` or `sim`) so operators can see at a glance which gating
matrix is in effect, alongside the regular `usbPresent`,
`bridgeRunning`, and `remsimClientRunning` flags.

Toggling between `reader` and `sim` between sessions is
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

### 5.1 ATR seeding

The supervisor starts the client with `-a <ATR>`, so the emulated card
answers with the card's real ATR from its first activation and again after
every bankd reconnect. With a remote card the ATR comes from the relay's
`statusUrl`; with a local reader it comes from the relay marker the bridge
child publishes once the reader is open, and the client start waits up to
5 s for that marker.

Without the seed the client presents its own `3B00` placeholder at start-up
and every time it re-establishes the bankd link, until bankd sends a
`setAtrReq`; the bridge sends one only after the modem reports a slot-status
edge. The bankd link is re-established after every card failure the bridge
recovers from (a PC/SC timeout among them), and a modem that activates in
that gap reads `3B00` instead of the card. A modem that was already powered when the bridge came up produces
no edge at all, latches `3B00`, and reports `+CPIN: NOT INSERTED`
indefinitely. `AT+CFUN=0` / `AT+CFUN=1` is radio-only and does not clear it;
a full `AT+CFUN=1,1` re-activates the SIM interface and does.

The seed is skipped, leaving the previous behaviour, when `--remsim-arg=-a`
already carries an ATR, when the remote relay is unreachable or a local
bridge publishes no marker in time (for example under `--no-apdu-relay`), or
when the reported ATR's TS is not `'3B'` or `'3F'` (ETSI TS 102 221 V18.4.0
Annex D). Those cases log a warning.

The bridge waits up to 30 s for the card to answer one APDU
(`--apdu-timeout-ms`, or `YGGDRASIM_HIL_APDU_TIMEOUT_MS` from Environment ->
Configuration, which the HIL session passes on). With a remote card the Card
Bridge that holds the reader applies its own wait (same default, same
variable on that host), and the relay request gives up after 30 s. An eUICC can hold a command
for seconds while the board keeps the modem waiting with NULL procedure
bytes; a timeout closes the bankd link and re-opens the reader, which the
modem sees as a card reset, so keep the value above the card's slowest step.

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
- `-H`, `-V/-P`, and other SIMtrace2 selectors are host-setup dependent; an ngff-cardem takes `-P 0x616e`
- any selector passed this way replaces the supervisor's own board choice (section 2), including its refusal to start a client for a board without card emulation
- when forwarding remsim flags that start with `-`, prefer `--remsim-arg=<value>` form
- if you want to run the remsim client by hand for debugging, disable supervisor management with `--no-remsim-client`

### 5.1 Pre-session board reset (remote reset-button equivalent)

A SIMtrace2 that has been through a few sessions can wedge: the cardem
state machine keeps stale ATR / PTS state, or `osmo-remsim-client-st2`
inherits a half-open USB endpoint. On a desk that is fixed by pressing
the board's reset button. On a rig in another building, needing a human
to press a button defeats the point of a remote rig.

The supervisor therefore reboots the board itself before every session,
without any firmware modification. Osmocom's cardem firmware already
resets its own microcontroller when USB drops below the `CONFIGURED`
state -- see `firmware/apps/cardem/main.c` upstream:

```c
if (USBD_GetState() < USBD_STATE_CONFIGURED) {
    /* HACK: we don't really deal with USB disconnect yet,
     * so let's just reset the entire uC if this happens */
    TRACE_INFO("Resetting uC on USB disconnect\n\r");
    NVIC_SystemReset();
}
```

`NVIC_SystemReset()` is exactly what the physical reset button
triggers, so any host-side action that de-configures the device gives
the same clean slate.

Modes, selected with `--simtrace-reset` or `YGGDRASIM_HIL_SIMTRACE_RESET`:

| Mode | What it does | Needs |
|------|--------------|-------|
| `usb-reset` *(default)* | `USBDEVFS_RESET` on `/dev/bus/usb/BBB/DDD` -- the kernel drives a port reset, the firmware reboots | write access to the device node |
| `port-power` | VBUS cycle through `uhubctl`; a true unplug/replug of the board | `uhubctl` plus a hub with per-port power switching |
| `auto` | `usb-reset`, falling back to `port-power` when it fails | as above |
| `off` | no automatic reset | -- |

> **This resets the board, not the card.** In this topology the SIM
> lives in the PC/SC reader; the SIMtrace2 only emulates a card toward
> the modem. Neither mode touches the card unless the reader happens to
> hang off the same switched hub port. Card state is cleared separately
> -- see [5.2](#52-card-session-hygiene).

> **On an ngff-cardem the modem restarts too.** That board carries the
> modem, and its firmware cuts the modem's supply for 200 ms on every
> switch between the board's own SIM slot and the emulated card
> (`sim_switch_use_physical`, simtrace2
> `firmware/libboard/ngff_cardem/source/sim_switch.c`): once when the reset
> reboots the board, which starts on its SIM slot, and again when the REMSIM
> client selects the emulated card. The client then pulses the modem's
> reset line (PERST#). The modem's USB ports re-enumerate each time, so a
> modem terminal or ModemManager loses its port for a few seconds after
> every session start.

Ordering inside the supervisor is deliberate:

1. the remsim client is stopped, so the bus is never reset underneath an
   open libusb handle
2. the board is reset and the supervisor waits for it to re-enumerate
3. the USB snapshot is re-read -- **a reset changes the device's USB
   address**, and the generated remsim command pins it with `-A`, so the
   bridge and client are always started from the post-reset snapshot

`--simtrace-reset-min-interval` (default 30 s) is a floor between two
automatic resets inside one supervisor lifetime, so a crash-looping
bridge child cannot power-cycle the board in a tight loop. It does not
throttle operator-driven session starts: those restart the supervisor,
which starts the interval fresh.

Give the operator's account access to the device node once, so the
unprivileged `systemd --user` supervisor can issue the ioctl:

```bash
sudo tee /etc/udev/rules.d/60-simtrace2.rules >/dev/null <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="60e3", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="616e", MODE="0660", GROUP="plugdev", TAG+="uaccess"
EOF
sudo usermod -a -G plugdev "$USER"
sudo udevadm control --reload-rules && sudo udevadm trigger
```

The second line is for an ngff-cardem. Both boards keep their USB ID in the
DFU bootloader, so the rule also lets an unprivileged `dfu-util` update them.

For the VBUS variant, find the hub location with `uhubctl` and pin it:

```bash
uhubctl                                   # prints e.g. "Current status for hub 1-1"
export YGGDRASIM_HIL_SIMTRACE_RESET=auto
export YGGDRASIM_HIL_UHUBCTL_LOCATION=1-1
export YGGDRASIM_HIL_UHUBCTL_PORT=2
```

The launcher and the GUI copy these into the generated `systemd --user`
unit, so the setting survives service restarts.

To reset the board by hand -- the remote equivalent of walking over and
pressing the button:

```bash
yggdrasim-hil-reset --usb-vidpid 1d50:60e3
```

Stop the session first; the reset refuses nothing, but resetting the bus
while a session holds the device only moves the problem.

The supervisor state file records what happened, under `simtraceReset`:

```bash
jq .simtraceReset ~/.local/state/yggdrasim/state/hil_bridge_supervisor.json
```

> **Do not use `dfu-util --detach` for this.** The DFU runtime interface
> in the application firmware latches `USB_DFU_MAGIC` before resetting,
> and the SIMtrace2 bootloader has no auto-boot timeout -- the board
> parks in DFU mode (`1d50:4004`) until somebody physically power-cycles
> it. That is precisely the situation a remote rig cannot recover from.

### 5.2 Card-session hygiene

Rebooting the board does not clear the card. The SIM sits in the PC/SC
reader and keeps its state across a SIMtrace2 reset exactly as it does
when you press the reset button: selected AID, open logical channels,
an established SCP03 / SCP11 secure channel, PIN verification status.

Three mechanisms clear it, all power-cycling the card with
`SCardReconnect(..., SCARD_UNPOWER_CARD)` and re-reading the ATR:

**Modem sessions.** When `osmo-remsim-client-st2` attaches -- or
re-attaches after the board reset -- the bridge power-cycles the card
and pushes the fresh ATR to the modem with `setAtrReq`. So every modem
session starts from a card that just came up.

**Modem resets.** The modem resets the emulated UICC, not the card: the
cardem firmware answers RST with the ATR it was given and reports the
edge to `osmo-remsim-client-st2`, which forwards it to the bridge as
`clientSlotStatusInd`. The bridge acts on that the way osmo-remsim's
bankd does -- a RST rising edge or a VCC drop power-cycles the card in
the reader before the modem's first post-reset command is served -- and
pushes the ATR to the board again when it changed (the board has already
answered that activation with the previous one; the new ATR serves the
next reset). This is what makes an eUICC profile switch land: the ISD-R
issues REFRESH in "UICC Reset" mode (SGP.02 v4.2 clause 3.2, step 7),
the terminal resets the UICC without a TERMINAL RESPONSE (ETSI TS 102 223
V18.3.0 clause 6.4.7), and the switch takes effect on that reset. A
bridge that stopped at the board left the eUICC serving the profile the
switch had just disabled, while the modem re-read it as the new one.

**Relay sessions.** Operator shells (SCP03, SCP80, SCP11) drive the same
card through the APDU relay, potentially while a modem session is live.
Each shell transacts under its own relay session id, and the bridge
power-cycles the card when that id first appears, when it is replaced by
another shell's, and when the shell disconnects. Without this the
secure channel an SCP11 session left open would still be there when the
modem next read the SIM.

A card power-cycle invalidates everyone's view of the card, so it also
drops the bankd side: `osmo-remsim-client-st2` re-handshakes and re-reads
the ATR rather than transacting against state that no longer exists.
Expect a modem re-attach whenever you start or finish shell work -- that
is the mechanism working, not a fault.

Watch it in the bridge log:

```text
Card power-cycled (relay session start (ygg-4213-9f2ab117)); reader ... ATR 3B9F...
Reset card for modem session; reader ... ATR 3B9F... reset={'mode': 'pcsc-reconnect-unpower'}
Card issued REFRESH (uicc-reset): the terminal resets the UICC instead of answering with TERMINAL RESPONSE; the card is power-cycled when the remsim client reports that reset
Modem slot status: RST active, VCC present, CLK unreported, card unreported
Modem reset the UICC (RST asserted, after REFRESH (uicc-reset)); card power-cycled, reader ... ATR 3B9F... reset={'mode': 'pcsc-reconnect-unpower'}
```

Set `YGGDRASIM_HIL_RELAY_SESSION_RESET=0` (or pass
`--no-relay-session-reset`) only for workflows that deliberately carry
card state across sessions -- for example driving a secure channel from
a shell and then inspecting it from another tool.

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

### 6.1 Modem-side SIM log

The bridge and a SIMtrace2 sniffer both show the SIM interface from the card
side. A modem with a Qualcomm baseband also logs it from its own side: the UIM
driver writes every character it sends and receives, with the modem's time
stamp, to the DIAG log item `LOG_UIM_DATA_C` (0x1098; 0x14CE on dual-SIM
builds). `yggdrasim-hil-modem-diag` reads that log from the modem's DIAG
port, rebuilds the T=0 exchanges and sends them into the same GSMTAP stream:

```bash
yggdrasim-hil-modem-diag --device /dev/serial/by-id/usb-Android_Android-if00-port0
```

The example is USB interface 0 (`if00`) of a modem that reports itself as
`Android`, which is where that by-id name comes from. `--device auto` takes
USB interface 0 of a modem the Linux `option` or `qcserial` driver serves and
looks it up again after every re-enumeration; a modem that puts DIAG on
another interface needs the path. Membership of the
`dialout` group is enough to open it; no `sudo`. Only one program may hold
the DIAG port, so stop QCSuper, SCAT or QXDM first. The command waits for
the port, and when the modem power-cycles it reopens the port once it is
back.

To have every HIL session start it, set `YGGDRASIM_HIL_MODEM_DIAG` to
`auto` or to the DIAG path (Environment -> Configuration in the GUI, `[E]`
in the launcher). The supervisor then runs the mirror as a child of its own
for the whole session, sending to the bridge's GSMTAP host and port. The
mirror sits outside the SIM path: when the modem is missing it waits, when
it exits the supervisor restarts it after 30 s (600 s after exit code 2, a
condition a restart will not change), and none of that touches the bridge,
the REMSIM client or the session status. The supervisor state reports it
under `modemDiag`.

The Wireshark a HIL session opens starts with the profile named in
`YGGDRASIM_HIL_WIRESHARK_PROFILE` (default `YggdraSIM-HIL`; `off` keeps the
last-used profile). YggdraSIM adds two files to that profile: filter
buttons -- **SIM side**, **Modem side**, **Modem notes**, **Modem cuts**,
**Exchanges**, **STK**, **TLS alerts** -- and coloring rules that show a TLS
certificate alert (at any level) or any fatal TLS alert in dark red on either
side, tint modem-side rows blue, notes amber and cut exchanges light red,
ahead of Wireshark's default rules. An encrypted alert cannot be read, so it
is not coloured. **STK** shows, on both sides, the toolkit traffic of ETSI
TS 102 221 V18.4.0 clause 14.6: TERMINAL PROFILE, ENVELOPE, FETCH and
TERMINAL RESPONSE (clause 14.6.3), STATUS, which the terminal sends for
proactive polling (clause 14.6.2), and every exchange whose answer announces
a proactive command: `91 XX` (clause 10.2.1.1), `62 F2` or `63 F2` (clause
10.2.1.3). BIP is part of it: OPEN CHANNEL, CLOSE CHANNEL, RECEIVE DATA and
SEND DATA arrive as FETCH answers and their results as TERMINAL RESPONSEs,
the Data available and Channel status events as ENVELOPEs (ETSI TS 102 223
V18.3.0 clauses 6.4 and 7.5). A filter sees one frame at a time, so the GET
RESPONSE that collects an ENVELOPE's answer data is left out unless the card
ended it with one of those status words; the modem's NULL holds and cut
exchanges stay under **Modem notes** and **Modem cuts**. Both files
open with a marker line; once Wireshark or you rewrite one without it, it is
left alone. If the profile cannot be prepared, Wireshark starts as before.
The decoded terminal view reads the bridge's own capture file, so it shows
the SIM side only.

That Wireshark also opens with its Time column on the UTC time of day each
frame was captured (`-t u`) rather than seconds since the first frame;
`journalctl --utc` prints the supervisor journal on the same clock.
`YGGDRASIM_HIL_WIRESHARK_TIME_FORMAT` takes any value of Wireshark's `-t`
option: `ud` adds the date, `a` and `ad` are local time, `r` is Wireshark's
relative default, and `.N` sets N decimals (`u.6`). Wireshark stores the
format in the profile when it exits, so `off` leaves the one last shown, and
a choice from View -> Time Display Format lasts until the next launch. A
value Wireshark would refuse counts as `off`. If the column is too narrow
for the longer value, widen it once; Wireshark keeps the width in the
profile.

The APDU dissector names a TLS alert in the row's Detail column, for
example `SEND DATA: channel 1, 7 bytes, fatal TLS alert bad_certificate (42)`
when the card rejects the server's certificate. A copy installed with
`yggdrasim-apdu-dissect install` loads before the one the HIL menu passes,
so it is the copy that decodes: re-run `install` after updating YggdraSIM,
or a stale copy hides newer decoding.

What it sends, all on UDP `4729`:

- one APDU frame per exchange, in the bridge's layout, so the APDU dissector
  decodes both sides the same way;
- the ATR frames the modem actually received;
- a log line (GSMTAP libosmocore log) for an exchange the card held with NULL
  procedure bytes or for at least `--hold-note-seconds` (default 0.5 s), for
  the PPS exchange, and for an exchange a reset cut short before its status
  word.

The modem-side frames carry GSMTAP antenna 1 and come from `127.0.0.2`; the
bridge and SIMtrace2 send antenna 0 from `127.0.0.1`. Wireshark 4.4 passes
SIM and log frames to their dissectors before it decodes the GSMTAP header,
so `gsmtap.antenna` stays empty; filter on the source or the raw byte:

- `ip.src == 127.0.0.2` -- modem side, live;
- `udp.payload[13:1] == 01` -- modem side, also in a saved pcap;
- `udp.payload[13:1] == 00` -- bridge or SIMtrace2 side.

What only the modem side shows: the ATR the modem got (the bridge mirrors the
reader's ATR, while a modem that activated before the bridge's `setAtrReq`
can have received the remsim client's `3B 00` stub), the PPS, the NULL bytes
SIMtrace2 drops, and whether the modem sent a command the card then held
through a reset. Hold times come from the modem's clock and are exact; the
frames themselves are sent when DIAG delivers the log, so their capture time
trails the bridge's frames by the DIAG latency.

`--capture-path` also writes the frames to a pcap, `--no-notes` leaves the
log lines out, and `--gsmtap-host` / `--gsmtap-port` / `--gsmtap-compat`
work as on the bridge.

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
- the GUI HIL dissector links decoded fields to the selected packet's
  byte dump when `tshark` exposes PDML offsets; hover a decoded row or
  byte to highlight the matching range, and click to pin that range

That means the operator flow is now:

1. start the HIL from the YggdraSIM wrapper
2. choose `raw`, `raw + Wireshark`, or `decoded view`
3. inspect the live modem / card traffic in the selected viewer
4. stop the HIL from the wrapper when the session is complete

The local relay status JSON still exposes bridge health such as:

- `status`
- `apduUrl`
- `statusUrl`
- `cardResetUrl`
- `controlConnected`
- `bankdConnected`

## 9. Shutdown behavior

Expected safe deactivation behavior:

- stopping the supervisor stops the bridge child
- unplugging the SIMtrace2 causes the supervisor to stop the bridge child
- `state/hil_bridge_card_relay.json` is removed
- direct PC/SC access to the reader works again

This is the main reason to prefer `yggdrasim-hil-supervisor` over the manual bridge command.

## 10. Offline pcap replay and session-key unwrap

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

From the `[B]` Local SIMtrace2 HIL Bridge Session menu, pick `[3] Open saved .pcap
(offline review, no bridge)`. The prompt first offers a native file
picker, then falls back to manual path entry, and finally asks for an
optional keybag JSON path.

### 11.2 Keybag auto-discovery

When no explicit `--keybag` / prompt path is given, sidecar keybags
are auto-discovered in this order:

1. `<pcap>.keys.json` (capture path + `.keys.json`)
2. `<stem>.keys.json` (capture path with extension stripped + `.keys.json`)

Both locations are checked before the TUI launches. A missing or
unreadable keybag is non-fatal -- ciphered APDUs simply stay wrapped
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

## 11. Troubleshooting

### SIMtrace2 not detected

Check:

```bash
lsusb -d 1d50:
```

If the supervisor state file shows `usbPresent: false`, the bridge child will not be started.
If the board is listed but the state reason starts with `No board in card emulation`, it
runs the sniffer firmware or sits in its DFU bootloader; `simtrace2-list` should show
`CardEmulator Modem 1` once the cardem firmware runs (`SIMTRACE2_CARDEM_GUIDE.md`).

### Supervisor uses polling instead of udev

If the log says `falling back to lsusb polling: No module named 'pyudev'`, install `pyudev` in the same environment:

```bash
python -m pip install pyudev
```

### `osmo-remsim-client-st2` cannot open the SIMtrace2

Try the explicit USB selectors:

- `-H <usb-path> -C 1 -I 0 -S 0`
- `-V 0x1d50 -P 0x60e3 -C 1 -I 0 -S 0` (`-P 0x616e` for an ngff-cardem)

Also confirm the board is really in the relay / card-emulation firmware mode.

### The board only behaves again after a physical reset

That is what the pre-session reset in [5.1](#51-pre-session-board-reset-remote-reset-button-equivalent)
is for. Check whether it is actually running:

```bash
jq .simtraceReset ~/.local/state/yggdrasim/state/hil_bridge_supervisor.json
```

- `"enabled": false` -- the mode is `off`; set `YGGDRASIM_HIL_SIMTRACE_RESET=usb-reset`
  and restart the supervisor.
- `last.error` mentioning *Permission denied* -- the supervisor cannot
  open `/dev/bus/usb/BBB/DDD`. Install the udev rule from 5.1.
- `last.reenumerated: false` -- the reset was issued but the board did
  not come back within the settle window. Raise
  `--simtrace-reset-settle-timeout`, and if the board is genuinely dead
  on the bus after a USB reset, switch to `port-power` so VBUS is cut
  as well.

If the board still misbehaves after a confirmed `usb-reset`, the state
going stale is not on the microcontroller. The card keeps its power and
its session across a board reset, so look at
[5.2](#52-card-session-hygiene) next: check the bridge log for a
`Card power-cycled` or `Reset card for modem session` line covering the
session that failed. If neither appears, the card was never cleared.

Note that `port-power` does not help here either unless the PC/SC
reader shares the switched hub port with the board -- the card is behind
the reader, not the SIMtrace2.

### The modem re-initialises after a REFRESH but still sees the old profile

An eUICC applies a profile switch at the next reset. The ISD-R issues
REFRESH in "UICC Reset" mode, the terminal resets the UICC without a
TERMINAL RESPONSE (ETSI TS 102 223 V18.3.0 clause 6.4.7), and the newly
enabled profile is what answers after the ATR. On the rig that reset
hits the SIMtrace2, which replays the ATR it holds; the card in the
reader is reset only because the bridge follows the
`clientSlotStatusInd` the remsim client forwards (see
[5.2](#52-card-session-hygiene)). A switch that landed logs three lines:

```text
Card issued REFRESH (uicc-reset): the terminal resets the UICC instead of answering with TERMINAL RESPONSE; the card is power-cycled when the remsim client reports that reset
Modem slot status: RST active, VCC present, CLK unreported, card unreported
Modem reset the UICC (RST asserted, after REFRESH (uicc-reset)); card power-cycled, reader ... ATR ... reset={'mode': 'pcsc-reconnect-unpower'}
```

If the first line appears and the third never does, the reset stopped at
the board and the modem is re-reading a card that was never reset. The
bridge says so on the modem's next command once the 10 s grace has
passed:

```text
REFRESH (uicc-reset) was served more than 10 s ago and the remsim client reported no UICC reset since; ...
```

Check the client. `osmo-remsim-client-st2` has to forward the modem's
RST and VCC edges as `clientSlotStatusInd` (osmo-remsim 1.2.0 does, and
logs `Tx clientSlotStatusInd(reset_act=1, ...)` when it happens); a
client that only prints `STATUS: flags=...` never tells the bridge.
Until that is in place, `yggdrasim-hil-reset` after the REFRESH forces a
re-attach, and the modem-session handshake power-cycles the card.

Rebooting the board on every REFRESH is not the fix. The board holds
only the ATR, never the profile; the file system the modem reads is the
card's, and the card is what has to be reset.

### The modem terminal

The HIL panel's modem terminal is always available on a build that
carries the HIL bridge. It needs no flag and no restart: what keeps it
safe is the command policy rather than a gate in front of it. It opens
no login shell and accepts only a known serial terminal (`tio`,
`minicom`, `picocom`, `screen`) against an explicit device path.

`sudo` and `doas` are allowed in front of that terminal, because a
serial device is often root-owned and a udev rule is not always yours to
write. They are allowed as a plain prefix only:

```text
sudo tio /dev/ttyUSB2          accepted
sudo -n tio /dev/ttyUSB2       accepted
sudo -s                        refused
sudo -i                        refused
sudo bash                      refused
sudo tio                       refused, no device path
```

Every option but `-n` is refused rather than reasoned about, so the word
after the wrapper is always the command that runs. Expect a password
prompt in the terminal unless that user has passwordless sudo for it.

Granting the device instead avoids the prompt entirely, and is the
better answer where you can write the rule: add the operator's group to
the device node the way the SIMtrace2 rule does.

### The modem terminal attaches to a port that answers nothing

A distribution that ships ModemManager claims a cellular modem's AT ports
the moment it enumerates, and it keeps them. The port still opens, so a
terminal attaches and simply sits there: ModemManager is consuming the
replies. Nothing in the terminal says so.

Check who holds it, naming the AT port for your modem:

```bash
sudo fuser -v /dev/ttyUSB2
systemctl is-active ModemManager
```

A rig modem is driven by hand, so hand the device back rather than
disabling the service for every other device on the host:

```bash
sudo tee /etc/udev/rules.d/62-modem-manual-control.rules >/dev/null <<'RULE'
SUBSYSTEM=="usb", ATTR{idVendor}=="<vid>", ATTR{idProduct}=="<pid>", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="<vid>", ATTRS{idProduct}=="<pid>", ENV{ID_MM_DEVICE_IGNORE}="1"
RULE
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --subsystem-match=tty --attr-match=idVendor=<vid>
sudo systemctl restart ModemManager
```

`fuser` should then report nobody, and `AT` should answer `OK`. Removing
the rule file and restarting ModemManager puts it back.

### The rig is up but the modem reports no SIM

`+CME ERROR: 10` for `AT+CPIN?` while the bridge reports its bankd side
attached is the expected state, not a fault. The card is presented to the
modem at activation, and a modem that was already powered when the rig
came up has nothing to re-read on its own.

Cycle the radio and the card appears:

```bash
printf 'AT+CFUN=0;+CFUN=1\r' | socat -T6 - /dev/ttyUSB2,b115200,raw,echo=0
```

That re-initialises the SIM interface in place and the card is readable
in a few seconds. `AT+CFUN=1,1` also works and is the wrong tool: it
reboots the modem, so the USB device disappears for about twenty seconds
and takes the AT port with it.

`yggdrasim-hil-supervisor` is not what sends this. The Remote Bridge rig
start issues it as its last step, once the path that feeds the modem is
up, because a refresh before that has nothing to find.

Afterwards `AT+CPIN?` reports `READY`, and `AT+CCID` reads the ICCID of
the card the rig is streaming, which is the quickest way to confirm the
modem is on the card you think it is.

Use `socat`, not `stty`. A USB serial modem rejects part of the raw mode
`stty` asks for and the whole command fails with it.

If the card never appears, check the card lease rather than the modem:
a rig whose reset is refused with `409 The card is leased by another
consumer` never re-presents the card, and the modem has nothing new to
read. `GET /lease` on the operator's Card Bridge names the holder, and a
holder of `""` means the lease was orphaned and should be force-released.

### The client log shows `ComponentType(1) != RemsimBankd`

osmo-remsim-client-st2 keeps two RSPRO links to the bridge, both to the
bridge's port (`-p`, 9997 by default): a control link in the remsim-server
role and a bankd link that carries the card traffic. The client sends the
same `connectClientReq` on both and checks the role named in the answer. A
link answered with the other role is closed, and the client re-dials it only
when the control link sends a new `configClientBankReq`; with both links
answered wrongly, the modem is left without a card until the client
restarts.

The bridge therefore keeps the roles apart by order. A failure closes only
the link it concerns: a card failure (a PC/SC timeout, a transmit error)
closes the bankd link and re-opens the reader, and a lost control link is
closed alone. A connection that arrives before the control link has
answered `configClientIdReq` is closed unanswered (the bridge logs
`Closing pending@...: control link not confirmed yet; the client re-dials
this link`), and the client re-dials it at once. A bridge restart stops the
client too, and a starting client
dials its bankd link only once the control link is configured.

The line can still appear when both links drop together, for example after
a keepalive timeout, and the client re-dials its bankd link first. That link
then comes back through the next `configClientBankReq`, and the bridge log
shows a fresh `Assigned ... as bankd connection`. These client lines around
a re-dial are expected on their own:

- `Connection to bankd lost` -- the bankd link dropped; the client waits for
  it in `WAIT_BANKD`.
- `Event MF_E_MDM_STATUS_IND not permitted` and `Event MF_E_SRVC_CONNECTED
  not permitted` in `WAIT_BANKD` -- modem status and a reconnected control
  link reported while the client waits for bankd; both are dropped.
- `transition to state WAIT_BANKD not permitted!` -- a `configClientBankReq`
  reached a client that already waits for bankd. The client re-dials bankd
  regardless.

A reconnected control link always sends `configClientBankReq`, and an
operational client answers it by dropping and re-dialling its bankd link,
so the modem sees a card reset even when only the control link was lost.
If no `Assigned ... as bankd connection` follows within a few seconds,
restart the HIL session.

### The modem resets the UICC after 120 s on a TERMINAL RESPONSE

The bridge log answers a FETCH with a RECEIVE DATA command, then shows
nothing for 120 s, then `Modem reset the UICC`; the modem-side mirror notes
`no status word before a new ATR; 178/178 command data bytes sent, ... NULL,
120 s after the terminal's last byte`. The modem did send its TERMINAL
RESPONSE. The SIMtrace2 board held it, keeping the modem waiting with NULL
procedure bytes, because its firmware ends a USB message of 128, 192 or 256
bytes without a zero-length packet, and the host only reads such a message
once the board sends the next one. That is any modem command carrying 114,
178 or 242 data bytes (Lc `72`, `B2`, `F2`); in practice a RECEIVE DATA that
returns the last 97, 160 or 224 bytes of a server response. Which response
does so is set by its length, so a card that has always worked fails on
every attempt once a server answer lands on one of those lengths.

The held command reaches the bridge after the reset. The bridge drops it
unanswered and logs `Dropping modem APDU ...: the modem sent it before
resetting the UICC`, naming the 192-byte USB message; it never forwards the
card's answer to a command sent before a reset, or to one a newer command
has superseded. Answering it would put the card's `6F00` on the modem's
first SELECT and every later answer one command late, which the modem
answers with more resets. The 120 s hold itself goes away only with
patched board firmware: `upstream_patches/osmocom-simtrace2-cardem-zlp/`
carries the patch, a journal scan (`repro_zlp_stall.py`) and an `AT+CSIM`
check; build and flash it as in [SIMTRACE2_CARDEM_GUIDE.md](SIMTRACE2_CARDEM_GUIDE.md).

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
6. Stop the supervisor when you want the reader fully released.
