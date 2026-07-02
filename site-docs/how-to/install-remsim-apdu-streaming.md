---
title: Install RemSIM / APDU Streaming
tags:
  - how-to
  - install
  - remsim
  - simtrace2
  - apdu
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Install RemSIM / APDU Streaming

## Goal

Prepare a Linux lab host or Raspberry Pi for the full APDU streaming stack:
YggdraSIM HIL bridge, Osmocom RemSIM client for SIMtrace2, GSMTAP capture,
and optional Card Bridge remote-card input.

Use this page before [Run a HIL Capture](run-hil-capture.md) or
[Remote APDU Streaming](remote-apdu-streaming.md).

## Supported hosts

| Host | Recommended install |
| --- | --- |
| Linux x86_64 lab host | `scripts/install/install-linux.sh --flavor full` |
| Raspberry Pi OS 64-bit | `scripts/install/install-raspberrypi.sh --flavor full` |
| Source checkout | `python -m pip install -e '.[full]'` or `'.[hil]'` |
| Windows / macOS | clean tools plus Card Bridge / remote APDU streaming; direct SIMtrace2/RemSIM HIL is Linux-only |

## System packages

Debian / Ubuntu / Raspberry Pi OS:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
  pcscd pcsc-tools libpcsclite1 libpcsclite-dev \
  usbutils dfu-util git build-essential pkg-config \
  autoconf automake libtool \
  wireshark tshark termshark \
  python3 python3-venv python3-pip
```

Add the user to groups needed by your distro:

```bash
sudo usermod -a -G plugdev,wireshark "$USER"
```

Log out and back in after group changes.

## External dependency references

Use distro packages where possible. These upstream links are the reference
points when a package is missing, stale, or needs to be built from source.

| Dependency | Used for | Upstream install/source reference |
| --- | --- | --- |
| Osmocom RemSIM / `osmo-remsim-client-st2` | SIMtrace2 RemSIM client attached to the HIL bridge | [Osmocom RemSIM](https://osmocom.org/projects/osmo-remsim/wiki), [Osmocom binary packages](https://osmocom.org/projects/cellular-infrastructure/wiki/Binary_Packages), [osmo-remsim source](https://gitea.osmocom.org/sim-card/osmo-remsim) |
| SIMtrace2 firmware and tools | card-emulation firmware, board utilities, USB bring-up | [SIMtrace2 wiki](https://osmocom.org/projects/sim-card/wiki/SIMtrace2), [firmware binaries](https://ftp.osmocom.org/binaries/simtrace2/firmware/), [simtrace2 source](https://gitea.osmocom.org/sim-card/simtrace2) |
| PC/SC Lite / `pcscd` | reader middleware on Linux and BSD-like hosts | [PCSC-Lite project](https://pcsclite.apdu.fr/), [pcsc-tools](https://pcsc-tools.apdu.fr/) |
| `dfu-util` | flashing SIMtrace2 card-emulation firmware | [dfu-util homepage](https://dfu-util.sourceforge.net/) |
| Wireshark / `tshark` / `dumpcap` | GSMTAP capture, live decode, offline pcap review | [Wireshark downloads](https://www.wireshark.org/download.html), [Wireshark documentation](https://www.wireshark.org/docs/) |
| Termshark | optional terminal UI around `tshark` on headless rigs | [Termshark](https://termshark.io/) |
| OpenSSH | `ssh -L` / `ssh -R` APDU bridge forwarding | [OpenSSH manual pages](https://www.openssh.org/manual.html) |
| Raspberry Pi OS | supported arm64 lab rig baseline | [Raspberry Pi software](https://www.raspberrypi.com/software/) |
| pySim | optional SAIP/SCP11 helper dependency pulled by YggdraSIM extras | [pySim GitHub mirror](https://github.com/osmocom/pysim), [pySim Osmocom source](https://gitea.osmocom.org/sim-card/pysim) |

## Install YggdraSIM full/HIL support

Release script:

```bash
scripts/install/install-linux.sh --flavor full
```

Source checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[full]'
```

For a lighter source install that only adds the HIL runtime:

```bash
python -m pip install -e '.[hil]'
```

## Install or locate `osmo-remsim-client-st2`

First check whether your distro already provides it:

```bash
command -v osmo-remsim-client-st2
osmo-remsim-client-st2 --help
```

If it is not packaged for your host, build/install it using your normal
Osmocom toolchain process and make sure the resulting executable is on
`PATH`, or note the absolute path for the supervisor's `--remsim-binary`
/ GUI **RPi REMSIM binary** field.

Validate the path:

```bash
/usr/local/bin/osmo-remsim-client-st2 --help
```

## Prepare SIMtrace2

1. Flash or update the SIMtrace2 card-emulation firmware. Use
   `guides/SIMTRACE2_CARDEM_GUIDE.md` for the firmware procedure.
2. Confirm USB enumeration:

    ```bash
    lsusb | rg -i 'simtrace|1d50:60e3'
    ```

3. Confirm optional tool visibility:

    ```bash
    command -v simtrace2-list || true
    command -v simtrace2-tool || true
    ```

## Verify PC/SC

```bash
systemctl status pcscd --no-pager
pcsc_scan -n
python main/main.py --card-bridge --card-bridge-no-token --card-bridge-reader-index 0
```

Stop the bridge with `Ctrl-C` after the startup banner confirms the reader
opened. On HIL-capable Linux hosts you can also list readers through the HIL
bridge:

```bash
python -m Tools.HilBridge.main --list-readers
```

If the reader is remote, start the Card Bridge on the reader host and validate
the SSH tunnel before starting HIL:

```bash
python main/main.py --card-bridge \
  --card-bridge-port 8642 \
  --card-bridge-reader-index 0

curl -s http://127.0.0.1:8642/ping
```

## Run doctor

```bash
python main/main.py --doctor
```

Expected HIL-related rows:

- `hil-bridge-runtime`
- `osmo-remsim-client-st2`
- `tshark`
- `dfu-util`
- `lsusb`
- PC/SC reader status

Warnings for optional tools are acceptable for offline-only work. A live
SIMtrace2 rig needs the RemSIM client and USB visibility.

## First local HIL start

```bash
yggdrasim-hil-supervisor \
  --reader-index 0 \
  --host 127.0.0.1 \
  --port 9997 \
  --advertise-host 127.0.0.1 \
  --usb-vidpid 1d50:60e3
```

If the RemSIM binary is not on `PATH`, pass it explicitly:

```bash
yggdrasim-hil-supervisor \
  --reader-index 0 \
  --remsim-binary /usr/local/bin/osmo-remsim-client-st2 \
  --usb-vidpid 1d50:60e3
```

## First remote-card HIL start

After Card Bridge and SSH forwarding are ready:

```bash
yggdrasim-hil-supervisor \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
  --apdu-timeout-ms 30000 \
  --usb-vidpid 1d50:60e3
```

This keeps the modem/SIMtrace2 rig local to the Linux host while APDUs are
served by the workstation card through SSH.

From the unified CLI you can manage the reader-side piece without opening
the GUI:

```bash
python main/main.py
# choose [CB] Card Bridge / Remote APDU Streaming
```

The `[CB]` menu can start or stop the local Card Bridge, print SSH tunnel
commands, apply `--remote-card-url` / token-file settings to the current CLI
session, and probe `/ping` plus authenticated `/status`.

## Optional `systemd --user` service

Copy the example:

```bash
mkdir -p ~/.config/systemd/user
cp guides/systemd/yggdrasim-hil-supervisor.service.example \
  ~/.config/systemd/user/yggdrasim-hil-supervisor.service
```

Edit:

- `WorkingDirectory`
- Python or executable path
- reader selector or remote-card flags
- `--remsim-binary` if needed
- `--usb-vidpid`

Then:

```bash
systemctl --user daemon-reload
systemctl --user start yggdrasim-hil-supervisor.service
systemctl --user status yggdrasim-hil-supervisor.service
```

For unattended Raspberry Pi rigs:

```bash
loginctl enable-linger "$USER"
```

## Validation checklist

- `pcsc_scan -n` sees the card or Card Bridge `/status` returns an ATR
- `lsusb` sees the SIMtrace2
- `osmo-remsim-client-st2 --help` works
- `python main/main.py --doctor` reports HIL readiness
- `python main/main.py` -> `[CB]` -> `[3]` probes the configured bridge
- `state/hil_bridge_supervisor.json` shows `status: running`
- `state/hil_bridge_card_relay.json` shows `status: ok`
- Wireshark or `tshark` sees GSMTAP on UDP `4729`
- the GUI live APDU dock receives rows during card traffic

## Related pages

- [Remote APDU Streaming](remote-apdu-streaming.md)
- [Run a HIL Capture](run-hil-capture.md)
- [Universal GUI Command Center](../subsystems/gui-command-center.md)
- [HIL Bridge](../subsystems/hil-bridge.md)
- `guides/INSTALL_FULL.md`
- `guides/INSTALL_RASPBERRYPI.md`
- `guides/SIMTRACE2_CARDEM_GUIDE.md`
