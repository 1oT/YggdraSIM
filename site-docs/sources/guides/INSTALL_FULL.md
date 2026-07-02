<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Installation — Full Flavor (HIL-Capable)

The **full** flavor is the Linux-only superset of YggdraSIM. It packages
everything the clean flavor offers plus:

- the local SIMtrace2/RemSIM HIL runtime
- the `pyudev` dependency used by the supervisor for USB hot-plug events
- the `[B] Local SIMtrace2 HIL Bridge Session` entry in the main menu
- the `yggdrasim-hil-bridge` and `yggdrasim-hil-supervisor` console
  scripts

Because the HIL bridge drives a sysmocom SIMtrace2 through
`osmo-remsim-client-st2` and relies on udev, the full flavor is only
supported on Linux hosts. On Windows / macOS use
[`INSTALL_CLEAN.md`](INSTALL_CLEAN.md) instead.

## When to use the full flavor

- You have a SIMtrace2 board flashed with the relay / cardem firmware.
- You want modem ⇆ SIM traffic mirrored to Wireshark or the decoded
  in-terminal view.
- You need YggdraSIM to share a live card with the modem through the
  local APDU relay.
- You run the modem / SIMtrace2 rig on Linux but need to stream the
  physical card from an operator workstation over SSH.

If you just want to run the SIM simulator, the SAIP tooling, or the SCP11
flows, the clean flavor is enough.

## Pre-built artefacts

```text
yggdrasim-linux-x86_64-full-<version>
yggdrasim-linux-arm64-full-<version>
yggdrasim-gui-linux-x86_64-full-<version>
yggdrasim-gui-linux-arm64-full-<version>
```

Two full bundles are published:

- `linux-x86_64-full` — desktop / server / lab hosts.
- `linux-arm64-full`  — Raspberry Pi OS 64-bit and other arm64 Linux
  hosts. The arm64 bundle is built through QEMU/Buildx inside CI; see
  [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md) for Pi-specific
  setup.

Download and make it executable:

```bash
chmod +x yggdrasim-linux-x86_64-full-<version>
./yggdrasim-linux-x86_64-full-<version> --version
./yggdrasim-linux-x86_64-full-<version> --doctor
```

## Scripted install

Use `scripts/install/install-linux.sh --flavor full` or, on Raspberry
Pi, `scripts/install/install-raspberrypi.sh --flavor full`. Add
`--with-gui` when you also want the desktop GUI executable installed as
`yggdrasim-gui`. Both scripts accept `--mode release` (default) or
`--mode source`, install host prerequisites through `apt-get`, and
refuse to run on non-Linux hosts because the HIL bridge cannot function
there. Full flag reference lives in `scripts/install/README.md`.

```bash
scripts/install/install-linux.sh --flavor full --with-gui
scripts/install/install-raspberrypi.sh --flavor full --with-gui
```

The `--doctor` probe adds HIL-specific rows:

```text
[+] Local HIL bridge readiness: pyudev present; osmo-remsim-client-st2 at /usr/local/bin/...
[+] tshark (Wireshark CLI): /usr/bin/tshark
[+] termshark (terminal decode): /usr/bin/termshark
[+] dfu-util (SIMtrace2 flashing): /usr/bin/dfu-util
[+] lsusb (USB identity): /usr/bin/lsusb
```

Rows marked `INFO` instead of `OK` are optional — the supervisor falls
back to `lsusb` polling when `pyudev` is missing, and the decoded view
degrades gracefully when `termshark` is absent.

## Host dependencies

Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
    libpcsclite1 libpcsclite-dev pcscd pcsc-tools \
    gpg dfu-util usbutils \
    wireshark tshark termshark
```

Add yourself to the `wireshark` group (or equivalent) if you want
non-root access to `dumpcap`:

```bash
sudo usermod -a -G wireshark "$USER"
```

Install or build `osmo-remsim-client-st2`. The cleanest path is a distro
or an Osmocom-provided package; otherwise build from source. See
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) for a
step-by-step walk-through. For the complete RemSIM, Card Bridge, SSH
tunnel, remote-card service setup, and upstream dependency links, use the
site runbook
[`site-docs/how-to/install-remsim-apdu-streaming.md`](../../how-to/install-remsim-apdu-streaming.md#external-dependency-references).

## Building the full bundle yourself

```bash
python -m pip install -e '.[full,gui]'
YGGDRASIM_FLAVOR=full python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
./dist/yggdrasim-full --version
./dist/yggdrasim-gui-full --version
```

The `[full]` extra covers:

- `pyudev; sys_platform == 'linux'`
- `pyinstaller`
- `pytest`
- `fastapi`, `uvicorn[standard]`, and `websockets` for headless
  `--web-server`
- `pySim @ git+https://github.com/osmocom/pysim.git` (so the SAIP
  ASN.1 compile path, the SAIP transcode TUI, and the SCP11-local /
  eIM-local flows are all unlocked without a separate `[saip]`
  install)

Note: `[full]` by itself includes the headless web-server stack but not
the optional desktop GUI dependency (`pywebview`). Use
`pip install -e '.[full,gui]'` for desktop mode. See
`BUILD_AND_PACKAGING.md` §"Optional extras orthogonal to the flavor
split".

`YGGDRASIM_FLAVOR=full` tells the spec to keep `Tools/HilBridge` and
`yggdrasim_common.hil_bridge_runtime` in the bundle and to record the
flavor in `yggdrasim_common/_build_flavor.py`.

## First HIL session

Detailed operator flow lives in
[`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md). Summary:

```bash
./yggdrasim-full
# Menu -> [B] Local SIMtrace2 HIL Bridge Session -> Start HIL session
```

Stop the session from the same menu; the supervisor, bridge, and
`osmo-remsim-client-st2` children are cleaned up together.

### Remote-card HIL session

When the Linux rig owns the modem and SIMtrace2 but the card sits in a
PC/SC reader on another workstation, publish the workstation reader with
Card Bridge and tunnel it to the rig. Start the supervisor on the rig
with the remote-card source:

```bash
yggdrasim-hil-supervisor \
  --remote-card-url http://127.0.0.1:8642/apdu \
  --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
  --apdu-timeout-ms 30000 \
  --usb-vidpid 1d50:60e3
```

The supervisor still owns the SIMtrace2 and `osmo-remsim-client-st2`
lifecycle locally. Only card APDUs cross the SSH tunnel.

### GUI-driven remote rig

For a Linux source install that should expose both HIL and the Universal
GUI Command Center, use:

```bash
python -m pip install -e '.[full,gui]'
```

The GUI's Card Bridge panel can start the local bridge, copy the bearer
token to a Raspberry Pi or lab host, open SSH forwards, and install or
restart the remote `systemd --user` HIL supervisor service.

Launch the desktop GUI with:

```bash
yggdrasim-gui
```

Launch the headless web GUI from the CLI executable or source console
script with:

```bash
yggdrasim --web-server --token-file ./gui.token
yggdrasim-web-server --token-file ./gui.token
```

## Optional systemd --user unit

The full flavor still exposes the sample `systemd --user` unit under
`guides/systemd/yggdrasim-hil-supervisor.service.example`. Copy it, edit
the paths, and enable it only when you want the supervisor to auto-start
with your login session.

## When to switch to another flavor

- You don't need the HIL bridge → [`INSTALL_CLEAN.md`](INSTALL_CLEAN.md)
- You want the repo for development with the test suite →
  [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md)
- Flashing / updating SIMtrace2 firmware →
  [`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md)
- Streaming a PC/SC reader to a remote HIL rig →
  [`CARD_BRIDGE_GUIDE.md`](CARD_BRIDGE_GUIDE.md)
