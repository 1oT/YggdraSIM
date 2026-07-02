<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SIMtrace2 — cardem firmware and osmo-remsim toolchain

The YggdraSIM HIL bridge sits on top of Osmocom's
[`osmo-remsim-client-st2`](https://osmocom.org/projects/osmo-remsim/)
and a sysmocom SIMtrace2 board running the **relay / cardem** firmware.

> **Naming note.** "sysmocom SIMtrace2" is the product identifier
> reported by Linux for USB VID:PID `1d50:60e3`; `osmo-remsim-client-st2`
> is the upstream Osmocom tool name. Both names appear here only as
> device / tool identifiers so operators can locate the hardware and
> the software on their host. No vendor endorsement, partnership, or
> certification is implied by these references.
This guide covers three scenarios:

1. First-time flashing of a fresh SIMtrace2 board.
2. Updating an existing SIMtrace2 to the latest cardem build.
3. Installing or refreshing the `osmo-remsim` toolchain on the host.

The YggdraSIM launcher reads local rig configuration from the main
menu entry `[B] Local SIMtrace2 HIL Bridge Session`. This document only covers the
hardware and host-side prerequisites — see
[`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) for the operator flow once
everything is in place.

> **Scope note**: this guide does not replace the upstream Osmocom
> documentation. When something is ambiguous, trust the Osmocom wiki
> and release notes over the convenience summary here.

## 1. Hardware sanity check

```bash
lsusb | rg -i 'simtrace|sysmocom|1d50:60e3'
```

Expected output examples:

```text
Bus 003 Device 042: ID 1d50:60e3 OpenMoko, Inc. Osmocom SIMtrace 2
Bus 001 Device 007: ID 1d50:4004 OpenMoko, Inc. DFU entry                 # DFU mode
Bus 001 Device 012: ID 1d50:60e3 OpenMoko, Inc. SIMtrace 2 (Osmocom)
```

`1d50:60e3` is the normal USB identity. `1d50:4004` shows up when the
board is in DFU (bootloader) mode — that is the window where you can
flash a new firmware.

If the board is not listed at all:

- try a different cable (SIMtrace2 needs a full data-capable micro-USB
  cable, not a charge-only one).
- confirm your user has the `dialout` group (`sudo usermod -a -G
  dialout "$USER"`, then log out and back in).

## 2. Install `dfu-util`

Debian / Ubuntu / Raspberry Pi OS:

```bash
sudo apt-get install --no-install-recommends dfu-util usbutils
```

macOS:

```bash
brew install dfu-util
```

Windows users can fetch `dfu-util` from
<https://dfu-util.sourceforge.net/>. The rest of this guide assumes a
POSIX shell.

## 3. Build (or fetch) the cardem firmware

The firmware lives in the official sysmocom repo:

```bash
git clone https://gitea.osmocom.org/sim-card/simtrace2.git
cd simtrace2
git submodule update --init --recursive

sudo apt-get install --no-install-recommends \
    build-essential gcc-arm-none-eabi libnewlib-arm-none-eabi \
    libusb-1.0-0-dev pkg-config
```

Build the cardem target:

```bash
cd firmware
make APP=cardem BOARD=simtrace
```

The resulting artefact lives at `firmware/bin/cardem-simtrace-*.bin`.
Osmocom also publishes prebuilt images under
<https://ftp.osmocom.org/binaries/simtrace2/firmware/>; grabbing the
latest `cardem-*.bin` works fine for most users.

## 4. Enter DFU mode

1. Hold the small **DFU button** on the SIMtrace2 board.
2. Re-plug the USB cable while the button is held.
3. Release the button after roughly one second.

`lsusb` should now show `1d50:4004` (DFU entry).

## 5. Flash cardem

```bash
sudo dfu-util -a 0 -D firmware/bin/cardem-simtrace.bin
```

- `-a 0` targets the application slot (alt-setting 0).
- Some boards need `-R` to reset automatically after flashing:
  `sudo dfu-util -a 0 -R -D firmware/bin/cardem-simtrace.bin`.
- Unplug and re-plug when `dfu-util` finishes. `lsusb` should now show
  `1d50:60e3` again.

## 6. Install `osmo-remsim-client-st2`

### Option A — sysmocom apt repository

```bash
sudo apt-get install --no-install-recommends software-properties-common gnupg

wget -O - https://ftp.osmocom.org/public-keys/OBS.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/osmocom.gpg

echo "deb [signed-by=/usr/share/keyrings/osmocom.gpg] " \
     "https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/ ./" | \
     sudo tee /etc/apt/sources.list.d/osmocom.list

sudo apt-get update
sudo apt-get install --no-install-recommends \
    osmo-remsim-client-st2 libosmocore-utils
```

Substitute `Debian_12` with the matching identifier for your
distribution (`Debian_11`, `Raspbian_12`, `Ubuntu_22.04`, …). Refer to
<https://osmocom.org/projects/cellular-infrastructure/wiki/Binary_Packages>
for the current list.

### Option B — source build

Clone and build `libosmocore` first, then `osmo-remsim`:

```bash
sudo apt-get install --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    libtalloc-dev libpcsclite-dev libusb-1.0-0-dev git

git clone https://gitea.osmocom.org/osmocom/libosmocore.git
cd libosmocore
autoreconf -fi
./configure
make -j"$(nproc)"
sudo make install
sudo ldconfig
cd ..

git clone https://gitea.osmocom.org/sim-card/osmo-remsim.git
cd osmo-remsim
autoreconf -fi
./configure
make -j"$(nproc)"
sudo make install
sudo ldconfig
```

Confirm the binary ended up on `PATH`:

```bash
which osmo-remsim-client-st2
osmo-remsim-client-st2 -h
```

## 7. Verify everything with YggdraSIM doctor

```bash
python main/main.py --doctor
# or, for a frozen bundle:
./dist/yggdrasim-full --doctor
```

Expected rows once the host is ready:

```text
[+] Local HIL bridge readiness: pyudev present; osmo-remsim-client-st2 at /usr/local/bin/osmo-remsim-client-st2
[+] dfu-util (SIMtrace2 flashing): /usr/bin/dfu-util
[+] lsusb (USB identity): /usr/bin/lsusb
```

`INFO` rows are non-fatal; the supervisor will pick the best available
option (for example `lsusb` polling when `pyudev` is missing).

## 8. Updating later

Two moving parts are worth refreshing together:

| Component                 | Update command                                           |
|---------------------------|----------------------------------------------------------|
| SIMtrace2 cardem firmware | Re-enter DFU and rerun `dfu-util -a 0 -D cardem-*.bin`   |
| `osmo-remsim-client-st2`  | `sudo apt-get update && sudo apt-get upgrade osmo-remsim-client-st2`, or rebuild from source |
| YggdraSIM bundle          | Replace the onefile or rerun the source-based build      |

Always rerun `python main/main.py --doctor` after upgrading any of
those; the HIL probes will call out regressions immediately.

## 9. Troubleshooting checklist

- `dfu-util` reports `No DFU capable USB device available` → re-enter
  DFU with the board button; some hubs also mis-advertise `1d50:4004`,
  plug the board directly into the host.
- `osmo-remsim-client-st2: command not found` → confirm the package is
  installed (`dpkg -l | rg osmo-remsim`) and that `/usr/local/sbin` or
  `/usr/local/bin` is on `PATH`.
- `pyudev` import failures after a Python upgrade → reinstall the extra:
  `python -m pip install -e '.[hil]'` inside the affected venv.
- The supervisor reports `usbPresent: false` while `lsusb` shows the
  board → verify your user is in `dialout`; some distributions ship
  their own udev rules under `/etc/udev/rules.d/` that require a
  reload (`sudo udevadm control --reload-rules && sudo udevadm
  trigger`).

## Related guides

- [`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) — operator flow.
- [`INSTALL_FULL.md`](INSTALL_FULL.md) — HIL-capable executable install.
- [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md) — Pi-specific HIL notes.
- Osmocom upstream documentation:
  - <https://osmocom.org/projects/sim-card/wiki/SIMtrace2>
  - <https://osmocom.org/projects/osmo-remsim/wiki>
