<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SIMtrace2 -- cardem firmware and osmo-remsim toolchain

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
hardware and host-side prerequisites -- see
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
board is in DFU (bootloader) mode -- that is the window where you can
flash a new firmware.

**The product ID is not a reliable test for DFU mode.** Some bootloader
builds keep `1d50:60e3` and change only the descriptors. The test that
holds on every board is the interface protocol: `1` is the DFU runtime
inside a running application, `2` is the bootloader itself.

```bash
sudo lsusb -v -d 1d50:60e3 | rg 'bInterfaceProtocol'
sudo dfu-util -l              # prints every alt setting when in DFU mode
```

If the board is not listed at all:

- try a different cable (SIMtrace2 needs a full data-capable micro-USB
  cable, not a charge-only one).

### Visible is not claimable

Listing the board needs no privilege; opening it does.
`osmo-remsim-client-st2` claims it over libusb and the HIL supervisor
resets it over usbfs, and both write to the device node, which udev
creates owned by `root:root`:

```bash
ls -la /dev/bus/usb/001/024      # the bus and device from lsusb
```

Without a rule granting your group write access, the client exits
immediately with `LIBUSB_ERROR_ACCESS` and `can't open USB device`, and
the supervisor restarts it every few seconds forever. Its state file
keeps reporting `remsimClientRunning: true`, because a process really
was just spawned, so the crash loop reads as a healthy client that never
attaches its control connection. The board reset fails the same way with
`Permission denied opening /dev/bus/usb/...`.

`dialout` does not help: that group governs tty devices, not usbfs
nodes. Grant the node instead:

```bash
sudo tee /etc/udev/rules.d/60-simtrace2-access.rules >/dev/null <<'RULE'
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="60e3", MODE="0660", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="4004", MODE="0660", GROUP="plugdev"
RULE
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=1d50
```

The second line covers the board in DFU mode, so a firmware flash needs
no root either. Confirm the node is now `root:plugdev` with group write,
and that your user is in that group.

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
<https://ftp.osmocom.org/binaries/simtrace2/firmware/latest/>, and for
most users that is the shorter route. The file names read
`<board>-<app>-<memory>-latest.bin`:

| Field | Value for a SIMtrace2 board running cardem |
|---|---|
| board | `simtrace`; `owhw`, `qmod`, `ngff_cardem` and `octsimtest` are other hardware |
| app | `cardem`; `trace` is the sniffer, `dfu` the bootloader, `blupdate` the bootloader updater |
| memory | `dfu`, linked above the bootloader and written over DFU |

So the image is `simtrace-cardem-dfu-latest.bin`. Take the `-dfu-`
build, never `-combined-` or `-flash-`: those are whole-chip images for
SAM-BA or JTAG and include a bootloader at offset zero, so writing one
into the application partition leaves nothing bootable.

## 4. Enter DFU mode

With the board in reach:

1. Hold the small **DFU button** on the SIMtrace2 board.
2. Re-plug the USB cable while the button is held.
3. Release the button after roughly one second.

`lsusb` should now show `1d50:4004` (DFU entry).

### Without touching the board

The application firmware carries a DFU **runtime** interface, so the
board can be switched to the bootloader over USB. Confirm it is there
before relying on it:

```bash
sudo lsusb -v -d 1d50:60e3 | rg -A3 'Application Specific Interface'
```

A board that answers `bInterfaceSubClass 1 Device Firmware Update`,
`bInterfaceProtocol 1` (runtime) and `bmAttributes` with bit 3 set
(`bitWillDetach`, e.g. `0x0b`) re-enumerates itself on a detach request
-- no button, no host-issued USB reset:

```bash
sudo dfu-util -d 1d50:60e3 -e
sleep 2
sudo dfu-util -l
```

Confirm the switch from `dfu-util -l`, not from `lsusb`. A board in the
bootloader lists several alt settings and reports
`bInterfaceProtocol 2`; the product ID may or may not change. Section 5
writes one of those alt settings and the choice is not guessable, so
read the list first.

This is the only supported use of a detach request. Section 9 explains
why the same call is the wrong way to reboot a board you do not intend
to re-flash.

## 5. Flash cardem

**Match the target by name, never by number.** The alt numbering
differs between bootloader builds, and the string order inside a
bootloader image is not the alt order, so it cannot be inferred either.
Read the live list:

```bash
sudo dfu-util -l
```

A SIMtrace2 board on a `0.9.0.x` bootloader answers:

```text
alt=0, name="RAM"
alt=1, name="Flash (Application Partition)"
alt=2, name="not available"
```

Here the application is **alt 1**. `RAM` is a volatile load that does
not survive a power cycle, and `not available` is the bootloader
partition locked out. Newer bootloaders expose that third slot as
`Flash (Bootloader Partition)`, and writing an application there is the
only USB-reachable way to make a board unrecoverable: a failed write
leaves no bootloader to retry through, and recovery drops to SAM-BA
over the serial pads or JTAG. Bootloader updates go through the
`blupdate` application instead, which runs from the application
partition and cannot saw off the branch it sits on.

Take the alt whose name is `Flash (Application Partition)` and pass
that number:

```bash
sudo dfu-util -d 1d50:60e3 -a 1 -R -D simtrace-cardem-dfu-latest.bin
```

- `-R` resets into the new firmware when the download completes. Without
  it, unplug and re-plug.
- `-d` disambiguates when more than one board is attached; match on the
  serial with `-S` instead when both are SIMtrace2 units.

Verify the running app by its active interface string rather than by
the file you wrote. Every app image carries the whole string table, so
only a live device tells you which one runs:

```bash
cat /sys/bus/usb/devices/<busid>/*/interface
```

`CardEmulator Modem 1` is cardem. `SIMtrace Sniffer` is the trace app,
which means the flash did not take.

## 6. Install `osmo-remsim-client-st2`

### Option A -- sysmocom apt repository

```bash
sudo apt-get install --no-install-recommends gnupg curl

curl -fsSL https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/Release.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/osmocom.gpg

echo 'deb [signed-by=/usr/share/keyrings/osmocom.gpg] https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/ ./' | \
    sudo tee /etc/apt/sources.list.d/osmocom.list

sudo apt-get update
sudo apt-get install --no-install-recommends \
    osmo-remsim-client-st2 libosmocore-utils
```

Substitute `Debian_12` with the matching identifier for your
distribution (`Debian_11`, `Ubuntu_22.04`, ...). Refer to
<https://osmocom.org/projects/cellular-infrastructure/wiki/Binary_Packages>
for the current list.

The signing key is served per suite as `Release.key` beside the
`Release` file, so it moves with the suite you picked. There is no
`public-keys/OBS.gpg` on `ftp.osmocom.org`; that path answers 404.

**64-bit Raspberry Pi OS keeps `Debian_12`.** That suite publishes
`i386 amd64 arm64 armhf`; `Raspbian_12` publishes `armhf` only, so an
`arm64` Pi pointed at it gets no candidate for
`osmo-remsim-client-st2`. Check `dpkg --print-architecture` before
choosing, and confirm the suite with
`curl -sS https://downloads.osmocom.org/packages/osmocom:/latest/<suite>/Release | rg Architectures`.

### Option B -- source build

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

## 9. Resetting the board without touching it

Unattended rigs need the reset button to be reachable from software.
The good news is that the stock cardem firmware already does the work --
no modified firmware, no custom vendor command, no `dfu-util`.

### Why a USB reset reboots the board

The cardem application's main loop treats any loss of USB configuration
as a hard fault and reboots the microcontroller
(`firmware/apps/cardem/main.c` in `osmocom/simtrace2`):

```c
if (USBD_GetState() < USBD_STATE_CONFIGURED) {
    /* HACK: we don't really deal with USB disconnect yet,
     * so let's just reset the entire uC if this happens */
    TRACE_INFO("Resetting uC on USB disconnect\n\r");
    NVIC_SystemReset();
}
```

`NVIC_SystemReset()` is the same reset path the board's reset button
drives, and the reboot leaves no DFU magic behind, so the bootloader
hands control straight back to the application. A host-issued USB port
reset is therefore a faithful remote stand-in for the button:

```bash
# what YggdraSIM does internally (USBDEVFS_RESET on the usbfs node)
yggdrasim-hil-reset --usb-vidpid 1d50:60e3
```

YggdraSIM runs this automatically before every HIL session; see
[`HIL_BRIDGE_GUIDE.md` §5.1](HIL_BRIDGE_GUIDE.md#51-pre-session-board-reset-remote-reset-button-equivalent)
for the modes, the udev rule, and the `uhubctl` VBUS variant.

### What a reset does *not* clear

`NVIC_SystemReset()` reboots the SAM3 only, and in the YggdraSIM
cardem/remsim topology that is further from the card than it looks:

```text
modem ← SIMtrace2 (emulates a card) ← osmo-remsim-client-st2
      → RSPRO → YggdraSIM HIL bridge → PC/SC reader → real SIM
```

The board never holds the card. Resetting it -- by button, by
`usb-reset`, or by cutting its VBUS with `uhubctl` -- leaves the SIM in
the reader powered, with its selected AID, open logical channels, and
any established secure channel intact. `port-power` only reaches the
card if the reader shares the switched hub port.

Card state is cleared by the bridge instead, with
`SCardReconnect(..., SCARD_UNPOWER_CARD)` at modem- and relay-session
boundaries. See
[`HIL_BRIDGE_GUIDE.md` §5.2](HIL_BRIDGE_GUIDE.md#52-card-session-hygiene).

Note also that the same firmware check fires on USB *suspend*
(`USBD_STATE_SUSPENDED` sorts below `USBD_STATE_CONFIGURED`). If a host
autosuspends the board mid-session it will reboot on its own. On rigs
that show unexplained mid-session resets, pin autosuspend off:

```bash
echo 'ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="60e3", TEST=="power/control", ATTR{power/control}="on"' \
    | sudo tee /etc/udev/rules.d/61-simtrace2-nosuspend.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### Why not `dfu-util --detach`

As a *reset* it looks like the obvious remote lever and it is a trap.
The DFU runtime handler stores `USB_DFU_MAGIC` before resetting
(`DFURT_SwitchToDFU` in
`firmware/atmel_softpack_libraries/usb/device/dfu/dfu_runtime.c`), the
bootloader honours that magic on the next boot, and it has no auto-boot
timeout. The board stays at `1d50:4004` until it is re-flashed or
power-cycled -- the worst possible outcome for a board that was only
meant to reboot. Use the USB port reset above for that.

Detaching to *flash* a remote board is a different operation and is
supported: the download that follows clears the magic, and a write to
the application slot never touches the bootloader, so an interrupted
flash leaves the board at `1d50:4004` and re-flashable rather than
bricked. Section 4 has the sequence.

## 10. Troubleshooting checklist

- `dfu-util` reports `No DFU capable USB device available` → re-enter
  DFU with the board button; some hubs also mis-advertise `1d50:4004`,
  plug the board directly into the host.
- `osmo-remsim-client-st2: command not found` → confirm the package is
  installed (`dpkg -l | rg osmo-remsim`) and that `/usr/local/sbin` or
  `/usr/local/bin` is on `PATH`.
- `pyudev` import failures after a Python upgrade → reinstall the extra:
  `python -m pip install -e '.[hil]'` inside the affected venv.
- The supervisor reports `usbPresent: false` while `lsusb` shows the
  board → some distributions ship their own udev rules under
  `/etc/udev/rules.d/` that require a reload (`sudo udevadm control
  --reload-rules && sudo udevadm trigger`).
- `LIBUSB_ERROR_ACCESS`, `can't open USB device`, or a REMSIM client
  that restarts every few seconds without ever attaching → the device
  node is not writable by your group. See *Visible is not claimable* in
  section 1.

## Related guides

- [`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) -- operator flow.
- [`INSTALL_FULL.md`](INSTALL_FULL.md) -- HIL-capable executable install.
- [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md) -- Pi-specific HIL notes.
- Osmocom upstream documentation:
  - <https://osmocom.org/projects/sim-card/wiki/SIMtrace2>
  - <https://osmocom.org/projects/osmo-remsim/wiki>
