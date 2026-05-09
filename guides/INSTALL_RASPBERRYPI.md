# Installation — Raspberry Pi (arm64)

YggdraSIM runs on Raspberry Pi 4 / 5 boards using Raspberry Pi OS 64-bit
(Debian Bookworm-based). This guide covers both the pre-built clean
bundle and the on-device build path for people who want the HIL bridge
on the Pi itself.

## 1. OS baseline

Use **Raspberry Pi OS 64-bit (Bookworm or newer)**. The 32-bit images
still work in editable-install mode but the PyInstaller bundles are only
produced for `linux-arm64`.

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends \
    libpcsclite1 libpcsclite-dev pcscd pcsc-tools \
    gpg usbutils python3-venv
```

Optional (useful even on a headless Pi):

```bash
sudo apt-get install --no-install-recommends \
    tshark wireshark-common dfu-util
```

During `tshark` installation you are asked whether non-root users should
be allowed to capture — answer **Yes** if you want GSMTAP captures from
the user you ran the installer as. Afterwards:

```bash
sudo usermod -a -G wireshark "$USER"
sudo usermod -a -G dialout "$USER"   # needed for SIMtrace2
```

Log out and back in so the new groups take effect.

## 2. Option A — pre-built clean bundle

Most Pi use-cases do not need the HIL bridge. Fetch the published
arm64 clean bundle:

```text
yggdrasim-linux-arm64-clean-<version>
```

Install and smoke-test it:

```bash
chmod +x yggdrasim-linux-arm64-clean-<version>
./yggdrasim-linux-arm64-clean-<version> --version
./yggdrasim-linux-arm64-clean-<version> --doctor
```

`--doctor` should report:

```text
[+] Build flavor: clean (no HIL bridge) (source: build-stamp)
```

Move the binary to somewhere on `PATH` if you want a persistent install:

```bash
sudo install -m 0755 yggdrasim-linux-arm64-clean-<version> /usr/local/bin/yggdrasim
```

That is it for SCP03, SCP11, SCP11 local, eIM local, SAIP, and SUCI work
on the Pi. No HIL bridge, no `pyudev`, no `osmo-remsim-client-st2`.

## 3. Option B — pre-built full bundle (HIL on the Pi)

As of the flavor-aware CI matrix the `full` bundle is also published
for `linux-arm64`:

```text
yggdrasim-linux-arm64-full-<version>
```

```bash
chmod +x yggdrasim-linux-arm64-full-<version>
./yggdrasim-linux-arm64-full-<version> --version
./yggdrasim-linux-arm64-full-<version> --doctor
```

The HIL probes will only pass once `osmo-remsim-client-st2` is
installed (see section 4) and the SIMtrace2 firmware is flashed (see
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md)). Move the
binary onto `PATH` the same way as the clean bundle.

## 4. Option C — source install with optional HIL on the Pi

The source path still works when you want the test suite or want to
iterate on the launcher. To run HIL on the Pi itself you build from
source:

```bash
sudo apt-get install --no-install-recommends \
    build-essential swig pkg-config git \
    libudev-dev libusb-1.0-0-dev

git clone https://github.com/<your-org>/YggdraSIM.git
cd YggdraSIM

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[full]'
```

Verify:

```bash
python main/main.py --version
python main/main.py --doctor
```

The doctor report should now include `HIL bridge readiness: OK` once the
prerequisites below are in place.

## Scripted install on the Pi

`scripts/install/install-raspberrypi.sh` handles both flavors and both
modes:

```bash
scripts/install/install-raspberrypi.sh                      # clean, release
scripts/install/install-raspberrypi.sh --flavor full        # full arm64 release
scripts/install/install-raspberrypi.sh --flavor full --mode source
```

The script bootstraps the apt prerequisites, downloads the matching
release asset (or sets up a `.venv` for source mode), and points at
the SIMtrace2 guide when the full flavor is selected.

## 5. `osmo-remsim-client-st2` on the Pi

The simplest path is to build the sysmocom packages from their apt
repository (Debian armhf / arm64 flavours are published for Bookworm):

```bash
sudo apt-get install --no-install-recommends \
    software-properties-common gnupg

wget -O - https://ftp.osmocom.org/public-keys/OBS.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/osmocom.gpg

echo "deb [signed-by=/usr/share/keyrings/osmocom.gpg] " \
    "https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/ ./" | \
    sudo tee /etc/apt/sources.list.d/osmocom.list

sudo apt-get update
sudo apt-get install --no-install-recommends osmo-remsim-client-st2
```

If that repository does not publish arm64 packages yet, fall back to a
source build — `libosmocore` + `osmo-remsim` — against the Pi's native
toolchain. See
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) for the SIMtrace2
firmware story; the build instructions there apply verbatim on arm64.

## 6. Running the HIL bridge on the Pi

Plug the SIMtrace2 board into a powered USB hub. The Pi's own USB supply
is usually fine for one SIMtrace2 + a PC/SC reader, but a powered hub is
recommended when you also run a modem on the same board.

```bash
lsusb | rg -i 'simtrace|sysmocom|1d50:60e3'
python -m Tools.HilBridge.main --list-readers
```

Then follow [`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) starting at
section 3. The Pi-specific differences are:

- `--usb-vidpid 1d50:60e3` is still the correct selector.
- The supervisor's `pyudev` path is slightly slower than on a desktop
  Linux box; the `lsusb` fallback works fine when you leave `pyudev`
  out.
- `wireshark` on a headless Pi is painful; prefer the built-in decoded
  terminal view (`[3] Decoded APDU view inside the terminal`).

## 7. Building your own bundle on the Pi

The on-device build produces an arm64 binary you can copy to another Pi:

```bash
# inside the cloned repo with .[build] or .[full] installed
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
# or, with HIL:
YGGDRASIM_FLAVOR=full python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

The resulting `dist/yggdrasim-clean` or `dist/yggdrasim-full` is an
arm64 onefile. There is no cross-build story: each architecture must be
built on a host of that architecture (the CI workflow uses QEMU
emulation to do this under `docker buildx`).

## Related guides

- [`INSTALL_CLEAN.md`](INSTALL_CLEAN.md) — general clean-flavor install.
- [`INSTALL_FULL.md`](INSTALL_FULL.md) — full-flavor Linux install.
- [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md) — editable install and tests.
- [`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) — flashing / updating SIMtrace2.
- [`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) — once the HIL stack is live.
