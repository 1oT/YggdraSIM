# Installation -- Clean Flavor

The **clean** flavor is the default distribution of YggdraSIM. It targets
operators who do not need the SIMtrace2-based hardware-in-the-loop (HIL)
bridge and want a lean executable that runs on Windows, macOS, desktop
Linux, and Raspberry Pi OS 64-bit.

## What the clean flavor ships

- Full SCP03 / SCP11 / SCP11 local / SCP11 eIM local / SCP80 OTA surfaces
- SAIP profile-package tooling, SUCI key tooling
- Simulated SIM backend (`--card-backend sim`) and PC/SC reader backend
- `--version`, `--doctor`, and the main menu

## What the clean flavor deliberately omits

- `Tools/HilBridge` and `yggdrasim_common.hil_bridge_runtime`
- the Linux-only `pyudev` dependency
- any reliance on `osmo-remsim-client-st2` or SIMtrace2 firmware

If any of those are required, use [`INSTALL_FULL.md`](INSTALL_FULL.md) or
[`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md) instead.

## Picking the correct pre-built artefact

Release artefacts follow this naming pattern:

```text
yggdrasim-<os>-<arch>-clean-<version>[.exe]
```

| Platform             | Artefact                                             |
|----------------------|------------------------------------------------------|
| Windows x86_64       | `yggdrasim-windows-x86_64-clean-<version>.exe`       |
| macOS Intel          | `yggdrasim-macos-x86_64-clean-<version>`             |
| macOS Apple Silicon  | `yggdrasim-macos-arm64-clean-<version>`              |
| Linux x86_64         | `yggdrasim-linux-x86_64-clean-<version>`             |
| Linux arm64 / RPi OS | `yggdrasim-linux-arm64-clean-<version>` -- see the Raspberry Pi guide |

Download the artefact that matches your OS and CPU, then make the file
executable (Linux / macOS):

```bash
chmod +x yggdrasim-<os>-<arch>-clean-<version>
```

## Scripted install

The repository ships opinionated installer scripts that wrap both the
pre-built-release path and the editable source path. They live in
`scripts/install/` and are safe to run from a checkout or from a
stand-alone download of just the script.

| Host | Script | Example |
|---|---|---|
| Linux desktop / server | `scripts/install/install-linux.sh` | `scripts/install/install-linux.sh` |
| macOS | `scripts/install/install-macos.sh` | `scripts/install/install-macos.sh` |
| Windows | `scripts/install/install-windows.ps1` | `powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1` |
| Raspberry Pi | `scripts/install/install-raspberrypi.sh` | `scripts/install/install-raspberrypi.sh` |

The scripts default to the clean flavor, latest release, and a
user-local install directory. Pass `--version <tag>` to pin to a
specific release or `--mode source` to do an editable install instead.
Full option reference lives in `scripts/install/README.md`.

## First run

```bash
./yggdrasim-linux-x86_64-clean-<version> --version
./yggdrasim-linux-x86_64-clean-<version> --doctor
./yggdrasim-linux-x86_64-clean-<version>
```

The `--doctor` probe reports the active build flavor and confirms the HIL
bridge is intentionally unavailable:

```text
[+] Build flavor: clean (no HIL bridge) (source: build-stamp)
[*] HIL bridge readiness: The HIL bridge is not bundled in this clean build. ...
```

If the user opens the `[B] HIL Bridge Session` entry in the main menu the
launcher prints a pointer to [`INSTALL_FULL.md`](INSTALL_FULL.md) and
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) instead of
crashing.

## Host dependencies (runtime)

The clean bundle is a PyInstaller onefile. It still needs a minimum host
baseline to talk to smart-card readers and optional encryption tooling:

### Windows

- A working PC/SC stack (built in to Windows 10 / 11).
- Vendor driver for your smart-card reader.
- Optional: `gpg4win` when `state/inventory_crypto.json` is enabled.

### macOS

- `pcscd` ships with the OS; no extra install is required for most USB
  CCID readers.
- Optional: `brew install gnupg` for the encrypted-inventory provider.
- First launch may prompt for network / USB permissions for the reader.

### Linux (desktop)

```bash
sudo apt-get install --no-install-recommends \
    libpcsclite1 pcscd pcsc-tools gpg
```

Check that your user is in the `pcscd` or equivalent group used by your
distribution for reader access.

### Raspberry Pi OS 64-bit

Use the arm64 bundle and follow [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md)
for the additional steps specific to Raspberry Pi hardware.

## Building the clean bundle yourself

The same onefile can be produced from a source checkout:

```bash
python -m pip install -e '.[build,test]'
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
./dist/yggdrasim-clean --version
```

The spec writes a build stamp into `yggdrasim_common/_build_flavor.py` so
the frozen executable reports its flavor accurately even without the
`YGGDRASIM_FLAVOR` environment variable at runtime. The stamp file is
git-ignored.

## When to switch to another flavor

- SIMtrace2 + modem HIL capture → [`INSTALL_FULL.md`](INSTALL_FULL.md)
- Full development checkout with test suite →
  [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md)
- Running on the Pi directly →
  [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md)
