<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Installation — Clean Flavor

The **clean** flavor is the default distribution of YggdraSIM. It targets
operators who need the normal CLI, GUI, Card Bridge, and remote APDU
streaming on Windows, macOS, desktop Linux, and Raspberry Pi OS 64-bit,
but do not need the same machine to drive a SIMtrace2 through the local
RemSIM/HIL runtime.

## What the clean flavor ships

- Full SCP03 / SCP11 / SCP11 local / SCP11 eIM local / SCP80 OTA surfaces
- SAIP profile-package tooling, SUCI key tooling
- Simulated SIM backend (`--card-backend sim`) and PC/SC reader backend
- Card Bridge / remote APDU streaming:
  `python main/main.py --card-bridge`, `yggdrasim-card-bridge`,
  and `--remote-card-url` consumers
- `--version`, `--doctor`, and the main menu

## What the clean flavor deliberately omits

- the local SIMtrace2/RemSIM HIL supervisor/runtime
- the Linux-only `pyudev` dependency
- any reliance on `osmo-remsim-client-st2` or SIMtrace2 firmware

If any of those are required, use [`INSTALL_FULL.md`](INSTALL_FULL.md) or
[`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md) instead.

## Picking the correct pre-built artefact

Release artefacts follow this naming pattern:

```text
yggdrasim-<os>-<arch>-clean-<version>[.exe]
yggdrasim-gui-<os>-<arch>-clean-<version>[.exe]
```

| Platform             | Artefact                                             |
|----------------------|------------------------------------------------------|
| Windows x86_64       | `yggdrasim-windows-x86_64-clean-<version>.exe`, `yggdrasim-gui-windows-x86_64-clean-<version>.exe` |
| macOS Apple Silicon  | `yggdrasim-macos-arm64-clean-<version>`, `yggdrasim-gui-macos-arm64-clean-<version>` |
| macOS Intel          | no prebuilt release bundle; use `scripts/install/install-macos.sh --mode source` |
| Linux x86_64         | `yggdrasim-linux-x86_64-clean-<version>`, `yggdrasim-gui-linux-x86_64-clean-<version>` |
| Linux arm64 / RPi OS | `yggdrasim-linux-arm64-clean-<version>`, `yggdrasim-gui-linux-arm64-clean-<version>` — see the Raspberry Pi guide |

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

The scripts default to the clean CLI flavor, latest release, and a
user-local install directory. Add `--with-gui` when you also want the
desktop GUI executable installed beside the CLI executable. Pass
`--version <tag>` to pin to a specific release or `--mode source` to do
an editable install instead. Full option reference lives in
`scripts/install/README.md`.

```bash
scripts/install/install-linux.sh --with-gui
scripts/install/install-macos.sh --with-gui
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1 -WithGui
```

## First run

```bash
./yggdrasim-linux-x86_64-clean-<version> --version
./yggdrasim-linux-x86_64-clean-<version> --doctor
./yggdrasim-linux-x86_64-clean-<version>
```

If you installed the companion GUI artifact, launch it directly:

```bash
yggdrasim-gui
```

The CLI binary remains available as `yggdrasim`; use it for shell/TUI
work, `--doctor`, batch commands, and headless web-server mode:

```bash
yggdrasim --doctor
yggdrasim --web-server --token-file ./gui.token
```

The `--doctor` probe reports the active build flavor, confirms remote-card
streaming support, and marks only the local SIMtrace2 HIL runtime as
intentionally unavailable:

```text
[+] Build flavor: clean (no local SIMtrace2 HIL bridge) (source: build-stamp)
[*] Local HIL bridge readiness: The local SIMtrace2/RemSIM HIL bridge is not bundled in this clean build. ...
[*] Remote card bridge: Not configured — set YGGDRASIM_CARD_RELAY_URL or pass --remote-card-url to talk to a Card Bridge over SSH.
```

Use `[CB] Card Bridge / Remote APDU Streaming` to publish a local PC/SC
reader or configure a tunneled remote reader. If the user opens the
`[B] Local SIMtrace2 HIL Bridge Session` entry, the launcher prints a
pointer to [`INSTALL_FULL.md`](INSTALL_FULL.md) and
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) instead of crashing.

## Host dependencies (runtime)

The clean bundle is a PyInstaller onefile. It still needs a minimum host
baseline to talk to smart-card readers and optional encryption tooling:

### Windows

- A working PC/SC stack (built in to Windows 10 / 11).
- Vendor driver for your smart-card reader.
- OpenSSH client when Card Bridge traffic is tunneled to or from another host.
- Optional: `gpg4win` when `state/inventory_crypto.json` is enabled.

### macOS

- `pcscd` ships with the OS; no extra install is required for most USB
  CCID readers.
- OpenSSH client ships with the OS and is used for Card Bridge tunnel recipes.
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
python -m pip install -e '.[build,test,gui]'
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
./dist/yggdrasim-clean --version
./dist/yggdrasim-gui-clean --version
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
