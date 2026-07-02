<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Install scripts

This directory holds thin, reviewable installer scripts for each
supported host. They cover both pre-built-release installs and
editable source installs, mapped to the flavors published by
`yggdrasim_main.spec` and `.github/workflows/build.yml`.

| Script | Host | Supported flavors | Modes |
|---|---|---|---|
| `install-linux.sh`        | Linux x86_64 / arm64 | clean, full | release, source |
| `install-macos.sh`        | macOS arm64 release; macOS x86_64 / arm64 source | clean | release, source |
| `install-windows.ps1`     | Windows x86_64       | clean       | release, source |
| `install-raspberrypi.sh`  | Raspberry Pi arm64 (Linux) | clean, full | release, source |

All POSIX scripts source `_common.sh` for argument parsing, flavor
validation, download / install helpers, and package-manager bootstrap.
The Windows script is self-contained PowerShell.

## Modes

- `release` (default) downloads the GitHub release asset that matches
  `<os>/<arch>/<flavor>` and drops it into a user-local bin directory.
- `source` creates a virtualenv (unless `--no-venv`) next to the repo
  checkout and runs `pip install -e '.'` or `pip install -e '.[full]'`.
- Add `--with-gui` to install the companion desktop GUI executable in
  release mode, or the `[gui]` extra plus the installed GUI commands in
  source mode.

## Flavors

- `clean` — Card Bridge / remote APDU streaming included; no direct
  SIMtrace2/RemSIM HIL runtime; cross-platform.
- `full` — direct SIMtrace2/RemSIM HIL runtime included; Linux only (including Raspberry Pi
  arm64). Any non-Linux installer will refuse `--flavor full` with a
  clear error.

## Common flags

```
--flavor clean|full           default: clean
--mode release|source         default: release
--version <tag>               default: latest
--install-dir <path>          default: ~/.local/bin (or %LOCALAPPDATA% on Windows)
--repo-root <path>            default: current directory (source mode)
--venv <path>                 default: <repo-root>/.venv (source mode)
--no-deps                     skip apt/brew/choco prerequisite install
--with-gui                    install desktop GUI support as well
--no-venv                     source mode: use current Python env
-h / --help                   print usage
```

## Environment overrides

- `YGGDRASIM_REPO` (default: `1oT/YggdraSIM`) — fork /
  mirror to pull releases from. The installer expands it into
  `https://github.com/<owner>/<repo>/releases/...` release URLs.
- `YGGDRASIM_PYTHON` — Python interpreter for source installs (default:
  `python3`).

## Examples

`--version` is the **GitHub release tag**, not only the dotted version in the
bundled executable name (artefacts are named with the value from `pyproject.toml`).
Published CI binaries attach to tags matching `refs/tags/v*`.

```bash
# Latest clean bundle on desktop Linux
scripts/install/install-linux.sh

# Latest clean CLI + desktop GUI bundle on desktop Linux
scripts/install/install-linux.sh --with-gui

# Specific release tag, clean
scripts/install/install-linux.sh --version v1.0.0

# HIL-capable bundle on Linux lab host
scripts/install/install-linux.sh --flavor full

# HIL-capable bundle with the GUI companion
scripts/install/install-linux.sh --flavor full --with-gui

# Editable source install with .[full] extras
scripts/install/install-linux.sh --flavor full --mode source

# Editable source install with desktop GUI commands
scripts/install/install-linux.sh --mode source --with-gui

# macOS Apple Silicon, latest clean release
scripts/install/install-macos.sh --with-gui

# macOS Intel, editable source install
scripts/install/install-macos.sh --mode source

# Raspberry Pi arm64, full flavor, editable source install
scripts/install/install-raspberrypi.sh --flavor full --mode source
```

```powershell
# Windows x86_64, clean release
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1 -WithGui

# Windows editable source install
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1 -Mode source
```

## What the scripts do not do

- They do not flash or update the SIMtrace2 firmware. Use
  `guides/SIMTRACE2_CARDEM_GUIDE.md` for that.
- They do not build or install `osmo-remsim-client-st2` when your
  distro does not package it.
- They do not open SSH tunnels, copy Card Bridge bearer tokens, or
  install remote HIL `systemd --user` services.
- They do not install system-wide (everything lands in user-local
  paths unless `--install-dir` points elsewhere).
- They do not configure the runtime tree layout. The launcher still
  uses the normal `YggdraSIM-data` fallback or `YGGDRASIM_RUNTIME_ROOT`.

## Launching after install

Release installs provide `yggdrasim` for the CLI launcher. When
`--with-gui` was used, they also provide `yggdrasim-gui` (or
`yggdrasim-gui.exe` on Windows) for the desktop Command Center.

Source installs expose the same names through Python console scripts:
`yggdrasim`, `yggdrasim-cli`, `yggdrasim-gui`, and
`yggdrasim-web-server`. Use `yggdrasim-web-server --token-file <path>`
for headless remote-lab access.

## Related guides

- `guides/INSTALL_CLEAN.md`
- `guides/INSTALL_FULL.md`
- `guides/INSTALL_FROM_SOURCE.md`
- `guides/INSTALL_RASPBERRYPI.md`
- `guides/SIMTRACE2_CARDEM_GUIDE.md`
- `guides/CARD_BRIDGE_GUIDE.md`
- `site-docs/how-to/install-remsim-apdu-streaming.md`
- `site-docs/how-to/remote-apdu-streaming.md`
