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
  `<os>/<arch>/<flavor>`, verifies it against the release
  `SHA256SUMS`, and drops it into a user-local bin directory. Windows
  additionally requires a valid Authenticode signature.
- `source` creates a virtualenv (unless `--no-venv`) next to the repo
  checkout and runs `pip install -e '.[saip]'` for clean or
  `pip install -e '.[full]'` for full.
- Add `--with-gui` to install the companion desktop GUI executable in
  release mode, or the `[gui]` extra plus the installed GUI commands in
  source mode.

## Flavors

- `clean` -- Card Bridge / remote APDU streaming included; no direct
  SIMtrace2/RemSIM HIL runtime; cross-platform.
- `full` -- direct SIMtrace2/RemSIM HIL runtime included; Linux only (including Raspberry Pi
  arm64). Any non-Linux installer will refuse `--flavor full` with a
  clear error.

Unsupported release architectures are rejected before any package-manager
or install-directory changes. Currently published binaries are Linux
x86_64/arm64, macOS arm64, and Windows x86_64.

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

- `YGGDRASIM_REPO` (default: `1oT/YggdraSIM`) -- fork /
  mirror to pull releases from. The installer expands it into
  `https://github.com/<owner>/<repo>/releases/...` release URLs.
- `YGGDRASIM_PYTHON` -- Python interpreter for source installs (default:
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
- They do not build `osmo-remsim-client-st2` from source. Full Linux
  installs try the exact package (then a distribution compatibility
  package) and fail fast if the executable is still unavailable.
- They do not open SSH tunnels, copy Card Bridge bearer tokens, or
  install remote HIL `systemd --user` services.
- They do not install system-wide (everything lands in user-local
  paths unless `--install-dir` points elsewhere).
- They do not configure the runtime tree layout. The launcher still
  uses the normal `YggdraSIM-data` fallback or `YGGDRASIM_RUNTIME_ROOT`.

## pipx install

`pipx` puts the toolchain in its own virtualenv and exposes the entry
points on `PATH`, which suits operators who want the commands without
managing a virtualenv by hand:

```bash
pipx install '.[gui,saip]'                                   # from a checkout
pipx install 'yggdrasim[gui,saip] @ git+https://github.com/1oT/YggdraSIM.git'
pipx inject yggdrasim mcp                                    # add an extra later
```

`pipx install yggdrasim` (the bare name, resolved from PyPI) does not
work today, and no packaging change in this repository can make it
work on its own. Two base dependencies are PEP 508 direct references --
the pinned `asn1tools` loop-fix fork and Osmocom `pySim`, neither of
which publishes wheels -- and PyPI rejects uploads whose `Requires-Dist`
carries a direct reference. pip honours direct references when it
builds from a local path or a git URL, which is why the specifiers
above work. Publishing the bare name to PyPI first requires vendoring
those two dependencies, waiting for upstream wheels, or demoting them
to an extra installed with `pipx inject`.

After the install, the following are on `PATH`:

| Command | Use |
|---|---|
| `yggdrasim` / `yggdrasim-cli` | CLI launcher; stays attached to the terminal for scripting and APDU piping |
| `yggdrasim-desktop` | GUI launcher declared in `[project.gui-scripts]`; `pythonw`-backed on Windows, so a shortcut opens no console window |
| `yggdrasim-gui` | GUI entry as a console script, for terminal use such as `yggdrasim-gui --web-server --token-file <path>` |
| `yggdrasim-web-server` | Headless server, no webview |

Every other `yggdrasim-*` tool listed in `pyproject.toml` is exposed the
same way.

## Desktop shortcuts

`scripts/install_shortcuts.py` writes one native launcher per host so
the Command Center starts without a terminal:

```bash
python scripts/install_shortcuts.py --dry-run    # print, write nothing
python scripts/install_shortcuts.py              # install
python scripts/install_shortcuts.py --force      # overwrite an existing launcher
python scripts/install_shortcuts.py --uninstall  # remove
```

| Host | What it writes |
|---|---|
| Linux | `~/.local/share/applications/yggdrasim.desktop` (`Terminal=false`), honouring `XDG_DATA_HOME` |
| Windows | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\YggdraSIM.lnk`, created through `WScript.Shell` |
| macOS | `~/Applications/YggdraSIM.app`, compiled with `osacompile`; `--system` targets `/Applications` |

The launcher target is resolved to an absolute path at install time:
`yggdrasim-desktop`, then `yggdrasim-gui`, then
`<interpreter> -m main.gui`, each looked up on `PATH` and next to the
running interpreter (where a pipx venv keeps its scripts). Desktop
sessions and Explorer do not inherit the shell `PATH`, so a launcher
naming a bare command would fail on the hosts this script exists for.
Run the script with the same interpreter or `PATH` that has YggdraSIM
installed; it refuses with a non-zero exit rather than writing a
launcher it cannot resolve.

Other flags: `--target <path>` pins the executable explicitly,
`--install-dir <path>` overrides the destination directory, `--no-icon`
skips the emblem. Exit codes are `0` success, `1` failure, `2`
unsupported platform. Windows without PowerShell and macOS without
`osacompile` print the manual steps instead of failing silently.

### Launcher icon

Launchers carry the YggdraSIM mark -- the same artwork the docs site and
the GUI header show. It ships as `yggdrasim_common` package data
(`assets/yggdrasim.svg` plus 256 px and 512 px PNG renders), so a pipx
install has it without the source tree:

| Host | How the mark is applied |
|---|---|
| Linux | SVG and PNG installed into `<XDG_DATA_HOME>/icons/hicolor/{scalable,256x256}/apps/yggdrasim.*`; the entry references the theme name `Icon=yggdrasim` |
| Windows | The 256 px PNG is wrapped in an ICO container at `%LOCALAPPDATA%\YggdraSIM\yggdrasim.ico` and set as the shortcut's `IconLocation` |
| macOS | `sips` converts the 512 px PNG to `Contents/Resources/applet.icns` inside the bundle |

Windows shortcuts accept an icon only from an `.ico`, `.exe`, or `.dll`,
so the installer writes the ICO itself: a PNG-compressed icon entry is
a 6-byte directory header plus one 16-byte entry in front of the PNG
bytes, which needs no image library and no rasterizer on the host. ICO
entries cap at 256×256, which is why a separate 256 px render is
shipped alongside the 512 px one macOS uses.

Every icon step is optional. A host missing the assets, missing `sips`,
or run with `--no-icon` still gets a working launcher -- the desktop
default icon is used and `Icon=` is omitted rather than left dangling.

`yggdrasim_common/assets/yggdrasim.svg` is a byte-identical copy of
`site-docs/assets/images/yggdrasil-mark.svg`;
`tests/test_install_shortcuts.py` fails if the two drift. The GUI header
carries a third copy of the same artwork inline in
`gui_frontend/src/index.html` (the page CSP rules out an external
reference), which no test currently ties to the other two.

## Launching after install

Release installs provide `yggdrasim` for the CLI launcher. When
`--with-gui` was used, they also provide `yggdrasim-gui` (or
`yggdrasim-gui.exe` on Windows) for the desktop Command Center.

Source installs expose the same names through Python console scripts:
`yggdrasim`, `yggdrasim-cli`, `yggdrasim-gui`, `yggdrasim-desktop`, and
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
