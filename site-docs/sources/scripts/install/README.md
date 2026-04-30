# Install scripts

This directory holds thin, reviewable installer scripts for each
supported host. They cover both pre-built-release installs and
editable source installs, mapped to the flavors published by
`yggdrasim_main.spec` and `.github/workflows/build.yml`.

| Script | Host | Supported flavors | Modes |
|---|---|---|---|
| `install-linux.sh`        | Linux x86_64 / arm64 | clean, full | release, source |
| `install-macos.sh`        | macOS x86_64 / arm64 | clean       | release, source |
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

## Flavors

- `clean` — no HIL bridge; cross-platform.
- `full` — HIL bridge included; Linux only (including Raspberry Pi
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
--no-venv                     source mode: use current Python env
-h / --help                   print usage
```

## Environment overrides

- `YGGDRASIM_REPO` (default: `hampushellsberg-dev/YggdraSIM`) — fork /
  mirror to pull releases from. The installer expands it into
  `https://github.com/<owner>/<repo>/releases/...` release URLs.
- `YGGDRASIM_PYTHON` — Python interpreter for source installs (default:
  `python3`).

## Examples

```bash
# Latest clean bundle on desktop Linux
scripts/install/install-linux.sh

# Specific release tag, clean
scripts/install/install-linux.sh --version v0.9.0

# HIL-capable bundle on Linux lab host
scripts/install/install-linux.sh --flavor full

# Editable source install with .[full] extras
scripts/install/install-linux.sh --flavor full --mode source

# macOS arm64, latest clean
scripts/install/install-macos.sh

# Raspberry Pi arm64, full flavor, editable source install
scripts/install/install-raspberrypi.sh --flavor full --mode source
```

```powershell
# Windows x86_64, clean release
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1

# Windows editable source install
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1 -Mode source
```

## What the scripts do not do

- They do not flash or update the SIMtrace2 firmware. Use
  `guides/SIMTRACE2_CARDEM_GUIDE.md` for that.
- They do not install system-wide (everything lands in user-local
  paths unless `--install-dir` points elsewhere).
- They do not configure the runtime tree layout. The launcher still
  uses the normal `YggdraSIM-data` fallback or `YGGDRASIM_RUNTIME_ROOT`.

## Related guides

- `guides/INSTALL_CLEAN.md`
- `guides/INSTALL_FULL.md`
- `guides/INSTALL_FROM_SOURCE.md`
- `guides/INSTALL_RASPBERRYPI.md`
- `guides/SIMTRACE2_CARDEM_GUIDE.md`
