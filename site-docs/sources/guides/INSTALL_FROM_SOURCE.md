# Installation -- From Source Checkout

This path is the right choice when you want to run the full test suite,
modify the code, or cherry-pick HIL features without committing to a
published executable.

A source checkout contains **every** module (including the HIL bridge)
on any operating system. HIL-specific behaviour is still runtime-gated:

- the `[B] HIL Bridge Session` main-menu entry is only shown on Linux and
  only after `pip install -e '.[hil]'` (or `.[full]`) makes `pyudev`
  available.
- `yggdrasim-hil-bridge` / `yggdrasim-hil-supervisor` emit a pointer to
  this guide and refuse to start when the current host is not Linux.
- `--doctor` warns when `osmo-remsim-client-st2` or the SIMtrace2 runtime
  tooling is missing, instead of failing silently.

## 1. Clone the repository

```bash
git clone https://github.com/1oT/YggdraSIM.git
cd YggdraSIM
```

Substitute the remote with your fork / mirror if applicable; the
installer scripts honour the `YGGDRASIM_REPO` environment variable for
exactly that case.

### 1b. (Optional) Enable SAIP / SCP11-local flows

The core simulator, HIL bridge, and SCP03 / SCP80 flows run **without**
pySim. Only SAIP profile decoding (`yggdrasim-profile-package`, the
SAIP transcode TUI) and the SCP11 local / eIM in-process SM-DP+ pull
it in. The recommended path is the `[saip]` extra, which installs
upstream pySim from its GitHub mirror:

```bash
python -m pip install -e '.[saip]'
```

`yggdrasim --doctor` reports `pySim: OK` once the import probe
succeeds and `WARN` otherwise; the warning is expected on lean
installations and does not block the clean flows.

**Developer checkout (advanced).** If you want to iterate on an
unreleased upstream branch, drop a checkout at `<repo>/pysim` and that
tree wins over the installed wheel:

```bash
git clone https://github.com/osmocom/pysim.git pysim
```

`pysim/` is gitignored so the checkout never ships in the
distribution.

### Optional -- let the installer script handle it

Steps 2 and 3 can be replaced by the corresponding script under
`scripts/install/`:

```bash
scripts/install/install-linux.sh --mode source                    # clean
scripts/install/install-linux.sh --mode source --flavor full      # HIL-capable
scripts/install/install-macos.sh --mode source
scripts/install/install-raspberrypi.sh --mode source --flavor full
```

The PowerShell variant is `scripts\install\install-windows.ps1 -Mode source`.
Use the manual path below if you want full control over the venv
layout or you are bootstrapping a locked-down CI runner.

## 2. Create a virtual environment

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
```

Python 3.10 or newer is required.

## 3. Pick the extras that match your needs

```bash
# Minimal -- matches the clean flavor. Runs on any OS.
python -m pip install -e .

# Clean + build + test tooling (PyInstaller, pytest, httpx).
python -m pip install -e '.[build,test]'

# HIL-capable on Linux (adds pyudev).
python -m pip install -e '.[hil]'

# HIL-capable Linux developer profile (pyudev + pyinstaller + pytest + pySim).
python -m pip install -e '.[full]'

# Optional: Universal GUI Command Center.
python -m pip install -e '.[gui]'        # desktop window via pywebview
python -m pip install -e '.[gui-server]' # headless web server only

# Optional: docs site tooling for `mkdocs build` / `mkdocs serve`.
python -m pip install -e '.[docs]'
```

`pyudev` is listed with `sys_platform == 'linux'` so the extras stay
installable on Windows / macOS -- the package simply gets skipped. The
extras can be combined: `pip install -e '.[full,gui]'` is a common
Linux-developer profile.

## 4. Verify the install

```bash
python main/main.py --version
python main/main.py --doctor
```

A clean source checkout prints:

```text
YggdraSIM <version> (source checkout)
```

On a Linux box with `.[hil]` or `.[full]` installed the doctor report
adds `HIL bridge readiness: OK` once `osmo-remsim-client-st2` is on
`PATH`.

## 5. Directly invoke module entry points

```bash
python main/main.py                             # unified launcher
python -m SCP03                                 # admin shell
python -m SCP11.live                            # live relay shell
python -m SCP11.local_access                    # local SMDPP shell
python -m SCP11.eim_local                       # local eIM shell
python -m Tools.ProfilePackage                  # SAIP tool shell
python -m Tools.SuciTool                        # SUCI tool shell
python -m Tools.HilBridge.main                  # HIL bridge -- Linux only
python -m Tools.HilBridge.supervisor            # HIL supervisor -- Linux only
```

After `pip install -e .` the same surfaces are available as console
scripts (`yggdrasim-scp03`, `yggdrasim-scp11-live`, ...). The HIL scripts
exit with a helpful message on non-Linux or clean-only environments.

## 6. Running the test suite

```bash
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 tests/test_flavor.py
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 tests/test_doctor.py
```

The project's testing policy (see the Testing Guide under
`site-docs/internals/testing-guide.md`) requires every pytest invocation
to target a single file or node id and to pass the noise-reducing flag
set `-q --tb=short --disable-warnings --no-header --maxfail=1`. Repo-wide
runs are reserved for explicit release validation.

## 7. Building a bundle from source

```bash
# Clean (any OS)
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec

# Full (Linux only -- requires pip install -e '.[full]')
YGGDRASIM_FLAVOR=full python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

The resulting onefile is written to
`dist/yggdrasim-clean` or `dist/yggdrasim-full`.

## HIL caveats when using a source checkout

- On macOS / Windows the HIL surfaces print a friendly "Linux only"
  pointer and never attempt to import `pyudev`.
- On Linux without `pyudev` the supervisor switches to `lsusb` polling,
  which is slower but still correct.
- SIMtrace2 firmware flashing / updating is documented separately in
  [`SIMTRACE2_CARDEM_GUIDE.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/SIMTRACE2_CARDEM_GUIDE.md).

## Related guides

- [`INSTALL_CLEAN.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/INSTALL_CLEAN.md) -- published lean executables.
- [`INSTALL_FULL.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/INSTALL_FULL.md) -- published HIL-capable executable.
- [`INSTALL_RASPBERRYPI.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/INSTALL_RASPBERRYPI.md) -- arm64 / Pi-specific notes.
- [`BUILD_AND_PACKAGING.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/BUILD_AND_PACKAGING.md) -- PyInstaller, `.deb`, and Docker notes.
- [`HIL_BRIDGE_GUIDE.md`](https://github.com/1oT/YggdraSIM/blob/main/guides/HIL_BRIDGE_GUIDE.md) -- operator flow once the HIL bundle is running.
