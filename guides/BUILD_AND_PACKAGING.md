<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Build and Packaging Guide

This repository supports three practical distribution models:

- editable install in a local Python environment
- containerized execution through `Dockerfile`
- bundled launcher builds through `yggdrasim_main.spec`

Each of those is published in two **flavors**:

| Flavor | Card Bridge / remote APDU | Direct SIMtrace2 HIL | Platforms | Dependencies |
|--------|---------------------------|----------------------|-----------|--------------|
| `clean` | Yes | No | Windows / macOS arm64 / Linux / Raspberry Pi arm64 | core only, no `pyudev`, no SIMtrace2 |
| `full`  | Yes | Yes | Linux x86_64 | core + `pyudev` + `osmo-remsim-client-st2` on host |

The active flavor is controlled by the `YGGDRASIM_FLAVOR` environment
variable at **build time**. The spec generates a PyInstaller runtime hook
under `build/` with the resolved flavor and version, so the **runtime**
launcher can advertise the correct SKU in its banner, in `--version`,
and in `--doctor` without modifying the source package.

Operator install notes for each flavor live in dedicated guides:

- [`INSTALL_CLEAN.md`](INSTALL_CLEAN.md)
- [`INSTALL_FULL.md`](INSTALL_FULL.md)
- [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md)
- [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md)
- [`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md)

## Optional extras orthogonal to the flavor split

The `clean` / `full` split only controls whether the local
SIMtrace2/RemSIM HIL stack is bundled. Card Bridge and remote APDU
streaming are part of the clean cross-platform surface. Several feature
surfaces sit on **opt-in extras** that are
declared in `pyproject.toml` and are not pulled in by either default
flavor:

| Extra          | Pulls in                                      | Used by                                        |
|----------------|-----------------------------------------------|------------------------------------------------|
| `[saip]`       | `openpyxl`, `defusedxml`                      | Hosting a spreadsheet import/export plugin (generator supplied separately) |
| `[mcp]`        | `mcp`                                         | Serving the tool surface to an AI agent (`yggdrasim-mcp`)    |
| `[hil]`        | `pyudev` (Linux only)                         | HIL bridge supervisor / event-driven hotplug   |
| `[gui]`        | `fastapi`, `uvicorn[standard]`, `pywebview`, `websockets`; pip Qt/WebEngine on Linux x86_64, `qtpy` plus system PyQt5 on Linux ARM | Desktop Universal GUI Command Center (`--gui`) |
| `[gui-server]` | `fastapi`, `uvicorn[standard]`, `websockets`  | Headless web Command Center (`--web-server`)   |
| `[open5gs]` | `pymongo>=4.5,<5.0`                           | YggdraCore BYO-Open5GS subscriber bridge       |
| `[build]`      | `pyinstaller`                                 | Producing `dist/yggdrasim-*` bundles           |
| `[test]`       | `pytest`, `httpx`                             | Running the `tests/` suite                     |
| `[docs]`       | `mkdocs`, `mkdocs-material`, `pymdown-extensions` | Building / serving `site-docs/`             |
| `[full]`       | `pyudev`, `fastapi`, `uvicorn`, `websockets` | Full Linux runtime profile |

Notes:

- `[full]` includes the headless GUI server dependencies, but not
  `pywebview`. An operator who wants the desktop window on a `full`
  source install must add `[gui]`: `pip install -e '.[full,gui]'`.
- Build and test tools are deliberately separate from `[full]`. A full
  developer/build environment uses `.[full,build,test,gui]`.
- The PyInstaller spec builds a paired CLI and desktop-GUI executable
  when the build environment has the `[gui]` extra installed. The CLI
  executable remains the shell/TUI surface; the GUI executable starts
  desktop mode by default.
- `[gui]` is a strict superset of `[gui-server]`; you only need
  `[gui-server]` on headless servers where `pywebview` would just fail
  to import a desktop toolkit.
- Linux ARM desktop source builds (`arm64` and `armv7l`) must install Debian's `python3-pyqt5`,
  `python3-pyqt5.qtwebengine`, and `python3-pyqt5.qtwebchannel` packages
  and create their build venv with `--system-site-packages`. This avoids
  the Qt 6 arm64 runtime's newer-glibc requirement on Debian Bookworm,
  supports the 32-bit ARM path, and retains a native desktop backend.

## Current structure status

The current layout is suitable for Docker and PyInstaller-style bundling with the
following model:

- bundled read-only assets come from the application bundle root
- mutable state lives under the runtime root
- non-editable wheel installs use the platform's per-user data directory and
  do not write into `site-packages`
- frozen builds use `YggdraSIM-data` next to the executable when writable, with
  `~/YggdraSIM-data` as fallback
- `YGGDRASIM_RUNTIME_ROOT` can override the runtime location explicitly

Packaging-sensitive areas addressed by the current layout:

- frozen module discovery uses an explicit published-package list and refuses
  ignored Python files or configured release canaries below those roots
- SCP11 relay defaults no longer need to write back into `config.py`; they can
  persist through runtime module state instead
- ProfilePackage now separates bundled seed content from writable runtime
  directories more cleanly
- SUCI tool launchers now resolve their working area from the runtime root

External host dependencies still matter:

- PC/SC access depends on host libraries, readers, and drivers
- encrypted inventory payloads still depend on the system `gpg` binary
- Windows `.exe` builds should be produced on Windows
- Linux `.deb` packages should be produced on the target Linux family

## Docker

The Dockerfile is flavor-aware through the `YGGDRASIM_FLAVOR` build
argument. Both flavors install from the committed, hash-bearing
`uv.lock`; `clean` omits udev entirely, while `full` installs the
`[full]` runtime extra.

```bash
# Clean (Windows / macOS / Linux hosts)
docker build -t yggdrasim:clean .

# Full (HIL-capable; Linux hosts)
docker build --build-arg YGGDRASIM_FLAVOR=full -t yggdrasim:full .
```

Run the umbrella SCP11 shell:

```bash
docker run --rm -it yggdrasim:clean
```

Run a specific installed command:

```bash
docker run --rm -it yggdrasim:clean yggdrasim-profile-package --cmd "HELP; EXIT"
```

Keep runtime state on the host:

```bash
docker run --rm -it \
  -v "$(pwd)/YggdraSIM-data:/opt/YggdraSIM-data" \
  yggdrasim:clean yggdrasim-scp11-live --cmd "HELP; EXIT"
```

HIL operation from the `full` image requires USB passthrough for the
SIMtrace2 and reader (for example `--device /dev/bus/usb` on Linux).
That integration is host-specific; see
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md) and
[`HIL_BRIDGE_GUIDE.md`](HIL_BRIDGE_GUIDE.md) before trying it.

Container notes:

- the image is most predictable for offline analysis, simulator flows, docs, and
  CI smoke paths
- real reader access is possible only with explicit host integration for PC/SC
  libraries, readers, and permissions
- do not assume smart-card USB passthrough is portable across hosts without
  reader-specific validation

## Bundled launchers

The committed `yggdrasim_main.spec` builds the unified `main/main.py`
launcher as a CLI executable plus a desktop GUI companion for the same
flavor.

Wheel and pipx installs get their launchers from two entry-point tables
instead. `[project.scripts]` holds the console commands;
`[project.gui-scripts]` holds `yggdrasim-desktop`, which setuptools backs
with `pythonw` on Windows so a shortcut opens no console window. A name
must not appear in both tables: each generates the same executable and
the loser is overwritten silently.

Install the build dependencies first:

```bash
python -m pip install -e '.[saip,build,test,gui]'   # clean + GUI companion
python -m pip install -e '.[full,saip,build,test,gui]' # full + GUI companion (Linux)
```

Build a clean bundle:

```bash
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

Build a full bundle (Linux x86_64):

```bash
YGGDRASIM_FLAVOR=full python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

Expected outputs:

- Linux:   `dist/yggdrasim-clean` / `dist/yggdrasim-gui-clean`, or
  `dist/yggdrasim-full` / `dist/yggdrasim-gui-full`
- Windows: `dist/yggdrasim-clean.exe` / `dist/yggdrasim-gui-clean.exe`
  (full flavor is not published for Windows)
- macOS:   `dist/yggdrasim-clean` / `dist/yggdrasim-gui-clean`
  (full flavor is not published for macOS)

Build notes:

- Build on the target OS and architecture. There is no cross-compilation
  path; CI emulates arm64 through QEMU inside Docker Buildx to publish
  the Raspberry Pi bundle.
- The spec generates build metadata below `build/bundle-data/` and
  compiles it as a runtime hook, so the resulting executable reports its
  own flavor/version without leaving a stale stamp in an editable source
  checkout.
- The clean bundle explicitly excludes the local HIL supervisor/runtime
  (`yggdrasim_common.hil_bridge_runtime`, `pyudev`, and the Linux
  SIMtrace2/RemSIM modules) while retaining `Tools.CardBridge` plus the
  minimal APDU relay/PCSC helpers it uses. Tests and launcher logic handle
  direct HIL being absent at runtime.
- Immutable runtime resources are selected file-by-file through
  `scripts/release/bundle-data.json`. The build fails on symlinks,
  repository escapes, missing resources, or release canaries; ignored
  workspaces and local extensions are never recursively copied.
- Release wheels are built from a freshly generated source distribution,
  not a checkout's potentially stale `build/` tree. The wheel verifier
  rejects every non-code resource that is not in the same allowlist.
- Tagged releases must match `v<project.version>`. Windows and macOS jobs
  require an annotated tag whose exact commit is reachable from
  `origin/main`, plus configured signing credentials. Release assets carry
  a CycloneDX SBOM plus `SHA256SUMS`, and GitHub publishes signed build
  provenance. Install scripts verify checksums before publication and the
  Windows installer additionally verifies Authenticode.
- `yggdrasim-gui-*` prepends `--gui` unless the operator explicitly
  passes `--web-server`; flags such as `--port`, `--token-file`, and
  `--allow-origin` are still parsed by the shared launcher.
- Console-script entry points such as `yggdrasim-scp11-live` remain the
  simpler operator surface for editable installs and Docker usage.

## Manual unsigned main-branch test drafts

The **Main Test Draft Release** workflow is a manual fallback for collecting
cross-platform test builds when ordinary GitHub Actions artifact storage is
unavailable. It is deliberately separate from the production release path:

- it can only be started with `workflow_dispatch` against `main`;
- pull requests and ordinary pushes never create or update a release;
- each run creates its own draft with the transient tag
  `ci-main-<run-id>-<attempt>`, targeted at the exact tested commit;
- the draft title, notes, and bundled notices identify every output as an
  **UNSIGNED TEST BUILD** and record both the commit SHA and Actions run;
- the draft is not marked as the latest release, and the install scripts do
  not consume `ci-main-*` drafts or their non-canonical asset names.

These assets are suitable for controlled build and smoke testing only.
Windows executables are not Authenticode-signed and can trigger Microsoft
Defender SmartScreen. macOS executables are unsigned and unnotarized and can
trigger Gatekeeper. Do not redistribute either as a production installer or
use the draft as evidence that the production signing gates passed.

Each primary test asset has a matching `.sha256` sidecar. After all build legs
finish, the workflow verifies the complete expected asset set and those
sidecars, then adds a CycloneDX SBOM and a global `SHA256SUMS` manifest. A
successfully verified draft is marked **COMPLETE**; a failed or partial run is
marked **INCOMPLETE** and remains a draft for diagnosis. Before testing an
asset, verify it against its sidecar or the global manifest.

Drafts are not removed automatically. Periodically delete stale
`ci-main-*` draft releases and their transient tags after they are no longer
needed. The annotated `v*` production path remains unchanged: it is
signed/notarized where required, publishes canonical installer-facing names,
and fails closed if its signing, provenance, checksum, or build gates do not
pass.

### Windows-only artifact test

Use the manual **Windows Test Artifact** workflow when only the Windows x86_64
clean bundle is needed. It is restricted to the exact revision dispatched
from `main` and does not start any Linux, macOS, Debian, or Docker build.

The workflow first attempts a one-day GitHub Actions artifact containing the
ZIP and its `.sha256` sidecar. That upload is a best-effort storage probe: an
account-level artifact-quota error is recorded in the run summary but does not
discard the build. Independently, every run creates a unique, private draft
prerelease tagged `ci-windows-main-<run-id>-<attempt>`. The workflow uploads,
redownloads, checksum-verifies, extracts, and smoke-tests that draft's Windows
bundle before changing the draft title from **INCOMPLETE** to **COMPLETE**.

The ZIP contains `yggdrasim-clean.exe`, `yggdrasim-gui-clean.exe`, and an
`UNSIGNED-TEST-BUILD.txt` notice. The executables are not Authenticode-signed,
so use them only for controlled testing and expect Microsoft Defender
SmartScreen warnings. The draft flow never publishes a production release,
overwrites assets, or deletes an earlier run.

## Debian package path

The cleanest `.deb` path is:

1. build the bundled launcher with PyInstaller (typically the `clean`
   flavor, which is the default target for the CI `.deb` job)
2. wrap that artifact in a Debian package
3. declare the host-side runtime dependencies you still need, such as
   `libpcsclite1`, `pcscd`, or `gpg`

Minimal skeleton (clean bundle):

```bash
mkdir -p pkg/DEBIAN pkg/usr/lib/yggdrasim pkg/usr/bin
cp dist/yggdrasim-clean pkg/usr/lib/yggdrasim/yggdrasim
cp dist/yggdrasim-gui-clean pkg/usr/lib/yggdrasim/yggdrasim-gui
ln -sf /usr/lib/yggdrasim/yggdrasim pkg/usr/bin/yggdrasim
ln -sf /usr/lib/yggdrasim/yggdrasim-gui pkg/usr/bin/yggdrasim-gui
```

Example `pkg/DEBIAN/control`:

```text
Package: yggdrasim
Version: [ENTER VERSION HERE]
Architecture: amd64
Maintainer: [ENTER MAINTAINER HERE]
Depends: libpcsclite1, pcscd, gpg, libegl1, libgl1, libxkbcommon-x11-0, libxcb-cursor0, libxcb-keysyms1, libxcb-shape0, libxcb-icccm4
Description: YggdraSIM secure-element and eUICC toolkit (clean build)
```

Build the package:

```bash
dpkg-deb --build pkg "yggdrasim_[ENTER VERSION HERE]_amd64.deb"
```

A `full`-flavor `.deb` is possible but should additionally depend on
`osmo-remsim-client-st2` and `dfu-util`; see
[`INSTALL_FULL.md`](INSTALL_FULL.md) and
[`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md).

## Windows executable notes

For Windows publication:

- build the executable on Windows with
  `YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec`
- Windows only ships the `clean` flavor; direct SIMtrace2 HIL is Linux-only,
  but Card Bridge / remote APDU streaming is included
- validate bundled smart-card, Card Bridge, SSH tunnel, and TLS flows on a
  reader-equipped Windows host
- treat `.exe` publication as a packaging layer, not as a substitute for host
  driver installation

## macOS executable notes

For macOS publication:

- build per architecture on that architecture (`x86_64` and `arm64`
  separately); CI runs both
- only `clean` is published; direct SIMtrace2 HIL is Linux-only, but Card
  Bridge / remote APDU streaming is included
- operators need Xcode command-line tools to run editable installs on
  source checkouts

## Recommended validation after packaging

Validate these before publication:

- launcher opens and writable runtime tree is created where expected
- `SCP11`, `SCP11.live`, and `SCP11.local_access` can read their seeded runtime
  material
- `yggdrasim-profile-package` can still locate `pySim` (either the
  installed PyPI wheel or the optional on-disk `pysim/` clone when the
  SAIP ASN.1 compile path is needed)
- state persistence writes land in runtime state, not inside the installed bundle
- smart-card flows are validated on each target OS that will be supported

## Pre-release sanitization

Before a commit that goes to a public tree, scan for identifiers that must
not ship:

```bash
python scripts/release/validate_release.py sanitize
```

It reports every tracked file carrying a real MCC/MNC, a non-test ICCID
IIN, or a routable address outside RFC 5737, and exits non-zero so it can
gate a release commit. Banned-prose findings are printed as advisory and do
not fail the run; `python -m plugins.release_sanitizer --phrases-are-fatal`
makes them fail too.

The rules live in an untracked plugin rather than in this tree. They name
the allocations the repo is scrubbed of, so publishing the detector would
tell a reader which allocations were once here -- it would leak more than
it prevents. A checkout without the plugin prints that it is skipping and
exits zero, so a public clone is never blocked by the absence of a check it
cannot run.
