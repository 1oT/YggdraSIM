# Build and Packaging Guide

This repository supports three practical distribution models:

- editable install in a local Python environment
- containerized execution through `Dockerfile`
- bundled launcher builds through `yggdrasim_main.spec`

Each of those is published in two **flavors**:

| Flavor | HIL bridge included | Platforms                                   | Dependencies                         |
|--------|---------------------|---------------------------------------------|--------------------------------------|
| `clean` | No                 | Windows / macOS / Linux / Raspberry Pi arm64 | core only, no `pyudev`, no SIMtrace2 |
| `full`  | Yes                | Linux x86_64                                | core + `pyudev` + `osmo-remsim-client-st2` on host |

The active flavor is controlled by the `YGGDRASIM_FLAVOR` environment
variable at **build time**. The spec writes the resolved flavor into
`yggdrasim_common/_build_flavor.py` so the **runtime** launcher can
advertise the correct SKU in its banner, in `--version`, and in
`--doctor` even when the env var is not set later.

Operator install notes for each flavor live in dedicated guides:

- [`INSTALL_CLEAN.md`](INSTALL_CLEAN.md)
- [`INSTALL_FULL.md`](INSTALL_FULL.md)
- [`INSTALL_FROM_SOURCE.md`](INSTALL_FROM_SOURCE.md)
- [`INSTALL_RASPBERRYPI.md`](INSTALL_RASPBERRYPI.md)
- [`SIMTRACE2_CARDEM_GUIDE.md`](SIMTRACE2_CARDEM_GUIDE.md)

## Optional extras orthogonal to the flavor split

The `clean` / `full` split only controls whether the HIL bridge stack
is bundled. Several feature surfaces sit on **opt-in extras** that are
declared in `pyproject.toml` and are not pulled in by either default
flavor:

| Extra          | Pulls in                                      | Used by                                        |
|----------------|-----------------------------------------------|------------------------------------------------|
| `[saip]`       | `pySim` from the upstream osmocom mirror      | SAIP transcode TUI, SCP11-local / eIM-local    |
| `[hil]`        | `pyudev` (Linux only)                         | HIL bridge supervisor / event-driven hotplug   |
| `[gui]`        | `fastapi`, `uvicorn[standard]`, `pywebview`, `websockets` | Desktop Universal GUI Command Center (`--gui`) |
| `[gui-server]` | `fastapi`, `uvicorn[standard]`, `websockets`  | Headless web Command Center (`--web-server`)   |
| `[build]`      | `pyinstaller`                                 | Producing `dist/yggdrasim-*` bundles           |
| `[test]`       | `pytest`, `httpx`                             | Running the `tests/` suite                     |
| `[docs]`       | `mkdocs`, `mkdocs-material`, `pymdown-extensions` | Building / serving `site-docs/`             |
| `[full]`       | `pyudev`, `pyinstaller`, `pytest`, `pySim`    | Full Linux maintainer profile                  |

Notes:

- `[full]` does **not** include `[gui]` / `[gui-server]`. An operator
  who wants the desktop window or the remote-lab web app on a `full`
  install must add them explicitly:
  `pip install -e '.[full,gui]'`.
- The PyInstaller spec does not currently bundle the GUI extras into
  the single-file launcher. Use the editable install or a Docker
  image when you need `--gui` / `--web-server`.
- `[gui]` is a strict superset of `[gui-server]`; you only need
  `[gui-server]` on headless servers where `pywebview` would just fail
  to import a desktop toolkit.

## Current structure status

The current layout is suitable for Docker and PyInstaller-style bundling with the
following model:

- bundled read-only assets come from the application bundle root
- mutable state lives under the runtime root
- frozen builds use `YggdraSIM-data` next to the executable when writable, with
  `~/YggdraSIM-data` as fallback
- `YGGDRASIM_RUNTIME_ROOT` can override the runtime location explicitly

Packaging-sensitive areas addressed by the current layout:

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
argument. `clean` is the default and installs `pip install -e .`;
`full` installs the `[full]` extra so the HIL bridge runtime is
available inside the image.

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

## Single bundled launcher

The committed `yggdrasim_main.spec` builds the unified `main/main.py`
launcher as one flavored executable.

Install the build dependencies first:

```bash
python -m pip install -e '.[build,test]'       # clean
python -m pip install -e '.[full]'             # full (Linux)
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

- Linux:   `dist/yggdrasim-clean`   or   `dist/yggdrasim-full`
- Windows: `dist/yggdrasim-clean.exe`   (full flavor is not published for Windows)
- macOS:   `dist/yggdrasim-clean`   (full flavor is not published for macOS)

Build notes:

- Build on the target OS and architecture. There is no cross-compilation
  path; CI emulates arm64 through QEMU inside Docker Buildx to publish
  the Raspberry Pi bundle.
- The spec writes `yggdrasim_common/_build_flavor.py` so the resulting
  executable reports its own flavor in `--version`, in the banner, and
  in `--doctor`. The stamp file is git-ignored.
- The clean bundle explicitly excludes `Tools/HilBridge`,
  `yggdrasim_common.hil_bridge_runtime`, and `pyudev`. Tests and
  launcher logic already handle those surfaces being absent at runtime.
- Console-script entry points such as `yggdrasim-scp11-live` remain the
  simpler operator surface for editable installs and Docker usage.

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
ln -sf /usr/lib/yggdrasim/yggdrasim pkg/usr/bin/yggdrasim
```

Example `pkg/DEBIAN/control`:

```text
Package: yggdrasim
Version: [ENTER VERSION HERE]
Architecture: amd64
Maintainer: [ENTER MAINTAINER HERE]
Depends: libpcsclite1, pcscd, gpg
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
- Windows only ships the `clean` flavor; the HIL bridge is Linux-only
- validate bundled smart-card and TLS flows on a reader-equipped Windows host
- treat `.exe` publication as a packaging layer, not as a substitute for host
  driver installation

## macOS executable notes

For macOS publication:

- build per architecture on that architecture (`x86_64` and `arm64`
  separately); CI runs both
- only `clean` is published; the HIL bridge is Linux-only
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
