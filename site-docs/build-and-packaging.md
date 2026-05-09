# Build and Packaging

## Distribution models

The repository supports three publication and distribution paths:

- editable install from a source checkout
- containerized execution through `Dockerfile`
- bundled launcher builds through `yggdrasim_main.spec`

Each of those is published in two flavors:

| Flavor | HIL bridge included | Platforms | Typical operator |
| --- | --- | --- | --- |
| `clean` | no | Windows x86_64 / macOS arm64 / Linux x86_64 / Raspberry Pi arm64 | desktop / CI / field |
| `full`  | yes | Linux x86_64 only | HIL lab |
| source  | optional via `[hil]` | any supported Python host | developer |

### Optional extras (orthogonal to the flavor split)

These extras are independently selectable on a source install.

| Extra | Adds | Use when |
| --- | --- | --- |
| `[saip]` | (empty back-compat alias; pySim is already in base deps) | onboarding scripts that reference the old name |
| `[hil]` | `pyudev` (Linux only) | enabling the HIL bridge supervisor on a source install |
| `[build]` | `pyinstaller` | building flavored launcher artifacts |
| `[test]` | `pytest` | running the test suite |
| `[docs]` | `mkdocs-material`, plugins | building / serving this site locally |
| `[full]` | `[hil]` + `[build]` + `[test]` | one-shot install of the HIL-capable source flavor |

The active flavor is selected at build time through the
`YGGDRASIM_FLAVOR` environment variable. The PyInstaller spec writes a
`yggdrasim_common/_build_flavor.py` stamp so that runtime surfaces such
as `--version`, `--doctor`, and the main menu can report the correct
SKU even when the variable is not exported afterwards.

External host dependencies still matter for real card workflows,
especially PC/SC libraries, reader drivers, and optional `gpg`.

## Docker

The image is flavor-aware through a build argument:

```bash
# Clean (Windows / macOS / Linux hosts)
docker build -t yggdrasim:clean .

# Full (HIL-capable; Linux host, USB passthrough required at runtime)
docker build --build-arg YGGDRASIM_FLAVOR=full -t yggdrasim:full .
```

Typical use:

```bash
docker run --rm -it yggdrasim:clean
docker run --rm -it yggdrasim:clean yggdrasim-profile-package --cmd "HELP; EXIT"
```

Persist runtime state:

```bash
docker run --rm -it \
  -v "$(pwd)/YggdraSIM-data:/opt/YggdraSIM-data" \
  yggdrasim:clean yggdrasim-scp11-live --cmd "HELP; EXIT"
```

Containers are most predictable for offline analysis, simulator flows,
docs, and CI smoke paths. Real reader access still depends on
host-specific USB, PC/SC, and permission setup. HIL mode additionally
requires explicit SIMtrace2 passthrough; see `guides/HIL_BRIDGE_GUIDE.md`
and `guides/SIMTRACE2_CARDEM_GUIDE.md`.

## Bundled launcher

The committed `yggdrasim_main.spec` builds the unified launcher as one
flavored executable. Install build extras first:

```bash
python -m pip install -e '.[build,test]'     # clean
python -m pip install -e '.[full]'           # full (Linux)
```

Clean build:

```bash
YGGDRASIM_FLAVOR=clean python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

Full build (Linux x86_64):

```bash
YGGDRASIM_FLAVOR=full python -m PyInstaller --noconfirm --clean yggdrasim_main.spec
```

Expected outputs:

- Linux: `dist/yggdrasim-clean` or `dist/yggdrasim-full`
- Windows: `dist/yggdrasim-clean.exe` (no full build published)
- macOS: `dist/yggdrasim-clean` (no full build published)

Build on the target OS and architecture; CI emulates arm64 through
QEMU/Buildx to publish the Raspberry Pi clean bundle.

## Debian package path

The cleanest `.deb` flow is:

1. build the bundled launcher with PyInstaller (typically the `clean`
   flavor)
2. wrap that artifact in a Debian package
3. declare host runtime dependencies such as `libpcsclite1`, `pcscd`, or
   `gpg`

Minimal skeleton (clean):

```bash
mkdir -p pkg/DEBIAN pkg/usr/lib/yggdrasim pkg/usr/bin
cp dist/yggdrasim-clean pkg/usr/lib/yggdrasim/yggdrasim
ln -sf /usr/lib/yggdrasim/yggdrasim pkg/usr/bin/yggdrasim
```

A `full`-flavor `.deb` should additionally depend on
`osmo-remsim-client-st2` and `dfu-util`.

## Writable runtime expectations

Frozen builds keep bundled assets read-only and move mutable state into
the writable runtime root:

- `YggdraSIM-data` next to the executable when writable
- `~/YggdraSIM-data` as fallback
- `YGGDRASIM_RUNTIME_ROOT` when the runtime location must be forced
  explicitly

## Recommended validation

Validate these before publication:

- `dist/yggdrasim-{clean,full} --version` prints the expected flavor
- `dist/yggdrasim-{clean,full} --doctor` reports green on the target
  host, including the HIL probes for `full` builds
- the launcher opens and creates the writable runtime tree where
  expected
- `SCP11`, `SCP11.live`, and `SCP11.local_access` can read seeded
  runtime material
- `yggdrasim-profile-package` can still locate `pySim` (either the
  installed PyPI wheel or the optional on-disk `pysim/` clone when the
  SAIP ASN.1 compile path is needed)
- state persistence writes land in runtime state, not inside the
  installed bundle
- smart-card flows are tested on each target OS that will be supported
- on `full` builds, the HIL bridge can acquire the reader, launch
  `osmo-remsim-client-st2`, and mirror GSMTAP to Wireshark

## Deep reference

Use these authored guides for the complete reference:

- `guides/BUILD_AND_PACKAGING.md` - full packaging walkthrough
- `guides/INSTALL_CLEAN.md` - clean executable install
- `guides/INSTALL_FULL.md` - full (HIL) executable install
- `guides/INSTALL_FROM_SOURCE.md` - source install matrix
- `guides/INSTALL_RASPBERRYPI.md` - Raspberry Pi notes
- `guides/SIMTRACE2_CARDEM_GUIDE.md` - SIMtrace2 firmware / toolchain
