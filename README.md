# YggdraSIM

YggdraSIM is a Python toolkit for secure-element research, eUICC analysis, SIM/eSIM management, OTA payload work, SCP11 relay/local flows, and SAIP profile-package tooling. The repository keeps the operator surfaces, protocol helpers, and test suite in one workspace so card work, relay work, and package work can be exercised without switching projects. The SAIP decoding path and the SCP11 local / eIM flows pull in upstream `pySim`; install them in one shot with `pip install -e '.[saip]'` (the `[saip]` extra pins pySim directly from its GitHub mirror).

## Distribution at a glance

YggdraSIM is offered in three shapes:

| Flavor                           | Platforms                                              | Includes HIL bridge | Guide |
|----------------------------------|--------------------------------------------------------|---------------------|-------|
| **Clean executable**             | Windows / macOS / Linux x86_64 / Raspberry Pi (arm64)  | No                  | [`guides/INSTALL_CLEAN.md`](guides/INSTALL_CLEAN.md) |
| **Full executable**              | Linux x86_64 / Raspberry Pi (arm64)                    | Yes                 | [`guides/INSTALL_FULL.md`](guides/INSTALL_FULL.md) |
| **Source checkout (`pip install -e .`)** | Any OS, HIL opt-in on Linux                    | Yes (Linux only)    | [`guides/INSTALL_FROM_SOURCE.md`](guides/INSTALL_FROM_SOURCE.md) |

The **clean** flavor is the default distribution. It omits `Tools/HilBridge` and the `yggdrasim_common.hil_bridge_runtime` module, and therefore does not require `pyudev` or `osmo-remsim-client-st2`. Use the **full** flavor when you need the SIMtrace2-based hardware-in-the-loop flow, or install from **source** when you want the test suite, editable imports, or on-device builds. HIL operators should also read [`guides/SIMTRACE2_CARDEM_GUIDE.md`](guides/SIMTRACE2_CARDEM_GUIDE.md) for flashing and updating the SIMtrace2 firmware. Raspberry Pi users have a dedicated walk-through in [`guides/INSTALL_RASPBERRYPI.md`](guides/INSTALL_RASPBERRYPI.md).

Every launcher reports its active flavor in the main-menu banner, the
`--version` string, and the `--doctor` report, so operators can always
tell which bundle they are working with.

### Scripted install

One-liner installer scripts live in `scripts/install/` and wrap both
the pre-built-release and the editable-source paths for every
supported host. See [`scripts/install/README.md`](scripts/install/README.md) for the full flag
reference.

```bash
scripts/install/install-linux.sh                      # Linux desktop, clean, latest release
scripts/install/install-linux.sh --flavor full        # Linux desktop, HIL-capable release
scripts/install/install-macos.sh                      # macOS (clean only)
scripts/install/install-raspberrypi.sh --flavor full  # Pi arm64, HIL-capable
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1
```

## Ownership and authors

- Copyright holder: 1oT OÜ (Tallinn, Estonia)
- Author and lead maintainer: Hampus Hellsberg (Creator, Lead Architect, Lead Maintainer)
- Additional contributors: see repository commit history

## What YggdraSIM contains

| Subsystem | Role | Primary operator surface |
|-----------|------|--------------------------|
| `main/` | Unified launcher, path setup, and in-process module dispatch | `python main/main.py` |
| `SCP03/` | GlobalPlatform-style admin shell, filesystem work, GSMA retrieval, report/export | interactive shell + one-shot commands |
| `SCP80/` | OTA packet construction, decode, and reader/send flows | OTA CLI |
| `SCP11/live/` | Live relay shell for LPAd / IPAd / IPAe work | interactive SCP11 console |
| `SCP11/test/` | Test relay shell mirroring the live surface | interactive SCP11 console |
| `SCP11/local_access/` | Direct local `ISD-R` bring-up and one-shot `LOAD-PROFILE` | local SCP11 shell |
| `SCP11/eim_local/` | eIM-local package generation, localized polling, hotfolder queues, and handover flows | eIM local shell |
| `Tools/ProfilePackage/` | SAIP shell, transcode UI, lint engine, JSON↔DER bridge | profile-package shell + TUI |
| `Tools/SuciTool/` | SUCI helper tooling | helper shell |
| `pysim/` | **Optional** developer checkout of upstream pySim (gitignored). Only needed when working against an unreleased upstream branch; the released SAIP surface ships via the `[saip]` extra (`pip install 'yggdrasim[saip]'`). | optional external tree |

## Core capabilities

- PC/SC-based GlobalPlatform and UICC/eUICC administration through `SCP03`.
- OTA packet generation, wrapping, transport, and decode through `SCP80`.
- Split SCP11 relay environments for live and test work, with `SCP11/relay`
  retained as the compatibility namespace.
- Direct local SCP11 provisioning and metadata handling through `SCP11/local_access`.
- eIM-centric local package work, localized polling, hotfolder campaigns, and response tracking through `SCP11/eim_local`.
- Hardware-in-the-loop SIMtrace2 bridge with GSMTAP mirroring, brokered APDU side-channel access, and modem REFRESH control through `Tools/HilBridge`.
- SAIP / UPP profile inspection, linting, JSON↔DER transcode, and shell automation through `Tools/ProfilePackage`.
- Visual side-by-side SAIP profile diffing (shell + Textual TUI) via
  `DIFF` / `DIFF-TUI` inside the profile-package shell.
- Simulator-to-TUI auto-open pipeline via `yggdrasim-profile-autoload`
  and the `WATCH-SIMCARD` shell command.
- Opt-in, safety-gated eUICC APDU mutation fuzzer via
  `yggdrasim-apdu-fuzzer` (`--i-mean-it` + ICCID/IMSI allow-list
  required).
- EUM / SM-DP+ diagnostics "God-Mode": session-key injection and
  Wireshark/tshark Lua dissector for BF36 Bound Profile Packages via
  `yggdrasim-eum-diag`.
- Centralized mutable state in SQLite, with optional `gpg`-based encryption for sensitive payloads.

## Quick start

### Prerequisites

- Python 3.10+
- A PC/SC-compatible smart-card reader for card flows
- Optional: `gpg` when encrypted SQLite inventory payloads are enabled

### Install Python dependencies

```bash
python -m pip install -r requirements.txt
python -m pip install -e '.[saip]'
```

The `[saip]` extra installs upstream pySim from its GitHub mirror
(`pySim @ git+https://github.com/osmocom/pysim.git`). That gives you
the SCP11-local flows, eIM-local flows, SAIP ASN.1 compile, the SAIP
transcode TUI, and the profile-scaffold wizards without any manual
clone step. A bare `pip install -e .` without the extra still works if
you only need the flows that do not touch SAIP (core SIMCARD
simulator, HIL bridge, SCP03, SCP80, SCP11 relay); `yggdrasim
--doctor` marks pySim as `WARN` in that case, which is expected.

If you are working against an unreleased upstream pySim branch you can
still drop a developer checkout at `<repo>/pysim` (`git clone
https://github.com/osmocom/pysim.git pysim`); that tree takes priority
over the installed wheel. The `pysim/` path stays gitignored so it
never ships in the distribution.

The editable install is what makes `python -m SCP11.live`,
`python -m SCP11.local_access`, and the other package entry points work from
any directory in the same environment. Without it, those `python -m ...`
commands only work when the repository root is already on `sys.path`, such as
when you are inside the repo.

The editable install also provides installed commands:

```bash
yggdrasim-scp03
yggdrasim-scp80
yggdrasim-scp11
yggdrasim-scp11-live
yggdrasim-scp11-test
yggdrasim-scp11-relay
yggdrasim-scp11-local-access
yggdrasim-scp11-eim-local
yggdrasim-hil-bridge
yggdrasim-hil-supervisor
yggdrasim-profile-package
yggdrasim-profile-autoload
yggdrasim-apdu-fuzzer
yggdrasim-eum-diag
yggdrasim-suci-tool
```

### Docker and bundle packaging

Container, PyInstaller, `.deb`, and `.exe` notes now live in:

- `guides/BUILD_AND_PACKAGING.md` — flavor-aware build commands
- `guides/INSTALL_CLEAN.md` — operator install for the clean bundle
- `guides/INSTALL_FULL.md` — operator install for the HIL-capable bundle
- `guides/INSTALL_FROM_SOURCE.md` — editable install and test-suite usage

Quick container smoke path:

```bash
docker build -t yggdrasim:clean .
docker run --rm -it yggdrasim:clean yggdrasim-scp11 --cmd "HELP; EXIT"

# HIL-capable image (Linux hosts only; SIMtrace2 access requires USB passthrough)
docker build --build-arg YGGDRASIM_FLAVOR=full -t yggdrasim:full .
```

### Launch the main menu

```bash
python main/main.py
python main/main.py --debug
python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json
```

Use `--debug` (or `--verbose`) on the wrapper when you want debug to become the
global default for modules launched from the main menu. Without it,
module-specific debug flags remain opt-in.

Diagnostic helpers:

```bash
python main/main.py --version
python main/main.py --doctor
```

`--version` is sourced from `pyproject.toml` through
`yggdrasim_common/__about__.py`, so any wrapper, plugin, or installed command
that imports `yggdrasim_common.__about__.__version__` reports the same value.
`--doctor` runs a read-only preflight report covering Python version,
`cryptography`, `pycryptodomex`, `asn1tools`, the optional `pysim/` tree,
SQLite, optional `textual` (TUI), PC/SC reader visibility, and the `gpg`
binary used by the optional inventory encryption provider. Exit code is `0`
when every probe is `ok`/`info` and `1` when any probe is `warn`/`fail`, so
the helper can be used directly from CI pipelines.

Simulator note:

- `--sim-eim-identity` selects the simulated card's default BF55 eIM identity file.
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM shell identity and does not automatically reconfigure the simulated card.

### Direct module entry points

After `python -m pip install -e /path/to/YggdraSIM`, these can be run from any
directory that uses the same Python environment:

```bash
python -m SCP03
python -m SCP80
python -m SCP11
python -m SCP11.live
python -m SCP11.test
python -m SCP11.relay
python -m SCP11.local_access
python -m SCP11.eim_local
python -m Tools.HilBridge.main
python -m Tools.HilBridge.supervisor
python -m Tools.ProfilePackage
python -m Tools.SuciTool
```

If you skip the editable install, run them from the repository root instead.

Installed command equivalents after editable install:

```bash
yggdrasim-scp03
yggdrasim-scp80
yggdrasim-scp11
yggdrasim-scp11-live
yggdrasim-scp11-test
yggdrasim-scp11-relay
yggdrasim-scp11-local-access
yggdrasim-scp11-eim-local
yggdrasim-hil-bridge
yggdrasim-hil-supervisor
yggdrasim-profile-package
yggdrasim-profile-autoload
yggdrasim-apdu-fuzzer
yggdrasim-eum-diag
yggdrasim-suci-tool
```

For non-interactive automation, piping, and ready-to-run profile lifecycle
examples, see:

- `guides/CLI_AND_PIPING_GUIDE.md`
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `guides/BUILD_AND_PACKAGING.md`
- `guides/HIL_BRIDGE_GUIDE.md`
- `guides/INSTALL_CLEAN.md`
- `guides/INSTALL_FULL.md`
- `guides/INSTALL_FROM_SOURCE.md`
- `guides/INSTALL_RASPBERRYPI.md`
- `guides/SIMTRACE2_CARDEM_GUIDE.md`

## Persistent state and security model

YggdraSIM now uses `state/device_inventory.sqlite3` as the primary mutable state store for:

- per-card `ICCID` inventory payloads
- per-card `EID` inventory payloads
- per-eIM identity counters and runtime markers
- module-level mutable settings such as the migrated `SCP03` and `SCP80` runtime state

Current migration model:

- `Workspace/SCP03/keys.ini` is a legacy import source. Live SCP03 state is now SQLite-primary.
- `SCP80/ota_config.ini` is a legacy import source. Live SCP80 state is now SQLite-primary.
- `Workspace/LocalEIM/eim_runtime_state.json` is a legacy import source. Live runtime state is now SQLite-primary.
- `Workspace/LocalEIM/eim_identity.json` defines the Local eIM shell identity, endpoint defaults, and certificate paths.
- `Workspace/SCP03/aid.txt`, `Workspace/SCP03/fids.txt`, and `Workspace/SCP03/binds.json` remain plain files because they are still better suited to manual editing and diff review.
- `Workspace/SIMCARD/eim_identity.json` controls the simulator's default BF55 eIM identity and is intentionally separate from `Workspace/LocalEIM/eim_identity.json`.
- use `Workspace/SIMCARD/isdr_config.json` with `eim_entries` when you need a full custom card-side eIM layout instead of the single seeded simulator default

Optional encryption:

- `state/inventory_crypto.json` controls SQLite payload encryption.
- Default is `enabled: false` to keep onboarding friction low.
- When enabled, inventory and module-state payloads are encrypted on write and decrypted only on demand.
- Current provider is `gpg` via the system binary and agent/keyring model.

Frozen executable runtime model:

- source runs continue to use the repository tree directly
- frozen builds spawn a writable runtime tree under `YggdraSIM-data` next to
  the executable when possible
- if that location is not writable, the runtime tree falls back to
  `~/YggdraSIM-data`
- set `YGGDRASIM_RUNTIME_ROOT` to force a specific runtime root
- user-editable certs, keys, package templates, hotfolders, caches, and state
  are read from that writable runtime tree in frozen mode
- `plugins/` is scanned at launch from the writable runtime root so optional
  capabilities can be dropped in after publication without rebuilding the core

## Optional plugins

YggdraSIM supports runtime plugins through `plugins/`.

- the loader scans `plugins/` at launch and registers plugin-provided
  capabilities
- the folder is intended for optional or restricted features that should not be
  shipped in the published core
- plugin implementation files are ignored by default; keep the loader contract
  and drop local plugins into `plugins/` when needed
- see `plugins/README.md` for the expected `register_plugins(manager)` entry
  point

## Typical operator paths

### SCP03 admin shell

Use `SCP03` for:

- GlobalPlatform authentication and registry operations
- ETSI / 3GPP filesystem navigation
- GSMA retrieval and local profile-state work
- report/export generation
- HIL keybag export via `EXPORT-KEYBAG` (after `AUTH-SD`)

Example:

```text
[APDU] > AUTH-SD
[A0...00] > APPS
[A0...00] > LIST
[A0...00] > SELECT USIM/IMSI
[A0...00] > READ
[A0...00] > EXPORT-KEYBAG session.keys.json run-01
```

### SCP80 OTA shell

Use `SCP80` for:

- OTA payload wrapping
- secured packet field tuning
- direct reader-mode or print-only flows
- `ICCID`-specific OTA state reuse through the shared inventory

### SCP11 relay shells

Use `SCP11/live` or `SCP11/test` for:

- `LPAd`: `DOWNLOAD-PROFILE <activation>`
- `IPAd`: `DISCOVER`, `DOWNLOAD [matchingId]`
- `IPAe` polling / compatibility work in relay mode

Example:

```text
[eSIM Live] > HELP
[eSIM Live] > DISCOVER
[eSIM Live] > DOWNLOAD-PROFILE LPA:1$...
```

See:

- `SCP11/README.md`
- `SCP11/live/README.md`
- `SCP11/test/README.md`
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

### HIL bridge and SIMtrace2

Use `Tools/HilBridge` when you need a physical-card-to-modem bridge with:

- `RSPRO` / `osmo-remsim-client-st2` connectivity on `127.0.0.1:9997`
- GSMTAP mirroring to Wireshark on UDP `4729`
- exclusive reader ownership with relay-backed YggdraSIM side access
- manual HIL capture sessions started and stopped on demand
- offline review of saved `.pcap` / `.pcapng` captures via
  `python main/main.py --open-pcap <path>` (no bridge, no supervisor);
  optional `--keybag <path>` unwraps SCP03 / SCP11c secure-messaging
  APDUs inline

Session-key keybag JSONs are produced by:

- `EXPORT-KEYBAG` in the SCP03 admin shell (after `AUTH-SD`)
- `EXPORT-KEYBAG` in `SCP11.local_access` (after any BSP-building verb)
- `python -m SCP11.local_access --dump-keybag <path>` non-interactively

`python -m SCP11.live --dump-keybag` is a documented no-op stub — live
SCP11c BSP keys are derived inside the eUICC and never reach the host.

The HIL bridge is **only shipped in the full executable and in source
checkouts** (Linux only). The clean executable hides the `[B] HIL Bridge
Session` menu entry, prints a pointer to the install guides when the
entry is still invoked manually, and omits the `yggdrasim-hil-bridge` /
`yggdrasim-hil-supervisor` console scripts.

See:

- `guides/HIL_BRIDGE_GUIDE.md` — operator flow
- `guides/INSTALL_FULL.md` — HIL-capable executable install
- `guides/SIMTRACE2_CARDEM_GUIDE.md` — flashing / updating SIMtrace2 and `osmo-remsim-client-st2`
- `guides/systemd/yggdrasim-hil-supervisor.service.example`

### Local SMDPP

Use `SCP11/local_access` for direct on-card local provisioning without the relay shells:

```text
[Local SMDPP] > STATUS
[Local SMDPP] > PROFILE /path/to/profile.der
[Local SMDPP] > METADATA /path/to/metadata.json
[Local SMDPP] > LOAD-PROFILE
[Local SMDPP] > EXPORT-KEYBAG session.keys.json local-run
```

`EXPORT-KEYBAG` (or the non-interactive `--dump-keybag <path>` launcher
flag) dumps the last-derived SCP11c BSP keys as a HIL keybag JSON for
later offline decryption in the HIL decoded-APDU TUI.

This path now restores per-card local choices by `EID` from the shared SQLite inventory.

For `--cmd`, `--stdin`, and log-capture examples, use
`guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`.

### Local eIM

Use `SCP11/eim_local` when you need:

- eIM identity and package fixtures
- local handover simulation
- hotfolder and poll campaign exercises
- AddInitialEim / AddEim command generation
- eIM response logs and counter control

When the card side is simulated:

- `Workspace/LocalEIM/eim_identity.json` still describes the local eIM / SM-DP+ side
- `Workspace/SIMCARD/eim_identity.json`, the wrapper settings screen, or `--sim-eim-identity` controls what the simulated card advertises in BF55

See:

- `SCP11/eim_local/README.md`
- `SCP11/eim_local/GUIDE.md`
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

### Profile package tooling

Use `Tools/ProfilePackage` for:

- SAIP shell operations
- JSON↔DER transcode
- linting and package inspection
- `saip-tool` bridge work

The transcode UI now uses a configurable transcode output directory, persists
its pane layout in the workspace, supports OS clipboard copy/paste, and writes
`*.transcode.json`, `*.transcode.der`, and `*.transcode.txt` sidecars.

`akaParameter` tooling (3GPP TS 35.206 / TS 35.231):

- `LIST-AKA` — read-only summary of every `akaParameter` PE in the active
  profile, including algorithm, Ki/OPc byte length, Keccak count,
  `authCounterMax`, and whether a 32-slot `sqnInit` seed is present.
- `PROVISION-AKA <out.der | IN-PLACE> [ALGORITHM=..] [KI=..] [OPC=..]
  [NUMBER-OF-KECCAK=..] [AUTH-COUNTER-MAX=..] [SQN-INIT=..]` — tag-granular
  provisioning. With only an output path it walks the interactive wizard.
  Passing any `NAME=VALUE` override switches to non-interactive mode so the
  command is safe to paste into scripts or tests. `IN-PLACE` rewrites the
  currently-selected DER.
- `RANDOMIZE-AKA <out.der | IN-PLACE> [ALGORITHM=..] [INCLUDE-AUTH-COUNTER-MAX]
  [INCLUDE-SQN-INIT]` — development helper that generates Ki / OPc / TOPc
  (and the TUAK-specific `numberOfKeccak`) via `secrets.token_bytes` and
  applies them to the first `akaParameter` PE. `authCounterMax` and `sqnInit`
  are skipped by default so replay-protection envelopes stay predictable.

## Documentation map

- `guides/README.md` - index of authored operator and developer guides
- `guides/CAPABILITIES.md` - suite-level capability reference grouped by subsystem and workflow
- `guides/ARCHITECTURE.md` - system structure, interdependency matrix, state model, and flow charts
- `guides/CLI_AND_PIPING_GUIDE.md` - shared non-interactive command and piping conventions
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` - ready-to-run lifecycle, polling, and logging command recipes
- `guides/BUILD_AND_PACKAGING.md` - Docker, PyInstaller, `.deb`, and packaging notes
- `guides/INSTALL_CLEAN.md` - clean-flavor executable install (Win / macOS / Linux / Pi)
- `guides/INSTALL_FULL.md` - HIL-capable full executable install (Linux)
- `guides/INSTALL_FROM_SOURCE.md` - editable source install with extras matrix
- `guides/INSTALL_RASPBERRYPI.md` - Raspberry Pi specific install notes
- `guides/SIMTRACE2_CARDEM_GUIDE.md` - flashing / updating SIMtrace2 and the remsim toolchain
- `guides/HIL_BRIDGE_GUIDE.md` - physical-card HIL bridge setup, supervision, and Wireshark usage
- `guides/systemd/yggdrasim-hil-supervisor.service.example` - example `systemd --user` unit for the HIL supervisor
- `docs/` - gitignored local developer workspace for non-shippable vendor PDFs and extracted standards text. The only schema the tool actually needs at runtime (`RSPRO.asn`) is redistributed inside `Tools/HilBridge/RSPRO.asn` as package data, so a fresh `pip install yggdrasim` works without a `docs/` tree. Operators doing offline reference reading can populate `docs/` themselves; nothing in the wheel or the clean bundle requires it.
- `NOTICE` - standards and third-party notice
- `AUTHORS` - project attribution
- `SCP11/README.md` - eSIM module selection and guide map
- `SCP11/live/README.md` - live relay operator guide
- `SCP11/test/README.md` - test relay operator guide
- `SCP11/local_access/README.md` - local SCP11 shell guide
- `SCP11/eim_local/README.md` - eIM module overview
- `SCP11/eim_local/GUIDE.md` - detailed eIM operational guide
- `SCP11/relay/README.md` - relay compatibility namespace note
- `SCP11/shared/README.md` - shared SCP11 helper layer
- `plugins/README.md` - runtime plugin contract and publication-ignore model

## Repository layout

- `main/` - top-level launcher
- `yggdrasim_common/registry.py` - discoverable map of subsystems, entry points, and stable symbols
- `SCP03/` - admin shell, transport, controllers, decoders, reports
- `SCP80/` - OTA CLI, builder, transport, decode helpers
- `SCP11/` - relay, local, shared, and eIM-related flows
- `Tools/ProfilePackage/` - SAIP shell, linter, transcode UI
- `Tools/SuciTool/` - SUCI helper shell
- `tests/` - first-party test suite
- `state/` - shared SQLite inventory and crypto bootstrap config
- `pysim/` - **optional** developer checkout of upstream pySim (gitignored). The released SAIP surface installs via the `[saip]` extra (`pip install 'yggdrasim[saip]'`); this tree is only needed when you want to pin against an unreleased upstream branch.

## Acknowledgements

A big-hearted thank you to the Osmocom community, the `pySim` maintainers and
contributors, and Martin Paljak for `GlobalPlatformPro`. Their published
tooling, interoperability references, and operator-focused ergonomics have
materially improved the card, relay, and profile-package workflows that
YggdraSIM builds on.

## Scope notes

- `SCP03` is not a generic SCP11 provisioning shell. It is the admin / filesystem / retrieval environment.
- `SCP11/live` and `SCP11/test` are the primary relay-facing shells.
- historical `SCP11/experimental` references are obsolete; relay work is now
  split between `SCP11/live`, `SCP11/test`, and the compatibility namespace
  `SCP11/relay`.
- `SCP11/local_access` is the direct local SCP11 path against `ISD-R`.
- `SCP11/eim_local` is the dedicated eIM-local package, polling, and handover shell.
- Compatibility helpers remain where card policy, certificate trust, or transport behavior can differ across eUICCs.

## License and notice

- License: [GNU GPL v3.0](LICENSE)
- Notice: [NOTICE](NOTICE)