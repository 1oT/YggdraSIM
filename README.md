# YggdraSIM

YggdraSIM is a Python toolkit for secure-element research, eUICC analysis, SIM/eSIM management, OTA payload work, SCP11 relay/local flows, and SAIP profile-package tooling. The repository keeps the operator surfaces, protocol helpers, vendored `pysim/` tree, and test suite in one workspace so card work, relay work, and package work can be exercised without switching projects.

## Authors

- Hampus Hellsberg - Creator, Lead Architect, Lead Maintainer

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
| `pysim/` | Vendored upstream runtime dependency used by SAIP and SCP11 flows | library / vendored source |

## Core capabilities

- PC/SC-based GlobalPlatform and UICC/eUICC administration through `SCP03`.
- OTA packet generation, wrapping, transport, and decode through `SCP80`.
- Split SCP11 relay environments for live and test work, with `SCP11/relay`
  retained as the compatibility namespace.
- Direct local SCP11 provisioning and metadata handling through `SCP11/local_access`.
- eIM-centric local package work, localized polling, hotfolder campaigns, and response tracking through `SCP11/eim_local`.
- SAIP / UPP profile inspection, linting, JSON↔DER transcode, and shell automation through `Tools/ProfilePackage`.
- Centralized mutable state in SQLite, with optional `gpg`-based encryption for sensitive payloads.

## Quick start

### Prerequisites

- Python 3.10+
- A PC/SC-compatible smart-card reader for card flows
- Optional: `gpg` when encrypted SQLite inventory payloads are enabled

### Install Python dependencies

```bash
pip install -r requirements.txt
```

### Launch the main menu

```bash
python main/main.py
```

### Direct module entry points

```bash
python -m SCP03
python -m SCP80
python -m SCP11
python -m SCP11.live
python -m SCP11.test
python -m SCP11.relay
python -m SCP11.local_access
python -m SCP11.eim_local
python -m Tools.ProfilePackage
python -m Tools.SuciTool
```

## Persistent state and security model

YggdraSIM now uses `state/device_inventory.sqlite3` as the primary mutable state store for:

- per-card `ICCID` inventory payloads
- per-card `EID` inventory payloads
- per-eIM identity counters and runtime markers
- module-level mutable settings such as the migrated `SCP03` and `SCP80` runtime state

Current migration model:

- `SCP03/keys.ini` is a legacy import source. Live SCP03 state is now SQLite-primary.
- `SCP80/ota_config.ini` is a legacy import source. Live SCP80 state is now SQLite-primary.
- `SCP11/eim_local/eim_runtime_state.json` is a legacy import source. Live runtime state is now SQLite-primary.
- `SCP03/aid.txt`, `SCP03/fids.txt`, and `SCP03/binds.json` remain plain files because they are still better suited to manual editing and diff review.

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

Example:

```text
[APDU] > AUTH-SD
[A0...00] > APPS
[A0...00] > LIST
[A0...00] > SELECT USIM/IMSI
[A0...00] > READ
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

### Local SMDPP

Use `SCP11/local_access` for direct on-card local provisioning without the relay shells:

```text
[Local SMDPP] > STATUS
[Local SMDPP] > PROFILE /path/to/profile.der
[Local SMDPP] > METADATA /path/to/metadata.json
[Local SMDPP] > LOAD-PROFILE
```

This path now restores per-card local choices by `EID` from the shared SQLite inventory.

### Local eIM

Use `SCP11/eim_local` when you need:

- eIM identity and package fixtures
- local handover simulation
- hotfolder and poll campaign exercises
- AddInitialEim / AddEim command generation
- eIM response logs and counter control

See:

- `SCP11/eim_local/README.md`
- `SCP11/eim_local/GUIDE.md`

### Profile package tooling

Use `Tools/ProfilePackage` for:

- SAIP shell operations
- JSON↔DER transcode
- linting and package inspection
- `saip-tool` bridge work

The transcode UI now uses a configurable transcode output directory and stores the setting in the workspace.

## Documentation map

- `CAPABILITIES.md` - suite-level capability reference grouped by subsystem and workflow
- `ARCHITECTURE.md` - system structure, interdependency matrix, state model, and flow charts
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
- `pysim/` - vendored upstream pySim source used by several subsystems

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