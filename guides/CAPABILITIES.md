# YggdraSIM Capability Reference

This document records the current subsystem-level capabilities of YggdraSIM.
Use it as a suite-wide index when deciding which module to launch, automate, or
extend. For command syntax and operator sequences, use the module guides linked
from each section.

## 1. Capability Scope

YggdraSIM currently provides:

- a unified launcher for the primary operator surfaces
- direct `python -m ...` entry points for each major subsystem
- interactive shells for card administration, OTA work, relay work, local
  SCP11 work, eIM-local work, SAIP package work, and SUCI key work
- non-interactive command, script, and report/export entry points where the
  subsystem already exposes them
- shared mutable state through SQLite, keyed by card identity or eIM identity
- optional encryption for stored runtime payloads
- a writable runtime-tree model for frozen executables
- optional `pysim/` integration for SAIP and SCP11-related flows (clone `https://gitlab.com/osmocom/pysim.git` into the repo root to enable)
- a repository-local registry for stable entry points and symbols
- a first-party pytest suite covering module behavior and regressions

This document is intentionally capability-oriented. It does not list every
command or every internal helper.

## 2. Primary Operator Surfaces

| Surface | Primary role | Representative capabilities | Deep guide |
| --- | --- | --- | --- |
| `main/main.py` | Unified launcher | module dispatch, docs, about, license, automation entry points | `README.md` |
| `SCP03/` | Admin shell | GP auth, ETSI filesystem, eUICC retrieval, report/export, diff/wizards | `README.md` |
| `SCP80/` | OTA shell | OTA wrap/build/send/decode, script execution, ICCID-bound runtime | `README.md` |
| `SCP11/live/` | Live relay shell | LPAd, IPAd, IPAe, relay preflight, ES9+/eIM endpoint control | `SCP11/live/README.md` |
| `SCP11/test/` | Test relay shell | live-shaped relay surface with test-default certs and request shaping | `SCP11/test/README.md` |
| `SCP11/relay/` | Compatibility relay namespace | legacy import/script continuity for relay workflows | `SCP11/relay/README.md` |
| `SCP11/local_access/` | Direct local shell | local SCP11 auth, metadata upload, direct profile load, ES10c state control | `SCP11/local_access/README.md` |
| `SCP11/eim_local/` | eIM-side shell | direct eIM lifecycle commands, localized polling, hotfolders, handover | `SCP11/eim_local/README.md` |
| `SCP11/shared/` | Shared helper layer | crypto, payload, ASN.1, GSMA error, pySim support helpers | `SCP11/shared/README.md` |
| `Tools/ProfilePackage/` | SAIP shell | inspect, lint, transcode, encode, split, extract, DIFF/DIFF-TUI, WATCH-SIMCARD | `README.md` |
| `Tools/ApduFuzz/` | Opt-in APDU mutation fuzzer | deterministic mutators, PC/SC/null transports, safety gate, crash dumps | `Tools/ApduFuzz/` sources |
| `Tools/EumDiag/` | EUM / SM-DP+ diagnostics | session-key injection, BF36 Lua dissector, tshark runner, BPP decode | `Tools/EumDiag/` sources |
| `Tools/SuciTool/` | SUCI shell | key selection, key generation, public-key export | `README.md` |

## 3. Launcher And Entry-Point Capabilities

The top-level launcher in `main/main.py` can:

- launch the `SCP03` admin shell
- launch the `SCP80` OTA shell
- launch the `SCP11/live` relay shell
- launch the `SCP11/test` relay shell
- launch the `SCP11/local_access` local SCP11 shell
- launch the `SCP11/eim_local` eIM-local shell
- launch the `Tools/ProfilePackage` SAIP shell
- launch the `Tools/SuciTool` SUCI shell
- launch SCP03 script execution mode
- launch SCP03 report and `DUMP-FS` mode
- launch SCP80 script execution mode
- open the guide/documentation menu
- show the about surface
- show the project license
- print the suite version via `--version`
- run a preflight environment report via `--doctor`
- open a saved `.pcap` / `.pcapng` directly in the HIL decoded-APDU TUI via
  `--open-pcap <path>` and an optional `--keybag <path>` sidecar
  (offline review, no bridge / supervisor / FIFO)

The repository also supports direct module entry:

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

Automation-oriented entry points currently include:

- `SCP11.relay` command-mode and stdin execution
- `SCP11.live` command-mode and stdin execution
- `SCP11.test` command-mode and stdin execution
- `SCP11.local_access` command-mode and stdin execution
- `SCP11.eim_local` command-mode and stdin execution
- `SCP03` command-mode execution and script-mode execution
- `SCP03` report/export mode
- `SCP80` script execution
- `Tools.ProfilePackage` command-mode entry
- `Tools.SuciTool` command-mode entry

Discovery-oriented developer access is also exposed through `yggdrasim_common/registry.py`,
which provides:

- subsystem descriptions
- direct CLI module inventory
- stable symbol lookup by registry key
- substring search over registered public symbols

## 4. SCP03 Admin-Shell Capabilities

`SCP03` is the card-administration and retrieval environment. Its capability
set includes:

- GlobalPlatform secure-channel authentication and registry access
- application, package, and security-domain enumeration
- TLV, CAP, and content-decoding helpers
- ETSI / 3GPP file selection, transparent EF read, record read, and update
- eUICC retrieval through `ISD-R`, including:
  - `GetProfilesInfo`
  - `GetEuiccConfiguredData`
  - `GetEID`
  - `GetEuiccInfo1`
  - `GetEuiccInfo2`
  - `GetRAT`
  - `RetrieveNotificationsList`
  - `GetEimConfigurationData`
  - `GetCerts`
- profile-state control for enable, disable, and delete paths
- PIN management and unblock/change/verify flows
- GSM, USIM, and ISIM authentication execution
- `GET-DATA`, `PUT-KEY`, and other GP-oriented wizarded operations
- custom bind/macros through `binds.json`
- filesystem export through `DUMP-FS`
- YAML-oriented report/export generation
- combined filesystem plus eUICC reporting
- persisted "gold profile" selection and live-vs-gold diff workflows
- operator guides, shell guides, and interactive wizards for complex flows
- `EXPORT-KEYBAG` to dump the active SCP03 session keys (S-ENC, S-MAC,
  S-RMAC, SSC, chaining value) plus the target AID into a keybag JSON for
  HIL offline pcap decryption

`SCP03` is intentionally not the SCP11 provisioning relay shell. SCP11
provisioning, relay download, and localized eIM orchestration live in the
dedicated `SCP11` modules.

## 5. SCP80 OTA Capabilities

`SCP80` is the OTA construction and send/decode environment. Its capability set
includes:

- OTA payload wrapping from direct hex input
- explicit `ota <hex>` handling
- configured or inline packet build preview
- configured or inline packet send execution
- raw APDU transmission without OTA wrapping
- command script execution from file
- command history and parameter inspection
- ICCID-specific inventory binding and state reuse
- STK reset and session reinitialization
- configurable OTA parameters, including concatenation and TP-UD sizing
- direct shell-to-shell handoff into `SCP03` when needed

The public shell verbs include `show`, `set`, `iccid`, `build`, `send`,
`sendraw`, `script`, `history`, `reset`, and direct OTA-hex submission.

## 6. SCP11 Relay-Family Capabilities

The relay-family modules are the eSIM relay operator surfaces. Across the live,
test, and relay namespaces, the current capability envelope includes:

- local PC/SC APDU transport or HTTP relay APDU transport
- startup preflight for transport, backend mode, endpoint shape, and credential
  availability
- session snapshot rendering at shell startup
- relay-side `LPAd`, `IPAd`, and `IPAe` flows
- ES9+ / SM-DP+ endpoint and TLS control
- notification retrieval and cleanup operations
- eUICC inventory retrieval and certificate readout
- optional plugin-backed relay-side eIM polling and watchdog flows
- optional concise or debug-oriented watchdog reporting
- hidden expert commands for lower-level inspection and compatibility probes

### `SCP11/live`

`SCP11/live` is the production-like relay shell. Its current capabilities
include:

- live-default certificate and endpoint assumptions
- `DOWNLOAD-PROFILE` for activation-code-driven relay download
- `DISCOVER` and `DOWNLOAD` for `IPAd`
- optional plugin-backed `POLL [attempts] [timer-window] [-t 20s] [-s 5] [--debug]` for `IPAe`,
  with `EIM-POLL` retained as an alias
- `ENABLE-PROFILE`, `DISABLE-PROFILE`, and `DELETE-PROFILE`
- `SET-SMDP`, `SET-ES9`, `SET-ES9-TLS`, and `SET-ES9-CA`
- `ES9-CERT-INFO`
- `FLOW` and `EIM-AUTHENTICATE` compatibility probes
- automatic notification synchronization around transactional flows

### `SCP11/test`

`SCP11/test` is the lab-oriented relay shell. Its current capabilities include:

- the same primary relay command shape as `SCP11/live`
- the same optional plugin-backed `POLL [attempts] [timer-window] [-t 20s] [-s 5] [--debug]`
  surface as `SCP11/live`, with `EIM-POLL` retained as an alias
- test-default certificate and endpoint assumptions
- additional request-shaping and result-shaping controls in `config.py`
- relay/eIM compatibility knobs such as:
  - request variant selection
  - no-package clear-ack behavior
  - synthetic error/result shaping
  - REST-path overrides for test environments

The intended difference between `live` and `test` is certificate/trust and
lab-only shaping behavior, not operator model drift.

### `SCP11/relay`

`SCP11/relay` remains the compatibility namespace. Current capabilities include:

- preserving older import and script contracts
- exposing a relay-oriented shell/orchestrator surface under the legacy module
  name

### `SCP11/shared`

`SCP11/shared` is the cross-flavour helper layer. Current capabilities include:

- shared crypto-engine helpers
- shared payload-builder helpers
- shared transport helper surfaces
- ASN.1 registry access
- GSMA error/result mapping tables
- shared pySim-support helpers used by relay and local SCP11 flows

### Optional plugin runtime

The current optional plugin capability model supports:

- launch-time capability discovery through `yggdrasim_common/plugin_runtime.py`
- source-tree plugin loading from `plugins/`
- writable-runtime plugin loading for frozen builds
- capability-scoped extension of `SCP11/live`, `SCP11/test`, and `SCP11/eim_local`
- the reserved `polling` capability used for relay `POLL` and localized `IPAE-*`
  surfaces

## 7. SCP11 Local-Card Capabilities

`SCP11/local_access` is the direct local `ISD-R` shell. Its current capability
set includes:

- one-shot local SCP11 session handling per command
- direct local `AuthenticateServer`
- direct local `PrepareDownload`
- direct profile/BPP load to card
- metadata JSON linting, encoding, store, and update flows
- custom metadata-tag send operations
- discovery and compact card snapshot generation
- local certificate inventory scanning and card-aware certificate selection
- local SM-DP+ certificate readout
- direct profile-state control through enable, disable, and delete
- per-`EID` persistence of profile, metadata, and certificate selections

Supported discovery/read surfaces include:

- `DISCOVER`
- `INFO`
- `STATUS`
- `CERTS`
- `SMDP-CERTS`

Supported provisioning and metadata surfaces include:

- `LOAD-PROFILE`
- `PROFILE`
- `METADATA`
- `METADATA-LINT`
- `STORE-METADATA`
- `STORE-METADATA-CUSTOM`
- `STORE-METADATA-CUSTOM-ALL`
- `UPDATE-METADATA`

Supported profile-state control includes:

- `ENABLE-PROFILE`
- `DISABLE-PROFILE`
- `DELETE-PROFILE`

Supported diagnostics surfaces include:

- `EXPORT-KEYBAG` to dump the last-built pySim BSP snapshot
  (S-ENC, S-MAC, MAC chain, block number, AID; protocol `SCP11c`) into
  a keybag JSON for HIL offline pcap decryption
- `--dump-keybag <path>` launcher flag for the same export run
  non-interactively at the tail of `--cmd` / `--stdin` (or
  standalone if no batch is supplied)

`SCP11/live` does not expose a functional keybag export: live-mode BSP
keys are derived inside the eUICC during BPP processing and never
reach the host. The Live CLI carries a `--dump-keybag` flag that acts
as an informational stub pointing at `SCP11.local_access` or SCP03.

## 8. SCP11 EIM-Local Capabilities

`SCP11/eim_local` extends the local SCP11 stack with eIM-side logic. Its
current capability set includes:

- direct eIM lifecycle command generation and send paths
- Local eIM identity defaults and identity-file management through
  `Workspace/LocalEIM/eim_identity.json`
- eIM package authoring from JSON templates
- canonical fake-eIM peer-provisioning artifacts for `AddEim`
- eIM package linting and issue workflows
- localized `IPAd` execution through live/test relay orchestrators
- adapter-first standalone `IPAd` runner export through `ipad_standalone.py`
- simulator-side default BF55 eIM identity override through
  `Workspace/SIMCARD/eim_identity.json`, with full card-side layouts still
  overridable through `Workspace/SIMCARD/isdr_config.json` and `eim_entries`
- optional plugin-backed localized `IPAe` watchdog execution through live/test relay orchestrators
- built-in localized handover-state management and linked download helpers
- hotfolder queue polling and fetch flows
- response logging and filtering
- counter inspection and override by `eim_id`
- error-code inspection and override
- poll audit export and aggregate reporting
- direct-to-`ISD-R` package validation without relay polling

Current execution-path families are:

- Direct Auth
- Localized `IPAd`
- Localized `IPAe`

Current lifecycle and direct-card operations include:

- `ADD-INITIAL-EIM`
- `ADD-EIM`
- `GET-EIM-CONFIG`
- `DELETE-EIM`
- `EUICC-MEMORY-RESET`
- `ISDR-ADD-INITIAL-EIM`
- `ISDR-ADD-EIM`
- `ISDR-GET-EIM-CONFIG`
- `ISDR-DELETE-EIM`
- `LOAD-EIM-PACKAGE`

Current localized polling and handover operations include:

- `IPAD-DISCOVER`
- `IPAD-LIVE`
- `IPAD-TEST`
- `IPAE-AUTHENTICATE`
- `IPAE-DOWNLOAD`
- `IPAE-LIVE` (optional plugin-backed)
- `IPAE-TEST` (optional plugin-backed)

Current queue-campaign operations include:

- `POLL-CAMPAIGN`
- `POLL-EXPORT`
- `POLL-AGGREGATE`
- `HOTFOLDER`
- `HOTFOLDER-LIST`
- `HOTFOLDER-POLL`
- `HOTFOLDER-FETCH`
- `EIM-ACKNOWLEDGE`

Current diagnostics and runtime-control operations include:

- `PATHS`
- `STATUS`
- `COUNTERS`
- `COUNTER`
- `RESP-LOG`
- `RESP-LOG-FILTER`
- `RESP-LOG-CLEAR`
- `ERROR-CODES`
- `ERROR-CODE-SET`
- `NOTIF-HYGIENE`

Current seeded fake-eIM peer artifacts include:

- `Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json`
- `Workspace/LocalEIM/eim_packages/fake_eim_peer_addition_info.json`

## 9. SAIP And SUCI Tooling Capabilities

### `Tools/ProfilePackage`

The SAIP/profile-package tool currently supports:

- selection of a source UPP/DER profile input
- automatic handling of `.txt` and `.hex` hex-encoded DER inputs
- status and workspace-path inspection
- default profile-directory management
- default transcode-directory management
- override of the external `saip-tool` command path
- `info`, `tree`, and `check` execution through the shell
- comprehensive profile linting with:
  - strict mode
  - metadata attachment
  - preset gate profiles
  - explicit rule gates
  - JSON or YAML output redirection
- structured dump/export in decoded or raw-oriented forms
- split-pane `TUI` with live JSON editing, live decode, and live lint
- persistent pane-layout selection for the transcode UI
- OS clipboard copy/paste integration inside the transcode UI
- transcode sidecar persistence as `*.transcode.json`, `*.transcode.der`, and
  `*.transcode.txt`
- uncapped inspector/decode retention for the current transcode UI report panes
- tagged SAIP JSON to DER rebuild through `ENCODE-JSON`
- package splitting
- app extraction in `CAP` or `IJC` form
- NAA removal for `USIM`, `ISIM`, or `CSIM`
- raw pass-through subcommands to the external backend tool
- tag-granular `akaParameter` provisioning wizard
- read-only `akaParameter` inventory summary
- non-interactive `akaParameter` overrides and in-place updates
- deterministic development-key randomisation for `akaParameter`

Representative shell verbs include:

- `USE`
- `STATUS`
- `PROFILE-DIR`
- `TRANSCODE-DIR`
- `TOOL`
- `INFO`
- `TREE`
- `CHECK`
- `LINT`
- `DUMP`
- `TUI`
- `ENCODE-JSON`
- `SPLIT`
- `EXTRACT-APPS`
- `REMOVE-NAA`
- `RAW`
- `PWD`
- `LIST-AKA`
- `PROVISION-AKA`
- `RANDOMIZE-AKA`

### `Tools/SuciTool`

The SUCI tool currently supports:

- selection of the active SUCI key file
- status and workspace-path inspection
- override of the external `suci-keytool` command path
- key generation for `SECP256R1`
- key generation for `CURVE25519`
- uncompressed public-key export
- compressed public-key export

Representative shell verbs include:

- `USE`
- `STATUS`
- `TOOL`
- `GENERATE`
- `DUMP`
- `PWD`

## 10. Shared Runtime, Security, And Persistence Capabilities

Cross-cutting runtime capabilities currently include:

- shared SQLite persistence in `state/device_inventory.sqlite3`
- optional encrypted storage envelopes controlled by
  `state/inventory_crypto.json`, with a configurable
  `gpg.timeout_seconds` bound (default 120 s) on every backing
  `gpg` invocation so a stuck `gpg-agent` or `pinentry` surfaces a
  clean error instead of wedging the shell
- per-`ICCID` inventory binding where the subsystem is profile/SIM oriented
- per-`EID` inventory binding where the subsystem is eUICC oriented
- per-`eim_id` counter/runtime persistence for eIM-local work
- seeded writable runtime directories for frozen executables
- drop-in certificate, key, package-template, profile, hotfolder, and cache
  directories under the writable runtime root
- optional plugin loading through `yggdrasim_common/plugin_runtime.py` from the active
  runtime-root `plugins/` directory
- runtime-root override through `YGGDRASIM_RUNTIME_ROOT`
- user-supplied drop-in certificate material for local SCP11 and eIM-local
  flows

Certificate and trust-management capabilities currently include:

- card-aware certificate matching using allowed `CI PKID` values where the
  module supports it
- drop-in override support for local SCP11 certificate material
- test-default and live-default trust separation in the relay shells
- eIM-local identity and certificate-path defaults through
  `Workspace/LocalEIM/eim_identity.json`
- simulator card-side default BF55 identity through
  `Workspace/SIMCARD/eim_identity.json`
- full simulator card-side eIM row override through
  `Workspace/SIMCARD/isdr_config.json` with `eim_entries`

## 11. Diagnostics, Reporting, And Validation Capabilities

The repository currently includes:

- module-specific help and guide surfaces
- SCP03 YAML and filesystem export/report generation
- eIM-local poll audit export and aggregate views
- response-log capture and filtering for eIM-local flows
- live and concise watchdog reporting for relay polling
- a root architecture document with flowcharts
- a registry for stable symbol discovery
- a pytest suite for targeted regression validation
- HIL decoded-APDU TUI with live capture and offline pcap review
  (`main/main.py --open-pcap <path> [--keybag <path>]` or `[B]` sub-menu
  option `[3]`), driven by `tshark -i` / `tshark -r` depending on mode
- SCP03 / SCP11c session-key keybag export (`EXPORT-KEYBAG` in the
  SCP03 shell and in `SCP11.local_access`; `--dump-keybag <path>`
  launcher flag for `SCP11.local_access`) paired with the HIL offline
  replay engine (`Tools.HilBridge.scp_replay.ScpReplayEngine`) for
  plaintext overlay of secure-messaging APDUs

## 12. Distribution And Packaging Capabilities

The suite is published in two executable flavors and a source option:

| Flavor | Platforms | HIL bridge | Entry point label |
| --- | --- | --- | --- |
| `clean` | Windows x86_64 / macOS x86_64 + arm64 / Linux x86_64 / Raspberry Pi arm64 | not bundled | `yggdrasim-clean[.exe]` |
| `full`  | Linux x86_64 only | bundled (requires SIMtrace2 + `osmo-remsim-client-st2` at runtime) | `yggdrasim-full` |
| source  | any supported Python host | optional via `pip install -e '.[hil]'` | `yggdrasim` from `main/main.py` |

Launcher features that are flavor-aware:

- `main/main.py --version` reports the build flavor alongside the suite
  version
- `main/main.py --doctor` reports the active flavor and probes HIL
  prerequisites (`pyudev`, `osmo-remsim-client-st2`, `dfu-util`,
  `lsusb`) where relevant
- the main menu hides or visibly disables the `[B] HIL Bridge Session`
  entry on clean builds and on non-Linux hosts, with a pointer to the
  right install guide
- console-script entry points `yggdrasim-hil-bridge` and
  `yggdrasim-hil-supervisor` refuse to start on clean or non-Linux
  hosts with a friendly message

Install-path documentation:

- `INSTALL_CLEAN.md` - clean executable, all target OSes
- `INSTALL_FULL.md` - full executable, Linux
- `INSTALL_FROM_SOURCE.md` - source install matrix
- `INSTALL_RASPBERRYPI.md` - Raspberry Pi specifics
- `SIMTRACE2_CARDEM_GUIDE.md` - SIMtrace2 firmware and toolchain

Build tooling:

- `yggdrasim_main.spec` reads `YGGDRASIM_FLAVOR` and emits a flavor-named
  executable in `dist/`
- `Dockerfile` accepts `--build-arg YGGDRASIM_FLAVOR={clean,full}`
- `.github/workflows/build.yml` produces clean artifacts for all
  supported OSes, a full Linux artifact, and an arm64 clean Debian
  artifact through QEMU/Buildx

## 13. Related Documents

Use the following documents together with this capability reference:

- `README.md` for launch paths, runtime model, and repository map
- `CLI_AND_PIPING_GUIDE.md` for shared `--cmd` / `--stdin` automation rules
- `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-run lifecycle and polling examples
- `ARCHITECTURE.md` for dependency and state-flow structure
- `BUILD_AND_PACKAGING.md` for flavor-aware build, Docker, and `.deb` details
- `INSTALL_CLEAN.md`, `INSTALL_FULL.md`, `INSTALL_FROM_SOURCE.md`, `INSTALL_RASPBERRYPI.md`, `SIMTRACE2_CARDEM_GUIDE.md` for install paths
- `HIL_BRIDGE_GUIDE.md` for the hardware-in-the-loop bridge (full flavor only)
- `SCP11/README.md` for eSIM module selection
- `SCP11/live/README.md` for live relay operation
- `SCP11/test/README.md` for test relay operation
- `SCP11/local_access/README.md` for direct local SCP11 work
- `SCP11/eim_local/README.md` for eIM-local overview
- `SCP11/eim_local/GUIDE.md` for detailed eIM-local workflows
- `plugins/README.md` for optional capability and plugin contract details
