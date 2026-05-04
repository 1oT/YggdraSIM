# Documentation Map

This MkDocs site is a curated entry point for the repository. The original
Markdown guides in the source tree remain the deeper operator reference for many
subsystems.

## Site pages to source material

| Site page | Main source material |
| --- | --- |
| `index.md` | `README.md`, `guides/README.md` |
| `getting-started.md` | `README.md`, `guides/INSTALL_*.md` |
| `architecture.md` | `guides/ARCHITECTURE.md` |
| `operator-surfaces.md` | `guides/CAPABILITIES.md`, `guides/CLI_AND_PIPING_GUIDE.md` |
| `subsystems/scp03.md` | `SCP03/README.md` |
| `subsystems/scp80.md` | `SCP80/README.md` |
| `subsystems/scp11-live.md` | `SCP11/README.md`, `SCP11/live/README.md` |
| `subsystems/scp11-test.md` | `SCP11/README.md`, `SCP11/test/README.md` |
| `subsystems/scp11-local-access.md` | `SCP11/local_access/README.md` |
| `subsystems/scp11-eim-local.md` | `SCP11/eim_local/README.md`, `SCP11/eim_local/GUIDE.md` |
| `subsystems/profile-package.md` | `Tools/ProfilePackage/` sources |
| `subsystems/hil-bridge.md` | `guides/HIL_BRIDGE_GUIDE.md`, `guides/SIMTRACE2_CARDEM_GUIDE.md` |
| `subsystems/apdu-fuzzer.md` | `Tools/ApduFuzz/` sources |
| `subsystems/eum-diagnostics.md` | `Tools/EumDiag/` sources |
| `subsystems/simcard-simulator.md` | `SIMCARD/` sources, `guides/CAPABILITIES.md` |
| `subsystems/suci-tool.md` | `Tools/SuciTool/` sources |
| `how-to/diagnostics-toolbox.md` | `guides/DIAGNOSTICS_TOOLBOX.md` |
| `reference/state-schema.md` | `plugins/README.md`, `guides/ARCHITECTURE.md` |
| `build-and-packaging.md` | `guides/BUILD_AND_PACKAGING.md` |

## Authored guide inventory

| Path | Purpose |
| --- | --- |
| `README.md` | top-level overview, install, launch, state model, and documentation map |
| `guides/README.md` | index of authored operator and developer guides |
| `guides/CAPABILITIES.md` | suite-level capability reference grouped by subsystem |
| `guides/ARCHITECTURE.md` | system structure, dependency map, runtime state, and flow charts |
| `guides/CLI_AND_PIPING_GUIDE.md` | non-interactive command, piping, and automation patterns |
| `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` | ready-to-run lifecycle, polling, and logging recipes |
| `guides/BUILD_AND_PACKAGING.md` | Docker, PyInstaller, `.deb`, and packaging guidance |
| `guides/HIL_BRIDGE_GUIDE.md` | SIMtrace2 and PCSC HIL bridge setup and operation |
| `guides/SIMTRACE2_CARDEM_GUIDE.md` | SIMtrace2 cardem hardware bring-up notes |
| `guides/DIAGNOSTICS_TOOLBOX.md` | SAIP diff, simulator-to-TUI, fuzzer, and EUM diag |
| `guides/INSTALL_CLEAN.md` | clean (no-HIL) install path |
| `guides/INSTALL_FULL.md` | full HIL-capable install path |
| `guides/INSTALL_FROM_SOURCE.md` | source-checkout install with optional extras |
| `guides/INSTALL_RASPBERRYPI.md` | Raspberry Pi install notes |
| `guides/TEMPLATE_AND_TOKENS.md` | template and token contract used by the launcher and shells |
| `SCP11/README.md` | SCP11 family selection guide |
| `SCP11/live/README.md` | live relay operator guide |
| `SCP11/test/README.md` | test relay operator guide |
| `SCP11/local_access/README.md` | local SCP11 shell guide |
| `SCP11/eim_local/README.md` | eIM-local shell overview |
| `SCP11/eim_local/GUIDE.md` | deep eIM-local operational guide |
| `SCP11/relay/README.md` | relay compatibility namespace note |
| `SCP11/shared/README.md` | shared SCP11 helper layer |
| `plugins/README.md` | runtime plugin contract and publication model |

## Working model

- Keep `site-docs/` focused on curated navigation and onboarding.
- Keep deep operator procedures in the authored source guides until they are intentionally ported.
- Treat `docs/` as an **optional** local developer tree for standards PDFs and extracted reference text; it is gitignored and not shipped. The only machine-read schema the runtime needs (`RSPRO.asn`) is redistributed as package data under `Tools/HilBridge/RSPRO.asn`.
