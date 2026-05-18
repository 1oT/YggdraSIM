# Guide Index

This directory holds authored operator and developer documentation for
YggdraSIM. The repository root keeps project-level entry files such as
`README.md`, `LICENSE`, `NOTICE`, and `AUTHORS`.

`docs/` is an **optional** local developer workspace (gitignored) for
vendor PDFs and extracted standards text. It is not redistributed in
the wheel or the clean bundle. The one schema the toolkit actually
needs at runtime (`RSPRO.asn`) is shipped as package data under
`Tools/HilBridge/RSPRO.asn`. Operators who want offline reference
reading can populate `docs/` themselves from the issuing body.

## Install Guides

- `INSTALL_CLEAN.md` - clean-flavor executable install (Win / macOS / Linux / Pi)
- `INSTALL_FULL.md` - HIL-capable executable install (Linux only)
- `INSTALL_FROM_SOURCE.md` - editable source install with the extras matrix
- `INSTALL_RASPBERRYPI.md` - Raspberry Pi specific install notes
- `SIMTRACE2_CARDEM_GUIDE.md` - flashing / updating SIMtrace2 and `osmo-remsim-client-st2`

## Core Guides

- `ARCHITECTURE.md` - system structure, dependency map, runtime state, and flow charts
- `CAPABILITIES.md` - suite-level capability reference grouped by subsystem
- `CLI_AND_PIPING_GUIDE.md` - non-interactive command, piping, and automation patterns
- `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` - ready-to-run lifecycle, polling, and logging recipes
- `BUILD_AND_PACKAGING.md` - Docker, PyInstaller, `.deb`, and packaging guidance
- `HIL_BRIDGE_GUIDE.md` - SIMtrace2 / PCSC HIL bridge setup and operation
- `DIAGNOSTICS_TOOLBOX.md` - SAIP diff, SIMCARD-to-TUI auto-open, APDU fuzzer, EUM/tshark dissector
- `TEMPLATE_AND_TOKENS.md` - SAIP template authoring, token sidecars, placeholder lifecycle
- `GUI_HOST_SHELL_GUIDE.md` - GUI `Advanced > Host shell` opt-in PTY surface, AT-decode overlay, threat model
- `CONFIGURATION_AND_CERTIFICATES.md` - canonical operator guide for every certificate, keyset, identity, and configuration drop-in surface
- `NAMING_CONVENTIONS.md` - source of truth for every operator-visible label, with the spec citation or YggdraSIM-coined provenance for each

## Supporting Examples

- `systemd/yggdrasim-hil-supervisor.service.example` - example `systemd --user` unit for the HIL supervisor
