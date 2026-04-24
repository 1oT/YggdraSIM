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

## Core Guides

- `ARCHITECTURE.md` - system structure, dependency map, runtime state, and flow charts
- `CAPABILITIES.md` - suite-level capability reference grouped by subsystem
- `CLI_AND_PIPING_GUIDE.md` - non-interactive command, piping, and automation patterns
- `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` - ready-to-run lifecycle, polling, and logging recipes
- `BUILD_AND_PACKAGING.md` - Docker, PyInstaller, `.deb`, and packaging guidance
- `HIL_BRIDGE_GUIDE.md` - SIMtrace2 / PCSC HIL bridge setup and operation
- `DIAGNOSTICS_TOOLBOX.md` - SAIP diff, SIMCARD-to-TUI auto-open, APDU fuzzer, EUM/tshark dissector
- `TEMPLATE_AND_TOKENS.md` - SAIP template authoring, token sidecars, placeholder lifecycle

## Supporting Examples

- `systemd/yggdrasim-hil-supervisor.service.example` - example `systemd --user` unit for the HIL supervisor
