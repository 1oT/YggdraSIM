---
title: Environment Flags
tags:
  - reference
  - configuration
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Environment Flags

`yggdrasim_common/env_flags.py` is the single source of truth for the
`YGGDRASIM_*` runtime flags: each one declares its name, category, summary,
accepted values, default, when a change takes effect, and where an override
is stored. Three surfaces read that one registry, and so does the table at
the bottom of this page:

- the launcher menu, `[E] Environment Flags (YGGDRASIM_*)`
- the Universal GUI, **Environment -> Configuration** (`/api/env_flags/list`,
  `/api/env_flags/{name}/set`, `/{name}/clear`, `/reset`)
- `yggdrasim_common.env_flags` itself, for anything that needs the contract
  in code

## Which value wins

1. The process environment. `VAR=... yggdrasim ...`, a shell `export`, or a
   CLI flag that sets the variable takes priority over everything else.
2. A persisted override, applied at process entry for flags the environment
   leaves unset.
3. The flag's own default, which is what the Default column describes.

`apply_persisted_env_overrides()` never overwrites a variable that is already
set, so a command-line choice is not silently replaced by a stored one.

!!! warning "Persisted overrides do not reach every command"
    Only the launcher (`yggdrasim`, `yggdrasim-gui`, `yggdrasim-desktop`,
    `yggdrasim-web-server`) and the SCP11 live shell call
    `apply_persisted_env_overrides()` at startup. A standalone console script
    such as `yggdrasim-scp03` or `yggdrasim-card-bridge` reads the process
    environment only. Export the variable in the shell -- or start from the
    launcher -- when a stored value has to apply to one of those.

## Where an override is stored

| Persistence | File | Used for |
| --- | --- | --- |
| runtime root | `state/env_overrides.json` under the runtime root | Most flags. |
| home | `~/.yggdrasim/env_overrides.json` | Flags that cannot live inside the runtime root, because selecting the root from inside it would be circular. Currently `YGGDRASIM_RUNTIME_ROOT`. |
| session only | -- | Never written. Export it in a shell profile to pin it across launches. |

A corrupt overrides file is quarantined rather than deleted, and only
registered flag names are read back.

## Reading the table

- **Accepts** -- the exact values the editors write. A toggle writes the on
  value and unsets for off, so a shell comparison against `1` stays valid.
- **Applies** -- *immediately* means the running process picks the change up;
  *next launch* means the value is read once at startup.
- **Persistence** -- the file an override lands in, per the table above.
- **(sensitive)** -- the flag weakens a security posture (insecure TLS, demo
  keys, the quirks gate, disabling plugins), so the editors ask for
  confirmation before writing it.

## The flags

<!-- env-flags:start -->

64 flags in 13 categories, generated from `yggdrasim_common/env_flags.py`.

### Build / runtime

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_FLAVOR` | `clean`, `full`, `source` | auto-detect (frozen build → clean; source checkout → source) | next launch | session only | Force build flavor (clean / full / source) |
| `YGGDRASIM_RUNTIME_ROOT` | path | source checkout: repo root. Frozen build: YggdraSIM-data next to the exe, else ~/YggdraSIM-data. | next launch | home | Force the writable runtime root |

### Card backend

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_CARD_BACKEND` | `reader`, `sim` | reader unless the saved selection picks sim | immediately | runtime root | Force reader vs simulated SIM |
| `YGGDRASIM_CARD_RELAY_URL` | text | unset (no relay) -- local PC/SC or simulator | immediately | runtime root | Remote HIL card-relay URL |
| `YGGDRASIM_SIM_QUIRKS` | path | Workspace/SIMCARD/sim_quirks.py (reseeded from template on first run) | immediately | runtime root | Override the simulated-SIM quirks file |
| `YGGDRASIM_SIM_ISDR_CONFIG` | path | Workspace/SIMCARD/isdr_config.json | immediately | runtime root | Override the simulated-ISD-R personality JSON |
| `YGGDRASIM_SIM_EIM_IDENTITY` | path | Workspace/SIMCARD/eim_identity.json | immediately | runtime root | Override the simulated default BF55 eIM identity |
| `YGGDRASIM_SIM_EUICC_STORE` | path | Workspace/SIMCARD/euicc_store | immediately | runtime root | Override the simulated eUICC store root |
| `YGGDRASIM_SIM_PROFILE_STORE` | path | derived per-EID under the eUICC store root | immediately | runtime root | Override the simulated profile artifact directory |

### Simulator behaviour

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_ALLOW_QUIRKS` | `1` / unset | unset → quirks files are refused | immediately | runtime root | (sensitive) Allow loading Python quirks files |
| `YGGDRASIM_DISABLE_QUIRKS` | `1` / unset | unset → quirks are loaded per YGGDRASIM_ALLOW_QUIRKS | immediately | runtime root | Kill switch for simulator quirks |
| `YGGDRASIM_SIM_DEBUG_FAULTS` | `1` / unset | unset → quiet | immediately | runtime root | Log simulator fault-injection decisions verbosely |
| `YGGDRASIM_ENABLE_TUAK` | `1` / unset | unset → MILENAGE only | immediately | runtime root | Enable TUAK auth algorithm in the simulator |

### Plugins

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_ALLOW_PLUGINS` | `1`, `0` | unset → plugins refused | next launch | runtime root | Opt in to runtime plugin loading |
| `YGGDRASIM_DISALLOW_PLUGINS` | `1` / unset | unset → still requires YGGDRASIM_ALLOW_PLUGINS=1 | next launch | runtime root | (sensitive) Hard-lock: refuse every plugin |

### Demo keys gate

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_ALLOW_DEMO_KEYS` | `1` / unset | unset → banner is printed when demo keys are detected | immediately | runtime root | (sensitive) Silence the SCP03 / SCP80 demo-keys warning |
| `YGGDRASIM_REQUIRE_NON_DEMO_KEYS` | `1` / unset | unset → demo keys only emit a warning | immediately | runtime root | Fail fast when demo keys are loaded |

### SCP11 TLS

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS` | `1` / unset | unset → unpinned request traffic is refused | immediately | runtime root | (sensitive) Allow unpinned SCP11 ES9 request traffic |
| `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS` | `1` / unset | unset → opt-in still possible | immediately | runtime root | Hard-lock: refuse unpinned SCP11 request traffic |
| `YGGDRASIM_SCP11_ALLOW_TLS_INTROSPECTION` | `1` / unset | unset → first-contact chain reads are refused | immediately | runtime root | (sensitive) Allow read-only TOFU chain reads on first contact |
| `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION` | `1` / unset | unset → ALLOW_TLS_INTROSPECTION=1 still required | immediately | runtime root | Hard-lock: refuse TOFU chain reads |

### SCP11 local SAIP decode

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_SCP11_SAIP_DECODE_TIMEOUT_SECONDS` | number | unset → built-in default (see SCP11/local_access/session.py) | immediately | runtime root | Extend the SAIP decode timeout for LocalSMDPP |
| `YGGDRASIM_SCP11_ALLOW_FULL_SAIP_DECODE` | `1` / unset | unset → compact decode only | immediately | runtime root | Allow expensive full SAIP decode on LocalSMDPP profiles |

### Debug

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_GLOBAL_DEBUG` | `1` / unset | unset → per-module debug stays opt-in | immediately | runtime root | Enable verbose debug across modules |

### HIL bridge

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_HIL_CAPTURE_INTERFACE` | text | lo0 on macOS, lo elsewhere | immediately | runtime root | Network interface Wireshark / tshark listen on |
| `YGGDRASIM_HIL_WIRESHARK_BIN` | path | shutil.which('wireshark') | immediately | runtime root | Explicit Wireshark binary path |
| `YGGDRASIM_HIL_TERMSHARK_BIN` | path | shutil.which('termshark') | immediately | runtime root | Explicit termshark binary path |
| `YGGDRASIM_HIL_TERMSHARK_WARMUP_SECONDS` | number | 2.0 | immediately | runtime root | Warm-up delay before starting the bridge after termshark |
| `YGGDRASIM_HIL_TUI_TERM` | text | auto-detect (prefers screen-256color / tmux-256color / xterm-256color) | immediately | runtime root | Override the TERM value used by the HIL live-decode TUI |
| `YGGDRASIM_HIL_RELAY_SESSION_RESET` | `1` / unset | enabled | immediately | runtime root | Power-cycle the card at relay-session boundaries |
| `YGGDRASIM_HIL_SIMTRACE_RESET` | text | usb-reset | immediately | runtime root | How the supervisor clears the SIMtrace2 board before a session |
| `YGGDRASIM_HIL_UHUBCTL_LOCATION` | text | unset (port-power reset disabled) | immediately | runtime root | Hub location for the port-power SIMtrace2 reset |
| `YGGDRASIM_HIL_UHUBCTL_PORT` | text | unset (all ports on the hub) | immediately | runtime root | Hub port for the port-power SIMtrace2 reset |
| `YGGDRASIM_HIL_UHUBCTL_BINARY` | path | uhubctl (resolved from PATH) | immediately | runtime root | Path to the uhubctl binary |
| `YGGDRASIM_RSPRO_ASN` | path | built-in module shipped with Tools/HilBridge | immediately | runtime root | Override the RSPRO ASN.1 module path |

### External tool locators

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_SAIP_TOOL` | text | shutil.which('saip-tool') | immediately | runtime root | Explicit saip-tool binary or command |
| `YGGDRASIM_SAIP_TOOL_TIMEOUT_SECONDS` | number | built-in default (see Tools/ProfilePackage/saip_tool.py) | immediately | runtime root | Default timeout for saip-tool subprocess calls |
| `YGGDRASIM_SAIP_TOOL_CACHE_MAX_BYTES` | integer | built-in default (see Tools/ProfilePackage/saip_tool.py) | immediately | runtime root | Cap for the on-disk SAIP tool decode cache |
| `YGGDRASIM_SAIP_UNIVERSAL_TOKENS` | path | ~/.yggdrasim/saip_universal_tokens.csv | immediately | runtime root | Universal placeholder test-value list for SAIP templates |
| `YGGDRASIM_SAIP_TOKEN_LISTS` | path | ~/.yggdrasim/saip_token_lists/ | immediately | runtime root | Library of profile-specific placeholder test-value lists |
| `YGGDRASIM_SAIP_PE_LIBRARY` | path | ~/.yggdrasim/saip_pe_library/ | immediately | runtime root | Library of saved profile elements for the SAIP workbench |
| `YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS` | `1` / unset | unset → templates are seeded from the list | immediately | runtime root | Seed opened templates from the universal test-value list |
| `YGGDRASIM_SUCI_TOOL` | text | shutil.which('suci-keytool') | immediately | runtime root | Explicit suci-keytool binary or command |
| `YGGDRASIM_SUCI_TIMEOUT` | number | built-in default (see Tools/SuciTool/tool.py) | immediately | runtime root | Default timeout for suci-keytool subprocess calls |
| `YGGDRASIM_EUM_SESSION_KEYS` | path | unset → no session key material available | immediately | runtime root | Path to the EUM session keys JSON repository |

### Session recording

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_SESSION_APDU_TRACE_CAP` | integer | 50000 | immediately | runtime root | Soft cap on APDU events per session recording |

### Appearance

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_CLI_THEME` | `nord`, `catppuccin-frappe`, `catppuccin-latte`, `catppuccin-macchiato`, `catppuccin-mocha`, `dracula`, `github-dark`, `github-light`, `graphite-light`, `gruv-dark`, `ink-light`, `islands-light`, `matrix`, `mono`, `nord-light`, `ocean-dark`, `oneot-dark`, `oneot-light`, `solarized-dark`, `solarized-light`, `tokyo-night` | nord (the canonical YggdraSIM palette) | next launch | runtime root | Terminal colour palette for the CLI and the shells |

### Universal GUI

| Variable | Accepts | Default | Applies | Persistence | Summary |
| --- | --- | --- | --- | --- | --- |
| `YGGDRASIM_GUI_HOST` | text | 127.0.0.1 | next launch | runtime root | Desktop GUI bind host |
| `YGGDRASIM_GUI_PORT` | integer | 27853 | next launch | runtime root | Desktop GUI bind port |
| `YGGDRASIM_GUI_SERVER_HOST` | text | 0.0.0.0 (SSH-tunnel-friendly: prefer 127.0.0.1) | next launch | runtime root | (sensitive) Remote lab GUI bind host |
| `YGGDRASIM_GUI_SERVER_PORT` | integer | 27854 | next launch | runtime root | Remote lab GUI bind port |
| `YGGDRASIM_GUI_TOKEN` | text | unset → auto-generated for --gui, rejected for --web-server | next launch | session only | (sensitive) Bearer token for the GUI API (inline) |
| `YGGDRASIM_GUI_TOKEN_FILE` | path | unset | next launch | runtime root | (sensitive) Path to a bearer-token file for the GUI API |
| `YGGDRASIM_GUI_FS_ROOTS` | path | unset -> whole filesystem for --gui, shortcut roots for --web-server | next launch | runtime root | Directories the in-app file picker may list |
| `YGGDRASIM_GUI_TLS_CERT` | path | unset (plain HTTP unless --tls-self-signed is passed) | next launch | runtime root | TLS certificate path for --web-server |
| `YGGDRASIM_GUI_TLS_KEY` | path | unset | next launch | runtime root | (sensitive) TLS private key path for --web-server |
| `YGGDRASIM_GUI_ALLOW_ORIGIN` | text | unset → deny-all (same-origin SPA only) | next launch | runtime root | Additional CORS origin(s) for --web-server |
| `YGGDRASIM_GUI_IDLE_SECONDS` | integer | 1800 | next launch | runtime root | WebSocket idle cutoff for GUI shell sessions |
| `YGGDRASIM_GUI_PATH_ALLOWLIST` | text | unset → runtime root + eUICC store + CWD | next launch | runtime root | Extra path roots the GUI is permitted to read |
| `YGGDRASIM_GUI_WEBVIEW_DEBUG` | `1` / unset | unset → dev tools closed | next launch | runtime root | Open the pywebview dev tools on --gui launch |
| `YGGDRASIM_GUI_ZOOM` | `auto`, `0.5`, `0.67`, `0.75`, `0.8`, `0.9`, `1`, `1.1`, `1.25`, `1.5`, `1.75`, `2`, `2.5`, `3` | 1 (native size) | immediately | runtime root | Page zoom of the --gui desktop window |
| `YGGDRASIM_GUI_GPU` | `1` / unset | unset → GPU off (software drawing, one raster thread) | next launch | runtime root | Let the --gui desktop window draw with the GPU |
| `YGGDRASIM_GUI_HOST_SHELL` | `1` / unset | unset → Host shell tab is hidden, route refuses connections | next launch | runtime root | (sensitive) Expose the GUI Host-Shell tab (free-form OS shell PTY) |
| `YGGDRASIM_GUI_CARD_SESSION_IDLE_SECONDS` | integer | 900 (15 minutes) | immediately | runtime root | Idle ceiling for a GUI card session holding a reader |

<!-- env-flags:end -->

## Related pages

- [Runtime Root](runtime-root.md) -- what the runtime root holds
- [State Schema](state-schema.md) -- the files under `state/`
- [Troubleshooting](troubleshooting.md)
- [Load Certificates and Configuration](../how-to/load-certificates-and-config.md)
