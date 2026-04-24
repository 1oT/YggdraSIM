---
title: CLI Matrix
tags:
  - reference
  - cli
---

# CLI Matrix

Every operator surface, every launch form, and every piping pattern the
repository ships. Details live on each subsystem page; this table is the
lookup.

## Installed commands versus module forms

| Installed command | Module form | Subsystem |
| --- | --- | --- |
| `yggdrasim-scp03` | `python -m SCP03` | [SCP03 Admin Shell](../subsystems/scp03.md) |
| `yggdrasim-scp80` | `python -m SCP80` | [SCP80 OTA Shell](../subsystems/scp80.md) |
| `yggdrasim-scp11` | `python -m SCP11` | [SCP11 Family](../concepts/rsp-architecture.md) |
| `yggdrasim-scp11-live` | `python -m SCP11.live` | [SCP11 Live Relay](../subsystems/scp11-live.md) |
| `yggdrasim-scp11-test` | `python -m SCP11.test` | [SCP11 Test Relay](../subsystems/scp11-test.md) |
| `yggdrasim-scp11-relay` | `python -m SCP11.relay` | compatibility namespace |
| `yggdrasim-scp11-local-access` | `python -m SCP11.local_access` | [SCP11 Local Access](../subsystems/scp11-local-access.md) |
| `yggdrasim-scp11-eim-local` | `python -m SCP11.eim_local` | [SCP11 eIM Local](../subsystems/scp11-eim-local.md) |
| `yggdrasim-hil-bridge` | `python -m Tools.HilBridge.main` | [HIL Bridge](../subsystems/hil-bridge.md) |
| `yggdrasim-hil-supervisor` | `python -m Tools.HilBridge.supervisor` | [HIL Bridge](../subsystems/hil-bridge.md) |
| `yggdrasim-profile-package` | `python -m Tools.ProfilePackage` | [Profile Package](../subsystems/profile-package.md) |
| `yggdrasim-suci-tool` | `python -m Tools.SuciTool` | [SUCI Tool](../subsystems/suci-tool.md) |

## Non-interactive patterns

Most shells expose one or more of these forms. Check the subsystem page for
specifics.

| Pattern | Effect |
| --- | --- |
| `--cmd "A; B; EXIT"` | semicolon-separated one-shot run |
| `--stdin` with here-doc | multi-line script run |
| `script <path>` inside shell | execute a saved script file |
| report / export mode | emits YAML or filesystem dump |

## Main launcher flags

| Flag | Meaning |
| --- | --- |
| `--debug` | elevate module log levels to debug globally |
| `--verbose` | alias for `--debug` in most contexts |
| `--card-backend sim` | route card work to the simulator backend |
| `--sim-eim-identity <path>` | pin the simulated card's BF55 eIM identity |
| `--open-pcap <path>` | open a saved `.pcap` / `.pcapng` in the HIL decoded-APDU TUI (offline review; no bridge, no supervisor, no FIFO) |
| `--keybag <path>` | optional keybag JSON paired with `--open-pcap`; unwraps SCP03 / SCP11c secure-messaging APDUs inline |

## HIL pcap replay + keybag export quick reference

| Tool | Command |
| --- | --- |
| Offline replay (TUI) | `python main/main.py --open-pcap capture.pcapng [--keybag capture.keys.json]` |
| Offline replay (menu) | `python main/main.py` → `[B]` → `[3] Open saved .pcap` |
| SCP03 keybag export | SCP03 shell, after `AUTH-SD`: `EXPORT-KEYBAG [path.keys.json] [label]` |
| SCP11 Local Access keybag export (shell) | `EXPORT-KEYBAG [path.keys.json] [label]` after any BSP-building verb |
| SCP11 Local Access keybag export (CLI) | `python -m SCP11.local_access --dump-keybag path.keys.json` |
| SCP11 Live keybag export | `python -m SCP11.live --dump-keybag …` is a **no-op stub** — live-mode BSP keys never reach the host |

## One-shot examples

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
LOAD-PROFILE
EXIT
EOF
python -m SCP80 --cmd "iccid 8946...; show; exit"
python -m Tools.ProfilePackage --cmd "USE profile.der; LINT --strict; EXIT"
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `YGGDRASIM_RUNTIME_ROOT` | force a specific runtime root directory |
| `GNUPGHOME` | pick the gpg home directory when inventory crypto is enabled |

## Related pages

- [Operator Surfaces](../operator-surfaces.md)
- [Getting Started](../getting-started.md)
- [HIL Bridge — offline pcap replay](../subsystems/hil-bridge.md#offline-pcap-replay)
- [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md)
- `guides/CLI_AND_PIPING_GUIDE.md`

<!-- cli-matrix:start -->

| Installed command | Module form | Description |
| --- | --- | --- |
| `yggdrasim-apdu-fuzzer` | _(manual module)_ |  |
| `yggdrasim-eum-diag` | _(manual module)_ |  |
| `yggdrasim-hil-bridge` | `python -m Tools.HilBridge.main` | SIMtrace2-backed HIL bridge (direct). |
| `yggdrasim-hil-supervisor` | `python -m Tools.HilBridge.supervisor` | HIL supervisor that manages the bridge and remsim-client lifecycle. |
| `yggdrasim-profile-autoload` | _(manual module)_ |  |
| `yggdrasim-profile-package` | `python -m Tools.ProfilePackage` | SAIP / UPP shell, saip-tool bridge, lint engine, JSON↔DER transcode. |
| `yggdrasim-scp03` | `python -m SCP03` | GlobalPlatform-style admin shell, card transport, TLV/CAP decoders, SGP.22 helpers. |
| `yggdrasim-scp11` | `python -m SCP11` | Thin facade; live SGP.22 types re-exported from SCP11.live. |
| `yggdrasim-scp11-eim-local` | `python -m SCP11.eim_local` | eIM-local package, polling, handover, and direct-card tooling. |
| `yggdrasim-scp11-live` | `python -m SCP11.live` | Production SGP.22 client: orchestrator, PC/SC or relay APDU, ES9+, STK polling. |
| `yggdrasim-scp11-local-access` | `python -m SCP11.local_access` | Local ISD-R / metadata codec / certificate helpers for on-card flows. |
| `yggdrasim-scp11-relay` | `python -m SCP11.relay` | ES9 relay / remote APDU front-end built on shared SCP11 patterns. |
| `yggdrasim-scp11-test` | `python -m SCP11.test` | Lab/test harness console and orchestrator (mirrors live layout). |
| `yggdrasim-scp80` | `python -m SCP80` | OTA SMS-SC / CAT-TP style scripting and smart decoding. |
| `yggdrasim-suci-tool` | `python -m Tools.SuciTool` | SUCI-related helper shell. |

<!-- cli-matrix:end -->
