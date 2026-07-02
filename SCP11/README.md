<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 eSIM Module Guide

`SCP11/` contains the repository's eSIM-facing shells and helper layers. The
family is split by operator model, transport path, and which side of the
workflow needs to be exercised.

Use this file as the entry point for choosing the correct `SCP11` module.

> **Test material notice.** The `*.pem` / `*.der` files at the root of
> `SCP11/` and the entire `SCP11/SGP.26_test_Certs/` subtree are the
> publicly-known GSMA **SGP.26 test certificates and private keys**.
> They are tracked because the SGP.26 conformance flows require them.
> They must not be used against live infrastructure. See
> `SCP11/TEST_MATERIAL_NOTICE.md` for the full breakdown.

## Module map

| Module | Use when | Card transport | Network role | Primary guide |
| --- | --- | --- | --- | --- |
| `SCP11/live` | eSIM management relay work against remote ES9+ / eIM endpoints | `pcsc` | remote ES9+ / eIM | `SCP11/live/README.md` |
| `SCP11/local_access` | direct local `ISD-R` bring-up and on-card profile loading | `pcsc` | no relay dependency | `SCP11/local_access/README.md` |
| `SCP11/eim_local` | eIM-side package authoring, hotfolder queues, response tracking, and handover validation | `pcsc` | local eIM / SM-DP+ bridge | `SCP11/eim_local/README.md` |
| `SCP11/relay` | preserve older relay imports and automation contracts | `pcsc` | compatibility namespace | `SCP11/relay/README.md` |
| `SCP11/shared` | shared helpers only | n/a | n/a | `SCP11/shared/README.md` |
| `SCP11/test` | preserve older import paths only | n/a | compatibility namespace | `SCP11/test/README.md` |

### Relay implementation layout

The relay implementation is exposed through one eSIM management entrypoint:

| Tree | Status | Notes |
| --- | --- | --- |
| `SCP11/orchestrator.py` and `SCP11/console.py` | **canonical** | Spec-correctness work, bug fixes, and API additions land here first. |
| `SCP11/live/orchestrator.py` and `SCP11/live/console.py` | **relay implementation** | Relay-first shell with LPAd / IPAd behavior and physical-card recovery helpers. |
| `SCP11/test/*.py` | **compatibility shims** | Import the live relay implementation for older imports. This namespace is not a separate operator entrypoint. |

Remote relay mode uses platform TLS trust by default. `ES9_CA_BUNDLE_PATH`
is empty unless the operator explicitly pins a CA bundle with `SET-ES9-CA`.
The SGP.26 test CI material remains available for local SGP.26 and fixture
flows, but is not selected implicitly by the eSIM management relay.

## Choose by task

- Use `SCP11/live` for relay-first work against the configured ES9+ / eIM
  endpoints.
- Use `SCP11/local_access` when the task is direct `ISD-R` discovery,
  `PrepareDownload`, metadata upload, or ES10c profile state control.
- Use `SCP11/eim_local` when the task is on the eIM side: `ADD-INITIAL-EIM`,
  `ADD-EIM`, package queues, hotfolders, response logs, or handover
  orchestration.
- Use `SCP11/relay` only when an older import path or script contract depends
  on that namespace.

## Entry points

From the repository root:

```bash
python -m SCP11.live
python -m SCP11.local_access
python -m SCP11.eim_local
python -m SCP11.relay
```

All operator shells in this family also support `--cmd` and `--stdin` batch
execution. For semicolon batches, here-docs, and log-capture patterns, use:

- `../guides/CLI_AND_PIPING_GUIDE.md`
- `../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

The top-level launcher in `main/main.py` exposes the same operator surfaces
through the Guides menu and the main module selector.

## Common runtime assumptions

- card-facing work requires a usable PC/SC reader unless the simulator backend
  is explicitly selected
- relay shells require ES9+ / SM-DP+ settings that are valid for the target
  environment
- direct local flows require usable local SCP11 credential material
- when the shared card backend is set to `sim`, card-facing SCP11 modules use
  the simulator and the card-side default BF55 eIM identity comes from
  `Workspace/SIMCARD/eim_identity.json`
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM shell identity
  and does not automatically rewrite the simulated card-side BF55 row
- mutable cross-shell state is stored in `state/device_inventory.sqlite3`
- frozen builds use a spawned writable runtime tree under `YggdraSIM-data`
  for mutable state, drop-in certs, package templates, and CA caches
- some advanced commands are intentionally hidden behind `HELP EXPERT`

## Reading order

1. `SCP11/live/README.md` for relay-side operation
2. `../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-run lifecycle
   and logging commands
3. `SCP11/local_access/README.md` for direct local `ISD-R` work
4. `SCP11/eim_local/README.md` for the eIM-side shell overview
5. `SCP11/eim_local/GUIDE.md` for deep eIM-local package, hotfolder, and
   handover workflows
