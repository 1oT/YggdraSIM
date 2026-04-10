# SCP11 eSIM Module Guide

`SCP11/` contains the repository's eSIM-facing shells and helper layers. The
family is split by operator model, transport path, and which side of the
workflow needs to be exercised.

Use this file as the entry point for choosing the correct `SCP11` module.

## Module map

| Module | Use when | Card transport | Network role | Primary guide |
| --- | --- | --- | --- | --- |
| `SCP11/live` | production-like relay work with live-certificate defaults | `pcsc` or `relay` | remote ES9+ / eIM | `SCP11/live/README.md` |
| `SCP11/test` | lab relay work with test-certificate defaults and extra request shaping | `pcsc` or `relay` | remote ES9+ / eIM | `SCP11/test/README.md` |
| `SCP11/local_access` | direct local `ISD-R` bring-up and on-card profile loading | `pcsc` | no relay dependency | `SCP11/local_access/README.md` |
| `SCP11/eim_local` | eIM-side package authoring, localized polling, and handover validation | `pcsc` | local eIM / SM-DP+ bridge | `SCP11/eim_local/README.md` |
| `SCP11/relay` | preserve older relay imports and automation contracts | `pcsc` or `relay` | compatibility namespace | `SCP11/relay/README.md` |
| `SCP11/shared` | shared helpers only | n/a | n/a | `SCP11/shared/README.md` |

## Choose by task

- Use `SCP11/live` when the workflow is relay-first and should reflect the
  live-default certificate and endpoint model.
- Use `SCP11/test` when the workflow is relay-first but needs test-default
  certificates, compatibility toggles, or lab-only eIM request variants.
- Use `SCP11/local_access` when the task is direct `ISD-R` discovery,
  `PrepareDownload`, metadata upload, or ES10c profile state control.
- Use `SCP11/eim_local` when the task is on the eIM side: `ADD-INITIAL-EIM`,
  `ADD-EIM`, package queues, localized IPAd / IPAe polling, or handover
  orchestration.
- Use `SCP11/relay` only when an older import path or script contract depends
  on that namespace.

## Entry points

From the repository root:

```bash
python -m SCP11.live
python -m SCP11.test
python -m SCP11.local_access
python -m SCP11.eim_local
python -m SCP11.relay
```

All operator shells in this family also support `--cmd` and `--stdin` batch
execution. For semicolon batches, here-docs, and log-capture patterns, use:

- `../CLI_AND_PIPING_GUIDE.md`
- `../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

The top-level launcher in `main/main.py` exposes the same operator surfaces
through the Guides menu and the main module selector.

## Common runtime assumptions

- card-facing work requires a usable PC/SC reader unless the selected relay
  shell is configured for HTTP relay transport
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

1. `SCP11/live/README.md` or `SCP11/test/README.md` for relay-side operation
2. `../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-run lifecycle, poll,
   and logging commands
3. `SCP11/local_access/README.md` for direct local `ISD-R` work
4. `SCP11/eim_local/README.md` for the eIM-side shell overview
5. `SCP11/eim_local/GUIDE.md` for deep eIM-local package, polling, and
   handover workflows
