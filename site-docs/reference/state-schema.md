---
title: State Schema
tags:
  - reference
  - state
  - sqlite
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# State Schema

YggdraSIM centralizes mutable cross-module state under `state/`. This page
documents what lives there, what identity key is used, and which subsystem
owns each area.

## Files under `state/`

| File | Purpose |
| --- | --- |
| `state/device_inventory.sqlite3` | primary SQLite inventory database |
| `state/inventory_crypto.json` | optional encryption configuration |
| `state/hil_bridge_supervisor.json` | HIL supervisor runtime status |
| `state/hil_bridge_card_relay.json` | HIL relay endpoint status |

## Logical sections in the inventory

The inventory is organized into logical sections by identity key and owner.
The concrete table layout is implementation-owned; consumers should go
through `yggdrasim_common/device_inventory.py` rather than querying tables
directly.

| Section | Identity key | Owner | Typical payload |
| --- | --- | --- | --- |
| per-card ICCID state | `ICCID` | `SCP03/`, `SCP80/`, `SCP11/` | keysets, OTA parameters, bind selections, last-seen metadata |
| per-card EID state | `EID` | `SCP11/` family | certificate selection, profile selection, metadata selection, per-flavor relay state |
| per-eIM state | `eim_id` | `SCP11/eim_local/` | counter values, runtime markers, error-code overrides, response-log pointers |
| module-level settings | module name | `SCP03/`, `SCP80/` | migrated values from legacy `.ini` files |

## Migration sources

| Legacy file | Current role |
| --- | --- |
| `Workspace/SCP03/keys.ini` | import source for SCP03 keyset state |
| `SCP80/ota_config.ini` | import source for SCP80 OTA parameters |
| `Workspace/LocalEIM/eim_runtime_state.json` | import source for eIM-local runtime state |

These files are imported once into the SQLite inventory, then kept for diff
review and continuity. Live truth is the SQLite-primary copy.

## Plain-file state that is intentionally not in SQLite

Some state is still better as plain files because manual editing and diff
review matter:

| File | Why it stays a plain file |
| --- | --- |
| `Workspace/SCP03/aid.txt` | human-curated AID list |
| `Workspace/SCP03/fids.txt` | human-curated FID shortlist |
| `Workspace/SCP03/binds.json` | human-curated macro binds |
| `Workspace/LocalEIM/eim_identity.json` | authored eIM identity |
| `Workspace/SIMCARD/eim_identity.json` | authored simulator BF55 identity |
| `Workspace/SIMCARD/isdr_config.json` | authored simulator ISD-R layout |

## Optional encryption envelope

`state/inventory_crypto.json` controls whether stored payloads are wrapped in
an encryption envelope. Default is `enabled: false` for friction-free
onboarding. When enabled:

- payloads are encrypted on write
- payloads are decrypted on read, only when a module asks for them
- the current provider is the system `gpg` binary via its agent/keyring
- metadata columns (for example identity keys used for lookup) remain
  cleartext

The provider block accepts an optional `gpg` map:

| Field | Meaning | Default |
| --- | --- | --- |
| `gpg.binary` | name or absolute path of the `gpg` binary | `gpg` on `PATH` |
| `gpg.timeout_seconds` | per-call wall-clock bound applied to every `gpg` invocation used by the inventory crypto manager | `120` |
| `gpg.gpg_key_file` | optional path to a file listing recipient fingerprints, resolved relative to `state/` and refused if it escapes that directory | unset |

See [Enable Inventory Encryption](../how-to/enable-inventory-encryption.md).

## HIL state files

| File | Meaning |
| --- | --- |
| `state/hil_bridge_supervisor.json` | supervisor status, bridge PID, USB presence |
| `state/hil_bridge_card_relay.json` | relay status, URLs, reader name, ATR |

These are written by `Tools/HilBridge/` and serve as live health surfaces.

## Runtime-root note

In source runs, `state/` lives under the repository. In frozen builds, the
runtime tree is resolved under the writable runtime root, not the bundled
application tree. See [Runtime Root](runtime-root.md).

## Related pages

- [Architecture](../architecture.md)
- [Runtime Root](runtime-root.md)
- [Enable Inventory Encryption](../how-to/enable-inventory-encryption.md)
