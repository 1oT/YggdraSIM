---
title: SCP11 eIM Local
tags:
  - subsystems
  - scp11
  - eim
  - sgp32
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SCP11 eIM Local

`SCP11/eim_local/` is the eIM-side shell for SGP.32 IoT RSP work. It layers
eIM package authoring, hotfolder queues, response logging, and handover
helpers on top of the local SCP11 stack.

!!! info "Underlying concept"
    Read [RSP Architecture](../concepts/rsp-architecture.md) first. This
    page assumes the SGP.32 eIM/IPA split is understood.

## When to use it

- queue PSMOs, eCOs, IPA eUICC data requests and profile download triggers for a
  test eUICC, and serve them to an IPA from the background ESipa service
- `ADD-INITIAL-EIM`, `GET-EIM-CONFIG`; `ADD-EIM` and `DELETE-EIM` queue their eCO
- `LOAD-EIM-PACKAGE` direct to ISD-R
- hotfolder-driven package campaigns
- counter and error-code inspection
- response log capture, filtering, and clear-out
- handover orchestration between Auth, Download, and status verbs
- direct-to-ISD-R package validation without relay transport

## Entry points

=== "Module"

    ```bash
    python -m SCP11.eim_local
    python -m SCP11.eim_local --cmd "STATUS; PATHS; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-scp11-eim-local
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP11 eIM Local entry.

## Command surface, grouped

### Diagnostics and paths

| Command | Purpose |
| --- | --- |
| `STATUS` | session and shell status |
| `PATHS` | resolved paths for identity, packages, logs, certs |
| `COUNTERS` | list known eIM counters |
| `COUNTER <eim_id>` | inspect or set a specific counter |
| `ERROR-CODES` | list configured error-code overrides |
| `ERROR-CODE-SET <code> <meaning>` | override or inspect an error code |
| `RESP-LOG` | print the response log |
| `RESP-LOG-FILTER <filter>` | filter response-log output |
| `RESP-LOG-CLEAR` | clear the response log |
| `NOTIF-HYGIENE` | notification list hygiene |

### Operation queue

| Command | Purpose |
| --- | --- |
| `IDENTITY` | show, create (`NEW`) or import the Local eIM identity |
| `ASSOCIATE` | reset the card's eIM configuration and store the Local eIM (AddInitialEim) |
| `EUICC` | list, show, add, read, edit or remove eUICC records |
| `QUEUE` | queue an operation (`--plan` shows it without storing) |
| `OPS` / `OP` | list operations / show one with its timeline and result |
| `EDIT` / `MOVE` / `CANCEL` / `COPY` | change, reorder, cancel or copy an operation |
| `EXPORT` / `RESULT` | sign one operation for another IPA / close it with that IPA's result |
| `PACKAGE-IMPORT` | queue what a package document (template, hotfolder file) stands for |
| `EIM-SETTINGS` | queue rules: unknown EIDs, result recovery, retries, result verification, Notification forwarding |
| `SERVE` | start, stop, restart or show the background ESipa service and local SM-DP+; the service also relays indirect downloads (`QUEUE DOWNLOAD ... indirect=on`) and runs the card-facing TLS listeners a card's own IPAe reaches: the eIM's, and the local SM-DP+'s for a direct download (ES9+ in the ASN.1 binding) |
| `TLS-SETUP` | build a TLS chain for the card-facing listener and choose the trustedPublicKeyDataTls `ASSOCIATE` gives the card; `LEAF` issues further leaves under a setup's CA and puts one on its name, `RESULTS` counts the recorded handshakes per leaf served (accepted, refused with the client's alert, resumed); a leaf's subject and extensions can be written as text (`subject=`, `ext.<extension>=`, `text=<file>`) and `TEXT` decodes a leaf or any certificate into that text |
| `DELIVER` | act as IPAd on the card in the reader until its queue is empty |
| `INJECT` | send an eUICC's queue to an IPA that listens for it: the eIM calls ESipa.TransferEimPackage (plain HTTP on the loopback, or `https://` with the certificate of `INJECT-CERT`; `EIM-LISTEN` in the eSIM Management console is that IPA) |
| `INJECT-CERT` | make, once, and show the client certificate this eIM presents to an IPA over HTTPS |
| `NOTIFICATIONS` | list the Notifications IPAs handed to the eIM; `SEND` sends them to the SM-DP+ each names (ES9+'.HandleNotification), `HOLD` stops the attempts. The eIM also sends them after `DELIVER` and `INJECT` and while the service runs |
| `SMDP-PROFILE` | which profile the local SM-DP+ serves for a Matching ID |
| `SMDS` | the service's own SM-DS: `REGISTER` and `DELETE` an Event Record for an eUICC, `LIST` them, `ADDRESS` sets the name it answers under; a download queued with `contact_smds=on` retrieves the records over ES11 (`EIM-DOWNLOAD` in the eSIM Management shell runs it), and the service runs a card-facing TLS listener for an IPAe that retrieves them itself (SGP.26 test certificates only) |

### eIM lifecycle (direct card)

| Command | Purpose |
| --- | --- |
| `ADD-INITIAL-EIM` | seed BF55 identity via the eIM path |
| `ADD-EIM` | queue the addEim eCO (`QUEUE ADD-EIM`) |
| `GET-EIM-CONFIG` | read eIM configuration data from the card |
| `DELETE-EIM` | queue the deleteEim eCO (`QUEUE DELETE-EIM`) |
| `EUICC-MEMORY-RESET` | trigger the eUICC memory reset flow |
| `ISDR-ADD-INITIAL-EIM` | direct-to-ISD-R variant of add-initial-eim |
| `ISDR-GET-EIM-CONFIG` | direct-to-ISD-R variant of get-eim-config |
| `LOAD-EIM-PACKAGE` | load a generated eIM package onto the card |

### IPAd discovery and handover

| Command | Purpose |
| --- | --- |
| `IPAD-DISCOVER` | IPAd discovery against the card, with optional package selection |
| `HANDOVER-SET` | seed the handover context by hand |
| `HANDOVER-STATUS` | inspect the current handover state |

### Queues and campaigns

| Command | Purpose |
| --- | --- |
| `HOTFOLDER` | manage the hotfolder |
| `HOTFOLDER-LIST` | list pending packages |
| `HOTFOLDER-FETCH` | fetch a specific hotfolder package |
| `EIM-ACKNOWLEDGE` | explicit eIM acknowledgement |

## Identity split to remember

- `Workspace/LocalEIM/eim_identity.json` defines the Local eIM and SM-DP+
  side of the shell.
- `Workspace/SIMCARD/eim_identity.json` defines the simulated card's default
  BF55 eIM identity.
- `Workspace/SIMCARD/isdr_config.json` with `eim_entries` defines a full
  custom card-side eIM layout when the single default is not enough.

The Local eIM identity does not silently rewrite the simulator-side BF55
row. Keep them aligned on purpose.

## Runtime dependencies

- a reader with an eUICC, or the simulator backend
- local SCP11 certificates for the direct-to-ISD-R flows
- local eIM certificates under `SCP11/eim_local/certs/`
- the shared SQLite inventory for per-`eim_id` state

## State the shell writes

| Location | Contents |
| --- | --- |
| `state/device_inventory.sqlite3` | per-eim_id counters and runtime markers |
| `SCP11/eim_local/eim_packages/` | authored packages and templates |
| `SCP11/eim_local/eim_packages/hotfolder/` | hotfolder queue |
| JSONL response logs | response-log evidence retained under the runtime root |

## Common recipes

### First-time eIM bring-up

```text
[eSIM eIM] > STATUS
[eSIM eIM] > ADD-INITIAL-EIM
[eSIM eIM] > GET-EIM-CONFIG
```

### Hotfolder fetch loop

```bash
python -m SCP11.eim_local --cmd "HOTFOLDER-LIST; HOTFOLDER-FETCH; RESP-LOG 5; EXIT"
```

### Review response evidence

```text
[eSIM eIM] > HOTFOLDER-LIST
[eSIM eIM] > HOTFOLDER-FETCH
[eSIM eIM] > RESP-LOG
```

## Pitfalls

- `ADD-INITIAL-EIM` can only run when the target BF55 row is empty or the
  card-side configuration explicitly allows overwrite. Check the simulator
  `isdr_config.json` before retrying.
- Hotfolder artifacts live under the writable runtime root on frozen builds,
  not under the source tree.
- Counter overrides through `COUNTER <eim_id> <value>` persist until changed
  again; they do not auto-reset on shell exit.

## Related pages

- [RSP Architecture](../concepts/rsp-architecture.md)
- [SCP11 Local Access](scp11-local-access.md)
- `SCP11/eim_local/GUIDE.md` for the full authored eIM-local guide
