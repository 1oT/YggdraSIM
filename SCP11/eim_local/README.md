# SCP11 Local eIM

`SCP11/eim_local` is the Local eIM shell. It extends the direct local SCP11
stack with package authoring, localized polling, handover orchestration,
response logging, and eIM identity management.

## Use this module when

- the task is `ADD-INITIAL-EIM`, `ADD-EIM`, `GET-EIM-CONFIG`, or `DELETE-EIM`
- the operator needs eIM package generation or validation
- localized `IPAd` / `IPAe` polling needs to terminate in a local eIM or
  local SM-DP+
- hotfolder queues and poll campaigns need to be exercised
- response logs and eIM counters must be inspected or overridden

If the task is only direct on-card provisioning, `SCP11/local_access` remains
the simpler shell.

## Launch

- standalone: `python -m SCP11.eim_local`
- launcher: use the Local eIM entry in `main/main.py`

## Three execution paths

Direct Auth:

- authenticate locally
- send package content directly toward `ISD-R`
- use this for precise command validation without relay polling

Localized `IPAd` polling:

- use the same relay `IPAd` download flow as the live/test shells
- intercept the eIM / SM-DP+ target locally
- terminate and acknowledge the relay exchange internally instead of externally

Localized `IPAe` polling:

- use the same plugin-backed watchdog style as relay `POLL` for `IPAE-LIVE` and
  `IPAE-TEST`
- keep handover and transaction continuity under local control through the
  built-in `IPAE-AUTHENTICATE` and `IPAE-DOWNLOAD` helpers
- intercept, route, and terminate the STK/BIP exchange locally

## Primary command groups

Baseline local SCP11:

- `LIST`
- `DISCOVER`
- `LOAD-PROFILE`
- `ENABLE-PROFILE`
- `DISABLE-PROFILE`
- `DELETE-PROFILE`
- `STORE-METADATA`
- `UPDATE-METADATA`

Direct Auth and eIM lifecycle:

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

Localized polling and handover:

- `IPAD-DISCOVER`
- `IPAD-LIVE [matchingId] [--debug]`
- `IPAD-TEST [matchingId] [--debug]`
- `IPAE-AUTHENTICATE`
- `IPAE-DOWNLOAD`
- `IPAE-LIVE` (optional plugin-backed)
- `IPAE-TEST` (optional plugin-backed)
- `HANDOVER-SET`
- `HANDOVER-STATUS`
- `PATHS`

Package and queue control:

- `EIM-PACKAGE`
- `EIM-PACKAGE-LINT`
- `EIM-PACKAGE-ISSUE`
- `EIM-PACKAGE-ISSUE-ALL`
- `EIM-CERTS`
- `HOTFOLDER`
- `HOTFOLDER-LIST`
- `HOTFOLDER-POLL`
- `HOTFOLDER-FETCH`
- `POLL-CAMPAIGN`
- `POLL-EXPORT`
- `POLL-AGGREGATE`
- `EIM-ACKNOWLEDGE`

Diagnostics and runtime state:

- `STATUS`
- `ERROR-CODES`
- `ERROR-CODE-SET`
- `COUNTERS`
- `COUNTER`
- `NOTIF-HYGIENE`
- `RESP-LOG`
- `RESP-LOG-FILTER`
- `RESP-LOG-CLEAR`

## State and persistence

Primary mutable state:

- `state/device_inventory.sqlite3`

Dedicated file roots:

- `SCP11/eim_local/profile`
- `SCP11/eim_local/profile/metadata`
- `SCP11/eim_local/eim_packages`
- `SCP11/eim_local/certs/eim`
- `SCP11/eim_local/eim_identity.json`

Compatibility file:

- `SCP11/eim_local/eim_runtime_state.json`

Runtime-root note:

- source runs resolve these paths directly in the repository tree
- frozen builds and explicit `YGGDRASIM_RUNTIME_ROOT` overrides resolve the same
  relative paths under the active writable runtime root

Effects:

- counter state can be persisted by `eim_id`
- last package, transaction, and handover context can be restored
- optional encryption still follows `state/inventory_crypto.json`

## Identity and package model

Identity defaults come from `eim_identity.json`, including:

- eIM ID
- eIM FQDN
- default `matchingId`
- endpoint addresses
- certificate paths

Package templates live under:

- `SCP11/eim_local/eim_packages/templates`

Seeded fake eIM peer-provisioning artifacts live under:

- `SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json`
- `SCP11/eim_local/eim_packages/fake_eim_peer_addition_info.json`

Operational queue roots live under:

- `SCP11/eim_local/eim_packages/fixtures`
- `SCP11/eim_local/eim_packages/hotfolder`

## Recommended reading order

1. this overview for module selection and execution paths
2. `SCP11/eim_local/GUIDE.md` for operator workflows
3. `SCP11/local_access/README.md` for the baseline local SCP11 behavior this
   module extends
4. `SCP11/eim_local/eim_packages/templates/README.md` for template inventory
