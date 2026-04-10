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

Batch automation examples:

```bash
python -m SCP11.eim_local --cmd "STATUS; PATHS; LIST; DISCOVER; EXIT"
python -m SCP11.eim_local --cmd "HOTFOLDER-LIST --json; POLL-CAMPAIGN --until-empty --max-cycles 20 --json; EXIT"
```

```bash
python -m SCP11.eim_local --stdin <<'EOF'
IPAE-AUTHENTICATE EIM-TEST-001
HANDOVER-STATUS
IPAE-DOWNLOAD Workspace/LocalEIM/profile/test_profile.txt EIM-TEST-001
EXIT
EOF
```

Use `../../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-paste lifecycle,
handover, and polling sequences.

## Three execution paths

Direct Auth:

- authenticate locally
- send package content directly toward `ISD-R`
- use this for precise command validation without relay polling

Localized `IPAd` polling:

- use the same relay `IPAd` download flow as the live/test shells
- intercept the eIM / SM-DP+ target locally
- terminate and acknowledge the relay exchange internally instead of externally

Simulator card note:

- `Workspace/LocalEIM/eim_identity.json` defines the local eIM / SM-DP+ side for this module
- `Workspace/SIMCARD/eim_identity.json` defines the simulated card's default BF55 eIM identity
- use the wrapper `eIM identity` setting or `--sim-eim-identity` when you want the simulated card to advertise a different eIM without changing the Local eIM shell identity

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

- `Workspace/LocalEIM/profile`
- `Workspace/LocalEIM/profile/metadata`
- `Workspace/LocalEIM/eim_packages`
- `Workspace/LocalEIM/certs/eim`
- `Workspace/LocalEIM/eim_identity.json`

Related simulator file:

- `Workspace/SIMCARD/eim_identity.json`

Compatibility file:

- `Workspace/LocalEIM/eim_runtime_state.json`

Runtime-root note:

- source runs resolve these paths directly in the repository tree
- frozen builds and explicit `YGGDRASIM_RUNTIME_ROOT` overrides resolve the same
  relative paths under the active writable runtime root

Effects:

- counter state can be persisted by `eim_id`
- last package, transaction, and handover context can be restored
- optional encryption still follows `state/inventory_crypto.json`

## Identity and package model

Identity defaults for the Local eIM shell come from `eim_identity.json`, including:

- eIM ID
- eIM FQDN
- default `matchingId`
- endpoint addresses
- certificate paths

Card-side distinction:

- the simulated card does not read `Workspace/LocalEIM/eim_identity.json` as its BF55 default
- the simulator uses `Workspace/SIMCARD/eim_identity.json` unless a stronger card-side override such as `Workspace/SIMCARD/isdr_config.json` with `eim_entries` is applied

Package templates live under:

- `Workspace/LocalEIM/eim_packages/templates`

Seeded fake eIM peer-provisioning artifacts live under:

- `Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json`
- `Workspace/LocalEIM/eim_packages/fake_eim_peer_addition_info.json`

Operational queue roots live under:

- `Workspace/LocalEIM/eim_packages/fixtures`
- `Workspace/LocalEIM/eim_packages/hotfolder`

## Recommended reading order

1. this overview for module selection and execution paths
2. `../../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for non-interactive lifecycle
   and poll recipes
3. `SCP11/eim_local/GUIDE.md` for operator workflows
4. `SCP11/local_access/README.md` for the baseline local SCP11 behavior this
   module extends
5. `Workspace/LocalEIM/eim_packages/templates/README.md` for template inventory
