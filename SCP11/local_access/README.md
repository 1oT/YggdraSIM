# SCP11 Local SMDPP

`SCP11/local_access` is the Local SMDPP shell and direct local `ISD-R` shell. Use it when the task is
on-card and local-first rather than relay-first.

## Use this module when

- you need direct `ISD-R` bring-up
- you need local `AuthenticateServer` and `PrepareDownload`
- you want one-shot `LOAD-PROFILE`
- you need ES10c profile state control
- you need metadata JSON encoding and upload

## Do not use this module when

- the workflow should model relay behavior through `LPAd`, `IPAd`, or `IPAe`
- the task is eIM-side package authoring, localized polling, or handover
- the operator needs the live/test relay shells rather than direct card access

## Launch

From the repository root:

```bash
python -m SCP11.local_access
```

## Operator model

The shell is intentionally one-shot. There is no long-lived `OPEN` / `CLOSE`
session surface.

Each card-touching command:

1. opens the required local SCP11 session
2. performs the requested APDU flow
3. closes the session in cleanup

This keeps local work deterministic and avoids cross-command session residue.

## Primary commands

Discovery and inspection:

- `DISCOVER`
- `INFO`
- `STATUS`
- `CERTS`
- `SMDP-CERTS`

Provisioning and file selection:

- `LOAD-PROFILE [path]`
- `PROFILE [path]`
- `PROFILE-CLEAR`
- `METADATA [path]`
- `METADATA-CLEAR`
- `METADATA-LINT [path]`

Metadata send operations:

- `STORE-METADATA [path]`
- `STORE-METADATA-CUSTOM <tagHex> [path]`
- `STORE-METADATA-CUSTOM-ALL [path]`
- `UPDATE-METADATA [path]`

Profile state management:

- `ENABLE-PROFILE <id>`
- `DISABLE-PROFILE <id>`
- `DELETE-PROFILE <id>`
- aliases: `ENABLE`, `DISABLE`, `DELETE`

Shell control:

- `HELP`
- `EXIT`
- `QA`

## Common workflows

### Discovery

Use this when you need a compact local card snapshot:

```text
DISCOVER
STATUS
CERTS
```

`DISCOVER` and `INFO` run the compact local discovery sequence:

1. `SELECT ISD-R`
2. `GetProfilesInfo`
3. `GetEuiccConfiguredData`
4. `GetEID` through `ECASD`, then reselect `ISD-R`
5. `GetEuiccInfo1`
6. `GetEuiccInfo2`
7. `GetRAT`
8. `RetrieveNotificationsList`
9. `GetEimConfigurationData`
10. `GetCerts`

### Local profile load

Use this when the goal is direct on-card download rather than relay behavior:

```text
PROFILE test_profile.txt
METADATA default_profile_metadata.json
LOAD-PROFILE
```

`LOAD-PROFILE [path]` performs:

1. `SELECT ISD-R`
2. `GetEuiccInfo1`
3. `GetEuiccConfiguredData`
4. `GetEuiccChallenge`
5. `AuthenticateServer`
6. `PrepareDownload`
7. profile or BPP resolution
8. payload load
9. `CancelSession`

### Metadata upload

Use this when profile metadata needs to be encoded from JSON and sent locally:

```text
METADATA-LINT
STORE-METADATA
UPDATE-METADATA
```

Supported metadata flows:

- `STORE-METADATA [path]` for `StoreMetadataRequest` (`BF25`)
- `UPDATE-METADATA [path]` for `UpdateMetadataRequest` (`BF2A`)
- `STORE-METADATA-CUSTOM <tagHex> [path]` for a targeted custom-tag send
- `STORE-METADATA-CUSTOM-ALL [path]` for all enabled custom tags

### Profile state control

Use these commands after discovery or after a local load:

```text
ENABLE-PROFILE <iccid|aid|alias>
DISABLE-PROFILE <iccid|aid|alias>
DELETE-PROFILE <iccid|aid|alias>
```

Accepted identifiers:

- ICCID digits
- ICCID EF-format hex
- ISD-P AID hex
- alias from `SCP03/aid.txt`

Current behavior:

- `ENABLE-PROFILE` auto-disables the currently enabled profile before enabling
  the target
- `DISABLE-PROFILE` no-ops cleanly when the target is already disabled
- `DELETE-PROFILE` is allowed directly even when the target is currently
  enabled

## Certificate model

APDU transport defaults to local PC/SC. Certificate selection is card-aware:

- bundled valid SGP.26 material is scanned automatically
- drop-in files under `SCP11/local_access/certs` are scanned together with the
  bundled inventory
- matching uses the allowed `CI PKID` values reported by the card
- local drop-ins win when they match and include usable key material

Supported sidecar fields:

- `role`: `auth` or `pb`
- `private_key_path`
- `root_ci_pkid`
- `server_address`

Legacy filename pairs still work:

- `CERT.DPauth.ECDSA.der` and `SK.DPauth.ECDSA.pem`
- `CERT.DPpb.ECDSA.der` and `SK.DPpb.ECDSA.pem`

See `SCP11/local_access/certs/README.md` for the drop-in format.

## Persistence model

Persistent operator choices are bound to the active `EID` through the shared
SQLite inventory.

Stored local-access state can include:

- selected profile override path
- selected metadata override path
- selected certificate and key paths
- other per-card local-access choices

Primary mutable state:

- `state/device_inventory.sqlite3`

Optional encryption:

- `state/inventory_crypto.json`

## Directory model

Default roots:

- profiles: `SCP11/local_access/profile`
- metadata: `SCP11/local_access/profile/metadata`
- debug output: `SCP11/local_access/debug`

Resolution rules:

- a single usable profile file becomes the default `LOAD-PROFILE` input
- if multiple profile files exist, use `PROFILE` or pass an explicit path
- relative profile paths resolve from the profile directory
- relative metadata paths resolve from the metadata directory
- metadata JSON is optional when base fields can be derived from the profile

## Session rules

- the local session opener does not use `matchingId`
- `AuthenticateServer`, `PrepareDownload`, and the final BPP must share one
  coherent transaction context
- session-bound BPP generation is preferred when the source payload does not
  already match the active card session
- some cards require the `serverAddress` in `AuthenticateServer` to match the
  default SM-DP+ address advertised by the eUICC

## Related guides

- `SCP11/README.md`
- `SCP11/live/README.md`
- `SCP11/test/README.md`
- `SCP11/eim_local/README.md`
- `SCP11/local_access/certs/README.md`
