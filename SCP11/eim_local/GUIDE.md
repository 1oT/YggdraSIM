# Local eIM Operator Guide

This guide explains how to operate `SCP11/eim_local` as the Local eIM shell for
local SGP.32 package work, direct card validation, localized polling, and
handover testing.

## 1. Scope and boundaries

`SCP11/eim_local` is intended for:

- eIM registration and lifecycle work:
  - `ADD-INITIAL-EIM`
  - `ADD-EIM`
  - `GET-EIM-CONFIG`
  - `DELETE-EIM`
- direct package execution against `ISD-R`
- localized `IPAd` and `IPAe` polling through the live/test relay
  orchestrators
- indirect and direct profile download package testing
- `BF50` result serialization, queue work, and campaign reporting

Current limit:

- the shell terminates endpoints locally and manages the runtime around the
  card
- it is not a standalone external eIM appliance with fully independent
  outbound TLS/private-key behavior

## 2. Before you start

Confirm the following first:

- the repository root is the current working directory
- the intended Python environment is active
- PC/SC access is available when real card execution is required
- a usable profile source exists under `SCP11/eim_local/profile`
- metadata JSON exists under `SCP11/eim_local/profile/metadata` when metadata
  override is needed
- eIM certificate material exists under `SCP11/eim_local/certs/eim`
- if `YGGDRASIM_RUNTIME_ROOT` is set, treat `SCP11/eim_local/...` as relative to
  the active runtime root rather than only to the git checkout

Recommended first commands inside the shell:

```text
STATUS
PATHS
HELP
COUNTERS
EIM-CERTS
HOTFOLDER-LIST
DISCOVER
```

## 3. Choose the execution path

### 3.1 Direct Auth

Use Direct Auth when:

- the goal is to validate a command directly against the card
- relay polling must be bypassed
- package semantics should be debugged without eIM/SM-DP+ transport effects

Primary commands:

- `ADD-INITIAL-EIM`
- `ADD-EIM`
- `ISDR-ADD-INITIAL-EIM`
- `ISDR-ADD-EIM`
- `LOAD-EIM-PACKAGE`
- `GET-EIM-CONFIG`
- `ISDR-GET-EIM-CONFIG`
- `DELETE-EIM`
- `ISDR-DELETE-EIM`

### 3.2 Localized IPAd

Use localized `IPAd` when:

- the discovery/download flow should run through the live or test relay shell
- the eIM endpoint must resolve locally instead of leaving the workstation
- the operator wants relay-style discovery with local interception

Primary commands:

- `IPAD-DISCOVER`
- `IPAD-LIVE`
- `IPAD-TEST`
- `PATHS`

### 3.3 Localized IPAe

Use localized `IPAe` when:

- the workflow must exercise polling, handover, or watchdog behavior
- the relay orchestrator should drive the timing while the eIM/SM-DP+ side
  stays local

Primary commands:

- `IPAE-AUTHENTICATE`
- `IPAE-DOWNLOAD`
- `IPAE-LIVE`
- `IPAE-TEST`
- `HANDOVER-SET`
- `HANDOVER-STATUS`
- `PATHS`

Practical split:

- `IPAE-AUTHENTICATE` and `IPAE-DOWNLOAD` are built into the Local eIM shell
- `IPAE-LIVE` and `IPAE-TEST` are the optional plugin-backed watchdog entry
  points that mirror relay `POLL`

## 4. Identity and certificate model

Identity defaults live in `SCP11/eim_local/eim_identity.json`.

Important identity fields:

- `eim_id`
- `eim_id_type`
- `eim_fqdn`
- `default_matching_id`
- `eim_endpoint`
- `smdpp_endpoint`
- `smdp_address`
- `eim_public_key_cert_path`
- `trusted_tls_cert_path`
- `euicc_ci_pk_id`

Practical rule:

- when an executable package leaves a compatible AddEim/AddInitialEim field
  empty, the shell can fall back to the identity value

Certificate handling:

- eIM-side signing and TLS material is read from `SCP11/eim_local/certs/eim`
- local SM-DP+ auth / download credentials are resolved through
  `SCP11/local_access/certs`
- `EIM-CERTS` previews the auto-selected signing certificate for the current
  card and package
- PEM and DER inputs are both accepted; PEM is normalized before wire encoding
- `eim_identity.json` pins the default identity signing cert to
  `CERT_S_EIMsign_YGGDRASIM_ACCEPTED.der`; command examples that pass
  `CERT_S_EIMsign_YGGDRASIM_NIST.pem` are intentionally overriding that default

## 5. Package model

Each package JSON is split into two layers:

- `sgp32`
  - spec-shaped data model
  - used for linting and wire preview
- `runtime`
  - execution hints used by the shell

Keep `runtime` populated for executable scenarios even when `sgp32` is already
complete.

Common runtime fields:

- `matching_id`
- `transaction_id_hex`
- `profile_path`
- `smdp_address`
- `bip_endpoints`
- `queue_id`

Hotfolder and poll order is resolved by:

1. `runtime.queue_id`
2. top-level `queue_id`
3. `runtime.transaction_id_hex`
4. numeric filename prefix
5. lexical fallback

Use `EIM-PACKAGE-LINT [path] [--strict-exec]` before issuing any new package.

## 6. Workflow: direct eIM registration

### 6.1 Prepare the session

Start with:

```text
STATUS
EIM-CERTS
DISCOVER
```

This confirms:

- active identity values
- selected signing certificate
- current card state and eIM rows

### 6.2 Register the first eIM

Package mode is preferred when full `EimConfigurationData` control is needed:

```text
ADD-INITIAL-EIM package SCP11/eim_local/eim_packages/templates/template_add_initial_eim.json
```

Direct `ISD-R` validation can also be forced explicitly:

```text
ISDR-ADD-INITIAL-EIM SCP11/eim_local/eim_packages/templates/template_add_initial_eim.json
```

### 6.3 Register an additional eIM

```text
ADD-EIM package SCP11/eim_local/eim_packages/templates/template_add_eim.json
```

Canonical seeded fake eIM peer package:

```text
ADD-EIM package SCP11/eim_local/eim_packages/fake_eim_add_eim_package.json
```

For explicit direct-to-card validation:

```text
ISDR-ADD-EIM SCP11/eim_local/eim_packages/templates/template_add_eim.json
```

### 6.4 Verify the result

```text
GET-EIM-CONFIG
ISDR-GET-EIM-CONFIG
RESP-LOG 20
```

Use `DELETE-EIM` or `ISDR-DELETE-EIM` only when the target eIM should be
removed.

## 7. Workflow: direct package execution against `ISD-R`

Use `LOAD-EIM-PACKAGE` when a package should be sent directly toward the card,
without queue or relay routing:

```text
LOAD-EIM-PACKAGE SCP11/eim_local/eim_packages/templates/template_add_eim.json
```

This is the fastest way to validate:

- AddEim / AddInitialEim semantics
- direct `ISD-R` command formatting
- package-to-card decoding and response reporting

Use `EUICC-MEMORY-RESET` only when the test case explicitly requires card-side
reset behavior.

## 8. Workflow: localized `IPAd`

Localized `IPAd` lets the live/test relay orchestrator drive the relay-side
logic while endpoint resolution stays local.

### 8.1 Prepare

```text
PATHS
STATUS
IPAD-DISCOVER
```

`PATHS` shows the active Direct Auth path plus the localized bridge endpoints
used for `IPAd` and `IPAe`.

### 8.2 Run the polling path

Live-default relay orchestrator:

```text
IPAD-LIVE [matchingId] [--debug]
```

Test-default relay orchestrator:

```text
IPAD-TEST [matchingId] [--debug]
```

These commands use the same relay-side `run_eim_poll()` path as the live/test
shell `DOWNLOAD` command, but the eIM / SM-DP+ traffic is intercepted and
terminated by the local bridge. Use `--debug` when you want raw APDU hex and
server-tagged labels such as `[eIM]` and `[SM-DP+]`; omit it for concise
operator output.

Provide a `matchingId` when the scenario depends on a specific package
selection:

```text
IPAD-LIVE EIM-FIRST-TEST
```

### 8.3 Inspect the result

```text
RESP-LOG 20
HOTFOLDER-LIST --json
```

## 9. Workflow: localized `IPAe`

Localized `IPAe` is the polling/watchdog path. Transaction continuity matters
more here than in Direct Auth.

### 9.1 Seed handover

```text
IPAE-AUTHENTICATE EIM-TEST-001
HANDOVER-STATUS
```

### 9.2 Continue with the linked download

```text
IPAE-DOWNLOAD test_profile.txt EIM-TEST-001
```

### 9.3 Run watchdog-style polling

Live orchestrator:

```text
IPAE-LIVE
```

Test orchestrator:

```text
IPAE-TEST
```

The localized watchdog uses the same argument model as relay `POLL` in the
live/test shells.

Plugin note:

- `IPAE-LIVE` and `IPAE-TEST` are exposed only when the optional `polling`
  capability is available through `plugins/`

With explicit attempts, timer window, attempt delay, and post-status loops:

```text
IPAE-LIVE 3 15 -t 20s -s 5 --debug
```

Practical rule:

- if transaction continuity is lost, reseed it with `IPAE-AUTHENTICATE` or
  `HANDOVER-SET`

## 10. Workflow: indirect and direct profile download packages

### 10.1 Indirect handover

Use `profile_download_trigger_request` when the eIM should hand the eUICC an
activation path toward the local SM-DP+ role.

Typical lint and issue cycle:

```text
EIM-PACKAGE-LINT SCP11/eim_local/eim_packages/templates/template_profile_download_trigger_request.json
EIM-PACKAGE-ISSUE SCP11/eim_local/eim_packages/templates/template_profile_download_trigger_request.json
```

### 10.2 Direct `BF36` relay

Use `bound_profile_package` or `direct_profile_download` when the eIM should
relay the profile payload itself.

```text
EIM-PACKAGE-LINT SCP11/eim_local/eim_packages/templates/template_bound_profile_package.json
EIM-PACKAGE-ISSUE SCP11/eim_local/eim_packages/templates/template_bound_profile_package.json
```

Source handling rules:

- if the selected profile source already begins with `BF36`, it is replayed
  directly
- otherwise the shell opens a local SCP11 session, runs `PrepareDownload`, and
  builds a session-bound `BF36`

### 10.3 Result-only serializers

The following families serialize result branches only:

- `provide_eim_package_result`
- `eim_package_result`
- `euicc_package_result`
- `ipa_euicc_data_response`
- `profile_download_trigger_result`

These do not start a download flow by themselves.

## 11. Workflow: queue and campaign operation

The effective queue can contain:

- fixed fixtures under `fixtures/eim_to_esim`
- fixed fixtures under `fixtures/esim_to_eim`
- the live hotfolder

Preview queue state:

```text
HOTFOLDER-LIST --json
```

Issue one deterministic queue pass:

```text
HOTFOLDER-FETCH --json
```

Run repeated campaigns:

```text
POLL-CAMPAIGN --until-empty --max-cycles 100 --json
POLL-EXPORT --until-empty --max-cycles 100
POLL-AGGREGATE reports --json
```

Campaign behavior:

- each campaign run issues each effective queue file at most once
- fixed fixtures and hotfolder files are merged into one ordered queue for that
  run
- `--until-empty` stops as soon as the effective queue has been drained

Expected empty-queue result:

- `noEimPackageAvailable(1)`
- wire response `BF4F03020101`

This is expected and is not treated as a failure.

## 12. Logs, counters, and audit state

Response log file:

- `SCP11/eim_local/eim_response_log.jsonl`

Poll audit database:

- `SCP11/eim_local/eim_poll_audit.sqlite3`

Shared mutable inventory:

- `state/device_inventory.sqlite3`

Useful commands:

```text
RESP-LOG 50
RESP-LOG-FILTER MID-EXAMPLE 50
COUNTERS
COUNTER 2.25.311782205282738360923618091971140414400
COUNTER 2.25.311782205282738360923618091971140414400 set 1
```

Compatibility note:

- `SCP11/eim_local/eim_runtime_state.json` remains as a legacy import source,
  not the primary mutable store

## 13. Troubleshooting

### 13.1 AddEim or AddInitialEim rejects missing data

Check:

- package row values
- `eim_identity.json`
- certificate paths
- CI PKID

If the package row is empty and no identity fallback exists, the encoder rejects
the command before it reaches the card.

### 13.2 A package lints but does not execute

Check:

- card I/O availability
- `runtime.allow_model_only`
- `transaction_id_hex`
- `matching_id`
- `profile_path`
- `smdp_address`

### 13.3 Direct download fails before load

Check:

- transaction ID presence
- profile path resolution
- local SCP11 credential validity
- `PrepareDownload` success

If the source is not already `BF36`, the shell must be able to build a
session-bound BPP for the current session.

### 13.4 Localized polling does not hit the expected endpoint

Check:

- `PATHS`
- active identity endpoint values in `STATUS`
- package `runtime.bip_endpoints`
- chosen live/test orchestrator command

### 13.5 Pending notifications remain on the card

Run:

```text
NOTIF-HYGIENE 0
```

If that still fails, inspect card state and response logs before issuing more
commands.

## 14. Validation

Focused test command:

```bash
python -m pytest tests/test_scp11_eim_local.py
```

Recommended shell-side validation after changes:

```text
EIM-PACKAGE-LINT --strict-exec
STATUS
RESP-LOG 20
COUNTERS
HOTFOLDER-LIST
```

## 15. Day-to-day operator order

For most sessions, this order keeps the shell deterministic:

1. verify `eim_identity.json`
2. confirm eIM and local-access certificate inventories
3. run `STATUS`
4. run `PATHS`
5. lint the package that will be issued
6. choose Direct Auth, localized `IPAd`, or localized `IPAe`
7. inspect `RESP-LOG`
8. drain notifications if needed with `NOTIF-HYGIENE 0`
9. export campaign reports when running queues over time
