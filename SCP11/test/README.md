<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 Test Compatibility Namespace

`SCP11/test` is a compatibility namespace for older imports. It imports the
same implementation as `SCP11/live`, but it is no longer exposed as a separate
operator entrypoint. Use `SCP11/live` for the eSIM management relay.

## Use this module when

- an older import path still references `SCP11.test.*`
- the task depends on compatibility toggles or synthetic eIM request variants

## Do not use this module when

- you need an operator shell or CLI entrypoint
- the task is direct local `ISD-R` provisioning or metadata upload
- the work is eIM-side package orchestration, hotfolder execution, or handover
- the goal is to select a different certificate trust mode; use `SET-ES9-CA`
  or `ES9_CA_BUNDLE_PATH` instead

## Launch

No standalone launch surface is provided. Use the consolidated relay instead:

```bash
python -m SCP11.live
```

One-shot and batch modes are available there:

```bash
python -m SCP11.live --flow
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
```

See `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-paste lifecycle
sequences and log-capture patterns.

## Startup preflight

The same preflight model as `SCP11/live` is applied:

- validate transport and backend mode
- check PC/SC reader availability when `TRANSPORT_MODE=pcsc`
- validate relay URL when `TRANSPORT_MODE=relay`
- validate ES9+ / SM-DP+ settings for relay work
- validate local SCP11 credential material when local fallback is enabled

## Runtime model

The shell keeps the standard relay snapshot and command layout:

- session snapshot at startup
- relay utilities plus grouped `LPAd` and `IPAd` commands
- hidden expert commands behind `HELP EXPERT`
- automatic notification sync for transactional commands

Simulator card note:

- when the shared card backend is set to `sim`, the relay shell still exercises the normal card-facing relay flow but against the simulator
- the simulated card's default BF55 eIM identity comes from `Workspace/SIMCARD/eim_identity.json`
- this is separate from `Workspace/LocalEIM/eim_identity.json`, which belongs to the Local eIM shell

Compatibility behavior:

- no separate implementation is loaded
- no test CA bundle is selected implicitly
- lab request-shaping knobs remain available through the shared relay config

## Primary command groups

Relay utilities:

- `HELP [EXPERT]`
- `SCAN` and alias `INFO`
- `RESET`
- `STATUS`
- `LIST`
- `METADATA <id|aid|alias>`
- `EXIT`
- `QA`

LPAd:

- `DOWNLOAD-PROFILE <activation>`
- `ENABLE-PROFILE <iccid-or-aid>`
- `DISABLE-PROFILE <iccid-or-aid>`
- `DELETE-PROFILE <iccid-or-aid>`

IPAd:

- `DISCOVER`
- `DOWNLOAD`

## Expert commands

Use `HELP EXPERT` to expose the hidden relay controls:

- low-level readout:
  - `GET-EID`
  - `GET-EUICC-INFO1`
  - `GET-EUICC-INFO2`
  - `GET-RAT`
  - `GET-CERTS`
  - `GET-EIM-CONFIG`
  - `GET-ALL-DATA`
- notification handling:
  - `GET-NOTIFICATIONS`
  - `REMOVE-NOTIFICATION <seq>`
  - `CLEAR-NOTIFICATIONS`
- endpoint and TLS control:
  - `GET-SMDP`
  - `SET-SMDP <address>`
  - `GET-ES9`
  - `SET-ES9 [--persist] <url>`
  - `SET-ES9-TLS [--persist] <on|off>`
  - `SET-ES9-CA [--persist] <pemPath|NONE>`
  - `ES9-CERT-INFO`
- compatibility probes:
  - `VERIFY-SCP11 [matchingId]`
  - `FLOW [matchingId]`
  - `EIM-AUTHENTICATE [matchingId]`

## Common operator sequences

Baseline relay discovery:

```text
HELP
DISCOVER
STATUS
```

Test LPAd session:

```text
DOWNLOAD-PROFILE LPA:1$...
STATUS
```

Test IPAd cycle:

```text
DISCOVER
DOWNLOAD
```

## Compatibility configuration knobs

The compatibility namespace imports the live relay config. In addition to the usual
transport and ES9 fields, the shared config supports extra eIM controls such
as:

- `EIM_TRANSPORT_MODE`
- `EIM_REQUEST_VARIANT`
- `EIM_GET_PACKAGE_NOTIFY_STATE_CHANGE`
- `EIM_GET_PACKAGE_STATE_CHANGE_CAUSE`
- `EIM_GET_PACKAGE_RPLMN`
- `EIM_CLEAR_ACK_ON_NO_PACKAGE`
- `EIM_CLEAR_ACK_GENERIC_ERROR_HEX`
- `EIM_CLEAR_ACK_RESULT_ERROR`
- `EIM_PROFILE_DOWNLOAD_ERROR_REASON`
- `EIM_REST_CREATE_PATH`
- `EIM_REST_LOOKUP_PATH_TEMPLATE`

Use these only when the test case explicitly depends on non-default relay or
eIM behavior. For ordinary relay work, keep the shell as close as possible to
the `SCP11/live` operator model.

## Related guides

- `SCP11/README.md`
- `../../guides/CLI_AND_PIPING_GUIDE.md`
- `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `SCP11/live/README.md`
- `SCP11/local_access/README.md`
- `SCP11/eim_local/README.md`
- `SCP11/relay/README.md`
