# SCP11 Test Relay

`SCP11/test` is the lab-oriented relay shell with test-default certificate and
endpoint assumptions. It mirrors the live relay layout, but keeps extra
request-shaping and compatibility controls available for controlled testing.

## Use this module when

- the workflow is relay-first but should use test-default settings
- the operator needs a safer lab surface than `SCP11/live`
- the task depends on compatibility toggles or synthetic eIM request variants
- the shell should still look and behave like the standard relay operator model

## Do not use this module when

- the task is direct local `ISD-R` provisioning or metadata upload
- the work is eIM-side package orchestration, hotfolder polling, or handover
- the goal is to validate live-default relay settings instead of lab defaults

## Launch

From the repository root:

```bash
python -m SCP11.test
```

One-shot flow mode is also available:

```bash
python -m SCP11.test --flow
```

Batch automation examples:

```bash
python -m SCP11.test --cmd "DISCOVER; STATUS; LIST; EXIT"
python -m SCP11.test --cmd "DOWNLOAD-PROFILE LPA:1$SMDP.TEST$TOKEN; STATUS; EXIT"
python -m SCP11.test --cmd "POLL 3 30 --debug; EXIT"
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

- when the shared card backend is set to `sim`, the relay shell still exercises the normal card-facing test flow but against the simulator
- the simulated card's default BF55 eIM identity comes from `Workspace/SIMCARD/eim_identity.json`
- this is separate from `Workspace/LocalEIM/eim_identity.json`, which belongs to the Local eIM shell

Difference from `SCP11/live`:

- the primary relay command surface tracks `SCP11/live`, including the
  `POLL` watchdog command shape
- the operational difference is primarily certificate/trust defaults and the
  availability of extra lab-oriented request/result shaping
- the configuration layer exposes more eIM test controls for request and result
  shaping

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

Compatibility polling:

- `POLL [attempts] [timer-window] [-t 20s] [-s 5] [--debug]`
- alias: `EIM-POLL`

Plugin note:

- `POLL` / `EIM-POLL` is provided by the optional `polling` plugin
- when the plugin is absent, the command is not exposed by the core shell
- see `plugins/README.md` for the capability contract and publication model

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

Compatibility polling:

```text
POLL
```

For long-running or timing-sensitive cases:

```text
POLL 3 30 --debug
```

## Test-only configuration knobs

The test shell reads defaults from `SCP11/test/config.py`. In addition to the
usual transport and ES9 fields, it supports extra eIM controls such as:

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
