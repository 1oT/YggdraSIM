# SCP11 Live Relay

`SCP11/live` is the primary relay-oriented eSIM shell with live-default
certificate and endpoint assumptions. Use it when the workflow should model a
real relay path rather than direct local `ISD-R` access.

## Use this module when

- the operator flow is relay-first rather than card-local
- `LPAd`, `IPAd`, or `IPAe` behavior is the primary concern
- the active transport should be local PC/SC or an HTTP APDU relay
- the backend should speak to remote ES9+ / eIM endpoints

## Do not use this module when

- the task is direct local `ISD-R` provisioning or metadata upload
- the task is eIM-side package generation, localized polling, or handover
- the work depends on lab-only request variants better suited to `SCP11/test`

## Launch

From the repository root:

```bash
python -m SCP11.live
```

One-shot flow mode is also available:

```bash
python -m SCP11.live --flow
```

## Startup preflight

Before the shell starts, it validates:

- `TRANSPORT_MODE`
- `BACKEND_MODE`
- PC/SC reader availability when `TRANSPORT_MODE=pcsc`
- relay URL format when `TRANSPORT_MODE=relay`
- ES9 base URL and SM-DP+ address sanity for remote relay work
- local SCP11 credential files when local fallback is required

If preflight fails, the shell exits with a readable startup error instead of
opening a partially usable session.

## Runtime model

The live relay shell is stateful while the shell is open:

- it establishes the relay/runtime context once at startup
- it renders a session snapshot with `EID`, default SM-DP+, queued
  notifications, profile versions, and eIM summary data
- transactional commands trigger notification sync and cleanup automatically
  when appropriate

Primary runtime dimensions:

- transport:
  - `pcsc` for a local reader
  - `relay` for an HTTP APDU relay endpoint
- backend:
  - `remote_dp` for ES9+ / SM-DP+ relay work
  - `local_sgp26` only when the workflow intentionally uses the local SGP.26
    credential inventory

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

IPAe:

- `POLL [attempts] [timer-window] [-t 20s] [-s 5] [--debug]`
- alias: `EIM-POLL`

Plugin note:

- `POLL` / `EIM-POLL` is provided by the optional `polling` plugin
- when the plugin is absent, the command is not exposed by the core shell
- see `plugins/README.md` for the capability contract and publication model

## Expert commands

The default help intentionally hides lower-level and compatibility commands.
Use `HELP EXPERT` when you need:

- card inventory and eUICC data:
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
- relay endpoint control:
  - `GET-SMDP`
  - `SET-SMDP <address>`
  - `GET-ES9`
  - `SET-ES9 [--persist] <url>`
  - `SET-ES9-TLS [--persist] <on|off>`
  - `SET-ES9-CA [--persist] <pemPath|NONE>`
  - `ES9-CERT-INFO`
- compatibility and flow probes:
  - `VERIFY-SCP11 [matchingId]`
  - `FLOW [matchingId]`
  - `EIM-AUTHENTICATE [matchingId]`

## Common operator sequences

Discovery-first relay session:

```text
HELP
DISCOVER
STATUS
LIST
```

LPAd download:

```text
DOWNLOAD-PROFILE LPA:1$...
STATUS
METADATA <iccid|aid|alias>
```

IPAd relay cycle:

```text
DISCOVER
DOWNLOAD
STATUS
```

IPAe polling run:

```text
POLL
```

For long-running or timing-sensitive cases:

```text
POLL 3 30 --debug
```

## Configuration fields to know first

The live shell reads its defaults from `SCP11/live/config.py`. The most
operator-relevant fields are:

- `TRANSPORT_MODE`
- `READER_INDEX`
- `RELAY_URL`
- `BACKEND_MODE`
- `RSP_SERVER_URL`
- `ES9_BASE_URL`
- `ES9_VERIFY_TLS`
- `ES9_CA_BUNDLE_PATH`
- `EIM_BASE_URL`
- `EIM_TRANSPORT_MODE`
- `EIM_TIMEOUT_SECONDS`

Practical rule:

- if the task is a real relay exchange, confirm `RSP_SERVER_URL`,
  `ES9_BASE_URL`, and TLS settings before issuing profile downloads
- if the task is a lab replay, confirm whether `TRANSPORT_MODE` should be
  `pcsc` or `relay`

## Related guides

- `SCP11/README.md`
- `SCP11/test/README.md`
- `SCP11/local_access/README.md`
- `SCP11/eim_local/README.md`
- `SCP11/relay/README.md`
