<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 eSIM Management Relay

`SCP11/live` is the eSIM management relay shell. Use it when the
workflow should model a real relay path rather than direct local `ISD-R`
access.

## Use this module when

- the operator flow is relay-first rather than card-local
- the active transport should be local PC/SC or an HTTP APDU relay
- the backend should speak to remote ES9+ / eIM endpoints

## Do not use this module when

- the task is direct local `ISD-R` provisioning or metadata upload
- the task is eIM-side package generation, hotfolder execution, or handover

## Launch

From the repository root:

```bash
python -m SCP11.live
```

One-shot flow mode is also available:

```bash
python -m SCP11.live --flow
```

Batch automation examples:

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
python -m SCP11.live --cmd "DOWNLOAD-PROFILE LPA:1$SMDP.EXAMPLE$TOKEN; STATUS; EXIT"
```

See `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-paste lifecycle
sequences and log-capture patterns.

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

The eSIM management relay shell is stateful while the shell is open:

- it establishes the relay/runtime context once at startup
- it renders a session snapshot with `EID`, default SM-DP+, queued
  notifications, profile versions, and eIM summary data
- transactional commands trigger notification sync and cleanup automatically
  when appropriate

Simulator card note:

- when the shared card backend is set to `sim`, the relay shell still runs the normal card-facing flow but against the simulator
- the simulated card's default BF55 eIM identity comes from `Workspace/SIMCARD/eim_identity.json`
- this is separate from `Workspace/LocalEIM/eim_identity.json`, which belongs to the Local eIM shell

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
- `DOWNLOAD [matchingId] [--<n>[,<n>...]]` (`--n` polls only the n-th configured eIM entry)
- `EIM-LISTEN [port=<n>] [calls=<n>] [idle=<seconds>] [notifications=deliver|keep]
  [host=<address> cert=<pem> key=<pem> client-ca=<pem>]`: eIM Package Injection
  (SGP.32 v1.3 §3.1.1.2). The shell connects to the card, prints its EID and
  answers ESipa.TransferEimPackage on `127.0.0.1:8746` (ASN.1 and JSON
  bindings) until Ctrl-C, after `calls` calls or after `idle` seconds without
  one. An injected eUICC Package or data request runs as one fetched with
  `DOWNLOAD` does and its result is the answer; an EimAcknowledgements
  package removes the named sequence numbers from the eUICC (§5.14.4).
  `notifications=keep` leaves the card's pending Notifications where they
  are instead of delivering them after each package. After an injected
  enable or disable the shell resets the card, so the state change is
  complete while the listener stays up. Without TLS: plain HTTP on the
  loopback only. With `cert`, `key` and `client-ca` the listener serves
  HTTPS on `host` and takes a call only from a client certificate that
  verifies against `client-ca` (§3.1.2.1: the eIM is the side that is
  authenticated); another address than a loopback one is taken only that
  way. No profile download: an injected trigger is answered undefinedError.
  The Local eIM's `INJECT` is the caller (`SCP11/eim_local/GUIDE.md` section
  6.4.5). In the GUI the verb is Listen for injected eIM packages on the
  SGP.32 IoT (IPA-d) tab, on the loopback over plain HTTP, ended with Cancel.
- `EIM-LISTEN-CERT <host name or address>... [out=<directory>]`: makes the
  self-signed certificate and key an HTTPS `EIM-LISTEN` serves with
  (`eim-listen-cert.pem`, `eim-listen-key.pem`, never replaced).
- `ADD-INITIAL-EIM`: a wizard asks for each EimConfigurationData member
  (SGP.32 v1.3 §2.11.1.1.1), with the certificates from the builder store and
  the last build's values as defaults. Options take a number, a name or
  shorthand (`oid`, `fqdn`, `cert`, `key`); a certificate file can be given as
  a path (PEM, DER, base64 or hex) and is stored under a name you confirm. It
  prints the request and the APDU sequence (`s` at the send prompt prints the
  full script) and, once confirmed, sends eUICCMemoryReset
  (resetEimConfigData, resetImmediateEnableConfig) and then AddInitialEim,
  decoding both answers. No card transport is held while the wizard waits;
  it is opened after the confirmation and released after the send. The GUI
  sends the same request with AddInitialEim send, in Offline Tools next to
  the build and in eSIM Management.
- `EIM-CERT-STORE [LIST|IMPORT <file> [name] [--overwrite]|RENAME <old> <new>|REMOVE <name>|VALUES|EDIT <field> <old> <new>|FORGET <field> <value>|CONFIGS|CONFIG-RENAME <old> <new>|CONFIG-DELETE <name>]`:
  the certificates, saved values and configurations of that builder, shared
  with the Offline Tools AddInitialEim build (`YGGDRASIM_EIM_BUILDER_STORE`,
  default `~/.yggdrasim/eim_builder/`, never tracked). `ADD-INITIAL-EIM` starts
  from a saved configuration when one is picked and offers to save the values
  as one before the send prompt.



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


## Configuration fields to know first

The eSIM management shell reads its defaults from `SCP11/live/config.py`. The most
operator-relevant fields are:

- `TRANSPORT_MODE`
- `READER_INDEX`
- `BACKEND_MODE`
- `RSP_SERVER_URL`
- `ES9_BASE_URL`
- `ES9_VERIFY_TLS`
- `ES9_CA_BUNDLE_PATH`
- `EIM_BASE_URL`
- `EIM_TRANSPORT_MODE` (`esipa_direct` for the ASN.1 binding, `esipa_json` for
  the SGP.32 section 6.4 JSON binding, `rest_resource` for a plain resource)
- `EIM_HTTP_PROTOCOL` (the `X-Admin-Protocol` value, `gsma/rsp/v1.3.0` by default)
- `EIM_TIMEOUT_SECONDS`
- `BPP_INSTALL_USE_SECTION_FRAMING`

Practical rule:

- if the task is a real relay exchange, confirm `RSP_SERVER_URL`,
  `ES9_BASE_URL`, and TLS settings before issuing profile downloads
- `ES9_CA_BUNDLE_PATH` is empty by default, which means platform TLS trust;
  set it only when the target requires an explicit CA bundle
- if the task is a lab replay, keep `TRANSPORT_MODE` set to `pcsc`

### BPP install framing

`BPP_INSTALL_USE_SECTION_FRAMING` defaults to `True` and should stay there.
It makes ES10b install emit the A1 and A3 container headers as their own
StoreData chains ahead of their 86/88 members, and the A2 header together
with its first `87`, per SGP.22 v3.1 section 2.5.5 and Annex M. Setting
it `False` selects the legacy flattened member-only mode, which sends the
first bare `86` with no owning container. eUICCs have been observed to read
that as a terminal `loadProfileElements` result and reply with a premature
ProfileInstallationResult, leaving the remaining protected segments unsent
and the SM-DP+ session pending.

Only set it `False` for a physical card that is known to reject
section-framed payloads, and confirm the install actually completed rather
than trusting the first success-looking result. The install banner prints
which mode is active. The flag is read only by `SCP11/live`; the segmenter
in `SCP11/local_access/session.py` is always section-framed.

## Related guides

- `SCP11/README.md`
- `../../guides/CLI_AND_PIPING_GUIDE.md`
- `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `SCP11/local_access/README.md`
- `SCP11/eim_local/README.md`
- `SCP11/relay/README.md`
