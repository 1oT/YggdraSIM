<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 Local eIM

`SCP11/eim_local` is the Local eIM: an operation queue per eUICC that signs
eUICC Packages when an IPA takes them (GSMA SGP.32 v1.3 §2.11.1), an ESipa
service that runs in the background, a local SM-DP+ for the downloads it
triggers, and the shell around them, which also reaches `ISD-R` directly.

## Use this module when

- operations (PSMOs, eCOs, IPA eUICC data requests, profile download triggers)
  should be queued for a test eUICC, edited, reordered or cancelled before they
  run, and their results read back
- a card should be associated with the Local eIM (`ASSOCIATE`) or its first eIM
  stored (`ADD-INITIAL-EIM`, `GET-EIM-CONFIG`)
- an IPA should poll a running eIM: the eSIM Management console's `DOWNLOAD`,
  or any other IPA that resolves the eIM FQDN
- eIM package documents (templates, hotfolder files) should be linted, explained
  or queued

If the task is only direct on-card provisioning, `SCP11/local_access` remains
the simpler shell.

## Launch

- standalone: `python -m SCP11.eim_local`
- launcher: use the Local eIM entry in `main/main.py`
- GUI: the Local eIM module (the page, and the Operations, eUICCs, eIM configuration, Direct card commands
  and Package files tabs of its action list)
- background service without the shell: `python -m SCP11.eim_local.engine.server start`

Batch automation examples:

```bash
python -m SCP11.eim_local --cmd "IDENTITY; EUICC; OPS pending; SERVE status; EXIT"
python -m SCP11.eim_local --cmd "QUEUE LIST-PROFILES 89049032123451234512345678901235; OPS all --json; EXIT"
```

```bash
python -m SCP11.eim_local --stdin <<'EOF'
SERVE start
SERVE status
EXIT
EOF
```

Use `GUIDE.md` for the operator workflows and
`../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for ready-to-paste
lifecycle sequences.

## How an operation runs

1. `IDENTITY NEW` creates the Local eIM's signing key and certificate (and a TLS
   pair); `ASSOCIATE` resets the card's eIM configuration and stores the Local
   eIM with AddInitialEim, so the card trusts its signature.
2. `QUEUE <operation> [eid] ...` stores an operation in state `CREATED`. A
   failed precondition (unknown card, profile not on the record, ...) is a
   warning; the operation is queued anyway.
3. An IPA asks for a package: the eUICC's next operation is signed with a
   fresh counterValue and served (`SENT`). One operation is in flight per eUICC.
4. The result is verified with the eUICC's certificate and closes the
   operation as `SUCCESS`, `PARTIAL_SUCCESS` or `ERROR`; the record (profiles,
   eIMs, counter, sequence number) follows the results. A result that does not
   verify is flagged, or discarded under `EIM-SETTINGS result_verification=discard`.
5. An operation without a result is retried (default 3 times, fresh counter);
   before a retry the Local eIM first asks the card for its stored eUICC
   Package Results, so a lost answer is recovered instead of run twice. A
   package that enables or disables a Profile is never served again by
   itself: the eUICC generates its result only after the REFRESH that
   completes the change (SGP.32 v1.3 §3.3.1 steps 8a-8b) and an IPAe reports
   it on a later session, so the operation is held until the result arrives
   or the operator cancels it.

Three routes hand the queue to an IPA:

- `SERVE start` runs the ESipa service in the background (plain HTTP on
  `127.0.0.1:8743` by default, `--tls` for HTTPS). Unless an explicit eIM base
  URL is configured, an IPA in another YggdraSIM process whose eIM FQDN or
  SM-DP+ address names the service is sent to it instead of resolving the
  name; a profile download trigger then runs against the local SM-DP+. A
  card-facing TLS listener runs next to it (`tls_port`, `127.0.0.1:8744` by
  default) for a card's own IPAe; `TLS-SETUP` builds the chains it serves (all
  of them at once, picked by the server name a card asks for), the trust and
  the eIM FQDN `ASSOCIATE` gives the card, the shape of the certificates (after
  a reference certificate) and the client authentication (GUIDE section
  6.4.1); `TLS-SETUP LEAF` issues further leaves under a setup's CA and
  `TLS-SETUP RESULTS` shows what the card did with each one served (GUIDE
  section 6.4.3); a leaf's subject and extensions can be written out line by
  line, and any certificate decoded into the same text (GUIDE section 6.4.4); each card's record remembers its setup, `ASSOCIATE CHOICES` lists
  them and `ASSOCIATE HANDOVER` puts another eIM's stored certificates on the
  card instead (section 6.2). A second one
  (`smdp_tls_port`, `127.0.0.1:8745` by default) is the local SM-DP+ for an
  IPAe that downloads directly: it serves the SM-DP+'s TLS certificate under
  the SGP.26 test CI and answers ES9+ in the ASN.1 binding (GUIDE section
  6.4.2). A third one (`smds_tls_port`, `127.0.0.1:8747` by default) is the
  local SM-DS for an IPAe that retrieves its Event Records itself.
- `SMDS` keeps the Event Records of the service's own SM-DS: `REGISTER` puts
  one on file for an eUICC, a download queued with `contact_smds=on` retrieves
  it over ES11 (`EIM-DOWNLOAD` in the eSIM Management shell runs it, the eIM
  asking the SM-DS with `indirect=on` and the IPA itself without), and the
  local SM-DP+ deletes it when the download it led to ends. Only an eUICC that
  trusts the SGP.26 test eSIM CA accepts this SM-DS (GUIDE section 6.4.6).
- `DELIVER [--once]` makes the shell the IPAd for the card in the reader: it
  serves that card's queue over STORE DATA and returns each result.
- `NOTIFICATIONS [<eid>]` lists the Notifications IPAs handed to the eIM. The
  eIM sends each one to the SM-DP+ its metadata names
  (ES9+'.HandleNotification, GSMA SGP.32 v1.3 §5.7.4): after `DELIVER` and
  `INJECT`, and from the running service, with further attempts for a server
  that did not answer. It holds none back; one it cannot deliver ends as
  failed. `NOTIFICATIONS SEND` sends now, the pending ones or the ones named
  (GUIDE section 6.5.1).
- `INJECT [<eid>] [target=http://127.0.0.1:<port>] [--once]` sends an eUICC's
  queue to an IPA that listens for it (eIM Package Injection, GSMA SGP.32
  v1.3 §3.1.1.2: the eIM calls ESipa.TransferEimPackage). The eSIM Management
  console's `EIM-LISTEN` is that IPA (`127.0.0.1:8746` by default). Plain
  HTTP on the loopback, or HTTPS on any address with the client certificate
  `INJECT-CERT` makes; no profile download (GUIDE section 6.4.5).
- `EXPORT <id>` signs one operation for an IPA outside YggdraSIM (package and
  STORE DATA script); `RESULT <id> <hex>` closes it with that IPA's answer.

`QUEUE DOWNLOAD [eid] activation_code=... indirect=on` keeps the Activation
Code at the Local eIM and serves an empty trigger: the IPA then runs the
download through the service, which relays every step to the SM-DP+ the code
names (the local one, or that host over ES9+) and forwards the installation
result to it (GSMA SGP.32 v1.3 §3.2.3.2). The operation's timeline shows each
relayed step.

## Primary command groups

Operation queue:

- `IDENTITY`, `ASSOCIATE`, `EUICC`
- `QUEUE`, `OPS`, `OP`
- `EDIT`, `MOVE`, `CANCEL`, `COPY`
- `EXPORT`, `RESULT`, `PACKAGE-IMPORT`
- `EIM-SETTINGS`

Service and delivery:

- `SERVE`
- `TLS-SETUP`
- `DELIVER`
- `INJECT`
- `NOTIFICATIONS`
- `SMDP-PROFILE`
- `SMDS`

Baseline local SCP11:

- `LIST`
- `DISCOVER`
- `LOAD-PROFILE`
- `ENABLE-PROFILE`
- `DISABLE-PROFILE`
- `DELETE-PROFILE`
- `STORE-METADATA`
- `UPDATE-METADATA`

Direct card commands and eIM lifecycle:

- `ADD-INITIAL-EIM`, `ISDR-ADD-INITIAL-EIM`
- `GET-EIM-CONFIG`, `ISDR-GET-EIM-CONFIG`
- `EUICC-MEMORY-RESET`
- `LOAD-EIM-PACKAGE`
- `ADD-EIM` and `DELETE-EIM` queue the addEim and deleteEim eCOs
  (`QUEUE ADD-EIM`, `QUEUE DELETE-EIM`); SGP.32 v1.3 §2.11.1.1.2 carries them
  in a signed eUICC Package, not in a STORE DATA of their own

IPAd discovery and handover:

- `IPAD-DISCOVER`
- `HANDOVER-SET`
- `HANDOVER-STATUS`
- `PATHS`

Package documents:

- `EIM-PACKAGE`
- `EIM-PACKAGE-LINT`
- `EIM-PACKAGE-EXPLAIN`
- `EIM-PACKAGE-ISSUE`
- `EIM-PACKAGE-ISSUE-ALL`
- `EIM-CERTS`
- `HOTFOLDER`
- `HOTFOLDER-LIST`
- `HOTFOLDER-FETCH`
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

The operation queue lives in its own store, `~/.yggdrasim/local_eim`
(`YGGDRASIM_LOCAL_EIM_STORE` moves it):

- `local_eim.sqlite3` -- settings, eUICC records, tasks and operations, and the
  exchanges the listeners answered (`TRAFFIC`; the newest 4000 are kept)
- `identity.json` and `keys/` -- the Local eIM identity; keys are written 0600
- `server.json` and `server.log` -- the running service and its log
- `tls-keylog.txt` -- the TLS session secrets of the card-facing listeners while
  `EIM-SETTINGS tls_keylog=on` (NSS key log format, for Wireshark; mode 0600)
- `smdp_profiles.json` -- the local SM-DP+ map from Matching ID to profile

Finished operations past `YGGDRASIM_LOCAL_EIM_HISTORY_CAP` (default 10000) are
pruned oldest first; pending ones never are.

The shell's own state:

- `state/device_inventory.sqlite3`
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

- source runs resolve the `Workspace/` and `state/` paths directly in the
  repository tree
- frozen builds and explicit `YGGDRASIM_RUNTIME_ROOT` overrides resolve the same
  relative paths under the active writable runtime root

## Identity and package model

The queue signs with the engine identity (`IDENTITY`). The shell's direct card
commands read their defaults from `Workspace/LocalEIM/eim_identity.json`:

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

`PACKAGE-IMPORT <file|folder> [eid]` queues what a PSMO, eCO, IPA eUICC data
request or profile download trigger document stands for; a folder is imported
in hotfolder order. Result documents are explained (`EIM-PACKAGE-EXPLAIN`), not
issued: results come from the card.

Operational queue roots live under:

- `Workspace/LocalEIM/eim_packages/fixtures`
- `Workspace/LocalEIM/eim_packages/hotfolder`

## Recommended reading order

1. this overview for module selection and the operation model
2. `SCP11/eim_local/GUIDE.md` for operator workflows
3. `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for non-interactive lifecycle
   and response-log recipes
4. `SCP11/local_access/README.md` for the baseline local SCP11 behavior this
   module extends
5. `Workspace/LocalEIM/eim_packages/templates/README.md` for template inventory
