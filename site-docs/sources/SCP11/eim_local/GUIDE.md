<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Local eIM Operator Guide

This guide explains how to operate `SCP11/eim_local` as the Local eIM: its
operation queue and background ESipa service, direct card validation, response
logging, and handover testing.

## 1. Scope and boundaries

`SCP11/eim_local` is intended for:

- the operation queue: PSMOs, eCOs, IPA eUICC data requests and profile
  download triggers for registered eUICCs, signed when an IPA takes them
- eIM association: `ASSOCIATE`, `ADD-INITIAL-EIM`, `GET-EIM-CONFIG`
- direct package execution against `ISD-R`
- `IPAd` discovery and the handover context
- indirect and direct profile download package testing
- `BF50` result serialization, queue work, and response reporting

Current limit:

- the ESipa service is a bench service: plain HTTP on `127.0.0.1` for the
  rig's IPAd, a card-facing TLS listener on the next port for a card's own
  IPAe (section 6.4.1) and one more for a direct download from the local
  SM-DP+ (section 6.4.2); it is not hardened for exposure beyond the test bench

## 2. Before you start

Confirm the following first:

- the repository root is the current working directory
- the intended Python environment is active
- PC/SC access is available when real card execution is required
- a usable profile source exists under `Workspace/LocalEIM/profile`
- metadata JSON exists under `Workspace/LocalEIM/profile/metadata` when metadata
  override is needed
- eIM certificate material exists under `Workspace/LocalEIM/certs/eim`
- if `YGGDRASIM_RUNTIME_ROOT` is set, treat `Workspace/LocalEIM/...` as relative to
  the active runtime root rather than only to the git checkout

Recommended first commands inside the shell:

```text
STATUS
HELP
IDENTITY
EUICC
OPS pending
SERVE status
DISCOVER
```

Batch-mode shortcut:

```bash
python -m SCP11.eim_local --cmd "STATUS; PATHS; HOTFOLDER-LIST --json; EXIT"
```

Use `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` when the goal is a ready-made
download, handover, or queue command sequence rather than a deep operator walk.

## 3. Choose the execution path

### 3.1 Direct Auth

Use Direct Auth when:

- the goal is to validate a command directly against the card
- relay transport must be bypassed
- package semantics should be debugged without eIM/SM-DP+ transport effects

Primary commands:

- `ADD-INITIAL-EIM`
- `ISDR-ADD-INITIAL-EIM`
- `LOAD-EIM-PACKAGE`
- `GET-EIM-CONFIG`
- `ISDR-GET-EIM-CONFIG`

Adding or deleting a further eIM is an eCO inside a signed eUICC Package
(SGP.32 v1.3 §2.11.1.1.2), so `ADD-EIM` and `DELETE-EIM` queue it (section 6.6).

### 3.2 IPAd discovery and handover

Use the `IPAd` side of the shell when:

- the card's eIM-facing state should be read before a package is issued
- a profile download must carry the transaction reference of the eIM exchange
  that asked for it

Primary commands:

- `IPAD-DISCOVER`
- `HANDOVER-SET`
- `HANDOVER-STATUS`
- `PATHS`

## 4. Identity and certificate model

Identity defaults for the Local eIM shell live in `Workspace/LocalEIM/eim_identity.json`.

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

Simulator-side split:

- `Workspace/LocalEIM/eim_identity.json` describes the local eIM / SM-DP+ side used by `SCP11/eim_local`
- `Workspace/SIMCARD/eim_identity.json` describes the simulated card's default BF55 eIM identity
- use the wrapper `Card Backend / Simulator Settings` screen or `python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json` when you want to swap the simulated card to a different local or real eIM-facing identity quickly
- use `Workspace/SIMCARD/isdr_config.json` with explicit `eim_entries` when the card side needs a full custom eIM layout instead of the single seeded default

Certificate handling:

- eIM-side signing and TLS material is read from operator-provided drop-ins under `Workspace/LocalEIM/certs/eim`
- local SM-DP+ auth / download credentials are resolved through
  `Workspace/LocalSMDPP/certs`
- `EIM-CERTS` previews the auto-selected signing certificate for the current
  card and package
- PEM and DER inputs are both accepted; PEM is normalized before wire encoding
- the repository does not ship usable Local eIM signing or TLS certificates
- `eim_identity.json` leaves the Local eIM certificate paths empty by default
- command examples should pass operator-provided certificate paths explicitly,
  or the operator can populate the identity file locally

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

Hotfolder queue order is resolved by:

1. `runtime.queue_id`
2. top-level `queue_id`
3. `runtime.transaction_id_hex`
4. numeric filename prefix
5. lexical fallback

Use `EIM-PACKAGE-LINT [path] [--strict-exec]` before issuing any new package.

## 6. Workflow: association and the operation queue

### 6.0 The Local eIM page in the GUI

The Local eIM module opens on a page built from the store, not on an action
form. It has two tabs.

- **eUICCs** lists every eUICC the eIM knows: EID, label, whether this eIM is
  linked, profile count, last poll and pending operations. "Read the card in
  the reader" adds or refreshes the record of the card in the bound reader;
  "Register an EID" adds one without a card.
- Opening an eUICC shows its EID with the last poll and the pending count,
  then five sections. **eSIM profiles** has "Refresh eSIM profile list",
  "Download a profile" (an activation code, optionally as an indirect
  download) and Enable / Disable / Delete per profile. **eUICC information**
  shows the default SM-DP+, the root SM-DS, immediate profile enabling, the
  association token and the counter, with the card's stored answers and its
  certificates under "Show more". **eIMs linked with eUICC** lists what the
  card reported and offers "Add an eIM (addEim)", which opens New operation
  on Add eIM: an addEim in a signed eUICC Package that adds an eIM beside the
  card's others (a saved configuration fills it; the result carries the
  association token the added eIM needs), and "Link this eIM" (Associate,
  card in the reader), which resets the card's eIM configuration first.
  **Event log** lists the eUICC's operations with their state; a row opens
  the operation's detail and a pending one can be canceled.
  **Notifications** lists what the card's IPA handed to this eIM, each with
  its sequence number, event, ICCID, Notification Receiver and state, and has
  "Send" (section 6.5.1).
- **eIM configuration** shows the identity, the signing certificate with its
  public key, every TLS chain the service serves with its certificates, the
  service state with Start / Restart / Stop, and the queue rules. Private keys
  are named by file, never shown.

The top bar carries a Local eIM pill beside HIL bridge and Remote: running,
not answering (the process runs but does not answer its /ping), stopped, or
unknown for a GUI server that does not report it. A click starts the service
with the defaults (`SERVE start`: port 8743, the card listeners on 8744,
8745 and 8747) or stops it (`SERVE stop`); other ports take the Start service
form.

"New operation" on an eUICC's page lists every operation type of the
catalogue (section 6.3) with one field per parameter, plus "Refresh
everything"; the queue options hold not-before, retries and "queue first".
For "Add eIM" the `config` field offers the eIM configurations saved in the
AddInitialEim builder; one of them fills every field left empty (section 6.6).
The eUICC information section sets the default SM-DP+ address and turns
immediate profile enabling on or off, a profile row sets or unsets the
fallback attribute, and "Enable with rollback" adds the rollbackFlag to an
Enable. An event-log row opens the operation: its parameters as fields while
it is queued ("Save changes"; "Queue a copy" for one that is not), the package
as named rows once it was served (before that, the part fixed so far), the
card's answer as named rows, and the timeline. "Deliver now (IPAd)" ends on a
list of the operations that run finished, each opening the same page; with a
plugin that drives the card's own IPAe loaded, "Deliver (IPAe)" opens its
form. EUICCInfo1 and EUICCInfo2 are decoded by field under "Show more".

A queued profile download is not carried out by "Deliver now (IPAd)": the eIM
hands over a trigger and an IPA downloads from the SM-DP+. While one is
queued the page says so and offers "Run the download (IPAd)", which opens
eSIM Management's "eIM download (SGP.32)" for the card in the reader (the
service has to run; "Start service" is offered when it does not).

Every button queues an operation (section 6.3) or opens the action's form; the
card takes a queued operation when it polls the running service or at once
with "Deliver now" and the card in the reader (section 6.4). Stored card data
is as old as the "Last updated" line under it. The action list on the left
keeps every action of sections 6 to 12; the "<- Local eIM" key above an
action's form or output returns to the page. The package-file tools (lint,
explain, load, hotfolder) are folded in the Inspector under "Package files
and hotfolder".

### 6.1 Create the Local eIM identity

```text
IDENTITY NEW 1.3.6.1.4.1.32473.999.10.124 eim.yggdrasim.local
IDENTITY
```

`IDENTITY NEW` writes a P-256 signing key and certificate and a TLS key and
certificate (SAN = the eIM FQDN) under the store's `keys/` folder; `IDENTITY
IMPORT` takes operator-provided material instead.

### 6.2 Associate the card

```text
ASSOCIATE
EUICC READ
```

`ASSOCIATE` resets the eIM configuration of the card in the reader and stores
the Local eIM with AddInitialEim (`--no-reset` skips the reset, `--public-key`
sends the bare key instead of the certificate). It echoes the EID and asks for
confirmation unless `--yes` is given. The record keeps the association token and
counter the card now holds. The eIM FQDN (eimFqdn) and the TLS trust
(trustedPublicKeyDataTls) the card is given follow the TLS setup in use
(section 6.4.1); without one they are the identity's.

`ASSOCIATE CHOICES` lists what an association can carry: the identity and every
TLS setup with the eIM FQDN and the trust it stands for, the one in use marked,
the cards associated under each, and the stored certificates `HANDOVER` takes.
`ASSOCIATE setup=<name>` associates under that setup, so one command picks the
certificates and the name the card is given. Without `setup=`, a card that was
associated before gets the setup it already holds; a new card gets the one in
use. Every association records its setup on the card's record, and the
card-facing listener serves every setup at once (the ClientHello's server name
picks the chain; a client naming no host gets the setup in use), so swapping
cards changes nothing in the service: each card polls the name it was given and
meets the chain it trusts. A setup built after the service started is served
after a restart, which `ASSOCIATE` and `TLS-SETUP NEW` do by themselves. The
Local eIM answers for one family of names only, `eim*.yggdrasim.local` (one
label that starts with `eim`; `.local` is not delegated in the public DNS): the service lists, and the IPAe route resolves and redirects, no
other name, so a production or test eIM's name always reaches that eIM. Every
name of that family is answered, whether a setup carries it or not; a setup
whose leaf is the wildcard (`san=*.yggdrasim.local`) serves them all with one
chain, and `ASSOCIATE fqdn=eim7.yggdrasim.local` gives a card any of them.
`ASSOCIATE` therefore refuses a setup or identity under any other name, since a
card told it would poll that host itself; `ASSOCIATE HANDOVER` is the verb that
hands a card to another eIM. The card-facing listener refuses a ClientHello
that names any other host (TLS alert unrecognized_name).

```text
ASSOCIATE HANDOVER eim_id=<id> sign=<stored certificate> [fqdn=<host>]
    [eim_id_type=oid|fqdn|proprietary] [tls=<stored certificate>|none]
    [--public-key] [--tls-key] [counter=<n>] [ci_pkid=<hex>|card]
    [indirect=on|off] [protocols=<a,b>] [--yes] [--no-reset]
```

`HANDOVER` runs the same reset and AddInitialEim with another eIM's certificates
from the AddInitialEim builder store (`EIM-CERT-STORE` in the eSIM Live shell,
the eIM certificate store action in Offline Tools): the card is handed to that
eIM, with the eimId, FQDN, counter and protocol bits given (`--public-key` and
`--tls-key` send a certificate's SubjectPublicKeyInfo instead of the
certificate; `ci_pkid=card` takes the first CI Public Key Identifier the card
lists for signing, SGP.32 v1.3 §5.9.4). The Local eIM holds no private key for
that eIM, so the record is marked foreign and the card refuses every package
from this rig (euiccPackageErrorUnsigned, §5.9.1) until `ASSOCIATE` puts the
identity back. The GUI has the same three under "eUICCs": Associate
card (with its TLS setup field), Association choices and Hand over card.

`EUICC READ` copies the card's profiles, eIMs and
certificate into the record. trustedPublicKeyDataTls follows the TLS setup in
use (section 6.4.1); without one it is the identity's TLS certificate.

A card needs no `EUICC ADD`: every EID YggdraSIM reads from a card (the eSIM
Management console, the eIM-local and local-access shells, the SCP03 admin
shell) gets a record the first time, labelled with the surface that saw it, and
so does an unknown EID that polls the eIM over ESipa. `EIM-SETTINGS
learn_unknown_eids=off` stops both; the eIM then answers an unknown EID with
eidNotFound.

### 6.3 Queue operations

```text
QUEUE ENABLE 89049032123451234512345678901235 8988201234567890123 rollback=on
QUEUE LIST-PROFILES 89049032123451234512345678901235 --plan
QUEUE REFRESH 89049032123451234512345678901235
OPS pending
```

Without an EID the operation is queued for the card in the reader. `--plan`
shows what would be queued; `--first`, `--at <time>` and `--retries <n>` set the
position, the earliest serve time and the retry budget. A failed precondition is
printed as a warning and the operation is queued anyway. `PACKAGE-IMPORT
<file|folder> [eid]` queues what a package document stands for.

`LIST-PROFILES` names every member of the ProfileInfo in its tagList
(`tags=all`, the default): without one the eUICC answers a default set without
the Profile Policy Rules, the Profile Owner and the Notification configuration
(GSMA SGP.32 v1.3 §2.11.1.1). The members are those of the SGP.32 version the
eUICC declares in EUICCInfo2 (iotVersion): §4.4 of v1.2 ends at
fallbackAllowed and v1.3 adds iotSpecificProfileInfo, which a card of v1.2 is
therefore not asked for; an eUICC whose EUICCInfo2 the record lacks gets the
v1.2 members (`IPA-DATA` reads it). The SGP.22 v3 tags an IoT eUICC holds none
of (RPM, LPA proxy, enterprise and Device Change configuration, service
description, eSIM port, Profile size) are not asked for; `tags=` with hex
names asks for a set of your own, and `tags=default` sends no tagList
(`BF2D00`), for the eUICC's own default set. A member outside section 4.4 in
an answer shows as a row of its own.

A card may refuse a tagList: one of SGP.32 v1.2 answered the v1.3 list with
incorrectInputValues. When the list the eIM chose is refused that way, the
operation ends as ERROR, the eIM queues the same list again without a tagList
(an operation of its own, served next) and the eUICC's record keeps the
refusal: from then on `LIST-PROFILES` without `tags` goes without a tagList at
once, and `--plan` and the operation view say so. `tags=all` sends the full
list whatever the card answered before, is not repeated when refused, and
clears the entry when the card accepts it. A tagList given in hex goes as
written and is never repeated, and a refused list that had `iccid=` beside it
is repeated but not kept, since the refusal does not say which of the two the
card objected to. `IPA-DATA` asks for
every IPA and eUICC data item but the Notifications `A0` and the stored eUICC
Package Results `A2`; `tags=all` asks for all eleven of SGP.32 v1.3 §2.11.1.2.
The eIM acknowledges both lists and the eUICC then deletes what was listed,
the Notifications going on to their SM-DP+ (section 6.5.1).

A queued operation stays editable until it is served:

```text
EDIT 3 iccid=8988201234567890123 at=2026-11-06T08:00Z
MOVE 3 first
CANCEL 4
COPY 2
```

`COPY` queues a copy of any operation, finished ones included, as the retry of
an operator portal.

### 6.4 Run the queue

- `SERVE start` runs the ESipa service in the background; the eSIM Management
  console's `DOWNLOAD` (and any other IPA that resolves the eIM FQDN) then polls
  it like any other eIM, and a profile download trigger runs against the local
  SM-DP+ (`SMDP-PROFILE <matchingId> <profilePath>` names the profile it serves).
  The service takes both function bindings of SGP.32 v1.3 §6: ASN.1 on
  `/gsma/rsp2/asn1` and JSON on `/gsma/rsp2/esipa/<function>` (Table 28; for
  example `getEimPackage`, `provideEimPackageResult`, `initiateAuthentication`),
  with the status codes of the function tables in a failed answer.
- `DELIVER` acts as IPAd on the card in the reader until its queue is empty
  (`--once` serves one operation). The Notifications it reads from the card
  with a result go on to their SM-DP+ once the reader is given back (section
  6.5.1).
- `INJECT` sends the queue to an IPA that listens for it: the eIM makes the
  call, ESipa.TransferEimPackage (section 6.4.5).
- `EXPORT <id>` signs one operation for an IPA outside YggdraSIM;
  `RESULT <id> <hex>` closes it with that IPA's EimPackageResult.

An indirect profile download (SGP.32 v1.3 §3.2.3.2) keeps the Activation Code
here and relays the download through the service:

```text
SMDP-PROFILE MID-1 Workspace/LocalSMDPP/profile/test_profile.txt
QUEUE DOWNLOAD 89049032123451234512345678901235 activation_code=1$smdpp.example.test$MID-1 indirect=on
SERVE start
```

Before each download the eIM asks the polling IPA for its IPA Capabilities,
since that IPA runs the download (a card's IPAe and an IPAd can take turns on
one eUICC, SGP.32 v1.3 §3.8.4), together with whatever the record lacks of
euiccInfo1, euiccInfo2, the eUICC and EUM certificates and DeviceInfo. An IPA
that leaves its capabilities out is treated as declaring none. The IPA
Capabilities decide the trigger. An IPA declaring `eimDownloadDataHandling`
receives a ProfileDownloadTriggerRequest without profileDownloadData, the only
case SGP.32 v1.3 §2.11.1.3 allows; any other IPA receives the Activation Code
and chooses whether to download through the eIM (the plan says which). The
service answers InitiateAuthentication with the Matching ID when the IPA got
no code and builds ctxParams1 itself, or with ctxParams1 for an IPA declaring
`eimCtxParams1Generation`. It relays AuthenticateClient,
GetBoundProfilePackage and CancelSession to the SM-DP+ the code names, checks
serverAddress and the optional SM-DP+ OID, and forwards the
ProfileInstallationResult. That result, which the IPA hands over through
ESipa.HandleNotification, closes the operation once its eUICC signature
verifies (§3.2.3.2 step 23); a ProfileDownloadTriggerResult reports a direct
download only (§2.11.2.3), and one that arrives as well is noted.

An IPA declaring `minimizeEsipaBytes` sends the compact forms of §5.14 and
leaves out what the eIM holds. The service restores the full forms from the
session and the record, checks each against its eUICC signature before it
goes to the SM-DP+, and answers without transactionId and with a truncated CI
Public Key Identifier. The compact AuthenticateServerResponse has no place for
`otherCertsInChain`, the certificates an SGP.22 v3 eUICC sends beyond its EUM
certificate when its chain is not Variant O (SGP.22 v3.1 §4.5.2.0a, §5.7.13);
the service appends the chain it holds for the eUICC, learnt from a full
answer of that eUICC or set with `EUICC SET <eid> other_certs_in_chain=<hex>`,
and refuses the answer when the EUM certificate is not issued by the selected
CI and no chain is on record. When the SM-DP+ requires a Confirmation Code
(`ccRequiredFlag` in smdpSigned2) and the operation carries one
(`QUEUE DOWNLOAD ... confirmation_code=<code>`, or the same line under More
parameters in the GUI), the service hands the IPA its hash in
ESipa.AuthenticateClient (SGP.22 v3.1 §3.1.3.2: SHA256(SHA256(code) |
TransactionID); SGP.32 v1.3 §5.14.3) and restores the compact PrepareDownload
answer with it; without a code the IPA has to supply hashCc itself. The code
is masked in operation listings. For an IPA declaring `eimProfileMetadataVerification`
the service checks the Profile Metadata itself, against the Rules
Authorisation Table and the Profile list on record (asked for with GET-RAT and
LIST-PROFILES before the download when missing): it answers pprNotAllowed when
a PPR is not allowed, keeps the metadata from the IPA and refuses a Bound
Profile Package whose metadata differs. The eSIM Management IPA takes an empty
trigger this way; `YGGDRASIM_IPA_INDIRECT_DOWNLOAD` makes it route an
Activation Code trigger through the eIM too. A download queued with
`contact_smds=on` (and `smds_address=<fqdn>` unless the card's root SM-DS is
on record) is an event retrieval by the eIM (§3.9.2.2): the service runs ES11'
against the SM-DS through the same relay (ES11 is bound as ES9+, SGP.22 v3.1
p.397), closes the operation with the Event Records it got, queues one
indirect download per record at the front of the eUICC's queue with the
EventID as its Matching ID (SGP.22 v3.1 §3.1.3, §3.6.2 step 10; `event_id`
and `smds_oid` on the operation), and answers the IPA with the SM-DS
transactionId and the first download's trigger (§6.3.2.2
authenticateClientOkDSEsipa). The eSIM Management IPA runs the trigger in
that answer; it also takes a contactSmds trigger and retrieves the records
itself (section 6.4.6). The SM-DS can be the service's own (section 6.4.6).

### 6.4.1 A card's own IPAe, and TLS setups

A card whose IPA runs in the eUICC (IPAe) opens its own bearer through the
terminal that drives it, resolves the eIM FQDN and runs TLS with server
authentication to the eIM (SGP.32 v1.3 §2.6.3.2). `SERVE start` brings up a
card-facing TLS listener for that next to the plain one (`tls_port`, the next
port by default; `tls_port=off` leaves it out). A terminal that carries the
card's channels on this machine can send the card's lookup of the eIM FQDN and
its session to that listener; the card then authenticates the chain the
listener serves against the trustedPublicKeyDataTls its last AddInitialEim
carried (§2.11.1.1.1).

`TLS-SETUP` builds the chain and decides what the card trusts:

```text
TLS-SETUP NEW ca-chain chain=intermediate trust=root --apply
TLS-SETUP NEW pinned-key trust=leaf_key --use
TLS-SETUP NEW no-ski chain=root trust=root ski=off
TLS-SETUP
TLS-SETUP SHOW ca-chain
TLS-SETUP USE identity --associate
```

| Option | Values | Default |
|---|---|---|
| `chain` | `self` (self-signed leaf), `root` (root CA, leaf), `intermediate` (root, intermediate, leaf) | `self` |
| `trust` | what AddInitialEim carries: `leaf` (trustedCertificateTls, the leaf), `leaf_key` (trustedEimPkTls), `root`, `intermediate`, `none` (member left out) | `leaf` |
| `curve` | `p256`, `p384`, `brainpoolp256r1`, `ed25519` (§2.6.3.2: P-256 required, the others optional) | `p256` |
| `send` | what the listener sends: `leaf`, `chain` (leaf and intermediate), `full` (and the root) | `chain` |
| `san` | the leaf's DNS name: empty for the eIM FQDN, `none` for no SubjectAltName, or another name | empty |
| `validity` | the leaf: `valid`, `expired`, `not_yet_valid` | `valid` |
| `ski`, `ca_basic_constraints`, `server_auth` | `on` / `off`: SubjectKeyIdentifier, the CA certificates' BasicConstraints cA, the leaf's serverAuth EKU | `on` |
| `versions` | `1.2+`, `1.2`, `1.3` | `1.2+` |
| `ciphers` | an OpenSSL TLS 1.2 cipher list | OpenSSL's default |
| `fqdn` | the eIM FQDN this setup stands for: AddInitialEim carries it as eimFqdn, the leaf is issued for it, the service and the IPAe route answer it next to the identity's | the identity's |
| `layout`, `ca_layout` | a stored certificate (AddInitialEim builder store) or a certificate file whose subject attributes, extension set, criticality and order, serial length and signature hash the leaf (`layout`) and the CA members (`ca_layout`) take; a CA certificate given as `layout` shapes the CA members. Keys, SubjectKeyIdentifier and AuthorityKeyIdentifier are fresh, a DNS name becomes the setup's FQDN, a registeredID the Local eIM's eimId; a CN that names the reference's host follows, any other CN is kept | the generic shape |
| `registered_id` | `auto`: a shaped leaf carries the Local eIM's eimId as a registeredID where the reference had one, a generic leaf none; `on`: the eimId next to the DNS name; `off`: a DNS-only SubjectAltName (an EUM's practice) | `auto` |
| `cn` | the shaped leaf's CN: `auto` (the reference's, unless it names the reference's host), `host` (the setup's FQDN, or `san` when given), `keep` (the reference's CN as it is); for any leaf, shaped or generic, `eim_id` (the Local eIM's eimId, so that only the SubjectAltName names the host). A card that checks the host against the CN rather than the SubjectAltName takes `host` or a wildcard `san` and refuses a product-name CN with a TLS `bad_certificate` alert | `auto` |
| `client_auth` | `none` (server authentication only, as §2.6.3.2 asks), `optional` (a client certificate is asked for; a client without one is served), `required` (mutual TLS: a client without a certificate under `client_ca` is refused) | `none` |
| `client_ca` | the CA certificates client certificates chain to: stored names or files, comma separated | the setup's own CA |
| `sni` | `any`, or `required`: only a ClientHello whose server_name (RFC 6066 §3) is the leaf's host is answered | `any` |

`TLS-SETUP CLIENT-CERT <name> [cn=<text>]` issues a TLS client certificate
under the setup's own CA (`client.pem` and `client_key.pem` in the setup
folder); a client that presents it passes `client_auth=required` with the
default `client_ca`. `TLS-SETUP SHOW` names the layout references, the client
CA and the client certificate.

The service serves every setup at once. The setups that authenticate the
server only share the card TLS port: the setup in use is the default (a client
that names no host, and what a new card is associated with), and a ClientHello
naming another setup's FQDN or leaf name (a wildcard leaf name matches one
label) gets that setup's chain and server-name rule. A setup with
`client_auth` other than `none` listens on a port of its own, because the
verify mode belongs to the listening context; the IPAe route sends a card to
the port its name maps to. `SERVE status` lists the listeners, the setups and
the names served; the resolver of the IPAe route answers all of them.

Every request a listener answers is recorded with the chain the server name
picked, and an IPAe terminal's trace prints it as an `eIM:` line where its answer
arrives (section 12.1); `EIM-SETTINGS tls_keylog=on` writes the session
secrets for Wireshark (section 12.2).

`ski=off`, `ca_basic_constraints=off`, `server_auth=off`, a `validity` other
than `valid` and a `san` naming another host break a rule on purpose:
§2.11.1.1.1 asks for a SubjectKeyIdentifier on the trusted certificate and cA
TRUE on a CA certificate, and a TLS client checks that the leaf is valid and
names the host it asked for. A setup is
built and kept in the store (`tls_setups/<name>/`, keys at mode 0600; at most
64). `--use` (or `TLS-SETUP USE <name>`) makes the listener serve it and
restarts a running service on the same ports; `--apply` (or `USE ...
--associate`) also runs `ASSOCIATE`, so the card is told to trust it.
`TLS-SETUP USE identity` goes back to the identity's own TLS certificate.

The card trusts whatever its last AddInitialEim carried: after `IDENTITY NEW`
or a change of setup, run `ASSOCIATE` again. The listener binds to the
service's host (`127.0.0.1` by default), so the terminal carrying the card's
channels has to run on the same machine. A direct profile download by the IPAe
is not served there (the listener presents the eIM's certificate): it goes to
the SM-DP+ listener of section 6.4.2. An indirect download runs over the same
ESipa session. The GUI has the same actions in the "eIM configuration" tab of
the Local eIM.

### 6.4.2 A direct download by a card's own IPAe

A profile download trigger queued without `indirect=on` carries the Activation
Code to the card, and its IPAe then calls the SM-DP+ itself (GSMA SGP.32 v1.3
§5.6): it resolves the SM-DP+ address, opens a TLS session with server
authentication and posts each ES9+ function in the ASN.1 binding, a
RemoteProfileProvisioningRequest to `/gsma/rsp2/asn1` (GSMA SGP.22 v3.1 §6,
§6.6.1). `SERVE start` brings up a second card-facing listener for that, the
local SM-DP+'s own (`smdp_tls_port`, two ports above the service port by
default; `smdp_tls_port=off` leaves it out):

```text
SMDP-PROFILE MID-1 Workspace/LocalEIM/profile/test_profile.txt
SERVE start
QUEUE DOWNLOAD 1$smdpp.example.test$MID-1
SERVE status
```

`SERVE status` names the listener, the host name it answers for (the local
SM-DP+ address of the session) and the certificate it serves. The card
authenticates that certificate against an eSIM CA it holds, not against
anything AddInitialEim carried, so the listener serves a CERT.DP.TLS under the
SGP.26 test CI that issued the CERT.DPauth in use (SGP.22 v3.1 §4.5.2.1.0.5).
The first of these that exists is served:

1. `smdp_tls/chain.pem` and `smdp_tls/key.pem` in the engine store with no
   `issued.json` beside them: a chain and its key you put there yourself;
2. the CERT.DP.TLS of the SGP.26 bundle, when it names the SM-DP+ host and is
   valid today;
3. a certificate issued for the host with the bundle's private key of that
   test CI (or of the SM-DP+ SubCA, whose certificate is then sent after it),
   kept in `smdp_tls/` and issued again when the SM-DP+ address or the
   CERT.DPauth in use changes or its year of validity runs out.

Only an eUICC that carries that test CI completes the TLS session and the
authentication that follows; a card with another CI refuses both, as it
refuses every other use of the local SM-DP+. The listener serves the chain to
the eSIM CA whatever server name the client sends. A terminal that routes the
card here answers the "rsp3-" name a v3 device tries first as not existing,
which sends the card on to the base name (SGP.22 v3.1 §2.6.6.2).

The ASN.1 binding answers InitiateAuthentication, AuthenticateClient (with the
Profile Metadata of the profile the Matching ID selects),
GetBoundProfilePackage, CancelSession and HandleNotification. A transactionId
the SM-DP+ did not hand out is answered invalidTransactionId, any other
failure undefinedError(127) with the cause in the service log (`SERVE status`
names the file). The plain loopback listener answers the same binding, and the
JSON binding on `/gsma/rsp2/es9plus/*` is unchanged. Not covered by the
SM-DP+: a Confirmation Code, RPM and Device Change. An Event Retrieval on the
same paths is answered by the local SM-DS (section 6.4.6).

The local SM-DP+ answers for its own address only: an InitiateAuthentication
that names another is refused with invalidDpAddress (8.8.1 / 3.8 in the JSON
binding, GSMA SGP.22 v3.1 §5.6.1), since serverSigned1 carries the address it
is signed for. Some IPAe implementations run a direct download over their
connection to the eIM's own address while naming the Activation Code's
SM-DP+ in smdpAddress. The eIM's card listener passes such a session through
to that SM-DP+ as it came, over HTTPS in the ASN.1 binding (the server
certificate checked as for any ES9+ call), when a download trigger it served
and still has open names that address; the later steps follow their
transactionId, each step is noted on the trigger's timeline, and a
ProfileInstallationResult the SM-DP+ does not take goes to the eIM's
Notifications (section 6.5.1). An address that no served trigger names is
refused the same way.

### 6.4.3 Finding the certificate a card accepts

A card judges the eIM's server certificate by rules its vendor chose: which
subject attribute or SubjectAltName entry has to name the host, whether a
registeredID carries the eimId, which key and signature it takes, how much of
the chain it wants sent. Each attempt is one leaf, and a leaf is cheap while
the CA above it stays: trustedCertificateTls may be the certificate of the root
CA or of an intermediate CA instead of the eIM's own (SGP.32 v1.3
§2.11.1.1.1), and a card that was given one of those (`trust=root`,
`trust=intermediate`) checks every leaf that CA signs. The next attempt then
needs no AddInitialEim and no reset of the card's eIM configuration.

`TLS-SETUP LEAF` issues further leaves under a setup's own CA and puts one of
them on the setup's name:

```text
TLS-SETUP NEW ca-chain chain=intermediate trust=root fqdn=eim5.yggdrasim.local --apply
TLS-SETUP LEAF ca-chain NEW cn-eimid cn=eim_id registered_id=on
TLS-SETUP LEAF ca-chain NEW no-ski ski=off --use
TLS-SETUP LEAF ca-chain
TLS-SETUP LEAF ca-chain SHOW cn-eimid
TLS-SETUP LEAF ca-chain USE cn-eimid
TLS-SETUP LEAF ca-chain USE built
TLS-SETUP LEAF ca-chain REMOVE no-ski
```

A leaf takes the options of the table in section 6.4.1 that belong to a leaf:
`cn`, `san`, `registered_id`, `layout` (`layout=none` for the generic shape),
`validity`, `ski`, `server_auth`, `curve` and `send`. An option left out is
the setup's own. The chain, the trust, the TLS versions, the ciphers, the
client authentication and the server-name rule belong to the setup; a variant
of one of those is another setup, under a name of its own. The leaf a setup
was built with stays available as `built`. A setup keeps at most 32 leaves,
under `tls_setups/<name>/leaves/<leaf>/` (keys at mode 0600), and a setup
built before leaves existed needs no conversion.

`USE` copies the leaf, its key and what is sent with it onto the setup's name
and restarts a running service on the same ports. A setup with `trust=leaf`
or `trust=leaf_key` told the card to trust the leaf itself, so there `USE`
(and `NEW ... --use`, before it issues anything) asks which is meant:

- `--associate` serves the leaf and runs `ASSOCIATE`: the card's eIM
  configuration is reset and AddInitialEim carries the new leaf.
- `--serve-only` serves the leaf and leaves the card as it is. That is the way
  to watch a card refuse a leaf it was not given, and the second half of a
  change without a reset: `LEAF <name> SHOW <leaf> --der` prints the leaf's
  certificate and public key in hex, `QUEUE UPDATE-EIM <eimId>
  tls_certificate=<hex>` carries either to the card as
  trustedPublicKeyDataTls (updateEim, SGP.32 v1.3 §2.11.1.1.2), and once
  that operation is delivered the swap follows.

`TLS-SETUP NEW <name> --replace` and `TLS-SETUP REMOVE <name>` take the
setup's CA with them. While the setup has further leaves, or cards associated
under it, both refuse without `--force`.

Every handshake on a card-facing listener is recorded: the server name the
client asked for, the setup that name picked, the SHA-256 of the leaf that
was served, and how it ended.

| Outcome | Meaning |
|---|---|
| `completed` | the handshake finished; the record says whether the session was resumed and how many requests followed on the connection |
| `refused` | the client sent a fatal alert, named in the record (`unknown_ca`, `bad_certificate`, `certificate_expired`, `certificate_unknown`, ...; RFC 8446 §6.2) |
| `failed` | this side ended it: no shared cipher suite for the leaf's key, no client certificate under mutual TLS, a server name the Local eIM does not answer for |
| `lost` | the connection closed or stalled before the handshake finished, without an alert |

A row belongs to a leaf from the moment the ClientHello's server name has
picked a chain. A connection that ended before that (a port probe, something
that is not TLS), or on a name this side refuses, was offered no leaf and is
listed under none.

`TLS-SETUP RESULTS` counts them per leaf served:

```text
TLS-SETUP RESULTS ca-chain
TLS-SETUP RESULTS ca-chain --rows n=20
TLS-SETUP RESULTS --json
```

A leaf counts as accepted when a full handshake completed and a request
followed on its connection; a completed handshake that nothing followed is
listed apart. A resumed session says nothing about a leaf, because the server
sends no Certificate in it (RFC 5246 §7.3, RFC 8446 §2.2), so resumptions are
counted on their own and decide no verdict. Every `USE` restarts the service,
which drops the sessions it could resume: the first handshake after a swap is
a full one. A card that closes its channel instead of sending an alert shows
as `lost`. `--rows` lists the handshakes themselves, `--json` gives both for a
script. The exchange records of section 12.1 carry the same fingerprint, and
the store keeps the newest 2000 handshakes.

The GUI has New leaf, Leaves, Show leaf, Use leaf, Remove leaf and TLS results
in the "eIM configuration" tab; the TLS certificates section of the Local eIM
page opens New leaf and runs TLS results.

### 6.4.4 Writing a leaf's subject and extensions

The options of section 6.4.3 shape a leaf by a handful of switches, or after a
reference certificate. A leaf can also be written out: its subject and its
extensions as text, one line each, built exactly as written. What the text
leaves out, the subject or the extensions, still follows the options.

```text
subject = CN={host},OU=Lab,O=Example Org,C=XX
keyUsage = critical, digitalSignature
extKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:{host}, DNS:eim9.yggdrasim.local, RID:{eim_id}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
2.999.7.1 = DER:0403010203
```

| Line | Value |
|---|---|
| `subject` | an RFC 4514 name, as the tool prints one: no space around `,`, `+` or `=`, a `,` inside a value written `\,`; `none` for an empty name. Each attribute gets its usual string type (PrintableString for C, UTF8String for most) |
| `rdn` | one relative distinguished name per line, in certificate order, each attribute as `type:string type:value` and several joined with ` + `, for a subject whose string types matter: `rdn = CN:IA5String:{host}`. A value that holds ` + `, or octets, is written `hex:<hex>` |
| `basicConstraints` | `CA:TRUE` or `CA:FALSE`, then `pathlen:<n>` (RFC 5280 §4.2.1.9) |
| `keyUsage` | the bits by name: digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly (RFC 5280 §4.2.1.3) |
| `extKeyUsage` | serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, anyExtendedKeyUsage, or object identifiers (RFC 5280 §4.2.1.12); `extendedKeyUsage` is read as the same line |
| `subjectAltName`, `issuerAltName` | names (RFC 5280 §4.2.1.6): `DNS:`, `IP:`, `URI:`, `email:`, `RID:<object identifier>`, `DirName:<RFC 4514 name>`, `otherName:<object identifier>:<hex of its value>` |
| `subjectKeyIdentifier` | `hash`, computed from the leaf's key, or its octets in hex |
| `authorityKeyIdentifier` | `keyid`, computed from the issuer's key, or its octets in hex |
| `certificatePolicies` | object identifiers, or `anyPolicy` |
| `cRLDistributionPoints`, `freshestCRL` | names, one distribution point each: `URI:http://crl.example.test/ca.crl` |
| `authorityInfoAccess`, `subjectInfoAccess` | `<method>:<name>` with the methods ocsp, caIssuers, timeStamping, caRepository: `ocsp:URI:http://ocsp.example.test` |
| any extension | `<name or object identifier> = DER:<hex of its value>`, or `DER:empty` for a value without octets. It is the only form for policyMappings, subjectDirectoryAttributes, nameConstraints, policyConstraints and inhibitAnyPolicy, and for an extension RFC 5280 does not define |

`critical,` before a value marks the extension critical. The leaf carries the
extensions in the order of the lines, and `extensions = none` writes a leaf
without any. `{host}` is the setup's eIM FQDN and `{eim_id}` the Local eIM's
eimId; a placeholder that has no value, or an eimId that is not an object
identifier under `RID:`, is refused when the leaf is issued. A line that does
not read is refused with its line named, never skipped.

On a shell line the subject is one option and each extension one more, in
order. No value uses `;`, which a batch line splits commands on.

```text
TLS-SETUP LEAF ca-chain NEW two-names ext.keyUsage=critical,digitalSignature ext.subjectAltName=DNS:{host},DNS:eim9.yggdrasim.local,RID:{eim_id}
TLS-SETUP LEAF ca-chain NEW own-subject subject="CN={host},OU=Lab,O=Example Org,C=XX"
TLS-SETUP LEAF ca-chain NEW bare subject=none extensions=none
TLS-SETUP LEAF ca-chain TEXT built
TLS-SETUP LEAF ca-chain TEXT built out=leaf.txt
TLS-SETUP LEAF ca-chain NEW edited text=leaf.txt
TLS-SETUP TEXT OTHER-EIM-TLS
```

`LEAF <name> TEXT <leaf>` prints a leaf in this form and `TLS-SETUP TEXT`
any stored certificate or certificate file; `out=<file>` writes the text to a
new file (never over an existing one) and `text=<file>` issues from it, so a
leaf is changed by decoding it, editing a line and issuing the result. A file
named as `text=` that is no certificate text is refused by its line number
alone; nothing of it is shown. An option that shapes the same part as the text
is refused: `cn` beside a written subject, and `san`, `registered_id`, `ski`
or `server_auth` beside written extensions.

Decoding loses nothing. A value is printed in its line form only when that
form reads back to the certificate's own octets, and as `DER:` otherwise (a
policy with a qualifier, an authority key identifier by issuer and serial, a
name constraint). Each extension is read on its own, so one value without a
line form does not cost the others theirs. A key identifier that is the one computed from the key is
printed `hash` or `keyid`, so the text suits a new key. A leaf issued from
text is read back before it is kept: its subject and its extensions have to
be the octets the text gives, in the same order.

The text is taken as written. The upper bounds RFC 5280 Appendix A gives the
attributes (a common name of 64 characters, a country of two letters) are not
applied to an `rdn` line, and a value given as DER is not looked into. Not
written this way: the validity dates, the serial number and the signature
hash, which the leaf's options and its layout decide; the CA members of a
setup; and certificates that are malformed on purpose.

In the GUI, New leaf has a Certificate text field and Certificate text prints
a leaf or a stored certificate; no GUI action opens a file for the text. The Leaf editor on the Local eIM page (eIM
configuration, TLS certificates: Leaf editor, or Edit a copy of this leaf
under a served chain) shows the same text as rows: one row per subject
attribute with its type, string type and value, and one block per extension
with the controls its value takes (boxes for the key usage bits, a row per
name, a hex field for DER). Rows are added, removed and moved; Check turns
them into the text, Edit as text takes the text back into rows, and Issue
leaf issues it under the chosen setup. A leaf opened in the editor and issued
unchanged is the same text again.

### 6.4.5 Injection: the eIM calls the IPA

SGP.32 v1.3 §3.1.1 gives two ways for an eIM Package to reach the IPA.
With retrieval the IPA fetches it (ESipa.GetEimPackage; `SERVE` and the
sections above). With injection the eIM sends it: ESipa.TransferEimPackage
(§3.1.1.2, §5.14.4), one eIM Package per call, the eIM Package Result in the
answer. `INJECT` is that call, and the eSIM Management console's `EIM-LISTEN`
is an IPAd that takes it.

```text
eSIM Management console (holds the card)      Local eIM shell (no reader)
----------------------------------------      ---------------------------
EIM-LISTEN                                     QUEUE ENABLE <eid> <iccid>
  listening on http://127.0.0.1:8746           INJECT <eid> target=http://127.0.0.1:8746
  for EID <eid>                                  [+] operation 12: enableResult: ok (0)
  ... Ctrl-C stops                             INJECT          (target kept; --once for one package)
```

`EIM-LISTEN [port=<n>] [calls=<n>] [idle=<seconds>]
[notifications=deliver|keep]` connects to the card,
prints its EID with the `INJECT` line to use, and answers calls until Ctrl-C,
after `calls` calls, or after `idle` seconds without one; the listener is up
only while the verb runs. The verb holds the reader for as long as it runs:
another YggdraSIM process that asks for that reader is told at once that it
is busy. Its HTTPS options are described further down.
`INJECT [<eid>] [target=http://127.0.0.1:<port>|https://<address>:<port>|none]
[binding=asn1|json] [timeout=<seconds>] [--once]` keeps the target on the
eUICC's record
(`EUICC <eid>` shows it, `target=none` clears it), so a later `INJECT` needs
no argument while one eUICC has a target. It opens no reader: the IPA holds
the card. The `asn1` binding posts to `/gsma/rsp2/asn1`, the `json` binding to
`/gsma/rsp2/esipa/transferEimPackage` (§6.1.1, §6.4.1 Table 28, §6.4.1.4).
In the GUI the same verb is Inject to IPA on the Local eIM's Operations tab
(EID, Inject target, Binding, One package only), and the listener is Listen
for injected eIM packages in eSIM Management, tab SGP.32 IoT (IPA-d): Reader,
Port, Notifications, and optional limits on calls and idle seconds. It holds
the reader until Cancel, the page is closed or a limit ends it, and it
listens on the loopback over plain HTTP; the HTTPS form further down is
started from a terminal. While it runs its form stays with the action: the
action's button carries a dot, and opening the action or entering eSIM
Management again shows the output so far and Cancel.

While a listener holds a reader, whatever would open that reader is refused
with "reader busy" and the name of the holder: Deliver, Read card into
record, the eSIM Management overview, and Queue operation or Import package
document with no EID given. With an EID they need no card and run; an EID
field that does not read as one (32 digits) is refused there and is never
looked up on the card. In the
shell a verb without an EID reads the card as before, but behind the reader
lock; when the reader is held or no card answers, `QUEUE` and
`PACKAGE-IMPORT` take the one eUICC that has an inject target and say so. A
card that can be read always comes first.

Per eIM Package the IPA does what §5.14.4 lists. A signed eUICC Package goes
to the ISD-R (ES10b.LoadEuiccPackage) and its EuiccPackageResult comes back
in the answer; a request for IPA and eUICC data is answered with
IpaEuiccDataResponse. What the eIM acknowledges travels as an
EimAcknowledgements package in the next call (§3.3.1 step 13): the IPA
removes each sequence number from the eUICC and answers
eimPackageReceivedWithCid. An error is eimPackageErrorWithCid with the
package's eimTransactionId, or the EID when it has none. The injecting eIM
has no reader, so the eUICC certificate it verifies results with is asked for
through the IPA before the first signed package, as on the fetch route.

After each injected package the eSIM Management IPA does what it does after
one fetched with `DOWNLOAD`: it lists the card's pending Notifications,
delivers each to the SM-DP+ it names and removes the delivered ones. Before a
first run on a card, `GET-NOTIFICATIONS` in that console shows what is
pending. An empty list means nothing leaves the machine for a package that
changes no Profile state. An enable or a disable creates a Notification of
its own where the Profile asks for one, and the listener delivers it in the
same session (next paragraph). With `notifications=keep` the listener reads
and delivers none: they stay on the eUICC for a later command, and no SM-DP+
is contacted while it runs.

An enable or a disable is completed by the eUICC after the REFRESH, or after
a reset (§3.3.1 steps 8a and 8b), and its Notification is created then. The
console sends no TERMINAL PROFILE, so the card sends it no REFRESH. A
listener that stays up therefore resets the card itself once the result of
such a package went back to the eIM, starts a new card session and then
handles the Notifications as above. A package the card work failed on is
followed by a new card session as well.

**Over HTTPS, for an eIM on another host.** Without TLS the listener binds a
loopback address only. With a certificate of its own and the certificates it
takes an eIM's by, it serves HTTPS on any address:

```text
eSIM Management console                        Local eIM shell
-----------------------                        ---------------
EIM-LISTEN-CERT ipad.example.test 192.0.2.4    INJECT-CERT
  [+] Listener certificate: .../eim-listen-cert.pem   [+] The eIM's client certificate ...: .../eim-cert.pem
EIM-LISTEN host=192.0.2.4 port=8746 \         INJECT <eid> target=https://192.0.2.4:8746
  cert=<pem> key=<pem> client-ca=<pem>
```

- `EIM-LISTEN-CERT <host name or address>... [out=<directory>]` makes the
  listener's certificate: self-signed, on NIST P-256, for the names given.
  It writes `eim-listen-cert.pem` and `eim-listen-key.pem` (mode 0600) and
  never replaces a file. `cert=` and `key=` take any other pair as well.
- `client-ca=<pem>` names what a caller's certificate has to verify against:
  a CA, an intermediate CA or the eIM's certificate itself, the three ways
  §2.6.3.2 gives for trusting the eIM. A client certificate is required;
  a caller without one, with another one, or with one that is not for client
  authentication gets no answer, and the listener prints why. TLS 1.2 is the
  oldest version taken (§2.6.3).
- `host=<address>` is the address to bind; `0.0.0.0` takes every interface.
  Another address than a loopback one is taken only together with the three
  TLS options.
- `INJECT-CERT` makes, once, the client certificate the Local eIM presents
  to such a listener and shows where it is; its file is the `client-ca` on
  the IPA. An `https://` target is refused until it exists. The Local eIM
  does not check the listener's certificate. In the GUI the verb is
  Injection client certificate on the Operations tab.
- The file options of both listener verbs are read from a terminal command
  line only.

§3.1.2.1 has the eIM, and only the eIM, authenticated by the IPA, which is
what the client certificate does here. §2.6.3.2 words the TLS roles the other
way round (the eIM as the TLS server). An eIM that calls with an ordinary
HTTPS client is the TLS client, and this is the form such an eIM can use.
While the HTTPS listener is up the console's IpaCapabilities declare
`ipaInjectHttps` in ipaSupportedProtocols (§4.1).

What a failed call costs depends on whether the request left:

- The target cannot be reached: nothing was served, no counter value was
  taken, the queue is as it was. The connection is opened before the eIM
  signs the package.
- The request left and no answer came back (or one that does not read): the
  operation stays `SENT`. The next `INJECT` first asks the eUICC for its
  stored eUICC Package Results and closes the operation with the one it
  finds; the signed package is not sent a second time. A Profile state
  change is held as in section 6.4.
- The answer names another eUICC (a correlationId with another EID, or an
  eUICC certificate issued to another EID, SGP.22 v3.1 §4.5.2.1.0.2): nothing
  of it is kept and the run stops. The eIM chose the address, so the answer
  is the only thing that says which card is behind it. A certificate that
  names no EID cannot be told apart this way.

`TRAFFIC` lists each call with `inject` in the chain column (`inject TLS`
over HTTPS), decoded like the other exchanges (section 12.1). An injection is
not counted as a poll of the eUICC.

A refused TLS connection counts as a target that cannot be reached. In TLS
1.3 a server judges the client certificate after the client's handshake is
done, so `INJECT` waits up to a second on its first connection for that
verdict before it signs a package.

Limits of this version:

- Without TLS: plain HTTP on the loopback only. Any process on the machine
  can call the listener while it runs: an eUICC Package is executed only
  with the eIM's signature, a request for data or an acknowledgement is not
  signed. A page in a browser on the same machine cannot: the listener takes
  a request only with a Host that is a loopback name, X-Admin-Protocol and
  the binding's Content-Type (the request format of §6.1.1), which a browser
  does not send across origins without a preflight the listener leaves
  unanswered.
- With TLS: the TLS roles are the reverse of §2.6.3.2, as said above, so an
  eIM that insists on being the TLS server cannot call this listener. The
  listener serves one connection at a time. A reachable address is a port
  open to the network for as long as the verb runs: who can connect is
  settled by the firewall, who is answered by `client-ca`. The Local eIM's
  own eimSupportedProtocol still declares retrieval alone (`eimInjectHttps`,
  §4.2, is not set).
- The card reset after an injected enable or disable is always given, also
  to a card that would complete the state change without one. It was
  exercised on the simulated card and on one eUICC in a PC/SC reader.
- No profile download. `INJECT` leaves a download trigger queued (run it with
  `SERVE` and `DOWNLOAD`), and `EIM-LISTEN` answers an injected
  ProfileDownloadTriggerRequest with undefinedError: §5.14.4 has the IPA
  acknowledge the trigger and report the download in a call of its own,
  which the listener does not start.
- Device-side functions (section 11.4) stay with `DELIVER`.
- When the answer cannot be written back, `EIM-LISTEN` leaves the result on
  the eUICC for the eIM's next read; the ES10b.ProfileRollback that §5.14.4
  recommends for that case is not called.
- CoAP (§6.2) is not built, and a card's own IPAe is not reached this way.

### 6.4.6 The local SM-DS

The service runs an SM-DS of its own beside the SM-DP+. An Event Record on
file for an eUICC is what an Event Retrieval finds (GSMA SGP.22 v3.1 §3.6),
and the EventID it carries is the Matching ID of the download that follows at
the RSP Server the record names. `SMDS` shows the SM-DS, its certificates and
its records; no `SMDS` verb opens a reader.

```text
SMDS
SMDS REGISTER 89049032123451234512345678901235 MID-1
SMDS LIST 89049032123451234512345678901235
SERVE start
QUEUE DOWNLOAD 89049032123451234512345678901235 contact_smds=on indirect=on smds_address=smds.example.test
```

`SMDS REGISTER <eid> [<eventId>] [rsp=<address>] [type=download|rpm]` puts a
record on file the way an SM-DP+ does with ES12.RegisterEvent (§5.9.1): the
EID, the EventID, the RSP Server address (the local SM-DP+ without `rsp=`) and
the event type. An EventID is unique within the server that registered it, and
without one the verb makes one up; the local SM-DP+ serves its configured
profile for a Matching ID that `SMDP-PROFILE` does not name. `SMDS DELETE
<eid> <eventId>` takes a record off (ES12.DeleteEvent, §5.9.2). The local
SM-DP+ deletes a record itself when the download it led to ends: on the
ProfileInstallationResult (§3.1.3.3 step 10), and on a CancelSession for any
reason but postponed or timeout (§3.0.2).

An Event Retrieval is ES11 (§5.8): InitiateAuthentication with the SM-DS
address, then AuthenticateClient. ES11 has no path of its own, so the service
answers it where it answers ES9+: the JSON binding on
`/gsma/rsp2/es9plus/initiateAuthentication` and `.../authenticateClient`
(§6.5.2 Table 57), the ASN.1 binding as a RemoteProfileProvisioningRequest on
`/gsma/rsp2/asn1` (§6.6.2.6, §6.6.2.7). A request is the SM-DS's when its
InitiateAuthentication names the SM-DS address, or when its transactionId is
one the SM-DS handed out; every other request stays with the SM-DP+. The
SM-DS verifies the eUICC certificate chain up to an eSIM CA of the SGP.26
bundle, the EID against the EINs the EUM certificate permits, euiccSignature1
and the serverChallenge (§5.8.2), and answers the records of that EID in the
order they were registered. An EventID in ctxParams1 asks for that one
record; none on file is answered Event Record - Unknown.

A card gets there in one of three ways:

- **The eIM retrieves the events** (GSMA SGP.32 v1.3 §3.9.2.2): `QUEUE
  DOWNLOAD <eid> contact_smds=on indirect=on smds_address=<SM-DS address>`.
  The relay of section 6.4 reaches the SM-DS in process, queues one download
  per record and hands the IPA the first one's trigger with its answer.
  `EIM-DOWNLOAD` in the eSIM Management shell (Run the download (IPAd) on the
  Local eIM page) is such an IPA: it runs the trigger in the answer and takes
  the further downloads from the queue in the same poll. Each download is an
  operation of its own with its own result.
- **The IPA retrieves the events itself** (§3.9.2.1, the LPA's part of GSMA
  SGP.22 v3.1 §3.6.2): the same line without `indirect`. The eSIM Management
  IPA asks the SM-DS over ES11 and downloads each record in the order
  received, with the EventID as Matching ID, until one installs no Profile. A
  YggdraSIM process that resolves the SM-DS address is sent to the service's
  loopback URL, as it is for the eIM FQDN and the SM-DP+ address. The
  operation has one result (ProfileDownloadTriggerResult, SGP.32 v1.3
  §2.11.2.3): the last download tried, and a download error when the SM-DS
  held no record for the eUICC. `YGGDRASIM_IPA_INDIRECT_DOWNLOAD=1` makes the
  IPA go through the eIM for this trigger too.
- **The card's own IPAe retrieves them** (§3.9.2.1): `SERVE start` brings up
  a third card-facing listener for that (`smds_tls_port`, four ports above the
  service port by default, since the port in between is the default of
  `EIM-LISTEN`; `smds_tls_port=off` leaves it out). It serves a CERT.DS.TLS
  (SGP.22 v3.1 §4.5.2.1.0.7) chosen the way section 6.4.2 describes for the
  SM-DP+: a chain and key of your own in `smds_tls/`, else the bundle's
  certificate when it names the host, else one issued for the host under the
  test CI of the CERT.DSauth.SIG in use. A terminal that routes the card here
  answers the "rsp3-" name of the SM-DS as not existing (§2.6.6.2).

`SMDS ADDRESS <fqdn>` sets the name the SM-DS answers under (the setting
`smds_address`, `smds.example.test` until changed) and restarts a running
service, so every process finds it under the new name. It refuses the address
of the local SM-DP+ and a Local eIM name: the two servers share their paths,
so one name can stand for one of them only. Should they come to share a name
anyway, the SM-DP+ keeps it, the SM-DS answers nothing and `SMDS` says so.

What it is and is not:

- The certificates are the Variant O CERT.DSauth.SIG pairs of the SGP.26 test
  bundle. Only an eUICC that trusts the SGP.26 test eSIM CA accepts the
  SM-DS; a card under a live eSIM CA refuses the session.
- It answers at the level of SGP.22 version 2: serverSigned1 carries no
  serverRspCapability and the Event Records come back unsigned (§3.6.2 step
  8). Signed Event Records, Event Checking (ES11.CheckEvent is answered Event
  Checking - Unsupported), the Push Service, the chain variants other than O
  and CRL stapling are not built.
- It is a Root SM-DS without cascade. ES12 and ES15 are not served over HTTP:
  an Event Record is registered by you or deleted by the local SM-DP+, in
  process.
- Of a eUICC certificate chain it verifies the signatures, the validity
  periods, the role and key usage a certificate declares and the EID against
  the permitted EINs. No revocation status is checked.
- `DELIVER` runs no download: a retrieval is run by `EIM-DOWNLOAD` in the
  eSIM Management shell, by a card's own IPAe or by another IPA that polls
  the service.
- The eSIM Management IPA follows no cascade (a record that leads to another
  SM-DS ends its run), asks the first Root SM-DS of the eUICC when the trigger
  names no address and leaves further Root SM-DS addresses untried. A trigger
  with neither address is answered invalidPackageFormat.

In the GUI the Operations tab has Local SM-DS, Register SM-DS event and Delete
SM-DS event, the eIM configuration tab has SM-DS address, and the Background
service facts of the page name the SM-DS address and its TLS listener.

### 6.5 Read the results

```text
OPS completed
OP 3
EUICC 89049032123451234512345678901235
```

`OP` prints an operation's parameters, timeline, served package and decoded
result. A result whose signature does not verify against the eUICC certificate
is flagged as unverified; `EIM-SETTINGS result_verification=discard` drops such
results instead. `EIM-SETTINGS` also sets `learn_unknown_eids` (on by
default, section 6.2), `recover_lost_results` and `max_retries` (0 holds an
unanswered operation for the operator). An enable or disable is held whatever
`max_retries` says: its result follows the eUICC's REFRESH (SGP.32 v1.3
§3.3.1 steps 8a-8b) and an IPAe polls again before it can report it, so
serving the package again would run the state change twice. `OP <id>` shows
the hold; `CANCEL <id>` ends it. An IPAe that reports its state as a
GetEimPackageRequest (eidValue, rPLMN) inside ProvideEimPackageResult, which
§5.14.6 does not define, is acknowledged with the empty response; the rPLMN
lands on the record (`EUICC <eid>`), and a notifyStateChange in it queues the
Profile list refresh GetEimPackage would.

### 6.5.1 Notifications go on to their SM-DP+

An IPA hands the eIM the pending Notifications of the eUICC with an eUICC
Package Result (ePRAndNotifications) or with ESipa.HandleNotification. The
Local eIM acknowledges them, so the IPA removes them from the eUICC, and sends
each one to the Notification Receiver its metadata names, the SM-DP+ of the
Profile, with ES9+'.HandleNotification (SGP.32 v1.3 §3.7 step 2b, §5.7.4,
§5.14.6, §5.14.7). Until that server has answered, the Notification stays on
the eUICC's record in the store.

It is sent:

- after `DELIVER` and `INJECT`, once the reader is given back, with a line
  per Notification;
- by the service while it runs: right after its answer to the IPA, and again
  for a receiver that did not answer, 1, 5 and 30 minutes and 2 and 6 hours
  after the attempt before; after the last one the Notification has failed;
- by `NOTIFICATIONS SEND`.

```text
NOTIFICATIONS
NOTIFICATIONS 89049032123451234512345678901235
NOTIFICATIONS SEND
NOTIFICATIONS SEND 89049032123451234512345678901235 7 9
```

`NOTIFICATIONS` lists each one with its sequence number, event, ICCID,
receiver and state: `pending` (the eIM will send it), `delivered`, `failed`
(the receiver refused it, the attempts are used up, or it cannot be sent as
it stands; the line gives the reason, and only `NOTIFICATIONS SEND` with its
sequence number tries it again, once) or `kept` (taken by a version that
forwarded none, or held by one; sent only when named, too). The eIM holds
none back: no rule and no verb keeps a Notification it took from going. It
acknowledges every one it takes, so the eUICC drops them: a card keeps its
Notifications only as long as nothing takes them from it.

What the eIM holds to:

- A Notification goes out only when its eUICC signature verifies under the
  eUICC certificate on the record it arrived for; the address is part of what
  the eUICC signed. ESipa.HandleNotification names no eUICC, so the signature
  also decides whose record a Notification lands on, and one that no record's
  certificate verifies is not taken. On a record without the eUICC
  certificate, or without the EUM certificate a compact one is restored
  with, a Notification waits, pending, until `QUEUE IPA-DATA` or a card read
  has given it, and goes at the next pass; no attempt is counted meanwhile.
  The certificate in an IPA data response that no operation asked for is not
  taken.
- The notificationAddress has to be a host name (SGP.22 v3.1 §5.7.9). The call
  is HTTPS to that host with the server certificate verified, the way the eSIM
  Management IPA calls an SM-DP+. HTTP status 204 says the receiver has the
  Notification (SGP.22 v3.1 §3.5 steps 7b and 10), and another 2XX is read
  the same way; a 4XX is its refusal, and the Notification has failed;
  anything else is tried again.
- A receiver gets its Notifications in sequence number order, one at a time
  (SGP.22 v3.1 §3.5). When two processes send at the same moment, the service
  and a shell, the second leaves the Notification to the first.
- The store's own SM-DP+ takes its Notifications in process. A name under a
  domain reserved for tests and documentation (`.test`, `.example`,
  `.invalid`, `.localhost`, `example.com`, `example.net`, `example.org`; RFC
  2606) or under `.local` is never contacted: the simulator's
  `rsp.example.com` prints as not sent.
- Sent on as well: the Notifications an IPA lists in an IPA data response
  (`QUEUE IPA-DATA` with tag `A0`). That request asks for what the eUICC
  stores (SGP.32 v1.3 §2.11.1.2), and the eIM acknowledges each one it takes
  from the list, so the eUICC drops it. An IPA with its own ES9+ interface,
  the eSIM Management IPAd among them, may deliver the same ones itself, so a
  receiver can get one twice. `IPA-DATA` without `tags=` and `REFRESH` leave
  `A0` out.
- The ProfileInstallationResult of an indirect download goes to its SM-DP+
  inside the download session (section 6.4); when that call fails the result
  joins the list here and is tried again like any other. The one inside a
  ProfileDownloadTriggerResult is not taken: the IPA of a direct download
  delivers it itself (SGP.32 v1.3 §3.2.3.1 steps 12 to 14). A
  compact ProfileInstallationResult outside such a session cannot be restored,
  since only the session has the data: one that came with a result has
  failed at once, and one that came by ESipa.HandleNotification is not taken,
  as nothing says whose it is. The Notifications of an imported result
  (`RESULT`) are sent on like any other; the IPA that left them on the eUICC
  may deliver them as well.
- At most 64 Notifications are kept per eUICC. When one more arrives, a
  delivered one makes room first, then a kept one, then a failed one; a
  pending one goes last.

In the GUI the eUICC's page lists them under Notifications, below the event
log: Send on a failed or kept one takes a second press, and a pending one
that waits for a certificate says which. Notifications and Send
Notifications are actions on the Operations tab.

### 6.6 Add or delete a further eIM

```text
QUEUE ADD-EIM 2.999.1 eim_fqdn=other.example.test certificate=<name or hex>
QUEUE ADD-EIM 89049032123451234512345678901235 config=other-eim
QUEUE ADD-EIM 89049032123451234512345678901235 config=other-eim counter_value=3 association_token=off
QUEUE DELETE-EIM 2.999.1
```

`ADD-EIM` and `DELETE-EIM` are shorthands for the same queue entries. The card
runs them only when the package is signed by one of its associated eIMs.

`config=<name>` names an eIM configuration saved in the AddInitialEim builder:
Offline Tools > AddInitialEim saves one in the GUI, `ADD-INITIAL-EIM` in the
eSIM Management console offers to after a build, and `EIM-CERT-STORE CONFIGS`
there lists them. The operation takes every field from the configuration, the
eimId included, and its eCO (addEim, SGP.32 v1.3 §2.11.1.1.2) carries the
EimConfigurationData that AddInitialEim (§5.9.4) puts on a card for the same
configuration. A
field given beside `config=` wins over the configuration's. The operation
keeps the fields and not the name, so renaming or deleting the configuration
later changes nothing that is queued, and `OP <id>` shows what will be sent.
An unknown name is refused with the saved ones listed.

The result line of an added eIM gives the association token the eUICC
assigned (`addEimResult: associationToken 2`). The eIM signature of every
package covers that value (SGP.32 v1.3 §2.11.1.1), so the added eIM needs it
before its first package for this eUICC. A euiccCiPKId names a key of one
eUICC family: leave it out of a configuration meant for cards of several, or
give `ci_pkid=` on the line.

## 7. Workflow: direct package execution against `ISD-R`

Use `LOAD-EIM-PACKAGE` when a package should be sent directly toward the card,
without queue or relay routing:

```text
LOAD-EIM-PACKAGE Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json
```

This is the fastest way to validate:

- AddInitialEim semantics
- direct `ISD-R` command formatting
- package-to-card decoding and response reporting

Use `EUICC-MEMORY-RESET` only when the test case explicitly requires card-side
reset behavior.

## 8. Workflow: `IPAd` discovery

`IPAD-DISCOVER [packagePath]` runs IPAd discovery against the card, syncs the
pending notifications, and, given a path, selects that eIM package for the next
issue.

### 8.1 Prepare

```text
PATHS
STATUS
IPAD-DISCOVER
```

`PATHS` lists the path families the shell offers and their endpoints.

Before proving a simulated-card loop:

- make sure the simulated card's BF55 view matches the intended eIM by checking `Workspace/SIMCARD/eim_identity.json` or the wrapper `eIM identity` override
- do not assume that changing `Workspace/LocalEIM/eim_identity.json` alone changes what the simulated card advertises

### 8.2 Inspect the result

```text
RESP-LOG 20
HOTFOLDER-LIST --json
```

## 9. Workflow: handover context

The handover context is the eIM transaction reference -- a transaction ID and
an optional `matchingId` -- that the shell holds for the profile download that
follows an eIM exchange.

### 9.1 Seed the context

```text
HANDOVER-SET <transactionIdHex> [matchingId]
HANDOVER-STATUS
```

`HANDOVER-SET` records the reference by hand; `HANDOVER-STATUS` prints it with
the profile path, the notification policy and where the reference came from.

### 9.2 Continue with the linked download

Issue the indirect profile download package (section 10.1). If the context was
lost, seed it again with `HANDOVER-SET`.

## 10. Workflow: indirect and direct profile download packages

### 10.1 Indirect handover

Use `profile_download_trigger_request` when the eIM should hand the eUICC an
activation path toward the local SM-DP+ role.

Typical lint and issue cycle:

```text
EIM-PACKAGE-LINT Workspace/LocalEIM/eim_packages/templates/template_profile_download_trigger_request.json
EIM-PACKAGE-ISSUE Workspace/LocalEIM/eim_packages/templates/template_profile_download_trigger_request.json
```

To have an IPA take the trigger from the queue instead, import it:
`PACKAGE-IMPORT <document> [eid]` queues a `PROFILE_DOWNLOAD_TRIGGER` with the
activation code `1$<SM-DP+ address>$<Matching ID>`.

### 10.2 Direct `BF36` relay

Use `bound_profile_package` or `direct_profile_download` when the eIM should
relay the profile payload itself.

```text
EIM-PACKAGE-LINT Workspace/LocalEIM/eim_packages/templates/template_bound_profile_package.json
EIM-PACKAGE-ISSUE Workspace/LocalEIM/eim_packages/templates/template_bound_profile_package.json
```

Source handling rules:

- if the selected profile source already begins with `BF36`, it is replayed
  directly
- otherwise the shell opens a local SCP11 session, runs `PrepareDownload`, and
  builds a session-bound `BF36`

### 10.3 Result-only serializers

The following families describe result branches only:

- `provide_eim_package_result`
- `eim_package_result`
- `euicc_package_result`
- `profile_download_trigger_result`

`EIM-PACKAGE-EXPLAIN` shows their encoding; `EIM-PACKAGE-ISSUE` refuses them,
since results come from the card (`OP <id>` shows each operation's result).

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

Queue behavior:

- fixed fixtures and hotfolder files are merged into one ordered queue for that
  run
- `HOTFOLDER-FETCH` issues the resolved queue in deterministic order
- PSMO, eCO and IPA eUICC data documents are signed and served by the
  operation queue, so issuing refuses them; `PACKAGE-IMPORT
  Workspace/LocalEIM/eim_packages/hotfolder [eid]` queues every document of the
  folder in the same order

Expected empty-queue result:

- `noEimPackageAvailable(1)`
- wire response `BF4F03020101`

This is expected and is not treated as a failure.

### 11.4 Device-side functions as operations

The three functions an IPAd calls on its own are operations of the queue
(`QUEUE ROLLBACK | EXECUTE-FALLBACK | RETURN-FALLBACK [refresh=off]`, labelled
"(device)"): `ES10b.ProfileRollback` (SGP.32 v1.3 §3.3.2) after an enable with
the rollback flag, `ES10b.ExecuteFallbackMechanism` and `ReturnFromFallback`
around a Profile that carries the Fallback Attribute. `DELIVER` executes them
on the reader, and an IPA polling over ESipa is never served one.

## 12. Logs, traffic, counters, and audit state

### 12.1 The exchanges the service answered (`TRAFFIC`)

The service records every request a listener answers, before it sends the
answer: the time to the millisecond (UTC), the peer's address and port, the
listener port, the TLS setup the ClientHello's server name picked with the
TLS version and cipher, the binding (ESipa ASN.1 or JSON, ES9+ ASN.1 or
JSON), the request and response bodies, the HTTP status, how long it took,
and what the engine made of it (the EID, the operation served or closed, a
note such as `noEimPackageAvailable` or `refused: ...`). A body the listener
would not read (a chunk size that is not hexadecimal, a body past the limit)
is recorded as a refusal with no bodies. The records live in the store
(`traffic` table, the newest 4000 kept) and `server.log` names each one by its
peer port and number.

```text
TRAFFIC                       the last 20, oldest first, decoded
TRAFFIC 50 --brief            one line each
TRAFFIC eid=<eid>             one card's exchanges
TRAFFIC op=504 --hex          the exchanges of one operation, with the bodies
TRAFFIC after=120             continue from an exchange number
```

Each exchange is shown by names and values: GetEimPackageRequest with its
eidValue, notifyStateChange, stateChangeCause and rPLMN; the answer's
EuiccPackageRequest with eimId, counter, transaction id and each PSMO or eCO
by name (`enable ICCID ..., rollback`, `listProfileInfo every Profile`,
`addEim eimId ...`), an IpaEuiccDataRequest's tagList, a download trigger's
Activation Code; ProvideEimPackageResult with the eUICC's result items
(`enableResult: ok (0)`, the Profiles a listProfileInfoResult carries) and
the acknowledgement's seqNumbers; a HandleNotification's PendingNotification;
the error names of SGP.32 v1.3 §6.3.2.6 and §6.3.2.7 when the eIM answered
one. `OP <id>` shows the same rows under the package it served and the result
it got; `OP <id> --decode` adds the Decoder's reading of both, every data
object of the SGP.22 / SGP.32 schema by name and value, a member the eIM does
not keep included. The operation view of the GUI folds the same reading
("Decoder reading") under the rows of the package and the result. The GUI
action is "Traffic" on the Local eIM's eIM configuration tab.

A call the eIM made itself (`INJECT`, section 6.4.5) is recorded in the same
table with the IPA's address as the peer, no listener port and `inject` in
the chain column. It reads TransferEimPackageRequest with its eIM Package and
the answer's result, acknowledgement or error; a call that got no answer
reads `no answer`.

An IPAe terminal that carries the card's channels to this service can print
each exchange in its own trace as an `eIM:` line, between the card's request
and the bytes of the answer, with the decoded rows and both bodies in hex. The
line is the service's record read by the socket's port, so a card in a modem or
on SIMtrace (no such terminal) is read with `TRAFFIC` instead.

### 12.2 TLS key log

`EIM-SETTINGS tls_keylog=on` makes every card-facing listener (the eIM
chains and the SM-DP+ one) append its TLS session secrets to
`tls-keylog.txt` in the store directory, in the NSS key log format Wireshark
reads (mode 0600; the setting is read when the service starts, so `SERVE
restart` applies it, and `SERVE status` names the file). With it a capture of
the card's sessions (a SIMtrace or modem capture of the BIP channel, a
loopback capture of the rig) decrypts in Wireshark, which is the independent
reading of what went over the wire next to the service's own records. It is
off by default; switch it off again and restart when the sessions are not
yours to read.

### 12.3 Legacy response log and counters

Response log file:

- `Workspace/LocalEIM/eim_response_log.jsonl`

Additional audit state:

- response evidence is retained through the JSONL response log

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

- `Workspace/LocalEIM/eim_runtime_state.json` remains as a legacy import source,
  not the primary mutable store

## 13. Troubleshooting

### 13.1 AddInitialEim rejects missing data

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
- the package type: PSMO, eCO and IPA eUICC data documents are queued with
  `PACKAGE-IMPORT`, not issued
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

### 13.4 Pending notifications remain on the card

Run:

```text
NOTIF-HYGIENE 0
```

If that still fails, inspect card state and response logs before issuing more
commands.

## 14. Validation

Focused test command:

```bash
python -m pytest tests/test_eim_local_exchange_and_reset_options.py \
    tests/test_eim_local_ipa_euicc_data_request.py tests/test_scp11_eim_packages.py \
    tests/test_local_eim_engine.py tests/test_local_eim_service.py \
    tests/test_eim_local_engine_shell.py
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

1. verify the Local eIM identity (`IDENTITY`) and `eim_identity.json`
2. confirm eIM and local-access certificate inventories
3. run `STATUS` and `SERVE status`
4. check the card's record and queue (`EUICC <eid>`, `OPS pending`)
5. queue with `--plan` first, then for real
6. read each result with `OP <id>`
7. drain notifications if needed with `NOTIF-HYGIENE 0`
8. export campaign reports when running queues over time

## 16. Related documents

- `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `../../guides/CLI_AND_PIPING_GUIDE.md`
- `README.md`
- `../local_access/README.md`
