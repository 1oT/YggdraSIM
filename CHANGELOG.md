<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Changelog

All notable changes to YggdraSIM are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
honours [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for
the public API surface -- the launcher, the documented CLI shells, the
SCP03 / SCP11 / SCP80 / SIMCARD module entry points, and the
`yggdrasim_common` helpers consumed by external integrators.

Internal helpers (modules under leading-underscore names, undocumented
SAIP wrappers) may change without notice between minor releases.

## [Unreleased]

## [2.3.0] -- 2026-11-20

### Added

- eSIM Management IPA: a profile download trigger with contactSmds starts an
  Event Retrieval where it was refused (GSMA SGP.32 v1.3 §2.11.1.3, §3.9.2).
  The SM-DS is the one the trigger names, else the eUICC's Root SM-DS
  (rootDsAddress); with neither the trigger is answered invalidPackageFormat.
  The IPA asks the SM-DS over ES11 in the LPA's role (GSMA SGP.22 v3.1
  §3.6.2) and downloads each Event Record in the order received, with the
  EventID as Matching ID, until one installs no Profile. The eIM gets one
  ProfileDownloadTriggerResult: the last download tried, or
  profileDownloadError when the SM-DS held no record for the eUICC.
  `YGGDRASIM_IPA_INDIRECT_DOWNLOAD` routes the retrieval through the eIM
  (§3.9.2.2). Not followed: a record that leads to another SM-DS, further
  Root SM-DS addresses and signed Event Records. With the Local eIM, `QUEUE
  DOWNLOAD <eid> contact_smds=on` with or without `indirect=on`, then
  `EIM-DOWNLOAD` in the eSIM Management shell (Run the download (IPAd) on the
  Local eIM page), runs end to end against the local SM-DS.
  A download asked for directly (`FLOW`, `DOWNLOAD-PROFILE`, `--flow`) whose
  server turns out to be an SM-DS fails with the Event Records named, where
  it reported an incomplete AuthenticateClient answer.
- Local eIM: the service runs an SM-DS of its own beside the SM-DP+. `SMDS
  REGISTER <eid> [<eventId>]` puts an Event Record on file for an eUICC
  (ES12.RegisterEvent, GSMA SGP.22 v3.1 §5.9.1), and an Event Retrieval finds
  it: ES11.InitiateAuthentication and AuthenticateClient (§5.8) are answered
  on the ES9+ paths of the JSON binding and in the same 'A2' wrapper of the
  ASN.1 binding (§6.5.2 Table 57, §6.6.2.6), a request being the SM-DS's when
  it names the SM-DS address or a transactionId the SM-DS handed out. The
  SM-DS verifies the eUICC certificate chain, the EID against the EUM's EINs,
  euiccSignature1 and the serverChallenge before it answers the records of
  that EID. A download queued with `contact_smds=on indirect=on` reaches it in
  process (GSMA SGP.32 v1.3 §3.9.2.2), another YggdraSIM process by its name,
  and a card's own IPAe over a new card-facing listener that serves CERT.DS.TLS
  (`SERVE start smds_tls_port=`, four ports above the service port by
  default). The local SM-DP+ deletes a record when the download it led to
  ends (§3.1.3.3 step 10). `SMDS LIST`, `DELETE` and `ADDRESS`, the Command
  Center actions Local SM-DS, Register SM-DS event, Delete SM-DS event and
  SM-DS address, and GUIDE section 6.4.6 cover the rest. The certificates are
  the SGP.26 test ones, so only an eUICC that trusts the SGP.26 test eSIM CA
  accepts it; signed Event Records, Event Checking, the Push Service, ES12
  and ES15 over HTTP and cascade to a root SM-DS are not built.
- Local eIM: Notifications go on to their Notification Receivers. What an IPA
  hands over with an eUICC Package Result or with ESipa.HandleNotification,
  or lists in an IPA data response, is acknowledged, kept on the eUICC's
  record and sent to the SM-DP+ its metadata names with
  ES9+'.HandleNotification (GSMA SGP.32 v1.3 §3.7, §5.7.4, §5.14.6,
  §5.14.7): after `DELIVER` and `INJECT`, by the running service after its
  answer, and again on a schedule for a receiver that did not answer. The
  eIM holds none back: one it cannot deliver (refused, out of attempts, or
  not sendable as it stands) ends as failed with the reason, and one waits
  only for an eUICC or EUM certificate its record lacks. The
  ProfileInstallationResult of an indirect download joins the list when its
  SM-DP+ call fails. `NOTIFICATIONS [<eid>]` lists them, and
  `NOTIFICATIONS SEND [<eid>] [<seqNumber> ...]` sends the pending ones or
  the ones named. A Notification is sent only when its eUICC signature
  verifies under the eUICC certificate on its record and its address is a
  host name; a name reserved for tests is never contacted. The Local eIM
  page lists them per eUICC, below the event log, with Send; the GUI
  actions are Notifications and Send Notifications. A failed one, and one
  kept by an earlier version, goes again only when named.
- Local eIM: an ES9+ session a card's IPAe opens on the eIM's own address
  for another SM-DP+, naming it in InitiateAuthentication, is passed through
  to that SM-DP+ over HTTPS in the ASN.1 binding when a download trigger the
  eIM served and still has open names the address; the later steps follow
  their transactionId and each step is noted on the trigger's timeline. Any
  other address is refused with invalidDpAddress.
- Local eIM: `LIST-PROFILES` asks for every member of the ProfileInfo
  (Profile Policy Rules, Profile Owner, Notification configuration, Fallback
  Attribute among them) instead of the eUICC's default set (`tags=default`
  sends the bare request). The members are those of the SGP.32 version the
  eUICC declares in EUICCInfo2: §4.4 of v1.3 adds iotSpecificProfileInfo to
  the members of v1.2, and a card of v1.2 answered the list of v1.3 with
  incorrectInputValues. A list the eIM chose and the eUICC refused that
  way is asked again without a tagList, and the eUICC's record keeps the
  refusal, so the next list goes without one at once; `tags=all` sends the
  full list again. `IPA-DATA tags=all` asks for every data item of SGP.32 v1.3
  §2.11.1.2, the Notifications and stored eUICC Package Results included.
  `OP <id> --decode` and a "Decoder reading" fold in the GUI's operation view
  show the Decoder's reading of a package and a result, every data object by
  name and value.
- GUI: the eIM section of a Local eIM eUICC page has "Add an eIM (addEim)",
  which opens New operation on Add eIM; before, only "Link this eIM"
  (AddInitialEim after a reset) was offered there.
- GUI: a Local eIM pill in the top bar, beside HIL bridge and Remote, shows
  whether the service runs and starts it with the defaults or stops it with a
  click.
- Local eIM: `ADD-EIM config=<name>` queues an Add eIM operation from an eIM
  configuration saved in the AddInitialEim builder. The eCO carries the entry
  AddInitialEim would put on a card for the same configuration; a field given
  beside `config=` wins, and the operation keeps the fields, not the name.
  The New operation form of the Local eIM page offers the saved names.
- eIM Package Injection between the Local eIM and the eSIM Management IPAd
  (GSMA SGP.32 v1.3 §3.1.1.2, ESipa.TransferEimPackage §5.14.4). `INJECT
  [<eid>] [target=http://127.0.0.1:<port>] [binding=asn1|json] [--once]` in
  the eIM-local shell sends an eUICC's queue to an IPA, one eIM Package per
  call, and takes the eIM Package Result from the answer; what the eIM
  acknowledges goes out as an EimAcknowledgements package in the next call.
  `EIM-LISTEN [port=<n>] [calls=<n>] [idle=<seconds>]` in the eSIM Management
  console is the IPAd that answers, on `127.0.0.1:8746`, in the ASN.1 and the
  JSON binding. An unreachable target costs nothing, a lost answer is
  recovered from the eUICC's stored results before anything new is served,
  and an answer for another eUICC is not kept. `TRAFFIC` lists the calls,
  and the GUI has Inject to IPA on the Local eIM's Operations tab and Listen
  for injected eIM packages in eSIM Management (loopback, plain HTTP; the
  listener's form stays reachable, with Cancel, while it runs). An action or
  verb that would open the reader a listener holds is refused as reader
  busy; queueing for a named eUICC needs no reader, and `QUEUE` without an
  EID then takes the one eUICC that has an inject target.
  `EIM-LISTEN notifications=keep` leaves the card's pending Notifications on
  the eUICC instead of delivering them after each package. Over HTTPS the
  listener binds any address: `EIM-LISTEN host=<address> cert=<pem> key=<pem>
  client-ca=<pem>` takes a call only from a client certificate that verifies
  against `client-ca` (the eIM is the side that is authenticated, SGP.32 v1.3
  §3.1.2.1), `EIM-LISTEN-CERT` makes the listener's certificate, `INJECT-CERT`
  (GUI: Injection client certificate) the one the Local eIM presents, and
  `INJECT` takes `target=https://<address>:<port>`. After an injected enable
  or disable the listener resets the card, so the state change is complete
  while it stays up.
  Limits: without TLS, plain HTTP on the loopback; with TLS the roles are the
  reverse of §2.6.3.2 (the eIM is the TLS client); no profile download, no
  CoAP, no ProfileRollback when an answer cannot be written back.
  `SCP11/shared/esipa_transfer.py` holds the request and response codec for
  both sides, all seven response alternatives included.
- Local eIM: a TLS leaf's subject and extensions can be written out and are
  built as written. `TLS-SETUP LEAF <setup> NEW <leaf>` takes
  `subject=<RFC 4514 name>`, one `ext.<extension>=` per extension in order
  (`keyUsage`, `extKeyUsage`, `subjectAltName` with several names,
  `basicConstraints`, key identifiers, policies, CRL and access locations, or
  any object identifier as `DER:<hex>`), `extensions=none` and
  `text=<file>`; `{host}` and `{eim_id}` stand for the setup's FQDN and the
  eimId. `LEAF <setup> TEXT <leaf>` and `TLS-SETUP TEXT <certificate>` decode
  a leaf or any certificate into the same text without loss: a value keeps
  its octets as DER where the line form cannot carry it, and a leaf issued
  from text is read back against it. `out=<file>` writes the text to a new
  file and `text=<file>` issues from one; only a shell line names a file. The
  GUI has a Certificate text field on New leaf, the action Certificate text,
  and a Leaf editor on the Local eIM page with a row per subject attribute
  and a block per extension.
- `yggdrasim_common/x509_tables.py`: the RFC 5280 extension, key usage, key
  purpose, general name and name attribute tables in one place; the
  certificate views read them, and now name Subject Directory Attributes and
  Subject Information Access.
- Local eIM: a TLS setup takes further leaves under its own CA
  (`TLS-SETUP LEAF <setup> NEW | LIST | SHOW | USE | REMOVE`, GUI actions New
  leaf, Leaves, Show leaf, Use leaf, Remove leaf). A leaf sets the certificate
  options (`cn`, `san`, `registered_id`, `layout`, `validity`, `ski`,
  `server_auth`, `curve`) and what the listener sends with it; the setup's
  name, CA and trust stay, so a card that trusts the root or the intermediate
  (SGP.32 v1.3 §2.11.1.1.1) meets the next leaf without a new AddInitialEim.
  A setup that told the card to trust the leaf itself asks for `--associate`
  or `--serve-only` before it swaps.
- Local eIM: every handshake on a card-facing listener is recorded with the
  server name asked for, the setup picked, the SHA-256 of the leaf served and
  its outcome: completed (resumed or not, requests that followed), refused
  with the client's alert (RFC 8446 §6.2), ended by this side, or lost.
  `TLS-SETUP RESULTS [<setup>] [--rows] [--json]` and the GUI action TLS
  results count them per leaf; exchange records carry the leaf's fingerprint.
  The store keeps the newest 2000 handshakes.
- A user manual: `guides/USER_MANUAL.md` (the modules, installing and
  starting, the concepts the GUI and the CLI share, work on a real card,
  what to do when something fails) with a chapter per surface,
  `guides/USER_MANUAL_GUI.md` and `guides/USER_MANUAL_CLI.md`, the modules
  in sidebar order in both. The GUI's About list and the launcher's Guides
  menu (`U`, `UG`, `UC`) open it, and the docs site lists it under
  Overview.
- `DERIVE-TOPC <TOP> <K> [Keccak iterations]` in the SCP03 shell: the TUAK
  TOPc (3GPP TS 35.231 v19 §6.1), until now reachable only from the GUI's Offline
  Tools. Both run one function, so they take and refuse the same input; the
  MCP shell tool refuses the verb, as it does `DERIVE-OPC`, because K would
  reach a transcript.
- GUI: Advanced, YggdraCore. The 5G core stub's actions (subscriptions, the
  Open5GS bridge, diagnostics) and the AKMA actions had no place in the
  sidebar; they are one module with four tabs, because the stub AUSF writes
  the AAnF store the AKMA actions read. The action ids are unchanged. Open5GS
  Remove subscriber and Purge YggdraSIM-managed docs ask before they run.
- The env-flag registry lists `YGGDRASIM_CARD_RELAY_TOKEN_FILE`, the MCP
  server's `YGGDRASIM_MCP_ACCESS`, `_ALLOW_CARD`, `_ALLOW_SCRIPT_FILES` and
  `_UPSTREAM_LOG_LEVEL`, and the 5G core launcher's `YGGDRASIM_5GCORE_MODE`,
  `_HOST`, `_PORT`, `_ALLOW_NONLOOPBACK`, `_TOKEN_FILE` and `_NO_TOKEN`. The
  MCP and 5G core flags are session-scoped, since neither process reads the
  persisted overrides. The inline `YGGDRASIM_CARD_RELAY_TOKEN` stays out: the
  Configuration page shows every value it lists.

- The Local eIM module of the GUI opens on a page centred on the cards the
  eIM knows (action `eim_local.overview`, read-only). The eUICCs tab lists
  them; an eUICC shows its Profiles, eUICC information, linked eIMs and event
  log, with buttons that queue an operation or open its form, quick controls
  (immediate enable, default SM-DP+, fallback attribute, rollback on Enable),
  a New operation form built from the operation catalogue, an operation view
  (parameters editable until the operation is taken, the package and the
  result as named rows) and a delivery report after Deliver now. The eIM
  configuration tab shows the identity and the TLS setups with their
  certificates. An action tagged `ipae-deliver` adds a "Deliver (IPAe)"
  button beside "Deliver now (IPAd)" (plugin contract, *Local eIM delivery
  route*).
- A Local eIM TLS setup carries its own eIM FQDN, a certificate layout taken
  from a reference certificate (`layout=`, `ca_layout=`: subject attribute
  order, extensions, serial length and hash, with fresh keys), the
  registeredID and CN choices, client authentication
  (`client_auth=none|optional|required`, `TLS-SETUP CLIENT-CERT <name>`) and
  an SNI rule. The card-facing listener serves every setup at once and picks
  the chain by the ClientHello's server name. `ASSOCIATE [setup=<name>]`
  gives a card the FQDN and trust of a setup and remembers it per card,
  `ASSOCIATE CHOICES` lists what can be picked, and `ASSOCIATE HANDOVER`
  binds a card to another eIM from stored certificates. The Local eIM answers
  names of the form `eim*.yggdrasim.local` only, so the name of any other
  eIM always reaches that eIM.
- A card action in the GUI shows what it is doing while it runs: one line per
  command under the action (a STORE DATA sequence once), or the raw exchanges
  under the global debug flag, sent over `/api/events/trace` and replaced by
  the answer when it arrives.
- A stream action can post its output as a terminal prints it
  (`_stream_console(terminal=True)`): the colours arrive as palette roles,
  blank lines are kept and the view follows the bottom while the reader is
  there (plugin contract, *Terminal output of a stream action*).
- The Local SM-DP+ panel takes a profile package dropped on it, loads it and
  reads the card overview again.
- The SAIP lint checks a Security Domain's keys and protocols: YRL-SDM-010
  (FAIL) for a key type GlobalPlatform Card Specification v2.4 Table 11-16
  reserves, YRL-SDM-011 (WARN) for a type the table does not define,
  YRL-SDM-012 (WARN) when the protocols in the install parameters and in the
  Card Recognition Data differ, and YRL-SDM-013 (INFO) for a protocol
  declared without a key set in its version range.
- The context decoder and the eSIM actions read the Profile Package
  Interpreter's EUICCResponse (SGP.22 v3.1 §2.5.6) and say which profile
  element failed, with what status and where.
- A Command Center action whose id is not in the page's tab lists names its
  tab with the tag `tab:<group id>`, and opens a tab of its own with
  `tab-label:<label>` (plugin contract, *Tab of a Command Center action*).
- The MCP server's `shell_run` knows the Local eIM shell's `TRAFFIC` verb as
  a read.
- The Local eIM records every exchange its listeners answer (the peer and its
  port, the TLS setup the server name picked, the bodies, the HTTP status, the
  operation served or closed) in its store, the newest 4000 kept, and shows
  them by name and value: `TRAFFIC [n] [eid=] [op=] [--brief|--hex]` on the
  shell, the "Traffic" action in the GUI, and the decoded rows under `OP
  <id>`'s served package and result (GetEimPackage, ProvideEimPackageResult
  and HandleNotification, SGP.32 v1.3 §5.14.5 to §5.14.7; the PSMO and eCO
  alternatives of §2.11.1.1 by name). A record is found by the peer's port,
  so a terminal that carries a card's channels to the service can print each
  exchange in its own trace as an `eIM:` line where the answer arrives, with
  the decoded rows and both bodies.
- The Local eIM queues the three device-side functions as operations of their
  own (`QUEUE ROLLBACK | EXECUTE-FALLBACK | RETURN-FALLBACK [refresh=off]`,
  labelled "(device)"): `ES10b.ProfileRollback`,
  `ES10b.ExecuteFallbackMechanism` and `ReturnFromFallback`. `DELIVER`
  executes them on the reader and an IPA polling over ESipa is never served
  one. The identity's signing key can be rotated and taken back
  (`identity.prepare_signing_key_rotation`, `commit_signing_key_rotation`,
  `restore_previous_signing_key`).
- `EIM-SETTINGS tls_keylog=on` makes the Local eIM's card-facing listeners
  write their TLS session secrets to `tls-keylog.txt` in the store directory
  (NSS key log format, mode 0600) so Wireshark can decrypt a capture of the
  sessions; read at service start, off by default.
- The Local eIM retrieves SM-DS events for a card (SGP.32 v1.3 §3.9.2.2): a
  download queued with `contact_smds=on` and `indirect=on` makes the relay run
  ES11'.InitiateAuthentication and AuthenticateClient against the SM-DS
  (`smds_address`, or the root SM-DS on record), close the operation with the
  Event Records, queue one indirect download per record at the front of the
  queue with the EventID as its Matching ID (SGP.22 v3.1 §3.1.3, §3.6.2) and
  answer the IPA with authenticateClientOkDSEsipa carrying the SM-DS
  transactionId and the first download's trigger (§6.3.2.2). Before, such an
  operation was refused.
- A Local eIM download operation takes `confirmation_code=<code>` (`QUEUE
  DOWNLOAD`, or More parameters in the GUI). When the SM-DP+ requires a
  Confirmation Code the eIM hands the IPA its hash in ESipa.AuthenticateClient
  (SGP.32 v1.3 §5.14.3; SHA256(SHA256(code) | TransactionID) per SGP.22 v3.1
  §3.1.3.2) and restores a compact PrepareDownload answer with it; without a
  code on the operation the IPA supplies hashCc itself, and the operation's
  history says so. Listings mask the code.
- Local eIM runs an operation queue per eUICC (`SCP11/eim_local/engine`):
  PSMOs, eCOs (`ADD-EIM`, `DELETE-EIM` among them), IPA eUICC data requests
  and profile download triggers are queued, edited, moved, copied,
  cancelled and delivered from the eIM-local shell (`QUEUE`, `OPS`, `OP`,
  `EDIT`, `MOVE`, `CANCEL`, `COPY`, `DELIVER`, `RESULT`), the Local eIM GUI
  module (New operation, Operations, eUICCs and delivery) and the MCP
  server, signed when an IPA takes them, with results and history kept in
  the store (`YGGDRASIM_LOCAL_EIM_STORE`, `YGGDRASIM_LOCAL_EIM_HISTORY_CAP`).
  `SERVE` runs the eIM as a service on 127.0.0.1:8743 with ESipa in the
  ASN.1 binding (SGP.32 v1.3 §6.3) and the JSON binding (§6.4,
  `/gsma/rsp2/esipa/`, the §6.4.1 status codes); the eSIM Management
  `DOWNLOAD` routes to it by eIM FQDN or SM-DP+ address, and every EID
  YggdraSIM reads registers with it. The indirect profile download
  (§3.2.3.2) is relayed between IPA and SM-DP+ (`QUEUE DOWNLOAD ...
  indirect=on`, `YGGDRASIM_IPA_INDIRECT_DOWNLOAD`): the IPA capabilities
  are asked per download (§2.11.1.3), the compact forms of §5.14 are
  restored from what the eIM holds, the metadata is verified before the
  BPP is fetched (§5.14.3, §3.2.3.2 step 15) and the download is closed by
  the ProfileInstallationResult the IPA forwards (§3.2.3.2 step 23). The
  ISD-R add/delete-eIM paths, the BF58/BF59 session paths and the handshake
  mode are retired; `ADD-EIM` / `DELETE-EIM` queue the eCO.
- Card readers are held across processes. A local PC/SC reader in use by
  one YggdraSIM process -- a card command in the eSIM Management console, a
  GUI card action or stream, the HIL bridge, an MCP card session or
  `pcsc_transmit` -- is locked against the others
  (`yggdrasim_common/reader_locks.py`: one `flock` per reader under
  `~/.yggdrasim/run/reader-locks`, `msvcrt.locking` on Windows, released by
  the kernel when the holder exits). A holder that runs until stopped is
  refused to the others at once and a short one is waited for, with
  "reader busy: <what runs> (pid <n>) has held '<reader>' since <time>"
  naming the holder, instead of one program resetting or powering down the
  card under the other (SCARD_W_RESET_CARD, 0x80100068) or an exclusive
  connect failing with a sharing violation. The HIL bridge holds its reader
  for its whole life, across its own reconnects and resets, and its
  supervisor starts no session (no SIMtrace2 reset, no modem reset pulse)
  while another process holds the reader, reporting state `reader-busy`
  with the holder.
- The raw APDU console's presets gain SELECT MNO-SD
  (`00A4040008A000000151000000`, the default Issuer Security Domain AID of
  GPC v2.3.1 Annex H.1.3, the instance AID the MNO-SD carries in the SAIP
  v3.4.1 example profile) beside SELECT ISD-R and SELECT ECASD.
- AddInitialEim builder. Offline Tools gains AddInitialEim build
  (`tool.eim_builder.add_initial_eim`), which composes the ES10b
  AddInitialEimRequest of GSMA SGP.32 v1.3 §5.9.4 from stored certificates and
  typed EimConfigurationData members, reads the encoded request back member by
  member, and returns the APDU script of the run: TERMINAL CAPABILITY declaring
  the IPAd, MANAGE CHANNEL, SELECT ISD-R, eUICCMemoryReset with
  resetEimConfigData and resetImmediateEnableConfig (§5.9.5), then AddInitialEim
  in 255-byte STORE DATA blocks. The eIM certificate store
  (`tool.eim_builder.certificates`) imports PEM, DER, base64 or hex
  certificates, several concatenated DER certificates included, and drops any
  private key block; each build saves the eimId, eimFqdn and euiccCiPKId it
  used, and the form offers them as suggestions and starts from the last build
  (`tool.eim_builder.saved_values` lists or forgets them). The store is per
  user and never tracked (`YGGDRASIM_EIM_BUILDER_STORE`, default
  `~/.yggdrasim/eim_builder/`). The build touches no card; AddInitialEim send,
  next to it (`tool.eim_builder.send`) and in the SGP.32 IoT (IPA-d) tab of
  eSIM Management (`scp11_live.add_initial_eim`), takes the same form, a
  reader and the confirm checkbox, and streams the decoded answers. The eSIM
  Live shell's `ADD-INITIAL-EIM` asks for the same members in a wizard (options
  take shorthand such as `oid` or `cert`; the eimId is free text, never read
  from a certificate, and offered from the last build), holds no card
  transport while it waits, and once confirmed sends the reset and the request
  and decodes both answers; `EIM-CERT-STORE` manages the store from a
  terminal. eimIdTypeOid is refused for an eimId that is not an OID (SGP.32
  v1.3 §4.3). Saved entries edit in place: a certificate renames (the saved
  values and configurations follow it) and a saved value changes without a
  forget and retype. Configurations (`tool.eim_builder.configurations`, the
  wizard's first and last prompts, `EIM-CERT-STORE CONFIGS`) keep whole forms
  under a name: tick Save beside a Configuration name to store one, pick it to
  fill the form.
- TERMINAL PROFILE decoder and builder (`yggdrasim_common/terminal_profile.py`).
  Every bit and count field of bytes 1-39 is named from ETSI TS 102 223
  V18.3.0 clause 5.2, with the 3GPP TS 31.111 V19.4.0 clause 5.2 reading of
  the bits TS 102 223 reserves for 3GPP. A decode reports RFU, deprecated and
  reserved bits that are set, byte 32 b7, a soft-key count of 'FF', non-zero
  bytes past byte 39, a facility whose TS 31.111 bits are set only in part,
  and the byte 33 NOTE. Offline Tools gains TERMINAL PROFILE decode
  (`tool.tp.decode`, with a two-profile comparison) and TERMINAL PROFILE build
  (`tool.tp.build`, from the maximal profile, an empty one or a pasted one);
  the context decoder, `python -m Tools.Asn1TlvDecode --context` and the
  `context_decode` MCP tool name the facilities of a TERMINAL PROFILE APDU; and
  `python -m yggdrasim_common.terminal_profile` decodes, compares, builds and
  lists from a terminal. The file imports nothing outside the standard
  library, so it also runs as a script on its own. Its maximal preset equals
  `MAXIMAL_TERMINAL_PROFILE` byte for byte (`tests/test_terminal_profile.py`).
- `yggdrasim-hil-modem-diag` (`Tools/HilBridge/modem_diag.py`) mirrors the
  modem's own SIM interface log into the HIL GSMTAP stream. It reads
  `LOG_UIM_DATA_C` (0x1098, or 0x14CE on dual-SIM builds) from a Qualcomm
  DIAG port through a minimal in-tree DIAG client (`Tools/HilBridge/qcdiag.py`),
  rebuilds the T=0 exchanges (ETSI TS 102 221 V18.4.0 clause 7.2.2.3) and
  sends them in the bridge's frame layout on GSMTAP antenna 1 from
  `127.0.0.2`, next to the bridge's or SIMtrace2's antenna-0 frames for the
  same exchanges. NULL bytes, long holds, the PPS exchange and an exchange
  cut short by a reset follow as libosmocore log records. `GsmtapTap` and
  `build_gsmtap_packet` take an `antenna` (default 0, so the bridge's frames
  are unchanged), and the live-decode state machine skips antenna-1 rows so
  a second view of an exchange is never paired twice. With
  `YGGDRASIM_HIL_MODEM_DIAG` set (`auto` finds the modem's DIAG port), the HIL
  supervisor runs the mirror for the whole session as a separate child on
  its own backoff (`--modem-diag-device`, state field `modemDiag`), outside
  the bridge, the REMSIM client and the session status. The Wireshark a HIL
  session opens starts with the profile in
  `YGGDRASIM_HIL_WIRESHARK_PROFILE` (default `YggdraSIM-HIL`), to which
  `Tools/HilBridge/wireshark_profile.py` adds SIM-side / modem-side filter
  buttons and coloring rules as two marked files it never writes over once
  the marker is gone.
- The context decoder (Offline Tools Decoder, `python -m Tools.Asn1TlvDecode
  --context`, the `context_decode` MCP tool) decodes the request and response
  types SGP.22 v3.1 added -- `EuiccConfiguredData`, `LoadRpmPackage`,
  `VerifySmdsResponse`, `PrepareDeviceChange`, `VerifyDeviceChange`,
  `VerifySmdpResponse`, `VerifyProfileRecovery`, `AlertData`, `CheckEvent`,
  `ConfirmDeviceChange`, `CheckProgress` -- with the SGP.22 v3.1 module the
  pinned pySim carries (`pySim.esim.rsp.asn1_v3`), and names the module that
  decoded each payload. With a pySim without that module it decodes as before.
- The HIL Wireshark profile gains an **STK** filter button for the toolkit
  traffic of ETSI TS 102 221 V18.4.0 clause 14.6, on both sides: TERMINAL
  PROFILE, ENVELOPE, FETCH and TERMINAL RESPONSE with the BIP commands and
  events they carry, STATUS (proactive polling), and every exchange answered
  `91 XX`, `62 F2` or `63 F2`, a proactive command pending. It reads the
  stock `gsm_sim` fields, so it works with or without the APDU dissector, and
  keeps to GSMTAP APDU records: stock `gsm_sim` reads an ATR record as an
  APDU, a T0 byte `12` as FETCH.
- The ASN.1/TLV decoder reads a BF-tagged GSMA RSP object against the
  SGP.22 / SGP.32 modules before showing the BER tree, in `yggdrasim-asn1`,
  the GUI's ASN.1/TLV decode action and the MCP `asn1_decode` tool: field
  names, named bits and numbers (`profileState = 1 (enabled)`), versions
  (`'020300'H (v2.3.0)`), and the members a tag list selects -- an
  IpaEuiccDataRequest's tagList names its IpaEuiccData items
  (SGP.32 v1.3 §2.11.1.2), a ProfileInfoListRequest's the ProfileInfo data
  objects (SGP.22 v3.1 §5.7.15). A field of a type with named bits or numbers
  lists every one the type names, the taken ones marked (`[x]`, `(*)`) and the
  rest greyed on a terminal, so `uiccCapability` or `ipaMode` shows what a
  card supports against what the specification defines; sibling values line
  up in one column. Certificates read as their subject,
  issuer, validity, key, RSP role and extensions, `DeviceInfo` `tac` and
  `imei` as digits (SGP.22 v3.1 §4.2), `extCardResource` as installed
  applications and free memory (ETSI TS 102 226 v19.0 §8.2.1.7.2). The
  reading is the notation: the BER tree moved to `berNotation` in the JSON and
  to `--ber` on the command line, and `asn1Notation` no longer carries it. A
  terminal gets the reading in the CLI theme's colours (`--color`,
  `NO_COLOR`). `--each` decodes every input line on its own into one JSON
  object per line, taking a leading label as the type name, so an ES9+ or
  ESipa JSON member such as `smdpSigned2` reads as its type.

### Changed

- GUI top bar: with the Local eIM pill beside HIL bridge and Remote, the
  pills' values (stopped, running) and the backend switch's label give way
  at 1760 px instead of 1400 px, the crumb at 1300 px on every page (before,
  only while a plugin pill showed), and the pill's label drops the word
  Local at 1240 px; the dot keeps the state and the title the whole text.
- Local eIM: `DELIVER` and `INJECT` end with a pass that sends the pending
  Notifications to their SM-DP+ (see Added); before, the Notifications a
  `DELIVER` took from the card stayed in the store. The result line of an
  added eIM names the association token (`addEimResult: associationToken
  2`). The eUICC and EUM certificates of an IPA data response are taken only
  when an operation of this eIM asked for the data.
- The APDU dissector's tree follows Wireshark's `gsm_sim` more closely. A
  command is named the way the specifications print it (`READ BINARY`,
  `STORE DATA`, an unknown instruction `INS AB`) in the tree, the Info
  column and `yapdu.command_name`, so a saved filter on the underscore form
  (`yapdu.command_name == "STORE_DATA"`) has to be rewritten. The header
  lines read `Class`, `Instruction`, `Parameter 1`, `Parameter 2` and one
  `Status Word: 9000 Success` line; a TLV is one line, its tag, length,
  class and constructed bit kept as filter fields without rows; the
  `Framing` node follows the response. No field abbreviation changed.
- The Wireshark profile a HIL session opens colours its rows in the
  Catppuccin Mocha palette: every GSMTAP row on the dark base, the text
  colour by kind (session, read, write, authentication, toolkit, ATR,
  warning and error status words, modem side, modem notes, TLS failures).
  The rules still read stock `gsm_sim`, `tls` and `udp` fields. The rest of
  the window follows on request: `python -m Tools.HilBridge.wireshark_profile
  --stylesheet <profile>` writes a Qt style sheet in the same palette into
  the profile, and the HIL menu then starts Wireshark with it. Without that
  file Wireshark keeps the desktop's own palette, as before.
- The SCP80 shell names a PoR status code from the table the context decoder
  reads (`yggdrasim_common/secured_packet.py`; ETSI TS 102 225 V19.0.0 Table 5
  with '0B' and '0C' of 3GPP TS 31.115 V19 clause 7) and keeps no table of its
  own. Four codes read differently on the `[POR]` line: '04' is "CNTR Blocked"
  and '09' "TAR Unknown", as the table spells them; '08' is "more time: the
  Receiving Entity needs more time to process the Command Packet" where it was
  "More time required"; '0C' names the ProcessUnstructuredSS-Request invoke
  component beside SEND USSD.
- The context decoder takes several commands at once, one per row. That is
  the script file the SCP03 shell's `RUN` and the SCP80 shell's `script` read
  (a row that starts with `#` is a comment, a row of hex is one command); each
  row is decoded as its own command, numbered by the row it stands on. Before, every second row
  was read as the answer to the row above it. A row without a marker now
  starts a new exchange when it is a well-formed command of a known
  instruction, and answers the command above it otherwise; the `apdu` context
  takes every row as a command and `response` every row as an answer. A row
  that holds no hex is left unread and counted by row number, never quoted.
  The Decoder panel has an Open file button and takes a dropped file, read in
  the page, and decodes the first 1000 exchanges of an input, saying how many
  it holds; `--file` reads UTF-8 and UTF-16 by their byte order marks; an MCP
  answer over 60000 characters comes back as the text view of as many whole
  exchanges as fit.
- The context decoder reads more forms and reads further into what it names
  (the Decoder of Offline Tools, `python -m Tools.Asn1TlvDecode --context`,
  the `context_decode` MCP tool). Hex stays the first reading, and an input it
  already reads into a domain reads as before, apart from rows without a
  marker (next entry). New forms: `AT+CSIM`, `+CRSM`,
  `+CGLA` and `+CRLA` lines (3GPP TS 27.007 V19.6 §8.17, §8.18, §8.43, §8.44;
  a restricted-access line names the file whose content it returns), PEM
  certificates, a JSON body with base64 RSP objects, base64, an EID, ICCID or
  IMSI in digits with its check digits (SGP.29 v1.1 §10, ITU-T E.118 §6), an
  ATR, a PC/SC return code, TLS records (RFC 5246 §6.2.1), a bare DER
  certificate, a profile package by its elements, and the `ef` context for the
  content of one file. New depth: the SMS TPDU with the secured command or
  response packet (ETSI TS 102 225 V19.0.0 §5.1, §5.2; 3GPP TS 31.115 V19
  §4.2, §4.4), BIP channel data followed across a trace as one stream per
  channel (TLS records and handshake messages, DNS, HTTP lines), the PUT KEY
  data field and the Key Information Template (GlobalPlatform Card
  Specification v2.4 §11.8.2.3, §11.3.3.1), TERMINAL CAPABILITY (ETSI TS 102 221 V18.4 §11.1.19.2 with the
  bits of SGP.22 v3.1 §3.4.2 and SGP.32 v1.3 §3.8.2), the SUCI of GET IDENTITY
  (3GPP TS 31.102 V19.5 §7.5.2.1) and the SCP11 commands of GlobalPlatform
  Amendment F v1.2 §6.4 to §6.6. An ES10 data field under secure messaging is
  no longer read as a clear object.
- Local eIM: `TLS-SETUP NEW <name> --replace` and `TLS-SETUP REMOVE <name>`
  refuse a setup that has further leaves or cards associated under it unless
  `--force` is given (GUI: Force), because both take the setup's CA with them.
- GUI: Offline Tools lists seven entries in place of seventeen. Tools that
  share an input or a store are one entry with a tab per tool: Decoder (the
  Decoder and ASN.1/TLV decode), TERMINAL PROFILE (Decode, Build),
  AddInitialEim (Build, Send, Configurations, Certificate store, Saved values)
  and SUCI keys (Use key file, Generate, Dump public key, under a line naming
  the key file and the `suci-keytool` command in use). eIM package lint, TUAK
  -- derive TOPc and the GSMA error-code reference stand alone, and a tool the
  page does not name, a plugin's included, still gets an entry of its own. A
  tab keeps what was typed while another one is open and reads the saved names
  and values again when it is shown. The action ids that remain, the shell
  verbs and the MCP tools are unchanged.
- GUI: the action list of the Local eIM has five tabs in place of eleven, one
  per store the actions work on: Operations (the queue, delivery, its rules),
  eUICCs (records, association, handover), eIM configuration (identity,
  service, traffic, TLS setups, leaves and handshake results), Direct card
  commands (profile state and load, metadata, memory reset, AddInitialEim)
  and Package files (package files, hotfolder, notification hygiene). A tab
  draws its buttons in the order of the workflow, Queue operation first, and
  the Leaf editor's own data action is no longer listed as a button.
- The context decoder (`tool.decoder.context`,
  `python -m Tools.Asn1TlvDecode --context`, the `context_decode` MCP tool)
  heads a ProfileInstallationResult with the outcome its EUICCResponse
  reports: every PE ok, or each failing PE with its status and offset (TCA
  eUICC Profile Package V3.4.1 section 8.11). It reads an EUICCResponse pasted
  on its own, names the rspCapability bits past the four the SGP.22 v2 text
  names (from EuiccRspCapability, GSMA SGP.22 v3.1 §4.3) and carries the
  SGP.32 check of an IoT eUICC's EUICCInfo2 as a note (GSMA SGP.32 v1.3
  §5.9.2). Result data or an EUICCInfo2 that does not decode against the
  schema is read by its tags instead: the outcome with bppCommandId and
  errorReason, the EUICCInfo2 members by name with the check.
- GUI: Environment > Configuration asks before it writes a sensitive flag,
  as the launcher's `[E]` menu does. Set shows the flag's name and its note
  with Confirm and Cancel, Confirm writes what the field and the persist box
  held when Set was pressed, and a change to either withdraws the question.
  Clearing a flag is not asked about on either editor, and neither is a
  request sent to `/api/env_flags/{name}/set` directly. Only the field of
  `YGGDRASIM_GUI_TOKEN` is masked while it is typed; the other sensitive
  fields are readable, as their values already were in the row.
- `YGGDRASIM_SUCI_TOOL` and `YGGDRASIM_SAIP_TOOL` are sensitive flags: each
  names a command YggdraSIM runs, so both editors ask before writing one.

- The macOS arm64 bundles are built on the macOS 15 runner image. GitHub
  retired the macOS 14 image on 2026-11-02.
- A finished stream action that printed a failure line reads Failed, and its
  error frames show without the debug flag. Before, every finished stream
  read Completed. The download form that ran over its own WebSocket flow is
  no longer offered; a profile download queued on the Local eIM page points
  at the eSIM Management download action.
- The AddInitialEim builder follows SGP.32 v1.3 §4.3 and §2.11.1.1.1 for
  `eimIdTypeFqdn`: the host is the eimId and no eimFqdn goes with it. A host
  typed as eimFqdn becomes the eimId with a warning, two different hosts are
  refused, and the linter reports an entry that carries both.
- A Key Version Number between '40' and '4F' reads as SCP81 (SGP.02 v4.2
  §2.2.5.1) in the SAIP decoder and shell.
- The Local eIM holds a package that enables or disables a Profile until its
  result arrives, and its ESipa listener reads chunked request bodies.
- Card actions started from the GUI take turns on a reader. Each call claims
  the reader it drives (its reader field, or the reader of the File system
  or Applications session it targets) for as long as it runs: a call on a
  reader a short action holds waits for it, up to a minute, and a call on a
  reader a stream or a profile download holds is refused at once with
  "reader busy: <action> has held '<reader>' since <time>". Before, the eSIM
  Management, Local SM-DP+ and OTA actions ran side by side, and an SCP11
  action powers the card down when it finishes, so two overlapping on one
  card could cut each other off. An open File system session between two
  commands holds no claim, the CLI shells and the MCP server run in other
  processes, and a plugin console takes the claim itself
  (`yggdrasim_common/reader_claims.py`, see the plugin contract).
- The raw APDU console (APDU ribbon tab of File system and Applications)
  takes one APDU per line, with '#' starting a comment as in the SCP03
  shell's RUN scripts, and the input grows with its lines. The breakdown
  table gives every line a row, and its Command column reads the command
  with the Offline Tools context decoder: instruction, what P1/P2 select and
  the named data fields, such as "SELECT FILE · selection by DF name (AID) ·
  AID A000000151000000 (MNOSD)". Decoded commands below the table unfolds
  the decoder's full reading, with header semantics and their clauses. Send
  ("Send N APDUs") transmits the lines in order, each answer numbered and
  named. A run stops at a failed send, a transport failure or an ended
  secure channel, and, with "stop at error SW" ticked (the default), at the
  first status word ETSI TS 102 221 v18.4 §10.2.1 classes as postponed
  processing or an execution, checking or application error; normal endings
  and warnings go on. A preset is added as a line of its own; the history
  Load key still replaces the input.
- The pinned pySim moves to hampushellsberg-dev/pysim `3322531`, seven
  commits past `f2db3ab`: the SGP.22 v3.1 members of `EUICCInfo1` and
  `EUICCInfo2` (a v3 eUICC's `highestSvn` and v3 CI key list no longer
  vanish from a decode), the SGP.22 v3.1 ASN.1 module, the `OperatorId` name
  the SGP.32 module imports, secure-channel log lines printed once,
  `fillFileOffset` kept within its UInt16 range, a security domain key's
  `keyAccess` and `keyCounterValue` kept on re-encode, and profiles with an
  rfu PE loading. The SAIP tools refuse a pySim without the three SAIP fixes,
  as they refuse one without the earlier fixes, and the SCP02 / SCP03
  sessions refuse a pySim that would print a secure-channel line twice.
- The pinned asn1tools moves to hampushellsberg-dev/asn1tools-loop-fix
  `2a06a6d`: osmocom/asn1tools master (`44277cd`, the asn1tools pySim
  installs) with three fixes, one commit each, also offered to
  eerimoq/asn1tools as #201, #209 and #210. A circular chain of tagged type
  references no longer hangs the compiler, and a malformed SEQUENCE OF / SET
  OF element raises a decode error instead of hanging; an OBJECT IDENTIFIER
  under arc 2 past 2.39 decodes as it was
  encoded in every binary codec (`2.999.1` read as `26.39.1` before); a
  tagged reference to a tagged CHOICE is compiled with one tag.
- The GUI has a skin beside its colour theme. The new default skin, Bench,
  sets the interface in IBM Plex Sans Condensed and the data in IBM Plex
  Mono (vendored, SIL OFL 1.1), draws square keys and flat panels separated
  by rules instead of rounded cards, shadows and gradients, puts the top
  bar, the event log and the status line on the code surface, and lights
  the current entry like a pressed key. Capitals are kept for UI legends,
  so names keep their case (the sidebar groups read "eSIM (SCP11)", not
  "ESIM (SCP11)"). A module workbench lays out three panes: its actions
  listed one per row with the open one lit and every label in full (the
  icon tiles cut them at 82 px), the output, and an inspector with the
  card or module overview; its head names its Command Center group and
  shows the bound reader and its action count. In eSIM Management the
  list leaves out Enable, Disable and Delete profile: each profile card in
  the inspector carries those buttons for its own profile. The File system and SAIP
  Tool ribbons are rows of keys under group legends. The Skin control in
  the top bar switches back to Classic, the previous look; every skin
  renders in all 22 themes, two of them new: Bench · dark and Bench · light,
  the palettes the skin was drawn in (achromatic accent, colour kept for
  ok / warn / fail and the data). The terminal palettes
  (`YGGDRASIM_CLI_THEME`) carry both.
- The Command Center sidebar collapses to a rail of keys, one per module
  with a short legend (FS, MGMT, SAIP, ...), instead of disappearing; the
  sidebar mode menu keeps Hidden and Auto-hide. A collapsed event log keeps
  one line with the latest row, a module's action list and inspector each
  collapse to a labelled strip, and the status line carries pane keys for
  the sidebar, the actions, the inspector and the log (Alt+1 to Alt+4).
  Keys 2 and 3 take the name of the pane in the current view (Actions,
  Files for the File system tree, Packages for the SAIP Tool's package
  drawer, Inspector) and are disabled where the view has none; each of
  those panes collapses to a labelled strip. The status line also shows
  the EID and ICCID the last card overview or File system scan read for
  the active reader, and its "viewing:" text follows every view switch.
- The SAIP Tool's ribbon shows one command group at a time behind a tab
  per group (Package, Actions, Element, File system, Tokens, Lint,
  Advanced, Reference) instead of one long scrolling strip; the chosen tab
  stays while the workbench re-renders.
- eSIM Management reads the card overview when the module is entered (a
  sidebar or Overview click, or picking its reader), so the profile cards
  and their Enable / Disable / Delete buttons are there without a click on
  Load. It reads once per entry: a reader pill click, a sibling leaf or a
  reset shows the last read with its time ("Card read at ..."), and Refresh
  reads again. It does not read a card a File system session, a running
  stream action (a profile download, for one), the HIL bridge or a remote
  consumer holds -- the read selects ISD-R on the basic channel and powers
  the card down when it releases it -- and says which; Load still reads it
  on request. An action started while the read is in flight waits for it
  instead of opening a second connection to the card.
- The SAIP Tool's profile element list has a Compact switch: one line per
  element (glyph, name, label, FS / APP and lint chips, index), so a
  17-element package fits the pane. The choice is kept in the browser.
- The File system key strip puts Delete, Resize and Suspend UICC in a
  Danger group at its end, apart from Create file, Lifecycle and Search
  rec.
- The FCP of the file picked in the File system tree is a card that starts
  folded, so the file body is the first thing under the file actions. Its
  summary line gives what the kind chip does not: the file size (records x
  record length for a record file, the total file size for a DF), the SFI,
  the life cycle status and the EF ARR record the access rules come from.
  Once opened it stays open from file to file until it is folded again; the
  result of the "Select file (no read)" and "Select + read file" action
  forms, where the FCP is the answer asked for, shows it open. Opened, it
  puts the short parameters in a grid of cells, as many across as the pane
  holds, the raw bytes, the access rules and any nested template on
  full-width rows after them, and names the parameters without a value once
  ("No value") on the toolbar line instead of a "null" row each. Each
  parameter of the FCP and of the decoded body (the file preview, each
  record card, the READ ribbon result) has a Copy key, shown on the row
  under the pointer (in the FCP grid it lies over the cell's right end),
  that copies its value: hex as one contiguous string (no byte grouping, no
  byte count), a list one entry per line, a structured value as JSON. Copy
  body beside Update body, and Copy record beside Update record, copy the
  bytes read as one hex string; the dump below them carries offsets and an
  ASCII column. Other views that show decoded values are unchanged.
- Remote Bridge shows one section at a time behind three tabs: Host (where
  the rig runs and how to reach it), Rig (Start / Stop full rig, the manual
  stages and the rig status) and Status (the bridge connection, the live
  probe and the latency history). The tab is kept in the browser. The
  Remote GUI and bridge URLs stay on one line, whole on hover, instead of
  breaking mid-string.
- The Overview's module cards carry a line of live state: an open File
  system session and its reader, open SAIP packages, the last eSIM card
  read with its profile count, and the module's last action and error
  count from the event log. It is read from what the GUI already holds,
  never from a card, and follows the log while the Overview is open.
  Entering a module from the Overview or another Meta view counts as
  opening it, so eSIM Management reads the card again.
- Local eIM's category tabs sit at the top of its action list and count
  the actions they list; a category whose actions all live in the eIM
  overview is not offered.
- Offline Tools lists each tool as its own entry under the Offline Tools
  navigation leaf instead of a grid of cards; an entry shows that one tool,
  and the leaf itself opens the Decoder. The entries show while Offline Tools
  is open.
- The Offline Tools decoder opens empty. It used to save the last input in
  the browser's storage and decode it again every time Offline Tools opened,
  so an old result filled the surface above the actions; that input is no
  longer kept, and the copy earlier builds left behind is removed.
- The Wireshark a HIL session opens shows the UTC time of day each frame
  was captured in its Time column (`-t u`) instead of seconds since the
  first frame. `YGGDRASIM_HIL_WIRESHARK_TIME_FORMAT` takes any Wireshark
  `-t` value (`ud` adds the date, `a` / `ad` are local time, `u.6` sets six
  decimals); `off` leaves the format the profile last used, and a value
  Wireshark would refuse counts as `off`, so a typo cannot stop it from
  starting.
- The APDU dissector names a TLS alert in the Detail column of its BIP
  row: the card's own in SEND DATA (`SEND DATA: channel 1, 7 bytes, fatal
  TLS alert bad_certificate (42)`), the peer's in the TERMINAL RESPONSE to
  RECEIVE DATA, and a ciphered one as `encrypted TLS alert`. The name was
  only in the packet tree, Expert Information and Info before, so a
  certificate rejection read like any other SEND DATA in the packet list.
  The HIL Wireshark profile adds a **TLS alerts** filter button and shows a
  certificate alert (RFC 5246, RFC 6066 and RFC 8446 codes, at any level)
  or any fatal alert in dark red. The dissector guide no longer calls an
  installed copy interchangeable with the `-X lua_script:` one: Wireshark
  loads the personal plugin folder first, so the installed copy is the one
  that runs until `install` is re-run.

### Removed

- The Offline Tools actions `tool.tlv.decode`, `tool.sw.lookup`,
  `tool.euicc_info2.decode` and `tool.sima_response.decode`. The Decoder reads
  each of their inputs: a bare TLV under its Raw BER-TLV context, a status
  word, an EUICCInfo2, and an EUICCResponse alone or inside a
  ProfileInstallationResult. The `/api/tools/*` routes are unchanged.
- The Offline Tools action `suci.set_tool_command` ("Set suci-keytool
  command"). It never had an effect in the GUI: every action builds its own
  bridge to the tool, so the command it set was gone before Generate or Dump
  ran. The command is set with `YGGDRASIM_SUCI_TOOL` (Environment >
  Configuration), which those actions already read, and the state line over
  the SUCI keys tabs now names the command in use, where it comes from and
  where to set it. The `TOOL` verb of the SUCI shell is unchanged.

- `SCP11/rsp_v3_schema.py`. It declared the SGP.22 v3.1
  `StoreMetadataRequest` members for a pySim that lacked them; the pinned
  hampushellsberg-dev/pysim declares them itself. With another pySim the
  metadata encoders refuse a v3.1 field instead of encoding it, as they
  already did whenever a member was missing.
- The workarounds the new pySim pin makes unnecessary: the security domain
  key field restorer and the `fillFileOffset` splitter in
  `Tools/ProfilePackage/saip_pysim_compat.py`, the SAIP GUI's
  `ProfileElement` constructor patch, the log gate's own deduplication and
  the context decoder's `OperatorId` supplement.
- The asn1tools workarounds the new asn1tools pin makes unnecessary: the
  OBJECT IDENTIFIER decoder wrapper (`yggdrasim_common/asn1tools_compat.py`)
  and the schema reading's tagged CHOICE repair, with its
  `taggedChoiceRepair` status.

### Fixed

- The local SM-DP+ answered an InitiateAuthentication that named another
  SM-DP+'s address, signing serverSigned1 for that address under its own
  certificate; an eUICC refused it (ciPKUnknown) and the download ended in
  undefinedError. It now refuses such a request with invalidDpAddress (8.8.1 /
  3.8 in the JSON binding, GSMA SGP.22 v3.1 §5.6.1).
- A shell batch (`--cmd`, `--stdin`) in which a command failed ended with
  exit code 0 in the SCP03, SCP80, SUCI, eSIM Management, Local SM-DP+ and
  Local eIM shells, and `yggdrasim --scp03 --cmd` swallowed the code. Those
  batches now end with 1 after a `[-]` line, a `[!]` line other than a
  warning, an unknown verb or a caught error; `EIM-LISTEN` and a verb that
  runs until it is stopped are judged by their own outcome. Notes that read as failures were re-marked
  (`LOGOUT` without a session, an empty ARA or registry answer, a reset the
  scan continues past). The SCP03 `--out` report is written when the batch
  ends with `EXIT`, where it was skipped before.
- `yggdrasim-gui`, `yggdrasim-web-server` and `yggdrasim --gui` ignored
  `--card-backend`, the `--sim-*` options, `--sim-import-profile` and
  `--debug`.
- The simulator refused to start on a fresh runtime root: the quirks file
  seeded there is the shipped template, which defines nothing, and the
  loader sent it through the `YGGDRASIM_ALLOW_QUIRKS` gate anyway. An
  unedited template is now skipped; an edited file still needs the gate.
- GUI: card-changing actions ran as soon as Run was pressed, among them Set
  status, Unlock, the install actions, the Local SM-DP+ profile and metadata
  actions, the Local eIM's direct card commands, Deliver to card, Deliver
  now and the OTA sends. Each now asks: a required acknowledgement in its
  form, or a question line with Confirm and Cancel for the buttons without
  one.
- eSIM Management in the GUI read a profile command as failed when any line
  of its trace held "failed" or "error", so a DISABLE the card had carried
  out showed Status `failed` because the Notification sync after it could
  not reach the SM-DP+. The verdict comes from the `[-]` and `[!]` lines; the
  sync is reported apart (`notification_sync`, and a Note when it did not
  complete). The page also put "<operation> ok" over an answer that said
  `ok: false`; it reads "<operation> failed" now.
- The first SAIP request could fail with "partially initialized module
  'pySim.esim.saip.templates' ... has no attribute 'FileTemplate'" when a
  second request imported pySim's SAIP templates module at the same moment (a
  pySim import race between the package and that module; seen once in the
  GUI, reproduced every time with a forced order on Python 3.11 and 3.13).
  Every direct import of the module now goes through
  `yggdrasim_common/pysim_saip_import.py`, which imports the package first.
  The pySim fix and its repro are prepared for the pinned fork.
- eSIM Management IPA: the eIM's answer to an Event Retrieval it ran itself
  (authenticateClientOkDSEsipa, GSMA SGP.32 v1.3 §3.9.2.2 step 14) was read
  as a failed download. The IPA printed a failure, sent the eIM a
  ProfileDownloadTriggerResult with profileDownloadError for a retrieval that
  had succeeded, and dropped the download trigger in the answer; the download
  still ran, from the queue, a poll round later. The flow now ends at that
  answer, the trigger in it is run and reported under its own
  eimTransactionId, and no eIM Package Result is sent for the retrieval. The
  Local eIM notes a download result that arrives for a retrieval it closed
  and keeps the Event Records it stored as the operation's result.
- Local SM-DP+: an encrypted segment of a Bound Profile Package was 1036 bytes
  long where GSMA SGP.22 v3.1 §2.5.3 allows 1020 (tag, length field and MAC
  included), because the profile was cut every 1008 bytes and the padding then
  added a block. An eUICC that holds to the limit answered the first profile
  segment with bspStructureError. Segments now carry 1007 bytes of the profile,
  a package with a longer segment is refused before it is sent
  (`BspSegmentTooLong`), and the simulated eUICC's own segment builder follows
  the same limit.
- Local SM-DP+: on an eUICC that enables ES10 only for a declared IPAd, a
  command died at its first ES10 exchange with `69 85` (`LOAD-PROFILE` at
  GetEUICCInfo1, right after SELECT ISD-R), because the session never sent
  TERMINAL CAPABILITY. It now declares IPAd support (tag '84', GSMA SGP.32
  v1.3 §3.8.2) once per card session, before the first application
  selection, and again after a card reset, as the eSIM Management and Local
  eIM shells do. The Command Center's Local SM-DP+ actions and the Local
  eIM's direct ISD-R actions run on the same session and send it too. A card
  that refuses the command is noted and the command goes on.
- Local SM-DP+: the EID is read with ES10c.GetEID on the ISD-R (GSMA SGP.22
  v3.1 §5.7.20; ES10b.GetEID of SGP.32 v1.3 §5.9.19). The session read it
  with GET DATA '5A' on the ECASD, the retrieval of SGP.02 v4.2 §2.2.2,
  which a later eUICC need not answer: on such a card `LOAD-PROFILE` stopped
  after PrepareDownload with `6D 00`, where the session keys need the EID,
  and the Command Center's Get EID and Discover and the card overview of
  the Local SM-DP+ and Local eIM (`SCAN` / `INFO`) failed the same way. The
  read no longer leaves the ISD-R inside an open session. The ECASD read
  remains for a card that refuses GetEID, and a card that gives no EID
  either way is reported with both answers.
- eSIM Management: the EID is read with ES10 GetEID once the connect phase
  has run (GSMA SGP.22 v3.1 §5.7.20, SGP.32 v1.3 §5.9.19), asked once and
  with no recovery cascade of its own, with GET DATA '5A' on the ECASD
  behind it for a card that refuses GetEID. On an eUICC that answers no GET
  DATA on its ECASD the Command Center's Get EID returned nothing, Status
  showed no EID, `EIM-LISTEN` refused to start and the IPAd poll had no EID
  for its GetEimPackage request. Get EID and Status now run the connect
  phase before the read, so the IPAd declaration leads the card session;
  Status used to select the ECASD ahead of it. Where no connect phase has
  run the read is the ECASD one alone, as before.
- eSIM Management transport: a card reset reconnected to the PC/SC reader of
  the same index when the simulated card backend was selected, so commands
  meant for the simulated card could reach a real one. The reset now
  reconnects to the simulated card.
- Local SM-DP+: `LOAD-PROFILE` refuses a file that is no profile package
  before the session opens. A variable template (`.varder`, hex text with
  `{name:TYPE:length}` fields still unset) was wrapped as it stood and failed
  after PrepareDownload with "TLV value overruns input"; the refusal now names
  the unset fields and `MATERIALIZE-TEMPLATE`. Hex text behind a UTF-8 byte
  order mark is read as hex, and when the legacy BF36/BF23 wrapper stands in
  for a session-bound package the debug lines give the metadata field that
  was missing.
- GUI: Set, Clear and Reset persisted overrides under Environment >
  Configuration were refused by the server (HTTP 422). The page sent its
  content-type header twice in two spellings, which arrives as one doubled
  value that is not read as JSON; the page's request helper now adds the
  header only when the caller gave none in any spelling.
- GUI: Generate SUCI key and Dump public key reported "suci-keytool exited
  with code 1" after a run that succeeded, because exit code 0 was read as a
  missing one. A finished run now says what it did, and the public key is
  shown whole.
- The context decoder no longer splits a GUI event-log line that carries
  answer data into two exchanges, keeps a status word written on a row
  (`sw=9000`) with the command or the data beside it, reads the raw exchange
  lines of the eSIM Management shells' `--debug`, and ends a response still to
  be fetched when a command other than GET RESPONSE follows (ETSI TS 102 221
  V18.4 §12.1.1.1).
- The SGP.32 check of an EUICCInfo2 no longer warns about a missing eCall
  flag: ecallSupported is an OPTIONAL NULL whose absence says the eUICC lacks
  the mechanism (GSMA SGP.32 v1.3 §5.9.2). An empty iotVersion list is
  reported instead of passing, since the same clause asks for at least one
  version.
- `suci.status` reports the SUCI key file chosen last. It read a new tool
  bridge on every call and always answered "(not selected)".
- The context decoder no longer shows an EUICCInfo2 the response type refuses
  as an empty GetEuiccInfo2Request: a type that reads no member of a
  non-empty object is not taken as its reading.
- The wheel and the source distribution contain `SCP11.eim_local.engine`. The
  package was missing from the reviewed package list, so an installed
  `yggdrasim-scp11-eim-local` failed at import and a successful EID read
  raised `ModuleNotFoundError` in the admin shell, the eSIM Management
  console and the local-access shell. A packaging test now refuses a tracked
  subpackage the list does not name.
- SCP03 admin shell: plugins extend the shell after its command table exists.
  The hook ran first, so a verb a plugin added to the table was never there.
- SCP03 admin shell: `OTA` starts the SCP80 shell by package name. It put the
  `SCP80` directory on `sys.path` and imported `main`, which is the launcher
  package inside the launcher and the GUI, and let SCP80 parse the admin
  shell's own command line.
- SCP80 shell: `set kic`, `set kid` and their older spellings stay out of
  `~/.scp80_history`, lines already in the file are dropped at the next
  save, and the file is readable by its owner only.
- GUI: the action catalogue carries `requires_auth`, so the Card
  Administration page asks for authentication before it opens a form that
  needs a secure channel. The catalogue model dropped the field.
- GUI: "Explain eIM package" answers with the payload of the shell's
  `EIM-PACKAGE-EXPLAIN`. It imported a class that does not exist and always
  failed.
- `yggdrasim-profile-autoload` watches the profile store the simulator
  writes to: the configured store, or the `profiles` directory of the eUICC
  store when the root holds one. It imported a module that does not exist
  and always watched `Workspace/SIMCARD/profile_store`.
- `yggdrasim-eum-diag decode-bpp` prints the BF36 layout and the number of
  ES10b segments. It imported a pySim module that does not exist and always
  reported pySim as missing.

- The HIL supervisor no longer stops on a host whose PC/SC service is not
  running. The reader lookup it makes before a session raised the PC/SC
  library's own error (`0x8010001D`, service not available); it now reads as
  "no reader", which the bridge child reports itself.
- The simulated eUICC's updateEim changes the members the request carries and
  keeps the rest (SGP.32 v1.3 §2.11.1.1.2); it replaced the whole entry. Its
  ListEimResult codes the list as 'A0' (§2.11.2.1) instead of '30'.
- The certificate store no longer repeats a warning about serial number 0
  for the SGP.26 test CI in every trace that scans it.
- A desktop window left open no longer grows without limit. Qt WebEngine
  6.11.1 does not collect the garbage a page leaves in its renderer (an idle
  window reached 3.5 GB in 42 hours), so the window now starts V8 with
  `--expose-gc` and the page asks for a collection once a minute; a
  QtWebEngine window whose `--js-flags` were replaced says so in the event
  log. The background polls (readers, health, Remote Lab sessions, plugin
  pills) drop to one per 30 s while the window is shown without focus and
  run again at once when it gets focus. Evidence and the release check are
  in `upstream_patches/qt-qtwebengine-renderer-gc/`.
- DeviceInfo follows SGP.22 v3.1 wherever it is sent. The IPA eUICC data
  answer (with `IPA_INCLUDE_DEVICE_INFO_IN_EIM_DATA` set) carried it with
  universal tags ('04' TAC, '30' capabilities) where the RSP module's
  AUTOMATIC TAGS give tac '80', deviceCapabilities 'A1' and each member the
  tag of its position; it is now the DeviceInfo of the AuthenticateServer
  ctxParams1 under IpaEuiccData's 'A9'. ctxParams1 and the AuthenticateServer
  request are encoded with pySim's SGP.22 v3.1 module instead of the v2 one:
  all DeviceInfo (6) and DeviceCapabilities (15) members, the v2 name
  `eutranSupportedRelease` read as `eutranEpcSupportedRelease`, a name v3.1
  does not define refused instead of dropped, and the SM-DP+'s ServerSigned1
  keeps the v3 members the v2 module dropped when it re-encoded the signed
  data (bytes unchanged for a v2 SM-DP+). The asn1crypto fallback used without
  pySim wrote universal tags across all of CtxParams1 and now gives the pySim
  bytes.
- The Local eIM restored a compact AuthenticateServerResponse (SGP.32 v1.3
  §5.14.3) with the eUICC and EUM certificates only, so an SGP.22 v3 eUICC
  whose certificate chain is not Variant O lost its `otherCertsInChain`
  (SGP.22 v3.1 §4.5.2.0a, §5.7.13) on the way to the SM-DP+, which could then
  not verify the chain. The relay now appends the chain it holds for the
  eUICC (learnt from a full answer of that eUICC, or set with `EUICC SET <eid>
  other_certs_in_chain=<hex>`), omits it for a Variant O chain, and refuses
  the answer when the EUM certificate is not issued by the selected CI and no
  chain is on record.
- The simulated eUICC's eUICCMemoryReset answered an empty `BF64 00` and,
  under resetEimConfigData, put its own default eIM back. SGP.32 v1.3 §5.9.5
  (p.130-132) removes all eIM Configuration Data and answers resetResult, with
  resetEimResult and resetImmediateEnableConfigResult for their bits; the
  simulator now does both (`BF64 09 80 01 00 81 01 00 82 01 00` for a reset of
  the eIM data and the immediate enable configuration, resetEimResult
  nothingToDelete once no eIM is left), and the emptied list survives a restart.
- An eIM added to the simulated eUICC without trustedPublicKeyDataTls (OPTIONAL,
  SGP.32 v1.3 §2.11.1.1.1) was given a generated certificate in its place; the
  member now stays absent. Only the simulator's own default eIM still gets one.
- The simulated eUICC listed its stored eUICC Package Results under
  RetrieveNotificationsList's `A2` as bare `A0` alternatives; SGP.32 v1.3
  (p.40, p.43, p.134) makes the list a SEQUENCE OF EuiccPackageResult, the
  `BF51` CHOICE, which is what LoadEuiccPackage answered with. Each element is
  now that `BF51`, by list and by seqNumber, stores saved earlier included.
- GetEimConfigurationData on the simulated eUICC answered eimPublicKeyData and
  trustedPublicKeyDataTls of the eIMs it seeds itself as a bare certificate,
  and its legacy entries as an `A1` around a whole certificate. Both are now the
  CHOICE alternative SGP.32 v1.3 §2.11.1.1.1 defines (`A1` Certificate or `A0`
  SubjectPublicKeyInfo in place of the SEQUENCE tag), and the signature check
  reads the wrapped legacy form instead of rebuilding a nested SEQUENCE.
- The AddInitialEim build and send forms remember their whole form. Every
  build or send keeps it as the last build (`last_configuration.json` in the
  builder store) and the forms open with it, eimIdType, the key forms,
  counterValue, associationToken, the eimSupportedProtocol bits and
  indirectProfileDownload included; before, only the typed eimId, eimFqdn,
  euiccCiPKId and certificate names came back unless the form was saved as a
  named configuration. The eSIM Live `ADD-INITIAL-EIM` wizard starts from the
  same last build. The build shows the request as one STORE DATA APDU, with an
  extended Lc past 255 bytes, in place of its bare TLV hex (which the result
  labelled "Raw response").
- The schema reading decodes the RSP types whose members reference a tagged
  CHOICE with a tag of their own: a ProvideEimPackageResult carrying its
  IpaEuiccDataResponse, an EuiccPackageResult with a listProfileInfoResult,
  CancelSessionRequestEsipa, the ESipa message alternatives. asn1tools gives
  such a reference an explicit tag of its own and took the single 'BF52' or
  'BF2D' an eUICC sends for a mismatch; X.680 (02/2021) §31.2.7 makes the tag
  implicit and X.690 (02/2021) §8.14.4 puts it in place of the CHOICE's own.
  The pinned asn1tools carries the fix
  (`upstream_patches/osmocom-asn1tools-tagged-choice/`). The reading's JSON
  carries certificate validity times and BIT STRING contents, which asn1tools
  hands over as `datetime` and `bytearray`, as text and hex; an object holding
  a certificate no longer fails to serialise.
- The context decoder read an IpaEuiccDataRequest (SGP.32 v1.3 §2.11.1.2)
  as IpaEuiccDataResponse (§2.11.2.2), both 'BF52', and showed
  `IpaEuiccDataResponse[0] = None`: asn1tools accepts the response's
  extensible CHOICE with an unknown alternative. A type now counts only when
  it reads every byte and its outer CHOICE matches. The generic tree no
  longer names one-byte context tags ('81', 'A0') from specification tables,
  whose rows gave names such as `ASN1_A0_ASN1_CHOICE_OPTION_1`, and prints a
  tag list as its tags instead of a dump of names and aliases; 'BF52' is
  named `IPA_EUICC_DATA` (`PACKAGE_DATA` stays an alias).
- The simulated eUICC's setFallbackAttribute follows SGP.32 v1.3 §3.4.6 step
  by step: a Profile whose fallbackAllowed is absent or FALSE is refused
  with fallbackNotAllowed (§4.4: only if set to TRUE it SHALL be possible to
  set the fallbackAttribute), the Emergency Profile with undefinedError, a
  Profile that already carries the attribute is answered ok before any other
  check, and an eUICC without the Fallback Mechanism answers
  processingTerminated (unknownOrDamagedCommand) instead of
  fallbackNotAllowed. After a processingTerminated result the rest of the
  eUICC Package is no longer executed (§5.9.1). The disabled lab Profile,
  Lab (EU 02), is seeded with fallbackAllowed TRUE and stays a valid
  fallback target; a saved simulator store that holds no value for it takes
  the seed's on load, while a TRUE or FALSE the store holds is kept. The
  enabled Lab (EU 01) now gets fallbackNotAllowed, as on a card.
- With BACKEND set to SIM, the reader-backed modules (File system,
  Applications, Over-the-Air, eSIM Management, Local SM-DP+, Local eIM)
  still listed only the PC/SC readers, so the simulated card could not be
  picked, and a real reader picked there was answered by the simulator under
  that reader's name. The SIM backend now lists one reader, YggdraSIM
  Simulator, with the simulated card's ATR; the SCP03, SCP11 and SCP80
  actions bind it, and the reader list follows a backend switch at once
  instead of on its next poll.
- Card Administration: once the inline action panels outgrew the module
  column (Applications: Apps, Sec. domains and AIDs), the session box above
  them shrank to nothing and the panels were laid out over the ribbon and
  the APDU console it still painted, which showed as soon as another ribbon
  tab was picked. The session keeps its floor (the ribbon at its height, the
  file panes at 220 px) and the column scrolls; the file panes still scroll
  inside themselves.
- The raw APDU console's GET STATUS presets carried three stray bytes after
  their data and no '4F' search criterion; they now send `80F2xx02024F0000`
  (GPC v2.3.1 §11.4.2.3, Table 11-35), the command the Registry ribbon
  sends, and the ISD one is labelled ISD (80) after Table 11-33.
- The context decoder raised IndexError on a command shorter than its four
  header bytes; it now reports the line as an APDU header that could not be
  parsed.
- Over-the-Air: Concatenated SMS offered Off, On, False and True, and a
  stored ON matched none of them, so the page added a fifth choice. It
  offers On and Off, the two values SCP80/config.py stores, and shows an
  older true / yes / 1 or false / no / 0 as the value it stands for.
- SCP03 Run script from the GUI refuses a line carrying `--log <file>` or a
  `TRACE` command, which the shell's line executor turned into a file
  written on the server host; the SCP11 console's GUI path already refused
  `--log` for that reason.
- The File system preview laid a decoded FCP out as a two-column grid of
  whole fields, so the `raw` value got a 73 px column and printed one byte
  per line; the FCP block's key/value grid no longer applies to the
  decoded object.
- SAIP Tool: Security Domain parameter names wrap instead of being cut,
  the profile element list no longer repeats its pane's heading, and the
  TAR value fields and the Configuration inputs carry accessible names.
- The simulated eUICC answered GetProfilesInfo only in its bare `BF2D00`
  form and refused a search criterion or a tag list with '6A 80', so every
  overview of it read Fallback "not reported". It now takes
  ProfileInfoListRequest as SGP.22 v3.1 §5.7.15 defines it (isdpAid, ICCID or
  Profile Class criterion, tag list '5C'), answers the requested data
  objects in ProfileInfo order including SGP.32 v1.3 §4.4 ecallIndication,
  fallbackAttribute and fallbackAllowed, and answers a malformed request
  with incorrectInputValues. The listProfileInfo PSMO goes through the same
  path with its own default list (§2.11.1.1.3). A simulated Profile carries
  fallbackAllowed when its metadata set it (StoreMetadataRequest '9F67' or
  the profile manifest). The PSMO's profileChangeOngoing error was encoded
  `02 01 0B`; the module's automatic tagging makes it `81 01 0B`, which is
  what pySim encodes.
- The simulated eUICC's GetEuiccConfiguredData answer (SGP.22 v3.1 §5.7.3)
  tagged each additional root SM-DS address `82` instead of UTF8String
  `0C` and each ciList entry as a bare `84` key identifier instead of
  `SEQUENCE { ciPKId, ciName }`, so the card overview printed the
  additional SM-DS addresses as one hex string and a strict decoder refused
  the answer. Both follow the v3.1 module now (pySim decodes it); a ciList
  entry is named after its eSIM CA RootCA certificate's common name.
- The eSIM card overview's profile cards show Fallback and Fallback allowed
  (SGP.32 v1.3 section 4.4 `fallbackAttribute` / `fallbackAllowed`) for
  every Profile, reading "not reported" when the eUICC refused the tag
  list. The overview payload dropped both values, so the card's former
  "Used as: Fallback" row never appeared. A failed overview read showed an
  empty inspector; it now shows the reason the read gave.
- The simulated card's EF.ARR coded every key-reference condition as
  `A4 03 83 01 <ref>`, without the usage qualifier `95 01 08` that
  TS 102 221 v18.4 §9.5.1 and Table 9.3 put in every CRT, and pySim refused
  the records. The SAIP EF.ARR encoder, which generated that table and builds
  every rule the ARR record picker creates from a condition name, now emits
  `A4 06 83 01 <ref> 95 01 08`; the simulator's records grow from 21 to 27
  bytes, the length the PIN1 record's two CRTs need.
- GetProfilesInfo is an ES10c function (SGP.22 v3.1 §5.7.15), as are
  EnableProfile, DisableProfile and DeleteProfile (§5.7.16 to §5.7.18). The
  eSIM Management "List profiles" action, its Local SM-DP+ twin, the eIM
  shells' merged profile-state result table and the SGP.22 Consumer tab hint
  called them ES10b.
- The Local eIM shell's AddInitialEim and AddEim packages encoded a
  counterValue or an explicit associationToken from 128 to 255 in one octet,
  which DER reads as a negative INTEGER (X.690 (02/2021) §8.3), and an
  eimSupportedProtocol with no bit set as `08 00`, a BIT STRING with eight
  unused bits; they now share the builder's DER encoders.
- The HIL bridge never answers a TPDU the modem has abandoned.
  osmo-remsim-client-st2 hands the card's next answer to whatever command
  the modem is on, so an answer to a command sent before a modem reset
  landed on the first command after it, and every answer after that was
  one command late: `6F00` on the first SELECT, then reset after reset. Each
  modem TPDU now records its card session (one per reset) and a sequence
  number; the card's answer to anything but the latest TPDU of the current
  session stays off the modem, a superseded TPDU still queued never reaches
  the card, and a FETCH, TERMINAL RESPONSE or GET RESPONSE arriving as the
  first TPDU after a reset is dropped unanswered. The usual source is the
  SIMtrace2 firmware: since 2019 it ends a 128-, 192- or 256-byte USB
  message without a zero-length packet, so a modem command with 114, 178
  or 242 data bytes (a RECEIVE DATA that returns 160 bytes, for one) reaches
  the host only after the modem has waited 120 s and reset the UICC.
  `upstream_patches/osmocom-simtrace2-cardem-zlp/` carries the firmware
  patch, a journal scan and an `AT+CSIM` check; the bridge's warning names
  the USB message size when a dropped command matches.
- A card that holds a command longer than 5 s no longer resets the HIL
  session. The PC/SC wait per APDU (`DEFAULT_APDU_TIMEOUT_MS`, shared by the
  HIL bridge and the Card Bridge) is now 30 s: the SIMtrace2 board keeps the
  modem waiting with NULL procedure bytes (ETSI TS 102 221 V18.4.0 clause
  7.2.2.3.1), while a timeout tore the bridge session down and the modem saw
  a card reset. `YGGDRASIM_HIL_APDU_TIMEOUT_MS` is now a registered setting
  that the launcher and the GUI pass to the supervisor as `--apdu-timeout-ms`.
- With a local reader, osmo-remsim-client-st2 is started with the card's ATR
  (`-a`, read from the relay marker the bridge child publishes), as it already
  was for a remote card. Unseeded, the client put its `3B 00` placeholder on
  the board at start-up and after every bankd reconnect, and a modem that
  activated in that gap read the placeholder instead of the card.
- The HIL bridge no longer closes both RSPRO links when one side fails.
  osmo-remsim-client-st2 sends the same `connectClientReq` on its control and
  bankd links, and a link answered with the other role is closed and not
  re-dialled on its own. A card failure used to close both links, the client
  re-dialled them together, and when its bankd link arrived first the bridge
  answered each link with the other role. Now a card failure closes the bankd
  link and re-opens the reader, a lost link is closed alone, and a connection
  that arrives before the control link has answered `configClientIdReq` is
  closed unanswered, so the client re-dials it.
- The simulated eUICC no longer accepts an RSP Server certificate chain it
  cannot verify when `conformance_strict` is off. A CERT.DPauth.SIG or
  CERT.DPpb.SIG that named a CI the card holds was accepted without that CI's
  signature, any certificate passed once `otherCertsInChain` was present, a
  self-signed certificate without an authorityKeyIdentifier was accepted, and
  a chain could end, unverified, at a configured CI the card held no key for.
  In both modes the chain is now verified up to a CI key the card holds
  (SGP.22 v3.1 §5.7.13, §2.4.2): a forged copy is invalidCertificate(1), and a
  chain to a CI without a held key, or a certificate without an
  authorityKeyIdentifier, is ciPKUnknown(7). Without `conformance_strict` the
  card still skips the keyUsage and role OID checks. A CI the card should
  trust is held through `ci_certificates_der_hex` in `isdr_config.json` or the
  eUICC store. A CI held there but missing from the configured CI PKIDs now
  anchors a chain in default mode as well; it used to answer ciPKUnknown(7).
- The simulated eUICC's euiccChallenge is random (SGP.22 v3.1 §5.7.7). It was
  a hash of the EID and the APDU count, so every fresh card answered the
  same sequence of challenges.
- The simulated eUICC refuses a Profile Package outside the SAIP V3.4.1
  framing (complete TLVs, one ProfileHeader first, one PE-End last) with
  installFailedDueToPEProcessingError(12) and the interpreter's
  invalid-request-format(5) in ppiResponse (SGP.22 v3.1 §2.5.6.1); random
  bytes, a truncated package or one without PE-End used to install. A BPP
  section member that runs past the length its section header declared is
  bspStructureError(7) instead of counting as a complete section.
- The live LPA no longer reports an install as complete when the last
  LoadBoundProfilePackage segment is answered without data. It looks for the
  session's ProfileInstallationResult among the card's pending notifications
  (SGP.22 v3.1 §2.5.6), uses it when one carries the session's transactionId,
  and fails the install otherwise.
- HandleNotification keeps the configured ES9+ base URL, port included, when
  a notification's notificationAddress names the configured SM-DP+ host. The
  address is an FQDN and carries no port, so the notifications of an SM-DP+
  on a non-default port went to port 443.
- The SCP80 shell answers a SET UP EVENT LIST the card raises behind a PoR.
  An OTA command that switches a toolkit applet on or off changes the
  registered event list, and the CAT Runtime sends the new list at once
  (TS 102 241 V18.1 §6.7.1.2); the shell fetched it and left it unanswered,
  which held the proactive session open on the connection the next send
  reuses. It now gets TERMINAL RESPONSE (OK), as at bring-up (TS 102 223
  V18.3 §6.4.16), and the shell prints the new list. Any other command
  behind a PoR still stays unanswered and is printed.
- The context decoder lost the SGP.32 v1.3 module whenever pySim's
  `asn1/rsp` directory listed `rsp.asn` before the two PKIX files, an order
  the file system decides: the `OperatorId` declaration SGP.32 imports went
  before the last `END` of the joined text, into a PKIX module, the joint
  compile failed, and SGP.32 types fell back to the generic BER tree with
  only a "SGP.32 module skipped" status note. The pinned pySim now declares
  `OperatorId` in `RSPDefinitions` itself, and the decoder compiles its files
  as they are.

## [2.2.0] -- 2026-10-18

### Added

- PE-Application instances are edited in place. "Edit instance..." opens
  the instance dialog on its INSTALL members (the AIDs, a check box per
  privilege, the life cycle state, C9 and the extradite security domain)
  and `saip.update_application_instance` (`update_instance` in
  `Tools/ProfilePackage/saip_application_edit.py`) rewrites them, keeping
  the instance's place in `instanceList` and every member it does not
  write. Each instance gets the security domain's parameter editor
  ("Instance parameters") for its system, UICC and process-data
  parameters: `saip.update_sd_parameters` takes an `instance_index`.
- `--log <file>` on any shell command line (SCP03 and its STK sub-shell,
  SCP80, the SCP11 eSIM management, Local SMDPP and Local eIM shells, the
  SAIP and SUCI tools, in `--cmd` / `--stdin` batches too): the command
  runs as with `--debug`, the raw APDU trace included, and everything it
  prints is appended to the file, without terminal escapes, each line
  stamped with its local time, between a header naming the command and a
  trailer saying how it ended (`yggdrasim_common/command_log.py`). A new
  file is created owner-only. The terminal shows the same debug output.
- SCP03 `TRACE START [file]` / `TRACE STOP` / `TRACE STATUS`: one such log
  over every command in between, each noted with a leading `>`; the prompt
  reads `TRACE` while one is open, and `EXIT`, `QA` and the end of a batch
  close it.
- `SCP11.transport.set_apdu_trace_renderer` and
  `set_apdu_trace_note_renderer`: a plugin prints the SCP11 transport's
  `--debug` exchanges, and the lines a flow prints between them
  (`print_apdu_trace_note`, so far the connect phase's), in its own form
  (*APDU trace renderer* in `site-docs/internals/plugin-contract.md`).
  With none installed the output is unchanged.
- An SCP11 console command can declare that its handler brings the card
  up itself (`runs_own_connect` on `_add_command` and `CommandSpec`): the
  console still rebuilds the transport under the command's session
  policy, then skips its ES10 connect phase. The Local eIM shell leaves
  `--debug` in the argument of every command in `_internal_debug_commands`
  instead of a fixed list.
- Placeholders are declared where their bytes go, in any package the
  workbench opens: a `{var:TYPE:len[:modifier]}` literal typed into the
  JSON tab, a Data-tab editor, the raw body or record editors or the
  header's ICCID registers the occurrence (`saip.update_file_decoded`,
  `saip.apply_decoded_edit`, `saip.update_file_content`,
  `saip.update_record_bytes` and `saip.update_profile_header_field`
  report `placeholders`), the projections show the literal, a varder save
  writes it and the test-value lists answer it. The Variables panel's
  rows, and a section listing the universal list's other placeholders
  with their test values, drag
  into any hex field or the JSON tab and copy on click; a dropped or
  pasted literal overwrites the bytes it stands for so the field keeps
  its width. The "Insert variable" buttons of the JSON tab (at the
  caret), the raw hex, ICCID and IMSI editors and the header ICCID row
  open a picker over the package's variables, the universal list and a
  new placeholder (name, type, width, modifier, value, saved to the list),
  placing a narrower one at a byte offset. The `{T}` buttons are gone;
  `saip.add_variable_to_pe` binds a dict field as a typed placeholder
  (`placeholder_type`, `modifier`, `value`, `keep_value`, `save_to_list`),
  keeping the field's bytes as the value. `saip.define_variable`, the panel's "Define a
  variable" form, `VARIABLES DEFINE` and a two-argument `TOKEN-LISTS SET`
  add a placeholder to a test-value list with its value or declared alone
  (`name,`), which the pickers list, the Variables panel flags as Unset
  (with the length-byte note for IMSI and MSISDN), the shell listing shows
  as `declared, no value`, and the validate run reports as `YRL-VAR-001`.
  The header follows the files: "Sync from EF.ICCID" and "Sync from
  EF.SMSP" put the file's placeholder into the header (ICCID in header
  order, the SMSC digits of the SMS-PP bearer) instead of copying sentinel
  bytes, adopting the value the file resolves to as the variable's typed
  value; an SMS-PP dialing number takes an MSISDN placeholder, which the
  connectivity encoder and decoder carry where the digit bytes go.
- `saip.generate_test_profile`, the "Generate test profile" entry of the
  SAIP workbench ribbon and Variables panel (in place of "Export complete
  profile") and the `VARIABLES GENERATE <out.der|out.hex>` spelling of
  `VARIABLES EXPORT` write one DER or HEX profile with every placeholder
  replaced by the value its Variables row shows: a typed value, else the
  test value of the profile's list or the universal one, read again at
  that moment so an entry added since the package opened counts. The run
  refuses, naming the variables, while one has no value anywhere, and
  reports the value and source used per variable; a DER or HEX save of a
  template reads the lists the same way, and `MATERIALIZE-TEMPLATE`
  writes ASCII hex for a `.hex` target. A list entry that merely names
  the variable now answers a placeholder in any spelling: a plain
  `PUK1,...` line supplies its bytes to `{puk1:TEXT:8:utf_8}`, and a
  typed entry of the same type with another width or modifier is
  re-encoded for the occurrence; an exact spelling still wins and a
  value that cannot fit is reported with its line.
- `saip.trim_padded_content` (SAIP workbench ribbon, Package group) and
  the ProfilePackage shell verb `TRIM` drop the `fillFileContent` bytes a
  file's initial image already holds: the Fcp fill / repeat pattern (ETSI
  TS 102 222 6.3.2.2.2) or the template default (TCA SAIP V3.4.1 section
  8.3.3), record by record. A file declaring neither, a BER-TLV file and a
  linked file are left alone, the first written record of a cyclic EF stays
  written, and every file is proven by replay before the package changes.
  A dry run lists each file with the bytes it would save; the shipped
  reference profile goes from 8884 B to 7088 B of DER with every file
  image unchanged.
- The PE-RFM card of the SAIP workbench shows which directory an RFM
  script starts in and moves the element between the two scopes TCA SAIP
  V3.4.1 section 8.8 defines: bound to an ADF (ADF RFM, ETSI TS 102 226
  section 7.3) or to the MF alone (UICC shared file system RFM, section
  7.2). "Bind ADF" picks one of the ADFs the profile creates or takes a
  custom AID, with the access domains defaulting to the PE's UICC domains;
  "Unbind ADF" drops the binding. The card also names the instance and
  its security domain, and the two add-PE presets start an RFM in either
  scope. The ProfilePackage shell verb `RFM` lists the elements and does
  the same by name (`RFM 15 ADF USIM OUTPUT=out.der`, `RFM 15 MF
  IN-PLACE`). `saip.get_rfm` reports the profile's ADFs
  (`adf_candidates`) and `saip.set_rfm_adf_access` accepts an ADF name.
- SAIP workbench editors keep what the operator typed but has not applied
  as a draft of the open package, so switching to another open package or
  element and back restores it; a Draft chip marks such an editor and
  Discard drops it. The PE-RFM TAR list and ADF binding are the first
  editors on the store.
- `YGGDRASIM_GUI_CARD_SESSION_IDLE_SECONDS` is the idle ceiling of a GUI
  card session that holds a reader, 900 s by default where the manager
  used to close one after 180 s. The workbench draws a decoded file from
  its own cache, so reading one never reaches the backend to refresh the
  clock; the ceiling covers reading time, not click frequency. A
  dispatcher's own value and a caller-chosen manager default keep
  precedence, the flag is read when a session opens, and the persisted
  override reaches the GUI console scripts, which do not apply persisted
  overrides themselves.
- `yggdrasim-desktop FILE` (and `yggdrasim --gui FILE` / `--web-server
  FILE`) opens FILE in the SAIP workbench once the GUI is up, and
  `scripts/install_shortcuts.py` lists the launcher under the file
  manager's Open With menu for `.txt` profiles and `.varder` templates on
  Linux, Windows and macOS. The registration is handler-only: the
  application a double-click uses is never changed, and on Linux a
  default the install happened to displace is put back. The server hands
  the path to the page once through `GET /api/gui/startup`, so a reload
  does not reopen it.
- The SAIP workbench keeps a library of saved profile elements. "Save PE"
  on the Element ribbon stores the selected element under a name as the
  PE document "Export PE" writes (`ygg.pe_document.v1`), and "PE library"
  lists the entries, loads one into the open package at a chosen index or
  deletes it (`saip.save_pe`, `saip.list_pe_library`, `saip.load_pe`,
  `saip.delete_saved_pe`; `Tools/ProfilePackage/saip_pe_library.py`). The
  library is `~/.yggdrasim/saip_pe_library/`, or the directory
  `YGGDRASIM_SAIP_PE_LIBRARY` names, outside every checkout. A saved
  template PE keeps its placeholder literals and registers them in the
  package it is loaded into.
- "Add above" and "Add below" open an "Insert profile element" dialog
  over every `ProfileElement` type the SAIP module in use can carry
  (`saip.list_pe_types`, in schema order, with a filter box), the presets
  of a type that has several, and the saved PEs of the library, inserted
  at the index the dialog shows. "Save as" names the format and the
  destination in one dialog: DER, HEX (`.hex` / `.txt`), ASN.1 value
  notation (`.asn`), tagged JSON (`.json`) and, for a template session,
  varder.
- The PE-SD card decodes each `sdPersoData` record into its DGI blocks
  under the raw hex and takes a new record ("Add DGI record"), which the
  server accepts only as whole DGI, length, value blocks
  (`validate_dgi_stream` in `Tools/ProfilePackage/saip_dgi_decode.py`).
- The Decoded view keeps its scroll offset, open folds and chosen tab per
  package and element; a link path clicked in a PE-GFM entry opens the
  referenced file in the FS tree with the top tab following; the FCP
  editor of a GFM entry carries every `Fcp` member, `dfName` for an ADF
  included, and for a link the EF size and proprietary-info rows are the
  conditional parameters that turn the link into an independent file.
- The Local SM-DP+ shell's load failure summary names the profile element
  a PEStatus points at. The unprotected package is outlined by byte span
  when the BPP is built (`SCP11/shared/sima_locator.py`, keeping file
  identifiers, paths and object identifiers and no other value), and the
  `EUICCResponse` offset, counted from the first byte of the rejected PE
  (TCA eUICC Profile Package V3.4.1 section 8.11), is read as the element
  that ends there and the element that starts at or holds it, the
  tolerance the Interoperable Format Test Specification V3.4 grants
  (RQ8.1.11.29, test 8.2.11.3).
- The SAIP workbench decodes EF.PSLOCI (P-TMSI, P-TMSI signature, RAI
  and the routing area update status; 3GPP TS 31.102 v19.5 section
  4.2.23), EF.5GAUTHKEYS (the '80' to '84' key and counter objects,
  with the all-'FF' value named as no valid value; section 4.4.11.6) and
  EF.TN3GPPSNN (the count byte and the '80' UTF-8 serving network name
  objects; section 4.4.11.13) in the Data tab, and EF.PSLOCI gets a
  wizard beside the LOCI and EPSLOCI ones. The cards show where the
  Python decoder has no payload of its own; a truncated or over-claiming
  TLV is named in the card instead of dropped.

- The guide viewer draws `mermaid` fences. Mermaid 11.17.2 is vendored
  under `gui_frontend/src/vendor/mermaid/` as the self-contained UMD
  build and is loaded on demand from a same-origin URL, only when an
  opened document carries such a fence, so the page keeps its
  `script-src 'self'` policy with no `unsafe-eval` and the desktop
  window draws with no network. The diagram palette is read from the
  theme tokens, so a diagram follows all twenty themes. NOTICE
  enumerates the three redistributed items -- the RSPRO schema,
  xterm.js and Mermaid -- and each vendor directory names the upstream
  project, the pinned version, the license and the update procedure.
- The environment-flag reference is generated rather than written.
  `site-docs/_tools/build_env_flags.py` renders
  `reference/env-flags.md` between markers from the flag registry in
  `yggdrasim_common/env_flags.py`, the CLI matrix generator carries the
  rows for the console scripts added since it was written, and
  `tests/test_docs_generated_pages.py` fails while either block is
  stale.
- The Card Bridge and the Remote Lab have subsystem pages of their own,
  and the README names `yggdrasim_common/remote_lab/` alongside the
  module entry points that had no line.

- The desktop window (`--gui`) has an adjustable page zoom. Ctrl+plus,
  Ctrl+minus and Ctrl+0 (or Ctrl+wheel) in the window step it through
  the browser ladder (0.5 to 3), and the chosen factor is remembered
  across launches through the new `YGGDRASIM_GUI_ZOOM` env flag, which
  the Configuration view also edits directly (an edit reaches the open
  window within a second). `1` is the native size the layout is drawn
  for (a 1280 x 800 window) and the default; `auto` fits the layout to
  the window instead, up to 2.0. Page zoom is the browser's Ctrl-plus,
  so viewport units, breakpoints, pointer coordinates and the
  terminal's cell metrics stay consistent. Browser tabs on
  `--web-server` keep the browser's own zoom.
- The Profile Header editor's SMS-PP bearer carries "Sync from EF.SMSP"
  beside its dialing number, the counterpart of "Sync from EF.ICCID": it
  copies the TS-Service Centre Address of the first EF.SMSP record (3GPP
  TS 31.102 clause 4.2.27, coded as the RP-Destination Address of 3GPP
  TS 24.011 clause 8.2.5.2) into that bearer's SMSC Address (SGP.02 v4.2
  Table 94) and applies it; PID, DCS, the other bearers and any trailing
  bytes re-encode as they were. The USIM template's linked EF.SMSP is
  followed to the DF.TELECOM file that generic file management creates.
  The `saip.update_profile_header_field` action takes the same step as
  field `smsc_from_ef_smsp`, with the bearer index as its value.
- Wizard 8 (Full CAP Install Sequence) and the GUI "Install script"
  action ask for the ADF AIDs an applet needs file access to (Enter or
  `N` for none). A listed AID adds the UICC
  System Specific Parameters object (Tag EA, ETSI TS 102 226 V19.0.0
  clause 8.2.1.3.2.2): the toolkit parameters (Tag 80, priority 01 and no
  resources, declinable) and the access parameters (Tag 81) granting full
  access to the shared UICC file system and to each ADF. Install
  parameters that already carry an EA or a CA object are refused instead
  of doubled. The Access Domain sub-wizard behind the Install Parameters
  TLV Builder takes the same ADF AID list for Tag 81 / 82. The script's
  INSTALL [for install] comment lists every install parameter object,
  naming each ADF and its access domain, or the absence of an EA object.
- Wizard 8 (Full CAP Install Sequence) offers to save the generated
  sequence as a script file and asks for the path (default
  `<cap stem>_install.txt` beside the CAP; an existing file is kept
  unless overwriting is confirmed). The file carries the source CAP and
  the format as `#` comments and one APDU per line, so the SCP80 shell
  runs an OTA-formatted script with `script <file>` and the SCP03 shell
  runs an ISO-formatted one with `RUN <file>`. The GUI's SCP03 workbench
  carries the same builder behind an Install-tab button, "Install
  script" (`scp03.build_install_script`, no card needed), with a save-as
  picker and an overwrite switch; both surfaces write byte-identical
  files.
- The SAIP workbench exports and imports one profile element as a PE
  document (`.pe.json`, schema `ygg.pe_document.v1`): the tagged decoded
  tree a saved package uses, the PE's DER bytes when the session can
  produce them, and a summary. A PE-Application therefore travels with its
  load block, the applet bytes and every instance, and Import PE puts it
  back into any package. The export dialog defaults to the document, names
  the file after the PE and lets the destination's extension pick DER or
  HEX; a template session keeps the placeholder literals or substitutes
  the stored values. `saip.import_pe` also reads a tagged single-section
  document, the plain decoded JSON of one PE, DER and hex text, proves the
  tree encodes before it reaches the sequence, reports a recorded DER that
  no longer matches the tree, and gives the copy the next free
  identification so the other PEs keep theirs.

- Offline Tools opens with a context-aware decoder. One paste box takes an
  APDU, a response, a bare TLV or a whole exchange trace; each command is
  classified by its CLA/INS pair and the payload decoded against the
  specification that governs it: TS 102 221 SELECT parameters and FCP
  templates, TS 102 223 / TS 101 220 proactive commands, envelopes and
  terminal responses, GPC v2.3.1 GET STATUS registry entries, INSTALL
  fields, DELETE, STORE DATA and GET DATA, SCP03 INITIALIZE UPDATE, ES10
  requests and responses named from their BF tag and decoded with the
  compiled SGP.22 v3.1 and SGP.32 v1.3 modules, and TS 31.102 AUTHENTICATE.
  A trace carries state: the selected file names READ BINARY content and a
  '61 xx' word chains GET RESPONSE onto its command. The same engine backs
  `python -m Tools.Asn1TlvDecode --context` and the `context_decode` MCP
  tool; `tool.decoder.context` is the Command Center action.

- GSMA SGP.02 v4.2 and 3GPP TS 24.011 v19 joined the specification library.
  `scripts/convert_tel_docs.py` now packs a form-feed paginated Markdown
  rendering whose file name it lists, which is how the SGP.02 copy that had
  sat unused in the source tree becomes readable; `scripts/fetch_tel_docs.py`
  downloads TS 24.011 and tracks the 3GPP2 CSIM specifications in its manual
  checklist. The SCP03 shell reads the eUICC identifier from the ECASD the way
  SGP.02 v4.2 section 2.2.2 describes, and the short-message decoders follow
  TS 24.011 for the transport-layer address.

- The SCP03 shell decodes EF_CCP and EF_ECCP (TS 51.011 section 10.5.4), EF_LP
  (TS 51.011 section 10.3.1), EF_HPPLMN, EF_LND, EF_MBDN and the USIM
  EF_GBABP, the DF_5GS files SUCI_Calc_Info, SUPI_NAI, TN3GPPSNN, 5GS eDRX, 5G
  NSWO configuration, MCHPPLMN and the KAUSF-derivation flag, and the ISIM
  EF_GBABP, EF_GBANL, EF_AD, EF_UICCIARI, EF_AC_GBAUAPI and EF_IMSDCI files
  (TS 31.102 v19.5 section 4.4.11, TS 31.103 v19 section 4.2). The file-system
  controller gained `resume_uicc` (SUSPEND UICC with P1 '01', TS 102 221 v18.4
  section 11.1.22.3) and the FCP view now carries the file identifier, the
  life-cycle name, the total size, the decoded PIN status template and the
  proprietary-information template. Every correction of the audit below is
  pinned in the new `tests/test_scp03_spec_*.py` files.

- `EIM_TRANSPORT_MODE=esipa_json` speaks the SGP.32 v1.3 section 6.4 JSON
  binding of ESipa: GetEimPackage posts `eidValue` with the optional
  `notifyStateChange`, `stateChangeCause` and `rPlmn` members to
  `/gsma/rsp2/esipa/getEimPackage` and reads back `euiccPackageRequest`,
  `ipaEuiccDataRequest`, `profileDownloadTriggerRequest` or
  `eimPackageError`; ProvideEimPackageResult posts the base64
  `eimPackageResult` to `/gsma/rsp2/esipa/provideEimPackageResult` and
  reads the optional `eimAcknowledgements`. `esipa_direct` keeps the ASN.1
  binding and the earlier lab JSON body.

- The eUICC is asked for the SGP.32 §2.11.1.1 fallback attributes.
  `ProfileInfoListRequest` carried no tag list, so the answer held the
  default `ProfileInfo` set and `fallbackAttribute` ('9F26') and
  `fallbackAllowed` ('9F67') were never in it -- `BF2D00` could not say
  whether a Profile is the Fallback Profile. The request now names the
  tags it needs, an eUICC that rejects the list is re-asked for the
  default set, and a member that was never on offer stays distinct from
  one the eUICC omitted: the console and the GUI profile card show a
  fallback row only when the attribute came back set.

- A notification read survives an eUICC that implements no `BF28`. The
  SGP.32 §5.1 ES10b function table carries `RetrieveNotificationsList`
  (`BF2B`) and no `ListNotification`, so an IoT eUICC can refuse `BF28`
  while ES10b is healthy. A refusal is now probed with `BF2B` on the
  untouched channel: if that answers, the card is latched as lacking
  `BF28` and the metadata list is rebuilt from the `BF2B` response
  (SGP.22 §5.7.12 / SGP.32 §5.9.11). Only when both are refused is the
  session itself treated as the fault.

- ES10 structures are decoded to their ASN.1 field names. A context tag
  means nothing on its own, so the dissector could only report `Tag 0x81`
  inside an `EUICCInfo2` and `Tag 0xA0` inside a profile listing. The TLV
  walker now carries the structure a tag sits in, and the names come from
  the ASN.1 of the converted SGP.22 and SGP.32 specifications through
  `scripts/generate_apdu_dissector_tables.py`: 228 types and 675 members
  under 62 `BFxx` function tags, including the `ProfileInfo` records that
  an `ES10c.GetProfilesInfo`
  answers with, which now read `iccid`, `isdpAid`, `profileState` and
  `profileNickname` rather than four bare tags. Carrying the structure
  rather than the parent tag is what lets `BF22` be `EUICCInfo2` at the
  top of a response and `serviceSpecificDataStoredInEuicc` inside a
  `ProfileInfo`, both correctly.

  The reader computes every tag from the class and number in the
  declaration and refuses to generate when one disagrees with the
  `-- Tag 'XX'` the specification states beside it; 125 agree and none
  differ. A type whose body cannot be read unambiguously contributes no
  names rather than names on the wrong tags.

- The eIM-local shell speaks SGP.32 §2.11.1.2 `IpaEuiccDataRequest`
  (`BF52`). The package codec builds, validates and decodes the body,
  a template ships beside the other eIM packages, and the tag list is
  checked against the data items the section defines rather than passed
  through. `EIM-DOWNLOAD` takes `--<n>` (or `--<n>,<m>`) to select
  configured eIM entries.

- ES10b.RetrieveNotificationsList answers the SGP.32 §5.9.11 search
  criteria: by sequence number, by `NotificationEvent` bit, and the
  `searchCriteriaEuiccPackageResult` alternative that selects the single
  stored eUICC Package Result. `SGP32Definitions` is an AUTOMATIC TAGS
  module, but X.680 §12.3 suppresses automatic tagging for a component
  list whose first member is tagged, so `enable`'s `rollbackFlag` is a
  universal NULL `05`; a request carrying the auto-tagged `81` is still
  honoured.

- EF.UAC_AIC (3GPP TS 31.102 §4.4.11.7) and EF.UMPC (ETSI TS 102 221
  §13.6) decode as themselves. The card view rendered EF.ACC for the
  first -- access identities are not access control classes -- and the
  3GPP file of the same acronym for the second.

- The ten SGP.22 v3.1 §5.5.3 `StoreMetadataRequest` members can be
  authored from a metadata document. They need a pySim carrying the
  schema extension in
  `upstream_patches/osmocom-pysim-rsp-v3-metadata/`; see *Fixed* below
  for what happens without it.

- A `graphite-light` theme, and a Command Center summary for an action
  that refused to do anything. A generator answers HTTP 200 whether or
  not it produced an artifact, reporting refusal in
  `materialization_state`, so a blocked run used to look identical to a
  successful one with the reason buried in the result JSON.

- `yggdrasim-desktop` is a `[project.gui-scripts]` entry point for the
  Command Center. setuptools backs a gui-script with `pythonw` on
  Windows, so a shortcut opens the GUI without a console window behind
  it. `yggdrasim-gui` stays a console script for terminal use such as
  `yggdrasim-gui --web-server --token-file <path>`.

- `scripts/install_shortcuts.py` writes a native launcher per host: a
  `Terminal=false` desktop entry on Linux, a `WScript.Shell` shortcut in
  the Windows Start Menu, and an `osacompile` applet in `~/Applications`
  on macOS. It resolves the launcher to an absolute path at install
  time, because desktop sessions and Explorer do not inherit the shell
  `PATH`. `--dry-run`, `--force`, `--uninstall`, `--target`,
  `--install-dir`, and `--no-icon` are supported.

- The launchers carry the YggdraSIM mark, shipped as `yggdrasim_common`
  package data so a pipx install has it without the source tree. The
  Windows `.ico` is written from the packaged PNG at install time, which
  needs no image library on the host.

- `pipx install '.[gui,saip]'` is documented in
  `scripts/install/README.md`, including why the bare package name does
  not resolve from PyPI: two base dependencies are PEP 508 direct
  references, which PyPI rejects in `Requires-Dist`.

- The Islands light theme joins the set: a soft grey canvas with white
  raised cards. The SCP03 session ribbon gains a collapse control that
  hides the button groups and hands their share of the viewport to the
  file tree and the detail pane. The tab strip stays visible while
  collapsed, and picking a category expands the toolbar again.

- The APDU dissector reads the SNI out of a TLS ClientHello on a BIP
  channel, so the `SEND DATA` row carrying the handshake names the host
  the way a DNS row already did. `yapdu.cat.payload_protocol` on the
  same row says which of the two the name came from. A handshake split
  across records or channel-data blocks reports nothing rather than a
  truncated guess, because BIP channel data is not reassembled.

- `scripts/check_repo_hygiene.py` refuses allocated MCCs: a dashed
  MCC-MNC pair, an IMSI whose leading digits are an allocated MCC, and
  the packed-BCD form both take on the wire (TS 24.008 10.5.1.3). The
  fixtures the new checks caught moved to the reserved test ranges.

### Changed

- The SAIP workbench lists its bit and service lists one entry per row,
  top to bottom: the privileges and other bit fields of the Fields tree,
  the decoded service tables (EF.UST and its kind), the service-table,
  access-class and access-rule wizards, the bit-mask fields and the
  profile header's mandatory services
  (`gui_frontend/src/css/views/saip/flag-rows.css`). An instance of
  PE-Application shows its members as rows instead of one line.
- An Application PE installs instances of its one load package (TCA SAIP
  v3.4.1 section 8.7.1): adding an instance of another package, or
  moving one to it, is refused; a replaced load package takes the
  instances along; an `instanceList` entry the Fields tree adds installs
  the PE's package. A profile that already installs several packages
  still opens, edits and round-trips.
- The MCP `shell_run` gate takes `--log` off a command before it reads the
  verb and files a read verb that carries one as a write, since the shell
  then writes a file on the server host; SCP03 `TRACE` is a write verb.
  The GUI's eSIM management actions refuse `--log` in an argument field.
- The Command Center files an eSIM Management action under the live eUICC
  configuration tab by its `euicc-config` tag.
- The Local eIM `PATHS` and `STATUS` commands print bridge rows only when a
  bridge reports a status.
- `site-docs/_tools/mirror_source_docs.py` leaves out every Markdown file
  git ignores, in place of a list of named paths.
- The GetCerts block of DISCOVER, GET-CERTS and the local-access discovery
  snapshot shows the EUM and eUICC certificates field by field: subject,
  issuer, serial number, validity with the time left, key, signature
  algorithm, the RSP role and the EID, fingerprints and every extension
  under its RFC 5280 name, with name constraints and Permitted EINs
  decoded. A Chain section verifies the eUICC signature against the EUM
  certificate and names the EUM's authority key identifier when its issuer
  is not in the response (`SCP11/shared/certificate_view.py`). The DER hex
  lines stay.
- The ASN.1 / BER-TLV decoder (`yggdrasim-asn1`, the `asn1Notation` of the
  MCP `asn1_decode` tool) draws DER carried in an OCTET STRING or BIT
  STRING as nested value notation (`ASN1_OCTET_STRING [04] encapsulates {
  ... }`) instead of a dump of every item field, and shows the text of an
  undecoded printable primitive beside its hex. A BIT STRING counts as
  encapsulating only when its first element is constructed, so an EC point
  keeps its payload hex. The JSON items are unchanged.
- The SAIP workbench's Token editor is the Variables panel: one row per
  placeholder with a value input (Enter stores it), the type and width,
  and a Source badge that says where the value comes from (Typed,
  Profile list, Universal list, List value, Unset; Catalog default, Token
  or Referenced for the other kinds). "Use list value" drops a typed value
  for the lists' answer, the name form folds under "Set a variable by
  name", the list controls (bind, apply, export, edit) and the complete
  export sit above the rows, and a tokenized field opens the panel on its
  variable. The ribbon's Tokens group carries two entries, Variables and
  Export complete profile; the three list actions left it and stay in the
  action palette. `saip.list_variables` reports `test_value_source` per
  inline row. The ProfilePackage shell verb `VARIABLES` lists, sets,
  clears, binds and exports over the active template in one place, for
  inline typed placeholders and for the `{NAME}` tokens of a tagged JSON
  template alike; `FILL`, `EXPORT-LIST` and `LISTS` fold
  `APPLY-UNIVERSAL-TOKENS`, `TOKEN-LISTS EXPORT` and `TOKEN-LISTS` under
  it, and the main `HELP` listing names only `VARIABLES` with the long
  form under `HELP TOKENS`.
- The typed placeholder spelling is the only one the tool writes: a new
  test-value list is written typed whatever the universal list uses (an
  existing list keeps its own spelling, `STYLE=universal` still follows
  the universal list), and a vendor template's compact literals are
  respelt on request: `VARIABLES NORMALISE` in the shell (dry run, then
  `IN-PLACE` with a `.bak` copy or `OUTPUT=`), "Typed spelling" in the
  Variables panel (`saip.normalise_placeholder_spelling`, which rewrites
  the session's literals and leaves the values bound). The panel shows
  the token sidecar export and the `{NAME}` style chip only for a package
  that carries legacy tokens.
- The typed placeholder spelling (`{iccid:ICCID:10:nibble_swap}`) is the
  default style of the SAIP test-value lists. A list with neither a
  `# style:` line nor a placeholder entry is written typed, and
  `TOKEN-LISTS EXPORT` and the GUI's list export fall back to it when no
  universal list is loaded; a list written in a compact spelling
  (`iccidICCID10NibbleSwap`, `[...]`, `{...}`) keeps it, and every
  spelling is still read. The typed spelling of the TEXT modifier is
  `utf_8` (`{pin1:TEXT:4:utf_8}`), in line with `nibble_swap` and
  `encode_imsi`; `utf8` is still accepted and names the same placeholder.
- The Local SM-DP+ shell enables the profile it has just installed:
  once `LoadBoundProfilePackage` returns a Profile Installation Result
  with `successResult`, `LOAD-PROFILE` (and the GUI "Load profile"
  action) selects ISD-R again and sends `EnableProfile` for the ICCID the
  result names, or the ISD-P AID when the notification metadata carries
  no ICCID. This answers the SGP.22 v3.1 section 3.1.3 step 8 question
  ("enable the profile after installation?") without a prompt. The eUICC
  performs the implicit disable and the PPR1 check itself (section
  5.7.16); a refused enable is reported after the load banner and the GUI
  result, and does not turn the successful install into a failed load.
  `AUTO_ENABLE_AFTER_LOAD = False` in `LocalAccessConfig` restores the
  download-only behaviour, and the Local eIM shell keeps it off.

- The desktop window announces itself as `yggdrasim` on Wayland. Both
  toolkits derive the xdg-shell app_id from the process -- Qt from the
  interpreter's basename, GTK from `g_get_prgname` -- so the window came
  up as `python3`, took the fallback icon, and could not be addressed by
  a window rule. The name is the basename of the desktop entry
  `scripts/install_shortcuts.py` writes. X11 is unchanged, because Qt
  takes WM_CLASS from `argv[0]` there and ignores the desktop file name.
- One seat starts and stops the Card Bridge on a rig, and which of the
  two it offers follows the rig poll rather than what the page last
  started. A local bridge running for a Remote Lab card offer no longer
  reads as a rig stream, hides the rig chooser, and points the button at
  a teardown nothing on the page began.
- `SCP11.relay` is described as the compatibility namespace aliasing
  `SCP11.live` that it became, not as a separate PC/SC entry point.

- Key material prints in full. The SCP80 shell's `show` and the SCP03
  shell's `CONFIG` print KIc / KID and KENC / KMAC / DEK / ADM instead of
  `<redacted>`; the GUI's SCP03 "Show config" leaves "Mask key material"
  off by default; AUTHENTICATE prints CK / IK / Kc on both surfaces
  without a reveal step. The EF.Keys / EF.KeysPS decoder returns KSI, CK
  and IK (it was a length-only summary), EF.EPSNSC and the 5GS NAS
  security contexts return K_ASME / K_AMF, EF.5GAUTHKEYS returns K_AUSF /
  K_SEAF, and EF.GBABP / EF.GBANL return RAND and the B-TID. The
  YggdraCore subscription list carries `k_hex` / `opc_hex`, the Open5GS
  read returns the stored K / OPc, the SAIP `info` summary prints each
  security-domain key component, the SSIM EAP-TLS inspector returns a
  private key's DER, and the `secret_outputs_redacted` marker on GUI
  results is gone. The GUI's SCP80 "Show config" describes
  `kic_indicator` / `kid_indicator` and prints `kic` / `kid` as stored;
  it ran the key material itself through the keyset describer. Auth
  tokens, PIN entry masking and the APDU trace's credential-payload
  redaction are unchanged.
- A template placeholder's value is edited in place: below the hex pane
  of a file, and below the ICCID row of the Profile Header, a "Decoded
  value" field shows the digits, text or hex the placeholder carries by its
  declared type, and "Apply value" stores it through `saip.set_variable`
  and re-fetches the surface so the hex pane, the wizard and the binding
  chips follow. The "Edit value" browser prompt is gone; every file redraw
  (Apply hex, record edits, wizards) now reaches a PE's template-file panel
  as well as the FS-tree file detail.
- The EF.SMSP record wizard edits the parameter block field by field per
  3GPP TS 31.102 §4.2.27: the Parameter Indicators as present/absent
  switches, TP-Destination Address and TS-Service Centre Address as type
  of number, numbering plan and digits (SM-TL length in semi-octets per
  TS 23.040 §9.1.2.5, RP length in octets per TS 24.011 §8.2.5.2),
  TP-Protocol Identifier, TP-Data Coding Scheme and TP-Validity Period as
  bytes, the last decoded to its relative duration (TS 23.040
  §9.2.3.12.1), with a live preview of the 28-byte block.
- The HIL Bridge toolbar is grouped into Session, Source, View and Backend
  controls, with the backend probes and service actions behind one overflow
  menu, and an empty packet list explains the three steps to a first
  session. The Remote Bridge page leads with the onboarding panel, a
  three-step guide, one primary action and grouped manual controls, and
  shares the page-header pattern of Remote Lab. Across the GUI the button
  variants `btn-small`, `btn-secondary`, `btn-ghost` and `btn-danger` are
  defined once, corner radii use the radius tokens, modal scrims and shadows
  come from new `--scrim` and `--shadow-modal` tokens, the file-kind chips
  share the file-system tree palette, the remaining Nord literals resolve
  through theme tokens, and the theme picker, log-dock handle, SAIP record
  navigator and action palette keep a visible focus ring.

- A file size and a maximum file size may exceed two bytes: TS 102 221 v18.4
  sections 11.1.1.4.1 and 11.1.1.4.6.7 both give the value as "length X, X at
  least 2", so both surfaces now accept up to four bytes and emit the length the
  value needs. Record length stays two bytes, which is what the create-file data
  field fixes it at.

- The eUICC information tag 90 is labelled "LPA/IPA Mode" because SGP.22 v3.1
  calls it lpaMode and the SGP.32 v1.3 module calls the same tag ipaMode. The
  registry view reads both GET STATUS subsets so supplementary security
  domains still appear now that the Issuer Security Domain subset returns only
  the issuer's domain.
- CREATE FILE builds cyclic and BER-TLV structure elementary files on both
  surfaces, RESIZE FILE carries the proprietary template of TS 102 222 v17.1
  table 18, and the privileges step offers the byte 2 and byte 3 flags of GPC
  v2.3.1 tables 11-8 and 11-9. A resize to size zero empties a file, so the
  graphical action asks for an explicit confirmation before sending it.

- GET STATUS sets P2.b2 (`02` for the first call, `03` for the next
  occurrences) so the card answers in the TLV format of GPC v2.3.1 table
  11-34; the `00`/`01` form the shell used is deprecated there and a card may
  reject it. The simulator ignores P2.
- The SCP03 STK terminal follows TS 102 223 v18.3 for a headless harness:
  reserved TERMINAL PROFILE bits are zero, REFRESH with qualifier `04` resets
  the card and repeats the profile download instead of sending a TERMINAL
  RESPONSE (section 6.4.7), and local-information requests the harness cannot
  serve are answered with general result `30`.
- The CREATE FILE wizards emit the four-byte linear-fixed descriptor of TS 102
  222 v17.1 table 4 (the card derives the record count from the file size),
  require the security-attribute step, omit tag 88 when no SFI is given so the
  card derives it from the file identifier, and the PUT KEY wizard sends DES
  keys with GPC key type `80`.
- `current_fcp["sfi"]` holds the short file identifier number (tag 88 shifted
  right by three) instead of the raw byte, which is what the profile validator
  compared against; `sfi_raw` keeps the byte. `SCP03/seeds/fids.txt` is only
  copied into a workspace that has none, so an existing `Workspace/SCP03/
  fids.txt` keeps its old tree until it is deleted and re-seeded.

- One PC/SC transport serves every SCP11 shell. `SCP11/transport.py` now
  carries what only the live copy had -- the STK bootstrap, the
  proactive-command drain after a `91 XX` status word, and a GET RESPONSE
  that keeps the logical-channel bits of the command it follows -- next
  to the concise, raw and quiet trace modes the local shell relies on.
  The live shell and the GUI open the channel quiet, so their output is
  unchanged; `SCP11.live.transport` is an alias of the shared module. The
  same fold removes the live copies of `asn1_registry`, `crypto_engine`,
  `payload_builder` and `pysim_support`, so the live shell decodes
  against the SGP.22 v3.1 `StoreMetadataRequest` schema supplement its
  own copy had never received.

- The core modules are readable source again. Fifty-two modules under
  `SCP03/`, `SCP80/` and `main/` had been through a minifier since commit
  `5f4b08b` in February 2026, and every release from v1.0.0 to v2.1.0
  shipped them that way: statements collapsed onto one line, spacing
  stripped, and roughly four fifths of their comments removed.
  Thirty-six files needed reformatting. Each parses to the same syntax
  tree before and after -- the one exception is `SCP03/main.py`, where a
  docstring lost two trailing spaces -- so no behaviour changed. Under
  GPL-3.0 this matters beyond readability: minified source is not the
  preferred form for making modifications. The comments the minifier
  removed are not recoverable from these versions.

- The APDU dissector's tree reads the way Wireshark's `gsm_sim` does. Every
  byte appeared under two or three names before: `P1` and then
  `Selection control` for the same byte, `Status word: 612B - Success` and
  then `[Status: Success]` under it, a SELECT by AID printing its sixteen
  bytes as `Application identifier` and again as `Command data`, and each
  COMPREHENSION-TLV rendered once as raw bytes and once more in a block of
  readings collected after the run, decoupled from the tags they came out
  of. A reading now sits on the line of the byte it decodes, the class and
  constructed bits of a tag are rendered as the bit fields ITU-T X.690
  clause 8.1.2 defines, and the split bookkeeping is one collapsed
  `Framing` node instead of six lines above the APDU. The fields that only
  restated a neighbouring line -- `yapdu.sw_meaning`, `yapdu.detail`,
  `yapdu.command_name`, `yapdu.tlv.name`, `yapdu.tlv.uint` -- stay
  addressable by display filter, custom column and `-T fields`, so the
  bundled Wireshark profile and the HIL-Bridge field queries are unchanged.
  A capture's expanded tree is a fifth shorter and the first level under
  each frame a third of its former size.

- Two dissector display-filter fields are gone. `yapdu.le_effective` and
  `yapdu.risk_name` each restated the line above them, and both readings
  now sit on the field they qualified: filter on `yapdu.le` and
  `yapdu.risk` instead. Every other field named in this section is still
  resolvable -- they are hidden from the detail tree, not removed -- so
  the bundled Wireshark profile and the HIL-Bridge field queries are
  unaffected. A saved filter naming either of these two needs updating.

- `Le` points at the Le bytes rather than at the class byte, so selecting
  the field selects what it describes -- one byte in a short command, three
  in a case 2E and two in a case 4E (ISO/IEC 7816-4 clause 5.1) -- and the
  effective count is appended to it instead of occupying a second line.

- One EF.ARR decoder serves the live view and the profile view. Both read
  the access-mode byte through ISO/IEC 7816-4 tables 17 and 18 as ETSI TS
  102 221 §9.2.4 applies them, and each had its own hand-rolled copy of
  the tables, which is how the two drifted. The SAIP decoder now owns
  them and takes a `scope`, because the same byte names different
  operations depending on the kind of file whose FCP cites the record: a
  DF or ADF reads the low three bits as DELETE CHILD / CREATE EF /
  CREATE DF where an EF reads READ / UPDATE / APPEND. A record read at a
  level rather than through one FCP prints both readings whenever they
  name different operations.

- The file-kind chips in the file-system tree read one palette. Twelve
  `--tree-*` tokens now sit at `:root` and derive from `--accent`,
  `--surface` and `--border`, so all sixteen themes inherit the same
  four-step ramp -- filled root, outlined application, neutral folder,
  hairline file -- rather than two Nord themes carrying a copy and the
  rules carrying a legacy hue as an unreachable fallback. Kind is a
  hierarchy, so weight encodes it, and `--ok` / `--warn` / `--fail` stay
  free to mean status in the same views.

- The BIP payload decoder existed in three copies that disagreed.
  `cat.lua` named thirty-seven `AlertDescription` values and the HIL
  decode view named two, so an eIM rejecting a chain read as
  `unknown_ca` in a capture and `0x30` in the terminal. The registries
  move to `yggdrasim_common/tls_tables.py`, `live_decode_state` drops
  its copy, and `cat.lua` takes its four TLS tables from the generator,
  which puts them under the digest guard that already covers the rest.
  The rendered strings are unchanged, except that a DNS response whose
  question does not parse is no longer reported: naming it from the
  header alone invents a response out of whatever the channel carried.

- No SGP.26 certificate, key, or reference bundle is tracked. The tree
  is gitignored and an operator supplies it locally;
  `SCP11/TEST_MATERIAL_NOTICE.md` records where it goes and how the
  suites behave without it.

- The STK history lists on the live session state, the pending BPP
  segments, the declared toolkit services, the menu selections and the
  GBA NAF-key map are capped at `MAX_HISTORY_ENTRIES` (256). A
  long-running session appends to them on every cycle, so each grew for
  the life of the process. Reset such a
  field with `clear()`; assigning `[]` puts an unbounded list back.

- The download-profile WebSocket event queue is capped and drops its
  oldest event rather than blocking the flow on a client that stopped
  reading.

- An eIM's `retry_after_seconds` is clamped to five minutes, so a
  misbehaving server cannot stall a bounded poll round indefinitely.

### Removed

- `bootstrap_stk()` on the SCP11 transport (`PcscApduChannel`,
  `SGP22Transport` and the `ApduChannel` protocol). Nothing called it, and
  the TERMINAL RESPONSE it sent was the fetched proactive command with a
  result appended rather than a terminal response.
- Command stubs on the SCP11 live and test consoles and the Local eIM
  shell, and one Command Center action, that had no implementation in this
  build: each only reported an error.
- `scripts/release/validate_release.py sanitize`. The pre-release
  identifier scan is `scripts/check_repo_hygiene.py`.

- The second copy of the SCP11 relay shell. `SCP11/orchestrator.py`,
  `SCP11/console.py`, `SCP11/es9_client.py`, `SCP11/models.py`,
  `SCP11/config.py`, `SCP11/factory.py` and `SCP11/providers.py` were an
  older fork of the `SCP11/live` modules that `python -m SCP11.relay`
  still started, and the two had drifted apart by some four thousand
  lines. `SCP11.relay` now aliases `SCP11.live` the way `SCP11.test`
  already did: `python -m SCP11.relay` and `yggdrasim-scp11-relay` open
  the eSIM management relay, read `Workspace/SCP11/live/`, load plugins,
  and keep `DOWNLOAD-AC`, `GET-METADATA`, `EIM-DISCOVER` and
  `EIM-DOWNLOAD` as aliases. Two habits leave with the old fork: it
  printed a synthesised eIM acknowledgement when the eIM answered a
  package result with nothing at all, and its `DELETE-PROFILE` enabled
  another Profile before deleting an enabled one, where the shared
  contract disables the target and deletes it.

### Fixed

- The windowed desktop executable (`yggdrasim-gui-clean`, built with
  `console=False`) and the `pythonw -m main.gui` shortcut fallback no
  longer exit at start with `AttributeError: 'NoneType' object has no
  attribute 'write'`. Without a console, `sys.stdin`, `sys.stdout` and
  `sys.stderr` are `None`, and a default install writes a plugin-loading
  notice on every start. `main/gui.py` now repairs the missing streams
  before the launcher loads, as `yggdrasim-desktop` already did. Skipping
  the notice alone is not enough: uvicorn's logging setup calls
  `sys.stdout.isatty()` next.
- The HIL Bridge live-decode view's refresh timers stop with the view.
  Textual removes the screens before it stops an app's timers, so a tick
  that landed in between could end the view on `NoMatches: No nodes match
  '#status_line'`.
- A stopped SCP11 Command Center run whose command ignores the stop flag
  no longer ends its worker thread on `RuntimeError: Event loop is
  closed`. The stream closes when the run is stopped and the command
  keeps running; what it reported after its event loop had closed (at
  server shutdown, or under a caller's own `asyncio.run`) raised in the
  worker, and is now dropped.
- The Local eIM guide's sections on IPAd discovery and the handover
  context are whole again: an earlier edit had cut their headings and
  left sentence fragments behind.
- The vendored `xterm.js` is byte-identical to xterm 5.3.0 again. A text
  sweep had turned its four NO-BREAK SPACEs into spaces, so an underlined
  or overlined blank cell lost its decoration in the terminal panel;
  `tests/test_gui_vendor_integrity.py` now pins each vendored library to
  the digest of its upstream release.
- `load_schema()` in `Tools/ProfilePackage/saip_structure_edit.py` reads
  pySim's SAIP ASN.1 modules as UTF-8, not in the locale's codec, which on
  Windows is cp1252.
- `scripts/generate_apdu_dissector_tables.py --check` and the dissector's
  drift tests pass in a checkout without the gitignored specification
  library, as in CI. The RSP member names the generator reads from the
  converted SGP.22 and SGP.32 documents are kept in
  `scripts/apdu_dissector_rsp_members.json`: `--write` refreshes it beside
  `tables.lua`, a checkout without the library renders from it, and one
  with the library checks that it is current.
- Privilege byte 3 b4 is Self-Removal (GP Card Spec v2.3.1 Table 11-9,
  page 149), not an RFU bit, in the security domain decoder and the GUI
  privilege tables; a one-byte privileges field reads as byte 1 (Table
  11-43, page 179).
- The simulated card's AUTHENTICATE reads P2 against the selected
  application (TS 31.102 v19.5 Table 7.1.2-1, TS 31.103 v19 §7.1.2).
  P2 '82' is VGCS/VBS on the USIM and HTTP Digest on the ISIM; neither
  is implemented, so it answers '98 64' instead of running AKA as "IMS
  AKA". IMS AKA is P2 '81' under the ISIM and answers RES, CK and IK
  without Kc (§7.1.2.1). '80' is reserved on the ISIM, and '85' / '86'
  are RFU with INS '88'.
- GBA follows TS 31.102 v19.5 §7.1.1.4 / §7.1.1.5 / §7.1.2.3 / §7.1.2.4
  and TS 31.103 v19 §7.1.1.2 / §7.1.1.3 / §7.1.2.3 / §7.1.2.4: both
  modes run on P2 '84' and the 'DD' / 'DE' tag picks one (NAF
  derivation used to sit on P2 '85'). Bootstrapping Mode undoes the
  MAC modification of TS 33.220 v19.1 §5.3.2, answers RES with its
  last bit flipped instead of RES, CK and IK, and writes RAND to
  EF_GBABP. NAF Derivation Mode keeps Ks_int_NAF, fills EF_GBANL and,
  on the ISIM, reads IMPI from EF_IMPI. A GET CHALLENGE between the two
  modes no longer replaces the bootstrap RAND. The default simulated
  USIM does not offer GBA (no service n°68) and answers '98 64'.
- ADF.ISIM's EF.IMPI holds the NAI as the tag-'80' TLV of TS 31.103 v19
  §4.2.2; profile images that stored the bare NAI still load.
  EF.GBABP starts as 128 'FF' bytes in its length-prefixed layout
  (§4.2.9) instead of three TLVs, EF.GBANL has two 128-byte records
  and UPDATE ADM (§4.2.10), and EF.IST no longer advertises HTTP Digest
  or GBA-based Local Key Establishment (services 3 and 4).
- The SAIP workbench shows a file that generic file management creates
  with its Fcp fill or repeat pattern. `saip.show_file` built no pySim
  `File` for a `fileManagementCMD[i][j]` address, so the hex pane, the
  record decoder, a link to the file and the session snapshot read every
  unwritten byte as 'FF' (an EF.SMS declaring `fillPattern '00FF'H` showed
  no '00' record status). The image now comes from the live `createFCP`
  span the body editors write through, with the pattern laid into each
  record (ETSI TS 102 222 V17.1.0 section 6.3.2.2.2).
- An FCP edit (`saip.update_file_field`) on a file that generic file
  management creates wrote into the first `createFCP` of its transaction
  that already carried the member, not the addressed one: setting EF.AD's
  `efFileSize` changed EF.LP's, and the edit looked reverted. It now lands
  on the `createFCP` its address names (TCA SAIP V3.4.1 section 8.3.5).
- An FCP edit that changes a file's type, record length or size returns
  the file to the content it is created with -- its fill or repeat
  pattern, the template default, or FF -- and drops the content and the
  placeholders it held (ETSI TS 102 222 V17.1.0 section 6.3.2.2.2, TCA
  SAIP V3.4.1 section 8.3.3); so does a size edit that leaves content
  running past the declared size. The workbench logs the reset. The image
  of a template file follows an FCP edit at once instead of the copy pySim
  built when the package was loaded.
- pySim read a template file's `proprietaryEFInfo` only when its Fcp also
  repeated `fileDescriptor`, so a fill or repeat pattern set on a template
  file never reached its image. `saip_pysim_compat` compensates; the
  evidence and the upstream patch are in
  `upstream_patches/osmocom-pysim-saip-proprietary-efinfo-without-descriptor/`.
- A hex edit on a template file saved bytes other than the ones shown.
  pySim's optimised encoding diffed the body against the template default
  even where the file's Fcp declares its own fill or repeat pattern (TCA
  SAIP V3.4.1 section 8.3.3), and computed each `fillFileOffset` as an
  absolute position although section 8.3.5 moves the pointer from where
  the last write left it, so every changed run after the first landed too
  far into the file. `saip_pysim_compat` re-encodes against the content the
  file is created with, with relative offsets, and checks the result
  rebuilds the body (`upstream_patches/osmocom-pysim-saip-optimised-body-encoding/`);
  the view shows the file rebuilt from the tuples written.
- The FCP tab no longer shows `specialFileInformation` '00' and
  `fileDetails` '01' on every file with a `proprietaryEFInfo`, nor flags
  that `fileDetails` as forbidden outside BER-TLV EFs: they are the ASN.1
  DEFAULTs of TCA SAIP V3.4.1 section 8.3.2, which DER never encodes (ITU-T
  X.690 (02/2021) section 11.5) and the decoder fills back in.
- A record that still holds what its file is created with -- the fill or
  repeat pattern, the template default, or FF -- counts as unallocated, so
  an EF.SMS whose slots carry the '00FF' pattern lists them as unallocated
  and the record navigator steps over them; a record written over the
  pattern is the one that reads as populated.
- The FCP tab's fill and repeat pattern rows name a conflict only when
  both patterns are declared (ETSI TS 102 222 V17.1.0 Table 4a note 1); a
  row whose sibling alone is set asks for it to be cleared first.
- The FCP tab of a link entry shows the source file's descriptor, size and
  proprietary information, read-only, instead of the entry's own or the
  template's half of them (TCA SAIP V3.4.1 section 8.3.3 note 1), and an
  access rule naming a linked EF.ARR reads its record on the source file
  instead of reporting it outside the record window. An editable EF size
  shows the bytes it allocates in decimal beside the hex.
- Ctrl/Cmd+Enter applies in every SAIP workbench editor that has an Apply
  button (FCP rows, raw and record hex, the JSON tab, the record editors,
  the profile header, SD and RFM forms), Ctrl+S saves with focus in an
  editor, and a save waits for an apply still in flight, so Ctrl+Enter
  then Ctrl+S writes the applied edit.
- The GetCerts summary listed the issuer's name attributes under the EUM
  certificate's subject and paired the eUICC subject attributes with the
  wrong values; the certificate view replaces it there. The parsed-tree
  GetCerts printer raised on a response longer than 255 bytes.
- Applying the JSON tab of a file that already carried a placeholder
  failed with "pySim rejected the new tuple list: a bytes-like object is
  required, not 'str'": the projection shows the literal, and the apply
  now maps it back to its occurrence. "Set a variable by name" refuses a
  name no placeholder of the package carries instead of storing an orphan
  token definition that changed no byte of the profile.
- The SAIP workbench's element detail fetches a PE its cache has lost and
  repaints when it lands, so storing a variable, applying test values or
  editing the profile header no longer leaves the pane on "Loading PE..."
  until the element is clicked again; concurrent loads of one PE share a
  request. The Profile elements count chip keeps the last known count
  while the list reloads instead of reading zero.
- The AID directory names an RFM instance's default directory beside its
  TARs: the MF, or the ADF its `adfRFMAccess` binds (TCA SAIP V3.4.1
  section 8.8).
- The IPAd `DOWNLOAD` (and the GUI's eIM download action, which runs it) answers an
  eIM package it does not recognise instead of dropping it. A
  GetEimPackageResponse (`BF4F`) alternative outside the four SGP.32 v1.3
  section 6.3.2.6 defines read as "no package", so no
  ProvideEimPackageResult went back and the eIM kept the package pending
  ahead of the ones queued behind it. It is now forwarded once to the
  eUICC as ES10b STORE DATA; the card's answer goes back when it carries
  the package's own tag, and a status word or an empty answer is returned
  as `eimPackageResultResponseError` `unknownPackage(2)` (section 6.3.2.7),
  on which the eIM manages its pending packages (section 5.14.6).
- After serving an eIM ProfileDownloadTrigger, the IPAd `DOWNLOAD` drew
  '6D00' on every later ES10b command of the poll: the SGP.22 download
  closed the poll's ISD-R logical channel when it finished, so the rest of
  the poll went to the basic channel, where ISD-R is not selected. The
  download now closes only a channel it opened, and
  RemoveNotificationFromList reports the eUICC's deleteNotificationStatus.
- The IPAd sends the ProfileDownloadTriggerResult to the eIM with
  ESipa.HandleNotification (`BF3D` on the ASN.1 binding,
  `/gsma/rsp2/esipa/handleNotification` on the JSON binding), as SGP.32
  v1.3 section 3.2.3.1 step 13 requires, instead of
  ProvideEimPackageResult. HandleNotification has no response, so the eIM
  no longer acknowledges the ProfileInstallationResult's seqNumber; the
  IPA removes it from the eUICC once the SM-DP+ has taken it. A trigger
  the IPA cannot use (an Activation Code that is not SGP.22 section 4.1,
  contactDefaultSmdp without a default SM-DP+ address, or no
  profileDownloadData) is answered with invalidPackageFormat (section
  3.2.3.1 steps 3 and 4), and a download that ends without a
  ProfileInstallationResult returns profileDownloadError (section
  2.11.2.3); before, it sent nothing, or the result an earlier download in
  the session had left.
- The SAIP workbench's Generic File Management card states the current DF
  of every file (TCA SAIP V3.4.1 section 8.3.5): a chip names each DF the
  PE creates files in, the file list groups its rows under their DF, and
  the General tab says how the DF was selected (this command's `filePath`,
  an earlier one's, a DF or ADF the PE created, or the MF the PE starts
  at). An ADF's temporary file ID resolves to the ADF's name; before, the
  `filePath` was visible only in the JSON tab and a GFM with several DFs
  read "N distinct parent paths".
- A record template's default value is laid into every record of a
  linear-fixed or cyclic EF (TCA SAIP V3.4.1 section 9, EF ICI: 20 records
  of 38 B): pySim expands it once across the file, so every record but the
  last read back erased where the card holds the default's tail
  (`install_record_aware_template_default`, bug 3 of
  `upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/`).
- The RSP role check refused every real certificate. It read the
  `id-rspRole` policies under `2.23.143.1`, the TCA eUICC Profile
  Package arc, while SGP.22 v3.1 section 2.4a.1.0 and Annex K put them
  under the GSMA arc `2.23.146.1`; every SGP.26 certificate and every
  production SM-DP+ certificate therefore read as "certificatePolicies
  without an id-rspRole value" and an ES9+ download failed right after
  the CA bundle check. The tests built their certificates from the
  module's own table and could not see it; they now pin the literal arc
  and read the SGP.26 material.
- The HIL bridge supervisor seeds the REMSIM client with the remote
  card's ATR. osmo-remsim-client presents a `3B00` placeholder until
  bankd sends a setAtrReq, which the bridge only sends on a modem
  slot-status edge; a modem that was already powered when the bridge
  came up latched the placeholder and reported no SIM until a full
  `AT+CFUN=1,1`. With a remote card the supervisor now reads the relay's
  status endpoint before it spawns the client and passes `-a <ATR>`. The
  seed is skipped for a bridge on a local reader, when the REMSIM
  arguments already carry `-a` or `--atr`, and when the relay is
  unreachable or reports no ATR whose TS byte is `3B` or `3F` (ETSI TS
  102 221 V18.4.0 Annex D); the last two log a warning.
- The SCP03 ribbon no longer collapses under a short viewport. Its
  `overflow: hidden` made it a scroll container with no automatic
  minimum size, so it was the one child of the session column that could
  shrink below its content and it absorbed the whole deficit (37 px
  against 118 px of content, cutting the tab labels in half); it is now
  `flex: 0 0 auto` and the panes, which scroll, take the squeeze. The
  file-system tree indents each nested level by 12 px instead of 18 px,
  so a fourth-level name sits beside its caret and kind chip rather than
  145 px into the panel. The design contract in `gui_frontend/README.md`
  records the rule.
- The SAIP workbench shows a linked file's data. A file-system entry
  whose FCP carries `linkPath` (TCA SAIP V3.4.1 section 8.3.2) shares
  the body of the file it names and takes that file's fileDescriptor,
  efFileSize and proprietaryEFInfo (section 8.3.3 Note 1). The Data
  tab used to render the entry's own empty template image, so
  ADF.USIM/EF.SPN linked to DF.GSM/EF.SPN read as FF bytes with every
  display condition set. `saip.show_file` now follows the link chain
  (a link to a link included; a loop or a missing file is reported)
  and answers with the source file's bytes and layout, decoded under
  the entry's own identity, naming the source under `link_source`;
  the Data tab opens with a "Linked file" card that names and opens
  the source. A body write addressed to a link
  (`saip.update_file_content`, `saip.update_record_bytes`) lands on
  the source file and reports `link_entry` and `link_aliases`, so
  every view sharing the body is refreshed; a link whose source is
  missing, or that carries fillFileContent of its own, is refused.
- SCP03 `CARD INFO`, the identity probe and the GUI GetEID action show
  only a real EID. A card may answer GetEuiccData under '9000' with a
  `BF3E` body that holds no 16-octet `eidValue` '5A' (SGP.22 v3.1
  section 5.7.20); that body was shown as the EID, keyed the device
  inventory and replaced the EID the ECASD had returned for GET DATA '5A'
  (SGP.02 v4.2 section 2.2.2). The eSIM Management shells send the tagged
  request (`BF3E 03 5C 01 5A`) first and the bare `BF3E00` form second,
  and an answer without the value is never reported as the EID.
- The eSIM Management relay and the Local SM-DP+ shell resend a command
  the card answers with '6Cxx' once, with Le = 'xx' (ETSI TS 102 221
  v18.4 section 7.3.1.1.5.0): a case 3 command gets the Le appended
  instead of its last data byte overwritten, a '6Cxx' to a GET RESPONSE
  corrects the GET RESPONSE rather than the command, a second '6Cxx'
  fails instead of looping, and each GET RESPONSE after '61xx' (or
  '9Fxx') asks for the length the card announced. A case 4 STORE DATA
  (GPC v2.3.1 section 11.11.2.1 Table 11-89, P1 b1) answered '91xx' on a
  link not known to run T=1 has its waiting response data collected
  before the proactive command is fetched, and an empty FETCH answer
  ends the drain without failing the command.
- An eIM sweep skips an entry whose eIM is no longer in the card's eIM
  configuration (`BF55`) and names it in the summary. The sweep used to
  select entries by position, so after a deletion an index landed on
  another eIM.
- After `ProvideEimPackageResult`, the IPAd removes every eUICC Package
  Result and Notification the eIM acknowledged (`EimAcknowledgements`,
  `BF53`) from the eUICC with `RemoveNotificationFromList` (SGP.32 v1.3
  section 3.3.1 steps 13 and 15; SGP.22 v3.1 section 5.7.11) and reports
  each `deleteNotificationStatus`; a result the eIM did not acknowledge
  stays on the card.
- The ICCID check digit finding (`YRL-ICC-004`, ITU-T E.118 (09/2025)
  section 6) reports the Luhn remainder, and when the digits pass the
  check once nibble-swapped it says the header was written in EF.ICCID
  order and carries both digit strings as evidence.
- The Local SM-DP+ load failure summary attributes `likelyProtectedChunk`
  to the A3 member whose STORE DATA round returned the
  ProfileInstallationResult, recorded during the load, and says so; the
  chunk carrying PE-End is the guess only when no load recorded the
  index.
- Four FID-map rows of the SAIP workbench (EF.ARR under ADF.USIM,
  EF.PSLOCI, EF.5GAUTHKEYS and EF.TN3GPPSNN) had no render path since
  they were added, which kept the decode-coverage test red: the three
  files have decoders now, and the test credits the `ef-arr-*` keys the
  EF.ARR helper already dispatches.
- The MCP `shell_run` tool refused `RFM`, `TRIM` and `VARIABLES` on the
  ProfilePackage shell as unknown verbs: the three had no entry in the
  server's access table. They sit at the write tier, with `TOKENS`,
  because each dispatches subcommands the leading-verb gate cannot see.
- The standalone `yggdrasim-mcp` distribution ships `remote_readers`
  beside the card transport it vendors and resolves the server's
  remote-reader imports locally. Since the remote reader reached every
  CLI surface, the vendored `card_backend` carried a relative import of
  a module the bundle did not hold, and the server's remote-binding
  paths pointed at the full install.
- The pySim file-template snapshot the SAIP workbench and the card engine
  share (`SIMCARD/saip_pysim_specs.py`) is built after every compatibility
  install, including the one that registers the IoT Minimal Profile
  templates (TCA SAIP V3.4.1 section 9.10.1) and the one that names the
  DF.PHONEBOOK EF.PBC rows pySim labels EF.ADN. It used to depend on what
  ran first in the process: a snapshot filled before a
  generic-file-management package had been decoded lacked those files
  (`ef-arr-usim` among them), and on stock pySim one filled before the
  SAIP JSON codec ran had no `ef-pbc`, until the process restarted.

- The HIL packet list keeps its place. A scroll event does not say who
  moved the list, and the event for a programmatic write is dispatched
  with the next rendering update -- after any timer meant to bracket the
  write has already run -- so the write is recognised by the position it
  asked for instead. The context tree is grouped over the whole retained
  capture and then pruned to the window of frames the client asked for,
  which keeps the poll numbering and the card-session wrappers identical
  to the TUI's, and a category group carries a bare count where a
  structural node counts frames, the way the TUI already reads.

- The SCP03 shell's `VALIDATE` and `SELECT` no longer describe an ADF with
  the descriptor of the file selected before it. The file-system
  controller selected an application with SELECT by DF name and P2 '00',
  a coding ETSI TS 102 221 V18.4.0 Table 11.2 leaves undefined; a card
  that accepted it without returning an FCP left the previous file's
  descriptor in place, so `VALIDATE` graded ADF USIM as a transparent EF
  and `SELECT USIM` printed the MF. The controller now asks with P2 '04'
  (return FCP template) first, falls back to the GlobalPlatform Card
  Specification v2.3.1 Table 11-81 coding P2 '00' when a security domain
  rejects the UICC form, and records the FCP as unknown when a SELECT
  answers without data; `VALIDATE` then reports the missing FCP instead
  of a wrong file type.
- The HIL bridge follows a modem-side UICC reset through to the card in
  the reader. `osmo-remsim-client-st2` reports the modem's RST and VCC
  edges as `clientSlotStatusInd`; the bridge used the first one to send
  the ATR and dropped every later one, so a REFRESH in "UICC Reset" mode
  (ETSI TS 102 223 V18.3.0 clause 6.4.7, the mode SGP.02 v4.2 clause 3.2
  uses to apply a profile switch) reset the SIMtrace2's emulation only:
  the eUICC, never reset, kept serving the profile the switch had just
  disabled, and the modem re-read it as the new one. A RST rising edge
  or a VCC drop now power-cycles the card (the rule osmo-remsim's bankd
  applies), a changed ATR is pushed to the board for the next
  activation, a REFRESH that ends in a UICC reset is logged, and a reset
  that does not follow it within 10 s is reported on the modem's next
  command.
- Save on a package dropped into the browser no longer writes a file
  named `upload:<name>` into the server's working directory. The upload
  label is a display name, not a location: Save now opens the save-as
  picker proposing the dropped file's name, and `saip.save_package`
  refuses the label as an `output_path`. A package opened by path still
  saves back in place.
- The "Sync from EF.ICCID" confirmation on the Profile Header's ICCID row
  survives the re-render the apply triggers instead of landing on the
  replaced row.
- `yggdrasim-scp11-live` no longer dies with `OSError: PC/SC channel is
  disconnected.` on the first command after the init banner (GitHub
  issue #10, seen on macOS). The per-command transport lifecycle unpowers
  the card after every command and cold-boots it before the next one, and
  Apple's bundled CCID driver is known to answer that SCardConnect with
  `SCARD_W_UNRESPONSIVE_CARD` for a card that is powered. Three things
  changed. The PC/SC connect is repeated up to six times on a growing pause
  (about five seconds in all) while the status is unresponsive, unpowered,
  reset or sharing-violation; an exhausted retry raises an error naming the
  reader, the attempt count and the last PC/SC status, and on macOS the
  libccid switch (`useIFDCCID`). The console no longer swallows a failed
  transport rebuild: the command is reported as not started instead of
  sending its first APDU into the released channel, and a transport error
  inside a command returns to the prompt instead of ending the process.
  The ES10 retry ladder stops with the reset error when the power cycle
  between rungs loses the PC/SC handle, instead of hiding it behind the
  next rung's "channel is disconnected".
- The SAIP workbench's "Whole file" hex scope applies to a linear-fixed
  or cyclic EF. `saip.update_file_content` refused every record-structured
  file ("file is not transparent / BER-TLV") and the hex pane reported
  "apply failed", so a record's byte could only be corrected through the
  "Record" scope. The action now takes the whole body of a record EF, sizes
  it as record length times record count, and pads a short write record by
  record with the file's fill or repeat pattern, or with FF when the FCP
  declares neither (ETSI TS 102 222 V17.1.0 clause 6.3.2.2.2). The card
  names the record geometry, and the result carries `file_type`,
  `record_size` and `record_count`.
- The SCP80 shell's default TP-PID is `7F`, (U)SIM Data download (3GPP
  TS 23.040 clause 9.2.3.9); it was `41`, Replace Short Message Type 1,
  a value a modem never hands to the UICC. The build breakdown flags a
  TP-PID other than `7F`, and the SMS-PP command packet is pinned
  byte-for-byte against pySim's encoder for a cryptographic-checksum SPI.
- The SAIP workbench opens a profile whose MF is created by a
  PE-GenericFileManagement instead of a PE-MF (TCA SAIP V3.4.1 §8.1; the
  only layout an IoT Minimal Profile allows). Upstream pySim resolves
  every GFM file through the sequence's MF and raised `AttributeError:
  'NoneType' object has no attribute 'lookup_by_fidpath'` on the createFCP
  that is the MF, so the strict parse failed and the tolerant walk skipped
  both GFM elements. `install_gfm_mf_creation` in
  `Tools/ProfilePackage/saip_pysim_compat.py` roots the created MF, verifies
  it and is pinned against the upstream gap; the evidence and the upstream
  patch are in `upstream_patches/osmocom-pysim-saip-gfm-mf-creation/`.
- A package with bytes behind its `end` PE (a file overwritten in place by
  a shorter revision keeps the old tail) no longer reports that tail as a
  run of broken profile elements: the loader cuts the stream after the
  first `end` PE (TCA SAIP V3.4.1 §8.1 provides PE-End once at the end),
  keeps the strict parse and logs one `trailing_data` warning with the
  offset, the length and the head bytes of the ignored tail.
- Applying a Profile Header field (SAIP version, profile type, ICCID
  digits, policy rules) said "Applied." but the decoded view and the JSON
  projection kept the old value until another PE was selected: the refresh
  looked for the detail pane inside the PE list's parent, which never
  contains it, so nothing re-rendered. The detail is now resolved from the
  workbench root and the confirmation survives the re-render.
- A whole-file wizard (EF.ACC and the other transparent-EF wizards) was
  seeded with the sentinel bytes of a template placeholder while the hex
  pane showed the placeholder's value, so the two disagreed. Wizards now
  read the same resolved image as the hex pane; a placeholder range a
  wizard changes becomes that placeholder's new value when the placeholder
  is hex-typed, and the file keeps its sentinel.
- The EF.ACC wizard follows the coding of 3GPP TS 31.102 §4.2.15: byte 1
  b8..b1 carry AC 15..8 (b3, AC 10, is set to 0) and byte 2 b8..b1 carry
  AC 7..0. The previous form had no AC 8 or AC 9 and labelled b3 as a
  random-backoff class.
- The eIM package trace of the SCP11 live orchestrator (`Full eIM package`
  and `eIM card response`, streamed by the eIM-local shell and the GUI's
  SGP.32 IoT (IPA-d) actions) walked every X.509 certificate in an addEim
  or updateEim package field by field. The certificate detector matched a
  tbsCertificate only when its serial number was short, so a certificate
  with OpenSSL's 20-byte serial fell through to the generic BER walk, met
  the eight-level depth cap inside its Name and Extensions SEQUENCEs
  (`<max decode depth reached>` on every RDN and extension) and spent the
  120-line budget before the eIM signature. The tree now recognises a
  certificate by its RFC 5280 section 4.1 shape under any tag, including
  the implicit `A1` of the SGP.32 v1.3 eimCertificate /
  trustedCertificateTls alternatives, names the four key-material
  alternatives (`eimPublicKey`, `eimCertificate`, `trustedEimPkTls`,
  `trustedCertificateTls`), and pastes each certificate as one DER hex line
  with the SEQUENCE tag restored instead of walking it.

- The SCP03 "Full CAP Install Sequence" wizard sized its OTA LOAD blocks
  at 103 (AES) or 111 (3DES) octets and appended an Le, and the SCP80
  segment estimate it consulted counted a one-octet UDH, so every block it
  printed as "single segment" exceeded the 140-octet TP-UD and the SCP80
  shell refused it. The block size now derives from the builder's
  single-SMS ceiling (`OtaPacketBuilder.single_sms_payload_limit`: a
  98-octet APDU for AES, 106 for 3DES, so 93 or 101 data octets), and the
  OTA lines carry no Le, since the compact remote format (ETSI TS 102 226
  clause 5.1.1) is a T=0 TPDU. The estimate now counts the same UDH and
  concatenation budget as the plan it predicts.

- Export PE's JSON form wrote a flat hex projection that Import PE read as
  three profile elements, its DER and HEX forms left a template session
  with the placeholder sentinel bytes instead of the stored values, every
  import renumbered the whole sequence, and the ribbon's Delete, Move and
  Export PE buttons stayed disabled after selecting a card until an
  unrelated re-render.

- A production release publishes the annotated tag's message as its notes.
  The checkout action re-points `refs/tags/<tag>` at the commit, so
  `gh release create --notes-from-tag`, which reads the local tag, put the
  tagged commit's message on the v2.1.0 release page. `publish-release` now
  reads the message from the tag object the policy gate verified and reads
  the page back after creation, and `scripts/release/release_notes.py`
  refuses, before any platform builds, a tag message that is the commit's
  message, lacks the `YggdraSIM vX.Y.Z` heading or a list of changes, or
  carries a trailer, and a `CHANGELOG.md` that still files work under
  `[Unreleased]` or has no section for the version.

- The GUI no longer rebuilds what has not changed. The HIL dissector repaints
  only the status bar, the packet list or the frame detail whose render key
  moved instead of tearing the whole pane down on every changed poll, its
  status bar ticker compares a signature before touching the DOM, the polls
  pause while the tab is hidden and back off when a decode round trip took
  longer than the interval, and the tail frame's decoded detail waits for the
  stream to pause instead of costing three tshark passes per poll. On the
  server `hil.decode_snapshot` caches the parsed summaries per capture and
  reads only frames past the last one it holds, memoises the replay engine
  and the stateful annotations, keeps a small per-frame detail cache, and
  answers `not_modified` when the caller already holds the detail for the
  frame it would select (new `known_detail_frame` input). The remote-rig
  capture sync runs at most every three seconds and appends only the new
  bytes of the same inode instead of buffering the whole pcap through ssh on
  every poll.

- Long GUI sessions stop accumulating. The reader-strip poll rebuilds its
  pills only when a reader's visible state changed; the log dock rehydrate
  path applies the same 4 KB message cap as the live path; the reader context
  menu dismisses its previous document listeners before installing new ones;
  the HIL window pointer listeners install once per page instead of once per
  workbench state; the SCP03 authentication gate binds one close listener per
  panel; the SAIP workbench reloads a re-opened unmodified file instead of
  stacking a second copy with its own backend session, clears the status node
  of a failed auto-apply job, and debounces the file-tree search; the log bus
  writes the activity stamp and tab badges once per frame; the SCP03 staged
  body decode preview, the APDU breakdown table and the Remote Bridge rig
  fields wait for a pause in typing; resize handlers coalesce to one reflow
  per frame. Processes the GUI stops are unregistered from the shutdown
  registry and reaped, and host-shell decoded-frame sends are tracked and
  cancelled when the socket closes.

- The simulator now accepts what the corrected SCP03 client sends. INSTALL
  reads its segmentation flag from P1 bit 8 rather than P2, parses the make-
  selectable, extradition, registry-update and personalization data fields of
  GPC v2.3.1 tables 11-44 to 11-47, and accepts the BER length forms of tables
  11-42 to 11-46, so INSTALL [for make selectable] works end to end for the
  first time. GET STATUS had the executable-load-file and module subsets
  swapped, reported supplementary domains under the Issuer Security Domain
  subset, matched a search AID anywhere in an entry and omitted the privileges
  object; DELETE ignored the segmentation flag of table 11-21, the security-
  domain modes of table 11-22 and the mandatory response field of table 11-25.
  PROVIDE LOCAL INFORMATION served the battery state on the broadcast-network
  qualifier with a reserved tag, and the SERVICE SEARCH, GET SERVICE
  INFORMATION and DECLARE SERVICE commands used tags belonging to other
  objects. EF_IMSI was written with a fixed length octet.
- The STK terminal no longer claims facilities it cannot serve: the terminal
  profile drops the local-information bits the handler answers with general
  result 30, declares the eUICC profile-state-change mode of TS 102 223 v18.3
  section 5.2 and implements the matching REFRESH, answers GET CHANNEL STATUS
  with no channel open as section 8.56 requires, and refuses an ENVELOPE above
  255 bytes unless the card declared extended length. The transport follows TS
  102 221 v18.4 section 7.3.1.1.4 step 4b, fetching the data a warning status
  word leaves pending on a case-4 command under T=0.
- SEARCH RECORD carries an Le in both the shell and the graphical interface,
  so the card returns the matching record numbers, and the referenced access
  rule is now located by walking to the parent as TS 102 221 v18.4 section
  9.2.7 describes instead of guessing between two file identifiers. The PIN
  layer gained the retry-counter query of section 11.1.9.1.2 and the
  alternative global key reference of section 11.1.11, both reachable from the
  shell, and applies the TS 31.101 v19 section 9.6 digit rules including the
  eight-digit unblocking PIN. The profile validator learned that a file can be
  absent when a service is available, which is what TS 31.102 v19.5 section
  4.2.2 says about EF_IMSI.
- The elementary-file decoders reach the files they used to fall back on:
  EF_BDN, EF_PSISMSC, the IMEI allow-list, the IP service and description
  files, the ePDG identifier and the disaster-roaming wait timers now decode
  their real layouts, and the access-rule parser reads the GlobalPlatform SE
  Access Control primitive data objects that the generic constructed-tag rule
  had made unreadable. Service-table names, the GSM 7-bit alphabet and the
  access-rule key references moved into shared modules, so the profile
  inspector and the shell no longer carry three copies that had drifted apart.
  The access-mode bit tables moved into the shared access-rule module as well,
  so the secure-channel decoder no longer reaches into the profile-package
  tool for them, and the inspector's service-name dictionaries are built from
  the shared clause tables instead of their own copies, which also adds the
  two services TS 31.102 v19.5 added after the copies were written. A record a
  card has never written reads back as nothing but 'FF' padding, which the
  padded parser now reports as an empty record rather than a tag that never
  ends.

- The SCP03 shell's command builders were checked against the library copies
  of GPC v2.3.1, GP Amendment D v1.1.2, TS 102 221 v18.4, TS 102 222 v17.1, TS
  102 223 v18.3, TS 102 226 v19, SGP.22 v3.1 and SGP.32 v1.3. On the wire:
  DeleteProfile sent `BF33 { A0 { 4F | 5A } 81 01 00 }` instead of the bare
  CHOICE of SGP.22 v3.1 section 5.7.18, and GetEID omitted the mandatory `5C
  01 5A` tag list; STORE DATA chunking had the last-block bit of table 11-89
  inverted; INSTALL [for make selectable], [for extradition] and [for
  personalization] missed the empty length fields of tables 11-44, 11-45 and
  11-47, parameter and token fields above 127 bytes used a one-byte length,
  and the case-4 GP commands carried no Le; PUT KEY could not wrap a 24-byte
  AES key and computed no check value for a DES key (Annex B.8); TERMINATE DF
  and TERMINATE EF carried a data field that TS 102 222 sections 6.7.2 and
  6.8.2 do not allow; SUSPEND UICC lacked the duration bytes and the Le of TS
  102 221 section 11.1.22 in the shell and in the GUI action; READ BINARY
  stopped after 256 bytes and UPDATE BINARY produced a malformed Lc above 255;
  the CREATE FILE wizards put the SFI in the low bits of tag 88, sent a tag 83
  inside the UICC system parameters that TS 102 226 does not define, nested
  the CA parameters beside EF instead of inside it and mis-ordered the toolkit
  and access-domain fields of section 8.2.1.3.2.2; the STK terminal set
  reserved TERMINAL PROFILE bits, ignored the comprehension-required bit when
  matching objects, mis-read three-byte tags, attached location information to
  every location-status event and answered POLL INTERVAL, TIMER MANAGEMENT,
  OPEN CHANNEL, SEND DATA and PROVIDE LOCAL INFORMATION without the objects
  sections 6.8 and 8.12 require. The GSM-context AUTHENTICATE omitted the
  length byte in front of RAND (TS 31.102 v19.5 section 7.1.2.1), the GET
  RESPONSE that follows a `9F XX` status on a class `A0` command was sent with
  class `00` (TS 51.011 section 9.4.1), the fallback SELECT by AID used the
  undefined P2 `00`, and closing the logical channel that carries the secure
  session left the host session alive (GPC v2.3.1 section 10.2.3).
- The SCP03 decoders were checked against TS 31.102 v19.5, TS 31.103 v19, TS
  51.011, TS 23.038, TS 23.040, TS 24.008, TS 24.301, TS 24.501, TS 33.220, GP
  SE Access Control v1.1 and the GSMA ASN.1 modules. The FCP parser classed a
  BER-TLV EF as a DF, took a DF's size from the UICC-characteristics byte of
  the A5 template, reported the raw SFI byte, ignored the (SEID, record) pairs
  of tag 8B, and never filled the FCI's maximum data length; every PLMN
  decoder prepended the third MNC digit that TS 24.008 section 10.5.1.3
  appends; the 0x81 alpha-identifier half-page base was shifted from the wrong
  byte; EF_CCP was read as an ADN record; the IMSI, ICCID, SMS parameter, SMS
  record, PUCT, EF_DIR and language decoders deviated in length, alphabet or
  field handling; the RAT operator identifiers, the EPS and 5GS NAS security
  contexts, the 5G authentication keys, the GBA NAF identifiers, the ARF
  access-control files (ACMF, ACRF, ACCF, DODF), the GP SEAC tag names, the
  ARR command-header access modes, the EUICCInfo2 certification data object,
  the eIM public-key CHOICE and the eUICC package result list were decoded
  wrong or not at all; the GP registry used one life-cycle table for every
  object kind and its key-type names stopped at AES; reading the CPLC raised.
  The seed FID tree gained the missing USIM, ISIM and TELECOM files and moved
  the mis-filed ones (EF_BDN is 6F4D, EF_CCP 6F3D, the 5G ProSe DF sits under
  the USIM ADF), and the shell's built-in guides no longer state the wrong KDF
  length field, PIN key references, GET STATUS and SET STATUS parameters,
  privilege names, descriptor bytes or OTA header lengths. The ATR view
  decoded TA(3) as the clock-stop byte even after T=1 (where it is the IFSC),
  left the first TB(i) after T=15 raw and had no Di = 64 (TS 102 221 v18.4
  section 6.3); the status-word table was rebuilt from TS 102 221 tables 10.7
  to 10.15, TS 102 222 table 6, GPC table 11-38 and TS 51.011 section 9.4; and
  the profile validator required EF_ARR at the MF and EF_IST, gated EF_HPPLMN
  on a service it does not depend on, expected SFIs that EF_FDN, EF_SMS and
  EF_SPN do not have, and demanded exact sizes for files the specifications
  define as variable.

- The SCP11 builders and decoders that disagreed with the GSMA and TCA
  modules now follow them, each pinned by a vector encoded from the official
  ASN.1 in `tests/test_scp11_spec_vector_fixes.py`. On the wire:
  ProvideEimPackageResult's error branch is `A0 03 02 01 xx`, not a
  primitive `80` around a SEQUENCE; the addEim and updateEim key material is
  carried as `A5 { A0 <SubjectPublicKeyInfo> }` or `A5 { A1 <Certificate> }`
  with the implicit tag replacing the SEQUENCE tag, in both eIM-local
  builders, and the simulator accepts that shape; PSMOs select a Profile by
  ICCID only and pack it into the ten EF_ICCID octets; the metadata codec
  nibble-swaps the ICCID as EF_ICCID does, so a StoreMetadataRequest built
  from a document matches the Profile's EF_ICCID (SGP.22 v3.1 section
  5.5.3); `profileOwner` is only emitted with a PLMN, and negative INTEGERs
  are minimal. On the reading side: ProfileDownloadTriggerRequest exposes
  which ProfileDownloadData alternative the eIM chose, the relay serves
  activationCode and contactDefaultSmdp and answers contactSmds and the
  empty trigger with a ProfileDownloadTriggerResult error instead of
  pushing the request into the eUICC, transaction-id bytes are never read
  as an activation code, and a zero-length MatchingID is accepted while an
  AC_Format other than 1 is refused (SGP.22 v3.1 section 4.1);
  IpaEuiccDataRequest's euiccCiPKIdentifierToBeUsed reaches
  ES10b.GetCerts as `BF56 { 80 pkid }`; ProfileInstallationResult reads
  ErrorResult as bppCommandId, errorReason and ppiResponse (tags 80, 81,
  82) and picks euiccSignPIR up beside BF27, with the v3.1 ErrorReason and
  BppCommandId names; EUICCResponse is decoded as the TCA PEStatus list with
  the abort flag and status message rather than an invented result CHOICE;
  a ProfileInfoList is walked as `BF2D { A0 { E3 ... } | 81 error }` so a
  length octet of `E3` no longer empties LIST; additionalRootDsAddresses
  elements are read with their universal UTF8String tag; NotificationMetadata
  ICCIDs in the local shell are read as EF_ICCID; OBJECT IDENTIFIER
  decoding follows X.690 clause 8.19.4 for arc 2 values above 2.47 and
  refuses truncated or non-minimal subidentifiers; the ES9+ AuthenticateClient
  response is read with the schema key `transactionId`; the download error
  code 4 is `noSession`, the profile-state result 7 is `commandError`, and
  profileDownloadErrorReason knows only ecallActive and undefinedError. The
  relay no longer sends the eUICC firmware version as rPLMN: EUICCInfo2
  carries no PLMN, so `EIM_GET_PACKAGE_RPLMN` is the only source. `BF50` is
  reported as the ProvideEimPackageResult it is instead of as an indirect
  download trigger. The simulated eUICC's ProfileInfoListResponse now holds
  its ProfileInfo entries directly under `A0`, as the module encodes it,
  rather than inside a second SEQUENCE; the shared list splitter still reads
  the older shape.

- The eSIM management relay decodes `profileManagementOperation` as the
  BIT STRING it is. `NotificationMetadata` carries a `NotificationEvent`
  under the implicit tag `81`, whose first contents octet is the unused-bit
  count (ITU-T X.690 clause 8.6.2.2); the live orchestrator read the
  contents as an integer and reported `notificationInstall` as 1920. The
  strict decoder the local-access shell and the old relay copy carried
  separately now lives in `SCP11/shared/notification_event.py` and serves
  both consumers, so a malformed, duplicate or non-canonical bit string
  is reported as a parse error instead of a number. The same pass makes
  the relay refuse to forward a notification whose `notificationAddress`
  is not valid UTF-8: the old copy kept the bytes as hex and used the
  configured ES9+ base URL, the live one dropped the invalid bytes from
  the FQDN and forwarded to what was left.

- The relay's readers accepted what the standards reject and rejected what
  they allow. The BER length octet `FF` is reserved (X.690 8.1.3.5) and now
  stops a decode in the relay, the local session, the ES9 client and the
  shared TLV reader, which also takes four length octets rather than two;
  AuthenticateServerResponse is only read from its `A0` / `A1`
  alternatives; a pending notification is taken from the
  RetrieveNotificationsListResponse structure itself (SGP.22 v3.1 section
  5.7.10, with the SGP.32 compact forms) rather than through pySim, so a
  missing pySim no longer empties the list; a provider string is decoded as
  hex or base64 by whichever parses as one complete TLV instead of by
  alphabet; non-digit BCD nibbles render as their hex letter instead of
  digits; a Profile Nickname or Service Provider Name in UTF-8 beyond ASCII
  is shown as text (SGP.22 v3.1 section 2.4a.2); PPR bit strings of `00`
  read as none and an unused-bit count above 7 as invalid (X.690 8.6.2); an
  ICCID longer than the twenty digits of EF_ICCID is refused (ETSI TS 102
  221 v18.4 section 13.2); short metadata values are no longer hex-dumped;
  the notification collector only descends into constructed values, or an
  OCTET STRING holding a complete TLV run, so a signature can no longer be
  mistaken for a list entry; EUICCInfo2 names tag `95` as the eUICC minimum
  security level and IoT tag `83` as fallbackAllowedUpdateSupported; and
  the eIM discovery snapshot labels the identifier `eimId`.
- Certificates are checked for their RSP role (SGP.22 v3.1 section
  4.5.2.1): the server certificate of an ES9+ session has to carry
  id-rspRole-dp-auth or -ds-auth, the CERT.DPpb.SIG of PrepareDownload
  id-rspRole-dp-pb, in either the v2 or the v3 arc; a mismatched role
  fails the session, a certificate without the extension is noted. A PEM
  bundle now contributes every certificate it holds to the CA ladder, not
  only the first, and a certificate file is recognised as PEM by its
  content rather than its suffix.
- The HTTP bindings follow their specifications: ES9+ requests carry
  `User-Agent: gsma-rsp-lpad`, `Content-Type: application/json;charset=UTF-8`
  and `X-Admin-Protocol: gsma/rsp/v2.1.0` (SGP.22 v3.1 section 6.5.1.4),
  AuthenticateClient and GetBoundProfilePackage bodies carry no
  `smdpAddress`, and ESipa requests carry `User-Agent: gsma-rsp-ipad` with
  `X-Admin-Protocol: gsma/rsp/v1.3.0` by default (SGP.32 v1.3 section 6.1).
- The BPP segmenters send the secondSequenceOf87 header in the same segment
  as its first `87` (SGP.22 v3.1 section 2.5.5) instead of as a segment of
  its own; A1 and A3 keep their own segment.
- The simulator's GetCertsResponse wraps `certs [0]` around `A5` / `A6`
  values that hold the certificates' SEQUENCE contents, as the implicit
  tags of SGP.32 v1.3 require, and the GetCerts decoder restores the
  SEQUENCE header for that shape while still reading the earlier full-DER
  form. The eIM package linter accepts every EimPackageResult alternative
  of SGP.32 v1.3 and wants `eco_choice_tag_hex` as the constructed `A8`
  wire tag, which the shipped templates now carry.

- The light themes separate their surfaces again. Every light palette
  now paints the canvas a step below its cards, keeps the cards white (or
  the palette's own paper tone), draws a firmer hairline border and a
  crisp two-layer card shadow, and the module workbench frame uses the
  canvas colour so panes, cards and tool panels read as raised islands
  instead of white blocks on a white slab. The reader gate card and the
  dashboard sections carry the card shadow, and `islands-light` and
  `graphite-light` finally declare `color-scheme: light`, so native
  controls and scrollbars stop rendering dark inside them. Secondary
  text and the status colours were re-checked against the deeper
  surfaces and darkened where the 4.5:1 floor demanded it.

- The session-recovery ladder stops power-cycling cards that answered.
  It now resets only on positive evidence that the link failed -- pyscard's
  own exceptions and the transport's PC/SC link errors -- because a status
  word means the card is talking and declined, and a reset would end a
  session that was never broken. TERMINAL PROFILE is no longer replayed
  mid-session either: ETSI TS 102 223 §5.1 scopes it to the start of a card
  session, and the minimal body the ladder sent is narrower than the profile
  STK bring-up negotiates, so a card that accepted it silently lost
  proactive features.

- The shipped reference profile no longer carries real-world identifiers.
  Its `sdPersoData` block held an allocated public IPv4 address and two
  allocated ICCIDs, written as hex-encoded ASCII inside the TLV --
  a form `scripts/check_repo_hygiene.py` does not match, since it reads
  ASCII and packed BCD. All three now hold reserved-range values of
  identical length, so every enclosing DER length byte is unchanged. The
  eIM certificate configs use `C=XX / ST=TestState / L=TestLocality`, the
  OTA ICCID placeholder uses the `8988` test range, and the GUI About
  panel no longer describes itself as scaffolding for an internal
  roadmap entry.

- `Tools.CardClone` ships. It was absent from the packaging include list
  and the reviewed-package manifest, so the wheel declared
  `yggdrasim-card-clone` and shipped nothing behind it: the entry point
  died with `ModuleNotFoundError` on a clean install.

- Every lint finding outside the in-flight working tree is cleared: 540
  down to one, and that one sits in an uncommitted file. Reformatting
  accounted for the 180 collapsed-statement findings (E701/E702), which
  the repository's own coding standard already forbade. The 249
  comparisons to `True`/`False` (E712) were rewritten only where the
  operand is provably a bool: 229 by static analysis over a repo-wide
  index of bool-returning callables, and the last twenty after reading
  each producer, because `d.get(k) == False` is not `not d.get(k)` when
  the key is absent. Of the 96 imports below the top of their module
  (E402), twelve were inert statements sitting between import blocks and
  were moved; 48 genuinely follow a `sys.path` or `sys.modules` side
  effect and now say so. The eleven assigned lambdas (E731) became
  functions, and the six `l` variables (E741) were renamed for what they
  hold.

- Four tests were written against minified source spellings. Three broke
  once the source was formatted -- they searched for `cmd =f"80F0...`,
  `read_text (encoding ="utf-8")` and `"name":"MF"` -- and now compare
  whitespace-condensed text, so formatting is not something a test can
  fail on. The fourth had already gone silent: pinned to `p1 ="80"`, its
  regex matched nothing once the module was formatted, and an empty set
  is a subset of anything, so it passed while checking nothing. It now
  asserts it found the literals it is about to check.

- Three SCP11 modules carried two module docstrings each. Only the first
  is reachable as `__doc__`; the second was a string statement the
  interpreter evaluates and discards, and in all three it held the prose
  saying which module is canonical and which carries the relay
  implementation. That prose is merged into the live docstring, which
  also returns the imports in those modules to the top of the file.

- `subsystems/scp11-test.md` was written but never reachable: it appears
  in no `mkdocs.yml` nav entry. It is listed under Internals, where a
  compatibility namespace belongs.

- Two members of the BoundProfilePackage were named the wrong way round.
  SGP.22 Table 4 puts `secondSequenceOf87` at `'A2'` and `sequenceOf86` at
  `'A3'`; the hand-written table had them swapped, so a failed profile
  installation reported the `'86'` payload segments as the
  ReplaceSessionKeys run and the `'87'` ReplaceSessionKeys segment as the
  profile payload. The names are generated from the ASN.1 now, and the
  test pins each one to its tag instead of only checking that all five
  strings appear -- which is why the swap survived a test that passed.

- CLA `AX` is decoded rather than treated as opaque. ETSI TS 102 221
  table 10.3 gives it the same shape as `0X` and `8X` -- bits 4 and 3 the
  secure-messaging indication, bits 2 and 1 the logical channel -- and `A0`
  is the class every GSM 11.11 command on a UICC carries, so the oldest
  traffic in a trace lost its channel and its SM level. `90` to `9F` and
  `B0` to `BF` stay opaque, which is what table 10.3 actually says.

- Every exchange reports its status word. The INITIALIZE UPDATE and the
  FETCH response readers each returned as soon as they had parsed their
  own structure, before the status word was added, so `yapdu.sw` was
  absent from exactly those frames -- every secure-channel opening and
  every FETCH in an SGP.32 proactive loop. `yapdu.sw != 0x9000`, which
  the documentation names as the filter for "every exchange the card did
  not accept", could not match them, and the bundled Wireshark profile
  showed them with an empty SW and Status column.

- A short primitive TLV no longer claims an integer reading it cannot
  support. Rendering any value of four bytes or fewer as a big-endian
  integer is right for a counter and wrong for the packed BCD of an ICCID,
  where `01 02 03` was reported as 66051. The reading is still available as
  `yapdu.tlv.uint`; the layer-specific decoders name the values that really
  are numbers.

- Profile metadata is no longer written with fields silently missing.
  `asn1tools` ignores a payload key the compiled schema does not define,
  returning the bytes it would have produced without it and raising
  nothing, and the pinned upstream pySim defines `StoreMetadataRequest`
  at SGP.22 v2. A document asking for `estimatedProfileSize` therefore
  encoded to 53 bytes where a patched schema writes 59, with no way for
  the caller to learn the field was gone -- and the path is reachable
  from the local-access shell, so it reached real profile installs. Both
  metadata encoders now read the member set off the compiled
  specification and refuse the encode rather than dropping the field.

- The ten members encode on a stock install, with no forked dependency.
  `pySim.esim.compile_asn1_subdir` concatenates the ASN.1 files in a
  directory and compiles the string, so `SCP11/rsp_v3_schema.py` reads
  the same text and declares the ten members and the eight types they
  reference before compiling it. A stock `pip install` now writes the
  59-byte request a patched checkout does, where it wrote 53 before.
  The substitution is confined to the `StoreMetadataRequest` block --
  its anchor line occurs in three types, and a first-match replace
  patches the wrong one and yields a nine-member schema in silence --
  and it retires itself: once upstream declares the members the anchor
  stops matching and the supplement becomes a no-op. The schema
  extension is logged for upstream in
  `upstream_patches/osmocom-pysim-rsp-v3-metadata/`.

- The bundled local-access profile is a profile package again. Its
  `telecom` PE declared `ef-arr` 41 bytes longer than the File it holds,
  so the element swallowed the three members that follow it --
  `ef-sume`, `df-phonebook`, `ef-pbr` -- and the top-level context tags
  read `0,1,2,3,8,10,17,24,32,1`, ending out of order, which a DER
  SEQUENCE cannot do. Framing desynchronised from there: 141 of the 154
  apparent elements were fragments of the ones before them, and only 13
  decoded. `SCP11/local_access/profile/test_profile.txt` ships through
  `MANIFEST.in` and the frozen bundle data, so this was the reference
  package an operator read. It is now the same 17-element profile the
  ProfilePackage reference and the eIM-local fixture already carry,
  byte for byte, and a test holds every shipped profile to elements that
  decode and tile the package. The blob had been in the tree, unchanged
  and undecodable, since it was first committed.

- `euiccCiPKIdListForSigningV3` is read at tag `B1`. SGP.32 v1.2 §6.3.1
  declares it `[17] SEQUENCE OF SubjectKeyIdentifier`, and a constructed
  context tag 17 is `B1`, not the primitive `91` this decoded before, so
  the member was never recognised and its absence never reported.
  `ipaMode` value 1 reads `IPAe active` rather than `Mode 1 active`;
  `treProperties` `8D` and `treProductReference` `8E` decode at the root
  where they occur, the first through a branch that keyed on the tag as
  a parent and so could not run; and the detail order follows the ASN.1.
  A tag the build does not name is reported as raw hex instead of
  dropped, which is what EXTENSIBILITY IMPLIED asks for.

- SCP80 no longer shadows the top-level `main` package. `SCP80/main.py`
  put its own directory at the front of `sys.path` so a bare-script
  launch could reach `cli`, and `SCP80/cli.py` did the same with
  `../SCP03`. Both entries outlived the import that needed them, and
  `SCP80/main.py` standing in front of the `main` package meant that
  once anything imported `SCP80.cli`, the launcher, GUI and web-server
  entry points raised `module 'main' has no attribute 'main'`. The
  SCP03 imports name their package, and the bare-script fallback puts
  the repo root on the path rather than the module directory.

- `SCP11/check_keys.py` is removed. It imported `sgp_utils` as a
  top-level module, which stopped resolving when SCP11 became a package,
  so the file raised `ModuleNotFoundError` on import; nothing referenced
  it, and it shipped in the wheel.

- The test suite compiles one pySim. A `<repo>/pysim` checkout reached
  `sys.path` from `pytest_collection_modifyitems`, after every test
  module had been imported and bound `sys.modules["pySim"]`, so a
  single-file run and a full-suite run could compile different ASN.1 --
  nineteen `StoreMetadataRequest` members or nine. Six test modules also
  replaced an installed pyscard with a four-submodule stub whenever they
  ran first, which broke every later test reaching `smartcard.util`.
  Both now check before they act.

- A TLS record that straddles two SEND DATA blocks no longer takes the
  whole payload down with it. ETSI TS 102 223 sizes BIP channel data to
  the transport, around 236 bytes, and the record layer knows nothing
  about that boundary, so a truncated record discarded the complete
  records sharing its block: a 2400-byte certificate flight reported as
  2812 bytes of raw payload, and a fatal alert arriving behind it was
  never seen, leaving the diagnosis layer's alert history empty.
  `yggdrasim_common/bip_stream_decode.py` holds a per-direction buffer
  and reports a record once it is whole; the carry-over is bounded at
  one record by `MAX_PENDING_BYTES`, and raw bytes are not retained,
  because these events accumulate on a process-wide singleton. Records
  after a ChangeCipherSpec are reported by length alone, since walking
  that ciphertext as HandshakeType and length invents message names.

- The relay shell ignored `ES9_CA_BUNDLE_PATH` on its eIM endpoints while
  the live shell honoured it, so `SET-ES9-CA` -- which the troubleshooting
  table names as the remedy for an untrusted eIM FQDN -- silently did
  nothing there. Both surfaces are pinned by tests so they cannot drift
  apart again.

- The Command Center's Stop control now ends a running action. The
  route set the run's cancel event, but `_stream_console` never accepted
  it, so every `scp11_live` streaming action was uncancellable and an
  eIM poll cadence ran until the process exited. The flag now travels to
  the console through `yggdrasim_common/cancellation.py`, and cadence
  waits are interruptible.

- Closing the desktop window ends the process instead of waiting on a
  stream that never finishes. A graceful uvicorn stop drains open
  connections, which a poll WebSocket will supply indefinitely; teardown
  now cancels in-flight runs, forces the server down, and bounds the
  cleanup that stops external services.

- A windowless launcher can start the process with no standard streams,
  where the missing-`[gui]`-extra diagnostic raised `AttributeError` on
  `None` and the shortcut appeared to do nothing.

- Live eUICC configuration actions have their own eSIM Management tab rather
  than falling into the SGP.22 bucket, whose label describes none of
  them.

- The Wireshark capability probe no longer enters the wheel or the
  source distribution. The `lua/*.lua` globs swept it in against the
  statement in its own header, and `verify_wheel.py` rejects it as a
  resource outside the release allowlist, so no wheel could verify.

- `uv.lock` records the current version, `Tools.ApduDissector` is in the
  reviewed-package manifest, and the SGP.26 suites skip on a checkout
  without the GSMA bundle rather than failing on a missing fixture.

- Returning to the MF worked only from outside an ADF. SELECT by FID
  uses P1=00, which resolves the file ID against the current DF
  (TS 102 221 11.1.1), so a card parked in ADF.USIM or ISD-R answered
  6A82. The select-by-path form is tried next, and a card that refuses
  every by-FID SELECT with 6A86 once an application is selected is
  reset rather than left unreadable for the rest of the session.

- The Command Center reported a working eUICC as a legacy card. The
  card-standard probe decided from whether the EID came back, but
  SGP.22 5.7.20 serves the EID over ES10c on a logical channel, so a
  card carrying ISD-R can still answer 6A88 to `GET DATA 5A` on the
  basic channel. The classification now follows which RSP applications
  answer SELECT, and the EID is reported separately when it is
  readable.

- UPDATE RECORD stored a short payload verbatim, and `record_length`
  is derived from the first record, so one short write redefined the
  geometry of every later record. The width is resolved before the
  growth loop and the payload padded or truncated to it
  (TS 102 221 11.1.6).

- Applying a profile's security domains left the previously enabled
  profile's rows in the registry, so GET STATUS and SELECT AID kept
  answering for every security domain the card had ever carried.

- The OTA shell decided whether a command already carried Le from the
  total length's parity, which is wrong in both directions for an
  even-length Lc payload: it truncated a case 3 command and doubled Le
  on a case 4 one. It follows from the parsed Lc instead.

- Two Command Center actions were unreachable from their tab. Two tab
  groups listed `hotfolder_metadata` twice, so the duplicate key
  overwrote the first and `hotfolder_cycle` fell through to Other;
  `import_certificate` was absent from the local SM-DP+ group.

- Two dispatchers could run against one card session at once,
  interleaving APDUs on the same channel and moving the same
  file-system cursor under each other. Sync dispatchers now take the
  session lock, acquired on the worker thread. The lock is reentrant,
  because scp03 dispatchers call siblings on the same session.

- A quirks, iSD-R or eUICC-store path change rebuilds the simulated
  engine singleton, and connections created before it went on mutating
  the abandoned instance. Each rechecks the generation it bound to.

- `pcsc_transmit` disconnected after its join timeout even while the
  worker was still inside `transmit()`, closing the handle under it.

- Launching `yggdrasim-scp11-live` without `--debug` wrote 0 over the
  debug flag the operator had stored from the launcher menu or the
  GUI, and the shell never read the persisted overrides back. Inside
  the shell `--debug` reached the handler as a positional, so
  `DOWNLOAD --debug` relayed the flag upstream as a matchingId.

- `render_applescript` nested a shell single-quoted word inside an
  AppleScript string literal without escaping either layer, so a path
  carrying a quote or a backslash broke out of both.

- The HIL bridge no longer pins Wireshark to `Adwaita-Dark`, which
  fought the desktop's own Qt palette on a light session.

### Security

- Twisted is out of the dependency lock. pySim lists `smpp.twisted3` in
  its `install_requires` although only its `pySim-smpp2sim.py` script
  uses it, and every release of that library pins `Twisted~=23.10.0`,
  which carries CVE-2026-42304, CVE-2024-41810 and CVE-2024-41671.
  Nothing in YggdraSIM reaches `smpp.twisted`; the SMPP PDU codec the
  local-access session uses is the separate `smpp.pdu` package and
  stays. A resolver override in `pyproject.toml` (`[tool.uv]`) drops the
  requirement, so `uv sync`, the CI environments and the bundles no
  longer carry Twisted; a `pip install` from the sdist still follows
  pySim's declaration. `tests/test_dependency_overrides.py` pins the
  effect and retires the override once pySim stops declaring the
  dependency; the proposed upstream change is recorded under
  `upstream_patches/osmocom-pysim-smpp-twisted-optional/`.
- The lock moves cryptography to 50.0.1, the first release fixed for
  CVE-2026-69247 (a Bleichenbacher oracle in PKCS#7 EnvelopedData
  decryption). Nothing here decrypts CMS enveloped data.

- A configured `ES9_CA_BUNDLE_PATH` naming a file that no longer exists is
  refused instead of skipped. The transport fell through to the per-host
  dynamic entry or the system store, so the operator kept believing
  traffic was pinned to their anchor while it ran on whatever else
  verified; the provider chain check already refused the same path.

- A first-contact TLS chain read is announced on stderr whether or not
  `YGGDRASIM_GLOBAL_DEBUG` is set, once per call site. The opt-in is
  routinely left set in `env_overrides.json`, so the reads continue for
  every later run, and a silent one left no trace that a chain nothing
  had vouched for became a persisted local anchor.

- Dynamic CA resolution requires a real chain match before it persists an
  anchor. `verify_certificate_against_ca_bundle` returns "" rather than
  raising when pySim is absent, and the handshake probe that followed is
  tautological for a bundle built from the endpoint's own chain, so an
  empty subject let an unvouched-for chain through.

Three checks that used to warn and continue now raise. Each was a
silent skip, so a deployment relying on one will fail where it
previously appeared to succeed.

- **A pinned eIM TLS connection no longer proceeds on a mismatch.**
  The pinned context is built with `CERT_NONE`, so the BF55 pin is the
  only thing authenticating the peer; a mismatch logged a warning and
  sent the request anyway. It now raises `PinnedTlsMismatchError`
  before the body goes out, and the poll retries over the CA-verified
  trust path. `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS=1` removes that
  fallback. An endpoint no CA bundle verifies now fails where it
  previously succeeded unverified.

- **Provider certificate chain verification is mandatory.** An
  unresolved CA bundle, an absent pySim and a missing Authority Key
  Identifier each returned quietly and left the chain unverified.
  Each now raises. Point `ES9_CA_BUNDLE_PATH` at a reviewed anchor, or
  set `YGGDRASIM_SCP11_ALLOW_TLS_INTROSPECTION=1` for one bootstrap
  read.

- **A BF23 `smdpSign` that does not verify aborts the download.** It
  was printed as a warning and the BPP relayed to the card regardless.

- SCP03 `CONFIG` printed KENC, KMAC, DEK and the ADM code; the OTA
  shell printed KIc and KID. Both now print `<redacted>`.
  `describe_keyset` on the `*_indicator` fields still confirms which
  keyset is loaded.

- The unprotected profile package, which for a real profile carries
  the subscriber authentication keys, was written to `DEBUG_DIR`
  whenever that was configured. It is now written only under
  `YGGDRASIM_GLOBAL_DEBUG=1`, and at 0600. The BSP session-key lines
  (S-ENC / S-MAC / MCV) embedded in `--json` and `--yaml` output take
  the same gate; `EXPORT-KEYBAG` stays the deliberate route and now
  writes through the symlink-safe atomic writer at 0600.
  `env_overrides.json` follows, since it names token and TLS-key paths
  alongside the security-posture toggles.

- `compare_tokens` ran its padded compare inside `False or ...`, which
  reads as a bug someone would later "fix" into returning the result.
  NUL-padding makes `b"abc"` and `b"abc\x00"` compare equal, so the
  padded result is not a valid verdict; it is now run for its timing
  and discarded.

## [2.1.0] -- 2026-08-18

### Added

- `Tools/ApduDissector/` is a Wireshark and tshark dissector for the
  GSMTAP SIM frames the HIL bridge mirrors on UDP `4729`. It decodes the
  ISO/IEC 7816-4 header with its class-byte breakdown and case
  classification, status words including the `61XX` / `6CXX` / `63CX`
  families whose SW2 carries a count, BER-TLV and COMPREHENSION-TLV,
  ETSI TS 102 221 clause 11.1.1.3 file-control templates, the contents
  of EF.ICCID / EF.IMSI / EF.UST / EF.AD, and ISO/IEC 7816-3 ATR frames.
  Each command also carries the risk class from
  `yggdrasim_common/apdu_risk.py`, so `yapdu.risk == 3` lists every
  irreversible command in a capture.

  Measured against TShark 4.2.2, this fixes three defects in the stock
  decode: a `GET RESPONSE` carrying an FCP template was reported as a
  malformed packet, a `STORE DATA` to the ISD-R rendered as a bare `e2`
  with its payload untouched, and ATR frames were mis-parsed as APDUs
  down to an invented status word.

  Available as `yggdrasim-apdu-dissect` (`decode`, `sidecar`,
  `install`, `uninstall`, `path`, `probe`), and loaded automatically by
  the HIL-bridge terminal decode view, offline pcap review, and the
  Wireshark launch under HIL start mode `[2]`. Set
  `YGGDRASIM_APDU_DISSECTOR=0` to opt out. A bare `tshark` or a
  desktop-launched Wireshark does not load it until
  `yggdrasim-apdu-dissect install` copies the Lua tree into the personal
  plugin folder, after which both read it at startup with no flags.

- `scripts/generate_apdu_dissector_tables.py` generates the dissector's
  Lua lookup tables from the Python modules that already own them, so an
  instruction name or status word cannot mean one thing in the toolkit
  and another in a packet trace. `tests/test_apdu_dissector_tables.py`
  fails when the committed Lua drifts.

- `yggdrasim_common/stk_tables.py` holds the ETSI TS 102 223 Table 9.4
  and clause 8.25 tables, which previously existed only as literals
  inside `tests/test_stk_spec_tables.py`.

- `yggdrasim_common/apdu_tables.py` records the ISO 7816-4 case each
  instruction normally uses, used as a confidence signal when splitting
  a concatenated command/response frame.

- `yggdrasim-apdu-dissect sidecar` recovers SCP03 / SCP11c plaintext
  from a capture into a sidecar file the dissector reads, using the
  same replay engine the terminal decode view uses. Wireshark's Lua
  binding has no AES, no CMAC and no hash, so a Lua dissector cannot
  decrypt regardless of what keys it is given. Recovered plaintext is
  re-decoded in full, so a ciphered ES10b STORE DATA renders as an
  ES10b tree. Sidecars are bound to their capture by the on-wire
  ciphered command rather than by frame number, so one built from a
  different capture contributes nothing instead of misattributing.

- `ScpReplayEngine.try_unwrap_bytes` returns the recovered plaintext
  bytes alongside the lines `try_unwrap` already rendered.

- Model Context Protocol server (`Tools/YggdraMCP`, opt-in `[mcp]` extra,
  console script `yggdrasim-mcp`). 26 tools covering spec / status-word /
  AID lookup, ASN.1 and APDU decode, SAIP and eIM linting, SAIP and
  session diffing, card transport control, and batch
  execution in all eight operator shells (`profile_package`, `scp80`,
  `scp11_eim`, `suci_tool`, `scp03`, `scp11_live`, `scp11_relay`,
  `scp11_local_access`) across 360 classified verbs. Four reference
  resources and three canned workflows.
  Private extensions register through the `mcp_extensions` plugin
  capability.
- MCP access model. The server is read-only by default;
  `YGGDRASIM_MCP_ACCESS=write` permits state changes,
  `YGGDRASIM_MCP_ALLOW_CARD` permits reaching a card, and
  `YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` permits verbs whose payload the gate
  cannot classify (`RUN`, `SCRIPT`, `RAW`). The three are independent.
  Shell verbs are allow-listed per shell, and every shell's classification
  is checked against that shell's own command table on each test run.
- MCP card transport control: `card_backend_status`,
  `card_backend_select`, `card_session_open`, `card_session_transmit`, and
  `card_session_close`. Sessions hold one connection open, so a
  select-then-read or secure-channel sequence survives across calls, which
  the stateless `pcsc_transmit` cannot do. Bounded to 4 concurrent
  sessions with a 10-minute idle reap.
- Standalone `yggdrasim-mcp` distribution generated by
  `scripts/release/build_mcp_standalone.py`. Publishes a single
  `yggdrasim_mcp` package that installs alongside `yggdrasim`, declares no
  Git dependencies, and vendors the card transport chain so it can drive a
  card locally or through a relay without the rest of the tree.
- HIL bridge: the supervisor now reboots the SIMtrace2 board before
  every session, replacing the trip to the rig to press the physical
  reset button. The cardem firmware resets its own microcontroller when
  USB drops below `CONFIGURED`, so `Tools/HilBridge/device_reset.py`
  forces that from the host -- `USBDEVFS_RESET` on the usbfs node by
  default, or a `uhubctl` VBUS cycle that also power-cycles the SIM.
  Selected with `--simtrace-reset` / `YGGDRASIM_HIL_SIMTRACE_RESET`
  (`usb-reset`, `port-power`, `auto`, `off`); the USB snapshot is
  re-read afterwards so `osmo-remsim-client-st2` is pinned to the
  board's new USB address. A new `yggdrasim-hil-reset` console script
  performs the same reset on demand, and the supervisor state file
  reports the result under `simtraceReset`.
- HIL bridge: relay sessions now power-cycle the physical card at their
  boundaries. Operator shells transact under a relay session id, and the
  bridge cold-resets the card (`SCARD_UNPOWER_CARD`) when that id first
  appears, when another shell replaces it, and when the shell
  disconnects -- so a selected AID, an open logical channel, or an
  established SCP03 / SCP11 secure channel can no longer leak into the
  modem session. Because a power-cycle invalidates every view of the
  card, the bankd side is dropped too and `osmo-remsim-client-st2`
  re-handshakes against the post-power-up ATR. Disable with
  `YGGDRASIM_HIL_RELAY_SESSION_RESET=0` or `--no-relay-session-reset`.
  The remote-rig systemd unit also gained the SIMtrace2 reset knobs, and
  `PcscCardChannel.disconnect()` now pins `SCARD_UNPOWER_CARD` instead
  of inheriting whatever disposition was last set.

### Changed

- `Tools/EumDiag/dissector.lua` is retired. `yggdrasim-eum-diag` now
  hands its captures to `Tools/ApduDissector`, which decodes the BF36
  BoundProfilePackage as a tree rather than dumping it as one blob, and
  still honours `YGGDRASIM_EUM_SESSION_KEYS`. The retired file
  byte-scanned for the tag with no TLV awareness, so it matched inside
  unrelated values; loaded the session keys and never applied them; set
  the protocol column on every packet in the capture whether or not it
  had touched it; and built a TvbRange from half the digit count of an
  ICCID, which breaks on any real 19-digit one.

- The HIL-bridge decode view names proactive command `0x04` `POLLING
  OFF`, matching ETSI TS 102 223 Table 9.4. It previously read `POLL
  OFF`. The TUI summary marker changed with it.

- `scripts/check_repo_hygiene.py` now scans `.lua` files.

### Security

- The GUI file picker (`/api/fs/browse`) no longer enumerates arbitrary
  directories in `--web-server` mode. That endpoint is authenticated and
  returns metadata only, never file contents, but a web-server session
  binds `0.0.0.0` by default and its token holder need not own the host,
  so directory enumeration was a disclosure. Listing is now limited to the
  roots the picker already offers (home, working dir, workspace,
  Documents, Downloads, Desktop). `--gui` is unchanged: it is loopback
  bound on the operator's own machine. `YGGDRASIM_GUI_FS_ROOTS` overrides
  either default. Paths are checked after resolution, so `..` traversal
  and symlinks are judged by their real target.

### Removed

- `.gitlab-ci.yml`. The GitLab remote is an internal mirror, not a build
  surface: releases are produced by the GitHub workflows under
  `.github/workflows/`, so a second pipeline definition duplicated that
  work and ran on every internal push. The file stays recoverable from
  history if GitLab CI is wanted again.

- The tracked GSMA SGP.26 reference certificates, the SM-DP+ test keys and
  `SCP03/script.txt`. Certificates and private keys are operator-supplied
  material even when the values are reference ones; the guides document
  where to place them. See `guides/REMOTES_AND_PUBLICATION.md`.

## [2.0.0] -- 2026-07-02

### Added

- Tools tier staging, not part of this release: in-process
  `Tools/YggdraCore/` stubs (subscription store, AUSF stub, AAnF stub,
  FastAPI loopback, BYO Open5GS bridge) and the local-loopback
  `Tools/CardBridge/` HTTP card-relay daemon. Their HTTP / CLI surface
  hardening, BYO-Open5GS resilience checks, and public docs pass are
  not covered by this release's compatibility promise.

### Changed

- Release engineering was rebuilt for a public line: SPDX headers across
  the tree, a `MANIFEST.in` for the sdist, reworked `.gitignore` /
  `.dockerignore`, GitHub issue and pull-request templates, the
  security-controls gate, and the build, Docker and Pages workflows.
  The full record of what moved is the `v2.0.0` tag and the
  `release/2.0.x` branch.

## [1.0.2] -- 2026-06-05

### Fixed

- SCP11 notification metadata and pending-notification extraction fall back
  to manual BER-TLV parsing when pySim returns an empty list or rejects
  long-form notification TLVs.
- SCP11 notification sequence values are encoded as positive ASN.1 INTEGERs
  for retrieve and local notification requests, including values with the
  high bit set.
- Source checkouts report the `pyproject.toml` version even when stale
  installed distribution metadata is present.

## [1.0.1] -- 2026-06-05

### Fixed

- A conformance sweep of `Tools/ApduDissector/` against the governing
  specifications corrected a set of defects that produced confidently
  wrong output rather than missing output. These change what an operator
  reads off a capture they have already collected, so they are listed
  individually:

  - The life-cycle status integer was inverted against ISO/IEC 7816-4
    Table 13. `'05'` and `'07'` were reported as deactivated when they
    are activated, and `'0C'` to `'0F'` -- the **termination state** --
    were reported as operational, so a permanently dead file or ADF
    rendered as healthy. The GlobalPlatform registry codings were also
    consulted ahead of the ISO table for an FCP `'8A'`, which made every
    ordinary UICC file report "LOADED" or "INSTALLED".
  - Warning status words were counted as success. `63 CX` is a *failed*
    verification, so `yapdu.sw_success` reported "Succeeded: True"
    beside the text "Verification failed", and a filter for failures
    missed every consumed retry and every blocked PIN. Status words are
    now classified into the four categories of ISO/IEC 7816-4
    clause 5.1.3 and published as `yapdu.sw.category`.
  - ETSI TS 102 223 clause 8.7 device identities had the UICC and the
    terminal swapped, reversing the reported direction of every
    proactive command and every terminal response; the channel block was
    read from `'10'` rather than `'21'`, so channels 1--7 were named as
    card readers. Source and destination are now rendered, which they
    previously were not at all.
  - The clause 8.52 bearer table was numbered from `'00'` instead of
    `'01'`, shifting every entry -- including `'03'`, the default packet
    bearer this repository's own toolkit emits, which read as "local
    link technology independent".
  - The clause 8.12 general result table was shifted by two from `'04'`
    up, so a REFRESH that merely could not draw an icon was reported as
    an inactive NAA.
  - Clause 8.59 transport levels had local and remote swapped, reporting
    a channel terminating on the handset as one to the network.
  - Case-4 commands were split one byte short. The case hint was scored
    as a single string comparison, so an instruction hinted `3S` beat
    its true `4S` reading by 20 points -- at confidence 100 and with no
    ambiguity flag -- and the trailing Le rendered as a one-byte
    response body. Every ES10b `STORE DATA` is case 4. Scoring now
    models the two properties a case actually asserts, and confidence
    derives from the margin over the runner-up rather than from evidence
    every candidate shares.
  - Secure messaging was detected from bit 3 alone, which missed
    ISO/IEC 7816-4 Table 3 type `'10'` (CLA `'08'` and `'88'`) and
    invented an eight-byte C-MAC on the further interindustry classes
    `'44'` and `'4C'`, where that bit is part of the channel number.
  - `61 00` and `6C 00` reported zero bytes rather than 256; `92 40`, a
    memory problem, was reported as a normal ending after 64 retries;
    and `9E XX`, a SIM data download error, had no description at all.
  - A proprietary or reserved class byte had a logical channel, a
    secure-messaging level and a chaining flag decoded out of bits
    ISO/IEC 7816-4 clause 5.4.1 assigns no meaning to, stating three
    facts per command that the specification does not.
  - COMPREHENSION-TLV tags `'1C'`, `'1D'` and `'1E'` were each named as
    their neighbour and `'32'` was named as `'3F'`; the tag table now
    covers the full ETSI TS 101 220 clause 7.2 allocation.
  - The BoundProfilePackage sections were numbered from `'A0'` as the
    initialiseSecureChannelRequest. GSMA SGP.22 clause 2.5.2 puts the
    request in `BF23` and gives `'A0'` to `'A3'` to the four sequences,
    so every name was shifted by one and `secondSequenceOf87` was
    missing entirely.
  - A secure-messaged SELECT had its ciphertext read as an AID, a file
    identifier or a path, and the result was committed to the
    cross-frame state -- so every following read in that channel was
    attributed to a file identifier made of ciphertext, while still
    reporting its context as available.
  - `Tools/ApduDissector/sidecar.py` split a wrapped exchange as case 3
    unconditionally. A GlobalPlatform `INSTALL` is sent case 4, so the
    recorded command was one byte short of the frame and a valid sidecar
    was refused with "does not match", which is both false and the most
    misleading thing the tool can report. It also hardcoded the card
    session index and the selected AID, making every keybag session that
    matches on either unreachable; both are now tracked from the
    capture.
  - A sidecar entry with no `command_hex` bypassed the check that binds
    a sidecar to its capture, making the guarantee opt-in. It now fails
    closed.

- The dissector also closes gaps the sweep found where the decode simply
  stopped early: ENVELOPE bodies (`D1`--`DE`) are unwrapped, so Event
  download exposes its event code, channel status and pending byte
  count; the Result cause byte names which of the thirteen BIP failures
  occurred; Channel status reports whether the link came up and whether
  it dropped; the OPEN CHANNEL port is bound to the channel the terminal
  allocates, so DNS inside a BIP session resolves; chained `STORE DATA`
  is reassembled; and DGI-format `STORE DATA`, the INSTALL extradition,
  registry-update and personalisation layouts, and SCP01/02/03/11
  INITIALIZE UPDATE responses are decoded per their own structures
  rather than a shared guess.

- SCP11 live and relay notification sync now encode
  `seqNumber >= 0x80` as positive ASN.1 INTEGER values before
  `RetrieveNotification`, `RemoveNotificationFromList`, and local-access
  notification requests. This avoids cards interpreting values such as
  `188` as a negative INTEGER.
- SCP11 notification sync now reports
  `notificationsListResultError` responses such as `undefinedError(127)`
  directly, instead of treating the response as an undecodable pending
  notification.
- SCP11 live notification listing now preserves active-channel recovery
  context and falls back through active logical channel priming, fresh
  logical-channel recovery, and STK-mode bootstrap for recoverable
  `6E00` / `6985` style failures after profile-state changes.

## [1.0.0] -- 2026-04-29

First SemVer-tagged release. Cut at git tag `v1.0.0`. Pinned commit
exposes a frozen v1 footprint; the v2 staging continues on `main`.

### Added

- Default eUICC identity is now the reserved SGP.22 Annex A.2 test EID
  `89049032123451234512345678901235`, with prefix `89049032` and a valid
  Luhn check digit.
- SIMCARD 5G core: TS 33.501 Annex A AKA helpers (`SIMCARD/aka_5g.py`),
  TS 33.535 AKMA (`SIMCARD/akma.py`), TS 33.501 section C.3 SUCI Profile A & B
  with EF.SUCI_Calc_Info codec (`SIMCARD/suci.py`), TS 31.102 section 7.1.2.4
  `GET IDENTITY` handler (`SIMCARD/identity.py`).
  transport (`SIMCARD/ipa_tls.py`); SAIP pySIM specs bridge
  (`SIMCARD/saip_pysim_specs.py`); SGP.32 package surfaces
  (`SIMCARD/sgp32_packages.py`); modem write persistence; shared EF
  mirror; legacy GSM modem attach path; FCP decoder; GFM walker;
  service-table staging.
- SAIP PE editors (`Tools/ProfilePackage/saip_pe_editors/`); SAIP
  profile diff engine and loader; AT-simlink modem bridge
  (`Tools/HilBridge/at_simlink.py`); APDU relay auth.
- SCP03 STK ETSI defaults / conformance, service-table decoders /
  staging, card-backend relay-token plumbing, doctor card-relay
  probe.
- SCP11 shared profile-actions module, card-overview renderer,
  eim_local live-delete auto-disable.
- yggdrasim_common: APDU recorder + WebSocket stream, card-bridge
  bearer-token helper (`card_bridge_auth.py`), Nord palette,
  remote-card argument parsing.
- Documentation: configuration & certificates guide, GUI host shell
  guide, "Load certificates and config" how-to recipe.
- `tests/live_scp03/` golden inputs for the SCP03 admin shell.
- Demo scripts under `scripts/demos/` covering 3GPP attach and profile
  lifecycle.

### Changed

- `pyproject.toml` version moves from CalVer `2026.4.10` to SemVer
  `1.0.0`. Both `yggdrasim_common.__about__` and the launcher's
  `--version` resolve to the new value through the existing dynamic
  pyproject lookup.
- HilBridge live decode TUI: ISO/IEC 7816-4 `MANAGE CHANNEL`
  (INS=0x70) is now classified into the STK group ahead of the BIP
  marker scan, so `MANAGE CHANNEL Operation=Open Channel` frames no
  longer fall into the unbound-channel tail in the decoded-APDU view.
- All hard-coded EID test fixtures that used to pin the previous
  default updated to the new BCD marker; tests that exercise
  `isdr_config` overrides keep their distinct fixtures.

### Removed

- `bridge` and `modem` zero-byte scratch files at the repo root.
- Legacy `YggdraSIM-docs-oneot.zip` documentation snapshot. The
  same content is canonically tracked in `site-docs/`.

### Security / Repo Hygiene

- `reports/` is now ignored. Live SCP03 capture reports contain
  derived session keys (s_enc / s_mac / s_rmac) and chaining
  values; pushing them to a shared remote was a foot-gun. The
  `reports/.gitkeep` placeholder documents the intended layout.

[Unreleased]: https://github.com/1oT/YggdraSIM/compare/v2.3.0...HEAD
[2.3.0]: https://github.com/1oT/YggdraSIM/releases/tag/v2.3.0
[2.2.0]: https://github.com/1oT/YggdraSIM/releases/tag/v2.2.0
[2.1.0]: https://github.com/1oT/YggdraSIM/releases/tag/v2.1.0
[2.0.0]: https://github.com/1oT/YggdraSIM/releases/tag/v2.0.0
[1.0.2]: https://github.com/1oT/YggdraSIM/releases/tag/v1.0.2
[1.0.1]: https://github.com/1oT/YggdraSIM/releases/tag/v1.0.1
[1.0.0]: https://github.com/1oT/YggdraSIM/releases/tag/v1.0.0
