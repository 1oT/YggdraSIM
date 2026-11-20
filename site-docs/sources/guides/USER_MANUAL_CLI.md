<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# User Manual -- CLI

This chapter covers the command-line surface of YggdraSIM: the launcher
menu, the shells, and the single-purpose commands. Section 4 describes the
modules in the same order as section 4 of `USER_MANUAL_GUI.md`. The
concepts both surfaces share -- the card backend, readers and reader locks,
where data is kept, configuration flags -- are in `USER_MANUAL.md` section
3. Every verb of every shell is listed in
`site-docs/reference/command-suite.md`.

## 1. Start

### 1.1 The launcher

`yggdrasim` (or `yggdrasim-cli`, or `python main/main.py` in a source
checkout) opens a menu:

| Key | Opens |
| --- | --- |
| `1` | Admin Shell - Local Management (the SCP03 shell, section 4.1) |
| `2` | OTA Simulator - Remote Management (the SCP80 shell, section 4.2) |
| `3A` | eSIM Management Relay (section 4.3) |
| `3C` | Local SMDPP (section 4.4) |
| `3D` | Local eIM (section 4.5) |
| `7` | SAIP Tool (section 4.6) |
| `8` | SUCI Key Tool (section 4.7) |
| `9A`, `9B` | Admin Shell - Script Execution; Admin Shell - Report & DUMP-FS |
| `9C` | OTA Simulator - Script Execution |
| `C` | Card Backend / Simulator Settings (section 4.10) |
| `CB` | Card Bridge / APDU Streaming (section 4.8) |
| `E` | Environment Flags (`USER_MANUAL.md` section 3.5) |
| `B` | Local SIMtrace2 HIL Bridge Session (Linux, full install; section 4.9) |
| `G`, `A`, `L` | Guides & Documentation (this manual among them), About, License |
| `Q` | Quit |

The launcher also takes options that run one thing and exit; the common
ones are:

| Option | Does |
| --- | --- |
| `--doctor` | Checks the environment (`USER_MANUAL.md` section 2.2) |
| `--card-backend reader` or `sim`, `--sim-quirks none` | Picks the card backend for this run, and runs the simulator without its quirks file; menu `[C]` saves a choice (`USER_MANUAL.md` section 2.3) |
| `--debug` | Debug output in every module started from the launcher, the GUI included |
| `--gui`, `--web-server` | Starts the GUI (`USER_MANUAL_GUI.md` section 1) |
| `--asn1 <hex>` | Decodes BER-TLV or a command APDU and exits |
| `--open-pcap <file>` | Opens a saved HIL capture for review (section 4.9) |
| `--card-bridge` | Publishes a local reader (section 4.8) |
| `--remote-card-url <url>` | Works on a card published by a Card Bridge (section 4.8) |
| `--scp03 --cmd "<commands>"` | Runs SCP03 commands without the menu |

`yggdrasim --help` lists every option.

### 1.2 The commands

Each module also has a command of its own, which is what scripts use:

| Command | Starts | GUI counterpart |
| --- | --- | --- |
| `yggdrasim-scp03` | The SCP03 admin shell | File system, Applications |
| `yggdrasim-scp80` | The SCP80 OTA shell | Over-the-Air |
| `yggdrasim-scp11-live` (or `yggdrasim-scp11`) | The eSIM Management console | Management |
| `yggdrasim-scp11-local-access` | The Local SM-DP+ shell | Local SM-DP+ |
| `yggdrasim-scp11-eim-local` | The Local eIM shell | Local eIM |
| `yggdrasim-profile-package` | The SAIP Tool shell | SAIP Tool |
| `yggdrasim-suci-tool` | The SUCI key shell | Offline Tools, SUCI keys |
| `yggdrasim-asn1` | The decoder | Offline Tools, Decoder |

Section 5 lists the other commands.

## 2. How every shell works

### 2.1 Interactive use

A shell prints a short banner and waits for commands at its prompt.

- `HELP` lists the verbs by group. `HELP <verb>` prints the usage and
  examples of one verb in the Local SM-DP+ and Local eIM shells.
  `HELP EXPERT` in the eSIM Management console adds the reads and
  settings the short list leaves out. The SAIP Tool has `HELP TOKENS`,
  `HELP TEMPLATE`, `HELP EDIT` and `HELP LINT`; the SCP03 shell has
  `GUIDE [topic]`.
- `EXIT` leaves the shell (`quit` in the SCP80 shell). `QA` leaves
  YggdraSIM altogether.
- The SCP80 shell takes its verbs in lower case (`show`, `build`); the
  other shells print theirs in capitals.

### 2.2 Batch runs

Every shell runs a list of commands without the prompt:

```bash
yggdrasim-scp11-live --cmd "GET-EID; LIST; EXIT"
yggdrasim-scp11-live --stdin < commands.txt
yggdrasim-scp11-live --stdin <<'EOF'
GET-EID
LIST
EXIT
EOF
```

- `--cmd` takes the commands separated by `;`, `--stdin` one per line.
- The commands run in order. End the list with `EXIT`.
- With `--stdin`, empty lines and lines that start with `#` are skipped.
  A `#` after a command on the same line is not a comment.

`CLI_AND_PIPING_GUIDE.md` covers pipelines and CI jobs, and
`PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` has ready-made batches for the
profile lifecycle.

### 2.3 Choosing the reader

`yggdrasim-scp03`, `yggdrasim-scp11-live` and
`yggdrasim-scp11-local-access` take `--reader "<reader name>"`, the exact
PC/SC name or `Remote Lab: <device>`. Without it, and in the other shells,
the first reader is used (`USER_MANUAL.md` section 3.1).

### 2.4 More detail: --debug, --log, TRACE, RECORD

- `--debug` on the command line prints the raw APDU exchanges of the whole
  session. In the eSIM Management, Local SM-DP+ and Local eIM shells,
  `--debug` after a card verb does the same for that one command.
- `--log <file>` after any command line runs that command with debug
  output and appends everything it prints to `<file>`, as well as showing
  it. A new file is readable by its owner only. Each command is one block,
  with a header and a time stamp per line:

```bash
yggdrasim-scp11-live --cmd "GET-EID --log eid.log; EXIT"
```

```text
=== 2026-11-18 09:31:26 +0100  eSIM Management > GET-EID ===
  09:31:26.742  [INIT: TERMINAL CAPABILITY] > 80AA000005A903840101
  09:31:26.742  [INIT: TERMINAL CAPABILITY] < SW: 9000 Data:
  09:31:26.742  [INIT: SELECT ISD-R CH1] > 01A4040010A0000005591010FFFFFFFF8900000100
  ...
  09:31:26.743  [GET: EID] > 81E2910006BF3E035C015A
```

- The SCP03 shell keeps a log open across commands: `TRACE START [file]`,
  then every command until `TRACE STOP` (`TRACE STATUS` tells whether one
  is open).
- The Local SM-DP+ and Local eIM shells record a session for replay:
  `RECORD START [path]` ... `RECORD STOP` writes the commands and their
  APDU trace (`RECORD STATUS`, `RECORD CANCEL`). `yggdrasim-session-diff
  <left> <right>` compares two recordings.
- Several verbs print structured output with `--json` or `--yaml`
  (`CERTS`, `METADATA-LINT`, `EXPLAIN-LAST`, `OPS ... --json`).

### 2.5 Failures and exit codes

A failed step prints a `[-]` line and a refusal or an error a `[!]` line
(`USER_MANUAL.md` section 3.6); a `[!] Warning:` line is a caveat. The shell
then carries on with the next command of a batch, and the batch ends with
exit code 1 when any of its commands failed. `yggdrasim-scp03`,
`yggdrasim-scp80`, `yggdrasim-scp11-live`, `yggdrasim-scp11-local-access`,
`yggdrasim-scp11-eim-local`, `yggdrasim-suci-tool` and
`yggdrasim --scp03 --cmd` count as failed a command that printed a `[-]`
line or a `[!]` line other than a warning, an unknown verb and an error the
shell caught. `yggdrasim-profile-package` counts the verbs that report their
own failure (an unknown verb is one). `EXIT` ends a batch early and keeps the
exit code of what ran before it.

Two commands are judged by their own outcome rather than their lines:
`EIM-LISTEN`, which prints a `[!]` line for each caller it refuses and fails
only when the listener itself does, and a command that runs until it is
stopped, which fails on a `[-]` line or a `[!]` line that says it failed. The lines still say which command failed, so keep the output
(`... | tee run.log`).

## 3. Automation

- Use the module commands of section 1.2 in scripts, not the launcher
  menu.
- Keep command lists in files and feed them with `--stdin`.
- The SCP03 shell writes the results of a `--cmd` or `--stdin` batch as
  YAML with `--out <file.yaml>`.
- Set flags for one run in the environment
  (`YGGDRASIM_CARD_BACKEND=sim yggdrasim-scp11-live --cmd "..."`), not in
  the persisted overrides.
- A job that must not reach a reader or the operator's stores runs as in
  `USER_MANUAL.md` section 4.2.

## 4. Modules

### 4.1 SCP03 admin shell: file system and applications

`yggdrasim-scp03 [--reader "<reader name>"]`, or launcher key `1`. The
shell opens the card at start (`[*] CONNECTED`, with `(SIMULATED CARD)` on
the simulator) and covers what the GUI splits into File system and
Applications.

| Group | Verbs |
| --- | --- |
| Session and card | `INFO`, `ATR`, `RESET`, `SCP03-SD` (or `AUTH-SD`), `SCP02-SD`, `KEYS [AID]`, `LOGOUT`, `OTA` (switch to the SCP80 shell), `STK` (the SIM Toolkit sub-shell) |
| GlobalPlatform | `APPS`, `PKGS`, `SD`, `GET-DATA`, `WIZARD`, `PUT-KEY`, `SET-STATUS`, `LOCK <AID>`, `UNLOCK <AID>`, `DELETE <AID>`, `STORE-DATA`, `MANAGE-CHANNEL`, `INSTALL`, `INSTALL-CAP`, `LOAD`, `INSTALL-APP`, `MAKE-SELECTABLE`, `EXTRADITE`, `PERSONALIZE`, `REGISTRY-UPDATE` |
| eSIM and authentication | `LIST`, `MANAGE-PROFILE`, `RUN-AUTH`, `RUN-AUTH-TEST`, `DERIVE-OPC <Ki> <OP>`, `DERIVE-TOPC <TOP> <K> [Keccak iterations]` |
| PIN | `MANAGE-PIN` |
| Configuration | `CONFIG`, `SHOW`, `AIDS`, `SET-AID-ALIAS <name> <AID>`, `SET-DEFAULT`, `BINDS` |
| File system | `SCAN`, `SELECT <path or FID>`, `READ [path]`, `RECORD <n, ALL or range> [path]`, `UPDATE BINARY <hex>`, `UPDATE RECORD <n> <hex>`, `FS-ADMIN`, `REPORT`, `VALIDATE`, `SET-GOLD-PROFILE`, `GOLD-PROFILE`, `PROFILE-DIFF` |
| Developer | `GUIDE [topic]`, `RUN <file> [out.yaml]`, `EXPORT-KEYBAG`, `DEBUG`, `TRACE`, `CLS` |

Read the ICCID, authenticate and list the applications, on the simulated
card:

```bash
yggdrasim-scp03 --cmd "INFO; SELECT 2FE2; READ; SCP03-SD; APPS; EXIT"
```

```text
=== CARD INFO ===
ATR   : 3B9F96801FC78031A073BE21136743200718000001A5
ICCID : 89881111111111111112
eID   : 89049032123451234512345678901235
Spec  : SGP.32 (IoT)
[+] Selected 2FE2 (2FE2)
--- FCP ---
    [Type]     EF (Transparent, shareable)
    [Size]     10 bytes
Data [9000]: 98881111111111111121
          | iccid: 89881111111111111112
[*] Authenticating to Security Domain via SCP03: A000000151000000...
[+] SCP03 Authenticated (Level 0x33, KVN 0x30)
--- GlobalPlatform Registry (APPS) ---
AID                                | State        | Privileges
A0000005591010FFFFFFFF8900000200   | PERSONALIZED | 9EFE80
A000000151000000                   | SELECTABLE   | 800000
```

- The keys come from `Workspace/SCP03/keys.ini` under the runtime root:
  `kenc`, `kmac`, `dek`, `kvn`, the default security domain `aid` and the
  `adm` key for VERIFY. `CONFIG` changes them, `SHOW` prints them and
  `SET-DEFAULT` returns to the default test keys.
- `UPDATE`, `DELETE`, `LOCK`, `UNLOCK`, `STORE-DATA` and the install
  verbs act at once. The wizards (`PUT-KEY`, `SET-STATUS`, `FS-ADMIN`,
  `WIZARD`, `MANAGE-PROFILE`, `MANAGE-PIN`) ask for their values first.
- `RUN <file>` sends a script of APDUs, one per line, with `#` comments on
  lines of their own; launcher key `9A` does the same from the menu. `REPORT`
  (launcher key `9B`) writes file system and eUICC reports.

### 4.2 SCP80 OTA shell

`yggdrasim-scp80`, or launcher key `2`. The shell builds SCP80 secured
packets, sends them as SMS-PP envelopes and decodes the answer.

| Verb | Does |
| --- | --- |
| `show` | Prints the settings: counter, SPI, KIc and KID key sets, TAR, keys, transport, reader |
| `set <key> <value>` | Changes a setting (keys listed by `HELP`: `kic`, `kid`, `kic_indicator`, `kid_indicator`, `pid`, `dcs`, `sender`, `concat_sms`, `tp_ud_max`) |
| `build [-v] [hex]` | Shows the APDU or APDUs a send would use; sends nothing |
| `send [-v] [hex]` | Sends the configured payload, or the one given |
| `<hex>`, `ota <hex>` | Wraps the payload and sends it |
| `sendraw <hex>` | Sends an APDU without OTA wrapping |
| `iccid [value]` | Reads or binds the settings kept for a card's ICCID |
| `script <file>` | Runs the commands of a file |
| `history`, `reset [-v]` | The command history; re-initialises the toolkit session |

```bash
yggdrasim-scp80 --cmd "show; build; exit"
```

`build` is the dry run: check the counter and the APDU it prints before the
first `send`.

### 4.3 eSIM Management console

`yggdrasim-scp11-live [--reader "<reader name>"]` (or `yggdrasim-scp11`),
or launcher key `3A`. The console works on an eUICC as the LPA (SGP.22) or
the IPA (SGP.32) would. Each card command opens the card, runs and
releases it again.

| Group | Verbs |
| --- | --- |
| Utilities | `SCAN`, `RESET`, `STATUS`, `LIST`, `METADATA <id, AID or alias>`, `HELP [EXPERT]` |
| LPAd | `DOWNLOAD-PROFILE <activation code>`, `ENABLE-PROFILE <ICCID or AID>`, `DISABLE-PROFILE <ICCID or AID>`, `DELETE-PROFILE <ICCID or AID>` |
| IPAd | `DISCOVER`, `DOWNLOAD [matchingId]`, `ADD-INITIAL-EIM`, `EIM-CERT-STORE`, `EIM-LISTEN`, `EIM-LISTEN-CERT` |
| Expert (`HELP EXPERT`) | `GET-EID`, `GET-NOTIFICATIONS`, `REMOVE-NOTIFICATION <seq>`, `CLEAR-NOTIFICATIONS`, `GET-EUICC-INFO1`, `GET-EUICC-INFO2`, `GET-RAT`, `GET-CERTS`, `GET-EIM-CONFIG`, `GET-ALL-DATA`, `GET-SMDP`, `SET-SMDP <address>`, `GET-ES9`, `SET-ES9`, `SET-ES9-TLS`, `SET-ES9-CA`, `ES9-CERT-INFO`, `READ-METADATA`, `GET-POL`, `SET-POL`, `STORE-METADATA`, `AIDS`, `FLOW`, `VERIFY-SCP11`, `EIM-AUTHENTICATE` |

Read the card first:

```bash
yggdrasim-scp11-live --cmd "GET-EID; LIST; GET-NOTIFICATIONS; EXIT"
```

```text
[*] EID: 89049032123451234512345678901235

Profiles on Card:
State     Class  FB  FBA ICCID                 Nickname                  AID / Alias
ENABLED   OPER   -   no  89881111111111111112 Lab (EU 01)              A0000005591010FFFFFFFF8900001100 (ISDP1)
DISABLED  TEST   -   yes 89881111111111111129 Lab (EU 02)              A0000005591010FFFFFFFF8900001200 (ISDP2)

[+] RetrieveNotificationsList
    | Notification Entries : 0
```

A profile is named by its ICCID or its AID. The name in brackets is an
alias from `Workspace/SCP03/aid.txt` (`AIDS` lists them, `SET-AID-ALIAS`
in the SCP03 shell adds one) and works as well: `ENABLE-PROFILE ISDP2`.
The file is written the first time the SCP03 shell runs; until then the
list shows `(ISD-P)` and an alias is refused ("Could not resolve
profile").

Enabling a profile disables the enabled one first. After a state change
the console posts the card's Notifications to the SM-DP+ each one names
and removes the delivered ones from the card (`USER_MANUAL.md` section
4.1, item 4). A refused change prints the eUICC's result code by name:

```text
[-] EnableProfile failed, code 0x01: iccidOrAidNotFound(1) [SGP.22 ES10b]
```

- `DOWNLOAD-PROFILE LPA:1$<SM-DP+ address>$<matching ID>` downloads and
  installs a profile.
- `GET-ES9` shows the active ES9+ base URL. `SET-ES9`, `SET-ES9-TLS` and
  `SET-ES9-CA` change it, its TLS verification and its CA bundle, for the
  session or, with `--persist`, for later sessions as well.
- `ADD-INITIAL-EIM` is a wizard that builds an AddInitialEim step by step,
  shows the run and sends it only when answered `y` (`s` shows the full
  APDU script, Enter sends nothing). A run first resets the card's eIM
  configuration, so every other eIM leaves the card. `EIM-CERT-STORE` keeps
  the certificates and configurations the wizard reuses.
- `EIM-LISTEN` answers eIM packages an eIM injects (SGP.32 eIM Package
  Injection) until it is stopped; `SCP11/eim_local/GUIDE.md` section 6.4.5
  covers it with the Local eIM.
- `yggdrasim-scp11-live --flow` runs one SCP11 flow without the shell.

### 4.4 Local SM-DP+ shell

`yggdrasim-scp11-local-access [--reader "<reader name>"]`, or launcher key
`3C`. The shell loads a profile package from disk onto an eUICC, acting as
the SM-DP+, and runs the profile and metadata commands of ES10. Every card
command opens its own session and closes it again.

| Group | Verbs |
| --- | --- |
| Session and discovery | `STATUS`, `DISCOVER` (or `INFO`), `CERTS`, `LOAD-PROFILE [path]`, `EXPLAIN-LAST` |
| Profile state | `ENABLE-PROFILE <id>`, `DISABLE-PROFILE <id>`, `DELETE-PROFILE <id>` |
| Metadata | `STORE-METADATA [path]`, `UPDATE-METADATA [path]`, `STORE-METADATA-CUSTOM <tag> [path]`, `STORE-METADATA-CUSTOM-ALL [path]`, `METADATA [path]`, `METADATA-LINT [path]`, `METADATA-CLEAR` |
| Files | `PROFILE [path]`, `PROFILE-CLEAR` |
| Shell | `RECORD`, `HELP [verb]`, `EXIT`, `QA` |

- The profile loaded is the one file in `Workspace/LocalSMDPP/profile/`, or
  the file `PROFILE <path>` names. With more than one file in that folder
  and no `PROFILE`, the shell refuses ("Profile directory contains multiple
  files").
- The metadata is `Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json`
  unless `METADATA <path>` names another.
- The DPauth certificate and key are required, the DPpb pair optional.
  They go in `Workspace/LocalSMDPP/certs/` with a sidecar file;
  `SCP11/local_access/certs/README.md` has the format and `CERTS` shows
  what was found.

```bash
yggdrasim-scp11-local-access --cmd "STATUS; CERTS; DISCOVER; EXIT"
yggdrasim-scp11-local-access --cmd "PROFILE <profile package>; LOAD-PROFILE; EXIT"
```

`LOAD-PROFILE` prints each ES10 step (GetEuiccInfo1,
GetEuiccConfiguredData, GetEuiccChallenge, then the authentication and the
download). The card accepts only a DPauth certificate under a CI it lists;
without one the load stops before the authentication:

```text
[-] No matching SGP.26 local credential set was found. Allowed CI PKIDs from card: F54172BDF98A95D65CBEB88A38A1C11D800A85C3
```

`--dump-keybag <path>` writes the session keys of the batch to a keybag
file for offline review of a HIL capture.

### 4.5 Local eIM shell

`yggdrasim-scp11-eim-local`, or launcher key `3D`. The Local eIM is an
SGP.32 eIM run on this machine (`USER_MANUAL_GUI.md` section 4.6 describes
the model). The shell has no reader option: its card verbs use the first
reader. `SCP11/eim_local/GUIDE.md` is the full guide.

First use, on the simulated card:

```bash
yggdrasim-scp11-eim-local --cmd "IDENTITY NEW; ASSOCIATE --yes; QUEUE LIST-PROFILES; OPS pending; DELIVER; OP 1; EXIT"
```

| Command | What it does here |
| --- | --- |
| `IDENTITY NEW` | Makes the identity: eimId `1.3.6.1.4.1.32473.999.10.124`, FQDN `eim.yggdrasim.local`, a P-256 signing key and its certificates |
| `ASSOCIATE --yes` | Resets the eIM configuration of the card in the reader and adds this eIM; without `--yes` it asks for the last eight digits of the EID |
| `QUEUE LIST-PROFILES` | Queues a list of the card's profiles; with no EID it reads the card in the reader for it |
| `OPS pending` | Lists the operations that wait |
| `DELIVER` | Acts as the IPA on the card in the reader until its queue is empty |
| `OP 1` | Shows operation 1: parameters, timeline, the package served and the card's answer |

The association and the operation read:

```text
[+] AddInitialEim: associationToken 1
[+] record 89049032123451234512345678901235: associationToken 1, counterValue 0
[+] Queued 1 operation(s), task 1:
      1  CREATED         78901235  2026-11-18T08:23:14  List profiles
[+] operation 1: listProfileInfoResult: ok
[*] Operation 1 (PROFILE_INFO_LIST) for 89049032123451234512345678901235: SUCCESS
    result     :
      BF2D  listProfileInfoResult          ok
      E3    ProfileInfo                    ICCID 89881111111111111112 enabled operational ...
```

The verbs of daily work:

| Verb | Does |
| --- | --- |
| `QUEUE <operation> [eid] [value] [key=value ...]` | Queues an operation. `--plan` shows what would be queued and queues nothing; `--first` puts it ahead of the card's other operations, `--at <UTC>` holds it until then, `--retries <n>` sets how often it is tried again |
| `OPS`, `OP <id>` | Lists operations (`pending`, `completed`, `all`); shows one, and with `--decode` the Decoder's reading of its package and result |
| `EDIT`, `MOVE`, `CANCEL`, `COPY` | Changes, reorders, cancels or copies an operation |
| `EUICC` | The eIM's record of each card: `EUICC <eid>`, `EUICC READ`, `EUICC ADD`, `EUICC SET`, `EUICC REMOVE` |
| `DELIVER [--once]` | Serves the queue to the card in the reader |
| `SERVE start`, `SERVE status`, `SERVE stop` | The background service IPAs poll, with the local SM-DP+ and SM-DS |
| `INJECT`, `INJECT-CERT` | Sends a card's queue to a listening IPA (`EIM-LISTEN`, section 4.3) |
| `NOTIFICATIONS [<eid>]`, `NOTIFICATIONS SEND` | The Notifications IPAs handed over and where each stands; send the pending ones, or the ones named, now |
| `EIM-SETTINGS [key=value ...]` | The queue rules |
| `TLS-SETUP`, `TRAFFIC`, `SMDS`, `SMDP-PROFILE` | The listener's certificates, the exchanges the service answered, the local SM-DS, the profiles the local SM-DP+ serves |

`QUEUE` takes these operations: `ADD-EIM`, `DEFAULT-SMDP`, `DELETE`,
`DELETE-EIM`, `DISABLE`, `DOWNLOAD`, `ENABLE`, `EXECUTE-FALLBACK`,
`FALLBACK`, `GET-RAT`, `IMMEDIATE-ENABLE`, `IPA-DATA`, `LIST-EIM`,
`LIST-PROFILES`, `RAW-ECO`, `RAW-PSMO`, `REFRESH`, `RETURN-FALLBACK`,
`ROLLBACK`, `UNSET-FALLBACK`, `UPDATE-EIM`. For example:

```bash
yggdrasim-scp11-eim-local --cmd "QUEUE ENABLE 89049032123451234512345678901235 89881111111111111129 --plan; EXIT"
```

`DELIVER` takes the card's pending Notifications as it goes: they are
acknowledged, the card drops them, and the Local eIM forwards each to the
SM-DP+ it names; it holds none back (`USER_MANUAL.md` section 4.1). The
shell also has the package-file verbs
(`EIM-PACKAGE-*`, `HOTFOLDER-*`) and direct card commands
(`ENABLE-PROFILE`, `LOAD-PROFILE`, `ADD-INITIAL-EIM`, ...); `HELP` lists
them.

### 4.6 SAIP Tool shell

`yggdrasim-profile-package`, or launcher key `7`. The shell inspects, lints
and edits profile packages and builds new ones from templates.

- The default input folder is `Workspace/SAIP/profile`; a sole file there
  is selected at start. `USE <file>` selects another (absolute paths are
  allowed for input; `.txt` and `.hex` files are read as hex).
- Every file the shell writes stays inside the workspace; `>` after a
  `DUMP` or `LINT` writes the output to a file there.
- A `USE` that fails leaves the previous selection in place, so in a batch
  the commands after it read the file selected before. Check for its `[-]`
  line.

```bash
yggdrasim-profile-package --cmd "USE reference_test_profile.txt; INFO; LINT; EXIT"
```

```text
SAIP profile version: 2.3
ICCID: 89880811111111111112
Mandatory services: usim, milenage, javacard, get-identity
NAAs: mf[1], usim[1]
=== PROFILE LINT REPORT ===
WARN: 4
FAIL: 1
[WARN] YRL-ICC-004 | header.iccid | ITU-T E.118 (09/2025) §6 / ISO/IEC 7812-1 Annex B
[FAIL] YRL-ICC-010 | mf.ef-iccid.fillFileContent | ETSI TS 102 221 §13.2
```

Each finding names its rule, the place in the package and the
specification behind it.

| Verbs | Do |
| --- | --- |
| `INFO`, `TREE`, `CHECK`, `DUMP [ALL, TYPE or NAA] [DECODED]` | Read the package |
| `LINT [STRICT]`, `LINT HELP`, `LINT PROFILES` | Lint it; the help lists the options and preset gates |
| `INSPECT` (or `TUI`) | The full-screen editor; `yggdrasim-profile-package --inspect --profile <file>` opens it directly |
| `DIFF <a> <b>`, `DIFF-TUI <a> <b>` | Compare two packages |
| `NEW-PROFILE`, `NEW-TEMPLATE`, `NEW-PROFILE-WIZARD`, `PRESETS` | Start a package from a preset |
| `GENERATE-TEMPLATE`, `GENERATE-PROFILE`, `GENERATE-BATCH`, `VARIABLES` | Templates, placeholders and test values (`TEMPLATE_AND_TOKENS.md`) |
| `LIST-AKA`, `PROVISION-AKA`, `RFM`, `TRIM`, `SPLIT`, `EXTRACT-APPS`, `REMOVE-NAA` | Targeted reads and changes |

### 4.7 Offline tools

The tools of the GUI's Offline Tools on the command line:

| Tool | Command |
| --- | --- |
| Decoder | `yggdrasim-asn1 --context <hex>`; `--domain` forces the reading (`apdu`, `response`, `es10`, `gp`, `uicc`, `cat`, `tlv`, `sw`, `ef`), `--file <file>` reads a trace or script, stdin when no hex is given, `--format json` for JSON |
| TERMINAL PROFILE | `python -m yggdrasim_common.terminal_profile <hex>`; `decode -s`, `diff <a> <b>`, `build`, `list` |
| AddInitialEim | `ADD-INITIAL-EIM` and `EIM-CERT-STORE` in the eSIM Management console (section 4.3); answer Enter at its last question to build without sending |
| eIM package lint | `EIM-PACKAGE-LINT [path]` in the Local eIM shell |
| GSMA error codes | `ERROR-CODES [spec]` in the Local eIM shell |
| SUCI keys | `yggdrasim-suci-tool`: `USE <key file>`, `GENERATE SECP256R1` or `CURVE25519`, `DUMP [COMPRESSED]`, `TOOL [command]` |
| TUAK TOPc | `DERIVE-TOPC <TOP> <K> [Keccak iterations]` in the SCP03 shell (section 4.1), with the checks of the Offline Tools TUAK entry: TOP of 32 bytes, K of 16 or 32, 1 to 16 iterations |

```bash
yggdrasim-asn1 --context 80E2910003BF2D00
```

```text
#1 STORE DATA [80 E2 91 00] -- ES10 transport command: the data field is one ES10x request TLV
  context: GSMA eUICC ES10 (SGP.22 / SGP.32) (SGP.22 v3.1 section 5.7.2 table 47)
  P1 91: last block; ... BER-TLV format; ISO case 4 (response data may be returned)
  ProfileInfoListRequest  [SGP.22-v3.1, SGP.32-v1.3]
```

The SUCI tool runs pySim's `suci-keytool`; name the command with the
`YGGDRASIM_SUCI_TOOL` flag when it is not on the `PATH`.

### 4.8 APDU Streaming

A reader on one machine can serve commands on another.

- `yggdrasim-card-bridge --reader-name "<reader name>"` publishes a local
  reader on `127.0.0.1:8642` behind a token. On the other machine, forward
  the port over SSH and point a command at it:
  `yggdrasim --remote-card-url http://127.0.0.1:8642/apdu
  --remote-card-token-file <token file>`, or set `YGGDRASIM_CARD_RELAY_URL`
  and `YGGDRASIM_CARD_RELAY_TOKEN_FILE` for any command. Launcher key `CB`
  holds the same steps as a menu.
- `yggdrasim-lab-agent --config <yaml>` publishes the rigs of a lab;
  `yggdrasim-lab --agent <url> --token-file <file>` lists them
  (`rigs`, `status`) and takes and gives back a session (`reserve`,
  `release`, `heartbeat`).

`CARD_BRIDGE_GUIDE.md` and `site-docs/how-to/run-a-remote-lab-agent.md`
are the guides.

### 4.9 HIL bridge

On Linux with the full install:

- `yggdrasim-hil-supervisor` runs the bridge and keeps it running;
  `yggdrasim-hil-bridge --reader-name "<reader name>"` runs one bridge
  session; launcher key `B` holds the same as a menu.
- `yggdrasim-hil-reset` reboots the SIMtrace2 board over USB;
  `yggdrasim-hil-modem-diag` mirrors a modem's own SIM interface log.
- `yggdrasim --open-pcap <file> [--keybag <file>]` reviews a saved capture
  without a bridge.

`HIL_BRIDGE_GUIDE.md` and `SIMTRACE2_CARDEM_GUIDE.md` cover the hardware
and the setup.

### 4.10 The simulator

Launcher key `C` saves the simulator as the card backend (`[2]`) and holds
its settings: the ISD-R configuration, the quirks file (`[D]` switches it
off), the eIM identity, the stores, a profile import and a reset to the
baseline. `USER_MANUAL.md` section 2.3 compares the ways to select it.

For one launcher run, `--card-backend sim --sim-quirks none` selects it,
and `--sim-isdr-config`, `--sim-eim-identity`, `--sim-euicc-store` and
`--sim-profile-store` change its settings. `--sim-import-profile <file>`
puts a profile package on the simulated card before the launch, and
`--sim-import-enable` enables it. `yggdrasim-gui` and `yggdrasim-web-server`
take the same options. The module commands of section 1.2 take none of
them; they follow the saved choice or the environment
(`YGGDRASIM_CARD_BACKEND=sim`, `YGGDRASIM_SIM_QUIRKS=none`).

## 5. Other commands

| Command | Does |
| --- | --- |
| `yggdrasim-mcp` | The MCP server over stdio, for an MCP client; card tools stay off unless `YGGDRASIM_MCP_ALLOW_CARD=1` (`site-docs/how-to/run-the-mcp-server.md`) |
| `yggdrasim-apdu-dissect` | APDU decoding inside Wireshark and tshark: install, decode, sidecar |
| `yggdrasim-apdu-fuzzer` | APDU mutation fuzzing, for lab cards only, behind an ICCID or IMSI allow list |
| `yggdrasim-eum-diag` | EUM and SM-DP+ diagnostics: session keys for the dissector, bound profile package decode |
| `yggdrasim-card-clone` | Charts a card's behaviour, read-only, into a profile the simulator can replay |
| `yggdrasim-profile-autoload` | Watches the simulator's profile store and opens each new profile in the SAIP Tool |
| `yggdrasim-session-diff` | Compares the APDU traces of two recordings (section 2.4) |
| `yggdrasim-yggdracore` | The 5G core stub over HTTP, off unless `YGGDRASIM_5GCORE_MODE=stub` |
| `yggdrasim-scp11-relay` | The eSIM Management console under its older name |

Each takes `--help`, and `site-docs/reference/command-suite.md` sections 10
to 12 describe them.
