<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# User Manual -- GUI

This chapter covers the Command Center, the graphical surface of
YggdraSIM, in a desktop window or a browser. Section 4 follows the sidebar
from top to bottom. The concepts both surfaces share -- the card backend,
readers and reader locks, where data is kept, configuration flags -- are in
`USER_MANUAL.md` section 3, and the same modules on the command line are in
`USER_MANUAL_CLI.md`.

## 1. Start the GUI

### 1.1 Desktop window

```bash
yggdrasim-gui                       # from a terminal
yggdrasim-desktop                   # the same, without a console window
yggdrasim-gui <profile package>     # opens the file in the SAIP Tool
yggdrasim-gui --card-backend sim --sim-quirks none   # on the simulated card, for this run
```

`--card-backend`, the `--sim-*` options and `--debug` apply to the GUI run
they are given to. Without them the GUI runs on the backend saved in the
launcher menu `[C]`, or the one the environment names
(`USER_MANUAL.md` section 2.3).

The desktop GUI listens on `127.0.0.1:27853` (on another free port when
that one is taken), makes its own access token and opens the window on it;
there is nothing to configure. The window zooms
with Ctrl+plus, Ctrl+minus and Ctrl+0 (or Ctrl and the mouse wheel), and the
chosen factor is kept for the next start. Closing the window, or the `×` at
the right end of the top bar, stops the server and the helpers it started.

The desktop GUI needs the `[gui]` extra (`USER_MANUAL.md` section 2.1).

### 1.2 In a browser

The same page can be served to a browser. The server refuses to start
without a token file:

```bash
mkdir -p ~/.config/yggdrasim
install -m 600 /dev/null ~/.config/yggdrasim/gui.token
python -c "import secrets; print(secrets.token_urlsafe(32))" > ~/.config/yggdrasim/gui.token
yggdrasim-web-server --host 127.0.0.1 --port 27854 --token-file ~/.config/yggdrasim/gui.token
```

Open `http://127.0.0.1:27854/?t=<token>` with the content of the token
file. The page keeps the token for that browser tab and removes it from the
address bar. Wrong tokens are counted: after several in a row the server
answers every call with a refusal for a while, and the page reports
"Rate-limited by auth backoff. Wait and retry."

Keep the server on the loopback address. To use it from another machine,
forward the port over SSH instead of binding it to the network:

```bash
ssh -fN -L 27854:127.0.0.1:27854 <user>@<lab host>
```

`site-docs/subsystems/gui-command-center.md` covers TLS and the other
server options. The browser server needs the `[gui-server]` extra.

## 2. The window

### 2.1 Top bar

From left to right:

| Element | What it does |
| --- | --- |
| Sidebar button (left arrow) | Hides the sidebar; click again to bring it back. Shift+click or right-click sets it to hide by itself. |
| Title and breadcrumb | Where you are, for example `Command Center · File system` |
| Version | The YggdraSIM version |
| HIL BRIDGE, REMOTE | State of the HIL bridge and of the remote rig; `stopped` while neither runs |
| BACKEND Reader / SIM | Switches between the reader and the simulated card for this GUI session (`USER_MANUAL.md` section 2.3) |
| Reader pill | The reader the modules work on; the Refresh readers button beside it reads the reader list again |
| `online` | The page reaches its server |
| Skin and theme | Two skins (Bench, Classic) and 22 colour themes, light and dark |
| Up arrow, `×` | Collapses the top bar; closes YggdraSIM |

### 2.2 Sidebar

The sidebar lists the modules in groups. The number beside a module is the
number of actions it offers.

| Group | Modules |
| --- | --- |
| Card Administration | File system, Applications, Over-the-Air |
| eSIM (SCP11) | Management, Local SM-DP+, Local eIM |
| Tools | SAIP Tool, Offline Tools (with an entry per tool) |
| APDU Streaming | Remote Lab, Remote Bridge |
| Advanced | HIL Bridge, SIM card helpers, Shell, Host shell, Registry browser |
| Environment | Configuration |
| Meta | Overview, About |

Overview shows the same modules as cards, with the card backend in use
below them.

### 2.3 A module's panes, the dock and the status bar

Most modules have three panes: the actions on the left, the form and its
answer in the middle, and an inspector on the right that shows the state
of the card or the module (the card overview, the OTA settings, the
certificate inventory).

Below the panes, the dock has five tabs:

| Tab | Shows |
| --- | --- |
| Messages | One line per action run and per notable event |
| Warnings, Errors | What went wrong, kept apart |
| APDU | Every APDU exchange of the server process, from every module |
| Validation | The findings of the last SAIP lint |

Copy copies the open tab and Clear all empties the dock. With the focus in
the dock and no text selected, Ctrl+C copies the open tab too.

The status bar at the very bottom names the view, the readers and sessions,
the last activity and the EID and ICCID of the card in use. Its four keys
open and close the panes; Alt+1 to Alt+4 do the same:

| Key | Pane |
| --- | --- |
| Alt+1 | Sidebar |
| Alt+2 | Actions (named Files in File system, Packages in SAIP Tool) |
| Alt+3 | Inspector |
| Alt+4 | The dock |

### 2.4 The reader gate

A module that needs a card shows a reader list first ("Select a reader
before running this reader-backed surface."). Pick the reader there or with
the reader pill; the module then opens on it. File system and Applications
then show "Open '<reader name>'", which starts the session and scans the
card.

The eSIM Management module reads a card overview when it is entered. It
skips that read, and says why, while another session holds the reader --
for example a File system session on the same reader ("card overview not
loaded: a File system session holds this reader"); Load card overview
reads it on request.

## 3. Run an action and read the answer

### 3.1 Run

1. Open the module and the tab the action is in, and click the action. Its
   form opens in the middle pane with a line on what the action does.
2. Fill the fields. A required field is marked `*`; the line under a field
   says what it takes. A form uses the reader the module is open on.
3. An action that changes the card may show "Persistent or disruptive
   action" and a checkbox to tick before it runs. Not every card-changing
   action asks; `USER_MANUAL.md` section 4.1 lists which do.
4. Press Run, or Start for an action that streams. The status line beside
   the button follows the run, from Ready to Completed or Failed.

### 3.2 Streams

An action that runs for a while (a download, a listener, a supervisor
watch) streams its lines under the form as they arrive and shows a Cancel
button. It keeps running when you open another module; its form, its
output and Cancel come back when you return to it. Closing or reloading the
page ends it.

### 3.3 Read the answer

The answer renders under the form:

- summary rows (Reader, Target, Status, Note, and what the action
  returns);
- RESULT TREE, the returned data field by field;
- CONSOLE TRACE, the lines the action printed, with the same markers as
  the CLI (`USER_MANUAL.md` section 3.6);
- for some actions SHOW JSON and COPY JSON.

Read the Status row together with the trace. For the profile actions of
eSIM Management, Status reads `failed` when the trace has a `[-]` line or a
`[!]` line other than a warning, and the module's status line then reads
"<operation> failed". The Notification sync that follows a profile state
change is reported on its own: when it does not complete, Status stays `ok`
and the Note says so, because the card has made the change. A profile
disable on the simulated card, whose Notification names an SM-DP+ that
cannot be reached, shows it:

```text
[+] DisableProfile: success.
[*] Notification sync: routing queued notification seq=1 to SM-DP+ rsp.example.com ...
[*] Notification sync: handleNotification failed for queued notification seq=1 (...)
[*] Notification sync: 1 notification(s) could not be forwarded to SM-DP+; leaving the unforwarded entries on-card for the next attempt.
```

The answer reads `ok`, `notification_sync` `incomplete`, and the Note
"Notification sync did not complete; the Notifications it did not deliver
stay on the eUICC (see the trace)". The card overview's profile list and its
Notifications count show the outcome.

## 4. Modules

### 4.1 File system

Card Administration, File system walks the card's file system: the MF, the
DFs, the ADFs of the applications (USIM, ISIM) and their EFs.

After the reader gate and Open, the module shows:

- a row of chips: the scope, the ATR, the ICCID, `eUICC` when the card has
  an ISD-R, the session, and the authentication state (`AUTH: NOT
  AUTHENTICATED` until Applications authenticates, section 4.2);
- a ribbon with four tabs (HIDE TOOLS folds it):

| Tab | Groups and buttons |
| --- | --- |
| HOME | Navigate: Rescan, Clear selection, Reset card. Inspect: Read selected, SELECT..., List apps, READ, RECORD..., ARR |
| DIAGNOSTICS | ATR, Card info, Decode..., Dump FS...; Validate, Cert info |
| APDU | The raw APDU console |
| ADMIN | Crypto: Derive OPc, Auth vector. Config: Show config, AID alias, Reset keys. Sub-shells: STK mode, OTA shell. Scripts: Run script, FS report, Guides. Session: Close |

- the FILES tree, each node with its type (MF, DF, EF) and file identifier,
  an ADF with its AID;
- the detail pane of the selected file.

Click a file to select and read it. The detail pane shows its path and
FID, its type, the FCP (size, SFI, life cycle state, the EF.ARR record
that sets its access rules), the body with its status word, and a decoded
view where YggdraSIM knows the file. EF.ICCID on the simulated card reads:

```text
path: MF/EF_ICCID   fid: 2FE2   EF · transparent
FCP     file size 10 B · SFI 02 · Operational state - activated · ARR 2F06 record 1
Body    SW: 9000 · length 10
iccid   89 88 11 11 11 11 11 11 11 12
```

The buttons of the detail pane write to the card: Update body, Create file,
Lifecycle, and the DANGER group Delete, Resize and Suspend UICC. A write
needs the file's access condition met, for many files an ADM key verified
first.

The APDU tab sends any APDU on the session: pick a preset (SELECT MF,
SELECT ISD-R, GET DATA for the EID, GET STATUS, ...) or type one APDU per
line, `#` starting a comment, and press Send APDU (Ctrl+Enter). The console
follows `61xx` with GET RESPONSE and repeats a `6Cxx` command with the
length the card asks for; each can be turned off. The card's current DF is
left where the APDUs put it; the next click in the tree selects from the MF
again.

### 4.2 Applications

Card Administration, Applications works on the GlobalPlatform side of the
same session: secure channels, the registry, installs, and the eUICC. The
file tree is hidden here; a handshake made here also counts for the File
system module.

| Tab | Groups and buttons |
| --- | --- |
| AUTH | Auth: Auth SCP03, Auth SCP02, Logout, Keys. Live AAA: PIN, Channel, Run AUTH |
| REGISTRY | Registry: Apps, Packages, Sec. domains, GET DATA..., AIDs. Mutate: Set status, Lock, Unlock, Delete, STORE DATA..., UPDATE BIN, UPDATE REC |
| INSTALL | PUT KEY, Install CAP, Install script, Install app, Make selectable, Extradition, Perso, Reg. update |
| EUICC | Profiles: Profiles, eUICC scan. eUICC: EID, eUICC certs, Config data, SGP.32 bulk, Enable, Disable, Delete profile. Snapshots: Set gold, Show gold, Clear gold, Diff. Export: eUICC YAML, Keybag |
| APDU, ADMIN | As in File system |

Worked example, on the simulated card:

1. AUTH, Auth SCP03. The form takes a target AID and overrides for the KVN
   and the three keys; left empty, it uses the issuer security domain and
   the keys of `Workspace/SCP03/keys.ini`. An override is used for the
   session only and never stored.
2. Authenticate. The answer reads `Status AUTHENTICATED`, `Protocol SCP03`,
   `Target AID A000000151000000`, `KVN 30`, `Sec level 33`, and the chip
   in the top row becomes `AUTH: SCP03 / AID=A000000151000000 / KVN=30`.
3. REGISTRY, Apps. The answer lists every application with its life cycle
   state and privileges:

```text
AID                                STATE         EXTRA
A0000005591010FFFFFFFF8900000200   PERSONALIZED  9EFE80
A000000151000000                   SELECTABLE    800000
A0000000871002FF86FF112233445566   SELECTABLE    000000
```

The Mutate and Install actions need an authenticated session. They change
the card's content; see `USER_MANUAL.md` section 4.1 for the ones that ask
before they run.

### 4.3 Over-the-Air

Card Administration, Over-the-Air builds SCP80 secured packets (ETSI TS
102 225 and TS 102 226), sends them to the card as SMS-PP envelopes and
decodes the answer.

The inspector holds the OTA profile:

| Section | Fields |
| --- | --- |
| Security | Counter (CNTR), SPI flags, KIc key set, KID key set, TAR |
| Transport | Transport mode, Print APDUs, Concatenated SMS on or off, TP-UD max bytes |
| Payload | Default payload (APDU hex), ICCID profile; Refresh, Save config, Bind ICCID |
| Send options | Payload override, Script file, Verbose APDU trace |
| Runtime | The configuration file, the reader, the ICCID, the protocol, the ATR |

Its buttons are Send OTA, Build plan, Smart OTA, Raw APDU, Script, Protocol
and Reset transport. Build plan is the dry run: it shows the segments, the
counter, the payload and the APDUs that a send would use, and sends
nothing. Send OTA sends; Smart OTA builds, sends and decodes the answer in
one step. Bind ICCID keeps the settings per card, so the right keys come
back when that card is used again.

### 4.4 eSIM Management

eSIM (SCP11), Management works on an eUICC as the LPA (SGP.22) or the IPA
(SGP.32) would.

The inspector holds the card overview, read when the module is entered:

- Card Identity: the EID and the issuer of the eUICC certificate;
- Profiles: one block per profile with its state, name and AID, and its
  Enable or Disable and Delete buttons;
- euiccConfigurationData: the default SM-DP+, the root SM-DS, further
  SM-DS addresses, the allowed CI key identifiers;
- eUICC Info2: the versions, the IPA mode, the IoT details;
- eIM Configuration: the eIMs the card knows;
- Notifications: the number pending.

The profile buttons ask in a dialog before they run ("Disable Lab (EU
01)?").

The actions are in two tabs. Reads such as Get EID or List profiles have no
button: the overview shows them.

| Tab | Actions |
| --- | --- |
| SGP.22 Consumer (LPA-d) | Download profile (activation code), Full SCP11 flow, Set default SM-DP+, Remove notification, Clear all notifications, Reset card session, Set ES9 base URL, Set ES9 TLS verification, Set ES9 CA bundle |
| SGP.32 IoT (IPA-d) | eIM download (SGP.32), eIM authenticate, Verify SCP11 handshake, AddInitialEim send, Listen for injected eIM packages, Get Profile Policy Rules, Set Profile Policy Rules, Get profile metadata, Get all profile metadata, Store profile metadata, Get all data (consolidated) |

Download a profile:

1. SGP.22 Consumer (LPA-d), Download profile (activation code).
2. Enter the activation code (`LPA:1$smdp.example.com$MATCHING-ID`).
3. Tick "I understand this installs a new profile on the card" and press
   Start. The download streams its steps. When it ends, enter the module
   again to read the card overview with the new profile.

After a profile state change the module delivers the card's Notifications
to the SM-DP+ each names and removes the delivered ones from the card
(`USER_MANUAL.md` section 4.1, item 4).

### 4.5 Local SM-DP+

eSIM (SCP11), Local SM-DP+ loads a profile package from disk straight onto
an eUICC, acting as the SM-DP+ itself, with certificates kept on this
machine.

The inspector holds:

- Profile, Certificate and Private key, each with Browse..., and a choice
  of DPauth, DPpb or auto for an imported certificate; Import cert,
  Inventory, Load profile;
- a drop zone: a profile package dropped there is loaded onto the card;
- the DPAUTH and DPPB rows: the certificate and key in use and how many
  candidates exist;
- the card overview, as in eSIM Management.

The card answers AuthenticateServer only for a certificate chain under a CI
it lists, so the DPauth certificate has to match the card. Without a match
the load stops at the start and the trace names the CI key identifiers the
card allows. `SCP11/local_access/certs/README.md` and
`CONFIGURATION_AND_CERTIFICATES.md` say where the certificates go.

| Tab | Actions |
| --- | --- |
| Local SM-DP+ Provisioning | Store metadata, Update metadata, Store metadata (custom tag), Store metadata (all custom tags), Lint metadata JSON |
| Card & Session Operations | Enable profile, Disable profile, Delete profile, Retrieve notifications list |

### 4.6 Local eIM

eSIM (SCP11), Local eIM runs an SGP.32 eIM on this machine. It has an
identity (an eimId, an FQDN and a signing key), it is associated with
cards, it queues operations for each card and signs them when the card's
IPA takes them, and it keeps every result. `SCP11/eim_local/GUIDE.md` is
its full guide.

The middle pane is the Local eIM page with two tabs, eUICCs and eIM
configuration. The action list has five tabs: Operations, eUICCs, eIM
configuration, Direct card commands and Package files; the page covers the
daily work, the action list the rest.

First use, on the simulated card:

1. The page says "This eIM has no identity yet". Create identity opens
   the New eIM identity form; Run with the fields empty makes one with
   eimId `1.3.6.1.4.1.32473.999.10.124` and FQDN `eim.yggdrasim.local`.
   The form back link at its top returns to the page.
2. The eUICCs tab lists the cards the eIM has seen (EID, Label, This eIM,
   Profiles, Last polled, Operations). Read the card in the reader adds
   the card in the reader; Register an EID adds one by hand. Open the
   card's row.
3. The card's page shows its pending operations, its profiles, its eUICC
   information, the eIMs linked with it, its Notifications and its event
   log. Under eIMs linked with eUICC, Link this eIM opens the Associate
   card form. It resets the card's eIM configuration and adds this eIM as
   the only one ("Every other eIM leaves the card"); tick Confirm and Run.
   The answer ends with the association token (first block below).
4. Refresh eSIM profile list queues a List profiles operation. A queued
   operation waits until the card's IPA asks for it, or until Deliver now
   (IPAd) sends the queue through the card in the reader.
5. Deliver now (IPAd). The delivery report lists each operation with its
   result and the run output.
6. Click an operation in the report or in the event log. The operation
   view shows its state, its timeline, the package as served and the card's
   answer, each data object by name (second and third blocks below).

The end of the Associate card answer:

```text
[+] resetEimResult: ok (0)
[+] AddInitialEim: associationToken 1
[+] record 89049032123451234512345678901235: associationToken 1, counterValue 0
```

The List profiles package as served:

```text
BF51  EuiccPackageRequest   eimId 1.3.6.1.4.1.32473.999.10.124, EID 89049032123451234512345678901235, counter 1, ...
BF2D  listProfileInfo       every Profile
5F37  eimSignature          64 bytes
```

and the card's answer:

```text
BF51  euiccPackageResultSigned  eimId 1.3.6.1.4.1.32473.999.10.124, counter 1, ...
BF2D  listProfileInfoResult     ok
E3    ProfileInfo               ICCID 89881111111111111112 enabled operational ...
```

A delivery also takes the card's pending Notifications: they are
acknowledged, the card drops them, and the Local eIM forwards each to the
SM-DP+ it names (or keeps it, see `USER_MANUAL.md` section 4.1). The
simulated card's Notifications name `rsp.example.com`; the report says they
were not sent because no Notification Receiver answers there.

The eIM configuration tab shows the identity and its certificate, the TLS
setups the card-facing listener serves, the service (Start service,
Traffic, the ports and the log file) and the queue rules. A card's IPA
polls the eIM only while the service runs; Deliver now needs no service.

### 4.7 SAIP Tool

Tools, SAIP Tool opens profile packages (SAIP), shows them element by
element, lints and edits them, and builds new ones from templates.

Open a package with Open on the ribbon (Ctrl+O), by dropping `.der`,
`.json` or `.hex` files on the module, or from the command line
(`yggdrasim-gui <file>`). The Open packages list on the left holds every
open package; the tabs above the middle pane switch between the PE list,
the FS tree (every file of the profile) and the AID directory, each with a
count.

| Ribbon tab | Buttons |
| --- | --- |
| PACKAGE | New, Open, Recent, Close, Save, Save as..., Revert, Diff vs saved, Compare |
| ACTIONS | Trim padded content |
| ELEMENT | Add above, Add below, Delete, Move up, Move down, Import PE, Export PE, Save PE, PE library, Undo, Redo |
| FILE SYSTEM | Find, Sync ARR |
| TOKENS | Variables, Generate test profile, Batch generate |
| LINT | Validate, Batch lint, Save report |
| ADVANCED | All actions, Refresh |
| REFERENCE | Spec card, Guides |

Click a profile element to open it. Its Decoded view edits the element's
fields by name, the JSON tab shows it whole. Edits stay in the open package
until Save or Save as...; Revert drops them and Diff vs saved shows them.

Validate lints the open package. The summary line goes to the dock
(`SAIP.VALIDATE score 73 · FAIL 1 · WARN 5 · INFO 0` for the reference
test profile) and the findings to its Validation tab: the score, the
counts per severity, Re-validate and a STRICT switch, and a click on that
row unfolds the findings grouped by rule, each with its severity, code,
specification, path and message, and a jump to the profile element it
concerns. All actions lists every SAIP action by name, including those
without a ribbon button. Templates, placeholders and test
values are described in `TEMPLATE_AND_TOKENS.md`.

### 4.8 Offline Tools

Tools, Offline Tools works on data alone and never touches a card, except
AddInitialEim send. Each tool has its own entry under Offline Tools in the
sidebar:

| Entry | Does |
| --- | --- |
| Decoder | Decodes an APDU, an answer, a whole exchange trace, a script of one APDU per line, a bare TLV, a status word or EF content |
| TERMINAL PROFILE | Decode: names each facility a TERMINAL PROFILE claims, or compares two. Build: makes one facility by facility |
| AddInitialEim | Build makes an ES10b AddInitialEim from stored certificates and shows the APDUs of the run without touching a card; Send sends it; Configurations, Certificate store and Saved values keep what the builder reuses |
| eIM package lint | Checks an eIM package document (JSON) and lists errors and warnings |
| SUCI keys | Use key file, Generate, Dump public key, through pySim's `suci-keytool` |
| TUAK -- derive TOPc | TOPc from TOP and K (3GPP TS 35.231) |
| GSMA error-code reference | The SGP.22 and SGP.32 result and error code tables |

The Decoder takes the input as it comes: hex with or without spaces, a
trace with `>` before a command and `<` before its answer, AT+CSIM lines,
PEM, base64, an EID or ICCID in digits, an ATR. Context picks the
specification (Auto-detect is the default), Example loads a worked input,
Open file reads a script file, Decode runs (Ctrl+Enter). The answer names
every field and cites the table it comes from:

```text
> 80E2910003BF2D0000
< BF2D14A012E3105A0A988802214365870921F39F700101 9000
```

decodes to STORE DATA carrying a ProfileInfoListRequest, then a
ProfileInfoListResponse with one profile: ICCID `8988201234567890123`,
profileState 1 (enabled).

SUCI keys needs the `suci-keytool` command; set it with the
`YGGDRASIM_SUCI_TOOL` flag under Configuration (section 4.14). The tool's
status line says which command is in use.

### 4.9 APDU Streaming: Remote Lab and Remote Bridge

These two modules move a card between machines.

- Remote Lab lists rigs other operators publish with a Remote Lab agent.
  Import adds the rigs of a `.ygglab` invite; a rig is reserved by token
  and its card then appears as a reader `Remote Lab: <device>`.
- Remote Bridge prepares a host over SSH and drives it yourself: the PC
  bridge publishes the local reader, the SSH tunnel carries it, and the HIL
  service on the remote host relays the APDUs to its modem. The default
  port plan is card 8642, GUI 27854, HIL 9997.

`CARD_BRIDGE_GUIDE.md` and `site-docs/how-to/run-a-remote-lab-agent.md`
are the guides.

### 4.10 HIL Bridge

Advanced, HIL Bridge puts the card in the reader in place of a modem's SIM
through a SIMtrace2 board and decodes the traffic between them (Linux,
full install). Pick the reader in the top bar, then:

- Session: Start launches the supervised session, Stop ends it; Start APDU
  Stream puts this machine's card on another machine's modem.
- Source: Live, or Open pcap to review a saved capture without a session.
- View: Refresh, Auto-refresh, Pause, Context, Clear view.

The lower tabs are the dissector (frame, decoded fields, bytes), the raw
APDU trace and a modem shell. `HIL_BRIDGE_GUIDE.md` covers the hardware and
the setup.

### 4.11 SIM card helpers

Advanced, SIM card helpers has three read-only actions for the simulator:
Profile store -- list, Quirks -- status, eUICC store -- list.

### 4.12 YggdraCore

Advanced, YggdraCore is the 5G core stub: an AUSF and an AAnF that live in
the GUI process. Its tabs:

- Subscriptions: add or update, list, delete and clear the subscribers
  (SUPI, K, OPc, AMF, SQN, the home network) the stub authenticates.
- AKMA: Derive AKMA keys from a KAUSF and a SUPI, and the AAnF stub
  (register an A-KID, list, clear, establish an AF session through it).
  The AUSF registers the A-KID and KAKMA of every 5G AKA it completes in
  the same AAnF.
- Open5GS: detect an Open5GS installation and read, provision or remove
  subscribers in its database, the one `YGGDRASIM_OPEN5GS_MONGO_URI` names
  (default `mongodb://127.0.0.1:27017`). Remove subscriber and Purge
  YggdraSIM-managed docs ask first.
- Diagnostics: Status (the mode, the counts and the HTTP endpoints) and
  Clear in-flight auth contexts.

The actions run whatever `YGGDRASIM_5GCORE_MODE` says; the mode only
decides whether `yggdrasim-yggdracore` serves the stub over HTTP (CLI
chapter, section 5).

### 4.13 Shell and Host shell

Shell runs one of the CLI shells inside the page, in a terminal tab:
choose the module (SCP03, SCP80, SCP11, SCP11.live, SCP11.relay,
SCP11.local_access, SCP11.eim_local, Tools.CardBridge,
Tools.ProfilePackage, Tools.SuciTool) and Open tab. Paste works, Ctrl+C
interrupts the shell, and several tabs can run side by side. Only these
modules can be started; the page runs no other command. It is the way to
reach a verb that has no form.

Host shell is a terminal on the GUI host itself, for modem tools such as
`minicom` or `socat`. It is off unless `YGGDRASIM_GUI_HOST_SHELL=1` is set
before the GUI starts; `GUI_HOST_SHELL_GUIDE.md` explains the risk and the
setup.

### 4.14 Registry browser, Configuration, About

- Registry browser lists the engine's entry points (key, module,
  attribute), the functions the commands call into.
- Configuration lists the `YGGDRASIM_*` flags by group, each with its
  current value and its scope. Set a value, tick persist to keep it, and
  confirm the extra line a sensitive flag shows; Clear removes it; Reset
  persisted overrides removes every kept value. The loaded plugins are
  listed at the end. `USER_MANUAL.md` section 3.5 explains the flags.
- About lists the guides, this manual among them. A click opens one in a
  reader window with a Copy button; a guide the running build does not
  include is shown disabled.

## 5. Keyboard

| Keys | Where | Does |
| --- | --- | --- |
| Alt+1 to Alt+4 | Anywhere | Open or close the sidebar, the actions pane, the inspector, the dock |
| Ctrl+O | SAIP Tool | Open a package |
| Ctrl+Enter | Decoder, APDU console | Decode; send |
| Escape | A dialog or panel | Close it |
| Ctrl+C | The dock, with no text selected | Copy the open tab |
| Ctrl+plus, Ctrl+minus, Ctrl+0 | Desktop window | Zoom in, out, back to the native size |

## 6. Not on the page

- `yggdrasim-yggdracore` serves the 5G core stub over HTTP; the page has
  its actions (section 4.12) but no control that starts the server
  (`site-docs/reference/command-suite.md` section 12.8).
- A shell verb without a form runs in Shell (section 4.13).
