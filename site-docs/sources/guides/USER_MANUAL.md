<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# YggdraSIM User Manual

YggdraSIM drives SIM cards, UICCs and eUICCs from a PC/SC reader, or a
simulated card in their place. It runs from two surfaces: a graphical
Command Center in a desktop window or a browser, and a set of command-line
shells. Both reach the same engine, so a task done in one can be done in the
other.

The manual has three files:

| File | Covers |
| --- | --- |
| `USER_MANUAL.md` (this file) | What each module is for, installing and starting, the concepts both surfaces share, work on a real card, what to do when something fails |
| `USER_MANUAL_GUI.md` | The Command Center: the window, running an action and reading its answer, every module in sidebar order |
| `USER_MANUAL_CLI.md` | The shells: the launcher, how every shell works, every module in the same order as the GUI chapter |

`RUNBOOK.md` is the one-page version: one row per task with the CLI command
and the GUI place side by side. The full verb reference of every shell is
`site-docs/reference/command-suite.md`. Examples in this manual use the
reserved test values of the project (`8988...` ICCIDs, `89049032...` EIDs,
`*.example.test` host names) and the answers of the simulated card.

## 1. Modules

Each module has a place in the GUI sidebar and a command on the CLI. The
section columns name where each chapter describes it.

| Module | What it is for | GUI place (GUI section) | CLI command (CLI section) |
| --- | --- | --- | --- |
| File system | Walk and read the UICC file system, send raw APDUs | Card Administration, File system (4.1) | `yggdrasim-scp03` (4.1) |
| Applications | GlobalPlatform secure channel (SCP03, SCP02), the card registry, applet installs, eUICC reads | Card Administration, Applications (4.2) | `yggdrasim-scp03` (4.1) |
| Over-the-Air | Build, send and decode SCP80 OTA packets | Card Administration, Over-the-Air (4.3) | `yggdrasim-scp80` (4.2) |
| eSIM Management | Read an eUICC, download a profile with an activation code, enable, disable and delete profiles, Notifications, the SGP.32 IPAd functions | eSIM (SCP11), Management (4.4) | `yggdrasim-scp11-live` (4.3) |
| Local SM-DP+ | Load a profile package from disk onto an eUICC with local SM-DP+ certificates, profile metadata | eSIM (SCP11), Local SM-DP+ (4.5) | `yggdrasim-scp11-local-access` (4.4) |
| Local eIM | An SGP.32 eIM run on this machine: identity, association with a card, an operation queue, delivery to the card, a service IPAs poll | eSIM (SCP11), Local eIM (4.6) | `yggdrasim-scp11-eim-local` (4.5) |
| SAIP Tool | Inspect, lint, edit and generate profile packages (SAIP) | Tools, SAIP Tool (4.7) | `yggdrasim-profile-package` (4.6) |
| Offline Tools | Decoder, TERMINAL PROFILE, AddInitialEim builder, eIM package lint, SUCI keys, TUAK, GSMA error codes | Tools, Offline Tools (4.8) | `yggdrasim-asn1`, `yggdrasim-suci-tool` and others (4.7) |
| APDU Streaming | Use a card that sits in a reader on another machine, or share rigs between operators | APDU Streaming (4.9) | `yggdrasim-card-bridge`, `yggdrasim-lab-agent`, `yggdrasim-lab` (4.8) |
| HIL Bridge | Bridge a card in a reader to a modem through a SIMtrace2 board and capture the traffic (Linux) | Advanced, HIL Bridge (4.10) | `yggdrasim-hil-supervisor`, `yggdrasim-hil-bridge` (4.9) |
| Simulator | A simulated UICC and eUICC in place of a reader | top bar BACKEND switch; Advanced, SIM card helpers (4.11) | launcher menu `[C]` (4.10); section 2.3 of this file |
| YggdraCore | A 5G core stub (an AUSF and an AAnF) for authentication and AKMA tests, its subscriber store, and a bridge to an Open5GS database | Advanced, YggdraCore (4.12) | `yggdrasim-yggdracore` (5) |

## 2. Install and first start

### 2.1 Install

Pick the install guide that matches the machine:

| Guide | For |
| --- | --- |
| `INSTALL_CLEAN.md` | The release executables without the HIL bridge (Windows, macOS, Linux, Raspberry Pi) |
| `INSTALL_FULL.md` | The release executable with the HIL bridge (Linux) |
| `INSTALL_FROM_SOURCE.md` | A source checkout, with the extras matrix |
| `INSTALL_RASPBERRYPI.md` | Raspberry Pi specifics |

From a source checkout, the base install and the GUI are:

```bash
python -m pip install -e '.[saip]'
python -m pip install -e '.[gui]'          # desktop window
python -m pip install -e '.[gui-server]'   # browser access, no desktop window
```

The editable install puts the commands of section 1 on the `PATH` of that
environment (`yggdrasim`, `yggdrasim-gui`, `yggdrasim-scp03`, ...).

### 2.2 Check the environment

```bash
yggdrasim --doctor
```

The check is read-only. It lists Python and the libraries, the pySim in use,
the runtime root (section 3.4), the readers, the optional tools (`gpg`,
`tshark`, `dfu-util`) and whether the GUI can start:

```text
[+] Python runtime: OK -- 3.13.7 (>= 3.10)
[+] pySim SAIP runtime: OK -- pySim.esim.saip
[+] Workspace root: OK -- /home/<user>/YggdraSIM
[*] Remote card bridge: INFO -- Not configured -- set YGGDRASIM_CARD_RELAY_URL or ...
[+] GUI desktop default port: OK -- 127.0.0.1:27853 is free
```

`[+]` is a check that passed and `[*]` a warning or a note. The command ends
with exit code 1 when any check warns, so it can gate a script.

### 2.3 First start without a card

The simulator answers like a UICC with an eUICC: a file system with a USIM,
a GlobalPlatform registry, an ISD-R with two test profiles and an eIM
configuration. It is the place to learn the tool and to rehearse a procedure
before it runs on a real card.

There are three ways to select it:

| Way | Lasts | Reaches |
| --- | --- | --- |
| Launcher menu `[C]`: `[2]` Use simulated SIM card, then `[D]` Disable simulator quirks | Until changed there (`[1]` returns to the reader) | Every later command and the GUI |
| `yggdrasim --card-backend sim --sim-quirks none` | That launcher run | The modules started from it; the GUI takes the same options (`yggdrasim-gui --card-backend sim --sim-quirks none`) |
| `YGGDRASIM_CARD_BACKEND=sim` and `YGGDRASIM_SIM_QUIRKS=none` in the environment | One process | Any command, the GUI included (`YGGDRASIM_CARD_BACKEND=sim YGGDRASIM_SIM_QUIRKS=none yggdrasim-gui`) |

The environment wins over the saved choice, and a launcher option wins over
both for its run: `yggdrasim-gui` and `yggdrasim-web-server` take
`--card-backend`, the `--sim-*` options and `--debug` like any other launcher
run. The GUI's BACKEND switch in the top bar changes the backend for that GUI
session only.

The quirks file is Python the simulator would run from the runtime root
(`Workspace/SIMCARD/sim_quirks.py`). As first seeded it is the shipped
template, which defines nothing, and the simulator starts without asking.
Once it is edited, loading it is refused until it is allowed
(`YGGDRASIM_ALLOW_QUIRKS=1`, for a file you trust) or switched off as above,
and a simulator started with neither stops at once:

```text
[!] Connection failed: Simulator quirk loading is disabled by default because it executes arbitrary Python from disk. ...
```

The simulated card keeps its state between runs in
`Workspace/SIMCARD/euicc_store` under the runtime root, so a profile
disabled today is still disabled tomorrow.

## 3. Concepts both surfaces share

### 3.1 Readers

A command works on one reader at a time.

- On the CLI, `yggdrasim-scp03`, `yggdrasim-scp11-live` and
  `yggdrasim-scp11-local-access` take `--reader "<reader name>"` with the
  exact PC/SC reader name. Without it they open the first reader the system
  lists. `yggdrasim-scp11-eim-local` has no reader option and always uses
  the first reader; `yggdrasim-scp80` uses the reader of its configuration
  (`show` lists `reader_idx` and `reader_name`).
- In the GUI, the reader pill in the top bar binds the reader the modules
  work on. Binding a reader starts nothing; a module that needs a reader
  asks for one first (GUI section 2.4).
- A reader of another machine reached through the Remote Lab appears as
  `Remote Lab: <device>` and is named the same way.

Name the reader whenever more than one is attached. Reader order can change
when a reader is plugged in or out.

### 3.2 One user per reader

Two programs sending APDUs to one card at the same time break each other's
sessions, so YggdraSIM keeps a lock per reader across processes. A command
that finds the reader held is refused with the holder named:

```text
reader busy: GET-EID in the eSIM Management console (pid 4242) has held '<reader name>' since 10:15:02
```

- A short holder (one command) is waited for; a long one (a stream, the HIL
  bridge, a listener) is refused at once.
- Taking part: GUI card actions, the card commands of the eSIM Management
  shell, the card verbs of the Local eIM shell, the HIL bridge and the MCP
  card tools.
- Not taking part: the SCP03, SCP80 and Local SM-DP+ shells, the Card
  Bridge and programs that are not YggdraSIM. They are neither refused nor
  seen, so do not run them against a reader another session is using.

Wait for the holder to finish or stop it. Do not unplug the reader under a
running session.

### 3.3 What the card backend changes

With the simulator selected, every card-facing module talks to the
simulated card and no reader is opened. Everything else -- the stores, the
Local eIM, the SM-DP+ and SM-DS addresses a flow contacts -- is the same as
with a reader. A download that names a real SM-DP+ reaches it from the
simulator too. For a run that must touch nothing real, follow section 4.2.

### 3.4 Where data is kept

The **runtime root** holds the writable state of the tool:

| Install | Runtime root |
| --- | --- |
| Source checkout (editable install) | The repository root |
| Installed wheel | The per-user data directory of the platform |
| Release executable | `YggdraSIM-data/` next to the executable, else `~/YggdraSIM-data/` |
| Any of the above with `YGGDRASIM_RUNTIME_ROOT` set | That directory |

Under it:

| Path | Holds |
| --- | --- |
| `Workspace/SCP03/` | `keys.ini` (the SCP03 and SCP02 keys the Applications module uses), `aid.txt` (AID aliases), `binds.json` (shell macros) |
| `Workspace/LocalSMDPP/` | The default profile and metadata of the Local SM-DP+, and its certificate drop folder `certs/` |
| `Workspace/LocalEIM/` | eIM package templates, the hotfolder, eIM certificates |
| `Workspace/SAIP/` | The default profile and output folders of the SAIP Tool |
| `Workspace/SIMCARD/` | The simulated card's configuration and its stored state |
| `state/` | The device inventory database and the persisted flag values |

Outside the runtime root, per user:

| Path | Holds | Flag that moves it |
| --- | --- | --- |
| `~/.yggdrasim/local_eim/` | The Local eIM store: identity, eUICC records, operations, Notifications | `YGGDRASIM_LOCAL_EIM_STORE` |
| `~/.yggdrasim/eim_builder/` | Certificates, saved values and configurations of the AddInitialEim builder | `YGGDRASIM_EIM_BUILDER_STORE` |

`site-docs/reference/runtime-root.md` has the resolution order;
`CONFIGURATION_AND_CERTIFICATES.md` says where each certificate and key goes.

### 3.5 Configuration flags

Runtime behaviour is set by `YGGDRASIM_*` flags. There are three ways to set
one:

- as an environment variable, for one process;
- in the launcher menu, entry `[E]`;
- in the GUI, Environment, Configuration.

A value set from the menu or the GUI can be persisted. It is written to
`state/env_overrides.json` under the runtime root (or, for
`YGGDRASIM_RUNTIME_ROOT` itself, to `~/.yggdrasim/env_overrides.json`) and
applied at the next start. A flag marked sensitive -- one that weakens a
check or names a command the process runs -- asks for confirmation before it
is written, in the menu and in the GUI alike.
`site-docs/reference/env-flags.md` lists the flags the menu and the GUI
edit, with their defaults.

### 3.6 Reading the output

Both surfaces print the same marked lines:

| Marker | Meaning |
| --- | --- |
| `[*]` | Progress or information |
| `[+]` | A step that succeeded |
| `[-]` | A step that failed |
| `[!]` | A refusal or an error the command stopped on |

A status word in an answer (`6985`, `6A82`) is named by the decoder:

```bash
yggdrasim-asn1 --context --domain sw 6985
```

```text
SW 6985: Conditions of use not satisfied
```

More detail, from least to most:

- `--debug` on a shell command line, or on the launcher for every module it
  starts, prints the raw APDU exchanges.
- `--log <file>` after any shell command line runs that one command with
  debug output and appends everything it prints to `<file>` (CLI section
  2.4).
- The GUI shows every APDU of its process in the APDU tab of the bottom
  dock, and the lines of a running action under its form (GUI section 3).

### 3.7 Plugins

Plugins add operator-supplied capabilities. Loading them is off by default:
`YGGDRASIM_ALLOW_PLUGINS=1` allows it, `YGGDRASIM_DISALLOW_PLUGINS=1` locks
it off. Loaded plugins are listed in the GUI under Environment,
Configuration. This manual covers the tool without plugins.

## 4. Work on a real card

### 4.1 Before a command reaches a real card

1. Rehearse the procedure on the simulator first (section 2.3).
2. Name the reader (section 3.1) and check that nothing else uses it
   (section 3.2).
3. Read before writing: EID, profile list and pending Notifications before
   any state change (`GET-EID; LIST; GET-NOTIFICATIONS` in
   `yggdrasim-scp11-live`, or the card overview of the eSIM Management
   module).
4. Decide what happens to the card's pending Notifications before a
   profile state change. They are signed records of enable, disable, delete
   and install events that the eUICC keeps until they are delivered:
   - the eSIM Management shell and module post them to the SM-DP+ each one
     names after a profile state change, and remove the delivered ones from
     the card (a Notification that cannot be delivered stays on the card);
   - a Local eIM delivery (`DELIVER`, Deliver now) takes the card's
     Notifications and acknowledges them, so the card drops them; the Local
     eIM then forwards each to the SM-DP+ it names and holds none back;
   - `EIM-LISTEN notifications=keep` leaves them on the card.
5. Know which actions write and how each asks.
   - In the GUI, every action that changes a card asks first. Its form
     carries a checkbox, "I have reviewed the target and understand the
     impact.", that has to be ticked before Run (under the heading
     "Persistent or disruptive action" outside the File system and
     Applications workbench). The buttons that run without a form put a question line
     with Confirm and Cancel under themselves: Send OTA packet, Smart OTA
     and Run script file in Over-the-Air, Create file in File system, and
     Deliver now on the Local eIM page. The Enable, Disable and Delete
     buttons of a card overview ask in a dialog. Not asked: the raw APDU
     consoles (Send APDU, Send raw APDU), where every command is typed by
     hand, and the card and transport resets, which change nothing the card
     stores.
   - On the CLI, `ASSOCIATE` asks for the last eight digits of the EID
     (`--yes` skips the question) and `ADD-INITIAL-EIM` asks before it
     sends. The SCP03 verbs `UPDATE`, `DELETE`, `LOCK`, `UNLOCK`,
     `STORE-DATA` and the install verbs act at once; the wizards
     (`PUT-KEY`, `SET-STATUS`, `FS-ADMIN`) ask for their values first.
6. Two writes need particular care:
   - associating a card with the Local eIM (`ASSOCIATE`, Link this eIM)
     and `ADD-INITIAL-EIM` reset the card's eIM configuration first: every
     other eIM leaves the card;
   - `DELETE-PROFILE` removes the profile and its data from the eUICC.
7. After each step, read the result before the next one. A run that ends
   without a `[-]` line is not by itself a success: read the answer.

### 4.2 A simulator run that touches nothing real

Give the run its own runtime root and stores and cut it off from PC/SC
(Linux), so it keeps its state apart from the operator's:

```bash
export YGGDRASIM_CARD_BACKEND=sim
export YGGDRASIM_SIM_QUIRKS=none
export YGGDRASIM_RUNTIME_ROOT=<scratch>/runtime
export YGGDRASIM_LOCAL_EIM_STORE=<scratch>/local_eim
export YGGDRASIM_EIM_BUILDER_STORE=<scratch>/eim_builder
export PCSCLITE_CSOCK_NAME=/nonexistent/pcscd.comm
```

The simulated card's state then lands under `<scratch>/runtime` as well.
The last line is the hard stop: with the PC/SC socket out of reach the
process cannot open a local reader whatever backend it believes it is on.
It does not cover a remote card, so give such a run no remote-card URL. A
flow that names a server on the network still reaches it; the simulated
card's own Notifications name `rsp.example.com`, which no server answers.

## 5. When something fails

1. Read the last lines of the answer. A refusal names its cause, and a
   status word can be decoded (section 3.6).
2. "reader busy: ..." names the action and process that hold the reader
   (section 3.2).
3. Run the one command again with `--log <file>` and read the file.
4. A batch (`--cmd`, `--stdin`) ends with exit code 1 when a command in it
   failed (CLI chapter, section 2.5, says how each shell decides); the lines
   that say which start with `[-]` or `[!]` (a `[!] Warning:` line is a
   caveat, not a failure).
5. In the GUI, an action whose Status reads `failed` has its reason in the
   console trace under the result (GUI section 3.3).
6. `site-docs/reference/troubleshooting.md` is sorted by subsystem;
   `SCP11/eim_local/GUIDE.md` section 13 covers the Local eIM.

## 6. Further reading

| Document | Read it for |
| --- | --- |
| `RUNBOOK.md` | Every task with its CLI command and GUI place, one row each |
| `site-docs/reference/command-suite.md` | Every verb of every shell, every launcher flag |
| `CLI_AND_PIPING_GUIDE.md` | Batch runs, pipes and CI jobs |
| `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` | Ready-to-paste profile lifecycle recipes |
| `CONFIGURATION_AND_CERTIFICATES.md` | Every certificate, key set and configuration drop-in |
| `SCP11/eim_local/GUIDE.md` | The Local eIM in depth |
| `TEMPLATE_AND_TOKENS.md` | Profile templates, placeholders and test values |
| `HIL_BRIDGE_GUIDE.md`, `SIMTRACE2_CARDEM_GUIDE.md` | The HIL bridge and the SIMtrace2 board |
| `CARD_BRIDGE_GUIDE.md` | A reader on another machine |
| `GUI_HOST_SHELL_GUIDE.md` | The GUI's host shell |
| `site-docs/reference/glossary.md` | The terms used here |
