<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Runbook

Short procedures for using YggdraSIM from the command line and from the GUI,
and for maintaining the repository. Each procedure names the guide that holds
the detail; this file does not repeat it.

- Part 1 is for operators: how to start each surface and how one task is done
  on the CLI and in the GUI.
- Part 2 is for maintainers: environment, tests, lint, the frontend build, the
  docs site, releases and pushes.
- Part 3 covers work on a real card and work on the simulator.

Placeholders are written `<like this>`. Examples use the reserved test values
of this project (`8988...` ICCIDs, `eim.example.test`).

## Part 1 - Using the tool

### 1.1 Start

| Goal | Command |
| --- | --- |
| Check the environment | `yggdrasim --doctor` (read-only; exit code 1 on a warning or failure) |
| Launcher menu | `yggdrasim` or `python main/main.py` |
| Desktop GUI | `yggdrasim-gui` or `python main/main.py --gui` (extra `[gui]`) |
| Desktop GUI without a console window | `yggdrasim-desktop` |
| GUI for a browser | `yggdrasim-web-server --host 127.0.0.1 --port <port> --token-file <file>` (extra `[gui-server]`) |
| One shell directly | `yggdrasim-scp03`, `yggdrasim-scp80`, `yggdrasim-scp11-live`, `yggdrasim-scp11-local-access`, `yggdrasim-scp11-eim-local`, `yggdrasim-profile-package`, `yggdrasim-suci-tool` |
| Simulated card instead of a reader | launcher menu `[C]`, `[2]` and `[D]` (saved); `--card-backend sim --sim-quirks none` on the launcher, `yggdrasim-gui` or `yggdrasim-web-server` (that run); `YGGDRASIM_CARD_BACKEND=sim YGGDRASIM_SIM_QUIRKS=none` (one process) |

Notes:

- The desktop GUI binds `127.0.0.1:27853` and makes its own bearer token. The
  web server binds `0.0.0.0:27854` unless `--host` says otherwise and refuses
  to start without `--token-file`. Keep it on the loopback and reach it
  through an SSH tunnel; `site-docs/subsystems/gui-command-center.md` has the
  token recipe and the posture.
- `--card-backend` on the launcher or a GUI command lasts for that run and
  is not saved; the saved selection changes in menu `[C]`. The quirks file
  as first seeded defines nothing and loads without asking; an edited one
  needs `YGGDRASIM_ALLOW_QUIRKS=1` or `--sim-quirks none`
  (`USER_MANUAL.md` section 2.3).
- `--debug` on the launcher or a GUI command turns debug output on for
  every module started from it.
- A `--cmd` or `--stdin` batch ends with exit code 1 when a command in it
  failed (`USER_MANUAL_CLI.md` section 2.5 says how each shell decides).
- Install paths: `INSTALL_CLEAN.md`, `INSTALL_FULL.md`,
  `INSTALL_FROM_SOURCE.md`, `INSTALL_RASPBERRYPI.md`.

### 1.2 How the CLI works

Every shell runs in three ways:

```bash
yggdrasim-scp11-live                                   # interactive prompt
yggdrasim-scp11-live --cmd "DISCOVER; STATUS; EXIT"    # one line, semicolons
yggdrasim-scp11-live --stdin < commands.txt            # one command per row
```

- End a batch with `EXIT`. `QA` quits the whole suite and is for interactive
  use.
- `HELP` in a shell lists its verbs. The verb lists are also in
  `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`.
- `--log <file>` on any command line writes that command's output, with debug
  detail, to the file as well as the terminal. The SCP03 shell also has
  `TRACE START [file]` and `TRACE STOP` for a run of commands.
- `CLI_AND_PIPING_GUIDE.md` covers batch conventions, output handling and
  pipelines.

### 1.3 How the GUI works

- The sidebar lists the modules in groups: Card Administration (File system,
  Applications, Over-the-Air), eSIM (SCP11) (Management, Local SM-DP+, Local
  eIM), Tools (SAIP Tool, Offline Tools), APDU Streaming (Remote Lab, Remote
  Bridge) and Advanced (HIL Bridge, SIM card helpers, YggdraCore, Shell, and
  Host shell when `YGGDRASIM_GUI_HOST_SHELL=1`), with Overview, Registry browser,
  Configuration and About beside them. The Management leaf is the eSIM
  Management module; the tables below use that name.
- The reader pills in the top bar bind the reader the modules work on. A pill
  binds and nothing more: it starts no scan.
- A module shows its actions as forms, grouped in tabs. The answer of an
  action renders under the form; a running stream keeps its form and a Cancel
  button until it ends.
- The live APDU dock at the bottom shows every exchange of the process.
- Shell runs a CLI shell inside the GUI, so a verb with no form is still
  reachable from the page.
- Configuration lists every `YGGDRASIM_*` flag and the loaded plugins.
  `site-docs/reference/env-flags.md` is the same list as a page.
- About opens the guides that ship with the build.

### 1.4 Task table

One row per task. Where a surface has no path for a task, the cell says so.

**Card and file system**

| Task | CLI | GUI |
| --- | --- | --- |
| See the readers | `yggdrasim --doctor` | reader pills in the top bar |
| Browse and read files | `yggdrasim-scp03 --cmd "LIST; SELECT <path>; READ; EXIT"` | File system |
| Open a GlobalPlatform secure channel, list applications and packages | `yggdrasim-scp03 --cmd "SCP03-SD; APPS; PKGS; EXIT"` | Applications |
| Send a script of APDUs | `yggdrasim-scp03 --cmd "RUN <script>; EXIT"` | File system or Applications, APDU tab |
| Build and send an OTA packet | `yggdrasim-scp80 --cmd "BUILD <hex>; EXIT"`, `SEND <hex>`, `OTA <hex>` | Over-the-Air: Build OTA plan (dry-run), Send OTA packet, OTA smart |

**Profiles on an eUICC**

| Task | CLI | GUI |
| --- | --- | --- |
| Read EID, profiles, notifications | `yggdrasim-scp11-live --cmd "DISCOVER; STATUS; LIST; GET-NOTIFICATIONS; EXIT"` | eSIM Management (the card overview is read when the module is entered): Get EID, List profiles (ES10c), List pending notifications |
| Download with an activation code | `yggdrasim-scp11-live --cmd "DOWNLOAD-PROFILE <activation code>; EXIT"` | eSIM Management: Download profile (activation code) |
| Enable, disable, delete | `ENABLE-PROFILE <iccid>`, `DISABLE-PROFILE <iccid>`, `DELETE-PROFILE <iccid>` in `yggdrasim-scp11-live` | eSIM Management: Enable profile, Disable profile, Delete profile |
| Load a profile package from disk | `yggdrasim-scp11-local-access --cmd "LOAD-PROFILE <file>; STATUS; EXIT"` | Local SM-DP+: Load profile (one-shot chain), or drop the file on the panel |
| Store or update metadata | `STORE-METADATA <file>`, `UPDATE-METADATA <file>` in `yggdrasim-scp11-local-access` | Local SM-DP+: Store metadata, Update metadata |

**Local eIM (SGP.32)**

| Task | CLI (`yggdrasim-scp11-eim-local`) | GUI (Local eIM) |
| --- | --- | --- |
| State of the eIM and its service | `IDENTITY`, `STATUS`, `SERVE status` | eIM configuration tab |
| A card's record and queue | `EUICC <eid>`, `OPS pending` | eUICCs tab, then the eUICC |
| Queue an operation | `QUEUE ENABLE <eid> <iccid>` (`--plan` first) | New operation on the eUICC, or Queue operation |
| Run the queue on the card in the reader | `DELIVER` | Deliver to card |
| Send a package to a listening IPA | `INJECT <eid> target=http://127.0.0.1:<port>`; the IPA side is `EIM-LISTEN` in `yggdrasim-scp11-live` | Inject to IPA; the IPA side is eSIM Management, Listen for injected eIM packages |
| Read a result | `OP <id>` | the operation view |
| Notifications the eIM took | `NOTIFICATIONS`, `NOTIFICATIONS SEND` | Notifications section of the eUICC |
| TLS setups and leaves | `TLS-SETUP ...` | eIM configuration tab, Leaf editor |

`SCP11/eim_local/GUIDE.md` is the operator guide for this module: association
in section 6.2, the queue in 6.3 and 6.4, injection in 6.4.5, Notifications in
6.5.1.

**Profile packages and offline tools**

| Task | CLI | GUI |
| --- | --- | --- |
| Inspect and lint a profile package | `yggdrasim-profile-package --cmd "USE <file>; INFO; LINT; EXIT"` | SAIP Tool; `yggdrasim-gui <file>` opens the file there |
| Edit a package | `TUI` in `yggdrasim-profile-package` | SAIP Tool |
| Build from a template | `GENERATE-PROFILE <template.json> <out.der> [NAME=value ...]` | SAIP Tool; `TEMPLATE_AND_TOKENS.md` describes both |
| Decode hex, an APDU exchange or a script | `yggdrasim-asn1 --context <hex>`, `yggdrasim-asn1 --file <file>`, `python main/main.py --asn1 <hex>` | Offline Tools: Decoder |
| Decode or build a TERMINAL PROFILE | `python -m yggdrasim_common.terminal_profile` | Offline Tools: TERMINAL PROFILE |
| Build an AddInitialEim | `ADD-INITIAL-EIM` in `yggdrasim-scp11-live` (a wizard, one step per member; it sends to the card) | Offline Tools: AddInitialEim builds; eSIM Management: AddInitialEim send |
| SUCI keys | `yggdrasim-suci-tool` | Offline Tools: SUCI keys |
| Compare two session recordings | `yggdrasim-session-diff` | no form |

**Hardware in the loop and remote readers**

| Task | CLI | GUI |
| --- | --- | --- |
| Bridge a card to a modem | `yggdrasim-hil-supervisor`, `yggdrasim-hil-bridge --reader-name "<reader name>"` | HIL Bridge: Launch supervisor, Start HIL session |
| Review a saved capture | `python main/main.py --open-pcap <file> [--keybag <file>]` | HIL Bridge: Decode snapshot (takes a capture path) |
| Publish a reader to another host | `python main/main.py --card-bridge --card-bridge-reader-name "<reader name>"` | Remote Bridge: Start local bridge, Probe bridge |
| Share rigs between operators | `yggdrasim-lab-agent` (publish), `yggdrasim-lab` (use) | Remote Lab |

Guides: `HIL_BRIDGE_GUIDE.md`, `SIMTRACE2_CARDEM_GUIDE.md`,
`CARD_BRIDGE_GUIDE.md`.

Not in the tables: the 5G core stub (GUI: Advanced, YggdraCore, with the
AKMA actions; CLI: `yggdrasim-yggdracore` serves it over HTTP), the MCP
server (`yggdrasim-mcp`), the APDU fuzzer,
the EUM diagnostics and the dissector. `site-docs/reference/cli-matrix.md`
lists every command with its documentation page, and
`site-docs/operator-surfaces.md` says which surface fits which task.

### 1.5 When something fails

1. Read the last line of the answer. A refusal names its cause; a status word
   can be pasted into the Decoder (`yggdrasim-asn1 --context --domain sw <sw>`).
2. "reader busy: ..." names the action and process that hold the reader. Wait
   for it or stop it; do not unplug the reader under it. Section 3.1 lists
   which surfaces take part in that lock.
3. Run the command again with `--log <file>` and read the file.
4. `site-docs/reference/troubleshooting.md` is sorted by subsystem;
   `SCP11/eim_local/GUIDE.md` section 13 covers the Local eIM.

## Part 2 - Maintaining the repository

### 2.1 Environment

```bash
python -m pip install -e '.[full,test]'    # see INSTALL_FROM_SOURCE.md for the extras
python -m pip install -r requirements-docs.txt
git config core.hooksPath .githooks        # once per clone: the push guard
```

Run tests with the interpreter of the environment the project is installed
in. An `osmocom` or `pySim` import error under pytest means the wrong
interpreter was used.

### 2.2 Tests

```bash
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_<area>.py
```

- Target one file, class or node. Keep a run under 90 seconds.
- No repo-wide run during iteration. A claim that the suite is clean needs one
  process over `tests/`, and a release claim also `--runslow`.
- A test that passes alone and fails in the suite, or the reverse, is an
  import-order defect. Bisect the file that ran before it.
- Detail: `site-docs/internals/testing-guide.md`.

### 2.3 Lint and hygiene

```bash
ruff check <path>
python scripts/check_repo_hygiene.py
```

The hygiene scan reads tracked files only, so a new file is seen after
`git add`. Rules: `site-docs/internals/coding-standards.md`.

### 2.4 GUI frontend

`gui_frontend/src/` is the source; `yggdrasim_common/gui_server/static/` is
build output and is never edited.

```bash
./scripts/build_gui_frontend.sh
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_gui_source_manifests.py
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_gui_design_system_consistency.py
```

A new label gets a row in `NAMING_CONVENTIONS.md`. Detail:
`gui_frontend/README.md`.

### 2.5 Documentation

```bash
python site-docs/_tools/mirror_source_docs.py
mkdocs build --strict
```

- `site-docs/sources/` is written by the mirror script and committed with the
  source it copies. It is never edited by hand.
- A new console script: `python site-docs/_tools/build_cli_matrix.py`.
- A new env flag: `python site-docs/_tools/build_env_flags.py`.
- `tests/test_docs_generated_pages.py` fails while a generated page is stale.

### 2.6 What a change needs before it is done

| The change touches | Run |
| --- | --- |
| any `.py` | `python -m py_compile <file>`, `ruff check <file>`, the narrowest test file |
| `gui_frontend/src/` | section 2.4 |
| a GUI action | the action sits in a tab of its module; `tests/test_gui_actions.py` |
| a guide or any mirrored Markdown | section 2.5 |
| `yggdrasim_common/env_flags.py` | the env-flag generator, `tests/test_env_flags_gui_route.py` |
| `pyproject.toml` console scripts | the CLI matrix generator |
| a plugin capability | a GUI action and a CLI verb, both run once; `site-docs/internals/plugin-contract.md` |
| a dependency defect | an `upstream_patches/<name>/` folder and the fix in this tree |

### 2.7 Release

`site-docs/internals/release-checklist.md` is the procedure: pre-flight,
source boundary, sdist and wheel verification, docs build, tag message
contract. Install the built wheel into a fresh virtual environment outside
the repository and start each console script before calling a release ready.
`BUILD_AND_PACKAGING.md` covers Docker, PyInstaller and `.deb`.

### 2.8 Commits and pushes

Read `REMOTES_AND_PUBLICATION.md` before a push or a remote change. Commit
metadata names the human author only. External contributions follow
`CONTRIBUTING.md`.

## Part 3 - Real cards and the simulator

### 3.1 Before a command reaches a real card

1. Know which reader the command will use: name it (`--reader "<reader name>"`
   on `yggdrasim-scp11-live`, `--reader-name` on the HIL and Card Bridge
   commands) or bind its pill, and do not rely on reader order.
2. Check that nothing else holds the reader. The reader lock is taken by GUI
   card actions, the eSIM Management console, the card verbs of the eIM-local
   shell, the HIL bridge and the MCP card tools, and a holder among them is
   named in the "reader busy" refusal. The SCP03, SCP80 and local-access
   shells, the Card Bridge and programs that are not YggdraSIM do not take
   it, so they are neither refused nor seen.
3. Read first, write second: EID, profile list and pending notifications
   before any state change (`DISCOVER; STATUS; LIST; GET-NOTIFICATIONS` in
   `yggdrasim-scp11-live`).
4. Decide what happens to pending Notifications before a profile state
   change. A session that syncs notifications posts them to the SM-DP+ each
   one names and removes them from the card. `EIM-LISTEN notifications=keep`
   leaves them on the eUICC. `DELIVER` hands them to the Local eIM, which
   acknowledges them, so the eUICC drops them, and sends each to the SM-DP+
   it names; it holds none back. So does an `IPA-DATA` that asks for tag
   `A0`. A card keeps its Notifications only while nothing takes them from
   it (`SCP11/eim_local/GUIDE.md` section 6.5.1).
5. For the Local eIM, check that the queue holds what is meant to run
   (`OPS pending`): `DELIVER` and `INJECT` serve whatever is queued.
6. After each step, read the stored result (`OP <id>`) before the next one.
   An error result is still an answer; the absence of a failure line does not
   make it a success.
7. Never run `ASSOCIATE` on a card that is not meant to be bound to this
   Local eIM. It writes eIM configuration to the eUICC.

### 3.2 A simulator run that cannot touch a reader

Set the backend and give the run its own stores, so that it reads and writes
nothing of the operator's:

```bash
export YGGDRASIM_CARD_BACKEND=sim
export YGGDRASIM_SIM_QUIRKS=none
export YGGDRASIM_SIM_EUICC_STORE=<scratch>/euicc
export YGGDRASIM_SIM_PROFILE_STORE=<scratch>/profiles
export YGGDRASIM_LOCAL_EIM_STORE=<scratch>/local_eim
export YGGDRASIM_EIM_BUILDER_STORE=<scratch>/eim_builder
export PCSCLITE_CSOCK_NAME=/nonexistent/pcscd.comm   # Linux: no PC/SC for this process
```

The last line is the hard stop for local readers: with the PC/SC socket out
of reach, the process cannot open a local PC/SC reader, whatever backend it
believes it is on. It does not cover a remote card (Card Bridge, Remote
Lab), so give such a run no remote-card URL. `site-docs/subsystems/simcard-simulator.md` describes the
simulator.

## Related documents

- `USER_MANUAL.md`, `USER_MANUAL_GUI.md`, `USER_MANUAL_CLI.md` - the user
  manual: every module in depth, on the GUI and on the CLI
- `README.md` in this directory - index of the guides
- `CLI_AND_PIPING_GUIDE.md`, `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
- `CONFIGURATION_AND_CERTIFICATES.md`
- `site-docs/how-to/` - one page per procedure
- `site-docs/reference/command-suite.md`, `site-docs/reference/cli-matrix.md`
