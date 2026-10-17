---
title: CLI And Piping Cheatsheet
tags:
  - reference
  - cli
  - automation
  - cicd
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# CLI And Piping Cheatsheet

Non-interactive invocation patterns for CI/CD, automation runners, and
scripted local operation. Use this alongside the full
[Command Suite](command-suite.md) and the [CLI Matrix](cli-matrix.md).

## Assumptions

Every `python -m ...` example assumes one of the following:

- you are running the command from the repository root, or
- you already ran `python -m pip install -e /path/to/YggdraSIM` in the same
  Python environment.

After an editable install you can also use the installed console scripts:

- `yggdrasim-scp03`
- `yggdrasim-scp80`
- `yggdrasim-scp11-live`
- `yggdrasim-scp11-relay`
- `yggdrasim-scp11-local-access`
- `yggdrasim-scp11-eim-local`
- `yggdrasim-profile-package`
- `yggdrasim-profile-autoload`
- `yggdrasim-apdu-fuzzer`
- `yggdrasim-eum-diag`
- `yggdrasim-suci-tool`
- `yggdrasim-hil-bridge`
- `yggdrasim-hil-supervisor`

## Flow at a glance

```mermaid
flowchart LR
    CI["CI job / script"] -->|"--cmd 'A; B; EXIT'"| Shell["python -m MODULE"]
    CI -->|"--stdin <<EOF"| Shell
    Shell -->|stdout + artifacts| Reports["reports/*.yaml\nreports/*.log"]
    Shell -. optional .-> Out["--out report.yaml\n(SCP03 only)"]
```

## Scope

| Module | Interactive shell | `--cmd` | `--stdin` | Notes |
| --- | --- | --- | --- | --- |
| `python -m SCP03` | Yes | Yes | Yes | Supports `--out` YAML export with `--cmd` or `--stdin`. |
| `python -m SCP80` | Yes | Yes | Yes | Uses the same OTA shell commands as the interactive prompt. |
| `python -m SCP11.relay` | Yes | Yes | Yes | Compatibility alias of the `SCP11.live` shell. |
| `python -m SCP11.live` | Yes | Yes | Yes | eSIM management relay shell. |
| `python -m SCP11.local_access` | Yes | Yes | Yes | Local SMDPP shell against ISD-R. |
| `python -m SCP11.eim_local` | Yes | Yes | Yes | Local eIM shell and localized flows. |
| `python -m Tools.ProfilePackage` | Yes | Yes | Yes | SAIP / profile package shell. |
| `python -m Tools.SuciTool` | Yes | Yes | Yes | SUCI key tool shell. |
| `yggdrasim-hil-bridge` | Daemon | n/a | n/a | Runs a TCP bridge; use supervisor for long-lived setups. |
| `yggdrasim-hil-supervisor` | Daemon | n/a | n/a | Long-running orchestrator for the HIL bridge. |

## Wrapper simulator flags

`python main/main.py` is not itself a `--cmd` shell, but it accepts
launch-time simulator override flags that affect every card-facing module
launched through the wrapper menu.

Useful wrapper flags:

- `--card-backend sim`
- `--sim-isdr-config /path/to/isdr_config.json`
- `--sim-quirks /path/to/sim_quirks.py`
- `--sim-eim-identity /path/to/card_side_eim_identity.json`
- `--sim-euicc-store /path/to/euicc_root`
- `--sim-profile-store /path/to/profile_store`
- `--sim-import-profile /path/to/profile.der`
- `--sim-import-enable`
- `--debug`

Example:

```bash
python main/main.py --card-backend sim \
    --sim-eim-identity /path/to/card_side_eim_identity.json
```

Practical note:

- `--sim-eim-identity` controls the simulated card's default BF55 eIM identity.
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM **shell**
  identity file and is configured separately.

## Batch conventions

- `--cmd` expects a semicolon-separated command list.
- `--stdin` expects newline-separated commands from standard input.
- Blank stdin lines are ignored.
- Stdin lines that start with `#` are ignored as comments.
- Use `EXIT` to terminate the current shell cleanly in batch mode.
- Avoid `QA` in CI/CD unless the calling wrapper explicitly expects a
  full-suite quit (it exits YggdraSIM entirely).
- Commands run in the same order as provided.

Practical shortcut:

- if the task is profile lifecycle work rather than generic shell
  automation, start from the how-to pair
  [Download a profile via Live](../how-to/download-a-profile-live.md) and
  [Enable / Disable / Delete a profile](../how-to/enable-disable-delete-profile.md).

## Semicolon mode

Use `--cmd` when the command list is naturally constructed as one string:

```bash
python -m SCP03 --cmd "SCP03-SD; LIST; GET-IOT"
```

```bash
python -m SCP11.local_access --cmd "DISCOVER; STATUS; EXIT"
```

```bash
python -m SCP11.eim_local --cmd "DISCOVER; HOTFOLDER-LIST --json; EXIT"
```

```bash
python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; INFO; EXIT"
```

## Stdin mode

Use `--stdin` when the command sequence is easier to store as a file or
here-doc:

```bash
python -m SCP11.live --stdin <<'EOF'
DISCOVER
STATUS
EXIT
EOF
```

```bash
cat ci/scp11_local_access.txt | python -m SCP11.local_access --stdin
```

```bash
python -m Tools.SuciTool --stdin <<'EOF'
USE keys/demo_suci.key
DUMP
EXIT
EOF
```

## Capture commands to a file

Every shell command line takes `--log <file>`. The command runs as it
would with `--debug` -- the raw APDU trace and the debug narration
included -- and everything it prints is appended to `<file>` as well as
shown on the terminal. The terminal therefore shows the debug output
too; the file carries the same text without colour codes.

```text
[eSIM Management] > DOWNLOAD --log logs/download.log
[Local eIM] > IPAD-DISCOVER --log "logs/ipad discover.log"
[APDU] > SELECT 3F00 --log=logs/select.log
```

- The flag can sit anywhere on the line and comes off before the command
  reads its arguments; `--log=<file>` and a quoted path both work.
- A relative path is taken from the working directory, and `~` and
  environment variables are expanded. A directory (an existing one, or a
  path ending in `/`) gets a file named after the command and the local
  time, such as `logs/poll-20261014-102233.log`.
- The file is opened for append, and a new one is readable by its owner
  only: the debug trace carries key material in full. Each run opens with a
  `===` header naming the shell and the command, and closes with a trailer
  that says how it ended (`ended`, `interrupted (Ctrl+C)`, ...) and how
  long it took. A traceback goes to the file only.
- The body is laid out to fold by indentation, so an editor that folds
  that way collapses a run, a block or a row. A line printed at the left
  margin opens a block and starts with the local time it was printed, to
  the millisecond; an indented line -- the decoded rows under an APDU, the
  full hex under a row, the fields under a TLS handshake -- continues the
  block above it without a time of its own, in the columns the terminal
  showed it in. The whole run sits one level under its `===` header:

```text
=== 2026-10-14 10:22:33 +0200  eSIM Management > poll --debug ===
  10:22:41.886  Card:      SEND DATA #1                             90 00
                           81 03 01 43 01  Command details     SEND DATA #1, 01: send immediately
                           82 02 81 21     Device identities   UICC -> channel 1
                           36 76 16 03..03 Channel data        118 bytes
                                           16 03 03 00 71 01 00 00 6D 03 03 ...
  10:22:41.887  Network:   sent 118 bytes to 192.0.2.4:443
                           TLS Handshake: ClientHello sni=eim.example.test (109 byte(s))
=== 2026-10-14 10:27:05 +0200  ended after 272.4 s ===
```

- Batch mode takes the flag too:

```bash
python -m SCP11.live --cmd "SCAN --log reports/scan.log; EXIT"
```

- The GUI refuses the flag: its action panels already hold the output, and
  a path typed into a web form would be written on the server host.

### SCP03 `TRACE`

The SCP03 shell can keep one log open across commands:

```text
[APDU] > TRACE START logs/session.log
[TRACE APDU] > SELECT 3F00
[TRACE APDU] > 00B0000010
[TRACE APDU] > TRACE STOP
```

From `TRACE START` to `TRACE STOP` (or `TRACE END`) every command runs
with debug output and is copied into the file, its output one level
under a `> command` line; a `RUN` script notes each of its lines one
level deeper again. `TRACE
STATUS`, or `TRACE` alone, reports the file and its line count. `TRACE
START` without a file writes `reports/command_logs/scp03-trace-<time>.log`
under the runtime root. `EXIT`, `QA` and the end of a `--cmd` batch close
an open trace. `--log` on one command still works during a trace; that
command then goes to both files. Debug output stays on until `TRACE STOP`:
a `DEBUG` typed during a trace flips the switch for that one command only.

A command log is a transcript: `--json` / `--yaml` output lands in it like
any other text, its first line stamped and the rest indented under it, so
the file does not parse as JSON or YAML. For a structured report use the shells'
own outputs (`--out` in SCP03, `RECORD START` / `RECORD STOP` in the SCP11
Local SMDPP and Local eIM shells).

## Profile lifecycle fast paths

Relay snapshot:

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
```

Relay `LPAd` download:

```bash
python -m SCP11.live --cmd "DOWNLOAD-PROFILE LPA:1\$SMDP.EXAMPLE\$TOKEN; STATUS; EXIT"
```

Local direct load:

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json
LOAD-PROFILE
EXIT
EOF
```

Local eIM queue run:

```bash
python -m SCP11.eim_local --cmd \
  "HOTFOLDER-LIST --json; HOTFOLDER-FETCH --json; RESP-LOG 5 --json; EXIT"
```


```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
```

## Module examples

### SCP03

Command batch:

```bash
python -m SCP03 --cmd "SCP03-SD; LIST; GET-IOT"
```

Command batch with YAML export (unique to SCP03):

```bash
python -m SCP03 --cmd "SCP03-SD; LIST" --out reports/scp03_list.yaml
```

Piped commands with structured output:

```bash
python -m SCP03 --stdin --out reports/scp03_batch.yaml <<'EOF'
SCP03-SD
LIST
GET-IOT
EOF
```

### SCP80

Use the OTA shell without entering the interactive prompt:

```bash
python -m SCP80 --cmd "show; build; quit"
```

```bash
python -m SCP80 --stdin <<'EOF'
iccid 8988001234567890123
build
quit
EOF
```

### SCP11 relay shells

Relay default:

```bash
python -m SCP11.relay --cmd "DISCOVER; STATUS; EXIT"
```

Live certificate defaults:

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; EXIT"
```

Stdin batch:

```bash
python -m SCP11.live --stdin <<'EOF'
DISCOVER
LIST
STATUS
EXIT
EOF
```

One-shot relay flow remains available:

```bash
python -m SCP11.live --flow
```

### SCP11 Local SMDPP

```bash
python -m SCP11.local_access --cmd "DISCOVER; CERTS --json; EXIT"
```

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE test_profile.txt
METADATA default_profile_metadata.json
LOAD-PROFILE
EXIT
EOF
```

### SCP11 Local eIM

```bash
python -m SCP11.eim_local --cmd "DISCOVER; PATHS; STATUS; EXIT"
```

```bash
python -m SCP11.eim_local --stdin <<'EOF'
HOTFOLDER-LIST --json
HOTFOLDER-FETCH --json
RESP-LOG 5 --json
EXIT
EOF
```

### SAIP Tool

```bash
python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; INFO; TREE; EXIT"
```

```bash
python -m Tools.ProfilePackage --stdin <<'EOF'
USE reference_test_profile.txt
LINT
EXIT
EOF
```

Interactive note:

- `INSPECT` / `TUI` / `TRANSCODE-TUI` remain interactive (split-pane Textual
  UI), but the same profile selection and path resolution rules apply
  before entering the UI.
- The transcode workspace writes `*.transcode.json`, `*.transcode.der`, and
  `*.transcode.txt` sidecars for saved edits.

### SUCI Tool

```bash
python -m Tools.SuciTool --cmd "USE keys/demo_suci.key; DUMP; EXIT"
```

```bash
python -m Tools.SuciTool --stdin <<'EOF'
USE keys/demo_suci.key
GENERATE SECP256R1
DUMP
EXIT
EOF
```

### HIL Bridge daemons

Both `yggdrasim-hil-bridge` and `yggdrasim-hil-supervisor` are
`argparse`-only daemons -- no `--cmd` / `--stdin`. Drive them through
systemd or the launcher's `[B]` Local SIMtrace2 HIL Bridge Session menu instead:

```bash
yggdrasim-hil-bridge \
    --host 127.0.0.1 --port 9997 \
    --reader-name "SIMtrace 2" \
    --gsmtap-capture-path /tmp/ygg-gsmtap.pcap
```

```bash
yggdrasim-hil-supervisor \
    --usb-match SIMtrace2 \
    --state-file /var/lib/yggdrasim/hil_bridge_supervisor.json
```

See [HIL Bridge subsystem](../subsystems/hil-bridge.md) for systemd unit
templates and the interactive `[B]` flow.

### HIL Bridge offline pcap replay

The wrapper exposes direct flags so CI or ad-hoc operators can re-open
a saved capture in the decoded-APDU TUI without bringing the bridge
stack up:

```bash
python main/main.py --open-pcap captures/session-example.pcapng
python main/main.py \
    --open-pcap captures/session-example.pcapng \
    --keybag    captures/session-2026-04-20.keys.json
```

Sidecar keybag files named `<pcap>.keys.json` or `<stem>.keys.json`
next to the capture are auto-discovered when `--keybag` is omitted.

See [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md)
for the full flow.

### Session keybag export

Keybag JSONs feed the HIL offline decoder. They can be produced by
the same shells that built the secure channel:

```bash
python -m SCP03 --cmd \
    "SCP03-SD; EXPORT-KEYBAG captures/session-2026-04-20.keys.json case-1234; EXIT"
```

```bash
python -m SCP11.local_access --cmd "LOAD-PROFILE" \
    --dump-keybag captures/session-2026-04-20.keys.json
```

```bash
python -m SCP11.local_access --stdin --dump-keybag captures/session.keys.json <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json
LOAD-PROFILE
EXIT
EOF
```

`python -m SCP11.live --dump-keybag ...` is an intentional **no-op
stub** -- live-mode SCP11c BSP keys are derived inside the eUICC and
never reach the host. Use `SCP11.local_access` or SCP03 for real
exports.

## Interactive recording

The local SCP11 shells can capture a replayable command transcript plus
the underlying APDU trace. YAML is the default artifact format; use a
`.json` suffix when you want machine-oriented JSON instead.

```bash
python -m SCP11.local_access
RECORD START reports/local_smdpp_session.yaml
DISCOVER
LOAD-PROFILE
RECORD STOP
```

```bash
python -m SCP11.eim_local
RECORD START reports/eim_local_session.yaml
DISCOVER
ADD-EIM package
RECORD STOP
```

## Output handling

- Redirect stdout when the command output is the artifact:

```bash
python -m SCP11.live --cmd "DISCOVER; EXIT" > reports/scp11_discover.txt
```

- Capture stdout and keep it visible with `tee`:

```bash
python -m SCP11.local_access --cmd "DISCOVER; EXIT" | tee reports/local_smdpp_discover.log
```

- For SCP03 structured exports, prefer the native `--out` option.

## CI/CD recommendations

- Use direct module entry points in pipelines instead of the top-level
  menu wrapper.
- Keep command files in source control and feed them through `--stdin`
  for repeatable jobs.
- Split hardware-backed jobs from offline jobs.
- Use `EXIT` as the last batch command so the shell terminates
  deterministically.
- Store generated reports outside the source tree or under dedicated
  report folders.

## Minimal pipeline pattern

```bash
set -euo pipefail

python -m SCP03 --stdin --out reports/scp03.yaml <<'EOF'
SCP03-SD
LIST
GET-IOT
EOF

python -m Tools.ProfilePackage --cmd "USE reference_test_profile.txt; LINT; EXIT"
python -m Tools.SuciTool --cmd "USE keys/demo_suci.key; DUMP; EXIT"
```

## Notes

- Hardware-backed commands still require the correct reader, card,
  certificates, and runtime files.
- `--stdin` only strips blank lines and full-line `#` comments. Inline
  comments are not removed.
- Existing interactive flows remain unchanged. The automation paths call
  the same shell handlers used by the prompts, so any new command added to
  a shell is immediately available via `--cmd` / `--stdin`.
