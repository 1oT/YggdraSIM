<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# CLI And Piping Guide

This guide documents the non-interactive command surfaces intended for CI/CD,
automation runners, and scripted local operation.

For task-oriented download, enable, disable, delete, and poll examples, also
use `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`.

All `python -m ...` examples in this guide assume one of these is true:

- you are running them from the repository root
- or you already ran `python -m pip install -e /path/to/YggdraSIM` in the same Python environment

After editable install, you can also use the installed commands directly, for
example `yggdrasim-scp03`, `yggdrasim-scp80`, `yggdrasim-scp11`,
`yggdrasim-scp11-live`, `yggdrasim-scp11-relay`,
`yggdrasim-scp11-local-access`, `yggdrasim-scp11-eim-local`,
`yggdrasim-hil-bridge`, `yggdrasim-hil-supervisor`,
`yggdrasim-profile-package`, `yggdrasim-profile-autoload`,
`yggdrasim-apdu-fuzzer`, `yggdrasim-eum-diag`, `yggdrasim-suci-tool`, and
`yggdrasim-asn1`.

## Scope

The following modules support direct command automation:

| Module | Interactive shell | `--cmd` | `--stdin` | Notes |
| --- | --- | --- | --- | --- |
| `python -m SCP03` | Yes | Yes | Yes | Supports `--out` YAML export with `--cmd` or `--stdin`. |
| `python -m SCP80` | Yes | Yes | Yes | Uses the same OTA shell commands as the interactive prompt. |
| `python -m SCP11.relay` | Yes | Yes | Yes | Relay shell using the default relay certificate set. |
| `python -m SCP11.live` | Yes | Yes | Yes | eSIM management relay shell. |
| `python -m SCP11.local_access` | Yes | Yes | Yes | Local SMDPP shell against ISD-R. |
| `python -m SCP11.eim_local` | Yes | Yes | Yes | Local eIM shell and localized flows. |
| `python -m Tools.ProfilePackage` | Yes | Yes | Yes | SAIP/profile package shell. Exposes `DIFF`, `DIFF-TUI`, and `WATCH-SIMCARD`. |
| `python -m Tools.ProfilePackage.simcard_watch` | No | No | No | Polling watcher: auto-opens the SAIP TUI when SIMCARD writes a new ICCID to the profile store. Ships as `yggdrasim-profile-autoload`. |
| `python -m Tools.ApduFuzz` | No | No | No | Opt-in APDU mutation fuzzer. Refuses to run without `--i-mean-it` and at least one `--allow-iccid` / `--allow-imsi`. Ships as `yggdrasim-apdu-fuzzer`. |
| `python -m Tools.EumDiag` | No | No | No | EUM diagnostics: `inject-keys` / `store-keys` / `decode-bpp` subcommands. Ships as `yggdrasim-eum-diag`. |
| `python -m Tools.SuciTool` | Yes | Yes | Yes | SUCI key tool shell. |
| `python -m Tools.Asn1TlvDecode` | No | No | Yes | BER/DER ASN.1, BER-TLV, and command APDU decoder. Ships as `yggdrasim-asn1`; also exposed through `python main/main.py --asn1`. |
| `python -m Tools.CardBridge` | No | No | No | Cross-platform PC/SC-to-HTTP APDU bridge for SSH-forwarded remote-card workflows. Ships as `yggdrasim-card-bridge` and is also exposed through `python main/main.py --card-bridge`. |
| `python -m Tools.HilBridge.main` | No | No | No | Local SIMtrace2 HIL bridge daemon (Linux only). Long-running RSPRO server. Ships as `yggdrasim-hil-bridge`. |
| `python -m Tools.HilBridge.supervisor` | No | No | No | Local SIMtrace2 HIL supervisor / health-check / restarter (Linux only). Ships as `yggdrasim-hil-supervisor`. |

## Wrapper simulator flags

`python main/main.py` is not a `--cmd` shell, but it does accept launch-time
simulator override flags that affect card-facing modules started through the
wrapper.

Useful wrapper flags:

- `--card-backend {reader,sim}`
- `--sim-isdr-config /path/to/isdr_config.json`
- `--sim-quirks /path/to/sim_quirks.py`
- `--sim-eim-identity /path/to/card_side_eim_identity.json`
- `--sim-euicc-store /path/to/euicc_root`
- `--sim-profile-store /path/to/profile_store`
- `--sim-import-profile /path/to/profile.der` (paired with `--sim-import-enable` to auto-enable on first boot)

Example:

```bash
python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json
```

Practical note:

- `--sim-eim-identity` controls the simulated card's default BF55 eIM identity
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM shell identity file and is configured separately

## Wrapper ASN.1/TLV Decode Flags

`python main/main.py --asn1` short-circuits into the ASN.1/TLV/APDU decoder
without launching the menu or touching the card backend.

```bash
python main/main.py --asn1 5C06BF51BF449F2A
echo 5C06BF51BF449F2A | python main/main.py --asn1
python main/main.py --asn1 --asn1-format json < sample.hex
python main/main.py --asn1-file sample.hex --asn1-format both
```

After editable install, the equivalent direct command is:

```bash
yggdrasim-asn1 5C06BF51BF449F2A
echo 5C06BF51BF449F2A | yggdrasim-asn1
```

## Wrapper HIL offline flags

Two extra wrapper flags short-circuit straight into the HIL decoded-APDU
TUI in offline review mode — no bridge, no supervisor, no `tshark -i`:

- `--open-pcap <path>` — open a saved `.pcap` / `.pcapng` in the TUI
- `--keybag <path>` — optional keybag JSON for SCP03 / SCP11c unwrap

Sidecar keybags named `<pcap>.keys.json` / `<stem>.keys.json` are
auto-discovered when `--keybag` is omitted. A full write-up lives in
`HIL_BRIDGE_GUIDE.md` §11 "Offline pcap replay and session-key unwrap".

## Wrapper GUI Command Center flags

`main/main.py` and the installed `yggdrasim` command can also
short-circuit into the optional Universal GUI Command Center instead of
the menu. Source installs additionally expose `yggdrasim-gui` and
`yggdrasim-web-server`. Both modes require the GUI extra to be installed
(`pip install -e '.[gui]'` for desktop; `'.[gui-server]'` for the
headless web server).

- `--gui` — desktop window via `pywebview`
- `--web-server` — headless FastAPI/uvicorn HTTP server with the SPA
- `--host <addr>` / `--port <num>` — override the loopback bind for `--web-server`
- `--token-file <path>` — bearer token expected on every request (`--web-server` only)
- `--tls-cert <path>` / `--tls-key <path>` — bring your own TLS material
- `--tls-self-signed` — generate or reuse a self-signed pair under `state/gui_tls/`

Examples:

```bash
yggdrasim-gui --card-backend sim
```

```bash
yggdrasim-web-server \
    --host 127.0.0.1 --port 18443 \
    --token-file ~/.config/yggdrasim/gui-token \
    --tls-self-signed
```

These flags are documented in detail in the `--help` output of
`main/main.py`.

## Wrapper diagnostics

The wrapper exposes two diagnostic surfaces that are safe to call from CI
without any side effects on state or transport:

- `python main/main.py --version` prints `YggdraSIM <version>` to stdout and
  exits `0`. The version string is sourced from `pyproject.toml` through
  `yggdrasim_common/__about__.py` so there is a single point of truth.
- `python main/main.py --doctor` runs a read-only preflight report across
  Python version, `cryptography`, `pycryptodomex`, `asn1tools`, the
  optional on-disk `pysim/` clone, SQLite, optional `textual` (TUI),
  PC/SC reader visibility, and `gpg`. Exit code is `0` when every probe
  is `ok`/`info`, `1` when any probe is `warn`/`fail`. The helper avoids
  opening any card transport and
  never writes SQLite rows, so it is safe to run at pipeline entry.

## Batch conventions

- `--cmd` expects a semicolon-separated command list.
- `--stdin` expects newline-separated commands from standard input.
- Blank stdin lines are ignored.
- Stdin lines that start with `#` are ignored as comments.
- Use `EXIT` to end the current shell cleanly in batch mode.
- Avoid `QA` in CI/CD unless the calling wrapper explicitly expects a full-suite quit.
- Commands run in the same order as provided.

Practical shortcut:

- if the task is profile lifecycle work rather than generic shell automation,
  start from `PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

## Semicolon mode

Use `--cmd` when the command list is naturally constructed in one shell string:

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

Use `--stdin` when the command sequence is easier to store as a file or here-doc:

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

## Profile lifecycle fast path

Relay snapshot:

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
```

Relay `LPAd` download:

```bash
python -m SCP11.live --cmd "DOWNLOAD-PROFILE LPA:1$SMDP.EXAMPLE$TOKEN; STATUS; EXIT"
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
python -m SCP11.eim_local --cmd "HOTFOLDER-LIST --json; HOTFOLDER-FETCH --json; RESP-LOG 5 --json; EXIT"
```

## Module examples

### SCP03

Command batch:

```bash
python -m SCP03 --cmd "SCP03-SD; LIST; GET-IOT"
```

Command batch with YAML export:

```bash
python -m SCP03 --cmd "SCP03-SD; LIST" --out reports/scp03_list.yaml
```

Piped commands:

```bash
python -m SCP03 --stdin --out reports/scp03_batch.yaml <<'EOF'
SCP03-SD
LIST
GET-IOT
EOF
```

Session-key export (for HIL offline pcap unwrap — see below):

```bash
python -m SCP03 --cmd \
    "SCP03-SD; EXPORT-KEYBAG reports/session-example.keys.json case-1234; EXIT"
```

### SCP80

Build or send through the OTA shell without entering the prompt:

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

### SCP11 eSIM management relay

Relay shell:

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

Session-key export (for HIL offline pcap unwrap — see below):

```bash
python -m SCP11.local_access --cmd "LOAD-PROFILE" \
    --dump-keybag reports/session-example.keys.json
```

```bash
python -m SCP11.local_access --stdin \
    --dump-keybag reports/session-example.keys.json <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json
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

- `TUI` remains interactive, but the same profile selection and path
  resolution rules apply before entering the UI
- the transcode workspace writes `*.transcode.json`, `*.transcode.der`, and
  `*.transcode.txt` sidecars for saved edits

#### Profile package AKA automation

`LIST-AKA` is fully non-interactive and makes a good preflight step before
downstream provisioning:

```bash
python -m Tools.ProfilePackage --cmd "USE reference.der; LIST-AKA; EXIT"
```

`PROVISION-AKA` switches to non-interactive mode the moment any
`NAME=VALUE` override is supplied. The command below writes a fresh DER
without touching the active input file:

```bash
python -m Tools.ProfilePackage --cmd \
  "USE reference.der; \
   PROVISION-AKA reports/milenage.der ALGORITHM=milenage KI=00112233445566778899AABBCCDDEEFF OPC=000102030405060708090A0B0C0D0E0F; \
   EXIT"
```

Use the `IN-PLACE` target when the pipeline is expected to mutate the
currently-selected DER:

```bash
python -m Tools.ProfilePackage --cmd \
  "USE reference.der; \
   PROVISION-AKA IN-PLACE ALGORITHM=tuak KI=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA OPC=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB NUMBER-OF-KECCAK=1; \
   EXIT"
```

`RANDOMIZE-AKA` is strictly for development profiles and uses
`secrets.token_bytes`. It leaves `authCounterMax` and `sqnInit` alone by
default so replay-protection stays predictable; opt in with
`INCLUDE-AUTH-COUNTER-MAX` / `INCLUDE-SQN-INIT` only when a fresh seed is
required:

```bash
python -m Tools.ProfilePackage --cmd \
  "USE reference.der; \
   RANDOMIZE-AKA reports/dev_profile.der ALGORITHM=tuak INCLUDE-AUTH-COUNTER-MAX; \
   EXIT"
```

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

## Interactive Recording

The local SCP11 shells can capture a replayable command transcript together with
the underlying APDU trace. YAML is the default artifact format; use a `.json`
suffix when you want machine-oriented JSON instead.

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

## HIL offline pcap replay and keybag export

The main wrapper accepts two extra flags purely for the HIL decoded-APDU
TUI's offline review mode. They short-circuit the menu and drop straight
into the TUI without starting the bridge, supervisor, or `tshark -i`:

```bash
python main/main.py --open-pcap captures/session-example.pcapng
python main/main.py \
    --open-pcap captures/session-example.pcapng \
    --keybag    captures/session-2026-04-20.keys.json
```

The same flow is reachable from the `[B]` Local SIMtrace2 HIL Bridge Session menu via
pick `[3] Open saved .pcap (offline review, no bridge)`.

If `--keybag` is omitted, sidecar JSONs named `<pcap>.keys.json` or
`<stem>.keys.json` next to the capture are auto-discovered. A missing
keybag is non-fatal — ciphered APDUs stay wrapped.

Keybag JSONs (`yggdrasim-hil-keybag/v1`) are produced by the same
shells that build the secure channel:

| Source shell | Non-interactive export |
| --- | --- |
| `python -m SCP03` | `--cmd "SCP03-SD; EXPORT-KEYBAG path.keys.json label; EXIT"` |
| `python -m SCP11.local_access` | `--dump-keybag path.keys.json` (standalone or combined with `--cmd` / `--stdin`) |
| `python -m SCP11.live` | **no-op stub** — live SCP11c BSP keys are derived inside the eUICC and never reach the host. The flag prints a clear message and exits with code `2`. |

See the HIL Bridge guide (`HIL_BRIDGE_GUIDE.md` §11 "Offline pcap
replay and session-key unwrap") for the keybag schema, replay engine
details, and the full operator flow.

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

- Use direct module entry points in pipelines instead of the top-level menu wrapper.
- Keep command files in source control and feed them through `--stdin` for repeatable jobs.
- Split hardware-backed jobs from offline jobs.
- Use `EXIT` as the last batch command so the shell terminates deterministically.
- Store generated reports outside the source tree or under dedicated report folders.

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

- Hardware-backed commands still require the correct reader, card, certificates, and runtime files.
- `--stdin` only strips blank lines and full-line `#` comments. Inline comments are not removed.
- Existing interactive flows remain unchanged. The automation paths call the same shell handlers used by the prompts.
