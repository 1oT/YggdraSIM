# CLI And Piping Guide

This guide documents the non-interactive command surfaces intended for CI/CD,
automation runners, and scripted local operation.

## Scope

The following modules support direct command automation:

| Module | Interactive shell | `--cmd` | `--stdin` | Notes |
| --- | --- | --- | --- | --- |
| `python -m SCP03` | Yes | Yes | Yes | Supports `--out` YAML export with `--cmd` or `--stdin`. |
| `python -m SCP80` | Yes | Yes | Yes | Uses the same OTA shell commands as the interactive prompt. |
| `python -m SCP11.relay` | Yes | Yes | Yes | Relay shell using the default relay certificate set. |
| `python -m SCP11.live` | Yes | Yes | Yes | Relay shell using live certificate defaults. |
| `python -m SCP11.test` | Yes | Yes | Yes | Relay shell using test certificate defaults. |
| `python -m SCP11.local_access` | Yes | Yes | Yes | Local SMDPP shell against ISD-R. |
| `python -m SCP11.eim_local` | Yes | Yes | Yes | Local eIM shell and localized flows. |
| `python -m Tools.ProfilePackage` | Yes | Yes | Yes | SAIP/profile package shell. |
| `python -m Tools.SuciTool` | Yes | Yes | Yes | SUCI key tool shell. |

## Batch conventions

- `--cmd` expects a semicolon-separated command list.
- `--stdin` expects newline-separated commands from standard input.
- Blank stdin lines are ignored.
- Stdin lines that start with `#` are ignored as comments.
- Use `EXIT` to end the current shell cleanly in batch mode.
- Avoid `QA` in CI/CD unless the calling wrapper explicitly expects a full-suite quit.
- Commands run in the same order as provided.

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

### SCP80

Build or send through the OTA shell without entering the prompt:

```bash
python -m SCP80 --cmd "show; build; quit"
```

```bash
python -m SCP80 --stdin <<'EOF'
iccid 8946001234567890123
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

Test certificate defaults:

```bash
python -m SCP11.test --stdin <<'EOF'
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
POLL-CAMPAIGN --until-empty --max-cycles 20 --json
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

## Output handling

- Redirect stdout when the command output is the artifact:

```bash
python -m SCP11.test --cmd "DISCOVER; EXIT" > reports/scp11_test_discover.txt
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
