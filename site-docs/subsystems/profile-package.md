---
title: Profile Package
tags:
  - subsystems
  - saip
  - profile-package
---

# Profile Package

`Tools/ProfilePackage/` is the SAIP profile-package workbench. Use it when
the task is package inspection, linting, JSON to DER transcode, or shell-driven
package manipulation before or after card-side workflows. It does not touch a
card directly; its output is what the card-facing shells consume.

!!! info "Underlying concept"
    Read [SAIP Profiles](../concepts/saip-profiles.md) first if terms like PE,
    UPP, BPP, or transcode sidecar are not already in context.

## When to use it

- confirming package structure before a `LOAD-PROFILE`
- running the lint engine with strict mode, metadata, or gate presets
- moving a profile between JSON and DER for review or for downstream tooling
- extracting applets (`CAP`, `IJC`) out of a profile
- splitting a profile into its PE segments
- removing a specific NAA for test fixtures
- driving the external `saip-tool` through a consistent shell
- interactive review through the split-pane transcode TUI

## Entry points

=== "Module"

    ```bash
    python -m Tools.ProfilePackage
    python -m Tools.ProfilePackage --cmd "USE <path>; INFO; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-profile-package
    ```

=== "From the launcher"

    `python main/main.py` and pick the Profile Package entry.

## Command surface

### Selection and configuration

| Verb | Purpose |
| --- | --- |
| `USE <path>` | select a source UPP/DER profile |
| `STATUS` | show active selection and paths |
| `PROFILE-DIR` | show or set the default profile directory |
| `TRANSCODE-DIR` | show or set the transcode output directory |
| `TOOL` | override the external `saip-tool` command path |
| `PWD` | print working directory |

### Inspection and linting

| Verb | Purpose |
| --- | --- |
| `INFO` | high-level package information |
| `TREE` | PE-level tree view |
| `CHECK` | fast structural check |
| `LINT` | full lint with strict mode, metadata, and gate preset support |
| `DUMP` | structured dump in decoded or raw form |

### Transform and transcode

| Verb | Purpose |
| --- | --- |
| `ENCODE-JSON` | rebuild DER from tagged JSON |
| `SPLIT` | split a package into its PE segments |
| `EXTRACT-APPS` | extract applets as `CAP` or `IJC` |
| `REMOVE-NAA <USIM/ISIM/CSIM>` | remove a NAA from a profile |
| `RAW <subcommand>` | pass-through to the external backend tool |

### Transcode TUI

| Verb | Purpose |
| --- | --- |
| `TUI` | launch the split-pane transcode UI |

### Diff and simulator-pipeline

| Verb | Purpose |
| --- | --- |
| `DIFF <a> <b> [NO-VALUES]` | structural diff of two profile inputs (transcode JSON, simulator manifest, or DER) with ANSI colour |
| `DIFF-TUI <a> <b>` | side-by-side Textual diff UI |
| `WATCH-SIMCARD [STORE=...] [POLL=...] [MAX=...] [LAUNCHER="..."]` | start the polling watcher; launches a configurable command when SIMCARD writes a new ICCID to the profile store |

See [Diagnostics Toolbox](../how-to/diagnostics-toolbox.md) for the
full operator walk-through.

The TUI supports:

- live JSON editing with immediate DER re-encoding
- live decode view
- live lint overlay
- persistent pane-layout selection saved in workspace config
- OS clipboard copy and paste
- uncapped inspector and decode retention

## Runtime dependencies

- Python runtime only
- the optional on-disk `pysim/` tree for the PE codecs (clone
  `https://gitlab.com/osmocom/pysim.git` into the repo root when SAIP
  flows are needed; the gitignored directory is not shipped)
- optional external `saip-tool` binary for extended RAW operations
- the writable runtime root for `*.transcode.json`, `*.transcode.der`,
  `*.transcode.txt` sidecars

## State the shell writes

| Location | Contents |
| --- | --- |
| workspace config | persisted pane layout and default directories |
| transcode output dir | `*.transcode.json`, `*.transcode.der`, `*.transcode.txt` |

## Common recipes

### Quick lint

```bash
python -m Tools.ProfilePackage --cmd "USE profile.der; LINT --strict; EXIT"
```

### Transcode DER to JSON and back

```text
[ProfilePackage] > USE profile.der
[ProfilePackage] > TUI
```

Inside the TUI, edit the JSON side and let the DER side re-encode as you
type.

### Split and extract

```text
[ProfilePackage] > USE profile.der
[ProfilePackage] > SPLIT
[ProfilePackage] > EXTRACT-APPS --cap
```

### Pipeline a package through lint plus encode

```bash
python -m Tools.ProfilePackage --cmd "USE in.json; ENCODE-JSON --out out.der; LINT --strict --rule-gates; EXIT"
```

## Pitfalls

- Hex-encoded DER (`.txt` or `.hex`) is accepted, but the file must be pure
  hex without byte separators. The shell prints an explanatory error when
  something else is detected.
- Lint gate presets and explicit rule gates can conflict. The preset is
  applied first; rule gates then override.
- The external `saip-tool` binary is optional; missing it only affects the
  `RAW` verb, not the in-shell linter or transcode.

## Related pages

- [SAIP Profiles](../concepts/saip-profiles.md)
- [Inspect and Transcode SAIP](../how-to/inspect-and-transcode-saip.md)
- [SCP11 Local Access](scp11-local-access.md)
