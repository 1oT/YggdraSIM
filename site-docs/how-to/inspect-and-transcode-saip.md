---
title: Inspect and Transcode SAIP
tags:
  - how-to
  - saip
  - profile-package
---

# Inspect and Transcode SAIP

## Goal

Take an existing profile package, validate it, transcode it between JSON and
DER, optionally edit it in the TUI, and leave behind canonical sidecars that
downstream flows can consume.

## Prerequisites

- the profile file (DER, UPP, or hex-encoded DER in `.txt` / `.hex`)
- `Tools/ProfilePackage` installed via the editable install
- optional external `saip-tool` binary for `RAW` passthrough operations

## Steps

1. Open the shell and select the input.

    ```text
    [ProfilePackage] > USE path/to/profile.der
    [ProfilePackage] > STATUS
    ```

2. Confirm it parses and lint it.

    ```text
    [ProfilePackage] > INFO
    [ProfilePackage] > TREE
    [ProfilePackage] > LINT --strict
    ```

3. Launch the transcode TUI.

    ```text
    [ProfilePackage] > TUI
    ```

    Edit the JSON side; the DER side re-encodes live. The lint overlay
    highlights issues as you type. Pane layout is persisted.

4. Write canonical sidecars.

    On exit the TUI (or explicit transcode commands) produces:

    - `*.transcode.json`
    - `*.transcode.der`
    - `*.transcode.txt`

    These land in the transcode output directory chosen via `TRANSCODE-DIR`.

5. Optional: split the package or extract applets.

    ```text
    [ProfilePackage] > SPLIT
    [ProfilePackage] > EXTRACT-APPS --cap
    ```

## One-shot form

```bash
python -m Tools.ProfilePackage --cmd "USE profile.der; LINT --strict; ENCODE-JSON --out profile.transcode.der; EXIT"
```

## Validation

- `LINT --strict` exits clean
- the produced `*.transcode.der` is the same size class as the source and
  round-trips through `DUMP` without mismatch
- downstream `LOAD-PROFILE` accepts the transcoded DER

## Common failures

| Symptom | Likely cause |
| --- | --- |
| `hex parse failed` | the input `.txt` / `.hex` has whitespace, commas, or `0x` prefixes. Strip them. |
| Lint errors on PE ordering | the profile has out-of-order PEs. Reorder in the TUI. |
| Metadata lint complains about missing fields | the profile lacks required metadata tags. Populate them in the JSON side. |
| `RAW` not found | the external `saip-tool` binary is missing. Use `TOOL <path>`. |

## Related pages

- [Profile Package](../subsystems/profile-package.md)
- [SAIP Profiles](../concepts/saip-profiles.md)
- [Download a Profile (Local Access)](download-a-profile-local.md)
