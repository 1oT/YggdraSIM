---
title: SUCI Tool
tags:
  - subsystems
  - suci
  - 3gpp
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SUCI Tool

`Tools/SuciTool/` is the helper shell around the external `suci-keytool`
binary. Use it to manage SUCI key material that a profile expects on a USIM
when 5G privacy features are in play.

!!! info "Underlying concept"
    The SUCI/SUPI model is summarized in [3GPP NAA](../concepts/3gpp-naa.md).

## When to use it

- selecting an active SUCI key file
- generating a `SECP256R1` or `CURVE25519` SUCI key
- exporting uncompressed or compressed public-key form
- inspecting the workspace paths the tool resolves

## Entry points

=== "Module"

    ```bash
    python -m Tools.SuciTool
    python -m Tools.SuciTool --cmd "STATUS; PWD; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-suci-tool
    ```

=== "From the launcher"

    `python main/main.py` and pick the SUCI Tool entry.

## Command surface

| Verb | Purpose |
| --- | --- |
| `USE <path>` | select the active SUCI key file |
| `STATUS` | show active file and workspace paths |
| `TOOL` | override the external `suci-keytool` command path |
| `GENERATE <curve>` | generate a key pair (`SECP256R1` or `CURVE25519`) |
| `DUMP` | export the public key (uncompressed or compressed form) |
| `PWD` | print working directory |

## Runtime dependencies

- an available `suci-keytool` binary on the host
- the workspace or runtime-root directory where SUCI key files live

## State the shell writes

SUCI Tool is file-oriented. It does not write into the shared SQLite
inventory. Key files land in the selected directory, and the tool manages
selection through the `USE` verb.

## Common recipes

### Generate a `SECP256R1` key and export compressed form

```bash
python -m Tools.SuciTool --cmd "GENERATE SECP256R1; DUMP --compressed; EXIT"
```

### Switch active key

```text
[SUCI] > USE path/to/profile_suci.key
[SUCI] > STATUS
```

## Pitfalls

- `GENERATE` requires that the external `suci-keytool` binary is resolvable.
  Use `TOOL <path>` if the binary lives outside `PATH`.
- The SUCI public key that lands on a profile must match the home network
  public key that the 5G serving network expects. A generated dev key works
  for loopback testing only.

## Related pages

- [3GPP NAA](../concepts/3gpp-naa.md)
- [SAIP Profiles](../concepts/saip-profiles.md)
