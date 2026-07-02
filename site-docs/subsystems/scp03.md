---
title: SCP03 Admin Shell
tags:
  - subsystems
  - scp03
  - globalplatform
  - filesystem
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SCP03 Admin Shell

`SCP03/` is the GlobalPlatform-style admin shell. It is the card-administration
and retrieval surface, not the SCP11 provisioning relay. Use it when the task
is secure-channel authentication, GP registry work, ETSI/3GPP filesystem
navigation, eUICC retrieval, PIN/auth diagnostics, or report/export.

!!! info "Underlying concepts"
    This shell builds on [GlobalPlatform](../concepts/globalplatform.md),
    [ETSI UICC](../concepts/etsi-uicc.md), and [3GPP NAA](../concepts/3gpp-naa.md).

## When to use it

- opening a GP secure channel to an ISD, SSD, or MNO-SD
- listing applications, packages, and security domains
- navigating the MF / DF / ADF / EF tree
- reading, updating, and reporting EF content
- running GSM, USIM, and ISIM `AUTHENTICATE` diagnostics
- generating a full filesystem export or YAML-oriented report
- comparing a live card against a stored "gold" profile snapshot

Do not use it as a relay provisioning shell. Relay work lives in `SCP11/live`.
Direct local ISD-R provisioning lives in
`SCP11/local_access`.

## Entry points

=== "Module"

    ```bash
    python -m SCP03
    python -m SCP03 --cmd "AUTH-SD; APPS; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-scp03
    yggdrasim-scp03 --cmd "AUTH-SD; APPS; EXIT"
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP03 entry.

## Command surface, grouped

### Secure channel and session

| Command | Purpose |
| --- | --- |
| `AUTH-SD` | authenticate the currently selected Security Domain |
| `AUTH-ISD` | authenticate the Issuer Security Domain |
| `AUTH-SSD` | authenticate a Supplementary Security Domain |
| `RESELECT` | reselect the active applet/SD |

### Registry and content management

| Command | Purpose |
| --- | --- |
| `APPS` | enumerate applications |
| `LIST` | list contents of the active selection |
| `SELECT <AID or path>` | select by AID or by ETSI path |
| `PUT-KEY` | install or rotate a key set on the active SD |

### Filesystem

| Command | Purpose |
| --- | --- |
| `SELECT <FID or path>` | select an EF, DF, or ADF |
| `READ` | read the selected EF |
| `UPDATE` | update the selected EF |
| `DUMP-FS` | export the entire filesystem |

### eUICC retrieval

Under the selected `ISD-R`, the shell can drive:

- `GetProfilesInfo`
- `GetEuiccConfiguredData`
- `GetEID`
- `GetEuiccInfo1`
- `GetEuiccInfo2`
- `GetRAT`
- `RetrieveNotificationsList`
- `GetEimConfigurationData`
- `GetCerts`

These land under wizarded and direct commands inside the SCP03 shell.

### PIN and authentication

| Command | Purpose |
| --- | --- |
| `VERIFY`, `CHANGE`, `DISABLE`, `ENABLE`, `UNBLOCK` | CHV and PUK handling |
| `AUTH-GSM`, `AUTH-USIM`, `AUTH-ISIM` | `AUTHENTICATE` helpers for each NAA |

### Reporting

| Command | Purpose |
| --- | --- |
| report mode | combined filesystem + eUICC report generation |
| `DUMP-FS` | full filesystem export |
| gold-snapshot workflow | live-vs-gold diff against a stored snapshot |

### HIL / diagnostics

| Command | Purpose |
| --- | --- |
| `EXPORT-KEYBAG [Path.keys.json] [Label]` | dump the active SCP03 session keys (S-ENC, S-MAC, S-RMAC, SSC, chaining value) and the active target AID into a keybag JSON for offline HIL pcap decryption |

See [Session key export](#session-key-export) below and the HIL Bridge
[offline replay flow](hil-bridge.md#offline-pcap-replay).

## Runtime dependencies

- a PC/SC reader with the card inserted
- live GP key material under `Workspace/SCP03/` (keyset, AID choices)
- the shared SQLite inventory for SCP03 per-card state
- optional `gpg` if the inventory crypto envelope is enabled

## State the shell writes

| Location | Contents |
| --- | --- |
| `state/device_inventory.sqlite3` | per-ICCID and per-EID SCP03 state |
| `Workspace/SCP03/aid.txt` | AID choices (plain file for diff review) |
| `Workspace/SCP03/fids.txt` | FID quick-select list |
| `Workspace/SCP03/binds.json` | custom bind macros |
| `Workspace/SCP03/keys.ini` | legacy import source for keysets |

## Common recipes

### Open an SD, list apps, read IMSI

```text
[APDU] > AUTH-SD
[A0...00] > APPS
[A0...00] > SELECT USIM/IMSI
[A0...00] > READ
```

### One-shot dump of the whole filesystem

```bash
python -m SCP03 --cmd "AUTH-SD; DUMP-FS; EXIT"
```

### Authenticate a USIM

```text
[A0...00] > SELECT ADF.USIM
[A0...00] > AUTH-USIM <RAND> <AUTN>
```

The response carries `RES`, `CK`, `IK`, or an `AUTS` on SQN mismatch.

### Gold-profile diff

After persisting a gold snapshot via the shell:

```text
[APDU] > GOLD-DIFF
```

The diff surfaces EF-level changes since the stored baseline.

### Session key export

`EXPORT-KEYBAG` snapshots the currently-authenticated SCP03 session
into a keybag JSON compatible with the HIL Bridge offline-replay
decoder.

```text
[APDU] > AUTH-SD
[A0...00] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234
```

Arguments (both optional):

- `OutputPath.keys.json` — destination file. Defaults to a
  timestamped path under the SCP03 workspace when omitted.
- `Label` — free-form identifier written to the entry for operator
  cross-referencing (ticket id, serial, pcap name, etc.).

The handler refuses cleanly if:

- there is no active card session
- the session exists but has not authenticated (no derived keys yet)

Written fields (per entry):

- `protocol`: `"SCP03"`
- `aid_hex`: current target AID (from `gp_ctrl.target_aid`)
- `s_enc_hex` / `s_mac_hex` / `s_rmac_hex`: session keys at time of export
- `ssc_hex` / `chaining_value_hex`: SCP03 state at time of export
- `label`: the operator-provided label

See [HIL Bridge — Keybag JSON schema](hil-bridge.md#keybag-json-schema)
for the complete file structure and
[Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md) for
how the keybag feeds into the decoded-APDU TUI.

## Pitfalls

- Wrong keyset returns `6982` before `EXTERNAL AUTHENTICATE` completes.
  Check `Workspace/SCP03/keys.ini` or the migrated inventory state.
- Selecting an EF that is not active returns `6A82`. Walk from `3F00` when in
  doubt.
- `PUT-KEY` without a live, authenticated session returns `6985`.
- eUICC retrieval commands require that the selected SD is the `ISD-R` or an
  SD authorized to issue them. Use the wizard when in doubt.

## In-shell documentation

SCP03 has an in-session guide and a grouped help surface.

- `GUIDE` opens the topic menu
- `GUIDE GP`, `GUIDE ETSI`, `GUIDE GSMA`, `GUIDE INSTALL`, `GUIDE SECURITY`,
  `GUIDE OTA`, `GUIDE CONFIG`, `GUIDE SAIP`, `GUIDE SUCI`, `GUIDE CLI` for
  topic deep dives
- `HELP` prints the grouped command reference

The same content is mirrored under [Shell Guides](../shell-guides/index.md)
for reading outside the terminal.

## Related pages

- [GlobalPlatform](../concepts/globalplatform.md)
- [ETSI UICC](../concepts/etsi-uicc.md)
- [3GPP NAA](../concepts/3gpp-naa.md)
- [CLI Matrix](../reference/cli-matrix.md)
- [Troubleshooting](../reference/troubleshooting.md)
- [HIL Bridge — offline pcap replay](hil-bridge.md#offline-pcap-replay)
- [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md)
