---
title: SCP80 OTA Shell
tags:
  - subsystems
  - scp80
  - ota
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SCP80 OTA Shell

`SCP80/` is the OTA construction and send/decode shell. Use it when the task
is building a secured packet, wrapping a payload with `KIc`/`KID`, sending it
to a reader target, decoding a received response packet, or running a scripted
OTA sequence against a per-ICCID state.

!!! info "Underlying concept"
    This shell builds on [SCP80 OTA](../concepts/ota-scp80.md). Read that first
    if SPI, TAR, and PoR are not already familiar terms.

## When to use it

- wrapping direct hex payloads into SCP80
- tuning secured-packet parameters
- sending an OTA payload to a reader-connected card
- decoding a received response packet
- running a scripted OTA sequence
- reusing per-ICCID configuration across sessions
- stepping into `SCP03` to observe what the OTA session changed on the
  filesystem or registry

## Entry points

=== "Module"

    ```bash
    python -m SCP80
    python -m SCP80 --cmd "show; iccid 8946xxx; build A0D6...; send; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-scp80
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP80 entry.

## Command surface

| Verb | Purpose |
| --- | --- |
| `show` | print current parameters |
| `set <param> <value>` | update an OTA parameter |
| `iccid <hex>` | bind the session to a specific ICCID state |
| `build <hex>` | assemble a secured packet from direct payload hex |
| `send` | transmit the last built packet |
| `sendraw <hex>` | transmit a raw APDU without OTA wrapping |
| `ota <hex>` | build and send in one step |
| `script <path>` | execute a command script |
| `history` | show session history |
| `reset` | reset the STK / toolkit context |
| `exit` | leave the shell |

The parameter set exposed by `set` covers:

- `KIc` / `KID` key indices
- `TAR`
- `SPI` (integrity, ciphering, counter, response requirements)
- `PoR` mode
- concatenation and TP-UD window sizing
- transport selection for reader and external send paths

## Runtime dependencies

- a PC/SC reader for reader-mode sends, or an external bearer for print-only
  workflows
- the shared SQLite inventory for per-ICCID OTA state
- optional `SCP03` session if the operator wants to observe filesystem
  changes after an RFM/RAM OTA

## State the shell writes

| Location | Contents |
| --- | --- |
| `state/device_inventory.sqlite3` | per-ICCID OTA parameters, history |
| `SCP80/ota_config.ini` | legacy import source, retained for migration |

## Common recipes

### Send a plain `UPDATE BINARY` via OTA

```text
[SCP80] > iccid 8988000000000000000F
[SCP80] > set kic_indicator 15
[SCP80] > set kid_indicator 15
[SCP80] > set TAR 000000
[SCP80] > build 00D6000003A0A0A0
[SCP80] > send
```

### One-shot OTA wrap and send

```bash
python -m SCP80 --cmd "iccid 8988000000000000000F; ota 00D6000003A0A0A0; exit"
```

### Reuse ICCID-bound state across sessions

```text
[SCP80] > iccid 8988000000000000000F
[SCP80] > show
[SCP80] > build 00A40000023F00
[SCP80] > send
```

Relaunching `SCP80` with the same ICCID restores `KIc`, `KID`, `TAR`, `SPI`,
and the rest of the parameter set.

### Script-mode send

```bash
python -m SCP80 --cmd "script ./my_ota_sequence.scp80; exit"
```

## Pitfalls

- SPI must be consistent on both sides. If `CC` is required, the card will
  reject any packet missing it with `6988` or a PoR error code.
- Counter mode must be aligned with whatever the card has seen last. An
  `increasing counter` SPI with a counter that is not strictly greater than
  the previous one is rejected.
- `TAR` mismatches route the payload to a different applet or to the RFM
  engine silently. Verify the TAR before expecting a response.
- Reader-mode send requires that the reader is not locked by another process.
  The HIL bridge, for example, takes exclusive ownership; see
  [HIL Bridge](hil-bridge.md).

## In-shell documentation

SCP80 documentation is integrated with the SCP03 `GUIDE OTA` topic and the
authored `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md` for lifecycle-flavored
OTA examples.

## Related pages

- [SCP80 OTA](../concepts/ota-scp80.md)
- [SCP03 Admin Shell](scp03.md)
- [CLI Matrix](../reference/cli-matrix.md)
