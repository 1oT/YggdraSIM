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
    python -m SCP80 --cmd "show; iccid 8988xxx; build A0D6...; send; EXIT"
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
| `sendraw <hex>` | transmit a raw APDU without OTA wrapping; a data field over 255 bytes is sent as a STORE DATA block sequence |
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
| `SCP80/ota_config.ini` | legacy import source, read while the inventory holds no SCP80 state; not shipped |

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

## Reading the answer

When the SPI asks for a PoR, `send` and `ota` collect it without operator
input. A PoR sent by SMS-DELIVER-REPORT is the ENVELOPE's own response data;
one sent by SMS-SUBMIT arrives as a SEND SHORT MESSAGE, which the shell
FETCHes on the ENVELOPE's `91 xx` and answers with a TERMINAL RESPONSE. The
shell then prints:

- `[<--] <data> <SW>` -- the response data and status word of the last
  command the script ran (TS 102 226 v19 table 5.1). A PoR without that
  field, an error PoR or one that does not decode prints raw, beside the
  ENVELOPE status word.
- `[POR] ...` -- the PoR status, TAR, CNTR, how many of the sent commands
  ran, the carrier and the status word that led to the FETCH. A PoR OK whose
  script ran to the end and answered `9000` prints this line only under `-v`.
- `--- Decoded (...) ---` -- the data of an EF read after a SELECT, or else
  the data decoded by context: GlobalPlatform registry entries, FCP
  templates, other BER-TLV objects.

Under `-v` the exchanges print below an `[OTA] SMS-PP data download` line,
each named: `ENVELOPE`, `FETCH`, `TERMINAL RESPONSE`, `GET RESPONSE`.

```text
[SCP80] > send 80F24002054F005C014F00C0000000
[<--] E3094F07F0010203040501E3094F07F0010203040502 9000
--- Decoded (GlobalPlatform card content management) ---
    GlobalPlatform registry entries  [GPC v2.3.1 tables 11-36 / 11-37]
      E3 GlobalPlatform Registry related data
        4F AID = 'F0010203040501'H
      E3 GlobalPlatform Registry related data
        4F AID = 'F0010203040502'H
    SW 9000: Success
```

## Pitfalls

- A compact command string is a list of T=0 TPDUs, so a case 4 command such
  as GET STATUS carries no Le, and its response stays on the card unless a
  GET RESPONSE (`00C0000000`) follows it. TS 102 226 v19 §5.1.1 allows one
  GET RESPONSE or case 2 command per string, as the last command; the
  `[POR]` line counts the commands that ran against those sent. A reply of
  `61 xx` means the GET RESPONSE was missing; the shell names the one to
  append.
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
