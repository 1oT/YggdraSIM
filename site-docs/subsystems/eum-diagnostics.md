---
title: EUM Diagnostics
tags:
  - subsystems
  - diagnostics
  - scp11
  - saip
  - wireshark
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# EUM Diagnostics "God-Mode"

`Tools/EumDiag/` is the *server-side* diagnostic toolbox for
ES8+ / Bound Profile Package (BPP) work. Its purpose is to take
ShS-ENC / ShS-MAC / DEK session material — which an EUM or
SM-DP+ operator already has in its session database — and turn
an otherwise opaque `BF36` capture into an analysable one through
a Wireshark/tshark Lua dissector.

## When to use it

- post-mortem analysis of a failed provisioning on a server you
  operate
- reproducing an ES8+ flow inside Wireshark / tshark during
  integration testing
- offline BPP decode (requires the optional pySim checkout)

!!! info "Not a decryptor"
    The dissector annotates BPP TLVs with the provided key bundle.
    Full plaintext recovery still requires a downstream decode step;
    that is what the `decode-bpp` subcommand is for.

## Entry points

=== "Console script"

    ```bash
    yggdrasim-eum-diag --help
    yggdrasim-eum-diag inject-keys --help
    yggdrasim-eum-diag store-keys --help
    yggdrasim-eum-diag decode-bpp --help
    ```

=== "Module"

    ```bash
    python -m Tools.EumDiag
    ```

## Subcommands

### `inject-keys`

Writes a JSON key repository (atomic, `0o600` on POSIX) and
launches `tshark` with the Lua dissector attached to the capture.

```bash
yggdrasim-eum-diag inject-keys \
    --iccid 89880012345678901234 \
    --shs-enc <32 hex chars> \
    --shs-mac <32 hex chars> \
    --dek     <32 hex chars> \
    --pcap    /captures/provisioning.pcapng
```

### `store-keys`

Writes the key repository only. Useful when a separate
`wireshark` / `tshark` process already has the dissector loaded
and just needs the key file to be created.

```bash
yggdrasim-eum-diag store-keys \
    --iccid 89880012345678901234 \
    --shs-enc ... --shs-mac ... \
    --keys-out /tmp/session-keys.json
```

### `decode-bpp`

Offline decode of a BPP binary through the optional pySim
checkout. Skips cleanly with a clear message if pySim is not
available.

```bash
yggdrasim-eum-diag decode-bpp --bpp /path/to/bpp.bin
```

## Key repository on disk

```json
{
    "format": "yggdrasim-eum-session-keys/v1",
    "entries": {
        "89880012345678901234": {
            "iccid": "89880012345678901234",
            "shs_enc_hex": "...",
            "shs_mac_hex": "...",
            "dek_hex": "...",
            "comment": "case-id"
        }
    }
}
```

The Lua dissector picks the path up from `YGGDRASIM_EUM_SESSION_KEYS`.
The tshark runner sets that variable for you when using `inject-keys`.

## Runtime dependencies

- `tshark` on `PATH` for `inject-keys`
- the shipped `Tools/EumDiag/dissector.lua` (part of the wheel's
  package-data)
- optional pySim checkout for `decode-bpp`

## Related references

- [Diagnostics Toolbox](../how-to/diagnostics-toolbox.md)
- `tests/test_eum_diag.py` for the reference behaviour contract
