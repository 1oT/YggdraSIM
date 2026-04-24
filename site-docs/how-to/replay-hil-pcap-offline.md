---
title: Replay a HIL pcap offline
tags:
  - how-to
  - hil
  - wireshark
  - scp03
  - scp11
---

# Replay a HIL pcap offline

## Goal

Open a previously captured HIL `.pcap` / `.pcapng` in the decoded-APDU
Textual TUI without bringing the SIMtrace2 / bridge / supervisor stack
back up. When a matching keybag JSON is available, decrypt the
SCP03 / SCP11c secure messaging sections inline so ciphered APDUs are
annotated with their plaintext.

Offline replay reuses the same TUI that drives live captures; the
difference is that `tshark -r` reads the file instead of `tshark -i`
streaming a live FIFO.

## Prerequisites

- a saved `.pcap` or `.pcapng` captured by the HIL bridge, Wireshark,
  `tshark`, or `dumpcap` — on-wire frames must be either plain APDUs or
  GSMTAP over UDP `4729`
- `tshark` on `PATH`
- Python environment with YggdraSIM installed (source checkout or
  `pip install -e .`)
- **optional**: a keybag JSON with SCP03 or SCP11c session keys for any
  secure-channel traffic that appears in the capture

For how to produce the keybag, see
[Session key export](#session-key-export) below and the subsystem pages
[SCP03](../subsystems/scp03.md#session-key-export) and
[SCP11 Local Access](../subsystems/scp11-local-access.md#session-key-export).

## Steps

1. Locate the capture file. Example:

    ```bash
    ls -lh Workspace/hil/captures/
    # session-2026-04-20.pcapng
    # session-2026-04-20.pcap.keys.json
    ```

    If the keybag lives next to the capture as
    `<capture>.pcap.keys.json` or `<capture>.keys.json`, it is
    auto-discovered.

2. Launch the decoded-APDU TUI in offline mode.

    === "CLI, automatic keybag"

        ```bash
        python main/main.py \
            --open-pcap Workspace/hil/captures/session-2026-04-20.pcapng
        ```

    === "CLI, explicit keybag"

        ```bash
        python main/main.py \
            --open-pcap Workspace/hil/captures/session-2026-04-20.pcapng \
            --keybag    Workspace/hil/captures/session-2026-04-20.keys.json
        ```

    === "From the `[B]` menu"

        ```text
        python main/main.py
        [B]   HIL Bridge Session
         [3]  Open saved .pcap (offline review, no bridge)
              pcap path  : Workspace/hil/captures/session-2026-04-20.pcapng
              keybag path: (blank → auto-discover)
        ```

3. Navigate the capture.

    The TUI behaves the same as in live capture mode — summary list on
    the left, detail pane, hex pane, and stateful context rows.
    Secure-messaging APDUs that match a keybag entry gain an extra
    "plaintext" context line. Entries that do not match (wrong AID, no
    keybag, unknown protocol) stay wrapped.

4. Leave the TUI.

    Press `Ctrl+Q` (or the normal exit keybind). No background
    processes were started; nothing needs to be torn down.

## Session key export

Keybag JSONs are produced by the same shells that build the secure
channel. Pick the path that matches how the capture was made:

### SCP03 sessions

Inside the SCP03 admin shell, after `AUTH-SD`:

```text
[APDU] > AUTH-SD
[A0...00] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234
```

The handler refuses cleanly if the session is not authenticated.

### SCP11 Local Access sessions

Inside `SCP11.local_access`, after any verb that builds a BSP (for
example `LOAD-PROFILE`, `ENABLE-PROFILE`, or `STORE-METADATA`):

```text
[Local SMDPP] > LOAD-PROFILE
[Local SMDPP] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234
```

Non-interactively:

```bash
python -m SCP11.local_access --dump-keybag \
    Workspace/hil/captures/session-2026-04-20.keys.json
```

### SCP11 Live sessions

`python -m SCP11.live --dump-keybag` is a **stub**. In live mode the
SCP11c BSP keys are derived inside the eUICC during BPP processing and
never leave the card. The flag prints a clear message and exits with
code `2`. Use `SCP11.local_access` or SCP03 if a real keybag is needed
for the capture.

## Keybag JSON schema

```json
{
  "format": "yggdrasim-hil-keybag/v1",
  "entries": [
    {
      "label": "case-1234",
      "protocol": "SCP03",
      "aid_hex": "A000000151000000",
      "s_enc_hex": "...32 hex chars...",
      "s_mac_hex": "...32 hex chars...",
      "s_rmac_hex": "...32 hex chars...",
      "ssc_hex": "0000000000000000",
      "chaining_value_hex": "",
      "block_nr": 0
    }
  ]
}
```

Multiple entries are allowed in one file. `protocol` is `"SCP03"` or
`"SCP11c"`. The replay engine matches entries against the AID in the
capture; unmatched entries are skipped silently.

## Validation

- TUI banner shows `offline review (no bridge, no live FIFO)`.
- TUI status line reports the resolved keybag path, or a no-keybag
  note if nothing was supplied or discovered.
- Secure-messaging APDUs (CLA bit `0x04`) gain a `[plaintext]` context
  row when the keybag entry matches.
- `state/hil_bridge_supervisor.json` is **not** touched; the systemd
  HIL service is left alone.

## Common failures

| Symptom | Likely cause |
| --- | --- |
| `tshark is not available` | Install `tshark` (`wireshark-cli`) and retry. |
| `pcap file not found` | Path typo, or permissions on the capture. |
| Ciphered APDUs stay wrapped | No keybag, wrong AID in the keybag entry, or the capture actually contains only plaintext APDUs. |
| `SCP11.live --dump-keybag` prints "no-op" | Expected — live mode BSP keys are not host-side. Use Local Access or SCP03. |

## Related pages

- [HIL Bridge](../subsystems/hil-bridge.md)
- [Run a HIL Capture](run-hil-capture.md)
- [SCP03 Admin Shell](../subsystems/scp03.md#session-key-export)
- [SCP11 Local Access](../subsystems/scp11-local-access.md#session-key-export)
- `guides/HIL_BRIDGE_GUIDE.md`
