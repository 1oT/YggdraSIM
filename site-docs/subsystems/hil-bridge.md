---
title: HIL Bridge
tags:
  - subsystems
  - hil
  - simtrace2
---

# HIL Bridge

`Tools/HilBridge/` is the physical-card-to-modem bridge. Use it when a real
UICC/eUICC must stay in a PC/SC reader on the host while serving a modem
through a SIMtrace2, and YggdraSIM shells still need live side-channel access
to the same card.

!!! info "Underlying concept"
    Read [HIL Model](../concepts/hil-model.md) first. This page focuses on the
    operator surface and health signals.

## When to use it

- reproducing a real modem's behavior against a real eUICC in the lab
- capturing end-to-end APDU traces with both modem and YggdraSIM activity
  visible
- observing a live relay or local-access session while the modem is
  interacting with the same card
- serving a SIMtrace2 in card-emulation mode for a DUT
- re-opening a previously saved `.pcap` / `.pcapng` in the decoded-APDU
  TUI without bringing the bridge stack back up (offline review mode)
- layering SCP03 / SCP11c plaintext onto ciphered APDUs in either live
  or offline review by pairing the capture with a keybag JSON sidecar

## Entry points

The supervisor is the recommended process. The bridge alone is meant for
manual debugging.

=== "Supervisor"

    ```bash
    yggdrasim-hil-supervisor \
      --reader-index 0 \
      --host 127.0.0.1 \
      --port 9997 \
      --advertise-host 127.0.0.1 \
      --usb-vidpid 1d50:60e3
    ```

=== "Module form"

    ```bash
    python -m Tools.HilBridge.supervisor \
      --reader-index 0 \
      --host 127.0.0.1 \
      --port 9997 \
      --advertise-host 127.0.0.1 \
      --usb-vidpid 1d50:60e3
    ```

=== "Bridge only"

    ```bash
    yggdrasim-hil-bridge
    python -m Tools.HilBridge.main
    ```

=== "Offline pcap review"

    ```bash
    python main/main.py --open-pcap /path/to/capture.pcapng
    python main/main.py --open-pcap /path/to/capture.pcap \
        --keybag /path/to/session.keys.json
    ```

    Opens the decoded-APDU TUI in offline mode. No SIMtrace2, no
    supervisor, no FIFO, no `tshark -i`. The capture is read via
    `tshark -r`. When a keybag is provided (or a sibling
    `<capture>.keys.json` is auto-discovered), SCP03 / SCP11c ciphered
    APDUs are unwrapped and shown as extra plaintext rows next to the
    matching frame. See [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md).

## Supervisor responsibilities

The supervisor:

- starts and supervises both the HIL bridge process and
  `osmo-remsim-client-st2`
- tracks USB presence of the SIMtrace2 by VID:PID
- writes health state to `state/hil_bridge_supervisor.json`
- writes card-relay endpoint state to `state/hil_bridge_card_relay.json`
- cleans up both processes on shutdown

## Runtime dependencies

- `pcscd` and its reader drivers
- `osmo-remsim-client-st2`
- SIMtrace2 hardware flashed for card emulation
- optional `simtrace2-list` / `simtrace2-tool` for manual inspection
- optional Wireshark for GSMTAP capture

## State the supervisor and bridge write

| File | Contents |
| --- | --- |
| `state/hil_bridge_supervisor.json` | supervisor status, bridge PID, USB presence |
| `state/hil_bridge_card_relay.json` | relay status, URLs, reader name, ATR |

## Health signals

Healthy state reads:

- supervisor `status: running`
- supervisor `usbPresent: true`
- supervisor `bridgePid` non-zero
- relay `status: ok`
- relay exposes `apduUrl`, `statusUrl`, `modemRefreshUrl`
- relay shows a non-empty `reader` and a non-empty `atr`

Anything else means the stack is not fully armed.

## Common recipes

### Start, check, stop

```bash
yggdrasim-hil-supervisor --reader-index 0 --host 127.0.0.1 --port 9997
# ... in another shell ...
cat state/hil_bridge_supervisor.json
cat state/hil_bridge_card_relay.json
# ... stop via the supervisor's shutdown path or Ctrl-C ...
```

### Pair with a YggdraSIM shell

Once the relay reports `status: ok`, open any SCP11 or SCP03 shell that can
be pointed at the relay URLs. The card will see both modem APDUs and
YggdraSIM APDUs on one session, serialized through the bridge.

### Use Wireshark to watch GSMTAP

Open Wireshark on UDP 4729 (loopback). The bridge mirrors every APDU as
GSMTAP while it is running, even if no YggdraSIM shell is attached.

## Offline pcap replay

The decoded-APDU TUI has two drive modes:

| Mode | How it is launched | Notes |
| --- | --- | --- |
| Live capture | `[B]` HIL sub-menu pick `[1]` with view `[3]` (Decoded APDU) | tails the running bridge's FIFO via `tshark -i` |
| Offline review | `[B]` sub-menu pick `[3]`, or `main/main.py --open-pcap <path>` | reads a saved `.pcap` / `.pcapng` via `tshark -r`, with no FIFO and no bridge |

Both modes accept a **keybag JSON** sidecar. It stores the per-session
SCP03 / SCP11c key material that the TUI's replay engine needs to
unwrap secure-messaging APDUs (CLA bit `0x04`). When resolving the
keybag, the TUI tries, in order:

1. `--keybag <path>` on the launcher, or the prompt in the `[B]`
   offline-review flow
2. `<capture>.pcap.keys.json` next to the capture
3. `<capture>.keys.json` (capture stem + `.keys.json`)

A missing or unreadable keybag is non-fatal -- ciphered APDUs simply
stay wrapped in the TUI. See [Keybag JSON schema](#keybag-json-schema)
below for the file shape and how to produce one with
[`EXPORT-KEYBAG`](#session-key-export) in SCP03 / SCP11 Local Access,
or with `--dump-keybag` from the same modules.

## Session key export

Keybags are produced host-side by the same shells that derive the
session keys. The two supported flows are:

| Source shell | Command | Where the keys come from |
| --- | --- | --- |
| `SCP03` | `EXPORT-KEYBAG [OutputPath.keys.json] [Label]` | `Scp03Session` S-ENC / S-MAC / S-RMAC + SSC + chaining value after `AUTH-SD` |
| `SCP11.local_access` (shell) | `EXPORT-KEYBAG [OutputPath.keys.json] [Label]` | last-built pySim BSP (S-ENC, S-MAC, MAC chain, block number, AID) |
| `SCP11.local_access` (CLI) | `python -m SCP11.local_access --dump-keybag <path>` | same BSP snapshot, non-interactive |
| `SCP11.live` (CLI) | `python -m SCP11.live --dump-keybag <path>` | **no-op**: live-mode BSP keys are derived inside the eUICC and never reach the host. The flag prints a clear message pointing at `SCP11.local_access` or SCP03. |

Both `EXPORT-KEYBAG` handlers refuse with a clear message when no
authenticated session / derived BSP snapshot is available.

### Keybag JSON schema

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

Keys:

- `format` must be `yggdrasim-hil-keybag/v1`.
- `entries` is a list; multiple SCP03 / SCP11c sessions can coexist in
  a single file.
- `protocol` is `"SCP03"` or `"SCP11c"`; the TUI uses it to decide which
  crypto path to drive.
- `s_enc_hex` / `s_mac_hex` / `s_rmac_hex` are the session keys
  (SCP03 naming; SCP11c fills S-RMAC with empty string).
- `ssc_hex` / `chaining_value_hex` / `block_nr` capture the state the
  replay engine needs to mirror the on-card counters at the moment of
  export.
- `aid_hex` binds the entry to the SELECT AID that preceded the secure
  channel on capture time, so multiple sessions against the same card
  are disambiguated.

Write a keybag with `EXPORT-KEYBAG` / `--dump-keybag` or by hand; the
schema is stable across `v1`.

## Pitfalls

- A second PC/SC client cannot open the same reader while the bridge owns
  it. Close other shells first, or go through the relay side-channel.
- USB presence alone is not readiness. Wait until the relay advertises
  `status: ok` and a non-empty `atr`.
- Restarting only the bridge without the supervisor can leave
  `osmo-remsim-client-st2` orphaned. Use the supervisor for normal lifecycle.
- A flashed firmware mismatch on the SIMtrace2 will let the supervisor
  enumerate the USB device, but the relay will never come up. Check the
  remsim-client logs.
- Offline review mode trusts the capture's ATR / SELECT context. If the
  keybag entry's `aid_hex` does not match the AID in the capture the
  corresponding APDUs simply stay wrapped.
- `SCP11.live --dump-keybag` is intentionally a stub -- the keys never
  leave the card in live mode. Use `SCP11.local_access` or SCP03 for
  real exports.

## AT+CSIM / AT+CRSM transcoder

`Tools/HilBridge/at_simlink.py` (3GPP TS 27.007 §8.17 / §8.18) is a
transport-agnostic transcoder that turns `AT+CSIM=...` and
`AT+CRSM=...` request lines into raw ISO 7816 APDUs and stringifies
the responses back into `+CSIM:` / `+CRSM:` reply lines. Use it when
an AT-controlled modem must exercise the simulator or a SIMtrace2-bridged
card without a direct PC/SC handle:

| Request shape | Decoded APDU |
| --- | --- |
| `AT+CSIM=<length>,"<hex>"` | raw `CLA INS P1 P2 P3 ...` |
| `AT+CRSM=<command>,<fileid>,<P1>,<P2>,<P3>[,"<data>"][,"<path>"]` | `CLA=0x00`, `INS` from the §8.18 command table |

Common modem REFRESH and AT-only flows can therefore be replayed
through the same simulator backend the SCP shells use, with no host
PC/SC involvement on the modem side.

## Optional `systemd --user` service

`guides/systemd/yggdrasim-hil-supervisor.service.example` ships as a starting
point when the supervisor should be launched on demand under user service
control.

## Related pages

- [HIL Model](../concepts/hil-model.md)
- [Run a HIL Capture](../how-to/run-hil-capture.md)
- [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md)
- [SCP03 Admin Shell -- EXPORT-KEYBAG](scp03.md#session-key-export)
- [SCP11 Local Access -- EXPORT-KEYBAG / `--dump-keybag`](scp11-local-access.md#session-key-export)
- `guides/HIL_BRIDGE_GUIDE.md` for the deep authored guide
