---
title: Run a HIL Capture
tags:
  - how-to
  - hil
  - simtrace2
  - wireshark
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Run a HIL Capture

## Goal

Bring up the HIL supervisor, attach a real UICC/eUICC, expose it to both a
modem and a YggdraSIM shell, and capture the combined APDU traffic in
Wireshark for post-mortem review.

## Prerequisites

- `pcscd` running on the host
- `osmo-remsim-client-st2` installed on `PATH`
- a SIMtrace2 flashed for card emulation
- a physical UICC or eUICC in a PC/SC reader
- Wireshark with a loopback interface available
- optional `simtrace2-list` / `simtrace2-tool` for USB inspection
- optional Card Bridge and SSH tunnel when the physical card is remote

## Steps

1. Start Wireshark listening on the loopback interface, filter `gsm_sim` or
   `udp.port == 4729`.

2. Launch the supervisor.

    ```bash
    yggdrasim-hil-supervisor \
      --reader-index 0 \
      --host 127.0.0.1 \
      --port 9997 \
      --advertise-host 127.0.0.1 \
      --usb-vidpid 1d50:60e3
    ```

    If the card is on a remote workstation, use remote-card mode instead:

    ```bash
    yggdrasim-hil-supervisor \
      --remote-card-url http://127.0.0.1:8642/apdu \
      --remote-card-token-file ~/.config/yggdrasim/card_bridge/8642.token \
      --apdu-timeout-ms 30000 \
      --usb-vidpid 1d50:60e3
    ```

    See [Remote APDU Streaming](remote-apdu-streaming.md) for the Card
    Bridge and SSH setup.

3. Confirm healthy state.

    ```bash
    cat state/hil_bridge_supervisor.json
    cat state/hil_bridge_card_relay.json
    ```

    Look for `status: running`, `usbPresent: true`, and a relay
    `status: ok` with a non-empty `atr`.

4. Let the modem attach to the SIMtrace2. Wireshark should now populate with
   GSMTAP APDUs between modem and card.

5. Open a YggdraSIM shell that can be pointed at the relay side-channel.

    ```bash
    python -m SCP11.live
    ```

    Traffic from the shell appears in the same Wireshark capture, serialized
    with modem traffic on the one live card.

    In the GUI, open the HIL module or Card bridge view and watch the live
    APDU dock. The GUI receives APDU rows from the same process-wide recorder
    that card-consuming actions use.

6. Save the capture when the observation is complete.

    If the session used a secure channel and you want to be able to
    unwrap it during later offline review, dump the session keys into a
    keybag JSON next to the capture (see
    [Replay a HIL pcap offline](replay-hil-pcap-offline.md)):

    ```text
    # from the SCP03 admin shell, after AUTH-SD
    [A0...00] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234

    # or from SCP11 Local Access, after a BSP-building verb
    [Local SMDPP] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234
    ```

7. Shut the supervisor down cleanly. It terminates both the bridge and
   `osmo-remsim-client-st2`.

## Validation

- Wireshark shows APDUs from both the modem and the YggdraSIM side
- no reader contention errors surface from other PC/SC clients
- state files show `status: running` / `status: ok` throughout the session

## Common failures

| Symptom | Likely cause |
| --- | --- |
| supervisor reports `usbPresent: false` | SIMtrace2 not enumerated. Check `dmesg` and `lsusb`. |
| relay never reports `status: ok` | `osmo-remsim-client-st2` is failing to attach. Check its logs. |
| missing `atr` in relay state | card not powered or seated. Reseat it in the reader. |
| Wireshark sees modem traffic but not YggdraSIM traffic | YggdraSIM shell is using a direct PC/SC handle instead of the relay. Verify the configuration. |
| remote-card HIL starts but APDUs time out | SSH tunnel latency or stale token | raise `--apdu-timeout-ms`, re-copy the token, verify `/status` |

## Related pages

- [HIL Bridge](../subsystems/hil-bridge.md)
- [Remote APDU Streaming](remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](install-remsim-apdu-streaming.md)
- [Universal GUI Command Center](../subsystems/gui-command-center.md)
- [HIL Model](../concepts/hil-model.md)
- [Replay a HIL pcap offline](replay-hil-pcap-offline.md)
- `guides/HIL_BRIDGE_GUIDE.md`
