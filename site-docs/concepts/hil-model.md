---
title: HIL Model
tags:
  - concepts
  - hil
  - simtrace2
---

# HIL Model

The HIL (Hardware-In-The-Loop) model is how YggdraSIM exercises a real
UICC/eUICC against a real modem while still letting operator shells see the
card. The physical plumbing is built around sysmocom's SIMtrace2 and the
`osmo-remsim-client-st2` bridge, with a local RSPRO relay on
`127.0.0.1:9997` and GSMTAP mirroring to Wireshark on UDP `4729`.

## Physical topology

```mermaid
flowchart LR
    Card["Physical UICC / eUICC<br/>in PC/SC reader"] --> PCSC["pcscd"]
    PCSC --> Bridge["YggdraSIM HIL bridge<br/>127.0.0.1:9997"]
    Bridge --> Remsim["osmo-remsim-client-st2"]
    Remsim --> SIMtrace2["SIMtrace2 device"]
    SIMtrace2 --> Modem["Modem / DUT"]
    Bridge --> Wireshark["Wireshark<br/>UDP 4729 GSMTAP"]
    Bridge --> YggdraSide["YggdraSIM operator shells<br/>via local relay"]
```

The card is physically in a reader attached to the host. The SIMtrace2 exposes
it to a modem as if it were a locally-inserted SIM. The bridge is the coupler
and the telemetry source.

## Responsibility split

| Component | Owns |
| --- | --- |
| `pcscd` | reader arbitration |
| HIL bridge | exclusive PC/SC ownership while active |
| HIL bridge | GSMTAP mirror of every APDU on UDP 4729 |
| HIL bridge | local APDU relay on 127.0.0.1:9997 |
| supervisor | lifecycle of bridge + remsim-client |
| `osmo-remsim-client-st2` | framing between SIMtrace2 and bridge |
| SIMtrace2 | card-emulation signals to the modem |
| YggdraSIM shells | brokered side-channel access to the same card |

## Access rules

- The HIL bridge keeps **exclusive ownership** of the physical reader while
  active. A second PC/SC client cannot open the same reader at the same time.
- YggdraSIM operator shells reach the card through the bridge's **relay
  side-channel**, not through a second direct PC/SC handle.
- Modem APDUs and YggdraSIM APDUs are **serialized**, not isolated. They
  share a single live session with the card.
- GSMTAP mirroring is passive. Wireshark sees every APDU traveling between
  modem and card, plus the YggdraSIM side-channel traffic.

## Lifecycle

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Sup as HIL supervisor
    participant Br as HIL bridge
    participant Rem as remsim-client
    participant ST as SIMtrace2
    Op->>Sup: start
    Sup->>Br: spawn bridge
    Br->>Rem: spawn remsim-client
    Rem->>ST: attach
    ST-->>Rem: modem active
    Br->>Op: relay endpoints ready (apduUrl, statusUrl)
    Op->>Br: YggdraSIM shell connects via relay
    Op->>Sup: stop
    Sup->>Br: shutdown
    Br->>Rem: terminate
```

The recommended launch path is the supervisor, not the bridge alone. The
supervisor tracks both processes, cleans up on failure, and keeps the
writable state under `state/hil_bridge_supervisor.json` and
`state/hil_bridge_card_relay.json` up to date.

## Signals to watch

Healthy state looks like:

- `status: running` and `usbPresent: true` in supervisor state
- non-zero `bridgePid`
- `status: ok`, `apduUrl`, `statusUrl`, `modemRefreshUrl`, selected `reader`,
  and an `atr` in relay state

Any of the following means the stack is not fully armed:

- supervisor `usbPresent: false` means the SIMtrace2 is not enumerated
- relay `status` other than `ok` means the bridge is not serving traffic
- missing `atr` means the card is not currently powered or inserted

## Use cases

- observe a live modem talking to a real eUICC while an SM-DP+ negotiation
  happens in an operator shell
- capture an authenticated SCP03 session end-to-end
- reproduce a field failure with the exact card and exact modem in front of
  you, without losing administrative access to the card
- run a HIL capture that includes both the modem side and the YggdraSIM side
  in one Wireshark trace

## Where to look in YggdraSIM

- [HIL Bridge](../subsystems/hil-bridge.md) for the operator surface
- [Run a HIL Capture](../how-to/run-hil-capture.md) for a recipe-style
  walkthrough
- `guides/HIL_BRIDGE_GUIDE.md` for the full authored procedure
