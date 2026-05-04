---
title: Subsystems
tags:
  - subsystems
---

# Subsystems

Subsystem pages are the operator-facing deep dives. Each page covers:

- what the shell is for, phrased as when to use it and when not to
- command surface, grouped
- prerequisites and runtime dependencies
- state the subsystem writes
- common recipes
- known pitfalls
- pointers to the concepts page that backs the work

## Pick a surface

<div class="grid cards" markdown>

-   :material-card-account-details: __SCP03 Admin Shell__

    ---

    GlobalPlatform administration, ETSI filesystem, retrieval, and report/export.

    [Open SCP03](scp03.md)

-   :material-antenna: __SCP80 OTA Shell__

    ---

    Secured packet build, send, decode, RFM / RAM payload work, ICCID-bound state.

    [Open SCP80](scp80.md)

-   :material-sim: __SCP11 Live Relay__

    ---

    Production-like relay shell for LPAd, IPAd, and optional plugin-backed IPAe.

    [Open Live](scp11-live.md)

-   :material-flask-outline: __SCP11 Test Relay__

    ---

    Live-shaped relay with test-default trust and lab-only request shaping.

    [Open Test](scp11-test.md)

-   :material-lan-connect: __SCP11 Local Access__

    ---

    Direct local ISD-R shell. One-shot auth, metadata, profile state control.

    [Open Local Access](scp11-local-access.md)

-   :material-chip: __SCP11 eIM Local__

    ---

    SGP.32 eIM-local package authoring, hotfolders, poll campaigns, handover.

    [Open eIM Local](scp11-eim-local.md)

-   :material-package-variant-closed: __Profile Package__

    ---

    SAIP shell, lint engine, JSON to DER transcode, transcode TUI.

    [Open Profile Package](profile-package.md)

-   :material-bridge: __HIL Bridge__

    ---

    SIMtrace2-backed physical-card bridge and supervisor workflow.

    [Open HIL Bridge](hil-bridge.md)

-   :material-key-outline: __SUCI Tool__

    ---

    SUCI key generation, key selection, and public-key export.

    [Open SUCI](suci-tool.md)

-   :material-devices: __SIMCARD Simulator__

    ---

    Simulator backend, eUICC store, profile store, and card-side BF55 identity.

    [Open SIMCARD](simcard-simulator.md)

-   :material-bomb: __APDU Mutation Fuzzer__

    ---

    Opt-in, safety-gated fuzzing harness for eUICC vulnerability research.

    [Open APDU Fuzzer](apdu-fuzzer.md)

-   :material-shield-key-outline: __EUM Diagnostics__

    ---

    Session-key injection and Wireshark/tshark Lua dissector for BF36 BPP traffic.

    [Open EUM Diagnostics](eum-diagnostics.md)

</div>

## Subsystem to concept map

| Subsystem | Primary concept page |
| --- | --- |
| SCP03 | [GlobalPlatform](../concepts/globalplatform.md), [ETSI UICC](../concepts/etsi-uicc.md) |
| SCP80 | [SCP80 OTA](../concepts/ota-scp80.md) |
| SCP11 Live / Test | [RSP Architecture](../concepts/rsp-architecture.md) |
| SCP11 Local Access | [RSP Architecture](../concepts/rsp-architecture.md) |
| SCP11 eIM Local | [RSP Architecture](../concepts/rsp-architecture.md) |
| Profile Package | [SAIP Profiles](../concepts/saip-profiles.md) |
| HIL Bridge | [HIL Model](../concepts/hil-model.md) |
| SIMCARD Simulator | [Secure Element Primer](../concepts/secure-element-primer.md) |
| SUCI Tool | [3GPP NAA](../concepts/3gpp-naa.md) |
| APDU Mutation Fuzzer | [Secure Element Primer](../concepts/secure-element-primer.md) |
| EUM Diagnostics | [RSP Architecture](../concepts/rsp-architecture.md), [SAIP Profiles](../concepts/saip-profiles.md) |
