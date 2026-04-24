---
title: SIMCARD Simulator
tags:
  - subsystems
  - simulator
  - simcard
---

# SIMCARD Simulator

`SIMCARD/` is the simulator backend used when the operator shells run without
physical card hardware. It implements a card-side APDU surface, a filesystem,
a profile store, a toolkit engine, and an eUICC-style store. The card-facing
shells can target it in place of a PC/SC reader through the launcher's
`--card-backend sim` flag.

!!! info "Underlying concept"
    Start with [Secure Element Primer](../concepts/secure-element-primer.md)
    for the APDU and filesystem mental model this simulator implements.

## When to use it

- shell development without physical hardware available
- deterministic test fixtures for CI or local regression runs
- reproducing specific card-side BF55 eIM identity configurations
- exercising `LOAD-PROFILE` and related flows against a predictable eUICC
- exploring SAIP installation without risking a real card

## Entry points

The simulator is selected through the launcher:

```bash
python main/main.py --card-backend sim
python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json
```

Individual subsystem entries accept the same backend selection when launched
through the wrapper menu.

## What the simulator implements

- an APDU dispatcher that speaks ISO 7816-4 case 1-4 commands
- an ETSI-shaped filesystem covering MF, DFs, ADFs, and EFs
- a card-side GP registry and ISD-R interaction
- a profile store that tracks installed profiles and their lifecycle
- a toolkit surface for CAT-style proactive commands
- a BF55 eIM identity surface that mirrors what a real eUICC advertises

## Identity files

| Path | Role |
| --- | --- |
| `Workspace/SIMCARD/eim_identity.json` | simulator default BF55 eIM identity |
| `Workspace/SIMCARD/isdr_config.json` | full card-side eIM layout with `eim_entries` |
| `--sim-eim-identity <path>` | one-shot override of the default BF55 identity |

Changing a Local eIM shell identity does not rewrite the simulator's BF55
row. Keep the two sides aligned on purpose.

## State the simulator writes

The simulator persists its card-side state under the writable runtime root.
Per-simulator-instance artifacts include:

- profile store contents
- eUICC store contents (EID, certs, runtime markers)
- BF55 identity selection

## Common recipes

### Launch a live relay against the simulator

```bash
python main/main.py --card-backend sim
# ... in the launcher menu, pick SCP11 Live ...
```

### One-shot local-access load against the simulator

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
LOAD-PROFILE
EXIT
EOF
```

with the launcher started in simulator backend mode beforehand.

### Pin a specific card-side eIM identity for a run

```bash
python main/main.py \
    --card-backend sim \
    --sim-eim-identity Workspace/SIMCARD/eim_identity_lab_alpha.json
```

## Pitfalls

- The simulator is not a silicon-grade model. Timing, side-channel, and
  some edge-case error responses are deliberately idealized.
- Simulator state persists unless deliberately reset. Expect state from the
  last session unless the simulator backend is cleared.
- The `SIMCARD` backend is selected through `--card-backend sim` on the
  launcher. Individual subsystem entries do not independently negotiate
  simulator vs PC/SC.

## Related pages

- [Secure Element Primer](../concepts/secure-element-primer.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- [SCP11 Local Access](scp11-local-access.md)
- [SCP11 eIM Local](scp11-eim-local.md)
