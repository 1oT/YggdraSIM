<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# YggdraSIM marketing demo scripts

Two short, self-contained scripts intended to drive 30-60 s screen-recordings.
Each one boots a real `SimulatedSimCardEngine` (no PCSC, no mocks) inside a
throwaway temp directory, drives a deliberate scenario, and narrates each step
with ANSI-coloured banners.

| Script | Scenario | Key surfaces exercised |
| --- | --- | --- |
| `demo_3gpp_attach.py` | 3GPP cold-attach + USIM-AKA Milenage authentication. | SELECT MF, SELECT ADF.USIM, GET CHALLENGE, AUTHENTICATE P2=0x81, RES/CK/IK/Kc extraction, AUTS resync against a stale SQN. |
| `demo_profile_lifecycle.py` | SGP.32 profile-state machine over the ISD-R surface. | BF20 GetEuiccInfo1, BF2E GetEuiccChallenge, BF2D GetProfilesInfo, BF31/BF32 enable+disable, BF2B notification drain, BF35 LoadCRL. |

## Running

```bash
python3 scripts/demos/demo_3gpp_attach.py
python3 scripts/demos/demo_profile_lifecycle.py
```

### Environment overrides

| Variable | Effect |
| --- | --- |
| `NO_COLOR=1` | Disable ANSI colour output (useful for clean terminal recordings). |
| `YGGDRASIM_DEMO_FAST=1` | Skip the small `time.sleep` pauses between steps so a CI/smoke run finishes in <1 s. |

## Recording tips

* Use a 100×30 or 120×34 terminal for a clean 16:9 capture.
* Leave `YGGDRASIM_DEMO_FAST` unset for live recordings — the built-in pauses
  are tuned to give viewers time to read each banner.
* Each script writes to a fresh `/tmp/yggdrasim_*_demo_*` directory; nothing
  in the repo is mutated, so multiple takes are safe.
