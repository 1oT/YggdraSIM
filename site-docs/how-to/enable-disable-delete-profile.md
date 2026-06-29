---
title: Enable, Disable, Delete a Profile
tags:
  - how-to
  - scp11
  - lifecycle
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Enable, Disable, Delete a Profile

## Goal

Transition a profile between `DISABLED`, `ENABLED`, and `ERASED` states, and
make sure notifications reach SM-DP+ when required.

## Prerequisites

- a physical or simulated eUICC with at least one installed profile
- either `SCP11/local_access` (for direct ES10c) or `SCP11/live` (for
  relay-aware handling with notification reconciliation)
- if relay-aware, the SM-DP+ endpoint must be reachable

## Choose the right surface

| Goal | Surface |
| --- | --- |
| State change only, no notification reconciliation needed | `SCP11/local_access` |
| State change plus automatic `HandleNotification` to SM-DP+ | `SCP11/live` |
| Bulk lifecycle orchestration in SGP.32 | `SCP11/eim_local` |

## Local-access path

```text
[Local SMDPP] > DISCOVER
[Local SMDPP] > ENABLE-PROFILE
[Local SMDPP] > STATUS
[Local SMDPP] > DISABLE-PROFILE
[Local SMDPP] > DELETE-PROFILE
```

Each command opens its own local SCP11 session. If you need to pick which
profile to act on, set the selection beforehand with `PROFILE` or with the
card-aware wizard built into the shell.

## Relay path with notification hygiene

```bash
python -m SCP11.live --cmd "ENABLE-PROFILE; STATUS; EXIT"
```

The live shell pulls notifications from the card after the state change and
forwards them via `HandleNotification`, then cleans them off the card. This
is important when SM-DP+ tracks lifecycle via notifications.

## Validation

After each transition:

```bash
python -m SCP11.local_access --cmd "DISCOVER; STATUS; EXIT"
```

Confirm the expected state is reflected in the listing and that no
notifications are left on the card.

## Common failures

| Symptom | Likely cause |
| --- | --- |
| `Policy rule refused enable` | PPR on the active profile rejects the transition. Disable the blocking profile first. |
| `No profile selected` | the shell cannot infer which profile you mean. Pick explicitly. |
| `Notification left on card` | `HandleNotification` failed. Re-run the `live` shell; it reconciles automatically. |
| Unexpected `DISABLED` state | a prior `ENABLE-PROFILE` rolled back mid-transaction because a policy rule fired. Check the response log. |

## Related pages

- [SCP11 Local Access](../subsystems/scp11-local-access.md)
- [SCP11 Live Relay](../subsystems/scp11-live.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
