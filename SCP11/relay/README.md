<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 Relay Compatibility Namespace

`SCP11/relay` preserves the historical relay namespace. It is still runnable,
but it is no longer the preferred place to start new operator documentation or
new day-to-day workflows.

## Use this namespace when

- an older script imports `SCP11.relay`
- an automation contract still expects the legacy relay entrypoint
- a transition needs the old namespace while the operator model is being
  migrated to the split `live` / `test` layout

## Preferred relay entry points

For new operator work, use:

- `SCP11/live` for live-default relay work
- `SCP11/test` for lab/test relay work
- `SCP11/relay` only when an older script still depends on the compatibility namespace

## Relay command model

The compatibility namespace follows the same broad relay shape:

- relay utilities and snapshot inspection
- `LPAd` activation-code download
- `IPAd` discovery and eIM-driven download
- compatibility and expert commands behind `HELP EXPERT`

Simulator note:

- when the shared card backend is set to `sim`, the simulated card's default BF55 eIM identity comes from `Workspace/SIMCARD/eim_identity.json`
- `Workspace/LocalEIM/eim_identity.json` remains the Local eIM shell identity and is configured separately

## Documentation rule

Point users to these guides unless the namespace itself is the topic:

- `SCP11/README.md`
- `SCP11/live/README.md`
- `SCP11/test/README.md`
- `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

Keep this file short and compatibility-focused. Do not duplicate the primary
relay operator guides here.
