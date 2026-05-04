# SCP11 Shared Helper Layer

`SCP11/shared` is the common helper layer for the split `SCP11` codebase. It is
not intended to be the primary operator surface. Its job is to keep the shared
runtime pieces in one place while the live, test, relay-compatibility, local,
and eIM-local modules expose the user-facing commands.

For operator-facing module selection, start with `SCP11/README.md`.

Automation references:

- `../../guides/CLI_AND_PIPING_GUIDE.md`
- `../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`

## Primary consumers

- `SCP11/live`
- `SCP11/test`
- `SCP11/relay`
- `SCP11/local_access`
- `SCP11/eim_local`

## Shared scope

- ASN.1 registries
- SCP11 crypto helpers
- payload builders
- pySim-backed encode and decode helpers
- transport abstractions
- shared GSMA-oriented error-code helpers
- shared discovery snapshot rendering
  - `discovery_snapshot.render_consolidated_discovery_snapshot` -- full
    SGP.32 consolidated dump (the `DISCOVER` command output)
  - `discovery_snapshot.render_card_overview_snapshot` -- quick header
    card (the `SCAN` / `INFO` command output, harmonised across all
    four SCP11 shells)
- shared profile lifecycle helpers
  - `profile_actions.run_enable_profile` -- auto-disable the active
    profile (with PPR1 guard) before enabling the target
  - `profile_actions.run_disable_profile` -- short-circuit when the
    target is already disabled
  - `profile_actions.run_delete_profile` -- auto-disable an enabled
    target before deleting it (SGP.22 §5.7.18)

## Command harmonisation contract

`profile_actions` is the single source of truth for the
`ENABLE-PROFILE` / `DISABLE-PROFILE` / `DELETE-PROFILE` semantics
exposed by the live, test, local-access, and eim-local shells. Each
shell wires a `ProfileActionAdapter` to its session-level callbacks and
calls into the helpers -- there is no per-shell branch for the
auto-disable contract or the PPR1 guard. The `INFO` alias on every
shell now resolves to `SCAN`, which renders the same header card as
eSIM Live's start-up snapshot via `render_card_overview_snapshot`.

## Design note

This package exists so the `SCP11` family can share one technical core while
still exposing separate operator models for:

- relay-oriented flows
- direct local `ISD-R` flows
- eIM-local package and handover work

When a capability belongs to more than one `SCP11` flavor, it should generally
live here instead of being duplicated in the individual operator packages.
