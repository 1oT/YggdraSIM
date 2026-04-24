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

## Design note

This package exists so the `SCP11` family can share one technical core while
still exposing separate operator models for:

- relay-oriented flows
- direct local `ISD-R` flows
- eIM-local package and handover work

When a capability belongs to more than one `SCP11` flavor, it should generally
live here instead of being duplicated in the individual operator packages.
