---
title: FAQ
tags:
  - reference
  - faq
---

# FAQ

## Which shell should I use for what?

Use the [Operator Surfaces](../operator-surfaces.md) table as the first
filter, then the [Subsystems](../subsystems/index.md) overview for a picture
view with links into the deep dives.

## Is `SCP03` a relay shell?

No. `SCP03/` is the card-administration and retrieval shell. Relay work
lives in `SCP11/live` and `SCP11/test`. Direct local ISD-R work lives in
`SCP11/local_access`. eIM-side SGP.32 work lives in `SCP11/eim_local`.

## What is the difference between `SCP11/live` and `SCP11/test`?

Same operator model. The intended drift is certificate trust, endpoint
defaults, and lab-only request/result shaping. See
[SCP11 Test Relay](../subsystems/scp11-test.md).

## What does `Workspace/LocalEIM/eim_identity.json` do and why is it separate from `Workspace/SIMCARD/eim_identity.json`?

The Local eIM identity describes the eIM/SM-DP+ endpoint side of the
`SCP11/eim_local` shell. The simulator-side file describes what a simulated
card advertises in BF55. They are on opposite sides of the same eIM
transaction. Keeping them separate lets you run compatibility tests where
one side is deliberately wrong. See
[SCP11 eIM Local](../subsystems/scp11-eim-local.md).

## Where is my runtime state stored?

In source runs, under the repository `state/` directory. In frozen builds,
under `YggdraSIM-data/` next to the executable, or `~/YggdraSIM-data/` as
fallback. `YGGDRASIM_RUNTIME_ROOT` wins over both. See
[Runtime Root](runtime-root.md).

## How do I reset a subsystem's state?

Per-card state is keyed by identity. Delete the row, or wipe the identity
bucket through the shell's reset verb where one exists. Module-level state
is reimported from legacy sources on next launch if they exist.

## Is encryption on by default?

No. `state/inventory_crypto.json` ships with `enabled: false` to keep
onboarding simple. Labs with real card material should enable it; see
[Enable Inventory Encryption](../how-to/enable-inventory-encryption.md).

## Can I run card flows inside Docker?

Analysis and simulator flows, yes. Real PC/SC and HIL work is host-specific;
run the launcher directly on the host. See
[Run in Docker](../how-to/run-in-docker.md).

## Do I have to use the unified launcher?

No. `python -m <module>` works after the editable install, and so do the
installed console scripts. The unified launcher is convenient for browsing
surfaces interactively.

## Where do plugins go?

Under the active runtime root's `plugins/` directory. On source runs that
is the repository `plugins/`. On frozen builds it is the writable runtime
root. See [Write a Plugin](../how-to/write-a-plugin.md).

## What if I do not want to build the docs locally?

You do not have to. The deep source material lives under the repository
`guides/` and `docs/` trees. The MkDocs site is a curated entry point. The
repository remains fully navigable without it.

## How do I find the command I want?

Every shell has a `HELP` verb and a `GUIDE` topic menu. For a cross-shell
cheatsheet, see the [CLI Matrix](cli-matrix.md).

## Related pages

- [Glossary](glossary.md)
- [Troubleshooting](troubleshooting.md)
- [Documentation Map](../documentation-map.md)
