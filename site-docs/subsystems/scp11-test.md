---
title: SCP11 Test Compatibility Namespace
tags:
  - subsystems
  - scp11
  - test
  - compatibility
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SCP11 Test Compatibility Namespace

`SCP11/test/` is a compatibility namespace for older imports. It imports the
same relay implementation as `SCP11/live`, but it is no longer exposed as a
separate operator entrypoint.

!!! info "Underlying concept"
    The relay model is documented once in
    [RSP Architecture](../concepts/rsp-architecture.md). This page focuses on
    the single eSIM management relay surface.

## When to use it

- compatibility with older `SCP11.test.*` imports
- reviewing where the old test namespace maps into the unified relay
- locating request/result-shaping knobs that now live in `SCP11/live/config.py`

## Entry points

No standalone launch surface is provided. Use `python -m SCP11.live` or
`yggdrasim-scp11-live` for relay operation.

## Compatibility Behavior

The shared relay config includes:

- request variant selection (for example, forcing a specific GSMA request
  shape that some test SM-DP+ builds require)
- no-package clear-ack behavior control
- synthetic error / result shaping, used to emulate specific negative paths
- REST path overrides for unusual test environments

The relay entrypoints do not select a test CA bundle implicitly. Use
`SET-ES9-CA` or `ES9_CA_BUNDLE_PATH` only when an endpoint requires an
explicit CA bundle.

## Runtime dependencies

- optional local extensions under the runtime root
- the shared SQLite inventory for per-EID state

## State

The compatibility namespace uses the same state schema as
[SCP11 eSIM Management](scp11-live.md).

## Common recipes

### Probe a test SM-DP+

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; ES9-CERT-INFO; EXIT"
```

### Force a specific request variant

The request-variant, clear-ack, and REST-path knobs are in `config.py`. Set
them there or via the shell's config verbs, then execute the flow.

### Use the eSIM management command surface

Every relay command is listed on [SCP11 eSIM Management](scp11-live.md).

## Pitfalls

- Synthetic error / shaping controls are meant to be reverted after a test
  run. Leaving them on leaks into the next relay session.

## Related pages

- [SCP11 eSIM Management Relay](scp11-live.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- [CLI Matrix](../reference/cli-matrix.md)
