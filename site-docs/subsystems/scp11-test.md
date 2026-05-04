---
title: SCP11 Test Relay
tags:
  - subsystems
  - scp11
  - test
  - relay
---

# SCP11 Test Relay

`SCP11/test/` mirrors `SCP11/live/` in operator model but assumes
test-default certificate trust and adds lab-only request shaping. Use it when
the workflow is still relay-first, but the environment is a lab SM-DP+,
certificate-test harness, or validation fixture.

!!! info "Underlying concept"
    The relay model is documented once in
    [RSP Architecture](../concepts/rsp-architecture.md). This page focuses on
    what makes `test` different from `live`.

## When to use it

- relay work against SGP.26 test certificates
- relay work against a test SM-DP+ that emits pre-canned BPPs
- flow validation that requires synthetic errors or result shaping
- compatibility probes using request variant selection
- REST-path override experiments

## Entry points

=== "Module"

    ```bash
    python -m SCP11.test
    python -m SCP11.test --cmd "DISCOVER; STATUS; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-scp11-test
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP11 Test entry.

## Differences from Live

The command surface is deliberately shaped like `live`. The lab-only knobs
live in `SCP11/test/config.py` and include:

- test-default certificate and endpoint assumptions
- request variant selection (for example, forcing a specific GSMA request
  shape that some test SM-DP+ builds require)
- no-package clear-ack behavior control
- synthetic error / result shaping, used to emulate specific negative paths
- REST path overrides for unusual test environments

The intended drift between `live` and `test` is **trust and shaping**, not
operator model. If the workflow itself is different, switch subsystems
instead of switching flavors.

## Runtime dependencies

- SGP.26-style test CI material on the card or on the relay side
- optional `polling` plugin for the `POLL` verb
- the shared SQLite inventory for per-EID state

## State the shell writes

Same schema as [SCP11 Live](scp11-live.md). Per-EID entries are kept
separate from `live` when the runtime detects different trust anchors.

## Common recipes

### Probe a test SM-DP+

```bash
python -m SCP11.test --cmd "DISCOVER; STATUS; ES9-CERT-INFO; EXIT"
```

### Force a specific request variant

The request-variant, clear-ack, and REST-path knobs are in `config.py`. Set
them there or via the shell's config verbs, then execute the flow.

### Reuse live command muscle memory

Every command listed on [SCP11 Live](scp11-live.md) works the same way here.

## Pitfalls

- Do not let a `test` session write to per-EID inventory entries that are
  meant for a production `live` session. The flavors are isolated at the
  runtime layer, but operator-supplied artifacts are not. Keep certificate
  bundles in the test-specific directories.
- Synthetic error / shaping controls are meant to be reverted after a test
  run. Leaving them on leaks into the next session.

## Related pages

- [SCP11 Live Relay](scp11-live.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- [CLI Matrix](../reference/cli-matrix.md)
