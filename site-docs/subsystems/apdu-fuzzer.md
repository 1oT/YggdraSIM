---
title: APDU Mutation Fuzzer
tags:
  - subsystems
  - fuzzing
  - security-research
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# APDU Mutation Fuzzer

`Tools/ApduFuzz/` is an opt-in, safety-gated fuzzing harness for
eUICC vulnerability research. It mutates APDUs from a known-good
corpus and transmits them at a selected transport, halts on
crash-class responses or transport errors, and dumps forensic
records per crash.

!!! danger "Operator responsibility"
    Only run this against cards you own and have explicitly
    allow-listed. The tooling refuses to start without an opt-in
    token **and** at least one `--allow-iccid` / `--allow-imsi`
    value. Crash dumps land in a `0o700` run directory under
    `--crash-dump-root`.

## When to use it

- researching mutation-triggered faults on a development eUICC
- regressing a historical bug against a freshly provisioned sample
- stressing a proprietary INS/CLA with deterministic mutations

## Entry points

=== "Console script"

    ```bash
    yggdrasim-apdu-fuzzer --help
    ```

=== "Module"

    ```bash
    python -m Tools.ApduFuzz
    ```

## Safety gate

All three conditions are required:

1. `--i-mean-it` passed on the command line.
2. At least one of `--allow-iccid <hex>` or `--allow-imsi <digits>`.
3. The probed card identity matches the allow-list exactly.

Additional knobs:

- `--max-apdus <N>` hard cap per run (default 10 000).
- `--crash-dump-root <path>` override the default dump location.
- `--seed <int>` deterministic mutation RNG seed.
- `--mutator <name>` restrict to specific mutators
  (`bit-flip`, `length-mangle`, `zero-Lc`, `tag-shuffle`,
  `padding-bloat`).

## Corpus

Corpora are JSON files — typically simulator session recordings.
Three shapes are accepted:

- the full recorder dump (`{"session_id": "...", "events": [...]}`)
- a bare list of dicts `[{"command_hex": "...", "response_hex": "..."}, ...]`
- a bare list of hex strings `["00A40400...", ...]`

`filter_select_only` trims to `SELECT` APDUs for a warm-up probe.

## Transports

- `null` — synthetic transport that always returns `90 00`. CI and
  dry-runs only.
- `pcsc` — live PC/SC reader. Requires `pyscard`.

## Crash records

Each crash writes a JSON file in the per-run directory with:

- sequence index within the run
- mutation description
- original APDU, mutated APDU, response bytes
- status word
- optional free-form notes

The run directory also contains a manifest summarising the seed,
the safety-config hash, the corpus path, and the halt reason.

## Related references

- [Diagnostics Toolbox](../how-to/diagnostics-toolbox.md)
- `tests/test_apdu_fuzzer.py` for the reference behaviour contract
