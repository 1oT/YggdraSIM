---
title: Testing Guide
tags:
  - internals
  - testing
  - pytest
---

# Testing Guide

YggdraSIM uses pytest and has strict operator rules around how the suite is
invoked. This page documents the layout, the scoping conventions, and the
no-mass-run policy that keeps test runs predictable.

## Layout

All tests live under the repository `tests/` directory. Each test file maps
to a subsystem or a cross-cutting concern. Representative file patterns:

| Pattern | Covers |
| --- | --- |
| `tests/test_scp03_*.py` | SCP03 shell and logic |
| `tests/test_scp11_*.py` | SCP11 family shells and helpers |
| `tests/test_scp11_eim_*.py` | SCP11 eIM-local shell and logic |
| `tests/test_scp11_local_access*.py` | SCP11 local-access shell |
| `tests/test_scp11_live_*.py` | SCP11 live relay |
| `tests/test_scp11_test_*.py` | SCP11 test relay |
| `tests/test_simcard_*.py` | SIMCARD simulator backend |
| `tests/test_saip_*.py` | SAIP profile package codecs and tooling |
| `tests/test_profile_package_*.py` | Profile Package shell / saip tool |
| `tests/test_hil_bridge_*.py` | HIL bridge, runtime, and protocol |
| `tests/test_polling_plugin_*.py` | plugin runtime behavior |
| `tests/test_apdu_fuzzer*.py` | APDU mutation fuzzer (allow-list, mutators, transports) |
| `tests/test_eum_diag*.py` | EUM / SM-DP+ session-key diagnostics + Lua dissector |
| `tests/test_yggdracore_*.py` *(post-v1 staging)* | YggdraCore AUSF / AAnF stubs, FastAPI loopback, Open5GS bridge |
| `tests/test_yggdrasim_common_*.py` | shared helpers |

## Scoping conventions

- Tests must be runnable in isolation. A single-node pytest invocation must
  produce a correct result.
- Tests should avoid module-level side effects. Fixtures own setup and
  teardown.
- Tests that touch PC/SC or HIL hardware must be clearly gated so they do
  not run unless the hardware is present.
- Tests that require plugin runtime behavior should drop a temporary plugin
  through fixtures, not mutate the repository `plugins/` tree.

## Running a single test

Respect the repository's memory-safety rule. Target narrowly.

```bash
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_scp11_local_access.py
```

For a single node:

```bash
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_scp11_local_access.py::test_load_profile_happy_path
```

## Redirecting output

Noisy tests or captured-output tests should be redirected to a log file,
with the log overwritten on each run:

```bash
python -m pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    tests/test_saip_transcode_tui.py > .pytest_last_run.log 2>&1
```

Read the log using `rg FAILED .pytest_last_run.log` or a tail-offset read.
Do not paste the full log into commit messages or issue threads.

## Shell-level timeout cap

Every pytest invocation is expected to complete within 90 seconds of wall
time. The cap keeps local and CI runs predictable and prevents a single
slow test from holding the queue. If a test genuinely needs more than 90 s:

1. Narrow the target first — a single test class or node id usually fits.
2. If it still does not fit, tag the offender with `@pytest.mark.slow`
   and note the flag in the test docstring.
3. Only ask to raise the cap explicitly, for a single named run. Do not
   silently override it.

`tests/test_saip_transcode_tui.py` is currently the one module-wide
`pytest.mark.slow` surface; invoke it with `--runslow` during release
validation.

## No mass runs

Repo-wide runs such as `pytest`, `python -m pytest`, `pytest tests`, or
`pytest .` are reserved for explicit user requests with a chunked plan. The
default is always the narrowest target possible.

## Writing a new test

When adding a new test:

1. Pick the closest existing filename and place the test there, or add a new
   `tests/test_<area>.py` that matches the patterns above.
2. Use plain functions and fixtures. Avoid class-based tests unless the
   fixture composition genuinely benefits.
3. Keep assertions specific. Prefer one clear assertion that fails with a
   meaningful message over a cascade of prints.
4. If you add a new fixture, keep it local to the file unless it is
   obviously useful for multiple files.
5. Never introduce a test that depends on real hardware without an
   explicit guard.

## What to test

- the public surface of a shell: `--cmd` outputs, verb parsing, error
  reporting
- codec round trips: SAIP JSON/DER, ASN.1 builders, TLV helpers
- registry resolution against stable keys
- plugin runtime absence and failure paths
- state persistence and migration behavior
- HIL protocol framing where the hardware is emulated

## Related pages

- [Coding Standards](coding-standards.md)
- [Release Checklist](release-checklist.md)
- `tests/` under the repository root
