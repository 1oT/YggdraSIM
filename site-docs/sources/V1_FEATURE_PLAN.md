# YggdraSIM v1 Feature Pass — Plan & Status

Four additive diagnostic / provisioning capabilities landed on top of
the post-audit stabilisation sweep. This document is the canonical
plan-and-delivery record. Each feature was scoped, implemented, tested
one file at a time (per the repo's pytest memory-safety rule), and
surfaced in the operator documentation before the next feature
started.

| Feature | Status |
| --- | --- |
| F4 — Visual SAIP Profile Diffing (TUI + shell) | Done |
| F2 — Direct Simulator-to-TUI Pipeline | Done |
| F3 — APDU Mutation Fuzzer (opt-in) | Done |
| F1 — EUM Diagnostics "God-Mode" (Lua dissector) | Done |
| Documentation sweep | Done |
| Regression pass | Done |

---

## F4. Visual SAIP Profile Diffing (TUI + shell)

Goal — a Harald-Welte-style side-by-side view of two SAIP profiles
(DER, simulator manifest, or transcode JSON) with jq-style paths and
stable change markers.

Plan:

1. Write a pure-function diff engine over jsonified SAIP documents;
   determinise ordering; fold top-level SAIP section reorders into a
   single `moved` entry.
2. Write a unified loader that auto-detects the three supported
   shapes (transcode JSON, SIMCARD profile manifest, raw DER via
   optional pySim) and returns a normalised `LoadedDocument`.
3. Add a Textual side-by-side application with diff markers and
   navigation bindings.
4. Wire `DIFF <a> <b> [NO-VALUES]` and `DIFF-TUI <a> <b>` into the
   profile-package shell.
5. Write unit tests first; integrate second.

Delivered artefacts:

* `Tools/ProfilePackage/saip_diff_engine.py`
* `Tools/ProfilePackage/saip_diff_loader.py`
* `Tools/ProfilePackage/saip_diff_tui.py`
* `Tools/ProfilePackage/shell.py` — `DIFF` / `DIFF-TUI` commands
* `tests/test_saip_diff_engine.py` — 15 tests, green

Acceptance criteria (all met):

* Diff engine is deterministic under input permutation.
* Section-reorder detection collapses to a single entry.
* Loader accepts all three shapes with clear errors when pySim is
  absent for DER input.
* TUI navigates diff entries, toggles value rendering.
* Shell command emits ANSI-coloured output.

---

## F2. Direct Simulator-to-TUI Pipeline

Goal — whenever SIMCARD writes a new ICCID to the profile store
(typically after an SCP11 download), auto-launch a command — by
default the SAIP TUI against the new manifest.

Plan:

1. Add a profile-download hook surface to `SIMCARD/engine.py`:
   callback list, ICCID-delta detection inside `_sync_all_stores`,
   per-hook error isolation.
2. Build a polling watcher that periodically snapshots the store,
   computes deltas, and dispatches a templated command. Polling
   (not inotify) so macOS / Windows / WSL behave identically.
3. Register a `yggdrasim-profile-autoload` console script.
4. Wire a `WATCH-SIMCARD` command into the profile-package shell.
5. Cover engine-side and watcher-side behaviour with unit tests.

Delivered artefacts:

* `SIMCARD/engine.py` — `register_profile_download_hook`,
  `unregister_profile_download_hook`, ICCID-snapshot delta logic.
* `Tools/ProfilePackage/simcard_watch.py`
* `Tools/ProfilePackage/shell.py` — `WATCH-SIMCARD` command
* `yggdrasim_common/console_scripts.py` — `profile_autoload` entry
* `pyproject.toml` — `yggdrasim-profile-autoload` script
* `tests/test_simcard_engine_profile_hook.py` — 6 tests, green
* `tests/test_profile_package_simcard_watch.py` — 9 tests, green

Acceptance criteria (all met):

* Hook registration is symmetric; duplicate calls are idempotent.
* First sync after boot seeds the snapshot without firing.
* New ICCIDs fire exactly once; repeat polls are no-ops.
* One raising callback does not poison the others.
* Watcher exits cleanly after `MAX` arrivals or on KeyboardInterrupt.

Launcher template variables (single-brace, `str.format_map`
convention): `{iccid}`, `{profile}`, `{profile_path}`,
`{profile_dir}`, `{manifest}`, `{python}`. Unknown placeholders
log a warning and expand to an empty string; argv is split with
`shlex.split(..., posix=True)` so whitespace paths survive.

---

## F3. APDU Mutation Fuzzer (opt-in)

Goal — a hard-gated fuzzing harness for eUICC vulnerability research.
Mutate APDUs from a known-good corpus, transmit through a selected
transport, halt on crash-class responses or transport errors, dump
forensic records.

Plan:

1. Package scaffold: `Tools/ApduFuzz/{__init__,__main__,main}.py`.
2. Deterministic mutators: `bit-flip`, `length-mangle`, `zero-Lc`,
   `tag-shuffle`, `padding-bloat`. Single RNG seed per run.
3. Corpus loader for simulator session recordings — accept full
   recorder dumps, list-of-dicts, and list-of-hex-strings; add a
   `filter_select_only` helper for warm-up probes.
4. Safety gate — `--i-mean-it` opt-in token **and** at least one
   `--allow-iccid` / `--allow-imsi`. Probe the card identity on
   connect; mismatch aborts the run. Crash dumps under a
   timestamped `0o700` directory; crash records written `0o600`.
   Run manifest captures seed, corpus, halt reason.
5. Transport-agnostic runner (PC/SC and null transports). Halt on
   `6F 00`, `6E 00`, `6D 00`, or transport exception.
6. CLI with mutator selection, max-APDU cap, inter-command delay.
7. Register `yggdrasim-apdu-fuzzer` console script.
8. Full unit-test coverage for mutators, corpus, safety, runner —
   no live card required.

Delivered artefacts:

* `Tools/ApduFuzz/__init__.py`, `__main__.py`, `main.py`
* `Tools/ApduFuzz/mutators.py`
* `Tools/ApduFuzz/corpus.py`
* `Tools/ApduFuzz/safety.py`
* `Tools/ApduFuzz/runner.py`
* `yggdrasim_common/console_scripts.py` — `apdu_fuzzer` entry
* `pyproject.toml` — `yggdrasim-apdu-fuzzer` script
* `tests/test_apdu_fuzzer.py` — 23 tests, green

Acceptance criteria (all met):

* Fuzzer refuses to run without opt-in or without allow-list.
* Same seed + same corpus produce identical mutation sequences.
* Crashes terminate the run and are dumped with fidelity
  (sequence index, mutation description, original, mutated,
  response, SW).
* Null transport works in CI without `pyscard`.
* No `DeprecationWarning` under `pytest -W error::DeprecationWarning`
  (timezone-aware UTC helper).

---

## F1. EUM Diagnostics "God-Mode" (Wireshark/tshark Lua dissector)

Goal — operator-side toolbox for ES8+ / BPP post-mortems. Inject
ShS-ENC / ShS-MAC / DEK session material into a Wireshark/tshark
Lua dissector that annotates `BF36` TLVs, turning opaque captures
into analysable ones.

Plan:

1. Package scaffold: `Tools/EumDiag/{__init__,__main__,main}.py`.
2. `session_keys.py` — strongly-typed `SessionKeyBundle` (hex
   discipline, ICCID normalisation, constant-time comparison);
   `SessionKeyRepository` with duplicate-ICCID rejection and
   JSON round-trip; atomic writer at `0o600` on POSIX.
3. `dissector.lua` — Wireshark post-dissector with a minimal
   pure-Lua JSON parser (no external deps), graceful degradation
   when the key repo is missing / malformed / unmatched ICCID.
   Reads repo path from `YGGDRASIM_EUM_SESSION_KEYS`.
4. `tshark_runner.py` — builder for `tshark -X lua_script:...`,
   env injection, `ensure_tshark_on_path`, `run_tshark`.
5. CLI `main.py` with subcommands:
   * `inject-keys` — write repo **and** launch tshark.
   * `store-keys` — write repo only.
   * `decode-bpp` — offline BPP decode via optional pySim.
6. Ship `dissector.lua` as package-data so wheel installs can
   locate it via `importlib.resources`.
7. Register `yggdrasim-eum-diag` console script.
8. Unit tests — patch tshark out; never require the binary.

Delivered artefacts:

* `Tools/EumDiag/__init__.py`, `__main__.py`, `main.py`
* `Tools/EumDiag/session_keys.py`
* `Tools/EumDiag/dissector.lua`
* `Tools/EumDiag/tshark_runner.py`
* `yggdrasim_common/console_scripts.py` — `eum_diag` entry
* `pyproject.toml` — `yggdrasim-eum-diag` script +
  `Tools.EumDiag = ["dissector.lua"]` package-data
* `tests/test_eum_diag.py` — 18 tests, green

Acceptance criteria (all met):

* Hex length / content validation on all key fields.
* ICCID normalisation (uppercase, trimmed).
* Constant-time secret comparison via `hmac.compare_digest`.
* Atomic repo write is `0o600` on POSIX.
* Repo round-trips `to_json_dict` / `from_json_dict`.
* Argv assembly puts `tshark -X lua_script:<path> -r <pcap>` in
  the correct order and injects `YGGDRASIM_EUM_SESSION_KEYS` into
  the environment.
* Missing tshark is a clear, typed error (`TsharkMissingError`).
* CLI refusal paths return distinct non-zero exit codes:
  * `2` — incomplete or invalid key inputs.
  * `3` — pcap missing for `inject-keys`.
  * `4` — `tshark` binary missing on PATH.

---

## Shared infrastructure changes

Both additions are wholly additive; no existing public surface
changed shape.

* `yggdrasim_common/console_scripts.py` — three new entry points:
  `profile_autoload`, `apdu_fuzzer`, `eum_diag`.
* `pyproject.toml`:
  * `[project.scripts]` — `yggdrasim-profile-autoload`,
    `yggdrasim-apdu-fuzzer`, `yggdrasim-eum-diag`.
  * `[tool.setuptools.package-data]` — `Tools.EumDiag = ["dissector.lua"]`.

---

## Documentation sweep

All operator-facing surfaces updated:

* `README.md` — new capability bullets + full console-scripts list.
* `V1_RELEASE_AUDIT.md` — "v1 Pre-Release Feature Pass" section
  covering F1–F4 with module, test, and integration notes.
* `guides/CAPABILITIES.md` — `Tools/ApduFuzz/` and `Tools/EumDiag/`
  rows.
* `guides/CLI_AND_PIPING_GUIDE.md` — four new rows in the module
  matrix.
* `guides/README.md` + new `guides/DIAGNOSTICS_TOOLBOX.md` — full
  operator walk-through of all four features.
* `site-docs/subsystems/apdu-fuzzer.md` — new.
* `site-docs/subsystems/eum-diagnostics.md` — new.
* `site-docs/subsystems/profile-package.md` — diff / watcher
  command additions.
* `site-docs/subsystems/index.md` — two new cards + concept-map rows.
* `site-docs/how-to/diagnostics-toolbox.md` — new.
* `mkdocs.yml` — nav additions; `mkdocs build --strict` is green.

---

## Regression coverage

Targeted pytest runs, one file at a time per repo policy
(`-q --tb=short --disable-warnings --no-header --maxfail=1`):

| Test file | Result |
| --- | --- |
| `tests/test_saip_diff_engine.py` | 15 passed |
| `tests/test_profile_package_simcard_watch.py` | 9 passed |
| `tests/test_simcard_engine_profile_hook.py` | 6 passed |
| `tests/test_apdu_fuzzer.py` | 23 passed |
| `tests/test_eum_diag.py` | 18 passed |
| `tests/test_console_scripts_guard.py` | 5 passed |
| `tests/test_about_version.py` | 3 passed |
| `tests/test_profile_package_shell.py` | 62 skipped (pySim optional — expected) |

Smoke checks:

* `from Tools.ProfilePackage.shell import ProfilePackageShell` —
  confirms `_cmd_diff`, `_cmd_diff_tui`, `_cmd_watch_simcard` are
  registered.
* `python -m Tools.EumDiag --help` — prints subcommand usage.
* `python -m Tools.ApduFuzz --help` — prints safety-gate flags.
* `from yggdrasim_common.console_scripts import profile_autoload,
  apdu_fuzzer, eum_diag` — all three resolve.
* `mkdocs build --strict` — builds successfully with the new pages.

---

## Summary

Four independent operator capabilities are now first-class in the
tree:

1. SAIP diffing — shell and TUI.
2. Simulator → TUI auto-open.
3. APDU fuzzer — hard-gated, allow-listed, deterministic.
4. EUM diagnostics — Lua dissector + CLI.

Each has its own console script, its own tests, and documents its
operator-visible failure modes in help output. Nothing in the
existing runtime changes behaviour unless the new command is
explicitly called.

---

## Post-landing 5 × 5 audit cycle

After the initial landing, a second 5-pass-per-area sweep (F4, F2,
F3, F1, and shared infrastructure — 25 passes total) produced the
following actionable findings. All were implemented in the same
commit as the sweep notes:

### F2 — Direct Simulator-to-TUI Pipeline

* **Custom launcher was whitespace-broken.** `_custom_factory` used
  `expanded.split()` which shatters a profile path containing
  spaces. Replaced with `shlex.split(..., posix=True)` via a new
  `_expand_launcher_template` helper.
* **Documented placeholder set was aspirational.** Docs advertised
  `{{iccid}}`, `{{profile}}`, `{{profile_dir}}`, `{{manifest}}`,
  `{{python}}`; code only honoured `{iccid}` and `{profile_path}`.
  Code now supports `{iccid}`, `{profile}`, `{profile_path}`,
  `{profile_dir}`, `{manifest}`, `{python}`; docs and shell HELP
  text rewritten to the single-brace Python-format convention.
* **Unknown placeholders no longer crash the watcher.** A
  `format_map` subclass logs a warning and substitutes an empty
  string so an operator typo does not kill the loop.
* **Filesystem scans are watch-safe.** `poll_once` now wraps the
  store scan in an `OSError` handler, and `run_forever` guards the
  whole poll body so a transient `PermissionError` on a stray
  profile child does not take the watcher down.
* **Default launcher is now operator-useful.** The previous default
  invoked `saip-diff-tui <profile> <profile> --text`, which always
  reported "no differences". The default now runs
  `python -m Tools.ProfilePackage --cmd "USE <profile>; INFO;
  TREE; EXIT"` so the operator sees the metadata and PE tree of the
  fresh profile immediately.

### F3 — APDU Mutation Fuzzer

* **Crash-dump tree is now operator-private.** `create_run_dir`
  chmods the run directory `0o700`; `dump_crash` and
  `dump_run_manifest` chmod the JSON records `0o600`. A new
  `_chmod_best_effort` helper no-ops on Windows. Matches the
  documented policy and the plan ("`0o700` / `0o600`").
* **Crash-SW documentation corrected.** `V1_RELEASE_AUDIT.md`
  claimed the runner halts on `6F00`/`6E00`/`6D00`; the code has
  always treated only `6F00`/`6F01`/`6FFF` as crashes (`6E00` and
  `6D00` are normal CLA/INS rejections when fuzzing). Doc updated
  with the correct set and rationale.
* Crash-dump filename sanitiser now escapes `\` and `:` in addition
  to `/` and space, so Windows-hostile mutation descriptions do
  not produce unwritable filenames.

### F1 — EUM Diagnostics "God-Mode"

* **`load_repository` now warns on loose permissions.** If the
  session-keys JSON is group- or world-readable on POSIX the
  loader emits a structured warning before parsing. AES-128
  session secrets living on a shared host is exactly the kind of
  operational blunder we want to surface.
* **Bundle format tag aligned across code and docs.**
  `BUNDLE_FILE_FORMAT` is `"yggdrasim-eum-session-keys/v1"`; docs
  that previously referenced `"yggdrasim.eum_diag/v1"` were
  updated (`guides/DIAGNOSTICS_TOOLBOX.md`,
  `site-docs/subsystems/eum-diagnostics.md`).

### F4 — Visual SAIP Profile Diffing

* No behaviour bugs surfaced. The five passes confirmed:
  determinism (stable `(path, op)` sort), TypeError on non-dict
  inputs, tolerant list/tuple equality, loader fallback to DER
  for JSON-that-is-not-a-profile, shell output colour bucketing
  on the leading tag character.

### Shared infrastructure

* No changes required. Console-script registration, package-data
  inclusion of `dissector.lua`, and `mkdocs build --strict` all
  remained green across the cycle.

### Regression after the sweep

All relevant targets pass (single-file runs, per repo policy):

| Test file | Result |
| --- | --- |
| `tests/test_saip_diff_engine.py` | 15 passed |
| `tests/test_profile_package_simcard_watch.py` | 13 passed (adds launcher-expansion + resilience cases) |
| `tests/test_simcard_engine_profile_hook.py` | 6 passed |
| `tests/test_apdu_fuzzer.py` | 24 passed (adds run-dir / crash-file permission assertion) |
| `tests/test_eum_diag.py` | 19 passed (adds world-readable warning assertion) |
| `tests/test_console_scripts_guard.py` + `tests/test_about_version.py` | 8 passed |
| `tests/test_profile_package_shell.py` | 62 skipped (pySim optional — expected) |

Smoke checks:

* `python -m Tools.EumDiag --help` — OK.
* `python -m Tools.ApduFuzz --help` — OK.
* `python -m Tools.ProfilePackage.simcard_watch --help` — OK,
  now advertises the full placeholder set.
* `Tools.ProfilePackage.simcard_watch._build_default_tui_command`
  and `_expand_launcher_template` produce well-formed argv for
  both default and custom launcher paths.
