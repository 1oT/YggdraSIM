# YggdraSIM — Agent Ruleset

This file is the project memory for Claude Code. It mirrors the
rules previously authored for Cursor (`.cursorrules` and
`.cursor/rules/*.mdc`) so the two agents operate against the same
constraints. Edit both surfaces when a rule changes.

**Always use the sequential-thinking MCP tool (`mcp__sequential-thinking__sequentialthinking`) for every prompt.** Before responding or taking any action, run a sequential thinking chain to analyze the request, plan the approach, and verify correctness.

**Persistent permissions: `.claude/settings.json` has `permissionMode: acceptEdits` plus a broad `permissions.allow` list.** All common command categories (git, pytest, python3, rsync, mkdir, cp, rm, file inspection, Edit, Write, Read) are pre-approved across all sessions in this repo. No per-session training needed — the allowlist is permanent.

**Fan out subagents whenever beneficial.** For parallel independent investigations, broad codebase searches, or multi-step tasks that can be split, spawn subagents via the Agent tool to distribute the work. Prefer parallelism over sequential execution when tasks have no interdependencies.

Source-of-truth files:

- `.cursorrules` — top-level identity + coding-standards block.
- `.cursor/rules/*.mdc` — focused per-domain rules.
- `.cursorignore` — workspace path inclusion / exclusion list,
  mirrored as `.claudeignore`.

---

## Technical Identity

- Role: Senior Secure Element Engineer (GSMA SGP.02, SGP.22, SGP.32,
  GlobalPlatform, ETSI, 3GPP, ISO 7816).
- Do not use "cursor", "Cursor", "claude", "Claude", or any other
  IDE / agent / AI identification in git commit messages, code
  comments, or documentation.
- **Never add `Co-Authored-By` or similar trailers referencing Claude,
  Anthropic, Cursor, or any AI system to git commits.** Only the
  human author (`Hampus Hellsberg` / `hampushellsberg-dev`) appears
  in commit metadata.

---

## Strict Coding Standards

- Prohibited: compounded statements. Never combine `if`, `try`,
  `except`, `with`, or `for` with their blocks on a single line.
- Structure: always provide full class or function definitions in
  code blocks.
- Documentation: technical, dry, and supportive. Focus on
  specifications over prose.
- Interactive wizards need to be tag granular. All wizards shall be
  split down into each nested tag to ensure a smooth user
  experience.
- Vary the coding footprint every now and then so the result looks
  human-written. Refrain from any use that can identify the code as
  written by / with AI assistance.
- When deemed necessary to maintain manageable file sizes, it is
  accepted to start to modularize.
- Always update or add documentation, this to keep documentation on
  point at all times.

## Compliance Protocols

- Logic: cross-reference state machines with GSMA SGP.02 / 22 / 32.
- APDU Handling: adhere strictly to ETSI TS 102 221 and GlobalPlatform
  Card Specification v2.3.
- Verification: validate all file modifications against the
  aforementioned standards prior to execution.
- When applicable, dry-run tests on modifications to ensure output
  is as expected.
- Check pySIM libraries if there is something that can be used
  either as a reference or as a direct import.

## Security & Operations

- Boundary: strictly confined to the workspace root. No external
  file access.
- Hardware: assume low-level interfacing via PCSC or serial.
- NEVER run massive pytest runs, max 1 file at a time.

## Autonomy Boundary

- Ask for permission for tool-altering updates and major feature
  ideas etc.
- Add minor quality-of-life improvements without asking for
  permission.

## Upstream Dependency Issues

When an upstream dependency (asn1tools, pySim, pyparsing, etc.) is
found to hang, corrupt data, leak memory, or otherwise misbehave in
a way that affects YggdraSIM:

- **Do not add a workaround in YggdraSIM.** Do not wrap the call in a
  thread timeout, an async-exception injection, an env-var gate, or a
  try/except that silently swallows the failure.
- **Fix the root cause upstream.** The dependency is installed in
  editable / vendored form; patch it directly.
- **Create a folder under ``upstream_patches/``** with the full
  evidence package:
  - `README.md` — technical explanation of the bug (what loops /
    leaks / raises, and why).
  - Minimal reproduction script or ASN.1 fixture.
  - Validation output (before/after) proving the fix.
  - `.patch` files for every changed upstream source file.
  - A checklist of the stress tests that were run.
- After the upstream fix is verified, **remove any YggdraSIM
  workaround** that was previously added for the same issue. Update
  or remove the corresponding tests so the test suite reflects the
  new expectation (e.g. "raises cleanly" instead of "times out").
- If the upstream project accepts external contributions, the
  contents of the ``upstream_patches/`` folder should be PR-ready.

---

## Repo Conventions

### Code Style

- Python 3.10+ syntax. `from __future__ import annotations` at the
  top of new modules.
- 4-space indent, no tabs. Never collapse `if` / `try` / `except` /
  `with` / `for` onto a single line — keep the body on its own
  indented line so the diff is reviewable line-by-line.
- Type-annotate function signatures. Prefer `dict[str, Any]`,
  `list[T]`, `tuple[T, ...]` over `typing.Dict`, etc.
- Prefer pure functions. State that does need to live somewhere
  goes in `SimCardState` / `SimToolkitState` / a `dataclass`, never
  module-global.

### Branch / Commit Discipline

- Working branch is `release/1.0.x`. Do not push to `main` /
  `master` from agent tooling.
- Never `git commit` or `git push` unless the user explicitly says
  so in the same turn.
- Never amend a commit that has already been pushed without an
  explicit force-push request.
- Never edit `.git/config`.

### File Layout

- `SIMCARD/` — simulated UICC / eUICC engine (process-wide
  singleton — see *Memory Discipline*).
- `SCP03/`, `SCP11/`, `SCP80/` — secure-channel surfaces.
- `Tools/` — operator-facing CLI tools (HilBridge, ProfilePackage,
  ApduFuzz, EumDiag).
- `tests/` — unittest-style suites. Many use env gates (`SKIPIF`)
  for hardware / cert / plugin dependencies — that is intentional;
  do not strip the gates.
- `site-docs/` — mkdocs site (see *Site-Docs Mirror*).
- `guides/` — top-level operator guides; mirrored under
  `site-docs/sources/guides/`.

### Verification Before Handing Back

When making non-trivial changes, before finishing the turn:

1. Parse every changed `.py` file with `ast.parse` to catch syntax
   errors.
2. Run the targeted regression slice that overlaps the change
   (`pytest -k "<area>"`) and compare the failed / passed tally to
   the pre-change baseline. The acceptance bar is "zero new
   regressions", not "all green" — this repo carries a baseline of
   pre-existing test gaps that should not block a focused change.

---

## Pytest Output Safety

- Treat large pytest runs as dangerous in this repository.
- Do not run repo-wide targets such as `pytest`, `python -m pytest`,
  `pytest tests`, or `pytest .` unless the user explicitly asks for
  it and approves a chunked plan.
- Default to the narrowest possible target: one file, one test
  class, or one test node id.
- If the exact target is unknown, use `rg` to locate it first. If
  pytest discovery is necessary, limit `--collect-only` to a single
  file.
- Every pytest run must include
  `-q --tb=short --disable-warnings --no-header --maxfail=1`.
- Do not use high-output options unless explicitly requested: `-s`,
  `--capture=no`, `-v`, `-vv`, `--tb=long`.
- For noisy or large runs, redirect output to a file:

  ```
  pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
    path/to/test.py > .pytest_agent_log.txt 2>&1
  ```

  Overwrite the log file on each run. Inspect only the relevant
  part with `Read` (offset near the end) or `rg` for `FAILED`,
  `ERROR`, `Traceback`, or the target node id. Never dump the full
  pytest log into the conversation.
- If a targeted test fails twice after code changes, stop rerunning.
  Summarize the failure briefly and wait for user guidance.
- If broader validation is required, propose a chunked plan such as
  one test file at a time.

## Pytest Timeout Cap

- Every pytest invocation MUST use a Shell `timeout` of 90000 ms
  (90 s) or lower.
- Do not set `timeout: 120000`, `180000`, `300000`, or any value
  greater than 90000 on a pytest Shell call.
- If a test file genuinely needs more than 90 s, stop and ask the
  user before raising the cap. Do not silently raise it.
- If a targeted pytest run times out, do NOT rerun with a higher
  timeout. Narrow the target to a single test class or test node id;
  if still too slow, mark the offender `@pytest.mark.slow` and note
  it for the user.

---

## No Real-World Identifier Leaks

This is a public-release simulator. Real-world identifiers
(operator PLMNs, allocated IINs, public IPs, internal hostnames,
geographic metadata) MUST NOT appear in code, fixtures, examples,
or docs.

### Use Standards-Reserved Test Ranges

| Identifier        | Use this                                                | Never use                                                       |
|-------------------|---------------------------------------------------------|-----------------------------------------------------------------|
| MCC / MNC         | `001/01` (3GPP TS 23.003 §2.2 test PLMN), `999/99(9)`   | Any real allocation (240 SE, 248 EE, 234 GB, 262 DE, 310/311 US, 244 FI, …) |
| ICCID IIN prefix  | `8988` (ITU-T E.118 "Universal" test range)             | `8946`/`8949` SE, `8937` NO, `8935` DK, `8949` EE, `89126` US, `8983` IT, … |
| EID prefix        | `89049032…` (SGP.22 §A.2 test EID body)                 | Any other 5-digit EUM IIN                                       |
| IPv4 in fixtures  | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) | Any APNIC / ARIN-allocated public range                         |
| FQDNs             | `*.example.test`, `*.example.com`, `*.example.org`, `*.example.invalid` | Any vendor / operator / internal-infra hostname                 |
| Email addresses   | `*@example.{com,org,test}` (RFC 2606)                   | Real corporate or operator domains                              |
| E.164 phone       | `+1 555 0XXXXXX` (NANP fictional)                       | Any real country-code + valid mobile body                       |
| Geographic data   | `C=XX / ST=TestState / L=TestLocality` in test certs    | City / country / region of any real office                      |
| Capture filenames | `session-example.pcapng`, `failing-example.pcapng`      | Anything with a real date `YYYY-MM-DD.pcapng`                   |

### Exceptions Allowed

- Spec citations that name a code as part of a worked example
  (e.g. "TS 24.008 §10.5.1.3 PLMN coding for MCC=310 MNC=260") may
  keep the code if no operator name appears in the comment.
- Public contact addresses in `SECURITY.md` / `CODE_OF_CONDUCT.md`
  (`security@1ot.com`, `conduct@1ot.com`) are intentional — keep.
- Existing test-fixture ICCIDs with a clearly synthetic body
  (`894611111111111111XX`) may stay to avoid mass test churn, but
  NEW fixtures MUST use the `8988…` test range.

### Doc Examples

Use generic placeholders. A doc example showing a CLI invocation
SHOULD use `8988201234567890123` for ICCID, `001010000000001` for
IMSI, `192.0.2.4` for an IP, and `eim.example.test` for a hostname.

---

## No Internal Roadmap / Timeline Leaks

This is a public release tree. Anything that exposes an internal
sprint cadence, planning document, or capture date MUST stay out of
tracked files.

### Banned Surfaces

- `Phase 1 / Phase 6 / Phase 7` style internal phase labels in
  module docstrings, test class docstrings, or PE-editor headers.
  Drop the phase tag entirely; the module is what it is regardless
  of when it was built.
- `MVP`, `next iteration`, `future iteration`, `next sprint`,
  `tracked as a future-roadmap item`, `tracked in maintainer
  roadmap notes`. Replace with neutral scope language: `not part of
  this release`, `not implemented in this release`, `outside the
  scope of this fuzzer`.
- Dated capture filenames in examples
  (`session-2026-04-20.pcapng`). Use `session-example.pcapng` /
  `failing-example.pcapng`.
- Internal change-log entries with calendar dates. Drop the date
  and the sequence-position implication.
- Internal handoff / readiness / audit reports
  (`*_handoff_YYYY-MM-DD.md`, `V1_RELEASE_AUDIT.md`,
  `V2_ROADMAP.md`, `*_REVIEW.md`). These belong in
  `.git/info/exclude` (local-only) or a separate private repo.
- BUILD constants that hardcode a date. Use the semantic suffix
  only (`var BUILD = "v3-shadow-aware";`).
- Vendor-specific operational quirks gated on a hardcoded prod
  domain. Move the suffix list to a config knob
  (`EIM_VENDOR_QUIRK_FQDN_SUFFIXES`).

### Acceptable Date References

- Public GitHub policy dates ("macos-13 was retired by GitHub on
  2025-12-08") in CI workflow comments.
- Spec citation years ("3GPP TS 31.102 v17.5.0 (2022-12)") that
  identify a specific revision.

### Acceptable Phase References

- Spec phase identifiers from standards (`CPHS Phase 2`, `GSM
  phase 1 / phase 2 / phase 2+`) — these are spec terminology, not
  internal sprint labels.

---

## Comments and Docstrings

Comments explain *intent and constraints the code cannot convey*.
They never narrate what the next line does.

1. **No restating the next line.** Skip `# Increment counter` ahead
   of `count += 1`, `# Loop through items` ahead of a `for`,
   `# Return result` ahead of `return value`.
2. **Cite the spec when relevant.** Prefer
   `# SGP.22 §5.7.16 GetRAT — empty SEQUENCE = no PPRs.` over a
   paragraph of prose.
3. **Keep module docstrings short.** Open with the subject:
   `"""SGP.32 IPA-poll state machine."""` then one paragraph
   summarising inputs / outputs / invariants.
4. **No `Note:` / `Important:` / `Warning:` / `Tip:` callouts**
   unless the warning is non-obvious and operational.
5. **No TODO / FIXME / XXX / HACK with a personal name.** File a
   tracked issue and reference its number, or omit.
6. **No bullet lists in code comments where prose is shorter.**
7. **No multi-paragraph docstrings on small functions.**

### Authorship Header (Python source files)

Every standalone Python module owned by this repo carries this
exact line at the top:

```python
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
```

Use `OÜ` (Ö = U-with-umlaut), not `OU` or `OE`. Do NOT add
`@author`, `@since`, or per-function copyright lines.

---

## No AI Prose

Write like a maintainer, not an assistant. Avoid the phrasing
patterns LLMs over-produce.

### Banned Phrases

| Don't write                                                  | Why                                |
|--------------------------------------------------------------|------------------------------------|
| "Let me", "Let's", "We'll", "I'll", "I've"                   | First-person AI narration          |
| "Feel free to …"                                             | Conversational AI tell             |
| "As we mentioned / noted / saw / discussed"                  | Reader-guidance AI tell            |
| "Now we", "Here we", "Above we", "Below we"                  | Narrative scaffolding              |
| "It is worth noting", "In a nutshell", "To sum up"           | Padding                            |
| "Out of the box", "Under the hood", "Behind the scenes", "Deep dive", "First-class" | Marketing / blog tone              |
| "Robust", "Seamless(ly)", "Comprehensive", "Powerful", "Cutting-edge", "Production-ready", "Battle-tested", "Industry-leading", "Best-in-class", "Enterprise-grade" | Marketing superlatives             |
| "Carefully crafted", "Thoughtfully", "Elegantly", "The magic", "Secret sauce", "Rich set" | Self-praise                        |
| "Crucial", "Imperative", "Paramount", "Cornerstone", "Hallmark" | Importance inflation               |
| "Delve", "Leverage", "Harness"                               | LLM-favoured verbs                 |
| "This module provides …", "This class represents …", "This file implements …" | Generic AI doc opener              |
| "Helper / utility / convenience class for X"                 | Generic AI class-doc opener        |
| "In this revision …"                                         | Implies an internal versioning timeline |

### What To Write Instead

- Cite the spec or behaviour the code implements.
- Describe the contract or invariant.
- Use neutral verbs: `uses` (not "leverages"), `tolerant of` (not
  "robust to"), `not implemented in this release` (not "future-
  roadmap item").
- Open module docstrings with the subject, not boilerplate.

---

## Memory Discipline (long-running singletons)

Applies to `SIMCARD/**`, `SCP11/**`, `yggdrasim_common/**`.

The simulated `SimulatedSimCardEngine` is held as a process-wide
singleton (`SIMCARD/connection.py::_SHARED_ENGINE`). Anything that
grows per-APDU, per-poll-phase, or per-package will leak unbounded
across multiple user interactions. The same applies to the
`Apdu*Recorder` and `SessionRecording` plumbing.

### Hard Rules

1. **No write-only history lists.** If a list is only ever read via
   `len(...)`, replace it with an `int` counter.
2. **Bound any history list that callers DO read.** Use the
   `append_bounded(target, value, maxlen=MAX_HISTORY_ENTRIES)`
   helper from `SIMCARD/state.py`.
3. **Default cap is 256 entries** (`MAX_HISTORY_ENTRIES`),
   overridable via the `YGGDRASIM_SIM_HISTORY_CAP` env var.
4. **Per-cycle reset is OK.** A list that is reassigned to `[]` at
   the start of every IPA-poll cycle (or every BPP segment, or
   every SCP11 session) is bounded by definition.
5. **Recorders use `collections.deque(maxlen=...)`.** The
   `apdu_recorder` ring is `deque(maxlen=5000)` and
   `session_recording._apdu_trace` has a soft cap of 50 000. Don't
   bypass these caps.

When adding a new history-style accumulator, declare its bound in
the same commit and update the table in
`.cursor/rules/memory-discipline.mdc`.

---

## Site-Docs Mirror

Applies to `site-docs/**`, `guides/**`, `README.md`,
`SCP11/**/*.md`, `tests/**/*.md`.

The repo ships an `mkdocs --strict` site under `site-docs/`. The
`site-docs/_tools/mirror_source_docs.py` step copies many top-level
markdown files into `site-docs/sources/` so the rendered site can
link them with stable paths.

### Mirrored Pairs

- `README.md` ↔ `site-docs/sources/README.md`
- `guides/*.md` ↔ `site-docs/sources/guides/*.md`
- `SCP11/eim_local/**/*.md` ↔ `site-docs/sources/SCP11/eim_local/**/*.md`
- `SCP11/eim_local/eim_packages/templates/*.md`
- `tests/eim-sh/*.md` ↔ `site-docs/sources/tests/eim-sh/*.md`
- `tests/live_scp03/README.md` ↔ `site-docs/sources/tests/live_scp03/README.md`

### Verify

```bash
python site-docs/_tools/mirror_source_docs.py
mkdocs build --strict
```

### Do NOT Mirror

- Internal planning docs (`V1_RELEASE_AUDIT.md`,
  `V2_UNIVERSAL_GUI_PLAN.md`, `V2_ROADMAP.md`,
  `SIMCARD_V1_REVIEW.md`) — kept in `.git/info/exclude`.
- Dated handoff reports (`*_handoff_YYYY-MM-DD.md`).
- Anything under `Workspace/`, `dist/`, `build/`, or PyInstaller
  scratch dirs.

---

## GUI Frontend — Source Discipline

The canonical GUI source lives under `gui_frontend/src/`.
`yggdrasim_common/gui_server/static/` is **build output** produced by
`scripts/build_gui_frontend.sh`. Never edit files under `static/`
directly — changes will be overwritten by the next build.

After any change to `gui_frontend/src/`, run
`./scripts/build_gui_frontend.sh` to update the served bundle.
Use `./scripts/build_gui_frontend.sh --dev` for a symlink mode that
serves source files directly (no rebuild needed during development).

### Source Layout

- **JS**: 6 domain-level chunks under `js/` (largest is
  `saip-workbench.js` at ~25.5K lines). Concatenation order is
  governed by `js/.js_order`.
- **CSS**: 101 files across 4 layers — `tokens/` (themes),
  `layout/`, `components/`, `views/`. Concatenation order is
  governed by `css/.css_order`.
- **Static assets**: `index.html`, `theme-init.js`, `vendor/` are
  copied verbatim to the output.

### Token Budget Limits

| Action | Limit |
|---|---|
| Single `Read` on any JS chunk | ≤ 200 lines |
| Single `Read` on any CSS file | ≤ 150 lines |
| Total `Read` calls on frontend files per turn | ≤ 6 |
| Lines of JS/CSS quoted back to the user | ≤ 80 |

### Adding a Theme

1. Create `css/tokens/<name>.css` with the custom property block.
2. Add `<name>` to `VALID` in `theme-init.js` (single source of truth).
3. Add `<option>` to the theme-select dropdown in `index.html`.
4. Run `./scripts/build_gui_frontend.sh`.

### Do Not

- Edit files in `yggdrasim_common/gui_server/static/` directly.
- Edit `theme-init.js` without syncing the `<select>` options in `index.html`.
- Open any JS file from line 1 without a prior `grep` to locate the target.
- Add a theme without updating `theme-init.js`'s `VALID` object.

---

## Documentation Path

Relevant offline documentation lives under
`/home/hampushellsberg/Documents/Tools/YggdraSIM/docs`. These should
cover most of the required documentation. If a relevant new piece
is sourced externally, copy it into the `docs/` folder so it can be
referenced offline.

---

## Workspace File Loading

Always ensure that `.cursorrules`, `.cursorignore`, `CLAUDE.md`, and
`.claudeignore` are loaded when the IDE / agent opens
`main.code-workspace`.
