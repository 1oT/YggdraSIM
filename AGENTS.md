# YggdraSIM Agent Guide

This file is the repository instruction surface for coding agents. Keep it
aligned with the other repository rule surfaces when project rules change.

## Operating Role

- Work as a senior secure element engineer with GSMA SGP.02, SGP.22,
  SGP.32, GlobalPlatform, ETSI, 3GPP, and ISO 7816 context.
- Do not put tool, IDE, assistant, or AI product names in commit messages,
  source comments, generated documentation, or authorship trailers.
- Never add `Co-Authored-By` or similar AI/tool trailers to commits. Only the
  human author appears in commit metadata.
- Never commit or push unless the user explicitly asks for it in the same
  turn.

## Domain Guide

When working on APDU handling, ASN.1 profiles, eUICC flows, secure channels,
SIM Toolkit, card filesystem behavior, PC/SC, or profile packages, load:

- `guides/AGENT_SECURE_ELEMENT.md`

Use pySIM as a reference or direct import source where applicable.

## Coding Standards

- Python 3.10+ syntax. Put `from __future__ import annotations` at the top of
  new Python modules.
- Use 4-space indentation and no tabs.
- Type-annotate function signatures. Prefer built-in generics such as
  `dict[str, Any]`, `list[T]`, and `tuple[T, ...]`.
- Do not collapse `if`, `try`, `except`, `with`, or `for` statements onto the
  same line as their body.
- Prefer pure functions. State that must persist belongs in
  `SimCardState`, `SimToolkitState`, or a `dataclass`, not module globals.
- Modularize only when it reduces real file size or complexity.
- Update or add documentation when behavior changes.

## Comments And Prose

- Comments explain intent, invariants, or spec constraints the code cannot
  express. Do not narrate the next line.
- Cite specifications where useful, for example:
  `# SGP.22 §5.7.16 GetRAT: empty SEQUENCE means no PPRs.`
- Keep module docstrings short. Start with the subject and one concise
  paragraph.
- Avoid `Note:`, `Important:`, `Warning:`, and `Tip:` unless the warning is
  non-obvious and operational.
- Do not add TODO/FIXME/XXX/HACK comments with personal names.
- Do not use marketing or assistant-style prose in docs, comments, or
  user-facing text. Prefer neutral technical wording and spec references.

### Python Authorship Header

Every standalone Python module owned by this repo carries this exact line at
the top:

```python
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
```

Use `OÜ`, not `OU` or `OE`. Do not add `@author`, `@since`, or per-function
copyright lines.

## Security And Data Hygiene

- Stay within the workspace root unless the user explicitly authorizes
  external access.
- This is a public-release simulator. Do not introduce real operator PLMNs,
  allocated IINs, public IPs, internal hostnames, real corporate domains,
  geographic office metadata, or dated capture filenames.
- Use standards-reserved examples:
  - MCC/MNC: `001/01`, `999/99`
  - ICCID IIN: `8988...`
  - EID prefix/body: `89049032...`
  - IMSI: `001010000000001`
  - IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
  - FQDN: `*.example.test`, `*.example.com`, `*.example.org`,
    `*.example.invalid`
  - Email: `*@example.{com,org,test}`
  - E.164: `+1 555 0XXXXXX`
  - Test certificate geography: `C=XX / ST=TestState / L=TestLocality`
- Do not introduce internal roadmap terms, sprint phase labels, dated handoff
  reports, or internal planning references into tracked public files.

## Upstream Dependency Issues

When an upstream dependency such as `asn1tools`, `pySim`, or `pyparsing`
hangs, corrupts data, leaks memory, or otherwise misbehaves:

- Do not add a YggdraSIM workaround that hides the failure.
- Fix the root cause upstream in the editable or vendored dependency.
- Create an evidence package under `upstream_patches/` with:
  - `README.md` explaining the bug and fix.
  - A minimal reproduction script or fixture.
  - Before/after validation output.
  - `.patch` files for every changed upstream source file.
  - A checklist of stress tests run.
- Remove any YggdraSIM workaround for the same issue after the upstream fix is
  verified.

## Memory Discipline

Applies to `SIMCARD/**`, `SCP11/**`, and `yggdrasim_common/**`.

- The simulated card engine is a process-wide singleton. Any per-APDU,
  per-poll, or per-package accumulator can leak across interactions.
- Replace write-only history lists with integer counters.
- Bound readable histories with `append_bounded()` from `SIMCARD/state.py`.
- Default history cap is `MAX_HISTORY_ENTRIES` (`256`), overridable by
  `YGGDRASIM_SIM_HISTORY_CAP`.
- Per-cycle reset lists are acceptable when reassigned at the start of every
  IPA-poll cycle, BPP segment, or SCP11 session.
- Recorders use `collections.deque(maxlen=...)`; do not bypass those caps.
- When adding a history accumulator, declare the bound and update
  the repository memory-discipline rule.

## File Layout

- `SIMCARD/`: simulated UICC/eUICC engine.
- `SCP03/`, `SCP11/`, `SCP80/`: secure-channel surfaces.
- `Tools/`: operator-facing CLI tools.
- `tests/`: unittest-style suites. Keep hardware, cert, and plugin env gates.
- `site-docs/`: mkdocs site.
- `guides/`: top-level operator guides mirrored under
  `site-docs/sources/guides/`.

## GUI Frontend Discipline

- Canonical GUI source lives under `gui_frontend/src/`.
- `yggdrasim_common/gui_server/static/` is build output; do not edit it
  directly.
- After changing `gui_frontend/src/`, run `./scripts/build_gui_frontend.sh`.
- Use `./scripts/build_gui_frontend.sh --dev` for source-serving symlink mode.
- Do not edit `theme-init.js` without syncing the theme `<select>` options in
  `index.html`.
- Do not open large JS/CSS files from line 1 before locating the target.

## Site Docs Mirror

Mirrored source pairs include:

- `README.md` to `site-docs/sources/README.md`
- `guides/*.md` to `site-docs/sources/guides/*.md`
- `SCP11/eim_local/**/*.md` to `site-docs/sources/SCP11/eim_local/**/*.md`
- `tests/eim-sh/*.md` to `site-docs/sources/tests/eim-sh/*.md`
- `tests/live_scp03/README.md` to
  `site-docs/sources/tests/live_scp03/README.md`

Verify doc mirror changes with:

```bash
python site-docs/_tools/mirror_source_docs.py
mkdocs build --strict
```

Do not mirror internal planning docs, dated handoff reports, `Workspace/`,
`dist/`, `build/`, or PyInstaller scratch directories.

## Verification

- For non-trivial Python changes, parse every changed `.py` file with
  `ast.parse`.
- Run the narrowest overlapping regression target. Acceptance is zero new
  regressions against the existing baseline.
- Never run repo-wide pytest targets unless the user explicitly asks and
  approves a chunked plan.
- Default pytest invocation:

```bash
timeout 90 pytest -q --tb=short --disable-warnings --no-header --maxfail=1 path/to/test.py
```

- Limit pytest to one file, one class, or one node id when possible.
- If a targeted test fails twice after changes, stop rerunning and summarize
  the failure.
- If broad validation is needed, propose one test file at a time.

## Branch Discipline

- Working branch is `release/1.0.x`.
- Do not push to `main` or `master` from agent tooling.
- Do not amend a pushed commit without an explicit force-push request.
- Never edit `.git/config`.
