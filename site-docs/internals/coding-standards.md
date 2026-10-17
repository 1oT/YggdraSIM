---
title: Coding Standards
tags:
  - internals
  - style
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Coding Standards

YggdraSIM enforces a small, specific set of conventions. They exist to keep
the codebase readable across very different subsystems (APDU builders, shell
dispatchers, TUIs, ASN.1 codecs) and to make review and maintenance
predictable.

## Structural rules

- Never combine a control statement with its block on the same line. `if`,
  `try`, `except`, `with`, and `for` always open a block on the next line.
- Prefer full class and function definitions in reviewable code blocks.
  Single-line one-off definitions are only acceptable in the vendored tree.
- Keep file sizes manageable. When a file crosses the point where a new
  contributor cannot find things fast, split it along functional seams.

## Comments

- Do not narrate code. No "// Import the module", "// Define the function",
  "# Increment the counter", or similar.
- Comments explain intent, trade-offs, or constraints that the code itself
  cannot convey.
- No "added by" / "updated by" markers. Git history owns authorship, not
  inline comments.

## Documentation tone

- Technical, dry, and supportive of specification language.
- Prefer precise terms. `ICCID`, `EID`, `ISD-R`, `PE`, `BPP`, `ADF USIM`
  should appear as written, not paraphrased.
- When a spec governs a behavior, cite the spec. Vendored copies under
  `docs/` are the canonical reference.

## Wizard granularity

Interactive wizards must be tag-granular. Each nested TLV, ASN.1 field, or
distinct conceptual step gets its own wizard stage. This keeps the operator
path navigable and the wizard maintainable as the spec evolves.

## Shell command lines

- Every interactive shell hands each command line, typed or from `--cmd`
  / `--stdin`, to `yggdrasim_common.command_log.run_with_command_log`
  before it parses the line, so `--log <file>` works on every command.
  Pass a `debug` context that switches the shell's own debug output on
  (raw APDU logging, a debug mode) and back; the helper turns the global
  debug flag on itself.
- A path that reaches the same handlers without a terminal, such as a GUI
  action, refuses `--log` (`command_log.log_flag_present`): a file path in
  a web request would be written on the server host.
- Swap `sys.stdout` / `sys.stderr` around one command, never across a
  prompt, so every swap stays nested and readline keeps the terminal.

## APDU and crypto handling

- ISO/IEC 7816-4 terminology is preferred: CLA, INS, P1, P2, Lc, Data, Le,
  SW1, SW2.
- GP content-management verbs follow the card-spec naming exactly:
  `INSTALL FOR LOAD`, `INSTALL FOR INSTALL`, `PUT KEY`.
- SCP11 payload shaping must respect the shared `SCP11/shared/` helpers
  instead of re-implementing the wheel per subsystem.

## Reuse before building

- Before writing a new decoder or encoder, an EF or ASN.1 definition, a
  protocol stack, or a card, reader or network tool, check the osmocom
  projects for one that exists: pySim first, then libosmocore and the
  other projects on gitea.osmocom.org (simtrace2, osmo-remsim, osmo-epdg,
  the osmo-ttcn3-hacks test suites).
- Prefer importing it, then porting it, then using it as the reference
  behaviour. Check its licence against GPL-3.0-or-later before copying
  code.
- When nothing fits, the change says what was checked and why it does
  not fit.
- A defect or gap found in a reused project is fixed twice: a patch with
  its evidence under `upstream_patches/<name>/` (see the
  `upstream_patches/osmocom-*` folders), and a compensation in this tree
  that verifies its own effect.

## Python conventions

- Follow PEP 8 loosely; clarity over pedantry.
- Type hints are welcome; they are not strictly enforced in legacy modules.
- Avoid deep inheritance chains. Composition over inheritance wins.
- Use `f"..."` for string interpolation; reserve `.format()` for unusual
  cases. Drop the `f` prefix when the literal has no `{...}` placeholders;
  a bare `f"static text"` is dead syntax and pyflakes flags it.
- Prefer narrow exception types at every `raise` site. `RuntimeError`
  covers operator-visible runtime failures, `ValueError` covers malformed
  user or card data, `TypeError` covers contract violations, and dedicated
  `OSError` subclasses cover transport issues. Avoid `raise Exception(...)`
  entirely -- the pre-release security sweep removed every
  remaining occurrence from the production tree, so new occurrences show
  up clearly in code review.
- `except Exception:` catches are acceptable only in display / TLV-fallback
  paths where any failure collapses to "render the raw hex instead". New
  production code should catch the specific exception it cares about.
- Mutable default arguments are prohibited. Use the `None` sentinel plus
  in-body initialization.

## Security and boundary

- Contributors work inside the repository checkout. Do not add code paths
  that reach outside the workspace root (absolute paths into `/etc/`,
  `/root/`, or foreign user homes) unless the feature explicitly requires
  it and the escape hatch is documented.
- Assume low-level interfacing via PC/SC or serial is in the threat model
  for every card-facing subsystem.
- Never commit keys, certificates, or credentials. Runtime material lives
  under the runtime root, not in the tree.

## Decode boundaries

Every subsystem decodes bytes it did not produce: a card response, an ES9+
payload, a workbook, a profile package. Those bytes can be truncated,
over-long, or hostile.

- **Contain upstream exception types at the module boundary.** Code that
  delegates to pySim, `asn1tools`, or `cryptography` can raise
  `OutOfByteDataError`, `MissingDataError`, or a bare `IndexError`. A
  caller catching `ValueError` never sees those, so a malformed remote
  payload unwinds the whole flow instead of failing the one step.
- **If the surrounding code already degrades gracefully for one malformed
  field, a sibling field must take the same route.** Two fields of the
  same response behaving differently is a defect, not a policy choice.
- **Guard the call, not one field.** Validating a single field leaves its
  siblings in the same call unguarded.
- **A rejection should raise a type the module owns** -- `ValueError`, or
  a domain error such as `Scp03ResponseProtectionError`. Those read as
  rejections; an `IndexError` reads as a crash.
- **A private helper may assume its caller's precondition.** Keep the
  bounds check next to the caller that enforces it, and do not treat a
  scanner calling the helper directly as a finding.

When you change a decoder, call it with `b""`, a single byte, a truncated
TLV header, a length that over-claims its body (`b"\x62\xc8"`), a
long-form length with no body, and an odd-nibble BCD run. Anything other
than a clean rejection is a defect.

## GUI frontend

- `gui_frontend/src/` is the source; `yggdrasim_common/gui_server/static/`
  is build output. Rebuild with `./scripts/build_gui_frontend.sh` after
  every source change; `tests/test_gui_source_manifests.py` requires the
  served bundle to be byte-identical to a fresh build.
- One design system, 20 themes. Colour reaches a rule through a theme
  token or not at all; the per-file literal budget in
  `tests/test_gui_design_system_consistency.py` only shrinks. New floating
  surfaces (`position: fixed`) are app chrome or transient overlays;
  action output renders inline.
- The page CSP forbids inline scripts, inline styles, inline handlers and
  `eval`. Build DOM with `createElement` / `textContent`.
- Every operator-visible label is anchored in a specification or marked
  YggdraSIM-coined in `guides/NAMING_CONVENTIONS.md`.
- The full contract, the CSS layer map and the theme registration steps
  are in `gui_frontend/README.md`.

## Git and commits

- Do not update the git config in checked-in scripts or CI.
- Do not amend commits that are already pushed. Fix-forward with a new
  commit instead.
- Never force-push to `main` without explicit maintainer approval.
- Commit messages are technical and dry. Do not embed editor, IDE, or
  authoring-tool identifiers in commit messages or source comments.

## Pull requests

- Keep PRs scoped. Cross-cutting refactors belong in their own branch.
- Run the narrowly-targeted tests that match the touched surface.
- Update the relevant docs under `site-docs/` when the operator-facing
  behavior changes.

## Related pages

- [Testing Guide](testing-guide.md)
- [Release Checklist](release-checklist.md)
