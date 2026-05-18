---
title: Coding Standards
tags:
  - internals
  - style
---

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

## APDU and crypto handling

- ISO/IEC 7816-4 terminology is preferred: CLA, INS, P1, P2, Lc, Data, Le,
  SW1, SW2.
- GP content-management verbs follow the card-spec naming exactly:
  `INSTALL FOR LOAD`, `INSTALL FOR INSTALL`, `PUT KEY`.
- SCP11 payload shaping must respect the shared `SCP11/shared/` helpers
  instead of re-implementing the wheel per subsystem.

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
  entirely — the pre-release security sweep removed every
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
