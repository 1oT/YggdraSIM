# Contributing to YggdraSIM

YggdraSIM is maintained by **1oT OÜ** (IP owner) with **Hampus Hellsberg** as
creator, lead architect, and lead maintainer. External contributions are
welcome under the project license (GPL-3.0-or-later) and the constraints
below.

## Ground rules

- The repository is a **secure-element research and auditing toolkit**. Do not
  submit material that embeds operator secrets, real subscriber identities
  (`IMSI`, `ICCID`, `EID`), production `AES`/`DES`/`ECC` keys, certified
  profile bundles, or vendor-confidential APDU traces.
- Only specification-grade references are acceptable in code, tests, or
  documentation. When in doubt, cite the public section of the relevant
  `GSMA SGP.02 / SGP.22 / SGP.32`, `GlobalPlatform Card Specification`,
  `ETSI TS 102 221 / 102 222`, `3GPP TS 31.102 / 31.115 / 31.116`, or
  `ISO/IEC 7816` document.
- All source files in the repository must preserve the standing header:
  `# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.`
  Do not remove or rewrite this header in submitted patches.

## Workflow

1. Open an issue before starting non-trivial work. Describe the scope,
   affected subsystem (`SCP03`, `SCP80`, `SCP11/*`, `Tools/HilBridge`,
   `Tools/ProfilePackage`, `SIMCARD`, `main/`), and the specification the
   change references.
2. Fork the repository and branch from `main`. Use one topic branch per
   logical change.
3. Keep the diff minimal. Prefer editing existing files to creating new
   ones. Follow the style already present in the neighbourhood of the
   change.
4. Respect the coding standards captured in the docs:
   [Coding Standards](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/site-docs/internals/coding-standards.md).
   Notably: never collapse `if` / `try` / `except` / `with` / `for` onto a
   single line with their block.
5. Add or update tests for any behavioural change. Run the narrowest
   relevant `pytest` target. Do not run the full suite in CI-at-a-glance
   mode; see
   [Testing Guide](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/site-docs/internals/testing-guide.md).
6. Update documentation in the same PR. If you change a CLI surface or an
   operator flow, update at minimum:
   - the subsystem page under `site-docs/subsystems/`
   - the affected entries in `site-docs/reference/command-suite.md`
   - the affected entries in `site-docs/reference/cli-matrix.md`
7. Never commit generated artifacts, build outputs, captured pcaps, card
   dumps, or files under `state/`, `Workspace/`, or `runtime/`.

## Commit and PR hygiene

- Write factual, technical commit messages. One logical change per commit.
  Describe the specification impact when applicable.
- Keep commit messages neutral and tool-agnostic. Do not embed editor,
  IDE, or authoring-tool identifiers in commit messages or source
  comments.
- Squash noisy review-fix commits before the PR is marked ready.
- Use the PR template at `.github/PULL_REQUEST_TEMPLATE.md` and fill in
  the test evidence section.

## Security-sensitive changes

Changes that touch cryptographic primitives, secure channel state
machines, key derivation, inventory encryption, keybag export, or
APDU-layer decoding must:

- cite the governing specification section in the commit message,
- include targeted unit tests under `tests/`,
- avoid weakening any existing invariant (never replace a `HMAC`,
  `CMAC`, `KDF`, or `ECDSA` check with a no-op for convenience).

For coordinated vulnerability disclosure, see
[`.github/SECURITY.md`](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/.github/SECURITY.md)
at the repository root instead of opening a public issue.

## Licensing of contributions

By submitting a pull request you agree that your contribution is
licensed to the project under **GPL-3.0-or-later** and may be
redistributed by 1oT OÜ as part of YggdraSIM. The project does not
require a CLA. Your authorship is preserved in the git history and, for
substantial contributions, in the `AUTHORS` file.
