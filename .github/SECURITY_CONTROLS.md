# Security controls for issues and pull requests

This document describes the contribution gate enforced by GitHub Actions
on the YggdraSIM repository. The goal is simple: nothing lands in `main`
unless a maintainer has explicitly approved the underlying request.

## Roles

- **Contributor** — anyone without `write`, `maintain` or `admin`
  permission on this repository. This is the default for community
  contributors and for new collaborators during onboarding.
- **Maintainer / privileged account** — an account with `write`,
  `maintain` or `admin` permission on this repository. Privilege is
  resolved at event time via the
  `GET /repos/{owner}/{repo}/collaborators/{username}/permission`
  endpoint.

## The gate

### 1. Every new issue starts unapproved

Issues opened through the forms under `.github/ISSUE_TEMPLATE/` are
auto-labelled `needs-approval` by
`.github/workflows/issue-approval.yml`. Blank issues are disabled in
`.github/ISSUE_TEMPLATE/config.yml`.

### 2. Only maintainers can approve

The `approved` label is gated. When a non-privileged account applies
`approved`:

- The label is removed immediately by the workflow.
- The `needs-approval` label is restored.
- A comment is posted on the issue citing this policy.

When a non-privileged account removes `approved` from an issue, the
workflow restores it.

### 3. Every pull request must link an approved issue

`.github/workflows/pr-require-approved-issue.yml` fires on every
pull-request event. It:

1. Parses the PR title and body for same-repo issue references using
   the GitHub keywords: `Closes`, `Fixes`, `Resolves`, `Refs`,
   `Related to` — all case-insensitive, with optional `:` or `-`
   separator.
2. Fetches each referenced issue (rejects references to PRs and
   non-existent issues).
3. Requires that at least one referenced issue carries the `approved`
   label.
4. If no approved issue is linked, the workflow **immediately closes
   the pull request** and posts a comment explaining the reason.

### 4. Only maintainers can bypass

`bypass-approval-check` is a PR- or issue-level label that skips the
linked-issue requirement. It is gated the same way as `approved`:
non-privileged accounts cannot apply or remove it. Bypass is intended
for urgent CI-only / docs-only maintainer fixes — never for code
changes that touch cryptography, SCP state machines, APDU surfaces,
TLS, or supply chain.

### 5. Same-privilege requirement for PR labels

`approved` and `bypass-approval-check` are also gated on pull requests
themselves, so a contributor cannot self-apply them from a fork.

## Relevant files

- `.github/ISSUE_TEMPLATE/config.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/security_report.yml`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/workflows/issue-approval.yml`
- `.github/workflows/pr-require-approved-issue.yml`
- `.github/SECURITY.md`

## Operator checklist (maintainers)

When triaging a new issue:

1. Read the issue form end to end. Reject forms with missing or
   falsified checklist items.
2. Confirm the issue cites the correct specification
   (GSMA / GlobalPlatform / ETSI / 3GPP / ISO 7816) if it touches
   crypto, state machines, profile formats, or APDU surfaces.
3. Apply the `approved` label to unblock contributions. The workflow
   will remove `needs-approval` automatically.
4. For urgent maintainer-only fixes, open the PR first, then apply
   `bypass-approval-check` to the PR itself.

## Threat model the gate defends against

- A contributor opens a PR that appears to address a trivial issue but
  actually introduces a cryptographic regression, a supply-chain
  vector, or a key-leak path — before any maintainer has seen the
  underlying issue.
- A contributor self-labels an issue `approved` to race a PR past the
  gate.
- A contributor applies `bypass-approval-check` to their own PR.
- A contributor removes `approved` from a triaged issue mid-flight to
  force a new approval cycle or to silence tooling.

All four are blocked by the workflows above. The gate does **not**
replace required reviewers, branch protection, or CODEOWNERS — it
adds a triage requirement on top of them.

## Future extensions (post-v1)

- Require a second maintainer approval for issues labelled with a
  `risk:high` category via a dedicated workflow.
- Enforce CODEOWNERS review for changes under `SCP11/`, `SIMCARD/`,
  `yggdrasim_common/inventory_crypto.py`.
- Mirror the gate into the Docker and bundle publishing workflows so
  tagged releases cannot be cut without an approved release issue.
