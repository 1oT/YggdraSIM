<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

<!--
  YggdraSIM pull request template.

  IMPORTANT: every PR MUST reference an issue that already carries the
  `approved` label. Maintainers grant approval after triage. Unapproved
  PRs are closed automatically by the `pr-require-approved-issue`
  workflow. See .github/SECURITY_CONTROLS.md for the full policy.
-->

## Linked approved issue

<!--
  Replace NNN with the issue number. The workflow accepts any of the
  GitHub keywords below. Using "Closes" or "Fixes" will also auto-close
  the issue when this PR is merged.
-->

Closes #NNN

## Summary

<!-- What changes in behaviour, and why. Keep it specific. -->

## Specification references

<!--
  Required for any change that touches cryptography, SCP03/11 state
  machines, APDU surfaces, eUICC profile formats or TLS/pinning.
  Otherwise, write "N/A — docs/packaging/UI only".
-->

- GSMA SGP.xx vX.Y, §...
- GlobalPlatform Card Specification v2.3, §...
- ETSI TS 102 221, §...
- 3GPP TS 31.102 / TS 33.102, §...

## Test plan

<!-- Exact commands, not a narrative. -->

```
pytest -q --tb=short --disable-warnings --no-header --maxfail=1 tests/...
```

## Security / compliance checklist

- [ ] No secret material (Ki, OPc, PSK, K_ENC/K_MAC, TLS keys, eUICC
      profiles) is logged, printed, or committed.
- [ ] No new `except:` / `except Exception: pass` without a spec-backed
      fallback (use `SCP11/shared/safe_parse.py` where applicable).
- [ ] No new `subprocess` calls with `shell=True` or untrusted strings.
- [ ] No new `verify=False` / `check_hostname=False` TLS sites outside
      the existing pinning-gated paths.
- [ ] No new `datetime.utcnow()` or tz-naive `datetime.now()`.
- [ ] `pyproject.toml` version bumped if this is a release-worthy change.
- [ ] Relevant docs under `docs/` / `site-docs/` updated.

## Reviewer notes

<!-- Anything specific a reviewer should verify by hand. -->
