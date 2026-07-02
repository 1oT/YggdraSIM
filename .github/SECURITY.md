<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Security policy

## Reporting an exploitable vulnerability

Do **not** open a public GitHub issue for exploitable vulnerabilities in
YggdraSIM. This includes, but is not limited to:

- Key-material leakage (Ki, OPc, K_ENC, K_MAC, PSK, TLS private keys).
- Signature / MAC forgery against SCP03, SCP11 or SCP80 sessions.
- Authentication bypass in any wizard or console.
- eUICC profile compromise (RSP, SGP.22, SGP.32).
- Supply-chain injection against the CI bundles, Docker image or
  Debian package.
- Any path-traversal, arbitrary-file-write, or arbitrary-command-exec
  bug reachable from operator input.

Use GitHub Security Advisories for private disclosure:

> <https://github.com/hampus/YggdraSIM/security/advisories/new>

Expect an acknowledgement within 72 hours. Coordinated disclosure
timelines are negotiated case by case.

## Non-exploitable hardening reports

Hardening gaps, audit findings without a working proof-of-concept, and
threat-model questions may be filed as public issues using the
**Security report (non-exploitable / hardening)** issue form.

Every such issue must be triaged and approved by a maintainer before a
pull request referencing it will be accepted. See
[`SECURITY_CONTROLS.md`](SECURITY_CONTROLS.md) for the gate.

## Scope

In scope:

- `main` branch HEAD
- Tagged `v*` releases (latest two minor versions)
- Bundles produced by `.github/workflows/build.yml` and the Docker
  image produced by `.github/workflows/docker.yml`

Out of scope:

- Forks outside this repository.
- Third-party dependencies — report to their upstream projects first.
- Attacks requiring physical possession of the host running
  YggdraSIM with an unlocked operating-system session.

## Cryptographic standards YggdraSIM is audited against

- GSMA SGP.02, SGP.22, SGP.32
- GlobalPlatform Card Specification v2.3
- ETSI TS 102 221
- 3GPP TS 31.102, TS 33.102
- ISO/IEC 7816-4

Findings that cite one of these specifications explicitly are
prioritised.
