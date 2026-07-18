<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Repository release-readiness remediation

**Date:** 2026-07-18<br>
**Source audit:** `REPOSITORY_RELEASE_READINESS_2026-07-18_AUDIT.md`<br>
**Validation host:** Linux x86_64, Python 3.13<br>
**Scope:** the already-dirty working tree was preserved; no unrelated change was
reverted or cleaned

## Outcome

The source-level fixes recommended by the audit have been implemented, with the
exceptions and external release gates stated below. The Linux regression groups
used during remediation pass. Clean and full Linux frozen artifacts were also
built, inspected, and smoke-tested. This document is not an unconditional
release approval: native Windows/macOS jobs, signed tagged builds,
Docker/Buildx, remote-host SSH qualification, and real card/HIL runs still have
to complete in their respective environments.

Status terms used below:

- **Implemented** — the source change and a relevant local regression test exist.
- **Gated** — the source/CI gate exists, but it cannot be proven by this Linux
  workspace alone.
- **External** — repository controls are present, but credentials, ownership,
  hardware, or a release-policy decision remains outside the checkout.

## Release and packaging findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| RR-001 | Implemented; gated | `scripts/release/bundle-data.json` is the explicit data allowlist. `scripts/release/python-packages.json` and `source_boundary.py` also constrain publication to 369 Python sources in 31 exact packages and nine exact release helpers, preventing sibling namespace packages such as local MCP tooling from entering artifacts. `prepare_bundle_data.py` rejects ignored Python, links, escapes, unexpected file types, and canaries, and emits a hash/size/mode manifest. Wheel, sdist, and frozen-archive negative scanners are wired into CI. `yggdrasim_main.spec` no longer bundles `Workspace/` or broad source trees. Final local clean/full staging contained 52/53 approved files, and an sdist-derived wheel passed both artifact verifiers. Covered by `test_release_packaging_policy.py` and `test_plugin_publication_boundary.py`. | Build both flavors from separately contaminated clean checkouts and compare their approved manifests in release CI. |
| RR-002 | Implemented; gated | POSIX-only imports in terminal, host-shell, and health paths are conditional; unsupported capabilities fail closed without preventing FastAPI construction. `test_gui_app_constructs_without_posix_only_stdlib_modules` covers simulated absence. | Construct and exercise the complete GUI application on native Windows. |
| RR-003 | Implemented; gated | `yggdrasim_common/frozen_dispatch.py` provides fixed, named internal capabilities; arbitrary modules, scripts, and code are rejected. All audited terminal, HIL, CardBridge, picker, watcher, and ProfilePackage launchers use it. The repository-owned SAIP adapter uses installed `pySim.esim.saip` APIs instead of an unshipped upstream `contrib` script. `test_frozen_subprocess_dispatch.py` covers source and simulated-frozen paths. Actual Linux clean Card Bridge and full HIL-supervisor internal-entry smokes pass. | Exercise every child action from actual clean artifacts on native Windows/macOS and complete the remaining Linux action matrix. |
| RR-004 | Implemented; gated | Linux GUI installs the Qt webview extra and installer system libraries. Linux CI checks the backend and holds the desktop GUI open under Xvfb. | Let the native Linux and Debian release jobs execute; desktop environments outside the supported Qt path remain out of scope. |
| RR-005 | Implemented; gated | Immutable resource allowlists are packaged and verified in sdist-derived wheels. `runtime_paths.py` distinguishes editable checkouts from wheels and selects a private platform user-data root for mutable state; seed copies are bounded and private. Required LocalEIM directories are created independently of optional seed assets. The final wheel was installed with read-only `site-packages` on Linux and passed imports, GUI-resource access, runtime-root creation, LocalEIM first-use, and ProfilePackage module probes. | Repeat the read-only installed-wheel probe on native Windows and macOS. |
| RR-006 | Implemented; external | Plug-ins remain external and are excluded from frozen, wheel, sdist, and Docker publication. Host discovery deduplicates aliases and publishes actions only for healthy providers. The external contract and dependency ownership are documented; absent/unhealthy/healthy behavior is covered by `test_plugin_action_visibility.py` and `test_plugin_publication_boundary.py`. | Package and test each ignored plug-in in its intended external deployment environment; they are intentionally not embedded in release artifacts. |
| RR-007 | Implemented; gated | Automated Validation now has a portable repository traversal/publication path, Windows locking, shared atomic private files, and Windows DACL authoring/verification. Health no longer advertises an unusable path. Its portable backend and storage contracts are tested in the plug-in suite. | Run the complete validation, review, signing, and vault workflow on native Windows; the local DACL test is Windows-only. |
| RR-008 | Implemented; gated | Excel Export uses the shared no-link, no-overwrite private atomic publisher and no longer depends on `fchmod` or hard links. Existing-target and symlink cases are covered by `test_contracts.py`. | Run on native Windows and representative APFS, ext4, network, and no-hard-link destinations. |
| RR-009 | Implemented; gated | Clean/full dependencies are split; clean excludes the local Linux HIL runtime and `pyudev` while retaining portable Card Bridge/APDU relay modules. Build flavor metadata is generated outside source imports. HIL modem access requires full capability plus `YGGDRASIM_GUI_HIL_MODEM=1`, and no command defaults to `sudo`. Actual Linux artifacts passed archive inspection: clean reports remote Card Bridge available without local HIL, while full loads `pyudev` and the HIL supervisor and its doctor resolves the exact `osmo-remsim-client-st2` executable. | Exercise clean artifacts on native Windows/macOS and complete physical SIMtrace2/RemSIM qualification. |
| RR-010 | Gated; external | Installers fail unsupported architectures early, normalize Windows containment, verify release checksums, and CI enforces tag/package version identity. Tagged Windows and macOS jobs require and verify Authenticode/codesign/notarization credentials. CLI and GUI companion naming is documented. | Execute tagged native jobs with production credentials. A separately signed checksum/attestation policy, beyond signed binaries and hosted checksums/provenance, remains a release-owner decision. |
| RR-011 | Implemented; external | `pySim` and `asn1tools` use exact commit pins; `uv.lock` supplies hashed platform resolutions, CI uses `uv sync --frozen`, and deterministic SBOM/provenance generation is wired into release workflows. Duplicate mutable-branch installation was removed. | Transfer or mirror the personal `asn1tools` fork under durable project ownership and regenerate the lock; this requires repository authority. |

## Security and privacy findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| SEC-001 | Implemented; gated | `yggdrasim_common/secure_files.py` centralizes private directory/file creation, hardening, bounded no-follow reads, and atomic publication. Runtime workspaces and seeds use it under permissive umasks. POSIX mode tests pass; a native Windows DACL assertion is present. | Execute the DACL test and migration against representative existing workspaces on Windows. |
| SEC-002 | Implemented | SAIP uploads enforce encoded/decoded caps before allocation, use private per-session storage and unpredictable exclusive publication, reject links, and are removed on session close/shutdown. Covered by runtime hardening tests. | Stress limits in a deployed GUI; no unresolved source defect remains. |
| SEC-003 | Implemented | Action schemas mark PIN/PUK/ADM/AKA and related inputs as secret. A final result scrubber removes known secret outputs, and SSIM inspection no longer returns full private key material. Covered by schema and result-scrubber tests. | Browser-level inspection on each packaged GUI is still part of release smoke testing. |
| SEC-004 | Implemented | APDU history is session/reader scoped and redacted by default; raw capture requires explicit short-lived consent and is purged on close. Recorder/stream and session-close tests cover sensitive commands and isolation. | Validate with multiple real readers/sessions during HIL testing. |
| SEC-005 | Implemented | Excel safe export classifies the semantic field before token handling and removes concrete fragments from mixed token/secret values. Adversarial mixed-value and XLSX-member assertions are in the Excel Export contract suite. | None beyond native exporter execution. |
| SEC-006 | Implemented | Excel Export enforces bounded source snapshots, traversal depth/node/cell/text/row/file-geometry budgets, Excel sheet limits, and a final XLSX-size cap. Excessive nesting and long mixed-token handling are tested. | Run large-but-valid production-scale performance tests in release qualification. |
| SEC-007 | Implemented | Validation signing uses `read_bounded_private_file`, operating on the same opened descriptor whose type, size, ownership, mode/ACL, and identity were checked. Deterministic replacement/swap coverage is in `test_runtime_security_hardening.py`. | Native Windows ACL execution remains required. |
| SEC-008 | Implemented | eIM JSONL output is private, minimized, bounded, and rotating. WebSocket bearer authentication moved from query strings to the subprotocol header. Plug-in responses return opaque configuration identity rather than absolute host paths. | Confirm proxy/subprotocol compatibility in deployment infrastructure. |
| SEC-009 | Implemented | Default simulator DNS/bootstrap behavior is deterministic, offline, and uses reserved example data; live networking requires explicit opt-in. Tests no longer assert branded public traffic. | Explicit live-network mode is an integration-only path. |
| SEC-010 | Implemented | Personal/customer fixtures and examples were replaced with synthetic neutral data; the variable-catalog writer uses a neutral schema with a legacy read alias; GUI token integration is metadata-driven rather than tied to a private action ID. Legal attribution and intentional project branding were preserved. | External/private plug-in repositories must retain the same neutral-fixture discipline. |
| SEC-011 | Implemented within the supported policy; external | TLS introspection is default-denied unless explicitly enabled, untrusted PDML is bounded and rejects entities/DTD, CSP no longer permits evaluated script or cross-origin WebSockets, and required legacy cryptography has targeted standards comments rather than unsafe mechanical replacement. | `style-src 'unsafe-inline'` remains while the frontend uses dynamic inline styles. Production pinning versus labeled lab TOFU is a deployment-policy decision. |

## Parser and encoding findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| PAR-001 | Implemented | Root/live/relay/test eIM paths share `SCP11/shared/ber_tlv.py`; malformed, indefinite, truncated, nested, and trailing input is rejected without leaking `IndexError`. | — |
| PAR-002 | Implemented | BER length encoding is minimal and arbitrary-width; duplicate encoders use the shared implementation. Boundary round trips include 127 through 65,536. | — |
| PAR-003 | Implemented | EF.ICCID accepts only the supported 19/20 decimal-digit forms and always emits ten bytes. | — |
| PAR-004 | Implemented | EF.IMSI uses one strict maximum-15-digit encoder and always emits the nine-byte EF form. | — |
| PAR-005 | Implemented | APDU parsing and encoded-length validation agree on extended case 2E/3E/4E framing and reject zero `Lc`/one-byte extended `Le` ambiguities. | — |
| PAR-006 | Implemented | SCP03 unwrap reconstructs valid extended APDUs from plaintext and `Le`, including authenticated empty plaintext and 16-bit lengths. | — |
| PAR-007 | Implemented within supported CRL scope | SGP.32 requires full outer consumption. CRL loading validates expected framing, X.509 structure, issuer/signature/time/revocation semantics, and stores canonical DER. Online distribution points, delta CRLs, and indirect CRLs are not claimed. | — |
| PAR-008 | Implemented | Remote Lab invite import no longer shadows `dataclasses.replace`. Registry access now uses portable cross-process locking plus atomic publication, and multi-invite/bundle import is one transaction with rollback on failure. Local device identity is separate from the remote rig identifier, allowing identically named rigs at different agents. Concurrency, collision, rollback, and symlink-root cases are tested. | — |
| PAR-009 | Implemented | `SCP03.config` import is read-only; seed creation is explicit and lazy. A regression test imports against an empty runtime root and asserts no mutation. | — |
| PAR-010 | Implemented | SAIP metadata now models `shortEFID` as bytes and `templateID` as an OID; structural type and round-trip tests cover the registry. | — |

The parser items above are collectively covered by
`tests/test_parser_correctness_regressions.py` plus the SCP03, SCP11, SIMCARD,
and ProfilePackage regression groups.

## Plug-in and user-experience findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| PLG-001 | Implemented | Template and token artifacts use the shared portable private atomic publisher; overwrite/no-overwrite, link, and independent snapshot behavior are covered by plug-in tests. | — |
| PLG-002 | Implemented | Profile generation uses one `inspect_and_normalize` transaction and preserves a digest-bound immutable intent instead of reopening/walking the workbook twice. | — |
| PLG-003 | Implemented | XLSX preflight performs XML/relationship checks only for declared XML parts while retaining member, compression, macro, external-link, XXE, path, and workbook budgets. | — |
| UX-001 | Implemented | Blanket GUI/test ignores were removed. Only generated artifacts are named explicitly, and CI fails for ignored protected source/tests or omitted source-manifest entries. The frontend build now requires ordered manifests and strips repeated chunk headers deterministically. `test_gui_source_manifests.py` proves that modular JS, CSS, HTML, and theme sources reconstruct the served bundle byte-for-byte. | — |
| UX-002 | Implemented | `remote-lab.css` is in the source manifest and rebuilt served CSS. The modular source and previously richer served bundle were reconciled so a rebuild preserves Remote Lab, Excel-to-SAIP, reader, OTA, and SAIP editing controls; layout and source-integrity tests cover the result. | — |
| UX-003 | Implemented | Remote Lab tests now verify the current headless API contract, SCP03 frontend tests verify behavior rather than function arity, and problematic synchronous request contracts were replaced with direct/async behavioral tests. | — |
| UX-004 | Implemented; gated | Test bootstrap isolates HOME, USERPROFILE, GNUPGHOME, XDG and runtime state. Socket tests skip only when the environment actually prohibits loopback and hardware/network suites remain explicitly integration-scoped. | Run provisioned socket/card/network jobs; Linux sandbox skips are not product passes. |
| UX-005 | Implemented; gated | Card Bridge remote-rig actions accept and persist an explicit SSH executable, discover OpenSSH portably, and use the Windows system OpenSSH fallback when needed. Local process arguments are shell-free, identity paths are Windows-safe, remote paths remain POSIX, IPv6 URLs are bracketed, responses are bounded, and remote-rig state writes are locked and atomic. The clean frozen boundary does not import Linux HIL or `pyudev` modules. | Run the clean artifact workflow against real remote Linux rigs from native Windows and macOS. |
| UX-006 | Implemented; gated | Remote Lab imports one invite, multiple selected invite files, arrays, or a versioned bundle atomically, with a 256-device ceiling. Status checks are parallel; IPv6/TLS proxy URLs, quoted identifiers, heartbeat shutdown, adoption rollback, and multi-process registry safety are covered. | Exercise mixed multi-rig imports and long-running leases over the deployment proxy on native clients. |

## Remote HIL attachment findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| HIL-001 | Implemented; gated | macOS/Windows clients use the clean Card Bridge/Remote Lab path and never import the Linux SIMtrace2 supervisor or `pyudev`. A blocked-import subprocess test proves that clean Card Bridge startup remains usable without those modules. | Native frozen-client execution remains required. |
| HIL-002 | Implemented; gated | Remote-rig start performs a read-only SSH preflight before local mutation. It verifies Linux, Python 3, user `systemd`, the resolved source or frozen supervisor entry, `pyudev` or `lsusb`, `curl`, and the exact `osmo-remsim-client-st2` binary separately on the remote host. | Run against each supported remote-host distribution and service layout. |
| HIL-003 | Implemented; gated | Full Linux/Raspberry Pi installers try the exact RemSIM client package first, permit the documented compatibility package fallback, and then fail fast unless `osmo-remsim-client-st2` exists. The default remote Python path is consistently `~/YggdraSIM/.venv/bin/python`. | Validate fresh-host installs and USB reconnect behavior with physical SIMtrace2 hardware. |
| HIL-004 | Implemented; gated | Windows and macOS CI jobs run the portable Card Bridge, Remote Lab, relay, token, GUI-action, and clean-dependency-boundary suites before building their frozen artifacts. | Successful native CI executions are the release evidence; they cannot be substituted by this Linux host. |

## Maintenance findings

| ID | Status | Implemented remediation and evidence | Remaining validation |
| --- | --- | --- | --- |
| MAINT-001 | Implemented | CI has a fatal Ruff `E9,F` gate. Unused locals/imports were triaged module-by-module, while intentional callback/compatibility surfaces were preserved and tested rather than bulk-deleted. Whole-scope tracked-source and ignored plug-in Ruff invocations are green; Vulture remains non-authoritative. Pytest warning suppression is limited to pinned upstream module namespaces (`asn1tools`, `pySim`, `construct`, and `cmd2`), keeping project warnings visible without thousands of repeated dependency deprecations. | — |
| MAINT-002 | Implemented | Strict BER/protocol helpers are canonical shared modules. SCP11 root/live/relay/test alternatives use explicit compatibility exports with `__all__`, and identity/import tests protect their public surface. | — |
| MAINT-003 | Implemented | Security policy, supported-version text, repository/reporting URLs, frozen GUI documentation, and generated documentation mirrors use the canonical project identity. Documentation contract tests enforce consistency. | — |

## Verification record

The remediation run used focused and module-level tests before broader
regressions. The following local Linux groups passed:

- the complete default regression suite: **7,646 passed, 148 skipped, 1,427
  subtests passed**; skips are confined to declared hardware, loopback-denied,
  optional-dependency, platform, and opt-in integration cases;
- release packaging policy, source/publication boundary, bundle staging, and
  wheel/sdist verification tests, including a final sdist-derived wheel and a
  read-only installed-wheel first-use smoke; extracted artifact scans contained
  no customer identifier, developer home/email, or named local-only tool
  namespace;
- runtime-path, private-file, upload, APDU, WebSocket, TLS/PDML, GUI action,
  GUI source-manifest, and plug-in action-visibility tests;
- parser correctness plus SCP03, SCP80, SCP11, SIMCARD, ProfilePackage, ASN.1,
  JSON, filesystem, and variable-materialization regressions;
- all local SAIP Profile Generator, SAIP Excel Export, and Automated Validation
  plug-in test modules; optional external fixtures remain explicit skips;
- repository documentation and compatibility-export contract tests;
- clean/full allowlist staging (52 and 53 files respectively), `uv lock
  --check --offline` (124 packages), whole-scope Ruff `E9,F` across tracked
  code and ignored external plug-ins, Python compilation, Node syntax
  validation, byte-exact GUI reconstruction, and strict builds of both MkDocs
  configurations;
- native-target Card Bridge/Remote Lab tests are wired into Windows and macOS
  CI, while the local cross-platform boundary, GUI action, HTTP action, relay,
  token, and HIL remote-card groups pass on Linux;
- actual Linux `yggdrasim-clean`, `yggdrasim-gui-clean`, `yggdrasim-full`, and
  `yggdrasim-gui-full` one-file builds passed version and frozen-archive policy
  checks. The clean Card Bridge and full HIL-supervisor internal entry points
  load successfully; full `doctor` reports both `pyudev` and
  `osmo-remsim-client-st2`, and both flavors use the configured persistent
  runtime root instead of the temporary one-file extraction directory.

The Windows DACL assertion is intentionally skipped on Linux. Native release
jobs and hardware tests were not represented as local passes.

## Required release closure

Before publishing a tagged release:

1. Run clean frozen builds and action smokes on native Windows/macOS, including
   GUI construction and internal subprocess actions; retain the completed Linux
   clean/full evidence.
2. Run the read-only installed-wheel scenario on Linux, Windows, and macOS.
3. Supply production Windows/macOS signing credentials and retain successful
   Authenticode, codesign, and notarization evidence.
4. Run Docker/Buildx provenance, SBOM, archive-canary, and manifest checks in CI.
5. Run the provisioned socket, card-reader, multi-reader APDU, remote SSH
   attachment, and physical SIMtrace2/RemSIM HIL suites.
6. Qualify each external plug-in independently in absent, unhealthy, and healthy
   dependency states.
7. Resolve durable ownership of the pinned `asn1tools` fork and the checksum
   attestation policy before calling the supply-chain work fully closed.
