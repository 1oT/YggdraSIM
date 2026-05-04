# Security Policy

YggdraSIM is a **secure-element research and auditing toolkit**. The
project owner -- **1oT OÜ** -- and the lead maintainer take security
findings seriously, both in the toolkit itself and in the standards-
adjacent surfaces it exercises (`SCP03`, `SCP11`, `SCP80`, `SIMCARD`,
`Tools/HilBridge`, profile packaging, etc.).

## Supported versions

Security fixes are accepted on the actively-maintained line:

| Version line | Supported | Notes |
| --- | --- | --- |
| `1.0.x` (released `v1.0.0`) | Yes | Tracked on the `release/1.0.x` branch and the `v1.0.0` tag. |
| `main` (development) | Yes | Pre-release work-in-progress; fixes that apply to `1.0.x` are back-ported. |
| Any earlier release-candidate tag | No | Superseded by `v1.0.0`. Re-base onto a supported line. |

## How to report a vulnerability

**Do not open a public GitHub issue for a security finding.** Use the
private channels below.

- Preferred: GitHub private vulnerability report on
  `https://github.com/1oT/YggdraSIM/security/advisories/new`.
- Alternative: email **`security@1ot.com`** with the subject prefix
  `[YggdraSIM][SECURITY]` and a descriptive title.
- For reports involving GSMA, SGP.02 / 22 / 32, or any disclosure that
  may be subject to coordinated handling under the GSMA Coordinated
  Vulnerability Disclosure (CVD) programme, mark the email
  `[YggdraSIM][SECURITY][GSMA-CVD]` so the maintainer can route it
  through the existing GSMA CVD workflow.

When you report, please include:

- the affected file paths, function names, or APDU / TLV sequences;
- the version (commit hash or tag) the finding was reproduced on;
- a minimal reproducer or step list (PCAP / `tshark` capture, APDU
  log, or shell transcript is welcome);
- the deployment context (simulator, HIL with SIMtrace2, live PC/SC,
  relay over IP) so the maintainer can assess exploitability;
- whether you intend to publish a write-up, conference talk, or CVE
  request, and any embargo deadline you need.

## Acknowledgement and timing

- Maintainer acknowledgement: within **5 working days** of receipt.
- Triage and severity assessment: within **15 working days** for any
  report that includes a reproducer.
- Coordinated fix window: typically **30 days** for high / critical,
  longer when GSMA CVD or upstream coordination is required.
- Public disclosure: only after a fix or mitigation has shipped, and
  only after the reporter has been credited (unless they request
  anonymity).

## Scope

In scope:

- Secure-channel implementations (`SCP03`, `SCP11`, `SCP80`).
- SIM/USIM/ISIM/eUICC simulator behaviour (`SIMCARD/`,
  `SIMCARD/auth.py`, `SIMCARD/akma.py`, `SIMCARD/aka_5g.py`,
  `SIMCARD/suci.py`).
- Profile-package handling (`Tools/ProfilePackage/`,
  `Tools/SuciTool/`).
- HIL bridge transport (`Tools/HilBridge/`,
  `yggdrasim_common/card_bridge_auth.py`,
  `yggdrasim_common/apdu_recorder.py`).
- Inventory / device-state crypto
  (`yggdrasim_common/inventory_crypto.py`).
- Installer paths under `scripts/install/`.

Out of scope (these are intentional research surfaces):

- The bundled GSMA **SGP.26 test certificates and keys** under
  `SCP11/` and `SCP11/SGP.26_test_Certs/`. They are publicly known
  test material; see `SCP11/TEST_MATERIAL_NOTICE.md`.
- Demo SCP03 / SCP80 keys gated by
  `YGGDRASIM_ALLOW_DEMO_KEYS=1`.
- Quirks / plugin loading paths gated by
  `YGGDRASIM_ALLOW_QUIRKS=1` and `YGGDRASIM_ALLOW_PLUGINS=1`.
- TLS verification bypass paths gated by
  `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS=1`. These are explicit lab
  toggles and not security regressions on their own.
- Operator-supplied material under `Workspace/` and `state/`. They are
  gitignored and never expected to leave the operator host.

If you are unsure whether a finding is in scope, send it anyway and
let the maintainer triage.

## Hardening defaults already in v1.0.0

For context, the following hardening landed before `v1.0.0`:

- `hmac.compare_digest` for SCP03 / SCP11 cryptogram and SPKI pin
  comparisons.
- Fail-closed demo-key policy on non-simulator backends
  (`YGGDRASIM_ALLOW_DEMO_KEYS=1` opt-in).
- Centralised TLS handling via `SCP11/shared/tls_helpers.py` with
  `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS=1` as the strict-mode toggle.
- Quirks / plugin loaders refuse to import operator code unless the
  matching env flag is set.
- `inventory_crypto` envelope encryption with corruption-safe
  sidecar rename and path containment for the GPG key file.
- `pyscard`, `pysim`, and operator-only state directories are
  excluded from the published wheel and Docker image (see
  `.gitignore`, `.dockerignore`, `MANIFEST.in`).

See the [GitHub Releases](https://github.com/1oT/YggdraSIM/releases)
page for per-release security notes.
