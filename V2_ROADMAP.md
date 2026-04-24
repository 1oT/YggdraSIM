# YggdraSIM v2 Roadmap

Post-v1 planning ledger. Every entry here is a committed future work item
with enough specification to estimate and to start on once v1 is tagged.
Casual ideas live in `NEW_FEATURE_IDEAS.md`; this file is where an idea
graduates once it is accepted as a v2 candidate.

The v2 line is additive. Nothing in v1 is deprecated by the items listed
here. The simulator must keep working with the default file-backed SGP.26
test CI material after every v2 delivery.

## Conventions

- Entries use the `R2-<NNN>` identifier scheme. Order tracks acceptance,
  not priority. Priority is explicit in the `Priority` field of each
  entry.
- Status ladder: `accepted` → `in-plan` → `in-progress` → `landed`.
  `in-plan` means the entry in this file is considered frozen and a
  dedicated `Tools/YggdraSIM/PLAN_R2-<NNN>_<slug>.md` mirror exists for
  day-to-day tracking.
- Scope / non-goal lists are authoritative. Any follow-up work outside
  those lists is a new roadmap entry, not a silent expansion.
- Every entry has acceptance criteria that map one-to-one to test cases
  or to runbook checks.
- GSMA, ETSI, and GlobalPlatform references are kept inline; readers
  should not have to chase links to validate the specification
  alignment.

---

## Index

| ID | Title | Priority | Status |
| --- | --- | --- | --- |
| R2-001 | HSM-backed signer seam for the local SMDPp | High | accepted |
| R2-002 | Signer seam follow-ups (cloud KMS providers) | Medium | accepted |
| R2-003 | Signer seam follow-ups (eUICC-side issuer chain) | Low | accepted |
| R2-004 | Universal GUI (desktop `--gui` + remote `--web-server`) | Medium | in-progress (Phase A + B + B-1/B-2/B-3 + Command Center 1st/2nd/3rd slice + G-1..G-4 SCP03 Workbench + SA-1..SA-4 SAIP Workbench + C-1..C-7 SCP03 module-parity + SIMCARD helpers + SCP11 Local workbench (read-only) + per-tab xterm + Playwright smoke skeleton landed) |

---

## R2-001. HSM-backed signer seam for the local SMDPp

### Summary

YggdraSIM's local SMDPp today reads `CERT.DPauth.ECDSA` / `SK.DPauth.ECDSA`
and `CERT.DPpb.ECDSA` / `SK.DPpb.ECDSA` directly from disk. Production
operators cannot use their GSMA-CI-issued chains against the simulator
without copying private keys onto the host — which is unacceptable
both under any approved-CI subscriber agreement (GSMA CIs require HSM
custody per their CPS; see SGP.24 §4 and the per-CI CPS published by
each approved GSMA CI operator) and under any sensible security posture.

R2-001 introduces a signer abstraction that lets an operator point
YggdraSIM at their **own** HSM (on-prem or cloud) and perform signing
through that HSM without the private key ever entering the simulator's
address space, without writing to disk, and without the YggdraSIM code
base taking custody of operator secrets at any point.

YggdraSIM ships an interface, a file-backed reference implementation
(current behaviour), and a PKCS#11 reference implementation that covers
the dominant enterprise HSM surface. The operator is responsible for
their own HSM, their own CPS alignment, and their own audit trail.

### Problem statement

Current state:

- `SCP11/local_access/config.py` and `SCP11/eim_local/config.py` resolve
  DPauth / DPpb material as filesystem paths.
- `SCP11/{local_access,eim_local}/crypto_engine.py` loads the PEM
  private key with `cryptography.hazmat.primitives.serialization.
  load_pem_private_key` and signs via that in-process key object.
- The SGP.26 test CI bundle under `SCP11/SGP.26_test_Certs/` is the only
  supported provisioning source.

Operator pain:

- An operator holding a GSMA-CI-issued SM-DP+ cert cannot exercise the
  simulator against their real trust chain without copying their
  HSM-held key onto disk. That copy is a contract breach, a compliance
  breach, and (in every jurisdiction with a telecoms compliance regime)
  a reportable event.
- Operators therefore run YggdraSIM only against SGP.26 test material,
  which means integration issues that are specific to their CI chain
  are caught late or not at all.
- There is no supported migration path from the SGP.26 test CI path to
  the operator's CI chain, even in lab environments that would
  otherwise be allowed to exercise it.

### Goals

- Define a stable `CertSigner` interface that no implementation ever
  satisfies by returning a private key object.
- Refactor SCP11 signing call sites to depend on that interface only.
- Ship a file-backed reference implementation that preserves the
  current default behaviour byte-for-byte.
- Ship a PKCS#11 reference implementation that works against any
  PKCS#11-compliant HSM (on-prem network appliance, cloud-hosted HSM
  exposed via its PKCS#11 library, or USB token). SoftHSM2 is the
  designated development and CI fixture.
- Gate the PKCS#11 dependency behind an optional extra so lean installs
  do not carry it.
- Provide a SoftHSM2-backed test fixture so CI exercises the signer
  seam against a real PKCS#11 surface, not a mock.
- Surface reachability (not secret material) via `yggdrasim-doctor`.
- Document a per-vendor integration runbook covering configuration,
  credential sourcing, and failure modes.

### Non-goals

- Native cloud KMS providers in this entry. Tracked as `R2-002`.
- Signer coverage for the eUICC-side issuer chain
  (`CERT.EUM`/`SK.EUM`). Tracked as `R2-003`.
- TLS termination. Operators who want HSM-backed TLS run a reverse
  proxy (nginx, envoy, caddy) with a PKCS#11 engine in front of the
  simulator's HTTP endpoints. YggdraSIM documents the seam, it does
  not own it.
- Key rotation automation. Operator-owned.
- Key lifecycle (generation, import, destruction). Operator-owned.
- Caching signed outputs. Every call is a fresh HSM sign operation.
- Retrieval of the public certificate chain from the HSM. Chains come
  from a PEM bundle on disk, supplied by the operator and treated as
  non-secret. This keeps the chain-load path uniform across all signer
  implementations.
- Storing any operator-supplied credential (PIN, IAM secret, key ARN,
  library path on a non-default location) inside version control.

### Trust and governance model

YggdraSIM owns: the `CertSigner` interface, the file reference
implementation, the PKCS#11 reference implementation, the configuration
schema, the doctor probes, the test fixture.

Operator owns: the HSM itself, the key objects it contains, the PIN /
credentials that unlock the HSM session, the audit trail on the HSM
side, the CPS / subscriber-agreement alignment for their chosen
YggdraSIM use case, the decision about whether simulator use is
permitted under their CI subscriber agreement at all, the network and
IAM boundaries around the HSM endpoint, the rotation schedule.

YggdraSIM therefore never:

- Reads a private key object from any source except the PEM file path
  that the legacy `FilePemSigner` consumes.
- Caches, logs, prints, marshals, serialises, or copies a private key.
- Stores a PIN, credential, or secret anywhere inside the repo or its
  default runtime root.
- Emits a log line that contains key material, signed payload preimage,
  or any HSM session identifier that would let an observer correlate
  simulator traffic with operator audit logs outside the simulator's
  own log surface.

### Architecture

```
                         +------------------------------+
                         |    CertSigner (Protocol)      |
                         |  certificate_chain_der()      |
                         |  sign_ecdsa_sha256(msg)       |
                         |  describe() -> SignerStatus   |
                         +---------------+---------------+
                                         ^
                  +---------+------------+-------------+
                  |         |                          |
           FilePemSigner  Pkcs11Signer       <future AwsKmsSigner>
          (current default)  (new, R2-001)    (R2-002)

 SCP11/local_access/crypto_engine.py  -- consumes CertSigner only
 SCP11/eim_local/crypto_engine.py     -- consumes CertSigner only
 SCP11/shared/signers/__init__.py     -- provider registry / factory
```

Provider resolution happens once at session construction. The session
caches the resolved signer for the lifetime of the session. Re-opening
a session re-resolves the signer, which lets the operator rotate the
HSM session (PIN, library path, key label) without restarting the
simulator.

### Interface definition

Python Protocol, typed, minimal, and exhaustive. The interface lives
in `SCP11/shared/signers/signer_abc.py`.

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SignerStatus:
    """Operator-visible summary of a signer, excluding any secret material."""

    provider: str
    reachable: bool
    certificate_subject: str
    certificate_issuer: str
    certificate_serial_hex: str
    certificate_not_after: str
    key_reference: str
    note: str


class CertSigner(Protocol):
    """Abstract signer interface.

    Implementations must guarantee:

    * No method returns a private key object, a raw key blob, or any
      value from which a private key can be derived.
    * ``sign_ecdsa_sha256`` signs exactly the supplied message bytes
      under SHA-256 and returns an ASN.1 DER-encoded ECDSA signature
      as defined in RFC 3279 section 2.2.3.
    * The returned certificate chain is ordered leaf-first and contains
      the full chain back to (but not including) the root trust anchor
      of the operator's choosing.
    * ``describe`` never performs a signing operation and never
      consumes a PIN. It is safe to call at startup and inside a
      doctor probe.
    """

    def certificate_chain_der(self) -> list[bytes]:
        ...

    def sign_ecdsa_sha256(self, message: bytes) -> bytes:
        ...

    def describe(self) -> SignerStatus:
        ...
```

`FilePemSigner` wraps the current `load_pem_private_key` path. Its
`describe()` reports `provider="file"`, `reachable=True`,
`key_reference=<abs path of the PEM file>`.

`Pkcs11Signer` uses `python-pkcs11` (MIT, pure-Python). Its
`describe()` reports `provider="pkcs11"`, `key_reference=<token label>:
<key label>`, and it performs a single `C_OpenSession` /
`C_FindObjects` probe to populate `reachable`. PIN is never part of
`key_reference`.

### Configuration surface

Configuration lives in `SCP11/local_access/config.py` and
`SCP11/eim_local/config.py` as new dataclass fields with file-backed
defaults so v1 behaviour is preserved.

```
CERT_PROVIDER            = file | pkcs11               # default: file
CERT_CHAIN_PATH_AUTH     = <path to DPauth PEM bundle> # provider-agnostic
CERT_CHAIN_PATH_PB       = <path to DPpb PEM bundle>   # provider-agnostic

# pkcs11 provider only
PKCS11_LIBRARY_PATH      = /usr/lib/softhsm/libsofthsm2.so
PKCS11_TOKEN_LABEL       = "yggdrasim-sim"
PKCS11_KEY_LABEL_AUTH    = "dpauth-ecdsa-p256"
PKCS11_KEY_LABEL_PB      = "dppb-ecdsa-p256"
PKCS11_PIN_SOURCE        = env:YGGDRASIM_PKCS11_PIN
                           | keyring:yggdrasim/pkcs11-pin
                           | prompt
                           | file:/run/secrets/yggdrasim-pkcs11-pin
```

Rules:

- The PIN is never stored inside the config file itself. `PKCS11_PIN_
  SOURCE` points at where YggdraSIM should read it from at session
  open.
- `file:` PIN source refuses to read a file whose permissions are
  group- or world-readable on POSIX.
- `prompt` PIN source reads via `getpass.getpass` and never echoes.
- `keyring:` uses the OS keyring (`python-keyring`). Optional extra.
- `env:` reads a single env var and wipes the local `str` after use.
  Full process env remains what it is; we cannot control the operator's
  OS, but we can avoid keeping our own second copy around.
- An unset provider's config block is never imported. An operator who
  never sets `CERT_PROVIDER=pkcs11` never triggers a `python-pkcs11`
  import and never needs the extra installed.

### Dependency and packaging model

Optional extras under `pyproject.toml`:

```
[project.optional-dependencies]
hsm-pkcs11 = [
    "python-pkcs11 >= 0.7, < 1.0",
    "asn1crypto >= 1.5, < 2.0",
]
hsm-pkcs11-keyring = [
    "keyring >= 24.0, < 26.0",
]
```

Install patterns:

- `pip install yggdrasim` — file-backed default, nothing new.
- `pip install 'yggdrasim[hsm-pkcs11]'` — enables PKCS#11 provider.
- `pip install 'yggdrasim[hsm-pkcs11,hsm-pkcs11-keyring]'` — enables
  keyring-backed PIN sourcing in addition.

The `full` extra gains `hsm-pkcs11` only; `keyring` stays opt-in so
that `full` stays installable on CI runners without a D-Bus / keyring
stack.

### Security requirements

Hard requirements, enforced in code. Each requirement maps to a test.

1. `CertSigner` has no method returning a key object. Enforced by a
   test that walks every implementation's public attributes with
   `inspect.signature` and asserts return types.
2. `FilePemSigner` rejects a PEM file whose POSIX permissions are
   world- or group-readable. Test: create a `0o644` file in a
   `tmp_path` and assert `PermissionError`.
3. `Pkcs11Signer` never receives a PIN through its constructor; PINs
   are resolved inside the PIN-source helper and held only in the
   shortest-lived local scope necessary to call `C_Login`.
4. `Pkcs11Signer.describe()` does not call `C_Login`. It only opens a
   read-only session, finds the certificate and public key objects,
   and closes the session. Test: force `C_Login` to raise via a mock
   and assert `describe()` still returns.
5. The config loader refuses to boot with `CERT_PROVIDER` set to a
   provider whose extra is not installed. Error message tells the
   operator exactly which extra to install.
6. The doctor probe never logs the PIN, never logs a session handle,
   and never dumps the raw cert. It logs the subject CN, issuer CN,
   serial (last 8 hex chars), and `not_after`.
7. No signer implementation may call `print`. All operator-visible
   output goes through the existing SCP11 logger surface.
8. `sign_ecdsa_sha256` signs only. It does not hash-then-sign a second
   time, does not re-serialise the message, and does not emit a log
   line containing the message bytes. Test: supply a 32-byte message,
   assert the PKCS#11 `mechanism=CKM_ECDSA` path is hit (not
   `CKM_ECDSA_SHA256`, which would re-hash inside the HSM).

### Testing strategy

The test matrix covers three layers.

Unit tests (always run, no HSM required):

- `tests/test_signer_protocol_surface.py` — asserts the `CertSigner`
  Protocol has no leaky methods, asserts every shipped implementation
  satisfies it, asserts no `print` or `logging.info(...key...)` calls
  are reachable.
- `tests/test_signer_file_backed.py` — regression for `FilePemSigner`
  against the existing SGP.26 fixture. Must produce byte-identical
  signatures to the current v1 code for the same input and same PEM.
- `tests/test_signer_pin_sources.py` — `env:`, `file:`, `prompt` PIN
  source helpers with a stub.
- `tests/test_signer_config_parse.py` — config dataclass parsing
  including the "extra not installed" error path.

PKCS#11 integration tests (CI only, SoftHSM2-provisioned):

- `tests/conftest.py` gains a session-scoped fixture that:
  - Locates a SoftHSM2 install, or skips.
  - Creates a tempdir-scoped token database.
  - Imports a test SGP.26 key + cert pair into a token labelled
    `yggdrasim-test`.
  - Yields the `PKCS11_*` config block the tests should use.
  - Tears the tempdir down on teardown.
- `tests/test_signer_pkcs11_roundtrip.py` — sign a known challenge,
  verify with the corresponding public key, assert byte-match against
  a stored golden signature (golden regenerated deterministically from
  the SGP.26 fixture).
- `tests/test_signer_pkcs11_reachability.py` — reachability probe hits
  (`describe()` ok), then flip the library path to `/does/not/exist`
  and assert `SignerStatus.reachable is False` with a clean error.
- `tests/test_signer_pkcs11_surface_integration.py` — drive a full
  SCP11 local-access `AuthenticateServer` handshake with the PKCS#11
  signer as the DPauth source; compare the output against the existing
  v1 golden captured from `FilePemSigner`.

The SoftHSM2 fixture gates itself on `shutil.which("softhsm2-util")`
and on a successful library load. CI runners that install SoftHSM2
(Linux Ubuntu job: `apt-get install -y softhsm2`) get the coverage;
others skip cleanly without a failure.

### Doctor integration

`yggdrasim_common/doctor.py` gains a `_probe_cert_signer` function
that, for each configured provider (auth and pb), reports:

- `ok` — `describe()` returned, `reachable=True`, chain validates
  against `CERT_CHAIN_PATH_*` (serial matches, EKU present, not
  expired).
- `warn` — reachable but chain is within 30 days of expiry.
- `warn` — reachable but EKU set does not match the expected RSP role
  OID.
- `fail` — `describe()` raised, or reachable but chain mismatch.

The probe never prompts for a PIN. It never triggers a signing
operation.

### Observability

Every signer implementation emits a single structured log line per
sign call at `info` level:

```
provider=pkcs11 sign_ok=True key_ref=yggdrasim-sim:dpauth-ecdsa-p256 \
    msg_len=32 sig_len=71 duration_ms=12.3 request_id=<uuid4>
```

No message bytes. No signature bytes. No PIN. No cert material.

`request_id` is a fresh UUID4 per call, surfaced back to the SCP11
transaction log so an operator who sees a suspect transaction can
correlate it against the HSM's own audit log by timestamp + key label.

### Documentation surface

New documents under `guides/`:

- `guides/HSM_INTEGRATION.md` — concept overview, configuration
  reference, security responsibilities, FAQ.
- `guides/HSM_WALKTHROUGH_SOFTHSM2.md` — step-by-step local setup
  using SoftHSM2 so operators can validate the integration before
  pointing at a real HSM.
- `guides/HSM_VENDOR_NOTES.md` — configuration snippets grouped by
  HSM family shape (on-prem network appliance, cloud-hosted HSM via
  its PKCS#11 library, USB token, SoftHSM2 dev fixture). Vendor names
  are intentionally not used; operators supply their own
  `PKCS11_LIBRARY_PATH` and token labels.

The walkthrough guide is the acceptance gate for the feature: if a
reader cannot follow it to a working SoftHSM2-backed signer without
touching code, the feature is not ready.

Existing documents updated:

- `README.md` — one-paragraph mention of the HSM seam with a pointer
  to `guides/HSM_INTEGRATION.md`.
- `guides/ARCHITECTURE.md` — signer layer added to the component
  diagram.
- `site-docs/concepts/rsp-architecture.md` — clarifies which
  certificates the simulator signs with and where the key material
  actually lives.
- `site-docs/subsystems/scp11-eim-local.md` and
  `site-docs/subsystems/scp11-local-access.md` — mention the signer
  seam as an extension point.
- `site-docs/reference/runtime-root.md` — new config keys listed.

### Phased delivery

Phase A — interface and file-backed parity. No behavioural change.

- Add `SCP11/shared/signers/signer_abc.py` with the Protocol + status
  dataclass.
- Add `SCP11/shared/signers/file_signer.py` as a drop-in wrapper over
  the current load-PEM behaviour.
- Refactor `SCP11/local_access/crypto_engine.py` and
  `SCP11/eim_local/crypto_engine.py` to depend on `CertSigner` and
  never hold a key object directly.
- Refactor `cert_store.py` modules to return `CertSigner` objects in
  place of `(cert_bytes, private_key)` tuples.
- Golden-signature regression test ensures byte-for-byte parity.
- Phase A ends with zero new optional dependencies and zero config
  changes for existing operators.

Phase B — PKCS#11 provider.

- Add `SCP11/shared/signers/pkcs11_signer.py`.
- Add PIN-source helpers in `SCP11/shared/signers/pin_sources.py`.
- Extend `SCP11/local_access/config.py` and
  `SCP11/eim_local/config.py` with the new config keys, defaulting
  `CERT_PROVIDER=file`.
- Add SoftHSM2 fixture to `tests/conftest.py`.
- Add PKCS#11 integration test suite.
- Add doctor probe.
- Phase B ends when `yggdrasim-doctor` reports `ok` against the
  SoftHSM2 walkthrough setup.

Phase C — documentation and hardening.

- `guides/HSM_INTEGRATION.md` + walkthrough + vendor notes.
- `README.md` / `site-docs/` updates.
- Per-vendor notes validated with at least one end-to-end run against
  SoftHSM2 + one end-to-end run against the operator's chosen real HSM
  (operator-sided sign-off, not a YggdraSIM CI job).
- Phase C ends with the vendor notes reviewed and the internal link
  checker green.

### Acceptance criteria

Each criterion maps to a test file or a runbook step.

1. `CertSigner` interface exists and is enforced at import time by
   `tests/test_signer_protocol_surface.py`.
2. `FilePemSigner` produces byte-identical signatures to v1 for the
   SGP.26 fixture. Covered by
   `tests/test_signer_file_backed.py`.
3. `Pkcs11Signer` produces a valid signature against the SoftHSM2
   fixture that verifies under the matching public key. Covered by
   `tests/test_signer_pkcs11_roundtrip.py`.
4. Doctor reports `ok` for both DPauth and DPpb signers against the
   SoftHSM2 fixture and `fail` with a clean, actionable message when
   the library path is wrong. Covered by
   `tests/test_signer_pkcs11_reachability.py`.
5. `pip install yggdrasim` works without `python-pkcs11` present, and
   attempts to use `CERT_PROVIDER=pkcs11` fail at config load with a
   message naming the missing extra.
6. `guides/HSM_WALKTHROUGH_SOFTHSM2.md` can be followed from a clean
   Linux box to a working doctor probe without touching code. Runbook
   check.
7. No log line in any signer, cert_store, or crypto_engine path
   contains PIN, private key bytes, or message bytes. Covered by
   `tests/test_signer_protocol_surface.py` (static log scan).
8. `mkdocs build --strict` passes with the new documents in the nav.
9. All existing SCP11 tests remain green. The full v1 test suite
   passes.
10. The feature is fully opt-in — a v1 user who does nothing sees
    identical behaviour to v1.

### Risks and mitigations

- **Risk: `python-pkcs11` lags behind vendor PKCS#11 library
  revisions.** The library is mature but single-maintainer. Mitigation:
  keep the `Pkcs11Signer` surface tight (open session, find cert, find
  key, sign, close), isolate `python-pkcs11` imports behind a narrow
  adapter module, document the exact version range in
  `guides/HSM_INTEGRATION.md` and pin it in the optional extra.
- **Risk: operator misconfigures the PIN source and the PIN leaks into
  a log.** Mitigation: the PIN-source helper is the only code path
  that ever sees the PIN, every other module receives the
  authenticated session handle instead; the helper is tested against
  a log-capture fixture.
- **Risk: vendor PKCS#11 library fails to load inside a PyInstaller
  bundle.** Mitigation: the feature is not claimed for the PyInstaller
  bundle at all; operators who want HSM-backed signing install from
  pip. `guides/HSM_INTEGRATION.md` states this explicitly.
- **Risk: SoftHSM2 unavailable on the CI runner.** Mitigation: the
  fixture skips cleanly on `which softhsm2-util` miss. The Linux CI
  job installs `softhsm2` so coverage exists somewhere.
- **Risk: signed-output provenance** (a BPP minted against the real CI
  chain is indistinguishable from a production BPP). Mitigation:
  explicit operator responsibility documented in
  `guides/HSM_INTEGRATION.md`. YggdraSIM cannot enforce this — it is
  an operator governance question — and the guide states that bluntly.
- **Risk: refactor regression** (the file-backed path stops producing
  the exact same signatures). Mitigation: golden-signature regression
  test, run in Phase A before any other work starts.

### Open questions

- Should the `describe()` call include the chain's CRL distribution
  points so that the doctor probe can flag unreachable CRL endpoints?
  Leaning yes, but it requires a network call inside the doctor probe
  which we have deliberately avoided so far.
- Should `Pkcs11Signer` support loading the public certificate from
  the HSM itself when the HSM stores a matching X.509 object, rather
  than always reading it from disk? Argument for: some operators keep
  the chain inside the HSM for atomic rotation. Argument against: the
  chain is not secret and reading it from disk removes an entire class
  of HSM-vendor quirks.
- Whether to auto-enable `hsm-pkcs11` in the `full` extra. Current
  intention is yes (one-stop install for maintainers), but CI runners
  without a native PKCS#11 library may fail to build
  `python-pkcs11`'s C extension. Resolution pending a CI dry run.

### Estimated effort

Phase A — 2 engineering days.
Phase B — 4 engineering days including SoftHSM2 fixture and integration
tests.
Phase C — 2 engineering days including vendor note collection and
cross-checks.

Total — 8 engineering days, assuming no vendor-specific blockers.

---

## R2-002. Signer seam follow-ups — cloud KMS providers

### Summary

Extend the `CertSigner` seam delivered in `R2-001` with native
providers for the major public-cloud KMS services (i.e. managed
key-signing services that expose ECDSA-P256 + SHA-256 behind an IAM
surface). Operators running fully in-cloud who do not want to manage a
PKCS#11 surface (the PKCS#11 path from `R2-001` remains available when
the cloud provider exposes its HSM via a PKCS#11 library) can point
YggdraSIM at a cloud KMS key handle directly.

### Prerequisites

- `R2-001` landed and stable.

### Goals

- Ship one `CertSigner` adapter per supported public-cloud KMS
  platform. Each adapter uses that platform's official Python SDK,
  selects the ECDSA + SHA-256 signing algorithm, and normalises the
  returned signature to DER.
- Gate each adapter behind its own optional extra of the form
  `hsm-cloud-<short-tag>` so lean installs do not pull cloud SDKs.
- Per-adapter doctor probes that call the platform's key-describe or
  key-metadata endpoint (never a sign call) to verify reachability and
  that the configured key handle is active.

### Non-goals

- Hybrid routing across clouds (signer mirroring / failover).
  Operator-owned if needed.
- IAM / role / principal management. Operator-owned.
- Inline credential rotation. Default credential chain for each SDK
  handles this out of the box.

### Notes

- Public-cloud KMS platforms differ on ECDSA signature encoding: some
  return DER directly, others return the raw `r||s` JWS form that
  must be re-encoded to DER before return. The adapter layer
  normalises to DER so the SCP11 callers never see the difference.
- None of the public-cloud KMS platforms expose the public key in
  DER-with-chain form, so the certificate chain continues to come
  from a PEM file per `R2-001`'s model.

### Estimated effort

3 engineering days per adapter, plus 1 day of shared test
infrastructure (either per-platform local emulators where available,
or a mocked transport otherwise).

---

## R2-003. Signer seam follow-ups — eUICC-side issuer chain

### Summary

`R2-001` and `R2-002` cover the SM-DP+ side (DPauth, DPpb). Extend the
signer seam to the eUICC-side issuer chain (`CERT.EUM`, `SK.EUM`, plus
the per-eUICC `CERT.EUICC` signing path used by the SIMCARD simulator
when it plays an eUICC that holds an EUM-issued chain).

### Prerequisites

- `R2-001` landed.
- SIMCARD engine's current internal key handling audited to identify
  every place a private key is consumed.

### Goals

- Extend `CertSigner` usage into `SIMCARD/sgp.py` and
  `SCP11/shared/signers` to cover eUICC-issuer operations.
- Ship PKCS#11 reference implementation coverage for
  `id-rspRole-euicc` and `id-rspRole-eum` EKUs.
- Doctor probe coverage.

### Non-goals

- eUICC-side TLS. Out of scope; the simulator does not terminate TLS
  on the eUICC side.
- Key agreement (ECKA-CG) against an HSM. ECKA requires a
  `DeriveKey` call which many PKCS#11 libraries implement
  inconsistently; tracked as a separate future entry if demand
  materialises.

### Estimated effort

4 engineering days, dependent on the SIMCARD audit outcome.

---

## R2-004. Universal GUI (desktop `--gui` + remote `--web-server`)

### Summary

Add a single web-based frontend that talks to a thin FastAPI layer
wrapping the existing YggdraSIM core. The same frontend launches in
two modes off one entry point:

- `yggdrasim --gui` — desktop mode. FastAPI binds to loopback only;
  `pywebview` opens the SPA in a native OS WebView window (GTK /
  WebKit2 on Linux, Edge on Windows, WKWebView on macOS). No browser
  tab, no exposed port, no Electron-class RAM cost.
- `yggdrasim --web-server` — remote lab mode. FastAPI binds to an
  operator-chosen interface with mandatory bearer token and strongly
  recommended TLS / SSH-tunnel. No `pywebview` window.

The engine stays headless. The CLI, the shell surfaces, and the
installed console scripts keep working byte-for-byte. The GUI is a
pure additive layer that resolves subsystem entry points through the
existing `yggdrasim_common.registry` and streams interactive shells
(SCP03, SCP11 live / test / local / eIM, SCP80, SAIP) over a
WebSocket-backed `xterm.js` terminal. HIL bridge capture views
(`raw`, `raw + Wireshark`, decoded TUI) are exposed through a
thin websocket over the existing bridge-runtime helpers.

### Status

`in-plan` — full design frozen in `V2_UNIVERSAL_GUI_PLAN.md` at the
repository root. That document is the day-to-day tracking mirror for
this entry per the roadmap's `in-plan` convention.

### Ports and loopback policy

The GUI avoids every existing claim in the tree:

| Subsystem                    | Claimed bind         |
| ---------------------------- | -------------------- |
| HIL bridge                   | `127.0.0.1:9997`     |
| SCP11 relay URL default      | `127.0.0.1:8080`     |
| GSMTAP mirror                | `127.0.0.1:4729/udp` |
| eIM poll bridge DNS stub     | `127.0.0.1:15353`    |
| eIM poll bridge eIM TLS      | `127.0.0.1:18443`    |
| eIM poll bridge SM-DP+ TLS   | `127.0.0.1:19443`    |
| HIL card relay fixtures      | `127.0.0.1:44215`    |

GUI defaults:

- `YGGDRASIM_GUI_PORT` (desktop) — `27853`
- `YGGDRASIM_GUI_SERVER_PORT` (server) — `27854`
- Desktop mode auto-falls back to an OS-assigned ephemeral port on
  `EADDRINUSE`. Server mode refuses to silently rebind.
- Optional loopback isolation: `YGGDRASIM_GUI_HOST=127.0.0.7` on
  Linux / macOS, documented but not forced (Windows cannot bind
  `127.0.0.2+` out of the box).

### Non-goals

- Replacing the CLI / shell. The CLI stays the supported operator
  surface and the source of truth for command semantics.
- Multi-user RBAC. Token auth is a single-secret bearer gate,
  consistent with the rest of the suite's operator-owned posture.
- Public internet hosting. `--web-server` is a **lab** surface; TLS
  and / or SSH tunnelling are documented as non-optional for any
  untrusted network.
- Reimplementing subsystem logic. The GUI resolves through the
  existing registry; it navigates and visualises, it does not
  duplicate SCP03 / SCP11 / SAIP code.

### Dependencies

- Nothing in this file today. Plays cleanly next to `R2-001` because
  both only touch integration surfaces — the signer seam lands inside
  SCP11 crypto engines, the GUI lands inside a new
  `yggdrasim_common/gui_server/` module.

### Packaging impact (summary)

- New optional extras: `gui` (adds `pywebview`), `gui-server`
  (headless lab server; no `pywebview` so GTK / Qt / WebKit are not
  required).
- `full` extra gains `fastapi`, `uvicorn`, `pywebview`, `websockets`
  so the HIL-capable Linux bundle covers both modes.
- `clean` bundles unchanged at install time; the launcher prints a
  pointer to `yggdrasim[gui]` when `--gui` is invoked without the
  extra installed.
- PyInstaller hook ships the frontend static bundle and the active
  `webview.platforms.*` backend. HIL flavor rules unchanged.
- Docker gains a `--build-arg YGGDRASIM_GUI=1` that pulls
  `yggdrasim[gui-server]` and exposes `27854`.

### Phased delivery

Per `V2_UNIVERSAL_GUI_PLAN.md` §15:

- Phase A — API scaffolding (health / registry / backend), config,
  token auth, unit tests. No UI yet. ~3 days.
- Phase B — desktop mode end-to-end with a minimal SPA. ~4 days.
- Phase C — WebSocket shell streaming + SAIP + HIL views. ~5 days.
- Phase D — remote server mode with TLS, token enforcement,
  rate-limit, access log. ~3 days.
- Phase E — packaging, doctor probe, documentation pass,
  `mkdocs build --strict`. ~2 days.

Total effort estimate: **17 engineering days**, assuming no
vendor-specific pywebview blockers. See the plan file for the
per-phase acceptance criteria that map one-to-one to test files.

### Acceptance criteria (top-level)

Full list in `V2_UNIVERSAL_GUI_PLAN.md` §16. The gating checks are:

1. `python main/main.py --gui` opens a native window without touching
   the system browser and binds only loopback.
2. `python main/main.py --web-server` refuses to start without a
   strong token, honours `--tls-cert` / `--tls-key`, and never
   exposes the token in logs.
3. `python main/main.py` with no flags behaves identically to today.
4. Ports `4729 / 8080 / 9997 / 15353 / 18443 / 19443 / 44215` remain
   free after the GUI is up in either mode.
5. `pip install yggdrasim` (no extras) keeps working and the CLI does
   not import `fastapi`, `uvicorn`, or `pywebview` at module load.
6. `yggdrasim --doctor` reports the GUI stack state accurately in
   both installed and uninstalled shapes.
7. All existing tests stay green. New GUI tests follow the workspace
   90 s / narrow-scope pytest policy.

### Open questions (carried over from the plan)

- Final frontend framework: Vue 3 vs Svelte. Decide during Phase A
  prototype.
- `--web-server` default bind host: `0.0.0.0` with a banner versus
  `127.0.0.1 + SSH tunnel` by default.
- Third combined mode (`--gui --web-server`): desktop window plus
  remote LAN API for demos. Parked, may graduate into a future
  roadmap entry.

See `V2_UNIVERSAL_GUI_PLAN.md` for the full design, port rationale,
security posture, REST surface sketch, risks, and change log.

---

## Change log

| Date | Change |
| --- | --- |
| 2026-04-19 | Initial file. `R2-001`, `R2-002`, `R2-003` added as accepted entries. |
| 2026-04-21 | `R2-004` added (`in-plan`), mirroring `V2_UNIVERSAL_GUI_PLAN.md`. |
| 2026-04-23 | `R2-004` Phase A + Phase B desktop + Milestones B-1 (engine panels) / B-2 (xterm.js PTY bridge) / B-3 (live readers + download-profile flow) landed. Remaining: Phase C (saIP decoded editor, HIL surface, remaining shells) and Phase D (web-server polish). |
| 2026-04-23 | `R2-004` Command Center first slice landed: typed action registry + `/api/actions[/{id}/run|/stream]` routes + card-session manager + 4 flagship actions (`scp03.scan`, `scp03.read_selected`, `scp11.download_profile`, `eim_local.poll_campaign`). SPA gains a Command Center nav with auto-generated forms, scan-tree + FCP + hex viewers, and structured log-stream panels. `FileSystemController.scan_tree(return_tree=True)` added as an opt-in (CLI path unchanged). Tests: `tests/test_gui_actions.py` (25 unit + 9 HTTP, 90 s-capped, FastAPI-optional). |
| 2026-04-23 | `R2-004` Command Center second slice landed: six engine-tool actions (`tool.tlv.decode`, `tool.sw.lookup`, `tool.euicc_info2.decode`, `tool.saip.lint`, `tool.eim.lint`, `tool.gsma.codes`) wrap the pure-function helpers already backing `/api/tools/*`; three session-based SCP03 extensions (`scp03.select`, `scp03.list_apps`, `scp03.close_session`); three `eim_local` helpers (`list_fixtures`, `hotfolder_metadata`, `issue_package`). New SPA renderers: `tlv_tree` (collapsible BER-TLV), `findings` (severity-pilled SAIP lint), `key_value_lines` (indented EUICCInfo2 detail/validation). Catalogue grows from 4 → 16 actions. Tests: `tests/test_gui_actions.py` gains `TestEngineToolDispatchers` (7 cases) + `TestScp03CloseSessionDispatcher` (2 cases); 35 unit tests total, 9 HTTP skipped without the `gui` extra. |
| 2026-04-23 | `R2-004` Command Center third slice landed: five SCP11 live read-only actions — `scp11_live.get_eid` (ECASD tag 5A → stripped BCD), `scp11_live.list_profiles` (BF2D00 → ICCID/state/class/nickname table), `scp11_live.get_smdp` (BF3C00 → default SM-DP+ / SM-DS + OID lines), `scp11_live.list_notifications` (BF2800 → pending queue), `scp11_live.euicc_info2` (BF2200 → shared detail-lines renderer). Each action opens a short-lived `PcscApduChannel`, runs through `SGP22Orchestrator`, and disconnects in `finally` — no long-lived live session state in the Command Center tier. Profile-row decode ported from `SCP11/live/console.py` (shares `SCP03.core.utils.TlvParser`). Three HIL bridge surfaces: `hil.supervisor_status` (snapshot of `hil_bridge_supervisor.json` → key/value lines), `hil.bridge_status` (HTTP probe of the relay status URL), `hil.watch_supervisor` (streaming: one diff event per poll cycle). Pre-existing `scp11.download_profile` bug fixed — was calling non-existent `card_backend.connect_card_backend` / `ensure_live_config`; now uses `PcscApduChannel(reader_index=…)` + `dataclasses.replace(SGPConfig(), READER_INDEX=…)`. Catalogue grows from 16 → 24 actions. Tests: `tests/test_gui_actions.py` gains `TestHilSupervisorHelpers`, `TestHilDispatchers`, `TestHilWatchSupervisorStream`, `TestScp11LiveDecoders`, `TestScp11LiveRegistration` (25 new cases, 58 unit total, 9 HTTP skipped without `gui` extra; supervisor snapshot + relay HTTP probe `monkeypatch`-injected so no hardware or systemd needed). |
| 2026-04-23 | `R2-004` SCP03 Workbench layout (G-1..G-4) landed: workbench shell with reader pane + status bar + bottom log dock + per-tab event-bus (`/api/readers`); ribbon-grouped action bar replacing the inline action cards; scan-tree breadcrumb + reader-pane context menu + double-click-to-open-tab; APDU trace piped into the bottom-log "APDU" tab via the existing `scp11_live.*` trace sinks; visual in-flight state per ribbon action. Dispatcher ids and HTTP shape unchanged. |
| 2026-04-23 | `R2-004` SAIP Workbench (SA-1..SA-4) landed. SA-1 (read-only): `saip.open_package` / `list_pes` / `show_pe` / `list_files` / `show_file` / `validate` / `close_package`. SA-2: package drawer + numbered PE list + main-area tabs + bottom validation dock. SA-3 (editor + save): `saip.update_file_field` + `saip.save_package` (writes through `Tools/ProfilePackage/saip_transcode_sync.py`); per-PE dirty-state tracking via `saip.get_dirty`; `saip.revert_changes` restores per-PE baseline. SA-4: `saip.compare` (PE/FS/field-level diff over two package sessions) + `saip.list_variables` / `saip.set_variable` (placeholder editor backed by `saip_profile_template.py`). SAIP package sessions live alongside SCP03 sessions in the same `SessionManager`. |
| 2026-04-23 | `R2-004` SCP03 module-parity slices (C-1..C-4, 45 actions total) landed — daily card workflows no longer need the raw terminal. C-1 (8 read-only telemetry): `scp03.atr` / `card_info` / `reset` / `decode` / `read_binary` / `read_record` / `arr` / `dump_fs`. C-2 (10 auth + GP registry + profile telemetry): `auth_scp03` / `auth_scp02` / `logout` / `keys`; `registry_apps` / `registry_pkgs` / `registry_sd` / `get_data` / `list_aids`; `list_profiles` / `profile_scan`. `GlobalPlatformManager` is lazily built per session and cached on `session.handle["gp"]`; key material is read from the inventory `scp03_config` module-state on first build. C-3 (11 mutation + validation + exports): `set_status` / `lock` / `unlock` / `delete` / `store_data`; `update_binary` / `update_record`; `validate` / `cert_info`; `export_euicc` / `export_keybag`. All mutations check `_require_auth_session` and surface a destructive banner; `delete` requires a typed-back confirm. C-4 (16 actions): eUICC telemetry — `get_eid` / `get_euicc_certs` / `get_euicc_configured_data` / `get_sgp32_all_data`; profile lifecycle — `enable_profile` / `disable_profile` / `delete_profile` (typed-back confirm); snapshots / gold profile — `set_gold_profile` / `show_gold_profile` / `clear_gold_profile` / `profile_diff` (eUICC-scope first pass; persistence reuses the inventory `scp03_config` module-state shared with the shell GOLD-PROFILE wizard); offline crypto — `derive_opc` / `run_auth_test_vector` (3GPP TS 35.207 Milenage vector with derived OPc / RES / CK / IK / Kc / AUTN / USIM-AUTH-APDU / USIM-AUTH-RESPONSE); Tier-3 admin — `show_config` (KEYS + GOLD_PROFILE + AID registry, with `mask_secrets` toggle), `set_aid_alias` (add / update / delete in `aid.txt`), `set_defaults` (RESET-confirmed key wipe; invalidates cached `gp` on live SCP03 sessions). Native pickers: fields with `kind="path"` / `"directory"` / `"save_path"` open the matching pywebview dialog (`window.pywebview.api.pick_file` / `pick_folder` / `save_file`) on Browse… click or input double-click; backend treats all three as plain strings via `coerce_input`. Catalogue grows from 24 → 117 actions across SCP03 (51) / eSIM Live (38) / SAIP (14) / Tools (6) / Local eIM (4) / HIL (3) / SCP11 (1). |
| 2026-04-23 | `R2-004` SCP03 module-parity slices C-5..C-7 landed (25 new actions + 2 sub-shell shortcuts). **C-5 — Mutation depth (16 actions)**: `scp03.put_key`; `install_cap` / `install_app` / `install_make_selectable` / `install_extradition` / `install_personalization` / `install_registry_update`; `fs_create_file` / `fs_delete_file` / `fs_resize` / `fs_lifecycle` / `fs_search_record` / `fs_suspend_uicc`; `manage_pin` / `manage_channel`; `run_auth_live`. Three new ribbon groups ("Install", "FS-Admin", "Live AAA") with typed-back confirmations on every destructive path. `scp03BuildInlineForm` extended to support `"select"` / `"bool"` / `"textarea"` / `"number"` kinds; 20 HTTP guard smoke cases pass. **C-6 — Sub-shell handoffs (2 shortcuts)**: `scp03.stk_shell` (SCP03 → auto-typed `STK-SHELL`) and `scp03.ota_shell` (`python -m SCP80`) under a new "Sub-shells" ribbon group reuse the B-2 PTY bridge instead of embedding per-tab xterms. **C-7 — QoL + adjacent (7 actions)**: SCP03 side — `scp03.run_script` (in-process `entry_cmd`), `scp03.fs_report` (YAML via `FileSystemController.generate_report`), `scp03.guide_list` + `scp03.guide_show` (captured `ShellGuides` topics). New `SIMCARD` subsystem — `simcard.quirks_status`, `simcard.profile_store_list`, `simcard.euicc_store_list`, `simcard.tuak_derive_topc` (pure 3GPP TS 35.231 derivation). 15 in-process smoke cases pass. Catalogue grows from 117 → 141 actions across SCP03 (71) / eSIM Live (38) / SAIP (14) / Tools (6) / SIMCARD (4) / Local eIM (4) / HIL (3) / SCP11 (1). |
| 2026-04-23 | `R2-004` pre-C-5 carry-overs cleared. **SCP11 Local workbench (7 read-only actions)** — new `SCP11 Local` subsystem wraps `SCP11.local_access.session.LocalIsdrSession` for daily offline drive-by reads: `scp11_local.get_eid` (ISD-R SELECT + ECASD 5A), `list_profiles` (BF2D00 with per-E3 decode via `decode_profile_metadata_rows`), `get_euicc_info2` (BF2200 rendered through the shared `SCP03.logic.euicc_info2.build_euicc_info2_detail_lines` key/value lines), `get_configured_data` (BF3C00 → default SM-DP+ / primary + additional SM-DS / allowed CI PKIDs), `list_notifications` (BF2B00 raw-hex), `get_certs_inventory` (pure filesystem scan of the local SGP.26 DPauth / DPpb bundle), `discover` (one-shot snapshot). Mirrors the `scp11_live` per-call PC/SC channel pattern (open → probe → disconnect); write / mutation surfaces (enable / disable / delete / metadata) stay deferred for a confirmation-gate pass. **Per-tab xterm** — the B-2 terminal view is now multi-tab. Each "Open tab" click creates a fresh `.terminal-pane` with its own `Terminal`, `FitAddon`, `WebSocket`, `module`, `pid`, and `status`; a pill-style tab strip over the host handles switch / close, and window resize re-fits only the visible pane. `terminalState.pendingInit` is promoted to a top-level `terminalPendingBootstrap` so C-6 sub-shell handoffs (`scp03.stk_shell` / `scp03.ota_shell`) deterministically seed the NEXT-spawned tab regardless of which tab the user has focused. Stale global-state callers fall through the legacy-alias shim. **Playwright smoke** — `tests/test_gui_playwright_smoke.py` ships a self-skipping end-to-end smoke that spins `uvicorn` on a loopback port (reusing the real `create_app` factory), drives the SPA with a headless Chromium, and verifies the Command Center nav renders the new `SCP11 Local` subsystem with its seven action cards. Cleanly skips with an actionable reason string whenever `playwright` or the Chromium binary is missing, so CI stays green until the headless lane is wired. Catalogue grows 141 → 148 actions across SCP03 (71) / eSIM Live (38) / SAIP (14) / SCP11 Local (7) / Tools (6) / SIMCARD (4) / Local eIM (4) / HIL (3) / SCP11 (1). |

## See also

- `V1_FEATURE_PLAN.md` — landed v1 feature plan.
- `V1_RELEASE_AUDIT.md` — v1 audit log, source of several post-v1
  carry-over items.
- `NEW_FEATURE_IDEAS.md` — unaccepted idea parking lot. Entries that
  graduate to v2 scope move here and leave a breadcrumb line in the
  ideas file.
- `V2_UNIVERSAL_GUI_PLAN.md` — full design mirror for `R2-004`
  (universal GUI / FastAPI + pywebview).
- `guides/ARCHITECTURE.md` — architecture overview updated as v2
  entries land.
