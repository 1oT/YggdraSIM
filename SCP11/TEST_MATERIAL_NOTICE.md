# SCP11 -- Test Material Notice (GSMA SGP.26)

> **`*.pem`, `*.der`, `*.crt`, and `*.key` files in `SCP11/` and
> `SCP11/SGP.26_test_Certs/` are the publicly-known GSMA SGP.26 test
> certificates and private keys.**
>
> They are intentionally tracked because they are required for
> reproducible SGP.26 conformance validation and lab bring-up. **They
> are not production material and must not be used against live
> infrastructure.**

## What is in scope

The following files are GSMA SGP.26 public test material:

- `SCP11/SK.DPauth.ECDSA.pem` -- SM-DP+ authentication private key
  (test variant; published as part of SGP.26 test material).
- `SCP11/SK.DPpb.ECDSA.pem` -- SM-DP+ profile-binding private key
  (test variant; published as part of SGP.26 test material).
- `SCP11/CERT.DPauth.ECDSA.der` -- SM-DP+ authentication certificate
  signed by the SGP.26 test CI.
- `SCP11/CERT.DPpb.ECDSA.der` -- SM-DP+ profile-binding certificate
  signed by the SGP.26 test CI.
- `SCP11/ES9_TEST_CI_CA.pem` -- SGP.26 test CI root used for the
  ES9+/ES10 certificate chain inside the local test mode.
- Everything below `SCP11/SGP.26_test_Certs/` -- the OpenSSL `*.cnf`
  inputs (CSR / extension config) that build the corresponding
  `.pem` / `.der` material on demand. The generated key and
  certificate files themselves are gitignored and rebuilt locally
  (see `SCP11/SGP.26_test_Certs/Valid Test Cases/build.sh` and the
  matching invalid-case helpers).

The `SCP11/local_access/certs/`, `SCP11/eim_local/certs/`, and
`SCP11/test/certs/` subtrees follow the same posture: they hold either
GSMA-published test material or material derived from it via the SGP.26
config files. Their READMEs already mark the directories as test-only,
but the same rule applies -- **do not deploy on production keys.**

## Why it ships in the repository

- `SCP11/test/`, `SCP11/local_access/`, and `SCP11/eim_local/` shells
  default to the SGP.26 test profile so that operators can exercise
  end-to-end ES9+/ES10 flows offline without rebuilding a full PKI.
- `tests/test_scp11_sgp26_provider.py` validates the loader against
  the published SGP.26 test fixtures.
- The published `SK.*.pem` keys are the only cryptographic material
  that allows `tests/` to verify ES9+ signature paths deterministically.

## What this notice is NOT

- It is **not** a permission to use these keys against live SM-DP+ or
  SM-SR+ infrastructure. Live deployment requires GSMA-issued
  production credentials.
- It is **not** a promise that the test material will remain valid
  forever. SGP.26 occasionally rotates published test keys; refresh
  from the GSMA reference release when that happens.
- It is **not** an indication that any other `*.pem` / `*.der` file in
  the repository is also test material. Operator-supplied or
  inventory-encrypted credentials live under `Workspace/` and
  `state/` and are gitignored.

## Pointers

- GSMA SGP.26 reference test material: <https://www.gsma.com/esim/sgp-26/>
- SGP.22 RSP architecture: GSMA SGP.22.
- ETSI TS 102 221 / 222 / 223 / 226 -- APDU and toolkit framing.
- GlobalPlatform Card Specification v2.3 -- secure-channel framing.

If a security-conscious reviewer files an issue about these files, link
this notice in the response.
