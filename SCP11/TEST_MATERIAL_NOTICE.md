<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SCP11 -- Test Material Notice (GSMA SGP.26)

> **No SGP.26 certificate, private key, or reference bundle is tracked in
> this repository.** Every `*.pem`, `*.der`, `*.crt`, and `*.key` path
> under `SCP11/`, and the whole `SCP11/SGP.26_test_Certs/` tree, is
> gitignored. An operator supplies the material locally.

A reviewer who arrives here after seeing SGP.26 paths referenced in the
source is looking at path references, not at committed material. The
repository ships no key material of any kind.

## Where the material goes

Place the GSMA SGP.26 reference release at:

```
SCP11/SGP.26_test_Certs/
├── Valid Test Cases/
│   └── Variant O/SM-DP+/{SM_DPauth,SM_DPpb}/...
└── Invalid Test Cases/
```

`SCP11/local_access/config.py` seeds a copy into the runtime workspace
(`Workspace/SCP11/SGP.26_test_Certs/Valid Test Cases`) on first use.
Seeding is best-effort: with no source tree the workspace directory is
created empty and nothing is copied, so the absence is never fatal.

Envelope encryption is supported. `read_secret_file_bytes` decrypts a
PGP-wrapped payload in place, so an encrypted certificate occupies the
same path as a plaintext one and needs no separate handling.

## What happens without it

The suites that need the bundle skip rather than fail.
`tests/sgp26_support.py` probes the four files those suites read -- the
Variant O NIST auth and profile-binding certificate and key pair -- and
raises `SkipTest` naming the first missing path. A checkout without the
material runs the full suite green, with those cases reported as
skipped.

Do not guard on the directory existing. The tree can be present and
empty, which is what a seeded workspace produces.

## Provenance and limits

The GSMA SGP.26 material is published test material. It is not
production material and must not be used against live SM-DP+, SM-DS, or
SM-SR+ infrastructure; live deployment requires GSMA-issued production
credentials. SGP.26 rotates its published keys from time to time, so
refresh from the GSMA reference release rather than treating a local
copy as durable.

Operator-supplied and inventory-encrypted credentials are a separate
concern and live under `Workspace/` and `state/`, which are also
gitignored.

## Pointers

- GSMA SGP.26 reference test material: <https://www.gsma.com/esim/sgp-26/>
- SGP.22 RSP architecture: GSMA SGP.22.
- ETSI TS 102 221 / 222 / 223 / 226 -- APDU and toolkit framing.
- GlobalPlatform Card Specification v2.3 -- secure-channel framing.
