<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Local-Access RSP Certificate Drop Zone

Drop operator-owned `DPauth` / `DPpb` certificates and matching private
keys here for the `SCP11/local_access` shell (`LOAD-PROFILE` against
`ISD-R`).

## Quick start

1. Drop the certificate and matching private key in this folder using
   any readable filename.
2. Add a sidecar metadata file beside the certificate, named either
   `<certificate>.meta.json` or `<certificate-stem>.meta.json`.
3. Verify with the shell's `CERTS` verb (alias `SMDP-CERTS`):

   ```bash
   yggdrasim-scp11-local-access --cmd "STATUS; CERTS; EXIT"
   ```

   Add `--json` or `--yaml` to `CERTS` for machine-readable output.

The legacy SGP.26 filenames `CERT.DPauth.ECDSA.der` /
`SK.DPauth.ECDSA.pem` and `CERT.DPpb.ECDSA.der` /
`SK.DPpb.ECDSA.pem` continue to work without a sidecar. The DPauth
pair is required for `AuthenticateServer`. The DPpb pair is optional;
present it when the local flow needs to sign download-side payloads
such as `PrepareDownload`.

## Sidecar fields (most common)

| Field              | Purpose                                                                |
| ------------------ | ---------------------------------------------------------------------- |
| `role`             | `auth` or `pb`. Inferred from filename when omitted.                   |
| `private_key_path` | Absolute, or relative to this directory.                               |
| `root_ci_pkid`     | Hex SKI used for card matching. Falls back to the cert's AKI.          |
| `server_address`   | Optional local SM-DP+ address surfaced to the eIM activation code.     |

## Canonical reference

The full sidecar schema, selection order (operator drop-in vs SGP.26
bundle, curve preference, AKI/SKI tie-breaks), and BYO-keys checklist
all live in the canonical operator guide:

- [`guides/CONFIGURATION_AND_CERTIFICATES.md`](../../../guides/CONFIGURATION_AND_CERTIFICATES.md)
  — § *SCP11 RSP certificates (local-access)*

Selector code: [`SCP11/local_access/cert_store.py`](https://github.com/1oT/YggdraSIM/blob/main/SCP11/local_access/cert_store.py).

Operator workflow: [`guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`](../../../guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md).
