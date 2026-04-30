# eIM-Local RSP Certificate Drop Zone

Drop operator-owned `DPauth` / `DPpb` certificates and matching private
keys here for the eIM local profile-loading path (`SCP11/eim_local`).

## Quick start

1. Drop the certificate and matching private key in this folder using
   any readable filename.
2. Add a sidecar metadata file beside the certificate, named either
   `<certificate>.meta.json` or `<certificate-stem>.meta.json`.
3. The eim-local shell does not expose a dedicated DPauth / DPpb
   inventory verb (the selector is exercised silently when the flow
   runs). Verify functionally by running the flow:

   ```bash
   yggdrasim-scp11-eim-local --cmd "STATUS; LOAD-PROFILE; EXIT"
   ```

   For the eIM **signing** inventory under `eim/`, use `EIM-CERTS`
   instead — see [`eim/README.md`](eim/README.md).

The drop-in pattern, sidecar fields, fallback rules, and selector
behaviour are **identical** to the local-access cert zone — the
eim-local shell reuses the same record schema. The only behavioural
difference is that the selected DPauth `server_address` is mirrored
into the eIM activation code when the package does not pin a
different `smdp_address`.

The legacy SGP.26 filenames `CERT.DPauth.ECDSA.der` /
`SK.DPauth.ECDSA.pem` and `CERT.DPpb.ECDSA.der` /
`SK.DPpb.ECDSA.pem` continue to work without a sidecar.

## Sub-directories

- [`eim/`](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/SCP11/eim_local/certs/eim) — operator-issued **eIM signing certificates** for
  `ADD-INITIAL-EIM` / `ADD-EIM`. Different selector
  (`EimCertificateStore`). See the README in that directory and the
  canonical guide.
- [`addeim/`](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/SCP11/eim_local/certs/addeim) — bundled fake-eIM identity sheet and template
  for `AddEim` package authoring.

## Canonical reference

- [`guides/CONFIGURATION_AND_CERTIFICATES.md`](../../../guides/CONFIGURATION_AND_CERTIFICATES.md)
  — § *SCP11 RSP certificates (eim-local)* and § *Local eIM signing
  certificates*.

Selector code:

- [`SCP11/local_access/cert_store.py`](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/SCP11/local_access/cert_store.py)
  (DPauth / DPpb)
- [`SCP11/eim_local/eim_cert_store.py`](https://github.com/hampushellsberg-dev/YggdraSIM/blob/main/SCP11/eim_local/eim_cert_store.py)
  (eIM signing certs under `eim/`)
