# eIM Certificate Drop Zone

Place eIM certificates here for:

- `ADD-INITIAL-EIM`
- `ADD-EIM`

Drop-in inventory behavior:

- The eIM selector scans this directory recursively for signing certificates.
- Operator-provided certificates can use custom filenames.
- Add a sidecar metadata file beside the certificate when the selector needs
  help binding the asset:
  - `<certificate>.meta.json`, or
  - `<certificate-stem>.meta.json`
- Recommended sidecar fields:
  - `role`: `signing`
  - `private_key_path`: PEM key path
  - `root_ci_pkid`: CI PKID binding for card or package matching
  - `subject`, `issuer`, `subject_cn`, `curve`: optional fallback metadata for
    non-standard certificates that the X.509 parser cannot fully decode

The default identity can still pin a `certPath`, but when it does not, the
inventory selector will rank the available operator-provided drop-ins.

Bundled policy:

- This repository does **not** ship usable Local eIM certificate or private key
  material.
- Keep GSMA assets out of the repository.
- Generate or drop local test-only material here when you need to exercise the
  Local eIM flow in a private environment.
- This directory feeds the Local eIM shell; the simulated card's default BF55
  identity is configured separately through `Workspace/SIMCARD/eim_identity.json`
  or the wrapper `eIM identity` override path.

Retained files:

- The OpenSSL configuration templates remain in-tree as local generation aids.
- README and metadata guidance remain in-tree for operator provisioning.

Certificate profile:

- Subject CN: `YggdraSIM.eSIM.Simulator.Cert`
- Algorithm: `EC P-256` + `ecdsa-with-SHA256`
- Extensions: `basicConstraints=CA:FALSE`, critical `keyUsage`, `extendedKeyUsage`,
  `subjectAltName`, `subjectKeyIdentifier`, `authorityKeyIdentifier`

CA-signed chain profile:

- Root CA CN: `YggdraSIM.eSIM.Simulator.RootCA`
- Leaf CN: `YggdraSIM.eSIM.Simulator.Cert.Chain`
- Algorithm: `EC P-256` + `ecdsa-with-SHA256`
- Chain verification command:
  - `openssl verify -CAfile /path/to/local_eim_ci_root_cert.pem /path/to/local_eim_leaf_cert.pem`

Use in package JSON:

- Point `cert_der_path` to an operator-provided DER or PEM certificate outside
  the bundled defaults.
- Keep private keys local to the operator environment and out of version
  control.
