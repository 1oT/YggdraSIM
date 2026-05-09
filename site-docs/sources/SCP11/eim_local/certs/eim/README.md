# eIM Signing Certificate Drop Zone

Drop operator-issued **eIM signing** certificates here for:

- `ADD-INITIAL-EIM`
- `ADD-EIM`

The bundled `openssl_eim_*.cnf` templates are local generation aids
and stay in-tree.

## Quick start

1. Drop the certificate (any of `.der` / `.pem` / `.crt` / `.cer`) into
   this folder.
2. Add a sidecar metadata file beside the certificate, named either
   `<certificate>.meta.json` or `<certificate-stem>.meta.json`.
3. Verify with the eim-local shell's `EIM-CERTS` verb:

   ```bash
   yggdrasim-scp11-eim-local --cmd "STATUS; EIM-CERTS; EXIT"
   ```

   Add `--json` / `--yaml` for machine-readable output, or pass a
   package path / cert path positional to preview how the selector
   would resolve a specific call site.

## Sidecar fields (most common)

| Field                  | Purpose                                                              |
| ---------------------- | -------------------------------------------------------------------- |
| `role`                 | `signing`, `tls`, or `ci`. Inferred from filename / X.509 BC + KU.   |
| `private_key_path`     | Absolute, or relative to this directory.                             |
| `root_ci_pkid`         | Hex SKI used for card / package matching.                            |
| `root_ci_pkids`        | List form of the above; merged with the single value.                |
| `subject_cn`           | Fallback when the X.509 parser cannot produce a Subject CN.          |
| `subject` / `issuer`   | RFC 4514 strings; only used when the certificate cannot be parsed.   |
| `curve`                | `NIST` or `BRP`. Falls back to AKI / SKI / curve OID inference.      |

## Bundled policy

This directory does **not** ship usable Local eIM certificate or
private key material. Production GSMA assets must stay out of the
repository. Generate or drop test-only material here when you need to
exercise the Local eIM flow in a private environment. The simulated
card's default BF55 identity is configured separately through
`Workspace/SIMCARD/eim_identity.json` (or `YGGDRASIM_SIM_EIM_IDENTITY`).

## Certificate profile expected by tooling

Bundled OpenSSL templates emit the following shape — operator-issued
certificates do not need to match it exactly, but the profile is a
useful reference:

- Subject CN: `YggdraSIM.eSIM.Simulator.Cert`
- Algorithm:  `EC P-256` + `ecdsa-with-SHA256`
- Extensions: `basicConstraints=CA:FALSE`, critical `keyUsage`,
  `extendedKeyUsage`, `subjectAltName`, `subjectKeyIdentifier`,
  `authorityKeyIdentifier`

CA-signed chain profile:

- Root CA CN: `YggdraSIM.eSIM.Simulator.RootCA`
- Leaf CN:    `YggdraSIM.eSIM.Simulator.Cert.Chain`
- Algorithm:  `EC P-256` + `ecdsa-with-SHA256`
- Chain verify: `openssl verify -CAfile <root.pem> <leaf.pem>`

## Use in an eIM package

- Point `cert_der_path` (in the package JSON) to an operator-provided
  DER or PEM certificate outside the bundled defaults.
- Keep private keys local to the operator environment and out of
  version control.

## Canonical reference

The full sidecar schema, selection order (`allowed_ci_pkids`,
`preferred_ci_pkids`, identity default, fallback path, ACCEPTED
hint, source preference, curve, lexical), and BYO-keys checklist are
in:

- [`guides/CONFIGURATION_AND_CERTIFICATES.md`](../../../../guides/CONFIGURATION_AND_CERTIFICATES.md)
  — § *Local eIM signing certificates*

Selector code: [`SCP11/eim_local/eim_cert_store.py`](https://github.com/1oT/YggdraSIM/blob/main/SCP11/eim_local/eim_cert_store.py).
