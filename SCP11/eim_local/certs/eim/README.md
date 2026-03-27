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
inventory selector will rank the available drop-ins and bundled assets.

Default first-test identity points to locally generated yggdrasim assets:

- `SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_ACCEPTED.der`
- `SCP11/eim_local/certs/eim/CERT_S_EIM_TLS_YGGDRASIM_NIST.der`
- `SCP11/eim_local/certs/eim/SK_S_EIM_TLS_YGGDRASIM_NIST.pem`

Generated lab certificate set:

- `CERT.EIM.pem` (PEM leaf cert used by `ADD-INITIAL-EIM` / `ADD-EIM`)
- `EIM.Simulator.key.pem` (private key, keep local and protected)

Seeded reference certificate set:

- `SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_ACCEPTED.der` (eIM signing cert chained to reference test CI)
- `SCP11/eim_local/certs/eim/SK_S_EIMsign_YGGDRASIM_ACCEPTED.pem` (eIM signing private key)
- `SCP11/eim_local/certs/eim/CERT_S_EIM_TLS_YGGDRASIM_NIST.der` (eIM TLS cert chained to reference test CI)
- `SCP11/eim_local/certs/eim/SK_S_EIM_TLS_YGGDRASIM_NIST.pem` (eIM TLS private key)
- `SCP11/eim_local/certs/eim/CA.EIM.Root.cert.pem` (reference test CI root / CI PKID source)

Generated CA-signed chain variant (for realistic validation tests):

- `CA.EIM.Root.key.pem` (mini test root CA private key)
- `CA.EIM.Root.cert.pem` / `CA.EIM.Root.cert.der` (mini test root CA cert)
- `EIM.Chain.Leaf.key.pem` (chain leaf private key)
- `EIM.Chain.Leaf.csr.pem` (leaf CSR)
- `CERT.EIM.CHAIN.pem` / `CERT.EIM.CHAIN.der` (CA-signed eIM leaf cert)
- `CA.EIM.Root.cert.srl` (OpenSSL serial tracker)

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
  - `openssl verify -CAfile CA.EIM.Root.cert.pem CERT.EIM.CHAIN.pem`

Use in package JSON:

- `cert_der_path: "SCP11/eim_local/certs/eim/CERT_S_EIMsign_YGGDRASIM_ACCEPTED.der"` for the seeded first-test setup
- `cert_der_path: "SCP11/eim_local/certs/eim/CERT.EIM.CHAIN.pem"` for chain leaf tests
- Keep `CA.EIM.Root.cert.pem` available for local validator/inspection tooling
