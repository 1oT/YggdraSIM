Place local SM-DP+ certificate material for `ISD-R` access in this directory.

Inventory behavior:

- If this folder contains no usable certificate material, the application uses the bundled valid SGP.26 certificate inventory.
- If this folder contains usable certificate material, the selector scans both the local drop-ins and the bundled inventory, then picks the best matching pair for the card.
- Legacy filenames still work, but they are no longer required.

Supported drop-in pattern:

- Place the certificate and matching private key in this folder using any readable filename.
- Add a sidecar metadata file next to the certificate:
  - `<certificate>.meta.json`, or
  - `<certificate-stem>.meta.json`

Recommended sidecar fields:

- `role`: `auth` or `pb`
- `private_key_path`: relative or absolute path to the PEM private key
- `root_ci_pkid`: CI PKID to use for card matching
- `server_address`: optional local SM-DP+ address to expose to the eIM local profile-download path

Example sidecar:

```json
{
  "role": "auth",
  "private_key_path": "operator-alpha-auth.key.pem",
  "root_ci_pkid": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
  "server_address": "local.smdpp.operator.example"
}
```

Compatibility note:

- The legacy pairs `CERT.DPauth.ECDSA.der` / `SK.DPauth.ECDSA.pem`
  and `CERT.DPpb.ECDSA.der` / `SK.DPpb.ECDSA.pem` remain valid.
- The DPauth pair is still required for local `AuthenticateServer`.
- The DPpb pair remains optional, but is used when the local flow needs to sign download-side payloads such as `PrepareDownload`.

Related operator docs:

- `../README.md`
- `../../../PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
