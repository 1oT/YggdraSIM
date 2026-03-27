Place local SM-DP+ certificate material for the eIM local profile-loading path
in this directory.

Selection behavior:

- The local SCP11 layer scans both this folder and the bundled valid SGP.26
  inventory.
- Local drop-ins are preferred when they match the card and include usable key
  material.
- The eIM reuses the selected local DPauth `server_address` when it builds a
  local profile-download trigger and the package does not pin another
  `smdp_address`.

Drop-in format:

- Any certificate filename is accepted.
- Add a sidecar metadata file beside the certificate:
  - `<certificate>.meta.json`, or
  - `<certificate-stem>.meta.json`
- Recommended sidecar fields:
  - `role`: `auth` or `pb`
  - `private_key_path`: PEM key path
  - `root_ci_pkid`: CI PKID binding
  - `server_address`: optional local SM-DP+ address to mirror into the eIM
    activation code

Legacy compatibility:

- `CERT.DPauth.ECDSA.der` / `SK.DPauth.ECDSA.pem`
- `CERT.DPpb.ECDSA.der` / `SK.DPpb.ECDSA.pem`

The DPauth pair is still required for local `AuthenticateServer`.
The DPpb pair remains optional, but is used when the local flow needs to sign
download-side payloads such as `PrepareDownload`.
