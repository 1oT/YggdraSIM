# AddEIM Registration Notes

Use this note when registering the simulated YggdraSIM eIM in another eIM or
operator portal for `ADD-EIM` / peer eIM linking.

## Required Public Certificates

Upload these two public certificates:

1. TLS server certificate
   Use the public PEM referenced by `trusted_tls_cert_path`.

2. eIM signing certificate
   Use the public PEM referenced by `eim_public_key_cert_path`.

Do not upload these private keys:

1. `tls_private_key_path`
2. eIM signing private key

The private keys stay local on the YggdraSIM side.

## Form Field Mapping

If the remote registration form contains these fields, map them as follows:

1. `Display name`
   Operator label only. Choose any local identifier.

2. `eIM hostname (FQDN)`
   Use the real eIM hostname. It shall match the TLS certificate CN/SAN and the
   endpoint that the remote system will contact.

3. `Choose a certificate to secure the TLS connection`
   Upload the TLS server certificate PEM from `trusted_tls_cert_path`.

4. `GSMA CI certificate`
   Select this only if the TLS certificate chain is GSMA CI-issued and the
   remote side expects that trust model.

5. `Server certificate`
   Select this for a normal operator or lab TLS server certificate.

6. `eIM signing certificate`
   Upload the public signing certificate PEM from `eim_public_key_cert_path`.

7. `Indirect profile downloading is supported`
   Enable this when using the standard YggdraSIM AddEIM profile.

## Suggested Protocol Flags

Use these defaults unless the remote side requires another transport profile:

1. `HTTPS over TCP (retrieval)` = enabled
2. `HTTPS over TCP (injection)` = disabled
3. `CoAP/DTLS over UDP (retrieval)` = disabled
4. `CoAP/DTLS over UDP (injection)` = disabled
5. `Indirect profile downloading is supported` = enabled

## Chain Handling

For the TLS upload:

1. If the portal accepts a PEM chain, provide leaf plus intermediates.
2. Do not include the TLS private key.
3. Do not upload the CI root unless the portal explicitly asks for a trust
   anchor or root certificate.

For the eIM signing upload:

1. Upload the public signing certificate PEM.
2. Do not upload the signing private key.

## Local YggdraSIM Mapping

Relevant local identity fields:

1. `eim_public_key_cert_path`
   Public eIM signing certificate used for `eim_public_key_data`.

2. `trusted_tls_cert_path`
   Public TLS server certificate used for `trusted_public_key_data_tls`.

3. `tls_private_key_path`
   Local private key for the TLS listener. Never export this to the remote
   registration form.

## Operational Note

YggdraSIM can be configured in a lab to reuse one PEM for both TLS and signing,
but for real interop and clean trust separation, use distinct TLS and signing
certificate pairs.
