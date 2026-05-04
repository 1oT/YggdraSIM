# YggdraSIM Simulated eIM - AddEim Identity Sheet

This document is the concrete, vendor-neutral identity record for the
YggdraSIM simulated eIM. It contains **every field** that a real-world eIM
portal (1oT, or any other GSMA SGP.32-compliant eIM operator) needs in
order to accept YggdraSIM's simulated eIM as a peer / indirect profile
download source, and to bind the resulting eIM Configuration Data to a
real eUICC via ES25 `AddEim`.

The structure mirrors the GSMA SGP.32 `EimConfigurationData` ASN.1 shape
(section 2.10.1, "eIM Configuration Data"). All values are hardcoded so
the sheet can be pasted straight into a vendor registration form.

## 1. Spec anchors

1. GSMA SGP.32 v1.x, section 2.10.1 "eIM Configuration Data"
2. GSMA SGP.32 v1.x, section 5.9.x "ES25: AddEim"
3. GSMA SGP.22 v3.x, section 2.6 "Certificate Hierarchy"
4. ITU-T X.509, SubjectKeyIdentifier encoding (for `euiccCiPkId`)

## 2. Field matrix

| ASN.1 field               | 1oT       | Strict eIM policy | Notes                                                  |
|---------------------------|-----------|-------------------|--------------------------------------------------------|
| `eimId`                   | Mandatory | Mandatory         | UTF8String, up to 128 chars, unique per eIM instance.  |
| `eimIdType`               | Mandatory | Mandatory         | `Oid`, `Fqdn`, or `ProprietaryId`.                     |
| `eimFqdn`                 | Mandatory | Mandatory         | Must match TLS leaf CN/SAN and AddEim endpoint.        |
| `eimPublicKeyData`        | Mandatory | Mandatory         | PEM of the eIM signing leaf (ECDSA P-256).             |
| `trustedPublicKeyDataTls` | Mandatory | Mandatory         | PEM of the TLS server leaf serving the AddEim URL.     |
| `eimSupportedProtocols`   | Mandatory | Mandatory         | JSON array. YggdraSIM ships with `["HttpsPull"]`.      |
| `euiccCiPkId`             | Optional  | Optional          | Only required when the eUICC selects the trust anchor. |
| `indirectProfileDownload` | Mandatory | Mandatory         | Boolean. YggdraSIM: `true`.                            |

> Policy note. Some eIM registration portals enforce that every field
> listed above be non-empty **except** `euiccCiPkId` -- i.e. they treat
> `euiccCiPkId` as the single optional field and everything else as
> mandatory. The 1oT portal follows the same superset but will accept
> a profile even if further optional fields are omitted. The record
> below satisfies both policies.

## 3. Primary profile (YggdraSIM-branded, SGP.26 NIST trust anchor)

Use this profile when the receiving eUICC trusts the SGP.26 Test CI
(`CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`, NIST P-256, SKI
`F54172BDF98A95D65CBEB88A38A1C11D800A85C3`). YggdraSIM's default test
lab posture targets this CI.

```
eimId                          2.25.311782205282738360923618091971140414400
eimFqdn                        eim.yggdrasim.example.test
eimIdType                      Oid
eimPublicKeyData
-----BEGIN CERTIFICATE-----
MIIBqjCCAVGgAwIBAgIUarwB02d11LG6bCY6mzOkQb9nMc8wCgYIKoZIzj0EAwIw
RDEQMA4GA1UEAwwHVGVzdCBDSTERMA8GA1UECwwIVEVTVENFUlQxEDAOBgNVBAoM
B1JTUFRFU1QxCzAJBgNVBAYTAklUMB4XDTI2MDMyMzE5NTA1MVoXDTMzMDMyMjE5
NTA1MVowMjELMAkGA1UEBhMCREUxIzAhBgNVBAMMGnlnZ2RyYXNpbS5laW0udGVz
dC4xb3QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEetnXgTPb6zziyCzz
M08MZK0iNmuc4q7NS+bZJIHBftd/tK/8jQmq62O+qwjLpuq8VGYnggpojFDe8Cx8
HACOnqMzMDEwHwYDVR0jBBgwFoAU9UFyvfmKldZcvriKOKHBHYAKhcMwDgYDVR0P
AQH/BAQDAgeAMAoGCCqGSM49BAMCA0cAMEQCICo0ivtvPZl0MuMbjsn2CSTeZYsO
tfoPy85uDmutb3uzAiAb9ePhhkw6PfbCfglXwC6FdjqMbTjztWInUCzp9ND45g==
-----END CERTIFICATE-----
trustedPublicKeyDataTls
-----BEGIN CERTIFICATE-----
MIICXjCCAgSgAwIBAgIUXQvN4skGC4yU89KY3ALfIrPobCwwCgYIKoZIzj0EAwIw
RDEQMA4GA1UEAwwHVGVzdCBDSTERMA8GA1UECwwIVEVTVENFUlQxEDAOBgNVBAoM
B1JTUFRFU1QxCzAJBgNVBAYTAklUMB4XDTI2MDMyMzE5NTA1MVoXDTI5MDMyMzE5
NTA1MVowMjELMAkGA1UEBhMCREUxIzAhBgNVBAMMGnlnZ2RyYXNpbS5laW0udGVz
dC4xb3QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOLKWxtc7qVS2cFU8
BmL5gVoVmwLXrGrVwX4vRi2Xd+PnsqVbsL/kCc7FglJx3gvAknPQDwHQ+22v9D6p
G4lmgqOB5TCB4jAfBgNVHSMEGDAWgBT1QXK9+YqV1ly+uIo4ocEdgAqFwzAOBgNV
HQ8BAf8EBAMCB4AwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCoG
A1UdEQQjMCGCGnlnZ2RyYXNpbS5laW0udGVzdC4xb3QuY29tiAOINxQwYQYDVR0f
BFowWDAqoCigJoYkaHR0cDovL2NpLnRlc3QuZXhhbXBsZS5jb20vQ1JMLTEuY3Js
MCqgKKAmhiRodHRwOi8vY2kudGVzdC5leGFtcGxlLmNvbS9DUkwtMi5jcmwwCgYI
KoZIzj0EAwIDSAAwRQIgZFSeBTxLMJKiFMyaU7eALSerz6+ub9e8j11vP1uZW7QC
IQDp4GT+u0lh7kpHyoDkx3FKdog6kVe+bmOMdI9cxrESnQ==
-----END CERTIFICATE-----
eimSupportedProtocols          ["HttpsPull"]
euiccCiPkId                    F54172BDF98A95D65CBEB88A38A1C11D800A85C3
indirectProfileDownload        true
```

Identity breakdown:

1. `eimId` is a UUID-backed OID under the RFC 4122 arc `2.25.*`. Any
   real-world eIM operator can use it verbatim; it is globally unique
   and not registered to any production CA.
2. `eimFqdn` is the canonical lab hostname. It matches the TLS leaf CN
   and the Subject Alternative Name (`DNS:eim.yggdrasim.example.test`).
3. `eimIdType` is `Oid`. `Fqdn` or `ProprietaryId` would require the
   signing leaf's SAN layout to carry the same identifier value, which
   YggdraSIM does not emit.
4. `eimPublicKeyData` is the ECDSA P-256 signing leaf (serial
   `6ABC01D3 6775D4B1 BA6C263A 9B33A441 BF6731CF`, issued by
   `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`).
5. `trustedPublicKeyDataTls` is the TLS server leaf (serial
   `5D0BCDE2 C9060B8C 94F3D298 DC02DF22 B3E86C2C`, SAN
   `DNS:eim.yggdrasim.example.test, Registered ID:2.999.20`, EKU
   `serverAuth + clientAuth`).
6. `eimSupportedProtocols` is exactly the single-protocol array
   `["HttpsPull"]`. YggdraSIM does not expose a push-mode endpoint or
   a CoAP/DTLS endpoint.
7. `euiccCiPkId` is the Subject Key Identifier of the SGP.26 Test CI
   NIST P-256 anchor. When omitted, the eUICC will pick any CI it
   trusts. When set, the eUICC must already have the matching trust
   anchor provisioned.
8. `indirectProfileDownload` is `true` because YggdraSIM operates in
   IPD mode (the eIM fetches a BPP from SM-DP+ and relays it to the
   eUICC over the LPAd transport).

## 4. Alternate profile (SGP.26 Variant O neutral)

Use this profile when the registering portal wants a vanilla SGP.26
Variant O identity (no YggdraSIM-specific hostname, neutral CN). The
trust anchor is identical to Profile 3; only the leaf identity changes.
Both leafs are issued by the SGP.26 Test CI (NIST).

```
eimId                          1.3.6.1.4.1.53775.99.1.0
eimFqdn                        eim.example.com
eimIdType                      Oid
eimPublicKeyData
-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgILA/8K/wAJmQEB/wEwCgYIKoZIzj0EAwIwRDEQMA4GA1UE
AwwHVGVzdCBDSTERMA8GA1UECwwIVEVTVENFUlQxEDAOBgNVBAoMB1JTUFRFU1Qx
CzAJBgNVBAYTAklUMB4XDTI0MDcxNjEwMDk0OVoXDTMxMDcxNTEwMDk0OVowJzEL
MAkGA1UEBhMCREUxGDAWBgNVBAMMD2VpbS5leGFtcGxlLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABLueiXUX7XGYxfdzi4h9Iq/GxoxXrZstBDN7XzoNyD/l
yDmXtrOqQn/C5gNxi3FAFRuo0V4LFwJ12Y3QXA/1woejMzAxMB8GA1UdIwQYMBaA
FPVBcr35ipXWXL64ijihwR2ACoXDMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQD
AgNIADBFAiEAj/TnLWnB0NEsKI8PorbjYB25qWdCJdhrjKRM6AIAnr0CICAmilNA
mafIHSUqd7aw6eD+XcWedTOthC2GbJ+L9Q5d
-----END CERTIFICATE-----
trustedPublicKeyDataTls
-----BEGIN CERTIFICATE-----
MIICQDCCAeegAwIBAgINA/8K/wAJmQEA/wD/ATAKBggqhkjOPQQDAjBEMRAwDgYD
VQQDDAdUZXN0IENJMREwDwYDVQQLDAhURVNUQ0VSVDEQMA4GA1UECgwHUlNQVEVT
VDELMAkGA1UEBhMCSVQwHhcNMjUwNjMwMTMxODEwWhcNMjYwODAyMTMxODEwWjAn
MQswCQYDVQQGEwJERTEYMBYGA1UEAwwPZWltLmV4YW1wbGUuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEZ5Dd47De9mOigjGBxTuX9M4VwoMKtJF0msPRrG6o
wgl2hC+ByszxL63nCMPWajxbJwXTkjhZmk1UwbFk0FiIEaOB2jCB1zAfBgNVHSME
GDAWgBT1QXK9+YqV1ly+uIo4ocEdgAqFwzAOBgNVHQ8BAf8EBAMCB4AwIAYDVR0l
AQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdEQQYMBaCD2VpbS5leGFt
cGxlLmNvbYgDiDcUMGEGA1UdHwRaMFgwKqAooCaGJGh0dHA6Ly9jaS50ZXN0LmV4
YW1wbGUuY29tL0NSTC0xLmNybDAqoCigJoYkaHR0cDovL2NpLnRlc3QuZXhhbXBs
ZS5jb20vQ1JMLTIuY3JsMAoGCCqGSM49BAMCA0cAMEQCIFjKCMz2Cv/te8r27K/l
bvXXR5Lxfi/3ZQiyhmKnr8EUAiAwVvE7TGP64dgV1RRJ/b/bddQyfk53WPUMTrXK
IvWqLw==
-----END CERTIFICATE-----
eimSupportedProtocols          ["HttpsPull"]
euiccCiPkId                    F54172BDF98A95D65CBEB88A38A1C11D800A85C3
indirectProfileDownload        true
```

Identity breakdown:

1. `eimId` uses the private enterprise OID arc
   `1.3.6.1.4.1.53775.99.*`. The `.99.1.0` leaf marks this as a
   YggdraSIM-issued test identity, deliberately distinct from any
   real 1oT production OID.
2. `eimFqdn` is the SGP.26 Variant O default (`eim.example.com`), which
   matches the TLS leaf SAN and the signing leaf CN shipped with the
   test vectors.
3. `eimPublicKeyData` is the SGP.26 Variant O `CERT_S_EIMsign_ECDSA_NIST`
   (serial `03FF0AFF 00099901 01FF01`, issuer
   `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`).
4. `trustedPublicKeyDataTls` is the SGP.26 Variant O `CERT_S_EIM_TLS_NIST`
   (serial `03FF0AFF 00099901 00FF00FF 01`, SAN
   `DNS:eim.example.com, Registered ID:2.999.20`).
5. `eimSupportedProtocols`, `euiccCiPkId`, `indirectProfileDownload`
   are identical to Profile 3 for the same reasons.

## 5. BRP (brainpoolP256r1) variant

Use this only when the target eUICC does **not** trust the NIST P-256
SGP.26 anchor and is instead provisioned with the brainpool anchor
(`CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`, brainpoolP256r1). In that
case all three values below change:

1. Replace `eimPublicKeyData` with the brainpool SGP.26 EIM signing
   leaf (`CERT_S_EIMsign_ECDSA_BRP`).
2. Replace `trustedPublicKeyDataTls` with the brainpool SGP.26 EIM TLS
   leaf (`CERT_S_EIM_TLS_BRP`).
3. Set `euiccCiPkId` to the brainpool CI SKI
   `C0BC70BA36929D43B467FF575705 30E57AB8FCD8` (no spaces:
   `C0BC70BA36929D43B467FF57570530E57AB8FCD8`).

The other scalar fields (`eimId`, `eimFqdn`, `eimIdType`,
`eimSupportedProtocols`, `indirectProfileDownload`) are the same as in
Profile 3 or Profile 4 depending on which naming you picked.

## 6. Security and custody

1. The PEM blocks above are **public** material only. They are safe to
   paste into any operator portal.
2. The matching private keys live exclusively on the YggdraSIM host
   (`SCP11/eim_local/certs/eim/` and `SCP11/SGP.26_test_Certs/Valid
   Test Cases/Variant O/`). They must not be uploaded to a peer eIM
   and must not be copied into this sheet.
3. If the receiving portal also requests a CI root certificate, use
   the matching SGP.26 Test CI from
   `SCP11/SGP.26_test_Certs/Valid Test Cases/Variant O/CI/` (NIST or
   BRP as applicable). Do not supply a production GSMA CI root.
4. The `eimId` values above are test identifiers. Do not reuse them
   against a production eIM or against a customer's live RSP chain.
5. YggdraSIM operates all of the above against self-signed / SGP.26
   test trust. The HSM-backed signer seam for the local SMDPp is not
   implemented in this release.

## 7. Verification cheatsheet

Quick OpenSSL calls to confirm the pasted values match the live lab
state:

```
openssl x509 -in <paste-eimPublicKeyData> -noout -subject -issuer -serial -dates
openssl x509 -in <paste-trustedPublicKeyDataTls> -noout -subject -issuer -serial -dates -ext subjectAltName -ext extendedKeyUsage
```

Expected output for Profile 3:

1. Signing leaf subject: `C=DE, CN=eim.yggdrasim.example.test`
2. Signing leaf issuer:  `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`
3. Signing leaf serial:  `6ABC01D36775D4B1BA6C263A9B33A441BF6731CF`
4. Signing leaf validity: `Mar 23 19:50:51 2026 GMT - Mar 22 19:50:51 2033 GMT`
5. TLS leaf subject:     `C=DE, CN=eim.yggdrasim.example.test`
6. TLS leaf issuer:      `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`
7. TLS leaf serial:      `5D0BCDE2C9060B8C94F3D298DC02DF22B3E86C2C`
8. TLS leaf validity:    `Mar 23 19:50:51 2026 GMT - Mar 23 19:50:51 2029 GMT`
9. TLS leaf SAN:         `DNS:eim.yggdrasim.example.test, Registered ID:2.999.20`
10. TLS leaf EKU:        `TLS Web Server Authentication, TLS Web Client Authentication`

Expected output for Profile 4:

1. Signing leaf subject: `C=DE, CN=eim.example.com`
2. Signing leaf issuer:  `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`
3. Signing leaf serial:  `03FF0AFF0009990101FF01`
4. Signing leaf validity: `Jul 16 10:09:49 2024 GMT - Jul 15 10:09:49 2031 GMT`
5. TLS leaf subject:     `C=DE, CN=eim.example.com`
6. TLS leaf issuer:      `CN=Test CI, OU=TESTCERT, O=RSPTEST, C=IT`
7. TLS leaf serial:      `03FF0AFF0009990100FF00FF01`
8. TLS leaf validity:    `Jun 30 13:18:10 2025 GMT - Aug  2 13:18:10 2026 GMT`
9. TLS leaf SAN:         `DNS:eim.example.com, Registered ID:2.999.20`
10. TLS leaf EKU:        `TLS Web Server Authentication, TLS Web Client Authentication`

The SGP.26 Variant O TLS leaf (Profile 4) rotates annually upstream; if
the serial or validity window in the live lab drifts from the values
above, regenerate this sheet from the current PEM rather than patching
the scalar fields.

## 8. Change log

1. Initial hardcoded sheet. Covers Profile 3 (YggdraSIM branded),
   Profile 4 (SGP.26 Variant O neutral), Profile 5 (BRP swap).
   Matches the common SGP.32 §6.4 AddInitialEim mandatory-field
   profile (every field except `euiccCiPkId`) so a stock eIM intake
   form has all data it needs.
