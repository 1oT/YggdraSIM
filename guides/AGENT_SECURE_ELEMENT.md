# YggdraSIM Secure Element Guide

Load this guide for APDU encoding/decoding, ASN.1 profiles, secure channels,
eUICC behavior, SIM Toolkit, card filesystem work, and profile packages.

## Spec Map

| Domain | Spec | Repo modules |
|---|---|---|
| Consumer eSIM | GSMA SGP.22 | `SCP03/logic/sgp22.py`, `SCP11/live/`, `SIMCARD/sgp.py` |
| IoT eSIM | GSMA SGP.32 | `SCP03/logic/sgp22.py`, `SCP11/eim_local/`, `SIMCARD/ipa_*.py` |
| M2M eSIM | GSMA SGP.02 | Reference context; legacy scans in `SCP03/logic/sgp22.py` |
| UICC filesystem | ETSI TS 102 221 | `SCP03/logic/fs.py`, `SIMCARD/` |
| Admin commands | ETSI TS 102 222 | `SCP03/logic/fs.py` |
| SIM Toolkit | ETSI TS 102 223 | `SCP03/logic/stk.py`, `SIMCARD/toolkit.py` |
| Secured Packet | ETSI TS 102 225 | `SCP80/` |
| Remote APDU | ETSI TS 102 226 | `SCP80/` |
| USIM | 3GPP TS 31.102 | `SCP03/core/decoders.py`, `SIMCARD/` |
| 5G AKA / SUCI | 3GPP TS 33.501 | `SIMCARD/aka_5g.py`, `SIMCARD/suci.py` |
| Milenage | 3GPP TS 35.205/206 | `SIMCARD/milenage.py` |
| TUAK | 3GPP TS 35.231 | `SIMCARD/tuak.py` |
| AKMA | 3GPP TS 33.535 | `SIMCARD/akma.py` |
| GlobalPlatform Card | GPC v2.3.1 | `SCP03/logic/gp.py`, `SCP03/interface/wizards.py` |
| SCP03 | GP SCP03 v1.1.2 | `SCP03/crypto/session.py` |
| SAIP profiles | TCA Profile Interop v3.4.1 | `Tools/ProfilePackage/` |
| APDU | ISO 7816-4 | `SCP03/core/utils.py`, `SCP03/logic/*.py` |
| PC/SC | ISO 7816-3 | `Tools/HilBridge/pcsc.py` |

## Test Identifier Ranges

Every new fixture, test, and doc example must use standards-reserved values.

| Type | Test value | Reference |
|---|---|---|
| MCC/MNC | `001/01`, `999/99` | 3GPP TS 23.003 §2.2 |
| ICCID IIN | `8988...` | ITU-T E.118 |
| EID | `89049032...` | SGP.22 §A.2 |
| IMSI | `001010000000001` | 3GPP TS 23.003 |
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 |
| FQDN | `*.example.test`, `*.example.com`, `*.example.org` | RFC 2606 |
| Email | `*@example.{com,org,test}` | RFC 2606 |
| E.164 | `+1 555 0XXXXXX` | NANP fictional |

Do not introduce real MCC/MNC allocations, real ICCID IINs, public IP
addresses, operator hostnames, internal hostnames, real emails, or real
geographic office metadata.

## APDU Structure

ISO 7816-4 §5.1 command layout:

```text
+------+------+------+------+------+--------+------+
| CLA  | INS  |  P1  |  P2  |  Lc  |  Data  |  Le  |
+------+------+------+------+------+--------+------+
| 1 B  | 1 B  | 1 B  | 1 B  |0/1/3B| 0-Nc B |0/1/3B|
+------+------+------+------+------+--------+------+
```

- Case 1: `CLA INS P1 P2`
- Case 2: `CLA INS P1 P2 Le`
- Case 3: `CLA INS P1 P2 Lc Data`
- Case 4: `CLA INS P1 P2 Lc Data Le`
- Extended length uses three-byte `Lc`/`Le`: first byte `00`, then a
  two-byte length.
- Logical channels are encoded in CLA bits b1-b0 for channels 0-3.
- GP commands commonly use `CLA=80` or `CLA=84`.
- Secure messaging uses CLA bits such as `0C` for wrapped commands and `04`
  for wrapped responses.

## Common Status Words

| SW1 SW2 | Meaning |
|---|---|
| `90 00` | Success |
| `61 XX` | Success, `XX` bytes available for GET RESPONSE |
| `62 83` | Selected file invalidated |
| `63 CX` | Verification failed, `X` retries remaining |
| `67 00` | Wrong length |
| `69 82` | Security status not satisfied |
| `69 83` | Authentication method blocked |
| `69 85` | Conditions of use not satisfied |
| `6A 80` | Incorrect parameters in data field |
| `6A 82` | File or applet not found |
| `6A 86` | Incorrect P1-P2 |
| `6D 00` | Instruction code not supported |
| `6E 00` | Class not supported |

## SGP.22 / SGP.32 BER-TLV Tags

| Tag | Name | Spec |
|---|---|---|
| `BF20` | EuiccInfo1 | SGP.22 §5.7.16 |
| `BF22` | EuiccInfo2 | SGP.22 §5.7.17 |
| `BF2B` | NotificationsList | SGP.22 §5.7.24 |
| `BF2D` | GetProfilesInfo | SGP.22 §5.7.20 |
| `BF31` | EnableProfile | SGP.22 §5.7.21 |
| `BF32` | DisableProfile | SGP.22 §5.7.22 |
| `BF33` | DeleteProfile | SGP.22 §5.7.23 |
| `BF3C` | EuiccConfiguredData | SGP.22 §5.7.18 |
| `BF3E` | ProfileInfo | SGP.22 §5.7.19 |
| `BF43` | RAT | SGP.22 §5.7.16 |
| `BF55` | EimConfigurationData | SGP.32 §6.5 |
| `BF56` | GetCertsResponse | SGP.22 §5.7.32 |
| `9F70` | ProfileState | SGP.22 §5.7.19 |
| `4F` | AID | ISO 7816-5 |
| `5A` | ICCID | ETSI TS 102 221 |

## ES10 Command Reference

| Command | CLA INS P1 P2 | Target |
|---|---|---|
| GetEuiccInfo1 | `80 E2 91 00 BF20` | ECASD/ISD-R |
| GetEuiccInfo2 | `80 E2 91 00 BF22` | ECASD/ISD-R |
| GetEuiccConfiguredData | `80 E2 91 00 BF3C` | ECASD/ISD-R |
| GetProfilesInfo | `80 E2 91 00 BF2D` | ISD-R |
| EnableProfile | `80 E2 91 00 BF31` | ISD-R |
| DisableProfile | `80 E2 91 00 BF32` | ISD-R |
| DeleteProfile | `80 E2 91 00 BF33` | ISD-R |
| GetRAT | `80 E2 91 00 BF43` | ISD-R |
| GetCerts | `80 E2 91 00 BF56` | ECASD |
| GetNotificationsList | `80 E2 91 00 BF2B` | ISD-R |

## Profile State

- Disabled to Enabled is reversible.
- Enabled to Disabled is reversible.
- Deleted is terminal.
- State bytes: `00` disabled, `01` enabled, `02` deleted.
- Only one profile is enabled at a time. Enabling a new profile disables the
  current enabled profile.

## Module Footguns

- Preserve the correct CLA channel bits. GP and secure messaging CLA values
  are easy to corrupt when adding channel handling.
- Encode extended-length APDUs as `00 XX XX` for lengths above 255.
- BER-TLV multi-byte tags are big-endian in the byte stream.
- ICCID BCD bytes swap nibble pairs. Printed `898820...` starts as bytes
  `98 88 02 ...`.
- Do not add real identifiers to tests or examples.
- Bound any state history that survives multiple APDU calls.
- Wizards must be granular down to nested tags.
