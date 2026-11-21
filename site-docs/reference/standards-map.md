---
title: Standards Map
tags:
  - reference
  - standards
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Standards Map

This page maps the published specifications YggdraSIM implements to the
concepts pages and the subsystem pages that act on them.

The folders below name the operator's optional local specification library.
`docs/` is gitignored and ships with nothing, so it starts empty:
`python scripts/fetch_tel_docs.py` downloads every freely published source in
its manifest (`--list` prints the manifest, `--manual` the documents that need
a click-through or a purchase, with the file name each must be saved under),
and `python scripts/convert_tel_docs.py` packs each one into
`docs/tel-docs/converted/<folder>/`: the full text, a `pages/` copy to grep, a
`tables/` directory, and verbatim `asn1/` extracts. `_index.md` is the
catalogue. Versions coexist on purpose -- encode against the version the peer
declares, not the newest text -- so a folder name carries its version and this
table names the newest packed one.

The exception is the RSPRO ASN.1 schema, redistributed as
`Tools/HilBridge/RSPRO.asn` package data so the HIL bridge works from a plain
`pip install`.

## ETSI

| Spec | Local library folder | Implemented at |
| --- | --- | --- |
| ETSI TS 102 221 | `ts_102221v18.4`, `ts_102221v160200p` | [ETSI UICC](../concepts/etsi-uicc.md), [SCP03 Admin Shell](../subsystems/scp03.md) |
| ETSI TS 102 222 | `ts_102222v130000p` | SCP80 RFM payloads, [SCP80 OTA Shell](../subsystems/scp80.md) |
| ETSI TS 102 225 | `ts_102225v180000p` | [SCP80 OTA](../concepts/ota-scp80.md), [SCP80 OTA Shell](../subsystems/scp80.md) |
| ETSI TS 102 226 | `ts_102226v120000p` | [SCP80 OTA Shell](../subsystems/scp80.md) |
| ETSI TS 102 223 (Card Application Toolkit, BIP) | `ts_102223v18.3` | [APDU Dissector](../subsystems/apdu-dissector.md) -- clauses 8.7 device identities, 8.12 general result and its cause byte, 8.52 bearer, 8.56 channel status, 8.59 transport level |
| ETSI TS 101 220 (COMPREHENSION-TLV tag allocation) | `ts_101220v19` | [APDU Dissector](../subsystems/apdu-dissector.md) -- clause 7.1 tag and length forms, clause 7.2 tag values |

## 3GPP

| Spec | Local library folder | Implemented at |
| --- | --- | --- |
| 3GPP TS 31.102 (USIM application + `GET IDENTITY`) | `ts_131102v180400p` | [3GPP NAA](../concepts/3gpp-naa.md), [SCP03 Admin Shell](../subsystems/scp03.md), [SUCI Tool](../subsystems/suci-tool.md), [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 33.501 (5G AKA + SUCI Profile A / B) | `ts_133501v19.7` | [SIMCARD Simulator](../subsystems/simcard-simulator.md), [SUCI Tool](../subsystems/suci-tool.md) |
| 3GPP TS 33.402 (EAP-AKA') | `ts_133402v19` | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 33.535 (AKMA) | `ts_133535v19` | [SIMCARD Simulator](../subsystems/simcard-simulator.md), YggdraCore AAnF stub |
| 3GPP TS 35.205 / 35.206 (Milenage) | `ts_135205v19` / `ts_135206v19` | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 35.231 (TUAK) | `ts_135231v19` | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 24.011 (point-to-point short message support) | `ts_124011v19` | [SCP80 OTA Shell](../subsystems/scp80.md) -- clause 8.2.5.2 RP-Destination Address, the coding the EF.SMSP service-centre address reuses |
| 3GPP TS 31.111 (USIM Application Toolkit) | `ts_131111v170600p` | [APDU Dissector](../subsystems/apdu-dissector.md) -- clause 9.1 BER-TLV envelope tags in the ME-to-UICC direction |

## GlobalPlatform

| Spec | Local library folder | Implemented at |
| --- | --- | --- |
| GP Card Specification v2.3.1 | `GPC_CardSpecification_v2.3.1.49_PublicRvw` | [GlobalPlatform](../concepts/globalplatform.md), [SCP03 Admin Shell](../subsystems/scp03.md) |
| GP SCP03 amendment v1.1.2 | `GPC_2.3_D_SCP03_v1.1.2_PublicRelease` | [SCP03 Admin Shell](../subsystems/scp03.md) |

## GSMA

| Spec | Local library folder | Implemented at |
| --- | --- | --- |
| SGP.02 (Classic M2M RSP) | `SGP.02-v4.2` | reference context |
| SGP.22 (Consumer RSP) | `SGP.22-v3.1` | [RSP Architecture](../concepts/rsp-architecture.md), [SCP11 Live](../subsystems/scp11-live.md), [Local Access](../subsystems/scp11-local-access.md) |
| SGP.32 (IoT RSP) | `SGP.32-v1.2`, `SGP.32-v1.3` | [RSP Architecture](../concepts/rsp-architecture.md), [SCP11 eIM Local](../subsystems/scp11-eim-local.md) |
| RSPRO ASN.1 | not packed; shipped as `Tools/HilBridge/RSPRO.asn` | [HIL Bridge](../subsystems/hil-bridge.md) |

## SIMalliance / TCA

| Spec | Local library folder | Implemented at |
| --- | --- | --- |
| Profile Interoperability Test Spec v3.4 | `Profile_interoperability_test_specification_V3.4` | [SAIP Profiles](../concepts/saip-profiles.md), [Profile Package](../subsystems/profile-package.md) |
| Profile Interoperability Technical Spec v3.4.1 | `Profile_interoperability_technical_specification_V3.4.1` | [Profile Package](../subsystems/profile-package.md) |

## ISO

| Spec | Implemented at |
| --- | --- |
| ISO/IEC 7816-3 (electrical, transport) | every card-facing subsystem; [APDU Dissector](../subsystems/apdu-dissector.md) decodes the ATR per clause 8.2 |
| ISO/IEC 7816-4 (APDU, logical) | [Secure Element Primer](../concepts/secure-element-primer.md), every card-facing subsystem; [APDU Dissector](../subsystems/apdu-dissector.md) -- clause 5.1.3 status categories, clause 5.4.1 class byte, Table 3 secure messaging, Table 12 file descriptor, Table 13 life-cycle status |
| ISO/IEC 8825-1 (BER-TLV) | [APDU Dissector](../subsystems/apdu-dissector.md); indefinite lengths are reported and refused, since DER prohibits them |

## Related pages

- [Architecture](../architecture.md)
- [Concepts](../concepts/index.md)
- [Glossary](glossary.md)
