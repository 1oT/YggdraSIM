---
title: Standards Map
tags:
  - reference
  - standards
---

# Standards Map

This page maps the published specifications YggdraSIM implements to the
concepts pages and the subsystem pages that act on them. The `docs/`
filenames below point at the operator's optional local developer tree
(gitignored, see the README "Repository layout" entry): they are not
shipped with the wheel or the clean bundle. Download the source
documents from the issuing body and drop them into `docs/` at the repo
root to populate the offline reference. The one exception is the
RSPRO ASN.1 schema which is redistributed as `Tools/HilBridge/RSPRO.asn`
package data so that the HIL bridge works from a plain `pip install`.

## ETSI

| Spec | Optional local file | Implemented at |
| --- | --- | --- |
| ETSI TS 102 221 | `docs/ts_102221v160200p.md` | [ETSI UICC](../concepts/etsi-uicc.md), [SCP03 Admin Shell](../subsystems/scp03.md) |
| ETSI TS 102 222 | `docs/ts_102222v130000p.md` | SCP80 RFM payloads, [SCP80 OTA Shell](../subsystems/scp80.md) |
| ETSI TS 102 225 | `docs/ts_102225v180000p.md` | [SCP80 OTA](../concepts/ota-scp80.md), [SCP80 OTA Shell](../subsystems/scp80.md) |
| ETSI TS 102 226 | `docs/ts_102226v120000p.md` | [SCP80 OTA Shell](../subsystems/scp80.md) |

## 3GPP

| Spec | Optional local file | Implemented at |
| --- | --- | --- |
| 3GPP TS 31.102 (USIM application + `GET IDENTITY`) | `docs/ts_131102v180400p.md` | [3GPP NAA](../concepts/3gpp-naa.md), [SCP03 Admin Shell](../subsystems/scp03.md), [SUCI Tool](../subsystems/suci-tool.md), [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 33.501 (5G AKA + SUCI Profile A / B) | `docs/ts_133501.md` (drop in) | [SIMCARD Simulator](../subsystems/simcard-simulator.md), [SUCI Tool](../subsystems/suci-tool.md) |
| 3GPP TS 33.402 (EAP-AKA') | `docs/ts_133402.md` (drop in) | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 33.535 (AKMA) | `docs/ts_133535.md` (drop in) | [SIMCARD Simulator](../subsystems/simcard-simulator.md), YggdraCore AAnF stub *(post-v1 staging)* |
| 3GPP TS 35.205 / 35.206 (Milenage) | `docs/ts_135205.md` / `docs/ts_135206.md` (drop in) | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |
| 3GPP TS 35.231 (TUAK) | `docs/ts_135231.md` (drop in) | [SIMCARD Simulator](../subsystems/simcard-simulator.md) |

## GlobalPlatform

| Spec | Optional local file | Implemented at |
| --- | --- | --- |
| GP Card Specification v2.3.1 | `docs/GPC_CardSpecification_v2.3.1.49_PublicRvw.md` | [GlobalPlatform](../concepts/globalplatform.md), [SCP03 Admin Shell](../subsystems/scp03.md) |
| GP SCP03 amendment v1.1.2 | `docs/GPC_2.3_D_SCP03_v1.1.2_PublicRelease.md` | [SCP03 Admin Shell](../subsystems/scp03.md) |

## GSMA

| Spec | Optional local file | Implemented at |
| --- | --- | --- |
| SGP.02 (Classic M2M RSP) | `docs/SGP.02-v4.2.md` | reference context |
| SGP.22 (Consumer RSP) | `docs/SGP.22-v3.1.md` | [RSP Architecture](../concepts/rsp-architecture.md), [SCP11 Live](../subsystems/scp11-live.md), [Local Access](../subsystems/scp11-local-access.md) |
| SGP.32 (IoT RSP) | `docs/SGP.32-v1.2.md` | [RSP Architecture](../concepts/rsp-architecture.md), [SCP11 eIM Local](../subsystems/scp11-eim-local.md) |
| RSPRO ASN.1 | `docs/RSPRO.asn` (+ shipped `Tools/HilBridge/RSPRO.asn`) | [HIL Bridge](../subsystems/hil-bridge.md) |

## SIMalliance / TCA

| Spec | Optional local file | Implemented at |
| --- | --- | --- |
| Profile Interoperability v3.4.1 | `docs/Profile_interoperability_V3.4.1.md` | [SAIP Profiles](../concepts/saip-profiles.md), [Profile Package](../subsystems/profile-package.md) |
| Profile Interoperability Technical Spec v3.4.1 | `docs/Profile_interoperability_technical_specification_V3.4.1.md` | [Profile Package](../subsystems/profile-package.md) |

## ISO

| Spec | Implemented at |
| --- | --- |
| ISO/IEC 7816-3 (electrical, transport) | every card-facing subsystem |
| ISO/IEC 7816-4 (APDU, logical) | [Secure Element Primer](../concepts/secure-element-primer.md), every card-facing subsystem |

## Related pages

- [Architecture](../architecture.md)
- [Concepts](../concepts/index.md)
- [Glossary](glossary.md)
