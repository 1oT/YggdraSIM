---
title: Concepts
tags:
  - concepts
---

# Concepts

The concepts section is the background layer for the rest of the
documentation. It explains the standards, the card model, the protocol stacks,
and the system shapes that the YggdraSIM operator surfaces act on. Read these
pages when a page elsewhere in the site references a term, a tag, a table, or a
state that you want to ground in the underlying specification.

## Reading order

If you are new to secure-element work, follow this order:

1. [Secure Element Primer](secure-element-primer.md)
2. [GlobalPlatform](globalplatform.md)
3. [ETSI UICC](etsi-uicc.md)
4. [3GPP NAA](3gpp-naa.md)
5. [RSP Architecture](rsp-architecture.md)
6. [SAIP Profiles](saip-profiles.md)
7. [SCP80 OTA](ota-scp80.md)
8. [HIL Model](hil-model.md)

## Concept to subsystem map

| Concept page | Where it lands in the tool |
| --- | --- |
| Secure Element Primer | every card-facing module in `SCP03/`, `SCP11/`, and `Tools/HilBridge/` |
| GlobalPlatform | [SCP03 Admin Shell](../subsystems/scp03.md), session establishment in `SCP11/local_access` |
| ETSI UICC | [SCP03 Admin Shell](../subsystems/scp03.md) filesystem commands |
| 3GPP NAA | `SCP03` USIM/ISIM auth helpers, profile content in SAIP, the in-process [SIMCARD Simulator](../subsystems/simcard-simulator.md) (5G AKA / EAP-AKA' / AKMA / SUCI / `GET IDENTITY`), and the [SUCI Tool](../subsystems/suci-tool.md) |
| RSP Architecture | [SCP11 Live](../subsystems/scp11-live.md), [Local Access](../subsystems/scp11-local-access.md), [eIM Local](../subsystems/scp11-eim-local.md) |
| SAIP Profiles | [Profile Package](../subsystems/profile-package.md) |
| SCP80 OTA | [SCP80 Shell](../subsystems/scp80.md) |
| HIL Model | [HIL Bridge](../subsystems/hil-bridge.md) |

## Specification sources

The authoritative text for each concept sits in the operator's
**optional** local `docs/` tree (gitignored; not shipped in the wheel
or the clean bundle). The concept pages are summaries, not
re-publications. See [Standards Map](../reference/standards-map.md)
for the `docs/` layout we recommend when populating it.

| Concept | Primary specification |
| --- | --- |
| Secure element transport | ISO/IEC 7816-3, ISO/IEC 7816-4 |
| UICC application model | `docs/ts_102221v160200p.md` (ETSI TS 102 221) |
| UICC toolkit | `docs/ts_102223` family, `docs/ts_102225v180000p.md`, `docs/ts_102226v120000p.md` |
| GlobalPlatform | `docs/GPC_CardSpecification_v2.3.1.49_PublicRvw.md` |
| SCP03 | `docs/GPC_2.3_D_SCP03_v1.1.2_PublicRelease.md` |
| NAA and authentication | `docs/ts_131102v180400p.md` (3GPP TS 31.102) |
| 5G AKA and SUCI | 3GPP TS 33.501 (`docs/ts_133501.md` if dropped in) |
| EAP-AKA' | 3GPP TS 33.402 (`docs/ts_133402.md` if dropped in) |
| AKMA | 3GPP TS 33.535 (`docs/ts_133535.md` if dropped in) |
| Milenage / TUAK | 3GPP TS 35.205 / 35.206 / 35.231 (drop into `docs/`) |
| SGP.02 classic RSP | `docs/SGP.02-v4.2.md` |
| SGP.22 consumer RSP | `docs/SGP.22-v3.1.md` |
| SGP.32 IoT RSP | `docs/SGP.32-v1.2.md` |
| SAIP | `docs/Profile_interoperability_V3.4.1.md`, `docs/Profile_interoperability_technical_specification_V3.4.1.md` |
| HIL RSPRO | `docs/RSPRO.asn` |
