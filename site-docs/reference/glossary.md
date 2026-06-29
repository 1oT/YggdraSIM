---
title: Glossary
tags:
  - reference
  - glossary
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Glossary

Every abbreviation used on this site, spelled out. For the interactive
tooltip version, hover over any abbreviation inside a page; the same terms
are defined in `site-docs/_includes/abbreviations.md`.

## A

**AAnF** - AKMA Anchor Function. The 5G core function that anchors AKMA
keys per UE.

**A-KID** - AKMA Key Identifier. Identifier carried alongside `K_AKMA`.

**AKA** - Authentication and Key Agreement.

**AKMA** - Authentication and Key Management for Applications (3GPP TS
33.535).

**AID** - Application Identifier. A globally unique identifier for an
on-card application, package, or Security Domain.

**APDU** - Application Protocol Data Unit. The ISO/IEC 7816-4 command and
response format exchanged between a host and a card.

**ARA-M** - Access Rule Application Master. The master applet that governs
access rules on a UICC.

**ATR** - Answer To Reset. The initial response a card sends after an
electrical or logical reset.

**AUSF** - Authentication Server Function. The 5G core function that
performs authentication with the UE.

## B

**BIP** - Bearer Independent Protocol (ETSI TS 102 223).

**BPP** - Bound Profile Package. The bound form of a profile delivered by
SM-DP+ to a device for installation into an ISD-P.

## C

**CAP** - Converted Applet. The JavaCard converted applet binary.

**CAT** - Card Application Toolkit. ETSI TS 102 223 proactive-command
framework.

**CI** - Certificate Issuer. The root of trust for SCP11 and RSP
certificates.

**CI PKID** - Certificate Issuer Public Key Identifier. A fingerprint of the
CI public key used by the eUICC to decide what it trusts.

**CRS** - Contactless Registry Service. A contactless management service
exposed on some cards.

## D

**DER** - Distinguished Encoding Rules. A canonical ASN.1 encoding.

**DF** - Dedicated File. An ETSI/3GPP filesystem directory.

**DGI** - Data Grouping Identifier. A key used in GP content-management
transfers.

## E

**EAP-AKA'** - EAP method for AKA over non-3GPP access (3GPP TS 33.402).

**EF** - Elementary File. An ETSI/3GPP filesystem data file.

**EID** - eUICC Identifier. The identity of an eUICC.

**eIM** - eSIM IoT Manager. The SGP.32 orchestrator actor.

**ES9+** - ES9+ interface between an LPA/IPA and SM-DP+.

**ES10a/b/c** - ES10 interfaces between LPAd/IPAd and the ISD-R.

**eSE** - Embedded Secure Element. A soldered-down SE, distinct from UICC.

**ETSI** - European Telecommunications Standards Institute.

**eUICC** - Embedded UICC. A soldered-down, remotely-provisionable UICC.

## F

**FCP** - File Control Parameters. An ETSI TLV template describing an EF.

**FID** - File Identifier. A 2-byte ETSI filesystem identifier.

## G

**GET IDENTITY** - 3GPP TS 31.102 §7.1.2.4 USIM command that returns the
SUCI built on-card.

**GP** - GlobalPlatform.

**GSMA** - GSM Association. The telecom industry body that authors SGP.
specifications.

**GSMTAP** - Encapsulation used to mirror SIM/modem traffic for capture
in Wireshark.

## H

**HIL** - Hardware-In-The-Loop.

## I

**IC** - Integrated Circuit.

**ICCID** - Integrated Circuit Card Identifier. The identity of a
subscription-level card state, typically 19-20 digits.

**IJC** - Intermediate Java Card. An intermediate applet format.

**IPAd** - IoT Profile Assistant, device-side.

that runs inside the eUICC itself rather than on the host device.

**ISD-P** - Issuer Security Domain - Profile. The per-profile SD.

**ISD-R** - Issuer Security Domain - Root. The top SD on an eUICC.

**ISIM** - IP Multimedia Services Identity Module.

## K

**K_AKMA** - AKMA Anchor Key derived from `Kausf`.

**Kausf** - 5G AKA anchor key derived during 5G authentication.

## L

**LPA** - Local Profile Assistant.

**LPAd** - Local Profile Assistant, device-side.

## M

**MF** - Master File. The root of the ETSI/3GPP filesystem.

## N

**NAA** - Network Access Application. USIM, ISIM, or CSIM.

## O

**OTA** - Over-The-Air.

## P

**PC/SC** - Personal Computer/Smart Card Workgroup.

**PE** - Profile Element. A SAIP component.

**PIN** - Personal Identification Number.

**PKID** - Public Key Identifier.

**PPR** - Profile Policy Rule.

**PUK** - Personal Unblocking Key.

## R

**RAM** - Remote Application Management.

**RES** / **RES*** - AKA response (`RES`) and the 5G AKA derived response
(`RES*`, derived per 3GPP TS 33.501 Annex A.4).

**RAT** - Rules Authorisation Table.

**RFM** - Remote File Management.

**RSP** - Remote SIM Provisioning.

## S

**SAIP** - SIMalliance Interoperable Profile.

**SCP** - Secure Channel Protocol.

**SCP02 / SCP03 / SCP11** - GP-defined secure channel protocols.

**SCP80** - ETSI TS 102 225 / 226 OTA secured packet format.

**SE** - Secure Element.

**SGP** - SIM Group Permanent. GSMA's permanent reference document series
covering SIM / eUICC specifications (e.g. SGP.02, SGP.22, SGP.32).

**SIM** - Subscriber Identity Module.

**SM-DP+** - Subscription Manager - Data Preparation (enhanced).

**SM-SR** - Subscription Manager - Secure Routing.

**SPI** - Security Parameter Indicator (OTA).

**STK** - SIM Application Toolkit.

**SUCI** - Subscription Concealed Identifier (5G).

**SUPI** - Subscription Permanent Identifier (5G).

## T

**TAC** - Toolkit Application Command.

**TLV** - Tag-Length-Value.

**TP-UD** - Transport Protocol User Data (OTA).

**TPDU** - Transport Protocol Data Unit (ISO 7816-3).

**TUAK** - 3GPP TUAK authentication algorithm set.

**TUI** - Text User Interface.

## U

**UICC** - Universal Integrated Circuit Card.

**UPP** - Unprotected Profile Package.

**USIM** - Universal Subscriber Identity Module.
