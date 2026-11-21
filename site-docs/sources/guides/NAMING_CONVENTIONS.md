<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Naming Conventions

YggdraSIM is a public-release SAIP / SIM / eUICC toolchain. Every
operator-visible label in the GUI, TUI and CLI is either anchored
in a published standard (3GPP, ETSI, GSMA, ISO 7816, GlobalPlatform,
TCA SAIP) or is YggdraSIM-coined and deliberately distinct from any
commercial SIM-tooling vendor's surface text.

This document is the source of truth for that lineage. When adding a
new operator-visible label, pick a row in the table below -- or
extend the table with a fresh entry citing the spec or, if no spec
applies, flagging the label as YggdraSIM-coined.

## Ribbon group labels (SAIP workbench, web GUI)

| Label       | Anchor                                                       |
| ----------- | ------------------------------------------------------------ |
| Package     | TCA SAIP §3 `ProfilePackage`; SGP.22 §2.5                    |
| Element     | SGP.22 §2.5.4 `ProfileElement` / TCA SAIP §6                 |
| Filesystem  | ETSI TS 102 221 §8 (file system); one word, YggdraSIM voice  |
| Tokens      | YggdraSIM-coined; binds `[NAME]` placeholders in a SAIP doc  |
| Lint        | YggdraSIM-coined; backed by `Tools/ProfilePackage/lint_engine` |
| Reference   | YggdraSIM-coined; surfaces spec citations + shipped guides   |

## Top-tab labels (SAIP workbench)

| Label         | Anchor                                                       |
| ------------- | ------------------------------------------------------------ |
| PE list       | SGP.22 §2.5.4; "list" is generic English                     |
| FS tree       | ETSI TS 102 221 §8 file system tree                          |
| AID directory | ETSI TS 102 221 §13.1 EF.DIR; ISO/IEC 7816-5 AID             |

## Per-PE detail tabs

| Label        | Anchor                                                        |
| ------------ | ------------------------------------------------------------- |
| Decoded view | YggdraSIM voice -- what the tab shows (typed editor + hex)     |
| JSON         | Generic data-format name; the projection is a flat JSON tree  |

The PE type travels in the tab's `data-pe-type` attribute and tooltip
(e.g. `PE-USIM`) so the operator can see the underlying class without
the label echoing any vendor's "PE-<Type> Editor" tab convention.

## File-detail tabs (FS tree → leaf EF)

| Label                    | Anchor                                                  |
| ------------------------ | ------------------------------------------------------- |
| File Control Parameters  | ETSI TS 102 221 §11.1.1 FCP template                    |
| Data                     | ETSI TS 102 221 §11.1.5 / TCA SAIP `fillFileContent`    |
| JSON                     | Generic                                                  |

## Reference (Help) buttons

| Label      | Anchor                                                          |
| ---------- | --------------------------------------------------------------- |
| Spec card  | YggdraSIM voice -- surfaces the PE's title + ASN.1 module + spec |
| Guides     | YggdraSIM voice -- opens the shipped `guides/` catalogue         |

## SAIP profile-element class names

These names live in the TCA SAIP ASN.1 schema
(`pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`). They are
spec-locked and used verbatim throughout the tool:

```
ProfileHeader, PE-End, PE-USIM, PE-OptUSIM, PE-ISIM, PE-OptISIM,
PE-CSIM, PE-OptCSIM, PE-Telecom, PE-PINCodes, PE-PUKCodes,
PE-AKAParameter, PE-CDMAParameter, PE-MF, PE-SecurityDomain,
PE-Application, PE-RFM, PE-NFC, PE-RAM, PE-3GPPRegistration,
PE-CRT, PE-ARA-M, PE-IoT, PE-OPT-IoT, genericFileManagement, ...
```

## IoT Minimal Profile (PE-IoT / PE-OPT-IoT)

| Label                              | Anchor                                                         |
| ---------------------------------- | -------------------------------------------------------------- |
| IoT Minimal Profile Files          | TCA SAIP v3.4.1 §7.5 "IoT Minimal Profile"; §8.3.4.8.1 PE-IoT  |
| IoT Minimal Profile Optional Files | TCA SAIP v3.4.1 §8.3.4.8.2 PE-OPT-IoT                          |
| MF + ADF.USIM                      | YggdraSIM-coined; the two levels one PE-IoT creates (§9.10.1)  |
| ADF.USIM (IoT optional)            | YggdraSIM-coined; PE-OPT-IoT files below the PE-IoT ADF        |

## Filesystem primitives

| Term | Anchor                              |
| ---- | ----------------------------------- |
| MF   | ETSI TS 102 221 §8.1                |
| ADF  | ETSI TS 102 221 §8.5                |
| DF   | ETSI TS 102 221 §8.4                |
| EF   | ETSI TS 102 221 §8.7                |
| FCP  | ETSI TS 102 221 §11.1.1             |
| ARR  | ETSI TS 102 221 §9.2.7              |
| SFI  | ETSI TS 102 221 §8.7                |
| FID  | ETSI TS 102 221 §8.6 file ID        |
| BER-TLV | ITU-T X.690                      |
| ATR  | ETSI TS 102 221 §6.3 Answer To Reset |
| Life-cycle state (LCSI) | ETSI TS 102 221 §11.1.1.4.9 life cycle status integer (tag '8A', Table 11.7b); TCA SAIP v3.4.1 §8.3.2 `Fcp.lcsi` |
| Link path | TCA SAIP v3.4.1 §8.3.2 `Fcp.linkPath` |
| Linked file | TCA SAIP v3.4.1 §8.3.5 createFCP table (EF link, DF link) |
| Source file | TCA SAIP v3.4.1 §8.3.3 note 1 (the file a link shares its body with) |
| Current DF | TCA SAIP v3.4.1 §8.3.5: the DF a Generic File Management command creates its file in. The PE starts at the MF, `filePath` selects a DF or ADF by path from the MF, a created DF or ADF is selected automatically. The GFM card's chip, group heads and detail card carry the label |

## 3GPP / GSMA terminology

| Term              | Anchor                                                      |
| ----------------- | ----------------------------------------------------------- |
| ICCID             | ITU-T E.118; TS 102 221 §13.2 EF.ICCID                      |
| IMSI              | TS 23.003 §2.2; TS 31.102 §4.2.2 EF.IMSI                    |
| Routing Indicator | TS 31.102 §4.4.11.10 EF.Routing_Indicator                   |
| SUCI              | TS 33.501 §6.12; TS 31.102 §4.4.11.8 EF.SUCI_Calc_Info      |
| URSP              | TS 24.526; TS 31.102 §4.4.11 EF.URSP                        |
| Mandated          | TCA SAIP `mandated` member; SGP.22 §2.5.4                   |
| SMSC address      | SGP.02 v4.2 Table 94 (SMS connectivity parameters); TS 24.011 §8.2.5.2 RP-Destination Address; TS 31.102 §4.2.27 TS-Service Centre Address |
| Fallback / Fallback allowed (profile card) | SGP.32 v1.3 §4.4 ProfileInfo `fallbackAttribute` (tag '9F26') and `fallbackAllowed` (tag '9F67'); "not reported" when the eUICC refused the tag list |

## GlobalPlatform terminology

| Term                  | Anchor                                                  |
| --------------------- | ------------------------------------------------------- |
| Issuer Security Domain | GP CardSpec v2.3 §11; SGP.22 §2.6.1 ISD-R / ISD-P      |
| Application Privileges | GP CardSpec v2.3 Table 11-49                           |
| Life Cycle State      | GP CardSpec v2.3 §11.1.1                                |
| OPEN                  | GP CardSpec v2.3 §6 GlobalPlatform Environment          |

## Security Domain key list (SAIP workbench, Decoded view)

The PE-SecurityDomain Decoded view opens its `keyList` with an overview
table, one row per `KeyObject`, above the per-key groups; a divider names
each run of equal key version numbers. Column headers are the ASN.1
member names shortened to the GlobalPlatform abbreviations.

| Label / column            | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Key list                  | TCA SAIP v3.4.1 section 8.6.1 `keyList`                                  |
| Keyset N (index i)        | YggdraSIM voice for one SAIP v3.4.1 section 8.6.3 `KeyObject`; "keyset" is the word that clause uses for the object a `keyCounterValue` belongs to, i is the `keyList` index |
| Key version 0xNN          | `keyVersionNumber` (SAIP v3.4.1 section 8.6.3, coded per GP CS); the divider between runs of one version |
| KVN / KID                 | `keyVersionNumber` / `keyIdentifier`, GP abbreviations                   |
| Role                      | YggdraSIM-coined column; KIc and KID per TS 102 225 v19 section 5.1, KIK and the ENC / MAC / DEK aliases per the tool's key-identifier option list (SCP02 / SCP03 convention) |
| Type                      | `keyType` (SAIP v3.4.1 section 8.6.3; GP CS Table 11-16) with the key length in bits |
| Usage / Access            | `keyUsageQualifier` / `keyAccess` (SAIP v3.4.1 section 8.6.3; GP CS section 11.1.9) |
| MAC                       | `macLength` (SAIP v3.4.1 section 8.6.3; TS 102 226)                      |
| Counter / default         | `keyCounterValue` (SAIP v3.4.1 section 8.6.3); "default" marks an absent value, which the eUICC replaces with the protocol's initial counter |
| initial counter           | The per-key group's meta text for the same field, YggdraSIM voice       |
| Key data                  | `keyData` (SAIP v3.4.1 section 8.6.3), shown in full                     |
| Expand all / Collapse all | Plain English; the same verbs as the EF.ARR record list                 |

## Remote File Management (SAIP workbench, Decoded view)

The PE-RFM card states which directory an RFM script starts in and moves
the instance between the two scopes TCA SAIP v3.4.1 section 8.8 defines
through the optional `adfRFMAccess` member.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Default directory         | YggdraSIM-coined block title; section 8.8 says the bound ADF "shall be selected by default" and the MF otherwise |
| Selected by default       | The same clause's wording, used as the row label                       |
| MF -- UICC shared file system | ETSI TS 102 226 V19.0.0 section 7.2 "UICC Shared File System Remote File Management" |
| ADF.USIM / ADF.ISIM / ADF.CSIM | ETSI TS 102 226 section 7.3 "ADF Remote File Management"; the ADF names of TS 102 221 section 8.3 |
| ADF access domain / ADF admin domain | `adfAccessDomain` / `adfAdminAccessDomain` (section 8.8), coded per TS 102 226 section 8.2.1.3.2.5 |
| UICC access domain / UICC admin domain | `uiccAccessDomain` / `uiccAdminAccessDomain` (section 8.8)             |
| Bind ADF / Edit binding / Unbind ADF (MF only) / Apply binding | YggdraSIM-coined verbs for installing, replacing and dropping `adfRFMAccess` |
| Custom AID...             | The ADF select's entry for an AID the profile does not create; plain English |
| Security domain AID / MNO-SD (associated by default) | `securityDomainAID` (section 8.8: absent, the instance is associated to the MNO-SD) |
| TAR values                | `tarList` (section 8.8); the ranges in the hint are ETSI TS 101 220 V19.0.0 Annex D Table D.1 |
| Draft / Discard           | YggdraSIM-coined chip on an editor whose values are typed but not applied; kept while the operator switches packages or elements |

## Security Domain personalisation data (SAIP workbench, Decoded view)

The PE-SD card shows each `sdPersoData` record raw and decoded, and takes a
new record.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| SD personalisation data   | `sdPersoData` (TCA SAIP v3.4.1 section 8.6); plain English for the card title |
| Decoded DGI blocks        | GlobalPlatform DGI coding (DGI, length, value) as the repo's DGI decoder reads it; YggdraSIM-coined block title |
| DGI / tag, Name, Len, Value | Column heads of the decoded table; generic                             |
| Record N                  | One `sdPersoData` entry, numbered from 1; generic                      |
| Add DGI record            | YggdraSIM-coined verb: appends one STORE DATA body to `sdPersoData`    |

## PE library (SAIP workbench, Element ribbon)

Saved profile elements, kept as the PE document Export PE writes under the
operator's `~/.yggdrasim/saip_pe_library/` (`YGGDRASIM_SAIP_PE_LIBRARY`).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Save PE                   | YggdraSIM-coined ribbon verb next to Import PE / Export PE; the dialog is "Save profile element" |
| Saved PE name             | The entry's name in the library; YggdraSIM-coined field label          |
| PE library                | YggdraSIM-coined ribbon entry and dialog title                         |
| Load / Delete             | The dialog's per-entry verbs; plain English                            |
| Save package as           | YggdraSIM-coined dialog title; its Format entries name the server's save formats (DER, HEX, ASN.1 value notation, tagged JSON, varder) |
| Insert profile element    | YggdraSIM-coined dialog title behind Add above / Add below; lists the `ProfileElement` CHOICE alternatives of the SAIP module (TCA SAIP v3.4.1 section 8.1) and the saved PEs |
| From the PE library / Back to types | Section title and footer verb of that dialog; plain English                 |
| DF name (AID)             | `Fcp.dfName` (TCA SAIP v3.4.1 section 8.3.2), the ADF's application identifier; row label of the FCP editor |

## Typed editors of a profile element added from scratch (SAIP workbench, Decoded view)

A profile element inserted blank carries only its header; these cards add
and edit the members TCA SAIP v3.4.1 section 8 gives it. Field labels name
the ASN.1 member they write.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Not available             | Insert dialog meta of a CHOICE alternative no blank can build (PE-CSIM: pySim has no CSIM template); YggdraSIM-coined |
| Insert PE-EAP / DF.EAP file ID | The DF.EAP a PE-EAP creates (TCA SAIP v3.4.1 section 8.3.4.7); its file ID is the one the application's EF.DIR record lists (ETSI TS 102 310 v9.1 section 5.2) |
| Mandated                  | `PEHeader.mandated` (section 8.1.3): an eUICC that does not support the PE aborts the installation |
| This element does not encode yet | YggdraSIM-coined notice naming the encoder's reason while a member the element needs is missing |
| No member of this element is set yet | YggdraSIM-coined empty state of the PE-level decoded form          |
| Application load and install | YggdraSIM-coined card title for PE-Application (section 8.7)         |
| Load package / Add load package... / Replace load package... / Remove load package | `ApplicationLoadPackage` (section 8.7.2); the verbs are plain English |
| CAP / IJC file            | The Java Card load file formats (JCVM 3.1 chapter 6) the load block is read from |
| Load block / Load package AID / Non-volatile code limit (C6) / Volatile data limit (C7) / Non-volatile data limit (C8) / Hash | `loadBlockObject`, `loadPackageAID`, `nonVolatileCodeLimitC6`, `volatileDataLimitC7`, `nonVolatileDataLimitC8`, `hashValue` (section 8.7.2) |
| Instances / Add instance... / Edit instance... / Remove instance | `instanceList` of `ApplicationInstance` (section 8.7.3); the instances install the PE's one load package (section 8.7.1) |
| Add application instance / Edit application instance | YggdraSIM-coined titles of the instance dialog; Privileges lists one check box per privilege bit (GP Card Spec v2.3.1 Tables 11-7 to 11-9) |
| Instance parameters       | YggdraSIM-coined card title: the install parameters of one PE-Application instance (`systemSpecificParameters`, `applicationParameters`, `processData`; section 8.7.3), in the security domain's parameter editor |
| Class AID / Instance AID / Privileges / Life cycle state / Application specific parameters (C9) / Extradite security domain AID / UICC toolkit parameters / UICC access parameters / UICC administrative access parameters / Process data | `classAID`, `instanceAID`, `applicationPrivileges`, `lifeCycleState`, `applicationSpecificParametersC9`, `extraditeSecurityDomainAID`, the `UICCApplicationParameters` fields and `processData` (section 8.7.3) |
| Priority level / Max timers / Max text length for menu entry / Menu entries (Position, Identifier) / Max channels / Minimum Security Level / TAR values | The toolkit resources in the order ETSI TS 102 226 V19.0.0 sections 8.2.1.3.2.1 and 8.2.1.3.2.2.1 give them; a menu entry is its position, then its identifier ('00' means do not care) |
| Max services / Additional bytes | The UICC toolkit parameters only (section 8.2.1.3.2.2.1): the maximum number of services for the instance, then additional parameters the card ignores; empty Max services ends the field after the TAR values |
| Access domain (SIM File Access and Toolkit, CA) | The access domain that leads the 'CA' block (section 8.2.1.3.2.1); the UICC toolkit parameters ('80') hold none |
| UICC file system / ADF / ADF AID / Access domain / Access domain DAP / + UICC file system entry / + ADF entry / Remove entry | The entries of the UICC (administrative) access parameters, ETSI TS 102 226 V19.0.0 section 8.2.1.3.2.2.2: an empty AID for the UICC file system, an ADF AID of 5 to 16 bytes, the access domain of section 8.2.1.3.2.5 and its DAP; the verbs are YggdraSIM-coined |
| Minimum Security Level presets: No check / CC / CC + counter / CC + ciphering + counter | The MSL field of the toolkit parameters, ETSI TS 102 226 V19.0.0 section 8.2.1.3.2.4: empty, or '01' Minimum SPI1 with the data byte '02', '12' or '16' (the first SPI octet of ETSI TS 102 225 V19.0.0 section 5.1.1; CC is its cryptographic checksum) |
| Keys and life cycle / Add key... / Replace... / Remove | YggdraSIM-coined card title and verbs for `keyList` (section 8.6.3) and the SD instance `lifeCycleState` |
| Key version number (KVN) / Key identifier (KID) / Key usage qualifier / Key access / Key type / Key value / MAC length / Key counter value | `KeyObject` members (section 8.6.3); Key value is `keyData`, shown in full |
| Remove DGI record...      | YggdraSIM-coined verb dropping one `sdPersoData` record                |
| Instance AID / Min. security level (RFM) | `instanceAID` / `minimumSecurityLevel` (section 8.8)            |
| CDMA authentication       | YggdraSIM voice for the PE-CDMAParameter card (section 8.4.3)          |
| Authentication key (A-key) / Shared secret data (SSD) / HRPD access authentication data / Simple IP authentication data / Mobile IP authentication data | `authenticationKey`, `ssd`, `hrpdAccessAuthenticationData`, `simpleIPAuthenticationData`, `mobileIPAuthenticationData` (section 8.4.3) |
| Non-standardised content / Issuer ID / Content | Section 8.9 title "Non standardised content"; `issuerID`, `content` |
| PIN context / Share the PINs of / Shared with / Define PINs here | `pinCodes` CHOICE (section 8.5.1): `pinconfig` or `filePath`, "PIN can be either defined in the current context or shared with another DF/ADF" |
| Authentication algorithm / Configure algorithm... / Map to another NAA... / Change mapping... / Use own algorithm | `algoConfiguration` CHOICE (section 8.4.2): `algoParameter` or `mappingParameter`; the verbs are YggdraSIM-coined |
| Algorithm / Key / OPc / TOPc / Algorithm options / Keccak iterations (TUAK) / authCounterMax / Rotation constants (MILENAGE) / Xoring constants (MILENAGE) / sqnInit seed | `AlgoParameter` members (section 8.4.2); the seed fills all 32 `sqnInit` slots |
| Mapped to / Source application AID / SQN sharing | `mappingSource` and the `mappingOptions` b3-b2 value (section 8.4.2, page 49) |

## Fields of a profile element (SAIP workbench, Decoded view)

The Decoded view ends in every member the SAIP ASN.1 module (TCA SAIP v3.4.1
section 8, as pySim compiles it) gives the selected element, present or not.
Each field carries the ASN.1 member name and type as the module spells them;
the controls, notices and the values the pickers offer are the labels below.
Clause numbers without a document are Rec. ITU-T X.680 (02/2021).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Fields / All fields       | YggdraSIM-coined card titles: the element's members; "All fields" folds them under a file-system workbench or the GFM card |
| ×                         | Takes an `OPTIONAL` or `DEFAULT` member (clause 25) or a list entry (clause 26) out of the element |
| New entry / Entry n       | YggdraSIM-coined: the place past the end of a `SEQUENCE OF` (clause 26) that a value turns into an entry, and the entries it holds, counted from 1 |
| (not set) / (choose an alternative) | YggdraSIM-coined: a member the element does not hold; a `CHOICE` (clause 29) holding no alternative yet |
| Switch                    | Confirms replacing the alternative a `CHOICE` holds (clause 29) |
| Custom value...           | YggdraSIM-coined: a value the list does not name, where the type takes one |
| Decoded                   | Opens the decoded editor of a field whose bytes have a decoder of their own (C9 install parameters) |
| Edited in SD personalisation data below. | YggdraSIM-coined: the PE-SD's `sdPersoData` is listed with its entry count and edited in the SD personalisation data card (raw DGI records, a placeholder inside a record, the decoded DGI blocks), not in the fields |
| optional / SIZE (...) / DEFAULT ... | The constraint as the module declares it (clauses 25 and 51.5) |
| placeholder               | YggdraSIM-coined chip: an all-zero AID, or the filler identifier or text, a member was added with and no profile carries |
| present / true            | A `NULL` member that is in the element (clause 24); a `BOOLEAN` set |
| Draft / Discard draft     | YggdraSIM-coined: edits pySim cannot build the element with yet, held outside the profile (and out of Save) until it can; Discard draft drops them, and a notice says when a change elsewhere (another editor, Undo) dropped one |
| Rule                      | The EF.ARR record a file's `securityAttributesReferenced` points at, offered with its decoded rules (ETSI TS 102 221 v18.4 §9.2.7; SAIP V3.4.1 §8.3), in the FCP editor |
| Privileges (n of m active) | YggdraSIM-coined count over a security domain's `applicationPrivileges`, shown as one chip per privilege of GP Card Spec v2.3.1 §11.1.2 Tables 11-7 to 11-9 (page 149) with the held ones lit, in the Fields tree and read-only on the AID directory's security-domain cards; an application's privileges keep one check box per row in the Fields tree and a list of the held ones in the AID directory |

The values the pickers offer carry the names their clause gives them:

| Field                     | Values from                                                            |
| ------------------------- | ---------------------------------------------------------------------- |
| lifeCycleState            | GP Card Spec v2.3.1 §11.1.1 Table 11-4 (applications) and Table 11-5 (security domains) |
| applicationPrivileges     | GP Card Spec v2.3.1 §11.1.2 Tables 11-7 to 11-9 |
| keyType / keyUsageQualifier / keyAccess | GP Card Spec v2.3.1 Table 11-16, §11.1.9, Table 11-19 |
| lcsi                      | ETSI TS 102 221 v18.4 Table 11.7b |
| fileDescriptor (Transparent, Linear fixed, Cyclic, BER-TLV, DF or ADF, Shareable, Record length) | ETSI TS 102 221 v18.4 Table 11.5 |
| shortEFID (No SFI, SFI n) | ETSI TS 102 221 v18.4 §11.1.1.4.8 and §8.3 |
| tarList                   | ETSI TS 101 220 V19.0.0 Annex D Table D.1 (remote file management TARs) |
| minimumSecurityLevel (Integrity, Ciphering, Counter) | The first SPI octet, ETSI TS 102 225 V19.0.0 §5.1.1, as ETSI TS 102 226 V19.0.0 §8.2.1.3.2.4.2 uses it |
| uicc / adf (Admin)AccessDomain | ETSI TS 102 226 V19.0.0 §8.2.1.3.2.5 (parameter, Application PIN 1-8, ADM1-ADM10, ALWAYS, Local PIN) |
| pinAttributes / maxNumOfAttemps-retryNumLeft | TCA SAIP v3.4.1 §8.5.1 (pages 52-53) |
| algorithmOptions / sqnOptions / mappingOptions | TCA SAIP v3.4.1 §8.4.2 (pages 48-49) |
| templateID (version n)    | The versions of one template under arc 2.23.143.1.2.n, TCA SAIP v3.4.1 Annex A (page 112) |
| named INTEGER values      | The ASN.1 module's own names (keyReference, algorithmID, ...) |
| AIDs                      | The ADFs the profile creates and the AIDs its elements hold |

## Variables panel (SAIP workbench)

The panel that was the Token editor: one row per placeholder of the open
package, with the value it takes and where it comes from.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Variables                 | YggdraSIM-coined; the panel and its ribbon entry. "Variable" is the TCA SAIP personalisation-data word for a placeholder's value |
| Source                    | YggdraSIM-coined column: where the row's value comes from              |
| Typed / Profile list / Universal list / List value / Unset | The Source badges: a value stored through the panel; the test-value list bound to the profile; the operator-wide list; bytes stored from a list no longer named; nothing yet. YggdraSIM-coined |
| Catalog default / Token / Referenced | The Source badges of a catalog variable without a typed value, a `{NAME}` token definition, and a name the document references without a definition. YggdraSIM-coined |
| Use list value            | YggdraSIM-coined verb: drop the typed value, take the lists' answer again |
| Set a variable by name    | YggdraSIM-coined; the folded name form for a name the table does not list |
| Generate test profile     | YggdraSIM-coined; the ribbon entry and panel button that write one DER or HEX with every placeholder replaced by its value (typed, else the lists'); it replaced "Export complete profile" |
| Apply test values / Export list / Edit lists / Test-value list | Unchanged labels of the list controls, now inside the panel (see *Test-value list* above) |
| Typed spelling            | YggdraSIM-coined; respells a vendor template's inline placeholders in the typed form (`{var:TYPE:len[:modifier]}`), shown only while a compact literal remains |
| Insert a variable / Insert variable... | YggdraSIM-coined; the placeholder picker opened by the Insert variable button of the JSON tab, the raw hex, ICCID and IMSI editors and the header ICCID row |
| At byte offset            | YggdraSIM-coined; the picker's placement of a placeholder narrower than the field |
| Universal list (panel section) | YggdraSIM-coined; the panel's rows of list placeholders the package does not carry, with their test values, dragged or copied into a field |
| New variable... / Define a variable | YggdraSIM-coined; the picker's new-placeholder form and the panel's folded form that writes a placeholder to the universal list |
| The selected bytes / The whole field | YggdraSIM-coined; the picker's two targets when bytes are selected in the input |
| Save to the universal list | YggdraSIM-coined; the picker's checkbox that makes a new placeholder available in every profile |

## Remote Lab device card (web GUI)

The card's verbs are plain English (Connect, Disconnect, Refresh, Export,
Remove, Edit, Save, Cancel) and carry no spec lineage. The editor's field
labels name the registry fields behind them, so the label and the stored key
stay readable as one thing.

| Label        | Anchor                                                        |
| ------------ | ------------------------------------------------------------- |
| Agent host   | `agent.host` in the Remote Lab invite / registry schema        |
| Control port | `agent.control_port`; the agent's control API, not the stream  |
| Scheme       | `agent.scheme`; `http` or `https` per RFC 9110 §4.2            |
| Tags         | `device.tags`; YggdraSIM-coined, free-form operator labels     |
| Owner        | `device.owner`; YggdraSIM-coined                               |
| Location     | `device.location`; YggdraSIM-coined, free-form site text       |
| Notes        | `device.notes`; YggdraSIM-coined                               |

## Certificate view (ES10b GetCerts in the eSIM shells)

The GetCerts block of DISCOVER, GET-CERTS and the local-access snapshot shows
each certificate field by field (`SCP11/shared/certificate_view.py`).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| EUM Certificate / eUICC Certificate | `eumCertificate [5]` / `euiccCertificate [6]` of GetCertsResponse (SGP.32 v1.3 §5.9.10) |
| Version                   | `version` (RFC 5280 §4.1.2.1), shown as 3 for a v3 certificate          |
| Subject / Issuer          | `subject` / `issuer` (RFC 5280 §4.1.2.6 / §4.1.2.4), most specific RDN first |
| Serial Number             | `serialNumber` (RFC 5280 §4.1.2.2); a value that is not positive is marked |
| Valid From / Valid Until  | `notBefore` / `notAfter` of `validity` (RFC 5280 §4.1.2.5); the time left follows Valid Until |
| Public Key / Public Key Bytes | `subjectPublicKeyInfo` (RFC 5280 §4.1.2.7): algorithm and size, then the `subjectPublicKey` contents |
| Signature Algorithm / Signature Value | `signatureAlgorithm` / `signatureValue` (RFC 5280 §4.1.1.2 / §4.1.1.3); an ECDSA value split into `r` and `s` (`ECDSA-Sig-Value`, RFC 5480 Appendix A) |
| Extensions                | `extensions` (RFC 5280 §4.1.2.9); each one under the name RFC 5280 §4.2.1.1 - §4.2.1.15 and §4.2.2.1 head it with, `[critical]` when `critical` is TRUE |
| Permitted EINs            | `id-rsp-extension-permitted-eins` (SGP.22 v3.1 §2.4a.1.0, §4.5.2.1.0.3 Table 12) |
| RSP Role                  | The `id-rspRole-*` value in `certificatePolicies` (SGP.22 v3.1 §2.4a.1.0) |
| EID                       | Subject `serialNumber` of an eUICC certificate (SGP.22 v3.1 §4.5.2.1.0.2 Table 11) |
| SHA-256 Fingerprint / SHA-1 Fingerprint | YggdraSIM-coined: the SHA-256 / SHA-1 digest of the certificate DER |
| DER Hex                   | YggdraSIM-coined: the certificate DER as one hex string                 |

## TLS handshake fields (BIP channel trace)

A card that runs TLS over BIP sends its handshake in clear until ChangeCipherSpec. The BIP
stream decoder and the certificate view label these fields under a `TLS Handshake:` line
(`yggdrasim_common/bip_stream_decode.py`, `SCP11/shared/certificate_view.py`).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| version                   | ClientHello `client_version` or its `supported_versions` list; ServerHello `server_version` or the version `supported_versions` selects (RFC 5246 §7.4.1.2, §7.4.1.3; RFC 8446 §4.2.1) |
| cipher suites / cipher suite | ClientHello `cipher_suites` / ServerHello `cipher_suite` (RFC 5246 §7.4.1.2, §7.4.1.3), each under the name its defining RFC gives it |
| max_fragment_length       | The extension of RFC 6066 §4: the value the client asks for, and on the ServerHello whether the server sent it back |
| extensions                | A hello's `extensions` (RFC 5246 §7.4.1.4) by ExtensionType name        |
| key exchange              | `ServerECDHParams` of an ECDHE ServerKeyExchange (RFC 8422 §5.4): named curve and public key length |
| signature                 | The algorithm of the `DigitallySigned` over those parameters (RFC 5246 §4.7), by SignatureScheme name (RFC 8446 §4.2.3) |
| structure                 | YggdraSIM-coined: a message whose layout the reader does not recognise  |
| certificate [n]           | Entry n of `certificate_list`, the sender's certificate first (RFC 5246 §7.4.2), named by its subject CN |
| issuer / valid / subjectAltName / public key | `issuer`, `validity`, the subjectAltName extension and `subjectPublicKeyInfo` (RFC 5280 §4.1.2.4, §4.1.2.5, §4.2.1.6, §4.1.2.7) |
| RSP role                  | The `id-rspRole-*` value in `certificatePolicies` (SGP.22 v3.1 §2.4a.1.0) |
| chain                     | YggdraSIM-coined: each certificate's signature checked against an issuer sent in the same list |
| server name               | The server identity check of RFC 2818 §3.1 against the `server_name` the ClientHello sent (RFC 6066 §3) |
| [n records] / [incomplete] | YggdraSIM-coined marks on the line: a message reassembled from several records (RFC 5246 §6.2.1), and one the channel closed on |
| Chain                     | YggdraSIM-coined: the issuer linkage among the certificates of one response; each entry reads `signature valid`, `signature INVALID`, `self-signed, ...` or `issuer not in the response, AKI ...` |
| Decode error / Parser Warning | YggdraSIM-coined: a value that is not an X.509 certificate / a warning the certificate parser raised for it |

## EF decode cards and wizards (SAIP workbench, Data tab)

A transparent EF the workbench understands gets an "EF.<name> decoded" card
under its hex and, where the file is edited field by field, an "EF.<name>
wizard"; `<name>` is the EF's TS 31.102 name. The rows the packet-switched
and 5GS files add:

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| EF.PSLOCI decoded / EF.PSLOCI wizard | `EFPSLOCI` (3GPP TS 31.102 v19.5 §4.2.23)                         |
| P-TMSI / P-TMSI signature / RAI / Routing Area update status | The four fields of that clause; RAI splits into PLMN, LAC and RAC as TS 24.008 codes them |
| EF.5GAUTHKEYS decoded     | `EF5GAUTHKEYS` (3GPP TS 31.102 v19.5 §4.4.11.6)                        |
| KAUSF / KSEAF for 3GPP access / KSEAF for non-3GPP access / SOR counter / UE parameter update counter | The '80' to '84' objects of that clause; `no valid value ('FF' fill)` is YggdraSIM-coined for the all-'FF' value the clause defines |
| EF.TN3GPPSNN decoded      | `EFTN3GPPSNN` (3GPP TS 31.102 v19.5 §4.4.11.13)                        |
| Serving network name objects | The count in byte 1 of that clause; each object is listed as `#n`   |

## Offline Tools entries

Offline Tools lists its entries under the Offline Tools leaf, opened one at a
time; there is no card grid. Tools that share an input or a store are one entry
with a tab per tool; every other tool is an entry under its own title, below.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Decoder                   | YggdraSIM-coined: the context decoder (`tool.decoder.context`), the first entry and what the Offline Tools leaf opens. Its tabs are Decoder and ASN.1/TLV decode (`tool.asn1_tlv.decode`, under its own title) |
| TERMINAL PROFILE (entry): Decode / Build | The TERMINAL PROFILE command (ETSI TS 102 221 V18.4 §11.2.1); the tabs are `tool.tp.decode` and `tool.tp.build`, plain English |
| AddInitialEim (entry): Build / Send / Configurations / Certificate store / Saved values | ES10b.AddInitialEim (GSMA SGP.32 v1.3 §5.9.4); the tabs are the five `tool.eim_builder.*` actions, each named after what it does with the builder store |
| SUCI keys (entry): Use key file / Generate / Dump public key | YggdraSIM-coined: the `suci.*` actions, which run pySim's `suci-keytool` on one key file; Generate shortens the action title Generate SUCI key |
| Workspace root / Active key file / Tool command (state line of SUCI keys) | YggdraSIM-coined: what `suci.status` reports, shown over the tabs and read again after every run; Tool command is the `suci-keytool` command in use, with where it comes from (the `YGGDRASIM_SUCI_TOOL` setting or the PATH) and where it is set (Environment > Configuration) |
| profile installation failed / all PEs ok (Decoder) | YggdraSIM-coined outcome of an EUICCResponse (TCA eUICC Profile Package V3.4.1 section 8.11), drawn over the Decoder's reading of a ProfileInstallationResult (GSMA SGP.22 v3.1 §2.5.6) or of the response pasted alone; the sentence beside it names each failing PEStatus and whether the installation was aborted |
| Open file (Decoder) | YggdraSIM-coined: reads a script or trace file into the Decoder's box, in the page; a script file is one command per row with `#` comments, as the SCP03 shell's `RUN` and the SCP80 shell's `script` read it |
| N commands / N exchanges / N of M commands, row N, "N rows held no hex and were left unread", "The input holds M commands; the first N are decoded here" (Decoder) | YggdraSIM-coined: a multi-row input with no answers is counted as commands, an exchange card names the input row it starts on, rows that are no hex are counted by number without being quoted, and the panel decodes the first 1000 exchanges of a longer input |
| EF content (Decoder context) | YggdraSIM-coined: the content of one elementary file, with the file identifier on the first line (with its path before it, `ADF_USIM/6F07`) and the content in hex below; read by the File system module's EF decoders |
| ATR / X.509 / Identifier / PC/SC / TLS / SAIP (Decoder chips) | YggdraSIM-coined short names of what a paste was read as when it is no APDU or TLV: an Answer To Reset (ETSI TS 102 221 V18.4 §6.3), a certificate (RFC 5280), an EID, ICCID or IMSI in digits (SGP.29 v1.1 §10, ITU-T E.118 §6, ITU-T E.212 §6.1), a PC/SC return code (the names are pyscard's), TLS records (RFC 5246 §6.2.1) and a profile package (TCA eUICC Profile Package V3.4.1) |
| SMS TPDU / TP-MTI, TP-OA, TP-PID, TP-DCS, TP-SCTS, TP-UDL, TP-UD, UDH (Decoder) | The elements of a short message transfer PDU (3GPP TS 23.040 V19 §9.2.2); Flags is YggdraSIM-coined for the one-bit elements that are set |
| Secured command packet / Secured response packet: CPL, CHL, SPI, KIc, KID, TAR, CNTR, PCNTR, RC/CC/DS, RPL, RHL, Status code (Decoder) | ETSI TS 102 225 V19.0.0 §5.1 and §5.2 as 3GPP TS 31.115 V19 §4.2 and §4.4 carry them in a short message; "SPI / integrity", "SPI / PoR transport" and the like are YggdraSIM-coined names of the SPI fields |
| Key Information Data / Key N / component N / Key Check Value / Key Usage Qualifier / Key Access Condition (Decoder) | GlobalPlatform Card Specification v2.4 §11.3.3.1 and §11.8.2.3 |
| MUTUAL AUTHENTICATE / INTERNAL AUTHENTICATE / PERFORM SECURITY OPERATION, ePK.OCE.ECKA, ePK.SD.ECKA, PK.SD.ECKA, Receipt, Control Reference Template (Key Agreement) (Decoder) | GlobalPlatform Card Specification Amendment F v1.2 §6.4 to §6.6, spelled as its tables spell them |
| TLS Handshake / TLS Record / TLS Alert / DNS Query / DNS Response / HTTP Request / HTTP Response under Channel data, with continues / reassembled / protected / cut short (Decoder) | The lines of the BIP payload decoder (`yggdrasim_common/bip_stream_decode.py`), as the HIL bridge decode view prints them: record and handshake names of RFC 5246 §6.2.1 and §7.4, DNS of RFC 1035 §4.1, HTTP of RFC 9112 §3 and §4; the four state words are YggdraSIM-coined |
| Data for key establishment / Key establishment response / Certificate(s) (Decoder) | YggdraSIM-coined titles of the data fields of the SCP11 commands (GlobalPlatform Card Specification Amendment F v1.2 Tables 6-11, 6-17, 6-20, 6-23 and 6-24) |
| SUCI: SUPI format / Home network identifier / Routing indicator / Protection scheme identifier / Home network public key identifier / Scheme output (Decoder) | 3GPP TS 31.102 V19.5 §7.5.2.1 |
| SGP.32 check PASS / WARN (Decoder note) | YggdraSIM-coined: the members GSMA SGP.32 v1.3 §5.9.2 makes mandatory in the EUICCInfo2 of an IoT eUICC and those it leaves unused, checked when the answer carries ipaMode or iotSpecificInfo |

## TERMINAL PROFILE entries (Offline Tools)

The Decode and Build tabs of the TERMINAL PROFILE entry (`tool.tp.decode`,
`tool.tp.build`), the context decoder's TERMINAL PROFILE rows and
`python -m yggdrasim_common.terminal_profile` share one table
(`yggdrasim_common/terminal_profile.py`).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| TERMINAL PROFILE decode / TERMINAL PROFILE build | The titles of the two actions, shown at the head of each tab's pane: the TERMINAL PROFILE command (ETSI TS 102 221 V18.4 §11.2.1) and the coding of its profile (ETSI TS 102 223 V18.3.0 §5.2); decode and build are plain English |
| Byte N (title)            | The bytes of that clause, counted from 1, with the title the clause gives a byte ("Download", "Screen height", ...) |
| Facility names            | The wording of TS 102 223 V18.3.0 §5.2; a bit it reserves for 3GPP carries the meaning in its parentheses, marked (3GPP) or (3GPP and 3GPP2) |
| TS 31.111                 | The reading 3GPP TS 31.111 V19.4.0 §5.2 gives a bit where it differs from TS 102 223 |
| 5.5 / 13.6-8 (address)    | YggdraSIM-coined: byte.bit with b1 the lowest bit, as the clause draws them; a count field by its bit range |
| Start from: maximal / empty / pasted | YggdraSIM-coined; maximal is the profile every YggdraSIM shell sends (`MAXIMAL_TERMINAL_PROFILE`, `yggdrasim_common/stk_terminal.py`) |
| Profile hex / Compare with / Show / Pasted profile / Set / Clear / Field values / Length | Plain English form labels |
| error / warning / info    | YggdraSIM-coined finding levels: a "bit = 0" or "shall not" coding broken; a "should" of the clause or a TS 31.111 bit group set in part; a negative or foreign claim, or a note on the input |

## AddInitialEim build (Offline Tools, eSIM Live)

The tabs of the Offline Tools AddInitialEim entry (`tool.eim_builder.add_initial_eim`,
`tool.eim_builder.send`, `tool.eim_builder.configurations`,
`tool.eim_builder.certificates`, `tool.eim_builder.saved_values`), the eSIM Management send
(`scp11_live.add_initial_eim`) and the eSIM Live verbs
`ADD-INITIAL-EIM` and `EIM-CERT-STORE` share one builder
(`SCP11/shared/eim_builder.py`) and one untracked store
(`YGGDRASIM_EIM_BUILDER_STORE`, default `~/.yggdrasim/eim_builder/`).

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| AddInitialEim build / AddInitialEim send / ADD-INITIAL-EIM | ES10b.AddInitialEim (GSMA SGP.32 v1.3 §5.9.4); build and send are plain English |
| I understand this removes the card's eIM Configuration Data and adds this eIM | Plain English confirm label of the send (`tool.eim_builder.send`, `scp11_live.add_initial_eim`) |
| eimId / eimFqdn / eimIdType / counterValue / eimPublicKeyData / eimCertificate / eimPublicKey / trustedPublicKeyDataTls / trustedCertificateTls / trustedEimPkTls / euiccCiPKId / indirectProfileDownload | The EimConfigurationData members and alternatives of SGP.32 v1.3 §2.11.1.1.1, spelled as its ASN.1 spells them |
| eimRetrieveHttps / eimRetrieveCoaps / eimInjectHttps / eimInjectCoaps / eimProprietary | The EimSupportedProtocol bits of SGP.32 v1.3 §2.11.1.1.1 (§4.2) |
| Request associationToken  | associationToken -1, the request for a token SGP.32 v1.3 §5.9.4 defines |
| auto / omit (eimIdType)   | YggdraSIM-coined: auto reads the eimId as an OID, an FQDN or proprietary text (SGP.32 v1.3 §4.3); omit leaves the member out |
| eUICCMemoryReset (resetEimConfigData, resetImmediateEnableConfig) | ES10b.eUICCMemoryReset and its resetOptions bits (SGP.32 v1.3 §5.9.5), sent before every AddInitialEim |
| APDU script               | YggdraSIM-coined: the command APDUs of one run, one per line, for a shell that replays APDUs; Copy takes the commands alone |
| AddInitialEim as one APDU | YggdraSIM-coined: the AddInitialEimRequest in a single STORE DATA (P1 '91'), with an extended Lc past 255 bytes, in place of the request's bare TLV |
| eIM certificate / TLS certificate | YggdraSIM-coined: the store entry that fills eimPublicKeyData / trustedPublicKeyDataTls |
| eIM certificate store / eIM builder saved values / EIM-CERT-STORE | YggdraSIM-coined: the store of certificates (`certificates/<name>.pem`) and of the values typed into the builder (`values.json`) |
| eIM builder configurations / Configuration / Save the form as this configuration | YggdraSIM-coined: a named copy of the whole AddInitialEim form (`configurations.json` in the store); picking one fills the form. Every build or send also keeps its whole form as the last build (`last_configuration.json`), which the build and send forms and the ADD-INITIAL-EIM wizard open with |
| Operation / Name / New name / Certificate file / Certificate text / Replace an entry of the same name / Field / Value / New value | Plain English form labels |
| (not in the certificate store) | YggdraSIM-coined marker on a saved certificate name whose certificate was removed or renamed outside the store |
| note / warning            | YggdraSIM-coined finding levels: a fact about the request; a clause the request or a certificate does not meet |

## Local eIM operation queue (Local eIM module, eIM-local shell)

The Command Center actions `eim_local.op_*`, `eim_local.euicc_*`, `eim_local.identity_*`,
`eim_local.associate`, `eim_local.service_*`, `eim_local.deliver`, `eim_local.queue_settings`,
`eim_local.package_import` and `eim_local.smdp_*` run the eIM-local shell verbs of the same names
(`SCP11/eim_local/engine_shell.py`) over the engine in `SCP11/eim_local/engine/`.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| Local eIM page: eUICCs / eIM configuration (tabs), Linked eUICCs, eSIM profiles, eUICC information, eIMs linked with eUICC, Event log, Refresh eSIM profile list, Download a profile, Refresh eUICC information, Refresh linked eIM list, Link this eIM, Deliver now (IPAd), Deliver (IPAe), Run the download (IPAd), New operation, Queue options, Enable with rollback, Set fallback / Unset fallback, Turn on / Turn off (immediate profile enabling), Set (default SM-DP+), Save changes, Queue a copy, Package / As served to the card / The part fixed so far, Result / The card's answer, Timeline, Read the card in the reader, Register an EID, Replace identity, Decode, Show more, Last updated, Queued / Sent to the card (operation states CREATED / SENT), Package files and hotfolder | YggdraSIM-coined, plain English. The page reads the store (`eim_local.overview`); each button queues the operation of the same meaning (PROFILE_INFO_LIST, PROFILE_DOWNLOAD_TRIGGER, IPA_EUICC_DATA, LIST_EIM, ENABLE / DISABLE / DELETE_PROFILE) or opens the action's form (Associate, Deliver, Read card into record). Linked means the record is associated with this eIM |
| Queue operation / QUEUE / New operation | YggdraSIM-coined; queues one operation, signed when an IPA takes it |
| LIST-PROFILES / ENABLE / DISABLE / DELETE / FALLBACK / UNSET-FALLBACK / IMMEDIATE-ENABLE / DEFAULT-SMDP / GET-RAT | The PSMOs listProfileInfo, enable, disable, delete, setFallbackAttribute, unsetFallbackAttribute, configureImmediateEnable, setDefaultDpAddress, getRAT (GSMA SGP.32 v1.3 §2.11.1.1.3) |
| ADD-EIM / UPDATE-EIM / DELETE-EIM / LIST-EIM | The eCOs addEim, updateEim, deleteEim, listEim (GSMA SGP.32 v1.3 §2.11.1.1.2) |
| IPA-DATA / DOWNLOAD | IpaEuiccDataRequest (GSMA SGP.32 v1.3 §2.11.1.2) / ProfileDownloadTriggerRequest |
| RAW-PSMO / RAW-ECO / Raw items | YggdraSIM-coined: a psmoList / ecoList whose items are given as hex |
| REFRESH | YggdraSIM-coined: LIST-PROFILES, LIST-EIM and IPA-DATA queued together |
| ENABLE_PROFILE, PROFILE_DOWNLOAD_TRIGGER, ... (operation types) | YggdraSIM-coined: the Local eIM's operation names, each mapped to the SGP.32 v1.3 object it becomes (a PSMO, an eCO, an IpaEuiccDataRequest or a ProfileDownloadTriggerRequest) |
| Created / Sent / Success / Partial success / Error / Canceled | YggdraSIM-coined operation states; SGP.32 v1.3 §3.1.1.1 says only that the eIM manages its queue of pending eIM Packages |
| Pending / Completed | YggdraSIM-coined: Created and Sent, then the other four states |
| Operations / Operation detail / Edit operation / Move operation / Cancel operation / Copy operation / Export operation / Import result | Plain English labels of the queue actions |
| eUICCs / eUICC record / Read card into record / Register eUICC / Edit eUICC record / Remove eUICC record | YggdraSIM-coined: what the Local eIM knows about each card (counterValue, associationToken, seqNumber, the eUICC certificate, profiles, eIMs) |
| eIM identity / New eIM identity / IDENTITY | YggdraSIM-coined: the Local eIM's eimId (GSMA SGP.32 v1.3 §4.3), signing key and certificates |
| Associate card / ASSOCIATE | YggdraSIM-coined: ES10b.eUICCMemoryReset with resetEimConfigData and resetImmediateEnableConfig, then ES10b.AddInitialEim (GSMA SGP.32 v1.3 §5.9.5, §5.9.4) |
| Association choices / ASSOCIATE CHOICES / TLS setup (field of Associate card, setup=) | YggdraSIM-coined: the identity, the TLS setups (eIM FQDN, trust) and the stored certificates an association can carry; the setup put in use before the association |
| Hand over card / ASSOCIATE HANDOVER | YggdraSIM-coined: ES10b.eUICCMemoryReset, then ES10b.AddInitialEim with another eIM's stored certificates (GSMA SGP.32 v1.3 §5.9.5, §5.9.4); the card then refuses this rig's packages (euiccPackageErrorUnsigned, §5.9.1) |
| Service status / Start service / Restart service / Stop service / SERVE | YggdraSIM-coined: the background ESipa service (ASN.1 binding, GSMA SGP.32 v1.3 §6.3) with the local SM-DP+ (ES9+) on the same address |
| Traffic / TRAFFIC / exchange / eIM: (IPAe terminal trace actor) | YggdraSIM-coined: one request a listener answered and its answer, recorded with the peer, the TLS chain picked and what the engine made of it; the ESipa functions are GetEimPackage, ProvideEimPackageResult and HandleNotification (GSMA SGP.32 v1.3 §5.14.5-5.14.7) |
| TLS key log (tls_keylog) | the NSS key log format Wireshark reads to decrypt TLS; the setting is YggdraSIM-coined |
| Profile rollback (device) / Execute fallback mechanism (device) / Return from fallback (device) / ROLLBACK, EXECUTE-FALLBACK, RETURN-FALLBACK | YggdraSIM-coined labels for the ES10b functions an IPAd calls on the eUICC itself, ES10b.ProfileRollback, ES10b.ExecuteFallbackMechanism and ES10b.ReturnFromFallback (GSMA SGP.32 v1.3 §5.9.16, §5.9.20, §5.9.21); "(device)" marks an operation the direct route executes on the reader and never serves to an IPA |
| Card TLS port / card-facing TLS listener | YggdraSIM-coined: the service's TLS listener for a card's IPAe (TLS with server authentication, GSMA SGP.32 v1.3 §2.6.3.2) |
| SM-DP+ card TLS port / SM-DP+ card-facing TLS listener | YggdraSIM-coined: the service's TLS listener for a card's IPAe that downloads directly from the local SM-DP+ (ES9+, GSMA SGP.32 v1.3 §5.6; ASN.1 binding, GSMA SGP.22 v3.1 §6.6.1; CERT.DP.TLS, §4.5.2.1.0.5) |
| TLS setups / New TLS setup / Show TLS setup / Use TLS setup / Remove TLS setup / TLS-SETUP | YggdraSIM-coined: a generated chain the card-facing listener serves and the trustedPublicKeyDataTls AddInitialEim carries for it (GSMA SGP.32 v1.3 §2.11.1.1.1) |
| Chain (self / root / intermediate) / Listener sends (leaf / chain / full) / Leaf name / Leaf validity / Then (build / use / apply) | YggdraSIM-coined: TLS setup options |
| New leaf / Leaves / Show leaf / Use leaf / Remove leaf / Leaf / Leaf on the name / TLS-SETUP LEAF / built | YggdraSIM-coined: a further end-entity certificate under a TLS setup's own CA and the one put on the setup's name; `built` is the leaf the setup was built with. A card given the root or an intermediate CA as trustedCertificateTls checks each of them (GSMA SGP.32 v1.3 §2.11.1.1.1) |
| setup (choice of a leaf option) / Put it on the setup's name / Replace a leaf of that name / Print the DER / Then (serve / serve_only / associate) / Force | YggdraSIM-coined: New leaf, Show leaf and Use leaf options; Print the DER gives the certificate and its SubjectPublicKeyInfo in hex, the two forms of trustedPublicKeyDataTls (GSMA SGP.32 v1.3 §2.11.1.1.1); setup keeps the TLS setup's own value, serve_only serves a leaf the card was not told to trust, associate runs Associate card, Force replaces or removes a TLS setup that has further leaves or associated cards |
| Certificate text / TLS-SETUP LEAF TEXT / TLS-SETUP TEXT / subject= / ext.<extension>= / extensions=none / text= / out= / Stored certificate / Leaf editor rows / Editor rows | YggdraSIM-coined: a leaf's subject and extensions as `key = value` lines, built as written. The subject is an RFC 4514 name or `rdn` lines with the string types of RFC 5280 §4.1.2.4; an extension goes by its RFC 5280 name (keyUsage §4.2.1.3, subjectAltName §4.2.1.6, extKeyUsage §4.2.1.12, ...) or its object identifier with `DER:<hex>`; `{host}`, `{eim_id}`, `hash` and `keyid` are YggdraSIM-coined stand-ins for the setup's FQDN, the eimId and the two computed key identifiers (§4.2.1.2, §4.2.1.1) |
| Leaf editor / Edit a copy of this leaf / Start from / Write the subject / Write the extensions / Same RDN as above / Add attribute / Add extension / Add name / Critical / CA / Path length / Other purposes / Leaf options / Check / Edit as text / Back to the rows / Apply text / Issue leaf / Load / Close / Move up / Move down / Remove / nothing (blank) / Other (object identifier) / Other (object identifier, DER) / hash (computed from the leaf's key) / keyid (computed from the issuer's key) / these octets | YggdraSIM-coined: the Local eIM page's view of a certificate text as rows. Critical, CA and Path length are the critical flag of an extension and the cA and pathLenConstraint members of BasicConstraints (RFC 5280 §4.2, §4.2.1.9); RDN is the relative distinguished name of §4.1.2.4 |
| TLS results / TLS-SETUP RESULTS / List the handshakes / completed / refused / failed / lost / resumed / accepted | YggdraSIM-coined: the recorded card-facing handshakes per leaf served; refused names the fatal alert the client sent (RFC 8446 §6.2), resumed a session resumption, in which no Certificate is sent (RFC 5246 §7.3, RFC 8446 §2.2), accepted a full handshake that a request followed |
| eIM FQDN (fqdn) / Leaf layout (layout) / CA layout (ca_layout) / SAN registeredID (registered_id) / Leaf CN (cn) | YggdraSIM-coined: TLS setup options; eimFqdn is the EimConfigurationData member the setup's name goes into (GSMA SGP.32 v1.3 §2.11.1.1.1), a layout the subject and extension shape taken from a reference certificate (RFC 5280 §4.1, §4.2), registeredID and CN the GeneralName and the subject attribute a shaped leaf names its owner with |
| Client authentication (none / optional / required) / Client CA / Server name (SNI) / Client certificate / CLIENT-CERT | TLS client authentication (mutual TLS) and the server_name extension (RFC 6066 §3); none is the server authentication GSMA SGP.32 v1.3 §2.6.3.2 asks for; the labels are YggdraSIM-coined |
| Key (p256 / p384 / brainpoolp256r1 / ed25519) | the curves GSMA SGP.32 v1.3 §2.6.3.2 names for TLS to the eIM (NIST P-256 required, the others optional) |
| Card trusts (leaf / leaf_key / root / intermediate / none) | trustedCertificateTls or trustedEimPkTls of trustedPublicKeyDataTls (GSMA SGP.32 v1.3 §2.11.1.1.1); leaf_key and none are YggdraSIM-coined |
| SubjectKeyIdentifier / CA BasicConstraints / serverAuth EKU / TLS versions / TLS 1.2 ciphers | X.509 extensions (RFC 5280) and TLS parameters (GSMA SGP.32 v1.3 §2.6.3.2) |
| Deliver to card / DELIVER | YggdraSIM-coined: the Local eIM as IPAd: ES10b.LoadEuiccPackage (GSMA SGP.32 v1.3 §5.9.1), then RemoveNotificationFromList for what it acknowledged (§3.3.1 steps 15-16) |
| Inject to IPA / INJECT / Inject target / Binding (asn1 / json) / EIM-LISTEN | YggdraSIM-coined verbs and labels for eIM Package Injection (GSMA SGP.32 v1.3 §3.1.1.2): INJECT is the eIM's call of ESipa.TransferEimPackage (§5.14.4), EIM-LISTEN the IPAd that answers it, the inject target the address kept per eUICC, Binding the function binding of §6 the call uses (ASN.1 or JSON). `inject` in the TRAFFIC chain column marks a call the eIM made |
| INJECT-CERT / Injection client certificate / EIM-LISTEN-CERT / notifications (deliver / keep) / inject TLS | YggdraSIM-coined verbs, labels and option values for eIM Package Injection over HTTPS: EIM-LISTEN-CERT makes the listener's own certificate, INJECT-CERT (GUI: Injection client certificate) the client certificate the IPA authenticates the eIM by (GSMA SGP.32 v1.3 §3.1.2.1: only the eIM is authenticated), `notifications=deliver` or `keep` says whether EIM-LISTEN delivers the pending Notifications (§3.3.1 step 17) or leaves them on the eUICC, `inject TLS` in the TRAFFIC chain column marks a call the eIM made over HTTPS |
| Listen for injected eIM packages / Port / Notifications / Stop after calls / Stop after idle seconds | YggdraSIM-coined action and field labels in eSIM Management for the IPAd side of eIM Package Injection (GSMA SGP.32 v1.3 §3.1.1.2): the action runs EIM-LISTEN as a stream on the loopback, Port is the port it listens on, Notifications is the verb's `notifications=deliver` or `keep`, the two limits are its `calls=` and `idle=` |
| Notifications (Local eIM) / NOTIFICATIONS / Send Notifications / Send pending / Send / Confirm send / Notification Receiver / Sequence number / Pending, Delivered, Failed, Kept | Notification, Notification Receiver and the sequence number are the terms of GSMA SGP.32 v1.3 §3.7 and SGP.22 v3.1 §3.5; the rest is YggdraSIM-coined. NOTIFICATIONS lists what IPAs handed to the Local eIM, which holds none back; SEND calls ES9+'.HandleNotification (SGP.32 v1.3 §5.7.4) for the pending ones or the ones named. Pending waits for its receiver, or for a certificate the record lacks; Delivered was answered by it; Failed was refused, ran out of attempts or cannot be sent as it stands, and goes again only when named; Kept was taken before the eIM forwarded any, or held by an earlier version |
| Queue rules / EIM-SETTINGS (learn_unknown_eids, recover_lost_results, max_retries, result_verification) | YggdraSIM-coined |
| Local SM-DP+ profiles / SMDP-PROFILE | YggdraSIM-coined: which profile file the local SM-DP+ serves for a Matching ID |
| Local SM-DS / SMDS / Register SM-DS event / Delete SM-DS event / SM-DS address / Local SM-DS address / Local SM-DS (TLS) / SM-DS card TLS port (`smds_tls_port`) / EventID / RSP Server address / Event type (download, rpm) / `smds_address` | SM-DS, Event Record, EventID, RSP Server address and the event types Profile Download and RPM are the terms of GSMA SGP.22 v3.1 §3.6 and §5.9.1 (Table 53); registering and deleting are ES12.RegisterEvent and ES12.DeleteEvent (§5.9). "Local SM-DS", the `SMDS` verb, the action titles, the option values `download` and `rpm` and the setting name `smds_address` are YggdraSIM-coined: the SM-DS the Local eIM service runs beside its SM-DP+, under the SGP.26 test certificates |
| Drop a profile package here to load it to the card. / Live trace | YggdraSIM-coined. The first is the Local SM-DP+ panel's drop hint: a dropped file fills the Profile field and starts Load profile, and the card overview is read again when the load ends. Live trace is the list of lines an action prints while it runs, shown under the action until its answer replaces it: one line per card command, every exchange in hex under the global debug flag |
| Import package document / PACKAGE-IMPORT | YggdraSIM-coined: queues the operation an eIM package document (template or hotfolder file) stands for |
| Profile type / Queue download / Indirect download / Do not release / Retire as Unavailable | Plain English form labels; Do not release is ConfirmOrder with releaseFlag false |
| indirect (DOWNLOAD parameter) | Indirect Profile Download: the eIM keeps the download data and relays the SGP.22 steps (GSMA SGP.32 v1.3 §3.2.3.2); the trigger carries no profileDownloadData (§2.11.1.3) |
| Not before (UTC) / Front of the queue / Plan only / Max retries / EID list file / Inject fault | Plain English form labels |
| stale-counter / wrong-eid / bad-signature / wrong-token / unknown-eim / counter-overflow | YggdraSIM-coined faults; each draws the eUICC answer of GSMA SGP.32 v1.3 §2.11.2.1: replayError(4), invalidEid(3), euiccPackageErrorUnsigned (three of them), counterValueOutOfRange(6) or replayError(4) (§5.9.1 names no range check for a package counterValue) |
| Operations / eUICCs / eIM configuration / Direct card commands / Package files (tabs of the action list) | YggdraSIM-coined: one tab per store the actions work on. Operations is the queue with its delivery and rules; eUICCs the eUICC records with association and handover; eIM configuration the identity, the service with its traffic, the TLS setups, their leaves and the handshake results (the name of the page's own tab); Package files the file-based flow with the hotfolder. Direct card commands goes straight to the ISD-R of the card in the reader, outside the queue: the SGP.22 ES10c EnableProfile / DisableProfile / DeleteProfile SGP.32 v1.3 puts out of scope (Table 1 note, p.16), profile load, metadata, eUICC memory reset and AddInitialEim. A tab draws its buttons in the order of the workflow, not of the alphabet |

## YggdraCore module (web GUI)

The YggdraCore leaf under Advanced holds the 5G core stub's actions and the
AKMA actions in one module, because the stub AUSF registers the A-KID and
KAKMA of every completed 5G AKA in the AAnF stub the AKMA actions read.

| Label                     | Anchor                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| YggdraCore (module)       | YggdraSIM-coined: the project's 5G core stub (an AUSF and an AAnF on loopback) and its Open5GS bridge; the same name as `yggdrasim-yggdracore` and the `Tools.YggdraCore` package |
| Subscriptions (tab)       | Plain English: the stub's subscriber store (`yggdracore.subscription_*`) |
| AKMA (tab)                | 3GPP TS 33.535 (Authentication and Key Management for Applications): key derivation and the AAnF stub (`akma.*`) |
| Open5GS (tab)             | The upstream Open5GS project; the bridge reads and writes subscribers in its database (`yggdracore.open5gs_*`) |
| Diagnostics (tab)         | Plain English: the stub's mode, endpoints and in-flight authentication contexts (`yggdracore.status`, `yggdracore.clear_auth_contexts`) |

## YggdraSIM-coined surface terms

These terms are not defined by any external standard. They live in
YggdraSIM's own surface and are documented here so they remain
distinct from any vendor's vocabulary.

| Term            | Meaning                                                   |
| --------------- | --------------------------------------------------------- |
| Token           | A `[NAME]` placeholder bound at personalisation time      |
| Token list      | A CSV / JSON / JSONL file mapping tokens to per-row values |
| Token mapping   | A persistent association between a package filename + token list |
| Test-value list | A `name,hex` file answering placeholder literals with test bytes: the operator-wide universal list, or a profile-specific list a template binds on top of it |
| Test value      | The bytes a placeholder occurrence took from a test-value list (chip in the token editor) |
| Name style      | The spelling a test-value list writes its placeholder names in: typed (`{var:TYPE:len[:modifier]}`), compact (`varTYPElen[Modifier]`), brace or bracket; declared by a `# style:` line or inferred from the first entry |
| Decoded value   | The editable form of a placeholder's value (decimal digits, text or hex by declared type) shown under the hex pane of a file or header field; "Apply value" stores it through `saip.set_variable` |
| PE document     | A `.pe.json` file carrying one profile element: its type and its tagged decoded tree, plus the placeholder names of a template PE (`ygg.pe_document.v1`) |
| Install script  | The CAP install sequence (INSTALL [for load], LOAD, INSTALL [for install and make selectable]) saved as a script file: `#` comments and one APDU per line, read by the SCP80 shell's `script` and the SCP03 shell's `RUN` |
| Roundtrip editor| A decoded-field editor that re-encodes losslessly         |
| Sync from EF.<name> | A Profile Header control that copies a file's value into the header field mirroring it and applies it: EF.ICCID -> `iccid`, EF.SMSP -> the SMS-PP bearer's SMSC address |
| Decoded view    | The PE detail tab carrying the typed editor + hex view    |
| Parent path     | The FID chain below the MF (`7F10`, empty for the MF) the Add-file bar of a Generic File Management PE creates a new EF in; the card's Current DF chip shows where the existing files landed |
| Spec card       | The pop-up that lists a PE's title, ASN.1 module, spec    |
| HIL bridge      | The hardware-in-the-loop bridge daemon (see `HIL_BRIDGE_GUIDE.md`) |
| Card bridge     | The PC/SC-over-HTTP relay (see `CARD_BRIDGE_GUIDE.md`)    |
| Runbook         | The About guide list's entry for `RUNBOOK.md`: short procedures per task on the CLI and in the GUI. YggdraSIM-coined |
| User Manual     | The About guide list's entry for `USER_MANUAL.md`, and the launcher Guides menu's `User manual:` block (`U`): the modules, install and start, the concepts both surfaces share, real-card work. Plain English |
| User Manual · GUI, User Manual · CLI | The About guide list's entries for `USER_MANUAL_GUI.md` and `USER_MANUAL_CLI.md`, picks `UG` and `UC` in the launcher Guides menu: one chapter per surface, the modules in sidebar order. Plain English |
| Card rig        | A Remote Lab rig that holds the card and streams it to the operator; `rigs[].kind: card` |
| Modem rig       | A Remote Lab rig that holds a modem and a SIMtrace2 and consumes a card the operator offers; `rigs[].kind: modem` |
| Card offer      | The Card Bridge endpoint an operator hands a modem rig when reserving it; `card_offer` in the reservation |
| Card lease      | The cooperative hold one consumer takes over a card so a second cannot drive it at the same time |
| Host card       | A registered device describing one physical box and the ways in to it, rather than one session |
| Card reachability | How a host reads the operator's card: `tunnel` for an SSH reverse forward, `direct` for a routable address |
| APDU Streaming  | The umbrella for moving a card between two machines, in either direction. Its two members are the Remote Lab, where rigs are shared and reserved by token, and the Remote Bridge, where one operator prepares and drives a rig over SSH |
| Card Bridge over SSH | The plain single-operator case of the above: one Card Bridge, one tunnel, no agent. Named `Remote APDU Streaming` until the umbrella took that word |
| Start APDU Stream | The HIL workbench button that puts this machine's card on another machine's modem. Names the action rather than one host, because the rig is chosen when it is pressed. YggdraSIM-coined, under the APDU Streaming umbrella |
| Stop APDU Stream | The same seat once the stream is up: it tears down the bridge on this machine, the SSH tunnel and the services on the rig. One button, because the direction that applies is never both |
| Terminal palette | The colour scheme the launcher, the shells and the CLI tools render with, chosen by `YGGDRASIM_CLI_THEME`. Most names are the GUI themes transcribed from their token files; `nord` is YggdraSIM's own and the default |
| Mono (palette)  | The terminal palette that emits no escape at all, for plain output from surfaces `NO_COLOR` does not reach |
| Plugin consoles | The nav group of the consoles the loaded plugins register, one leaf per console; the group is shown only while at least one console is registered. The console titles, field labels, action labels, section titles and stream titles are the plugin's own and come from its manifest |
| Plugin console  | The generic view one console renders into, in two panes of tabs: controls (Session, the state tab, Actions, or Command line when the console has no actions, the run form, the credentials) and output (the Comparison, one tab per stream, the runs). The Actions tab holds the Command line panel ("Output" when the console takes no free line) with its Commands list above the Actions panel; an action's answer also shows under its own card, reading done or failed when the answer is empty |
| Session (console) | The console panel that starts and stops the plugin's session and lists the state it reports; its status chip reads running, stopped, ready or the plugin's own busy phase. A plugin that titles its state moves the list into a tab of that name, State by default, which reads "Nothing reported yet." while empty |
| Wrap (stream table) | The button of a stream table whose values can be cut at the column edge (hex, narrow text): Wrap shows every value in full, and a click on a row opens that row only. Plain English |
| Plugin console pills | The top bar pills a console declares, beside HIL bridge and Remote: the label and the value are the plugin's own, a pill shows only while the console reports a value, and a click opens the console. YggdraSIM-coined |
| Local eIM (top bar pill) / running / not answering / stopped / unknown / starting / stopping | The top bar pill beside HIL bridge and Remote with the state of the Local eIM service (SERVE status): not answering is a running process that does not answer its /ping, unknown a server that does not report it. A click starts the service with the defaults (SERVE start, the Start service action) or stops it (SERVE stop). YggdraSIM-coined |
| Decoder reading | The fold beside the eIM's rows of an operation's package and result on the Local eIM page (and `OP <id> --decode` in the shell): the Decoder's reading of the same bytes in the ES10 context, every data object of the SGP.22 / SGP.32 schema by name and value. YggdraSIM-coined |
| Add an eIM (addEim) | The button in the eIMs section of a Local eIM eUICC page that opens New operation on Add eIM: the addEim eCO of a signed eUICC Package (SGP.32 v1.3 §2.11.1.1), which adds an eIM beside the card's others, unlike Link this eIM (AddInitialEim after a reset) |
| (pick one)      | The blank first option of a run-form choice the console fills from its status (`options_from`), shown until the operator picks; a plugin may replace it with the field's placeholder. YggdraSIM-coined |
| Comparison section heading | The fold control of one section of a console's comparison panel: the section title, then its row count and what differs ("16 rows, 2 differ, 1 on one side"); the folded sections are remembered per console. YggdraSIM-coined |
| Run form (console) | The console panel a plugin declares to start runs: a Variant select, the fields every run uses, one card per item (tick it and its own fields open inline), and the field groups the ticked items use, above or below the items. Its default titles are New run, Variant, Items, Credentials and Run; a plugin's manifest replaces each. YggdraSIM-coined |
| Current run / History | The console panels beside a run form: the run being followed (state chip, meta lines, one result per item with its checks and details, the event log, Cancel) and the list of earlier runs, which reads "No runs yet." while empty. Default titles, replaced by the manifest's. YggdraSIM-coined |
| Run and result states | queued, running, passed, failed, error, cancelled, skipped, pending and unknown: the fixed words a run or an item result shows, coloured through the status tokens; "no run" while nothing is followed. YggdraSIM-coined |
| automatic / unavailable (item) | The chip of an item the run selects by itself from a field value, and of an item that cannot run yet; a variant that cannot run is listed with "(unavailable)". YggdraSIM-coined |
| Store / Replace / Forget (credential) | The verbs of a stored credential panel in the credentials tab: Store keeps a typed secret on the plugin's side, Replace opens the fields again (Cancel closes them), Forget drops it; the panel shows the plugin's summary line, or Stored. / Not stored. when it gives none. A plugin may rename the three (a portal sign-in reads Sign in / Sign in again / Sign out). The run form shows one status line per credential the variant needs, with a button named after the credentials tab. Plain English |
| Add / Name / Use for this run (named credential) | A named credential's panel lists its entries by name, each with Replace and Forget; Add opens a Name field (one word, unique in the list) beside the credential's fields, and the Use for this run select on the run form's status line picks the entry a run uses, reading (choose one) while several are usable and none is picked. YggdraSIM-coined |
| Comparison / Item / Verdict: same, differs, one side (comparison panel) | A console that declares a comparison gets one table per section: an Item column, one column per side the plugin names, and a Verdict column reading same, differs or one side (the item exists on one side only). The summary beside the title reads nothing to compare yet, all rows match, or the counts of rows that differ and that exist on one side only. YggdraSIM-coined |
| Command log (`--log <file>`) | The modifier every shell command line takes: the command runs with debug output on, and everything it prints is appended to the file without terminal escapes, between a header naming the command and a trailer saying how it ended. The body folds by indentation: a line printed at the left margin carries its local time, an indented line sits under it without one. A terminal surface only; the GUI refuses it. YggdraSIM-coined |
| TRACE START / STOP / STATUS | The SCP03 shell's command log over a span of commands: from START to STOP every command is noted in the file with a leading `>`, its output one level under the note, and runs with debug output; the prompt reads TRACE while one is open. YggdraSIM-coined |
| Skin: Bench / Classic | The top bar control beside Theme that picks the interface skin (`data-skin`): typefaces, type scale, shape, separation and chrome, independent of the colour theme. Bench is the default lab-instrument skin (IBM Plex Sans Condensed and Plex Mono, square keys, flat panels, capitals for UI legends only); Classic is the look before it. YggdraSIM-coined |
| Show or hide the tools (sidebar caret) | YggdraSIM-coined tooltip of the caret beside Offline Tools: it opens or closes the list of tools in place, without selecting the module, and the choice is kept across reloads |
| Rail (sidebar) | The Command Center sidebar collapsed to a column of keys, one per module, with short legends: FS (File system), APPS (Applications), OTA (Over-the-Air), MGMT (Management), SMDP (Local SM-DP+), EIM (Local eIM), SAIP (SAIP Tool), OFFL (Offline Tools), LAB (Remote Lab), BRDG (Remote Bridge), HIL (HIL Bridge), SIM (SIM card helpers), CORE (YggdraCore), SHELL (Shell), HOST (Host shell), REG (Registry browser), CFG (Configuration), OVW (Overview), ABOUT (About); a plugin console's key takes the first word of its title. The sidebar mode menu reads Always show, Rail (keys only), Auto-hide and Hidden. YggdraSIM-coined |
| Actions / Inspector (module panes) | The side panes of a module workbench under Bench: Actions lists the module's actions one per row with the open one lit, and Inspector holds what the module reads back (the card overview, the OTA, Local SM-DP+ or Local eIM overview); the output pane sits between them. Each collapses to a labelled strip and back. YggdraSIM-coined |
| Pane keys: Sidebar / Actions / Inspector / Log | The keys at the right of the status line, lit while their pane is open (Alt+1 to Alt+4). Key 2 is named after the current view's index pane (Actions, Files for the File system tree, Packages for the SAIP package drawer) and keys 2 and 3 are disabled in a view without the pane. A collapsed pane keeps its entry points: the rail, the labelled strips, and the event log's one line, which shows the latest row of any bucket but Validation. YggdraSIM-coined |
| Status-line card readout: EID / ICCID | The EID and ICCID the last card overview or File system scan read for the active reader, shortened in the line and whole on hover; nothing is read from the card for it. Labels anchored in SGP.22 (EID) and ITU-T E.118 (ICCID) |
| SAIP ribbon tabs | One tab per command group of the SAIP Tool ribbon (Package, Actions, Element, File system, Tokens, Lint, Advanced, Reference); the group names were the ribbon's group legends before. YggdraSIM-coined |
| Theme: Bench · dark / Bench · light | The palettes the Bench skin was drawn in, offered as two more themes beside the twenty existing ones: near-black or grey fields, recessed wells, an achromatic accent, colour kept for ok / warn / fail. They pair with either skin. YggdraSIM-coined |
| Card read at ... (card overview) | The time the eSIM Management card overview last read the card, above the overview; the module reads the card on entry and shows the stored read on a re-render. "not re-read" in the module's status means the card was held by another session on entry (File system, a stream action, the HIL bridge, a remote consumer) and the shown read is the earlier one. YggdraSIM-coined |
| Danger (File system key group) | The group at the end of the File system file-action strip holding Delete, Resize and Suspend UICC, apart from Create file, Lifecycle and Search rec. YggdraSIM-coined |
| reader busy: <action> has held '<reader>' since <time> | The answer to a card action whose reader another operation holds: a stream or a profile download ("Profile download") holds it until it ends, a short action is waited for up to a minute first. Another YggdraSIM process's hold carries its pid, "<what runs> (pid <n>)": "<VERB> in the eSIM Management console", "HIL bridge", "MCP card session <id>", "<action> in the GUI" (`yggdrasim_common/reader_locks.py`). YggdraSIM-coined |
| YggdraSIM Simulator | The one reader the reader list and the reader gates offer while BACKEND is SIM: every card connection then goes to the simulated card whatever reader it names, so the PC/SC and remote readers are not listed. YggdraSIM-coined |
| Raw APDU console: Send N APDUs / stop at error SW / Command / Decoded commands / SELECT MNO-SD | The APDU ribbon tab of File system and Applications takes one APDU per line (`#` starts a comment, the format of an Install script). Send N APDUs sends the lines in order; stop at error SW ends the run at the first status word ETSI TS 102 221 v18.4 §10.2.1 classes as postponed processing or an execution, checking or application error (§10.2.1.2, §10.2.1.4 to §10.2.1.6), and "Stopped after #n" names where it ended. The breakdown table's Command column and the Decoded commands section are the Offline Tools context decoder's reading of each line. SELECT MNO-SD selects the default Issuer Security Domain AID (GPC v2.3.1 Annex H.1.3); GET STATUS -- ISD (80) and -- Apps (40) name P1 after GPC v2.3.1 Table 11-33. MNO-SD is the GSMA term; the rest is YggdraSIM-coined |
| FCP card / Copy (File system preview) | The folded card holding the selected file's FCP (ETSI TS 102 221 v18.4 §11.1.1.4), titled FCI for a GlobalPlatform FCI (GPC v2.3.1 §11.9.3.1 Table 11-82). Its summary reads "file size N B" (§11.1.1.4.1), "N records x L B" (§11.1.1.4.3 number of records and record length), "total file size N B" for a DF (§11.1.1.4.2), "SFI xx" (§11.1.1.4.8), the life cycle status name (§11.1.1.4.9 Table 11.7b), "ARR <FID> record <n>" (§11.1.1.4.7.3 EF ARR file ID and record number), "compact" / "expanded security attributes" (§11.1.1.4.7.1 / .2), "AID ..." for an FCI, or "not decoded". Opened, "No value" on the toolbar line names the parameters the decode left null. Copy / Copied is the per-parameter key of the FCP and of a decoded File system body (preview, record card, READ result); Copy body and Copy record, beside Update body and Update record, copy the bytes read as one hex string. Plain English. The card arrangement is YggdraSIM-coined |
| <flag> is security-sensitive. / Confirm / Cancel (Environment > Configuration) | The question the Configuration page puts between Set and the write of a flag the registry marks sensitive (a weakened security posture, or a command YggdraSIM runs), followed by the flag's note; the launcher's flag menu asks "Type Y to continue" at the same point. Confirm writes what the field held when Set was pressed. YggdraSIM-coined |
| Persistent or disruptive action / I have reviewed the target and understand the impact. | The heading and the required checkbox the page adds to the form of an action that changes a card (a `confirm` field or the `destructive` tag); the File system and Applications workbench shows the checkbox alone. Run stays refused until it is ticked. YggdraSIM-coined |
| Confirm / Cancel (question line under a button) | The line a button that runs without a form puts under itself before it writes (Send OTA packet, Smart OTA and Run script file in Over-the-Air, Create file in File system, Deliver now on the Local eIM page): it names what is about to be sent and where, Confirm sends what the inputs held when the button was pressed, and a change to an input withdraws it. YggdraSIM-coined |
| Compact (SAIP element list) | The switch in the SAIP Tool's Profile elements pane head that shows one line per element instead of a card. YggdraSIM-coined |
| Remote Bridge tabs: Host / Rig / Status | The three sections of the Remote Bridge page: Host (stored hosts, SSH target, reader, ports, remote service settings), Rig (Start / Stop full rig, Manual controls, Rig status) and Status (Bridge connection, Live probe, Latency history). YggdraSIM-coined |
| Overview module state line | The line under an Overview module card's hint: "session open: <reader>" or "N sessions open" (File system), "N packages open" (SAIP Tool), "card read <time> · N profiles" (eSIM Management), "last: <action> <time>" and "N errors" from the event log. YggdraSIM-coined |
| Module head: group, Reader, Actions | The head of a compact module workbench: the Command Center group above the title (a name, so it keeps its case), the scope line under it, and readouts that need no card exchange (the reader the module is bound to, the number of actions it registers). YggdraSIM-coined |

## Rules for new labels

1. If the underlying concept has a spec name, use that spec name and
   cite the section in the tooltip / hint text.
2. If no spec applies, pick a YggdraSIM-coined term that is clearly
   distinct from any commercial SIM-tooling vendor's surface text
   and add it to the YggdraSIM-coined table above.
3. Never replicate a vendor's tab-naming convention
   (e.g. `PE-<Type> Editor Tab`, `Variable Editor`,
   `ASN.1 Value Notation Tab`) verbatim.
4. Comments and docstrings in source code follow the same rule --
   prefer `# TCA SAIP v3.4.1 §8.3.5 genericFileManagement ...` over a
   prose paraphrase that quotes a vendor's manual.
