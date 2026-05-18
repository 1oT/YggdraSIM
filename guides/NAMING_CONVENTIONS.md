# Naming Conventions

YggdraSIM is a public-release SAIP / SIM / eUICC workbench. Every
operator-visible label in the GUI, TUI and CLI is either anchored
in a published standard (3GPP, ETSI, GSMA, ISO 7816, GlobalPlatform,
TCA SAIP) or is YggdraSIM-coined and deliberately distinct from any
commercial SIM-tooling vendor's surface text.

This document is the source of truth for that lineage. When adding a
new operator-visible label, pick a row in the table below — or
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
| Decoded view | YggdraSIM voice — what the tab shows (typed editor + hex)     |
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
| Spec card  | YggdraSIM voice — surfaces the PE's title + ASN.1 module + spec |
| Guides     | YggdraSIM voice — opens the shipped `guides/` catalogue         |

## SAIP profile-element class names

These names live in the TCA SAIP ASN.1 schema
(`pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn`). They are
spec-locked and used verbatim throughout the tool:

```
ProfileHeader, PE-End, PE-USIM, PE-OptUSIM, PE-ISIM, PE-OptISIM,
PE-CSIM, PE-OptCSIM, PE-Telecom, PE-PINCodes, PE-PUKCodes,
PE-AKAParameter, PE-CDMAParameter, PE-MF, PE-SecurityDomain,
PE-Application, PE-RFM, PE-NFC, PE-RAM, PE-3GPPRegistration,
PE-CRT, PE-ARA-M, genericFileManagement, ...
```

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

## 3GPP / GSMA terminology

| Term              | Anchor                                                      |
| ----------------- | ----------------------------------------------------------- |
| ICCID             | ITU-T E.118; TS 31.102 §4.2.2                               |
| IMSI              | TS 23.003 §2.2; TS 31.102 §4.2.3                            |
| Routing Indicator | TS 31.102 §4.4.11.10 EF.Routing_Indicator                   |
| SUCI              | TS 33.501 §6.12; TS 31.102 §4.4.11.8 EF.SUCI_Calc_Info      |
| URSP              | TS 24.526; TS 31.102 §4.4.11 EF.URSP                        |
| Mandated          | TCA SAIP `mandated` member; SGP.22 §2.5.4                   |

## GlobalPlatform terminology

| Term                  | Anchor                                                  |
| --------------------- | ------------------------------------------------------- |
| Issuer Security Domain | GP CardSpec v2.3 §11; SGP.22 §2.6.1 ISD-R / ISD-P      |
| Application Privileges | GP CardSpec v2.3 Table 11-49                           |
| Life Cycle State      | GP CardSpec v2.3 §11.1.1                                |
| OPEN                  | GP CardSpec v2.3 §6 GlobalPlatform Environment          |

## YggdraSIM-coined surface terms

These terms are not defined by any external standard. They live in
YggdraSIM's own surface and are documented here so they remain
distinct from any vendor's vocabulary.

| Term            | Meaning                                                   |
| --------------- | --------------------------------------------------------- |
| Token           | A `[NAME]` placeholder bound at personalisation time      |
| Token list      | A CSV / JSON / JSONL file mapping tokens to per-row values |
| Token mapping   | A persistent association between a package filename + token list |
| Roundtrip editor| A decoded-field editor that re-encodes losslessly         |
| Decoded view    | The PE detail tab carrying the typed editor + hex view    |
| Spec card       | The pop-up that lists a PE's title, ASN.1 module, spec    |
| HIL bridge      | The hardware-in-the-loop bridge daemon (see `HIL_BRIDGE_GUIDE.md`) |
| Card bridge     | The PC/SC-over-HTTP relay (see `CARD_BRIDGE_GUIDE.md`)    |

## Rules for new labels

1. If the underlying concept has a spec name, use that spec name and
   cite the section in the tooltip / hint text.
2. If no spec applies, pick a YggdraSIM-coined term that is clearly
   distinct from any commercial SIM-tooling vendor's surface text
   and add it to the YggdraSIM-coined table above.
3. Never replicate a vendor's tab-naming convention
   (e.g. `PE-<Type> Editor Tab`, `Variable Editor`,
   `ASN.1 Value Notation Tab`) verbatim.
4. Comments and docstrings in source code follow the same rule —
   prefer `# TCA SAIP §6.6.7 genericFileManagement …` over a
   prose paraphrase that quotes a vendor's manual.
