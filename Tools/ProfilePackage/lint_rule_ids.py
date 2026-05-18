# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
YggdraSIM-native lint rule identifiers (``YRL-*``).

These IDs are owned by this tree and are not meant to track external lab or
vendor rule catalogs. Spec references stay in each finding's ``spec`` field.

Pattern: ``YRL-<domain>-<suffix>``

Domains (suffix is numeric or mnemonic):
  DOC  Decoded document / empty PE list
  SEQ  PE sequence shape (header / mf / end, singleton counts)
  SVC  Header ``eUICC-Mandatory-services`` vs PE presence
  ICC  ICCID encoding in header (-001..-003) and cross-PE consistency
       between header.iccid and EF.ICCID fillFileContent (-010, TS 102 221 §13.2);
       Luhn mod-10 check digit validation on the BCD digit string (-004 WARN,
       ITU-T E.118 §3.3 / ISO/IEC 7812-1)
  AD   EF.AD administrative data: mnc_length byte (byte 4) not 2 or 3
       (-001 FAIL), EF.AD fewer than 4 bytes (-002 WARN), mnc_length=3
       but IMSI third MNC digit is filler 0xF (-003 WARN)
       (3GPP TS 31.102 §4.2.18)
  ACC  EF.ACC access control class: not exactly 2 bytes (-001 FAIL),
       user class bits 0–9 all zero (-002 WARN)
       (3GPP TS 31.102 §4.2.15)
  HPLMN EF.HPLMNwAcT HPLMN search timer: timer byte 0x00 (-001 WARN),
        empty content (-002 FAIL) (3GPP TS 31.102 §4.2.6)
  IMS  EF.IMSI byte-level encoding (3GPP TS 31.102 §4.2.2): total length,
       length-byte (0x08), parity nibble (0x1 odd / 0x9 even), BCD digit
       validity, parity-vs-digit-count consistency, and digit-count range
       (3GPP TS 23.003 §2.2 — 6..15 digits)
  HDR  Profile header fields: mandatory field presence (-001 WARN),
       connectivityParameters non-hex sub-field (-002 WARN), port outside
       1..65535 (-003 WARN), transport protocol not UDP/TCP (-004 INFO)
       (ETSI TS 102 223 §8.52 / GSMA TS.48 §7.2); eUICC-Mandatory-AIDs entry
       shape: AID outside ISO 7816-5 5..16 byte range, version not 2 bytes,
       missing aid/version, duplicate AID (-005 FAIL/WARN, TCA SAIP §A.2);
       SAIP (major, minor) version not in TCA-published set + iotOptions on
       SAIP < 3.3 (-006 FAIL/WARN, TCA PP TS §3.1 / §A.2);
       eUICC-Mandatory-GFSTEList OID component invalid / non-dotted /
       duplicate (-007 FAIL/WARN, TCA SAIP §A.2 / ITU-T X.660); profileType
       empty or > 100 UTF-8 bytes (-008 WARN/FAIL, TCA SAIP §A.2)
  PID  PE ``identification`` uniqueness (-001 FAIL, -002 WARN); profile
       must declare at least one NAA (-003 WARN, TCA PP TS §4.4 /
       GSMA TS.48 §6 — a profile without USIM/CSIM/ISIM/SSIM has no
       subscription identity to expose)
  NAA  Each NAA needs a set of authentication parameters (-005 WARN,
       TCA PP TS §4.4.1 / 3GPP TS 33.102 §6.3 — USIM / CSIM / ISIM
       require an akaParameter PE; SSIM may use SSIM-EAPTLSParameters
       instead, per the TCA PP TS NAA rules covering EAP-TLS, RFC 9190 /
       RFC 9048)
  DEP  PE dependency ordering: opt-usim/-isim → host NAA, gsm-access /
       phonebook / df-5gs / df-saip / df-snpn / df-5gprose → USIM
       (TCA PP TS GSM-ACCESS / PHONEBOOK / DF-5GS / DF-SAIP / DF-SNPN /
       DF-5GPROSE: each shall come after the creation of an ADF USIM)
  SDM  Security domain instance / keys (shape: -001..-004) and Application
       extraditeSecurityDomainAID cross-reference (-005 FAIL,
       TCA PP TS PP-004 — the extradite target must be defined by a
       preceding PE-SecurityDomain)
  SDK  Security domain key-list entry-level checks: keyVersionNumber=0 (-001
       WARN), keyType outside GP CPS §11.1.8 registry (-002 WARN),
       keyUsageQualifier absent or zero (-003 WARN)
  JCA  Application load block / package AID; PE-Application missing both
       loadBlock and instanceList (-004 FAIL, TCA PP TS APP-004);
       instance applicationLoadPackageAID does not match the parent
       loadBlock or any preceding PE-Application load package (-005
       WARN, ETSI TS 102 226 / GP CS §11.5)
  JCI  Application instance list entries; applicationModuleAID outside
       5..16 byte AID range (-005 WARN, ISO 7816-4 §8.2.1)
  HEX  Hex field length / padding
  APD  APDU-shaped hex fields
  N5G  DF.5GS vs USIM presence
  FIL  File definition FCP / fileID / EF sizing (ETSI TS 102 22x); linked
       file also declares size or content fields — efFileSize /
       maximumFileSize / fillFileContent / fillFileOffset / fillFilePattern
       (-015 FAIL, TCA PP TS FS-015 — the link target owns size and
       proprietary information per ETSI TS 102 222 file-management
       semantics); linkPath declared on an ADF (-024 FAIL, TCA PP TS
       FS-024 — linkPath is the EF/DF-only symlink-target field);
       fileDescriptor byte 0 file-class bits vs declared kind — DF/ADF
       must use 0b11, EF must not (-040 FAIL, ETSI TS 102 222 §6.2 /
       ISO 7816-4 §5.3.1.1); lifeCycleStatus byte outside the registered
       set 0x00/0x01/0x03/0x04/0x05/0x0C..0x0F (-041 WARN, ETSI TS 102
       221 §11.1.1.1 / TS 102 222 §6.10); securityAttributesReferenced
       and securityAttributesCompact declared on the same FCP (-042
       FAIL, ETSI TS 102 221 §11.1.1.4 — mutually exclusive); dfName
       declared on an EF / MF, or ADF dfName outside 5..16 byte AID
       range (-043 FAIL/WARN, ETSI TS 102 222 §6.4 / ISO 7816-4 §8.2.1)
  GFM  genericFileManagement command-block sequence coherence: write op
       without preceding filePath/createFCP (-001 WARN), createFCP with no
       subsequent fillFileContent (-002 INFO), empty block (-003 INFO)
       (TS 102 222 §5)
  FS   File-system content consistency: efFileSize vs fillFileContent byte
       length (TS 102 222 §6.4 — -001), BER-TLV integrity checks
  ARR  EF.ARR reference checks: rule-index vs record count (-001 WARN),
       unresolvable EF.ARR reference (-002 INFO) (TS 102 221 §11.1.1)
  AKA  AKA parameter field-length checks: K byte length (-001 FAIL —
       MILENAGE 16 B, TUAK 16 or 32 B per TS 35.231 Annex F),
       OP(c)/TOP(c) byte length (-002 FAIL, mismatched TUAK K/TOPc width
       WARN), fixed SGP.22 §B.3 fields (algorithmOptions / authCounterMax /
       sqnDelta / sqnAgeLimit / rotationConstants) out of spec (-003 WARN),
       unknown algorithmID (-004 WARN); mappingSource AID must resolve to
       a NAA defined earlier in the profile (-005 WARN, TCA PP TS
       PE-AKAParameter / ISO 7816-5 §8.5)
  CDMA PE-CDMAParameter material sanity: A-Key (authenticationKey) 8 B and
       SSD 16 B (-001 FAIL, 3GPP2 C.S0023 §3.4); HRPD / Simple-IP /
       Mobile-IP authentication-data declared but empty (-002 WARN, GSMA
       SAIP Annex D)
  SSIM PE-SSIM-EAPTLSParameters mandatory cert / key fields missing
       (-001 FAIL) or declared but empty (-002 FAIL) (TCA PP TS
       PE-SSIM-EAPTLSParameters / RFC 9190 / RFC 9048)
  PIN  PIN / PUK byte-level encoding: packed retry-byte nibbles (-001 max=0,
       -004 remaining>max, -006 remaining=0 ships blocked), pinValue/pukValue
       length exactly 8 bytes (-002/-003) (SGP.22 §B.2); PIN unblocking
       reference must resolve to a PE-PUKCodes keyReference (-005 FAIL,
       TCA PP TS PIN-007); keyReference outside ETSI TS 102 221 §9.5 Table
       9.3 ranges — global 0x01..0x08, local 0x81..0x88 (-007 FAIL)
  UCR  USIM decoded shape expectations
  UST  EF(UST) service bits vs related files (informational coherence)
  MET  Sidecar metadata alignment / operator fields
  RFM  Remote File Management PE coherence: duplicate TAR value across PEs
       (-001 FAIL, ETSI TS 102 226 §8.2), TAR not exactly 3 bytes (-002 WARN,
       TS 102 226 §8.1), keyReference is 0x00 (-003 WARN, GP CPS §11.1.8);
       minimumSecurityLevel (SPI MSL) not 1 byte or 0x00 disables crypto
       on remote-management traffic (-004 WARN, ETSI TS 102 225 §5.1.1)
  RAM  Remote Application Management PE integrity: securityDomainAID absent
       (-001 FAIL, GP CPS §11.1.4), AID out of 5–16 byte range (-002 WARN),
       applicationLoadPackageAID out of range (-003 WARN) (ISO 7816-4 §8.2.1);
       minimumSecurityLevel (SPI MSL) not 1 byte or 0x00 disables crypto
       on remote-management traffic (-004 WARN, ETSI TS 102 225 §5.1.1)
  SUCI    EF.SUCI-CALC-INFO (4F07) SUCI computation parameters (3GPP TS
          31.102 §4.4.11.3): unknown Protection Scheme Identifier (-001
          FAIL), non-null PSI but HNPK absent (-002 WARN — ME falls back
          to null-scheme), null-scheme PSI=0 in production context
          (-003 INFO — SUPI transmitted in the clear)
  KC      EF.KC (4F20) and EF.KCGPRS (4F52) GSM ciphering-key context (3GPP
          TS 31.102 §4.2.9b): not exactly 9 bytes (-001 FAIL for KC,
          -002 FAIL for KCGPRS — Kc 8B + CKSN 1B)
  STARTHFN EF.START-HFN (6F5B) RRC HFN start values (3GPP TS 31.102 §4.2.40):
           not exactly 6 bytes (-001 FAIL — START-CS 3B + START-PS 3B)
  EPSNSC  EF.EPSNSC EPS NAS Security Context (3GPP TS 31.102 §4.2.77): not
          exactly 54 bytes (-001 FAIL — wrong size forces full re-auth on
          every attach, critical for IoT high-attach-rate deployments)
  KEYS    EF.KEYS (6F08) and EF.KEYSPS (6F09) key-context size (3GPP TS
          31.102 §4.2.9): not exactly 33 bytes (-001 FAIL for KEYS,
          -002 FAIL for KEYSPS — KSI 1B + CK 16B + IK 16B)
  LOCI    EF.LOCI location information (3GPP TS 31.102 §4.2.7): not exactly
          11 bytes (-001 FAIL — TMSI 4B + LAI 5B + RFU 1B + LUS 1B)
  EPSLOCI EF.EPSLOCI EPS location information (3GPP TS 31.102 §4.2.76): not
          exactly 18 bytes (-001 FAIL — GUTI 10B + Last-Visited-TAI 5B +
          EPS-Update-Status 1B + RFU 2B)
  EST  EF.EST enabled-service table encoding and UST coherence
       (3GPP TS 31.102 §4.2.46): empty content (-001 FAIL), bit set for a
       UST service that is not available (-002 WARN — ME will never activate)
  SPN  EF.SPN service provider name encoding (3GPP TS 31.102 §4.2.12):
       not exactly 17 bytes (-001 FAIL), reserved bits in display-conditions
       byte (-002 WARN), name bytes all 0xFF (-003 WARN, name not configured)
  SMSP EF.SMSP short message service parameters (3GPP TS 31.102 §4.2.27):
       record shorter than 28 bytes (-001 FAIL), SC address length byte
       exceeds 11 (-002 WARN, ITU-T E.164 / TS 31.102 §4.2.27)
  MSISDN EF.MSISDN (6F40) ADN record shape (3GPP TS 31.102 §4.2.26): record
         shorter than 14 bytes (-001 FAIL — same minimum as EF.FDN)
  FPLMN  EF.FPLMN (6F7B) Forbidden PLMN list (3GPP TS 31.102 §4.2.20): not
         a multiple of 3 bytes (-001 WARN — each PLMN entry is 3-byte BCD)
  ECC    EF.ECC (6FB7) Emergency Call Codes (3GPP TS 31.102 §4.2.21): not
         a multiple of 4 bytes (-001 WARN — 3B BCD number + 1B category)
  EHPLMN EF.EHPLMN (6FD9) Equivalent HPLMN list (3GPP TS 31.102 §4.2.84):
         not a multiple of 3 bytes (-001 WARN — same encoding as EF.FPLMN)
  GID    EF.GID1 (6F3E) / EF.GID2 (6F3F) Group Identifier (3GPP TS 31.102
         §4.2.10 / §4.2.11): all bytes 0xFF (-001 WARN — not personalised,
         group identifier lock will not function)
  SMS  EF.SMS (6F3C) record size (3GPP TS 31.102 §4.2.16): not exactly 176
       bytes (-001 FAIL — status 1B + TPDU 175B)
  CBMI EF.CBMI (6F45) CB message identifier list (3GPP TS 31.102 §4.2.14):
       content not a multiple of 2 bytes (-001 WARN); EF.CBMIR (6F50)
       range pairs not a multiple of 4 bytes (-002 WARN, §4.2.36)
  FDN  EF.FDN (6F3B) and EF.BDN (6F4D) ADN record shape (3GPP TS 31.102
       §4.2.13 / §4.2.25): record shorter than 14 bytes (-001 FAIL),
       number-length byte > 10 (-002 WARN, exceeds 10-byte BCD field)
  PNN  EF.PNN (6FC5) PLMN Network Name BER-TLV record (3GPP TS 31.102
       §4.2.58): mandatory tag 0x80 (full name) absent (-001 FAIL)
  OPL  EF.OPL (6FC6) Operator PLMN List (3GPP TS 31.102 §4.2.59): content
       not a multiple of 8 bytes (-001 WARN — each record is 8 bytes)
  CHK  ``saip-tool check`` integration

Dynamic SVC rows use ``YRL-SVC-OK-<SERVICE>`` (PASS) and ``YRL-SVC-MIS-<SERVICE>`` (FAIL).
"""
