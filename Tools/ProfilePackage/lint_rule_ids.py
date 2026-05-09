# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
YggdraSIM-native lint rule identifiers (``YRL-*``).

These IDs are owned by this tree and are not meant to track external lab or
vendor rule catalogs. Spec references stay in each finding's ``spec`` field.

Pattern: ``YRL-<domain>-<suffix>``

Domains (suffix is numeric or mnemonic):
  DOC  Decoded document / empty PE list
  SEQ  PE sequence shape (header / mf / end, singleton counts)
  DEP  PE dependency ordering (opt-usim, df-5gs, …)
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
       (ETSI TS 102 223 §8.52 / GSMA TS.48 §7.2)
  PID  PE ``identification`` uniqueness
  SDM  Security domain instance / keys (shape: -001..-004)
  SDK  Security domain key-list entry-level checks: keyVersionNumber=0 (-001
       WARN), keyType outside GP CPS §11.1.8 registry (-002 WARN),
       keyUsageQualifier absent or zero (-003 WARN)
  JCA  Application load block / package AID
  JCI  Application instance list entries
  HEX  Hex field length / padding
  APD  APDU-shaped hex fields
  N5G  DF.5GS vs USIM presence
  FIL  File definition FCP / fileID / EF sizing (ETSI TS 102 22x)
  GFM  genericFileManagement command-block sequence coherence: write op
       without preceding filePath/createFCP (-001 WARN), createFCP with no
       subsequent fillFileContent (-002 INFO), empty block (-003 INFO)
       (TS 102 222 §5)
  FS   File-system content consistency: efFileSize vs fillFileContent byte
       length (TS 102 222 §6.4 — -001), BER-TLV integrity checks
  ARR  EF.ARR reference checks: rule-index vs record count (-001 WARN),
       unresolvable EF.ARR reference (-002 INFO) (TS 102 221 §11.1.1)
  AKA  AKA parameter field-length checks: K byte length (-001 FAIL),
       OP(c)/TOP(c) byte length (-002 FAIL), fixed SGP.22 §B.3 fields
       (algorithmOptions/authCounterMax/sqnDelta/sqnAgeLimit/rotationConstants)
       out of spec (-003 WARN), unknown algorithmID (-004 WARN)
  PIN  PIN / PUK byte-level encoding: packed retry-byte nibbles (-001 max=0,
       -004 remaining>max), pinValue/pukValue length exactly 8 bytes
       (-002/-003) (SGP.22 §B.2)
  UCR  USIM decoded shape expectations
  UST  EF(UST) service bits vs related files (informational coherence)
  MET  Sidecar metadata alignment / operator fields
  RFM  Remote File Management PE coherence: duplicate TAR value across PEs
       (-001 FAIL, ETSI TS 102 226 §8.2), TAR not exactly 3 bytes (-002 WARN,
       TS 102 226 §8.1), keyReference is 0x00 (-003 WARN, GP CPS §11.1.8)
  RAM  Remote Application Management PE integrity: securityDomainAID absent
       (-001 FAIL, GP CPS §11.1.4), AID out of 5–16 byte range (-002 WARN),
       applicationLoadPackageAID out of range (-003 WARN) (ISO 7816-4 §8.2.1)
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
