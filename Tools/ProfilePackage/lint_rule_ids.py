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
  ICC  ICCID encoding in header
  HDR  Profile header fields (e.g. operational profile type)
  PID  PE ``identification`` uniqueness
  SDM  Security domain instance / keys
  JCA  Application load block / package AID
  JCI  Application instance list entries
  HEX  Hex field length / padding
  APD  APDU-shaped hex fields
  N5G  DF.5GS vs USIM presence
  FIL  File definition FCP / fileID / EF sizing (ETSI TS 102 22x)
  UCR  USIM decoded shape expectations
  UST  EF(UST) service bits vs related files (informational coherence)
  MET  Sidecar metadata alignment / operator fields
  CHK  ``saip-tool check`` integration

Dynamic SVC rows use ``YRL-SVC-OK-<SERVICE>`` (PASS) and ``YRL-SVC-MIS-<SERVICE>`` (FAIL).
"""
