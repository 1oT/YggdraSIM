<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# ASN.1/TLV Decode Tool

Decode pasted BER/DER ASN.1, BER-TLV, or command APDU hex into JSON and
readable notation.

```bash
python -m Tools.Asn1TlvDecode "BF2203810102"
echo "3006020105040141" | python -m Tools.Asn1TlvDecode --format json
python -m Tools.Asn1TlvDecode "00A40400023F00"
python -m Tools.Asn1TlvDecode "80E2910003BF5100"
```

The default output is compact ASN.1-like notation. Use `--format json` when
machine-readable metadata is needed, or `--format both` to print both views.

When no positional hex and no `--file` are supplied, the decoder reads
non-interactive stdin. Running it from a terminal without input prints usage
instead of waiting for EOF.

The decoder loads tag names from `docs/tel-docs/converted/_indexes` and the
converted SGP.22, SGP.32, GlobalPlatform, and ETSI tag tables when those files
are present. Built-in fallback names cover the SGP.22 v3.1 and SGP.32 v1.2 tag
allocation tables, plus SGP.02 eCASD/GlobalPlatform probe tags used by the
repository's legacy M2M scan path. Inputs that are not valid BER-TLV are parsed
as command APDUs, with ISO/ETSI and GlobalPlatform instruction names plus
embedded TLV decoding for APDU data fields. A one-byte context-specific tag
(`'81'`, `'A0'`) takes no name from those tables: it means what the enclosing
type says, so the generic tree shows its BER class name (`CONTEXT_1`).

SGP.32 `BF51` eIM packages get a semantic terminal rendering for
`EuiccPackageSigned`, eCO/PSMO choices, `EimConfigurationData`, public-key
containers, and signatures. Use `--format json` for the full generic BER tree.

## GSMA RSP objects

When pySim and the SGP.32 v1.3 asset compile, a single BF-tagged object is
read against the SGP.22 / SGP.32 modules first, and that reading is the
notation; the JSON carries it as `rspSchema` and the BER tree as
`berNotation`, which `--ber` prints below the reading. A request and a response share their tag, so a
type counts only when it reads every byte: an `IpaEuiccDataRequest` is never
taken for the `IpaEuiccDataResponse` CHOICE that asn1tools would accept as an
unknown alternative. Named bits and numbers are shown by name, a `VersionType`
as `v2.3.0` (SGP.22 v3.1 §2.4a.1.0), and a tag list names the members it
selects: `IpaEuiccData` for `IpaEuiccDataRequest` (SGP.32 v1.3 §2.11.1.2),
`ProfileInfo` for `ProfileInfoListRequest` and `ListProfileInfo`
(SGP.22 v3.1 §5.7.15), the EID for `GetEuiccDataRequest` (§5.7.20).
An ANY value holding a universal string or OID reads as that text. Sibling
values line up in one column and a list element is named by its index (`[0]`).
A value of a type with named bits or numbers lists every one the type names
below it, the taken ones marked, so a capability field shows what is supported
and what is not: `[x]` / `[ ]` for a bit, `(*)` / `( )` for a number, and the
bit string itself says how many are set (`(21 of 32 set)`). On a terminal the
taken ones are drawn in the reading colour and the rest greyed out. A
certificate reads as the rows of `SCP11/shared/certificate_view.py`
(subject, issuer, validity, key, RSP role, EID, extensions) once its bytes are
found in the input, `DeviceInfo` `tac` and `imei` as their Telephony BCD
digits (SGP.22 v3.1 §4.2), and `extCardResource` as the ETSI TS 102 226 v19.0
§8.2.1.7.2 resources (installed applications, free non-volatile and volatile
memory in bytes).

On a terminal the reading is coloured from the active CLI theme
(`YGGDRASIM_CLI_THEME`): names, CHOICE alternatives, strings, numbers and the
decoded readings each have their colour. `--color auto` (the default) colours
a terminal unless `NO_COLOR` is set, `always` and `never` decide outright; the
stored notation, the JSON and the GUI never carry escape codes.

A stock asn1tools (eerimoq releases up to 0.169.0, osmocom/asn1tools master)
gives a tagged reference to a tagged CHOICE an explicit tag of its own:
`EimPackageResult.ipaEuiccDataResponse [82] IpaEuiccDataResponse` reads as two
`BF52`, where X.680 (02/2021) §31.2.7 makes the tag implicit and X.690
(02/2021) §8.14.4 puts it in place of the CHOICE's own, so a card's encoding
of such a member does not decode. The asn1tools YggdraSIM pins carries the fix
(`upstream_patches/osmocom-asn1tools-tagged-choice/`).

```text
$ python -m Tools.Asn1TlvDecode BF52195C0DA081A2BF20BF228384A5A6A8A983080000000000002475
IpaEuiccDataRequest  [SGP.32-v1.3]
  tagList = 'A081A2BF20BF228384A5A6A8A9'H (11 IpaEuiccData tags, SGP.32 v1.3 §2.11.1.2)
    A0    notificationsList
    81    defaultSmdpAddress
    ...
    A9    deviceInfo
  eimTransactionId = '0000000000002475'H
```

With `--ber` the BER tree follows:

```text
-- BER-TLV
IPA_EUICC_DATA [BF52] ::= {
  TAG_LIST [5C] = { A0, 81, A2, BF20 EUICC_INFO_1, BF22 EUICC_INFO_2, 83, 84, A5, A6, A8, A9 },
  CONTEXT_3 [83] = '0000000000002475'H
}
```

`--each` decodes every input line on its own and prints one JSON object per
line (`kind` is `schema`, `tlv`, `none` or `error`, with the `notation`). A
line is hex, or a label, a tab and hex; a label naming an RSP type, as given or
with its first letter raised, is tried as that type first, so an ES9+ or ESipa
JSON member reads as its type (`smdpSigned2` -> `SmdpSigned2`). Bytes that are
not BER-TLV are never read as an APDU here. The output is JSON, so only
`--color always` puts escape codes into its notations.

```bash
printf 'smdpSigned2\t300D800801000000000007AC010100\n' | python -m Tools.Asn1TlvDecode --each
```

## Context-aware decoding

`--context` reads the input as card traffic rather than as one TLV. Each
command is classified by its CLA/INS pair, refined by P1/P2 and the leading
data tag, and the payload is decoded against the specification that governs
it:

- UICC file and PIN commands (ETSI TS 102 221 v18.4): SELECT parameters,
  FCP templates with the file descriptor, life cycle status, referenced
  security attributes and PIN status template named clause by clause.
- Card Application Toolkit (ETSI TS 102 223 v18.3 / TS 101 220 v19):
  proactive commands, envelopes and terminal responses as COMPREHENSION-TLV
  objects with command types, device identities, general results and events.
- GlobalPlatform (GPC v2.3.1, SCP03 Amendment D): GET STATUS registry
  entries with life cycle and privileges, INSTALL fields per role, DELETE,
  STORE DATA, GET DATA and INITIALIZE UPDATE.
- ES10 over STORE DATA (SGP.22 v3.1 / SGP.32 v1.3): the request or response
  type is named from the BF tag and decoded with the compiled ASN.1 modules
  when pySim is installed, with the generic BER tree as the fallback. pySim's
  SGP.22 v2 module and the SGP.32 v1.3 module are compiled together; a pySim
  that carries the SGP.22 v3.1 module (`pySim.esim.rsp.asn1_v3`) decodes the
  types the joint compile lacks, such as the v3.1 ES10 functions
  (`EuiccConfiguredData`, `LoadRpmPackage`, `CheckProgress`, ...), and
  `EUICCInfo1` and `StoreMetadataRequest`, so their v3.1 members are shown
  (a v2 eUICC's `svn` appears as `lowestSvn`). The payload's `schemaSource`
  names the modules that decoded it.
- AUTHENTICATE (3GPP TS 31.102 v19.5): context from P2, RAND/AUTN and the
  'DB' / 'DC' response layouts.
- SCP11 (GlobalPlatform Amendment F v1.2 sections 6.4 to 6.6): PERFORM
  SECURITY OPERATION with its certificate, MUTUAL AUTHENTICATE and INTERNAL
  AUTHENTICATE with the key agreement template, the public keys and the
  receipt.
- Inside the objects: the SMS TPDU of an SMS-PP download or a SEND SHORT
  MESSAGE with its secured command or response packet (ETSI TS 102 225
  V19.0.0 sections 5.1 and 5.2), BIP channel data followed across a trace
  as one stream per channel (TLS records and handshake messages, DNS, HTTP
  lines), the
  PUT KEY data field and the Key Information Template (GPC v2.4 sections
  11.8.2.3, 11.3.3.1), TERMINAL CAPABILITY, and the SUCI of GET IDENTITY
  (3GPP TS 31.102 V19.5 section 7.5.2.1).

Hex is read first. Around it, `AT+CSIM`, `AT+CRSM`, `AT+CGLA` and `AT+CRLA`
lines with their answers (3GPP TS 27.007 V19.6 sections 8.17, 8.18, 8.43 and
8.44) are read as exchanges, and a restricted-access line names the file
whose content it returns. Text that is not hex is tried as a PEM certificate
(a key block is left unread), a JSON body whose base64 members are RSP
objects, base64, an EID, ICCID or IMSI in digits with its check digits, an
ATR and TLS records; four bytes that are a PC/SC return code are named. A
plain BER tree is replaced by the certificate or the profile package it is,
and `--domain tlv` keeps the tree. `--domain ef` reads the content of one
file: the file identifier on the first line, the content below.

A trace of exchanges keeps state: the selected file names the content a
READ BINARY returns, a '61 xx' status word chains the following GET RESPONSE
onto its command, and segmented STORE DATA blocks are reassembled first.

```bash
python -m Tools.Asn1TlvDecode --context "80F24002024F0000"
printf '> 00A4040407A0000000871002\n< 6F...9000\n' | python -m Tools.Asn1TlvDecode --context
python -m Tools.Asn1TlvDecode --context --domain gp --format json "E3..."
printf 'AT+CRSM=176,28423,0,0,9\n+CRSM: 144,0,"080910100000000010"\n' | python -m Tools.Asn1TlvDecode --context
printf 'ADF_USIM/6F07\n080910100000000010\n' | python -m Tools.Asn1TlvDecode --context --domain ef
python -m Tools.Asn1TlvDecode --context --file leaf.pem
python -m Tools.Asn1TlvDecode --context --file install.txt
```

Several commands go in at once, one per row. That is the script file the
SCP03 shell's `RUN` and the SCP80 shell's `script` read: a row that starts
with `#` is a comment, a row of hex is one command. Each row is decoded as
its own command, with the trace state carried from row to row, so a script
reads as its commands in order:

```text
# Select the USIM, then EF.IMSI, and read it
00A4040007A0000000871002
00A40004026F07
# Nine bytes from offset 0
00B0000009
```

The decoder also drops a `#` comment written after the hex on a row, as the
SCP80 `script` does; `RUN` in the SCP03 shell does not take one, so a script
meant for both keeps its comments on rows of their own.

Rows may also be exchanges: a command with its answer on the row below, or
on the same row after ` | `, ` ; ` or a tab (a plain space does not part the
two: the hex on a row is one string). A marker (below) says what a row is. Without one, a row that is a
well-formed command of an instruction the decoder knows starts a new
exchange, also while the command above still waits for its answer; any
other row answers the command above it. `--domain apdu` takes every row as a
command and `--domain response` every row as an answer, whatever the row
looks like. A row that holds no hex (a shell verb such as `SELECT 3F00`) is
left unread and counted in a note by its row number; it is never mined for
hex and never quoted. `--file` reads UTF-8, with or without a byte order
mark, and UTF-16 by its byte order mark.

Lines may start with `>`, `<`, `->`, `<-`, `C:`, `R:` or carry `sw=XXXX`;
the GUI event-log format (`→ ... · ← ... · sw=9000`) is accepted as well, and
so are the raw exchange lines of the eSIM Management shells' `--debug`
(`[label] > command`, `[label] < SW: 9000 Data: ...`). The
same decoder backs the Decoder panel under Offline Tools in the GUI and the
`context_decode` MCP tool.

Schema-aware decoding is available by passing an ASN.1 module and type. The
generic BER/DER tree is still emitted, and the `schemaDecode` field contains
the `asn1tools` result.

```bash
python -m Tools.Asn1TlvDecode --schema path/to/schema.asn --type MyType "3003020101"
```
