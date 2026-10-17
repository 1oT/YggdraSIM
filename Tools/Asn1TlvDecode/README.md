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
embedded TLV decoding for APDU data fields.

SGP.32 `BF51` eIM packages get a semantic terminal rendering for
`EuiccPackageSigned`, eCO/PSMO choices, `EimConfigurationData`, public-key
containers, and signatures. Use `--format json` for the full generic BER tree.

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
  when pySim is installed, with the generic BER tree as the fallback.
- AUTHENTICATE (3GPP TS 31.102 v19.5): context from P2, RAND/AUTN and the
  'DB' / 'DC' response layouts.

A trace of exchanges keeps state: the selected file names the content a
READ BINARY returns, a '61 xx' status word chains the following GET RESPONSE
onto its command, and segmented STORE DATA blocks are reassembled first.

```bash
python -m Tools.Asn1TlvDecode --context "80F24002024F0000"
printf '> 00A4040407A0000000871002\n< 6F...9000\n' | python -m Tools.Asn1TlvDecode --context
python -m Tools.Asn1TlvDecode --context --domain gp --format json "E3..."
```

Lines may start with `>`, `<`, `->`, `<-`, `C:`, `R:` or carry `sw=XXXX`;
the GUI event-log format (`→ ... · ← ... · sw=9000`) is accepted as well. The
same decoder backs the Decoder panel under Offline Tools in the GUI and the
`context_decode` MCP tool.

Schema-aware decoding is available by passing an ASN.1 module and type. The
generic BER/DER tree is still emitted, and the `schemaDecode` field contains
the `asn1tools` result.

```bash
python -m Tools.Asn1TlvDecode --schema path/to/schema.asn --type MyType "3003020101"
```
