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

Schema-aware decoding is available by passing an ASN.1 module and type. The
generic BER/DER tree is still emitted, and the `schemaDecode` field contains
the `asn1tools` result.

```bash
python -m Tools.Asn1TlvDecode --schema path/to/schema.asn --type MyType "3003020101"
```
