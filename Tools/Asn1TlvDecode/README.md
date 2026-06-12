# ASN.1/TLV Decode Tool

Decode pasted BER/DER ASN.1 or BER-TLV hex into JSON and ASN.1-like value
notation.

```bash
python -m Tools.Asn1TlvDecode "BF2203810102"
echo "3006020105040141" | python -m Tools.Asn1TlvDecode --format json
```

The decoder loads tag names from `docs/tel-docs/converted/_indexes` and the
converted SGP.22, SGP.32, GlobalPlatform, and ETSI tag tables when those files
are present. Built-in fallback names cover the common ES10, ESipa, and
GlobalPlatform tags.

Schema-aware decoding is available by passing an ASN.1 module and type. The
generic BER/DER tree is still emitted, and the `schemaDecode` field contains
the `asn1tools` result.

```bash
python -m Tools.Asn1TlvDecode --schema path/to/schema.asn --type MyType "3003020101"
```
