# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ASN.1/TLV decoder tests."""
from __future__ import annotations

from io import StringIO
import json
import tempfile
from pathlib import Path
import unittest

from Tools.Asn1TlvDecode.main import decode_bytes, normalise_hex, run_cli


class Asn1TlvDecodeTests(unittest.TestCase):
    def test_generic_sequence_decodes_universal_values(self) -> None:
        decoded = decode_bytes(bytes.fromhex("3006020105040141"))

        self.assertTrue(decoded["complete"])
        root = decoded["items"][0]
        self.assertEqual(root["name"], "ASN1_SEQUENCE")
        self.assertEqual(root["items"][0]["decoded"], 5)
        self.assertEqual(root["items"][1]["decoded"]["hex"], "41")
        self.assertIn("ASN1_SEQUENCE [30]", decoded["asn1Notation"])

    def test_gsma_tag_names_load_from_registry(self) -> None:
        decoded = decode_bytes(bytes.fromhex("BF2203810102"))

        root = decoded["items"][0]
        self.assertEqual(root["name"], "EUICC_INFO_2")
        self.assertEqual(root["tag"], "BF22")
        self.assertEqual(root["items"][0]["tag"], "81")

    def test_tag_list_value_is_split_into_tags(self) -> None:
        decoded = decode_bytes(bytes.fromhex("5C034F5A90"))

        tags = decoded["items"][0]["decoded"]["tags"]
        self.assertEqual([tag["tag"] for tag in tags], ["4F", "5A", "90"])
        self.assertEqual(tags[0]["name"], "AID")

    def test_cli_json_output_accepts_stdin(self) -> None:
        stdin = StringIO("BF2203810102")
        stdout = StringIO()
        original_stdin = __import__("sys").stdin
        try:
            __import__("sys").stdin = stdin
            code = run_cli(["--format", "json"], stdout=stdout, stderr=StringIO())
        finally:
            __import__("sys").stdin = original_stdin

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["items"][0]["name"], "EUICC_INFO_2")

    def test_normalise_hex_accepts_common_separators(self) -> None:
        self.assertEqual(normalise_hex("0xBF:22 03_81-01.02"), bytes.fromhex("BF2203810102"))

    def test_asn1tools_schema_decode_when_type_is_supplied(self) -> None:
        schema = """
Example DEFINITIONS ::= BEGIN
ExampleSeq ::= SEQUENCE {
    count INTEGER,
    label UTF8String
}
END
"""
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "example.asn"
            schema_path.write_text(schema, encoding="utf-8")
            decoded = decode_bytes(
                bytes.fromhex("30080201050C036F6E65"),
                schema_paths=[schema_path],
                type_name="ExampleSeq",
            )

        self.assertTrue(decoded["schemaDecode"]["ok"])
        self.assertEqual(decoded["schemaDecode"]["value"]["count"], 5)
        self.assertEqual(decoded["schemaDecode"]["value"]["label"], "one")


if __name__ == "__main__":
    unittest.main()
