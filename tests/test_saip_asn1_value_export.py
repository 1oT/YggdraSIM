# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest
from collections import OrderedDict
from pathlib import Path

from Tools.ProfilePackage.saip_asn1_value import (
    _Lexer,
    _Parser,
    _coerce_parsed_value,
    parse_asn1_value_profile,
    render_asn1_value,
    render_asn1_value_profile,
)
from Tools.ProfilePackage.saip_hex_template import (
    substitute_inline_placeholders,
)
from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path


class SaipAsn1ValueExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)

        from pySim.esim.saip import ProfileElementSequence, asn1

        cls.ProfileElementSequence = ProfileElementSequence
        cls.asn1 = asn1

    def _reference_sequence(self):
        path = (
            self.workspace_root
            / "Tools"
            / "ProfilePackage"
            / "profile"
            / "reference_test_profile.txt"
        )
        if path.is_file() is False:
            self.skipTest("No tracked reference SAIP profile fixture")
        raw = bytes.fromhex("".join(path.read_text(encoding="utf-8").split()))
        return self.ProfileElementSequence.from_der(raw)

    def test_reference_profile_der_round_trip(self) -> None:
        source = self._reference_sequence()

        rendered = render_asn1_value_profile(
            source,
            workspace_root=self.workspace_root,
        )
        parsed = parse_asn1_value_profile(
            rendered,
            workspace_root=self.workspace_root,
        )

        self.assertIn('profileType "Sample Lab"', rendered)
        self.assertIn("templateID { 2 23 143 1 2 1 }", rendered)
        self.assertIn("pinconfig :", rendered)
        self.assertEqual(parsed.inline_placeholder_records, [])
        self.assertEqual(parsed.pes.to_der(), source.to_der())

    def test_inline_placeholder_literal_round_trip(self) -> None:
        source = self._reference_sequence()
        sentinel_hex, records = substitute_inline_placeholders("[iccidICCID10]")
        source.pe_list[0].decoded["iccid"] = bytes.fromhex(sentinel_hex)
        sentinel_der = source.to_der()

        rendered = render_asn1_value_profile(
            source,
            workspace_root=self.workspace_root,
            inline_placeholder_records=records,
        )
        parsed = parse_asn1_value_profile(
            rendered,
            workspace_root=self.workspace_root,
        )

        self.assertIn("iccid '[iccidICCID10]'H", rendered)
        self.assertNotIn(sentinel_hex, rendered)
        self.assertEqual(parsed.inline_placeholder_records, records)
        self.assertEqual(parsed.pes.to_der(), sentinel_der)

    def test_bit_string_renders_and_parses_with_exact_bit_length(self) -> None:
        schema_node = self.asn1.types["UICCCapability"]._type
        source = (b"\xa8", 5)

        rendered = render_asn1_value(source, schema_node)
        parser = _Parser(_Lexer(rendered).tokens(), named_numbers={})
        parsed = parser._parse_value()

        self.assertEqual(rendered, "'10101'B")
        self.assertEqual(parsed, source)
        self.assertEqual(
            self.asn1.encode("UICCCapability", parsed),
            self.asn1.encode("UICCCapability", source),
        )

    def test_schema_disambiguates_empty_sequence_from_sequence_of(self) -> None:
        empty_sequence_schema = self.asn1.types["PE-Dummy"]._type
        header_schema = self.asn1.types["ProfileHeader"]._type
        oid_list_schema = next(
            member
            for member in header_schema.root_members
            if member.name == "eUICC-Mandatory-GFSTEList"
        )

        self.assertEqual(
            _coerce_parsed_value(
                empty_sequence_schema,
                [],
                path="PE-Dummy",
            ),
            OrderedDict(),
        )
        self.assertEqual(
            _coerce_parsed_value(
                oid_list_schema,
                [],
                path="ProfileHeader.eUICC-Mandatory-GFSTEList",
            ),
            [],
        )

    def test_placeholder_record_requires_matching_sentinel_in_octets(self) -> None:
        source = self._reference_sequence()
        _sentinel_hex, records = substitute_inline_placeholders("[iccidICCID10]")

        with self.assertRaisesRegex(
            ValueError,
            "sentinel\\(s\\) not found",
        ):
            render_asn1_value_profile(
                source,
                workspace_root=self.workspace_root,
                inline_placeholder_records=records,
            )


if __name__ == "__main__":
    unittest.main()
