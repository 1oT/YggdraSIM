# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Exhaustive tests for decoded ASN.1 / pySim object trees → tagged JSON (and back).

Targets ``jsonify_saip_value``, ``jsonify_document``, ``dejsonify_*``, and helpers
used on the SAIP dump / TRANSCODE path.
"""

import json
import unittest
from collections import OrderedDict
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import (
    _META_PLACEHOLDER_STYLE,
    _META_TOKEN_DEFS,
    _TAG_BYTES,
    _TAG_PLACEHOLDER,
    _TAG_TUPLE,
    TokenExpansionContext,
    base_pe_type,
    build_decoded_document_from_sequence,
    dejsonify_document,
    dejsonify_saip_value,
    document_to_pretty_json,
    format_der_hex,
    jsonify_document,
    jsonify_saip_value,
    parse_editor_json,
)


class JsonifySaipValueBranchTests(unittest.TestCase):
    """One test per ``jsonify_saip_value`` structural branch (ASN.1-ish shapes)."""

    def test_bytes_nonempty(self) -> None:
        out = jsonify_saip_value(b"\xde\xad")
        self.assertEqual(out, {_TAG_BYTES: "dead"})

    def test_bytes_empty(self) -> None:
        out = jsonify_saip_value(b"")
        self.assertEqual(out, {_TAG_BYTES: ""})

    def test_bytearray(self) -> None:
        out = jsonify_saip_value(bytearray([1, 2]))
        self.assertEqual(out, {_TAG_BYTES: "0102"})

    def test_tuple_empty(self) -> None:
        out = jsonify_saip_value(tuple())
        self.assertEqual(out, {_TAG_TUPLE: []})

    def test_tuple_choice_like_nested(self) -> None:
        inner = (
            "someChoice",
            OrderedDict([("k", b"\x00"), ("n", 7)]),
        )
        out = jsonify_saip_value(inner)
        self.assertIn(_TAG_TUPLE, out)
        self.assertEqual(out[_TAG_TUPLE][0], "someChoice")
        self.assertEqual(out[_TAG_TUPLE][1]["k"][_TAG_BYTES], "00")

    def test_ordereddict_order_preserved_in_tagged_tree(self) -> None:
        od: OrderedDict[str, object] = OrderedDict(
            [
                ("z-first", 1),
                ("a-second", b"\xff"),
            ]
        )
        tagged = jsonify_saip_value(od)
        keys = list(tagged.keys())
        self.assertEqual(keys, ["z-first", "a-second"])

    def test_plain_dict_json_object(self) -> None:
        tagged = jsonify_saip_value({"x": True, "y": None})
        self.assertEqual(tagged["x"], True)
        self.assertIsNone(tagged["y"])

    def test_list_nested(self) -> None:
        tagged = jsonify_saip_value([1, [b"\xab"], {"k": ()}])
        self.assertEqual(tagged[0], 1)
        self.assertEqual(tagged[1][0][_TAG_BYTES], "ab")
        self.assertEqual(tagged[2]["k"][_TAG_TUPLE], [])

    def test_primitives_passthrough(self) -> None:
        self.assertIsNone(jsonify_saip_value(None))
        self.assertIs(jsonify_saip_value(True), True)
        self.assertEqual(jsonify_saip_value(42), 42)
        self.assertEqual(jsonify_saip_value(-3), -3)
        self.assertAlmostEqual(jsonify_saip_value(1.25), 1.25)
        self.assertEqual(jsonify_saip_value("ascii"), "ascii")
        self.assertEqual(jsonify_saip_value("åäö"), "åäö")


class JsonifyDejsonifyRoundTripTests(unittest.TestCase):
    """Full tree round-trip through JSON wire (as in editor files)."""

    def test_deep_mixed_tree(self) -> None:
        original = OrderedDict(
            [
                ("present", 2),
                (
                    "element",
                    OrderedDict(
                        [
                            ("octets", b"\x01"),
                            ("inner_list", [("t", b""), 0]),
                        ]
                    ),
                ),
            ]
        )
        tagged = jsonify_saip_value(original)
        dumped = json.dumps(tagged)
        loaded = json.loads(dumped)
        back = dejsonify_saip_value(loaded)
        self.assertIsInstance(back, OrderedDict)
        self.assertEqual(back["present"], 2)
        self.assertEqual(back["element"]["octets"], b"\x01")
        self.assertEqual(back["element"]["inner_list"][0], ("t", b""))
        self.assertEqual(back["element"]["inner_list"][1], 0)

    def test_tuple_roundtrip(self) -> None:
        t = ("a", b"\x02", {"k": 1})
        tagged = jsonify_saip_value(t)
        back = dejsonify_saip_value(json.loads(json.dumps(tagged)))
        self.assertEqual(back, ("a", b"\x02", OrderedDict([("k", 1)])))


class DejsonifyEdgeAndErrorTests(unittest.TestCase):
    def test_ygg_label_keys_stripped(self) -> None:
        payload = {
            "a": 1,
            "__ygg_label__": "note",
            "__ygg_label__imsi": "ignored",
            "b": b"\x03",
        }
        tagged = jsonify_saip_value(payload)
        loaded = json.loads(json.dumps(tagged))
        back = dejsonify_saip_value(loaded)
        self.assertEqual(set(back.keys()), {"a", "b"})
        self.assertEqual(back["b"], b"\x03")

    def test_tuple_inner_not_list_raises(self) -> None:
        with self.assertRaises(ValueError):
            dejsonify_saip_value({_TAG_TUPLE: "bad"})

    def test_tagged_bytes_odd_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            dejsonify_saip_value({_TAG_BYTES: "a"})

    def test_tagged_bytes_ignores_whitespace_in_hex(self) -> None:
        out = dejsonify_saip_value({_TAG_BYTES: "aa\n bb\tcc"})
        self.assertEqual(out, b"\xaa\xbb\xcc")

    def test_placeholder_ph_empty_object(self) -> None:
        out = dejsonify_saip_value({_TAG_PLACEHOLDER: {}})
        self.assertEqual(out, b"")

    def test_placeholder_ph_pattern_hex(self) -> None:
        out = dejsonify_saip_value(
            {_TAG_PLACEHOLDER: {"pattern_hex": "ab", "byte_len": 5}}
        )
        self.assertEqual(out, b"\xab\xab\xab\xab\xab")

    def test_placeholder_ph_invalid_shape_raises(self) -> None:
        with self.assertRaises(ValueError):
            dejsonify_saip_value({_TAG_PLACEHOLDER: {"unknown": 1}})


class JsonifyDocumentTests(unittest.TestCase):
    def test_intro_coerced_when_not_list(self) -> None:
        doc = {"intro": "single", "sections": {"p": 1}}
        tagged = jsonify_document(doc)
        self.assertEqual(tagged["intro"], ["single"])

    def test_sections_must_be_object(self) -> None:
        with self.assertRaises(ValueError):
            jsonify_document({"intro": [], "sections": []})

    def test_meta_keys_copied(self) -> None:
        doc = {
            "intro": [],
            "sections": {"a": b""},
            _META_TOKEN_DEFS: {"t": {"hex": "00"}},
            _META_PLACEHOLDER_STYLE: "bracket",
        }
        tagged = jsonify_document(doc)
        self.assertIn(_META_TOKEN_DEFS, tagged)
        self.assertIn(_META_PLACEHOLDER_STYLE, tagged)


class DejsonifyDocumentTests(unittest.TestCase):
    def test_sections_must_be_object(self) -> None:
        with self.assertRaises(ValueError):
            dejsonify_document({"intro": [], "sections": "nope"})

    def test_intro_coerced_when_not_list(self) -> None:
        restored = dejsonify_document(
            {"intro": "one-line", "sections": {"p": 0}}
        )
        self.assertEqual(restored["intro"], ["one-line"])

    def test_token_defs_must_be_object(self) -> None:
        with self.assertRaises(ValueError):
            dejsonify_document(
                {
                    "intro": [],
                    "sections": {},
                    _META_TOKEN_DEFS: [],
                }
            )

    def test_placeholder_style_curly_alias(self) -> None:
        restored = dejsonify_document(
            {
                "intro": [],
                "sections": {"s": {_TAG_BYTES: "00{tok}11"}},
                _META_TOKEN_DEFS: {"tok": {"hex": "aa"}},
                _META_PLACEHOLDER_STYLE: "curly",
            }
        )
        self.assertEqual(restored["sections"]["s"], b"\x00\xaa\x11")


class TokenExpansionContextTests(unittest.TestCase):
    def test_invalid_style(self) -> None:
        with self.assertRaises(ValueError):
            TokenExpansionContext({}, "hex")

    def test_invalid_defs_type(self) -> None:
        with self.assertRaises(ValueError):
            TokenExpansionContext([], "brace")  # type: ignore[arg-type]


class BasePeTypeTests(unittest.TestCase):
    def test_no_suffix(self) -> None:
        self.assertEqual(base_pe_type("header"), "header")

    def test_numeric_suffix(self) -> None:
        self.assertEqual(base_pe_type("usim_2"), "usim")

    def test_empty(self) -> None:
        self.assertEqual(base_pe_type(""), "")

    def test_suffix_not_only_digits(self) -> None:
        self.assertEqual(base_pe_type("usim_extra"), "usim_extra")


class BuildDecodedDocumentTests(unittest.TestCase):
    def test_unique_keys_for_duplicate_pe_types(self) -> None:
        class _Pe:
            def __init__(self, t: str, d: object) -> None:
                self.type = t
                self.decoded = d

        class _Seq:
            pe_list: list[_Pe]

        seq = _Seq()
        seq.pe_list = [
            _Pe("mf", {"i": 1}),
            _Pe("mf", {"i": 2}),
        ]
        doc = build_decoded_document_from_sequence(seq, intro_lines=["x"])
        self.assertEqual(doc["intro"], ["x"])
        self.assertEqual(set(doc["sections"].keys()), {"mf", "mf_2"})


class ParseEditorJsonTests(unittest.TestCase):
    def test_empty_buffer(self) -> None:
        with self.assertRaises(ValueError):
            parse_editor_json("   ")

    def test_root_not_object(self) -> None:
        with self.assertRaises(ValueError):
            parse_editor_json("[1]")


class DocumentPrettyJsonTests(unittest.TestCase):
    def test_trailing_newline(self) -> None:
        text = document_to_pretty_json({"intro": [], "sections": {}})
        self.assertTrue(text.endswith("\n"))


class FormatDerHexTests(unittest.TestCase):
    def test_uppercase_spaced_lines(self) -> None:
        text = format_der_hex(b"\x01\xab\xcd", width=2)
        self.assertIn("01", text)
        self.assertIn("AB", text)
        self.assertIn("CD", text)
        lines = text.strip().split("\n")
        self.assertEqual(len(lines), 2)


class DerToJsonGoldenPathTests(unittest.TestCase):
    """ASN.1 DER → pySim decode → tagged JSON text (when DER fixtures exist)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = Path(__file__).resolve().parents[1]

    def _reference_profile_der(self) -> bytes:
        path = self.workspace / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        if path.is_file() is False:
            self.skipTest("No tracked reference SAIP profile fixture")
        return bytes.fromhex("".join(path.read_text(encoding="utf-8").split()))

    def test_der_decode_jsonify_preserves_pe_types(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            ensure_workspace_pysim_on_path,
        )

        ensure_workspace_pysim_on_path(self.workspace)
        from pySim.esim.saip import ProfileElementSequence

        raw = self._reference_profile_der()
        pes = ProfileElementSequence.from_der(raw)
        doc = build_decoded_document_from_sequence(pes, intro_lines=["golden"])
        text = document_to_pretty_json(doc)
        loaded = json.loads(text)
        self.assertIn("intro", loaded)
        self.assertIn("sections", loaded)
        for _key, section in loaded["sections"].items():
            self.assertIsInstance(section, dict)
