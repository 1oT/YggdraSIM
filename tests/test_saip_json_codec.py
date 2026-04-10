import json
import unittest
from collections import OrderedDict
from pathlib import Path

from Tools.ProfilePackage.saip_json_codec import (
    _TAG_BYTES,
    _TAG_TUPLE,
    TokenExpansionContext,
    dejsonify_document,
    dejsonify_saip_value,
    document_to_pretty_json,
    encode_der_from_document,
    jsonify_document,
    jsonify_saip_value,
    parse_editor_json,
    reapply_transcode_editor_placeholders,
    transcode_sidecar_paths,
)


class SaipJsonCodecTests(unittest.TestCase):
    def test_jsonify_dejsonify_nested(self) -> None:
        original = {
            "a": b"\x01\x02",
            "b": ("choice", {"inner": b"abcd"}),
            "c": [b"\xff", {"k": b""}],
        }
        tagged = jsonify_saip_value(original)
        roundtrip = dejsonify_saip_value(tagged)
        self.assertEqual(roundtrip["a"], b"\x01\x02")
        self.assertEqual(roundtrip["b"], ("choice", {"inner": b"abcd"}))
        self.assertIsInstance(roundtrip["c"][1], OrderedDict)

    def test_document_roundtrip_text(self) -> None:
        doc = {
            "intro": ["test intro"],
            "sections": {
                "header": OrderedDict(
                    [
                        ("major-version", 2),
                        ("blob", b"\x00\x11"),
                    ]
                ),
            },
        }
        text = document_to_pretty_json(doc)
        parsed = parse_editor_json(text)
        self.assertEqual(parsed["intro"], ["test intro"])
        self.assertIn("sections", parsed)

    def test_jsonify_document_keys(self) -> None:
        doc = {"intro": ["x"], "sections": {"pe1": b"\xab\xcd"}}
        tagged = jsonify_document(doc)
        dumped = json.dumps(tagged)
        loaded = json.loads(dumped)
        restored = dejsonify_document(loaded)
        self.assertEqual(restored["sections"]["pe1"], b"\xab\xcd")

    def test_tag_shape(self) -> None:
        self.assertEqual(
            jsonify_saip_value(b"\x0a"),
            {_TAG_BYTES: "0a"},
        )
        self.assertEqual(
            jsonify_saip_value(("x", 1))[_TAG_TUPLE][0],
            "x",
        )

    def test_placeholder_tokens_in_tagged_hex(self) -> None:
        ctx = TokenExpansionContext({"pad": {"zero_len": 2}}, "brace")
        out = dejsonify_saip_value({_TAG_BYTES: "ff{pad}ee"}, ctx)
        self.assertEqual(out, b"\xff\x00\x00\xee")

    def test_placeholder_bracket_style(self) -> None:
        ctx = TokenExpansionContext({"x": {"hex": "ab"}}, "bracket")
        out = dejsonify_saip_value({_TAG_BYTES: "00[x]11"}, ctx)
        self.assertEqual(out, b"\x00\xab\x11")

    def test_placeholder_unknown_token_raises(self) -> None:
        ctx = TokenExpansionContext({}, "brace")
        with self.assertRaises(ValueError):
            dejsonify_saip_value({_TAG_BYTES: "{missing}"}, ctx)

    def test_parse_editor_json_reports_value_path_for_invalid_hex(self) -> None:
        text = json.dumps(
            {
                "intro": [],
                "sections": {
                    "header": {
                        "blob": {
                            _TAG_BYTES: "ABC",
                        }
                    }
                },
            }
        )
        with self.assertRaisesRegex(
            ValueError,
            r"Invalid value at sections\.header\.blob: Hex string has odd length",
        ):
            parse_editor_json(text)

    def test_dejsonify_document_preserves_token_meta(self) -> None:
        loaded = {
            "intro": ["t"],
            "sections": {"s1": {_TAG_BYTES: "aa{tok}bb"}},
            "__ygg_token_defs__": {"tok": {"hex": "ccdd"}},
            "__ygg_placeholder_style__": "brace",
        }
        restored = dejsonify_document(loaded)
        self.assertEqual(restored["sections"]["s1"], b"\xaa\xcc\xdd\xbb")
        self.assertEqual(restored["__ygg_token_defs__"]["tok"], {"hex": "ccdd"})
        self.assertEqual(restored["__ygg_placeholder_style__"], "brace")

    def test_jsonify_document_emits_token_meta(self) -> None:
        doc = {
            "intro": ["i"],
            "sections": {"p": b"\x01"},
            "__ygg_token_defs__": {"a": {"zero_len": 1}},
            "__ygg_placeholder_style__": "bracket",
        }
        tagged = jsonify_document(doc)
        self.assertEqual(tagged["__ygg_token_defs__"]["a"], {"zero_len": 1})
        self.assertEqual(tagged["__ygg_placeholder_style__"], "bracket")

    def test_jsonify_document_adds_path_label_to_nested_bytes(self) -> None:
        doc = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-iccid": [
                        ("fillFileContent", b"\x01\x02"),
                    ],
                },
            },
        }
        tagged = jsonify_document(doc)
        inner = tagged["sections"]["mf"]["ef-iccid"][0][_TAG_TUPLE][1]
        self.assertEqual(inner[_TAG_BYTES], "0102")
        self.assertIn("label", inner)
        self.assertIn("Master file", inner["label"])
        self.assertIn("EF.ICCID", inner["label"])
        self.assertIn("Fill file content", inner["label"])

    def test_reapply_transcode_restores_bytes_template_and_meta(self) -> None:
        pre_loaded = {
            "intro": ["editor intro"],
            "sections": {"s1": {_TAG_BYTES: "aa{tok}bb"}},
            "__ygg_token_defs__": {"tok": {"hex": "c1d1"}},
            "__ygg_placeholder_style__": "brace",
        }
        post_tagged = {
            "intro": ["Re-encoded …"],
            "sections": {"s1": {_TAG_BYTES: "aac1d1bb"}},
        }
        reapply_transcode_editor_placeholders(pre_loaded, post_tagged)
        self.assertEqual(post_tagged["sections"]["s1"][_TAG_BYTES], "aa{tok}bb")
        self.assertEqual(post_tagged["__ygg_token_defs__"]["tok"], {"hex": "c1d1"})
        self.assertEqual(post_tagged["__ygg_placeholder_style__"], "brace")

    def test_reapply_does_not_restore_when_expansion_mismatches(self) -> None:
        pre_loaded = {
            "intro": [],
            "sections": {"s1": {_TAG_BYTES: "aa{tok}bb"}},
            "__ygg_token_defs__": {"tok": {"hex": "c1d1"}},
            "__ygg_placeholder_style__": "brace",
        }
        post_tagged = {
            "intro": [],
            "sections": {"s1": {_TAG_BYTES: "11223344"}},
        }
        reapply_transcode_editor_placeholders(pre_loaded, post_tagged)
        self.assertEqual(post_tagged["sections"]["s1"][_TAG_BYTES], "11223344")

    def test_transcode_sidecar_paths(self) -> None:
        base = Path("workspace") / "in" / "profile.der"
        jp, dp, tp = transcode_sidecar_paths(base)
        r = base.resolve()
        self.assertEqual(jp, r.parent / "profile.transcode.json")
        self.assertEqual(dp, r.parent / "profile.transcode.der")
        self.assertEqual(tp, r.parent / "profile.transcode.txt")

    def test_transcode_sidecar_paths_use_dedicated_transcode_root(self) -> None:
        workspace_root = Path("workspace").resolve()
        source_root = workspace_root / "Tools" / "ProfilePackage" / "profile"
        transcode_root = workspace_root / "Tools" / "ProfilePackage" / "transcode"
        base = source_root / "profile.der"

        jp, dp, tp = transcode_sidecar_paths(
            base,
            transcode_root=transcode_root,
            source_root=source_root,
        )

        self.assertEqual(jp, transcode_root / "profile.transcode.json")
        self.assertEqual(dp, transcode_root / "profile.transcode.der")
        self.assertEqual(tp, transcode_root / "profile.transcode.txt")

    def test_reapply_nested_tuple_fill_file_content(self) -> None:
        pre_loaded = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-x": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {_TAG_BYTES: "01{p}02"},
                            ],
                        },
                    ],
                },
            },
            "__ygg_token_defs__": {"p": {"hex": "abcd"}},
            "__ygg_placeholder_style__": "brace",
        }
        post_tagged = {
            "intro": [],
            "sections": {
                "mf": {
                    "ef-x": [
                        {
                            _TAG_TUPLE: [
                                "fillFileContent",
                                {_TAG_BYTES: "01abcd02"},
                            ],
                        },
                    ],
                },
            },
        }
        reapply_transcode_editor_placeholders(pre_loaded, post_tagged)
        inner = post_tagged["sections"]["mf"]["ef-x"][0][_TAG_TUPLE][1]
        self.assertEqual(inner[_TAG_BYTES], "01{p}02")


class SaipDerRoundTripIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = Path(__file__).resolve().parents[1]

    def test_json_tagged_roundtrip_preserves_pe_sequence(self) -> None:
        der_path = self.workspace / ".profilepackage-cache"
        candidates = sorted(der_path.glob("*.der"))
        if len(candidates) == 0:
            self.skipTest("No cached DER under .profilepackage-cache")

        der_file = candidates[0]
        raw = der_file.read_bytes()

        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
        )

        ensure = __import__(
            "Tools.ProfilePackage.saip_json_codec",
            fromlist=["ensure_workspace_pysim_on_path"],
        ).ensure_workspace_pysim_on_path

        ensure(self.workspace)
        from pySim.esim.saip import ProfileElementSequence

        pes0 = ProfileElementSequence.from_der(raw)
        doc = build_decoded_document_from_sequence(
            pes0,
            intro_lines=["integration"],
        )
        text = document_to_pretty_json(doc)
        doc2 = parse_editor_json(text)
        out = encode_der_from_document(doc2, self.workspace)
        pes1 = ProfileElementSequence.from_der(out)
        self.assertEqual(len(pes1.pe_list), len(pes0.pe_list))
        types0 = [pe.type for pe in pes0.pe_list]
        types1 = [pe.type for pe in pes1.pe_list]
        self.assertEqual(types1, types0)


if __name__ == "__main__":
    unittest.main()
