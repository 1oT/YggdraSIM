# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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
    humanize_saip_display_path,
    jsonify_document,
    jsonify_saip_value,
    parse_editor_json,
    reapply_transcode_editor_placeholders,
    transcode_sidecar_paths,
)


def _variable_catalog() -> dict:
    return {
        "schema_version": "yggdrasim.saip-variable-catalog/v1",
        "selector_dialect": "YGGDRASIM_SAIP_SEMANTIC_SELECTOR_V1",
        "variables": [
            {
                "id": "ICCID",
                "classification": "IDENTIFIER",
                "required": True,
                "bindings": [
                    {
                        "selector": "PROFILE_HEADER.ICCID",
                        "encoder": "ICCID_HEADER_BCD_V1",
                        "output_length_bytes": 10,
                    }
                ],
            }
        ],
    }


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

    def test_variable_catalog_survives_tagged_json_roundtrip(self) -> None:
        catalog = _variable_catalog()
        document = {
            "intro": ["catalog"],
            "sections": {"header": {"iccid": b"\x00" * 10}},
            "__ygg_variable_catalog__": catalog,
        }

        tagged = jsonify_document(document)
        reopened = dejsonify_document(json.loads(json.dumps(tagged)))

        self.assertEqual(tagged["__ygg_variable_catalog__"], catalog)
        self.assertEqual(reopened["__ygg_variable_catalog__"], catalog)

    def test_variable_catalog_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"__ygg_variable_catalog__ must be an object",
        ):
            dejsonify_document(
                {
                    "intro": [],
                    "sections": {},
                    "__ygg_variable_catalog__": [],
                }
            )

    def test_inline_placeholder_sidecar_survives_tagged_json_roundtrip(self) -> None:
        sidecar = {
            "version": 1,
            "placeholders": [
                {
                    "index": 0,
                    "literal": "{ICCIDICCID10}",
                    "variable": "ICCID",
                    "type": "ICCID",
                    "byte_length": 10,
                    "modifier": None,
                    "sentinel_hex": "AA" * 10,
                }
            ],
        }
        document = {
            "intro": ["inline template"],
            "sections": {"header": {"iccid": bytes.fromhex("AA" * 10)}},
            "__ygg_inline_placeholders__": sidecar,
        }

        tagged = jsonify_document(document)
        reopened = dejsonify_document(json.loads(json.dumps(tagged)))

        self.assertEqual(tagged["__ygg_inline_placeholders__"], sidecar)
        self.assertEqual(reopened["__ygg_inline_placeholders__"], sidecar)

    def test_inline_placeholder_sidecar_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"__ygg_inline_placeholders__ must be an object",
        ):
            dejsonify_document(
                {
                    "intro": [],
                    "sections": {},
                    "__ygg_inline_placeholders__": [],
                }
            )

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
        self.assertIn("File content", inner["label"])

    def test_humanize_saip_display_path_skips_raw_ef_record_indexes(self) -> None:
        rendered = humanize_saip_display_path(
            [
                "mf",
                "ef-arr",
                "[0]",
                "fileDescriptor",
                "shortEFID",
            ]
        )
        self.assertEqual(
            rendered,
            "Master file (MF) tree / EF.ARR / File descriptor / Short EF Identifier",
        )

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

    def test_reapply_transcode_restores_variable_catalog(self) -> None:
        catalog = _variable_catalog()
        pre_loaded = {
            "intro": ["before sequence rebuild"],
            "sections": {"header": {"iccid": {_TAG_BYTES: "00" * 10}}},
            "__ygg_variable_catalog__": catalog,
        }
        post_tagged = {
            "intro": ["after sequence rebuild"],
            "sections": {"header": {"iccid": {_TAG_BYTES: "00" * 10}}},
        }

        reapply_transcode_editor_placeholders(pre_loaded, post_tagged)

        self.assertEqual(post_tagged["__ygg_variable_catalog__"], catalog)
        self.assertIsNot(post_tagged["__ygg_variable_catalog__"], catalog)

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

    def _reference_profile_der(self) -> bytes:
        path = self.workspace / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        if path.is_file() is False:
            self.skipTest("No tracked reference SAIP profile fixture")
        return bytes.fromhex("".join(path.read_text(encoding="utf-8").split()))

    def test_json_tagged_roundtrip_preserves_pe_sequence(self) -> None:
        raw = self._reference_profile_der()

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

    def test_sequence_transcode_reapplies_variable_catalog(self) -> None:
        raw = self._reference_profile_der()

        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            build_profile_sequence_from_document,
            ensure_workspace_pysim_on_path,
        )

        ensure_workspace_pysim_on_path(self.workspace)
        from pySim.esim.saip import ProfileElementSequence

        source_sequence = ProfileElementSequence.from_der(raw)
        source_document = build_decoded_document_from_sequence(
            source_sequence,
            intro_lines=["catalog sequence roundtrip"],
        )
        catalog = _variable_catalog()
        source_document["__ygg_variable_catalog__"] = catalog
        pre_loaded = json.loads(document_to_pretty_json(source_document))
        restored = dejsonify_document(pre_loaded)

        rebuilt_sequence = build_profile_sequence_from_document(
            restored,
            self.workspace,
        )
        rebuilt_document = build_decoded_document_from_sequence(
            rebuilt_sequence,
            intro_lines=["rebuilt"],
        )
        post_tagged = jsonify_document(rebuilt_document)
        self.assertNotIn("__ygg_variable_catalog__", post_tagged)

        reapply_transcode_editor_placeholders(pre_loaded, post_tagged)
        reopened = dejsonify_document(json.loads(json.dumps(post_tagged)))

        self.assertEqual(reopened["__ygg_variable_catalog__"], catalog)


if __name__ == "__main__":
    unittest.main()


class TranscodeRoundTripFidelity(unittest.TestCase):
    """A profile opened and saved without edits must come back byte for byte.

    build_profile_sequence_from_document used to renumber every PE header
    identification to a dense 1..N. That is what makes authoring safe -- a
    PE added through quick-add arrives with identification 0 -- but it also
    rewrote numbering the issuer chose. A real package in this tree carries
    identifications [2, 5, 6, ..., 20, 19, 21]: gapped, and deliberately
    non-monotonic. Renumbering silently replaced them with [1, 4, 5, ...].
    """

    def _reference_package(self) -> Path:
        root = Path(__file__).resolve().parents[1]
        for candidate in sorted((root / ".profilepackage-cache").glob("profile-*.der")):
            if candidate.stat().st_size > 1024:
                return candidate
        self.skipTest("no cached reference profile available")

    def _identifications(self, sequence) -> list:
        out = []
        for pe in sequence.pe_list:
            header = getattr(pe, "header", None)
            if header and "identification" in header:
                out.append(header["identification"])
        return out

    def test_no_op_round_trip_is_byte_identical(self) -> None:
        from Tools.ProfilePackage.saip_json_codec import (
            build_decoded_document_from_sequence,
            ensure_workspace_pysim_on_path,
        )

        workspace = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(workspace)
        from pySim.esim.saip import ProfileElementSequence

        raw = self._reference_package().read_bytes()
        source = ProfileElementSequence.from_der(raw)
        document = build_decoded_document_from_sequence(source, intro_lines=["fidelity"])
        restored = dejsonify_document(json.loads(document_to_pretty_json(document)))
        rebuilt = encode_der_from_document(restored, workspace)

        self.assertEqual(rebuilt, raw, "opening and saving an unedited profile changed it")
        self.assertEqual(
            self._identifications(ProfileElementSequence.from_der(rebuilt)),
            self._identifications(source),
            "PE header identification numbering was not preserved",
        )

    def test_renumbering_still_repairs_what_authoring_breaks(self) -> None:
        """Preserving valid numbering must not stop invalid numbering being fixed."""

        from Tools.ProfilePackage.saip_json_codec import _identifications_are_usable

        class _Pe:
            def __init__(self, identification):
                self.header = (
                    {"identification": identification}
                    if identification is not None
                    else None
                )

        class _Seq:
            def __init__(self, identifications):
                self.pe_list = [_Pe(i) for i in identifications]

        # Preserved: an imported package, gaps and non-monotonic order intact.
        self.assertTrue(_identifications_are_usable(_Seq([2, 5, 6, 20, 19, 21])))
        self.assertTrue(_identifications_are_usable(_Seq([])))
        # Repaired: quick-add leaves a zero, and duplicates are never valid.
        self.assertFalse(_identifications_are_usable(_Seq([1, 2, 0, 4])))
        self.assertFalse(_identifications_are_usable(_Seq([1, 2, 2, 3])))
        self.assertFalse(_identifications_are_usable(_Seq([1, -1])))
