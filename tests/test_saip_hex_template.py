"""Unit tests for inline typed hex placeholder handling."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_hex_template import (
    InlinePlaceholderRecord,
    describe_inline_placeholder_hex,
    detect_inline_placeholders,
    extract_inline_placeholders_from_hex_text,
    read_sidecar,
    records_to_sidecar_payload,
    sidecar_path_for_cache,
    sidecar_payload_to_records,
    splice_literals_into_tagged_document,
    substitute_inline_placeholders,
    substitute_inline_placeholders_in_editor_json,
    write_sidecar,
)
from Tools.ProfilePackage.saip_json_codec import jsonify_document
from Tools.ProfilePackage.saip_tool import SaipToolBridge


_TELNA_STYLE_SAMPLE = (
    "A0819A800102810100821354656C6E615F494D534931305F544341322E30"
    "830A{iccid:ICCID:10}840100A5088100820084008B00"
    "A638060667810F01020106{smsc:MSISDN:5:nibble_swap}"
    "0667810F010203"
)

_MINIMAL_TLV_TEMPLATE = (
    # SEQUENCE header, length 12 bytes of body:
    "300C"
    # OCTET STRING tag 04, length 8, body = 8-byte IMSI placeholder
    "0408{imsi:IMSI:8:encode_imsi}"
    # Trailing literal tag 80 02 7F 20
    "80027F20"
)


class TestInlinePlaceholderParsing(unittest.TestCase):
    def test_detect_returns_true_for_typed_placeholder(self) -> None:
        self.assertTrue(detect_inline_placeholders("AA{imsi:IMSI:8}BB"))

    def test_detect_returns_false_for_plain_hex(self) -> None:
        self.assertFalse(detect_inline_placeholders("AABBCCDDEEFF"))

    def test_detect_ignores_ygg_simple_placeholder(self) -> None:
        # {IMSI} (the native YggdraSIM form) must NOT be picked up by the
        # typed-placeholder regex — that surface is handled elsewhere.
        self.assertFalse(detect_inline_placeholders("AA{IMSI}BB"))

    def test_substitute_produces_pure_hex(self) -> None:
        substituted, records = substitute_inline_placeholders(_TELNA_STYLE_SAMPLE)
        cleaned = substituted.replace(" ", "").replace("\n", "").upper()
        self.assertEqual(len(records), 2)
        for character in cleaned:
            self.assertIn(character, "0123456789ABCDEF")
        for record in records:
            self.assertEqual(len(record.sentinel_hex), record.byte_length * 2)
            for character in record.sentinel_hex:
                self.assertIn(character, "0123456789ABCDEF")

    def test_substitute_captures_record_fields(self) -> None:
        _substituted, records = substitute_inline_placeholders(_TELNA_STYLE_SAMPLE)
        first, second = records
        self.assertEqual(first.variable_name, "iccid")
        self.assertEqual(first.type_name, "ICCID")
        self.assertEqual(first.byte_length, 10)
        self.assertIsNone(first.modifier)
        self.assertEqual(first.literal, "{iccid:ICCID:10}")
        self.assertEqual(second.modifier, "nibble_swap")
        self.assertEqual(second.literal, "{smsc:MSISDN:5:nibble_swap}")

    def test_substitute_sentinels_unique_per_index(self) -> None:
        raw = (
            "AA{a:ICCID:10}BB{b:ICCID:10}CC{c:ICCID:10:nibble_swap}DD"
        )
        _substituted, records = substitute_inline_placeholders(raw)
        sentinels = {record.sentinel_hex for record in records}
        self.assertEqual(len(sentinels), 3)

    def test_substitute_rejects_byte_length_below_minimum(self) -> None:
        with self.assertRaises(ValueError):
            substitute_inline_placeholders("AA{tiny:FOO:1}BB")

    def test_substitute_rejects_huge_byte_length(self) -> None:
        with self.assertRaises(ValueError):
            substitute_inline_placeholders("AA{huge:FOO:99999}BB")


class TestSpliceLiteralsIntoDocument(unittest.TestCase):
    def _records_for_substitution(self, raw_text: str) -> tuple[str, list[InlinePlaceholderRecord]]:
        return substitute_inline_placeholders(raw_text)

    def test_splice_restores_literals_in_hex_tagged_leaves(self) -> None:
        substituted, records = self._records_for_substitution(_MINIMAL_TLV_TEMPLATE)
        cleaned_hex = substituted.replace(" ", "").lower()
        document = {
            "sections": {
                "mf": {
                    "ef-iccid": [
                        {"@": ["fillFileContent", {"hex": cleaned_hex}]}
                    ]
                }
            }
        }
        replacement_count = splice_literals_into_tagged_document(document, records)
        self.assertEqual(replacement_count, 1)
        rewritten_hex = document["sections"]["mf"]["ef-iccid"][0]["@"][1]["hex"]
        self.assertIn("{imsi:IMSI:8:encode_imsi}", rewritten_hex)
        self.assertNotIn(records[0].sentinel_hex.lower(), rewritten_hex.lower())

    def test_splice_is_noop_without_records(self) -> None:
        document = {"sections": {"mf": {"ef-iccid": [{"hex": "deadbeef"}]}}}
        replacement_count = splice_literals_into_tagged_document(document, [])
        self.assertEqual(replacement_count, 0)
        self.assertEqual(document["sections"]["mf"]["ef-iccid"][0]["hex"], "deadbeef")

    def test_splice_handles_legacy_tag_spelling(self) -> None:
        substituted, records = self._records_for_substitution(_MINIMAL_TLV_TEMPLATE)
        cleaned_hex = substituted.replace(" ", "").lower()
        document = {"__ygg_saip_bytes__": cleaned_hex}
        replacement_count = splice_literals_into_tagged_document(document, records)
        self.assertEqual(replacement_count, 1)
        self.assertIn("{imsi:IMSI:8:encode_imsi}", document["__ygg_saip_bytes__"])

    def test_splice_operates_on_jsonify_document_output(self) -> None:
        # Regression check: the splice MUST run after ``jsonify_document``.
        # The native decoded document carries raw ``bytes`` values, which
        # the jsonifier converts to ``{"hex": "..."}`` dicts. Splicing
        # before that conversion is a no-op and silently leaves sentinel
        # runs in the editor JSON.
        _substituted, records = self._records_for_substitution(
            "DEADBEEF{marker:PROBE:6:tail}CAFEBABE"
        )
        sentinel_bytes = bytes.fromhex(records[0].sentinel_hex)
        native_document = {
            "intro": ["probe"],
            "sections": {
                "mf": {
                    "ef-probe": [
                        ("fillFileContent", b"\xde\xad\xbe\xef" + sentinel_bytes + b"\xca\xfe\xba\xbe"),
                    ],
                },
            },
        }

        # Splice against the native tree should find nothing.
        native_hits = splice_literals_into_tagged_document(native_document, records)
        self.assertEqual(native_hits, 0)

        tagged = jsonify_document(native_document)
        tagged_hits = splice_literals_into_tagged_document(tagged, records)
        self.assertEqual(tagged_hits, 1)
        rendered = json.dumps(tagged)
        self.assertIn(records[0].literal, rendered)
        self.assertNotIn(records[0].sentinel_hex.lower(), rendered.lower())


class TestEditorSaveRoundTrip(unittest.TestCase):
    """Exercise the save pipeline de-splice / re-splice pair at the helper layer.

    The TUI save flow is:

        editor_text --substitute--> sentinelised_text --json.loads--> dict
          --dejsonify--> native --> encode DER --> decode --> jsonify
          --splice--> tagged JSON with literals restored

    These tests stand in for the DER-round-trip middle hop (no pySim) and
    verify that the literal survives the text-level substitution plus the
    tree-level splice with the newly-allocated records.
    """

    def test_literal_survives_substitute_parse_splice(self) -> None:
        editor_text = json.dumps(
            {
                "intro": ["probe"],
                "sections": {
                    "mf": {
                        "ef-probe": [
                            {
                                "@": [
                                    "fillFileContent",
                                    {"hex": "0908{marker:PROBE:6:tail}cafebabe"},
                                ]
                            }
                        ]
                    }
                },
            },
            indent=2,
        )

        substituted, records = substitute_inline_placeholders(editor_text)
        parsed = json.loads(substituted)
        self.assertEqual(len(records), 1)
        self.assertIn(records[0].sentinel_hex.lower(),
                      parsed["sections"]["mf"]["ef-probe"][0]["@"][1]["hex"].lower())

        # Simulate the round-trip through a DER decode without pySim:
        # the sentinelised hex is carried verbatim on the post-decode tree
        # because the encode/decode would round-trip the same bytes.
        post_tagged = parsed

        spliced = splice_literals_into_tagged_document(post_tagged, records)
        self.assertEqual(spliced, 1)
        out_hex = post_tagged["sections"]["mf"]["ef-probe"][0]["@"][1]["hex"]
        self.assertIn("{marker:PROBE:6:tail}", out_hex)
        self.assertNotIn(records[0].sentinel_hex.lower(), out_hex.lower())

    def test_literal_reappears_alongside_original_hex(self) -> None:
        # The placeholder sits mid-hex; the surrounding bytes must stay
        # untouched after the round-trip.
        editor_hex = "62128202412183026F{iccid:ICCID:10:nibble_swap}840100"
        editor_text = json.dumps({"hex": editor_hex})
        substituted, records = substitute_inline_placeholders(editor_text)
        parsed = json.loads(substituted)
        self.assertTrue(parsed["hex"].startswith("62128202412183026F"))
        self.assertTrue(parsed["hex"].endswith("840100"))

        splice_literals_into_tagged_document(parsed, records)
        self.assertEqual(
            parsed["hex"],
            "62128202412183026F{iccid:ICCID:10:nibble_swap}840100",
        )

    def test_no_placeholders_is_a_noop(self) -> None:
        editor_text = json.dumps({"hex": "deadbeefcafebabe"})
        substituted, records = substitute_inline_placeholders(editor_text)
        self.assertEqual(editor_text, substituted)
        self.assertEqual(records, [])
        parsed = json.loads(substituted)
        count = splice_literals_into_tagged_document(parsed, records)
        self.assertEqual(count, 0)
        self.assertEqual(parsed["hex"], "deadbeefcafebabe")

    def test_fresh_records_are_allocated_per_save(self) -> None:
        # Save-path records are generated by running the substituter on
        # the editor text at save time, independent of the load-time
        # sidecar. Two saves with the same placeholder literal produce
        # identical sentinels (deterministic per-index), so the splice
        # maps cleanly in each save without cross-save state.
        editor_text = "{probe:PROBE:4}"
        _sub_a, records_a = substitute_inline_placeholders(editor_text)
        _sub_b, records_b = substitute_inline_placeholders(editor_text)
        self.assertEqual(len(records_a), 1)
        self.assertEqual(len(records_b), 1)
        self.assertEqual(records_a[0].sentinel_hex, records_b[0].sentinel_hex)


class TestSidecarRoundTrip(unittest.TestCase):
    def test_records_to_payload_and_back_round_trips(self) -> None:
        _substituted, records = substitute_inline_placeholders(_TELNA_STYLE_SAMPLE)
        payload = records_to_sidecar_payload(records)
        restored = sidecar_payload_to_records(payload)
        self.assertEqual(len(restored), len(records))
        for original, restored_record in zip(records, restored):
            self.assertEqual(original.index, restored_record.index)
            self.assertEqual(original.literal, restored_record.literal)
            self.assertEqual(original.byte_length, restored_record.byte_length)
            self.assertEqual(original.modifier, restored_record.modifier)
            self.assertEqual(original.sentinel_hex, restored_record.sentinel_hex)

    def test_sidecar_file_round_trips(self) -> None:
        _substituted, records = substitute_inline_placeholders(_TELNA_STYLE_SAMPLE)
        with tempfile.TemporaryDirectory() as tmp_root:
            sidecar = Path(tmp_root) / "payload.placeholders.json"
            write_sidecar(sidecar, records)
            loaded = read_sidecar(sidecar)
        self.assertEqual(len(loaded), len(records))
        self.assertEqual(loaded[0].variable_name, records[0].variable_name)

    def test_sidecar_path_for_cache_appends_suffix(self) -> None:
        sidecar = sidecar_path_for_cache(Path("/tmp/some-cache-abc123.der"))
        self.assertTrue(str(sidecar).endswith(".placeholders.json"))

    def test_sidecar_payload_rejects_malformed_shape(self) -> None:
        with self.assertRaises(ValueError):
            sidecar_payload_to_records({"placeholders": "not a list"})
        with self.assertRaises(ValueError):
            sidecar_payload_to_records({"placeholders": [{"index": 0}]})


class TestSubstituteInlineInEditorJson(unittest.TestCase):
    """Exercise the lint-harness pre-substitution helper.

    ``lint_profile_json_buffer`` calls
    :func:`substitute_inline_placeholders_in_editor_json` so that
    ``bytes.fromhex`` never sees a placeholder literal. The paths it
    returns are fed into the linter as ``placeholder_paths`` — the
    FAIL/WARN → INFO downgrade then makes sure a template-bearing
    buffer renders softer than a genuinely broken profile.
    """

    def test_no_placeholders_returns_input_unchanged(self) -> None:
        editor_text = json.dumps({"sections": {"mf": {"ef": [{"hex": "deadbeef"}]}}})
        out_text, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(editor_text, out_text)
        self.assertEqual(paths, frozenset())
        self.assertEqual(count, 0)

    def test_invalid_json_returns_input_unchanged(self) -> None:
        editor_text = "{ this is not valid json {probe:PROBE:2} "
        out_text, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(editor_text, out_text)
        self.assertEqual(paths, frozenset())
        self.assertEqual(count, 0)

    def test_captures_dotted_path_and_substitutes_hex_leaf(self) -> None:
        editor_text = json.dumps(
            {
                "intro": ["probe"],
                "sections": {
                    "mf": {
                        "ef-iccid": [
                            {"@": ["fillFileContent", {"hex": "0908{iccid:ICCID:10:nibble_swap}80027F20"}]}
                        ]
                    }
                },
            }
        )
        out_text, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(count, 1)
        self.assertEqual(len(paths), 1)
        # Path format mirrors the lint engine's walker: the ``sections.``
        # wrapper is elided and the dotted path points at the parent of
        # the tagged ``hex`` leaf (so prefix matching covers every nested
        # finding rooted at this scaffolding).
        only_path = next(iter(paths))
        self.assertTrue(only_path.startswith("mf.ef-iccid"))
        self.assertIn("@", only_path)
        rewritten = json.loads(out_text)
        hex_text = rewritten["sections"]["mf"]["ef-iccid"][0]["@"][1]["hex"]
        self.assertNotIn("{iccid:ICCID:10:nibble_swap}", hex_text)
        # Length preserved (the placeholder occupied 10 bytes = 20 hex chars).
        self.assertEqual(len(hex_text), len("0908") + 20 + len("80027F20"))

    def test_rewrites_legacy_bytes_tag(self) -> None:
        editor_text = json.dumps(
            {
                "sections": {
                    "usim": {
                        "ef-loci": [
                            {"__ygg_saip_bytes__": "AABB{marker:PROBE:4}CCDD"}
                        ]
                    }
                }
            }
        )
        _out, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(count, 1)
        only_path = next(iter(paths))
        self.assertTrue(only_path.startswith("usim.ef-loci"))

    def test_multiple_leaves_report_distinct_paths(self) -> None:
        editor_text = json.dumps(
            {
                "sections": {
                    "mf": {
                        "ef-iccid": [
                            {"@": ["fillFileContent", {"hex": "{iccid:ICCID:10}"}]}
                        ],
                        "ef-imsi": [
                            {"@": ["fillFileContent", {"hex": "{imsi:IMSI:8}"}]}
                        ],
                    }
                }
            }
        )
        _out, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(count, 2)
        self.assertEqual(len(paths), 2)

    def test_placeholder_outside_sections_is_ignored(self) -> None:
        editor_text = json.dumps(
            {
                "intro": ["note: {not:a:hex:1}"],
                "sections": {"mf": {"ef-x": [{"hex": "deadbeef"}]}},
            }
        )
        out_text, paths, count = substitute_inline_placeholders_in_editor_json(editor_text)
        self.assertEqual(editor_text, out_text)
        self.assertEqual(paths, frozenset())
        self.assertEqual(count, 0)


class TestDescribeInlinePlaceholderHex(unittest.TestCase):
    """Back the read-only decoded view for inline typed placeholders."""

    def test_extract_reports_every_match_with_offsets(self) -> None:
        hex_text = "0908{iccid:ICCID:10:nibble_swap}80{x:Y:3}FF"
        entries = extract_inline_placeholders_from_hex_text(hex_text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["variable"], "iccid")
        self.assertEqual(entries[0]["byte_length"], 10)
        self.assertEqual(entries[0]["modifier"], "nibble_swap")
        self.assertEqual(
            hex_text[entries[0]["start"]:entries[0]["end"]],
            "{iccid:ICCID:10:nibble_swap}",
        )
        self.assertEqual(entries[1]["variable"], "x")
        self.assertIsNone(entries[1]["modifier"])

    def test_describe_returns_none_when_no_placeholders(self) -> None:
        self.assertIsNone(describe_inline_placeholder_hex("DEADBEEF"))
        self.assertIsNone(describe_inline_placeholder_hex(""))
        self.assertIsNone(describe_inline_placeholder_hex(None))  # type: ignore[arg-type]

    def test_describe_builds_segmented_payload(self) -> None:
        hex_text = "0908{iccid:ICCID:10:nibble_swap}80027F20"
        payload = describe_inline_placeholder_hex(
            hex_text,
            field_name="fillFileContent",
            ef_key="ef-iccid",
        )
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["field"], "fillFileContent")
        self.assertEqual(payload["ef"], "ef-iccid")
        self.assertEqual(payload["hex_with_literals"], hex_text)
        self.assertEqual(len(payload["placeholders"]), 1)
        only_ph = payload["placeholders"][0]
        self.assertEqual(only_ph["literal"], "{iccid:ICCID:10:nibble_swap}")
        self.assertEqual(only_ph["variable"], "iccid")
        self.assertEqual(only_ph["type"], "ICCID")
        self.assertEqual(only_ph["byte_length"], 10)
        self.assertEqual(only_ph["modifier"], "nibble_swap")

        segments = payload["segments"]
        self.assertEqual(len(segments), 3)
        self.assertEqual(segments[0], {"kind": "hex", "text": "0908"})
        self.assertEqual(segments[1]["kind"], "placeholder")
        self.assertEqual(segments[1]["literal"], "{iccid:ICCID:10:nibble_swap}")
        self.assertEqual(segments[2], {"kind": "hex", "text": "80027F20"})

    def test_describe_handles_leading_and_trailing_placeholders(self) -> None:
        payload = describe_inline_placeholder_hex("{head:H:2}DEAD{tail:T:2}")
        assert payload is not None
        segments = payload["segments"]
        self.assertEqual(segments[0]["kind"], "placeholder")
        self.assertEqual(segments[0]["variable"], "head")
        self.assertEqual(segments[1], {"kind": "hex", "text": "DEAD"})
        self.assertEqual(segments[2]["kind"], "placeholder")
        self.assertEqual(segments[2]["variable"], "tail")

    def test_describe_omits_modifier_when_absent(self) -> None:
        payload = describe_inline_placeholder_hex("AA{var:T:3}BB")
        assert payload is not None
        only_ph = payload["placeholders"][0]
        self.assertNotIn("modifier", only_ph)


class TestInspectWalkerEmitsPlaceholderBlock(unittest.TestCase):
    """Verify the ASN.1 walker no longer swallows placeholder-bearing fields.

    Before this sweep, ``_walk`` bailed silently when
    ``_hex_from_tagged_bytes`` rejected the leaf content (which it does
    for any tagged hex carrying a ``{var:TYPE:N[:mod]}`` literal), so
    the INSPECT pane rendered no entry at all for template-scaffolded
    fields. The walker now emits a dedicated ``Field semantics`` block
    so the operator still gets a field-level record.
    """

    def test_placeholder_field_emits_field_semantics_block(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            build_inspector_report_for_subtree,
        )

        subtree = {
            "ef-iccid": [
                {
                    "@": [
                        "fillFileContent",
                        {"hex": "0908{iccid:ICCID:10:nibble_swap}80027F20"},
                    ]
                }
            ]
        }
        report = build_inspector_report_for_subtree(
            subtree,
            "mf",
            last_ef_key="ef-iccid",
        )
        self.assertIn("Field semantics", report)
        self.assertIn("Inline template placeholder", report)
        self.assertIn("{iccid:ICCID:10:nibble_swap}", report)
        self.assertIn("byte_length", report)
        self.assertIn("16", report)

    def test_plain_hex_field_unchanged(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            build_inspector_report_for_subtree,
        )

        subtree = {
            "ef-iccid": [
                {"@": ["fillFileContent", {"hex": "98103210325476981032"}]}
            ]
        }
        report = build_inspector_report_for_subtree(
            subtree,
            "mf",
            last_ef_key="ef-iccid",
        )
        self.assertNotIn("Inline template placeholder", report)

    def test_placeholder_only_field_no_surrounding_hex(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            build_inspector_report_for_subtree,
        )

        subtree = {
            "ef-iccid": [
                {"@": ["fillFileContent", {"hex": "{iccid:ICCID:10:nibble_swap}"}]}
            ]
        }
        report = build_inspector_report_for_subtree(
            subtree,
            "mf",
            last_ef_key="ef-iccid",
        )
        self.assertIn("Inline template placeholder", report)
        self.assertIn("1 inline placeholder", report)

    def test_multiple_placeholders_counted(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            build_inspector_report_for_subtree,
        )

        subtree = {
            "ef-imsi": [
                {
                    "@": [
                        "fillFileContent",
                        {"hex": "08{a:IMSI:8}FF{b:MSISDN:4}"},
                    ]
                }
            ]
        }
        report = build_inspector_report_for_subtree(
            subtree,
            "mf",
            last_ef_key="ef-imsi",
        )
        self.assertIn("2 inline placeholders", report)


class TestLintDowngradeForInlinePlaceholders(unittest.TestCase):
    """End-to-end check that the lint harness softens placeholder findings."""

    def test_lint_buffer_with_inline_placeholders_downgrades_findings(self) -> None:
        from Tools.ProfilePackage.saip_tui_lint import lint_profile_json_buffer

        editor_text = json.dumps(
            {
                "intro": ["probe"],
                "sections": {
                    "mf": {
                        "ef-iccid": [
                            {"@": ["fillFileContent", {"hex": "{iccid:ICCID:10:nibble_swap}"}]}
                        ]
                    }
                },
            }
        )
        outcome = lint_profile_json_buffer(editor_text, "inline-probe", strict=False)
        self.assertIsNone(outcome.parse_error)
        self.assertEqual(outcome.inline_placeholder_count, 1)
        self.assertEqual(len(outcome.inline_placeholder_paths), 1)
        only_path = next(iter(outcome.inline_placeholder_paths))
        self.assertTrue(only_path.startswith("mf.ef-iccid"))
        self.assertIn(only_path, outcome.placeholder_paths)


class TestPrepareInputForTool(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        cls._bridge = SaipToolBridge(cls.workspace_root)

    def test_plain_hex_input_still_writes_der_and_no_sidecar(self) -> None:
        resolved = self._bridge.resolve_input_path(
            "Tools/ProfilePackage/profile/reference_test_profile.txt",
            must_exist=True,
        )
        cache_path = self._bridge._prepare_input_for_tool(resolved)
        self.assertTrue(cache_path.exists())
        sidecar = sidecar_path_for_cache(cache_path)
        self.assertFalse(sidecar.exists())

    def test_inline_placeholder_input_writes_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_root:
            source = self.workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
            staging = Path(tmp_root) / "inline_placeholder_probe.txt"
            base_hex = source.read_text(encoding="utf-8").strip()
            # Swap the last 4 hex chars (2 bytes) for a typed placeholder
            # declaring the same 2-byte length so the cached DER keeps
            # its original size after substitution. The test does not
            # depend on pySim decoding the result; it only checks the
            # sidecar + cache side-effects of ``_prepare_input_for_tool``.
            templated = base_hex[:-4] + "{probe:TEST:2}"
            staging.write_text(templated, encoding="utf-8")

            bridge = SaipToolBridge(self.workspace_root)
            cache_path = bridge._prepare_input_for_tool(staging)
            sidecar = sidecar_path_for_cache(cache_path)

            self.assertTrue(cache_path.exists())
            self.assertTrue(sidecar.exists())

            sidecar_payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(sidecar_payload["version"], 1)
            self.assertEqual(len(sidecar_payload["placeholders"]), 1)
            record = sidecar_payload["placeholders"][0]
            self.assertEqual(record["variable"], "probe")
            self.assertEqual(record["type"], "TEST")
            self.assertEqual(record["byte_length"], 2)
            self.assertEqual(record["literal"], "{probe:TEST:2}")

            cached_bytes = cache_path.read_bytes()
            self.assertEqual(len(cached_bytes), len(base_hex) // 2)

    def test_native_style_placeholder_text_gets_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_root:
            staging = Path(tmp_root) / "native_placeholder_probe.txt"
            staging.write_text("AABB{ICCID}CCDD", encoding="utf-8")
            bridge = SaipToolBridge(self.workspace_root)
            with self.assertRaises(ValueError) as ctx:
                bridge._prepare_input_for_tool(staging)
            self.assertIn("APPLY-TEMPLATE", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
