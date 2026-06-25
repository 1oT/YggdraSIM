"""Tests for the token sidecar module and derived-length placeholders.

Covers:

- :mod:`Tools.ProfilePackage.saip_token_sidecar` I/O and validation helpers.
- ``{#NAME}`` / ``[#NAME]`` derived-length token resolution in
  :class:`Tools.ProfilePackage.saip_json_codec.TokenExpansionContext`.
- Placeholder-name extraction and placeholder-path collection when
  derived-length companions are present in a template document.
"""

import copy
import json
import pathlib
import tempfile
import unittest

from Tools.ProfilePackage.saip_json_codec import (
    TokenExpansionContext,
    _encode_ber_tlv_length,
    parse_editor_json_template_aware,
)
from Tools.ProfilePackage.saip_profile_template import (
    extract_template_placeholder_names,
)
from Tools.ProfilePackage.saip_token_sidecar import (
    TokenSidecarError,
    build_sidecar_from_template,
    candidate_sidecar_paths,
    count_token_references,
    default_sidecar_path_for,
    first_available_sidecar,
    list_token_definitions,
    load_sidecar,
    merge_sidecar_into_template,
    parse_token_value_argument,
    remove_token_definition,
    rename_token_in_template,
    find_unmigrated_length_candidates,
    read_token_defs_from_file,
    retokenise_template_lengths,
    set_token_definition,
    template_has_unresolved_placeholders,
    validate_sidecar_document,
    write_sidecar,
)


class BerTlvLengthTests(unittest.TestCase):
    """``_encode_ber_tlv_length`` boundary behaviour (ISO 7816-4)."""

    def test_short_form_boundaries(self) -> None:
        self.assertEqual(_encode_ber_tlv_length(0), b"\x00")
        self.assertEqual(_encode_ber_tlv_length(1), b"\x01")
        self.assertEqual(_encode_ber_tlv_length(0x7F), b"\x7f")

    def test_long_form_single_octet(self) -> None:
        self.assertEqual(_encode_ber_tlv_length(0x80), bytes.fromhex("8180"))
        self.assertEqual(_encode_ber_tlv_length(0xFF), bytes.fromhex("81FF"))

    def test_long_form_multi_octet(self) -> None:
        self.assertEqual(_encode_ber_tlv_length(0x0100), bytes.fromhex("820100"))
        self.assertEqual(_encode_ber_tlv_length(0xFFFF), bytes.fromhex("82FFFF"))
        self.assertEqual(_encode_ber_tlv_length(0x010000), bytes.fromhex("83010000"))

    def test_negative_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _encode_ber_tlv_length(-1)


class DerivedLengthTokenTests(unittest.TestCase):
    """``{#NAME}`` / ``[#NAME]`` companion token semantics."""

    def test_short_form_matches_literal_length_byte(self) -> None:
        defs = {"ICCID": {"hex": "89881111111111111112"}}
        ctx = TokenExpansionContext(defs, "brace")
        self.assertEqual(
            ctx.expand_mixed_hex("0A{ICCID}"),
            ctx.expand_mixed_hex("{#ICCID}{ICCID}"),
        )

    def test_long_form_length_prefix(self) -> None:
        ctx = TokenExpansionContext(
            {"BIG": {"zero_len": 200}},
            "brace",
        )
        out = ctx.expand_mixed_hex("{#BIG}{BIG}")
        self.assertEqual(out[:2], bytes.fromhex("81C8"))
        self.assertEqual(len(out), 2 + 200)

    def test_three_octet_long_form(self) -> None:
        ctx = TokenExpansionContext(
            {"HUGE": {"zero_len": 70000}},
            "brace",
        )
        out = ctx.expand_mixed_hex("{#HUGE}{HUGE}")
        self.assertEqual(out[:4], bytes.fromhex("83011170"))
        self.assertEqual(len(out), 4 + 70000)

    def test_bracket_style_supports_companion(self) -> None:
        ctx = TokenExpansionContext(
            {"ICCID": {"hex": "89881111111111111112"}},
            "bracket",
        )
        out = ctx.expand_mixed_hex("5F[#ICCID][ICCID]")
        self.assertEqual(
            out,
            bytes.fromhex("5F0A89881111111111111112"),
        )

    def test_undefined_companion_tolerated(self) -> None:
        ctx = TokenExpansionContext({}, "brace", tolerate_undefined=True)
        out = ctx.expand_mixed_hex("{#MISSING}{MISSING}")
        self.assertEqual(out, bytes([0x00]))
        self.assertIn("MISSING", ctx.undefined_tokens)

    def test_undefined_companion_strict_raises(self) -> None:
        ctx = TokenExpansionContext({}, "brace")
        with self.assertRaises(ValueError) as guard:
            ctx.expand_mixed_hex("{#MISSING}")
        self.assertIn("derived-length", str(guard.exception).lower())

    def test_mixed_literal_and_companion(self) -> None:
        ctx = TokenExpansionContext(
            {"IMSI": {"hex": "08" + "99" * 7}},
            "brace",
        )
        out = ctx.expand_mixed_hex("5F{#IMSI}{IMSI}FF")
        self.assertEqual(
            out,
            bytes.fromhex("5F08") + bytes.fromhex("08" + "99" * 7) + bytes.fromhex("FF"),
        )


class PlaceholderNameExtractionTests(unittest.TestCase):
    """``extract_template_placeholder_names`` treats ``#`` companions as dependencies."""

    def test_companion_tokens_recognised(self) -> None:
        doc = {
            "sections": {
                "header": {"iccid": {"hex": "{#ICCID}{ICCID}"}},
                "usim": {
                    "ef-imsi": {
                        "@": [["fillFileContent", {"hex": "[#IMSI][IMSI]"}]],
                    },
                },
            },
        }
        names = extract_template_placeholder_names(doc)
        self.assertIn("ICCID", names)
        self.assertIn("IMSI", names)

    def test_template_aware_parse_reports_companion_paths(self) -> None:
        doc = {
            "intro": [],
            "sections": {
                "header": {"iccid": {"hex": "{#ICCID}{ICCID}"}},
            },
        }
        _restored, paths, undefined = parse_editor_json_template_aware(
            json.dumps(doc)
        )
        self.assertIn("ICCID", undefined)
        self.assertTrue(
            any(
                "header.iccid" == entry or entry.startswith("header.iccid")
                for entry in paths
            ),
            f"expected header.iccid path in {paths!r}",
        )


class TokenSidecarValidationTests(unittest.TestCase):
    """``validate_sidecar_document`` schema enforcement."""

    def test_minimal_valid_payload(self) -> None:
        payload = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {"ICCID": "00" * 10},
        }
        validate_sidecar_document(payload)

    def test_non_object_rejected(self) -> None:
        with self.assertRaises(TokenSidecarError):
            validate_sidecar_document([])  # type: ignore[arg-type]

    def test_style_required_to_be_known(self) -> None:
        with self.assertRaises(TokenSidecarError):
            validate_sidecar_document(
                {
                    "__ygg_placeholder_style__": "arbitrary",
                    "__ygg_token_defs__": {},
                }
            )

    def test_defs_must_be_dict(self) -> None:
        with self.assertRaises(TokenSidecarError):
            validate_sidecar_document(
                {
                    "__ygg_placeholder_style__": "brace",
                    "__ygg_token_defs__": "nope",
                }
            )


class TokenSidecarIOTests(unittest.TestCase):
    """Round-trip write/load/merge cycle for ``*.tokens.json`` sidecars."""

    def setUp(self) -> None:
        self._tmp = pathlib.Path(tempfile.mkdtemp())
        self._template_path = self._tmp / "profile.json"
        self._sidecar_path = default_sidecar_path_for(self._template_path)

    def test_default_sidecar_path_matches_stem(self) -> None:
        self.assertEqual(
            self._sidecar_path.name,
            "profile.tokens.json",
        )
        candidates = [p.name for p in candidate_sidecar_paths(self._template_path)]
        self.assertIn("profile.tokens.json", candidates)
        self.assertIn("profile.json.tokens.json", candidates)
        self.assertIn("tokens.json", candidates)

    def test_roundtrip_build_write_load(self) -> None:
        template = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "08" + "99" * 7,
            },
            "sections": {
                "header": {"iccid": {"hex": "{ICCID}"}},
            },
        }
        payload = build_sidecar_from_template(
            template,
            source_label=self._template_path.name,
        )
        self.assertEqual(
            sorted(payload["__ygg_token_defs__"].keys()),
            ["ICCID", "IMSI"],
        )
        write_sidecar(
            self._sidecar_path,
            style=payload["__ygg_placeholder_style__"],
            token_defs=payload["__ygg_token_defs__"],
            source_label=self._template_path.name,
        )
        disk_payload = json.loads(self._sidecar_path.read_text(encoding="utf-8"))
        self.assertEqual(
            disk_payload["__ygg_placeholder_style__"],
            "brace",
        )
        self.assertEqual(
            sorted(disk_payload["__ygg_token_defs__"].keys()),
            ["ICCID", "IMSI"],
        )
        loaded = load_sidecar(self._sidecar_path)
        self.assertEqual(
            loaded["__ygg_token_defs__"]["ICCID"],
            {"hex": "89881111111111111112"},
        )

    def test_merge_additive_preserves_existing_defs(self) -> None:
        sidecar = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "08" + "99" * 7,
            },
        }
        template = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "DEADBEEFCAFED00DBABE"},
            },
            "sections": {"header": {"iccid": {"hex": "{ICCID}"}}},
        }
        summaries = merge_sidecar_into_template(
            template,
            sidecar,
            overwrite=False,
        )
        self.assertEqual(
            template["__ygg_token_defs__"]["ICCID"],
            {"hex": "DEADBEEFCAFED00DBABE"},
        )
        self.assertEqual(
            template["__ygg_token_defs__"]["IMSI"],
            "08" + "99" * 7,
        )
        self.assertTrue(
            any("added defs" in summary for summary in summaries),
            f"expected 'added defs' note in {summaries!r}",
        )

    def test_merge_overwrite_replaces_existing_defs(self) -> None:
        sidecar = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
            },
        }
        template = {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "DEADBEEFCAFED00DBABE"},
            },
            "sections": {},
        }
        merge_sidecar_into_template(template, sidecar, overwrite=True)
        self.assertEqual(
            template["__ygg_token_defs__"]["ICCID"],
            {"hex": "89881111111111111112"},
        )

    def test_template_has_unresolved_placeholders_reports_names(self) -> None:
        template = {
            "sections": {
                "header": {"iccid": {"hex": "{ICCID}"}},
                "usim": {"ef-imsi": {"@": [["fillFileContent", {"hex": "{IMSI}"}]]}},
            },
        }
        unresolved = template_has_unresolved_placeholders(template)
        self.assertEqual(sorted(unresolved), ["ICCID", "IMSI"])

    def test_first_available_sidecar_returns_none_when_missing(self) -> None:
        self.assertIsNone(first_available_sidecar(self._template_path))

    def test_first_available_sidecar_locates_default(self) -> None:
        self._sidecar_path.write_text(
            json.dumps(
                {
                    "__ygg_placeholder_style__": "brace",
                    "__ygg_token_defs__": {},
                }
            ),
            encoding="utf-8",
        )
        found = first_available_sidecar(self._template_path)
        self.assertEqual(found, self._sidecar_path)


class TokenListEditTests(unittest.TestCase):
    """``list_token_definitions`` / ``set_token_definition`` / ``remove_token_definition``."""

    def test_list_returns_deep_copy(self) -> None:
        doc = {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
            },
        }
        listed = list_token_definitions(doc)
        listed["ICCID"]["hex"] = "TOUCHED"
        self.assertEqual(
            doc["__ygg_token_defs__"]["ICCID"]["hex"],
            "89881111111111111112",
        )

    def test_set_creates_when_missing(self) -> None:
        doc: dict = {}
        created, previous = set_token_definition(doc, "ICCID", "00" * 10)
        self.assertTrue(created)
        self.assertIsNone(previous)
        self.assertIn("ICCID", doc["__ygg_token_defs__"])

    def test_set_overwrite_false_preserves_existing(self) -> None:
        doc = {
            "__ygg_token_defs__": {"ICCID": {"hex": "AA"}},
        }
        created, previous = set_token_definition(
            doc,
            "ICCID",
            "BB",
            overwrite=False,
        )
        self.assertFalse(created)
        self.assertEqual(previous, {"hex": "AA"})
        self.assertEqual(doc["__ygg_token_defs__"]["ICCID"], {"hex": "AA"})

    def test_set_overwrite_true_returns_previous(self) -> None:
        doc = {"__ygg_token_defs__": {"ICCID": "AA"}}
        created, previous = set_token_definition(doc, "ICCID", "BB")
        self.assertFalse(created)
        self.assertEqual(previous, "AA")
        self.assertEqual(doc["__ygg_token_defs__"]["ICCID"], "BB")

    def test_set_rejects_invalid_name(self) -> None:
        doc: dict = {}
        with self.assertRaises(TokenSidecarError):
            set_token_definition(doc, "123bad", "AA")

    def test_remove_returns_previous(self) -> None:
        doc = {"__ygg_token_defs__": {"ICCID": {"hex": "AA"}}}
        removed = remove_token_definition(doc, "ICCID")
        self.assertEqual(removed, {"hex": "AA"})
        self.assertEqual(doc["__ygg_token_defs__"], {})

    def test_remove_missing_returns_none(self) -> None:
        doc = {"__ygg_token_defs__": {}}
        self.assertIsNone(remove_token_definition(doc, "NOPE"))

    def test_parse_token_value_hex_string(self) -> None:
        self.assertEqual(
            parse_token_value_argument("89 46 11"),
            "894611",
        )

    def test_parse_token_value_json_object(self) -> None:
        self.assertEqual(
            parse_token_value_argument('{"zero_len": 10}'),
            {"zero_len": 10},
        )

    def test_parse_token_value_rejects_empty(self) -> None:
        with self.assertRaises(TokenSidecarError):
            parse_token_value_argument("   ")

    def test_parse_token_value_rejects_odd_hex(self) -> None:
        with self.assertRaises(TokenSidecarError):
            parse_token_value_argument("ABC")


class TokenReferenceCountTests(unittest.TestCase):
    """``count_token_references`` traverses tagged-bytes hex fields only."""

    def test_counts_content_and_length_refs(self) -> None:
        doc = {
            "__ygg_token_defs__": {"ICCID": "AA" * 10},
            "sections": {
                "a": {"x": {"hex": "{ICCID}{#ICCID}"}},
                "b": {"y": {"hex": "5F{#ICCID}{ICCID}AA"}},
                "c": {"z": {"hex": "nothing"}},
            },
        }
        counts = count_token_references(doc, "ICCID")
        self.assertEqual(counts["content"], 2)
        self.assertEqual(counts["length"], 2)
        self.assertEqual(counts["total"], 4)

    def test_zero_when_absent(self) -> None:
        doc = {"__ygg_token_defs__": {}, "sections": {"a": {"x": {"hex": "AA"}}}}
        self.assertEqual(count_token_references(doc, "ICCID")["total"], 0)

    def test_bracket_style(self) -> None:
        doc = {
            "__ygg_placeholder_style__": "bracket",
            "__ygg_token_defs__": {"A": "00"},
            "sections": {"a": {"x": {"hex": "[A][#A]"}}},
        }
        counts = count_token_references(doc, "A")
        self.assertEqual(counts["total"], 2)


class RenameTokenTests(unittest.TestCase):
    """``rename_token_in_template`` updates defs and references atomically."""

    def test_rename_rewrites_all_references(self) -> None:
        doc = {
            "__ygg_token_defs__": {"OLD": "AA"},
            "sections": {
                "a": {"x": {"hex": "{OLD}{#OLD}"}},
                "b": {"y": {"hex": "5F{#OLD}{OLD}AA"}},
            },
        }
        summary = rename_token_in_template(doc, "OLD", "NEW")
        self.assertTrue(summary["renamed_def"])
        self.assertEqual(summary["content_refs"], 2)
        self.assertEqual(summary["length_refs"], 2)
        self.assertEqual(
            doc["sections"]["a"]["x"]["hex"],
            "{NEW}{#NEW}",
        )
        self.assertEqual(
            doc["sections"]["b"]["y"]["hex"],
            "5F{#NEW}{NEW}AA",
        )
        self.assertEqual(list(doc["__ygg_token_defs__"].keys()), ["NEW"])

    def test_rename_preserves_references_when_disabled(self) -> None:
        doc = {
            "__ygg_token_defs__": {"OLD": "AA"},
            "sections": {"a": {"x": {"hex": "{OLD}"}}},
        }
        summary = rename_token_in_template(
            doc,
            "OLD",
            "NEW",
            rewrite_references=False,
        )
        self.assertTrue(summary["renamed_def"])
        self.assertEqual(summary["content_refs"], 0)
        self.assertEqual(doc["sections"]["a"]["x"]["hex"], "{OLD}")
        self.assertEqual(list(doc["__ygg_token_defs__"].keys()), ["NEW"])

    def test_rename_collision_raises(self) -> None:
        doc = {"__ygg_token_defs__": {"OLD": "AA", "NEW": "BB"}, "sections": {}}
        with self.assertRaises(TokenSidecarError) as guard:
            rename_token_in_template(doc, "OLD", "NEW")
        self.assertIn("already exists", str(guard.exception))

    def test_rename_to_same_name_is_noop(self) -> None:
        doc = {
            "__ygg_token_defs__": {"A": "AA"},
            "sections": {"a": {"x": {"hex": "{A}"}}},
        }
        summary = rename_token_in_template(doc, "A", "A")
        self.assertFalse(summary["renamed_def"])
        self.assertEqual(summary["content_refs"], 0)
        self.assertEqual(summary["length_refs"], 0)

    def test_rename_when_name_absent_is_noop(self) -> None:
        doc = {
            "__ygg_token_defs__": {"KEEP": "AA"},
            "sections": {"a": {"x": {"hex": "{KEEP}"}}},
        }
        summary = rename_token_in_template(doc, "GONE", "OTHER")
        self.assertFalse(summary["renamed_def"])
        self.assertEqual(doc["sections"]["a"]["x"]["hex"], "{KEEP}")


class RetokeniseLengthsTests(unittest.TestCase):
    """``retokenise_template_lengths`` rewrites ``<length>{NAME}`` pairs."""

    def _base_doc(self) -> dict:
        return {
            "__ygg_placeholder_style__": "brace",
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": {"hex": "08" + "99" * 7},
                "BIG": {"zero_len": 200},
            },
            "sections": {},
        }

    def test_short_form_match_rewrites(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {
            "header": {"iccid": {"hex": "0A{ICCID}"}},
        }
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 1)
        self.assertEqual(
            doc["sections"]["header"]["iccid"]["hex"],
            "{#ICCID}{ICCID}",
        )

    def test_long_form_match_rewrites(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {"big": {"x": {"hex": "81C8{BIG}"}}}
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 1)
        self.assertEqual(
            doc["sections"]["big"]["x"]["hex"],
            "{#BIG}{BIG}",
        )

    def test_mismatched_prefix_skipped(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {"bad": {"x": {"hex": "08{ICCID}"}}}
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 0)
        self.assertEqual(doc["sections"]["bad"]["x"]["hex"], "08{ICCID}")
        self.assertEqual(len(report["skipped"]), 1)
        self.assertIn("does not end with", report["skipped"][0]["reason"])

    def test_already_derived_is_left_alone(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {"ok": {"x": {"hex": "{#ICCID}{ICCID}"}}}
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 0)
        self.assertEqual(
            doc["sections"]["ok"]["x"]["hex"],
            "{#ICCID}{ICCID}",
        )

    def test_preserves_preceding_literal_bytes(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {"p": {"x": {"hex": "AABB0A{ICCID}"}}}
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 1)
        self.assertEqual(
            doc["sections"]["p"]["x"]["hex"],
            "AABB{#ICCID}{ICCID}",
        )

    def test_unknown_token_skipped(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {"u": {"x": {"hex": "05{UNKNOWN}"}}}
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 0)
        self.assertEqual(doc["sections"]["u"]["x"]["hex"], "05{UNKNOWN}")
        self.assertEqual(report["skipped"][0]["token"], "UNKNOWN")

    def test_semantic_bytes_preserved(self) -> None:
        doc = self._base_doc()
        doc["sections"] = {
            "header": {"iccid": {"hex": "0A{ICCID}"}},
            "big": {"x": {"hex": "AA81C8{BIG}FF"}},
        }
        ctx_before = TokenExpansionContext(doc["__ygg_token_defs__"], "brace")
        before_iccid = ctx_before.expand_mixed_hex(
            doc["sections"]["header"]["iccid"]["hex"]
        )
        before_big = ctx_before.expand_mixed_hex(
            doc["sections"]["big"]["x"]["hex"]
        )
        retokenise_template_lengths(doc)
        ctx_after = TokenExpansionContext(doc["__ygg_token_defs__"], "brace")
        after_iccid = ctx_after.expand_mixed_hex(
            doc["sections"]["header"]["iccid"]["hex"]
        )
        after_big = ctx_after.expand_mixed_hex(
            doc["sections"]["big"]["x"]["hex"]
        )
        self.assertEqual(before_iccid, after_iccid)
        self.assertEqual(before_big, after_big)


class RetokeniseOnlyTokensTests(unittest.TestCase):
    """``retokenise_template_lengths(only_tokens=...)`` scoping behaviour."""

    def _base_doc(self) -> dict[str, object]:
        return {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "AABB",
            },
            "__ygg_placeholder_style__": "brace",
            "sections": {
                "a": {"x": {"hex": "0A{ICCID}"}},
                "b": {"x": {"hex": "02{IMSI}"}},
            },
        }

    def test_only_rewrites_requested_token(self) -> None:
        doc = self._base_doc()
        report = retokenise_template_lengths(doc, only_tokens={"IMSI"})
        self.assertEqual(report["rewrites"], 1)
        self.assertEqual(doc["sections"]["a"]["x"]["hex"], "0A{ICCID}")
        self.assertEqual(
            doc["sections"]["b"]["x"]["hex"], "{#IMSI}{IMSI}"
        )

    def test_unscoped_default_rewrites_everything(self) -> None:
        doc = self._base_doc()
        report = retokenise_template_lengths(doc)
        self.assertEqual(report["rewrites"], 2)

    def test_empty_scope_rewrites_nothing(self) -> None:
        doc = self._base_doc()
        report = retokenise_template_lengths(doc, only_tokens=set())
        self.assertEqual(report["rewrites"], 0)
        self.assertEqual(doc["sections"]["a"]["x"]["hex"], "0A{ICCID}")
        self.assertEqual(doc["sections"]["b"]["x"]["hex"], "02{IMSI}")

    def test_scope_with_unknown_token_is_noop(self) -> None:
        doc = self._base_doc()
        report = retokenise_template_lengths(doc, only_tokens={"UNKNOWN"})
        self.assertEqual(report["rewrites"], 0)


class FindUnmigratedLengthCandidatesTests(unittest.TestCase):
    """``find_unmigrated_length_candidates`` discovery (non-mutating)."""

    def _base_doc(self) -> dict[str, object]:
        return {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "AABB",
            },
            "__ygg_placeholder_style__": "brace",
            "sections": {
                "a": {"x": {"hex": "0A{ICCID}"}},
                "b": {"x": {"hex": "02{IMSI}"}},
                "c": {"x": {"hex": "{#IMSI}{IMSI}"}},
            },
        }

    def test_finds_single_candidate(self) -> None:
        hits = find_unmigrated_length_candidates(self._base_doc(), "IMSI")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["path"], "sections.b.x")
        self.assertEqual(hits[0]["prefix"], "02")
        self.assertEqual(hits[0]["needed"], "02")

    def test_already_derived_is_not_candidate(self) -> None:
        doc = self._base_doc()
        doc["sections"]["b"]["x"]["hex"] = "{#IMSI}{IMSI}"
        hits = find_unmigrated_length_candidates(doc, "IMSI")
        self.assertEqual(hits, [])

    def test_unknown_token_returns_empty(self) -> None:
        hits = find_unmigrated_length_candidates(self._base_doc(), "UNKNOWN")
        self.assertEqual(hits, [])

    def test_is_non_mutating(self) -> None:
        doc = self._base_doc()
        snapshot = copy.deepcopy(doc)
        find_unmigrated_length_candidates(doc, "ICCID")
        self.assertEqual(doc, snapshot)

    def test_wrong_prefix_length_not_reported(self) -> None:
        doc = self._base_doc()
        doc["sections"]["b"]["x"]["hex"] = "FF{IMSI}"
        hits = find_unmigrated_length_candidates(doc, "IMSI")
        self.assertEqual(hits, [])


class ReadTokenDefsFromFileTests(unittest.TestCase):
    """``read_token_defs_from_file`` on-disk token watcher helper."""

    def test_returns_none_for_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "missing.json"
            self.assertIsNone(read_token_defs_from_file(path))

    def test_returns_none_for_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "bad.json"
            path.write_text("not json at all")
            self.assertIsNone(read_token_defs_from_file(path))

    def test_returns_none_when_token_defs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "empty.json"
            path.write_text(json.dumps({"unrelated": 1}))
            self.assertIsNone(read_token_defs_from_file(path))

    def test_reads_defs_and_default_style(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "t.json"
            path.write_text(
                json.dumps({"__ygg_token_defs__": {"ICCID": "AABB"}})
            )
            result = read_token_defs_from_file(path)
            self.assertIsNotNone(result)
            defs, style = result
            self.assertEqual(defs, {"ICCID": "AABB"})
            self.assertEqual(style, "brace")

    def test_reads_explicit_bracket_style(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "t.json"
            path.write_text(
                json.dumps(
                    {
                        "__ygg_token_defs__": {"K": "CC"},
                        "__ygg_placeholder_style__": "bracket",
                    }
                )
            )
            result = read_token_defs_from_file(path)
            self.assertIsNotNone(result)
            self.assertEqual(result[1], "bracket")

    def test_is_non_mutating_and_returns_copy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "t.json"
            payload = {"__ygg_token_defs__": {"K": {"hex": "CC"}}}
            path.write_text(json.dumps(payload))
            defs, _style = read_token_defs_from_file(path)
            defs["K"]["hex"] = "ZZ"
            again, _again_style = read_token_defs_from_file(path)
            self.assertEqual(again["K"]["hex"], "CC")


if __name__ == "__main__":
    unittest.main()
