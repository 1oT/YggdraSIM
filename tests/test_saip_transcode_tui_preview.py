"""Unit tests for the resolved-preview document builder."""

from __future__ import annotations

import json
import unittest

from Tools.ProfilePackage.saip_transcode_tui_preview import (
    build_resolved_preview_document,
    find_placeholder_locations,
    format_placeholder_hud,
    format_preview_banner,
    format_template_mode_sub_title,
    render_resolved_preview_json,
)


class BuildResolvedPreviewDocumentTests(unittest.TestCase):

    def _base_document(self) -> dict:
        return {
            "__ygg_token_defs__": {
                "ICCID": {"hex": "89881111111111111112"},
                "IMSI": "0899999999999999",
            },
            "__ygg_placeholder_style__": "brace",
            "sections": {
                "header": {
                    "iccid": {"hex": "{ICCID}"},
                    "imsi_with_len": {"hex": "{#IMSI}{IMSI}"},
                    "prefixed": {"hex": "BF370A{ICCID}"},
                    "plain": {"hex": "01020304"},
                },
                "mixed": [
                    {"hex": "{ICCID}"},
                    {"hex": "{UNKNOWN}"},
                ],
            },
        }

    def test_content_placeholder_expanded_in_place(self) -> None:
        resolved, undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(
            resolved["sections"]["header"]["iccid"]["hex"],
            "89881111111111111112",
        )
        self.assertEqual(set(undef.keys()), {"UNKNOWN"})

    def test_derived_length_marker_expanded(self) -> None:
        resolved, _undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(
            resolved["sections"]["header"]["imsi_with_len"]["hex"],
            "080899999999999999",
        )

    def test_plain_hex_left_untouched(self) -> None:
        resolved, _undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(
            resolved["sections"]["header"]["plain"]["hex"],
            "01020304",
        )

    def test_mixed_literal_and_placeholder(self) -> None:
        resolved, _undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(
            resolved["sections"]["header"]["prefixed"]["hex"],
            "BF370A89461111111111111112",
        )

    def test_unknown_token_collected_with_dotted_path(self) -> None:
        _resolved, undef = build_resolved_preview_document(self._base_document())
        self.assertIn("UNKNOWN", undef)
        self.assertEqual(undef["UNKNOWN"], {"sections.mixed.[1]"})

    def test_unknown_token_expands_to_empty(self) -> None:
        resolved, _undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(resolved["sections"]["mixed"][1]["hex"], "")

    def test_metadata_keys_preserved(self) -> None:
        resolved, _undef = build_resolved_preview_document(self._base_document())
        self.assertEqual(
            resolved["__ygg_token_defs__"]["ICCID"],
            {"hex": "89881111111111111112"},
        )
        self.assertEqual(resolved["__ygg_placeholder_style__"], "brace")

    def test_original_document_not_mutated(self) -> None:
        doc = self._base_document()
        snapshot = json.loads(json.dumps(doc))
        build_resolved_preview_document(doc)
        self.assertEqual(doc, snapshot)

    def test_bracket_style_tokens(self) -> None:
        doc = {
            "__ygg_token_defs__": {"SPARE": {"hex": "FFFF"}},
            "__ygg_placeholder_style__": "bracket",
            "sections": {
                "a": {"hex": "[SPARE]"},
                "b": {"hex": "[#SPARE]"},
            },
        }
        resolved, undef = build_resolved_preview_document(doc)
        self.assertEqual(resolved["sections"]["a"]["hex"], "FFFF")
        self.assertEqual(resolved["sections"]["b"]["hex"], "02")
        self.assertEqual(undef, {})

    def test_document_without_defs_tolerates_placeholders(self) -> None:
        doc = {
            "sections": {
                "a": {"hex": "{ICCID}"},
            },
        }
        resolved, undef = build_resolved_preview_document(doc)
        self.assertEqual(resolved["sections"]["a"]["hex"], "")
        self.assertIn("ICCID", undef)
        self.assertEqual(undef["ICCID"], {"sections.a"})

    def test_non_dict_raises_typeerror(self) -> None:
        with self.assertRaises(TypeError):
            build_resolved_preview_document("not a dict")


class RenderResolvedPreviewJsonTests(unittest.TestCase):

    def test_returns_pretty_json(self) -> None:
        doc = {
            "__ygg_token_defs__": {"A": {"hex": "FF"}},
            "__ygg_placeholder_style__": "brace",
            "sections": {"a": {"hex": "{A}"}},
        }
        text, undef = render_resolved_preview_json(doc)
        self.assertIn('"hex": "FF"', text)
        self.assertTrue(text.endswith("\n"))
        parsed = json.loads(text)
        self.assertEqual(parsed["sections"]["a"]["hex"], "FF")
        self.assertEqual(undef, {})


class FormatPreviewBannerTests(unittest.TestCase):

    def test_all_resolved(self) -> None:
        banner = format_preview_banner({})
        self.assertIn("all placeholders expanded", banner)

    def test_lists_unresolved_tokens(self) -> None:
        banner = format_preview_banner(
            {"ZULU": {"sections.a"}, "ALPHA": {"sections.b"}}
        )
        self.assertIn("unresolved tokens: ALPHA, ZULU", banner)
        self.assertIn("Ctrl+K", banner)


class FormatTemplateModeSubTitleTests(unittest.TestCase):

    def test_no_badge_when_nothing_active(self) -> None:
        result = format_template_mode_sub_title(
            "session base",
            preview_active=False,
            template_mode=False,
            undefined_tokens=None,
            placeholder_paths=None,
        )
        self.assertEqual(result, "session base")

    def test_unresolved_count_badge(self) -> None:
        result = format_template_mode_sub_title(
            "session base",
            preview_active=False,
            template_mode=True,
            undefined_tokens={"ICCID", "IMSI"},
            placeholder_paths=[],
        )
        self.assertEqual(result, "[TEMPLATE MODE · 2 unresolved] session base")

    def test_template_mode_without_undefined_tokens(self) -> None:
        result = format_template_mode_sub_title(
            "session base",
            preview_active=False,
            template_mode=True,
            undefined_tokens=[],
            placeholder_paths=[],
        )
        self.assertEqual(result, "[TEMPLATE MODE] session base")

    def test_placeholder_only_reports_count(self) -> None:
        result = format_template_mode_sub_title(
            "session base",
            preview_active=False,
            template_mode=False,
            undefined_tokens=[],
            placeholder_paths=["header.iccid", "header.imsi"],
        )
        self.assertEqual(
            result, "[TEMPLATE · 2 placeholder(s)] session base"
        )

    def test_preview_plus_template_combines(self) -> None:
        result = format_template_mode_sub_title(
            "session base",
            preview_active=True,
            template_mode=True,
            undefined_tokens={"ICCID"},
            placeholder_paths=[],
        )
        self.assertEqual(
            result,
            "[PREVIEW MODE · TEMPLATE MODE · 1 unresolved] session base",
        )

    def test_preview_with_empty_base(self) -> None:
        result = format_template_mode_sub_title(
            "",
            preview_active=True,
            template_mode=False,
            undefined_tokens=[],
            placeholder_paths=[],
        )
        self.assertEqual(result, "PREVIEW MODE")


class FindPlaceholderLocationsTests(unittest.TestCase):

    def test_empty_text_returns_empty(self) -> None:
        self.assertEqual(find_placeholder_locations(""), [])

    def test_no_placeholders_returns_empty(self) -> None:
        self.assertEqual(find_placeholder_locations('{"a": "bb"}'), [])

    def test_single_brace_placeholder(self) -> None:
        text = '{"iccid": "{ICCID}"}'
        locs = find_placeholder_locations(text)
        self.assertEqual(len(locs), 1)
        loc = locs[0]
        self.assertEqual(loc["name"], "ICCID")
        self.assertEqual(loc["is_length"], False)
        self.assertEqual(loc["style"], "brace")
        self.assertEqual(text[loc["start"]:loc["end"]], "{ICCID}")

    def test_length_companion_detected(self) -> None:
        locs = find_placeholder_locations('"{#IMSI}{IMSI}"')
        self.assertEqual(len(locs), 2)
        self.assertTrue(locs[0]["is_length"])
        self.assertEqual(locs[0]["name"], "IMSI")
        self.assertFalse(locs[1]["is_length"])
        self.assertEqual(locs[1]["name"], "IMSI")

    def test_bracket_style_is_recognised(self) -> None:
        locs = find_placeholder_locations("[KEY] and [#OTHER]")
        self.assertEqual(len(locs), 2)
        self.assertEqual(locs[0]["style"], "bracket")
        self.assertEqual(locs[0]["is_length"], False)
        self.assertEqual(locs[1]["style"], "bracket")
        self.assertEqual(locs[1]["is_length"], True)

    def test_line_and_column_are_one_based(self) -> None:
        text = 'first\n{\n  "hex": "{ICCID}"\n}'
        locs = find_placeholder_locations(text)
        self.assertEqual(len(locs), 1)
        loc = locs[0]
        self.assertEqual(loc["line"], 3)
        self.assertEqual(loc["column"], text.split("\n")[2].index("{") + 1)


class FormatPlaceholderHudTests(unittest.TestCase):

    def test_empty_when_no_locations(self) -> None:
        self.assertEqual(format_placeholder_hud([]), "")

    def test_counts_reported(self) -> None:
        locs = [
            {"name": "ICCID", "is_length": False},
            {"name": "IMSI", "is_length": True},
            {"name": "IMSI", "is_length": False},
        ]
        hud = format_placeholder_hud(locs)
        self.assertIn("3 placeholder(s)", hud)
        self.assertIn("2 content · 1 length", hud)

    def test_unresolved_count_reflects_undefined_tokens(self) -> None:
        locs = [
            {"name": "ICCID", "is_length": False},
            {"name": "KI", "is_length": False},
        ]
        hud = format_placeholder_hud(locs, undefined_tokens={"KI"})
        self.assertIn("1 unresolved", hud)


if __name__ == "__main__":
    unittest.main()
