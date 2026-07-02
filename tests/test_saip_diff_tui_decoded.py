# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the decoded-view helpers in ``Tools.ProfilePackage.saip_diff_tui``.

The Textual ``DiffApp`` itself is not exercised here — it is gated behind
the optional ``textual`` extra and would require a headless pilot. The
helpers under test are pure functions that the app delegates to, so
locking them in protects the diff-tui's decoded pane against silent
regressions on path parsing and the read-only decoder cascade.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_diff_tui import (
    _build_relevant_path_set,
    _extract_hex_from_payload,
    _is_hex_string,
    _render_decoded_pane,
    _render_hex_with_byte_diff,
)


class HexHelperTests(unittest.TestCase):
    def test_is_hex_string_accepts_even_hex(self) -> None:
        self.assertTrue(_is_hex_string("AABBCC"))
        self.assertTrue(_is_hex_string("0123456789abcdef"))

    def test_is_hex_string_rejects_non_hex_or_odd(self) -> None:
        self.assertFalse(_is_hex_string("ABC"))
        self.assertFalse(_is_hex_string(""))
        self.assertFalse(_is_hex_string("XX"))
        self.assertFalse(_is_hex_string(None))

    def test_extract_hex_from_raw_hex_decoded_view(self) -> None:
        decoded = {
            "title": "Raw hex view",
            "kind": "raw_hex",
            "payload": {"hex": "deadbeef"},
        }
        self.assertEqual(_extract_hex_from_payload(decoded), "DEADBEEF")

    def test_extract_hex_returns_none_for_structured_payload(self) -> None:
        decoded = {
            "title": "Decoded view",
            "kind": "editor",
            "payload": {"fields": [{"name": "foo"}]},
        }
        self.assertIsNone(_extract_hex_from_payload(decoded))

    def test_extract_hex_returns_none_for_none_input(self) -> None:
        self.assertIsNone(_extract_hex_from_payload(None))

    def _diff_byte_tokens(self, rendered, expected_bg: str) -> list[str]:
        """Return the byte tokens carrying the directional diff background.

        Centralised so the byte-diff tests stay legible when the
        rendered ``Text`` layout grows (offset prefix, summary line,
        per-line breaks).
        """
        plain = rendered.plain
        tokens: list[str] = []
        for span in rendered.spans:
            style_str = str(span.style or "")
            if expected_bg in style_str:
                tokens.append(plain[span.start:span.end])
        return tokens

    def test_render_hex_with_byte_diff_marks_diverging_bytes(self) -> None:
        rendered = _render_hex_with_byte_diff("AABBCC", "AAFFCC", side="a")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        plain = rendered.plain
        self.assertIn("(1 of 3 bytes differ)", plain)
        self.assertIn("0000: AA BB CC", plain)
        diff_tokens = self._diff_byte_tokens(rendered, "on red")
        self.assertEqual(diff_tokens, ["BB"])
        # ``AA`` and ``CC`` match across sides and must NOT carry the
        # diff background.
        self.assertNotIn(
            "AA",
            self._diff_byte_tokens(rendered, "on red"),
        )

    def test_render_hex_with_byte_diff_uses_green_for_b_side(self) -> None:
        rendered = _render_hex_with_byte_diff("AAFFCC", "AABBCC", side="b")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        diff_tokens = self._diff_byte_tokens(rendered, "on green")
        self.assertEqual(diff_tokens, ["FF"])
        self.assertEqual(self._diff_byte_tokens(rendered, "on red"), [])

    def test_render_hex_with_byte_diff_handles_missing_other(self) -> None:
        rendered = _render_hex_with_byte_diff("AABBCC", None, side="a")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        # Every byte is "different" because the other side is absent
        # entirely. The summary should reflect that.
        self.assertIn("(3 of 3 bytes differ)", rendered.plain)
        diff_tokens = self._diff_byte_tokens(rendered, "on red")
        self.assertEqual(diff_tokens, ["AA", "BB", "CC"])

    def test_render_hex_with_byte_diff_truncated_other_marks_tail(self) -> None:
        rendered = _render_hex_with_byte_diff("AABBCC", "AABB", side="a")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        diff_tokens = self._diff_byte_tokens(rendered, "on red")
        self.assertEqual(diff_tokens, ["CC"])
        self.assertIn("(1 of 3 bytes differ)", rendered.plain)

    def test_render_hex_with_byte_diff_wraps_at_16_bytes(self) -> None:
        # 24 bytes → 2 lines (16 + 8). Confirm the offset prefix.
        long_hex = "AA" * 24
        rendered = _render_hex_with_byte_diff(long_hex, long_hex, side="a")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        plain = rendered.plain
        self.assertIn("0000: ", plain)
        self.assertIn("0010: ", plain)
        # No bytes differ, so no summary line should appear.
        self.assertNotIn("bytes differ", plain)

    def test_render_hex_with_byte_diff_no_summary_when_equal(self) -> None:
        rendered = _render_hex_with_byte_diff("AABBCC", "AABBCC", side="a")
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        self.assertNotIn("bytes differ", rendered.plain)
        self.assertEqual(self._diff_byte_tokens(rendered, "on red"), [])


class RenderDecodedPanePlainModeTests(unittest.TestCase):
    """Default mode (``show_hex_diff=False``) renders the original plain view.

    No diff colouring inside the pane body — the side-by-side tree
    above carries the diff signal. The pane content is whatever the
    decoder cascade produced, formatted as pretty-JSON.
    """

    def test_missing_payload_returns_plain_string(self) -> None:
        rendered = _render_decoded_pane(
            None,
            {"title": "x", "payload": {"hex": "AA"}},
            side_label="A",
            missing_label="<missing on this side>",
            op="removed",
            show_hex_diff=False,
        )
        self.assertIsInstance(rendered, str)
        self.assertEqual(rendered, "A: <missing on this side>")

    def test_structured_payload_renders_pretty_json_string(self) -> None:
        side = {
            "title": "Editor",
            "payload": {"fields": [{"name": "foo"}]},
        }
        rendered = _render_decoded_pane(
            side,
            None,
            side_label="A",
            missing_label="<missing>",
            op="changed",
            show_hex_diff=False,
        )
        self.assertIsInstance(rendered, str)
        self.assertIn("A: Editor", rendered)
        self.assertIn('"name"', rendered)
        self.assertNotIn("0000:", rendered)
        self.assertNotIn("bytes differ", rendered)

    def test_hex_payload_renders_plain_json_in_default_mode(self) -> None:
        # Plain mode: even if the payload carries a hex blob, the
        # pane shows the JSON-rendered payload, not the xxd panel.
        side = {"title": "Raw hex view", "payload": {"hex": "AABBCC"}}
        rendered = _render_decoded_pane(
            side,
            {"title": "Raw hex view", "payload": {"hex": "AAFFCC"}},
            side_label="A",
            missing_label="<missing>",
            op="changed",
            show_hex_diff=False,
        )
        self.assertIsInstance(rendered, str)
        self.assertIn('"hex"', rendered)
        self.assertIn("AABBCC", rendered)
        self.assertNotIn("0000:", rendered)


class RenderDecodedPaneHexDiffModeTests(unittest.TestCase):
    """Toggle mode (``show_hex_diff=True``) overlays the byte-level diff."""

    def test_missing_payload_uses_op_styled_label(self) -> None:
        rendered = _render_decoded_pane(
            None,
            {"title": "x", "payload": {"hex": "AA"}},
            side_label="A",
            missing_label="<missing on this side>",
            op="removed",
            show_hex_diff=True,
        )
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        self.assertIn("missing on this side", rendered.plain)

    def test_hex_payload_renders_byte_diff_panel(self) -> None:
        side_a = {"title": "Raw hex", "payload": {"hex": "AABBCC"}}
        side_b = {"title": "Raw hex", "payload": {"hex": "AAFFCC"}}
        rendered = _render_decoded_pane(
            side_a,
            side_b,
            side_label="A",
            missing_label="<missing>",
            op="changed",
            show_hex_diff=True,
        )
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        plain = rendered.plain
        self.assertIn("0000: AA BB CC", plain)
        self.assertIn("(1 of 3 bytes differ)", plain)
        self.assertTrue(
            any(
                span.style and "on red" in str(span.style)
                for span in rendered.spans
            ),
            msg="expected at least one byte-diff span on side A",
        )

    def test_hex_payload_uses_green_on_side_b(self) -> None:
        side_a = {"title": "Raw hex", "payload": {"hex": "AABBCC"}}
        side_b = {"title": "Raw hex", "payload": {"hex": "AAFFCC"}}
        rendered = _render_decoded_pane(
            side_b,
            side_a,
            side_label="B",
            missing_label="<missing>",
            op="changed",
            show_hex_diff=True,
        )
        if isinstance(rendered, str):
            self.skipTest("rich.text not available in this environment")
        self.assertTrue(
            any(
                span.style and "on green" in str(span.style)
                for span in rendered.spans
            ),
            msg="expected the B-side pane to use the green-background style",
        )

    def test_structural_payload_with_no_hex_falls_back_to_plain(self) -> None:
        # Hex-diff mode is only meaningful when the payload carries a
        # flat hex blob. For structural-only payloads it falls back
        # to the plain decoded view rather than emitting an empty
        # panel; that way ``h`` is safe to leave on.
        side = {
            "title": "Editor",
            "payload": {"fields": [{"name": "foo"}]},
        }
        rendered = _render_decoded_pane(
            side,
            None,
            side_label="A",
            missing_label="<missing>",
            op="changed",
            show_hex_diff=True,
        )
        self.assertIsInstance(rendered, str)
        self.assertIn("A: Editor", rendered)
        self.assertIn('"name"', rendered)


class BuildRelevantPathSetTests(unittest.TestCase):
    """Lock the diffs-only breadcrumb expansion."""

    def test_empty_input_returns_root_only(self) -> None:
        self.assertEqual(_build_relevant_path_set([]), {""})

    def test_top_level_key_has_no_extra_ancestors(self) -> None:
        self.assertEqual(
            _build_relevant_path_set(["intro"]),
            {"", "intro"},
        )

    def test_dotted_path_yields_each_ancestor(self) -> None:
        self.assertEqual(
            _build_relevant_path_set(["sections.akaParameter.algoConfiguration"]),
            {
                "",
                "sections",
                "sections.akaParameter",
                "sections.akaParameter.algoConfiguration",
            },
        )

    def test_indexed_path_strips_brackets_and_dots(self) -> None:
        self.assertEqual(
            _build_relevant_path_set(["sections.list[2].field"]),
            {
                "",
                "sections",
                "sections.list",
                "sections.list[2]",
                "sections.list[2].field",
            },
        )

    def test_top_level_index_only_adds_itself_and_root(self) -> None:
        self.assertEqual(
            _build_relevant_path_set(["[3]"]),
            {"", "[3]"},
        )

    def test_multiple_overlapping_paths_dedupe(self) -> None:
        result = _build_relevant_path_set([
            "sections.foo.bar",
            "sections.foo.baz",
            "sections.foo",
            "intro[0]",
        ])
        self.assertEqual(
            result,
            {
                "",
                "sections",
                "sections.foo",
                "sections.foo.bar",
                "sections.foo.baz",
                "intro",
                "intro[0]",
            },
        )

    def test_non_string_inputs_are_skipped(self) -> None:
        result = _build_relevant_path_set(["sections.x", 42, None, "intro"])
        self.assertEqual(result, {"", "sections", "sections.x", "intro"})

from Tools.ProfilePackage.saip_diff_tui import (
    build_decoded_view_for_diff_path,
    diff_path_to_components,
)


class DiffPathComponentsTests(unittest.TestCase):
    def test_empty_path_yields_no_components(self) -> None:
        self.assertEqual(diff_path_to_components(""), [])

    def test_simple_dotted_path(self) -> None:
        self.assertEqual(
            diff_path_to_components("sections.mf.fid"),
            ["sections", "mf", "fid"],
        )

    def test_trailing_index_splits_off(self) -> None:
        # ``intro[0]`` becomes the bare key ``intro`` plus integer 0.
        self.assertEqual(
            diff_path_to_components("intro[0]"),
            ["intro", 0],
        )

    def test_multiple_indices_on_single_segment(self) -> None:
        # ``fileManagementCMD[0][1]`` parses as the key plus two ints.
        self.assertEqual(
            diff_path_to_components("sections.gfm.fileManagementCMD[0][1]"),
            ["sections", "gfm", "fileManagementCMD", 0, 1],
        )

    def test_tagged_tuple_path(self) -> None:
        # ``@`` is a literal dict key (``_TAG_TUPLE``) followed by an index.
        self.assertEqual(
            diff_path_to_components("sections.akaParameter.algoConfiguration.@[1].key.hex"),
            ["sections", "akaParameter", "algoConfiguration", "@", 1, "key", "hex"],
        )


class DecodedViewCascadeTests(unittest.TestCase):
    def test_unknown_hex_field_falls_back_to_raw_hex_view(self) -> None:
        # The cascade ends with build_decoded_value_raw_hex_model, which
        # claims any tagged-bytes leaf so the operator at least sees the
        # byte count. That is the contract the diff-tui relies on.
        document = {"sections": {"mf": {"unknownField": {"hex": "ABCD"}}}}
        result = build_decoded_view_for_diff_path(
            document,
            "sections.mf.unknownField.hex",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["kind"], "raw_hex")
        self.assertEqual(result["payload"].get("hex", "").upper(), "ABCD")

    def test_missing_path_returns_none(self) -> None:
        document = {"sections": {"mf": {}}}
        self.assertIsNone(
            build_decoded_view_for_diff_path(
                document,
                "sections.mf.notThere.hex",
            )
        )

    def test_non_hex_scalar_without_decoder_returns_none(self) -> None:
        # No tagged-bytes leaf, no scalar decoder for ``customLabel``,
        # so every cascade step returns None.
        document = {"sections": {"mf": {"customLabel": "free-text"}}}
        self.assertIsNone(
            build_decoded_view_for_diff_path(
                document,
                "sections.mf.customLabel",
            )
        )

    def test_short_efid_decodes_via_editor_cascade(self) -> None:
        # ``shortEFID`` is registered in build_decoded_value_editor_model
        # (saip_decoded_edit). The diff-tui must surface it the same way.
        document = {
            "sections": {
                "mf": {
                    "shortEFID": {"hex": "08"},
                },
            },
        }
        result = build_decoded_view_for_diff_path(
            document,
            "sections.mf.shortEFID.hex",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["field_name"], "shortEFID")
        self.assertIn("payload", result)
        self.assertIn("title", result)


if __name__ == "__main__":
    unittest.main()
