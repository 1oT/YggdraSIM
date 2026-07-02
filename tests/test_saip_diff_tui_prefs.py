# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit tests for ``saip_diff_tui_prefs``.

Covers:

* round-tripping the ``diff_tui`` sub-dict through the shared config
  file without clobbering transcode-side keys (``theme``, ``splits``,
  ``panes``, ``outline``);
* the decoded-height clamp window;
* graceful handling of a missing or malformed config file.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_diff_tui_prefs import (
    DECODED_HEIGHT_DEFAULT,
    DECODED_HEIGHT_MAX,
    DECODED_HEIGHT_MIN,
    clamp_decoded_height,
    load_diff_tui_layout,
    load_theme_pref,
    persist_diff_tui_layout,
)
from Tools.ProfilePackage.saip_transcode_tui_prefs import (
    load_transcode_tui_prefs,
    persist_split_sizes,
    persist_theme,
    transcode_tui_prefs_path,
)


class SaipDiffTuiPrefsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._temp_workspace.name)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_load_layout_returns_empty_when_config_missing(self) -> None:
        self.assertEqual(load_diff_tui_layout(self.workspace_root), {})

    def test_load_theme_returns_none_when_config_missing(self) -> None:
        self.assertIsNone(load_theme_pref(self.workspace_root))

    def test_round_trip_layout_keeps_unrelated_keys(self) -> None:
        persist_theme(self.workspace_root, "nord")
        persist_split_sizes(
            self.workspace_root,
            json_outline_width=33,
            json_col_width=72,
            inspect_width=49,
            bottom_height=17,
        )

        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=True,
            decoded_height=20,
            show_values=False,
            diffs_only=True,
            decoded_show_hex_diff=True,
        )

        self.assertEqual(
            load_diff_tui_layout(self.workspace_root),
            {
                "decoded_visible": True,
                "decoded_height": 20,
                "show_values": False,
                "diffs_only": True,
                "decoded_show_hex_diff": True,
            },
        )
        self.assertEqual(
            load_theme_pref(self.workspace_root),
            "nord",
        )
        full = load_transcode_tui_prefs(self.workspace_root)
        self.assertIn("splits", full)
        self.assertEqual(full["splits"]["json_outline_width"], 33)

    def test_decoded_height_is_clamped_on_write(self) -> None:
        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=True,
            decoded_height=1000,
            show_values=True,
            diffs_only=False,
            decoded_show_hex_diff=False,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertEqual(layout["decoded_height"], DECODED_HEIGHT_MAX)

        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=False,
            decoded_height=1,
            show_values=True,
            diffs_only=False,
            decoded_show_hex_diff=False,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertEqual(layout["decoded_height"], DECODED_HEIGHT_MIN)

    def test_diffs_only_default_absent_from_layout(self) -> None:
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertNotIn("diffs_only", layout)

    def test_diffs_only_round_trip_independent_of_other_flags(self) -> None:
        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=False,
            decoded_height=12,
            show_values=True,
            diffs_only=True,
            decoded_show_hex_diff=False,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertIs(layout["diffs_only"], True)

        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=False,
            decoded_height=12,
            show_values=True,
            diffs_only=False,
            decoded_show_hex_diff=False,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertIs(layout["diffs_only"], False)

    def test_decoded_show_hex_diff_round_trip(self) -> None:
        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=True,
            decoded_height=12,
            show_values=True,
            diffs_only=False,
            decoded_show_hex_diff=True,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertIs(layout["decoded_show_hex_diff"], True)

        persist_diff_tui_layout(
            self.workspace_root,
            decoded_visible=True,
            decoded_height=12,
            show_values=True,
            diffs_only=False,
            decoded_show_hex_diff=False,
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertIs(layout["decoded_show_hex_diff"], False)

    def test_decoded_height_default_is_within_clamp_window(self) -> None:
        self.assertGreaterEqual(DECODED_HEIGHT_DEFAULT, DECODED_HEIGHT_MIN)
        self.assertLessEqual(DECODED_HEIGHT_DEFAULT, DECODED_HEIGHT_MAX)
        self.assertEqual(
            clamp_decoded_height(DECODED_HEIGHT_DEFAULT),
            DECODED_HEIGHT_DEFAULT,
        )

    def test_malformed_config_yields_empty_prefs(self) -> None:
        path = transcode_tui_prefs_path(self.workspace_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json{{{", encoding="utf-8")
        self.assertEqual(load_diff_tui_layout(self.workspace_root), {})
        self.assertIsNone(load_theme_pref(self.workspace_root))

    def test_diff_tui_section_with_unknown_keys_ignored(self) -> None:
        path = transcode_tui_prefs_path(self.workspace_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "diff_tui": {
                        "decoded_visible": "yes",
                        "decoded_height": "22",
                        "show_values": "no",
                        "diffs_only": "on",
                        "decoded_show_hex_diff": "true",
                        "spurious_key": [1, 2, 3],
                    }
                }
            ),
            encoding="utf-8",
        )
        layout = load_diff_tui_layout(self.workspace_root)
        self.assertEqual(
            layout,
            {
                "decoded_visible": True,
                "decoded_height": 22,
                "show_values": False,
                "diffs_only": True,
                "decoded_show_hex_diff": True,
            },
        )

    def test_unknown_theme_string_falls_back_to_none(self) -> None:
        path = transcode_tui_prefs_path(self.workspace_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"theme": "no-such-theme"}),
            encoding="utf-8",
        )
        self.assertIsNone(load_theme_pref(self.workspace_root))


if __name__ == "__main__":
    unittest.main()
