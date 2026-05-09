import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_transcode_tui_prefs import (
    load_outline_prefs,
    load_pane_layout_prefs,
    load_split_size_prefs,
    persist_outline_prefs,
    persist_pane_layout_prefs,
    load_transcode_tui_prefs,
    persist_split_sizes,
    persist_theme,
    save_transcode_tui_prefs,
)


class SaipTranscodeTuiPrefsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self._temp_workspace.name)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_persist_split_sizes_round_trip_and_keep_theme(self) -> None:
        persist_theme(self.workspace_root, "nord")

        persist_split_sizes(
            self.workspace_root,
            json_outline_width=33,
            json_col_width=72,
            inspect_width=49,
            bottom_height=17,
        )

        self.assertEqual(
            load_split_size_prefs(self.workspace_root),
            {
                "json_outline_width": 33,
                "json_col_width": 72,
                "inspect_width": 49,
                "bottom_height": 17,
            },
        )
        self.assertEqual(load_transcode_tui_prefs(self.workspace_root).get("theme"), "nord")

    def test_load_split_size_prefs_ignores_invalid_values(self) -> None:
        save_transcode_tui_prefs(
            self.workspace_root,
            {
                "splits": {
                    "json_outline_width": 0,
                    "json_col_width": "bad",
                    "inspect_width": "44",
                    "bottom_height": True,
                },
            },
        )

        self.assertEqual(
            load_split_size_prefs(self.workspace_root),
            {
                "inspect_width": 44,
            },
        )

    def test_persist_pane_layout_round_trip_and_keep_theme(self) -> None:
        persist_theme(self.workspace_root, "nord")

        persist_pane_layout_prefs(
            self.workspace_root,
            outline_visible=False,
            right_mode="lint",
            bottom_left_mode="der",
            bottom_right_mode="none",
        )

        self.assertEqual(
            load_pane_layout_prefs(self.workspace_root),
            {
                "outline_visible": False,
                "right_mode": "lint",
                "bottom_left_mode": "der",
                "bottom_right_mode": "none",
            },
        )
        self.assertEqual(load_transcode_tui_prefs(self.workspace_root).get("theme"), "nord")

    def test_load_pane_layout_prefs_ignores_invalid_values(self) -> None:
        save_transcode_tui_prefs(
            self.workspace_root,
            {
                "panes": {
                    "outline_visible": "maybe",
                    "right_mode": "lint",
                    "bottom_left_mode": "bad",
                    "bottom_right_mode": "DER",
                },
            },
        )

        self.assertEqual(
            load_pane_layout_prefs(self.workspace_root),
            {
                "right_mode": "lint",
                "bottom_right_mode": "der",
            },
        )

    def test_persist_outline_prefs_round_trip_preserves_siblings(self) -> None:
        persist_theme(self.workspace_root, "nord")
        persist_split_sizes(
            self.workspace_root,
            json_outline_width=40,
            json_col_width=120,
            inspect_width=90,
            bottom_height=15,
        )
        persist_pane_layout_prefs(
            self.workspace_root,
            outline_visible=True,
            right_mode="lint",
            bottom_left_mode="der",
            bottom_right_mode="none",
        )

        persist_outline_prefs(
            self.workspace_root,
            fold_redundant_file_paths=False,
        )

        self.assertEqual(
            load_outline_prefs(self.workspace_root),
            {"fold_redundant_file_paths": False},
        )
        full = load_transcode_tui_prefs(self.workspace_root)
        self.assertEqual(full.get("theme"), "nord")
        self.assertEqual(full.get("splits", {}).get("json_col_width"), 120)
        self.assertEqual(full.get("panes", {}).get("right_mode"), "lint")

        persist_outline_prefs(
            self.workspace_root,
            fold_redundant_file_paths=True,
        )
        self.assertEqual(
            load_outline_prefs(self.workspace_root),
            {"fold_redundant_file_paths": True},
        )

    def test_load_outline_prefs_ignores_invalid_values(self) -> None:
        save_transcode_tui_prefs(
            self.workspace_root,
            {
                "outline": {
                    "fold_redundant_file_paths": "maybe",
                },
            },
        )
        self.assertEqual(load_outline_prefs(self.workspace_root), {})

        save_transcode_tui_prefs(
            self.workspace_root,
            {
                "outline": {
                    "fold_redundant_file_paths": "yes",
                },
            },
        )
        self.assertEqual(
            load_outline_prefs(self.workspace_root),
            {"fold_redundant_file_paths": True},
        )

    def test_load_outline_prefs_returns_empty_when_key_missing(self) -> None:
        save_transcode_tui_prefs(
            self.workspace_root,
            {
                "theme": "nord",
            },
        )
        self.assertEqual(load_outline_prefs(self.workspace_root), {})


if __name__ == "__main__":
    unittest.main()
