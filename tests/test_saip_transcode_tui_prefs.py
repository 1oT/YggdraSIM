import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_transcode_tui_prefs import (
    load_split_size_prefs,
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


if __name__ == "__main__":
    unittest.main()
