# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_gui_deep_audit_round3 import (
    fs_marker_roots_vs_editable_subfields,
    gui_referenced_saip_actions_are_registered,
    quick_add_factory_keys_match_row_ids,
    quick_add_row_ids_match_gap_frozenset,
    quick_add_rows_avoid_gui_catchall_tier,
)


class Round3Sweep01QuickAddVsGapFrozenset(unittest.TestCase):
    """Angle 1: TUI quick-add menu ids stay aligned with ``saip_pe_gui_gap``."""

    def test_quick_add_rows_equal_gap_menu_keys(self) -> None:
        self.assertEqual(quick_add_row_ids_match_gap_frozenset(), [])


class Round3Sweep02QuickAddGuiTiers(unittest.TestCase):
    """Angle 2: quick-add targets never map to the untyped catch-all GUI bucket."""

    def test_quick_add_rows_have_typed_gui_tiers(self) -> None:
        self.assertEqual(quick_add_rows_avoid_gui_catchall_tier(), [])


class Round3Sweep03FactoryMapAstVsRows(unittest.TestCase):
    """Angle 3: ``_factory_map`` keys (AST, no pySim import) match quick-add rows."""

    def test_factory_map_keys_equal_quick_add_rows(self) -> None:
        self.assertEqual(quick_add_factory_keys_match_row_ids(), [])


class Round3Sweep04WorkbenchActionRegistration(unittest.TestCase):
    """Angle 4: every ``app.js`` ``/api/actions/saip.*/run`` call is declared in ``saip.py``."""

    def test_gui_saip_actions_registered(self) -> None:
        self.assertEqual(gui_referenced_saip_actions_are_registered(), [])


class Round3Sweep05FsMarkersVsEditableWhitelist(unittest.TestCase):
    """Angle 5: FS detection markers line up with ``update_file_field`` whitelist + fill-only."""

    def test_fs_markers_covered(self) -> None:
        self.assertEqual(fs_marker_roots_vs_editable_subfields(), [])


if __name__ == "__main__":
    unittest.main()
