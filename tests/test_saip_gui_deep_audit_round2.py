# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_gui_deep_audit_round2 import (
    filesystem_branch_matches_gap_module,
    hand_written_fill_ef_keys_backed_by_file_specs,
    lossy_splice_ef_keys_backed_by_file_specs,
    render_saip_pe_editor_duplicate_dispatch_types,
    saip_app_friendly_types_match_app_pe_types,
    saip_app_pe_types_cover_security_domains,
)


class Round2Sweep01BackendAppPeLists(unittest.TestCase):
    """Angle 1: ``saip.py`` application list frozensets stay internally consistent."""

    def test_app_pe_types_include_all_security_domain_types(self) -> None:
        self.assertEqual(saip_app_pe_types_cover_security_domains(), [])

    def test_app_friendly_labels_cover_exactly_app_pe_types(self) -> None:
        self.assertEqual(saip_app_friendly_types_match_app_pe_types(), [])


class Round2Sweep02LossySpliceAnchors(unittest.TestCase):
    """Angle 2: lossy-splice EF keys are backed by simulator rows or allow-list."""

    def test_lossy_splice_keys_resolved(self) -> None:
        self.assertEqual(lossy_splice_ef_keys_backed_by_file_specs(), [])


class Round2Sweep03HandWrittenFillAnchors(unittest.TestCase):
    """Angle 3: fillFileContent hand-edit anchors exist in ``_FILE_SPECS``."""

    def test_hand_written_fill_ef_keys_in_file_specs(self) -> None:
        self.assertEqual(hand_written_fill_ef_keys_backed_by_file_specs(), [])


class Round2Sweep04PeDispatchHygiene(unittest.TestCase):
    """Angle 4: no duplicate ``} else if (t === …)`` PE branch in ``renderSaipPeEditor``."""

    def test_no_duplicate_else_if_dispatch(self) -> None:
        self.assertEqual(render_saip_pe_editor_duplicate_dispatch_types(), [])


class Round2Sweep05FilesystemBranchParity(unittest.TestCase):
    """Angle 5: filesystem template ``if`` chain matches ``_FILE_TEMPLATE_PE``."""

    def test_js_filesystem_branch_matches_gap_frozenset(self) -> None:
        self.assertEqual(filesystem_branch_matches_gap_module(), [])


if __name__ == "__main__":
    unittest.main()
