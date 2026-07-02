# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_gui_deep_audit_round5 import (
    dispatch_branch_literals_for_tiered_pe_types,
    file_spec_structure_vocabulary,
    gp_privilege_bit_masks_unique,
    hand_written_decoded_fields_vs_update_file_field_whitelist,
    registry_pe_icon_kinds_have_stylesheet_rules,
)


class Round5Sweep01PeIconKindsVsCss(unittest.TestCase):
    """Angle 1: ``SAIP_PE_REGISTRY`` ``kind`` strings map to shipped icon CSS."""

    def test_registry_kinds_have_icon_rules(self) -> None:
        self.assertEqual(registry_pe_icon_kinds_have_stylesheet_rules(), [])


class Round5Sweep02HandWrittenFieldsVsSaipWhitelist(unittest.TestCase):
    """Angle 2: decoded-edit hand-written fields stay aligned with ``update_file_field``."""

    def test_hand_written_fields_accounted_for(self) -> None:
        self.assertEqual(hand_written_decoded_fields_vs_update_file_field_whitelist(), [])


class Round5Sweep03FileSpecStructures(unittest.TestCase):
    """Angle 3: simulator ``_FILE_SPECS`` structure strings stay in-band."""

    def test_file_spec_structures(self) -> None:
        self.assertEqual(file_spec_structure_vocabulary(), [])


class Round5Sweep04TieredPeDispatchLiterals(unittest.TestCase):
    """Angle 4: gap-module typed/sparse/SD PE bases have ``t ===`` hooks in ``app.js``."""

    def test_tiered_pe_branches_present(self) -> None:
        self.assertEqual(dispatch_branch_literals_for_tiered_pe_types(), [])


class Round5Sweep05GpPrivilegeBits(unittest.TestCase):
    """Angle 5: GlobalPlatform privilege bit table has no duplicate (byte, mask)."""

    def test_gp_privilege_rows_unique(self) -> None:
        self.assertEqual(gp_privilege_bit_masks_unique(), [])


if __name__ == "__main__":
    unittest.main()
