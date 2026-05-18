# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_pe_gui_gap import (
    classify_pe_gui_tier,
    known_pe_types_union,
    _normalise_gui_pe_type,
)


class SaipPeGuiGapTests(unittest.TestCase):
    def test_filesystem_branch_includes_df_saip(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("df-saip"),
            "filesystem_template_catalog_no_pe_decoded_panel",
        )

    def test_cd_uses_filesystem_template_branch(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("cd"),
            "filesystem_template_catalog_no_pe_decoded_panel",
        )

    def test_security_domain_normalisation(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("securityDomain"),
            "security_domain_cards_wizard",
        )
        self.assertEqual(
            classify_pe_gui_tier("MNO-SD"),
            "security_domain_cards_wizard",
        )

    def test_sparse_pe_branch(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("cdmaParameter"),
            "sparse_identity_card_section_wizard",
        )

    def test_union_contains_diff_only_labels(self) -> None:
        names = known_pe_types_union()
        self.assertIn("umts", names)
        self.assertIn("df-tetra", names)

    def test_profileheader_normalises_to_header_tier(self) -> None:
        self.assertEqual(_normalise_gui_pe_type("profileHeader"), "header")
        self.assertEqual(
            classify_pe_gui_tier("profileHeader"),
            "profile_header_only",
        )

    def test_securitydomain_ssd_normalises_to_ssd_tier(self) -> None:
        self.assertEqual(_normalise_gui_pe_type("securityDomain_ssd"), "ssd")
        self.assertEqual(
            classify_pe_gui_tier("securityDomain_ssd"),
            "security_domain_cards_wizard",
        )

    def test_javacard_application_tier(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("application"),
            "typed_summary_cards_wizard",
        )

    def test_nonstandard_sparse_tier(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("nonStandard"),
            "nonstandard_sparse_card_untyped_section_wizard",
        )

    def test_isdr_security_tier(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("isdr"),
            "security_domain_cards_wizard",
        )

    def test_umts_filesystem_tier(self) -> None:
        self.assertEqual(
            classify_pe_gui_tier("umts"),
            "filesystem_template_catalog_no_pe_decoded_panel",
        )


if __name__ == "__main__":
    unittest.main()
