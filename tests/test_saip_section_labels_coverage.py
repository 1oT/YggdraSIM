# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from SIMCARD.saip_profile import _SECTION_SPECS
from Tools.ProfilePackage.saip_profile_diff import _SECTION_LABELS


class SaipSectionLabelsCoverageTests(unittest.TestCase):
    def test_section_specs_have_diff_labels(self) -> None:
        missing = sorted(k for k in _SECTION_SPECS if k not in _SECTION_LABELS)
        self.assertEqual(
            missing,
            [],
            msg="Add _SECTION_LABELS entries for simulator PE keys: " + ", ".join(missing),
        )

    def test_securitydomain_ssd_label_for_quick_add_key(self) -> None:
        self.assertIn("securityDomain_ssd", _SECTION_LABELS)


if __name__ == "__main__":
    unittest.main()
