# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_gui_deep_audit_round4 import (
    action_spec_symbols_match_registry_register,
    declared_saip_actions_reachable_from_workbench_tests_or_tooling,
    duplicate_saip_action_ids,
    enum_payload_keys_have_choice_descriptors,
    security_domain_types_have_application_friendly_labels,
)


class Round4Sweep01ActionSpecRegisterParity(unittest.TestCase):
    """Angle 1: every ``ActionSpec`` symbol is registered on the global registry."""

    def test_specs_match_register_calls(self) -> None:
        self.assertEqual(action_spec_symbols_match_registry_register(), [])


class Round4Sweep02UniqueActionIds(unittest.TestCase):
    """Angle 2: no duplicate ``id="saip.…"`` strings inside ``saip.py``."""

    def test_no_duplicate_action_ids(self) -> None:
        self.assertEqual(duplicate_saip_action_ids(), [])


class Round4Sweep03SecurityDomainFriendlyLabels(unittest.TestCase):
    """Angle 3: SD PE types used by ``list_applications`` carry friendly labels."""

    def test_sd_types_have_friendly_names(self) -> None:
        self.assertEqual(security_domain_types_have_application_friendly_labels(), [])


class Round4Sweep04EnumPickerRegistry(unittest.TestCase):
    """Angle 4: decoded-editor enum keys stay unique and backed by choice tables."""

    def test_enum_keys_round_trip(self) -> None:
        self.assertEqual(enum_payload_keys_have_choice_descriptors(), [])


class Round4Sweep05DeclaredActionsSurfaceArea(unittest.TestCase):
    """Angle 5: each declared ``saip.*`` action is used from UI, tests, or tooling."""

    def test_no_orphan_declared_actions(self) -> None:
        self.assertEqual(declared_saip_actions_reachable_from_workbench_tests_or_tooling(), [])


if __name__ == "__main__":
    unittest.main()
