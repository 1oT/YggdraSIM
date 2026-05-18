# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_ef_wizard_gui_audit import (
    dedicated_wizard_keys_subset_of_specs_or_orphans,
    duplicate_wizard_assignments,
    ef_decoded_edit_coverage_gaps,
    ef_dispatcher_key_gaps,
    ef_fid_mismatches_ef_key_to_fid_vs_file_specs,
    normalize_ef_gui_key,
    parse_saip_record_wizard_ef_keys,
    pe_decoded_edit_coverage_gaps,
    pe_registry_gaps_for_known_union,
    record_wizard_keys_subset_of_specs_or_orphans,
)
from Tools.ProfilePackage.saip_pe_gui_gap import known_pe_types_union
from Tools.ProfilePackage.saip_profile_diff import _SECTION_LABELS


class Sweep01DedicatedTransparentWizards(unittest.TestCase):
    """Angle 1: every ``_SAIP_WIZARDS`` EF key is spec-backed or allow-listed."""

    def test_no_orphan_dedicated_transparent_keys(self) -> None:
        self.assertEqual(dedicated_wizard_keys_subset_of_specs_or_orphans(), [])

    def test_no_duplicate_bracket_wizard_assignments(self) -> None:
        self.assertEqual(duplicate_wizard_assignments(), [])

    def test_ef_supinai_aliases_supe_nai_wizard(self) -> None:
        app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        self.assertIn('_SAIP_WIZARDS["ef-supinai"]', app_js)


class Sweep02RecordFixedWizards(unittest.TestCase):
    """Angle 2: record wizards attach only to known ``_FILE_SPECS`` EF keys."""

    def test_no_orphan_record_wizard_keys(self) -> None:
        self.assertEqual(record_wizard_keys_subset_of_specs_or_orphans(), [])

    def test_acm_has_dedicated_record_wizard(self) -> None:
        app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        keys = parse_saip_record_wizard_ef_keys(app_js)
        self.assertIn("ef-acm", keys)


class Sweep03FidAlignmentAsn1VsSimulator(unittest.TestCase):
    """Angle 3: shared non-empty FIDs match between ASN.1 map and ``_FILE_SPECS``."""

    def test_no_unexpected_fid_mismatches(self) -> None:
        self.assertEqual(ef_fid_mismatches_ef_key_to_fid_vs_file_specs(), [])


class Sweep04DiffSectionLabelsVsPeUnion(unittest.TestCase):
    """Angle 4: diff UI labels exist for every PE base in the GUI gap union."""

    def test_union_bases_have_section_labels(self) -> None:
        missing = sorted(pe for pe in known_pe_types_union() if pe not in _SECTION_LABELS)
        self.assertEqual(missing, [], msg="missing _SECTION_LABELS: " + ", ".join(missing))


class Sweep05PeRegistryVsUnion(unittest.TestCase):
    """Angle 5: explicit ``SAIP_PE_REGISTRY`` rows for non-DF template PE bases."""

    def test_no_implicit_default_registry_for_union_bases(self) -> None:
        self.assertEqual(pe_registry_gaps_for_known_union(), [])

    def test_file_spec_ef_keys_normalise_uniquely(self) -> None:
        from SIMCARD.saip_profile import _FILE_SPECS

        seen: dict[str, str] = {}
        dupes: list[tuple[str, str, str]] = []
        for raw in _FILE_SPECS:
            k = normalize_ef_gui_key(raw)
            if k in seen and seen[k] != raw:
                dupes.append((seen[k], raw, k))
            seen.setdefault(k, raw)
        self.assertEqual(dupes, [], msg="duplicate normalised EF keys: " + repr(dupes))


class Sweep06DecodedEditCoverage(unittest.TestCase):
    """Angle 6: every PE / EF in the truth set has a decoded-edit surface.

    Covered by either a typed editor branch in the JS dispatch, the per-PE
    generic ``saipRenderDecodedEditPanel`` mount, or (for EFs) a routed
    dispatcher decoder. The two gap helpers must stay at zero so a
    regression — adding a typed editor branch that bypasses the decoded
    panel without supplying its own edit affordances — fails CI.
    """

    def test_ef_decoded_edit_coverage_gaps_empty(self) -> None:
        self.assertEqual(
            ef_decoded_edit_coverage_gaps(),
            [],
            msg="EFs with no decoded-edit surface — add to dispatcher / wizard / opaque catalog.",
        )

    def test_ef_dispatcher_key_gaps_empty(self) -> None:
        self.assertEqual(
            ef_dispatcher_key_gaps(),
            [],
            msg="Normalised _FILE_SPECS ef-keys that _decode_known_ef_payload cannot route.",
        )

    def test_pe_decoded_edit_coverage_gaps_empty(self) -> None:
        self.assertEqual(
            pe_decoded_edit_coverage_gaps(),
            [],
            msg="PEs that opt out of the generic decoded panel without a typed editor.",
        )


if __name__ == "__main__":
    unittest.main()
