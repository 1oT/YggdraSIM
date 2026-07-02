# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for the pySim-derived ``_FILE_SPECS`` overlay.

These tests pin three distinct invariants:

  1. The pySim ``ProfileTemplateRegistry`` snapshot exposes every
     ``ProfileTemplate`` registered at import time and projects it
     into the dependency-free ``FileTemplateSnapshot`` shape used by
     the simulator.

  2. ``apply_pysim_augmentations`` only fills missing fields; it never
     overwrites the simulator's hand-curated ``fid`` / ``structure`` /
     ``name`` anchors and never overrides an SFI that is already set.

  3. The augmented ``_FILE_SPECS`` carries pySim's authoritative SFIs
     for the high-traffic EFs the modem actually selects (LOCI, AD,
     EHPLMN, etc.) so SFI-based ``READ BINARY`` requests resolve.
"""

from __future__ import annotations

import unittest
from typing import Any

from SIMCARD.saip_profile import _FILE_SPECS
from SIMCARD.saip_pysim_specs import (
    FileTemplateSnapshot,
    apply_pysim_augmentations,
    pysim_alias_specs_for,
    pysim_file_template_registry,
    reset_registry_cache,
)


class PySimRegistryShapeTests(unittest.TestCase):
    """Verify the cached pySim snapshot exposes the expected shape."""

    def test_registry_contains_core_usim_efs(self) -> None:
        registry = pysim_file_template_registry()

        for pe_name in ("ef-imsi", "ef-loci", "ef-ad", "ef-ust", "ef-est"):
            self.assertIn(pe_name, registry, f"missing pe_name {pe_name!r} in pySim registry")

    def test_registry_entries_are_immutable_snapshots(self) -> None:
        registry = pysim_file_template_registry()
        snaps = registry["ef-imsi"]

        self.assertGreaterEqual(len(snaps), 1)
        self.assertIsInstance(snaps[0], FileTemplateSnapshot)
        self.assertEqual(snaps[0].fid_hex, "6F07")
        self.assertEqual(snaps[0].file_type, "TR")
        self.assertEqual(snaps[0].structure, "transparent")
        self.assertEqual(snaps[0].sfi, 7)

    def test_registry_excludes_mf_df_adf_anchors(self) -> None:
        registry = pysim_file_template_registry()
        for pe_name, snaps in registry.items():
            for snap in snaps:
                self.assertIn(
                    snap.file_type,
                    ("TR", "LF", "CY", "BT"),
                    f"pe_name {pe_name!r} unexpectedly retained file_type {snap.file_type!r}",
                )

    def test_cache_reset_repopulates_registry(self) -> None:
        first = pysim_file_template_registry()
        reset_registry_cache()
        second = pysim_file_template_registry()
        # We expect the same content; cache reset is safe.
        self.assertEqual(set(first.keys()), set(second.keys()))


class ApplyPySimAugmentationsTests(unittest.TestCase):
    """Pin the gap-fill semantics of ``apply_pysim_augmentations``."""

    def _build_specs(self) -> dict[str, dict[str, Any]]:
        return {
            "ef-imsi": {
                "name": "EF.IMSI",
                "fid": "6F07",
                "structure": "transparent",
                "sfi": None,
            },
            "ef-loci": {
                "name": "EF.LOCI",
                "fid": "6F7E",
                "structure": "transparent",
                "sfi": None,
            },
            "ef-iccid": {
                "name": "EF.ICCID",
                "fid": "2FE2",
                "structure": "transparent",
                "sfi": 0x02,
            },
            "ef-mmsucp": {
                "name": "EF.MMSUCP",
                "fid": "",
                "structure": "transparent",
                "sfi": None,
            },
            # Local-only entry that pySim has no record of -- left untouched.
            "ef-vendor-private": {
                "name": "EF.VENDOR-PRIVATE",
                "fid": "DEAD",
                "structure": "transparent",
                "sfi": None,
            },
        }

    def test_missing_sfi_is_filled_from_pysim(self) -> None:
        specs = self._build_specs()
        apply_pysim_augmentations(specs)

        self.assertEqual(specs["ef-imsi"]["sfi"], 7)
        self.assertEqual(specs["ef-loci"]["sfi"], 11)

    def test_existing_sfi_is_preserved_against_pysim_none(self) -> None:
        specs = self._build_specs()
        apply_pysim_augmentations(specs)

        # pySim's FilesAtMF declares EF.ICCID with SFI=None even though
        # TS 102 221 §13.2 mandates SFI=02. Our literal table is the
        # authoritative source; the augmenter must not zero it out.
        self.assertEqual(specs["ef-iccid"]["sfi"], 0x02)

    def test_fid_anchor_is_never_overridden(self) -> None:
        specs = self._build_specs()
        apply_pysim_augmentations(specs)

        # ``ef-mmsucp`` deliberately carries fid="" because the canonical
        # 6FD2 collides with EF.VBSCA per legacy SAIP tooling. Augment
        # must keep the empty FID even though pySim knows about 6FD2.
        self.assertEqual(specs["ef-mmsucp"]["fid"], "")

    def test_local_only_entries_are_left_alone(self) -> None:
        specs = self._build_specs()
        apply_pysim_augmentations(specs)

        local_only = specs["ef-vendor-private"]
        self.assertEqual(local_only["fid"], "DEAD")
        self.assertEqual(local_only["sfi"], None)
        self.assertNotIn("arr", local_only)

    def test_metadata_fields_are_filled_in(self) -> None:
        specs = self._build_specs()
        apply_pysim_augmentations(specs)

        loci = specs["ef-loci"]
        self.assertEqual(loci["arr"], 5)
        self.assertEqual(loci["default_val"], "FFFFFFFFFFFFFF0000FF01")
        self.assertEqual(loci["high_update"], True)
        self.assertEqual(loci["content_rqd"], False)
        self.assertEqual(loci["template_class"], "FilesUsimMandatory")


class PySimAliasGenerationTests(unittest.TestCase):
    """Aliases must be (FID, EF-name) anchored, not FID-only."""

    def test_supi_nai_alias_targets_supinai_not_pbc(self) -> None:
        specs = {
            "ef-supinai": {
                "name": "EF.SUPI_NAI",
                "fid": "4F09",
                "structure": "transparent",
                "sfi": None,
            },
            "ef-pbc": {
                "name": "EF.PBC",
                "fid": "4F09",
                "structure": "linear-fixed",
                "sfi": None,
            },
        }
        aliases = pysim_alias_specs_for(specs)

        self.assertIn("ef-supi-nai", aliases)
        self.assertEqual(aliases["ef-supi-nai"]["alias_of"], "ef-supinai")
        self.assertEqual(aliases["ef-supi-nai"]["structure"], "transparent")

    def test_no_alias_emitted_when_local_table_already_has_pe_name(self) -> None:
        specs = {
            "ef-supinai": {
                "name": "EF.SUPI_NAI",
                "fid": "4F09",
                "structure": "transparent",
                "sfi": None,
            },
            "ef-supi-nai": {
                "name": "EF.SUPI-NAI",
                "fid": "4F09",
                "structure": "transparent",
                "sfi": None,
            },
        }
        aliases = pysim_alias_specs_for(specs)

        self.assertNotIn("ef-supi-nai", aliases)

    def test_alias_dict_is_independent_copy(self) -> None:
        specs = {
            "ef-supinai": {
                "name": "EF.SUPI_NAI",
                "fid": "4F09",
                "structure": "transparent",
                "sfi": None,
            },
        }
        aliases = pysim_alias_specs_for(specs)
        self.assertIn("ef-supi-nai", aliases)

        aliases["ef-supi-nai"]["sfi"] = 99
        self.assertNotEqual(specs["ef-supinai"].get("sfi"), 99)


class FileSpecsAuthoritativeSfiTests(unittest.TestCase):
    """End-to-end: the production ``_FILE_SPECS`` carries pySim SFIs."""

    EXPECTED_SFIS: tuple[tuple[str, int], ...] = (
        ("ef-imsi", 7),
        ("ef-keys", 8),
        ("ef-keysPS", 9),
        ("ef-hpplmn", 18),
        ("ef-ust", 4),
        ("ef-est", 5),
        ("ef-acc", 6),
        ("ef-fplmn", 13),
        ("ef-loci", 11),
        ("ef-ad", 3),
        ("ef-ecc", 1),
        ("ef-epsloci", 30),
        ("ef-epsnsc", 24),
        ("ef-cbmid", 14),
        ("ef-spdi", 27),
        ("ef-pnn", 25),
        ("ef-opl", 26),
        ("ef-ehplmn", 29),
        ("ef-ici", 20),
        ("ef-oci", 21),
        ("ef-ccp2", 22),
        ("ef-plmnwact", 10),
        ("ef-oplmnwact", 17),
        ("ef-hplmnwact", 19),
        ("ef-start-hfn", 15),
        ("ef-threshold", 16),
        ("ef-psloci", 12),
    )

    def test_modem_traffic_efs_have_authoritative_sfis(self) -> None:
        for pe_name, expected_sfi in self.EXPECTED_SFIS:
            with self.subTest(pe_name=pe_name):
                spec = _FILE_SPECS.get(pe_name)
                self.assertIsNotNone(spec, f"_FILE_SPECS missing {pe_name!r}")
                self.assertEqual(
                    spec["sfi"],
                    expected_sfi,
                    f"_FILE_SPECS[{pe_name!r}] sfi expected {expected_sfi}, got {spec['sfi']}",
                )

    def test_fids_remain_at_simulator_anchors(self) -> None:
        # Spot-check entries where pySim's pe_name maps to a different
        # parent context (DF.TELECOM EF.ADN at 4F67 vs simulator's
        # legacy 6F3A). The simulator anchor must win.
        adn = _FILE_SPECS.get("ef-adn")
        self.assertIsNotNone(adn)
        self.assertEqual(adn["fid"], "6F3A")

        iccid = _FILE_SPECS.get("ef-iccid")
        self.assertIsNotNone(iccid)
        self.assertEqual(iccid["fid"], "2FE2")
        self.assertEqual(iccid["sfi"], 0x02)

    def test_local_only_entries_survive(self) -> None:
        for pe_name in ("ef-imsi-m", "ef-cdmahome", "ef-prl", "ef-ah", "ef-aop"):
            with self.subTest(pe_name=pe_name):
                self.assertIn(pe_name, _FILE_SPECS)

    def test_supi_nai_alias_present_in_production_table(self) -> None:
        alias = _FILE_SPECS.get("ef-supi-nai")
        self.assertIsNotNone(alias)
        self.assertEqual(alias["fid"], "4F09")
        self.assertEqual(alias["sfi"], 9)
        self.assertEqual(alias.get("alias_of"), "ef-supinai")


class AugmentationGracefulDegradationTests(unittest.TestCase):
    """The augmenter must no-op cleanly even on a stripped-down spec dict."""

    def test_empty_specs_dict_is_returned_unchanged(self) -> None:
        specs: dict[str, dict[str, Any]] = {}
        result = apply_pysim_augmentations(specs)

        self.assertIs(result, specs)
        self.assertEqual(specs, {})

    def test_pe_name_unknown_to_pysim_is_left_alone(self) -> None:
        specs = {
            "ef-totally-fake": {
                "name": "EF.TOTALLY-FAKE",
                "fid": "BEEF",
                "structure": "transparent",
                "sfi": None,
            }
        }
        apply_pysim_augmentations(specs)

        self.assertEqual(specs["ef-totally-fake"]["fid"], "BEEF")
        self.assertEqual(specs["ef-totally-fake"]["sfi"], None)
        self.assertNotIn("arr", specs["ef-totally-fake"])


if __name__ == "__main__":
    unittest.main()
