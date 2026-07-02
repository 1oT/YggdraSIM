# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for pySim service-table overlays.

Pins the ``saip_pysim_specs`` helpers used to replace the inspector's
hand-curated bit -> service-name dictionaries:

  * ``pysim_service_table`` -- imports pySim's authoritative
    ``EF_UST_map`` / ``EF_EST_map`` / ``EF_IST_map`` /
    ``EF_5G_PROSE_ST_map`` / ``EF_SST_map`` (TS 31.102, TS 31.103,
    TS 51.011) and exposes them as plain dicts.
  * ``overlay_pysim_service_names`` -- mutates a target dict in place
    while degrading gracefully when pySim is unavailable.
  * ``apply_pysim_service_table_overlay_to_inspector`` -- replaces the
    SAIP inspector's ``_UST_SERVICE_NAMES`` / ``_EST_SERVICE_NAMES`` /
    ``_ISIM_SERVICE_NAMES`` dicts with the pySim copies so a live-card
    dump and an inspector pass agree on every bit's label.

The asserts deliberately compare against pySim's *string* values
rather than the local copies so a TS-revision-induced drift in either
side triggers a regression here.
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_pysim_specs import (
    apply_pysim_service_table_overlay_to_inspector,
    overlay_pysim_service_names,
    pysim_service_table,
    reset_pysim_service_table_cache,
)


def _has_pysim_service_tables() -> bool:
    """Return ``True`` only if pySim's service-name maps import cleanly."""

    reset_pysim_service_table_cache()
    return bool(pysim_service_table("UST"))


class PySimServiceTableImportTests(unittest.TestCase):
    """``pysim_service_table`` returns a copy of pySim's TS maps."""

    def setUp(self) -> None:
        reset_pysim_service_table_cache()

    def test_ust_map_covers_documented_5g_services(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        ust = pysim_service_table("UST")

        self.assertEqual(ust[1], "Local Phone Book")
        self.assertEqual(ust[125], "SUCI calculation by the USIM")
        self.assertEqual(ust[139], "5G ProSe")
        self.assertEqual(ust[146], "Network Identifier for SNPN (NID)")

    def test_est_map_lists_only_three_services(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        est = pysim_service_table("EST")

        self.assertEqual(
            est,
            {
                1: "Fixed Dialling Numbers (FDN)",
                2: "Barred Dialling Numbers (BDN)",
                3: "APN Control List (ACL)",
            },
        )

    def test_ist_map_carries_isim_specific_strings(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        ist = pysim_service_table("IST")

        self.assertEqual(ist[1], "P-CSCF address")
        self.assertEqual(ist[2], "Generic Bootstrapping Architecture (GBA)")
        self.assertEqual(ist[15], "MCPTT")

    def test_5g_prose_map_describes_five_buckets(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        prose = pysim_service_table("5G_PROSE_ST")

        self.assertEqual(len(prose), 5)
        self.assertIn("direct discovery", prose[1])
        self.assertIn("UE-to-network relay", prose[3])

    def test_sst_map_includes_legacy_gsm_services(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        sst = pysim_service_table("SST")

        self.assertEqual(sst[1], "CHV1 disable function")
        self.assertEqual(sst[3], "Fixed Dialling Numbers (FDN)")
        self.assertEqual(sst[38], "GPRS")

    def test_unknown_table_name_returns_empty_dict(self) -> None:
        self.assertEqual(pysim_service_table("does-not-exist"), {})

    def test_returned_dict_is_a_copy_not_the_cache(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        first = pysim_service_table("UST")
        first[9999] = "scribble"
        second = pysim_service_table("UST")
        self.assertNotIn(9999, second)


class PySimOverlayTests(unittest.TestCase):
    """``overlay_pysim_service_names`` mutates the target in place."""

    def test_overlay_applies_pysim_values_to_target_dict(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        target: dict[int, str] = {1: "stale", 200: "local-only"}
        result = overlay_pysim_service_names(target, "UST")

        self.assertIs(result, target)
        self.assertEqual(target[1], "Local Phone Book")
        self.assertEqual(target[200], "local-only")

    def test_overlay_with_unknown_table_is_a_noop(self) -> None:
        target: dict[int, str] = {1: "kept"}
        overlay_pysim_service_names(target, "no-such-table")
        self.assertEqual(target, {1: "kept"})


class InspectorOverlayIntegrationTests(unittest.TestCase):
    """Integration test for the SAIP inspector dict overlay."""

    def test_overlay_synchronises_inspector_with_pysim(self) -> None:
        if not _has_pysim_service_tables():
            self.skipTest("pySim not installed")

        from Tools.ProfilePackage import saip_asn1_decode

        applied = apply_pysim_service_table_overlay_to_inspector()

        self.assertIn("UST", applied)
        self.assertIn("EST", applied)
        self.assertIn("IST", applied)
        self.assertGreaterEqual(applied["UST"], 100)

        ust = pysim_service_table("UST")
        ist = pysim_service_table("IST")
        for bit, expected in ust.items():
            self.assertEqual(saip_asn1_decode._UST_SERVICE_NAMES[bit], expected)
        for bit, expected in ist.items():
            self.assertEqual(saip_asn1_decode._ISIM_SERVICE_NAMES[bit], expected)

    def test_overlay_keeps_locally_only_services(self) -> None:
        from Tools.ProfilePackage import saip_asn1_decode

        saip_asn1_decode._UST_SERVICE_NAMES[9999] = "local-canary"
        try:
            apply_pysim_service_table_overlay_to_inspector()
            self.assertEqual(
                saip_asn1_decode._UST_SERVICE_NAMES[9999],
                "local-canary",
            )
        finally:
            saip_asn1_decode._UST_SERVICE_NAMES.pop(9999, None)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
