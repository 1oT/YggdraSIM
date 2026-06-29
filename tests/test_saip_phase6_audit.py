# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Decoded-EF + template-OID coverage audit.

These tests assert lower-bound coverage thresholds the YggdraSIM
roundtrip-editor registry must meet. They double as a regression
guard: if anyone deletes EFs from the decoded-editor registry the
suite trips.

PE-SSIM coverage is intentionally NOT asserted — the in-tree pySim
3.3.1 ASN.1 schema does not yet ship an SSIM PE definition, so any
SSIM editor would be encoding bytes pySim refuses to round-trip.
This is documented in the dispatcher catalog audit below.
"""

from __future__ import annotations

import unittest


class DecodedEfCoverageTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_dispatcher_returns_split_buckets(self) -> None:
        result = self._actions._dispatch_list_interpreted_efs(ctx=None)
        self.assertIn("round_trip", result)
        self.assertIn("lossy_splice", result)
        self.assertIn("total", result)

    def test_total_above_minimum_floor(self) -> None:
        # The Phase-6 audit floor is 100 EFs — well below the actual
        # 185 the registry currently carries. The floor is a regression
        # guard, not the target.
        result = self._actions._dispatch_list_interpreted_efs(ctx=None)
        self.assertGreaterEqual(result["total"], 100)

    def test_round_trip_includes_core_3gpp_efs(self) -> None:
        result = self._actions._dispatch_list_interpreted_efs(ctx=None)
        round_trip = set(result["round_trip"])
        # Spot-check: every profile carries these and they all need
        # structured editors per the manual.
        for required in (
            "ef-spn",
            "ef-pnn",
            "ef-loci",
            "ef-psloci",
            "ef-epsloci",
            "ef-ust",
            "ef-est",
            "ef-ist",
            "ef-gid1",
            "ef-cbmi",
        ):
            self.assertIn(required, round_trip, f"{required!r} missing from round_trip catalog")

    def test_lossy_splice_includes_record_based_efs(self) -> None:
        result = self._actions._dispatch_list_interpreted_efs(ctx=None)
        lossy = set(result["lossy_splice"])
        # ADN / FDN / SDN / SMS-P / MSISDN are record-based EFs whose
        # editors necessarily re-encode from the decoded form.
        for required in ("ef-adn", "ef-fdn", "ef-sdn", "ef-msisdn", "ef-smsp"):
            self.assertIn(required, lossy, f"{required!r} missing from lossy_splice catalog")

    def test_round_trip_includes_5g_efs(self) -> None:
        result = self._actions._dispatch_list_interpreted_efs(ctx=None)
        round_trip = set(result["round_trip"])
        for required in (
            "ef-5gs3gpploci",
            "ef-5gauthkeys",
            "ef-5g-suci-calc-info",
            "ef-routing-indicator",
            "ef-ursp",
        ):
            self.assertIn(required, round_trip, f"{required!r} missing")


class TemplateOidCatalogTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        self._actions = saip_actions

    def test_template_catalog_returns_pysim_oids(self) -> None:
        result = self._actions._dispatch_list_template_oids(ctx=None)
        self.assertGreaterEqual(result["count"], 10)
        oids = {row["oid"] for row in result["templates"]}
        # The well-known TCA SAIP §A.2 root OIDs must be present.
        for required in (
            "2.23.143.1.2.1",
            "2.23.143.1.2.2",
            "2.23.143.1.2.3",
            "2.23.143.1.2.4",
        ):
            self.assertIn(required, oids, f"template OID {required} missing from registry")

    def test_template_catalog_rows_carry_class_name(self) -> None:
        result = self._actions._dispatch_list_template_oids(ctx=None)
        for row in result["templates"]:
            self.assertIn("oid", row)
            self.assertIn("class", row)
            self.assertGreater(len(row["class"]), 0)


class PeSsimDeferralTests(unittest.TestCase):
    """Document why PE-SSIM has no editor in this release.

    PE-SSIM lives in TCA SAIP §A.2 only from version 3.4 onwards. The
    in-tree pySim 3.3.1 ASN.1 schema (``PE_Definitions-3.3.1.asn``)
    does NOT define PE-SSIM, so any editor we shipped would encode
    bytes the pySim encoder refuses to round-trip. We therefore wait
    for the upstream pySim bump.
    """

    def test_no_ssim_pe_in_pysim_schema(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from pathlib import Path
        repo_root = Path(__file__).resolve().parents[1]
        schema_path = (
            repo_root
            / "pysim"
            / "pySim"
            / "esim"
            / "asn1"
            / "saip"
            / "PE_Definitions-3.3.1.asn"
        )
        if schema_path.is_file() is False:
            self.skipTest(f"pySim ASN.1 schema not found at {schema_path}")
        text = schema_path.read_text(encoding="utf-8")
        # If this assertion ever flips, pySim has shipped SSIM and
        # we can lift the deferral.
        self.assertNotIn("PE-SSIM", text)
        self.assertNotIn("ssimParameter", text)


if __name__ == "__main__":
    unittest.main()
