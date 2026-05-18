# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit tests for ``saip_rfm_edit``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_rfm_edit as rfm_edit


def _empty_rfm() -> dict:
    return {
        "rfm-header": {},
        "instanceAID": bytes.fromhex("A0000000871002"),
        "minimumSecurityLevel": bytes([0x00]),
        "uiccAccessDomain": b"",
        "uiccAdminAccessDomain": b"",
    }


class LocateRfmSectionsTests(unittest.TestCase):

    def test_returns_rfm_sections(self) -> None:
        doc = {
            "sections": {
                "header": {},
                "rfm": _empty_rfm(),
                "anotherRfm": _empty_rfm(),
                "noiseSection": {"foo": "bar"},
            }
        }
        keys = sorted(k for k, _ in rfm_edit.locate_rfm_sections(doc))
        self.assertEqual(keys, ["anotherRfm", "rfm"])


class TarListTests(unittest.TestCase):

    def test_add_first_tar_creates_list(self) -> None:
        rfm = _empty_rfm()
        msg = rfm_edit.add_tar(rfm, "B00001")
        self.assertIn("B00001", msg)
        self.assertEqual(rfm["tarList"], [bytes.fromhex("B00001")])

    def test_add_three_tars(self) -> None:
        rfm = _empty_rfm()
        for tar in ("B00001", "B00002", "B00003"):
            rfm_edit.add_tar(rfm, tar)
        self.assertEqual(len(rfm["tarList"]), 3)

    def test_duplicate_tar_rejected(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.add_tar(rfm, "B00001")
        with self.assertRaises(ValueError):
            rfm_edit.add_tar(rfm, "B00001")

    def test_tar_must_be_three_bytes(self) -> None:
        with self.assertRaises(ValueError):
            rfm_edit.add_tar(_empty_rfm(), "B000")  # 2 bytes
        with self.assertRaises(ValueError):
            rfm_edit.add_tar(_empty_rfm(), "B0000001")  # 4 bytes

    def test_remove_tar(self) -> None:
        rfm = _empty_rfm()
        for tar in ("B00001", "B00002"):
            rfm_edit.add_tar(rfm, tar)
        rfm_edit.remove_tar(rfm, "B00001")
        self.assertEqual(rfm["tarList"], [bytes.fromhex("B00002")])

    def test_remove_last_tar_drops_list(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.add_tar(rfm, "B00001")
        rfm_edit.remove_tar(rfm, "B00001")
        self.assertNotIn("tarList", rfm)

    def test_remove_missing_tar_raises(self) -> None:
        with self.assertRaises(LookupError):
            rfm_edit.remove_tar(_empty_rfm(), "B00001")

    def test_set_tar_list_round_trip(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_tar_list(rfm, ["B00001", "B00002", "B00003"])
        self.assertEqual(len(rfm["tarList"]), 3)

    def test_set_tar_list_rejects_duplicates_in_input(self) -> None:
        with self.assertRaises(ValueError):
            rfm_edit.set_tar_list(_empty_rfm(), ["B00001", "B00001"])

    def test_set_tar_list_empty_clears(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.add_tar(rfm, "B00001")
        rfm_edit.set_tar_list(rfm, [])
        self.assertNotIn("tarList", rfm)


class ScalarTests(unittest.TestCase):

    def test_set_minimum_security_level(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_minimum_security_level(rfm, 0x12)
        self.assertEqual(rfm["minimumSecurityLevel"], bytes([0x12]))

    def test_set_security_domain_aid(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_security_domain_aid_hex(rfm, "A0000001515350")
        self.assertEqual(rfm["securityDomainAID"], bytes.fromhex("A0000001515350"))

    def test_set_security_domain_aid_clear(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_security_domain_aid_hex(rfm, "A0000001515350")
        rfm_edit.set_security_domain_aid_hex(rfm, "")
        self.assertNotIn("securityDomainAID", rfm)


class AdfBindingTests(unittest.TestCase):

    def test_set_adf_access_round_trip(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_adf_access(
            rfm,
            adf_aid_hex="A0000000871002",
            adf_access_domain_hex="01",
            adf_admin_access_domain_hex="02",
        )
        block = rfm["adfRFMAccess"]
        self.assertEqual(block["adfAID"], bytes.fromhex("A0000000871002"))
        self.assertEqual(block["adfAccessDomain"], bytes.fromhex("01"))
        self.assertEqual(block["adfAdminAccessDomain"], bytes.fromhex("02"))

    def test_set_adf_access_replaces_existing(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_adf_access(rfm, adf_aid_hex="A0000000871002")
        rfm_edit.set_adf_access(rfm, adf_aid_hex="A0000005591010")
        self.assertEqual(rfm["adfRFMAccess"]["adfAID"], bytes.fromhex("A0000005591010"))

    def test_remove_adf_access(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.set_adf_access(rfm, adf_aid_hex="A0000000871002")
        rfm_edit.remove_adf_access(rfm)
        self.assertNotIn("adfRFMAccess", rfm)

    def test_remove_missing_adf_access_raises(self) -> None:
        with self.assertRaises(LookupError):
            rfm_edit.remove_adf_access(_empty_rfm())


class SummaryTests(unittest.TestCase):

    def test_summary_round_trip(self) -> None:
        rfm = _empty_rfm()
        rfm_edit.add_tar(rfm, "B00001")
        rfm_edit.add_tar(rfm, "B00002")
        rfm_edit.set_minimum_security_level(rfm, 0x12)
        rfm_edit.set_adf_access(rfm, adf_aid_hex="A0000000871002")
        summary = rfm_edit.rfm_summary(rfm)
        self.assertEqual(summary["instance_aid_hex"], "A0000000871002")
        self.assertEqual(summary["tar_list"], ["B00001", "B00002"])
        self.assertEqual(summary["minimum_security_level"], 0x12)
        self.assertEqual(summary["adf_access"]["adf_aid_hex"], "A0000000871002")


if __name__ == "__main__":
    unittest.main()
