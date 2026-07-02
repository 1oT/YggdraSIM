# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit tests for ``saip_profile_header_edit``.

These exercise the spec-aware mutators without requiring a full SAIP
ASN.1 round-trip — every helper operates on a dict-shaped header
section. The integration with ``build_profile_sequence_from_document``
is exercised in the action-dispatcher tests.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_profile_header_edit as ph


class LocateHeaderSectionTests(unittest.TestCase):

    def test_finds_canonical_header_key(self) -> None:
        doc = {"sections": {"header": {"major-version": 2, "iccid": b"\x00" * 10}}}
        key, header = ph.locate_header_section(doc)
        self.assertEqual(key, "header")
        self.assertEqual(header["major-version"], 2)

    def test_finds_legacy_profile_header_key(self) -> None:
        doc = {"sections": {"profileHeader": {"major-version": 3}}}
        key, header = ph.locate_header_section(doc)
        self.assertEqual(key, "profileHeader")

    def test_raises_when_missing(self) -> None:
        with self.assertRaises(LookupError):
            ph.locate_header_section({"sections": {"end": {}}})


class ScalarFieldTests(unittest.TestCase):

    def test_set_profile_type_round_trip(self) -> None:
        header: dict = {}
        msg = ph.set_profile_type(header, "Lab v1")
        self.assertIn("Lab v1", msg)
        self.assertEqual(header["profileType"], "Lab v1")

    def test_set_profile_type_clear_drops_key(self) -> None:
        header: dict = {"profileType": "old"}
        ph.set_profile_type(header, "  ")
        self.assertNotIn("profileType", header)

    def test_set_profile_type_rejects_oversize(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_profile_type({}, "X" * 101)

    def test_set_iccid_digits_19_pads_with_F(self) -> None:
        header: dict = {}
        ph.set_iccid_digits(header, "8988201234567890123")
        self.assertEqual(len(header["iccid"]), 10)
        # ProfileHeader stores the ICCID in header-order hex; EF.ICCID
        # is the swapped-BCD form handled by the sync helper below.
        self.assertEqual(header["iccid"][0], 0x89)

    def test_sync_header_iccid_from_ef_iccid(self) -> None:
        doc = {
            "sections": {
                "header": {},
                "mf": {
                    "ef-iccid": {
                        "fillFileContent": bytes.fromhex("988802214365870921F3"),
                    },
                },
            },
        }
        msg = ph.sync_header_iccid_from_ef(doc)
        self.assertIn("iccid set", msg)
        self.assertEqual(
            doc["sections"]["header"]["iccid"],
            bytes.fromhex("8988201234567890123F"),
        )

    def test_set_iccid_digits_rejects_wrong_length(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_iccid_digits({}, "1234")

    def test_set_iccid_hex_must_be_10_bytes(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_iccid_hex({}, "DEADBEEF")

    def test_set_pol_clear_drops_key(self) -> None:
        header: dict = {"pol": b"\x04"}
        ph.set_pol_hex(header, "")
        self.assertNotIn("pol", header)

    def test_set_pol_rejects_non_hex(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_pol_hex({}, "not-hex")


class MajorMinorVersionTests(unittest.TestCase):

    def test_both_versions_round_trip(self) -> None:
        header: dict = {}
        msg = ph.set_major_minor_version(header, major=3, minor=4)
        self.assertEqual(header["major-version"], 3)
        self.assertEqual(header["minor-version"], 4)
        self.assertIn("major-version=3", msg)
        self.assertIn("minor-version=4", msg)

    def test_only_minor_leaves_major_alone(self) -> None:
        header: dict = {"major-version": 3}
        ph.set_major_minor_version(header, minor=4)
        self.assertEqual(header["major-version"], 3)
        self.assertEqual(header["minor-version"], 4)

    def test_string_input_accepted(self) -> None:
        header: dict = {}
        ph.set_major_minor_version(header, major="3", minor="3")
        self.assertEqual(header["major-version"], 3)
        self.assertEqual(header["minor-version"], 3)

    def test_clear_with_empty_string_drops_field(self) -> None:
        header: dict = {"major-version": 3, "minor-version": 3}
        ph.set_major_minor_version(header, major="")
        self.assertNotIn("major-version", header)
        self.assertEqual(header["minor-version"], 3)

    def test_out_of_uint8_range_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_major_minor_version({}, major=256)
        with self.assertRaises(ValueError):
            ph.set_major_minor_version({}, minor=-1)

    def test_non_integer_input_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_major_minor_version({}, major="three")

    def test_no_kwargs_is_noop(self) -> None:
        header: dict = {"major-version": 3, "minor-version": 3}
        msg = ph.set_major_minor_version(header)
        self.assertEqual(header["major-version"], 3)
        self.assertEqual(header["minor-version"], 3)
        self.assertIn("no version", msg)


class MandatoryServicesTests(unittest.TestCase):

    def test_only_truthy_keys_kept_as_null(self) -> None:
        header: dict = {}
        ph.set_mandatory_services(
            header,
            {"usim": True, "isim": False, "milenage": True},
        )
        self.assertEqual(
            header["eUICC-Mandatory-services"],
            {"usim": None, "milenage": None},
        )

    def test_unknown_service_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_mandatory_services({}, {"not-a-service": True})

    def test_full_replace_drops_old_entries(self) -> None:
        header: dict = {"eUICC-Mandatory-services": {"old": None}}
        ph.set_mandatory_services(header, {"usim": True})
        self.assertEqual(
            list(header["eUICC-Mandatory-services"].keys()),
            ["usim"],
        )


class MandatoryGfsteTests(unittest.TestCase):

    def test_normalises_and_filters_blanks(self) -> None:
        header: dict = {}
        ph.set_mandatory_gfste(
            header,
            ["2.23.143.1.2.1", "  ", "2.23.143.1.2.4"],
        )
        self.assertEqual(
            header["eUICC-Mandatory-GFSTEList"],
            ["2.23.143.1.2.1", "2.23.143.1.2.4"],
        )

    def test_rejects_non_oid_strings(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_mandatory_gfste({}, ["abc"])

    def test_empty_list_still_writes_empty(self) -> None:
        header: dict = {"eUICC-Mandatory-GFSTEList": ["2.23.143.1.2.1"]}
        ph.set_mandatory_gfste(header, [])
        self.assertEqual(header["eUICC-Mandatory-GFSTEList"], [])


class MandatoryAidsTests(unittest.TestCase):

    def test_round_trip_two_aids(self) -> None:
        header: dict = {}
        ph.set_mandatory_aids(
            header,
            [
                {"aid": "A0000000871002", "version": "0100"},
                {"aid_hex": "A0000000871004", "version_hex": "0200"},
            ],
        )
        self.assertEqual(len(header["eUICC-Mandatory-AIDs"]), 2)
        self.assertEqual(header["eUICC-Mandatory-AIDs"][0]["aid"], bytes.fromhex("A0000000871002"))
        self.assertEqual(header["eUICC-Mandatory-AIDs"][0]["version"], bytes.fromhex("0100"))

    def test_aid_too_short_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_mandatory_aids({}, [{"aid": "A001", "version": "0100"}])

    def test_version_must_be_2_bytes(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_mandatory_aids({}, [{"aid": "A0000000871002", "version": "010203"}])

    def test_empty_list_drops_key(self) -> None:
        header: dict = {"eUICC-Mandatory-AIDs": [{"aid": b"\x01" * 5, "version": b"\x00\x00"}]}
        ph.set_mandatory_aids(header, [])
        self.assertNotIn("eUICC-Mandatory-AIDs", header)


class ConnectivityParametersTests(unittest.TestCase):

    def test_round_trip_hex(self) -> None:
        header: dict = {}
        ph.set_connectivity_parameters_hex(header, "A1 18 35 07")
        self.assertEqual(header["connectivityParameters"], bytes.fromhex("A1183507"))

    def test_clear(self) -> None:
        header: dict = {"connectivityParameters": b"\x01\x02"}
        ph.set_connectivity_parameters_hex(header, "")
        self.assertNotIn("connectivityParameters", header)


class IotPixTests(unittest.TestCase):

    def test_round_trip(self) -> None:
        header: dict = {}
        ph.set_iot_pix_hex(header, "00112233445566")
        self.assertEqual(header["iotOptions"]["pix"], bytes.fromhex("00112233445566"))

    def test_too_short_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_iot_pix_hex({}, "0011")

    def test_too_long_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ph.set_iot_pix_hex({}, "00" * 12)

    def test_clear(self) -> None:
        header: dict = {"iotOptions": {"pix": b"\x00" * 7}}
        ph.set_iot_pix_hex(header, "")
        self.assertNotIn("iotOptions", header)


class HeaderSummaryTests(unittest.TestCase):

    def test_summary_round_trips_iccid_digits(self) -> None:
        header: dict = {}
        ph.set_iccid_digits(header, "8988201234567890123")
        ph.set_profile_type(header, "Lab profile")
        ph.set_mandatory_services(header, {"usim": True, "milenage": True})
        ph.set_mandatory_gfste(header, ["2.23.143.1.2.1"])
        summary = ph.header_summary(header)
        self.assertEqual(summary["profile_type"], "Lab profile")
        self.assertEqual(summary["iccid_digits"], "8988201234567890123")
        self.assertIn("usim", summary["mandatory_services"])
        self.assertEqual(summary["mandatory_gfste"], ["2.23.143.1.2.1"])

    def test_summary_handles_missing_optional_fields(self) -> None:
        header: dict = {"major-version": 2, "minor-version": 3, "iccid": b""}
        summary = ph.header_summary(header)
        self.assertEqual(summary["profile_type"], "")
        self.assertEqual(summary["iccid_digits"], "")
        self.assertEqual(summary["pol_hex"], "")
        self.assertEqual(summary["mandatory_aids"], [])


if __name__ == "__main__":
    unittest.main()
