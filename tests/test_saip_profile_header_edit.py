# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit tests for ``saip_profile_header_edit``.

These exercise the spec-aware mutators without requiring a full SAIP
ASN.1 round-trip -- every helper operates on a dict-shaped header
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


# 3GPP TS 31.102 v18.4.0 §4.2.27: Y alpha bytes, Parameter Indicators,
# 12-byte TP-Destination Address, 12-byte TS-Service Centre Address (a
# length byte, TON/NPI and swapped BCD digits per TS 24.011 §8.2.5.2),
# TP-PID, TP-DCS, TP-VP. The number below is the NANP fictional range.
_SMSC_SCA_HEX = "07912120550501F0"
_SMSC_DIGITS = "12025550100"


def _smsp_record(alpha_len: int, indicators: int, sca_hex: str = _SMSC_SCA_HEX) -> bytes:
    return bytes.fromhex(
        "FF" * alpha_len + f"{indicators:02X}" + "FF" * 12 + sca_hex.ljust(24, "F") + "FFFFFF"
    )


def _gfm_smsp_group(record_size: int, indicators: int, sca_hex: str = _SMSC_SCA_HEX) -> list:
    alpha = record_size - 28
    return [
        ("filePath", bytes.fromhex("7F10")),
        ("createFCP", {
            "fileDescriptor": bytes.fromhex(f"4221{record_size:04X}"),
            "fileID": bytes.fromhex("6F42"),
            "efFileSize": bytes([record_size]),
        }),
        ("fillFileOffset", alpha),
        ("fillFileContent", bytes([indicators])),
        ("fillFileOffset", 12),
        ("fillFileContent", bytes.fromhex(sca_hex)),
    ]


def _connectivity(bearers: list) -> bytes:
    from Tools.ProfilePackage.saip_connectivity_parameters import encode_connectivity_parameters

    return bytes.fromhex(encode_connectivity_parameters(bearers))


_HTTPS_BEARER = {
    "bearer": "https",
    "bearer_description_hex": "02000003000002",
    "network_access_name": {"text": "apn"},
}


def _sms_bearer(digits: str) -> dict:
    return {
        "bearer": "sms",
        "dialing_number": {"ton": "international", "npi": "isdn", "digits": digits},
        "pid_hex": "7F",
        "dcs_hex": "F6",
    }


class SyncSmscFromEfSmspTests(unittest.TestCase):

    def _document(self, ef_smsp: list, *, connectivity: bytes | None, gfm: list | None = None) -> dict:
        header: dict = {}
        if connectivity is not None:
            header["connectivityParameters"] = connectivity
        sections: dict = {"header": header}
        if gfm is not None:
            sections["genericFileManagement"] = {"fileManagementCMD": [gfm]}
        sections["usim"] = {"ef-smsp": ef_smsp}
        return {"sections": sections}

    def _sms_numbers(self, header: dict) -> list:
        from Tools.ProfilePackage.saip_connectivity_parameters import decode_connectivity_parameters

        decoded = decode_connectivity_parameters(header["connectivityParameters"].hex())
        return [
            (bearer["bearer"], (bearer.get("dialing_number") or {}).get("digits"))
            for bearer in decoded["bearers"]
        ]

    def test_template_record_with_descriptor_updates_the_sms_bearer(self) -> None:
        # Record length 0x26 = 38: a 10-byte alpha identifier before the tail.
        doc = self._document(
            [
                ("fileDescriptor", {"fileDescriptor": bytes.fromhex("42210026")}),
                ("fillFileContent", _smsp_record(10, 0xFD) + _smsp_record(10, 0xFF, "FF" * 12)),
            ],
            connectivity=_connectivity([_HTTPS_BEARER, _sms_bearer("15550100")]) + b"\xab",
        )
        msg = ph.sync_header_smsc_from_ef_smsp(doc)
        self.assertIn("SMS-PP bearer [1]", msg)
        self.assertIn("usim.ef-smsp", msg)
        header = doc["sections"]["header"]
        self.assertEqual(self._sms_numbers(header), [("https", None), ("sms", _SMSC_DIGITS)])
        # PID, DCS, the other bearer and the trailing byte are kept.
        expected = _connectivity([_HTTPS_BEARER, _sms_bearer(_SMSC_DIGITS)]) + b"\xab"
        self.assertEqual(header["connectivityParameters"], expected)

    def test_whole_body_is_one_record_without_a_size(self) -> None:
        doc = self._document(
            [("fillFileContent", _smsp_record(4, 0xFD))],
            connectivity=_connectivity([_sms_bearer("15550100")]),
        )
        ph.sync_header_smsc_from_ef_smsp(doc)
        self.assertEqual(self._sms_numbers(doc["sections"]["header"]), [("sms", _SMSC_DIGITS)])

    def test_linked_template_entry_follows_link_path_to_the_gfm_file(self) -> None:
        # The USIM template links ADF.USIM EF.SMSP to DF.TELECOM 7F10/6F42.
        doc = self._document(
            [("fileDescriptor", {"linkPath": bytes.fromhex("7F106F42"), "lcsi": b"\x05"})],
            connectivity=_connectivity([_sms_bearer("15550100")]),
            gfm=_gfm_smsp_group(0x40, 0xFD),
        )
        msg = ph.sync_header_smsc_from_ef_smsp(doc)
        self.assertIn("genericFileManagement.7F10/6F42", msg)
        self.assertEqual(self._sms_numbers(doc["sections"]["header"]), [("sms", _SMSC_DIGITS)])

    def test_bearer_index_selects_one_of_several_sms_bearers(self) -> None:
        doc = self._document(
            [("fillFileContent", _smsp_record(0, 0xFD))],
            connectivity=_connectivity([_sms_bearer("15550100"), _sms_bearer("15550101")]),
        )
        ph.sync_header_smsc_from_ef_smsp(doc, bearer_index="1")
        self.assertEqual(
            self._sms_numbers(doc["sections"]["header"]),
            [("sms", "15550100"), ("sms", _SMSC_DIGITS)],
        )
        with self.assertRaises(ValueError):
            ph.sync_header_smsc_from_ef_smsp(doc, bearer_index="2")
        with self.assertRaises(ValueError):
            ph.sync_header_smsc_from_ef_smsp(doc, bearer_index="one")

    def test_rejects_headers_without_an_sms_bearer(self) -> None:
        doc = self._document(
            [("fillFileContent", _smsp_record(0, 0xFD))],
            connectivity=_connectivity([_HTTPS_BEARER]),
        )
        with self.assertRaisesRegex(ValueError, "no SMS-PP bearer"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        doc = self._document([("fillFileContent", _smsp_record(0, 0xFD))], connectivity=None)
        with self.assertRaisesRegex(ValueError, "no SMS-PP bearer"):
            ph.sync_header_smsc_from_ef_smsp(doc)

    def test_rejects_absent_or_malformed_service_centre_address(self) -> None:
        connectivity = _connectivity([_sms_bearer("15550100")])
        # Parameter Indicators bit 2 set: the address is marked absent.
        doc = self._document([("fillFileContent", _smsp_record(0, 0xFF))], connectivity=connectivity)
        with self.assertRaisesRegex(ValueError, "absent"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        # Present but empty (length byte FF).
        doc = self._document([("fillFileContent", _smsp_record(0, 0xFD, "FF" * 12))], connectivity=connectivity)
        with self.assertRaisesRegex(ValueError, "empty"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        # Length outside 2..11.
        doc = self._document([("fillFileContent", _smsp_record(0, 0xFD, "0C912120550501F0"))], connectivity=connectivity)
        with self.assertRaisesRegex(ValueError, "2..11"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        # Shorter than the 28-byte tail.
        doc = self._document([("fillFileContent", b"\xfd" + b"\xff" * 10)], connectivity=connectivity)
        with self.assertRaisesRegex(ValueError, "at least 28"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        # No EF.SMSP body anywhere.
        doc = self._document([("fileDescriptor", {"linkPath": bytes.fromhex("7F106F42")})], connectivity=connectivity)
        with self.assertRaisesRegex(ValueError, "not found"):
            ph.sync_header_smsc_from_ef_smsp(doc)
        self.assertEqual(doc["sections"]["header"]["connectivityParameters"], connectivity)


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
