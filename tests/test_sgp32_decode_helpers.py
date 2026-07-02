# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest

from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
from SCP03.logic.sgp32_decode import decode_euicc_info1_summary
from SCP03.logic.sgp32_decode import decode_get_certs_response
from SCP03.logic.sgp32_decode import decode_notifications_response
from SCP03.logic.sgp32_decode import decode_rat_rules


DUMMY_TEST_EIM_OID = "2.25.311782205282738360923618091971140414400"


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_length(len(value)) + value


class Sgp32DecodeHelperTests(unittest.TestCase):
    def test_decode_euicc_info1_summary_formats_svn(self) -> None:
        response = bytes.fromhex(
            "BF20358203020600A916041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "AA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
        )

        summary = decode_euicc_info1_summary(response)

        self.assertEqual(summary["svn"], "v2.6.0 (020600)")
        self.assertEqual(summary["ci_pk_verify_entries"], 1)
        self.assertEqual(summary["ci_pk_sign_entries"], 1)

    def test_decode_notifications_response_decodes_notification_fields(self) -> None:
        notification = b"".join(
            [
                tlv("80", b"\x07"),
                tlv("81", bytes.fromhex("04C0")),
                tlv("0C", b"notify.example.com"),
                tlv("5A", bytes.fromhex("981032547698103254F6")),
            ]
        )
        response = tlv("BF2B", tlv("A0", tlv("BF2F", notification)))

        decoded = decode_notifications_response(response)

        self.assertEqual(len(decoded["notifications"]), 1)
        first = decoded["notifications"][0]
        self.assertEqual(first["seqNumber"], "7")
        self.assertIn("notificationInstall", first["operation"])
        self.assertIn("notificationEnable", first["operation"])
        self.assertEqual(first["notificationAddress"], '"notify.example.com"')
        self.assertEqual(first["iccid"], "8901234567890123456")

    def test_decode_rat_rules_preserves_rule_structure(self) -> None:
        rule = tlv(
            "30",
            b"".join(
                [
                    tlv("80", bytes.fromhex("0560")),
                    tlv(
                        "A1",
                        tlv(
                            "30",
                            b"".join(
                                [
                                    tlv("80", bytes.fromhex("EEEEEE")),
                                    tlv("81", b""),
                                    tlv("82", b""),
                                ]
                            ),
                        ),
                    ),
                    tlv("82", bytes.fromhex("0780")),
                ]
            ),
        )
        response = tlv("BF43", tlv("A0", rule))

        rules = decode_rat_rules(response)

        self.assertGreaterEqual(len(rules), 1)
        self.assertEqual(rules[0]["pprIdsRaw"], "0560")
        self.assertIn("ppr1-disable-not-allowed", rules[0]["pprIds"])
        self.assertEqual(rules[0]["allowedOperators"][0]["mccMnc"], "EEEEEE")
        self.assertIn("consentRequired", rules[0]["pprFlags"])

    def test_decode_get_certs_response_decodes_error_choice(self) -> None:
        response = tlv("BF56", tlv("81", b"\x01"))

        decoded = decode_get_certs_response(response)

        self.assertEqual(decoded["error"], "invalidCiPKId")

    def test_decode_get_certs_response_finds_nested_certificate_blocks(self) -> None:
        response = tlv(
            "BF56",
            b"".join(
                [
                    tlv("A0", tlv("A5", tlv("30", b"\x01\x02\x03"))),
                    tlv("A1", tlv("A6", tlv("30", b"\x04\x05\x06"))),
                ]
            ),
        )

        decoded = decode_get_certs_response(response)

        self.assertEqual(decoded["eumCertificate"], tlv("30", b"\x01\x02\x03"))
        self.assertEqual(decoded["euiccCertificate"], tlv("30", b"\x04\x05\x06"))

    def test_decode_eim_configuration_entries_keeps_entry_without_fqdn(self) -> None:
        entry = b"".join(
            [
                tlv("80", DUMMY_TEST_EIM_OID.encode("utf-8")),
                tlv("82", b"\x01"),
                tlv("83", b"\x05"),
                tlv("84", b"\x10"),
                tlv("87", bytes.fromhex("0780")),
                tlv("88", bytes.fromhex("81370F5125D0B1D408D4C3B232E6D25E795BEBFB")),
                tlv("89", b""),
            ]
        )
        response = tlv("BF55", tlv("A0", tlv("30", entry)))

        entries = decode_eim_configuration_entries(response)

        self.assertEqual(len(entries), 1)
        first = entries[0]
        self.assertEqual(first["eim_id"], DUMMY_TEST_EIM_OID)
        self.assertEqual(first["eim_id_type"], "eimIdTypeOid (1)")
        self.assertEqual(first["counter_value"], "5")
        self.assertEqual(first["association_token"], "16")
        self.assertIn("eimRetrieveHttps", first["supported_protocol"])
        self.assertEqual(first["indirect_profile_download"], "Present")


if __name__ == "__main__":
    unittest.main()
