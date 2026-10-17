# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec vectors for the telephony EF decoders in ``SCP03.core.decoders``.

Every vector is taken from the clause named on the test, using only the
reserved identifiers (test PLMN 001/01, IIN 8988, NANP fictional numbers).
"""

from __future__ import annotations

import unittest

from SCP03.core.decoders import ContentDecoder


def _reset_registry() -> None:
    ContentDecoder._registry = {}


class PlmnDigitOrderTests(unittest.TestCase):
    """TS 24.008 v19.5 §10.5.1.3 Figure 10.5.3: MNC digit 3 is the last digit."""

    def test_two_digit_mnc_reads_f_in_octet_two_high_nibble(self) -> None:
        self.assertEqual(
            ContentDecoder._decode_plmn_bytes(bytes.fromhex("00F110")), "001-01"
        )

    def test_three_digit_mnc_appends_digit_three(self) -> None:
        # MCC 001, MNC 012: octet 2 = MNC digit 3 (2) | MCC digit 3 (1),
        # octet 3 = MNC digit 2 (1) | MNC digit 1 (0).
        self.assertEqual(
            ContentDecoder._decode_plmn_bytes(bytes.fromhex("002110")), "001-012"
        )

    def test_wildcard_digit_keeps_position(self) -> None:
        self.assertEqual(
            ContentDecoder._decode_plmn_bytes(
                bytes.fromhex("21DD43"), allow_wildcard=True
            ),
            "12*-34*",
        )


class AlphaIdentifierBasePointerTests(unittest.TestCase):
    """TS 102 221 v18.4 Annex A item 2: byte 3 is bits 15..8 of the base pointer."""

    def test_spec_example_half_page_0980(self) -> None:
        self.assertEqual(
            ContentDecoder._decode_alpha_identifier(bytes.fromhex("8102135395")),
            ("Sক", "compressed UCS-2 (0x81)"),
        )

    def test_half_page_above_4000_uses_whole_byte(self) -> None:
        # Byte 3 '9C' -> base pointer '4E00'; offsets 00 and 2D give the
        # CJK ideographs U+4E00 and U+4E2D.
        text, encoding = ContentDecoder._decode_alpha_identifier(
            bytes.fromhex("81029C80AD")
        )
        self.assertEqual(text, "一中")
        self.assertEqual(encoding, "compressed UCS-2 (0x81)")


class LanguageCodeTests(unittest.TestCase):
    """TS 102 221 v18.4 §13.3, TS 31.102 v19.5 §4.2.1 and TS 51.011 v4.15 §10.3.1."""

    def test_two_byte_codes_use_gsm_default_alphabet(self) -> None:
        decoded = ContentDecoder.decode_language_indicators("656EFFFF")
        self.assertEqual(decoded["Preferred Languages"], ["en"])
        self.assertNotIn("Invalid Entries", decoded)

    def test_bit_eight_set_is_not_a_language_code(self) -> None:
        decoded = ContentDecoder.decode_language_indicators("E56E")
        self.assertEqual(decoded["Preferred Languages"], [])
        self.assertEqual(decoded["Invalid Entries"], ["E56E"])

    def test_lp_bytes_are_cbs_dcs_language_values(self) -> None:
        # TS 23.038 v19 §5: '01' English (group 0000), '24' Icelandic (group 0010).
        decoded = ContentDecoder.decode_lp_language_codes("0124FF")
        self.assertEqual(decoded["Preferred Languages"], ["English", "Icelandic"])
        self.assertEqual(decoded["Codes"], ["01", "24"])

    def test_lp_reserved_value_is_named_reserved(self) -> None:
        decoded = ContentDecoder.decode_lp_language_codes("2F")
        self.assertEqual(
            decoded["Preferred Languages"], ["Reserved GSM 7-bit language (0x2F)"]
        )

    def test_registry_routes_li_and_lp_by_context(self) -> None:
        _reset_registry()
        usim = ContentDecoder.decode_raw("6F05", "656EFFFF")
        gsm = ContentDecoder.decode_raw("6F05", "0124", context_path="MF/DF_GSM/EF_LP")
        self.assertEqual(usim["Preferred Languages"], ["en"])
        self.assertEqual(gsm["Preferred Languages"], ["English", "Icelandic"])


class ImsiLengthOctetTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.2.2 and TS 24.008 v19.5 §10.5.1.4 Table 10.5.4."""

    def test_fifteen_digit_imsi(self) -> None:
        decoded = ContentDecoder.decode_imsi("080910100000000010")
        self.assertEqual(decoded["imsi"], "001010000000001")
        self.assertEqual(decoded["length_octet"], 8)
        self.assertTrue(decoded["odd_digit_count"])
        self.assertNotIn("Warnings", decoded)

    def test_length_octet_below_eight_bounds_the_digits(self) -> None:
        # Ten digits need six significant bytes; the last high nibble and
        # the remaining bytes are filler.
        decoded = ContentDecoder.decode_imsi("060110100000F1FFFF")
        self.assertEqual(decoded["imsi"], "0010100001")
        self.assertEqual(decoded["length_octet"], 6)
        self.assertFalse(decoded["odd_digit_count"])
        self.assertNotIn("Warnings", decoded)

    def test_length_octet_disagreeing_with_digits_is_a_warning(self) -> None:
        decoded = ContentDecoder.decode_imsi("080110100000F1FFFF")
        self.assertEqual(decoded["imsi"], "0010100001")
        self.assertIn("implies 14 digits", decoded["Warnings"][0])

    def test_length_octet_outside_one_to_eight_is_rejected(self) -> None:
        self.assertIn("Error", ContentDecoder.decode_imsi("000910100000000010"))
        self.assertIn("Error", ContentDecoder.decode_imsi("090910100000000010"))

    def test_identity_type_must_be_imsi(self) -> None:
        # Type of identity 010 (IMEI) in b3-b1 of byte 2.
        self.assertIn("Error", ContentDecoder.decode_imsi("080A10100000000010"))


class IccidLengthTests(unittest.TestCase):
    """TS 102 221 v18.4 §13.2 coding, ITU-T E.118 (09/2025) §6 length."""

    def test_nineteen_digits_no_warning(self) -> None:
        decoded = ContentDecoder.decode_iccid("9888" + "00" * 7 + "F1")
        self.assertEqual(decoded["iccid"], "8988000000000000001")
        self.assertNotIn("Warning", decoded)

    def test_eighteen_digits_decode_with_a_warning(self) -> None:
        decoded = ContentDecoder.decode_iccid("988800000000000000FF")
        self.assertEqual(decoded["iccid"], "898800000000000000")
        self.assertIn("E.118", decoded["Warning"])

    def test_all_filler_is_an_error(self) -> None:
        self.assertIn("Error", ContentDecoder.decode_iccid("FF" * 10))


class DirRecordTests(unittest.TestCase):
    """TS 102 221 v18.4 §13.1 Table 13.2."""

    def test_label_uses_annex_a_alpha_coding(self) -> None:
        decoded = ContentDecoder.decode_dir("610D4F07A00000008710025002555AFFFF")
        self.assertEqual(decoded["AID"], "A0000000871002")
        self.assertEqual(decoded["Label"], "UZ")
        self.assertEqual(decoded["Label Encoding"], "GSM default alphabet")

    def test_ucs2_label(self) -> None:
        decoded = ContentDecoder.decode_dir("610E4F07A0000000871002500380004B")
        self.assertEqual(decoded["Label"], "K")
        self.assertEqual(decoded["Label Encoding"], "UCS-2")

    def test_short_aid_is_accepted_with_a_warning(self) -> None:
        decoded = ContentDecoder.decode_dir("61094F03A000015002555A")
        self.assertEqual(decoded["AID"], "A00001")
        self.assertIn("5-byte RID", decoded["Warning"])

    def test_aid_longer_than_sixteen_bytes_is_an_error(self) -> None:
        decoded = ContentDecoder.decode_dir("61134F11" + "A0" * 17)
        self.assertIn("Error", decoded["Applications"][0])


class DiallingNumberRecordTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.4.2.3 and §4.2.26, TS 51.011 v4.15 §10.5.1."""

    def test_ton_npi_ff_means_no_dialling_number(self) -> None:
        record = "FFFFFFFF" + "03FF" + "AABB" + "FF" * 8 + "FFFF"
        decoded = ContentDecoder.decode_adn_like_record(record)
        self.assertEqual(decoded["TON"], "Not present (FF)")
        self.assertEqual(decoded["NPI"], "Not present (FF)")
        self.assertEqual(decoded["Dialing Number"], "**##")

    def test_msisdn_ton_npi_ff(self) -> None:
        decoded = ContentDecoder.decode_msisdn("03FF" + "AABB" + "FF" * 8 + "FFFF")
        self.assertEqual(decoded["TON"], "Not present (FF)")

    def test_msisdn_international_number(self) -> None:
        # +1 555 0100000 (NANP fictional), TON international / NPI E.164.
        record = "07" + "91" + "5155100000F0" + "FF" * 4 + "FFFF"
        decoded = ContentDecoder.decode_msisdn(record)
        self.assertEqual(decoded["Dialing Number"], "15550100000")
        self.assertEqual(decoded["TON"], "International")
        self.assertEqual(decoded["NPI"], "ISDN / E.164")

    def test_npi_labels_cover_both_specifications(self) -> None:
        # TS 23.040 v19 §9.1.2.5 plans 5/6 and 10, TS 24.008 v19.5 Table 10.5.118 plan 11.
        self.assertEqual(ContentDecoder._NPI_LABELS[6], "Service Centre Specific")
        self.assertEqual(ContentDecoder._NPI_LABELS[11], "Reserved for CTS")
        self.assertIn("dedicated access", ContentDecoder._TON_LABELS[4])


class CapabilityConfigurationTests(unittest.TestCase):
    """TS 51.011 v4.15 §10.5.4.1 EF.CCP and §10.5.4.2 EF.ECCP."""

    def test_ccp_record_is_length_prefixed_bearer_capability(self) -> None:
        decoded = ContentDecoder.decode_ccp("0490961000" + "FF" * 9)
        self.assertEqual(decoded["Bearer Capability Length"], 4)
        self.assertEqual(decoded["Bearer Capability"], "90961000")
        self.assertNotIn("Warnings", decoded)

    def test_ccp_tail_must_be_ff(self) -> None:
        decoded = ContentDecoder.decode_ccp("0490961000" + "00" + "FF" * 8)
        self.assertIn("not FF", decoded["Warnings"][0])

    def test_registry_no_longer_treats_6f3d_as_a_dialling_number(self) -> None:
        _reset_registry()
        record = "0490961000" + "FF" * 9
        for context in (None, "MF/DF_TELECOM/EF_CCP"):
            decoded = ContentDecoder.decode_raw("6F3D", record, context_path=context)
            self.assertEqual(decoded["Bearer Capability"], "90961000")
        eccp = ContentDecoder.decode_raw(
            "6F4F", "0490961000" + "FF" * 10, context_path="MF/DF_TELECOM/EF_ECCP"
        )
        self.assertEqual(eccp["Bearer Capability Length"], 4)


class RegistryRoutingTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.7 Figure 4.1 file identifiers."""

    def test_lnd_and_mbdn_are_dialling_number_records(self) -> None:
        _reset_registry()
        record = "07" + "91" + "5155100000F0" + "FF" * 4 + "FFFF"
        for fid, context in (("6F44", "MF/DF_TELECOM/EF_LND"), ("6FC7", None)):
            decoded = ContentDecoder.decode_raw(fid, record, context_path=context)
            self.assertEqual(decoded["Dialing Number"], "15550100000")

    def test_hpplmn_interval_semantics(self) -> None:
        # TS 31.102 v19.5 §4.2.6: 'YZ' is (16Y+Z) multiples of n minutes.
        _reset_registry()
        decoded = ContentDecoder.decode_raw("6F31", "0A")
        self.assertEqual(decoded["HPPLMN Search Interval"], 10)
        self.assertIn("10 x n minutes", decoded["Meaning"])
        self.assertIn(
            "No higher priority", ContentDecoder.decode_hpplmn("00")["Meaning"]
        )

    def test_keys_ps_decodes_ksi_ck_and_ik(self) -> None:
        # TS 31.102 v19.5 §4.2.4: EF.KeysPS holds KSI, CK and IK like EF.Keys.
        _reset_registry()
        decoded = ContentDecoder.decode_raw("6F09", "02" + "11" * 16 + "22" * 16)
        self.assertEqual(decoded["KSI"], 2)
        self.assertEqual(decoded["CK"], "11" * 16)
        self.assertEqual(decoded["IK"], "22" * 16)


class SmsParameterTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.2.27, TS 23.040 v19 §9.1.2.3, §9.1.2.5 and §9.2.3.9."""

    def test_inner_filler_in_address_is_skipped(self) -> None:
        decoded = ContentDecoder._decode_address_field(bytes.fromhex("0691F15555"))
        self.assertEqual(decoded["call_number"], "15555")
        self.assertNotIn("error", decoded)

    def test_inner_filler_in_a_file_body_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            ContentDecoder._decode_bcd_digits(bytes.fromhex("F155"))

    def test_alphanumeric_address_is_unpacked(self) -> None:
        # "Hi" packed 7-bit ('48', '69') fills four semi-octets.
        decoded = ContentDecoder._decode_address_field(bytes.fromhex("04D0C834"))
        self.assertEqual(decoded["call_number"], "Hi")
        self.assertEqual(decoded["encoding"], "alphanumeric GSM 7-bit")

    def test_tp_dcs_automatic_deletion_group(self) -> None:
        # TS 23.038 v19 §4 coding group 01xx: bits 5..0 as for group 00xx.
        decoded = ContentDecoder._decode_tp_dcs(0x58)
        self.assertIn("UCS-2", decoded)
        self.assertIn("marked for automatic deletion", decoded)
        self.assertNotIn("automatic deletion", ContentDecoder._decode_tp_dcs(0x18))

    def test_tp_pid_labels(self) -> None:
        self.assertEqual(
            ContentDecoder._tp_pid_label(0x48), "Device Triggering Short Message"
        )
        self.assertEqual(ContentDecoder._tp_pid_label(0x3F), "GSM/UMTS mobile station")
        self.assertEqual(ContentDecoder._tp_pid_label(0x7F), "(U)SIM Data download")
        self.assertEqual(ContentDecoder._tp_pid_label(0xC1), "SC specific use")
        self.assertEqual(ContentDecoder._tp_pid_label(0x90), "Reserved")

    def test_smsp_record_with_service_centre_only(self) -> None:
        # Parameter indicators 'E1': b1 = 1 marks TP-DA absent, b2..b5 = 0
        # mark TS-SCA, TP-PID, TP-DCS and TP-VP present, b6..b8 reserved = 1.
        record = (
            "E1"
            + "FF" * 12
            + "07915155100000F0" + "FFFFFFFF"
            + "00"
            + "00"
            + "A7"
        )
        decoded = ContentDecoder.decode_sms_params(record)
        flags = decoded["Parameter Indicators"]["flags"]
        self.assertTrue(flags["TP-Service Centre Address"])
        self.assertFalse(flags["TP-Destination Address"])
        self.assertEqual(
            decoded["Service Center Address"]["call_number"], "15550100000"
        )
        self.assertEqual(decoded["TP-Validity Period"]["minutes"], 24 * 60)
        self.assertEqual(decoded["TP-PID Label"], "SME-to-SME protocol (no interworking)")


class SmsRecordTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.2.25 status byte and record layout."""

    SCA = "0791515500000 0F0".replace(" ", "")
    TPDU = "01FF0B915155000000F00000A705C8329BFD06"

    def test_service_centre_address_precedes_the_tpdu(self) -> None:
        decoded = ContentDecoder.decode_sms_record("05" + self.SCA + self.TPDU)
        self.assertEqual(decoded["Direction"], "MO")
        self.assertEqual(
            decoded["Record State"], "Stored Sent (status report not requested)"
        )
        self.assertEqual(
            decoded["Service Centre Address"]["call_number"], "15550000000"
        )
        self.assertEqual(decoded["TPDU (raw)"], self.TPDU)

    def test_status_report_sub_states(self) -> None:
        self.assertIn("not yet received", ContentDecoder._decode_sms_status(0x0D))
        self.assertIn("not stored", ContentDecoder._decode_sms_status(0x15))
        self.assertIn("received and stored", ContentDecoder._decode_sms_status(0x1D))
        self.assertEqual(ContentDecoder._decode_sms_status(0x03), "Received Unread")
        self.assertEqual(ContentDecoder._sms_status_direction(0x03), "MT")

    def test_free_record_keeps_raw_remainder(self) -> None:
        decoded = ContentDecoder.decode_sms_record("00" + "FF" * 175)
        self.assertEqual(decoded["Record State"], "Free")
        self.assertEqual(decoded["Direction"], "free")
        self.assertNotIn("Service Centre Address", decoded)

    def test_smsr_zero_identifier_marks_an_empty_record(self) -> None:
        # TS 31.102 v19.5 §4.2.32: '00' = empty record.
        decoded = ContentDecoder.decode_smsr("00" + "FF" * 29)
        self.assertTrue(decoded["Empty"])
        self.assertNotIn("Empty", ContentDecoder.decode_smsr("05" + "FF" * 29))


class PuctAndAdTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.2.13 and §4.2.18."""

    def test_currency_uses_gsm_default_alphabet(self) -> None:
        # TS 23.038 v19 §6.2.1: '00' '@', '01' '£', '24' '¤'.
        decoded = ContentDecoder.decode_puct("000124" + "1274")
        self.assertEqual(decoded["Currency"], "@£¤")
        self.assertEqual(ContentDecoder.decode_puct("455552" + "1274")["Currency"], "EUR")

    def test_maintenance_mode_marks_manufacturer_specific_bytes(self) -> None:
        decoded = ContentDecoder.decode_ad("02123402")
        self.assertEqual(decoded["Administrative Mode"], "Maintenance (off-line)")
        self.assertEqual(
            decoded["Additional Information Meaning"], "ME manufacturer specific"
        )
        self.assertNotIn(
            "Additional Information Meaning", ContentDecoder.decode_ad("00000002")
        )


if __name__ == "__main__":
    unittest.main()
