# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Spec-clause checks for the SAIP EF decoders and their paired encoders.

Each test pins one layout or coding rule from TS 31.102, TS 102 221 or
TS 24.008 that the decoders used to get wrong: bit positions, record
layouts, key-reference names and the Network Name IE header.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_arr_security_condition,
    _decode_cfis_record,
    _decode_lcsi,
    _decode_mbi_record,
    _decode_msisdn,
    _decode_mwis_record,
    _decode_nasconfig,
    _decode_network_name_ie,
    _decode_phonebook_pbr,
    _decode_pnn_record,
    _decode_suci_calc_info,
    arr_key_reference_name,
    lcsi_state_name,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    _ARR_CONDITION_KEY_REFERENCE,
    RoundtripEncoderError,
    _encode_network_name_ie,
    encode_ef_cfis_record,
    encode_ef_mbi_record,
    encode_ef_mwis_record,
    encode_ef_pnn_record,
)


class ArrKeyReferenceTests(unittest.TestCase):
    # TS 102 221 Table 9.3.
    def test_table_9_3_names(self) -> None:
        self.assertEqual(arr_key_reference_name(0x01), "PIN1")
        self.assertEqual(arr_key_reference_name(0x02), "PIN Appl 2")
        self.assertEqual(arr_key_reference_name(0x0A), "ADM1")
        self.assertEqual(arr_key_reference_name(0x0E), "ADM5")
        self.assertEqual(arr_key_reference_name(0x11), "Universal PIN")
        self.assertEqual(arr_key_reference_name(0x81), "PIN2")
        self.assertEqual(arr_key_reference_name(0x82), "Second PIN Appl 2")
        self.assertEqual(arr_key_reference_name(0x8A), "ADM6")
        self.assertEqual(arr_key_reference_name(0x8E), "ADM10")
        self.assertEqual(arr_key_reference_name(0x09), "RFU (0x09)")
        self.assertEqual(arr_key_reference_name(0x12), "RFU global (0x12)")
        self.assertEqual(arr_key_reference_name(0x90), "RFU local (0x90)")
        self.assertEqual(arr_key_reference_name(0x7F), "KeyRef(0x7F)")

    def test_condition_uses_table_names(self) -> None:
        decoded = _decode_arr_security_condition(bytes.fromhex("83018A"))
        assert decoded is not None
        self.assertEqual(decoded["condition"], "ADM6")
        decoded = _decode_arr_security_condition(bytes.fromhex("830111"))
        assert decoded is not None
        self.assertEqual(decoded["condition"], "Universal PIN")

    def test_encoder_table_is_the_inverse(self) -> None:
        self.assertEqual(_ARR_CONDITION_KEY_REFERENCE["PIN2"], 0x81)
        self.assertEqual(_ARR_CONDITION_KEY_REFERENCE["ADM5"], 0x0E)
        self.assertEqual(_ARR_CONDITION_KEY_REFERENCE["ADM6"], 0x8A)
        self.assertEqual(_ARR_CONDITION_KEY_REFERENCE["UNIVERSAL PIN"], 0x11)
        for name, reference in _ARR_CONDITION_KEY_REFERENCE.items():
            self.assertEqual(arr_key_reference_name(reference).upper(), name)


class LcsiStateTests(unittest.TestCase):
    # TS 102 221 Table 11.7b.
    def test_state_names(self) -> None:
        self.assertEqual(lcsi_state_name(0x00), "no_information")
        self.assertEqual(lcsi_state_name(0x01), "creation")
        self.assertEqual(lcsi_state_name(0x03), "initialization")
        self.assertEqual(lcsi_state_name(0x05), "operational_activated")
        self.assertEqual(lcsi_state_name(0x04), "operational_deactivated")
        self.assertEqual(lcsi_state_name(0x0C), "termination")
        self.assertEqual(lcsi_state_name(0x0F), "termination")
        self.assertEqual(lcsi_state_name(0x25), "proprietary")

    def test_decoder_reports_termination(self) -> None:
        decoded = _decode_lcsi(b"\x0C")
        assert decoded is not None
        self.assertEqual(decoded["state"], "termination")


class NetworkNameIeTests(unittest.TestCase):
    # TS 24.008 §10.5.3.5a octet 3: b7-b5 coding scheme, b4 Add CI, b3-b1 spare.
    def test_coding_scheme_sits_in_bits_7_to_5(self) -> None:
        ucs2 = bytes([0x90]) + "Hi".encode("utf-16-be")
        decoded = _decode_network_name_ie(ucs2)
        assert decoded is not None
        self.assertEqual(decoded["codingScheme"], 1)
        self.assertEqual(decoded["encoding"], "ucs-2-be")
        self.assertEqual(decoded["text"], "Hi")
        gsm = bytes([0x8F]) + bytes.fromhex("41E19058341E01")
        decoded = _decode_network_name_ie(gsm)
        assert decoded is not None
        self.assertEqual(decoded["codingScheme"], 0)
        self.assertTrue(decoded["addCountryInitials"])
        self.assertEqual(decoded["spareBits"], 7)
        self.assertEqual(decoded["text"], "ABCDEFG")

    def test_encoder_packs_gsm7_with_spare_bit_count(self) -> None:
        self.assertEqual(_encode_network_name_ie("ABCDEFG").hex().upper(), "8741E19058341E01")
        self.assertEqual(_encode_network_name_ie("ABCDEFGH").hex().upper(), "8041E19058341E91")
        self.assertEqual(_encode_network_name_ie("Hi").hex().upper(), "82C834")

    def test_encoder_falls_back_to_ucs2(self) -> None:
        ie = _encode_network_name_ie("日本")
        self.assertEqual(ie[0], 0x90)
        decoded = _decode_network_name_ie(ie)
        assert decoded is not None
        self.assertEqual(decoded["text"], "日本")

    def test_pnn_record_roundtrip_through_the_ie(self) -> None:
        record = encode_ef_pnn_record({"fullName": "Net A", "shortName": "SN"})
        decoded = _decode_pnn_record(record.hex())
        assert decoded is not None
        self.assertEqual(decoded["fullName"], "Net A")
        self.assertEqual(decoded["shortName"], "SN")
        # Tag 43 value begins with the IE header, never bare text.
        self.assertEqual(record[0], 0x43)
        self.assertTrue(record[2] & 0x80)


class MessageWaitingTests(unittest.TestCase):
    # TS 31.102 §4.2.63 (MWIS) and §4.2.62 (MBI): videomail is b5 / byte 5-6.
    def test_mwis_six_byte_record(self) -> None:
        decoded = _decode_mwis_record("110102030405")
        assert decoded is not None
        self.assertTrue(decoded["voicemailWaiting"])
        self.assertTrue(decoded["videomailWaiting"])
        self.assertEqual(decoded["videomailCount"], 5)
        self.assertNotIn("rfuBitsSet", decoded)
        encoded = encode_ef_mwis_record(dict(decoded, hex=""), target_length=6)
        self.assertEqual(encoded.hex().upper(), "110102030405")

    def test_mwis_five_byte_record_keeps_shape(self) -> None:
        decoded = _decode_mwis_record("E101020304")
        assert decoded is not None
        self.assertTrue(decoded["rfuBitsSet"])
        self.assertNotIn("videomailCount", decoded)
        self.assertEqual(
            encode_ef_mwis_record(dict(decoded, hex=""), target_length=5).hex().upper(),
            "E101020304",
        )

    def test_mbi_videomail_slot(self) -> None:
        decoded = _decode_mbi_record("0102030405")
        assert decoded is not None
        self.assertEqual(decoded["slots"]["videomail"], 5)
        encoded = encode_ef_mbi_record({"slots": decoded["slots"]}, target_length=5)
        self.assertEqual(encoded.hex().upper(), "0102030405")


class CallForwardingTests(unittest.TestCase):
    # TS 31.102 §4.2.64: 16-byte record, CFU b5 = all bearer services.
    _RAW = "0111" + "05" + "91" + "1122334455FFFFFFFFFF" + "02" + "03"

    def test_record_layout(self) -> None:
        decoded = _decode_cfis_record(self._RAW)
        assert decoded is not None
        self.assertEqual(decoded["mspNumber"], 1)
        self.assertTrue(decoded["voiceForwardActive"])
        self.assertTrue(decoded["bearerForwardActive"])
        self.assertEqual(decoded["number"], "11223344")
        self.assertEqual(decoded["ton"], "International")
        self.assertEqual(decoded["capabilityConfigurationIdentifier"], "0x02")
        self.assertEqual(decoded["extensionRecordIdentifier"], "0x03")

    def test_flag_rebuild_roundtrip(self) -> None:
        decoded = dict(_decode_cfis_record(self._RAW))
        decoded.pop("hex")
        decoded.pop("cfIndicator")
        encoded = encode_ef_cfis_record(decoded, target_length=16)
        self.assertEqual(encoded.hex().upper(), self._RAW)


class DiallingNumberFooterTests(unittest.TestCase):
    # TS 31.102 §4.4.2.3: footer byte 13 is the CCP identifier.
    def test_msisdn_exposes_ccp_identifier(self) -> None:
        raw = "05" + "91" + "1122334455FFFFFFFFFF" + "AB" + "FF"
        decoded = _decode_msisdn(raw)
        assert decoded is not None
        self.assertEqual(decoded["capabilityConfigurationIdentifier"], "0xAB")
        self.assertEqual(decoded["extensionRecordIdentifier"], "0xFF")


class PhonebookReferenceTests(unittest.TestCase):
    # TS 31.102 §4.4.2.1: length 3 = FID + SFI; 'CC' is EF.PURI.
    def test_fid_with_sfi(self) -> None:
        decoded = _decode_phonebook_pbr("A80A" + "C0034F3A01" + "CC034F3C02")
        assert decoded is not None
        entries = decoded["items"][0]["items"]
        self.assertEqual(entries[0]["decoded"], {"fid": "4F3A", "sfi": "0x01"})
        self.assertEqual(entries[1]["name"], "PURI reference")
        self.assertEqual(entries[1]["decoded"]["sfi"], "0x02")


class NasConfigTests(unittest.TestCase):
    # TS 31.102 §4.2.94 / TS 24.368.
    def test_tags_and_leaf_codings(self) -> None:
        decoded = _decode_nasconfig(
            "800101" + "810101" + "8C020102" + "8E0400F11001" + "8F0200F1" + "FFFF"
        )
        assert decoded is not None
        by_tag = {item["tag"]: item for item in decoded["items"]}
        self.assertEqual(by_tag["80"]["name"], "NAS signalling priority")
        self.assertEqual(by_tag["80"]["decoded"]["priority"], "NAS signalling low priority")
        self.assertTrue(by_tag["81"]["decoded"]["b1"])
        self.assertEqual(by_tag["8C"]["decoded"]["dcnId"], 258)
        entry = by_tag["8E"]["decoded"]["entries"][0]
        self.assertEqual(entry["plmn"], "001-01")
        self.assertTrue(entry["samePriorityAsNext"])
        self.assertEqual(by_tag["8F"]["decoded"]["mccs"], ["001"])
        self.assertNotIn("FF", by_tag)


class SuciCalcInfoTests(unittest.TestCase):
    # TS 31.102 §4.4.11.8: 'A0' holds (scheme id, key index) pairs.
    def test_scheme_pairs(self) -> None:
        decoded = _decode_suci_calc_info("A004" + "0101" + "0000")
        assert decoded is not None
        entries = decoded["items"][0]["decoded"]["entries"]
        self.assertEqual(entries[0]["keyIndex"], 1)
        self.assertIn("Profile A", entries[0]["protectionScheme"])
        self.assertEqual(entries[1]["protectionScheme"], "null-scheme")
        self.assertEqual(entries[1]["keyIndex"], 0)

    def test_odd_length_list_is_flagged(self) -> None:
        decoded = _decode_suci_calc_info("A003" + "010100")
        assert decoded is not None
        self.assertIn("warning", decoded["items"][0]["decoded"])


class EncoderRejectsTests(unittest.TestCase):
    def test_mwis_rejects_bad_trailer(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_mwis_record({"voicemailCount": 1, "trailerHex": "F"})


if __name__ == "__main__":
    unittest.main()
