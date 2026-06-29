# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Roundtrip tests for the 24 EF encoders that lacked coverage.

Each test class covers one or more of: identity roundtrip
(decode → encode → compare raw bytes), semantic-edit roundtrip
(mutate a field → re-decode → verify new value), and error-path
(invalid payload raises ``RoundtripEncoderError``).
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_aaem_record,
    _decode_ad,
    _decode_cfis_record,
    _decode_dck_record,
    _decode_emlpp_record,
    _decode_hpplmn_search_interval,
    _decode_mbi_record,
    _decode_mwis_record,
    _decode_opl5g_record,
    _decode_plmn_list,
    _decode_routing_indicator,
    _decode_smss,
    _decode_start_hfn,
    _decode_three_byte_counter,
    _decode_tlv80_text,
    _decode_uac_aic,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_ef_aaem_record,
    encode_ef_acc,
    encode_ef_ad,
    encode_ef_cfis_record,
    encode_ef_dck_record,
    encode_ef_ehplmnpi,
    encode_ef_emlpp_record,
    encode_ef_file_size_field,
    encode_ef_hpplmn_search_interval,
    encode_ef_language_records,
    encode_ef_mbi_record,
    encode_ef_mwis_record,
    encode_ef_opl5g_record,
    encode_ef_pbr,
    encode_ef_plmn_list,
    encode_ef_plmn_list_no_act,
    encode_ef_plmn_list_with_act,
    encode_ef_routing_indicator,
    encode_ef_smss,
    encode_ef_start_hfn,
    encode_ef_three_byte_counter,
    encode_ef_tlv80_text,
    encode_ef_uac_aic,
    encode_ef_uri_tlv,
)


class SmssEncoderTests(unittest.TestCase):
    """EF.SMSS (3GPP TS 31.102 §4.2.16b)."""

    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x03, 0xFF])
        decoded = _decode_smss(raw.hex().upper())
        self.assertIsNotNone(decoded)
        encoded = encode_ef_smss(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_memory_exceeded_flag(self) -> None:
        raw = bytes([0x0A, 0xFE])
        decoded = _decode_smss(raw.hex().upper())
        self.assertTrue(decoded["memoryCapacityExceeded"])
        encoded = encode_ef_smss(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_semantic_edit_last_used(self) -> None:
        raw = bytes([0x05, 0xFF])
        decoded = dict(_decode_smss(raw.hex().upper()))
        decoded["lastUsedTpMr"] = 20
        encoded = encode_ef_smss(decoded)
        redecoded = _decode_smss(encoded.hex().upper())
        self.assertEqual(redecoded["lastUsedTpMr"], 20)

    def test_error_on_missing_fields(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_smss({})


class StartHfnEncoderTests(unittest.TestCase):
    """EF.START-HFN (3GPP TS 31.102 §4.2.40, 6 bytes)."""

    def test_identity_roundtrip(self) -> None:
        raw = bytes([0, 0, 1, 0, 0, 2])
        decoded = _decode_start_hfn(raw.hex().upper())
        self.assertIsNotNone(decoded)
        encoded = encode_ef_start_hfn(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_semantic_values(self) -> None:
        payload = {"startCs": 0x000100, "startPs": 0x000200}
        encoded = encode_ef_start_hfn(payload)
        self.assertEqual(len(encoded), 6)
        redecoded = _decode_start_hfn(encoded.hex().upper())
        self.assertEqual(redecoded["startCs"], 0x000100)
        self.assertEqual(redecoded["startPs"], 0x000200)

    def test_hex_passthrough(self) -> None:
        raw = "AABBCCDDEE11"
        encoded = encode_ef_start_hfn({"hex": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_error_on_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_start_hfn({})


class AdEncoderTests(unittest.TestCase):
    """EF.AD (3GPP TS 31.102 §4.2.18)."""

    def test_identity_with_raw(self) -> None:
        raw = bytes([0x00, 0x00, 0x02, 0x00])
        decoded = _decode_ad(raw.hex().upper())
        self.assertIsNotNone(decoded)
        encoded = encode_ef_ad(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_mode_byte_rewrite(self) -> None:
        # 0x00 = Normal; rewrite to Proprietary (0x80) leaving remaining bytes intact
        raw = bytes([0x00, 0x00, 0x02, 0x00])
        decoded = dict(_decode_ad(raw.hex().upper()))
        decoded["administrativeMode"] = "Proprietary"
        encoded = encode_ef_ad(decoded)
        self.assertEqual(encoded[0], 0x80)
        self.assertEqual(encoded[1:], raw[1:])

    def test_error_on_unknown_mode(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_ad({"administrativeMode": "InvalidMode"})


class HpplmnEncoderTests(unittest.TestCase):
    """EF.HPPLMN search interval."""

    def test_identity(self) -> None:
        raw = bytes([0x1E])
        decoded = _decode_hpplmn_search_interval(raw.hex().upper())
        self.assertIsNotNone(decoded)
        encoded = encode_ef_hpplmn_search_interval({"intervalMinutes": decoded["interval"]})
        self.assertEqual(encoded, raw)

    def test_zero_interval(self) -> None:
        encoded = encode_ef_hpplmn_search_interval({"intervalMinutes": 0})
        self.assertEqual(encoded, bytes([0x00]))

    def test_error_on_overflow(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_hpplmn_search_interval({"intervalMinutes": 256})


class AccEncoderTests(unittest.TestCase):
    """EF.ACC (3GPP TS 31.102 §4.2.15)."""

    def test_class_bit_encoding(self) -> None:
        encoded = encode_ef_acc({"accessControlClasses": [0, 4, 15]})
        self.assertEqual(len(encoded), 2)
        value = int.from_bytes(encoded, "big")
        self.assertTrue(value & (1 << 0))
        self.assertTrue(value & (1 << 4))
        self.assertTrue(value & (1 << 15))
        self.assertFalse(value & (1 << 1))

    def test_raw_passthrough(self) -> None:
        raw = bytes([0x03, 0xFF])
        encoded = encode_ef_acc({"raw": raw.hex().upper()})
        self.assertEqual(encoded, raw)

    def test_error_on_out_of_range_class(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_acc({"accessControlClasses": [16]})

    def test_target_length_pads(self) -> None:
        encoded = encode_ef_acc({"accessControlClasses": [0]}, target_length=4)
        self.assertEqual(len(encoded), 4)
        self.assertEqual(encoded[2:], bytes([0xFF, 0xFF]))


class EhplmnpiEncoderTests(unittest.TestCase):
    """EF.EHPLMNwAcT presentation indication."""

    def test_known_name(self) -> None:
        # Valid names are snake_case: no_preference / display_highest_prio_only / display_all
        encoded = encode_ef_ehplmnpi({"presentationIndication": "display_all"})
        self.assertEqual(len(encoded), 1)

    def test_raw_fallback(self) -> None:
        encoded = encode_ef_ehplmnpi({"raw": "FF"})
        self.assertEqual(encoded, bytes([0xFF]))

    def test_error_on_unknown(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_ehplmnpi({"presentationIndication": "Invalid"})


class RoutingIndicatorEncoderTests(unittest.TestCase):
    """EF.Routing_Indicator (3GPP TS 31.102 §4.4.11.8)."""

    def test_identity(self) -> None:
        raw = "F1FF0000"
        decoded = _decode_routing_indicator(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_routing_indicator(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_hex_roundtrip(self) -> None:
        raw = "10FF8000"
        encoded = encode_ef_routing_indicator({"hex": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_error_on_missing_ri(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_routing_indicator({"flagByteDecimal": 0, "reservedByte": "0xFF"})


class UacAicEncoderTests(unittest.TestCase):
    """EF.UAC_AIC (3GPP TS 31.102 §4.4.11.6)."""

    def test_identity(self) -> None:
        raw = "00000080"
        decoded = _decode_uac_aic(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_uac_aic(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_identity_list(self) -> None:
        payload = {"accessIdentities": [0, 7, 31]}
        encoded = encode_ef_uac_aic(payload)
        self.assertEqual(len(encoded), 4)
        redecoded = _decode_uac_aic(encoded.hex().upper())
        ids = set(redecoded["accessIdentities"])
        self.assertIn(0, ids)
        self.assertIn(7, ids)
        self.assertIn(31, ids)

    def test_error_on_out_of_range(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_uac_aic({"accessIdentities": [32]})


class ThreeByteCounterEncoderTests(unittest.TestCase):
    """EF.ACM / EF.ACMmax (3GPP TS 31.102 §4.2.16 / §4.2.17)."""

    def test_identity(self) -> None:
        raw = "000100"
        decoded = _decode_three_byte_counter(raw, format_name="ACM", field_name="acm")
        self.assertIsNotNone(decoded)
        encoded = encode_ef_three_byte_counter({"acm": decoded["acm"]})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_zero_value(self) -> None:
        encoded = encode_ef_three_byte_counter({"acmMax": 0})
        self.assertEqual(encoded, bytes([0, 0, 0]))

    def test_error_on_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_three_byte_counter({})


class Tlv80TextEncoderTests(unittest.TestCase):
    """EF.IMPI / EF.DOMAIN / EF.NAFKCA TLV-0x80 text."""

    def test_domain_identity(self) -> None:
        raw = "800B6578616D706C652E636F6D"
        decoded = _decode_tlv80_text(raw, format_name="Domain", field_name="domain")
        self.assertIsNotNone(decoded)
        encoded = encode_ef_tlv80_text({"domain": "example.com"})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_identity_field(self) -> None:
        encoded = encode_ef_tlv80_text({"identity": "user@example.test"})
        self.assertEqual(encoded[0], 0x80)
        self.assertEqual(encoded[1], len("user@example.test".encode()))
        self.assertEqual(encoded[2:].decode(), "user@example.test")

    def test_raw_passthrough(self) -> None:
        raw = "800200FF"
        encoded = encode_ef_tlv80_text({"raw": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_error_on_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_tlv80_text({})


class MwisEncoderTests(unittest.TestCase):
    """EF.MWIS (3GPP TS 31.102 §4.2.44)."""

    def test_identity(self) -> None:
        raw = "01030000FF"
        decoded = _decode_mwis_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_mwis_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_flag_encoding(self) -> None:
        payload = {
            "voicemailWaiting": True,
            "faxWaiting": False,
            "emailWaiting": True,
            "otherWaiting": False,
            "voicemailCount": 2,
            "faxCount": 0,
            "emailCount": 1,
            "otherCount": 0,
        }
        encoded = encode_ef_mwis_record(payload)
        self.assertEqual(len(encoded), 5)
        self.assertEqual(encoded[0] & 0x01, 0x01)
        self.assertEqual(encoded[0] & 0x04, 0x04)
        self.assertEqual(encoded[1], 2)
        self.assertEqual(encoded[3], 1)

    def test_hex_passthrough(self) -> None:
        raw = "FF0102030400"
        encoded = encode_ef_mwis_record({"hex": raw[:10]})
        self.assertEqual(encoded, bytes.fromhex(raw[:10]))


class MbiEncoderTests(unittest.TestCase):
    """EF.MBI (3GPP TS 31.102 §4.2.53)."""

    def test_identity(self) -> None:
        raw = "01020304"
        decoded = _decode_mbi_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_mbi_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_individual_slots(self) -> None:
        payload = {"slots": {"voicemail": 5, "fax": 0, "email": 3, "other": 0}}
        encoded = encode_ef_mbi_record(payload)
        self.assertEqual(encoded[0], 5)
        self.assertEqual(encoded[2], 3)

    def test_error_on_missing_slots(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_mbi_record({})


class CfisEncoderTests(unittest.TestCase):
    """EF.CFIS (3GPP TS 31.102 §4.2.63)."""

    def test_identity(self) -> None:
        raw = "0103" + "FF" * 11
        decoded = _decode_cfis_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_cfis_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_flag_bits(self) -> None:
        tail = "FF" * 11
        payload = {
            "mspNumber": 2,
            "voiceForwardActive": True,
            "faxForwardActive": True,
            "dataForwardActive": False,
            "smsForwardActive": False,
            "tailHex": tail,
        }
        encoded = encode_ef_cfis_record(payload)
        self.assertEqual(encoded[0], 2)
        self.assertEqual(encoded[1] & 0x03, 0x03)
        self.assertEqual(encoded[1] & 0x04, 0x00)

    def test_error_on_missing_msp(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_cfis_record({"voiceForwardActive": True, "tailHex": ""})


class EmlppEncoderTests(unittest.TestCase):
    """EF.eMLPP (3GPP TS 31.102 §4.2.38)."""

    def test_identity(self) -> None:
        raw = "2010"
        decoded = _decode_emlpp_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_emlpp_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_bit_encoding(self) -> None:
        payload = {"supportedPriorityLevels": [0, 1], "fastCallSetupLevels": [0]}
        encoded = encode_ef_emlpp_record(payload)
        self.assertEqual(encoded[0] & 0x03, 0x03)
        self.assertEqual(encoded[1] & 0x01, 0x01)


class AaemEncoderTests(unittest.TestCase):
    """EF.AAeM (3GPP TS 31.102 §4.2.45)."""

    def test_identity(self) -> None:
        raw = "05"
        decoded = _decode_aaem_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_aaem_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_level_bits(self) -> None:
        payload = {"aaEnabledLevels": [1, 3], "trailerHex": ""}
        encoded = encode_ef_aaem_record(payload)
        self.assertEqual(encoded[0] & (1 << 1), 1 << 1)
        self.assertEqual(encoded[0] & (1 << 3), 1 << 3)
        self.assertEqual(encoded[0] & (1 << 0), 0)


class DckEncoderTests(unittest.TestCase):
    """EF.DCK (3GPP TS 31.102 §4.2.30)."""

    def test_identity(self) -> None:
        raw = "AABBCCDD" * 4
        decoded = _decode_dck_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_dck_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_four_key_fields(self) -> None:
        payload = {
            "networkKey": "11223344",
            "networkSubsetKey": "AABBCCDD",
            "serviceProviderKey": "01020304",
            "corporateKey": "F0F0F0F0",
        }
        encoded = encode_ef_dck_record(payload)
        self.assertEqual(len(encoded), 16)
        self.assertEqual(encoded[:4], bytes.fromhex("11223344"))
        self.assertEqual(encoded[12:], bytes.fromhex("F0F0F0F0"))


class Opl5gEncoderTests(unittest.TestCase):
    """EF.OPL5G (3GPP TS 31.102 §4.4.11)."""

    def test_identity(self) -> None:
        raw = "21F300000000000000FF"
        decoded = _decode_opl5g_record(raw)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_opl5g_record(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_structured_payload(self) -> None:
        payload = {"plmnHex": "21F300", "tacStart": 100, "tacEnd": 200, "pnnRecordId": 3}
        encoded = encode_ef_opl5g_record(payload)
        self.assertEqual(len(encoded), 10)
        self.assertEqual(encoded[:3], bytes.fromhex("21F300"))
        self.assertEqual(encoded[9], 3)

    def test_error_on_bad_plmn(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_opl5g_record(
                {"plmnHex": "GG", "tacStart": 0, "tacEnd": 0, "pnnRecordId": 0}
            )


class PlmnListEncoderTests(unittest.TestCase):
    """EF.PLMNwAcT / EF.OPLMNwAcT / EF.HPLMNwAcT (PLMN lists with and without AcT)."""

    def test_no_act_identity(self) -> None:
        # 001-01 TBCD-encoded: 00 F1 10 (roundtrips cleanly)
        raw = "00F110"
        decoded = _decode_plmn_list(raw, with_act=False)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_plmn_list_no_act(dict(decoded))
        self.assertEqual(encoded[:3], bytes.fromhex(raw))

    def test_with_act_identity(self) -> None:
        # 001-01 + GSM COMPACT AcT (0x0040)
        raw = "00F1100040"
        decoded = _decode_plmn_list(raw, with_act=True)
        self.assertIsNotNone(decoded)
        encoded = encode_ef_plmn_list_with_act(dict(decoded))
        self.assertEqual(encoded[:5], bytes.fromhex(raw))

    def test_plmn_list_dispatcher_with_act(self) -> None:
        payload = {"entries": [{"plmn": "001-01", "act": ["GSM COMPACT"]}]}
        encoded = encode_ef_plmn_list(payload, with_act=True)
        self.assertEqual(len(encoded), 5)

    def test_plmn_list_dispatcher_no_act(self) -> None:
        payload = {"entries": [{"plmn": "001-01"}]}
        encoded = encode_ef_plmn_list(payload, with_act=False)
        self.assertEqual(len(encoded), 3)

    def test_error_on_bad_plmn(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_plmn_list_no_act({"entries": [{"plmn": "bad"}]})


class LanguageRecordsEncoderTests(unittest.TestCase):
    """EF.LP / EF.PL (3GPP TS 31.102 §4.2.83 — two-char language codes)."""

    def test_encode_languages(self) -> None:
        payload = {"languages": ["en", "de", "fr"]}
        encoded = encode_ef_language_records(payload)
        self.assertEqual(encoded, b"endefr")

    def test_round_trip_ascii(self) -> None:
        raw = b"fise"
        encoded = encode_ef_language_records({"languages": ["fi", "se"]})
        self.assertEqual(encoded, raw)

    def test_error_on_wrong_length(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_language_records({"languages": ["eng"]})

    def test_error_on_non_list(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_language_records({"languages": "en"})


class UriTlvEncoderTests(unittest.TestCase):
    """Generic 80-TLV URI encoder (EF.FDN_URI, EF.SDN_URI, ISIM EHURI, …)."""

    def test_uri_field(self) -> None:
        uri = "sip:example@example.test"
        encoded = encode_ef_uri_tlv({"uri": uri})
        self.assertEqual(encoded[0], 0x80)
        self.assertEqual(encoded[1], len(uri.encode()))
        self.assertEqual(encoded[2:].decode(), uri)

    def test_nai_field(self) -> None:
        nai = "user@example.test"
        encoded = encode_ef_uri_tlv({"nai": nai})
        self.assertEqual(encoded[2:].decode(), nai)

    def test_hex_passthrough(self) -> None:
        raw = "8003414243"
        encoded = encode_ef_uri_tlv({"hex": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_original_hex_fallback(self) -> None:
        raw = "8003414243"
        encoded = encode_ef_uri_tlv({"_ygg_original_hex": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_error_on_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_uri_tlv({})


class PbrEncoderTests(unittest.TestCase):
    """EF.PBR hex passthrough (encoding is BER-TLV; hex path covers identity)."""

    def test_hex_passthrough(self) -> None:
        raw = "A0084F02 4F20 4F02 5020".replace(" ", "")
        encoded = encode_ef_pbr({"hex": raw})
        self.assertEqual(encoded, bytes.fromhex(raw))

    def test_error_on_bad_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_pbr({"hex": "ZZ"})

    def test_error_on_missing_payload(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_pbr({})


class FileSizeFieldEncoderTests(unittest.TestCase):
    """encode_ef_file_size_field hex-passthrough field."""

    def test_hex_passthrough(self) -> None:
        # efFileSize is a tagged-hex passthrough field; provide hex directly
        result = encode_ef_file_size_field({"hex": "0100"})
        self.assertEqual(result, bytes([0x01, 0x00]))

    def test_two_bytes(self) -> None:
        result = encode_ef_file_size_field({"hex": "0040"})
        self.assertEqual(result, bytes([0x00, 0x40]))

    def test_error_on_no_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_file_size_field({"byteCount": 256})
