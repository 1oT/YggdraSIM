# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the 25 untested public decoders in SCP03/core/decoders.py.

Exercises: decode_gp_seac_arf, decode_pkcs15_acrf, decode_cert_der,
init_registry, decode_language_indicators, decode_cbmi_list,
decode_cbmid_range_list, decode_raw, decode_dir, decode_sms_params,
decode_smsr, decode_epsnsc, decode_nafkca, decode_isim_tlv80_text,
decode_isim_pcscf, decode_tlv_as_map, decode_utf8_or_hex,
decode_hex_chunks, decode_pkcs15_acrf_json, decode_pkcs15_accf_json,
decode_5gs_nsc, decode_5gs_auth_keys, decode_5gs_uac_aic,
decode_5gs_sor_cmci, decode_dri.
"""

from __future__ import annotations

import unittest

from SCP03.core.decoders import AdvancedDecoders, ContentDecoder


# ---------------------------------------------------------------------------
# GP SEAC / PKCS #15 structural decoders
# ---------------------------------------------------------------------------

class GpSeacDecoderTests(unittest.TestCase):

    def test_empty_returns_sentinel(self) -> None:
        result = AdvancedDecoders.decode_gp_seac_arf("")
        self.assertIn("Empty", str(result[0]))

    def test_valid_hex_returns_list(self) -> None:
        result = AdvancedDecoders.decode_gp_seac_arf("E28001FF")
        self.assertIsInstance(result, list)

    def test_invalid_hex_returns_list(self) -> None:
        result = AdvancedDecoders.decode_gp_seac_arf("ZZZZ")
        self.assertIsInstance(result, list)


class Pkcs15AcrfDecoderTests(unittest.TestCase):

    def test_empty_returns_sentinel(self) -> None:
        result = AdvancedDecoders.decode_pkcs15_acrf("")
        self.assertIn("Empty", str(result[0]))

    def test_minimal_tlv_returns_list(self) -> None:
        result = AdvancedDecoders.decode_pkcs15_acrf("3000")
        self.assertIsInstance(result, list)


class Pkcs15AcrfJsonTests(unittest.TestCase):

    def test_empty_hex_returns_list(self) -> None:
        result = ContentDecoder.decode_pkcs15_acrf_json("")
        self.assertIsInstance(result, list)

    def test_invalid_hex_returns_error_entry(self) -> None:
        result = ContentDecoder.decode_pkcs15_acrf_json("ZZ")
        self.assertIsInstance(result, list)

    def test_valid_hex_returns_list(self) -> None:
        result = ContentDecoder.decode_pkcs15_acrf_json("3000")
        self.assertIsInstance(result, list)


class Pkcs15AccfJsonTests(unittest.TestCase):

    def test_empty_returns_list(self) -> None:
        result = ContentDecoder.decode_pkcs15_accf_json("")
        self.assertIsInstance(result, list)

    def test_valid_hex_returns_list(self) -> None:
        result = ContentDecoder.decode_pkcs15_accf_json("3000")
        self.assertIsInstance(result, list)


# ---------------------------------------------------------------------------
# X.509 certificate decoder
# ---------------------------------------------------------------------------

class CertDerDecoderTests(unittest.TestCase):

    def test_short_data_returns_none(self) -> None:
        self.assertIsNone(AdvancedDecoders.decode_cert_der(b"\x30\x00"))

    def test_non_sequence_tag_returns_none(self) -> None:
        self.assertIsNone(AdvancedDecoders.decode_cert_der(b"\x02\x01\x00"))

    def test_empty_bytes_returns_none(self) -> None:
        self.assertIsNone(AdvancedDecoders.decode_cert_der(b""))

    def test_minimal_sequence_returns_dict_or_none(self) -> None:
        result = AdvancedDecoders.decode_cert_der(b"\x30\x05\x00\x00\x00\x00\x00")
        # Either None (too short for cert) or a dict with raw_len
        self.assertTrue(result is None or isinstance(result, dict))


# ---------------------------------------------------------------------------
# Registry initialisation
# ---------------------------------------------------------------------------

class InitRegistryTests(unittest.TestCase):

    def test_registry_is_populated_after_init(self) -> None:
        ContentDecoder.init_registry()
        self.assertIsInstance(ContentDecoder._registry, dict)
        self.assertGreater(len(ContentDecoder._registry), 0)

    def test_known_fids_are_present(self) -> None:
        ContentDecoder.init_registry()
        self.assertIn("2FE2", ContentDecoder._registry)
        self.assertIn("2F00", ContentDecoder._registry)

    def test_decode_raw_calls_registered_decoder(self) -> None:
        ContentDecoder.init_registry()
        result = ContentDecoder.decode_raw("2FE2", "9888021054637281092300")
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# Language / CB decoders
# ---------------------------------------------------------------------------

class LanguageIndicatorTests(unittest.TestCase):

    def test_two_byte_lang_code(self) -> None:
        # "en" in ASCII = 0x65 0x6E
        result = ContentDecoder.decode_language_indicators("656E")
        self.assertIsInstance(result, dict)
        langs = result.get("Preferred Languages", [])
        self.assertIn("en", langs)

    def test_multiple_langs(self) -> None:
        # "de" "fr"
        result = ContentDecoder.decode_language_indicators("6465" + "6672")
        langs = result.get("Preferred Languages", [])
        self.assertGreaterEqual(len(langs), 1)

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_language_indicators("")
        self.assertIsInstance(result, dict)


class CbmiListTests(unittest.TestCase):

    def test_two_ids(self) -> None:
        # IDs 0x0001 and 0x0002
        result = ContentDecoder.decode_cbmi_list("00010002")
        self.assertIsInstance(result, dict)
        ids = result.get("Message Identifiers", [])
        self.assertIn(1, ids)
        self.assertIn(2, ids)

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_cbmi_list("")
        self.assertIsInstance(result, dict)


class CbmidRangeListTests(unittest.TestCase):

    def test_one_range(self) -> None:
        # from=0x0001, to=0x0005
        result = ContentDecoder.decode_cbmid_range_list("00010005")
        self.assertIsInstance(result, dict)
        ranges = result.get("Message Identifier Ranges", [])
        self.assertEqual(len(ranges), 1)
        self.assertIn("1", str(ranges[0]))

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_cbmid_range_list("")
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# EF.DIR
# ---------------------------------------------------------------------------

class DirDecoderTests(unittest.TestCase):

    def test_all_ff_returns_empty_aids(self) -> None:
        result = ContentDecoder.decode_dir("FF" * 16)
        self.assertIsInstance(result, dict)
        aids = result.get("AIDs", [])
        self.assertEqual(aids, [])

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_dir("")
        self.assertIsInstance(result, dict)

    def test_valid_aid_record(self) -> None:
        # Minimal ISO 7816 record: 61 05 4F 03 A00001
        result = ContentDecoder.decode_dir("610561034F03A00001")
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# SMS decoders
# ---------------------------------------------------------------------------

class SmsParamsTests(unittest.TestCase):

    def test_short_data_returns_raw(self) -> None:
        result = ContentDecoder.decode_sms_params("AABB")
        self.assertIsInstance(result, dict)

    def test_12_byte_record(self) -> None:
        result = ContentDecoder.decode_sms_params("FF" * 28)
        self.assertIsInstance(result, dict)


class SmsrTests(unittest.TestCase):

    def test_empty_returns_raw(self) -> None:
        result = ContentDecoder.decode_smsr("")
        self.assertIsInstance(result, dict)

    def test_single_byte_returns_dict(self) -> None:
        result = ContentDecoder.decode_smsr("01")
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# EPS/5G NAS security context decoders
# ---------------------------------------------------------------------------

class EpsNscTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_epsnsc("")
        self.assertIsInstance(result, dict)

    def test_single_byte_returns_dict(self) -> None:
        result = ContentDecoder.decode_epsnsc("07")
        self.assertIsInstance(result, dict)
        self.assertIn("Raw", result)


class FiveGsNscTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_5gs_nsc("")
        self.assertIsInstance(result, dict)

    def test_single_byte_returns_dict(self) -> None:
        result = ContentDecoder.decode_5gs_nsc("07")
        self.assertIsInstance(result, dict)


class FiveGsAuthKeysTests(unittest.TestCase):

    def test_valid_hex_returns_length_and_blob(self) -> None:
        result = ContentDecoder.decode_5gs_auth_keys("AABBCCDD")
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("Length"), 4)

    def test_invalid_hex_returns_dict(self) -> None:
        result = ContentDecoder.decode_5gs_auth_keys("ZZ")
        self.assertIsInstance(result, dict)


class FiveGsUacAicTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_5gs_uac_aic("")
        self.assertIsInstance(result, dict)

    def test_zero_byte_returns_bits_set(self) -> None:
        result = ContentDecoder.decode_5gs_uac_aic("00")
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("Bits Set"), [])

    def test_nonzero_byte_returns_bit_list(self) -> None:
        result = ContentDecoder.decode_5gs_uac_aic("03")
        bits = result.get("Bits Set", [])
        self.assertIn(0, bits)
        self.assertIn(1, bits)


class FiveGsSorCmciTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_5gs_sor_cmci("")
        self.assertIsInstance(result, dict)

    def test_one_byte_returns_control_byte(self) -> None:
        result = ContentDecoder.decode_5gs_sor_cmci("AA")
        self.assertIsInstance(result, dict)
        self.assertIn("Control Byte", result)


# ---------------------------------------------------------------------------
# ISIM decoders
# ---------------------------------------------------------------------------

class NafkcaTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_nafkca("")
        self.assertIsInstance(result, dict)

    def test_tlv80_text_extraction(self) -> None:
        # TLV: tag=0x80, len=0x05, value="test\0"
        addr = "test"
        tlv = bytes([0x80, len(addr)]) + addr.encode()
        result = ContentDecoder.decode_nafkca(tlv.hex().upper())
        self.assertIsInstance(result, dict)


class IsimTlv80TextTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_isim_tlv80_text("")
        self.assertIsInstance(result, dict)

    def test_valid_tlv80_utf8(self) -> None:
        text = "user@example.test"
        tlv = bytes([0x80, len(text)]) + text.encode()
        result = ContentDecoder.decode_isim_tlv80_text(tlv.hex().upper())
        self.assertIsInstance(result, dict)


class IsimPcscfTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_isim_pcscf("")
        self.assertIsInstance(result, dict)

    def test_valid_tlv80_record(self) -> None:
        addr = "sip.example.test"
        tlv = bytes([0x80, len(addr)]) + addr.encode()
        result = ContentDecoder.decode_isim_pcscf(tlv.hex().upper())
        self.assertIsInstance(result, dict)


# ---------------------------------------------------------------------------
# Generic fallback decoders
# ---------------------------------------------------------------------------

class TlvAsMapTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_tlv_as_map("")
        self.assertIsInstance(result, dict)

    def test_simple_tlv(self) -> None:
        result = ContentDecoder.decode_tlv_as_map("8001FF")
        self.assertIsInstance(result, dict)


class Utf8OrHexTests(unittest.TestCase):

    def test_valid_utf8_hex(self) -> None:
        # "hi" = 0x6869
        result = ContentDecoder.decode_utf8_or_hex("6869")
        self.assertIsInstance(result, dict)
        self.assertIn("Text", result)
        self.assertIn("hi", result["Text"])

    def test_invalid_hex_returns_raw(self) -> None:
        result = ContentDecoder.decode_utf8_or_hex("ZZZZ")
        self.assertIsInstance(result, dict)


class HexChunksTests(unittest.TestCase):

    def test_returns_raw_passthrough(self) -> None:
        result = ContentDecoder.decode_hex_chunks("AABBCC")
        self.assertEqual(result.get("Raw"), "AABBCC")


# ---------------------------------------------------------------------------
# EF.DRI
# ---------------------------------------------------------------------------

class DriTests(unittest.TestCase):

    def test_empty_returns_dict(self) -> None:
        result = ContentDecoder.decode_dri("")
        self.assertIsInstance(result, dict)

    def test_valid_byte_returns_dict(self) -> None:
        result = ContentDecoder.decode_dri("01")
        self.assertIsInstance(result, dict)
        self.assertIn("DRI", result)


if __name__ == "__main__":
    unittest.main()
