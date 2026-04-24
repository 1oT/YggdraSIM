"""
Remaining-gap closure tests — structured decoders + round-trip encoders
for the ``_PASSTHROUGH_BYTES_FIELD_NAMES`` entries that were previously
hex-only on the editor surface:

* ``restrictParameter``                (SAIP §8.6.6 / GP Amd F §A.4)
* GP memory quotas (C7/C8/reserved/cumulative; GP Amd A §5.1.2)
* ``ts102226SIMFileAccessToolkitParameter`` (TS 102 226 §8.2.1.3.2.3)
* ``uiccAccessApplicationSpecificParametersField`` and the
  administrative variant (TS 102 226 §8.2.1.3.2.2)

The tests assert both the decoder's semantic output and the matching
encoder's round-trip identity from the decoder's dictionary form back to
the original on-card bytes.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _GP_MEMORY_QUOTA_FIELD_LABELS,
    _RESTRICT_PARAMETER_BITS,
    _decode_gp_memory_quota_field,
    _decode_restrict_parameter,
    _decode_special_field,
    _decode_ts102226_sim_file_access_toolkit_parameter,
    _decode_uicc_access_application_specific_parameters,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    _GP_MEMORY_QUOTA_FIELD_NAMES,
    encode_decoded_roundtrip_bytes,
    encode_restrict_parameter_field,
    encode_ts102226_sim_file_access_toolkit_parameter_field,
    encode_uicc_access_application_specific_parameters_field,
    encode_uicc_administrative_access_application_specific_parameters_field,
)


class RestrictParameterDecodingTests(unittest.TestCase):
    def test_decode_restrict_open_personalisation_bit(self):
        decoded = _decode_restrict_parameter(bytes.fromhex("01"))
        self.assertIsInstance(decoded, dict)
        assert decoded is not None
        self.assertEqual(decoded["bitmap"], "0x01")
        self.assertEqual(
            decoded["activeRestrictions"],
            ["Restrict Open Personalisation"],
        )
        self.assertEqual(decoded["rfuBitsMask"], "0x00")
        self.assertNotIn("rfuBitsSet", decoded)

    def test_decode_multiple_bits_enumerates_all_labels(self):
        decoded = _decode_restrict_parameter(bytes.fromhex("03"))
        assert decoded is not None
        self.assertEqual(
            decoded["activeRestrictions"],
            [
                "Restrict Open Personalisation",
                "Restrict Contactless Self-Activation",
            ],
        )

    def test_decode_rfu_bits_are_flagged(self):
        decoded = _decode_restrict_parameter(bytes.fromhex("84"))
        assert decoded is not None
        self.assertEqual(decoded["rfuBitsMask"], "0x84")
        self.assertTrue(decoded.get("rfuBitsSet"))
        self.assertEqual(decoded["activeRestrictions"], [])

    def test_decode_rejects_non_one_byte_input(self):
        self.assertIsNone(_decode_restrict_parameter(b""))
        self.assertIsNone(_decode_restrict_parameter(b"\x00\x00"))

    def test_decode_special_field_dispatches_to_restrict_decoder(self):
        decoded = _decode_special_field("restrictParameter", bytes.fromhex("02"))
        assert isinstance(decoded, dict)
        self.assertEqual(
            decoded["activeRestrictions"],
            ["Restrict Contactless Self-Activation"],
        )

    def test_bits_table_has_known_entries(self):
        self.assertEqual(_RESTRICT_PARAMETER_BITS[0x01], "Restrict Open Personalisation")
        self.assertEqual(
            _RESTRICT_PARAMETER_BITS[0x02],
            "Restrict Contactless Self-Activation",
        )


class RestrictParameterEncodingTests(unittest.TestCase):
    def test_encoder_accepts_hex_passthrough(self):
        self.assertEqual(
            encode_restrict_parameter_field({"hex": "03"}),
            bytes.fromhex("03"),
        )

    def test_encoder_accepts_bitmap_form(self):
        self.assertEqual(
            encode_restrict_parameter_field({"bitmap": "0x02"}),
            bytes.fromhex("02"),
        )

    def test_encoder_accepts_active_restrictions_list(self):
        encoded = encode_restrict_parameter_field(
            {"activeRestrictions": ["Restrict Open Personalisation"]}
        )
        self.assertEqual(encoded, bytes.fromhex("01"))

    def test_encoder_combines_active_restrictions(self):
        encoded = encode_restrict_parameter_field(
            {
                "activeRestrictions": [
                    "Restrict Open Personalisation",
                    "Restrict Contactless Self-Activation",
                ]
            }
        )
        self.assertEqual(encoded, bytes.fromhex("03"))

    def test_encoder_rejects_unknown_restriction_name(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_restrict_parameter_field({"activeRestrictions": ["nope"]})

    def test_encoder_rejects_missing_fields(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_restrict_parameter_field({})

    def test_round_trip_through_dispatcher(self):
        decoded = _decode_restrict_parameter(bytes.fromhex("03"))
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes("restrictParameter", decoded)
        self.assertEqual(encoded, bytes.fromhex("03"))


class GpMemoryQuotaDecodingTests(unittest.TestCase):
    def test_decode_two_byte_quota(self):
        decoded = _decode_gp_memory_quota_field(
            "volatileMemoryQuotaC7", bytes.fromhex("1000")
        )
        assert decoded is not None
        self.assertEqual(decoded["length"], 2)
        self.assertEqual(decoded["decimal"], 4096)
        self.assertIn("volatile memory quota", decoded["format"])

    def test_decode_four_byte_quota(self):
        decoded = _decode_gp_memory_quota_field(
            "cumulativeGrantedNonVolatileMemory",
            bytes.fromhex("00010000"),
        )
        assert decoded is not None
        self.assertEqual(decoded["length"], 4)
        self.assertEqual(decoded["decimal"], 65536)

    def test_decode_rejects_length_out_of_range(self):
        self.assertIsNone(
            _decode_gp_memory_quota_field("volatileMemoryQuotaC7", b"\x10")
        )
        self.assertIsNone(
            _decode_gp_memory_quota_field("volatileMemoryQuotaC7", b"\x00" * 5)
        )

    def test_decode_rejects_unknown_field(self):
        self.assertIsNone(
            _decode_gp_memory_quota_field("bogusField", bytes.fromhex("1000"))
        )

    def test_field_label_catalog_matches_encoder_names(self):
        self.assertEqual(
            set(_GP_MEMORY_QUOTA_FIELD_LABELS),
            set(_GP_MEMORY_QUOTA_FIELD_NAMES),
        )


class GpMemoryQuotaEncodingTests(unittest.TestCase):
    def test_hex_passthrough_wins(self):
        encoded = encode_decoded_roundtrip_bytes(
            "volatileMemoryQuotaC7",
            {"hex": "1000", "decimal": 42},
        )
        self.assertEqual(encoded, bytes.fromhex("1000"))

    def test_decimal_encodes_to_two_bytes_when_fits(self):
        encoded = encode_decoded_roundtrip_bytes(
            "volatileMemoryQuotaC7",
            {"decimal": 4096},
        )
        self.assertEqual(encoded, bytes.fromhex("1000"))

    def test_decimal_encodes_to_three_bytes_when_needed(self):
        encoded = encode_decoded_roundtrip_bytes(
            "cumulativeGrantedVolatileMemory",
            {"decimal": 70000},
        )
        self.assertEqual(encoded, bytes.fromhex("011170"))

    def test_decimal_capped_at_four_bytes(self):
        encoded = encode_decoded_roundtrip_bytes(
            "cumulativeGrantedNonVolatileMemory",
            {"decimal": 2**31},
        )
        self.assertEqual(encoded, (2**31).to_bytes(4, "big"))

    def test_decimal_rejects_value_that_exceeds_four_bytes(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "nonVolatileMemoryQuotaC8",
                {"decimal": 2**32},
            )

    def test_missing_hex_and_decimal_is_rejected(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("nonVolatileReservedMemory", {})

    def test_negative_decimal_is_rejected(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "volatileReservedMemory", {"decimal": -1}
            )

    def test_round_trip_through_decoder_and_encoder(self):
        for field_name in _GP_MEMORY_QUOTA_FIELD_NAMES:
            decoded = _decode_special_field(field_name, bytes.fromhex("00001000"))
            assert isinstance(decoded, dict)
            encoded = encode_decoded_roundtrip_bytes(field_name, decoded)
            self.assertEqual(encoded, bytes.fromhex("00001000"))


class Ts102226FileAccessToolkitDecodingTests(unittest.TestCase):
    def test_decode_splits_toolkit_and_file_access_sections(self):
        payload = bytes.fromhex("02AABB02CCDD")
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(payload)
        assert decoded is not None
        self.assertEqual(decoded["simToolkitApplicationParameters"]["length"], 2)
        self.assertEqual(
            decoded["simToolkitApplicationParameters"]["hex"], "AABB"
        )
        self.assertEqual(decoded["simFileAccessParameters"]["length"], 2)
        self.assertEqual(decoded["simFileAccessParameters"]["hex"], "CCDD")

    def test_decode_captures_trailing_bytes_when_present(self):
        payload = bytes.fromhex("0102020304FFFF")
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(payload)
        assert decoded is not None
        self.assertEqual(decoded.get("trailingBytes"), "FFFF")

    def test_decode_rejects_truncated_toolkit_section(self):
        self.assertIsNone(
            _decode_ts102226_sim_file_access_toolkit_parameter(
                bytes.fromhex("05AABB")
            )
        )

    def test_decode_rejects_truncated_file_access_section(self):
        self.assertIsNone(
            _decode_ts102226_sim_file_access_toolkit_parameter(
                bytes.fromhex("01AA0500")
            )
        )

    def test_decoder_dispatches_via_special_field(self):
        decoded = _decode_special_field(
            "ts102226SIMFileAccessToolkitParameter",
            bytes.fromhex("0102020304"),
        )
        assert isinstance(decoded, dict)
        self.assertEqual(
            decoded["simFileAccessParameters"]["hex"], "0304"
        )


class Ts102226FileAccessToolkitEncodingTests(unittest.TestCase):
    def test_hex_passthrough_roundtrips(self):
        payload = bytes.fromhex("0102020304")
        encoded = encode_ts102226_sim_file_access_toolkit_parameter_field(
            {"hex": payload.hex().upper()}
        )
        self.assertEqual(encoded, payload)

    def test_structured_encoding_matches_decoder_output(self):
        source = bytes.fromhex("0102020304")
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(source)
        assert decoded is not None
        decoded.pop("hex")
        encoded = encode_ts102226_sim_file_access_toolkit_parameter_field(decoded)
        self.assertEqual(encoded, source)

    def test_trailing_bytes_are_appended(self):
        encoded = encode_ts102226_sim_file_access_toolkit_parameter_field(
            {
                "simToolkitApplicationParameters": {"hex": "AA"},
                "simFileAccessParameters": {"hex": "BB"},
                "trailingBytes": "CC",
            }
        )
        self.assertEqual(encoded, bytes.fromhex("01AA01BBCC"))

    def test_missing_sections_raise(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_ts102226_sim_file_access_toolkit_parameter_field({})

    def test_over_long_section_rejected(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_ts102226_sim_file_access_toolkit_parameter_field(
                {
                    "simToolkitApplicationParameters": {
                        "hex": "00" * 256,
                    },
                    "simFileAccessParameters": {"hex": "00"},
                }
            )


class UiccAccessApplicationParametersDecodingTests(unittest.TestCase):
    def test_decode_full_access_record(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("0100"),
            administrative=False,
        )
        assert decoded is not None
        records = decoded["accessDomainRecords"]
        assert isinstance(records, list)
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["domainLabel"],
            "Full access to the UICC file system",
        )
        self.assertEqual(records[0]["declaredLength"], 1)

    def test_decode_chv_access_record_has_bitmap(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("050201020304"),
            administrative=False,
        )
        assert decoded is not None
        records = decoded["accessDomainRecords"]
        assert isinstance(records, list)
        self.assertEqual(records[0]["chvReferenceBitmap"], "01020304")
        self.assertEqual(
            records[0]["domainLabel"],
            "Access granted to CHV references (3G/UICC)",
        )

    def test_decode_administrative_label_differs(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("01FF"),
            administrative=True,
        )
        assert decoded is not None
        self.assertIn("administrative", decoded["format"])

    def test_decode_rejects_length_overflow(self):
        self.assertIsNone(
            _decode_uicc_access_application_specific_parameters(
                bytes.fromhex("050102"),
                administrative=False,
            )
        )

    def test_decoder_dispatches_via_special_field(self):
        decoded = _decode_special_field(
            "uiccAdministrativeAccessApplicationSpecificParametersField",
            bytes.fromhex("01FF"),
        )
        assert isinstance(decoded, dict)
        self.assertIn("administrative", decoded["format"])

    def test_multiple_records_are_captured(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("010001FF"),
            administrative=False,
        )
        assert decoded is not None
        self.assertEqual(len(decoded["accessDomainRecords"]), 2)


class UiccAccessApplicationParametersEncodingTests(unittest.TestCase):
    def test_hex_passthrough_roundtrips(self):
        payload = bytes.fromhex("050201020304")
        encoded = encode_uicc_access_application_specific_parameters_field(
            {"hex": payload.hex().upper()}
        )
        self.assertEqual(encoded, payload)

    def test_structured_roundtrip_matches_decoder(self):
        source = bytes.fromhex("050201020304")
        decoded = _decode_uicc_access_application_specific_parameters(
            source, administrative=False
        )
        assert decoded is not None
        decoded.pop("hex")
        encoded = encode_uicc_access_application_specific_parameters_field(decoded)
        self.assertEqual(encoded, source)

    def test_administrative_encoder_roundtrips(self):
        source = bytes.fromhex("01FF")
        decoded = _decode_uicc_access_application_specific_parameters(
            source, administrative=True
        )
        assert decoded is not None
        decoded.pop("hex")
        encoded = encode_uicc_administrative_access_application_specific_parameters_field(
            decoded
        )
        self.assertEqual(encoded, source)

    def test_missing_fields_raise(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_uicc_access_application_specific_parameters_field({})

    def test_record_without_hex_is_rejected(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_uicc_access_application_specific_parameters_field(
                {"accessDomainRecords": [{"domainByte": "0x00"}]}
            )

    def test_record_over_255_bytes_rejected(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_uicc_access_application_specific_parameters_field(
                {
                    "accessDomainRecords": [
                        {"hex": "00" * 256},
                    ]
                }
            )

    def test_dispatcher_round_trip_identity(self):
        source = bytes.fromhex("010001FF")
        decoded = _decode_uicc_access_application_specific_parameters(
            source, administrative=False
        )
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "uiccAccessApplicationSpecificParametersField", decoded
        )
        self.assertEqual(encoded, source)


if __name__ == "__main__":
    unittest.main()
