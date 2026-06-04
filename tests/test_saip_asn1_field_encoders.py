# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the 55 encode_* functions in saip_asn1_encode not covered by prior suites.

Groups:
  - Enum-name encoders (life-cycle-state, key-access, key-type, algorithm-id)
  - Single-byte encoders (pin-attributes, msl, aka-option, counter, tar, access-domain)
  - Integer-return encoders (retry-counter, mac-length, fill-file-offset, puk-ref,
    adm-key-ref, version fields, identification, short-efid, template-id)
  - Multi-byte / hex-passthrough field encoders
  - Complex structured encoders (profile-policy-rules, application-privileges,
    global-service-parameters, implicit-selection, restrict-parameter,
    contactless-protocol-parameters, user-interaction-contactless-parameters,
    application-provider-identifier, ts102226-sim-file-access-toolkit)
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_access_domain,
    encode_adf_rfm_access_field,
    encode_aka_option_octet,
    encode_aka_secret_material,
    encode_algorithm_id,
    encode_application_privileges,
    encode_application_provider_identifier_field,
    encode_contactless_protocol_parameters_field,
    encode_counter_field,
    encode_custom_field_octets,
    encode_fill_file_offset,
    encode_global_service_parameters_field,
    encode_hash_value_field,
    encode_iccid_field,
    encode_identification_field,
    encode_implicit_selection_parameter_field,
    encode_key_access,
    encode_key_counter_value,
    encode_key_identifier,
    encode_key_type,
    encode_life_cycle_state,
    encode_mac_length,
    encode_major_version_field,
    encode_mapping_options_field,
    encode_mapping_source_field,
    encode_memory_limit_field,
    encode_minimum_security_level,
    encode_minor_version_field,
    encode_notification_address_field,
    encode_number_of_keccak,
    encode_pin_attributes,
    encode_pin_puk_retry_counter,
    encode_process_data_field,
    encode_profile_policy_rules,
    encode_profile_version_field,
    encode_proprietary_ef_info_field,
    encode_puk_key_reference,
    encode_restrict_parameter_field,
    encode_rotation_constants,
    encode_sd_perso_data_field,
    encode_serial_number_field,
    encode_short_efid_field,
    encode_tar_value,
    encode_tlv_bytes_field,
    encode_uicc_access_application_specific_parameters_field,
    encode_uicc_administrative_access_application_specific_parameters_field,
    encode_user_interaction_contactless_parameters_field,
    encode_xoring_constants,
    encode_lcsi_field,
    encode_key_usage_qualifier,
    encode_key_version_number,
    encode_pin_puk_adm_key_reference,
    encode_sd_perso_data_field,
    encode_template_id_field,
)


# ---------------------------------------------------------------------------
# Enum-name encoders
# ---------------------------------------------------------------------------

class EnumNameEncoderTests(unittest.TestCase):

    def test_life_cycle_state_loaded(self) -> None:
        result = encode_life_cycle_state({"state": "Loaded"})
        self.assertEqual(result, bytes([1]))

    def test_life_cycle_state_personalized(self) -> None:
        result = encode_life_cycle_state({"state": "Personalized"})
        self.assertEqual(result, bytes([15]))

    def test_life_cycle_state_unknown_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_life_cycle_state({"state": "Invalid"})

    def test_key_access_sd_only(self) -> None:
        result = encode_key_access({"access": "Security Domain only"})
        self.assertEqual(result, bytes([1]))

    def test_key_access_not_available(self) -> None:
        result = encode_key_access({"access": "Not available"})
        self.assertEqual(result, bytes([255]))

    def test_key_access_unknown_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_key_access({"access": "bogus"})

    def test_key_type_aes(self) -> None:
        result = encode_key_type({"type": "AES"})
        self.assertEqual(result, bytes([136]))

    def test_key_type_des(self) -> None:
        result = encode_key_type({"type": "DES"})
        self.assertEqual(result, bytes([128]))

    def test_key_type_extended_manual_values(self) -> None:
        self.assertEqual(encode_key_type({"type": "RSA Private Exponent"}), bytes([0xA3]))
        self.assertEqual(encode_key_type({"type": "ECC public key"}), bytes([0xB0]))

    def test_key_type_unknown_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_key_type({"type": "bogus"})

    def test_algorithm_id_milenage(self) -> None:
        result = encode_algorithm_id({"algorithm": "milenage"})
        self.assertEqual(result, 1)

    def test_algorithm_id_tuak(self) -> None:
        result = encode_algorithm_id({"algorithm": "tuak"})
        self.assertEqual(result, 2)

    def test_algorithm_id_decimal(self) -> None:
        result = encode_algorithm_id({"decimal": 3})
        self.assertEqual(result, 3)

    def test_algorithm_id_unknown_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_algorithm_id({"algorithm": "nonexistent"})


# ---------------------------------------------------------------------------
# Single-byte encoders
# ---------------------------------------------------------------------------

class SingleByteEncoderTests(unittest.TestCase):

    def test_pin_attributes_zero(self) -> None:
        self.assertEqual(encode_pin_attributes({"decimal": 0}), bytes([0]))

    def test_pin_attributes_max(self) -> None:
        self.assertEqual(encode_pin_attributes({"decimal": 255}), bytes([255]))

    def test_pin_attributes_out_of_range_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_pin_attributes({"decimal": 256})

    def test_minimum_security_level_mid(self) -> None:
        self.assertEqual(encode_minimum_security_level({"decimal": 0x11}), bytes([0x11]))

    def test_minimum_security_level_out_of_range_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_minimum_security_level({"decimal": 300})

    def test_aka_option_octet_zero(self) -> None:
        self.assertEqual(encode_aka_option_octet({"decimal": 0}), bytes([0]))

    def test_aka_option_octet_max(self) -> None:
        self.assertEqual(encode_aka_option_octet({"decimal": 0xFF}), bytes([0xFF]))

    def test_aka_option_octet_overflow_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_aka_option_octet({"decimal": 256})

    def test_tar_value_hex(self) -> None:
        self.assertEqual(encode_tar_value({"hex": "B00010"}), bytes.fromhex("B00010"))

    def test_access_domain_hex(self) -> None:
        self.assertEqual(encode_access_domain({"hex": "FF"}), bytes([0xFF]))


# ---------------------------------------------------------------------------
# Key integer fields
# ---------------------------------------------------------------------------

class KeyIntegerFieldTests(unittest.TestCase):

    def test_key_identifier_valid(self) -> None:
        self.assertEqual(encode_key_identifier({"decimal": 1}), bytes([1]))

    def test_key_identifier_max(self) -> None:
        self.assertEqual(encode_key_identifier({"decimal": 255}), bytes([255]))

    def test_key_identifier_overflow_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_key_identifier({"decimal": 256})

    def test_key_version_number_valid(self) -> None:
        self.assertEqual(encode_key_version_number({"decimal": 1}), bytes([1]))

    def test_key_version_number_overflow_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_key_version_number({"decimal": 256})

    def test_key_counter_value_decimal(self) -> None:
        result = encode_key_counter_value({"decimal": 5})
        self.assertIsInstance(result, (bytes, bytearray))
        self.assertGreater(len(result), 0)

    def test_key_counter_value_hex(self) -> None:
        result = encode_key_counter_value({"hex": "0005"})
        self.assertIsInstance(result, (bytes, bytearray))


# ---------------------------------------------------------------------------
# Integer-return encoders
# ---------------------------------------------------------------------------

class IntReturnEncoderTests(unittest.TestCase):

    def test_pin_puk_retry_counter_packs_nibbles(self) -> None:
        result = encode_pin_puk_retry_counter({"maxAttempts": 3, "remainingAttempts": 3})
        self.assertEqual(result, 0x33)

    def test_pin_puk_retry_counter_max_overflow_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_pin_puk_retry_counter({"maxAttempts": 16, "remainingAttempts": 3})

    def test_mac_length_zero(self) -> None:
        self.assertEqual(encode_mac_length({"decimal": 0}), 0)

    def test_mac_length_negative_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_mac_length({"decimal": -1})

    def test_fill_file_offset_valid(self) -> None:
        self.assertEqual(encode_fill_file_offset({"decimal": 10}), 10)

    def test_fill_file_offset_negative_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_fill_file_offset({"decimal": -1})

    def test_puk_key_reference_valid(self) -> None:
        result = encode_puk_key_reference({"decimal": 2})
        self.assertEqual(result, 2)

    def test_pin_puk_adm_key_reference_valid(self) -> None:
        result = encode_pin_puk_adm_key_reference({"decimal": 5})
        self.assertEqual(result, 5)

    def test_major_version_field_valid(self) -> None:
        self.assertEqual(encode_major_version_field({"decimal": 1}), 1)

    def test_major_version_field_overflow_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_major_version_field({"decimal": 256})

    def test_minor_version_field_valid(self) -> None:
        self.assertEqual(encode_minor_version_field({"decimal": 0}), 0)

    def test_identification_field_valid(self) -> None:
        self.assertEqual(encode_identification_field({"decimal": 42}), 42)

    def test_identification_field_negative_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_identification_field({"decimal": -1})

    def test_short_efid_field_valid(self) -> None:
        result = encode_short_efid_field({"decimal": 10})
        self.assertIsInstance(result, int)

    def test_template_id_field_valid(self) -> None:
        result = encode_template_id_field({"decimal": 1})
        self.assertIsInstance(result, int)


# ---------------------------------------------------------------------------
# Multi-byte / hex-passthrough field encoders
# ---------------------------------------------------------------------------

class HexFieldEncoderTests(unittest.TestCase):

    def _check_hex(self, fn, hex_val: str = "DEADBEEF") -> None:
        # All _encode_tagged_hex_passthrough functions expect {"hex": ...}
        result = fn({"hex": hex_val})
        self.assertEqual(result, bytes.fromhex(hex_val))

    def test_iccid_field(self) -> None:
        # ICCID: 10 bytes = 20 hex nibbles
        result = encode_iccid_field({"hex": "98880200000000000000"})
        self.assertIsInstance(result, bytes)

    def test_hash_value_field(self) -> None:
        self._check_hex(encode_hash_value_field, "AABBCC")

    def test_lcsi_field(self) -> None:
        self._check_hex(encode_lcsi_field, "07")

    def test_adf_rfm_access_field(self) -> None:
        self._check_hex(encode_adf_rfm_access_field, "80")

    def test_mapping_options_field(self) -> None:
        self._check_hex(encode_mapping_options_field, "01")

    def test_mapping_source_field(self) -> None:
        self._check_hex(encode_mapping_source_field, "02")

    def test_process_data_field(self) -> None:
        self._check_hex(encode_process_data_field, "CAFE")

    def test_sd_perso_data_field(self) -> None:
        self._check_hex(encode_sd_perso_data_field, "BEEF")

    def test_proprietary_ef_info_field(self) -> None:
        self._check_hex(encode_proprietary_ef_info_field, "AA")

    def test_tlv_bytes_field(self) -> None:
        self._check_hex(encode_tlv_bytes_field, "8001FF")

    def test_profile_version_field(self) -> None:
        self._check_hex(encode_profile_version_field, "010200")

    def test_custom_field_octets(self) -> None:
        self._check_hex(encode_custom_field_octets, "1234")

    def test_serial_number_field(self) -> None:
        self._check_hex(encode_serial_number_field, "ABCD")

    def test_notification_address_field(self) -> None:
        result = encode_notification_address_field({"hex": "AABB"})
        self.assertIsInstance(result, bytes)

    def test_aka_secret_material_hex(self) -> None:
        result = encode_aka_secret_material({"hex": "00" * 16})
        self.assertEqual(result, bytes(16))


# ---------------------------------------------------------------------------
# Counter and Keccak encoders
# ---------------------------------------------------------------------------

class CounterEncoderTests(unittest.TestCase):

    def test_counter_field_decimal(self) -> None:
        result = encode_counter_field({"decimal": 100})
        self.assertIsInstance(result, (bytes, bytearray))

    def test_counter_field_hex(self) -> None:
        result = encode_counter_field({"hex": "0064"})
        self.assertIsInstance(result, (bytes, bytearray))

    def test_memory_limit_field_hex(self) -> None:
        result = encode_memory_limit_field({"hex": "0100"})
        self.assertEqual(result, bytes.fromhex("0100"))

    def test_number_of_keccak_hex(self) -> None:
        result = encode_number_of_keccak({"hex": "0002"})
        self.assertEqual(result, bytes.fromhex("0002"))


# ---------------------------------------------------------------------------
# Rotation/XOR constants
# ---------------------------------------------------------------------------

class ConstantsEncoderTests(unittest.TestCase):

    def test_rotation_constants_hex(self) -> None:
        # 5 bytes exactly, passed as hex
        result = encode_rotation_constants({"hex": "0102030405"})
        self.assertEqual(result, bytes([1, 2, 3, 4, 5]))

    def test_rotation_constants_r_fields(self) -> None:
        payload = {"r1": 1, "r2": 2, "r3": 3, "r4": 4, "r5": 5}
        result = encode_rotation_constants(payload)
        self.assertEqual(result, bytes([1, 2, 3, 4, 5]))

    def test_rotation_constants_missing_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_rotation_constants({})

    def test_xoring_constants_hex(self) -> None:
        result = encode_xoring_constants({"hex": "00" * 16})
        self.assertEqual(result, bytes(16))

    def test_xoring_constants_block_count(self) -> None:
        result = encode_xoring_constants({"blockCount": 1, "c1": "AA" * 16})
        self.assertEqual(len(result), 16)

    def test_xoring_constants_missing_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_xoring_constants({})


# ---------------------------------------------------------------------------
# Bitmap/flag encoders
# ---------------------------------------------------------------------------

class BitmapEncoderTests(unittest.TestCase):

    def test_profile_policy_rules_hex(self) -> None:
        result = encode_profile_policy_rules({"hex": "01"})
        self.assertEqual(result, bytes([1]))

    def test_profile_policy_rules_set_bits(self) -> None:
        result = encode_profile_policy_rules({"setBits": [0]})
        self.assertEqual(result, bytes([1]))

    def test_profile_policy_rules_empty_bits(self) -> None:
        result = encode_profile_policy_rules({"setBits": []})
        self.assertEqual(result, bytes([0]))

    def test_profile_policy_rules_missing_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_profile_policy_rules({})

    def test_application_privileges_hex(self) -> None:
        result = encode_application_privileges({"hex": "80"})
        self.assertEqual(result, bytes([0x80]))

    def test_key_usage_qualifier_hex(self) -> None:
        result = encode_key_usage_qualifier({"hex": "3C"})
        self.assertEqual(result, bytes([0x3C]))

    def test_global_service_parameters_hex(self) -> None:
        result = encode_global_service_parameters_field({"hex": "01"})
        self.assertEqual(result, bytes([0x01]))

    def test_implicit_selection_parameter_hex(self) -> None:
        result = encode_implicit_selection_parameter_field({"hex": "01"})
        self.assertEqual(result, bytes([0x01]))

    def test_restrict_parameter_hex(self) -> None:
        result = encode_restrict_parameter_field({"hex": "00"})
        self.assertEqual(result, bytes([0x00]))


# ---------------------------------------------------------------------------
# Complex structured encoders — hex passthrough path
# ---------------------------------------------------------------------------

class ComplexStructuredEncoderTests(unittest.TestCase):

    def test_contactless_protocol_parameters_hex(self) -> None:
        result = encode_contactless_protocol_parameters_field({"hex": "8001FF"})
        self.assertEqual(result, bytes.fromhex("8001FF"))

    def test_user_interaction_contactless_parameters_hex(self) -> None:
        result = encode_user_interaction_contactless_parameters_field({"hex": "8001AA"})
        self.assertEqual(result, bytes.fromhex("8001AA"))

    def test_application_provider_identifier_hex(self) -> None:
        result = encode_application_provider_identifier_field({"hex": "2A864886"})
        self.assertEqual(result, bytes.fromhex("2A864886"))

    def test_ts102226_sim_file_access_toolkit_hex(self) -> None:
        from Tools.ProfilePackage.saip_asn1_encode import (
            encode_ts102226_sim_file_access_toolkit_parameter_field,
        )
        result = encode_ts102226_sim_file_access_toolkit_parameter_field({"hex": "01AABB"})
        self.assertEqual(result, bytes.fromhex("01AABB"))

    def test_uicc_access_app_specific_params_hex(self) -> None:
        result = encode_uicc_access_application_specific_parameters_field(
            {"hex": "AABB"}
        )
        self.assertEqual(result, bytes.fromhex("AABB"))

    def test_uicc_admin_access_app_specific_params_hex(self) -> None:
        result = encode_uicc_administrative_access_application_specific_parameters_field(
            {"hex": "CCDD"}
        )
        self.assertEqual(result, bytes.fromhex("CCDD"))


if __name__ == "__main__":
    unittest.main()
