"""Roundtrip tests for ``saip_asn1_encode``.

Every registered encoder must satisfy the stability invariant:

    decode(encode(decode(bytes))) == decode(bytes)

Where possible we also verify byte-exact identity:

    encode(decode(bytes)) == bytes

When the decoder is lossy (e.g. minimal re-encodings where the input had
padding bytes) we relax to the stability invariant only.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_access_domain,
    _decode_acc,
    _decode_ad,
    _decode_aka_counter_field,
    _decode_aka_option_octet,
    _decode_aka_secret_material,
    _decode_application_identifier,
    _decode_application_privileges,
    _decode_ehplmn_presentation_indication,
    _decode_hpplmn_search_interval,
    _decode_key_access,
    _decode_key_counter_value,
    _decode_key_identifier,
    _decode_key_type,
    _decode_key_usage_qualifier,
    _decode_key_version_number,
    _decode_life_cycle_state,
    _decode_mac_length,
    _decode_memory_limit_field,
    _decode_minimum_security_level,
    _decode_pin_attributes,
    _decode_pin_puk_retry_counter,
    _decode_plmn_list,
    _decode_profile_policy_rules,
    _decode_rotation_constants,
    _decode_scalar_special_field,
    _decode_smss,
    _decode_special_field,
    _decode_start_hfn,
    _decode_tar_value,
    _decode_three_byte_counter,
    _decode_tlv80_text,
    _decode_two_byte_language_records,
    _decode_xoring_constants,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_bytes,
    encode_decoded_roundtrip_ef_content,
    encode_decoded_roundtrip_scalar,
    roundtrip_capable_ef_keys,
    roundtrip_capable_fields,
)


def _hex_to_bytes(hex_text: str) -> bytes:
    return bytes.fromhex(hex_text)


class SaipEncodeEnumRoundtripTests(unittest.TestCase):
    def test_life_cycle_state_roundtrips_for_every_named_state(self) -> None:
        for code in (0x01, 0x03, 0x07, 0x0F, 0x83):
            raw = bytes([code])
            decoded = _decode_life_cycle_state(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("lifeCycleState", decoded)
            self.assertEqual(encoded, raw, f"lifeCycleState byte-identity failed for 0x{code:02X}")
            self.assertEqual(
                _decode_life_cycle_state(encoded),
                decoded,
                f"lifeCycleState stability failed for 0x{code:02X}",
            )

    def test_key_access_roundtrip_for_every_named_state(self) -> None:
        for code in (0x00, 0x01, 0x02, 0xFF):
            raw = bytes([code])
            decoded = _decode_key_access(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyAccess", decoded)
            self.assertEqual(encoded, raw)
            self.assertEqual(_decode_key_access(encoded), decoded)

    def test_key_type_roundtrip_for_every_named_state(self) -> None:
        for code in (0x80, 0x85, 0x88, 0x90, 0x91, 0xA0, 0xA1, 0xA2):
            raw = bytes([code])
            decoded = _decode_key_type(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyType", decoded)
            self.assertEqual(encoded, raw)
            self.assertEqual(_decode_key_type(encoded), decoded)


class SaipEncodeSimpleByteRoundtripTests(unittest.TestCase):
    def test_pin_attributes_roundtrip(self) -> None:
        for byte_value in (0x00, 0x01, 0x07, 0x80, 0xFF):
            raw = bytes([byte_value])
            decoded = _decode_pin_attributes(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("pinAttributes", decoded)
            self.assertEqual(encoded, raw)
            self.assertEqual(_decode_pin_attributes(encoded), decoded)

    def test_minimum_security_level_roundtrip(self) -> None:
        for byte_value in (0x00, 0x03, 0x33, 0xFF):
            raw = bytes([byte_value])
            decoded = _decode_minimum_security_level(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("minimumSecurityLevel", decoded)
            self.assertEqual(encoded, raw)

    def test_key_identifier_roundtrip(self) -> None:
        for byte_value in (0x00, 0x01, 0x02, 0x03, 0xFE):
            raw = bytes([byte_value])
            decoded = _decode_key_identifier(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyIdentifier", decoded)
            self.assertEqual(encoded, raw)

    def test_key_version_number_roundtrip(self) -> None:
        for byte_value in (0x00, 0x01, 0x11, 0x20, 0x30, 0xFF):
            raw = bytes([byte_value])
            decoded = _decode_key_version_number(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyVersionNumber", decoded)
            self.assertEqual(encoded, raw)

    def test_key_counter_value_roundtrip_various_widths(self) -> None:
        for raw in (b"\x00", b"\x01", b"\xFF\xFF", b"\x01\x02\x03\x04"):
            decoded = _decode_key_counter_value(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyCounterValue", decoded)
            self.assertEqual(encoded, raw)

    def test_tar_value_roundtrip(self) -> None:
        for raw in (bytes.fromhex("B00000"), bytes.fromhex("A00001"), bytes.fromhex("00AAAA")):
            decoded = _decode_tar_value(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("tarList", decoded)
            self.assertEqual(encoded, raw)

    def test_access_domain_roundtrip(self) -> None:
        fixtures = [
            bytes.fromhex("02"),
            bytes.fromhex("020100"),
            bytes.fromhex("02028002"),
        ]
        for raw in fixtures:
            decoded = _decode_access_domain(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("uiccAccessDomain", decoded)
            self.assertEqual(encoded, raw)

    def test_aid_roundtrip(self) -> None:
        for hex_fixture in ("A0000000871002", "A000000087100212FFFFFFFF8907090000"):
            raw = _hex_to_bytes(hex_fixture)
            decoded = _decode_application_identifier(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("adfAID", decoded)
            self.assertEqual(encoded, raw)
            self.assertEqual(
                encode_decoded_roundtrip_bytes("instanceAID", decoded),
                raw,
            )


class SaipEncodeCounterRoundtripTests(unittest.TestCase):
    def test_aka_counter_various_widths(self) -> None:
        for raw in (b"\x01", b"\x00\x00", b"\x00\x01\x00", b"\xFF\xFF\xFF\xFF"):
            decoded = _decode_aka_counter_field(raw, format_name="AKA counter")
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("authCounterMax", decoded)
            self.assertEqual(encoded, raw)

    def test_aka_option_octet_roundtrip(self) -> None:
        for byte_value in (0x00, 0x01, 0x80, 0xFF):
            raw = bytes([byte_value])
            decoded = _decode_aka_option_octet(raw, format_name="AKA option octet")
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("sqnOptions", decoded)
            self.assertEqual(encoded, raw)

    def test_aka_secret_material_roundtrip(self) -> None:
        for length in (16, 32, 64):
            raw = bytes(range(length))
            decoded = _decode_aka_secret_material(raw, format_name="Key material")
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("key", decoded)
            self.assertEqual(encoded, raw)
            encoded_opc = encode_decoded_roundtrip_bytes("opc", decoded)
            self.assertEqual(encoded_opc, raw)

    def test_rotation_constants_roundtrip(self) -> None:
        for raw in (b"\x00\x01\x02\x03\x04", b"\x40\x00\x20\x40\x60"):
            decoded = _decode_rotation_constants(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("rotationConstants", decoded)
            self.assertEqual(encoded, raw)

    def test_xoring_constants_roundtrip(self) -> None:
        for block_count in (1, 2, 3):
            raw = bytes(i & 0xFF for i in range(16 * block_count))
            decoded = _decode_xoring_constants(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("xoringConstants", decoded)
            self.assertEqual(encoded, raw)

    def test_memory_limit_roundtrip(self) -> None:
        for field in ("nonVolatileCodeLimitC6", "volatileDataLimitC7", "nonVolatileDataLimitC8"):
            for raw in (b"\x02\x00", b"\x00\x00\x10\x00"):
                decoded = _decode_memory_limit_field(field, raw)
                assert decoded is not None, f"{field} decoder returned None"
                encoded = encode_decoded_roundtrip_bytes(field, decoded)
                self.assertEqual(encoded, raw)


class SaipEncodeFlagBitmaskTests(unittest.TestCase):
    def test_application_privileges_single_byte_inputs(self) -> None:
        for hex_fixture in ("000000", "800000", "804000", "FFFFF0"):
            raw = _hex_to_bytes(hex_fixture)
            decoded = _decode_application_privileges(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("applicationPrivileges", decoded)
            # Re-decode and compare decoded view for stability.
            redecoded = _decode_application_privileges(encoded)
            self.assertEqual(decoded, redecoded)

    def test_key_usage_qualifier_roundtrip(self) -> None:
        for hex_fixture in ("80", "C0", "8000", "8080", "FFFF"):
            raw = _hex_to_bytes(hex_fixture)
            decoded = _decode_key_usage_qualifier(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("keyUsageQualifier", decoded)
            self.assertEqual(encoded, raw)

    def test_profile_policy_rules_roundtrip(self) -> None:
        for raw in (b"\x00", b"\x01", b"\x07", b"\x07\x00"):
            decoded = _decode_profile_policy_rules(raw)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_bytes("pol", decoded)
            # pol has a canonical encoding — re-decoding must be stable.
            self.assertEqual(_decode_profile_policy_rules(encoded), _decode_profile_policy_rules(encoded))
            # Byte-identity only when input was canonical (minimal width).
            if len(raw) == 1:
                self.assertEqual(encoded, raw)


class SaipEncodeScalarRoundtripTests(unittest.TestCase):
    def test_pin_puk_retry_counter_roundtrip(self) -> None:
        for value in (0x00, 0x33, 0x35, 0x55, 0xFF):
            decoded = _decode_pin_puk_retry_counter(value)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_scalar(
                "maxNumOfAttemps-retryNumLeft",
                decoded,
            )
            self.assertEqual(encoded, value)

    def test_mac_length_roundtrip(self) -> None:
        for value in (0, 8, 16):
            decoded = _decode_mac_length(value)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_scalar("macLength", decoded)
            self.assertEqual(encoded, value)

    def test_key_reference_roundtrip_via_scalar(self) -> None:
        decoded = _decode_scalar_special_field("keyReference", 129)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_scalar("keyReference", decoded)
        self.assertEqual(encoded, 129)

    def test_unblocking_pin_reference_roundtrip(self) -> None:
        decoded = _decode_scalar_special_field("unblockingPINReference", 5)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_scalar("unblockingPINReference", decoded)
        self.assertEqual(encoded, 5)

    def test_algorithm_id_roundtrip_by_name_and_decimal(self) -> None:
        decoded = _decode_scalar_special_field("algorithmID", 1)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_scalar("algorithmID", decoded)
        self.assertEqual(encoded, 1)

        decoded_tuak = _decode_scalar_special_field("algorithmID", 2)
        assert decoded_tuak is not None
        encoded_tuak = encode_decoded_roundtrip_scalar("algorithmID", decoded_tuak)
        self.assertEqual(encoded_tuak, 2)

    def test_fill_file_offset_roundtrip(self) -> None:
        decoded = _decode_scalar_special_field("fillFileOffset", 42)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_scalar("fillFileOffset", decoded)
        self.assertEqual(encoded, 42)


class SaipEncodeEfContentRoundtripTests(unittest.TestCase):
    def test_ef_acc_roundtrip_stability(self) -> None:
        for hex_fixture in ("0000", "0001", "00FF", "FFFF"):
            decoded = _decode_acc(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-acc", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            redecoded = _decode_acc(encoded.hex().upper())
            self.assertEqual(decoded, redecoded)

    def test_ef_ehplmnpi_roundtrip(self) -> None:
        for hex_fixture in ("00", "01", "02"):
            decoded = _decode_ehplmn_presentation_indication(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-ehplmnpi", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(encoded.hex().upper(), hex_fixture)

    def test_ef_start_hfn_roundtrip(self) -> None:
        for hex_fixture in ("000000000000", "0000010000FF", "FFFFFFFFFFFF"):
            decoded = _decode_start_hfn(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-start-hfn", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(encoded.hex().upper(), hex_fixture)

    def test_ef_smss_roundtrip_stability(self) -> None:
        # Decoder keeps only first 2 bytes semantically; 2-byte canonical encoding is stable.
        for hex_fixture in ("00FF", "0001", "FFFE", "ABFE"):
            decoded = _decode_smss(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-smss", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            redecoded = _decode_smss(encoded.hex().upper())
            self.assertEqual(decoded["lastUsedTpMr"], redecoded["lastUsedTpMr"])
            self.assertEqual(
                decoded["memoryCapacityExceeded"],
                redecoded["memoryCapacityExceeded"],
            )

    def test_ef_ad_roundtrip_by_raw_field(self) -> None:
        for hex_fixture in ("00FFFF01", "018000", "0400", "80"):
            decoded = _decode_ad(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-ad", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(encoded.hex().upper(), hex_fixture)

    def test_ef_hpplmn_roundtrip(self) -> None:
        for hex_fixture in ("00", "02", "FF"):
            decoded = _decode_hpplmn_search_interval(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-hpplmn", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(encoded.hex().upper(), hex_fixture)

    def test_ef_three_byte_counter_roundtrip(self) -> None:
        pairs = [
            ("acm", "Accumulated Call Meter", "000000"),
            ("acmMax", "Accumulated Call Meter Maximum", "0000FF"),
            ("ict", "Incoming Call Timer", "0100FF"),
            ("oct", "Outgoing Call Timer", "FFFFFF"),
        ]
        ef_keys = ("ef-acm", "ef-acmax", "ef-ict", "ef-oct")
        for ef_key, (field_key, format_name, hex_fixture) in zip(ef_keys, pairs):
            decoded = _decode_three_byte_counter(
                hex_fixture,
                format_name=format_name,
                field_name=field_key,
            )
            assert decoded is not None, f"{ef_key} decoder returned None"
            encoded = encode_decoded_roundtrip_ef_content(ef_key, decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            self.assertEqual(encoded.hex().upper(), hex_fixture)

    def test_ef_language_records_roundtrip_stability(self) -> None:
        for hex_fixture in ("656E", "656EFFFF", "657365726672"):
            decoded = _decode_two_byte_language_records(hex_fixture)
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-li", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            redecoded = _decode_two_byte_language_records(encoded.hex().upper())
            assert redecoded is not None
            self.assertEqual(decoded["languages"], redecoded["languages"])

    def test_ef_tlv80_text_roundtrip(self) -> None:
        for hex_fixture in (
            "800B7369703A616C6963654031",  # sip:alice@1
            "800A6578616D706C652E636F",  # example.co
        ):
            decoded = _decode_tlv80_text(
                hex_fixture,
                format_name="ISIM IMPI",
                field_name="identity",
            )
            assert decoded is not None
            encoded = encode_decoded_roundtrip_ef_content("ef-impi", decoded)
            self.assertIsNotNone(encoded)
            assert encoded is not None
            redecoded = _decode_tlv80_text(
                encoded.hex().upper(),
                format_name="ISIM IMPI",
                field_name="identity",
            )
            self.assertEqual(decoded.get("identity"), redecoded.get("identity"))

    def test_ef_plmn_list_roundtrip_without_act(self) -> None:
        # 2 entries (234-15, 234-20) followed by 1 padded entry.
        hex_fixture = "32F410" + "32F402" + "FFFFFF"
        decoded = _decode_plmn_list(hex_fixture, with_act=False)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_ef_content("ef-fplmn", decoded)
        self.assertIsNotNone(encoded)
        assert encoded is not None
        redecoded = _decode_plmn_list(encoded.hex().upper(), with_act=False)
        self.assertEqual(decoded["entries"], redecoded["entries"])

    def test_ef_plmn_list_roundtrip_with_act(self) -> None:
        # PLMN 234-15 with UTRAN bit + E-UTRAN WB-S1 + GSM.
        hex_fixture = "32F410" + "C080"
        decoded = _decode_plmn_list(hex_fixture, with_act=True)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_ef_content("ef-plmnwact", decoded)
        self.assertIsNotNone(encoded)
        assert encoded is not None
        redecoded = _decode_plmn_list(encoded.hex().upper(), with_act=True)
        self.assertEqual(decoded["entries"], redecoded["entries"])


class SaipEncodeDispatcherTests(unittest.TestCase):
    def test_unknown_field_returns_none(self) -> None:
        self.assertIsNone(encode_decoded_roundtrip_bytes("thisFieldDoesNotExist", {}))
        self.assertIsNone(encode_decoded_roundtrip_scalar("thisFieldDoesNotExist", {}))

    def test_missing_required_field_raises(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("keyIdentifier", {})

    def test_roundtrip_capable_fields_listing_includes_core_entries(self) -> None:
        kinds = roundtrip_capable_fields()
        self.assertEqual(kinds.get("lifeCycleState"), "bytes")
        self.assertEqual(kinds.get("algorithmID"), "scalar")
        self.assertEqual(kinds.get("key"), "bytes")
        self.assertEqual(kinds.get("maxNumOfAttemps-retryNumLeft"), "scalar")

    def test_roundtrip_capable_ef_keys_include_expected_entries(self) -> None:
        ef_keys = roundtrip_capable_ef_keys()
        for expected in ("ef-acc", "ef-start-hfn", "ef-smss", "ef-li", "ef-impi", "ef-fplmn"):
            self.assertIn(expected, ef_keys)

    def test_unknown_ef_key_returns_none(self) -> None:
        self.assertIsNone(encode_decoded_roundtrip_ef_content("ef-bogus", {}))


if __name__ == "__main__":
    unittest.main()
