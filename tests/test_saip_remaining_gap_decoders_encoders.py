# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Remaining-gap closure tests -- structured decoders + round-trip encoders
for the ``_PASSTHROUGH_BYTES_FIELD_NAMES`` entries that were previously
hex-only on the editor surface:

* ``restrictParameter``                (SAIP §8.6.6 / GP Amd F §A.4)
* GP memory quotas (C7/C8/reserved/cumulative; GP Amd A §5.1.2)
* ``ts102226SIMFileAccessToolkitParameter`` (ETSI TS 102 226 V19.0.0
  §8.2.1.3.2.1: the access domain, then the toolkit resources)
* ``uiccAccessApplicationSpecificParametersField`` and the
  administrative variant (ETSI TS 102 226 V19.0.0 §8.2.1.3.2.2.2 and
  §8.2.1.3.2.2.4: entries of AID, access domain and DAP)

The tests assert both the decoder's semantic output and the matching
encoder's round-trip identity from the decoder's dictionary form back to
the original on-card bytes.
"""

import unittest

from SCP03.core import install_script
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


# Access domain '00', priority 01, two timers, menu text length 16, one menu
# entry at position 3 with identifier 4, two channels, MSL '01' + '12', TAR
# B00001 (ETSI TS 102 226 V19.0.0 §8.2.1.3.2.1, page 25).
CA_EXAMPLE = bytes.fromhex("01000102100103040202011203B00001")


class Ts102226FileAccessToolkitDecodingTests(unittest.TestCase):
    def test_decode_reads_the_access_domain_then_the_toolkit_resources(self):
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(CA_EXAMPLE)
        assert decoded is not None
        self.assertEqual(decoded["accessDomain"], "00")
        self.assertEqual(decoded["accessDomainSummary"], "Full access to the File System")
        self.assertEqual(decoded["priorityLevelOfToolkitAppInstance"], 1)
        self.assertEqual(decoded["maxNumberOfTimers"], 2)
        self.assertEqual(decoded["maxTextLengthForMenuEntry"], 0x10)
        self.assertEqual(decoded["menuEntries"], [{"position": 3, "id": 4}])
        self.assertEqual(decoded["maxNumberOfChannels"], 2)
        self.assertEqual(decoded["minimumSecurityLevelRaw"], "0112")
        self.assertEqual(decoded["tarValues"], ["B00001"])
        self.assertNotIn("additionalBytes", decoded)

    def test_decode_keeps_bytes_after_the_tar_values(self):
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(CA_EXAMPLE + b"\xff\xff")
        assert decoded is not None
        self.assertEqual(decoded["additionalBytes"], "FFFF")

    def test_decode_rejects_what_is_not_the_layout(self):
        # The two-section reading this field used to get does not parse.
        for raw in ("05AABB", "0100", "01AA02BBCC", ""):
            with self.subTest(raw=raw):
                self.assertIsNone(
                    _decode_ts102226_sim_file_access_toolkit_parameter(bytes.fromhex(raw))
                )

    def test_decoder_dispatches_via_special_field(self):
        decoded = _decode_special_field("ts102226SIMFileAccessToolkitParameter", CA_EXAMPLE)
        assert isinstance(decoded, dict)
        self.assertEqual(decoded["tarValues"], ["B00001"])


class Ts102226FileAccessToolkitEncodingTests(unittest.TestCase):
    def test_hex_passthrough_roundtrips(self):
        encoded = encode_ts102226_sim_file_access_toolkit_parameter_field(
            {"hex": CA_EXAMPLE.hex().upper()}
        )
        self.assertEqual(encoded, CA_EXAMPLE)

    def test_structured_encoding_matches_decoder_output(self):
        for source in (CA_EXAMPLE, CA_EXAMPLE + b"\xff"):
            with self.subTest(source=source.hex()):
                decoded = _decode_ts102226_sim_file_access_toolkit_parameter(source)
                assert decoded is not None
                decoded.pop("hex")
                encoded = encode_ts102226_sim_file_access_toolkit_parameter_field(decoded)
                self.assertEqual(encoded, source)

    def test_the_two_section_shape_is_refused(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_ts102226_sim_file_access_toolkit_parameter_field(
                {
                    "simToolkitApplicationParameters": {"hex": "AA"},
                    "simFileAccessParameters": {"hex": "BB"},
                }
            )

    def test_missing_access_domain_raises(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_ts102226_sim_file_access_toolkit_parameter_field({})

    def test_over_long_access_domain_rejected(self):
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(CA_EXAMPLE)
        assert decoded is not None
        decoded.pop("hex")
        decoded["accessDomain"] = "00" * 256
        with self.assertRaises(RoundtripEncoderError):
            encode_ts102226_sim_file_access_toolkit_parameter_field(decoded)


# The SCP03 install-script builder writes the same entries: the UICC file
# system (empty AID) and one ADF, both with full access and no DAP.
ADF_AID = bytes.fromhex("A0000000871002")
SCP03_ACCESS = install_script.build_access_parameters(install_script.TAG_UICC_ACCESS, [ADF_AID])[2:]


class UiccAccessApplicationParametersDecodingTests(unittest.TestCase):
    def test_decode_the_uicc_file_system_entry(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("00010000"),
            administrative=False,
        )
        assert decoded is not None
        self.assertEqual(
            [(entry["aid"], entry["target"], entry["accessDomain"], entry["dap"]) for entry in decoded["entries"]],
            [("", "UICC file system", "00", "")],
        )
        self.assertEqual(decoded["entries"][0]["accessDomainSummary"], "Full access to the File System")

    def test_decode_what_the_install_script_builder_writes(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            SCP03_ACCESS,
            administrative=False,
        )
        assert decoded is not None
        self.assertEqual(
            [entry["target"] for entry in decoded["entries"]],
            ["UICC file system", "ADF A0000000871002"],
        )

    def test_decode_uicc_access_mechanism_names_the_granted_conditions(self):
        # ETSI TS 102 226 V19.0.0 §8.2.1.3.2.5.2: '02' and three data bytes.
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("00040203010400"),
            administrative=False,
        )
        assert decoded is not None
        record = decoded["entries"][0]["accessDomainDecoded"]
        self.assertEqual(record["accessDomainData"], "030104")
        self.assertEqual(record["domainLabel"], "UICC access mechanism")
        self.assertEqual(
            record["grantedAccessConditions"],
            ["Application PIN 1", "Application PIN 2", "ADM1", "ALWAYS"],
        )

    def test_decode_keeps_the_dap(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("00010002AABB"),
            administrative=False,
        )
        assert decoded is not None
        self.assertEqual(decoded["entries"][0]["dap"], "AABB")
        self.assertIn("DAP AABB", decoded["summary"])

    def test_decode_administrative_label_differs(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            bytes.fromhex("0001FF00"),
            administrative=True,
        )
        assert decoded is not None
        self.assertIn("administrative", decoded["format"])

    def test_decode_rejects_what_is_not_whole_entries(self):
        # '0100' was read as one record before; it is an AID with no entry.
        for raw in ("050102", "0100", "000100", "00"):
            with self.subTest(raw=raw):
                self.assertIsNone(
                    _decode_uicc_access_application_specific_parameters(
                        bytes.fromhex(raw),
                        administrative=False,
                    )
                )

    def test_decoder_dispatches_via_special_field(self):
        decoded = _decode_special_field(
            "uiccAdministrativeAccessApplicationSpecificParametersField",
            bytes.fromhex("0001FF00"),
        )
        assert isinstance(decoded, dict)
        self.assertIn("administrative", decoded["format"])


class UiccAccessApplicationParametersEncodingTests(unittest.TestCase):
    def test_hex_passthrough_roundtrips(self):
        encoded = encode_uicc_access_application_specific_parameters_field(
            {"hex": SCP03_ACCESS.hex().upper()}
        )
        self.assertEqual(encoded, SCP03_ACCESS)

    def test_structured_roundtrip_matches_decoder(self):
        for source in (SCP03_ACCESS, bytes.fromhex("00040203010400"), bytes.fromhex("00010002AABB")):
            with self.subTest(source=source.hex()):
                decoded = _decode_uicc_access_application_specific_parameters(
                    source, administrative=False
                )
                assert decoded is not None
                decoded.pop("hex")
                encoded = encode_uicc_access_application_specific_parameters_field(decoded)
                self.assertEqual(encoded, source)

    def test_administrative_encoder_roundtrips(self):
        source = bytes.fromhex("0001FF00")
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

    def test_the_record_shape_is_refused(self):
        with self.assertRaises(RoundtripEncoderError):
            encode_uicc_access_application_specific_parameters_field(
                {"accessDomainRecords": [{"hex": "00"}]}
            )

    def test_entries_the_clause_does_not_allow_are_refused(self):
        for entries in (
            [{"aid": "A000", "accessDomain": "00"}],
            [{"aid": "", "accessDomain": "00"}, {"aid": "", "accessDomain": "FF"}],
            [{"aid": "", "accessDomain": ""}],
            [{"aid": "", "accessDomain": "00", "dap": "00" * 256}],
        ):
            with self.subTest(entries=entries), self.assertRaises(RoundtripEncoderError):
                encode_uicc_access_application_specific_parameters_field({"entries": entries})

    def test_dispatcher_round_trip_identity(self):
        decoded = _decode_uicc_access_application_specific_parameters(
            SCP03_ACCESS, administrative=False
        )
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "uiccAccessApplicationSpecificParametersField", decoded
        )
        self.assertEqual(encoded, SCP03_ACCESS)


if __name__ == "__main__":
    unittest.main()
