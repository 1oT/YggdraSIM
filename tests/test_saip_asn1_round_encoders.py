"""Unit tests for the SAIP pair-encoders (file structure, PKCS#15,
PIN/key material, install parameters).

All encoders are verified against ``decode -> encode -> decode`` identity
where the decoder is lossless. For lossy summaries (PKCS#15 object types,
install-parameter flag tables) we verify that the ``hex`` passthrough
restores the exact bytes and that structured rebuilds at least yield a
valid TLV stream whose decoded form matches the payload again.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_cbmi,
    _decode_cbmir,
    _decode_connectivity_parameters,
    _decode_file_descriptor,
    _decode_file_details,
    _decode_file_path,
    _decode_fill_pattern,
    _decode_group_identifier,
    _decode_key_data,
    _decode_link_path,
    _decode_pin_secret_value,
    _decode_pin_status_template_do,
    _decode_pkcs15_accf,
    _decode_pkcs15_acm,
    _decode_pkcs15_dodf,
    _decode_pkcs15_odf,
    _decode_sd_install_parameters,
    _decode_special_field,
    _decode_special_file_information,
    _decode_uicc_toolkit_parameters,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_connectivity_parameters,
    encode_decoded_roundtrip_bytes,
    encode_decoded_roundtrip_ef_content,
    encode_ef_cbmi,
    encode_ef_cbmir,
    encode_ef_group_identifier,
    encode_ef_pkcs15_accf,
    encode_ef_pkcs15_acm,
    encode_ef_pkcs15_dodf,
    encode_ef_pkcs15_odf,
    encode_file_descriptor,
    encode_file_details,
    encode_file_path,
    encode_fill_pattern,
    encode_key_data,
    encode_link_path,
    encode_pin_secret_value,
    encode_pin_status_template_do,
    encode_repeat_pattern,
    encode_sd_install_parameters,
    encode_special_file_information,
    encode_uicc_toolkit_parameters,
    roundtrip_capable_ef_keys,
    roundtrip_capable_fields,
)


# ---------------------------------------------------------------------------
# file-structure fields.


class FilePathEncoderTests(unittest.TestCase):
    def test_mf_empty_roundtrip(self) -> None:
        decoded = _decode_file_path(b"")
        encoded = encode_file_path(dict(decoded))
        self.assertEqual(encoded, b"")

    def test_two_segment_roundtrip(self) -> None:
        raw = bytes.fromhex("3F007FFF")
        decoded = _decode_file_path(raw)
        encoded = encode_file_path(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_edit_segment_fid(self) -> None:
        raw = bytes.fromhex("3F007FFF")
        decoded = _decode_file_path(raw)
        decoded["segments"][1]["fid"] = "7F10"
        encoded = encode_file_path(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex("3F007F10"))

    def test_reject_bad_fid(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_file_path({"segments": [{"fid": "ABC"}]})

    def test_dispatcher_registers_file_path(self) -> None:
        self.assertEqual(
            roundtrip_capable_fields().get("filePath"),
            "bytes",
        )


class LinkPathEncoderTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        raw = bytes.fromhex("7F106F07")
        decoded = _decode_link_path(raw)
        encoded = encode_link_path(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_independent_file_is_empty(self) -> None:
        decoded = _decode_link_path(b"")
        encoded = encode_link_path(dict(decoded))
        self.assertEqual(encoded, b"")


class FileDescriptorEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw = bytes.fromhex("4221000A01")
        decoded = _decode_file_descriptor(raw)
        encoded = encode_file_descriptor(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_structured_recompose_linear_fixed(self) -> None:
        payload = {
            "shareable": True,
            "fileType": "working_ef",
            "structure": "linear_fixed",
            "descriptorCodingByte": "0x21",
            "recordLength": 0x20,
            "numberOfRecords": 4,
        }
        encoded = encode_file_descriptor(payload)
        redecoded = _decode_file_descriptor(encoded)
        self.assertEqual(redecoded["structure"], "linear_fixed")
        self.assertEqual(redecoded["recordLength"], 0x20)
        self.assertEqual(redecoded["numberOfRecords"], 4)
        self.assertTrue(redecoded["shareable"])

    def test_ber_tlv_shortcut(self) -> None:
        payload = {
            "shareable": False,
            "fileType": "working_ef",
            "structure": "ber_tlv",
            "descriptorCodingByte": "0x21",
        }
        encoded = encode_file_descriptor(payload)
        self.assertEqual(encoded[0], 0x39)

    def test_reject_unknown_structure(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_file_descriptor({"fileType": "df", "structure": "???"})


class SpecialFileInformationEncoderTests(unittest.TestCase):
    def test_decimal_roundtrip(self) -> None:
        for byte_value in (0x00, 0x40, 0x80, 0xC0):
            decoded = _decode_special_file_information(bytes([byte_value]))
            encoded = encode_special_file_information(dict(decoded))
            self.assertEqual(encoded, bytes([byte_value]))

    def test_flag_recompose(self) -> None:
        encoded = encode_special_file_information(
            {"highUpdateActivity": True, "readAndUpdateWhenDeactivated": False}
        )
        self.assertEqual(encoded, bytes([0x80]))


class FillPatternEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("00DEADBEEF")
        decoded = _decode_fill_pattern(raw, repeat_pattern=False)
        encoded = encode_fill_pattern(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_ascii_recompose(self) -> None:
        encoded = encode_fill_pattern({"ascii": "test"})
        self.assertEqual(encoded, b"test")

    def test_byte_value_recompose(self) -> None:
        encoded = encode_fill_pattern({"byteValue": "0xAA"})
        self.assertEqual(encoded, b"\xAA")

    def test_repeat_pattern_roundtrip(self) -> None:
        raw = bytes.fromhex("FFFF")
        decoded = _decode_fill_pattern(raw, repeat_pattern=True)
        encoded = encode_repeat_pattern(dict(decoded))
        self.assertEqual(encoded, raw)


class FileDetailsEncoderTests(unittest.TestCase):
    def test_der_coding(self) -> None:
        decoded = _decode_file_details(bytes([0x01]))
        encoded = encode_file_details(dict(decoded))
        self.assertEqual(encoded, bytes([0x01]))

    def test_unknown_coding(self) -> None:
        decoded = _decode_file_details(bytes([0xAB]))
        encoded = encode_file_details(dict(decoded))
        self.assertEqual(encoded, bytes([0xAB]))

    def test_coding_label(self) -> None:
        encoded = encode_file_details({"coding": "DER coding"})
        self.assertEqual(encoded, bytes([0x01]))


# ---------------------------------------------------------------------------
# PKCS#15 EFs.


class Pkcs15EncoderTests(unittest.TestCase):
    def test_odf_hex_passthrough(self) -> None:
        # Minimal PKCS#15 ODF: A7 (data objects) wrapping an OCTET STRING path.
        raw = bytes.fromhex("A706" + "3004" + "04025207")
        encoded = encode_ef_pkcs15_odf({"hex": raw.hex().upper()})
        self.assertEqual(encoded, raw)

    def test_dodf_hex_passthrough(self) -> None:
        raw = bytes.fromhex("3004" + "04025207")
        encoded = encode_ef_pkcs15_dodf({"hex": raw.hex().upper()})
        self.assertEqual(encoded, raw)

    def test_acm_hex_passthrough(self) -> None:
        raw = bytes.fromhex("3004" + "04024200")
        encoded = encode_ef_pkcs15_acm({"hex": raw.hex().upper()})
        self.assertEqual(encoded, raw)

    def test_accf_hex_passthrough(self) -> None:
        raw = bytes.fromhex("3022" + "0420" + ("A1" * 32))
        encoded = encode_ef_pkcs15_accf({"hex": raw.hex().upper()})
        self.assertEqual(encoded, raw)

    def test_original_hex_hint_fallback(self) -> None:
        raw = bytes.fromhex("3004" + "04025207")
        encoded = encode_ef_pkcs15_odf(
            {"_ygg_original_hex": raw.hex().upper()}
        )
        self.assertEqual(encoded, raw)

    def test_reject_missing_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_pkcs15_odf({})

    def test_dispatcher_routes_pkcs15(self) -> None:
        keys = roundtrip_capable_ef_keys()
        for ef_key in (
            "ef-pkcs15-odf",
            "ef-pkcs15-dodf",
            "ef-pkcs15-acm",
            "ef-pkcs15-accf",
        ):
            self.assertIn(ef_key, keys)


# ---------------------------------------------------------------------------
# PIN/PUK/key-material fields.


class PinSecretEncoderTests(unittest.TestCase):
    def test_digits_with_padding(self) -> None:
        raw = b"1234" + (b"\xFF" * 4)
        decoded = _decode_pin_secret_value(raw)
        encoded = encode_pin_secret_value(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_hex_passthrough(self) -> None:
        raw_hex = "12345678FFFFFFFF"
        encoded = encode_pin_secret_value({"hex": raw_hex})
        self.assertEqual(encoded, bytes.fromhex(raw_hex))

    def test_reject_bad_digits(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_pin_secret_value({"digits": "12A4"})

    def test_dispatcher_bytes_pin_and_puk(self) -> None:
        self.assertEqual(
            encode_decoded_roundtrip_bytes("pinValue", {"digits": "1111", "paddingHex": "FFFFFFFF"}),
            b"1111" + (b"\xFF" * 4),
        )
        self.assertEqual(
            encode_decoded_roundtrip_bytes("pukValue", {"digits": "99999999", "paddingHex": ""}),
            b"99999999",
        )


class KeyDataEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw_hex = "00" * 16
        decoded = _decode_key_data(bytes.fromhex(raw_hex))
        encoded = encode_key_data(dict(decoded))
        self.assertEqual(encoded, bytes.fromhex(raw_hex))

    def test_reject_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_key_data({"hex": ""})


class PinStatusTemplateDoEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw = bytes.fromhex("8301" + "01" + "9001" + "C0" + "9501" + "08")
        decoded = _decode_pin_status_template_do(raw)
        encoded = encode_pin_status_template_do(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_rebuild_from_items(self) -> None:
        payload = {
            "items": [
                {"tag": "83", "raw": "01"},
                {"tag": "90", "raw": "C0"},
                {"tag": "95", "raw": "08"},
            ]
        }
        encoded = encode_pin_status_template_do(payload)
        redecoded = _decode_pin_status_template_do(encoded)
        self.assertIsInstance(redecoded, dict)
        self.assertEqual(len(redecoded["items"]), 3)

    def test_flat_status_bytes(self) -> None:
        encoded = encode_pin_status_template_do(
            {"statusBytes": "C0", "keyReference": {"decimal": 0x01}}
        )
        self.assertEqual(encoded, bytes.fromhex("C001"))


# ---------------------------------------------------------------------------
# install and connectivity parameters.


class ConnectivityParametersEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw = bytes.fromhex("8102" + "0001")
        decoded = _decode_connectivity_parameters(raw)
        encoded = encode_connectivity_parameters(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_rebuild_from_items(self) -> None:
        payload = {
            "items": [
                {"tag": "81", "raw": "0001"},
                {"tag": "82", "raw": "0002"},
            ]
        }
        encoded = encode_connectivity_parameters(payload)
        redecoded = _decode_connectivity_parameters(encoded)
        self.assertEqual(len(redecoded["items"]), 2)


class SdInstallParametersEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw = bytes.fromhex("8101" + "04" + "8201" + "01")
        decoded = _decode_sd_install_parameters(raw)
        encoded = encode_sd_install_parameters(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_rebuild_from_items(self) -> None:
        payload = {
            "items": [
                {"tag": "81", "raw": "04"},
                {"tag": "82", "raw": "01"},
            ]
        }
        encoded = encode_sd_install_parameters(payload)
        redecoded = _decode_sd_install_parameters(encoded)
        self.assertEqual(len(redecoded["items"]), 2)


class UiccToolkitParametersEncoderTests(unittest.TestCase):
    def _build_toolkit_bytes(self) -> bytes:
        # Access domain: 1 byte (length=1, value=0x00)
        access_domain = bytes([0x01, 0x00])
        header = bytes([0x02, 0x01, 0x10, 0x00])
        # 0 menu entries
        channels = bytes([0x02])
        msl = bytes([0x02, 0x00, 0x01])  # length=2, value=0x0001
        tar = bytes([0x03, 0xB0, 0x00, 0x00])  # length=3, one TAR
        return access_domain + header + channels + msl + tar

    def test_raw_hex_passthrough(self) -> None:
        raw = self._build_toolkit_bytes()
        decoded = _decode_uicc_toolkit_parameters(raw)
        encoded = encode_uicc_toolkit_parameters(dict(decoded))
        self.assertEqual(encoded, raw)

    def test_structured_rebuild(self) -> None:
        raw = self._build_toolkit_bytes()
        decoded = _decode_uicc_toolkit_parameters(raw)
        decoded["rawHex"] = ""
        encoded = encode_uicc_toolkit_parameters(dict(decoded))
        redecoded = _decode_uicc_toolkit_parameters(encoded)
        self.assertEqual(redecoded["accessDomain"], decoded["accessDomain"])
        self.assertEqual(redecoded["tarValues"], decoded["tarValues"])


# ---------------------------------------------------------------------------
# common 3GPP EFs previously without decoders.


class GroupIdentifierEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("41424344" + "FFFFFFFF")
        decoded = _decode_group_identifier(raw.hex().upper(), format_name="Group Identifier Level 1")
        encoded = encode_ef_group_identifier(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_ascii_recompose_with_padding(self) -> None:
        encoded = encode_ef_group_identifier(
            {"ascii": "ABCD"},
            target_length=8,
        )
        self.assertEqual(encoded, b"ABCD" + (b"\xFF" * 4))

    def test_reject_missing_fields(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_group_identifier({})


class CbmiEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("000100FF" + "FFFF0010")
        decoded = _decode_cbmi(raw.hex().upper())
        encoded = encode_ef_cbmi(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_entries_recompose(self) -> None:
        encoded = encode_ef_cbmi(
            {
                "entries": [
                    {"code": 0x0001},
                    {"unused": True},
                    {"code": 0x1234},
                ]
            }
        )
        self.assertEqual(encoded, bytes.fromhex("0001FFFF1234"))

    def test_reject_invalid_code(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_cbmi({"entries": [{"code": 0x10000}]})


class CbmirEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("00010002" + "FFFFFFFF")
        decoded = _decode_cbmir(raw.hex().upper())
        encoded = encode_ef_cbmir(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_entries_recompose(self) -> None:
        encoded = encode_ef_cbmir(
            {
                "entries": [
                    {"lower": 0x0001, "upper": 0x0002},
                    {"unused": True},
                ]
            }
        )
        self.assertEqual(encoded, bytes.fromhex("00010002FFFFFFFF"))

    def test_reject_bad_item_size(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_cbmir({"hex": "00010002FF"})


# ---------------------------------------------------------------------------
# Dispatcher integration.


class DispatcherIntegrationTests(unittest.TestCase):
    def test_bytes_dispatcher_routes_new_field_keys(self) -> None:
        fields = roundtrip_capable_fields()
        for key in (
            "filePath",
            "linkPath",
            "fileDescriptor",
            "specialFileInformation",
            "fillPattern",
            "repeatPattern",
            "fileDetails",
            "pinValue",
            "pukValue",
            "keyData",
            "pinStatusTemplateDO",
            "connectivityParameters",
            "applicationSpecificParametersC9",
            "uiccToolkitApplicationSpecificParametersField",
        ):
            self.assertEqual(fields.get(key), "bytes", f"missing {key}")

    def test_ef_dispatcher_routes_pkcs15(self) -> None:
        self.assertIsInstance(
            encode_decoded_roundtrip_ef_content(
                "ef-pkcs15-odf",
                {"hex": "3004" + "04025207"},
                target_length=8,
            ),
            bytes,
        )

    def test_ef_dispatcher_routes_round5(self) -> None:
        keys = roundtrip_capable_ef_keys()
        for ef_key in ("ef-gid1", "ef-gid2", "ef-cbmi", "ef-cbmid", "ef-cbmir"):
            self.assertIn(ef_key, keys)


if __name__ == "__main__":
    unittest.main()
