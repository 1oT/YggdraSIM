# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""ASN.1/TLV decoder tests."""
from __future__ import annotations

from io import StringIO
import json
import tempfile
from pathlib import Path
import unittest

from Tools.Asn1TlvDecode.main import TagRegistry, decode_apdu, decode_bytes, normalise_hex, run_cli


def _encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + _encode_der_length(len(value)) + value


class Asn1TlvDecodeTests(unittest.TestCase):
    def test_generic_sequence_decodes_universal_values(self) -> None:
        decoded = decode_bytes(bytes.fromhex("3006020105040141"))

        self.assertTrue(decoded["complete"])
        root = decoded["items"][0]
        self.assertEqual(root["name"], "ASN1_SEQUENCE")
        self.assertEqual(root["items"][0]["decoded"], 5)
        self.assertEqual(root["items"][1]["decoded"]["hex"], "41")
        self.assertIn("ASN1_SEQUENCE [30]", decoded["asn1Notation"])

    def test_gsma_tag_names_load_from_registry(self) -> None:
        decoded = decode_bytes(bytes.fromhex("BF2203810102"))

        root = decoded["items"][0]
        self.assertEqual(root["name"], "EUICC_INFO_2")
        self.assertEqual(root["tag"], "BF22")
        self.assertEqual(root["items"][0]["tag"], "81")

    def test_sgp32_bf51_uses_eim_package_name(self) -> None:
        decoded = decode_bytes(bytes.fromhex("BF5103800101"))

        root = decoded["items"][0]
        self.assertEqual(root["tag"], "BF51")
        self.assertEqual(root["name"], "EIM_PACKAGE")
        self.assertIn("EIM_PACKAGE [BF51]", decoded["asn1Notation"])
        self.assertIn("EUICC_PACKAGE", root["aliases"])

    def test_tag_list_value_is_split_into_tags(self) -> None:
        decoded = decode_bytes(bytes.fromhex("5C034F5A90"))

        tags = decoded["items"][0]["decoded"]["tags"]
        self.assertEqual([tag["tag"] for tag in tags], ["4F", "5A", "90"])
        self.assertEqual(tags[0]["name"], "AID")

    def test_tag_list_recognizes_sgp32_eim_package_tag(self) -> None:
        decoded = decode_bytes(bytes.fromhex("5C02BF51"))

        tags = decoded["items"][0]["decoded"]["tags"]
        self.assertEqual(tags[0]["tag"], "BF51")
        self.assertEqual(tags[0]["name"], "EIM_PACKAGE")

    def test_builtin_registry_covers_sgp22_sgp32_allocated_tags_without_converted_docs(self) -> None:
        registry = TagRegistry.load(root=Path("/tmp/yggdrasim-no-such-spec-root"))
        expected_names = {
            "9F2A": "UPDATE_METADATA_RESPONSE",
            "9F26": "FALLBACK_ATTRIBUTE",
            "9F67": "FALLBACK_ALLOWED",
            "9F7B": "E_CALL_INDICATION",
            "BF20": "EUICC_INFO_1",
            "BF21": "PREPARE_DOWNLOAD_RESPONSE",
            "BF22": "EUICC_INFO_2",
            "BF23": "INITIALIZE_SECURE_CHANNEL",
            "BF24": "CONFIGURE_ISD_P",
            "BF25": "STORE_METADATA",
            "BF26": "REPLACE_SESSION_KEYS",
            "BF27": "PROFILE_INSTALLATION_RESULT_DATA",
            "BF28": "LIST_NOTIFICATION",
            "BF29": "SET_NICKNAME",
            "BF2A": "UPDATE_METADATA",
            "BF2B": "PENDING_NOTIFICATIONS_LIST",
            "BF2D": "PROFILE_INFO_LIST",
            "BF2E": "GET_EUICC_CHALLENGE",
            "BF2F": "NOTIFICATION_METADATA",
            "BF30": "NOTIFICATION_SENT",
            "BF31": "ENABLE_PROFILE",
            "BF32": "DISABLE_PROFILE",
            "BF33": "DELETE_PROFILE",
            "BF34": "EUICC_MEMORY_RESET",
            "BF35": "LOAD_CRL",
            "BF36": "BOUND_PROFILE_PACKAGE",
            "BF37": "PROFILE_INSTALLATION",
            "BF38": "AUTHENTICATE_SERVER",
            "BF39": "INITIATE_AUTHENTICATION",
            "BF3A": "GET_BOUND_PROFILE_PACKAGE",
            "BF3B": "AUTHENTICATE_CLIENT",
            "BF3C": "EUICC_CONFIGURED_ADDRESSES",
            "BF3D": "HANDLE_NOTIFICATION",
            "BF3E": "GET_EUICC_DATA",
            "BF3F": "SET_DEFAULT_DP_ADDRESS",
            "BF40": "AUTHENTICATE_CLIENT_ES11",
            "BF41": "CANCEL_SESSION",
            "BF42": "LPA_E_ACTIVATION",
            "BF43": "GET_RAT",
            "BF44": "LOAD_RPM_PACKAGE",
            "BF45": "VERIFY_SMDS_RESPONSE",
            "BF46": "CHECK_EVENT",
            "BF4A": "ALERT_DATA",
            "BF4B": "VERIFY_DEVICE_CHANGE",
            "BF4C": "CONFIRM_DEVICE_CHANGE",
            "BF4D": "PREPARE_DEVICE_CHANGE",
            "BF4E": "TRANSFER_EIM_PACKAGE",
            "BF4F": "GET_EIM_PACKAGE",
            "BF50": "PROVIDE_EIM_PACKAGE_RESULT",
            "BF51": "EIM_PACKAGE",
            "BF52": "PACKAGE_DATA",
            "BF53": "EIM_ACKNOWLEDGEMENTS",
            "BF54": "PROFILE_DOWNLOAD_TRIGGER",
            "BF55": "GET_EIM_CONFIGURATION_DATA",
            "BF56": "GET_CERTS",
            "BF57": "ADD_INITIAL_EIM",
            "BF58": "PROFILE_ROLLBACK_OR_ADD_EIM",
            "BF59": "CONFIGURE_IMMEDIATE_PROFILE_ENABLING",
            "BF5A": "IMMEDIATE_ENABLE",
            "BF5B": "ENABLE_EMERGENCY_PROFILE",
            "BF5C": "DISABLE_EMERGENCY_PROFILE",
            "BF5D": "EXECUTE_FALLBACK_MECHANISM",
            "BF5E": "RETURN_FROM_FALLBACK",
            "BF5F": "GET_CONNECTIVITY_PARAMETERS_OR_MEMORY_RESET",
            "BF60": "VERIFY_SMDP_RESPONSE",
            "BF61": "CHECK_PROGRESS",
            "BF62": "VERIFY_PROFILE_RECOVERY",
            "BF63": "DELETE_NOTIFICATION_FOR_DC",
            "BF64": "EUICC_MEMORY_RESET",
            "BF65": "SET_DEFAULT_DP_ADDRESS",
        }

        for tag, name in expected_names.items():
            with self.subTest(tag=tag):
                info = registry.lookup(tag, "context", 0)
                self.assertEqual(info.name, name)

    def test_builtin_registry_covers_sgp02_ecasd_probe_tags_without_converted_docs(self) -> None:
        registry = TagRegistry.load(root=Path("/tmp/yggdrasim-no-such-spec-root"))
        expected_names = {
            "2F00": "APPLICATIONS_IN_SECURITY_DOMAIN",
            "42": "IIN",
            "45": "CIN",
            "5A": "EID_OR_ICCID",
            "66": "SECURITY_DOMAIN_MANAGEMENT_DATA",
            "67": "CARD_CAPABILITY_INFORMATION",
            "7F21": "CERTIFICATE",
            "E0": "KEY_INFORMATION_TEMPLATE",
        }

        for tag, name in expected_names.items():
            with self.subTest(tag=tag):
                info = registry.lookup_exact(tag)
                self.assertIsNotNone(info)
                self.assertEqual(info.name, name)

    def test_sgp02_get_data_context_disambiguates_bf30_ecasd(self) -> None:
        decoded = decode_apdu(bytes.fromhex("81CABF30035C0166"))

        self.assertEqual(decoded["apdu"]["commandName"], "GET_DATA")
        self.assertEqual(decoded["apdu"]["referencedTag"]["name"], "ECASD_RECOGNITION_DATA")
        self.assertEqual(decoded["apdu"]["profileContext"], "SGP.02 eCASD recognition data probe")
        self.assertIn("references ECASD_RECOGNITION_DATA [BF30]", decoded["asn1Notation"])

    def test_sgp02_get_data_context_disambiguates_ecasd_certificate_store(self) -> None:
        decoded = decode_apdu(bytes.fromhex("81CABF30045C027F21"))

        self.assertEqual(decoded["apdu"]["referencedTag"]["name"], "ECASD_CERTIFICATE_STORE")
        self.assertEqual(decoded["apdu"]["profileContext"], "SGP.02 eCASD certificate-store probe")

    def test_sgp02_get_status_context_marks_profile_list_probe(self) -> None:
        decoded = decode_apdu(bytes.fromhex("81F2400000"))

        self.assertEqual(decoded["apdu"]["commandName"], "GET_STATUS")
        self.assertEqual(decoded["apdu"]["profileContext"], "SGP.02 / GlobalPlatform application registry list")

    def test_sgp02_get_data_resolves_non_ber_p1p2_data_object_identifier(self) -> None:
        decoded = decode_apdu(bytes.fromhex("81CA2F00025C0000"))

        self.assertEqual(decoded["apdu"]["commandName"], "GET_DATA")
        self.assertEqual(decoded["apdu"]["referencedTag"]["tag"], "2F00")
        self.assertEqual(decoded["apdu"]["referencedTag"]["name"], "APPLICATIONS_IN_SECURITY_DOMAIN")

    def test_sgp02_get_data_resolves_common_ecasd_data_objects(self) -> None:
        vectors = {
            "01CA005A00": "EID_OR_ICCID",
            "81CA00E000": "KEY_INFORMATION_TEMPLATE",
            "81CA006600": "SECURITY_DOMAIN_MANAGEMENT_DATA",
            "81CA006700": "CARD_CAPABILITY_INFORMATION",
        }

        for apdu_hex, name in vectors.items():
            with self.subTest(apdu=apdu_hex):
                decoded = decode_apdu(bytes.fromhex(apdu_hex))
                self.assertEqual(decoded["apdu"]["commandName"], "GET_DATA")
                self.assertEqual(decoded["apdu"]["referencedTag"]["name"], name)

    def test_iso_etsi_select_apdu_is_recognized(self) -> None:
        decoded = decode_bytes(bytes.fromhex("00A40400023F00"))

        self.assertEqual(decoded["format"], "APDU")
        self.assertEqual(decoded["apdu"]["commandName"], "SELECT")
        self.assertEqual(decoded["apdu"]["dataHex"], "3F00")
        self.assertIn("APDU SELECT [00 A4]", decoded["asn1Notation"])

    def test_globalplatform_get_data_apdu_resolves_referenced_tag(self) -> None:
        decoded = decode_apdu(bytes.fromhex("80CA9F7F00"))

        self.assertEqual(decoded["apdu"]["commandName"], "GET_DATA")
        self.assertEqual(decoded["apdu"]["referencedTag"]["tag"], "9F7F")
        self.assertEqual(decoded["apdu"]["referencedTag"]["name"], "CPLC")

    def test_sgp_store_data_apdu_decodes_embedded_profile_tlv(self) -> None:
        decoded = decode_bytes(bytes.fromhex("80E2910003BF5100"))

        self.assertEqual(decoded["format"], "APDU")
        self.assertEqual(decoded["apdu"]["commandName"], "STORE_DATA")
        self.assertEqual(decoded["apdu"]["storeData"]["profileContext"], "SGP.02/SGP.22/SGP.32 profile-management STORE DATA")
        self.assertEqual(decoded["apdu"]["dataTlv"][0]["name"], "EIM_PACKAGE")
        self.assertIn("EIM_PACKAGE [BF51]", decoded["asn1Notation"])

    def test_sgp32_bf51_default_render_names_eim_package_fields(self) -> None:
        eim_configuration = _tlv("A8", b"".join(
            [
                _tlv("80", b"1.3.6.1.4.1.99999.0.1"),
                _tlv("81", b"eim.example.test"),
                _tlv("82", b"\x01"),
                _tlv("83", b"\x02"),
                _tlv("87", b"\x07\x80"),
                _tlv("89", b""),
            ]
        ))
        signed = _tlv("30", b"".join(
            [
                _tlv("80", b"1.3.6.1.4.1.99999.0.5"),
                _tlv("5A", bytes.fromhex("89049032000000000000000000000001")),
                _tlv("81", b"\x01"),
                _tlv("82", bytes.fromhex("0000000000000001")),
                _tlv("A1", eim_configuration),
            ]
        ))
        decoded = decode_bytes(_tlv("BF51", signed + _tlv("5F37", b"\xAA" * 64)))

        notation = decoded["asn1Notation"]
        self.assertIn("euiccPackageSigned [30]", notation)
        self.assertIn("eimId [80] = \"1.3.6.1.4.1.99999.0.5\"", notation)
        self.assertIn("eidValue [5A] = '89049032000000000000000000000001'H", notation)
        self.assertIn("ecoList [A1]", notation)
        self.assertIn("addEim [A8] EimConfigurationData", notation)
        self.assertIn("eimFqdn [81] = \"eim.example.test\"", notation)
        self.assertIn("eimIdType [82] = eimIdTypeOid(1)", notation)
        self.assertIn("eimSupportedProtocol [87] = { eimRetrieveHttps }", notation)
        self.assertIn("eimSignature [5F37] = Signature(len=64", notation)
        self.assertNotIn("offset", notation)

    def test_cli_json_output_accepts_stdin(self) -> None:
        stdin = StringIO("BF2203810102")
        stdout = StringIO()
        original_stdin = __import__("sys").stdin
        try:
            __import__("sys").stdin = stdin
            code = run_cli(["--format", "json"], stdout=stdout, stderr=StringIO())
        finally:
            __import__("sys").stdin = original_stdin

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["items"][0]["name"], "EUICC_INFO_2")

    def test_cli_default_output_is_compact_asn1_notation(self) -> None:
        stdout = StringIO()

        code = run_cli(["3006020105040141"], stdout=stdout, stderr=StringIO())

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("ASN1_SEQUENCE [30] ::=", output)
        self.assertNotIn('"tagRegistry"', output)

    def test_cli_terminal_stdout_starts_with_blank_line(self) -> None:
        class TtyStdout(StringIO):
            def isatty(self) -> bool:
                return True

        stdout = TtyStdout()

        code = run_cli(["3006020105040141"], stdout=stdout, stderr=StringIO())

        self.assertEqual(code, 0)
        self.assertTrue(stdout.getvalue().startswith("\nASN1_SEQUENCE [30] ::="))

    def test_cli_without_input_on_tty_prints_usage(self) -> None:
        class TtyStdin(StringIO):
            def isatty(self) -> bool:
                return True

            def read(self, *args: object, **kwargs: object) -> str:
                raise AssertionError("interactive stdin should not be read")

        stderr = StringIO()
        original_stdin = __import__("sys").stdin
        try:
            __import__("sys").stdin = TtyStdin()
            code = run_cli([], stdout=StringIO(), stderr=stderr)
        finally:
            __import__("sys").stdin = original_stdin

        self.assertEqual(code, 2)
        self.assertIn("usage: asn1-tlv-decode", stderr.getvalue())
        self.assertIn("hex input is required", stderr.getvalue())

    def test_normalise_hex_accepts_common_separators(self) -> None:
        self.assertEqual(normalise_hex("0xBF:22 03_81-01.02"), bytes.fromhex("BF2203810102"))

    def test_asn1tools_schema_decode_when_type_is_supplied(self) -> None:
        schema = """
Example DEFINITIONS ::= BEGIN
ExampleSeq ::= SEQUENCE {
    count INTEGER,
    label UTF8String
}
END
"""
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "example.asn"
            schema_path.write_text(schema, encoding="utf-8")
            decoded = decode_bytes(
                bytes.fromhex("30080201050C036F6E65"),
                schema_paths=[schema_path],
                type_name="ExampleSeq",
            )

        self.assertTrue(decoded["schemaDecode"]["ok"])
        self.assertEqual(decoded["schemaDecode"]["value"]["count"], 5)
        self.assertEqual(decoded["schemaDecode"]["value"]["label"], "one")


if __name__ == "__main__":
    unittest.main()
