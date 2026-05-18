import datetime
import io
import unittest
from contextlib import redirect_stdout

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP03.config import Config
from SCP03.logic.sgp22 import Sgp22Manager
from SCP03.logic.sgp32_decode import decode_rat_rules


PROFILE_LIST_HEX = (
    "BF2D49A047E3455A0A980103000040773677634F10A0000005591010FFFFFFFF8900001100"
    "9F700101910B4C6162202845552030312992114C61622028446F6D61696E2D4120303129950102"
)
PROFILE_LIST_SEQUENCE_HEX = PROFILE_LIST_HEX.replace("A047E345", "A0473045", 1)

DUMMY_TEST_EIM_OID = "2.25.311782205282738360923618091971140414400"
DEFAULT_TEST_EIM_FQDN = "yggdrasim.eim.test.1ot.com"


def _encode_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def _tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + _encode_length(len(value)) + value


def _build_test_certificate_der() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Retry Ladder Test"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class DummyTransport:
    def __init__(self):
        self.calls = []
        self.reset_calls = 0

    def reset(self):
        self.reset_calls += 1
        return True

    def transmit(self, apdu_hex: str, silent: bool = False):
        normalized = apdu_hex.upper()
        self.calls.append(normalized)
        if normalized == "00A4040010A0000005591010FFFFFFFF8900000100":
            return b"", 0x90, 0x00
        if normalized == "80E2910003BF2D00":
            return b"", 0x69, 0x85
        if normalized == "0070000001":
            return b"\x01", 0x90, 0x00
        if normalized == "01A4040010A0000005591010FFFFFFFF8900000100":
            return b"", 0x90, 0x00
        if normalized == "81E2910003BF2D00":
            return bytes.fromhex(PROFILE_LIST_HEX), 0x90, 0x00
        if normalized == "0070800100":
            return b"", 0x90, 0x00
        if normalized == "80E291001ABF3117A0124F10A0000005591010FFFFFFFF8900001100810100":
            return b"", 0x69, 0x85
        if normalized == "81E291001ABF3117A0124F10A0000005591010FFFFFFFF8900001100810100":
            return bytes.fromhex("BF3103800100"), 0x90, 0x00
        raise AssertionError(f"Unexpected APDU: {apdu_hex}")


class StkBasicRetryTransport:
    def __init__(self):
        self.calls = []
        self.reset_calls = 0
        self.base_attempts = 0

    def reset(self):
        self.reset_calls += 1
        return True

    def transmit(self, apdu_hex: str, silent: bool = False):
        del silent
        normalized = apdu_hex.upper()
        self.calls.append(normalized)
        if normalized == "00A4040010A0000005591010FFFFFFFF8900000100":
            return b"", 0x90, 0x00
        if normalized == "80E2910003BF2D00":
            self.base_attempts += 1
            if self.base_attempts == 1:
                return b"", 0x69, 0x85
            return bytes.fromhex(PROFILE_LIST_HEX), 0x90, 0x00
        if normalized == "0070000001":
            return b"", 0x68, 0x81
        if normalized == "80AA00000DA90B8100820101830107840101":
            return b"", 0x90, 0x00
        if normalized == "80100000010C":
            return b"", 0x90, 0x00
        if normalized == "81E2910003BF2D00":
            return b"", 0x68, 0x81
        raise AssertionError(f"Unexpected APDU: {apdu_hex}")


class ExportReportManager(Sgp22Manager):
    def __init__(self, payload_map):
        super().__init__(DummyTransport())
        self.payload_map = payload_map

    def get_euicc_report(self):
        return {
            "profiles": [],
            "eid": "89049032118427504800000000006079",
            "euicc_info1": {},
            "euicc_info2": {},
            "euicc_configured_data": {},
            "key_info": "",
            "sd_mgmt_data": "",
            "euicc_info1_raw": "",
            "euicc_info2_raw": "",
            "euicc_configured_data_raw": "",
            "key_info_raw": "",
            "sd_mgmt_data_raw": "",
        }

    def _es10_retrieve_data(self, payload: str) -> bytes:
        return self.payload_map.get(payload, b"")


class Sgp22RetryLadderTests(unittest.TestCase):
    def setUp(self):
        self.transport = DummyTransport()
        self.manager = Sgp22Manager(self.transport)

    def test_list_profiles_uses_logical_retry_ladder(self):
        self.manager.list_profiles()

        self.assertEqual(self.transport.reset_calls, 1)
        self.assertIn("LAB (DOMAIN-A 01)", self.manager.profile_cache)
        self.assertEqual(
            self.transport.calls,
            [
                "00A4040010A0000005591010FFFFFFFF8900000100",
                "80E2910003BF2D00",
                "0070000001",
                "01A4040010A0000005591010FFFFFFFF8900000100",
                "81E2910003BF2D00",
                "0070800100",
            ],
        )

    def test_enable_profile_uses_same_retry_ladder(self):
        self.manager.profile_cache["PROFILE-A"] = (
            self.manager.TAG_AID,
            "A0000005591010FFFFFFFF8900001100",
        )

        success = self.manager.enable_profile("PROFILE-A")

        self.assertTrue(success)
        self.assertEqual(self.transport.reset_calls, 1)
        self.assertEqual(
            self.transport.calls,
            [
                "00A4040010A0000005591010FFFFFFFF8900000100",
                "80E291001ABF3117A0124F10A0000005591010FFFFFFFF8900001100810100",
                "0070000001",
                "01A4040010A0000005591010FFFFFFFF8900000100",
                "81E291001ABF3117A0124F10A0000005591010FFFFFFFF8900001100810100",
                "0070800100",
            ],
        )

    def test_list_profiles_retries_on_basic_channel_after_stk_bootstrap(self):
        transport = StkBasicRetryTransport()
        manager = Sgp22Manager(transport)

        with redirect_stdout(io.StringIO()) as output:
            manager.list_profiles()

        self.assertEqual(transport.reset_calls, 2)
        self.assertIn("LAB (DOMAIN-A 01)", manager.profile_cache)
        self.assertIn("81E2910003BF2D00", transport.calls)
        self.assertEqual(transport.calls[-1], "80E2910003BF2D00")
        self.assertIn("Lab (Domain-A 01)", output.getvalue())

    def test_profile_list_parser_handles_nested_sequence_profile_entries(self):
        payload = bytes.fromhex(PROFILE_LIST_SEQUENCE_HEX)

        entries = self.manager._profile_list_to_dicts(payload)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "Lab (Domain-A 01)")
        with redirect_stdout(io.StringIO()) as output:
            self.manager._parse_profile_list(payload)
        rendered = output.getvalue()
        self.assertIn("Lab (Domain-A 01)", rendered)
        self.assertNotIn("No decodable profiles found", rendered)

    def test_euicc_info2_tag_mapping_matches_sgp32(self):
        self.assertEqual(self.manager._resolve_tag_name(0x87, 0xBF22), "GlobalPlatform Version")
        self.assertEqual(self.manager._resolve_tag_name(0x88, 0xBF22), "RSP Capability")
        self.assertEqual(self.manager._resolve_tag_name(0x99, 0xBF22), "Forbidden Profile Policy Rules")
        self.assertEqual(self.manager._resolve_tag_name(0x04, 0xBF22), "PP Version")
        self.assertEqual(self.manager._resolve_tag_name(0x90, 0xBF22), "IPA Mode")
        self.assertEqual(self.manager._resolve_tag_name(0xB4, 0xBF22), "IoT Specific Info")

    def test_euicc_info2_value_decoder_formats_pp_version_and_ipa_mode(self):
        self.assertEqual(
            self.manager._decode_value(0x04, bytes.fromhex("FFFFFF"), 0xBF22),
            "v255.255.255 (FFFFFF)",
        )
        self.assertEqual(
            self.manager._decode_value(0x90, bytes.fromhex("01"), 0xBF22),
            "ipae (IPAe is active) (1)",
        )
        self.assertIn(
            "ppr1",
            self.manager._decode_value(0x99, bytes.fromhex("0640"), 0xBF22),
        )

    def test_summarize_cert_block_decodes_wrapped_certificate_bytes(self):
        certificate_der = _build_test_certificate_der()
        wrapped_block = _tlv("A1", certificate_der)

        summary = self.manager._summarize_cert_block(wrapped_block)

        self.assertEqual(len(summary.get("certificates", [])), 1)
        first = summary["certificates"][0]
        self.assertIn("CN=Retry Ladder Test", first["subject"])
        self.assertTrue(
            any("ecdsa-with-SHA256" in item for item in summary.get("objectIdentifiers", []))
        )

    def test_extended_report_keeps_notifications_and_structured_cert_blocks(self):
        certificate_der = _build_test_certificate_der()
        certificate_tlv = _tlv("30", certificate_der)
        ci_pkid = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
        notifications = _tlv(
            "BF2B",
            _tlv(
                "A0",
                _tlv(
                    "BF2F",
                    b"".join(
                        [
                            _tlv("80", b"\x07"),
                            _tlv("81", bytes.fromhex("04C0")),
                            _tlv("0C", b"notify.example.com"),
                            _tlv("5A", bytes.fromhex("981032547698103254F6")),
                        ]
                    ),
                ),
            ),
        )
        eim_entry = b"".join(
            [
                _tlv("80", DUMMY_TEST_EIM_OID.encode("utf-8")),
                _tlv("81", DEFAULT_TEST_EIM_FQDN.encode("utf-8")),
                _tlv("82", b"\x01"),
                _tlv("84", b"\x0D"),
                _tlv("87", bytes.fromhex("0780")),
                _tlv("88", ci_pkid),
                _tlv("A5", certificate_tlv),
                _tlv("A6", certificate_tlv),
            ]
        )
        eim_response = _tlv("BF55", _tlv("A0", _tlv("30", eim_entry)))
        certs_response = _tlv("BF56", _tlv("A5", certificate_tlv) + _tlv("A6", certificate_tlv))
        rat_response = bytes.fromhex("BF4319A017301580020560A10B30098003EEEEEE8100820082020780")

        manager = ExportReportManager(
            {
                "BF4300": rat_response,
                "BF2B00": notifications,
                "BF5500": eim_response,
                "BF5600": certs_response,
            }
        )

        report = manager.get_euicc_report_extended("SGP.32")

        extra = report["sgp32_extra"]
        self.assertIn("retrieve_notifications_list", extra)
        self.assertEqual(
            extra["retrieve_notifications_list"]["notifications"][0]["seqNumber"],
            "7",
        )
        self.assertEqual(
            extra["retrieve_notifications_list"]["package_results"],
            [],
        )

        eim_export = extra["get_eim_configuration_data"]
        self.assertEqual(len(eim_export["entries"]), 1)
        first_eim_entry = eim_export["entries"][0]
        self.assertIn("eim_public_key_data", first_eim_entry)
        self.assertIn("trusted_tls_public_key_data", first_eim_entry)
        self.assertEqual(
            first_eim_entry["eim_public_key_data_raw_hex"],
            certificate_tlv.hex().upper(),
        )
        self.assertIn(
            "CN=Retry Ladder Test",
            first_eim_entry["trusted_tls_public_key_data"]["certificates"][0]["subject"],
        )

        cert_export = extra["get_certs"]
        self.assertEqual(
            cert_export["eum_certificate"]["raw_hex"],
            certificate_tlv.hex().upper(),
        )
        self.assertIn("summary", cert_export["euicc_certificate"])
        self.assertIn(
            "CN=Retry Ladder Test",
            cert_export["euicc_certificate"]["summary"]["certificates"][0]["subject"],
        )

    def test_print_cert_block_summary_lines_identifies_signed_key_container(self):
        summary = {
            "rawHex": "A1B2C3D4",
            "publicKeys": ["0x04AABBCC"],
            "signatures": ["0x30440220AABB"],
            "objectIdentifiers": [
                "1.2.840.10045.2.1 (id-ecPublicKey)",
                "1.2.840.10045.4.3.2 (ecdsa-with-SHA256)",
            ],
            "utf8Strings": [DEFAULT_TEST_EIM_FQDN],
            "integers": ["13"],
            "octetStrings": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
        }

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_cert_block_summary_lines("eIM Public Key Data", summary)

        rendered = buffer.getvalue()
        self.assertIn("Signed key container", rendered)
        self.assertIn("signatureAlgorithm", rendered)
        self.assertIn("Subject", rendered)
        self.assertIn("Certificate Version", rendered)
        self.assertIn("Extension Blob 1", rendered)
        self.assertIn("Raw Hex (1st)", rendered)
        self.assertNotIn("summary unavailable", rendered)

    def test_decode_rat_rules_accepts_nested_wrapper(self):
        wrapped_response = _tlv(
            "BF43",
            _tlv(
                "A0",
                _tlv(
                    "A1",
                    _tlv(
                        "30",
                        b"".join(
                            [
                                _tlv("80", bytes.fromhex("0560")),
                                _tlv("A1", _tlv("30", _tlv("80", bytes.fromhex("EEEEEE")))),
                                _tlv("82", bytes.fromhex("0780")),
                            ]
                        ),
                    ),
                ),
            ),
        )

        rules = decode_rat_rules(wrapped_response)

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["pprIdsRaw"], "0560")
        self.assertIn("consentRequired", rules[0]["pprFlags"])

    def test_print_cert_block_summary_lines_does_not_truncate_hex_fields(self):
        long_hex = "A1" * 80
        summary = {
            "rawHex": long_hex,
            "publicKeys": [f"0x{long_hex}"],
            "signatures": [f"0x{long_hex}"],
            "octetStrings": [long_hex],
        }

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_cert_block_summary_lines("EUM Certificate", summary)

        rendered = buffer.getvalue()
        self.assertGreaterEqual(rendered.count("A1"), len(long_hex) // 2)
        self.assertNotIn("...", rendered)

    def test_print_euicc_info2_detailed_includes_compact_section_header(self):
        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_euicc_info2_detailed(response)

        rendered = buffer.getvalue()
        self.assertIn("[+] EuiccInfo2", rendered)
        self.assertIn("Profile Version", rendered)
        self.assertIn("SGP.32 Validation", rendered)

    def test_print_euicc_info2_detailed_uses_color_and_aligned_value_column(self):
        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_euicc_info2_detailed(response)

        rendered = buffer.getvalue()
        self.assertIn(Config.Colors.CYAN, rendered)
        target_labels = [
            "Profile Version",
            "Ver Supported",
            "GP Version",
            "Forbidden PPR",
            "Additional PP Vers.",
            "SGP.32 Validation",
        ]
        colon_positions = []
        for line in rendered.splitlines():
            for label in target_labels:
                if label in line:
                    colon_positions.append(line.index(":"))
                    break

        self.assertEqual(len(colon_positions), len(target_labels))
        self.assertEqual(len(set(colon_positions)), 1)
        self.assertIn("CI PKId Verify", rendered)
        self.assertIn("CI PKId Sign", rendered)
        self.assertIn("SAS Accr. Number", rendered)
        self.assertNotIn("Additional eUICC Profile Package Versions", rendered)

        root_colon = None
        nested_colon = None
        for line in rendered.splitlines():
            if "Profile Version" in line:
                root_colon = line.index(":")
            if "Installed Apps" in line:
                nested_colon = line.index(":")
        self.assertIsNotNone(root_colon)
        self.assertIsNotNone(nested_colon)
        self.assertEqual(root_colon, nested_colon)

    def test_print_euicc_info2_wraps_long_values_with_hanging_indent(self):
        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        self.manager._get_console_width = lambda: 80

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_euicc_info2_detailed(response)

        rendered_lines = buffer.getvalue().splitlines()
        uicc_line_index = -1
        for idx, line in enumerate(rendered_lines):
            if "UICC Capability" in line:
                uicc_line_index = idx
                break

        self.assertNotEqual(uicc_line_index, -1)
        self.assertGreater(len(rendered_lines), uicc_line_index + 1)
        continuation_line = rendered_lines[uicc_line_index + 1]
        self.assertTrue(continuation_line.startswith("    | "))
        self.assertNotIn(":", continuation_line)

    def test_print_cert_block_summary_lines_wraps_long_values_with_hanging_indent(self):
        long_hex = "A1" * 120
        summary = {
            "rawHex": long_hex,
            "publicKeys": [f"0x{long_hex}"],
            "signatures": [f"0x{long_hex}"],
            "objectIdentifiers": ["1.2.840.10045.4.3.2 (ecdsa-with-SHA256)"],
        }

        self.manager._get_console_width = lambda: 80

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_cert_block_summary_lines("EUM Certificate", summary)

        rendered_lines = buffer.getvalue().splitlines()
        raw_hex_line_index = -1
        for idx, line in enumerate(rendered_lines):
            if "Raw Hex (1st)" in line:
                raw_hex_line_index = idx
                break

        self.assertNotEqual(raw_hex_line_index, -1)
        self.assertGreater(len(rendered_lines), raw_hex_line_index + 1)
        continuation_line = rendered_lines[raw_hex_line_index + 1]
        self.assertTrue(continuation_line.startswith("    | "))
        self.assertNotIn(":", continuation_line)

    def test_print_pipe_line_wraps_compact_section_values_with_hanging_indent(self):
        self.manager._get_console_width = lambda: 80

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_pipe_line(
                "Long Value",
                "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu",
                0,
            )

        rendered_lines = buffer.getvalue().splitlines()
        self.assertGreaterEqual(len(rendered_lines), 2)
        self.assertTrue(rendered_lines[0].startswith("    | Long Value"))
        self.assertTrue(rendered_lines[1].startswith("    | "))
        self.assertNotIn(":", rendered_lines[1])

    def test_print_pipe_line_keeps_nested_compact_colon_aligned(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.manager._print_pipe_line("EuiccConfiguredData", "Present", 0)
            self.manager._print_pipe_line("SM-DP+ Address", "smdpplus2.smdpp.example.test", 1)

        rendered_lines = buffer.getvalue().splitlines()
        self.assertEqual(len(rendered_lines), 2)
        root_colon = rendered_lines[0].index(":")
        nested_colon = rendered_lines[1].index(":")
        self.assertEqual(root_colon, nested_colon)


if __name__ == "__main__":
    unittest.main()
