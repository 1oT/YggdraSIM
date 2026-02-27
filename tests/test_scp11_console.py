import unittest
import importlib.util
import sys
from pathlib import Path

CONSOLE_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "console.py"
spec = importlib.util.spec_from_file_location("scp11_console_module", CONSOLE_PATH)
console_module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
sys.modules[spec.name] = console_module
spec.loader.exec_module(console_module)
SCP11Console = console_module.SCP11Console


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + encode_length(len(value)) + value


class DummyCfg:
    RSP_SERVER_URL = "rsp.default.example"


class DummyClient:
    def __init__(self):
        self.cfg = DummyCfg()
        self.apdu_channel = None
        self.orchestrator = None


class SCP11ConsoleStatusDecodeTests(unittest.TestCase):
    def setUp(self):
        self.console = SCP11Console(DummyClient())
        self.console._aid_registry = {
            "ISDP1": "A0000005591010FFFFFFFF8900001000",
            "ISDP2": "A0000005591010FFFFFFFF8900001100",
        }

    def test_decode_euicc_configured_data_extracts_addresses(self):
        default_smdp = b"rsp.example.com"
        primary_smds = b"lpa.ds.gsma.com"
        additional_smds_1 = b"smds1.example.com"
        additional_smds_2 = b"smds2.example.com"
        allowed_ci_pkid = b"\xAA\xBB\xCC\xDD"

        nested_additional = tlv(bytes.fromhex("82"), additional_smds_1) + tlv(
            bytes.fromhex("82"),
            additional_smds_2,
        )
        inner = (
            tlv(bytes.fromhex("80"), default_smdp)
            + tlv(bytes.fromhex("81"), primary_smds)
            + tlv(bytes.fromhex("A2"), nested_additional)
            + tlv(bytes.fromhex("83"), allowed_ci_pkid)
        )
        payload = tlv(bytes.fromhex("BF3C"), inner)

        decoded = self.console._decode_euicc_configured_data(payload)

        self.assertEqual(decoded["default_smdp"], "rsp.example.com")
        self.assertEqual(decoded["root_smds_primary"], "lpa.ds.gsma.com")
        self.assertEqual(
            decoded["root_smds_additional"],
            ["smds1.example.com", "smds2.example.com"],
        )
        self.assertEqual(decoded["allowed_ci_pkid"], ["AABBCCDD"])

    def test_decode_accepts_inner_payload_without_bf3c_wrapper(self):
        inner = tlv(bytes.fromhex("80"), b"rsp.inner.example")
        decoded = self.console._decode_euicc_configured_data(inner)
        self.assertEqual(decoded["default_smdp"], "rsp.inner.example")

    def test_build_enable_profile_payload_matches_expected_shape(self):
        payload = self.console._build_profile_command_payload(
            func_tag=self.console.TAG_ENABLE_PROFILE,
            tag_type=self.console.TAG_ICCID,
            value_hex="981032547698103254F6",
        )
        self.assertEqual(payload.hex().upper(), "BF3111A00C5A0A981032547698103254F6810100")

    def test_build_remove_notification_payload(self):
        payload = self.console._build_remove_notification_payload(7)
        self.assertEqual(payload.hex().upper(), "BF3003800107")

    def test_encode_iccid_for_command(self):
        encoded = self.console._encode_iccid_for_command("8901234567890123456")
        self.assertEqual(encoded, "981032547698103254F6")

    def test_resolve_profile_target_by_alias(self):
        resolved = self.console._resolve_profile_target("isdp1")
        self.assertEqual(resolved, (self.console.TAG_AID, "A0000005591010FFFFFFFF8900001000"))


if __name__ == "__main__":
    unittest.main()
