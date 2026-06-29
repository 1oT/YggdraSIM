# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
LIVE_CONSOLE_PATH = ROOT / "SCP11" / "live" / "console.py"
TEST_CONSOLE_PATH = ROOT / "SCP11" / "test" / "console.py"
ISD_R_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class DummyCfg:
    RSP_SERVER_URL = "rsp.default.example"
    ES9_BASE_URL = "https://rsp.default.example"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""
    AID_ISD_R = ISD_R_AID


class FallbackApduChannel:
    def __init__(self, eid_response: bytes):
        self.eid_response = eid_response
        self.send_calls = []
        self.reset_calls = 0

    def reset(self) -> bool:
        self.reset_calls += 1
        return True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "GET: EID":
            raise IOError("APDU Failed: 6985")
        if log_name == "GET: EID [TAGGED]":
            raise AssertionError("Tagged EID fallback should not run when direct fallback succeeds.")
        if log_name == "GET: EID [OPEN LOGICAL CHANNEL]":
            return b"\x01"
        if log_name == "GET: EID [SELECT ISD-R CH1]":
            return b""
        if log_name == "GET: EID [CH1]":
            return self.eid_response
        if log_name == "GET: EID [CLOSE LOGICAL CHANNEL 1]":
            return b""
        return b""


class StkModeFallbackApduChannel:
    def __init__(self, eid_response: bytes):
        self.eid_response = eid_response
        self.send_calls = []
        self.reset_calls = 0

    def reset(self) -> bool:
        self.reset_calls += 1
        return True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "GET: EID":
            raise IOError("APDU Failed: 6985")
        if log_name == "GET: EID [TAGGED]":
            raise AssertionError("Tagged EID fallback should not run when STK mode direct fallback succeeds.")
        if log_name == "GET: EID [OPEN LOGICAL CHANNEL]":
            return b"\x01"
        if log_name == "GET: EID [SELECT ISD-R CH1]":
            raise IOError("APDU Failed: 6999")
        if log_name == "GET: EID [CLOSE LOGICAL CHANNEL 1]":
            return b""
        if log_name == "GET: EID [STK MODE TERMINAL CAPABILITY]":
            return b""
        if log_name == "GET: EID [STK MODE SELECT ISD-R]":
            return b""
        if log_name == "GET: EID [STK MODE TERMINAL PROFILE]":
            return b""
        if log_name == "GET: EID [STK MODE BASIC]":
            return self.eid_response
        return b""


class LogicalChannelFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live_module = _load_module("live_console_fallback_module", LIVE_CONSOLE_PATH)
        cls.test_module = _load_module("test_console_fallback_module", TEST_CONSOLE_PATH)

    def _build_console(self, module, channel_class=FallbackApduChannel):
        eid_response = module._build_tlv(
            bytes.fromhex("BF3E"),
            module._build_tlv(bytes.fromhex("5A"), bytes.fromhex("89044045930000000000001492294428")),
        )
        client = SimpleNamespace(
            cfg=DummyCfg(),
            apdu_channel=channel_class(eid_response),
            orchestrator=SimpleNamespace(),
        )
        console = module.SCP11Console(client)
        console._style = module.ConsoleStyle("", "", "", "", "", "", "")
        return console

    def _assert_eid_fallback(self, module):
        console = self._build_console(module)

        eid = console._get_eid()

        self.assertEqual(eid, "89044045930000000000001492294428")
        self.assertEqual(console.apdu_channel.reset_calls, 1)
        call_names = [name for name, _ in console.apdu_channel.send_calls]
        self.assertEqual(
            call_names,
            [
                "GET: EID",
                "GET: EID [OPEN LOGICAL CHANNEL]",
                "GET: EID [SELECT ISD-R CH1]",
                "GET: EID [CH1]",
                "GET: EID [CLOSE LOGICAL CHANNEL 1]",
            ],
        )
        self.assertEqual(console.apdu_channel.send_calls[1][1], bytes.fromhex("0070000001"))
        self.assertEqual(
            console.apdu_channel.send_calls[2][1],
            bytes([0x01, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID,
        )
        self.assertEqual(console.apdu_channel.send_calls[3][1][:2], bytes.fromhex("81E2"))
        self.assertEqual(console.apdu_channel.send_calls[4][1], bytes.fromhex("0070800100"))

    def _assert_stk_mode_fallback(self, module):
        console = self._build_console(module, channel_class=StkModeFallbackApduChannel)

        eid = console._get_eid()

        self.assertEqual(eid, "89044045930000000000001492294428")
        self.assertEqual(console.apdu_channel.reset_calls, 2)
        call_names = [name for name, _ in console.apdu_channel.send_calls]
        self.assertEqual(
            call_names,
            [
                "GET: EID",
                "GET: EID [OPEN LOGICAL CHANNEL]",
                "GET: EID [SELECT ISD-R CH1]",
                "GET: EID [CLOSE LOGICAL CHANNEL 1]",
                "GET: EID [STK MODE TERMINAL CAPABILITY]",
                "GET: EID [STK MODE SELECT ISD-R]",
                "GET: EID [STK MODE TERMINAL PROFILE]",
                "GET: EID [STK MODE BASIC]",
            ],
        )
        self.assertEqual(
            console.apdu_channel.send_calls[4][1],
            bytes.fromhex("80AA000005A903840101"),
        )
        self.assertEqual(console.apdu_channel.send_calls[5][1], bytes([0x00, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID)
        self.assertEqual(console.apdu_channel.send_calls[6][1], bytes.fromhex("80100000010C"))
        self.assertEqual(console.apdu_channel.send_calls[7][1][:2], bytes.fromhex("80E2"))

    def test_live_console_retries_eid_read_on_logical_channel(self):
        self._assert_eid_fallback(self.live_module)

    def test_test_console_retries_eid_read_on_logical_channel(self):
        self._assert_eid_fallback(self.test_module)

    def test_live_console_retries_eid_read_with_stk_mode(self):
        self._assert_stk_mode_fallback(self.live_module)

    def test_test_console_retries_eid_read_with_stk_mode(self):
        self._assert_stk_mode_fallback(self.test_module)


if __name__ == "__main__":
    unittest.main()
