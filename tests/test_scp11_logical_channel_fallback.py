# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
LIVE_CONSOLE_PATH = ROOT / "SCP11" / "live" / "console.py"
TEST_CONSOLE_PATH = ROOT / "SCP11" / "test" / "console.py"
ISD_R_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
# SGP.22 v3.1 §5.7.20: GetEuiccDataRequest with the mandatory tagList '5C 01 5A'.
TAGGED_GET_EID = bytes.fromhex("80E2910006BF3E035C015A")
BARE_GET_EID = bytes.fromhex("80E2910003BF3E00")
# SGP.26 v3.0.2 §3.2.1 Table 5 test eUICC.
TEST_EID = "89049032123451234512345678901235"
# A BF3E answer that carries no '5A', returned under a success status word.
NO_EID_BODY = bytes.fromhex("BF3E0380017F")


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


class LinkFaultFallbackApduChannel:
    """The card stops answering entirely -- PC/SC raises instead of
    returning a status word. This is the failure a transport reset is
    for, and the one that starts a new card session, so the STK-mode
    rung must both power-cycle and re-send TERMINAL PROFILE.
    """

    def __init__(self, eid_response: bytes):
        self.eid_response = eid_response
        self.send_calls = []
        self.reset_calls = 0
        self.link_up = False

    def reset(self) -> bool:
        self.reset_calls += 1
        self.link_up = True
        return True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if self.link_up is False:
            raise IOError("PC/SC channel is disconnected.")
        if log_name == "GET: EID [OPEN LOGICAL CHANNEL]":
            return b"\x01"
        if log_name == "GET: EID [SELECT ISD-R CH1]":
            raise IOError("APDU Failed: 6999")
        if log_name == "GET: EID [STK MODE BASIC]":
            return self.eid_response
        return b""


class ScriptedEidChannel:
    """Answers each GetEID attempt on the base channel from a table."""

    def __init__(self, answers: dict[str, bytes]):
        self.answers = answers
        self.send_calls = []
        self.reset_calls = 0

    def reset(self) -> bool:
        self.reset_calls += 1
        return True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        return self.answers[log_name]


class LogicalChannelFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live_module = _load_module("live_console_fallback_module", LIVE_CONSOLE_PATH)
        cls.test_module = _load_module("test_console_fallback_module", TEST_CONSOLE_PATH)

    def _build_console(self, module, channel_class=FallbackApduChannel):
        eid_response = module._build_tlv(
            bytes.fromhex("BF3E"),
            module._build_tlv(bytes.fromhex("5A"), bytes.fromhex("89049032000000000000000000000101")),
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

        self.assertEqual(eid, "89049032000000000000000000000101")
        # 6985 is the card answering: the retry moves to a logical
        # channel without power-cycling the card out of its session.
        self.assertEqual(console.apdu_channel.reset_calls, 0)
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
        self.assertEqual(console.apdu_channel.send_calls[0][1], TAGGED_GET_EID)
        self.assertEqual(console.apdu_channel.send_calls[1][1], bytes.fromhex("0070000001"))
        self.assertEqual(
            console.apdu_channel.send_calls[2][1],
            bytes([0x01, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID,
        )
        self.assertEqual(console.apdu_channel.send_calls[3][1], bytes.fromhex("81") + TAGGED_GET_EID[1:])
        self.assertEqual(console.apdu_channel.send_calls[4][1], bytes.fromhex("0070800100"))

    def _assert_stk_mode_fallback(self, module):
        console = self._build_console(module, channel_class=StkModeFallbackApduChannel)

        eid = console._get_eid()

        self.assertEqual(eid, "89049032000000000000000000000101")
        self.assertEqual(console.apdu_channel.reset_calls, 0)
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
                "GET: EID [STK MODE BASIC]",
            ],
        )
        self.assertEqual(
            console.apdu_channel.send_calls[4][1],
            bytes.fromhex("80AA000005A903840101"),
        )
        self.assertEqual(console.apdu_channel.send_calls[5][1], bytes([0x00, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID)
        self.assertEqual(console.apdu_channel.send_calls[6][1], TAGGED_GET_EID)

    def _assert_link_fault_fallback(self, module):
        # The other half of the rule: when the link itself is down the
        # reset is the only thing that can recover, and the card session
        # it starts is where TERMINAL PROFILE belongs (TS 102 223 §5.4).
        console = self._build_console(module, channel_class=LinkFaultFallbackApduChannel)

        eid = console._get_eid()

        self.assertEqual(eid, "89049032000000000000000000000101")
        # One power cycle, not one per rung: the first reset brought the
        # link back, after which 6999 is the card answering again.
        self.assertEqual(console.apdu_channel.reset_calls, 1)
        call_names = [name for name, _ in console.apdu_channel.send_calls]
        # The reset started a new card session, and that signal carries
        # down the cascade, so the STK rung re-declares the profile.
        self.assertIn("GET: EID [STK MODE TERMINAL PROFILE]", call_names)
        self.assertEqual(call_names[-1], "GET: EID [STK MODE BASIC]")

    def _build_scripted_console(self, module, answers):
        client = SimpleNamespace(
            cfg=DummyCfg(),
            apdu_channel=ScriptedEidChannel(answers),
            orchestrator=SimpleNamespace(),
        )
        console = module.SCP11Console(client)
        console._style = module.ConsoleStyle("", "", "", "", "", "", "")
        return console

    @staticmethod
    def _eid_answer(module, eid_hex):
        return module._build_tlv(
            bytes.fromhex("BF3E"),
            module._build_tlv(bytes.fromhex("5A"), bytes.fromhex(eid_hex)),
        )

    def _assert_tagged_request_goes_first(self, module):
        console = self._build_scripted_console(
            module,
            {"GET: EID": self._eid_answer(module, TEST_EID)},
        )

        self.assertEqual(console._get_eid(), TEST_EID)
        self.assertEqual(console.apdu_channel.send_calls, [("GET: EID", TAGGED_GET_EID)])

    def _assert_bare_request_follows_an_answer_without_eid(self, module):
        console = self._build_scripted_console(
            module,
            {
                "GET: EID": NO_EID_BODY,
                "GET: EID [BARE]": self._eid_answer(module, TEST_EID),
            },
        )

        self.assertEqual(console._get_eid(), TEST_EID)
        self.assertEqual(
            console.apdu_channel.send_calls,
            [("GET: EID", TAGGED_GET_EID), ("GET: EID [BARE]", BARE_GET_EID)],
        )

    def _assert_answer_without_eid_is_never_the_eid(self, module):
        # eidValue is Octet16, so a 15-byte '5A' is no EID either.
        short_eid_answer = self._eid_answer(module, TEST_EID[:30])
        console = self._build_scripted_console(
            module,
            {"GET: EID": NO_EID_BODY, "GET: EID [BARE]": short_eid_answer},
        )
        output = io.StringIO()

        with redirect_stdout(output):
            eid = console._get_eid()

        self.assertEqual(eid, "")
        self.assertIn("GET: EID: no EID in response BF3E0380017F", output.getvalue())
        self.assertIn(f"GET: EID [BARE]: no EID in response {short_eid_answer.hex().upper()}", output.getvalue())

    def test_eid_extraction_survives_decode_boundaries(self):
        console = self._build_scripted_console(self.live_module, {})
        for response in (
            b"",
            bytes.fromhex("BF"),
            bytes.fromhex("BF3E"),
            bytes.fromhex("BF3E105A10"),
            bytes.fromhex("BF3E035A1089"),
        ):
            with self.subTest(response=response.hex().upper()):
                self.assertIsNone(console._eid_from_get_euicc_data_response(response))

    def test_live_console_sends_the_tagged_get_eid_first(self):
        self._assert_tagged_request_goes_first(self.live_module)

    def test_test_console_sends_the_tagged_get_eid_first(self):
        self._assert_tagged_request_goes_first(self.test_module)

    def test_live_console_falls_back_to_the_bare_get_eid(self):
        self._assert_bare_request_follows_an_answer_without_eid(self.live_module)

    def test_test_console_falls_back_to_the_bare_get_eid(self):
        self._assert_bare_request_follows_an_answer_without_eid(self.test_module)

    def test_live_console_never_reports_an_answer_without_eid_as_the_eid(self):
        self._assert_answer_without_eid_is_never_the_eid(self.live_module)

    def test_test_console_never_reports_an_answer_without_eid_as_the_eid(self):
        self._assert_answer_without_eid_is_never_the_eid(self.test_module)

    def test_live_console_resets_the_card_only_on_a_link_fault(self):
        self._assert_link_fault_fallback(self.live_module)

    def test_test_console_resets_the_card_only_on_a_link_fault(self):
        self._assert_link_fault_fallback(self.test_module)

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
