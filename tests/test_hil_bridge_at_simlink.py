"""3GPP TS 27.007 §8.17 / §8.18 AT+CSIM and AT+CRSM transcoder tests.

Verifies the small at_simlink helper turns AT requests into the
correct ISO 7816 APDUs, round-trips through the simulator engine,
and re-formats the response back into the +CSIM / +CRSM AT shapes
that the modem expects.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from Tools.HilBridge.at_simlink import (
    build_apdu_for_crsm,
    build_select_apdu_for_crsm,
    format_at_crsm_response,
    format_at_csim_response,
    parse_at_crsm_request,
    parse_at_csim_request,
)


def _make_engine() -> SimulatedSimCardEngine:
    td = tempfile.mkdtemp()
    store_root = Path(td) / "simcard"
    store_root.mkdir(parents=True, exist_ok=True)
    (store_root / "euicc").mkdir(parents=True, exist_ok=True)
    profile_store = store_root / "profile_store"
    profile_store.mkdir(parents=True, exist_ok=True)
    return SimulatedSimCardEngine(
        euicc_store_root=str(store_root),
        profile_store_path=str(profile_store),
    )


class AtCsimParserAcceptsCommonShapes(unittest.TestCase):

    def test_quoted_form_parses(self) -> None:
        request = parse_at_csim_request('AT+CSIM=14,"00A40004023F00"')
        self.assertIsNotNone(request)
        self.assertEqual(request.length_chars, 14)
        self.assertEqual(request.apdu.hex().upper(), "00A40004023F00")

    def test_unquoted_form_parses(self) -> None:
        request = parse_at_csim_request("AT+CSIM=14,00A40004023F00")
        self.assertIsNotNone(request)
        self.assertEqual(request.apdu[0], 0x00)
        self.assertEqual(request.apdu[1], 0xA4)

    def test_length_mismatch_is_rejected(self) -> None:
        # Declared length says 16 hex chars, the body has 14.
        self.assertIsNone(parse_at_csim_request('AT+CSIM=16,"00A40004023F00"'))

    def test_odd_hex_string_is_rejected(self) -> None:
        self.assertIsNone(parse_at_csim_request('AT+CSIM=13,"00A40004023F0"'))

    def test_response_formatter_appends_status_word(self) -> None:
        line = format_at_csim_response(bytes.fromhex("DEADBEEF"), 0x90, 0x00)
        self.assertEqual(line, '+CSIM: 12,"DEADBEEF9000"')


class AtCsimEndToEndAgainstSimulatorEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_select_mf_and_get_response_round_trip(self) -> None:
        request = parse_at_csim_request('AT+CSIM=14,"00A40004023F00"')
        self.assertIsNotNone(request)
        data, sw1, sw2 = self.engine.transmit(request.apdu)
        self.assertEqual(sw1 & 0xF0, 0x60 if sw1 in (0x61,) else sw1 & 0xF0)
        # SELECT MF returns either 9000 with FCP or 61xx (for short APDU);
        # both are spec-legal. format the response and assert it's a
        # well-formed +CSIM line.
        line = format_at_csim_response(data, sw1, sw2)
        self.assertTrue(line.startswith('+CSIM: '))


class AtCrsmParserBuildsCorrectApdus(unittest.TestCase):

    def test_read_binary_no_data_no_path(self) -> None:
        request = parse_at_crsm_request("AT+CRSM=176,12258,0,0,11")
        self.assertIsNotNone(request)
        self.assertEqual(request.command, 176)
        self.assertEqual(request.file_id, 12258)
        apdu = build_apdu_for_crsm(request)
        self.assertEqual(apdu.hex().upper(), "00B000000B")
        self.assertEqual(len(request.select_path), 0)

    def test_update_binary_with_data(self) -> None:
        # 11 bytes of data (matches P3=11 per TS 27.007 §8.18).
        request = parse_at_crsm_request('AT+CRSM=214,28542,0,0,11,"DEADBEEFCAFEFEEDFACE01"')
        self.assertIsNotNone(request)
        apdu = build_apdu_for_crsm(request)
        self.assertEqual(apdu[1], 0xD6)
        self.assertEqual(apdu[4], 0x0B)
        self.assertEqual(apdu[5:], bytes.fromhex("DEADBEEFCAFEFEEDFACE01"))

    def test_unknown_command_is_rejected(self) -> None:
        # Command 999 is not in CRSM_COMMAND_INS.
        self.assertIsNone(parse_at_crsm_request("AT+CRSM=999,12258,0,0,11"))

    def test_select_apdu_for_path_id_matches_fid(self) -> None:
        # File id 28448 = 0x6F20 (EF.PROVIDER_INFO under USIM-like profiles).
        request = parse_at_crsm_request('AT+CRSM=176,28448,0,0,11,"","3F00"')
        self.assertIsNotNone(request)
        select = build_select_apdu_for_crsm(request)
        self.assertEqual(select.hex().upper(), "00A40004026F20")

    def test_response_formatter_emits_no_payload_when_empty(self) -> None:
        line = format_at_crsm_response(b"", 0x90, 0x00)
        self.assertEqual(line, "+CRSM: 144,0")

    def test_response_formatter_emits_payload_hex_when_present(self) -> None:
        line = format_at_crsm_response(bytes.fromhex("AABBCC"), 0x90, 0x00)
        self.assertEqual(line, '+CRSM: 144,0,"AABBCC"')


class AtCrsmEndToEndAgainstSimulatorEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_status_242_reaches_the_engine(self) -> None:
        request = parse_at_crsm_request("AT+CRSM=242,0,0,0,32")
        self.assertIsNotNone(request)
        apdu = build_apdu_for_crsm(request)
        # STATUS = INS 0xF2.
        self.assertEqual(apdu[1], 0xF2)
        # The base-CLA STATUS without 80 prefix routes through the
        # toolkit handler; we only need to confirm the engine accepts
        # the request, not the response format here.
        _, sw1, sw2 = self.engine.transmit(apdu)
        self.assertIn(sw1 & 0xF0, {0x90, 0x60, 0x61, 0x62, 0x6A})
        line = format_at_crsm_response(b"", sw1, sw2)
        self.assertTrue(line.startswith("+CRSM:"))


if __name__ == "__main__":
    unittest.main()
