# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Sixth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

The previous five passes closed:

* SGP.32 v1.2 / SGP.22 v3.1 ES10b/c command backlog.
* PIN lifecycle (CHANGE / DISABLE / ENABLE PIN) and GET CHALLENGE.
* GP GET DATA fingerprinting tags and the FF21 Extended Card Resources
  template.
* TS 31.111 / TS 102 223 envelope dispatch by tag.
* SAIP profile-header connectivity parameters.
* File lifecycle ACTIVATE / DEACTIVATE FILE, SEARCH RECORD, SUSPEND
  UICC, LAUNCH BROWSER.

This pass closes a different class of gaps -- behaviours that a real
UICC always exposes but the simulator was missing:

* ETSI TS 102 221 §11.1.16 / §11.1.17 / §11.1.18 lifecycle terminator
  commands TERMINATE EF / TERMINATE DF / TERMINATE CARD USAGE
  (INS 0xE8 / 0xE6 / 0xFE). These set the file lifecycle to 0x0C
  (terminated, irreversible) or brick the card globally.
* ETSI TS 102 221 §11.1.8 INCREASE (INS 0x32) on cyclic EFs.
* ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION (proactive type
  0x26) with TR-side latching of location info / IMEI / date-time /
  language / IMEISV / battery state.
* ETSI TS 102 223 §7.4 Event Download for events 0x07 (Idle Screen
  Available), 0x09 (Browser Termination + cause), 0x0F (Network
  Rejection + cause).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    PROVIDE_LOCAL_INFORMATION_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import read_tlv, tlv


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self._temp_root = Path(self._temp_dir.name)
        self.engine = self._build_engine()
        self._select_usim_adf()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _build_engine(self) -> SimulatedSimCardEngine:
        return SimulatedSimCardEngine(
            quirks_path=str(self._temp_root / "missing_quirks.py"),
            isdr_config_path=str(self._temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(self._temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(self._temp_root / "euicc_store"),
            profile_store_path=str(self._temp_root / "profile_store"),
        )

    def _select_usim_adf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_ef(self, fid_hex: str) -> bytes:
        fid = bytes.fromhex(fid_hex)
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA4, 0x00, 0x04, len(fid)]) + fid
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data

    @staticmethod
    def _fcp_lifecycle_byte(fcp_response: bytes) -> int | None:
        outer_tag, outer_value, _raw, _next = read_tlv(fcp_response, 0)
        if outer_tag != b"\x62":
            return None
        offset = 0
        while offset < len(outer_value):
            tag, value, _raw_inner, offset = read_tlv(outer_value, offset)
            if tag == b"\x8A" and len(value) >= 1:
                return int(value[0])
        return None


class FileLifecycleTerminationTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.16 / §11.1.17 TERMINATE EF / DF."""

    def test_terminate_ef_flips_lifecycle_to_0c(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E8000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fcp = self._select_ef("6F05")
        self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x0C)

    def test_terminated_ef_returns_6283_on_read(self) -> None:
        self._select_ef("6F05")
        self.engine.transmit(bytes.fromhex("00E8000000"))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0000002"))
        self.assertEqual((sw1, sw2), (0x62, 0x83))

    def test_activate_rejects_terminated_ef_with_6985(self) -> None:
        self._select_ef("6F05")
        self.engine.transmit(bytes.fromhex("00E8000000"))
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0044000000"))
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_terminate_ef_is_idempotent(self) -> None:
        self._select_ef("6F05")
        self.engine.transmit(bytes.fromhex("00E8000000"))
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E8000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_terminate_ef_persists_across_engine_restart(self) -> None:
        self._select_ef("6F05")
        self.engine.transmit(bytes.fromhex("00E8000000"))
        self.engine = self._build_engine()
        self._select_usim_adf()
        fcp = self._select_ef("6F05")
        self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x0C)

    def test_terminate_df_flips_adf_lifecycle_byte(self) -> None:
        # USIM ADF was selected in setUp. TERMINATE DF (CLA=00 INS=E6).
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E6000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Re-select to read FCP.
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fcp = _data
        # SELECT may return only 9000/no-FCP for some ADFs; if FCP is
        # available, assert the lifecycle. Otherwise rely on the
        # in-memory state.
        if len(fcp) > 0 and fcp[:1] == b"\x62":
            self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x0C)
        node = self.engine.fs.current_node()
        self.assertEqual(int(node.lifecycle_state) & 0xFF, 0x0C)

    def test_terminate_df_on_mf_returns_6986(self) -> None:
        # SELECT MF (3F00).
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40000023F00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E6000000"))
        self.assertEqual((sw1, sw2), (0x69, 0x86))

    def test_terminate_df_rejects_ef_target_with_6981(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E6000000"))
        self.assertEqual((sw1, sw2), (0x69, 0x81))

    def test_terminate_ef_rejects_df_target_with_6981(self) -> None:
        # USIM ADF is currently selected from setUp.
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00E8000000"))
        self.assertEqual((sw1, sw2), (0x69, 0x81))


class TerminateCardUsageTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.18 TERMINATE CARD USAGE."""

    def test_terminate_card_usage_returns_9000(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00FE000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertTrue(self.engine.state.terminated_card_usage)

    def test_subsequent_select_after_terminate_returns_6f00(self) -> None:
        self.engine.transmit(bytes.fromhex("00FE000000"))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40000023F00"))
        self.assertEqual((sw1, sw2), (0x6F, 0x00))

    def test_status_still_responds_after_terminate(self) -> None:
        self.engine.transmit(bytes.fromhex("00FE000000"))
        # GP STATUS uses CLA=80 P1!=0; a plain TS 102 221 STATUS uses
        # CLA=00 P1=00 P2=00 (poll). The simulator routes both via INS
        # F2; we accept any successful SW because the goal is just
        # "card is reachable for presence detection".
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("80F2000000"))
        # Either a successful STATUS or a 9000 GP GET STATUS response
        # is acceptable; we just don't want 6F00.
        self.assertNotEqual((sw1, sw2), (0x6F, 0x00))

    def test_terminate_card_usage_blocks_read_binary(self) -> None:
        self.engine.transmit(bytes.fromhex("00FE000000"))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0000002"))
        self.assertEqual((sw1, sw2), (0x6F, 0x00))


class IncreaseTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.8 INCREASE (INS 0x32)."""

    def setUp(self) -> None:
        super().setUp()
        # EF.ECC is linear-fixed; convert it to cyclic at runtime so
        # the test owns a deterministic 4-byte counter without
        # touching the default profile.
        self._select_ef("6FB7")
        node = self.engine.fs.current_node()
        node.structure = "cyclic"
        node.records = [b"\x00\x00\x00\x10"]

    def test_increase_adds_value_and_returns_new_record_plus_increment(self) -> None:
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00320000020003")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Record length was 4. Response = 4 bytes new value + 4 bytes
        # increment value, both big-endian.
        self.assertEqual(len(data), 8)
        self.assertEqual(int.from_bytes(data[:4], "big"), 0x13)
        self.assertEqual(int.from_bytes(data[4:8], "big"), 0x03)

    def test_increase_appends_record_and_caps_history(self) -> None:
        self.engine.transmit(bytes.fromhex("00320000020001"))
        node = self.engine.fs.current_node()
        # The cyclic EF only carried one record in the test fixture.
        # After a single INCREASE the list still holds one record
        # (the new most-recent value).
        self.assertEqual(len(node.records), 1)
        self.assertEqual(int.from_bytes(node.records[-1], "big"), 0x11)

    def test_increase_overflow_returns_6300(self) -> None:
        node = self.engine.fs.current_node()
        node.records = [b"\xFF\xFF\xFF\xFE"]
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("003200000200FF")
        )
        self.assertEqual((sw1, sw2), (0x63, 0x00))

    def test_increase_on_deactivated_ef_returns_6283(self) -> None:
        # Deactivate the cyclic EF first.
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self._select_ef("6FB7")
        # Re-coerce structure since SELECT rebuilt the runtime node.
        node = self.engine.fs.current_node()
        node.structure = "cyclic"
        node.records = [b"\x00\x00\x00\x10"]
        node.lifecycle_state = 0x04
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00320000020001")
        )
        self.assertEqual((sw1, sw2), (0x62, 0x83))

    def test_increase_on_transparent_ef_returns_6981(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00320000020001")
        )
        self.assertEqual((sw1, sw2), (0x69, 0x81))

    def test_increase_with_empty_body_returns_6700(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0032000000"))
        self.assertEqual((sw1, sw2), (0x67, 0x00))


class ProvideLocalInformationTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION TR latching."""

    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901234",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)

    def _build_terminal_response(
        self,
        *,
        command_number: int,
        qualifier: int,
        result_code: int = 0x00,
        extra: bytes = b"",
    ) -> bytes:
        command_details = tlv(
            "81",
            bytes((command_number & 0xFF, PROVIDE_LOCAL_INFORMATION_COMMAND, qualifier & 0xFF)),
        )
        device_identities = tlv("82", bytes((0x82, 0x81)))
        result = tlv("83", bytes((result_code & 0xFF,)))
        return command_details + device_identities + result + extra

    def _activate_provide_local_info(self, qualifier: int) -> int:
        result = self.toolkit.queue_provide_local_information(qualifier)
        command_number = int(result["commandNumber"])
        _payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return command_number

    def test_location_info_response_latches_on_terminal_response(self) -> None:
        cmd = self._activate_provide_local_info(0x00)
        loc_info = bytes.fromhex("62F2200000FFFE0001")
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x00,
            extra=tlv("93", loc_info),
        )
        _data, sw1, _sw2 = self.toolkit.handle_terminal_response(tr)
        # Either 9000 (no follow-up command queued) or 91xx (follow-up
        # proactive command pending) is acceptable per TS 102 223 §7.2.
        self.assertIn(sw1, (0x90, 0x91))
        self.assertEqual(self.state.toolkit.location_information, loc_info)

    def test_imei_response_latches(self) -> None:
        cmd = self._activate_provide_local_info(0x01)
        imei_bcd = bytes.fromhex("0853791450003012")
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x01,
            extra=tlv("94", imei_bcd),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.imei, imei_bcd)

    def test_date_time_timezone_response_latches(self) -> None:
        cmd = self._activate_provide_local_info(0x03)
        # 7 bytes of BCD: YY MM DD hh mm ss timezone (TS 102 223 §8.39).
        date_time = bytes.fromhex("62402511223344")
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x03,
            extra=tlv("A6", date_time),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.date_time_timezone, date_time)

    def test_language_response_latches(self) -> None:
        cmd = self._activate_provide_local_info(0x04)
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x04,
            extra=tlv("AD", b"sv"),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.language, b"sv")

    def test_imeisv_response_latches(self) -> None:
        cmd = self._activate_provide_local_info(0x08)
        imeisv = bytes.fromhex("3553791450003012")
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x08,
            extra=tlv("E2", imeisv),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.imeisv, imeisv)

    def test_battery_state_response_latches(self) -> None:
        cmd = self._activate_provide_local_info(0x0D)
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x0D,
            extra=tlv("DC", bytes((0x03,))),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.battery_state, 0x03)

    def test_failed_terminal_response_does_not_overwrite_state(self) -> None:
        original = self.state.toolkit.location_information
        cmd = self._activate_provide_local_info(0x00)
        bogus_loc = b"\xAA" * 9
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x00,
            result_code=0x20,
            extra=tlv("93", bogus_loc),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.location_information, original)

    def test_queue_returns_provide_local_information_descriptor(self) -> None:
        result = self.toolkit.queue_provide_local_information(0x03)
        self.assertEqual(result["mode"], "provide-local-information")
        self.assertEqual(result["qualifier"], "03")


class EventDownloadGapTests(unittest.TestCase):
    """ETSI TS 102 223 §7.4 / 3GPP TS 31.111 §7.5 Event Download."""

    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901234",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)
        self.fallback_called: list[bytes] = []

        def _fallback(payload: bytes) -> tuple[bytes, int, int]:
            self.fallback_called.append(payload)
            return b"", 0x90, 0x00

        self._fallback = _fallback

    def _envelope(self, *event_tlv_bytes: bytes) -> bytes:
        body = b"".join(event_tlv_bytes)
        return bytes((0xD6, len(body))) + body

    def test_idle_screen_available_event_latches_state(self) -> None:
        envelope = self._envelope(tlv("99", bytes((0x07,))))
        _data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(sw1 & 0xF0, 0x90)
        self.assertTrue(self.state.toolkit.idle_screen_available)
        self.assertEqual(self.state.toolkit.last_event_code, 0x07)

    def test_browser_termination_event_latches_cause(self) -> None:
        envelope = self._envelope(
            tlv("99", bytes((0x09,))),
            tlv("B4", bytes((0x01,))),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_event_code, 0x09)
        self.assertEqual(self.state.toolkit.last_browser_termination_cause, 0x01)

    def test_network_rejection_event_latches_cause_blob(self) -> None:
        envelope = self._envelope(
            tlv("99", bytes((0x0F,))),
            tlv("CA", bytes.fromhex("020003")),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_event_code, 0x0F)
        self.assertEqual(
            self.state.toolkit.last_network_rejection_cause,
            bytes.fromhex("020003"),
        )

    def test_event_history_records_each_received_event(self) -> None:
        self.toolkit.handle_envelope(
            self._envelope(tlv("99", bytes((0x07,)))),
            self._fallback,
        )
        self.toolkit.handle_envelope(
            self._envelope(tlv("99", bytes((0x09,)))),
            self._fallback,
        )
        self.assertEqual(self.state.toolkit.event_history, [0x07, 0x09])


if __name__ == "__main__":
    unittest.main()
