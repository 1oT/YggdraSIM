# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Seventh-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-7 closes the following:

* ETSI TS 102 221 §11.1.5 STATUS (CLA bit 8 cleared) with P1 in
  ``{0x00, 0x01, 0x02}`` and P2 in ``{0x00, 0x01, 0x0C}``. P1=0x02
  triggers the §11.1.5.4 session-termination side-effects: PIN
  retry counters retain their values but the verified flags are
  dropped, the SCP03 session is torn down, the toolkit pending
  queue clears, and channels above 0 are released.
* ETSI TS 102 221 §11.1.12 GET RESPONSE (INS 0xC0). Backed by
  ``state.last_response_buffer``; chains on partial reads via
  ``61 LL`` and reports ``6C LL`` when Le exceeds the buffer.
* ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT proactive command
  (start / deactivate / get current value) with TR-side latching
  into ``state.toolkit.timer_table``, plus the matching ``D7``
  TIMER EXPIRATION envelope decode.
* ETSI TS 102 223 §6.4.2 MORE TIME, §6.4.7 POLLING OFF (TR
  acknowledgement → ``polling_off_active``), and §6.4.34
  DECLARE SERVICE (registrations stored in
  ``state.toolkit.declared_services``).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState, SimChvReference
from SIMCARD.toolkit import (
    DECLARE_SERVICE_COMMAND,
    MORE_TIME_COMMAND,
    POLLING_OFF_COMMAND,
    TIMER_MANAGEMENT_COMMAND,
    ToolkitLogic,
    _decode_timer_value_bcd,
    _encode_timer_value_bcd,
)
from SIMCARD.utils import read_tlv, tlv


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self._temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(self._temp_root / "missing_quirks.py"),
            isdr_config_path=str(self._temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(self._temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(self._temp_root / "euicc_store"),
            profile_store_path=str(self._temp_root / "profile_store"),
        )
        self._select_usim_adf()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

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


class IsoStatusVariantsTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.5 STATUS (CLA bit 8 cleared)."""

    def test_status_p2_00_returns_fcp_of_current_adf(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertGreater(len(data), 0)
        self.assertEqual(data[:1], b"\x62")

    def test_status_p2_01_returns_adf_aid(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2000100"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data.hex().upper(), USIM_AID)

    def test_status_p2_0c_returns_empty_9000(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2000C00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"")

    def test_status_p1_01_initialised_marker_returns_fcp(self) -> None:
        # §11.1.5.4: P1=0x01 informs the card that the application
        # is initialised in the terminal. Behaviour is identical to
        # P1=0x00 because the card has no follow-up data.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2010000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[:1], b"\x62")

    def test_status_p1_02_terminates_session_and_clears_state(self) -> None:
        # Plant a CHV-verified flag and a SCP03 session, then issue
        # STATUS P1=0x02. Both should drop afterwards.
        self.engine.state.chv_references[0x01] = SimChvReference(
            reference=0x01,
            value="1234",
            verified=True,
            retries_remaining=3,
        )
        self.engine.state.scp03_session.authenticated = True
        self.engine.state.pending_fetch_queue.append(b"\xD0\x03\x81\x01\x00")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2020000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertFalse(self.engine.state.chv_references[0x01].verified)
        self.assertFalse(self.engine.state.scp03_session.authenticated)
        self.assertEqual(len(self.engine.state.pending_fetch_queue), 0)
        self.assertEqual(self.engine.state.open_logical_channels, {0})

    def test_status_invalid_p1_returns_6a86(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2030000"))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_status_invalid_p2_returns_6a86(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2007F00"))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_status_p2_01_on_ef_returns_6a82(self) -> None:
        # Select an EF (no DF name available) and ask for the AID.
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00F2000100"))
        self.assertEqual((sw1, sw2), (0x6A, 0x82))


class GetResponseTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.12 GET RESPONSE (INS 0xC0)."""

    def test_empty_buffer_returns_6985(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000010"))
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_full_buffer_returns_all_with_9000(self) -> None:
        self.engine.state.last_response_buffer = b"\xDE\xAD\xBE\xEF"
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000004"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\xDE\xAD\xBE\xEF")
        self.assertEqual(self.engine.state.last_response_buffer, b"")

    def test_partial_read_returns_61ll_with_remainder(self) -> None:
        self.engine.state.last_response_buffer = b"\x01\x02\x03\x04\x05"
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000002"))
        self.assertEqual(sw1, 0x61)
        self.assertEqual(sw2, 0x03)
        self.assertEqual(data, b"\x01\x02")
        self.assertEqual(self.engine.state.last_response_buffer, b"\x03\x04\x05")

    def test_le_exceeding_buffer_returns_6cll(self) -> None:
        self.engine.state.last_response_buffer = b"\xAA\xBB"
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000010"))
        self.assertEqual(sw1, 0x6C)
        self.assertEqual(sw2, 0x02)
        # Buffer untouched so the IFD can retry with the right Le.
        self.assertEqual(self.engine.state.last_response_buffer, b"\xAA\xBB")

    def test_le_zero_means_256_and_overshoots_small_buffer(self) -> None:
        # ISO 7816-4 §5.1 case 2S: a single trailing 0x00 encodes
        # Le=256. The buffer holds 4 bytes so the strict-ETSI reply
        # is 6C 04 telling the IFD to retry with the correct Le.
        self.engine.state.last_response_buffer = b"\x10\x20\x30\x40"
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000000"))
        self.assertEqual(sw1, 0x6C)
        self.assertEqual(sw2, 0x04)
        # Buffer must remain populated for the retry.
        self.assertEqual(self.engine.state.last_response_buffer, b"\x10\x20\x30\x40")
        # Retry with the suggested Le drains the buffer.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000004"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\x10\x20\x30\x40")

    def test_chained_get_response_drains_buffer(self) -> None:
        self.engine.state.last_response_buffer = b"\x01\x02\x03\x04"
        first, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000002"))
        self.assertEqual(sw1, 0x61)
        self.assertEqual(sw2, 0x02)
        self.assertEqual(first, b"\x01\x02")
        second, sw1, sw2 = self.engine.transmit(bytes.fromhex("00C0000002"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(second, b"\x03\x04")
        self.assertEqual(self.engine.state.last_response_buffer, b"")


class TimerValueBcdTests(unittest.TestCase):
    """Round-trip the BCD HH/MM/SS encoding used by TIMER MANAGEMENT."""

    def test_zero_seconds_round_trips(self) -> None:
        encoded = _encode_timer_value_bcd(0)
        self.assertEqual(encoded, b"\x00\x00\x00")
        self.assertEqual(_decode_timer_value_bcd(encoded), 0)

    def test_one_minute_round_trips(self) -> None:
        encoded = _encode_timer_value_bcd(60)
        self.assertEqual(encoded, b"\x00\x10\x00")
        self.assertEqual(_decode_timer_value_bcd(encoded), 60)

    def test_one_hour_thirty_seconds_round_trips(self) -> None:
        encoded = _encode_timer_value_bcd(3630)
        self.assertEqual(_decode_timer_value_bcd(encoded), 3630)

    def test_clamps_above_99_hours(self) -> None:
        encoded = _encode_timer_value_bcd(100 * 3600 + 70 * 60 + 70)
        decoded = _decode_timer_value_bcd(encoded)
        # Clamped to 99h 99m 99s -- representation is informational
        # only; the exact decoded number matches the clamped fields.
        self.assertEqual(decoded, 99 * 3600 + 99 * 60 + 99)


class TimerManagementProactiveTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT queue + TR latch."""

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
        timer_id: int,
        timer_seconds: int | None = None,
        result_code: int = 0x00,
    ) -> bytes:
        command_details = tlv(
            "81",
            bytes((command_number & 0xFF, TIMER_MANAGEMENT_COMMAND, qualifier & 0xFF)),
        )
        device_identities = tlv("82", bytes((0x82, 0x81)))
        result = tlv("83", bytes((result_code & 0xFF,)))
        body = command_details + device_identities + result
        body += tlv("A4", bytes((timer_id & 0xFF,)))
        if timer_seconds is not None:
            body += tlv("A5", _encode_timer_value_bcd(timer_seconds))
        return body

    def test_queue_start_enqueues_proactive_with_timer_id_and_value(self) -> None:
        result = self.toolkit.queue_timer_management(
            timer_id=1,
            qualifier=0x00,
            timer_value_seconds=300,
        )
        self.assertEqual(result["mode"], "timer-management")
        self.assertEqual(result["qualifier"], "00")
        payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fields = self.toolkit._parse_proactive_command(payload)
        assert fields is not None
        self.assertEqual(fields["command_type"], TIMER_MANAGEMENT_COMMAND)
        self.assertEqual(fields["qualifier"], 0x00)
        self.assertEqual(fields["timer_id"], 1)
        self.assertEqual(fields["timer_value_seconds"], 300)

    def test_start_caches_setpoint_in_table_immediately(self) -> None:
        self.toolkit.queue_timer_management(
            timer_id=2,
            qualifier=0x00,
            timer_value_seconds=120,
        )
        self.assertEqual(self.state.toolkit.timer_table.get(2), 120)

    def test_terminal_response_for_start_keeps_setpoint(self) -> None:
        result = self.toolkit.queue_timer_management(
            timer_id=3,
            qualifier=0x00,
            timer_value_seconds=600,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x00,
            timer_id=3,
            timer_seconds=600,
        )
        _data, sw1, _sw2 = self.toolkit.handle_terminal_response(tr)
        self.assertIn(sw1, (0x90, 0x91))
        self.assertEqual(self.state.toolkit.timer_table.get(3), 600)

    def test_terminal_response_for_deactivate_removes_entry(self) -> None:
        self.state.toolkit.timer_table[4] = 90
        result = self.toolkit.queue_timer_management(
            timer_id=4,
            qualifier=0x01,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x01,
            timer_id=4,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertNotIn(4, self.state.toolkit.timer_table)

    def test_terminal_response_for_get_current_value_updates_table(self) -> None:
        self.state.toolkit.timer_table[5] = 600
        result = self.toolkit.queue_timer_management(
            timer_id=5,
            qualifier=0x02,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x02,
            timer_id=5,
            timer_seconds=421,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.timer_table.get(5), 421)

    def test_failed_terminal_response_keeps_existing_table(self) -> None:
        self.state.toolkit.timer_table[6] = 80
        result = self.toolkit.queue_timer_management(
            timer_id=6,
            qualifier=0x02,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = self._build_terminal_response(
            command_number=cmd,
            qualifier=0x02,
            timer_id=6,
            timer_seconds=10,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        # The simulator caches the original setpoint at queue-time
        # for qualifier 0x00; for qualifier 0x02 the original value
        # remains because the failed TR did not commit a new value.
        self.assertEqual(self.state.toolkit.timer_table.get(6), 80)


class TimerExpirationEnvelopeTests(unittest.TestCase):
    """3GPP TS 31.111 §7.5.6 TIMER EXPIRATION envelope (D7)."""

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
        self.state.toolkit.timer_table[2] = 300

        def _fallback(payload: bytes) -> tuple[bytes, int, int]:
            del payload
            return b"", 0x90, 0x00

        self._fallback = _fallback

    def _envelope(self, *body: bytes) -> bytes:
        joined = b"".join(body)
        return bytes((0xD7, len(joined))) + joined

    def test_expiration_clears_table_entry_and_latches_id(self) -> None:
        envelope = self._envelope(
            tlv("A4", bytes((0x02,))),
            tlv("A5", _encode_timer_value_bcd(0)),
        )
        _data, sw1, _sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(sw1 & 0xF0, 0x90)
        self.assertEqual(self.state.toolkit.last_expired_timer_id, 0x02)
        self.assertNotIn(0x02, self.state.toolkit.timer_table)

    def test_unknown_timer_id_does_not_crash(self) -> None:
        envelope = self._envelope(tlv("A4", bytes((0x07,))))
        _data, sw1, _sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(sw1 & 0xF0, 0x90)
        self.assertEqual(self.state.toolkit.last_expired_timer_id, 0x07)
        self.assertEqual(self.state.toolkit.timer_table.get(2), 300)

    def test_envelope_without_timer_id_is_silently_ignored(self) -> None:
        envelope = self._envelope()
        _data, sw1, _sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(sw1 & 0xF0, 0x90)
        self.assertEqual(self.state.toolkit.last_expired_timer_id, 0)


class MoreTimePollingOffDeclareServiceTests(unittest.TestCase):
    """Round-7 small proactive helpers."""

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

    def test_queue_more_time_returns_descriptor(self) -> None:
        result = self.toolkit.queue_more_time()
        self.assertEqual(result["mode"], "more-time")
        payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fields = self.toolkit._parse_proactive_command(payload)
        assert fields is not None
        self.assertEqual(fields["command_type"], MORE_TIME_COMMAND)

    def test_polling_off_tr_success_sets_polling_off_active(self) -> None:
        result = self.toolkit.queue_polling_off()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = (
            tlv("81", bytes((cmd & 0xFF, POLLING_OFF_COMMAND, 0x00)))
            + tlv("82", bytes((0x82, 0x81)))
            + tlv("83", bytes((0x00,)))
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertTrue(self.state.toolkit.polling_off_active)

    def test_polling_off_tr_failure_does_not_set_flag(self) -> None:
        result = self.toolkit.queue_polling_off()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = (
            tlv("81", bytes((cmd & 0xFF, POLLING_OFF_COMMAND, 0x00)))
            + tlv("82", bytes((0x82, 0x81)))
            + tlv("83", bytes((0x20,)))
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertFalse(self.state.toolkit.polling_off_active)

    def test_declare_service_records_registration_in_state(self) -> None:
        record = bytes.fromhex("0102030405")
        result = self.toolkit.queue_declare_service(service_record=record)
        self.assertEqual(result["mode"], "declare-service")
        self.assertEqual(self.state.toolkit.declared_services, [record])
        payload, _sw1, _sw2 = self.toolkit.handle_fetch()
        fields = self.toolkit._parse_proactive_command(payload)
        assert fields is not None
        self.assertEqual(fields["command_type"], DECLARE_SERVICE_COMMAND)
        self.assertEqual(fields["service_record"], record)


if __name__ == "__main__":
    unittest.main()
