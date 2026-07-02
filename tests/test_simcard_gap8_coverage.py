# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Eighth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-8 closes the following:

* ETSI TS 102 221 §11.1.4 UPDATE BINARY by SFI (P1 bit 8 set selects
  the EF under the current DF; P2 carries the byte offset 0..255).
* ETSI TS 102 221 §11.1.6 UPDATE RECORD by SFI (P2 bits 7..3 select
  the EF; bits 2..0 select the access mode).
* ETSI TS 102 223 §6.4.32 SERVICE SEARCH (proactive 0x45) and
  §6.4.33 GET SERVICE INFORMATION (proactive 0x46) with TR-side
  latching into ``state.toolkit.last_service_search_result`` /
  ``last_service_information``.
* ETSI TS 102 223 §6.4.11..14 multi-card terminal proactives:
  PERFORM CARD APDU (0x30), POWER OFF CARD (0x31), POWER ON CARD
  (0x32), GET READER STATUS (0x33). Successful TRs update
  ``state.toolkit.powered_card_readers``,
  ``last_card_apdu_response`` and ``last_reader_status``.
* ETSI TS 102 223 §7.4.10 / §7.4.12 Event Download additions: SS
  (0x0A), USSD (0x0B), Local Connection (0x0C). Latch the
  data / DCS / connection status into ``state.toolkit``.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    GET_READER_STATUS_COMMAND,
    GET_SERVICE_INFORMATION_COMMAND,
    PERFORM_CARD_APDU_COMMAND,
    POWER_OFF_CARD_COMMAND,
    POWER_ON_CARD_COMMAND,
    SERVICE_SEARCH_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _terminal_response(
    *,
    command_number: int,
    command_type: int,
    qualifier: int,
    extra: bytes = b"",
    result_code: int = 0x00,
) -> bytes:
    body = (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((result_code & 0xFF,)))
        + bytes(extra or b"")
    )
    return body


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

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _select_mf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40000023F00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_usim_adf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class UpdateBinaryBySfiTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.4 UPDATE BINARY with implicit SELECT-by-SFI."""

    def test_update_binary_via_sfi_writes_to_target_ef(self) -> None:
        self._select_mf()
        # EF.PL is at SFI=0x05 under MF; default content is b"en".
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00D6850002") + b"de"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Re-read via SFI to verify the new content.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0850002"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"de")

    def test_update_binary_unknown_sfi_returns_6a82(self) -> None:
        self._select_mf()
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00D69F0002") + b"xx"
        )
        # P1=0x9F => SFI=0x1F (last possible SFI). Not assigned.
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_update_binary_via_sfi_implicitly_selects_ef(self) -> None:
        self._select_mf()
        self.engine.transmit(bytes.fromhex("00D6850001") + b"x")
        # After UPDATE BINARY by SFI the simulator follows ETSI TS 102 221
        # §11.1.3.4 by making the resolved EF the current EF, so a
        # subsequent SFI-less read returns the same data.
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0000002"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"xn")


class UpdateRecordBySfiTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.6 UPDATE RECORD via SFI in P2."""

    def test_update_record_via_sfi_writes_target_record(self) -> None:
        self._select_mf()
        # EF.ARR (linear-fixed) has SFI=0x06. P2 layout: SFI<<3 | mode.
        # Mode 0x04 = absolute; record number lives in P1.
        record_payload = bytes.fromhex("0102030405060708090A0B0C0D0E")
        p2 = (0x06 << 3) | 0x04
        apdu = bytes([0x00, 0xDC, 0x01, p2 & 0xFF, len(record_payload)]) + record_payload
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Read-back via SFI confirms the new content.
        read_p2 = (0x06 << 3) | 0x04
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xB2, 0x01, read_p2 & 0xFF, 0x00])
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[: len(record_payload)], record_payload)

    def test_update_record_unknown_sfi_returns_6a82(self) -> None:
        self._select_mf()
        p2 = (0x1F << 3) | 0x04
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xDC, 0x01, p2 & 0xFF, 0x01, 0xAA])
        )
        self.assertEqual((sw1, sw2), (0x6A, 0x82))


class _ToolkitHarness(unittest.TestCase):
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


class ServiceSearchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.32 SERVICE SEARCH proactive command."""

    def test_queue_service_search_descriptor_and_payload(self) -> None:
        result = self.toolkit.queue_service_search(
            service_record=bytes.fromhex("0102"),
            device_filter=bytes.fromhex("AABB"),
        )
        self.assertEqual(result["mode"], "service-search")
        payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # The proactive command must carry the service record (61) and
        # the device filter (63) in the body.
        self.assertIn(b"\x61\x02\x01\x02", payload)
        self.assertIn(b"\x63\x02\xAA\xBB", payload)

    def test_terminal_response_latches_service_record(self) -> None:
        result = self.toolkit.queue_service_search(
            service_record=bytes.fromhex("AB"),
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        record = bytes.fromhex("AABBCCDD")
        tr = _terminal_response(
            command_number=cmd,
            command_type=SERVICE_SEARCH_COMMAND,
            qualifier=0x00,
            extra=tlv("61", record),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_service_search_result, record)

    def test_failed_service_search_clears_previous_record(self) -> None:
        self.state.toolkit.last_service_search_result = b"\xDE\xAD"
        result = self.toolkit.queue_service_search(
            service_record=bytes.fromhex("AA"),
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SERVICE_SEARCH_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_service_search_result, b"")


class GetServiceInformationTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.33 GET SERVICE INFORMATION."""

    def test_queue_get_service_information_descriptor(self) -> None:
        result = self.toolkit.queue_get_service_information(
            service_record=bytes.fromhex("12"),
        )
        self.assertEqual(result["mode"], "get-service-information")
        payload, _sw1, _sw2 = self.toolkit.handle_fetch()
        self.assertIn(b"\x61\x01\x12", payload)

    def test_terminal_response_latches_service_information(self) -> None:
        result = self.toolkit.queue_get_service_information(
            service_record=bytes.fromhex("12"),
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        info = bytes.fromhex("DEADBEEF")
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_SERVICE_INFORMATION_COMMAND,
            qualifier=0x00,
            extra=tlv("62", info),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_service_information, info)


class PerformCardApduTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.11 PERFORM CARD APDU."""

    def test_queue_payload_carries_card_apdu_under_a4(self) -> None:
        card_apdu = bytes.fromhex("00A40004023F00")
        result = self.toolkit.queue_perform_card_apdu(
            card_apdu=card_apdu,
            reader_id=0x21,
        )
        self.assertEqual(result["mode"], "perform-card-apdu")
        payload, _sw1, _sw2 = self.toolkit.handle_fetch()
        # 82 02 82 21 device-identities (UICC -> reader 0x21).
        self.assertIn(b"\x82\x02\x82\x21", payload)
        # A4 LL <card_apdu>.
        self.assertIn(bytes([0xA4, len(card_apdu)]) + card_apdu, payload)

    def test_terminal_response_latches_card_apdu_response(self) -> None:
        card_apdu = bytes.fromhex("00B0000004")
        result = self.toolkit.queue_perform_card_apdu(
            card_apdu=card_apdu,
            reader_id=0x21,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        r_apdu = bytes.fromhex("DEADBEEF9000")
        tr = _terminal_response(
            command_number=cmd,
            command_type=PERFORM_CARD_APDU_COMMAND,
            qualifier=0x00,
            extra=tlv("A4", r_apdu),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_card_apdu_response, r_apdu)
        self.assertEqual(self.state.toolkit.last_card_apdu_reader, 0x21)


class PowerCardLifecycleTests(_ToolkitHarness):
    """POWER ON / POWER OFF CARD update powered_card_readers."""

    def test_power_on_then_off_updates_reader_set(self) -> None:
        on_result = self.toolkit.queue_power_on_card(reader_id=0x21)
        on_cmd = int(on_result["commandNumber"])
        self.toolkit.handle_fetch()
        on_tr = _terminal_response(
            command_number=on_cmd,
            command_type=POWER_ON_CARD_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(on_tr)
        self.assertIn(0x21, self.state.toolkit.powered_card_readers)

        off_result = self.toolkit.queue_power_off_card(reader_id=0x21)
        off_cmd = int(off_result["commandNumber"])
        self.toolkit.handle_fetch()
        off_tr = _terminal_response(
            command_number=off_cmd,
            command_type=POWER_OFF_CARD_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(off_tr)
        self.assertNotIn(0x21, self.state.toolkit.powered_card_readers)

    def test_power_on_failure_does_not_register_reader(self) -> None:
        result = self.toolkit.queue_power_on_card(reader_id=0x22)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=POWER_ON_CARD_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertNotIn(0x22, self.state.toolkit.powered_card_readers)


class GetReaderStatusTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.14 GET READER STATUS."""

    def test_terminal_response_latches_reader_status_records(self) -> None:
        result = self.toolkit.queue_get_reader_status()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        # Two reader records concatenated under E0 templates.
        record_blob = tlv("E0", b"\x21\x80") + tlv("E0", b"\x22\x00")
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_READER_STATUS_COMMAND,
            qualifier=0x00,
            extra=record_blob,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_reader_status, record_blob)


class EventDownloadGap8Tests(_ToolkitHarness):
    """Round-8 Event Download additions: SS, USSD, Local Connection."""

    def _envelope(self, *body: bytes) -> bytes:
        joined = b"".join(body)
        return bytes((0xD6, len(joined))) + joined

    def _fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        del payload
        return b"", 0x90, 0x00

    def test_ss_event_latches_ss_string(self) -> None:
        ss_blob = bytes.fromhex("8101FF")
        envelope = self._envelope(
            tlv("99", b"\x0A"),
            tlv("89", ss_blob),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_event_code, 0x0A)
        self.assertEqual(self.state.toolkit.last_ss_event_data, ss_blob)

    def test_ussd_event_latches_dcs_and_text(self) -> None:
        text = b"hello"
        envelope = self._envelope(
            tlv("99", b"\x0B"),
            tlv("8A", b"\x0F" + text),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_event_code, 0x0B)
        self.assertEqual(self.state.toolkit.last_ussd_event_dcs, 0x0F)
        self.assertEqual(self.state.toolkit.last_ussd_event_data, text)

    def test_local_connection_event_sets_active_flag(self) -> None:
        envelope = self._envelope(
            tlv("99", b"\x0C"),
            tlv("40", b"\x80"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertTrue(self.state.toolkit.local_connection_active)
        self.assertEqual(self.state.toolkit.last_event_code, 0x0C)

    def test_local_connection_event_clears_active_flag_on_terminate(self) -> None:
        self.state.toolkit.local_connection_active = True
        envelope = self._envelope(
            tlv("99", b"\x0C"),
            tlv("40", b"\x00"),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertFalse(self.state.toolkit.local_connection_active)


if __name__ == "__main__":
    unittest.main()
