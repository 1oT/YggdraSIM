"""Eighteenth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-18 closes the following:

* ETSI TS 102 223 §6.4.16 ``SET UP EVENT LIST`` -- TR latch was
  missing entirely from ``_apply_terminal_response``. The new
  ``last_set_up_event_list_result`` field captures the result code.
* ETSI TS 102 223 §6.4.4 ``POLLING OFF`` -- TR result code latched
  into ``last_polling_off_result`` in addition to the existing
  ``polling_off_active`` flag.
* ETSI TS 102 223 §6.4.27 ``TIMER MANAGEMENT`` -- TR result code
  latched into ``last_timer_management_result`` alongside the
  existing timer-table updates.
* ETSI TS 102 223 §6.4.15 ``PROVIDE LOCAL INFORMATION`` -- TR
  result code + qualifier echo latched into
  ``last_provide_local_information_result`` /
  ``last_provide_local_information_qualifier``.
* 3GPP TS 31.102 §4.2.6 / §4.2.34 / §4.2.86 default seeding for
  EF.HPPLMN (6F31), EF.NETPAR (6FC4), EF.LRPLMNSI (6FDC).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    POLLING_OFF_COMMAND,
    PROVIDE_LOCAL_INFORMATION_COMMAND,
    SET_UP_EVENT_LIST_COMMAND,
    TIMER_MANAGEMENT_COMMAND,
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
    return (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((result_code & 0xFF,)))
        + bytes(extra or b"")
    )


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
        self._td = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._td.cleanup()


class SetUpEventListTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.16 SET UP EVENT LIST TR latch."""

    def test_success_records_result_zero(self) -> None:
        result = self.toolkit.queue_setup_event_list([0x07, 0x09])
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_EVENT_LIST_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_up_event_list_result, 0x00)

    def test_terminal_busy_records_0x20(self) -> None:
        result = self.toolkit.queue_setup_event_list([0x0D])
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_EVENT_LIST_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_up_event_list_result, 0x20)


class PollingOffTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.4 POLLING OFF TR latch."""

    def test_success_sets_active_and_records_result(self) -> None:
        result = self.toolkit.queue_polling_off()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=POLLING_OFF_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_polling_off_result, 0x00)
        self.assertTrue(self.state.toolkit.polling_off_active)

    def test_failure_records_result_but_keeps_polling(self) -> None:
        result = self.toolkit.queue_polling_off()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=POLLING_OFF_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_polling_off_result, 0x20)
        self.assertFalse(self.state.toolkit.polling_off_active)


class TimerManagementTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.27 TIMER MANAGEMENT TR latch."""

    def test_start_success_records_result_and_table(self) -> None:
        result = self.toolkit.queue_timer_management(
            timer_id=2,
            qualifier=0x00,
            timer_value_seconds=120,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=TIMER_MANAGEMENT_COMMAND,
            qualifier=0x00,
            extra=tlv("A4", bytes((0x02,))),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_timer_management_result, 0x00)
        self.assertEqual(self.state.toolkit.timer_table.get(2), 120)

    def test_terminal_busy_records_result_only(self) -> None:
        result = self.toolkit.queue_timer_management(
            timer_id=3,
            qualifier=0x00,
            timer_value_seconds=60,
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=TIMER_MANAGEMENT_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_timer_management_result, 0x20)


class ProvideLocalInformationTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.15 PROVIDE LOCAL INFORMATION TR latch."""

    def test_imei_request_records_result_and_qualifier(self) -> None:
        result = self.toolkit.queue_provide_local_information(qualifier=0x01)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        imei_blob = bytes.fromhex("083570990013154700")
        tr = _terminal_response(
            command_number=cmd,
            command_type=PROVIDE_LOCAL_INFORMATION_COMMAND,
            qualifier=0x01,
            extra=tlv("14", imei_blob),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_provide_local_information_result, 0x00)
        self.assertEqual(toolkit.last_provide_local_information_qualifier, 0x01)
        self.assertEqual(toolkit.imei, imei_blob)

    def test_terminal_busy_still_records_result(self) -> None:
        result = self.toolkit.queue_provide_local_information(qualifier=0x00)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=PROVIDE_LOCAL_INFORMATION_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_provide_local_information_result, 0x20)
        self.assertEqual(toolkit.last_provide_local_information_qualifier, 0x00)


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(self._root / "missing_quirks.py"),
            isdr_config_path=str(self._root / "missing_isdr.json"),
            sim_eim_identity_path=str(self._root / "missing_eim_identity.json"),
            euicc_store_root=str(self._root / "euicc"),
            profile_store_path=str(self._root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select_usim(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        body = bytes((len(aid_bytes),)) + aid_bytes
        apdu = bytes([0x00, 0xA4, 0x04, 0x04]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_ef(self, fid: str) -> None:
        body = bytes.fromhex(fid)
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _read_binary(self, length: int) -> bytes:
        apdu = bytes([0x00, 0xB0, 0x00, 0x00, length & 0xFF])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data


class HpplmnNetparLrplmnSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.6 / §4.2.34 / §4.2.86 default EFs."""

    def test_ef_hpplmn_seeded_with_30_minute_timer(self) -> None:
        self._select_usim()
        self._select_ef("6F31")
        self.assertEqual(self._read_binary(1), bytes((0x05,)))

    def test_ef_netpar_seeded_all_ff_16_bytes(self) -> None:
        self._select_usim()
        self._select_ef("6FC4")
        self.assertEqual(self._read_binary(16), b"\xFF" * 16)

    def test_ef_lrplmnsi_seeded_to_first_attempt(self) -> None:
        self._select_usim()
        self._select_ef("6FDC")
        self.assertEqual(self._read_binary(1), bytes((0x00,)))


if __name__ == "__main__":
    unittest.main()
