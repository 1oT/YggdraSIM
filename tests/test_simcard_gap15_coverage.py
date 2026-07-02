# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Fifteenth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-15 closes the following:

* 3GPP TS 31.102 §4.2.40 ``EF.MSISDN`` (FID 6F40) seeded under
  ADF.USIM as a linear-fixed EF with one 22-byte slot
  (8-byte alpha + 14-byte dial body), all-FF so the modem can
  UPDATE RECORD over it.
* 3GPP TS 31.102 §4.2.55 / §4.2.56 / §4.2.57 ``EF.MBI`` (FID
  6FC9), ``EF.MBDN`` (FID 6FC7), ``EF.MWIS`` (FID 6FCA) seeded
  under ADF.USIM with sane voicemail defaults.
* ETSI TS 102 223 §6.4.5 / §6.6.5 ``REFRESH`` TR-side latch.
* ETSI TS 102 223 §6.4.13 / §6.6.13 ``SET UP CALL`` TR-side
  latch (result code, dialled-number, Additional Information
  cause).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    REFRESH_COMMAND,
    SET_UP_CALL_COMMAND,
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


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "missing_quirks.py"),
            isdr_config_path=str(root / "missing_isdr.json"),
            sim_eim_identity_path=str(root / "missing_eim_identity.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._td.cleanup()


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


class _UsimEfFinder:
    def _find_usim_ef(self, engine, fid_hex: str):
        target = fid_hex.upper()
        for node in engine.state.nodes.values():
            if node.kind != "ef":
                continue
            if node.fid.upper() != target:
                continue
            node_id_text = str(node.node_id).upper()
            if "USIM" in node_id_text and "ISIM" not in node_id_text:
                return node
        return None


class MsisdnFileTests(_EngineHarness, _UsimEfFinder):
    """3GPP TS 31.102 §4.2.40 EF.MSISDN."""

    def test_msisdn_seeded_with_blank_record(self) -> None:
        ef = self._find_usim_ef(self.engine, "6F40")
        self.assertIsNotNone(ef)
        self.assertEqual(ef.structure, "linear-fixed")
        self.assertGreaterEqual(len(ef.records), 1)
        record = ef.records[0]
        # 8 alpha + 14 body = 22 bytes.
        self.assertEqual(len(record), 22)
        self.assertEqual(record, b"\xFF" * 22)


class VoicemailFilesTests(_EngineHarness, _UsimEfFinder):
    """TS 31.102 §4.2.55-57 EF.MBI / EF.MBDN / EF.MWIS."""

    def test_mbi_record_points_voicemail_at_first_mbdn_slot(self) -> None:
        mbi = self._find_usim_ef(self.engine, "6FC9")
        self.assertIsNotNone(mbi)
        self.assertEqual(mbi.structure, "linear-fixed")
        self.assertEqual(mbi.records[0], b"\x01\x00\x00\x00")

    def test_mbdn_record_layout_matches_msisdn(self) -> None:
        mbdn = self._find_usim_ef(self.engine, "6FC7")
        self.assertIsNotNone(mbdn)
        self.assertEqual(mbdn.structure, "linear-fixed")
        self.assertEqual(mbdn.records[0], b"\xFF" * 22)

    def test_mwis_default_has_no_messages_waiting(self) -> None:
        mwis = self._find_usim_ef(self.engine, "6FCA")
        self.assertIsNotNone(mwis)
        self.assertEqual(mwis.structure, "linear-fixed")
        self.assertEqual(mwis.records[0], b"\x00\x00\x00\x00\x00")


class RefreshTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.5 REFRESH TR latch."""

    def test_refresh_success_records_mode_and_increments_counter(self) -> None:
        before = int(self.state.toolkit.refresh_attempts or 0)
        result = self.toolkit.queue_refresh(0x04)
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=REFRESH_COMMAND,
            qualifier=qualifier,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_refresh_result, 0x00)
        self.assertEqual(self.state.toolkit.last_refresh_mode, qualifier)
        self.assertEqual(self.state.toolkit.refresh_attempts, before + 1)

    def test_refresh_failure_still_increments_counter(self) -> None:
        before = int(self.state.toolkit.refresh_attempts or 0)
        result = self.toolkit.queue_refresh(0x00)
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=REFRESH_COMMAND,
            qualifier=qualifier,
            result_code=0x32,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_refresh_result, 0x32)
        self.assertEqual(self.state.toolkit.last_refresh_mode, qualifier)
        self.assertEqual(self.state.toolkit.refresh_attempts, before + 1)


class SetUpCallTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.13 SET UP CALL TR latch."""

    def test_set_up_call_success_records_address(self) -> None:
        result = self.toolkit.queue_setup_call(
            "+15551234567",
            alpha_identifier="Call",
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_CALL_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_set_up_call_result, 0x00)
        self.assertIn("15551234567", toolkit.last_set_up_call_address)
        self.assertEqual(toolkit.last_set_up_call_additional, b"")

    def test_set_up_call_failure_records_additional_info(self) -> None:
        result = self.toolkit.queue_setup_call("+15551234567")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        # Result 0x21 = "Network currently unable to process command";
        # cause 0x91 0x05 = network busy.
        cause_blob = bytes((0x91, 0x05))
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_CALL_COMMAND,
            qualifier=0x00,
            extra=tlv("9A", cause_blob),
            result_code=0x21,
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_set_up_call_result, 0x21)
        self.assertEqual(toolkit.last_set_up_call_additional, cause_blob)


if __name__ == "__main__":
    unittest.main()
