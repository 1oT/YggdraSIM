# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Thirteenth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-13 closes the following:

* ETSI TS 102 221 §11.1.19 ``TERMINAL CAPABILITY`` (INS 0xAA)
  TLV-level decode. Each well-known sub-tag is latched into a
  dedicated ``state.toolkit`` field (Terminal Power Supply,
  Extended Logical Channels, Additional Interfaces, eUICC
  Capabilities, E-UTRAN secure-channel hint).
* 3GPP TS 31.103 §4.2.7 ISIM ``EF.IST`` (FID 6F07) seeded with
  the four core IMS service bits flagged.
* 3GPP TS 31.103 §4.2.8 ISIM ``EF.PCSCF`` (FID 6F09) seeded with
  a deterministic ``pcscf.<realm>`` FQDN.
* ETSI TS 102 223 §6.4.2 ``MORE TIME`` and §6.4.3 ``POLL
  INTERVAL`` TR-side latches; the negotiated duration is decoded
  from TLV ``04``/``84`` and normalized to seconds.
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
    MORE_TIME_COMMAND,
    POLL_INTERVAL_COMMAND,
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


class TerminalCapabilityDecodeTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.19 TERMINAL CAPABILITY TLV decode."""

    def _send_terminal_capability(self, body: bytes) -> tuple[int, int]:
        apdu = bytes([0x80, 0xAA, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        return sw1, sw2

    def test_terminal_power_and_logical_channels_decoded(self) -> None:
        body = (
            bytes([0x80, 0x01, 0x02])
            + bytes([0x81, 0x01, 0x07])
        )
        sw1, sw2 = self._send_terminal_capability(body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        toolkit = self.engine.state.toolkit
        self.assertEqual(toolkit.terminal_power_supply, 0x02)
        self.assertEqual(toolkit.terminal_extended_logical_channels, 0x07)

    def test_additional_interfaces_and_euicc_capabilities(self) -> None:
        ifaces = bytes.fromhex("AA01")
        euicc = bytes.fromhex("0102030405")
        body = (
            bytes([0x83, len(ifaces)]) + ifaces
            + bytes([0x87, len(euicc)]) + euicc
        )
        sw1, sw2 = self._send_terminal_capability(body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        toolkit = self.engine.state.toolkit
        self.assertEqual(toolkit.terminal_additional_interfaces, ifaces)
        self.assertEqual(toolkit.terminal_euicc_capabilities, euicc)

    def test_truncated_tlv_does_not_crash(self) -> None:
        body = bytes([0x80, 0x05, 0x00])
        sw1, sw2 = self._send_terminal_capability(body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.engine.state.toolkit.terminal_power_supply, 0)


class IsimServiceTableTests(_EngineHarness):
    """3GPP TS 31.103 §4.2.7 EF.IST seeded under ADF.ISIM."""

    def _find_isim_ef(self, fid_hex: str):
        target = fid_hex.upper()
        for node in self.engine.state.nodes.values():
            if node.kind != "ef":
                continue
            if node.fid.upper() != target:
                continue
            if "ISIM" in str(node.node_id).upper():
                return node
        return None

    def test_ef_ist_present_and_advertises_core_services(self) -> None:
        ist = self._find_isim_ef("6F07")
        self.assertIsNotNone(ist)
        self.assertEqual(ist.structure, "transparent")
        self.assertGreaterEqual(len(ist.data), 1)
        # All eight bits of byte 0 advertised by the simulator.
        self.assertEqual(ist.data[0] & 0x0F, 0x0F)


class IsimPcscfTests(_EngineHarness):
    """3GPP TS 31.103 §4.2.8 EF.PCSCF seeded under ADF.ISIM."""

    def _find_isim_ef(self, fid_hex: str):
        target = fid_hex.upper()
        for node in self.engine.state.nodes.values():
            if node.kind != "ef":
                continue
            if node.fid.upper() != target:
                continue
            if "ISIM" in str(node.node_id).upper():
                return node
        return None

    def test_pcscf_record_format(self) -> None:
        pcscf = self._find_isim_ef("6F09")
        self.assertIsNotNone(pcscf)
        self.assertEqual(pcscf.structure, "linear-fixed")
        self.assertGreaterEqual(len(pcscf.records), 1)
        record = pcscf.records[0]
        self.assertEqual(record[0], 0x80)
        body_length = record[1]
        self.assertGreater(body_length, 1)
        body = record[2:2 + body_length]
        self.assertEqual(body[0], 0x00)
        # The address must be a non-empty FQDN starting with
        # ``pcscf.``.
        self.assertTrue(body[1:].startswith(b"pcscf."))


class MoreTimeTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.2 MORE TIME TR latch."""

    def test_more_time_success_records_result(self) -> None:
        result = self.toolkit.queue_more_time()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=MORE_TIME_COMMAND,
            qualifier=0x00,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_more_time_result, 0x00)

    def test_more_time_failure_records_result(self) -> None:
        result = self.toolkit.queue_more_time()
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=MORE_TIME_COMMAND,
            qualifier=0x00,
            result_code=0x32,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_more_time_result, 0x32)


class PollIntervalTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.3 POLL INTERVAL TR latch."""

    def test_poll_interval_seconds_negotiation(self) -> None:
        result = self.toolkit.queue_poll_interval(45)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        # Terminal accepts 30s instead of 45s.
        tr = _terminal_response(
            command_number=cmd,
            command_type=POLL_INTERVAL_COMMAND,
            qualifier=0x00,
            extra=tlv("84", bytes((0x01, 0x1E))),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_poll_interval_result, 0x00)
        self.assertEqual(toolkit.last_poll_interval_negotiated_seconds, 30)
        self.assertEqual(toolkit.last_poll_interval_negotiated_raw, b"\x01\x1E")

    def test_poll_interval_minutes_unit_decoded(self) -> None:
        result = self.toolkit.queue_poll_interval(120)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=POLL_INTERVAL_COMMAND,
            qualifier=0x00,
            extra=tlv("84", bytes((0x00, 0x02))),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_poll_interval_negotiated_seconds, 120)

    def test_poll_interval_failure_clears_duration_cache(self) -> None:
        # First successful negotiation populates the cache.
        result = self.toolkit.queue_poll_interval(15)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        ok_tr = _terminal_response(
            command_number=cmd,
            command_type=POLL_INTERVAL_COMMAND,
            qualifier=0x00,
            extra=tlv("84", bytes((0x01, 0x0F))),
        )
        self.toolkit.handle_terminal_response(ok_tr)
        self.assertEqual(self.state.toolkit.last_poll_interval_negotiated_seconds, 15)

        # Then a failed negotiation must reset the cache.
        result = self.toolkit.queue_poll_interval(20)
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        bad_tr = _terminal_response(
            command_number=cmd,
            command_type=POLL_INTERVAL_COMMAND,
            qualifier=0x00,
            result_code=0x32,
        )
        self.toolkit.handle_terminal_response(bad_tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_poll_interval_result, 0x32)
        self.assertEqual(toolkit.last_poll_interval_negotiated_seconds, 0)
        self.assertEqual(toolkit.last_poll_interval_negotiated_raw, b"")


if __name__ == "__main__":
    unittest.main()
