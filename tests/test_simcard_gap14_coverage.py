"""Fourteenth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

Round-14 closes the following:

* 3GPP TS 31.102 §4.2.10 / §4.2.11 ``EF.GID1`` (FID 6F3E) and
  ``EF.GID2`` (FID 6F3F) seeded under ADF.USIM. Both default to a
  4-byte ``FF FF FF FF`` placeholder so MVNO / service-provider
  group lookups don't 6A 82.
* 3GPP TS 31.102 §4.2.27 ``EF.SMSP`` (FID 6F42) seeded as a
  linear-fixed EF with a single 40-byte slot (12-byte alpha +
  parameter-indicators ``FF`` + 12-byte destination + 12-byte SC
  + PID + DCS + Validity).
* 3GPP TS 31.102 §4.2.9 ``EF.SMSS`` (FID 6F43) seeded transparent
  with the canonical ``00 FF`` (TP-MR=0, memory not full).
* ETSI TS 102 223 §6.4.21 / §6.6.21 ``LAUNCH BROWSER`` TR-side
  latch. The only TR payload is a result code; the simulator
  records it independently of the BROWSER TERMINATION envelope.
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
    LAUNCH_BROWSER_COMMAND,
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
    """Mixin: locate seeded EFs under ADF.USIM by FID."""

    def _find_usim_ef(self, engine, fid_hex: str):
        target = fid_hex.upper()
        for node in engine.state.nodes.values():
            if node.kind != "ef":
                continue
            if node.fid.upper() != target:
                continue
            node_id_text = str(node.node_id).upper()
            # ADF.USIM seeds use ``PROFILE::ADF.USIM::EF.*`` node IDs.
            if "USIM" in node_id_text and "ISIM" not in node_id_text:
                return node
        return None


class GroupIdentifierFilesTests(_EngineHarness, _UsimEfFinder):
    """3GPP TS 31.102 §4.2.10 EF.GID1 / §4.2.11 EF.GID2."""

    def test_gid1_seeded_with_default_placeholder(self) -> None:
        gid1 = self._find_usim_ef(self.engine, "6F3E")
        self.assertIsNotNone(gid1)
        self.assertEqual(gid1.structure, "transparent")
        self.assertEqual(gid1.data, b"\xFF\xFF\xFF\xFF")

    def test_gid2_seeded_with_default_placeholder(self) -> None:
        gid2 = self._find_usim_ef(self.engine, "6F3F")
        self.assertIsNotNone(gid2)
        self.assertEqual(gid2.structure, "transparent")
        self.assertEqual(gid2.data, b"\xFF\xFF\xFF\xFF")

    def test_group_identifiers_are_admin_locked(self) -> None:
        for fid_hex in ("6F3E", "6F3F"):
            ef = self._find_usim_ef(self.engine, fid_hex)
            self.assertIsNotNone(ef, f"missing {fid_hex}")
            self.assertEqual(getattr(ef, "write_acl", "always"), "adm")


class SmsProfileFilesTests(_EngineHarness, _UsimEfFinder):
    """3GPP TS 31.102 §4.2.27 EF.SMSP / §4.2.9 EF.SMSS."""

    def test_smsp_seeded_as_linear_fixed_with_blank_slot(self) -> None:
        smsp = self._find_usim_ef(self.engine, "6F42")
        self.assertIsNotNone(smsp)
        self.assertEqual(smsp.structure, "linear-fixed")
        self.assertGreaterEqual(len(smsp.records), 1)
        record = smsp.records[0]
        # 12 alpha + 1 PI + 12 dest + 12 SC + PID + DCS + Validity.
        self.assertEqual(len(record), 12 + 1 + 12 + 12 + 1 + 1 + 1)
        # All-FF means no profile parameters provisioned.
        self.assertEqual(record, b"\xFF" * len(record))

    def test_smss_seeded_with_zero_tpmr_and_no_memory_alarm(self) -> None:
        smss = self._find_usim_ef(self.engine, "6F43")
        self.assertIsNotNone(smss)
        self.assertEqual(smss.structure, "transparent")
        self.assertEqual(smss.data, b"\x00\xFF")


class LaunchBrowserTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.21 LAUNCH BROWSER TR latch."""

    def test_launch_browser_success_records_result(self) -> None:
        result = self.toolkit.queue_launch_browser(
            "https://example.test/path",
            alpha_identifier="Open",
        )
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=LAUNCH_BROWSER_COMMAND,
            qualifier=0x02,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_launch_browser_result, 0x00)

    def test_launch_browser_failure_records_result(self) -> None:
        result = self.toolkit.queue_launch_browser("https://example.test/")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=LAUNCH_BROWSER_COMMAND,
            qualifier=0x02,
            result_code=0x26,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_launch_browser_result, 0x26)

    def test_launch_browser_latch_is_independent_of_browser_termination(
        self,
    ) -> None:
        # Pre-seed a browser-termination cause to confirm the new
        # latch does not clobber the unrelated state field.
        self.state.toolkit.last_browser_termination_cause = 0x01
        result = self.toolkit.queue_launch_browser("https://example.test/")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=LAUNCH_BROWSER_COMMAND,
            qualifier=0x02,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_launch_browser_result, 0x00)
        self.assertEqual(self.state.toolkit.last_browser_termination_cause, 0x01)


if __name__ == "__main__":
    unittest.main()
