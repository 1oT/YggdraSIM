# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EIDs read from a card are registered with the Local eIM without an EUICC ADD.

``register_detected_eid`` is the hook every card-reading surface calls; the
eSIM Management orchestrator's ECASD read is exercised here with a scripted
channel, the console, eIM-local and SCP03 reads in their own test files.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine.detected import register_detected_eid
from SCP11.eim_local.engine.service import LocalEim

EID = "89049032123451234512345678901235"


class _StoreTestBase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Path(directory.name)
        patcher = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(self.store)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.lines: list[str] = []

    def record(self, eid: str = EID):
        return LocalEim(self.store).record(eid)


class RegisterDetectedEidTests(_StoreTestBase):
    def test_a_new_eid_is_registered_and_announced_once(self) -> None:
        self.assertTrue(register_detected_eid(EID, "the eSIM Management console", emit=self.lines.append))
        self.assertEqual(self.record().label, "detected by the eSIM Management console")
        self.assertEqual(self.lines, [f"[*] Local eIM: EID {EID} registered (first seen by the eSIM Management console)."])
        self.assertFalse(register_detected_eid(EID, "the SCP03 admin shell", emit=self.lines.append))
        self.assertEqual(len(self.lines), 1)

    def test_nothing_to_register(self) -> None:
        self.assertFalse(register_detected_eid("", "the eSIM Management console", emit=self.lines.append))
        self.assertFalse(register_detected_eid("1234", "the eSIM Management console", emit=self.lines.append))
        self.assertIn("not registered", self.lines[-1])
        self.assertEqual(LocalEim(self.store).records(), [])

    def test_learning_off_is_respected(self) -> None:
        LocalEim(self.store).set_setting("learn_unknown_eids", "off")
        self.assertFalse(register_detected_eid(EID, "the eSIM Management console", emit=self.lines.append))
        self.assertIsNone(self.record())
        self.assertEqual(self.lines, [])

    def test_an_unavailable_store_never_stops_the_caller(self) -> None:
        blocker = self.store / "a-file"
        blocker.write_text("not a directory", encoding="utf-8")
        with mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(blocker / "store")}):
            self.assertFalse(register_detected_eid(EID, "the eSIM Management console", emit=self.lines.append))
        self.assertIn("the eIM store is unavailable", self.lines[-1])


class _EcasdChannel:
    """Answers the orchestrator's SELECT ECASD and GET DATA '5A', the retrieval of SGP.02 v4.2 §2.2.2."""

    def __init__(self, eid: str) -> None:
        self.eid = eid
        self.sent: list[str] = []

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.sent.append(log_name)
        if log_name == "EIM: GetEID (ECASD)":
            return bytes.fromhex("5A10" + self.eid)
        return b""


class OrchestratorEidReadTests(_StoreTestBase):
    def test_the_ecasd_eid_read_registers_the_eid(self) -> None:
        from SCP11.live.orchestrator import SGP22Orchestrator

        orchestrator = object.__new__(SGP22Orchestrator)
        orchestrator._es10b_logical_channel = 0
        orchestrator.apdu_channel = _EcasdChannel(EID)
        orchestrator._select_isd_r = lambda _label: b""
        with mock.patch("builtins.print"):
            eid = orchestrator._read_card_eid()
        self.assertEqual(eid, EID)
        self.assertEqual(self.record().label, "detected by the eSIM Management console")


if __name__ == "__main__":
    unittest.main()
