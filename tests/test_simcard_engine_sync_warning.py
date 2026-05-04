"""Regression test for the SIMCARD engine surfacing store-sync failures.

``SimulatedSimCardEngine._sync_all_stores`` swallows persistence
exceptions raised by ``sync_profiles_to_store`` / ``sync_euicc_store``
at the control-flow level (so a disk-full or permission-denied
condition cannot take down the dispatch loop) but emits a one-shot
stderr banner plus a ``logging.WARNING`` so operators see the problem
at least once per process.
"""

from __future__ import annotations

import io
import logging
import sys
import unittest
from unittest import mock

from SIMCARD import engine as engine_module
from SIMCARD.engine import SimulatedSimCardEngine, _SIMCARD_SYNC_WARNED


class SimcardEngineSyncWarningTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reset the module-level one-shot guard so each test case exercises
        # the first-failure path independently of sibling tests.
        _SIMCARD_SYNC_WARNED["euicc"] = False
        _SIMCARD_SYNC_WARNED["profiles"] = False

    def test_profile_store_failure_emits_one_shot_stderr_banner(self) -> None:
        captured_stderr = io.StringIO()
        with mock.patch.object(sys, "stderr", captured_stderr):
            engine = SimulatedSimCardEngine()
            # Construction itself already triggered one clean sync. Force a
            # failure on the next pass and verify the banner fires.
            with mock.patch.object(
                engine_module,
                "sync_profiles_to_store",
                side_effect=OSError("disk full"),
            ):
                engine._sync_all_stores()
                # A second failure should log but not re-emit the banner.
                engine._sync_all_stores()

        output = captured_stderr.getvalue()
        self.assertIn("[SIMCARD] WARNING", output)
        self.assertIn("disk full", output)
        # ``one-shot`` means exactly one banner line, not two.
        banner_count = output.count("[SIMCARD] WARNING")
        self.assertEqual(banner_count, 1)

    def test_logging_warning_still_fires_after_banner_drained(self) -> None:
        # Banner already fired from a previous call; logger should still
        # capture every subsequent failure so CI/daemon wrappers do not lose
        # the second-and-later incidents.
        _SIMCARD_SYNC_WARNED["profiles"] = True
        engine = SimulatedSimCardEngine()
        with self.assertLogs(engine_module._LOGGER, level=logging.WARNING) as cm:
            with mock.patch.object(
                engine_module,
                "sync_profiles_to_store",
                side_effect=OSError("still full"),
            ):
                engine._sync_all_stores()

        joined = "\n".join(cm.output)
        self.assertIn("still full", joined)
        self.assertIn("profiles", joined)


if __name__ == "__main__":
    unittest.main()
