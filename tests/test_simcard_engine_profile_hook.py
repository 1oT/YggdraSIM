"""Regression tests for ``SIMCARD.engine`` profile-download hook.

These locks guard the contract that:

* A hook registered before the first store sync does NOT receive a
  callback for profiles that were already on disk at construction
  time (the first sync is a "seed", not a "download").
* A genuinely new ICCID fires the hook exactly once.
* A repeat sync with the same ICCID set is a no-op (hook not re-fired).
* Multiple hooks can be registered and each receives the event.
* A hook that raises does not corrupt the snapshot bookkeeping: the
  ICCID is still recorded as seen so later syncs behave correctly.
* ``unregister_profile_download_hook`` silently tolerates non-member
  callables (important for shutdown paths).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimProfileEntry


class ProfileDownloadHookTests(unittest.TestCase):
    def _build_engine_with_isolated_stores(self) -> SimulatedSimCardEngine:
        self._td = tempfile.TemporaryDirectory()
        store_root = Path(self._td.name) / "simcard"
        store_root.mkdir(parents=True, exist_ok=True)
        euicc_path = store_root / "euicc"
        euicc_path.mkdir(parents=True, exist_ok=True)
        profile_store = store_root / "profile_store"
        profile_store.mkdir(parents=True, exist_ok=True)
        engine = SimulatedSimCardEngine(
            euicc_store_root=str(store_root),
            profile_store_path=str(profile_store),
        )
        self.addCleanup(self._td.cleanup)
        return engine

    def test_seed_sync_does_not_fire_hook(self) -> None:
        engine = self._build_engine_with_isolated_stores()
        events: list[dict] = []
        engine.register_profile_download_hook(events.append)
        engine._sync_all_stores()
        self.assertEqual(events, [])

    def test_new_iccid_fires_hook_exactly_once(self) -> None:
        engine = self._build_engine_with_isolated_stores()
        events: list[dict] = []
        engine.register_profile_download_hook(events.append)
        engine._sync_all_stores()
        engine.state.profiles.append(
            SimProfileEntry(aid="A000000087", iccid="89000055550000111122")
        )
        engine._sync_all_stores()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["iccid"], "89000055550000111122")
        engine._sync_all_stores()
        self.assertEqual(len(events), 1)

    def test_multiple_hooks_each_receive_event(self) -> None:
        engine = self._build_engine_with_isolated_stores()
        events_a: list[dict] = []
        events_b: list[dict] = []
        engine.register_profile_download_hook(events_a.append)
        engine.register_profile_download_hook(events_b.append)
        engine._sync_all_stores()
        engine.state.profiles.append(
            SimProfileEntry(aid="A0000000871A", iccid="89000066660000222233")
        )
        engine._sync_all_stores()
        self.assertEqual(len(events_a), 1)
        self.assertEqual(len(events_b), 1)

    def test_hook_exception_does_not_drop_snapshot(self) -> None:
        engine = self._build_engine_with_isolated_stores()
        events: list[dict] = []

        def _exploding_hook(event: dict) -> None:
            events.append(event)
            raise RuntimeError("simulated handler failure")

        engine.register_profile_download_hook(_exploding_hook)
        engine._sync_all_stores()
        engine.state.profiles.append(
            SimProfileEntry(aid="A000000087", iccid="89000077770000333344")
        )
        engine._sync_all_stores()
        engine._sync_all_stores()
        self.assertEqual(len(events), 1)
        self.assertIn("89000077770000333344", engine._last_profile_iccids)

    def test_unregister_tolerates_unknown_callable(self) -> None:
        engine = self._build_engine_with_isolated_stores()

        def _phantom(_event: dict) -> None:
            return None

        engine.unregister_profile_download_hook(_phantom)

    def test_register_rejects_non_callable(self) -> None:
        engine = self._build_engine_with_isolated_stores()
        with self.assertRaises(TypeError):
            engine.register_profile_download_hook("not a callable")  # type: ignore[arg-type]
