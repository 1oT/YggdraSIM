# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The disabled built-in lab Profile may become the Fallback Profile.

setFallbackAttribute refuses a Profile whose fallbackAllowed is not TRUE
(SGP.32 v1.3 §3.4.6 step 4, §4.4), so the simulator seeds the disabled lab
Profile with it and leaves the enabled one without. A Profile store saved
before the flag was seeded gets the seed's value for a built-in Profile that
holds none; a value the store holds and a downloaded Profile are kept as they
are.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine, _backfill_seed_fallback_allowed
from SIMCARD.etsi_fs import ISDP2_AID, build_default_state
from SIMCARD.profile_store import sync_profiles_to_store
from SIMCARD.state import SimProfileEntry


def _by_aid(profiles: list[SimProfileEntry]) -> dict[str, SimProfileEntry]:
    return {profile.aid.upper(): profile for profile in profiles}


class SeedTests(unittest.TestCase):
    def test_only_the_disabled_lab_profile_is_seeded_fallback_allowed(self) -> None:
        profiles = build_default_state().profiles
        self.assertEqual(
            [(profile.state, profile.fallback_allowed) for profile in profiles],
            [("enabled", None), ("disabled", True)],
        )
        self.assertEqual(profiles[1].aid.upper(), ISDP2_AID)


class BackfillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seeded = build_default_state().profiles

    def _saved(self, **changes: object) -> list[SimProfileEntry]:
        return [replace(profile, **changes) for profile in self.seeded]

    def test_a_built_in_profile_saved_without_the_flag_takes_the_seed(self) -> None:
        loaded = self._saved(fallback_allowed=None)
        _backfill_seed_fallback_allowed(loaded, self.seeded)
        self.assertEqual([profile.fallback_allowed for profile in loaded], [None, True])

    def test_a_value_the_store_holds_is_kept(self) -> None:
        loaded = self._saved(fallback_allowed=False)
        _backfill_seed_fallback_allowed(loaded, self.seeded)
        self.assertEqual([profile.fallback_allowed for profile in loaded], [False, False])

    def test_a_profile_without_a_seed_twin_is_untouched(self) -> None:
        downloaded = replace(self.seeded[1], iccid="8988000000000000301", fallback_allowed=None)
        other_aid = replace(
            self.seeded[1], aid="A0000005591010FFFFFFFF8900001300", fallback_allowed=None
        )
        loaded = [downloaded, other_aid]
        _backfill_seed_fallback_allowed(loaded, self.seeded)
        self.assertEqual([profile.fallback_allowed for profile in loaded], [None, None])

    def test_an_engine_on_an_older_store_reads_the_seed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = Path(temp_dir) / "profiles"
            sync_profiles_to_store(str(store), self._saved(fallback_allowed=None))
            engine = SimulatedSimCardEngine(
                quirks_path="none",
                behaviour_profile_path="none",
                euicc_store_root=str(Path(temp_dir) / "euicc"),
                profile_store_path=str(store),
                private=True,
            )
            profiles = _by_aid(engine.state.profiles)
            self.assertIs(profiles[ISDP2_AID].fallback_allowed, True)
            self.assertIsNone(profiles[self.seeded[0].aid.upper()].fallback_allowed)


if __name__ == "__main__":
    unittest.main()
