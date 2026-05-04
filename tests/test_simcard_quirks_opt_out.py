"""Coverage for the two "disable simulator quirks" opt-out surfaces.

The simulator quirks system has three independent layers:

1. The path resolver in :mod:`yggdrasim_common.card_backend`. Recognises a
   ``none`` sentinel (also ``off`` / ``disabled`` / ``disable``) on either
   the env var ``YGGDRASIM_SIM_QUIRKS`` or the persisted settings entry.
   When seen, it short-circuits to ``""`` so the reseeded workspace
   default is skipped.
2. The loader in :mod:`SIMCARD.quirks`. Honours the ``none`` path
   sentinel and also an orthogonal process-wide kill switch
   ``YGGDRASIM_DISABLE_QUIRKS`` that always wins.
3. The security gate (``YGGDRASIM_ALLOW_QUIRKS``) - unchanged, still
   required before an actual Python quirks file is executed.

These tests lock all three layers independently so future refactors
cannot silently regress the "run the simulator with an empty registry"
guarantee.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.card_backend import (
    SETTING_SOURCE_DISABLED,
    SIM_QUIRKS_ENV,
    SIM_QUIRKS_PATH_DISABLED_ALIASES,
    SIM_QUIRKS_PATH_NONE,
    _is_sim_quirks_disabled_sentinel,
    _SETTINGS_KEY_SIM_QUIRKS_PATH,
    get_sim_quirks_path,
    get_sim_quirks_source,
    is_sim_quirks_disabled,
    set_sim_quirks_path,
)

from SIMCARD.quirks import load_quirk_registry
from yggdrasim_common.env_flags import FLAG_REGISTRY


class _EnvIsolationMixin:
    """Scrub quirks-related env vars so each test starts in a known state."""

    def _clear_env(self) -> None:
        for key in (
            SIM_QUIRKS_ENV,
            "YGGDRASIM_ALLOW_QUIRKS",
            "YGGDRASIM_DISABLE_QUIRKS",
        ):
            os.environ.pop(key, None)


class SentinelRecognitionTests(_EnvIsolationMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._clear_env()

    def tearDown(self) -> None:
        self._clear_env()

    def test_sentinel_aliases_cover_expected_keywords(self) -> None:
        # Any rename / reshuffle of the alias tuple should be deliberate
        # and caught by this test rather than surfacing as a silent
        # regression in the getters.
        self.assertIn("none", SIM_QUIRKS_PATH_DISABLED_ALIASES)
        self.assertIn("off", SIM_QUIRKS_PATH_DISABLED_ALIASES)
        self.assertIn("disabled", SIM_QUIRKS_PATH_DISABLED_ALIASES)
        self.assertIn("disable", SIM_QUIRKS_PATH_DISABLED_ALIASES)
        self.assertEqual(SIM_QUIRKS_PATH_NONE, "none")

    def test_helper_is_case_and_whitespace_insensitive(self) -> None:
        self.assertTrue(_is_sim_quirks_disabled_sentinel("none"))
        self.assertTrue(_is_sim_quirks_disabled_sentinel("NONE"))
        self.assertTrue(_is_sim_quirks_disabled_sentinel("  None  "))
        self.assertTrue(_is_sim_quirks_disabled_sentinel("off"))
        self.assertTrue(_is_sim_quirks_disabled_sentinel("DISABLED"))
        self.assertFalse(_is_sim_quirks_disabled_sentinel(""))
        self.assertFalse(_is_sim_quirks_disabled_sentinel("/tmp/q.py"))
        self.assertFalse(_is_sim_quirks_disabled_sentinel(None))


class GetterShortCircuitTests(_EnvIsolationMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._clear_env()

    def tearDown(self) -> None:
        self._clear_env()

    def test_env_sentinel_suppresses_default_fallthrough(self) -> None:
        # When the env var is set to "none" the getter must return the
        # empty path, NOT the reseeded workspace default, so the loader
        # can build an empty registry without the security gate firing.
        os.environ[SIM_QUIRKS_ENV] = "none"

        self.assertEqual(get_sim_quirks_path(), "")
        self.assertTrue(is_sim_quirks_disabled())
        self.assertEqual(get_sim_quirks_source(), SETTING_SOURCE_DISABLED)

    def test_env_sentinel_is_case_insensitive_and_whitespace_tolerant(self) -> None:
        os.environ[SIM_QUIRKS_ENV] = "  OFF  "

        self.assertEqual(get_sim_quirks_path(), "")
        self.assertTrue(is_sim_quirks_disabled())

    def test_persisted_sentinel_suppresses_default_fallthrough(self) -> None:
        with mock.patch(
            "yggdrasim_common.card_backend._get_persisted_setting",
            return_value="disabled",
        ) as mocked_persisted:
            self.assertEqual(get_sim_quirks_path(), "")
            self.assertTrue(is_sim_quirks_disabled())
            self.assertEqual(get_sim_quirks_source(), SETTING_SOURCE_DISABLED)
            mocked_persisted.assert_called_with(_SETTINGS_KEY_SIM_QUIRKS_PATH)

    def test_concrete_env_path_still_resolves_to_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = str(Path(temp_dir) / "custom_quirks.py")
            os.environ[SIM_QUIRKS_ENV] = path

            resolved = get_sim_quirks_path()

            self.assertEqual(resolved, os.path.abspath(path))
            self.assertFalse(is_sim_quirks_disabled())


class SetterSentinelPersistenceTests(_EnvIsolationMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._clear_env()

    def tearDown(self) -> None:
        self._clear_env()

    def test_set_sim_quirks_path_none_writes_canonical_sentinel(self) -> None:
        # We mock the persistence layer so the test does not pollute
        # the real workspace settings file.
        with mock.patch(
            "yggdrasim_common.card_backend._try_persist_setting"
        ) as mocked_persist:
            returned = set_sim_quirks_path("none")

        self.assertEqual(returned, SIM_QUIRKS_PATH_NONE)
        self.assertEqual(os.environ.get(SIM_QUIRKS_ENV), SIM_QUIRKS_PATH_NONE)
        mocked_persist.assert_called_once_with(
            _SETTINGS_KEY_SIM_QUIRKS_PATH,
            SIM_QUIRKS_PATH_NONE,
        )

    def test_set_sim_quirks_path_off_is_normalised_to_none(self) -> None:
        with mock.patch(
            "yggdrasim_common.card_backend._try_persist_setting"
        ):
            returned = set_sim_quirks_path("OFF")

        self.assertEqual(returned, SIM_QUIRKS_PATH_NONE)
        self.assertEqual(os.environ.get(SIM_QUIRKS_ENV), SIM_QUIRKS_PATH_NONE)

    def test_set_sim_quirks_path_empty_clears_env_and_persist(self) -> None:
        os.environ[SIM_QUIRKS_ENV] = "/old/value.py"
        with mock.patch(
            "yggdrasim_common.card_backend._try_persist_setting"
        ) as mocked_persist:
            returned = set_sim_quirks_path("")

        self.assertEqual(returned, "")
        self.assertNotIn(SIM_QUIRKS_ENV, os.environ)
        mocked_persist.assert_called_once_with(_SETTINGS_KEY_SIM_QUIRKS_PATH, "")


class LoaderKillSwitchTests(_EnvIsolationMixin, unittest.TestCase):
    """Validate the loader's three independent exits from the gate.

    Each case uses a real on-disk file for ``/path`` so that without
    the opt-out the loader would definitely either execute the module
    (trust gate on) or raise ``PermissionError`` (trust gate off).
    """

    def setUp(self) -> None:
        self._clear_env()
        self._temp = tempfile.TemporaryDirectory()
        self.quirks_path = Path(self._temp.name) / "trust_me.py"
        self.quirks_path.write_text(
            "# This file should never execute during these tests.\n"
            "raise RuntimeError('quirks file must not be imported')\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._clear_env()
        self._temp.cleanup()

    def test_disable_env_wins_even_when_path_points_at_existing_file(self) -> None:
        os.environ["YGGDRASIM_DISABLE_QUIRKS"] = "1"
        # Allow gate is still off, but the kill switch must short-circuit
        # *before* the gate check, so no PermissionError is raised.

        registry = load_quirk_registry(str(self.quirks_path))

        self.assertEqual(len(registry.before_apdu_hooks), 0)
        self.assertEqual(len(registry.after_apdu_hooks), 0)
        self.assertEqual(len(registry.on_reset_hooks), 0)
        self.assertEqual(len(registry.state_hooks), 0)

    def test_disable_env_wins_even_with_allow_gate_enabled(self) -> None:
        os.environ["YGGDRASIM_ALLOW_QUIRKS"] = "1"
        os.environ["YGGDRASIM_DISABLE_QUIRKS"] = "1"

        registry = load_quirk_registry(str(self.quirks_path))

        self.assertEqual(len(registry.before_apdu_hooks), 0)

    def test_path_sentinel_none_skips_loading(self) -> None:
        # No kill switch, no allow gate, but path == "none": the loader
        # must still return an empty registry without raising.
        registry = load_quirk_registry("none")
        self.assertEqual(len(registry.before_apdu_hooks), 0)

        registry = load_quirk_registry("  DISABLED  ")
        self.assertEqual(len(registry.before_apdu_hooks), 0)

    def test_empty_path_still_returns_empty_registry(self) -> None:
        registry = load_quirk_registry("")
        self.assertEqual(len(registry.before_apdu_hooks), 0)

    def test_existing_file_without_gate_still_raises(self) -> None:
        # Confirms the security gate is preserved: no DISABLE flag, no
        # sentinel, gate off - the PermissionError path is still taken
        # so this refactor cannot silently weaken the original
        # protection.
        with self.assertRaises(PermissionError) as ctx:
            load_quirk_registry(str(self.quirks_path))
        self.assertIn("YGGDRASIM_ALLOW_QUIRKS", str(ctx.exception))
        # And the error message now also mentions the new opt-out paths
        # so operators know how to bypass the gate safely.
        self.assertIn("YGGDRASIM_DISABLE_QUIRKS", str(ctx.exception))
        self.assertIn("none", str(ctx.exception))


class EnvFlagRegistrationTests(unittest.TestCase):
    """Lock the new kill switch into the shared env-flag catalog."""

    def test_disable_quirks_flag_is_registered(self) -> None:
        names = {flag.name for flag in FLAG_REGISTRY}
        self.assertIn("YGGDRASIM_DISABLE_QUIRKS", names)
        self.assertIn("YGGDRASIM_ALLOW_QUIRKS", names)

    def test_sim_quirks_flag_documents_none_sentinel(self) -> None:
        flag = next(
            flag for flag in FLAG_REGISTRY if flag.name == "YGGDRASIM_SIM_QUIRKS"
        )
        description = (flag.description or "").lower()
        self.assertIn("none", description)
        self.assertIn("yggdrasim_disable_quirks", description)


if __name__ == "__main__":
    unittest.main()
