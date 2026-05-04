"""Coverage for the launcher's ``[D] Disable simulator quirks`` menu.

Two things need to hold:

1. ``_quirks_value_display`` must surface the opt-out intent clearly
   rather than the generic "(workspace default unavailable)" string,
   because the resolver returns an empty path for both cases.
2. The ``configure_card_backend`` loop must toggle correctly:
   pressing ``D`` from an unconfigured state persists the ``none``
   sentinel, and pressing ``D`` again from the disabled state falls
   back to the workspace default.

These tests shell out into the real ``main.main`` module (so that a
regression in the menu wiring is caught) but isolate the env + the
persisted settings via ``mock.patch.dict`` and a private
``_try_persist_setting`` stub.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

import main.main as main_wrapper
from yggdrasim_common.card_backend import (
    SETTING_SOURCE_DISABLED,
    SIM_QUIRKS_ENV,
    SIM_QUIRKS_PATH_NONE,
)


class _EnvIsolationMixin:
    def _clear_env(self) -> None:
        for key in (
            SIM_QUIRKS_ENV,
            "YGGDRASIM_ALLOW_QUIRKS",
            "YGGDRASIM_DISABLE_QUIRKS",
        ):
            os.environ.pop(key, None)


class QuirksValueDisplayTests(_EnvIsolationMixin, unittest.TestCase):
    def setUp(self) -> None:
        self._clear_env()

    def tearDown(self) -> None:
        self._clear_env()

    def test_disabled_state_is_rendered_explicitly(self) -> None:
        os.environ[SIM_QUIRKS_ENV] = "none"

        text = main_wrapper._quirks_value_display()

        self.assertIn("empty quirks registry", text)
        self.assertNotIn("workspace default unavailable", text)

    def test_concrete_path_is_passed_through(self) -> None:
        # Route the getter through a patched env to avoid depending on
        # the operator's real workspace. An absolute path survives the
        # normalisation, so the result can be asserted directly.
        os.environ[SIM_QUIRKS_ENV] = "/tmp/example-quirks.py"

        text = main_wrapper._quirks_value_display()

        self.assertEqual(text, "/tmp/example-quirks.py")

    def test_missing_default_keeps_legacy_fallback_text(self) -> None:
        # Neither env nor persisted nor an existing workspace file:
        # the legacy "(workspace default unavailable)" string is still
        # the right thing to show.
        with mock.patch(
            "yggdrasim_common.card_backend._get_persisted_setting",
            return_value="",
        ), mock.patch(
            "yggdrasim_common.card_backend.get_default_sim_quirks_path",
            return_value="/does/not/exist.py",
        ):
            text = main_wrapper._quirks_value_display()

        self.assertEqual(text, "(workspace default unavailable)")


class ConfigureCardBackendDisableToggleTests(_EnvIsolationMixin, unittest.TestCase):
    """Drive the menu via mocked ``input()`` to cover the toggle paths."""

    def setUp(self) -> None:
        self._clear_env()
        self._persist_patcher = mock.patch(
            "yggdrasim_common.card_backend._try_persist_setting"
        )
        self._persist = self._persist_patcher.start()
        self.addCleanup(self._persist_patcher.stop)
        self._persisted_store: dict[str, str] = {}

        def _fake_persist(key: str, value: str) -> None:
            self._persisted_store[key] = value

        self._persist.side_effect = _fake_persist

        self._persisted_getter_patcher = mock.patch(
            "yggdrasim_common.card_backend._get_persisted_setting",
            side_effect=lambda key: self._persisted_store.get(key, ""),
        )
        self._persisted_getter_patcher.start()
        self.addCleanup(self._persisted_getter_patcher.stop)

    def tearDown(self) -> None:
        self._clear_env()

    def _run_menu_with_inputs(self, inputs: list[str]) -> None:
        """Drive ``configure_card_backend`` by scripting stdin input."""
        input_iter = iter(inputs)
        with mock.patch.object(main_wrapper, "clear_screen", lambda: None), \
             mock.patch.object(main_wrapper, "pause", lambda: None), \
             mock.patch("builtins.input", side_effect=lambda *_a, **_kw: next(input_iter)), \
             mock.patch.object(main_wrapper, "print"):
            main_wrapper.configure_card_backend()

    def test_pressing_d_from_clean_state_persists_none_sentinel(self) -> None:
        self._run_menu_with_inputs(["D", "Q"])

        self.assertEqual(os.environ.get(SIM_QUIRKS_ENV), SIM_QUIRKS_PATH_NONE)
        self.assertEqual(
            self._persisted_store.get("sim_quirks_path"),
            SIM_QUIRKS_PATH_NONE,
        )
        from yggdrasim_common.card_backend import (
            get_sim_quirks_path,
            get_sim_quirks_source,
            is_sim_quirks_disabled,
        )

        self.assertEqual(get_sim_quirks_path(), "")
        self.assertEqual(get_sim_quirks_source(), SETTING_SOURCE_DISABLED)
        self.assertTrue(is_sim_quirks_disabled())

    def test_pressing_d_twice_toggles_back_to_workspace_default(self) -> None:
        self._run_menu_with_inputs(["D", "D", "Q"])

        # After the second toggle both env and persisted store must be
        # clear so the resolver falls back to the workspace default.
        self.assertNotIn(SIM_QUIRKS_ENV, os.environ)
        self.assertEqual(self._persisted_store.get("sim_quirks_path"), "")

        from yggdrasim_common.card_backend import is_sim_quirks_disabled

        self.assertFalse(is_sim_quirks_disabled())

    def test_lowercase_d_is_accepted_via_upper_normalisation(self) -> None:
        # The menu normalises selections via ``.upper()`` so lowercase
        # should be equivalent. This guards against a future refactor
        # that accidentally drops the normalisation step.
        self._run_menu_with_inputs(["d", "Q"])

        self.assertEqual(os.environ.get(SIM_QUIRKS_ENV), SIM_QUIRKS_PATH_NONE)


if __name__ == "__main__":
    unittest.main()
