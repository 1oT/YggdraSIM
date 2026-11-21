# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The launcher's run options reach the GUI modes as they reach the menu.

``--card-backend``, the ``--sim-*`` options and ``--debug`` used to be
applied after ``--gui`` / ``--web-server`` had returned, so a GUI started
with ``--card-backend sim`` came up on the reader.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.card_backend import (
    CARD_BACKEND_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_QUIRKS_ENV,
    get_card_backend,
    get_sim_euicc_store_root,
    get_sim_quirks_path,
)
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV


MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_gui_session_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)


class LauncherGuiSessionArgumentsTests(unittest.TestCase):
    def _run_gui_mode(self, argv: list[str]) -> dict[str, object]:
        """Run ``run_cli`` with the GUI routing stubbed; return what the GUI would see."""
        seen: dict[str, object] = {}

        def fake_route(args):
            if not (getattr(args, "gui", False) or getattr(args, "web_server", False)):
                return None
            seen["backend"] = get_card_backend()
            seen["quirks"] = get_sim_quirks_path()
            seen["euicc_store"] = get_sim_euicc_store_root()
            seen["debug"] = os.environ.get(GLOBAL_DEBUG_ENV)
            return 0

        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_root = str(Path(temp_dir) / "runtime_root")
            with mock.patch.dict(
                os.environ,
                {
                    "YGGDRASIM_RUNTIME_ROOT": runtime_root,
                    CARD_BACKEND_ENV: "",
                    SIM_QUIRKS_ENV: "",
                    SIM_EUICC_STORE_ENV: "",
                    GLOBAL_DEBUG_ENV: "0",
                },
                clear=False,
            ):
                os.environ.pop(CARD_BACKEND_ENV, None)
                with mock.patch.object(main_wrapper, "_route_gui_modes", side_effect=fake_route):
                    with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                        seen["exit"] = main_wrapper.run_cli(argv)
                seen["menu_called"] = mocked_menu.called
                os.environ.pop(CARD_BACKEND_ENV, None)
                seen["saved_backend"] = get_card_backend()
                seen["store_dir"] = temp_dir
        return seen

    def test_web_server_runs_on_the_backend_and_quirks_it_was_given(self) -> None:
        seen = self._run_gui_mode(
            ["--web-server", "--card-backend", "sim", "--sim-quirks", "none", "--token-file", "unused"]
        )
        self.assertEqual(seen["exit"], 0)
        self.assertFalse(seen["menu_called"])
        self.assertEqual(seen["backend"], "sim")
        self.assertEqual(seen["quirks"], "")
        # The option lasts for the run: the saved selection is unchanged.
        self.assertEqual(seen["saved_backend"], "reader")

    def test_desktop_gui_takes_the_simulator_paths_and_debug(self) -> None:
        with tempfile.TemporaryDirectory() as store_dir:
            seen = self._run_gui_mode(
                ["--gui", "--card-backend", "sim", "--sim-euicc-store", store_dir, "--debug"]
            )
            self.assertEqual(seen["exit"], 0)
            self.assertEqual(seen["backend"], "sim")
            self.assertEqual(os.path.realpath(str(seen["euicc_store"])), os.path.realpath(store_dir))
            self.assertEqual(seen["debug"], "1")

    def test_a_failed_profile_import_stops_before_the_gui(self) -> None:
        with mock.patch.object(main_wrapper, "_import_simulator_profile", return_value=1) as mocked_import:
            seen = self._run_gui_mode(["--gui", "--sim-import-profile", "missing.der"])
        self.assertEqual(seen["exit"], 1)
        self.assertNotIn("backend", seen)
        mocked_import.assert_called_once()


if __name__ == "__main__":
    unittest.main()
