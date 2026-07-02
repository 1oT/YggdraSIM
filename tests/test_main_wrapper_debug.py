# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV


MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_debug_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)


class MainWrapperDebugTests(unittest.TestCase):
    def test_wrapper_debug_flag_promotes_debug_to_menu_session(self) -> None:
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "0"}, clear=False):
            with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                exit_code = main_wrapper.run_cli(["--debug"])
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(debug_value, "1")
        mocked_menu.assert_called_once_with()

    def test_wrapper_verbose_alias_promotes_debug_to_menu_session(self) -> None:
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "0"}, clear=False):
            with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                exit_code = main_wrapper.run_cli(["--verbose"])
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(debug_value, "1")
        mocked_menu.assert_called_once_with()

    def test_wrapper_without_debug_preserves_existing_debug_state(self) -> None:
        # When --debug is omitted, a previously enabled debug flag survives
        # across invocations instead of being reset to 0.
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "1"}, clear=False):
            with mock.patch.object(main_wrapper, "main_menu") as mocked_menu:
                exit_code = main_wrapper.run_cli([])
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(debug_value, "1")
        mocked_menu.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
