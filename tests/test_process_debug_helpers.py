# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import io
import os
import unittest
import warnings
from unittest import mock

from yggdrasim_common.process_debug import (
    GLOBAL_DEBUG_ENV,
    debug_print,
    install_noisy_warning_filters,
    is_global_debug_enabled,
    set_global_debug,
    suppress_noisy_crypto_warnings,
)
from yggdrasim_common.nord_palette import NORD


class DebugPrintGatingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_value = os.environ.get(GLOBAL_DEBUG_ENV, "")

    def tearDown(self) -> None:
        os.environ[GLOBAL_DEBUG_ENV] = self._previous_value

    def test_debug_print_is_silent_when_flag_is_off(self) -> None:
        set_global_debug(False)
        buffer = io.StringIO()
        debug_print("[*] this should stay hidden", stream=buffer)
        self.assertFalse(is_global_debug_enabled())
        self.assertEqual(buffer.getvalue(), "")

    def test_debug_print_emits_message_when_flag_is_on(self) -> None:
        set_global_debug(True)
        buffer = io.StringIO()
        debug_print("[*] surfaced in debug mode", stream=buffer)
        self.assertTrue(is_global_debug_enabled())
        self.assertEqual(buffer.getvalue(), "[*] surfaced in debug mode\n")

    def test_debug_print_defaults_to_stdout(self) -> None:
        set_global_debug(True)
        with mock.patch("sys.stdout", new_callable=io.StringIO) as patched_stdout:
            debug_print("[*] default stream path")
        self.assertEqual(patched_stdout.getvalue(), "[*] default stream path\n")

    def test_debug_print_can_emit_colored_status(self) -> None:
        env = {GLOBAL_DEBUG_ENV: "1", "YGGDRASIM_FORCE_COLOR": "1"}
        with mock.patch.dict(os.environ, env, clear=True):
            buffer = io.StringIO()
            debug_print("[+] surfaced in debug mode", stream=buffer)

        expected = f"{NORD.GREEN}[+] surfaced in debug mode{NORD.RESET}\n"
        self.assertEqual(buffer.getvalue(), expected)

    def test_debug_print_tolerates_broken_streams(self) -> None:
        set_global_debug(True)

        class _BrokenStream:
            def write(self, _text: str) -> None:
                raise IOError("stream gone")

            def flush(self) -> None:
                raise IOError("flush gone")

        debug_print("[*] will be swallowed", stream=_BrokenStream())


class SuppressNoisyCryptoWarningsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._previous_value = os.environ.get(GLOBAL_DEBUG_ENV, "")

    def tearDown(self) -> None:
        os.environ[GLOBAL_DEBUG_ENV] = self._previous_value

    def test_suppresses_crypto_deprecation_when_debug_off(self) -> None:
        try:
            from cryptography.utils import CryptographyDeprecationWarning
        except Exception:
            self.skipTest("cryptography library is unavailable in this interpreter")

        set_global_debug(False)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with suppress_noisy_crypto_warnings():
                warnings.warn("synthetic", CryptographyDeprecationWarning)
        emitted = [item for item in captured if issubclass(item.category, CryptographyDeprecationWarning)]
        self.assertEqual(len(emitted), 0)

    def test_passes_through_crypto_deprecation_when_debug_on(self) -> None:
        try:
            from cryptography.utils import CryptographyDeprecationWarning
        except Exception:
            self.skipTest("cryptography library is unavailable in this interpreter")

        set_global_debug(True)
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with suppress_noisy_crypto_warnings():
                warnings.warn("synthetic", CryptographyDeprecationWarning)
        emitted = [item for item in captured if issubclass(item.category, CryptographyDeprecationWarning)]
        self.assertEqual(len(emitted), 1)

    def test_install_noisy_warning_filters_is_noop_when_debug_on(self) -> None:
        try:
            from cryptography.utils import CryptographyDeprecationWarning
        except Exception:
            self.skipTest("cryptography library is unavailable in this interpreter")

        set_global_debug(True)
        original_filters = list(warnings.filters)
        try:
            install_noisy_warning_filters()
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always")
                warnings.warn("synthetic", CryptographyDeprecationWarning)
            emitted = [item for item in captured if issubclass(item.category, CryptographyDeprecationWarning)]
            self.assertEqual(len(emitted), 1)
        finally:
            warnings.filters[:] = original_filters


if __name__ == "__main__":
    unittest.main()
