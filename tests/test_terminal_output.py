# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from yggdrasim_common.nord_palette import NORD
from yggdrasim_common.terminal_output import (
    classify_status_text,
    colorize_hex_dump_line,
    colorize_status_text,
    status_print,
)


class _TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class TerminalOutputTests(unittest.TestCase):
    def test_classifies_common_status_roles(self) -> None:
        cases = {
            "[+] eIM package exchange completed.": "success",
            "[OK] profile state verified": "success",
            "OK": "success",
            "[!] eIM entry failed: eIM2": "error",
            "Failure": "error",
            "[WARNING] retrying poll": "warning",
            "Warning": "warning",
            "[*] eIM response: len=699 format=binary first=BF4F": "data",
            "[*] Phase: GetEimPackage": "info",
        }

        for text, role in cases.items():
            with self.subTest(text=text):
                self.assertEqual(classify_status_text(text), role)

    def test_non_tty_output_stays_plain_by_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            rendered = colorize_status_text("[+] ok", stream=io.StringIO())

        self.assertEqual(rendered, "[+] ok")

    def test_tty_output_uses_role_color(self) -> None:
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            rendered = colorize_status_text("[+] ok", stream=_TtyBuffer())

        self.assertEqual(rendered, f"{NORD.GREEN}[+] ok{NORD.RESET}")

    def test_no_color_overrides_forced_color(self) -> None:
        env = {"NO_COLOR": "set", "YGGDRASIM_FORCE_COLOR": "1"}
        with mock.patch.dict(os.environ, env, clear=True):
            rendered = colorize_status_text("[ERROR] failed", stream=_TtyBuffer())

        self.assertEqual(rendered, "[ERROR] failed")

    def test_force_color_supports_redirected_output(self) -> None:
        with mock.patch.dict(os.environ, {"YGGDRASIM_FORCE_COLOR": "1"}, clear=True):
            rendered = colorize_status_text("[ERROR] failed", stream=io.StringIO())

        self.assertEqual(rendered, f"{NORD.FAIL}[ERROR] failed{NORD.RESET}")

    def test_hex_dump_line_colors_offset_and_payload(self) -> None:
        with mock.patch.dict(os.environ, {"YGGDRASIM_FORCE_COLOR": "1"}, clear=True):
            rendered = colorize_hex_dump_line("    000000: BF 51 03")

        self.assertIn(f"{NORD.GUIDE}000000:{NORD.RESET}", rendered)
        self.assertIn(f"{NORD.SURFACE}BF 51 03{NORD.RESET}", rendered)

    def test_status_print_colors_full_line_when_enabled(self) -> None:
        buffer = io.StringIO()

        with mock.patch.dict(os.environ, {"YGGDRASIM_FORCE_COLOR": "1"}, clear=True):
            status_print("[WARNING] retrying", file=buffer)

        self.assertEqual(buffer.getvalue(), f"{NORD.WARNING}[WARNING] retrying{NORD.RESET}\n")


if __name__ == "__main__":
    unittest.main()
