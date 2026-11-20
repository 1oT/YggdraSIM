# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""pySim's secure-channel log lines (``yggdrasim_common.pysim_log_gate``).

pySim prints the SCP02 / SCP03 key derivations through ``PySimLogger``.
``pySim.global_platform`` and ``pySim.global_platform.scp`` both carry its
print handler, and the pinned pySim prints a record once all the same
(``upstream_patches/osmocom-pysim-log-duplicate-handlers/``). YggdraSIM shows
them only while ``YGGDRASIM_GLOBAL_DEBUG`` is on, and refuses a pySim that
would print them twice. A pySim without the print handlers prints nothing
either way.
"""

from __future__ import annotations

import contextlib
import io
import logging
import os
import threading
import unittest
from unittest import mock

from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV
from yggdrasim_common.pysim_log_gate import (
    SECURE_CHANNEL_LOGGERS,
    PySimLogGateMismatch,
    install_pysim_secure_channel_log_gate,
)

try:
    from pySim.global_platform.scp import scp03_key_derivation
except ImportError:
    scp03_key_derivation = None


def _print_handlers() -> list[logging.Handler]:
    return [
        handler
        for name in SECURE_CHANNEL_LOGGERS
        for handler in logging.getLogger(name).handlers
        if type(handler).__name__ == "_PySimLogHandler"
    ]


def _gated(handler: logging.Handler) -> bool:
    return any(type(existing).__name__ == "_PySimSecureChannelGate" for existing in handler.filters)


def _kdf_stdout_lines() -> list[str]:
    captured = io.StringIO()
    # The MCP server module sets the "pySim" logger to WARNING when it is
    # imported, and an earlier test file of the same process imports it; the
    # gate under test is the handler filter, so the level is pinned here.
    upstream = logging.getLogger("pySim")
    level = upstream.level
    upstream.setLevel(logging.DEBUG)
    try:
        with contextlib.redirect_stdout(captured):
            scp03_key_derivation(b"\x04", bytes(16), bytes(range(16)), 128)
    finally:
        upstream.setLevel(level)
    return captured.getvalue().splitlines()


@unittest.skipIf(scp03_key_derivation is None, "pySim is not installed")
class PySimSecureChannelLogGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        install_pysim_secure_channel_log_gate()

    def test_installer_is_idempotent(self) -> None:
        self.assertFalse(install_pysim_secure_channel_log_gate())
        self.assertTrue(all(_gated(handler) for handler in _print_handlers()))

    def test_key_derivation_prints_nothing_without_the_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "0"}):
            self.assertEqual(_kdf_stdout_lines(), [])

    def test_key_derivation_prints_once_under_the_debug_flag(self) -> None:
        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "1"}):
            lines = _kdf_stdout_lines()
        if not _print_handlers():
            self.assertEqual(lines, [])
            return
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("scp03_kdf(", lines[0])

    def test_the_scp03_session_installs_the_gate(self) -> None:
        from SCP03.crypto import session

        handlers = _print_handlers()
        for handler in handlers:
            for existing in [f for f in handler.filters if type(f).__name__ == "_PySimSecureChannelGate"]:
                handler.removeFilter(existing)
        previous = session._PYSIM_SCP03_KDF
        session._PYSIM_SCP03_KDF = None
        try:
            session._resolve_kdf()
            self.assertTrue(all(_gated(handler) for handler in handlers))
        finally:
            session._PYSIM_SCP03_KDF = previous
            install_pysim_secure_channel_log_gate()

    def _with_rogue_handlers(self, handler_class: type) -> None:
        # One on each level, so the record reaches two of them whatever pySim
        # itself installed.
        rogues = [(logging.getLogger(name), handler_class()) for name in SECURE_CHANNEL_LOGGERS]
        for logger, rogue in rogues:
            logger.addHandler(rogue)
        try:
            with self.assertRaises(PySimLogGateMismatch):
                install_pysim_secure_channel_log_gate()
        finally:
            for logger, rogue in rogues:
                logger.removeHandler(rogue)

    def test_a_pysim_that_prints_a_record_twice_raises(self) -> None:
        # The handler before the fix: every handler a record reaches prints it.
        class _PySimLogHandler(logging.Handler):
            def __init__(self, log_callback=lambda message, record: None) -> None:
                super().__init__()
                self.log_callback = log_callback

            def emit(self, record: logging.LogRecord) -> None:
                self.log_callback(self.format(record), record)

        self._with_rogue_handlers(_PySimLogHandler)

    def test_a_handler_that_cannot_be_probed_raises(self) -> None:
        class _PySimLogHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                pass

        self._with_rogue_handlers(_PySimLogHandler)

    def test_installing_leaves_stdout_to_other_threads(self) -> None:
        # The GUI server prints from worker threads while an SCP session
        # installs the gate; none of their lines may go missing or count as
        # a probe line.
        captured = io.StringIO()
        lines = 300
        failures: list[BaseException] = []

        def _print_lines() -> None:
            for index in range(lines):
                print(f"worker line {index}")

        def _install_repeatedly() -> None:
            try:
                for _ in range(50):
                    install_pysim_secure_channel_log_gate()
            except BaseException as error:  # noqa: BLE001 -- reported below
                failures.append(error)

        with mock.patch("sys.stdout", captured):
            threads = [threading.Thread(target=_print_lines), threading.Thread(target=_install_repeatedly)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
        self.assertEqual(failures, [])
        self.assertEqual(len(captured.getvalue().splitlines()), lines)

    def test_concurrent_installs_add_one_gate_per_handler(self) -> None:
        handlers = _print_handlers()
        for handler in handlers:
            for existing in [f for f in handler.filters if type(f).__name__ == "_PySimSecureChannelGate"]:
                handler.removeFilter(existing)
        barrier = threading.Barrier(8)

        def _install() -> None:
            barrier.wait(timeout=10)
            install_pysim_secure_channel_log_gate()

        threads = [threading.Thread(target=_install) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        for handler in handlers:
            gates = [f for f in handler.filters if type(f).__name__ == "_PySimSecureChannelGate"]
            self.assertEqual(len(gates), 1)


if __name__ == "__main__":
    unittest.main()
