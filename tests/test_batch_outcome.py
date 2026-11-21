# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A shell batch fails when a command in it fails, and its process says so.

The SCP03, SCP80, SUCI, eSIM Management and Local eIM shells used to end every
``--cmd`` / ``--stdin`` batch with exit code 0, whatever a command printed.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import pytest

from yggdrasim_common.batch_outcome import (
    RULE_STREAM,
    BatchOutcome,
    is_failure_line,
    is_stream_failure_line,
)


class FailureLineRuleTests(unittest.TestCase):
    def test_failed_steps_and_refusals_fail(self) -> None:
        for line in (
            "[-] Select Failed: '7FFF'",
            "    [-] indented",
            "[!] No operation 999.",
            "[!] Could not resolve profile: ISDP2",
            "\x1b[38;2;191;97;106m[!] Unknown command: FOO\x1b[0m",
        ):
            self.assertTrue(is_failure_line(line), line)

    def test_notes_and_warnings_do_not_fail(self) -> None:
        for line in (
            "[!] Warning: File is Linear Fixed. Use 'RECORD' command.",
            "[!] warning: lower case",
            "[*] Notification sync: handleNotification failed for queued notification seq=1",
            "[+] DisableProfile: success.",
            "  [*] Skipped: MF/7F10 (None of ['7F10'] found)",
            "plain text that mentions [-] in the middle",
            "",
        ):
            self.assertFalse(is_failure_line(line), line)

    def test_stream_rule_lets_running_notices_pass(self) -> None:
        self.assertFalse(is_stream_failure_line("[!] TransferEimPackage: request refused, not loopback"))
        self.assertTrue(is_stream_failure_line("[!] FLOW failed: timeout"))
        self.assertTrue(is_stream_failure_line("[-] EnableProfile failed"))


class BatchOutcomeTests(unittest.TestCase):
    def _run(self, outcome: BatchOutcome, line: str, printed: str, **judgement) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            with outcome.command(line, **judgement):
                sys.stdout.write(printed)

    def test_a_failure_line_fails_the_batch_and_names_the_command(self) -> None:
        outcome = BatchOutcome()
        self._run(outcome, "GET-EID", "[*] EID: 89049032123451234512345678901235\n")
        self.assertTrue(outcome.ok)
        self._run(outcome, "OP 999", "[!] No operation 999.\n")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.failed_commands, ["OP 999"])

    def test_a_line_without_its_newline_still_counts(self) -> None:
        outcome = BatchOutcome()
        self._run(outcome, "X", "[-] no newline at the end")
        self.assertFalse(outcome.ok)

    def test_output_split_across_writes_is_judged_as_one_line(self) -> None:
        outcome = BatchOutcome()
        with contextlib.redirect_stdout(io.StringIO()):
            with outcome.command("X"):
                sys.stdout.write("[")
                sys.stdout.write("-] split\n")
        self.assertFalse(outcome.ok)

    def test_stderr_is_watched_too(self) -> None:
        outcome = BatchOutcome()
        with contextlib.redirect_stderr(io.StringIO()):
            with outcome.command("X"):
                print("[!] error on stderr", file=sys.stderr)
        self.assertFalse(outcome.ok)

    def test_an_exception_fails_the_command_and_is_raised_on(self) -> None:
        outcome = BatchOutcome()
        with self.assertRaises(ValueError):
            with outcome.command("BOOM"):
                raise ValueError("boom")
        self.assertFalse(outcome.ok)

    def test_a_clean_exit_is_not_a_failure(self) -> None:
        outcome = BatchOutcome()
        with self.assertRaises(SystemExit):
            with outcome.command("EXIT"):
                raise SystemExit(0)
        self.assertTrue(outcome.ok)

    def test_a_verdict_decides_over_the_lines(self) -> None:
        outcome = BatchOutcome()
        self._run(outcome, "EIM-LISTEN", "[!] TransferEimPackage: request refused\n", verdict=lambda: True)
        self.assertTrue(outcome.ok)
        self._run(outcome, "EIM-LISTEN", "[*] nothing wrong printed\n", verdict=lambda: False)
        self.assertFalse(outcome.ok)

    def test_no_verdict_falls_back_to_the_lines(self) -> None:
        outcome = BatchOutcome()
        self._run(outcome, "EIM-LISTEN", "[-] port in use\n", verdict=lambda: None)
        self.assertFalse(outcome.ok)

    def test_the_stream_rule_for_commands_that_run_until_stopped(self) -> None:
        outcome = BatchOutcome()
        self._run(outcome, "WATCH", "[!] notice while running\n", rule=RULE_STREAM)
        self.assertTrue(outcome.ok)

    def test_the_streams_are_put_back(self) -> None:
        before_out, before_err = sys.stdout, sys.stderr
        outcome = BatchOutcome()
        with outcome.command("X"):
            pass
        self.assertIs(sys.stdout, before_out)
        self.assertIs(sys.stderr, before_err)


class ConsoleJudgementTests(unittest.TestCase):
    def test_the_listener_and_long_running_verbs_get_their_own_rule(self) -> None:
        from SCP11.live.console import SCP11Console

        fake = types.SimpleNamespace(
            _commands={
                "WATCH": types.SimpleNamespace(long_running=True),
                "LIST": types.SimpleNamespace(long_running=False),
            },
            _last_eim_listen_ok=True,
        )
        self.assertEqual(SCP11Console._batch_judgement(fake, "LIST"), {})
        self.assertEqual(SCP11Console._batch_judgement(fake, "WATCH --debug"), {"rule": RULE_STREAM})
        judged = SCP11Console._batch_judgement(fake, "EIM-LISTEN port=8746")
        # A verdict left from an earlier listener in the batch is not reused.
        self.assertIsNone(judged["verdict"]())
        fake._last_eim_listen_ok = False
        self.assertFalse(judged["verdict"]())


class Scp03BatchTests(unittest.TestCase):
    def _dispatcher(self, script: dict[str, str]):
        pytest.importorskip("smartcard")
        from SCP03.interface.shell import ShellDispatcher

        shell = ShellDispatcher.__new__(ShellDispatcher)
        shell._flush_pending_startup_stderr = lambda: None
        shell._close_trace = lambda reason="": None
        shell._history_line_is_sensitive = lambda line: False
        shell._redact_command_line_for_display = lambda line: line

        def exec_line(line: str) -> None:
            if line.upper() == "EXIT":
                raise SystemExit(0)
            print(script[line])

        shell._exec_line = exec_line
        return shell

    def test_a_failed_command_fails_the_batch_and_exit_still_ends_it(self) -> None:
        shell = self._dispatcher({"SELECT 7FFF": "[-] Select Failed: '7FFF'", "INFO": "[+] ok"})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(shell.run_commands("SELECT 7FFF; EXIT; INFO"))
            self.assertTrue(shell.run_commands("INFO; EXIT"))

    def test_the_yaml_report_is_written_when_the_batch_ends_with_exit(self) -> None:
        shell = self._dispatcher({"INFO": "[+] ok"})
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.yaml"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(shell.run_commands("INFO; EXIT", yaml_out=str(report)))
            self.assertTrue(report.is_file())
            self.assertIn('command: "INFO"', report.read_text(encoding="utf-8"))


class Scp80BatchTests(unittest.TestCase):
    def _shell(self, script: dict[str, tuple[str, bool]]):
        pytest.importorskip("smartcard")
        from SCP80.cli import OtaShell

        shell = OtaShell.__new__(OtaShell)
        shell.last_command_ok = True

        def process_line(line: str) -> bool:
            if line == "exit":
                return False
            printed, delivered = script[line]
            print(printed)
            shell.last_command_ok = delivered
            return True

        shell._process_line = process_line
        return shell

    def test_a_failed_delivery_fails_the_batch_even_without_a_failure_line(self) -> None:
        shell = self._shell({"show": ("[*] keyset 1", True), "send 00A4": ("[*] PoR missing", False)})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(shell.run_commands("show; exit"))
            self.assertFalse(shell.run_commands("show; send 00A4; exit"))

    def test_a_failure_line_fails_the_batch_although_the_delivery_flag_is_set(self) -> None:
        shell = self._shell({"foo": ("[!] Unknown command or invalid hex.", True)})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(shell.run_commands("foo"))


class SuciBatchTests(unittest.TestCase):
    def test_an_unknown_verb_fails_the_batch(self) -> None:
        from Tools.SuciTool.shell import SuciToolShell

        with tempfile.TemporaryDirectory() as folder:
            shell = SuciToolShell(workspace_root=Path(folder))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(shell.run_commands("STATUS; EXIT"))
                self.assertFalse(shell.run_commands("FOO; EXIT"))


class EimLocalBatchTests(unittest.TestCase):
    def test_a_refused_command_fails_the_batch(self) -> None:
        from SCP11.eim_local.main import EimLocalShell

        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder}):
                shell = EimLocalShell()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(shell.run_commands("OPS all"))
                    self.assertFalse(shell.run_commands("OPS all; OP 999"))
                    self.assertFalse(shell.run_commands("NOT-A-VERB"))


if __name__ == "__main__":
    unittest.main()
