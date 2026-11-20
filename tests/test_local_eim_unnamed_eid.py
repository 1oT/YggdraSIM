# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The eUICC of a Local eIM verb that names none, and the reader it may not take from a listener.

A verb without an EID reads the card in the reader. Opening the channel
power-cycles the card, so the read waits for the reader lock like every card
verb: a reader that another process holds until stopped (EIM-LISTEN) refuses
it, and QUEUE and PACKAGE-IMPORT then take the one eUICC that has an inject
target. The other process here is a real one.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.main import EimLocalShell
from tests.reader_lock_support import READER, OtherProcess
from tests.test_local_eim_engine import EIM_ID, SimCard
from yggdrasim_common import reader_locks
from yggdrasim_common.reader_locks import ReaderBusyError

LISTENER = "EIM-LISTEN in the eSIM Management console"
OTHER_EID = "89049032123451234512345678901268"
TARGET = "http://127.0.0.1:8746"


class _Reader:
    def __str__(self) -> str:
        return READER


class UnnamedEidTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.lock_dir = Path(folder.name) / "reader-locks"
        for patch in (
            mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(Path(folder.name) / "store"),
                                         "YGGDRASIM_CARD_BACKEND": "reader"}),
            mock.patch.object(reader_locks, "_DIRECTORY", self.lock_dir),
            mock.patch("smartcard.System.readers", return_value=[_Reader()]),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.shell = EimLocalShell()
        self.verbs = self.shell._engine_verbs
        self.engine = self.verbs.engine
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        self.shell.session.apdu_channel = None
        # No test here may open a reader: the channel class stands for it.
        self.channel = mock.patch("SCP11.transport.PcscApduChannel", side_effect=AssertionError("the reader was opened"))
        self.opened = self.channel.start()
        self.addCleanup(self.channel.stop)

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def listener(self) -> OtherProcess:
        holder = OtherProcess(self.lock_dir, READER, long_running=True, holder=LISTENER)
        self.addCleanup(holder.close)
        return holder

    def card_answers(self, eid: str) -> None:
        """A card in a free reader that gives *eid*, without a channel of the real kind."""
        for patch in (mock.patch.object(type(self.verbs), "_ensure_channel", lambda _self: None),
                      mock.patch.object(self.shell.session, "_read_card_eid_safe", return_value=eid, create=True)):
            patch.start()
            self.addCleanup(patch.stop)

    def queued_for(self) -> list[str]:
        return [operation.eid for operation in self.engine.operations() if operation.state == "CREATED"]

    def busy_text(self, holder: OtherProcess) -> str:
        return f"reader busy: {LISTENER} (pid {holder.pid}) has held {READER!r} since "

    def test_a_reader_another_process_listens_on_is_not_opened_for_the_eid(self) -> None:
        holder = self.listener()
        with self.assertRaises(ReaderBusyError) as refusal:
            self.verbs._card_eid()
        self.assertTrue(str(refusal.exception).startswith(self.busy_text(holder)))
        self.opened.assert_not_called()

    def test_queue_then_takes_the_one_euicc_that_has_an_inject_target(self) -> None:
        holder = self.listener()
        self.engine.set_inject_target(self.card.eid, TARGET)
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertIn(f"[*] No EID given; {self.busy_text(holder)}", output)
        self.assertIn(f". Taking the eUICC that has an inject target: {self.card.eid}", output)
        self.assertIn("[+] Queued 1 operation(s)", output)
        self.assertEqual(self.queued_for(), [self.card.eid])
        self.opened.assert_not_called()

    def test_without_one_such_euicc_the_busy_reader_is_what_the_operator_reads(self) -> None:
        holder = self.listener()
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertIn(f"[!] No EID given; {self.busy_text(holder)}", output)
        self.assertIn(", and no eUICC has an inject target. Name the EID.", output)
        self.run_line(f"EUICC ADD {OTHER_EID} second")
        self.engine.set_inject_target(self.card.eid, TARGET)
        self.engine.set_inject_target(OTHER_EID, "http://127.0.0.1:8747")
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertIn(", and more than one eUICC has an inject target. Name the EID.", output)
        self.assertEqual(self.queued_for(), [])
        self.opened.assert_not_called()

    def test_a_named_eid_needs_no_reader_at_all(self) -> None:
        self.listener()
        output = self.run_line(f"QUEUE LIST-PROFILES {self.card.eid}")
        self.assertIn("[+] Queued 1 operation(s)", output)
        self.assertNotIn("No EID given", output)
        self.opened.assert_not_called()

    def test_deliver_on_that_reader_is_refused_in_a_line(self) -> None:
        holder = self.listener()
        output = self.run_line("DELIVER")
        self.assertIn(f"[!] {self.busy_text(holder)}", output)
        self.assertNotIn("Traceback", output)
        self.opened.assert_not_called()

    def test_a_card_that_can_be_read_wins_over_a_kept_target(self) -> None:
        self.run_line(f"EUICC ADD {OTHER_EID} second")
        self.engine.set_inject_target(OTHER_EID, TARGET)
        self.card_answers(self.card.eid)
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertNotIn("Taking the eUICC", output)
        self.assertEqual(self.queued_for(), [self.card.eid])
        # The read held the reader and gave it back.
        hold = reader_locks.acquire(READER, "probe", wait_s=0.0)
        hold.release()

    def test_without_a_card_the_target_is_taken_and_the_reason_said(self) -> None:
        self.engine.set_inject_target(self.card.eid, TARGET)
        self.opened.side_effect = RuntimeError("Reader index 0 is out of range. Detected readers: 0.")
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertIn("[*] No EID given; no card answered (RuntimeError: Reader index 0 is out of range. "
                      f"Detected readers: 0.). Taking the eUICC that has an inject target: {self.card.eid}", output)
        self.assertEqual(self.queued_for(), [self.card.eid])

    def test_a_card_that_gives_no_eid_is_said_as_such(self) -> None:
        self.card_answers("")
        self.assertIn("[!] No EID given; no EID was read from a card, and no eUICC has an inject target. Name the EID.",
                      self.run_line("QUEUE LIST-PROFILES"))
        self.engine.set_inject_target(self.card.eid, TARGET)
        output = self.run_line("QUEUE LIST-PROFILES")
        self.assertIn(f"[*] No EID given; no EID was read from a card. Taking the eUICC that has an inject target: "
                      f"{self.card.eid}", output)

    def test_the_card_read_itself_keeps_its_own_refusal(self) -> None:
        self.card_answers("")
        with self.assertRaises(Exception) as refusal:
            self.verbs._card_eid()
        self.assertEqual(str(refusal.exception), "No EID given and none read from a card; name the EID.")


if __name__ == "__main__":
    unittest.main()
