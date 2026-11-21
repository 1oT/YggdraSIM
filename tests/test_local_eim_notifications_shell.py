# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""NOTIFICATIONS in the eIM-local shell, and the forwarding pass after DELIVER.

The verb lists the Notifications IPAs handed to the Local eIM, sends them on
and holds them (SGP.32 v1.3 §5.7.4, ES9+'.HandleNotification); DELIVER sends
the ones its run took from the card once the reader is given back. The
receiver here is a recorder: no test contacts a host.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine.service import OperationRequest
from SCP11.eim_local.engine_shell import DOCS, HELP_SECTIONS, EngineVerbs
from SCP11.eim_local.main import EimLocalShell
from tests.local_eim_notification_support import ICCID, RECEIVER, Receiver, SigningEuicc
from tests.test_local_eim_engine import EIM_ID, ENABLED, SimCard

# The store's own sender, read before any test replaces it.
_ORIGINAL_SENDER = outbox.receiver_sender


class ShellTestBase(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.receiver = Receiver()
        for patch in (
            mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(Path(folder.name) / "store")}),
            # The sender a pass builds for itself: the recorder, whatever the store.
            mock.patch.object(outbox, "receiver_sender", lambda *_args, **_options: self.receiver),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.shell = EimLocalShell()
        self.verbs = self.shell._engine_verbs
        self.engine = self.verbs.engine
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()


class NotificationsVerbTests(ShellTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.euicc = SigningEuicc()
        self.eid = self.euicc.eid
        self.engine.register(self.eid)
        self.engine.apply_card_reads(self.eid, {"euicc_certificate": self.euicc.certificate,
                                                "eum_certificate": self.euicc.eum_certificate})

    def take(self, *numbers: int, event: str = "enable") -> None:
        for number in numbers:
            self.engine.accept_notification(self.eid, self.euicc.other(number, event))

    def test_the_verb_is_documented_and_listed_in_help(self) -> None:
        self.assertIn("NOTIFICATIONS", DOCS)
        self.assertIn("NOTIFICATIONS", [key for _title, rows in HELP_SECTIONS for _text, key in rows])
        self.assertIn("NOTIFICATIONS", self.run_line("HELP"))
        self.assertIn("Usage   : NOTIFICATIONS [<eid>] | NOTIFICATIONS SEND", self.run_line("HELP NOTIFICATIONS"))

    def test_an_empty_list_says_so_and_no_rule_holds_notifications(self) -> None:
        self.assertIn("[*] No Notifications on record.", self.run_line("NOTIFICATIONS"))
        self.assertIn("[!] Unknown setting 'notification_forwarding'",
                      self.run_line("EIM-SETTINGS notification_forwarding=hold"))
        self.assertNotIn("notification_forwarding", self.run_line("EIM-SETTINGS"))
        self.assertNotIn("HOLD", DOCS["NOTIFICATIONS"]["usage"])

    def test_the_list_gives_one_line_per_notification_under_its_euicc(self) -> None:
        self.take(7, event="disable")
        self.take(9)
        output = self.run_line("NOTIFICATIONS")
        self.assertIn(f"[*] {self.eid}: 2 pending", output)
        self.assertIn(f"         7  disable  for {RECEIVER}, ICCID {ICCID}: pending", output)
        self.assertIn(f"         9  enable   for {RECEIVER}, ICCID {ICCID}: pending", output)
        self.assertIn("[*] A pending Notification goes to its receiver after DELIVER and INJECT", output)
        self.assertEqual(self.receiver.calls, [])

    def test_send_tries_the_pending_ones_and_reports_each(self) -> None:
        self.take(7, 9)
        output = self.run_line("NOTIFICATIONS SEND")
        self.assertIn(f"[+] Notification 7 (enable) of {self.eid}: delivered to {RECEIVER}", output)
        self.assertIn(f"[+] Notification 9 (enable) of {self.eid}: delivered to {RECEIVER}", output)
        self.assertEqual(self.receiver.hosts, [RECEIVER, RECEIVER])
        self.assertIn("[*] No Notification to send.", self.run_line(f"NOTIFICATIONS SEND {self.eid}"))
        self.assertIn(f"[*] {self.eid}: 2 delivered", self.run_line("NOTIFICATIONS"))

    def test_a_receiver_that_is_down_prints_as_a_failure_with_the_next_attempt(self) -> None:
        self.receiver.fail(RECEIVER, "connection refused")
        self.take(7)
        output = self.run_line("NOTIFICATIONS SEND")
        self.assertIn(f"[!] Notification 7 (enable) of {self.eid}: not delivered to {RECEIVER} (attempt 1): "
                      "connection refused; next attempt at ", output)
        self.assertIn("pending, 1 attempt(s), last: connection refused", self.run_line("NOTIFICATIONS"))

    def test_a_refused_one_has_failed_and_a_named_send_tries_it_again(self) -> None:
        self.take(7, 9)
        self.receiver.fail(RECEIVER, f"{RECEIVER} answered HTTP 403", retry=False)
        output = self.run_line("NOTIFICATIONS SEND")
        self.assertIn(f"[!] Notification 7 (enable) of {self.eid}: not sent: {RECEIVER} answered HTTP 403", output)
        self.assertIn(f"failed: {RECEIVER} answered HTTP 403", self.run_line("NOTIFICATIONS"))
        self.receiver.recover(RECEIVER)
        self.assertIn("[*] No Notification to send. A failed or kept one is sent when its seqNumber is named",
                      self.run_line(f"NOTIFICATIONS SEND {self.eid} 11"))
        self.assertIn("delivered", self.run_line(f"NOTIFICATIONS SEND {self.eid} 7"))

    def test_what_the_verb_refuses(self) -> None:
        self.take(7)
        other = "89049032123451234512345678901250"
        for line, said in (
            ("NOTIFICATIONS SEND 7", "[!] Name the eUICC"),
            ("NOTIFICATIONS HOLD", "[!] Usage: NOTIFICATIONS"),
            (f"NOTIFICATIONS HOLD {self.eid} 7", "[!] Usage: NOTIFICATIONS"),
            ("NOTIFICATIONS 7", "[!] Usage: NOTIFICATIONS"),
            ("NOTIFICATIONS DROP", "[!] Usage: NOTIFICATIONS"),
            ("NOTIFICATIONS SEND all", "[!] Usage: NOTIFICATIONS"),
            ("NOTIFICATIONS SEND target=smdp.example.test", "[!] Usage: NOTIFICATIONS"),
            ("NOTIFICATIONS SEND --force", "[!] Usage: NOTIFICATIONS"),
            (f"NOTIFICATIONS {other}", f"[!] No eUICC {other}."),
            (f"NOTIFICATIONS SEND {self.eid} {other}", "[!] Usage: NOTIFICATIONS"),
        ):
            self.assertIn(said, self.run_line(line), line)
        self.assertEqual(self.receiver.calls, [])


class DeliverTests(ShellTestBase):
    """DELIVER on the simulated eUICC: the reader is the card's exchange, no channel is opened."""

    def setUp(self) -> None:
        super().setUp()
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        self.order: list[str] = []

        def with_reader(_verbs: EngineVerbs, verb: str, body):
            self.order.append(f"{verb} takes the reader")
            try:
                return body()
            finally:
                self.order.append(f"{verb} gives the reader back")

        def send(host: str, notification: bytes) -> None:
            self.order.append(f"sent to {host}")
            self.receiver(host, notification)

        for patch in (
            mock.patch.object(EngineVerbs, "_with_reader", with_reader),
            mock.patch.object(EngineVerbs, "_exchange", lambda _verbs, payload, label: self.card.exchange(payload, label)),
            mock.patch.object(EngineVerbs, "_reset_card", lambda _verbs: True),
            mock.patch.object(outbox, "receiver_sender", lambda *_args, **_options: send),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.engine.submit([OperationRequest(eid=self.card.eid, type="DISABLE_PROFILE", params={"iccid": ENABLED})])

    def test_the_notification_of_a_disable_goes_on_after_the_reader_is_given_back(self) -> None:
        output = self.run_line("DELIVER")
        self.assertIn("[+] notification 1 for rsp.example.com taken", output)
        self.assertIn("[*] 1 package(s) delivered.", output)
        self.assertIn(f"[+] Notification 1 (disable) of {self.card.eid}: delivered to rsp.example.com", output)
        self.assertEqual(self.order, ["DELIVER takes the reader", "DELIVER gives the reader back",
                                      "sent to rsp.example.com"])
        self.assertLess(output.index("package(s) delivered"), output.index("delivered to rsp.example.com"))

    def test_a_hold_rule_an_earlier_version_stored_does_not_keep_deliver_from_sending(self) -> None:
        self.engine.store.set_setting("notification_forwarding", "hold")
        output = self.run_line("DELIVER")
        self.assertIn("[+] notification 1 for rsp.example.com taken", output)
        self.assertIn(f"[+] Notification 1 (disable) of {self.card.eid}: delivered to rsp.example.com", output)
        self.assertEqual(self.receiver.hosts, ["rsp.example.com"])


class OwnSenderTests(ShellTestBase):
    """With the store's own sender: the simulator's test address is reported as a fact, and nobody is contacted."""

    def test_a_reserved_address_prints_without_the_failure_mark(self) -> None:
        card = SimCard()
        self.engine.associate(card.exchange, card.eid)
        self.engine.submit([OperationRequest(eid=card.eid, type="DISABLE_PROFILE", params={"iccid": ENABLED})])
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(EngineVerbs, "_with_reader", lambda _verbs, _verb, body: body()))
            stack.enter_context(mock.patch.object(EngineVerbs, "_exchange",
                                                  lambda _verbs, payload, label: card.exchange(payload, label)))
            stack.enter_context(mock.patch.object(EngineVerbs, "_reset_card", lambda _verbs: True))
            stack.enter_context(mock.patch.object(outbox, "receiver_sender", _ORIGINAL_SENDER))
            stack.enter_context(mock.patch("SCP11.live.es9_client.Es9LikeClient",
                                           side_effect=AssertionError("a receiver was contacted")))
            output = self.run_line("DELIVER")
        self.assertIn(f"[*] Notification 1 (disable) of {card.eid}: not sent: rsp.example.com is a reserved or local "
                      "name where no Notification Receiver answers", output)
        self.assertNotIn("[!]", output)


if __name__ == "__main__":
    unittest.main()
