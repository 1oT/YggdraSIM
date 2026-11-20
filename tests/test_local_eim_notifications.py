# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Local eIM sends the Notifications it is handed on to their Notification Receivers.

An IPA hands them over with an eUICC Package Result, in an IPA data response
or by ESipa.HandleNotification; the eIM acknowledges them and calls
ES9+'.HandleNotification at the notificationAddress each names (SGP.32 v1.3
§3.7 step 2b, §5.7.4, §5.14.6, §5.14.7). No test here opens a socket to a
receiver: the sender is a recorder, and the ES9+ client is a stand-in.
"""

from __future__ import annotations

import base64
import datetime
import io
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine.delivery import deliver
from SCP11.eim_local.engine.esipa import LocalEimHttpServer, handle_asn1
from SCP11.eim_local.engine.service import (
    ROUTE_DIRECT,
    ROUTE_ESIPA,
    ROUTE_IMPORT,
    LocalEim,
    LocalEimError,
    OperationRequest,
)
from SCP11.eim_local.engine.smdp import LocalSmdp
from SCP11.eim_local.engine.store import RECORD_NOTIFICATION_CAP
from SCP11.eim_local.engine.traffic import Verdict
from SCP11.shared import esipa_download
from SCP11.shared.ber_tlv import retag_sequence
from tests.local_eim_notification_support import ICCID, OTHER_RECEIVER, RECEIVER, Receiver, SigningEuicc
from tests.test_local_eim_engine import DISABLED, EIM_ID, ENABLED, SimCard

START = datetime.datetime(2026, 11, 4, 12, 0, tzinfo=datetime.timezone.utc)

# RFC 2606 §2 (TLDs for testing and documentation examples) and §3 (reserved example second level
# domain names), whole.
RFC_2606_TOP_LEVEL = ("test", "example", "invalid", "localhost")
# A name that is not reserved for tests and is nobody's allocation either: the special-use domain of
# home networks. The sender treats it like any SM-DP+ host, and the client that would call it is a stand-in.
ORDINARY_HOST = "smdp.home.arpa"
RFC_2606_SECOND_LEVEL = ("example.com", "example.net", "example.org")


class ReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.euicc = SigningEuicc()

    def test_the_four_forms_of_a_pending_notification_are_read(self) -> None:
        full = outbox.read(self.euicc.other(7, "disable"))
        self.assertEqual((full.kind, full.compact, full.seq_number, full.event, full.address, full.iccid),
                         (outbox.KIND_OTHER, False, 7, "disable", RECEIVER, ICCID))
        compact = outbox.read(self.euicc.compact_other(8, "enable"))
        self.assertEqual((compact.kind, compact.compact, compact.seq_number, compact.event, compact.eid),
                         (outbox.KIND_OTHER, True, 8, "enable", self.euicc.eid))
        result = outbox.read(self.euicc.installation_result(9))
        self.assertEqual((result.kind, result.compact, result.seq_number, result.event, result.address),
                         (outbox.KIND_INSTALLATION, False, 9, "install", RECEIVER))
        compact_result = codec.tlv(b"\xA0", codec.tlv(b"\xA0", codec.tlv(b"\x80", bytes(16)) + codec.integer_tlv(b"\x02", 10)
                                                      + codec.tlv(b"\xA2", codec.tlv(b"\xA0", b"")))
                                   + codec.tlv(b"\x5F\x37", bytes(64)))
        read = outbox.read(compact_result)
        self.assertEqual((read.kind, read.compact, read.seq_number), (outbox.KIND_INSTALLATION, True, 10))

    def test_octets_that_are_no_notification_are_refused_by_name(self) -> None:
        whole = self.euicc.other(7)
        for octets in (b"", b"\x30", whole[:3], whole[:40], b"\x30\x82\xFF\xFF" + whole[4:60], b"\x04\x02\x00\x00",
                       codec.tlv(b"\x30", b""), codec.tlv(b"\x30", self.euicc.metadata(1, "enable", RECEIVER))):
            with self.assertRaises(outbox.NotificationError, msg=octets.hex()):
                outbox.read(octets)
            self.assertIsNone(outbox.seq_number_of(octets))

    def test_the_signature_is_judged_under_the_certificate_given(self) -> None:
        stranger = SigningEuicc("89049032123451234512345678901250")
        for notification in (self.euicc.other(7), self.euicc.compact_other(7), self.euicc.installation_result(7)):
            view = outbox.read(notification)
            self.assertEqual(outbox.unverified(view, self.euicc.certificate), "")
            self.assertIn("does not verify", outbox.unverified(view, stranger.certificate))
            self.assertIn("no eUICC certificate", outbox.unverified(view, b""))
        tampered = bytearray(self.euicc.other(7))
        tampered[tampered.index(RECEIVER.encode())] ^= 0x01
        self.assertIn("does not verify", outbox.unverified(outbox.read(bytes(tampered)), self.euicc.certificate))

    def test_a_compact_notification_is_restored_to_the_octets_the_euicc_made(self) -> None:
        compact = self.euicc.compact_other(7, "disable")
        restored = outbox.full_form(compact, outbox.read(compact), self.euicc.certificate, self.euicc.eum_certificate)
        self.assertEqual(restored, self.euicc.other(7, "disable")[:4] + restored[4:])
        self.assertEqual(outbox.read(restored).signed, outbox.read(compact).signed)
        self.assertTrue(restored.endswith(self.euicc.certificate + self.euicc.eum_certificate))
        full = self.euicc.other(7)
        self.assertEqual(outbox.full_form(full, outbox.read(full), b"", b""), full)
        with self.assertRaises(outbox.NotificationError):
            outbox.full_form(compact, outbox.read(compact), self.euicc.certificate, b"")

    def test_a_notification_address_is_a_host_name_and_nothing_else(self) -> None:
        self.assertEqual(outbox.receiver_host(" SMDP.Example.Test. "), "smdp.example.test")
        for address in ("", "localhost", "https://smdp.example.test", "smdp.example.test:8443", "smdp.example.test/x",
                        "user@smdp.example.test", "192.0.2.4", "[2001:db8::1]", "smdp..example.test",
                        "-smdp.example.test", "smdp.example.test?x=1", "smdp.example\n.test", "a b.example.test",
                        "x" * 64 + ".example.test", ".".join(["a" * 60] * 5) + ".test"):
            with self.assertRaises(outbox.NotificationError, msg=address):
                outbox.receiver_host(address)

    def test_names_no_receiver_answers_under_are_known(self) -> None:
        self.assertEqual(outbox.RESERVED_TOP_LEVEL, RFC_2606_TOP_LEVEL)
        self.assertEqual(outbox.RESERVED_SECOND_LEVEL, RFC_2606_SECOND_LEVEL)
        for label in RFC_2606_TOP_LEVEL:
            self.assertTrue(outbox.reserved_name(f"smdp.{label}"), label)
        for name in RFC_2606_SECOND_LEVEL:
            self.assertTrue(outbox.reserved_name(name), name)
            self.assertTrue(outbox.reserved_name(f"rsp.{name}"), name)
        self.assertTrue(outbox.reserved_name("smdpp.yggdrasim.local"))
        # A reserved label counts at the end of the name only.
        for name in (ORDINARY_HOST, f"example.com.{ORDINARY_HOST}", f"test.{ORDINARY_HOST}", f"local.{ORDINARY_HOST}"):
            self.assertFalse(outbox.reserved_name(name), name)


class OutboxTestBase(unittest.TestCase):
    """An engine with one eUICC of the test's own key on record, certificates read as from a card."""

    def setUp(self) -> None:
        super().setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.now = START
        self.engine = LocalEim(self.directory, clock=lambda: self.now)
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.euicc = SigningEuicc()
        self.eid = self.euicc.eid
        self.engine.register(self.eid)
        self.engine.apply_card_reads(self.eid, {"euicc_certificate": self.euicc.certificate,
                                                "eum_certificate": self.euicc.eum_certificate})
        self.receiver = Receiver()

    def take(self, *notifications: bytes, route: str = ROUTE_ESIPA) -> list:
        return [self.engine.accept_notification(self.eid, notification, route=route) for notification in notifications]

    def forward(self, **options):
        return self.engine.forward_notifications(sender=self.receiver, **options)

    def states(self) -> dict[int, str]:
        return {row["seq_number"]: row["state"] for row in self.engine.notifications(self.eid)}

    def entry(self, seq_number: int) -> dict:
        return outbox.find(self.engine.record(self.eid), seq_number)

    def later(self, seconds: float) -> None:
        self.now = self.now + datetime.timedelta(seconds=seconds)


class TakeTests(OutboxTestBase):
    def test_a_notification_is_put_on_the_record_and_acknowledged(self) -> None:
        accepted = self.take(self.euicc.other(7, "disable"))[0]
        self.assertEqual(accepted.acknowledgements, [7])
        self.assertEqual(accepted.notifications, 1)
        self.assertEqual(accepted.messages, [f"notification 7 for {RECEIVER} taken"])
        entry = self.entry(7)
        self.assertEqual((entry["state"], entry["event"], entry["address"], entry["iccid"], entry["route"]),
                         (outbox.STATE_PENDING, "disable", RECEIVER, ICCID, ROUTE_ESIPA))
        self.assertEqual(self.receiver.calls, [])

    def test_the_same_notification_again_is_acknowledged_and_not_taken_twice(self) -> None:
        self.take(self.euicc.other(7))
        self.forward()
        again = self.take(self.euicc.other(7))[0]
        self.assertEqual(again.acknowledgements, [7])
        self.assertEqual(again.notifications, 0)
        self.assertEqual(again.messages, ["notification 7 was taken before (delivered)"])
        self.assertEqual(len(self.engine.notifications(self.eid)), 1)
        self.assertEqual(self.forward(), [])
        self.assertEqual(len(self.receiver.calls), 1)

    def test_no_rule_and_no_verb_holds_a_notification_back(self) -> None:
        with self.assertRaises(LocalEimError):
            self.engine.set_setting("notification_forwarding", "hold")
        self.assertNotIn("notification_forwarding", self.engine.settings())
        self.assertFalse(hasattr(self.engine, "hold_notifications"))
        self.assertFalse(hasattr(outbox, "hold"))
        accepted = self.take(self.euicc.other(7))[0]
        self.assertEqual(accepted.acknowledgements, [7])
        self.assertEqual(self.entry(7)["state"], outbox.STATE_PENDING)
        self.assertTrue(self.forward()[0].delivered)

    def test_a_notification_of_an_imported_result_is_sent_on(self) -> None:
        accepted = self.take(self.euicc.other(7), route=ROUTE_IMPORT)[0]
        self.assertEqual(accepted.messages, [f"notification 7 for {RECEIVER} taken"])
        self.assertEqual(self.entry(7)["state"], outbox.STATE_PENDING)
        self.assertTrue(self.forward()[0].delivered)
        self.assertEqual(self.receiver.hosts, [RECEIVER])

    def test_a_notification_listed_in_an_ipa_data_response_is_acknowledged_and_sent_on(self) -> None:
        # SGP.32 v1.3 §2.11.1.2: tag 'A0' asks the IPA for what the eUICC stores. The eIM acknowledges
        # each one it takes, so the eUICC drops it: it goes on from here, also where the IPA has an
        # ES9+ interface of its own and may deliver it as well.
        listed = codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", codec.tlv(b"\xA0", self.euicc.other(7))))
        accepted = self.engine.accept_result(self.eid, listed)
        self.assertEqual(accepted.acknowledgements, [7])
        self.assertEqual(self.entry(7)["state"], outbox.STATE_PENDING)
        self.assertNotIn("reason", self.entry(7))
        self.assertTrue(self.forward()[0].delivered)
        self.assertEqual(self.receiver.hosts, [RECEIVER])

    def test_a_listed_notification_under_another_key_fails_and_is_never_sent(self) -> None:
        # The list of an IPA data response no operation asked for is taken as well, so the signature is
        # what stands between a listed Notification and the address it names.
        forger = SigningEuicc(self.eid)
        listed = codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", codec.tlv(
            b"\xA0", forger.other(7, "enable", "collector.example.test"))))
        self.engine.accept_result(self.eid, listed)
        outcome = self.forward()[0]
        self.assertEqual(outcome.result, outbox.STATE_FAILED)
        self.assertIn("the eUICC signature does not verify", outcome.text)
        self.assertTrue(outcome.problem)
        self.assertEqual(self.receiver.calls, [])
        self.assertEqual(self.forward(explicit=True), [])

    def test_a_listed_notification_waits_for_the_certificate_and_then_goes(self) -> None:
        other = SigningEuicc("89049032123451234512345678901250")
        self.engine.register(other.eid)
        listed = codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", codec.tlv(b"\xA0", other.other(4))))
        self.assertEqual(self.engine.accept_result(other.eid, listed).acknowledgements, [4])
        self.assertEqual(self.engine.forward_notifications(other.eid, sender=self.receiver), [])
        row = self.engine.notifications(other.eid)[0]
        self.assertEqual((row["state"], row["waiting"]), (outbox.STATE_PENDING, outbox.MISSING_EUICC_CERTIFICATE))
        self.engine.apply_card_reads(other.eid, {"euicc_certificate": other.certificate,
                                                 "eum_certificate": other.eum_certificate})
        self.assertTrue(self.engine.forward_notifications(other.eid, sender=self.receiver)[0].delivered)
        self.assertEqual(self.receiver.hosts, [RECEIVER])

    def test_octets_that_do_not_read_fail_at_once_and_are_never_sent(self) -> None:
        accepted = self.take(codec.tlv(b"\x30", codec.tlv(b"\xBF\x2F", codec.integer_tlv(b"\x80", 5))))[0]
        self.assertEqual(accepted.acknowledgements, [5])
        self.assertIn("taken, cannot be sent", accepted.messages[0])
        self.assertEqual(self.states(), {5: outbox.STATE_FAILED})
        self.assertEqual(self.forward(), [])
        self.assertEqual(self.forward(seq_numbers=[5])[0].result, outbox.STATE_FAILED)
        self.assertEqual(self.receiver.calls, [])

    def test_a_compact_installation_result_outside_its_download_session_fails_at_once(self) -> None:
        compact_result = codec.tlv(b"\xA0", codec.tlv(b"\xA0", codec.tlv(b"\x80", bytes(16)) + codec.integer_tlv(b"\x02", 10)
                                                      + codec.tlv(b"\xA2", codec.tlv(b"\xA0", b"")))
                                   + codec.tlv(b"\x5F\x37", bytes(64)))
        self.take(compact_result)
        entry = self.entry(10)
        self.assertEqual((entry["state"], entry["reason"]), (outbox.STATE_FAILED, outbox.COMPACT_RESULT))
        self.assertEqual(self.forward(), [])
        self.assertEqual(self.forward(seq_numbers=[10])[0].result, outbox.STATE_FAILED)
        self.assertEqual(self.receiver.calls, [])

    def test_a_notification_taken_before_the_eim_forwarded_any_leaves_only_when_named(self) -> None:
        # What every store written before this code holds: an entry without a state.
        record = self.engine.record(self.eid)
        record.data["notifications"] = [{"at": "2026-10-30T08:00:00+00:00", "seq_number": 3,
                                         "hex": self.euicc.other(3, "enable").hex().upper()}]
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        self.assertEqual(self.states(), {3: outbox.STATE_KEPT})
        # Stored without its facts: the list reads them from the octets, and writes nothing back.
        row = self.engine.notifications(self.eid)[0]
        self.assertEqual((row["event"], row["address"], row["iccid"]), ("enable", RECEIVER, ICCID))
        self.assertEqual(row["text"], f"     3  enable   for {RECEIVER}, ICCID {ICCID}: kept (taken before the eIM "
                                      "forwarded Notifications)")
        self.assertNotIn("event", self.entry(3))
        self.assertEqual(self.forward(), [])
        self.assertEqual(self.forward(explicit=True), [])
        self.assertEqual(self.receiver.calls, [])
        self.assertIn("kept (taken before the eIM forwarded Notifications)", self.engine.notifications(self.eid)[0]["text"])
        outcome = self.forward(seq_numbers=[3])[0]
        self.assertTrue(outcome.delivered)
        self.assertEqual(self.receiver.hosts, [RECEIVER])
        self.assertEqual(self.states(), {3: outbox.STATE_DELIVERED})

    def test_one_an_earlier_version_held_is_kept_with_its_reason_and_leaves_only_when_named(self) -> None:
        record = self.engine.record(self.eid)
        record.data["notifications"] = [{"at": "2026-11-16T08:00:00+00:00", "seq_number": 3, "state": outbox.LEGACY_HELD,
                                         "reason": "held by the operator", "kind": outbox.KIND_OTHER, "event": "enable",
                                         "address": RECEIVER, "hex": self.euicc.other(3, "enable").hex().upper()}]
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        row = self.engine.notifications(self.eid)[0]
        self.assertEqual((row["state"], row["reason"]), (outbox.STATE_KEPT, "held by the operator"))
        self.assertTrue(row["text"].endswith(": kept (held by an earlier version: held by the operator)"), row["text"])
        self.assertEqual(self.forward(), [])
        self.assertEqual(self.forward(explicit=True), [])
        self.assertTrue(self.forward(seq_numbers=[3])[0].delivered)
        self.assertEqual(self.states(), {3: outbox.STATE_DELIVERED})

    def test_at_the_cap_the_delivered_ones_make_room_first(self) -> None:
        self.take(self.euicc.other(1), self.euicc.other(2))
        self.forward(seq_numbers=[1])
        self.take(*(self.euicc.other(number) for number in range(3, RECORD_NOTIFICATION_CAP + 2)))
        states = self.states()
        self.assertEqual(len(states), RECORD_NOTIFICATION_CAP)
        self.assertNotIn(1, states)
        self.assertEqual(states[2], outbox.STATE_PENDING)
        self.assertEqual(outbox.bounded([{"state": "pending", "seq_number": 1}, {"state": "delivered", "seq_number": 2},
                                         {"seq_number": 3}], 2),
                         [{"state": "pending", "seq_number": 1}, {"seq_number": 3}])
        self.assertEqual([entry["seq_number"] for entry in
                          outbox.bounded([{"seq_number": number, "state": "pending"} for number in range(5)], 3)],
                         [2, 3, 4])
        # What the eIM still owes a receiver is the last to go: delivered, kept, failed, then pending.
        mixed = [{"seq_number": 1, "state": "pending"}, {"seq_number": 2, "state": "failed"}, {"seq_number": 3},
                 {"seq_number": 4, "state": "delivered"}, {"seq_number": 5, "state": "pending"}]
        self.assertEqual([[entry["seq_number"] for entry in outbox.bounded(list(mixed), cap)] for cap in (4, 3, 2, 1)],
                         [[1, 2, 3, 5], [1, 2, 5], [1, 5], [5]])


class ForwardTests(OutboxTestBase):
    def test_each_receiver_gets_its_notifications_in_sequence_order_and_whole(self) -> None:
        first, second = self.euicc.other(9, "enable"), self.euicc.other(7, "disable")
        elsewhere = self.euicc.other(8, "delete", OTHER_RECEIVER)
        self.take(first, second, elsewhere)
        outcomes = self.forward()
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in outcomes],
                         [(7, outbox.STATE_DELIVERED), (9, outbox.STATE_DELIVERED), (8, outbox.STATE_DELIVERED)])
        self.assertEqual(self.receiver.calls, [(RECEIVER, second), (RECEIVER, first), (OTHER_RECEIVER, elsewhere)])
        self.assertEqual(set(self.states().values()), {outbox.STATE_DELIVERED})
        self.assertEqual(self.entry(7)["delivered_at"], START.isoformat())
        self.assertEqual(outcomes[0].line(), f"Notification 7 (disable) of {self.eid}: delivered to {RECEIVER}")
        self.assertEqual(self.forward(explicit=True), [])

    def test_a_compact_notification_goes_out_in_its_full_form(self) -> None:
        self.take(self.euicc.compact_other(7, "disable"))
        self.assertTrue(self.forward()[0].delivered)
        host, sent = self.receiver.calls[0]
        self.assertEqual(host, RECEIVER)
        self.assertEqual(sent[:1], b"\x30")
        self.assertTrue(sent.endswith(self.euicc.certificate + self.euicc.eum_certificate))
        self.assertEqual(outbox.unverified(outbox.read(sent), self.euicc.certificate), "")

    def test_a_profile_installation_result_outside_a_relayed_download_goes_to_its_address(self) -> None:
        result = self.euicc.installation_result(7)
        self.take(result)
        self.assertTrue(self.forward()[0].delivered)
        self.assertEqual(self.receiver.calls, [(RECEIVER, result)])

    def test_a_notification_signed_by_another_key_is_never_sent(self) -> None:
        forger = SigningEuicc(self.eid)
        self.take(forger.other(7, "enable", "collector.example.test"))
        outcome = self.forward()[0]
        self.assertEqual(outcome.result, outbox.STATE_FAILED)
        self.assertIn("the eUICC signature does not verify", outcome.text)
        self.assertEqual(self.receiver.calls, [])
        self.assertEqual(self.states(), {7: outbox.STATE_FAILED})
        # Named by the operator it is judged again, by the same rule.
        self.assertEqual(self.forward(seq_numbers=[7])[0].result, outbox.STATE_FAILED)
        self.assertEqual(self.receiver.calls, [])

    def test_an_address_that_is_no_host_name_is_never_sent_to(self) -> None:
        for number, address in enumerate(("https://collector.example.test/x", "198.51.100.7", "collector.example.test:8443",
                                          "localhost"), start=1):
            self.take(self.euicc.other(number, "enable", address))
        outcomes = self.forward()
        self.assertEqual([outcome.result for outcome in outcomes], [outbox.STATE_FAILED] * 4)
        for outcome in outcomes:
            self.assertIn("is no host name", outcome.text)
        self.assertEqual(self.receiver.calls, [])

    def test_without_a_certificate_on_record_a_notification_waits_for_one(self) -> None:
        other = SigningEuicc("89049032123451234512345678901250")
        self.engine.register(other.eid)
        self.engine.accept_notification(other.eid, other.other(4))
        self.engine.accept_notification(other.eid, other.other(5))
        # An automatic pass leaves it as it is and counts no attempt.
        self.assertEqual(self.engine.forward_notifications(other.eid, sender=self.receiver), [])
        row = self.engine.notifications(other.eid)[0]
        self.assertEqual((row["state"], row["attempts"], row["waiting"]),
                         (outbox.STATE_PENDING, 0, outbox.MISSING_EUICC_CERTIFICATE))
        self.assertIn("pending; waits for the eUICC certificate", row["text"])
        # Named, it says why it does not go, and nothing changes on the entry.
        outcomes = self.engine.forward_notifications(other.eid, seq_numbers=[4, 5], sender=self.receiver)
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in outcomes], [(4, outbox.RESULT_WAITING)])
        self.assertIn("waits for the eUICC certificate", outcomes[0].text)
        self.assertFalse(outcomes[0].problem)
        self.assertEqual(self.receiver.calls, [])
        entry = outbox.find(self.engine.record(other.eid), 4)
        self.assertEqual((outbox.state_of(entry), entry["attempts"]), (outbox.STATE_PENDING, 0))
        self.assertNotIn("sender", entry)
        # The first pass after a card read sends both, in order.
        self.engine.apply_card_reads(other.eid, {"euicc_certificate": other.certificate,
                                                 "eum_certificate": other.eum_certificate})
        sent = self.engine.forward_notifications(other.eid, sender=self.receiver)
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in sent],
                         [(4, outbox.STATE_DELIVERED), (5, outbox.STATE_DELIVERED)])

    def test_a_compact_notification_waits_for_the_eum_certificate_its_full_form_carries(self) -> None:
        other = SigningEuicc("89049032123451234512345678901250")
        self.engine.register(other.eid)
        self.engine.apply_card_reads(other.eid, {"euicc_certificate": other.certificate})
        self.engine.accept_notification(other.eid, other.compact_other(6))
        self.assertEqual(self.engine.forward_notifications(other.eid, sender=self.receiver), [])
        self.assertEqual(self.engine.notifications(other.eid)[0]["waiting"], outbox.MISSING_EUM_CERTIFICATE)
        self.engine.apply_card_reads(other.eid, {"eum_certificate": other.eum_certificate})
        self.assertTrue(self.engine.forward_notifications(other.eid, sender=self.receiver)[0].delivered)

    def test_a_receiver_that_is_down_is_tried_again_on_a_schedule_and_keeps_the_order(self) -> None:
        self.receiver.fail(RECEIVER, "connection refused")
        self.take(self.euicc.other(7), self.euicc.other(9), self.euicc.other(8, "delete", OTHER_RECEIVER))
        outcomes = self.forward()
        # The first failure ends that receiver's turn; the other receiver is served.
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in outcomes],
                         [(7, outbox.RESULT_RETRY), (8, outbox.STATE_DELIVERED)])
        self.assertEqual(self.receiver.hosts, [RECEIVER, OTHER_RECEIVER])
        entry = self.entry(7)
        self.assertEqual((entry["state"], entry["attempts"], entry["last_error"]),
                         (outbox.STATE_PENDING, 1, "connection refused"))
        self.assertEqual(entry["next_attempt_at"], (START + datetime.timedelta(seconds=60)).isoformat())
        self.assertIn("next attempt at", outcomes[0].text)
        # Before the next attempt is due nothing goes, the later Notification included.
        self.later(59)
        self.assertEqual(self.forward(), [])
        self.assertEqual(len(self.receiver.calls), 2)
        self.receiver.recover(RECEIVER)
        self.later(1)
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in self.forward()],
                         [(7, outbox.STATE_DELIVERED), (9, outbox.STATE_DELIVERED)])
        self.assertEqual(self.entry(7)["attempts"], 2)
        self.assertNotIn("next_attempt_at", self.entry(7))

    def test_the_operator_can_send_before_the_next_attempt_is_due(self) -> None:
        self.receiver.fail(RECEIVER)
        self.take(self.euicc.other(7))
        self.forward()
        self.receiver.recover(RECEIVER)
        self.assertEqual(self.forward(), [])
        self.assertTrue(self.forward(explicit=True)[0].delivered)

    def test_after_the_last_attempt_a_notification_has_failed(self) -> None:
        self.receiver.fail(RECEIVER, "timed out")
        self.take(self.euicc.other(7))
        results = []
        for _attempt in range(len(outbox.RETRY_DELAYS_S) + 1):
            results.append(self.forward()[0].result)
            self.later(max(outbox.RETRY_DELAYS_S) + 1)
        self.assertEqual(results, [outbox.RESULT_RETRY] * len(outbox.RETRY_DELAYS_S) + [outbox.STATE_FAILED])
        entry = self.entry(7)
        self.assertEqual(entry["state"], outbox.STATE_FAILED)
        self.assertEqual(entry["reason"], f"not delivered after {len(outbox.RETRY_DELAYS_S) + 1} attempts, last: timed out")
        self.assertEqual(self.forward(), [])
        # The operator's Send of a failed one is one attempt: while the receiver is down it stays failed,
        # and nothing puts it back on the schedule.
        again = self.forward(seq_numbers=[7])[0]
        self.assertEqual(again.result, outbox.STATE_FAILED)
        entry = self.entry(7)
        self.assertEqual((entry["state"], entry["reason"], entry["attempts"]),
                         (outbox.STATE_FAILED, "timed out", len(outbox.RETRY_DELAYS_S) + 2))
        self.assertNotIn("next_attempt_at", entry)
        self.later(max(outbox.RETRY_DELAYS_S) + 1)
        self.assertEqual(self.forward(), [])
        self.assertEqual(len(self.receiver.calls), len(outbox.RETRY_DELAYS_S) + 2)
        self.receiver.recover(RECEIVER)
        self.assertTrue(self.forward(seq_numbers=[7])[0].delivered)

    def test_a_receiver_that_refuses_one_notification_still_gets_the_next(self) -> None:
        self.take(self.euicc.other(7), self.euicc.other(9))
        calls: list[int] = []

        def sender(_host: str, notification: bytes) -> None:
            number = outbox.read(notification).seq_number
            calls.append(number)
            if number == 7:
                raise outbox.Undelivered(f"{RECEIVER} answered HTTP 404", retry=False)

        outcomes = self.engine.forward_notifications(sender=sender)
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in outcomes],
                         [(7, outbox.STATE_FAILED), (9, outbox.STATE_DELIVERED)])
        self.assertEqual(calls, [7, 9])
        entry = self.entry(7)
        self.assertEqual((entry["reason"], entry["attempts"]), (f"{RECEIVER} answered HTTP 404", 1))
        # Failed is final: no pass tries it again, however late; only its own Send does.
        self.later(max(outbox.RETRY_DELAYS_S) + 1)
        self.assertEqual(self.engine.forward_notifications(sender=sender), [])
        self.assertEqual(self.engine.forward_notifications(sender=sender, explicit=True), [])
        self.assertEqual(calls, [7, 9])
        sent = self.engine.forward_notifications(seq_numbers=[7], sender=lambda _host, _octets: None)
        self.assertTrue(sent[0].delivered)
        self.assertNotIn("reason", self.entry(7))

    def test_a_named_send_of_a_refused_one_that_misses_again_stays_failed(self) -> None:
        self.take(self.euicc.other(7))
        self.receiver.fail(RECEIVER, f"{RECEIVER} answered HTTP 403", retry=False)
        self.assertEqual(self.forward()[0].result, outbox.STATE_FAILED)
        self.receiver.fail(RECEIVER, "connection refused")
        self.assertEqual(self.forward(seq_numbers=[7])[0].result, outbox.STATE_FAILED)
        entry = self.entry(7)
        self.assertEqual((entry["state"], entry["reason"], entry["attempts"]),
                         (outbox.STATE_FAILED, "connection refused", 2))
        self.assertNotIn("next_attempt_at", entry)

    def test_two_senders_at_once_send_a_notification_once(self) -> None:
        self.take(self.euicc.other(7))
        inside, release = threading.Event(), threading.Event()
        calls: list[str] = []

        def slow(host: str, _notification: bytes) -> None:
            calls.append(host)
            inside.set()
            self.assertTrue(release.wait(10))

        first: list = []
        worker = threading.Thread(target=lambda: first.extend(self.engine.forward_notifications(sender=slow)))
        worker.start()
        self.assertTrue(inside.wait(10))
        second = self.engine.forward_notifications(sender=slow)
        self.assertEqual([(outcome.seq_number, outcome.result) for outcome in second], [(7, outbox.RESULT_BUSY)])
        release.set()
        worker.join(10)
        self.assertEqual(calls, [RECEIVER])
        self.assertTrue(first[0].delivered)
        self.assertEqual(self.forward(explicit=True), [])

    def test_a_sender_that_died_frees_its_notification_after_a_while(self) -> None:
        self.take(self.euicc.other(7))
        record = self.engine.record(self.eid)
        entry = outbox.find(record, 7)
        entry["sending_since"], entry["sender"] = START.isoformat(), "4242-1"
        with self.engine.store.transaction() as connection:
            self.engine.store.save_record(record, connection)
        self.later(outbox.CLAIM_S - 1)
        self.assertEqual(self.forward()[0].result, outbox.RESULT_BUSY)
        self.later(2)
        self.assertTrue(self.forward()[0].delivered)
        self.assertNotIn("sender", self.entry(7))

    def test_the_rows_an_operator_reads_carry_no_octets(self) -> None:
        self.receiver.fail(RECEIVER)
        self.take(self.euicc.other(7, "disable"))
        self.forward()
        row = self.engine.notifications(self.eid)[0]
        self.assertNotIn("hex", row)
        self.assertEqual(row["eid"], self.eid)
        self.assertEqual(row["text"], f"     7  disable  for {RECEIVER}, ICCID {ICCID}: pending, 1 attempt(s), last: "
                                      f"connection refused; next at {(START + datetime.timedelta(seconds=60)).isoformat()}")
        self.assertEqual(outbox.counts(self.engine.record(self.eid))[outbox.STATE_PENDING], 1)


class _Client:
    """Stands where the ES9+ client is built: records the call and answers as told."""

    built: list["_Client"] = []
    answer: object = 204

    def __init__(self, base_url: str, timeout_seconds: int = 0) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.requests: list = []
        self.last_http_status: int | None = None
        type(self).built.append(self)

    def handle_notification(self, request) -> dict:
        self.requests.append(request)
        answer = type(self).answer
        if isinstance(answer, BaseException):
            raise answer
        self.last_http_status = int(answer)
        return {}


def _http_error(status: int) -> OSError:
    error = OSError(f"ES9 request failed: HTTP Error {status}")
    error.__cause__ = urllib.error.HTTPError("https://smdp.operator.invalid", status, "refused", None, io.BytesIO(b""))
    return error


class ReceiverSenderTests(OutboxTestBase):
    """The sender a store uses when none is given: which receiver gets a call, and what its answer means."""

    def setUp(self) -> None:
        super().setUp()
        _Client.built = []
        _Client.answer = 204
        patch = mock.patch("SCP11.live.es9_client.Es9LikeClient", _Client)
        patch.start()
        self.addCleanup(patch.stop)
        self.smdp = mock.Mock(spec=LocalSmdp)
        self.smdp.host.return_value = "smdpp.yggdrasim.local"
        self.smdp.handle.return_value = {}
        self.send = outbox.receiver_sender(self.engine, self.smdp)

    def test_the_store_s_own_sm_dp_plus_is_answered_in_process(self) -> None:
        notification = self.euicc.other(7, "enable", "smdpp.yggdrasim.local")
        self.send("smdpp.yggdrasim.local", notification)
        path, payload = self.smdp.handle.call_args.args
        self.assertEqual(path, "/gsma/rsp2/es9plus/handleNotification")
        self.assertEqual(base64.b64decode(payload["pendingNotification"]), notification)
        self.assertEqual(_Client.built, [])

    def test_a_reserved_or_local_name_is_never_contacted(self) -> None:
        for host in ("rsp.example.com", "smdp.example.test", "other.yggdrasim.local", "smdp.invalid"):
            with self.assertRaises(outbox.Undelivered) as refusal:
                self.send(host, self.euicc.other(7))
            self.assertFalse(refusal.exception.retry)
            self.assertIn("reserved or local name", str(refusal.exception))
        self.assertEqual(_Client.built, [])
        self.smdp.handle.assert_not_called()

    def test_another_receiver_is_called_over_https_at_its_own_name(self) -> None:
        notification = self.euicc.other(7)
        self.send(ORDINARY_HOST, notification)
        client = _Client.built[0]
        self.assertEqual((client.base_url, client.timeout_seconds), (f"https://{ORDINARY_HOST}", outbox.SEND_TIMEOUT_S))
        request = client.requests[0]
        self.assertEqual(request.smdp_address, ORDINARY_HOST)
        self.assertEqual(base64.b64decode(request.pending_notification), notification)

    def test_only_a_2xx_answer_says_the_receiver_has_it(self) -> None:
        # SGP.22 v3.1 §3.5 step 10: removal upon 204, never upon 5XX; a 4XX is the receiver's refusal.
        for answer, retry in ((302, True), (_http_error(503), True), (OSError("timed out"), True),
                              (_http_error(404), False), (_http_error(400), False)):
            _Client.answer = answer
            with self.assertRaises(outbox.Undelivered, msg=str(answer)) as failure:
                self.send(ORDINARY_HOST, self.euicc.other(7))
            self.assertEqual(failure.exception.retry, retry, str(answer))
        for answer in (204, 200):
            _Client.answer = answer
            self.send(ORDINARY_HOST, self.euicc.other(7))

    def test_a_pass_without_a_sender_uses_the_store_s_own(self) -> None:
        self.take(self.euicc.other(7, "enable", "rsp.example.com"))
        outcome = self.engine.forward_notifications()[0]
        self.assertEqual(outcome.result, outbox.STATE_FAILED)
        self.assertIn("reserved or local name", outcome.text)
        self.assertFalse(outcome.problem)
        self.assertEqual(_Client.built, [])


class SimulatedCardTests(unittest.TestCase):
    """The direct route on the simulated eUICC: its own Notifications, signed with its own key."""

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.engine = LocalEim(Path(folder.name))
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        self.receiver = Receiver()

    def run_queue(self, *requests: tuple[str, str]) -> list:
        self.engine.submit([OperationRequest(eid=self.card.eid, type=kind, params={"iccid": iccid})
                            for kind, iccid in requests])
        return deliver(self.engine, self.card.exchange, self.card.eid, reset=lambda: True)

    def test_a_disable_and_an_enable_leave_two_notifications_that_reach_their_receiver(self) -> None:
        steps = self.run_queue(("DISABLE_PROFILE", ENABLED), ("ENABLE_PROFILE", DISABLED))
        self.assertEqual([step.messages[-1] for step in steps],
                         ["notification 1 for rsp.example.com taken", "notification 3 for rsp.example.com taken"])
        # Acknowledged, so the eUICC holds none of them any more.
        self.assertEqual(codec.decode_notification_list(
            self.card.exchange(codec.build_retrieve_notifications_request())), [])
        rows = self.engine.notifications(self.card.eid)
        self.assertEqual([(row["seq_number"], row["event"], row["iccid"], row["state"], row["route"]) for row in rows],
                         [(1, "disable", ENABLED, "pending", ROUTE_DIRECT), (3, "enable", DISABLED, "pending", ROUTE_DIRECT)])
        outcomes = self.engine.forward_notifications(sender=self.receiver)
        self.assertEqual([outcome.result for outcome in outcomes], [outbox.STATE_DELIVERED] * 2)
        self.assertEqual(self.receiver.hosts, ["rsp.example.com", "rsp.example.com"])
        for _host, sent in self.receiver.calls:
            self.assertEqual(outbox.unverified(outbox.read(sent), self.engine.record(self.card.eid).euicc_certificate), "")

    def test_the_store_s_own_sender_contacts_nobody_for_the_simulator_s_test_address(self) -> None:
        self.run_queue(("DISABLE_PROFILE", ENABLED))
        with mock.patch("SCP11.live.es9_client.Es9LikeClient", side_effect=AssertionError("a receiver was contacted")):
            outcome = self.engine.forward_notifications()[0]
        self.assertEqual(outcome.result, outbox.STATE_FAILED)


class EsipaTests(OutboxTestBase):
    def post(self, notification: bytes) -> tuple[int, bytes, Verdict]:
        verdict = Verdict()
        status, answer = handle_asn1(self.engine, esipa_download.encode_handle_notification(notification),
                                     verdict=verdict)
        return int(status), answer, verdict

    def test_handle_notification_puts_it_on_the_record_of_the_euicc_that_signed_it(self) -> None:
        for number, notification in enumerate((self.euicc.other(7), self.euicc.compact_other(8),
                                               self.euicc.compact_other(9, with_eid=False),
                                               self.euicc.installation_result(10)), start=1):
            status, answer, verdict = self.post(notification)
            self.assertEqual((status, answer), (204, b""))
            self.assertEqual((verdict.eid, verdict.notifications), (self.eid, 1), number)
            self.assertIn("taken", verdict.note)
        self.assertEqual(self.states(), {7: "pending", 8: "pending", 9: "pending", 10: "pending"})
        self.assertEqual(len(self.forward()), 4)
        self.assertEqual(self.receiver.hosts, [RECEIVER] * 4)

    def test_a_notification_no_record_s_certificate_verifies_is_not_taken(self) -> None:
        forger = SigningEuicc(self.eid)
        for notification in (forger.other(7, "enable", "collector.example.test"),
                             forger.compact_other(8, "enable", "collector.example.test")):
            status, answer, verdict = self.post(notification)
            self.assertEqual((status, answer), (204, b""))
            self.assertEqual(verdict.note, "notification signed by no eUICC on record: not taken")
            self.assertEqual((verdict.eid, verdict.notifications), ("", 0))
        self.assertEqual(self.engine.notifications(), [])
        self.assertEqual(self.forward(explicit=True), [])
        self.assertEqual(self.receiver.calls, [])

    def test_the_eid_a_compact_notification_names_does_not_decide_whose_it_is(self) -> None:
        other = SigningEuicc("89049032123451234512345678901250")
        self.engine.register(other.eid)
        self.engine.apply_card_reads(other.eid, {"euicc_certificate": other.certificate,
                                                 "eum_certificate": other.eum_certificate})
        # Signed by the second eUICC, naming the first one's EID.
        metadata = other.metadata(5, "enable", RECEIVER)
        claimed = codec.tlv(b"\xA1", codec.tlv(b"\x5A", bytes.fromhex(self.eid)) + metadata
                            + codec.tlv(b"\x5F\x37", other.sign(metadata)))
        _status, _answer, verdict = self.post(claimed)
        self.assertEqual(verdict.eid, other.eid)
        self.assertEqual(self.engine.notifications(self.eid), [])

    def test_certificates_of_an_ipa_data_response_nobody_asked_for_are_not_taken(self) -> None:
        forger = SigningEuicc(self.eid)
        unasked = codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", retag_sequence(b"\xA6", forger.certificate)))
        accepted = self.engine.accept_result(self.eid, unasked)
        self.assertIn("certificates of an IPA data response no operation asked for were not taken", accepted.messages)
        self.assertEqual(self.engine.record(self.eid).euicc_certificate, self.euicc.certificate)
        # So a Notification under the forger's key still finds no owner.
        self.assertEqual(self.engine.notification_owner(forger.other(7)), "")
        # The answer to an operation this eIM queued is taken.
        operation = self.engine.submit([OperationRequest(eid=self.eid, type="IPA_EUICC_DATA", params={})])[0]
        self.engine.next_package(self.eid)
        self.engine.accept_result(self.eid, unasked, operation_id=operation.id)
        self.assertEqual(self.engine.record(self.eid).euicc_certificate, forger.certificate)


class ServiceTests(OutboxTestBase):
    def test_a_listener_without_a_forwarder_takes_and_sends_nothing(self) -> None:
        server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=LocalSmdp(self.directory))
        self.addCleanup(server.server_close)
        self.assertIsNone(server.forwarder)
        server.notifications_taken(Verdict(notifications=2))

    def test_the_forwarder_sends_when_it_is_woken_and_stops_when_told(self) -> None:
        lines: list[str] = []
        delivered = threading.Event()

        def sender(host: str, notification: bytes) -> None:
            self.receiver(host, notification)
            delivered.set()

        forwarder = outbox.Forwarder(self.engine, sender, log=lines.append, tick_s=3600)
        forwarder.start()
        self.addCleanup(forwarder.stop)
        server = LocalEimHttpServer(self.engine, ("127.0.0.1", 0), smdp=LocalSmdp(self.directory))
        self.addCleanup(server.server_close)
        server.forwarder = forwarder
        self.take(self.euicc.other(7))
        server.notifications_taken(Verdict(notifications=0))
        self.assertFalse(delivered.wait(0.3))
        server.notifications_taken(Verdict(notifications=1))
        self.assertTrue(delivered.wait(10))
        forwarder.stop()
        self.assertEqual(self.receiver.hosts, [RECEIVER])
        self.assertEqual(lines, [f"Notification 7 (enable) of {self.eid}: delivered to {RECEIVER}"])

    def test_a_hold_rule_an_earlier_version_stored_stops_nothing(self) -> None:
        self.engine.store.set_setting("notification_forwarding", "hold")
        self.take(self.euicc.other(7))
        self.assertEqual(self.entry(7)["state"], outbox.STATE_PENDING)
        self.assertEqual(len(outbox.Forwarder(self.engine, self.receiver).run_once()), 1)
        self.assertEqual(self.receiver.hosts, [RECEIVER])

    def test_a_pass_that_fails_does_not_end_the_forwarder(self) -> None:
        lines: list[str] = []
        woke = threading.Event()

        def log(line: str) -> None:
            lines.append(line)
            woke.set()

        forwarder = outbox.Forwarder(self.engine, self.receiver, log=log, tick_s=3600)
        # A store another process holds raises sqlite3.OperationalError, which is no OSError.
        with mock.patch.object(outbox, "forward", side_effect=[OSError("disk full"),
                                                               sqlite3.OperationalError("database is locked")]):
            forwarder.start()
            self.addCleanup(forwarder.stop)
            forwarder.kick()
            self.assertTrue(woke.wait(10))
            woke.clear()
            forwarder.kick()
            self.assertTrue(woke.wait(10))
        self.assertEqual(lines, ["notification forwarding pass failed: OSError: disk full",
                                 "notification forwarding pass failed: OperationalError: database is locked"])
        woke.clear()
        self.take(self.euicc.other(7))
        forwarder.kick()
        self.assertTrue(woke.wait(10))
        self.assertIn("delivered", lines[-1])


if __name__ == "__main__":
    unittest.main()
