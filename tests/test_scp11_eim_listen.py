# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EIM-LISTEN: the IPAd takes injected eIM Packages (SGP.32 v1.3 §5.14.4).

The orchestrator entry is run with its card steps replaced, over real HTTP on
the loopback; the console verb is checked for what it registers and passes on.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from SCP11.live import console as live_console
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.live.transfer_provider import DEFAULT_PORT, TransferListener
from SCP11.shared import esipa_transfer as transfer
from tests.test_scp11_orchestrator import TEST_EID, FakeApduChannel, FakeCfg, FakeProvider

RESULT = bytes.fromhex("BF511AA218801065696D2E6578616D706C652E746573748204A1A2A3A4")
PACKAGE = bytes.fromhex("BF51023000")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _orchestrator() -> SGP22Orchestrator:
    return SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=FakeProvider(bpp_bytes=b""))


class InjectedPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orchestrator = _orchestrator()
        self.relayed: list[dict] = []
        self.card_answer = RESULT

        def relay(package: bytes, **arguments: object) -> bytes:
            self.relayed.append({"package": package, **arguments})
            return self.card_answer

        self.orchestrator._relay_eim_package_to_card = relay

    def run_package(self, package: bytes = PACKAGE) -> bytes:
        with contextlib.redirect_stdout(io.StringIO()):
            return self.orchestrator._run_injected_eim_package(package)

    def test_the_result_is_the_alternative_an_eim_package_result_carries(self) -> None:
        self.assertEqual(self.run_package(), RESULT)
        self.assertEqual(self.run_package(), RESULT)
        self.assertEqual(
            [(call["package"], call["poll_round"], call["package_index"], call["source"]) for call in self.relayed],
            [(PACKAGE, 0, 1, "injected by the eIM"), (PACKAGE, 0, 2, "injected by the eIM")],
        )

    def test_a_card_answer_that_is_no_result_is_reported_as_on_the_poll_route(self) -> None:
        # eimPackageResultResponseError invalidPackageFormat(1), SGP.32 v1.3 §6.3.2.7.
        self.card_answer = bytes.fromhex("6A80")
        self.assertEqual(self.run_package(), bytes.fromhex("A003020101"))

    def test_no_card_answer_is_an_error_for_the_listener_to_report(self) -> None:
        self.card_answer = b""
        with self.assertRaises(RuntimeError):
            self.run_package()

    def test_the_relay_names_an_injected_package_as_such(self) -> None:
        answer = bytes.fromhex("CA0100")

        class Channel(FakeApduChannel):
            def send(self, apdu, log_name, *arguments, **options):
                answered = super().send(apdu, log_name, *arguments, **options)
                return answer if log_name.startswith("EIM: InjectedPackage") else answered

        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=Channel(),
                                         profile_provider=FakeProvider(bpp_bytes=b""))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            response = orchestrator._relay_eim_package_to_card(
                bytes.fromhex("CA0401020304"), poll_round=0, package_index=3, source="injected by the eIM")
        self.assertEqual(response, answer)
        self.assertIn("[*] Relaying eIM package 3 injected by the eIM: tag=CA len=6", output.getvalue())
        self.assertNotIn("poll round", output.getvalue())
        names = [name for name, _apdu in orchestrator.apdu_channel.send_calls]
        self.assertTrue(any(name.startswith("EIM: InjectedPackage [package=3]") for name in names), names)


def _tlv(tag: str, value: bytes) -> bytes:
    length = len(value)
    encoded = bytes([length]) if length < 0x80 else bytes([0x81, length]) if length < 0x100 else b"\x82" + length.to_bytes(2, "big")
    return bytes.fromhex(tag) + encoded + value


# NotificationMetadata (SGP.22 v3.1 §5.7.10): seqNumber 7, a disable event, its SM-DP+ and ICCID.
NOTIFICATION_METADATA = _tlv("BF2F", _tlv("80", b"\x07") + _tlv("81", bytes.fromhex("0520"))
                             + _tlv("0C", b"rsp.example.test") + _tlv("5A", bytes.fromhex("98882143658709214365")))
PENDING_NOTIFICATION = _tlv("30", NOTIFICATION_METADATA + _tlv("5F37", b"\x22" * 64))
NOTIFICATION_LIST = _tlv("BF28", _tlv("A0", NOTIFICATION_METADATA))
NOTIFICATION_RETRIEVED = _tlv("BF2B", _tlv("A0", PENDING_NOTIFICATION))


class KeptNotificationTests(unittest.TestCase):
    """notifications=keep: the sync that follows every injected package reads and delivers nothing."""

    def setUp(self) -> None:
        self.channel = FakeApduChannel(notification_list_response=NOTIFICATION_LIST,
                                       notification_retrieve_response=NOTIFICATION_RETRIEVED)
        self.provider = FakeProvider(bpp_bytes=b"")
        self.orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=self.channel, profile_provider=self.provider)

    def sync(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.orchestrator._sync_pending_notifications()
        return output.getvalue()

    def card_commands(self) -> list[str]:
        return [name for name, _apdu in self.channel.send_calls] + [str(call) for call in self.channel.chunked_calls]

    def test_by_default_a_pending_notification_goes_to_its_sm_dp(self) -> None:
        self.sync()
        self.assertEqual(len(self.provider.handle_notification_calls), 1)
        self.assertTrue(any("RemoveNotificationFromList" in name for name in self.card_commands()), self.card_commands())

    def test_held_it_stays_on_the_card_and_nothing_is_read_or_sent(self) -> None:
        self.orchestrator._notification_sync_held = True
        printed = self.sync()
        self.assertEqual(self.provider.handle_notification_calls, [])
        self.assertEqual(self.card_commands(), [])
        # Nothing was read, so nothing may be taken as delivered.
        self.assertIsNone(self.orchestrator._last_notification_sync_succeeded)
        self.assertIn("left out (notifications=keep)", printed)

    def test_the_hold_lasts_for_the_listening_and_no_longer(self) -> None:
        seen: list[bool] = []
        orchestrator = self.orchestrator
        orchestrator._phase_connect = lambda: None
        orchestrator._read_card_eid = lambda reselect_isdr=True: TEST_EID
        orchestrator._close_es10b_logical_channel = lambda _scope: None

        def serve(_listener: TransferListener, **_options: object) -> int:
            seen.append(orchestrator._notification_sync_held)
            return 0

        for keep in (True, False):
            with mock.patch.object(TransferListener, "serve", serve), contextlib.redirect_stdout(io.StringIO()) as output:
                orchestrator.run_eim_listen(port=_free_port(), keep_notifications=keep)
            self.assertFalse(orchestrator._notification_sync_held)
            self.assertEqual("notifications=keep" in output.getvalue(), keep)
        self.assertEqual(seen, [True, False])

    def test_a_failed_start_releases_the_hold(self) -> None:
        self.orchestrator._phase_connect = mock.Mock(side_effect=RuntimeError("no card"))
        self.orchestrator._close_es10b_logical_channel = lambda _scope: None
        with self.assertRaises(RuntimeError):
            self.orchestrator.run_eim_listen(port=_free_port(), keep_notifications=True)
        self.assertFalse(self.orchestrator._notification_sync_held)


class ListenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orchestrator = _orchestrator()
        self.removed: list[int] = []
        self.closed: list[str] = []
        self.connects = 0
        self.eid = TEST_EID

        def connect() -> None:
            self.connects += 1

        self.orchestrator._phase_connect = connect
        self.orchestrator._read_card_eid = lambda reselect_isdr=True: self.eid
        self.orchestrator._relay_eim_package_to_card = lambda package, **_arguments: RESULT
        self.orchestrator._remove_notification_from_list = self.removed.append
        self.orchestrator._close_es10b_logical_channel = self.closed.append

    def listen(self, **options: object) -> tuple[threading.Thread, dict, io.StringIO]:
        outcome: dict = {}
        output = io.StringIO()

        def run() -> None:
            try:
                outcome["calls"] = self.orchestrator.run_eim_listen(**options)  # type: ignore[arg-type]
            except Exception as error:  # noqa: BLE001 - the test reads what was raised
                outcome["error"] = error

        with contextlib.redirect_stdout(output):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "listening on" not in output.getvalue() and thread.is_alive():
                time.sleep(0.02)
        return thread, outcome, output

    def post(self, port: int, body: bytes) -> bytes:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("POST", transfer.PATH_ASN1, body=body, headers={
                "Content-Type": transfer.CONTENT_TYPE_ASN1, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL})
            return connection.getresponse().read()
        finally:
            connection.close()

    def test_calls_are_answered_until_the_stop_and_the_channel_is_closed(self) -> None:
        port = _free_port()
        stop = threading.Event()
        output_sink = io.StringIO()
        with contextlib.redirect_stdout(output_sink):
            thread, outcome, output = self.listen(port=port, stop=stop)
            result = transfer.decode_response(self.post(port, transfer.build_request(PACKAGE)))
            acknowledged = transfer.decode_response(self.post(port, bytes.fromhex("BF4E09BF5306800101800102")))
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome, {"calls": 2})
        self.assertEqual((result.kind, result.result), (transfer.RESULT_EUICC_PACKAGE, RESULT))
        self.assertEqual((acknowledged.kind, acknowledged.eid), (transfer.RECEIVED_WITH_CID, TEST_EID))
        self.assertEqual((self.removed, self.closed, self.connects), ([1, 2], ["EIM"], 1))
        printed = output.getvalue() + output_sink.getvalue()
        self.assertIn(f"listening on http://127.0.0.1:{port} for EID {TEST_EID}.", printed)
        self.assertIn(f"INJECT {TEST_EID} target=http://127.0.0.1:{port}", printed)
        # Nothing listens once the entry returned.
        with self.assertRaises(OSError):
            self.post(port, transfer.build_request(PACKAGE))

    def test_it_ends_by_itself_after_the_calls_or_the_idle_time_given(self) -> None:
        port = _free_port()
        with contextlib.redirect_stdout(io.StringIO()):
            thread, outcome, _output = self.listen(port=port, max_calls=1)
            self.post(port, transfer.build_request(PACKAGE))
            thread.join(timeout=5)
        self.assertEqual(outcome, {"calls": 1})
        with contextlib.redirect_stdout(io.StringIO()):
            thread, outcome, _output = self.listen(port=_free_port(), idle_seconds=0.3)
            thread.join(timeout=5)
        self.assertEqual(outcome, {"calls": 0})
        self.assertEqual(self.closed, ["EIM", "EIM"])

    def test_without_an_eid_nothing_listens(self) -> None:
        self.eid = ""
        port = _free_port()
        with contextlib.redirect_stdout(io.StringIO()):
            thread, outcome, _output = self.listen(port=port)
            thread.join(timeout=5)
        self.assertIsInstance(outcome.get("error"), RuntimeError)
        self.assertEqual(self.closed, ["EIM"])
        with self.assertRaises(OSError):
            self.post(port, transfer.build_request(PACKAGE))

    def test_an_interrupt_ends_the_listening_without_an_error(self) -> None:
        output = io.StringIO()
        with mock.patch.object(TransferListener, "serve", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(output):
                calls = self.orchestrator.run_eim_listen(port=_free_port())
        self.assertEqual((calls, self.closed), (0, ["EIM"]))
        self.assertIn("stopped after 0 call(s).", output.getvalue())

    def test_it_binds_the_loopback_only(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                self.orchestrator.run_eim_listen(host="0.0.0.0", port=_free_port())
        self.assertEqual(self.closed, ["EIM"])


class ConsoleVerbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[dict] = []
        orchestrator = SimpleNamespace(run_eim_listen=lambda **options: self.calls.append(options) or 0)
        client = SimpleNamespace(
            cfg=SimpleNamespace(READER_INDEX=0, READER_NAME="", RSP_SERVER_URL="rsp.example.test",
                                ES9_BASE_URL="https://rsp.example.test", ES9_VERIFY_TLS=True, ES9_CA_BUNDLE_PATH=""),
            apdu_channel=SimpleNamespace(),
            orchestrator=orchestrator,
        )
        self.console = live_console.SCP11Console(client)
        self.console._style = live_console.ConsoleStyle("", "", "", "", "", "", "")

    def run_verb(self, argument: str) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(self.console._cmd_eim_listen(argument))
        return output.getvalue()

    def test_the_verb_holds_the_reader_as_a_long_running_command(self) -> None:
        spec = self.console._commands["EIM-LISTEN"]
        self.assertEqual((spec.session_policy, spec.long_running, spec.runs_own_connect),
                         (live_console.SessionPolicy.HARD_RESET, True, True))
        self.assertEqual(spec.section, self.console.HELP_SECTION_IPAD)
        self.assertIn("EIM-LISTEN", self.console._primary_commands)

    def test_options_reach_the_orchestrator(self) -> None:
        self.run_verb("")
        self.run_verb("port=0 calls=3 idle=2.5")
        self.run_verb("notifications=keep")
        self.run_verb("notifications=DELIVER calls=1")
        plain = {"host": "127.0.0.1", "tls_context": None, "stop": None}
        self.assertEqual(self.calls, [
            {"port": DEFAULT_PORT, "max_calls": None, "idle_seconds": None, "keep_notifications": False, **plain},
            {"port": 0, "max_calls": 3, "idle_seconds": 2.5, "keep_notifications": False, **plain},
            {"port": DEFAULT_PORT, "max_calls": None, "idle_seconds": None, "keep_notifications": True, **plain},
            {"port": DEFAULT_PORT, "max_calls": 1, "idle_seconds": None, "keep_notifications": False, **plain},
        ])
        self.assertEqual(DEFAULT_PORT, 8746)

    def test_other_arguments_are_refused_before_anything_starts(self) -> None:
        for argument in ("8746", "port=", "port=x", "port=70000", "port=-1", "calls=0", "calls=two", "idle=0",
                         "idle=-3", "idle=soon", "host=0.0.0.0", "--debug=1", 'port="8746', "notifications=",
                         "notifications=drop", "notifications"):
            with self.subTest(argument=argument):
                output = self.run_verb(argument)
                self.assertIn(
                    "[!] Usage: EIM-LISTEN [port=<n>] [calls=<n>] [idle=<seconds>] [notifications=deliver|keep]", output)
        self.assertEqual(self.calls, [])

    def test_a_failure_is_printed_and_the_shell_goes_on(self) -> None:
        def fail(**_options: object) -> int:
            raise RuntimeError("the eUICC gave no EID")

        self.console.orchestrator.run_eim_listen = fail
        self.assertIn("[!] EIM-LISTEN failed: the eUICC gave no EID", self.run_verb(""))


if __name__ == "__main__":
    unittest.main()
