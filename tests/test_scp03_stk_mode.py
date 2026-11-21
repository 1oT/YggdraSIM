# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP03 STK mode: the shell keeps working while the transport answers the toolkit."""
from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace

from SCP03.interface.shell import ShellDispatcher
from SCP03.logic.stk import StkController
from SCP03.transport.card import CardTransporter
from yggdrasim_common.stk_terminal import terminal_profile_apdu

# SET UP EVENT LIST (Location status, Data available): 15 bytes, '91 0F'.
_SET_UP_EVENT_LIST = bytes.fromhex("D00D" "8103010500" "82028182" "99020309")
_SELECT_MF = "00A40004023F00"


class _ScriptedConnection:
    """PC/SC stand-in answering from a script, one reply per APDU."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[str] = []

    def transmit(self, apdu):
        self.calls.append(bytes(apdu).hex().upper())
        if len(self.replies) == 0:
            raise AssertionError(f"Unexpected APDU: {bytes(apdu).hex().upper()}")
        data, sw1, sw2 = self.replies.pop(0)
        return list(data), sw1, sw2


def _transporter(connection: _ScriptedConnection) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.connection = connection
    transporter.session = None
    transporter.verbose = False
    transporter.debug = False
    transporter.last_trace = ()
    transporter.last_error = None
    transporter.last_session_invalidation = None
    transporter.proactive_handler = None
    return transporter


class TransportProactiveHandlerTests(unittest.TestCase):
    """TS 102 221 V18.4 §7.4.2.1: '91 XX' is a normal ending with a command pending."""

    def test_without_stk_mode_the_status_word_reaches_the_caller(self) -> None:
        transporter = _transporter(_ScriptedConnection([(b"\x62\x00", 0x91, 0x0F)]))

        self.assertEqual(
            transporter.transmit(_SELECT_MF, silent=True), (b"\x62\x00", 0x91, 0x0F)
        )

    def test_stk_mode_answers_the_command_before_the_caller_sees_it(self) -> None:
        transporter = _transporter(_ScriptedConnection([(b"\x62\x00", 0x91, 0x0F)]))
        seen = []
        transporter.proactive_handler = lambda sw1, sw2: (seen.append((sw1, sw2)), (0x90, 0x00))[1]

        self.assertEqual(
            transporter.transmit(_SELECT_MF, silent=True), (b"\x62\x00", 0x90, 0x00)
        )
        self.assertEqual(seen, [(0x91, 0x0F)])

    def test_the_controller_fetches_and_answers_on_the_same_connection(self) -> None:
        connection = _ScriptedConnection(
            [
                (b"\x62\x00", 0x91, 0x0F),
                (_SET_UP_EVENT_LIST, 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        transporter = _transporter(connection)
        controller = StkController(transporter)
        transporter.proactive_handler = controller.drain_pending

        self.assertEqual(
            transporter.transmit(_SELECT_MF, silent=True), (b"\x62\x00", 0x90, 0x00)
        )
        self.assertEqual(connection.calls[1], "801200000F")
        self.assertEqual(connection.calls[2][:4], "8014")
        self.assertEqual(controller.state.event_list, [0x03, 0x09])

    def test_a_failed_drain_leaves_the_command_result_intact(self) -> None:
        connection = _ScriptedConnection(
            [
                (b"\x62\x00", 0x91, 0x0F),
                (b"", 0x6F, 0x00),
            ]
        )
        transporter = _transporter(connection)
        controller = StkController(transporter)
        transporter.proactive_handler = controller.drain_pending

        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = transporter.transmit(_SELECT_MF, silent=True)

        self.assertEqual(result, (b"\x62\x00", 0x91, 0x0F))
        self.assertIn("proactive command left pending", output.getvalue())


class _Transport:
    """Transport stand-in for the shell: a scripted connection plus reset hooks."""

    def __init__(self, replies):
        self.connection = _ScriptedConnection(replies)
        self.session = SimpleNamespace(is_authenticated=False)
        self.proactive_handler = None
        self.debug = False
        self.reset_calls = 0

    def reset(self):
        self.reset_calls += 1
        return True

    def reset_session_state(self):
        return None

    def connect(self):
        return True


def _shell(transport: _Transport) -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.transport = transport
    shell.debug_mode = False
    shell._stk_mode_controller = None
    shell.fs_ctrl = SimpleNamespace(current_fid=None, current_fcp={})
    shell.prompts: list[str] = []
    shell._update_prompt_state = lambda: shell.prompts.append(
        "STK" if shell._active_stk_mode_controller() is not None else "APDU"
    )
    shell._clear_prompt_context_tracking = lambda: None
    return shell


class ShellStkModeTests(unittest.TestCase):
    def _bootstrap_replies(self):
        # TERMINAL PROFILE answered with SET UP EVENT LIST, then its response.
        return [
            (b"", 0x91, 0x0F),
            (_SET_UP_EVENT_LIST, 0x90, 0x00),
            (b"", 0x90, 0x00),
        ]

    def test_stk_on_bootstraps_and_hands_the_drain_to_the_transport(self) -> None:
        transport = _Transport(self._bootstrap_replies())
        shell = _shell(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            shell._run_stk_shell("ON")

        self.assertEqual(transport.connection.calls[0], terminal_profile_apdu().hex().upper())
        self.assertEqual(transport.reset_calls, 1)
        controller = shell._active_stk_mode_controller()
        self.assertIsNotNone(controller)
        self.assertEqual(transport.proactive_handler, controller.drain_pending)
        self.assertEqual(shell.prompts[-1], "STK")

    def test_stk_verbs_run_on_the_kept_session_without_a_new_bootstrap(self) -> None:
        transport = _Transport(
            self._bootstrap_replies()
            + [
                # EVENT DOWNLOAD Location status, accepted.
                (b"", 0x90, 0x00),
            ]
        )
        shell = _shell(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            shell._run_stk_shell("ON")
            shell._run_stk_shell("EVENT LOCATION-STATUS; STATE")

        self.assertEqual(transport.reset_calls, 1)
        self.assertEqual(transport.connection.calls[-1][:4], "80C2")
        self.assertIsNotNone(shell._active_stk_mode_controller())

    def test_stk_off_removes_the_drain(self) -> None:
        transport = _Transport(self._bootstrap_replies())
        shell = _shell(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            shell._run_stk_shell("ON")
            shell._run_stk_shell("OFF")

        self.assertIsNone(transport.proactive_handler)
        self.assertIsNone(shell._active_stk_mode_controller())
        self.assertEqual(shell.prompts[-1], "APDU")

    def test_a_new_transport_ends_the_mode(self) -> None:
        # A reconnect builds a transporter without the drain.
        transport = _Transport(self._bootstrap_replies())
        shell = _shell(transport)
        with contextlib.redirect_stdout(io.StringIO()):
            shell._run_stk_shell("ON")

        shell.transport = _Transport([])

        self.assertIsNone(shell._active_stk_mode_controller())

    def test_a_failed_bootstrap_leaves_the_mode_off(self) -> None:
        transport = _Transport([(b"", 0x6D, 0x00)])
        shell = _shell(transport)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            shell._run_stk_shell("ON")

        self.assertIsNone(shell._active_stk_mode_controller())
        self.assertIsNone(transport.proactive_handler)
        self.assertIn("STK bootstrap failed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
