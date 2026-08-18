# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for cooperative cancellation of GUI console streams.

The Command Center's Stop control sets a per-run ``threading.Event``, but
the work it stops runs in a worker thread reached through a console
object. These tests pin the contract that carries the flag across that
boundary, and the desktop teardown that must not wait for a run which
never ends.
"""

from __future__ import annotations

import asyncio
import threading
import time
import unittest
from typing import Any
from unittest import mock

from yggdrasim_common import cancellation
from yggdrasim_common.gui_server.actions import scp11_live


class CancelContractTests(unittest.TestCase):
    def test_attach_publishes_the_event_under_the_documented_name(self) -> None:
        target = mock.Mock()
        event = threading.Event()
        self.assertTrue(cancellation.attach_cancel_event(target, event))
        self.assertIs(getattr(target, cancellation.CANCEL_ATTRIBUTE), event)
        self.assertIs(cancellation.cancel_event_for(target), event)

    def test_attach_of_none_is_a_no_op(self) -> None:
        class Target:
            pass

        target = Target()
        self.assertFalse(cancellation.attach_cancel_event(target, None))
        self.assertIsNone(cancellation.cancel_event_for(target))

    def test_attach_tolerates_a_target_that_rejects_attributes(self) -> None:
        class Slotted:
            __slots__ = ()

        self.assertFalse(
            cancellation.attach_cancel_event(Slotted(), threading.Event())
        )

    def test_cancel_requested_tracks_the_event(self) -> None:
        class Target:
            pass

        target = Target()
        event = threading.Event()
        cancellation.attach_cancel_event(target, event)
        self.assertFalse(cancellation.cancel_requested(target))
        event.set()
        self.assertTrue(cancellation.cancel_requested(target))

    def test_detach_removes_the_event(self) -> None:
        class Target:
            pass

        target = Target()
        cancellation.attach_cancel_event(target, threading.Event())
        cancellation.detach_cancel_event(target)
        self.assertIsNone(cancellation.cancel_event_for(target))
        cancellation.detach_cancel_event(target)

    def test_cancel_requested_is_false_without_an_event(self) -> None:
        self.assertFalse(cancellation.cancel_requested(object()))

    def test_sleep_returns_early_when_cancelled(self) -> None:
        class Target:
            pass

        target = Target()
        event = threading.Event()
        cancellation.attach_cancel_event(target, event)
        event.set()
        started = time.monotonic()
        self.assertTrue(cancellation.sleep_unless_cancelled(target, 30.0))
        self.assertLess(time.monotonic() - started, 1.0)

    def test_sleep_without_an_event_still_waits(self) -> None:
        started = time.monotonic()
        self.assertFalse(cancellation.sleep_unless_cancelled(object(), 0.05))
        self.assertGreaterEqual(time.monotonic() - started, 0.04)

    def test_active_events_are_cancelled_together(self) -> None:
        first = threading.Event()
        second = threading.Event()
        cancellation.register_active_event(first)
        cancellation.register_active_event(second)
        self.assertGreaterEqual(cancellation.cancel_all_active_events(), 2)
        self.assertTrue(first.is_set())
        self.assertTrue(second.is_set())

    def test_already_cancelled_events_are_not_counted_again(self) -> None:
        event = threading.Event()
        event.set()
        cancellation.register_active_event(event)
        first_pass = cancellation.cancel_all_active_events()
        second_pass = cancellation.cancel_all_active_events()
        self.assertEqual(second_pass, 0)
        self.assertIsInstance(first_pass, int)


class CancelEventFromContextTests(unittest.TestCase):
    def test_reads_the_event_off_the_action_context(self) -> None:
        event = threading.Event()
        ctx = scp11_live.ActionContext(extras={"cancel_event": event})
        self.assertIs(scp11_live._cancel_event_from(ctx), event)

    def test_missing_or_wrong_typed_extras_yield_none(self) -> None:
        self.assertIsNone(scp11_live._cancel_event_from(object()))
        self.assertIsNone(
            scp11_live._cancel_event_from(scp11_live.ActionContext(extras={}))
        )
        self.assertIsNone(
            scp11_live._cancel_event_from(
                scp11_live.ActionContext(extras={"cancel_event": "yes"})
            )
        )


class _LoopingConsole:
    """Stand-in for a console whose command loops until asked to stop."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.finished = threading.Event()
        self._style = mock.Mock()
        self._commands: dict[str, Any] = {}

    def _cmd_forever(self, argument: str = "") -> None:
        self.started.set()
        while not cancellation.cancel_requested(self):
            time.sleep(0.01)
        self.finished.set()


class _DeafConsole:
    """Stand-in for a command that never checks the stop flag."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.finished = threading.Event()
        self.release = threading.Event()
        self._style = mock.Mock()
        self._commands: dict[str, Any] = {}

    def _cmd_forever(self, argument: str = "") -> None:
        self.started.set()
        self.release.wait(timeout=30)
        self.finished.set()


class StreamCancellationTests(unittest.TestCase):
    """The stream must end on cancel and hand the flag to the console."""

    def _drain(self, cancel_event: threading.Event | None, console: Any) -> list[dict]:
        async def _run() -> list[dict]:
            events: list[dict] = []
            agen = scp11_live._stream_console(
                0,
                "_cmd_forever",
                connect_first=False,
                done_message="TEST complete.",
                cancel_event=cancel_event,
            )
            async for event in agen:
                events.append(event)
                if event.get("level") == "done":
                    break
            return events

        with mock.patch.object(
            scp11_live, "_build_console", return_value=(console, mock.Mock())
        ):
            return asyncio.run(asyncio.wait_for(_run(), timeout=20))

    def test_cooperative_console_ends_the_run_itself(self) -> None:
        console = _LoopingConsole()
        event = threading.Event()

        def _cancel_once_running() -> None:
            console.started.wait(timeout=10)
            event.set()

        waiter = threading.Thread(target=_cancel_once_running, daemon=True)
        waiter.start()
        events = self._drain(event, console)
        waiter.join(timeout=5)

        self.assertEqual(events[-1].get("level"), "done")

    def test_unresponsive_console_still_releases_the_stream(self) -> None:
        # A command that ignores the flag must not strand the GUI: the
        # stream closes with a cancelled terminal event while the daemon
        # worker unwinds on its own.
        console = _DeafConsole()
        self.addCleanup(console.release.set)
        event = threading.Event()

        def _cancel_once_running() -> None:
            console.started.wait(timeout=10)
            event.set()

        waiter = threading.Thread(target=_cancel_once_running, daemon=True)
        waiter.start()
        events = self._drain(event, console)
        waiter.join(timeout=5)

        terminal = events[-1]
        self.assertEqual(terminal.get("level"), "done")
        self.assertTrue(terminal.get("cancelled"))
        self.assertFalse(terminal.get("ok"))
        self.assertFalse(console.finished.is_set())

    def test_the_console_receives_the_flag_so_a_loop_can_honour_it(self) -> None:
        console = _LoopingConsole()
        event = threading.Event()

        def _cancel_once_running() -> None:
            console.started.wait(timeout=10)
            event.set()

        waiter = threading.Thread(target=_cancel_once_running, daemon=True)
        waiter.start()
        self._drain(event, console)
        waiter.join(timeout=5)

        # The worker loop exits only by observing the attached event.
        self.assertTrue(console.finished.wait(timeout=10))


class DesktopShutdownTests(unittest.TestCase):
    def test_forceful_stop_sets_uvicorn_force_exit(self) -> None:
        from yggdrasim_common.gui_server import app as gui_app

        runner = gui_app._UvicornRunner.__new__(gui_app._UvicornRunner)
        server = mock.Mock()
        server.should_exit = False
        server.force_exit = False
        object.__setattr__(runner, "_server", server)
        object.__setattr__(runner, "_thread", None)

        runner.stop(force=True, timeout=0.1)
        self.assertTrue(server.should_exit)
        self.assertTrue(server.force_exit)

    def test_graceful_stop_leaves_force_exit_alone(self) -> None:
        from yggdrasim_common.gui_server import app as gui_app

        runner = gui_app._UvicornRunner.__new__(gui_app._UvicornRunner)
        server = mock.Mock()
        server.should_exit = False
        server.force_exit = False
        object.__setattr__(runner, "_server", server)
        object.__setattr__(runner, "_thread", None)

        runner.stop(timeout=0.1)
        self.assertTrue(server.should_exit)
        self.assertFalse(server.force_exit)

    def test_shutdown_cleanup_gives_up_rather_than_hanging(self) -> None:
        from yggdrasim_common.gui_server import app as gui_app

        release = threading.Event()
        self.addCleanup(release.set)

        def _hang(**_kwargs: Any) -> dict:
            release.wait(timeout=30)
            return {}

        module = mock.Mock()
        module.cleanup_gui_runtime = _hang
        started = time.monotonic()
        with mock.patch.dict(
            "sys.modules",
            {"yggdrasim_common.gui_server.lifecycle": module},
        ):
            gui_app._cleanup_gui_runtime_on_shutdown(
                include_default_hil_service=False,
                timeout=0.3,
            )
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
