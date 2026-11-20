# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Live operation trace: the lines an action prints, delivered while it runs.

A dispatcher captures its stdout in a sink and returns the text as
``data["trace"]`` when it ends. ``live_trace_sink()`` returns a sink that
keeps that contract and also publishes each finished line to the
``/api/events/trace`` subscribers, tagged with the run that printed it
(``begin_run``, set by the action route around the dispatcher call).

How much a card channel prints is decided where it is built, by
``configure_channel_trace``: one line per command (a STORE DATA sequence
counts once) by default, every exchange in hex under the global debug flag.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import io
import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from yggdrasim_common.process_debug import is_global_debug_enabled

# A subscriber that stops reading loses lines, never memory.
QUEUE_CAP = 512
MAX_SUBSCRIBERS = 16
MAX_LINE_CHARS = 4096
# A raw-mode profile load prints megabytes; a partial line is cut here.
_MAX_PENDING_CHARS = 65536

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


@dataclass
class TraceRun:
    """One action call whose printed lines are published."""

    action_id: str
    trace_id: str
    published: int = 0


_CURRENT_RUN: contextvars.ContextVar[TraceRun | None] = contextvars.ContextVar(
    "yggdrasim_gui_trace_run", default=None
)


class LiveTraceBus:
    """Fan-out of trace frames to the connected WebSocket clients."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[tuple[asyncio.Queue[dict[str, Any]], asyncio.AbstractEventLoop]] = []

    def attach(
        self,
        queue: asyncio.Queue[dict[str, Any]],
        loop: asyncio.AbstractEventLoop,
    ) -> Callable[[], None]:
        entry = (queue, loop)
        with self._lock:
            self._subscribers.append(entry)
            overflow = len(self._subscribers) - MAX_SUBSCRIBERS
            if overflow > 0:
                del self._subscribers[:overflow]

        def _detach() -> None:
            with self._lock:
                try:
                    self._subscribers.remove(entry)
                except ValueError:
                    pass

        return _detach

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def publish(self, frame: dict[str, Any]) -> int:
        """Hand *frame* to every subscriber; return how many took it."""
        with self._lock:
            subscribers = list(self._subscribers)
        delivered = 0
        for queue, loop in subscribers:
            if loop.is_closed():
                continue
            try:
                loop.call_soon_threadsafe(_offer, queue, frame)
            except RuntimeError:
                # The loop closed between the check and the post.
                continue
            delivered += 1
        return delivered


def _offer(queue: asyncio.Queue[dict[str, Any]], frame: dict[str, Any]) -> None:
    try:
        queue.put_nowait(frame)
    except asyncio.QueueFull:
        pass


_BUS = LiveTraceBus()


def get_bus() -> LiveTraceBus:
    return _BUS


def begin_run(action_id: str, trace_id: str) -> tuple[TraceRun, contextvars.Token[TraceRun | None]]:
    """Mark the calling context as running *action_id*; pair with ``end_run``."""
    run = TraceRun(action_id=str(action_id), trace_id=str(trace_id or ""))
    return run, _CURRENT_RUN.set(run)


def end_run(token: contextvars.Token[TraceRun | None]) -> None:
    _CURRENT_RUN.reset(token)


def infer_level(line: str) -> str:
    lowered = line.lower()
    if "[-]" in line or "error" in lowered or "failed" in lowered:
        return "error"
    if "[!]" in line or "warn" in lowered:
        return "warn"
    return "info"


class LiveTraceSink(io.StringIO):
    """``io.StringIO`` that also publishes each finished line of its run.

    Outside an action call (no run in the context) or with nobody listening
    it is a plain ``StringIO``. A carriage return restarts the line, so a
    redrawn progress bar publishes its last state only.
    """

    def __init__(self) -> None:
        super().__init__()
        self._run = _CURRENT_RUN.get()
        self._pending = ""

    def write(self, text: str) -> int:
        written = super().write(text)
        run = self._run
        if run is None or _BUS.subscriber_count() == 0:
            self._pending = ""
            return written
        self._pending += text
        while "\n" in self._pending:
            line, _, self._pending = self._pending.partition("\n")
            self._publish(run, line)
        if len(self._pending) > _MAX_PENDING_CHARS:
            self._pending = self._pending[-_MAX_PENDING_CHARS:]
        return written

    def flush(self) -> None:
        super().flush()

    def getvalue(self) -> str:
        # Dispatchers read the sink once, when the work is over: the
        # unterminated tail goes out with it.
        run = self._run
        if run is not None and len(self._pending) > 0:
            tail, self._pending = self._pending, ""
            self._publish(run, tail)
        return super().getvalue()

    def _publish(self, run: TraceRun, raw_line: str) -> None:
        line = _ANSI_RE.sub("", raw_line.rsplit("\r", 1)[-1]).rstrip()
        if len(line.strip()) == 0:
            return
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS] + f" ... [+{len(line) - MAX_LINE_CHARS} chars]"
        delivered = _BUS.publish(
            {
                "event": "trace",
                "action": run.action_id,
                "trace_id": run.trace_id,
                "level": infer_level(line),
                "line": line,
            }
        )
        if delivered > 0:
            run.published += 1


def live_trace_sink() -> LiveTraceSink:
    """Sink for a dispatcher's ``redirect_stdout``; see the module docstring."""
    return LiveTraceSink()


_SHELL_OUTPUT = threading.local()


@contextlib.contextmanager
def shell_output() -> Iterator[None]:
    """Leave the channels built on this thread as a shell has them.

    A stream action that shows a command's output as the terminal does
    (``_stream_console(terminal=True)``) must print what the shell prints and
    nothing more, so ``configure_channel_trace`` changes no channel inside
    this block.
    """
    previous = getattr(_SHELL_OUTPUT, "active", False)
    _SHELL_OUTPUT.active = True
    try:
        yield
    finally:
        _SHELL_OUTPUT.active = previous


def configure_channel_trace(channel: Any) -> Any:
    """Set what a GUI card channel prints per exchange, and return it.

    Global debug off: one line per command, a chunked STORE DATA once.
    Global debug on: every exchange with its command and response bytes.
    Inside ``shell_output()`` the channel is returned as built.
    """
    if getattr(_SHELL_OUTPUT, "active", False):
        return channel
    debug = is_global_debug_enabled()
    for name, value in (
        ("set_quiet_apdu_logging", not debug),
        ("set_milestone_apdu_logging", not debug),
        ("set_raw_apdu_logging", debug),
    ):
        setter = getattr(channel, name, None)
        if callable(setter):
            setter(value)
    return channel
