# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Verdict of a shell batch (``--cmd`` / ``--stdin``): did any command in it fail.

The shells print a failed step as a ``[-]`` line and a refusal or an error as
a ``[!]`` line; ``[!] Warning`` lines and the other markers are notes. Each
command of a batch runs under :meth:`BatchOutcome.command`, which watches what
it prints and counts an exception it raises, so the entry point can end the
process with exit code 1 when a command failed. A command that runs until it
is stopped can be judged by the narrower stream rule the GUI applies, and a
command with a verdict of its own passes it in.
"""

from __future__ import annotations

import re
import sys
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, TextIO

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# A batch is finite, but keep the names it reports bounded all the same.
_MAX_NAMED_FAILURES = 32
# A line still waiting for its newline is cut to this many characters.
_MAX_PENDING_CHARS = 4096

RULE_LINES = "lines"
RULE_STREAM = "stream"


def _plain(line: str) -> str:
    return _ANSI.sub("", str(line)).lstrip()


def is_failure_line(line: str) -> bool:
    """A ``[-]`` line, or a ``[!]`` line other than ``[!] Warning``."""
    text = _plain(line)
    if text.startswith("[-]"):
        return True
    if text.startswith("[!]"):
        return not text[3:].lstrip().lower().startswith("warning")
    return False


def is_stream_failure_line(line: str) -> bool:
    """The rule for a command that runs until stopped: ``[-]``, or ``[!]`` saying it failed.

    The GUI judges a streamed console command the same way
    (``_is_failure_line`` in ``gui_server/actions/scp11_live.py``): such a
    command reports passing events with ``[!]`` while it keeps running.
    """
    text = _plain(line)
    if text.startswith("[-]"):
        return True
    return text.startswith("[!]") and "failed" in text.lower()


class _WatchedStream:
    """Forwards every write to the stream it wraps and remembers a failure line."""

    def __init__(self, stream: TextIO, rule: Callable[[str], bool]) -> None:
        self._stream = stream
        self._rule = rule
        self._pending = ""
        self.failed = False

    def write(self, text: str) -> int:
        if not self.failed:
            lines = (self._pending + str(text)).split("\n")
            self._pending = lines.pop()[-_MAX_PENDING_CHARS:]
            if any(self._rule(line) for line in lines):
                self.failed = True
        return self._stream.write(text)

    def finish(self) -> None:
        if not self.failed and self._pending and self._rule(self._pending):
            self.failed = True
        self._pending = ""

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class BatchOutcome:
    """The verdict of one batch: ``ok`` until a command printed a failure line or raised."""

    def __init__(self) -> None:
        self.failures = 0
        self.failed_commands: list[str] = []

    @property
    def ok(self) -> bool:
        return self.failures == 0

    def _record(self, line: str) -> None:
        self.failures += 1
        if len(self.failed_commands) < _MAX_NAMED_FAILURES:
            self.failed_commands.append(str(line).strip())

    @contextmanager
    def command(
        self,
        line: str,
        *,
        rule: str = RULE_LINES,
        verdict: Optional[Callable[[], Optional[bool]]] = None,
    ) -> Iterator[None]:
        """Run one command of the batch and judge it.

        ``verdict``, when given, is asked after the command: True or False
        decides, None falls back to the lines it printed. An exception the
        command raises is a failure and is raised on.
        """
        predicate = is_stream_failure_line if rule == RULE_STREAM else is_failure_line
        watched_out = _WatchedStream(sys.stdout, predicate)
        watched_err = _WatchedStream(sys.stderr, predicate)
        sys.stdout = watched_out
        sys.stderr = watched_err
        raised = False
        try:
            yield
        except Exception:
            raised = True
            raise
        finally:
            if sys.stdout is watched_out:
                sys.stdout = watched_out._stream
            if sys.stderr is watched_err:
                sys.stderr = watched_err._stream
            watched_out.finish()
            watched_err.finish()
            decided = verdict() if verdict is not None else None
            if decided is None:
                failed = raised or watched_out.failed or watched_err.failed
            else:
                failed = raised or decided is False
            if failed:
                self._record(line)
