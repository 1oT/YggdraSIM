# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Command logs: a file copy of what shell commands print, with debug detail.

Two shell surfaces write one. ``--log <file>`` on any command line runs that
command with the global debug flag (and the shell's own debug switches) on and
appends everything it prints to the file; ``TRACE START [file]`` /
``TRACE STOP`` in the SCP03 shell does the same for every command in between.
Output is a single stream of print calls, so the terminal shows the debug
output too: the file cannot be more verbose than the screen. The file gets the
same text without terminal escape sequences; a run opens with a header line and
closes with a trailer that says how it ended. In between, the file is laid out
to fold by indentation: a line printed at the left margin opens a block and
carries the local time it was printed, an indented line continues the block
above it, and a noted command's output sits one level under its ``>`` line. A
new file is created owner-only, because the debug trace carries key material in
full.

Streams are swapped per command, never across a prompt, so every swap is
strictly nested and the readline prompt stays untouched.
"""
from __future__ import annotations

import io
import os
import re
import sys
import threading
import time
import traceback
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Callable, ContextManager, Iterator, Optional, TextIO, TypeVar

from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV, set_global_debug
from yggdrasim_common.runtime_paths import runtime_root

LOG_FLAG = "--log"
LOG_FLAG_HELP = (
    "Add --log <file> to any command to run it with --debug and append "
    "everything it prints to <file>."
)

# OSC (hyperlinks, window titles), CSI (colour, cursor, scroll region), then
# the remaining two-byte escapes.
_TERMINAL_ESCAPE_RE = re.compile(
    r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B\[[0-?]*[ -/]*[@-~]|\x1B[@-Z\\-_]"
)
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F]")
_FILE_STEM_RE = re.compile(r"[^a-z0-9._-]+")
# Text a writer never ends with a newline is written out once it is this long.
_MAX_PENDING_CHARACTERS = 65536
# A block's first line opens with the local time to the millisecond and two spaces.
_STAMP_WIDTH = len("00:00:00.000  ")
# One nesting level: a run's body under its header, a noted command's output under its line.
_LEVEL_INDENT = "  "

T = TypeVar("T")
DebugScope = Callable[[], ContextManager[object]]


def _scan_words(line: str) -> list[tuple[int, int, str]]:
    """Split a command line at unquoted whitespace into (start, end, unquoted text).

    Quotes group and nothing else is special: a backslash stays literal, so a
    Windows path survives, and an unbalanced quote runs to the end of the line.
    """
    words: list[tuple[int, int, str]] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index].isspace():
            index += 1
            continue
        start = index
        characters: list[str] = []
        quote = ""
        while index < length:
            character = line[index]
            if len(quote) > 0:
                if character == quote:
                    quote = ""
                else:
                    characters.append(character)
            elif character.isspace():
                break
            elif character in ("'", '"'):
                quote = character
            else:
                characters.append(character)
            index += 1
        words.append((start, index, "".join(characters)))
    return words


def split_words(line: str) -> list[str]:
    """The words of a command line, quotes removed (see ``_scan_words``)."""
    return [text for _, _, text in _scan_words(str(line or ""))]


def split_log_flag(line: str) -> tuple[str, str]:
    """Return ``line`` without its ``--log <file>``, and the file it names.

    ``--log <file>`` and ``--log=<file>`` are both accepted, anywhere on the
    line; the file may be quoted. A line without the flag comes back unchanged
    with an empty file, quoting and spacing included. The flag is matched as
    typed, so a quoted ``"--log"`` stays an ordinary argument. Raises
    ``ValueError`` for a flag without a file, an option where the file should
    be, or a second ``--log``.
    """
    text = str(line or "")
    if LOG_FLAG not in text.lower():
        return text, ""
    words = _scan_words(text)
    found: Optional[tuple[int, int, str]] = None
    position = 0
    while position < len(words):
        start, end, _ = words[position]
        typed = text[start:end].lower()
        is_flag = typed == LOG_FLAG
        is_assignment = typed.startswith(f"{LOG_FLAG}=")
        if is_flag is False and is_assignment is False:
            position += 1
            continue
        if found is not None:
            raise ValueError("--log is given twice; a command writes one log file.")
        if is_assignment:
            found = (start, end, words[position][2][len(LOG_FLAG) + 1:])
            position += 1
            continue
        if position + 1 >= len(words):
            raise ValueError("--log needs a file: <command> --log <file>.")
        value_start, value_end, value = words[position + 1]
        value_typed = text[value_start:value_end]
        if value_typed.startswith("-"):
            raise ValueError(f"--log needs a file, not the option {value_typed}.")
        found = (start, value_end, value)
        position += 2
    if found is None:
        return text, ""
    start, end, requested = found
    if len(requested.strip()) == 0:
        raise ValueError("--log needs a file: <command> --log <file>.")
    kept = [part for part in (text[:start].strip(), text[end:].strip()) if len(part) > 0]
    return " ".join(kept), requested


def log_flag_present(line: str) -> bool:
    """Whether a command line carries ``--log``, well-formed or not."""
    try:
        _, requested = split_log_flag(line)
    except ValueError:
        return True
    return len(requested) > 0


def strip_log_flag(line: str) -> str:
    """``line`` without its ``--log`` modifier, for matching and display; never raises.

    A malformed flag is cut off with everything after it, so a credential
    check still sees the command a stray ``--log`` follows.
    """
    text = str(line or "")
    try:
        command_line, _ = split_log_flag(text)
    except ValueError:
        for start, end, _ in _scan_words(text):
            typed = text[start:end].lower()
            if typed == LOG_FLAG or typed.startswith(f"{LOG_FLAG}="):
                return text[:start].strip()
        return text
    return command_line


def default_log_directory() -> Path:
    """Where a log goes when no file is named (``TRACE START`` alone)."""
    return Path(runtime_root()) / "reports" / "command_logs"


def resolve_log_path(requested: str, *, label: str, now: Optional[datetime] = None) -> Path:
    """The file a requested log path names.

    ``~`` and environment variables are expanded and a relative path is taken
    from the working directory. A directory -- an existing one, a path ending
    in a separator, or no path at all, which means ``default_log_directory()``
    -- gets a file named after ``label`` and the local time.
    """
    text = os.path.expandvars(os.path.expanduser(str(requested or "").strip()))
    path = Path(text) if len(text) > 0 else default_log_directory()
    if path.is_absolute() is False:
        path = Path.cwd() / path
    path = Path(os.path.abspath(path))
    names_directory = len(text) == 0 or text.endswith(("/", os.sep)) or path.is_dir()
    if names_directory:
        moment = now if now is not None else datetime.now()
        stem = _FILE_STEM_RE.sub("-", str(label or "").strip().lower()).strip("-.")
        if len(stem) == 0:
            stem = "command"
        path = path / f"{stem}-{moment.strftime('%Y%m%d-%H%M%S')}.log"
    return path


def _open_log_file(path: Path) -> TextIO:
    """Open ``path`` for append, creating it owner-only when it is new."""
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(path, flags)
    except OSError as error:
        reason = error.strerror or str(error)
        raise RuntimeError(f"cannot write {path}: {reason}.") from error
    return os.fdopen(descriptor, "a", encoding="utf-8", errors="replace", newline="\n", buffering=1)


def _clean_terminal_text(text: str) -> str:
    """What a terminal leaves of one line: no escapes, a carriage return overwrites."""
    value = _TERMINAL_ESCAPE_RE.sub("", text).rstrip("\r")
    if "\r" in value:
        value = value.rsplit("\r", 1)[-1]
    return _CONTROL_CHARACTER_RE.sub("", value).rstrip()


def _clock(moment: float) -> str:
    milliseconds = int((moment % 1) * 1000)
    return f"{time.strftime('%H:%M:%S', time.localtime(moment))}.{milliseconds:03d}"


def _file_line(started: float, text: str, level: int) -> str:
    """One body line of the file, ``level`` steps in.

    A line printed at the left margin opens a block and carries the time it was
    printed. An indented line continues the block above it: the stamp's width in
    blanks keeps its columns where the terminal had them, so an editor that folds
    by indentation folds it under the block's first line.
    """
    if len(text) == 0:
        return ""
    margin = _LEVEL_INDENT * level
    if text[0].isspace():
        return f"{margin}{' ' * _STAMP_WIDTH}{text}"
    return f"{margin}{_clock(started)}  {text}"


def _wall_clock() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def _restore_debug_env(previous: Optional[str]) -> None:
    if previous is None:
        os.environ.pop(GLOBAL_DEBUG_ENV, None)
        return
    os.environ[GLOBAL_DEBUG_ENV] = previous


class _LogSink:
    """The file side of one capture: whole lines, per stream, stamped when they began."""

    def __init__(self, log: CommandLog) -> None:
        self._log = log
        self._pending: dict[str, tuple[float, str]] = {}

    def write(self, stream: str, text: str) -> None:
        if len(text) == 0:
            return
        with self._log._lock:
            started, partial = self._pending.pop(stream, (time.time(), ""))
            partial += text
            cut = partial.find("\n")
            while cut >= 0:
                self._log._write_line(started, partial[:cut])
                partial = partial[cut + 1:]
                started = time.time()
                cut = partial.find("\n")
            if len(partial) >= _MAX_PENDING_CHARACTERS:
                self._log._write_line(started, partial)
                partial = ""
            if len(partial) > 0:
                self._pending[stream] = (started, partial)

    def flush_pending(self) -> None:
        with self._log._lock:
            for started, partial in self._pending.values():
                self._log._write_line(started, partial)
            self._pending.clear()


class _TeeStream(io.TextIOBase):
    """``sys.stdout`` / ``sys.stderr`` during a capture: the terminal as before, plus the log.

    The terminal-facing attributes (``isatty``, ``fileno``, ``encoding``) are the
    terminal's, so colour decisions and ``input()`` behave exactly as without it.
    """

    def __init__(self, console: Optional[TextIO], sink: _LogSink, name: str) -> None:
        self._console = console if console is not None else _NullConsole()
        self._sink = sink
        self._name = name
        super().__init__()

    def write(self, text: str) -> int:
        written = self._console.write(text)
        self._sink.write(self._name, str(text))
        if isinstance(written, int):
            return written
        return len(text)

    def flush(self) -> None:
        self._console.flush()

    def close(self) -> None:
        """Closing the tee leaves the terminal stream open."""

    def isatty(self) -> bool:
        return bool(self._console.isatty())

    def fileno(self) -> int:
        return self._console.fileno()

    def writable(self) -> bool:
        return True

    @property
    def encoding(self) -> str:
        return getattr(self._console, "encoding", None) or "utf-8"

    @property
    def errors(self) -> Optional[str]:
        return getattr(self._console, "errors", None)

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._console, name)


class _NullConsole(io.TextIOBase):
    """The terminal side when the process has no ``sys.stdout`` (``pythonw``)."""

    def write(self, text: str) -> int:
        return len(text)


class CommandLog:
    """One log file: opened once, written by one or more captures, then closed.

    ``title`` heads the file (``"<shell> > <command>"`` for ``--log``);
    ``label`` names the file when the requested path is a directory.
    """

    def __init__(self, requested_path: str, *, title: str, label: str = "command") -> None:
        self.requested_path = str(requested_path or "").strip()
        self.title = str(title or "").strip()
        self.label = str(label or "").strip() or "command"
        self.path: Optional[Path] = None
        self.lines_written = 0
        self._handle: Optional[TextIO] = None
        self._lock = threading.Lock()
        self._opened_at = 0.0
        self._capturing = False
        self._capture_command = ""
        # Noted commands the current output sits under; read and changed under ``_lock``.
        self._depth = 0
        self._sink: Optional[_LogSink] = None

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    def open(self) -> Path:
        """Open the file for append and write the header; ``RuntimeError`` when it cannot."""
        if self._handle is not None and self.path is not None:
            return self.path
        path = resolve_log_path(self.requested_path, label=self.label)
        handle = _open_log_file(path)
        try:
            if os.fstat(handle.fileno()).st_size > 0:
                handle.write("\n")
            handle.write(f"=== {_wall_clock()}  {self.title} ===\n")
        except OSError as error:
            handle.close()
            raise RuntimeError(f"cannot write {path}: {error.strerror or error}.") from error
        self.path = path
        self._handle = handle
        self._opened_at = time.monotonic()
        self.lines_written = 0
        return path

    def close(self, ending: str = "ended") -> None:
        """Write the trailer and close the file; a second call does nothing."""
        with self._lock:
            handle = self._handle
            if handle is None:
                return
            self._handle = None
            elapsed = time.monotonic() - self._opened_at
            try:
                handle.write(f"=== {_wall_clock()}  {ending} after {elapsed:.1f} s ===\n")
            except OSError:
                pass
            try:
                handle.close()
            except OSError:
                pass

    def __enter__(self) -> CommandLog:
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def note_command(self, command_line: str) -> None:
        """Write the command about to run (the terminal shows it as typed already)."""
        with self._lock:
            self._write_line(time.time(), f"> {command_line}")

    @contextmanager
    def capture(self, command_line: str = "", *, debug: Optional[DebugScope] = None) -> Iterator[None]:
        """Copy what the block prints into the file, with debug output on.

        ``command_line`` is noted first when given, and what the block prints
        sits one level under the note. Inside a capture of the same log (a
        script line under ``RUN``, a bind's expansion), a capture only notes its
        command, one level deeper again. An exception leaving the block is
        written to the file -- the traceback for an ``Exception`` -- and passed
        on.
        """
        if self._handle is None:
            raise RuntimeError("the log file is not open.")
        command_text = str(command_line or "").strip()
        if self._capturing:
            noted = len(command_text) > 0 and command_text != self._capture_command
            if noted:
                self.note_command(command_text)
                self._nest(1)
            try:
                yield
            finally:
                if noted:
                    self._nest(-1)
            return
        if len(command_text) > 0:
            self.note_command(command_text)
            self._nest(1)
        sink = _LogSink(self)
        self._capturing = True
        self._capture_command = command_text
        self._sink = sink
        try:
            with ExitStack() as stack:
                stack.enter_context(redirect_stdout(_TeeStream(sys.stdout, sink, "stdout")))
                stack.enter_context(redirect_stderr(_TeeStream(sys.stderr, sink, "stderr")))
                stack.callback(_restore_debug_env, os.environ.get(GLOBAL_DEBUG_ENV))
                set_global_debug(True, persist=False)
                if debug is not None:
                    stack.enter_context(debug())
                try:
                    yield
                except BaseException as error:
                    sink.flush_pending()
                    self._write_exception(error)
                    raise
        finally:
            sink.flush_pending()
            with self._lock:
                self._depth = 0
            self._sink = None
            self._capturing = False
            self._capture_command = ""

    def _nest(self, step: int) -> None:
        """Move the output one level under a noted command (1) or back out (-1)."""
        if step < 0 and self._sink is not None:
            # A line the command left open is its own: it goes out before the level drops.
            self._sink.flush_pending()
        with self._lock:
            self._depth = max(0, self._depth + step)

    def _write_exception(self, error: BaseException) -> None:
        if isinstance(error, Exception):
            rendered = traceback.format_exception(type(error), error, error.__traceback__)
            lines = "".join(rendered).splitlines()
        elif isinstance(error, KeyboardInterrupt):
            lines = ["! interrupted (Ctrl+C)"]
        else:
            lines = [f"! ended by {type(error).__name__}"]
        with self._lock:
            moment = time.time()
            for line in lines:
                self._write_line(moment, line)

    def _write_line(self, started: float, text: str) -> None:
        # The caller holds ``_lock``.
        handle = self._handle
        if handle is None:
            return
        line = _file_line(started, _clean_terminal_text(text), self._depth + 1)
        try:
            handle.write(f"{line}\n")
        except (OSError, ValueError):
            return
        self.lines_written += 1


def run_with_command_log(
    line: str,
    execute: Callable[[str], T],
    *,
    shell: str,
    refused: T,
    debug: Optional[DebugScope] = None,
    shown: Optional[Callable[[str], str]] = None,
    raise_refusal: bool = False,
) -> T:
    """Run one shell command line; one carrying ``--log <file>`` runs under a command log.

    ``execute`` is the shell's own dispatcher and gets the line without the
    flag. ``debug`` returns a context that turns the shell's own debug switches
    on (raw APDU logging, a debug mode) and back; the global debug flag is
    turned on for every shell. ``shown`` renders the line for the file header,
    so a shell that redacts a credential on screen redacts it there too. A
    malformed flag or a file that cannot be written is reported and returns
    ``refused`` without running the command; with ``raise_refusal`` it is
    raised instead (``ValueError`` / ``RuntimeError``), for a shell whose batch
    mode counts a raised command as a failure.
    """
    try:
        command_line, requested = split_log_flag(line)
        if len(requested) > 0 and len(command_line.strip()) == 0:
            raise ValueError("--log needs a command to run: <command> --log <file>.")
    except ValueError as error:
        if raise_refusal:
            raise
        print(f"[!] {error}")
        return refused
    if len(requested) == 0:
        return execute(line)
    display = shown(command_line) if shown is not None else command_line
    words = command_line.split(None, 1)
    log = CommandLog(requested, title=f"{shell} > {display}", label=words[0] if words else "")
    try:
        path = log.open()
    except RuntimeError as error:
        if raise_refusal:
            raise RuntimeError(f"--log: {error}") from error
        print(f"[!] --log: {error}")
        return refused
    print(f"[*] --log: running with --debug; the output also goes to {path}")
    ending = "ended"
    try:
        with log.capture(debug=debug):
            return execute(command_line)
    except KeyboardInterrupt:
        ending = "interrupted (Ctrl+C)"
        raise
    except BaseException as error:
        ending = f"ended by {type(error).__name__}"
        raise
    finally:
        log.close(ending)
        print(f"[*] --log: {log.lines_written} line(s) appended to {path}")
