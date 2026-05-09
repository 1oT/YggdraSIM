# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge tshark stream: drives a tshark subprocess and pipes decoded SIM-frame events to the live-decode state."""
from __future__ import annotations

import errno
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from Tools.HilBridge.live_decode_view import (
    DEFAULT_DECODE_RULE,
    PacketSummary,
    _local_tshark_config_home,
    parse_summary_output,
)

DEFAULT_STREAM_QUEUE_CAPACITY = 8192
DEFAULT_STREAM_DRAIN_LIMIT = 1024
DEFAULT_STREAM_STARTUP_GRACE_SECONDS = 0.25
DEFAULT_STREAM_STOP_TIMEOUT_SECONDS = 2.0
_MAX_STDERR_CAPTURE_BYTES = 4096


@dataclass(frozen=True, slots=True)
class LiveTsharkStreamOptions:
    fifo_path: str
    tshark_binary: str = "tshark"
    decode_rule: str = DEFAULT_DECODE_RULE
    queue_capacity: int = DEFAULT_STREAM_QUEUE_CAPACITY
    extra_command: tuple[str, ...] = ()


def build_live_stream_command(
    fifo_path: str,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
    extra_command: tuple[str, ...] = (),
) -> list[str]:
    """Build the tshark command-line args list for live interface capture."""
    normalized_fifo = str(fifo_path or "").strip()
    command: list[str] = [
        str(tshark_binary or "tshark"),
        "-i",
        normalized_fifo,
        "-l",
        "-n",
        "-Q",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "_ws.col.Time",
        "-e",
        "frame.time_epoch",
        "-e",
        "_ws.col.Source",
        "-e",
        "_ws.col.Destination",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Length",
        "-e",
        "_ws.col.Info",
        "-e",
        "udp.payload",
        "-d",
        str(decode_rule or DEFAULT_DECODE_RULE),
    ]
    for token in extra_command:
        command.append(str(token))
    return command


def ensure_fifo(fifo_path: str, *, mode: int = 0o600) -> None:
    """Create the named FIFO pipe if it does not already exist."""
    normalized_path = str(fifo_path or "").strip()
    if len(normalized_path) == 0:
        raise ValueError("FIFO path must not be empty.")
    target = Path(normalized_path).expanduser()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    if target.exists():
        if not _path_is_fifo(str(target)):
            raise OSError(
                errno.EEXIST,
                f"Path exists but is not a FIFO: {target}",
            )
        return
    os.mkfifo(str(target), mode)


def _path_is_fifo(path_text: str) -> bool:
    try:
        import stat

        return stat.S_ISFIFO(os.stat(path_text).st_mode)
    except OSError:
        return False


@dataclass(slots=True)
class _StreamRuntime:
    process: subprocess.Popen | None = None
    stdout_thread: threading.Thread | None = None
    stderr_thread: threading.Thread | None = None
    keepalive_fd: int | None = None
    stderr_tail: bytearray = field(default_factory=bytearray)
    last_error: str = ""
    started_monotonic: float = 0.0
    stopped: bool = False


class LiveTsharkStream:
    """Persistent `tshark -i <fifo>` reader that feeds PacketSummary rows into a queue."""

    def __init__(
        self,
        options: LiveTsharkStreamOptions,
        *,
        popen_factory: Callable[[list[str], dict[str, Any]], subprocess.Popen] | None = None,
    ) -> None:
        self._options = options
        self._queue: queue.Queue[PacketSummary] = queue.Queue(
            maxsize=max(1, int(options.queue_capacity or DEFAULT_STREAM_QUEUE_CAPACITY))
        )
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._runtime = _StreamRuntime()
        self._popen_factory = popen_factory or self._default_popen

    @property
    def options(self) -> LiveTsharkStreamOptions:
        return self._options

    def start(self) -> bool:
        """Launch the live tshark capture process and begin streaming to the FIFO."""
        fifo_path = str(self._options.fifo_path or "").strip()
        if len(fifo_path) == 0:
            self._set_error("FIFO path was not provided to LiveTsharkStream.")
            return False
        try:
            ensure_fifo(fifo_path)
        except (OSError, ValueError) as exc:
            self._set_error(f"Could not create FIFO {fifo_path}: {exc}")
            return False
        try:
            keepalive_fd = os.open(
                fifo_path,
                os.O_RDWR | os.O_NONBLOCK,
            )
        except OSError as exc:
            self._set_error(f"Could not keep FIFO alive: {exc}")
            return False
        command = build_live_stream_command(
            fifo_path,
            tshark_binary=self._options.tshark_binary,
            decode_rule=self._options.decode_rule,
            extra_command=self._options.extra_command,
        )
        environment = dict(os.environ)
        try:
            environment["XDG_CONFIG_HOME"] = _local_tshark_config_home(fifo_path)
        except (OSError, ValueError):
            pass
        try:
            process = self._popen_factory(command, environment)
        except Exception as exc:
            try:
                os.close(keepalive_fd)
            except OSError:
                pass
            self._set_error(f"Could not start tshark: {exc}")
            return False
        runtime = self._runtime
        runtime.process = process
        runtime.keepalive_fd = keepalive_fd
        runtime.started_monotonic = time.monotonic()
        runtime.stdout_thread = threading.Thread(
            target=self._drain_stdout_loop,
            name="LiveTsharkStream-stdout",
            daemon=True,
        )
        runtime.stderr_thread = threading.Thread(
            target=self._drain_stderr_loop,
            name="LiveTsharkStream-stderr",
            daemon=True,
        )
        runtime.stdout_thread.start()
        runtime.stderr_thread.start()
        return True

    def is_alive(self) -> bool:
        """Return True when the live tshark capture process is still running."""
        process = self._runtime.process
        if process is None:
            return False
        if self._stop_event.is_set():
            return False
        try:
            return process.poll() is None
        except (OSError, ValueError):
            return False

    def drain(self, *, limit: int = DEFAULT_STREAM_DRAIN_LIMIT) -> list[PacketSummary]:
        """Drain any buffered packet data from the tshark output pipe."""
        normalized_limit = max(1, int(limit or DEFAULT_STREAM_DRAIN_LIMIT))
        rows: list[PacketSummary] = []
        for _ in range(normalized_limit):
            try:
                rows.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return rows

    def error_text(self) -> str:
        """Return the last error text emitted by the tshark process, if any."""
        with self._lock:
            message = str(self._runtime.last_error or "").strip()
            stderr_blob = bytes(self._runtime.stderr_tail or b"")
        if len(stderr_blob) == 0:
            return message
        stderr_text = stderr_blob.decode("utf-8", errors="replace").strip()
        if len(stderr_text) == 0:
            return message
        if len(message) == 0:
            return stderr_text
        return f"{message} | tshark: {stderr_text}"

    def stop(self, *, timeout: float = DEFAULT_STREAM_STOP_TIMEOUT_SECONDS) -> None:
        """Terminate the tshark process and clean up the output pipe."""
        if self._runtime.stopped:
            return
        self._runtime.stopped = True
        self._stop_event.set()
        process = self._runtime.process
        if process is not None:
            try:
                process.terminate()
            except (OSError, ProcessLookupError):
                pass
            deadline = time.monotonic() + max(0.1, float(timeout or 0.1))
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            if process.poll() is None:
                try:
                    process.kill()
                except (OSError, ProcessLookupError):
                    pass
                try:
                    process.wait(timeout=0.5)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            for stream in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError:
                    pass
        keepalive_fd = self._runtime.keepalive_fd
        if keepalive_fd is not None:
            try:
                os.close(keepalive_fd)
            except OSError:
                pass
            self._runtime.keepalive_fd = None
        for thread in (self._runtime.stdout_thread, self._runtime.stderr_thread):
            if thread is None:
                continue
            try:
                thread.join(timeout=max(0.1, float(timeout or 0.1)))
            except RuntimeError:
                pass

    def _default_popen(
        self,
        command: list[str],
        environment: dict[str, Any],
    ) -> subprocess.Popen:
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            bufsize=0,
        )

    def _drain_stdout_loop(self) -> None:
        process = self._runtime.process
        if process is None or process.stdout is None:
            return
        stdout_stream = process.stdout
        try:
            for raw_line in stdout_stream:
                if self._stop_event.is_set():
                    break
                if raw_line is None:
                    break
                if isinstance(raw_line, bytes):
                    line_text = raw_line.decode("utf-8", errors="replace")
                else:
                    line_text = str(raw_line)
                normalized_line = line_text.rstrip("\r\n")
                if len(normalized_line) == 0:
                    continue
                parsed_rows = parse_summary_output(normalized_line + "\n")
                for row in parsed_rows:
                    self._enqueue_row_drop_oldest(row)
        except Exception as exc:
            self._set_error(f"Live tshark stdout reader crashed: {exc}")

    def _drain_stderr_loop(self) -> None:
        process = self._runtime.process
        if process is None or process.stderr is None:
            return
        stderr_stream = process.stderr
        try:
            while self._stop_event.is_set() is False:
                chunk = stderr_stream.read(1024)
                if chunk is None or len(chunk) == 0:
                    break
                with self._lock:
                    buffer = self._runtime.stderr_tail
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", errors="replace")
                    buffer.extend(chunk)
                    overflow = len(buffer) - _MAX_STDERR_CAPTURE_BYTES
                    if overflow > 0:
                        del buffer[:overflow]
        except Exception:
            pass

    def _enqueue_row_drop_oldest(self, row: PacketSummary) -> None:
        try:
            self._queue.put_nowait(row)
            return
        except queue.Full:
            pass
        try:
            self._queue.get_nowait()
        except queue.Empty:
            pass
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            pass

    def _set_error(self, message: str) -> None:
        normalized = str(message or "").strip()
        with self._lock:
            self._runtime.last_error = normalized
