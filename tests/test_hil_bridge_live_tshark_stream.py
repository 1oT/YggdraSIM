from __future__ import annotations

import io
import os
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path

from Tools.HilBridge.live_tshark_stream import (
    DEFAULT_STREAM_QUEUE_CAPACITY,
    LiveTsharkStream,
    LiveTsharkStreamOptions,
    build_live_stream_command,
    ensure_fifo,
)


SAMPLE_LINES = [
    '"1"\t"0.000000000"\t"1744634400.123456"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"40"\t"Sample A"\t"0a:1b:2c"',
    '"2"\t"0.000500000"\t"1744634400.678901"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"44"\t"Sample B"\t"ab:cd"',
    '"3"\t"0.001000000"\t"1744634400.999999"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"48"\t"Sample C"\t"ff"',
]


class FakeProcess:
    """Minimal Popen-like stand-in used by LiveTsharkStream tests."""

    def __init__(
        self,
        stdout_lines: list[str],
        *,
        delay_between_lines: float = 0.0,
        stderr_payload: bytes = b"",
    ) -> None:
        self._stdout_lines = list(stdout_lines)
        self._delay_between_lines = float(delay_between_lines)
        self._stderr_payload = bytes(stderr_payload)
        self._exit_event = threading.Event()
        self._returncode: int | None = None
        self.stdout = _SlowTextIterator(
            self._stdout_lines,
            delay=self._delay_between_lines,
            close_event=self._exit_event,
        )
        self.stderr = io.BytesIO(self._stderr_payload)

    def poll(self) -> int | None:
        return self._returncode

    def terminate(self) -> None:
        self._returncode = 143
        self._exit_event.set()

    def kill(self) -> None:
        self._returncode = 137
        self._exit_event.set()

    def wait(self, *, timeout: float | None = None) -> int | None:
        self._exit_event.wait(timeout=timeout)
        return self._returncode


class _SlowTextIterator:
    """Iterator that yields pre-supplied lines with optional delays and supports early close."""

    def __init__(
        self,
        lines: list[str],
        *,
        delay: float,
        close_event: threading.Event,
    ) -> None:
        self._lines = list(lines)
        self._index = 0
        self._delay = float(delay)
        self._close_event = close_event
        self._closed = False

    def __iter__(self) -> "_SlowTextIterator":
        return self

    def __next__(self) -> bytes:
        if self._closed or self._close_event.is_set():
            raise StopIteration
        if self._index >= len(self._lines):
            raise StopIteration
        next_line = self._lines[self._index]
        self._index += 1
        if self._delay > 0.0:
            time.sleep(self._delay)
        return (next_line + "\n").encode("utf-8")

    def close(self) -> None:
        self._closed = True


class BuildLiveStreamCommandTests(unittest.TestCase):
    def test_command_contains_fifo_interface_and_line_flush(self) -> None:
        command = build_live_stream_command(
            "/tmp/example.fifo",
            tshark_binary="/usr/bin/tshark",
        )
        self.assertIn("-i", command)
        fifo_index = command.index("-i")
        self.assertEqual(command[fifo_index + 1], "/tmp/example.fifo")
        self.assertIn("-l", command)
        self.assertEqual(command[0], "/usr/bin/tshark")

    def test_extra_command_tokens_are_appended(self) -> None:
        command = build_live_stream_command(
            "/tmp/example.fifo",
            extra_command=("--disable-protocol", "tcp"),
        )
        self.assertEqual(command[-2], "--disable-protocol")
        self.assertEqual(command[-1], "tcp")


class EnsureFifoTests(unittest.TestCase):
    def test_ensure_fifo_creates_named_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            ensure_fifo(str(fifo_path))
            self.assertTrue(fifo_path.exists())
            import stat
            self.assertTrue(stat.S_ISFIFO(os.stat(fifo_path).st_mode))

    def test_ensure_fifo_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            ensure_fifo(str(fifo_path))
            ensure_fifo(str(fifo_path))
            self.assertTrue(fifo_path.exists())

    def test_ensure_fifo_rejects_empty_path(self) -> None:
        with self.assertRaises(ValueError):
            ensure_fifo("")

    def test_ensure_fifo_rejects_existing_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            regular_path = Path(temp_dir) / "regular.txt"
            regular_path.write_text("", encoding="utf-8")
            with self.assertRaises(OSError):
                ensure_fifo(str(regular_path))


class LiveTsharkStreamTests(unittest.TestCase):
    def _make_stream(
        self,
        fifo_path: str,
        stdout_lines: list[str],
        *,
        delay_between_lines: float = 0.0,
        stderr_payload: bytes = b"",
    ) -> tuple[LiveTsharkStream, FakeProcess]:
        fake_process_slot: dict[str, FakeProcess] = {}

        def popen_factory(command, environment):
            fake = FakeProcess(
                stdout_lines,
                delay_between_lines=delay_between_lines,
                stderr_payload=stderr_payload,
            )
            fake_process_slot["process"] = fake
            return fake

        stream = LiveTsharkStream(
            LiveTsharkStreamOptions(
                fifo_path=fifo_path,
                tshark_binary="echo",
                queue_capacity=DEFAULT_STREAM_QUEUE_CAPACITY,
            ),
            popen_factory=popen_factory,
        )
        self.assertTrue(stream.start())
        return stream, fake_process_slot["process"]

    def _wait_for_row_count(
        self,
        stream: LiveTsharkStream,
        *,
        expected_count: int,
        timeout_seconds: float = 2.0,
    ) -> list:
        deadline = time.monotonic() + float(timeout_seconds)
        collected: list = []
        while time.monotonic() < deadline:
            collected.extend(stream.drain())
            if len(collected) >= expected_count:
                return collected
            time.sleep(0.02)
        collected.extend(stream.drain())
        return collected

    def test_stream_parses_stdout_lines_into_summary_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            stream, _ = self._make_stream(str(fifo_path), SAMPLE_LINES)
            try:
                rows = self._wait_for_row_count(stream, expected_count=3)
                self.assertEqual(len(rows), 3)
                self.assertEqual([row.number for row in rows], [1, 2, 3])
                self.assertEqual(rows[0].info, "Sample A")
                self.assertEqual(rows[0].udp_payload_hex, "0A1B2C")
            finally:
                stream.stop(timeout=0.5)

    def test_drain_returns_empty_when_no_rows_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            stream, _ = self._make_stream(str(fifo_path), [], delay_between_lines=0.0)
            try:
                time.sleep(0.1)
                self.assertEqual(stream.drain(), [])
            finally:
                stream.stop(timeout=0.5)

    def test_error_text_includes_stderr_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            stream, _ = self._make_stream(
                str(fifo_path),
                [],
                stderr_payload=b"tshark: Capture child died unexpectedly.\n",
            )
            try:
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    if "Capture child died" in stream.error_text():
                        break
                    time.sleep(0.02)
                self.assertIn("Capture child died", stream.error_text())
            finally:
                stream.stop(timeout=0.5)

    def test_start_fails_gracefully_when_popen_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"

            def failing_factory(command, environment):
                raise RuntimeError("tshark is missing from test harness.")

            stream = LiveTsharkStream(
                LiveTsharkStreamOptions(fifo_path=str(fifo_path)),
                popen_factory=failing_factory,
            )
            self.assertFalse(stream.start())
            self.assertIn("tshark is missing", stream.error_text())

    def test_stop_is_idempotent_and_closes_keepalive_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fifo_path = Path(temp_dir) / "live.fifo"
            stream, _ = self._make_stream(str(fifo_path), SAMPLE_LINES)
            stream.stop(timeout=0.5)
            stream.stop(timeout=0.5)
            self.assertFalse(stream.is_alive())


if __name__ == "__main__":
    unittest.main()
