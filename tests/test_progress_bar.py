"""Unit tests for ``yggdrasim_common.progress``.

The progress session is a display-only surface with two hard
requirements that must not regress:

1. On any non-interactive stream (pipes, redirected output, dumb
   terminals, ``YGGDRASIM_NO_PROGRESS=1``) the session is a silent
   no-op; no ANSI escapes leak into the stream.
2. Even on the exception path the DECSTBM scroll region and cursor
   visibility are restored, so Ctrl-C in the middle of a sequence
   does not leave the terminal with a stuck footer area.

The rest of the suite covers counter bookkeeping, indeterminate
behaviour, and the thread-safety contract of the ``message`` helper.
"""

from __future__ import annotations

import io
import os
import threading
import unittest
from unittest import mock

from yggdrasim_common import progress as progress_module


class _FakeStream(io.StringIO):
    """A StringIO that reports as a TTY so we can exercise the
    activation path without a real terminal attached.
    """

    def __init__(self, tty: bool = True) -> None:
        super().__init__()
        self._tty = bool(tty)

    def isatty(self) -> bool:  # type: ignore[override]
        return self._tty


class NoOpActivationTests(unittest.TestCase):
    """Activation must be suppressed for any non-interactive stream."""

    def test_non_tty_stream_yields_inactive_session(self) -> None:
        stream = _FakeStream(tty=False)
        with progress_module.progress_session("download", total=5, stream=stream) as bar:
            bar.advance("seed")
            bar.advance("auth")
        self.assertFalse(bar.is_active)
        # No ANSI escapes or footer content leak to the stream.
        self.assertEqual(stream.getvalue(), "")

    def test_yggdrasim_no_progress_env_suppresses_activation(self) -> None:
        stream = _FakeStream(tty=True)
        with mock.patch.dict(os.environ, {"YGGDRASIM_NO_PROGRESS": "1"}, clear=False):
            with progress_module.progress_session(
                "download", total=3, stream=stream
            ) as bar:
                bar.advance("seed")
        self.assertFalse(bar.is_active)
        self.assertEqual(stream.getvalue(), "")

    def test_dumb_terminal_suppresses_activation(self) -> None:
        stream = _FakeStream(tty=True)
        with mock.patch.dict(os.environ, {"TERM": "dumb"}, clear=False):
            with progress_module.progress_session(
                "download", total=3, stream=stream
            ) as bar:
                bar.advance("seed")
        self.assertFalse(bar.is_active)
        self.assertEqual(stream.getvalue(), "")

    def test_unset_term_suppresses_activation(self) -> None:
        stream = _FakeStream(tty=True)
        # Pop TERM explicitly to simulate a bare subprocess without
        # TERM exported.
        clean_env = dict(os.environ)
        clean_env.pop("TERM", None)
        with mock.patch.dict(os.environ, clean_env, clear=True):
            with progress_module.progress_session(
                "download", total=3, stream=stream
            ) as bar:
                bar.advance("seed")
        self.assertFalse(bar.is_active)
        self.assertEqual(stream.getvalue(), "")

    def test_tiny_terminal_suppresses_activation(self) -> None:
        stream = _FakeStream(tty=True)
        # A 10x2 terminal is too small to host a sticky footer; the
        # session should decline to activate rather than paint into a
        # cramped space.
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((10, 2)),
        ):
            with progress_module.progress_session(
                "download", total=3, stream=stream
            ) as bar:
                bar.advance("seed")
        self.assertFalse(bar.is_active)
        self.assertEqual(stream.getvalue(), "")


class ActiveRenderingTests(unittest.TestCase):
    """When activation succeeds the footer must paint ANSI escapes."""

    def _activated_stream(self) -> _FakeStream:
        return _FakeStream(tty=True)

    def test_activation_emits_scroll_region_and_hides_cursor(self) -> None:
        stream = self._activated_stream()
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            with progress_module.progress_session(
                "download", total=4, stream=stream
            ) as bar:
                self.assertTrue(bar.is_active)
                # Hold a snapshot of the activation payload before any
                # teardown writes so we can assert on activation
                # bytes only.
                activation_output = stream.getvalue()
        output_text = stream.getvalue()
        self.assertIn("\x1b[1;23r", activation_output)  # DECSTBM 1..23
        self.assertIn("\x1b[?25l", activation_output)   # hide cursor
        # Teardown must restore the scroll region and re-show the
        # cursor even when no exception was raised.
        self.assertIn("\x1b[r", output_text)
        self.assertIn("\x1b[?25h", output_text)

    def test_exception_teardown_restores_scroll_region(self) -> None:
        stream = self._activated_stream()
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            with self.assertRaises(RuntimeError):
                with progress_module.progress_session(
                    "download", total=3, stream=stream
                ) as bar:
                    bar.advance("seed")
                    raise RuntimeError("boom")
        output_text = stream.getvalue()
        self.assertIn("\x1b[r", output_text)
        self.assertIn("\x1b[?25h", output_text)

    def test_footer_contains_title_and_counter_for_determinate_mode(self) -> None:
        stream = self._activated_stream()
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            with progress_module.progress_session(
                "download", total=4, stream=stream
            ) as bar:
                bar.advance("auth-server", count=1)
                bar.advance("prepare-download", count=1)
        output_text = stream.getvalue()
        self.assertIn("download", output_text)
        self.assertIn("auth-server", output_text)
        # Bar / counter fragment for 2/4 at 50 %.
        self.assertIn("2/4", output_text)
        self.assertIn("50%", output_text)

    def test_determinate_bar_uses_hash_filled_and_space_empty_cells(self) -> None:
        """The loading bar motif is ``#####`` for completed cells and
        raw spaces for the remainder — dashes and dots must not leak
        into the rendered footer regardless of completion percentage.
        """

        stream = self._activated_stream()
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            with progress_module.progress_session(
                "download", total=10, stream=stream
            ) as bar:
                bar.advance("phase-1", count=3)
        output_text = stream.getvalue()
        # A 3/10 completion must render three filled hash cells —
        # the rendered footer embeds the bar inside square brackets
        # so we can assert on the opening segment directly.
        self.assertIn("[###", output_text)
        # Empty cells are plain spaces; the dash character must not
        # appear between the opening ``[`` and the closing ``] NN%``
        # segment anywhere in the output.
        self.assertNotIn("[###-", output_text)
        self.assertNotIn("[##--", output_text)

    def test_indeterminate_mode_emits_spinner_frame(self) -> None:
        stream = self._activated_stream()
        with mock.patch.dict(
            os.environ, {"TERM": "xterm-256color"}, clear=False
        ), mock.patch.object(
            progress_module.shutil,
            "get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            with progress_module.progress_session(
                "eim-poll", stream=stream
            ) as bar:
                bar.set_status("round 1")
                bar.set_status("round 2")
                bar.set_status("round 3")
        output_text = stream.getvalue()
        # At least one ASCII spinner frame must have rendered.
        spinner_frame_seen = False
        for frame in progress_module.ProgressSession._SPINNER_FRAMES:
            if frame in output_text:
                spinner_frame_seen = True
                break
        self.assertTrue(spinner_frame_seen)


class CounterBookkeepingTests(unittest.TestCase):
    """advance() and set_total() must clamp and track correctly."""

    def test_advance_respects_total_clamp(self) -> None:
        stream = _FakeStream(tty=False)  # no-op path is fine for bookkeeping
        with progress_module.progress_session("seq", total=3, stream=stream) as bar:
            bar.advance("a", count=1)
            bar.advance("b", count=5)  # would overshoot; must clamp to total
            self.assertEqual(bar.completed, 3)

    def test_set_total_to_none_switches_to_indeterminate(self) -> None:
        stream = _FakeStream(tty=False)
        with progress_module.progress_session("seq", total=4, stream=stream) as bar:
            bar.advance("a", count=2)
            self.assertEqual(bar.total, 4)
            bar.set_total(None)
            self.assertIsNone(bar.total)

    def test_negative_count_is_treated_as_zero(self) -> None:
        stream = _FakeStream(tty=False)
        with progress_module.progress_session("seq", total=3, stream=stream) as bar:
            bar.advance("a", count=-4)
            self.assertEqual(bar.completed, 0)


class MessageHelperTests(unittest.TestCase):
    """message() must not require an active session."""

    def test_message_writes_to_stream_when_inactive(self) -> None:
        stream = _FakeStream(tty=False)
        with progress_module.progress_session("seq", total=2, stream=stream) as bar:
            bar.message("hello from non-tty")
        self.assertIn("hello from non-tty\n", stream.getvalue())

    def test_message_is_thread_safe(self) -> None:
        """Concurrent message() calls should not interleave into a single line."""
        stream = _FakeStream(tty=False)
        with progress_module.progress_session("seq", total=2, stream=stream) as bar:
            threads: list[threading.Thread] = []
            worker_count = 10

            def _worker(index: int) -> None:
                bar.message(f"line-{index:02d}")

            for worker_index in range(worker_count):
                thread_object = threading.Thread(
                    target=_worker, args=(worker_index,)
                )
                threads.append(thread_object)
            for thread_object in threads:
                thread_object.start()
            for thread_object in threads:
                thread_object.join()
        output_text = stream.getvalue()
        # Every worker line should appear exactly once.
        for worker_index in range(worker_count):
            expected_line = f"line-{worker_index:02d}\n"
            self.assertIn(expected_line, output_text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
