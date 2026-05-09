# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Sticky-footer progress session for long-running YggdraSIM commands.

Rationale
---------
The suite's interactive surfaces (SCP03 shell, SCP11 live/local_access/eim
shells, SAIP Tool bulk sweeps, HIL bridge captures) are built on plain
``print()`` and do not pull in Rich or Textual. Any progress indicator we
add therefore has to be:

* dependency-free,
* invisible on non-TTY outputs (pipes, ``--cmd`` / ``--stdin`` surfaces,
  CI, redirected ``stdout``/``stderr``, captured test runs),
* safe to tear down even on exceptions (so Ctrl-C does not leave the
  terminal with a bogus scroll region),
* compatible with the existing ``print(...)`` flow so log lines already
  emitted by the callers simply scroll above the bar without any
  wrapping.

The implementation uses DECSTBM (``ESC[t;br``) to carve the last row of
the terminal out of the scroll region. Subsequent output scrolls in the
rows above while the sticky footer stays pinned to the bottom. On
teardown the scroll region is restored to the full screen and the cursor
is made visible again.

The module honours ``YGGDRASIM_NO_PROGRESS`` (set to ``1/true/yes/on`` to
suppress) and ``TERM=dumb`` / unset ``TERM`` as explicit kill switches.

Usage
-----
.. code-block:: python

    from yggdrasim_common.progress import progress_session

    with progress_session("Profile download", total=7) as bar:
        bar.advance("AUTH-SD")
        ...
        bar.advance("INSTALL PACKAGE")

Leave ``total`` as ``None`` for an indeterminate spinner when the number
of steps is not known up front (e.g. polling loops).
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import Optional, TextIO


_ESC = "\x1b"
_SAVE_CURSOR = f"{_ESC}7"
_RESTORE_CURSOR = f"{_ESC}8"
_HIDE_CURSOR = f"{_ESC}[?25l"
_SHOW_CURSOR = f"{_ESC}[?25h"
_RESET_SCROLL_REGION = f"{_ESC}[r"
_CLEAR_LINE = f"{_ESC}[2K"


# --- environment kill switches ---------------------------------------------

def _progress_disabled_by_env() -> bool:
    """Return ``True`` when ``YGGDRASIM_NO_PROGRESS`` is set truthy."""
    raw_value = os.environ.get("YGGDRASIM_NO_PROGRESS", "")
    normalized = str(raw_value or "").strip().lower()
    truthy_values = {"1", "true", "yes", "on"}
    if normalized in truthy_values:
        return True
    return False


def _term_is_dumb() -> bool:
    """Return ``True`` when ``TERM`` is unset or explicitly ``dumb``."""
    term_value = str(os.environ.get("TERM", "") or "").strip().lower()
    if term_value == "":
        return True
    if term_value == "dumb":
        return True
    return False


def _format_hms(seconds: float) -> str:
    """Format a monotonic delta as ``M:SS`` or ``H:MM:SS``."""
    total_seconds = int(max(0.0, float(seconds)))
    minutes_total = total_seconds // 60
    seconds_part = total_seconds % 60
    if minutes_total >= 60:
        hours_part = minutes_total // 60
        minutes_part = minutes_total % 60
        return f"{hours_part}:{minutes_part:02d}:{seconds_part:02d}"
    return f"{minutes_total}:{seconds_part:02d}"


# --- session class ---------------------------------------------------------

class ProgressSession:
    """Sticky-footer progress session anchored to the terminal's last row.

    The session is a context manager; on ``__enter__`` it carves the
    bottom row out of the terminal scroll region via DECSTBM and begins
    painting the progress line. On ``__exit__`` (including the
    exception path) it restores the scroll region and cursor visibility.

    When activation would not be safe (non-TTY stream, dumb terminal,
    ``YGGDRASIM_NO_PROGRESS``, tiny terminal) the session silently
    becomes a no-op so callers can use ``progress_session(...)``
    unconditionally without branching.

    The class is thread-safe for concurrent ``advance()`` / ``message()``
    / ``set_status()`` calls from helper threads; the repaint lock is
    re-entrant so a callback invoked from inside a repaint can still
    update the session state without dead-locking.
    """

    _SPINNER_FRAMES = ("|", "/", "-", "\\")

    _MIN_ROWS = 3
    _MIN_COLS = 20

    # Throttle repaints so high-frequency ``advance()`` calls do not
    # hammer the terminal. 50 ms yields ~20 Hz which is smooth enough
    # for human perception and cheap for the emulator to flush.
    _MIN_REPAINT_INTERVAL_SECONDS = 0.05

    def __init__(
        self,
        title: str,
        *,
        total: Optional[int] = None,
        stream: Optional[TextIO] = None,
    ) -> None:
        self._title = str(title or "").strip()
        self._total = self._coerce_total(total)
        if stream is None:
            self._stream = sys.stderr
        else:
            self._stream = stream
        self._lock = threading.RLock()
        self._active = False
        self._completed = 0
        self._status = ""
        self._started_at = 0.0
        self._last_rendered_at = 0.0
        self._spinner_index = 0
        self._cached_rows = 0
        self._cached_cols = 0

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> "ProgressSession":
        if self._should_activate():
            self._activate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self._teardown()
        except Exception:
            # Teardown must never raise into the caller's error path.
            pass
        return None

    # -- public API ---------------------------------------------------------
    @property
    def is_active(self) -> bool:
        """Return ``True`` when the sticky footer is currently drawn."""
        return self._active

    @property
    def completed(self) -> int:
        """Return the number of steps counted so far."""
        return self._completed

    @property
    def total(self) -> Optional[int]:
        """Return the configured step total, or ``None`` for indeterminate."""
        return self._total

    def advance(self, step_label: str = "", count: int = 1) -> None:
        """Bump the completed counter and optionally update the status label.

        ``count`` may be any non-negative integer; callers that batch
        work can pass ``count=N`` to move the bar by ``N`` steps at
        once. ``step_label`` replaces the current status line when
        non-empty and forces a repaint regardless of the throttle so
        the operator always sees the phase transition. Counter-only
        bumps honour the repaint throttle to avoid hammering the
        terminal in per-byte / per-record update loops.
        """
        step_count = int(count)
        if step_count < 0:
            step_count = 0
        with self._lock:
            previous_completed = self._completed
            self._completed = self._completed + step_count
            if self._total is not None and self._completed > self._total:
                self._completed = self._total
            label_text = str(step_label or "").strip()
            status_changed = False
            if len(label_text) > 0 and label_text != self._status:
                self._status = label_text
                status_changed = True
            reached_total = False
            if self._total is not None:
                if previous_completed < self._total and self._completed >= self._total:
                    reached_total = True
            self._repaint(force=(status_changed or reached_total))

    def set_status(self, step_label: str) -> None:
        """Replace the status label without advancing the counter."""
        normalized_label = str(step_label or "").strip()
        with self._lock:
            label_changed = normalized_label != self._status
            self._status = normalized_label
            self._repaint(force=label_changed)

    def set_total(self, total: Optional[int]) -> None:
        """Update the step total (pass ``None`` to switch to indeterminate)."""
        with self._lock:
            self._total = self._coerce_total(total)
            if self._total is not None and self._completed > self._total:
                self._completed = self._total
            self._repaint(force=True)

    def message(self, text: str) -> None:
        """Print ``text`` above the sticky footer.

        When the session is inactive this falls back to a plain
        ``stream.write`` so callers can emit status lines without
        checking ``is_active``.
        """
        rendered_text = str(text or "")
        if self._active is False:
            self._write_raw(rendered_text + "\n")
            return
        with self._lock:
            # Writes inside the scroll region auto-scroll above the
            # sticky footer. We repaint afterwards so any flush
            # initiated by the write does not leave the footer stale.
            self._write_raw(rendered_text + "\n")
            self._repaint(force=True)

    # -- internals ----------------------------------------------------------
    @staticmethod
    def _coerce_total(total: Optional[int]) -> Optional[int]:
        if total is None:
            return None
        try:
            coerced = int(total)
        except (TypeError, ValueError):
            return None
        if coerced <= 0:
            return None
        return coerced

    def _should_activate(self) -> bool:
        if _progress_disabled_by_env():
            return False
        if _term_is_dumb():
            return False
        try:
            tty_attached = bool(self._stream.isatty())
        except Exception:
            tty_attached = False
        if tty_attached is False:
            return False
        rows, cols = self._terminal_size()
        if rows < self._MIN_ROWS:
            return False
        if cols < self._MIN_COLS:
            return False
        return True

    def _terminal_size(self) -> tuple[int, int]:
        try:
            size = shutil.get_terminal_size(fallback=(0, 0))
        except Exception:
            return (0, 0)
        cols_value = max(0, int(size.columns))
        rows_value = max(0, int(size.lines))
        return (rows_value, cols_value)

    def _write_raw(self, text: str) -> None:
        try:
            self._stream.write(text)
        except Exception:
            return
        try:
            self._stream.flush()
        except Exception:
            pass

    def _activate(self) -> None:
        rows, cols = self._terminal_size()
        self._cached_rows = rows
        self._cached_cols = cols
        self._active = True
        self._started_at = time.monotonic()
        self._last_rendered_at = 0.0
        # Push the cursor onto a fresh row so there is a sacrificial
        # line the scroll region can claim without overwriting
        # existing output already on the current row.
        payload_parts: list[str] = []
        payload_parts.append("\n")
        payload_parts.append(f"{_ESC}[1;{rows - 1}r")
        payload_parts.append(_HIDE_CURSOR)
        payload_parts.append(f"{_ESC}[{rows - 1};1H")
        self._write_raw("".join(payload_parts))
        self._repaint(force=True)

    def _teardown(self) -> None:
        if self._active is False:
            return
        self._active = False
        rows = self._cached_rows
        if rows <= 0:
            rows, _cols = self._terminal_size()
        payload_parts: list[str] = []
        payload_parts.append(_SAVE_CURSOR)
        if rows > 0:
            payload_parts.append(f"{_ESC}[{rows};1H")
            payload_parts.append(_CLEAR_LINE)
        payload_parts.append(_RESET_SCROLL_REGION)
        payload_parts.append(_RESTORE_CURSOR)
        payload_parts.append(_SHOW_CURSOR)
        # Trailing newline so the caller's next prompt / log line lands
        # on a fresh row rather than the cleared former-footer row.
        payload_parts.append("\n")
        self._write_raw("".join(payload_parts))

    def _repaint(self, *, force: bool = False) -> None:
        if self._active is False:
            return
        now = time.monotonic()
        if force is False:
            if (now - self._last_rendered_at) < self._MIN_REPAINT_INTERVAL_SECONDS:
                return
        self._last_rendered_at = now
        rows, cols = self._terminal_size()
        if rows < self._MIN_ROWS:
            return
        if cols < self._MIN_COLS:
            return
        payload_parts: list[str] = []
        if rows != self._cached_rows:
            # Terminal was resized while we were active; re-declare
            # the scroll region so the new bottom row is reserved.
            self._cached_rows = rows
            self._cached_cols = cols
            payload_parts.append(f"{_ESC}[1;{rows - 1}r")
        line_text = self._render_line(cols)
        payload_parts.append(_SAVE_CURSOR)
        payload_parts.append(f"{_ESC}[{rows};1H")
        payload_parts.append(_CLEAR_LINE)
        payload_parts.append(line_text)
        payload_parts.append(_RESTORE_CURSOR)
        self._write_raw("".join(payload_parts))

    def _render_line(self, cols: int) -> str:
        elapsed_seconds = time.monotonic() - self._started_at
        left_segments: list[str] = []
        if len(self._title) > 0:
            left_segments.append(self._title)
        status_text = self._status.strip()
        if len(status_text) > 0:
            left_segments.append(status_text)
        left_text = "  ".join(left_segments)
        right_segments: list[str] = []
        counters_text = self._render_counters()
        if len(counters_text) > 0:
            right_segments.append(counters_text)
        right_segments.append(_format_hms(elapsed_seconds))
        right_text = "  ".join(right_segments)
        bar_text = self._render_bar(cols, left_text, right_text)
        composed = f"{left_text}  {bar_text}  {right_text}"
        if len(composed) > cols:
            composed = composed[: cols]
        return composed

    def _render_counters(self) -> str:
        if self._total is None:
            return ""
        return f"{self._completed}/{self._total}"

    def _render_bar(self, cols: int, left_text: str, right_text: str) -> str:
        reserved_cells = len(left_text) + len(right_text) + 4
        available_cells = max(0, cols - reserved_cells)
        if available_cells < 6:
            if self._total is None:
                return self._advance_spinner_frame()
            pct_value = self._percent()
            return f"{pct_value:>3d}%"
        inner_width = available_cells - 2
        if self._total is None:
            return self._render_indeterminate_bar(inner_width)
        pct_value = self._percent()
        filled_cells = int(inner_width * (pct_value / 100.0))
        if filled_cells < 0:
            filled_cells = 0
        if filled_cells > inner_width:
            filled_cells = inner_width
        empty_cells = inner_width - filled_cells
        filled_text = "#" * filled_cells
        empty_text = " " * empty_cells
        return f"[{filled_text}{empty_text}] {pct_value:>3d}%"

    def _advance_spinner_frame(self) -> str:
        frame = self._SPINNER_FRAMES[self._spinner_index % len(self._SPINNER_FRAMES)]
        self._spinner_index = self._spinner_index + 1
        return frame

    def _render_indeterminate_bar(self, inner_width: int) -> str:
        frame = self._advance_spinner_frame()
        if inner_width <= 0:
            return frame
        position = self._spinner_index % inner_width
        body_cells = [" "] * inner_width
        body_cells[position] = frame
        return f"[{''.join(body_cells)}]"

    def _percent(self) -> int:
        if self._total is None:
            return 0
        if self._total <= 0:
            return 0
        pct_value = int((self._completed / self._total) * 100)
        if pct_value < 0:
            return 0
        if pct_value > 100:
            return 100
        return pct_value


# --- factory ---------------------------------------------------------------

def progress_session(
    title: str,
    *,
    total: Optional[int] = None,
    stream: Optional[TextIO] = None,
) -> ProgressSession:
    """Return a :class:`ProgressSession` suitable for a ``with`` block.

    ``title`` is shown on the left-hand side of the footer. ``total``
    switches the bar to determinate mode when set to a positive integer;
    pass ``None`` for a spinner-driven indeterminate bar. ``stream``
    defaults to :data:`sys.stderr` so that ``stdout`` redirection to a
    YAML/JSON report does not interleave with the footer.
    """
    return ProgressSession(title=title, total=total, stream=stream)


__all__ = ["ProgressSession", "progress_session"]
