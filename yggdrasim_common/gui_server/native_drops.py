# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Paths of files dropped onto the desktop window, handed to the page on request.

A browser never tells a page where a dropped file lives, and the desktop
webview is no different: a package dropped onto the SAIP workbench opened
as an ``upload:<name>`` copy with nowhere to save. pywebview 5.4 does
learn the paths -- every backend appends ``(basename, path)`` to
``webview.dom._dnd_state["paths"]`` on a native drop -- but only while
``_dnd_state["num_listeners"]`` is positive, and the one public way to
raise that count is a Python-side DOM listener, which runs on
``evaluate_js`` and fails under the page CSP (``upstream_patches/pywebview``
records both). This module raises the count itself once the window exists
and lets the page collect the paths over ``/api/gui/native_drop/resolve``
right after its own ``drop`` event, matched by file name and size the way
pywebview's bridge matches them. The private contract is verified before
it is relied on: a pywebview without that state leaves capture off and
drops keep opening as uploads.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Final, Optional, Sequence


_LOGGER = logging.getLogger("yggdrasim.gui.native_drops")

# pywebview appends an entry per dropped file and removes nothing itself;
# a drop the page never resolves (a file dropped on the terminal panel)
# would otherwise accumulate for the life of the process.
RECORDED_DROP_CAP: Final[int] = 64

# WebView2 hands the paths over from the page, asynchronously, so the
# resolve request can arrive before they are recorded; GTK and Qt record
# them before the DOM event fires and never wait.
RESOLVE_WAIT_S: Final[float] = 1.0
_RESOLVE_POLL_S: Final[float] = 0.05


@dataclass
class _CaptureState:
    enabled: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


_STATE = _CaptureState()


def _shared_state() -> Optional[dict[str, Any]]:
    """Return pywebview's drop record when the installed version carries it."""
    try:
        from webview import dom as webview_dom  # type: ignore
    except ImportError:
        return None
    state = getattr(webview_dom, "_dnd_state", None)
    if not isinstance(state, dict):
        return None
    if not isinstance(state.get("num_listeners"), int):
        return None
    if not isinstance(state.get("paths"), list):
        return None
    return state


def enable_native_drop_capture() -> bool:
    """Make every pywebview backend record dropped paths; return whether it will.

    Fails closed: without the expected state the switch stays off, the
    reason is logged once, and the page's resolve requests answer with no
    paths, so a drop opens as an upload as it did before.
    """
    state = _shared_state()
    if state is None:
        _LOGGER.warning(
            "dropped-file paths unavailable: this pywebview carries no "
            "dom._dnd_state of the expected shape; drops open as uploads."
        )
        return False
    with _STATE.lock:
        if not _STATE.enabled:
            state["num_listeners"] += 1
            _STATE.enabled = True
    return True


def capture_enabled() -> bool:
    with _STATE.lock:
        return _STATE.enabled


def _take_locked(state: dict[str, Any], name: str, size: Optional[int]) -> Optional[str]:
    """Consume and return the oldest recorded entry for ``name``, or None.

    An entry is a match when its basename decodes to ``name``, its file
    exists and, when the page reported a size, the file has that size. A
    consumed entry cannot serve a later drop of a same-named file.
    """
    recorded = state["paths"]
    for entry in list(recorded):
        try:
            basename, raw_path = entry[0], entry[1]
        except (TypeError, IndexError, KeyError):
            continue
        if urllib.parse.unquote(str(basename)) != name:
            continue
        path = urllib.parse.unquote(str(raw_path))
        if not os.path.isfile(path):
            continue
        if size is not None:
            try:
                if os.path.getsize(path) != int(size):
                    continue
            except OSError:
                continue
        try:
            recorded.remove(entry)
        except ValueError:
            continue
        return path
    return None


def resolve_dropped_paths(
    files: Sequence[tuple[str, Optional[int]]],
    *,
    wait_s: float = RESOLVE_WAIT_S,
) -> list[Optional[str]]:
    """Return the on-disk path of each dropped file, aligned with ``files``.

    ``files`` is the page's ``(name, size)`` per ``File`` in drop order.
    A file the record cannot place resolves to None and its caller falls
    back to the upload route. With capture off the answer is immediate.
    """
    answers: list[Optional[str]] = [None] * len(files)
    if len(files) == 0 or not capture_enabled():
        return answers
    state = _shared_state()
    if state is None:
        return answers
    deadline = time.monotonic() + max(0.0, float(wait_s))
    while True:
        with _STATE.lock:
            recorded = state["paths"]
            if len(recorded) > RECORDED_DROP_CAP:
                del recorded[:-RECORDED_DROP_CAP]
            for index, (name, size) in enumerate(files):
                if answers[index] is None:
                    answers[index] = _take_locked(state, str(name), size)
        if all(answer is not None for answer in answers):
            return answers
        if time.monotonic() >= deadline:
            return answers
        time.sleep(_RESOLVE_POLL_S)
