# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Cooperative cancellation for long-running console work.

The GUI's streaming routes build one :class:`threading.Event` per run and
publish it on ``ActionContext.extras['cancel_event']``. Work reached
through a console object -- an eIM poll loop, a STATUS watchdog -- runs
in a worker thread that never sees that context, so the flag travels on
the console itself under one documented attribute name. A plugin can
then honour Stop without importing anything from the GUI server.

Cancellation is cooperative: setting the event asks a loop to stop at its
next checkpoint. Nothing here interrupts an APDU exchange already in
flight, and nothing here kills a thread.

The module also tracks the events of in-flight runs so shutdown can ask
every active loop to stop at once, which is what keeps a never-ending
poll from holding the GUI server open when the desktop window closes.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from weakref import WeakSet

CANCEL_ATTRIBUTE = "yggdrasim_cancel_event"

_ACTIVE_EVENTS: WeakSet[threading.Event] = WeakSet()
_ACTIVE_LOCK = threading.Lock()


def attach_cancel_event(target: Any, event: threading.Event | None) -> bool:
    """Publish ``event`` on ``target`` for worker-thread code to consult.

    Returns ``False`` when the target rejects attribute assignment (a
    ``__slots__`` class, a C extension type), which is not an error: the
    caller simply loses cancellation for that run rather than failing it.
    """
    if event is None:
        return False
    try:
        setattr(target, CANCEL_ATTRIBUTE, event)
    except (AttributeError, TypeError):
        return False
    return True


def detach_cancel_event(target: Any) -> None:
    """Remove a previously attached event, ignoring an absent attribute."""
    try:
        delattr(target, CANCEL_ATTRIBUTE)
    except (AttributeError, TypeError):
        pass


def cancel_event_for(target: Any) -> threading.Event | None:
    """Return the event attached to ``target``, or ``None``."""
    event = getattr(target, CANCEL_ATTRIBUTE, None)
    if isinstance(event, threading.Event):
        return event
    return None


def cancel_requested(target: Any) -> bool:
    """Report whether a stop has been asked for on ``target``."""
    event = cancel_event_for(target)
    if event is None:
        return False
    return bool(event.is_set())


def sleep_unless_cancelled(target: Any, seconds: float) -> bool:
    """Sleep, waking early if a stop is requested.

    Returns ``True`` when the wait ended because cancellation was
    requested. Poll cadences are measured in tens of seconds, so a plain
    ``time.sleep`` there is what makes a Stop button feel dead even after
    the loop learns to check the flag.
    """
    duration = max(0.0, float(seconds))
    event = cancel_event_for(target)
    if event is None:
        time.sleep(duration)
        return False
    return bool(event.wait(duration))


def register_active_event(event: threading.Event | None) -> None:
    """Track an in-flight run's event so shutdown can cancel it."""
    if event is None:
        return
    with _ACTIVE_LOCK:
        _ACTIVE_EVENTS.add(event)


def cancel_all_active_events() -> int:
    """Ask every in-flight run to stop; returns how many were signalled."""
    with _ACTIVE_LOCK:
        events = list(_ACTIVE_EVENTS)
    signalled = 0
    for event in events:
        if event.is_set():
            continue
        event.set()
        signalled += 1
    return signalled


__all__ = [
    "CANCEL_ATTRIBUTE",
    "attach_cancel_event",
    "cancel_all_active_events",
    "cancel_event_for",
    "cancel_requested",
    "detach_cancel_event",
    "register_active_event",
    "sleep_unless_cancelled",
]
