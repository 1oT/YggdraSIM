# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""In-process card-session manager for Command Center actions.

Some actions hold a live PC/SC connection for multiple round-trips
(e.g. SCP03 scan → click-to-select → read FCP → read binary). Opening /
closing the reader on every click would be unusable. This module keeps
bounded, idle-timed-out sessions keyed by opaque ``session_id``.

Design constraints
------------------

* **Never leak card handles.** Every session has an idle timer; when it
  fires (or when the GUI explicitly closes), ``disconnect()`` is called.
* **Single session per ``kind`` by default.** The GUI only ever drives
  one card at a time. The default limit is 4 sessions total — more than
  enough for the foreseeable Command Center surface and still cheap.
* **Thread-safe.** FastAPI handlers may hit the registry concurrently
  (HTTP + WS). A single ``threading.Lock`` guards the dict.
* **No imports of pyscard / SCP03 at module load time.** The manager is
  generic; concrete "opener" callables are provided by each dispatcher.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional


_LOGGER = logging.getLogger("yggdrasim.gui.sessions")


@dataclass
class CardSession:
    """One live PC/SC-backed session.

    Attributes
    ----------
    id
        Opaque 16-byte hex string; the GUI passes it back on every call.
    kind
        Short label, e.g. ``scp03`` / ``scp11-live``. Used for logging
        and "close all sessions of this kind" housekeeping.
    handle
        The actual live object (e.g. ``CardTransporter``). Action
        dispatchers unwrap this with :meth:`claim`.
    close
        Callable invoked on disconnect / idle-timeout.
    created_at
        Wall-clock timestamp (``time.time()``).
    last_used_at
        Wall-clock timestamp of the last :meth:`touch`.
    idle_timeout_s
        Seconds of inactivity before the reaper closes this session.
    metadata
        Free-form extra info (reader name, ATR, …) surfaced in the
        ``/api/sessions`` listing.
    """

    id: str
    kind: str
    handle: Any
    close: Callable[[], None]
    created_at: float
    last_used_at: float
    idle_timeout_s: float
    metadata: dict[str, Any]
    _lock: threading.Lock

    def touch(self) -> None:
        self.last_used_at = time.time()

    def is_idle(self, *, now: Optional[float] = None) -> bool:
        probe = now if now is not None else time.time()
        return (probe - self.last_used_at) >= self.idle_timeout_s

    def to_dict(self) -> dict[str, Any]:
        """Serialise this session record to a JSON-compatible dict."""
        return {
            "id": self.id,
            "kind": self.kind,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "idle_timeout_s": self.idle_timeout_s,
            "metadata": dict(self.metadata),
        }


class SessionManager:
    """Process-wide, thread-safe session registry."""

    def __init__(
        self,
        *,
        max_sessions: int = 4,
        default_idle_timeout_s: float = 180.0,
    ) -> None:
        self._sessions: dict[str, CardSession] = {}
        self._lock = threading.Lock()
        self._max_sessions = int(max_sessions)
        self._default_idle_timeout_s = float(default_idle_timeout_s)

    # ---- lifecycle ----------------------------------------------------

    def open(
        self,
        *,
        kind: str,
        handle: Any,
        close: Callable[[], None],
        idle_timeout_s: Optional[float] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> CardSession:
        """Register a new session. Reaps idle peers first to stay under the cap."""
        self._reap_idle_locked_unsafe()  # cheap no-op if no idle peers
        with self._lock:
            if len(self._sessions) >= self._max_sessions:
                # Evict the oldest one to make room. Better than 503-ing.
                oldest = min(self._sessions.values(), key=lambda entry: entry.last_used_at)
                _LOGGER.info(
                    "session cap reached (%d); evicting %s/%s",
                    self._max_sessions,
                    oldest.kind,
                    oldest.id,
                )
                self._close_session_locked(oldest)
            session_id = secrets.token_hex(8)
            timeout = idle_timeout_s if idle_timeout_s is not None else self._default_idle_timeout_s
            now = time.time()
            session = CardSession(
                id=session_id,
                kind=str(kind),
                handle=handle,
                close=close,
                created_at=now,
                last_used_at=now,
                idle_timeout_s=float(timeout),
                metadata=dict(metadata or {}),
                _lock=threading.Lock(),
            )
            self._sessions[session_id] = session
            _LOGGER.info("session opened kind=%s id=%s", kind, session_id)
            return session

    def close(self, session_id: str) -> bool:
        """Terminate this session and release associated resources."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        self._invoke_close(session)
        return True

    def close_all(self) -> int:
        """Terminate all active sessions in the session store."""
        with self._lock:
            live = list(self._sessions.values())
            self._sessions.clear()
        for session in live:
            self._invoke_close(session)
        return len(live)

    def _close_session_locked(self, session: CardSession) -> None:
        """Caller already holds ``self._lock``."""
        self._sessions.pop(session.id, None)
        self._invoke_close(session)

    def _invoke_close(self, session: CardSession) -> None:
        try:
            session.close()
        except Exception as close_error:  # noqa: BLE001
            _LOGGER.warning(
                "session close failed kind=%s id=%s (%s: %s)",
                session.kind,
                session.id,
                type(close_error).__name__,
                close_error,
            )

    # ---- access -------------------------------------------------------

    def get(self, session_id: str) -> CardSession:
        """Return the session record for the given session ID, or None."""
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"unknown session: {session_id!r}")
        session.touch()
        return session

    def has(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._sessions

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [session.to_dict() for session in self._sessions.values()]

    def claim(self, session_id: str) -> Any:
        """Return the underlying handle for a session, touching the timestamp."""
        return self.get(session_id).handle

    # ---- reaper -------------------------------------------------------

    def reap_idle(self) -> int:
        """Close every session past its idle deadline. Returns the close count."""
        return self._reap_idle_locked_unsafe()

    def _reap_idle_locked_unsafe(self) -> int:
        now = time.time()
        victims: list[CardSession] = []
        with self._lock:
            for session in list(self._sessions.values()):
                if session.is_idle(now=now):
                    victims.append(session)
                    self._sessions.pop(session.id, None)
        for session in victims:
            _LOGGER.info("session idle-reaped kind=%s id=%s", session.kind, session.id)
            self._invoke_close(session)
        return len(victims)


_MANAGER = SessionManager()


def get_manager() -> SessionManager:
    return _MANAGER
