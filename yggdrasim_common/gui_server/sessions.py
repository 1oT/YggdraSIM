# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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
        return {
            "id": self.id,
            "kind": self.kind,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "idle_timeout_s": self.idle_timeout_s,
            "metadata": dict(self.metadata),
        }


class SessionManager:
    def __init__(
        self,
        *,
        max_sessions: int = 8,
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
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        self._invoke_close(session)
        return True

    def close_all(self) -> int:
        with self._lock:
            live = list(self._sessions.values())
            self._sessions.clear()
        for session in live:
            self._invoke_close(session)
        return len(live)

    def _close_session_locked(self, session: CardSession) -> None:
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
        return self.get(session_id).handle

    # ---- reaper -------------------------------------------------------

    def reap_idle(self) -> int:
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
