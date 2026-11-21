# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Final, Optional


_LOGGER = logging.getLogger("yggdrasim.gui.sessions")


# Idle ceiling for a session that owns a PC/SC handle. The workbench
# renders a decoded file from its own cache, so an operator reading one
# never reaches the backend to refresh the clock -- the ceiling covers
# reading time, not click frequency, and a card left in an unattended
# reader still frees its handle within it.
DEFAULT_CARD_SESSION_IDLE_S: Final[float] = 900.0

CARD_SESSION_IDLE_ENV: Final[str] = "YGGDRASIM_GUI_CARD_SESSION_IDLE_SECONDS"


# In-memory authoring handles set this flag while they contain unsaved work.
# The generic session manager deliberately does not inspect subsystem-specific
# dirty-state shapes; this single opt-in key is the cross-subsystem contract.
AUTO_CLOSE_PROTECTION_HANDLE_KEY = "__ygg_protect_from_automatic_close__"


def _operator_card_session_idle_seconds() -> Optional[float]:
    """Return the operator's idle ceiling, or None when unset or unusable.

    Resolved per ``open()`` rather than in ``__init__``: the manager is a
    module singleton built at import, so a value bound there would freeze
    whatever the process started with and the GUI's Environment ->
    Configuration view could never move it. The persistence file is read
    directly because the GUI console scripts do not call
    ``apply_persisted_env_overrides`` -- ``yggdrasim_common/cli_theme.py``
    reads its own flag the same way.
    """
    raw = str(os.environ.get(CARD_SESSION_IDLE_ENV, "") or "").strip()
    if len(raw) == 0:
        try:
            from yggdrasim_common.env_flags import load_persisted_overrides
            raw = str(load_persisted_overrides().get(CARD_SESSION_IDLE_ENV, "") or "").strip()
        except (ImportError, OSError):
            # Resolving the runtime root touches the filesystem. The
            # ceiling is housekeeping, so a root that cannot be read
            # falls back rather than stopping a session from opening.
            return None
    if len(raw) == 0:
        return None
    try:
        parsed = float(raw)
    except ValueError:
        _LOGGER.warning(
            "%s=%r is not a number; using the built-in ceiling.",
            CARD_SESSION_IDLE_ENV,
            raw,
        )
        return None
    if parsed <= 0.0:
        _LOGGER.warning(
            "%s=%r is not positive; using the built-in ceiling.",
            CARD_SESSION_IDLE_ENV,
            raw,
        )
        return None
    return parsed


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
    # Reentrant: a dispatcher holding this may call a sibling dispatcher on
    # the same session (scp03 does so in ~11 places, e.g. enable_profile ->
    # profile_lifecycle), which a plain Lock would deadlock.
    _lock: threading.RLock
    protect_from_auto_close: bool = False
    # A kind that names its own ceiling is counted against it alone and
    # stays out of the shared pool ``max_sessions`` bounds.
    max_of_kind: Optional[int] = None

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
            "protect_from_auto_close": self.is_auto_close_protected(),
            "max_of_kind": self.max_of_kind,
            "metadata": dict(self.metadata),
        }

    def is_auto_close_protected(self) -> bool:
        """Return whether idle/cap cleanup must leave this session alone."""
        if self.protect_from_auto_close:
            return True
        if isinstance(self.handle, dict):
            return bool(self.handle.get(AUTO_CLOSE_PROTECTION_HANDLE_KEY))
        return False


class SessionManager:
    def __init__(
        self,
        *,
        max_sessions: int = 8,
        default_idle_timeout_s: Optional[float] = None,
    ) -> None:
        self._sessions: dict[str, CardSession] = {}
        self._lock = threading.Lock()
        self._max_sessions = int(max_sessions)
        # A caller that names its own ceiling keeps it: the env flag tunes
        # the shipped default, it does not overrule a deliberate choice.
        self._default_is_caller_chosen = default_idle_timeout_s is not None
        self._default_idle_timeout_s = float(
            DEFAULT_CARD_SESSION_IDLE_S
            if default_idle_timeout_s is None
            else default_idle_timeout_s
        )

    # ---- lifecycle ----------------------------------------------------

    def _resolve_idle_timeout(self, requested: Optional[float]) -> float:
        """Return the ceiling for a session opening now.

        Precedence: the dispatcher's own value (SAIP authoring asks for
        hours), then a caller-chosen manager default, then the operator's
        flag, then the shipped default.
        """
        if requested is not None:
            return float(requested)
        if self._default_is_caller_chosen:
            return self._default_idle_timeout_s
        operator_choice = _operator_card_session_idle_seconds()
        if operator_choice is not None:
            return operator_choice
        return self._default_idle_timeout_s

    def open(
        self,
        *,
        kind: str,
        handle: Any,
        close: Callable[[], None],
        idle_timeout_s: Optional[float] = None,
        protect_from_auto_close: bool = False,
        max_of_kind: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> CardSession:
        """Register a session and return it.

        ``max_sessions`` bounds the shared pool: every kind that names no
        ceiling of its own, which is the kinds holding a reader. A kind
        that passes ``max_of_kind`` is counted against that ceiling alone
        -- it neither fills the shared pool nor is evicted to make room
        in it -- and is refused, not evicted, once the ceiling is reached.
        """
        self._reap_idle_locked_unsafe()  # cheap no-op if no idle peers
        with self._lock:
            if max_of_kind is None:
                self._make_room_in_shared_pool_locked()
            else:
                self._assert_kind_ceiling_locked(str(kind), int(max_of_kind))
            session_id = secrets.token_hex(8)
            timeout = self._resolve_idle_timeout(idle_timeout_s)
            now = time.time()
            session = CardSession(
                id=session_id,
                kind=str(kind),
                handle=handle,
                close=close,
                created_at=now,
                last_used_at=now,
                idle_timeout_s=float(timeout),
                protect_from_auto_close=bool(protect_from_auto_close),
                max_of_kind=None if max_of_kind is None else int(max_of_kind),
                metadata=dict(metadata or {}),
                _lock=threading.RLock(),
            )
            self._sessions[session_id] = session
            _LOGGER.info("session opened kind=%s id=%s", kind, session_id)
            return session

    def _make_room_in_shared_pool_locked(self) -> None:
        pool = [
            entry for entry in self._sessions.values() if entry.max_of_kind is None
        ]
        if len(pool) < self._max_sessions:
            return
        # Never discard protected authoring work to make room. Prefer the
        # oldest unprotected session; if every live session is protected,
        # make the caller ask the operator to close one.
        candidates = [
            entry for entry in pool if entry.is_auto_close_protected() is False
        ]
        if len(candidates) == 0:
            raise RuntimeError(
                "session cap reached and every live session contains "
                "protected work; save or close a session before opening another."
            )
        oldest = min(candidates, key=lambda entry: entry.last_used_at)
        _LOGGER.info(
            "session cap reached (%d); evicting %s/%s",
            self._max_sessions,
            oldest.kind,
            oldest.id,
        )
        self._close_session_locked(oldest)

    def _assert_kind_ceiling_locked(self, kind: str, ceiling: int) -> None:
        """Refuse ``kind`` at its ceiling rather than evict a peer.

        A kind with a ceiling of its own holds documents, not readers. The
        operator loaded each one on purpose, so a clean peer vanishing to
        admit the next is the defect the ceiling rules out; the idle
        reaper still reclaims what a closed page left behind.
        """
        live = sum(1 for entry in self._sessions.values() if entry.kind == kind)
        if live >= ceiling:
            raise RuntimeError(
                f"{kind} session ceiling reached ({ceiling} open); "
                "close one before opening another."
            )

    def close(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        self._invoke_close(session)
        return True

    def release(self, session_id: str) -> bool:
        """Compatibility alias for an explicit operator/test close."""
        return self.close(session_id)

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
        finally:
            self._clear_apdu_raw_capture(session)

    @staticmethod
    def _clear_apdu_raw_capture(session: CardSession) -> None:
        """Purge reader-scoped raw APDUs when their owning session closes."""
        scope = str(session.metadata.get("apdu_scope") or "").strip()
        if not scope:
            scope = str(session.metadata.get("reader_name") or "").strip()
        if not scope or scope == "(default)":
            return
        try:
            from yggdrasim_common.apdu_recorder import get_recorder

            get_recorder().disable_raw_capture(scope)
        except Exception as cleanup_error:  # noqa: BLE001 -- session close must continue
            _LOGGER.warning(
                "APDU raw-capture cleanup failed kind=%s id=%s (%s)",
                session.kind,
                session.id,
                type(cleanup_error).__name__,
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

    def reap_idle(
        self,
        *,
        select: Optional[Callable[[CardSession], bool]] = None,
    ) -> int:
        """Close idle sessions, optionally narrowed to ``select``.

        A caller that owns one subsystem passes a predicate so its own
        housekeeping cannot decide the lifetime of unrelated work.
        Without one the sweep covers the whole store, which is what
        ``open()`` wants before it admits a new session.
        """
        return self._reap_idle_locked_unsafe(select=select)

    def _reap_idle_locked_unsafe(
        self,
        *,
        select: Optional[Callable[[CardSession], bool]] = None,
    ) -> int:
        now = time.time()
        victims: list[CardSession] = []
        with self._lock:
            for session in list(self._sessions.values()):
                if session.is_idle(now=now) is False:
                    continue
                if session.is_auto_close_protected():
                    continue
                if select is not None and select(session) is False:
                    continue
                victims.append(session)
                self._sessions.pop(session.id, None)
        for session in victims:
            _LOGGER.info("session idle-reaped kind=%s id=%s", session.kind, session.id)
            self._invoke_close(session)
        return len(victims)


_MANAGER = SessionManager()


def get_manager() -> SessionManager:
    return _MANAGER
