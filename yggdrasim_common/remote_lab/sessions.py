# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Remote Lab in-memory lock and session manager."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .config import RemoteLabDefaults, RigConfig


class RigBusyError(RuntimeError):
    def __init__(self, message: str, *, payload: dict[str, Any]) -> None:
        super().__init__(message)
        self.payload = dict(payload)


@dataclass(slots=True)
class LockRecord:
    resource_id: str
    held_by_session: str
    expires_at: float


@dataclass(slots=True)
class LabSession:
    id: str
    token: str
    rig_id: str
    locks: tuple[str, ...]
    user: str
    client_id: str
    state: str
    created_at: float
    started_at: float = 0.0
    last_heartbeat_at: float = 0.0
    expires_at: float = 0.0
    reservation_expires_at: float = 0.0
    max_expires_at: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    error: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self, *, include_token: bool = False) -> dict[str, Any]:
        payload = {
            "session_id": self.id,
            "rig_id": self.rig_id,
            "status": self.state,
            "user": self.user,
            "client_id": self.client_id,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "expires_at": self.expires_at,
            "reservation_expires_at": self.reservation_expires_at,
            "max_expires_at": self.max_expires_at,
            "locks": list(self.locks),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }
        if include_token:
            payload["session_token"] = self.token
        return payload


class LabSessionManager:
    def __init__(
        self,
        rigs: list[RigConfig] | tuple[RigConfig, ...],
        defaults: RemoteLabDefaults,
        *,
        clock: Any = time.time,
    ) -> None:
        self._rigs = {rig.id: rig for rig in rigs}
        self._defaults = defaults
        self._clock = clock
        self._sessions: dict[str, LabSession] = {}
        self._locks: dict[str, LockRecord] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        rig_id: str,
        *,
        user: str = "",
        client_id: str = "",
        requested_ttl_seconds: int = 3600,
    ) -> LabSession:
        with self._lock:
            self.expire_stale_locked()
            rig = self._rigs.get(str(rig_id or "").strip())
            if rig is None:
                raise KeyError(f"unknown rig: {rig_id!r}")
            if not rig.enabled:
                raise RigBusyError(
                    "rig is in maintenance",
                    payload={"error": "rig_maintenance", "message": "Rig is in maintenance."},
                )
            conflicts = [self._locks[lock_id] for lock_id in rig.locks if lock_id in self._locks]
            if conflicts:
                conflict = conflicts[0]
                holder = self._sessions.get(conflict.held_by_session)
                raise RigBusyError(
                    "rig is busy",
                    payload={
                        "error": "rig_busy",
                        "message": "Rig or shared resource is currently in use.",
                        "locked_by": holder.user if holder else "",
                        "started_at": holder.started_at if holder else 0,
                        "expires_at": holder.expires_at if holder else conflict.expires_at,
                        "held_resource": conflict.resource_id,
                    },
                )

            now = float(self._clock())
            ttl = max(1, min(int(requested_ttl_seconds or 3600), self._defaults.max_session_seconds))
            session = LabSession(
                id=secrets.token_hex(16),
                token=secrets.token_urlsafe(32),
                rig_id=rig.id,
                locks=tuple(rig.locks),
                user=str(user or "").strip(),
                client_id=str(client_id or "").strip(),
                state="reserved",
                created_at=now,
                last_heartbeat_at=now,
                expires_at=now + ttl,
                reservation_expires_at=now + self._defaults.reservation_timeout_seconds,
                max_expires_at=now + self._defaults.max_session_seconds,
            )
            for lock_id in session.locks:
                self._locks[lock_id] = LockRecord(
                    resource_id=lock_id,
                    held_by_session=session.id,
                    expires_at=session.expires_at,
                )
            self._sessions[session.id] = session
            return session

    def get(self, session_id: str) -> LabSession | None:
        with self._lock:
            self.expire_stale_locked()
            return self._sessions.get(str(session_id or "").strip())

    def status_for_rig(self, rig_id: str) -> tuple[str, LabSession | None]:
        with self._lock:
            self.expire_stale_locked()
            for session in self._sessions.values():
                if session.rig_id == rig_id:
                    return session.state, session
            return "available", None

    def validate_for_rig(self, rig_id: str, token: str) -> LabSession:
        with self._lock:
            self.expire_stale_locked()
            for session in self._sessions.values():
                if session.rig_id == rig_id and session.token == str(token or "").strip():
                    now = float(self._clock())
                    if now > session.expires_at or now > session.max_expires_at:
                        self._release_locked(session.id)
                        raise PermissionError("session expired")
                    return session
            raise PermissionError("missing or invalid Remote Lab session token")

    def mark_stream_use(self, session: LabSession) -> None:
        with self._lock:
            if session.id not in self._sessions:
                raise PermissionError("session no longer active")
            now = float(self._clock())
            if session.state == "reserved":
                session.state = "busy"
                session.started_at = now
            session.last_heartbeat_at = now

    def record_bytes(self, session_id: str, *, bytes_in: int = 0, bytes_out: int = 0) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session.bytes_in += max(0, int(bytes_in))
            session.bytes_out += max(0, int(bytes_out))

    def heartbeat(self, session_id: str, token: str) -> LabSession:
        with self._lock:
            session = self._sessions.get(str(session_id or "").strip())
            if session is None or session.token != str(token or "").strip():
                raise PermissionError("missing or invalid session token")
            now = float(self._clock())
            if now > session.expires_at or now > session.max_expires_at:
                self._release_locked(session.id)
                raise PermissionError("session expired")
            session.last_heartbeat_at = now
            for lock_id in session.locks:
                if lock_id in self._locks:
                    self._locks[lock_id].expires_at = session.expires_at
            return session

    def release(self, session_id: str, token: str = "", *, force: bool = False) -> LabSession | None:
        with self._lock:
            session = self._sessions.get(str(session_id or "").strip())
            if session is None:
                return None
            if not force and session.token != str(token or "").strip():
                raise PermissionError("missing or invalid session token")
            self._release_locked(session.id)
            return session

    def force_release_rig(self, rig_id: str) -> LabSession | None:
        with self._lock:
            for session in list(self._sessions.values()):
                if session.rig_id == rig_id:
                    self._release_locked(session.id)
                    return session
            return None

    def expire_stale(self) -> int:
        with self._lock:
            return self.expire_stale_locked()

    def expire_stale_locked(self) -> int:
        now = float(self._clock())
        expired: list[str] = []
        for session in list(self._sessions.values()):
            if session.state == "reserved" and now >= session.reservation_expires_at:
                expired.append(session.id)
                continue
            if now >= session.expires_at or now >= session.max_expires_at:
                expired.append(session.id)
                continue
            if now - session.last_heartbeat_at >= self._defaults.heartbeat_timeout_seconds:
                expired.append(session.id)
        for session_id in expired:
            self._release_locked(session_id)
        return len(expired)

    def _release_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        for lock_id in session.locks:
            record = self._locks.get(lock_id)
            if record is not None and record.held_by_session == session.id:
                self._locks.pop(lock_id, None)

    def sessions(self) -> list[LabSession]:
        with self._lock:
            self.expire_stale_locked()
            return list(self._sessions.values())

    def locks(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            self.expire_stale_locked()
            return {
                lock_id: {
                    "held_by_session": record.held_by_session,
                    "expires_at": record.expires_at,
                }
                for lock_id, record in self._locks.items()
            }
