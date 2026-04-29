"""In-process CAMARA Quality-on-Demand v1.0.0 stub client.

Mirrors the public surface that ``sunrise6g_opensdk``'s
``BaseNetworkClient`` exposes for QoD:

* ``create_qod_session(session_info)`` -- POST /sessions
* ``get_qod_session(session_id)``      -- GET  /sessions/{id}
* ``delete_qod_session(session_id)``   -- DELETE /sessions/{id}

Plus a few helpers no real CAMARA gateway exposes -- ``list``,
``expire_due``, ``clear`` -- that the Command Center uses to drive
the demo. The stub keeps everything in-memory and is thread-safe.
Each call validates inputs against the same constraints CAMARA
QoD v1.0.0 imposes (qosProfile enum, duration bounds, IPv4
literals) so a payload that succeeds here will also succeed
against a real NEF.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import replace
from typing import Any, Optional

from .models import (
    DeviceIdentity,
    QodSession,
    QosProfile,
    QosStatus,
    SUPPORTED_QOS_PROFILES,
)


DEFAULT_QOD_DURATION_SECONDS = 3_600


class QodStubError(RuntimeError):
    """Raised when a stub call cannot complete."""


class QodSessionNotFoundError(QodStubError):
    """Raised when ``session_id`` does not match any live session."""


class QodStubClient:
    """Process-local QoD session manager.

    The :meth:`create_qod_session` API takes a CAMARA-shape dict (or
    keyword arguments). It returns a CAMARA ``SessionInfo`` dict
    with a UUID-shaped ``sessionId``.
    """

    def __init__(
        self,
        *,
        clock: Any = None,
        id_factory: Any = None,
    ) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, QodSession] = {}
        self._clock = clock or time.time
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))

    # ------------------------------------------------------------------
    # CAMARA-shaped surface
    # ------------------------------------------------------------------

    def create_qod_session(
        self,
        session_info: Optional[dict[str, Any]] = None,
        **overrides: Any,
    ) -> dict[str, Any]:
        merged = dict(session_info or {})
        merged.update(overrides)
        device = _device_from_payload(merged.get("device"))
        application_server_ip = _application_server_ipv4(merged.get("applicationServer"))
        qos_profile = _qos_profile(merged.get("qosProfile"))
        duration_seconds = int(merged.get("duration") or DEFAULT_QOD_DURATION_SECONDS)
        sink_url = merged.get("sink")
        device_ports = _ports(merged.get("devicePorts"))
        application_server_ports = _ports(merged.get("applicationServerPorts"))

        session = QodSession(
            session_id=self._id_factory(),
            device=device,
            application_server_ip=application_server_ip,
            qos_profile=qos_profile,
            duration_seconds=duration_seconds,
            started_at_unix=float(self._clock()),
            sink_url=sink_url,
            device_ports=tuple(device_ports),
            application_server_ports=tuple(application_server_ports),
            status=QosStatus.AVAILABLE,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session.to_camara_session_info()

    def get_qod_session(self, session_id: str) -> dict[str, Any]:
        session = self._lookup(session_id)
        return session.to_camara_session_info()

    def delete_qod_session(self, session_id: str) -> None:
        with self._lock:
            removed = self._sessions.pop(_coerce_id(session_id), None)
        if removed is None:
            raise QodSessionNotFoundError(f"unknown sessionId: {session_id!r}")

    # ------------------------------------------------------------------
    # Helpers (not part of the CAMARA surface)
    # ------------------------------------------------------------------

    def list_sessions(self, *, include_expired: bool = False) -> list[dict[str, Any]]:
        now_unix = float(self._clock())
        with self._lock:
            sessions = sorted(self._sessions.values(), key=lambda s: s.started_at_unix)
        live = []
        for session in sessions:
            if not include_expired and session.is_expired(now_unix=now_unix):
                continue
            view = session.to_camara_session_info()
            view["remainingDurationSeconds"] = session.remaining_seconds(now_unix=now_unix)
            view["expired"] = session.is_expired(now_unix=now_unix)
            live.append(view)
        return live

    def expire_due(self) -> int:
        now_unix = float(self._clock())
        with self._lock:
            expired_ids = [
                sid for sid, s in self._sessions.items() if s.is_expired(now_unix=now_unix)
            ]
            for sid in expired_ids:
                self._sessions.pop(sid, None)
        return len(expired_ids)

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def clear(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
        return count

    def find_by_device(self, device: DeviceIdentity) -> list[dict[str, Any]]:
        target = device.stable_key()
        with self._lock:
            sessions = [
                s.to_camara_session_info()
                for s in self._sessions.values()
                if s.device.stable_key() == target
            ]
        return sessions

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _lookup(self, session_id: str) -> QodSession:
        normalised = _coerce_id(session_id)
        with self._lock:
            session = self._sessions.get(normalised)
        if session is None:
            raise QodSessionNotFoundError(f"unknown sessionId: {session_id!r}")
        if session.is_expired(now_unix=float(self._clock())):
            raise QodSessionNotFoundError(
                f"sessionId {session_id!r} has expired"
            )
        return session


# ----------------------------------------------------------------------
# Coercion helpers
# ----------------------------------------------------------------------


def _coerce_id(session_id: Any) -> str:
    text = str(session_id or "").strip()
    if not text:
        raise QodStubError("sessionId must not be empty")
    return text


def _device_from_payload(payload: Any) -> DeviceIdentity:
    if isinstance(payload, DeviceIdentity):
        return payload
    if not isinstance(payload, dict):
        raise QodStubError("device payload must be a dict or DeviceIdentity")
    device = DeviceIdentity.from_camara(payload)
    if device.is_empty():
        raise QodStubError("device must carry at least one identifier")
    return device


def _application_server_ipv4(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        ipv4 = payload.get("ipv4Address")
        if isinstance(ipv4, str):
            return ipv4
        if isinstance(ipv4, dict):
            address = ipv4.get("publicAddress") or ipv4.get("privateAddress")
            if isinstance(address, str):
                return address
    raise QodStubError(
        "applicationServer.ipv4Address must be present (CAMARA QoD §4.5.2)"
    )


def _qos_profile(value: Any) -> QosProfile:
    text = str(value or "").strip().upper()
    if text not in SUPPORTED_QOS_PROFILES:
        raise QodStubError(
            f"qosProfile must be one of {SUPPORTED_QOS_PROFILES}; got {value!r}"
        )
    return text


def _ports(payload: Any) -> list[int]:
    if payload is None:
        return []
    if isinstance(payload, dict):
        ports = list(payload.get("ports") or [])
    elif isinstance(payload, (list, tuple)):
        ports = list(payload)
    else:
        raise QodStubError(f"port payload must be a dict / list (got {type(payload).__name__})")
    return [int(p) for p in ports]


# ----------------------------------------------------------------------
# Module-level singleton (used by the GUI dispatcher)
# ----------------------------------------------------------------------


_DEFAULT_CLIENT: Optional[QodStubClient] = None


def get_default_qod_stub_client() -> QodStubClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = QodStubClient()
    return _DEFAULT_CLIENT


def reset_default_qod_stub_client() -> None:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is not None:
        _DEFAULT_CLIENT.clear()


__all__ = [
    "DEFAULT_QOD_DURATION_SECONDS",
    "QodSessionNotFoundError",
    "QodStubClient",
    "QodStubError",
    "get_default_qod_stub_client",
    "reset_default_qod_stub_client",
]
