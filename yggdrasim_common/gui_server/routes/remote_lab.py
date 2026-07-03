# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GUI routes for YggdraSIM Remote Lab."""

from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yggdrasim_common.remote_lab.client import RemoteLabAgentClient, RemoteLabClientError
from yggdrasim_common.remote_lab.registry import (
    export_invite,
    get_device,
    import_invite,
    list_devices,
    load_registry,
    remove_device,
)
from yggdrasim_common.remote_lab.security import read_token_file


_LOGGER = logging.getLogger("yggdrasim.gui.remote_lab")

router = APIRouter(prefix="/api/remote-lab", tags=["remote-lab"])


class ImportInviteRequest(BaseModel):
    invite: dict[str, Any] = Field(default_factory=dict)
    replace: bool = True


class ConnectRequest(BaseModel):
    user: str = ""
    requested_ttl_seconds: int = 3600


class ReleaseRequest(BaseModel):
    session_id: str


class ForceReleaseRequest(BaseModel):
    admin_token: str
    reason: str = ""


def _control_token_for_device(device_id: str) -> str:
    device = get_device(device_id)
    if not device.token_file:
        raise RuntimeError("Remote Lab device has no token file.")
    return read_token_file(device.token_file)


def _client_for_device(device_id: str, *, timeout_seconds: float = 5.0) -> RemoteLabAgentClient:
    device = get_device(device_id)
    token = _control_token_for_device(device.id)
    return RemoteLabAgentClient(device.control_base_url, token, timeout_seconds=timeout_seconds)


def _client_id() -> str:
    return f"yggdrasim-gui:{socket.gethostname()}:{os.getpid()}"


def _open_remote_lab_scp03_session(
    *,
    device_id: str,
    user: str,
    requested_ttl_seconds: int,
) -> dict[str, Any]:
    from SCP03.crypto.session import Scp03Session
    from SCP03.transport.card import CardTransporter
    from yggdrasim_common.card_backend import RelayCardConnection
    from yggdrasim_common.gui_server.actions.scp03 import (
        _close_transporter,
        _scan_transporter_to_session,
    )

    device = get_device(device_id)
    client = _client_for_device(device.id, timeout_seconds=8.0)
    session_payload = client.create_session(
        device.id,
        user=user or os.environ.get("USER", "") or os.environ.get("USERNAME", ""),
        client_id=_client_id(),
        requested_ttl_seconds=requested_ttl_seconds,
    )
    remote_session_id = str(session_payload.get("session_id") or "").strip()
    remote_session_token = str(session_payload.get("session_token") or "").strip()
    stream = session_payload.get("stream") if isinstance(session_payload.get("stream"), dict) else {}
    relay_url = str(stream.get("url") or "").strip()
    if not remote_session_id or not remote_session_token or not relay_url:
        raise RuntimeError("agent returned an incomplete session grant")

    stop_heartbeat = threading.Event()
    heartbeat_interval = 10.0

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(heartbeat_interval):
            try:
                client.heartbeat(remote_session_id, remote_session_token)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning(
                    "remote_lab heartbeat failed device=%s session=%s (%s: %s)",
                    device.id,
                    remote_session_id,
                    type(exc).__name__,
                    exc,
                )

    connection = RelayCardConnection(relay_url, auth_token=remote_session_token)
    transporter = None
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        name=f"remote-lab-heartbeat-{device.id}",
        daemon=True,
    )
    heartbeat_thread.start()

    def _release_remote_session() -> None:
        stop_heartbeat.set()
        try:
            client.release(remote_session_id, remote_session_token)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.info(
                "remote_lab release failed device=%s session=%s (%s: %s)",
                device.id,
                remote_session_id,
                type(exc).__name__,
                exc,
            )
        if transporter is not None:
            _close_transporter(transporter)

    try:
        connection.connect()
        transporter = CardTransporter.__new__(CardTransporter)
        transporter.connection = connection
        transporter.session = Scp03Session({"kenc": b"", "kmac": b"", "dek": b""})
        transporter.verbose = False
        transporter.debug = False
        result = _scan_transporter_to_session(
            transporter,
            reader_index=-1,
            reader_label=f"Remote Lab: {device.name}",
            close_callback=_release_remote_session,
            metadata_extra={
                "remote_lab": True,
                "remote_lab_device_id": device.id,
                "remote_lab_rig_id": device.id,
                "remote_lab_session_id": remote_session_id,
                "remote_lab_agent": device.control_base_url,
            },
        )
    except Exception:
        _release_remote_session()
        raise

    result["remote_lab"] = {
        "device_id": device.id,
        "rig_id": device.id,
        "agent": device.control_base_url,
        "remote_session_id": remote_session_id,
        "expires_at": session_payload.get("expires_at") or "",
    }
    return result


@router.get("/devices")
def devices() -> dict[str, Any]:
    rows = list_devices()
    return {"count": len(rows), "devices": rows}


@router.post("/import")
def import_device(body: ImportInviteRequest) -> dict[str, Any]:
    try:
        device = import_invite(body.invite, replace=body.replace)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"ok": True, "device": device.redacted_dict()}


@router.get("/devices/{device_id}/export")
def export_device(device_id: str, include_token: bool = True) -> dict[str, Any]:
    try:
        return export_invite(device_id, include_token=include_token)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/devices/{device_id}")
def delete_device(device_id: str, remove_token_file: bool = False) -> dict[str, Any]:
    removed = remove_device(device_id, remove_token_file=remove_token_file)
    if not removed:
        raise HTTPException(status_code=404, detail="device not found")
    return {"ok": True, "removed": device_id}


@router.get("/devices/{device_id}/status")
def device_status(device_id: str) -> dict[str, Any]:
    try:
        client = _client_for_device(device_id, timeout_seconds=4.0)
        return client.status(device_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        return {
            "id": device_id,
            "status": "offline",
            "error": str(exc),
            "agent_status": exc.status,
        }


@router.get("/status")
def all_status() -> dict[str, Any]:
    statuses = []
    for device_id in sorted(load_registry().keys()):
        statuses.append(device_status(device_id))
    return {"count": len(statuses), "devices": statuses}


@router.get("/sessions")
def active_sessions() -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    manager.reap_idle()
    sessions = []
    for session in manager.list():
        metadata = session.get("metadata") if isinstance(session.get("metadata"), dict) else {}
        if not metadata.get("remote_lab"):
            continue
        sessions.append(
            {
                "session_id": session.get("id") or "",
                "device_id": metadata.get("remote_lab_device_id") or "",
                "rig_id": metadata.get("remote_lab_rig_id") or "",
                "remote_session_id": metadata.get("remote_lab_session_id") or "",
                "agent": metadata.get("remote_lab_agent") or "",
                "reader_name": metadata.get("reader_name") or "",
                "created_at": session.get("created_at") or 0,
                "last_used_at": session.get("last_used_at") or 0,
            }
        )
    return {"count": len(sessions), "sessions": sessions}


@router.post("/devices/{device_id}/connect")
def connect_device(device_id: str, body: ConnectRequest) -> dict[str, Any]:
    try:
        data = _open_remote_lab_scp03_session(
            device_id=device_id,
            user=body.user,
            requested_ttl_seconds=body.requested_ttl_seconds,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        if exc.status == 423:
            raise HTTPException(status_code=423, detail=exc.payload or str(exc)) from exc
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc
    return {"ok": True, "data": data}


@router.post("/devices/{device_id}/release")
def release_device_session(device_id: str, body: ReleaseRequest) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    try:
        session = manager.get(body.session_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail="session not found") from exc
    metadata = session.metadata or {}
    if metadata.get("remote_lab_device_id") != device_id:
        raise HTTPException(status_code=400, detail="session is not bound to this Remote Lab device")
    if not manager.close(body.session_id):
        raise HTTPException(status_code=404, detail="session not found")
    return {"ok": True, "released": body.session_id}


@router.post("/devices/{device_id}/force-release")
def force_release_device(device_id: str, body: ForceReleaseRequest) -> dict[str, Any]:
    try:
        client = _client_for_device(device_id, timeout_seconds=5.0)
        return client.force_release(device_id, admin_token=body.admin_token, reason=body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        raise HTTPException(status_code=exc.status or 502, detail=exc.payload or str(exc)) from exc
