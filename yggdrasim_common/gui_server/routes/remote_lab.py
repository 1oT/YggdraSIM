# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""GUI routes for YggdraSIM Remote Lab."""

from __future__ import annotations

import logging
import math
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yggdrasim_common.remote_lab.client import RemoteLabAgentClient, RemoteLabClientError
from yggdrasim_common.remote_lab.registry import (
    create_ssh_host,
    export_invite,
    get_device,
    import_invites,
    list_devices,
    load_registry,
    remove_device,
    update_device,
)
from yggdrasim_common.remote_lab.security import read_token_file
from yggdrasim_common.remote_readers import (
    REMOTE_READER_INDEX,
    register_remote_reader,
    unregister_remote_reader,
)


_LOGGER = logging.getLogger("yggdrasim.gui.remote_lab")

router = APIRouter(prefix="/api/remote-lab", tags=["remote-lab"])


class ImportInviteRequest(BaseModel):
    invite: dict[str, Any] | list[dict[str, Any]] = Field(default_factory=dict)
    replace: bool = True


class UpdateDeviceRequest(BaseModel):
    """Editable device fields. Every field is optional and omission means
    "leave this alone" -- the route forwards only the keys the caller actually
    sent, so a form that posts just ``name`` cannot blank the notes beside it.
    An explicitly sent empty string does clear a free-text field."""

    name: str | None = None
    location: str | None = None
    owner: str | None = None
    notes: str | None = None
    # A string is accepted as well as a list: update_device splits on commas
    # and whitespace, so the comma-separated text field the GUI shows needs no
    # second splitting implementation on the client.
    tags: list[str] | str | None = None
    capabilities: list[str] | str | None = None
    agent_scheme: str | None = None
    agent_host: str | None = None
    agent_control_port: int | None = None
    # The SSH half of a host card. Local to this operator and never part
    # of an invite, but editable here so a host can be described once
    # instead of retyped into the Remote Bridge form every time.
    ssh_target: str | None = None
    ssh_identity_file: str | None = None
    remote_workdir: str | None = None
    remote_python: str | None = None
    hil_service_name: str | None = None
    card_reachability: str | None = None
    card_url: str | None = None


class ConnectRequest(BaseModel):
    user: str = ""
    requested_ttl_seconds: int = 3600


class OfferCardRequest(BaseModel):
    """Reserve a modem rig and feed it a card from this machine."""

    user: str = ""
    requested_ttl_seconds: int = 3600
    card_url: str = ""
    card_token: str = ""
    card_token_file: str = ""


class ReleaseRequest(BaseModel):
    session_id: str = ""


class ForceReleaseRequest(BaseModel):
    admin_token: str
    reason: str = ""


def _control_token_for_device(device_id: str) -> str:
    device = get_device(device_id)
    if not device.token_file:
        raise RuntimeError("Remote Lab device has no token file.")
    try:
        return read_token_file(device.token_file)
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(
            "Remote Lab device token file is unavailable or invalid."
        ) from exc


def _client_for_device(device_id: str, *, timeout_seconds: float = 5.0) -> RemoteLabAgentClient:
    device = get_device(device_id)
    token = _control_token_for_device(device.id)
    return RemoteLabAgentClient(device.control_base_url, token, timeout_seconds=timeout_seconds)


def _client_id() -> str:
    return f"yggdrasim-gui:{socket.gethostname()}:{os.getpid()}"


LINK_SESSION_KIND = "remote_lab_link"

# Agent replies that mean the remote session no longer exists. A heartbeat
# that meets one of these tears the link down; any other failure is transient
# and only logged, so a flapping tunnel does not release a healthy rig.
_SESSION_GONE_STATUSES = frozenset({401, 403, 404, 410})


def _open_remote_lab_link(
    *,
    device_id: str,
    user: str,
    requested_ttl_seconds: int,
    card_offer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reserve the rig and publish its reader; open no card session.

    This is the remote counterpart of plugging in a local reader. The agent
    session, its heartbeat and its release are held by one link session in
    the session manager, module-neutral: the SCP03 workbench, eSIM
    management and the local SM-DP+ each open their own card channel through
    the registered reader name and never own the relay. Disconnect, an
    expired agent session or a dead heartbeat close the link, and the link's
    close callback is the single teardown funnel.

    The card is not scanned here. The ATR is read from the relay's status
    endpoint (one round trip, no APDU) so the reader row and pill show a
    present card the way a local probe does.
    """
    from yggdrasim_common.card_backend import RelayCardConnection
    from yggdrasim_common.gui_server.sessions import get_manager

    device = get_device(device_id)
    client = _client_for_device(device.id, timeout_seconds=8.0)
    session_payload = client.create_session(
        device.remote_rig_id,
        user=user or os.environ.get("USER", "") or os.environ.get("USERNAME", ""),
        client_id=_client_id(),
        requested_ttl_seconds=requested_ttl_seconds,
        card_offer=card_offer,
    )
    # A modem rig consumes the operator's own card, so there is no relay to
    # stream from and no remote reader to publish: the card is already here.
    consumes_offered_card = card_offer is not None
    remote_session_id = str(session_payload.get("session_id") or "").strip()
    remote_session_token = str(session_payload.get("session_token") or "").strip()
    stream = (
        session_payload.get("stream")
        if isinstance(session_payload.get("stream"), dict)
        else {}
    )
    relay_url = str(stream.get("url") or "").strip()
    grant_is_complete = bool(remote_session_id) and bool(remote_session_token)
    if consumes_offered_card is False:
        grant_is_complete = grant_is_complete and bool(relay_url)
    if grant_is_complete is False:
        if remote_session_id and remote_session_token:
            try:
                client.release(remote_session_id, remote_session_token)
            except Exception:  # noqa: BLE001
                pass
        raise RuntimeError("agent returned an incomplete session grant")

    stop_heartbeat = threading.Event()
    try:
        heartbeat_interval = float(
            session_payload.get("heartbeat_interval_seconds") or 10.0
        )
    except (TypeError, ValueError):
        heartbeat_interval = 10.0
    if not math.isfinite(heartbeat_interval):
        heartbeat_interval = 10.0
    heartbeat_interval = min(30.0, max(1.0, heartbeat_interval))
    release_lock = threading.Lock()
    release_started = False
    heartbeat_thread: threading.Thread | None = None
    link_session_id = ""
    expires_at = str(session_payload.get("expires_at") or "")

    # The name every module re-resolves. Registering it is what lets any
    # workbench open this card: a Remote Lab reader has no PC/SC ordinal, so
    # without the binding the name resolves to nothing.
    reader_label = "" if consumes_offered_card else f"Remote Lab: {device.name}"

    def _release_remote_session() -> None:
        nonlocal release_started
        with release_lock:
            if release_started:
                return
            release_started = True
        # Drop the binding before the session token behind it is released,
        # so no module can resolve this name to a reaped session.
        if len(reader_label) > 0:
            unregister_remote_reader(reader_label)
        stop_heartbeat.set()
        thread = heartbeat_thread
        if (
            thread is not None
            and thread.is_alive()
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=max(1.0, client.timeout_seconds + 1.0))
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

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(heartbeat_interval):
            try:
                client.heartbeat(remote_session_id, remote_session_token)
            except RemoteLabClientError as exc:
                if exc.status in _SESSION_GONE_STATUSES:
                    _LOGGER.warning(
                        "remote_lab session gone device=%s session=%s (HTTP %s); closing link",
                        device.id,
                        remote_session_id,
                        exc.status,
                    )
                    # Closing through the manager runs _release_remote_session
                    # and drops the row the GUI polls, so Disconnect and the
                    # reader pill both see the link go.
                    if link_session_id:
                        get_manager().close(link_session_id)
                    return
                _LOGGER.warning(
                    "remote_lab heartbeat failed device=%s session=%s (%s: %s)",
                    device.id,
                    remote_session_id,
                    type(exc).__name__,
                    exc,
                )
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning(
                    "remote_lab heartbeat failed device=%s session=%s (%s: %s)",
                    device.id,
                    remote_session_id,
                    type(exc).__name__,
                    exc,
                )

    atr_hex = ""
    try:
        if consumes_offered_card is False:
            # One status round trip for the ATR; the connection is not kept.
            probe = RelayCardConnection(relay_url, auth_token=remote_session_token)
            probe.connect()
            atr_hex = bytes(probe.getATR() or []).hex().upper()
            register_remote_reader(
                reader_label,
                relay_url=relay_url,
                auth_token=remote_session_token,
                origin="remote-lab",
                device_id=device.id,
                rig_id=device.remote_rig_id,
                remote_session_id=remote_session_id,
                agent=device.control_base_url,
                expires_at=expires_at,
            )
        metadata = {
            "remote_lab": True,
            "remote_lab_link": True,
            "remote_lab_device_id": device.id,
            "remote_lab_rig_id": device.remote_rig_id,
            "remote_lab_session_id": remote_session_id,
            "remote_lab_agent": device.control_base_url,
            "reader_name": reader_label,
            "atr_hex": atr_hex,
            "expires_at": expires_at,
            "consumes_offered_card": consumes_offered_card,
        }
        link = get_manager().open(
            kind=LINK_SESSION_KIND,
            handle={"relay_url": relay_url, "reader_name": reader_label},
            close=_release_remote_session,
            # The agent's TTL and heartbeat govern the link's life, not the
            # GUI idle sweep: an operator who connected and then reads a
            # profile in another module has not abandoned the rig.
            protect_from_auto_close=True,
            metadata=metadata,
        )
        link_session_id = link.id
        if not stop_heartbeat.is_set():
            heartbeat_thread = threading.Thread(
                target=_heartbeat_loop,
                name=f"remote-lab-heartbeat-{device.id}",
                daemon=True,
            )
            heartbeat_thread.start()
    except Exception:
        _release_remote_session()
        raise

    result: dict[str, Any] = {
        "session_id": link.id,
        "kind": LINK_SESSION_KIND,
        "reader_name": reader_label,
        "reader_index": REMOTE_READER_INDEX,
        "atr_hex": atr_hex,
        "remote_lab": {
            "device_id": device.id,
            "rig_id": device.remote_rig_id,
            "agent": device.control_base_url,
            "remote_session_id": remote_session_id,
            "expires_at": expires_at,
        },
    }
    if consumes_offered_card is True:
        result["consumes_offered_card"] = True
        result["consumer"] = session_payload.get("consumer") or {}
        # The operator keeps using their own reader, so there is no remote
        # reader name to hand back and no index to resolve.
        result["reader_index"] = None
    return result


def _is_remote_lab_link(session: Any) -> bool:
    return str(getattr(session, "kind", "")) == LINK_SESSION_KIND


def _link_for_device(device_id: str) -> Any:
    """Return the live link session for *device_id*, or ``None``."""
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    for entry in manager.list():
        if entry.get("kind") != LINK_SESSION_KIND:
            continue
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        if str(metadata.get("remote_lab_device_id") or "") != str(device_id or ""):
            continue
        try:
            return manager.get(str(entry.get("id") or ""))
        except Exception:  # noqa: BLE001 -- closed between list and get
            return None
    return None


def _close_module_sessions_for_reader(reader_name: str) -> int:
    """Close every module session opened through *reader_name*.

    Called before a link is released so each module's transporter ends its
    relay boundary while the relay still answers, and so no session outlives
    the binding it was opened through.
    """
    from yggdrasim_common.gui_server.sessions import get_manager

    # A modem-rig link registers no reader, because the card never left the
    # operator's machine. Matching on an empty name would match every
    # session that carries no reader name at all and close all of them.
    if len(str(reader_name or "").strip()) == 0:
        return 0

    manager = get_manager()
    closed = 0
    for entry in manager.list():
        if entry.get("kind") == LINK_SESSION_KIND:
            continue
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        if str(metadata.get("reader_name") or "") != str(reader_name or ""):
            continue
        if manager.close(str(entry.get("id") or "")):
            closed += 1
    return closed


@router.get("/devices")
def devices() -> dict[str, Any]:
    rows = list_devices()
    return {"count": len(rows), "devices": rows}


@router.post("/import")
def import_device(body: ImportInviteRequest) -> dict[str, Any]:
    try:
        imported_devices = import_invites(body.invite, replace=body.replace)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    redacted = [device.redacted_dict() for device in imported_devices]
    response: dict[str, Any] = {
        "ok": True,
        "count": len(redacted),
        "devices": redacted,
    }
    if len(redacted) == 1:
        response["device"] = redacted[0]
    return response


@router.get("/devices/{device_id}/export")
def export_device(device_id: str, include_token: bool = True) -> dict[str, Any]:
    try:
        return export_invite(device_id, include_token=include_token)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class CreateHostRequest(BaseModel):
    """A host reached over SSH that publishes no Remote Lab agent yet.

    There is no invite for this: an invite carries an agent and a token,
    and this host has neither. It is what an operator records before
    setting one up.
    """

    id: str
    name: str = ""
    ssh_target: str
    ssh_identity_file: str = ""
    remote_workdir: str = ""
    remote_python: str = ""
    hil_service_name: str = ""
    location: str = ""
    owner: str = ""
    notes: str = ""


@router.post("/hosts")
def create_host(body: CreateHostRequest) -> dict[str, Any]:
    try:
        device = create_ssh_host(
            device_id=body.id,
            name=body.name,
            ssh_target=body.ssh_target,
            ssh_identity_file=body.ssh_identity_file,
            remote_workdir=body.remote_workdir,
            remote_python=body.remote_python,
            hil_service_name=body.hil_service_name,
            location=body.location,
            owner=body.owner,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"ok": True, "device": device.redacted_dict()}


@router.post("/devices/{device_id}/update")
def update_device_route(device_id: str, body: UpdateDeviceRequest) -> dict[str, Any]:
    # ``exclude_unset`` is what makes omission mean "leave alone": without it
    # every unsent field arrives as None and would clear the stored value.
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="no editable fields supplied")
    try:
        device = update_device(device_id, changes)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 -- validation errors are the caller's
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"ok": True, "device": device.redacted_dict()}


@router.delete("/devices/{device_id}")
def delete_device(device_id: str, remove_token_file: bool = False) -> dict[str, Any]:
    removed = remove_device(device_id, remove_token_file=remove_token_file)
    if not removed:
        raise HTTPException(status_code=404, detail="device not found")
    return {"ok": True, "removed": device_id}


@router.get("/devices/{device_id}/status")
def device_status(device_id: str) -> dict[str, Any]:
    try:
        device = get_device(device_id)
        if device.has_agent is False:
            # A host recorded for SSH alone publishes nothing to probe.
            # Calling it offline would read as a fault; it is simply a
            # different kind of host, and one this path cannot reserve.
            return {
                "id": device.id,
                "rig_id": device.remote_rig_id,
                "status": "ssh-only",
                "kind": "host",
                "ssh_target": device.ssh_target,
                "agent_status": 0,
            }
        client = _client_for_device(device_id, timeout_seconds=4.0)
        payload = client.status(device.remote_rig_id)
        remote_id = str(payload.get("id") or device.remote_rig_id)
        payload["id"] = device.id
        payload["rig_id"] = remote_id
        return payload
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        return {
            "id": device_id,
            "status": "offline",
            "error": str(exc),
            "agent_status": exc.status,
        }
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "id": device_id,
            "status": "offline",
            "error": f"{type(exc).__name__}: {exc}",
            "agent_status": 0,
        }


@router.get("/status")
def all_status() -> dict[str, Any]:
    device_ids = sorted(
        load_registry().keys(),
        key=lambda value: (value.casefold(), value),
    )
    if not device_ids:
        return {"count": 0, "devices": []}

    def _status_or_offline(device_id: str) -> dict[str, Any]:
        try:
            return device_status(device_id)
        except HTTPException as exc:
            return {
                "id": device_id,
                "status": "offline",
                "error": str(exc.detail),
                "agent_status": int(exc.status_code),
            }

    with ThreadPoolExecutor(
        max_workers=min(8, len(device_ids)),
        thread_name_prefix="remote-lab-status",
    ) as executor:
        statuses = list(executor.map(_status_or_offline, device_ids))
    return {"count": len(statuses), "devices": statuses}


def _is_remote_lab_session(session: Any) -> bool:
    """Return whether a session belongs to the Remote Lab subsystem."""
    metadata = getattr(session, "metadata", None)
    if not isinstance(metadata, dict):
        return False
    return bool(metadata.get("remote_lab"))


@router.get("/sessions")
def active_sessions() -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    # Sweep this subsystem only. The GUI polls this route every 10 s from
    # boot whether or not a rig is configured, so an unscoped sweep here
    # decided the lifetime of every other subsystem's sessions -- it closed
    # SAIP authoring sessions an operator was still reading.
    manager.reap_idle(select=_is_remote_lab_session)
    # One row per link. Module sessions opened through a link carry the same
    # identity but are the link's children; listing them here would make
    # the GUI count one rig several times and let Disconnect pick a child.
    sessions = []
    for session in manager.list():
        if session.get("kind") != LINK_SESSION_KIND:
            continue
        metadata = session.get("metadata") if isinstance(session.get("metadata"), dict) else {}
        sessions.append(
            {
                "session_id": session.get("id") or "",
                "kind": LINK_SESSION_KIND,
                "device_id": metadata.get("remote_lab_device_id") or "",
                "rig_id": metadata.get("remote_lab_rig_id") or "",
                "remote_session_id": metadata.get("remote_lab_session_id") or "",
                "agent": metadata.get("remote_lab_agent") or "",
                "reader_name": metadata.get("reader_name") or "",
                "atr_hex": metadata.get("atr_hex") or "",
                "expires_at": metadata.get("expires_at") or "",
                "created_at": session.get("created_at") or 0,
                "last_used_at": session.get("last_used_at") or 0,
            }
        )
    return {"count": len(sessions), "sessions": sessions}


@router.post("/devices/{device_id}/connect")
def connect_device(device_id: str, body: ConnectRequest) -> dict[str, Any]:
    try:
        data = _open_remote_lab_link(
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


@router.post("/devices/{device_id}/offer-card")
def offer_card_to_device(device_id: str, body: OfferCardRequest) -> dict[str, Any]:
    """Reserve a modem rig, offering it a card this machine publishes.

    The rig holds no card. It runs a modem and a SIMtrace2 and consumes
    the Card Bridge named here, so the bridge has to be reachable from the
    rig: open a reverse tunnel, or publish it on a routable address.
    """
    from yggdrasim_common.remote_lab.consumer import (
        CardOffer,
        CardOfferError,
        resolve_local_card_token,
    )

    try:
        token = str(body.card_token or "").strip()
        if len(token) == 0:
            token = resolve_local_card_token(
                body.card_url, token_file=body.card_token_file
            )
        offer = CardOffer.from_payload({"url": body.card_url, "token": token})
    except CardOfferError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        data = _open_remote_lab_link(
            device_id=device_id,
            user=body.user,
            requested_ttl_seconds=body.requested_ttl_seconds,
            card_offer={"url": offer.url, "token": offer.token},
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        if exc.status == 423:
            raise HTTPException(status_code=423, detail=exc.payload or str(exc)) from exc
        if exc.status == 400:
            raise HTTPException(status_code=400, detail=exc.payload or str(exc)) from exc
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc
    return {"ok": True, "data": data}


@router.post("/devices/{device_id}/release")
def release_device_session(device_id: str, body: ReleaseRequest) -> dict[str, Any]:
    from yggdrasim_common.gui_server.sessions import get_manager

    manager = get_manager()
    # Accept the link's id, the id of any module session opened through it,
    # or no id at all: every one of them means "release this device's rig".
    link = _link_for_device(device_id)
    requested = str(body.session_id or "").strip()
    if link is None:
        if requested and manager.has(requested):
            raise HTTPException(status_code=400, detail="session is not bound to this Remote Lab device")
        raise HTTPException(status_code=404, detail="session not found")
    if requested and requested != link.id:
        try:
            child = manager.get(requested)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=404, detail="session not found") from exc
        child_metadata = child.metadata or {}
        if child_metadata.get("remote_lab_device_id") != device_id:
            raise HTTPException(status_code=400, detail="session is not bound to this Remote Lab device")
    reader_name = str((link.metadata or {}).get("reader_name") or "")
    closed_children = _close_module_sessions_for_reader(reader_name)
    if not manager.close(link.id):
        raise HTTPException(status_code=404, detail="session not found")
    return {"ok": True, "released": link.id, "closed_sessions": closed_children}


@router.post("/devices/{device_id}/force-release")
def force_release_device(device_id: str, body: ForceReleaseRequest) -> dict[str, Any]:
    try:
        device = get_device(device_id)
        client = _client_for_device(device_id, timeout_seconds=5.0)
        return client.force_release(
            device.remote_rig_id,
            admin_token=body.admin_token,
            reason=body.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RemoteLabClientError as exc:
        raise HTTPException(status_code=exc.status or 502, detail=exc.payload or str(exc)) from exc
