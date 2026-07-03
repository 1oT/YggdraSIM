# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local Remote Lab invite/device registry used by the GUI."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from yggdrasim_common.card_bridge_auth import write_token_file
from yggdrasim_common.remote_lab.security import read_token_file
from yggdrasim_common.runtime_paths import ensure_workspace_dir, workspace_path


INVITE_SCHEMA = "yggdrasim.remoteLabInvite.v1"
REGISTRY_SCHEMA = "yggdrasim.remoteLabRegistry.v1"


def _remote_lab_workspace() -> str:
    return ensure_workspace_dir("RemoteLab")


def registry_path() -> str:
    return workspace_path("RemoteLab", "registry.json")


def token_directory() -> str:
    return ensure_workspace_dir("RemoteLab", "tokens")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip())
    cleaned = cleaned.strip(".-")
    return cleaned or "device"


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass(frozen=True)
class RemoteLabDevice:
    id: str
    name: str
    location: str = ""
    tags: tuple[str, ...] = ()
    agent_host: str = ""
    agent_control_port: int = 0
    agent_scheme: str = "http"
    stream_transport: str = "http-card-bridge"
    token_file: str = ""
    owner: str = ""
    notes: str = ""
    capabilities: tuple[str, ...] = ()
    created_at: str = ""
    updated_at: str = ""

    def to_registry_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "location": self.location,
            "tags": list(self.tags),
            "agent": {
                "scheme": self.agent_scheme,
                "host": self.agent_host,
                "control_port": int(self.agent_control_port),
            },
            "stream": {"transport": self.stream_transport},
            "auth": {
                "mode": "bearer",
                "token_file": self.token_file,
            },
            "owner": self.owner,
            "notes": self.notes,
            "capabilities": list(self.capabilities),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def redacted_dict(self) -> dict[str, Any]:
        payload = self.to_registry_dict()
        auth = dict(payload.get("auth") or {})
        auth["token_present"] = bool(self.token_file and Path(self.token_file).expanduser().is_file())
        auth.pop("token_file", None)
        payload["auth"] = auth
        return payload

    @property
    def control_base_url(self) -> str:
        scheme = self.agent_scheme or "http"
        return f"{scheme}://{self.agent_host}:{int(self.agent_control_port)}"


def _device_from_registry(raw: dict[str, Any]) -> RemoteLabDevice:
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    stream = raw.get("stream") if isinstance(raw.get("stream"), dict) else {}
    auth = raw.get("auth") if isinstance(raw.get("auth"), dict) else {}
    return RemoteLabDevice(
        id=str(raw.get("id") or "").strip(),
        name=str(raw.get("name") or raw.get("id") or "").strip(),
        location=str(raw.get("location") or "").strip(),
        tags=tuple(str(item).strip() for item in raw.get("tags", []) if str(item).strip()),
        agent_scheme=str(agent.get("scheme") or "http").strip() or "http",
        agent_host=str(agent.get("host") or "").strip(),
        agent_control_port=int(agent.get("control_port") or 0),
        stream_transport=str(stream.get("transport") or "http-card-bridge").strip()
        or "http-card-bridge",
        token_file=str(auth.get("token_file") or "").strip(),
        owner=str(raw.get("owner") or "").strip(),
        notes=str(raw.get("notes") or "").strip(),
        capabilities=tuple(
            str(item).strip() for item in raw.get("capabilities", []) if str(item).strip()
        ),
        created_at=str(raw.get("created_at") or "").strip(),
        updated_at=str(raw.get("updated_at") or "").strip(),
    )


def _validate_device(device: RemoteLabDevice) -> None:
    if len(device.id) == 0:
        raise ValueError("device id is required")
    if len(device.name) == 0:
        raise ValueError("device name is required")
    if len(device.agent_host) == 0:
        raise ValueError("agent host is required")
    if device.agent_control_port <= 0 or device.agent_control_port > 65535:
        raise ValueError("agent control_port must be between 1 and 65535")
    if device.agent_scheme not in ("http", "https"):
        raise ValueError("agent scheme must be http or https")
    if device.stream_transport != "http-card-bridge":
        raise ValueError("MVP supports stream transport 'http-card-bridge' only")


def load_registry() -> dict[str, RemoteLabDevice]:
    path = registry_path()
    if os.path.isfile(path) is False:
        return {}
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    devices_raw = payload.get("devices", [])
    if not isinstance(devices_raw, list):
        return {}
    devices: dict[str, RemoteLabDevice] = {}
    for item in devices_raw:
        if not isinstance(item, dict):
            continue
        try:
            device = _device_from_registry(item)
            _validate_device(device)
        except Exception:
            continue
        devices[device.id] = device
    return devices


def save_registry(devices: dict[str, RemoteLabDevice]) -> None:
    _remote_lab_workspace()
    payload = {
        "schema": REGISTRY_SCHEMA,
        "updated_at": _utc_now_iso(),
        "devices": [
            devices[key].to_registry_dict()
            for key in sorted(devices.keys())
        ],
    }
    path = Path(registry_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def list_devices() -> list[dict[str, Any]]:
    return [device.redacted_dict() for device in load_registry().values()]


def get_device(device_id: str) -> RemoteLabDevice:
    device = load_registry().get(str(device_id or "").strip())
    if device is None:
        raise KeyError(f"Remote Lab device not found: {device_id!r}")
    return device


def remove_device(device_id: str, *, remove_token_file: bool = False) -> bool:
    devices = load_registry()
    device = devices.pop(str(device_id or "").strip(), None)
    if device is None:
        return False
    save_registry(devices)
    if remove_token_file and device.token_file:
        try:
            Path(device.token_file).expanduser().unlink()
        except OSError:
            pass
    return True


def import_invite(invite: dict[str, Any], *, replace: bool = True) -> RemoteLabDevice:
    if not isinstance(invite, dict):
        raise ValueError("invite must be a JSON object")
    if str(invite.get("schema") or "").strip() != INVITE_SCHEMA:
        raise ValueError("unsupported Remote Lab invite schema")

    device_raw = invite.get("device") if isinstance(invite.get("device"), dict) else {}
    agent_raw = invite.get("agent") if isinstance(invite.get("agent"), dict) else {}
    stream_raw = invite.get("stream") if isinstance(invite.get("stream"), dict) else {}
    auth_raw = invite.get("auth") if isinstance(invite.get("auth"), dict) else {}

    device_id = str(device_raw.get("id") or "").strip()
    if len(device_id) == 0:
        raise ValueError("invite device.id is required")
    token = str(auth_raw.get("token") or "").strip()
    if str(auth_raw.get("mode") or "bearer") != "bearer":
        raise ValueError("only bearer-token invites are supported")
    if len(token) == 0:
        raise ValueError("invite auth.token is required")

    now = _utc_now_iso()
    devices = load_registry()
    existing = devices.get(device_id)
    if existing is not None and not replace:
        raise ValueError(f"device already exists: {device_id}")

    token_path = Path(token_directory()) / f"{_slug(device_id)}.token"
    device = RemoteLabDevice(
        id=device_id,
        name=str(device_raw.get("name") or device_id).strip(),
        location=str(device_raw.get("location") or "").strip(),
        tags=tuple(
            str(item).strip() for item in device_raw.get("tags", []) if str(item).strip()
        ),
        agent_scheme=str(agent_raw.get("scheme") or "http").strip() or "http",
        agent_host=str(agent_raw.get("host") or "").strip(),
        agent_control_port=int(agent_raw.get("control_port") or 0),
        stream_transport=str(stream_raw.get("transport") or "http-card-bridge").strip()
        or "http-card-bridge",
        token_file=str(token_path),
        owner=str(device_raw.get("owner") or "").strip(),
        notes=str(device_raw.get("notes") or "").strip(),
        capabilities=tuple(
            str(item).strip()
            for item in device_raw.get("capabilities", [])
            if str(item).strip()
        ),
        created_at=existing.created_at if existing else str(invite.get("created_at") or now),
        updated_at=now,
    )
    _validate_device(device)

    written = write_token_file(token_path, token)
    if str(written) != device.token_file:
        device = replace(device, token_file=str(written))
    devices[device.id] = device
    save_registry(devices)
    return device


def export_invite(device_id: str, *, include_token: bool = True) -> dict[str, Any]:
    device = get_device(device_id)
    token = read_token_file(device.token_file) if include_token and device.token_file else ""
    payload = {
        "schema": INVITE_SCHEMA,
        "device": {
            "id": device.id,
            "name": device.name,
            "location": device.location,
            "tags": list(device.tags),
            "owner": device.owner,
            "notes": device.notes,
            "capabilities": list(device.capabilities),
        },
        "agent": {
            "scheme": device.agent_scheme,
            "host": device.agent_host,
            "control_port": int(device.agent_control_port),
        },
        "stream": {"transport": device.stream_transport},
        "auth": {"mode": "bearer"},
        "created_at": _utc_now_iso(),
    }
    if include_token:
        payload["auth"]["token"] = token
    return payload
