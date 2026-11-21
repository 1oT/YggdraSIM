# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local Remote Lab invite/device registry used by the GUI."""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path
from typing import Any, Iterator

from yggdrasim_common.remote_lab.security import read_token_file
from yggdrasim_common.runtime_paths import ensure_workspace_dir, workspace_path
from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    ensure_private_file,
    read_bounded_regular_file,
)


INVITE_SCHEMA = "yggdrasim.remoteLabInvite.v1"
INVITE_BUNDLE_SCHEMA = "yggdrasim.remoteLabInviteBundle.v1"
REGISTRY_SCHEMA = "yggdrasim.remoteLabRegistry.v1"
MAX_INVITES_PER_IMPORT = 256
_MAX_REGISTRY_BYTES = 4 * 1024 * 1024
_REGISTRY_LOCK_TIMEOUT_SECONDS = 10.0
_REGISTRY_LOCK_POLL_SECONDS = 0.05
_REGISTRY_LOCK = threading.RLock()
_REGISTRY_LOCK_STATE = threading.local()


def _remote_lab_workspace() -> str:
    return ensure_workspace_dir("RemoteLab")


def registry_path() -> str:
    return workspace_path("RemoteLab", "registry.json")


def registry_lock_path() -> str:
    return workspace_path("RemoteLab", ".registry.lock")


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
    rig_id: str = ""
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
    # How this operator reaches the host over SSH, for the setup and
    # single-operator path. Deliberately local: an invite hands a
    # colleague an agent and a token, never this operator's login or the
    # path to their private key.
    ssh_target: str = ""
    ssh_identity_file: str = ""
    remote_workdir: str = ""
    remote_python: str = ""
    hil_service_name: str = ""
    # Where this host reads the operator's card from. "tunnel" opens an
    # SSH reverse forward so the card stays on loopback; "direct" points
    # the host at a card this machine publishes on a routable address.
    card_reachability: str = "tunnel"
    card_url: str = ""

    @property
    def has_agent(self) -> bool:
        """True when this host can be reached by bearer token."""
        return len(self.agent_host) > 0 and int(self.agent_control_port) > 0

    @property
    def has_ssh(self) -> bool:
        """True when this host can be prepared and driven over SSH."""
        return len(self.ssh_target) > 0

    def access_dict(self) -> dict[str, Any]:
        """The SSH half of a host card. Never part of an invite."""
        return {
            "ssh_target": self.ssh_target,
            "identity_file": self.ssh_identity_file,
            "remote_workdir": self.remote_workdir,
            "remote_python": self.remote_python,
            "hil_service_name": self.hil_service_name,
            "card_reachability": self.card_reachability,
            "card_url": self.card_url,
        }

    def to_registry_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rig_id": self.remote_rig_id,
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
            "access": self.access_dict(),
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
        return f"{scheme}://{_url_host(self.agent_host)}:{int(self.agent_control_port)}"

    @property
    def remote_rig_id(self) -> str:
        return self.rig_id or self.id


def _normalize_host(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if "%25" in text and ":" in text:
        text = text.replace("%25", "%")
    if (
        not text
        or "://" in text
        or any(character in text for character in ("/", "\\", "@", "?", "#"))
        or any(character.isspace() or ord(character) < 32 for character in text)
    ):
        raise ValueError("agent host must be a hostname or IP address without a URL path")
    if ":" in text:
        import ipaddress

        try:
            ipaddress.IPv6Address(text)
        except ValueError as exc:
            raise ValueError("agent host contains an invalid IPv6 address") from exc
        return text
    try:
        normalized = text.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("agent host contains an invalid hostname") from exc
    if not normalized or len(normalized) > 253:
        raise ValueError("agent host contains an invalid hostname")
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9_-]+", label) is None
        for label in labels
    ):
        raise ValueError("agent host contains an invalid hostname")
    return normalized


def _url_host(value: Any) -> str:
    host = _normalize_host(value)
    if ":" not in host:
        return host
    return f"[{host.replace('%', '%25')}]"


def _device_from_registry(raw: dict[str, Any]) -> RemoteLabDevice:
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    stream = raw.get("stream") if isinstance(raw.get("stream"), dict) else {}
    auth = raw.get("auth") if isinstance(raw.get("auth"), dict) else {}
    access = raw.get("access") if isinstance(raw.get("access"), dict) else {}
    return RemoteLabDevice(
        id=str(raw.get("id") or "").strip(),
        name=str(raw.get("name") or raw.get("id") or "").strip(),
        rig_id=str(raw.get("rig_id") or raw.get("id") or "").strip(),
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
        ssh_target=str(access.get("ssh_target") or "").strip(),
        ssh_identity_file=str(access.get("identity_file") or "").strip(),
        remote_workdir=str(access.get("remote_workdir") or "").strip(),
        remote_python=str(access.get("remote_python") or "").strip(),
        hil_service_name=str(access.get("hil_service_name") or "").strip(),
        card_reachability=str(access.get("card_reachability") or "tunnel").strip()
        or "tunnel",
        card_url=str(access.get("card_url") or "").strip(),
    )


def _validate_device(device: RemoteLabDevice) -> None:
    if len(device.id) == 0:
        raise ValueError("device id is required")
    if (
        len(device.id) > 128
        or any(
            character in ("/", "\\") or ord(character) < 32
            for character in device.id
        )
    ):
        raise ValueError(
            "device id must contain 1-128 characters without slashes or control characters"
        )
    if len(device.remote_rig_id) == 0 or len(device.remote_rig_id) > 256:
        raise ValueError("remote rig id must contain 1-256 characters")
    if any(ord(character) < 32 for character in device.remote_rig_id):
        raise ValueError("remote rig id contains control characters")
    if len(device.name) == 0:
        raise ValueError("device name is required")
    # A host needs at least one way in. An agent is how a rig is shared by
    # token; SSH is how one operator prepares a rig that has no agent yet,
    # which is every rig before somebody sets one up on it. Requiring the
    # agent would mean standing up the thing you were about to install in
    # order to record where to install it.
    if device.has_agent is False and device.has_ssh is False:
        raise ValueError(
            "a device needs an agent (host and control_port) or an ssh_target"
        )
    if device.has_agent is True:
        _normalize_host(device.agent_host)
        if device.agent_control_port <= 0 or device.agent_control_port > 65535:
            raise ValueError("agent control_port must be between 1 and 65535")
        if device.agent_scheme not in ("http", "https"):
            raise ValueError("agent scheme must be http or https")
    elif device.agent_control_port != 0 or len(device.agent_host) > 0:
        # Half an agent is worse than none: the control URL would be built
        # from a host with no port or a port with no host.
        raise ValueError(
            "an agent needs both host and control_port, or neither"
        )
    if device.stream_transport != "http-card-bridge":
        raise ValueError("stream transport must be 'http-card-bridge'")
    if device.card_reachability not in ("tunnel", "direct"):
        raise ValueError("card_reachability must be 'tunnel' or 'direct'")
    if any(ord(character) < 32 for character in device.ssh_target):
        raise ValueError("ssh_target contains control characters")
    if len(device.ssh_target) > 256:
        raise ValueError("ssh_target must be at most 256 characters")
    if device.card_reachability == "direct" and len(device.card_url) == 0:
        raise ValueError(
            "card_reachability 'direct' needs card_url naming a Card Bridge "
            "this host can route to"
        )


def _lock_registry_descriptor(descriptor: int) -> None:
    deadline = time.monotonic() + _REGISTRY_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Timed out waiting for the Remote Lab registry lock."
                ) from exc
            time.sleep(_REGISTRY_LOCK_POLL_SECONDS)


def _unlock_registry_descriptor(descriptor: int) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def _locked_registry() -> Iterator[None]:
    """Serialize registry read/modify/write cycles across threads and processes."""

    with _REGISTRY_LOCK:
        depth = int(getattr(_REGISTRY_LOCK_STATE, "depth", 0))
        if depth > 0:
            _REGISTRY_LOCK_STATE.depth = depth + 1
            try:
                yield
            finally:
                _REGISTRY_LOCK_STATE.depth = depth
            return

        _remote_lab_workspace()
        path = Path(registry_lock_path())
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        locked = False
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            ensure_private_file(path)
            _lock_registry_descriptor(descriptor)
            locked = True
            _REGISTRY_LOCK_STATE.depth = 1
            yield
        finally:
            _REGISTRY_LOCK_STATE.depth = 0
            if locked:
                _unlock_registry_descriptor(descriptor)
            os.close(descriptor)


def _load_registry_unlocked(*, strict: bool) -> dict[str, RemoteLabDevice]:
    path = Path(registry_path())
    if not path.is_file():
        return {}
    try:
        ensure_private_file(path)
        encoded = read_bounded_regular_file(path, _MAX_REGISTRY_BYTES)
        payload = json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if strict:
            raise RuntimeError(
                "Remote Lab registry is unreadable; repair or remove it before importing devices."
            ) from exc
        return {}
    if not isinstance(payload, dict):
        if strict:
            raise RuntimeError("Remote Lab registry root must be a JSON object.")
        return {}
    devices_raw = payload.get("devices", [])
    if not isinstance(devices_raw, list):
        if strict:
            raise RuntimeError("Remote Lab registry devices must be a JSON list.")
        return {}
    devices: dict[str, RemoteLabDevice] = {}
    normalized_ids: set[str] = set()
    for item in devices_raw:
        if not isinstance(item, dict):
            continue
        try:
            device = _device_from_registry(item)
            _validate_device(device)
        except Exception as exc:
            if strict:
                raise RuntimeError("Remote Lab registry contains an invalid device entry.") from exc
            continue
        normalized_id = device.id.casefold()
        if normalized_id in normalized_ids:
            if strict:
                raise RuntimeError(
                    f"Remote Lab registry contains a case-insensitive device-id collision: {device.id!r}."
                )
            continue
        normalized_ids.add(normalized_id)
        devices[device.id] = device
    return devices


def load_registry(*, strict: bool = False) -> dict[str, RemoteLabDevice]:
    with _locked_registry():
        return _load_registry_unlocked(strict=strict)


def _save_registry_unlocked(devices: dict[str, RemoteLabDevice]) -> None:
    normalized_ids: set[str] = set()
    for key, device in devices.items():
        _validate_device(device)
        if key != device.id:
            raise ValueError(f"registry key does not match device id: {key!r}")
        normalized_id = device.id.casefold()
        if normalized_id in normalized_ids:
            raise ValueError(
                f"case-insensitive Remote Lab device-id collision: {device.id!r}"
            )
        normalized_ids.add(normalized_id)
    payload = {
        "schema": REGISTRY_SCHEMA,
        "updated_at": _utc_now_iso(),
        "devices": [
            devices[key].to_registry_dict()
            for key in sorted(devices.keys(), key=lambda value: (value.casefold(), value))
        ],
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(registry_path(), encoded)


def save_registry(devices: dict[str, RemoteLabDevice]) -> None:
    """Atomically replace the registry with a complete, private JSON file."""

    with _locked_registry():
        _save_registry_unlocked(devices)


def list_devices() -> list[dict[str, Any]]:
    return [device.redacted_dict() for device in load_registry().values()]


def get_device(device_id: str) -> RemoteLabDevice:
    device = load_registry().get(str(device_id or "").strip())
    if device is None:
        raise KeyError(f"Remote Lab device not found: {device_id!r}")
    return device


# Fields an operator may edit after import. ``id`` is the registry key and
# ``token_file`` is credential plumbing, so neither is editable here. ``rig_id``
# is deliberately excluded too: it is the id the agent matches, and it is baked
# into the remote-reader binding, the session metadata ``reader_name`` and the
# per-reader localStorage key, so changing it behind a live tab would strand
# every one of them. Re-import the invite to change it.
EDITABLE_DEVICE_FIELDS = (
    "name",
    "location",
    "owner",
    "notes",
    "tags",
    "capabilities",
    "agent_scheme",
    "agent_host",
    "agent_control_port",
    "ssh_target",
    "ssh_identity_file",
    "remote_workdir",
    "remote_python",
    "hil_service_name",
    "card_reachability",
    "card_url",
)


def update_device(device_id: str, changes: dict[str, Any]) -> RemoteLabDevice:
    """Apply *changes* to one registered device and return the stored result.

    Only keys in :data:`EDITABLE_DEVICE_FIELDS` are accepted; anything else
    raises rather than being silently dropped. Values are normalised the same
    way :func:`_build_imported_device` normalises an invite, so a host typed
    with stray case or a trailing dot is stored in the one form every lookup
    compares against.
    """

    requested = {str(key): value for key, value in dict(changes or {}).items()}
    unknown = sorted(set(requested) - set(EDITABLE_DEVICE_FIELDS))
    if unknown:
        raise ValueError(
            "not editable: " + ", ".join(unknown)
            + " (editable: " + ", ".join(EDITABLE_DEVICE_FIELDS) + ")"
        )

    patch: dict[str, Any] = {}
    if "name" in requested:
        name = str(requested["name"] or "").strip()
        if len(name) == 0:
            raise ValueError("device name is required")
        patch["name"] = name
    for key in ("location", "owner", "notes"):
        if key in requested:
            patch[key] = str(requested[key] or "").strip()
    for key in ("tags", "capabilities"):
        if key in requested:
            raw = requested[key]
            if isinstance(raw, str):
                raw = [part for part in raw.replace(",", " ").split()]
            if not isinstance(raw, (list, tuple)):
                raise ValueError(f"{key} must be a list of strings")
            patch[key] = tuple(
                str(item).strip() for item in raw if str(item).strip()
            )
    if "agent_scheme" in requested:
        scheme = str(requested["agent_scheme"] or "").strip().lower() or "http"
        if scheme not in ("http", "https"):
            raise ValueError("agent scheme must be http or https")
        patch["agent_scheme"] = scheme
    if "agent_host" in requested:
        # _validate_device only calls _normalize_host to raise; it discards the
        # canonical form. Store the normalised value or every later exact-string
        # comparison (reader-bar matching, remote-reader registry) can miss.
        patch["agent_host"] = _normalize_host(requested["agent_host"])
    if "agent_control_port" in requested:
        try:
            port = int(requested["agent_control_port"])
        except (TypeError, ValueError) as exc:
            raise ValueError("agent control_port must be an integer") from exc
        patch["agent_control_port"] = port
    # The SSH half of a host card. Plain text fields: the path values are
    # left as typed so a leading ~ survives to whoever expands it.
    for key in (
        "ssh_target",
        "ssh_identity_file",
        "remote_workdir",
        "remote_python",
        "hil_service_name",
        "card_url",
    ):
        if key in requested:
            patch[key] = str(requested[key] or "").strip()
    if "card_reachability" in requested:
        patch["card_reachability"] = (
            str(requested["card_reachability"] or "").strip().lower() or "tunnel"
        )

    with _locked_registry():
        devices = _load_registry_unlocked(strict=False)
        key = str(device_id or "").strip()
        current = devices.get(key)
        if current is None:
            raise KeyError(f"Remote Lab device not found: {device_id!r}")
        updated = dataclass_replace(current, updated_at=_utc_now_iso(), **patch)
        _validate_device(updated)
        devices[key] = updated
        _save_registry_unlocked(devices)
    return updated


def remove_device(device_id: str, *, remove_token_file: bool = False) -> bool:
    with _locked_registry():
        devices = load_registry(strict=True)
        device = devices.pop(str(device_id or "").strip(), None)
        if device is None:
            return False
        save_registry(devices)
    if remove_token_file and device.token_file:
        token_path = Path(device.token_file).expanduser()
        managed_directory = Path(token_directory()).resolve()
        try:
            resolved_token_path = token_path.resolve()
        except OSError:
            resolved_token_path = token_path.absolute()
        if resolved_token_path.parent == managed_directory:
            try:
                resolved_token_path.unlink()
            except OSError:
                pass
    return True


def normalize_invites(payload: Any, *, _depth: int = 0) -> list[dict[str, Any]]:
    """Flatten one invite, an invite array, or a v1 invite bundle."""

    if _depth > 4:
        raise ValueError("Remote Lab invite bundles are nested too deeply")
    if isinstance(payload, list):
        flattened: list[dict[str, Any]] = []
        for item in payload:
            flattened.extend(normalize_invites(item, _depth=_depth + 1))
            if len(flattened) > MAX_INVITES_PER_IMPORT:
                raise ValueError(
                    f"at most {MAX_INVITES_PER_IMPORT} Remote Lab invites may be imported at once"
                )
        return flattened
    if not isinstance(payload, dict):
        raise ValueError("invite must be a JSON object, array, or invite bundle")
    if str(payload.get("schema") or "").strip() == INVITE_BUNDLE_SCHEMA:
        invites = payload.get("invites")
        if not isinstance(invites, list):
            raise ValueError("Remote Lab invite bundle 'invites' must be a list")
        return normalize_invites(invites, _depth=_depth + 1)
    return [dict(payload)]


def _build_imported_device(
    invite: dict[str, Any],
    *,
    existing: RemoteLabDevice | None,
    token_path: Path,
    now: str,
) -> tuple[RemoteLabDevice, str]:
    if not isinstance(invite, dict):
        raise ValueError("invite must be a JSON object")
    if str(invite.get("schema") or "").strip() != INVITE_SCHEMA:
        raise ValueError("unsupported Remote Lab invite schema")

    device_raw = invite.get("device") if isinstance(invite.get("device"), dict) else {}
    agent_raw = invite.get("agent") if isinstance(invite.get("agent"), dict) else {}
    stream_raw = invite.get("stream") if isinstance(invite.get("stream"), dict) else {}
    auth_raw = invite.get("auth") if isinstance(invite.get("auth"), dict) else {}

    device_id = str(device_raw.get("local_id") or device_raw.get("id") or "").strip()
    rig_id = str(device_raw.get("rig_id") or device_raw.get("id") or "").strip()
    if len(device_id) == 0:
        raise ValueError("invite device.id is required")
    token = str(auth_raw.get("token") or "").strip()
    if str(auth_raw.get("mode") or "bearer") != "bearer":
        raise ValueError("only bearer-token invites are supported")
    if len(token) == 0:
        raise ValueError("invite auth.token is required")

    device = RemoteLabDevice(
        id=device_id,
        name=str(device_raw.get("name") or device_id).strip(),
        rig_id=rig_id,
        location=str(device_raw.get("location") or "").strip(),
        tags=tuple(
            str(item).strip() for item in device_raw.get("tags", []) if str(item).strip()
        ),
        agent_scheme=str(agent_raw.get("scheme") or "http").strip().lower() or "http",
        agent_host=_normalize_host(agent_raw.get("host")),
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
    return device, token


def import_invites(payload: Any, *, replace: bool = True) -> list[RemoteLabDevice]:
    invites = normalize_invites(payload)
    if not invites:
        raise ValueError("at least one Remote Lab invite is required")

    with _locked_registry():
        now = _utc_now_iso()
        devices = load_registry(strict=True)
        managed_token_directory = Path(token_directory()).resolve()
        prepared: list[tuple[RemoteLabDevice, str, RemoteLabDevice | None]] = []
        import_ids: set[str] = set()
        existing_ids = {key.casefold(): key for key in devices}
        for invite in invites:
            device_raw = invite.get("device") if isinstance(invite.get("device"), dict) else {}
            candidate_id = str(
                device_raw.get("local_id") or device_raw.get("id") or ""
            ).strip()
            normalized_id = candidate_id.casefold()
            if not normalized_id:
                raise ValueError("invite device.id is required")
            if normalized_id in import_ids:
                raise ValueError(
                    f"duplicate device id in Remote Lab import: {candidate_id}"
                )
            import_ids.add(normalized_id)
            colliding_id = existing_ids.get(normalized_id)
            if colliding_id is not None and colliding_id != candidate_id:
                raise ValueError(
                    "device id collides case-insensitively with an existing device: "
                    f"{candidate_id}"
                )
            existing = devices.get(candidate_id)
            if existing is not None and not replace:
                raise ValueError(f"device already exists: {candidate_id}")
            token_path = (
                managed_token_directory
                / f"device-{_slug(candidate_id)}.{secrets.token_hex(8)}.token"
            )
            device, token = _build_imported_device(
                invite,
                existing=existing,
                token_path=token_path,
                now=now,
            )
            prepared.append((device, token, existing))

        written_devices: list[tuple[RemoteLabDevice, Path, RemoteLabDevice | None]] = []
        try:
            for device, token, existing in prepared:
                written = atomic_write_bytes(
                    Path(device.token_file),
                    token.encode("utf-8") + b"\n",
                    overwrite=False,
                )
                if str(written) != device.token_file:
                    device = dataclass_replace(device, token_file=str(written))
                devices[device.id] = device
                written_devices.append((device, written, existing))
            save_registry(devices)
        except Exception:
            for _device, written, _existing in written_devices:
                try:
                    written.unlink()
                except OSError:
                    pass
            raise

        for _device, written, existing in written_devices:
            if existing is None or not existing.token_file:
                continue
            previous_token = Path(existing.token_file).expanduser()
            try:
                previous_resolved = previous_token.resolve()
            except OSError:
                previous_resolved = previous_token.absolute()
            if (
                previous_resolved != written
                and previous_resolved.parent == managed_token_directory
            ):
                try:
                    previous_resolved.unlink()
                except OSError:
                    pass
        return [device for device, _written, _existing in written_devices]


def import_invite(invite: dict[str, Any], *, replace: bool = True) -> RemoteLabDevice:
    return import_invites(invite, replace=replace)[0]


def create_ssh_host(
    *,
    device_id: str,
    name: str = "",
    ssh_target: str,
    ssh_identity_file: str = "",
    remote_workdir: str = "",
    remote_python: str = "",
    hil_service_name: str = "",
    location: str = "",
    owner: str = "",
    notes: str = "",
    tags: tuple[str, ...] = (),
) -> RemoteLabDevice:
    """Store a host reached over SSH that publishes no agent.

    This is the bootstrap case and it has no invite, by definition: an
    invite hands a colleague an agent and a token, and this host has
    neither yet. It is what you record before setting one up, so it
    carries only the SSH half and gains the agent half later, through the
    ordinary invite import, without changing identity.
    """
    identifier = str(device_id or "").strip()
    if len(identifier) == 0:
        raise ValueError("device id is required")
    target = str(ssh_target or "").strip()
    if len(target) == 0:
        raise ValueError("ssh_target is required for a host with no agent")

    with _locked_registry():
        devices = _load_registry_unlocked(strict=False)
        existing = {key.casefold(): key for key in devices}
        collision = existing.get(identifier.casefold())
        if collision is not None:
            raise ValueError(
                f"device id collides with an existing device: {collision}"
            )
        now = _utc_now_iso()
        device = RemoteLabDevice(
            id=identifier,
            name=str(name or identifier).strip(),
            rig_id=identifier,
            location=str(location or "").strip(),
            tags=tuple(str(tag).strip() for tag in tags if str(tag).strip()),
            owner=str(owner or "").strip(),
            notes=str(notes or "").strip(),
            created_at=now,
            updated_at=now,
            ssh_target=target,
            ssh_identity_file=str(ssh_identity_file or "").strip(),
            remote_workdir=str(remote_workdir or "").strip(),
            remote_python=str(remote_python or "").strip(),
            hil_service_name=str(hil_service_name or "").strip(),
        )
        _validate_device(device)
        devices[identifier] = device
        _save_registry_unlocked(devices)
    return device


def export_invite(device_id: str, *, include_token: bool = True) -> dict[str, Any]:
    device = get_device(device_id)
    token = ""
    if include_token and device.token_file:
        try:
            token = read_token_file(device.token_file)
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(
                "Remote Lab device token file is unavailable or invalid."
            ) from exc
    payload = {
        "schema": INVITE_SCHEMA,
        "device": {
            "id": device.id,
            "rig_id": device.remote_rig_id,
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
