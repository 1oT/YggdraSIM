# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card readers reachable over an HTTP APDU relay rather than local PC/SC.

A Remote Lab session publishes a card that no local ``smartcard.System.readers()``
enumeration can ever return, so every helper that maps a reader name to a
zero-based PC/SC index rejects it. This registry is the name-to-relay lookup
those helpers consult first: a registered name resolves to
:data:`REMOTE_READER_INDEX` and carries the relay endpoint the connection
factory needs, which keeps the reader identity stable across the scan, open
and rescan calls that each re-resolve the name from scratch.

Entries are live session state, not configuration. The owner registers one
when its relay connection is established and drops it during teardown, so a
name never outlives the session token behind it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

# Sentinel index for a reader with no PC/SC ordinal. Matches the value the
# Remote Lab connect route already records in its session metadata, and the
# local branch of ``card_backend.create_card_connection`` rejects it as out
# of range, so an unresolved remote reader fails loudly instead of silently
# binding to the operator's first local reader.
REMOTE_READER_INDEX = -1

# One entry per connected remote device. Keyed by reader name, so a
# reconnect replaces its entry instead of adding one; the cap bounds a
# caller that registers without ever tearing down.
MAX_REMOTE_READERS = 64


class RemoteReaderError(RuntimeError):
    """A remote reader could not be registered or resolved."""


@dataclass(frozen=True)
class RemoteReaderBinding:
    """A reader name bound to the relay endpoint that serves its card.

    The link that registers the binding owns the agent session behind it;
    ``rig_id``, ``remote_session_id``, ``agent`` and ``expires_at`` describe
    that session so a module opening the card through the binding can tag its
    own session with the same identity without holding a reference to the
    link.
    """

    name: str
    relay_url: str
    auth_token: str = ""
    origin: str = ""
    device_id: str = ""
    rig_id: str = ""
    remote_session_id: str = ""
    agent: str = ""
    expires_at: str = ""

    def redacted_dict(self) -> dict[str, Any]:
        """Return the binding without its bearer token, for API payloads."""
        return {
            "name": self.name,
            "relay_url": self.relay_url,
            "origin": self.origin,
            "device_id": self.device_id,
            "rig_id": self.rig_id,
            "remote_session_id": self.remote_session_id,
            "agent": self.agent,
            "expires_at": self.expires_at,
            "token_present": len(self.auth_token) > 0,
        }

    def session_metadata(self) -> dict[str, Any]:
        """Metadata a module session opened through this binding carries."""
        return {
            "remote_lab": True,
            "remote_lab_device_id": self.device_id,
            "remote_lab_rig_id": self.rig_id,
            "remote_lab_session_id": self.remote_session_id,
            "remote_lab_agent": self.agent,
        }


_LOCK = threading.RLock()
_REGISTRY: dict[str, RemoteReaderBinding] = {}


def canonical_reader_name(name: Any) -> str:
    """Return *name* stripped, the form every lookup compares against."""
    return str(name or "").strip()


def register_remote_reader(
    name: Any,
    *,
    relay_url: Any,
    auth_token: Any = "",
    origin: Any = "",
    device_id: Any = "",
    rig_id: Any = "",
    remote_session_id: Any = "",
    agent: Any = "",
    expires_at: Any = "",
) -> RemoteReaderBinding:
    """Bind *name* to *relay_url* and return the stored binding.

    Re-registering a known name replaces its binding, which is what a
    reconnect needs: the relay URL is stable but the session bearer is not.
    """
    cleaned_name = canonical_reader_name(name)
    if len(cleaned_name) == 0:
        raise ValueError("remote reader name must not be empty")
    cleaned_url = str(relay_url or "").strip()
    if len(cleaned_url) == 0:
        raise ValueError(f"remote reader {cleaned_name!r} needs a relay URL")
    binding = RemoteReaderBinding(
        name=cleaned_name,
        relay_url=cleaned_url,
        auth_token=str(auth_token or "").strip(),
        origin=str(origin or "").strip(),
        device_id=str(device_id or "").strip(),
        rig_id=str(rig_id or "").strip(),
        remote_session_id=str(remote_session_id or "").strip(),
        agent=str(agent or "").strip(),
        expires_at=str(expires_at or "").strip(),
    )
    with _LOCK:
        if cleaned_name not in _REGISTRY and len(_REGISTRY) >= MAX_REMOTE_READERS:
            raise RemoteReaderError(
                f"too many remote readers registered (limit {MAX_REMOTE_READERS}); "
                "release an existing Remote Lab session before opening another"
            )
        _REGISTRY[cleaned_name] = binding
    return binding


def unregister_remote_reader(name: Any) -> bool:
    """Drop the binding for *name*; return whether one was present."""
    cleaned_name = canonical_reader_name(name)
    if len(cleaned_name) == 0:
        return False
    with _LOCK:
        return _REGISTRY.pop(cleaned_name, None) is not None


def lookup_remote_reader(name: Any) -> RemoteReaderBinding | None:
    """Return the binding for *name*, or ``None`` when it is not remote."""
    cleaned_name = canonical_reader_name(name)
    if len(cleaned_name) == 0:
        return None
    with _LOCK:
        return _REGISTRY.get(cleaned_name)


def is_remote_reader(name: Any) -> bool:
    """Return whether *name* is a registered remote reader."""
    return lookup_remote_reader(name) is not None


def resolve_reader_name(name: Any) -> tuple[int, str]:
    """Map an operator-typed reader name to ``(reader_index, reader_name)``.

    The one rule every surface shares, so a name means the same thing in the
    GUI, the shells and the MCP server: a registered remote reader resolves
    first, to ``REMOTE_READER_INDEX`` and its canonical name; an empty name is
    the first PC/SC reader; anything else must match a PC/SC reader name
    exactly. A name that matches nothing raises rather than falling back to
    index 0, so a typo can never land a command on the wrong card.
    """
    cleaned = canonical_reader_name(name)
    binding = lookup_remote_reader(cleaned)
    if binding is not None:
        return REMOTE_READER_INDEX, binding.name
    if len(cleaned) == 0:
        return 0, ""
    try:
        from smartcard.System import readers as list_pcsc_readers
    except ImportError as error:
        raise RuntimeError("pyscard is not installed -- cannot pick a reader by name.") from error
    try:
        reader_list = list(list_pcsc_readers() or [])
    except Exception as error:  # noqa: BLE001 -- surface PC/SC faults as one message
        raise RuntimeError(f"PC/SC reader enumeration failed: {error}") from error
    for index, reader in enumerate(reader_list):
        if str(reader) == cleaned:
            return index, str(reader)
    raise RuntimeError(f"reader not found: {cleaned!r}")


def list_remote_readers() -> list[RemoteReaderBinding]:
    """Return every registered binding, ordered by reader name."""
    with _LOCK:
        return sorted(_REGISTRY.values(), key=lambda entry: entry.name)


def clear_remote_readers() -> None:
    """Drop every binding. Intended for test isolation."""
    with _LOCK:
        _REGISTRY.clear()
