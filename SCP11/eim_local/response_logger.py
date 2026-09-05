# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eIM response logger: writes structured ES2+ response payloads to a JSONL audit trail."""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

from yggdrasim_common.secure_files import (
    ensure_private_directory,
    ensure_private_file,
)


_MAX_LOG_BYTES = 5 * 1024 * 1024
_MAX_LOG_FILES = 3
_MAX_EVENT_BYTES = 64 * 1024
_SENSITIVE_DETAIL_FRAGMENTS = (
    "eid",
    "key",
    "matching",
    "package",
    "path",
    "payload",
    "preview",
    "profile",
    "secret",
    "token",
    "transaction",
)


def _opaque_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _sanitise_event(event: dict[str, Any]) -> dict[str, Any]:
    """Keep operational outcomes while dropping profile/identity material."""
    source = dict(event)
    payload: dict[str, Any] = {}
    for key in (
        "logged_at_utc",
        "action",
        "package_type",
        "success",
        "result_len",
        "flow",
        "transport",
        "execution_path",
        "eim_result_code",
        "eim_result_name",
        "error_type",
    ):
        if key in source:
            payload[key] = source[key]
    package_path = str(source.get("package_path") or "").strip()
    if package_path:
        payload["package_name"] = os.path.basename(package_path)
    for key in (
        "transaction_id_hex",
        "session_transaction_id_hex",
        "matching_id",
        "flow_run_id",
        "eid",
    ):
        identifier = _opaque_id(source.get(key))
        if identifier:
            payload[f"{key}_id"] = identifier
    details = source.get("details")
    if isinstance(details, dict):
        safe_details = {
            str(key): value
            for key, value in details.items()
            if not any(
                fragment in str(key).lower()
                for fragment in _SENSITIVE_DETAIL_FRAGMENTS
            )
            and isinstance(value, (bool, int, float, type(None)))
        }
        if safe_details:
            payload["details"] = safe_details
    return payload

class EimResponseLogger:
    """Append-only JSONL logger for eIM package and flow responses."""

    def __init__(self, log_file_path: str):
        self.log_file_path = str(log_file_path).strip()
        self._lock = threading.Lock()

    def append_event(self, event: dict[str, Any]) -> None:
        """Append one ES2+ response event record to the JSONL response log file."""
        if len(self.log_file_path) == 0:
            return
        directory = os.path.dirname(self.log_file_path) or "."
        if len(directory) > 0:
            ensure_private_directory(directory)
        payload = _sanitise_event(event)
        if len(str(payload.get("logged_at_utc", "") or "").strip()) == 0:
            payload["logged_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        if len(encoded) > _MAX_EVENT_BYTES:
            raise ValueError("eIM response log event exceeds the 64 KiB limit")
        with self._lock:
            self._rotate_if_needed(len(encoded))
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.log_file_path, flags, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                view = memoryview(encoded)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short eIM response-log write")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
            ensure_private_file(self.log_file_path)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        try:
            current_size = os.lstat(self.log_file_path).st_size
            ensure_private_file(self.log_file_path)
        except FileNotFoundError:
            current_size = 0
        if current_size + int(incoming_bytes) <= _MAX_LOG_BYTES:
            return
        oldest = f"{self.log_file_path}.{_MAX_LOG_FILES}"
        try:
            os.unlink(oldest)
        except FileNotFoundError:
            pass
        for index in range(_MAX_LOG_FILES - 1, 0, -1):
            source = f"{self.log_file_path}.{index}"
            destination = f"{self.log_file_path}.{index + 1}"
            try:
                ensure_private_file(source)
                os.replace(source, destination)
                ensure_private_file(destination)
            except FileNotFoundError:
                continue
        try:
            os.replace(self.log_file_path, f"{self.log_file_path}.1")
            ensure_private_file(f"{self.log_file_path}.1")
        except FileNotFoundError:
            pass
