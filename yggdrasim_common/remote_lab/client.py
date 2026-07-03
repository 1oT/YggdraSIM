# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HTTP client helpers for Remote Lab agents."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class RemoteLabClientError(RuntimeError):
    def __init__(self, message: str, *, status: int = 0, payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.payload = dict(payload or {})


def _json_request(
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    payload: dict[str, Any] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=max(1.0, float(timeout_seconds))) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload_obj = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload_obj = {"error": raw}
        message = str(payload_obj.get("message") or payload_obj.get("error") or exc.reason)
        raise RemoteLabClientError(message, status=int(exc.code), payload=payload_obj) from exc
    except urllib.error.URLError as exc:
        raise RemoteLabClientError(f"agent unreachable: {exc.reason}") from exc

    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise RemoteLabClientError(f"agent returned invalid JSON: {raw}") from exc
    if not isinstance(data, dict):
        raise RemoteLabClientError("agent response was not a JSON object")
    return data


class RemoteLabAgentClient:
    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 5.0) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.token = str(token or "").strip()
        self.timeout_seconds = float(timeout_seconds)

    def info(self) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/info",
            token=self.token,
            timeout_seconds=self.timeout_seconds,
        )

    def rigs(self) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/rigs",
            token=self.token,
            timeout_seconds=self.timeout_seconds,
        )

    def status(self, rig_id: str) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{rig_id}/status",
            token=self.token,
            timeout_seconds=self.timeout_seconds,
        )

    def create_session(
        self,
        rig_id: str,
        *,
        user: str = "",
        client_id: str = "",
        requested_ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{rig_id}/sessions",
            method="POST",
            token=self.token,
            payload={
                "user": user,
                "client_id": client_id,
                "requested_ttl_seconds": int(requested_ttl_seconds),
            },
            timeout_seconds=self.timeout_seconds,
        )

    def heartbeat(self, session_id: str, session_token: str) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/sessions/{session_id}/heartbeat",
            method="POST",
            token=self.token,
            payload={"session_token": session_token},
            timeout_seconds=self.timeout_seconds,
        )

    def release(self, session_id: str, session_token: str) -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/sessions/{session_id}",
            method="DELETE",
            token=self.token,
            payload={"session_token": session_token},
            timeout_seconds=self.timeout_seconds,
        )

    def force_release(self, rig_id: str, *, admin_token: str, reason: str = "") -> dict[str, Any]:
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{rig_id}/force-release",
            method="POST",
            token=self.token,
            payload={"admin_token": admin_token, "reason": reason},
            timeout_seconds=self.timeout_seconds,
        )
