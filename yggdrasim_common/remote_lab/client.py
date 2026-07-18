# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HTTP client helpers for Remote Lab agents."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlsplit


_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_ERROR_MESSAGE_CHARACTERS = 4096


class RemoteLabClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = int(status)
        self.payload = dict(payload or {})


def _read_bounded_response(response: Any) -> str:
    content_length = str(response.headers.get("Content-Length") or "").strip()
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise RemoteLabClientError(
                "agent returned an invalid Content-Length header"
            ) from exc
        if declared_length < 0 or declared_length > _MAX_RESPONSE_BYTES:
            raise RemoteLabClientError("agent response exceeded the 1 MiB limit")
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise RemoteLabClientError("agent response exceeded the 1 MiB limit")
    return raw.decode("utf-8", errors="replace")


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
        with urllib.request.urlopen(
            request,
            timeout=max(1.0, float(timeout_seconds)),
        ) as response:
            raw = _read_bounded_response(response)
    except urllib.error.HTTPError as exc:
        try:
            raw = _read_bounded_response(exc)
        except RemoteLabClientError:
            raw = ""
        try:
            payload_obj = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload_obj = {"error": raw}
        message = str(
            payload_obj.get("message")
            or payload_obj.get("error")
            or exc.reason
        )[:_MAX_ERROR_MESSAGE_CHARACTERS]
        raise RemoteLabClientError(
            message,
            status=int(exc.code),
            payload=payload_obj,
        ) from exc
    except urllib.error.URLError as exc:
        raise RemoteLabClientError(f"agent unreachable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RemoteLabClientError("agent request timed out") from exc
    except (OSError, ValueError) as exc:
        raise RemoteLabClientError(
            f"agent request failed: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        excerpt = raw[:_MAX_ERROR_MESSAGE_CHARACTERS]
        raise RemoteLabClientError(
            f"agent returned invalid JSON: {excerpt}"
        ) from exc
    if not isinstance(data, dict):
        raise RemoteLabClientError("agent response was not a JSON object")
    return data


class RemoteLabAgentClient:
    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 5.0) -> None:
        normalized_base_url = str(base_url or "").strip().rstrip("/")
        parsed = urlsplit(normalized_base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Remote Lab base URL must be an http(s) origin without credentials"
            )
        self.base_url = normalized_base_url
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
        encoded_rig_id = quote(str(rig_id or "").strip(), safe="")
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{encoded_rig_id}/status",
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
        encoded_rig_id = quote(str(rig_id or "").strip(), safe="")
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{encoded_rig_id}/sessions",
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
        encoded_session_id = quote(str(session_id or "").strip(), safe="")
        return _json_request(
            f"{self.base_url}/api/v1/sessions/{encoded_session_id}/heartbeat",
            method="POST",
            token=self.token,
            payload={"session_token": session_token},
            timeout_seconds=self.timeout_seconds,
        )

    def release(self, session_id: str, session_token: str) -> dict[str, Any]:
        encoded_session_id = quote(str(session_id or "").strip(), safe="")
        return _json_request(
            f"{self.base_url}/api/v1/sessions/{encoded_session_id}",
            method="DELETE",
            token=self.token,
            payload={"session_token": session_token},
            timeout_seconds=self.timeout_seconds,
        )

    def force_release(
        self,
        rig_id: str,
        *,
        admin_token: str,
        reason: str = "",
    ) -> dict[str, Any]:
        encoded_rig_id = quote(str(rig_id or "").strip(), safe="")
        return _json_request(
            f"{self.base_url}/api/v1/rigs/{encoded_rig_id}/force-release",
            method="POST",
            token=self.token,
            payload={"admin_token": admin_token, "reason": reason},
            timeout_seconds=self.timeout_seconds,
        )
