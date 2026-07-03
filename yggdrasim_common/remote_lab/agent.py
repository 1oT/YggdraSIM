# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraSIM Remote Lab agent.

The agent exposes a small control API and one Card Bridge-compatible
session relay per configured rig. The upstream data plane remains the
existing HTTP ``/apdu`` relay; this process only adds identity, status,
and exclusive session locking in front of it.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse, urlunparse

from yggdrasim_common.__about__ import __version__
from yggdrasim_common.card_backend import _request_card_relay_json
from yggdrasim_common.card_bridge_auth import fingerprint, parse_bearer_header
from yggdrasim_common.remote_lab.config import (
    AccessTokenConfig,
    RemoteLabAgentConfig,
    RigConfig,
    load_config,
)
from yggdrasim_common.remote_lab.security import read_token_file, verify_token
from yggdrasim_common.remote_lab.sessions import LabSession, LabSessionManager, RigBusyError


_LOGGER = logging.getLogger("yggdrasim.remote_lab.agent")


def _utc_iso(epoch: float) -> str:
    if not epoch:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(epoch)))


def _status_url_for_apdu(apdu_url: str) -> str:
    parsed = urlparse(apdu_url)
    path = parsed.path.rstrip("/")
    if path.endswith("/apdu"):
        path = path[: -len("/apdu")] + "/status"
    else:
        path = path + "/status"
    return urlunparse((parsed.scheme, parsed.netloc, path or "/status", "", "", ""))


def _reset_url_for_apdu(apdu_url: str) -> str:
    parsed = urlparse(apdu_url)
    path = parsed.path.rstrip("/")
    if path.endswith("/apdu"):
        path = path[: -len("/apdu")] + "/card/reset"
    else:
        path = path + "/card/reset"
    return urlunparse((parsed.scheme, parsed.netloc, path or "/card/reset", "", "", ""))


def _base_url_for_apdu(apdu_url: str) -> str:
    parsed = urlparse(apdu_url)
    path = parsed.path.rstrip("/")
    if path.endswith("/apdu"):
        path = path[: -len("/apdu")]
    return urlunparse((parsed.scheme, parsed.netloc, path or "", "", "", "")).rstrip("/")


def _read_optional_token(raw_token: str = "", token_file: str = "") -> str:
    token = str(raw_token or "").strip()
    if token:
        return token
    if str(token_file or "").strip():
        try:
            return read_token_file(str(token_file).strip())
        except OSError:
            return ""
    return ""


@dataclass(frozen=True, slots=True)
class AuthorizedToken:
    id: str
    role: str


class _JsonHandler(BaseHTTPRequestHandler):
    server_version = "YggdraSIMRemoteLab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_text(self, status: int, payload: bytes) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header.") from exc
        if length < 0 or length > 1024 * 1024:
            raise ValueError("Request body size is invalid.")
        raw = self.rfile.read(length)
        if len(raw) == 0:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload


class RemoteLabAgentService:
    def __init__(self, config: RemoteLabAgentConfig) -> None:
        self.config = config
        self.rigs = {rig.id: rig for rig in config.rigs}
        self.sessions = LabSessionManager(config.rigs, config.defaults)
        self._control_server: _ControlServer | None = None
        self._relay_servers: list[_RelayServer] = []
        self._relay_threads: list[threading.Thread] = []
        self._cleanup_stop = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

    def authorize(self, presented_token: str, *, role: str = "user") -> AuthorizedToken | None:
        required_admin = role == "admin"
        for item in self.config.access_tokens:
            if not verify_token(presented_token, item.token_hash):
                continue
            if required_admin and item.role != "admin":
                return None
            return AuthorizedToken(id=item.id, role=item.role)
        return None

    def authorize_header(self, header: str, *, role: str = "user") -> AuthorizedToken | None:
        return self.authorize(parse_bearer_header(header), role=role)

    def upstream_token(self, rig: RigConfig) -> str:
        return _read_optional_token(rig.upstream.token, rig.upstream.token_file)

    def upstream_status(self, rig: RigConfig, *, timeout_seconds: float = 2.0) -> dict[str, Any]:
        return _request_card_relay_json(
            _status_url_for_apdu(rig.upstream.url),
            method="GET",
            timeout_seconds=int(timeout_seconds),
            auth_token=self.upstream_token(rig),
        )

    def rig_health(self, rig: RigConfig) -> dict[str, Any]:
        health: dict[str, Any] = {
            "agent": "ok",
            "stream_proxy": "ok",
            "upstream_apdu_backend": "unknown",
            "modem": "unknown",
            "simtrace2": "unknown",
        }
        try:
            status = self.upstream_status(rig)
        except Exception as exc:  # noqa: BLE001
            health["upstream_apdu_backend"] = "error"
            health["error"] = f"{type(exc).__name__}: {exc}"
        else:
            health["upstream_apdu_backend"] = str(status.get("status") or "ok")
            if status.get("atr"):
                health["atr"] = str(status.get("atr"))
            if status.get("reader"):
                health["reader"] = str(status.get("reader"))
        return health

    def rig_status_payload(self, rig: RigConfig) -> dict[str, Any]:
        session_state, session = self.sessions.status_for_rig(rig.id)
        health = self.rig_health(rig)
        if not rig.enabled:
            status_text = "maintenance"
        elif session is not None:
            status_text = session_state
        elif health.get("upstream_apdu_backend") == "error":
            status_text = "error"
        else:
            status_text = "available"

        payload: dict[str, Any] = {
            "id": rig.id,
            "name": rig.name,
            "location": rig.location,
            "tags": list(rig.tags),
            "status": status_text,
            "health": health,
            "last_seen": _utc_iso(time.time()),
            "stream_port": rig.stream_proxy.external_port,
            "owner": rig.owner,
            "notes": rig.notes,
            "capabilities": list(rig.capabilities),
        }
        if session is not None:
            payload["locked_by"] = session.user
            payload["session_id"] = session.id
            payload["session_started_at"] = _utc_iso(session.started_at or session.created_at)
            payload["expires_at"] = _utc_iso(session.expires_at)
        return payload

    def relay_base_url(self, handler: BaseHTTPRequestHandler, rig: RigConfig) -> str:
        public_host = rig.stream_proxy.public_host or self.config.agent.public_host
        if not public_host:
            host_header = str(handler.headers.get("Host") or "").strip()
            public_host = host_header.split(":", 1)[0] if host_header else ""
        if not public_host:
            public_host = rig.stream_proxy.bind_host
        if public_host in ("0.0.0.0", "::"):
            public_host = "127.0.0.1"
        return f"http://{public_host}:{rig.stream_proxy.external_port}"

    def create_session_payload(
        self,
        handler: BaseHTTPRequestHandler,
        rig: RigConfig,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        session = self.sessions.create_session(
            rig.id,
            user=str(body.get("user") or "").strip(),
            client_id=str(body.get("client_id") or "").strip(),
            requested_ttl_seconds=int(body.get("requested_ttl_seconds") or 3600),
        )
        base_url = self.relay_base_url(handler, rig)
        return {
            "session_id": session.id,
            "session_token": session.token,
            "rig_id": rig.id,
            "status": session.state,
            "expires_at": _utc_iso(session.expires_at),
            "reservation_expires_at": _utc_iso(session.reservation_expires_at),
            "stream": {
                "transport": "http-card-bridge",
                "url": base_url + "/apdu",
                "status_url": base_url + "/status",
                "card_reset_url": base_url + "/card/reset",
            },
        }

    def validate_relay_session(self, rig: RigConfig, header: str) -> LabSession:
        token = parse_bearer_header(header)
        return self.sessions.validate_for_rig(rig.id, token)

    def start(self) -> None:
        for rig in self.config.rigs:
            server = _RelayServer(
                (rig.stream_proxy.bind_host, rig.stream_proxy.external_port),
                _RelayHandler,
                self,
                rig,
            )
            thread = threading.Thread(
                target=server.serve_forever,
                name=f"remote-lab-relay-{rig.id}",
                daemon=True,
            )
            thread.start()
            self._relay_servers.append(server)
            self._relay_threads.append(thread)
            _LOGGER.info(
                "remote_lab relay started rig=%s addr=%s:%s",
                rig.id,
                rig.stream_proxy.bind_host,
                rig.stream_proxy.external_port,
            )

        self._control_server = _ControlServer(
            (self.config.agent.bind_host, self.config.agent.control_port),
            _ControlHandler,
            self,
        )
        self._cleanup_stop.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="remote-lab-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()
        _LOGGER.info(
            "remote_lab control API listening on %s:%s",
            self.config.agent.bind_host,
            self.config.agent.control_port,
        )

    def serve_forever(self) -> None:
        if self._control_server is None:
            self.start()
        assert self._control_server is not None
        self._control_server.serve_forever()

    def stop(self) -> None:
        self._cleanup_stop.set()
        server = self._control_server
        self._control_server = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            server.server_close()
        for relay in self._relay_servers:
            try:
                relay.shutdown()
            except Exception:
                pass
            relay.server_close()
        self._relay_servers = []
        for thread in self._relay_threads:
            try:
                thread.join(timeout=1.0)
            except RuntimeError:
                pass
        self._relay_threads = []
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=1.0)
            self._cleanup_thread = None

    def _cleanup_loop(self) -> None:
        while not self._cleanup_stop.wait(5.0):
            expired = self.sessions.expire_stale()
            if expired:
                _LOGGER.info("remote_lab expired %d stale session(s)", expired)


class _ControlServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], service: RemoteLabAgentService) -> None:
        self.service = service
        super().__init__(address, handler)


class _RelayServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        service: RemoteLabAgentService,
        rig: RigConfig,
    ) -> None:
        self.service = service
        self.rig = rig
        super().__init__(address, handler)


class _ControlHandler(_JsonHandler):
    @property
    def service(self) -> RemoteLabAgentService:
        return self.server.service  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/healthz":
            self._send_text(HTTPStatus.OK, b"ok\n")
            return
        auth = self.service.authorize_header(self.headers.get("Authorization", ""))
        if auth is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if path == "/api/v1/info":
            self._send_json(HTTPStatus.OK, self._info_payload())
            return
        if path == "/api/v1/rigs":
            self._send_json(
                HTTPStatus.OK,
                {"rigs": [self.service.rig_status_payload(rig) for rig in self.service.config.rigs]},
            )
            return
        if path.startswith("/api/v1/rigs/") and path.endswith("/status"):
            rig_id = path[len("/api/v1/rigs/") : -len("/status")].strip("/")
            rig = self.service.rigs.get(rig_id)
            if rig is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "rig_not_found"})
                return
            self._send_json(HTTPStatus.OK, self.service.rig_status_payload(rig))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        auth = self.service.authorize_header(self.headers.get("Authorization", ""))
        if auth is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            body = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if path.startswith("/api/v1/rigs/") and path.endswith("/sessions"):
            rig_id = path[len("/api/v1/rigs/") : -len("/sessions")].strip("/")
            rig = self.service.rigs.get(rig_id)
            if rig is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "rig_not_found"})
                return
            try:
                payload = self.service.create_session_payload(self, rig, body)
            except RigBusyError as exc:
                self._send_json(HTTPStatus.LOCKED, exc.payload)
                return
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.CREATED, payload)
            return

        if path.startswith("/api/v1/sessions/") and path.endswith("/heartbeat"):
            session_id = path[len("/api/v1/sessions/") : -len("/heartbeat")].strip("/")
            try:
                session = self.service.sessions.heartbeat(
                    session_id, str(body.get("session_token") or "").strip()
                )
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, {"status": "ok", "expires_at": _utc_iso(session.expires_at)})
            return

        if path.startswith("/api/v1/rigs/") and path.endswith("/force-release"):
            rig_id = path[len("/api/v1/rigs/") : -len("/force-release")].strip("/")
            rig = self.service.rigs.get(rig_id)
            if rig is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "rig_not_found"})
                return
            admin_token = str(body.get("admin_token") or "").strip()
            bearer_is_admin = auth.role == "admin"
            body_is_admin = self.service.authorize(admin_token, role="admin") is not None
            if not bearer_is_admin and not body_is_admin:
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "admin_required"})
                return
            previous = self.service.sessions.force_release_rig(rig.id)
            _LOGGER.warning(
                "remote_lab force_release rig=%s previous=%s by=%s reason=%s",
                rig.id,
                previous.id if previous else "",
                auth.id,
                str(body.get("reason") or "").strip(),
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "released",
                    "previous_session_id": previous.id if previous else "",
                },
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_DELETE(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        auth = self.service.authorize_header(self.headers.get("Authorization", ""))
        if auth is None:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            body = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        if path.startswith("/api/v1/sessions/"):
            session_id = path[len("/api/v1/sessions/") :].strip("/")
            try:
                session = self.service.sessions.release(
                    session_id, str(body.get("session_token") or "").strip()
                )
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "released" if session else "not_found",
                    "session_id": session.id if session else "",
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _info_payload(self) -> dict[str, Any]:
        return {
            "agent_id": self.service.config.agent.id,
            "version": str(__version__),
            "name": self.service.config.agent.name,
            "capabilities": [
                "remote-apdu",
                "session-lock",
                "http-card-bridge-proxy",
                "resource-locks",
            ],
        }


class _RelayHandler(_JsonHandler):
    @property
    def service(self) -> RemoteLabAgentService:
        return self.server.service  # type: ignore[attr-defined]

    @property
    def rig(self) -> RigConfig:
        return self.server.rig  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/ping":
            self._send_text(HTTPStatus.OK, b"pong\n")
            return
        if path == "/status":
            try:
                session = self.service.validate_relay_session(
                    self.rig, self.headers.get("Authorization", "")
                )
                upstream = self.service.upstream_status(self.rig)
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            payload = dict(upstream)
            payload.setdefault("status", "ok")
            payload["rigId"] = self.rig.id
            payload["remoteLabSessionId"] = session.id
            payload["authRequired"] = True
            payload["tokenFingerprint"] = fingerprint(session.token)
            payload["url"] = self.service.relay_base_url(self, self.rig) + "/apdu"
            payload["apduUrl"] = payload["url"]
            payload["statusUrl"] = self.service.relay_base_url(self, self.rig) + "/status"
            payload["cardResetUrl"] = self.service.relay_base_url(self, self.rig) + "/card/reset"
            self._send_json(HTTPStatus.OK, payload)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in ("/apdu", "/card/reset"):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            session = self.service.validate_relay_session(
                self.rig, self.headers.get("Authorization", "")
            )
        except PermissionError as exc:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            return
        try:
            body = self._read_json_body()
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if path == "/apdu":
            apdu_hex = str(body.get("apdu") or "").strip()
            if not apdu_hex:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body is missing 'apdu'."})
                return
            self.service.sessions.mark_stream_use(session)
            try:
                payload = _request_card_relay_json(
                    self.rig.upstream.url,
                    method="POST",
                    request_json={"apdu": apdu_hex, "sessionId": session.id},
                    timeout_seconds=30,
                    auth_token=self.service.upstream_token(self.rig),
                )
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
                return
            self.service.sessions.record_bytes(
                session.id,
                bytes_in=max(0, len(apdu_hex) // 2),
                bytes_out=max(0, len(str(payload.get("data") or "")) // 2 + 2),
            )
            self._send_json(HTTPStatus.OK, payload)
            return

        try:
            payload = _request_card_relay_json(
                _reset_url_for_apdu(self.rig.upstream.url),
                method="POST",
                request_json={},
                timeout_seconds=30,
                auth_token=self.service.upstream_token(self.rig),
            )
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        self._send_json(HTTPStatus.OK, payload)


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-lab-agent",
        description="Run a self-hosted YggdraSIM Remote Lab agent.",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the Remote Lab YAML config.",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("YGGDRASIM_REMOTE_LAB_LOG_LEVEL", "INFO"),
        help="Python logging level (default: INFO).",
    )
    return parser


def run_agent_from_args(argv: list[str] | None = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level or "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = load_config(args.config)
    service = RemoteLabAgentService(config)
    stop_event = threading.Event()
    stop_lock = threading.Lock()
    stop_started = False
    stop_thread: threading.Thread | None = None

    def _stop_service_once() -> None:
        nonlocal stop_started
        with stop_lock:
            if stop_started:
                return
            stop_started = True
        service.stop()

    def _request_stop(signum: int, _frame: Any) -> None:
        nonlocal stop_thread
        _LOGGER.info("remote_lab received signal %s; stopping", signum)
        stop_event.set()
        stop_thread = threading.Thread(
            target=_stop_service_once,
            name="remote-lab-signal-stop",
            daemon=False,
        )
        stop_thread.start()

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, _request_stop)
        except (ValueError, OSError):
            pass

    try:
        service.start()
        service.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        _stop_service_once()
        if stop_thread is not None:
            stop_thread.join(timeout=2.0)
    return 0


def main() -> int:
    return run_agent_from_args()


if __name__ == "__main__":
    raise SystemExit(main())
