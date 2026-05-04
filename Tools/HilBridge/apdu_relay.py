from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from yggdrasim_common.card_bridge_auth import (
    compare as _token_compare,
    fingerprint as _token_fingerprint,
    is_loopback_host,
    parse_bearer_header,
)

APDU_RELAY_PATH = "/apdu"
APDU_RELAY_PING_PATH = "/ping"
APDU_RELAY_STATUS_PATH = "/status"
APDU_RELAY_MODEM_REFRESH_PATH = "/modem/refresh"

# Reject request bodies larger than this. An extended APDU tops out at
# ~65 KiB of payload; the hex-encoded JSON envelope still fits
# comfortably inside 1 MiB, so anything past this is either a buggy
# caller or an attempt to hold the handler thread on an obviously
# oversized read.
_APDU_RELAY_MAX_BODY_BYTES = 1 * 1024 * 1024

DEFAULT_AUDIT_LOGGER_NAME = "yggdrasim.card_bridge.audit"


@dataclass(frozen=True, slots=True)
class ApduRelayConfig:
    """Bind + security configuration for the APDU relay HTTP service.

    Defaults reproduce the historical HilBridge behaviour (loopback,
    no auth, no audit) so existing single-machine deployments keep
    working without changes. Operators who expose the relay to anything
    other than ``127.0.0.1`` / ``::1`` must supply a non-empty
    :attr:`auth_token`; the service refuses to start otherwise -- see
    :meth:`HilBridgeApduRelayService.start`.
    """

    host: str = "127.0.0.1"
    port: int = 0
    enabled: bool = True
    # Bearer token presented by clients in ``Authorization: Bearer ...``.
    # Empty token + loopback bind = unauthenticated (back-compat).
    # Empty token + non-loopback bind = service refuses to start.
    auth_token: str = ""
    # Per-peer auth-failure throttle. Three failures inside
    # ``auth_lockout_window_seconds`` lock the peer out for
    # ``auth_lockout_duration_seconds``; afterwards the peer's failure
    # log is cleared.
    auth_lockout_failures: int = 3
    auth_lockout_window_seconds: float = 30.0
    auth_lockout_duration_seconds: float = 60.0
    # Structured audit emission. Header-only by default -- never logs
    # APDU data bytes or response payloads. The full-hex form must be
    # opted into explicitly because PIN material rides through here.
    audit_enabled: bool = False
    audit_full_apdu: bool = False
    audit_logger_name: str = DEFAULT_AUDIT_LOGGER_NAME


class _PeerThrottle:
    """Thread-safe sliding-window throttle keyed by peer IP.

    Counts authentication failures per peer and locks the peer out
    when the failure count breaches :attr:`failures` inside
    :attr:`window_seconds`. Successful authentications reset the peer's
    state so a legitimate operator who fat-fingered the token once
    isn't held out longer than they have to be.
    """

    def __init__(
        self,
        *,
        failures: int,
        window_seconds: float,
        lockout_seconds: float,
    ) -> None:
        self._failures = max(1, int(failures))
        self._window = max(0.1, float(window_seconds))
        self._lockout = max(0.1, float(lockout_seconds))
        self._lock = threading.Lock()
        self._failure_log: dict[str, list[float]] = {}
        self._lockouts: dict[str, float] = {}

    def is_locked(self, peer: str, now: float) -> bool:
        with self._lock:
            until = self._lockouts.get(peer)
            if until is None:
                return False
            if now >= until:
                self._lockouts.pop(peer, None)
                return False
            return True

    def record_failure(self, peer: str, now: float) -> bool:
        """Append a failure timestamp for *peer* and return ``True`` if locked."""
        with self._lock:
            stamps = self._failure_log.setdefault(peer, [])
            cutoff = now - self._window
            kept = [stamp for stamp in stamps if stamp >= cutoff]
            kept.append(now)
            if len(kept) >= self._failures:
                self._lockouts[peer] = now + self._lockout
                self._failure_log[peer] = []
                return True
            self._failure_log[peer] = kept
            return False

    def record_success(self, peer: str) -> None:
        with self._lock:
            self._failure_log.pop(peer, None)
            self._lockouts.pop(peer, None)


class _ApduRelayHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        service: "HilBridgeApduRelayService",
    ) -> None:
        self.service = service
        super().__init__(server_address, handler_class)


class _ApduRelayHandler(BaseHTTPRequestHandler):
    server_version = "YggdraSIMHilRelay/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        normalized_path = self.path.rstrip("/") or "/"
        if normalized_path == APDU_RELAY_PING_PATH:
            # Liveness probe stays unauthenticated. It carries no card
            # data and is the canonical way for an SSH-tunnelled
            # consumer to confirm the LocalForward is wired up.
            self._send_text_response(HTTPStatus.OK, b"pong\n")
            return
        if normalized_path == APDU_RELAY_STATUS_PATH:
            if self._enforce_authorization() is False:
                return
            self._send_json_response(
                HTTPStatus.OK, self.server.service.status_payload()
            )
            return
        self._send_text_response(HTTPStatus.NOT_FOUND, b"not found\n")

    def do_POST(self) -> None:
        normalized_path = self.path.rstrip("/") or "/"
        if normalized_path == APDU_RELAY_PATH:
            if self._enforce_authorization() is False:
                return
            self._handle_apdu_post()
            return
        if normalized_path == APDU_RELAY_MODEM_REFRESH_PATH:
            if self._enforce_authorization() is False:
                return
            self._handle_modem_refresh_post()
            return
        self._send_text_response(HTTPStatus.NOT_FOUND, b"not found\n")

    def log_message(self, format: str, *args: Any) -> None:
        # Silence stdlib's default access log; the audit log is the
        # authoritative record and the BaseHTTPRequestHandler default
        # is far too noisy for a smartcard relay.
        return

    def _send_json_response(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if len(encoded) > 0:
            self.wfile.write(encoded)

    def _send_text_response(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if len(payload) > 0:
            self.wfile.write(payload)

    def _peer_address(self) -> str:
        try:
            return str(self.client_address[0] or "").strip()
        except (AttributeError, IndexError, TypeError):
            return ""

    def _enforce_authorization(self) -> bool:
        """Return ``True`` if the caller may proceed; ``False`` after sending error.

        Wraps the throttle check + bearer comparison so the per-route
        plumbing in :meth:`do_GET` / :meth:`do_POST` stays a one-liner.
        On rejection the response has already been emitted, so the
        caller must simply return.
        """
        service: HilBridgeApduRelayService = self.server.service
        peer = self._peer_address()
        now = time.monotonic()

        if service.peer_throttle.is_locked(peer, now) is True:
            self._send_json_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Too many authentication failures; peer temporarily locked out."},
            )
            return False

        expected = service.expected_token
        if len(expected) == 0:
            # Backward-compatible loopback-only mode. The non-loopback
            # bind path is gated up at start() so we know the listen
            # interface is loopback when we get here.
            return True

        presented = parse_bearer_header(
            self.headers.get("Authorization", "")
        )
        if _token_compare(presented, expected) is True:
            service.peer_throttle.record_success(peer)
            return True

        locked_now = service.peer_throttle.record_failure(peer, now)
        if locked_now is True:
            self._send_json_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Too many authentication failures; peer temporarily locked out."},
            )
        else:
            self._send_json_response(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Missing or invalid bearer token."},
            )
        return False

    def _read_request_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            raise ValueError("Invalid Content-Length header.")
        if content_length < 0:
            raise ValueError("Negative Content-Length header.")
        if content_length > _APDU_RELAY_MAX_BODY_BYTES:
            raise ValueError(
                f"Request body of {content_length} bytes exceeds the "
                f"{_APDU_RELAY_MAX_BODY_BYTES}-byte cap."
            )
        raw_body = self.rfile.read(content_length)
        try:
            request_json = json.loads(raw_body.decode("utf-8")) if len(raw_body) > 0 else {}
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc
        if isinstance(request_json, dict) is False:
            raise ValueError("Request body must be a JSON object.")
        return request_json

    def _handle_apdu_post(self) -> None:
        started_at = time.monotonic()
        try:
            request_json = self._read_request_json()
        except ValueError as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        apdu_hex = str(request_json.get("apdu", "") or "").strip()
        session_id = str(request_json.get("sessionId", "") or "").strip()
        if len(apdu_hex) == 0:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Request body is missing 'apdu'."})
            return

        try:
            apdu = bytes.fromhex(apdu_hex)
        except ValueError as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": f"Invalid APDU hex: {exc}"})
            return

        try:
            response_data, sw1, sw2 = self.server.service.exchange_apdu(apdu, session_id=session_id)
        except Exception as exc:
            self.server.service.record_apdu_audit(
                peer=self._peer_address(),
                apdu=apdu,
                response_data=b"",
                sw1=0,
                sw2=0,
                started_at=started_at,
                session_id=session_id,
                error=str(exc),
            )
            self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return

        self.server.service.record_apdu_audit(
            peer=self._peer_address(),
            apdu=apdu,
            response_data=response_data,
            sw1=sw1,
            sw2=sw2,
            started_at=started_at,
            session_id=session_id,
            error="",
        )
        self._send_json_response(
            HTTPStatus.OK,
            {
                "data": response_data.hex().upper(),
                "sw1": f"{sw1:02X}",
                "sw2": f"{sw2:02X}",
            },
        )

    def _handle_modem_refresh_post(self) -> None:
        try:
            request_json = self._read_request_json()
        except ValueError as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        mode = str(request_json.get("mode", "") or "").strip()
        session_id = str(request_json.get("sessionId", "") or "").strip()
        try:
            payload = self.server.service.request_modem_refresh(mode=mode, session_id=session_id)
        except Exception as exc:
            self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return
        self._send_json_response(HTTPStatus.OK, payload)


class HilBridgeApduRelayService:
    def __init__(
        self,
        config: ApduRelayConfig,
        *,
        exchange_callback: Callable[[bytes], tuple[bytes, int, int]] | Callable[..., tuple[bytes, int, int]],
        status_callback: Callable[[], dict[str, Any]],
        modem_refresh_callback: Callable[[str], dict[str, Any]] | Callable[..., dict[str, Any]] | None = None,
    ) -> None:
        self._config = config
        self._exchange_callback = exchange_callback
        self._status_callback = status_callback
        self._modem_refresh_callback = modem_refresh_callback
        self._server: _ApduRelayHttpServer | None = None
        self._thread: threading.Thread | None = None
        self._peer_throttle = _PeerThrottle(
            failures=config.auth_lockout_failures,
            window_seconds=config.auth_lockout_window_seconds,
            lockout_seconds=config.auth_lockout_duration_seconds,
        )
        self._audit_logger = logging.getLogger(
            config.audit_logger_name or DEFAULT_AUDIT_LOGGER_NAME
        )

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def base_url(self) -> str:
        host = self._config.host
        port = self._config.port
        if self._server is not None:
            host = str(self._server.server_address[0])
            port = int(self._server.server_address[1])
        return f"http://{host}:{port}"

    @property
    def apdu_url(self) -> str:
        return self.base_url + APDU_RELAY_PATH

    @property
    def status_url(self) -> str:
        return self.base_url + APDU_RELAY_STATUS_PATH

    @property
    def modem_refresh_url(self) -> str:
        return self.base_url + APDU_RELAY_MODEM_REFRESH_PATH

    @property
    def expected_token(self) -> str:
        return self._config.auth_token

    @property
    def token_fingerprint(self) -> str:
        return _token_fingerprint(self._config.auth_token)

    @property
    def peer_throttle(self) -> _PeerThrottle:
        return self._peer_throttle

    @property
    def audit_logger(self) -> logging.Logger:
        return self._audit_logger

    def start(self) -> None:
        if self.enabled is False:
            return
        if self._server is not None:
            return

        # Refuse to expose a card to the network without authentication.
        # SSH ``-L`` deployments still hit this branch with loopback,
        # which is exactly what we want.
        if (
            is_loopback_host(self._config.host) is False
            and len(self._config.auth_token) == 0
        ):
            raise RuntimeError(
                f"Refusing to bind {self._config.host}:{self._config.port} without "
                f"a bearer token. Set ApduRelayConfig.auth_token to a non-empty "
                f"value or bind to a loopback address (127.0.0.1 / ::1) and route "
                f"remote access via SSH LocalForward."
            )

        self._server = _ApduRelayHttpServer(
            (self._config.host, int(self._config.port)),
            _ApduRelayHandler,
            self,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="hilbridge-apdu-relay",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        try:
            server.shutdown()
        except (OSError, RuntimeError):
            pass
        try:
            server.server_close()
        except OSError:
            pass
        if thread is not None:
            try:
                thread.join(timeout=1.0)
            except RuntimeError:
                pass

    def status_payload(self) -> dict[str, Any]:
        payload = dict(self._status_callback())
        payload.setdefault("status", "ok")
        payload.setdefault("url", self.apdu_url)
        payload.setdefault("apduUrl", self.apdu_url)
        payload.setdefault("statusUrl", self.status_url)
        if self._modem_refresh_callback is not None:
            payload.setdefault("modemRefreshUrl", self.modem_refresh_url)
        # Surface auth posture so SSH-tunnelled consumers can confirm
        # they're hitting a daemon that requires a token. We never
        # publish the token itself -- the fingerprint is enough for an
        # operator to correlate with the on-disk file.
        payload["authRequired"] = len(self._config.auth_token) > 0
        if len(self._config.auth_token) > 0:
            payload["tokenFingerprint"] = self.token_fingerprint
        return payload

    def exchange_apdu(self, apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
        return self._exchange_callback(apdu, session_id=session_id)

    def request_modem_refresh(self, *, mode: str = "", session_id: str = "") -> dict[str, Any]:
        if self._modem_refresh_callback is None:
            raise RuntimeError("Modem REFRESH control is not enabled.")
        return self._modem_refresh_callback(mode, session_id=session_id)

    def record_apdu_audit(
        self,
        *,
        peer: str,
        apdu: bytes,
        response_data: bytes,
        sw1: int,
        sw2: int,
        started_at: float,
        session_id: str,
        error: str,
    ) -> None:
        """Emit a structured audit record for one APDU exchange.

        Header-only by default. The header bytes (CLA/INS/P1/P2) plus
        ``Lc``/``Le`` and the status word leak no secret material. PIN
        bodies and AUTHENTICATE responses ride in the data fields and
        are deliberately omitted unless ``audit_full_apdu`` is set --
        which the operator must opt into and which logs a startup
        warning at the call site so they know what's on disk.
        """
        if self._config.audit_enabled is False:
            return
        record = self._build_audit_record(
            peer=peer,
            apdu=apdu,
            response_data=response_data,
            sw1=sw1,
            sw2=sw2,
            started_at=started_at,
            session_id=session_id,
            error=error,
        )
        if self._config.audit_full_apdu is True:
            record["apduHex"] = apdu.hex().upper()
            record["respHex"] = response_data.hex().upper()
        # Use a deterministic, log-friendly text format. Consumers who
        # need JSON can attach a structured handler to the named logger.
        message = " ".join(f"{key}={value}" for key, value in record.items())
        self._audit_logger.info("apdu_relay %s", message, extra={"audit": record})

    @staticmethod
    def _build_audit_record(
        *,
        peer: str,
        apdu: bytes,
        response_data: bytes,
        sw1: int,
        sw2: int,
        started_at: float,
        session_id: str,
        error: str,
    ) -> dict[str, Any]:
        elapsed_ms = max(0.0, (time.monotonic() - started_at) * 1000.0)
        record: dict[str, Any] = {
            "peer": peer or "?",
            "session": session_id or "-",
            "len": len(apdu),
            "respLen": len(response_data),
            "sw": f"{sw1:02X}{sw2:02X}",
            "latMs": f"{elapsed_ms:.2f}",
        }
        if len(apdu) >= 4:
            record["cla"] = f"{apdu[0]:02X}"
            record["ins"] = f"{apdu[1]:02X}"
            record["p1"] = f"{apdu[2]:02X}"
            record["p2"] = f"{apdu[3]:02X}"
        if len(apdu) >= 5:
            record["lc"] = f"{apdu[4]:02X}"
        if len(error) > 0:
            record["error"] = error
        return record
