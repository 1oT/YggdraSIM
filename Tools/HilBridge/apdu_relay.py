from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

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


@dataclass(frozen=True, slots=True)
class ApduRelayConfig:
    host: str = "127.0.0.1"
    port: int = 0
    enabled: bool = True


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
            self._send_text_response(HTTPStatus.OK, b"pong\n")
            return
        if normalized_path == APDU_RELAY_STATUS_PATH:
            self._send_json_response(HTTPStatus.OK, self.server.service.status_payload())
            return
        self._send_text_response(HTTPStatus.NOT_FOUND, b"not found\n")

    def do_POST(self) -> None:
        normalized_path = self.path.rstrip("/") or "/"
        if normalized_path != APDU_RELAY_PATH:
            if normalized_path == APDU_RELAY_MODEM_REFRESH_PATH:
                self._handle_modem_refresh_post()
                return
            self._send_text_response(HTTPStatus.NOT_FOUND, b"not found\n")
            return

        self._handle_apdu_post()

    def log_message(self, format: str, *args: Any) -> None:
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
            self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)})
            return

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

    def start(self) -> None:
        if self.enabled is False:
            return
        if self._server is not None:
            return

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
        return payload

    def exchange_apdu(self, apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
        return self._exchange_callback(apdu, session_id=session_id)

    def request_modem_refresh(self, *, mode: str = "", session_id: str = "") -> dict[str, Any]:
        if self._modem_refresh_callback is None:
            raise RuntimeError("Modem REFRESH control is not enabled.")
        return self._modem_refresh_callback(mode, session_id=session_id)
