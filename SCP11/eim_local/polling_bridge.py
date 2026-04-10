import base64
import binascii
import json
import os
import socketserver
import ssl
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

try:
    from SCP11.live.crypto_engine import CryptoEngine
    from SCP11.live.payload_builder import PayloadBuilder
    from SCP11.live.pysim_support import decode_authenticate_server_response
except ImportError:
    from ..live.crypto_engine import CryptoEngine
    from ..live.payload_builder import PayloadBuilder
    from ..live.pysim_support import decode_authenticate_server_response

from .eim_package_codec import load_eim_package_document


@dataclass(frozen=True)
class LocalizedRouteDecision:
    host: str
    port: int
    reason: str


class _BridgeHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, bridge: "LocalizedPollingBridge", role: str):
        self.bridge = bridge
        self.role = role
        super().__init__(server_address, handler_class)


class _BridgeDnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, bridge: "LocalizedPollingBridge"):
        self.bridge = bridge
        super().__init__(server_address, handler_class)


class _BridgeHttpHandler(BaseHTTPRequestHandler):
    server_version = "YggdraSIMPollBridge/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/ping":
            payload = b"pong\n"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._send_error_payload(HTTPStatus.NOT_FOUND, b"not found\n")

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(content_length)
        if self.server.role == "eim":
            status, headers, payload = self.server.bridge.handle_eim_http_request(self.path, body)
        else:
            status, headers, payload = self.server.bridge.handle_smdp_http_request(self.path, body)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(str(key), str(value))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if len(payload) > 0:
            self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_error_payload(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if len(payload) > 0:
            self.wfile.write(payload)


class _BridgeDnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet = bytes(self.request[0])
        udp_socket = self.request[1]
        response = self.server.bridge.handle_dns_query(packet)
        if len(response) == 0:
            return
        udp_socket.sendto(response, self.client_address)


class LocalizedPollingBridge:
    """
    Local DNS + HTTPS terminator used by IPAd/IPAe validation paths.

    The bridge keeps the package queue in memory and never mutates user JSON
    files on disk. Each command run can reset the in-memory queue cursor.
    """

    EIM_PACKAGE_TAG_PREFIXES: tuple[bytes, ...] = (
        bytes.fromhex("BF51"),
        bytes.fromhex("BF52"),
        bytes.fromhex("BF54"),
    )

    def __init__(self, session: Any):
        self.session = session
        self.cfg = session.cfg
        self.bind_host = str(getattr(self.cfg, "POLL_BRIDGE_BIND_HOST", "127.0.0.1")).strip() or "127.0.0.1"
        self.dns_port = int(getattr(self.cfg, "POLL_BRIDGE_DNS_PORT", 15353) or 15353)
        self.eim_tls_port = int(getattr(self.cfg, "POLL_BRIDGE_EIM_TLS_PORT", 18443) or 18443)
        self.smdp_tls_port = int(getattr(self.cfg, "POLL_BRIDGE_SMDP_TLS_PORT", 19443) or 19443)
        self.runtime_dir = os.path.join(
            os.path.dirname(os.path.abspath(self.cfg.EIM_RUNTIME_STATE_FILE)),
            ".poll_bridge_runtime",
        )
        self._dns_server: Optional[_BridgeDnsServer] = None
        self._eim_server: Optional[_BridgeHttpServer] = None
        self._smdp_server: Optional[_BridgeHttpServer] = None
        self._threads: list[threading.Thread] = []
        self._started = False
        self._state_lock = threading.RLock()
        self._queue_index = 0
        self._pending_package: Optional[dict[str, Any]] = None
        self._acknowledgements: list[dict[str, Any]] = []
        self._transaction_counter = 0
        self._smdp_transactions: dict[str, dict[str, Any]] = {}
        self._eim_runtime_certificate_pem = ""
        self._smdp_runtime_certificate_pem = ""
        self._flow_context = {
            "flow": "localized_poll",
            "flow_run_id": "",
            "eid": "",
        }

    @property
    def eim_base_url(self) -> str:
        return f"https://{self.bind_host}:{self.eim_tls_port}"

    @property
    def smdp_base_url(self) -> str:
        return f"https://{self.bind_host}:{self.smdp_tls_port}"

    @property
    def eim_fqdn(self) -> str:
        return self._endpoint_hostname(self.session._effective_eim_endpoint())

    @property
    def smdp_fqdn(self) -> str:
        return self._endpoint_hostname(self.session._effective_smdpp_endpoint())

    def status_payload(self) -> dict[str, Any]:
        return {
            "bind_host": self.bind_host,
            "dns_port": self.dns_port,
            "eim_tls_port": self.eim_tls_port,
            "smdp_tls_port": self.smdp_tls_port,
            "eim_base_url": self.eim_base_url,
            "smdp_base_url": self.smdp_base_url,
            "eim_fqdn": self.eim_fqdn,
            "smdp_fqdn": self.smdp_fqdn,
            "queue_index": self._queue_index,
            "pending_package_path": (
                str(self._pending_package.get("path", "")).strip()
                if isinstance(self._pending_package, dict)
                else ""
            ),
            "flow": str(self._flow_context.get("flow", "")).strip(),
            "flow_run_id": str(self._flow_context.get("flow_run_id", "")).strip(),
            "eid": str(self._flow_context.get("eid", "")).strip(),
            "ack_count": len(self._acknowledgements),
            "active_transactions": len(self._smdp_transactions),
            "started": self._started,
        }

    def start(self) -> None:
        if self._started:
            return
        os.makedirs(self.runtime_dir, exist_ok=True)
        self._start_dns_server()
        self._start_https_server(role="eim")
        self._start_https_server(role="smdp")
        self._started = True

    def stop(self) -> None:
        servers = [self._dns_server, self._eim_server, self._smdp_server]
        for server in servers:
            if server is None:
                continue
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        for thread in self._threads:
            try:
                thread.join(timeout=1.0)
            except Exception:
                pass
        self._threads = []
        self._dns_server = None
        self._eim_server = None
        self._smdp_server = None
        self._started = False

    def reset_runtime_state(self) -> None:
        with self._state_lock:
            self._queue_index = 0
            self._pending_package = None
            self._acknowledgements = []
            self._smdp_transactions = {}
            self._transaction_counter = 0

    def set_flow_context(self, flow: str, flow_run_id: str = "", eid: str = "") -> None:
        normalized_flow = str(flow or "").strip().lower()
        normalized_flow = normalized_flow.replace("-", "_")
        normalized_flow = normalized_flow.replace(" ", "_")
        if len(normalized_flow) == 0:
            normalized_flow = "localized_poll"
        with self._state_lock:
            self._flow_context = {
                "flow": normalized_flow,
                "flow_run_id": str(flow_run_id or "").strip(),
                "eid": str(eid or "").strip(),
            }

    def _flow_context_snapshot(self) -> tuple[str, str, str]:
        with self._state_lock:
            return (
                str(self._flow_context.get("flow", "")).strip(),
                str(self._flow_context.get("flow_run_id", "")).strip(),
                str(self._flow_context.get("eid", "")).strip(),
            )

    def _record_poll_event(
        self,
        *,
        action: str,
        package_path: str = "",
        package_type: str = "",
        transaction_id_hex: str = "",
        matching_id: str = "",
        success: bool,
        result_len: int = 0,
        response_preview_hex: str = "",
        details: Optional[dict[str, Any]] = None,
        error: Optional[Exception] = None,
    ) -> None:
        record_event = getattr(self.session, "record_poll_audit_event", None)
        if callable(record_event) is False:
            return
        flow, flow_run_id, eid = self._flow_context_snapshot()
        record_event(
            action=action,
            package_path=package_path,
            package_type=package_type,
            transaction_id_hex=transaction_id_hex,
            matching_id=matching_id,
            success=success,
            result_len=result_len,
            response_preview_hex=response_preview_hex,
            details=details,
            error=error,
            flow=flow,
            flow_run_id=flow_run_id,
            eid=eid,
        )

    def resolve_open_channel_target(
        self,
        protocol_type: int,
        remote_address: str,
        remote_port: int,
        requested_fqdn: str = "",
        fields: Optional[dict[str, Any]] = None,
    ) -> Optional[LocalizedRouteDecision]:
        _ = protocol_type
        _ = remote_address
        _ = fields
        fqdn_value = self._normalize_fqdn(requested_fqdn)
        if remote_port == 53:
            return LocalizedRouteDecision(
                host=self.bind_host,
                port=self.dns_port,
                reason="local-dns-intercept",
            )
        if remote_port == 443 and fqdn_value == self._normalize_fqdn(self.eim_fqdn):
            return LocalizedRouteDecision(
                host=self.bind_host,
                port=self.eim_tls_port,
                reason="local-eIM-termination",
            )
        if remote_port == 443 and fqdn_value == self._normalize_fqdn(self.smdp_fqdn):
            return LocalizedRouteDecision(
                host=self.bind_host,
                port=self.smdp_tls_port,
                reason="local-SM-DP+-termination",
            )
        return None

    def handle_dns_query(self, packet: bytes) -> bytes:
        question = self._parse_dns_question(packet)
        if question is None:
            return b""
        qname_value, qtype_value, qclass_value, question_end = question
        answer_ip = ""
        if qclass_value == 1 and qtype_value == 1:
            normalized = self._normalize_fqdn(qname_value)
            if normalized == self._normalize_fqdn(self.eim_fqdn):
                answer_ip = self.bind_host
            elif normalized == self._normalize_fqdn(self.smdp_fqdn):
                answer_ip = self.bind_host
        return self._build_dns_response(packet, question_end, qtype_value, qclass_value, answer_ip)

    def handle_eim_http_request(self, path: str, body: bytes) -> tuple[int, dict[str, str], bytes]:
        normalized_path = path.strip() or "/"
        if normalized_path.rstrip("/") == "/ping":
            payload = b"pong\n"
            return HTTPStatus.OK, {"Content-Type": "text/plain; charset=utf-8"}, payload
        if normalized_path != "/gsma/rsp2/asn1":
            payload = b""
            return HTTPStatus.NOT_FOUND, {"Content-Type": "application/x-gsma-rsp-asn1"}, payload
        try:
            if body.startswith(bytes.fromhex("BF4F")):
                payload = self._serve_eim_package()
                return HTTPStatus.OK, {"Content-Type": "application/x-gsma-rsp-asn1"}, payload
            if body.startswith(bytes.fromhex("BF50")):
                payload = self._acknowledge_eim_package_result(body)
                return HTTPStatus.OK, {"Content-Type": "application/x-gsma-rsp-asn1"}, payload
        except Exception:
            return HTTPStatus.OK, {"Content-Type": "application/x-gsma-rsp-asn1"}, bytes.fromhex("BF4F0302017F")
        return HTTPStatus.OK, {"Content-Type": "application/x-gsma-rsp-asn1"}, bytes.fromhex("BF4F0302017F")

    def handle_smdp_http_request(self, path: str, body: bytes) -> tuple[int, dict[str, str], bytes]:
        normalized_path = path.strip() or "/"
        if normalized_path.rstrip("/") == "/ping":
            payload = b"pong\n"
            return HTTPStatus.OK, {"Content-Type": "text/plain; charset=utf-8"}, payload
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            error_payload = json.dumps({"error": "invalid_json"}, ensure_ascii=True).encode("utf-8")
            return HTTPStatus.BAD_REQUEST, {"Content-Type": "application/json"}, error_payload
        try:
            if normalized_path == "/gsma/rsp2/es9plus/initiateAuthentication":
                response = self._handle_smdp_initiate_authentication(payload)
            elif normalized_path == "/gsma/rsp2/es9plus/authenticateClient":
                response = self._handle_smdp_authenticate_client(payload)
            elif normalized_path == "/gsma/rsp2/es9plus/getBoundProfilePackage":
                response = self._handle_smdp_get_bound_profile_package(payload)
            elif normalized_path == "/gsma/rsp2/es9plus/cancelSession":
                response = {}
            elif normalized_path == "/gsma/rsp2/es9plus/handleNotification":
                response = {}
            else:
                return HTTPStatus.NOT_FOUND, {"Content-Type": "application/json"}, b"{}"
        except Exception as error:
            error_payload = json.dumps(
                {"error": f"{type(error).__name__}: {error}"},
                ensure_ascii=True,
            ).encode("utf-8")
            return HTTPStatus.INTERNAL_SERVER_ERROR, {"Content-Type": "application/json"}, error_payload
        return HTTPStatus.OK, {"Content-Type": "application/json"}, json.dumps(response, ensure_ascii=True).encode("utf-8")

    def _start_dns_server(self) -> None:
        self._dns_server = _BridgeDnsServer((self.bind_host, self.dns_port), _BridgeDnsHandler, bridge=self)
        thread = threading.Thread(target=self._dns_server.serve_forever, name="yggdrasim-poll-dns", daemon=True)
        thread.start()
        self._threads.append(thread)

    def _start_https_server(self, role: str) -> None:
        if role == "eim":
            port = self.eim_tls_port
            certificate_path, private_key_path = self._resolve_eim_tls_material()
        elif role == "smdp":
            port = self.smdp_tls_port
            certificate_path, private_key_path = self._resolve_smdp_tls_material()
        else:
            raise ValueError(f"Unsupported bridge role: {role}")
        server = _BridgeHttpServer((self.bind_host, port), _BridgeHttpHandler, bridge=self, role=role)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=certificate_path, keyfile=private_key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"yggdrasim-poll-{role}",
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        if role == "eim":
            self._eim_server = server
        else:
            self._smdp_server = server

    def _resolve_eim_tls_material(self) -> tuple[str, str]:
        certificate_setting = self.session._effective_trusted_tls_cert_path()
        private_key_setting = str(self.session.eim_identity.get("tls_private_key_path", "")).strip()
        if len(certificate_setting) == 0 or len(private_key_setting) == 0:
            raise RuntimeError(
                "Local eIM TLS material is not configured. "
                "Set trusted_tls_cert_path and tls_private_key_path in eim_identity.json."
            )
        certificate_path = self.session._normalize_user_path(
            certificate_setting,
            base_dir=self.cfg.EIM_CERTS_DIR,
        )
        private_key_path = self.session._normalize_user_path(
            private_key_setting,
            base_dir=self.cfg.EIM_CERTS_DIR,
        )
        pem_path = self._ensure_pem_certificate_path(certificate_path, role="eim")
        return pem_path, private_key_path

    def _resolve_smdp_tls_material(self) -> tuple[str, str]:
        self.session._ensure_local_material_loaded()
        certificate_path = str(self.session.state.selected_auth_certificate_path or "").strip()
        private_key_path = str(self.session.state.selected_auth_private_key_path or "").strip()
        if len(certificate_path) == 0 or len(private_key_path) == 0:
            certificate_path = str(getattr(self.cfg, "CERT_PATH_AUTH", "")).strip()
            private_key_path = str(getattr(self.cfg, "KEY_PATH_AUTH", "")).strip()
        pem_path = self._ensure_pem_certificate_path(certificate_path, role="smdp")
        return pem_path, private_key_path

    def _ensure_pem_certificate_path(self, certificate_path: str, role: str) -> str:
        normalized = os.path.abspath(certificate_path)
        if os.path.exists(normalized) is False:
            raise FileNotFoundError(f"Bridge certificate does not exist: {normalized}")
        lower_path = normalized.lower()
        if lower_path.endswith(".pem"):
            return normalized
        runtime_target = os.path.join(self.runtime_dir, f"{role}_server_cert.pem")
        with open(normalized, "rb") as handle:
            raw_certificate = handle.read()
        certificate = crypto_x509.load_der_x509_certificate(raw_certificate)
        pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        with open(runtime_target, "wb") as handle:
            handle.write(pem_bytes)
        if role == "eim":
            self._eim_runtime_certificate_pem = runtime_target
        else:
            self._smdp_runtime_certificate_pem = runtime_target
        return runtime_target

    def _serve_eim_package(self) -> bytes:
        with self._state_lock:
            if isinstance(self._pending_package, dict):
                return bytes(self._pending_package.get("payload", b""))
            package_paths = self._queue_package_paths()
            while self._queue_index < len(package_paths):
                package_path = package_paths[self._queue_index]
                entry = self._prepare_eim_queue_entry(package_path)
                if entry is None:
                    self._queue_index += 1
                    continue
                self._pending_package = entry
                self._record_poll_event(
                    action="localized_eim_package_served",
                    package_path=str(entry.get("path", "")).strip(),
                    package_type=str(entry.get("package_type", "")).strip(),
                    transaction_id_hex=str(entry.get("transaction_id_hex", "")).strip(),
                    matching_id=str(entry.get("matching_id", "")).strip(),
                    success=True,
                    result_len=len(bytes(entry.get("payload", b""))),
                    response_preview_hex=self.session._response_preview_hex(bytes(entry.get("payload", b""))),
                    details={
                        "queue_index": self._queue_index,
                    },
                )
                return bytes(entry["payload"])
            self._record_poll_event(
                action="localized_eim_poll_no_package",
                package_path="",
                package_type="no_package_available",
                transaction_id_hex="",
                matching_id="",
                success=True,
                result_len=0,
                response_preview_hex="BF4F03020101",
                details={
                    "queue_index": self._queue_index,
                    "eim_result_code": 1,
                    "eim_result_name": "noEimPackageAvailable",
                },
            )
            return bytes.fromhex("BF4F03020101")

    def _acknowledge_eim_package_result(self, result_tlv: bytes) -> bytes:
        with self._state_lock:
            if isinstance(self._pending_package, dict):
                pending_entry = dict(self._pending_package)
                self._acknowledgements.append(
                    {
                        "path": str(self._pending_package.get("path", "")).strip(),
                        "transaction_id_hex": str(self._pending_package.get("transaction_id_hex", "")).strip(),
                        "result_tlv_hex": bytes(result_tlv).hex().upper(),
                    }
                )
                self._record_poll_event(
                    action="localized_eim_package_result",
                    package_path=str(pending_entry.get("path", "")).strip(),
                    package_type=str(pending_entry.get("package_type", "")).strip(),
                    transaction_id_hex=str(pending_entry.get("transaction_id_hex", "")).strip(),
                    matching_id=str(pending_entry.get("matching_id", "")).strip(),
                    success=True,
                    result_len=len(result_tlv),
                    response_preview_hex=self.session._response_preview_hex(result_tlv),
                    details={
                        "queue_index": self._queue_index,
                        "result_tlv_hex": bytes(result_tlv).hex().upper(),
                    },
                )
                self._queue_index += 1
                self._pending_package = None
            package_paths = self._queue_package_paths()
            while self._queue_index < len(package_paths):
                package_path = package_paths[self._queue_index]
                entry = self._prepare_eim_queue_entry(package_path)
                if entry is None:
                    self._queue_index += 1
                    continue
                self._pending_package = entry
                self._record_poll_event(
                    action="localized_eim_package_served",
                    package_path=str(entry.get("path", "")).strip(),
                    package_type=str(entry.get("package_type", "")).strip(),
                    transaction_id_hex=str(entry.get("transaction_id_hex", "")).strip(),
                    matching_id=str(entry.get("matching_id", "")).strip(),
                    success=True,
                    result_len=len(bytes(entry.get("payload", b""))),
                    response_preview_hex=self.session._response_preview_hex(bytes(entry.get("payload", b""))),
                    details={
                        "queue_index": self._queue_index,
                    },
                )
                return bytes(entry["payload"])
            self._record_poll_event(
                action="localized_eim_poll_no_package",
                package_path="",
                package_type="no_package_available",
                transaction_id_hex="",
                matching_id="",
                success=True,
                result_len=0,
                response_preview_hex="BF4F03020101",
                details={
                    "queue_index": self._queue_index,
                    "eim_result_code": 1,
                    "eim_result_name": "noEimPackageAvailable",
                },
            )
            return bytes.fromhex("BF4F03020101")

    def _queue_package_paths(self) -> list[str]:
        package_paths: list[str] = []
        if bool(getattr(self.cfg, "EIM_POLL_INCLUDE_FIXED_FIXTURES", True)):
            fixture_dir = self.session._normalize_user_path(
                self.cfg.EIM_POLL_EIM_TO_ESIM_DIR,
                base_dir=self.cfg.EIM_PACKAGES_DIR,
            )
            if os.path.isdir(fixture_dir):
                package_paths.extend(self.session.list_eim_package_files(package_dir=fixture_dir))
        hotfolder_dir = self.session.resolve_hotfolder_path()
        if os.path.isdir(hotfolder_dir):
            package_paths.extend(self.session.list_eim_package_files(package_dir=hotfolder_dir))
        return self.session._sort_poll_queue_files(package_paths)

    def _prepare_eim_queue_entry(self, package_path: str) -> Optional[dict[str, Any]]:
        document = load_eim_package_document(package_path)
        prepared = self._prepare_network_runtime_document(document)
        payload = self.session.build_wire_payload_preview(prepared)
        if any(payload.startswith(prefix) for prefix in self.EIM_PACKAGE_TAG_PREFIXES) is False:
            return None
        runtime = prepared.get("runtime", {})
        transaction_id_hex = ""
        matching_id = ""
        if isinstance(runtime, dict):
            transaction_id_hex = str(runtime.get("transaction_id_hex", "")).strip().upper()
            matching_id = str(runtime.get("matching_id", "")).strip()
        return {
            "path": package_path,
            "package_type": str(prepared.get("package_type", "")).strip().lower(),
            "payload": payload,
            "transaction_id_hex": transaction_id_hex,
            "matching_id": matching_id,
        }

    def _prepare_network_runtime_document(self, package_document: dict[str, Any]) -> dict[str, Any]:
        prepared = json.loads(json.dumps(package_document))
        runtime = prepared.get("runtime", {})
        if isinstance(runtime, dict) is False:
            runtime = {}
            prepared["runtime"] = runtime
        package_type = str(prepared.get("package_type", "")).strip().lower()
        if package_type in ("profile_download_trigger_request", "eim_package_request"):
            if len(str(runtime.get("transaction_id_hex", "")).strip()) == 0:
                runtime["transaction_id_hex"] = self._next_eim_transaction_id_hex()
            if len(str(runtime.get("matching_id", "")).strip()) == 0:
                handover = self.session.handover_context()
                matching_id = str(handover.get("matching_id", "")).strip()
                if len(matching_id) == 0:
                    matching_id = self.session._default_matching_id()
                runtime["matching_id"] = matching_id
            if len(str(runtime.get("smdp_address", "")).strip()) == 0:
                runtime["smdp_address"] = self.session._resolve_runtime_smdp_address({})
        return prepared

    def _next_eim_transaction_id_hex(self) -> str:
        self._transaction_counter += 1
        counter_bytes = int(self._transaction_counter).to_bytes(4, "big", signed=False)
        return (bytes.fromhex("220000000000000000000000") + counter_bytes).hex().upper()

    def _handle_smdp_initiate_authentication(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.session._ensure_local_material_loaded()
        euicc_challenge = self._decode_flexible_bytes(str(payload.get("euiccChallenge", "")).strip())
        if len(euicc_challenge) == 0:
            raise ValueError("euiccChallenge is missing or empty.")
        smdp_address = str(payload.get("smdpAddress", "")).strip()
        if len(smdp_address) == 0:
            smdp_address = self.session._resolve_runtime_smdp_address({})
        signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(
            euicc_challenge,
            smdp_address,
        )
        signature = CryptoEngine.sign_asn1(signed1, self.session._key_auth)
        transaction_hex = transaction_id.hex().upper()
        self._smdp_transactions[transaction_hex] = {
            "transaction_id": bytes(transaction_id),
            "server_challenge": bytes(server_challenge),
            "smdp_address": smdp_address,
        }
        self._record_poll_event(
            action="localized_smdp_initiate_authentication",
            package_path="",
            package_type="es9plus_initiate_authentication",
            transaction_id_hex=transaction_hex,
            matching_id="",
            success=True,
            result_len=len(transaction_id),
            response_preview_hex=transaction_hex,
            details={
                "smdp_address": smdp_address,
            },
        )
        return {
            "transactionId": self._b64encode(transaction_id),
            "serverSigned1": self._b64encode(signed1),
            "serverSignature1": self._b64encode(signature),
            "serverCertificate": self._b64encode(self.session._cert_auth),
            "euiccCiPKIdToBeUsed": str(self.session.state.selected_ci_pkid or self.cfg.ROOT_CI_ID.hex().upper()),
        }

    def _handle_smdp_authenticate_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.session._ensure_local_material_loaded()
        transaction_id = self._decode_flexible_bytes(str(payload.get("transactionId", "")).strip())
        if len(transaction_id) == 0:
            raise ValueError("transactionId is missing or empty.")
        authenticate_server_response = self._decode_flexible_bytes(
            str(payload.get("authenticateServerResponse", "")).strip()
        )
        euicc_signature1 = self._extract_euicc_signature1(authenticate_server_response)
        if len(euicc_signature1) == 0:
            raise ValueError("Could not extract euiccSignature1 from authenticateServerResponse.")
        prepare_download = PayloadBuilder.build_prepare_download(
            transaction_id,
            euicc_signature1,
            self.session._cert_pb,
            self.session._key_pb,
        )
        children = self._tlv_children(self._unwrap_single_tlv_value(prepare_download, bytes.fromhex("BF21")))
        if len(children) < 3:
            raise ValueError("Local PrepareDownload payload did not contain expected children.")
        self._record_poll_event(
            action="localized_smdp_authenticate_client",
            package_path="",
            package_type="es9plus_authenticate_client",
            transaction_id_hex=transaction_id.hex().upper(),
            matching_id="",
            success=True,
            result_len=len(prepare_download),
            response_preview_hex=self.session._response_preview_hex(prepare_download),
            details={
                "prepare_download_len": len(prepare_download),
            },
        )
        return {
            "transactionID": self._b64encode(transaction_id),
            "smdpSigned2": self._b64encode(children[0]),
            "smdpSignature2": self._b64encode(children[1]),
            "smdpCertificate": self._b64encode(children[2]),
        }

    def _handle_smdp_get_bound_profile_package(self, payload: dict[str, Any]) -> dict[str, Any]:
        prepare_download_response = self._decode_flexible_bytes(
            str(payload.get("prepareDownloadResponse", "")).strip()
        )
        if len(prepare_download_response) == 0:
            raise ValueError("prepareDownloadResponse is missing or empty.")
        transaction_id = self._decode_flexible_bytes(str(payload.get("transactionId", "")).strip())
        builder_session = self._build_offline_profile_builder_session()
        builder_session.state.prepare_download_response = bytes(prepare_download_response)
        builder_session.state.transaction_id = bytes(transaction_id)
        source_bytes = builder_session._read_profile_source_bytes(profile_path="")
        if source_bytes.startswith(bytes.fromhex("BF36")):
            bpp_bytes = bytes(source_bytes)
        else:
            bpp_bytes = builder_session._build_session_bound_profile_package(source_bytes)
        self._record_poll_event(
            action="localized_smdp_get_bound_profile_package",
            package_path="",
            package_type="es9plus_get_bound_profile_package",
            transaction_id_hex=bytes(transaction_id).hex().upper(),
            matching_id="",
            success=True,
            result_len=len(bpp_bytes),
            response_preview_hex=self.session._response_preview_hex(bpp_bytes),
            details={
                "source_len": len(source_bytes),
                "bpp_len": len(bpp_bytes),
            },
        )
        return {
            "boundProfilePackage": self._b64encode(bpp_bytes),
        }

    def _build_offline_profile_builder_session(self) -> Any:
        builder = self.session.__class__(cfg=self.cfg, apdu_channel=self.session.apdu_channel)
        builder._cert_auth = self.session._cert_auth
        builder._key_auth = self.session._key_auth
        builder._cert_pb = self.session._cert_pb
        builder._key_pb = self.session._key_pb
        builder.state.allowed_ci_pkids = list(self.session.state.allowed_ci_pkids)
        builder.state.selected_ci_pkid = str(self.session.state.selected_ci_pkid or "")
        builder.state.selected_auth_certificate_path = str(self.session.state.selected_auth_certificate_path or "")
        builder.state.selected_pb_certificate_path = str(self.session.state.selected_pb_certificate_path or "")
        builder.state.selected_auth_private_key_path = str(self.session.state.selected_auth_private_key_path or "")
        builder.state.selected_pb_private_key_path = str(self.session.state.selected_pb_private_key_path or "")
        return builder

    def _extract_euicc_signature1(self, authenticate_server_response: bytes) -> bytes:
        decoded = decode_authenticate_server_response(authenticate_server_response)
        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "authenticateResponseOk" and isinstance(choice_value, dict):
                value = choice_value.get("euiccSignature1", b"")
                if isinstance(value, bytes):
                    return value
        inner_value = self._unwrap_single_tlv_value(authenticate_server_response, bytes.fromhex("BF38"))
        return self._find_first_tlv_value(inner_value, bytes.fromhex("5F37"))

    def _tlv_children(self, value: bytes) -> list[bytes]:
        rows: list[bytes] = []
        offset = 0
        while offset < len(value):
            _, _, raw_tlv, next_offset = self.session._read_tlv(value, offset)
            rows.append(raw_tlv)
            offset = next_offset
        return rows

    def _unwrap_single_tlv_value(self, payload: bytes, expected_tag: bytes) -> bytes:
        tag_bytes, value, _, _ = self.session._read_tlv(payload, 0)
        if tag_bytes != expected_tag:
            raise ValueError(f"Expected TLV {expected_tag.hex().upper()}, got {tag_bytes.hex().upper()}.")
        return value

    def _find_first_tlv_value(self, payload: bytes, wanted_tag: bytes) -> bytes:
        offset = 0
        while offset < len(payload):
            tag_bytes, value, _, next_offset = self.session._read_tlv(payload, offset)
            if tag_bytes == wanted_tag:
                return value
            if len(tag_bytes) > 0 and ((tag_bytes[0] & 0x20) != 0 or tag_bytes[0] in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3, 0xBF)):
                nested = self._find_first_tlv_value(value, wanted_tag)
                if len(nested) > 0:
                    return nested
            offset = next_offset
        return b""

    @staticmethod
    def _looks_like_hex(value: str) -> bool:
        text = str(value or "").strip()
        if len(text) == 0 or len(text) % 2 != 0:
            return False
        try:
            bytes.fromhex(text)
        except ValueError:
            return False
        return True

    def _decode_flexible_bytes(self, value: str) -> bytes:
        text = str(value or "").strip()
        if len(text) == 0:
            return b""
        if self._looks_like_hex(text):
            return bytes.fromhex(text)
        try:
            return base64.b64decode(text.encode("utf-8"), validate=True)
        except (binascii.Error, ValueError):
            return text.encode("utf-8")

    @staticmethod
    def _coerce_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        dump_method = getattr(value, "dump", None)
        if callable(dump_method):
            try:
                dumped = dump_method()
            except Exception:
                dumped = b""
            if isinstance(dumped, bytes):
                return dumped
        try:
            return bytes(value)
        except Exception:
            return b""

    def _b64encode(self, value: Any) -> str:
        raw_value = self._coerce_bytes(value)
        if len(raw_value) == 0:
            return ""
        return base64.b64encode(raw_value).decode("ascii")

    def _endpoint_hostname(self, endpoint: str) -> str:
        text = str(endpoint).strip()
        if len(text) == 0:
            return ""
        if "://" not in text:
            text = f"https://{text}"
        parsed = urlparse(text)
        return str(parsed.hostname or "").strip().lower()

    def _normalize_fqdn(self, value: str) -> str:
        return str(value or "").strip().rstrip(".").lower()

    def _parse_dns_question(self, packet: bytes) -> Optional[tuple[str, int, int, int]]:
        if len(packet) < 17:
            return None
        question_count = int.from_bytes(packet[4:6], "big", signed=False)
        if question_count != 1:
            return None
        labels: list[str] = []
        offset = 12
        while offset < len(packet):
            label_len = packet[offset]
            offset += 1
            if label_len == 0:
                break
            label_end = offset + label_len
            if label_end > len(packet):
                return None
            try:
                labels.append(packet[offset:label_end].decode("ascii"))
            except UnicodeDecodeError:
                return None
            offset = label_end
        if len(labels) == 0 or offset + 4 > len(packet):
            return None
        qtype_value = int.from_bytes(packet[offset:offset + 2], "big", signed=False)
        qclass_value = int.from_bytes(packet[offset + 2:offset + 4], "big", signed=False)
        return ".".join(labels), qtype_value, qclass_value, offset + 4

    def _build_dns_response(
        self,
        query: bytes,
        question_end: int,
        qtype_value: int,
        qclass_value: int,
        answer_ip: str,
    ) -> bytes:
        header = bytearray(query[:12])
        header[2] = 0x81
        header[3] = 0x80
        answer_count = 0
        answer_section = b""
        if len(answer_ip) > 0 and qtype_value == 1 and qclass_value == 1:
            address_bytes = bytes(int(part) & 0xFF for part in answer_ip.split("."))
            if len(address_bytes) == 4:
                answer_count = 1
                answer_section = (
                    b"\xC0\x0C"
                    + qtype_value.to_bytes(2, "big")
                    + qclass_value.to_bytes(2, "big")
                    + (60).to_bytes(4, "big")
                    + (4).to_bytes(2, "big")
                    + address_bytes
                )
        header[6:8] = (answer_count).to_bytes(2, "big")
        header[8:10] = (0).to_bytes(2, "big")
        header[10:12] = (0).to_bytes(2, "big")
        return bytes(header) + query[12:question_end] + answer_section
