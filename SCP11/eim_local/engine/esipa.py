# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ESipa for the Local eIM, and the HTTP service that carries it with the local SM-DP+ and SM-DS.

The ASN.1 binding (SGP.32 v1.3 §6.3) arrives as one POST to
``/gsma/rsp2/asn1``: GetEimPackageRequest 'BF4F', ProvideEimPackageResult
'BF50' or HandleNotificationEsipa 'BF3D' (§5.14.5-5.14.7), and the indirect
download functions. The JSON binding (§6.4) takes one path per function under
``/gsma/rsp2/esipa/`` and is transcoded onto the same handler
(``esipa_json``). The same server
answers ES9+ for the local SM-DP+, so one address serves both the eIM and the
SM-DP+ a download trigger names: the JSON binding on ``/gsma/rsp2/es9plus/*``
and the ASN.1 binding, a RemoteProfileProvisioningRequest 'A2' on the same
``/gsma/rsp2/asn1`` (SGP.22 v3.1 §6.6.1). Plain HTTP on the loopback is the
default (the rig's IPAd needs nothing more). A card's IPAe reaches the eIM over
TLS with server authentication (§2.6.3.2): ``LocalEimCardTlsServer`` is that
listener, serving the certificate chain the card was told to trust in
AddInitialEim (trustedPublicKeyDataTls). A second instance of it serves the
SM-DP+'s own TLS certificate for a card that downloads directly (``smdp_tls``).

The local SM-DS answers on the same paths: ES11 has none of its own (SGP.22
v3.1 §6.5.2 Table 57, §6.6.2.6), so ``es11_binding`` picks out the requests
that are the SM-DS's before the SM-DP+ sees them.
"""

from __future__ import annotations

import json
import re
import sqlite3
import ssl
import threading
import time
import weakref
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Sequence

from SCP11.eim_local.engine import codec, es11_binding, esipa_json
from SCP11.eim_local.engine.es9_binding import function_name, handle_es9_asn1
from SCP11.eim_local.engine.es9_passthrough import Es9PassThrough
from SCP11.eim_local.engine.identity import local_eim_name
from SCP11.eim_local.engine.indirect import IndirectRelay
from SCP11.eim_local.engine.notifications import Forwarder
from SCP11.eim_local.engine.service import ROUTE_ESIPA, LocalEim
from SCP11.eim_local.engine.smdp import ES9_PATHS, LocalSmdp, SmdpError
from SCP11.eim_local.engine.smds import LocalSmds
from SCP11.eim_local.engine.store import (
    HANDSHAKE_COMPLETED,
    HANDSHAKE_FAILED,
    HANDSHAKE_LOST,
    HANDSHAKE_REFUSED,
    TlsHandshake,
    TrafficRecord,
    utc_now_ms,
)
from SCP11.eim_local.engine.traffic import (
    BINDING_ES9_ASN1,
    BINDING_ES9_JSON,
    BINDING_ESIPA_ASN1,
    BINDING_ESIPA_JSON,
    BINDING_REFUSED,
    Verdict,
)
from SCP11.shared import es9_asn1, esipa_download
from yggdrasim_common.tls_tables import TLS_ALERT_DESCRIPTIONS

# One relay per engine for callers without a service of their own; its
# sessions must outlive a single request.
_DEFAULT_RELAYS: "weakref.WeakKeyDictionary[LocalEim, IndirectRelay]" = weakref.WeakKeyDictionary()
_DEFAULT_RELAYS_LOCK = threading.Lock()


def default_relay(engine: LocalEim) -> IndirectRelay:
    """The indirect download relay of *engine*, answering through a local SM-DP+ and SM-DS in its store."""
    with _DEFAULT_RELAYS_LOCK:
        relay = _DEFAULT_RELAYS.get(engine)
        if relay is None:
            smdp = LocalSmdp(engine.directory)
            smds = LocalSmds(engine.directory, store=engine.store)
            smdp.smds = smds
            smds.smdp = smdp
            relay = IndirectRelay(engine, smdp, smds=smds)
            _DEFAULT_RELAYS[engine] = relay
        return relay

# A card's TLS client and HTTP requests arrive one SEND DATA at a time over the
# bearer it opened, so the card-facing socket waits in minutes, not seconds.
CARD_SOCKET_TIMEOUT_S = 180.0

ASN1_PATH = "/gsma/rsp2/asn1"
ASN1_CONTENT_TYPE = "application/x-gsma-rsp-asn1"
JSON_CONTENT_TYPE = "application/json"
MAX_BODY_OCTETS = 1 << 20
ESIPA_ADMIN_PROTOCOL = "gsma/rsp/v1.3.0"
# On ES9+ the field is deprecated and fixed to v2.1.0 in request and response (SGP.22 v3.1 §6.1.1).
ES9_ADMIN_PROTOCOL = "gsma/rsp/v2.1.0"


def handle_asn1(
    engine: LocalEim,
    body: bytes,
    *,
    route: str = ROUTE_ESIPA,
    relay: IndirectRelay | None = None,
    log: Callable[[str], None] | None = None,
    verdict: Verdict | None = None,
) -> tuple[int, bytes]:
    """Answer one ESipa ASN.1 request; return (HTTP status, body).

    The indirect download steps (SGP.32 v1.3 §3.2.3.2) go to *relay*, or to
    the engine's default relay when the caller has none. *log* gets the body
    of a request the codec refuses, so an IPA's unexpected form is on record;
    *verdict* collects what the engine made of the request (the EID, the
    operation served or closed, a note) for the exchange record.
    """
    data = bytes(body or b"")
    verdict = verdict if verdict is not None else Verdict()
    if data[:2] in esipa_download.DOWNLOAD_TAGS:
        verdict.note = "indirect download step"
        return HTTPStatus.OK, (relay or default_relay(engine)).handle(data)
    if data.startswith(codec.TAG_GET_EIM_PACKAGE):
        try:
            request = codec.decode_get_eim_package_request(data)
        except codec.CodecError:
            verdict.note = codec.EIM_PACKAGE_ERRORS[codec.INVALID_EID]
            return HTTPStatus.OK, codec.build_get_eim_package_error(codec.INVALID_EID)
        verdict.eid = request.eid
        if len(request.eid) == 0:
            verdict.note = codec.EIM_PACKAGE_ERRORS[codec.MISSING_EID]
            return HTTPStatus.OK, codec.build_get_eim_package_error(codec.MISSING_EID)
        served = engine.next_package(
            request.eid,
            route=route,
            notify_state_change=request.notify_state_change,
            state_change_cause=request.state_change_cause,
        )
        verdict.served(served)
        return HTTPStatus.OK, served.response
    if data.startswith(codec.TAG_PROVIDE_EIM_PACKAGE_RESULT):
        return HTTPStatus.OK, _provide_result(engine, data, route, log, verdict)
    if data.startswith(codec.TAG_HANDLE_NOTIFICATION_ESIPA):
        try:
            kind, inner = codec.decode_handle_notification_esipa(data)
        except codec.CodecError as error:
            if log is not None:
                log(f"ESipa BF3D refused ({error}): {data.hex().upper()[:200]}")
            verdict.note = f"refused: {error}"
            return HTTPStatus.BAD_REQUEST, b""
        if kind == "provide_result":
            _provide_result(engine, inner, route, log, verdict)
        elif (relay or default_relay(engine)).forward_notification(inner):
            # The ProfileInstallationResult of a relayed download went to its SM-DP+ inside the
            # download session (SGP.32 v1.3 §3.2.3.2 step 23), or is on the record for another attempt.
            verdict.note = "ProfileInstallationResult of an indirect download taken by its session"
        else:
            _take_notification(engine, inner, route, log, verdict)
        # A Notification function: HTTP 204, no body (SGP.32 v1.3 §6.1).
        return HTTPStatus.NO_CONTENT, b""
    if len(data) == 0:
        # A live IPAe posts an ESipa request with Content-Length 0 now and then and, answered 400, closes its
        # channel and polls no more until the next reset. No ESipa function has an empty body (SGP.32 v1.3
        # §6.3), so there is nothing to execute; the empty answer of a notification (HTTP 204, §6.1) lets the
        # IPA go on with its next poll.
        verdict.note = "empty ESipa request; answered 204 so the IPA goes on"
        return HTTPStatus.NO_CONTENT, b""
    verdict.note = "refused: not an ESipa message"
    return HTTPStatus.BAD_REQUEST, b""


def _take_notification(
    engine: LocalEim,
    notification: bytes,
    route: str,
    log: Callable[[str], None] | None,
    verdict: Verdict,
) -> None:
    """Put a Notification of ESipa.HandleNotification on the record of the eUICC that signed it.

    The function carries no EID (SGP.32 v1.3 §5.14.7), and the answer is the
    204 of a Notification function whatever the eIM makes of it: the eUICC is
    found by its signature, and a Notification no record's certificate
    verifies is not taken, so it is never sent anywhere.
    """
    eid = engine.notification_owner(notification)
    if not eid:
        verdict.note = "notification signed by no eUICC on record: not taken"
        if log is not None:
            log(f"ESipa BF3D: {verdict.note}: {bytes(notification).hex().upper()[:200]}")
        return
    verdict.eid = eid
    verdict.accepted(engine.accept_notification(eid, notification, route=route))


def _provide_result(
    engine: LocalEim,
    data: bytes,
    route: str,
    log: Callable[[str], None] | None = None,
    verdict: Verdict | None = None,
) -> bytes:
    verdict = verdict if verdict is not None else Verdict()
    try:
        request = codec.decode_provide_eim_package_result(data)
        verdict.eid = request.eid
        accepted = engine.accept_result(request.eid, request.result.raw, route=route)
    except codec.CodecError as error:
        report = codec.misplaced_get_eim_package_request(data)
        if report is not None:
            verdict.eid = report.eid
            noted = engine.note_state_report(report.eid, report) if len(report.eid) > 0 else "no EID"
            verdict.note = f"IPA state report ({noted}), acknowledged"
            if log is not None:
                log(f"ESipa BF50 carries a GetEimPackageRequest, an IPA state report ({noted}): acknowledged "
                    "with the empty response")
            return codec.build_provide_result_response()
        if log is not None:
            log(f"ESipa BF50 refused ({error}): {data.hex().upper()[:400]}")
        verdict.note = f"refused: {error}"
        return codec.build_provide_result_response(error=codec.UNDEFINED_ERROR)
    verdict.accepted(accepted)
    return accepted.response


class _Handler(BaseHTTPRequestHandler):
    server_version = "YggdraSIM-LocalEim/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class names it so
        self.server.log(f"{self.address_string()} {format % args}")

    def _reply(
        self,
        status: int,
        body: bytes,
        content_type: str | None,
        admin_protocol: str = ESIPA_ADMIN_PROTOCOL,
    ) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Admin-Protocol", admin_protocol)
        self.end_headers()
        if len(body) > 0:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        if self.path.rstrip("/") == "/ping":
            self._reply(HTTPStatus.OK, b"pong\n", "text/plain; charset=utf-8")
            return
        if self.path.rstrip("/") == "/status":
            self._reply(HTTPStatus.OK, json.dumps(self.server.status()).encode("utf-8"), JSON_CONTENT_TYPE)
            return
        self._reply(HTTPStatus.NOT_FOUND, b"", "text/plain")

    def handle_one_request(self) -> None:
        """One request, with a chunk terminator left between two requests skipped instead of answered 400.

        An IPA that frames a POST with the chunked transfer coding and only
        sends its final ``0`` and empty line after it has read the answer
        leaves them in front of its next request line (a live eUICC's IPAe did,
        and got a 400 for the "0" on every poll). They end the previous
        message (RFC 2616 §3.6.1) and are consumed as such.
        """
        try:
            self.raw_requestline = self.rfile.readline(65537)
            while len(self.raw_requestline) > 0 and self.raw_requestline.strip() in (b"", b"0"):
                self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if len(self.raw_requestline) == 0:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            method = getattr(self, "do_" + self.command, None)
            if method is None:
                self.send_error(HTTPStatus.NOT_IMPLEMENTED, f"Unsupported method ({self.command!r})")
                return
            method()
            self.wfile.flush()
        except TimeoutError as error:
            self.log_error("Request timed out: %r", error)
            self.close_connection = True

    def _read_body(self) -> bytes | None:
        """The request body under Content-Length or the chunked transfer coding (RFC 2616 §3.6.1); None once refused."""
        if "chunked" in str(self.headers.get("Transfer-Encoding", "") or "").lower():
            body = bytearray()
            while True:
                size_line = self.rfile.readline(65537)
                if len(size_line) == 0:
                    break
                try:
                    size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                except ValueError:
                    self._refuse_body(HTTPStatus.BAD_REQUEST, "refused: a chunk size that is not hexadecimal")
                    return None
                if size == 0:
                    # The trailer section, if any, ends with an empty line.
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                if len(body) + size > MAX_BODY_OCTETS:
                    self._refuse_body(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                      f"refused: a chunked body past {MAX_BODY_OCTETS} bytes")
                    return None
                body += self.rfile.read(size)
                self.rfile.readline(3)
            return bytes(body)
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY_OCTETS:
            self._refuse_body(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, f"refused: a body of {length} bytes")
            return None
        return self.rfile.read(length)

    def _request_envelope(self) -> str:
        """The request line and headers, kept with a refusal: what the IPA sent around a body that was not read."""
        headers = "; ".join(f"{name}: {value}" for name, value in self.headers.items())
        return f"{self.requestline}; {headers}"[:400]

    def _refuse_body(self, status: int, note: str) -> None:
        """Answer a body the listener will not read, and record the refusal so the exchange is on file too."""
        path = self.path.split("?", 1)[0].rstrip("/")
        self.server.record_traffic(self.connection, self.client_address, BINDING_REFUSED, path, b"", int(status), b"",
                                   Verdict(note=f"{note}; request {self._request_envelope()}"), 0.0)
        self.server.log(f"{path}: {note}")
        self._reply(status, b"", "text/plain")

    def do_POST(self) -> None:  # noqa: N802 - http.server's naming
        started = time.monotonic()
        body = self._read_body()
        if body is None:
            return
        path = self.path.split("?", 1)[0].rstrip("/")
        verdict = Verdict()
        # The answer is recorded before it is sent (_answer), so an IPAe terminal that reads the
        # bytes off its channel socket finds the exchange in the store at once.
        if path == ASN1_PATH and es9_asn1.is_wrapped(body) and es11_binding.claims_asn1(self.server.smds, body):
            # ES11 shares the 'A2' wrapper with ES9+ (SGP.22 v3.1 §6.6.2.6): the SM-DS takes what names it.
            name = es11_binding.function_name(body)
            try:
                status, answer = es11_binding.handle_es11_asn1(self.server.smds, body)
            except (ValueError, OSError, RuntimeError, LookupError, sqlite3.Error) as error:
                self.server.log(f"ES11 ASN.1 {name} failed: {type(error).__name__}: {error}")
                verdict.note = f"failed: {type(error).__name__}: {error}"
                self._answer(BINDING_ES9_ASN1, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"", None,
                             ES9_ADMIN_PROTOCOL, verdict, started)
                return
            verdict.note = f"ES11 {name}"
            record = self._answer(BINDING_ES9_ASN1, path, body, status, answer,
                                  ASN1_CONTENT_TYPE if len(answer) > 0 else None, ES9_ADMIN_PROTOCOL, verdict, started)
            self.server.log(f"ES11 ASN.1 {name} -> HTTP {int(status)}, {len(answer)} bytes{record}")
            return
        passthrough = getattr(self.server, "es9_passthrough", None)
        if path == ASN1_PATH and es9_asn1.is_wrapped(body) and passthrough is not None and passthrough.claims(body):
            # An InitiateAuthentication that names another SM-DP+, or a later step of one: passed through to
            # that SM-DP+ when a download trigger of this eIM names it, else refused; never answered here.
            name = function_name(body)
            try:
                status, answer, note = passthrough.handle(body, str(self.headers.get("X-Admin-Protocol", "") or ""))
            except (ValueError, OSError, RuntimeError, LookupError, sqlite3.Error) as error:
                self.server.log(f"ES9+ ASN.1 {name} pass-through failed: {type(error).__name__}: {error}")
                verdict.note = f"failed: {type(error).__name__}: {error}"
                self._answer(BINDING_ES9_ASN1, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"", None,
                             ES9_ADMIN_PROTOCOL, verdict, started)
                return
            verdict.note = note
            record = self._answer(BINDING_ES9_ASN1, path, body, status, answer,
                                  ASN1_CONTENT_TYPE if len(answer) > 0 else None, ES9_ADMIN_PROTOCOL, verdict, started)
            self.server.log(f"ES9+ ASN.1 {name} -> HTTP {int(status)}, {len(answer)} bytes: {note}{record}")
            return
        if path == ASN1_PATH and es9_asn1.is_wrapped(body) and self.server.smdp is not None:
            # 'A2' opens no ESipa message (SGP.32 v1.3 §6.3), so the wrapper alone tells the two bindings apart.
            name = function_name(body)
            try:
                status, answer = handle_es9_asn1(self.server.smdp, body)
            except (ValueError, OSError, RuntimeError, LookupError) as error:
                self.server.log(f"ES9+ ASN.1 {name} failed: {type(error).__name__}: {error}")
                verdict.note = f"failed: {type(error).__name__}: {error}"
                self._answer(BINDING_ES9_ASN1, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"", None,
                             ES9_ADMIN_PROTOCOL, verdict, started)
                return
            verdict.note = f"ES9+ {name}"
            # No Content-Type on an empty body (SGP.22 v3.1 §6.1.1).
            record = self._answer(BINDING_ES9_ASN1, path, body, status, answer,
                                  ASN1_CONTENT_TYPE if len(answer) > 0 else None, ES9_ADMIN_PROTOCOL, verdict, started)
            self.server.log(f"ES9+ ASN.1 {name} -> HTTP {int(status)}, {len(answer)} bytes{record}")
            return
        if path == ASN1_PATH:
            try:
                status, answer = handle_asn1(self.server.engine, body, relay=self.server.relay, log=self.server.log,
                                             verdict=verdict)
            except (ValueError, OSError, RuntimeError, LookupError) as error:
                # The IPA gets an answer either way; the cause goes to the log.
                self.server.log(f"ESipa {body[:2].hex().upper()} failed: {type(error).__name__}: {error}")
                verdict.note = f"failed: {type(error).__name__}: {error}"
                self._answer(BINDING_ESIPA_ASN1, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"",
                             ASN1_CONTENT_TYPE, ESIPA_ADMIN_PROTOCOL, verdict, started)
                return
            if int(status) == HTTPStatus.BAD_REQUEST:
                # What came around a body that is no ESipa message (an IPAe sent an empty POST on a reopened
                # channel): the request line and headers go on file with the refusal.
                verdict.note = f"{verdict.note}; request {self._request_envelope()}"
            record = self._answer(BINDING_ESIPA_ASN1, path, body, status, answer, ASN1_CONTENT_TYPE,
                                  ESIPA_ADMIN_PROTOCOL, verdict, started)
            self.server.log(f"ESipa {body[:2].hex().upper()} -> {answer[:6].hex().upper()} ({len(answer)} bytes){record}")
            self.server.notifications_taken(verdict)
            return
        if path in esipa_json.JSON_PATHS:
            function = esipa_json.JSON_PATHS[path]
            try:
                status, answer = esipa_json.handle_json(
                    function, body,
                    lambda message: handle_asn1(self.server.engine, message, relay=self.server.relay,
                                                log=self.server.log, verdict=verdict))
            except (ValueError, OSError, RuntimeError, LookupError) as error:
                self.server.log(f"ESipa JSON {function} failed: {type(error).__name__}: {error}")
                verdict.note = f"failed: {type(error).__name__}: {error}"
                self._answer(BINDING_ESIPA_JSON, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"", None,
                             ESIPA_ADMIN_PROTOCOL, verdict, started)
                return
            # A Notification answers 204 with no body, hence no Content-Type (SGP.32 v1.3 §6.1.2).
            record = self._answer(BINDING_ESIPA_JSON, path, body, status, answer,
                                  esipa_json.CONTENT_TYPE if len(answer) > 0 else None, ESIPA_ADMIN_PROTOCOL,
                                  verdict, started)
            self.server.log(f"ESipa JSON {function} -> HTTP {int(status)}, {len(answer)} bytes{record}")
            self.server.notifications_taken(verdict)
            return
        if path in ES9_PATHS and self.server.smds is not None:
            try:
                claimed = json.loads(body.decode("utf-8") or "{}")
            except ValueError:
                claimed = None
            if isinstance(claimed, dict) and es11_binding.claims_json(self.server.smds, path, claimed):
                # ES11 is posted to the ES9+ paths (SGP.22 v3.1 §6.5.2 Table 57): the SM-DS takes what names it.
                function = path.rsplit("/", 1)[-1]
                try:
                    answer = es11_binding.handle_es11_json(self.server.smds, path, claimed)
                except sqlite3.Error as error:
                    self.server.log(f"ES11 {function} failed: {type(error).__name__}: {error}")
                    verdict.note = f"failed: {type(error).__name__}: {error}"
                    self._answer(BINDING_ES9_JSON, path, body, HTTPStatus.INTERNAL_SERVER_ERROR, b"", None,
                                 ES9_ADMIN_PROTOCOL, verdict, started)
                    return
                failed = answer.get("header", {}).get("functionExecutionStatus", {}).get("status") == "Failed"
                verdict.note = f"ES11 {function}" + (" refused" if failed else "")
                self._answer(BINDING_ES9_JSON, path, body, HTTPStatus.OK, json.dumps(answer).encode("utf-8"),
                             JSON_CONTENT_TYPE, ES9_ADMIN_PROTOCOL, verdict, started)
                return
        if path in ES9_PATHS and self.server.smdp is not None:
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
                answer = self.server.smdp.handle(path, payload if isinstance(payload, dict) else {})
            except (SmdpError, ValueError, OSError, RuntimeError, LookupError) as error:
                self.server.log(f"ES9+ {path} refused: {error}")
                # A refusal that names its status code (SmdpAddressError) keeps it; the rest are 8.1 / 4.2.
                failure = {"header": {"functionExecutionStatus": {"status": "Failed", "statusCodeData": {
                    "subjectCode": str(getattr(error, "subject_code", "8.1")),
                    "reasonCode": str(getattr(error, "reason_code", "4.2")), "message": str(error)[:200]}}}}
                verdict.note = f"refused: {error}"
                self._answer(BINDING_ES9_JSON, path, body, HTTPStatus.OK, json.dumps(failure).encode("utf-8"),
                             JSON_CONTENT_TYPE, ES9_ADMIN_PROTOCOL, verdict, started)
                return
            answer.setdefault("header", {"functionExecutionStatus": {"status": "Executed-Success"}})
            verdict.note = f"ES9+ {path.rsplit('/', 1)[-1]}"
            self._answer(BINDING_ES9_JSON, path, body, HTTPStatus.OK, json.dumps(answer).encode("utf-8"),
                         JSON_CONTENT_TYPE, ES9_ADMIN_PROTOCOL, verdict, started)
            return
        verdict.note = "no such path"
        self._answer("", path, body, HTTPStatus.NOT_FOUND, b"", "text/plain", ESIPA_ADMIN_PROTOCOL, verdict, started)

    def _answer(
        self,
        binding: str,
        path: str,
        body: bytes,
        status: int,
        answer: bytes,
        content_type: str | None,
        admin_protocol: str,
        verdict: Verdict,
        started: float,
    ) -> str:
        """Record the exchange, then send the answer; returns the log suffix naming the record."""
        suffix = ""
        if len(binding) > 0:
            record = self.server.record_traffic(self.connection, self.client_address, binding, path, body,
                                                int(status), answer, verdict, time.monotonic() - started)
            if record is not None:
                suffix = f" peer :{record.peer_port} #{record.id}"
        self._reply(status, answer, content_type, admin_protocol)
        return suffix


class LocalEimHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        engine: LocalEim,
        address: tuple[str, int],
        *,
        smdp: LocalSmdp | None = None,
        smds: LocalSmds | None = None,
        tls: tuple[str, str] | None = None,
        log: Callable[[str], None] | None = None,
        relay: IndirectRelay | None = None,
    ) -> None:
        super().__init__(address, _Handler)
        self.engine = engine
        self.smdp = smdp
        self.smds = smds
        self.log = log or (lambda _line: None)
        if self.smdp is not None:
            self.smdp.log = self.log
        if self.smds is not None:
            self.smds.log = self.log
            if self.smdp is not None:
                # The SM-DP+ deletes the Event Record a download came from (SGP.22 v3.1 §3.1.3.3 step 10),
                # and keeps a name the SM-DS was given as well.
                self.smdp.smds = self.smds
                self.smds.smdp = self.smdp
        self.relay = relay if relay is not None else IndirectRelay(engine, smdp, smds=smds, log=self.log)
        # ES9+ a card sends to this address for another SM-DP+ (es9_passthrough).
        self.es9_passthrough = Es9PassThrough(engine, smdp, log=self.log)
        # Set by a service that forwards Notifications (server.run); a listener without one takes them
        # and sends none.
        self.forwarder: Forwarder | None = None
        self.tls = tls is not None
        # The chain a card-facing listener serves when no server name picks another; '' on the plain one.
        self.tls_label = ""
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=tls[0], keyfile=tls[1])
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"{'https' if self.tls else 'http'}://{host}:{port}"

    def notifications_taken(self, verdict: Verdict) -> None:
        """Start a forwarding pass when the request just answered put Notifications on a record."""
        if self.forwarder is not None and verdict.notifications > 0:
            self.forwarder.kick()

    def record_traffic(
        self,
        connection: Any,
        client_address: Any,
        binding: str,
        path: str,
        request: bytes,
        status: int,
        response: bytes,
        verdict: Verdict,
        seconds: float,
    ) -> TrafficRecord | None:
        """Write one exchange to the engine store; None when the store refused it (the answer still goes out)."""
        peer_host, peer_port = "", 0
        if isinstance(client_address, tuple) and len(client_address) >= 2:
            peer_host, peer_port = str(client_address[0]), int(client_address[1])
        version, cipher = "", ""
        version_of = getattr(connection, "version", None)
        cipher_of = getattr(connection, "cipher", None)
        if callable(version_of) and callable(cipher_of):
            try:
                version = str(version_of() or "")
                chosen = cipher_of()
                cipher = str(chosen[0]) if chosen else ""
            except (ssl.SSLError, OSError, ValueError):
                version, cipher = "", ""
        setup = str(getattr(connection, "yggdrasim_tls_setup", "") or "") or (self.tls_label if version else "")
        record = TrafficRecord(
            id=0, at=utc_now_ms(), peer_host=peer_host, peer_port=peer_port,
            listener_port=int(self.server_address[1]), tls_setup=setup, tls_version=version, tls_cipher=cipher,
            binding=binding, path=path, request=bytes(request), status=int(status), response=bytes(response),
            duration_ms=int(round(seconds * 1000)), eid=verdict.eid, operation_id=verdict.operation_id,
            note=verdict.note, tls_leaf=str(getattr(connection, "yggdrasim_tls_leaf", "") or ""),
        )
        try:
            self.engine.store.insert_traffic(record)
        except (OSError, ValueError, RuntimeError) as error:
            self.log(f"exchange not recorded: {type(error).__name__}: {error}")
            return None
        handshake_id = getattr(connection, "yggdrasim_tls_handshake", None)
        if isinstance(handshake_id, int):
            # The handshake row learns that the client went on to talk, and which eUICC it was.
            try:
                self.engine.store.note_handshake_request(handshake_id, verdict.eid)
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                self.log(f"handshake {handshake_id} not updated: {type(error).__name__}: {error}")
        return record

    def status(self) -> dict[str, Any]:
        from SCP11.eim_local.engine.tls_setup import effective_fqdn

        identity = self.engine.identity_or_none()
        return {
            "url": self.url,
            "eim_id": identity.eim_id if identity else "",
            "eim_fqdn": effective_fqdn(self.engine.directory, identity),
            "smdp_address": self.smdp.address() if self.smdp is not None else "",
            "smds_address": self.smds.address() if self.smds is not None else "",
        }

    def start_in_thread(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, name="local-eim-esipa", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def card_tls_context(
    chain_path: str,
    key_path: str,
    *,
    versions: str = "1.2+",
    ciphers: str = "",
    client_auth: str = "none",
    client_ca_path: str = "",
    sni_names: tuple[str, ...] = (),
    keylog_path: str = "",
) -> ssl.SSLContext:
    """Server context for a card's IPAe: TLS 1.2 or later (SGP.32 v1.3 §2.6.3.2, p.21).

    *chain_path* holds the leaf certificate followed by any intermediate the
    listener sends. *versions* is ``1.2``, ``1.3`` or ``1.2+``; *ciphers* an
    OpenSSL TLS 1.2 cipher list, empty for OpenSSL's default. §2.6.3.2 asks
    for server authentication, which is *client_auth* ``none``; ``optional``
    asks the client for a certificate under *client_ca_path* and serves a
    client without one, ``required`` refuses that client. A non-empty
    *sni_names* makes the listener answer only a ClientHello whose
    server_name (RFC 6066 §3) is one of them. *keylog_path* names the file
    the session secrets are appended to in the NSS key log format, which
    Wireshark reads to decrypt a capture of the sessions this context serves.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if len(keylog_path) > 0:
        context.keylog_filename = keylog_path
    if client_auth in ("optional", "required"):
        if len(client_ca_path) == 0:
            raise ValueError(f"client_auth {client_auth} needs the CA file the client certificates chain to.")
        context.verify_mode = ssl.CERT_REQUIRED if client_auth == "required" else ssl.CERT_OPTIONAL
        try:
            context.load_verify_locations(cafile=client_ca_path)
        except (ssl.SSLError, OSError) as error:
            raise ValueError(f"The client CA file {client_ca_path} does not load: {error}") from error
    elif client_auth != "none":
        raise ValueError(f"client_auth is none, optional or required, not {client_auth!r}.")
    if len(sni_names) > 0:
        wanted = {str(name).lower().rstrip(".") for name in sni_names}

        def _check_server_name(_socket: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext) -> int | None:
            if server_name is None or server_name.lower().rstrip(".") not in wanted:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            return None

        context.sni_callback = _check_server_name
    if versions == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif versions == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    elif versions == "1.2+":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        raise ValueError(f"TLS versions are 1.2, 1.3 or 1.2+, not {versions!r}.")
    if len(ciphers) > 0:
        try:
            context.set_ciphers(ciphers)
        except ssl.SSLError as error:
            raise ValueError(f"OpenSSL takes no cipher from {ciphers!r}: {error}") from error
    try:
        context.load_cert_chain(certfile=chain_path, keyfile=key_path)
    except (ssl.SSLError, OSError) as error:
        raise ValueError(f"The TLS chain {chain_path} with key {key_path} does not load: {error}") from error
    return context


def card_tls_contexts(materials: Sequence[Any], keylog_path: str = "") -> ssl.SSLContext:
    """One server context per chain, the first the default; the ClientHello's server_name picks another (RFC 6066 §3).

    Each material (``tls_setup.ServingMaterial``) answers for its ``names``
    (exact) and ``patterns`` (``*.domain``); a Local eIM server_name
    (``identity.local_eim_name``) no chain answers for stays with the default,
    any other server_name is refused with unrecognized_name. A material with ``sni_names`` (its setup's
    ``sni=required``) is served only to a ClientHello naming it. The client
    authentication of the picked chain applies to the connection. The chain
    picked is noted on the connection (``yggdrasim_tls_setup``) for the
    exchange record. *keylog_path* goes to every context.
    """
    if len(materials) == 0:
        raise ValueError("The card-facing listener needs at least one chain to serve.")
    contexts: list[tuple[Any, ssl.SSLContext]] = []
    for material in materials:
        context = card_tls_context(material.chain_path, material.key_path, versions=material.versions,
                                   ciphers=material.ciphers, client_auth=material.client_auth,
                                   client_ca_path=material.client_ca_path, keylog_path=keylog_path)
        contexts.append((material, context))
    default_material, default = contexts[0]
    exact: dict[str, tuple[Any, ssl.SSLContext]] = {}
    patterns: list[tuple[str, Any, ssl.SSLContext]] = []
    for material, context in reversed(contexts):
        # Earlier materials win a name two of them carry; the default is first.
        for name in material.names:
            exact[name] = (material, context)
    for material, context in contexts:
        for pattern in material.patterns:
            patterns.append((pattern[1:], material, context))

    def _refuse_name(sslobj: ssl.SSLObject) -> int:
        _note(sslobj, "yggdrasim_tls_alert", TLS_ALERT_DESCRIPTIONS[ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME])
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    def _pick(sslobj: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext) -> int | None:
        if server_name is None:
            _note_setup(sslobj, default_material.label)
            return _refuse_name(sslobj) if default_material.sni_names else None
        asked = server_name.lower().rstrip(".")
        _note(sslobj, "yggdrasim_tls_server_name", asked)
        if not local_eim_name(asked):
            # Another eIM's name is never answered, whatever brought the connection here.
            _note_setup(sslobj, default_material.label)
            return _refuse_name(sslobj)
        picked = exact.get(asked)
        if picked is None:
            for suffix, material, context in patterns:
                # A wildcard matches one domain name component (RFC 2818 §3.1): the part before the suffix holds no dot.
                head = asked[: -len(suffix)] if asked.endswith(suffix) else ""
                if len(head) > 0 and "." not in head:
                    picked = (material, context)
                    break
        if picked is None:
            picked = (default_material, default)
        material, context = picked
        _note_setup(sslobj, material.label)
        if material.sni_names and asked not in {name.lower().rstrip(".") for name in material.sni_names}:
            return _refuse_name(sslobj)
        if context is not default:
            sslobj.context = context
        return None

    default.sni_callback = _pick
    # The listener reads this: on such a context a connection without a picked chain never got a leaf offered.
    _note(default, "yggdrasim_notes_setup", True)
    return default


def _note(sslobj: Any, attribute: str, value: Any) -> None:
    """Leave *value* on the connection under *attribute*; an SSLObject of a memory BIO takes no attribute."""
    try:
        setattr(sslobj, attribute, value)
    except (AttributeError, TypeError):
        pass


def _note_setup(sslobj: Any, label: str) -> None:
    """Leave the picked chain's label on the connection."""
    _note(sslobj, "yggdrasim_tls_setup", str(label))


# The TLS library names a fatal alert it received in the reason of its error: SSLV3_ALERT_BAD_CERTIFICATE,
# TLSV1_ALERT_UNKNOWN_CA, TLSV13_ALERT_CERTIFICATE_REQUIRED, and five of them without the word ALERT.
_ALERT_BY_REASON = {name.upper(): name for name in TLS_ALERT_DESCRIPTIONS.values()}
_ALERT_REASON = re.compile(r"^(?:SSLV3|TLSV1|TLSV13)_ALERT_(?P<name>[A-Z0-9_]+)$")
_UNMARKED_ALERT_REASONS = {
    "TLSV1_UNSUPPORTED_EXTENSION": "unsupported_extension",
    "TLSV1_CERTIFICATE_UNOBTAINABLE": "certificate_unobtainable",
    "TLSV1_UNRECOGNIZED_NAME": "unrecognized_name",
    "TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE": "bad_certificate_status_response",
    "TLSV1_BAD_CERTIFICATE_HASH_VALUE": "bad_certificate_hash_value",
}
# The peer closed the connection in the middle of the handshake; some builds report it as a plain SSLError.
_EOF_REASONS = frozenset({"UNEXPECTED_EOF_WHILE_READING"})


def classify_handshake_end(error: BaseException) -> tuple[str, str, str]:
    """(outcome, alert, reason) for the exception that ended a card-facing handshake.

    ``refused`` with the alert's registry name (RFC 8446 §6) when the client
    sent a fatal alert; ``failed`` when this side ended it (no shared cipher,
    no client certificate, a ClientHello it cannot read); ``lost`` when the
    connection closed or stalled without an alert. *reason* is the library's
    own word for it.
    """
    reason = str(getattr(error, "reason", "") or "")
    if isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError)) or reason in _EOF_REASONS:
        return HANDSHAKE_LOST, "", reason or type(error).__name__
    if isinstance(error, ssl.SSLError) and len(reason) > 0:
        marked = _ALERT_REASON.match(reason)
        if marked is not None:
            # The library spells one alert the British way; the registry name is user_canceled.
            name = marked.group("name").replace("CANCELLED", "CANCELED")
            return HANDSHAKE_REFUSED, _ALERT_BY_REASON.get(name, name.lower()), reason
        if reason in _UNMARKED_ALERT_REASONS:
            return HANDSHAKE_REFUSED, _UNMARKED_ALERT_REASONS[reason], reason
        return HANDSHAKE_FAILED, "", reason
    text = str(error)
    return HANDSHAKE_LOST, "", f"{type(error).__name__}: {text}" if text else type(error).__name__


class LocalEimCardTlsServer(LocalEimHttpServer):
    """The card-facing ESipa listener: TLS per connection, the handshake on the worker thread.

    Wrapping the listening socket would run every handshake on the accept
    loop, so one card's slow ClientHello over its bearer would hold every
    other client, the loopback IPAd included.
    """

    def __init__(
        self,
        engine: LocalEim,
        address: tuple[str, int],
        context: ssl.SSLContext,
        *,
        smdp: LocalSmdp | None = None,
        smds: LocalSmds | None = None,
        log: Callable[[str], None] | None = None,
        relay: IndirectRelay | None = None,
        socket_timeout_s: float = CARD_SOCKET_TIMEOUT_S,
        tls_label: str = "",
        leaves: dict[str, tuple[str, str]] | None = None,
    ) -> None:
        super().__init__(engine, address, smdp=smdp, smds=smds, log=log, relay=relay)
        self.tls = True
        self.tls_label = str(tls_label or "")
        self._context = context
        self._socket_timeout_s = float(socket_timeout_s)
        # Chain label -> (leaf name, SHA-256 of the leaf) for the handshake records; fixed for the listener's life.
        self._leaves = dict(leaves or {})

    def finish_request(self, request: Any, client_address: Any) -> None:
        request.settimeout(self._socket_timeout_s)
        try:
            secured = self._context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        except (ssl.SSLError, OSError) as error:
            self.log(f"TLS {client_address[0]}: {error}")
            return
        try:
            try:
                secured.do_handshake()
            except (ssl.SSLError, OSError) as error:
                self.log(f"TLS {client_address[0]}: handshake failed: {error}")
                self._record_handshake(secured, client_address, error)
                return
            self.log(f"TLS {client_address[0]}: {secured.version()} {(secured.cipher() or ('?',))[0]}")
            self._record_handshake(secured, client_address, None)
            try:
                self.RequestHandlerClass(secured, client_address, self)
            except (ssl.SSLError, OSError) as error:
                self.log(f"TLS {client_address[0]}: session ended: {error}")
        finally:
            try:
                secured.close()
            except OSError:
                pass

    def _record_handshake(self, secured: ssl.SSLSocket, client_address: Any, error: BaseException | None) -> None:
        """Write one handshake to the engine store; a completed one leaves its id and leaf on the connection.

        The exchanges that follow on the connection read both: each carries
        the leaf's fingerprint and counts on the handshake's row.
        """
        picked = getattr(secured, "yggdrasim_tls_setup", None)
        label = str(picked or self.tls_label)
        offered = True
        if error is not None and getattr(self._context, "yggdrasim_notes_setup", False):
            # A chain is offered once the ClientHello's server name has picked one. Before that (a port
            # probe, something that is not TLS) and for a name this side refuses, no client saw a leaf,
            # so the row counts against none.
            offered = picked is not None and not getattr(secured, "yggdrasim_tls_alert", "")
        if not offered:
            label = ""
        leaf, fingerprint = self._leaves.get(label, ("", ""))
        peer_host, peer_port = "", 0
        if isinstance(client_address, tuple) and len(client_address) >= 2:
            peer_host, peer_port = str(client_address[0]), int(client_address[1])
        record = TlsHandshake(
            id=0, at=utc_now_ms(), peer_host=peer_host, peer_port=peer_port, listener_port=int(self.server_address[1]),
            server_name=str(getattr(secured, "yggdrasim_tls_server_name", "") or ""), tls_setup=label, leaf=leaf,
            leaf_sha256=fingerprint,
        )
        if error is None:
            record.outcome = HANDSHAKE_COMPLETED
            try:
                record.tls_version = str(secured.version() or "")
                record.tls_cipher = str((secured.cipher() or ("",))[0])
                record.resumed = bool(secured.session_reused)
            except (ssl.SSLError, OSError, ValueError):
                pass
        else:
            record.outcome, record.alert, record.reason = classify_handshake_end(error)
            sent = str(getattr(secured, "yggdrasim_tls_alert", "") or "")
            if record.outcome == HANDSHAKE_FAILED and len(sent) > 0:
                record.alert = sent
        try:
            handshake_id = self.engine.store.insert_handshake(record)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as failure:
            self.log(f"handshake not recorded: {type(failure).__name__}: {failure}")
            return
        if error is None:
            _note(secured, "yggdrasim_tls_handshake", int(handshake_id))
            _note(secured, "yggdrasim_tls_leaf", fingerprint)
