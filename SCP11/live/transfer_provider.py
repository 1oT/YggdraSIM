# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The IPA side of ESipa.TransferEimPackage: an injected eIM Package in, its result out.

SGP.32 v1.3 §5.14.4 has the IPA provide the function and the eIM call it. Per
eIM Package the IPA runs an eUICC Package on the ISD-R and returns its result,
answers a request for IPA and eUICC data, or removes what the eIM acknowledged
and answers eimPackageReceivedWithCid. ``answer_transfer`` is that rule over
two callables, so the card work stays with the caller; ``TransferListener``
carries it over HTTP in both bindings (§6.1.1, §6.1.2).

Limits of this version:

- A profile download trigger is answered undefinedError. §5.14.4 has the IPA
  acknowledge the trigger and run the download; its result then goes to the
  eIM in a call the IPA makes, which this listener does not start.
- When the answer cannot be written back, the result stays on the eUICC for
  the eIM's next read. The ES10b.ProfileRollback that §5.14.4 recommends for
  that case is not called.
- Without TLS the listener binds a loopback address and speaks plain HTTP,
  not the HTTPS of §3.1.2.1. Any local process can call it while it runs: an
  eUICC Package still has to carry the eIM's signature to be executed, a
  request for data or an acknowledgement does not.

A page open in a browser on the same machine can address a loopback port as
well. Without TLS the listener therefore takes a request only with what
§6.1.1 puts in every request: a Host that is a loopback name,
X-Admin-Protocol and the Content-Type of the binding. A browser sends a
cross-origin request carrying either header only after a preflight, which
this listener does not answer, and a Host that is no loopback name is how a
rebound DNS name shows.

With TLS (``listener_tls_context``) the listener can bind any address. It
serves HTTPS with a certificate of its own and takes a connection only from
a client certificate that verifies against the certificates the operator
named: §3.1.2.1 has the eIM, and only the eIM, authenticated by the IPA.
§2.6.3.2 words the roles the other way round, the eIM as the TLS server; an
eIM that calls with an ordinary HTTPS client is the TLS client, and this is
the form such a client can use.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from SCP03.logic.sgp32_decode import decode_eim_acknowledgements
from SCP11.eim_packages import parse_eim_package
from SCP11.shared import esipa_transfer as transfer

# Next to the Local eIM's loopback ports (ESipa 8743, card-facing TLS 8744, SM-DP+ 8745).
DEFAULT_PORT = 8746
MAX_BODY = 1024 * 1024
# A connection that sends nothing for this long is closed, so an idle client cannot hold the listener.
CONNECTION_IDLE_S = 10.0

RunPackage = Callable[[bytes], bytes]
RemoveAcknowledged = Callable[[int], Any]
Log = Callable[[str], None]


def listener_tls_context(certificate: str, key: str, client_ca: str) -> ssl.SSLContext:
    """The HTTPS side of a listener: its own certificate, and what it takes a calling eIM's certificate by.

    *client_ca* is a PEM file of certificates the caller's certificate has to
    verify against: a CA, an intermediate CA, or the eIM's certificate itself,
    the three ways SGP.32 v1.3 §2.6.3.2 gives for trusting the eIM. A client
    certificate is required. TLS 1.2 is the oldest version taken (§2.6.3).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        # An empty pass phrase: an encrypted key then fails to load, where without one OpenSSL would ask the
        # terminal for it and hold the shell.
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key), password="")
    except (OSError, ValueError) as error:
        raise ValueError(f"the listener's certificate and key do not load: {_tls_reason(error)}") from None
    try:
        context.load_verify_locations(cafile=str(client_ca))
    except (OSError, ValueError) as error:
        raise ValueError(f"client-ca does not load: {_tls_reason(error)}") from None
    context.verify_mode = ssl.CERT_REQUIRED
    # A certificate named directly is trusted without a chain up to a root.
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _tls_reason(error: BaseException) -> str:
    """What a TLS or file error says, without the library's bracketed codes."""
    verify = str(getattr(error, "verify_message", "") or "")
    reason = str(getattr(error, "reason", "") or "")
    if verify:
        return verify
    if reason:
        return reason.replace("_", " ").lower()
    return str(getattr(error, "strerror", "") or error) or type(error).__name__


def _peer_line(connection: ssl.SSLSocket) -> str:
    der = connection.getpeercert(binary_form=True) or b""
    subject = ""
    for attribute in (connection.getpeercert() or {}).get("subject", ()):
        for key, value in attribute:
            if key == "commonName":
                subject = str(value)
    cipher = connection.cipher()
    return (f"{connection.version()} {cipher[0] if cipher else ''}, client certificate CN={subject or '?'} "
            f"(SHA-256 {hashlib.sha256(der).hexdigest().upper()})")


def answer_transfer(
    request: bytes,
    *,
    eid: str,
    run_package: RunPackage,
    remove_acknowledged: RemoveAcknowledged,
    log: Log | None = None,
) -> bytes:
    """Answer one TransferEimPackageRequest (SGP.32 v1.3 §5.14.4).

    *run_package* takes an EuiccPackageRequest or an IpaEuiccDataRequest and
    returns what an EimPackageResult would carry for it: 'BF51',
    '30' { 'BF51', 'A0' }, 'BF52', or the error form 'A0' { ['80'] '02' }.
    *remove_acknowledged* removes one acknowledged sequence number from the
    eUICC. An error answer names the eimTransactionId of the package, or the
    EID when the package has none.
    """
    say = log or (lambda _line: None)
    try:
        decoded = transfer.decode_request(request)
    except transfer.UnknownPackage as error:
        say(f"[!] TransferEimPackage: {error}")
        return transfer.build_error_response(transfer.UNKNOWN_PACKAGE, eid=eid)
    except transfer.TransferError as error:
        say(f"[!] TransferEimPackage: {error}")
        return transfer.build_error_response(transfer.INVALID_PACKAGE_FORMAT, eid=eid)
    transaction_id = bytes(parse_eim_package(decoded.package).eim_transaction_id or b"")
    if decoded.kind == "profileDownloadTriggerRequest":
        say("[!] TransferEimPackage: this listener runs no profile download for an injected trigger; "
            "answered undefinedError")
        return transfer.build_error_response(transfer.UNDEFINED_ERROR, transaction_id=transaction_id, eid=eid)
    if decoded.kind == "eimAcknowledgements":
        try:
            numbers = decode_eim_acknowledgements(decoded.package)
        except ValueError as error:
            say(f"[!] TransferEimPackage: {error}")
            return transfer.build_error_response(transfer.INVALID_PACKAGE_FORMAT, eid=eid)
        try:
            for number in numbers:
                remove_acknowledged(number)
        except Exception as error:  # noqa: BLE001 - whatever the card work raised, the eIM gets an answer for it
            say(f"[!] TransferEimPackage: removing acknowledged sequence numbers failed: {type(error).__name__}: {error}")
            return transfer.build_error_response(transfer.UNDEFINED_ERROR, eid=eid)
        say(f"[*] TransferEimPackage: the eIM acknowledged {', '.join(map(str, numbers)) or 'nothing'}")
        return transfer.build_received_response(eid=eid)
    try:
        result = bytes(run_package(decoded.package) or b"")
        return transfer.result_as_response(result, transaction_id=transaction_id, eid=eid)
    except Exception as error:  # noqa: BLE001 - whatever the card work raised, the eIM gets an answer for it
        say(f"[!] TransferEimPackage: {decoded.kind} gave no eIM Package Result: {type(error).__name__}: {error}")
        return transfer.build_error_response(transfer.UNDEFINED_ERROR, transaction_id=transaction_id, eid=eid)


class _Handler(BaseHTTPRequestHandler):
    server_version = "YggdraSIM-IPAd"
    protocol_version = "HTTP/1.1"
    timeout = CONNECTION_IDLE_S

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base class names it
        return

    def _send(self, status: int, content_type: str, body: bytes) -> bool:
        try:
            self.send_response(int(status))
            self.send_header("X-Admin-Protocol", transfer.ADMIN_PROTOCOL)
            if body:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            return False
        return True

    def _refuse(self, status: int, reason: str) -> None:
        """Answer without reading the body or calling the handler, and drop the connection."""
        listener: TransferListener = self.server.listener  # type: ignore[attr-defined]
        listener.log(f"[!] TransferEimPackage: request refused, {reason}")
        self.close_connection = True
        self._send(status, "text/plain", b"")

    def _named_host(self) -> str:
        try:
            return str(urlsplit("//" + str(self.headers.get("Host", "") or "")).hostname or "")
        except ValueError:
            return ""

    def do_POST(self) -> None:  # noqa: N802 - the base class names it
        listener: TransferListener = self.server.listener  # type: ignore[attr-defined]
        if not listener.secure and (
            not transfer.is_loopback(str(self.client_address[0])) or not transfer.is_loopback(self._named_host())
        ):
            self._refuse(HTTPStatus.FORBIDDEN, "the Host it names is no loopback address")
            return
        path = self.path.split("?", 1)[0]
        wanted = {transfer.PATH_ASN1: transfer.CONTENT_TYPE_ASN1, transfer.PATH_JSON: "application/json"}.get(path)
        if wanted is None:
            self._refuse(HTTPStatus.NOT_FOUND, "the path is no binding of TransferEimPackage")
            return
        media_type = str(self.headers.get("Content-Type", "") or "").split(";", 1)[0].strip().lower()
        if media_type != wanted:
            self._refuse(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, f"Content-Type is not {wanted}")
            return
        if not str(self.headers.get("X-Admin-Protocol", "") or "").strip():
            self._refuse(HTTPStatus.BAD_REQUEST, "no X-Admin-Protocol")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._refuse(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "the body is past the limit")
            return
        body = self.rfile.read(length) if length else b""
        if path == transfer.PATH_ASN1:
            written = self._send(HTTPStatus.OK, transfer.CONTENT_TYPE_ASN1, listener.answer(body))
        else:
            try:
                request = transfer.request_from_json(json.loads(body.decode("utf-8") or "{}"))
            except (UnicodeDecodeError, json.JSONDecodeError, transfer.TransferError) as error:
                listener.log(f"[!] TransferEimPackage (JSON): {error}")
                # The handler answers a request that does not read; an empty one draws that answer.
                request = b""
            message = transfer.response_to_json(listener.answer(request))
            written = self._send(HTTPStatus.OK, transfer.CONTENT_TYPE_JSON,
                                 json.dumps(message, separators=(",", ":")).encode("utf-8"))
        if listener.finished():
            self.close_connection = True
        if not written:
            listener.log("[!] TransferEimPackage: the answer could not be written back; a result stays on the "
                         "eUICC for the eIM's next read (no ProfileRollback is called)")
        listener.settle()


class _Server(HTTPServer):
    """One connection at a time; with TLS, the handshake is made per connection and bounded in time."""

    listener: "TransferListener"

    def get_request(self) -> tuple[Any, Any]:
        connection, address = self.socket.accept()
        context = self.listener.tls_context
        if context is None:
            return connection, address
        # A peer that connects and says nothing must not hold the one thread.
        connection.settimeout(CONNECTION_IDLE_S)
        try:
            secured = context.wrap_socket(connection, server_side=True)
        except OSError as error:
            connection.close()
            self.listener.log(f"[!] TransferEimPackage: TLS with {address[0]} failed: {_tls_reason(error)}")
            # socketserver takes an OSError from here as a connection that never arrived.
            raise OSError("TLS handshake failed") from None
        self.listener.log(f"[*] TransferEimPackage: {address[0]} connected, {_peer_line(secured)}")
        return secured, address


class TransferListener:
    """Serves ESipa.TransferEimPackage on one address, one call at a time.

    *handler* answers a TransferEimPackageRequest with a
    TransferEimPackageResponse and runs in the thread that calls ``serve``;
    *settle*, when given, runs after each answer was written, for work that
    must not hold the answer back. Without *tls_context* the listener speaks
    plain HTTP and binds a loopback address only. With one (see
    ``listener_tls_context``) it serves HTTPS on any address, and the context
    has to require a client certificate: off the loopback nothing else says
    who is calling.
    """

    def __init__(self, handler: Callable[[bytes], bytes], *, host: str = "127.0.0.1", port: int = 0,
                 log: Log | None = None, tls_context: ssl.SSLContext | None = None,
                 settle: Callable[[], None] | None = None) -> None:
        if tls_context is None and not transfer.is_loopback(str(host)):
            raise ValueError("Off the loopback the TransferEimPackage listener serves HTTPS only: it needs its "
                             "certificate, its key and the certificates it takes an eIM's by.")
        if tls_context is not None and getattr(tls_context, "verify_mode", None) != ssl.CERT_REQUIRED:
            raise ValueError("The TransferEimPackage listener takes TLS only with a required client certificate: "
                             "the eIM is the side that is authenticated.")
        self._handler = handler
        self._settle = settle
        self.log: Log = log or (lambda _line: None)
        self.tls_context = tls_context
        self.calls = 0
        self._max_calls: int | None = None
        self._stop: threading.Event | None = None
        self._server = _Server((str(host), int(port)), _Handler)
        self._server.listener = self
        self.host = str(self._server.server_address[0])
        self.port = int(self._server.server_address[1])

    @property
    def secure(self) -> bool:
        return self.tls_context is not None

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{'https' if self.secure else 'http'}://{host}:{self.port}"

    def answer(self, request: bytes) -> bytes:
        self.calls += 1
        return self._handler(bytes(request))

    def settle(self) -> None:
        """Run the caller's work between two calls; what it raises is logged, the listener goes on."""
        if self._settle is None:
            return
        try:
            self._settle()
        except Exception as error:  # noqa: BLE001 - the listener outlives whatever the work between calls raised
            self.log(f"[!] TransferEimPackage: work after the answer failed: {type(error).__name__}: {error}")

    def finished(self) -> bool:
        """Whether ``serve`` is to stop: a connection that is kept open is closed after its answer then."""
        if self._stop is not None and self._stop.is_set():
            return True
        return self._max_calls is not None and self.calls >= self._max_calls

    def serve(self, *, max_calls: int | None = None, idle_seconds: float | None = None,
              stop: threading.Event | None = None) -> int:
        """Answer calls until *max_calls* were answered, *idle_seconds* passed without one, or *stop* is set."""
        self._server.timeout = 0.25
        self._max_calls = max_calls
        self._stop = stop
        last = time.monotonic()
        seen = self.calls
        while True:
            if self.finished():
                break
            if idle_seconds is not None and time.monotonic() - last >= idle_seconds:
                break
            self._server.handle_request()
            if self.calls != seen:
                seen = self.calls
                last = time.monotonic()
        return self.calls

    def close(self) -> None:
        self._server.server_close()


__all__ = ["CONNECTION_IDLE_S", "DEFAULT_PORT", "TransferListener", "answer_transfer", "listener_tls_context"]
