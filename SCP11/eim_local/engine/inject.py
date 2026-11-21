# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Injection: the Local eIM calls ESipa.TransferEimPackage on an IPA.

eIM Package Injection (SGP.32 v1.3 §3.1.1.2): one eIM Package per call, the
eIM Package Result in the answer (§5.14.4). What the engine acknowledges goes
out as an EimAcknowledgements package in the next call (§3.3.1 step 13). A
profile download trigger stays queued in this version: §5.14.4 has the IPA
acknowledge an injected trigger and report the download in a call of its own,
and the answer has no alternative for the download's result (§6.3.3.1).

What matters when a call fails is whether the request left. A target that
cannot be reached costs nothing: the transport is opened before the engine
serves the package, which is when a signed package takes its counter value. A
request that left without an answer leaves its operation in flight, and the
next call asks the eUICC for its stored results first, as the engine does on
the fetch route (``LocalEim._unanswered``).

A target is plain HTTP on the loopback, or HTTPS on any address. Over HTTPS
the eIM presents a client certificate and does not check the IPA's: §3.1.2.1
has the eIM, and only the eIM, authenticated. The eIM is the TLS client here,
where §2.6.3.2 words it as the TLS server; ``SCP11.live.transfer_provider``
says why the listener takes that form.
"""

from __future__ import annotations

import http.client
import json
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import urlsplit

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.catalogue import PACKAGE_DOWNLOAD
from SCP11.eim_local.engine.service import ROUTE_INJECT, LocalEim
from SCP11.eim_local.engine.store import TrafficRecord, utc_now_ms
from SCP11.shared import esipa_transfer as transfer

BINDING_ASN1 = "asn1"
BINDING_JSON = "json"
BINDINGS = (BINDING_ASN1, BINDING_JSON)
DEFAULT_MAX_PACKAGES = 32
DEFAULT_TIMEOUT_S = 60.0
# How long a TLS 1.3 connection is watched for the server's verdict on the client certificate.
TLS_VERDICT_S = 1.0


class InjectError(RuntimeError):
    """An injection that could not be carried out as asked."""


class TargetUnreachable(InjectError):
    """The request did not leave: nothing happened at the IPA."""


class AnswerLost(InjectError):
    """The request left and no usable answer came back: the IPA may have run the package."""


@dataclass(frozen=True)
class InjectTarget:
    """Where the IPA of an eUICC takes ESipa.TransferEimPackage."""

    url: str
    binding: str = BINDING_ASN1

    @property
    def host(self) -> str:
        return str(urlsplit(self.url).hostname or "")

    @property
    def port(self) -> int:
        return int(urlsplit(self.url).port or 80)

    @property
    def secure(self) -> bool:
        return urlsplit(self.url).scheme == "https"

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "binding": self.binding}


def parse_target(url: str, binding: str = BINDING_ASN1) -> InjectTarget:
    """Check a target: ``http://<loopback address>:<port>`` or ``https://<address>:<port>``, binding ``asn1`` or ``json``."""
    text = str(url or "").strip()
    name = str(binding or BINDING_ASN1).strip().lower()
    if name not in BINDINGS:
        raise InjectError(f"Unknown binding {binding!r}; known: {', '.join(BINDINGS)}.")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as error:
        raise InjectError(f"{text!r} is not a URL: {error}") from error
    if parts.scheme not in ("http", "https"):
        raise InjectError("An inject target is http://<loopback address>:<port> or https://<address>:<port>.")
    host = str(parts.hostname or "")
    if not host:
        raise InjectError(f"{text!r} names no address.")
    if parts.scheme == "http" and not transfer.is_loopback(host):
        raise InjectError(f"Plain HTTP reaches a loopback address only; {host} takes https://.")
    if port is None:
        raise InjectError("An inject target names its port.")
    if parts.username is not None or parts.password is not None:
        raise InjectError("An inject target carries no user name or password.")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise InjectError("An inject target is an address and a port; the path follows from the binding.")
    return InjectTarget(url=f"{parts.scheme}://{parts.netloc}", binding=name)


class Transport(Protocol):
    """One connection to an IPA: opened before a package is served, then one call per package."""

    def open(self) -> None: ...

    def call(self, request: bytes) -> bytes: ...

    def close(self) -> None: ...


class HttpTransport:
    """ESipa over HTTP towards the IPA, in the ASN.1 or the JSON binding (SGP.32 v1.3 §6.1.1, §6.1.2).

    The request body carries the message of the requester, here the eIM: the
    TransferEimPackageRequest that §6.3.1 lists under EsipaMessageFromEimToIpa.
    """

    def __init__(self, target: InjectTarget, *, timeout: float = DEFAULT_TIMEOUT_S,
                 record: Callable[[str, str, bytes, int, bytes, float], None] | None = None,
                 client_certificate: tuple[str, str] | None = None) -> None:
        self.target = target
        self.timeout = float(timeout)
        self._record = record
        self._connection: http.client.HTTPConnection | None = None
        self._client_certificate = client_certificate
        self._context: ssl.SSLContext | None = None
        self._verdict_seen = False
        if target.secure:
            if client_certificate is None:
                raise InjectError("An https target takes the eIM's client certificate; INJECT-CERT makes it.")
            self._context = _client_tls_context(*client_certificate)

    def open(self) -> None:
        self.close()
        if self._context is None:
            connection = http.client.HTTPConnection(self.target.host, self.target.port, timeout=self.timeout)
        else:
            connection = http.client.HTTPSConnection(self.target.host, self.target.port, timeout=self.timeout,
                                                     context=self._context)
        try:
            connection.connect()
            if self._context is not None:
                self._await_verdict(connection)
        except ssl.SSLError as error:
            connection.close()
            raise TargetUnreachable(f"{self.target.url} did not take the TLS connection: {_tls_reason(error)}") from error
        except OSError as error:
            connection.close()
            raise TargetUnreachable(f"{self.target.url} cannot be reached: {error}") from error
        self._connection = connection

    def _await_verdict(self, connection: http.client.HTTPConnection) -> None:
        """Learn, before anything is sent, whether the IPA took the client certificate.

        In TLS 1.2 the handshake itself fails when it did not. In TLS 1.3 the
        client is done before the server has judged its certificate (RFC 8446
        section 4.4.2.4), so the refusal arrives as an alert afterwards: the
        first connection of a run is watched for it, or a refused eIM would
        find out only after a package took its counter value.
        """
        secured = connection.sock
        if not isinstance(secured, ssl.SSLSocket):
            return
        note = getattr(self._record, "secured", None)
        if callable(note):
            cipher = secured.cipher()
            note(str(secured.version() or ""), str(cipher[0]) if cipher else "")
        if self._verdict_seen or secured.version() != "TLSv1.3":
            return
        secured.settimeout(min(TLS_VERDICT_S, self.timeout))
        try:
            if secured.recv(1) == b"":
                raise ConnectionResetError("the IPA closed the connection after the handshake")
        except TimeoutError:
            # Silence is the good case: a server that took the certificate waits for the request.
            pass
        finally:
            secured.settimeout(self.timeout)
        self._verdict_seen = True

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def call(self, request: bytes) -> bytes:
        if self._connection is None:
            self.open()
        connection = self._connection
        assert connection is not None
        if self.target.binding == BINDING_JSON:
            path, content_type = transfer.PATH_JSON, transfer.CONTENT_TYPE_JSON
            body = json.dumps(transfer.request_to_json(request), separators=(",", ":")).encode("utf-8")
        else:
            path, content_type = transfer.PATH_ASN1, transfer.CONTENT_TYPE_ASN1
            body = bytes(request)
        started = time.monotonic()
        status, answer = 0, b""
        try:
            connection.request("POST", path, body=body, headers={
                "Content-Type": content_type, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL,
                "Content-Length": str(len(body)),
            })
            response = connection.getresponse()
            status, answer = int(response.status), response.read()
        except (OSError, http.client.HTTPException) as error:
            self.close()
            self._note(path, body, status, answer, started)
            raise AnswerLost(f"no answer from {self.target.url}: {type(error).__name__}: {error}") from error
        self._note(path, body, status, answer, started)
        if status != 200 or len(answer) == 0:
            self.close()
            raise AnswerLost(f"{self.target.url} answered HTTP {status} without a usable body")
        if self.target.binding != BINDING_JSON:
            return answer
        try:
            return transfer.response_from_json(json.loads(answer.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, transfer.TransferError) as error:
            raise AnswerLost(f"{self.target.url} answered with a body that is no TransferEimPackage response: {error}") from error

    def _note(self, path: str, body: bytes, status: int, answer: bytes, started: float) -> None:
        if self._record is not None:
            binding = "esipa-json" if self.target.binding == BINDING_JSON else "esipa-asn1"
            self._record(binding, path, body, status, answer, time.monotonic() - started)


@dataclass
class InjectStep:
    operation_id: int | None
    description: str
    request_hex: str = ""
    response_hex: str = ""
    answer: str = ""
    messages: list[str] = field(default_factory=list)
    acknowledged: list[int] = field(default_factory=list)


def _client_tls_context(certificate: str, key: str) -> ssl.SSLContext:
    """The eIM's side of HTTPS towards an IPA: its client certificate, no check of the IPA's (§3.1.2.1)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        # An empty pass phrase, so an encrypted key fails to load and OpenSSL asks no terminal for one.
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key), password="")
    except (OSError, ValueError) as error:
        raise InjectError(f"The eIM's client certificate does not load: {_tls_reason(error)}") from None
    return context


def _tls_reason(error: BaseException) -> str:
    reason = str(getattr(error, "reason", "") or "")
    if reason:
        return reason.replace("_", " ").lower()
    return str(getattr(error, "strerror", "") or error) or type(error).__name__


def transport_for(engine: LocalEim, target: InjectTarget, *, timeout: float = DEFAULT_TIMEOUT_S,
                  record: Callable[[str, str, bytes, int, bytes, float], None] | None = None) -> HttpTransport:
    """The transport to *target*; an https one presents the client certificate this Local eIM keeps."""
    if not target.secure:
        return HttpTransport(target, timeout=timeout, record=record)
    pair = engine.inject_client_pair()
    if pair is None:
        raise InjectError("An https target takes the eIM's client certificate, and this Local eIM has none yet: "
                          "INJECT-CERT makes it.")
    return HttpTransport(target, timeout=timeout, record=record, client_certificate=(str(pair[0]), str(pair[1])))


class TrafficLog:
    """Writes each call of an injection to the traffic table, marked as a call the eIM made.

    ``operation_id`` is set by the run before a package goes out, so the row
    names the operation its exchange served.
    """

    def __init__(self, engine: LocalEim, target: InjectTarget, eid: str) -> None:
        self.engine = engine
        self.target = target
        self.eid = eid
        self.operation_id: int | None = None
        self.tls_version = ""
        self.tls_cipher = ""

    def serving(self, operation_id: int | None) -> None:
        self.operation_id = operation_id

    def secured(self, version: str, cipher: str) -> None:
        self.tls_version, self.tls_cipher = str(version), str(cipher)

    def __call__(self, binding: str, path: str, request: bytes, status: int, response: bytes, seconds: float) -> None:
        row = TrafficRecord(
            id=0, at=utc_now_ms(), peer_host=self.target.host, peer_port=self.target.port, listener_port=0,
            binding=binding, path=path, request=bytes(request), status=int(status), response=bytes(response),
            duration_ms=int(round(seconds * 1000)), eid=self.eid, operation_id=self.operation_id,
            tls_version=self.tls_version, tls_cipher=self.tls_cipher,
            note="injected: the eIM called the IPA",
        )
        try:
            self.engine.store.insert_traffic(row)
        except (OSError, ValueError, RuntimeError):
            # The exchange happened whether or not its record could be written.
            return


def inject(
    engine: LocalEim,
    eid: str,
    transport: Transport,
    *,
    once: bool = False,
    max_packages: int = DEFAULT_MAX_PACKAGES,
    emit: Callable[[str], None] | None = None,
    on_serve: Callable[[int | None], None] | None = None,
) -> list[InjectStep]:
    """Send the queued operations of *eid* to its IPA, one eIM Package per call, until none is left.

    Raises ``TargetUnreachable`` when the IPA cannot be reached before a
    package was served. A lost answer ends the run without raising: the
    operation stays in flight and the returned step says so.
    """
    say = emit or (lambda _line: None)
    normalized = codec.normalize_eid(eid)
    steps: list[InjectStep] = []
    try:
        while len(steps) < max_packages:
            transport.open()
            served = engine.next_package(normalized, route=ROUTE_INJECT, refuse_packages=(PACKAGE_DOWNLOAD,))
            if served.error is not None:
                name = codec.EIM_PACKAGE_ERRORS.get(served.error, str(served.error))
                if served.operation is not None and served.blocked:
                    kind = "a profile download" if served.operation.type == "PROFILE_DOWNLOAD_TRIGGER" else "a device-side function"
                    say(f"[!] operation {served.operation.id} is {kind}; injection does not carry it")
                elif served.operation is not None:
                    say(f"[!] operation {served.operation.id}: {served.operation.error or name}")
                else:
                    say(f"[*] {normalized}: {name}")
                break
            operation = served.operation
            if on_serve is not None:
                on_serve(operation.id if operation is not None else None)
            request = transfer.build_request(served.package)
            step = InjectStep(
                operation_id=operation.id if operation is not None else None,
                description=operation.type if operation is not None else "",
                request_hex=request.hex().upper(),
            )
            steps.append(step)
            try:
                answer = transport.call(request)
                response = transfer.decode_response(answer)
            except (AnswerLost, transfer.TransferError) as error:
                step.answer = "no answer"
                step.messages.append(f"{error}; the operation stays in flight and the next INJECT asks the eUICC "
                                     "for its stored results first")
                say(f"[!] {step.messages[-1]}")
                break
            step.response_hex = answer.hex().upper()
            step.answer = response.kind
            other = _other_eid(response, normalized)
            if other:
                # The eIM chose the address: only the answer says which eUICC is behind it.
                step.messages.append(f"the IPA answers for EID {other}, not {normalized}; nothing of this answer is "
                                     "kept and the operation stays in flight: check the inject target")
                say(f"[!] {step.messages[-1]}")
                engine.ask_for_certificate_again(normalized)
                break
            if response.is_result:
                try:
                    accepted = engine.accept_result(normalized, response.result, route=ROUTE_INJECT)
                except codec.CodecError as error:
                    step.messages.append(f"the IPA's result does not read ({error}); the operation stays in flight "
                                         "and the next INJECT asks the eUICC for its stored results first")
                    say(f"[!] {step.messages[-1]}")
                    break
            elif response.is_error:
                # The error answers the package just sent, whether or not it names a transaction.
                accepted = engine.accept_result(
                    normalized, transfer.error_as_result(response), route=ROUTE_INJECT,
                    operation_id=operation.id if operation is not None else None,
                )
            else:
                # §5.14.4 has the IPA answer an eUICC Package or a data request with its result.
                step.messages.append("the IPA acknowledged the package without a result; the operation stays in "
                                     "flight and the next INJECT asks the eUICC for its stored results first")
                say(f"[!] {step.messages[-1]}")
                break
            step.messages = [*step.messages, *accepted.messages]
            if accepted.acknowledgements:
                step.acknowledged = _acknowledge(transport, list(accepted.acknowledgements), step, on_serve)
            for message in step.messages:
                say(f"[+] {message}")
            if once:
                break
    finally:
        transport.close()
    return steps


def _other_eid(response: transfer.TransferResponse, eid: str) -> str:
    """The EID an answer names when it is not *eid*: its correlationId, or the eUICC certificate it carries."""
    if response.eid and response.eid != eid:
        return response.eid
    if not response.result.startswith(codec.TAG_IPA_EUICC_DATA):
        return ""
    try:
        data = codec.decode_ipa_euicc_data_response(response.result)
    except codec.CodecError:
        return ""
    certificate = data.members.get("euicc_certificate") if data.ok else None
    found = codec.certificate_eid(certificate) if certificate else ""
    return found if found and found != eid else ""


def _acknowledge(transport: Transport, seq_numbers: list[int], step: InjectStep,
                 on_serve: Callable[[int | None], None] | None) -> list[int]:
    """Send the sequence numbers the engine processed as the next call (SGP.32 v1.3 §3.3.1 step 13)."""
    if on_serve is not None:
        on_serve(step.operation_id)
    request = transfer.build_request(codec.build_eim_acknowledgements(seq_numbers))
    try:
        response = transfer.decode_response(transport.call(request))
    except (InjectError, transfer.TransferError) as error:
        step.messages.append(f"acknowledgement of {', '.join(map(str, seq_numbers))} not delivered: {error}")
        return []
    if not response.is_received:
        step.messages.append(f"acknowledgement answered with {response.kind}"
                             + (f" ({response.error_name})" if response.is_error else ""))
        return []
    return seq_numbers


__all__ = [
    "AnswerLost", "BINDINGS", "BINDING_ASN1", "BINDING_JSON", "DEFAULT_TIMEOUT_S", "HttpTransport", "InjectError",
    "InjectStep", "InjectTarget", "TLS_VERDICT_S", "TargetUnreachable", "TrafficLog", "Transport", "inject",
    "parse_target", "transport_for",
]
