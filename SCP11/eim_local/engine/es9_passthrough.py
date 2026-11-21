# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES9+ sessions a card opens on the eIM's own address for another SM-DP+, passed through to that SM-DP+.

An IPAe can run the direct download of a trigger (SGP.32 v1.3 §3.2.3.1) over a
connection to the eIM's address while naming the SM-DP+ of the Activation Code
in InitiateAuthentication (smdpAddress, SGP.22 v3.1 §5.6.1). The card listener
carries such a session to that SM-DP+ as it came, in the ES9+ ASN.1 binding
(SGP.22 v3.1 §6.6), when a download trigger this eIM served and still has open
names the address; the later steps follow their transactionId. Any other
address is refused the way an SM-DP+ refuses it (invalidDpAddress), so no
answer is signed for a server this service is not.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Callable

from SCP11.eim_local.engine.indirect import activation_code_fields
from SCP11.eim_local.engine.smdp import host_of
from SCP11.eim_local.engine.store import STATE_SENT
from SCP11.shared import es9_asn1
from SCP11.shared import esipa_download as esipa
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

MAX_SESSIONS = 64
DOWNLOAD_TRIGGER = "PROFILE_DOWNLOAD_TRIGGER"
_FAILURES = (OSError, RuntimeError, ValueError, LookupError)
# (SM-DP+ host, the request as the card sent it, X-Admin-Protocol) -> the SM-DP+'s answer body.
Poster = Callable[[str, bytes, str], bytes]

_NAMES = {
    esipa.TAG_INITIATE_AUTHENTICATION: "InitiateAuthentication",
    esipa.TAG_AUTHENTICATE_CLIENT: "AuthenticateClient",
    esipa.TAG_GET_BOUND_PROFILE_PACKAGE: "GetBoundProfilePackage",
    esipa.TAG_CANCEL_SESSION: "CancelSession",
    esipa.TAG_HANDLE_NOTIFICATION: "HandleNotification",
}


def post_to_smdp(host: str, body: bytes, protocol_header: str) -> bytes:
    """The SM-DP+ at *host* over HTTPS, its server certificate checked as for any ES9+ call."""
    from SCP11.live.es9_client import Es9LikeClient

    return Es9LikeClient(base_url=f"https://{host}").post_es9_asn1(body, protocol_header)


def _function(body: bytes) -> bytes | None:
    try:
        return es9_asn1.unwrap(body)
    except es9_asn1.Es9Asn1Error:
        return None


def _children(function: bytes) -> list[tuple[bytes, bytes]]:
    """(tag, value) of each member of one function's TLV."""
    try:
        _tag, value, _raw = read_single_ber_tlv(function)
        members: list[tuple[bytes, bytes]] = []
        offset = 0
        while offset < len(value):
            tag, item, _item_raw, offset = read_ber_tlv(value, offset)
            members.append((bytes(tag), bytes(item)))
        return members
    except (ValueError, IndexError):
        return []


def _requested_address(function: bytes) -> str:
    try:
        return str(esipa.decode_initiate_authentication_request(function).smdp_address or "")
    except (esipa.EsipaDownloadError, ValueError, IndexError):
        return ""


def _transaction_of(tag: bytes, function: bytes) -> bytes:
    """The transactionId a later step names: its '80', or that of the ProfileInstallationResult it hands over."""
    if tag == esipa.TAG_HANDLE_NOTIFICATION:
        try:
            return esipa.installation_result_transaction_id(es9_asn1.decode_handle_notification(function))
        except (es9_asn1.Es9Asn1Error, ValueError, IndexError):
            return b""
    for member_tag, value in _children(function):
        if member_tag == b"\x80":
            return value
    return b""


def _answer_transaction(answer: bytes) -> bytes:
    try:
        return bytes(es9_asn1.decode_initiate_authentication_response(answer).transaction_id)
    except (es9_asn1.Es9Asn1Error, ValueError, IndexError):
        return b""


def _error_code(answer: bytes) -> int | None:
    """The error INTEGER an answer carries ('81', or '02' inside 'A1'), None for an OK answer or none read."""
    function = _function(answer)
    members = _children(function) if function is not None else []
    if len(members) != 1:
        return None
    tag, value = members[0]
    if tag == b"\x81":
        return int.from_bytes(value, "big", signed=True) if value else None
    if tag == b"\xA1" and len(value) > 0:
        # An SM-DP+ that tags the INTEGER alternative explicitly: 'A1' { '02' code }.
        try:
            inner_tag, inner_value, _raw, _next = read_ber_tlv(value, 0)
        except (ValueError, IndexError):
            return None
        if inner_tag == b"\x02" and inner_value:
            return int.from_bytes(inner_value, "big", signed=True)
    return None


def _error_answer(tag: bytes) -> bytes:
    """undefinedError(127) in the CHOICE of the function the card called."""
    if tag == esipa.TAG_INITIATE_AUTHENTICATION:
        return es9_asn1.encode_initiate_authentication_error(es9_asn1.UNDEFINED_ERROR)
    if tag == esipa.TAG_AUTHENTICATE_CLIENT:
        return es9_asn1.encode_authenticate_client_error(es9_asn1.UNDEFINED_ERROR)
    if tag == esipa.TAG_GET_BOUND_PROFILE_PACKAGE:
        return es9_asn1.encode_get_bound_profile_package_error(es9_asn1.UNDEFINED_ERROR)
    if tag == esipa.TAG_CANCEL_SESSION:
        return es9_asn1.encode_cancel_session_error(es9_asn1.UNDEFINED_ERROR)
    return b""


@dataclass
class _Passed:
    host: str
    operation_id: int | None


class Es9PassThrough:
    """One listener's passed-through ES9+ sessions, keyed by the transactionId the SM-DP+ handed out."""

    def __init__(
        self,
        engine: Any,
        smdp: Any = None,
        *,
        log: Callable[[str], None] | None = None,
        poster: Poster | None = None,
    ) -> None:
        self.engine = engine
        self.smdp = smdp
        self.log = log or (lambda _line: None)
        self._post = poster or post_to_smdp
        self._sessions: OrderedDict[str, _Passed] = OrderedDict()
        self._lock = threading.Lock()

    def claims(self, body: bytes) -> bool:
        """Whether *body* is an InitiateAuthentication for another SM-DP+, or a later step of a session passed through."""
        function = _function(body)
        if function is None:
            return False
        tag = function[:2]
        if tag == esipa.TAG_INITIATE_AUTHENTICATION:
            host = host_of(_requested_address(function))
            return len(host) > 0 and host != self._local_host()
        transaction = _transaction_of(tag, function)
        return len(transaction) > 0 and self._session(transaction) is not None

    def sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    def handle(self, body: bytes, protocol_header: str = "") -> tuple[int, bytes, str]:
        """Pass one step through, or refuse it: (HTTP status, answer, a note for the exchange record)."""
        function = _function(body)
        if function is None:
            return HTTPStatus.BAD_REQUEST, b"", "not one ES9+ function"
        tag = function[:2]
        if tag == esipa.TAG_INITIATE_AUTHENTICATION:
            return self._initiate_authentication(body, function, protocol_header)
        name = _NAMES.get(tag, "?")
        transaction = _transaction_of(tag, function)
        ends = tag in (esipa.TAG_CANCEL_SESSION, esipa.TAG_HANDLE_NOTIFICATION)
        passed = self._session(transaction, pop=ends)
        if passed is None:
            return HTTPStatus.OK, _error_answer(tag), f"ES9+ {name}: no session passed through for that transactionId"
        try:
            answer = self._post(passed.host, body, protocol_header)
        except _FAILURES as error:
            text = f"ES9+ {name} not passed through to {passed.host}: {error}"
            self._note(passed.operation_id, text)
            if tag == esipa.TAG_HANDLE_NOTIFICATION:
                return self._keep_notification(function, passed, text)
            return HTTPStatus.OK, _error_answer(tag), text
        code = _error_code(answer)
        if tag == esipa.TAG_AUTHENTICATE_CLIENT and code is not None:
            reason = es9_asn1.AUTHENTICATE_CLIENT_ERRORS.get(code, "unknown")
            text = f"ES9+ AuthenticateClient passed through to {passed.host}: it answered {reason} ({code})"
        elif tag == esipa.TAG_GET_BOUND_PROFILE_PACKAGE and code is None:
            text = f"ES9+ GetBoundProfilePackage passed through to {passed.host} ({len(answer)} bytes)"
        else:
            text = f"ES9+ {name} passed through to {passed.host}" + (f": it answered error {code}" if code else "")
        self._note(passed.operation_id, text)
        return (HTTPStatus.NO_CONTENT if len(answer) == 0 else HTTPStatus.OK), answer, text

    def _initiate_authentication(self, body: bytes, function: bytes, protocol_header: str) -> tuple[int, bytes, str]:
        host = host_of(_requested_address(function))
        operations = self._open_downloads_naming(host)
        if len(operations) == 0:
            text = (f"ES9+ InitiateAuthentication for {host} refused (invalidDpAddress): no open download trigger "
                    "of this eIM names it")
            self.log(text)
            return (HTTPStatus.OK,
                    es9_asn1.encode_initiate_authentication_error(es9_asn1.INITIATE_AUTHENTICATION_INVALID_DP_ADDRESS),
                    text)
        operation_id = operations[0].id if len(operations) == 1 else None
        try:
            answer = self._post(host, body, protocol_header)
        except _FAILURES as error:
            text = f"ES9+ InitiateAuthentication not passed through to {host}: {error}"
            self._note(operation_id, text)
            return HTTPStatus.OK, _error_answer(esipa.TAG_INITIATE_AUTHENTICATION), text
        transaction = _answer_transaction(answer)
        if len(transaction) > 0:
            self._remember(transaction, _Passed(host, operation_id))
            text = f"ES9+ InitiateAuthentication passed through to {host} (transactionId {transaction.hex().upper()})"
        else:
            code = _error_code(answer)
            reason = es9_asn1.INITIATE_AUTHENTICATION_ERRORS.get(code, "an error") if code is not None else "an error"
            text = f"ES9+ InitiateAuthentication passed through to {host}: it answered {reason}"
        self._note(operation_id, text)
        return (HTTPStatus.NO_CONTENT if len(answer) == 0 else HTTPStatus.OK), answer, text

    def _keep_notification(self, function: bytes, passed: _Passed, text: str) -> tuple[int, bytes, str]:
        """A ProfileInstallationResult the SM-DP+ did not take goes to the eIM's own Notifications, which try again.

        The card removes what it handed over once it is answered, so the eIM
        keeps it (``notifications.take``); one that no record's certificate
        verifies is left with the card (HTTP 500).
        """
        try:
            notification = es9_asn1.decode_handle_notification(function)
            owner = self.engine.notification_owner(notification)
            if owner:
                self.engine.accept_notification(owner, notification)
                kept = f"{text}; the eIM keeps it and tries again"
                self._note(passed.operation_id, kept)
                return HTTPStatus.NO_CONTENT, b"", kept
        except _FAILURES as error:
            self.log(f"ES9+ HandleNotification: could not keep it: {error}")
        return HTTPStatus.INTERNAL_SERVER_ERROR, b"", f"{text}; left with the card"

    def _open_downloads_naming(self, host: str) -> list[Any]:
        """The served, unfinished download triggers whose Activation Code names *host*."""
        found = []
        for operation in self.engine.operations(types=(DOWNLOAD_TRIGGER,), states=(STATE_SENT,)):
            code = str((operation.params or {}).get("activation_code", "") or "")
            address, _matching_id, _oid = activation_code_fields(code)
            if address and host_of(address) == host:
                found.append(operation)
        return found

    def _local_host(self) -> str:
        if self.smdp is None:
            return ""
        try:
            return host_of(self.smdp.address())
        except (AttributeError, OSError, ValueError):
            return ""

    def _remember(self, transaction_id: bytes, passed: _Passed) -> None:
        with self._lock:
            key = bytes(transaction_id).hex().upper()
            self._sessions[key] = passed
            self._sessions.move_to_end(key)
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)

    def _session(self, transaction_id: bytes, *, pop: bool = False) -> _Passed | None:
        key = bytes(transaction_id or b"").hex().upper()
        if not key:
            return None
        with self._lock:
            return self._sessions.pop(key, None) if pop else self._sessions.get(key)

    def _note(self, operation_id: int | None, text: str) -> None:
        self.log(text)
        if operation_id is None:
            return
        try:
            self.engine.note(operation_id, text)
        except _FAILURES as error:
            self.log(f"ES9+ pass-through: could not note on operation {operation_id}: {error}")


__all__ = ["DOWNLOAD_TRIGGER", "Es9PassThrough", "MAX_SESSIONS", "Poster", "post_to_smdp"]
