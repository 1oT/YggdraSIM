# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Notifications the Local eIM sends on to their Notification Receivers.

An IPA hands pending Notifications to the eIM with an eUICC Package Result,
in an IPA data response or by ESipa.HandleNotification. The eIM acknowledges
them and sends each one to the notificationAddress of its metadata with
ES9+'.HandleNotification, in the role of the LPA (SGP.32 v1.3 §3.7 step 2b,
§5.7.4, §5.14.6, §5.14.7). A Notification stays on the eUICC record until its
receiver answers, so a receiver that is down gets it at a later attempt.

None is held back: every Notification taken goes out, and one that cannot be
delivered ends as failed, with the reason, and goes again only when the
operator names it. One waits only for a certificate the record lacks.

A Notification is sent only when its eUICC signature verifies under the eUICC
certificate on the record it arrived for. The address is part of what the
eUICC signed, so a caller of the ESipa listener cannot make the eIM post to a
host of its choosing.
"""

from __future__ import annotations

import base64
import datetime
import os
import re
import sqlite3
import threading
import urllib.error
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine import compact as compact_forms
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv
from SCP11.shared.iccid import decode_ef_iccid
from SCP11.shared.notification_event import decode_notification_operation_contents

STATE_PENDING = "pending"
STATE_DELIVERED = "delivered"
# Not delivered, and not tried again by itself: the receiver refused it, the attempts are used up,
# or it cannot be sent as it stands (it does not read, its signature does not verify, its address
# is no host name). It goes again only when the operator names it.
STATE_FAILED = "failed"
# A Notification taken before the eIM forwarded any carries no state, and one an earlier version
# held carries LEGACY_HELD: both are listed as kept and go out only when the operator names them.
STATE_KEPT = "kept"
LEGACY_HELD = "held"

KIND_INSTALLATION = "installation"
KIND_OTHER = "other"

# What a forwarding pass says of one Notification, besides delivered and failed.
# The attempt did not reach the receiver: the Notification stays pending for the next one.
RESULT_RETRY = "retry"
# The record lacks a certificate the Notification needs: it stays pending until one arrives.
RESULT_WAITING = "waiting"
RESULT_BUSY = "busy"
RESULT_SKIPPED = "skipped"

# After the n-th failed attempt the next one waits RETRY_DELAYS_S[n-1] seconds; when the delays are
# used up the Notification has failed.
RETRY_DELAYS_S = (60, 300, 1800, 7200, 21600)

COMPACT_RESULT = "a compact ProfileInstallationResult is restored only inside its download session"
MISSING_EUICC_CERTIFICATE = "the eUICC certificate (IPA-DATA or a card read gives one)"
MISSING_EUM_CERTIFICATE = "the EUM certificate its full form carries (IPA-DATA or a card read gives one)"
# A sender that died between its claim and its verdict frees the Notification after this long.
CLAIM_S = 120.0
SEND_TIMEOUT_S = 20
FORWARDER_TICK_S = 30.0

# RFC 2606 §2 and §3: names kept for tests and documentation, where no Notification Receiver answers.
RESERVED_TOP_LEVEL = ("test", "example", "invalid", "localhost")
RESERVED_SECOND_LEVEL = ("example.com", "example.net", "example.org")
# Not delegated in the public DNS: the one receiver there is this store's own SM-DP+.
LOCAL_TOP_LEVEL = "local"

_HOST_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

Sender = Callable[[str, bytes], None]


class NotificationError(ValueError):
    """A PendingNotification that cannot be read, or cannot be sent as it stands."""


class Undelivered(RuntimeError):
    """The receiver did not take a Notification; ``retry`` says whether another attempt can help.

    ``expected`` marks an address nobody could have delivered to (a name kept
    for tests), which a surface reports as a fact and not as a failure.
    """

    def __init__(self, text: str, *, retry: bool, expected: bool = False) -> None:
        super().__init__(text)
        self.retry = retry
        self.expected = expected


@dataclass(frozen=True)
class Notification:
    """What a PendingNotification says about itself, in any of its four forms."""

    kind: str
    compact: bool
    seq_number: int | None
    event: str = ""
    address: str = ""
    iccid: str = ""
    eid: str = ""
    # The octets the eUICC signature covers, and the signature (raw r || s).
    signed: bytes = b""
    signature: bytes = b""
    metadata_tlv: bytes = b""
    signature_tlv: bytes = b""


@dataclass(frozen=True)
class Outcome:
    """One Notification of a forwarding pass."""

    eid: str
    seq_number: int | None
    event: str
    address: str
    result: str
    text: str
    # Not delivered, and nothing an operator has to look into (see Undelivered.expected).
    expected: bool = False

    @property
    def delivered(self) -> bool:
        return self.result == STATE_DELIVERED

    @property
    def problem(self) -> bool:
        """Whether the Notification did not reach its receiver for a reason worth an operator's attention."""
        return self.result in (STATE_FAILED, RESULT_RETRY) and not self.expected

    def line(self) -> str:
        what = f"Notification {self.seq_number}" if self.seq_number is not None else "Notification"
        about = f" ({self.event})" if self.event else ""
        return f"{what}{about} of {self.eid}: {self.text}"


def _now(now: datetime.datetime | None = None) -> datetime.datetime:
    moment = now or datetime.datetime.now(datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc).replace(microsecond=0)


def _stamp(moment: datetime.datetime) -> str:
    return moment.isoformat()


def _moment(text: Any) -> datetime.datetime | None:
    try:
        moment = datetime.datetime.fromisoformat(str(text))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment


def _items(value: bytes) -> list[tuple[bytes, bytes, bytes]]:
    items: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, item, raw, offset = read_ber_tlv(value, offset)
        items.append((tag, item, raw))
    return items


def _first(items: Iterable[tuple[bytes, bytes, bytes]], tag: bytes) -> tuple[bytes, bytes] | None:
    for item_tag, value, raw in items:
        if item_tag == tag:
            return value, raw
    return None


def _metadata(value: bytes) -> dict[str, Any]:
    """seqNumber, event, notificationAddress and ICCID of a NotificationMetadata 'BF2F' (SGP.22 v3.1 §5.7.9)."""
    facts: dict[str, Any] = {"seq_number": None, "event": "", "address": "", "iccid": ""}
    for tag, item, _raw in _items(value):
        if tag == b"\x80" and len(item) > 0:
            facts["seq_number"] = int.from_bytes(item, "big", signed=True)
        elif tag == b"\x81":
            try:
                facts["event"] = decode_notification_operation_contents(item)[1]
            except ValueError:
                facts["event"] = ""
        elif tag == b"\x0C":
            facts["address"] = item.decode("utf-8", errors="replace").strip()
        elif tag == b"\x5A":
            facts["iccid"] = decode_ef_iccid(item, strict=False)
    return facts


def read(notification: bytes) -> Notification:
    """Read a PendingNotification: 'BF37', a SEQUENCE '30', or the compact forms 'A0' and 'A1'.

    The four alternatives are those of SGP.32 v1.3 §5.14.7; nothing here checks a signature.
    """
    data = bytes(notification or b"")
    try:
        tag, value, _raw = read_single_ber_tlv(data)
        items = _items(value)
        signature = _first(items, b"\x5F\x37")
        if tag in (b"\x30", b"\xA1"):
            metadata = _first(items, b"\xBF\x2F")
            if metadata is None or signature is None:
                raise NotificationError("an OtherSignedNotification lacks its metadata or its signature")
            eid = _first(items, b"\x5A") if tag == b"\xA1" else None
            return Notification(
                kind=KIND_OTHER, compact=tag == b"\xA1", eid=eid[0].hex().upper() if eid is not None else "",
                signed=metadata[1], signature=signature[0], metadata_tlv=metadata[1], signature_tlv=signature[1],
                **_metadata(metadata[0]),
            )
        if tag == b"\xBF\x37":
            result_data = _first(items, b"\xBF\x27")
            if result_data is None or signature is None:
                raise NotificationError("a ProfileInstallationResult lacks its data or its signature")
            metadata = _first(_items(result_data[0]), b"\xBF\x2F")
            facts = _metadata(metadata[0]) if metadata is not None else {"seq_number": None}
            return Notification(
                kind=KIND_INSTALLATION, compact=False, signed=result_data[1], signature=signature[0],
                metadata_tlv=metadata[1] if metadata is not None else b"", signature_tlv=signature[1], **facts,
            )
        if tag == b"\xA0":
            return Notification(
                kind=KIND_INSTALLATION, compact=True, event="install",
                seq_number=compact_forms.compact_notification_seq_number(data),
                signature=signature[0] if signature is not None else b"",
                signature_tlv=signature[1] if signature is not None else b"",
            )
    except ValueError as error:
        if isinstance(error, NotificationError):
            raise
        raise NotificationError(f"not a PendingNotification: {error}") from error
    raise NotificationError(f"tag '{tag.hex().upper()}' opens no PendingNotification")


def seq_number_of(notification: bytes) -> int | None:
    try:
        return read(notification).seq_number
    except NotificationError:
        return None


def unverified(view: Notification, euicc_certificate: bytes) -> str:
    """Why the eUICC signature of *view* is not good under *euicc_certificate*; '' when it verifies.

    SGP.22 v3.1 §5.7.10: euiccNotificationSignature applies on tbsOtherNotification. §2.5.6: euiccSignPIR
    covers ProfileInstallationResultData.
    """
    if len(euicc_certificate) == 0:
        return "no eUICC certificate on the record (IPA-DATA or a card read gives one)"
    if view.kind == KIND_INSTALLATION and view.compact:
        return COMPACT_RESULT
    if len(view.signed) == 0 or len(view.signature) == 0:
        return "it carries no signed data"
    if not compact_forms.verify_euicc_signature(euicc_certificate, view.signed, view.signature):
        return "the eUICC signature does not verify under the eUICC certificate on the record"
    return ""


def full_form(notification: bytes, view: Notification, euicc_certificate: bytes, eum_certificate: bytes) -> bytes:
    """The PendingNotification as ES9+'.HandleNotification takes it: a compact form restored, a full one as it is."""
    if not view.compact:
        return bytes(notification)
    if view.kind != KIND_OTHER:
        raise NotificationError(COMPACT_RESULT)
    if len(euicc_certificate) == 0 or len(eum_certificate) == 0:
        raise NotificationError("the record lacks the eUICC or the EUM certificate the full form carries")
    return codec.tlv(b"\x30", view.metadata_tlv + view.signature_tlv + bytes(euicc_certificate) + bytes(eum_certificate))


def receiver_host(address: str) -> str:
    """The host name a notificationAddress gives, lower case.

    SGP.22 v3.1 §5.7.9 has it an FQDN: a scheme, a port, a path, an address
    literal or anything else that is no host name is refused.
    """
    host = str(address or "").strip().lower().rstrip(".")
    if _HOST_NAME.match(host) is None:
        raise NotificationError(f"notificationAddress {str(address)[:80]!r} is no host name")
    return host


def reserved_name(host: str) -> bool:
    """Whether *host* is a name no Notification Receiver answers under (RFC 2606 §2, §3), or a ``.local`` one."""
    labels = host.lower().rstrip(".").split(".")
    if labels[-1] in RESERVED_TOP_LEVEL or labels[-1] == LOCAL_TOP_LEVEL:
        return True
    return ".".join(labels[-2:]) in RESERVED_SECOND_LEVEL


# ----------------------------------------------------------------------
# The list on a eUICC record
# ----------------------------------------------------------------------


def entries(record: Any) -> list[dict[str, Any]]:
    value = record.data.get("notifications")
    return value if isinstance(value, list) else []


def state_of(entry: dict[str, Any]) -> str:
    state = str(entry.get("state") or "")
    return state if state in (STATE_PENDING, STATE_DELIVERED, STATE_FAILED) else STATE_KEPT


def find(record: Any, seq_number: int | None, notification_hex: str = "") -> dict[str, Any] | None:
    """The entry of *seq_number*; one without a readable seqNumber is found by its octets."""
    for entry in entries(record):
        if seq_number is not None and entry.get("seq_number") == seq_number:
            return entry
        if seq_number is None and notification_hex and entry.get("hex") == notification_hex:
            return entry
    return None


def _missing_certificate(compact: bool, euicc_certificate: bytes, eum_certificate: bytes) -> str:
    """The certificate a Notification still waits for, or ''.

    Its signature is judged under the eUICC certificate (``unverified``), and a
    compact one is restored with both certificates (``full_form``).
    """
    if len(euicc_certificate) == 0:
        return MISSING_EUICC_CERTIFICATE
    if compact and len(eum_certificate) == 0:
        return MISSING_EUM_CERTIFICATE
    return ""


def waits_for(record: Any, entry: dict[str, Any]) -> str:
    """What *record* still lacks before *entry* can be sent, or '' when nothing."""
    euicc_certificate = bytes(record.euicc_certificate or b"")
    eum_certificate = bytes(record.eum_certificate or b"")
    if euicc_certificate and eum_certificate:
        return ""
    try:
        compact = read(bytes.fromhex(str(entry.get("hex") or ""))).compact
    except ValueError:
        compact = False
    return _missing_certificate(compact, euicc_certificate, eum_certificate)


def take(record: Any, notification: bytes, *, route: str, now: str) -> tuple[dict[str, Any], bool]:
    """Put a PendingNotification on *record*; returns its entry and whether it is new.

    The seqNumber identifies a Notification of an eUICC (SGP.22 v3.1 §3.5: one
    counter per eUICC, across Profiles and Notification types), so one that
    arrives again is the entry already there. A new one is pending whatever
    route it came by; one that cannot be sent as it stands has failed at once.
    """
    raw_hex = bytes(notification).hex().upper()
    unread = ""
    try:
        view = read(notification)
    except NotificationError as error:
        view = Notification(kind="", compact=False, seq_number=codec.notification_seq_number(notification))
        unread = str(error)
    known = find(record, view.seq_number, raw_hex)
    if known is not None:
        return known, False
    entry: dict[str, Any] = {"at": now, "seq_number": view.seq_number, "hex": raw_hex, "route": route}
    for key, value in (("kind", view.kind), ("event", view.event), ("address", view.address), ("iccid", view.iccid)):
        if value:
            entry[key] = value
    if unread or view.seq_number is None:
        entry["state"] = STATE_FAILED
        entry["reason"] = unread or "it carries no seqNumber"
    elif view.kind == KIND_INSTALLATION and view.compact:
        entry["state"] = STATE_FAILED
        entry["reason"] = COMPACT_RESULT
    else:
        entry["state"] = STATE_PENDING
        entry["attempts"] = 0
    record.data.setdefault("notifications", []).append(entry)
    return entry, True


def bounded(notifications: list[dict[str, Any]], cap: int) -> list[dict[str, Any]]:
    """At most *cap* entries, the oldest going first within each state.

    Delivered ones make room first, then the ones kept from before, then the
    failed ones; a pending Notification, which the eIM still owes its receiver,
    goes only when nothing else is left to drop.
    """
    excess = len(notifications) - cap
    if excess <= 0:
        return notifications
    dropped: set[int] = set()
    for state in (STATE_DELIVERED, STATE_KEPT, STATE_FAILED, STATE_PENDING):
        for index, entry in enumerate(notifications):
            if len(dropped) >= excess:
                break
            if state_of(entry) == state:
                dropped.add(index)
    return [entry for index, entry in enumerate(notifications) if index not in dropped]


def describe(entry: dict[str, Any], waiting: str = "") -> str:
    """One line for an operator: what the Notification is and where it stands; *waiting* is ``waits_for``."""
    seq_number = entry.get("seq_number")
    head = f"{seq_number if seq_number is not None else '-':>6}  {str(entry.get('event') or entry.get('kind') or '?'):<8}"
    target = f" for {entry['address']}" if entry.get("address") else ""
    profile = f", ICCID {entry['iccid']}" if entry.get("iccid") else ""
    state = state_of(entry)
    if state == STATE_DELIVERED:
        tail = f"delivered {entry.get('delivered_at', '')}".rstrip()
    elif state == STATE_PENDING:
        attempts = int(entry.get("attempts") or 0)
        tail = "pending" if attempts == 0 else f"pending, {attempts} attempt(s), last: {entry.get('last_error', '')}"
        if entry.get("next_attempt_at"):
            tail += f"; next at {entry['next_attempt_at']}"
        if waiting:
            tail += f"; waits for {waiting}"
    elif state == STATE_FAILED:
        tail = f"failed: {entry.get('reason', '')}".rstrip(": ")
    elif entry.get("state") == LEGACY_HELD:
        tail = f"kept (held by an earlier version: {entry.get('reason') or 'no reason given'})"
    else:
        tail = "kept (taken before the eIM forwarded Notifications)"
    return f"{head}{target}{profile}: {tail}"


def _with_facts(entry: dict[str, Any]) -> dict[str, Any]:
    """*entry* with its event, receiver and ICCID read from the octets when it was stored without them.

    An entry kept by a version that forwarded nothing holds the octets and the
    seqNumber only; nothing is written back.
    """
    if entry.get("kind") or not entry.get("hex"):
        return entry
    try:
        view = read(bytes.fromhex(str(entry["hex"])))
    except ValueError:
        return entry
    filled = dict(entry)
    for key, value in (("kind", view.kind), ("event", view.event), ("address", view.address), ("iccid", view.iccid)):
        if value:
            filled[key] = value
    return filled


def rows_of(record: Any) -> list[dict[str, Any]]:
    """The Notifications of one record as JSON-ready rows, in the order they arrived, without the octets."""
    rows: list[dict[str, Any]] = []
    for stored in entries(record):
        entry = _with_facts(stored)
        row = {key: value for key, value in entry.items() if key not in ("hex", "sender", "sending_since")}
        row["eid"] = record.eid
        row["state"] = state_of(entry)
        waiting = waits_for(record, entry) if row["state"] == STATE_PENDING else ""
        if waiting:
            row["waiting"] = waiting
        row["text"] = describe(entry, waiting)
        rows.append(row)
    return rows


def listing(engine: Any, eid: str = "") -> list[dict[str, Any]]:
    """Every Notification on record, eUICC by eUICC, as ``rows_of`` gives them."""
    records = [engine.record(eid)] if eid else engine.records()
    return [row for record in records if record is not None for row in rows_of(record)]


def counts(record: Any) -> dict[str, int]:
    tally = {STATE_PENDING: 0, STATE_FAILED: 0, STATE_DELIVERED: 0, STATE_KEPT: 0}
    for entry in entries(record):
        tally[state_of(entry)] += 1
    return tally


# ----------------------------------------------------------------------
# Sending
# ----------------------------------------------------------------------


def _due(entry: dict[str, Any], now: datetime.datetime) -> bool:
    moment = _moment(entry.get("next_attempt_at")) if entry.get("next_attempt_at") else None
    return moment is None or moment <= now


def _claimed(entry: dict[str, Any], now: datetime.datetime, sender_id: str) -> bool:
    """Whether another sender holds *entry* now."""
    since = _moment(entry.get("sending_since")) if entry.get("sending_since") else None
    if since is None or entry.get("sender") == sender_id:
        return False
    return (now - since).total_seconds() < CLAIM_S


def _address_key(entry: dict[str, Any]) -> str:
    return str(entry.get("address") or "").strip().lower()


def _candidates(
    record: Any, seq_numbers: set[int], explicit: bool, now: datetime.datetime,
) -> list[list[int | None]]:
    """seqNumbers to attempt, grouped by receiver and in sequence order (SGP.22 v3.1 §3.5)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries(record):
        state = state_of(entry)
        if state == STATE_DELIVERED:
            continue
        if seq_numbers:
            if entry.get("seq_number") not in seq_numbers:
                continue
        elif state != STATE_PENDING:
            continue
        groups.setdefault(_address_key(entry), []).append(entry)
    chosen: list[list[int | None]] = []
    for group in groups.values():
        group.sort(key=lambda entry: (entry.get("seq_number") is None, entry.get("seq_number") or 0))
        # The oldest Notification for a receiver goes first; while it waits for its next attempt,
        # or for a certificate the record lacks, the later ones wait behind it.
        if not explicit and (not _due(group[0], now) or waits_for(record, group[0])):
            continue
        chosen.append([entry.get("seq_number") for entry in group])
    return chosen


def _claim(engine: Any, eid: str, seq_number: int | None, now: datetime.datetime, sender_id: str) -> dict[str, Any] | str:
    """Mark the entry as being sent by this sender; a string says why it is not this sender's to send."""
    with engine.store.transaction() as connection:
        record = engine.store.record(eid, connection)
        entry = find(record, seq_number) if record is not None and seq_number is not None else None
        if entry is None or state_of(entry) == STATE_DELIVERED:
            # Dropped from the record, or another sender delivered it since the pass read the list.
            return RESULT_SKIPPED
        if _claimed(entry, now, sender_id):
            return RESULT_BUSY
        entry["sending_since"] = _stamp(now)
        entry["sender"] = sender_id
        engine.store.save_record(record, connection)
        claimed = dict(entry)
        claimed["_euicc_certificate"] = bytes(record.euicc_certificate)
        claimed["_eum_certificate"] = bytes(record.eum_certificate)
        return claimed


def _settle(engine: Any, eid: str, seq_number: int | None, change: Callable[[dict[str, Any]], None]) -> None:
    with engine.store.transaction() as connection:
        record = engine.store.record(eid, connection)
        entry = find(record, seq_number) if record is not None else None
        if entry is None:
            return
        entry.pop("sending_since", None)
        entry.pop("sender", None)
        change(entry)
        engine.store.save_record(record, connection)


def _send_one(
    engine: Any, eid: str, seq_number: int | None, sender: Sender, now: datetime.datetime, sender_id: str,
) -> Outcome:
    claimed = _claim(engine, eid, seq_number, now, sender_id)
    if isinstance(claimed, str):
        text = "another sender has it now" if claimed == RESULT_BUSY else "nothing left to send"
        return Outcome(eid, seq_number, "", "", claimed, text)
    notification = bytes.fromhex(str(claimed.get("hex") or ""))
    event = str(claimed.get("event") or "")
    address = str(claimed.get("address") or "")

    def failed(reason: str, expected: bool = False, attempts: int | None = None) -> Outcome:
        def change(entry: dict[str, Any]) -> None:
            entry["state"] = STATE_FAILED
            entry["reason"] = reason
            entry.pop("next_attempt_at", None)
            if attempts is not None:
                entry["attempts"] = attempts
                entry["last_attempt_at"] = _stamp(now)

        _settle(engine, eid, seq_number, change)
        return Outcome(eid, seq_number, event, address, STATE_FAILED, f"not sent: {reason}", expected)

    try:
        view = read(notification)
    except NotificationError as error:
        return failed(str(error))
    if view.kind == KIND_INSTALLATION and view.compact:
        return failed(COMPACT_RESULT)
    waiting = _missing_certificate(view.compact, claimed["_euicc_certificate"], claimed["_eum_certificate"])
    if waiting:
        # Not an attempt: the entry stays as it is until the record has the certificate.
        _settle(engine, eid, seq_number, lambda _entry: None)
        return Outcome(eid, seq_number, event, address, RESULT_WAITING, f"not sent yet: it waits for {waiting}")
    reason = unverified(view, claimed["_euicc_certificate"])
    if reason:
        return failed(reason)
    try:
        host = receiver_host(view.address)
        full = full_form(notification, view, claimed["_euicc_certificate"], claimed["_eum_certificate"])
    except NotificationError as error:
        return failed(str(error))
    try:
        sender(host, full)
    except Undelivered as error:
        attempts = int(claimed.get("attempts") or 0) + 1
        text = str(error)
        if not error.retry:
            return failed(text, error.expected, attempts)
        if state_of(claimed) == STATE_FAILED:
            # The operator's Send of a failed one is one attempt: it stays failed, with what this one met.
            return failed(text, attempts=attempts)
        if attempts > len(RETRY_DELAYS_S):
            return failed(f"not delivered after {attempts} attempts, last: {text}", attempts=attempts)
        next_at = _stamp(now + datetime.timedelta(seconds=RETRY_DELAYS_S[attempts - 1]))

        def retry(entry: dict[str, Any]) -> None:
            entry["state"] = STATE_PENDING
            entry["attempts"] = attempts
            entry["last_error"] = text
            entry["last_attempt_at"] = _stamp(now)
            entry["next_attempt_at"] = next_at
            entry.pop("reason", None)

        _settle(engine, eid, seq_number, retry)
        return Outcome(eid, seq_number, event, host, RESULT_RETRY,
                       f"not delivered to {host} (attempt {attempts}): {text}; next attempt at {next_at}")

    def delivered(entry: dict[str, Any]) -> None:
        entry["state"] = STATE_DELIVERED
        entry["delivered_at"] = _stamp(now)
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        entry["address"] = view.address
        for key in ("reason", "last_error", "next_attempt_at"):
            entry.pop(key, None)

    _settle(engine, eid, seq_number, delivered)
    return Outcome(eid, seq_number, event, host, STATE_DELIVERED, f"delivered to {host}")


def forward(
    engine: Any,
    eid: str = "",
    *,
    seq_numbers: Iterable[int] = (),
    sender: Sender | None = None,
    explicit: bool = False,
    now: datetime.datetime | None = None,
) -> list[Outcome]:
    """Send the Notifications that are due, one receiver after the other and each receiver's in order.

    Without *seq_numbers* the pending ones go: those whose next attempt is due
    and whose record has the certificates they need, or all of them when
    *explicit* (the operator asked). With *seq_numbers* exactly those go, failed
    and kept ones included; naming them is the only way a failed or kept
    Notification leaves. A failure that another attempt can cure, or a missing
    certificate, ends that receiver's turn, so the order of SGP.22 v3.1 §3.5
    holds.
    """
    moment = _now(now)
    wanted = {int(number) for number in seq_numbers}
    send = sender or receiver_sender(engine)
    sender_id = f"{os.getpid()}-{threading.get_ident()}"
    records = [engine.record(codec.normalize_eid(eid))] if eid else engine.records()
    outcomes: list[Outcome] = []
    for record in records:
        if record is None:
            continue
        for group in _candidates(record, wanted, explicit or bool(wanted), moment):
            for seq_number in group:
                outcome = _send_one(engine, record.eid, seq_number, send, moment, sender_id)
                if outcome.result == RESULT_SKIPPED:
                    continue
                outcomes.append(outcome)
                if outcome.result in (RESULT_RETRY, RESULT_WAITING, RESULT_BUSY):
                    break
    return outcomes


def receiver_sender(engine: Any, smdp: Any = None, *, timeout_seconds: int = SEND_TIMEOUT_S) -> Sender:
    """The sender of a store: its own SM-DP+ in process, any other receiver over ES9+ with HTTPS.

    SGP.22 v3.1 §3.5 step 7b and step 10: HTTP status 204 says the receiver
    has the Notification. A '4XX' is the receiver refusing it, which no second
    attempt changes; anything else is worth another attempt.
    """
    from SCP11.eim_local.engine.indirect import LocalSmdpEs9
    from SCP11.eim_local.engine.smdp import LocalSmdp
    from SCP11.live.models import HandleNotificationRequest

    local = smdp if smdp is not None else LocalSmdp(engine.directory)

    def send(host: str, notification: bytes) -> None:
        request = HandleNotificationRequest(
            pending_notification=base64.b64encode(bytes(notification)).decode("ascii"), smdp_address=host,
        )
        own = str(local.host() or "").lower()
        if own and host == own:
            try:
                LocalSmdpEs9(local).handle_notification(request)
            except (RuntimeError, ValueError, OSError, LookupError) as error:
                raise Undelivered(f"the local SM-DP+ refused it: {error}", retry=False) from error
            return
        if reserved_name(host):
            raise Undelivered(f"{host} is a reserved or local name where no Notification Receiver answers",
                              retry=False, expected=True)
        from SCP11.live.es9_client import Es9LikeClient

        client = Es9LikeClient(base_url=f"https://{host}", timeout_seconds=timeout_seconds)
        try:
            client.handle_notification(request)
        except (OSError, ValueError, RuntimeError) as error:
            cause = error.__cause__ if isinstance(error.__cause__, urllib.error.HTTPError) else error
            status = int(cause.code) if isinstance(cause, urllib.error.HTTPError) else 0
            if 400 <= status < 500:
                raise Undelivered(f"{host} answered HTTP {status}", retry=False) from error
            raise Undelivered(f"{type(cause).__name__}: {cause}"[:300], retry=True) from error
        status = client.last_http_status
        if status is not None and not 200 <= int(status) < 300:
            raise Undelivered(f"{host} answered HTTP {status}, not 204", retry=True)

    return send


class Forwarder:
    """The forwarding thread of a running service: a pass when a Notification arrives and one every tick."""

    def __init__(
        self,
        engine: Any,
        sender: Sender,
        *,
        log: Callable[[str], None] | None = None,
        tick_s: float = FORWARDER_TICK_S,
    ) -> None:
        self.engine = engine
        self.sender = sender
        self.log = log or (lambda _line: None)
        self.tick_s = float(tick_s)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="local-eim-notifications", daemon=True)
        self._thread.start()

    def kick(self) -> None:
        self._wake.set()

    def stop(self, wait_s: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(wait_s)
            self._thread = None

    def run_once(self) -> list[Outcome]:
        outcomes = forward(self.engine, sender=self.sender)
        for outcome in outcomes:
            self.log(outcome.line())
        return outcomes

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.tick_s)
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                self.run_once()
            except (OSError, RuntimeError, ValueError, LookupError, sqlite3.Error) as error:
                # The store (a locked database is sqlite3.OperationalError) or one receiver failing
                # must not end the thread: the next tick tries again.
                self.log(f"notification forwarding pass failed: {type(error).__name__}: {error}")


__all__ = [
    "COMPACT_RESULT", "Forwarder", "KIND_INSTALLATION", "KIND_OTHER", "LEGACY_HELD", "MISSING_EUICC_CERTIFICATE",
    "MISSING_EUM_CERTIFICATE", "Notification", "NotificationError", "Outcome", "RESULT_BUSY", "RESULT_RETRY",
    "RESULT_SKIPPED", "RESULT_WAITING", "RETRY_DELAYS_S", "STATE_DELIVERED", "STATE_FAILED", "STATE_KEPT",
    "STATE_PENDING", "Sender", "Undelivered", "bounded", "counts", "describe", "entries", "find", "forward",
    "full_form", "listing", "read", "receiver_host", "receiver_sender", "reserved_name", "rows_of",
    "seq_number_of", "state_of", "take", "unverified", "waits_for",
]
