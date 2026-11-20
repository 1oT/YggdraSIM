# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SQLite store of the Local eIM: eUICC records, tasks, operations and settings.

One file, ``local_eim.sqlite3`` in the engine store directory, shared by the
shell, the GUI server and the ESipa server; every call opens its own
connection, so threads and processes can use it side by side. The operator
never needs to open it: every field an operation carries is read and changed
through the engine API. History grows on disk only, and finished operations
are pruned past the history cap.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

STORE_DIR_ENV = "YGGDRASIM_LOCAL_EIM_STORE"
HISTORY_CAP_ENV = "YGGDRASIM_LOCAL_EIM_HISTORY_CAP"
DATABASE_FILE = "local_eim.sqlite3"
DEFAULT_HISTORY_CAP = 10000
# Per-operation timeline and per-record notification copies: both bounded.
OPERATION_HISTORY_CAP = 64
RECORD_NOTIFICATION_CAP = 64
# Exchanges the listeners record (what an IPA sent, what the eIM answered): the newest
# TRAFFIC_CAP rows are kept, the oldest go as a new one is written.
TRAFFIC_CAP = 4000
# TLS handshakes the card-facing listeners record (which leaf was served, how the client answered):
# the newest TLS_HANDSHAKE_CAP rows are kept, the oldest go as a new one is written.
TLS_HANDSHAKE_CAP = 2000
# How a card-facing handshake ended: completed; the client sent an alert; this side ended it; or the
# connection went away without an alert.
# Event Records the local SM-DS holds (SGP.22 v3.1 3.6.1). A registry, not a history: a registration
# past the cap is refused, so no pending Event Record is dropped to make room.
SMDS_EVENT_CAP = 2000
HANDSHAKE_COMPLETED = "completed"
HANDSHAKE_REFUSED = "refused"
HANDSHAKE_FAILED = "failed"
HANDSHAKE_LOST = "lost"

STATE_CREATED = "CREATED"
STATE_SENT = "SENT"
STATE_SUCCESS = "SUCCESS"
STATE_PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
STATE_ERROR = "ERROR"
STATE_CANCELED = "CANCELED"
FINAL_STATES = (STATE_SUCCESS, STATE_PARTIAL_SUCCESS, STATE_ERROR, STATE_CANCELED)
PENDING_STATES = (STATE_CREATED, STATE_SENT)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS setting (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS euicc (
    eid TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    association_token INTEGER,
    counter_value INTEGER NOT NULL DEFAULT 0,
    seq_number INTEGER,
    euicc_certificate BLOB,
    eum_certificate BLOB,
    data TEXT NOT NULL DEFAULT '{}',
    first_poll_at TEXT,
    last_poll_at TEXT,
    poll_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS task (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS operation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    eid TEXT NOT NULL,
    position INTEGER NOT NULL,
    type TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    raw_items TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    system INTEGER NOT NULL DEFAULT 0,
    recovery_for INTEGER,
    retries INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    not_before TEXT,
    transaction_id TEXT NOT NULL,
    counter_value INTEGER,
    association_token INTEGER,
    created_at TEXT NOT NULL,
    served_at TEXT,
    finished_at TEXT,
    route TEXT NOT NULL DEFAULT '',
    served_hex TEXT NOT NULL DEFAULT '',
    result_hex TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '{}',
    warnings TEXT NOT NULL DEFAULT '[]',
    error TEXT NOT NULL DEFAULT '',
    flags TEXT NOT NULL DEFAULT '[]',
    fault TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL DEFAULT '',
    history TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS operation_queue ON operation (eid, state, position);
CREATE INDEX IF NOT EXISTS operation_transaction ON operation (transaction_id);
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    peer_host TEXT NOT NULL DEFAULT '',
    peer_port INTEGER NOT NULL DEFAULT 0,
    listener_port INTEGER NOT NULL DEFAULT 0,
    tls_setup TEXT NOT NULL DEFAULT '',
    tls_version TEXT NOT NULL DEFAULT '',
    tls_cipher TEXT NOT NULL DEFAULT '',
    binding TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    request BLOB NOT NULL DEFAULT X'',
    status INTEGER NOT NULL DEFAULT 0,
    response BLOB NOT NULL DEFAULT X'',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    eid TEXT NOT NULL DEFAULT '',
    operation_id INTEGER,
    note TEXT NOT NULL DEFAULT '',
    tls_leaf TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS traffic_peer ON traffic (peer_port, id);
CREATE INDEX IF NOT EXISTS traffic_eid ON traffic (eid, id);
CREATE TABLE IF NOT EXISTS tls_handshake (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    peer_host TEXT NOT NULL DEFAULT '',
    peer_port INTEGER NOT NULL DEFAULT 0,
    listener_port INTEGER NOT NULL DEFAULT 0,
    server_name TEXT NOT NULL DEFAULT '',
    tls_setup TEXT NOT NULL DEFAULT '',
    leaf TEXT NOT NULL DEFAULT '',
    leaf_sha256 TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '',
    alert TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    tls_version TEXT NOT NULL DEFAULT '',
    tls_cipher TEXT NOT NULL DEFAULT '',
    resumed INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    eid TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tls_handshake_setup ON tls_handshake (tls_setup, id);
CREATE TABLE IF NOT EXISTS smds_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    eid TEXT NOT NULL,
    event_id TEXT NOT NULL,
    rsp_server_address TEXT NOT NULL,
    event_type INTEGER NOT NULL DEFAULT 1,
    caller TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS smds_event_caller ON smds_event (caller, event_id);
CREATE INDEX IF NOT EXISTS smds_event_eid ON smds_event (eid, id);
"""

# Columns a table gained after stores were created with it: CREATE TABLE IF NOT EXISTS leaves an existing
# table as it is, so each is added once when the store opens.
_ADDED_COLUMNS = (
    ("traffic", "tls_leaf", "TEXT NOT NULL DEFAULT ''"),
)

_OPERATION_JSON = {"params": {}, "result": {}, "warnings": [], "flags": [], "history": []}


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def utc_now_ms() -> str:
    """UTC to the millisecond: the stamp of an exchange, which a terminal trace's ms stamps are read against."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def store_directory() -> Path:
    """Return the engine store directory: the env override, else ``~/.yggdrasim/local_eim``."""
    override = os.environ.get(STORE_DIR_ENV, "").strip()
    if len(override) > 0:
        return Path(os.path.expanduser(override))
    return Path(os.path.expanduser("~")) / ".yggdrasim" / "local_eim"


def history_cap() -> int:
    raw = os.environ.get(HISTORY_CAP_ENV, "").strip()
    if len(raw) == 0:
        return DEFAULT_HISTORY_CAP
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_HISTORY_CAP
    return max(100, value)


@dataclass
class EuiccRecord:
    """What the eIM knows about one eUICC."""

    eid: str
    label: str = ""
    created_at: str = ""
    association_token: int | None = None
    counter_value: int = 0
    seq_number: int | None = None
    euicc_certificate: bytes = b""
    eum_certificate: bytes = b""
    data: dict[str, Any] = field(default_factory=dict)
    first_poll_at: str | None = None
    last_poll_at: str | None = None
    poll_count: int = 0

    @property
    def profiles(self) -> list[dict[str, Any]]:
        value = self.data.get("profiles")
        return value if isinstance(value, list) else []

    @property
    def eims(self) -> list[dict[str, Any]]:
        value = self.data.get("eims")
        return value if isinstance(value, list) else []


@dataclass
class Operation:
    id: int
    eid: str
    type: str
    state: str
    position: int
    task_id: int | None = None
    params: dict[str, Any] = field(default_factory=dict)
    raw_items: str = ""
    system: bool = False
    recovery_for: int | None = None
    retries: int = 0
    max_retries: int = 3
    not_before: str | None = None
    transaction_id: str = ""
    counter_value: int | None = None
    association_token: int | None = None
    created_at: str = ""
    served_at: str | None = None
    finished_at: str | None = None
    route: str = ""
    served_hex: str = ""
    result_hex: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    flags: list[str] = field(default_factory=list)
    fault: str = ""
    author: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def final(self) -> bool:
        return self.state in FINAL_STATES


@dataclass
class TrafficRecord:
    """One exchange a listener answered: the request as received, the answer as sent, and what the engine made of it.

    ``peer_port`` is the client's source port, the number an IPAe terminal reads
    from its own channel socket to find the exchanges of that socket;
    ``tls_setup`` the chain the ClientHello's server_name picked ('' on the
    plain listener), ``tls_leaf`` the SHA-256 of the leaf certificate that
    chain served on this connection (a setup's leaf can be swapped under one
    name, so the name alone does not say what the client saw). ``binding`` is
    ``esipa-asn1``, ``esipa-json``, ``es9-asn1`` or ``es9-json``;
    ``operation_id`` the operation served or closed by the exchange, when one
    was.
    """

    id: int
    at: str
    peer_host: str = ""
    peer_port: int = 0
    listener_port: int = 0
    tls_setup: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    binding: str = ""
    path: str = ""
    request: bytes = b""
    status: int = 0
    response: bytes = b""
    duration_ms: int = 0
    eid: str = ""
    operation_id: int | None = None
    note: str = ""
    tls_leaf: str = ""


@dataclass
class TlsHandshake:
    """One TLS handshake on a card-facing listener: what was served and how it ended.

    ``server_name`` is what the ClientHello asked for ('' when it named no
    host), ``tls_setup`` the chain picked, ``leaf`` the name of the leaf that
    chain served and ``leaf_sha256`` the SHA-256 of its DER. ``outcome`` is
    one of the HANDSHAKE_* values; ``alert`` the AlertDescription name when
    an alert ended it (the client's when the outcome is refused, this side's
    when it is failed) and ``reason`` the TLS library's own word for the end.
    ``resumed`` marks a session resumption, in which the client checks no
    certificate. ``requests`` counts the exchanges the connection went on to
    carry and ``eid`` is the eUICC the first of them named.
    """

    id: int
    at: str
    peer_host: str = ""
    peer_port: int = 0
    listener_port: int = 0
    server_name: str = ""
    tls_setup: str = ""
    leaf: str = ""
    leaf_sha256: str = ""
    outcome: str = ""
    alert: str = ""
    reason: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    resumed: bool = False
    requests: int = 0
    eid: str = ""


@dataclass
class SmdsEvent:
    """One Event Record of the local SM-DS (SGP.22 v3.1 5.9.1, Table 53).

    ``id`` is the order of registration, which is the order an Event
    Retrieval returns the records in (3.6.2). ``event_type`` is 1 for a
    Profile download and 2 for RPM; ``caller`` is the identity of the RSP
    Server that registered the record, within which the EventID is unique.
    """

    id: int
    at: str
    eid: str
    event_id: str
    rsp_server_address: str
    event_type: int = 1
    caller: str = ""


class StoreError(RuntimeError):
    """A store request names an operation or eUICC that is not there, or one in the wrong state."""


class EimStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            self._add_missing_columns(connection)

    @staticmethod
    def _add_missing_columns(connection: sqlite3.Connection) -> None:
        for table, column, definition in _ADDED_COLUMNS:
            if column in {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}:
                continue
            try:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                # Another process opening the same store added it between the look and the change.
                if column not in {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}:
                    raise

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=15.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One write transaction; BEGIN IMMEDIATE serialises writers across processes."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")

    # -- settings ----------------------------------------------------------

    def setting(self, key: str, default: Any = None) -> Any:
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM setting WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return json.loads(row["value"])

    def settings(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute("SELECT key, value FROM setting ORDER BY key").fetchall()
        return {row["key"]: json.loads(row["value"]) for row in rows}

    def set_setting(self, key: str, value: Any) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO setting (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )

    # -- eUICC records -----------------------------------------------------

    @staticmethod
    def _record(row: sqlite3.Row) -> EuiccRecord:
        return EuiccRecord(
            eid=row["eid"],
            label=row["label"],
            created_at=row["created_at"],
            association_token=row["association_token"],
            counter_value=int(row["counter_value"]),
            seq_number=row["seq_number"],
            euicc_certificate=bytes(row["euicc_certificate"] or b""),
            eum_certificate=bytes(row["eum_certificate"] or b""),
            data=json.loads(row["data"] or "{}"),
            first_poll_at=row["first_poll_at"],
            last_poll_at=row["last_poll_at"],
            poll_count=int(row["poll_count"]),
        )

    def record(self, eid: str, connection: sqlite3.Connection | None = None) -> EuiccRecord | None:
        if connection is not None:
            row = connection.execute("SELECT * FROM euicc WHERE eid = ?", (eid,)).fetchone()
            return None if row is None else self._record(row)
        with self._connect() as own:
            row = own.execute("SELECT * FROM euicc WHERE eid = ?", (eid,)).fetchone()
        return None if row is None else self._record(row)

    def records(self) -> list[EuiccRecord]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM euicc ORDER BY created_at, eid").fetchall()
        return [self._record(row) for row in rows]

    def insert_record(self, record: EuiccRecord, connection: sqlite3.Connection) -> None:
        connection.execute(
            "INSERT INTO euicc (eid, label, created_at, association_token, counter_value, seq_number, "
            "euicc_certificate, eum_certificate, data, first_poll_at, last_poll_at, poll_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.eid, record.label, record.created_at or utc_now(), record.association_token,
                int(record.counter_value), record.seq_number, record.euicc_certificate or None,
                record.eum_certificate or None, json.dumps(record.data), record.first_poll_at,
                record.last_poll_at, int(record.poll_count),
            ),
        )

    def save_record(self, record: EuiccRecord, connection: sqlite3.Connection) -> None:
        notifications = record.data.get("notifications")
        if isinstance(notifications, list) and len(notifications) > RECORD_NOTIFICATION_CAP:
            from SCP11.eim_local.engine.notifications import bounded

            # The delivered ones make room first: one still to be sent is the only copy left.
            record.data["notifications"] = bounded(notifications, RECORD_NOTIFICATION_CAP)
        connection.execute(
            "UPDATE euicc SET label = ?, association_token = ?, counter_value = ?, seq_number = ?, "
            "euicc_certificate = ?, eum_certificate = ?, data = ?, first_poll_at = ?, last_poll_at = ?, "
            "poll_count = ? WHERE eid = ?",
            (
                record.label, record.association_token, int(record.counter_value), record.seq_number,
                record.euicc_certificate or None, record.eum_certificate or None, json.dumps(record.data),
                record.first_poll_at, record.last_poll_at, int(record.poll_count), record.eid,
            ),
        )

    def delete_record(self, eid: str) -> int:
        with self.transaction() as connection:
            connection.execute("DELETE FROM operation WHERE eid = ?", (eid,))
            cursor = connection.execute("DELETE FROM euicc WHERE eid = ?", (eid,))
        return int(cursor.rowcount)

    # -- tasks -------------------------------------------------------------

    def insert_task(self, connection: sqlite3.Connection, *, author: str, summary: str) -> int:
        cursor = connection.execute(
            "INSERT INTO task (created_at, author, summary) VALUES (?, ?, ?)",
            (utc_now(), author, summary),
        )
        return int(cursor.lastrowid)

    # -- operations ----------------------------------------------------------

    @staticmethod
    def _operation(row: sqlite3.Row) -> Operation:
        values = dict(row)
        for key, empty in _OPERATION_JSON.items():
            text = values.get(key) or ""
            values[key] = json.loads(text) if len(text) > 0 else type(empty)()
        values["system"] = bool(values.get("system"))
        return Operation(**values)

    def operation(self, operation_id: int, connection: sqlite3.Connection | None = None) -> Operation:
        query = "SELECT * FROM operation WHERE id = ?"
        if connection is not None:
            row = connection.execute(query, (int(operation_id),)).fetchone()
        else:
            with self._connect() as own:
                row = own.execute(query, (int(operation_id),)).fetchone()
        if row is None:
            raise StoreError(f"No operation {operation_id}.")
        return self._operation(row)

    def operations(
        self,
        *,
        eid: str = "",
        states: tuple[str, ...] = (),
        types: tuple[str, ...] = (),
        since: str = "",
        limit: int = 200,
        newest_first: bool = True,
    ) -> list[Operation]:
        clauses: list[str] = []
        values: list[Any] = []
        if len(eid) > 0:
            clauses.append("eid = ?")
            values.append(eid)
        if states:
            clauses.append(f"state IN ({', '.join('?' for _ in states)})")
            values.extend(states)
        if types:
            clauses.append(f"type IN ({', '.join('?' for _ in types)})")
            values.extend(types)
        if len(since) > 0:
            clauses.append("created_at >= ?")
            values.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if newest_first else "ASC"
        query = f"SELECT * FROM operation {where} ORDER BY id {order} LIMIT ?"
        values.append(max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, values).fetchall()
        return [self._operation(row) for row in rows]

    def queue(self, eid: str, connection: sqlite3.Connection) -> list[Operation]:
        """Pending operations of one eUICC in serving order: SENT first, then CREATED by position."""
        rows = connection.execute(
            "SELECT * FROM operation WHERE eid = ? AND state IN (?, ?) "
            "ORDER BY CASE state WHEN ? THEN 0 ELSE 1 END, position, id",
            (eid, STATE_SENT, STATE_CREATED, STATE_SENT),
        ).fetchall()
        return [self._operation(row) for row in rows]

    def next_position(self, eid: str, connection: sqlite3.Connection) -> int:
        row = connection.execute("SELECT MAX(position) AS top FROM operation WHERE eid = ?", (eid,)).fetchone()
        return int(row["top"] or 0) + 1

    def first_position(self, eid: str, connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT MIN(position) AS low FROM operation WHERE eid = ? AND state = ?",
            (eid, STATE_CREATED),
        ).fetchone()
        low = row["low"]
        return (int(low) - 1) if low is not None else self.next_position(eid, connection)

    def insert_operation(self, operation: Operation, connection: sqlite3.Connection) -> int:
        cursor = connection.execute(
            "INSERT INTO operation (task_id, eid, position, type, params, raw_items, state, system, recovery_for, "
            "retries, max_retries, not_before, transaction_id, created_at, warnings, flags, fault, author, history) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                operation.task_id, operation.eid, int(operation.position), operation.type,
                json.dumps(operation.params), operation.raw_items, operation.state, int(operation.system),
                operation.recovery_for, int(operation.retries), int(operation.max_retries), operation.not_before,
                operation.transaction_id, operation.created_at or utc_now(), json.dumps(operation.warnings),
                json.dumps(operation.flags), operation.fault, operation.author,
                json.dumps(operation.history[-OPERATION_HISTORY_CAP:]),
            ),
        )
        return int(cursor.lastrowid)

    def save_operation(self, operation: Operation, connection: sqlite3.Connection) -> None:
        operation.history = operation.history[-OPERATION_HISTORY_CAP:]
        connection.execute(
            "UPDATE operation SET position = ?, type = ?, params = ?, raw_items = ?, state = ?, recovery_for = ?, "
            "retries = ?, max_retries = ?, not_before = ?, counter_value = ?, association_token = ?, served_at = ?, "
            "finished_at = ?, route = ?, served_hex = ?, result_hex = ?, result = ?, warnings = ?, error = ?, "
            "flags = ?, fault = ?, history = ? WHERE id = ?",
            (
                int(operation.position), operation.type, json.dumps(operation.params), operation.raw_items,
                operation.state, operation.recovery_for, int(operation.retries), int(operation.max_retries),
                operation.not_before, operation.counter_value, operation.association_token, operation.served_at,
                operation.finished_at, operation.route, operation.served_hex, operation.result_hex,
                json.dumps(operation.result), json.dumps(operation.warnings), operation.error,
                json.dumps(operation.flags), operation.fault, json.dumps(operation.history), operation.id,
            ),
        )

    def find_by_transaction(self, eid: str, transaction_id: str, connection: sqlite3.Connection) -> Operation | None:
        row = connection.execute(
            "SELECT * FROM operation WHERE eid = ? AND transaction_id = ? ORDER BY id DESC LIMIT 1",
            (eid, transaction_id.upper()),
        ).fetchone()
        return None if row is None else self._operation(row)

    def find_by_transaction_any(self, transaction_id: str, connection: sqlite3.Connection) -> Operation | None:
        """The operation of *transaction_id* whatever its eUICC, the one in flight first."""
        row = connection.execute(
            "SELECT * FROM operation WHERE transaction_id = ? ORDER BY (state = ?) DESC, id DESC LIMIT 1",
            (transaction_id.upper(), STATE_SENT),
        ).fetchone()
        return None if row is None else self._operation(row)

    def find_by_counter(self, eid: str, counter_value: int, connection: sqlite3.Connection) -> Operation | None:
        row = connection.execute(
            "SELECT * FROM operation WHERE eid = ? AND counter_value = ? ORDER BY id DESC LIMIT 1",
            (eid, int(counter_value)),
        ).fetchone()
        return None if row is None else self._operation(row)

    def prune(self, cap: int | None = None) -> int:
        """Delete the oldest finished operations past *cap*; pending ones are never pruned."""
        limit = history_cap() if cap is None else int(cap)
        with self.transaction() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS total FROM operation WHERE state IN ({', '.join('?' for _ in FINAL_STATES)})",
                FINAL_STATES,
            ).fetchone()
            excess = int(row["total"]) - limit
            if excess <= 0:
                return 0
            cursor = connection.execute(
                f"DELETE FROM operation WHERE id IN (SELECT id FROM operation WHERE state IN "
                f"({', '.join('?' for _ in FINAL_STATES)}) ORDER BY id ASC LIMIT ?)",
                (*FINAL_STATES, excess),
            )
        return int(cursor.rowcount)

    # -- traffic -----------------------------------------------------------

    @staticmethod
    def _traffic(row: sqlite3.Row) -> TrafficRecord:
        values = dict(row)
        values["request"] = bytes(values.get("request") or b"")
        values["response"] = bytes(values.get("response") or b"")
        return TrafficRecord(**values)

    def insert_traffic(self, record: TrafficRecord, cap: int = TRAFFIC_CAP) -> int:
        """Write one exchange and return its id; the rows past *cap* go in the same transaction."""
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO traffic (at, peer_host, peer_port, listener_port, tls_setup, tls_version, tls_cipher, "
                "binding, path, request, status, response, duration_ms, eid, operation_id, note, tls_leaf) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.at or utc_now_ms(), record.peer_host, int(record.peer_port), int(record.listener_port),
                    record.tls_setup, record.tls_version, record.tls_cipher, record.binding, record.path,
                    bytes(record.request), int(record.status), bytes(record.response), int(record.duration_ms),
                    record.eid, record.operation_id, record.note, record.tls_leaf,
                ),
            )
            record.id = int(cursor.lastrowid)
            connection.execute(
                "DELETE FROM traffic WHERE id <= (SELECT id FROM traffic ORDER BY id DESC LIMIT 1 OFFSET ?)",
                (max(1, int(cap)),),
            )
        return record.id

    def traffic(
        self,
        *,
        limit: int = 20,
        eid: str = "",
        operation_id: int | None = None,
        after_id: int | None = None,
        peer_port: int | None = None,
        newest_first: bool = True,
    ) -> list[TrafficRecord]:
        clauses: list[str] = []
        values: list[Any] = []
        if len(eid) > 0:
            clauses.append("eid = ?")
            values.append(eid)
        if operation_id is not None:
            clauses.append("operation_id = ?")
            values.append(int(operation_id))
        if after_id is not None:
            clauses.append("id > ?")
            values.append(int(after_id))
        if peer_port is not None:
            clauses.append("peer_port = ?")
            values.append(int(peer_port))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if newest_first else "ASC"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM traffic {where} ORDER BY id {order} LIMIT ?", (*values, max(1, int(limit))),
            ).fetchall()
        return [self._traffic(row) for row in rows]

    def traffic_record(self, record_id: int) -> TrafficRecord:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM traffic WHERE id = ?", (int(record_id),)).fetchone()
        if row is None:
            raise StoreError(f"No exchange {record_id}.")
        return self._traffic(row)

    # -- TLS handshakes ----------------------------------------------------

    @staticmethod
    def _handshake(row: sqlite3.Row) -> TlsHandshake:
        values = dict(row)
        values["resumed"] = bool(values.get("resumed"))
        return TlsHandshake(**values)

    def insert_handshake(self, record: TlsHandshake, cap: int = TLS_HANDSHAKE_CAP) -> int:
        """Write one card-facing handshake and return its id; the rows past *cap* go in the same transaction."""
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO tls_handshake (at, peer_host, peer_port, listener_port, server_name, tls_setup, leaf, "
                "leaf_sha256, outcome, alert, reason, tls_version, tls_cipher, resumed, requests, eid) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.at or utc_now_ms(), record.peer_host, int(record.peer_port), int(record.listener_port),
                    record.server_name, record.tls_setup, record.leaf, record.leaf_sha256, record.outcome,
                    record.alert, record.reason, record.tls_version, record.tls_cipher, int(bool(record.resumed)),
                    int(record.requests), record.eid,
                ),
            )
            record.id = int(cursor.lastrowid)
            connection.execute(
                "DELETE FROM tls_handshake WHERE id <= "
                "(SELECT id FROM tls_handshake ORDER BY id DESC LIMIT 1 OFFSET ?)",
                (max(1, int(cap)),),
            )
        return record.id

    def note_handshake_request(self, handshake_id: int, eid: str = "") -> None:
        """Count one more exchange on the connection of *handshake_id*; the first EID named stays."""
        with self.transaction() as connection:
            connection.execute(
                "UPDATE tls_handshake SET requests = requests + 1, eid = CASE WHEN eid = '' THEN ? ELSE eid END "
                "WHERE id = ?",
                (str(eid or ""), int(handshake_id)),
            )

    def handshakes(self, *, limit: int = 200, setup: str = "", newest_first: bool = True) -> list[TlsHandshake]:
        clause, values = ("WHERE tls_setup = ?", [setup]) if len(setup) > 0 else ("", [])
        order = "DESC" if newest_first else "ASC"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM tls_handshake {clause} ORDER BY id {order} LIMIT ?", (*values, max(1, int(limit))),
            ).fetchall()
        return [self._handshake(row) for row in rows]

    # -- SM-DS Event Records -----------------------------------------------

    def smds_events(
        self,
        *,
        eid: str = "",
        event_id: str = "",
        event_type: int | None = None,
        caller: str = "",
        connection: sqlite3.Connection | None = None,
    ) -> list[SmdsEvent]:
        """Event Records in the order they were registered; every argument given narrows the list."""
        clauses: list[str] = []
        values: list[Any] = []
        for column, value in (("eid", eid), ("event_id", event_id), ("caller", caller)):
            if len(str(value or "")) > 0:
                clauses.append(f"{column} = ?")
                values.append(str(value))
        if event_type is not None:
            clauses.append("event_type = ?")
            values.append(int(event_type))
        query = "SELECT * FROM smds_event" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY id"
        if connection is not None:
            rows = connection.execute(query, values).fetchall()
        else:
            with self._connect() as own:
                rows = own.execute(query, values).fetchall()
        return [SmdsEvent(**dict(row)) for row in rows]

    def insert_smds_event(self, event: SmdsEvent, connection: sqlite3.Connection, cap: int = SMDS_EVENT_CAP) -> int:
        """Write one Event Record and return its id; a table at *cap* refuses it."""
        held = int(connection.execute("SELECT COUNT(*) FROM smds_event").fetchone()[0])
        if held >= max(1, int(cap)):
            raise StoreError(f"The SM-DS holds its cap of {held} Event Records; delete some before registering more.")
        cursor = connection.execute(
            "INSERT INTO smds_event (at, eid, event_id, rsp_server_address, event_type, caller) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event.at or utc_now(), event.eid, event.event_id, event.rsp_server_address, int(event.event_type),
             event.caller),
        )
        event.id = int(cursor.lastrowid)
        return event.id

    def delete_smds_events(self, ids: list[int], connection: sqlite3.Connection) -> int:
        removed = 0
        for record_id in ids:
            removed += connection.execute("DELETE FROM smds_event WHERE id = ?", (int(record_id),)).rowcount
        return removed
