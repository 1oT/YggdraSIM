import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class EimPollAuditStore:
    """SQLite-backed audit trail for direct and localized eIM poll flows."""

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(os.path.expanduser(str(db_path).strip()))
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        parent = os.path.dirname(self.db_path)
        if len(parent) > 0:
            os.makedirs(parent, exist_ok=True)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS poll_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        logged_at_utc TEXT NOT NULL,
                        eid TEXT NOT NULL,
                        flow TEXT NOT NULL,
                        flow_run_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        package_path TEXT NOT NULL,
                        package_name TEXT NOT NULL,
                        package_type TEXT NOT NULL,
                        transaction_id_hex TEXT NOT NULL,
                        matching_id TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        result_len INTEGER NOT NULL,
                        transport TEXT NOT NULL,
                        execution_path TEXT NOT NULL,
                        eim_result_code TEXT NOT NULL,
                        eim_result_name TEXT NOT NULL,
                        response_preview_hex TEXT NOT NULL,
                        error_type TEXT NOT NULL,
                        error_message TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        event_json TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_poll_events_logged_at
                    ON poll_events(logged_at_utc DESC)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_poll_events_eid
                    ON poll_events(eid, logged_at_utc DESC)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_poll_events_flow
                    ON poll_events(flow, logged_at_utc DESC)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_poll_events_package_type
                    ON poll_events(package_type, logged_at_utc DESC)
                    """
                )
                connection.commit()
            finally:
                connection.close()

    def append_event(self, event: dict[str, Any]) -> None:
        payload = dict(event)
        logged_at_utc = str(payload.get("logged_at_utc", "") or "").strip()
        if len(logged_at_utc) == 0:
            logged_at_utc = _utc_now()
            payload["logged_at_utc"] = logged_at_utc
        details = payload.get("details", {})
        if isinstance(details, dict) is False:
            details = {}
        package_path = str(payload.get("package_path", "") or "").strip()
        package_name = os.path.basename(package_path) if len(package_path) > 0 else ""
        details_json = json.dumps(details, sort_keys=True, ensure_ascii=True)
        event_json = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        transport = str(payload.get("transport", "") or details.get("transport", "") or "").strip()
        execution_path = str(
            payload.get("execution_path", "") or details.get("execution_path", "") or ""
        ).strip()
        eim_result_code = str(
            payload.get("eim_result_code", "") or details.get("eim_result_code", "") or ""
        ).strip()
        eim_result_name = str(
            payload.get("eim_result_name", "") or details.get("eim_result_name", "") or ""
        ).strip()
        with self._lock:
            connection = self._connect()
            try:
                connection.execute(
                    """
                    INSERT INTO poll_events (
                        logged_at_utc,
                        eid,
                        flow,
                        flow_run_id,
                        action,
                        package_path,
                        package_name,
                        package_type,
                        transaction_id_hex,
                        matching_id,
                        success,
                        result_len,
                        transport,
                        execution_path,
                        eim_result_code,
                        eim_result_name,
                        response_preview_hex,
                        error_type,
                        error_message,
                        details_json,
                        event_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        logged_at_utc,
                        str(payload.get("eid", "") or "").strip(),
                        str(payload.get("flow", "") or "").strip(),
                        str(payload.get("flow_run_id", "") or "").strip(),
                        str(payload.get("action", "") or "").strip(),
                        package_path,
                        package_name,
                        str(payload.get("package_type", "") or "").strip().lower(),
                        str(payload.get("transaction_id_hex", "") or "").strip().upper(),
                        str(payload.get("matching_id", "") or "").strip(),
                        1 if bool(payload.get("success", False)) else 0,
                        int(payload.get("result_len", 0) or 0),
                        transport,
                        execution_path,
                        eim_result_code,
                        eim_result_name,
                        str(payload.get("response_preview_hex", "") or "").strip().upper(),
                        str(payload.get("error_type", "") or "").strip(),
                        str(payload.get("error_message", "") or "").strip(),
                        details_json,
                        event_json,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

    def list_events(
        self,
        limit: int = 50,
        *,
        eid: str = "",
        flow: str = "",
        package_type: str = "",
    ) -> list[dict[str, Any]]:
        normalized_limit = int(limit)
        if normalized_limit <= 0:
            normalized_limit = 1
        clauses: list[str] = []
        params: list[Any] = []
        eid_value = str(eid or "").strip()
        if len(eid_value) > 0:
            clauses.append("eid = ?")
            params.append(eid_value)
        flow_value = str(flow or "").strip().lower()
        if len(flow_value) > 0:
            clauses.append("flow = ?")
            params.append(flow_value)
        package_type_value = str(package_type or "").strip().lower()
        if len(package_type_value) > 0:
            clauses.append("package_type = ?")
            params.append(package_type_value)
        query = "SELECT * FROM poll_events"
        if len(clauses) > 0:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(normalized_limit)
        with self._lock:
            connection = self._connect()
            try:
                rows = connection.execute(query, params).fetchall()
            finally:
                connection.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            payload["success"] = bool(int(payload.get("success", 0) or 0))
            details_text = str(payload.get("details_json", "") or "")
            event_text = str(payload.get("event_json", "") or "")
            try:
                payload["details"] = json.loads(details_text) if len(details_text) > 0 else {}
            except Exception:
                payload["details"] = {}
            try:
                payload["event"] = json.loads(event_text) if len(event_text) > 0 else {}
            except Exception:
                payload["event"] = {}
            results.append(payload)
        return results

    def clear(self) -> int:
        with self._lock:
            connection = self._connect()
            try:
                row = connection.execute("SELECT COUNT(*) FROM poll_events").fetchone()
                count = int(row[0]) if row is not None else 0
                connection.execute("DELETE FROM poll_events")
                connection.commit()
                return count
            finally:
                connection.close()
