from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .inventory_crypto import InventoryCryptoManager
from .runtime_paths import runtime_path


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_identity_kind(identity_kind: str) -> str:
    normalized = str(identity_kind or "").strip().lower()
    if normalized not in {"eid", "iccid", "eim_id"}:
        raise ValueError("identity_kind must be 'eid', 'iccid', or 'eim_id'.")
    return normalized


def _normalize_identity_value(identity_kind: str, identity_value: Any) -> str:
    normalized_kind = _normalize_identity_kind(identity_kind)
    raw_text = str(identity_value or "").strip()
    if len(raw_text) == 0:
        raise ValueError(f"{normalized_kind.upper()} value must not be empty.")

    if normalized_kind == "eid":
        compact = "".join(ch for ch in raw_text.upper() if ch in "0123456789ABCDEF")
        if len(compact) == 0:
            raise ValueError("EID must contain hexadecimal digits.")
        return compact

    if normalized_kind == "eim_id":
        return raw_text

    digits = "".join(ch for ch in raw_text if ch.isdigit())
    if len(digits) > 0:
        return digits
    compact = "".join(ch for ch in raw_text.upper() if ch in "0123456789ABCDEF")
    if len(compact) == 0:
        raise ValueError("ICCID must contain decimal or hexadecimal digits.")
    return compact


def _normalize_namespace(namespace: str) -> str:
    normalized = str(namespace or "").strip().lower()
    if len(normalized) == 0:
        raise ValueError("namespace must not be empty.")
    return normalized


def _normalize_module_name(module_name: str) -> str:
    normalized = str(module_name or "").strip().lower()
    if len(normalized) == 0:
        raise ValueError("module_name must not be empty.")
    return normalized


class DeviceInventoryStore:
    """Shared identifier-indexed configuration inventory for SCP03/SCP80/SCP11."""

    DEFAULT_DB_PATH = Path(runtime_path("state", "device_inventory.sqlite3"))

    def __init__(
        self,
        db_path: Optional[str] = None,
        crypto_manager: Optional[Any] = None,
    ):
        if db_path is None:
            self.db_path = str(self.DEFAULT_DB_PATH)
        else:
            self.db_path = os.path.abspath(os.path.expanduser(str(db_path).strip()))
        self.crypto = crypto_manager or InventoryCryptoManager()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        parent = os.path.dirname(self.db_path)
        if len(parent) > 0:
            os.makedirs(parent, exist_ok=True)
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS inventory_namespaces (
                    identity_kind TEXT NOT NULL,
                    identity_value TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    PRIMARY KEY (identity_kind, identity_value, namespace)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS module_state (
                    module_name TEXT NOT NULL PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()
        self._migrate_plaintext_rows_if_needed()

    def write_encryption_enabled(self) -> bool:
        return bool(self.crypto.write_encryption_enabled())

    def blocks_plaintext_secret_writes(self) -> bool:
        return bool(self.crypto.blocks_plaintext_secret_writes())

    def _serialize_payload(self, payload: dict[str, Any]) -> str:
        stored_payload = dict(payload)
        if self.write_encryption_enabled():
            stored_payload = dict(self.crypto.encrypt_payload(payload))
        return json.dumps(stored_payload, indent=2, sort_keys=True, ensure_ascii=True)

    def _deserialize_payload(self, payload_text: str) -> dict[str, Any]:
        try:
            payload = json.loads(str(payload_text))
        except (json.JSONDecodeError, TypeError):
            return {}
        if isinstance(payload, dict) is False:
            return {}
        if self.crypto.is_encrypted_payload(payload):
            decrypted = self.crypto.decrypt_payload(payload)
            if isinstance(decrypted, dict):
                return decrypted
            return {}
        return payload

    def _migrate_plaintext_rows_if_needed(self) -> None:
        if self.write_encryption_enabled() is False:
            return
        if hasattr(self.crypto, "provider_ready_for_encrypt"):
            if bool(self.crypto.provider_ready_for_encrypt()) is False:
                return
        connection = self._connect()
        try:
            inventory_rows = connection.execute(
                """
                SELECT identity_kind, identity_value, namespace, payload_json
                FROM inventory_namespaces
                """
            ).fetchall()
            inventory_updates: list[tuple[str, str, str, str]] = []
            for row in inventory_rows:
                payload = self._deserialize_payload(str(row["payload_json"]))
                if len(payload) == 0:
                    continue
                try:
                    raw_payload = json.loads(str(row["payload_json"]))
                except (json.JSONDecodeError, TypeError):
                    continue
                if self.crypto.is_encrypted_payload(raw_payload):
                    continue
                encoded_payload = self._serialize_payload(payload)
                inventory_updates.append(
                    (
                        encoded_payload,
                        str(row["identity_kind"]),
                        str(row["identity_value"]),
                        str(row["namespace"]),
                    )
                )
            for encoded_payload, identity_kind, identity_value, namespace in inventory_updates:
                connection.execute(
                    """
                    UPDATE inventory_namespaces
                    SET payload_json = ?, updated_at_utc = ?
                    WHERE identity_kind = ?
                      AND identity_value = ?
                      AND namespace = ?
                    """,
                    (
                        encoded_payload,
                        _utc_now(),
                        identity_kind,
                        identity_value,
                        namespace,
                    ),
                )

            module_rows = connection.execute(
                """
                SELECT module_name, payload_json
                FROM module_state
                """
            ).fetchall()
            module_updates: list[tuple[str, str]] = []
            for row in module_rows:
                payload = self._deserialize_payload(str(row["payload_json"]))
                if len(payload) == 0:
                    continue
                try:
                    raw_payload = json.loads(str(row["payload_json"]))
                except (json.JSONDecodeError, TypeError):
                    continue
                if self.crypto.is_encrypted_payload(raw_payload):
                    continue
                encoded_payload = self._serialize_payload(payload)
                module_updates.append((encoded_payload, str(row["module_name"])))
            for encoded_payload, module_name in module_updates:
                connection.execute(
                    """
                    UPDATE module_state
                    SET payload_json = ?, updated_at_utc = ?
                    WHERE module_name = ?
                    """,
                    (
                        encoded_payload,
                        _utc_now(),
                        module_name,
                    ),
                )

            if len(inventory_updates) > 0 or len(module_updates) > 0:
                connection.commit()
        finally:
            connection.close()

    def get_namespace(
        self,
        identity_kind: str,
        identity_value: Any,
        namespace: str,
    ) -> dict[str, Any]:
        normalized_kind = _normalize_identity_kind(identity_kind)
        normalized_value = _normalize_identity_value(normalized_kind, identity_value)
        normalized_namespace = _normalize_namespace(namespace)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT payload_json
                FROM inventory_namespaces
                WHERE identity_kind = ?
                  AND identity_value = ?
                  AND namespace = ?
                """,
                (normalized_kind, normalized_value, normalized_namespace),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return {}
        return self._deserialize_payload(str(row["payload_json"]))

    def replace_namespace(
        self,
        identity_kind: str,
        identity_value: Any,
        namespace: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if isinstance(payload, dict) is False:
            raise ValueError("payload must be a dictionary.")
        normalized_kind = _normalize_identity_kind(identity_kind)
        normalized_value = _normalize_identity_value(normalized_kind, identity_value)
        normalized_namespace = _normalize_namespace(namespace)
        encoded_payload = self._serialize_payload(payload)
        updated_at_utc = _utc_now()
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO inventory_namespaces (
                    identity_kind,
                    identity_value,
                    namespace,
                    payload_json,
                    updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(identity_kind, identity_value, namespace)
                DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (
                    normalized_kind,
                    normalized_value,
                    normalized_namespace,
                    encoded_payload,
                    updated_at_utc,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return dict(payload)

    def merge_namespace(
        self,
        identity_kind: str,
        identity_value: Any,
        namespace: str,
        updates: dict[str, Any],
        drop_empty: bool = False,
    ) -> dict[str, Any]:
        if isinstance(updates, dict) is False:
            raise ValueError("updates must be a dictionary.")
        payload = self.get_namespace(identity_kind, identity_value, namespace)
        merged = dict(payload)
        for key, value in updates.items():
            if drop_empty:
                if value is None:
                    merged.pop(key, None)
                    continue
                if isinstance(value, str) and len(value.strip()) == 0:
                    merged.pop(key, None)
                    continue
            merged[str(key)] = value
        return self.replace_namespace(identity_kind, identity_value, namespace, merged)

    def list_identities(self, identity_kind: Optional[str] = None) -> list[dict[str, str]]:
        query = """
            SELECT identity_kind, identity_value, MAX(updated_at_utc) AS updated_at_utc
            FROM inventory_namespaces
        """
        params: tuple[Any, ...] = ()
        if identity_kind is not None and len(str(identity_kind).strip()) > 0:
            normalized_kind = _normalize_identity_kind(identity_kind)
            query += " WHERE identity_kind = ?"
            params = (normalized_kind,)
        query += " GROUP BY identity_kind, identity_value ORDER BY identity_kind, identity_value"
        connection = self._connect()
        try:
            rows = connection.execute(query, params).fetchall()
        finally:
            connection.close()
        results: list[dict[str, str]] = []
        for row in rows:
            results.append(
                {
                    "identity_kind": str(row["identity_kind"]),
                    "identity_value": str(row["identity_value"]),
                    "updated_at_utc": str(row["updated_at_utc"] or ""),
                }
            )
        return results

    def get_module_state(self, module_name: str) -> dict[str, Any]:
        normalized_module_name = _normalize_module_name(module_name)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT payload_json
                FROM module_state
                WHERE module_name = ?
                """,
                (normalized_module_name,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return {}
        return self._deserialize_payload(str(row["payload_json"]))

    def replace_module_state(self, module_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if isinstance(payload, dict) is False:
            raise ValueError("payload must be a dictionary.")
        normalized_module_name = _normalize_module_name(module_name)
        encoded_payload = self._serialize_payload(payload)
        updated_at_utc = _utc_now()
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO module_state (
                    module_name,
                    payload_json,
                    updated_at_utc
                )
                VALUES (?, ?, ?)
                ON CONFLICT(module_name)
                DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (
                    normalized_module_name,
                    encoded_payload,
                    updated_at_utc,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return dict(payload)
