# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eIM runtime state store: persists per-EID session state between package rounds."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from yggdrasim_common.device_inventory import DeviceInventoryStore
except ImportError:
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from yggdrasim_common.device_inventory import DeviceInventoryStore


class EimRuntimeStateStore:
    """Persist lightweight eIM runtime state (counter tracking + last operation)."""
    INVENTORY_NAMESPACE = "scp11_eim_local"
    MODULE_STATE_NAME = "scp11_eim_local_runtime"

    DEFAULT_STATE: dict[str, Any] = {
        "counter_by_eim_id": {},
        "last_transaction_id_hex": "",
        "last_matching_id": "",
        "last_operation": "",
        "updated_at_utc": "",
    }

    def __init__(self, file_path: str, inventory: Optional[DeviceInventoryStore] = None):
        self.file_path = file_path
        self.state: dict[str, Any] = {}
        self.inventory = inventory or DeviceInventoryStore()
        self._load()

    def _load(self) -> None:
        self.state = dict(self.DEFAULT_STATE)
        module_state = self.inventory.get_module_state(self.MODULE_STATE_NAME)
        if isinstance(module_state, dict) and len(module_state) > 0:
            self.state.update(module_state)
            self._rebuild_counter_table_from_inventory()
            if isinstance(self.state.get("counter_by_eim_id"), dict) is False:
                self.state["counter_by_eim_id"] = {}
            self._save()
            return

        if os.path.isfile(self.file_path):
            try:
                with open(self.file_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                payload = {}
            if isinstance(payload, dict):
                self.state.update(payload)
        if isinstance(self.state.get("counter_by_eim_id"), dict) is False:
            self.state["counter_by_eim_id"] = {}
        self._save()
        self._rebuild_counter_table_from_inventory()

    def _save(self) -> None:
        self.state["updated_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        self.inventory.replace_module_state(self.MODULE_STATE_NAME, self._module_state_payload())
        counter_table = self.state.get("counter_by_eim_id", {})
        if isinstance(counter_table, dict):
            for eim_id in counter_table.keys():
                self._persist_inventory_record(str(eim_id))

    def to_dict(self) -> dict[str, Any]:
        self._rebuild_counter_table_from_inventory()
        return dict(self.state)

    def get_next_counter(self, eim_id: str, default_value: int = 1) -> int:
        """Return the next available transaction counter value."""
        key = str(eim_id or "default").strip()
        inventory_payload = self.inventory.get_namespace("eim_id", key, self.INVENTORY_NAMESPACE)
        if isinstance(inventory_payload, dict):
            inventory_counter = inventory_payload.get("next_counter")
            if isinstance(inventory_counter, int) and inventory_counter > 0:
                table = self.state.get("counter_by_eim_id", {})
                if isinstance(table, dict):
                    table[key] = inventory_counter
        table = self.state.get("counter_by_eim_id", {})
        if isinstance(table, dict) is False:
            table = {}
            self.state["counter_by_eim_id"] = table
        raw = table.get(key)
        if isinstance(raw, int) and raw > 0:
            return raw
        table[key] = int(default_value)
        self._save()
        return int(default_value)

    def set_next_counter(self, eim_id: str, next_value: int) -> int:
        """Persist a new counter value to the runtime state store."""
        key = str(eim_id or "default").strip()
        value = int(next_value)
        if value <= 0:
            raise ValueError("next counter value must be a positive integer.")
        table = self.state.get("counter_by_eim_id", {})
        if isinstance(table, dict) is False:
            table = {}
            self.state["counter_by_eim_id"] = table
        table[key] = value
        self._save()
        self._persist_inventory_record(key)
        return value

    def mark_counter_used(self, eim_id: str, used_value: int) -> None:
        """Record that a counter value has been consumed in this session."""
        key = str(eim_id or "default").strip()
        table = self.state.get("counter_by_eim_id", {})
        if isinstance(table, dict) is False:
            table = {}
            self.state["counter_by_eim_id"] = table
        next_value = int(used_value) + 1
        current = table.get(key)
        if isinstance(current, int) and current >= next_value:
            return
        table[key] = next_value
        self._save()
        self._persist_inventory_record(key)

    def record_operation(self, operation: str, transaction_id_hex: str = "", matching_id: str = "") -> None:
        """Append an operation record to the audit log for this EID."""
        self.state["last_operation"] = str(operation).strip()
        self.state["last_transaction_id_hex"] = str(transaction_id_hex).strip().upper()
        self.state["last_matching_id"] = str(matching_id).strip()
        self._save()
        counter_table = self.state.get("counter_by_eim_id", {})
        if isinstance(counter_table, dict):
            for eim_id in counter_table.keys():
                self._persist_inventory_record(str(eim_id))

    def _persist_inventory_record(self, eim_id: str) -> None:
        key = str(eim_id or "default").strip()
        if len(key) == 0:
            return
        counter_table = self.state.get("counter_by_eim_id", {})
        next_counter = None
        if isinstance(counter_table, dict):
            candidate = counter_table.get(key)
            if isinstance(candidate, int) and candidate > 0:
                next_counter = candidate
        payload = {
            "next_counter": next_counter,
            "last_operation": str(self.state.get("last_operation", "")).strip(),
            "last_transaction_id_hex": str(self.state.get("last_transaction_id_hex", "")).strip().upper(),
            "last_matching_id": str(self.state.get("last_matching_id", "")).strip(),
        }
        self.inventory.replace_namespace("eim_id", key, self.INVENTORY_NAMESPACE, payload)

    def _module_state_payload(self) -> dict[str, Any]:
        return {
            "last_operation": str(self.state.get("last_operation", "")).strip(),
            "last_transaction_id_hex": str(self.state.get("last_transaction_id_hex", "")).strip().upper(),
            "last_matching_id": str(self.state.get("last_matching_id", "")).strip(),
            "updated_at_utc": str(self.state.get("updated_at_utc", "")).strip(),
        }

    def _rebuild_counter_table_from_inventory(self) -> None:
        counter_table: dict[str, int] = {}
        for row in self.inventory.list_identities("eim_id"):
            eim_id = str(row.get("identity_value", "")).strip()
            if len(eim_id) == 0:
                continue
            payload = self.inventory.get_namespace("eim_id", eim_id, self.INVENTORY_NAMESPACE)
            if isinstance(payload, dict) is False:
                continue
            next_counter = payload.get("next_counter")
            if isinstance(next_counter, int) and next_counter > 0:
                counter_table[eim_id] = next_counter
        self.state["counter_by_eim_id"] = counter_table
