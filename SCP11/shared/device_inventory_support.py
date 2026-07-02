# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 device-inventory support: EID-keyed namespace adapter writing profile metadata to the device inventory store."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

try:
    from yggdrasim_common.device_inventory import DeviceInventoryStore
except ImportError:
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from yggdrasim_common.device_inventory import DeviceInventoryStore


class EidInventoryNamespace:
    """Thin helper for EID-indexed module settings."""

    def __init__(self, namespace: str, db_path: Optional[str] = None):
        self.namespace = str(namespace or "").strip().lower()
        if len(self.namespace) == 0:
            raise ValueError("namespace must not be empty.")
        self.store = DeviceInventoryStore(db_path=db_path)

    @staticmethod
    def normalize_eid(eid: Any) -> str:
        return "".join(ch for ch in str(eid or "").strip().upper() if ch in "0123456789ABCDEF")

    def load(self, eid: Any) -> dict[str, Any]:
        normalized_eid = self.normalize_eid(eid)
        if len(normalized_eid) == 0:
            return {}
        return self.store.get_namespace("eid", normalized_eid, self.namespace)

    def replace(self, eid: Any, payload: dict[str, Any]) -> dict[str, Any]:
        normalized_eid = self.normalize_eid(eid)
        if len(normalized_eid) == 0:
            return {}
        return self.store.replace_namespace("eid", normalized_eid, self.namespace, dict(payload))

    def merge(self, eid: Any, updates: dict[str, Any], drop_empty: bool = False) -> dict[str, Any]:
        """Merge a discovery-snapshot dict into the device inventory record for the given EID."""
        normalized_eid = self.normalize_eid(eid)
        if len(normalized_eid) == 0:
            return {}
        return self.store.merge_namespace(
            "eid",
            normalized_eid,
            self.namespace,
            dict(updates),
            drop_empty=drop_empty,
        )
