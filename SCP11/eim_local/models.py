# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eIM-local data models: handover context, runtime state, and transaction helpers for the local eIM session."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EimHandoverContext:
    transaction_id: bytes = b""
    matching_id: str = ""
    profile_path: str = ""
    notification_policy: str = "strict"
    source: str = "unset"

    def as_json_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["transaction_id_hex"] = self.transaction_id.hex().upper()
        payload.pop("transaction_id", None)
        return payload


@dataclass
class EimLocalState:
    eim_package_override_path: str = ""
    hotfolder_override_path: str = ""
    hotfolder_metadata_session_dir: str = ""
    hotfolder_metadata_session_issued_paths: set[str] = field(default_factory=set)
    selected_eim_certificate_path: str = ""
    selected_eim_certificate_reason: str = ""
    selected_eim_certificate_ci_pkids: list[str] = field(default_factory=list)
    selected_eim_private_key_path: str = ""
    current_bip_role: str = "eim"
    current_bip_endpoint: str = ""
    bip_routing_mode: str = "runtime-managed-intercept"
    last_intercepted_target: str = ""
    last_intercept_reason: str = ""
    pending_operations: list[dict[str, str]] = field(default_factory=list)
    handover: EimHandoverContext = field(default_factory=EimHandoverContext)


def ensure_handover_transaction(handover: EimHandoverContext) -> bytes:
    transaction_id = bytes(handover.transaction_id)
    if len(transaction_id) == 0:
        raise RuntimeError("No handover transaction is present. Set a handover transaction first.")
    return transaction_id
