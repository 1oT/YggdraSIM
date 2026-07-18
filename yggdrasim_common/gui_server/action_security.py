# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Last-mile secret minimisation for GUI action responses."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


_ACTION_SECRET_OUTPUT_KEYS: dict[str, frozenset[str]] = {
    "scp03.derive_opc": frozenset({"ki", "ki_hex", "op", "op_hex"}),
    "simcard.tuak_derive_topc": frozenset({"top", "top_hex", "key", "key_hex"}),
}


def scrub_action_result(
    action_id: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a detached result with action-specific secret outputs removed."""
    action = str(action_id or "")
    cleaned = deepcopy(dict(result))
    redacted: list[str] = []
    for key in _ACTION_SECRET_OUTPUT_KEYS.get(action, frozenset()):
        if key in cleaned:
            cleaned.pop(key, None)
            redacted.append(key)

    if action == "saip.ssim_eaptls_inspect":
        kind = str(cleaned.get("kind") or "").lower()
        if kind.startswith("private_key") and "der_hex" in cleaned:
            cleaned.pop("der_hex", None)
            redacted.append("der_hex")

    if redacted:
        cleaned["secret_outputs_redacted"] = sorted(redacted)
    return cleaned


__all__ = ["scrub_action_result"]
