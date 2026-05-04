# -----------------------------------------------------------------------------
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

from __future__ import annotations

import copy
import difflib
from typing import Any, Tuple

import yaml


def strip_generated_fields(value: Any) -> Any:
    """
    Drop ``generated`` keys recursively so exports can be compared without
    timestamp noise.
    """
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, inner in value.items():
            if str(key) == "generated":
                continue
            out[key] = strip_generated_fields(inner)
        return out
    if isinstance(value, list):
        return [strip_generated_fields(item) for item in value]
    return value


def dump_sorted_yaml(data: dict[str, Any]) -> str:
    """Stable YAML text for byte-wise or line-wise comparison."""
    return yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=True,
        width=120,
    )


def combined_profile_unified_diff(
    gold: dict[str, Any],
    live: dict[str, Any],
    *,
    gold_label: str = "gold",
    live_label: str = "live",
) -> Tuple[bool, str]:
    """
    Compare two combined profile dicts (FS + euicc_report + mnosd_report).

    Returns (identical_after_normalization, unified_diff_or_message).
    """
    gold_n = strip_generated_fields(copy.deepcopy(gold))
    live_n = strip_generated_fields(copy.deepcopy(live))
    gold_text = dump_sorted_yaml(gold_n)
    live_text = dump_sorted_yaml(live_n)
    if gold_text == live_text:
        return True, ""
    diff_lines = difflib.unified_diff(
        gold_text.splitlines(),
        live_text.splitlines(),
        fromfile=gold_label,
        tofile=live_label,
        lineterm="",
    )
    return False, "\n".join(diff_lines)
