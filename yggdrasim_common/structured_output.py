# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Structured output helpers: serialises arbitrary payloads to JSON or YAML for piped CLI consumers."""
from __future__ import annotations

import json
from typing import Any

import yaml


def dump_structured_payload(payload: Any, output_mode: str = "json") -> str:
    """Render a structured payload as JSON or YAML."""

    mode = str(output_mode or "json").strip().lower()
    if mode == "json":
        return json.dumps(payload, indent=2, sort_keys=False)
    if mode == "yaml":
        rendered = yaml.safe_dump(
            payload,
            sort_keys=False,
            allow_unicode=False,
            default_flow_style=False,
        )
        return rendered.rstrip()
    raise ValueError(f"Unsupported structured output mode: {output_mode}")
