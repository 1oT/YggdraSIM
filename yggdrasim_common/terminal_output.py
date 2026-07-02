# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Terminal output helpers for role-coloured status and payload traces."""
from __future__ import annotations

import builtins
import os
import re
import sys
from typing import TextIO

from yggdrasim_common.nord_palette import NORD


_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_HEX_DUMP_RE = re.compile(r"^(\s*)([0-9A-Fa-f]{4,8}:)(\s+)([0-9A-Fa-f ]+)$")
_TRUE_VALUES = {"1", "true", "yes", "y", "on", "always", "force"}
_FALSE_VALUES = {"0", "false", "no", "n", "off", "never"}


def should_use_color(stream: TextIO | None = None) -> bool:
    if _env_disables_color("NO_COLOR"):
        return False
    if _env_disables_color("YGGDRASIM_NO_COLOR"):
        return False
    if _env_forces_color("YGGDRASIM_FORCE_COLOR"):
        return True
    if _env_forces_color("FORCE_COLOR"):
        return True
    if _env_forces_color("CLICOLOR_FORCE"):
        return True
    if _parse_bool_env("CLICOLOR", default=True) is False:
        return False
    term = str(os.environ.get("TERM", "") or "").strip().lower()
    if term == "dumb":
        return False
    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", None)
    return bool(callable(isatty) and isatty())


def colorize_status_text(text: str, stream: TextIO | None = None) -> str:
    value = str(text)
    if len(value) == 0:
        return value
    if should_use_color(stream) is False:
        return value
    if _ANSI_RE.search(value):
        return value
    role = classify_status_text(value)
    color = _role_color(role)
    if len(color) == 0:
        return value
    return f"{color}{value}{NORD.RESET}"


def colorize_hex_dump_line(text: str, stream: TextIO | None = None) -> str:
    value = str(text)
    if should_use_color(stream) is False:
        return value
    if _ANSI_RE.search(value):
        return value
    match = _HEX_DUMP_RE.match(value)
    if match is None:
        return colorize_status_text(value, stream=stream)
    indent, offset, gap, payload = match.groups()
    return (
        f"{indent}{NORD.GUIDE}{offset}{NORD.RESET}"
        f"{gap}{NORD.SURFACE}{payload}{NORD.RESET}"
    )


def status_print(
    *values: object,
    sep: str = " ",
    end: str = "\n",
    file: TextIO | None = None,
    flush: bool = False,
) -> None:
    target = file if file is not None else sys.stdout
    text = sep.join(str(value) for value in values)
    builtins.print(
        colorize_status_text(text, stream=target),
        sep="",
        end=end,
        file=target,
        flush=flush,
    )


def classify_status_text(text: str) -> str:
    value = _ANSI_RE.sub("", str(text or "")).strip()
    if len(value) == 0:
        return ""
    lowered = value.lower()
    if _is_error_text(value, lowered):
        return "error"
    if _is_warning_text(value, lowered):
        return "warning"
    if _is_success_text(value, lowered):
        return "success"
    if _is_data_text(value, lowered):
        return "data"
    if value.startswith("[*]") or lowered.startswith("phase:"):
        return "info"
    return ""


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "") or "").strip().lower()
    if len(raw) == 0:
        return bool(default)
    if raw in _TRUE_VALUES:
        return True
    if raw in _FALSE_VALUES:
        return False
    return bool(default)


def _env_disables_color(name: str) -> bool:
    raw = str(os.environ.get(name, "") or "").strip().lower()
    if len(raw) == 0:
        return False
    return raw not in _FALSE_VALUES


def _env_forces_color(name: str) -> bool:
    raw = str(os.environ.get(name, "") or "").strip().lower()
    if len(raw) == 0:
        return False
    return raw not in _FALSE_VALUES


def _role_color(role: str) -> str:
    if role == "success":
        return NORD.GREEN
    if role == "warning":
        return NORD.WARNING
    if role == "error":
        return NORD.FAIL
    if role == "info":
        return NORD.CYAN
    if role == "data":
        return NORD.SURFACE
    return ""


def _is_error_text(value: str, lowered: str) -> bool:
    if lowered in {"error", "failed", "failure", "fatal"}:
        return True
    if value.startswith("[-]") or value.startswith("[ERROR]") or value.startswith("[FAIL]"):
        return True
    if value.startswith("[!]") and "warning" not in lowered and "warn" not in lowered:
        return True
    error_tokens = (
        " failed",
        " failure",
        " error",
        " fatal",
        " exception",
        " rejected",
        " mismatch",
        " timed out",
        " unavailable",
        " aborted",
    )
    return any(token in lowered for token in error_tokens)


def _is_warning_text(value: str, lowered: str) -> bool:
    if lowered in {"warning", "warn"}:
        return True
    if value.startswith("[WARN]") or value.startswith("[WARNING]"):
        return True
    if value.startswith("[!]") and ("warning" in lowered or "warn" in lowered):
        return True
    warning_tokens = (
        " warning",
        " warn",
        " retrying",
        " fallback",
        " ignoring",
        " skipped",
        " no packages",
        "not available",
    )
    return any(token in lowered for token in warning_tokens)


def _is_success_text(value: str, lowered: str) -> bool:
    if lowered in {"ok", "pass", "passed", "success", "successful", "complete", "completed"}:
        return True
    if value.startswith("[+]") or value.startswith("[SUCCESS]") or value.startswith("[OK]"):
        return True
    success_tokens = (
        " success",
        " successful",
        " succeeded",
        " completed",
        " complete",
        " pass",
        " ok",
        " resolved",
        " persisted",
        " verified",
    )
    return any(token in lowered for token in success_tokens)


def _is_data_text(value: str, lowered: str) -> bool:
    if _HEX_DUMP_RE.match(value) is not None:
        return True
    return (
        " len=" in lowered
        or " bytes" in lowered
        or " hex=" in lowered
        or " first=" in lowered
        or "data:" in lowered
    )


__all__ = [
    "classify_status_text",
    "colorize_hex_dump_line",
    "colorize_status_text",
    "should_use_color",
    "status_print",
]
