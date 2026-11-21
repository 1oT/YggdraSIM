# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""What a plugin console answers, reduced to plain values before it reaches the browser.

A provider is asked for plain dicts, but nothing obliges it to return them:
every answer is copied into JSON types (bytes as upper-case hex, anything
else as its text) under depth, entry and length caps, a stream batch keeps
only the columns its manifest declared, a comparison keeps one text cell
per declared side, and a pill keeps one line of text and a tone. The view renders these values as text, never as markup,
so the caps bound what one poll can cost.
"""
from __future__ import annotations

import math
from typing import Any

from .plugin_console_manifest import MAX_LABEL, MAX_OPTION_VALUE

MAX_DEPTH = 6
# Options a console hands a run field that declares ``options_from``, per source.
MAX_CHOICES = 64
MAX_ITEMS = 256
MAX_KEY = 128
MAX_TEXT = 4096
MAX_OUTPUT = 65536
MAX_STREAM_ENTRIES = 500
MAX_HELP_GROUPS = 64
MAX_HELP_COMMANDS = 400
MAX_COMPARE_SECTIONS = 24
MAX_COMPARE_ROWS = 256
MAX_COMPARE_LABEL = 256
MAX_COMPARE_CELL = 2048
# What a comparison row says about its cells; anything else reads "info".
COMPARE_VERDICTS = ("same", "differs", "missing", "info")
MAX_PILL_VALUE = 48
# The tone of a top bar pill; anything else reads "idle".
PILL_STATES = ("ok", "warn", "error", "busy", "idle")
# Integers past 2**53 lose digits in a browser; they travel as text.
_SAFE_INTEGER = 2**53


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def _items(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def plain(value: Any, depth: int = 0) -> Any:
    """*value* as JSON types: bounded depth, entry count and text length."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) < _SAFE_INTEGER else str(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _clip(value, MAX_TEXT)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _clip(bytes(value).hex().upper(), MAX_TEXT)
    if depth >= MAX_DEPTH:
        return _clip(str(value), MAX_TEXT)
    if isinstance(value, dict):
        return {_clip(str(key), MAX_KEY): plain(item, depth + 1) for key, item in list(value.items())[:MAX_ITEMS]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(item, depth + 1) for item in list(value)[:MAX_ITEMS]]
    return _clip(str(value), MAX_TEXT)


def status_payload(raw: Any, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """A status answer; ``running`` is always a boolean, ``last_error`` always text.

    ``compare`` is kept only for a console whose manifest declares the panel,
    and is cut by ``compare_payload``; ``plain`` would stop at its depth cap
    and hand the view a repr instead of the cells.
    """
    source = raw if isinstance(raw, dict) else {}
    payload = plain({key: value for key, value in source.items() if key != "compare"})
    payload["running"] = payload.get("running") is True
    error = payload.get("last_error")
    payload["last_error"] = error if isinstance(error, str) else ""
    if "active_run" in payload and not isinstance(payload["active_run"], str):
        payload["active_run"] = ""
    compare = manifest.get("compare") if isinstance(manifest, dict) else None
    if compare is not None and "compare" in source:
        payload["compare"] = compare_payload(compare, source["compare"])
    runs = manifest.get("runs") if isinstance(manifest, dict) else None
    payload.pop("choices", None)
    if runs is not None and dynamic_sources(runs) and "choices" in source:
        payload["choices"] = choices_payload(runs, source["choices"])
    return payload


def dynamic_sources(runs: dict[str, Any]) -> list[str]:
    """The ``options_from`` sources the run form's fields name, in declaration order."""
    names: list[str] = []
    fields = list(runs["fields"]) + [field for variant in runs["variants"] for field in variant["fields"]]
    for field in fields:
        source = field.get("options_from") or ""
        if source and source not in names:
            names.append(source)
    return names


def choices_payload(runs: dict[str, Any], raw: Any) -> dict[str, list[dict[str, str]]]:
    """The console's current options per declared source: text value and label, at most
    ``MAX_CHOICES`` each, an empty or repeated value dropped, an unnamed source dropped."""
    given = raw if isinstance(raw, dict) else {}
    payload: dict[str, list[dict[str, str]]] = {}
    for name in dynamic_sources(runs):
        options: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in _items(given.get(name)):
            if not isinstance(item, dict):
                continue
            value = _clip(_cell("text", item.get("value")), MAX_OPTION_VALUE)
            if value == "" or value in seen:
                continue
            seen.add(value)
            options.append({"value": value, "label": _clip(_cell("text", item.get("label")), MAX_LABEL) or value})
            if len(options) == MAX_CHOICES:
                break
        payload[name] = options
    return payload


def compare_payload(compare: dict[str, Any], raw: Any) -> dict[str, Any]:
    """Sections of rows, one text cell per declared side and a verdict from ``COMPARE_VERDICTS``.

    A cell for a side the manifest does not declare is dropped and a missing
    one reads empty, so every row has exactly the declared columns.
    """
    source = raw if isinstance(raw, dict) else {}
    side_ids = [side["id"] for side in compare["sides"]]
    sections: list[dict[str, Any]] = []
    for section in _items(source.get("sections"))[:MAX_COMPARE_SECTIONS]:
        if not isinstance(section, dict):
            continue
        rows: list[dict[str, Any]] = []
        for row in _items(section.get("rows"))[:MAX_COMPARE_ROWS]:
            if not isinstance(row, dict):
                continue
            cells = row.get("cells") if isinstance(row.get("cells"), dict) else {}
            verdict = row.get("verdict")
            rows.append(
                {
                    "label": _clip(_cell("text", row.get("label")), MAX_COMPARE_LABEL),
                    "cells": {side: _clip(_cell("text", cells.get(side)), MAX_COMPARE_CELL) for side in side_ids},
                    "verdict": verdict if isinstance(verdict, str) and verdict in COMPARE_VERDICTS else "info",
                }
            )
        sections.append({"title": _clip(_cell("text", section.get("title")), MAX_COMPARE_LABEL), "rows": rows})
    return {"sections": sections, "note": _clip(_cell("text", source.get("note")), MAX_TEXT)}


def _cursor(value: Any, fallback: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return fallback
    return value


def _cell(shape: str, value: Any) -> Any:
    if shape == "time":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return None
        return float(value)
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _clip(bytes(value).hex().upper(), MAX_TEXT)
    return _clip(str(value), MAX_TEXT)


def stream_batch(stream: dict[str, Any], raw: Any, after: int) -> dict[str, Any]:
    """The entries after *after*, each cut to the declared columns; the newest are kept on overflow."""
    source = raw if isinstance(raw, dict) else {}
    entries = [entry for entry in _items(source.get("entries")) if isinstance(entry, dict)]
    truncated = len(entries) > MAX_STREAM_ENTRIES
    rows = [
        {column["key"]: _cell(column["format"], entry.get(column["key"])) for column in stream["columns"]}
        for entry in entries[-MAX_STREAM_ENTRIES:]
    ]
    return {"entries": rows, "next": _cursor(source.get("next"), after), "truncated": truncated}


def help_payload(raw: Any) -> dict[str, Any]:
    """Command help as groups of name / usage / summary / aliases, plus an optional free text."""
    source = raw if isinstance(raw, dict) else {}
    groups: list[dict[str, Any]] = []
    budget = MAX_HELP_COMMANDS
    for group in _items(source.get("groups"))[:MAX_HELP_GROUPS]:
        if not isinstance(group, dict):
            continue
        commands: list[dict[str, Any]] = []
        for item in _items(group.get("commands")):
            if budget <= 0:
                break
            if not isinstance(item, dict):
                continue
            commands.append(
                {
                    "name": _clip(str(item.get("name") or ""), 64),
                    "usage": _clip(str(item.get("usage") or ""), 1024),
                    "summary": _clip(str(item.get("summary") or ""), 1024),
                    "aliases": [_clip(str(alias), 64) for alias in _items(item.get("aliases"))[:16]],
                }
            )
            budget -= 1
        groups.append({"group": _clip(str(group.get("group") or ""), 64), "commands": commands})
    text = source.get("text")
    return {"groups": groups, "text": _clip(text, MAX_OUTPUT) if isinstance(text, str) else ""}


def fill_payload(field: dict[str, Any], raw: Any) -> dict[str, Any]:
    """A start field's value, cut to the field's own length, and an optional note for the form."""
    source = raw if isinstance(raw, dict) else {}
    value = _cell("text", source.get("value"))
    return {"value": _clip(value, int(field.get("max_length") or MAX_TEXT)), "note": _clip(_cell("text", source.get("note")), MAX_TEXT)}


def pills_payload(manifest: dict[str, Any], raw: Any) -> list[dict[str, str]]:
    """The declared pills that carry a value, in manifest order, each one line of text.

    A pill the answer leaves out, or gives an empty value, is not shown: a
    stopped console takes no room in the top bar.
    """
    source = raw if isinstance(raw, dict) else {}
    pills: list[dict[str, str]] = []
    for pill in manifest["pills"]:
        entry = source.get(pill["id"])
        if not isinstance(entry, dict):
            continue
        value = _clip(" ".join(_cell("text", entry.get("value")).split()), MAX_PILL_VALUE)
        if not value:
            continue
        state = entry.get("state")
        pills.append(
            {
                "console": manifest["id"],
                "title": manifest["title"],
                "id": pill["id"],
                "label": pill["label"],
                "value": value,
                "state": state if isinstance(state, str) and state in PILL_STATES else "idle",
            }
        )
    return pills


def command_payload(line: str, raw: Any) -> dict[str, Any]:
    """The line that ran and the text it answered, cut at ``MAX_OUTPUT`` characters."""
    output = raw.get("output") if isinstance(raw, dict) else raw
    text = "" if output is None else str(output)
    return {"line": line, "output": _clip(text, MAX_OUTPUT), "truncated": len(text) > MAX_OUTPUT}
