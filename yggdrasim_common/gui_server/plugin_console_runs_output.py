# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""What a run console answers, cut to closed shapes before the browser sees it.

Run and result states come from fixed vocabularies (anything else reads
``unknown``), so the view can colour them through the status tokens without
trusting a plugin's words. Every text is clipped, lists are capped and a
report's detail texts share one budget. A credential answer keeps only
``stored``, ``usable``, a summary line and the declared non-secret field
values; a named credential keeps a summary line and its entries, each a
well-formed name (once), ``usable``, a summary line and those values. A
stored secret cannot reach the page even when a provider returns it.
"""
from __future__ import annotations

from typing import Any

from .plugin_console_runform import ENTRY_NAME, MAX_CREDENTIAL_ENTRIES

RUN_STATES = ("queued", "running", "passed", "failed", "error", "cancelled", "unknown")
RESULT_STATES = ("pending", "running", "passed", "failed", "error", "skipped", "unknown")
FINISHED_STATES = ("passed", "failed", "error", "cancelled")
EVENT_LEVELS = ("info", "ok", "warn", "error")

MAX_RUN_LIST = 200
MAX_META = 16
MAX_RESULTS = 64
MAX_CHECKS = 64
MAX_DETAILS = 16
MAX_DETAIL_TEXT = 16384
MAX_REPORT_DETAIL_BUDGET = 524288
MAX_EVENTS = 500
MAX_LINE = 1024
DETAIL_CUT = "[cut at the report size cap]"


def _line(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= limit else text[:limit]


def _state(value: Any, allowed: tuple[str, ...]) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    return text if text in allowed else "unknown"


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def run_summary(raw: Any) -> dict[str, Any]:
    """One run as the history lists it."""
    source = _dict(raw)
    return {
        "id": _line(source.get("id"), 64),
        "status": _state(source.get("status"), RUN_STATES),
        "title": _line(source.get("title"), 240),
        "summary": _line(source.get("summary"), 480),
        "time": _line(source.get("time"), 64),
    }


def run_list(raw: Any, limit: int) -> dict[str, Any]:
    """The newest runs first, at most *limit* of them."""
    rows = _list(_dict(raw).get("runs") if isinstance(raw, dict) else raw)
    return {"runs": [run_summary(row) for row in rows if isinstance(row, dict)][: max(1, min(int(limit), MAX_RUN_LIST))]}


def _details(raw: Any, budget: list[int]) -> list[dict[str, str]]:
    details: list[dict[str, str]] = []
    for item in _list(raw)[:MAX_DETAILS]:
        source = _dict(item)
        text = _line(source.get("text"), MAX_DETAIL_TEXT)
        if len(text) > budget[0]:
            text = DETAIL_CUT
        budget[0] -= len(text)
        details.append({"summary": _line(source.get("summary"), 240), "text": text})
    return details


def _result(raw: Any, budget: list[int]) -> dict[str, Any]:
    source = _dict(raw)
    return {
        "label": _line(source.get("label"), 120),
        "status": _state(source.get("status"), RESULT_STATES),
        "note": _line(source.get("note"), MAX_LINE),
        "checks": [{"ok": _dict(check).get("ok") is True, "text": _line(_dict(check).get("text"), MAX_LINE)} for check in _list(source.get("checks"))[:MAX_CHECKS]],
        "details": _details(source.get("details"), budget),
    }


def run_report(raw: Any) -> dict[str, Any]:
    """One run in full: state, a title line, meta lines and a result per item."""
    source = _dict(raw)
    status = _state(source.get("status"), RUN_STATES)
    budget = [MAX_REPORT_DETAIL_BUDGET]
    return {
        "id": _line(source.get("id"), 64),
        "status": status,
        "finished": status in FINISHED_STATES,
        "title": _line(source.get("title"), 240),
        "meta": [_line(item, 480) for item in _list(source.get("meta"))[:MAX_META]],
        "error": _line(source.get("error"), MAX_LINE),
        "results": [_result(item, budget) for item in _list(source.get("results"))[:MAX_RESULTS]],
    }


def run_events(raw: Any, after: int) -> dict[str, Any]:
    """The events after *after*; the newest are kept on overflow."""
    source = _dict(raw)
    rows = [row for row in _list(source.get("entries")) if isinstance(row, dict)]
    following = source.get("next")
    cursor = following if isinstance(following, int) and not isinstance(following, bool) and following >= 0 else after
    entries = [
        {
            "time": _line(row.get("time"), 64),
            "level": row.get("level") if row.get("level") in EVENT_LEVELS else "info",
            "text": _line(row.get("text"), MAX_LINE),
        }
        for row in rows[-MAX_EVENTS:]
    ]
    return {"entries": entries, "next": cursor, "finished": source.get("finished") is True, "truncated": len(rows) > MAX_EVENTS}


def _plain_values(declared: dict[str, Any], raw: Any) -> dict[str, str]:
    given = _dict(raw)
    return {
        field["name"]: _line(given[field["name"]], field["max_length"])
        for field in declared["fields"]
        if not field["secret"] and isinstance(given.get(field["name"]), str)
    }


def _named_entries(declared: dict[str, Any], raw: Any) -> list[dict[str, Any]]:
    """A named credential's entries: a name that is malformed or seen before (in any case) is dropped."""
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in _list(raw):
        source = _dict(row)
        name = source.get("name")
        if not isinstance(name, str) or ENTRY_NAME.fullmatch(name) is None or name.lower() in seen:
            continue
        seen.add(name.lower())
        entries.append({"name": name, "usable": source.get("usable") is True, "summary": _line(source.get("summary"), 480), "values": _plain_values(declared, source.get("values"))})
        if len(entries) == MAX_CREDENTIAL_ENTRIES:
            break
    return entries


def credential_entry(declared: dict[str, Any], raw: Any) -> dict[str, Any]:
    """A stored credential's status: never a secret field's value."""
    source = _dict(raw)
    if declared["named"]:
        entries = _named_entries(declared, source.get("entries"))
        return {"stored": len(entries) > 0, "usable": any(entry["usable"] for entry in entries), "summary": _line(source.get("summary"), 480), "entries": entries}
    stored = source.get("stored") is True
    return {"stored": stored, "usable": stored and source.get("usable") is True, "summary": _line(source.get("summary"), 480), "values": _plain_values(declared, source.get("values"))}


def credentials_payload(runs: dict[str, Any], raw: Any) -> dict[str, Any]:
    """Every declared credential's status, keyed by id; an undeclared answer is dropped."""
    source = _dict(raw)
    return {"credentials": {item["id"]: credential_entry(item, source.get(item["id"])) for item in runs["credentials"]}}
