# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Which items a run request selects and which of its fields the plugin receives.

A field is in use when no item names it or a selected item does; it is
visible when it is in use and, if it has a ``visible_when``, its controller
is visible and holds the wanted value. Only visible fields are checked and
passed on, so a hidden or unused value never reaches the plugin, however the
browser filled it. An item with ``auto_when`` is selected by the value of an
always-used field, never by a tick. ``plan_run`` is mirrored by
``pcRunPlan`` in ``plugin-console-runform.js``; the tests run both on the
same cases. The entry picked for a needed named credential is not a field:
``select_run`` checks its shape and carries it in ``credential_entries``, and
the route checks that it is stored and usable.
"""
from __future__ import annotations

from typing import Any

from .plugin_console_runform import MAX_ITEMS
from .plugin_console_values import ConsoleInputError, check_entry_name, check_value


def find_variant(runs: dict[str, Any], variant_id: Any) -> dict[str, Any]:
    for variant in runs["variants"]:
        if variant["id"] == variant_id:
            return variant
    raise ConsoleInputError(f"no variant {variant_id!r}")


def run_fields(runs: dict[str, Any], variant: dict[str, Any]) -> list[dict[str, Any]]:
    """The common fields, then the variant's, in declaration order."""
    return list(runs["fields"]) + list(variant["fields"])


def always_used(runs: dict[str, Any], variant: dict[str, Any]) -> set[str]:
    named = {name for item in variant["items"] for name in item["fields"]}
    return {field["name"] for field in run_fields(runs, variant) if field["name"] not in named}


def _matches(value: Any, wanted: Any) -> bool:
    if isinstance(wanted, bool):
        return value is wanted
    if isinstance(wanted, (int, float)):
        return not isinstance(value, bool) and isinstance(value, (int, float)) and value == wanted
    return isinstance(value, str) and value == wanted


def _blank(field: dict[str, Any], value: Any) -> bool:
    if field["type"] in ("boolean", "choice"):
        return False
    return value is None or (isinstance(value, str) and len(value.strip()) == 0)


def field_options(field: dict[str, Any], choices: dict[str, Any] | None) -> list[dict[str, str]]:
    """The options a choice is checked against: the manifest's, or the console's current
    list for a field that declares ``options_from`` (empty until the console names one)."""
    source = field.get("options_from") or ""
    if not source:
        return list(field["options"])
    given = (choices or {}).get(source)
    return [option for option in given if isinstance(option, dict)] if isinstance(given, list) else []


def _evaluate(fields: list[dict[str, Any]], used: set[str], given: dict[str, Any], choices: dict[str, Any] | None = None) -> dict[str, Any]:
    """The visible fields in declaration order, their checked values, the blank required ones and every problem."""
    visible: list[str] = []
    values: dict[str, Any] = {}
    missing: list[str] = []
    problems: list[str] = []
    for field in fields:
        name = field["name"]
        if name not in used:
            continue
        condition = field["visible_when"]
        if condition is not None and (condition["field"] not in values or not _matches(values[condition["field"]], condition["equals"])):
            continue
        visible.append(name)
        raw = given.get(name, field["default"])
        if field.get("options_from"):
            # A choice the console fills: blank counts as missing, and the value has to be on the current list.
            if raw is None or raw == "":
                if field["required"]:
                    missing.append(name)
                    problems.append(f"{field['label']}: required")
                else:
                    values[name] = ""
                continue
            options = field_options(field, choices)
            if not isinstance(raw, str) or raw not in [option["value"] for option in options]:
                problems.append(f"{field['label']}: " + ("nothing to pick from yet" if not options else "not one of the current choices"))
                continue
            values[name] = raw
            continue
        if field["required"] and _blank(field, raw):
            missing.append(name)
        try:
            values[name] = check_value(field, raw)
        except ConsoleInputError as error:
            problems.append(str(error))
    return {"visible": visible, "values": values, "missing": missing, "problems": problems}


def _used_by(items: list[dict[str, Any]]) -> set[str]:
    return {name for item in items for name in item["fields"]}


def plan_run(runs: dict[str, Any], variant: dict[str, Any], ticked: list[str], given: dict[str, Any], choices: dict[str, Any] | None = None) -> dict[str, Any]:
    """The selection a variant, its ticked item ids and the operator's values amount to;
    ``choices`` are the console's current options for the fields it fills."""
    fields = run_fields(runs, variant)
    always = always_used(runs, variant)
    manual = [item for item in variant["items"] if item["id"] in ticked and item["auto_when"] is None]
    first = _evaluate(fields, always | _used_by(manual), given, choices)["values"]
    auto = [
        item
        for item in variant["items"]
        if item["auto_when"] is not None
        and item["auto_when"]["field"] in first
        and _matches(first[item["auto_when"]["field"]], item["auto_when"]["equals"])
    ]
    selected = [item for item in variant["items"] if item in manual or item in auto]
    final = _evaluate(fields, always | _used_by(selected), given, choices)
    wanted = {name for item in selected for name in item["credentials"]}
    return {
        "items": [item["id"] for item in manual],
        "auto_items": [item["id"] for item in auto],
        **final,
        "credentials": [credential["id"] for credential in runs["credentials"] if credential["id"] in wanted],
    }


def _ticked(variant: dict[str, Any], raw: Any) -> list[str]:
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS:
        raise ConsoleInputError(f"items must be a list of at most {MAX_ITEMS} item ids")
    by_id = {item["id"]: item for item in variant["items"]}
    ticked: list[str] = []
    for value in raw:
        item = by_id.get(value) if isinstance(value, str) else None
        if item is None:
            raise ConsoleInputError(f"no item {value!r} in {variant['label']}")
        if item["auto_when"] is not None:
            raise ConsoleInputError(f"{item['label']}: selected by itself, not by a tick")
        if value not in ticked:
            ticked.append(value)
    return ticked


def _refuse_unavailable(variant: dict[str, Any], selected: list[str]) -> None:
    if not variant["available"]:
        raise ConsoleInputError(f"{variant['label']}: {variant['unavailable_reason'] or 'cannot run'}")
    for item in variant["items"]:
        if item["id"] in selected and not item["available"]:
            raise ConsoleInputError(f"{item['label']}: {item['unavailable_reason'] or 'cannot run'}")


def _picks(runs: dict[str, Any], needed: list[str], raw: Any) -> dict[str, str]:
    """The entry names picked for needed named credentials; a pick for any other credential is refused."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConsoleInputError("credential_entries must be an object")
    declared = {credential["id"]: credential for credential in runs["credentials"]}
    picks: dict[str, str] = {}
    for credential_id, name in raw.items():
        credential = declared.get(credential_id)
        if credential is None or not credential["named"] or credential_id not in needed:
            raise ConsoleInputError(f"no entry can be picked for {str(credential_id)[:40]!r}: the selected items need no such named credential")
        picks[credential_id] = check_entry_name(name, credential["label"])
    return picks


def select_run(runs: dict[str, Any], payload: Any, choices: dict[str, Any] | None = None) -> dict[str, Any]:
    """The checked request a provider's ``run_start`` receives, or ``ConsoleInputError``;
    ``choices`` are the console's current options for the fields it fills."""
    if not isinstance(payload, dict):
        raise ConsoleInputError("a run request must be an object")
    variant = find_variant(runs, payload.get("variant"))
    ticked = _ticked(variant, payload.get("items", []))
    given = payload.get("values", {})
    if not isinstance(given, dict):
        raise ConsoleInputError("values must be an object")
    declared = {field["name"] for field in run_fields(runs, variant)}
    unknown = sorted(str(name) for name in given if name not in declared)
    if unknown:
        raise ConsoleInputError("no field named " + ", ".join(unknown))
    plan = plan_run(runs, variant, ticked, given, choices)
    if len(plan["items"]) == 0:
        raise ConsoleInputError(f"{runs['labels']['items']}: tick at least one")
    _refuse_unavailable(variant, plan["items"] + plan["auto_items"])
    if plan["problems"]:
        raise ConsoleInputError("; ".join(plan["problems"]))
    picks = _picks(runs, plan["credentials"], payload.get("credential_entries"))
    request = {
        "variant": variant["id"],
        "items": plan["items"],
        "auto_items": plan["auto_items"],
        "values": plan["values"],
        "credentials": plan["credentials"],
    }
    # Present only when a needed credential is named, so a run form without
    # one sends the plugin exactly what it did before named credentials.
    if any(credential["named"] and credential["id"] in plan["credentials"] for credential in runs["credentials"]):
        request["credential_entries"] = picks
    return request
