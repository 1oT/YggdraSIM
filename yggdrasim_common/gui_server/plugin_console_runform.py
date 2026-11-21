# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The run form a plugin console may declare: variants of selectable items and their fields.

A console with a ``runs`` section starts runs instead of (or beside) a
session: the operator picks a variant, ticks items, fills the fields the
ticked items use and the view posts one structured request. Fields are
declared once per variant; an item names the fields it uses, a field no item
names is always in use, and a field used by several items belongs to a group
the view shows once. ``visible_when`` hides a field until an earlier field
holds a value, ``auto_when`` selects an item from an always-used field, and
``credentials`` are the stored secrets (API keys) the view offers to store
in a tab of their own, with a status line and the pick beside the form. A
``named`` credential keeps several entries on the plugin's side, each under
a name the operator gives it, and a run uses the entry the operator picks.
A credential may rename its Store / Forget / Replace buttons (a sign-in
whose secret is used once and never kept reads "Sign in" / "Sign out"). A
choice field with ``options_from`` takes its options from the console's
status answer instead of the manifest (the profiles on a card, the eIMs of a
tenant), so the operator picks a name and the plugin receives the value
behind it. ``accepts_while_running`` lets the form start a run while one is
in progress (a queue the console adds to). Everything is checked against
this closed shape, like the rest of the manifest; labels default to generic
wording so the core names no plugin's vocabulary.
"""
from __future__ import annotations

import math
import re
from typing import Any

from .plugin_console_manifest import (
    CONSOLE_ID,
    FIELD_NAME,
    MAX_HINT,
    MAX_LABEL,
    MAX_SUMMARY,
    ConsoleManifestError,
    _entries,
    _fail,
    _flag,
    _identifier,
    _mapping,
    _text,
    _unique,
    validate_field,
)

MAX_VARIANTS = 8
MAX_COMMON_FIELDS = 8
MAX_RUN_FIELDS = 128
MAX_ITEMS = 64
MAX_ITEM_FIELDS = 48
MAX_GROUPS = 16
MAX_CREDENTIALS = 8
MAX_CREDENTIAL_FIELDS = 8
MAX_CREDENTIAL_ENTRIES = 32
MAX_ITEM_SUMMARY = 480
MAX_BADGE = 40
MAX_CONDITION_TEXT = 256
GROUP_PLACES = ("before_items", "after_items")
# The name of one entry of a named credential: one word, so a shell line or a
# URL query carries it without quoting.
ENTRY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")

LABEL_DEFAULTS: dict[str, str] = {
    "form": "New run",
    "variant": "Variant",
    "items": "Items",
    "credentials": "Credentials",
    "start": "Run",
    "cancel": "Cancel",
    "current": "Current run",
    "history": "History",
    "empty_history": "No runs yet.",
}

_RUNS_KEYS = frozenset({"labels", "fields", "groups", "credentials", "variants", "accepts_while_running"})
_GROUP_KEYS = frozenset({"id", "label", "place"})
_CREDENTIAL_KEYS = frozenset({"id", "label", "hint", "named", "fields", "labels"})
CREDENTIAL_LABEL_DEFAULTS: dict[str, str] = {"store": "Store", "forget": "Forget", "replace": "Replace"}
MAX_CREDENTIAL_BUTTON = 24
_VARIANT_KEYS = frozenset({"id", "label", "summary", "available", "unavailable_reason", "credentials", "fields", "items"})
_ITEM_KEYS = frozenset({"id", "label", "summary", "badge", "available", "unavailable_reason", "fields", "credentials", "auto_when"})
_CONDITION_KEYS = frozenset({"field", "equals"})
_RUN_FIELD_EXTRA = frozenset({"group", "visible_when", "secret", "options_from"})


def _condition(raw: Any, where: str, earlier: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """``{field, equals}`` on a field declared earlier, with a value of that field's type."""
    if raw is None:
        return None
    entry = _mapping(raw, where, _CONDITION_KEYS, _CONDITION_KEYS)
    name = _identifier(entry["field"], f"{where}.field", FIELD_NAME)
    controller = earlier.get(name)
    if controller is None:
        raise _fail(f"{where}.field", f"{name!r} is not a field declared before this one")
    if controller["secret"]:
        raise _fail(f"{where}.field", "a secret field cannot control another")
    if controller.get("options_from"):
        raise _fail(f"{where}.field", "a choice the console fills cannot control another field")
    wanted = entry["equals"]
    kind = controller["type"]
    if kind == "boolean":
        if not isinstance(wanted, bool):
            raise _fail(f"{where}.equals", "true or false for a boolean field")
    elif kind == "number":
        if isinstance(wanted, bool) or not isinstance(wanted, (int, float)) or not math.isfinite(wanted):
            raise _fail(f"{where}.equals", "a finite number for a number field")
    elif kind == "choice":
        if wanted not in [option["value"] for option in controller["options"]]:
            raise _fail(f"{where}.equals", "one of the controlling field's option values")
    else:
        _text(wanted, f"{where}.equals", MAX_CONDITION_TEXT, empty=True)
    return {"field": name, "equals": wanted}


def _run_field(raw: Any, where: str, groups: set[str], earlier: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """A form field plus the run-form keys: ``group``, ``visible_when``, ``secret`` and ``options_from``."""
    if not isinstance(raw, dict):
        raise _fail(where, "must be an object")
    source = raw.get("options_from")
    plain = {key: value for key, value in raw.items() if key not in _RUN_FIELD_EXTRA}
    if source is not None:
        # The options come with the console's status answer, so the manifest
        # declares none and a value is checked against the list current at the start.
        if plain.get("type") != "choice":
            raise _fail(f"{where}.options_from", "only a choice field takes its options from the console")
        if "options" in plain or "default" in plain:
            raise _fail(f"{where}.options_from", "a choice the console fills declares no options and no default")
        plain["options"] = [{"value": "", "label": "-"}]
    field = validate_field(plain, where)
    field["options_from"] = ""
    if source is not None:
        field["options"] = []
        field["default"] = ""
        field["options_from"] = _identifier(source, f"{where}.options_from", FIELD_NAME)
    group = _text(raw.get("group", ""), f"{where}.group", 32, empty=True)
    if group and group not in groups:
        raise _fail(f"{where}.group", f"no group {group!r} is declared here")
    secret = _flag(raw.get("secret", False), f"{where}.secret")
    if secret and field["type"] != "text":
        raise _fail(f"{where}.secret", "only a text field can be secret")
    if secret and field["default"]:
        raise _fail(f"{where}.default", "a secret field carries no default")
    field["group"] = group
    field["secret"] = secret
    field["visible_when"] = _condition(raw.get("visible_when"), f"{where}.visible_when", earlier)
    return field


def _run_fields(value: Any, where: str, limit: int, groups: set[str], earlier: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Fields in declaration order; a condition may only look back, so none can loop."""
    known = dict(earlier)
    fields: list[dict[str, Any]] = []
    for index, item in enumerate(_entries(value, where, limit)):
        field = _run_field(item, f"{where}[{index}]", groups, known)
        if field["name"] in known:
            raise _fail(f"{where}[{index}].name", f"{field['name']!r} is declared twice")
        known[field["name"]] = field
        fields.append(field)
    return fields


def _labels(raw: Any, where: str) -> dict[str, str]:
    entry = _mapping({} if raw is None else raw, where, frozenset(LABEL_DEFAULTS), frozenset())
    return {key: _text(entry.get(key, default), f"{where}.{key}", MAX_LABEL) for key, default in LABEL_DEFAULTS.items()}


def _groups(raw: Any, where: str) -> list[dict[str, str]]:
    groups: list[dict[str, str]] = []
    for index, item in enumerate(_entries([] if raw is None else raw, where, MAX_GROUPS)):
        spot = f"{where}[{index}]"
        entry = _mapping(item, spot, _GROUP_KEYS, frozenset({"id", "label"}))
        place = entry.get("place", "after_items")
        if place not in GROUP_PLACES:
            raise _fail(f"{spot}.place", "one of " + ", ".join(GROUP_PLACES))
        groups.append({"id": _identifier(entry["id"], f"{spot}.id", FIELD_NAME), "label": _text(entry["label"], f"{spot}.label", MAX_LABEL), "place": place})
    _unique([group["id"] for group in groups], where)
    return groups


def _credentials(raw: Any, where: str) -> list[dict[str, Any]]:
    credentials: list[dict[str, Any]] = []
    for index, item in enumerate(_entries([] if raw is None else raw, where, MAX_CREDENTIALS)):
        spot = f"{where}[{index}]"
        entry = _mapping(item, spot, _CREDENTIAL_KEYS, frozenset({"id", "label", "fields"}))
        fields = _run_fields(entry["fields"], f"{spot}.fields", MAX_CREDENTIAL_FIELDS, set(), {})
        for field in fields:
            if field["type"] != "text" or field["visible_when"] is not None:
                raise _fail(f"{spot}.fields", "a credential takes plain text fields only")
        if not any(field["secret"] for field in fields):
            raise _fail(f"{spot}.fields", "a credential needs at least one secret field")
        buttons = _mapping({} if entry.get("labels") is None else entry["labels"], f"{spot}.labels", frozenset(CREDENTIAL_LABEL_DEFAULTS), frozenset())
        credentials.append(
            {
                "id": _identifier(entry["id"], f"{spot}.id", FIELD_NAME),
                "label": _text(entry["label"], f"{spot}.label", MAX_LABEL),
                "hint": _text(entry.get("hint", ""), f"{spot}.hint", MAX_HINT, empty=True),
                "named": _flag(entry.get("named", False), f"{spot}.named"),
                "fields": fields,
                "labels": {key: _text(buttons.get(key, default), f"{spot}.labels.{key}", MAX_CREDENTIAL_BUTTON) for key, default in CREDENTIAL_LABEL_DEFAULTS.items()},
            }
        )
    _unique([credential["id"] for credential in credentials], where)
    return credentials


def _references(value: Any, where: str, known: set[str], what: str, limit: int) -> list[str]:
    names: list[str] = []
    for index, item in enumerate(_entries([] if value is None else value, where, limit)):
        name = _identifier(item, f"{where}[{index}]", FIELD_NAME)
        if name not in known:
            raise _fail(f"{where}[{index}]", f"no {what} {name!r}")
        names.append(name)
    _unique(names, where)
    return names


def _item(raw: Any, where: str, field_names: set[str], credential_ids: set[str]) -> dict[str, Any]:
    entry = _mapping(raw, where, _ITEM_KEYS, frozenset({"id", "label"}))
    return {
        "id": _identifier(entry["id"], f"{where}.id", CONSOLE_ID),
        "label": _text(entry["label"], f"{where}.label", MAX_LABEL),
        "summary": _text(entry.get("summary", ""), f"{where}.summary", MAX_ITEM_SUMMARY, empty=True),
        "badge": _text(entry.get("badge", ""), f"{where}.badge", MAX_BADGE, empty=True),
        "available": _flag(entry.get("available", True), f"{where}.available"),
        "unavailable_reason": _text(entry.get("unavailable_reason", ""), f"{where}.unavailable_reason", MAX_HINT, empty=True),
        "fields": _references(entry.get("fields"), f"{where}.fields", field_names, "field", MAX_ITEM_FIELDS),
        "credentials": _references(entry.get("credentials"), f"{where}.credentials", credential_ids, "credential", MAX_CREDENTIALS),
        # Checked once every item is read: the controller has to be a field no item names.
        "auto_when": entry.get("auto_when"),
    }


def _check_usage(variant: dict[str, Any], common: dict[str, dict[str, Any]], where: str) -> None:
    """A field used by several items needs a group, and a condition never outlives its controller."""
    users: dict[str, set[str]] = {}
    for item in variant["items"]:
        for name in item["fields"]:
            users.setdefault(name, set()).add(item["id"])
    always = set(common) | {field["name"] for field in variant["fields"] if field["name"] not in users}
    by_name = {**common, **{field["name"]: field for field in variant["fields"]}}
    for field in variant["fields"]:
        name = field["name"]
        if len(users.get(name, ())) > 1 and not field["group"]:
            raise _fail(f"{where}: field {name!r}", "used by several items, so it needs a group")
        condition = field["visible_when"]
        if condition is None or condition["field"] in always:
            continue
        # The controller must be in use whenever the field is: named by every item that names the field.
        if name in always or not users[name] <= users.get(condition["field"], set()):
            raise _fail(f"{where}: field {name!r}", f"its controller {condition['field']!r} is not in use whenever it is")
    for item in variant["items"]:
        if item["auto_when"] is None:
            continue
        spot = f"{where}: item {item['id']!r}.auto_when"
        condition = _condition(item["auto_when"], spot, by_name)
        if condition is None or condition["field"] not in always:
            raise _fail(spot, "the controlling field must be one no item names")
        item["auto_when"] = condition


def _variant(raw: Any, where: str, groups: set[str], credential_ids: set[str], common: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entry = _mapping(raw, where, _VARIANT_KEYS, frozenset({"id", "label", "fields", "items"}))
    variant_id = _identifier(entry["id"], f"{where}.id", CONSOLE_ID)
    spot = f"{where} {variant_id!r}"
    fields = _run_fields(entry["fields"], f"{spot}.fields", MAX_RUN_FIELDS, groups, common)
    names = {field["name"] for field in fields}
    items = [_item(item, f"{spot}.items[{index}]", names, credential_ids) for index, item in enumerate(_entries(entry["items"], f"{spot}.items", MAX_ITEMS))]
    if len(items) == 0:
        raise _fail(f"{spot}.items", "a variant needs at least one item")
    _unique([item["id"] for item in items], f"{spot}.items")
    shown = _references(entry.get("credentials"), f"{spot}.credentials", credential_ids, "credential", MAX_CREDENTIALS)
    for item in items:
        missing = [name for name in item["credentials"] if name not in shown]
        if missing:
            raise _fail(f"{spot}: item {item['id']!r}", "needs credential(s) the variant does not offer: " + ", ".join(missing))
    variant = {
        "id": variant_id,
        "label": _text(entry["label"], f"{spot}.label", MAX_LABEL),
        "summary": _text(entry.get("summary", ""), f"{spot}.summary", MAX_SUMMARY, empty=True),
        "available": _flag(entry.get("available", True), f"{spot}.available"),
        "unavailable_reason": _text(entry.get("unavailable_reason", ""), f"{spot}.unavailable_reason", MAX_HINT, empty=True),
        "credentials": shown,
        "fields": fields,
        "items": items,
    }
    _check_usage(variant, common, spot)
    return variant


def validate_runs(raw: Any, where: str) -> dict[str, Any]:
    """The checked copy of a ``runs`` section, or ``ConsoleManifestError``."""
    entry = _mapping(raw, where, _RUNS_KEYS, frozenset({"variants"}))
    groups = _groups(entry.get("groups"), f"{where}.groups")
    group_ids = {group["id"] for group in groups}
    common_fields = _run_fields(entry.get("fields", []), f"{where}.fields", MAX_COMMON_FIELDS, set(), {})
    common = {field["name"]: field for field in common_fields}
    credentials = _credentials(entry.get("credentials"), f"{where}.credentials")
    credential_ids = {credential["id"] for credential in credentials}
    variants = [_variant(item, f"{where}.variants[{index}]", group_ids, credential_ids, common) for index, item in enumerate(_entries(entry["variants"], f"{where}.variants", MAX_VARIANTS))]
    if len(variants) == 0:
        raise _fail(f"{where}.variants", "a run form needs at least one variant")
    _unique([variant["id"] for variant in variants], f"{where}.variants")
    return {
        "labels": _labels(entry.get("labels"), f"{where}.labels"),
        "fields": common_fields,
        "groups": groups,
        "credentials": credentials,
        "variants": variants,
        # A start while a run is in progress is accepted: the console adds it to the run (a queue).
        "accepts_while_running": _flag(entry.get("accepts_while_running", False), f"{where}.accepts_while_running"),
    }


__all__ = ["CREDENTIAL_LABEL_DEFAULTS", "ConsoleManifestError", "ENTRY_NAME", "LABEL_DEFAULTS", "MAX_CREDENTIAL_ENTRIES", "validate_runs"]
