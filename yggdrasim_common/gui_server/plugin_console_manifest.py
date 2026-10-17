# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Plugin console manifests: the closed shape a plugin declares for the GUI.

A manifest names one console and declares what the generic view may render
for it: a start form, action buttons with inline fields, an optional free
command line, the named streams the view tails, a comparison panel whose
sides the status answer fills, a title for the state the status reports
(which then gets a tab of its own), the top bar pills its ``pills()``
answer fills, and a run form
(``plugin_console_runform``). Every key is checked
against the shape below and a manifest with anything else is refused whole
(``ConsoleManifestError``), so a plugin cannot hand the browser markup,
styles, links or a field kind the view does not know. The validated copy
carries every optional key with its default, which is what the view reads.
"""
from __future__ import annotations

import math
import re
from typing import Any

CONSOLE_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
# One word that cannot read as an option: what an action may put into a line.
WORD = re.compile(r"[^\s-]\S*")
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# ``reader`` is a PC/SC or remote reader name the view offers from the live
# reader list; an empty value leaves the pick to the plugin.
FIELD_TYPES = ("text", "number", "boolean", "choice", "reader")
ACTION_FIELD_TYPES = ("text", "number", "choice")
MAX_READER_NAME = 256
# ``mono`` is text set in the mono font with its spacing kept: a captured terminal, an APDU trace.
COLUMN_FORMATS = ("text", "time", "hex", "mono")
# How much of a stream table a column takes: "narrow" and "medium" are fixed
# widths, "fill" columns share the rest. A time column is always narrow.
COLUMN_WIDTHS = ("narrow", "medium", "fill")

MAX_TITLE = 60
MAX_LABEL = 60
MAX_SUMMARY = 240
MAX_HINT = 240
MAX_TEMPLATE = 240
MAX_PATTERN = 200
MAX_OPTION_VALUE = 64
MAX_TEXT_LENGTH = 8192
DEFAULT_TEXT_LENGTH = 256
MAX_FIELDS = 16
MAX_ACTIONS = 48
MAX_OPTIONS = 32
MAX_STREAMS = 4
MAX_COLUMNS = 8
MIN_COMPARE_SIDES = 2
MAX_COMPARE_SIDES = 4
# Top bar pills: a few words each, beside the app's own status pills.
MAX_PILLS = 3
MAX_PILL_LABEL = 20

_MANIFEST_KEYS = frozenset({"id", "title", "summary", "start", "actions", "command_line", "streams", "compare", "state", "pills", "runs"})
_PILL_KEYS = frozenset({"id", "label"})
_STATE_KEYS = frozenset({"title"})
_COMPARE_KEYS = frozenset({"title", "hint", "sides"})
# A start field the plugin can fill from the other start values (an EID read from the card in the chosen reader).
_FILL_KEYS = frozenset({"label"})
_SIDE_KEYS = frozenset({"id", "label"})
_START_KEYS = frozenset({"label", "fields"})
_ACTION_KEYS = frozenset({"id", "label", "template", "fields", "group", "hint", "place"})
# Where an action's button renders: the Actions tab, or the toolbar of the
# comparison panel for an action that refreshes what the panel shows.
ACTION_PLACES = ("actions", "compare")
_COMMAND_LINE_KEYS = frozenset({"placeholder", "hint"})
_STREAM_KEYS = frozenset({"id", "title", "columns"})
_COLUMN_KEYS = frozenset({"key", "label", "format", "width"})
_OPTION_KEYS = frozenset({"value", "label"})
_FIELD_KEYS = frozenset({"name", "label", "type", "default", "required", "placeholder", "hint"})
_TYPE_KEYS = {
    "text": frozenset({"pattern", "max_length"}),
    "number": frozenset({"min", "max", "step"}),
    "boolean": frozenset(),
    "choice": frozenset({"options"}),
    "reader": frozenset(),
}
_ANY_TYPE_KEY = frozenset().union(*_TYPE_KEYS.values())


class ConsoleManifestError(ValueError):
    """A manifest outside the closed shape; the message names the offending key."""


def _fail(where: str, message: str) -> ConsoleManifestError:
    return ConsoleManifestError(f"{where}: {message}")


def _mapping(value: Any, where: str, allowed: frozenset[str], required: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(where, "must be an object")
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise _fail(where, "unknown key(s) " + ", ".join(unknown))
    missing = sorted(key for key in required if key not in value)
    if missing:
        raise _fail(where, "missing key(s) " + ", ".join(missing))
    return value


def _text(value: Any, where: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise _fail(where, "must be a string")
    if CONTROL.search(value) is not None:
        raise _fail(where, "must not contain control characters")
    if len(value) > limit:
        raise _fail(where, f"longer than {limit} characters")
    if not empty and len(value.strip()) == 0:
        raise _fail(where, "must not be empty")
    return value


def _identifier(value: Any, where: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail(where, f"must match {pattern.pattern}")
    return value


def _entries(value: Any, where: str, limit: int) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(where, "must be a list")
    if len(value) > limit:
        raise _fail(where, f"more than {limit} entries")
    return value


def _flag(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(where, "must be true or false")
    return value


def _number(value: Any, where: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise _fail(where, "must be a finite number")
    return value


def _unique(names: list[str], where: str) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise _fail(where, f"{name!r} is declared twice")
        seen.add(name)


def _options(value: Any, where: str) -> list[dict[str, str]]:
    options: list[dict[str, str]] = []
    for index, item in enumerate(_entries(value, where, MAX_OPTIONS)):
        spot = f"{where}[{index}]"
        entry = _mapping(item, spot, _OPTION_KEYS, _OPTION_KEYS)
        options.append(
            {
                "value": _text(entry["value"], f"{spot}.value", MAX_OPTION_VALUE, empty=True),
                "label": _text(entry["label"], f"{spot}.label", MAX_LABEL),
            }
        )
    if len(options) == 0:
        raise _fail(where, "a choice needs at least one option")
    _unique([option["value"] for option in options], where)
    return options


def _pattern(value: Any, where: str) -> str:
    text = _text(value, where, MAX_PATTERN, empty=True)
    try:
        re.compile(text)
    except re.error as error:
        raise _fail(where, f"not a regular expression ({error})") from error
    return text


def _typed_keys(entry: dict[str, Any], field: dict[str, Any], where: str) -> None:
    kind = field["type"]
    if kind == "text":
        field["pattern"] = _pattern(entry.get("pattern", ""), f"{where}.pattern")
        length = entry.get("max_length", DEFAULT_TEXT_LENGTH)
        if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= MAX_TEXT_LENGTH:
            raise _fail(f"{where}.max_length", f"an integer from 1 to {MAX_TEXT_LENGTH}")
        field["max_length"] = length
    elif kind == "number":
        for key in ("min", "max", "step"):
            field[key] = _number(entry.get(key), f"{where}.{key}")
        if field["min"] is not None and field["max"] is not None and field["min"] > field["max"]:
            raise _fail(where, "min is above max")
        if field["step"] is not None and field["step"] <= 0:
            raise _fail(f"{where}.step", "must be above zero")
    elif kind == "choice":
        field["options"] = _options(entry.get("options"), f"{where}.options")


def _default(entry: dict[str, Any], field: dict[str, Any], where: str) -> Any:
    kind = field["type"]
    spot = f"{where}.default"
    if kind == "boolean":
        return _flag(entry.get("default", False), spot)
    if kind == "number":
        value = _number(entry.get("default"), spot)
        low, high = field["min"], field["max"]
        if value is not None and ((low is not None and value < low) or (high is not None and value > high)):
            raise _fail(spot, "outside min / max")
        return value
    if kind == "choice":
        values = [option["value"] for option in field["options"]]
        value = entry.get("default", values[0])
        if value not in values:
            raise _fail(spot, "must be one of the option values")
        return value
    if kind == "reader":
        return _text(entry.get("default", ""), spot, MAX_READER_NAME, empty=True)
    value = _text(entry.get("default", ""), spot, field["max_length"], empty=True)
    if value and field["pattern"] and re.fullmatch(field["pattern"], value) is None:
        raise _fail(spot, "does not match the field's pattern")
    return value


def validate_field(raw: Any, where: str, types: tuple[str, ...] = FIELD_TYPES) -> dict[str, Any]:
    """One form field, checked against its type's keys; every optional key filled in."""
    entry = _mapping(raw, where, _FIELD_KEYS | _ANY_TYPE_KEY, frozenset({"name", "label", "type"}))
    name = _identifier(entry["name"], f"{where}.name", FIELD_NAME)
    kind = entry["type"]
    if kind not in types:
        raise _fail(f"{where}.type", "one of " + ", ".join(types))
    foreign = sorted(key for key in entry if key in _ANY_TYPE_KEY and key not in _TYPE_KEYS[kind])
    if foreign:
        raise _fail(where, f"{', '.join(foreign)} does not apply to a {kind} field")
    field: dict[str, Any] = {
        "name": name,
        "label": _text(entry["label"], f"{where}.label", MAX_LABEL),
        "type": kind,
        "required": _flag(entry.get("required", False), f"{where}.required"),
        "placeholder": _text(entry.get("placeholder", ""), f"{where}.placeholder", MAX_HINT, empty=True),
        "hint": _text(entry.get("hint", ""), f"{where}.hint", MAX_HINT, empty=True),
    }
    _typed_keys(entry, field, where)
    field["default"] = _default(entry, field, where)
    return field


def _fields(value: Any, where: str, types: tuple[str, ...]) -> list[dict[str, Any]]:
    fields = [validate_field(item, f"{where}[{index}]", types) for index, item in enumerate(_entries(value, where, MAX_FIELDS))]
    _unique([field["name"] for field in fields], where)
    return fields


def _start_fields(value: Any, where: str) -> list[dict[str, Any]]:
    """The start form's fields; a text field may carry ``fill: {label}``, a button beside it
    that asks the console's ``fill`` for its value. Every start field carries ``fill``."""
    fields: list[dict[str, Any]] = []
    for index, item in enumerate(_entries(value, where, MAX_FIELDS)):
        spot = f"{where}[{index}]"
        fill_raw = item.get("fill") if isinstance(item, dict) else None
        plain = {key: entry for key, entry in item.items() if key != "fill"} if isinstance(item, dict) else item
        field = validate_field(plain, spot, FIELD_TYPES)
        field["fill"] = None
        if fill_raw is not None:
            if field["type"] != "text":
                raise _fail(f"{spot}.fill", "only a text field can be filled")
            fill = _mapping(fill_raw, f"{spot}.fill", _FILL_KEYS, _FILL_KEYS)
            field["fill"] = {"label": _text(fill["label"], f"{spot}.fill.label", MAX_LABEL)}
        fields.append(field)
    _unique([field["name"] for field in fields], where)
    return fields


def _action(raw: Any, where: str) -> dict[str, Any]:
    entry = _mapping(raw, where, _ACTION_KEYS, frozenset({"id", "label", "template"}))
    action_id = _identifier(entry["id"], f"{where}.id", CONSOLE_ID)
    fields = _fields(entry.get("fields", []), f"{where}.fields", ACTION_FIELD_TYPES)
    for index, field in enumerate(fields):
        if entry["fields"][index].get("required", True) is not True:
            raise _fail(f"{where}.fields[{index}]", "an action field is always required")
        field["required"] = True
        for option in field.get("options", []):
            if WORD.fullmatch(option["value"]) is None:
                raise _fail(f"{where}.fields[{index}].options", f"{option['value']!r} is not one word")
    template = _text(entry["template"], f"{where}.template", MAX_TEMPLATE)
    if "{" in PLACEHOLDER.sub("", template) or "}" in PLACEHOLDER.sub("", template):
        raise _fail(f"{where}.template", "a brace outside a {field} placeholder")
    named = PLACEHOLDER.findall(template)
    declared = [field["name"] for field in fields]
    unknown = sorted(set(named) - set(declared))
    if unknown:
        raise _fail(f"{where}.template", "placeholder(s) without a field: " + ", ".join(unknown))
    unused = sorted(set(declared) - set(named))
    if unused:
        raise _fail(f"{where}.template", "field(s) the template never uses: " + ", ".join(unused))
    place = entry.get("place", "actions")
    if place not in ACTION_PLACES:
        raise _fail(f"{where}.place", "one of " + ", ".join(ACTION_PLACES))
    return {
        "id": action_id,
        "label": _text(entry["label"], f"{where}.label", MAX_LABEL),
        "template": template,
        "fields": fields,
        "group": _text(entry.get("group", ""), f"{where}.group", MAX_LABEL, empty=True),
        "hint": _text(entry.get("hint", ""), f"{where}.hint", MAX_HINT, empty=True),
        "place": place,
    }


def _stream(raw: Any, where: str) -> dict[str, Any]:
    entry = _mapping(raw, where, _STREAM_KEYS, _STREAM_KEYS)
    columns: list[dict[str, str]] = []
    for index, item in enumerate(_entries(entry["columns"], f"{where}.columns", MAX_COLUMNS)):
        spot = f"{where}.columns[{index}]"
        column = _mapping(item, spot, _COLUMN_KEYS, frozenset({"key", "label"}))
        shape = column.get("format", "text")
        if shape not in COLUMN_FORMATS:
            raise _fail(f"{spot}.format", "one of " + ", ".join(COLUMN_FORMATS))
        if shape == "time" and "width" in column:
            raise _fail(f"{spot}.width", "a time column has a fixed width")
        width = column.get("width", "narrow" if shape == "time" else "fill")
        if width not in COLUMN_WIDTHS:
            raise _fail(f"{spot}.width", "one of " + ", ".join(COLUMN_WIDTHS))
        columns.append(
            {
                "key": _identifier(column["key"], f"{spot}.key", FIELD_NAME),
                "label": _text(column["label"], f"{spot}.label", MAX_LABEL),
                "format": shape,
                "width": width,
            }
        )
    if len(columns) == 0:
        raise _fail(f"{where}.columns", "a stream needs at least one column")
    _unique([column["key"] for column in columns], f"{where}.columns")
    return {
        "id": _identifier(entry["id"], f"{where}.id", CONSOLE_ID),
        "title": _text(entry["title"], f"{where}.title", MAX_LABEL),
        "columns": columns,
    }


def _compare(raw: Any, where: str) -> dict[str, Any]:
    """The comparison panel: its title and the sides every row has one cell for."""
    entry = _mapping(raw, where, _COMPARE_KEYS, frozenset({"sides"}))
    sides: list[dict[str, str]] = []
    for index, item in enumerate(_entries(entry["sides"], f"{where}.sides", MAX_COMPARE_SIDES)):
        spot = f"{where}.sides[{index}]"
        side = _mapping(item, spot, _SIDE_KEYS, _SIDE_KEYS)
        sides.append(
            {
                "id": _identifier(side["id"], f"{spot}.id", FIELD_NAME),
                "label": _text(side["label"], f"{spot}.label", MAX_LABEL),
            }
        )
    if len(sides) < MIN_COMPARE_SIDES:
        raise _fail(f"{where}.sides", f"a comparison needs at least {MIN_COMPARE_SIDES} sides")
    _unique([side["id"] for side in sides], f"{where}.sides")
    return {
        "title": _text(entry.get("title", "Comparison"), f"{where}.title", MAX_LABEL),
        "hint": _text(entry.get("hint", ""), f"{where}.hint", MAX_HINT, empty=True),
        "sides": sides,
    }


def _pills(raw: Any, where: str) -> list[dict[str, str]]:
    """The top bar pills: an id the ``pills()`` answer is keyed by and a short label."""
    pills: list[dict[str, str]] = []
    for index, item in enumerate(_entries(raw, where, MAX_PILLS)):
        spot = f"{where}[{index}]"
        pill = _mapping(item, spot, _PILL_KEYS, _PILL_KEYS)
        pills.append({"id": _identifier(pill["id"], f"{spot}.id", FIELD_NAME), "label": _text(pill["label"], f"{spot}.label", MAX_PILL_LABEL)})
    _unique([pill["id"] for pill in pills], where)
    return pills


def validate_manifest(raw: Any) -> dict[str, Any]:
    """The checked copy of a console manifest, or ``ConsoleManifestError``."""
    entry = _mapping(raw, "manifest", _MANIFEST_KEYS, frozenset({"id", "title"}))
    console_id = _identifier(entry["id"], "manifest.id", CONSOLE_ID)
    where = f"console {console_id!r}"
    manifest: dict[str, Any] = {
        "id": console_id,
        "title": _text(entry["title"], f"{where}: title", MAX_TITLE),
        "summary": _text(entry.get("summary", ""), f"{where}: summary", MAX_SUMMARY, empty=True),
        "start": None,
        "actions": [],
        "command_line": None,
        "streams": [],
        "compare": None,
        "state": None,
        "pills": [],
        "runs": None,
    }
    if entry.get("start") is not None:
        start = _mapping(entry["start"], f"{where}: start", _START_KEYS, frozenset())
        manifest["start"] = {
            "label": _text(start.get("label", "Start"), f"{where}: start.label", MAX_LABEL),
            "fields": _start_fields(start.get("fields", []), f"{where}: start.fields"),
        }
    actions = [_action(item, f"{where}: actions[{index}]") for index, item in enumerate(_entries(entry.get("actions", []), f"{where}: actions", MAX_ACTIONS))]
    _unique([action["id"] for action in actions], f"{where}: actions")
    manifest["actions"] = actions
    if entry.get("command_line") is not None:
        line = _mapping(entry["command_line"], f"{where}: command_line", _COMMAND_LINE_KEYS, frozenset())
        manifest["command_line"] = {
            "placeholder": _text(line.get("placeholder", ""), f"{where}: command_line.placeholder", MAX_HINT, empty=True),
            "hint": _text(line.get("hint", ""), f"{where}: command_line.hint", MAX_HINT, empty=True),
        }
    streams = [_stream(item, f"{where}: streams[{index}]") for index, item in enumerate(_entries(entry.get("streams", []), f"{where}: streams", MAX_STREAMS))]
    _unique([stream["id"] for stream in streams], f"{where}: streams")
    manifest["streams"] = streams
    if entry.get("compare") is not None:
        manifest["compare"] = _compare(entry["compare"], f"{where}: compare")
    placed = [action["id"] for action in actions if action["place"] == "compare"]
    if placed and manifest["compare"] is None:
        raise _fail(f"{where}: actions", "placed in the comparison panel, which this console does not declare: " + ", ".join(placed))
    if entry.get("state") is not None:
        state = _mapping(entry["state"], f"{where}: state", _STATE_KEYS, frozenset())
        manifest["state"] = {"title": _text(state.get("title", "State"), f"{where}: state.title", MAX_LABEL)}
    manifest["pills"] = _pills(entry.get("pills", []), f"{where}: pills")
    if entry.get("runs") is not None:
        # Imported here: the run form module builds on this one's helpers.
        from .plugin_console_runform import validate_runs

        manifest["runs"] = validate_runs(entry["runs"], f"{where}: runs")
    shows = (actions, manifest["command_line"], streams, manifest["compare"], manifest["runs"])
    if all(not part for part in shows):
        raise _fail(where, "declares no action, command line, stream, comparison or run form")
    return manifest
